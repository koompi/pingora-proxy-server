// src/services/lock.rs
use std::fs::{self, File, OpenOptions};
use std::io::{Error as IoError, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

/// A file-based distributed lock for coordinating across multiple nodes
pub struct DistributedLock {
    /// Path to the lock file
    lock_path: PathBuf,
    /// Unique ID of this node
    node_id: String,
    /// Time-to-live for the lock in seconds
    ttl: Duration,
}

impl DistributedLock {
    /// Create a new DistributedLock
    pub fn new(
        lock_dir: impl AsRef<Path>,
        lock_name: &str,
        node_id: &str,
        ttl_seconds: u64,
    ) -> Self {
        // Create lock directory if it doesn't exist
        let dir = lock_dir.as_ref();
        if !dir.exists() {
            fs::create_dir_all(dir).expect("Failed to create lock directory");
        }

        Self {
            lock_path: dir.join(format!("{}.lock", lock_name)),
            node_id: node_id.to_string(),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    /// Try to acquire the lock with retries
    pub async fn acquire(
        &self,
        max_attempts: usize,
        retry_delay: Duration,
    ) -> Result<bool, IoError> {
        for attempt in 1..=max_attempts {
            match self.try_acquire() {
                Ok(true) => {
                    println!("Successfully acquired lock: {:?}", self.lock_path);
                    return Ok(true);
                }
                Ok(false) if attempt < max_attempts => {
                    println!(
                        "Lock {:?} already held, attempt {}/{}. Waiting...",
                        self.lock_path, attempt, max_attempts
                    );
                    sleep(retry_delay).await;
                }
                Ok(false) => {
                    println!("Failed to acquire lock after {} attempts", max_attempts);
                    return Ok(false);
                }
                Err(e) => {
                    println!(
                        "Error acquiring lock {:?}: {:?}. Attempt {}/{}",
                        self.lock_path, e, attempt, max_attempts
                    );
                    if attempt == max_attempts {
                        return Err(e);
                    }
                    sleep(retry_delay).await;
                }
            }
        }

        Ok(false)
    }

    /// Try to acquire the lock once
    fn try_acquire(&self) -> Result<bool, IoError> {
        // Check if lock exists and is valid
        if self.lock_path.exists() {
            let mut lock_file = File::open(&self.lock_path)?;
            let mut contents = String::new();
            lock_file.read_to_string(&mut contents)?;

            // Parse lock contents
            let parts: Vec<&str> = contents.trim().split(':').collect();
            if parts.len() < 2 {
                // Invalid lock format, consider it expired
                println!("Invalid lock format, removing: {:?}", self.lock_path);
                fs::remove_file(&self.lock_path)?;
            } else {
                let lock_owner = parts[0];
                let lock_time = parts[1].parse::<u64>().unwrap_or(0);

                // Check if we already own the lock
                if lock_owner == self.node_id {
                    // We already own the lock, update the timestamp
                    self.write_lock_file()?;
                    return Ok(true);
                }

                // Check if the lock has expired
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                if now - lock_time > self.ttl.as_secs() {
                    // Lock has expired, we can take it
                    println!("Found expired lock, removing: {:?}", self.lock_path);
                    self.write_lock_file()?;
                    return Ok(true);
                }

                // Lock is valid and held by someone else
                return Ok(false);
            }
        }

        // Add cleanup for very old locks (e.g., 5x TTL)
        if self.lock_path.exists() {
            let metadata = fs::metadata(&self.lock_path)?;
            if let Ok(modified) = metadata.modified() {
                if SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default()
                    > self.ttl * 5
                {
                    println!("Found very old lock, removing: {:?}", self.lock_path);
                    fs::remove_file(&self.lock_path)?;
                }
            }
        }

        // No valid lock exists, try to create it
        match self.write_lock_file() {
            Ok(_) => Ok(true),
            Err(e) => {
                if e.kind() == ErrorKind::AlreadyExists {
                    // Another process created the lock file before us
                    Ok(false)
                } else {
                    Err(e)
                }
            }
        }
    }

    pub fn debug_lock_status(&self) -> Result<String, IoError> {
        if !self.lock_path.exists() {
            return Ok(format!("Lock {:?} does not exist", self.lock_path));
        }

        let mut lock_file = File::open(&self.lock_path)?;
        let mut contents = String::new();
        lock_file.read_to_string(&mut contents)?;

        Ok(format!("Lock {:?} contents: {}", self.lock_path, contents))
    }

    /// Write the lock file with our node ID and current time
    fn write_lock_file(&self) -> Result<(), IoError> {
        // Handle stale file handle by removing the file first if it exists
        if self.lock_path.exists() {
            Self::retry_file_operation(|| fs::remove_file(&self.lock_path)).ok();
        }

        // Create parent directory if it doesn't exist
        if let Some(parent) = self.lock_path.parent() {
            if !parent.exists() {
                Self::retry_file_operation(|| fs::create_dir_all(parent))?;
            }
        }

        // Make sure we can write to the directory
        if let Some(parent) = self.lock_path.parent() {
            let temp_file_path = parent.join(".write_test_tmp");
            let write_test = fs::File::create(&temp_file_path);
            if let Err(e) = write_test {
                return Err(IoError::new(
                    ErrorKind::PermissionDenied,
                    format!("Cannot write to lock directory: {}", e),
                ));
            }
            fs::remove_file(temp_file_path).ok();
        }

        // Create lock file with exclusive access
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.lock_path)?;

        // Write node ID and timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let contents = format!("{}:{}", self.node_id, now);
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;

        // Explicitly drop the file handle
        drop(file);

        Ok(())
    }
    /// Release the lock
    pub async fn release(&self) -> Result<(), IoError> {
        // Only remove the lock if it's ours
        if self.lock_path.exists() {
            let mut lock_file = File::open(&self.lock_path)?;
            let mut contents = String::new();
            lock_file.read_to_string(&mut contents)?;

            let parts: Vec<&str> = contents.trim().split(':').collect();
            if parts.len() >= 1 && parts[0] == self.node_id {
                // This is our lock, remove it
                fs::remove_file(&self.lock_path)?;
                println!("Released lock: {:?}", self.lock_path);
            } else {
                println!("Lock {:?} not owned by us, not releasing", self.lock_path);
            }
        } else {
            println!("Lock {:?} not found", self.lock_path);
        }

        Ok(())
    }
    // Add a method to try to become the leader
    pub async fn try_become_leader(&self) -> Result<bool, IoError> {
        self.acquire(1, Duration::from_millis(0)).await
    }

    // Add a method to refresh leadership
    pub async fn refresh_leadership(&self) -> Result<bool, IoError> {
        if !self.lock_path.exists() {
            return self.try_become_leader().await;
        }

        // Check if we own the lock
        let mut lock_file = File::open(&self.lock_path)?;
        let mut contents = String::new();
        lock_file.read_to_string(&mut contents)?;

        let parts: Vec<&str> = contents.trim().split(':').collect();
        if parts.len() >= 1 && parts[0] == self.node_id {
            // Update the timestamp to extend our leadership
            self.write_lock_file()?;
            Ok(true)
        } else {
            // Someone else is the leader
            Ok(false)
        }
    }
    fn retry_file_operation<F, T>(operation: F) -> Result<T, IoError>
    where
        F: Fn() -> Result<T, IoError>,
    {
        let mut backoff = 10; // Start with 10ms
        let max_attempts = 5;

        for attempt in 1..=max_attempts {
            match operation() {
                Ok(result) => return Ok(result),
                Err(err) if attempt < max_attempts => {
                    println!("File operation failed (attempt {}): {}", attempt, err);
                    std::thread::sleep(Duration::from_millis(backoff));
                    backoff *= 2; // Exponential backoff
                }
                Err(err) => return Err(err),
            }
        }

        // This should never be reached due to the loop structure
        Err(IoError::new(ErrorKind::Other, "Retry mechanism failed"))
    }
    pub async fn cleanup_recently_deleted() -> Result<(), IoError> {
        let recently_deleted_file = PathBuf::from("/pingora-proxy/locks/recently_deleted.json");

        if recently_deleted_file.exists() {
            if let Ok(content) = fs::read_to_string(&recently_deleted_file) {
                if let Ok(timestamp_domains) = serde_json::from_str::<Vec<(u64, String)>>(&content)
                {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    // Filter out entries older than 5 minutes
                    let fresh_entries: Vec<(u64, String)> = timestamp_domains
                        .into_iter()
                        .filter(|(timestamp, _)| now - timestamp < 300)
                        .collect();

                    if let Ok(json) = serde_json::to_string(&fresh_entries) {
                        let _ = fs::write(&recently_deleted_file, json);
                    }
                }
            }
        }

        Ok(())
    }
}
