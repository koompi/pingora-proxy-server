// src/proxy/db_proxy_main.rs
use log::{error, info};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::Duration;

use crate::config::model::ConfigStore;
use crate::proxy::tcp::{DatabaseIpRules, DatabaseMapping, DatabaseType};
use crate::proxy::tls_db_proxy::TlsDatabaseProxy;

/// Main entry point for creating and managing database proxies with SNI
pub async fn setup_db_proxies(
    config_store: Arc<std::sync::Mutex<ConfigStore>>,
    ip_rules: Arc<Mutex<DatabaseIpRules>>,
    cert_dir: &str,
    enable_tls: bool,
) -> Vec<mpsc::Sender<()>> {
    if !enable_tls {
        info!("TLS is disabled for database proxies, SNI routing will not be available");
        return Vec::new();
    }

    info!("Initializing database proxies with SNI routing");

    // Initialize the database mappings
    let db_mappings = Arc::new(Mutex::new(HashMap::new()));

    // Extract mappings from config
    init_db_mappings(&config_store, &db_mappings).await;

    // Create a proxy for each database type
    let mut shutdown_channels = Vec::new();

    for db_type in [
        DatabaseType::MongoDB,
        DatabaseType::PostgreSQL,
        DatabaseType::MySQL,
        DatabaseType::Redis,
    ]
    .iter()
    {
        // Create shutdown channel
        let (tx, rx) = mpsc::channel(1);
        shutdown_channels.push(tx);

        // Clone necessary references
        let db_mappings_clone = db_mappings.clone();

        // Extract the cloned IP rules BEFORE the await point
        let ip_rules_guard = ip_rules.lock().await;
        let ip_rules_clone = ip_rules_guard.clone();
        // Now drop the guard before moving to the spawned task
        drop(ip_rules_guard);

        let cert_dir = cert_dir.to_string();
        let db_type = *db_type;

        // Spawn a task for this database type
        tokio::spawn(async move {
            // Create the TLS proxy
            match TlsDatabaseProxy::new(db_type, &cert_dir, db_mappings_clone, ip_rules_clone).await
            {
                Ok(proxy) => {
                    info!(
                        "Starting {:?} database proxy on port {}",
                        db_type,
                        db_type.listen_port()
                    );
                    if let Err(e) = proxy.start(rx).await {
                        error!("Error running {:?} database proxy: {}", db_type, e);
                    }
                }
                Err(e) => {
                    error!("Failed to create {:?} database proxy: {}", db_type, e);
                }
            }
        });

        // Add a small delay between starting proxies to avoid resource contention
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Create a task to monitor config changes and update mappings
    let config_store_clone = config_store.clone();
    let db_mappings_clone = db_mappings.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;
            // Clone the Arc before passing to init_db_mappings
            let config_store_ref = config_store_clone.clone();
            let db_mappings_ref = db_mappings_clone.clone();
            init_db_mappings(&config_store_ref, &db_mappings_ref).await;
        }
    });

    info!("Database proxies initialized with SNI routing");
    shutdown_channels
}

/// Initialize database mappings from the config store
async fn init_db_mappings(
    config_store: &Arc<std::sync::Mutex<ConfigStore>>,
    db_mappings: &Arc<Mutex<HashMap<String, DatabaseMapping>>>,
) {
    info!("Updating database mappings from config");

    // Acquire the lock for the config store but don't hold it across an await point
    let new_mappings = {
        // Lock for the config store - using a block to limit the scope of the guard
        let configs = match config_store.lock() {
            Ok(configs) => configs,
            Err(e) => {
                error!("Failed to lock config store: {:?}", e);
                return;
            }
        };

        // Create a new set of mappings
        let mut new_mappings = HashMap::new();

        // Find database domains
        for (domain, (backend, _origin)) in configs.iter() {
            // Check if this is a database domain
            if domain.contains(".mongodb.")
                || domain.contains(".postgres.")
                || domain.contains(".postgresql.")
                || domain.contains(".mysql.")
                || domain.contains(".sql.")
                || domain.contains(".redis.")
                || domain.contains(".database.")
                || domain.contains(".db.")
            {
                // Create mapping
                let mapping = DatabaseMapping::new(domain.clone(), backend.clone());

                info!(
                    "Adding database mapping: {} -> {}:{} (type: {:?})",
                    domain, mapping.target_host, mapping.target_port, mapping.db_type
                );

                new_mappings.insert(domain.clone(), mapping);
            }
        }

        // Return the new mappings, dropping the MutexGuard before any await point
        new_mappings
    }; // End of scope for the configs MutexGuard

    // Now update the mappings
    let mut mappings = db_mappings.lock().await;
    *mappings = new_mappings;
    info!("Updated {} database mappings", mappings.len());
}

/// Export the setup function
pub mod db_proxy {
    pub use super::setup_db_proxies;
}
