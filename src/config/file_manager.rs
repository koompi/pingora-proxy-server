use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    path::Path,
};

use super::model::{ConfigStore, Configuration, MappingOrigin, ServerMapping};

// Default path can be overridden by CONFIG_PATH environment variable
fn get_config_path() -> String {
    std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.json".to_string())
}

// Creates the directory if it doesn't exist
fn ensure_config_dir(config_path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(config_path).parent() {
        if !parent.exists() {
            println!("Creating config directory: {:?}", parent);
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

/// Load configuration from file
pub async fn get_config() -> ConfigStore {
    let config_path = get_config_path();
    println!("Using config path: {}", config_path);

    let mut content = String::new();

    // Try to open the config file, create with default if it doesn't exist
    let file_result = fs::File::open(&config_path);

    match file_result {
        Ok(mut file) => {
            if let Err(err) = file.read_to_string(&mut content) {
                println!("Error reading config file: {}", err);
                content = r#"{"servers":[]}"#.to_string();
            }
        }
        Err(err) => {
            println!("Config file not found ({}), creating with defaults", err);
            content = r#"{"servers":[]}"#.to_string();
            if let Err(e) = ensure_config_dir(&config_path) {
                println!("Warning: Could not create config directory: {}", e);
            }
            update_config(vec![]).ok(); // Use ok() to discard the Result
        }
    }

    let config = match serde_json::from_str::<Configuration>(&content) {
        Ok(cfg) => cfg,
        Err(err) => {
            println!("Error parsing config file: {}", err);
            Configuration::new()
        }
    };

    let store = config.to_hashmap();

    // Log loaded mappings
    for (from, (to, origin)) in &store {
        let origin_str = match origin {
            MappingOrigin::Manual => "Manual",
            MappingOrigin::SwarmDiscovery => "SwarmDiscovery",
        };
        println!(
            "Loaded mapping: {} -> {} (Origin: {})",
            from, to, origin_str
        );
    }

    store
}

/// Update configuration file with new server mappings
pub fn update_config(servers: Vec<ServerMapping>) -> Result<(), std::io::Error> {
    let config_path = get_config_path();

    // Ensure the config directory exists
    ensure_config_dir(&config_path)?;

    let config = Configuration { servers };
    let data = match serde_json::to_string_pretty(&config) {
        Ok(data) => data,
        Err(err) => {
            println!("Error serializing config: {}", err);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Serialization error: {}", err),
            ));
        }
    };

    // Use a more robust approach to writing the file:
    // 1. First write to a temporary file
    // 2. Then rename the temporary file to the target file
    let temp_path = format!("{}.tmp", config_path);

    // Create and write to temp file
    {
        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(data.as_bytes())?;
        file.sync_all()?; // Make sure all data is flushed to disk
    }

    // Rename temp file to actual config file
    std::fs::rename(&temp_path, config_path)?;

    println!("Config updated successfully");
    Ok(())
}

/// Create mappings from config store
pub fn create_mappings_from_store(store: &ConfigStore) -> Vec<ServerMapping> {
    store
        .iter()
        .map(|(k, (v, origin))| ServerMapping {
            from: k.to_string(),
            to: v.to_string(),
            origin: origin.clone(),
        })
        .collect()
}

/// Handle backward compatibility with old config structure
/// This can be used during migration from the old format
pub fn maybe_migrate_old_config() -> Result<(), std::io::Error> {
    let config_path = get_config_path();
    let file_result = fs::File::open(&config_path);
    if let Ok(mut file) = file_result {
        let mut content = String::new();
        if file.read_to_string(&mut content).is_ok() {
            // Try to parse with old format (just as a simple HashMap<String, String>)
            let old_format_result: Result<HashMap<String, String>, _> =
                serde_json::from_str(&content);

            if old_format_result.is_ok() {
                println!("Detected potential old config format. Checking structure...");

                // Try to parse as new format to verify if it's actually old format
                let new_format_result: Result<Configuration, _> = serde_json::from_str(&content);

                if new_format_result.is_err() {
                    println!("Confirmed old format. Migrating to new format with MappingOrigin...");

                    // It's definitely old format, so migrate it
                    let old_store = old_format_result.unwrap();
                    let new_store: ConfigStore = old_store
                        .into_iter()
                        .map(|(domain, target)| (domain, (target, MappingOrigin::Manual)))
                        .collect();

                    let mappings = new_store
                        .iter()
                        .map(|(domain, (target, origin))| ServerMapping {
                            from: domain.clone(),
                            to: target.clone(),
                            origin: origin.clone(),
                        })
                        .collect();

                    update_config(mappings)?;
                    println!("Migration complete!");
                }
            }
        }
    }
    Ok(())
}
