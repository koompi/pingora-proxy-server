use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
};

use super::model::{ConfigStore, Configuration, ServerMapping};

const CONFIG_PATH: &str = "config.json";
const DEFAULT_CONFIG: &str = r#"{"servers":[]}"#;

/// Load configuration from file
pub fn get_config() -> ConfigStore {
    let mut content = String::new();

    // Try to open the config file, create with default if it doesn't exist
    let file_result = fs::File::open(CONFIG_PATH);

    match file_result {
        Ok(mut file) => {
            if let Err(err) = file.read_to_string(&mut content) {
                println!("Error reading config file: {}", err);
                content = DEFAULT_CONFIG.to_string();
            }
        }
        Err(err) => {
            println!("Config file not found ({}), creating with defaults", err);
            content = DEFAULT_CONFIG.to_string();
            update_config(vec![]);
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
    for (from, to) in &store {
        println!("Loaded mapping: {} -> {}", from, to);
    }

    store
}

/// Update configuration file with new server mappings
pub fn update_config(servers: Vec<ServerMapping>) -> Result<(), std::io::Error> {
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
    let temp_path = format!("{}.tmp", CONFIG_PATH);

    // Create and write to temp file
    {
        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(data.as_bytes())?;
        file.sync_all()?; // Make sure all data is flushed to disk
    }

    // Rename temp file to actual config file
    std::fs::rename(&temp_path, CONFIG_PATH)?;

    println!("Config updated successfully");
    Ok(())
}

/// Create mappings from config store
pub fn create_mappings_from_store(store: &ConfigStore) -> Vec<ServerMapping> {
    store
        .iter()
        .map(|(k, v)| ServerMapping {
            from: k.to_string(),
            to: v.to_string(),
        })
        .collect()
}
