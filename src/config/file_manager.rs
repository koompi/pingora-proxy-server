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
pub fn update_config(servers: Vec<ServerMapping>) {
    let config = Configuration { servers };
    let data = match serde_json::to_string_pretty(&config) {
        Ok(data) => data,
        Err(err) => {
            println!("Error serializing config: {}", err);
            return;
        }
    };

    let file_result = std::fs::File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(CONFIG_PATH);

    match file_result {
        Ok(mut file) => {
            if let Err(err) = file.write_all(data.as_bytes()) {
                println!("Error writing config: {}", err);
                return;
            }

            if let Err(err) = file.sync_all() {
                println!("Error syncing config file: {}", err);
            }

            if let Err(err) = file.flush() {
                println!("Error flushing config file: {}", err);
            }

            println!("Config updated successfully");
        }
        Err(err) => {
            println!("Error opening config file for writing: {}", err);
        }
    }
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
