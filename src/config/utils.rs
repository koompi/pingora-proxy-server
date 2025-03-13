use crate::{config, proxy::utils::clean_backend_address};
pub fn fix_config_file() {
    // Load the configuration
    let config_path = "config.json";
    let content = match std::fs::read_to_string(config_path) {
        Ok(content) => content,
        Err(e) => {
            println!("Error reading config file: {}", e);
            return;
        }
    };

    // Parse the configuration
    let mut config: config::model::Configuration = match serde_json::from_str(&content) {
        Ok(config) => config,
        Err(e) => {
            println!("Error parsing config file: {}", e);
            return;
        }
    };

    // Clean up the addresses
    let mut changes_made = false;
    for mapping in &mut config.servers {
        let cleaned_to = clean_backend_address(&mapping.to);
        if cleaned_to != mapping.to {
            println!("Cleaning address: {} -> {}", mapping.to, cleaned_to);
            mapping.to = cleaned_to;
            changes_made = true;
        }
    }

    // Write the configuration back if changes were made
    if changes_made {
        let data = match serde_json::to_string_pretty(&config) {
            Ok(data) => data,
            Err(e) => {
                println!("Error serializing config: {}", e);
                return;
            }
        };

        if let Err(e) = std::fs::write(config_path, data) {
            println!("Error writing config file: {}", e);
        } else {
            println!("Config file cleaned successfully");
        }
    } else {
        println!("No changes needed in config file");
    }
}
