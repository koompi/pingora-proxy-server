use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type alias for the configuration store used throughout the application
pub type ConfigStore = HashMap<String, String>;

/// Represents a server mapping from domain to backend
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerMapping {
    pub from: String,
    pub to: String,
}

/// Root configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Configuration {
    pub servers: Vec<ServerMapping>,
}

impl Configuration {
    /// Create a new empty configuration
    pub fn new() -> Self {
        Self { servers: vec![] }
    }

    /// Convert configuration to HashMap for easier lookup
    pub fn to_hashmap(&self) -> ConfigStore {
        let mut result = HashMap::new();
        self.servers.iter().for_each(|srv| {
            result.insert(srv.from.clone(), srv.to.clone());
        });
        result
    }

    /// Create configuration from HashMap
    pub fn from_hashmap(map: &ConfigStore) -> Self {
        let servers = map
            .iter()
            .map(|(from, to)| ServerMapping {
                from: from.clone(),
                to: to.clone(),
            })
            .collect();

        Self { servers }
    }
}
