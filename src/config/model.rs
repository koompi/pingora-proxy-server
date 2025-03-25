use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Define an enum for tracking the origin of domain mappings
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MappingOrigin {
    Manual,
    SwarmDiscovery,
}

// Default to Manual for backward compatibility
impl Default for MappingOrigin {
    fn default() -> Self {
        Self::Manual
    }
}

/// Type alias for the configuration store used throughout the application
pub type ConfigStore = HashMap<String, (String, MappingOrigin)>;

/// Represents a server mapping from domain to backend with origin
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerMapping {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub origin: MappingOrigin,
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
            result.insert(srv.from.clone(), (srv.to.clone(), srv.origin.clone()));
        });
        result
    }

    /// Create configuration from HashMap
    pub fn from_hashmap(map: &ConfigStore) -> Self {
        let servers = map
            .iter()
            .map(|(from, (to, origin))| ServerMapping {
                from: from.clone(),
                to: to.clone(),
                origin: origin.clone(),
            })
            .collect();

        Self { servers }
    }
}
