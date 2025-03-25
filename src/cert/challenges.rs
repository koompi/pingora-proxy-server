// src/cert/challenges.rs
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

// Global store for active ACME challenges
pub static CHALLENGE_STORE: Lazy<Mutex<HashMap<String, (String, String)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// Get a challenge by domain name
pub fn get_challenge_by_key(key: &str) -> Option<(String, String)> {
    let store = CHALLENGE_STORE.lock().unwrap();
    store.get(key).cloned()
}

// Insert a challenge into the store
pub fn insert_challenge(key: String, value: (String, String)) {
    let mut store = CHALLENGE_STORE.lock().unwrap();
    store.insert(key, value);
}

// Remove a challenge from the store
pub fn remove_challenge(key: &str) {
    let mut store = CHALLENGE_STORE.lock().unwrap();
    store.remove(key);
}
