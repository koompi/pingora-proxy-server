// src/logging.rs
use log::{error, info, warn, LevelFilter};
use std::env;

pub fn setup_logging() {
    // Get log level from environment or default to "info"
    let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());

    // Convert string to LevelFilter
    let level = match log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };

    // Initialize logger with custom configuration
    env_logger::Builder::new()
        .filter_level(level)
        // Don't log pingora body events at debug level
        .filter_module("pingora_core::protocols::http", LevelFilter::Info)
        .filter_module("pingora_proxy::proxy_h1", LevelFilter::Info)
        .init();

    info!("Logger initialized with level: {}", log_level);
}

// Helper functions to make logging more consistent
pub fn log_config_update(component: &str, message: &str) {
    info!("[CONFIG] {}: {}", component, message);
}

pub fn log_cert_operation(domain: &str, message: &str) {
    info!("[CERT] {}: {}", domain, message);
}

pub fn log_network_operation(network: &str, message: &str) {
    info!("[NETWORK] {}: {}", network, message);
}

pub fn log_proxy_request(domain: &str, action: &str) {
    if log::log_enabled!(log::Level::Debug) {
        info!("[PROXY] {}: {}", domain, action);
    }
}

// Function to log HTTP responses without the full body details
pub fn log_http_response(domain: &str, status: u16) {
    if log::log_enabled!(log::Level::Debug) {
        info!("[RESPONSE] {} status: {}", domain, status);
    }
}
