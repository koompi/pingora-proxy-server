use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex},
};

use pingora::{Result, prelude::HttpPeer, server::Server};
use pingora_proxy::{ProxyHttp, Session};
use pingora::listeners::tls::TlsSettings;
use regex::Regex;
use serde::{Deserialize, Serialize};

fn extract_hostname(request_line: &str) -> Option<String> {
    let re = Regex::new(r"Host:\s*([^\s,]+)").unwrap();

    if let Some(captures) = re.captures(request_line) {
        if let Some(hostname) = captures.get(1) {
            return Some(hostname.as_str().to_string());
        }
    }

    None
}

#[derive(Clone)]
pub struct MyProxy {
    pub servers: Arc<Mutex<HashMap<String, String>>>,
}

#[derive(Clone)]
pub struct MyProxyTls {
    pub servers: Arc<Mutex<HashMap<String, String>>>,
}

#[derive(Clone)]
pub struct MyManager {
    pub servers: Arc<Mutex<HashMap<String, String>>>,
}

#[async_trait::async_trait]
impl ProxyHttp for MyProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    fn upstream_peer<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        session: &'life1 mut Session,
        _ctx: &'life2 mut Self::CTX,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<Box<HttpPeer>>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let hostname = extract_hostname(&session.request_summary()).unwrap_or_default();

        match self.servers.lock().unwrap().get(&hostname) {
            Some(to) => {
                let res = HttpPeer::new(to.to_owned(), false, hostname.to_string());
                Box::pin(async move { Ok(Box::new(res)) })
            }
            None => {
                let res = HttpPeer::new("127.0.0.1:5500", false, "".to_string());
                Box::pin(async move { Ok(Box::new(res)) })
            }
        }
    }
}

#[async_trait::async_trait]
impl ProxyHttp for MyProxyTls {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    fn upstream_peer<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        session: &'life1 mut Session,
        _ctx: &'life2 mut Self::CTX,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<Box<HttpPeer>>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let hostname = extract_hostname(&session.request_summary()).unwrap_or_default();

        match self.servers.lock().unwrap().get(&hostname) {
            Some(to) => {
                let res = HttpPeer::new(to.to_owned(), true, hostname.to_string());
                Box::pin(async move { Ok(Box::new(res)) })
            }
            None => {
                let res = HttpPeer::new("127.0.0.1:5500", true, "".to_string());
                Box::pin(async move { Ok(Box::new(res)) })
            }
        }
    }
}

#[async_trait::async_trait]
impl ProxyHttp for MyManager {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    fn upstream_peer<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        session: &'life1 mut Session,
        _ctx: &'life2 mut Self::CTX,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<Box<HttpPeer>>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let summary = session.request_summary().replace(", Host:", "");
        let segments = summary.split_whitespace().collect::<Vec<&str>>();
        let method = segments.iter().nth(0).map(|s| s.to_string()).unwrap();
        let pathname = segments.iter().nth(1).map(|s| s.to_string()).unwrap();

        let path_segments: Vec<String> = pathname.split("/").map(|seg| seg.to_string()).collect();
        println!("{:#?}", &path_segments);

        if method == "POST" {
            let from = path_segments.iter().nth(1).unwrap();
            let to = path_segments.iter().nth(2).unwrap();
            let mut servers = self.servers.lock().unwrap();

            servers.insert(from.to_string(), to.to_string());

            let updates: Vec<MyServer> = servers
                .iter()
                .map(|(k, v)| MyServer {
                    from: k.to_string(),
                    to: v.to_string(),
                })
                .collect();

            update_config(updates)
        }
        if method == "PUT" {
            let from = path_segments.iter().nth(1).unwrap();
            let to = path_segments.iter().nth(2).unwrap();

            let mut servers = self.servers.lock().unwrap();
            servers.insert(from.to_string(), to.to_string());

            let updates: Vec<MyServer> = servers
                .iter()
                .map(|(k, v)| MyServer {
                    from: k.to_string(),
                    to: v.to_string(),
                })
                .collect();

            update_config(updates)
        }

        if method == "DELETE" {
            let from = path_segments.iter().nth(1).unwrap();

            let mut servers = self.servers.lock().unwrap();
            servers.remove_entry(from);

            let updates: Vec<MyServer> = servers
                .iter()
                .map(|(k, v)| MyServer {
                    from: k.to_string(),
                    to: v.to_string(),
                })
                .collect();

            update_config(updates)
        }

        let res = HttpPeer::new("127.0.0.1:5500", false, "".to_string());
        Box::pin(async move { Ok(Box::new(res)) })
    }
}

// Struct to represent domain certificate information
struct DomainCert {
    domain: String,
    cert_path: String,
    key_path: String,
}

// Function to check for certbot certificates
fn find_certbot_certs(domains: &[String]) -> Vec<DomainCert> {
    let certbot_live_dir = "backup/letsencrypt/live";
    let mut certs = Vec::new();

    for domain in domains {
        let domain_dir = Path::new(certbot_live_dir).join(domain);
        let fullchain_path = domain_dir.join("fullchain.pem");
        let privkey_path = domain_dir.join("privkey.pem");

        if fullchain_path.exists() && privkey_path.exists() {
            println!("Found certificates for domain: {}", domain);
            certs.push(DomainCert {
                domain: domain.clone(),
                cert_path: fullchain_path.to_string_lossy().to_string(),
                key_path: privkey_path.to_string_lossy().to_string(),
            });
        } else {
            println!("No certificates found for domain: {}", domain);
        }
    }

    certs
}

pub fn main() {
    env_logger::init();

    let config = Arc::new(Mutex::new(get_config()));
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    // Extract domain names from the config
    let domains: Vec<String> = config.lock().unwrap().keys().cloned().collect();
    println!("Configured domains: {:?}", domains);
    
    // Find certificates for the domains
    let certs = find_certbot_certs(&domains);
    
    let mut proxy_http = pingora_proxy::http_proxy_service(
        &server.configuration,
        MyProxy {
            servers: config.clone(),
        },
    );

    let mut proxy_https = pingora_proxy::http_proxy_service(
        &server.configuration,
        MyProxyTls {
            servers: config.clone(),
        },
    );

    let mut manager = pingora_proxy::http_proxy_service(
        &server.configuration,
        MyManager {
            servers: config.clone(),
        },
    );

    // Add HTTP endpoint
    proxy_http.add_tcp("0.0.0.0:80");
    
    // Add manager endpoint with TLS if certs are available
    if !certs.is_empty() {
        // Use the first certificate for the manager interface
        let mgr_cert = &certs[0];
        println!("Using certificate for manager: {}", mgr_cert.domain);
        
        match TlsSettings::intermediate(&mgr_cert.cert_path, &mgr_cert.key_path) {
            Ok(tls_settings) => {
                manager.add_tls_with_settings("0.0.0.0:81", None, tls_settings);
                println!("Manager TLS configured successfully");
            },
            Err(e) => {
                println!("Error setting up TLS for manager: {}", e);
                manager.add_tcp("0.0.0.0:81");
            }
        };
    } else {
        // Fallback to HTTP if no certs
        manager.add_tcp("0.0.0.0:81");
    }
    
    // Configure HTTPS with domain-specific certificates
    if !certs.is_empty() {
        for cert in &certs {
            println!("Setting up TLS for domain: {}", cert.domain);
            
            // Create TLS settings
            let tls_settings = match TlsSettings::intermediate(&cert.cert_path, &cert.key_path) {
                Ok(settings) => settings,
                Err(e) => {
                    println!("Error creating TLS settings for {}: {}", cert.domain, e);
                    continue;
                }
            };
                
            // Add TLS endpoint
            proxy_https.add_tls_with_settings("0.0.0.0:443", None, tls_settings);
        }
    } else {
        println!("Warning: No TLS certificates found. HTTPS service will not be available.");
    }

    // Add the services to the server
    server.add_service(proxy_http);
    
    // Only add HTTPS service if we have certificates
    if !certs.is_empty() {
        server.add_service(proxy_https);
    }
    
    server.add_service(manager);
    
    println!("Starting server with configured services");
    server.run_forever();
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MyServer {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MyCfg {
    pub servers: Vec<MyServer>,
}

fn get_config() -> HashMap<String, String> {
    let mut content = String::new();
    
    // Try to open the config file, create with default if it doesn't exist
    let file_result = fs::File::open("config.json");
    
    match file_result {
        Ok(mut file) => {
            file.read_to_string(&mut content).unwrap_or_else(|err| {
                println!("Error reading config file: {}", err);
                0
            });
        },
        Err(err) => {
            println!("Config file not found ({}), creating with defaults", err);
            content = r#"{"servers":[]}"#.to_string();
            update_config(vec![]);
        }
    }

    let data = match serde_json::from_str::<MyCfg>(&content) {
        Ok(cfg) => cfg,
        Err(err) => {
            println!("Error parsing config file: {}", err);
            MyCfg { servers: vec![] }
        }
    };
    
    let mut res = HashMap::new();

    data.servers.iter().for_each(|sv| {
        println!("Loaded mapping: {} -> {}", sv.from, sv.to);
        res.insert(sv.from.to_owned(), sv.to.to_owned());
    });

    res
}

fn update_config(servers: Vec<MyServer>) {
    let data = serde_json::to_string_pretty(&MyCfg { servers }).unwrap();
    let file_result = std::fs::File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .open("config.json");
        
    match file_result {
        Ok(mut file) => {
            if let Err(err) = file.write_all(&data.as_bytes()) {
                println!("Error writing config: {}", err);
                return;
            }
            file.sync_all().unwrap_or_else(|err| {
                println!("Error syncing config file: {}", err);
            });
            file.flush().unwrap_or_else(|err| {
                println!("Error flushing config file: {}", err);
            });
            println!("Config updated successfully");
        },
        Err(err) => {
            println!("Error opening config file for writing: {}", err);
        }
    }
}