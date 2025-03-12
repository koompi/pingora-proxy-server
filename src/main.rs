use std::{
    collections::HashMap,
    io::{Read, Write},
    pin::{self, Pin},
    sync::{Arc, Mutex},
};

use pingora::{Result, prelude::HttpPeer, server::Server};
use pingora_proxy::{ProxyHttp, Session};
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
    #[doc = " The per request object to share state across the different filters"]
    type CTX = ();

    #[doc = " Define how the `ctx` should be created."]
    fn new_ctx(&self) -> Self::CTX {}

    #[doc = " Define where the proxy should send the request to."]
    #[doc = ""]
    #[doc = " The returned [HttpPeer] contains the information regarding where and how this request should"]
    #[doc = " be forwarded to."]
    #[must_use]
    #[allow(
        elided_named_lifetimes,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds
    )]
    fn upstream_peer<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        session: &'life1 mut Session,
        ctx: &'life2 mut Self::CTX,
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
    #[doc = " The per request object to share state across the different filters"]
    type CTX = ();

    #[doc = " Define how the `ctx` should be created."]
    fn new_ctx(&self) -> Self::CTX {}

    #[doc = " Define where the proxy should send the request to."]
    #[doc = ""]
    #[doc = " The returned [HttpPeer] contains the information regarding where and how this request should"]
    #[doc = " be forwarded to."]
    #[must_use]
    #[allow(
        elided_named_lifetimes,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds
    )]
    fn upstream_peer<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        session: &'life1 mut Session,
        ctx: &'life2 mut Self::CTX,
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
    #[doc = " The per request object to share state across the different filters"]
    type CTX = ();

    #[doc = " Define how the `ctx` should be created."]
    fn new_ctx(&self) -> Self::CTX {}

    #[doc = " Define where the proxy should send the request to."]
    #[doc = ""]
    #[doc = " The returned [HttpPeer] contains the information regarding where and how this request should"]
    #[doc = " be forwarded to."]
    #[must_use]
    #[allow(
        elided_named_lifetimes,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds
    )]
    fn upstream_peer<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        session: &'life1 mut Session,
        ctx: &'life2 mut Self::CTX,
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

pub fn main() {
    env_logger::init();

    let config = Arc::new(Mutex::new(get_config()));
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

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

    let mut mananger = pingora_proxy::http_proxy_service(
        &server.configuration,
        MyManager {
            servers: config.clone(),
        },
    );

    proxy_http.add_tcp("0.0.0.0:80");
    // proxy_https.add_tcp("0.0.0.0:443");
    proxy_https.add_tls("0.0.0.0:443", "", "").unwrap();
    mananger.add_tcp("0.0.0.0:81");

    server.add_service(proxy_http);
    server.add_service(mananger);
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
    let mut file = std::fs::File::open("config.json").unwrap();
    file.read_to_string(&mut content).unwrap();

    let data = serde_json::from_str::<MyCfg>(&content).unwrap();
    let mut res = HashMap::new();

    data.servers.iter().for_each(|sv| {
        res.insert(sv.from.to_owned(), sv.to.to_owned());
    });

    res
}

fn update_config(servers: Vec<MyServer>) {
    let data = serde_json::to_string_pretty(&MyCfg { servers }).unwrap();
    let mut file = std::fs::File::options()
        .write(true)
        .truncate(true)
        .open("config.json")
        .unwrap();

    file.write_all(&data.as_bytes()).unwrap();
    file.sync_all().unwrap();
    file.flush().unwrap();
}
