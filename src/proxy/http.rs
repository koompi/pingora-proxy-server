use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use pingora::{Result, prelude::HttpPeer};
use pingora_proxy::{ProxyHttp, Session};

use super::utils::extract_hostname;

/// HTTP Proxy implementation
#[derive(Clone)]
pub struct HttpProxy {
    pub servers: Arc<Mutex<HashMap<String, String>>>,
}

#[async_trait::async_trait]
impl ProxyHttp for HttpProxy {
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

        match self.servers.lock() {
            Ok(servers) => match servers.get(&hostname) {
                Some(to) => {
                    let res = HttpPeer::new(to.to_owned(), false, hostname.to_string());
                    Box::pin(async move { Ok(Box::new(res)) })
                }
                None => {
                    // Default backend when no matching host is found
                    let res = HttpPeer::new("127.0.0.1:5500", false, "".to_string());
                    Box::pin(async move { Ok(Box::new(res)) })
                }
            },
            Err(e) => {
                println!("Error locking servers mutex in HttpProxy: {:?}", e);
                // Return default backend on lock error
                let res = HttpPeer::new("127.0.0.1:5500", false, "".to_string());
                Box::pin(async move { Ok(Box::new(res)) })
            }
        }
    }
}
