use async_trait::async_trait;
use pingora::http::Version;
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorType, Result};
use pingora_proxy::{ProxyHttp, Session};

use crate::proxy::http::HttpProxy;
use crate::proxy::https::HttpsProxy;
use crate::proxy::tcp::is_database_domain;

pub mod http;
pub mod https;
pub mod manager;
pub mod tcp;
pub mod utils;

/// Proxy struct that implements both HTTP and HTTPS proxy logic
#[derive(Clone)]
pub struct Proxy {
    http_proxy: HttpProxy,
    https_proxy: HttpsProxy,
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let hostname = match session.req_header().uri.authority() {
            Some(auth) => auth.host().to_string(),
            None => return Err(Error::new(ErrorType::HTTPStatus(400))),
        };

        // Check if this is a database domain
        if is_database_domain(&hostname) {
            // Let the database proxy handle it
            return Ok(false);
        }

        // Let the regular proxy handle it
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Check if this is an HTTP/2 connection
        if session.req_header().version == Version::HTTP_2 {
            self.https_proxy.upstream_peer(session, ctx).await
        } else {
            self.http_proxy.upstream_peer(session, ctx).await
        }
    }
}
