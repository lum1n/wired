//! Serving a relay. Any node can serve one; it holds no keys and only sees
//! ciphertext, so it can run anywhere reachable: a public IP, or behind a
//! TLS-terminating proxy such as exe.dev's.

use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result, ensure};
use data_encoding::HEXLOWER;
use iroh::SecretKey;
use iroh_relay::server::{
    Access, AccessControl, CertConfig, ClientRequest, QuicConfig, RelayConfig, Server, ServerConfig, TlsConfig,
};
use sha2::{Digest, Sha256};

use crate::{invite::RelayInfo, tls};

/// How this node serves a relay.
#[derive(Debug, Clone)]
pub enum RelayServe {
    /// Directly on a public host: HTTPS on `bind` with a certificate made from
    /// this node's key (clients pin it), and QUIC address discovery on `qad_bind`.
    Public {
        bind: SocketAddr,
        qad_bind: Option<SocketAddr>,
        /// Host name or IP clients use. Detected from the default route if unset.
        public_host: Option<String>,
    },
    /// Behind a proxy that terminates TLS (exe.dev, nginx, Caddy): plain HTTP
    /// on `bind`, reached by clients at `url`. The proxy must forward `/relay`
    /// (a WebSocket) and `/ping` at the root of `url` to `bind`.
    BehindProxy { bind: SocketAddr, url: String },
}

impl RelayServe {
    /// A public relay on the default ports: TCP 7443 for HTTPS, UDP 7842 for address discovery.
    pub fn public() -> Self {
        Self::Public {
            bind: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 7443)),
            qad_bind: Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 7842))),
            public_host: None,
        }
    }
}

/// Bearer token nodes present to the network's relays. It keeps strangers off
/// the relays' bandwidth; it is not what protects traffic (that is end to end).
pub fn token(network_id: &[u8; 16]) -> String {
    let mut h = Sha256::new();
    h.update(b"wired/1 relay-token");
    h.update(network_id);
    HEXLOWER.encode(&h.finalize()[..16])
}

/// Admits nodes with the network's token whose key is not revoked.
#[derive(Debug)]
pub(crate) struct RelayAccess {
    token: String,
    pub(crate) denied: Arc<RwLock<BTreeSet<[u8; 32]>>>,
}

impl AccessControl for RelayAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        if request.auth_token().as_deref() != Some(self.token.as_str()) {
            return Access::Deny { reason: Some("not a member of this network".into()) };
        }
        if self.denied.read().unwrap().contains(request.endpoint_id().as_bytes()) {
            return Access::Deny { reason: Some("revoked".into()) };
        }
        Access::Allow
    }
}

/// A running relay.
pub(crate) struct ServedRelay {
    pub(crate) info: RelayInfo,
    /// Where it listens (for `BehindProxy`, what the proxy forwards to).
    pub(crate) local_addr: SocketAddr,
    pub(crate) denied: Arc<RwLock<BTreeSet<[u8; 32]>>>,
    /// Taken by `Node::close`, which shuts it down so its port is free again at once.
    pub(crate) server: std::sync::Mutex<Option<Server>>,
}

pub(crate) async fn start(serve: &RelayServe, key: &SecretKey, network_id: &[u8; 16]) -> Result<ServedRelay> {
    let denied = Arc::new(RwLock::new(BTreeSet::new()));
    let access = Arc::new(RelayAccess { token: token(network_id), denied: denied.clone() });
    let mut config = ServerConfig::default();
    let (server, info, local_addr) = match serve {
        RelayServe::Public { bind, qad_bind, public_host } => {
            let tls_config = tls::relay_server_config(key)?;
            let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
            relay.tls = Some(TlsConfig::new(*bind, CertConfig::Manual { server_config: tls_config.clone() }));
            relay.access = access;
            config.relay = Some(relay);
            config.quic = qad_bind.map(|addr| {
                let mut q = QuicConfig::new(addr);
                q.server_config = Some(tls_config);
                q
            });
            let server = Server::spawn(config).await.context("start relay")?;
            let https = server.https_addr().context("relay has no https address")?;
            let host = match public_host {
                Some(h) => h.clone(),
                None => crate::node::detect_host().await,
            };
            let info = RelayInfo {
                url: format!("https://{}:{}", url_host(&host), https.port()),
                pin: Some(*key.public().as_bytes()),
                qad_port: server.quic_addr().map(|a| a.port()),
                owner: Some(*key.public().as_bytes()),
            };
            (server, info, https)
        }
        RelayServe::BehindProxy { bind, url } => {
            let parsed: url::Url = url.parse().with_context(|| format!("bad relay url {url}"))?;
            ensure!(matches!(parsed.scheme(), "https" | "http"), "relay url must be https:// (or http:// for testing)");
            ensure!(parsed.path() == "/" && parsed.query().is_none(), "relay url must be an origin, like https://host");
            let mut relay = RelayConfig::new(*bind);
            relay.access = access;
            config.relay = Some(relay);
            let server = Server::spawn(config).await.context("start relay")?;
            let http = server.http_addr().context("relay has no http address")?;
            let info = RelayInfo {
                url: parsed.as_str().trim_end_matches('/').to_string(),
                pin: None,
                qad_port: None,
                owner: Some(*key.public().as_bytes()),
            };
            (server, info, http)
        }
    };
    Ok(ServedRelay { info, local_addr, denied, server: std::sync::Mutex::new(Some(server)) })
}

/// `[v6]` for IPv6 literals, as URLs and `host:port` need.
pub(crate) fn url_host(host: &str) -> String {
    if host.contains(':') { format!("[{host}]") } else { host.to_string() }
}

/// Two relay URLs name the same relay (ignoring a trailing slash).
pub(crate) fn same_url(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_depends_on_network() {
        assert_eq!(token(&[1; 16]), token(&[1; 16]));
        assert_ne!(token(&[1; 16]), token(&[2; 16]));
        assert_eq!(token(&[1; 16]).len(), 32);
    }
}
