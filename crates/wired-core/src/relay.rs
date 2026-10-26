//! Serving a relay. Any node can serve one; it holds no keys and only sees
//! ciphertext, so it can run anywhere reachable: a public IP, or behind a
//! TLS-terminating proxy such as exe.dev's.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result, ensure};
use data_encoding::HEXLOWER;
use iroh::SecretKey;
use iroh_relay::{
    KeyCache,
    defaults::DEFAULT_KEY_CACHE_CAPACITY,
    server::{
        Access, AccessControl, ClientRequest, Metrics, QuicConfig, Server, ServerConfig,
        http_server::{Handlers, RelayService},
    },
};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, task::JoinHandle};

use crate::{invite::RelayInfo, tls};

mod http;

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
    /// The URL this node itself reaches it at: its local address. The public URL may not lead
    /// back to the host it is served from: behind a proxy (on exe.dev it resolves to the VM's
    /// internal address, where nothing serves HTTPS), or a router without hairpin NAT.
    pub(crate) self_url: String,
    /// Taken by `Node::close`, which shuts it down so its port is free again at once.
    running: std::sync::Mutex<Option<Running>>,
}

/// The relay's listener, the relay itself (its clients), and its address discovery.
struct Running {
    http: JoinHandle<()>,
    service: RelayService,
    qad: Option<Server>,
}

impl Running {
    async fn stop(self) {
        self.http.abort();
        let _ = self.http.await;
        self.service.shutdown().await;
        if let Some(qad) = self.qad {
            let _ = qad.shutdown().await;
        }
    }
}

impl ServedRelay {
    /// The URL this node uses for `url`: its local address when `url` is this relay's.
    pub(crate) fn reach<'a>(&'a self, url: &'a str) -> &'a str {
        if same_url(url, &self.info.url) { &self.self_url } else { url }
    }

    /// Stops it, disconnecting its clients so they look for another relay.
    pub(crate) async fn shutdown(&self) {
        let running = self.running.lock().unwrap().take();
        if let Some(running) = running {
            running.stop().await;
        }
    }
}

impl Drop for ServedRelay {
    /// A relay server dropped without shutting down stops accepting but keeps the clients it has,
    /// which then stay attached to it, looking connected. So it is shut down here too.
    fn drop(&mut self) {
        if let Some(running) = self.running.get_mut().unwrap().take()
            && let Ok(rt) = tokio::runtime::Handle::try_current()
        {
            rt.spawn(running.stop());
        }
    }
}

pub(crate) async fn start(serve: &RelayServe, key: &SecretKey, network_id: &[u8; 16]) -> Result<ServedRelay> {
    start_with(serve, key, network_id, http::ADMIT_TIMEOUT).await
}

async fn start_with(
    serve: &RelayServe,
    key: &SecretKey,
    network_id: &[u8; 16],
    admit_timeout: std::time::Duration,
) -> Result<ServedRelay> {
    let denied = Arc::new(RwLock::new(BTreeSet::new()));
    let access = Arc::new(RelayAccess { token: token(network_id), denied: denied.clone() });
    let service = RelayService::new(
        Handlers::default(),
        Default::default(),
        None,
        KeyCache::new(DEFAULT_KEY_CACHE_CAPACITY),
        access,
        Arc::new(Metrics::default()),
    );
    let (bind, tls_config, qad_bind) = match serve {
        RelayServe::Public { bind, qad_bind, .. } => (*bind, Some(tls::relay_server_config(key)?), *qad_bind),
        RelayServe::BehindProxy { bind, .. } => (*bind, None, None),
    };
    let listener = TcpListener::bind(bind).await.with_context(|| format!("start relay on {bind}"))?;
    let local_addr = listener.local_addr()?;
    let qad = match (qad_bind, &tls_config) {
        (Some(addr), Some(tls_config)) => {
            let mut q = QuicConfig::new(addr);
            q.server_config = Some(tls_config.clone());
            let mut config = ServerConfig::default();
            config.quic = Some(q);
            Some(Server::spawn(config).await.context("start relay address discovery")?)
        }
        _ => None,
    };
    let info = match serve {
        RelayServe::Public { public_host, .. } => {
            let host = match public_host {
                Some(h) => h.clone(),
                None => crate::node::detect_host().await,
            };
            RelayInfo {
                url: origin(&format!("https://{}:{}", url_host(&host), local_addr.port()))?,
                pin: Some(*key.public().as_bytes()),
                qad_port: qad.as_ref().and_then(|q| q.quic_addr()).map(|a| a.port()),
                owner: Some(*key.public().as_bytes()),
            }
        }
        RelayServe::BehindProxy { url, .. } => {
            RelayInfo { url: origin(url)?, pin: None, qad_port: None, owner: Some(*key.public().as_bytes()) }
        }
    };
    let tls = tls_config.map(|c| tokio_rustls::TlsAcceptor::from(Arc::new(c)));
    let http = http::serve(listener, tls, service.clone(), admit_timeout);
    let ip = match local_addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    // A public relay's certificate is pinned by key, so the local address verifies as well.
    let scheme = if info.pin.is_some() { "https" } else { "http" };
    let self_url = format!("{scheme}://{}", SocketAddr::new(ip, local_addr.port()));
    let running = Running { http, service, qad };
    Ok(ServedRelay { info, local_addr, denied, self_url, running: std::sync::Mutex::new(Some(running)) })
}

/// `[v6]` for IPv6 literals, as URLs and `host:port` need.
pub(crate) fn url_host(host: &str) -> String {
    if host.contains(':') { format!("[{host}]") } else { host.to_string() }
}

/// Longest relay URL accepted. Listings travel in every snapshot and invite.
pub(crate) const MAX_URL: usize = 256;

/// Checks that `url` is a relay origin (`https://host[:port]`, or `http://` for
/// testing) and returns its canonical form, without a trailing slash.
pub(crate) fn origin(url: &str) -> Result<String> {
    ensure!(url.len() <= MAX_URL, "relay url is longer than {MAX_URL} bytes");
    let parsed: url::Url = url.parse().with_context(|| format!("bad relay url {url}"))?;
    ensure!(matches!(parsed.scheme(), "https" | "http"), "relay url must be https:// (or http:// for testing)");
    ensure!(
        parsed.has_host()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.path() == "/"
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "relay url must be an origin, like https://host"
    );
    let url = parsed.as_str().trim_end_matches('/').to_string();
    ensure!(url.len() <= MAX_URL, "relay url is longer than {MAX_URL} bytes");
    url.parse::<iroh::RelayUrl>().with_context(|| format!("bad relay url {url}"))?;
    Ok(url)
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

    /// Sends `request` to `addr` and returns the response head.
    async fn http(addr: SocketAddr, request: &str) -> (tokio::net::TcpStream, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(request.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut b = [0u8; 1];
            assert_eq!(s.read(&mut b).await.unwrap(), 1, "closed early: {}", String::from_utf8_lossy(&head));
            head.push(b[0]);
        }
        (s, String::from_utf8(head).unwrap())
    }

    /// A stranger that upgrades to a WebSocket and then never finishes the relay
    /// handshake (it has no token) is cut off, rather than held forever.
    #[tokio::test]
    async fn a_connection_that_is_never_admitted_is_closed() {
        use tokio::io::AsyncReadExt;

        let serve = RelayServe::BehindProxy { bind: "127.0.0.1:0".parse().unwrap(), url: "http://127.0.0.1".into() };
        let timeout = std::time::Duration::from_secs(1);
        let relay = start_with(&serve, &SecretKey::generate(), &[3; 16], timeout).await.unwrap();
        let (_, ping) = http(relay.local_addr, "GET /ping HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(ping.starts_with("HTTP/1.1 200"), "{ping}");

        let upgrade = "GET /relay HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
            Sec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n";
        let (mut s, head) = http(relay.local_addr, upgrade).await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        let closed = tokio::time::timeout(timeout * 5, async {
            let mut buf = [0u8; 256];
            while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
        })
        .await;
        assert!(closed.is_ok(), "an unadmitted connection is still open");
        relay.shutdown().await;
    }

    /// A relay dropped without `Node::close`, as when a first join fails, must not keep its
    /// clients: they would stay attached to it, looking connected, and miss the one that replaces it.
    #[tokio::test]
    async fn dropping_a_relay_disconnects_its_clients() {
        use n0_future::StreamExt;

        let key = SecretKey::generate();
        let serve = RelayServe::BehindProxy { bind: "127.0.0.1:0".parse().unwrap(), url: "http://127.0.0.1".into() };
        let relay = start(&serve, &key, &[3; 16]).await.unwrap();
        let url: iroh::RelayUrl = format!("http://{}", relay.local_addr).parse().unwrap();
        let mut client =
            iroh_relay::client::ClientBuilder::new(url, SecretKey::generate(), iroh::dns::DnsResolver::new())
                .tls_client_config(iroh::tls::CaTlsConfig::default().client_config(tls::provider()).unwrap())
                .auth_token(token(&[3; 16]))
                .connect()
                .await
                .unwrap();
        drop(relay);
        let gone = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while let Some(Ok(_)) = client.next().await {}
        })
        .await;
        assert!(gone.is_ok(), "the client is still connected to a relay that was dropped");
    }

    #[test]
    fn same_url_ignores_a_trailing_slash() {
        assert!(same_url("https://r.example/", "https://r.example"));
        assert!(!same_url("https://r.example", "https://r.example:7443"));
    }

    #[test]
    fn url_host_brackets_ipv6() {
        assert_eq!(url_host("::1"), "[::1]");
        assert_eq!(url_host("10.0.0.1"), "10.0.0.1");
    }

    /// A node reaches the relay it serves at its local address, not its public URL, which may
    /// not lead back to the host; other relays keep their URL.
    #[tokio::test]
    async fn reach_maps_only_our_relay_to_its_local_address() {
        let serve =
            RelayServe::BehindProxy { bind: "0.0.0.0:0".parse().unwrap(), url: "https://robin.exe.xyz/".into() };
        let relay = start(&serve, &SecretKey::generate(), &[3; 16]).await.unwrap();
        assert_eq!(relay.info.url, "https://robin.exe.xyz");
        let local = format!("http://127.0.0.1:{}", relay.local_addr.port());
        assert_eq!(relay.self_url, local, "an unspecified bind is reached at loopback, over plain http");
        assert_eq!(relay.reach("https://robin.exe.xyz/"), local);
        assert_eq!(relay.reach("https://other.example"), "https://other.example");
        relay.shutdown().await;
    }

    /// A public relay's certificate is pinned by key, so its local address is reached over https.
    #[tokio::test]
    async fn public_relay_is_reached_locally_over_https() {
        let serve = RelayServe::Public {
            bind: "127.0.0.1:0".parse().unwrap(),
            qad_bind: None,
            public_host: Some("vps.example.com".into()),
        };
        let relay = start(&serve, &SecretKey::generate(), &[3; 16]).await.unwrap();
        let port = relay.local_addr.port();
        assert_eq!(relay.info.url, format!("https://vps.example.com:{port}"));
        assert_eq!(relay.reach(&relay.info.url), format!("https://127.0.0.1:{port}"));
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn behind_proxy_url_must_be_an_http_origin() {
        let key = SecretKey::generate();
        for url in ["https://r.example/relay", "https://r.example/?x=1", "ftp://r.example"] {
            let serve = RelayServe::BehindProxy { bind: "127.0.0.1:0".parse().unwrap(), url: url.into() };
            assert!(start(&serve, &key, &[3; 16]).await.is_err(), "{url} was accepted");
        }
    }
}
