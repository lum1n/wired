//! The embedded node: public API and startup.

use std::{
    collections::{BTreeSet, HashMap},
    fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex, RwLock, Weak},
    task::{Context as TaskCx, Poll},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use iroh::{
    Endpoint, EndpointAddr, PublicKey, RelayMap, RelayMode, RelayUrl, SecretKey,
    address_lookup::MemoryLookup,
    endpoint::{Connection, NetReportConfig, RecvStream, SendStream, presets},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tracing::{info, warn};

use crate::{
    anchor::AnchorState,
    cert,
    invite::{AnchorInfo, Invite, NetworkSecret, RelayInfo},
    peer::is_fatal,
    proto::{ALPN, Cert, Role, Snapshot},
    relay::{self, RelayServe, ServedRelay},
    state::{self, AnchorDisk, MemberDisk},
    tls,
};

const DEFAULT_PORT: u16 = 7443;

/// Settings for running a node as an anchor. An anchor holds authority (the
/// root key, or a replica of the network state); it does not need to be
/// reachable from the internet. Reachability comes from relays (see
/// [`Builder::relay`]), which any node can serve.
#[derive(Debug, Clone)]
pub struct AnchorConfig {
    /// UDP socket for peer QUIC traffic.
    pub bind: SocketAddr,
    /// Host name or IP others can use to reach `bind` directly, if any.
    /// Detected from the default route if unset.
    pub public_host: Option<String>,
    /// Run as a replica of the network this invite is for. Its key must be
    /// approved on the root anchor (`wired approve <id>`) before it serves.
    pub replica_of: Option<Invite>,
}

impl Default for AnchorConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_PORT),
            public_host: None,
            replica_of: None,
        }
    }
}

/// Builds a [`Node`].
#[derive(Debug, Default)]
pub struct Builder {
    name: String,
    invite: Option<Invite>,
    anchor: Option<AnchorConfig>,
    secret_key: Option<SecretKey>,
    state_dir: Option<PathBuf>,
    ephemeral: bool,
    relay_only: bool,
    relay: Option<RelayServe>,
}

impl Builder {
    /// Network invite. Falls back to the `WIRED_INVITE` environment variable.
    pub fn invite(mut self, invite: Invite) -> Self {
        self.invite = Some(invite);
        self
    }

    /// Run as an anchor: admit members, own (root) or replicate the network state.
    pub fn anchor(mut self, config: AnchorConfig) -> Self {
        self.anchor = Some(config);
        self
    }

    /// Serve a relay for the network. A member's relay is listed once it
    /// joins; to join *through* it, add it on the root first (`add_relay`).
    pub fn relay(mut self, serve: RelayServe) -> Self {
        self.relay = Some(serve);
        self
    }

    /// Use this identity instead of the one stored in the state directory.
    pub fn secret_key(mut self, key: SecretKey) -> Self {
        self.secret_key = Some(key);
        self
    }

    /// Where keys and cached state live. Defaults to `$XDG_CONFIG_HOME/wired`.
    pub fn state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(dir.into());
        self
    }

    /// Keep everything in memory: no key file, no cache, no admin socket.
    pub fn ephemeral(mut self) -> Self {
        self.ephemeral = true;
        self
    }

    /// Test hook: send all traffic through the relay, never direct.
    #[doc(hidden)]
    pub fn relay_only(mut self) -> Self {
        self.relay_only = true;
        self
    }

    pub async fn spawn(self) -> Result<Node> {
        ensure!(valid_name(&self.name), "invalid node name {:?}: use 1-63 of [a-z0-9-]", self.name);
        #[cfg(unix)]
        ignore_sigpipe();
        let dir = self.state_dir.clone().unwrap_or_else(state::default_dir);
        let key = match (self.secret_key.clone(), self.ephemeral) {
            (Some(k), _) => k,
            (None, true) => SecretKey::generate(),
            (None, false) => state::load_or_create_key(&dir, &self.name)?,
        };
        let dir = (!self.ephemeral).then_some(dir);
        match self.anchor.clone() {
            Some(cfg) => spawn_anchor(self, cfg, key, dir).await,
            None => spawn_member(self, key, dir).await,
        }
    }
}

/// Writes to a socket the peer already closed raise SIGPIPE, which kills
/// the process unless it is handled. Rust binaries, Go and Node ignore it;
/// other hosts (Swift apps, C programs) may not, and some of the I/O happens
/// inside dependencies we cannot change. So ignore it, but only if the host
/// still has the default (terminating) disposition.
#[cfg(unix)]
fn ignore_sigpipe() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: querying and setting a signal disposition; no handler code runs.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut old) == 0 && old.sa_sigaction == libc::SIG_DFL {
                libc::signal(libc::SIGPIPE, libc::SIG_IGN);
            }
        }
    });
}

/// Who is on the other end of a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub name: String,
    pub id: PublicKey,
}

/// A member of the network, as listed by [`Node::members`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub id: PublicKey,
    pub anchor: bool,
}

/// How traffic to a peer currently flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Direct,
    Relay,
}

/// An embedded Wired node. Cheap to clone.
#[derive(Clone)]
pub struct Node {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    /// Ourselves, for spawning work from `&self` methods.
    pub(crate) me: Weak<Inner>,
    /// The runtime the node was started on. Sync API calls (from JS, cgo or
    /// Swift threads) spawn through it, since they have no runtime of their own.
    pub(crate) rt: tokio::runtime::Handle,
    pub(crate) name: String,
    pub(crate) ep: Endpoint,
    pub(crate) network_id: [u8; 16],
    /// The root anchor's key: the network's trust anchor.
    pub(crate) root: PublicKey,
    /// The join secret this node knows (members: from the invite).
    pub(crate) secret: RwLock<NetworkSecret>,
    /// Our certificate; `None` until the first join.
    pub(crate) cert: RwLock<Option<Cert>>,
    /// Latest network state. Authoritative on the root, replicated elsewhere.
    pub(crate) snap: RwLock<Arc<Snapshot>>,
    pub(crate) services: Mutex<HashMap<String, Service>>,
    pub(crate) peers: Mutex<HashMap<PublicKey, Peer>>,
    pub(crate) anchor: Option<AnchorState>,
    /// The relay this node serves, if any.
    pub(crate) relay: Option<ServedRelay>,
    pub(crate) lookup: MemoryLookup,
    pub(crate) pinned: tls::Pinned,
    /// Relay URLs the endpoint is configured with.
    pub(crate) known_relays: Mutex<BTreeSet<String>>,
    pub(crate) dir: Option<PathBuf>,
    pub(crate) tasks: Mutex<Vec<JoinHandle<()>>>,
}

pub(crate) struct Service {
    pub(crate) tx: mpsc::Sender<Stream>,
    /// Node names allowed to open this service; `None` allows every member.
    pub(crate) allow: Option<BTreeSet<String>>,
}

#[derive(Clone)]
pub(crate) struct Peer {
    pub(crate) conn: Connection,
    pub(crate) name: String,
    /// Who issued the peer's certificate; revoking it drops this peer.
    pub(crate) issuer: [u8; 32],
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("name", &self.inner.name)
            .field("id", &self.inner.ep.id())
            .field("anchor", &self.inner.anchor.is_some())
            .finish()
    }
}

/// Node and service names: DNS-label safe so `service.node.wired` works as a host.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Splits `service@node`.
pub fn parse_target(target: &str) -> Result<(&str, &str)> {
    let (service, node) =
        target.split_once('@').with_context(|| format!("target {target:?} must look like service@node"))?;
    ensure!(valid_name(service), "invalid service name {service:?}");
    ensure!(valid_name(node), "invalid node name {node:?}");
    Ok((service, node))
}

impl Node {
    pub fn builder(name: impl Into<String>) -> Builder {
        Builder { name: name.into(), ..Default::default() }
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn id(&self) -> PublicKey {
        self.inner.ep.id()
    }

    /// An invite for this network. On the root anchor it carries the current
    /// join secret; hand it to new nodes and treat it like a password.
    pub fn invite(&self) -> String {
        self.inner.invite().encode()
    }

    pub fn is_anchor(&self) -> bool {
        self.inner.anchor.is_some()
    }

    /// Whether this is the root anchor, where new nodes join and admin changes happen.
    pub fn is_root(&self) -> bool {
        self.inner.is_root()
    }

    /// The network's relays, as last synced from an anchor.
    pub fn relays(&self) -> Vec<RelayInfo> {
        self.inner.snapshot().relays.clone()
    }

    /// The relay this node serves: its public URL and the local address it
    /// listens on (for `BehindProxy`, where the proxy should forward to).
    pub fn served_relay(&self) -> Option<(String, SocketAddr)> {
        self.inner.relay.as_ref().map(|r| (r.info.url.clone(), r.local_addr))
    }

    /// Every member of the network, as last synced from an anchor.
    pub fn members(&self) -> Vec<Member> {
        let snap = self.inner.snap.read().unwrap().clone();
        snap.members
            .iter()
            .filter_map(|(name, key)| {
                Some(Member { name: name.clone(), id: PublicKey::from_bytes(key).ok()?, anchor: snap.is_anchor(key) })
            })
            .collect()
    }

    /// Accept streams for `service` from any member. Dropping the listener unregisters it.
    pub fn listen(&self, service: &str) -> Result<Listener> {
        self.register(service, None)
    }

    /// Accept streams for `service` only from the named nodes.
    pub fn listen_allow<I, S>(&self, service: &str, allow: I) -> Result<Listener>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let allow: BTreeSet<String> = allow.into_iter().map(Into::into).collect();
        for n in &allow {
            ensure!(valid_name(n), "invalid node name {n:?} in allowlist");
        }
        self.register(service, Some(allow))
    }

    fn register(&self, service: &str, allow: Option<BTreeSet<String>>) -> Result<Listener> {
        ensure!(valid_name(service), "invalid service name {service:?}");
        let mut services = self.inner.services.lock().unwrap();
        ensure!(!services.contains_key(service), "service {service:?} is already listening");
        let (tx, rx) = mpsc::channel(64);
        services.insert(service.to_string(), Service { tx, allow });
        Ok(Listener { service: service.to_string(), rx, node: Arc::downgrade(&self.inner) })
    }

    /// Open a byte stream to `service@node`.
    pub async fn dial(&self, target: &str) -> Result<Stream> {
        let (service, node) = parse_target(target)?;
        match self.inner.dial(service, node).await {
            Ok(s) => Ok(s),
            Err(first) if !is_fatal(&first) => {
                // The pooled connection may be stale; retry once on a fresh one.
                tracing::debug!(%target, "dial failed, retrying: {first:#}");
                self.inner.dial(service, node).await.with_context(|| format!("dial {target}"))
            }
            Err(e) => Err(e.context(format!("dial {target}"))),
        }
    }

    /// Forward streams for `service` to a local TCP address, e.g. an existing HTTP server.
    pub fn expose(&self, service: &str, target: impl Into<String>) -> Result<Task> {
        Ok(spawn_expose(&self.inner.rt, self.listen(service)?, target.into()))
    }

    /// Like [`Node::expose`], but only the named nodes may connect.
    pub fn expose_allow<I, S>(&self, service: &str, target: impl Into<String>, allow: I) -> Result<Task>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Ok(spawn_expose(&self.inner.rt, self.listen_allow(service, allow)?, target.into()))
    }

    /// Listen on a local TCP address and forward each connection to `target` (`service@node`).
    pub async fn forward(&self, local: impl tokio::net::ToSocketAddrs, target: &str) -> Result<Task> {
        parse_target(target)?;
        let listener = TcpListener::bind(local).await.context("bind forward listener")?;
        let local_addr = listener.local_addr()?;
        let node = self.clone();
        let target = target.to_string();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else { break };
                let node = node.clone();
                let target = target.clone();
                tokio::spawn(async move {
                    match node.dial(&target).await {
                        Ok(mut stream) => {
                            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
                        }
                        Err(e) => warn!(%target, "forward: {e:#}"),
                    }
                });
            }
        });
        Ok(Task { handle, local_addr: Some(local_addr) })
    }

    /// Whether traffic to `node` currently goes direct or through a relay,
    /// if there is a live connection to it.
    pub fn path(&self, node: &str) -> Option<PathKind> {
        let key = *self.inner.snap.read().unwrap().members.get(node)?;
        let peer = self.inner.live_peer(PublicKey::from_bytes(&key).ok()?)?;
        let paths = peer.conn.paths();
        let selected = paths.iter().find(|p| p.is_selected())?;
        Some(if selected.is_ip() { PathKind::Direct } else { PathKind::Relay })
    }

    /// Shuts the node down. Pending `Listener::accept` calls return `None`.
    pub async fn close(&self) {
        for t in self.inner.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
        self.inner.services.lock().unwrap().clear();
        self.inner.ep.close().await;
    }
}

fn spawn_expose(rt: &tokio::runtime::Handle, mut ln: Listener, target: String) -> Task {
    let handle = rt.spawn(async move {
        while let Some(mut stream) = ln.accept().await {
            let target = target.clone();
            tokio::spawn(async move {
                match TcpStream::connect(&target).await {
                    Ok(mut tcp) => {
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
                    }
                    Err(e) => warn!(%target, "expose: connect failed: {e}"),
                }
            });
        }
    });
    Task { handle, local_addr: None }
}

/// Accepts streams for one service.
pub struct Listener {
    service: String,
    rx: mpsc::Receiver<Stream>,
    node: Weak<Inner>,
}

impl Listener {
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The next incoming stream, or `None` once the node has shut down.
    pub async fn accept(&mut self) -> Option<Stream> {
        self.rx.recv().await
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(inner) = self.node.upgrade() {
            inner.services.lock().unwrap().remove(&self.service);
        }
    }
}

/// A background task (expose/forward). Stops when dropped.
pub struct Task {
    handle: JoinHandle<()>,
    local_addr: Option<SocketAddr>,
}

impl Task {
    /// For `forward`: the bound local address.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// A bidirectional byte stream to a service on a peer.
pub struct Stream {
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
    pub(crate) peer: PeerInfo,
}

impl Stream {
    pub fn peer(&self) -> &PeerInfo {
        &self.peer
    }
}

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream").field("peer", &self.peer).finish()
    }
}

impl AsyncRead for Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buf).map_err(io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Shared state helpers

impl Inner {
    pub(crate) fn spawn(&self, fut: impl Future<Output = ()> + Send + 'static) {
        self.tasks.lock().unwrap().push(self.rt.spawn(fut));
    }

    pub(crate) fn is_root(&self) -> bool {
        self.ep.id() == self.root
    }

    pub(crate) fn snapshot(&self) -> Arc<Snapshot> {
        self.snap.read().unwrap().clone()
    }

    pub(crate) fn invite(&self) -> Invite {
        let snap = self.snapshot();
        Invite::new(
            self.network_id,
            *self.root.as_bytes(),
            self.secret.read().unwrap().clone(),
            snap.anchors.clone(),
            snap.relays.clone(),
        )
    }

    /// Writes what this node needs to restart (and, on the root, the invite).
    pub(crate) fn persist(&self) {
        let Some(dir) = &self.dir else { return };
        let snapshot = (*self.snapshot()).clone();
        let res = match &self.anchor {
            Some(a) => state::save(
                &state::anchor_path(dir),
                &AnchorDisk {
                    network_id: self.network_id,
                    root: *self.root.as_bytes(),
                    secret: self.secret.read().unwrap().clone(),
                    snapshot,
                    approved: a.approved.lock().unwrap().clone(),
                    cert: if self.is_root() { None } else { self.cert.read().unwrap().clone() },
                },
            )
            .and_then(|()| state::save_invite(dir, &self.invite().encode())),
            None => match self.cert.read().unwrap().clone() {
                Some(cert) => state::save(
                    &state::member_path(dir, &self.name),
                    &MemberDisk { network_id: self.network_id, root: *self.root.as_bytes(), cert, snapshot },
                ),
                None => Ok(()),
            },
        };
        if let Err(e) = res {
            warn!("saving state failed: {e:#}");
        }
    }

    /// Brings the endpoint in line with the network: connects to new relays,
    /// drops removed ones (never our own), and refreshes anchor addresses.
    pub(crate) async fn learn_network(&self, snap: &Snapshot) {
        let own = self.relay.as_ref().map(|r| norm_url(&r.info.url));
        let (add, remove) = {
            let mut known = self.known_relays.lock().unwrap();
            let want: BTreeSet<String> = snap.relays.iter().map(|r| norm_url(&r.url)).chain(own.clone()).collect();
            let add: Vec<RelayInfo> = snap.relays.iter().filter(|r| known.insert(norm_url(&r.url))).cloned().collect();
            let remove: Vec<String> = known.iter().filter(|u| !want.contains(*u)).cloned().collect();
            for u in &remove {
                known.remove(u);
            }
            (add, remove)
        };
        let token = relay::token(&self.network_id);
        for r in add {
            if let Some(pin) = r.pin.and_then(|p| PublicKey::from_bytes(&p).ok()) {
                self.pinned.write().unwrap().push(pin);
            }
            match relay_config(&r, &token) {
                Ok(config) => {
                    self.ep.insert_relay(config.url.clone(), Arc::new(config)).await;
                }
                Err(e) => warn!(url = %r.url, "ignoring relay: {e:#}"),
            }
        }
        for u in remove {
            if let Ok(url) = u.parse::<RelayUrl>() {
                self.ep.remove_relay(&url).await;
            }
        }
        let relays = relay_urls(snap);
        for a in &snap.anchors {
            if let Ok(id) = PublicKey::from_bytes(&a.id)
                && id != self.ep.id()
            {
                self.lookup.add_endpoint_info(anchor_addr(id, &relays, &a.addrs).await);
            }
        }
    }

    /// Relay URLs to reach a peer through: every relay in the network.
    pub(crate) fn relay_urls(&self) -> Vec<RelayUrl> {
        relay_urls(&self.snapshot())
    }
}

fn norm_url(u: &str) -> String {
    u.trim_end_matches('/').to_string()
}

fn relay_urls(snap: &Snapshot) -> Vec<RelayUrl> {
    snap.relays.iter().filter_map(|r| r.url.parse().ok()).collect()
}

fn relay_config(r: &RelayInfo, token: &str) -> Result<iroh::RelayConfig> {
    let url: RelayUrl = r.url.parse().with_context(|| format!("bad relay url {}", r.url))?;
    Ok(iroh::RelayConfig::new(url, r.qad_port.map(iroh_relay::RelayQuicConfig::new)).with_auth_token(token))
}

async fn anchor_addr(id: PublicKey, relays: &[RelayUrl], hosts: &[String]) -> EndpointAddr {
    let mut addr = EndpointAddr::from_parts(id, relays.iter().cloned().map(iroh::TransportAddr::Relay));
    for host in hosts {
        match tokio::net::lookup_host(host).await {
            Ok(ips) => {
                for ip in ips {
                    addr = addr.with_ip_addr(ip);
                }
            }
            Err(e) => warn!(%host, "cannot resolve anchor address: {e}"),
        }
    }
    addr
}

// ---------------------------------------------------------------------------
// Startup

/// `extra` entries whose key `key` is not already in `base`, appended.
fn merge<T: Clone, K: PartialEq>(mut base: Vec<T>, extra: &[T], key: impl Fn(&T) -> K) -> Vec<T> {
    for e in extra {
        if !base.iter().any(|b| key(b) == key(e)) {
            base.push(e.clone());
        }
    }
    base
}

struct Bound {
    ep: Endpoint,
    lookup: MemoryLookup,
    pinned: tls::Pinned,
    known: BTreeSet<String>,
}

async fn bind_endpoint(
    key: SecretKey,
    network_id: &[u8; 16],
    relays: &[RelayInfo],
    bind: Option<SocketAddr>,
    relay_only: bool,
) -> Result<Bound> {
    let pins = relays.iter().filter_map(|r| r.pin.and_then(|p| PublicKey::from_bytes(&p).ok())).collect();
    let pinned: tls::Pinned = Arc::new(RwLock::new(pins));
    let token = relay::token(network_id);
    let map: RelayMap = relays.iter().map(|r| relay_config(r, &token)).collect::<Result<_>>()?;
    let lookup = MemoryLookup::new();
    let mut net_report = NetReportConfig::default();
    // Relays behind proxies serve only `/relay` and `/ping`; no `/generate_204`.
    net_report.captive_portal_check = false;
    let mut b = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Custom(map))
        .ca_tls_config(tls::ca_tls_config(pinned.clone()))
        .net_report_config(net_report)
        .address_lookup(lookup.clone());
    if let Some(addr) = bind {
        b = b.clear_ip_transports().bind_addr(addr)?;
    } else if relay_only {
        b = b.clear_ip_transports();
    }
    let ep = b.bind().await?;
    Ok(Bound { ep, lookup, pinned, known: relays.iter().map(|r| norm_url(&r.url)).collect() })
}

#[allow(clippy::too_many_arguments)]
fn new_inner(
    name: String,
    bound: Bound,
    network_id: [u8; 16],
    root: PublicKey,
    secret: NetworkSecret,
    cert: Option<Cert>,
    snap: Snapshot,
    anchor: Option<AnchorState>,
    relay: Option<ServedRelay>,
    dir: Option<PathBuf>,
) -> Arc<Inner> {
    Arc::new_cyclic(|me| Inner {
        me: me.clone(),
        rt: tokio::runtime::Handle::current(),
        name,
        ep: bound.ep,
        network_id,
        root,
        secret: RwLock::new(secret),
        cert: RwLock::new(cert),
        snap: RwLock::new(Arc::new(snap)),
        services: Mutex::new(HashMap::new()),
        peers: Mutex::new(HashMap::new()),
        anchor,
        relay,
        lookup: bound.lookup,
        pinned: bound.pinned,
        known_relays: Mutex::new(bound.known),
        dir,
        tasks: Mutex::new(Vec::new()),
    })
}

async fn start_relay(b: &Builder, key: &SecretKey, network_id: &[u8; 16]) -> Result<Option<ServedRelay>> {
    match &b.relay {
        Some(serve) => Ok(Some(relay::start(serve, key, network_id).await?)),
        None => Ok(None),
    }
}

async fn spawn_member(b: Builder, key: SecretKey, dir: Option<PathBuf>) -> Result<Node> {
    let invite = match b.invite.clone() {
        Some(i) => i,
        None => std::env::var("WIRED_INVITE").context("no invite given and WIRED_INVITE is not set")?.parse()?,
    };
    let root = PublicKey::from_bytes(&invite.root).map_err(|e| anyhow!("bad root key in invite: {e}"))?;
    let disk = match &dir {
        Some(d) => state::load::<MemberDisk>(&state::member_path(d, &b.name))?
            .filter(|m| m.network_id == invite.network_id && m.root == invite.root),
        None => None,
    };
    let (cert, mut snap) = match disk {
        Some(d) if d.cert.body.node_id == *key.public().as_bytes() => (Some(d.cert), d.snapshot),
        _ => (None, Snapshot::default()),
    };
    snap.anchors = merge(snap.anchors, &invite.anchors, |a| a.id);
    snap.relays = merge(snap.relays, &invite.relays, |r| norm_url(&r.url));

    let relay = start_relay(&b, &key, &invite.network_id).await?;
    let relays =
        merge(snap.relays.clone(), &relay.iter().map(|r| r.info.clone()).collect::<Vec<_>>(), |r| norm_url(&r.url));
    let bound = bind_endpoint(key, &invite.network_id, &relays, None, b.relay_only).await?;
    let inner = new_inner(b.name, bound, invite.network_id, root, invite.secret, cert, snap, None, relay, dir);
    inner.learn_network(&inner.snapshot()).await;

    match inner.open_session_any().await {
        Ok(session) => inner.spawn(inner.clone().control_loop(Some(session))),
        Err(e) => {
            let cached = inner.cert.read().unwrap().as_ref().is_some_and(|c| cert::remaining(c) > 0);
            if is_fatal(&e) || !cached {
                inner.ep.close().await;
                return Err(e.context("could not join the network"));
            }
            warn!("no anchor reachable, starting from cached state: {e:#}");
            inner.spawn(inner.clone().control_loop(None));
        }
    }
    inner.spawn(inner.clone().accept_loop());
    Ok(Node { inner })
}

async fn spawn_anchor(b: Builder, cfg: AnchorConfig, key: SecretKey, dir: Option<PathBuf>) -> Result<Node> {
    let disk = match &dir {
        Some(d) => state::load::<AnchorDisk>(&state::anchor_path(d))?,
        None => None,
    };
    let me = *key.public().as_bytes();
    let (network_id, root, secret, snap, approved, cert) = match (&cfg.replica_of, disk) {
        (None, Some(d)) => {
            ensure!(d.root == me, "this state directory belongs to a replica; pass its invite with --replica-of");
            (d.network_id, d.root, d.secret, d.snapshot, d.approved, None)
        }
        (None, None) => (rand::random(), me, NetworkSecret::generate(), Snapshot::default(), BTreeSet::new(), None),
        (Some(inv), Some(d)) if d.network_id == inv.network_id && d.root == inv.root => {
            let snap = Snapshot {
                anchors: merge(d.snapshot.anchors.clone(), &inv.anchors, |a| a.id),
                relays: merge(d.snapshot.relays.clone(), &inv.relays, |r| norm_url(&r.url)),
                ..d.snapshot
            };
            (d.network_id, d.root, d.secret, snap, BTreeSet::new(), d.cert)
        }
        (Some(inv), _) => {
            ensure!(inv.root != me, "a replica cannot use the root's key");
            let snap = Snapshot { anchors: inv.anchors.clone(), relays: inv.relays.clone(), ..Default::default() };
            (inv.network_id, inv.root, inv.secret.clone(), snap, BTreeSet::new(), None)
        }
    };
    let root = PublicKey::from_bytes(&root).map_err(|e| anyhow!("bad root key: {e}"))?;
    let is_root = root == key.public();

    let relay = start_relay(&b, &key, &network_id).await?;
    let own_relay: Vec<RelayInfo> = relay.iter().map(|r| r.info.clone()).collect();
    let relays = merge(snap.relays.clone(), &own_relay, |r| norm_url(&r.url));
    let bind = (!b.relay_only).then_some(cfg.bind);
    let bound = bind_endpoint(key.clone(), &network_id, &relays, bind, b.relay_only).await?;
    let mut info = AnchorInfo { id: me, addrs: Vec::new() };
    if let Some(socket) = bound.ep.bound_sockets().first() {
        let host = match cfg.public_host.clone() {
            Some(h) => h,
            None => detect_host().await,
        };
        info.addrs.push(format!("{}:{}", relay::url_host(&host), socket.port()));
    }

    let mut snap = snap;
    let cert = if is_root {
        if let Some(owner) = snap.members.get(&b.name)
            && *owner != me
        {
            bail!("name {:?} belongs to another key in this network", b.name);
        }
        let mut next = snap.clone();
        next.members.retain(|_, k| *k != me);
        next.members.insert(b.name.clone(), me);
        next.anchors.retain(|a| a.id != me);
        next.anchors.insert(0, info.clone());
        // Our own relay replaces whatever we served last time.
        next.relays.retain(|r| r.owner != Some(me));
        next.relays.extend(own_relay);
        if next != snap {
            next.version += 1;
            snap = next;
        }
        Some(cert::issue(&key, None, network_id, key.public(), &b.name, Role::Anchor))
    } else {
        cert
    };

    let (updates, _) = watch::channel(Arc::new(snap.clone()));
    let anchor = AnchorState { info, approved: Mutex::new(approved), updates };
    let inner = new_inner(b.name, bound, network_id, root, secret, cert, snap, Some(anchor), relay, dir.clone());
    inner.learn_network(&inner.snapshot()).await;
    if let Some(r) = &inner.relay {
        *r.denied.write().unwrap() = inner.snapshot().denied.clone();
    }
    inner.persist();
    inner.spawn(inner.clone().accept_loop());

    if is_root {
        inner.spawn(inner.clone().renew_root_loop());
    } else {
        let session = match inner.open_session_any().await {
            Ok(s) => Some(s),
            Err(e) => {
                info!("replica not synced yet: {e:#}");
                None
            }
        };
        inner.spawn(inner.clone().control_loop(session));
    }
    let node = Node { inner };
    #[cfg(unix)]
    if let Some(d) = &dir {
        let handle = crate::admin::spawn(node.clone(), state::admin_socket(d))?;
        node.inner.tasks.lock().unwrap().push(handle);
    }
    Ok(node)
}

/// The IP of the interface holding the default route. Sends no packets.
pub(crate) async fn detect_host() -> String {
    let probe = async {
        let sock = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        sock.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).await?;
        io::Result::Ok(sock.local_addr()?.ip())
    };
    match probe.await {
        Ok(ip) if !ip.is_unspecified() => ip.to_string(),
        _ => Ipv4Addr::LOCALHOST.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid_name("laptop"));
        assert!(valid_name("api-2"));
        assert!(!valid_name(""));
        assert!(!valid_name("Laptop"));
        assert!(!valid_name("-x"));
        assert!(!valid_name("a.b"));
        assert_eq!(parse_target("api@laptop").unwrap(), ("api", "laptop"));
        assert!(parse_target("api").is_err());
    }
}
