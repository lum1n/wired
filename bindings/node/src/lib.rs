//! Native half of `@wired/node`. Streams cross into JS as socket descriptors
//! (see `wired::bridge`); `index.js` wraps them in `net.Socket`.

use std::{net::SocketAddr, os::fd::IntoRawFd, sync::Mutex};

use napi::bindgen_prelude::*;
use napi_derive::napi;

fn to_napi(e: impl std::fmt::Display) -> Error {
    Error::from_reason(format!("{e:#}"))
}

fn anyhow_napi(e: anyhow::Error) -> Error {
    Error::from_reason(format!("{e:#}"))
}

#[napi(object)]
pub struct JoinOptions {
    pub name: String,
    /// Defaults to the WIRED_INVITE environment variable.
    pub invite: Option<String>,
    pub state_dir: Option<String>,
    /// Keep keys in memory only.
    pub ephemeral: Option<bool>,
    /// Serve a relay behind a TLS-terminating proxy, reached at this URL
    /// (e.g. `https://robin.exe.xyz`). Needs `relayBind`.
    pub relay_url: Option<String>,
    /// Local address the relay listens on, e.g. `127.0.0.1:8790`.
    pub relay_bind: Option<String>,
    /// Testing: never connect directly, only through relays.
    pub relay_only: Option<bool>,
}

#[napi(object)]
pub struct AnchorOptions {
    pub name: String,
    /// Address to bind (default 0.0.0.0).
    pub bind_host: Option<String>,
    /// UDP port for peers and TCP port for the relay (default 7443, 0 = any).
    pub port: Option<u32>,
    /// UDP port for address discovery (default 7842, 0 = any).
    pub qad_port: Option<u32>,
    /// Disable QUIC address discovery.
    pub no_qad: Option<bool>,
    /// Host or IP others reach this machine at.
    pub public_host: Option<String>,
    /// Don't serve a relay (this machine isn't reachable from the internet).
    pub no_relay: Option<bool>,
    /// Serve the relay behind a TLS-terminating proxy at this URL instead. Needs `relayBind`.
    pub relay_url: Option<String>,
    pub relay_bind: Option<String>,
    /// Testing: never connect directly, only through relays.
    pub relay_only: Option<bool>,
    /// Run as a replica of the network this invite is for.
    pub replica_of: Option<String>,
    pub state_dir: Option<String>,
    pub ephemeral: Option<bool>,
}

#[napi(object)]
pub struct RelayEntry {
    pub url: String,
    /// Whether its certificate is pinned to a key (a self-signed relay) rather than CA-checked.
    pub pinned: bool,
    /// Id of the node serving it, when a member announced it.
    pub owner: Option<String>,
}

#[napi(object)]
pub struct ServedRelayInfo {
    pub url: String,
    pub local_addr: String,
}

#[napi(object)]
pub struct MemberInfo {
    pub name: String,
    pub id: String,
    pub anchor: bool,
}

#[napi(object)]
pub struct Accepted {
    pub fd: i32,
    pub peer_name: String,
    pub peer_id: String,
}

fn port(p: Option<u32>, default: u16) -> Result<u16> {
    u16::try_from(p.unwrap_or(default as u32)).map_err(|_| Error::from_reason("port out of range"))
}

fn common(
    mut b: wired::Builder,
    state_dir: Option<String>,
    ephemeral: Option<bool>,
    relay_only: Option<bool>,
) -> wired::Builder {
    if let Some(d) = state_dir {
        b = b.state_dir(d);
    }
    if ephemeral.unwrap_or(false) {
        b = b.ephemeral();
    }
    if relay_only.unwrap_or(false) {
        b = b.relay_only();
    }
    b
}

fn behind_proxy(url: Option<String>, bind: Option<String>) -> Result<Option<wired::RelayServe>> {
    match (url, bind) {
        (Some(url), Some(bind)) => {
            Ok(Some(wired::RelayServe::BehindProxy { bind: bind.parse().map_err(to_napi)?, url }))
        }
        (None, None) => Ok(None),
        _ => Err(Error::from_reason("relayUrl and relayBind go together")),
    }
}

#[napi]
pub async fn join(opts: JoinOptions) -> Result<WiredNode> {
    let mut b = wired::Node::builder(opts.name);
    if let Some(inv) = opts.invite {
        b = b.invite(inv.parse().map_err(anyhow_napi)?);
    }
    if let Some(serve) = behind_proxy(opts.relay_url, opts.relay_bind)? {
        b = b.relay(serve);
    }
    let node = common(b, opts.state_dir, opts.ephemeral, opts.relay_only).spawn().await.map_err(anyhow_napi)?;
    Ok(WiredNode { node })
}

#[napi]
pub async fn anchor(opts: AnchorOptions) -> Result<WiredNode> {
    let host: std::net::IpAddr = opts.bind_host.as_deref().unwrap_or("0.0.0.0").parse().map_err(to_napi)?;
    let p = port(opts.port, 7443)?;
    let cfg = wired::AnchorConfig {
        bind: SocketAddr::new(host, p),
        public_host: opts.public_host.clone(),
        replica_of: opts.replica_of.map(|i| i.parse()).transpose().map_err(anyhow_napi)?,
    };
    let serve = match (behind_proxy(opts.relay_url, opts.relay_bind)?, opts.no_relay.unwrap_or(false)) {
        (Some(s), _) => Some(s),
        (None, true) => None,
        (None, false) => Some(wired::RelayServe::Public {
            bind: SocketAddr::new(host, p),
            qad_bind: (!opts.no_qad.unwrap_or(false))
                .then(|| port(opts.qad_port, 7842).map(|q| SocketAddr::new(host, q)))
                .transpose()?,
            public_host: opts.public_host,
        }),
    };
    let mut b = wired::Node::builder(opts.name).anchor(cfg);
    if let Some(s) = serve {
        b = b.relay(s);
    }
    let node = common(b, opts.state_dir, opts.ephemeral, opts.relay_only).spawn().await.map_err(anyhow_napi)?;
    Ok(WiredNode { node })
}

#[napi]
pub struct WiredNode {
    node: wired::Node,
}

#[napi]
impl WiredNode {
    #[napi(getter)]
    pub fn name(&self) -> String {
        self.node.name().to_string()
    }

    #[napi(getter)]
    pub fn id(&self) -> String {
        self.node.id().to_string()
    }

    #[napi(getter)]
    pub fn invite(&self) -> String {
        self.node.invite()
    }

    #[napi(getter)]
    pub fn is_anchor(&self) -> bool {
        self.node.is_anchor()
    }

    #[napi(getter)]
    pub fn is_root(&self) -> bool {
        self.node.is_root()
    }

    #[napi]
    pub fn members(&self) -> Vec<MemberInfo> {
        self.node
            .members()
            .into_iter()
            .map(|m| MemberInfo { name: m.name, id: m.id.to_string(), anchor: m.anchor })
            .collect()
    }

    #[napi]
    pub fn relays(&self) -> Vec<RelayEntry> {
        self.node
            .relays()
            .into_iter()
            .map(|r| RelayEntry {
                url: r.url,
                pinned: r.pin.is_some(),
                owner: r.owner.and_then(|o| wired::PublicKey::from_bytes(&o).ok()).map(|k| k.to_string()),
            })
            .collect()
    }

    /// The relay this node serves, if any.
    #[napi(getter)]
    pub fn served_relay(&self) -> Option<ServedRelayInfo> {
        self.node.served_relay().map(|(url, local)| ServedRelayInfo { url, local_addr: local.to_string() })
    }

    /// Root only: lists a relay (e.g. `https://robin.exe.xyz`) for the whole network.
    #[napi]
    pub fn add_relay(&self, url: String) -> Result<()> {
        self.node.add_relay(&url).map_err(anyhow_napi)
    }

    /// Root only: stops listing a relay.
    #[napi]
    pub fn remove_relay(&self, url: String) -> Result<()> {
        self.node.remove_relay(&url).map_err(anyhow_napi)
    }

    /// Root only: removes a node now and returns the new invite.
    #[napi]
    pub fn revoke(&self, name: String) -> Result<String> {
        self.node.revoke(&name).map_err(anyhow_napi)
    }

    /// Root only: replaces the invite.
    #[napi]
    pub fn rotate_invite(&self) -> Result<String> {
        self.node.rotate_invite().map_err(anyhow_napi)
    }

    /// Root only: allows a replica anchor with this id.
    #[napi]
    pub fn approve_anchor(&self, id: String) -> Result<()> {
        self.node.approve_anchor(id.parse().map_err(to_napi)?).map_err(anyhow_napi)
    }

    /// Opens a stream to `service@node`; returns a socket descriptor.
    #[napi]
    pub async fn dial(&self, target: String) -> Result<i32> {
        let stream = self.node.dial(&target).await.map_err(anyhow_napi)?;
        Ok(wired::bridge::stream_to_fd(stream).map_err(to_napi)?.into_raw_fd())
    }

    /// `allow`: node names that may connect; omit to allow every member.
    #[napi]
    pub fn listen(&self, service: String, allow: Option<Vec<String>>) -> Result<WiredListener> {
        let ln = match allow {
            Some(a) => self.node.listen_allow(&service, a),
            None => self.node.listen(&service),
        }
        .map_err(anyhow_napi)?;
        Ok(WiredListener { ln: tokio::sync::Mutex::new(Some(ln)), closed: Default::default() })
    }

    #[napi]
    pub fn expose(&self, service: String, target: String, allow: Option<Vec<String>>) -> Result<WiredTask> {
        let task = match allow {
            Some(a) => self.node.expose_allow(&service, target, a),
            None => self.node.expose(&service, target),
        }
        .map_err(anyhow_napi)?;
        Ok(WiredTask { local_addr: None, task: Mutex::new(Some(task)) })
    }

    #[napi]
    pub async fn forward(&self, local: String, target: String) -> Result<WiredTask> {
        let task = self.node.forward(local, &target).await.map_err(anyhow_napi)?;
        Ok(WiredTask { local_addr: task.local_addr().map(|a| a.to_string()), task: Mutex::new(Some(task)) })
    }

    /// "direct", "relay", or null when there is no connection to `node`.
    #[napi]
    pub fn path(&self, node: String) -> Option<String> {
        self.node.path(&node).map(|p| match p {
            wired::PathKind::Direct => "direct".into(),
            wired::PathKind::Relay => "relay".into(),
        })
    }

    #[napi]
    pub async fn close(&self) {
        self.node.close().await;
    }
}

#[napi]
pub struct WiredListener {
    ln: tokio::sync::Mutex<Option<wired::Listener>>,
    closed: tokio::sync::Notify,
}

#[napi]
impl WiredListener {
    /// The next stream, or null once the listener or node is closed.
    #[napi]
    pub async fn accept(&self) -> Result<Option<Accepted>> {
        let mut guard = self.ln.lock().await;
        let Some(ln) = guard.as_mut() else { return Ok(None) };
        let stream = tokio::select! {
            s = ln.accept() => s,
            _ = self.closed.notified() => None,
        };
        let Some(stream) = stream else {
            guard.take();
            return Ok(None);
        };
        let peer = stream.peer().clone();
        let fd = wired::bridge::stream_to_fd(stream).map_err(to_napi)?.into_raw_fd();
        Ok(Some(Accepted { fd, peer_name: peer.name, peer_id: peer.id.to_string() }))
    }

    /// Stops accepting and unregisters the service; a pending `accept()` resolves to null.
    #[napi]
    pub fn close(&self) {
        // notify_one stores a permit, so this also works if no accept() is pending yet.
        self.closed.notify_one();
        if let Ok(mut g) = self.ln.try_lock() {
            g.take();
        }
    }
}

#[napi]
pub struct WiredTask {
    local_addr: Option<String>,
    task: Mutex<Option<wired::Task>>,
}

#[napi]
impl WiredTask {
    #[napi(getter)]
    pub fn local_addr(&self) -> Option<String> {
        self.local_addr.clone()
    }

    #[napi]
    pub fn close(&self) {
        self.task.lock().unwrap().take();
    }
}
