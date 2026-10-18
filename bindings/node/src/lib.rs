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
    /// Host or IP put in the invite.
    pub public_host: Option<String>,
    /// Run as a replica of the network this invite is for.
    pub replica_of: Option<String>,
    pub state_dir: Option<String>,
    pub ephemeral: Option<bool>,
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

fn common(mut b: wired::Builder, state_dir: Option<String>, ephemeral: Option<bool>) -> wired::Builder {
    if let Some(d) = state_dir {
        b = b.state_dir(d);
    }
    if ephemeral.unwrap_or(false) {
        b = b.ephemeral();
    }
    b
}

#[napi]
pub async fn join(opts: JoinOptions) -> Result<WiredNode> {
    let mut b = wired::Node::builder(opts.name);
    if let Some(inv) = opts.invite {
        b = b.invite(inv.parse().map_err(anyhow_napi)?);
    }
    let node = common(b, opts.state_dir, opts.ephemeral).spawn().await.map_err(anyhow_napi)?;
    Ok(WiredNode { node })
}

#[napi]
pub async fn anchor(opts: AnchorOptions) -> Result<WiredNode> {
    let host: std::net::IpAddr = opts.bind_host.as_deref().unwrap_or("0.0.0.0").parse().map_err(to_napi)?;
    let p = port(opts.port, 7443)?;
    let cfg = wired::AnchorConfig {
        bind: SocketAddr::new(host, p),
        relay_bind: SocketAddr::new(host, p),
        qad_bind: (!opts.no_qad.unwrap_or(false))
            .then(|| port(opts.qad_port, 7842).map(|q| SocketAddr::new(host, q)))
            .transpose()?,
        public_host: opts.public_host,
        replica_of: opts.replica_of.map(|i| i.parse()).transpose().map_err(anyhow_napi)?,
    };
    let b = wired::Node::builder(opts.name).anchor(cfg);
    let node = common(b, opts.state_dir, opts.ephemeral).spawn().await.map_err(anyhow_napi)?;
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
