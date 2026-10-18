//! UniFFI surface for Swift. `Wired.swift` (generated) plus the hand-written
//! wrapper in `Sources/Wired` sit on top of this.

use std::{net::SocketAddr, sync::Arc};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::{Mutex, Notify},
};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum WiredError {
    #[error("{message}")]
    Failed { message: String },
}

impl From<anyhow::Error> for WiredError {
    fn from(e: anyhow::Error) -> Self {
        Self::Failed { message: format!("{e:#}") }
    }
}

impl From<std::io::Error> for WiredError {
    fn from(e: std::io::Error) -> Self {
        Self::Failed { message: e.to_string() }
    }
}

type Res<T> = Result<T, WiredError>;

#[derive(uniffi::Enum)]
pub enum PathKind {
    Direct,
    Relay,
}

#[derive(uniffi::Record)]
pub struct JoinOptions {
    pub name: String,
    /// Defaults to the WIRED_INVITE environment variable.
    #[uniffi(default = None)]
    pub invite: Option<String>,
    #[uniffi(default = None)]
    pub state_dir: Option<String>,
    #[uniffi(default = false)]
    pub ephemeral: bool,
}

#[derive(uniffi::Record)]
pub struct AnchorOptions {
    pub name: String,
    #[uniffi(default = None)]
    pub bind_host: Option<String>,
    /// UDP port for peers and TCP port for the relay; 0 = any.
    #[uniffi(default = 7443)]
    pub port: u16,
    /// UDP port for address discovery; 0 = any.
    #[uniffi(default = 7842)]
    pub qad_port: u16,
    #[uniffi(default = false)]
    pub no_qad: bool,
    #[uniffi(default = None)]
    pub public_host: Option<String>,
    /// Run as a replica of the network this invite is for.
    #[uniffi(default = None)]
    pub replica_of: Option<String>,
    #[uniffi(default = None)]
    pub state_dir: Option<String>,
    #[uniffi(default = false)]
    pub ephemeral: bool,
}

#[derive(uniffi::Record)]
pub struct MemberInfo {
    pub name: String,
    pub id: String,
    pub anchor: bool,
}

fn common(mut b: wired::Builder, state_dir: Option<String>, ephemeral: bool) -> wired::Builder {
    if let Some(d) = state_dir {
        b = b.state_dir(d);
    }
    if ephemeral {
        b = b.ephemeral();
    }
    b
}

/// Joins a network as a member.
#[uniffi::export(async_runtime = "tokio")]
pub async fn join(options: JoinOptions) -> Res<Arc<WiredNode>> {
    let mut b = wired::Node::builder(options.name);
    if let Some(inv) = options.invite {
        b = b.invite(inv.parse()?);
    }
    let node = common(b, options.state_dir, options.ephemeral).spawn().await?;
    Ok(Arc::new(WiredNode { node }))
}

/// Starts an anchor on a publicly reachable host.
#[uniffi::export(async_runtime = "tokio")]
pub async fn anchor(options: AnchorOptions) -> Res<Arc<WiredNode>> {
    let host: std::net::IpAddr = options
        .bind_host
        .as_deref()
        .unwrap_or("0.0.0.0")
        .parse()
        .map_err(|e: std::net::AddrParseError| WiredError::Failed { message: e.to_string() })?;
    let cfg = wired::AnchorConfig {
        bind: SocketAddr::new(host, options.port),
        relay_bind: SocketAddr::new(host, options.port),
        qad_bind: (!options.no_qad).then(|| SocketAddr::new(host, options.qad_port)),
        public_host: options.public_host,
        replica_of: options.replica_of.map(|i| i.parse()).transpose()?,
    };
    let b = wired::Node::builder(options.name).anchor(cfg);
    let node = common(b, options.state_dir, options.ephemeral).spawn().await?;
    Ok(Arc::new(WiredNode { node }))
}

#[derive(uniffi::Object)]
pub struct WiredNode {
    node: wired::Node,
}

#[uniffi::export(async_runtime = "tokio")]
impl WiredNode {
    pub fn name(&self) -> String {
        self.node.name().to_string()
    }

    pub fn id(&self) -> String {
        self.node.id().to_string()
    }

    /// The network invite; it is a credential.
    pub fn invite(&self) -> String {
        self.node.invite()
    }

    pub fn is_anchor(&self) -> bool {
        self.node.is_anchor()
    }

    pub fn is_root(&self) -> bool {
        self.node.is_root()
    }

    pub fn members(&self) -> Vec<MemberInfo> {
        self.node
            .members()
            .into_iter()
            .map(|m| MemberInfo { name: m.name, id: m.id.to_string(), anchor: m.anchor })
            .collect()
    }

    /// Root only: removes a node now; returns the new invite.
    pub fn revoke(&self, name: String) -> Res<String> {
        Ok(self.node.revoke(&name)?)
    }

    /// Root only: replaces the invite; returns the new one.
    pub fn rotate_invite(&self) -> Res<String> {
        Ok(self.node.rotate_invite()?)
    }

    /// Root only: lets the replica anchor with this id join.
    pub fn approve_anchor(&self, id: String) -> Res<()> {
        let id = id.parse::<wired::PublicKey>().map_err(|e| WiredError::Failed { message: e.to_string() })?;
        Ok(self.node.approve_anchor(id)?)
    }

    /// Opens a stream to `service@node`.
    pub async fn dial(&self, target: String) -> Res<Arc<WiredStream>> {
        Ok(WiredStream::new(self.node.dial(&target).await?))
    }

    /// `allow`: node names that may connect; nil allows every member.
    #[uniffi::method(default(allow = None))]
    pub fn listen(&self, service: String, allow: Option<Vec<String>>) -> Res<Arc<WiredListener>> {
        let ln = match allow {
            Some(a) => self.node.listen_allow(&service, a)?,
            None => self.node.listen(&service)?,
        };
        Ok(Arc::new(WiredListener { ln: Mutex::new(Some(ln)), closed: Notify::new() }))
    }

    /// Forwards streams for `service` to a local TCP address.
    #[uniffi::method(default(allow = None))]
    pub fn expose(&self, service: String, target: String, allow: Option<Vec<String>>) -> Res<Arc<WiredTask>> {
        let task = match allow {
            Some(a) => self.node.expose_allow(&service, target, a)?,
            None => self.node.expose(&service, target)?,
        };
        Ok(Arc::new(WiredTask { local_addr: None, task: std::sync::Mutex::new(Some(task)) }))
    }

    /// Listens on a local TCP address and forwards to `service@node`.
    pub async fn forward(&self, local: String, target: String) -> Res<Arc<WiredTask>> {
        let task = self.node.forward(local, &target).await?;
        let local_addr = task.local_addr().map(|a| a.to_string());
        Ok(Arc::new(WiredTask { local_addr, task: std::sync::Mutex::new(Some(task)) }))
    }

    pub fn path(&self, node: String) -> Option<PathKind> {
        self.node.path(&node).map(|p| match p {
            wired::PathKind::Direct => PathKind::Direct,
            wired::PathKind::Relay => PathKind::Relay,
        })
    }

    pub async fn close(&self) {
        self.node.close().await;
    }
}

#[derive(uniffi::Object)]
pub struct WiredListener {
    ln: Mutex<Option<wired::Listener>>,
    closed: Notify,
}

#[uniffi::export(async_runtime = "tokio")]
impl WiredListener {
    /// The next stream, or nil once the listener or node is closed.
    pub async fn accept(&self) -> Res<Option<Arc<WiredStream>>> {
        let mut guard = self.ln.lock().await;
        let Some(ln) = guard.as_mut() else { return Ok(None) };
        let stream = tokio::select! {
            s = ln.accept() => s,
            _ = self.closed.notified() => None,
        };
        match stream {
            Some(s) => Ok(Some(WiredStream::new(s))),
            None => {
                guard.take();
                Ok(None)
            }
        }
    }

    /// Stops accepting; a pending `accept()` returns nil.
    pub fn close(&self) {
        self.closed.notify_one();
        if let Ok(mut g) = self.ln.try_lock() {
            g.take();
        }
    }
}

#[derive(uniffi::Object)]
pub struct WiredStream {
    peer_name: String,
    peer_id: String,
    reader: Mutex<ReadHalf<wired::Stream>>,
    writer: Mutex<WriteHalf<wired::Stream>>,
}

impl WiredStream {
    fn new(s: wired::Stream) -> Arc<Self> {
        let peer = s.peer().clone();
        let (r, w) = tokio::io::split(s);
        Arc::new(Self {
            peer_name: peer.name,
            peer_id: peer.id.to_string(),
            reader: Mutex::new(r),
            writer: Mutex::new(w),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl WiredStream {
    pub fn peer_name(&self) -> String {
        self.peer_name.clone()
    }

    pub fn peer_id(&self) -> String {
        self.peer_id.clone()
    }

    /// Up to `max` bytes; nil at end of stream.
    pub async fn read(&self, max: u32) -> Res<Option<Vec<u8>>> {
        let mut buf = vec![0u8; max.clamp(1, 1 << 20) as usize];
        let n = self.reader.lock().await.read(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        Ok(Some(buf))
    }

    pub async fn write(&self, data: Vec<u8>) -> Res<()> {
        self.writer.lock().await.write_all(&data).await?;
        Ok(())
    }

    /// Half-close: no more writes; the peer sees end of stream.
    pub async fn finish(&self) -> Res<()> {
        self.writer.lock().await.shutdown().await?;
        Ok(())
    }
}

#[derive(uniffi::Object)]
pub struct WiredTask {
    local_addr: Option<String>,
    task: std::sync::Mutex<Option<wired::Task>>,
}

#[uniffi::export]
impl WiredTask {
    pub fn local_addr(&self) -> Option<String> {
        self.local_addr.clone()
    }

    pub fn close(&self) {
        self.task.lock().unwrap().take();
    }
}
