//! Connections between nodes: authentication, the connection pool, services.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail, ensure};
use iroh::{
    EndpointAddr, PublicKey, TransportAddr,
    endpoint::{Connection, Incoming, RecvStream, SendStream},
};
use tracing::debug;

use crate::{
    cert::{self, Trust},
    frame,
    node::{Inner, Peer, PeerInfo, Stream},
    proto::{Cert, ErrorCode, JOIN_EXPORTER_LABEL, JOIN_MAC_CONTEXT, Open, PROTOCOL_VERSION, Reply, Snapshot},
};

pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a dial waits for an unknown name to show up in the network state.
const NAME_WAIT: Duration = Duration::from_secs(2);

/// An error reported by the other side.
#[derive(Debug, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct RemoteError {
    pub code: ErrorCode,
    pub message: String,
}

/// Whether retrying cannot help without operator action.
pub(crate) fn is_fatal(e: &anyhow::Error) -> bool {
    e.downcast_ref::<RemoteError>().is_some_and(|r| r.code.is_fatal())
}

pub(crate) fn reply_err(reply: Reply) -> anyhow::Error {
    match reply {
        Reply::Error { code, message } => RemoteError { code, message }.into(),
        other => anyhow!("unexpected reply: {other:?}"),
    }
}

/// Why a request was refused; becomes a [`Reply::Error`].
pub(crate) struct Refusal(pub ErrorCode, pub String);

impl From<Refusal> for Reply {
    fn from(Refusal(code, message): Refusal) -> Self {
        Reply::Error { code, message }
    }
}

fn err(code: ErrorCode, message: impl Into<String>) -> Reply {
    Reply::Error { code, message: message.into() }
}

/// Sends `open` on a fresh stream and reads the reply.
pub(crate) async fn request(conn: &Connection, open: &Open) -> Result<(SendStream, RecvStream, Reply)> {
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let (mut send, mut recv) = conn.open_bi().await?;
        frame::write(&mut send, open).await?;
        let reply: Reply = frame::read(&mut recv).await?;
        Ok((send, recv, reply))
    })
    .await
    .context("request timed out")?
}

impl Inner {
    pub(crate) fn trust<'a>(&self, snap: &'a Snapshot) -> Trust<'a> {
        Trust { root: self.root, network_id: self.network_id, denied: &snap.denied }
    }

    pub(crate) fn own_cert(&self) -> Result<Cert> {
        self.cert.read().unwrap().clone().context("this node has no certificate yet")
    }

    pub(crate) fn live_peer(&self, id: PublicKey) -> Option<Peer> {
        let mut peers = self.peers.lock().unwrap();
        match peers.get(&id) {
            Some(p) if p.conn.close_reason().is_none() => Some(p.clone()),
            Some(_) => {
                peers.remove(&id);
                None
            }
            None => None,
        }
    }

    pub(crate) fn add_peer(self: &Arc<Self>, conn: Connection, name: String, issuer: [u8; 32]) {
        let id = conn.remote_id();
        self.peers.lock().unwrap().insert(id, Peer { conn: conn.clone(), name: name.clone(), issuer });
        // Ends by itself when the connection closes, so it is not tracked in `tasks`.
        tokio::spawn(self.clone().serve_streams(conn, name));
    }

    /// Closes connections to revoked keys and to peers certified by revoked anchors.
    pub(crate) fn enforce_denied(&self, snap: &Snapshot) {
        self.peers.lock().unwrap().retain(|id, p| {
            let revoked = snap.denied.contains(id.as_bytes()) || snap.denied.contains(&p.issuer);
            if revoked {
                debug!(peer = %p.name, "closing connection to revoked node");
                p.conn.close(2u32.into(), b"revoked");
            }
            !revoked
        });
    }

    pub(crate) fn join_proof(&self, conn: &Connection) -> Result<[u8; 32]> {
        let mut exporter = [0u8; 32];
        conn.export_keying_material(&mut exporter, JOIN_EXPORTER_LABEL, b"")
            .map_err(|e| anyhow!("tls exporter: {e:?}"))?;
        let secret = self.secret.read().unwrap();
        Ok(secret.mac(&[JOIN_MAC_CONTEXT, self.ep.id().as_bytes(), &exporter]))
    }

    // --- dialing -------------------------------------------------------------

    pub(crate) async fn dial(self: &Arc<Self>, service: &str, node: &str) -> Result<Stream> {
        let key = self.member(node).await?;
        let id = PublicKey::from_bytes(&key).map_err(|e| anyhow!("{e}"))?;
        let peer = match self.live_peer(id) {
            Some(p) => p,
            None => self.connect_hello(id).await?,
        };
        ensure!(peer.name == node, "node {node:?} answered as {:?}", peer.name);
        let (send, recv, reply) = match request(&peer.conn, &Open::Service { name: service.to_string() }).await {
            Ok(r) => r,
            Err(e) => {
                self.peers.lock().unwrap().remove(&id);
                return Err(e);
            }
        };
        match reply {
            Reply::ServiceOk => Ok(Stream { send, recv, peer: PeerInfo { name: peer.name, id } }),
            other => Err(reply_err(other)),
        }
    }

    /// The key of the member called `node`. A node that joined a moment ago may not have
    /// reached us yet: the anchor pushes it within moments, so wait briefly for that.
    async fn member(&self, node: &str) -> Result<[u8; 32]> {
        let deadline = tokio::time::Instant::now() + NAME_WAIT;
        loop {
            // Registered before looking, so a snapshot arriving in between still wakes us.
            let changed = self.snap_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(key) = self.snapshot().members.get(node) {
                return Ok(*key);
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                bail!("unknown node {node:?}");
            }
        }
    }

    async fn connect_hello(self: &Arc<Self>, id: PublicKey) -> Result<Peer> {
        ensure!(id != self.ep.id(), "cannot dial ourselves");
        let addr = EndpointAddr::from_parts(id, self.relay_urls().into_iter().map(TransportAddr::Relay));
        let conn = self.ep.connect(addr, crate::proto::ALPN).await.context("connect")?;
        let open = Open::Hello { version: PROTOCOL_VERSION, cert: self.own_cert()? };
        let (_, _, reply) = request(&conn, &open).await?;
        let Reply::Hello { cert: theirs } = reply else { return Err(reply_err(reply)) };
        let snap = self.snapshot();
        cert::verify(&theirs, &self.trust(&snap), id).context("peer presented a bad certificate")?;
        let peer = Peer { conn: conn.clone(), name: theirs.body.name.clone(), issuer: theirs.body.issuer };
        self.add_peer(conn, peer.name.clone(), peer.issuer);
        Ok(peer)
    }

    // --- accepting -----------------------------------------------------------

    pub(crate) async fn accept_loop(self: Arc<Self>) {
        while let Some(incoming) = self.ep.accept().await {
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.handle_incoming(incoming).await {
                    debug!("incoming connection rejected: {e:#}");
                }
            });
        }
    }

    async fn handle_incoming(self: Arc<Self>, incoming: Incoming) -> Result<()> {
        let conn = incoming.await?;
        let (mut send, mut recv) =
            tokio::time::timeout(REQUEST_TIMEOUT, conn.accept_bi()).await.context("no hello")??;
        let open: Open = frame::read_limited(&mut recv, frame::MAX_UNAUTHENTICATED_FRAME).await?;
        let (reply, peer) = match open {
            Open::Join { .. } | Open::Hello { .. } => match self.authenticate(&conn, open) {
                Ok((reply, name, issuer)) => (reply, Some((name, issuer))),
                Err(r) => (r.into(), None),
            },
            _ => (err(ErrorCode::Unauthorized, "authenticate first"), None),
        };
        frame::write(&mut send, &reply).await?;
        let _ = send.finish();
        match peer {
            Some((name, issuer)) => {
                self.add_peer(conn, name, issuer);
                Ok(())
            }
            None => {
                // Give the reply a moment to reach the peer before closing.
                tokio::time::sleep(Duration::from_millis(200)).await;
                conn.close(1u32.into(), b"unauthorized");
                Err(reply_err(reply))
            }
        }
    }

    /// Handles `Join` or `Hello`; returns the reply, the peer's name and its issuer.
    fn authenticate(&self, conn: &Connection, open: Open) -> Result<(Reply, String, [u8; 32]), Refusal> {
        let own =
            || self.own_cert().map_err(|_| Refusal(ErrorCode::NotApproved, "this anchor is not ready yet".into()));
        match open {
            Open::Join { version, network_id, name, proof, anchor, relay } if self.anchor.is_some() => {
                let cert = self.admit(conn, version, network_id, &name, proof, anchor, relay)?;
                Ok((Reply::Joined { cert, anchor: own()? }, name, *self.ep.id().as_bytes()))
            }
            Open::Join { .. } => Err(Refusal(ErrorCode::Protocol, "not an anchor".into())),
            Open::Hello { version, cert } => {
                if version != PROTOCOL_VERSION {
                    return Err(Refusal(ErrorCode::BadVersion, format!("unsupported version {version}")));
                }
                let snap = self.snapshot();
                cert::verify(&cert, &self.trust(&snap), conn.remote_id())
                    .map_err(|e| Refusal(ErrorCode::Unauthorized, format!("{e:#}")))?;
                Ok((Reply::Hello { cert: own()? }, cert.body.name, cert.body.issuer))
            }
            _ => Err(Refusal(ErrorCode::Protocol, "expected Join or Hello".into())),
        }
    }

    /// Serves streams the peer opens on an authenticated connection.
    async fn serve_streams(self: Arc<Self>, conn: Connection, peer_name: String) {
        let remote = conn.remote_id();
        while let Ok((send, recv)) = conn.accept_bi().await {
            let me = self.clone();
            let conn = conn.clone();
            let peer = PeerInfo { name: peer_name.clone(), id: remote };
            tokio::spawn(async move {
                if let Err(e) = me.handle_stream(&conn, send, recv, peer).await {
                    debug!("stream failed: {e:#}");
                }
            });
        }
        let mut peers = self.peers.lock().unwrap();
        if peers.get(&remote).is_some_and(|p| p.conn.stable_id() == conn.stable_id()) {
            peers.remove(&remote);
        }
    }

    async fn handle_stream(
        &self,
        conn: &Connection,
        mut send: SendStream,
        mut recv: RecvStream,
        peer: PeerInfo,
    ) -> Result<()> {
        // The peer may have been revoked since it authenticated.
        if self.snapshot().denied.contains(peer.id.as_bytes()) {
            conn.close(2u32.into(), b"revoked");
            return Ok(());
        }
        let open: Open = frame::read(&mut recv).await?;
        let reply = match open {
            Open::Service { name } => {
                let found = self.services.lock().unwrap().get(&name).map(|s| (s.tx.clone(), s.allow.clone()));
                match found {
                    Some((_, Some(allow))) if !allow.contains(&peer.name) => {
                        err(ErrorCode::Denied, format!("{} may not use {name:?} on {}", peer.name, self.name))
                    }
                    Some((tx, _)) => {
                        frame::write(&mut send, &Reply::ServiceOk).await?;
                        tx.send(Stream { send, recv, peer })
                            .await
                            .map_err(|_| anyhow!("service {name:?} stopped listening"))?;
                        return Ok(());
                    }
                    None => err(ErrorCode::NoSuchService, format!("no service {name:?} on {}", self.name)),
                }
            }
            Open::Watch if self.anchor.is_some() => return self.serve_watch(send, peer.id).await,
            open @ (Open::Join { .. } | Open::Hello { .. }) => match self.authenticate(conn, open) {
                Ok((reply, _, _)) => reply,
                Err(r) => r.into(),
            },
            Open::Watch => err(ErrorCode::Protocol, "not an anchor"),
        };
        frame::write(&mut send, &reply).await?;
        let _ = send.finish();
        Ok(())
    }
}
