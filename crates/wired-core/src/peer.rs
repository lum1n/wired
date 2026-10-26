//! Connections between nodes: authentication, the connection pool, services.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, ensure};
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
/// Longest wait between checks that a peer's certificate is still good. A timer doesn't
/// count time the machine sleeps, so a long one could fire well after the expiry.
const EXPIRY_CHECK: Duration = Duration::from_secs(60);
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

    /// Adds an authenticated connection, from the certificate the peer showed on it.
    pub(crate) fn add_peer(self: &Arc<Self>, conn: Connection, cert: &Cert) -> Peer {
        let peer = Peer {
            conn: conn.clone(),
            name: cert.body.name.clone(),
            issuer: cert.body.issuer,
            expires: Arc::new(AtomicU64::new(cert::valid_until(cert))),
        };
        self.peers.lock().unwrap().insert(conn.remote_id(), peer.clone());
        // Ends by itself when the connection closes, so it is not tracked in `tasks`.
        tokio::spawn(self.clone().serve_streams(peer.clone()));
        peer
    }

    /// Shows our certificate, just renewed, to every peer, so connections outlive the one they
    /// saw. Each answers with its own current certificate.
    pub(crate) fn announce_cert(&self) {
        let Some(me) = self.me.upgrade() else { return };
        let peers: Vec<Peer> = self.peers.lock().unwrap().values().cloned().collect();
        for peer in peers {
            let me = me.clone();
            self.rt.spawn(async move {
                if let Err(e) = me.rehello(&peer).await {
                    debug!(peer = %peer.name, "showing a renewed certificate failed: {e:#}");
                }
            });
        }
    }

    async fn rehello(&self, peer: &Peer) -> Result<()> {
        let open = Open::Hello { version: PROTOCOL_VERSION, cert: self.own_cert()? };
        let (_, _, reply) = request(&peer.conn, &open).await?;
        let Reply::Hello { cert: theirs } = reply else { return Err(reply_err(reply)) };
        cert::verify(&theirs, &self.trust(&self.snapshot()), peer.conn.remote_id())
            .context("peer presented a bad certificate")?;
        ensure!(theirs.body.name == peer.name, "{} answered as {:?}", peer.name, theirs.body.name);
        peer.expires.store(cert::valid_until(&theirs), Ordering::Relaxed);
        Ok(())
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

    /// The key of the member called `node`.
    async fn member(&self, node: &str) -> Result<[u8; 32]> {
        self.await_state(|s| s.members.get(node).copied()).await.with_context(|| format!("unknown node {node:?}"))
    }

    /// Whether `name` is registered to `key` in the network state.
    async fn is_member(&self, name: &str, key: &[u8; 32]) -> bool {
        self.await_state(|s| (s.members.get(name) == Some(key)).then_some(())).await.is_some()
    }

    /// Looks something up in the network state. A node that joined a moment ago may not
    /// have reached us yet: the anchor pushes it within moments, so wait briefly for that.
    async fn await_state<T>(&self, find: impl Fn(&Snapshot) -> Option<T>) -> Option<T> {
        let deadline = tokio::time::Instant::now() + NAME_WAIT;
        loop {
            // Registered before looking, so a snapshot arriving in between still wakes us.
            let changed = self.snap_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(found) = find(&self.snapshot()) {
                return Some(found);
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                return None;
            }
        }
    }

    pub(crate) async fn connect_hello(self: &Arc<Self>, id: PublicKey) -> Result<Peer> {
        ensure!(id != self.ep.id(), "cannot dial ourselves");
        let addr = EndpointAddr::from_parts(id, self.relay_urls().into_iter().map(TransportAddr::Relay));
        let conn = self.ep.connect(addr, crate::proto::ALPN).await.context("connect")?;
        let open = Open::Hello { version: PROTOCOL_VERSION, cert: self.own_cert()? };
        let (_, _, reply) = request(&conn, &open).await?;
        let Reply::Hello { cert: theirs } = reply else { return Err(reply_err(reply)) };
        let snap = self.snapshot();
        cert::verify(&theirs, &self.trust(&snap), id).context("peer presented a bad certificate")?;
        ensure!(
            self.is_member(&theirs.body.name, id.as_bytes()).await,
            "{:?} is not registered to that key",
            theirs.body.name
        );
        Ok(self.add_peer(conn, &theirs))
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
        let open: Open =
            tokio::time::timeout(REQUEST_TIMEOUT, frame::read_limited(&mut recv, frame::MAX_UNAUTHENTICATED_FRAME))
                .await
                .context("no hello")??;
        let (reply, peer) = match open {
            Open::Join { .. } | Open::Hello { .. } => match self.authenticate(&conn, open).await {
                Ok((reply, cert)) => (reply, Some(cert)),
                Err(r) => (r.into(), None),
            },
            _ => (err(ErrorCode::Unauthorized, "authenticate first"), None),
        };
        frame::write(&mut send, &reply).await?;
        let _ = send.finish();
        match peer {
            Some(cert) => {
                self.add_peer(conn, &cert);
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

    /// Handles `Join` or `Hello`; returns the reply and the peer's certificate (the one it
    /// showed, or the one it was just issued).
    async fn authenticate(&self, conn: &Connection, open: Open) -> Result<(Reply, Cert), Refusal> {
        let own =
            || self.own_cert().map_err(|_| Refusal(ErrorCode::NotApproved, "this anchor is not ready yet".into()));
        match open {
            Open::Join { version, network_id, name, proof, anchor, relay } if self.anchor.is_some() => {
                let cert = self.admit(conn, version, network_id, &name, proof, anchor, relay)?;
                Ok((Reply::Joined { cert: cert.clone(), anchor: own()? }, cert))
            }
            Open::Join { .. } => Err(Refusal(ErrorCode::Protocol, "not an anchor".into())),
            Open::Hello { version, cert } => {
                if version != PROTOCOL_VERSION {
                    return Err(Refusal(ErrorCode::BadVersion, format!("unsupported version {version}")));
                }
                let snap = self.snapshot();
                cert::verify(&cert, &self.trust(&snap), conn.remote_id())
                    .map_err(|e| Refusal(ErrorCode::Unauthorized, format!("{e:#}")))?;
                // An anchor may only certify a name for the key the root registered it to.
                if !self.is_member(&cert.body.name, &cert.body.node_id).await {
                    let msg = format!("{:?} is not registered to this key", cert.body.name);
                    return Err(Refusal(ErrorCode::Unauthorized, msg));
                }
                Ok((Reply::Hello { cert: own()? }, cert))
            }
            _ => Err(Refusal(ErrorCode::Protocol, "expected Join or Hello".into())),
        }
    }

    /// Serves streams the peer opens on an authenticated connection, until it closes or the
    /// peer's certificate expires.
    async fn serve_streams(self: Arc<Self>, peer: Peer) {
        let Peer { conn, name: peer_name, expires, .. } = peer;
        let remote = conn.remote_id();
        let expired = expiry(expires.clone());
        tokio::pin!(expired);
        loop {
            let (send, recv) = tokio::select! {
                accepted = conn.accept_bi() => match accepted {
                    Ok(s) => s,
                    Err(_) => break,
                },
                () = &mut expired => {
                    debug!(peer = %peer_name, "closing connection: its certificate expired");
                    conn.close(3u32.into(), b"certificate expired");
                    break;
                }
            };
            let me = self.clone();
            let conn = conn.clone();
            let expires = expires.clone();
            let peer = PeerInfo { name: peer_name.clone(), id: remote };
            tokio::spawn(async move {
                if let Err(e) = me.handle_stream(&conn, send, recv, peer, &expires).await {
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
        expires: &AtomicU64,
    ) -> Result<()> {
        // The peer may have been revoked since it authenticated.
        if self.snapshot().denied.contains(peer.id.as_bytes()) {
            conn.close(2u32.into(), b"revoked");
            return Ok(());
        }
        let open: Open =
            tokio::time::timeout(REQUEST_TIMEOUT, frame::read(&mut recv)).await.context("no request")??;
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
            // A renewal, or a renewed certificate shown: the connection lives on with it.
            open @ (Open::Join { .. } | Open::Hello { .. }) => match self.authenticate(conn, open).await {
                Ok((reply, cert)) => {
                    if cert.body.name == peer.name {
                        expires.store(cert::valid_until(&cert), Ordering::Relaxed);
                    }
                    reply
                }
                Err(r) => r.into(),
            },
            Open::Watch => err(ErrorCode::Protocol, "not an anchor"),
        };
        frame::write(&mut send, &reply).await?;
        let _ = send.finish();
        Ok(())
    }
}

/// Resolves once the time in `expires` (Unix seconds, which a renewal may move on) has passed.
async fn expiry(expires: Arc<AtomicU64>) {
    loop {
        let left = expires.load(Ordering::Relaxed).saturating_sub(cert::now_unix());
        if left == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_secs(left).min(EXPIRY_CHECK)).await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use iroh::{Endpoint, SecretKey, endpoint::presets};

    use super::*;
    use crate::{AnchorConfig, Node, proto::Role};

    async fn root() -> Node {
        let lo: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let cfg = AnchorConfig { bind: lo, public_host: Some("127.0.0.1".into()), replica_of: None };
        Node::builder("root").anchor(cfg).ephemeral().spawn().await.unwrap()
    }

    /// Presents `cert` from `key` to `node`, and returns its answer.
    async fn hello(node: &Node, key: &SecretKey, cert: Cert) -> Reply {
        let ep = Endpoint::builder(presets::Minimal)
            .secret_key(key.clone())
            .alpns(vec![crate::proto::ALPN.to_vec()])
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let addr = EndpointAddr::new(node.id()).with_ip_addr(node.inner.ep.bound_sockets()[0]);
        let conn = ep.connect(addr, crate::proto::ALPN).await.unwrap();
        let (_, _, reply) = request(&conn, &Open::Hello { version: PROTOCOL_VERSION, cert }).await.unwrap();
        ep.close().await;
        reply
    }

    /// An anchor (here the root itself) certifying a name for a key the name isn't registered to.
    #[tokio::test(flavor = "multi_thread")]
    async fn hello_refuses_a_certificate_whose_name_belongs_to_another_key() {
        let root = root().await;
        let alice = Node::builder("alice").invite(root.invite().parse().unwrap()).ephemeral().spawn().await.unwrap();
        let (issuer, net) = (root.inner.ep.secret_key(), root.inner.network_id);
        let mallory = SecretKey::generate();
        let forged = cert::issue(issuer, None, net, mallory.public(), "alice", Role::Member);
        let reply = hello(&root, &mallory, forged).await;
        assert!(matches!(reply, Reply::Error { code: ErrorCode::Unauthorized, .. }), "{reply:?}");
        // The same check passes for the key the name is registered to.
        let real = cert::issue(issuer, None, net, alice.id(), "alice", Role::Member);
        let alice_key = alice.inner.ep.secret_key().clone();
        alice.close().await;
        assert!(matches!(hello(&root, &alice_key, real).await, Reply::Hello { .. }));
        root.close().await;
    }

    /// A connection lasts as long as the certificate last shown on it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_connection_closes_when_the_peers_certificate_expires_unless_renewed() {
        let root = root().await;
        let alice = Node::builder("alice").invite(root.invite().parse().unwrap()).ephemeral().spawn().await.unwrap();
        let alice_key = alice.inner.ep.secret_key().clone();
        alice.close().await;
        let (issuer, net) = (root.inner.ep.secret_key(), root.inner.network_id);
        let expiring_in = |secs| {
            cert::issue_until(issuer, None, net, alice_key.public(), "alice", Role::Member, cert::now_unix() + secs)
        };

        let ep = Endpoint::builder(presets::Minimal)
            .secret_key(alice_key.clone())
            .alpns(vec![crate::proto::ALPN.to_vec()])
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let addr = EndpointAddr::new(root.id()).with_ip_addr(root.inner.ep.bound_sockets()[0]);
        let conn = ep.connect(addr, crate::proto::ALPN).await.unwrap();
        let hello = |secs| Open::Hello { version: PROTOCOL_VERSION, cert: expiring_in(secs) };
        let started = tokio::time::Instant::now();
        let (_, _, reply) = request(&conn, &hello(3)).await.unwrap();
        assert!(matches!(reply, Reply::Hello { .. }), "{reply:?}");

        // Showing a renewed certificate keeps the connection past the first one's expiry...
        let (_, _, reply) = request(&conn, &hello(8)).await.unwrap();
        assert!(matches!(reply, Reply::Hello { .. }), "{reply:?}");
        tokio::time::sleep_until(started + Duration::from_secs(5)).await;
        assert!(conn.close_reason().is_none(), "closed while the renewed certificate was good");

        // ...until that one expires too.
        tokio::time::timeout(Duration::from_secs(10), conn.closed()).await.expect("still open after expiry");
        assert!(started.elapsed() >= Duration::from_secs(6));
        ep.close().await;
        root.close().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_renewed_certificate_reaches_connected_peers() {
        let root = root().await;
        let laptop = Node::builder("laptop").invite(root.invite().parse().unwrap()).ephemeral().spawn().await.unwrap();
        let expires = cert::now_unix() + 1000;
        let renewed = cert::issue_until(
            root.inner.ep.secret_key(),
            None,
            root.inner.network_id,
            laptop.id(),
            "laptop",
            Role::Member,
            expires,
        );
        *laptop.inner.cert.write().unwrap() = Some(renewed);
        laptop.inner.announce_cert();
        let mut seen = false;
        for _ in 0..100 {
            let peer = root.inner.live_peer(laptop.id()).expect("the root is connected to the laptop");
            if peer.expires.load(Ordering::Relaxed) == expires {
                seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(seen, "the root still holds the laptop's old certificate");
        laptop.close().await;
        root.close().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_anchor_limits_the_watches_one_node_holds() {
        let root = root().await;
        let laptop = Node::builder("laptop").invite(root.invite().parse().unwrap()).ephemeral().spawn().await.unwrap();
        let conn = laptop.inner.live_peer(root.id()).expect("laptop is connected to the root").conn;
        // The laptop's control session holds one already.
        let mut held = Vec::new();
        for _ in 1..crate::anchor::MAX_WATCHES {
            let (send, recv, reply) = request(&conn, &Open::Watch).await.unwrap();
            assert!(matches!(reply, Reply::State(_)), "{reply:?}");
            held.push((send, recv));
        }
        let (_, _, reply) = request(&conn, &Open::Watch).await.unwrap();
        assert!(matches!(reply, Reply::Error { code: ErrorCode::Protocol, .. }), "{reply:?}");
        // Closing one frees its place.
        drop(held.pop());
        let mut freed = false;
        for _ in 0..50 {
            if let (_, _, Reply::State(_)) = request(&conn, &Open::Watch).await.unwrap() {
                freed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(freed);
        laptop.close().await;
        root.close().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn members_take_only_newer_snapshots_the_root_signed() {
        let root = root().await;
        let bob = Node::builder("bob").invite(root.invite().parse().unwrap()).ephemeral().spawn().await.unwrap();
        let laptop = Node::builder("laptop").invite(root.invite().parse().unwrap()).ephemeral().spawn().await.unwrap();
        let synced = |n: &Node| n.inner.snapshot().version == root.inner.snapshot().version;
        for _ in 0..100 {
            if synced(&laptop) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(synced(&laptop));
        let before = laptop.inner.snapshot();

        // A replica can't forge state: a changed or unsigned snapshot is ignored, at any version.
        let mut forged = (*before).clone();
        forged.version = u64::MAX;
        forged.denied.clear();
        laptop.inner.apply_snapshot(forged.clone()).await;
        forged.sig.clear();
        laptop.inner.apply_snapshot(forged).await;
        assert_eq!(laptop.inner.snapshot(), before);

        // Nor replay an older one the root signed, to undo a revocation.
        root.revoke("bob").unwrap();
        for _ in 0..100 {
            if synced(&laptop) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let after = laptop.inner.snapshot();
        assert!(after.denied.contains(bob.id().as_bytes()));
        laptop.inner.apply_snapshot((*before).clone()).await;
        assert_eq!(laptop.inner.snapshot(), after);

        for n in [bob, laptop, root] {
            n.close().await;
        }
    }
}
