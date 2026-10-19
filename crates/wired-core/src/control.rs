//! A member's (or replica's) standing session with an anchor: join or renew,
//! then watch the network state so revocations apply within moments.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use iroh::{
    EndpointAddr, PublicKey,
    endpoint::{Connection, RecvStream, SendStream},
};
use tracing::{debug, error, info, warn};

use crate::{
    cert, frame,
    node::Inner,
    peer::{REQUEST_TIMEOUT, RemoteError, is_fatal, reply_err, request},
    proto::{ALPN, Cert, ErrorCode, Open, PROTOCOL_VERSION, Reply, Role, Snapshot},
};

const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Delay between starting attempts at successive anchors.
const STAGGER: Duration = Duration::from_secs(2);
/// While attached to a replica, how often to try the root again.
const PREFER_ROOT_AFTER: Duration = Duration::from_secs(300);

pub(crate) struct Session {
    anchor: PublicKey,
    conn: Connection,
    /// Kept open: dropping it would finish the watch stream.
    _send: SendStream,
    recv: RecvStream,
    /// The state as of the last frame on the watch stream, which deltas apply to.
    state: Snapshot,
}

impl Inner {
    /// Anchors to try, root first.
    fn anchor_order(&self) -> Vec<PublicKey> {
        let me = self.ep.id();
        let mut order = vec![self.root];
        for a in &self.snapshot().anchors {
            if let Ok(id) = PublicKey::from_bytes(&a.id)
                && id != self.root
            {
                order.push(id);
            }
        }
        order.retain(|id| *id != me);
        order
    }

    /// Opens a session with the first anchor that accepts us. Attempts start
    /// root first, each next anchor `STAGGER` later, so a dead root costs
    /// seconds rather than a full timeout.
    pub(crate) async fn open_session_any(self: &Arc<Self>) -> Result<Session> {
        let mut attempts = tokio::task::JoinSet::new();
        for (i, anchor) in self.anchor_order().into_iter().enumerate() {
            let me = self.clone();
            attempts.spawn(async move {
                tokio::time::sleep(STAGGER * i as u32).await;
                let res = tokio::time::timeout(REQUEST_TIMEOUT, me.open_session(anchor)).await;
                (anchor, res.unwrap_or_else(|_| Err(anyhow!("timed out"))))
            });
        }
        // Report the most useful failure: a fatal refusal, then any answer from
        // an anchor, then a transport error.
        let (mut fatal, mut refused, mut other) = (None, None, None);
        while let Some(joined) = attempts.join_next().await {
            let Ok((anchor, res)) = joined else { continue };
            match res {
                Ok(s) => return Ok(s),
                Err(e) => {
                    debug!(anchor = %anchor.fmt_short(), "session failed: {e:#}");
                    if is_fatal(&e) {
                        fatal.get_or_insert(e);
                    } else if e.downcast_ref::<RemoteError>().is_some() {
                        refused.get_or_insert(e);
                    } else {
                        other.get_or_insert(e);
                    }
                }
            }
        }
        Err(fatal.or(refused).or(other).unwrap_or_else(|| anyhow!("no anchors to connect to")))
    }

    async fn open_session(self: &Arc<Self>, anchor: PublicKey) -> Result<Session> {
        let (conn, fresh) = match self.live_peer(anchor) {
            Some(p) => (p.conn, false),
            None => (self.ep.connect(EndpointAddr::new(anchor), ALPN).await.context("connect to anchor")?, true),
        };
        let theirs = self.join_on(&conn).await?;
        if fresh {
            self.add_peer(conn.clone(), theirs.body.name.clone(), theirs.body.issuer);
        }
        let (mut send, mut recv) = conn.open_bi().await?;
        frame::write(&mut send, &Open::Watch).await?;
        let state = match frame::read::<_, Reply>(&mut recv).await? {
            Reply::State(snap) => snap,
            other => return Err(reply_err(other)),
        };
        self.apply_snapshot(state.clone()).await;
        Ok(Session { anchor, conn, _send: send, recv, state })
    }

    /// Gets or renews our certificate from the anchor on `conn`; returns the anchor's certificate.
    async fn join_on(&self, conn: &Connection) -> Result<Cert> {
        let anchor = conn.remote_id();
        let open = Open::Join {
            version: PROTOCOL_VERSION,
            network_id: self.network_id,
            name: self.name.clone(),
            // Only needed the first time this key joins; cheap to always send.
            proof: Some(self.join_proof(conn)?),
            anchor: self.anchor.as_ref().map(|a| a.info.clone()),
            relay: self.relay.as_ref().map(|r| r.info.clone()),
        };
        let (_, _, reply) = request(conn, &open).await?;
        let Reply::Joined { cert: mine, anchor: theirs } = reply else { return Err(reply_err(reply)) };
        let snap = self.snapshot();
        let trust = self.trust(&snap);
        cert::verify(&theirs, &trust, anchor).context("anchor presented a bad certificate")?;
        ensure!(theirs.body.role == Role::Anchor, "{} is not an anchor", theirs.body.name);
        cert::verify(&mine, &trust, self.ep.id()).context("anchor issued a bad certificate")?;
        ensure!(mine.body.name == self.name, "anchor certified the wrong name");
        let want = if self.anchor.is_some() { Role::Anchor } else { Role::Member };
        if mine.body.role == want {
            *self.cert.write().unwrap() = Some(mine);
            self.persist();
        } else if self.cert.read().unwrap().is_none() {
            // A replica only gets anchor certificates from the root.
            bail!("{} issued a {:?} certificate; waiting for the root", theirs.body.name, mine.body.role);
        }
        Ok(theirs)
    }

    /// Applies a snapshot pushed by an anchor, if it is newer than ours.
    pub(crate) async fn apply_snapshot(&self, mut snap: Snapshot) {
        let secret = snap.secret.take();
        let snap = {
            let mut cur = self.snap.write().unwrap();
            if snap.version < cur.version || (snap.version == cur.version && snap == **cur) {
                return;
            }
            *cur = Arc::new(snap);
            cur.clone()
        };
        if let Some(secret) = secret
            && self.anchor.is_some()
        {
            *self.secret.write().unwrap() = secret;
        }
        self.learn_network(&snap).await;
        if snap.denied.contains(self.ep.id().as_bytes()) {
            error!("this node has been revoked from the network");
        }
        self.snapshot_changed(snap);
    }

    /// Keeps a session with some anchor alive for the life of the node.
    pub(crate) async fn control_loop(self: Arc<Self>, mut session: Option<Session>) {
        let mut backoff = Duration::from_secs(1);
        loop {
            if let Some(s) = session.take() {
                let anchor = s.anchor.fmt_short();
                match self.run_session(s).await {
                    Ok(()) => debug!(%anchor, "session ended"),
                    Err(e) => info!(%anchor, "session with anchor lost: {e:#}"),
                }
                backoff = Duration::from_secs(1);
            }
            tokio::time::sleep(backoff).await;
            match self.open_session_any().await {
                Ok(s) => session = Some(s),
                Err(e) => {
                    match e.downcast_ref::<RemoteError>() {
                        Some(r) if r.code == ErrorCode::NotApproved => {
                            info!("waiting for approval: {}", r.message)
                        }
                        _ => warn!("cannot reach any anchor (retrying in {backoff:?}): {e:#}"),
                    }
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    /// Applies pushed changes and renews the certificate until the session ends.
    async fn run_session(self: &Arc<Self>, s: Session) -> Result<()> {
        let Session { anchor, conn, _send, mut recv, mut state } = s;
        let me = self.clone();
        // Reads run in their own task: cancelling a read mid-frame would corrupt the stream.
        let mut reader = tokio::spawn(async move {
            loop {
                match frame::read::<_, Reply>(&mut recv).await? {
                    Reply::State(snap) => state = snap,
                    // Deltas apply to this stream's state, not ours: the anchor
                    // may be behind what we learned elsewhere.
                    Reply::Delta(delta) => delta.apply(&mut state).map_err(|e| anyhow!(e))?,
                    other => return Err(reply_err(other)),
                }
                me.apply_snapshot(state.clone()).await;
            }
        });
        let back_to_root = (anchor != self.root).then(|| Instant::now() + PREFER_ROOT_AFTER);
        let result = loop {
            let renew_in = self.cert.read().unwrap().as_ref().map(|c| cert::remaining(c) / 2).unwrap_or(0).max(60);
            let prefer_root = async {
                match back_to_root {
                    Some(at) => tokio::time::sleep_until(at.into()).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                r = &mut reader => break r.unwrap_or_else(|e| Err(anyhow!(e))),
                _ = tokio::time::sleep(Duration::from_secs(renew_in)) => {
                    if let Err(e) = self.join_on(&conn).await {
                        if is_fatal(&e) {
                            break Err(e);
                        }
                        warn!("certificate renewal failed: {e:#}");
                    }
                }
                _ = prefer_root => break Ok(()),
            }
        };
        reader.abort();
        result
    }
}
