//! Anchor duties: admitting nodes, owning (root) or replicating the network
//! state, pushing it to watchers, and the admin operations.

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    cert, frame,
    invite::{AnchorInfo, NetworkSecret, RelayInfo},
    node::{Inner, Node, valid_name},
    peer::{Refusal, reply_err, request},
    proto::{Cert, ErrorCode, JOIN_EXPORTER_LABEL, JOIN_MAC_CONTEXT, Open, PROTOCOL_VERSION, Reply, Role, Snapshot},
    relay::{self, same_url},
};
use anyhow::{Result, bail, ensure};
use iroh::{PublicKey, SecretKey, endpoint::Connection, endpoint::SendStream};
use tokio::sync::watch;
use tracing::{debug, warn};

/// How long a restarted root waits for the other anchors' snapshots.
const CATCH_UP: Duration = Duration::from_secs(5);

pub(crate) struct AnchorState {
    /// How to reach this anchor; published in the snapshot.
    pub(crate) info: AnchorInfo,
    /// Root only: replica keys allowed to become anchors.
    pub(crate) approved: Mutex<BTreeSet<[u8; 32]>>,
    /// Latest snapshot, for `Watch` streams.
    pub(crate) updates: watch::Sender<Arc<Snapshot>>,
}

impl Inner {
    fn anchor_state(&self) -> &AnchorState {
        self.anchor.as_ref().expect("anchor-only code path")
    }

    /// Root: changes the network state, then persists and broadcasts it.
    /// `change` returns whether anything changed.
    pub(crate) fn update_snapshot(&self, change: impl FnOnce(&mut Snapshot) -> bool) {
        let snap = {
            let mut guard = self.snap.write().unwrap();
            let mut next = (**guard).clone();
            if !change(&mut next) {
                return;
            }
            seal(&mut next, self.ep.secret_key());
            *guard = Arc::new(next);
            guard.clone()
        };
        self.snapshot_changed(snap);
    }

    /// After the snapshot changed (locally or by replication): enforce,
    /// reconfigure relays, persist, publish.
    pub(crate) fn snapshot_changed(&self, snap: Arc<Snapshot>) {
        self.enforce_denied(&snap);
        if let Some(r) = &self.relay {
            *r.denied.write().unwrap() = snap.denied.clone();
        }
        if let Some(me) = self.me.upgrade() {
            let snap = snap.clone();
            self.rt.spawn(async move { me.learn_network(&snap).await });
        }
        if let Some(a) = &self.anchor {
            a.updates.send_replace(snap);
        }
        self.snap_changed.notify_waiters();
        self.persist();
    }

    /// Checks a join request and issues a certificate.
    ///
    /// Keys already in the network renew without a proof (TLS proved the key).
    /// New keys need a valid proof of the current join secret and can only
    /// join at the root, so names are assigned in exactly one place.
    #[allow(clippy::too_many_arguments)] // the fields of `Open::Join`
    pub(crate) fn admit(
        &self,
        conn: &Connection,
        version: u8,
        network_id: [u8; 16],
        name: &str,
        proof: Option<[u8; 32]>,
        anchor: Option<AnchorInfo>,
        relay: Option<RelayInfo>,
    ) -> Result<Cert, Refusal> {
        let remote = conn.remote_id();
        let rk = *remote.as_bytes();
        if version != PROTOCOL_VERSION {
            return Err(Refusal(ErrorCode::BadVersion, format!("unsupported version {version}")));
        }
        if network_id != self.network_id {
            return Err(Refusal(ErrorCode::WrongNetwork, "wrong network".into()));
        }
        if !valid_name(name) {
            return Err(Refusal(ErrorCode::Protocol, "invalid name".into()));
        }
        if anchor.as_ref().is_some_and(|a| a.id != rk) {
            return Err(Refusal(ErrorCode::Protocol, "anchor info is for another key".into()));
        }
        let relay = relay
            .map(|r| announced_relay(r, rk))
            .transpose()
            .map_err(|e| Refusal(ErrorCode::Protocol, format!("{e:#}")))?;
        let snap = self.snapshot();
        if snap.denied.contains(&rk) {
            return Err(Refusal(ErrorCode::Denied, "this key is revoked".into()));
        }
        let root = self.is_root();
        let approved = |k: &[u8; 32]| self.anchor_state().approved.lock().unwrap().contains(k) || snap.is_anchor(k);

        match snap.name_of(&rk) {
            Some(registered) if registered != name => {
                return Err(Refusal(ErrorCode::NameTaken, format!("this key is registered as {registered:?}")));
            }
            Some(_) => {
                if let Some(info) = anchor {
                    if !root {
                        return Err(Refusal(ErrorCode::NotPrimary, "anchors register at the root".into()));
                    }
                    if !approved(&rk) {
                        return Err(not_approved(remote));
                    }
                    self.update_snapshot(|s| upsert_anchor(s, info));
                }
            }
            None => {
                if !root {
                    return Err(Refusal(ErrorCode::NotPrimary, "new nodes join at the root anchor".into()));
                }
                let mut exporter = [0u8; 32];
                conn.export_keying_material(&mut exporter, JOIN_EXPORTER_LABEL, b"")
                    .map_err(|_| Refusal(ErrorCode::Protocol, "tls exporter unavailable".into()))?;
                let valid = proof
                    .is_some_and(|p| self.secret.read().unwrap().verify_mac(&[JOIN_MAC_CONTEXT, &rk, &exporter], &p));
                if !valid {
                    return Err(Refusal(ErrorCode::Unauthorized, "invalid join proof (old invite?)".into()));
                }
                if anchor.is_some() && !approved(&rk) {
                    return Err(not_approved(remote));
                }
                // Check and claim under the snapshot lock, so concurrent joins
                // cannot both take the same name.
                let mut taken = false;
                self.update_snapshot(|s| {
                    if s.members.contains_key(name) || s.name_of(&rk).is_some() {
                        taken = true;
                        return false;
                    }
                    s.members.insert(name.to_string(), rk);
                    if let Some(info) = anchor {
                        upsert_anchor(s, info);
                    }
                    true
                });
                if taken {
                    return Err(Refusal(ErrorCode::NameTaken, format!("name {name:?} belongs to another key")));
                }
            }
        }

        // A member serving a relay: list it, owned by that member. Only the
        // root changes the network; elsewhere the member re-announces later.
        if root && let Some(r) = relay {
            self.update_snapshot(|s| list_member_relay(s, r));
        }

        let role = if root && self.snapshot().is_anchor(&rk) { Role::Anchor } else { Role::Member };
        let issuer_cert = match root {
            true => None,
            false => Some(self.own_cert().map_err(|_| Refusal(ErrorCode::NotApproved, "anchor not ready".into()))?),
        };
        Ok(cert::issue(self.ep.secret_key(), issuer_cert.as_ref(), self.network_id, remote, name, role))
    }

    /// Streams the network state to a watcher, once now and again on every change.
    pub(crate) async fn serve_watch(&self, mut send: SendStream, peer: PublicKey) -> Result<()> {
        let mut rx = self.anchor_state().updates.subscribe();
        loop {
            let snap = rx.borrow_and_update().clone();
            let mut out = (*snap).clone();
            // Anchors get the join secret so they can hand out current invites.
            out.secret = snap.is_anchor(peer.as_bytes()).then(|| self.secret.read().unwrap().clone());
            frame::write(&mut send, &Reply::State(out)).await?;
            if snap.denied.contains(peer.as_bytes()) {
                return Ok(());
            }
            rx.changed().await?;
        }
    }

    /// Root restarted from saved state: asks the other anchors for the newest
    /// snapshot this root signed, in case the saved state is older (restored
    /// from a backup, or a save failed). Returns it if it is newer than `since`.
    pub(crate) async fn newest_from_anchors(self: &Arc<Self>, since: u64) -> Option<Snapshot> {
        let me = self.ep.id();
        let mut asks = tokio::task::JoinSet::new();
        for a in &self.snapshot().anchors {
            let Ok(id) = PublicKey::from_bytes(&a.id) else { continue };
            if id == me {
                continue;
            }
            let inner = self.clone();
            asks.spawn(async move { (id, tokio::time::timeout(CATCH_UP, inner.fetch_snapshot(id)).await) });
        }
        let mut newest: Option<Snapshot> = None;
        while let Some(Ok((id, res))) = asks.join_next().await {
            match res {
                Ok(Ok(s)) if s.version > newest.as_ref().map_or(since, |n| n.version) => newest = Some(s),
                Ok(Ok(_)) => {}
                Ok(Err(e)) => debug!(anchor = %id.fmt_short(), "no snapshot from anchor: {e:#}"),
                Err(_) => debug!(anchor = %id.fmt_short(), "no snapshot from anchor: timed out"),
            }
        }
        newest
    }

    /// The snapshot an anchor holds, checked to be one the root signed.
    async fn fetch_snapshot(self: &Arc<Self>, id: PublicKey) -> Result<Snapshot> {
        let peer = match self.live_peer(id) {
            Some(p) => p,
            None => self.connect_hello(id).await?,
        };
        let (_send, _recv, reply) = request(&peer.conn, &Open::Watch).await?;
        let Reply::State(snap) = reply else { return Err(reply_err(reply)) };
        snap.verify(&self.root)?;
        Ok(snap)
    }

    /// Root: re-signs its own anchor certificate at half its lifetime.
    pub(crate) async fn renew_root_loop(self: Arc<Self>) {
        loop {
            let wait = self.cert.read().unwrap().as_ref().map(|c| cert::remaining(c) / 2).unwrap_or(0).max(60);
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
            let c = cert::issue(self.ep.secret_key(), None, self.network_id, self.ep.id(), &self.name, Role::Anchor);
            *self.cert.write().unwrap() = Some(c);
        }
    }

    fn rotate_secret(&self) {
        *self.secret.write().unwrap() = NetworkSecret::generate();
    }
}

/// Root: moves `snap` to a new version and signs it. Versions are at least the
/// clock in Unix milliseconds, so a root restarted from older state still
/// outranks every snapshot it published before.
pub(crate) fn seal(snap: &mut Snapshot, root: &SecretKey) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    snap.version = (snap.version + 1).max(now);
    snap.secret = None;
    snap.sign(root);
}

fn not_approved(key: PublicKey) -> Refusal {
    Refusal(ErrorCode::NotApproved, format!("run `wired approve {key}` on the root anchor"))
}

/// A relay a member announced in `Join`, checked and owned by `owner`.
fn announced_relay(r: RelayInfo, owner: [u8; 32]) -> Result<RelayInfo> {
    let url = relay::origin(&r.url)?;
    // A public relay's certificate is made from its node's key, so that is the only pin it can have.
    ensure!(r.pin.is_none_or(|p| p == owner), "a relay's pin must be the announcing node's key");
    Ok(RelayInfo { url, pin: r.pin, qad_port: r.qad_port, owner: Some(owner) })
}

/// Lists a member's relay, replacing the one it listed before (one per member).
/// A member never takes over a listing another node owns. It may claim one the
/// root added for it (so it could join through it), as long as it adds no pin.
fn list_member_relay(s: &mut Snapshot, info: RelayInfo) -> bool {
    if s.relays.contains(&info) {
        return false;
    }
    let claimable = |r: &RelayInfo| r.owner == info.owner || (r.owner.is_none() && info.pin.is_none());
    if let Some(r) = s.relays.iter().find(|r| same_url(&r.url, &info.url))
        && !claimable(r)
    {
        warn!(url = %info.url, "ignoring a relay announcement for a listing another node owns");
        return false;
    }
    s.relays.retain(|r| r.owner != info.owner && !same_url(&r.url, &info.url));
    s.relays.push(info);
    true
}

fn upsert_anchor(s: &mut Snapshot, info: AnchorInfo) -> bool {
    if s.anchors.contains(&info) {
        return false;
    }
    s.anchors.retain(|a| a.id != info.id);
    s.anchors.push(info);
    true
}

/// Admin operations; only the root anchor can change the network.
impl Node {
    fn require_root(&self, what: &str) -> Result<()> {
        ensure!(self.inner.is_root(), "only the root anchor can {what}");
        Ok(())
    }

    /// Removes `name` from the network immediately: its key is denied, every
    /// node drops connections to it, and certificates it issued (if it was an
    /// anchor) stop being accepted. The join secret is rotated, so the
    /// returned invite replaces the old one for adding new nodes; existing
    /// members are unaffected.
    pub fn revoke(&self, name: &str) -> Result<String> {
        self.require_root("revoke nodes")?;
        let inner = &self.inner;
        let Some(key) = inner.snapshot().members.get(name).copied() else { bail!("unknown node {name:?}") };
        ensure!(key != *inner.root.as_bytes(), "cannot revoke the root anchor");
        inner.anchor_state().approved.lock().unwrap().remove(&key);
        inner.rotate_secret();
        inner.update_snapshot(|s| {
            s.members.remove(name);
            s.anchors.retain(|a| a.id != key);
            s.relays.retain(|r| r.owner != Some(key));
            s.denied.insert(key);
            true
        });
        Ok(self.invite())
    }

    /// Replaces the join secret (e.g. after an invite leaked). Existing members
    /// are unaffected; the returned invite is the only one that adds new nodes.
    pub fn rotate_invite(&self) -> Result<String> {
        self.require_root("rotate the invite")?;
        self.inner.rotate_secret();
        // Bump the version so replicas pick up the new secret.
        self.inner.update_snapshot(|_| true);
        Ok(self.invite())
    }

    /// Lists a relay at `url` for the whole network, e.g. a relay another node
    /// serves behind a proxy (`https://robin.exe.xyz`). Every node connects to
    /// it, so a node can then join *through* it. Its certificate is checked
    /// against the usual CA roots.
    pub fn add_relay(&self, url: &str) -> Result<()> {
        self.require_root("add relays")?;
        let url = relay::origin(url)?;
        self.inner.update_snapshot(|s| {
            // Keep an entry the relay's own node announced (it knows more).
            if s.relays.iter().any(|r| same_url(&r.url, &url)) {
                return false;
            }
            s.relays.push(RelayInfo { url, pin: None, qad_port: None, owner: None });
            true
        });
        Ok(())
    }

    /// Stops listing a relay. A member that serves it lists it again when it renews.
    pub fn remove_relay(&self, url: &str) -> Result<()> {
        self.require_root("remove relays")?;
        let mut found = false;
        self.inner.update_snapshot(|s| {
            let before = s.relays.len();
            s.relays.retain(|r| !same_url(&r.url, url));
            found = s.relays.len() != before;
            found
        });
        ensure!(found, "no relay {url}");
        Ok(())
    }

    /// Allows the replica with this key to become an anchor. It registers
    /// itself the next time it connects (it retries on its own).
    pub fn approve_anchor(&self, id: PublicKey) -> Result<()> {
        self.require_root("approve anchors")?;
        ensure!(!self.inner.snapshot().denied.contains(id.as_bytes()), "that key is revoked");
        self.inner.anchor_state().approved.lock().unwrap().insert(*id.as_bytes());
        self.inner.persist();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(url: &str, pin: Option<[u8; 32]>, owner: Option<[u8; 32]>) -> RelayInfo {
        RelayInfo { url: url.into(), pin, qad_port: None, owner }
    }

    #[test]
    fn announced_relays_must_be_bounded_origins_pinned_to_their_owner() {
        let ok = announced_relay(relay("https://Robin.example.com:443/", None, None), [1; 32]).unwrap();
        assert_eq!(ok, relay("https://robin.example.com", None, Some([1; 32])));
        announced_relay(relay("https://vps.example.com:7443", Some([1; 32]), None), [1; 32]).unwrap();
        let long = format!("https://{}.example.com", "z".repeat(250));
        for bad in ["http//[bad", "not a url", "ftp://host", "https://host/path", "https://u:p@host", &long] {
            assert!(announced_relay(relay(bad, None, None), [1; 32]).is_err(), "{bad}");
        }
        assert!(announced_relay(relay("https://vps.example.com", Some([2; 32]), None), [1; 32]).is_err());
    }

    #[test]
    fn a_member_lists_one_relay_and_never_takes_over_another_nodes() {
        let (root, alice, eve) = ([0; 32], [1; 32], [2; 32]);
        let mut s = Snapshot {
            relays: vec![
                relay("https://root.example", Some(root), Some(root)),
                relay("https://admin.example", None, None),
            ],
            ..Default::default()
        };
        assert!(list_member_relay(&mut s, relay("https://alice.example", Some(alice), Some(alice))));
        // Another node's listing stays as it is, pinned or not.
        assert!(!list_member_relay(&mut s, relay("https://root.example", None, Some(eve))));
        assert!(!list_member_relay(&mut s, relay("https://alice.example", Some(eve), Some(eve))));
        // A root-added listing can be claimed by its server, but not re-pinned.
        assert!(!list_member_relay(&mut s, relay("https://admin.example", Some(eve), Some(eve))));
        assert!(list_member_relay(&mut s, relay("https://admin.example", None, Some(eve))));
        // A new announcement replaces the member's earlier one.
        assert!(list_member_relay(&mut s, relay("https://eve2.example", None, Some(eve))));
        assert!(!list_member_relay(&mut s, relay("https://eve2.example", None, Some(eve))));
        let urls: Vec<&str> = s.relays.iter().map(|r| r.url.as_str()).collect();
        assert_eq!(urls, ["https://root.example", "https://alice.example", "https://eve2.example"]);
        assert_eq!(s.relays[0].owner, Some(root));
        assert_eq!(s.relays[1].owner, Some(alice));
    }
}
