//! Wire messages. See `spec/PROTOCOL.md`.
//!
//! Every QUIC bi-stream starts with one [`Open`] frame from the opener and is
//! answered with [`Reply`] frames. The first stream on a connection must be
//! `Join` (to an anchor) or `Hello`; after that it may be `Join` (renewal),
//! `Hello`, `Watch` (anchors send `Reply::State`, then `Reply::Delta` on every change) or
//! `Service`, whose payload is the raw byte stream that follows `ServiceOk`.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use iroh::{PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};

use crate::invite::{AnchorInfo, NetworkSecret, RelayInfo};

pub const ALPN: &[u8] = b"wired/1";
pub const PROTOCOL_VERSION: u8 = 2;

/// Label for the TLS exporter that binds a join proof to its QUIC session.
pub const JOIN_EXPORTER_LABEL: &[u8] = b"wired/1 join";
/// Domain-separation prefix for the join proof HMAC.
pub const JOIN_MAC_CONTEXT: &[u8] = b"wired/1 join-proof";
/// Domain-separation prefix for certificate signatures.
pub const CERT_SIG_CONTEXT: &[u8] = b"wired/1 cert";
/// Domain-separation prefix for the root's signature on a snapshot.
pub const SNAPSHOT_SIG_CONTEXT: &[u8] = b"wired/1 snapshot";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Member,
    /// May issue member certificates. Only the root issues anchor certificates.
    Anchor,
}

/// What an issuer vouches for: this key may use this name in this network until `expires`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertBody {
    pub network_id: [u8; 16],
    pub node_id: [u8; 32],
    pub name: String,
    pub role: Role,
    /// Seconds since the Unix epoch.
    pub expires: u64,
    /// Key that signed this certificate: the root, or an anchor certified by the root.
    pub issuer: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cert {
    pub body: CertBody,
    /// Ed25519 signature by `issuer` over `CERT_SIG_CONTEXT ‖ postcard(body)`.
    pub sig: Vec<u8>,
    /// The issuer's anchor certificate, when the issuer is not the root.
    pub issuer_cert: Option<Box<Cert>>,
}

/// The network's shared state, owned by the root anchor and replicated to
/// every anchor and member. The root signs it, so other anchors can only pass it on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Increases on every change, and never goes back even if the root is
    /// restored from older state: at least the root's clock in Unix milliseconds.
    /// Nodes only take a snapshot newer than the one they have.
    pub version: u64,
    /// Name → key of every member, anchors included.
    pub members: BTreeMap<String, [u8; 32]>,
    /// Revoked keys. Certificates for, or issued by, these keys are rejected.
    pub denied: BTreeSet<[u8; 32]>,
    /// Every anchor, root included.
    pub anchors: Vec<AnchorInfo>,
    /// Every relay. Nodes connect to all of them as needed.
    pub relays: Vec<RelayInfo>,
    /// Current join secret; only sent to anchors. Not covered by `sig`.
    pub secret: Option<NetworkSecret>,
    /// The root's Ed25519 signature over `SNAPSHOT_SIG_CONTEXT ‖ postcard(snapshot)`,
    /// encoded with `secret` and `sig` empty. Empty on a snapshot the root never signed.
    pub sig: Vec<u8>,
}

impl Snapshot {
    pub fn is_anchor(&self, key: &[u8; 32]) -> bool {
        self.anchors.iter().any(|a| a.id == *key)
    }

    pub fn name_of(&self, key: &[u8; 32]) -> Option<&str> {
        self.members.iter().find(|(_, k)| *k == key).map(|(n, _)| n.as_str())
    }

    fn signed_bytes(&self) -> Vec<u8> {
        let unsigned = Snapshot { secret: None, sig: Vec::new(), ..self.clone() };
        let mut msg = SNAPSHOT_SIG_CONTEXT.to_vec();
        msg.extend(postcard::to_stdvec(&unsigned).expect("snapshot serializes"));
        msg
    }

    /// Root: signs the snapshot as it is now.
    pub fn sign(&mut self, root: &SecretKey) {
        self.sig = root.sign(&self.signed_bytes()).to_bytes().to_vec();
    }

    /// Checks that the root signed this snapshot.
    pub fn verify(&self, root: &PublicKey) -> Result<()> {
        let sig: &[u8; 64] = self.sig.as_slice().try_into().context("snapshot is not signed")?;
        root.verify(&self.signed_bytes(), &Signature::from_bytes(sig)).context("bad snapshot signature")?;
        Ok(())
    }
}

/// The changes that turn the snapshot at version `from` into the one at `to`.
/// Anchors send these on a `Watch` stream after the first full snapshot, so a
/// change costs its own size rather than the whole member list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delta {
    pub from: u64,
    pub to: u64,
    /// Members added, or whose key changed.
    pub members_set: BTreeMap<String, [u8; 32]>,
    pub members_removed: BTreeSet<String>,
    pub denied_added: BTreeSet<[u8; 32]>,
    pub denied_removed: BTreeSet<[u8; 32]>,
    /// The full list, when it changed. These lists are short.
    pub anchors: Option<Vec<AnchorInfo>>,
    pub relays: Option<Vec<RelayInfo>>,
    /// Current join secret; only sent to anchors, as in [`Snapshot`].
    pub secret: Option<NetworkSecret>,
    /// The root's signature on the snapshot at `to`, so the watcher can check what it builds.
    pub sig: Vec<u8>,
}

impl Delta {
    /// The delta from `old` to `new`. `secret` is left unset.
    pub fn between(old: &Snapshot, new: &Snapshot) -> Self {
        let members_set =
            new.members.iter().filter(|(n, k)| old.members.get(*n) != Some(*k)).map(|(n, k)| (n.clone(), *k)).collect();
        let members_removed = old.members.keys().filter(|n| !new.members.contains_key(*n)).cloned().collect();
        Delta {
            from: old.version,
            to: new.version,
            members_set,
            members_removed,
            denied_added: new.denied.difference(&old.denied).copied().collect(),
            denied_removed: old.denied.difference(&new.denied).copied().collect(),
            anchors: (old.anchors != new.anchors).then(|| new.anchors.clone()),
            relays: (old.relays != new.relays).then(|| new.relays.clone()),
            secret: None,
            sig: new.sig.clone(),
        }
    }

    /// Applies this delta to `snap`, which must be at version `from`. The result
    /// is only as good as its signature: check it with [`Snapshot::verify`].
    pub fn apply(self, snap: &mut Snapshot) -> Result<(), String> {
        if snap.version != self.from {
            return Err(format!("delta from version {} applied to version {}", self.from, snap.version));
        }
        snap.version = self.to;
        for n in &self.members_removed {
            snap.members.remove(n);
        }
        snap.members.extend(self.members_set);
        for k in &self.denied_removed {
            snap.denied.remove(k);
        }
        snap.denied.extend(self.denied_added);
        if let Some(a) = self.anchors {
            snap.anchors = a;
        }
        if let Some(r) = self.relays {
            snap.relays = r;
        }
        snap.secret = self.secret;
        snap.sig = self.sig;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Open {
    /// Ask an anchor for a certificate. Keys the network already knows are
    /// renewed without `proof`; new keys need it and can only join at the root.
    Join {
        version: u8,
        network_id: [u8; 16],
        name: String,
        /// `HMAC(secret, JOIN_MAC_CONTEXT ‖ node_id ‖ exporter)`.
        proof: Option<[u8; 32]>,
        /// Set by a replica anchor asking to be (re)registered.
        anchor: Option<AnchorInfo>,
        /// Set by a node that serves a relay, so the root lists it.
        relay: Option<RelayInfo>,
    },
    /// Present a certificate to another node.
    Hello { version: u8, cert: Cert },
    /// Subscribe to network state; the anchor answers with `State` frames.
    Watch,
    /// Open a byte stream to the named service.
    Service { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Reply {
    Joined { cert: Cert, anchor: Cert },
    Hello { cert: Cert },
    State(Snapshot),
    ServiceOk,
    Error { code: ErrorCode, message: String },
    Delta(Delta),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    BadVersion,
    WrongNetwork,
    Unauthorized,
    NameTaken,
    /// New keys must join at the root anchor.
    NotPrimary,
    /// A replica's key has not been approved on the root.
    NotApproved,
    NoSuchService,
    Denied,
    Protocol,
}

impl ErrorCode {
    /// Errors that retrying will not fix without operator action.
    pub fn is_fatal(self) -> bool {
        matches!(self, Self::BadVersion | Self::WrongNetwork | Self::Unauthorized | Self::NameTaken | Self::Denied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(version: u64, members: &[(&str, u8)], denied: &[u8], anchors: &[u8]) -> Snapshot {
        Snapshot {
            version,
            members: members.iter().map(|(n, k)| (n.to_string(), [*k; 32])).collect(),
            denied: denied.iter().map(|k| [*k; 32]).collect(),
            anchors: anchors.iter().map(|k| AnchorInfo { id: [*k; 32], addrs: vec![] }).collect(),
            relays: vec![],
            secret: None,
            sig: Vec::new(),
        }
    }

    /// A replica can pass deltas on but not change them: what a watcher builds must carry the root's signature.
    #[test]
    fn a_delta_builds_a_snapshot_the_root_signed_or_nothing() {
        let root = SecretKey::generate();
        let mut old = snap(1, &[("a", 1)], &[], &[]);
        old.sign(&root);
        let mut new = snap(2, &[("a", 1), ("b", 2)], &[7], &[]);
        new.sign(&root);
        let delta = Delta::between(&old, &new);
        let mut got = old.clone();
        delta.clone().apply(&mut got).unwrap();
        assert_eq!(got, new);
        got.verify(&root.public()).unwrap();

        let mut forged = delta;
        forged.denied_added.clear();
        let mut got = old.clone();
        forged.apply(&mut got).unwrap();
        assert!(got.verify(&root.public()).is_err());
    }

    #[test]
    fn delta_turns_old_into_new() {
        let old = snap(4, &[("a", 1), ("b", 2), ("c", 3)], &[], &[1]);
        let new = snap(6, &[("a", 1), ("c", 4), ("d", 5)], &[2], &[1, 4]);
        let delta = Delta::between(&old, &new);
        assert_eq!(delta.members_set.len(), 2, "only changed members are sent");
        assert_eq!(delta.relays, None, "unchanged lists are not sent");
        let mut got = old.clone();
        delta.apply(&mut got).unwrap();
        assert_eq!(got, new);
    }

    #[test]
    fn delta_needs_its_base_version() {
        let old = snap(4, &[("a", 1)], &[], &[]);
        let new = snap(5, &[("a", 1), ("b", 2)], &[], &[]);
        let mut other = snap(3, &[], &[], &[]);
        assert!(Delta::between(&old, &new).apply(&mut other).is_err());
    }

    #[test]
    fn delta_undoes_removals() {
        let old = snap(7, &[("a", 1), ("b", 2)], &[3, 4], &[]);
        let new = snap(8, &[("a", 1)], &[4], &[]);
        let delta = Delta::between(&old, &new);
        assert_eq!(delta.members_removed, BTreeSet::from(["b".to_string()]));
        assert_eq!(delta.denied_removed, BTreeSet::from([[3; 32]]));
        assert!(delta.members_set.is_empty() && delta.denied_added.is_empty());
        let mut got = old.clone();
        delta.apply(&mut got).unwrap();
        assert_eq!(got, new);
    }

    #[test]
    fn delta_of_unchanged_state_carries_only_versions() {
        let old = snap(2, &[("a", 1)], &[5], &[1]);
        let new = Snapshot { version: 3, ..old.clone() };
        assert_eq!(Delta::between(&old, &new), Delta { from: 2, to: 3, ..Delta::default() });
    }

    #[test]
    fn delta_sends_changed_relays_in_full() {
        let old = snap(1, &[], &[], &[]);
        let relay = RelayInfo { url: "https://r.example".into(), pin: None, qad_port: None, owner: None };
        let new = Snapshot { version: 2, relays: vec![relay], ..old.clone() };
        let delta = Delta::between(&old, &new);
        assert_eq!(delta.relays.as_deref(), Some(&new.relays[..]));
        assert_eq!(delta.anchors, None);
        let mut got = old.clone();
        delta.apply(&mut got).unwrap();
        assert_eq!(got, new);
    }

    /// The secret is the delta's, not the base's: a node no longer an anchor stops holding one.
    #[test]
    fn delta_replaces_the_secret() {
        let mut held = Snapshot { secret: Some(NetworkSecret([1; 32])), ..snap(1, &[], &[], &[]) };
        let next = snap(2, &[], &[], &[]);
        Delta { secret: Some(NetworkSecret([2; 32])), ..Delta::between(&held, &next) }.apply(&mut held).unwrap();
        assert_eq!(held.secret, Some(NetworkSecret([2; 32])));
        let last = snap(3, &[], &[], &[]);
        Delta::between(&held, &last).apply(&mut held).unwrap();
        assert_eq!(held.secret, None);
    }

    #[test]
    fn delta_survives_the_wire() {
        let delta = Delta::between(&snap(1, &[("a", 1)], &[], &[1]), &snap(2, &[("b", 2)], &[1], &[]));
        let bytes = postcard::to_stdvec(&Reply::Delta(delta.clone())).unwrap();
        match postcard::from_bytes::<Reply>(&bytes).unwrap() {
            Reply::Delta(got) => assert_eq!(got, delta),
            other => panic!("decoded as {other:?}"),
        }
    }
}
