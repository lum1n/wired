//! Wire messages. See `spec/PROTOCOL.md`.
//!
//! Every QUIC bi-stream starts with one [`Open`] frame from the opener and is
//! answered with [`Reply`] frames. The first stream on a connection must be
//! `Join` (to an anchor) or `Hello`; after that it may be `Join` (renewal),
//! `Hello`, `Watch` (anchors stream `Reply::State` on every change) or
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
