//! Invite strings: everything a node needs to join a network.
//!
//! Format: `wired1` + lowercase base32 of `postcard(Invite) ‖ sha256(payload)[..4]`.
//! The invite contains the join secret, so it is a credential: anyone holding
//! it can add a new node until the secret is rotated.

use anyhow::{Context, Result, bail, ensure};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PREFIX: &str = "wired1";
const VERSION: u8 = 1;

/// A 32-byte shared network secret. Never sent over the wire.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSecret(pub [u8; 32]);

impl std::fmt::Debug for NetworkSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NetworkSecret(..)")
    }
}

impl NetworkSecret {
    pub fn generate() -> Self {
        Self(rand::random())
    }

    /// HMAC-SHA256 over the concatenation of `parts`.
    pub fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.0).expect("hmac accepts any key length");
        for p in parts {
            m.update(p);
        }
        m.finalize().into_bytes().into()
    }

    pub fn verify_mac(&self, parts: &[&[u8]], tag: &[u8]) -> bool {
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.0).expect("hmac accepts any key length");
        for p in parts {
            m.update(p);
        }
        m.verify_slice(tag).is_ok()
    }
}

/// How to reach one anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorInfo {
    /// The anchor's Ed25519 public key (its endpoint id).
    pub id: [u8; 32],
    /// Relay URL served by the anchor, e.g. `http://vps.example.com:7443`.
    pub relay_url: String,
    /// Direct UDP addresses as `host:port`; hostnames are resolved at join time.
    pub addrs: Vec<String>,
    /// UDP port of the relay's QUIC address discovery, if enabled.
    pub qad_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub version: u8,
    /// Random, fixed for the life of the network.
    pub network_id: [u8; 16],
    /// The root anchor's key: the network's trust anchor.
    pub root: [u8; 32],
    /// Join secret for new keys. Rotated when a node is revoked.
    pub secret: NetworkSecret,
    pub anchors: Vec<AnchorInfo>,
}

impl Invite {
    pub fn new(network_id: [u8; 16], root: [u8; 32], secret: NetworkSecret, anchors: Vec<AnchorInfo>) -> Self {
        Self { version: VERSION, network_id, root, secret, anchors }
    }

    pub fn encode(&self) -> String {
        let mut buf = postcard::to_stdvec(self).expect("invite serializes");
        let sum = Sha256::digest(&buf);
        buf.extend_from_slice(&sum[..4]);
        format!("{PREFIX}{}", BASE32_NOPAD.encode(&buf).to_ascii_lowercase())
    }

    pub fn decode(s: &str) -> Result<Self> {
        let s = s.trim();
        let body = s.strip_prefix(PREFIX).context("invite must start with `wired1`")?;
        let buf = BASE32_NOPAD.decode(body.to_ascii_uppercase().as_bytes()).context("invite is not valid base32")?;
        ensure!(buf.len() > 4, "invite is too short");
        let (payload, sum) = buf.split_at(buf.len() - 4);
        if Sha256::digest(payload)[..4] != *sum {
            bail!("invite checksum mismatch (copy/paste error?)");
        }
        let inv: Invite = postcard::from_bytes(payload).context("invite payload is malformed")?;
        ensure!(inv.version == VERSION, "unsupported invite version {}", inv.version);
        ensure!(!inv.anchors.is_empty(), "invite lists no anchors");
        Ok(inv)
    }
}

impl std::str::FromStr for Invite {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::decode(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Invite {
        Invite::new(
            [3; 16],
            [7; 32],
            NetworkSecret::generate(),
            vec![AnchorInfo {
                id: [7; 32],
                relay_url: "http://vps.example.com:7443".into(),
                addrs: vec!["vps.example.com:7443".into(), "203.0.113.5:7443".into()],
                qad_port: Some(7842),
            }],
        )
    }

    #[test]
    fn roundtrip() {
        let inv = sample();
        let s = inv.encode();
        assert!(s.starts_with("wired1"));
        assert!(s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_eq!(Invite::decode(&s).unwrap(), inv);
    }

    #[test]
    fn detects_corruption() {
        let s = sample().encode();
        let mut bytes = s.into_bytes();
        let i = bytes.len() / 2;
        bytes[i] = if bytes[i] == b'a' { b'b' } else { b'a' };
        assert!(Invite::decode(std::str::from_utf8(&bytes).unwrap()).is_err());
    }

    #[test]
    fn mac_verifies() {
        let s = NetworkSecret::generate();
        let tag = s.mac(&[b"a", b"b"]);
        assert!(s.verify_mac(&[b"a", b"b"], &tag));
        assert!(!NetworkSecret::generate().verify_mac(&[b"a", b"b"], &tag));
    }
}
