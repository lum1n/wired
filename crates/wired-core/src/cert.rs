//! Certificates: an issuer's signed statement that a key owns a name.
//!
//! The root anchor's key is the trust anchor. It signs member certificates and
//! anchor certificates; anchors sign member certificates and attach their own
//! anchor certificate, so a chain is at most two links long.

use std::{
    collections::BTreeSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use iroh::{PublicKey, SecretKey, Signature};

use crate::proto::{CERT_SIG_CONTEXT, Cert, CertBody, Role};

pub const MEMBER_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
pub const ANCHOR_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);

pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn signed_bytes(body: &CertBody) -> Vec<u8> {
    let mut msg = CERT_SIG_CONTEXT.to_vec();
    msg.extend(postcard::to_stdvec(body).expect("cert body serializes"));
    msg
}

/// Signs a certificate. `issuer_cert` is the issuer's anchor certificate,
/// required unless the issuer is the root.
pub fn issue(
    issuer: &SecretKey,
    issuer_cert: Option<&Cert>,
    network_id: [u8; 16],
    node: PublicKey,
    name: &str,
    role: Role,
) -> Cert {
    let lifetime = match role {
        Role::Member => MEMBER_LIFETIME,
        Role::Anchor => ANCHOR_LIFETIME,
    };
    let body = CertBody {
        network_id,
        node_id: *node.as_bytes(),
        name: name.to_string(),
        role,
        expires: now_unix() + lifetime.as_secs(),
        issuer: *issuer.public().as_bytes(),
    };
    let sig = issuer.sign(&signed_bytes(&body)).to_bytes().to_vec();
    Cert { body, sig, issuer_cert: issuer_cert.map(|c| Box::new(strip(c))) }
}

/// An anchor certificate without its own chain (anchor certs are root-issued).
fn strip(c: &Cert) -> Cert {
    Cert { body: c.body.clone(), sig: c.sig.clone(), issuer_cert: None }
}

/// What a node checks certificates against.
pub struct Trust<'a> {
    pub root: PublicKey,
    pub network_id: [u8; 16],
    pub denied: &'a BTreeSet<[u8; 32]>,
}

fn check_sig(key: &PublicKey, cert: &Cert) -> Result<()> {
    let sig: &[u8; 64] = cert.sig.as_slice().try_into().context("bad signature length")?;
    key.verify(&signed_bytes(&cert.body), &Signature::from_bytes(sig))?;
    Ok(())
}

fn check_body(b: &CertBody, trust: &Trust<'_>) -> Result<()> {
    ensure!(b.network_id == trust.network_id, "certificate is for another network");
    ensure!(b.expires > now_unix(), "certificate expired");
    ensure!(!trust.denied.contains(&b.node_id), "key {} is revoked", short(&b.node_id));
    ensure!(!trust.denied.contains(&b.issuer), "issuer {} is revoked", short(&b.issuer));
    Ok(())
}

fn short(k: &[u8; 32]) -> String {
    k[..5].iter().map(|b| format!("{b:02x}")).collect()
}

/// Checks a certificate presented by `remote` on a live connection.
pub fn verify(cert: &Cert, trust: &Trust<'_>, remote: PublicKey) -> Result<()> {
    ensure!(cert.body.node_id == *remote.as_bytes(), "certificate was issued to another key");
    check_body(&cert.body, trust)?;
    if cert.body.issuer == *trust.root.as_bytes() {
        return check_sig(&trust.root, cert);
    }
    let Some(ic) = cert.issuer_cert.as_deref() else {
        bail!("certificate issuer is not the root and no issuer certificate is attached");
    };
    ensure!(ic.body.node_id == cert.body.issuer, "issuer certificate is for another key");
    ensure!(ic.body.role == Role::Anchor, "issuer is not an anchor");
    ensure!(ic.body.issuer == *trust.root.as_bytes(), "issuer certificate is not signed by the root");
    check_body(&ic.body, trust)?;
    check_sig(&trust.root, ic)?;
    let issuer = PublicKey::from_bytes(&cert.body.issuer).context("bad issuer key")?;
    check_sig(&issuer, cert)
}

/// Seconds until `cert` expires (0 if it already has).
pub fn remaining(cert: &Cert) -> u64 {
    cert.body.expires.saturating_sub(now_unix())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: [u8; 16] = [1; 16];

    fn trust<'a>(root: &SecretKey, denied: &'a BTreeSet<[u8; 32]>) -> Trust<'a> {
        Trust { root: root.public(), network_id: NET, denied }
    }

    #[test]
    fn root_issued() {
        let root = SecretKey::generate();
        let node = SecretKey::generate().public();
        let cert = issue(&root, None, NET, node, "laptop", Role::Member);
        let none = BTreeSet::new();
        verify(&cert, &trust(&root, &none), node).unwrap();

        assert!(verify(&cert, &trust(&SecretKey::generate(), &none), node).is_err());
        assert!(verify(&cert, &trust(&root, &none), SecretKey::generate().public()).is_err());
        let mut renamed = cert.clone();
        renamed.body.name = "vps".into();
        assert!(verify(&renamed, &trust(&root, &none), node).is_err());
        let mut expired = cert.clone();
        expired.body.expires = 1;
        assert!(verify(&expired, &trust(&root, &none), node).is_err());
        let denied = BTreeSet::from([*node.as_bytes()]);
        assert!(verify(&cert, &trust(&root, &denied), node).is_err());
    }

    #[test]
    fn anchor_chain() {
        let root = SecretKey::generate();
        let replica = SecretKey::generate();
        let node = SecretKey::generate().public();
        let none = BTreeSet::new();
        let anchor_cert = issue(&root, None, NET, replica.public(), "vps2", Role::Anchor);
        let cert = issue(&replica, Some(&anchor_cert), NET, node, "laptop", Role::Member);
        verify(&cert, &trust(&root, &none), node).unwrap();

        // Revoking the issuer invalidates what it issued.
        let denied = BTreeSet::from([*replica.public().as_bytes()]);
        assert!(verify(&cert, &trust(&root, &denied), node).is_err());

        // A member cannot act as an issuer.
        let member_cert = issue(&root, None, NET, replica.public(), "vps2", Role::Member);
        let forged = issue(&replica, Some(&member_cert), NET, node, "laptop", Role::Member);
        assert!(verify(&forged, &trust(&root, &none), node).is_err());

        // An issuer certificate not signed by the root is rejected.
        let self_signed = issue(&replica, None, NET, replica.public(), "vps2", Role::Anchor);
        let forged = issue(&replica, Some(&self_signed), NET, node, "laptop", Role::Member);
        assert!(verify(&forged, &trust(&root, &none), node).is_err());

        // Without the chain, a replica-issued certificate does not verify.
        let mut bare = cert.clone();
        bare.issuer_cert = None;
        assert!(verify(&bare, &trust(&root, &none), node).is_err());
    }
}
