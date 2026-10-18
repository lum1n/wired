//! TLS for the anchor's relay, pinned to the anchor's Ed25519 key.
//!
//! The relay (HTTPS + QUIC address discovery) presents a self-signed certificate
//! whose key is the anchor's endpoint key. Clients accept a certificate only if
//! its public key is one of the anchor ids in the invite, so no CA is involved.

use std::{
    fmt,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use iroh::{PublicKey, SecretKey};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};

/// DER prefix of a PKCS#8 v1 Ed25519 private key; the 32-byte seed follows.
const ED25519_PKCS8_PREFIX: [u8; 16] =
    [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
/// DER prefix of an Ed25519 SubjectPublicKeyInfo; the 32-byte key follows.
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A self-signed certificate whose key is `key`, plus that key in PKCS#8 form.
fn anchor_cert(key: &SecretKey) -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> {
    let mut pkcs8 = ED25519_PKCS8_PREFIX.to_vec();
    pkcs8.extend_from_slice(&key.to_bytes());
    let pkcs8 = PrivatePkcs8KeyDer::from(pkcs8);
    let key_pair = rcgen::KeyPair::try_from(&pkcs8).context("load anchor key")?;
    let params = rcgen::CertificateParams::new(vec!["wired-anchor".to_string()])?;
    let cert = params.self_signed(&key_pair).context("self-sign anchor certificate")?;
    Ok((cert.der().clone(), pkcs8))
}

/// A rustls server config presenting a self-signed certificate for `key`.
pub fn anchor_server_config(key: &SecretKey) -> Result<rustls::ServerConfig> {
    let (cert, pkcs8) = anchor_cert(key)?;
    let config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], PrivateKeyDer::Pkcs8(pkcs8))?;
    Ok(config)
}

/// The Ed25519 key in a certificate, if it has one.
fn cert_key(cert: &CertificateDer<'_>) -> Option<PublicKey> {
    let ee = webpki::EndEntityCert::try_from(cert).ok()?;
    let spki = ee.subject_public_key_info();
    let raw = spki.as_ref().strip_prefix(&ED25519_SPKI_PREFIX[..])?;
    let raw: &[u8; 32] = raw.try_into().ok()?;
    PublicKey::from_bytes(raw).ok()
}

/// Anchor keys whose relays we trust; grows as replicas are approved.
pub type Pinned = Arc<RwLock<Vec<PublicKey>>>;

/// Accepts exactly the certificates whose key is one of `pinned`.
pub struct PinnedVerifier {
    pinned: Pinned,
    provider: Arc<CryptoProvider>,
}

impl PinnedVerifier {
    pub fn new(pinned: Pinned, provider: Arc<CryptoProvider>) -> Self {
        Self { pinned, provider }
    }
}

impl fmt::Debug for PinnedVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedVerifier").field("pinned", &self.pinned).finish()
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match cert_key(end_entity) {
            Some(k) if self.pinned.read().unwrap().contains(&k) => Ok(ServerCertVerified::assertion()),
            _ => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOfferedOrEnabled))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// iroh's relay TLS settings: trust only the pinned anchors.
pub fn ca_tls_config(pinned: Pinned) -> iroh::tls::CaTlsConfig {
    iroh::tls::CaTlsConfig::custom_server_cert_verifier(Arc::new(move |provider| {
        Ok(Arc::new(PinnedVerifier::new(pinned.clone(), provider)) as Arc<dyn ServerCertVerifier>)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_cert_carries_anchor_key() {
        let sk = SecretKey::generate();
        let (cert, _) = anchor_cert(&sk).unwrap();
        assert_eq!(cert_key(&cert), Some(sk.public()));
        anchor_server_config(&sk).unwrap();
    }

    #[test]
    fn verifier_rejects_unpinned_key() {
        let (cert, _) = anchor_cert(&SecretKey::generate()).unwrap();
        let v = PinnedVerifier::new(Arc::new(RwLock::new(vec![SecretKey::generate().public()])), provider());
        let name = ServerName::try_from("wired-anchor").unwrap();
        assert!(v.verify_server_cert(&cert, &[], &name, &[], UnixTime::now()).is_err());
    }
}
