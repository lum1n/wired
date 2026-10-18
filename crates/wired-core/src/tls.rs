//! TLS for relays.
//!
//! A relay on a public IP serves HTTPS and QUIC address discovery with a
//! self-signed certificate whose key is its node key; clients pin that key.
//! A relay behind a TLS-terminating proxy (exe.dev, a real domain) presents a
//! CA-issued certificate, which is checked against the usual roots. Either
//! way the relay only ever sees ciphertext; TLS here protects metadata.

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
fn relay_cert(key: &SecretKey) -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> {
    let mut pkcs8 = ED25519_PKCS8_PREFIX.to_vec();
    pkcs8.extend_from_slice(&key.to_bytes());
    let pkcs8 = PrivatePkcs8KeyDer::from(pkcs8);
    let key_pair = rcgen::KeyPair::try_from(&pkcs8).context("load anchor key")?;
    let params = rcgen::CertificateParams::new(vec!["wired-anchor".to_string()])?;
    let cert = params.self_signed(&key_pair).context("self-sign anchor certificate")?;
    Ok((cert.der().clone(), pkcs8))
}

/// A rustls server config presenting a self-signed certificate for `key`.
pub fn relay_server_config(key: &SecretKey) -> Result<rustls::ServerConfig> {
    let (cert, pkcs8) = relay_cert(key)?;
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

/// Keys of self-signed relays we trust; grows as relays are added.
pub type Pinned = Arc<RwLock<Vec<PublicKey>>>;

/// Accepts a certificate whose key is pinned, or else one that chains to the
/// usual CA roots for the server name.
pub struct PinnedVerifier {
    pinned: Pinned,
    provider: Arc<CryptoProvider>,
    webpki: Arc<dyn ServerCertVerifier>,
}

impl PinnedVerifier {
    pub fn new(pinned: Pinned, provider: Arc<CryptoProvider>) -> Result<Self, rustls::Error> {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let webpki = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        Ok(Self { pinned, provider, webpki })
    }

    fn is_pinned(&self, cert: &CertificateDer<'_>) -> bool {
        cert_key(cert).is_some_and(|k| self.pinned.read().unwrap().contains(&k))
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
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.is_pinned(end_entity) {
            return Ok(ServerCertVerified::assertion());
        }
        self.webpki.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Pinned relays speak TLS 1.3 only; TLS 1.2 is for CA-issued certificates.
        if self.is_pinned(cert) {
            return Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOfferedOrEnabled));
        }
        self.webpki.verify_tls12_signature(message, cert, dss)
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
        self.webpki.supported_verify_schemes()
    }
}

/// iroh's relay TLS settings: pinned relay keys, or else the usual CA roots.
pub fn ca_tls_config(pinned: Pinned) -> iroh::tls::CaTlsConfig {
    iroh::tls::CaTlsConfig::custom_server_cert_verifier(Arc::new(move |provider| {
        let v = PinnedVerifier::new(pinned.clone(), provider).map_err(std::io::Error::other)?;
        Ok(Arc::new(v) as Arc<dyn ServerCertVerifier>)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_cert_carries_anchor_key() {
        let sk = SecretKey::generate();
        let (cert, _) = relay_cert(&sk).unwrap();
        assert_eq!(cert_key(&cert), Some(sk.public()));
        relay_server_config(&sk).unwrap();
    }

    #[test]
    fn verifier_accepts_pinned_and_rejects_unpinned_self_signed() {
        let sk = SecretKey::generate();
        let (cert, _) = relay_cert(&sk).unwrap();
        let name = ServerName::try_from("wired-anchor").unwrap();
        let other =
            PinnedVerifier::new(Arc::new(RwLock::new(vec![SecretKey::generate().public()])), provider()).unwrap();
        // Not pinned, and not CA-issued either.
        assert!(other.verify_server_cert(&cert, &[], &name, &[], UnixTime::now()).is_err());
        let pinned = PinnedVerifier::new(Arc::new(RwLock::new(vec![sk.public()])), provider()).unwrap();
        assert!(pinned.verify_server_cert(&cert, &[], &name, &[], UnixTime::now()).is_ok());
    }
}
