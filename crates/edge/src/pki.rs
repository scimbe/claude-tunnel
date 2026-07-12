//! Internal CA + certificate issuance (M20.1, productionization).
//!
//! Replaces the per-certificate pinning of the dev/testbed scaffolding with a
//! proper PKI: an internal Certificate Authority signs the Edge's leaf
//! certificate, and Clients trust the **CA root** instead of a specific leaf.
//! Rotating the Edge cert then means issuing a new leaf under the same CA — no
//! client re-pinning required.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::Endpoint;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::transport::install_crypto_provider;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// An in-memory Certificate Authority that issues leaf certificates.
pub struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Ca {
    /// Generate a fresh CA with the given common name.
    pub fn new(common_name: &str) -> Result<Self, BoxError> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let cert = params.self_signed(&key)?;
        Ok(Self { cert, key })
    }

    /// The CA root certificate (DER) that Clients must trust.
    pub fn root_der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    /// Issue a leaf certificate for `sans` (hostnames/IPs), signed by this CA.
    /// Returns the leaf certificate (DER) and its private key.
    pub fn issue(
        &self,
        sans: Vec<String>,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), BoxError> {
        let leaf_key = KeyPair::generate()?;
        let params = CertificateParams::new(sans)?;
        let leaf = params.signed_by(&leaf_key, &self.cert, &self.key)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        Ok((leaf.der().clone(), key))
    }
}

/// Build a QUIC server [`Endpoint`] bound to `addr` using a CA-issued leaf for
/// `sans`; returns the endpoint and the CA root (which Clients trust). This is
/// the production replacement for the self-signed `build_server_endpoint_at`.
pub fn build_server_endpoint_from_ca(
    ca: &Ca,
    addr: SocketAddr,
    sans: Vec<String>,
) -> Result<(Endpoint, CertificateDer<'static>), BoxError> {
    install_crypto_provider();
    let (cert, key) = ca.issue(sans)?;
    let server_config = quinn::ServerConfig::with_single_cert(vec![cert], key)?;
    let endpoint = Endpoint::server(server_config, addr)?;
    Ok((endpoint, ca.root_der()))
}

/// Build a QUIC client [`Endpoint`] that trusts a **CA root** — and therefore
/// any leaf that CA signs (enabling Edge cert rotation without re-pinning).
pub fn build_client_endpoint_trusting_ca(
    ca_root: CertificateDer<'static>,
) -> Result<Endpoint, BoxError> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_root)?;
    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::accept_and_echo_one;

    /// A leaf signed by the CA is accepted by a client that trusts the CA root
    /// (not the leaf) — the PKI trust chain works and rotation is possible.
    #[tokio::test]
    async fn ca_issued_leaf_is_trusted_via_ca_root() {
        let ca = Ca::new("ct-edge-ca").unwrap();
        let (server, ca_root) =
            build_server_endpoint_from_ca(&ca, "127.0.0.1:0".parse().unwrap(), vec!["localhost".into()])
                .unwrap();
        let addr = server.local_addr().unwrap();
        let srv = tokio::spawn(async move { accept_and_echo_one(&server).await });

        let client = build_client_endpoint_trusting_ca(ca_root).unwrap();
        let conn = client
            .connect(addr, "localhost")
            .unwrap()
            .await
            .expect("handshake against CA-issued cert");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"ping").await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(64).await.unwrap();
        assert_eq!(echoed, b"ping", "echo over the CA-trusted connection");

        conn.close(0u32.into(), b"done");
        let _ = srv.await;
    }

    /// A client trusting a *different* CA root rejects the Edge's leaf.
    #[tokio::test]
    async fn leaf_from_unknown_ca_is_rejected() {
        let ca = Ca::new("ct-edge-ca").unwrap();
        let (server, _ca_root) =
            build_server_endpoint_from_ca(&ca, "127.0.0.1:0".parse().unwrap(), vec!["localhost".into()])
                .unwrap();
        let addr = server.local_addr().unwrap();
        let _srv = tokio::spawn(async move {
            let _ = accept_and_echo_one(&server).await;
        });

        let other = Ca::new("other-ca").unwrap();
        let client = build_client_endpoint_trusting_ca(other.root_der()).unwrap();
        let result = client.connect(addr, "localhost").unwrap().await;
        assert!(result.is_err(), "leaf signed by an untrusted CA is rejected");
    }
}
