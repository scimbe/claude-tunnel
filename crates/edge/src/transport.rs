//! Edge QUIC transport (ADR-0004).
//!
//! P1.1a: construct a server [`quinn::Endpoint`] with a self-signed certificate
//! and bind an ephemeral UDP port. Connection handling and stream echo land in
//! P1.1b. The self-signed cert is test/dev scaffolding; production certs are
//! Agent-held (ADR-0003) and, for the Mesh Plane, replaced by Noise (ADR-0013).

use std::net::{Ipv4Addr, SocketAddr};

use quinn::Endpoint;

/// Errors constructing an Edge endpoint.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Build a QUIC server [`Endpoint`] bound to `127.0.0.1:0` (ephemeral port),
/// using a freshly generated self-signed certificate.
///
/// Must be called within a Tokio runtime (quinn spawns an I/O driver).
pub fn build_server_endpoint() -> Result<Endpoint, BoxError> {
    // Install a process-default rustls crypto provider (idempotent; a second
    // call returns Err, which we ignore).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = certified.cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());

    let server_config = quinn::ServerConfig::with_single_cert(
        vec![cert_der],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
    )?;

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let endpoint = Endpoint::server(server_config, addr)?;
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_endpoint_binds_to_ephemeral_port() {
        let endpoint = build_server_endpoint().expect("build server endpoint");
        let port = endpoint
            .local_addr()
            .expect("endpoint has a local address")
            .port();
        assert_ne!(port, 0, "server must bind a concrete ephemeral UDP port");
    }
}
