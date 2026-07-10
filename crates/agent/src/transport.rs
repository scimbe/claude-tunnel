//! Agent → Edge transport (ADR-0004).
//!
//! The Agent dials outbound (no inbound ports). QUIC/UDP-443 is primary; when
//! outbound UDP is blocked it falls back to HTTP/2 over TCP/443.
//!
//! P1.2a implements the transport-selection decision and the QUIC dialer. The
//! actual TCP fallback transport (P1.2c) and reconnect-on-drop (P1.2b) follow.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use quinn::{Connection, Endpoint};
use rustls::pki_types::CertificateDer;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Transport the Agent uses to reach the Edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Primary: QUIC over UDP/443.
    Quic,
    /// Fallback when outbound UDP is blocked: HTTP/2 over TCP/443.
    TcpFallback,
}

/// Select the transport given whether outbound UDP is reachable. QUIC is
/// preferred; TCP fallback is used only when UDP is blocked (ADR-0004).
pub fn select_transport(udp_reachable: bool) -> Transport {
    if udp_reachable {
        Transport::Quic
    } else {
        Transport::TcpFallback
    }
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn client_endpoint(edge_cert: CertificateDer<'static>) -> Result<Endpoint, BoxError> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(edge_cert)?;
    let crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(cfg);
    Ok(endpoint)
}

/// Dial the Edge over QUIC, returning the established connection. `edge_cert` is
/// the Edge's certificate the Agent trusts for this dial.
pub async fn dial_quic(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<Connection, BoxError> {
    let endpoint = client_endpoint(edge_cert)?;
    let conn = endpoint.connect(edge_addr, "localhost")?.await?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_quic_when_udp_reachable() {
        assert_eq!(select_transport(true), Transport::Quic);
    }

    #[test]
    fn falls_back_to_tcp_when_udp_blocked() {
        assert_eq!(select_transport(false), Transport::TcpFallback);
    }

    #[tokio::test]
    async fn agent_dials_edge_over_quic() {
        let (server, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("edge server");
        let addr = server.local_addr().expect("edge addr");

        let server_task = tokio::spawn(async move {
            ct_edge::transport::accept_and_echo_one(&server)
                .await
                .expect("edge echo");
        });

        let conn = dial_quic(addr, cert).await.expect("agent dial");
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        send.write_all(b"agent-hello").await.expect("write");
        send.finish().expect("finish");
        let echoed = recv.read_to_end(64 * 1024).await.expect("read echo");
        assert_eq!(&echoed, b"agent-hello", "agent must round-trip via the Edge");

        conn.close(0u32.into(), b"done");
        server_task.await.expect("edge task join");
    }
}
