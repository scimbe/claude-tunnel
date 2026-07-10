//! Agent → Edge transport (ADR-0004).
//!
//! The Agent dials outbound (no inbound ports). QUIC/UDP-443 is primary; when
//! outbound UDP is blocked it falls back to HTTP/2 over TCP/443.
//!
//! P1.2a implements the transport-selection decision and the QUIC dialer. The
//! actual TCP fallback transport (P1.2c) and reconnect-on-drop (P1.2b) follow.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use std::path::Path;

use ct_common::credential::SignedCredential;
use ct_common::RoutingToken;
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
    // Bind all interfaces (not loopback) so the Agent can reach a non-local Edge.
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
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

/// Present `signed` to the Edge over a fresh bidirectional stream and await the
/// Edge's decision. Returns `Ok(())` only if the Edge accepted the credential.
pub async fn present_credential(
    conn: &Connection,
    signed: &SignedCredential,
) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&signed.encode()).await?;
    send.finish()?;
    let ack = recv.read_to_end(64).await?;
    if ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected credential".into())
    }
}

/// Register this Agent's tunnel for `token` with the Edge over `conn`: open a
/// control stream, send `role='A' | token(32)`, and await the Edge's `OK`.
pub async fn register_tunnel(conn: &Connection, token: &RoutingToken) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut msg = vec![b'A'];
    msg.extend_from_slice(&token.0);
    send.write_all(&msg).await?;
    send.finish()?;
    let ack = recv.read_to_end(8).await?;
    if ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected tunnel registration".into())
    }
}

/// Load an Edge certificate (DER) the Edge published to a shared path.
pub fn load_cert(path: impl AsRef<Path>) -> std::io::Result<CertificateDer<'static>> {
    Ok(CertificateDer::from(std::fs::read(path)?))
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

    // --- P1.4d-ii: credential handshake over QUIC ---

    use crate::identity::AgentIdentity;
    use ct_common::{AgentId, TenantId};
    use ct_control_plane::credential::CredentialIssuer;
    use ct_control_plane::enrollment::Enrollment;
    use ct_control_plane::issuance::mint_for_enrolled;

    fn enrolled_credential(
        expires_at: u64,
    ) -> (ct_common::credential::SignedCredential, [u8; 32]) {
        let issuer = CredentialIssuer::generate();
        let mut enrollment = Enrollment::new();
        let tenant = TenantId("tenant-1".into());
        let token = enrollment.issue_join_token(tenant);
        let identity = AgentIdentity::generate();
        let agent_id = AgentId("agent-1".into());
        enrollment
            .redeem(&token, agent_id.clone(), identity.public_key_bytes())
            .unwrap();
        let signed = mint_for_enrolled(&issuer, &enrollment, &agent_id, expires_at).unwrap();
        (signed, issuer.public_key_bytes())
    }

    #[tokio::test]
    async fn agent_authenticates_to_edge_with_valid_credential() {
        let (signed, issuer_pk) = enrolled_credential(1_000);
        let (server, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        let server_task = tokio::spawn(async move {
            let conn = ct_edge::auth::accept_and_authenticate(&server, &issuer_pk, 500)
                .await
                .map_err(|e| e.to_string())?;
            conn.closed().await;
            Ok::<(), String>(())
        });

        let conn = dial_quic(addr, cert).await.expect("dial");
        present_credential(&conn, &signed)
            .await
            .expect("edge accepts valid credential");
        conn.close(0u32.into(), b"done");
        server_task.await.expect("join").expect("edge auth ok");
    }

    #[tokio::test]
    async fn edge_rejects_expired_credential() {
        let (signed, issuer_pk) = enrolled_credential(100); // expires at 100
        let (server, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        let server_task = tokio::spawn(async move {
            // now = 500 >= 100 → expired → Err
            ct_edge::auth::accept_and_authenticate(&server, &issuer_pk, 500)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });

        let conn = dial_quic(addr, cert).await.expect("dial");
        let result = present_credential(&conn, &signed).await;
        assert!(result.is_err(), "expired credential must be rejected");
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn agent_registers_tunnel_with_edge() {
        use ct_edge::state::EdgeState;
        use quinn::Connection;
        use std::sync::Arc;

        let token = RoutingToken([9u8; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        let state_e = state.clone();
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            ct_edge::serve::register_agent(&conn, &state_e)
                .await
                .map_err(|e| e.to_string())?;
            conn.closed().await;
            Ok::<(), String>(())
        });

        let conn = dial_quic(addr, cert).await.expect("dial");
        register_tunnel(&conn, &token)
            .await
            .expect("agent registers tunnel");
        assert!(state.is_known(&token), "edge now routes the agent's token");
        conn.close(0u32.into(), b"done");
        let _ = edge.await;
    }

    #[tokio::test]
    async fn load_cert_reads_written_der() {
        let (_endpoint, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("cert");
        let path = std::env::temp_dir().join(format!("ct-agent-cert-{}.der", std::process::id()));
        std::fs::write(&path, cert.as_ref()).unwrap();
        let loaded = load_cert(&path).expect("load");
        assert_eq!(loaded, cert, "agent loads the edge cert from the shared file");
        let _ = std::fs::remove_file(&path);
    }
}
