//! Agent origin-serving (M5.2b).
//!
//! When the Edge relays a Client stream to this Agent, the Agent dials the local
//! Origin (TCP) and pipes the QUIC stream to it. The Client↔Origin payload is
//! Noise-encrypted end to end (ADR-0013); the Agent forwards opaque bytes to the
//! Origin, which terminates the Noise session (P3). The Agent never inspects
//! them beyond forwarding.

use std::net::SocketAddr;

use quinn::{RecvStream, SendStream};
use rustls::pki_types::CertificateDer;
use tokio::io::{copy_bidirectional, join};
use tokio::net::TcpStream;

use crate::config::AgentConfig;
use crate::transport::{dial_quic, register_tunnel};
use ct_common::RoutingToken;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Serve one relayed QUIC stream: dial the local `origin` (TCP) and relay bytes
/// bidirectionally between the QUIC stream and the Origin connection.
pub async fn serve_stream_to_origin(
    quic_send: SendStream,
    quic_recv: RecvStream,
    origin: SocketAddr,
) -> Result<(), BoxError> {
    let mut tcp = TcpStream::connect(origin).await?;
    let mut quic = join(quic_recv, quic_send);
    copy_bidirectional(&mut quic, &mut tcp).await?;
    Ok(())
}

/// Run the Agent: dial the Edge, register the tunnel for `token`, then serve each
/// relayed stream to the local Origin. Loops until the connection closes.
pub async fn run_agent(
    config: &AgentConfig,
    edge_cert: CertificateDer<'static>,
    token: RoutingToken,
) -> Result<(), BoxError> {
    let conn = dial_quic(config.edge, edge_cert).await?;
    register_tunnel(&conn, &token).await?;
    loop {
        let (send, recv) = conn.accept_bi().await?;
        let origin = config.origin;
        tokio::spawn(async move {
            let _ = serve_stream_to_origin(send, recv, origin).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::dial_quic;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn echo_origin() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
            sock.shutdown().await.unwrap();
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn agent_relays_quic_stream_to_local_origin() {
        // Local TCP echo origin that closes its write side after echoing.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        // "Edge": open a relayed stream to the Agent, send "ping", read the echo.
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(b"ping").await.unwrap();
            send.finish().unwrap();
            recv.read_to_end(64).await.unwrap()
        });

        // Agent: dial the edge, accept the relayed stream, serve it to origin.
        let conn = dial_quic(addr, cert).await.expect("agent dial");
        let (a_send, a_recv) = conn.accept_bi().await.unwrap();
        serve_stream_to_origin(a_send, a_recv, origin_addr)
            .await
            .expect("serve to origin");

        let echoed = edge.await.unwrap();
        assert_eq!(echoed, b"ping", "edge gets the origin's echo through the agent");
        let _ = origin.await;
    }

    #[tokio::test]
    async fn run_agent_registers_and_serves_relayed_streams() {
        use ct_edge::state::EdgeState;
        use quinn::Connection;
        use std::sync::Arc;

        let (origin_addr, origin) = echo_origin().await;

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let edge_addr = server.local_addr().expect("addr");
        let token = RoutingToken([3u8; 32]);

        // Edge: accept the Agent, register it, then relay a stream and read the echo.
        let state_e = state.clone();
        let edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            ct_edge::serve::register_agent(&agent_conn, &state_e)
                .await
                .map_err(|e| e.to_string())?;
            let (mut send, mut recv) = agent_conn.open_bi().await.unwrap();
            send.write_all(b"ping").await.unwrap();
            send.finish().unwrap();
            let got = recv.read_to_end(64).await.unwrap();
            Ok::<Vec<u8>, String>(got)
        });

        // Agent: run the full loop (dial → register → accept-and-serve).
        let config = AgentConfig {
            edge: edge_addr,
            origin: origin_addr,
        };
        let token_a = token.clone();
        let agent = tokio::spawn(async move {
            let _ = run_agent(&config, cert, token_a).await;
        });

        let echoed = edge.await.unwrap().unwrap();
        assert_eq!(echoed, b"ping", "relayed stream reaches origin and echoes back");
        assert!(state.is_known(&token), "agent registered its tunnel");
        agent.abort();
        let _ = origin.await;
    }
}
