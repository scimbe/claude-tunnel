//! Client-side PoW-gated rendezvous (M5.3a).
//!
//! The counterpart to the Edge's `resolve_rendezvous_gated`: read the Edge's
//! challenge, solve the proof of work, present `solution | token`, and await OK.

use ct_common::pow::{build_request, Challenge};
use ct_common::RoutingToken;
use quinn::Connection;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Perform PoW-gated rendezvous for `token` on `conn`. Returns `Ok(())` when the
/// Edge accepts the token.
pub async fn client_rendezvous(conn: &Connection, token: &RoutingToken) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut chal = [0u8; 17];
    recv.read_exact(&mut chal).await?;
    let challenge = Challenge {
        nonce: chal[..16].try_into().unwrap(),
        difficulty: chal[16],
    };
    let req = build_request(&challenge, token);
    send.write_all(&req).await?;
    send.finish()?;
    let ack = recv.read_to_end(8).await?;
    if ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected rendezvous".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{client_exchange, dial_edge};

    #[tokio::test]
    async fn client_tunnels_data_to_agent_through_edge() {
        use crate::transport::client_tunnel;
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use quinn::Connection;
        use std::sync::Arc;

        let token = RoutingToken([4u8; 32]);
        let challenge = Challenge {
            nonce: [0x33; 16],
            difficulty: 8,
        };
        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        // Edge: serve the Agent (register) then the Client (rendezvous+route+relay).
        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&agent_conn, &state_e, &chal_e)
                .await
                .map_err(|e| e.to_string())?;
            let client_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&client_conn, &state_e, &chal_e)
                .await
                .map_err(|e| e.to_string())?;
            client_conn.closed().await; // hold the client conn until it closes
            Ok::<(), String>(())
        });

        // Agent: register ('A' | token), then echo the relayed stream.
        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut ra_send, mut ra_recv) = agent_conn.open_bi().await.unwrap();
        ra_send.write_all(b"A").await.unwrap();
        ra_send.write_all(&token.0).await.unwrap();
        ra_send.finish().unwrap();
        assert_eq!(ra_recv.read_to_end(8).await.unwrap(), b"OK");
        let agent_task = tokio::spawn(async move {
            let (mut s, mut r) = agent_conn.accept_bi().await.unwrap();
            let data = r.read_to_end(1024).await.unwrap();
            s.write_all(&data).await.unwrap();
            s.finish().unwrap();
            agent_conn.closed().await;
        });

        // Client: tunnel data through the edge to the agent.
        let conn = dial_edge(addr, cert).await.expect("client dial");
        let resp = client_tunnel(&conn, &token, b"payload")
            .await
            .expect("client tunnel");
        assert_eq!(
            resp, b"payload",
            "client data reaches the agent and echoes back through the edge"
        );
        conn.close(0u32.into(), b"done");
        agent_task.abort();
        let _ = edge.await;
    }

    #[tokio::test]
    async fn client_exchanges_data_over_stream() {
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let edge = tokio::spawn(async move {
            ct_edge::transport::accept_and_echo_one(&server)
                .await
                .map_err(|e| e.to_string())
        });

        let conn = dial_edge(addr, cert).await.expect("dial");
        let response = client_exchange(&conn, b"hello-origin")
            .await
            .expect("exchange");
        assert_eq!(response, b"hello-origin", "data round-trips over the tunnel stream");
        conn.close(0u32.into(), b"done");
        let _ = edge.await;
    }

    #[tokio::test]
    async fn client_completes_pow_gated_rendezvous() {
        let token = RoutingToken([7u8; 32]);
        let challenge = Challenge {
            nonce: [0x11; 16],
            difficulty: 10,
        };
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        let token_e = token.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            ct_edge::rendezvous::resolve_rendezvous_gated(&server, chal_e, move |t| *t == token_e)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });

        let conn = dial_edge(addr, cert).await.expect("dial");
        client_rendezvous(&conn, &token)
            .await
            .expect("client completes rendezvous");
        conn.close(0u32.into(), b"done");
        edge.await.unwrap().expect("edge resolved");
    }

    #[tokio::test]
    async fn load_cert_reads_written_der() {
        use crate::transport::load_cert;
        let (_endpoint, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("cert");
        let path = std::env::temp_dir().join(format!("ct-client-cert-{}.der", std::process::id()));
        std::fs::write(&path, cert.as_ref()).unwrap();
        assert_eq!(load_cert(&path).unwrap(), cert);
        let _ = std::fs::remove_file(&path);
    }
}
