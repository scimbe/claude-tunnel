//! Edge rendezvous — token resolution (ADR-0006, ADR-0015).
//!
//! P2.3a: a Client presents a Routing Token; the Edge resolves it against the
//! Tunnel Registry — via a caller-supplied `is_known` predicate, so the Edge
//! stays decoupled from the control-plane registry type — and replies OK/NO.
//! The actual byte relay to the Agent (relay-first path) is P2.4.

use ct_common::RoutingToken;
use quinn::Endpoint;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Accept one connection, read the 32-byte Routing Token the Client presents,
/// resolve it via `is_known`, reply `OK`/`NO`, and return the token on success.
pub async fn resolve_rendezvous<F>(endpoint: &Endpoint, is_known: F) -> Result<RoutingToken, BoxError>
where
    F: Fn(&RoutingToken) -> bool,
{
    let incoming = endpoint
        .accept()
        .await
        .ok_or("endpoint closed with no incoming")?;
    let conn = incoming.await?;
    let (mut send, mut recv) = conn.accept_bi().await?;
    let bytes = recv.read_to_end(64).await?;
    if bytes.len() != 32 {
        let _ = send.write_all(b"NO").await;
        let _ = send.finish();
        return Err("routing token must be 32 bytes".into());
    }
    let mut token = [0u8; 32];
    token.copy_from_slice(&bytes);
    let token = RoutingToken(token);

    if is_known(&token) {
        send.write_all(b"OK").await?;
        send.finish()?;
        conn.closed().await; // hold the connection so the Client reads the ack
        Ok(token)
    } else {
        let _ = send.write_all(b"NO").await;
        let _ = send.finish();
        Err("unknown routing token".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use quinn::Connection;

    async fn present_token(conn: &Connection, token: &RoutingToken) -> Vec<u8> {
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        send.write_all(&token.0).await.expect("write token");
        send.finish().expect("finish");
        recv.read_to_end(64).await.unwrap_or_default()
    }

    #[tokio::test]
    async fn edge_resolves_known_token() {
        let known = RoutingToken([7u8; 32]);
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let known_task = known.clone();
        let server_task = tokio::spawn(async move {
            resolve_rendezvous(&server, move |t| *t == known_task)
                .await
                .map_err(|e| e.to_string())
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("conn");
        let ack = present_token(&conn, &known).await;
        assert_eq!(ack, b"OK");
        conn.close(0u32.into(), b"done");
        let resolved = server_task.await.expect("join").expect("resolved");
        assert_eq!(resolved, known);
    }

    #[tokio::test]
    async fn edge_rejects_unknown_token() {
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            resolve_rendezvous(&server, |_| false)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("conn");
        let ack = present_token(&conn, &RoutingToken([9u8; 32])).await;
        assert_ne!(ack, b"OK", "unknown token must not be accepted");
        let _ = server_task.await;
    }
}
