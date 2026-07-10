//! Edge serve orchestration (M5.1c).
//!
//! The Agent-registration path: an Agent opens a control stream and registers
//! the Routing Token it serves; the Edge stores the connection in [`EdgeState`]
//! so a later Client rendezvous for that token can be routed to it. The Client
//! route→relay path is exercised end to end in the M5.6 testbed smoke.

use crate::relay::relay_quic;
use crate::state::EdgeState;
use ct_common::pow::{check_request, Challenge};
use ct_common::RoutingToken;
use quinn::{Connection, RecvStream, SendStream};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Handle one Agent registration on `conn`: read `role='A'(1) | token(32)` on a
/// fresh bi-stream, register the connection in `state`, ack `OK`, and return the
/// registered token.
pub async fn register_agent(
    conn: &Connection,
    state: &EdgeState<Connection>,
) -> Result<RoutingToken, BoxError> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let hdr = recv.read_to_end(33).await?;
    if hdr.len() != 33 || hdr[0] != b'A' {
        return Err("malformed agent registration".into());
    }
    let mut token = [0u8; 32];
    token.copy_from_slice(&hdr[1..33]);
    let token = RoutingToken(token);

    state.register(token.clone(), conn.clone());
    send.write_all(b"OK").await?;
    send.finish()?;
    Ok(token)
}

/// Route a resolved Client stream to the Agent tunnel serving `token` and relay
/// bytes between them. Opens a fresh stream on the Agent's registered connection
/// and pipes the two together (provider-blind).
pub async fn route_and_relay(
    state: &EdgeState<Connection>,
    token: &RoutingToken,
    client_send: SendStream,
    client_recv: RecvStream,
) -> Result<(), BoxError> {
    let agent_conn = state.route(token).ok_or("no agent tunnel for token")?;
    let (agent_send, agent_recv) = agent_conn.open_bi().await?;
    relay_quic(client_send, client_recv, agent_send, agent_recv).await?;
    Ok(())
}

/// Serve one connection by dispatching on its first stream's role byte. `'A'`
/// registers an Agent tunnel (`token`); `'C'` runs a PoW-gated rendezvous, then
/// routes and relays the same stream to the Agent. This is the unified
/// per-connection Edge protocol the daemon's accept loop runs.
pub async fn serve_connection(
    conn: &Connection,
    state: &EdgeState<Connection>,
    challenge: &Challenge,
) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut role = [0u8; 1];
    recv.read_exact(&mut role).await?;

    match role[0] {
        b'A' => {
            let mut token = [0u8; 32];
            recv.read_exact(&mut token).await?;
            state.register(RoutingToken(token), conn.clone());
            send.write_all(b"OK").await?;
            send.finish()?;
            Ok(())
        }
        b'C' => {
            let mut chal = [0u8; 17];
            chal[..16].copy_from_slice(&challenge.nonce);
            chal[16] = challenge.difficulty;
            send.write_all(&chal).await?;

            let mut req = [0u8; 40];
            recv.read_exact(&mut req).await?;
            let token = check_request(challenge, &req).map_err(|_| "proof of work rejected")?;

            let agent_conn = state.route(&token).ok_or("no agent tunnel for token")?;
            let (agent_send, agent_recv) = agent_conn.open_bi().await?;
            relay_quic(send, recv, agent_send, agent_recv).await?;
            Ok(())
        }
        other => Err(format!("unknown role byte: {other}").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use std::sync::Arc;

    #[tokio::test]
    async fn agent_registers_and_becomes_known() {
        let token = RoutingToken([5u8; 32]);
        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let state_srv = state.clone();
        let token_srv = token.clone();
        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let registered = register_agent(&conn, &state_srv)
                .await
                .map_err(|e| e.to_string())?;
            assert_eq!(registered, token_srv);
            conn.closed().await;
            Ok::<(), String>(())
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("conn");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut msg = vec![b'A'];
        msg.extend_from_slice(&token.0);
        send.write_all(&msg).await.unwrap();
        send.finish().unwrap();
        let ack = recv.read_to_end(8).await.unwrap();
        assert_eq!(ack, b"OK");

        // The Edge registers before acking, so by the time we read OK the tunnel
        // is routable in the shared state.
        assert!(state.is_known(&token), "agent tunnel is now routable");
        conn.close(0u32.into(), b"done");
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn edge_routes_client_data_to_registered_agent() {
        let token = RoutingToken([5u8; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        // Edge orchestrator: register the Agent, then route the Client's stream.
        let state_e = state.clone();
        let token_e = token.clone();
        let edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            register_agent(&agent_conn, &state_e)
                .await
                .map_err(|e| e.to_string())?;

            let client_conn = server.accept().await.unwrap().await.unwrap();
            let (c_send, mut c_recv) = client_conn.accept_bi().await.unwrap();
            let mut tok = [0u8; 32];
            c_recv.read_exact(&mut tok).await.unwrap();
            route_and_relay(&state_e, &RoutingToken(tok), c_send, c_recv)
                .await
                .map_err(|e| e.to_string())?;
            Ok::<(), String>(())
        });

        // Agent connects, registers, then reads the relayed stream.
        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut reg_send, mut reg_recv) = agent_conn.open_bi().await.unwrap();
        let mut reg = vec![b'A'];
        reg.extend_from_slice(&token.0);
        reg_send.write_all(&reg).await.unwrap();
        reg_send.finish().unwrap();
        assert_eq!(reg_recv.read_to_end(8).await.unwrap(), b"OK");
        let agent_task = tokio::spawn(async move {
            let (_s, mut r) = agent_conn.accept_bi().await.unwrap();
            r.read_to_end(1024).await.unwrap()
        });

        // Client connects and sends token + data on one stream.
        let client_ep = build_client_endpoint(cert).expect("client ep");
        let client_conn = client_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("client conn");
        let (mut c_send, _c_recv) = client_conn.open_bi().await.unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&token.0);
        payload.extend_from_slice(b"client-data");
        c_send.write_all(&payload).await.unwrap();
        c_send.finish().unwrap();

        let received = agent_task.await.unwrap();
        assert_eq!(
            received, b"client-data",
            "agent receives the client's data relayed by the edge"
        );
        drop(client_conn);
        edge.abort();
    }
}
