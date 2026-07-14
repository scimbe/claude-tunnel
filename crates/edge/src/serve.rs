//! Edge serve orchestration (M5.1c).
//!
//! The Agent-registration path: an Agent opens a control stream and registers
//! the Routing Token it serves; the Edge stores the connection in [`EdgeState`]
//! so a later Client rendezvous for that token can be routed to it. The Client
//! route→relay path is exercised end to end in the M5.6 testbed smoke.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::EdgeConfig;
use crate::relay::{relay, relay_quic};
use crate::state::EdgeState;
use crate::pki::{build_dual_edge_from_ca, Ca};
use crate::transport::save_cert;
use ct_common::pow::{check_request, Challenge};
use ct_common::RoutingToken;
use quinn::{Connection, RecvStream, SendStream};
use rand::RngCore;
use tokio::io::{join, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

    // Record the Agent's Edge-observed reflexive address as its peer candidate
    // for P2P rendezvous (M11.2).
    state.register_with_candidate(token.clone(), conn.clone(), conn.remote_address());
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
            state.register_with_candidate(
                RoutingToken(token),
                conn.clone(),
                conn.remote_address(),
            );
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
        b'D' => {
            // Agent advertises its direct-path listener (M11.4b-ii):
            // token(32) | addr_len(1) | addr | cert_len(2 BE) | cert.
            let mut token = [0u8; 32];
            recv.read_exact(&mut token).await?;
            let mut al = [0u8; 1];
            recv.read_exact(&mut al).await?;
            let mut addr_buf = vec![0u8; al[0] as usize];
            recv.read_exact(&mut addr_buf).await?;
            let mut cl = [0u8; 2];
            recv.read_exact(&mut cl).await?;
            let mut cert = vec![0u8; u16::from_be_bytes(cl) as usize];
            recv.read_exact(&mut cert).await?;
            let addr: SocketAddr = std::str::from_utf8(&addr_buf)?.parse()?;
            state.advertise_direct(RoutingToken(token), addr, cert);
            send.write_all(b"OK").await?;
            send.finish()?;
            Ok(())
        }
        b'P' => {
            // Client queries the Agent's advertised direct endpoint (M11.4b-ii):
            // reply `[0]` if none, else `[1] addr_len(1) addr cert_len(2 BE) cert`.
            // Separate from the 'C' relay flow — it changes no data path.
            let mut token = [0u8; 32];
            recv.read_exact(&mut token).await?;
            match state.direct_endpoint(&RoutingToken(token)) {
                Some((addr, cert)) => {
                    let a = addr.to_string();
                    let ab = a.as_bytes();
                    send.write_all(&[1u8, ab.len() as u8]).await?;
                    send.write_all(ab).await?;
                    send.write_all(&(cert.len() as u16).to_be_bytes()).await?;
                    send.write_all(&cert).await?;
                }
                None => {
                    send.write_all(&[0u8]).await?;
                }
            }
            send.finish()?;
            Ok(())
        }
        other => Err(format!("unknown role byte: {other}").into()),
    }
}

/// Serve one connection over the **TCP fallback** (M12.2b, issue #3 / P1.2c-3b)
/// by dispatching on the first byte's role:
///
/// * `'A'` — an Agent registers over TCP (UDP/QUIC blocked): read the token, ack
///   `OK`, park in the rendezvous, and relay this stream to the first Client that
///   arrives (single-tunnel — a TCP agent has one stream, no QUIC-style muxing).
/// * `'C'` — a Client runs the `'C'` rendezvous (challenge → PoW) and is delivered
///   to a parked TCP agent if one exists, else relayed to a QUIC-registered agent.
///
/// The relay is transport-agnostic, so any Client (TCP or QUIC) bridges to either
/// a TCP-registered or a QUIC-registered agent.
pub async fn serve_tcp_connection<S>(
    mut stream: S,
    state: &EdgeState<Connection>,
    challenge: &Challenge,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut role = [0u8; 1];
    stream.read_exact(&mut role).await?;
    match role[0] {
        b'A' => {
            let mut token_buf = [0u8; 32];
            stream.read_exact(&mut token_buf).await?;
            let token = RoutingToken(token_buf);
            stream.write_all(b"OK").await?;
            stream.flush().await?;
            // Park and await a Client, then relay this agent stream to it.
            match state.park_tcp_agent(token).await {
                Ok(mut client) => {
                    relay(&mut stream, &mut client).await?;
                    Ok(())
                }
                // Never matched with a Client (edge shutdown / registration replaced).
                Err(_) => Ok(()),
            }
        }
        b'C' => {
            let mut chal = [0u8; 17];
            chal[..16].copy_from_slice(&challenge.nonce);
            chal[16] = challenge.difficulty;
            stream.write_all(&chal).await?;
            stream.flush().await?;

            let mut req = [0u8; 40];
            stream.read_exact(&mut req).await?;
            let token = check_request(challenge, &req).map_err(|_| "proof of work rejected")?;

            // Prefer a parked TCP-fallback agent; else relay to a QUIC agent.
            match state.deliver_to_tcp_agent(&token, Box::new(stream)) {
                Ok(()) => Ok(()),
                Err(mut stream) => {
                    let agent_conn = state.route(&token).ok_or("no agent tunnel for token")?;
                    let (agent_send, agent_recv) = agent_conn.open_bi().await?;
                    let mut agent = join(agent_recv, agent_send);
                    relay(&mut stream, &mut agent).await?;
                    Ok(())
                }
            }
        }
        other => Err(format!("unknown TCP role byte: {other}").into()),
    }
}

/// Run the Edge daemon: bind to `config.listen`, write the cert to `cert_out`
/// (shared volume), and serve each incoming connection via [`serve_connection`]
/// with a fresh per-connection PoW challenge.
pub async fn run_edge(config: &EdgeConfig, cert_out: &str) -> Result<(), BoxError> {
    // Issue the Edge's leaf from an internal CA (M20.3b) and listen on both QUIC
    // (primary) and TLS-TCP (fallback) with that one shared leaf.
    let ca = Ca::new("ct-edge-ca")?;
    let (endpoint, tcp_listener, acceptor, ca_root) =
        build_dual_edge_from_ca(&ca, config.listen, config.listen, vec!["localhost".to_string()])
            .await?;
    // Publish the CA *root* (not the leaf): Agents/Clients trust the CA and
    // therefore any Edge leaf it signs, so the cert can rotate without redistribution.
    save_cert(cert_out, &ca_root)?;

    let state = Arc::new(EdgeState::<Connection>::new());
    let difficulty = config.pow_difficulty;

    // TCP fallback accept loop (for Clients whose outbound UDP is blocked).
    let state_tcp = state.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = tcp_listener.accept().await {
            let acceptor = acceptor.clone();
            let state = state_tcp.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let mut nonce = [0u8; 16];
                    rand::rngs::OsRng.fill_bytes(&mut nonce);
                    let challenge = Challenge { nonce, difficulty };
                    let _ = serve_tcp_connection(tls, &state, &challenge).await;
                }
            });
        }
    });

    // QUIC accept loop (primary).
    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                let mut nonce = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                let challenge = Challenge { nonce, difficulty };
                let _ = serve_connection(&conn, &state, &challenge).await;
                conn.closed().await;
            }
        });
    }
    Ok(())
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
        // And its Edge-observed peer candidate is recorded (M11.2).
        assert!(
            state.candidate(&token).is_some(),
            "agent peer candidate recorded at registration"
        );
        conn.close(0u32.into(), b"done");
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn edge_relays_tcp_fallback_client_to_quic_agent() {
        // M12.2b: a Client on the TCP fallback ('C' + PoW over TLS-TCP) is
        // relayed to a QUIC-registered Agent (cross-transport relay).
        use crate::transport::{
            build_client_endpoint, build_server_endpoint_with_cert, build_tcp_tls_listener_at,
            tcp_tls_connect,
        };
        use ct_common::pow::build_request;
        use std::net::Ipv4Addr;

        let token = RoutingToken([0x66; 32]);
        let challenge = Challenge {
            nonce: [0x44; 16],
            difficulty: 8,
        };
        let state = Arc::new(EdgeState::<Connection>::new());

        // QUIC edge (for the Agent) + TLS-TCP listener (for the fallback Client).
        let (server, qcert) = build_server_endpoint_with_cert().expect("quic edge");
        let qaddr = server.local_addr().unwrap();
        let (tcp_listener, acceptor, tcert) =
            build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into()).await.expect("tcp edge");
        let taddr = tcp_listener.local_addr().unwrap();

        // QUIC edge: register the Agent, keep the connection alive.
        let state_q = state.clone();
        let quic_edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            register_agent(&agent_conn, &state_q).await.map_err(|e| e.to_string())?;
            agent_conn.closed().await;
            Ok::<(), String>(())
        });

        // Agent: QUIC connect, register, echo the relayed stream (fixed 15 bytes).
        let agent_ep = build_client_endpoint(qcert).expect("agent ep");
        let aconn = agent_ep.connect(qaddr, "localhost").unwrap().await.unwrap();
        let (mut rs, mut rr) = aconn.open_bi().await.unwrap();
        rs.write_all(b"A").await.unwrap();
        rs.write_all(&token.0).await.unwrap();
        rs.finish().unwrap();
        assert_eq!(rr.read_to_end(8).await.unwrap(), b"OK");
        let agent = tokio::spawn(async move {
            let (mut s, mut r) = aconn.accept_bi().await.unwrap();
            let mut buf = [0u8; 15];
            r.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
            s.finish().unwrap();
            aconn.closed().await;
        });

        // TLS-TCP edge: serve one fallback client.
        let state_t = state.clone();
        let chal_t = challenge.clone();
        let tcp_edge = tokio::spawn(async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let _ = serve_tcp_connection(tls, &state_t, &chal_t).await;
        });

        // Client over TLS-TCP: 'C' rendezvous + 15 bytes, read the 15-byte echo.
        let mut client = tcp_tls_connect(taddr, tcert).await.expect("tcp connect");
        client.write_all(b"C").await.unwrap();
        let mut chal = [0u8; 17];
        client.read_exact(&mut chal).await.unwrap();
        let ch = Challenge {
            nonce: chal[..16].try_into().unwrap(),
            difficulty: chal[16],
        };
        client.write_all(&build_request(&ch, &token)).await.unwrap();
        client.write_all(b"tcp-tunnel-data").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 15];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"tcp-tunnel-data", "TCP fallback client relayed to the QUIC agent");

        agent.await.unwrap();
        quic_edge.abort();
        tcp_edge.abort();
    }

    #[tokio::test]
    async fn edge_routes_client_data_to_registered_agent() {
        let token = RoutingToken([5u8; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        // Edge orchestrator: register the Agent, then route the Client's stream.
        let state_e = state.clone();
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

    #[tokio::test]
    async fn tcp_agent_registers_and_relays_a_delivered_client() {
        // issue #3 / P1.2c-3b: an Agent registers over the TCP fallback ('A'),
        // parks, and the edge relays a delivered Client stream to it end to end.
        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x55; 32]);
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        // Run the edge 'A' handler on the edge side of the agent duplex.
        let (mut agent_peer, agent_edge) = tokio::io::duplex(1024);
        let state_a = state.clone();
        let chal_a = challenge.clone();
        let edge = tokio::spawn(async move { serve_tcp_connection(agent_edge, &state_a, &chal_a).await });

        // Agent peer: register 'A' | token, read OK, then echo (origin-relay sim).
        let mut hdr = vec![b'A'];
        hdr.extend_from_slice(&token.0);
        agent_peer.write_all(&hdr).await.unwrap();
        let mut ok = [0u8; 2];
        agent_peer.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK", "edge acks the TCP registration");
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 5];
            agent_peer.read_exact(&mut buf).await.unwrap();
            agent_peer.write_all(&buf).await.unwrap();
            agent_peer.flush().await.unwrap();
        });

        // Once parked, deliver a Client stream (the 'C'/PoW path is tested
        // separately); the edge relays agent <-> client.
        while !state.has_tcp_agent(&token) {
            tokio::task::yield_now().await;
        }
        let (mut client_peer, client_edge) = tokio::io::duplex(1024);
        state
            .deliver_to_tcp_agent(&token, Box::new(client_edge))
            .map_err(|_| "deliver failed")
            .unwrap();

        client_peer.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        client_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello", "round-trip relayed through the TCP-registered agent");

        echo.await.unwrap();
        drop(client_peer);
        let _ = edge.await;
    }
}
