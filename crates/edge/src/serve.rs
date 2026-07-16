//! Edge serve orchestration (M5.1c).
//!
//! The Agent-registration path: an Agent opens a control stream and registers
//! the Routing Token it serves; the Edge stores the connection in [`EdgeState`]
//! so a later Client rendezvous for that token can be routed to it. The Client
//! route→relay path is exercised end to end in the M5.6 testbed smoke.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

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

/// How long the Edge waits for `open_bi()` to the Agent to yield a stream before
/// declaring the tunnel unresponsive. Kept under the Client's own tunnel timeout
/// (8 s) so the Edge fails first with a precise reason instead of the Client
/// giving up with an opaque "no relay" (issue #2, mode b).
const RELAY_OPEN_BI_TIMEOUT: Duration = Duration::from_secs(5);

/// First 8 hex chars of a token, for correlating an Edge trace line with a
/// field-supplied token during cross-host diagnosis.
fn token_hex(token: &RoutingToken) -> String {
    token.0.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Parse a 64-hex admin token (`CT_EDGE_ADMIN_TOKEN`) into 32 bytes, if valid (#27 RB3).
fn parse_admin_token_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut t = [0u8; 32];
    for (i, b) in t.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(t)
}

/// Emit an Edge-side diagnostic line when `CT_EDGE_TRACE` is set. Off by default
/// (no overhead / noise in production); enabled for a lockstep cross-host capture.
fn edge_trace(args: std::fmt::Arguments<'_>) {
    if std::env::var_os("CT_EDGE_TRACE").is_some() {
        eprintln!("[edge-trace] {args}");
    }
}

/// Resolve `token` to its registered Agent connection and open a relay stream to
/// it, bounded by `timeout`. Distinguishes the two cross-host failure modes the
/// Client can't tell apart: **no registration** (`route` miss) vs a **live but
/// unresponsive** Agent whose `open_bi()` never yields a stream (e.g. it granted
/// no bidi-stream credit, or the return path is broken). Traces each decision
/// point under `CT_EDGE_TRACE` (issue #2, mode b).
async fn open_agent_stream_with(
    state: &EdgeState<Connection>,
    token: &RoutingToken,
    timeout: Duration,
) -> Result<(SendStream, RecvStream), BoxError> {
    let th = token_hex(token);
    let agents = state.routes(token);
    if agents.is_empty() {
        edge_trace(format_args!("route token={th} -> MISS (no registration)"));
        return Err("no agent tunnel for token".into());
    }
    // Failover (#8 R2): try each live agent, newest first, until one opens a relay
    // stream. This covers redundant agents AND the race where the chosen agent's
    // connection is dead but not yet evicted — the next agent takes over instead
    // of the client seeing an opaque "no relay".
    let total = agents.len();
    let mut last_err = String::new();
    for (i, agent_conn) in agents.into_iter().enumerate() {
        edge_trace(format_args!(
            "route token={th} -> hit (agent {}/{total}); opening relay stream",
            i + 1
        ));
        match tokio::time::timeout(timeout, agent_conn.open_bi()).await {
            Ok(Ok(streams)) => {
                edge_trace(format_args!("open_bi token={th} agent {}/{total} -> ok", i + 1));
                if i > 0 {
                    state.note_failover(); // served by a non-primary agent (#10 O2)
                }
                return Ok(streams);
            }
            Ok(Err(e)) => {
                edge_trace(format_args!("open_bi token={th} agent {}/{total} -> err: {e}", i + 1));
                last_err = e.to_string();
            }
            Err(_) => {
                edge_trace(format_args!(
                    "open_bi token={th} agent {}/{total} -> TIMED OUT after {timeout:?}",
                    i + 1
                ));
                last_err = format!("open_bi to {th} timed out");
            }
        }
    }
    Err(format!("agent tunnel unresponsive: all {total} agent(s) failed ({last_err})").into())
}

/// [`open_agent_stream_with`] using the default [`RELAY_OPEN_BI_TIMEOUT`].
async fn open_agent_stream(
    state: &EdgeState<Connection>,
    token: &RoutingToken,
) -> Result<(SendStream, RecvStream), BoxError> {
    open_agent_stream_with(state, token, RELAY_OPEN_BI_TIMEOUT).await
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
    let (agent_send, agent_recv) = open_agent_stream(state, token).await?;
    let (a, b) = relay_quic(client_send, client_recv, agent_send, agent_recv, &token_hex(token)).await?;
    state.note_relay(a + b); // #10 O2
    Ok(())
}

/// Browser Plane (#23, sub-packet 1): serve one inbound TLS connection by SNI.
/// Peek the ClientHello's SNI hostname **without terminating TLS**, map it to a
/// routing token, open a stream to the serving Agent, replay the buffered
/// ClientHello, and relay the raw TLS bytes both ways. TLS terminates at the
/// Origin (which holds the certificate); the Edge sees only the hostname and
/// ciphertext, so the payload stays provider-blind.
pub async fn serve_sni_passthrough<S>(
    mut inbound: S,
    state: &EdgeState<Connection>,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (hello, sni) = crate::sni::read_client_hello(&mut inbound)
        .await
        .ok_or("no SNI in the TLS ClientHello")?;
    let token = state
        .route_host(&sni)
        .ok_or_else(|| format!("no tunnel registered for host '{sni}'"))?;
    let (mut agent_send, agent_recv) = open_agent_stream(state, &token).await?;
    // Replay the buffered ClientHello to the Agent first, then relay the rest so
    // the browser<->origin TLS handshake completes end-to-end through the tunnel.
    agent_send.write_all(&hello).await?;
    let mut agent = join(agent_recv, agent_send);
    let (a, b) = relay(&mut inbound, &mut agent).await?;
    state.note_relay(a + b);
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
) -> Result<Option<(RoutingToken, u64)>, BoxError> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut role = [0u8; 1];
    recv.read_exact(&mut role).await?;

    match role[0] {
        b'A' => {
            let mut token = [0u8; 32];
            recv.read_exact(&mut token).await?;
            let token = RoutingToken(token);
            // #27 RB3: a revoked token stays down even though the agent keeps
            // reconnecting — refuse the registration instead of accepting it.
            if state.is_revoked(&token) {
                send.write_all(b"NO").await?;
                send.finish()?;
                return Ok(None);
            }
            let reg = state.register_with_candidate(token.clone(), conn.clone(), conn.remote_address());
            send.write_all(b"OK").await?;
            send.finish()?;
            // Return the (token, registration id) so the caller can evict exactly
            // THIS agent when its connection drops — issue #2 (mode a): a dropped
            // agent's registration was never removed, so a later Client `route()`
            // kept resolving to a dead `Connection` whose `open_bi()` stalls.
            // The registration id (not just the token) is what makes eviction
            // precise now that multiple agents may register one token for
            // redundancy (#8): dropping one must not disturb the others.
            // Eviction lives in `run_edge`, which owns the connection lifetime;
            // keeping this path non-blocking preserves the "register then return"
            // contract the relay harnesses depend on (they serve 'A' then 'C' on
            // one task).
            Ok(Some((token, reg)))
        }
        b'C' => {
            let mut chal = [0u8; 17];
            chal[..16].copy_from_slice(&challenge.nonce);
            chal[16] = challenge.difficulty;
            send.write_all(&chal).await?;

            let mut req = [0u8; 40];
            recv.read_exact(&mut req).await?;
            let token = check_request(challenge, &req).map_err(|_| "proof of work rejected")?;

            // A QUIC client must also reach a TCP-fallback agent (#13): the TCP
            // path prefers a parked TCP agent, and the QUIC path must mirror it or
            // a QUIC-client → TCP-agent tunnel is invisible and dies with
            // `early eof`. If one is parked, hand off the joined client stream
            // (cross-transport QUIC↔TCP relay); otherwise keep the QUIC→QUIC
            // relay_quic path unchanged.
            if state.has_tcp_agent(&token) {
                match state.deliver_to_tcp_agent(&token, Box::new(join(recv, send))) {
                    Ok(()) => return Ok(None),
                    // Raced (the parked agent was consumed between check and
                    // deliver) → relay this client to a QUIC agent instead.
                    Err(mut client) => {
                        let (agent_send, agent_recv) = open_agent_stream(state, &token).await?;
                        let mut agent = join(agent_recv, agent_send);
                        let (a, b) = relay(&mut client, &mut agent).await?;
                        state.note_relay(a + b);
                        return Ok(None);
                    }
                }
            }
            let (agent_send, agent_recv) = open_agent_stream(state, &token).await?;
            let (a, b) = relay_quic(send, recv, agent_send, agent_recv, &token_hex(&token)).await?;
            state.note_relay(a + b); // #10 O2
            Ok(None)
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
            Ok(None)
        }
        b'H' => {
            // Browser Plane (#23 BP3): bind a public hostname to a routing token
            // so an SNI-routed browser connection reaches this tunnel. Wire
            // format: 'H' | token(32) | host_len(2 BE) | host. A browser-mode
            // agent declares its hostname after registering the tunnel ('A').
            let mut token = [0u8; 32];
            recv.read_exact(&mut token).await?;
            let mut hl = [0u8; 2];
            recv.read_exact(&mut hl).await?;
            let hlen = u16::from_be_bytes(hl) as usize;
            if hlen == 0 || hlen > 253 {
                return Err("invalid Browser-Plane hostname length".into());
            }
            let mut host = vec![0u8; hlen];
            recv.read_exact(&mut host).await?;
            let host = std::str::from_utf8(&host).map_err(|_| "hostname is not valid UTF-8")?;
            // Takeover-safe (#23 BP4a): refuse if the hostname is already bound to
            // a different tunnel, so a later bind can't silently steal the route.
            if state.register_host(host, RoutingToken(token)) {
                send.write_all(b"OK").await?;
            } else {
                send.write_all(b"NO").await?;
            }
            send.finish()?;
            Ok(None)
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
            Ok(None)
        }
        b'R' => {
            // #27 RB3: authenticated revoke — `'R' | admin_token(32) | routing_token(32)`.
            // The control plane calls this when a customer revokes a tunnel; the
            // edge tears the tunnel down and blocks its re-registration.
            let mut auth = [0u8; 32];
            recv.read_exact(&mut auth).await?;
            let mut token = [0u8; 32];
            recv.read_exact(&mut token).await?;
            if state.admin_revoke_ok(&auth) {
                state.revoke_token(&RoutingToken(token));
                send.write_all(b"OK").await?;
            } else {
                send.write_all(b"NO").await?;
            }
            send.finish()?;
            Ok(None)
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
                    let (agent_send, agent_recv) = open_agent_stream(state, &token).await?;
                    let mut agent = join(agent_recv, agent_send);
                    let (a, b) = relay(&mut stream, &mut agent).await?;
                    state.note_relay(a + b); // #10 O2
                    Ok(())
                }
            }
        }
        other => Err(format!("unknown TCP role byte: {other}").into()),
    }
}

/// Path of the persisted CA signing key: `edge-ca-key.pem` beside the published
/// root cert (`cert_out`), so both live on the Edge's shared/runtime volume.
fn ca_key_path_for(cert_out: &str) -> String {
    let p = std::path::Path::new(cert_out);
    match p.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => {
            dir.join("edge-ca-key.pem").to_string_lossy().into_owned()
        }
        _ => "edge-ca-key.pem".to_string(),
    }
}

/// Run the Edge daemon: bind to `config.listen`, write the cert to `cert_out`
/// (shared volume), and serve each incoming connection via [`serve_connection`]
/// with a fresh per-connection PoW challenge.
pub async fn run_edge(config: &EdgeConfig, cert_out: &str) -> Result<(), BoxError> {
    // Issue the Edge's leaf from an internal CA (M20.3b) and listen on both QUIC
    // (primary) and TLS-TCP (fallback) with that one shared leaf. Persist the CA
    // signing key beside the published root so a redeploy reloads the SAME CA
    // and every pinned Agent/Client stays valid — a fresh CA per boot rotated
    // the root under everyone and broke pins with BadSignature (issue #2).
    let ca_key_path = ca_key_path_for(cert_out);
    let ca = Ca::load_or_create(&ca_key_path, "ct-edge-ca")?;
    let (endpoint, tcp_listener, acceptor, ca_root) =
        build_dual_edge_from_ca(&ca, config.listen, config.listen, vec!["localhost".to_string()])
            .await?;
    // Publish the CA *root* (not the leaf): Agents/Clients trust the CA and
    // therefore any Edge leaf it signs, so the cert can rotate without redistribution.
    save_cert(cert_out, &ca_root)?;

    let state = Arc::new(EdgeState::<Connection>::new());
    // #27 RB3: enable the authenticated revoke op only when the shared admin
    // secret is configured (64-hex CT_EDGE_ADMIN_TOKEN, matching the control
    // plane's CT_CP_EDGE_ADMIN_TOKEN). Absent -> revocation stays disabled.
    if let Some(tok) = std::env::var("CT_EDGE_ADMIN_TOKEN")
        .ok()
        .and_then(|s| parse_admin_token_hex(&s))
    {
        state.set_admin_token(tok);
        eprintln!("ct-edge: tunnel revocation enabled (CT_EDGE_ADMIN_TOKEN set)");
        // #27 RB4: serve the authenticated admin API (POST /admin/revoke/:token)
        // the control plane calls on a customer revoke — only when an admin
        // listener is configured, and bind it to a private interface in prod.
        if let Ok(addr) = std::env::var("CT_EDGE_ADMIN_LISTEN") {
            match addr.parse::<SocketAddr>() {
                Ok(listen) => {
                    let astate = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = crate::admin::serve_admin(astate, listen).await {
                            eprintln!("ct-edge: admin endpoint on {listen} exited: {e}");
                        }
                    });
                }
                Err(e) => eprintln!("ct-edge: invalid CT_EDGE_ADMIN_LISTEN '{addr}': {e}"),
            }
        }
    }
    let difficulty = config.pow_difficulty;

    // Optional observability endpoint (#10): serve GET /metrics with the Edge's
    // live gauges when CT_EDGE_METRICS_LISTEN is set (off by default). Metadata
    // only — the Edge stays provider-blind.
    if let Ok(addr) = std::env::var("CT_EDGE_METRICS_LISTEN") {
        match addr.parse::<SocketAddr>() {
            Ok(listen) => {
                let mstate = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::observe::serve_metrics(listen, mstate).await {
                        eprintln!("ct-edge: metrics endpoint on {listen} exited: {e}");
                    }
                });
                eprintln!("ct-edge: metrics endpoint on {listen} (GET /metrics)");
            }
            Err(e) => eprintln!("ct-edge: invalid CT_EDGE_METRICS_LISTEN '{addr}': {e}"),
        }
    }

    // Browser Plane public listener (#23 BP3): a RAW TCP listener that routes an
    // incoming browser TLS connection to a tunnel by its SNI hostname WITHOUT
    // terminating TLS (serve_sni_passthrough) — TLS terminates at the Origin, so
    // the Edge stays payload-blind. Off by default; set
    // CT_EDGE_BROWSER_LISTEN=0.0.0.0:443. Hostnames are bound by agents via 'H'.
    if let Ok(addr) = std::env::var("CT_EDGE_BROWSER_LISTEN") {
        match addr.parse::<SocketAddr>() {
            Ok(listen) => match tokio::net::TcpListener::bind(listen).await {
                Ok(bl) => {
                    let bstate = state.clone();
                    tokio::spawn(async move {
                        while let Ok((tcp, _)) = bl.accept().await {
                            let state = bstate.clone();
                            tokio::spawn(async move {
                                let _ = serve_sni_passthrough(tcp, &state).await;
                            });
                        }
                    });
                    eprintln!("ct-edge: Browser-Plane SNI listener on {listen}");
                }
                Err(e) => eprintln!("ct-edge: cannot bind CT_EDGE_BROWSER_LISTEN {listen}: {e}"),
            },
            Err(e) => eprintln!("ct-edge: invalid CT_EDGE_BROWSER_LISTEN '{addr}': {e}"),
        }
    }

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
                let registered = serve_connection(&conn, &state, &challenge).await;
                conn.closed().await;
                // Evict exactly this dropped agent's registration so a later
                // Client route() fails fast instead of hitting a dead handle (#2)
                // — and, with redundant agents (#8), so the OTHER agents serving
                // the same token keep the tunnel up.
                if let Ok(Some((token, reg))) = registered {
                    state.remove_registration(&token, reg);
                }
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
    async fn registration_is_evicted_when_the_agent_connection_drops() {
        // issue #2 (mode a): after an Agent registers over QUIC and its
        // connection drops, the Edge must evict the registration so a later
        // Client `route()` returns None (fail fast) rather than resolving to a
        // dead Connection. Drives the real `serve_connection` 'A' path.
        let token = RoutingToken([7u8; 32]);
        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let state_srv = state.clone();
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let challenge = Challenge {
                nonce: [0u8; 16],
                difficulty: 0,
            };
            // Mirror run_edge: serve, then on close evict the returned registration.
            let registered = serve_connection(&conn, &state_srv, &challenge).await;
            assert!(
                matches!(&registered, Ok(Some(_))),
                "'A' registration returns its (token, id) for eviction"
            );
            conn.closed().await;
            if let Ok(Some((token, reg))) = registered {
                state_srv.remove_registration(&token, reg);
            }
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
        assert!(state.route(&token).is_some(), "routable while the agent is alive");

        // The agent drops — the edge must evict within a bounded window.
        conn.close(0u32.into(), b"gone");
        drop(client);
        let evicted = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while state.route(&token).is_some() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(evicted.is_ok(), "dead registration evicted after the connection dropped");
        assert!(state.candidate(&token).is_none(), "candidate evicted too");
        edge.abort();
    }

    #[tokio::test]
    async fn registration_is_evicted_when_a_killed_agent_goes_idle() {
        // issue #8 (failover regression): the test above covers a *graceful*
        // drop (`conn.close` sends a QUIC CLOSE frame → `conn.closed()` fires at
        // once). A *killed* agent sends NO close frame, so eviction can only fire
        // on the Edge server's idle timeout. Without an Edge-side
        // `max_idle_timeout` the dead registration lingers (~30s peer-negotiated),
        // clients keep routing to the corpse, and redundancy failover never
        // engages — which is exactly what `redundancy-smoke.sh` caught. This pins
        // the mechanism the production fix adds (`edge_server_transport`): build a
        // server with a short idle timeout, register an agent, then let its
        // connection go SILENT (no keepalive, no close — the kill analogue) and
        // assert the idle timeout tears it down so `run_edge`'s eviction runs.
        use quinn::{Endpoint, IdleTimeout, TransportConfig};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::net::Ipv4Addr;

        let token = RoutingToken([11u8; 32]);
        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());

        // Edge server with a 1s idle timeout (fast analogue of the production
        // ~10s) and NO keepalive — so a silent peer idles out within the test
        // window instead of being kept warm.
        crate::transport::install_crypto_provider();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = certified.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.key_pair.serialize_der(),
        ));
        let mut server_config =
            quinn::ServerConfig::with_single_cert(vec![cert.clone()], key).unwrap();
        let mut t = TransportConfig::default();
        t.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(1)).unwrap()));
        server_config.transport_config(Arc::new(t));
        let server =
            Endpoint::server(server_config, (Ipv4Addr::LOCALHOST, 0).into()).expect("server");
        let addr = server.local_addr().expect("addr");

        let state_srv = state.clone();
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            // Mirror run_edge exactly: serve, await close, evict on drop.
            let registered = serve_connection(&conn, &state_srv, &challenge).await;
            conn.closed().await;
            if let Ok(Some((token, reg))) = registered {
                state_srv.remove_registration(&token, reg);
            }
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
        assert!(state.route(&token).is_some(), "routable while the agent is alive");

        // The agent goes SILENT — no close frame, no keepalive (the kill case).
        // The Edge's idle timeout must tear the connection down so eviction runs
        // well before the old ~30s peer-negotiated timeout. Hold `conn`/`client`
        // (do NOT drop them, which would send a close) so only the idle path can
        // trigger eviction.
        let evicted = tokio::time::timeout(Duration::from_secs(5), async {
            while state.route(&token).is_some() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            evicted.is_ok(),
            "a killed (silent) agent is evicted via the edge idle timeout"
        );
        drop(conn);
        drop(client);
        edge.abort();
    }

    #[tokio::test]
    async fn open_agent_stream_distinguishes_missing_from_unresponsive() {
        // issue #2 (mode b): the Client can't tell "no registration" from "live
        // agent that never yields a relay stream" — both look like "no relay".
        // The Edge must: (1) return the missing-registration error for an unknown
        // token, and (2) time out with a distinct "unresponsive" verdict when a
        // registered, still-connected agent grants no bidi-stream credit (so the
        // Edge's open_bi() never completes) — instead of hanging until the Client
        // gives up.
        use quinn::{Endpoint, TransportConfig};
        use std::net::Ipv4Addr;

        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());

        // (1) Unknown token → immediate missing-registration error.
        let miss = open_agent_stream_with(&state, &RoutingToken([9u8; 32]), Duration::from_millis(300))
            .await
            .unwrap_err()
            .to_string();
        assert!(miss.contains("no agent tunnel"), "unknown token: {miss}");

        // (2) A live agent that grants the Edge zero bidi streams.
        let token = RoutingToken([8u8; 32]);
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().unwrap();
        let state_srv = state.clone();
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            let _ = serve_connection(&conn, &state_srv, &challenge).await;
        });

        // Starved client: allows the peer (edge) to open 0 bidi streams toward it.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ));
        let mut tc = TransportConfig::default();
        tc.max_concurrent_bidi_streams(0u32.into());
        cfg.transport_config(Arc::new(tc));
        let mut client = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        client.set_default_client_config(cfg);

        let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
        // Registration is a client-initiated stream, so it succeeds despite the 0
        // peer-bidi limit; the agent then stays connected.
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut msg = vec![b'A'];
        msg.extend_from_slice(&token.0);
        send.write_all(&msg).await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(8).await.unwrap(), b"OK");
        assert!(state.route(&token).is_some(), "registered and live");

        // The Edge tries to open a relay stream: it can't (0 credit) and must time
        // out with the distinct unresponsive verdict, not hang.
        let err = open_agent_stream_with(&state, &token, Duration::from_millis(300))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("unresponsive"), "live-but-starved agent: {err}");

        conn.close(0u32.into(), b"done");
        edge.abort();
    }

    #[tokio::test]
    async fn relay_fails_over_from_a_dead_agent_to_a_live_one() {
        // #8 R2: two agents serve one token; the most-recent one can't open a
        // relay stream (0 bidi-stream credit = effectively dead), so
        // open_agent_stream must fail over to the surviving agent instead of
        // returning "no relay".
        use quinn::{Endpoint, TransportConfig};
        use std::net::Ipv4Addr;

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().unwrap();
        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());
        let token = RoutingToken([5u8; 32]);

        // Healthy agent (default bidi credit) connects first → registered older.
        let healthy_ep = build_client_endpoint(cert.clone()).unwrap();
        let h_task =
            tokio::spawn(async move { healthy_ep.connect(addr, "localhost").unwrap().await.unwrap() });
        let srv_healthy = server.accept().await.unwrap().await.unwrap();
        let _h_client = h_task.await.unwrap();
        state.register(token.clone(), srv_healthy);

        // Starved agent (0 bidi credit) connects second → registered most-recent.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ));
        let mut tc = TransportConfig::default();
        tc.max_concurrent_bidi_streams(0u32.into());
        cfg.transport_config(Arc::new(tc));
        let mut starved_ep = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        starved_ep.set_default_client_config(cfg);
        let s_task =
            tokio::spawn(async move { starved_ep.connect(addr, "localhost").unwrap().await.unwrap() });
        let srv_starved = server.accept().await.unwrap().await.unwrap();
        let _s_client = s_task.await.unwrap();
        state.register(token.clone(), srv_starved);

        assert_eq!(state.registration_count(&token), 2, "two redundant agents");

        // Tries the starved (most-recent) agent first → times out → fails over to
        // the healthy one and returns a stream.
        let r = open_agent_stream_with(&state, &token, Duration::from_millis(300)).await;
        assert!(r.is_ok(), "failed over to the surviving agent: {:?}", r.err());
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
    async fn quic_client_reaches_a_tcp_fallback_agent() {
        // #13: the mirror of edge_relays_tcp_fallback_client_to_quic_agent — a
        // QUIC client must reach a parked TCP-fallback agent. Before the fix,
        // serve_connection's 'C' arm ignored deliver_to_tcp_agent and the tunnel
        // died with `early eof`.
        use crate::transport::{
            build_client_endpoint, build_server_endpoint_with_cert, build_tcp_tls_listener_at,
            tcp_tls_connect,
        };
        use ct_common::pow::build_request;
        use std::net::Ipv4Addr;

        let token = RoutingToken([0x77; 32]);
        let challenge = Challenge {
            nonce: [0x55; 16],
            difficulty: 8,
        };
        let state = Arc::new(EdgeState::<Connection>::new());

        // QUIC edge (for the client) + TLS-TCP listener (for the fallback agent).
        let (server, qcert) = build_server_endpoint_with_cert().expect("quic edge");
        let qaddr = server.local_addr().unwrap();
        let (tcp_listener, acceptor, tcert) =
            build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into()).await.expect("tcp edge");
        let taddr = tcp_listener.local_addr().unwrap();

        // TLS-TCP edge: serve the fallback AGENT ('A' → park → relay).
        let state_t = state.clone();
        let chal_t = challenge.clone();
        let tcp_edge = tokio::spawn(async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let _ = serve_tcp_connection(tls, &state_t, &chal_t).await;
        });

        // Agent over TLS-TCP: register 'A', then echo the relayed client bytes.
        let agent = tokio::spawn(async move {
            let mut a = tcp_tls_connect(taddr, tcert).await.expect("agent tcp connect");
            a.write_all(b"A").await.unwrap();
            a.write_all(&token.0).await.unwrap();
            a.flush().await.unwrap();
            let mut ok = [0u8; 2];
            a.read_exact(&mut ok).await.unwrap();
            assert_eq!(&ok, b"OK");
            let mut buf = [0u8; 15];
            a.read_exact(&mut buf).await.unwrap();
            a.write_all(&buf).await.unwrap();
            a.flush().await.unwrap();
        });

        // Let the agent register + park before the client rendezvouses.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // QUIC edge: serve one client connection.
        let state_q = state.clone();
        let chal_q = challenge.clone();
        let quic_edge = tokio::spawn(async move {
            let client_conn = server.accept().await.unwrap().await.unwrap();
            let _ = serve_connection(&client_conn, &state_q, &chal_q).await;
            client_conn.closed().await;
        });

        // QUIC client: 'C' rendezvous + 15 bytes, read the 15-byte echo.
        let client_ep = build_client_endpoint(qcert).expect("client ep");
        let cconn = client_ep.connect(qaddr, "localhost").unwrap().await.unwrap();
        let (mut cs, mut cr) = cconn.open_bi().await.unwrap();
        cs.write_all(b"C").await.unwrap();
        let mut chal = [0u8; 17];
        cr.read_exact(&mut chal).await.unwrap();
        let ch = Challenge {
            nonce: chal[..16].try_into().unwrap(),
            difficulty: chal[16],
        };
        cs.write_all(&build_request(&ch, &token)).await.unwrap();
        cs.write_all(b"quic-to-tcp-agt").await.unwrap();
        let mut got = [0u8; 15];
        cr.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"quic-to-tcp-agt", "QUIC client relayed to the TCP-fallback agent");

        agent.await.unwrap();
        quic_edge.abort();
        tcp_edge.abort();
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

    #[tokio::test]
    async fn sni_passthrough_routes_a_browser_tls_connection_to_the_origin() {
        // #23 Browser Plane (sub-packet 1): a plain rustls "browser" reaches a
        // public-hostname HTTPS origin THROUGH the tunnel, routed purely by the
        // TLS SNI — the edge never terminates TLS (provider-blind), and the
        // browser validates the origin's cert client-side (TLS terminates at the
        // origin). No ct-client protocol, no capability: just SNI -> tunnel.
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        crate::transport::install_crypto_provider();

        // A "public" HTTPS origin with a cert for browser.test (the browser
        // trusts it, standing in for a publicly-trusted / Let's Encrypt cert).
        let certified =
            rcgen::generate_simple_self_signed(vec!["browser.test".to_string()]).unwrap();
        let origin_cert = certified.cert.der().clone();
        let origin_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![origin_cert.clone()], origin_key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));
        let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (sock, _) = origin_listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.expect("origin TLS handshake");
            let mut b = [0u8; 1024];
            let n = tls.read(&mut b).await.unwrap();
            assert!(b[..n].starts_with(b"GET "), "origin got an HTTP request over TLS");
            tls.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await
                .unwrap();
            tls.shutdown().await.unwrap();
        });

        // Edge + a raw-forwarding Agent: the agent pipes the tunnel stream to the
        // origin verbatim (Browser Plane carries raw TLS, not Noise).
        let token = RoutingToken([0x42; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());
        state.register_host("Browser.Test", token.clone()); // case-insensitive
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let edge_addr = server.local_addr().unwrap();
        let state_e = state.clone();
        let edge_srv = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            let _ = serve_connection(&conn, &state_e, &challenge).await;
            conn.closed().await;
        });
        let agent_ep = build_client_endpoint(cert).expect("agent ep");
        let agent_conn = agent_ep
            .connect(edge_addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut a_s, mut a_r) = agent_conn.open_bi().await.unwrap();
        a_s.write_all(b"A").await.unwrap();
        a_s.write_all(&token.0).await.unwrap();
        a_s.finish().unwrap();
        assert_eq!(a_r.read_to_end(8).await.unwrap(), b"OK");
        let agent_task = tokio::spawn(async move {
            let (e_send, e_recv) = agent_conn.accept_bi().await.unwrap();
            let mut edge_side = tokio::io::join(e_recv, e_send);
            let mut origin_tcp = tokio::net::TcpStream::connect(origin_addr).await.unwrap();
            let _ = crate::relay::relay(&mut edge_side, &mut origin_tcp).await;
        });

        // Browser: rustls over a duplex; the other end feeds serve_sni_passthrough.
        let (browser_side, edge_inbound) = tokio::io::duplex(64 * 1024);
        let state_p = state.clone();
        let pass =
            tokio::spawn(async move { serve_sni_passthrough(edge_inbound, &state_p).await });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(origin_cert).unwrap();
        let ccfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
        let sni = rustls::pki_types::ServerName::try_from("browser.test").unwrap();
        let mut tls = connector
            .connect(sni, browser_side)
            .await
            .expect("browser validates the cert and completes TLS via SNI routing");
        tls.write_all(b"GET / HTTP/1.0\r\nHost: browser.test\r\n\r\n").await.unwrap();
        tls.flush().await.unwrap();
        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let page = String::from_utf8_lossy(&resp);
        assert!(
            page.contains("200 OK") && page.contains("hello"),
            "HTTPS 200 through the tunnel via SNI passthrough: {page}"
        );

        pass.abort();
        agent_task.abort();
        edge_srv.abort();
        origin.abort();
    }

    #[tokio::test]
    async fn agent_binds_a_hostname_via_the_h_role() {
        // #23 BP3: an agent binds host -> token over the edge protocol (role 'H'),
        // so an SNI-routed browser can later reach this tunnel. Case-insensitive.
        let token = RoutingToken([0x5A; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().unwrap();
        let state_e = state.clone();
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            let _ = serve_connection(&conn, &state_e, &challenge).await;
            conn.closed().await;
        });
        let ep = build_client_endpoint(cert).expect("client");
        let conn = ep.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        let host = b"Shop.Example.Test";
        s.write_all(b"H").await.unwrap();
        s.write_all(&token.0).await.unwrap();
        s.write_all(&(host.len() as u16).to_be_bytes()).await.unwrap();
        s.write_all(host).await.unwrap();
        s.finish().unwrap();
        assert_eq!(r.read_to_end(8).await.unwrap(), b"OK");
        assert_eq!(
            state.route_host("shop.example.test"),
            Some(token),
            "host bound case-insensitively to the token"
        );
        conn.close(0u32.into(), b"done");
        edge.abort();
    }
}
