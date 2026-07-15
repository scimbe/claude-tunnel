//! Client → Edge transport (M5.3a).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use crate::noise::client_noise_exchange;
use ct_common::noise::{client_handshake_for, frame, noise_pump, read_frame};
use ct_common::pow::{build_request, Challenge};
use ct_common::{Capability, RoutingToken};
use quinn::{Connection, Endpoint};
use rustls::pki_types::CertificateDer;
use std::io;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{join, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Dial the Edge over QUIC, trusting `edge_cert`.
pub async fn dial_edge(
    edge: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<Connection, BoxError> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(edge_cert)?;
    let crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    // Bind all interfaces (not loopback) so the Client can reach a non-local Edge.
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    endpoint.set_default_client_config(cfg);
    let conn = endpoint.connect(edge, "localhost")?.await?;
    Ok(conn)
}

/// After rendezvous, open a data stream to the Edge and exchange `input` for the
/// tunnel's response. In the daemon, `input`/output are the Client's local
/// socket; the Edge relays the stream to the Agent → Origin.
pub async fn client_exchange(conn: &Connection, input: &[u8]) -> Result<Vec<u8>, BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(input).await?;
    send.finish()?;
    let response = recv.read_to_end(64 * 1024).await?;
    Ok(response)
}

/// Load an Edge certificate (DER) the Edge published to a shared path.
pub fn load_cert(path: impl AsRef<Path>) -> std::io::Result<CertificateDer<'static>> {
    Ok(CertificateDer::from(std::fs::read(path)?))
}

/// Tunnel `input` to the Origin through the Edge in one stream, matching the
/// Edge's `serve_connection` `'C'` path: send role `'C'`, read the challenge,
/// present `solution | token`, send the data, and read the tunnel's response.
pub async fn client_tunnel(
    conn: &Connection,
    token: &RoutingToken,
    input: &[u8],
) -> Result<Vec<u8>, BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"C").await?;

    let mut chal = [0u8; 17];
    recv.read_exact(&mut chal).await?;
    let challenge = Challenge {
        nonce: chal[..16].try_into().unwrap(),
        difficulty: chal[16],
    };

    let req = build_request(&challenge, token); // solution(8) | token(32) = 40 bytes
    send.write_all(&req).await?;
    send.write_all(input).await?;
    send.finish()?;

    let response = recv.read_to_end(64 * 1024).await?;
    Ok(response)
}

/// Tunnel `payload` to the Origin over Noise E2E (M8.4a): open a stream, complete
/// the PoW-gated rendezvous for `token`, then run the `Noise_IK` exchange
/// (pinning `cap`'s Origin Identity) and return the decrypted response. The Edge
/// only relays the resulting ciphertext frames.
pub async fn client_tunnel_noise(
    conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"C").await?;

    let mut chal = [0u8; 17];
    recv.read_exact(&mut chal).await?;
    let challenge = Challenge {
        nonce: chal[..16].try_into().unwrap(),
        difficulty: chal[16],
    };
    let req = build_request(&challenge, token);
    send.write_all(&req).await?;

    // The stream is now bridged to the Agent; run Noise over it.
    let response = client_noise_exchange(&mut send, &mut recv, client_private, cap, payload).await?;
    send.finish()?;
    Ok(response)
}

/// Connect to the Edge's TCP+TLS fallback at `addr`, trusting `edge_cert`
/// (M12.3b) — used when outbound UDP/QUIC is blocked.
pub async fn tcp_tls_connect(
    addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BoxError> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(edge_cert)?;
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(addr).await?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost")?;
    Ok(connector.connect(server_name, tcp).await?)
}

/// Tunnel `payload` to the Origin over a **TCP-fallback** stream (M12.2c): when
/// UDP/QUIC is blocked, the Client connects to the Edge via TLS-TCP and runs the
/// same `'C'` rendezvous + Noise exchange over that single byte stream. Generic
/// over the stream so it works with a `tokio-rustls` client TLS stream.
pub async fn client_tunnel_noise_tcp<T>(
    mut stream: T,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // 'C' rendezvous over the single stream.
    stream.write_all(b"C").await?;
    let mut chal = [0u8; 17];
    stream.read_exact(&mut chal).await?;
    let challenge = Challenge {
        nonce: chal[..16].try_into().unwrap(),
        difficulty: chal[16],
    };
    stream.write_all(&build_request(&challenge, token)).await?;

    // Noise over the same stream (split into read/write halves).
    let (mut r, mut w) = split(stream);
    let response = client_noise_exchange(&mut w, &mut r, client_private, cap, payload).await?;
    Ok(response)
}

/// A tunnel-operation timeout error (issue #2): the edge accepted the connection
/// but never relayed, so the client would otherwise block indefinitely.
fn tunnel_timeout_error(deadline: Duration) -> BoxError {
    format!(
        "tunnel operation timed out after {}s (edge reachable but no relay — is an agent registered for this token?)",
        deadline.as_secs()
    )
    .into()
}

/// [`client_tunnel_noise`] with an overall `deadline` on the tunnel operation, so
/// the client never hangs when the edge accepts the QUIC connection but cannot
/// relay (e.g. no agent is registered for the token). Returns a clear timeout
/// error instead of blocking. (issue #2)
pub async fn client_tunnel_noise_timed(
    conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    deadline: Duration,
) -> Result<Vec<u8>, BoxError> {
    match tokio::time::timeout(
        deadline,
        client_tunnel_noise(conn, token, cap, client_private, payload),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(tunnel_timeout_error(deadline)),
    }
}

/// [`client_tunnel_noise_tcp`] with an overall `deadline` — the TLS-over-TCP
/// equivalent of [`client_tunnel_noise_timed`]. (issue #2)
pub async fn client_tunnel_noise_tcp_timed<T>(
    stream: T,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    deadline: Duration,
) -> Result<Vec<u8>, BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(
        deadline,
        client_tunnel_noise_tcp(stream, token, cap, client_private, payload),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(tunnel_timeout_error(deadline)),
    }
}

/// Open a **streaming** Noise tunnel (M9.3): PoW-gated rendezvous for `token`,
/// then the `Noise_IK` initiator handshake (pinning `cap`'s Origin Identity),
/// then [`noise_pump`] bridging the local `app` stream to the Origin over the
/// live session. Runs until either side closes. The Edge relays only ciphertext.
pub async fn client_tunnel_stream<P>(
    conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    app: P,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"C").await?;

    let mut chal = [0u8; 17];
    recv.read_exact(&mut chal).await?;
    let challenge = Challenge {
        nonce: chal[..16].try_into().unwrap(),
        difficulty: chal[16],
    };
    let req = build_request(&challenge, token);
    send.write_all(&req).await?;

    // Noise_IK initiator handshake over the relayed stream.
    let mut hs = client_handshake_for(client_private, cap)?;
    let mut buf = vec![0u8; 65535];
    let mut tmp = vec![0u8; 65535];
    let n = hs.write_message(&[], &mut buf)?;
    send.write_all(&frame(&buf[..n])).await?;
    let m2 = read_frame(&mut recv).await?;
    hs.read_message(&m2, &mut tmp)?;
    let transport = hs.into_transport_mode()?;

    // Bridge the local app stream <-> the Origin over the Noise session.
    let cipher = join(recv, send);
    noise_pump(transport, cipher, app).await?;
    Ok(())
}

/// Open a **UDP** tunnel (M10.2): PoW-gated rendezvous + `Noise_IK` initiator
/// handshake, then bridge the local (connected) UDP socket `local` to the UDP
/// Origin over the Noise session. One datagram from `local` becomes one Noise
/// frame and vice versa, preserving datagram boundaries. Runs until the tunnel
/// stream closes (UDP itself has no EOF).
pub async fn client_tunnel_udp(
    conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    local: UdpSocket,
) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"C").await?;

    let mut chal = [0u8; 17];
    recv.read_exact(&mut chal).await?;
    let challenge = Challenge {
        nonce: chal[..16].try_into().unwrap(),
        difficulty: chal[16],
    };
    send.write_all(&build_request(&challenge, token)).await?;

    let mut hs = client_handshake_for(client_private, cap)?;
    let mut buf = vec![0u8; 65535];
    let mut tmp = vec![0u8; 65535];
    let n = hs.write_message(&[], &mut buf)?;
    send.write_all(&frame(&buf[..n])).await?;
    let m2 = read_frame(&mut recv).await?;
    hs.read_message(&m2, &mut tmp)?;
    let transport = hs.into_transport_mode()?;

    let ts = Mutex::new(transport);
    // `e` infers to snow::Error (naming it needs snow as a direct dep).
    let noise_err = |e| io::Error::new(io::ErrorKind::Other, format!("{e}"));

    // Local datagram -> encrypt -> frame to the Edge.
    let to_edge = async {
        let mut dg = vec![0u8; 65535];
        let mut ct = vec![0u8; 65535 + 256];
        loop {
            let n = local.recv(&mut dg).await?;
            let len = ts.lock().unwrap().write_message(&dg[..n], &mut ct).map_err(noise_err)?;
            send.write_all(&frame(&ct[..len])).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };

    // Frame from the Edge -> decrypt -> local datagram.
    let from_edge = async {
        let mut pt = vec![0u8; 65535];
        loop {
            let fr = match read_frame(&mut recv).await {
                Ok(f) => f,
                Err(_) => break,
            };
            let len = ts.lock().unwrap().read_message(&fr, &mut pt).map_err(noise_err)?;
            local.send(&pt[..len]).await?;
        }
        Ok::<(), io::Error>(())
    };

    tokio::select! {
        r = to_edge => r?,
        r = from_edge => r?,
    }
    Ok(())
}

/// Attempt a **direct** QUIC connection to the Agent's advertised candidate
/// (M11.3c), trusting `agent_cert`, within `timeout`. On success the Client can
/// tunnel straight to the Agent, bypassing the Edge relay; on timeout/failure the
/// caller falls back to the relay path (M11.4).
pub async fn client_direct_connect(
    candidate: SocketAddr,
    agent_cert: CertificateDer<'static>,
    timeout: Duration,
) -> Result<Connection, BoxError> {
    match tokio::time::timeout(timeout, dial_edge(candidate, agent_cert)).await {
        Ok(res) => res,
        Err(_) => Err("direct connect timed out".into()),
    }
}

/// Tunnel `payload` to the Origin over a **direct** connection to the Agent
/// (M11.3c): no Edge rendezvous or PoW — the Noise handshake authenticates the
/// path (Client pins the Origin Identity). Returns the decrypted response.
pub async fn client_tunnel_direct(
    conn: &Connection,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let response = client_noise_exchange(&mut send, &mut recv, client_private, cap, payload).await?;
    send.finish()?;
    Ok(response)
}

/// Auto P2P tunnel (M11.4b-iv): discover the Agent's advertised direct endpoint
/// from the Edge (`'P'`), then try the direct path, falling back to the Edge
/// relay if none is advertised or the direct attempt fails. Returns
/// `(used_direct, response)`.
pub async fn client_tunnel_auto(
    edge_conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    timeout: Duration,
) -> Result<(bool, Vec<u8>), BoxError> {
    let direct = query_direct_endpoint(edge_conn, token).await.ok().flatten();
    client_tunnel_p2p_or_relay(edge_conn, token, cap, client_private, payload, direct, timeout).await
}

/// Try the **direct** P2P path first, else fall back to the **Edge relay**
/// (M11.4). `direct` is the Agent's advertised `(candidate, cert)`; if it is
/// `None`, or the direct connect/tunnel fails within `timeout`, the tunnel goes
/// through the Edge relay on `edge_conn`. Returns `(used_direct, response)`.
pub async fn client_tunnel_p2p_or_relay(
    edge_conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    direct: Option<(SocketAddr, CertificateDer<'static>)>,
    timeout: Duration,
) -> Result<(bool, Vec<u8>), BoxError> {
    if let Some((candidate, cert)) = direct {
        if let Ok(conn) = client_direct_connect(candidate, cert, timeout).await {
            if let Ok(resp) = client_tunnel_direct(&conn, cap, client_private, payload).await {
                conn.close(0u32.into(), b"done");
                return Ok((true, resp));
            }
        }
    }
    // Fallback: PoW-gated rendezvous + Noise tunnel through the Edge relay.
    let resp = client_tunnel_noise(edge_conn, token, cap, client_private, payload).await?;
    Ok((false, resp))
}

/// Ask the Edge for the Agent's advertised direct endpoint for `token`
/// (M11.4b-ii): send a `'P'` query and parse the reply `[0]` (none) or
/// `[1] addr_len(1) addr cert_len(2 BE) cert` into `(addr, cert)`. Used to
/// attempt the direct P2P path before falling back to the Edge relay.
pub async fn query_direct_endpoint(
    conn: &Connection,
    token: &RoutingToken,
) -> Result<Option<(SocketAddr, CertificateDer<'static>)>, BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"P").await?;
    send.write_all(&token.0).await?;
    send.finish()?;
    let resp = recv.read_to_end(4096).await?;
    if resp.is_empty() || resp[0] == 0 {
        return Ok(None);
    }
    let truncated = || -> BoxError { "truncated direct-endpoint reply".into() };
    if resp.len() < 2 {
        return Err(truncated());
    }
    let addr_end = 2 + resp[1] as usize;
    if resp.len() < addr_end + 2 {
        return Err(truncated());
    }
    let addr: SocketAddr = std::str::from_utf8(&resp[2..addr_end])?.parse()?;
    let clen = u16::from_be_bytes([resp[addr_end], resp[addr_end + 1]]) as usize;
    let cert_start = addr_end + 2;
    if resp.len() < cert_start + clen {
        return Err(truncated());
    }
    let cert = CertificateDer::from(resp[cert_start..cert_start + clen].to_vec());
    Ok(Some((addr, cert)))
}

/// UDP self-test (M10.4): bind a local app UDP socket, send `payload` as one
/// datagram through [`client_tunnel_udp`] to the Origin, and return the echoed
/// datagram. The tunnel runs concurrently and is torn down once the echo arrives.
pub async fn udp_selftest(
    conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, BoxError> {
    // A local "app" socket mutually connected to the tunnel's local socket.
    let app = UdpSocket::bind("127.0.0.1:0").await?;
    let app_addr = app.local_addr()?;
    let local = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = local.local_addr()?;
    app.connect(local_addr).await?;
    local.connect(app_addr).await?;

    let mut got = vec![0u8; 65535];
    tokio::select! {
        r = client_tunnel_udp(conn, token, cap, client_private, local) => {
            r?;
            Err("udp tunnel exited before the echo arrived".into())
        }
        res = async {
            app.send(payload).await?;
            let n = app.recv(&mut got).await?;
            Ok::<usize, std::io::Error>(n)
        } => {
            let n = res?;
            Ok(got[..n].to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::noise::generate_static_keypair;
    use ct_common::OriginIdentity;
    use ct_edge::transport::build_server_endpoint_with_cert;
    use std::time::Instant;

    /// issue #2 regression: when the edge accepts the QUIC connection but never
    /// relays (no agent registered for the token), the tunnel op must return a
    /// timeout error promptly instead of hanging indefinitely.
    #[tokio::test]
    async fn tunnel_noise_timed_errors_when_edge_never_relays() {
        let token = RoutingToken([7u8; 32]);
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // A "silent edge": accept the client's connection, then do nothing (no
        // rendezvous, no relay) — the client would block reading the challenge.
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let edge = tokio::spawn(async move {
            let _conn = server.accept().await.unwrap().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };
        let conn = dial_edge(addr, cert).await.expect("client dial");

        let start = Instant::now();
        let r = client_tunnel_noise_timed(
            &conn,
            &token,
            &cap,
            &client_kp.private,
            b"x",
            Duration::from_millis(300),
        )
        .await;
        let elapsed = start.elapsed();

        assert!(r.is_err(), "must error, not hang, when the edge never relays");
        assert!(
            r.unwrap_err().to_string().contains("timed out"),
            "error should name the timeout"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "must return near the deadline, took {elapsed:?}"
        );
        edge.abort();
    }

    // #21 WC4: cover client_tunnel_noise_tcp_timed (the TLS-over-TCP timed
    // variant, issue #2) over an in-memory duplex — both the deadline arm and
    // the surfaced-inner-error arm, without needing a real edge.
    #[tokio::test]
    async fn tcp_timed_surfaces_timeout_and_inner_error() {
        let token = RoutingToken([8u8; 32]);
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "127.0.0.1:4433".into(),
        };

        // (a) Idle peer: the inner op blocks -> the deadline (Err) arm fires.
        let (client_side, peer) = tokio::io::duplex(4096);
        let start = Instant::now();
        let r = client_tunnel_noise_tcp_timed(
            client_side,
            &token,
            &cap,
            &client_kp.private,
            b"hi",
            Duration::from_millis(200),
        )
        .await;
        assert!(r.is_err(), "idle peer -> error, not a hang");
        assert!(start.elapsed() < Duration::from_secs(2), "returned near the deadline");
        drop(peer);

        // (b) Closed peer: the inner op hits EOF and errors before the deadline,
        // so the Ok(inner) arm surfaces that error.
        let (client_side2, peer2) = tokio::io::duplex(4096);
        drop(peer2);
        let r2 = client_tunnel_noise_tcp_timed(
            client_side2,
            &token,
            &cap,
            &client_kp.private,
            b"hi",
            Duration::from_secs(5),
        )
        .await;
        assert!(r2.is_err(), "closed peer -> inner error surfaced");
    }
}
