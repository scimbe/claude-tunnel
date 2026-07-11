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
use tokio::io::{join, AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;

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

/// Ask the Edge for the Agent's peer candidate for `token` (M11.3a): send a `'P'`
/// query and parse the length-prefixed UTF-8 address reply (length 0 = none).
/// Used to attempt a direct P2P path before falling back to the Edge relay.
pub async fn query_peer_candidate(
    conn: &Connection,
    token: &RoutingToken,
) -> Result<Option<SocketAddr>, BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"P").await?;
    send.write_all(&token.0).await?;
    send.finish()?;
    let resp = recv.read_to_end(64).await?;
    if resp.is_empty() || resp[0] == 0 {
        return Ok(None);
    }
    let len = resp[0] as usize;
    if resp.len() < 1 + len {
        return Err("truncated peer-candidate reply".into());
    }
    let addr = std::str::from_utf8(&resp[1..1 + len])?.parse()?;
    Ok(Some(addr))
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
