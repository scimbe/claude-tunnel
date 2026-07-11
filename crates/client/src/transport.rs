//! Client → Edge transport (M5.3a).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use crate::noise::client_noise_exchange;
use ct_common::pow::{build_request, Challenge};
use ct_common::{Capability, RoutingToken};
use quinn::{Connection, Endpoint};
use rustls::pki_types::CertificateDer;

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
