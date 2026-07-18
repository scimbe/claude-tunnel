//! Agent Fabric — the A2A channel *runner* (#72 AF4-session-wire, #98/#100).
//!
//! [`crate::channel`] rendezvouses two members and [`ct_common::a2a`] establishes the
//! Noise_IK session; this module is the piece that makes it *runnable*: given an
//! established QUIC connection, a role, and the Noise keys, it completes the A2A
//! handshake and then pumps a local byte stream (the CLI's stdin/stdout, or any
//! `AsyncRead + AsyncWrite`) over the encrypted tunnel — a "netcat over the channel".
//! A thin `ct-agent` subcommand feeds it stdio; tests feed it an in-memory duplex.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use ct_common::channel::ChannelJoinRequest;
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::channel::{present_channel_join, ChannelJoinOutcome};
use ct_common::a2a::{a2a_initiate, a2a_respond};
use ct_common::noise::noise_pump;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Which side of the A2A session this agent drives. Selected from the channel
/// grant's `Direction`: the initiator dials + opens the stream; the responder
/// accepts. (In `Noise_IK` the initiator also pins the peer's static key.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelRole {
    /// Dial the peer and open the bi-stream (grant `Direction::Initiate`).
    Initiate,
    /// Accept the peer's bi-stream (grant `Direction::Accept`).
    Accept,
}

/// A quinn bi-stream (`SendStream` + `RecvStream`) presented as one combined
/// `AsyncRead + AsyncWrite`, so [`noise_pump`] (which `tokio::io::split`s a single
/// duplex) can relay over it. Reads delegate to `recv`, writes to `send`.
struct BiStream {
    send: SendStream,
    recv: RecvStream,
}

// quinn's Send/RecvStream carry inherent poll_* methods (quinn error types) that
// shadow the tokio trait methods, so delegate with fully-qualified trait syntax.
impl AsyncRead for BiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for BiStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// Run one side of an A2A channel session over the established `conn`, then pump
/// `local` (the CLI's stdio, or any duplex) over the encrypted tunnel until either
/// end closes (#72 AF4-session-wire). `role` selects initiator/responder;
/// `own_noise_private` is this agent's member Noise key; `peer_noise_public` is the
/// peer's, pinned by the initiator. Returns when the session ends (EOF either way).
pub async fn run_channel_session<P>(
    conn: &Connection,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    let map_err = |e: Box<dyn std::error::Error + Send + Sync>| io::Error::new(io::ErrorKind::Other, e.to_string());
    let (mut send, mut recv) = match role {
        ChannelRole::Initiate => conn.open_bi().await.map_err(|e| map_err(Box::new(e)))?,
        ChannelRole::Accept => conn.accept_bi().await.map_err(|e| map_err(Box::new(e)))?,
    };
    let session = match role {
        ChannelRole::Initiate => {
            a2a_initiate(&mut send, &mut recv, own_noise_private, peer_noise_public).await
        }
        ChannelRole::Accept => a2a_respond(&mut send, &mut recv, own_noise_private).await,
    }
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    noise_pump(session, BiStream { send, recv }, local).await
}

/// Hands-off A2A join (#72 AF4 / #100): present `request` to the edge broker over
/// `broker_conn`, and on admission use the endpoint **and Noise key the rendezvous
/// relays** (no operator-conveyed value) to establish the encrypted session, piping
/// `local` over it. `role` (from the grant `Direction`) selects the side: an
/// `Initiate` peer dials the learned `peer_endpoint` with the accept-any channel
/// dialer; an `Accept` peer takes the next connection on its own `listener` (bound at
/// the endpoint it advertised in `request`). Fails if the broker refuses or relays no
/// peer Noise key (the registry must carry it — AF4-keydist).
pub async fn run_channel_join<P>(
    broker_conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    listener: Option<Endpoint>,
    local: P,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    let (peer_endpoint, peer_noise) = match present_channel_join(broker_conn, request, holder).await? {
        ChannelJoinOutcome::Admitted { peer_endpoint, peer_noise_pubkey } => {
            let noise = peer_noise_pubkey
                .ok_or("broker admitted the join but relayed no peer Noise key (registry has none)")?;
            (peer_endpoint, noise)
        }
        ChannelJoinOutcome::Refused => return Err("edge broker refused the channel join".into()),
    };
    match role {
        ChannelRole::Initiate => {
            let addr = peer_endpoint
                .parse()
                .map_err(|_| format!("broker returned an unparseable peer endpoint: {peer_endpoint:?}"))?;
            let conn = match dial_peer_direct(addr, DIRECT_DIAL_TIMEOUT).await {
                Ok(conn) => conn,
                // #72 AF4-session-resilience: the direct path is blocked
                // (NAT/firewall/down). Edge-relay fallback is the next packet; until
                // it's wired, surface a clear, actionable error instead of hanging.
                Err(ChannelDialError::Unreachable) => {
                    return Err(format!(
                        "direct A2A dial to {addr} timed out — peer unreachable on the direct \
                         path (NAT/firewall/down); edge-relay fallback not yet wired \
                         (#72 AF4-session-resilience)"
                    )
                    .into());
                }
                Err(ChannelDialError::Failed(e)) => return Err(e),
            };
            run_channel_session(&conn, ChannelRole::Initiate, own_noise_private, &peer_noise, local).await?;
        }
        ChannelRole::Accept => {
            let ep = listener.ok_or("responder role requires a bound listener")?;
            let conn = ep.accept().await.ok_or("channel listener closed with no incoming")?.await?;
            run_channel_session(&conn, ChannelRole::Accept, own_noise_private, &peer_noise, local).await?;
        }
    }
    Ok(())
}

/// Bound on a direct A2A dial before giving up (#72 AF4-session-resilience). Kept
/// short so a peer that's unreachable on the direct path (NAT / firewall / down) fails
/// fast — the signal to fall back to the edge relay — instead of hanging on the QUIC
/// handshake's retransmits.
pub const DIRECT_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Why a direct dial to a paired peer did not connect (#72 AF4-session-resilience).
#[derive(Debug)]
pub enum ChannelDialError {
    /// The dial did not complete within the timeout — the peer is unreachable on the
    /// **direct** path. This is the signal to fall back to the edge relay, not an error
    /// to surface to the user.
    Unreachable,
    /// The dial failed for another reason (bad address, endpoint setup, connect error).
    Failed(BoxError),
}

impl std::fmt::Display for ChannelDialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelDialError::Unreachable => write!(f, "peer unreachable on the direct path"),
            ChannelDialError::Failed(e) => write!(f, "direct dial failed: {e}"),
        }
    }
}

impl std::error::Error for ChannelDialError {}

/// Dial a paired peer's advertised endpoint directly over QUIC (accept-any transport —
/// Noise_IK is the real auth), bounded by `timeout`. A timeout is classified as
/// [`ChannelDialError::Unreachable`] rather than a generic error, so the caller can
/// distinguish "the direct path is blocked, fall back to the relay" from "the dial
/// itself is malformed" — the crux of the connection-difficulty handling.
pub async fn dial_peer_direct(
    addr: std::net::SocketAddr,
    timeout: std::time::Duration,
) -> Result<Connection, ChannelDialError> {
    let dialer = crate::transport::build_channel_dialer().map_err(ChannelDialError::Failed)?;
    let connecting = dialer
        .connect(addr, "localhost")
        .map_err(|e| ChannelDialError::Failed(Box::new(e)))?;
    match tokio::time::timeout(timeout, connecting).await {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(e)) => Err(ChannelDialError::Failed(Box::new(e))),
        Err(_elapsed) => Err(ChannelDialError::Unreachable),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let v = hex_bytes(s)?;
    <[u8; 32]>::try_from(v.as_slice()).ok()
}

/// Configuration for the `ct-agent channel` runner (#98/#100), read from the
/// environment so the whole thing fits a copy-paste one-liner. The peer's transport
/// cert and Noise key travel as hex (as the broker/CP will hand them over); Noise_IK
/// is the real mutual authentication, so the QUIC cert is only the transport anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelRunConfig {
    pub role: ChannelRole,
    /// Responder: the address to bind. Initiator: the peer address to dial.
    pub addr: SocketAddr,
    /// This agent's member Noise (X25519) private key.
    pub own_noise_private: [u8; 32],
    /// The peer's member Noise public key (pinned by the initiator).
    pub peer_noise_public: [u8; 32],
    /// Initiator only: the peer responder's QUIC cert (DER) to trust for the dial.
    pub peer_cert_der: Option<Vec<u8>>,
}

impl ChannelRunConfig {
    /// Parse from the process environment (`CT_CHANNEL_*`).
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from an arbitrary key→value lookup (testable without touching real env).
    /// Required: `CT_CHANNEL_ROLE` (initiate|accept), `CT_CHANNEL_ADDR` (host:port),
    /// `CT_CHANNEL_NOISE_KEY` + `CT_CHANNEL_PEER_NOISE_KEY` (64 hex each). For
    /// `initiate`, `CT_CHANNEL_PEER_CERT` (hex DER of the responder's cert) is required.
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let role = match f("CT_CHANNEL_ROLE").as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref r) if r == "initiate" || r == "initiator" => ChannelRole::Initiate,
            Some(ref r) if r == "accept" || r == "responder" || r == "listen" => ChannelRole::Accept,
            other => return Err(format!("CT_CHANNEL_ROLE must be initiate|accept, got {other:?}")),
        };
        let addr = f("CT_CHANNEL_ADDR")
            .ok_or("CT_CHANNEL_ADDR required (host:port)")?
            .trim()
            .parse::<SocketAddr>()
            .map_err(|e| format!("CT_CHANNEL_ADDR invalid: {e}"))?;
        let own_noise_private = f("CT_CHANNEL_NOISE_KEY")
            .as_deref()
            .and_then(hex32)
            .ok_or("CT_CHANNEL_NOISE_KEY required (64 hex chars)")?;
        let peer_noise_public = f("CT_CHANNEL_PEER_NOISE_KEY")
            .as_deref()
            .and_then(hex32)
            .ok_or("CT_CHANNEL_PEER_NOISE_KEY required (64 hex chars)")?;
        // Optional: pin the peer's transport cert. Omit it and the initiator dials
        // accept-any (Noise_IK authenticates), which keeps the one-liner self-contained.
        let peer_cert_der = match f("CT_CHANNEL_PEER_CERT").filter(|s| !s.trim().is_empty()) {
            Some(h) => Some(hex_bytes(&h).ok_or("CT_CHANNEL_PEER_CERT must be hex DER")?),
            None => None,
        };
        Ok(Self { role, addr, own_noise_private, peer_noise_public, peer_cert_der })
    }
}

/// Run the `ct-agent channel` subcommand: bring up this agent as one side of an A2A
/// channel and pipe **stdin/stdout** over the encrypted tunnel (#98/#100). The
/// responder binds `addr` and prints its cert (hex) so the initiator can trust the
/// direct path; the initiator dials `addr` trusting the configured peer cert. The
/// real mutual auth is the Noise_IK session keyed on the member Noise keys.
pub async fn run_channel_command(cfg: ChannelRunConfig) -> Result<(), BoxError> {
    let local = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
    match cfg.role {
        ChannelRole::Accept => {
            let (endpoint, cert) = crate::transport::build_direct_listener_at(cfg.addr)?;
            eprintln!(
                "ct-agent channel: listening on {} (responder); peer must set \
                 CT_CHANNEL_PEER_CERT={}",
                cfg.addr,
                hex_encode(cert.as_ref())
            );
            let conn = endpoint
                .accept()
                .await
                .ok_or("channel endpoint closed with no incoming")?
                .await?;
            run_channel_session(
                &conn,
                ChannelRole::Accept,
                &cfg.own_noise_private,
                &cfg.peer_noise_public,
                local,
            )
            .await?;
        }
        ChannelRole::Initiate => {
            // Pin the peer's transport cert if one was supplied; otherwise dial with
            // the accept-any channel dialer — Noise_IK is the real auth, so no cert
            // needs to be conveyed (self-contained one-liner, #100).
            let conn = match cfg.peer_cert_der.clone() {
                Some(der) => crate::transport::dial_quic(cfg.addr, CertificateDer::from(der)).await?,
                None => {
                    let endpoint = crate::transport::build_channel_dialer()?;
                    endpoint.connect(cfg.addr, "localhost")?.await?
                }
            };
            eprintln!("ct-agent channel: connected to {} (initiator)", cfg.addr);
            run_channel_session(
                &conn,
                ChannelRole::Initiate,
                &cfg.own_noise_private,
                &cfg.peer_noise_public,
                local,
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::noise::generate_static_keypair;
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn cfg_from(pairs: &[(&str, &str)]) -> Result<ChannelRunConfig, String> {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        ChannelRunConfig::from_lookup(|k| map.get(k).cloned())
    }

    const K64: &str = "aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20";

    #[test]
    fn channel_config_parses_roles_keys_and_the_initiator_cert_requirement() {
        // #98/#100: the one-liner's config contract. A responder needs no peer cert;
        // an initiator does. Bad role / missing key / bad addr are rejected.
        let acc = cfg_from(&[
            ("CT_CHANNEL_ROLE", "accept"),
            ("CT_CHANNEL_ADDR", "0.0.0.0:9000"),
            ("CT_CHANNEL_NOISE_KEY", K64),
            ("CT_CHANNEL_PEER_NOISE_KEY", K64),
        ])
        .expect("responder config is valid without a peer cert");
        assert_eq!(acc.role, ChannelRole::Accept);
        assert_eq!(acc.addr, "0.0.0.0:9000".parse().unwrap());
        assert!(acc.peer_cert_der.is_none());

        // Initiator without a cert is valid (dials accept-any; Noise authenticates);
        // a hex cert, if given, is parsed and pinned.
        let base = [
            ("CT_CHANNEL_ROLE", "initiate"),
            ("CT_CHANNEL_ADDR", "203.0.113.9:9000"),
            ("CT_CHANNEL_NOISE_KEY", K64),
            ("CT_CHANNEL_PEER_NOISE_KEY", K64),
        ];
        let no_cert = cfg_from(&base).expect("initiator without a cert is valid (accept-any dial)");
        assert!(no_cert.peer_cert_der.is_none());
        let mut with_cert = base.to_vec();
        with_cert.push(("CT_CHANNEL_PEER_CERT", "deadbeef"));
        let init = cfg_from(&with_cert).expect("initiator with a cert is valid");
        assert_eq!(init.peer_cert_der.as_deref(), Some(&[0xde, 0xad, 0xbe, 0xef][..]));

        // Rejections.
        assert!(cfg_from(&[("CT_CHANNEL_ROLE", "bogus"), ("CT_CHANNEL_ADDR", "0.0.0.0:1"), ("CT_CHANNEL_NOISE_KEY", K64), ("CT_CHANNEL_PEER_NOISE_KEY", K64)]).is_err(), "bad role");
        assert!(cfg_from(&[("CT_CHANNEL_ROLE", "accept"), ("CT_CHANNEL_ADDR", "not-an-addr"), ("CT_CHANNEL_NOISE_KEY", K64), ("CT_CHANNEL_PEER_NOISE_KEY", K64)]).is_err(), "bad addr");
        assert!(cfg_from(&[("CT_CHANNEL_ROLE", "accept"), ("CT_CHANNEL_ADDR", "0.0.0.0:1"), ("CT_CHANNEL_NOISE_KEY", "tooshort"), ("CT_CHANNEL_PEER_NOISE_KEY", K64)]).is_err(), "bad key");
    }

    #[tokio::test]
    async fn runner_pipes_local_data_over_the_a2a_tunnel() {
        // #72 AF4-session-wire / #98: the runnable path. Two agents each call
        // run_channel_session with their role over a REAL QUIC connection, each
        // handing it a LOCAL duplex. Bytes written to the initiator's local side come
        // out of the responder's local side — plaintext in, plaintext out, encrypted
        // A2A tunnel in between. This is exactly what the CLI wires to stdin/stdout.
        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let resp_priv = responder.private;
        let init_priv = initiator.private;
        let resp_pub = responder.public;

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        // Responder: accept the connection, run the Accept side, pump its local end.
        let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
        let resp_task = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            run_channel_session(&conn, ChannelRole::Accept, &resp_priv, &[0u8; 32], resp_local_run)
                .await
                .expect("responder session");
        });

        // Initiator: dial, run the Initiate side (pinning the responder key), pump local.
        let (mut init_local_test, init_local_run) = tokio::io::duplex(8192);
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let init_task = tokio::spawn(async move {
            run_channel_session(&conn, ChannelRole::Initiate, &init_priv, &resp_pub, init_local_run)
                .await
                .expect("initiator session");
            // hold the connection until the pump finishes
        });

        // Drive it: write a payload into the initiator's local side; the pump
        // forwards it, so exactly those bytes come out of the responder's local side.
        // (Read the exact length rather than to-EOF: both pumps stay open for the
        // reverse direction, so there is no EOF to wait on here.)
        let payload = b"data flowing agent A -> agent B over the channel";
        init_local_test.write_all(payload).await.expect("write local");
        init_local_test.flush().await.expect("flush local");

        let mut got = vec![0u8; payload.len()];
        resp_local_test.read_exact(&mut got).await.expect("read peer local");
        assert_eq!(got, payload, "the responder's local side receives exactly what A sent");

        init_task.abort();
        resp_task.abort();
    }

    // A minimal edge-broker stand-in that admits one join and acks a fixed peer
    // endpoint + Noise key. It replicates the broker wire protocol (length-framed
    // request, possession challenge, `OK <endpoint> <noise_hex>`) but omits the
    // `safe_endpoint` SSRF gate — which is tested in `ct_edge::channel_broker` and
    // would (correctly) reject the loopback address a hermetic test must use.
    async fn stub_broker_admit(server: &Endpoint, peer_addr: std::net::SocketAddr, peer_noise: [u8; 32]) {
        let conn = server.accept().await.expect("incoming").await.expect("conn");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let mut len = [0u8; 2];
        recv.read_exact(&mut len).await.expect("len");
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        recv.read_exact(&mut buf).await.expect("req");
        send.write_all(&[0u8; 32]).await.expect("challenge"); // possession challenge
        let mut sig = [0u8; 64];
        let _ = recv.read_exact(&mut sig).await; // (signature not checked by the stub)
        let ack = format!("OK {} {}", peer_addr, hex_encode(&peer_noise));
        send.write_all(ack.as_bytes()).await.expect("ack");
        send.finish().expect("finish");
        conn.closed().await;
    }

    #[tokio::test]
    async fn channel_join_initiator_uses_the_rendezvous_peer_and_pipes_data() {
        // #72 AF4 / #100 hands-off capstone: run_channel_join presents to the broker,
        // takes the peer endpoint AND Noise key from the ack (no out-of-band value),
        // dials the peer (accept-any), and pipes data. Here the peer is a real
        // responder listener; the stub broker supplies its addr+key.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ed25519_dalek::Signer;

        // Responder: a real direct listener running the Accept side of the session.
        let responder_noise = generate_static_keypair();
        let (resp_listener, _c) = crate::transport::build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
        let resp_addr = resp_listener.local_addr().expect("resp addr");
        let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
        let rnp = responder_noise.private;
        let resp_task = tokio::spawn(async move {
            let conn = resp_listener.accept().await.expect("incoming").await.expect("conn");
            run_channel_session(&conn, ChannelRole::Accept, &rnp, &[0u8; 32], resp_local_run)
                .await
                .expect("responder session");
        });

        // Stub broker: admits the initiator and relays the responder's addr + key.
        let (broker_ep, broker_cert) = build_server_endpoint_with_cert().expect("broker");
        let broker_addr = broker_ep.local_addr().expect("broker addr");
        let rnpub = responder_noise.public;
        let broker_task = tokio::spawn(async move { stub_broker_admit(&broker_ep, resp_addr, rnpub).await });

        // Initiator: run_channel_join over a connection to the (stub) broker.
        let initiator_noise = generate_static_keypair();
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let holder = SigningKey::from_bytes(&[0x11u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId([0xD0u8; 32]),
            holder: holder.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant = SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() };
        let req = ChannelJoinRequest { grant, endpoint: "203.0.113.1:7001".to_string() };
        let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
        let inp = initiator_noise.private;
        let a_task = tokio::spawn(async move {
            let c = build_client_endpoint(broker_cert).expect("client");
            let conn = c.connect(broker_addr, "localhost").expect("cfg").await.expect("conn");
            run_channel_join(&conn, &req, &holder, ChannelRole::Initiate, &inp, None, a_local_run).await
        });

        // Data flows initiator -> responder with zero out-of-band key/cert exchange.
        let payload = b"hands-off: peer addr + Noise key came from the rendezvous ack";
        a_local_test.write_all(payload).await.expect("write");
        a_local_test.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        resp_local_test.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "the responder receives the initiator's data, keyed only via rendezvous");

        a_task.abort();
        resp_task.abort();
        broker_task.abort();
    }

    #[tokio::test]
    async fn direct_dial_to_an_unreachable_peer_fails_fast_as_unreachable() {
        // #72 AF4-session-resilience — THE case that matters: a peer that can't be
        // reached on the direct path (NAT/firewall/blackhole). The dial must classify
        // as `Unreachable` (the relay-fallback signal) and fail FAST, not hang on the
        // QUIC handshake's retransmits. A bound-but-silent UDP socket blackholes the
        // handshake (the port is "open", so no ICMP reject short-circuits it).
        use std::time::{Duration, Instant};
        let sink = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sink");
        let addr = sink.local_addr().expect("sink addr"); // occupied, never answers QUIC

        let start = Instant::now();
        let result = dial_peer_direct(addr, Duration::from_millis(400)).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(ChannelDialError::Unreachable)),
            "an unreachable peer classifies as Unreachable (relay-fallback signal), got {result:?}"
        );
        assert!(elapsed < Duration::from_secs(2), "failed fast in {elapsed:?}, did not hang");
        drop(sink);
    }

    #[tokio::test]
    async fn initiator_dials_without_a_pre_shared_cert_noise_authenticates() {
        // #100 self-containment: the initiator uses the accept-any channel dialer, so
        // NO transport cert is conveyed — only the peer's Noise key. The responder
        // self-signs (a cert the initiator has never seen); the A2A session still
        // forms and data flows, because Noise_IK is the real mutual auth.
        use crate::transport::{build_channel_dialer, build_direct_listener_at};
        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let resp_priv = responder.private;
        let init_priv = initiator.private;
        let resp_pub = responder.public;

        let (server, _cert) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
        let addr = server.local_addr().expect("addr");

        let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
        let resp_task = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            run_channel_session(&conn, ChannelRole::Accept, &resp_priv, &[0u8; 32], resp_local_run)
                .await
                .expect("responder session");
        });

        let (mut init_local_test, init_local_run) = tokio::io::duplex(8192);
        let endpoint = build_channel_dialer().expect("dialer");
        // Dial with NO peer cert — the accept-any verifier trusts the transport.
        let conn = endpoint.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let init_task = tokio::spawn(async move {
            run_channel_session(&conn, ChannelRole::Initiate, &init_priv, &resp_pub, init_local_run)
                .await
                .expect("initiator session");
        });

        let payload = b"self-contained: no transport cert was conveyed";
        init_local_test.write_all(payload).await.expect("write");
        init_local_test.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        resp_local_test.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "data flows without a pre-shared transport cert");

        init_task.abort();
        resp_task.abort();
    }
}
