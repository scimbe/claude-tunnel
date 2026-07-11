//! Agent origin-serving (M5.2b).
//!
//! When the Edge relays a Client stream to this Agent, the Agent dials the local
//! Origin (TCP) and pipes the QUIC stream to it. The Client↔Origin payload is
//! Noise-encrypted end to end (ADR-0013); the Agent forwards opaque bytes to the
//! Origin, which terminates the Noise session (P3). The Agent never inspects
//! them beyond forwarding.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use quinn::{Endpoint, RecvStream, SendStream};
use rustls::pki_types::CertificateDer;
use tokio::io::{copy_bidirectional, join, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::config::{AgentConfig, OriginProto};
use crate::transport::{dial_quic, register_tunnel};
use ct_common::metrics::{Metered, TunnelMetrics};
use ct_common::noise::{frame, noise_pump, origin_handshake};
use ct_common::RoutingToken;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Read one length-prefixed frame (2-byte big-endian length + body).
async fn read_frame<R: AsyncRead + Unpin>(recv: &mut R) -> Result<Vec<u8>, BoxError> {
    let mut len = [0u8; 2];
    recv.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    let mut body = vec![0u8; n];
    recv.read_exact(&mut body).await?;
    Ok(body)
}

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

/// Serve one relayed stream as the Origin's Noise responder (M8.3): terminate
/// the `Noise_IK` handshake with the Origin private key, then bridge one
/// request/response to the local `origin` — decrypt the Client's frame, forward
/// the plaintext to the Origin (TCP), read its reply, and return it encrypted.
///
/// Generic over the byte transport so it drives a QUIC stream in the live path
/// (M8.4) and an in-memory duplex in tests. The Edge only ever relays the
/// encrypted frames.
pub async fn serve_noise_bridge<S, R>(
    send: &mut S,
    recv: &mut R,
    origin: SocketAddr,
    origin_private: &[u8; 32],
) -> Result<(), BoxError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut hs = origin_handshake(origin_private)?;
    let mut buf = vec![0u8; 65535];
    let mut tmp = vec![0u8; 65535];

    // <- handshake message 1, -> handshake message 2
    let m1 = read_frame(recv).await?;
    hs.read_message(&m1, &mut tmp)?;
    let n = hs.write_message(&[], &mut buf)?;
    send.write_all(&frame(&buf[..n])).await?;
    send.flush().await?;

    let mut transport = hs.into_transport_mode()?;

    // Decrypt the Client's request and forward the plaintext to the Origin.
    let req_ct = read_frame(recv).await?;
    let n = transport.read_message(&req_ct, &mut tmp)?;
    let request = tmp[..n].to_vec();

    let mut tcp = TcpStream::connect(origin).await?;
    tcp.write_all(&request).await?;
    tcp.shutdown().await?;
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await?;

    // Encrypt the Origin's response back to the Client.
    let n = transport.write_message(&response, &mut buf)?;
    send.write_all(&frame(&buf[..n])).await?;
    send.flush().await?;
    Ok(())
}

/// Serve one relayed stream as the Origin's Noise responder with a **full-duplex
/// streaming** bridge (M9.2): terminate the `Noise_IK` handshake, then
/// [`noise_pump`] between the decrypted Client stream and the local Origin TCP
/// socket — arbitrary bidirectional, multi-message traffic, not a single
/// request/response. Generic over the byte transport (QUIC live, duplex in tests).
pub async fn serve_noise_stream<S, R>(
    mut send: S,
    mut recv: R,
    origin: SocketAddr,
    origin_private: &[u8; 32],
    metrics: Arc<TunnelMetrics>,
) -> Result<(), BoxError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut hs = origin_handshake(origin_private)?;
    let mut buf = vec![0u8; 65535];
    let mut tmp = vec![0u8; 65535];

    // <- handshake message 1, -> handshake message 2. Time it and count the
    // outcome for observability (M14.1b): a completed handshake is an opened
    // tunnel; a failed one increments the failure counter.
    let started = Instant::now();
    let handshake: Result<(), BoxError> = async {
        let m1 = read_frame(&mut recv).await?;
        hs.read_message(&m1, &mut tmp)?;
        let n = hs.write_message(&[], &mut buf)?;
        send.write_all(&frame(&buf[..n])).await?;
        send.flush().await?;
        Ok(())
    }
    .await;
    if let Err(e) = handshake {
        metrics.tunnels_failed.inc();
        return Err(e);
    }
    let transport = match hs.into_transport_mode() {
        Ok(t) => {
            metrics.observe_handshake(started.elapsed());
            metrics.tunnels_opened.inc();
            t
        }
        Err(e) => {
            metrics.tunnels_failed.inc();
            return Err(e.into());
        }
    };

    // Bridge the Noise session <-> the Origin TCP socket, both ways, streaming.
    // Meter the Origin socket: bytes read from it flow back to the Client
    // (bytes_to_client); bytes written to it came from the Client
    // (bytes_to_origin).
    let tcp = TcpStream::connect(origin).await?;
    let tcp = Metered::new(
        tcp,
        Arc::clone(&metrics.bytes_to_client),
        Arc::clone(&metrics.bytes_to_origin),
    );
    let cipher = join(recv, send);
    noise_pump(transport, cipher, tcp).await?;
    Ok(())
}

/// Serve one relayed stream as the Origin's Noise responder bridging to a **UDP**
/// Origin (M10.1). One Noise frame carries exactly one UDP datagram, so the
/// tunnel's framing preserves datagram boundaries: each decrypted frame is `send`
/// as a datagram to the Origin, and each datagram `recv`d from the Origin is
/// encrypted back as one frame. Runs until the Client closes the tunnel.
pub async fn serve_noise_udp<S, R>(
    mut send: S,
    mut recv: R,
    origin: SocketAddr,
    origin_private: &[u8; 32],
) -> Result<(), BoxError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut hs = origin_handshake(origin_private)?;
    let mut hbuf = vec![0u8; 65535];
    let mut htmp = vec![0u8; 65535];
    let m1 = read_frame(&mut recv).await?;
    hs.read_message(&m1, &mut htmp)?;
    let n = hs.write_message(&[], &mut hbuf)?;
    send.write_all(&frame(&hbuf[..n])).await?;
    send.flush().await?;
    let transport = hs.into_transport_mode()?;

    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(origin).await?;

    let ts = Mutex::new(transport);
    // `e` is inferred as snow::Error from the map_err call sites (naming it would
    // need snow as a direct dep, which ct-agent gets only transitively).
    let noise_err = |e| io::Error::new(io::ErrorKind::Other, format!("{e}"));

    // Client -> decrypt frame -> UDP datagram to Origin.
    let to_origin = async {
        let mut tmp = vec![0u8; 65535];
        loop {
            let fr = match read_frame(&mut recv).await {
                Ok(f) => f,
                Err(_) => break, // tunnel closed
            };
            let len = ts.lock().unwrap().read_message(&fr, &mut tmp).map_err(noise_err)?;
            udp.send(&tmp[..len]).await?;
        }
        Ok::<(), io::Error>(())
    };

    // Origin datagram -> encrypt -> frame to Client.
    let to_client = async {
        let mut dgram = vec![0u8; 65535];
        let mut ct = vec![0u8; 65535 + 256];
        loop {
            let n = udp.recv(&mut dgram).await?;
            let len = ts.lock().unwrap().write_message(&dgram[..n], &mut ct).map_err(noise_err)?;
            send.write_all(&frame(&ct[..len])).await?;
            send.flush().await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };

    // The Client closing the tunnel ends `to_origin`; UDP has no EOF, so
    // `to_client` only ends on error — whichever finishes first tears down.
    tokio::select! {
        r = to_origin => r?,
        r = to_client => r?,
    }
    Ok(())
}

/// Serve the Agent's **direct-path** listener (M11.4b-iii): accept direct Client
/// connections (which bypass the Edge relay) and serve each one as the Origin's
/// Noise responder — streaming for TCP, datagram-preserving for UDP. Loops until
/// the listener closes.
pub async fn serve_direct(
    listener: Endpoint,
    origin: SocketAddr,
    origin_private: [u8; 32],
    proto: OriginProto,
    metrics: Arc<TunnelMetrics>,
) -> Result<(), BoxError> {
    while let Some(incoming) = listener.accept().await {
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                if let Ok((send, recv)) = conn.accept_bi().await {
                    let _ = match proto {
                        OriginProto::Tcp => {
                            serve_noise_stream(send, recv, origin, &origin_private, metrics).await
                        }
                        OriginProto::Udp => serve_noise_udp(send, recv, origin, &origin_private).await,
                    };
                }
                conn.closed().await;
            }
        });
    }
    Ok(())
}

/// Run the Agent: dial the Edge, register the tunnel for `token`, then serve each
/// relayed stream as the Origin's Noise responder, bridging plaintext to the
/// local Origin (M8.4c-i). `origin_private` is the Agent-held Origin static key.
/// Loops until the connection closes.
pub async fn run_agent(
    config: &AgentConfig,
    edge_cert: CertificateDer<'static>,
    token: RoutingToken,
    origin_private: [u8; 32],
) -> Result<(), BoxError> {
    let conn = dial_quic(config.edge, edge_cert.clone()).await?;
    register_tunnel(&conn, &token).await?;

    // Shared tunnel metrics for this Agent (M14.1b): handed to every serve task
    // so the counters aggregate across all tunnels this Agent carries.
    let metrics = Arc::new(TunnelMetrics::new());

    // Optional direct-path listener + advertisement (M11.4b-v): if an advertise
    // IP is configured, run a direct listener, tell the Edge about it (on a
    // separate short-lived connection), and serve direct Client connections.
    if let Some(ip) = config.direct_advertise_ip {
        if let Ok((listener, cert)) = crate::transport::build_direct_listener() {
            if let Ok(bound) = listener.local_addr() {
                let advertised = SocketAddr::new(ip, bound.port());
                if let Ok(adv) = dial_quic(config.edge, edge_cert.clone()).await {
                    let _ = crate::transport::advertise_direct_listener(&adv, &token, advertised, &cert)
                        .await;
                    adv.close(0u32.into(), b"advertised");
                }
                let (origin, proto) = (config.origin, config.origin_proto);
                let dmetrics = Arc::clone(&metrics);
                tokio::spawn(async move {
                    let _ = serve_direct(listener, origin, origin_private, proto, dmetrics).await;
                });
            }
        }
    }

    let proto = config.origin_proto;
    loop {
        let (send, recv) = conn.accept_bi().await?;
        let origin = config.origin;
        let lmetrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let _ = match proto {
                OriginProto::Tcp => {
                    serve_noise_stream(send, recv, origin, &origin_private, lmetrics).await
                }
                OriginProto::Udp => serve_noise_udp(send, recv, origin, &origin_private).await,
            };
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
    async fn noise_bridge_decrypts_to_origin_and_reencrypts() {
        use ct_common::noise::{client_handshake_for, frame, generate_static_keypair};
        use ct_common::{Capability, OriginIdentity, RoutingToken};

        // A real TCP echo Origin — it only ever sees plaintext.
        let (origin_addr, origin) = echo_origin().await;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        let (client_io, server_io) = tokio::io::duplex(8192);
        let (mut c_read, mut c_write) = tokio::io::split(client_io);

        // Agent-side responder bridge (the code under test).
        let origin_priv = origin_kp.private;
        let bridge = tokio::spawn(async move {
            let (mut s_read, mut s_write) = tokio::io::split(server_io);
            serve_noise_bridge(&mut s_write, &mut s_read, origin_addr, &origin_priv).await
        });

        // Inline Client initiator (mirrors ct-client::noise::client_noise_exchange).
        let mut hs = client_handshake_for(&client_kp.private, &cap).expect("initiator");
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        c_write.write_all(&frame(&buf[..n])).await.unwrap();
        let m2 = read_frame(&mut c_read).await.unwrap();
        hs.read_message(&m2, &mut tmp).unwrap();
        let mut transport = hs.into_transport_mode().unwrap();
        let n = transport.write_message(b"secret-request", &mut buf).unwrap();
        c_write.write_all(&frame(&buf[..n])).await.unwrap();
        let resp_ct = read_frame(&mut c_read).await.unwrap();
        let n = transport.read_message(&resp_ct, &mut tmp).unwrap();

        assert_eq!(
            &tmp[..n],
            b"secret-request",
            "agent decrypted to origin, origin echoed, agent re-encrypted"
        );
        bridge.await.unwrap().expect("bridge ok");
        let _ = origin.await;
    }

    #[tokio::test]
    async fn serve_noise_stream_bridges_streaming_to_origin() {
        use ct_common::noise::{
            client_handshake_for, frame, generate_static_keypair, noise_pump, read_frame,
        };
        use ct_common::{Capability, OriginIdentity, RoutingToken};
        use tokio::net::TcpListener;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        // Streaming TCP echo Origin (echoes bytes as they arrive).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });

        let (ini_cipher, agent_cipher) = tokio::io::duplex(64 * 1024);

        // Agent under test: serve_noise_stream over the relayed cipher stream.
        let origin_priv = origin_kp.private;
        let metrics = std::sync::Arc::new(ct_common::metrics::TunnelMetrics::new());
        let mcheck = std::sync::Arc::clone(&metrics);
        let (a_read, a_write) = tokio::io::split(agent_cipher);
        let agent = tokio::spawn(async move {
            serve_noise_stream(a_write, a_read, origin_addr, &origin_priv, metrics).await
        });

        // Initiator: handshake, then pump a 100 KB app stream over the session.
        let (mut i_read, mut i_write) = tokio::io::split(ini_cipher);
        let mut hs = client_handshake_for(&client_kp.private, &cap).unwrap();
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        i_write.write_all(&frame(&buf[..n])).await.unwrap();
        let m2 = read_frame(&mut i_read).await.unwrap();
        hs.read_message(&m2, &mut tmp).unwrap();
        let ini_t = hs.into_transport_mode().unwrap();

        let (app_local, app_remote) = tokio::io::duplex(1024 * 1024);
        let cipher = tokio::io::join(i_read, i_write);
        let pump = tokio::spawn(noise_pump(ini_t, cipher, app_local));

        let expected: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let (mut app_r, mut app_w) = tokio::io::split(app_remote);
        let payload = expected.clone();
        let writer = tokio::spawn(async move {
            app_w.write_all(&payload).await.unwrap();
            app_w.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        app_r.read_to_end(&mut got).await.unwrap();

        assert_eq!(got, expected, "100 KB streams through serve_noise_stream to the echo Origin");
        writer.await.unwrap();
        pump.await.unwrap().unwrap();
        agent.await.unwrap().unwrap();
        origin.abort();

        // The serve task recorded the handshake and metered both directions.
        assert_eq!(mcheck.tunnels_opened.get(), 1, "one tunnel opened");
        assert_eq!(mcheck.tunnels_failed.get(), 0, "no failures");
        assert_eq!(mcheck.handshakes.get(), 1, "one handshake observed");
        assert_eq!(mcheck.bytes_to_origin.get(), 100_000, "100 KB forwarded to the origin");
        assert_eq!(mcheck.bytes_to_client.get(), 100_000, "100 KB echoed back to the client");
    }

    #[tokio::test]
    async fn serve_noise_udp_bridges_datagrams_to_origin() {
        use ct_common::noise::{client_handshake_for, frame, generate_static_keypair, read_frame};
        use ct_common::{Capability, OriginIdentity, RoutingToken};
        use tokio::io::AsyncWriteExt;
        use tokio::net::UdpSocket;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        // UDP echo Origin.
        let origin_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_sock.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let mut b = vec![0u8; 65535];
            while let Ok((n, peer)) = origin_sock.recv_from(&mut b).await {
                let _ = origin_sock.send_to(&b[..n], peer).await;
            }
        });

        let (ini_cipher, agent_cipher) = tokio::io::duplex(64 * 1024);
        let origin_priv = origin_kp.private;
        let (a_read, a_write) = tokio::io::split(agent_cipher);
        let agent =
            tokio::spawn(async move { serve_noise_udp(a_write, a_read, origin_addr, &origin_priv).await });

        // Initiator: handshake, then send discrete datagrams and read echoes.
        let (mut i_read, mut i_write) = tokio::io::split(ini_cipher);
        let mut hs = client_handshake_for(&client_kp.private, &cap).unwrap();
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        i_write.write_all(&frame(&buf[..n])).await.unwrap();
        let m2 = read_frame(&mut i_read).await.unwrap();
        hs.read_message(&m2, &mut tmp).unwrap();
        let mut transport = hs.into_transport_mode().unwrap();

        for msg in [b"one".as_slice(), b"two", b"a-longer-datagram-payload"] {
            let n = transport.write_message(msg, &mut buf).unwrap();
            i_write.write_all(&frame(&buf[..n])).await.unwrap();
            let fr = read_frame(&mut i_read).await.unwrap();
            let n = transport.read_message(&fr, &mut tmp).unwrap();
            assert_eq!(&tmp[..n], msg, "UDP datagram boundary + content preserved through the tunnel");
        }

        // Close the tunnel so serve_noise_udp's reader hits EOF and returns.
        // NOTE: `drop(i_write)` does NOT signal EOF while the split ReadHalf is
        // alive (the DuplexStream stays open) — an explicit shutdown is required.
        i_write.shutdown().await.unwrap();
        agent.await.unwrap().unwrap();
        origin.abort();
    }

    #[tokio::test]
    async fn serve_direct_bridges_a_direct_connection() {
        // M11.4b-iii: serve_direct accepts a direct Client connection and serves
        // it as the Noise responder straight to the Origin (no Edge).
        use crate::transport::build_direct_listener_at;
        use ct_common::noise::{client_handshake_for, frame, generate_static_keypair, read_frame};
        use ct_common::{Capability, OriginIdentity, RoutingToken};
        use std::net::Ipv4Addr;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        let (origin_addr, origin) = echo_origin().await;
        let (listener, cert) =
            build_direct_listener_at((Ipv4Addr::LOCALHOST, 0).into()).expect("listener");
        let laddr = listener.local_addr().expect("laddr");
        let opriv = origin_kp.private;
        let dmetrics = std::sync::Arc::new(ct_common::metrics::TunnelMetrics::new());
        let srv = tokio::spawn(async move {
            let _ = serve_direct(listener, origin_addr, opriv, OriginProto::Tcp, dmetrics).await;
        });

        // Inline Client: connect directly to the listener, handshake, one payload.
        let client = ct_edge::transport::build_client_endpoint(cert).expect("client");
        let conn = client.connect(laddr, "localhost").expect("cfg").await.expect("conn");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut hs = client_handshake_for(&client_kp.private, &cap).unwrap();
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        send.write_all(&frame(&buf[..n])).await.unwrap();
        let m2 = read_frame(&mut recv).await.unwrap();
        hs.read_message(&m2, &mut tmp).unwrap();
        let mut transport = hs.into_transport_mode().unwrap();
        let n = transport.write_message(b"direct-serve", &mut buf).unwrap();
        send.write_all(&frame(&buf[..n])).await.unwrap();
        let resp = read_frame(&mut recv).await.unwrap();
        let n = transport.read_message(&resp, &mut tmp).unwrap();
        assert_eq!(&tmp[..n], b"direct-serve", "serve_direct bridged the direct connection to the origin");

        conn.close(0u32.into(), b"done");
        srv.abort();
        let _ = origin.await;
    }

    #[tokio::test]
    async fn run_agent_registers_and_serves_relayed_streams() {
        use ct_common::noise::{client_handshake_for, frame, generate_static_keypair};
        use ct_common::{Capability, OriginIdentity};
        use ct_edge::state::EdgeState;
        use quinn::Connection;
        use std::sync::Arc;

        let (origin_addr, origin) = echo_origin().await;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let token = RoutingToken([3u8; 32]);
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let edge_addr = server.local_addr().expect("addr");

        // Edge: accept the Agent, register it, then act as the Noise initiator
        // over a relayed stream and return the decrypted echo.
        let state_e = state.clone();
        let cap_e = cap.clone();
        let client_priv = client_kp.private;
        let edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            ct_edge::serve::register_agent(&agent_conn, &state_e)
                .await
                .map_err(|e| e.to_string())?;
            let (mut send, mut recv) = agent_conn.open_bi().await.unwrap();

            let mut hs = client_handshake_for(&client_priv, &cap_e).map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; 65535];
            let mut tmp = vec![0u8; 65535];
            let n = hs.write_message(&[], &mut buf).unwrap();
            send.write_all(&frame(&buf[..n])).await.unwrap();
            let m2 = read_frame(&mut recv).await.map_err(|e| e.to_string())?;
            hs.read_message(&m2, &mut tmp).unwrap();
            let mut transport = hs.into_transport_mode().unwrap();
            let n = transport.write_message(b"ping", &mut buf).unwrap();
            send.write_all(&frame(&buf[..n])).await.unwrap();
            let resp_ct = read_frame(&mut recv).await.map_err(|e| e.to_string())?;
            let n = transport.read_message(&resp_ct, &mut tmp).unwrap();
            Ok::<Vec<u8>, String>(tmp[..n].to_vec())
        });

        // Agent: run the full loop (dial → register → accept-and-serve-noise).
        let config = AgentConfig {
            edge: edge_addr,
            origin: origin_addr,
            origin_proto: OriginProto::Tcp,
            direct_advertise_ip: None,
        };
        let token_a = token.clone();
        let origin_priv = origin_kp.private;
        let agent = tokio::spawn(async move {
            let _ = run_agent(&config, cert, token_a, origin_priv).await;
        });

        let echoed = edge.await.unwrap().unwrap();
        assert_eq!(echoed, b"ping", "Noise-relayed stream reaches origin and echoes back");
        assert!(state.is_known(&token), "agent registered its tunnel");
        agent.abort();
        let _ = origin.await;
    }
}
