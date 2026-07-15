//! Opaque byte relay (ADR-0015 fallback relay path).
//!
//! When a Client and Agent cannot form a direct P2P path, the Edge relays
//! ciphertext between them. The Edge is provider-blind: it copies bytes without
//! inspecting them. P2.4a is the generic bidirectional relay primitive; P2.4b
//! wires it onto paired QUIC streams (Client stream ↔ Agent tunnel).

use quinn::{RecvStream, SendStream};
use tokio::io::{
    copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};

/// Emit an Edge relay diagnostic when `CT_EDGE_TRACE` is set (issue #2, mode b).
fn relay_trace(args: std::fmt::Arguments<'_>) {
    if std::env::var_os("CT_EDGE_TRACE").is_some() {
        eprintln!("[edge-trace] {args}");
    }
}

/// Relay bytes both directions between `a` and `b` until both sides close.
/// Returns `(bytes a→b, bytes b→a)`. The bytes are never inspected.
pub async fn relay<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    copy_bidirectional(a, b).await
}

/// Pump one direction: read from `r`, write+**flush** each chunk to `w`, until
/// `r` reaches EOF, then shut `w` down. Flushing per chunk means a small reply
/// (e.g. a Noise handshake response) is pushed to the wire immediately instead
/// of waiting for more source data — and the per-direction byte count + trace
/// make a stalled direction visible in real time (issue #2, mode b: the agent's
/// reply reached the edge but never made it back to the client).
async fn pump_dir<R, W>(mut r: R, mut w: W, dir: &str, label: &str) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            break;
        }
        if total == 0 {
            relay_trace(format_args!("relay {label} {dir}: first {n} bytes"));
        }
        total += n as u64;
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
    }
    relay_trace(format_args!("relay {label} {dir}: {total} bytes total then EOF"));
    Ok(total)
}

/// Relay both directions between an `a` side (`a_recv`/`a_send`) and a `b` side,
/// pumping each direction independently so the reverse direction is never
/// starved by the forward one. Returns `(bytes a→b, bytes b→a)`.
async fn relay_pair<AR, AW, BR, BW>(
    a_recv: AR,
    a_send: AW,
    b_recv: BR,
    b_send: BW,
    label: &str,
) -> std::io::Result<(u64, u64)>
where
    AR: AsyncRead + Unpin,
    AW: AsyncWrite + Unpin,
    BR: AsyncRead + Unpin,
    BW: AsyncWrite + Unpin,
{
    let fwd = pump_dir(a_recv, b_send, "a->b", label);
    let rev = pump_dir(b_recv, a_send, "b->a", label);
    tokio::try_join!(fwd, rev)
}

/// Relay between a Client's QUIC stream and an Agent's QUIC tunnel stream,
/// pumping `client→agent` and `agent→client` independently (each flushed per
/// chunk) so the agent's reply can't be stranded behind an idle forward
/// direction. `label` (a token hex) tags the per-direction trace.
pub async fn relay_quic(
    client_send: SendStream,
    client_recv: RecvStream,
    agent_send: SendStream,
    agent_recv: RecvStream,
    label: &str,
) -> std::io::Result<(u64, u64)> {
    // a = client, b = agent: a→b is client→agent, b→a is agent→client.
    relay_pair(client_recv, client_send, agent_recv, agent_send, label).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn relays_bytes_both_directions() {
        use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

        // client <-> edge_client   and   edge_agent <-> agent
        let (mut client, mut edge_client) = duplex(1024);
        let (mut edge_agent, mut agent) = duplex(1024);

        let relay_task =
            tokio::spawn(async move { relay(&mut edge_client, &mut edge_agent).await });

        client.write_all(b"c2a").await.unwrap();
        client.shutdown().await.unwrap();
        agent.write_all(b"a2c").await.unwrap();
        agent.shutdown().await.unwrap();

        let mut got_agent = Vec::new();
        agent.read_to_end(&mut got_agent).await.unwrap();
        let mut got_client = Vec::new();
        client.read_to_end(&mut got_client).await.unwrap();

        assert_eq!(got_agent, b"c2a", "client bytes reach the agent");
        assert_eq!(got_client, b"a2c", "agent bytes reach the client");

        let (a2b, b2a) = relay_task.await.unwrap().unwrap();
        assert_eq!((a2b, b2a), (3, 3), "byte counts in each direction");
    }

    #[tokio::test]
    async fn relay_delivers_the_reply_while_the_request_side_stays_open() {
        // issue #2 (mode b): the forward leg (client→agent) works and the agent
        // writes its reply, but the reply must reach the client even though the
        // client hasn't closed its send (a Noise handshake: send msg1, keep the
        // stream open, await msg2). The reverse direction must not be starved by
        // the idle forward direction. Drives the generic relay_pair core.
        use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};

        let (mut client, edge_client) = duplex(1024);
        let (edge_agent, mut agent) = duplex(1024);
        let (ec_r, ec_w) = split(edge_client);
        let (ea_r, ea_w) = split(edge_agent);

        let relay_task =
            tokio::spawn(async move { relay_pair(ec_r, ec_w, ea_r, ea_w, "test").await });

        // Client sends msg1 and keeps its stream OPEN (no shutdown).
        client.write_all(b"msg1").await.unwrap();
        let mut got = [0u8; 4];
        agent.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"msg1", "forward leg delivers the request");

        // Agent replies while the forward (request) direction is still open.
        agent.write_all(b"msg2").await.unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"msg2", "reply relayed back with the request side still open");

        // Close both ends so the relay finishes and reports byte counts.
        client.shutdown().await.unwrap();
        agent.shutdown().await.unwrap();
        let (fwd, rev) = relay_task.await.unwrap().unwrap();
        assert_eq!((fwd, rev), (4, 4), "one message each direction");
    }

    #[tokio::test]
    async fn edge_relays_client_bytes_to_agent_over_quic() {
        use crate::transport::{build_client_endpoint, build_server_endpoint_with_cert};

        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        // Edge: accept the Agent conn (open the tunnel stream), accept the
        // Client conn (accept its stream), and relay between them. The
        // client->agent direction completes once the client finishes its send;
        // we don't require the reverse direction to close (avoids a teardown
        // race), so the relay future is simply dropped when the test ends.
        let edge_task = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            let (agent_send, agent_recv) = agent_conn.open_bi().await.unwrap();
            let client_conn = server.accept().await.unwrap().await.unwrap();
            let (client_send, client_recv) = client_conn.accept_bi().await.unwrap();
            let _ = relay_quic(client_send, client_recv, agent_send, agent_recv, "test").await;
        });

        // Agent connects first, then reads the relayed stream to end.
        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let agent_task = tokio::spawn(async move {
            let (_a_send, mut a_recv) = agent_conn.accept_bi().await.unwrap();
            a_recv.read_to_end(1024).await.unwrap()
        });

        // Client connects, sends bytes, finishes its send.
        let client_ep = build_client_endpoint(cert).expect("client ep");
        let client_conn = client_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("client conn");
        let (mut c_send, _c_recv) = client_conn.open_bi().await.unwrap();
        c_send.write_all(b"hello-agent").await.unwrap();
        c_send.finish().unwrap();

        let agent_got = agent_task.await.unwrap();
        assert_eq!(
            agent_got, b"hello-agent",
            "client bytes reach the agent via the relay"
        );

        drop(client_conn); // hold the client connection until the assertion
        edge_task.abort();
    }

    #[tokio::test]
    async fn noise_e2e_through_relay_edge_sees_only_ciphertext() {
        use ct_common::noise::{client_handshake, generate_static_keypair, origin_handshake};
        use tokio::io::{duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

        async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, msg: &[u8]) {
            w.write_all(&(msg.len() as u16).to_be_bytes()).await.unwrap();
            w.write_all(msg).await.unwrap();
            w.flush().await.unwrap();
        }
        async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Vec<u8> {
            let mut len = [0u8; 2];
            r.read_exact(&mut len).await.unwrap();
            let n = u16::from_be_bytes(len) as usize;
            let mut buf = vec![0u8; n];
            r.read_exact(&mut buf).await.unwrap();
            buf
        }

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let origin_pub = origin_kp.public;

        // client <-> edge_c   and   edge_a <-> origin; the Edge relays between
        // edge_c and edge_a, seeing only opaque bytes.
        let (mut client, mut edge_c) = duplex(8192);
        let (mut edge_a, mut origin) = duplex(8192);

        let relay_task = tokio::spawn(async move {
            let _ = relay(&mut edge_c, &mut edge_a).await;
        });

        // Origin (responder): finish the handshake, decrypt one payload.
        let origin_task = tokio::spawn(async move {
            let mut hs = origin_handshake(&origin_kp.private).unwrap();
            let mut scratch = [0u8; 4096];
            let m1 = read_frame(&mut origin).await;
            hs.read_message(&m1, &mut scratch).unwrap();
            let mut out = [0u8; 4096];
            let n = hs.write_message(&[], &mut out).unwrap();
            write_frame(&mut origin, &out[..n]).await;
            let mut transport = hs.into_transport_mode().unwrap();
            let ct = read_frame(&mut origin).await;
            let mut pt = [0u8; 4096];
            let m = transport.read_message(&ct, &mut pt).unwrap();
            pt[..m].to_vec()
        });

        // Client (initiator): pins the Origin's public key.
        let mut hs = client_handshake(&client_kp.private, &origin_pub).unwrap();
        let mut out = [0u8; 4096];
        let n = hs.write_message(&[], &mut out).unwrap();
        write_frame(&mut client, &out[..n]).await;
        let m2 = read_frame(&mut client).await;
        let mut scratch = [0u8; 4096];
        hs.read_message(&m2, &mut scratch).unwrap();
        let mut transport = hs.into_transport_mode().unwrap();

        let secret = b"provider-blind payload";
        let n = transport.write_message(secret, &mut out).unwrap();
        let ciphertext = out[..n].to_vec();
        assert_ne!(
            ciphertext.as_slice(),
            secret.as_slice(),
            "the relayed bytes must be ciphertext, not plaintext"
        );
        write_frame(&mut client, &ciphertext).await;

        let received = origin_task.await.unwrap();
        assert_eq!(
            received, secret,
            "origin decrypts the E2E payload the edge relayed blindly"
        );
        relay_task.abort();
    }
}
