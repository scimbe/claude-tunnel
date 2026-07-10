//! Opaque byte relay (ADR-0015 fallback relay path).
//!
//! When a Client and Agent cannot form a direct P2P path, the Edge relays
//! ciphertext between them. The Edge is provider-blind: it copies bytes without
//! inspecting them. P2.4a is the generic bidirectional relay primitive; P2.4b
//! wires it onto paired QUIC streams (Client stream ↔ Agent tunnel).

use quinn::{RecvStream, SendStream};
use tokio::io::{copy_bidirectional, join, AsyncRead, AsyncWrite};

/// Relay bytes both directions between `a` and `b` until both sides close.
/// Returns `(bytes a→b, bytes b→a)`. The bytes are never inspected.
pub async fn relay<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    copy_bidirectional(a, b).await
}

/// Relay between a Client's QUIC stream and an Agent's QUIC tunnel stream. Each
/// `(recv, send)` pair is joined into one duplex, then relayed via [`relay`].
pub async fn relay_quic(
    client_send: SendStream,
    client_recv: RecvStream,
    agent_send: SendStream,
    agent_recv: RecvStream,
) -> std::io::Result<(u64, u64)> {
    let mut client = join(client_recv, client_send);
    let mut agent = join(agent_recv, agent_send);
    relay(&mut client, &mut agent).await
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
            let _ = relay_quic(client_send, client_recv, agent_send, agent_recv).await;
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
