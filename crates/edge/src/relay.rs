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
}
