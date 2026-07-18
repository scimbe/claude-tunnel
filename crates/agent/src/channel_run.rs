//! Agent Fabric — the A2A channel *runner* (#72 AF4-session-wire, #98/#100).
//!
//! [`crate::channel`] rendezvouses two members and [`ct_common::a2a`] establishes the
//! Noise_IK session; this module is the piece that makes it *runnable*: given an
//! established QUIC connection, a role, and the Noise keys, it completes the A2A
//! handshake and then pumps a local byte stream (the CLI's stdin/stdout, or any
//! `AsyncRead + AsyncWrite`) over the encrypted tunnel — a "netcat over the channel".
//! A thin `ct-agent` subcommand feeds it stdio; tests feed it an in-memory duplex.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use quinn::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use ct_common::a2a::{a2a_initiate, a2a_respond};
use ct_common::noise::noise_pump;

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

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::noise::generate_static_keypair;
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
}
