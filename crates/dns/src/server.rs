//! Authoritative UDP+TCP `:53` responder for the ACME challenge store (#31 AD2).
//!
//! It parses each incoming DNS query, looks up the published TXT value(s) in the
//! [`AcmeDnsStore`], and answers. Malformed datagrams are dropped silently (a
//! resolver simply retries) — never a panic. This is the public-facing half; the
//! record-mutating HTTP API stays localhost-only (AD3).

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::message;
use crate::store::AcmeDnsStore;

/// Build the DNS response for a raw query datagram against `store`, or `None` if
/// the query is malformed (drop it). Pure — the socket loops wrap this.
pub fn respond(store: &AcmeDnsStore, query: &[u8]) -> Option<Vec<u8>> {
    let q = message::parse_query(query)?;
    let txts = store.txt(&q.name);
    Some(message::build_response(&q, &txts))
}

/// Serve DNS over UDP on `listen` until the process ends.
pub async fn serve_udp(store: Arc<AcmeDnsStore>, listen: SocketAddr) -> std::io::Result<()> {
    let sock = tokio::net::UdpSocket::bind(listen).await?;
    udp_loop(store, sock).await
}

/// The UDP receive/answer loop over an already-bound socket (also the test seam).
pub async fn udp_loop(store: Arc<AcmeDnsStore>, sock: tokio::net::UdpSocket) -> std::io::Result<()> {
    // 512 is the classic DNS/UDP message ceiling; ACME TXT answers fit easily.
    let mut buf = vec![0u8; 512];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        if let Some(resp) = respond(&store, &buf[..n]) {
            let _ = sock.send_to(&resp, peer).await;
        }
    }
}

/// Serve DNS over TCP on `listen` until the process ends. TCP DNS messages are
/// length-prefixed with a 2-byte big-endian length.
pub async fn serve_tcp(store: Arc<AcmeDnsStore>, listen: SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    loop {
        let (stream, _peer) = listener.accept().await?;
        let store = store.clone();
        tokio::spawn(async move {
            let _ = handle_tcp(&store, stream).await;
        });
    }
}

async fn handle_tcp(store: &AcmeDnsStore, mut stream: tokio::net::TcpStream) -> std::io::Result<()> {
    let mut lenb = [0u8; 2];
    stream.read_exact(&mut lenb).await?;
    let len = u16::from_be_bytes(lenb) as usize;
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await?;
    if let Some(resp) = respond(store, &msg) {
        stream.write_all(&(resp.len() as u16).to_be_bytes()).await?;
        stream.write_all(&resp).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{CLASS_IN, TYPE_TXT};

    /// Minimal raw TXT query for `name`.
    fn txt_query(id: u16, name: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
        b.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&TYPE_TXT.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b
    }

    #[test]
    fn respond_serves_a_stored_txt_and_drops_malformed() {
        let store = AcmeDnsStore::new();
        store.set_txt("_acme-challenge.host.test", "the-token");

        let resp = respond(&store, &txt_query(0x21, "_acme-challenge.host.test")).unwrap();
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x21, "echoes the id");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "one answer");
        assert!(resp.windows(9).any(|w| w == b"the-token"), "carries the TXT");

        // Unknown name -> valid response, zero answers.
        let resp = respond(&store, &txt_query(1, "_acme-challenge.other.test")).unwrap();
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);

        // Malformed -> dropped.
        assert!(respond(&store, b"\x00\x01").is_none());
    }

    #[tokio::test]
    async fn udp_server_round_trips_a_query() {
        let store = Arc::new(AcmeDnsStore::new());
        store.set_txt("_acme-challenge.host.test", "tok-xyz");

        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(udp_loop(store, server));

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&txt_query(0x42, "_acme-challenge.host.test"), addr).await.unwrap();
        let mut buf = vec![0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no timeout")
            .unwrap();
        let resp = &buf[..n];
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x42);
        assert!(resp.windows(7).any(|w| w == b"tok-xyz"), "answer over the wire");
    }
}
