//! Direct-baseline QUIC echo server for the thesis FF2 measurement (#51).
//!
//! Binds `CT_QUIC_ECHO_LISTEN` (default `0.0.0.0:4433`) and, for every accepted
//! bidirectional stream, reads the request to EOF and writes it straight back —
//! no tunnel, no Noise, no PoW. This is the direct QUIC endpoint the
//! direct-baseline bench (`direct_bench` with `CT_DIRECT_PROTO=quic`) dials, so
//! FF2 can quantify the tunnel's overhead against a plain QUIC round-trip over the
//! *same* `tc netem` path. It reuses the Edge's own QUIC endpoint builder and
//! self-signed cert plumbing so the transport stack matches the tunnel edge; the
//! generated cert is published to `CT_QUIC_ECHO_CERT_OUT`
//! (default `/shared/quic-echo-cert.der`) for the bench client to trust.

use std::net::SocketAddr;

use ct_edge::transport::{build_server_endpoint_at, save_cert};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen: SocketAddr = std::env::var("CT_QUIC_ECHO_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:4433".to_string())
        .parse()?;
    let cert_out =
        std::env::var("CT_QUIC_ECHO_CERT_OUT").unwrap_or_else(|_| "/shared/quic-echo-cert.der".to_string());
    // Per-stream echo read cap. The latency baseline sends tiny payloads; the
    // throughput baseline (#57) sends a multi-MiB bulk payload, so the cap is
    // configurable (default 256 MiB) — large enough for the bulk transfer, bounded
    // so a runaway peer can't allocate without limit.
    let max_bytes: usize = std::env::var("CT_QUIC_ECHO_MAX_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&b| b > 0)
        .unwrap_or(256 * 1024 * 1024);

    let (endpoint, cert) = build_server_endpoint_at(listen)?;
    save_cert(&cert_out, &cert)?;
    eprintln!("quic_echo: listening on {listen}, published cert to {cert_out}");

    // One task per connection; one echo per accepted bi stream (a fresh
    // connection per bench iteration, mirroring the tunnel's one-shot path).
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else {
                return;
            };
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                tokio::spawn(async move {
                    if let Ok(buf) = recv.read_to_end(max_bytes).await {
                        let _ = send.write_all(&buf).await;
                        let _ = send.finish();
                    }
                });
            }
        });
    }
    Ok(())
}
