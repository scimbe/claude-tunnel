//! Direct-connection baseline bench for the thesis FF2 measurement (#51).
//!
//! Measures the round-trip latency of a **direct** client→server connection over
//! the same `tc netem` path the tunnel sweep uses, with **no ct-edge / no tunnel
//! hop** in between, and emits a `RESULT <csv_row>` line in the *exact* format the
//! tunnel bench prints (`ct_client::bench::csv_row`) so `scripts/tabulate.py` can
//! diff tunnel − baseline into an overhead column. Two protocols:
//!
//!   CT_DIRECT_PROTO=tcp   — plain TCP round-trip to a TCP echo (the testbed's
//!                           socat `origin`); the transport the tunnel ultimately
//!                           delivers at the Origin.
//!   CT_DIRECT_PROTO=quic  — plain QUIC round-trip to `quic_echo`; isolates the
//!                           Noise/relay/PoW overhead from the QUIC transport the
//!                           tunnel's client→edge hop already pays.
//!
//! Methodology mirrors the tunnel one-shot bench (`bench::run_once`): a *fresh*
//! connection per iteration, write payload → half-close → read the echo back,
//! timed end-to-end; failed iterations are skipped. The netem condition labels are
//! read from the same `CT_BENCH_DELAY/LOSS/RATE` env the tunnel client uses, so the
//! baseline rows line up with the tunnel rows for the same grid point.
//!
//! Env:
//!   CT_DIRECT_PROTO       tcp | quic            (default tcp)
//!   CT_DIRECT_TARGET      host:port to dial     (default 10.5.0.3:8080)
//!   CT_DIRECT_CERT        quic server cert (der) (default /shared/quic-echo-cert.der)
//!   CT_CLIENT_ITERATIONS  round-trips to measure (default 30)
//!   CT_CLIENT_PAYLOAD     bytes to echo          (default hello-direct)
//!   CT_BENCH_DELAY/LOSS/RATE  condition labels for the CSV row (blank = none)

use std::net::SocketAddr;
use std::time::Instant;

use ct_client::bench::{csv_row, summarize};
use ct_client::transport::{dial_edge, load_cert};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// One fresh-connection TCP round-trip: connect → write → half-close → read echo.
async fn tcp_once(target: SocketAddr, payload: &[u8]) -> Result<f64, BoxError> {
    let start = Instant::now();
    let mut stream = TcpStream::connect(target).await?;
    stream.write_all(payload).await?;
    stream.shutdown().await?; // signal EOF so the echo (socat /bin/cat) replies + closes
    let mut got = Vec::new();
    stream.read_to_end(&mut got).await?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    if got == payload {
        Ok(elapsed)
    } else {
        Err("tcp echo mismatch".into())
    }
}

/// One fresh-connection QUIC round-trip: connect → open_bi → write → finish → read
/// echo. Reuses the client's QUIC dialer (`dial_edge`), which trusts exactly the
/// server cert we load from the shared volume.
async fn quic_once(
    target: SocketAddr,
    cert: rustls::pki_types::CertificateDer<'static>,
    payload: &[u8],
) -> Result<f64, BoxError> {
    let start = Instant::now();
    let conn = dial_edge(target, cert).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(payload).await?;
    send.finish()?;
    let got = recv.read_to_end(64 * 1024).await?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    conn.close(0u32.into(), b"done");
    if got == payload {
        Ok(elapsed)
    } else {
        Err("quic echo mismatch".into())
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let proto = std::env::var("CT_DIRECT_PROTO").unwrap_or_else(|_| "tcp".to_string());
    let target: SocketAddr = std::env::var("CT_DIRECT_TARGET")
        .unwrap_or_else(|_| "10.5.0.3:8080".to_string())
        .parse()?;
    let iterations: usize = std::env::var("CT_CLIENT_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let payload = std::env::var("CT_CLIENT_PAYLOAD").unwrap_or_else(|_| "hello-direct".to_string());
    let payload = payload.as_bytes();

    // For QUIC, wait briefly for the echo server to publish its cert (startup race).
    let cert = if proto == "quic" {
        let path = std::env::var("CT_DIRECT_CERT")
            .unwrap_or_else(|_| "/shared/quic-echo-cert.der".to_string());
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match load_cert(&path) {
                Ok(c) => break Some(c),
                Err(_) if Instant::now() < deadline => {
                    eprintln!("direct_bench: waiting for quic echo cert at {path} ...");
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                Err(e) => return Err(format!("quic echo cert not available at {path}: {e}").into()),
            }
        }
    } else {
        None
    };

    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let r = match proto.as_str() {
            "quic" => quic_once(target, cert.clone().unwrap(), payload).await,
            _ => tcp_once(target, payload).await,
        };
        match r {
            Ok(ms) => samples.push(ms),
            Err(e) => eprintln!("direct_bench: iteration failed: {e}"),
        }
    }

    let summary = summarize(&samples).ok_or("direct bench produced no samples")?;
    let delay = std::env::var("CT_BENCH_DELAY").unwrap_or_default();
    let loss = std::env::var("CT_BENCH_LOSS").unwrap_or_default();
    let rate = std::env::var("CT_BENCH_RATE").unwrap_or_default();
    println!("RESULT {}", csv_row(&delay, &loss, &rate, &summary, &samples));
    eprintln!(
        "direct_bench: proto={} {}/{} iterations, mean {:.2}ms p95 {:.2}ms",
        proto, summary.n, iterations, summary.mean_ms, summary.p95_ms
    );
    Ok(())
}
