//! Claude Tunnel Client tool (M6.1c).
//!
//! Waits for the Edge cert and the Agent's Capability, then either tunnels a
//! single payload (verifying the round-trip) or, when `CT_CLIENT_ITERATIONS>1`,
//! runs the latency bench and prints a labeled `RESULT` CSV row for the sweep.

use std::net::SocketAddr;
use std::time::Duration;

use ct_client::bench::{csv_row, run_bench, summarize};
use ct_client::config::ClientConfig;
use ct_client::transport::{client_tunnel, dial_edge, load_cert};
use ct_common::Capability;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = ClientConfig::from_env();
    let payload = std::env::var("CT_CLIENT_PAYLOAD").unwrap_or_else(|_| "hello-tunnel".to_string());
    let iterations: usize = std::env::var("CT_CLIENT_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    // Wait for the Edge cert.
    let edge_cert = loop {
        match load_cert(&config.edge_cert_file) {
            Ok(cert) => break cert,
            Err(_) => {
                eprintln!("ct-client: waiting for edge cert ...");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    // Wait for the Agent's Capability.
    let cap = loop {
        match std::fs::read(&config.capability_file)
            .ok()
            .and_then(|b| Capability::decode(&b).ok())
        {
            Some(cap) => break cap,
            None => {
                eprintln!("ct-client: waiting for capability ...");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    let edge_addr: SocketAddr = cap.edge_addr.parse()?;

    // Bench mode: run N round-trips and emit a labeled CSV row.
    if iterations > 1 {
        let samples = run_bench(edge_addr, edge_cert, &cap.token, payload.as_bytes(), iterations).await;
        let summary = summarize(&samples).ok_or("bench produced no samples")?;
        let delay = std::env::var("CT_BENCH_DELAY").unwrap_or_default();
        let loss = std::env::var("CT_BENCH_LOSS").unwrap_or_default();
        let rate = std::env::var("CT_BENCH_RATE").unwrap_or_default();
        println!("RESULT {}", csv_row(&delay, &loss, &rate, &summary));
        eprintln!(
            "ct-client: bench {}/{} iterations, mean {:.2}ms p95 {:.2}ms",
            summary.n, iterations, summary.mean_ms, summary.p95_ms
        );
        return Ok(());
    }

    // Single-tunnel mode: verify the round-trip.
    let conn = dial_edge(edge_addr, edge_cert).await?;
    let response = client_tunnel(&conn, &cap.token, payload.as_bytes()).await?;
    println!(
        "ct-client: sent {:?}, received {:?}",
        payload,
        String::from_utf8_lossy(&response)
    );
    if response == payload.as_bytes() {
        eprintln!("ct-client: tunnel round-trip OK");
        Ok(())
    } else {
        Err("tunnel response mismatch".into())
    }
}
