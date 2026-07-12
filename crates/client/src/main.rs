//! Claude Tunnel Client tool (M6.1c).
//!
//! Waits for the Edge cert and the Agent's Capability, then either tunnels a
//! single payload (verifying the round-trip) or, when `CT_CLIENT_ITERATIONS>1`,
//! runs the latency bench and prints a labeled `RESULT` CSV row for the sweep.

use std::net::SocketAddr;
use std::time::Duration;

use ct_client::bench::{csv_row, run_bench, run_bench_stream, run_bench_udp, summarize};
use ct_client::config::ClientConfig;
use ct_client::transport::{
    client_tunnel_auto, client_tunnel_noise, client_tunnel_noise_tcp, dial_edge, tcp_tls_connect,
    udp_selftest, load_cert,
};
use ct_common::noise::generate_static_keypair;
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

    // The Client's ephemeral Noise static key (its static key is not pinned by
    // the Origin in Noise_IK, so a fresh one per run is fine).
    let client_kp = generate_static_keypair();

    // UDP mode: send one datagram through the tunnel to a UDP Origin and verify
    // the echo (the Agent must run with CT_AGENT_ORIGIN_PROTO=udp).
    if std::env::var("CT_CLIENT_MODE").as_deref() == Ok("udp") {
        let conn = dial_edge(edge_addr, edge_cert).await?;
        let echo =
            udp_selftest(&conn, &cap.token, &cap, &client_kp.private, payload.as_bytes()).await?;
        println!(
            "ct-client: udp sent {:?}, received {:?}",
            payload,
            String::from_utf8_lossy(&echo)
        );
        return if echo == payload.as_bytes() {
            eprintln!("ct-client: UDP tunnel round-trip OK");
            Ok(())
        } else {
            Err("udp echo mismatch".into())
        };
    }

    // P2P mode: auto-discover the Agent's direct endpoint and use the direct
    // path, falling back to the Edge relay. Retries briefly to win the startup
    // race where the Agent hasn't advertised its listener yet.
    if std::env::var("CT_CLIENT_MODE").as_deref() == Ok("p2p") {
        let mut result = (false, Vec::new());
        for attempt in 0..5u32 {
            let conn = dial_edge(edge_addr, edge_cert.clone()).await?;
            let (used_direct, resp) = client_tunnel_auto(
                &conn,
                &cap.token,
                &cap,
                &client_kp.private,
                payload.as_bytes(),
                Duration::from_secs(3),
            )
            .await?;
            conn.close(0u32.into(), b"done");
            if resp != payload.as_bytes() {
                return Err("p2p echo mismatch".into());
            }
            result = (used_direct, resp);
            if used_direct || attempt == 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let (used_direct, resp) = result;
        println!(
            "ct-client: p2p sent {:?}, received {:?} (direct={used_direct})",
            payload,
            String::from_utf8_lossy(&resp)
        );
        eprintln!("ct-client: P2P tunnel round-trip OK (direct={used_direct})");
        return Ok(());
    }

    // Bench mode: run N round-trips and emit a labeled CSV row. CT_BENCH_MODE
    // selects the measured path — "stream" for the full-duplex streaming path,
    // otherwise the one-shot path (M16.2b).
    if iterations > 1 {
        let bench_mode = std::env::var("CT_BENCH_MODE").unwrap_or_default();
        let samples = match bench_mode.as_str() {
            "stream" => {
                run_bench_stream(
                    edge_addr,
                    edge_cert,
                    &cap,
                    &client_kp.private,
                    payload.as_bytes(),
                    iterations,
                )
                .await
            }
            "udp" => {
                run_bench_udp(
                    edge_addr,
                    edge_cert,
                    &cap,
                    &client_kp.private,
                    payload.as_bytes(),
                    iterations,
                )
                .await
            }
            _ => {
                run_bench(
                    edge_addr,
                    edge_cert,
                    &cap,
                    &client_kp.private,
                    payload.as_bytes(),
                    iterations,
                )
                .await
            }
        };
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

    // Single-tunnel mode: QUIC primary, TLS-TCP fallback when UDP is blocked.
    // CT_CLIENT_FORCE_TCP forces the fallback (used by the UDP-blocked smoke).
    let force_tcp = std::env::var("CT_CLIENT_FORCE_TCP").is_ok();
    let quic_conn = if force_tcp {
        None
    } else {
        match tokio::time::timeout(Duration::from_secs(2), dial_edge(edge_addr, edge_cert.clone()))
            .await
        {
            Ok(Ok(conn)) => Some(conn),
            _ => None,
        }
    };
    let (response, via) = match quic_conn {
        Some(conn) => {
            let r = client_tunnel_noise(&conn, &cap.token, &cap, &client_kp.private, payload.as_bytes())
                .await?;
            (r, "quic")
        }
        None => {
            let tls = tcp_tls_connect(edge_addr, edge_cert).await?;
            let r = client_tunnel_noise_tcp(tls, &cap.token, &cap, &client_kp.private, payload.as_bytes())
                .await?;
            (r, "tcp")
        }
    };
    println!(
        "ct-client: sent {:?}, received {:?} (via={via})",
        payload,
        String::from_utf8_lossy(&response)
    );
    if response == payload.as_bytes() {
        eprintln!("ct-client: tunnel round-trip OK (via={via})");
        Ok(())
    } else {
        Err("tunnel response mismatch".into())
    }
}
