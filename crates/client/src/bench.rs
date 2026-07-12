//! Performance bench harness (M6.1a).
//!
//! Summary statistics over latency samples (pure, tested here), plus — in M6.1b —
//! a runner that measures tunnel round-trip latency under `tc netem` conditions
//! for the evaluation (M6).

use std::net::SocketAddr;
use std::time::Instant;

use crate::transport::{client_tunnel_noise, dial_edge};
use ct_common::Capability;
use rustls::pki_types::CertificateDer;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// CSV header for a sweep result file. The M16 statistical columns
/// (`stddev_ms`, `ci95_ms`, `p99_ms`) are appended after the original M6 columns
/// so existing readers that index the first nine columns keep working.
pub const CSV_HEADER: &str =
    "delay,loss,rate,n,mean_ms,min_ms,max_ms,p50_ms,p95_ms,stddev_ms,ci95_ms,p99_ms";

/// Summary statistics over a set of latency samples (milliseconds).
#[derive(Debug, Clone, PartialEq)]
pub struct Summary {
    pub n: usize,
    pub mean_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    /// Sample standard deviation (n−1 denominator); 0 for n < 2.
    pub stddev_ms: f64,
    /// Half-width of the 95% confidence interval for the mean
    /// (1.96·stddev/√n); 0 for n < 2.
    pub ci95_ms: f64,
    /// 99th percentile (nearest-rank) — the tail the study reports.
    pub p99_ms: f64,
}

/// Summarize latency `samples` (ms). Returns `None` for an empty set. Percentiles
/// use nearest-rank on the sorted samples; the spread is reported as the sample
/// standard deviation and a 95% confidence interval for the mean (M16 — results
/// must be statistically defensible, not single-point).
pub fn summarize(samples: &[f64]) -> Option<Summary> {
    if samples.is_empty() {
        return None;
    }
    let n = samples.len();
    let mean_ms = samples.iter().sum::<f64>() / n as f64;

    // Sample variance (n−1); undefined for a single sample → treat spread as 0.
    let (stddev_ms, ci95_ms) = if n >= 2 {
        let variance = samples
            .iter()
            .map(|x| {
                let d = x - mean_ms;
                d * d
            })
            .sum::<f64>()
            / (n as f64 - 1.0);
        let stddev = variance.sqrt();
        (stddev, 1.96 * stddev / (n as f64).sqrt())
    } else {
        (0.0, 0.0)
    };

    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let percentile = |p: f64| -> f64 {
        let idx = ((p / 100.0) * (n as f64 - 1.0)).round() as usize;
        sorted[idx]
    };

    Some(Summary {
        n,
        mean_ms,
        min_ms: sorted[0],
        max_ms: sorted[n - 1],
        p50_ms: percentile(50.0),
        p95_ms: percentile(95.0),
        stddev_ms,
        ci95_ms,
        p99_ms: percentile(99.0),
    })
}

/// One fresh-connection Noise round-trip: dial → `client_tunnel_noise` → verify
/// echo, returning the elapsed time in milliseconds (M8.4c-ii).
async fn run_once(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
) -> Result<f64, BoxError> {
    let start = Instant::now();
    let conn = dial_edge(edge_addr, edge_cert).await?;
    let response = client_tunnel_noise(&conn, &cap.token, cap, client_private, payload).await?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    conn.close(0u32.into(), b"done");
    if response == payload {
        Ok(elapsed)
    } else {
        Err("bench response mismatch".into())
    }
}

/// Run `iterations` fresh-connection Noise round-trips, returning per-iteration
/// latency in milliseconds. Failed iterations are skipped.
pub async fn run_bench(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    iterations: usize,
) -> Vec<f64> {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        if let Ok(ms) = run_once(edge_addr, edge_cert.clone(), cap, client_private, payload).await {
            samples.push(ms);
        }
    }
    samples
}

/// Format a CSV row for a netem condition and its latency [`Summary`]. Column
/// order matches [`CSV_HEADER`]: the M16 stats are appended after `p95_ms`.
pub fn csv_row(delay: &str, loss: &str, rate: &str, s: &Summary) -> String {
    format!(
        "{},{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3}",
        delay,
        loss,
        rate,
        s.n,
        s.mean_ms,
        s.min_ms,
        s.max_ms,
        s.p50_ms,
        s.p95_ms,
        s.stddev_ms,
        s.ci95_ms,
        s.p99_ms
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_known_samples() {
        let s = summarize(&[10.0, 20.0, 30.0, 40.0, 50.0]).unwrap();
        assert_eq!(s.n, 5);
        assert_eq!(s.mean_ms, 30.0);
        assert_eq!(s.min_ms, 10.0);
        assert_eq!(s.max_ms, 50.0);
        assert_eq!(s.p50_ms, 30.0);
        assert_eq!(s.p95_ms, 50.0);
        assert_eq!(s.p99_ms, 50.0);
        // Sample stddev = sqrt(1000/4) = sqrt(250) ≈ 15.811; CI95 = 1.96·σ/√5.
        assert!((s.stddev_ms - 250.0_f64.sqrt()).abs() < 1e-9, "sample stddev");
        assert!((s.ci95_ms - 1.96 * 250.0_f64.sqrt() / 5.0_f64.sqrt()).abs() < 1e-9, "95% CI");
    }

    #[test]
    fn single_sample_has_zero_spread() {
        let s = summarize(&[42.0]).unwrap();
        assert_eq!(s.n, 1);
        assert_eq!(s.mean_ms, 42.0);
        assert_eq!(s.p99_ms, 42.0);
        assert_eq!(s.stddev_ms, 0.0, "no spread from one sample");
        assert_eq!(s.ci95_ms, 0.0, "no CI from one sample");
    }

    #[test]
    fn unsorted_input_is_handled() {
        let s = summarize(&[50.0, 10.0, 30.0]).unwrap();
        assert_eq!(s.min_ms, 10.0);
        assert_eq!(s.max_ms, 50.0);
        assert_eq!(s.p50_ms, 30.0);
    }

    #[test]
    fn empty_is_none() {
        assert!(summarize(&[]).is_none());
    }

    #[test]
    fn csv_row_formats() {
        let s = Summary {
            n: 5,
            mean_ms: 30.0,
            min_ms: 10.0,
            max_ms: 50.0,
            p50_ms: 30.0,
            p95_ms: 50.0,
            stddev_ms: 1.5,
            ci95_ms: 2.5,
            p99_ms: 50.0,
        };
        assert_eq!(
            csv_row("30ms", "1%", "10mbit", &s),
            "30ms,1%,10mbit,5,30.000,10.000,50.000,30.000,50.000,1.500,2.500,50.000"
        );
    }

    #[tokio::test]
    async fn run_bench_measures_iterations() {
        use ct_agent::serve::serve_noise_bridge;
        use ct_common::noise::generate_static_keypair;
        use ct_common::pow::Challenge;
        use ct_common::{OriginIdentity, RoutingToken};
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use quinn::Connection;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let token = RoutingToken([6u8; 32]);
        let challenge = Challenge {
            nonce: [0x44; 16],
            difficulty: 6,
        };
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // Multi-accept TCP echo Origin (one connection per bench iteration).
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = origin_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let _ = sock.read_to_end(&mut buf).await;
                    let _ = sock.write_all(&buf).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };

        // Edge: serve every incoming connection.
        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            while let Some(inc) = server.accept().await {
                let state = state_e.clone();
                let chal = chal_e.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = inc.await {
                        let _ = serve_connection(&conn, &state, &chal).await;
                        conn.closed().await;
                    }
                });
            }
        });

        // Agent: register, then serve every relayed stream as the Noise responder.
        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut rs, mut rr) = agent_conn.open_bi().await.unwrap();
        rs.write_all(b"A").await.unwrap();
        rs.write_all(&token.0).await.unwrap();
        rs.finish().unwrap();
        assert_eq!(rr.read_to_end(8).await.unwrap(), b"OK");
        let origin_priv = origin_kp.private;
        let agent_task = tokio::spawn(async move {
            while let Ok((mut s, mut r)) = agent_conn.accept_bi().await {
                let priv_ = origin_priv;
                tokio::spawn(async move {
                    let _ = serve_noise_bridge(&mut s, &mut r, origin_addr, &priv_).await;
                });
            }
        });

        let samples = run_bench(addr, cert, &cap, &client_kp.private, b"ping", 3).await;
        assert_eq!(samples.len(), 3, "three successful Noise round-trips measured");
        assert!(summarize(&samples).is_some());

        agent_task.abort();
        edge.abort();
        origin.abort();
    }
}
