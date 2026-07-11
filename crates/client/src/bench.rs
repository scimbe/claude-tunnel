//! Performance bench harness (M6.1a).
//!
//! Summary statistics over latency samples (pure, tested here), plus — in M6.1b —
//! a runner that measures tunnel round-trip latency under `tc netem` conditions
//! for the evaluation (M6).

use std::net::SocketAddr;
use std::time::Instant;

use crate::transport::{client_tunnel, dial_edge};
use ct_common::RoutingToken;
use rustls::pki_types::CertificateDer;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// CSV header for a sweep result file.
pub const CSV_HEADER: &str = "delay,loss,rate,n,mean_ms,min_ms,max_ms,p50_ms,p95_ms";

/// Summary statistics over a set of latency samples (milliseconds).
#[derive(Debug, Clone, PartialEq)]
pub struct Summary {
    pub n: usize,
    pub mean_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
}

/// Summarize latency `samples` (ms). Returns `None` for an empty set. Percentiles
/// use nearest-rank on the sorted samples.
pub fn summarize(samples: &[f64]) -> Option<Summary> {
    if samples.is_empty() {
        return None;
    }
    let n = samples.len();
    let mean_ms = samples.iter().sum::<f64>() / n as f64;

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
    })
}

/// One fresh-connection round-trip: dial → tunnel `payload` → verify echo,
/// returning the elapsed time in milliseconds.
async fn run_once(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    token: &RoutingToken,
    payload: &[u8],
) -> Result<f64, BoxError> {
    let start = Instant::now();
    let conn = dial_edge(edge_addr, edge_cert).await?;
    let response = client_tunnel(&conn, token, payload).await?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    conn.close(0u32.into(), b"done");
    if response == payload {
        Ok(elapsed)
    } else {
        Err("bench response mismatch".into())
    }
}

/// Run `iterations` fresh-connection round-trips, returning per-iteration latency
/// in milliseconds. Failed iterations are skipped.
pub async fn run_bench(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    token: &RoutingToken,
    payload: &[u8],
    iterations: usize,
) -> Vec<f64> {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        if let Ok(ms) = run_once(edge_addr, edge_cert.clone(), token, payload).await {
            samples.push(ms);
        }
    }
    samples
}

/// Format a CSV row for a netem condition and its latency [`Summary`].
pub fn csv_row(delay: &str, loss: &str, rate: &str, s: &Summary) -> String {
    format!(
        "{},{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3}",
        delay, loss, rate, s.n, s.mean_ms, s.min_ms, s.max_ms, s.p50_ms, s.p95_ms
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
        };
        assert_eq!(
            csv_row("30ms", "1%", "10mbit", &s),
            "30ms,1%,10mbit,5,30.000,10.000,50.000,30.000,50.000"
        );
    }

    #[tokio::test]
    async fn run_bench_measures_iterations() {
        use ct_common::pow::Challenge;
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use quinn::Connection;
        use std::sync::Arc;

        let token = RoutingToken([6u8; 32]);
        let challenge = Challenge {
            nonce: [0x44; 16],
            difficulty: 6,
        };
        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

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

        // Agent: register, then echo every relayed stream.
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
        let agent_task = tokio::spawn(async move {
            while let Ok((mut s, mut r)) = agent_conn.accept_bi().await {
                tokio::spawn(async move {
                    let d = r.read_to_end(4096).await.unwrap_or_default();
                    let _ = s.write_all(&d).await;
                    let _ = s.finish();
                });
            }
        });

        let samples = run_bench(addr, cert, &token, b"ping", 3).await;
        assert_eq!(samples.len(), 3, "three successful round-trips measured");
        assert!(summarize(&samples).is_some());

        agent_task.abort();
        edge.abort();
    }
}
