//! Lightweight tunnel metrics for Agent/Client observability (M14.1, ADR-0016).
//!
//! A tiny, dependency-free metric set: atomic counters for tunnel activity plus
//! a sum/count pair for handshake latency, rendered in the Prometheus text
//! exposition format. A `/metrics` endpoint (M14.2) serves the rendered text so
//! a Prometheus scraper can read it. No external metrics crate — the set is
//! small and the exposition format is trivial, which keeps the data path and
//! the dependency graph light.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A monotonically increasing counter (Prometheus `counter`).
///
/// `Relaxed` ordering is sufficient: the counters carry no happens-before
/// relationship to other state; only their eventual totals matter.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// Increment by one.
    pub fn inc(&self) {
        self.add(1);
    }

    /// Increment by `n` (e.g. a relayed byte count).
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    /// Current value.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Tunnel-activity metrics, shared behind an `Arc` by the data-path tasks and
/// the `/metrics` endpoint. Each counter is itself an `Arc` so a single series
/// can be handed to a [`Metered`] stream wrapper independently of the others.
#[derive(Debug, Default, Clone)]
pub struct TunnelMetrics {
    /// Tunnels successfully established (handshake completed).
    pub tunnels_opened: Arc<Counter>,
    /// Tunnel attempts that failed before or during the handshake.
    pub tunnels_failed: Arc<Counter>,
    /// Bytes relayed from the client toward the origin.
    pub bytes_to_origin: Arc<Counter>,
    /// Bytes relayed from the origin back to the client.
    pub bytes_to_client: Arc<Counter>,
    /// Completed handshakes (denominator for the latency average).
    pub handshakes: Arc<Counter>,
    /// Cumulative handshake latency in milliseconds (numerator).
    pub handshake_millis_total: Arc<Counter>,
}

impl TunnelMetrics {
    /// A fresh, all-zero metric set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one completed handshake and its latency. A scraper derives the
    /// mean latency as `handshake_millis_total / handshakes`.
    pub fn observe_handshake(&self, latency: Duration) {
        self.handshakes.inc();
        self.handshake_millis_total.add(latency.as_millis() as u64);
    }

    /// Render the current values in the Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        render_counter(
            &mut out,
            "ct_tunnels_opened_total",
            "Tunnels successfully established.",
            self.tunnels_opened.get(),
        );
        render_counter(
            &mut out,
            "ct_tunnels_failed_total",
            "Tunnel attempts that failed before or during the handshake.",
            self.tunnels_failed.get(),
        );
        render_counter(
            &mut out,
            "ct_bytes_to_origin_total",
            "Bytes relayed from client to origin.",
            self.bytes_to_origin.get(),
        );
        render_counter(
            &mut out,
            "ct_bytes_to_client_total",
            "Bytes relayed from origin to client.",
            self.bytes_to_client.get(),
        );
        render_counter(
            &mut out,
            "ct_handshakes_total",
            "Completed Noise handshakes.",
            self.handshakes.get(),
        );
        render_counter(
            &mut out,
            "ct_handshake_millis_total",
            "Cumulative handshake latency in milliseconds.",
            self.handshake_millis_total.get(),
        );
        out
    }
}

/// Append one Prometheus `counter` block (`# HELP`, `# TYPE`, value) for `name`.
fn render_counter(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
    ));
}

/// A byte-counting wrapper around a stream: bytes successfully read add to
/// `read`, bytes successfully written add to `write`. Drop it around the Origin
/// socket so the tunnel's throughput counters update without threading counts
/// back out of the copy loop (M14.1b).
///
/// Transparent otherwise — it just forwards `poll_*` to the inner stream.
pub struct Metered<S> {
    inner: S,
    read: Arc<Counter>,
    write: Arc<Counter>,
}

impl<S> Metered<S> {
    /// Wrap `inner`, counting reads into `read` and writes into `write`.
    pub fn new(inner: S, read: Arc<Counter>, write: Arc<Counter>) -> Self {
        Self { inner, read, write }
    }

    /// Recover the wrapped stream.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let n = buf.filled().len() - before;
            self.read.add(n as u64);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &poll {
            self.write.add(*n as u64);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn counter_inc_add_get() {
        let c = Counter::default();
        assert_eq!(c.get(), 0);
        c.inc();
        c.add(41);
        assert_eq!(c.get(), 42);
    }

    #[test]
    fn observe_handshake_accumulates_count_and_latency() {
        let m = TunnelMetrics::new();
        m.observe_handshake(Duration::from_millis(30));
        m.observe_handshake(Duration::from_millis(70));
        assert_eq!(m.handshakes.get(), 2);
        assert_eq!(m.handshake_millis_total.get(), 100, "sum of latencies");
    }

    #[test]
    fn render_reflects_current_values_in_prometheus_format() {
        let m = TunnelMetrics::new();
        m.tunnels_opened.inc();
        m.bytes_to_origin.add(1500);
        m.observe_handshake(Duration::from_millis(12));

        let text = m.render_prometheus();
        // Exposition shape: HELP + TYPE + value for each series.
        assert!(text.contains("# TYPE ct_tunnels_opened_total counter\n"));
        assert!(text.contains("\nct_tunnels_opened_total 1\n"));
        assert!(text.contains("\nct_bytes_to_origin_total 1500\n"));
        assert!(text.contains("\nct_handshakes_total 1\n"));
        assert!(text.contains("\nct_handshake_millis_total 12\n"));
        // Untouched series still render at zero.
        assert!(text.contains("\nct_tunnels_failed_total 0\n"));
    }

    #[tokio::test]
    async fn metered_counts_bytes_in_both_directions() {
        let (near, far) = tokio::io::duplex(1024);
        let read = Arc::new(Counter::default());
        let write = Arc::new(Counter::default());
        let mut m = Metered::new(near, Arc::clone(&read), Arc::clone(&write));
        let (mut far_r, mut far_w) = tokio::io::split(far);

        // Writes through the wrapper land on the far end and count as writes.
        m.write_all(b"hello").await.unwrap();
        m.flush().await.unwrap();
        let mut got = [0u8; 5];
        far_r.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
        assert_eq!(write.get(), 5, "5 bytes written");
        assert_eq!(read.get(), 0, "nothing read yet");

        // Bytes sent from the far end count as reads through the wrapper.
        far_w.write_all(b"abc").await.unwrap();
        let mut rb = [0u8; 3];
        m.read_exact(&mut rb).await.unwrap();
        assert_eq!(&rb, b"abc");
        assert_eq!(read.get(), 3, "3 bytes read");
    }

    #[test]
    fn counters_are_shareable_and_sum_across_threads() {
        let m = Arc::new(TunnelMetrics::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = Arc::clone(&m);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    m.tunnels_opened.inc();
                    m.bytes_to_client.add(2);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.tunnels_opened.get(), 8000);
        assert_eq!(m.bytes_to_client.get(), 16000);
    }
}
