//! Performance bench harness (M6.1a).
//!
//! Summary statistics over latency samples (pure, tested here), plus — in M6.1b —
//! a runner that measures tunnel round-trip latency under `tc netem` conditions
//! for the evaluation (M6).

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
}
