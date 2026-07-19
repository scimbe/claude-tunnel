//! Overlay-topology optimization for the Topology Editor (#107).
//!
//! Given a network's agents and the **candidate links** it may form — the pairs the
//! [`crate::policy`] permits, each annotated with a measured latency — compute the
//! **best-connectivity overlay**. Per the locked design (scimbe, 2026-07-19) the
//! objective is **latency** and the scale is **arbitrary N**, so this is a real graph
//! algorithm, not a heuristic: a **minimum spanning tree** (Kruskal + union-find) over
//! the latency-weighted candidate edges. That yields a connected overlay of `N-1` links
//! whose **total link latency is minimal** while every agent stays reachable, for any N.
//!
//! This is the first, graph-wiring phase (the issue's phased "SDN" answer): it emits an
//! edge-list the controller wires as A2A channels. Later phases can add latency-reducing
//! shortcuts (stretch, cf. #76's smart-routing/shortcut study) and, eventually, real
//! flow-rules — this MST is the connectivity backbone they build on. Pure and
//! deterministic (ties broken by the canonical node pair), so it is exhaustively testable
//! before any live mesh exists.

use serde::{Deserialize, Serialize};

/// A candidate overlay link between two agents and its measured latency cost. The unit
/// is opaque (microseconds by convention); only the ordering matters to the optimizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeightedLink {
    pub a: String,
    pub b: String,
    /// Lower is better — the optimizer minimizes the total of the chosen links' costs.
    pub cost: u64,
}

impl WeightedLink {
    pub fn new(a: impl Into<String>, b: impl Into<String>, cost: u64) -> Self {
        Self { a: a.into(), b: b.into(), cost }
    }
}

/// The computed overlay: the chosen links (a minimum-latency spanning tree), their total
/// cost, and whether the candidate links could connect **all** the agents.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OverlayPlan {
    /// The chosen links, each canonical `(a, b)` with `a <= b`, in the order added.
    pub links: Vec<(String, String)>,
    /// Sum of the chosen links' costs.
    pub total_cost: u64,
    /// `true` iff every agent is reachable in the result (a spanning tree exists over the
    /// candidates); `false` means the candidates leave the overlay partitioned — the
    /// operator must allow/measure more links to fully connect it.
    pub connected: bool,
}

/// A minimal union-find (disjoint-set) with path compression + union by size.
struct DisjointSet {
    parent: Vec<usize>,
    size: Vec<usize>,
}

impl DisjointSet {
    fn new(n: usize) -> Self {
        Self { parent: (0..n).collect(), size: vec![1; n] }
    }

    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]]; // path halving
            x = self.parent[x];
        }
        x
    }

    /// Union `x` and `y`; returns `true` if they were in different sets (an edge that
    /// reduces the component count — i.e. one the spanning tree keeps).
    fn union(&mut self, x: usize, y: usize) -> bool {
        let (rx, ry) = (self.find(x), self.find(y));
        if rx == ry {
            return false;
        }
        let (big, small) = if self.size[rx] >= self.size[ry] { (rx, ry) } else { (ry, rx) };
        self.parent[small] = big;
        self.size[big] += self.size[small];
        true
    }
}

/// Canonicalize an unordered link `(a, b)` so `a <= b`.
fn canon(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

/// Compute the minimum-latency connected overlay over `nodes` using the candidate
/// `links` (each an allowed pair + its measured latency): a minimum spanning tree via
/// Kruskal's algorithm with union-find, for arbitrary N (#107). Deterministic — links are
/// considered in ascending `(cost, canonical-pair)` order, so ties resolve stably.
///
/// A link whose endpoint is not in `nodes`, or a self-loop, is ignored. If the candidates
/// cannot span all nodes the result is the minimum spanning **forest** found so far with
/// `connected = false`. An empty or single-node network is trivially `connected` with no
/// links.
pub fn min_latency_overlay(nodes: &[String], links: &[WeightedLink]) -> OverlayPlan {
    // Map node ids to dense indices; ignore links that reference an unknown node.
    let index: std::collections::HashMap<&str, usize> =
        nodes.iter().enumerate().map(|(i, n)| (n.as_str(), i)).collect();

    // Sort candidate links by (cost, canonical pair) for a deterministic MST.
    let mut sorted: Vec<(u64, String, String, usize, usize)> = links
        .iter()
        .filter_map(|l| {
            if l.a == l.b {
                return None; // self-loop
            }
            let (ia, ib) = (*index.get(l.a.as_str())?, *index.get(l.b.as_str())?);
            let (ca, cb) = canon(&l.a, &l.b);
            Some((l.cost, ca, cb, ia, ib))
        })
        .collect();
    sorted.sort_by(|x, y| (x.0, &x.1, &x.2).cmp(&(y.0, &y.1, &y.2)));

    let mut ds = DisjointSet::new(nodes.len());
    let mut plan = OverlayPlan::default();
    for (cost, ca, cb, ia, ib) in sorted {
        if ds.union(ia, ib) {
            plan.links.push((ca, cb));
            plan.total_cost = plan.total_cost.saturating_add(cost);
            if plan.links.len() == nodes.len().saturating_sub(1) {
                break; // a spanning tree is complete
            }
        }
    }
    plan.connected = plan.links.len() == nodes.len().saturating_sub(1);
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn mst_minimizes_total_latency_and_connects_all_nodes() {
        // Classic 4-node MST: the cheapest spanning tree is a-b(1), b-c(2), a-d(3) = 6,
        // dropping the pricier c-d(4) and a-c(5).
        let ns = nodes(&["a", "b", "c", "d"]);
        let links = vec![
            WeightedLink::new("a", "b", 1),
            WeightedLink::new("b", "c", 2),
            WeightedLink::new("a", "d", 3),
            WeightedLink::new("c", "d", 4),
            WeightedLink::new("a", "c", 5),
        ];
        let plan = min_latency_overlay(&ns, &links);
        assert!(plan.connected, "all nodes reachable");
        assert_eq!(plan.links.len(), 3, "N-1 links");
        assert_eq!(plan.total_cost, 6, "minimum total latency");
        assert_eq!(
            plan.links,
            vec![("a".into(), "b".into()), ("b".into(), "c".into()), ("a".into(), "d".into())],
            "the three cheapest tree links, in ascending cost order"
        );
    }

    #[test]
    fn a_partitioned_candidate_set_reports_not_connected() {
        // {a,b} and {c,d} are each linked but nothing bridges the two components.
        let ns = nodes(&["a", "b", "c", "d"]);
        let links = vec![WeightedLink::new("a", "b", 1), WeightedLink::new("c", "d", 1)];
        let plan = min_latency_overlay(&ns, &links);
        assert!(!plan.connected, "candidates can't span all nodes");
        assert_eq!(plan.links.len(), 2, "the spanning forest is kept");
        assert_eq!(plan.total_cost, 2);
    }

    #[test]
    fn ties_and_unordered_or_bad_links_are_handled_deterministically() {
        // Reversed endpoints canonicalize; a self-loop and an unknown-node link are
        // ignored; equal costs break ties by the canonical pair (a-b before a-c).
        let ns = nodes(&["a", "b", "c"]);
        let links = vec![
            WeightedLink::new("b", "a", 5),      // reversed -> (a,b)
            WeightedLink::new("a", "c", 5),      // same cost -> tie
            WeightedLink::new("a", "a", 1),      // self-loop -> ignored
            WeightedLink::new("a", "ghost", 0),  // unknown node -> ignored
        ];
        let plan = min_latency_overlay(&ns, &links);
        assert!(plan.connected);
        assert_eq!(plan.links, vec![("a".into(), "b".into()), ("a".into(), "c".into())], "tie broken by pair");
        assert_eq!(plan.total_cost, 10);
    }

    #[test]
    fn trivial_networks_are_connected_with_no_links() {
        assert_eq!(min_latency_overlay(&[], &[]), OverlayPlan { links: vec![], total_cost: 0, connected: true });
        let one = min_latency_overlay(&nodes(&["solo"]), &[]);
        assert!(one.connected && one.links.is_empty(), "a single agent needs no links");
    }

    #[test]
    fn overlay_plan_round_trips_through_serde() {
        let plan = min_latency_overlay(&nodes(&["a", "b", "c"]), &[
            WeightedLink::new("a", "b", 2),
            WeightedLink::new("b", "c", 3),
        ]);
        let json = serde_json::to_string(&plan).unwrap();
        assert_eq!(serde_json::from_str::<OverlayPlan>(&json).unwrap(), plan);
    }
}
