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

/// Extend an overlay `base` (typically a [`min_latency_overlay`] spanning tree) with up
/// to `budget` latency-reducing **shortcut** links beyond the tree backbone (#107 /
/// #76's smart-shortcuts topology). Greedy + deterministic: each round adds the candidate
/// link — not already chosen — that most reduces the overlay's **worst pairwise path
/// latency** (the two agents currently farthest apart get a direct link), until the
/// budget is spent or no remaining candidate shortens any path. Pure; ties broken by the
/// canonical pair. The tree keeps the graph connected, so shortcuts only ever *reduce*
/// path latency — they never disconnect it.
pub fn add_shortcuts(
    nodes: &[String],
    links: &[WeightedLink],
    base: OverlayPlan,
    budget: usize,
) -> OverlayPlan {
    let n = nodes.len();
    if n < 2 || budget == 0 {
        return base;
    }
    let index: std::collections::HashMap<&str, usize> =
        nodes.iter().enumerate().map(|(i, x)| (x.as_str(), i)).collect();

    // Cheapest candidate cost per canonical pair (ignore self-loops / unknown nodes).
    let mut cost: std::collections::HashMap<(usize, usize), u64> = std::collections::HashMap::new();
    for l in links {
        if l.a == l.b {
            continue;
        }
        let (ia, ib) = match (index.get(l.a.as_str()), index.get(l.b.as_str())) {
            (Some(&ia), Some(&ib)) => (ia.min(ib), ia.max(ib)),
            _ => continue,
        };
        cost.entry((ia, ib)).and_modify(|c| *c = (*c).min(l.cost)).or_insert(l.cost);
    }

    let mut chosen: std::collections::HashSet<(usize, usize)> = base
        .links
        .iter()
        .filter_map(|(a, b)| Some((*index.get(a.as_str())?, *index.get(b.as_str())?)))
        .map(|(a, b)| (a.min(b), a.max(b)))
        .collect();

    let inf = u64::MAX / 4;
    let mut plan = base;
    for _ in 0..budget {
        // All-pairs shortest paths over the currently-chosen links (Floyd–Warshall).
        let mut dist = vec![vec![inf; n]; n];
        for (d, di) in dist.iter_mut().enumerate() {
            di[d] = 0;
        }
        for &(a, b) in &chosen {
            let c = cost[&(a, b)];
            dist[a][b] = dist[a][b].min(c);
            dist[b][a] = dist[b][a].min(c);
        }
        for k in 0..n {
            for i in 0..n {
                if dist[i][k] == inf {
                    continue;
                }
                for j in 0..n {
                    let via = dist[i][k].saturating_add(dist[k][j]);
                    if via < dist[i][j] {
                        dist[i][j] = via;
                    }
                }
            }
        }
        // Pick the candidate link that most reduces its endpoints' current path latency.
        let mut best: Option<((usize, usize), u64)> = None;
        for (&(a, b), &c) in &cost {
            if chosen.contains(&(a, b)) {
                continue;
            }
            let improvement = dist[a][b].saturating_sub(c);
            if improvement == 0 {
                continue;
            }
            // Deterministic: max improvement, ties broken by the smaller (a, b) pair
            // (the HashMap iteration order is otherwise unspecified).
            let better = match best {
                None => true,
                Some((pair, bi)) => improvement > bi || (improvement == bi && (a, b) < pair),
            };
            if better {
                best = Some(((a, b), improvement));
            }
        }
        match best {
            Some(((a, b), _)) => {
                chosen.insert((a, b));
                let (ca, cb) = canon(&nodes[a], &nodes[b]);
                plan.links.push((ca, cb));
                plan.total_cost = plan.total_cost.saturating_add(cost[&(a, b)]);
            }
            None => break, // no shortcut improves any path
        }
    }
    plan
}

/// Compile a [`Network`](crate::policy::Network) into the concrete overlay to wire (#107
/// controller step): the candidate links are exactly the pairs the network's **policy
/// permits** ([`crate::policy::Network::desired_channels`]), each weighted by its
/// **measured latency** from `latency(a, b)`; the result is the two-phase optimizer's plan
/// — the MST backbone plus up to `shortcut_budget` latency-reducing shortcuts. A pair with
/// no measured latency is dropped (an unmeasured link can't be wired). Policy-forbidden
/// pairs are never candidates, so the plan is always policy-conformant by construction.
/// Pure given `latency`; the controller then compiles each returned link into an A2A
/// channel grant (the per-link grant minting + live establishment is a follow).
pub fn plan_network_overlay<F>(
    network: &crate::policy::Network,
    mut latency: F,
    shortcut_budget: usize,
) -> OverlayPlan
where
    F: FnMut(&str, &str) -> Option<u64>,
{
    let nodes: Vec<String> = network.agents.iter().map(|a| a.id.clone()).collect();
    let links: Vec<WeightedLink> = network
        .desired_channels()
        .into_iter()
        .filter_map(|p| latency(&p.0, &p.1).map(|c| WeightedLink::new(p.0, p.1, c)))
        .collect();
    let base = min_latency_overlay(&nodes, &links);
    add_shortcuts(&nodes, &links, base, shortcut_budget)
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
    fn shortcuts_cut_the_worst_path_latency_within_budget() {
        // Line a-b-c-d (each hop cost 1): the MST is that line (cost 3), so a<->d costs 3
        // over it. A direct a-d candidate of cost 2 is skipped by the MST (the three cost-1
        // hops span first) but is a genuine shortcut (2 < the 3-hop path).
        let ns = nodes(&["a", "b", "c", "d"]);
        let links = vec![
            WeightedLink::new("a", "b", 1),
            WeightedLink::new("b", "c", 1),
            WeightedLink::new("c", "d", 1),
            WeightedLink::new("a", "d", 2), // shortcut across the ends: dearer than a hop, cheaper than the path
        ];
        let base = min_latency_overlay(&ns, &links);
        assert_eq!(base.links.len(), 3, "MST is the line (a-d not needed for connectivity)");
        assert!(!base.links.contains(&("a".to_string(), "d".to_string())), "the line MST excludes a-d");

        // Budget 1 adds the highest-improvement shortcut: a-d (path 3 -> direct 2).
        let one = add_shortcuts(&ns, &links, base.clone(), 1);
        assert_eq!(one.links.len(), 4, "one shortcut added");
        assert!(one.links.contains(&("a".to_string(), "d".to_string())), "the a-d shortcut");
        assert_eq!(one.total_cost, base.total_cost + 2);

        // Budget 0 is a no-op; a huge budget adds no more once no path improves.
        assert_eq!(add_shortcuts(&ns, &links, base.clone(), 0), base, "budget 0 -> unchanged");
        let maxed = add_shortcuts(&ns, &links, base.clone(), 100);
        assert_eq!(maxed.links.len(), 4, "only the improving shortcut is added, then it stops");
    }

    #[test]
    fn shortcuts_are_a_noop_when_no_candidate_improves_a_path() {
        // A triangle where every pair is already a direct MST/base edge -> no shortcut helps.
        let ns = nodes(&["a", "b", "c"]);
        let links = vec![WeightedLink::new("a", "b", 1), WeightedLink::new("b", "c", 1)];
        let base = min_latency_overlay(&ns, &links); // a-b, b-c
        // Only candidate not chosen would be... none improving (no a-c candidate exists).
        let out = add_shortcuts(&ns, &links, base.clone(), 5);
        assert_eq!(out, base, "no improving candidate -> unchanged");
    }

    #[test]
    fn plan_network_overlay_wires_only_policy_permitted_links_by_latency() {
        use crate::policy::{Agent, AllowRule, Levels, Network, Policy, Selector};

        // dev + ops may connect (both ways, same level); finance is isolated by policy.
        let net = Network {
            agents: vec![
                Agent::new("dev-1", "dev", "internal"),
                Agent::new("dev-2", "dev", "internal"),
                Agent::new("ops-1", "ops", "internal"),
                Agent::new("fin-1", "finance", "internal"),
            ],
            policy: Policy {
                levels: Levels::new(["public", "internal", "secret"]),
                rules: vec![
                    AllowRule { from: Selector::group("dev"), to: Selector::group("dev") },
                    AllowRule { from: Selector::group("dev"), to: Selector::group("ops") },
                    AllowRule { from: Selector::group("ops"), to: Selector::group("dev") },
                ],
                mac_flow_control: true,
            },
        };
        // Measured latencies (symmetric); finance links are permitted by NO policy rule,
        // so they never become candidates even though we'd "measure" them.
        let lat = |a: &str, b: &str| -> Option<u64> {
            let (x, y) = if a <= b { (a, b) } else { (b, a) };
            match (x, y) {
                ("dev-1", "dev-2") => Some(1),
                ("dev-1", "ops-1") => Some(2),
                ("dev-2", "ops-1") => Some(3),
                _ => Some(9), // e.g. any finance pair — but policy excludes them upstream
            }
        };

        // No shortcuts: the MST over the 3 permitted dev/ops links (1,2,3) = {dev1-dev2,
        // dev1-ops1}, total 3, and fin-1 is left unconnected (policy isolates it).
        let plan = plan_network_overlay(&net, lat, 0);
        assert_eq!(
            plan.links,
            vec![("dev-1".into(), "dev-2".into()), ("dev-1".into(), "ops-1".into())]
        );
        assert_eq!(plan.total_cost, 3);
        assert!(!plan.connected, "fin-1 is policy-isolated, so the overlay can't span it");
        // No finance link ever appears — the plan is policy-conformant by construction.
        assert!(!plan.links.iter().any(|(a, b)| a.starts_with("fin") || b.starts_with("fin")));

        // Here the only unchosen candidate (dev2-ops1, cost 3) equals its current path
        // latency (dev2-dev1-ops1 = 3), so no shortcut improves anything and a budget adds
        // nothing — assert the plan never regresses (shortcuts only ever add links).
        let with_budget = plan_network_overlay(&net, lat, 5);
        assert!(with_budget.links.len() >= plan.links.len(), "shortcuts never drop links");
        assert_eq!(with_budget.links.len(), 2, "no candidate improves a path -> no shortcut");
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
