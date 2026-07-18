//! Policy decision engine for the intent-/policy-driven mesh control plane (#102).
//!
//! A pure, wire-serializable **RBAC + MAC** (label flow-control) evaluator. Given a
//! declarative [`Policy`] — ordered security levels, default-deny allow-rules, and an
//! optional mandatory no-write-down constraint — and two agents, it decides whether
//! `from` may establish a directed flow to `to`, with a human/AI-legible reason.
//!
//! This is the SDN-style control plane's core, independent of the live mesh: the
//! controller compiles a declaration into channel grants from it, the edge broker
//! enforces it at channel admission (#81/#99), and the MCP `net.explain(a, b)` tool
//! renders its [`Decision`]. Two access-control models compose, matching the locked
//! design in #102:
//!
//! * **RBAC** (discretionary): default-deny — a flow is permitted only if at least one
//!   [`AllowRule`] matches the `(from, to)` pair by group and/or label.
//! * **MAC** (mandatory, non-discretionary): when [`Policy::mac_flow_control`] is on,
//!   a Bell–LaPadula **no-write-down** rule overrides RBAC — a higher-level `from` may
//!   never initiate a flow to a lower-level `to`, so sensitive data cannot leak down a
//!   level even if an allow-rule would otherwise permit it.

use serde::{Deserialize, Serialize};

/// An agent's policy attributes: its RBAC `group` and its security `label`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Agent {
    /// Stable agent id (for reasons/audit).
    pub id: String,
    /// RBAC group / role (e.g. `dev`, `ops`, `finance`).
    pub group: String,
    /// Security label; must appear in [`Levels`] when MAC is enforced.
    pub label: String,
}

impl Agent {
    /// Convenience constructor.
    pub fn new(id: impl Into<String>, group: impl Into<String>, label: impl Into<String>) -> Self {
        Self { id: id.into(), group: group.into(), label: label.into() }
    }
}

/// Ordered security levels, least→most sensitive (e.g. `public < internal < secret`).
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Levels {
    /// Labels in ascending sensitivity; index is the rank.
    pub order: Vec<String>,
}

impl Levels {
    /// Build from an ordered (least→most sensitive) list of labels.
    pub fn new<I, S>(order: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self { order: order.into_iter().map(Into::into).collect() }
    }

    /// The rank of `label` (0 = least sensitive), or `None` if it is not a known level.
    pub fn rank(&self, label: &str) -> Option<usize> {
        self.order.iter().position(|l| l == label)
    }
}

/// Selects a set of agents by (optionally) group and/or label. A `None` field matches
/// any value; an all-`None` selector matches every agent.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Selector {
    /// Match this RBAC group, or any group when `None`.
    #[serde(default)]
    pub group: Option<String>,
    /// Match this security label, or any label when `None`.
    #[serde(default)]
    pub label: Option<String>,
}

impl Selector {
    /// A selector matching every agent (both fields unconstrained).
    pub fn any() -> Self {
        Self::default()
    }

    /// A selector matching a group (any label).
    pub fn group(group: impl Into<String>) -> Self {
        Self { group: Some(group.into()), label: None }
    }

    fn matches(&self, a: &Agent) -> bool {
        self.group.as_ref().map_or(true, |g| g == &a.group)
            && self.label.as_ref().map_or(true, |l| l == &a.label)
    }
}

/// A default-deny **allow-rule**: agents matching `from` may initiate a directed flow
/// to agents matching `to`. Absent any matching rule, the flow is denied.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowRule {
    pub from: Selector,
    pub to: Selector,
}

/// A network's declarative policy (#102): ordered security levels, default-deny
/// allow-rules, and whether the mandatory no-write-down flow constraint is enforced.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Policy {
    /// Ordered security levels; only consulted when `mac_flow_control` is on.
    #[serde(default)]
    pub levels: Levels,
    /// Default-deny allow-rules (RBAC). A flow needs at least one match.
    #[serde(default)]
    pub rules: Vec<AllowRule>,
    /// Enforce Bell–LaPadula no-write-down on `levels`: a higher-level `from` may not
    /// initiate a flow to a lower-level `to` (mandatory — overrides the allow-rules).
    #[serde(default)]
    pub mac_flow_control: bool,
}

/// The outcome of a policy check: allow/deny + a human/AI-legible reason (rendered by
/// the MCP `net.explain` tool and used in the broker's `NO <reason>` refusal).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
}

impl Decision {
    fn deny(reason: String) -> Self {
        Self { allowed: false, reason }
    }
    fn allow(reason: String) -> Self {
        Self { allowed: true, reason }
    }
}

impl Policy {
    /// Decide whether `from` may establish a **directed** flow to `to`.
    ///
    /// Mandatory access control is checked first and overrides RBAC: with
    /// `mac_flow_control` on, a write-down (`rank(from) > rank(to)`) is denied even if
    /// an allow-rule matches, and an unknown label fails closed. Otherwise the flow is
    /// allowed iff at least one [`AllowRule`] matches (default-deny).
    pub fn evaluate(&self, from: &Agent, to: &Agent) -> Decision {
        if self.mac_flow_control {
            match (self.levels.rank(&from.label), self.levels.rank(&to.label)) {
                (Some(rf), Some(rt)) => {
                    if rf > rt {
                        return Decision::deny(format!(
                            "MAC write-down blocked: {} ({}) may not initiate a flow to lower level {} ({})",
                            from.id, from.label, to.id, to.label
                        ));
                    }
                }
                _ => {
                    return Decision::deny(format!(
                        "MAC enabled but a label is not a known level (from={}, to={})",
                        from.label, to.label
                    ));
                }
            }
        }
        if self.rules.iter().any(|r| r.from.matches(from) && r.to.matches(to)) {
            Decision::allow(format!(
                "allowed: an allow-rule permits {} ({}/{}) -> {} ({}/{})",
                from.id, from.group, from.label, to.id, to.group, to.label
            ))
        } else {
            Decision::deny(format!(
                "default-deny: no allow-rule permits {} ({}/{}) -> {} ({}/{})",
                from.id, from.group, from.label, to.id, to.group, to.label
            ))
        }
    }

    /// Decide whether `a` and `b` may **establish a channel** — a bidirectional flow,
    /// so it is permitted only if the directed flow is allowed **both** ways. Returns
    /// the first-denied direction's [`Decision`] (so the reason names the actual
    /// blocker), else an allow. This is the check the edge broker applies at channel
    /// admission (a cross-level pair is refused because one direction is a write-down).
    pub fn may_establish_channel(&self, a: &Agent, b: &Agent) -> Decision {
        let ab = self.evaluate(a, b);
        if !ab.allowed {
            return ab;
        }
        let ba = self.evaluate(b, a);
        if !ba.allowed {
            return ba;
        }
        Decision::allow(format!("allowed: {} and {} may establish a channel (both directions permitted)", a.id, b.id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The "verteilte Firma" fixture from #102: segments dev/ops/finance at levels
    /// internal/secret, default-deny with a small allow-list and MAC on.
    fn company_policy() -> Policy {
        Policy {
            levels: Levels::new(["public", "internal", "secret"]),
            rules: vec![
                // dev may talk within dev and out to ops; finance may talk within finance.
                AllowRule { from: Selector::group("dev"), to: Selector::group("dev") },
                AllowRule { from: Selector::group("dev"), to: Selector::group("ops") },
                AllowRule { from: Selector::group("ops"), to: Selector::group("dev") },
                AllowRule { from: Selector::group("finance"), to: Selector::group("finance") },
            ],
            mac_flow_control: true,
        }
    }

    #[test]
    fn rbac_allows_a_permitted_pair_and_default_denies_the_rest() {
        let p = company_policy();
        let dev = Agent::new("dev-1", "dev", "internal");
        let ops = Agent::new("ops-1", "ops", "internal");
        let fin = Agent::new("fin-1", "finance", "internal");

        // An allow-rule permits dev -> ops (same level, so MAC is satisfied).
        let d = p.evaluate(&dev, &ops);
        assert!(d.allowed, "dev->ops permitted: {}", d.reason);

        // No rule permits dev -> finance: default-deny.
        let d = p.evaluate(&dev, &fin);
        assert!(!d.allowed, "dev->finance must be default-denied");
        assert!(d.reason.contains("default-deny"), "reason: {}", d.reason);
    }

    #[test]
    fn mac_blocks_write_down_but_allows_write_up_even_with_a_matching_rule() {
        let p = company_policy();
        let fin_secret = Agent::new("fin-s", "finance", "secret");
        let fin_internal = Agent::new("fin-i", "finance", "internal");

        // finance->finance rule matches BOTH ways, but MAC overrides:
        // secret -> internal is a write-down -> denied.
        let down = p.evaluate(&fin_secret, &fin_internal);
        assert!(!down.allowed, "write-down must be blocked despite the allow-rule");
        assert!(down.reason.contains("write-down"), "reason: {}", down.reason);

        // internal -> secret is a write-up -> allowed (rule matches, MAC satisfied).
        let up = p.evaluate(&fin_internal, &fin_secret);
        assert!(up.allowed, "write-up permitted: {}", up.reason);
    }

    #[test]
    fn mac_fails_closed_on_an_unknown_label() {
        let p = company_policy();
        let known = Agent::new("a", "dev", "internal");
        let unknown = Agent::new("b", "dev", "top-secret"); // not in the level order
        let d = p.evaluate(&known, &unknown);
        assert!(!d.allowed && d.reason.contains("not a known level"), "reason: {}", d.reason);
    }

    #[test]
    fn channel_establishment_needs_both_directions_and_refuses_cross_level() {
        let p = company_policy();
        let dev1 = Agent::new("dev-1", "dev", "internal");
        let dev2 = Agent::new("dev-2", "dev", "internal");
        let ops = Agent::new("ops-1", "ops", "internal");
        let fin_i = Agent::new("fin-i", "finance", "internal");
        let fin_s = Agent::new("fin-s", "finance", "secret");

        // Same group + level, rule both ways -> a channel forms.
        assert!(p.may_establish_channel(&dev1, &dev2).allowed, "dev<->dev channel allowed");
        // dev<->ops: rules exist both ways (dev->ops, ops->dev), same level -> allowed.
        assert!(p.may_establish_channel(&dev1, &ops).allowed, "dev<->ops channel allowed");
        // finance internal<->secret: one direction is a write-down -> channel refused.
        let d = p.may_establish_channel(&fin_i, &fin_s);
        assert!(!d.allowed && d.reason.contains("write-down"), "cross-level channel refused: {}", d.reason);
        // dev<->finance: no rule at all -> refused.
        assert!(!p.may_establish_channel(&dev1, &fin_i).allowed, "dev<->finance channel refused");
    }

    #[test]
    fn policy_round_trips_through_serde() {
        let p = company_policy();
        let json = serde_json::to_string(&p).unwrap();
        let back: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back, "policy survives a JSON round-trip (REST/OpenAPI surface)");
    }
}
