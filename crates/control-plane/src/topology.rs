//! Topology Editor domain logic (#107) — the exclusive agent-to-topology assignment.
//!
//! The Topology Editor lets a user compose an overlay network by wiring agents (their
//! own, or ones shared to them) into a topology. This module is the pure core of the
//! one constraint the issue calls out as **genuinely new — no prior art in the repo**:
//!
//! > an agent belongs to **at most one** topology at a time; once shared into a
//! > topology, the sharing can only be **revoked, not reassigned**.
//!
//! That is a small state machine — `unassigned → assigned-to-topology-X → revoked →
//! unassigned` — modelled here as [`AgentAssignment`], separate from any storage (the
//! durable `SqliteTopologyStore` wraps it later, like `accounts::Ledger` ↔
//! `storage::SqliteLedger`). Keeping it pure means the exclusivity + ownership rules
//! are exhaustively unit-tested before the schema, REST surface, N-way rendezvous, or
//! UI (each its own follow packet) exist.
//!
//! **Chosen interpretation of an open question in #107** (revocation mechanics):
//! revoking returns control to the agent's **original owner** — the agent becomes
//! reassignable only by that owner (who may then re-share it), *not* free-for-all
//! claimable by any other topology. The issue notes its phrasing implies this; it is
//! adopted here as the safe default and flagged for scimbe to confirm. Either the
//! owner (reclaim) or the assigned topology (release) may trigger the revocation.

use serde::{Deserialize, Serialize};

/// Why an assignment transition was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssignError {
    /// Exclusivity violation: the agent is already in a topology and must be revoked
    /// before it can join another.
    AlreadyAssigned { topology: String },
    /// A revoke was attempted while the agent is not assigned to any topology.
    NotAssigned,
    /// The caller is neither the agent's owner nor (for revoke) its current topology.
    NotAuthorized,
}

impl std::fmt::Display for AssignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssignError::AlreadyAssigned { topology } => {
                write!(f, "agent already assigned to topology {topology} (revoke first)")
            }
            AssignError::NotAssigned => write!(f, "agent is not assigned to any topology"),
            AssignError::NotAuthorized => write!(f, "caller may not change this assignment"),
        }
    }
}

impl std::error::Error for AssignError {}

/// The assignment state of one agent: its owning subject and, if shared, the single
/// topology it currently belongs to. Enforces exclusivity (at most one topology) and
/// owner-scoped control (#107).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAssignment {
    /// The subject that owns this agent (never changes here — ownership is separate
    /// from topology membership).
    owner: String,
    /// The topology the agent is currently shared into, or `None` when unassigned.
    topology: Option<String>,
}

impl AgentAssignment {
    /// A freshly-owned, unassigned agent.
    pub fn new(owner: impl Into<String>) -> Self {
        Self { owner: owner.into(), topology: None }
    }

    /// The owning subject.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The topology the agent is assigned to, if any.
    pub fn topology(&self) -> Option<&str> {
        self.topology.as_deref()
    }

    /// Whether the agent is currently in a topology.
    pub fn is_assigned(&self) -> bool {
        self.topology.is_some()
    }

    /// Share the agent into `topology`. Only the **owner** may assign, and only when
    /// the agent is unassigned — an already-assigned agent must be
    /// [`revoke`](Self::revoke)d first (exclusivity: at most one topology at a time).
    pub fn assign(&mut self, by: &str, topology: impl Into<String>) -> Result<(), AssignError> {
        if by != self.owner {
            return Err(AssignError::NotAuthorized);
        }
        if let Some(existing) = &self.topology {
            return Err(AssignError::AlreadyAssigned { topology: existing.clone() });
        }
        self.topology = Some(topology.into());
        Ok(())
    }

    /// End the current sharing, returning the agent to its owner's control (unassigned).
    /// Either the **owner** (reclaim) or the **current topology** (release) may revoke;
    /// no one else. Sharing can only be revoked, never reassigned — a new assignment is
    /// a separate [`assign`](Self::assign) by the owner afterwards. Errors with
    /// [`AssignError::NotAssigned`] if the agent is not in any topology.
    pub fn revoke(&mut self, by: &str) -> Result<(), AssignError> {
        let current = self.topology.as_deref().ok_or(AssignError::NotAssigned)?;
        if by != self.owner && by != current {
            return Err(AssignError::NotAuthorized);
        }
        self.topology = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_agent_is_owned_and_unassigned() {
        let a = AgentAssignment::new("alice");
        assert_eq!(a.owner(), "alice");
        assert!(!a.is_assigned());
        assert_eq!(a.topology(), None);
    }

    #[test]
    fn only_the_owner_may_assign_and_exclusivity_is_enforced() {
        let mut a = AgentAssignment::new("alice");

        // A non-owner cannot share the agent.
        assert_eq!(a.assign("mallory", "net-1"), Err(AssignError::NotAuthorized));
        assert!(!a.is_assigned(), "a rejected assign leaves the agent unassigned");

        // The owner shares it into a topology.
        assert!(a.assign("alice", "net-1").is_ok());
        assert_eq!(a.topology(), Some("net-1"));

        // Exclusivity: it cannot join a second topology while assigned.
        assert_eq!(
            a.assign("alice", "net-2"),
            Err(AssignError::AlreadyAssigned { topology: "net-1".into() }),
            "an agent belongs to at most one topology at a time"
        );
        assert_eq!(a.topology(), Some("net-1"), "the failed assign didn't move it");
    }

    #[test]
    fn revoke_returns_control_to_the_owner_and_only_then_can_it_be_reassigned() {
        let mut a = AgentAssignment::new("alice");
        a.assign("alice", "net-1").unwrap();

        // A stranger can neither revoke nor reassign.
        assert_eq!(a.revoke("mallory"), Err(AssignError::NotAuthorized));

        // The current topology may release it (revoke), OR the owner may reclaim it.
        assert!(a.revoke("net-1").is_ok(), "the assigned topology may release the agent");
        assert!(!a.is_assigned(), "revocation returns the agent to its owner (unassigned)");

        // Sharing can only be revoked, not reassigned: a *new* assignment is a fresh
        // owner action — and now that it's unassigned, the owner can share it again.
        assert!(a.assign("alice", "net-2").is_ok(), "owner reassigns after revoke");
        assert_eq!(a.topology(), Some("net-2"));

        // The owner can also reclaim (revoke) their own agent.
        assert!(a.revoke("alice").is_ok());
        assert!(!a.is_assigned());
    }

    #[test]
    fn revoking_an_unassigned_agent_is_an_error() {
        let mut a = AgentAssignment::new("alice");
        assert_eq!(a.revoke("alice"), Err(AssignError::NotAssigned));
    }

    #[test]
    fn assignment_round_trips_through_serde() {
        let mut a = AgentAssignment::new("alice");
        a.assign("alice", "net-1").unwrap();
        let json = serde_json::to_string(&a).unwrap();
        let back: AgentAssignment = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back, "assignment state survives a JSON round-trip (REST surface)");
    }
}
