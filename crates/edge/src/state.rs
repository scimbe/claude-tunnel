//! Edge routing state (M5.1b).
//!
//! Maps a Routing Token to the Agent tunnel handle that serves it, so the Edge
//! can route a resolved Client rendezvous to the right Agent connection. Generic
//! over the handle type (`quinn::Connection` in the daemon) to stay
//! unit-testable. `is_known` plugs straight into `resolve_rendezvous_gated`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

use ct_common::RoutingToken;

/// Thread-safe registry of live Agent tunnels keyed by Routing Token, plus each
/// Agent's Edge-observed peer candidate (its reflexive address) for P2P
/// rendezvous (M11.1).
pub struct EdgeState<H> {
    agents: Mutex<HashMap<RoutingToken, H>>,
    candidates: Mutex<HashMap<RoutingToken, SocketAddr>>,
}

impl<H: Clone> EdgeState<H> {
    pub fn new() -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
            candidates: Mutex::new(HashMap::new()),
        }
    }

    /// Register (or replace) the Agent tunnel serving `token`.
    pub fn register(&self, token: RoutingToken, handle: H) {
        self.agents.lock().unwrap().insert(token, handle);
    }

    /// Register the Agent tunnel and record its Edge-observed peer candidate —
    /// the reflexive address a Client will hole-punch toward (M11.1).
    pub fn register_with_candidate(&self, token: RoutingToken, handle: H, candidate: SocketAddr) {
        self.candidates.lock().unwrap().insert(token.clone(), candidate);
        self.register(token, handle);
    }

    /// The Agent's Edge-observed peer candidate for `token`, if recorded.
    pub fn candidate(&self, token: &RoutingToken) -> Option<SocketAddr> {
        self.candidates.lock().unwrap().get(token).copied()
    }

    /// Route `token` to its Agent tunnel handle, if registered.
    pub fn route(&self, token: &RoutingToken) -> Option<H> {
        self.agents.lock().unwrap().get(token).cloned()
    }

    /// Remove the Agent tunnel (and its candidate) for `token`.
    pub fn remove(&self, token: &RoutingToken) {
        self.agents.lock().unwrap().remove(token);
        self.candidates.lock().unwrap().remove(token);
    }

    /// Whether `token` currently has a live Agent tunnel.
    pub fn is_known(&self, token: &RoutingToken) -> bool {
        self.agents.lock().unwrap().contains_key(token)
    }
}

impl<H: Clone> Default for EdgeState<H> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(b: u8) -> RoutingToken {
        RoutingToken([b; 32])
    }

    #[test]
    fn register_then_route() {
        let state = EdgeState::new();
        state.register(token(1), 42u32);
        assert_eq!(state.route(&token(1)), Some(42));
        assert!(state.is_known(&token(1)));
    }

    #[test]
    fn route_unknown_is_none() {
        let state: EdgeState<u32> = EdgeState::new();
        assert_eq!(state.route(&token(9)), None);
        assert!(!state.is_known(&token(9)));
    }

    #[test]
    fn remove_drops_route() {
        let state = EdgeState::new();
        state.register(token(1), 42u32);
        state.remove(&token(1));
        assert_eq!(state.route(&token(1)), None);
        assert!(!state.is_known(&token(1)));
    }

    #[test]
    fn register_with_candidate_records_and_routes() {
        let state = EdgeState::new();
        let cand: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
        state.register_with_candidate(token(2), 7u32, cand);
        assert_eq!(state.route(&token(2)), Some(7), "handle routable");
        assert_eq!(state.candidate(&token(2)), Some(cand), "candidate recorded");
    }

    #[test]
    fn candidate_unknown_is_none() {
        let state: EdgeState<u32> = EdgeState::new();
        assert_eq!(state.candidate(&token(9)), None);
    }

    #[test]
    fn remove_drops_candidate() {
        let state = EdgeState::new();
        let cand: std::net::SocketAddr = "198.51.100.4:4433".parse().unwrap();
        state.register_with_candidate(token(3), 1u32, cand);
        state.remove(&token(3));
        assert_eq!(state.candidate(&token(3)), None);
    }
}
