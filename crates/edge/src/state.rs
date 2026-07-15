//! Edge routing state (M5.1b).
//!
//! Maps a Routing Token to the Agent tunnel handle that serves it, so the Edge
//! can route a resolved Client rendezvous to the right Agent connection. Generic
//! over the handle type (`quinn::Connection` in the daemon) to stay
//! unit-testable. `is_known` plugs straight into `resolve_rendezvous_gated`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use ct_common::RoutingToken;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

/// A boxed bidirectional byte stream — the concrete handoff type for a
/// TCP-fallback agent rendezvous (issue #3 / P1.2c-3), where a single stream
/// cannot be cloned/multiplexed like a QUIC connection.
pub trait DuplexStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> DuplexStream for T {}
pub type BoxedStream = Box<dyn DuplexStream>;

/// Thread-safe registry of live Agent tunnels keyed by Routing Token, plus each
/// Agent's Edge-observed peer candidate (its reflexive address) for P2P
/// rendezvous (M11.1).
pub struct EdgeState<H> {
    /// Live Agent tunnels per token. **Multiple** Agents may register the same
    /// token for redundancy/failover (#8); each is tagged with a monotonic
    /// registration id so exactly one can be evicted when its connection drops.
    agents: Mutex<HashMap<RoutingToken, Vec<(u64, H)>>>,
    /// Source of monotonic registration ids.
    next_reg: AtomicU64,
    candidates: Mutex<HashMap<RoutingToken, SocketAddr>>,
    /// Agent-advertised direct-path listener: (address, cert DER) a Client can
    /// connect to directly, bypassing the Edge relay (M11.4b).
    direct: Mutex<HashMap<RoutingToken, (SocketAddr, Vec<u8>)>>,
    /// Parked TCP-fallback agents (issue #3 / P1.2c-3): a `token` maps to a
    /// sender the Client handler uses to hand its stream to the waiting agent.
    /// Unlike QUIC agents these are single-use (one client per registration).
    tcp_agents: Mutex<HashMap<RoutingToken, oneshot::Sender<BoxedStream>>>,
}

impl<H: Clone> EdgeState<H> {
    pub fn new() -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
            next_reg: AtomicU64::new(1),
            candidates: Mutex::new(HashMap::new()),
            direct: Mutex::new(HashMap::new()),
            tcp_agents: Mutex::new(HashMap::new()),
        }
    }

    /// Park a TCP-fallback agent for `token`: returns a receiver that resolves to
    /// a Client's stream once one rendezvouses for this token (single-tunnel).
    /// The agent then relays its own stream to the received one.
    pub fn park_tcp_agent(&self, token: RoutingToken) -> oneshot::Receiver<BoxedStream> {
        let (tx, rx) = oneshot::channel();
        self.tcp_agents.lock().unwrap().insert(token, tx);
        rx
    }

    /// Hand a Client's `stream` to a parked TCP-fallback agent for `token`.
    /// Returns the stream back as `Err` if no TCP agent is waiting (so the caller
    /// can fall through to the QUIC route), consuming the registration on success.
    pub fn deliver_to_tcp_agent(
        &self,
        token: &RoutingToken,
        stream: BoxedStream,
    ) -> Result<(), BoxedStream> {
        let tx = self.tcp_agents.lock().unwrap().remove(token);
        match tx {
            Some(tx) => tx.send(stream),
            None => Err(stream),
        }
    }

    /// Whether a TCP-fallback agent is currently parked for `token`.
    pub fn has_tcp_agent(&self, token: &RoutingToken) -> bool {
        self.tcp_agents.lock().unwrap().contains_key(token)
    }

    /// Record the Agent's advertised direct-path listener for `token` (M11.4b):
    /// the address and cert DER a Client uses to connect directly.
    pub fn advertise_direct(&self, token: RoutingToken, addr: SocketAddr, cert: Vec<u8>) {
        self.direct.lock().unwrap().insert(token, (addr, cert));
    }

    /// The Agent's advertised direct-path `(addr, cert)` for `token`, if any.
    pub fn direct_endpoint(&self, token: &RoutingToken) -> Option<(SocketAddr, Vec<u8>)> {
        self.direct.lock().unwrap().get(token).cloned()
    }

    /// Register an Agent tunnel serving `token`, returning a **registration id**.
    /// Multiple Agents may register the same token for redundancy/failover (#8);
    /// the id lets exactly this registration be evicted (via
    /// [`remove_registration`](Self::remove_registration)) when its connection
    /// drops, without disturbing the other Agents serving the token.
    pub fn register(&self, token: RoutingToken, handle: H) -> u64 {
        let id = self.next_reg.fetch_add(1, Ordering::Relaxed);
        self.agents
            .lock()
            .unwrap()
            .entry(token)
            .or_default()
            .push((id, handle));
        id
    }

    /// Register the Agent tunnel and record its Edge-observed peer candidate —
    /// the reflexive address a Client will hole-punch toward (M11.1). Returns the
    /// registration id (see [`register`](Self::register)).
    pub fn register_with_candidate(
        &self,
        token: RoutingToken,
        handle: H,
        candidate: SocketAddr,
    ) -> u64 {
        self.candidates.lock().unwrap().insert(token.clone(), candidate);
        self.register(token, handle)
    }

    /// The Agent's Edge-observed peer candidate for `token`, if recorded.
    pub fn candidate(&self, token: &RoutingToken) -> Option<SocketAddr> {
        self.candidates.lock().unwrap().get(token).copied()
    }

    /// Route `token` to a live Agent tunnel handle, if any. Returns the **most
    /// recently registered** Agent, so a reconnecting Agent is preferred over its
    /// own dying registration and, with redundant Agents (#8), the newest serves
    /// (the next takes over on its drop).
    pub fn route(&self, token: &RoutingToken) -> Option<H> {
        self.agents
            .lock()
            .unwrap()
            .get(token)
            .and_then(|v| v.last().map(|(_, h)| h.clone()))
    }

    /// All live Agent handles for `token`, **most-recently-registered first** —
    /// the failover order for the relay: try the newest, fall back to older ones
    /// if its `open_bi()` fails (#8 R2, covers the dead-but-not-yet-evicted race).
    pub fn routes(&self, token: &RoutingToken) -> Vec<H> {
        self.agents.lock().unwrap().get(token).map_or_else(Vec::new, |v| {
            v.iter().rev().map(|(_, h)| h.clone()).collect()
        })
    }

    /// Number of redundant Agent registrations currently serving `token` (#8).
    pub fn registration_count(&self, token: &RoutingToken) -> usize {
        self.agents.lock().unwrap().get(token).map_or(0, Vec::len)
    }

    /// Distinct routing tokens with at least one live Agent — the number of
    /// tunnels the Edge is currently serving (observability gauge, #10).
    pub fn active_tunnels(&self) -> usize {
        self.agents.lock().unwrap().values().filter(|v| !v.is_empty()).count()
    }

    /// Total live Agent registrations across all tokens — redundant Agents (#8)
    /// counted separately (observability gauge, #10).
    pub fn total_registrations(&self) -> usize {
        self.agents.lock().unwrap().values().map(Vec::len).sum()
    }

    /// Evict exactly the registration `id` for `token` — an Agent whose
    /// connection dropped — leaving any other redundant Agents in place (#8).
    /// The token's candidate/direct entries are cleared only when the **last**
    /// Agent for the token is gone.
    pub fn remove_registration(&self, token: &RoutingToken, id: u64) {
        let mut agents = self.agents.lock().unwrap();
        if let Some(v) = agents.get_mut(token) {
            v.retain(|(rid, _)| *rid != id);
            if v.is_empty() {
                agents.remove(token);
                drop(agents);
                self.candidates.lock().unwrap().remove(token);
                self.direct.lock().unwrap().remove(token);
            }
        }
    }

    /// Remove **all** Agent tunnels (and candidate + direct + tcp) for `token` —
    /// a full teardown, regardless of how many redundant Agents serve it.
    pub fn remove(&self, token: &RoutingToken) {
        self.agents.lock().unwrap().remove(token);
        self.candidates.lock().unwrap().remove(token);
        self.direct.lock().unwrap().remove(token);
        self.tcp_agents.lock().unwrap().remove(token);
    }

    /// Whether `token` currently has at least one live Agent tunnel.
    pub fn is_known(&self, token: &RoutingToken) -> bool {
        self.agents
            .lock()
            .unwrap()
            .get(token)
            .is_some_and(|v| !v.is_empty())
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
    fn redundant_agents_fail_over_on_registration_drop() {
        // #8 R1: two Agents register the same token; routing prefers the most
        // recent, and evicting one registration fails over to the other without
        // disturbing it — the whole point of Agent redundancy.
        let state: EdgeState<u32> = EdgeState::new();
        let t = token(1);
        let a = state.register(t.clone(), 10); // Agent A
        let b = state.register(t.clone(), 20); // Agent B (more recent)
        assert_eq!(state.registration_count(&t), 2, "both agents registered");
        assert_eq!(state.route(&t), Some(20), "most-recent agent serves");

        // Agent B's connection drops → evict just B → fail over to A.
        state.remove_registration(&t, b);
        assert_eq!(state.route(&t), Some(10), "failover to the surviving agent");
        assert_eq!(state.registration_count(&t), 1);
        assert!(state.is_known(&t), "tunnel still up on one agent");

        // Evicting an already-gone id is a no-op (idempotent).
        state.remove_registration(&t, b);
        assert_eq!(state.route(&t), Some(10));

        // Last agent drops → tunnel is gone and its metadata is cleaned up.
        state.remove_registration(&t, a);
        assert_eq!(state.route(&t), None, "no agents left");
        assert!(!state.is_known(&t));
        assert_eq!(state.registration_count(&t), 0);
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

    #[test]
    fn advertise_and_look_up_direct_endpoint() {
        let state: EdgeState<u32> = EdgeState::new();
        let addr: std::net::SocketAddr = "203.0.113.9:5000".parse().unwrap();
        state.advertise_direct(token(4), addr, vec![1, 2, 3, 4]);
        assert_eq!(state.direct_endpoint(&token(4)), Some((addr, vec![1, 2, 3, 4])));
        assert_eq!(state.direct_endpoint(&token(5)), None, "unknown → None");
    }

    #[test]
    fn remove_drops_direct_endpoint() {
        let state = EdgeState::new();
        let addr: std::net::SocketAddr = "203.0.113.9:5000".parse().unwrap();
        state.advertise_direct(token(6), addr, vec![9, 9]);
        state.register(token(6), 1u32);
        state.remove(&token(6));
        assert_eq!(state.direct_endpoint(&token(6)), None);
    }

    #[tokio::test]
    async fn tcp_agent_park_then_deliver_hands_over_the_stream() {
        // issue #3 / P1.2c-3: a parked TCP agent receives the Client's stream.
        let state: EdgeState<u32> = EdgeState::new();
        let rx = state.park_tcp_agent(token(7));
        assert!(state.has_tcp_agent(&token(7)));
        let client: BoxedStream = Box::new(tokio::io::duplex(16).0);
        assert!(
            state.deliver_to_tcp_agent(&token(7), client).is_ok(),
            "delivery to a parked agent succeeds"
        );
        assert!(rx.await.is_ok(), "the agent receives the client stream");
        assert!(!state.has_tcp_agent(&token(7)), "registration consumed (single-use)");
    }

    #[tokio::test]
    async fn deliver_without_parked_tcp_agent_returns_the_stream() {
        let state: EdgeState<u32> = EdgeState::new();
        let client: BoxedStream = Box::new(tokio::io::duplex(16).0);
        assert!(
            state.deliver_to_tcp_agent(&token(8), client).is_err(),
            "no parked agent → stream handed back so the caller can fall through"
        );
    }

    #[tokio::test]
    async fn remove_drops_parked_tcp_agent() {
        let state: EdgeState<u32> = EdgeState::new();
        let _rx = state.park_tcp_agent(token(9));
        state.remove(&token(9));
        assert!(!state.has_tcp_agent(&token(9)));
    }
}
