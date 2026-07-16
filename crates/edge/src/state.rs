//! Edge routing state (M5.1b).
//!
//! Maps a Routing Token to the Agent tunnel handle that serves it, so the Edge
//! can route a resolved Client rendezvous to the right Agent connection. Generic
//! over the handle type (`quinn::Connection` in the daemon) to stay
//! unit-testable. `is_known` plugs straight into `resolve_rendezvous_gated`.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use ct_common::metrics::Counter;
use ct_common::RoutingToken;
use ct_common::sync::MutexExt;
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
    /// Browser Plane (#23): public hostname -> routing token, so an SNI-routed
    /// TLS connection can be mapped to a tunnel without the Client protocol.
    /// Hostnames are stored lowercased. The payload stays blind (TLS ciphertext
    /// is passed through); only the SNI hostname is visible to the Edge.
    hosts: Mutex<HashMap<String, RoutingToken>>,
    /// Revoked routing tokens (#27 RB3): a token here is torn down and refuses
    /// re-registration, so a customer's "revoke" actually stops the tunnel even
    /// though the agent keeps reconnecting.
    revoked: Mutex<HashSet<RoutingToken>>,
    /// Shared admin secret authenticating the control plane's `'R'` revoke op
    /// (#27 RB3). `None` = revocation disabled (no `CT_EDGE_ADMIN_TOKEN`).
    admin_token: Mutex<Option<[u8; 32]>>,
    /// Cumulative data-plane counters for observability (#10 O2).
    registrations: Counter,
    relays: Counter,
    relay_bytes: Counter,
    failovers: Counter,
}

impl<H: Clone> EdgeState<H> {
    pub fn new() -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
            next_reg: AtomicU64::new(1),
            candidates: Mutex::new(HashMap::new()),
            direct: Mutex::new(HashMap::new()),
            tcp_agents: Mutex::new(HashMap::new()),
            hosts: Mutex::new(HashMap::new()),
            revoked: Mutex::new(HashSet::new()),
            admin_token: Mutex::new(None),
            registrations: Counter::default(),
            relays: Counter::default(),
            relay_bytes: Counter::default(),
            failovers: Counter::default(),
        }
    }

    /// Bind a public hostname to a routing token (Browser Plane, #23), **unless**
    /// the hostname is already bound to a *different* token — a takeover-safe bind
    /// (#23 BP4a). Rebinding the same token (an agent reconnecting) is idempotent
    /// and succeeds. Returns `true` when the binding is in place, `false` when a
    /// conflicting bind was refused (the existing route is left untouched). The
    /// hostname is lowercased so SNI lookups are case-insensitive.
    pub fn register_host(&self, host: &str, token: RoutingToken) -> bool {
        let key = host.to_ascii_lowercase();
        let mut hosts = self.hosts.lock_safe();
        match hosts.get(&key) {
            Some(existing) if *existing != token => false,
            _ => {
                hosts.insert(key, token);
                true
            }
        }
    }

    /// Remove every hostname bound to `token` — called when its last agent drops
    /// or it is revoked, so no stale host->token route lingers (#23 BP4a).
    fn clear_hosts_for(&self, token: &RoutingToken) {
        self.hosts.lock_safe().retain(|_, v| v != token);
    }

    /// Resolve a public hostname (from the TLS SNI) to its routing token.
    pub fn route_host(&self, host: &str) -> Option<RoutingToken> {
        self.hosts.lock_safe().get(&host.to_ascii_lowercase()).cloned()
    }

    /// Note a completed relay of `bytes` total bytes (both directions), and a
    /// failover to a non-primary agent, for observability (#10 O2).
    pub fn note_relay(&self, bytes: u64) {
        self.relays.inc();
        self.relay_bytes.add(bytes);
    }
    pub fn note_failover(&self) {
        self.failovers.inc();
    }
    /// Cumulative counter snapshots for the metrics endpoint (#10 O2).
    pub fn registrations_total(&self) -> u64 {
        self.registrations.get()
    }
    pub fn relays_total(&self) -> u64 {
        self.relays.get()
    }
    pub fn relay_bytes_total(&self) -> u64 {
        self.relay_bytes.get()
    }
    pub fn failovers_total(&self) -> u64 {
        self.failovers.get()
    }

    /// Park a TCP-fallback agent for `token`: returns a receiver that resolves to
    /// a Client's stream once one rendezvouses for this token (single-tunnel).
    /// The agent then relays its own stream to the received one.
    pub fn park_tcp_agent(&self, token: RoutingToken) -> oneshot::Receiver<BoxedStream> {
        let (tx, rx) = oneshot::channel();
        self.tcp_agents.lock_safe().insert(token, tx);
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
        let tx = self.tcp_agents.lock_safe().remove(token);
        match tx {
            Some(tx) => tx.send(stream),
            None => Err(stream),
        }
    }

    /// Whether a TCP-fallback agent is currently parked for `token`.
    pub fn has_tcp_agent(&self, token: &RoutingToken) -> bool {
        self.tcp_agents.lock_safe().contains_key(token)
    }

    /// Record the Agent's advertised direct-path listener for `token` (M11.4b):
    /// the address and cert DER a Client uses to connect directly.
    pub fn advertise_direct(&self, token: RoutingToken, addr: SocketAddr, cert: Vec<u8>) {
        self.direct.lock_safe().insert(token, (addr, cert));
    }

    /// The Agent's advertised direct-path `(addr, cert)` for `token`, if any.
    pub fn direct_endpoint(&self, token: &RoutingToken) -> Option<(SocketAddr, Vec<u8>)> {
        self.direct.lock_safe().get(token).cloned()
    }

    /// Register an Agent tunnel serving `token`, returning a **registration id**.
    /// Multiple Agents may register the same token for redundancy/failover (#8);
    /// the id lets exactly this registration be evicted (via
    /// [`remove_registration`](Self::remove_registration)) when its connection
    /// drops, without disturbing the other Agents serving the token.
    pub fn register(&self, token: RoutingToken, handle: H) -> u64 {
        let id = self.next_reg.fetch_add(1, Ordering::Relaxed);
        self.agents
            .lock_safe()
            .entry(token)
            .or_default()
            .push((id, handle));
        self.registrations.inc();
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
        self.candidates.lock_safe().insert(token.clone(), candidate);
        self.register(token, handle)
    }

    /// The Agent's Edge-observed peer candidate for `token`, if recorded.
    pub fn candidate(&self, token: &RoutingToken) -> Option<SocketAddr> {
        self.candidates.lock_safe().get(token).copied()
    }

    /// Route `token` to a live Agent tunnel handle, if any. Returns the **most
    /// recently registered** Agent, so a reconnecting Agent is preferred over its
    /// own dying registration and, with redundant Agents (#8), the newest serves
    /// (the next takes over on its drop).
    pub fn route(&self, token: &RoutingToken) -> Option<H> {
        self.agents
            .lock_safe()
            .get(token)
            .and_then(|v| v.last().map(|(_, h)| h.clone()))
    }

    /// All live Agent handles for `token`, **most-recently-registered first** —
    /// the failover order for the relay: try the newest, fall back to older ones
    /// if its `open_bi()` fails (#8 R2, covers the dead-but-not-yet-evicted race).
    pub fn routes(&self, token: &RoutingToken) -> Vec<H> {
        self.agents.lock_safe().get(token).map_or_else(Vec::new, |v| {
            v.iter().rev().map(|(_, h)| h.clone()).collect()
        })
    }

    /// Number of redundant Agent registrations currently serving `token` (#8).
    pub fn registration_count(&self, token: &RoutingToken) -> usize {
        self.agents.lock_safe().get(token).map_or(0, Vec::len)
    }

    /// Distinct routing tokens with at least one live Agent — the number of
    /// tunnels the Edge is currently serving (observability gauge, #10).
    pub fn active_tunnels(&self) -> usize {
        self.agents.lock_safe().values().filter(|v| !v.is_empty()).count()
    }

    /// Total live Agent registrations across all tokens — redundant Agents (#8)
    /// counted separately (observability gauge, #10).
    pub fn total_registrations(&self) -> usize {
        self.agents.lock_safe().values().map(Vec::len).sum()
    }

    /// Evict exactly the registration `id` for `token` — an Agent whose
    /// connection dropped — leaving any other redundant Agents in place (#8).
    /// The token's candidate/direct entries are cleared only when the **last**
    /// Agent for the token is gone.
    pub fn remove_registration(&self, token: &RoutingToken, id: u64) {
        let mut agents = self.agents.lock_safe();
        if let Some(v) = agents.get_mut(token) {
            v.retain(|(rid, _)| *rid != id);
            if v.is_empty() {
                agents.remove(token);
                drop(agents);
                self.candidates.lock_safe().remove(token);
                self.direct.lock_safe().remove(token);
                // The tunnel is gone — drop its hostname routes too (#23 BP4a).
                self.clear_hosts_for(token);
            }
        }
    }

    /// Remove **all** Agent tunnels (and candidate + direct + tcp) for `token` —
    /// a full teardown, regardless of how many redundant Agents serve it.
    pub fn remove(&self, token: &RoutingToken) {
        self.agents.lock_safe().remove(token);
        self.candidates.lock_safe().remove(token);
        self.direct.lock_safe().remove(token);
        self.tcp_agents.lock_safe().remove(token);
        self.clear_hosts_for(token);
    }

    /// Revoke `token` (#27 RB3): tear down its live registrations and any hostname
    /// mappings, and mark it so a reconnecting Agent cannot re-register it. This
    /// is what makes a customer's "revoke" actually stop the tunnel — without the
    /// revoked set, the Agent's reconnect loop would simply register again.
    pub fn revoke_token(&self, token: &RoutingToken) {
        self.revoked.lock_safe().insert(token.clone());
        self.remove(token); // also clears the token's hostname routes (#23 BP4a)
    }

    /// Whether `token` has been revoked (#27 RB3).
    pub fn is_revoked(&self, token: &RoutingToken) -> bool {
        self.revoked.lock_safe().contains(token)
    }

    /// Configure the shared admin secret that authenticates the `'R'` revoke op
    /// (#27 RB3). Set from `CT_EDGE_ADMIN_TOKEN` at startup.
    pub fn set_admin_token(&self, token: [u8; 32]) {
        *self.admin_token.lock_safe() = Some(token);
    }

    /// Constant-time check that `auth` matches the configured admin secret.
    /// Always `false` when no admin token is configured (revocation disabled).
    pub fn admin_revoke_ok(&self, auth: &[u8; 32]) -> bool {
        match self.admin_token.lock_safe().as_ref() {
            Some(expected) => {
                auth.iter().zip(expected).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
            }
            None => false,
        }
    }

    /// Register an Agent tunnel unless its token has been revoked (#27 RB3).
    /// Returns the registration id, or `None` if the token is revoked — the
    /// registration path the serve loop uses so a revoked token stays down even
    /// as its Agent keeps reconnecting.
    pub fn register_unless_revoked(&self, token: RoutingToken, handle: H) -> Option<u64> {
        if self.is_revoked(&token) {
            return None;
        }
        Some(self.register(token, handle))
    }

    /// Whether `token` currently has at least one live Agent tunnel.
    pub fn is_known(&self, token: &RoutingToken) -> bool {
        self.agents
            .lock_safe()
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
    fn host_binding_is_takeover_safe_and_cleared_on_agent_drop() {
        // #23 BP4a: first bind wins; a conflicting bind can't steal the route;
        // the binding is cleared when the tunnel's last agent drops.
        let state = EdgeState::new();
        let (t1, t2) = (token(1), token(2));
        let id = state.register(t1.clone(), 5u32);

        // First bind wins; rebinding the SAME token (reconnect) is idempotent-OK.
        assert!(state.register_host("app.example", t1.clone()));
        assert!(state.register_host("app.example", t1.clone()), "same-token rebind ok");
        assert_eq!(state.route_host("app.example"), Some(t1.clone()));

        // A conflicting bind to a DIFFERENT token is refused; route untouched.
        assert!(!state.register_host("app.example", t2.clone()), "takeover refused");
        assert_eq!(state.route_host("app.example"), Some(t1.clone()), "original route intact");

        // When the tunnel's last agent drops, the stale host route is cleared.
        state.remove_registration(&t1, id);
        assert_eq!(state.route_host("app.example"), None, "host route cleared on drop");

        // ...so the hostname is now free for a different tunnel to claim.
        assert!(state.register_host("app.example", t2.clone()));
        assert_eq!(state.route_host("app.example"), Some(t2));
    }

    #[test]
    fn admin_revoke_ok_requires_the_configured_secret() {
        // #27 RB3: the 'R' revoke op authenticates against CT_EDGE_ADMIN_TOKEN.
        let state = EdgeState::<u32>::new();
        let secret = [0x11u8; 32];
        // Unconfigured -> revocation disabled, every auth rejected.
        assert!(!state.admin_revoke_ok(&secret));
        state.set_admin_token(secret);
        assert!(state.admin_revoke_ok(&secret), "correct secret accepted");
        let mut wrong = secret;
        wrong[31] ^= 1;
        assert!(!state.admin_revoke_ok(&wrong), "wrong secret rejected");
    }

    #[test]
    fn revoke_token_drops_registration_and_blocks_reregistration() {
        // #27 RB3: revoke tears down the live tunnel and refuses re-registration,
        // so a reconnecting agent can't defeat a customer's "revoke".
        let state = EdgeState::new();
        let t = token(9);
        state.register_host("app.example", t.clone());
        state.register(t.clone(), 1u32);
        assert_eq!(state.active_tunnels(), 1);

        state.revoke_token(&t);
        assert_eq!(state.active_tunnels(), 0, "revoke drops the live registration");
        assert!(state.is_revoked(&t));
        assert_eq!(state.route_host("app.example"), None, "hostname mapping cleared");

        // A reconnecting agent cannot re-register the revoked token.
        assert!(state.register_unless_revoked(t.clone(), 2u32).is_none());
        assert_eq!(state.active_tunnels(), 0, "still no tunnel after a blocked re-register");

        // A different (unrevoked) token registers normally.
        assert!(state.register_unless_revoked(token(10), 3u32).is_some());
        assert_eq!(state.active_tunnels(), 1);
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
