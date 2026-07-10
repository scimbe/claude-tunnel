# Build Progress Log

Driven by the `/loop` process (`DEVELOPMENT-PROCESS.md` D1–D8): one Task Packet per cycle, each green increment committed. The loop reads this file to know what's next.

## Packet status

| Packet | Status | Notes |
|--------|--------|-------|
| P0.1 workspace + CI + docker | ✅ done | 4 crates, `cargo build/test --workspace` green in `rust:1-slim` |
| P0.2 `common` wire-types | ✅ done | TenantId, AgentId, RoutingToken, OriginIdentity, Capability, ControlFrame + serde round-trip tests |
| P1.1 Edge QUIC listener | ✅ done | P1.1a endpoint/cert · P1.1b connect+echo · P1.1c reject untrusted — 4 ct-edge tests |
| P1.2 Agent dialer + TCP fallback | 🔨 in progress | P1.2a ✅ (selection + QUIC dialer + interop) · P1.2b (reconnect) · P1.2c (TCP fallback transport) |
| P1.3 join-token enrollment | ✅ done | P1.3a service + P1.3b agent ed25519 identity + enroll interop |
| P1.4 short-lived mTLS auth | ✅ done | full auth chain over QUIC: enroll → mint → present → verify (P1.4a–d) |

**🎯 Milestone 1 complete** (P0.1–P1.4 core): authenticated QUIC transport between Agent and Edge, backed by enrollment + short-lived credentials. Deferred enhancements: P1.2b (reconnect), P1.2c (HTTP/2-over-TCP fallback).

**Milestone 2** (Tunnel Registry + Rendezvous, SPEC §10 item 2): P2.1 ✅ (Tunnel Registry) · P2.2 ✅ (agent mints Capability + registers token) · P2.3 ⏳ (rendezvous relay path) · P2.4 (relay data path).

## Cycle log

- **Cycle 1 — P0.1**: Cargo workspace (`ct-common`, `ct-agent`, `ct-edge`, `ct-control-plane`), `Dockerfile.dev`, `.github/workflows/ci.yml`. Local gate: `cargo build --workspace` + `cargo test --workspace` in `rust:1-slim` → 4 tests pass. Committed.
- **Cycle 2 — P0.2**: `ct-common` wire types (TenantId, AgentId, RoutingToken, OriginIdentity, Capability, ControlFrame), serde derive + serde_json round-trip test per type. Green in `rust:1-slim` (serde fetched from crates.io — container network confirmed). Committed.
- **Cycle 3 — P1.1a**: decomposed P1.1 (too big for one pass) into P1.1a/b/c. P1.1a: `ct-edge::transport::build_server_endpoint` — quinn server `Endpoint` with rcgen self-signed cert + ring crypto provider, binds an ephemeral UDP port; `#[tokio::test]` asserts non-zero port. Stack (quinn 0.11 / rustls 0.23-ring / rcgen 0.13) compiled clean. Green in `rust:1-slim`. Committed.
- **Cycle 4 — P1.1b**: client endpoint that trusts the server's self-signed cert (proper verification, no skip); `accept_and_echo_one` accepts one bi stream and echoes. `#[tokio::test] echo_roundtrip_over_bidirectional_stream` connects client→server, round-trips `b"ping"`. 3 ct-edge tests green in `rust:1-slim`. Committed.
- **Cycle 5 — P1.1c**: negative-path test `untrusted_server_cert_is_rejected` — client trusting a different cert must fail the handshake (proves TLS verification is enforced, not skipped). No new production code. **P1.1 complete.** Full workspace regression: 11 tests green in `rust:1-slim`. Committed.
- **Cycle 6 — P1.2a**: decomposed P1.2 into a/b/c. P1.2a: `ct-agent::transport` — `select_transport(udp_reachable)` decision (QUIC vs TcpFallback) + `dial_quic`; interop test `agent_dials_edge_over_quic` drives a real `ct-edge` server (dev-dep) and round-trips bytes. Full workspace: 14 tests green. Committed.
- **Cycle 7 — P1.3a**: decomposed P1.3. P1.3a: `ct-control-plane::enrollment` — in-memory `Enrollment` service; `issue_join_token` (random single-use), `redeem` binds Agent public key to Tenant and consumes the token, rejects reuse (`TokenAlreadyUsed`) and unknown tokens. Service holds no private keys. 3 enrollment tests; full workspace 17 tests green. Committed.
- **Cycle 8 — P1.3b**: `ct-agent::identity::AgentIdentity` — ed25519 keypair (ed25519-dalek 2 + rand 0.8); `public_key_bytes()` + `sign()`, **no signing-key accessor** (private key never leaves the Agent). Tests: distinct keys, signature verifies, and `enroll_binds_agent_identity` redeems a real identity against `ct-control-plane`. **P1.3 complete.** Full workspace 20 tests green. Committed.
- **Cycle 9 — P1.4a**: decomposed P1.4 into a/b/c. P1.4a: `ct-control-plane::credential` — `CredentialIssuer` mints ed25519 issuer-signed, expiry-bounded credentials; `verify(issuer_pubkey, signed, now)` checks signature + expiry. Time passed in (no wall-clock in lib). Tests: verify-ok-before-expiry, expired, wrong-issuer, tampered-claims. Full workspace 24 tests green. Committed.
- **Cycle 10 — P1.4b**: `ct-control-plane::issuance::mint_for_enrolled` — mints a credential only for an enrolled Agent (Tenant taken from the binding, not the caller); unenrolled → `MintError::NotEnrolled`. Split Edge-side verify into P1.4c (needs credential types shared across crates — avoid coupling edge→control-plane hastily). 2 tests; full workspace 26 tests green. Committed.
- **Cycle 11 — P1.4c**: refactor — moved credential claims/wire-form/`verify` to `ct-common::credential`; `ct-control-plane::credential` re-exports them + keeps `CredentialIssuer` (signing key); new `ct-edge::auth::verify_presented_credential` lets the Edge verify statelessly. All prior tests survived the move; full workspace 29 tests green. Committed.
- **Cycle 12 — P1.4d-i**: caught that serde can't derive `Deserialize` for `[u8; 64]`, so gave `SignedCredential` a hand-rolled binary wire form (`signature | tenant_len | tenant | agent_len | agent | expires_at`) via `encode`/`decode`; added `CredError::Malformed`. Tests: round-trip, truncated, trailing-garbage. Split P1.4d into d-i (this) + d-ii (QUIC handshake). Full workspace 32 tests green. Committed.
- **Cycle 13 — P1.4d-ii**: `ct-edge::auth::accept_and_authenticate` (accept → read credential → decode → verify → reply OK/NO, return authenticated conn) + `ct-agent::transport::present_credential` (open bi-stream → send encoded credential → await ack). Interop tests over live QUIC: valid credential authenticates; expired is rejected. **P1.4 done → Milestone 1 complete.** Full workspace 34 tests green. Committed.
- **Cycle 14 — P2.1**: extended the DAG to Milestone 2 (Tunnel Registry + Rendezvous). P2.1: `ct-control-plane::registry::TunnelRegistry` — in-memory `RoutingToken` → `TunnelInfo` (tenant, agent); `register`/`lookup`/`unregister`. Tests: register→lookup, unknown→None, unregister-removes (+ idempotent), re-register overwrites. Full workspace 38 tests green. Committed.
- **Cycle 15 — P2.2**: `ct-agent::capability::mint_capability(origin, edge_addr)` — mints a `Capability` with a fresh random Routing Token (ADR-0014). Tests: distinct tokens across mints; minted token registers + looks up in a `TunnelRegistry` (interop with control-plane). Full workspace 40 tests green. Committed.

## Verification method

Local green bar per cycle = `cargo build --workspace` + `cargo test --workspace` inside `rust:1-slim` (host has no cargo; docker is the hermetic runner, per D3). `cargo fmt`/`clippy`/`audit` run in CI (`ci.yml`); added to the local gate once components are baked into `Dockerfile.dev` (a later packet).
