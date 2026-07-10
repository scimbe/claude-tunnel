# Build Progress Log

Driven by the `/loop` process (`DEVELOPMENT-PROCESS.md` D1–D8): one Task Packet per cycle, each green increment committed. The loop reads this file to know what's next.

## Packet status

| Packet | Status | Notes |
|--------|--------|-------|
| P0.1 workspace + CI + docker | ✅ done | 4 crates, `cargo build/test --workspace` green in `rust:1-slim` |
| P0.2 `common` wire-types | ✅ done | TenantId, AgentId, RoutingToken, OriginIdentity, Capability, ControlFrame + serde round-trip tests |
| P1.1 Edge QUIC listener | ✅ done | P1.1a endpoint/cert · P1.1b connect+echo · P1.1c reject untrusted — 4 ct-edge tests |
| P1.2 Agent dialer + TCP fallback | 🔨 in progress | P1.2a ✅ (selection + QUIC dialer + interop) · P1.2b (reconnect) · P1.2c (TCP fallback transport) |
| P1.3 join-token enrollment | 🔨 in progress | P1.3a ✅ (service: issue/redeem/single-use) · P1.3b ⏳ (agent ed25519 identity + interop) |
| P1.4 short-lived mTLS auth | pending | |

## Cycle log

- **Cycle 1 — P0.1**: Cargo workspace (`ct-common`, `ct-agent`, `ct-edge`, `ct-control-plane`), `Dockerfile.dev`, `.github/workflows/ci.yml`. Local gate: `cargo build --workspace` + `cargo test --workspace` in `rust:1-slim` → 4 tests pass. Committed.
- **Cycle 2 — P0.2**: `ct-common` wire types (TenantId, AgentId, RoutingToken, OriginIdentity, Capability, ControlFrame), serde derive + serde_json round-trip test per type. Green in `rust:1-slim` (serde fetched from crates.io — container network confirmed). Committed.
- **Cycle 3 — P1.1a**: decomposed P1.1 (too big for one pass) into P1.1a/b/c. P1.1a: `ct-edge::transport::build_server_endpoint` — quinn server `Endpoint` with rcgen self-signed cert + ring crypto provider, binds an ephemeral UDP port; `#[tokio::test]` asserts non-zero port. Stack (quinn 0.11 / rustls 0.23-ring / rcgen 0.13) compiled clean. Green in `rust:1-slim`. Committed.
- **Cycle 4 — P1.1b**: client endpoint that trusts the server's self-signed cert (proper verification, no skip); `accept_and_echo_one` accepts one bi stream and echoes. `#[tokio::test] echo_roundtrip_over_bidirectional_stream` connects client→server, round-trips `b"ping"`. 3 ct-edge tests green in `rust:1-slim`. Committed.
- **Cycle 5 — P1.1c**: negative-path test `untrusted_server_cert_is_rejected` — client trusting a different cert must fail the handshake (proves TLS verification is enforced, not skipped). No new production code. **P1.1 complete.** Full workspace regression: 11 tests green in `rust:1-slim`. Committed.
- **Cycle 6 — P1.2a**: decomposed P1.2 into a/b/c. P1.2a: `ct-agent::transport` — `select_transport(udp_reachable)` decision (QUIC vs TcpFallback) + `dial_quic`; interop test `agent_dials_edge_over_quic` drives a real `ct-edge` server (dev-dep) and round-trips bytes. Full workspace: 14 tests green. Committed.
- **Cycle 7 — P1.3a**: decomposed P1.3. P1.3a: `ct-control-plane::enrollment` — in-memory `Enrollment` service; `issue_join_token` (random single-use), `redeem` binds Agent public key to Tenant and consumes the token, rejects reuse (`TokenAlreadyUsed`) and unknown tokens. Service holds no private keys. 3 enrollment tests; full workspace 17 tests green. Committed.

## Verification method

Local green bar per cycle = `cargo build --workspace` + `cargo test --workspace` inside `rust:1-slim` (host has no cargo; docker is the hermetic runner, per D3). `cargo fmt`/`clippy`/`audit` run in CI (`ci.yml`); added to the local gate once components are baked into `Dockerfile.dev` (a later packet).
