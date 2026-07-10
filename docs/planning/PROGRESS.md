# Build Progress Log

Driven by the `/loop` process (`DEVELOPMENT-PROCESS.md` D1–D8): one Task Packet per cycle, each green increment committed. The loop reads this file to know what's next.

## Packet status

| Packet | Status | Notes |
|--------|--------|-------|
| P0.1 workspace + CI + docker | ✅ done | 4 crates, `cargo build/test --workspace` green in `rust:1-slim` |
| P0.2 `common` wire-types | ✅ done | TenantId, AgentId, RoutingToken, OriginIdentity, Capability, ControlFrame + serde round-trip tests |
| P1.1 Edge QUIC listener | ⏳ next | |
| P1.2 Agent dialer + TCP fallback | pending | |
| P1.3 join-token enrollment | pending | |
| P1.4 short-lived mTLS auth | pending | |

## Cycle log

- **Cycle 1 — P0.1**: Cargo workspace (`ct-common`, `ct-agent`, `ct-edge`, `ct-control-plane`), `Dockerfile.dev`, `.github/workflows/ci.yml`. Local gate: `cargo build --workspace` + `cargo test --workspace` in `rust:1-slim` → 4 tests pass. Committed.
- **Cycle 2 — P0.2**: `ct-common` wire types (TenantId, AgentId, RoutingToken, OriginIdentity, Capability, ControlFrame), serde derive + serde_json round-trip test per type. Green in `rust:1-slim` (serde fetched from crates.io — container network confirmed). Committed.

## Verification method

Local green bar per cycle = `cargo build --workspace` + `cargo test --workspace` inside `rust:1-slim` (host has no cargo; docker is the hermetic runner, per D3). `cargo fmt`/`clippy`/`audit` run in CI (`ci.yml`); added to the local gate once components are baked into `Dockerfile.dev` (a later packet).
