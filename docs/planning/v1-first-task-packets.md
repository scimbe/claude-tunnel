# v1 — First Task-Packet DAG (bootstrap dry-run)

> A concrete application of `DEVELOPMENT-PROCESS.md` (D1–D8) to `SPEC.md` §10. Covers Milestone 0 (foundation) and Milestone 1 (Agent⇄Edge transport + enrollment). Later milestones continue in the same shape. Because the repo is greenfield, every packet's context bundle currently resolves to the ADRs / `CONTEXT.md` / `SPEC.md` (the only existing context) plus the crates produced by earlier packets.

## Dependency DAG

```
P0.1 workspace+CI+docker
      │
P0.2 common wire-types crate
      ├────────────┬────────────┐
P1.1 Edge QUIC   P1.2 Agent    P1.3 join-token
     listener      dialer+FB     enrollment
                                    │
                                 P1.4 short-lived mTLS auth (Agent→Edge)
```

Independent after P0.2: **P1.1, P1.2, P1.3** run in parallel. **P1.4** waits on P1.3. Edge↔Agent end-to-end auth demo waits on P1.1+P1.4.

---

## P0.1 — Rust workspace + CI + dev docker image

- **Goal:** a buildable Cargo workspace with empty `agent`, `edge`, `control-plane`, `common` crates; CI runs build+test+lint+`cargo audit`; a hermetic dev/CI docker image.
- **Acceptance tests:** `cargo build --workspace` and `cargo test --workspace` green; CI workflow green on the empty tree; `docker build` of the dev image succeeds and runs the test suite.
- **Allowed surface:** `Cargo.toml`, `crates/*/`, `.github/workflows/ci.yml` (or local CI runner), `Dockerfile.dev`.
- **Context bundle:** ADR-0007 (Rust), DEVELOPMENT-PROCESS D3/D7 (docker/CI substrate). No prior code.
- **Fits budget:** trivially. **Prereq of everything.**

## P0.2 — `common` wire-types crate

- **Goal:** shared, logic-free types: `TenantId`, `AgentId`, `RoutingToken`, `OriginIdentity` (pubkey), `Capability`, message framing enums. serde-serializable.
- **Acceptance tests:** types compile; serde round-trip property tests for every type; no dependency on `agent`/`edge`.
- **Allowed surface:** `crates/common/`.
- **Context bundle:** `CONTEXT.md` (Routing Token, Origin Identity, Capability, Tenant, Agent Identity); ADR-0013/0014. Depends on P0.1.
- **Fits budget:** yes.

## P1.1 — Edge QUIC listener (relay-less echo)

> **Decomposed (cycle 3):** exceeded a single Haiku-sized pass (quinn + async runtime + TLS cert plumbing + connection + echo + integration test). Split into:
> - **P1.1a** — QUIC/TLS plumbing: server `Endpoint` with self-signed cert binds an ephemeral port. Isolates dependency + crypto-provider risk.
> - **P1.1b** — connect + bidirectional echo stream (integration test, client↔server).
> - **P1.1c** — reject malformed/untrusted handshake.

- **Goal:** Edge accepts QUIC/UDP-443 connections (quinn), opens per-stream handling, echoes a stream (transport correctness before routing).
- **Acceptance tests:** integration test — a QUIC client connects, opens a stream, bytes echo back; malformed handshake rejected.
- **Allowed surface:** `crates/edge/` (transport module only).
- **Context bundle:** ADR-0004 (QUIC), `common` framing (P0.2). Depends on P0.2.
- **Fits budget:** yes (single module + one integration test).

## P1.2 — Agent QUIC dialer + TCP fallback detection

> **Decomposed (cycle 6):** split into P1.2a (transport-selection decision + QUIC dialer + interop test), P1.2b (reconnect-on-drop with backoff), P1.2c (actual HTTP/2-over-TCP fallback transport). P1.2a done; b/c are follow-ups (P1.3 enrollment prioritised next for the Milestone-1 critical path).

- **Goal:** Agent dials outbound QUIC to a given Edge address; detects blocked UDP and selects HTTP/2-over-TCP fallback.
- **Acceptance tests:** Agent connects to a P1.1 test Edge; unit test forces UDP-blocked and asserts fallback selection; reconnect on drop.
- **Allowed surface:** `crates/agent/` (transport module only).
- **Context bundle:** ADR-0004, `common` (P0.2). Depends on P0.2 (test-integrates with P1.1 but does not import it).
- **Fits budget:** yes.

## P1.3 — Join-token enrollment

- **Goal:** control-plane endpoint issues a single-use join token; Agent redeems it, generates an identity keypair, and binds its public key to the Tenant.
- **Acceptance tests:** enroll flow test (issue → redeem → bound); single-use enforced (second redeem rejected); keypair never leaves the Agent (asserted by interface).
- **Allowed surface:** `crates/control-plane/` (enrollment module), `crates/agent/` (enroll module).
- **Context bundle:** ADR-0005 (asymmetric identity), `common` (P0.2). Depends on P0.2.
- **Fits budget:** yes.

## P1.4 — Short-lived mTLS credential + Agent→Edge auth

- **Goal:** control-plane mints a short-lived mTLS credential from the bound identity; Agent authenticates to the Edge with it.
- **Acceptance tests:** Agent with a valid fresh credential authenticates to Edge; expired/rotated credential rejected; hostname/tenant scoping enforced.
- **Allowed surface:** `crates/control-plane/` (minting), `crates/edge/` (auth), `crates/agent/` (auth).
- **Context bundle:** ADR-0005, P1.1 (Edge transport), P1.3 (bound identity). Depends on **P1.3** (and integrates with P1.1).
- **Fits budget:** borderline — if the bundle (mint + edge-auth + agent-auth across three crates) exceeds budget at grading time, D1 says **decompose** (e.g. split minting from verification).

---

## Notes for the run

- **Readiness gate (D2):** each packet's acceptance tests + stubs must resolve against its bundle before a Haiku agent is assigned; P1.4 is the first likely **decompose** candidate.
- **Escalation (D6/HITL):** nothing here should hit an unsourceable gap — all context exists in the ADRs. The first genuine escalations are more likely in Milestone 5 (billing/PoW) where the backlog risks (jurisdiction, billing-sybil) are unresolved.
- **Frozen tests (D4):** the acceptance tests above are authored by the strong model and are immutable to the executing Haiku.
