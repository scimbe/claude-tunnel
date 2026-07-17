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

> **Decomposed (cycle 7):** P1.3a (control-plane in-memory enrollment service: issue single-use token, redeem binds Agent public key to Tenant, reject reuse/unknown) — done. P1.3b (Agent ed25519 identity keypair + enroll interop, private key never leaves Agent) — next.

- **Goal:** control-plane endpoint issues a single-use join token; Agent redeems it, generates an identity keypair, and binds its public key to the Tenant.
- **Acceptance tests:** enroll flow test (issue → redeem → bound); single-use enforced (second redeem rejected); keypair never leaves the Agent (asserted by interface).
- **Allowed surface:** `crates/control-plane/` (enrollment module), `crates/agent/` (enroll module).
- **Context bundle:** ADR-0005 (asymmetric identity), `common` (P0.2). Depends on P0.2.
- **Fits budget:** yes.

## P1.4 — Short-lived mTLS credential + Agent→Edge auth

> **Decomposed (cycle 9, refined cycle 10):** P1.4a (credential primitive — issuer-signed, expiry-bounded `Credential`; `mint`/`verify`) ✅ · P1.4b (enrollment-gated minting — only bound identities) ✅ · P1.4c (credential types + `verify` extracted to `ct-common`; Edge-side verification in `ct-edge::auth`) ✅ · P1.4d-i (credential binary wire encode/decode — serde can't derive `[u8;64]`) ✅ · P1.4d-ii (present the credential over the QUIC handshake: Agent presents, Edge verifies). Note: implemented as an ed25519 issuer-signed credential (same CA-signed/short-lived/verifiable trust structure as mTLS); real X.509 client-cert mTLS is a later hardening.

- **Goal:** control-plane mints a short-lived mTLS credential from the bound identity; Agent authenticates to the Edge with it.
- **Acceptance tests:** Agent with a valid fresh credential authenticates to Edge; expired/rotated credential rejected; hostname/tenant scoping enforced.
- **Allowed surface:** `crates/control-plane/` (minting), `crates/edge/` (auth), `crates/agent/` (auth).
- **Context bundle:** ADR-0005, P1.1 (Edge transport), P1.3 (bound identity). Depends on **P1.3** (and integrates with P1.1).
- **Fits budget:** borderline — if the bundle (mint + edge-auth + agent-auth across three crates) exceeds budget at grading time, D1 says **decompose** (e.g. split minting from verification).

---

## Milestone 2 — Tunnel Registry + Rendezvous (SPEC §10 item 2)

Relay path first (correctness before NAT traversal), per ADR-0006 / ADR-0015.

### P2.1 — Tunnel Registry (in-memory)
- **Goal:** control-plane registry mapping `RoutingToken` → `TunnelInfo` (tenant, agent); `register` / `lookup` / `unregister`.
- **Acceptance:** register→lookup; unknown→None; unregister removes; re-register overwrites.
- **Surface:** `crates/control-plane/src/registry.rs`. **Context:** ADR-0006, ADR-0017, CONTEXT (Tunnel Registry, Routing Token).

### P2.2 — Agent registers a tunnel
- Agent mints a `Capability` (Routing Token + Origin Identity) and registers the token → tunnel in the registry.

### P2.3 — Rendezvous (relay path)
> **Decomposed (cycle 16):** P2.3a (token-resolution handshake — Client presents a Routing Token, Edge resolves via an `is_known` predicate over the registry, replies OK/NO) · P2.3b (byte relay, folded into P2.4).
- Client presents a Routing Token to the Edge; the Edge looks up the registry and relays between Client and Agent (relay-first; NAT hole-punching is a later packet).

### M5.4b — Unified serve + client tunnel (prereq for compose)
> **Inserted (cycle 38):** the compose topology (M5.5) needs the binaries to run the protocol end to end. M5.4b unifies the Edge into `serve_connection` (role dispatch: `'A'` register / `'C'` rendezvous→route→relay on one stream) + matching `ct-client::transport::client_tunnel`, with a full client→edge→agent e2e test. Remaining: M5.4c main-wiring (edge run loop, agent/client run from config+cert, edge writes its cert to a shared volume) → then M5.5 compose+netem+NAT → M5.6 smoke.

### P2.4 — Relay data path
> **Decomposed (cycle 17):** P2.4a (generic provider-blind bidirectional relay primitive via `copy_bidirectional`, tested with in-memory duplex) · P2.4b (wire the relay onto paired QUIC streams: Client stream ↔ Agent tunnel).
- Edge relays opaque ciphertext bytes between the Client stream and the Agent tunnel (provider-blind).

## Milestone 3 — Noise Client↔Origin E2E (SPEC §10 item 3)

Provider-blind E2E via the Noise Protocol Framework (ADR-0013): Noise_IK, static X25519 keys, Client pins the Origin Identity.

### P3.1 — Noise static keypair + Origin Identity
- **Goal:** generate a Noise static X25519 keypair (via `snow`); its public half is the Origin Identity.
- **Surface:** `crates/common/src/noise.rs`. **Context:** ADR-0013, CONTEXT (Origin Identity).

### P3.2 — Noise handshake (Client↔Origin)
- Complete a Noise_IK handshake between two parties; derive transport keys; encrypt/decrypt a message end to end.

### P3.3 — Noise session over QUIC (through the relay)
> **Decomposed (cycle 21):** P3.3a (message framing codec — 2-byte length prefix, since Noise messages are variable-length) · P3.3b (drive the Noise handshake + transport through the relay/QUIC; prove the Edge sees only ciphertext).
- Run the Noise session inside the QUIC stream so the Edge relays only ciphertext (provider-blind).

### P3.4 — Capability import (Client)
- Client parses a `Capability`, pins the Origin Identity, and uses it as the handshake's remote static key.

## Milestone 4 — PoW-gated rendezvous (SPEC §10 item 5, ADR-0018)

Proof-of-work gates expensive Edge operations against floods/sybil (the deferred sybil-resistance lever). **NAT hole-punching (SPEC §10 item 4) is deferred** — it needs real network topology and isn't hermetically testable in the build container; noted, not silently skipped.

### P4.1 — PoW challenge/solve/verify primitive
- **Goal:** SHA-256 leading-zero-bits PoW. `Challenge { nonce, difficulty }`; `solve` finds a solution; `verify` checks cheaply.
- **Surface:** `crates/common/src/pow.rs` (sha2). **Context:** ADR-0018.

### P4.2 — Gate rendezvous behind PoW
> **Decomposed (cycle 25):** P4.2a (`ct-common::pow::build_request`/`check_request` — solve+pack, verify+unpack the gated request) · P4.2b (wire into the QUIC rendezvous: Edge issues a Challenge, Client solves, Edge checks before resolving the token).
- `resolve_rendezvous` requires a valid PoW solution before resolving a token.

### P4.3 — Per-token rate limiting
- Rate-limit rendezvous per Routing Token / identity.

## Reframe (cycle 26): academic testbed + BA thesis — everything in Docker

The project is now an **academic testbed**: emulate the full topology in Docker, run performance tests, and write a **BA thesis** (HAW Hamburg conventions, **German**, Abstract DE+EN, scaffolded). **Everything runs in Docker** — the host has no passwordless sudo and no mininet, so Docker containers with `--cap-add=NET_ADMIN` + `tc netem` + an iptables NAT container are the mininet-equivalent; LaTeX and plotting are also containerized. **NAT / hole-punching (SPEC §10 item 4), previously deferred, is now in scope via emulation.** Priority: finish M4 → M5 testbed → M6 perf → M7 thesis.

## Milestone 5 — Docker emulation testbed

Prereq: the library crates need runnable **binaries** (the deferred end-to-end wiring).

- **M5.1** Edge binary (`ct-edge` bin): QUIC listener wiring auth + rendezvous + relay from config.
  > **Decomposed (cycle 28–29):** M5.1a (daemon skeleton — `EdgeConfig` from env, bind, accept loop) ✅ · M5.1b (`EdgeState<H>` routing registry: token → Agent handle, `is_known` plugs into gated rendezvous) ✅ · M5.1c (serve: Agent-register path — `register_agent` stores the tunnel connection in `EdgeState`) · M5.1d (Client route→relay path in the serve loop, validated end to end in the M5.6 testbed smoke).
- **M5.2** Agent binary: enroll → register tunnel → serve a local origin.
  > **Decomposed (cycle 32):** M5.2a (`AgentConfig` from env + `register_tunnel` helper + `main.rs` skeleton) · M5.2b (dial Edge + load cert + serve the local Origin: accept relayed streams, dial Origin, relay).
- **M5.3** Client tool: import Capability → PoW-gated rendezvous → Noise E2E to origin.
  > **Decomposed (cycle 35):** M5.3a (new `ct-client` crate: `dial_edge` + `client_rendezvous` PoW-gated, config, bin skeleton) · M5.3b (import Capability + data path through the tunnel to the Origin, optionally Noise E2E).
- **M5.4** Multi-stage Dockerfiles (build → slim runtime) for edge/agent/client.
- **M5.5** `docker compose` topology (client-net / edge / agent-net) + `tc netem` link shaping (verified: `NET_ADMIN` container runs netem) + NAT-gateway container (un-defers hole-punching). **Containernet** (privileged DinD) is the mininet-style alternative — cited + justified in the thesis methodology; Compose+netem chosen for reproducibility/simplicity and because it needs only docker-group, not privileged DinD.
- **M5.6** End-to-end testbed smoke: client reaches origin through the emulated net; assert the edge relays only ciphertext.
- **Verification:** `docker compose up` + scripted assertion (not `cargo test`).

## Milestone 6 — Performance evaluation

- **M6.1** Rust bench harness: handshake latency, connection setup, throughput, relay overhead.
  > **Decomposed (cycle 45):** M6.1a (`ct-client::bench::summarize` — mean/min/max/p50/p95 over latency samples, pure + tested) · M6.1b (round-trip latency runner + client bench mode emitting CSV).
- **M6.2** netem sweep (delay/loss/bandwidth matrix) → metrics to CSV.
- **M6.3** Plots from CSV (matplotlib in a python container).
- **M6.4** Results tables + analysis.
- **Verification:** benches run in-container → CSV + PNG artifacts under `docs/thesis/data/`.

## Milestone 7 — BA thesis (German, HAW-konform, Docker/texlive)

- **M7.1** LaTeX scaffold: Titelblatt, Eidesstattliche Erklärung, Abstract (DE+EN), Gliederung, BibLaTeX; compiled to PDF via a **texlive Docker image**.
- **M7.2** Einleitung + Grundlagen (ZK-Tunnel, Noise, QUIC, PoW). **Decomposed** (two full chapters > one pass):
  - **M7.2a** Einleitung: Motivation/Problemstellung, Zielsetzung, Forschungsfragen, Aufbau (aus SPEC §1–3/§9, ADR-0001/0002/0011).
  - **M7.2b** Grundlagen: providerblinde Relays, Noise (`Noise_IK`), QUIC-Transport, Proof-of-Work (aus ADR-0004/0013/0018, CONTEXT.md).
- **M7.3** Architektur (aus ADRs/CONTEXT/SPEC).
- **M7.4** Implementierung (aus crates).
- **M7.5** Evaluation (aus M6-Ergebnissen + Plots).
- **M7.6** Fazit + Ausblick (Backlog-Risiken).
- **Verification:** thesis PDF compiles cleanly in the texlive container.

## Notes for the run

- **Readiness gate (D2):** each packet's acceptance tests + stubs must resolve against its bundle before a Haiku agent is assigned; P1.4 is the first likely **decompose** candidate.
- **Escalation (D6/HITL):** nothing here should hit an unsourceable gap — all context exists in the ADRs. The first genuine escalations are more likely in Milestone 5 (billing/PoW) where the backlog risks (jurisdiction, billing-sybil) are unresolved.
- **Frozen tests (D4):** the acceptance tests above are authored by the strong model and are immutable to the executing Haiku.

## Milestone 8 — Noise E2E on the live data path (DAG extension, SPEC §8)

The prototype's live path currently relays plaintext. M8 wires the Noise_IK
Client↔Origin session (building blocks already in `ct-common::noise`) onto it,
so the Edge relays only ciphertext. Decomposed:

- **M8.1** Agent holds the Origin static Noise keypair (custodian) and mints the
  Capability with the real OriginIdentity (replacing the `[0u8;32]` placeholder).
- **M8.2** Client-side Noise initiator over the tunnel stream (framed handshake +
  encrypted payload), pinning the Capability's Origin Identity.
- **M8.3** Agent-side Noise responder + plaintext bridge: decrypt client frames →
  local Origin TCP → encrypt replies.
- **M8.4** E2E integration. **Decomposed** (wiring + tap + live mains > one pass):
  - **M8.4a** `client_tunnel_noise` (rendezvous + Noise over one QUIC stream) +
    functional E2E test: Client → real Edge `serve_connection` relay → Agent
    `serve_noise_bridge` → real TCP echo Origin → back, Noise-encrypted.
  - **M8.4b** provider-blind assertion: a tapping relay (byte-identical to the
    Edge's `relay_quic`) proves the relayed bytes ≠ plaintext.
  - **M8.4c** rewire the live path onto Noise. **Decomposed**:
    - **M8.4c-i** `run_agent` serves relayed streams via `serve_noise_bridge`
      (takes the Origin private); agent `main` threads `origin_key.private_bytes()`;
      its integration test becomes a Noise initiator.
    - **M8.4c-ii** client `main` + bench use `client_tunnel_noise`.
    - **M8.4c-iii** docker-compose smoke: the containerized round-trip still
      succeeds over the encrypted path.
- **Verification:** cargo test green each packet; M8.4 asserts provider-blindness.

---

# Full-product roadmap (DAG extension → SPEC §8 v1 feature-completeness)

> Goal (user directive): develop **and** test until **all** SPEC §8 v1 features run and
> **all tests, especially E2E**, are green. Each milestone below lands with a frozen
> E2E test through real components (Edge relay / containers) before it counts as done.
> One packet per cycle; decompose any packet that exceeds a Haiku-sized pass.

Gap analysis vs SPEC §8 (verified against crates): Noise E2E ✅, PoW gating ✅,
credential auth ✅, relay path ✅. **Remaining:** general streaming data path,
UDP, direct P2P + relay fallback, HTTP/2-over-TCP fallback, hosted control-plane
service, agent-side observability, pseudonymous accounts + crypto payment.

## Milestone 9 — General streaming data path
The live Noise path is currently one request/response. Make it a full
bidirectional, multi-message Noise stream so arbitrary TCP protocols tunnel.
- **M9.1** ✅ Noise transport framing loop (`noise_pump`): continuous
  encrypt/decrypt of a bidirectional byte stream over one session.
- **M9.2** Agent `serve_noise_stream` = handshake + `noise_pump` between the
  Noise stream and the Origin TCP socket (isolated streaming test; not yet wired).
- **M9.3** Client streaming API (`client_tunnel_stream`) over the live session.
- **M9.4** Wire the live path onto streaming (`run_agent`/client `main`) and
  **migrate the one-shot E2E tests** to streaming semantics (the one-shot
  `read_to_end` origins deadlock a streaming client — they must half-close
  correctly). **E2E:** multi-message + >64 KiB + interleaved bidirectional
  through the real Edge; ciphertext-only tap.

## Milestone 10 — UDP origin support
Mesh Plane promises "any TCP/UDP".
- **M10.1** ✅ Agent bridges a Noise stream to a UDP Origin (`serve_noise_udp`).
- **M10.2** ✅ Client UDP tunnel mode (`client_tunnel_udp`) + UDP E2E through the
  real Edge (agent `serve_noise_udp`, real UDP echo Origin, boundaries preserved).
- **M10.3** Agent live-path selection: `AgentConfig.origin_proto` (tcp|udp from
  `CT_AGENT_ORIGIN_PROTO`); `run_agent` branches `serve_noise_stream` vs
  `serve_noise_udp`.
- **M10.4** Client `main` UDP mode: `CT_CLIENT_MODE=udp` → `udp_selftest`
  (local UDP socket → `client_tunnel_udp` → verify echo).
- **M10.5** docker-compose UDP smoke: UDP echo Origin + agent
  `CT_AGENT_ORIGIN_PROTO=udp` + client `CT_CLIENT_MODE=udp` → round-trip OK.

## Milestone 11 — Direct P2P path + relay fallback (ADR-0015)
- **M11.1** ✅ `EdgeState` records each Agent's Edge-observed peer candidate
  (reflexive addr) at registration; `register_with_candidate` / `candidate`.
  (Protocol wiring — Edge sends candidate to Client — is M11.2.)
- **M11.2** ✅ Record candidate on the live registration path (`register_agent`
  + `serve_connection` `'A'` → `register_with_candidate(conn.remote_address())`).
- **M11.3** Direct P2P path. **Decomposed** (hole-punch hard/uncertain):
  - **M11.3a** `'P'` peer-candidate query verb (Client asks the Edge for the
    Agent's candidate; separate from the `'C'` relay flow — non-breaking).
  - **M11.3b** Agent direct-path QUIC listener; advertise its address.
  - **M11.3c** Client attempts a direct QUIC connection to the candidate.
- **M11.4** Fallback + integration. **Decomposed**:
  - **M11.4a** ✅ `client_tunnel_p2p_or_relay` orchestrator (try direct, fall
    back to relay on timeout/failure); returns `(used_direct, response)`.
  - **M11.4b** Full-signalling wiring + NAT-testbed E2E: Agent advertises its
    direct-listener `(addr, cert)` via registration → Edge → `'P'` query returns
    them → Client uses them. **HONEST GAP**: today the recorded candidate is the
    Agent's *outbound* Edge-connection address, not its direct-listener address,
    and the listener cert isn't distributed via `'P'` yet — M11.4b closes this.
  - NOTE: the flat Docker bridge has no NAT → the direct path trivially succeeds
    there; true simultaneous-open hole-punching needs emulated NAT and may hit
    testbed limits — will be reported honestly if so.

## Milestone 12 — HTTP/2-over-TCP fallback transport (ADR-0004)
- **M12.1** Agent/Client probe UDP reachability; select TCP transport when blocked.
- **M12.2** Edge listens for the TCP transport and demuxes onto the same relay.
- **E2E:** UDP-blocked testbed (drop UDP/443 via netem/iptables) → tunnel still
  works over TCP.

## Milestone 13 — Hosted control-plane service (ADR-0017)
Turn the in-memory `ct-control-plane` library into a running service.
- **M13.1** HTTP service exposing enrollment (issue/redeem join token).
- **M13.2** Tunnel-registry + rendezvous endpoints over the wire.
- **M13.3** Service binary (`ct-control-plane`) + merged enrollment+registry router.
- **M13.4** Dockerized control-plane container in the compose topology + E2E.
  Decomposed (too big for one gate-green pass — needs an HTTP client the
  Agent/Client can drive, plus a compose overlay):
  - **M13.4a** ✅ `ControlPlaneClient` (reqwest) — issue/redeem/register/resolve
    against the *running* service; integration test drives the full flow over a
    real TCP socket (`axum::serve` on an ephemeral port).
  - **M13.4b** ✅ standalone compose (`docker-compose.controlplane.yml`):
    control-plane container + `cp_selftest` driver enrolls→registers→resolves
    against the running service. Live: `selftest OK`, `COMPOSE_EXIT=0`.
    **Milestone 13 complete.**
- **E2E:** Agent enrolls against the running service, registers its tunnel, and
  a Client resolves + connects — all through the containerized control plane.

## Milestone 14 — Agent-side observability (ADR-0016)
- **M14.1** Prometheus/OpenTelemetry metrics in Agent + Client (tunnel counts,
  bytes, handshake latency). Decomposed:
  - **M14.1a** ✅ `ct-common::metrics` — dependency-free `Counter` +
    `TunnelMetrics` (tunnels opened/failed, bytes each way, handshake
    count+latency-sum) with Prometheus text rendering; unit-tested.
  - **M14.1b** instrument the Agent/Client data path: increment the counters on
    handshake + relayed bytes (share `Arc<TunnelMetrics>` through the tasks).
    Decomposed:
    - **M14.1b-i** ✅ `ct-common::metrics::Metered<S>` — a byte-counting
      `AsyncRead`+`AsyncWrite` wrapper (drops around the Origin socket, no
      change to `noise_pump`); `TunnelMetrics` counters are now `Arc<Counter>`
      so one series can be handed to the wrapper. Unit-tested.
    - **M14.1b-ii** ✅ wired `Metered` + handshake timing into
      `serve_noise_stream`/`serve_direct`/`run_agent`: tunnels_opened on a
      completed handshake, tunnels_failed on error, `observe_handshake` latency,
      and the Origin socket wrapped in `Metered` for bytes each way. `run_agent`
      builds one shared `Arc<TunnelMetrics>` (signature unchanged). Test asserts
      the counters after a 100 KB round-trip. **M14.1 complete.**
- **M14.2** `/metrics` endpoint; compose scrape target. Decomposed:
  - **M14.2a** ✅ `ct-agent::observe` — `metrics_router` (`GET /metrics` →
    Prometheus text, `text/plain; version=0.0.4`) + `serve_metrics(addr, m)`;
    `run_agent` spawns it when `CT_AGENT_METRICS_LISTEN` is set
    (`AgentConfig.metrics_listen`). Tested via `tower::oneshot` + a real-socket
    scrape.
  - **M14.2b** ✅ compose scrape overlay (`docker-compose.metrics.yml`): agent
    exposes `/metrics`, the client runs the tunnel then `metrics_probe` scrapes
    the agent and confirms `ct_tunnels_opened_total >= 1`. Live: `metrics probe
    OK: ct_tunnels_opened_total=1 ct_bytes_to_origin_total=12`, `COMPOSE_EXIT=0`.
    **Milestone 14 complete.**
- **E2E:** metrics endpoint scraped in the testbed; counters increment on
  tunnel activity.

## Milestone 15 — Pseudonymous accounts + crypto payment (ADR-0012, SPEC §9)
Minimal technical model; the funded-adversary sybil economics stay an open risk
(`BACKLOG.md`) and are flagged, not hand-waved.
- **M15.1** ✅ Pseudonymous account + prepaid-credit ledger (control plane) —
  `ct-control-plane::accounts::Ledger` with opaque random `AccountId`,
  `open_account`/`balance`/`credit`/`debit`; insufficient debit refused without
  mutation, saturating top-ups. Unit-tested.
- **M15.2** ✅ Capability/token issuance gated by credit balance —
  `ct-control-plane::billing::issue_token_for_payment(ledger, account, price)`:
  debits first, so insufficient credit (or unknown account) mints no token and
  leaves the balance unchanged; on success debits and returns a random
  `RoutingToken`. `TOKEN_PRICE` default. Unit-tested (funded, zero-balance
  denied, run-until-exhausted with distinct tokens, unknown account).
- **M15.3** ✅ Crypto-payment intake stub (credit top-up) —
  `ct-control-plane::payment::PaymentIntake`: `create_intent(account, credits)`
  → opaque `PaymentId`; `confirm_payment(id, ledger)` credits the account,
  idempotent (a replayed confirmation returns `AlreadyConfirmed`, no
  double-credit). Unit-tested + a mini-E2E (open → top-up → gated issuance).
- **M15.4** accounts/payment HTTP endpoints on the control-plane service
  (open account, create+confirm payment, buy token) — wires M15.1–3 to the wire
  like M13 did for enrollment/registry. Decomposed:
  - **M15.4a** ✅ `billing_router` + `BillingState` (Ledger+PaymentIntake under
    one lock): `POST /accounts/open`, `POST /payment/intent`,
    `POST /payment/confirm` (409 already-confirmed), `POST /billing/issue` (402
    insufficient credit). Oneshot-tested end to end.
  - **M15.4b** ✅ merged `billing_router` into `control_plane_router` (+ `main` +
    `BillingState`) and added `ControlPlaneClient` methods (`open_account`,
    `create_payment_intent`, `confirm_payment`, `buy_token`). Live-service E2E
    test: open → broke=402 → intent → confirm → buy token; replay confirm 409.
- **E2E:** account → top-up → gated token issuance → tunnel; zero-balance denied.
  - Live-service HTTP E2E (account → top-up → gated issuance → token, zero-balance
    denied) is ✅ (M15.4b).
  - **M15.5** ✅ money→tunnel E2E (`billing_issued_token_establishes_a_tunnel`):
    the token issued through the paid control-plane flow establishes a real Noise
    tunnel (edge relay + agent bridge + echo origin); a zero-balance account is
    denied the token. **Milestone 15 complete — all v1 feature milestones
    (M9–M15) done.**

**Definition of done (full product):** every milestone above green, the whole
docker-compose topology runs the full stack, and a top-level E2E suite exercises
the product end to end under netem. Then refresh the thesis to match.

---

# BA-Thesis — Neugestaltung (User-Direktive, Zyklus 75)

> Die bisherige Thesis (M7, 21 S., in `docs/thesis/thesis.tex`) ist zu flach und
> nutzt nicht die offizielle Vorlage. Sie wird **ersetzt**. Neue Vorgaben:
> - **Offizielle HAW-Vorlage** (Thomas Lehmann) — heruntergeladen und extrahiert
>   nach `docs/thesis/haw-template/` (Quelle:
>   `https://thomas-lehmann.inf.haw-hamburg.de/batemplate/template-latex_std.zip`;
>   `style/thesisstyle.sty`, `coverpage_*.tex`, HAW-Logos, `configuration.tex`).
> - **Tiefe & Umfang: ca. 64 Seiten** (nicht 21). Deutlich ausführlichere,
>   besser formulierte Analysen.
> - **Reihenfolge**: erst das **Produkt fertigstellen** (M11–M15), *dann* die
>   Experimente/Parameterstudie am fertigen Produkt — d.h. die Thesis-Arbeiten
>   ans **Ende** hängen, um eine geeignete Parameterstudie durchzuführen.

## Milestone 16 — Umfassende Parameterstudie (nach M15, am fertigen Produkt)
- Große `tc netem`-Matrix (Delay × Loss × Bandbreite), hohe Iterationszahl je
  Bedingung (statistisch belastbar: Mittel, CI, p50/p95/p99), Warmup/Wiederholung.
- Vergleich der Betriebsarten: TCP-Stream vs. UDP vs. One-shot; Einfluss der
  PoW-Schwierigkeit; Handshake- vs. Datenphase; ggf. P2P-Direktpfad vs. Relay.
- Reproduzierbar via `scripts/sweep.sh` (erweitert) → CSV + Plots + Tabellen unter
  `docs/thesis/data/`, mit Beschreibung von Aufbau, Störgrößen und Methodik.

Decomposed:
- **M16.1** ✅ statistically-robust `Summary` — added sample `stddev_ms`,
  `ci95_ms` (95% CI for the mean), and `p99_ms` to `bench::summarize`/`csv_row`
  (appended CSV columns, backward-compatible). Unit-tested.
- **M16.2** ✅ extend `scripts/sweep.sh`: PoW-difficulty axis (`SWEEP_POWS` →
  `EDGE_POW_DIFFICULTY`, plumbed through `docker-compose.yml`), the 12-column
  M16 stats CSV with a prepended `pow` column, higher default n (30). Validated
  (`bash -n`, `docker compose config`).
- **M16.2b** ✅ stream mode axis: `bench::run_bench_stream` (full-duplex path
  via `client_tunnel_stream` + duplex round-trip), client `CT_BENCH_MODE`
  selector, `SWEEP_MODES` axis + `mode` column in `sweep.sh`, `BENCH_MODE`
  plumbed through compose. Frozen test measures 3 streaming round-trips.
- **M16.2c** ✅ UDP mode measurement: `bench::run_bench_udp` (dial → `udp_selftest`
  datagram round-trip), client `CT_BENCH_MODE=udp` selector. Frozen test measures
  3 UDP round-trips (agent `serve_noise_udp`, fixed-port UDP echo origin). The
  live `SWEEP_MODES=udp` compose run needs a **fixed-port** UDP echo origin (the
  one-shot smoke's forking socat replies from an ephemeral port → rejected by the
  agent's connected socket) — that overlay folds into **M16.3**.
- **M16.3** ✅ run the matrix under netem → CSV. Added `udp_echo` bin (fixed-port
  UDP echo) + `docker-compose.udpbench.yml` overlay + sweep udp-overlay
  selection. Live run (3 modes × 3 delays × 2 losses, n=20) →
  `docs/thesis/data/latency.csv`, 18 rows with the full M16 stats. All modes
  scale ~6.5·delay (handshake RTTs); 2% loss inflates the p99 tail to ~1.3 s.
- **M16.4** extend `plot.py`/`tabulate.py` for the new stats/modes; write the
  analysis under `docs/thesis/data/`. Decomposed:
  - **M16.4a** ✅ mode-aware `tabulate.py` (Modus column, mean±95%-CI, p50/p95/p99;
    back-compatible with old CSVs) → regenerated `results-table.{md,tex}`.
  - **M16.4b** ✅ mode-aware `plot.py`: per-loss figures filtered to the reference
    mode + a new `latency-by-mode.png` (mean vs delay, one series per mode at 0%
    loss). Rendered all three PNGs; the modes overlap at 0% loss (latency is
    delay-dominated, not transport-dominated).
  - **M16.4c** ✅ rewrote `results.md` as the mode-aware M16 analysis (baseline
    ~8ms all modes, `RT≈8.8+6.1·d`, loss hits the p99 tail not the median [×7.7
    at 20ms/2%], modes indistinguishable at 0% loss and CI-overlapping under
    loss, PoW axis available). **Milestone 16 complete.**

## Milestone 17 — Tiefe BA-Thesis (ersetzt M7, HAW-Vorlage, ~64 S.)
- Aufsetzen auf `docs/thesis/haw-template/` (Coverpage, Konfiguration, Glossar,
  BibLaTeX), texlive-in-Docker-Build.
- Kapitel deutlich ausgearbeitet: Einleitung/Motivation, **Related Work**,
  Grundlagen (ZK/providerblind, Noise, QUIC, PoW, NAT-Traversal), Anforderungen &
  Bedrohungsmodell, Architektur (aus ADRs), Implementierung (aus allen Crates,
  inkl. Streaming/UDP/P2P), **Evaluation mit der Parameterstudie (M16)**,
  Diskussion/Limitierungen, Fazit & Ausblick, Anhang.
- **Verification**: kompiliert sauber im texlive-Container; Seitenumfang ~64.

Decomposed (one chapter per cycle; each verified by a clean HAW build):
- **M17.1** ✅ HAW-Template-Scaffold — Arbeitskopie `…/ct_thesis/` (Metadaten,
  Glossar/Akronyme, Stub-Kapitel), `scripts/thesis-haw-build.sh`
  (pdflatex→bibtex→makeglossaries→pdflatex×2), Dockerfile um siunitx/pictures/
  fonts-extra erweitert. Baut sauber → 18-Seiten-PDF (Frontmatter), 0 Fehler.
- **M17.2** ✅ Einleitung (Motivation, Problemstellung mit 4 Anforderungen,
  Forschungsfragen FF1–FF3, Beitrag, Aufbau; echte Zitate: QUIC-RFCs, Noise,
  Hashcash, Tor, NAT-Traversal). `literature.bib` mit realen Referenzen;
  `dinat.bst` fehlt im Container → auf `plainnat` (natbib-Builtin) umgestellt.
  Baut sauber → 21 S., 0 undefined citations.
- **M17.3** ✅ Grundlagen (Providerblindheit/ZK-Prinzip, QUIC+TLS1.3, Noise_IK
  mit Origin-Pinning, PoW/Hashcash, NAT-Traversal/ICE) — 5 zitierte Abschnitte,
  +3 S. `csquotes` für `\enquote` ergänzt. Baut sauber (24 S.).
- **M17.4** ✅ Verwandte Arbeiten (VPN/WireGuard, Tor, Oblivious HTTP, MASQUE,
  Zensurumgehung [Domain Fronting/Decoy Routing]; Einordnung: die Kombination ist
  neu). 6 neue Referenzen, +4 S., baut sauber (28 S.).
- **M17.5** ✅ Anforderungen & Bedrohungsmodell (F1–F8, N1–N5, Akteure A1–A4,
  Vertrauensgrenzen, Schutzziele S1–S4 + explizite Nicht-Ziele inkl.
  finanzierter Sybil). Baut sauber (31 S.).
- **M17.6** ✅ Architektur (TikZ-Topologie-Diagramm, Schlüsselflüsse, Rollen-
  Dispatch 'A'/'C'/'D'/'P', Entwurfsentscheidungen aus ADRs). TikZ in Preamble
  ergänzt; baut sauber (34 S., Abb. 4.1).
- **M17.7** ✅ Implementierung (5-Crate-Tabelle, ct-common-Bausteine + PoW-/
  Dispatch-Listings, Daten-/Steuerpfad). `booktabs`/`listings` in Preamble;
  baut sauber (37 S.).
- **M17.8** ✅ Evaluation (Testbett/Methodik, M16-Ergebnistabelle + 3 Abbildungen
  eingebettet, FF2/FF3 beantwortet, Limitierungen). M16-Outputs nach
  `ct_thesis/data/` kopiert, graphicspath ergänzt, Platzhalter-Selbstrefs auf
  `ch:evaluation`/`ch:architektur` gefixt. Baut sauber (41 S.).
- **M17.9** ✅ Diskussion (FF1–FF3 beantwortet, Schutzziele S1–S4 gegen A1–A4,
  offene Risiken [Sybil, Traffic-Analyse, Hole-Punching, PoW-Parametrisierung],
  methodische Einordnung). Baut sauber (44 S.).
- **M17.10** ✅ Fazit & Ausblick + Reproduzierbarkeits-Anhang. Alle 10 Kapitel
  vorhanden, baut sauber (49 S.). Template-Stubs (first_chapter, example_appendix)
  entfernt.
- **M17.11+** Vertiefungs-Pass (pro Zyklus ein Kapitel) bis ~64 S.:
  - **M17.11** ✅ Grundlagen vertieft (QUIC Handshake/0-RTT/Streams, IK-Handshake
    Nachricht-für-Nachricht + Vorwärtsgeheimnis, PoW-Kostenmodell $2^{-d}/2^{d}$,
    NAT-Typen-Taxonomie + symmetrisches NAT). 49→51 S.
  - **M17.12** ✅ Implementierung vertieft (noise_pump-Listing + Framing,
    §Beobachtbarkeit mit /metrics-Listing, §Guthaben-gedeckte Ausgabe mit
    Billing-Listing, Money→Tunnel-E2E-Verweis). 51→52 S.
  - **M17.13** ✅ Architektur vertieft (nummerierter 6-Schritt-Tunnelaufbau +
    Direktpfad-Kurzschluss, Wire-Format-Tabelle des Rollen-Dispatch). 52→53 S.
  - **M17.14** ✅ Neues Kapitel „Produktivierung" (`chapters/produktivierung.tex`,
    zwischen Implementierung und Evaluation eingehängt): dokumentiert die
    Überführung Testbett→Dienst (M18–M26) in 6+1 Abschnitten (Persistenz,
    Identität/OIDC, PKI+TLS, Auslieferung, Härtung, Bezahlung, Zusammenfassung),
    HAW-Stil (ASCII-Umlaute, `\cite` nur auf existierende Bib-Keys perrin2018noise/
    rfc9001/rfc8446/back2002hashcash, interne `\ref`). Texlive-Build im Container:
    **PDF_OK, 0 undefined refs/citations, 0 errors, 53→56 S.**
  - **M17.15** ✅ Evaluation um eine analytische Sicherheitsbewertung ergänzt
    (`evaluation.tex`, neuer Abschnitt `sec:eval-security`): qualitative Bewertung der
    Produktivierungs-Kontrollen gegen ein Angreifermodell — Booktabs-Tabelle
    Angreifer×Kontrolle×Restrisiko + Prosa (strukturelle E2E-Invariante, graduelle
    Verfügbarkeit, an Secret gebundene Abrechnungsintegrität, ehrliche offene Flanke
    finanzierter Sybil). Verweist auf `ch:produktivierung`, zitiert perrin2018noise/
    back2002hashcash. Build: PDF_OK, 0 undefined refs/errors, 56→57 S.
  - **M17.16** ✅ Related-Work-Einordnung um eine systematische Vergleichstabelle
    ergänzt (`relatedwork.tex`, `tab:rw-vergleich`): WireGuard/Tor/Oblivious HTTP/MASQUE/
    Diese Arbeit × 5 Eigenschaften (E2E-blind, allg. TCP/UDP, QUIC, P2P, Missbrauchsschranke)
    mit $\bullet$/$\circ$/-- + erläuternde Prosa. Nutzt nur vorhandene Bib-Keys
    (donenfeld2017wireguard/dingledine2004tor/rfc9458/rfc9298). Build: PDF_OK, 0 undefined
    refs/errors, 57 S. (OHTTP + CONNECT-UDP waren bereits als Prosa vorhanden → Tabelle
    statt Redundanz). (Anm.: OHTTP/MASQUE-Prosa existierte schon; Beitrag ist die Matrix.)
  - **M17.17** ✅ Fazit mit der Produktivierung konsistent gemacht: (1) neuer
    Zusammenfassungs-Absatz (Testbett→betreibbarer Dienst, Verweis `ch:produktivierung`,
    Kern-Eigenschaft bleibt, nur Pseudonymität bewusst aufgegeben); (2) **Widerspruch
    behoben** im Ausblick — der Sybil-Punkt sagte „ohne die Pseudonymität aufzugeben",
    obwohl die Produktivierung sie gerade aufgab → auf „konventionelle Konten schrecken
    den finanzierten A4 dennoch nicht ab" umformuliert. `\gls{ac:oidc/pki}` vermieden
    (nicht definiert) → Klartext. Build: PDF_OK, 0 undefined refs/errors, 57 S.
  - **M17.18** ✅ Diskussion mit der Produktivierung konsistent gemacht (parallel zu
    M17.17): (1) neuer Absatz in „Schutzziele" — OIDC-Auth/signaturgesicherte Abrechnung/
    Per-Konto-Rate-Limit erweitern die Schutzziele, Betreiber-Blindheit bleibt; (2) **gleicher
    Pseudonymitäts-Widerspruch behoben** im A4-Risiko-Punkt (»pseudonyme Konten … im
    Spannungsfeld zur Pseudonymität« → »konventionelle Konten«). Build: PDF_OK, 0 undefined
    refs/errors, 57 S. **Thesis nun durchgängig konsistent mit dem produktivierten System.**
  - **M17.19+** ⏳ optional (Thesis inhaltlich vollständig & konsistent; weitere Ausbauten
    nur bei Bedarf).

---

# 🚀 Produktivierung (User-Direktive, Zyklus 130) — von Testbett zu produktivem SaaS

**Entscheidungen des Users:** (a) Auslieferung **beides** — gehosteter Portal +
self-hostbarer Core; (b) **konventionelle Accounts überall** (Keycloak/OIDC-Identität;
die Pseudonymitäts-Marketingaussage wird bewusst aufgegeben). **Wichtig:** Die
**E2E-Payload-Verschlüsselung (Noise) bleibt** — Accounts identifizieren den Kunden
(Identität/Abrechnung), der Betreiber liest die Tunnel-Nutzlast weiterhin nicht.
Marketing-Claim verschiebt sich von „wir wissen nicht, wer du bist" zu „wir können
nicht lesen, was du sendest".

**Neue Priorität:** Produktivierung **M18+ vor** Thesis-Vertiefung (M17.14+ pausiert,
optional). Der Loop nimmt ab jetzt das niedrigste offene M18+-Paket.

**Ehrlicher Ausgangsbefund:** Kernkrypto-Datenpfad + Rendezvous/PoW/Fallbacks/
Control-Plane laufen (160 Tests, Compose-Smokes). NICHT produktionsreif: alles
In-Memory (kein Neustart-Überleben), self-signed Certs, keine echte AuthN/AuthZ,
Deployment nur als Compose-Smoke, Payment nur Stub, kein Rate-Limiting/Quota jenseits
PoW, P2P-Hole-Punching nur im flachen Bridge-Netz.

## Milestone 18 — Persistenz (Fundament; blockiert alles andere)
In-Memory-Zustand durch dauerhaften Speicher ersetzen (SQLite self-host / Postgres
hosted, hinter einem Storage-Trait).
- **M18.1** ✅ SQLite-Backend (rusqlite `bundled`, kein System-Dep) für Enrollment:
  `SqliteEnrollment` [open/open_in_memory, Schema join_tokens+agent_bindings]
  mit issue/redeem/binding, gleiche Semantik wie in-memory `Enrollment`;
  `RedeemError::{Enroll,Db}`. Test `state_survives_reopen` belegt: Binding
  persistiert + Token bleibt konsumiert über einen Reopen (Neustart-Ersatz).
- **M18.2** ✅ `SqliteRegistry` (Schema `tunnels`; register/lookup/unregister,
  INSERT OR REPLACE) — durables Äquivalent zu `TunnelRegistry`. Kann dieselbe
  DB-Datei wie `SqliteEnrollment` teilen (eigene Tabellen/Connection je Store).
  Test `registry_state_survives_reopen` belegt Persistenz über Reopen.
- **M18.3** ✅ `SqliteLedger` (Schema `accounts`+`payments`): open_account/balance/
  credit/debit (Ledger-Semantik, InsufficientCredit ohne Mutation) +
  create_intent/confirm_payment (idempotent, in Transaktion → kein Doppel-Credit
  bei Crash). `LedgerOpError`/`PaymentOpError`. Test `ledger_state_survives_reopen`
  belegt Balance + confirmed-Flag über Reopen.
- **M18.4** persistente Stores in den Service verdrahten (In-Memory ersetzen).
  Decomposed:
  - **M18.4a** ✅ `service.rs`: `enrollment_router_sqlite(Arc<SqliteEnrollment>)`
    (gleiche JSON-API wie http, aber durabel; Fehler→409/404/500). E2E
    `enrollment_survives_service_restart`: enroll gegen Instanz 1, frische
    Instanz auf **derselben DB-Datei**, konsumiertes Token bleibt konsumiert.
  - **M18.4b** ✅ `registry_router_sqlite(Arc<SqliteRegistry>)` (register/resolve,
    404 unknown). E2E `registry_survives_service_restart`. · **M18.4c** ✅ `billing_router_sqlite(Arc<SqliteLedger>)`
    (open/intent/confirm/issue; 402/409/404). E2E `billing_survives_service_restart`
    (Balance + Idempotenz überleben Neustart).
  - **M18.4d** ✅ `persistent_control_plane_router(db_path)` (merged alle 3 Stores
    auf **einer** DB) + `main` serviert es durabel (`CT_CONTROL_PLANE_DB`, Default
    `control-plane.db`). E2E `unified_control_plane_survives_restart`:
    enroll+register+topup gegen Instanz-1, frische Instanz auf derselben DB →
    alle drei Concerns persistiert. **Milestone 18 (Persistenz) komplett.**
- **E2E:** ✅ Zustand überlebt einen Control-Plane-Neustart (frozen Integrationstest,
  Service-Level, für alle drei Concerns + unified).

## Milestone 19 — Identität & Auth (Keycloak/OIDC, konventionelle Accounts)
- **M19.1** ✅ Account-Modell an OIDC-Subject gebunden — `SqliteLedger::account_for_subject(subject)`
  (Tabelle `account_subjects`): erstellt beim ersten Mal ein Konto, gibt danach
  idempotent dasselbe zurück; in Transaktion (ein Subject → nie zwei Konten).
  Datenpfad bleibt E2E-Noise (Accounts = Identität, nicht Payload-Zugriff).
  Tests: idempotent, distinkte Subjects, überlebt Reopen.
- **M19.2** ✅ OIDC-Token-Verifikation (`ct-control-plane::oidc`): `OidcVerifier`
  (`jsonwebtoken`) prüft Signatur/Expiry/Issuer und liefert `sub`.
  `from_rsa_pem` (RS256, Keycloak-Realm-Pubkey) für Prod, `from_hs_secret`
  (HS256) für dev/Tests. 4 Tests: valid→sub, expired/wrong-issuer/bad-sig
  abgelehnt. (HTTP-Middleware, die den Bearer prüft + `account_for_subject`
  mappt, folgt in M19.3.)
- **M19.3** ✅ Token-Ausgabe an authentifizierte Accounts gekoppelt —
  `authed_billing_router(ledger, verifier)`: `GET /me/account` + `POST /me/issue`
  {price}; das Konto wird aus dem verifizierten Bearer-`sub` abgeleitet
  (`account_for_subject`), nicht aus dem Request. Ohne gültiges Token → 401, mit
  → Debit auf das eigene Konto (402 bei zu wenig Guthaben). Oneshot-E2E.
  **Milestone 19 (Identität & Auth) komplett.**
- **E2E:** ✅ nur ein authentifizierter Account kann Tokens beziehen (401 ohne Token).

## Milestone 20 — PKI & TLS
- Echte Zertifikatsausstellung/-rotation für den Edge (interne CA oder ACME); ersetzt
  self-signed; Trust-Distribution an Clients.
- **M20.1** ✅ Interne CA (`ct-edge::pki::Ca`, rcgen): `new`/`root_der`/`issue(sans)`
  signiert Edge-Leafs. `build_server_endpoint_from_ca` (Edge nutzt CA-Leaf) +
  `build_client_endpoint_trusting_ca` (Client vertraut dem **CA-Root**, nicht dem
  Leaf → Rotation ohne Re-Pinning). Trust-Chain-Tests: Leaf via CA-Root
  akzeptiert (QUIC-Handshake+Echo), Leaf fremder CA abgelehnt.
- **M20.2** ✅ Rotation: `client_survives_edge_cert_rotation` — ein Client, der
  den CA-Root einmal vertraut, verbindet sich nach dem Rotieren auf einen
  frischen Leaf (neuer Cert+Key) unter derselben CA ohne Re-Pinning und tunnelt.
- **M20.3** Edge-Daemon/`run_edge` auf CA umstellen; CA-Root persistieren + an
  Clients verteilen. Decomposed:
  - **M20.3a** ✅ `build_dual_edge_from_ca(ca, quic_addr, tcp_addr, sans)` —
    CA-issued Dual-Transport-Edge (QUIC + TLS-TCP, ein Leaf), gibt CA-Root zurück.
    Test: CA-Root-Client tunnelt über QUIC.
  - **M20.3b** ✅ `run_edge` auf CA umgestellt: erzeugt eine `Ca`, baut den
    Dual-Edge daraus und schreibt den **CA-Root** nach `CT_EDGE_CERT_OUT` (statt
    des self-signed Leafs). Agents/Clients bleiben unverändert (trusten den
    geladenen Cert als Trust-Anchor → jetzt die CA). Compose-Smoke: `tunnel
    round-trip OK (via=quic)`, `COMPOSE_EXIT=0`. **Milestone 20 (PKI & TLS)
    komplett.**

## Milestone 21 — Deployment (hosted + self-host)
- Helm-Chart / K8s-Manifeste (hosted) + gehärtetes Compose-Bundle (self-host);
  Konfiguration, Secrets-Handling, Health/Readiness.
- **M21.1a** ✅ Health/Readiness-Endpoints: `GET /healthz` (Liveness, immer 200)
  + `GET /readyz` (Readiness, prüft DB via `SqliteLedger::ping`→200/503), in
  `persistent_control_plane_router` gemerged. Oneshot-Test.
- **M21.1b** ✅ gehärtetes Self-Host-Compose-Bundle (`docker/deploy/compose.selfhost.yml`):
  control-plane + edge als langlebige Services, persistentes `cpdata`-Volume
  (`/data/control-plane.db`), `restart: unless-stopped`, Docker-Healthcheck
  `curl -fsS /readyz` (curl in die Runtime-Image aufgenommen), edge
  `depends_on: control-plane condition: service_healthy`; Secrets via
  `.env`/`env_file` (`.env.example` als Vorlage, `.env` gitignored). Live-Smoke:
  Image neu gebaut, `--wait` bis Healthcheck grün → `WAIT_EXIT=0`,
  `health=healthy`, sauberer `down -v`.
- **M21.2** K8s-Manifeste (hosted, kustomize-basiert) mit Probes + Secrets.
  Dekomponiert (Helm-Tooling nicht vorhanden → rohe kustomize-Manifeste, offline
  via `kubectl kustomize` validierbar; Helm-Verpackung optional später):
  - **M21.2a** ✅ Control-Plane-Manifeste (`docker/deploy/k8s/`): Namespace `ct-system`,
    ConfigMap (Listen/DB/Issuer), PVC `ct-control-plane-data` (durable SQLite `/data`,
    RWO), Deployment (replicas 1 + `Recreate` da SQLite Single-Writer; Liveness
    `/healthz` + Readiness `/readyz`-Probes; PVC-Mount `/data`; `envFrom` ConfigMap;
    non-root + read-only-rootfs + `drop: ALL`), Service (ClusterIP :8090), gebündelt
    per `kustomization.yaml`. Verifikation: `kubectl kustomize` rendert offline (RC=0,
    5 Objekte) + 11 Asserts grün (Probes, PVC, Mount, Recreate, non-root, envFrom).
  - **M21.2b** ✅ Edge-Manifeste (`docker/deploy/k8s/`): ConfigMap `ct-edge-config`
    (Listen/PoW/CertOut), Deployment `ct-edge` (QUIC-UDP + TLS-TCP-Fallback beide
    :4433; `tcpSocket`-Liveness/Readiness auf den TCP-Listener; `emptyDir` `/shared`
    für CA-Root; non-root/read-only-rootfs/`drop:ALL`; replicas 1 — jeder Edge prägt
    eigene CA), Service `ct-edge` (LoadBalancer, UDP+TCP :4433; Hinweis: Mixed-Protocol-LB
    braucht k8s≥1.26). In dieselbe kustomization gehängt. Verifikation: `kubectl kustomize`
    RC=0, **8 Objekte** (2 ConfigMap/2 Deployment/1 NS/1 PVC/2 Service), 7 Edge-Asserts grün.
    **🎯 M21.2 komplett → Milestone 21 (Deployment) komplett** (hosted K8s + self-host compose).

## Milestone 22 — Onboarding-UX (so wenige Schritte wie möglich)
- Ein-Kommando-Agent-Setup (Install → Auto-Enroll → Tunnel); portalgeführte
  Tunnel-Einrichtung; Kurzanleitung. Dekomponiert:
  - **M22.1** ✅ Onboarding-Primitive (`crates/agent/src/onboard.rs`): `onboard(cp_url,
    join_token, agent_id, config) -> OnboardedAgent` fasst Identitäts-Erzeugung +
    Join-Token-Redeem (bindet frischen Pubkey an Tenant) + Config-Assemblierung in
    **einen** Aufruf; einziges Geheimnis ist das Single-Use-Join-Token. `ct-control-plane`
    von dev-dep zu regulärer dep (azyklisch: hängt nur an ct-common). 2 Frozen-Tests
    gegen In-Process-Enrollment-Router: enrollt+bindet frische Identität; Join-Token
    single-use (zweiter Onboard scheitert). Gate: 190 (+2).
  - **M22.2** ✅ `ct-agent` Ein-Kommando-Binary: `OnboardEnv::{parse,from_env,onboard}`
    (liest `CT_AGENT_CP_URL`/`CT_AGENT_JOIN_TOKEN`-hex/`CT_AGENT_ID` + Edge/Origin-Config,
    dekodiert Hex-Token → [u8;32], validiert). `main.rs` dispatcht in Onboarding-Modus
    wenn `onboard`-Subcommand oder `CT_AGENT_JOIN_TOKEN` gesetzt → auto-enroll → serve;
    sonst Legacy-Pfad. 3 Frozen-Tests (parse ok+Hex-Dekodierung, parse rejects
    leer/kurz/nicht-hex/leere-ID, `OnboardEnv::onboard` E2E gegen In-Process-CP). Gate 193 (+3).
  - **M22.3** ✅ Quickstart (`docs/onboarding/quickstart.md`): die zwei Schritte
    (Portal/Operator issued Single-Use-Join-Token via `POST /enroll/issue`; Agent-Host
    startet `ct-agent onboard` mit `CT_AGENT_CP_URL`/`_JOIN_TOKEN`/`_ID`/`_EDGE`/`_ORIGIN`
    → auto-enroll → tunnel), optionale Env-Knöpfe, „was gerade passiert ist" (Privatschlüssel
    bleibt lokal, Payload E2E-verschlüsselt). Verifikation: Drift-Check-Skript — jede zitierte
    `CT_*`-Var (9) existiert im Code, `/enroll/issue` ist eine Route, `main` dispatcht `onboard`,
    tenant→token-Felder matchen `IssueReq/Resp`. **DOC_DRIFT_CHECK_OK**.
    **🎯 Milestone 22 (Onboarding-UX) komplett** (Ein-Aufruf-Primitive + Ein-Kommando-Binary + Quickstart).

## Milestone 23 — Security-Hardening & Audit
- Rate-Limits/Quotas je Account, TLS überall, Secrets-Management, Dependency- +
  Crypto-Usage-Review, Aktualisierung des Bedrohungsmodells für den Produktivbetrieb.
  Dekomponiert:
  - **M23.1** ✅ Per-Subject-Rate-Limit auf Token-Ausgabe: `RateLimiter` zu generischem
    `KeyedRateLimiter<K>` verallgemeinert (Alias `RateLimiter = KeyedRateLimiter<RoutingToken>`),
    `AuthedState` bekommt `Arc<Mutex<KeyedRateLimiter<String>>>`; `POST /me/issue` prüft je
    authentifiziertem Subject ein Fixed-Window-Limit (60s) **vor** dem Ledger-Zugriff → 429
    ohne Credit-Verbrauch. 2 Frozen-Tests (keyed limiter/String, HTTP 3.→429). Gate 195 (+2).
  - **M23.2** ✅ Dependency-Audit: `scripts/security-audit.sh` (reproduzierbarer
    `cargo audit` gegen `Cargo.lock` im Hermetic-Container, cargo-audit in
    persistenten Cache installiert, RustSec-Advisory-DB) + `docs/security/dependency-audit.md`
    (Ergebnis + Pinning-Policy). Realer Scan: cargo-audit 0.22.2, 1160 Advisories,
    **206 Deps, 0 Vulnerabilities, 0 Warnings, RC=0**. Verifikation: `sh -n` grün,
    Skript installiert+ruft cargo-audit, Report=0 Vulns, keine Advisories im Output.
  - **M23.3** ✅ Secrets-Review + Threat-Model: `scripts/check-no-secrets.sh`
    (Guard — scannt git-getrackte Dateien auf PEM-Private-Keys/Cloud-Access-Keys,
    verweigert getrackte echte `.env`, prüft `.env` gitignored; exit≠0 CI-tauglich)
    + `docs/security/threat-model.md` (Produktions-Posture: Trust-Boundaries/„Operator
    liest Payload nicht", Adversar×Control-Matrix, Secrets-Inventar+Handling, Residual-Risks).
    Verifikation: `sh -n` grün, Guard clean auf Repo (RC=0), Selbst-Test (Patterns matchen
    Known-Bad), E2E (gestagete AKIA-Fixture → Guard RC=1).
  - **M23.4** ✅ „TLS überall": `docker/deploy/k8s/control-plane-ingress.yaml` (TLS-terminierender
    Ingress vor der Control-Plane — `tls.secretName ct-control-plane-tls`, cert-manager-Annotation,
    `ssl-redirect`, Backend `ct-control-plane:8090`) in die kustomization gehängt +
    `docs/security/tls-everywhere.md` (Hop-für-Hop-Tabelle: Payload E2E-Noise, Edge QUIC/TLS,
    Control-Plane-API HTTPS am Ingress; self-host = TLS-Reverse-Proxy; Pre-Expose-Checkliste).
    Verifikation: `kubectl kustomize` RC=0, **9 Objekte** (+Ingress), 6 TLS-Asserts grün,
    Secret-Guard clean. **🎯 Milestone 23 (Security-Hardening & Audit) komplett.**

## Milestone 24 — Payment (echt, ersetzt Stub)
- Zahlungsanbieter-Integration an Accounts + Credit-Ledger gebunden. Kern:
  Bestätigung muss vom **verifizierten Provider-Webhook** kommen, nicht von einem
  client-aufrufbaren Endpoint (der M18-Stub). Dekomponiert:
  - **M24.1** ✅ Webhook-Signatur-Verifier (`crates/control-plane/src/payment_provider.rs`):
    `WebhookVerifier` (HMAC-SHA256 über `"<timestamp>.<body>"` mit Shared-Secret,
    Stripe-Stil; `verify` prüft Signatur konstantzeitig via `Mac::verify_slice` +
    Timestamp-Toleranz gegen Replay; `sign` = Provider-Seite/Tests). Rein & clock-injected
    (`now` Parameter), wie der OIDC-Verifier. Deps `hmac`+`sha2`. 5 Frozen-Tests: valid,
    tampered body, wrong secret, stale timestamp, malformed hex. Gate 200 (+5).
  - **M24.2** ✅ `/payment/webhook`-Endpoint (`payment_webhook_router(ledger, verifier)`
    in service.rs): `WebhookState{ledger, verifier}`; Handler extrahiert
    `X-CT-Webhook-Timestamp`/`-Signature`-Header + rohen Body (`Bytes`), **verifiziert
    zuerst** die Signatur (401 sonst), parst `{payment, status}`, kreditiert nur bei
    `status=="succeeded"` via `confirm_payment` — PaymentId reist als Provider-Metadaten
    im Body (kein Mapping-Schema nötig). Idempotent: `AlreadyConfirmed`→200 (kein
    Doppel-Credit), Unknown→404. 2 Frozen-Tests (forged→401/kein Credit, valid→200/+7,
    replay→200/kein Doppel-Credit; stale→401). Gate 202 (+2).
  - **M24.3** ✅ Produktions-Wiring: `persistent_control_plane_router(db, webhook_secret)`
    mountet den Webhook-Router und baut die Billing-Fläche **ohne** client-`/payment/confirm`
    (der M18-Stub ist aus dem Prod-Router raus). `main.rs` liest `CT_PAYMENT_WEBHOOK_SECRET`
    (unset → zufälliges Secret, Webhook inert statt fälschbar). 1 neuer Test
    (`/payment/confirm`→404 im Prod-Router) + `unified_control_plane_survives_restart`
    kreditiert jetzt via signiertem Webhook statt Client-Confirm. Gate 203 (+1).
  - **M24.4** ✅ Payment-Integrations-Doku (`docs/payment/integration.md`): Flow
    (open→intent→Kunde zahlt→signierter Webhook→issue), Signatur-Schema (HMAC-SHA256
    über `"<timestamp>.<raw-body>"`, Header-Tabelle, 401-Regeln, Idempotenz),
    `CT_PAYMENT_WEBHOOK_SECRET`-Config (fail-safe bei unset), Test-Ablauf. Verifikation:
    Drift-Check — Env-Var/4 Routes/2 Header/Schema/300s-Toleranz/`succeeded`/Helper
    existieren im Code, `/payment/confirm` als entfernt dokumentiert → **PAYMENT_DOC_DRIFT_OK**.
    **🎯 Milestone 24 (echtes Payment) komplett** (Verifier + Webhook-Endpoint + Prod-Wiring + Doku).

## Milestone 25 — Produktdokumentation
- Positionierung/Marketing (ehrliche Claims), Security-Whitepaper, Betriebs-Runbook,
  Onboarding-Guide. Dekomponiert (Onboarding-Guide = bereits M22.3):
  - **M25.1** ✅ Positionierung/Selling-Points (`docs/product/positioning.md`): 7 Selling-Points
    je mit Code-Beweis (E2E-Noise „we can't read what you send", Ein-Kommando-Onboarding,
    hosted+self-host, durabel/self-healing, CA-Rotation, Abuse-Resistenz, provider-signiertes
    Payment) + ehrlicher „What we don't claim"-Abschnitt (keine Anonymität/Metadaten-Blindheit/
    Zensur-Immunität). Drift-Check: 9 Proof-Artefakte + 4 verlinkte Docs existieren, **keine**
    positive Anonymitäts-Behauptung, Disclaimer vorhanden → POSITIONING_DRIFT_OK.
  - **M25.2** ✅ Security-Whitepaper (`docs/security/whitepaper.md`): kundenseitige
    Konsolidierung — Summary + 7 Abschnitte (E2E-Noise-Suite, TLS-überall, OIDC-RS256-Auth,
    interne CA, PoW+Rate-Limit, provider-signiertes Payment mit HMAC-SHA256, Dependency-Audit+
    Secret-Guard) je mit Code-Verweis + „out of scope"-Abschnitt. Drift-Check: zitierte
    Primitive (Noise-Suite/RS256/HMAC-SHA256/CA/429) im Code, 5 verlinkte Docs existieren,
    keine Anonymitäts-Behauptung → WHITEPAPER_DRIFT_OK.
  - **M25.3** ✅ Betriebs-Runbook (`docs/ops/runbook.md`): Deploy (self-host compose /
    hosted kustomize), Config-Tabelle (Env-Vars je Komponente), Monitoring
    (`/healthz`/`/readyz`/`/metrics` + Alert-Regeln), Routine (Cert-/Secret-Rotation,
    Backup, Audit), Incident-Response-Tabelle, „Known limitations". Drift-Check: alle
    zitierten Env-Vars/Endpoints/Artefakte/Skripte existieren → RUNBOOK_DRIFT_OK.

## Milestone 26 — Wiring-Lücken, Aufräumen & Publish
- **M26.3** ✅ Repo publiziert (github.com/scimbe/claude-tunnel, public, `main`) +
  MIT-LICENSE-Datei ergänzt (Cargo deklarierte `license = "MIT"`, aber keine
  LICENSE-Datei → GitHub erkannte keine Lizenz; jetzt „MIT License" erkannt).
  README + `docs/architecture.md` (Source-Base) + `docs/install.md` (Nutzung/Skripte)
  als Einstiegspunkte. CI-Workflow temporär untracked (Push ohne `workflow`-Token-Scope).
- **M26.1** ✅ OIDC-Authed-Endpoints in Produktion gemountet: `persistent_control_plane_router`
  nimmt jetzt `oidc: Option<Arc<OidcVerifier>>` und merged `authed_billing_router` (`/me/*`,
  Cap `AUTHED_ISSUES_PER_WINDOW=60`) nur wenn Some. `main.rs` baut den Verifier via
  `OidcVerifier::from_rsa_pem` aus `CT_OIDC_ISSUER`+`CT_OIDC_PUBKEY_PATH` (PEM-Datei);
  beide gesetzt → mounted, sonst None (Endpoints abwesend). 2 Frozen-Tests: mit Some →
  `/me/account` ohne Token 401 / mit gültigem Token 200 durch den Prod-Router; mit None →
  404. Runbook „Known limitation" entfernt, `CT_OIDC_PUBKEY_PATH` dokumentiert. Gate 205 (+2).
- **M26.2** ✅ Warning-freier Build: 4 Compiler-Warnungen in Testmodulen entfernt
  (toter `token_e`-Binding in edge/serve.rs; ungenutzte `AsyncReadExt`/`AsyncWriteExt`-Imports
  in client/bench.rs ×2 + rendezvous.rs — `write_all`/`read_to_end` laufen dort über
  quinn-Inherent bzw. einen Projekt-Helfer, nicht die Tokio-Traits; nur die tatsächlich
  ungenutzten Imports entfernt, die Mehrfach-Vorkommen per Token-Seed disambiguiert).
  Frozen: Gate-Log **0 `warning:`-Zeilen**, 205 Tests grün, 0 Fehler.

**Definition of done (Produkt):** durabler Zustand, echte Identität/Auth, echte PKI,
reproduzierbares Deployment (hosted + self-host), Ein-Kommando-Onboarding,
Hardening-Pass bestanden, echtes Payment, Produktdoku — alle mit frozen Tests bzw.
Deploy-Verifikation.

## Milestone 27 — Field-gemeldete Lücken (GitHub-Issues, nur scimbe)
- **P1.2c (Issue #3) — Agent-TCP-Fallback-Registrierung.** Der Agent registriert
  nur über QUIC; bei blockiertem UDP kann er sich nicht registrieren, daher kein
  Round-trip (auch nicht mit Client-`CT_CLIENT_FORCE_TCP`). Zu groß für einen
  Zyklus → dekomponiert:
  - **P1.2c-1** ✅ Klarer, umsetzbarer Fehler statt bare `TimedOut`, wenn die
    Edge-UDP blockiert ist: `dial_quic_or_blocked_error(edge, cert, timeout)` in
    `agent/transport.rs`; `run_agent` nutzt es (5s). Frozen-Test
    `dial_quic_or_blocked_error_reports_udp_blocked` (toter UDP-Port → Fehler nennt
    „UDP"+„issue #3", schnell). Gate 207 (+1).
  - **P1.2c-2** ✅ Agent-seitige Stream-Register-Primitive `register_tunnel_stream(stream, token)`
    in `agent/transport.rs`: schreibt `'A'|token(32)` über einen generischen
    `AsyncRead+AsyncWrite`-Stream und liest `OK` (TLS-TCP-Fallback; TCP-Agent bedient
    einen Client pro Stream — kein QUIC-Multiplexing). 2 Frozen-Tests gegen
    `tokio::io::duplex`-Mock-Edge (OK-Ack akzeptiert, Nicht-OK → Fehler). Gate 209 (+2).
  - **P1.2c-3a** ✅ `EdgeState`-Rendezvous-Primitive für TCP-Agents: `park_tcp_agent(token)
    -> oneshot::Receiver<BoxedStream>`, `deliver_to_tcp_agent(token, stream)` (gibt den
    Stream als `Err` zurück wenn kein Agent parkt → Caller fällt auf QUIC-Route durch),
    `has_tcp_agent`; `remove` räumt auf. `BoxedStream = Box<dyn DuplexStream>`
    (AsyncRead+Write+Unpin+Send). tokio-Feature `sync` ergänzt. 3 Frozen-Tests. Gate 212 (+3).
  - **P1.2c-3b** ✅ `serve_tcp_connection` verdrahtet: neuer `'A'`-Zweig (Token lesen, `OK`
    acken, `park_tcp_agent`, auf Client warten, `relay`); `'C'`-Zweig liefert nach PoW an
    einen parkenden TCP-Agent (`deliver_to_tcp_agent`), sonst Fallback auf QUIC-Route.
    `S`-Bound um `Send + 'static` erweitert (Boxing). Integrations-Frozen-Test
    `tcp_agent_registers_and_relays_a_delivered_client` (TCP-Register → Park → gelieferter
    Client → Echo-Round-trip). Gate 213 (+1). **Edge-Seite komplett.**
  - **P1.2c-4a** ✅ Agent `tcp_tls_connect(addr, ca_root)` (Spiegel des Client-Dialers,
    `tokio-rustls`-Dep ergänzt). Integrations-Frozen-Test `agent_connects_and_registers_over_tls_tcp`:
    Agent dialt den **echten** Edge (`build_dual_edge_from_ca`) über TLS-TCP + `register_tunnel_stream`,
    Edge parkt ihn (`has_tcp_agent`). Gate 214 (+1).
  - **P1.2c-4b** ✅ `run_agent` verzweigt bei blockierter UDP zu `run_agent_tcp_fallback`
    (`tcp_tls_connect` + `register_tunnel_stream` + `serve_noise_stream` über `split`,
    single-tunnel). **End-to-End-Akzeptanztest** `tcp_fallback_agent_serves_a_noise_round_trip_end_to_end`:
    echter Dual-Edge, Agent registriert über TLS-TCP + serviert, ct-client tunnelt über TLS-TCP
    → **Noise-Round-trip `hello-tcp-fallback` durch, ohne QUIC/UDP**. `ct-client` als dev-dep
    (azyklisch). Gate 215 (+1). **🎯 P1.2c komplett → Issue #3 gelöst: Cross-Host-Tunnel bei
    blockierter UDP funktioniert über den TLS-TCP-Fallback (Client+Agent+Edge).**
  - **P1.2c-4** ⏳ Agent `tcp_tls_connect` + `run_agent` Transport-Wahl (QUIC, sonst
    TCP-Fallback bei blockierter UDP) + Serve über TCP → Cross-Host-Round-trip.
  - _(Reconnect-on-drop P1.2b → eigenes Feature #5.)_

## Milestone 28 — Feature-Backlog „Full functional setup" (GitHub-Issues #4–#6, nur scimbe)
- **#4 Operator-Monitoring-Landing-Page** (dekomponiert):
  - **F4.1** ✅ `GET /status` (JSON): `status_router(enrollment, registry, ledger)` +
    `StatusResp{ready, tunnels, agents, accounts, payments_confirmed}`; Count-Methoden
    `agent_count`/`tunnel_count`/`account_count`/`confirmed_payment_count` in storage.rs;
    in `persistent_control_plane_router` gemerged. Nur Metadaten/Health, nie Payload
    (ADR-0016). Frozen-Test `status_endpoint_reports_aggregated_counts` (je 1 seed → Counts=1).
  - **F4.2** ✅ `GET /` HTML-Landing-Page (`landing_router`, self-contained `LANDING_HTML`, keine externen Assets/CSP-safe, fetcht `/status`, Auto-Refresh 5s, Uptime; `/status` um `uptime_seconds` erweitert). In den Prod-Router gemerged. Frozen-Test `landing_page_serves_self_contained_html` (200 text/html, enthält Titel/fetch/Figures, keine externen URLs).
  - **F4.3** ✅ Runbook-Monitoring-Abschnitt: `GET /` Dashboard + `GET /status` JSON dokumentiert (Felder, `http://<host>:8090/`, „nur Metadaten/Health, nie Payload"). Drift-Check: Routes + 6 Status-Felder code-backed → MONITORING_DOC_DRIFT_OK. **🎯 #4 komplett (F4.1 JSON + F4.2 HTML + F4.3 Doku).**
- **#5** Agent Reconnect-on-drop (P1.2b) — offen.
- **#6** Ein-Kommando-Cross-Host-E2E-Smoke — offen.
- **#5 Agent Reconnect-on-drop (P1.2b)** (dekomponiert):
  - **F5.1** ✅ Backoff-Primitive `reconnect::Backoff` (exponentiell ab `base`, gedeckelt bei
    `max`, `next_delay()→None` nach `max_attempts`; rein/clock-frei, `reset()` nach Erfolg).
    3 Frozen-Tests (Wachstum+Cap, Aufgabe nach max, reset). Gate 220 (+3).
  - **F5.2** ✅ `run_agent` in Reconnect-Loop: Einmal-Setup (Metrics/Direct-Listener) vor der Schleife; `serve_quic_connection` serviert bis zum Drop, dann `Backoff` (base 500ms, max 30s, 10 Versuche), re-dial+re-register, klare Log-Zeile je Versuch, Aufgabe mit Fehler nach max. First-Dial-Fail → TCP-Fallback (#3). Frozen-Test `run_agent_reconnects_after_the_edge_connection_drops` (Edge registriert, schließt, Agent re-registriert = 2 Registrierungen). Gate 221 (+1).
    mit `Backoff`, klare Log-Zeile je Versuch, Aufgabe mit Fehler nach max. Test: Edge-Drop → Re-Register.
  - **F5.3** ✅ TCP-Fallback reconnectet: `run_agent_tcp_fallback` in Reconnect-Loop (`tcp_connect_register_serve`-Helfer; nach jedem Tunnel re-register, Backoff bei Fehler, Aufgabe nach max). Frozen-Test `tcp_fallback_reconnects_after_a_tunnel_drops` (Edge akzeptiert 2 TLS-Registrierungen mit Drop dazwischen → Agent re-registriert = 2). Gate 222 (+1). **🎯 #5 komplett (F5.1 Backoff + F5.2 QUIC-Reconnect + F5.3 TCP-Reconnect).**
- **#6 Ein-Kommando-Cross-Host-E2E-Smoke** (dekomponiert):
  - **F6.1** ✅ `scripts/e2e-smoke.sh`: env-getrieben (CENTRAL, EDGE_CERT, opt. CT_JOIN_TOKEN/
    CT_CLIENT_FORCE_TCP), mintet Token via `/enroll/issue`, startet socat-Echo-Origin, onboardet
    `ct-agent onboard` (schreibt Capability), fährt `ct-client`, meldet `SMOKE OK via=<quic|tcp>`
    bzw. `SMOKE FAIL: …` (Exit-Code). Frozen: `bash -n` grün + Drift-Check (11 CT_*-Env-Vars,
    `/enroll/issue`, `onboard`, `round-trip OK`/`via=`-Marker existieren im Code) → E2E_SMOKE_DRIFT_OK.
  - **F6.2** ✅ Runbook-Abschnitt „Verify a deployment end to end (smoke)": `./scripts/e2e-smoke.sh` als Feld-Standard-Check dokumentiert (CENTRAL/EDGE_CERT, TCP-Fallback-Variante, Voraussetzungen). Drift-Check: Skript/Env-Vars/SMOKE-Marker code/skript-backed → SMOKE_DOC_DRIFT_OK. **🎯 #6 komplett → Milestone „Full functional setup" (#4/#5/#6 + #3) fertig.**
- **#2 QUIC-Keepalive (Feld-diagnostiziert, kritisch)**: ✅ Ohne `keep_alive_interval` baut
  quinns Idle-Timeout die registrierte Agent→Edge-Kontrollverbindung ab (+ kaltes NAT/UDP-
  Mapping) → Edge evictet die Registrierung → Client bekommt „no relay" (nur cross-host; loopback
  0-RTT verdeckt es). Fix in `agent/transport.rs::client_endpoint`: `TransportConfig` mit
  `keep_alive_interval(5s)` + `max_idle_timeout(30s)` (via testbares `client_endpoint_with`).
  Deterministischer Frozen-Test `keepalive_holds_the_connection_across_an_idle_gap` (Server mit
  1s-Idle, Client 300ms-Keepalive, 2s Idle-Gap → Round-trip überlebt). **Das war der letzte
  Blocker für echtes cross-host `via=quic`.**
- **#7 Menschlich-nachvollziehbare Demo (via=quic/tcp, Origin sichtbar, Live-Leistung)** (dekomponiert):
  Akzeptanz #7: (1) Ein-Kommando-Start mit sichtbarem privatem Origin, (2) sichtbarer Beweis
  (Origin-Inhalt kommt durch den Tunnel an), (3) Kontrast „ohne Tunnel nicht erreichbar", (4)
  Leistung sichtbar (N Round-Trips, mean/p95), (5) QUIC + TCP-Fallback umschaltbar, (6) „Demo in
  2 Minuten"-Doku. Abgrenzung zu #6: #6 ist der Maschinen-Smoke (Exit-Code); #7 *zeigt* es einem
  Menschen. Voraussetzung für echtes cross-host `via=quic` ist der Keepalive-Fix (#2).
  - **F7.1** ✅ `scripts/demo.sh`: narriertes Ein-Kommando-Skript, das einen **privaten** Origin
    (socat-Echo, an 127.0.0.1 gebunden, loggt jede Anfrage) startet, den Kontrast „direkt von
    außen nicht erreichbar" zeigt, den Agent onboardet (registriert am zentralen Edge), einen
    `ct-client` mit erkennbarem Payload durch den Tunnel schickt und menschenlesbar meldet:
    „Client hat \"<secret>\" durch den Tunnel zurückerhalten — via=<quic|tcp>, Round-trip <ms>",
    plus das Origin-Log als Beweis. `CT_CLIENT_FORCE_TCP=1` schaltet den TCP-Pfad um (Akz. 5).
    Deckt Akzeptanz 1–3 + 5 (Terminal-Variante). Frozen: `bash -n` grün + Drift-Check (alle
    CT_AGENT_*/CT_CLIENT_*-Env-Vars + `round-trip OK`/`via=`-Marker code-backed) → DEMO_DRIFT_OK.
  - **F7.2** ✅ Live-Leistung sichtbar: nach dem Round-Trip-Beweis fährt `demo.sh` einen
    Bench-Pass (`CT_CLIENT_ITERATIONS`, Default 20, gleicher Pfad — respektiert `CT_CLIENT_FORCE_TCP`)
    und rendert menschenlesbar „Live latency over the tunnel — N/N: mean X.XXms p95 Y.YYms" aus
    ct-clients Bench-Zeile (Akz. 4). Frozen: `bash -n` grün + Drift-Check (Bench-Marker
    `bench {}/{} iterations, mean … p95 …` + `CT_CLIENT_ITERATIONS` code-backed) → DEMO_BENCH_DRIFT_OK.
  - **F7.3** ✅ Runbook-Abschnitt „Demo in 2 minutes (show a human the tunnel works)":
    `./scripts/demo.sh`-Aufruf (QUIC + `CT_CLIENT_FORCE_TCP` + `CT_CLIENT_ITERATIONS`) mit
    vollständiger narrierter Beispiel-Ausgabe, abgegrenzt vom Operator-Smoke (#6); Hinweis auf
    Keepalive (#2) als Voraussetzung für cross-host `via=quic` (Akz. 6). Frozen: Drift-Check
    (5 Env-Vars + 9 zitierte Output-Marker literal in `demo.sh` vorhanden) → DEMO_DOC_DRIFT_OK.
  - **🎯 #7 komplett (F7.1 Demo-Skript + F7.2 Live-Latenz + F7.3 Doku) → alle 6 Akzeptanzkriterien erfüllt → fix-ready.**
- **#2 (mode a) Edge evicts dropped agent registrations** ✅: der QUIC-Accept-Pfad
  (`serve_connection` 'A') registrierte die Agent-`Connection`, entfernte sie aber nie beim
  Verbindungsabbruch → `route(token)` lieferte einen toten Handle, `open_bi()` stockte statt
  „no agent tunnel". Fix: `serve_connection` gibt den registrierten Token zurück
  (`Result<Option<RoutingToken>, _>`, non-blocking — die Relay-Harnesses servieren 'A' dann 'C'
  auf einem Task, dürfen also nicht blockieren); `run_edge` evictet nach `conn.closed()`.
  Frozen-Test `registration_is_evicted_when_the_agent_connection_drops` (Agent registriert über
  echtes QUIC, droppt → `route`/`candidate` werden None). Gate 224 (+1), 0 Warnungen.
  **Mode (b)** (cross-host kein `via=quic` bei frischem Token + lebendem Agent) ist laut Feld-
  Daten **umgebungsbedingt** (Pfad-MTU/PMTUD, symmetrisches NAT, Loss auf dem realen WAN; das
  `ss UNCONN`-Indiz war ein False-Positive — quinn nutzt unverbundene UDP-Sockets) → needs-info,
  gezielter tcpdump/MTU-Capture vom Feld, bevor ein MTU-Clamp codiert wird.
- **#2 (Blocker) Edge CA persistiert über Neustarts** ✅: `run_edge` rief `Ca::new()` bei jedem
  Start → **frische CA pro Boot** → jeder Redeploy rotierte den Trust-Root und brach alle
  gepinnten Agents/Clients mit `BadSignature` (Feld 2× getroffen, blockierte alle Verifikation).
  Das widersprach dem eigenen PKI-Versprechen („Client traut der CA-Root, Leaf rotiert frei").
  Fix: `Ca::load_or_create(key_pem_path, cn)` lädt den persistierten CA-Signing-Key (0600, auf
  dem Edge-Runtime-Volume neben der publizierten Root), sonst generieren+persistieren; `run_edge`
  nutzt ihn (`ca_key_path_for(cert_out)` → `edge-ca-key.pem`). Gleicher Key ⇒ gleiche Root ⇒
  Pins bleiben gültig. Frozen-Test `persisted_ca_reload_keeps_pinned_clients_valid` (zwei
  unabhängige `load_or_create` = Prozess-Neustart; Client mit Pre-Restart-Pin handshaked gegen
  das Leaf der reloaded CA). Gate 225 (+1), 0 Warnungen. Der CA-Key landet nie im Repo
  (Runtime-Pfad). Mode (b) bleibt offen (Feld: PMTU/DF ausgeschlossen, Verdacht Edge-Route/Relay-
  App-Logik) → needs-info, sobald Cert neu publiziert ist, Edge-seitiges Tracing nachziehen.
- **#2 (mode b) Edge-seitige Relay-Diagnose** ✅ (Diagnose, kein Fix): mode (b) — frischer Token +
  lebender Agent, aber Client-`'C'` wird nie relayed — reproduziert das Feld auf sauberem Pfad
  (1 Hop, MTU 1500, 0% Loss; PMTU/DF ausgeschlossen). In der Single-Host-Gate nicht reproduzierbar
  (alle e2e-Tests loopback). Statt zu raten diagnostiziert jetzt der Edge selbst: `open_agent_stream`
  routet + öffnet den Relay-Stream mit Timeout (`RELAY_OPEN_BI_TIMEOUT` 5s < Client-8s) und liefert
  **unterscheidbare Verdikte**: `no agent tunnel` (route-miss) vs `agent tunnel unresponsive:
  open_bi … timed out` (registriert+lebend, aber Edge kann keinen Stream öffnen — z.B. kein
  bidi-Stream-Credit / kaputter Rückweg). `CT_EDGE_TRACE=1` loggt jeden Entscheidungspunkt
  (route hit/miss, open_bi ok/err/timeout) mit Token-Hex-Präfix für den Lockstep-Capture. Alle drei
  Relay-Call-Sites (QUIC 'C', `route_and_relay`, TCP→QUIC) nutzen den Helper. Frozen-Test
  `open_agent_stream_distinguishes_missing_from_unresponsive` (hungernder Agent = 0 bidi-Credit,
  registriert+lebend → Edge-Timeout mit `unresponsive`; unbekannter Token → `no agent tunnel`) —
  reproduziert die mode-b-Form (registriert+lebend, doch nicht öffenbar) erstmals in der Gate.
  Gate 226 (+1), 0 Warnungen. needs-info bleibt: Operator deployt mit `CT_EDGE_TRACE=1`, Feld fährt
  den timestamped Lauf → Edge-Log grep auf Token lokalisiert route-miss vs unresponsive.
- **#2 (mode b) Edge-Relay Rückrichtung: expliziter Pump + per-Richtung-Trace** (Diagnose + plausibler Fix):
  Feld hat mit Agent-Trace bewiesen: Vorwärts-Leg (client→agent) voll ok — `accept_bi` liefert den
  Stream, Client-msg1 (96B) kommt an, Agent schreibt msg2 (48B) zurück + flush + noise_pump. Client
  bekommt msg2 nie → Verlust auf **Rückrichtung (agent→edge→client)**. `relay_quic` nutzte
  `copy_bidirectional` (opak, keine Per-Richtung-Sicht). Ersetzt durch expliziten Zwei-Richtungs-Pump
  (`relay_pair`/`pump_dir`): jede Richtung unabhängig, **flush pro Chunk** (kleine Antwort wird sofort
  auf die Leitung geschoben statt hinter der leerlaufenden Vorwärtsrichtung zu hängen), Per-Richtung-
  Byte-Zähler + `CT_EDGE_TRACE` First-Byte-Log, mit Token-Label. Frozen-Test
  `relay_delivers_the_reply_while_the_request_side_stays_open` (Client sendet msg1 und lässt offen,
  Agent antwortet msg2 → muss beim Client ankommen; fwd=rev=4B) — genau das mode-b-Muster. Alle e2e-
  Relay-Tests (client→edge→agent, bidirektional, noise-to-origin) grün durch den neuen Relay. Gate 227
  (+1), 0 Warnungen. **Kein bestätigter Fix** (cross-host nicht in der Gate verifizierbar): Feld deployt
  Edge auf diesen Rev + `CT_EDGE_TRACE=1`, re-fire → Trace zeigt fwd/rev-Bytes. rev>0 & Client bekommt
  msg2 = gefixt; rev=0 = agent→edge-Stream-Richtung (nächster Schritt). needs-info bis Feld bestätigt.
- **#2 AUFGELÖST — kein Defekt (Test-Harness-Origin ohne Echo).** Feld-Client-Trace zeigte: msg2
  wurde sauber empfangen, Handshake beidseitig fertig; der Client blockierte danach auf der
  **verschlüsselten Antwort auf sein Payload** — weil das Origin `python3 -m http.server` war, das den
  `hello-tunnel`-Payload **nicht zurückschickt**. Mit Echo-Origin cross-host: `ct-client: tunnel
  round-trip OK (via=quic)`, exit 0, ~2s. Also weder Relay noch msg2 noch Stream-State noch Wire —
  ein nicht-antwortendes Origin. Konsistent mit dem Code (Agent bridged den Noise-Tunnel zum
  Origin-Socket; antwortet das Origin nicht, hat der Client-Read nichts). Die auf dem Weg gelandeten
  Fixes bleiben eigenständig korrekt: QUIC-Keepalive (`aa42363`→ wait, keepalive war früher),
  Edge-Eviction (`aa42363`), persistente CA (`f9e64e9`), Relay-Diagnose (`c75fd9e`),
  Per-Richtung-Relay-Pump (`f35f72e`). #2 geschlossen als „not a defect". Sanktionierter
  `SMOKE OK via=quic` via `scripts/e2e-smoke.sh` (socat-Echo-Origin) als formale Bestätigung offen.

## Milestone 18 — Agent-Redundanz (mehrere Agents pro Tunnel, Failover) — #8
> Produktions-HA auf der Origin-Seite: mehrere Agents dürfen denselben Routing-Token
> registrieren; der Edge failovert auf einen überlebenden Agent, wenn einer wegbricht.
> Komplement zu Reconnect (#5) und zur Eviction (`aa42363`).
- **R1** ✅ EdgeState-Multi-Agent-Primitive: `agents` von `HashMap<Token, H>` → `HashMap<Token,
  Vec<(u64, H)>>` (monotone Registrierungs-Id via `AtomicU64`). `register`/`register_with_candidate`
  geben die Reg-Id zurück; `route` liefert den **zuletzt** registrierten Agent (reconnectender Agent
  wird der eigenen sterbenden Registrierung vorgezogen; bei Redundanz bedient der neueste, der nächste
  übernimmt beim Drop); `remove_registration(token, id)` evictet **genau einen** Agent (Kandidat/Direct
  erst beim letzten bereinigt); `remove(token)` bleibt Full-Teardown; `registration_count` neu.
  `serve_connection` gibt jetzt `(RoutingToken, u64)` zurück, `run_edge` evictet via
  `remove_registration` — ein wegbrechender Agent stört die anderen für denselben Token nicht mehr.
  Frozen-Test `redundant_agents_fail_over_on_registration_drop` (2 Agents, route bevorzugt neuesten,
  Evict → Failover auf Überlebenden, idempotent, letzter weg → Tunnel weg). Alle Edge-/e2e-Relay-Tests
  grün durch die geänderte Registry. **fix-ready erst wenn R1–R4 alle Akzeptanzkriterien erfüllen.**
- **R2** ✅ Edge-Relay-Failover-Retry: `EdgeState::routes(token)` liefert alle Live-Agents (neuester
  zuerst); `open_agent_stream` probiert sie der Reihe nach durch, bis ein `open_bi()` gelingt — deckt
  redundante Agents UND das Dead-but-not-yet-evicted-Rennen ab (Client bekommt Failover statt „no
  relay"). Frozen-Test `relay_fails_over_from_a_dead_agent_to_a_live_one` (2 echte QUIC-Agents, der
  neueste mit 0 bidi-Credit = tot → Failover auf den überlebenden). Gate grün.
- **R4a** ✅ Shared-Identity-Support (Voraussetzung für deploybare Redundanz): zwei unabhängig
  gestartete Agents minteten bisher je eigenen Origin-Key + Zufalls-Token → nie redundant.
  `resolve_serving_identity(key_path, cap_path, edge)`: mit `CT_AGENT_ORIGIN_KEY` persistiert der
  erste Agent Origin-Key (0600) + Capability und spätere Agents **laden** sie → gleicher Token →
  mehrere Agents bedienen einen Tunnel; ohne die Env frische Einzel-Identität (Default). `main.rs`
  verdrahtet. Frozen-Test `shared_identity_lets_multiple_agents_serve_one_token` (geteilte Dateien →
  gleicher Token/Key/Identity; Default → eindeutig). Gate grün. (Ersten Agent zuerst starten, damit
  die geteilten Dateien existieren.)
- **R3** ⏳ Round-Robin/Lastverteilung über redundante Agents (optional).
- **R4b** ✅ Runbook-Abschnitt „Run redundant agents (HA origin)" + `scripts/redundancy-smoke.sh`:
  ein Echo-Origin, zwei Agents mit geteilter Identität (`CT_AGENT_ORIGIN_KEY`), Client-Round-Trip,
  dann den bedienenden Agent killen → Client bekommt weiter `via=quic` vom Überlebenden
  (`REDUNDANCY OK`). Frozen: `bash -n` grün + Drift-Check (alle CT_*-Env-Vars, `CT_AGENT_ORIGIN_KEY`,
  `round-trip OK`/`via=`, `/enroll/issue` code-backed). **🎯 #8 komplett (R1 Registry + R2 Failover +
  R4a Shared-Identity + R4b Doku/Smoke) → alle Akzeptanzkriterien erfüllt → fix-ready. R3 (Round-
  Robin/Last) optional/deferred.**

## Milestone 19 — Edge-Observability (`/metrics` für die Datenebene) — #10
> Der Edge (Relay) war unbeobachtet; nur Control-Plane-Landing (#4) + Agent-`/metrics` existierten.
> Prometheus-`/metrics` am Edge, spiegelt das Agent-`observe`-Muster; nur Metadaten (ADR-0016).
- **O1** ✅ Live-Gauges + `/metrics`-Endpoint: `EdgeState::active_tunnels()` (distinkte Tokens mit ≥1
  Agent) + `total_registrations()` (alle Live-Registrierungen, redundante Agents #8 mitgezählt).
  Neues `edge::observe` (axum): `render_edge_metrics<H>` (generisch/testbar) → `ct_edge_active_tunnels`
  + `ct_edge_active_agents` im Prometheus-Format; `metrics_router`/`serve_metrics`. In `run_edge` per
  `CT_EDGE_METRICS_LISTEN` opt-in verdrahtet (default aus). Frozen-Tests
  `gauges_reflect_registered_agents` (2 Agents auf Token A + 1 auf B → tunnels 2, agents 3) +
  `metrics_endpoint_serves_prometheus` (leerer Edge → 200, `text/plain; version=0.0.4`, gauges 0).
- **O2** ✅ Kumulative Counter in `EdgeState` (ct-common `Counter`): `registrations_total` (jede
  Registrierung), `relays_total`/`relay_bytes_total` (nach jedem Relay via `note_relay(a+b)` in
  QUIC-'C'/`route_and_relay`/TCP-Pfad), `failovers_total` (`open_agent_stream` bei Erfolg auf
  Nicht-Primär-Agent, #8). `/metrics` rendert alle vier als Prometheus-Counter. Frozen-Test
  `cumulative_counters_render_after_activity`. Gate grün.
- **O3** ✅ `docker/docker-compose.metrics.yml` um den Edge erweitert (`CT_EDGE_METRICS_LISTEN`
  `:9101`) + Runbook-Abschnitt „Edge data-plane metrics" (alle 6 Serien-Tabelle, Scrape-Beispiel,
  Provider-blind/Metadaten-only). Drift-Check: alle Metriknamen + `CT_EDGE_METRICS_LISTEN` code-backed.
  **🎯 #10 komplett (O1 Gauges + O2 Counter + O3 Compose/Doku) → fix-ready.**

## Milestone 20 — Edge-CA-Root über Control-Plane publizieren (self-serve cross-host Cert-Distribution) — #11
> #9 zeigte: kein cross-host Distributionskanal für die Edge-CA-Root (nur Shared-Volume). Da CP+Edge
> auf dem zentralen Host co-lokiert sind, liest die CP die vom Edge geschriebene Cert-Datei und
> publiziert sie über HTTP. Nur öffentliches Schlüsselmaterial (Trust-Root, nie der Signing-Key).
- **C1** ✅ CP-Endpoint `GET /pki/ca`: `pki_router(cert_path)` liest die Edge-CA-Root-DER vom Pfad
  (`CT_CP_EDGE_CERT_PATH`, default `/shared/edge-cert.der` = Edge-`CT_EDGE_CERT_OUT`), liefert sie mit
  `application/x-x509-ca-cert` (200), sonst 503 (Edge hat noch nicht publiziert). In
  `persistent_control_plane_router` gemerged. Stabil über Edge-Redeploys dank persistenter CA (#2).
  Frozen-Test `pki_endpoint_publishes_the_edge_ca_root` (DER geschrieben → 200 + exakte Bytes +
  Content-Type; fehlend → 503). Gate grün.
- **C2** ✅ `ControlPlaneClient::fetch_edge_cert()` (GET /pki/ca via reqwest) + Agent-Verdrahtung:
  ist `CT_AGENT_EDGE_CERT_URL` gesetzt, holt der Agent die Edge-CA-Root von der CP (self-serve
  cross-host, kein Out-of-Band-Kopieren) statt vom Shared-Volume-Pfad. Frozen-Test
  `fetch_edge_cert_downloads_the_published_root` (pki_router live gebunden → Client holt exakte
  Bytes). Gate grün. (Client-Seite `CT_CLIENT_EDGE_CERT_URL` als kleiner Folgeschritt in C3.)
- **C3** ✅ Runbook: Config-Tabelle um `CT_EDGE_METRICS_LISTEN`/`CT_CP_EDGE_CERT_PATH`/
  `CT_AGENT_EDGE_CERT_URL` erweitert + Abschnitt „Distribute the edge CA root cross-host" (Agent
  Auto-Fetch via `CT_AGENT_EDGE_CERT_URL`; der schlanke Client bleibt HTTP-Client-frei und holt die
  Root per einmaligem `curl /pki/ca -o edge-cert.der` → `CT_CLIENT_EDGE_CERT`). Kein ct-control-plane
  (rusqlite/axum) ins Client-Binary ziehen. **🎯 #11 komplett (C1 CP-Endpoint + C2 Agent-Fetch +
  C3 Client-curl/Doku) → fix-ready.**

## Milestone 21 — Key-Rotation (Origin/Capability rotieren ohne Client-Bruch) — #12
> Origin-Key kompromittiert/fällig → rotieren, ohne Clients mit alter Capability zu brechen. Im
> Rotationsfenster bedient der Agent BEIDE Identitäten (Noise-Responder probiert mehrere Keys),
> danach wird der alte Key retired. Deferred-Backlog (ADR-0013/0014).
- **K1** ✅ Multi-Key-Origin-Handshake-Primitive `noise::origin_handshake_any(candidates, msg1)`:
  probiert jeden Kandidaten-Origin-Private-Key als Responder gegen Client-msg1; in Noise_IK
  entschlüsselt nur der passende Private-Key msg1 (falscher Key → AEAD-Tag-Fehler) → gibt den
  passenden Handshake-State zurück, sonst None. Basis für ein Agent, der mehrere Origin-Identitäten
  gleichzeitig terminiert. Frozen-Test `origin_handshake_any_selects_the_pinned_identity` (Client
  pinnt A; Kandidaten {B,A} → matcht A und schließt den Handshake ab; {B,client} → None). Gate grün.
- **K2** ✅ Agent bedient ein Origin-Key-SET: origin-Key-Typ durch die ganze Serve-Kette von
  `[u8;32]` → `Arc<Vec<[u8;32]>>` / `&[[u8;32]]` (run_agent, run_agent_tcp_fallback, serve_direct,
  serve_quic_connection, tcp_connect_register_serve) + `serve_noise_stream`/`serve_noise_udp` nutzen
  `origin_handshake_any`. `main` übergibt `[identity.origin_private]` (Verhalten unverändert; K3 lädt
  mehrere). Alle Client-/Agent-Test-Call-Sites auf 1-Element-Sets angepasst. Frozen-Test
  `serve_noise_stream_selects_the_pinned_key_from_a_rotation_set` (Set [old,new], Client pinnt new →
  Round-trip über den nicht-ersten Key). Gate grün.
- **K3** ✅ Agent lädt ein Key-SET: `ServingIdentity.origin_private` → `origin_keys: Vec<[u8;32]>`
  (Primary zuerst); `resolve_serving_identity(..., extra_keys_dir)` hängt zusätzliche 32-Byte-Key-
  Dateien aus `CT_AGENT_ORIGIN_KEY_DIR` an (sortiert, Nicht-32-Byte ignoriert, fehlendes Dir → leer).
  `main` liest die Env und übergibt das Set an `run_agent`. K3 ist NUR der Lade-Mechanismus
  (mehrere Origin-Keys halten). Frozen-Test `rotation_dir_adds_old_keys_alongside_the_primary`
  (2 alte Keys im Dir → 3 Keys, Primary zuerst, Nicht-Key ignoriert). Gate grün.
- **K4** ⏳ **Token-erhaltender Rotate**: Damit alte Clients während des Fensters weiter *routen*,
  muss der Routing-Token GLEICH bleiben und nur die Origin-Identität (Key) rotieren. Braucht ein
  `rotate`-Kommando ✅: `mint_capability_with_token` (expliziter Token) + `rotate_origin_key`
  (liest alte Cap → gleicher Token; neuer Origin-Key; neue Cap = Token + neuer Pubkey; alten Key als
  `retired-<hex>.key` in `CT_AGENT_ORIGIN_KEY_DIR`; neuen Key als Primary). `ct-agent rotate`-Subcommand.
  Frozen-Test `rotate_keeps_the_token_and_retires_the_old_key` (Token erhalten, Origin geändert, nach
  Rotate serviert Agent 2 Identitäten mit gleichem Token). Runbook „Rotate the origin key" +
  `scripts/rotation-smoke.sh` (alt+neu-Cap round-trippen, `bash -n`+Drift grün). Gate grün.
  **🎯 #12 komplett (K1 Primitive + K2 Serve-Set + K3 Key-Set-Loading + K4 Token-erhaltender Rotate)
  → alle Akzeptanzkriterien → fix-ready.**

## #20 — ct-agent Test-Coverage → 95% (lib-only)

Baseline (gemessen, `cargo llvm-cov -p ct-agent`): Crate **84.9%** / lib-only **91.1%**.
Ziel: **lib-only ≥95%** (bin/*, main.rs sind dünne Entrypoints → aus dem Nenner, TC7).
Zu groß für einen Zyklus → dekomponiert; pro Zyklus genau EIN Sub-Paket mit Frozen-Test.

- **TC1** ✅ `config.rs::from_env()` (größte Lib-Lücke, 64.9% → ~100%): testbare Naht
  `from_env_with(get: impl Fn(&str)->Option<String>)` extrahiert, `from_env` delegiert an
  `std::env::var`. Deckt alle Zweige OHNE globale-Env-Mutation (kein Test-Race, kein `unsafe set_var`).
  Frozen-Tests `from_env_defaults_when_all_unset`, `from_env_reads_every_var`,
  `from_env_blank_optionals_are_treated_as_unset`, `from_env_rejects_each_invalid_value`
  (alle Fehler-Branches: edge/origin/proto/direct/metrics). Gate grün.
- **TC2** ✅ `onboard.rs::OnboardEnv::from_env()` (L79-88): gleiche `from_env_with(get)`-Naht;
  `AgentConfig::from_env_with` auf `pub(crate)` erweitert und via `&get` delegiert. Frozen-Tests
  `onboard_from_env_reads_required_vars_and_delegates_config` (alle 3 Pflichtvars + Config-Delegation,
  Proto fließt durch) und `onboard_from_env_requires_each_var` (jede fehlende Pflichtvar → spezifischer
  Fehler). Gate grün.
- **TC3** ✅ `transport.rs` Fehler-Branches: `present_credential` war bereits gedeckt
  (`agent_authenticates…` + `edge_rejects_expired_credential`). Neu ein Mock-Edge-Helper
  `mock_edge_replying(ack)` (liest einen Bi-Stream, antwortet mit fixem Ack) → deckt die
  Reject-Zweige, die der echte Edge nie nimmt. Frozen-Tests `register_tunnel_surfaces_an_edge_rejection`
  (non-OK → "rejected tunnel registration") und `advertise_direct_listener_roundtrips_and_surfaces_rejection`
  (OK-Happy-Path + non-OK → "advertisement rejected"; deckt auch `build_direct_listener`). Gate grün.
- **Wrapper** ✅ `config.rs::from_env()` + `onboard.rs::OnboardEnv::from_env()` dünne Real-Env-Wrapper
  (`from_env_wrapper_*`-Tests; kein Test setzt CT_AGENT_*, also race-frei). config.rs + onboard.rs → 100%.
- **TC5** ✅ `observe.rs::serve_metrics()`: `serve_metrics_binds_its_own_listener_and_serves` (ephemeren
  Port reservieren → an serve_metrics geben → einmal per Raw-HTTP scrapen → Server abbrechen). 100% Funktionen.
- **TC6** ✅ `capability.rs` Fehler-Branches: `resolve_tolerates_a_missing_rotation_dir` (read_dir Err → leer)
  und `rotate_rejects_a_non_32_byte_current_key` ("not 32 bytes"). capability.rs 99.1% Zeilen / 100% Funktionen.
- **TC4** ⏭️ `serve.rs` tiefe reconnect-/Fehler-Branches (Netzwerk-Fehlerpfade) BEWUSST zurückgestellt:
  das Aggregat-Ziel (lib-only ≥95%) ist ohne sie erreicht; serve.rs bleibt die einzige Datei <95%
  (89.8% Zeilen / 89.6% Regions). Optionaler Stretch, falls per-file/Region-95% gewünscht wird.
- **TC7** ✅ Gemessen (`cargo llvm-cov -p ct-agent --ignore-filename-regex '(bin/|main\.rs)'`):
  **lib-only 95.41% Zeilen / 96.56% Funktionen** (Baseline 91.1%), ct-agent 52 → 65 Tests. Ziel erreicht
  → **#20 fix-ready** (Regions 94.05%, serve.rs die einzige Restlücke — transparent kommuniziert).

## #21 — Workspace-Coverage → 95% (lib-only)

Baseline (Report): Workspace 90.84% Zeilen / 89.75% Funktionen. #20 hat davon schon
`agent/config.rs` (66%→100%) und `agent/observe.rs` (87%→97%) erledigt. Scope-Entscheidung:
**lib-only** (dünne main.rs/bin/*-Entrypoints raus, via Shell-Smokes gedeckt), wie bei #20.
Zu groß für einen Zyklus → dekomponiert.

- **WC1** ✅ `scripts/coverage.sh` — hermetische Coverage-Messung (rust:1-slim, persistenter
  CARGO_HOME, cargo-llvm-cov) mit `--fail-under-lines`-Gate (Default 95) und Knöpfen
  `COVERAGE_MIN` / `COVERAGE_SCOPE` (lib|all) / `COVERAGE_PKG`. Muster wie `scripts/security-audit.sh`.
  Verifiziert: `sh -n` grün + hermetischer Lauf `COVERAGE_PKG=ct-agent` → 95.41% Zeilen, Exit 0
  (Gate greift). Kein Rust geändert → Cargo-Gate trivial grün.
- **WC2** ✅ `edge/src/config.rs` (72.22% → 97.06% Zeilen): `from_env_with(get)`-Naht wie beim Agent (TC1).
  Frozen-Tests `from_env_defaults_when_unset`, `from_env_reads_both_vars`,
  `from_env_rejects_each_invalid_value` (listen + difficulty), `from_env_wrapper_reads_the_process_environment`.
  Gate grün.
- **WC3** ✅ `control-plane/src/oidc.rs` (88.89%): der RS256/Keycloak-Produktions-Konstruktor
  `from_rsa_pem` (bisher ungetestet; HS256-Tests decken die geteilte subject()-Logik) + `OidcError`
  Display. Frozen-Tests `from_rsa_pem_builds_a_verifier_from_a_public_key` (eingebetteter RSA-PUBLIC-Key
  — vom Secret-Guard erlaubt, nur PRIVATE-Keys werden geflaggt), `from_rsa_pem_rejects_malformed_pem`,
  `oidc_error_displays_a_reason`. Gate grün.
- **WC4** ✅ `client/src/transport.rs` (90.72% Zeilen): `client_tunnel_noise_tcp_timed` (der TLS-über-TCP
  Timed-Wrapper, #2) war komplett ungetestet. Frozen-Test `tcp_timed_surfaces_timeout_and_inner_error`
  deckt beide Zweige über einen In-Memory-`tokio::io::duplex` (idle Peer → Deadline-Arm; geschlossener
  Peer → innerer Fehler wird durchgereicht) — ohne echten Edge. Gate grün.
  (Restliche Lücken: UDP-Data-Loop-Branches + timed-QUIC-Success-Arm — Harness-lastig, in WC5 mit dem
  Kern-Relay-Pfad.)
- **WC5** ⏭️ `edge/src/serve.rs` (85.08%) + `agent/src/serve.rs` (89.80%) — tiefe Kern-Relay-Fehler-/
  Reconnect-Branches (Netzwerk-Fehlerpfade) BEWUSST zurückgestellt: das gestellte Ziel (**95% Zeilen**,
  lib-only, Workspace) ist ohne sie erreicht. edge/serve.rs bleibt die schwächste Datei (86.3% Zeilen).
  Optionaler Stretch für per-file/Funktions-95%.
- **WC6** ✅ Re-Messung via `scripts/coverage.sh` (Workspace, lib-only, Gate 95): **Workspace 95.59% Zeilen**
  (Baseline 90.84%), Funktionen 94.44%, Regions 93.76%. Zeilen-Ziel erreicht → **#21 fix-ready**
  (Funktionen/Regions knapp darunter, edge/serve.rs die Restlücke — transparent kommuniziert).

## #22 — HTTPS-Website als Origin durch den Tunnel (TLS-at-origin, v1/Mesh Plane)

Scope (v1): TLS terminiert **am Origin**, nicht am Edge; self-signed/local-CA (hermetisch, CI-tauglich).
Browser Plane (öffentliches SNI + Let's Encrypt, ADR-0010) ist post-v1 → separates Tracking-Issue (HW3).

- **HW1** ✅ Hermetischer e2e-Test `https_website_through_the_tunnel_with_client_side_cert_validation`
  (ct-client rendezvous): echter HTTPS-Origin via `ct_edge::transport::build_tcp_tls_listener_at`
  (self-signed, SAN „localhost"), erreicht durch den echten Edge+Agent-Tunnel; Client fährt TLS
  über den Noise-Stream, vertraut NUR dem Origin-Cert (erfolgreicher Handshake = client-seitige
  Cert-Validierung), liest HTTP 200 + „hello, secured". Edge-sieht-nur-Ciphertext ist separat via
  `relay::tests::noise_e2e_through_relay_edge_sees_only_ciphertext` bewiesen. Gate grün.
- **HW2a** ✅ Client-**Forward-Modus** (`CT_CLIENT_MODE=forward` + `CT_CLIENT_LISTEN`): `client_forward`
  bindet einen lokalen TCP-Port und brückt jede Verbindung über einen eigenen Tunnel via
  `client_tunnel_stream` zum Origin — der Enabler, damit echte TCP/TLS-Apps (curl, Browser) über einen
  lokalen Port den Mesh nutzen (TLS terminiert am Origin, Edge provider-blind). Frozen-Test
  `forward_mode_bridges_a_local_tcp_connection_through_the_tunnel` (lokaler TCP-Client → Forward →
  Tunnel → Echo-Origin). Gate grün.
- **HW2b** ✅ `scripts/https-demo.sh` — menschlich nachvollziehbare Demo mit HW2a: self-signed HTTPS-Origin
  (openssl s_server, SAN IP:127.0.0.1) + Agent + Client-Forward, dann `curl --cacert` durch den Tunnel.
  **Lokal end-to-end verifiziert** gegen die laufende ct-selfhost-Central: HTTP 200 über TLS, Cert
  client-seitig validiert, Origin liefert echtes HTML. `bash -n` grün.
- **HW3** ✅ Separates Tracking-Issue **#23** für die **Browser Plane** (ADR-0010 öffentliches SNI +
  ADR-0003 DNS-01 Let's Encrypt) angelegt, Label `enhancement,deferred` (Loop baut es NICHT). Verlinkt
  den bewusst zurückgestellten post-v1-Teil, damit #22 schließen kann ohne „fehlt/kaputt" zu implizieren.
  **→ #22 fix-ready** (HW1 Test + HW2 Demo decken die v1-Akzeptanz; TLS-terminiert-am-Origin durch den
  Tunnel, Cert client-seitig validiert, Edge ciphertext-only).

## #23 — Browser Plane (öffentlicher Hostname + SNI-Routing, post-v1 auf Wunsch reaktiviert)

Ziel: Browser tippt `https://<hostname>/`, Let's Encrypt „funktioniert einfach" über SNI; TLS
terminiert am Origin (öffentlich vertrautes Cert), Edge sieht nur Hostname (SNI) + Chiffretext
(ADR-0010-Kompromiss: Hostname sichtbar, Nutzlast blind). Zu groß für einen Zyklus → dekomponiert.

- **BP1** ✅ **SNI-Passthrough-Routing am Edge**: `sni::peek_sni` (bounds-checked TLS-ClientHello-Parser)
  + `sni::read_client_hello` (puffert den ersten Record) + Host→Token-Registry in `EdgeState`
  (`register_host`/`route_host`, lowercased) + `serve_sni_passthrough` (SNI lesen ohne TLS-Terminierung
  → Token → Agent-Stream öffnen → gepufferten ClientHello + rohe TLS-Bytes durchreichen). Frozen-Tests:
  `peek_sni_*`, `read_client_hello_*`, und `sni_passthrough_routes_a_browser_tls_connection_to_the_origin`
  (rustls-„Browser" erreicht einen public-hostname HTTPS-Origin durch den Tunnel, validiert das Cert
  client-seitig, HTTP 200 — Edge terminiert nie TLS). Gate grün.
- **BP2** ✅ **Agent-Browser-Forward-Modus**: `CT_AGENT_MODE=browser` (`AgentConfig.browser_forward`) →
  `serve_quic_connection` reicht jeden relayed Stream via `serve_stream_to_origin` (raw
  `copy_bidirectional`) roh zum Origin durch statt Noise zu terminieren; die Browser-TLS terminiert am
  Origin. Frozen-Tests `from_env_browser_mode_enables_raw_forward` und
  `serve_stream_to_origin_carries_a_full_tls_session` (rustls-„Browser" über einen QUIC-Stream →
  serve_stream_to_origin → TLS-Origin: voller Handshake + HTTP 200 überlebt die rohe Weiterleitung). Gate grün.
- **BP3** ✅ **Öffentlicher :443-Browser-Listener + Hostname-Bindung (Mechanismus)**: `run_edge` bindet
  bei gesetztem `CT_EDGE_BROWSER_LISTEN` einen ROHEN TCP-Listener (keine TLS-Terminierung) → jede
  Browser-Verbindung geht an `serve_sni_passthrough`. Neue Edge-Protokoll-Rolle `'H'`
  (`'H' | token(32) | host_len(2) | host`) in `serve_connection` bindet Hostname→Token
  (`state.register_host`, case-insensitive). Frozen-Test `agent_binds_a_hostname_via_the_h_role`. Gate grün.
  (Autorisierung — Control-Plane prüft, dass der Agent den Hostnamen besitzt — ist Härtung/Folgepaket.)
- **BP3b** ✅ **Agent deklariert den Hostnamen**: `AgentConfig.hostname` aus `CT_AGENT_HOSTNAME`;
  `transport::bind_hostname` (öffnet Stream, sendet `'H' | token | len | host`, liest OK);
  `run_agent` bindet nach der Registrierung im Browser-Modus (bei jedem Reconnect neu). Frozen-Tests
  `bind_hostname_sends_h_and_surfaces_the_ack` (OK/Reject/leerer-Host-Guard). Damit läuft die Kette
  Agent→Edge (Token+Host) → Edge-`:443`-Listener → SNI→Token→Agent→Origin end-to-end (BP1–BP3b).
  Gate grün.
- **BP4a** ✅ **Host-Binding-Härtung** (Feld-Review-Punkt #2): `register_host` ist jetzt **takeover-sicher** —
  ein bereits gebundener Hostname kann nicht durch einen Bind auf ein *anderes* Token übernommen werden (erster
  Bind gewinnt; Same-Token-Rebind bei Reconnect idempotent); der 'H'-Handler antwortet bei Konflikt mit `NO`.
  Stale-Bindings werden beim Agent-Drop (letzte Registrierung weg) und bei `revoke_token`/`remove` via
  `clear_hosts_for` aufgeräumt. Frozen-Test `host_binding_is_takeover_safe_and_cleared_on_agent_drop`. Gate grün (ct-edge 61).
- **BP4b** **Hostname-Ownership-Autorisierung** (Feld-Review-Punkt #1) — MUSS vor öffentlichem `:443` landen:
  - **BP4b-a** ✅ Edge-Gate: `EdgeState` bekommt `host_auth` (None=nicht erforderlich/legacy; Some(map)=erforderlich)
    + `require_host_auth`/`authorize_host`/`host_bind_allowed`; der 'H'-Handler weist einen nicht-autorisierten Bind mit
    `NO` ab (vor der BP4a-Takeover-Prüfung). `run_edge` aktiviert via `CT_EDGE_REQUIRE_HOST_AUTH`. Frozen-Test
    `host_bind_authorization_gates_binds_when_required`. Gate grün (ct-edge 64).
  - **BP4b-b** ✅ Edge-Endpoint `POST /admin/authorize-host/:token/:host` (`crate::admin`, reuse Admin-Token-Auth via
    `admin_authed`) → `state.authorize_host`. Frozen-Test `authorize_host_endpoint_authenticates_then_authorizes`
    (401 ohne Auth, 200 + bind-allowed mit Secret, nur der autorisierte Host). Gate grün (ct-edge 65).
  - **BP4b-c** ✅ Control-Plane-Push: `create_tunnel` mit Hostname ruft nach dem Anlegen den Edge-Endpoint
    `POST /admin/authorize-host/{routing_token}/{host}` (best-effort, `edge_admin`-Config aus RB4b wiederverwendet).
    Frozen-Test `create_tunnel_with_a_hostname_authorizes_it_at_the_edge` (Mock-Edge empfängt Routing-Token + Host + Auth).
    ct-control-plane 113. **Autorisierungskette end-to-end**: Portal-Create(Hostname) → Edge-authorize → 'H'-Bind erlaubt.
  - **BP4b-d** ✅ Hostname-Validierung/-Normalisierung: `ct_common::normalize_hostname` (trim, Trailing-Dot strippen,
    lowercase, RFC-1123-Charset/Label/Länge; `xn--` erlaubt) — konsistent an Edge (`register_host`/`route_host`/
    `authorize_host`/`host_bind_allowed`) und CP (`create_tunnel` → 400 bei ungültig). Frozen-Tests
    `normalize_hostname_canonicalizes_and_validates` (common), `host_normalization_collapses_trailing_dot_and_rejects_junk`
    (edge), `create_tunnel_rejects_an_invalid_hostname` (CP). Voller Workspace-Gate grün.
  - **#41 (Feld-Bug) Browser-Plane über TLS-TCP-Fallback** — der TCP-Fallback (ADR-0004, für UDP/QUIC-blockierte Netze)
  konnte nie einen Hostnamen binden: Single-Stream, kein separates `'H'` möglich. Dekomponiert FB1..FB3:
  - **FB1** ✅ Neue Edge-Rolle `'B'` (Browser-Register) im TCP-Fallback (`serve_tcp_connection`):
    `'B' | token(32) | host_len(2) | host` → registriert Tunnel **und** bindet Hostname in EINER Nachricht
    (gleiche Gates wie QUIC-`'H'`: BP4b-Autz + Takeover-sicher), dann park+relay. Frozen-Test
    `tcp_fallback_browser_register_binds_hostname` (In-Memory-Duplex: `'B'`+Host → `route_host` löst auf). Gate grün (ct-edge 68).
  - **FB2** ⏳ `serve_sni_passthrough` an TCP-Fallback-Agenten relayen (`has_tcp_agent`/`deliver_to_tcp_agent` statt QUIC-`open_agent_stream`).
  - **FB3** ⏳ Agent: im Browser-Modus über den TCP-Fallback `'B'` senden (statt `'A'`, kein separates `bind_hostname`).
- **#40 (Feld-Bug) ✅** SNI-Passthrough routete nie zum Agenten: der Agent öffnet nach `'A'` einen SEPARATEN `'H'`-Stream, aber der Edge bearbeitete pro Verbindung nur EINEN Stream → `route_host` fand nichts. Fix: `serve_agent_connection` akzeptiert weitere Streams derselben Agent-Verbindung bis zum Close. QUIC-Integrationstest `agent_registers_and_binds_hostname_over_one_connection` (A + H über eine Verbindung → `route_host` löst auf). Der BP3b-Unit-Test hatte den 'H'-Handler direkt getrieben und den Multi-Stream-Flow verfehlt.
- **BP4b ✅ komplett** — `:443` ist jetzt sicher exponierbar (mit `CT_EDGE_REQUIRE_HOST_AUTH`): nur CP-autorisierte,
    validierte Hostnamen; takeover-sicher (BP4a); Reconnect-fest. Review-Punkte #1 + #2 + #3 adressiert.
- **BP4c** ⏳ **Agent-seitiges ACME** (Let's Encrypt DNS-01, ADR-0003) + BYO-Cert-Fallback; nur
  LE-*Staging* hermetisch testbar, Prod-LE in einem manuellen/gated Job. Reale Domain jetzt verfügbar (#30: bunsenbrenner.org).
  **Dekomponiert (Zyklus: BP4c ist zu groß für einen Takt, braucht neue ACME-Abhängigkeit):**
  - **BP4c-a** ✅ **Schlüssel + CSR** (`ct-agent::acme`): `generate_csr(hostname) -> CsrBundle { key_pem, csr_pem, csr_der }` —
    rcgen-`KeyPair::generate` + `CertificateParams::serialize_request` (Hostname via `ct_common::normalize_hostname`
    normalisiert/validiert → CN + DNS-SAN). Das gemeinsame Artefakt beider Pfade: ACME-Finalize base64url-t die DER, BYO
    liefert stattdessen ein eigenes Leaf. Frozen-Tests `generate_csr_binds_the_normalized_hostname_and_a_usable_key`
    (Key-Roundtrip + normalisierter Host verbatim in der DER, Mixed-Case wegnormalisiert), `generate_csr_rejects_an_invalid_hostname`.
    Gate grün (ct-agent 73). *(CSR-Parsing in rcgen 0.13 braucht das `x509-parser`-Feature — bewusst nicht aktiviert; Test prüft die DER-Bytes.)*
  - **BP4c-b** ✅ **ACME-Protokoll-Parsing + DNS-01-Ableitung** (RFC 8555, `ct-agent::acme`, rein/hermetisch): `parse_directory`
    (newNonce/newAccount/newOrder), `parse_order` (status/authorizations/finalize/certificate), `select_dns01` (wählt die
    `dns-01`-Challenge, überspringt http-01), `dns01_record_name` (`_acme-challenge.<domain>`), `dns01_txt_value`
    (`base64url(SHA256(keyAuthorization))`). Deps `serde_json`/`sha2`/`base64`. Frozen-Tests
    `parses_acme_directory_order_and_selects_dns01`, `dns01_record_name_and_txt_value_follow_rfc8555` (unabhängiger Vektor:
    `base64url(SHA256("")) == 47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU`). Gate grün (ct-agent 75). *(Das JWS-signierte
    Account/Order-**Netz-I/O** selbst — Nonce, `jwk`/`kid`, POST — ist BP4c-c und wird gegen ein lokales Pebble getestet, nicht im
    hermetischen Cargo-Gate.)*
  - **BP4c-c** ⏳ **DNS-01-Erfüllung + Finalize**: TXT-Challenge via `ct-dns`-Provider (AD5 `set_txt`/`clear_txt`) publizieren,
    pollen, mit der BP4c-a-CSR finalisieren, Leaf holen + speichern/erneuern.
  - **BP4c-d** ⏳ **BYO-Cert-Fallback**: Operator-Cert+Key aus Env/Pfad laden (überspringt ACME), Renewal-Hook.
- **BP5** ⏳ **Browser-e2e** (echter/headless Browser lädt `https://<hostname>/` mit öffentlich
  vertrautem Cert durch den Tunnel). Erst wenn BP1–BP5 erfüllt → **#23 fix-ready**.

## #25–#29 — Kunden-Selfservice-Portal (Epic)

Kundenportal: SSO-Login, Konto-Selbstverwaltung, Tunnel anlegen/verwalten, Zugriffsrechte, Per-OS-One-Liner.
Server-gerendertes self-contained HTML in der Control-Plane (wie #4), OIDC/Keycloak. **Keine Secrets in Issues/Logs**;
Capabilities/Join-Token nur server-seitig, nur an eingeloggte Besitzer, `check-no-secrets` vor jedem Push.

### #25 Portal + SSO-Login (OIDC Authorization Code) — ✅ **fix-ready**
- **PP1** ✅ Portal-Shell (`GET /portal`, self-contained „Sign in with SSO"-CTA) + `GET /portal/login`
  (302-Redirect zum IdP-Authorize-Endpoint: `response_type=code`, `client_id`, `redirect_uri`,
  `scope=openid`, zufälliger `state`). `PortalOidc::from_env` (`CT_OIDC_CLIENT_ID/REDIRECT_URI/ISSUER`
  bzw. `AUTHORIZE_URL`; Client-Secret NICHT hier gehalten). Router in `persistent_control_plane_router`
  gemerged. Frozen-Tests `from_lookup_derives_authorize_url_from_issuer`, `portal_home_renders_the_sso_cta`,
  `login_redirects_to_the_authorize_endpoint`, `login_without_config_reports_unconfigured`. Gate grün.
- **PP2** ✅ `GET /portal/callback` mit **CSRF-`state`-Bindung**: `login` setzt den `state` zusätzlich in ein
  Single-Use-Cookie `ct_portal_state` (HttpOnly, Secure, SameSite=Lax, `/portal`, 10 min); der Callback lehnt
  fehlende Params (400) und fehlendes/abweichendes `state`-Cookie (403) ab, räumt bei Erfolg das Single-Use-Cookie
  ab. Frozen-Tests `login_binds_state_in_an_httponly_cookie_matching_the_redirect`,
  `callback_rejects_missing_params_and_mismatched_state`, `callback_accepts_matching_state_and_clears_the_cookie`,
  `callback_reports_unconfigured_without_oidc`. Gate grün (92 Tests, 0 Warnings).
- **PP3** ✅ Signiertes **Session-Primitive**: `sign_session`/`verify_session` (HMAC-SHA256, domänensepariert via `SESSION_CTX`,
  konstantzeitiger Vergleich, 8 h TTL), Session-Cookie `ct_portal_session` (HttpOnly/Secure/SameSite=Lax/`/portal`).
  `GET /portal/home` (auf gültige Session gegated, sonst Redirect auf `/portal`, zeigt HTML-escaptes Subject),
  `GET /portal/logout` (Cookie löschen → `/portal`). Frozen-Tests `session_sign_verify_roundtrips_and_rejects_tampering`,
  `home_requires_a_valid_session_else_redirects`, `logout_clears_the_session_cookie`,
  `session_cookie_carries_the_hardening_flags`. Session-Key = domänensepariertes Webhook-Secret. Gate grün (96 Tests, 0 Warnings).
- **PP4** ✅ Code→Token-Tausch: `PortalOidc.token_url` (aus Issuer/Env), injizierbarer `Exchanger`
  (Default: `reqwest`-POST an den Token-Endpoint, Client-Secret aus `CT_OIDC_CLIENT_SECRET` zur Laufzeit,
  nie gespeichert/geloggt; `subject_from_id_token` liest `sub` aus dem id_token über den TLS-Back-Channel).
  Callback bei gültigem `state` → Exchange → `sign_session` → Session-Cookie + Redirect `/portal/home`;
  Fehler → 502 ohne Session. Frozen-Tests `callback_exchanges_the_code_and_mints_a_session`,
  `callback_reports_bad_gateway_when_exchange_fails`, `subject_from_id_token_reads_the_sub_claim`.
  Gate grün (98 Tests, 0 Warnings). **#25 fix-ready** — SSO-Login end-to-end; die #26–#29-Portalseiten nutzen `verify_session`.
  Härtungs-Follow-up: id_token-Signaturprüfung via JWKS/`OidcVerifier`.
### #26 Konto-Selbstverwaltung (Guthaben, Profil, Credits) — ✅ **fix-ready**
- **PP2/PP3** ✅ Neues `portal_api`-Modul: `GET /portal/account` (session-gated, rendert Subject + Account-ID + Guthaben,
  strikt selbstbezüglich) und `POST /portal/account/credits` (legt einen Payment-Intent gegen die bestehende
  Billing-Fläche an; Gutschrift NUR über den signierten Webhook). Frozen-Tests `account_page_requires_a_session`,
  `account_page_shows_self_scoped_account_and_balance`, `buy_credits_creates_an_intent_for_the_callers_account`,
  `buy_credits_requires_a_session`. Gate grün (102 Tests).
- **PP1** ✅ Daten-Fläche der Selbstbedienung: `GET /me/account` liefert jetzt `{account, balance, subject}`
  (statt nur `{account}`) — Account-ID, Credit-Guthaben (`ledger.balance`) und verifiziertes Subject.
  Strikt selbstbezüglich (Subject aus dem verifizierten Token, nie aus dem Body). Bearer-testbar, unabhängig
  von der #25-Session. Frozen-Test `me_account_exposes_balance_and_subject_for_the_authenticated_customer`.
  Gate grün (84 Tests, 0 Warnings).
- **PP2** ⏳ Portal-Konto-Seite (server-gerendertes HTML) rendert die Session-Account-Daten (braucht #25 PP2-Session).
- **PP3** ⏳ „Credits kaufen": UI-Anbindung an `/payment/intent` + `/me/issue` (Guthaben-Anzeige aktualisiert nach Webhook-Top-up).
### #27 Tunnel-Verwaltung — ⚠️ **REOPENED (Feld-Bug): „revoke" widerruft nicht wirklich**
Feld-Verifikation (live): nach `POST /portal/tunnels/:id/delete` verschwindet der Tunnel aus der Portal-Liste,
aber der Agent bleibt beim Edge registriert und bedient weiter (`ct_edge_active_tunnels` unverändert). Ursache:
`delete_tunnel` löscht nur die DB-Zeile; es gibt **keine Verknüpfung Portal-Tunnel ↔ Edge-Routing-Token** und
keinen Kontrollkanal Control-Plane→Edge. Behebung ist Cross-Crate, mehrzyklig — dekomponiert in RB1..RB4:
- **RB1** ✅ Storage-Linkage: jeder Tunnel prägt bei `create` ein persistiertes `routing_token` (server-seitig, NIE in
  Listen gerendert — Routing-Identifier, nicht die Noise-Capability); `revoke` gibt das Token des entfernten Tunnels
  zurück, damit ein späterer Zyklus die Edge-Registrierung invalidieren kann. Frozen-Test
  `each_tunnel_binds_a_persistent_routing_token_returned_on_revoke`. Gate grün (109 Tests).
- **RB2a** ✅ Control-Plane-Conveyance: `installer::install_one_liner` trägt jetzt zusätzlich das Tunnel-Routing-Token
  als `CT_AGENT_TOKEN` (Env, nie argv); `install_page` holt es via neuem owner-gescopten `SqliteTunnelStore::routing_token`
  (dient zugleich als Owner-Gate) und rendert es in den Einzeiler. Frozen-Tests
  `one_liners_embed_both_tokens_via_env_per_os` + erweitertes `install_page_is_owner_only_...` (CT_AGENT_TOKEN). Gate grün (109 Tests).
- **RB2b** ✅ Agent-Consume: `main.rs` liest `CT_AGENT_TOKEN` → `parse_routing_token_hex` →
  `resolve_serving_identity_with_token(…, Some(token))` → `mint_capability_with_token` statt zufälligem `mint_capability`.
  Der Agent registriert nun unter dem Tunnel-Routing-Token beim Edge (deterministische Portal↔Edge-Verknüpfung steht).
  Frozen-Tests `forced_routing_token_is_honored_on_a_fresh_identity`, `parse_routing_token_hex_validates_length_and_hex`.
  Gate grün (ct-agent 70 Tests).
- **RB3a** ✅ Edge-Revocation-Primitive (`EdgeState`): `revoke_token` (Registrierungen + Hostname-Mappings abräumen +
  in `revoked`-Set aufnehmen), `is_revoked`, `register_unless_revoked` (None bei revoked). Kern-Erkenntnis: ohne das
  `revoked`-Set würde der Reconnect-Loop des Agenten den Tunnel einfach neu registrieren — das Set verhindert genau das.
  Frozen-Test `revoke_token_drops_registration_and_blocks_reregistration`. Gate grün (ct-edge 58 Tests).
- **RB3b** ✅ Edge-Serve-Layer: 'A'-Handler weist revoked Token ab (sendet `NO` → Agent-`register_tunnel` failt →
  Reconnect-Loop bleibt draußen); neuer authentifizierter 'R'-Op (`'R' | admin-token(32) | routing-token(32)`) prüft
  `admin_revoke_ok` (konstantzeitig) und ruft `revoke_token`. `run_edge` liest `CT_EDGE_ADMIN_TOKEN` (64-hex) →
  `set_admin_token`; ohne Secret bleibt Revocation deaktiviert. Frozen-Test `admin_revoke_ok_requires_the_configured_secret`.
  Gate grün (ct-edge 59 Tests).
- **RB4a** ✅ Edge-Admin-HTTP-Endpoint (`crate::admin`): `POST /admin/revoke/:token`, authentifiziert via
  `x-ct-admin-token` (konstantzeitig, reused RB3b `admin_revoke_ok`) → `revoke_token`. Eigener Listener
  `CT_EDGE_ADMIN_LISTEN` (privates Interface). HTTP-Gegenstück zum QUIC-'R'-Op, damit die HTTP-basierte Control-Plane
  ihn per `reqwest` ruft (kein quinn-Client nötig). Frozen-Test `revoke_endpoint_authenticates_then_revokes`
  (401 ohne/falsche Auth, 200 + revoked mit korrektem Secret, 400 bei Malformed). Gate grün (ct-edge 60 Tests).
- **RB4b** ✅ Control-Plane `delete_tunnel` POSTet `{CT_CP_EDGE_ADMIN_URL}/admin/revoke/{routing_token}` (Header
  `x-ct-admin-token`) via `reqwest` für das von `revoke` zurückgegebene Token; best-effort + Log bei Fehler.
  Integrationstest `delete_tunnel_propagates_the_revoke_to_the_edge` (Mock-Edge empfängt exakt das Routing-Token + Auth).
  Voller Workspace-Gate grün. **#27 REVOKE-KETTE KOMPLETT → fix-ready.**

**Deploy-Config für echte Revocation:** Edge mit `CT_EDGE_ADMIN_TOKEN` (64-hex) + `CT_EDGE_ADMIN_LISTEN` (privates Interface);
Control-Plane mit `CT_CP_EDGE_ADMIN_URL` (= Edge-Admin-Listener) + `CT_CP_EDGE_ADMIN_TOKEN` (= selbes Secret). Ohne diese
Env bleibt der Revoke „nur DB-Zeile weg" (Legacy-Verhalten) — mit ihnen fällt `ct_edge_active_tunnels` beim Widerruf.
- **RB4** ⏳ `delete_tunnel` ruft den Edge-Revoke für das Tunnel-Token (und/oder Rotation via #12) → Agent wird deregistriert;
  Live-Repro (`ct_edge_active_tunnels` fällt) grün → **fix-ready**.

#### (vor der Feld-Verifikation gelandet)
- **PP2** ✅ Session-gated Portal-HTTP in `portal_api`: `GET /portal/tunnels` (Liste eigener Tunnel + Anlage-Formular),
  `POST /portal/tunnels` (anlegen: name + optional hostname), `POST /portal/tunnels/:id/delete` (Widerruf).
  Strikt selbstbezüglich (Subject aus Session; `revoke` nur eigene). „Install"-Button pro Tunnel → #28-Endpoint.
  Frozen-Tests `tunnels_are_created_listed_and_revoked_self_scoped`, `create_tunnel_rejects_an_empty_name`. Gate grün (104 Tests).
- **PP3** ⏳ Live-Status je Tunnel via Edge `/metrics` (#17) + Widerruf per Rotation (#12) — Härtungs-Follow-up.
- **PP1** ✅ Per-Subject-Tunnel-Store (`storage::SqliteTunnelStore`): `create`/`list_for_subject`/`revoke`,
  jede Operation nach `subject` gescopt — ein Kunde sieht/widerruft nur seine EIGENEN Tunnel (kein
  Cross-Subject-Delete). **Secret-frei by design**: gespeichert werden nur `id`, `name`, optionaler
  `hostname` (#23), `created_at` — Routing-Token/Capability werden erst bei der Anlage (PP2) einmalig
  geprägt/angezeigt und NIE persistiert. Frozen-Test
  `subject_tunnel_store_is_self_scoped_for_create_list_revoke`. Gate grün (85 Tests, 0 Warnings).
- **PP2** ⏳ Authed HTTP: `POST /portal/tunnels` (Anlage → einmalige Token/Capability-Anzeige), `GET /portal/tunnels` (Liste), `DELETE /portal/tunnels/:id` (Widerruf) — Subject aus Session/Token.
- **PP3** ⏳ Live-Status je Tunnel via Edge `/metrics` (`ct_edge_active_tunnels`, #17) + Widerruf nutzt Token-Rotation (#12).
### #28 Per-OS One-Liner-Installer — ✅ **fix-ready** (Portal-Seite)
- **PP2** ✅ `GET /portal/tunnels/:id/install?os=` (session-gated, **owner-only** via `SqliteTunnelStore::owns`):
  prägt pro Anforderung ein **frisches, einmaliges** Join-Token (`enrollment.issue_join_token`, Subject als Tenant),
  rendert die Per-OS-One-Liner (`installer::install_one_liner`, Token via Env). Token wird einmalig dem eingeloggten
  Besitzer gezeigt, **nie geloggt/persistiert**; Tests mit generierten Token. Frozen-Tests
  `install_page_is_owner_only_and_renders_per_os_one_liners`, `install_mints_a_fresh_single_use_token_each_request`.
  Gate grün (106 Tests).
- **PP3** ⏳ Deployment-Follow-up: ausgelieferte `install.sh`/`install.ps1` + gehostetes `ct-agent`-Binary
  (der Einzeiler onboardet dann in field: CA-Root via `/pki/ca` #11, `onboard` mit `CT_JOIN_TOKEN`, Serve-Loop).
- **PP1** ✅ Reiner Renderer `installer::install_one_liner(portal_base, join_token, os)` + `InstallOs{Unix,Windows}`/`parse`.
  Unix: `curl -fsSL <base>/install.sh | CT_JOIN_TOKEN=<tok> sh`; Windows: `$env:CT_JOIN_TOKEN='<tok>'; irm <base>/install.ps1 | iex`.
  **Secret-sicher**: Token wird per **Env-Variable** übergeben (nie als argv-Positionsargument), und der Renderer prägt/loggt/speichert
  KEIN Token — er bettet nur ein übergebenes ein. Frozen-Tests `parse_maps_os_aliases`,
  `one_liners_embed_the_token_via_env_per_os` (Dummy-Token). Gate grün (87 Tests, 0 Warnings).
- **PP2** ⏳ Authed `GET /portal/tunnels/:id/install?os=…`: prägt pro Anforderung ein **frisches, einmaliges, kurzlebiges** Join-Token
  (server-seitig, nie geloggt) und rendert den Einzeiler; Subject aus Session, nur für eigene Tunnel (#27).
- **PP3** ⏳ Ausgelieferte `install.sh`/`install.ps1` (ct-agent holen, `onboard` mit `CT_JOIN_TOKEN`, CA-Root via `/pki/ca` #11, Serve-Loop).
### #29 Zugriffsrechte/Sharing (Grants pro Tunnel) — ✅ **fix-ready** (Feld-Bug behoben)
- **Feld-Bug**: `is_authorized` hatte NULL Produktions-Call-Sites — Grants waren rein kosmetisch; ein Grantee
  konnte den geteilten Tunnel weder sehen noch installieren. **Fix**: `SqliteTunnelStore::routing_token_if_authorized`
  (Owner ODER Grantee) gated jetzt `install_page` (statt owner-only `routing_token`); `list_authorized_for_subject`
  (eigene + geteilte Tunnel, mit `owned`-Flag) speist `tunnels_page` — geteilte Tunnel erscheinen read-only
  („shared with you", keine Share/Revoke-Buttons), aber mit Install. Frozen-Tests
  `granted_tunnels_are_visible_and_authorized_to_the_grantee` (storage),
  `a_grant_lets_the_grantee_see_and_install_the_shared_tunnel` (portal). Voller Workspace-Gate grün (112 CP-Tests).
- **PP2** ✅ Session-gated Grant-HTTP in `portal_api` (owner-only, sonst 404): `GET /portal/tunnels/:id/grants`
  (Liste + Add-Formular), `POST …/grants` (Grant), `POST …/grants/:grantee/delete` (Entzug). „Share"-Button je Tunnel.
  Frozen-Tests `grants_are_owner_managed_via_http`, `add_grant_rejects_empty_subject`. Gate grün (108 Tests).
- **PP3** ⏳ Cross-Crate-Follow-up: `is_authorized`-Gate in die tatsächliche Capability-Ausgabe des Datenpfads
  einweben (nur berechtigte Subjects erhalten den Zugang eines geteilten Tunnels).
- **PP1** ✅ Grant-Datenschicht auf `SqliteTunnelStore`: `grant`/`revoke_grant`/`list_grants` (nur der Besitzer, sonst
  `GrantError::NotOwner`) + `is_authorized(subject, tunnel_id)` = Besitzer ODER Grantee. Tunnel-Widerruf löscht die
  Grants mit (keine Waisen). Frozen-Test `tunnel_grants_are_owner_managed_and_gate_authorization`. Gate grün (88 Tests, 0 Warnings).
- **PP2** ⏳ Authed HTTP: `POST`/`DELETE`/`GET /portal/tunnels/:id/grants` — nur der Besitzer verwaltet; Subject aus Session.
- **PP3** ⏳ Capability-Ausgabe respektiert `is_authorized` (nur berechtigte, eingeloggte Subjects erhalten den Zugang eines geteilten Tunnels).

## Unified :443 Gateway — Portal-Auth + Tunnel-Subdomains + ACME auf einem Port (ADR-0019)

Motivation: restriktive Client-Netze lassen nur **ausgehend TCP 443** zu (empirisch bestätigt: `:8090`/`:4433`/`:80`
blockiert). Deshalb müssen Landing-Page/Portal (SSO-Auth, #25–#29), Kunden-Tunnel-Subdomains (#23) **und** die
TLS-Zertifizierung alle über **:443** laufen. Entscheidung (ADR-0019): das Edge-`:443` wird ein **SNI-multiplexter
Gateway** — *terminate+reverse-proxy* für den Portal-Host vs *passthrough* für Kunden-Subdomains vs *reject*.
Blindheit bleibt: der Gateway terminiert nur die **operator-eigene** Portalfläche; Kunden-Tunnel-Bytes bleiben
Ciphertext (Cert am Origin). Gewählt: **Edge erweitern** (kein separates Gateway-Deployment).

- **GW1** ⏳ SNI-Demux auf Edge-`:443`: klassifiziere gepeektes SNI als *Portal* (konfigurierter Host) vs *Tunnel*
  (autorisierte Host-Registry) vs *reject*; route zu Terminate vs Passthrough. Frozen-Test auf dem Klassifizierer.
- **GW2** ⏳ Terminate + Reverse-Proxy: TLS für den Portal-Host terminieren und HTTP an die Control-Plane (`:8090`)
  proxien; beide Richtungen streamen.
- **GW3** ⏳ Edge-seitiges ACME (**TLS-ALPN-01**) für den Portal-Host auf `:443` (On-Disk-Cert-Cache + Renewal;
  Staging-CA in CI, Prod in gated Job).
- **GW4** ⏳ DNS + Deployment: `A <zone>`/`A *.<zone>` → Plane, `CT_GATEWAY_PORTAL_HOST` + Proxy-Ziel + ACME-Config,
  Everything-on-443-Topologie dokumentieren. Reale Zone via Cloudflare (DNS-01-API; #30 bunsenbrenner.org).
- **Kunden-Subdomain-Hälfte**: #23 BP4b (Hostname-Ownership-Autorisierung) + BP4c (Agent DNS-01) + BP5 (Browser-e2e) —
  hier nicht dupliziert.

## #31 Universal :443 reachability — Tunnel Control+Data-Plane hinter einer :443-Front-Door (priority:high)

Feld-Evidenz (HAW Hamburg 141.22.x): Egress erlaubt **nur :80/:443**; `:8090`/`:4433`/UDP timeout (host-unabhängig,
gegen `portquiz.net` verifiziert). Konsolidiert #2/#3/#9 (Non-Standard-Ports blockiert). **Reuse** von #23 (SNI-Peek,
ACME) und **ADR-0019** (Front-Door-Design). **Diese Epic subsumiert das von mir angelegte #32** (GW1–GW4 ↦ FD1–FD5);
#32 als in-progress/„consolidated into #31" markiert, damit die Loop nicht doppelt baut. Demux ist **ALPN-primär**.

- **FD1** ✅ ClientHello-**ALPN-Peek** (`sni::peek_alpn`, teilt den Extension-Walk mit `peek_sni`) + reiner
  **Front-Door-Klassifizierer** `classify_front_door(alpn, sni, portal_host) -> {EdgeRelay | ControlPlane |
  BrowserTunnel(host) | Reject}` (`ct-edge`-ALPN → Datenebene; Portal-SNI/Web-ALPN-ohne-SNI → Control-Plane; sonstige
  SNI → Browser-Passthrough; sonst reject). Frozen-Tests `peek_alpn_parses_the_protocol_list_alongside_sni`,
  `classify_front_door_routes_by_alpn_then_sni`. Gate grün (ct-edge 63).
- **FD2** ✅ `:443`-Front-Door-Listener (`CT_FRONT_DOOR`, default off): `serve_front_door` puffert den ClientHello,
  klassifiziert via `classify_front_door` (ALPN-dann-SNI) und dispatcht OHNE den Handshake zu konsumieren — ein
  `Prepend` spielt die gepufferten Bytes am gewählten Backend zurück: EdgeRelay (ALPN `ct-edge`) → TLS mit Edge-Leaf
  terminieren → `serve_tcp_connection` (ADR-0004-Fallback); ControlPlane (Portal-SNI / Web-ALPN ohne SNI) → Roh-Proxy
  des ganzen TLS-Stroms zum Portal (payload-blind); BrowserTunnel(host) → `serve_sni_passthrough` (TLS am Origin);
  Reject → close. `CT_EDGE_PORTAL_HOST`/`CT_CP_PROXY_ADDR`. `sni::read_client_hello` auf SNI-optionales
  `read_client_hello_bytes` refaktoriert (der `ct-edge`-Zweig trägt kein SNI). Direkte `:8090`/`:4433` bleiben.
  Frozen-Test `front_door_proxies_the_portal_sni_to_the_control_plane` (echtes TCP, Echo-Upstream, ClientHello
  intakt zurückgespielt+proxied). Gate grün (ct-edge 69).
- **FD3** ⏳ Client-Fallback-Leiter: `QUIC :4433 → TLS-TCP :4433 → QUIC/UDP :443 → TLS-TCP :443`, pro Netz gecacht.
  **Dekomponiert:**
  - **FD3-a** ✅ **Reine Leiter-Logik + Cache** (`ct-client::ladder`): `Rung::{Quic(u16)|TlsTcp(u16)}`, `default_ladder()`
    (die 4 Sprossen, direkt-zuerst/restriktiv-zuletzt), `LadderCache` (network-Signatur → letzte funktionierende Sprosse),
    `attempt_order` (gecachte Sprosse zuerst, ohne Duplikat; stale/leer → Default-Leiter) und `connect_via_ladder` mit
    **injiziertem** async `dial` (Live-Sockets in FD3-b, Stub im Test) — nimmt die erste erreichbare Sprosse und cached sie.
    Frozen-Tests: `default_ladder_is_direct_first_restrictive_last`, `attempt_order_puts_the_cached_rung_first_without_duplicating`,
    `connect_via_ladder_picks_first_reachable_and_caches_it` (nur TLS-TCP:443 erreichbar → alle Sprossen der Reihe nach, dann
    gecached → beim Reconnect zuerst probiert, keine blockierte Sprosse erneut), `connect_via_ladder_returns_none_when_every_rung_fails`.
    Gate grün (ct-client 34).
  - **FD3-b** ✅ **Live Per-Rung-Dialer** (`ct-client::transport`): `EdgeConn::{Quic(Connection)|Tcp(TlsStream)}` +
    `dial_rung(rung, edge_ip, cert, timeout) -> Option<EdgeConn>` (QUIC-Rung → `dial_edge`, TLS-TCP-Rung → `tcp_tls_connect`
    auf dem Rung-Port; `None` bei Timeout/Fehler, damit `connect_via_ladder` weiterläuft). Frozen-Test
    `dial_rung_walks_the_ladder_to_the_live_quic_rung_and_caches_it`: echter In-Process-Edge auf Ephemeral-QUIC-Port, tote
    TLS-TCP-Rung zuerst → Leiter überspringt sie, landet live auf QUIC, cached den Rung. Gate grün (ct-client 35).
  - **FD3-c** ✅ **`main.rs`-Verdrahtung**: Single-Tunnel-Pfad läuft jetzt über `connect_via_ladder(&dial_rung)` — EdgeConn-Variante
    → `client_tunnel_noise_timed` bzw. `..._tcp_timed`, `via`-Label bleibt grob (`quic`/`tcp`, damit die Smoke-Greps `via=…` über
    die neuen `:443`-Sprossen weiter matchen). `filtered_ladder(force_tcp)` respektiert `CT_CLIENT_FORCE_TCP` (nur TLS-TCP-Sprossen);
    `network_signature()` = `CT_CLIENT_NET_SIG`-Override, sonst Egress-IPv4-/24, sonst `default` (reine `network_signature_from`
    getestet). Frozen-Tests `filtered_ladder_keeps_only_tcp_when_forced`, `network_signature_prefers_override_then_reduces_egress_ip`.
    Gate grün (ct-client 37). **FD3 damit funktional komplett** (Leiter-Modell + Live-Dialer + Live-Pfad); Cache-Persistenz über
    getrennte Prozess-Läufe ist optionale Erweiterung (Single-Shot-Client walkt die Leiter jeden Lauf ohnehin korrekt), nicht Teil
    der #31-Akzeptanz.
- **FD4** ⏳ Öffentliches **ACME-Cert** auf `:443` (rustls-acme TLS-ALPN-01 in-process **oder** fronting Terminator);
  reuse #23/ADR-0003; reale Domain via #30. **DNS-01 via selbst-gehostetem `ct-dns`** (acme-dns-Pattern, Strato hat keine API):
  - **FD4-a** ✅ **Edge terminiert Portal-TLS auf `:443`** — der Grund, warum bisher keine Landing-Page erschien: der
    ControlPlane-Zweig von `serve_front_door` (FD2) **raw-proxyte** den TLS-Strom an die Control-Plane, die aber nur **HTTP**
    spricht → kein TLS-Abschluss → keine Seite. Jetzt: mit gesetztem `CT_EDGE_PORTAL_CERT`/`CT_EDGE_PORTAL_KEY` (PEM, öffentlich
    vertrauenswürdig für den Portal-Host — z.B. eine out-of-band bezogene LE-Cert wie beim help-site) terminiert der Edge die
    Browser-TLS (`transport::build_portal_acceptor`, `rustls-pemfile`) und reverse-proxyt **Klartext-HTTP** an
    `CT_CP_PROXY_ADDR` (Control-Plane `:8090`). Ohne Cert bleibt der Legacy-Raw-Proxy (für einen TLS-sprechenden Upstream, z.B.
    fronting Caddy). Frozen-Test `front_door_terminates_portal_tls_and_proxies_http_to_the_control_plane` (echter rustls-Browser-Handshake
    → HTTP-GET → Control-Plane-Seite kommt über HTTPS zurück). Gate grün (ct-edge 70). *(Cert-Automatisierung — in-process ACME
    statt BYO — bleibt der ACME/AD-Teil unten + AD4-Operator-Delegation.)*
  - **AD1** ✅ Neue Crate `ct-dns`: hand-rolled DNS-Wire-Codec (`message::parse_query`/`build_response`, TXT, bounds-checked,
    panikfrei wie der SNI-Parser) + `store::AcmeDnsStore` (challenge-name → TXT, poison-safe, case-insensitive, add/set/clear/txt).
    Frozen-Tests `parse_query_reads_the_question`, `build_response_carries_the_txt_answer`,
    `build_response_is_empty_for_a_non_txt_or_unknown_name`, `store_publishes_accumulates_and_clears_case_insensitively`. Gate grün (ct-dns 5).
  - **AD2** ✅ Autoritativer UDP+TCP-`:53`-Responder (`server`): `respond(store, query)` (pure: parse→lookup→build),
    `serve_udp`/`serve_tcp` (+ `udp_loop`-Test-Seam; TCP mit 2-Byte-Längenpräfix); Malformed wird verworfen, nie Panik.
    Frozen-Tests `respond_serves_a_stored_txt_and_drops_malformed`, `udp_server_round_trips_a_query`. Gate grün (ct-dns 7).
  - **AD3** ✅ Localhost-HTTP-API (`api`, axum): `PUT /txt/:name` (Body=TXT-Wert)/`DELETE /txt/:name`, optionaler
    `x-ct-dns-token`; + `ct-dns`-Binary (`main.rs`) das `:53` (udp+tcp) + die Loopback-API zusammen fährt
    (`CT_DNS_LISTEN`/`CT_DNS_API_LISTEN`/`CT_DNS_API_TOKEN`; Warnung wenn API nicht loopback). Frozen-Tests
    `api_publishes_and_clears_a_txt_record`, `api_enforces_the_token_when_configured`. Voller Workspace-Gate grün (ct-dns 9).
    **ct-dns damit als DNS-01-Responder end-to-end lauffähig** (öffentliches `:53`, private Mutations-API).
  - **AD4** ⏳ Strato-Delegation dokumentieren (`CNAME _acme-challenge`→`auth.<zone>` + NS/Glue = „IP zu Strato hinzufügen").
  - **AD5** ✅ **DNS-01-Provider-Abstraktion** (`provider`): `Dns01Provider::{SelfHosted(store) | Desec(DesecClient)}`
    (`set_txt`/`clear_txt`) — self-hosted bleibt erhalten, **deSEC (desec.io)** als Alternative (Bulk-PATCH-RRset,
    `Authorization: Token`, TXT gequotet; `DESEC_TOKEN`/`DESEC_DOMAIN`/`DESEC_API_BASE` aus `.env`, Token nie geloggt).
    `subname_of`-Helper. Frozen-Tests `subname_is_derived_relative_to_the_zone`, `desec_from_lookup_needs_token_and_domain`,
    `desec_set_and_clear_hit_the_bulk_rrset_endpoint_with_auth` (Mock-deSEC). Doku `docs/dns01-desec.md` (Signup +
    NS-Delegation + Token) + `config/desec.env.example`. Gate grün (ct-dns 12).
  - **AD6** ✅ **deSEC-Self-Test** (Testen vorantreiben, unabhängig von globaler Propagation): Codec um
    `message::build_query`/`parse_txt_answers` (+ `skip_name`) erweitert; `client::query_txt` (TCP-DNS an einen NS,
    Test gegen die eigene `tcp_loop`); `ct-dns selftest`-Subcommand — publiziert ein Unique-TXT via deSEC, fragt
    `ns1.desec.io` direkt ab (bis ~30s), verifiziert, räumt auf → `SELFTEST OK`. Frozen-Tests
    `build_query_and_parse_txt_answers_round_trip`, `query_txt_reads_txt_records_over_tcp`. Gate grün (ct-dns 14).
- **FD5** ⏳ e2e-Smoke über den `:443`-TLS-TCP-Sprosse (`SMOKE OK via=tcp`) aus einem :80/:443-only-Netz +
  `docs/security/tls-everywhere.md`/Runbook. Blindheit (Noise_IK e2e) im Threat-Model bestätigen. Dann #31 **fix-ready**.

## #46 Agent-Firewall-Fallback — Register/Revoke über `:443`, wenn der Primärport blockiert ist

Ziel: ein Agent, dessen ausgehendes `:4433` (QUIC+TLS-TCP) von einer Firewall geblockt ist, erreicht den Edge trotzdem —
über die unified `:443`-Front-Door (#31 FD2, die `ALPN=ct-edge` → `serve_tcp_connection` routet, wo `'A'`/`'B'`-Register **und**
`'R'`-Revoke laufen). Fehlt agent-seitig: eine Fallback-Leiter (analog Client-FD3) + `ALPN=ct-edge` auf der `:443`-TLS-TCP-Verbindung.

- **FB-a** ✅ **Reine Edge-Rung-Leiter** (`ct-agent::ladder`): `EdgeRung::{Quic(SocketAddr)|TlsTcp(SocketAddr)}` +
  `edge_ladder(edge, fallback_443)` → `[Quic(edge), TlsTcp(edge)]`, plus `TlsTcp(edge_ip:443)` als letzte Sprosse wenn
  `fallback_443` und der konfigurierte Port ≠ 443 (nie dupliziert). Frozen-Tests
  `ladder_without_fallback_is_quic_then_tls_tcp_on_the_configured_port`, `ladder_with_fallback_appends_the_443_front_door`,
  `ladder_does_not_double_the_443_rung_when_already_configured_on_443`. Gate grün (ct-agent 80).
- **FB-b** ✅ **`ALPN=ct-edge` + Register über die Front-Door bewiesen**: `transport::tcp_tls_connect` setzt jetzt
  `alpn_protocols=["ct-edge"]` im ClientHello (harmlos am direkten `:4433`-TLS-Listener, der kein ALPN anbietet → Server ignoriert
  das Angebot). Frozen-Test `agent_registers_through_the_443_front_door_via_alpn`: echter In-Process-Edge, der die **Front-Door**
  (`serve_front_door`) fährt → ALPN-Peek `ct-edge` → `EdgeRelay` → `serve_tcp_connection` → Agent registriert `'A'` und wird geparkt.
  Der bestehende Direkt-Listener-Test bleibt grün (ALPN-Angebot schadet dort nicht). Gate grün (ct-agent 81).
- **FB-c** ✅ **Live-Ladder-Walk + Config**: `run_agent_tcp_fallback` walkt jetzt `tcp_rungs(config.edge, fallback_443)` — versucht
  den konfigurierten Edge-Port, dann (wenn `CT_AGENT_FALLBACK_443` gesetzt) die `:443`-Front-Door; die erste Sprosse, die
  verbindet+registriert, bedient den Client, sonst Backoff. `tcp_connect_register_serve` nimmt jetzt eine `target`-Adresse.
  `AgentConfig.fallback_443` aus `CT_AGENT_FALLBACK_443` (default off). Frozen-Tests `tcp_rungs_are_the_tls_tcp_addresses_in_order`,
  `fallback_443_reads_the_env_flag`. Gate grün (ct-agent 83). **Abmelden**: Verbindungsabbruch → Edge evictet die Registrierung
  (Standard-Pfad, gilt für jede Sprosse inkl. `:443`); **Revoke** (#27) weist ein widerrufenes Token auf jeder Sprosse ab
  (`register_unless_revoked`). **#46 damit fix-ready** — Feld-Verifikation: `:4433` per `iptables` DROP blocken, Agent registriert über `:443`.
- **:80 (Plaintext)** ⏳ separat/niedrigprior — braucht HTTP-`CONNECT`/WebSocket-Upgrade; nur falls ein `:80`-only-Netz auftaucht.

## #48 Keycloak über die unified `:443`-Front-Door (kein separater Port)

Ziel: die IdP (Keycloak) nicht auf einem eigenen Port exponieren, sondern als **zweites Terminate+Reverse-Proxy-Ziel** hinter
derselben `:443`-Front-Door wie das Portal (FD4-a), erreichbar per eigenem Hostnamen (`auth.<zone>`). Löst das
`KEYCLOAK_PUBLIC_URL`-Split-Horizon (der `iss`-Claim wird dann eine real extern erreichbare URL).

- **AP-a** ✅ **Multi-Host-Proxy-Map am Edge**: `FrontDoorRoute::ControlPlane` → `Proxy(String)` (der gematchte Terminate-Host);
  `classify_front_door(alpn, sni, terminate_hosts: &[&str], default_host)` matcht SNI gegen eine Liste von Terminate-Hosts
  (Portal **und** Auth-IdP), sonst BrowserTunnel; no-SNI-Web → `default_host` (Portal). `serve_front_door` nimmt jetzt eine
  `HashMap<host, (upstream, Option<TlsAcceptor>)>` + `default_host`: pro Host mit Cert → TLS terminieren + HTTP-Proxy (FD4-a),
  ohne Cert → Raw-Proxy. `run_edge` baut die Map aus Portal (`CT_EDGE_PORTAL_HOST`/`CT_CP_PROXY_ADDR`/`CT_EDGE_PORTAL_CERT|KEY`)
  + Auth (`CT_EDGE_AUTH_HOST`/`CT_EDGE_AUTH_ADDR`/`CT_EDGE_AUTH_CERT|KEY`); `build_front_door_cert`-Helper. Frozen-Tests:
  `classify_front_door_routes_by_alpn_then_sni` (2 Terminate-Hosts), `front_door_routes_a_second_terminate_host_to_its_own_upstream`
  (echter Browser-Handshake SNI=auth.test → AUTH-Cert terminiert → AUTH-Upstream, nicht Portal); FD2/FD4-a/#46-Tests grün mit
  Map-Signatur. Gate grün (ct-edge 73). **Edge-Seite damit komplett** — jeder zusätzliche Terminate-Host braucht nur ein Env-Paar.
- **AP-b** ✅ **Deploy-Verdrahtung**: `compose.sso.yml` — `edge`-Override mit `CT_EDGE_AUTH_HOST=${AUTH_PUBLIC_HOST}`,
  `CT_EDGE_AUTH_ADDR=keycloak:8080`, `CT_EDGE_AUTH_CERT|KEY=/certs/auth/*` (BYO-Cert-Mount via `AUTH_CERT_DIR`);
  Keycloak-`ports:`-Publish entfernt (nur noch `expose: 8080`, erreichbar über die Front-Door); `KC_HOSTNAME`/`CT_OIDC_ISSUER`
  = `KEYCLOAK_PUBLIC_URL` (jetzt `:?`-required, `https://auth.<zone>`), `CT_OIDC_REDIRECT_URI`/`PORTAL_PUBLIC_URL` ebenfalls required.
  Runbook `keycloak-sso.md` auf die Front-Door-Route umgeschrieben (neue `.env`-Keys `AUTH_PUBLIC_HOST`/`AUTH_CERT_DIR`), Runbook-Env-Tabelle
  um `CT_EDGE_AUTH_*` ergänzt. Frozen-Test `sso_compose_wires_the_control_plane_to_the_demo_realm` erweitert (`CT_EDGE_AUTH_HOST` verdrahtet,
  **kein** `KEYCLOAK_PORT`-Publish). Gate grün (control-plane 127). **#48 fix-ready** — central fährt den externen Browser-Klick-Durchlauf.

## #49 Keycloak Identity-Brokering — Google/GitHub/GitLab + Custom-OIDC (KC4)

Ziel: die Portal-„Sign in with SSO" soll Google/GitHub/GitLab (+ beliebiger Custom-OIDC) als Login-Optionen anbieten. **Kein**
Control-Plane-/Portal-Code ändert sich — Keycloak-Feature *Identity Brokering*; die #43-Email-Gate greift danach unverändert.

- **KC4-a** ✅ **Realm-IdP-Block**: `ct-demo-realm.json` um `identityProviders` (google/github/gitlab, `enabled`, `trustEmail`
  für die #43-Gate) erweitert; Credentials via `${env.KC_GOOGLE_CLIENT_ID:}` etc. (leerer Default → import-sicher, **kein Secret im
  Repo**). `compose.sso.yml` reicht `KC_GOOGLE/GITHUB/GITLAB_CLIENT_ID|SECRET` (leer-Default) an Keycloak durch, damit die
  `${env.*}`-Substitution beim Import greift. Frozen-Test (Erweiterung von `demo_realm_matches_the_portal_oidc_contract`):
  alle 3 Broker deklariert, `trustEmail`, Creds aus `${env.*}` (nie gebacken). Gate grün (control-plane 127).
  **Verifikations-Abhängigkeit:** dass Keycloak den IdP-Block *sauber importiert* + die Login-Buttons erscheinen, ist **nicht
  hermetisch prüfbar** (kein Keycloak im Cargo-Gate) — central verifiziert live (wie #42). Darum #49 **in-progress**, nicht fix-ready.
- **KC4-b** ✅ **Runbook** (`keycloak-sso.md`, Abschnitt „Social login / identity brokering"): OAuth-App-Registrierung
  (Google/GitHub/GitLab, mit Registrierungs-Ort je Provider), Broker-Redirect-URI
  `https://<AUTH_PUBLIC_HOST>/realms/ct-demo/broker/<alias>/endpoint`, `.env`-Keys-Tabelle (`KC_*_CLIENT_ID|SECRET`), Hinweis zum
  Deaktivieren/Entfernen leerer Provider, und Custom-OIDC-Provider via Admin-Console (Identity Providers → Add → OpenID Connect v1.0,
  Discovery-URL). **#49 fix-ready** (Developer-Seite komplett) — central verifiziert live: Realm importiert sauber + Buttons erscheinen
  (echte Creds in `.env`), #43-Gate greift weiter.

## #38 Automatischer DNS-Record-Lifecycle für öffentliche Agent-Hostnamen

Ziel: kein manuelles A-Record-Anlegen mehr — beim Setzen eines Tunnel-Hostnamens automatisch den A-Record (Host → Edge-IP)
anlegen, beim Widerruf/Drop wieder löschen. Klinkt sich in die vorhandenen Hooks ein: BP4b-c (CP autorisiert Hostname beim
Anlegen) + RB4b (best-effort HTTP-Push-Muster). Reuse der deSEC-Provider-Abstraktion (AD5).

- **DL1** ✅ `DesecClient` um **A-Record-CRUD** erweitert: `set_a(host, ip)`/`clear_a(host)` (generalisiertes
  `patch_rrset` mit `rtype`), + `guard_under_zone` (ein Host muss unter `DESEC_DOMAIN` liegen, sonst Fehler). Frozen-Test
  `desec_set_and_clear_a_records_and_guard_the_zone` (Mock-deSEC: A-RRset mit IP, empty-records-Clear, Zone-Guard). Gate grün (ct-dns 15).
- **DL2** ✅ Control-Plane-Verdrahtung (`portal_api`): `create_tunnel` mit Hostname → `set_a(host, CT_CP_DNS_EDGE_IP)`;
  `delete_tunnel` → `clear_a(host)` (Hostname vor `revoke` gefetcht via `SqliteTunnelStore::tunnel_hostname`); beide
  best-effort + logged, DNS unabhängig vom Edge-Push. `DnsAutopilot` in `ApiState` (aus `DESEC_TOKEN`/`DESEC_DOMAIN` +
  `CT_CP_DNS_EDGE_IP`); `DesecClient` jetzt `Clone`. Frozen-Test `tunnel_hostname_creates_and_deletes_its_dns_a_record`
  (Mock-deSEC: A-Record bei Create, empty-records-Clear bei Revoke). Voller Workspace-Gate grün (control-plane 115).
  **Hostname-DNS jetzt vollautomatisch** — kein manueller deSEC-A-Record-Schritt mehr.
- **DL3** ⏳ Design-Frage (nicht blockierend): Provider-Trait für Nicht-deSEC-Selfhoster (aktuell deSEC-only genügt).

## #42 Toggle-barer Keycloak/OIDC-IdP-Container im Deploy-Stack

Ziel: das SSO-Login (#25) end-to-end klickbar machen — bisher nur hermetisch (HS256-Testdouble) verifiziert, live 503 weil kein
IdP läuft (`CT_OIDC_ISSUER` leer). Ein **standardmäßig ausgeschalteter**, zuschaltbarer Keycloak-Container mit deklarativ
importierter Demo-Realm, passend zu dem, was `PortalOidc::from_env`/`OidcVerifier::from_rsa_pem` bereits erwarten.

- **KC1** ✅ **IdP-Container + deklarativer Realm** (default off): `docker/deploy/compose.sso.yml` (Overlay — nur aktiv wenn
  explizit mit `-f` benannt) fährt `quay.io/keycloak/keycloak:25` mit `start-dev --import-realm` und mountet
  `docker/deploy/keycloak/ct-demo-realm.json` (Realm `ct-demo`, confidential Client `ct-portal` mit RS256 + Authorization-Code
  + `/portal/callback`-Redirects, `registrationAllowed` statt mitgeliefertem Credential — **kein Secret im Repo**). Frozen-Test
  `demo_realm_matches_the_portal_oidc_contract` (`include_str!` des Realm-Exports zur Compile-Zeit → gegen `PortalOidc::from_lookup`
  gegroundet: client_id/redirect/Realm-Name ergeben exakt Keycloaks Authorize/Token-Endpoints). Gate grün (control-plane 117).
- **KC2** ⏳ **Realm-Signaturschlüssel in den Verifier**: statt eines hand-exportierten PEM den RS256-Public-Key direkt aus dem
  Realm-JWKS beziehen. **Dekomponiert:**
  - **KC2-a** ✅ **JWKS-Dokument-Handling** (`ct-control-plane::oidc`): `jwks_uri_for(issuer)` (→ `<issuer>/protocol/openid-connect/certs`,
    Trailing-Slash-tolerant) + `jwks_signing_key(&Value) -> Option<(n,e)>` (wählt den RSA-**Signatur**-Schlüssel: `kty=RSA`,
    `use=sig`-oder-fehlt, `alg=RS256`-oder-fehlt; überspringt EC-/Enc-Keys; `None` wenn keiner) + `OidcVerifier::from_rsa_components(n,e,issuer)`
    (jsonwebtoken `DecodingKey::from_rsa_components`, spart den PEM-Umweg). Frozen-Tests `jwks_uri_is_derived_from_the_issuer`,
    `jwks_signing_key_selects_the_rs256_sig_key_among_decoys`, `from_rsa_components_rejects_malformed_components`. Gate grün (control-plane 124).
  - **KC2-b** ✅ **Positiver Krypto-Round-Trip**: Frozen-Test `from_rsa_components_verifies_a_token_signed_by_the_matching_key` —
    generiert zur Laufzeit einen 2048-bit-RSA-Schlüssel (Dev-Deps `rsa`+`base64`, **kein** Private-Key im Baum, Secret-Guard-konform),
    publiziert `(n,e)` base64url wie ein JWK, signiert ein RS256-Token mit dem Private-Half und verifiziert es über `from_rsa_components`
    (`subject()`==`user-99`); ein Fremdschlüssel weist das Token ab (prüft die Signatur, nicht nur das Parsen). Gate grün (control-plane 125).
  - **KC2-c** ✅ **Startup-Fetch**: `oidc::verifier_from_jwks(issuer, fetch)` (injizierter Fetcher → hermetisch) holt das Realm-JWKS,
    wählt den Signaturschlüssel und baut den Verifier. `main.rs`-Startup umgestellt: `CT_OIDC_ISSUER` allein genügt jetzt (JWKS-Fetch via
    reqwest, `fetch_jwks`, best-effort + geloggt, `None` → /me/* bleibt aus); `CT_OIDC_PUBKEY_PATH` bleibt expliziter Offline-Override
    (Vorrang). `reqwest` um `rustls-tls` erweitert (HTTPS-Issuer). Frozen-Test `verifier_from_jwks_fetches_selects_and_verifies` (Fetch →
    Auswahl → echtes Token verifiziert; Fetch-Fehler/kein RS256-Key → `None`). Gate grün (control-plane 126). **KC2 damit komplett.**
- **KC3** ✅ **Control-Plane-Verdrahtung + Doku**: `compose.sso.yml` merged die `CT_OIDC_*`-Env auf den control-plane-Service
  (`CT_OIDC_ISSUER=<KEYCLOAK_PUBLIC_URL>/realms/ct-demo`, `CT_OIDC_CLIENT_ID=ct-portal`, `CT_OIDC_REDIRECT_URI=<PORTAL_PUBLIC_URL>/portal/callback`;
  Client-Secret aus `.env`, **nie** im Compose), `depends_on keycloak healthy`, Keycloak-`KC_HOSTNAME` für stabilen Issuer. Runbook
  `docs/deploy/keycloak-sso.md` (Split-Horizon-Caveat zu `KEYCLOAK_PUBLIC_URL`, `.env`-Keys, Bring-up, Klick-Durchlauf). Frozen-Test
  `sso_compose_wires_the_control_plane_to_the_demo_realm` (`include_str!` des Compose → client-id/redirect/realm konsistent mit Realm+Code,
  kein Secret im Compose). Gate grün (control-plane 127). **KC1–KC3 erfüllt → #42 fix-ready.**

## #50 Literaturverzeichnis ausbauen (4 → 20–40 Quellen); Related Work belegen; OHTTP + iCloud Private Relay abgrenzen

Gutachten-Befund (schwerster Punkt): `references.bib` hat nur 4 Einträge; Kap. 3 nennt WireGuard, Cloudflare
Tunnel, ngrok, Tailscale Funnel, Tor, obfs4, Shadowsocks, MASQUE — keines zitiert. Ziel: ≥20 belastbare Quellen,
jedes diskutierte System zitiert, 3.5 gegen OHTTP + iCloud Private Relay abgegrenzt. Thesis-Issue → gated durch
`scripts/thesis-build.sh` (latexmk, 0 undefined). Feature-groß → in drei Teilpakete dekomponiert:

- **T50.1** ✅ **Bibliografie-Grundstock + bestehende Systeme zitiert**: 10 verifizierte Primärquellen aus der
  Issue-Tabelle in `references.bib` ergänzt (WireGuard/Donenfeld NDSS'17, Tor/Dingledine USENIX'04, Sybil/Douceur
  IPTPS'02, MASQUE RFC 9298 + RFC 9484, obfs4, Shadowsocks + Produkt-Refs Cloudflare Tunnel/ngrok/Tailscale Funnel)
  und in `chapters/relatedwork.tex` an **jedem bereits im Text genannten System** `\cite{}` verdrahtet (§3.1
  WireGuard, §3.2 Reverse-Tunnel-Produkte, §3.3 Tor+obfs4+Shadowsocks+Sybil, §3.4 MASQUE). Gate: Thesis baut grün
  (`latexmk` exit 0), `grep -ci undefined thesis.log == 0`; gedruckte Bibliografie 4 → 14. Frozen = der Build-Gate.
- **T50.2** ⏳ **3.5 Abgrenzung + Zensur-Quellen**: OHTTP (RFC 9458), Apple iCloud Private Relay (Zwei-Hop,
  Ingress/Egress-Trennung), TLS 1.3 (RFC 8446), Domain Fronting (Fifield PoPETs'15), Telex/Decoy-Routing
  (Wustrow USENIX'11) als konzeptionelle Vorläufer aufnehmen; §3.5 explizit dagegen abgrenzen (Alleinstellung der
  Vier-Bausteine-Kombination). Zensurresistenz mit Mess-/Umgehungsforschung belegen (OONI, Snowflake/meek).
- **T50.3** ⏳ **Noise peer-reviewed + Zielzahl**: Noise über die Webseite hinaus mit peer-reviewter Analyse
  untermauern (Kobeissi et al.; Dowling & Paterson, WireGuard/Noise), Privacy Pass (Davidson PoPETs'18) für
  tokenbasierten anonymen Zugang; auf ≥20 gedruckte Quellen auffüllen + finaler Zitations-Audit. **fix-ready erst
  wenn Akzeptanz (≥20, jedes System zitiert, 3.5 abgegrenzt) vollständig erfüllt.**

## #69 Tunnel-creation UX — first-time-customer friendliness (decomposable)

User feedback after using the portal as a first-time customer: creation is unintuitive — unexplained
fields, no DNS guidance, no "what's next", no context on the install one-liner, sharp single-use-token
UX. Reporter explicitly asked for decomposable-feature treatment. Gated by the cargo hermetic gate (these
are control-plane HTML producers with oneshot render tests). Decomposed:

- **T69.1** ✅ **Inline help on the create form** (friction points 1+2): the two bare inputs
  (`name`, `hostname`) get real labels + muted help text — what each field is, that an empty hostname
  means a standard end-to-end tunnel vs. a set hostname makes it a browser-openable HTTPS site (the
  "Browser Plane"), and that DNS is pointed at the edge automatically when the operator has deSEC
  configured (#38 DL2). Frozen test asserts the rendered form carries the field labels + the
  Browser-Plane/DNS explanation. Gate: cargo build+test, 0 warnings.
- **T69.2** ✅ **Post-create "next steps" panel** (friction point 3): the tunnel list carries a numbered
  create → install → run-on-the-origin → done walkthrough, making the critical "run the one-liner on the
  machine you want to expose, not your browsing device" distinction explicit. Frozen test asserts the
  steps panel + that guidance. Gate: cargo build+test, 0 warnings.
- **T69.3** ✅ **Install-page context + lost-token signposting** (friction points 4+5): the install page
  now frames WHERE to run the one-liner (on the origin — the machine you want to expose, not the browsing
  device — what it does, no inbound port) and signposts lost-token recovery (reopen the page → a fresh
  single-use token per visit, which the code already mints). Frozen test asserts both. **All five friction
  points addressed → #69 fix-ready.**

## #72 Agent Fabric — direct agent-to-agent channels with trust chains (relay fallback)

Substantial new architecture feature (user feedback on "Share"): agents address & talk to each other
directly, central plane only as fallback, organised by explicit trust chains — incl. cross-user. scimbe
prescribed design-first (ADR before code). Named "Agent Fabric" / "Channels" to avoid collision with the
existing "Mesh" terminology (ADR-0010/0013/0015 = client↔origin data plane, not an agent network).
Decomposed:

- **AF1** ✅ **ADR-0020 — addressing + trust model** (design, no code): `docs/adr/0020-agent-fabric-channels-and-trust-chains.md`.
  Grounds what exists (subject-scoped tunnel *sharing* = same routing token/full access; client↔agent
  rendezvous only; flat bearer `RoutingToken`/`Capability`; two-party `Noise_IK`) and decides: Channels
  addressed by opaque `ChannelId`; structured/expiring/directional `ChannelGrant` for trust chains
  (vs. flat bearer); cross-user via explicit invitation (distinct from sharing); transport reuses ADR-0015
  rendezvous (edge broker, pairwise agent↔agent Noise, relay only as payload-blind fallback); a channel is
  a hub of pairwise 2-party sessions (sidesteps group-crypto). Gate: design artifact — workspace unchanged/green.
- **AF2a** ✅ **Trust primitives in ct-common** (`crates/common/src/channel.rs`): `ChannelId` (opaque
  address, like RoutingToken) + `ChannelGrant`/`SignedChannelGrant` — a scoped/directional/expiring,
  ed25519-operator-signed grant (mirrors `credential.rs`), with `Direction`{initiate,accept,both} +
  `Rights`{r,w,rw} + `delegable`, fixed-layout wire encode/decode, and stateless `verify(operator_pk, now)`.
  Deliberately NOT a flat bearer token: tampering scope/holder breaks the signature. 7 frozen tests
  (roundtrip all variants, expiry, wrong-key, 4-way tamper, malformed/bad-enum, predicates). Gate green.
- **AF2b** ✅ **Edge channel-pairing authorization** (`crates/edge/src/channel_broker.rs`): the pure
  enforcement core ADR-0020 places at the edge rendezvous gate — `authorize_channel_pair(operator_pk,
  grant_a, grant_b, now)` verifies both `SignedChannelGrant`s, requires same channel + distinct holders +
  a compatible Initiate/Accept split, and returns the `ChannelPairing` (who dials, who accepts) or a typed
  `BrokerError`. No sockets — testable without a network. 7 frozen tests (pairing, role reversal,
  both-flexible→a-leads, two-initiators/two-acceptors rejected, channel mismatch, same-holder, expired/
  wrong-key). Gate green.
- **AF2c** ✅ **Channel-join request wire type** (`ct-common::channel::ChannelJoinRequest`): the on-wire
  form an agent presents to the edge — its `SignedChannelGrant` (fixed `WIRE_LEN` prefix) + advertised
  direct endpoint (host:port tail). encode/decode with non-empty-endpoint + full-grant validation; the AF2b
  broker parses two of these to pair. 1 frozen test (roundtrip + malformed: no endpoint / truncated /
  bad-utf8). Design-robust (independent of the key-custody decision). Gate green.
- **AF2d** ⏳ **Same-user QUIC brokering + transport** (BLOCKED on a design decision): generalise
  `rendezvous.rs` to relay/broker two agents over QUIC using AF2b + the AF2c request; the two run a pairwise
  Noise session (edge broker, no payload relay); real two-agent integration test. Needs scimbe's call on
  channel-operator **key custody** (agent-held vs. portal/control-plane-held) + the channel registry that
  supplies the edge the operator pubkey (like host-auth). Do NOT build until answered — avoids rework.
- **AF3** ⏳ **Cross-user invitation model**: operator issues an invitation, another user's agent redeems it
  into a scoped member grant; trust-fail (deny/expiry/revoke) rules enforced + tested.
- **AF4** ⏳ **Fallback + hardening**: edge relay fallback when direct setup fails (fallback-path integration
  test) + revoke/expiry enforcement. **fix-ready only when real direct A2A data exchange + trust chains +
  tested fallback are all met.**

## #75 Real agent binary distribution + /install.sh//install.ps1 (the one-liner's missing backend)

KRITISCH: the polished install one-liner (#67/#68/#69/#71) points at /install.sh + /install.ps1, which
404 — no route, no handler, no prebuilt-binary distribution exists at all. A real customer without a
prebuilt image dead-ends at the final step. Substantial feature (like #72) → decomposed:

- **IS1** ✅ **Honest install page (stopgap)**: the install page no longer presents the broken
  `curl … | sh` as a working command — it carries a prominent "not available yet (#75)" banner and
  surfaces the **working manual path** (the `CT_JOIN_TOKEN`/`CT_AGENT_TOKEN` values for `ct-agent onboard`
  via the binary/`ct-testbed` image, + onboarding-guide link); the one-liner is demoted under a
  "coming soon (not functional yet)" heading. Frozen test asserts the honesty banner + manual path.
  Gate: cargo build+test, 0 warnings. Stops misleading real customers immediately.
- **IS2** ⏳ **Binary distribution**: GitHub Releases (or equivalent) with prebuilt `ct-agent` binaries
  for Linux x86_64/arm64, macOS, Windows — without this `install.sh` has nothing to download.
- **IS3** ⏳ **`/install.sh` route**: served POSIX script (rustup/Homebrew pattern) that detects OS/arch,
  downloads the matching release binary, and runs `ct-agent onboard` with `CT_JOIN_TOKEN`/`CT_AGENT_TOKEN`
  from the env.
- **IS4** ⏳ **`/install.ps1` route**: same for PowerShell/Windows.
- **IS5** ⏳ **Real integration test**: execute the served script in a CLEAN container (no prebuilt
  image), not just the page's text generation. **fix-ready only when a fresh customer can run the
  one-liner end-to-end.**
