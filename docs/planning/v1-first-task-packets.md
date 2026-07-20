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
- **T50.2** ✅ **3.5 Abgrenzung + Zensur-Quellen**: 6 verifizierte Quellen in `references.bib` (OHTTP RFC 9458,
  TLS 1.3 RFC 8446, Domain Fronting Fifield PoPETs'15, Telex Wustrow USENIX'11, OONI Filastò/Appelbaum FOCI'12,
  Apple iCloud Private Relay Overview). §3.5 um einen Absatz erweitert, der OHTTP und iCloud Private Relay als
  die **konzeptionell nächsten Vorläufer** benennt und explizit abgrenzt (OHTTP: Gateway sieht Ziel+Klartext,
  request-scoped; Private Relay: Zwei-Betreiber-Trennung, reguläre Ziel-TLS — beide ohne Nutzlast-Blindheit
  gegenüber einem *einzelnen* Vermittler) → stützt die Vier-Bausteine-Alleinstellung. §3.3 Zensurumgehung mit
  Domain Fronting + Telex + OONI belegt; §3.4 TLS 1.3 zitiert. Gate: Thesis baut grün (`latexmk` exit 0,
  **0 undefined citations**, 62 S.); gedruckte Bibliografie **14 → 20** — Akzeptanz (≥20, jedes System zitiert,
  3.5 abgegrenzt) **erfüllt**.
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
- **AF2d** ⏳ **Same-user QUIC brokering + transport** (UNBLOCKED — key custody decided 2026-07-17:
  **agent-held**, ADR-0020). Operator agent holds its channel keypair + signs grants; control-plane
  channel registry stores only the operator PUBLIC key + membership and hands the edge that pubkey (like
  host-auth supplies authorized hostnames). Then: generalise `rendezvous.rs` to broker two agents over QUIC
  using AF2b + the AF2c request; the two run a pairwise Noise session (edge broker, no payload relay); real
  two-agent integration test. Split: AF2d-registry then AF2d-transport.
- **AF2d-registry** ✅ **Control-plane channel store** (`SqliteChannelStore` in storage.rs): agent-held
  custody — stores the operator PUBLIC key + membership (never a signing key), owner-scoped. Methods:
  register_channel (re-key own, reject others), operator_pubkey (the edge lookup, like host-auth),
  channel_owner, add_member/is_member/remove_member (owner-scoped, idempotent). 2 frozen tests
  (register+lookup+owner-scoped membership; survives reopen). Gate green.
- **AF2d-transport-a** ✅ **Edge QUIC channel-join admission** (`ct-edge::channel_broker::resolve_channel_join`):
  accepts one `ChannelJoinRequest` over QUIC, looks up the channel's operator pubkey (injected, wired to
  AF2d-registry), verifies the grant, replies OK/NO, returns the request + advertised endpoint. 2 QUIC
  integration tests (admit valid; refuse unknown-channel + expired). Gate green.
- **AF2d-transport-b** ✅ **Two-agent broker** (`broker_channel_rendezvous`): accepts two channel-joins for
  the same channel, pairs them via AF2b, and replies to each with the PEER's advertised endpoint (`OK
  <endpoint>`) so the two can connect directly (edge = rendezvous broker, never payload). Refactored the
  read step into `accept_and_read_join`. Real TWO-agent QUIC integration test (two clients pair + each
  learns the other's endpoint + roles follow directions). Gate green (channel_broker 10).
- **AF3** ⏳ **Cross-user invitation**: operator issues an invitation → another user's agent redeems it into
  a scoped member grant (agent-signed); trust-fail (deny/expiry/revoke) rules + tests. Split:
  - **AF3-primitive** ✅ **Invitation trust primitive** (`ct_common::channel`): the cross-user handoff, pure
    crypto. `ChannelInvitation { channel, invitee_identity, direction, rights, delegable, expires_at }` +
    `SignedChannelInvitation` (operator-signed; fixed 139-byte wire `encode`/`decode` mirroring
    `SignedChannelGrant`) + `verify_invitation(operator_pubkey, now)` (sig + expiry). Bound to the invitee's
    **identity** key (not a member key), so the operator can invite *before* knowing the key the invitee will
    use. Redemption: `invitation_redeem_bytes(channel, invitee_identity, holder)` — the domain-separated
    message the invitee signs with its **identity** key to accept and bind the `holder` key it chose —
    verified by `verify_invitation_redemption(...)`. So only the intended invitee can accept, only into the
    key it chose, only for that channel. Signing bytes are domain-separated (`ct-chan-invite:v1` vs
    `ct-grant:v1`), so an invitation can't be replayed as a grant. Frozen tests: verify sig+expiry+wrong-key;
    wire round-trip + truncation→Malformed; redemption binding (wrong holder/channel/identity all rejected);
    invitation≠grant domain separation. Gate green.
  - **AF3-redeem-core** ✅ **Redemption verification** (`ct_common::channel::redeem_invitation`): the two-proof
    gate the CP runs on a redemption — `verify_invitation` (operator authentic + current) **and**
    `verify_invitation_redemption` (the intended invitee accepted + bound `holder`) — returning, on success,
    the `ChannelGrant` claims (channel/direction/rights/delegable/expiry) now bound to the chosen `holder`,
    exactly what the CP records as membership. **No operator private key at redeem time** — the operator
    authority already rides in the signed invitation, so a provider-blind CP admits the member from the two
    public-key proofs alone. Frozen test `redeem_invitation_yields_membership_claims_bound_to_the_chosen_holder`
    (happy path binds the chosen member key not the invitee identity; expired→Expired; wrong operator→
    BadSignature; a holder-swap→BadSignature). Gate green.
  - **AF3-redeem-cp** ✅ **The proof-gated CP endpoint** (`service::channel_invite_router` →
    `POST /channel/invite/redeem`): a *different* user's agent joins a channel it was invited to, **with no
    session**. Takes `{invitation, redeem_sig, holder, noise_pubkey, noise_attestation}` (hex), looks up the
    channel's `operator_pubkey` from the registry (404 if unknown), runs `redeem_invitation` (operator
    invitation + invitee redemption; `Expired`→410, other→403) then `verify_member_noise_attestation` (#101;
    403), and `add_member`s the invitee's holder + Noise key **on the owner's behalf** (the invitation *is* the
    owner's authorization; the owner is looked up via `channel_owner` to satisfy the owner-scoped `add_member`).
    **Public but proof-gated — not an open write (cf. #87):** no membership can be added without the owner's
    signature on an invitation, the invitee's possession proof, and the holder's Noise attestation. Merged into
    `persistent_control_plane_router`. Frozen test
    `channel_invite_redeem_admits_a_cross_user_member_from_the_proofs` (valid proofs admit + the member then
    resolves the operator key and its pinned Noise key; a holder-swapped redemption→403; an unregistered
    channel→404). Gate green. **This makes cross-user channel membership drivable end-to-end** and unblocks
    #100's brokered channel one-liner generator (an operator surface can now mint an invitation an invitee
    redeems into real membership).
  - **#108 SEC — invitation redemption is single-use** ✅ **(security-review fix; the replay/revocation
    bypass).** The invitation is a stateless signed object with a *static* redemption proof (no nonce), and
    `add_member` is `INSERT OR REPLACE`, so before this a **revoked** member could re-POST the identical
    `/channel/invite/redeem` to re-insert its `channel_members` row and restore membership until `expires_at` —
    defeating `remove_member`. Fix: `SqliteChannelStore::consume_invitation(signature, expires_at, now)` records
    a durable `consumed_invitations` row keyed by the invitation's 64-byte operator signature (unique per
    invitation; a replay carries the identical bytes) — `true` the first time an unexpired invitation is
    redeemed, `false` on any replay; expired rows pruned. The redeem endpoint consumes **after** the proofs
    verify (a bad proof burns nothing, mirroring `verify_fresh`) and **before** `add_member`; a replay is a
    `409`. So a revoked member replaying the same redemption is refused and `remove_member` stays effective. The
    `channel.rs` docs are corrected: an invitation object is stateless and single-use is the redeeming CP's
    responsibility (like `verify` vs `verify_fresh`). Frozen tests
    `consume_invitation_is_single_use_and_prunes_expired` (storage) and
    `channel_invite_redeem_single_use_survives_revocation` (the exact #108 scenario: redeem→409 replay→revoke→
    409 replay, membership never restored). Gate green.
- **AF4** ⏳ **Agent-side channel role + Noise session + relay fallback**. Split:
  - **AF4-join** ✅ **Agent-side channel-join client** (`ct-agent::channel::present_channel_join`): the client
    half of the broker handshake — sends the `u16`-framed `ChannelJoinRequest`, answers the edge's 32-byte
    possession challenge with a 64-byte ed25519 signature under the holder key, and parses the `OK[ <peer>]`/
    `NO` ack into a `ChannelJoinOutcome` (`Admitted { peer_endpoint }` / `Refused`). This is the production
    counterpart to the broker's inline test client, and it's the piece SEC81c-c will drive once the broker is
    mounted live. Two frozen round-trip tests against the **real** `ct_edge::channel_broker` (ct-agent already
    dev-deps ct-edge): a genuine holder is admitted while a wrong possession key is refused; and two clients
    paired via `broker_channel_rendezvous` each parse the peer's advertised endpoint. Gate green.
  - **AF4-keydist** ✅ **Registry carries each member's X25519 Noise static key** (scimbe decision 2026-07-18,
    `ct-control-plane::storage`): Noise_IK needs the peer's static X25519 key pinned, but the grant carried only
    ed25519 signing keys. `channel_members` gains a `noise_pubkey` column (additive `ensure_column` migration, #44);
    `add_member(channel, owner, holder, noise_pubkey)` pins it (re-add updates it); new `member_noise_key(channel,
    holder) -> Option<[u8;32]>` lookup (a peer fetches the other side's key; revoked/pre-migration member → None).
    The authed `POST /me/channels/:channel/members` now takes `{holder, noise_pubkey}`. Frozen tests:
    `channel_member_noise_key_round_trips_and_reflects_revocation` (set/update/revoke) + the HTTP round-trip in
    `authed_channel_registry_is_owner_scoped`. Gate green. This is the input AF4-session pins.
  - **AF4-session-core** ✅ **The A2A Noise session + data path exists and is proven end-to-end.**
    `ct_common::a2a` drives a pairwise **Noise_IK** session (generic over the stream): `a2a_initiate` (pins the
    peer's member Noise pubkey), `a2a_respond`, and framed `a2a_send`/`a2a_recv`. Three frozen tests:
    (1) `two_agents_establish_a_session_and_exchange_data_both_ways` (duplex, bidirectional payload);
    (2) `a_session_only_forms_with_the_intended_peer_key` (IK auth — an impostor peer key yields no session);
    (3) **`ct_agent::channel::two_agents_carry_data_over_a_channel_session`** — two agents over a **real QUIC
    connection** run the session and exchange application data both ways (the live tunnel-to-tunnel path). Gate
    green (full `cargo test --workspace -D warnings`).
  - **AF4-session-runner** ✅ **The runnable engine.** `ct_agent::channel_run::run_channel_session(conn, role,
    own_noise_priv, peer_noise_pub, local)` selects initiator/responder by `ChannelRole` (from the grant
    `Direction`), completes the A2A handshake over the QUIC connection, and then `noise_pump`s a **local byte
    stream over the encrypted tunnel** (a `BiStream` adapter presents the quinn bi-stream as one duplex). This
    is exactly what a CLI wires to stdin/stdout — "netcat over the channel". Frozen test
    `runner_pipes_local_data_over_the_a2a_tunnel`: two agents over a REAL QUIC connection, bytes written to the
    initiator's local side arrive at the responder's local side. Gate green (full `cargo test --workspace -D warnings`).
  - **AF4-session-cli** ✅ **`ct-agent channel` subcommand — the runner is now invocable.** `ChannelRunConfig`
    reads `CT_CHANNEL_*` (role, bind/peer addr, own+peer Noise keys, peer cert as hex) so it fits a one-liner;
    `run_channel_command` brings the agent up as responder (binds via `build_direct_listener_at`, prints its
    cert hex for the peer to trust) or initiator (`dial_quic` trusting the configured peer cert) and pipes
    **stdin/stdout** over the A2A tunnel via `run_channel_session`. `main.rs` dispatches `channel`. Frozen test
    `channel_config_parses_roles_keys_and_the_initiator_cert_requirement`. Gate green (added tokio `io-std`).
  - **#100 one-liner-gen** ✅ **`installer::channel_one_liner(ChannelOneLiner, os)`** renders the copy-paste
    command that brings a machine up as a channel `Responder`/`Initiator` and pipes stdio over the tunnel —
    the `CT_CHANNEL_*=… ct-agent channel` form (POSIX) + `$env:` PowerShell analog, targeting the shipped
    subcommand. Keys/cert ride in env, never argv (SEC90; inline-secret residual is #97). Frozen test
    `channel_one_liner_renders_the_ct_agent_channel_command`. Gate green.
  - **AF4-session-nocert** ✅ **Initiator dials accept-any — no transport cert conveyed.** `build_channel_dialer`
    (agent transport) uses an `AcceptAnyServerCert` rustls verifier (accepts any cert, still checks handshake
    signature consistency); `run_channel_command`'s initiator uses it when no cert is pinned, and
    `CT_CHANNEL_PEER_CERT` is now optional (the one-liner drops it). Safe because Noise_IK is the real mutual
    auth — a transport MITM can't complete the handshake without the peer's Noise private key. Frozen test
    `initiator_dials_without_a_pre_shared_cert_noise_authenticates` (responder self-signs a cert the initiator
    never sees; data flows). Gate green. **So the one-liner now needs only the peer's Noise key, not a cert.**
  - **AF4-session-keydeliver-cp** ✅ **The CP now serves the member's attested Noise key to the edge.** The
    `/internal/channel/authorize` response gained `noise_pubkey` (from the registry `member_noise_key`), and
    `ChannelAuthorizer::resolve` returns `MemberResolution { operator_pubkey, noise_pubkey }` (the existing
    `authorize` delegates to it, unchanged for the broker). So the edge can look up the peer's **attested**
    Noise key (not agent-advertised — addresses #101) during rendezvous. Frozen tests: CP
    `internal_channel_authorize_…` asserts the key is served; edge `resolve_carries_the_members_attested_noise_key`.
  - **#100 channel-scripts** ✅ **Served `/channel.sh` + `/channel.ps1`** (curl-pipe delivery, mirrors
    install.sh): `render_channel_sh`/`render_channel_ps1` detect OS/arch, download `ct-agent` from the release
    base, and `exec ct-agent channel` reading `CT_CHANNEL_*` from the env (keys never argv). Mounted in
    `installer_router`. So the operator can hand out one URL:
    `curl -fsSL <portal>/channel.sh | CT_CHANNEL_ROLE=… CT_CHANNEL_ADDR=… CT_CHANNEL_NOISE_KEY=… CT_CHANNEL_PEER_NOISE_KEY=… sh`.
    Frozen test `channel_scripts_are_served_and_exec_ct_agent_channel` (content + both routes 200).
  - **#100 channel-bootstrap** ✅ **Channel one-liner carries only `CT_BOOTSTRAP` — the member's Noise private
    key is no longer in argv.** Applies the bootstrap-token exchange (#90/#97 SEC90b) to the A2A one-liner,
    closing the "inline-secret residual (#97)" the one-liner-gen slice flagged. New
    `channel_bundle_secret(&ChannelOneLiner)` (flat shell-tractable `CT_CHANNEL_ROLE=…;CT_CHANNEL_ADDR=…;
    CT_CHANNEL_NOISE_KEY=…;CT_CHANNEL_PEER_NOISE_KEY=…[;CT_CHANNEL_PEER_CERT=…]`) is the bundle an operator mints
    a bootstrap token over; `channel_one_liner_bootstrap(portal, token, os)` renders
    `curl … /channel.sh | CT_BOOTSTRAP=<token> sh` (+ PowerShell). `render_channel_sh`/`render_channel_ps1`
    gained a `portal_base` param and a redeem branch (with `CT_BOOTSTRAP` set they `POST /bootstrap/redeem`,
    lift each `CT_CHANNEL_*` field with one `sed`/regex, and export them; else fall back to the env directly).
    `installer_router` already carries `portal_base` (SEC90b-installer-wire), so the channel routes serve the
    redeem-capable scripts. Frozen test `channel_bootstrap_one_liner_carries_no_noise_private_key` (bundle
    round-trips incl. the optional cert; the Noise private key never appears in either OS one-liner). Gate
    green. The manual inline form (`channel_one_liner`) stays for the direct/back-compat path.
  - **#100 brokered-oneliner** ✅ **The plane-path (broker-mediated) one-liner generator**
    (`installer::brokered_channel_one_liner` + `BrokeredChannelOneLiner`): renders the copy-paste command for
    the *brokered* A2A path (`CT_CHANNEL_ROLE`/`_BROKER`/`_RELAY`/`_GRANT`/`_HOLDER_KEY`/`_NOISE_KEY`/`_LISTEN`
    … `ct-agent channel`) — the plane path where members rendezvous through the edge broker + relay-fallback and
    the broker relays the peer's attested Noise key (no out-of-band peer key). Mirrors `channel_one_liner` for
    the brokered `ChannelJoinCliConfig` env; grant + both private keys ride in `CT_CHANNEL_*` env, never argv.
    Frozen test `brokered_channel_one_liner_renders_the_plane_path_command` (all vars present, role mapping,
    `ct-agent channel`, no secret in argv, both OSes). Gate green. *(Bootstrap-hardening the brokered form —
    generalizing `channel.sh`'s redeem to export any `CT_CHANNEL_*` field — is the follow, mirroring the direct
    form's `channel-bootstrap`.)*
  - **AF4-session-swap** ✅ **The broker relays the peer's attested Noise key in the rendezvous ack.** The
    `authorize` closure now returns `(operator, member_noise)`; `broker_channel_rendezvous` appends the peer's
    Noise key to each `OK <endpoint> <noise_hex>`; `present_channel_join` parses it into
    `Admitted { peer_endpoint, peer_noise_pubkey }`. The live edge closure sources it via
    `ChannelAuthorizer::resolve` (the CP-attested `member_noise_key`). So an agent learns **both** the peer
    endpoint AND the peer Noise key from rendezvous alone — no operator-conveyed key. Combined with the
    accept-any dialer (no cert), the A2A session can form fully hands-off. Frozen test
    `rendezvous_relays_each_peers_attested_noise_key` (each agent learns the peer's key). Gate green.
  - **AF4-session-join** ✅ **`run_channel_join` — the hands-off join orchestration.** Presents `request` to
    the broker over `broker_conn`, takes the peer endpoint AND Noise key from the rendezvous ack (no
    out-of-band value), then (by role) dials the peer accept-any / accepts on its listener and runs
    `run_channel_session`. Frozen test `channel_join_initiator_uses_the_rendezvous_peer_and_pipes_data`
    (initiator learns peer addr+key from the ack, dials, data flows; a stub broker supplies the loopback peer
    since the real `safe_endpoint` rejects loopback). Gate green.
  - **AF4-session-resilience** (scimbe steer: the *connection-difficulty* paths are what matter):
    - **AF4-resilience-classify** ✅ **Bounded, classified direct dial.** `dial_peer_direct(addr, timeout)`
      returns `ChannelDialError::Unreachable` (timeout — the **relay-fallback signal**) vs `Failed(..)`
      (malformed dial), instead of hanging on the QUIC handshake. `run_channel_join`'s initiator uses it with
      `DIRECT_DIAL_TIMEOUT` (5 s) and, on `Unreachable`, returns a clear actionable error (relay is the next
      packet). Frozen test `direct_dial_to_an_unreachable_peer_fails_fast_as_unreachable` **induces** the hard
      case (a bound-but-silent UDP port blackholes the handshake) and asserts fast `Unreachable`, not a hang.
    - **AF4-relay-splice** ✅ **Edge relay-forward for two channel members**, reusing the ADR-0015 relay core.
      `relay::relay_two_connections(conn_a, conn_b, label)` accepts one bi-stream from each connection and
      splices them via the existing (tested) `relay_quic` — ciphertext only, Noise stays E2E. Frozen test
      `relay_two_connections_splices_two_channel_members_and_tears_down_cleanly`: bytes cross both ways over
      real QUIC, AND when one member drops the relay returns (no hang) — the teardown behaviour a fallback
      needs. (Added tokio `time` to ct-edge for the timeout guard.) Gate green.
    - **AF4-relay-endpoint** ✅ **Edge relay-mode admission handler.** `broker_channel_relay(endpoint, now,
      authorize)` accepts + authorizes two joins for the same channel (reusing `accept_and_read_join` — the
      possession-proof/membership gate), acks `OK`, then splices each side's next bi-stream via
      `relay_two_connections`, so two members that can't go direct tunnel through the edge (ciphertext; Noise
      E2E). Frozen test `broker_channel_relay_splices_two_members_tunnels`: both members present valid joins,
      open data streams, and bytes cross both ways through the edge. Gate green.
    - **AF4-relay-clientwire** ✅ **Agent relay path + end-to-end proof.** `join_via_relay` presents the grant
      to the edge relay endpoint (possession proof) and runs the Noise_IK session over the spliced stream by
      reusing `run_channel_session` (the relay preserves the direct-path roles). Corrected the relay to be
      **role-aware** (`relay::relay_initiator_to_acceptor`: accept the initiator's opened stream, *open* one to
      the acceptor) — the symmetric accept-both version silently hung on the read-first Noise responder, which
      the raw-bytes test had hidden. **Capstone frozen test** `agents_tunnel_a_noise_session_over_the_edge_relay`:
      two agents fall back to the relay, run a REAL Noise session over it, and application data flows through
      the edge (ciphertext; Noise E2E). Gate green.
    - **AF4-relay-orchestrate** ✅ **Automatic direct-then-relay recovery.** `run_channel_join` now takes a
      `relay_conn` + `dial_timeout`/`accept_timeout`: the initiator dials direct and on `Unreachable`
      auto-invokes `join_via_relay`; the acceptor waits on its listener with a timeout and, if the direct
      connection never arrives, also falls back to the relay — so a blocked direct path recovers with no
      caller intervention. **Frozen test** `run_channel_join_auto_falls_back_to_the_relay_when_direct_is_blocked`
      *induces* the failure (the rendezvous hands a bound-but-silent blackhole endpoint; the 400 ms direct dial
      times out) and asserts the tunnel auto-recovers via the edge relay and carries data. Gate green.

  - **AF4-cli-brokered** ✅ **Plane-brokered `ct-agent channel` flow (#98/#103).** When `CT_CHANNEL_BROKER`
    is set, `main` dispatches to `run_channel_join_command`: `ChannelJoinCliConfig` parses the cross-host
    one-liner env (`CT_CHANNEL_BROKER`/`_RELAY`/`_GRANT`(hex)/`_HOLDER_KEY`/`_NOISE_KEY`/`_LISTEN`/`_ROLE`),
    dials the edge rendezvous + relay (accept-any; grant + possession are the auth), presents the grant, and
    pipes stdio over the tunnel with automatic direct-then-relay recovery — the broker relays the peer Noise
    key, so **no out-of-band `CT_CHANNEL_PEER_*`**. Otherwise the direct-address path (`CT_CHANNEL_ADDR`) is
    used. Frozen test `channel_join_cli_config_parses_the_plane_one_liner` (grant round-trips through decode;
    each required field enforced). Gate green. *(Live plane pairing (#103) is blocked on the operator
    deploying the broker on bunsenbrenner.org — `CT_EDGE_CHANNEL_LISTEN` + the channel port — not on code.)*

  **AF4-session-resilience is complete** (scimbe's connection-difficulty focus): fast **classified** dial
  (`Unreachable`) → role-aware edge relay-forward → relay-mode admission handler → agent relay path with a
  real Noise session over the relay → **automatic direct-then-relay recovery**, each with an induced-failure
  test. The remaining #72 work is non-resilience: AF3 operator-signed invitations, and closing out #100's
  self-contained one-liner polish.
    - Also: refused-join and unresolvable-peer error surfacing; retry/backoff.
  - **AF4-session-cli-join** ⏳ a thin `ct-agent channel-join` subcommand wiring env → `run_channel_join`.
  **#72 fix-ready when direct A2A data exchange + trust chains + tested fallback are all met.**
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
- **IS2** ✅ **Binary distribution via GitHub Releases** (scimbe decision 2026-07-18; `workflow` scope now
  granted): `.github/workflows/release.yml` — on a `v*` tag, builds `ct-agent` per OS/arch and uploads to the
  Release the six assets the IS3a/IS4 renderers download (`ct-agent-{linux,darwin}-{x86_64,aarch64}`,
  `ct-agent-windows-{x86_64,aarch64}.exe`). First-party actions + `gh` CLI only (no third-party actions);
  `fail-fast: false` so one target failing still ships the rest; linux-aarch64 via the gcc cross-linker.
  Gate: valid YAML, the six asset names match the renderer patterns, and a hermetic `cargo build -p ct-agent
  --release --locked` produces the `ct-agent` binary. Binaries populate when a release tag is cut (the tag
  itself is gated on the 0-open-issues release condition); the workflow itself is in place.
- **IS3a** ✅ **`/install.sh` script renderer** (`installer::render_install_sh`): pure function producing the
  POSIX installer — detects OS (uname) + arch (x86_64/aarch64 normalised), downloads `ct-agent-<os>-<arch>`
  from the release base, `set -eu` + temp-dir + `exec ct-agent onboard` (tokens from env, never argv).
  1 frozen test (shebang, detection, asset name, download URL, env-token requirement, onboard exec, no
  secret in argv). Gate green.
- **IS3b** ✅ **`/install.sh` + `/install.ps1` routes** — `installer::installer_router` serves both via axum
  GET handlers (`text/x-shellscript` / `text/plain`) with the release base from `CT_RELEASE_BASE` (default
  the GitHub-Releases latest-download base), merged into `persistent_control_plane_router`. The two URLs the
  portal one-liners fetch no longer 404. Frozen test `installer_routes_serve_the_scripts_that_were_404ing`:
  both routes return 200 and serve exactly `render_install_sh`/`render_install_ps1` for the release base.
- **IS4** ✅ **`/install.ps1` script renderer** (`installer::render_install_ps1`): the Windows analog of
  IS3a — detects arch (PROCESSOR_ARCHITECTURE → x86_64/aarch64), downloads `ct-agent-windows-<arch>.exe`
  from the release base, `$ErrorActionPreference=Stop`, temp dir, `& $exe onboard` (tokens from env, never
  argv). 1 frozen test. Gate green. (The route serving it is IS3b; binaries are IS2.)
- **IS5** ✅ **Real end-to-end test**: `served_install_sh_runs_end_to_end_with_tokens_from_the_env`
  fetches `/install.sh` through the real route and actually **runs** it — OS/arch detection, the download
  step, and `exec ct-agent onboard`. Hermetic: a fake `curl` on `PATH` intercepts the binary download and
  drops a stub `ct-agent` (no network / no published release needed), and the stub records its argv+env;
  the test asserts it was invoked as `onboard` with both tokens inherited from the **environment**, never
  argv. Unix-only (the served script is POSIX `sh`). Gate green.

**Status:** all install code + verification (IS1/IS2/IS3a/IS3b/IS4/IS5) landed and gate-green → **fix-ready**.
The only remaining step is *operational*: publishing a `v*` release so `releases/latest/download/…` serves
the real binaries (handled by the standing "cut `v0.1.0` at 0 open issues" release rule) — not a code gap.

## #76 Multi-agent tunnel overlay + topology study (epic) [+ Part B MA thesis, idle-time only]

Research epic (priority:high, Part A): stand up ≤8-agent overlay on the Agent Fabric (#72), bulk-transfer
workload, compare routing approaches (baseline / smart-routing / smart-shortcuts / random-mesh) × topology
× link condition on Mininet/Containernet, report throughput/tail-latency/stretch/failover. Part B (LOW,
idle-only): a HAW MA thesis (DoE, SIGCOMM-grade, ≥10p longer than the BA, security/metadata-obfuscation as
a factor), linked everywhere the BA is. Decomposed:

- **OV1** ✅ **Throughput measurement primitive** (`ct-client::bench`): `Throughput` {bytes, secs, mbps,
  mib_s} + `throughput(bytes, secs)` + `throughput_csv_row`/`THROUGHPUT_CSV_HEADER` — the pure,
  network-free bytes/sec metric the bulk-transfer mode emits (RTT is the wrong lens for overlay-under-load).
  3 frozen tests (mbps/MiB-s math, non-positive-duration None, CSV format + header/row column match). Gate green.
- **OV2** ⏳ **Bulk-transfer run mode**: client sends N bytes sustained over the tunnel (`CT_CLIENT_BULK_BYTES`),
  measures wall-clock, emits a `Throughput` row — the load workload (vs today's RTT-only bench).
- **OV3** ⏳ **Switchable routing-approach factor** (the cleanly-isolated factor for the DoE): an enum +
  config (`CT_OVERLAY_ROUTING` = baseline|smart-route|shortcut|random-mesh) threaded so a run pins exactly one.
- **OV4** ⏳ **N-agent (≤8) scale-out harness**: compose/script (like `redundancy-smoke.sh`, but N-agent +
  bulk transfer) bringing up an overlay on the Agent Fabric channels (#72).
- **OV5** ⏳ **Mininet/Containernet topology sweep**: emulator harness sweeping {routing × topology × netem
  link condition (#57)}, emitting comparable numbers (throughput, p95/p99 #52, stretch, failover #8, overhead #51).
- **OV6** ⏳ **Results write-up**: which routing/topology wins under which link regime + raw data.
- **Part B (OV7+, idle-only)** ⏳ HAW MA thesis on the above (DoE, security/metadata factor, ≥10p > BA),
  linked everywhere the BA thesis is. **#72/#76 fix-ready per their own acceptance; this stays in-progress.**

## #81 Agent Fabric security hardening (security-review of #72)

GLM-5.2 review found 4 trust gaps in the AF2d admission gate. Ordering per the review: close the trust
gaps BEFORE wiring the broker into the live edge binary. Decomposed:

- **SEC81a** ✅ **Membership/revocation check + endpoint SSRF guard** (gaps 2+3, `ct-edge::channel_broker`):
  the gate's `authorize(channel, holder)` now returns the operator key ONLY iff the holder is a current
  member (folds `is_member` in → removing a member denies admission at the gate, real revocation without
  key rotation/expiry-shortening). Advertised endpoints must pass `safe_endpoint` (parseable SocketAddr,
  reject loopback/unspecified/multicast) before a peer will dial them. 2 new frozen tests (non-member
  refused; loopback endpoint refused) + the 10 existing. Gate green.
- **SEC81b-a** ✅ **Possession-proof primitive** (`ct-common::channel::verify_holder_possession`): the pure
  check — `signature` must be the holder's ed25519 signature over the edge-issued `challenge`, verified
  against the grant's `holder` pubkey. Closes replay of an old proof against a fresh nonce. 1 frozen test
  (real holder verifies; wrong key / stale challenge / tampered sig rejected). Gate green.
- **SEC81b-b** ✅ **Wire the challenge-response into the QUIC gate** (`ct-edge::channel_broker`): after
  grant+membership+endpoint pass, `accept_and_read_join` fills a fresh 32-byte `OsRng` challenge, writes it,
  reads a 64-byte holder signature, and calls `verify_holder_possession` before acking — so a stolen grant
  (exfiltrated wire bytes) can no longer join, and an old proof can't be replayed against a new nonce. The
  request read moved to a `u16`-BE length prefix so the presenter's send stream stays open for the round-trip
  (a `read_to_end` would force an early finish). Frozen test `edge_requires_holder_possession_of_the_grant`:
  the genuine holder signs the challenge and is admitted; a thief who replays the identical grant but signs
  with another key is refused. Broker still NOT live (SEC81c) — this only hardens the gate it will mount.
  Gate green (13 broker tests).
- **SEC81c** ⏳ **Wire the broker into the live edge** (gap 4), ONLY after SEC81b (now unblocked). Broken
  into three bounded steps so no live serve-loop code lands before its inputs are proven:
  - **SEC81c-a** ✅ **Registry→broker `authorize` adapter** (`ct-control-plane::storage`): the broker's
    admission gate needs `authorize(channel, holder) -> Option<operator_pubkey>` returning the key **iff the
    holder is a current member**. Added `SqliteChannelStore::authorize_holder`, a single JOIN over
    `channels`⋈`channel_members` that folds the gap-2 membership/revocation check into the key source (a
    non-member, a never-added holder, or a removed member all resolve to `None` → refused at the gate, no
    key rotation). Atomic (no torn read between separate `is_member`/`operator_pubkey` calls). This is the
    exact production source for `accept_and_read_join`'s closure. Frozen test
    `channel_authorize_holder_yields_operator_key_only_for_members` (unknown channel / non-member / member /
    stranger / revoked / re-key). Gate green.
  - **SEC81c-b** ✅ **Channel-registry HTTP API** (`ct-control-plane::service`): `authed_channel_router`
    exposes owner-scoped `POST /me/channels` (register), `POST /me/channels/:channel/members` (add), and
    `POST /me/channels/:channel/members/:holder/remove` (revoke), backed by `SqliteChannelStore`. **OIDC-
    authenticated** — `owner` is the verified token subject, never a request field, and the router is mounted
    only when an OIDC verifier is configured (like `/me/*`). So it adds **no** unauthenticated DB-writing
    surface (sidesteps the #87 SEC87b auth question rather than being blocked by it). Frozen test
    `authed_channel_registry_is_owner_scoped`: unauth → 401; owner registers + adds a member (which then
    resolves via `authorize_holder`); a non-owner can neither add members nor re-key (403, key unchanged);
    owner revokes → the authorize lookup denies. Gate green.
  - **#94 SSRF hardening** ✅ **`safe_endpoint` rejects private/internal ranges** (prerequisite to mounting the
    broker on a public edge): the guard rejected only loopback/unspecified/multicast and *allowed* RFC1918 /
    link-local / CGNAT / IPv6 unique-local — so a holder could make the peer dial the operator's LAN or the
    cloud metadata IP (`169.254.169.254`). Now only globally-routable unicast passes (v4: `is_private` +
    `is_link_local` + `100.64/10`; v6: `fc00::/7` + `fe80::/10`). Frozen test
    `safe_endpoint_rejects_private_and_internal_ranges`; broker/agent tests moved to `203.0.113.x`. Gate green.
  - **SEC81c-c** ⏳ **Mount the broker in the live edge** — the roadmap "many things wait for" (scimbe):
    - **c-i** ✅ **CP edge-facing authorize endpoint** (`ct-control-plane::service`): `POST /internal/channel/authorize`
      `{channel, holder}` + header `x-ct-admin-token` → `200 {operator_pubkey}` iff the holder is a current member,
      `401` bad/missing token (constant-time compare of the shared edge↔CP admin token, `CT_CP_EDGE_ADMIN_TOKEN`),
      `404` non-member. This is the exact `authorize(channel, holder) -> Option<operator_pubkey>` the live broker
      needs, sourced from `authorize_holder` (membership+revocation folded in). Mounted only when the admin token is
      set. Frozen test `internal_channel_authorize_requires_admin_token_and_membership`. Gate green.
    - **c-ii** ✅ **Edge-side authorize resolver** (`ct-edge::channel_authorize::ChannelAuthorizer`): queries c-i
      (`reqwest` POST + the shared admin token) and maps the response to `Option<[u8;32]>` — **fail-closed** (any
      non-member/401/transport error → `None`, so an unresolvable authorization denies admission). Frozen test
      `resolver_returns_operator_key_only_for_a_member_with_the_admin_token` against a mock CP (member → key; non-
      member, bad token, unreachable CP → None). Gate green. c-iii wraps this as the broker's `authorize` closure.
    - **c-iii-1** ✅ **Broker `authorize` closure made async** (`ct-edge::channel_broker`): the three broker fns
      (`accept_and_read_join`/`resolve_channel_join`/`broker_channel_rendezvous`) now take
      `F: Fn(ChannelId, [u8;32]) -> Fut, Fut: Future<Output=Option<[u8;32]>>` and `.await` it — required so the
      async c-ii resolver can be the `authorize` source (a sync closure couldn't do the HTTP round-trip). All 14
      broker + 2 agent channel tests updated to `|c,_h| async move { … }` closures; gate green.
    - **c-iii-2** ✅ **Connection-level join read** (`ct-edge::channel_broker::read_join_on_connection`): extracted
      the per-connection admission gate (accept_bi + framed read + membership/endpoint/grant/possession checks)
      from the endpoint-owning `accept_and_read_join`, which now delegates to it. So the live edge can dispatch a
      channel-join `quinn::Connection` (from its accept loop, via a new role byte) straight into the gate rather
      than needing a dedicated endpoint. Frozen test `read_join_on_connection_admits_a_valid_join` (accept the
      connection, then read → admit). Gate green (15 broker tests).
    - **c-iii-3a** ✅ **Full authorize-path composition proven** (`ct-edge::channel_broker` test): the c-ii
      `ChannelAuthorizer` plugged in as the broker's async `authorize` closure, sourcing membership from a mock
      control plane, admits a member end-to-end (agent join → gate → resolver → CP → operator key → grant verify
      → possession → OK). Frozen test `channel_authorizer_as_the_gate_closure_admits_a_member`. Gate green — the
      live wiring is validated before the run_edge glue.
    - **c-iii-3b** ✅ **Broker mounted in the live edge** (`run_edge`): when `CT_EDGE_CHANNEL_LISTEN` +
      `CT_EDGE_CP_URL` + `CT_EDGE_ADMIN_TOKEN` are all set, `run_edge` binds a dedicated channel-rendezvous QUIC
      endpoint (a fresh leaf under the same CA, so agents already trust it) and spawns a loop running
      `broker_channel_rendezvous` with the `ChannelAuthorizer` closure — membership resolved via the control
      plane (c-i/c-ii, fail-closed). Opt-in; absent config → no channel endpoint. Gate: build `-D warnings` + all
      95 ct-edge tests (the mount is integration glue over the unit-tested broker/resolver/composition). **The
      broker is now live.** Remaining for a *usable A2A tunnel*: #72 AF4-session (agents dial the peer endpoint +
      run Noise_IK using `member_noise_key` + relay fallback); a live edge+CP+2-agent smoke is the final
      end-to-end confirmation.
    Then #72 AF4-session (dial peer + Noise_IK using the peer's `member_noise_key` + relay fallback) makes it a
    usable end-to-end tunnel.

## #78 CI gate / build-isolation security review (security-review)

GLM-5.2 review: no independent CI between push and main; role skills pull+run main each tick; the
"hermetic" build runs as host uid against a bind-mounted repo + host cache; cargo-audit cached-reused
unverified. Mostly architectural (needs scimbe decisions); one clean fix landed.

- **SEC78a** ✅ **Un-hardcode the cargo-cache path** (evidence #3): the 3 tracked role skills
  (agent/central/developer SKILL.md) hardcoded `/home/becke/.cache/ct-cargo` in the hermetic-gate command
  — a cross-user-write / non-portable footgun on any host without user `becke`. Parameterized to
  `$HOME/.cache/ct-cargo` (matching `security-audit.sh`). Gate: `git grep '/home/becke/.cache/ct-cargo'`
  in tracked files == 0.
- **SEC78b** ✅ **Independent server-side CI** (scimbe decision 2026-07-18; `workflow` scope now granted):
  `.github/workflows/ci.yml` is tracked and gates `main` (and pull requests) independently of the autonomous
  agent — a read-only gate mirroring the loop's hermetic gate: workspace build + test under `-D warnings`,
  the committed-secret guard (`check-no-secrets`), and `cargo audit`. This also unblocked #75 IS2 (release workflow).
- **SEC78c** ⏳ **NEEDS DECISION** — build isolation: drop the host-cache bind-mount / run as a non-host
  uid so a dep `build.rs` can't write the repo or poison the shared cache; pin+verify `cargo-audit`
  instead of cached-reuse (evidence #4). Relates to #77 (skill trust model).

## #82 OIDC hardening (security-review)

GLM-5.2 review: 3 OIDC weaknesses. Decomposed:

- **SEC82a** ✅ **id_token now cryptographically verified** (issue #1, the auth-bypass) + **kid-bound JWKS
  key selection** (issue #3) + **id_token audience validated** (issue #2, for the id_token specifically):
  `portal.rs` replaced the insecure `insecure_disable_signature_validation()` decode with
  `identity_from_verified_id_token` — the exchanger fetches the realm JWKS and verifies the id_token's RS256
  signature (key chosen by the token's `kid`, `oidc::jwks_signing_key_for_kid`/`token_kid`), issuer,
  audience (an id_token's aud IS the client) and expiry before trusting sub/email. So a tampered/confused
  token-endpoint response can no longer inject an arbitrary subject/email. Frozen tests: hermetic runtime-RSA
  id_token verified (valid → sub+email; forged-key/wrong-issuer/wrong-audience rejected; sub required) +
  kid selection among multiple JWKS keys. Gate green.
- **SEC82b** ✅ **Bearer-token audience (issue #2 for /me/*)** — **opt-in enforcement landed.**
  `OidcVerifier::require_audience(aud)` sets `validate_aud=true`, pins the expected audience, and marks
  `aud` a required spec claim (so an *absent* `aud` is also rejected, not just a mismatched one). Wired in
  `main.rs`: when `CT_OIDC_ACCESS_AUD` is set the `/me/*` verifier enforces it; unset preserves the prior
  no-aud-check behavior (no blind flip — Keycloak access-token audiences vary by client, so the operator
  supplies their realm's field-checked value). Frozen test `required_audience_gates_bearer_tokens`:
  matching aud accepted; mismatched + missing aud rejected under enforcement; both accepted by default.

## #80 cargo-audit exit 1 vs doc "0 vulnerabilities" (security-review)

`cargo audit` exits 1 on RUSTSEC-2023-0071 (rsa Marvin, dev-only) + warns on rustls-pemfile unmaintained
(runtime edge); the doc claimed exit 0. Decomposed:

- **SEC80a** ✅ **Restore the green audit gate + align the doc**: `rsa` is a DEV-dependency only (test RSA
  key-gen / RS256 signing), not in any shipped binary and the timing side-channel is not reachable via
  key generation with no fix available → accepted+ignored in `.cargo/audit.toml` (RUSTSEC-2023-0071) with a
  documented rationale. `docs/security/dependency-audit.md` updated to the real state (0 vulns with the
  documented ignore, 1 unmaintained warning, exit 0). Verified live: `scripts/security-audit.sh` now exits
  0 (only the non-failing rustls-pemfile warning remains).
- **SEC80b** ✅ **Replaced the runtime unmaintained `rustls-pemfile`** (RUSTSEC-2025-0134) with the
  maintained `rustls-pki-types` PemObject decoders in `ct-edge::transport::build_portal_acceptor`.
  `rustls-pemfile` is gone from Cargo.lock (218 deps, was 219). Frozen test
  `build_portal_acceptor_parses_pem_via_pki_types` (real self-signed PEM cert+key parse; junk rejected).
  cargo audit now fully clean: exit 0, 0 vulns (rsa ignored), 0 warnings. **#80 fix-ready.**

## #86 Edge DoS defense — ADR-0018 half-deployed (security-review)

Two availability gaps: no connection cap on the accept loops, and the per-token RateLimiter unwired.
Decomposed:

- **SEC86a** ✅ **Wire the per-token rendezvous rate limit** (ADR-0018's second half): `EdgeState` gains an
  opt-in `rendezvous_limiter` (`set_rendezvous_limit` / `rendezvous_allowed(token, window)`), enabled by
  `CT_EDGE_RENDEZVOUS_MAX_PER_MIN` (off by default). Both `'C'` rendezvous handlers (QUIC + TCP-fallback)
  now reject a token over its per-minute budget AFTER PoW — PoW raises per-attempt cost, this caps
  per-token volume a solver farm could still push. Frozen test on the state method (off by default; caps
  N per window; per-token independent; new window resets). Gate green.
- **SEC86b** ✅ **Connection cap on the primary QUIC accept loop**: added `state::ConnectionCap` — a
  `tokio::sync::Semaphore` handing out an owned permit per admitted connection (held for the connection's
  lifetime), with load-shedding (`try_admit → None` ⇒ quinn `Incoming::ignore`) rather than unbounded
  queueing. Opt-in via `CT_EDGE_MAX_CONNECTIONS` (>0); off otherwise. Wired into `run_edge`'s QUIC accept
  loop so a flood can't exhaust memory/FDs before the PoW gate runs. Frozen test
  `connection_cap_admits_up_to_max_then_sheds_until_a_permit_frees` (admit N, shed N+1, releasing a permit
  frees exactly one slot). Gate green (ct-edge lib, 90 tests).
- **SEC86c** ✅ **Extend the cap to the TCP fallback rendezvous loop**: the `tcp_listener` accept loop (the
  TCP analog of the QUIC path, for clients whose UDP is blocked) now shares the **same** `ConnectionCap` — a
  clone, so the `CT_EDGE_MAX_CONNECTIONS` budget is global across QUIC+TCP, not per-loop. Over the cap it
  sheds by dropping the socket. Frozen test `connection_cap_clones_share_one_global_budget` (a permit taken
  through one handle is unavailable through a clone; releasing frees it for both). Gate green (ct-edge lib,
  91 tests). With SEC86a+b+c the two reviewer-flagged gaps (rate limiter unwired, no connection limit) are
  fully closed on both rendezvous surfaces.
- **SEC86d** ✅ **Doc reconciliation + closeout**: updated `docs/security/threat-model.md` so the rendezvous-
  flood row states the truth — PoW is always on, while the per-token rate limit and connection cap are wired
  but **opt-in** (`CT_EDGE_RENDEZVOUS_MAX_PER_MIN` / `CT_EDGE_MAX_CONNECTIONS`), no longer implying an
  always-on limit. The reviewer's two core gaps (rate limiter unwired, no connection limit) are now closed on
  both rendezvous surfaces (SEC86a/b/c), so #86 is marked fix-ready. Deliberately **not** capping the
  HTTP→HTTPS redirect listener: it would share the one rendezvous budget, so a plaintext-redirect flood could
  starve real rendezvous — a negligible-value surface not worth that risk. An optional PoW gate on `'A'`
  registration is a separate hardening enhancement, outside this finding.

## #87 Control-plane endpoints: unauth / un-rate-limited / client-priced (security-review)

Several `service.rs` endpoints require no auth + no rate limit and write durable SQLite, and issuance
took a **client-supplied `price`** so `price:0` minted a routing token for free. Decomposed:

- **SEC87a** ✅ **Reject issuance below the token price** (the free-token mint): `billing::issuance_price_ok`
  (`price >= TOKEN_PRICE`) is now enforced in both live issuance handlers — `buy_token` (`/billing/issue`)
  and `me_issue` (`/me/issue`) — *before* the ledger is touched, returning `402` for an underpayment. So a
  funded, in-rate subject can no longer buy a token for less than it costs, and `price:0` mints/debits
  nothing. The rate-limit test that abused `price:0` to isolate the limiter now funds the subject and pays
  the token price. Frozen test `issuance_rejects_price_below_the_token_price` (price:0 → 402, balance
  unchanged; price:TOKEN_PRICE → 200, debited). Gate green. (The parallel `http.rs`/`issue_token_for_payment`
  surface is **not** wired into `main` — no live vuln — but must adopt the same floor if ever mounted.)
- **SEC87b-rl** ✅ **Per-IP flood cap on the unauthenticated DB-writers** (`/enroll/issue`, `/accounts/open`,
  `/registry/register`, `/payment/intent`) — the *disk-DoS* half, landable without the auth decision.
  `with_unauth_write_limit` wraps the app in a `from_fn` layer that meters exactly those `POST` paths per
  client IP (from `ConnectInfo`, reusing `KeyedRateLimiter`, fixed 60 s window) → `429` past the cap; reads,
  authed `/me/*`, and health pass through, and a missing peer IP fails **open**. Off by default (no behavior
  change — a default-on policy is the maintainer's call); enable with `CT_CP_UNAUTH_WRITE_PER_MIN=<n>`.
  `main.rs` now serves with `into_make_service_with_connect_info`. Frozen test
  `unauthenticated_writers_are_rate_limited_per_ip` (3rd metered POST from one IP → 429; other IP
  independent; non-listed path + reads unmetered). Gate green.
- **SEC87b-auth** ⏳ **Authentication on those writers** (decision: scimbe → gate the writers, 2026-07-18).
  Landing it per-writer, one bounded slice at a time:
  - **SEC87b-auth-issue** ✅ **`/enroll/issue` gated behind the shared admin token.** The join-token
    *issuance* route is a machine/operator surface — the real portal flow mints in-process
    (`portal_api.rs::issue_join_token`), not over HTTP — so it's gated with the same `CT_CP_EDGE_ADMIN_TOKEN`
    the edge/operator already hold rather than an OIDC user bearer. New `EnrollState { store, issue_admin_token }`
    + `enrollment_router_sqlite_with_admin(store, Option<[u8;32]>)`; the `issue` handler requires
    `x-ct-admin-token` (constant-time compare) when a token is configured, `401` otherwise; with none
    configured issuance stays open (dev/back-compat). `persistent_control_plane_router` wires the env token, so
    a live deployment is gated automatically. `/enroll/redeem` is unchanged (already agent-authed by its
    single-use token + PoP proof, #88). Frozen test `enroll_issue_requires_the_admin_token_when_configured`
    (401 no/wrong token, 200 correct, open when unset). Gate green.
  - **SEC87b-auth-billing** ✅ **The billing writers (`/accounts/open`, `/payment/intent`, `/billing/issue`)
    gated behind the shared admin token.** These three take a **client-supplied** account (or mint an
    anonymous one), so left open they are an unauthenticated durable-SQLite writer surface (#87). The **real
    customer top-up path is not here**: it is the session-authenticated portal (`POST /portal/account/credits`,
    which derives the account from the verified subject and calls the ledger in-process). Traced: no live caller
    hits these HTTP routes — only `ControlPlaneClient` (tests); `cp_selftest`/agent don't. So — exactly like
    `/enroll/issue` — they're a machine/operator surface, gated with the same `CT_CP_EDGE_ADMIN_TOKEN`.
    New `billing_writers_gated(ledger, Option<[u8;32]>)` + a `require_billing_admin` layer (constant-time
    `x-ct-admin-token` compare) applied only when a token is configured; open when unset (dev/back-compat).
    `/payment/webhook` (provider-signature-authed) and the `/me/*` + portal customer paths are untouched.
    `persistent_control_plane_router` shares one `admin_token` for both the enrollment and billing gates.
    Frozen test `billing_writers_require_the_admin_token_when_configured` (401 without/wrong on
    `/accounts/open` + `/payment/intent`, 200 with correct token, open when unset). Gate green.
  - **SEC87b-auth-registry** ✅ **`/registry/register` gated behind the shared admin token; `ControlPlaneClient`
    + `cp_selftest` made admin-aware.** `/registry/register` maps a client-supplied routing token →
    `(tenant, agent)` in the durable registry — an unauthenticated durable-writer surface (#87). No live
    customer path uses it: the agent registers its tunnel over the **QUIC data path to the edge**
    (`register_tunnel_stream`), not this HTTP route; the only HTTP caller is the operator selftest
    (`cp_selftest`). So gated with the same `CT_CP_EDGE_ADMIN_TOKEN` via the reusable `AdminGate` /
    `require_admin_token` layer (factored out of the billing gate); the **read** `/registry/resolve` stays
    open. New `registry_router_sqlite_gated(store, Option<[u8;32]>)`. To keep the operator selftest working
    against a gated CP, `ControlPlaneClient` gained `with_admin_token(hex)` (sends `x-ct-admin-token` on the
    five gated writers — issue / register / accounts-open / payment-intent / billing-issue) and `cp_selftest`
    reads `CT_CP_EDGE_ADMIN_TOKEN` and presents it. Frozen test
    `registry_register_requires_the_admin_token_but_resolve_stays_open` (401 without/wrong, 200 with,
    resolve open, open when unset). Gate green.
  - **Net for SEC87b-auth:** every unauthenticated durable-writer the review flagged
    (`/enroll/issue`, `/accounts/open`, `/payment/intent`, `/billing/issue`, `/registry/register`) is now gated
    behind the shared admin token in production (open in dev when unset), the operator client/selftest presents
    the token, and reads/customer paths are untouched. Combined with SEC87a (price floor) and SEC87b-rl (per-IP
    cap), #87's surface is closed. Note the *mechanism* is the shared admin token rather than an OIDC user
    bearer, because these are machine/operator routes — the customer flows are the session-authed portal and
    the OIDC `/me/*` router, neither of which touches these; a maintainer can still layer OIDC if a future
    customer-facing use of these routes appears.

## #88 Replay cache + enrollment proof-of-possession (security-review, medium)

Three trust-primitive gaps: (1) `SignedCredential` and (2) `ChannelGrant` are signature+expiry only, so a
captured token is replayable until expiry; (3) enrollment `redeem` binds a join token to an agent pubkey
with **no** proof-of-possession, so an intercepted token can bind an attacker's key. Decomposed:

- **SEC88a** ✅ **Replay-cache primitive** (`ct_common::replay::ReplayCache`) — the named missing mechanism.
  `check_and_record(id, expires_at, now) -> bool`: fresh the first time an unexpired `id` is seen, `false` on
  a replay; already-expired ids are never fresh/stored; expired entries are evicted on access so the map only
  holds currently-valid ids. Caller-supplied time (deterministic, mirrors `ratelimit`). The `id` is opaque —
  a token's 64-byte signature works (a replay carries the identical signature) as does an explicit nonce, so
  it wires into both credential and grant paths without a format change. 4 frozen tests. Gate green.
- **SEC88b-api** ✅ **Replay-checking verify** — `credential::verify_fresh` and `channel::verify_fresh` wrap
  the existing `verify` (signature+expiry) and then consult a caller-owned `ReplayCache` keyed on the token's
  64-byte signature: first presentation of a valid, unexpired token is admitted; any later presentation of
  the same signature fails with `CredError::Replayed` / `GrantError::Replayed`. Signature/expiry are checked
  first, so an invalid/expired token never populates the cache. No wire/format change. 2 frozen tests
  (admit-once-then-replay; distinct token still fresh; bad-key/expired rejected before the cache). Gate green.
- **SEC88b-wire** ✅→**N/A (redundant on the live paths)**: on review the two live-ish `verify` sites are
  already replay-safe or not live. The channel broker (`channel_broker.rs::read_join_on_connection`) gates
  every join on a **fresh single-use possession challenge** — a captured grant's old signature can't answer a
  new challenge, so a `ReplayCache` there is dead weight. The credential path (`edge/src/auth.rs`) is **not
  mounted in the live edge** (`serve.rs` never verifies a `SignedCredential`). `verify_fresh` remains the
  correct API to use if/when a `SignedCredential` is verified on a live long-lived path.
- **SEC88c-core** ✅ **Enrollment proof-of-possession — verification on the live durable store.**
  `enrollment::verify_join_proof(token, pubkey, proof)` checks `proof` is `pubkey`'s ed25519 signature over
  the join token; `SqliteEnrollment::redeem_with_proof` verifies it **before** consuming the token (a bad
  proof burns nothing → new `EnrollError::BadProof`, mapped to `403` in the redeem handler). This ensures a
  redemption can only bind a key the caller proves it controls. Frozen test
  `redeem_with_proof_requires_possession_of_the_bound_key` (wrong-key proof → BadProof + nothing bound;
  genuine proof binds + single-use). Gate green. *Scope note:* PoP binds the redemption to a proven key
  holder; it does not by itself stop an on-path attacker who captured the token (bearer secret; TLS-protected).
- **SEC88c-wire** ✅ **Proof required end-to-end**: `RedeemReq` gained a `proof` field; the durable
  `/enroll/redeem` handler now calls `redeem_with_proof` (malformed proof → `400`, bad proof → `403`);
  `ControlPlaneClient::redeem` takes a `proof: &[u8; 64]` and sends it; the agent `onboard` signs the join
  token with its identity key (`identity.sign(join_token)`); `cp_selftest` signs too. Existing durable-path
  redeem tests reworked to present a real keypair + signature. Gate green (workspace `-D warnings`; ct-agent
  85 + ct-control-plane 149 tests). *(The in-memory `http.rs`/`Enrollment` dev router is unchanged — it
  ignores the extra field; the live/durable path is the one that enforces PoP.)*
- **SEC88d** ✅→**accepted residual (no in-`ct-common` fix)**: `verify`/`verify_fresh` trust a caller-supplied
  `now`, so a backwards-skewed edge clock extends validity. The verifying host owns its clock, so this is an
  operational control (NTP + monotonic-time discipline), recorded in `docs/security/threat-model.md` §Residual
  risks #4. Replay is bounded independently (broker possession-challenge #81; `verify_fresh` primitive; #88
  SEC88c PoP). (ChannelGrant *revocation* is already covered via #81's membership check.)

**#88 complete:** all three reviewer gaps addressed (SEC88a/b-api/c-core/c-wire ✅; SEC88b-wire N/A) and the
secondary clock-skew note accepted as an operational residual → fix-ready.

## #89 Keycloak demo realm: unverified-email + open registration + social trustEmail (security-review, low)

`ct-demo-realm.json` had `verifyEmail=false` + `registrationAllowed=true` +
`registrationEmailAsUsername=true` and `trustEmail=true` on google/github/gitlab. Impact is bounded — billing
identity is the Keycloak `sub`, not email (#82/#92 sub mapper), and free issuance is closed (#87 SEC87a) — so
priority:low. Decomposed:

- **SEC89a** ❌ **REVERTED — conflicts with #43's email gate (was a bad unilateral call).** I set
  `trustEmail=false` on github/gitlab, but that broke the tested contract `demo_realm_matches_the_portal_oidc_contract`
  (`portal.rs:771`) which asserts `trustEmail=true` for all three social IDPs **"so #43's email gate works"** —
  and red-lit CI on `main`. The demo realm *deliberately* trusts social emails so the #43
  `CT_PORTAL_ALLOWED_EMAIL_DOMAINS` access-list + smooth social login work. Reverted to `trustEmail=true`
  (matching the contract). **Process lesson:** the realm JSON *is* covered by a Rust test — never skip the
  full `cargo test --workspace` gate for a "config-only" change again. So social-email trust is **not** a safe
  unilateral tightening; it folds into SEC89b.
- **SEC89b** ⏳ **Realm email-trust + registration/verification policy (maintainer call)**: reconcile the
  reviewer's unverified-email concern with **#43's email-domain gate** (which the current `trustEmail=true`
  serves) and with the fact that `verifyEmail=true` needs SMTP on the KC deployment (flipping blind breaks
  registration + reset on `bunsenbrenner.org`) and `registrationAllowed=false` (invite-only) is a
  signup-model decision. Mitigating context: billing identity is the Keycloak `sub`, not email (#82/#92), and
  free issuance is closed (#87 SEC87a), so the residual is low.

## #90 Secret-handling: token in install one-liner + routing token in revoke logs (security-review, low)

Two secret-exposure observations. Decomposed:

- **SEC90a** ✅ **Redact the routing token in edge-revoke failure logs** (`portal_api.rs`): on a failed
  `POST {edge}/admin/revoke/{routing_token}`, the handler logged the raw `reqwest` error, whose `Display`
  embeds the request URL — leaking the routing token (a server-side secret never rendered in listings) into
  control-plane logs. Added `redact_routing_tokens`, a pure helper that replaces any maximal run of ≥64
  lowercase-hex chars (the token shape) with `<redacted-token>`, applied to the error before logging — so the
  secret is stripped wherever in the error chain the URL surfaces. Frozen test
  `redact_routing_tokens_strips_the_token_from_a_revoke_error` (token gone + marker present + non-secret
  context and short hex preserved). Gate green.
- **SEC90b** ⏳ **Install one-liner embeds tokens in the command string** (`installer.rs::install_one_liner`):
  the join/routing tokens appear in the shown one-liner (`CT_JOIN_TOKEN=<hex> … sh`), so they land in shell
  history and `ps`. Fix (maintainer decision, scimbe 2026-07-18): a **bootstrap-token exchange** — the
  one-liner carries only a short-lived, single-use opaque token the agent exchanges **server-side over TLS**
  for the real secrets, so the real secret never touches the command line. Shared with #97. Landing bottom-up:
  - **SEC90b-core** ✅ **Bootstrap-token store primitive** (`storage::SqliteBootstrap` + `BootstrapError`):
    durable `mint(secret, ttl_secs, now) -> [u8;32]` / `redeem(token, now) -> String` / `prune(now)`. Redeem
    hands off the opaque secret **exactly once** within a short TTL: single-use is persisted (survives
    restart), an expired token is **consumed** so it can't be retried (`Expired`), a second redemption is
    `AlreadyUsed`, an unknown token is `UnknownToken`. Caller-supplied `now` (deterministic, mirrors
    `ReplayCache`/rate limiters); the `secret` payload is opaque to the store (shape decided by the wire
    packet). This is the core that makes a leaked one-liner useless once redeemed/expired. Frozen test
    `bootstrap_token_redeems_once_within_ttl_then_is_dead`. Gate green (full `cargo test --workspace -D warnings`).
  - **SEC90b-wire** ✅ **Bootstrap-token exchange routes** (`service::bootstrap_router`, backed by
    `SqliteBootstrap` opened on the shared `db_path`): `POST /bootstrap/mint {secret, ttl_secs?}` → `{token}`,
    **admin-gated** (minting hands off a secret bundle — same `AdminGate` / `CT_CP_EDGE_ADMIN_TOKEN` as the
    other operator writers; open in dev when unset); `POST /bootstrap/redeem {token}` → `{secret}`, **public**
    (possession of the short-lived single-use token is the auth, handed off in the TLS response body, never on
    the command line): `404` unknown, `409` already used, `410` expired. Default mint TTL 600 s; handlers use
    wall-clock `now_secs()` over the deterministic store core. Merged into `persistent_control_plane_router`.
    Frozen test `bootstrap_mint_is_admin_gated_and_redeem_hands_off_once` (mint 401 without admin / 200 with;
    redeem hands off the exact secret once, 409 on reuse, 404 unknown; open when unset). Gate green.
  - **SEC90b-installer-render** ✅ **Bootstrap one-liner renderer + install-bundle codec** (`installer.rs`,
    pure): `install_one_liner_bootstrap(portal_base, bootstrap_token, os)` renders the copy-paste command
    carrying **only** `CT_BOOTSTRAP=<token>` (Unix `curl … | CT_BOOTSTRAP=… sh`; Windows `$env:CT_BOOTSTRAP=…;
    irm … | iex`) — the real join/routing tokens never appear in it. `install_bundle_secret(join, routing)` /
    `parse_install_bundle` are the JSON `{join_token, routing_token}` bundle the portal mints a bootstrap token
    over (`SqliteBootstrap::mint`) and the agent recovers after `POST /bootstrap/redeem`. Frozen test
    `bootstrap_one_liner_carries_only_the_bootstrap_token_not_the_real_secrets` (bundle round-trips + rejects
    malformed; neither real token appears in either OS one-liner; bootstrap token carried exactly once). Gate
    green. The embedded-token `install_one_liner` stays for the manual/back-compat path.
  - **SEC90b-installer-wire** ✅ **The served `/install.sh` + `/install.ps1` redeem `CT_BOOTSTRAP` server-side.**
    `render_install_sh`/`render_install_ps1` gained a `portal_base` param and a redeem branch: when
    `CT_BOOTSTRAP` is set they `POST {portal}/bootstrap/redeem`, lift the two tokens out of the returned bundle
    (a single `sed`/regex each — no nested-JSON parse, no `eval` of server data, enabled by switching
    `install_bundle_secret` to the flat `CT_JOIN_TOKEN=…;CT_AGENT_TOKEN=…` form) and `export` them; otherwise
    they fall back to tokens already in the env (manual/back-compat path). `installer_router` now takes
    `portal_base` (wired from `CT_PORTAL_BASE_URL`) via a small `InstallerState`. Frozen tests: content
    (`install_sh`/`install_ps1` assert the redeem branch + portal URL) and a Unix end-to-end
    `served_install_sh_redeems_a_bootstrap_token_for_the_real_tokens` (only `CT_BOOTSTRAP` set → a fake curl
    serves the redeem JSON → the stub agent onboards with the two real tokens, proving the extraction works in
    a real POSIX `sh`); the pre-existing embedded-token end-to-end test still passes (back-compat). Gate green.
  - **SEC90b-installer-portal** ✅ **The portal install page now shows the bootstrap one-liner.** `SqliteBootstrap`
    is threaded into `ApiState`/`portal_api_router`; `install_page` mints a short-lived (600 s) single-use
    bootstrap token over `install_bundle_secret(join, routing)` and renders `install_one_liner_bootstrap(...)`,
    so the **copy-paste command carries only `CT_BOOTSTRAP=<token>`** — no real secret in shell history / `ps`.
    The raw tokens are still shown once, separately, for the manual-onboarding block (an authenticated,
    shown-once display, not a shell exposure). Frozen test
    `install_page_shows_a_bootstrap_one_liner_carrying_no_real_token` (one-liner carries `CT_BOOTSTRAP`, the
    routing token never appears inside the shown command; the manual block is retained). Gate green.

  **Net for #90/#97 (SEC90b):** the bootstrap-token exchange is complete end-to-end — durable store (core) →
  admin-gated mint + public redeem routes (wire) → bootstrap one-liner + shell-tractable bundle codec (render)
  → served scripts redeem `CT_BOOTSTRAP` (installer-wire) → the portal shows the bootstrap one-liner
  (installer-portal). Combined with **SEC90a** (routing-token redaction in edge-revoke logs), both
  secret-exposure observations in #90 — and the #97 follow-up (one-liner still embeds tokens) — are resolved:
  no real join/routing token is ever on the command line or in logs. #90 and #97 → fix-ready.

## #95 Rendezvous rate-limit + connection cap are opt-in / off by default (security-review)

Follow-up to #86: both edge flood controls (per-token rendezvous rate limit, concurrent-connection cap) were
gated on an env var and did nothing when unset (the default), so a public edge shipped flood-exposed.

- **SEC95a** ✅ **Both controls on by default, tunable + disable-able**: `resolve_flood_limit(raw, default)` —
  unset → the safe `default` (ON); a positive value overrides; explicit `0`/`off`/`false`/`none` disables; an
  unparseable value fails safe to the default (a typo never opens the flood gate). Wired at both `run_edge`
  sites with generous defaults — `CT_EDGE_RENDEZVOUS_MAX_PER_MIN` default **600/min per token** (≈10/s; a
  solver-farm flood is orders of magnitude higher, so normal use + the testbed are unaffected) and
  `CT_EDGE_MAX_CONNECTIONS` default **8192** concurrent (well above any real/testbed footprint, bounds FD/mem
  exhaustion). Frozen test `flood_limits_are_on_by_default_but_tunable_and_disable_able`. Gate green (full
  `cargo test --workspace -D warnings`). The per-token/per-connection semantics (from #86) are unchanged;
  only the default flipped from off→on with an explicit opt-out.

## #101 AF4-keydist: member Noise key stored un-attested in the CP registry (security-review)

The registry stores each member's X25519 Noise key as an un-attested BLOB with no binding to the holder
identity, so a DB-controlling operator could substitute a key to MITM the A2A direct-path `Noise_IK`
handshake. Fix: **attest** the Noise key with the member's holder key and verify end-to-end. Decomposed:

- **SEC101a** ✅ **Attestation primitive** (`ct_common::channel`): `member_noise_attest_bytes(channel, holder,
  noise_pubkey)` is the domain-separated (`ct-a2a-noise-attest-v1`) message the member signs with its **holder**
  key; `verify_member_noise_attestation(...)` checks it. Binds the Noise key to `(channel, holder)`, so a
  substituted key carries no valid holder signature. Frozen test
  `member_noise_attestation_binds_the_key_to_holder_and_channel` (genuine verifies; substituted key / wrong
  channel / wrong holder all rejected). Gate green.
- **SEC101b** ✅ **CP stores + verifies the attestation.** `channel_members` gained a `noise_attestation`
  column (`ensure_column`); `add_member` persists it + a `member_noise_attestation` getter. `POST
  /me/channels/:channel/members` now requires `noise_attestation` (hex) and **verifies**
  `verify_member_noise_attestation(channel, holder, noise_pubkey, sig)` before storing — an un-attested /
  operator-forged key is rejected `400`. `/internal/channel/authorize` returns the attestation alongside the
  key. Frozen coverage in `authed_channel_registry_is_owner_scoped` (valid attestation → stored; all-zero →
  `400`). Gate green.
- **SEC101c-i** ✅ **Edge resolver carries the attestation.** `AuthorizeResp`/`MemberResolution` gained
  `noise_attestation`; `ChannelAuthorizer::resolve` parses the CP-served attestation (hex→`[u8;64]`). Frozen
  test `resolve_carries_the_members_attested_noise_key` asserts it. Gate green — the edge now has the
  attestation ready to relay.
- **SEC101c-ii** ✅ **Relay + verify end-to-end.** The broker's authorize closure now returns the attestation
  (`(operator, noise, attestation)`); `broker_channel_rendezvous` appends the peer's **grant-authenticated**
  holder + Noise key + attestation to the ack (`member_ack_suffix`, all-or-nothing); `present_channel_join`
  parses them into `Admitted { peer_holder, peer_attestation, … }`; and `run_channel_join`
  **`verify_member_noise_attestation` before pinning** — refusing a key whose attestation doesn't verify
  against the grant-holder. Because the holder comes from the operator-signed grant (not the mutable
  registry), a DB-substituted key can't produce a matching attestation. Frozen tests:
  `run_channel_join_rejects_a_peer_key_with_a_bad_attestation` (substituted key → error, no session) +
  `rendezvous_relays_each_peers_attested_noise_key`/`auto_falls_back` reworked to relay+verify real
  attestations. Closure-signature ripple handled across the broker/agent. Gate green.

**#101 complete:** the member Noise key is attested by its holder (SEC101a), verified + stored at the CP
(SEC101b), and relayed + **verified by the initiator before pinning** (SEC101c) — closing the DB-operator
MITM vector on the A2A direct path end-to-end.

## #96 OIDC back-channel: JWKS + token-exchange fetched per callback with no timeout (security-review)

Each portal login callback fired `reqwest` calls to the IdP (token exchange + JWKS) with a fresh client and
**no timeout** — a slow/hanging IdP wedges the login path (login DoS).

- **Fix ✅** `oidc_http_client()` builds a reqwest client with a bounded total timeout (`OIDC_HTTP_TIMEOUT`
  = 10 s) + a 5 s connect timeout; both back-channel calls use it. `oidc_http_client_with(timeout)` is
  parameterised for tests. Frozen test `oidc_back_channel_client_times_out_a_hanging_idp` (a hanging IdP →
  error in <2 s, not a hang). Gate green.
- **Follow ⏳** no explicit response-size cap on the JWKS/token JSON — the timeout bounds a slow-drip huge
  response, but a fast huge response could still spike memory; a byte-capped read is a small hardening follow.

## #105 broker_channel_rendezvous: no per-round timeout — a stalled connection wedges the broker (bug)

A connection that completes the QUIC handshake but never submits a join blocked `read_join_on_connection`'s
`accept_bi` **forever**, wedging the broker's serial round loop for every channel (a trivial low-effort DoS).

- **Fix ✅** `read_join_on_connection` gained a `join_timeout` param and wraps the whole join read (accept_bi +
  framed request + possession round-trip) in `tokio::time::timeout`; on elapse it drops the stalled connection
  with an error and the round moves on. `accept_and_read_join` passes `JOIN_READ_TIMEOUT` (15 s — well above
  the single CP `authorize` round-trip). Frozen test `read_join_on_connection_times_out_a_stalled_connection`
  (a silent connection → error in <2 s, not a hang). Gate green.
- **Follow ⏳** the serial `run_edge` loop still processes rounds one at a time, so a stalled connection can
  delay others for up to the timeout; running rounds concurrently (`spawn` per round) + correlating the two
  connections of a pairing is a separate robustness redesign (the reporter's second suggestion) — see **#109**.

## #109 broker/relay pair the next-two-arrivals in one serial loop — single-slot, cross-channel mis-pairing, no 2nd-accept timeout (report, priority:high)

Robustness report on `broker_channel_rendezvous`/`broker_channel_relay`: both accept **two channel-blind,
sequential** connections and pair whatever arrives next. Three failure modes: **(1)** the relay splice runs
**inline** in the accept loop, so it serves exactly one channel globally — a persistent channel (the #103 sink)
wedges every other NAT'd member; **(2)** channel-blind pairing mis-pairs two concurrent channels' members
(`X-init` gets paired with `Y-init` → both refused); **(3)** the second `endpoint.accept()` has **no timeout**
(the #105 fix bounded the join *read*, not the wait for a partner), so a lone first-comer stalls the round.
The concept decision (scale model) is the developer's; the fix is a demux-by-`ChannelId` accept model. Too big
for one cycle — decomposed so the pure correlator (the substrate for all three) lands first:

- **#109-pairer** ✅ **Channel-keyed pairing correlator** (`ct_edge::channel_broker::ChannelPairer<T>`, pure, no
  sockets): a per-`ChannelId` waiting map. `offer(member)` parks the first holder of a channel and returns
  `Parked`; when a **different holder of the same channel** arrives it returns `Paired(first, second)` so the
  caller brokers exactly those two — two *different* channels park independently and never cross-pair (**fixes
  #2**). A same-holder re-offer (a retry) `Superseded`s the stale wait rather than pairing a holder with itself.
  Each parked member carries a `deadline`; `drain_expired(now)` evicts and returns timed-out lone waiters so the
  caller can close them with a clean `NO` (**the correlation half of #3**). Frozen test: park X→Parked, park Y
  (different channel)→Parked+both waiting (no cross-pair), second X holder→Paired(the two X members) with Y
  still parked, same-holder re-offer→Superseded, expired waiter→drained. Gate green.
- **#109-concurrent** — driving the accept loop through the pairer + spawning brokerage per pair is too big for one
  cycle (it entangles a socket-accept-loop rewrite with the splice-off-the-hot-path fix). Decomposed into ordered,
  finishable slices, each behaviour-frozen before the next:
  - **#109-concurrent-a** ✅ **Separate *admit* from *pair-completion*** (`ct_edge::channel_broker`, mechanical, no
    loop change): the two `broker_channel_*` functions each did two sequential `accept_and_read_join` calls then an
    inline `authorize_channel_pair` + finish. Extracted an `AdmittedMember` (conn + reply stream + verified
    `ChannelJoinRequest` + operator key + peer noise/attest) produced by an `accept_member` helper, and two
    completers `finish_rendezvous_pair(a, b, now)` (ack + endpoint-swap) / `finish_relay_pair(a, b, now)` (ack +
    `relay_initiator_to_acceptor` splice). `broker_channel_rendezvous`/`broker_channel_relay` now just admit two
    members and delegate — behaviour-preserving, so the two QUIC integration tests
    (`broker_pairs_two_agents_and_swaps_endpoints`, `broker_channel_relay_splices_two_members_tunnels`) freeze the
    behaviour across the refactor. New frozen test `finish_rendezvous_pair_completes_two_separately_admitted_members`
    admits two members and calls the finisher directly — the exact `offer→Paired(a,b)→spawn finish_*_pair` seam. This
    is the mechanical prerequisite for the concurrent loop: `finish_*_pair(a, b)` is now a standalone `spawn`-able
    task. Gate green, 0 warnings.
  - **#109-concurrent-b** ✅ **pairer-driven concurrent RELAY** (`ct_edge::channel_broker::run_relay_broker_loop`,
    wired in `serve.rs`): the RELAY accept loop now accepts one member (`accept_member`), offers it to a shared
    `ChannelPairer` keyed by `ChannelId`, and on `Paired(a, b)` `tokio::spawn`s `finish_relay_pair(a, b, now)` so
    the accept loop stays free — a persistent channel's splice no longer wedges the loop (**fixes #1**). Same-
    channel-only correlation (**fixes #2**: no cross-channel mis-pair). Each accept also `drain_expired`s the
    pairer, closing lone waiters past their park TTL (**addresses #3**: the 2nd-accept no longer waits unbounded).
    Replaces the serial `loop { broker_channel_relay(..).await }`. Frozen test
    `relay_broker_loop_pairs_two_channels_concurrently_without_wedging`: two channels over real QUIC — channel X
    is paired and its relay HELD OPEN, then Y races in and pairs (its bytes cross both ways) while X is held —
    which would hang under the old serial loop; asserts channel-keyed correlation (no X↔Y cross-pair). Verified
    non-flaky (5/5 runs). Gate green, 0 warnings.
  - **#109-concurrent-rendezvous** ✅ **pairer-driven concurrent RENDEZVOUS** (done as **#120** — see below). The
    earlier "single-slot exposure is far smaller / lower priority" note was **wrong**: the code contradicted it —
    `finish_rendezvous_pair` awaits `a.conn.closed().await; b.conn.closed().await` unbounded, so a single held-open
    paired member wedged the ENTIRE serial rendezvous endpoint (every channel's pairing blocked), the same
    single-slot wedge as the relay. Now fixed identically.

## #120 security: rendezvous endpoint still serial — single held-open member wedges all rendezvous pairing (review, priority:high)

Security-review follow-up to #109: the RELAY endpoint was made pairer-driven/concurrent (#109-concurrent-b) but the
RENDEZVOUS endpoint was left on the serial `tokio::spawn(async move { loop { broker_channel_rendezvous(..).await } })`.
Because `finish_rendezvous_pair` acks `OK <peer_endpoint>` then awaits `a.conn.closed().await; b.conn.closed().await`
with **no timeout**, a single paired member that holds its rendezvous connection open blocks the accept loop forever —
so every other channel's rendezvous pairing is wedged (the exact single-slot failure #109 fixed for the relay).

- **#120** ✅ **Generalized pairer-driven concurrent broker loop for BOTH endpoints** (`ct_edge::channel_broker`,
  wired in `serve.rs`): `run_relay_broker_loop` was generalized into `run_channel_broker_loop<..., C, CFut>` which
  takes the pairing **completer** as a closure `C: Fn(AdmittedMember, AdmittedMember, UnixSeconds) -> CFut` (spawned
  on `Paired`, `Send + 'static`). The RELAY call site + its frozen test pass `|a,b,now| finish_relay_pair(a,b,now)`;
  the RENDEZVOUS spawn now passes `|a,b,now| finish_rendezvous_pair(a,b,now)`, replacing the serial
  `loop { broker_channel_rendezvous(..) }`. Park-TTL / `drain_expired` / `Superseded` / `Parked` behaviour is
  identical to the relay loop, so a held-open rendezvous member's `conn.closed()` wait now runs on its **own spawned
  task** and the accept loop stays free (**fixes #1**); channel-keying means two channels can never cross-pair
  (**fixes #2**). `broker_channel_rendezvous` is kept for its existing pairing tests. Frozen test
  `rendezvous_broker_loop_pairs_two_channels_concurrently_without_wedging`: two channels over real QUIC — channel X is
  paired and its two rendezvous connections HELD OPEN (so X's spawned finisher blocks in `conn.closed()`), then Y
  races in and both Y members receive their `OK <peer_endpoint>` ack while X is held — which would hang under the old
  serial loop; asserts channel-keyed correlation (Y never learns an X endpoint). Verified non-flaky. Gate green,
  0 warnings.

## #114 Efficiency: per-frame heap allocs on the Noise bulk data path + backoff jitter (report, priority:high)

Efficiency review of the hot data path. Five ranked findings; the two HIGH ones are symmetric per-frame
framing allocations on `noise_pump` (the bulk tunnel path). Decomposed; the drop-in, wire-preserving
hot-path pair landed first:

- **#114-framing** ✅ **Zero-alloc framing on the `noise_pump` bulk path** (`ct_common::noise`): findings #1+#2.
  Outbound no longer calls `frame()` (which heap-allocated a fresh `Vec` and copied the whole ≤16 KB ciphertext
  just to prepend a 2-byte length) — the 2-byte length prefix is reserved at the front of the reused `ct`
  buffer, `write_message` encrypts in place after it, and the frame ships as one `ct[..2+len]` slice (no
  per-frame alloc, no second copy; wire bytes byte-identical to `frame()`). Inbound no longer calls
  `read_frame` (fresh `Vec` per frame) — a new `read_frame_into(recv, &mut buf)` reads into one buffer hoisted
  for the whole inbound loop (`resize` reuses capacity), returning the body length; `read_frame` stays as a
  thin fresh-`Vec` wrapper for the low-rate handshake paths (client/a2a/transport unchanged). Net: two heap
  allocs + up to two ~16 KB copies removed per 16 KB per direction. Frozen test
  `read_frame_into_reuses_one_buffer_across_varied_frames` (large→small→mid, byte-identical bodies via the
  reused buffer + clean EOF); the existing `noise_pump_streams_bidirectionally` freezes the end-to-end wire
  behaviour across the outbound in-place change. Gate green, 0 warnings. (Profiler-confirm before treating the
  pump as the bottleneck — but drop-in and directly serves the max-bandwidth goal, so low-risk to land now.)
- **#114-backoff-jitter** ✅ (finding #3, cheap robustness win, independent of throughput): `Backoff` gained
  `next_delay_jittered(rand01)` applying **equal jitter** — the delay is spread uniformly in `[d/2, d]` (not a
  naive `×0.5..1.5`, which could exceed `max`), so a shared-edge outage/restart no longer triggers a
  synchronized fleet retry storm, while the exponential growth, the `max` cap and the give-up after
  `max_attempts` are preserved. The caller supplies the random sample (`rand::random::<f64>()` at the 4 serve
  reconnect sites), keeping `Backoff` pure + deterministically testable. Frozen test
  `jitter_within_half_to_full_delay_and_still_gives_up` (endpoints `d/2`/`d`, in-range across the growth,
  `≤ max`, unchanged give-up). Gate green, 0 warnings.
- **#114-dialer-reuse** ✅ (finding #4, config half) — **confirmed against source**: `build_channel_dialer`
  rebuilt a rustls `ClientConfig` + cert verifier + QUIC crypto **and** bound a new UDP `Endpoint` on every
  dial (broker, relay, each #106 ladder rung). Landed the **safe** half: the runtime-independent client config
  is now cached in a `OnceLock` and cloned per call (built once, not per dial). The UDP socket is still bound
  per call **by necessity** — a quinn `Endpoint`'s driver is tied to its creating tokio runtime, so a
  process-wide shared `Endpoint` would break across runtimes (e.g. the per-test runtimes). Frozen test
  `build_channel_dialer_reuses_config_but_binds_its_own_socket` asserts both calls build working, distinctly
  bound endpoints. Gate green, 0 warnings.
  - **#114-endpoint-reuse** ⏳ (optional follow): reuse ONE `Endpoint` *within a join flow* — build it once in
    `run_channel_join_command` and thread it through the broker/relay/direct dials (`dial_peer_direct`,
    `present_channel_join_via_ladder`). Localized (same runtime), so safe; saves the 2-3 extra socket binds per
    join. Minor; the config rebuild (the allocation-heavy part) is already gone.
- **#114-hex32** ✅ (finding #5, LOW): `hex32` now writes a static nibble table directly into the pre-sized
  `String` — **byte-identical** output to the old `format!("{:02x}")` loop (signing preimage unchanged, so all
  existing grant/invite signatures still verify), removing the ~64 throwaway `format!` allocs per call. Called
  twice per grant/invitation verify on the per-connection A2A admission gate. Frozen test
  `hex32_is_byte_identical_to_the_format_loop` (fixed `00…`/`ff…` vectors + an arbitrary nibble-spanning
  pattern, each equal to the `format!`-loop reference, always 64 chars); the existing grant/invite verify
  tests freeze the preimage end-to-end. Gate green, 0 warnings.

## #117 self-service Agent-Fabric channel provisioning (feature, priority:medium)

Central flagged a real operational gap: portal accounts are fully self-service for **tunnels** but not for
**Agent-Fabric channels** — registering/joining a channel assumes the caller already holds an ed25519 holder
key + X25519 Noise key + a signed grant, so today an account either runs CLI tooling with hand-generated keys
or comes back to central for manual crypto provisioning (as was done for #103). The concept is the developer's
call. **Direction chosen by scimbe (2026-07-19): CLI self-service subcommand** — keys are generated **locally**
(never in the browser or on the server), preserving the provider-blind/zero-knowledge posture. Decomposed:

- **#117-cli-identity** ✅ **Local channel-identity generator** (`ct_agent::channel_run::ChannelIdentity`):
  `ChannelIdentity::generate()` mints a fresh holder ed25519 keypair (`SigningKey` from the OS CSPRNG) + an
  X25519 Noise static keypair (`ct_common::noise::generate_static_keypair`) locally, and emits them in exactly
  the hex the `ct-agent channel` CLI consumes — `holder_key_hex()`→`CT_CHANNEL_HOLDER_KEY`,
  `noise_key_hex()`→`CT_CHANNEL_NOISE_KEY` — plus the two public keys (`holder_pubkey_hex`/`noise_pubkey_hex`)
  an operator needs to register the channel / sign the member's grant. Closes the "must hand-generate keys"
  half of the gap: a participant mints their own material with no central round-trip, private keys never
  leaving their machine. Frozen test round-trips the generated holder + Noise keys through the real
  `ChannelJoinCliConfig::from_lookup` (with an operator-signed grant over the generated holder pubkey) and
  asserts the CLI parses back the *same* keys + unique-per-mint. Gate green, 0 warnings.
- **#117-cli-subcommand** ✅ **`ct-agent channel init`** (`main.rs` + `ChannelIdentity::env_block`): the
  subcommand mints a fresh identity locally (`ChannelIdentity::generate`) and prints a copy-pasteable shell
  block — the two SECRET private keys as `export CT_CHANNEL_HOLDER_KEY`/`CT_CHANNEL_NOISE_KEY` (exactly what
  `ct-agent channel` reads) plus the two PUBLIC keys as comments to hand the operator. A participant runs
  `eval "$(ct-agent channel init)"`, gives the operator the public keys, then runs `ct-agent channel` with the
  operator-supplied `CT_CHANNEL_GRANT` — no hand-crafted keys, no central round-trip, private keys never leaving
  the machine. Frozen test `channel_identity_env_block_exports_the_keys_the_cli_reads` (block exports both
  private-key env vars, surfaces both public keys, and is `eval`-safe — every line a comment or an `export`).
  Gate green, 0 warnings.
- **#117-operator-flow** — the create-a-channel side; decomposed:
  - **#117-operator-grant** ✅ **Operator identity + grant issuance** (`ct_agent::channel_run::OperatorIdentity`):
    `generate()` mints the operator ed25519 key locally (its public key is the channel's authority);
    `issue_member_grant(channel, holder_pubkey, direction, expires_at)` signs a `ChannelGrant` binding the
    member's `channel init` holder public key and returns the hex the member sets as `CT_CHANNEL_GRANT`. Pure
    crypto — no server round-trip, no private key leaves either machine. Frozen test
    `operator_issues_a_grant_the_edge_verifies_and_the_member_cli_accepts` closes the loop: the issued grant
    **verifies under the operator public key** exactly as the edge's admission gate does, and the **member CLI
    (`from_lookup`) accepts** it alongside the member's self-generated keys. Gate green, 0 warnings.
  - **#117-operator-cli** ✅ **Operator CLI: `channel operator-init` + `channel grant`** (`main.rs` +
    `OperatorIdentity::operator_env_block` + `OperatorGrantRequest`): `ct-agent channel operator-init` mints the
    operator key locally and prints its `eval`-safe env block (`CT_CHANNEL_OPERATOR_KEY` + the operator pubkey to
    register); `ct-agent channel grant` reads the operator key + `CT_GRANT_*` (channel id, member holder pubkey,
    direction, expiry) and prints the `CT_CHANNEL_GRANT` hex the member uses. Frozen test
    `operator_grant_request_parses_env_and_issues_a_verifiable_grant` (env → params, issued grant verifies under
    the operator key + binds the member, required-field enforcement). Gate green, 0 warnings.
  - **#117-operator-register** ✅ **Register the channel authority with the CP** (`ControlPlaneClient::register_channel`
    + `ct-agent channel register` + `ChannelRegisterRequest`): `register_channel(channel_hex, operator_pubkey_hex,
    bearer_token)` does `POST /me/channels {channel, operator_pubkey}` with `Authorization: Bearer <token>` (owner =
    the OIDC subject), so the edge's channel-authorize lookup knows the channel's authority. `ct-agent channel register`
    reads `CT_AGENT_CP_URL` (as onboarding), `CT_GRANT_CHANNEL`, `CT_OIDC_TOKEN`, and the operator authority — deriving
    the operator **public** key from `CT_CHANNEL_OPERATOR_KEY` (private never sent) or taking `CT_CHANNEL_OPERATOR_PUBKEY`
    directly. Frozen tests: `channel_register_request_parses_env_and_derives_the_operator_pubkey` (env → params, pubkey
    derivation, required-field enforcement) + `client_registers_a_channel_against_the_authed_service` (client-over-HTTP
    round-trip against the real `authed_channel_router` with a minted OIDC bearer: 200 registers + store resolves the
    operator key; non-owner re-key → 403; missing token → 401). Gate green, 0 warnings. The full self-service flow now
    works end-to-end (operator-init → register → members init → operator grant → members join). ⏳ remaining:
    cross-user invitations (deferred) + live verification by @central.
- **#117-docs** ⏳: a short onboarding doc walking two accounts through create→invite→join over `:443` (ties to
  the #106 front-door path + the #100 one-liner).

## #52 Tail-Latenz-Statistik — symmetrisches KI auf schiefen Daten; p99 aus n=30 unbelastbar (thesis)

Gutachten: Tabelle 7.1 „80,8 ± 91,9 ms" impliziert negative Latenz (symmetrisches Normal-KI auf
rechtsschiefen Verlustdaten), und p99 aus n=30 ist faktisch das Stichprobenmaximum. Nur die
aggregierte `latency.csv` (Mittel/p50/p95/p99/ci95) ist eingecheckt — die Roh-Stichproben (für
Bootstrap-KI/ECDF) und größeres n brauchen einen echten Testbett-Lauf. Dekomposition:

- **T52.1** ✅ **Ungültiges symmetrisches KI entfernen + p99 aus der Headline-Tabelle** (deterministisch aus
  den vorhandenen Aggregaten): `scripts/tabulate.py` gibt jetzt Mittel + robuste p50/p95 aus (kein `±`-KI,
  kein p99), Tabelle aus `latency.csv` **neu generiert** (`results-table.{tex,md}`) → keine negative
  KI-Untergrenze mehr. Neuer Absatz „Statistische Darstellung" in `evaluation.tex`: symmetrisches
  Normal-KI wegen Rechtsschiefe verworfen; p99 nur als grober Größenordnungs-Indikator (bei n=30 = Maximum),
  belastbare Aussage über Median + p95; FF2/FF3-Fließtext entsprechend bereinigt (kein `±`-KI, p95 statt
  p95+p99). Thesis baut grün (`thesis-build.sh` exit 0, 0 undefined, 63 S.).
- **T52.2** ⏳ **Roh-Daten-Re-Analyse** (braucht Testbett): Roh-Stichproben je Bedingung sichern, ausreichend
  großes n (mehrere Hundert), Perzentil-Bootstrap-KI + ECDF/Violin, und die p99-zentrische Tiefenanalyse in
  §7.x (p99-Schwierigkeitstabelle, „Warum Verlust das p99 aufbläht") auf die robuste Basis umstellen.
  **fix-ready erst mit T52.2** (Bootstrap-KI dokumentiert, ECDF gezeigt).

## #56 CPU-Contention-Confound (Single-Host, 4 Container) auf die Latenz-Tails (thesis)

Gutachten [Mittel/Hoch]: alle vier Container teilen sich die CPU eines Hosts; PoW + asymmetrische
Krypto konkurrieren um Rechenzeit und treiben die p99-Tails artifiziell, ohne dass das analysiert
wird. Dekomposition:

- **T56.1** ✅ **Confound benennen + Tails einordnen** (deterministisch, `evaluation.tex`
  §Limitierungen): neuer Validitätspunkt „CPU-Contention auf geteilten Kernen" — die absoluten
  Tails (p95 und darüber) sind teils Emulations-/Contention-Artefakt (PoW + `Noise_IK`-Krypto auf
  geteilten Kernen; `netem` modelliert stochastische Drops, keinen realen Congestion-Tail). Der
  Interne-Validität-Absatz verweist jetzt darauf und wurde zugleich mit #52 T52.1 versöhnt (das
  ungültige symmetrische `±117,261 ms`-KI durch Median/Mittel/Stddev + Skew-Aussage ersetzt).
  Thesis baut grün (`thesis-build.sh` exit 0, 0 undefined, 63 S.).
- **T56.2** ⏳ **Quantifizieren/mitigieren** (braucht Testbett): Kontroll-Läufe mit `CPU`-Pinning je
  Container + protokollierter Auslastung (oder reduzierter Contention), um den Contention-Anteil am
  Tail von der Netzbedingung zu trennen. **fix-ready erst mit T56.2** (explizite Messung/Pinning-Kontrolle).

## #70 USP-Einwand einordnen — PQC-Lücke, Ockam/Nebula/Headscale, Passthrough-Modi (thesis)

Externer USP-Einwand; per central-Analyse trifft er nur teilweise (die Arbeit beansprucht die
Vier-Bausteine-Kombination, nicht „provider-blind" allein; Metadaten/Dezentralität bereits als
Out-of-Scope getrackt — #59, ADR-0002/0017, fazit). Drei echte Restlücken, dekomponiert:

- **T70.1** ✅ **PQC-Lücke benennen** (`fazit.tex` §Grenzen der Arbeit): neuer „Fünftens"-Punkt — die
  E2E-Schicht ruht auf klassischer EC-Kryptographie (`Noise_IK_25519_ChaChaPoly_BLAKE2s`, X25519, belegt in
  `noise.rs:13`), nicht quantensicher; harvest-now-decrypt-later benannt; hybrider PQC-Schlüsselaustausch mit
  NIST-standardisiertem ML-KEM (FIPS 203, 2024) als bewusst zurückgestellter nächster Schritt. Neue
  Bib-Quelle `nistfips203`. Thesis baut grün (0 undefined, 64 S.). Analog zum bestehenden
  Metadaten-/Dezentralitäts-Disclaimer — schließt die „PQC fehlt auch als Erwähnung"-Lücke.
- **T70.2** ✅ **Ockam, Nebula, Headscale/Tailscale-DERP** aufgenommen (`relatedwork.tex` §3.1 + 4 Bib-Quellen
  `nebula`/`tailscalederp`/`headscale`/`ockam`): neuer Absatz benennt sie als die architektonisch nächsten
  payload-blinden Relay-/Overlay-Systeme (Nebula Noise-Mesh mit Lighthouses; Tailscale-DERP reicht
  verschlüsselte WireGuard-Pakete durch, Headscale = selbst-hostbare Steuerebene; Ockam mehrsprüngige E2E-
  Kanäle). **Kein Overclaim** (Gegenkorrektur beachtet): „deren Relays *als Architektur-Eigenschaft* Chiffretext
  weiterleiten", und explizit eingeräumt, dass payload-blindes Relaying *verbreitete Praxis* ist → der Beitrag
  ist die Vier-Bausteine-Kombination, nicht Nutzlast-Blindheit allein (Verweis §3.5). Bibliografie 20 → 24.
  Thesis baut grün (0 undefined, 64 S.).
- **T70.3** ✅ **Passthrough-/Raw-TCP-Modi eingeordnet** (`relatedwork.tex` §3.5): neuer Absatz nach der
  Abgrenzungstabelle — die Tabelle vergleicht die Standard-Betriebsart (Anbieter-TLS-Terminierung);
  Cloudflare Tunnel/ngrok/Tailscale Funnel bieten zusätzlich Passthrough-/Raw-TCP-Modi, in denen der
  Vermittler ebenfalls nutzlast-blind ist. Ehrlich eingeräumt + gezeigt, dass die Abgrenzung trotzdem hält:
  auch im Passthrough adressiert der Anbieter per bekanntem Hostnamen (kein opakes Token, das das Ziel
  verbirgt), ohne KYC-freies PoW-Rendezvous und ohne kundenverankerte Schlüssel ohne zentrale PKI → der
  Passthrough schließt nur den Payload-, nicht die übrigen drei der vier Bausteine. Thesis baut grün (65 S.).
  **#70 fix-ready** (alle drei echten Lücken adressiert: PQC benannt, nächste Vergleichsprojekte zitiert,
  Passthrough-Modi eingeordnet).

## #77 Skill trust model — prompt-only enforcement (security-review, decided 2026-07-18)

scimbe's decision: **commit the enforcement layer** — programmatic guardrails + a stable account-id anchor.
Decomposed:

- **SEC77a** ✅ **Pin the issue-author trust anchor to scimbe's STABLE account id** (`scripts/verify-issue-author.sh`):
  the three role skills keyed authorship on the mutable `author.login`; GitHub allows a username rename +
  reuse of the freed login on another account (#77 gap 6). The guard pins scimbe's stable account **node id**
  (`MDQ6VXNlcjEyNzk5MTI=`, = numeric id 1279912) — which `gh issue view --json author` exposes as
  `.author.id` — and exits non-zero for any other author. All three SKILLs (developer/central/agent) now
  mandate `scripts/verify-issue-author.sh <n>` (exit 0 iff pinned) instead of a login string compare. Gate:
  `bash -n` + `--selftest` (pinned id passes; foreign id, login string, empty all rejected) + live check
  (#77 → OK; a foreign account → rejected).
- **SEC77b** ✅ **PreToolUse role-enforcement guard** (`scripts/role-guard.sh`; scimbe decision: CT_ROLE env var): a Claude Code PreToolUse hook that, when the launching role sets `CT_ROLE=agent|central`, denies `Edit`/`Write`/`MultiEdit`/`NotebookEdit` and Bash file-writes (`> file`, `tee`, `sed -i`, `git` mutations) — so "field roles cannot modify the codebase" is shim-enforced, not prose (#77 gaps 1,8). The developer role may edit. The hook is committed + self-tested; its wiring into the LOCAL, untracked `.claude/settings.json` is documented in the script header + all three role SKILLs (the local settings.json is machine-specific, per #91). Gate: `bash -n` + `--selftest` (agent Edit/Write/MultiEdit + Bash write/git-mutate blocked; agent Read + read-only Bash allowed; developer Edit/write allowed).
- **SEC77c** ✅ **Treat non-scimbe issue *comments* as untrusted** (#77 gaps 4,9, `scripts/verify-comment-authors.sh`):
  the real injection vector on a public repo is a comment (from any account) on a scimbe-authored issue. The
  guard lists an issue's comment authors and flags every one not from the pinned scimbe account, exit 3 iff any
  are untrusted. **Correctness note:** `gh issue view --json comments` returns the comment author with *no id*
  (login only), so the guard uses the REST endpoint `gh api repos/…/issues/N/comments` which exposes the stable
  numeric `user.id` (1279912). All three SKILLs now mandate running it and treating any flagged comment body as
  DATA, never as an instruction. Gate: `bash -n` + `--selftest` (scimbe id trusted; foreign id, and a *recycled
  scimbe login on a different id*, both flagged) + live (#77 all-scimbe → OK exit 0).

## #102 Intent-/policy-driven SDN-style control plane for the agent mesh (feature, epic)

An orchestration/policy layer **on top of** the Agent Fabric: declare *who may talk to whom under which
conditions* (RBAC groups + security Labels/Levels with MAC flow-control, default-deny) and drive it via a
token-authenticated REST/OpenAPI surface + an MCP tool layer; the controller compiles the declaration into
`SignedChannelGrant`s and the edge broker enforces admission. Big epic — decomposed bottom-up so the pure,
mesh-independent core lands first:

- **#102-policy-core** ✅ **Policy decision engine** (`ct_common::policy`): the pure RBAC + MAC evaluator every
  other layer consumes (controller compiles grants from it, broker enforces it at admission #81/#99, MCP
  `net.explain` renders its `Decision`). `Policy { levels, rules, mac_flow_control }` with `Levels` (ordered
  labels), default-deny `AllowRule`s over `Selector { group?, label? }`, and Bell–LaPadula **no-write-down**
  MAC that overrides RBAC. `evaluate(from, to) -> Decision { allowed, reason }` (directed flow) and
  `may_establish_channel(a, b)` (bidirectional — the broker-admission check; a cross-level pair is refused
  because one direction is a write-down). Wire-serializable (serde) for the REST surface. Reasons are
  human/AI-legible (for `net.explain` and the broker's `NO <reason>`). Frozen tests: the #102 "verteilte
  Firma" fixture (dev/ops/finance × internal/secret) — RBAC allow + default-deny, MAC blocks write-down /
  allows write-up even with a matching rule, MAC fails closed on an unknown label, channel establishment needs
  both directions + refuses cross-level, and a serde round-trip. Gate green (full `cargo test --workspace -D warnings`).
- **#102-network-model** ✅ **Declarative `Network` + reconcile diff** (`ct_common::policy`, pure): the
  desired-state layer the SDN controller reconciles the mesh toward, built on the policy core. `Network {
  agents, policy }` (wire-serializable for the REST surface); `Network::desired_channels() -> BTreeSet<Pair>`
  compiles the connectivity the policy permits — the canonical unordered agent-`Pair`s where
  `may_establish_channel` is allowed (self-pairs excluded, cross-segment/MAC-write-down pairs excluded).
  `reconcile(desired, current) -> Reconciliation { to_establish, to_revoke }` is the pure set diff
  (`desired − current` / `current − desired`) the controller applies to make the live mesh match the
  declaration (the actual grant minting / teardown is the caller's job). Frozen tests: `Pair` canonical
  regardless of order; `desired_channels` compiles exactly the policy-permitted pairs on the "verteilte Firma"
  fixture (dev↔dev, dev↔ops in; dev↔finance + finance internal↔secret out); `reconcile` establishes the
  missing allowed channels + revokes a stale one + is a no-op when converged. Gate green.
  - **#102-network-store** ✅ **Durable owner-scoped persistence** (`control-plane::storage::SqliteNetworkStore`):
    a `Network` is stored as a JSON blob keyed by `(owner, id)` — strictly owner-scoped, so a subject only
    reads/writes networks it owns. `put`/`get`/`delete`/`list(owner)`; `get` for another owner or an unknown id
    returns `None` (isolation), and a blob that no longer deserializes is treated as absent rather than
    erroring the caller. Frozen test `network_store_is_owner_scoped_and_round_trips` (round-trips the full
    Network for its owner; invisible to another subject; owner-scoped list; in-place replace; scoped delete).
    Gate green.
  - **#102-rest** ✅ **The authenticated declarative-network REST surface** (`service::authed_network_router`,
    `/me/networks/*`): `PUT /me/networks/:id {Network}` persists the caller's desired state (idempotent),
    `GET /me/networks/:id` loads it (404 if none), and `GET /me/networks/:id/plan` returns
    `{desired: [[a,b],…]}` — the policy-compiled connectivity (`Network::desired_channels`). Follows the
    `/me/*` OIDC-bearer, subject-scoped convention: the `owner` is always the verified subject
    (`subject_of`), never a request field, so it carries **no unauthenticated write surface** (cf. #87) and is
    owner-isolated. Mounted in the `oidc`-gated block of `persistent_control_plane_router`. Frozen test
    `authed_network_api_is_owner_scoped_and_plans_from_the_policy` (no bearer→401; owner PUT→GET round-trips the
    Network; another subject→404; `/plan` compiles exactly the permitted pair from the policy). Gate green.
  - **#102-explain** ✅ **`Network::explain(a_id, b_id) -> Decision`** (`ct_common::policy`): the
    `net.explain(a, b) → allowed? why` decision the acceptance names — resolves both ids to members, then
    `may_establish_channel`, with a legible reason; an id that isn't a member is a **fail-closed deny**. This is
    the pure primitive both the MCP `net.explain` tool and the broker-enforce path call. Frozen test
    `network_explain_answers_allowed_and_why_for_two_agent_ids` (permitted→allowed; no-rule→default-deny;
    cross-level→MAC write-down; unknown id→"not both members"). Gate green.
  - **#102-broker-enforce** ⏳ (live-gated): the edge broker's `authorize` closure consults the compiled policy
    (via `explain`) so a non-conformant join is refused with `NO <reason>` — needs the policy served to the edge
    + the live A2A mesh (#99/#98/#100) to prove end-to-end. **#102-mcp** ⏳: expose `net.apply/grant/revoke/
    explain` as agent-native MCP tools (`explain` now has its core). Both exercise the live mesh.
- **#102-rest** ✅ (mostly — verified 2026-07-20): `PUT /me/networks/:id` + `GET` + `/plan` are built and owner-scoped (`authed_network_router`, tested `authed_network_api_is_owner_scoped_and_plans_from_the_policy`); the imperative overrides are also built as `authed_channel_router` — `POST /me/channels` (register), `POST /me/channels/:channel/members` (add), `POST /me/channels/:channel/members/:holder/remove` (**revocation**); all under OIDC-bearer authN. **Remaining (low-priority, not blocking):** an OpenAPI/schema document (no `utoipa` dep today) and an *optional* scoped-API-token authN alongside OIDC — the OIDC-bearer gate already covers every writer (#87), so this is a convenience, not a gap. *(Corrected a stale ⏳ marker: PUT + imperative overrides + revocation were already landed.)*
- **#102-broker-enforce** ⏳: the edge broker's `authorize` closure consults the compiled policy so a
  non-conformant join is refused with `NO <reason>` (defense-in-depth with the agent-side grant check).
- **#102-mcp** ⏳: the same operations as agent-native MCP tools (`net.apply`, `net.grant`, `net.revoke`,
  `net.explain(a, b) → allowed? why`). Depends on the live A2A mesh (#99/#98/#100/#81/#72) for the end-to-end
  "allowed flow connects, disallowed refused at the broker" acceptance.

## #104 Opportunistic relay→direct upgrade for A2A channels (feature)

Once two members fall back to the edge relay (`AF4-relay-clientwire`), the edge carries the full ciphertext
path for the session's life — even if a direct path later becomes viable (NAT rebinds, firewall opens, peers
roam). Goal: silently promote back to direct and free the relay (the Tailscale DERP→direct shape), a real edge
offload. Decomposed so the pure, mesh-independent core lands first:

- **#104-coordinate** ✅ **Upgrade coordination + offload metric** (`ct_common::upgrade`, pure/deterministic):
  the two pieces the issue calls out as the load-reduction proof and the race-avoidance rule.
  - `UpgradeCoordinator` — decides **when** and **who**: only the **initiator** owns triggering the swap
    (`should_attempt` is always false for the responder, so the peers never race), retries a background direct
    dial on **exponential backoff** (`base·2^n`, capped) while still relayed, and `confirm_upgraded` flips the
    path `Relay→Direct`, stops further attempts, and records the **time-to-upgrade**. Caller-supplied `now`
    (deterministic, mirrors `replay`/`ratelimit`).
  - `PathMeter` — per-session **relay-vs-direct byte accounting** + `direct_fraction()`, the number that shows
    the edge is actually offloaded.
  Frozen tests: initiator-only triggering + schedule, exponential backoff to the cap, confirm→direct stops
  attempts + records time-to-upgrade (idempotent), and relay/direct byte accounting. Gate green
  (full `cargo test --workspace -D warnings`).
- **#104-signal** ✅ **Handover control protocol** (`ct_common::upgrade::UpgradeMsg`): the tiny message the two
  members speak **over the still-open relay stream** to coordinate the swap. `Offer { direct_endpoint }`
  (initiator → responder: "I can reach you direct — prepare the swap, here's the endpoint"), `Ready`
  (responder → initiator: the direct path is live on my side — the both-ways-live confirmation before either
  side drops the relay, so no data-drop window), and `Abort` (back out, stay on relay). Wire form `tag(1) |
  payload` with `encode`/`decode`; decode is bounds-checked/panic-free (empty, unknown tag, empty-endpoint
  Offer, non-UTF-8 endpoint, or a payload on a payloadless tag all → `None`), so a garbled relay byte can't
  crash the coordination. Frozen test `upgrade_msg_round_trips_and_rejects_malformed`. Gate green.
- **#104-handover** ⏳ then: wire `UpgradeCoordinator` into `run_channel_session` — background `dial_peer_direct`
  (reusing `AF4-resilience-classify`) while relayed; on success open a second direct QUIC connection, run a
  fresh Noise_IK over it, hand the ciphertext stream over, and release the relay only after the direct path is
  confirmed live both ways. Needs live connections, so its e2e is the follow packet.
  **Decomposed (2026-07-20, developer) — sequenced, with the testability boundary marked:**
  - **H1 — coordination handshake driver** ⏳ (unit-gatable): `negotiate_upgrade(role, coord, ctrl_stream, dial)` — drives the existing `UpgradeCoordinator` + `UpgradeMsg` over the still-open relay control stream: initiator (on a successful **injected** `dial`) sends `Offer{direct_endpoint}`, responder dials + replies `Ready`, both `confirm_upgraded`; `Abort` on failure keeps the relay. NO application-byte movement yet — pure coordination, so it's inert/safe until H2/H3 wire the actual cutover. Frozen test over two in-memory duplexes (relay ctrl) + a mock dial: both sides reach `Path::Direct`; a failing dial → stays `Relay`; an `Abort` is honoured.
  - **H2 — data cutover primitive** ⏳ (unit-gatable, SECURITY-SENSITIVE): migrate the running A2A application stream from the relay `Noise_IK` session to a freshly-established direct `Noise_IK` **without losing or duplicating bytes** — quiesce relay writes, drain in-flight, switch, then close the relay. Frozen test over injected relay+direct duplex pairs asserting **byte-exact continuity** across the switch (a monotonic payload sequence arrives complete + in order, no gap/dup at the seam). This is the risky core; land it in isolation first.
  - **H3 — wire H1+H2 into `run_channel_session_on_stream`** ⏳ (integration): the live session loop background-dials on the coordinator's backoff, runs H1 then H2, updates `PathMeter`. Its correctness under real timing/loss is the live concern.
  - **H4 — LIVE cross-NAT hole-punch + clean-cutover PROOF** ⏳ (live only, NOT the cargo gate): real NAT'd hosts; DCUtR punch succeeds and the relay→direct cutover drops zero application bytes. The analog of `#103`'s live smokes — the roles that own the deploy (source/sink/central) prove this; it cannot be hermetically tested (no NAT on loopback).
  **Boundary:** H1/H2 are unit-gatable and land behind frozen tests; H3 is integration (mockable but its value is live); **H4 is the actual proof and is live-only.** Recommend landing H1 → H2 (de-risk the cutover in isolation) before H3, and gating a live deploy on H4.

## #106 :443 front-door fallback for the Agent-Fabric channel broker + relay (feature, priority:high)

The channel broker listens only on `:4435`; a restrictive/NAT'd network (empirically `:4433` open, **`:4435`
filtered**, `:443` open — #103) can't reach it, so channel-to-channel is usable only from permissive networks.
Same problem the classic tunnel had before #31/#46 — fix by multiplexing the channel service behind the unified
`:443` front door with an ALPN discriminator, mirroring the `ct-edge` data-plane leg. Decomposed:

- **#106-alpn-classify** ✅ **Channel ALPN discriminator + front-door routing** (`ct_edge::sni`): new
  `CT_EDGE_CHANNEL_ALPN = "ct-edge-channel"` (the channel-service analog of `CT_EDGE_ALPN`) and a
  `FrontDoorRoute::ChannelBroker` variant; `classify_front_door` routes a ClientHello carrying the channel ALPN
  to it, ahead of any SNI (the channel leg, like `ct-edge`, carries no SNI). This is the pure demux decision
  both the edge dispatch and the client fallback build on (the #31 FD1 pattern). `serve_front_door` gains the
  arm (closes cleanly with a clear reason — the dispatch is the follow packet). Frozen test
  `classify_front_door_routes_the_channel_alpn_to_the_broker` (channel ALPN → `ChannelBroker`, wins over a
  terminate-host SNI; the classic `ct-edge` ALPN still → `EdgeRelay`; the two ids are distinct). Gate green.
- **#106-client-fallback** — decomposed (too big for one cycle) into:
  - **#106-client-ladder** ✅ **The dial fallback ladder** (`ct_agent::channel_run`): `ChannelJoinCliConfig`
    gained an optional `CT_CHANNEL_FRONT_DOOR` (host:port) + pure `broker_ladder()`/`relay_ladder()` returning
    the ordered `ChannelDialRung`s — the direct channel port first, then (if configured) the `:443` front door
    (`via_front_door`, TLS-TCP + `ct-edge-channel` ALPN). A set-but-malformed front door is a hard error (a typo
    can't silently drop the fallback). This is the client's fallback *decision* — pure/testable now; the actual
    TLS-TCP dial through the front door is the next slice. Frozen test extends
    `channel_join_cli_config_parses_the_plane_one_liner` (no front door → direct-only; set → direct then :443;
    relay likewise; malformed → error). Gate green.
  - **#106-client-dial** — decomposed (the ladder-walk control logic is separable from the transport dials):
    - **#106-client-dial-walk** ✅ **The fallback-ladder walker** (`ct_agent::channel_run::dial_ladder`): pure,
      socket-free — tries each `ChannelDialRung` in order, returns the first that connects, and falls through a
      failed rung (`Unreachable`/`Failed`) to the next, so a blocked *direct* rung falls back to the `:443`
      front-door rung; errors only when EVERY rung is blocked. The per-rung transport connect is **injected** (a
      closure), so the walk is unit-testable without sockets. Frozen test
      `dial_ladder_falls_through_to_the_front_door_then_errors_when_all_blocked` (fall-through, first-success
      short-circuit, all-blocked→error). Gate green, 0 warnings.
    - **#106-client-join-generic** ✅ **Transport-agnostic client join protocol**
      (`ct_agent::channel::present_channel_join_on_stream`): extracted the channel-join wire protocol (framed
      request, possession challenge/response, `OK`/`NO` ack) out of `present_channel_join` to run over any
      `AsyncWrite + AsyncRead` duplex, not just a `quinn` bi-stream — the client mirror of the edge's
      `read_channel_join_on_stream`. `present_channel_join(&conn, …)` is now the thin QUIC wrapper (`open_bi` →
      delegate), signature unchanged so all callers are unaffected. Frozen test drives the full protocol over an
      in-memory `tokio::io::duplex` against a minimal test "edge" (framed request → challenge → possession
      verify → `OK <endpoint>`), asserting the client returns `Admitted` with the peer endpoint over a non-QUIC
      stream. Gate green, 0 warnings.
    - **#106-client-dial-443** ✅ **The agent broker-join fallback over `:443`** (`ct_agent`): the `:443` channel
      dialer + the ladder-driven join that composes the three primitives. `transport.rs` gains
      `tcp_tls_connect_channel` (TLS-TCP to the `:443` front door advertising ALPN `ct-edge-channel`) by
      **additively** extracting a `tcp_tls_connect_with_alpn(addr, cert, alpn)` helper — `tcp_tls_connect` is now a
      thin `b"ct-edge"` wrapper (existing callers unchanged). `channel_run.rs` gains
      `present_channel_join_via_ladder(rungs, request, holder, edge_cert, direct_timeout)`: walks the broker/relay
      ladder over `dial_ladder` — a **direct** rung dials QUIC (`dial_peer_direct` → `present_channel_join`); a
      **front-door** rung dials TLS-TCP (`tcp_tls_connect_channel`) and runs the identical join over the split
      stream (`present_channel_join_on_stream`). The first rung that *completes* the join (Admitted or Refused)
      wins; a transport `Unreachable`/`Failed` falls through, so a blocked direct channel port recovers over
      `:443`. Frozen test `present_channel_join_via_ladder_falls_back_to_the_443_front_door`: a **dead** direct rung
      + a **live** real `:443`-style TLS-TCP edge whose accepted stream is admitted with the production
      `ct_edge::channel_broker::admit_channel_join_on_duplex` gate — asserts the agent falls through the dead direct
      rung and completes the join (Admitted, learning the peer endpoint) over the `:443` TLS-TCP rung. Gate green,
      0 warnings.
    - **#106-client-dial-wire** ✅ **`run_channel_join_command` admits over the broker ladder** (`ct_agent`): the
      command now *uses* the `:443` fallback instead of only dialing QUIC directly. `run_channel_join` is split
      **additively** — its data path is extracted into `run_channel_join_with_admission(admission:
      ChannelJoinOutcome, relay_conn, …)`, and `run_channel_join(broker_conn, …)` becomes the thin wrapper
      (`present_channel_join(broker_conn)` → delegate), so the peer-attestation verify (#101) + direct-then-relay
      legs are unchanged and all existing QUIC integration tests keep passing untouched. The command captures the
      broker ladder, then admits over `present_channel_join_via_ladder` (direct QUIC → the `:443` TLS-TCP front
      door) whenever a front-door **cert** is configured, else the direct-QUIC `present_channel_join` — and feeds
      the resulting outcome to `run_channel_join_with_admission`. `ChannelJoinCliConfig` gains
      `front_door_cert: Option<CertificateDer>` from `CT_CHANNEL_FRONT_DOOR_CERT` (hex DER) — the trust anchor a
      front-door TLS dial needs, independent of `CT_CHANNEL_FRONT_DOOR` (absent ⇒ direct-only admission). Frozen
      test `run_channel_join_with_admission_runs_the_direct_session_from_a_443_ladder_admission`: a **dead** direct
      broker rung + a real `:443` TLS-TCP front door (`build_tcp_tls_listener_at` +
      `admit_channel_join_on_duplex`, acking the responder's attested-key triple) admit the join over `:443`, then
      the outcome drives the direct A2A session to a real responder and application data flows — proving broker
      admission is decoupled from and reachable over `:443` independently of the data legs. Gate green, 0 warnings.
    - **#106-relay-session-generic** ✅ **Transport-agnostic A2A session** (`ct_agent::channel_run`): the Noise_IK
      session was quinn-only (`BiStream` held `SendStream`/`RecvStream`; `run_channel_session` did `open_bi`/
      `accept_bi`). Made `BiStream<W, R>` generic and extracted `run_channel_session_on_stream<W, R, P>` — the
      handshake (`a2a_initiate`/`a2a_respond`, already generic) + `noise_pump` over any split write/read halves.
      `run_channel_session(conn, …)` is now the thin QUIC wrapper (`open_bi` → delegate). A `:443`/TLS-TCP relay
      stream runs the identical session by `tokio::io::split`ting it. Frozen test
      `run_channel_session_on_stream_forms_the_noise_tunnel_over_a_plain_duplex`: two members handshake over an
      in-memory duplex, then plaintext written to one member's local side arrives **decrypted** at the other's —
      the Noise tunnel forms over a non-quinn stream. Gate green, 0 warnings.
    - **#106-relay-leg-443** ✅ **The relay data leg walks the `:443` front-door ladder** (`ct_agent::channel_run`):
      the relay leg was hardcoded QUIC — a `:443`-only member whose relay port is also FILTERED could not reach the
      relay at all (the exact #103-sink blocker). Added `join_via_relay_ladder` — the relay-leg analog of
      `present_channel_join_via_ladder`: it walks `relay_ladder()`, falls through a blocked **direct** rung
      (`Unreachable`) to the `:443` **front-door** rung, presents the join over TLS-TCP **without** consuming the
      stream (new `present_channel_relay_join_on_stream` — no `shutdown`, reads exactly the 2-byte `OK`/`NO` ack so
      the spliced session's first frame isn't swallowed), and runs the Noise session over that **same**
      relay-spliced stream via `run_channel_session_on_stream`. `run_channel_join_with_admission`'s relay param
      changed from `&Connection` to a `RelayFallback<'_>` descriptor (`Quic` | `Ladder{rungs, edge_cert,
      direct_timeout}`) selected in one seam; every existing QUIC caller is wrapped `RelayFallback::Quic(..)` and is
      unchanged. `run_channel_join_command` passes `RelayFallback::Ladder` when a front-door cert is configured
      (else the eager QUIC relay dial, so nothing regresses). Frozen test
      `join_via_relay_ladder_falls_back_to_the_443_front_door_and_forms_the_noise_tunnel`: two members (Initiate +
      Accept) each walk `join_via_relay_ladder` with a DEAD direct rung + a LIVE `:443` front door driven by the
      **production** edge relay path (`admit_and_pair_on_stream` → `finish_relay_pair_over_streams`); a real payload
      round-trips **both** directions over the `:443` relay, Noise staying end-to-end. Gate green, 0 warnings; the
      frozen test + both concurrency tests ran 5×/5× non-flaky. This makes a truly `:443`-only member (broker AND
      relay ports blocked) fully functional. Remaining tail: **N4** — a local docker-compose A2A e2e ops artifact
      exercising the `:443` front door end-to-end (deployment/ops, not code).
  - **#106-edge-dispatch** — the pairing half; too big for one cycle, decomposed into:
    - **#106-dispatch-admit** ✅ **Transport-agnostic channel-join admission** (`ct_edge::channel_broker`):
      extracted `read_channel_join_on_stream<W: AsyncWrite, R: AsyncRead>` from `read_join_on_connection` — the
      framed `ChannelJoinRequest` read + membership/grant verify + single-use possession challenge now run over
      *any* duplex, not just a `quinn` bi-stream. `read_join_on_connection` is now a thin QUIC wrapper (bounds
      `accept_bi`, then delegates). This is the piece that lets a TLS-over-TCP `:443` stream be admitted
      identically to a QUIC stream — no QUIC assumption left in the admission path. Frozen test drives the full
      handshake (framed request → possession challenge → OK ack) over an in-memory `tokio::io::duplex` (the
      `:443`/TLS-TCP stand-in), asserting the same OK ack + advertised endpoint as the QUIC path. Gate green.
    - **#106-dispatch-transport** — the broker speaks QUIC; `:443` is TLS-TCP. Admitting *and* pairing over a
      non-quinn stream is too big for one cycle (the pair-completers are quinn-bound), so decomposed into:
      - **#106-dispatch-accept** ✅ **TLS-TCP accept leg** (`ct_edge::channel_broker::admit_channel_join_on_duplex`):
        takes an already-TLS-accepted `:443` stream (any `AsyncRead + AsyncWrite + Unpin` duplex — a
        `tokio_rustls` server stream), `tokio::io::split`s it and runs the identical
        `read_channel_join_on_stream` admission (length-framed `ChannelJoinRequest` + membership/grant verify
        + single-use possession challenge), returning the write half + admitted request/keys for the caller to
        pair. Proves a real TLS-over-TCP `:443` stream is admitted IDENTICALLY to a QUIC bi-stream. Frozen test
        stands up a genuine rustls TLS-over-TCP server+client over loopback (the `transport.rs` fallback helpers
        `build_tcp_tls_listener_at`/`tcp_tls_connect`) and drives the full handshake (framed request →
        possession challenge → OK) over it, asserting the same OK ack + advertised endpoint as the QUIC path.
        Gate green.
      - **#106-dispatch-complete** — drive the pairing over the admitted TLS-TCP stream. Was blocked on a seam:
        `AdmittedMember` + `finish_rendezvous_pair`/`finish_relay_pair` are quinn-specific (they hold a
        `quinn::Connection`; the relay splice runs `relay_initiator_to_acceptor` over quinn). Too big for one
        cycle — decomposed into (relay first, since a `:443`-only member which can't be dialed *needs* the relay,
        not rendezvous):
        - **#106-complete-relay-splice** ✅ **Transport-agnostic channel relay splice** (`ct_edge`): the relay
          completer generalised past quinn. New `relay::relay_streams<A,B: AsyncRead+AsyncWrite>(a, b, label)` —
          `tokio::io::split`s each generic duplex and reuses the same per-direction, per-chunk-flushed `relay_pair`
          core as `relay_quic` (a member admitted over a non-quinn transport carries its data on the *same* stream
          it joined on — no separate bi-stream to open/accept, so a symmetric split-and-pump is exactly right, no
          initiator/acceptor role dance). New `channel_broker::AdmittedStreamMember<S>` (stream + verified request +
          operator key, **no** `quinn::Connection`) and `finish_relay_pair_over_streams<A,B>` — authorize the pair,
          ack `OK` on each stream, splice via `relay_streams`; the Noise_IK tunnel flows end-to-end as ciphertext.
          Additive: the working quinn `finish_relay_pair` is left untouched (unifying the two call sites is deferred
          — see below). Two frozen tests: `relay_streams` over two in-memory duplexes (bytes both ways, reverse leg
          not starved by an idle forward leg, clean teardown, byte counts) and `finish_relay_pair_over_streams`
          over two plain `tokio::io::duplex` members (both `OK` acks + bidirectional splice + roles from grants —
          the same completion as the quinn `finish_relay_pair`, with no `quinn::Connection` anywhere). Gate green.
        - **#106-complete-rendezvous-generic** ⏳ next: the rendezvous sibling of the relay slice — a
          transport-generic rendezvous finisher (endpoint-swap + attested-key `member_ack_suffix` over a plain
          duplex write half, no `quinn::Connection`), so a `:443` member that *can* be reached can also be
          rendezvous-paired. Optional-after-relay for the `:443`-only sink but needed for symmetry.
        - **#106-complete-wire443** ✅ (reunite): the admitted **read half** is no longer trapped —
          `read_channel_join_on_stream` now returns *both* halves (write, read), and `admit_channel_join_on_duplex`
          reunites them via `ReadHalf::unsplit` and returns the **whole full-duplex stream** (was: only the write
          half). So an admitted `:443`/TLS-TCP stream is ready to hand straight to `finish_relay_pair_over_streams`.
          The quinn wrapper `read_join_on_connection` drops the returned read half (quinn pairs over the
          `Connection`, not the join stream — behaviour unchanged). Frozen: the real TLS-TCP admission test now also
          reads a post-admission app byte off the reunited stream (proving the read half survived), and the
          plain-duplex admission test updated for the new arity. Gate green, 0 warnings.
          - **#106-complete-wire443-e2e** ✅: the capstone — a frozen end-to-end test admits **two** real
            TLS-over-TCP members via `admit_channel_join_on_duplex` (a source + a `:443`-only sink, neither
            dialable) and relay-splices them with `finish_relay_pair_over_streams`, then pushes one app byte each
            way and asserts both cross (the edge spliced the two admitted duplexes) + roles come from the grants.
            Proves the full `:443` source↔sink relay data path end-to-end (no quinn), with only the front-door
            ALPN routing left. Test-only (all production pieces landed in the prior slices). Gate green, 0 warnings.
          - **#106-dispatch-frontdoor** — the last mile; decomposed (front-door signature/plumbing is too big for
            one cycle alongside the pairing core):
            - **#106-frontdoor-handler** ✅: `admit_and_pair_on_stream(stream, …, pairer)` — the transport-generic
              front-door core. Because `:443` members arrive **independently** (can't be dialed, so the front door
              can't pair "the next two arrivals"), it admits the stream (`admit_channel_join_on_duplex`) and offers
              it to a shared `ChannelPairer` keyed by `ChannelId`: first holder → `Ok(None)` (parked), second → 
              `Ok(Some((a, b)))` (the caller relay-splices those two, typically on its own task). Same-holder retry
              supersedes + closes the stale stream. Lock held only for the synchronous `offer`, never across await.
              Frozen test parks-then-pairs two members over in-memory duplexes, relay-splices the returned pair, and
              asserts the bytes cross + the pairer drains. Gate green, 0 warnings.
            - **#106-frontdoor-wire** ✅ **`:443` channel ALPN → admit+pair+relay broker** (`ct_edge::serve`):
              `serve_front_door`'s `ChannelBroker` arm (was an error stub) now takes an optional
              `channel: Option<&ChannelFrontDoor>` context (additive — every non-channel caller/test passes `None`,
              so no behaviour change off the channel path). `ChannelFrontDoor` bundles a **long-lived shared**
              `Arc<Mutex<ChannelPairer<AdmittedStreamMember<FrontDoorChannelStream>>>>` (so the two
              independently-arriving `:443` members of a channel correlate by `ChannelId`) + a boxed
              `ChannelMemberResolver` membership seam. On a channel-ALPN connection the arm TLS-terminates with the
              edge leaf (same `Prepend`-replay pattern as the `EdgeRelay` leg), computes `now`, builds the same
              `authorize` closure shape the QUIC broker uses (routed through the resolver), calls
              `admit_and_pair_on_stream(tls, now, JOIN_TIMEOUT, &authorize, now+PARK_TTL, &ctx.pairer)`, and on a
              pair `tokio::spawn`s `finish_relay_pair_over_streams`. `run_edge`'s `CT_FRONT_DOOR` block builds the
              context ONCE outside the accept loop when `CT_EDGE_CP_URL` + `CT_EDGE_ADMIN_TOKEN` are both set (a
              CP-backed `ChannelAuthorizer` — the same opt-in style the QUIC broker uses; logs one activation line),
              else passes `None`. The `ChannelMemberResolver` trait object keeps `serve_front_door` non-generic and
              lets a test inject a mock (no HTTP CP stood up). Frozen front-door-level e2e:
              `front_door_wires_channel_alpn_to_the_admit_pair_relay_broker` drives **two** members over REAL
              TLS-over-TCP carrying ALPN `ct-edge-channel` (a test client that sets
              `ClientConfig.alpn_protocols`) through the WIRED `serve_front_door` with a `Some(ctx)` built from a
              mock resolver + shared pairer — first parks, second pairs + spawns the relay — and asserts an app byte
              crosses both ways (the two `:443` members were paired by `ChannelId` and relay-spliced through the
              front door) + roles from grants. Gate green, 0 warnings.
              - **Known limitation**: this front-door pairer is `:443`-to-`:443` only (two `:443`/TLS-TCP members
                pair with each other via `finish_relay_pair_over_streams`); cross-transport QUIC↔`:443` pairing (a
                `:443` sink paired with a QUIC member on the QUIC broker's pairer) is a separate future concern — the
                two brokers hold independent pairers today. Also: nothing calls `drain_expired` on the front-door
                pairer yet, so a lone parked member's stream lives until it drops (a reaper is out of scope here).
            - **#118** ✅ **`:443` channel leg genuinely negotiates the `ct-edge-channel` ALPN** (`ct_edge`): the
              `ChannelBroker` arm routed correctly (ClientHello ALPN peek) but TLS-terminated with the **shared**
              edge acceptor (empty `alpn_protocols`), so it never echoed the ALPN — a readiness probe checking
              `alpn_protocol()` post-handshake saw `None` (a false-negative that confused the source/sink testers).
              Fix: a **dedicated** channel acceptor `pki::build_channel_front_door_acceptor(ca, sans)` (a fresh
              CA-signed leaf whose `ServerConfig.alpn_protocols = [ct-edge-channel]`), carried in
              `ChannelFrontDoor` (`new(resolver, acceptor)`) and used ONLY by the `ChannelBroker` arm
              (`ctx.acceptor.accept(joined)`). The shared acceptor keeps its empty ALPN — advertising the channel
              ALPN there would make rustls fatal-alert (`no_application_protocol`) the `EdgeRelay` leg's `ct-edge`
              clients (no ALPN overlap). Frozen test (the reworked
              `front_door_wires_channel_alpn_to_the_admit_pair_relay_broker`): a single `pki::Ca` derives both the
              client's trusted root and the channel acceptor, and after the handshake asserts
              `alpn_protocol() == Some(b"ct-edge-channel")` — plus the existing admit→pair→relay byte-crossing.
              Gate green, 0 warnings.
            - **#119** ✅ (security-review) **`:443` front door now honours the #95 connection cap**: the front-door
              TCP accept loop spawned a task per connection with **no** `ConnectionCap` — the `#95` cap was cloned to
              the QUIC and TCP-fallback loops but never to the most-exposed public port, so an unauthenticated
              `:443` connection flood could exhaust tasks/FDs (each parking at the un-timed TLS handshake) before any
              PoW/grant/membership gate. Fix: the loop now `conn_cap.try_admit()`s a permit and **sheds over the
              cap** (drops the socket), holding the permit for the connection's lifetime — mirroring the QUIC/
              TCP-fallback loops exactly. Added the missing `ConnectionCap` unit test
              (`connection_cap_admits_up_to_max_then_sheds_and_recovers_on_release`: admit up to max → shed → free a
              slot on release → re-admit) since the primitive had none. Gate green, 0 warnings.
            - then **N4** ⏳ — local docker-compose A2A e2e over a real `:443` front door (the connection-difficulty proof).
    - **#106-dispatch-frontdoor** ⏳: wire `serve_front_door`'s `ChannelBroker` arm to hand the buffered
      ClientHello + stream to the TLS-TCP accept leg, and route the channel ALPN on `:443` in the deploy. This is
      what lets a `:443`-only host (the #103 sink) reach the broker/relay end-to-end.

## #107 Topology Editor — per-user overlay composition from agents (feature, epic)

Per-user editor to wire agents (own or shared-in) into an overlay topology, with an exclusivity rule, a
best-connectivity computation, a per-topology `<net-uuid>` live-status subdomain, and a click-together UI. A
big epic with **open design questions** (see the issue) that gate several parts. Decomposed so the one piece
with **no prior art** and **no dependency on those open questions** lands first:

- **#107-exclusivity** ✅ **Exclusive agent-to-topology assignment state machine** (`control-plane::topology`,
  pure): the "genuinely new constraint" the issue flags — *an agent belongs to at most one topology; sharing
  can only be revoked, not reassigned*. `AgentAssignment { owner, topology: Option<_> }` with
  `assign(by, topology)` (owner-only; `AlreadyAssigned` if already in a topology — exclusivity) and
  `revoke(by)` (the owner **or** the current topology may end it; returns to unassigned/owner control).
  Separate from storage, like `accounts::Ledger` ↔ `storage::SqliteLedger` (the durable `SqliteTopologyStore`
  is a follow packet). Wire-serializable for the REST surface. Frozen tests: fresh=owned+unassigned;
  owner-only assign + exclusivity block; revoke returns to owner then owner can reassign; revoke-unassigned
  errors; serde round-trip. Gate green.
  - **Chosen interpretation** of the issue's revocation open-question: revoking returns control to the
    **original owner** (reassignable only by them), *not* free-for-all — the safe default; flagged for scimbe.
- **#107-datamodel** ✅ (membership core) **Durable exclusive assignment** (`storage::SqliteTopologyStore`):
  the durable equivalent of the `AgentAssignment` state machine, so the exclusivity constraint holds **across
  restarts**. One row per agent (`agent PK, owner, topology?`); `assign(by, agent, topology)` (first touch
  registers `by` as owner; owner-only + exclusivity enforced by the pure state machine), `revoke(by, agent)`
  (owner-reclaim or topology-release), `assignment(agent)`, `agents_in(topology)`. `TopologyError` wraps
  `AssignError`/DB. Frozen test `topology_store_enforces_exclusivity_across_a_restart` (assign; AlreadyAssigned
  blocks a second topology; a non-owner can neither reassign nor revoke; **reopen on the same file → state
  persisted, still exclusive**; revoke→owner control→reassign; revoke-unassigned errors). Gate green.
  - **#107-topology-entity** ✅ **The `Topology` container** (`topology::Topology` + `SqliteTopologyStore`): a
    named overlay owned by a subject, keyed by a unique `net_uuid` (its live-status subdomain).
    `create_topology(owner, id, net_uuid)` (no-op `false` on a duplicate id **or** net_uuid — both stay
    unique), `topology(id)`, `topology_by_uuid(net_uuid)` (the `<net_uuid>.<zone>` resolver),
    `list_topologies(owner)`, `delete_topology(owner, id)` (owner-scoped). Frozen test
    `topology_entity_has_unique_id_and_net_uuid_and_is_owner_scoped`. Gate green.
  - **#107-edge-list** ✅ **The who-connects-to-whom wiring** (`SqliteTopologyStore`): `add_edge`/`remove_edge`/
    `edges(topology)` over undirected, canonical (`a—b` == `b—a`) edges. Owner-scoped (only the topology owner
    may edit its wiring), idempotent, self-loops rejected. `edges` returns the sorted adjacency the optimizer /
    renderer consume. Frozen test `topology_edge_list_is_undirected_owner_scoped_and_deduped` (canonical store;
    dup/self-loop/non-owner no-ops; sorted adjacency; canonical owner-scoped removal). Gate green. **The #107
    durable datamodel is now complete** (exclusive assignment + Topology entity + edge-list). Next: the
    `/me/topologies*` REST surface (create/list/assign/wire), then the `<net_uuid>.<zone>` live page (reuse #38
    DL2 DNS + authorize-host).
- **#107-rest** ✅ **The Topology Editor REST surface** (`service::authed_topology_router`, `/me/topologies*`):
  the compose flow — `POST /me/topologies` (create; server-generated `id` + `net_uuid` → `{id, net_uuid}`),
  `GET /me/topologies` (list), `GET /me/topologies/:id` (composite `{id, net_uuid, agents, edges}`),
  `POST /me/topologies/:id/agents {agent}` (assign; `409` on the exclusivity conflict), `POST
  /me/topologies/:id/edges {a,b}` (wire an undirected edge). Owner = verified subject (`subject_of`), never a
  request field; a topology another subject doesn't own is `404` (isolation, not `403`). Mounted in the
  `oidc`-gated block. Frozen test `authed_topology_editor_composes_an_overlay_and_is_owner_scoped` (no
  bearer→401; create → assign two agents → an exclusive re-assign 409 → wire an edge → the composite view shows
  agents + the canonical edge; mallory can neither see nor edit alice's topology, and her listing is empty).
  Gate green. **The Topology Editor is now usable at the API level** (create + compose + read). Follow: the
  `<net_uuid>.<zone>` live page (reuse #38 DL2), and the design-question-gated optimizer / N-way / UI slices.
- **#107-subdomain** ✅ (page + resolver) **The public live-status page** (`service::topology_status_router`,
  `GET /net/:net_uuid`): resolves a topology by its `net_uuid` (`topology_by_uuid`) and renders a
  self-contained (CSP-safe, no external assets) HTML view of the overlay — net-uuid, member agents, and links.
  **UUID-only access** (unauthenticated, per the issue's "for now unauthenticated-by-UUID"); an owner auth-gate
  is a tracked follow. Mounted **publicly** in `persistent_control_plane_router` (the store is opened once and
  shared with the authed `/me/topologies*` editor). Frozen test
  `topology_status_page_is_public_and_resolves_by_net_uuid` (known uuid → 200 HTML listing the agents + the
  link, no bearer; unknown → 404). Gate green. **Follow:** the actual `<net_uuid>.<zone>` **subdomain** routing
  (Host-header → this page) + auto DNS, reusing the Browser-Plane / #38 DL2 pipeline — deploy wiring on top of
  this path-addressed page.
- **#107-diagram** ✅ **The live node-graph diagram** (`service::render_topology_svg`): the status page now
  renders a self-contained inline **SVG** — agents laid out on a circle as labelled nodes, edges as lines
  between them (a single node centred; an empty topology → an empty canvas). Pure, no external assets; an edge
  to a non-member is dropped (never a dangling line / panic). Directly satisfies the issue's "live **diagram**
  + current status" for the subdomain page. Frozen test
  `topology_svg_diagram_has_a_node_per_agent_and_a_line_per_edge` (one `<circle>` per agent, one `<line>` per
  edge, labels present; dangling edge dropped; empty canvas). Gate green.
- **Design answers (scimbe 2026-07-19):** objective = **latency**, scale = **arbitrary N**, "SDN" = **both /
  phased** (graph-wiring first, flow-rules later). See [[project_scimbe_decisions_2026-07-19]].
- **#107-optimize** ✅ (backbone) **Minimum-latency overlay** (`ct_common::overlay::min_latency_overlay`): the
  "best-connectivity" computation, now unblocked. Given the agents + policy-allowed candidate links (each with a
  measured latency `cost`), it computes a **minimum spanning tree** (Kruskal + union-find) — a connected overlay
  of `N-1` links with **minimal total latency**, for **arbitrary N** (a real graph algorithm per the scale
  answer), deterministic (ties broken by the canonical node pair). Ignores self-loops / unknown-node links; a
  partitioned candidate set yields the spanning **forest** with `connected=false`; a 0/1-node network is
  connected with no links. This is the graph-wiring phase's connectivity backbone; latency-reducing **shortcuts**
  (stretch, cf. #76) and later real flow-rules build on it. Frozen tests: MST minimizes total latency + connects
  all; partition→not-connected; tie/canonical/bad-link handling; trivial networks; serde round-trip. Gate green.
- **#107-nway** ⏳ (now unblocked — scale=arbitrary N, phase=graph-wiring): generalize `authorize_channel_pair`
  + the broker's fixed two-connection loop so a topology's MST links (from `min_latency_overlay`) each form an
  A2A channel — the controller compiles the plan into per-link grants. Needs the live mesh (#99/#103) for e2e.
  - **#107-nway-channelid** ✅ **Deterministic per-link `ChannelId` derivation** (`ct_common::channel::channel_id_for_link`, pure): the foundational primitive — each overlay link `(holder_a, holder_b)` under an operator maps to a channel **both endpoints derive locally with no round-trip**. Domain-separated SHA-256 over `ct-link-channel-v1 ‖ operator_pubkey ‖ min(a,b) ‖ max(a,b)`: **canonical** (order-independent, so both members compute the same id), **operator-bound** (cross-operator isolation — two operators can't collide onto one channel for the same pair), and **collision-resistant** (distinct pairs → distinct channels). It is a channel *address* only — membership still flows from the operator-signed grant the controller mints for this channel. Frozen test `link_channel_id_is_canonical_operator_bound_and_collision_resistant`. Gate green.
  - **#107-nway-compile** ✅ **Plan → per-link grant-pair compilation** (`OperatorIdentity::compile_overlay_grants`, `ct-agent::channel_run`): the controller turns an `OverlayPlan`'s links into concrete A2A channels. Each link (a canonical node-id pair) becomes a `CompiledLink { channel, initiator_holder, acceptor_holder, initiator_grant, acceptor_grant }`: the channel is `channel_id_for_link` and the two grants are minted **locally** with the operator key (invariant #6 — no central round-trip; central only distributes) via the extracted `sign_member_grant`, splitting Initiate/Accept by the canonically-smaller node id (stable, like `authorize_channel_pair`). `holder_of` maps a node id → member holder pubkey; an unmapped id fails the whole compile with that id (no partially-wired overlay). Frozen test `operator_compiles_an_overlay_plan_into_verifiable_per_link_grants` (both grants of a link verify under the operator key, bind distinct holders + the same derived channel, split roles; distinct links are distinct channels; unmapped node → `Err(id)`). Gate green. **Remaining #107-nway:** the broker's **N-link establishment** — bring each `CompiledLink` up as a live A2A channel — needs the live mesh (#99/#103) for e2e.
- **#107-shortcuts** ✅ **Latency-reducing shortcut edges** (`ct_common::overlay::add_shortcuts`): extends the
  MST backbone with up to `budget` shortcut links (the #76 smart-shortcuts topology). Greedy + deterministic —
  each round adds the unchosen candidate that most reduces the overlay's **worst pairwise path latency** (the
  two agents currently farthest apart get a direct link, via Floyd–Warshall over the chosen edges), until the
  budget is spent or no candidate shortens any path; ties broken by the canonical pair. The tree keeps it
  connected, so shortcuts only ever *reduce* latency. Frozen tests: a line's `a↔d` shortcut is added within
  budget (path 3 → direct 2), budget 0 is a no-op, a huge budget stops once nothing improves, and no-improving-
  candidate → unchanged. Gate green. **The #107 optimizer is now a two-phase pipeline: MST backbone → greedy
  shortcuts**, both pure/deterministic for arbitrary N.
- **#107-plan** ✅ **Policy→overlay controller compile** (`ct_common::overlay::plan_network_overlay`): ties #102
  and #107 — compiles a `Network` (agents + policy) + measured per-link latencies into the concrete overlay to
  wire. Candidates are exactly the **policy-permitted** pairs (`Network::desired_channels`) weighted by
  `latency(a,b)` (a pair with no measurement is dropped), then the two-phase optimizer (MST + shortcuts). So the
  plan is **policy-conformant by construction** — a forbidden pair is never a candidate. Pure given the latency
  fn. Frozen test `plan_network_overlay_wires_only_policy_permitted_links_by_latency` (dev/ops MST by latency; a
  policy-isolated finance agent leaves the overlay `connected=false` and never appears in a link; a shortcut
  budget never regresses). Gate green. **This is the controller's core deliverable** — "given a declared
  network + measured latencies, here are the exact A2A channels to establish."
- **#107-optimize-follow** ⏳: edge latency probes feed `plan_network_overlay`'s `latency`; then the controller
  mints a per-link channel grant for each planned link (grant signing is operator/client-side) and the broker
  generalizes past two-connection (#107-nway) — the live-mesh e2e.
  **REQUIRED precondition (#113, preventive):** before `add_shortcuts`/`plan_network_overlay` is wired into ANY
  live handler, this slice MUST cap the topology size `n` and the shortcut `budget` — `add_shortcuts` runs
  Floyd–Warshall O(n³) per round, so cost is O(budget·n³). The primitive is inert today (no caller outside
  `overlay.rs` tests) and panic-safe (saturating arithmetic), so the bound is a *product topology-size policy*
  decided here at the wiring point (with the request-auth context), not an arbitrary constant retrofitted into
  the pure library fn. Reject or gracefully degrade oversized topologies at the handler before invoking the optimizer. **#113 precondition ✅ (the size-cap mechanism landed):** `ct_common::overlay::plan_network_overlay_bounded(network, latency, budget, max_agents, max_shortcut_budget) -> Result<OverlayPlan, TopologyTooLarge>` is the **size-checked entry point** a live handler MUST call instead of the raw optimizer — it rejects a topology whose agent count or shortcut budget exceeds the caller-supplied (inclusive) limits **before** any O(budget·n³) work, so an oversized request can't wedge the control plane. Limits are parameters (the handler decides them as a product policy in its request-auth context — not hardcoded). Frozen test `plan_network_overlay_bounded_rejects_oversized_topologies_before_optimizing`. Gate green. *(The remaining #107-optimize-follow work — feeding live edge-latency probes + the broker N-link establishment — is the live-mesh e2e, now unblocked by Milestone A.)* **#107-ui** ⏳ **(design-gated)**: greenfield
  node-graph editor — awaiting the framework-vs-vanilla call. **#107-testing** ⏳: unit/API (done for the pure
  layers) + a real N-agent formation smoke once the mesh is live.

## #121 NAT-only members can't join — no address satisfies both `safe_endpoint` and a bindable listener (report)

After #106 landed, a `:443`-only Accept/sink member still can't join: `channel_run.rs` bound a **direct
listener** at `CT_CHANNEL_LISTEN` and advertised that same value to the broker, but the broker's `safe_endpoint`
(#94) rejects every private/loopback/CGNAT/link-local range. A NAT-only host has no address that is both
bindable locally **and** a global-unicast address the broker will accept → `EADDRNOTAVAIL`. The edge relay
already splices two non-dialable members (proven in #118); only the production **client** lacked a relay-only
mode. The reporter offered three options: (1) an explicit relay-only sentinel, (2) skip the listener when
relay-only, (3) relax `safe_endpoint`. **Decision: 1+2 hybrid, explicitly NOT 3** — `safe_endpoint` stays
intact (a member can't smuggle a LAN SSRF target), and a NAT-only member advertises a reserved non-address
sentinel + skips its listener.

**Phase A — reachability floor (relay-only member mode) ✅** landed this cycle. Frozen e2e
`two_relay_only_members_join_without_a_dialable_address_and_relay_splice` (in ct-agent): TWO relay-only members
— both advertising the sentinel, both with `listener == None` — join and are relay-spliced by the **production**
edge relay path (`broker_channel_relay`), and a real payload round-trips **both** directions with Noise staying
end-to-end. What Phase A is:

- **ct-common** `pub const CHANNEL_ENDPOINT_RELAY_ONLY = "relay-only"` + `ChannelJoinRequest::is_relay_only()`:
  one shared definition of the reserved non-dialable sentinel (a value `safe_endpoint` never parses as a
  `SocketAddr`, so it can't collide with a real endpoint). Frozen
  `relay_only_sentinel_is_recognized_and_is_not_a_socket_addr`.
- **ct-edge** admission accepts the sentinel **without weakening `safe_endpoint`**: the endpoint guard becomes
  `is_relay_only() || safe_endpoint(..).is_some()` (helper `admissible_endpoint`). A real `10.x`/`127.0.0.1`/
  `192.168.x` is STILL refused. Frozen
  `admission_accepts_the_relay_only_sentinel_but_still_refuses_private_addresses`; existing
  `edge_refuses_an_unsafe_endpoint` still passes.
- **ct-agent** relay-only mode: `CT_CHANNEL_RELAY_ONLY=1` forces it on, PLUS auto-detect when the advertised
  `CT_CHANNEL_LISTEN` is not globally routable (pure helper `relay_only_mode(explicit, listen_addr)`, frozen
  `relay_only_mode_forces_on_explicitly_and_auto_detects_a_non_routable_listen_addr`). A relay-only member skips
  binding the direct listener (`listener == None`) and advertises the sentinel. In
  `run_channel_join_with_admission`: an **initiator** paired with a sentinel peer_endpoint skips
  `dial_peer_direct` and goes straight to the relay fallback; an **acceptor** with no listener does the same.
  Net: a NAT-only member (source or sink) participates purely via relay + the #106 `:443` fallback (outbound-only).

**Phase B — direct P2P across NAT (hole-punching; the #104 mechanism) ⏳ — decomposed, not built.** Sequenced
after Phase A (a hole-punch needs a joined member + the relay as its symmetric-NAT fallback). This is the #104
opportunistic relay→direct **upgrade** (start relayed per Phase A, upgrade when NAT type allows). Follow-on
slices:

- **#121-reflexive-observe (Phase B1) ✅** landed this cycle — the AutoNAT primitive + reachability classifier.
  The edge observes each member's **post-NAT reflexive** source `ip:port` on its ALREADY-AUTHENTICATED channel
  connection (edge-OBSERVED, NOT self-reported — no separate STUN server, no new trust: the member is already
  grant-authenticated), reports it back in the OK ack, and the joining member learns it. What B1 is:
  - **ct-edge observation at the accept seam**: `read_join_on_connection` captures `conn.remote_address()` (the
    same primitive the classic tunnel uses in `serve.rs`); the `:443`/duplex path `admit_channel_join_on_duplex`
    takes an added `observed: SocketAddr` param its front-door caller (`serve_front_door`) fills from the accepted
    `TcpStream`'s `peer_addr()`. Both thread it through the transport-agnostic core `read_channel_join_on_stream`
    (which takes `observed` in — it never calls `remote_address()` itself) and echo it as the last returned tuple
    element. `serve_front_door` now captures `inbound.peer_addr()` before the socket is consumed.
  - **report-in-ack (backward-additive wire)**: `ChannelJoinOutcome::Admitted` gains `observed_reflexive:
    Option<SocketAddr>`; the OK ack carries it as a **tagged `r=<addr>` token** the client pulls out first
    (self-addressed, order-independent, absent on older acks → `None`; the relay leg's bare 2-byte `OK` carries
    none — a relay-only member is `RelayOnly` and has no punchable reflexive). Frozen e2e (ct-agent), proving BOTH
    transports carry it: `member_learns_its_edge_observed_reflexive_over_quic` and
    `member_learns_its_edge_observed_reflexive_over_tls_tcp_443` — each asserts the learned reflexive equals what
    the edge observed AND (QUIC) the loopback source the client actually connected from.
  - **pure reachability classifier (ct-common)**: `reachability_class(advertised: &str, reflexive: SocketAddr) ->
    Reachability { Public | Nat { reflexive } | RelayOnly }`, plus a shared `is_global_unicast(SocketAddr) -> bool`
    that `ct_edge::safe_endpoint` is now defined in terms of (behaviour-preserving — the frozen
    `safe_endpoint_rejects_private_and_internal_ranges` still passes; the SSRF filter and the classifier now agree
    by construction). Frozen `reachability_class_maps_advertised_and_reflexive_to_a_class` (the 5-case matrix) and
    `is_global_unicast_matches_the_edge_ssrf_filter_ranges`.
  - **Deferred to a trivial B1-follow slice** (not built here): wiring the `r=<addr>` token into the **live**
    pair-completion acks (`finish_rendezvous_pair`/`finish_relay_pair`/`resolve_channel_join`) so a member learns
    its reflexive during production rendezvous/relay pairing — the observed address is captured + returned at the
    admission seam and the client-side parse is done, so this is just emitting the token in the finisher acks (the
    relay 2-byte-ack path needs the open ADR wire decision). B1 proves the full observe→report→learn round trip
    end-to-end at the admission seam today.
- **#121-punch-signal (Phase B2) ⏳**: broker punch-coordination signalling — relay the peer's reflexive address +
  a synchronized instant to both members (the hole-punch/DCUtR; punches toward the B1 reflexive).
- **#121-simultaneous-open (Phase B2) ⏳**: client simultaneous-open at the agreed instant.
- **#121-symmetric-fallback (Phase B2) ⏳**: symmetric-NAT (`RelayOnly`, no consistent reflexive mapping) stays on
  the relay; this is the #104 upgrade **trigger** — promote to direct only when `reachability_class` allows.
- **Phase C (superpeer election) / D (DHT) / E (fail-static) ⏳**: later, classify on the B1 `Reachability`.

### Phase B2→E under the libp2p decision (2026-07-19, maintainer-approved)

**Decision:** adopt **libp2p** as the connectivity substrate (DHT routing, DCUtR hole-punch, Circuit-Relay v2) — chosen over a home-grown Kademlia. **Consequence:** the home-grown B2 stubs above (`#121-punch-signal` / `-simultaneous-open`) are **superseded** — the hole-punch is libp2p **DCUtR**, Phase C relay is libp2p **Circuit-Relay v2**, Phase D discovery is libp2p **Kademlia**. `#121-symmetric-fallback` stays (it's the #104 upgrade trigger, transport-agnostic). B1's reflexive-observe + `Reachability` remain the AutoNAT input regardless.

**Governing principle:** the central (bunsenbrenner.org) is a **replaceable coordinator + policy authority + bootstrap seed**, never in the data path; absence degrades **fail-static** (existing channels + last overlay keep running), never fail-closed.

**Normative security invariants (validated 2026-07-19; must hold across all libp2p integration — libp2p is untrusted plumbing, our security lives above it):**
1. **Authorization = operator-signed grant + #101 attestation, NEVER the libp2p PeerId.** A libp2p connection implies nothing about channel membership.
2. **E2E confidentiality/integrity = our channel-attested `Noise_IK` running INSIDE the libp2p stream** (accept libp2p-Noise-outer + our-Noise_IK-inner as defense-in-depth; do NOT fuse the channel key into the libp2p handshake).
3. **A superpeer relays ONLY channels it is a grant-member of** (metadata containment — it learns nothing beyond membership it already holds). Enforced as a membership gate on the Circuit-Relay path (the circuit carries the `ChannelId`; forward only after the requester's grant proves co-membership).
4. **DHT coordinate records are holder-signed** → poisoning defeated for authenticity (residual: availability/eclipse, mitigated by central-as-bootstrap).
5. **Punch targets are edge-observed reflexive addresses (B1 ✅), never self-reported** → no punch redirection / SSRF.
6. **Grants signed by the operator key held locally (#117), never on the central** → central compromise = DoS/metadata only, not impersonation.
7. **Revocation latency = membership-staple TTL** (fail-static trade; operator-tunable). Proposed default: **1h staple / 15m gossip refresh** — pending maintainer confirmation.

Residual risks are all **availability or metadata (none break confidentiality/integrity)**: metadata to in-channel superpeers (bounded by #3), availability under DHT eclipse/Sybil (bounded by central bootstrap + operator-designated superpeer eligibility), revocation latency (bounded by #7). Supply-chain note: libp2p enlarges the security-relevant dependency surface (its Noise/Kademlia/relay stack) — invariants #1–#2 keep our security above it, but the threat model must name this.

**Bounded libp2p integration packets (decomposed; sequenced):**
- **B2-libp2p-seam ✅ (first slice; maintainer confirmed pulling libp2p, decision 2026-07-19):** added `libp2p 0.56.0` (features `tokio, noise, yamux`) + `libp2p-stream 0.4.0-alpha` (the raw-substream `stream::Behaviour`) and `tokio-util 0.7` (`compat`, to bridge libp2p's `futures` async-IO to Tokio's). New `ct-agent::p2p` module (`connected_memory_stream_pair`) stands up two in-process peers over `MemoryTransport` (upgraded noise+yamux), opens a raw substream, and hands each side an `AsyncRead + AsyncWrite + Unpin` duplex; our existing transport-agnostic `run_channel_session_on_stream` runs the `Noise_IK` session *inside* it. Frozen test **`channel_noise_session_runs_over_a_libp2p_memory_stream`** proves invariant #2 (the Noise tunnel forms over the libp2p stream — payload round-trips both directions) and invariant #1 (admission is purely the members' channel-attested Noise keys; the libp2p `PeerId` is untrusted plumbing, never an authorization input). No network, no DHT.
- **B2-libp2p-tcp ✅ (real-transport slice):** enabled the libp2p **`tcp`** feature (no `dns` — we dial raw `/ip4/.../tcp/...` addresses) and added `connected_tcp_stream_pair` to `ct-agent::p2p`: the listener binds `127.0.0.1:0`, reports its OS-assigned listen `Multiaddr` (with the peer id) via `NewListenAddr`, and the dialer **dials that multiaddr**, opens a raw substream — each side an `AsyncRead + AsyncWrite + Unpin` duplex, over **real loopback TCP** instead of `MemoryTransport`. Frozen test **`channel_noise_session_runs_over_a_libp2p_tcp_stream`** re-proves invariants #1–2 over real sockets (dial-by-multiaddr; a payload round-trips both directions inside the `Noise_IK` tunnel; admission is purely the members' channel-attested Noise keys, never the libp2p `PeerId`). This real network address is the prerequisite for the DCUtR/Relay slices below.
- **B2-dcutr ✅ (integration slice; cross-NAT PROOF is a live test):** enabled the libp2p **`dcutr`** feature and extended the relay-client behaviour to carry `dcutr::Behaviour` (constructed with the local peer id) alongside the Circuit-Relay v2 client + `stream::Behaviour` — new `DcutrRelayClientBehaviour` + `build_dcutr_relay_client_swarm`. Added `connected_dcutr_stream_pair` to `ct-agent::p2p`: same relay + two clients shape as `connected_relayed_stream_pair`, but both clients are DCUtR-enabled, so once the relayed connection forms the peers may attempt a **direct** connection upgrade (the hole-punch); the relay is then only needed for setup. Frozen test **`channel_noise_session_runs_with_dcutr_enabled_over_the_relay`** proves that **enabling DCUtR does not break the relayed `Noise_IK` session** — the machinery is wired end to end (invariants #1–2 hold: a payload round-trips both directions inside the tunnel; admission is purely the members' channel-attested Noise keys, never any libp2p/DCUtR `PeerId`). The whole path is bounded by a `tokio::time::timeout` so a DCUtR stall fails fast, never hangs the gate. **The event is NOT asserted:** on loopback both peers are already directly reachable (no NAT, no identify-observed addresses), so whether/when DCUtR fires is timing-dependent — asserting it would be flaky. **⚠️ The actual *cross-NAT* hole-punch PROOF — DCUtR's real value — needs real NAT'd hosts and cannot run on loopback; it is a LIVE test (analog of Milestone A's FD5/#103 live smokes), not the cargo gate.** Symmetric-NAT → relay stays the #104 trigger.
- **C-circuit-relay-transport ✅ (relay mechanism slice):** enabled the libp2p **`relay`** feature (Circuit-Relay v2 server behaviour + client transport) and **`macros`** (the `#[derive(NetworkBehaviour)]` composing relay-client + `stream::Behaviour` on a client swarm). Added `connected_relayed_stream_pair` to `ct-agent::p2p`: three in-process nodes over TCP loopback — a **relay** node (`relay::Behaviour`, `relay::Config::default()`), and clients **A** and **B** (each `SwarmBuilder::with_relay_client(noise, yamux)` + `stream::Behaviour`). A makes a **reservation** (`listen_on(<relay>/p2p-circuit)`, awaits `relay::client::Event::ReservationReqAccepted`) and listens on its relayed address; B **dials A through the relay** (`<relay>/p2p-circuit/p2p/<A-peerid>`), and once the relayed connection to A is `ConnectionEstablished` opens a `/ct/channel/1.0.0` substream — each side an `AsyncRead + AsyncWrite + Unpin` duplex. Frozen test **`channel_noise_session_runs_over_a_libp2p_circuit_relay`** re-proves invariants #1–2 through a relay (a payload round-trips both directions inside the `Noise_IK` tunnel; admission is purely the members' channel-attested Noise keys, never the libp2p `PeerId`). This relayed path is the prerequisite for **B2-dcutr** (DCUtR upgrades a relayed connection to direct). **⚠️ GUARDRAIL: the relay in this slice is UNGUARDED (it relays any circuit) and is therefore TEST-ONLY, in-process. It MUST NOT be wired to a live/public relay node before the invariant-#3 membership gate (`C-membership-gate`) lands.**
- **C-membership-gate ✅ (invariant-#3 authorization core; live-relay wiring is the follow-on):** added `authorize_relay_circuit` + `RelayCircuitError` to `ct-agent::p2p` — the admission predicate a superpeer applies before forwarding a Circuit-Relay circuit. It enforces, purely from the operator-signed grants (never the libp2p `PeerId`, invariant #1): (1) the **relay's own** grant verifies against the operator key and (2) is **for this circuit's channel** — invariant #3's containment, a superpeer relays ONLY channels it is itself a grant-member of; (3) the **requester's** grant verifies and (4) is for the same channel (co-membership). The exact analog of the broker's `authorize_channel_pair`, applied to relay *use*. Frozen test **`relay_circuit_authz_enforces_invariant_3_membership_containment`** proves the happy path (A-member relay admits an A-co-member) and every refusal: relay holds only a channel-B grant (`RelayNotMember`), requester holds only a channel-B grant (`RequesterChannelMismatch`), forged relay/requester grant (foreign operator → `…GrantInvalid(BadSignature)`), and an expired relay grant (`…GrantInvalid(Expired)`, TTL-bound per invariant #7). Like `verify`, this does NOT check holder *possession* — that connect-time challenge (as in `admit_channel_join_on_duplex`) is layered on when the predicate is wired to the live relayed substream. **The `C-circuit-relay-transport` relay stays test-only until that wiring lands; this predicate is the reusable authorization heart that makes a live/public relay safe.**
- **C-superpeer-election ⏳:** self-organizing election with operator policy/veto (maintainer-chosen trust boundary), classifying on B1 `Reachability`.
- **D-kademlia ✅ (integration + holder-signed records / invariant #4):** enabled the libp2p **`kad`** feature and added a minimal in-process Kademlia DHT to `ct-agent::p2p` — `build_kad_swarm` (TCP + noise + yamux driving `kad::Behaviour<MemoryStore>` in `kad::Mode::Server`) + the helper **`kademlia_publish_and_resolve`**: node A `put_record`s a `ChannelId → coordinates` mapping, node B (bootstrapped to A via `add_address`) issues `get_record` for the same `ChannelId` and returns the retrieved bytes — both swarms polled together to completion (the classic bug is polling only the querier so A never answers). The record VALUE is **holder-signed** (`SignedCoordinateRecord`): the channel member signs `domain || channel_id || holder || coordinates` with its ed25519 **holder** key (same key family as `member_noise_attest_bytes`), and a reader trusts the coordinates **only if** `verified_coordinates` confirms the signature against the record's `holder` pubkey — enforcing **invariant #4**. Frozen test **`kademlia_resolves_a_holder_signed_coordinate_record`** (whole body wrapped in a 15s `tokio::time::timeout` so a stalled DHT query fails fast, never hangs the gate): A publishes, B resolves the ChannelId + gets the record, and the coordinates match AND the holder signature verifies; it ALSO asserts the security property — a **poisoned** record (tampered coordinates OR a substituted holder pubkey) fails verification and is **rejected** (`verified_coordinates` → `None`), so the DHT (like the libp2p `PeerId`, invariant #1) is untrusted plumbing. The DHT is loopback-only; the **real cross-host bootstrap** (a central node seeded as the bootstrap peer) is a **live** step, not the cargo gate.
- **E-fail-static ✅ (soft-state membership-staple core; the gossip *transport* is the follow-on):** added `MembershipStaple` + `StapleCache` to `ct-common::channel`. A **staple** is the operator's short-lived signed assertion that `holder` is *currently* a member of `channel` (domain-separated preimage `ct-membership-staple-v1 ‖ channel ‖ holder ‖ stapled_at ‖ expires_at`, so it can't be replayed onto another pair nor its TTL extended without re-signing) — distinct from the long-lived `SignedChannelGrant`. `StapleCache` keeps the **latest-expiring** staple per `(channel, holder)`: `refresh` verifies before caching and never regresses validity (out-of-order gossip can't shorten a member); `is_member` is the **fail-static admission input** — it admits a known member with **no central round-trip**, so existing channels survive a central outage until the TTL, and a lapsed entry is evicted (a no-longer-refreshed/revoked member is gone within one TTL — **invariant #7**, revocation latency = staple TTL, default 1h staple / 15m refresh). Frozen tests **`staple_cache_admits_offline_until_ttl_then_lapses`** (offline admission up to `expires_at-1`, refuses + evicts at `expires_at`, re-admits on a fresh mint) and **`staple_cache_rejects_forged_and_never_regresses_validity`** (forged foreign-operator staple never cached; a post-signing channel swap fails verification; a shorter stale staple can't shrink validity; membership is per-`(channel,holder)`). Gate green, 0 warnings. **Follow-on (live/wiring, not the cargo gate):** the gossip transport that distributes/refreshes staples between peers, and wiring `is_member` into the broker/relay admission path as the offline fallback.
- **E-admission-policy ✅ (option A — staple-optional; maintainer decision 2026-07-20):** the maintainer chose **A** (staple-optional, backwards-compatible) over B (staple-required, breaking) / C (defer). Added `ChannelAdmissionPolicy { Open (default), RequireStaple }` + `StapleCache::admits_under_policy(policy, operator, channel, holder, now)` to `ct-common::channel` — the single chokepoint the edge broker consults **after** its existing grant check. `Open` (the default / zero value) is byte-for-byte today's grant-only admission and never consults a staple, so channels that don't opt in are unaffected; `RequireStaple` additionally demands a fresh cached staple (delegates to `is_member`), so revocation propagates within the TTL (invariant #7). Because it runs after the grant check and only ever *adds* a requirement, enabling staples can never weaken admission. Frozen test `staple_admission_policy_is_optional_and_only_ever_adds_a_requirement` (Open admits with no staple; RequireStaple denies without / admits with a fresh staple / denies once it lapses; Open is unaffected by lapse). Gate green. **Remaining follow-on (live/wiring):** the gossip transport that populates the edge's `StapleCache`, per-channel policy served from the control plane, and the call site in `read_channel_join_on_stream` — all need the live mesh, not the cargo gate.
- **E-staple-mint ✅ (the operator is the staple source — invariant #6, NOT central):** added `OperatorIdentity::issue_membership_staple(channel, holder, stapled_at, ttl_secs) -> MembershipStaple` to `ct-agent::channel_run`, alongside `issue_member_grant`. The operator — the only party holding the signing key locally (#117/#6) — mints short-lived staples on a refresh timer; **central never holds the key, so it can distribute/refresh staples but can never mint or forge one** (a central compromise stays DoS/metadata, never impersonation). *(This corrects the earlier E-fail-static follow-on note that said "central mints staples off the grant table" — that would have put the operator key on central, violating invariant #6.)* Frozen test **`operator_mints_a_staple_the_cache_accepts_and_only_the_operator_can_mint`**: the operator mints a staple, a peer's `StapleCache` accepts it under the operator *public* key and admits the member offline until the TTL lapses (invariant #7), and a **foreign** operator's staple is rejected under this channel's operator key (invariant #6 — only the local-key holder can mint an admissible staple). Gate green, 0 warnings. **Remaining follow-on:** the gossip transport (encode/decode + peer distribution) and wiring `is_member` into the broker admission path as the offline fallback.
- **E-staple-wire ✅ (the staple wire codec — first half of the gossip transport):** added `MembershipStaple::{WIRE_LEN, encode, decode}` to `ct-common::channel`, the fixed 144-byte record (`signature(64) ‖ channel(32) ‖ holder(32) ‖ stapled_at(u64 LE) ‖ expires_at(u64 LE)`) the gossip transport ships/refreshes — same fixed-layout style as `SignedChannelGrant::encode/decode`. Decoding does NOT authenticate (a well-formed record can still be forged/lapsed): the caller still gates on `is_valid`. Frozen test **`membership_staple_wire_roundtrips_and_rejects_malformed`**: byte-exact `encode→decode` identity, `WIRE_LEN == 144`, the decoded copy **still verifies** under the operator key (authenticity survives the wire), and truncated / over-long buffers are both rejected as `Malformed` (never half-trusted). Gate green, 0 warnings. **Remaining follow-on (live/wiring):** the peer-to-peer gossip *distribution/refresh* loop that ships these records, and wiring `StapleCache::is_member` into the broker/relay admission path as the offline fallback.

**Design note (2026-07-20) — invariant-#3 relay-gating + the Milestone-B testability boundary (developer):** grounding `C-membership-gate` clarified how the invariant maps onto libp2p, and where the unit-gate ends:
- **The libp2p Circuit-Relay is COORDINATION-ONLY / transient.** In the DCUtR flow two peers connect *via* the relay, then DCUtR **upgrades to direct** — the relay never carries channel *data*. The persistent **data** relay (the symmetric-NAT fallback, when a punch fails) is our **existing grant-gated `broker_channel_relay`/`:443` relay**, which already satisfies invariant #3. So the libp2p relay is never the data path, and #3's *data-metadata-containment* is already met by the existing relay.
- **`C-membership-gate` refined:** the residual concern for the libp2p relay is **open-relay abuse** (an unguarded relay forwards *anyone's* circuits) + coordination-metadata exposure. The gate = bind relay **use** (reservation/circuit) to a **grant proof for the ChannelId** the circuit is for, so a peer can only use the relay for a channel it holds a grant to — *without* making the libp2p `PeerId` an authz input (invariant #1 preserved). This is the remaining **unit-gatable** security slice, and it **blocks any live/public relay**. (The `C-circuit-relay-transport` relay stays test-only until it lands.)
- **Testability boundary — the rest of Milestone B is design + LIVE test, not unit-gated.** `B2-dcutr`'s real value is *cross-NAT* hole-punching, which **cannot be unit-tested on loopback** (both peers are directly reachable — there is no NAT to punch). Its verification is a **live/real-NAT test** (the analog of Milestone A's FD5/#103 live smokes), driven on a real deploy with real NAT'd hosts — not the cargo gate. The **unit-testable libp2p integration is essentially complete** (`B2-libp2p-seam` ✅ / `B2-libp2p-tcp` ✅ / `C-circuit-relay-transport` ✅ all prove `Noise_IK` over the respective libp2p transports). Remaining: `C-membership-gate` (unit-gatable, gates a live relay) → the *live* cross-NAT/cross-host verification of `B2-dcutr` + `D-kademlia` (both now integration-complete with holder-signed records for `D-kademlia`, invariant #4) → `E-fail-static`.

Full architecture belongs in an ADR (*"Decentralized NAT-aware overlay: replaceable coordinator, peer-run superpeer relays, fail-static control plane"*) — to be written on maintainer go (repo rule: no new doc files unprompted). Open confirmations before B2-libp2p-seam lands: (a) pull the libp2p dependency now? (b) staleness TTL (default above).
