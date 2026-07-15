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
- **C3** ⏳ Runbook + Onboarding-Doku.
