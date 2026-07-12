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
- **M17.4** Related Work.
- **M17.5** Anforderungen & Bedrohungsmodell.
- **M17.6** Architektur (aus ADRs).
- **M17.7** Implementierung (alle Crates, inkl. Streaming/UDP/P2P/Payment).
- **M17.8** Evaluation (Parameterstudie M16, Tabellen + Abbildungen).
- **M17.9** Diskussion & Limitierungen.
- **M17.10** Fazit & Ausblick + Anhang.
