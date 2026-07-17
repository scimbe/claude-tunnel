# ADR-0020 — Agent Fabric: direct agent-to-agent channels with trust chains

## Status
Proposed (planning). First sub-packet of the agent-to-agent networking feature
(issue #72). Builds the transport on ADR-0015 (P2P mesh with rendezvous) and the
payload-blind relay of ADR-0010; deliberately distinct from the existing
tunnel-**sharing** grants (`/portal/tunnels/{id}/grants`). No code lands with this
ADR — it fixes the addressing and trust model **before** any implementation, per
the issue's explicit sequencing.

## Context

A user asked for **direct agent-to-agent communication**: tunnels that address one
another and exchange data **directly**, with the central plane used only as a
fallback when a direct path can't be established — organised by explicit trust
chains and data-exchange rules, **including across user boundaries** (an agent of
user A connects to a "channel" that user B operates).

What exists today does **not** cover this:

- **Tunnel "sharing" is not agent-to-agent.** `/portal/tunnels/{id}/grants`
  (`crates/control-plane/src/portal_api.rs`) is *subject-scoped owner sharing of the
  same tunnel*: a grantee gets read-sight + install right for the **same** tunnel
  and, crucially, the **same `tunnel.routing_token`** as the owner
  (`routing_token_if_authorized`). That is a redundancy/HA primitive ("another
  agent can serve this one tunnel"), not "two different tunnels can talk". There is
  no role/scope separation — whoever holds the token has full access to both ends.
- **Direct-path infra is client↔one-agent only.** `CT_AGENT_DIRECT_ADVERTISE`
  (`crates/agent/src/config.rs`, `direct_advertise_ip`) + edge rendezvous
  (`crates/edge/src/rendezvous.rs`: `resolve_rendezvous[_gated]`) + the client's
  direct-then-relay dial (`crates/client/src/transport.rs`) let a **client** learn
  one agent's advertised endpoint, connect directly, and fall back to edge relay.
  There is no agent↔agent route anywhere in `crates/` (verified).
- **The token/identity model is flat.** `RoutingToken` and `Capability`
  (`crates/common/src/lib.rs`) are flat bearer values: possession = full access,
  no direction, no rights, no expiry, no notion of "which agent may address which".
- **Noise is structurally two-party.** `Noise_IK_25519_ChaChaPoly_BLAKE2s`
  (`crates/common/src/noise.rs`) pins one Origin identity a client authenticates —
  no third party, no group session.

**Terminology caveat.** "Mesh Plane" (ADR-0010), "Noise Mesh Handshake" (ADR-0013),
"P2P Mesh with Rendezvous" (ADR-0015) all denote the authenticated **client↔origin
data plane** (as opposed to the SNI-passthrough Browser Plane) — *not* a network of
interconnected agents. To avoid overloading "Mesh", this feature is named the
**Agent Fabric**, and its unit of connectivity is a **Channel**.

## Decision

Introduce an **Agent Fabric** layered on the existing rendezvous transport, with a
new addressing-and-trust model that is explicitly separate from flat routing tokens.

### 1. Channels as the addressing primitive
A **Channel** is a named agent-to-agent rendezvous point that **one agent operates**
(the *channel operator*) and other agents may **join** (the *members*). A channel is
addressed by an opaque **`ChannelId`** (a `[u8; 32]`, like `RoutingToken` — no
hostname, operator-blind), decoupling "who I want to talk to" from any network
address. An agent reaches a peer by naming a channel, never an IP.

### 2. Trust chains as *scoped, expiring, directional* grants
Replace flat bearer access, for the fabric only, with a **`ChannelGrant`**: an
authorization minted by a channel operator for a member, carrying — at minimum —
`channel` (which `ChannelId`), `direction` (`initiate` | `accept` | `both`),
`rights` (e.g. `read` | `write` | `read-write`), a `subject`/holder binding, and an
`expiry`. A *trust chain* is the verifiable path operator → grant → member; a member
may only re-delegate if its grant says so (a `delegable` right), which is how chains
extend without becoming flat bearer tokens. Enforcement lives at the edge (rendezvous
gate) and at each agent (accept/deny by grant), never "possession = full access".

### 3. Cross-user connection is an explicit invitation, not a shared token
For user A's agent to join a channel user B operates, B's operator issues an
**invitation** (a one-time, scoped `ChannelGrant` template) that A redeems through
the control plane to obtain its own member grant. This is *analogous to but
fundamentally different from* tunnel sharing: sharing hands over the **same** token
(same tunnel, full access); an invitation mints a **new, scoped, revocable** grant
into a **different** agent's channel. Failed/expired/revoked trust yields a clean
deny (edge refuses the rendezvous; the peer agent refuses the session) with no
partial access.

### 4. Transport: direct-first, relay-fallback, payload-blind — reuse ADR-0015
Two agents establish connectivity exactly as client↔agent does today: the edge acts
as a **rendezvous/NAT-punch broker** between the two advertised endpoints
(generalising `resolve_rendezvous`), the two agents run a **two-party Noise session**
between themselves (so `Noise_IK` still fits — one initiator, one responder per
channel connection), and the edge **relays only as a fallback**, seeing ciphertext
only (unchanged payload-blindness). A channel is therefore a **hub of pairwise
agent↔agent Noise sessions**, *not* a multi-party group session — which sidesteps the
two-party Noise constraint honestly instead of inventing group crypto.

## Consequences

New building blocks the later sub-packets must add (none exist yet):
- `ChannelId` + `ChannelGrant` types in `ct-common` (structured, signed, expiring —
  the antithesis of the flat `RoutingToken`).
- A control-plane **channel registry + membership/invitation** store and API
  (mint channel, issue invitation, redeem → member grant, revoke).
- An **edge agent↔agent rendezvous route** (generalise `rendezvous.rs` to broker two
  agents, gated by a valid `ChannelGrant`).
- An **agent dial-out + accept role** (an agent both serves its origin and joins/
  operates channels), advertising its direct endpoint via the existing
  `CT_AGENT_DIRECT_ADVERTISE` path.

Relationship to existing features: the Agent Fabric is **complementary** to tunnel
sharing (HA redundancy) — sharing stays as-is; the fabric is a new, orthogonal
capability. Provider-blindness is preserved end to end (operator sees opaque
`ChannelId`s and relays ciphertext; grants authorise without revealing payload).

### Alternatives considered
- **Extend the flat `RoutingToken` with a role field** — rejected: bolting scope
  onto a bearer token that already means "full access" invites confused-deputy bugs;
  a distinct `ChannelGrant` keeps the two models cleanly separated.
- **Group/multi-party Noise session per channel** — rejected: `Noise_IK` is
  two-party; multi-party secure group messaging (MLS-style) is a research-grade
  dependency far out of scope. Pairwise sessions under a channel hub give the same
  user-visible behaviour without it.
- **Adopt libp2p / a full P2P stack** — rejected: heavy dependency surface and its
  own addressing/identity assumptions conflict with the provider-blind, opaque-token
  design; the existing rendezvous primitive already does the hard NAT-punch part.

## Decomposition (issue #72)
1. **This ADR** — addressing + trust model (design, no code). ← landed
2. **Same-user minimal prototype** — two agents of one user establish a direct
   channel via the existing rendezvous (edge as broker only, no payload relay);
   feasibility proof on the NAT-punch base, with a real two-agent integration test.
3. **Cross-user invitation model** — operator issues an invitation, another user's
   agent redeems it into a scoped member grant; trust-fail rules enforced.
4. **Fallback + hardening** — edge relay fallback when direct setup fails, with a
   fallback-path integration test, plus revoke/expiry enforcement tests.

`fix-ready` only when the whole acceptance (real direct agent-to-agent data exchange
with trust chains and a tested fallback) is met.
