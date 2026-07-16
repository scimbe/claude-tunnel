# ADR-0019 — Unified :443 gateway (portal auth + tunnel subdomains + ACME on one port)

## Status
Proposed (planning). Builds on ADR-0010 (Mesh-Plane-first / Browser-Plane SNI),
ADR-0003 (agent-side public-CA ACME), ADR-0017 (thin control plane). Tracked by
the "Unified :443 gateway" epic and the Browser-Plane issue #23.

## Context
Real client networks are hostile: they routinely allow **only outbound TCP 443**
and block everything else, including UDP (empirically confirmed — a restricted
network could not reach `:8090`, `:4433`, or even `:80`, but 443 is the universal
survivor). Therefore *everything a user or their traffic needs* must ride **:443**:

1. the **landing page / portal** (user authentication via SSO, account + tunnel
   management — #25–#29), which today is plain HTTP on the control plane `:8090`;
2. **customer tunnels**, each on its **own public subdomain**, reachable by a
   browser over 443 (Browser Plane, #23);
3. **publicly-trusted TLS certificates** for all of the above, issued/renewed
   automatically — with no extra inbound port to validate against.

The edge already owns `:443` and peeks SNI (`serve_sni_passthrough`, ADR-0010),
but only in **passthrough** mode; the portal is a separate plaintext service. We
need one front door that serves both without breaking payload-blindness.

## Decision
Make the edge's `:443` a **single SNI-multiplexed gateway** with two modes,
chosen by the peeked SNI hostname:

- **Passthrough mode — customer tunnel subdomains** (`*.<zone>`, e.g.
  `app1.bunsenbrenner.org`). Unchanged from ADR-0010: the edge reads only the SNI
  hostname, maps `host -> routing token` (takeover-safe, #23 BP4a) and forwards
  the **raw TLS** to the tunnel's agent. **TLS terminates at the origin**; the
  edge never sees plaintext. The origin's cert is obtained by the **agent via
  DNS-01 ACME** (ADR-0003, #23 BP4c) — the only challenge type that works when the
  origin is reachable *only through the tunnel*.

- **Terminate + reverse-proxy mode — the operator portal** (a configured
  hostname, e.g. `portal.<zone>` or the apex). The gateway **terminates TLS** with
  its **own** publicly-trusted cert and reverse-proxies plaintext HTTP to the
  control-plane portal (`:8090`). This is the **operator's own web console**, not
  a customer's tunneled payload, so terminating here is *not* a blindness
  violation — customer tunnels remain passthrough/blind.

Certificate automation, also all on :443:

- **Portal hostname → edge-side ACME via TLS-ALPN-01.** The gateway owns :443, so
  it answers the `acme-tls/1` ALPN challenge inline — **no HTTP-01, no extra
  port**. Ideal for the everything-on-443 constraint.
- **Customer subdomains → agent-side ACME via DNS-01** (as above), gated by
  **control-plane hostname-ownership authorization** (#23 BP4b) so a tunnel can
  only claim a subdomain it owns.

DNS: `A <zone> -> plane`, `A *.<zone> -> plane` (wildcard), so both the portal and
every customer subdomain resolve to the plane and hit its :443. DNS-01 needs a
DNS provider with an API (Cloudflare recommended over Strato for exactly this).

## Why the edge terminates the portal but stays blind for tunnels
Blindness (ADR-0001/0010) is about **customer payload** carried *inside tunnels*.
The portal is the plane operator's own authenticated web app; the operator
necessarily runs its auth. Terminating the portal's TLS at the plane exposes only
the operator's own console traffic, never a customer's tunneled bytes — those
still pass through as ciphertext with the cert terminating at the customer origin.
The SNI demux keeps the two classes strictly separate on the wire.

## DNS-01 via a self-hosted authoritative responder (`ct-dns`)
The registrar (Strato) has no usable DNS API, so DNS-01 is served by a **minimal
authoritative DNS run as part of the SaaS** — the `ct-dns` crate (the `acme-dns`
pattern). It answers `_acme-challenge.<name> TXT` on `:53` from records published
by a **localhost-only** HTTP API that the co-located ACME client calls; the
mutation API is never public. At Strato you only delegate the challenge —
`CNAME _acme-challenge.<zone> -> <id>.auth.<zone>` plus an `NS`/glue record
pointing `auth.<zone>` at the plane IP ("add the IP to Strato") — while the static
`A <zone>` / `A *.<zone>` routing records stay at Strato. This keeps the stack
self-contained (no third-party DNS in the trust path; fits ADR-0017), at the cost
of running public `:53` (inbound) and, for production robustness, ≥2 nameservers.
Cloudflare (free API, anycast NS) remains the zero-code alternative if a third
party is acceptable.

## Consequences
- One public port (443) for auth, management, tunnels, and cert issuance — works
  in the most restrictive real networks. QUIC/UDP (`:4433`) stays as the fast path
  where reachable, with the existing TLS-over-TCP fallback (ADR-0004) underneath.
- The edge gains a TLS-terminating + reverse-proxy branch (portal only). This is a
  new responsibility; it is fenced to the configured portal hostname(s) and must
  never touch a passthrough (tunnel) SNI.
- ACME state (account key, issued certs, renewal) lives at the gateway for the
  portal hostname and at the agent for customer subdomains.
- **Ordering guard (security):** the gateway must refuse to serve any hostname it
  is not explicitly configured/authorized for — a passthrough SNI with no
  authorized `host->token` binding is rejected, and terminate mode only applies to
  configured portal hostname(s). This prevents anonymous/half-configured binds
  (#23 BP4b) from ever being reachable on a live :443.

## Decomposition (epic sub-packets)
- **GW1** SNI demux on the edge :443: classify peeked SNI as *portal* (configured)
  vs *tunnel* (authorized host registry) vs *reject*; route to terminate vs
  passthrough. Frozen test on the classifier.
- **GW2** Terminate + reverse-proxy: terminate TLS for the portal hostname and
  proxy HTTP to the control plane; stream both directions.
- **GW3** Edge-side ACME (TLS-ALPN-01) for the portal hostname on :443, with
  on-disk cert cache + renewal; staging CA in CI, prod in a gated job.
- **GW4** Wire DNS + deployment (`A`/`*.A` records, `CT_GATEWAY_PORTAL_HOST`,
  proxy target, ACME config) and document the everything-on-443 topology.
- **(#23) BP4b/BP4c/BP5** cover the customer-subdomain half: hostname-ownership
  authorization, agent DNS-01, and the real-browser e2e. Not duplicated here.
