# Demo: `https://help.bunsenbrenner.org` through the Browser Plane

A single-page overview of the project that links to the (LLM-generated) BA thesis,
served **through a claude-tunnel demo tunnel** with a **publicly-trusted HTTPS
certificate** — an end-to-end demo of the Browser Plane (#23) + deSEC DNS-01 (#31).

## How it works (payload-blind, cert at the origin)
```
Browser ──TLS(SNI=help.bunsenbrenner.org)──▶ Plane edge :443 (SNI passthrough, blind)
                                                   │ host → routing token
                                                   ▼
                                          ct-agent (browser mode) ──raw TLS──▶ Caddy origin
                                                                               (terminates TLS,
                                                                                LE cert via deSEC DNS-01,
                                                                                serves index.html)
```
The edge never sees plaintext — TLS terminates at the Caddy **origin**, which holds
the Let's Encrypt certificate. Caddy gets that cert itself via **DNS-01 against
deSEC**, so this demo does **not** depend on the in-tree ACME work (#31 FD4) yet.

## Prerequisites (the transition setup)
1. **DNS**: `help.bunsenbrenner.org` (and `A *.bunsenbrenner.org` / the apex)
   resolves to the plane IP. During the deSEC transition, host the zone at deSEC
   (`ns1.desec.io` / `ns2.desec.org`) — see `docs/dns01-desec.md`.
2. **deSEC token** in `docker/deploy/.env` (`DESEC_TOKEN=...`), scoped to
   `_acme-challenge*` if possible.
3. A **running plane**: `ct-edge` with `CT_EDGE_BROWSER_LISTEN=0.0.0.0:443`, and a
   `ct-control-plane` to onboard the agent against. `:443` open inbound on the host.

## Deploy (central/agent, on the plane)
```bash
# in docker/deploy/.env, in addition to DESEC_TOKEN:
#   HELP_AGENT_EDGE=<edge host:port>          e.g. edge:4433
#   HELP_AGENT_CP_URL=<control-plane URL>
#   HELP_JOIN_TOKEN=<fresh single-use join token>   # mint via the portal / enrollment
#   HELP_AGENT_EDGE_CERT_URL=<control-plane>/pki/ca  # optional, self-serve edge CA

docker compose -f examples/help-site/compose.help-site.yml \
  --env-file docker/deploy/.env up --build -d
```

## Verify it's retrievable
```bash
# real cert, no --cacert needed:
curl -v https://help.bunsenbrenner.org/ | head
# or open it in a browser — a normal HTTPS page, no warning.
```
First load may take a moment while Caddy completes the DNS-01 challenge (deSEC
propagation). While testing, uncomment the staging CA line in `Caddyfile` to avoid
Let's Encrypt rate limits, then switch to production once it works.

> Tuning note: this demo terminates TLS at the origin (payload-blind). It is the
> Browser Plane's intended shape; the unified `:443` gateway (#31) additionally
> multiplexes the operator portal on the same port.
