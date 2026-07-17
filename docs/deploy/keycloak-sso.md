# Keycloak SSO demo (#42)

Turn the customer portal's `Sign in with SSO` into a real, clickable
Authorization-Code login backed by a Keycloak identity provider. This is the
optional SSO overlay from `docker/deploy/compose.sso.yml`; the base self-host
stack runs unchanged without it.

## What ships in-repo

- `docker/deploy/compose.sso.yml` — the Keycloak service (`quay.io/keycloak/keycloak:25`,
  `start-dev --import-realm`) plus the `CT_OIDC_*` env merged onto the control-plane.
- `docker/deploy/keycloak/ct-demo-realm.json` — a declarative realm `ct-demo` with a
  confidential RS256 client `ct-portal` and self-registration enabled. **No secret is
  baked in** — Keycloak mints the client secret on import.

The control-plane verifies tokens by fetching the realm's RS256 signing key from
its JWKS at startup (`CT_OIDC_ISSUER` alone is enough; no PEM export needed).

## Keycloak is served through the `:443` front door (#48)

Keycloak no longer publishes its own port. It's reached on its **own hostname**
(`auth.<zone>`) through the edge's unified `:443` front door — the edge terminates
TLS for `auth.<zone>` with a BYO cert and reverse-proxies to `keycloak:8080`
internally, exactly like it does for the Portal (FD4-a).

This solves the split-horizon that a published-port setup hit: the realm
**issuer** (`<KEYCLOAK_PUBLIC_URL>/realms/ct-demo`) is baked into every token's
`iss` and is where both the browser (login redirect) and the control-plane
(JWKS + token endpoint) talk to Keycloak — and now both go through the **same**
public URL `https://auth.<zone>`, reachable identically from an external browser
and from the control-plane container.

- ✅ `KEYCLOAK_PUBLIC_URL=https://auth.bunsenbrenner.org` — the front-door hostname.
- ❌ `http://localhost:8091` / an internal `172.x` IP — the browser can't reach it
  (or the control-plane can't), so the login redirect points somewhere unreachable
  and/or the boot-time JWKS fetch fails (`the realm JWKS had no usable RS256 key —
  /me/* disabled` in the control-plane logs).

**Prereq:** the edge must already run the front door for the Portal (FD4-a):
`CT_FRONT_DOOR=0.0.0.0:443` + `CT_EDGE_PORTAL_HOST`/`CT_CP_PROXY_ADDR`/
`CT_EDGE_PORTAL_CERT`|`_KEY`. This overlay adds the Auth route to it. Point
`auth.<zone>`'s DNS at the edge, and get a BYO cert for it the same way as the
Portal's (deSEC DNS-01).

## `.env` keys (add to `docker/deploy/.env`)

```dotenv
# Keycloak's own front-door hostname (its DNS points at the edge :443).
AUTH_PUBLIC_HOST=auth.bunsenbrenner.org
KEYCLOAK_PUBLIC_URL=https://auth.bunsenbrenner.org
# Host dir holding the BYO cert for auth.<zone>: fullchain.pem + privkey.pem.
AUTH_CERT_DIR=/etc/ct/certs/auth
# Portal base URL the browser uses.
PORTAL_PUBLIC_URL=https://bunsenbrenner.org
# The ct-portal client secret Keycloak minted on import (see step 3). Keep it ONLY here.
CT_OIDC_CLIENT_SECRET=<paste-from-keycloak>
# Optional (#43): restrict who may self-register, by email domain.
CT_PORTAL_ALLOWED_EMAIL_DOMAINS=becke.biz
# Keycloak admin console creds (change for anything reachable).
KC_ADMIN_USER=admin
KC_ADMIN_PASSWORD=change-me
```

`CT_OIDC_ISSUER`, `CT_OIDC_CLIENT_ID`, and `CT_OIDC_REDIRECT_URI` are derived from
`KEYCLOAK_PUBLIC_URL` / `PORTAL_PUBLIC_URL` in the compose overlay — you don't set
them directly.

## Bring it up

```bash
docker compose \
  -f docker/deploy/compose.selfhost.yml \
  -f docker/deploy/compose.sso.yml \
  --env-file docker/deploy/.env up --build -d
```

1. Wait for Keycloak to become healthy (`docker compose ... ps`); the realm
   imports on first boot.
2. If the control-plane started before Keycloak was ready and logged OIDC as
   disabled, restart it: `docker compose ... restart control-plane` — it re-fetches
   the JWKS. (A boot-time retry is a possible follow-up.)
3. **Grab the client secret**: Keycloak admin console (`KEYCLOAK_PUBLIC_URL`) →
   realm `ct-demo` → Clients → `ct-portal` → Credentials → copy the secret into
   `CT_OIDC_CLIENT_SECRET` in `.env`, then `restart control-plane`.

## Click-through

1. Open `PORTAL_PUBLIC_URL/portal` → **Sign in with SSO**.
2. Keycloak login page → **Register** (self-registration is on) → create an
   account (if `CT_PORTAL_ALLOWED_EMAIL_DOMAINS` is set, use an allowed domain).
3. Back to `/portal/home` — signed in. From there: account, tunnels, installer.
4. **Sign out** clears the session cookie and returns to the shell.

If a non-allowed email is used with `CT_PORTAL_ALLOWED_EMAIL_DOMAINS` set, the
callback returns a clear "not on the access list" page and mints no session (#43).

## How it verifies (no key export)

`CT_OIDC_ISSUER` → the control-plane derives `<issuer>/protocol/openid-connect/certs`,
fetches the JWKS, selects the RS256 signing key, and builds the verifier at
startup. `CT_OIDC_PUBKEY_PATH` (a PEM of the realm public key) remains an explicit
offline override and takes precedence when set.
