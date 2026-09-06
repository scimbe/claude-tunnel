//! Agent install + Agent-Fabric channel script delivery (#28 / #75 / #100).
//!
//! Only the **consuming** side of the curl-pipe delivery lives here:
//! [`installer_router`] mounts `/install.sh` + `/install.ps1` (a redirect to
//! ct-agent's own guided setup script) and `/channel.sh` + `/channel.ps1`
//! (served runner scripts that redeem a `CT_BOOTSTRAP` token server-side and
//! exec `ct-agent channel`, keys inherited from the environment, never argv).
//!
//! **Removed in #620 (2026-09-06).** This module used to also hold the
//! **producing** side: pure renderers for the copy-paste one-liners
//! (`install_one_liner`, `install_one_liner_bootstrap`, the
//! `install_bundle_secret`/`parse_install_bundle` codec, `channel_one_liner`,
//! `channel_bundle_secret`, `channel_one_liner_bootstrap`,
//! `brokered_channel_one_liner`, plus `InstallOs`, `ChannelSide` and the
//! `ChannelOneLiner`/`BrokeredChannelOneLiner` parameter structs). They were
//! deleted rather than hardened because
//!
//! * nothing called them: the live install page (`install_page` in
//!   `portal_api.rs`) grew its own independent command rendering and never
//!   wired these, and no portal code ever minted a bootstrap token over the
//!   bundle codecs (`SqliteBootstrap::mint` takes a raw secret);
//! * every one of them built its command with **unquoted** `format!`
//!   interpolation of caller-supplied `host:port` strings (`addr`, `broker`,
//!   `relay`, `listen`), some of which the *peer* advertises. That is a
//!   shell-injection shape (code execution on the customer's machine from a
//!   pasted line), latent only because of the first point, and it would have
//!   gone live the moment someone wired it.
//!
//! Whoever needs copy-paste one-liners again builds them from the living
//! `install_page` implementation, with shell quoting at the render boundary as
//! part of the same change.

use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;

/// Default GitHub-Releases asset base the served scripts download `ct-agent` from
/// (#75 IS2 — matches the asset names `release.yml` publishes). Overridable at
/// deploy time via `CT_RELEASE_BASE` (e.g. a mirror or a pinned tag).
pub const DEFAULT_RELEASE_BASE: &str =
    "https://github.com/scimbe/CADS-Tunnel/releases/latest/download";

/// Render the POSIX `/channel.sh` script the A2A one-liner pipes into `sh` (#100).
/// It detects OS+arch, downloads the matching prebuilt `ct-agent` from `release_base`,
/// and execs `ct-agent channel` — which reads the `CT_CHANNEL_*` config (role, addr,
/// Noise keys) from the environment the one-liner set, so no key is ever a script
/// argument. The served route is in [`installer_router`].
pub fn render_channel_sh(portal_base: &str, release_base: &str) -> String {
    let base = release_base.trim_end_matches('/');
    let portal = portal_base.trim_end_matches('/');
    format!(
        r#"#!/bin/sh
# CADS-Tunnel agent-to-agent channel runner (#100). Piped from the operator one-liner:
#   curl -fsSL <portal>/channel.sh | CT_BOOTSTRAP=... sh
# Brings this machine up as a channel member and pipes stdin/stdout over the
# encrypted agent-to-agent tunnel.
set -eu

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) echo "ct-agent channel: unsupported architecture '$arch'" >&2; exit 1 ;;
esac
case "$os" in
  linux|darwin) ;;
  *) echo "ct-agent channel: unsupported OS '$os'" >&2; exit 1 ;;
esac

# #100 / #97 SEC90b: if a short-lived bootstrap token is set, redeem it server-side
# over TLS for the channel config (keeps the Noise private key off the command line /
# shell history / ps); otherwise fall back to CT_CHANNEL_* set directly (manual path).
if [ -n "${{CT_BOOTSTRAP:-}}" ]; then
  resp=$(curl -fsSL -X POST -H 'content-type: application/json' \
    --data "{{\"token\":\"$CT_BOOTSTRAP\"}}" "{portal}/bootstrap/redeem")
  bundle=$(printf '%s' "$resp" | sed -n 's/.*"secret":"\([^"]*\)".*/\1/p')
  CT_CHANNEL_ROLE=$(printf '%s' "$bundle" | sed -n 's/.*CT_CHANNEL_ROLE=\([^;"]*\).*/\1/p')
  CT_CHANNEL_ADDR=$(printf '%s' "$bundle" | sed -n 's/.*CT_CHANNEL_ADDR=\([^;"]*\).*/\1/p')
  CT_CHANNEL_NOISE_KEY=$(printf '%s' "$bundle" | sed -n 's/.*CT_CHANNEL_NOISE_KEY=\([^;"]*\).*/\1/p')
  CT_CHANNEL_PEER_NOISE_KEY=$(printf '%s' "$bundle" | sed -n 's/.*CT_CHANNEL_PEER_NOISE_KEY=\([^;"]*\).*/\1/p')
  export CT_CHANNEL_ROLE CT_CHANNEL_ADDR CT_CHANNEL_NOISE_KEY CT_CHANNEL_PEER_NOISE_KEY
  cert=$(printf '%s' "$bundle" | sed -n 's/.*CT_CHANNEL_PEER_CERT=\([^;"]*\).*/\1/p')
  [ -n "$cert" ] && export CT_CHANNEL_PEER_CERT="$cert"
fi
: "${{CT_CHANNEL_ROLE:?set CT_BOOTSTRAP (or CT_CHANNEL_ROLE: accept|initiate)}}"
: "${{CT_CHANNEL_ADDR:?set CT_BOOTSTRAP (or CT_CHANNEL_ADDR: bind host:port for accept, peer host:port for initiate)}}"
: "${{CT_CHANNEL_NOISE_KEY:?set CT_BOOTSTRAP (or CT_CHANNEL_NOISE_KEY: this member's Noise private key, hex)}}"
: "${{CT_CHANNEL_PEER_NOISE_KEY:?set CT_BOOTSTRAP (or CT_CHANNEL_PEER_NOISE_KEY: the peer's Noise public key, hex)}}"

asset="ct-agent-${{os}}-${{arch}}"
url="{base}/${{asset}}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "ct-agent channel: downloading $url" >&2
curl -fsSL "$url" -o "$tmp/ct-agent"
chmod +x "$tmp/ct-agent"
# Keys are inherited from the environment (never on the command line).
exec "$tmp/ct-agent" channel
"#,
        base = base,
        portal = portal,
    )
}

/// Render the PowerShell `/channel.ps1` script (#100 — the Windows analog of
/// [`render_channel_sh`]). Detects the arch, downloads `ct-agent-windows-<arch>.exe`
/// from `release_base`, and runs `ct-agent channel` reading `CT_CHANNEL_*` from the
/// environment. Placeholder + replace so PowerShell's `{}` need no brace-escaping.
pub fn render_channel_ps1(portal_base: &str, release_base: &str) -> String {
    CHANNEL_PS1_TEMPLATE
        .replace("__RELEASE_BASE__", release_base.trim_end_matches('/'))
        .replace("__PORTAL_BASE__", portal_base.trim_end_matches('/'))
}

const CHANNEL_PS1_TEMPLATE: &str = r#"#Requires -Version 5
# CADS-Tunnel agent-to-agent channel runner (#100). Piped from the operator one-liner:
#   $env:CT_BOOTSTRAP='...'; irm <portal>/channel.ps1 | iex
$ErrorActionPreference = 'Stop'
# #100 / #97 SEC90b: redeem a short-lived bootstrap token server-side over TLS for the
# channel config (keeps the Noise private key off the command line); else fall back to
# CT_CHANNEL_* set directly (manual path).
if ($env:CT_BOOTSTRAP) {
  $resp = Invoke-RestMethod -Method Post -Uri '__PORTAL_BASE__/bootstrap/redeem' -ContentType 'application/json' -Body (ConvertTo-Json @{ token = $env:CT_BOOTSTRAP })
  $bundle = $resp.secret
  if ($bundle -match 'CT_CHANNEL_ROLE=([^;]*)')           { $env:CT_CHANNEL_ROLE = $Matches[1] }
  if ($bundle -match 'CT_CHANNEL_ADDR=([^;]*)')           { $env:CT_CHANNEL_ADDR = $Matches[1] }
  if ($bundle -match 'CT_CHANNEL_NOISE_KEY=([^;]*)')      { $env:CT_CHANNEL_NOISE_KEY = $Matches[1] }
  if ($bundle -match 'CT_CHANNEL_PEER_NOISE_KEY=([^;]*)') { $env:CT_CHANNEL_PEER_NOISE_KEY = $Matches[1] }
  if ($bundle -match 'CT_CHANNEL_PEER_CERT=([^;]*)')      { $env:CT_CHANNEL_PEER_CERT = $Matches[1] }
}
if (-not $env:CT_CHANNEL_ROLE)            { Write-Error 'ct-agent channel: set CT_BOOTSTRAP (or CT_CHANNEL_ROLE: accept|initiate)'; exit 1 }
if (-not $env:CT_CHANNEL_ADDR)            { Write-Error 'ct-agent channel: set CT_BOOTSTRAP (or CT_CHANNEL_ADDR)'; exit 1 }
if (-not $env:CT_CHANNEL_NOISE_KEY)       { Write-Error 'ct-agent channel: set CT_BOOTSTRAP (or CT_CHANNEL_NOISE_KEY)'; exit 1 }
if (-not $env:CT_CHANNEL_PEER_NOISE_KEY)  { Write-Error 'ct-agent channel: set CT_BOOTSTRAP (or CT_CHANNEL_PEER_NOISE_KEY)'; exit 1 }
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { 'x86_64' }
  'ARM64' { 'aarch64' }
  default { Write-Error "ct-agent channel: unsupported architecture '$($env:PROCESSOR_ARCHITECTURE)'"; exit 1 }
}
$asset = "ct-agent-windows-$arch.exe"
$url = "__RELEASE_BASE__/$asset"
$dir = Join-Path $env:TEMP ("ct-agent-" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$exe = Join-Path $dir $asset
Write-Host "ct-agent channel: downloading $url"
Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing
# Keys are inherited from the environment (never on the command line).
& $exe channel
"#;

/// `/install.sh` and `/install.ps1` (#75 IS3b originally, now retired in favor of
/// ct-agent's own richer setup script) redirect to that script's raw content
/// (`serve_install_sh`/`serve_install_ps1`) rather than serving a rendered one —
/// any existing `curl -fsSL <portal>/install.sh | … sh` one-liner keeps working
/// transparently. `/channel.sh`/`/channel.ps1` are unaffected: a different
/// subcommand (Agent-Fabric channel setup, not the tunnel-install path this
/// script's replacement covers), still rendered and served directly.
pub fn installer_router(portal_base: String, release_base: String) -> Router {
    Router::new()
        .route("/install.sh", get(serve_install_sh))
        .route("/install.ps1", get(serve_install_ps1))
        // #100: the A2A channel runner scripts, served the same way as the installer.
        .route("/channel.sh", get(serve_channel_sh))
        .route("/channel.ps1", get(serve_channel_ps1))
        .with_state(InstallerState {
            portal_base: Arc::new(portal_base),
            release_base: Arc::new(release_base),
        })
}

/// Served-script config: the portal origin (for the bootstrap-redeem call
/// /channel.sh|.ps1 make) and the release asset base (for the `ct-agent`
/// download). `/install.sh`|`.ps1` need neither -- they're a plain redirect.
#[derive(Clone)]
struct InstallerState {
    portal_base: Arc<String>,
    release_base: Arc<String>,
}

/// `ct-agent` moved to its own repo (scimbe/ct-agent), which ships a much richer
/// guided setup script (environment checks, a Docker mode, Rot/Gelb/Grün status
/// reporting, stop/reset commands) than this thin one-liner ever did. Rather than
/// leave old `curl -fsSL <portal>/install.sh | sh` links/docs dead, redirect them
/// straight to that script's raw content -- `curl -fsSL` follows redirects, so
/// existing invocations keep working transparently and just get the better script.
const CT_AGENT_SETUP_SH: &str = "https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.sh";
const CT_AGENT_SETUP_PS1: &str = "https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.ps1";

/// #448: a self-hosting operator (this product's own stated audience) previously had
/// no way to point this redirect at their own mirror without patching the crate --
/// a single chokepoint on `raw.githubusercontent.com` for a censorship-resistant,
/// explicitly self-hostable service. `CT_AGENT_SETUP_URL`/`CT_AGENT_SETUP_PS1_URL`
/// override the default when set; unset behaves exactly as before (verified by the
/// existing tests below, which set neither). Pinning to a release tag + publishing a
/// SHA-256 for `channel.sh`/`channel.ps1` to verify (this issue's other half) is
/// deliberately NOT done here -- it needs a real tagged `ct-agent` release to pin to,
/// which doesn't exist yet (this workspace's other git-dependency pins are all by
/// commit rev for the same reason); tracked separately, not attempted in this pass.
fn ct_agent_setup_sh_url() -> String {
    setup_url_or_default(std::env::var("CT_AGENT_SETUP_URL").ok().as_deref(), CT_AGENT_SETUP_SH)
}

fn ct_agent_setup_ps1_url() -> String {
    setup_url_or_default(std::env::var("CT_AGENT_SETUP_PS1_URL").ok().as_deref(), CT_AGENT_SETUP_PS1)
}

/// #538: the override rule itself, as a pure function of the value — so testing it needs no
/// process-global environment at all.
///
/// The flake this closes was real: one test set `CT_AGENT_SETUP_*` while another read it
/// through the router, and CI went red once and green on the next push with no code change.
/// It was fixed with a mutex both tests take, which works but is **discipline**: the next
/// test that exercises `/install.sh` without remembering the lock brings the race back, and
/// it will again look like a fluke rather than a defect.
///
/// A pure rule cannot be raced. The env read stays in the two callers above, where it belongs
/// and where nothing tests it; everything worth asserting about the OVERRIDE is here.
///
/// An empty value counts as unset: an operator who writes `CT_AGENT_SETUP_URL=` in a compose
/// file means "I did not configure this", and redirecting installs to the empty string would
/// be a broken download rather than an honest default.
fn setup_url_or_default(configured: Option<&str>, default: &str) -> String {
    match configured.map(str::trim) {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => default.to_string(),
    }
}

async fn serve_install_sh() -> Redirect {
    Redirect::temporary(&ct_agent_setup_sh_url())
}

async fn serve_install_ps1() -> Redirect {
    Redirect::temporary(&ct_agent_setup_ps1_url())
}

async fn serve_channel_sh(State(st): State<InstallerState>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        render_channel_sh(&st.portal_base, &st.release_base),
    )
        .into_response()
}

async fn serve_channel_ps1(State(st): State<InstallerState>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        render_channel_ps1(&st.portal_base, &st.release_base),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn channel_scripts_are_served_and_exec_ct_agent_channel() {
        // #100: /channel.sh + /channel.ps1 are served (like /install.sh) and run
        // `ct-agent channel`, requiring the CT_CHANNEL_* keys from the environment
        // (never argv) and downloading the agent from the release base.
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let portal = "https://portal.example";
        let base = "https://github.com/scimbe/CADS-Tunnel/releases/latest/download";

        // Content: POSIX script requires the channel env, execs the subcommand.
        let sh = render_channel_sh(portal, base);
        assert!(sh.starts_with("#!/bin/sh") && sh.contains("set -eu"), "POSIX + fail-fast");
        assert!(sh.contains("CT_CHANNEL_ROLE:?") && sh.contains("CT_CHANNEL_NOISE_KEY:?"), "requires channel env");
        assert!(sh.contains(r#"exec "$tmp/ct-agent" channel"#), "execs ct-agent channel");
        assert!(sh.contains(&format!("{base}/${{asset}}")), "downloads from the release base");
        assert!(!sh.contains("channel $CT_CHANNEL_NOISE_KEY"), "keys stay in the env, not argv");
        // #100/#97 SEC90b: the channel script also redeems CT_BOOTSTRAP against the portal.
        assert!(sh.contains(r#"if [ -n "${CT_BOOTSTRAP:-}" ]; then"#), "has the bootstrap-redeem branch");
        assert!(sh.contains("https://portal.example/bootstrap/redeem"), "redeems against the portal");
        let ps = render_channel_ps1(portal, base);
        assert!(ps.contains("#Requires -Version 5") && ps.contains("& $exe channel"), "ps runs channel");
        assert!(ps.contains("$env:CT_CHANNEL_ROLE"), "ps requires the channel env");
        assert!(ps.contains("if ($env:CT_BOOTSTRAP)"), "ps has the bootstrap-redeem branch");

        // Route: GET /channel.sh -> 200 serving exactly the rendered script.
        let app = installer_router(portal.to_string(), base.to_string());
        let resp = app
            .clone()
            .oneshot(Request::get("/channel.sh").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "/channel.sh is served");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(String::from_utf8(body.to_vec()).unwrap(), render_channel_sh(portal, base), "serves the rendered script");
        let resp2 = app
            .oneshot(Request::get("/channel.ps1").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK, "/channel.ps1 is served");
    }

    /// #448 via #538: the same property, asserted without touching the process environment.
    ///
    /// This test used to set `CT_AGENT_SETUP_*` and read them back, which raced with the
    /// router test that reads the same variables — CI went red once and green on the next
    /// push with no code change. A mutex made that safe, but only for the tests that
    /// remember to take it. Asserting the rule as a pure function removes the shared state
    /// instead of scheduling around it, so no future test can reintroduce the race.
    #[test]
    fn setup_script_urls_are_overridable_for_self_hosting_operators_448() {
        // Unset -> today's exact default, unchanged.
        assert_eq!(setup_url_or_default(None, CT_AGENT_SETUP_SH), CT_AGENT_SETUP_SH);
        assert_eq!(setup_url_or_default(None, CT_AGENT_SETUP_PS1), CT_AGENT_SETUP_PS1);

        // Set -> the operator's mirror wins.
        assert_eq!(
            setup_url_or_default(Some("https://mirror.example/setup.sh"), CT_AGENT_SETUP_SH),
            "https://mirror.example/setup.sh"
        );
        assert_eq!(
            setup_url_or_default(Some("https://mirror.example/setup.ps1"), CT_AGENT_SETUP_PS1),
            "https://mirror.example/setup.ps1"
        );

        // An empty or whitespace-only value is "not configured", not "redirect installs to
        // nowhere" -- `CT_AGENT_SETUP_URL=` in a compose file is an operator leaving a knob
        // blank, and honouring it literally would serve a broken download.
        for blank in ["", "   ", "\t"] {
            assert_eq!(
                setup_url_or_default(Some(blank), CT_AGENT_SETUP_SH),
                CT_AGENT_SETUP_SH,
                "{blank:?} must fall back to the default"
            );
        }
    }

    /// ct-agent moved to its own repo with a much richer setup script; `/install.sh`
    /// and `/install.ps1` now redirect to it rather than serving a rendered
    /// one-liner, so any existing `curl -fsSL <portal>/install.sh | sh` (curl
    /// follows redirects) keeps working transparently and gets the better script.
    #[tokio::test]
    async fn install_routes_redirect_to_the_ct_agent_setup_scripts() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        // #538: no lock needed any more. Nothing in this crate sets CT_AGENT_SETUP_* --
        // the override rule is asserted as a pure function (`setup_url_or_default`), so this
        // test reads the real defaults and cannot race anyone.
        let app = installer_router(
            "https://portal.example".to_string(),
            "http://release.invalid/base".to_string(),
        );

        let resp = app
            .clone()
            .oneshot(Request::get("/install.sh").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT, "/install.sh redirects, not 404");
        assert_eq!(
            resp.headers().get("location").and_then(|v| v.to_str().ok()),
            Some("https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.sh")
        );

        let resp = app
            .clone()
            .oneshot(Request::get("/install.ps1").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT, "/install.ps1 redirects, not 404");
        assert_eq!(
            resp.headers().get("location").and_then(|v| v.to_str().ok()),
            Some("https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.ps1")
        );
    }
}
