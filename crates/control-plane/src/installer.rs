//! Per-OS agent install one-liners (#28) — pure command renderers.
//!
//! The portal offers a customer a copy-paste command that downloads, onboards
//! and starts a `ct-agent` for one of their tunnels, realising it over the
//! Plane edge. This module renders that command string for each OS family.
//!
//! **Secret handling (critical).** The join token is a secret. It is minted
//! server-side, single-use and short-lived by the caller (a later sub-packet);
//! this renderer only *embeds* a token it is given — it never mints, stores or
//! logs one. The token is passed to the install script through an **environment
//! variable**, never as a positional argument, so it stays out of the script's
//! `argv`. Tests use dummy tokens only.

use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

/// Default GitHub-Releases asset base the served scripts download `ct-agent` from
/// (#75 IS2 — matches the asset names `release.yml` publishes). Overridable at
/// deploy time via `CT_RELEASE_BASE` (e.g. a mirror or a pinned tag).
pub const DEFAULT_RELEASE_BASE: &str =
    "https://github.com/scimbe/claude-tunnel/releases/latest/download";

/// Target OS family for the copy-paste installer command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallOs {
    /// Linux and macOS — POSIX `sh`.
    Unix,
    /// Windows — PowerShell.
    Windows,
}

impl InstallOs {
    /// Parse the `os` query/path value used by the portal (`linux`, `macos`,
    /// `darwin`, `unix` → Unix; `windows`, `win` → Windows). Case-insensitive.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "linux" | "macos" | "darwin" | "unix" | "mac" => Some(Self::Unix),
            "windows" | "win" => Some(Self::Windows),
            _ => None,
        }
    }
}

/// Render the copy-paste one-liner that installs + onboards a `ct-agent`.
///
/// `portal_base` is the public portal origin (e.g. `https://portal.example`).
/// `join_token` is a freshly-minted, single-use join token. `routing_token` is
/// the tunnel's persistent routing token (#27 RB1) so the agent registers at the
/// edge under the token the portal knows — the linkage a revocation acts on
/// (#27 RB2). Both are carried in environment variables so they never land in the
/// piped shell's argument vector.
pub fn install_one_liner(
    portal_base: &str,
    join_token: &str,
    routing_token: &str,
    os: InstallOs,
) -> String {
    let base = portal_base.trim_end_matches('/');
    match os {
        // curl the installer, hand the tokens to it via the environment, run it.
        InstallOs::Unix => format!(
            "curl -fsSL {base}/install.sh | CT_JOIN_TOKEN={join_token} CT_AGENT_TOKEN={routing_token} sh"
        ),
        // Set the env vars for the child scope, then fetch + invoke the script.
        InstallOs::Windows => format!(
            "$env:CT_JOIN_TOKEN='{join_token}'; $env:CT_AGENT_TOKEN='{routing_token}'; irm {base}/install.ps1 | iex"
        ),
    }
}

/// Encode the real install secrets — the single-use `join_token` and the tunnel's
/// persistent `routing_token` — as the opaque `secret` payload a bootstrap token
/// carries (#90/#97 SEC90b). The portal mints a bootstrap token over this bundle
/// (`SqliteBootstrap::mint`); the agent redeems the bootstrap token server-side
/// (`POST /bootstrap/redeem`) and [`parse_install_bundle`]s the result back into the
/// two tokens — so the real secrets travel in the TLS response body, never in the
/// one-liner's command string. JSON so the redeem response is self-describing and
/// forward-compatible.
pub fn install_bundle_secret(join_token: &str, routing_token: &str) -> String {
    serde_json::json!({
        "join_token": join_token,
        "routing_token": routing_token,
    })
    .to_string()
}

/// Parse the bundle produced by [`install_bundle_secret`] back into
/// `(join_token, routing_token)`. Returns `None` if the JSON is malformed or either
/// field is missing/non-string.
pub fn parse_install_bundle(secret: &str) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_str(secret).ok()?;
    let join = v.get("join_token")?.as_str()?.to_string();
    let routing = v.get("routing_token")?.as_str()?.to_string();
    Some((join, routing))
}

/// Render the copy-paste one-liner in its **bootstrap-token** form (#90/#97 SEC90b):
/// the command carries only a short-lived, single-use `bootstrap_token` — never the
/// real join/routing tokens — so nothing secret lands in shell history or `ps`. The
/// install script redeems `CT_BOOTSTRAP` server-side (`POST {portal}/bootstrap/redeem`)
/// for the real [`install_bundle_secret`] bundle. This is the secret-hygiene upgrade
/// over [`install_one_liner`], whose embedded-token form remains for the manual path
/// and back-compat until the live install flow (#75) adopts this.
pub fn install_one_liner_bootstrap(portal_base: &str, bootstrap_token: &str, os: InstallOs) -> String {
    let base = portal_base.trim_end_matches('/');
    match os {
        InstallOs::Unix => {
            format!("curl -fsSL {base}/install.sh | CT_BOOTSTRAP={bootstrap_token} sh")
        }
        InstallOs::Windows => {
            format!("$env:CT_BOOTSTRAP='{bootstrap_token}'; irm {base}/install.ps1 | iex")
        }
    }
}

/// Which side of an Agent-Fabric channel a one-liner brings the machine up as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelSide {
    /// Binds and waits for the peer to dial (grant `Direction::Accept`).
    Responder,
    /// Dials the responder's advertised endpoint (grant `Direction::Initiate`).
    Initiator,
}

/// Everything a per-test-system A2A channel one-liner needs (#100). The keys/cert
/// travel in **environment variables** (never argv), matching the `ct-agent channel`
/// subcommand's `CT_CHANNEL_*` contract and the install one-liner's secret hygiene.
pub struct ChannelOneLiner<'a> {
    pub side: ChannelSide,
    /// Responder: the local bind address (`0.0.0.0:<port>`). Initiator: the peer's
    /// advertised `host:port`.
    pub addr: &'a str,
    /// This member's Noise (X25519) **private** key, hex.
    pub own_noise_private_hex: &'a str,
    /// The peer member's Noise **public** key, hex (pinned by the initiator).
    pub peer_noise_public_hex: &'a str,
    /// Initiator only: the responder's QUIC cert (hex DER) to trust for the dial.
    pub peer_cert_hex: Option<&'a str>,
}

/// Render the copy-paste command that brings a machine up as one side of an A2A
/// channel and pipes stdin/stdout over the encrypted tunnel (#100). It targets the
/// already-installed `ct-agent channel` subcommand (run the install one-liner first),
/// setting the `CT_CHANNEL_*` env the subcommand reads. The Noise keys/cert ride in
/// the environment, never the argument vector (SEC90 hygiene; the still-inline-secret
/// concern is #97). `os` selects the POSIX `env VAR=… cmd` vs PowerShell `$env:` form.
pub fn channel_one_liner(p: &ChannelOneLiner, os: InstallOs) -> String {
    let role = match p.side {
        ChannelSide::Responder => "accept",
        ChannelSide::Initiator => "initiate",
    };
    match os {
        InstallOs::Unix => {
            let mut cmd = format!(
                "CT_CHANNEL_ROLE={role} CT_CHANNEL_ADDR={addr} \
                 CT_CHANNEL_NOISE_KEY={own} CT_CHANNEL_PEER_NOISE_KEY={peer}",
                addr = p.addr,
                own = p.own_noise_private_hex,
                peer = p.peer_noise_public_hex,
            );
            if let Some(cert) = p.peer_cert_hex {
                cmd.push_str(&format!(" CT_CHANNEL_PEER_CERT={cert}"));
            }
            cmd.push_str(" ct-agent channel");
            cmd
        }
        InstallOs::Windows => {
            let mut cmd = format!(
                "$env:CT_CHANNEL_ROLE='{role}'; $env:CT_CHANNEL_ADDR='{addr}'; \
                 $env:CT_CHANNEL_NOISE_KEY='{own}'; $env:CT_CHANNEL_PEER_NOISE_KEY='{peer}'; ",
                addr = p.addr,
                own = p.own_noise_private_hex,
                peer = p.peer_noise_public_hex,
            );
            if let Some(cert) = p.peer_cert_hex {
                cmd.push_str(&format!("$env:CT_CHANNEL_PEER_CERT='{cert}'; "));
            }
            cmd.push_str("ct-agent channel");
            cmd
        }
    }
}

/// Render the POSIX `/channel.sh` script the A2A one-liner pipes into `sh` (#100).
/// It detects OS+arch, downloads the matching prebuilt `ct-agent` from `release_base`,
/// and execs `ct-agent channel` — which reads the `CT_CHANNEL_*` config (role, addr,
/// Noise keys) from the environment the one-liner set, so no key is ever a script
/// argument. Mirrors [`render_install_sh`]; the served route is in [`installer_router`].
pub fn render_channel_sh(release_base: &str) -> String {
    let base = release_base.trim_end_matches('/');
    format!(
        r#"#!/bin/sh
# claude-tunnel agent-to-agent channel runner (#100). Piped from the operator one-liner:
#   curl -fsSL <portal>/channel.sh | CT_CHANNEL_ROLE=... CT_CHANNEL_ADDR=... \
#     CT_CHANNEL_NOISE_KEY=... CT_CHANNEL_PEER_NOISE_KEY=... sh
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

: "${{CT_CHANNEL_ROLE:?set CT_CHANNEL_ROLE (accept|initiate)}}"
: "${{CT_CHANNEL_ADDR:?set CT_CHANNEL_ADDR (bind host:port for accept, peer host:port for initiate)}}"
: "${{CT_CHANNEL_NOISE_KEY:?set CT_CHANNEL_NOISE_KEY (this member's Noise private key, hex)}}"
: "${{CT_CHANNEL_PEER_NOISE_KEY:?set CT_CHANNEL_PEER_NOISE_KEY (the peer's Noise public key, hex)}}"

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
    )
}

/// Render the PowerShell `/channel.ps1` script (#100 — the Windows analog of
/// [`render_channel_sh`]). Detects the arch, downloads `ct-agent-windows-<arch>.exe`
/// from `release_base`, and runs `ct-agent channel` reading `CT_CHANNEL_*` from the
/// environment. Placeholder + replace so PowerShell's `{}` need no brace-escaping.
pub fn render_channel_ps1(release_base: &str) -> String {
    CHANNEL_PS1_TEMPLATE.replace("__RELEASE_BASE__", release_base.trim_end_matches('/'))
}

const CHANNEL_PS1_TEMPLATE: &str = r#"#Requires -Version 5
# claude-tunnel agent-to-agent channel runner (#100). Piped from the operator one-liner:
#   $env:CT_CHANNEL_ROLE='...'; ...; irm <portal>/channel.ps1 | iex
$ErrorActionPreference = 'Stop'
if (-not $env:CT_CHANNEL_ROLE)            { Write-Error 'ct-agent channel: set CT_CHANNEL_ROLE (accept|initiate)'; exit 1 }
if (-not $env:CT_CHANNEL_ADDR)            { Write-Error 'ct-agent channel: set CT_CHANNEL_ADDR'; exit 1 }
if (-not $env:CT_CHANNEL_NOISE_KEY)       { Write-Error 'ct-agent channel: set CT_CHANNEL_NOISE_KEY'; exit 1 }
if (-not $env:CT_CHANNEL_PEER_NOISE_KEY)  { Write-Error 'ct-agent channel: set CT_CHANNEL_PEER_NOISE_KEY'; exit 1 }
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

/// Render the POSIX `/install.sh` script the Unix one-liner pipes into `sh`
/// (#75 IS3a). It detects OS+arch, downloads the matching prebuilt `ct-agent`
/// binary from `release_base` (the GitHub-Releases-style asset base, e.g.
/// `https://github.com/scimbe/claude-tunnel/releases/latest/download`), and execs
/// `ct-agent onboard` — which reads `CT_JOIN_TOKEN`/`CT_AGENT_TOKEN` from the
/// environment the one-liner set, so no secret is ever a script argument. This is
/// the served script CONTENT; wiring the `/install.sh` route is IS3b and the
/// prebuilt release binaries it downloads are IS2.
///
/// `release_base` is trusted config (never user input) and has any trailing slash
/// trimmed. The script is `set -eu`, fails loudly on an unsupported OS/arch, and
/// installs into a fresh temp dir.
pub fn render_install_sh(release_base: &str) -> String {
    let base = release_base.trim_end_matches('/');
    format!(
        r#"#!/bin/sh
# claude-tunnel agent installer (#75). Piped from the portal one-liner:
#   curl -fsSL <portal>/install.sh | CT_JOIN_TOKEN=... CT_AGENT_TOKEN=... sh
# Run this on the machine you want to expose (the origin), not your laptop.
set -eu

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) echo "ct-agent install: unsupported architecture '$arch'" >&2; exit 1 ;;
esac
case "$os" in
  linux|darwin) ;;
  *) echo "ct-agent install: unsupported OS '$os' (use the manual path)" >&2; exit 1 ;;
esac

: "${{CT_JOIN_TOKEN:?set CT_JOIN_TOKEN (from the portal install page)}}"
: "${{CT_AGENT_TOKEN:?set CT_AGENT_TOKEN (from the portal install page)}}"

asset="ct-agent-${{os}}-${{arch}}"
url="{base}/${{asset}}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "ct-agent install: downloading $url" >&2
curl -fsSL "$url" -o "$tmp/ct-agent"
chmod +x "$tmp/ct-agent"
# Tokens are inherited from the environment (never on the command line).
exec "$tmp/ct-agent" onboard
"#,
        base = base,
    )
}

/// Render the PowerShell `/install.ps1` script the Windows one-liner pipes into
/// `iex` (#75 IS4 — the Windows analog of [`render_install_sh`]). It detects the
/// arch, downloads the matching prebuilt `ct-agent-windows-<arch>.exe` from
/// `release_base`, and runs `ct-agent onboard` — which reads
/// `CT_JOIN_TOKEN`/`CT_AGENT_TOKEN` from the environment the one-liner set (never a
/// command argument). `release_base` is trusted config, trailing slash trimmed.
/// This is the served script CONTENT; the `/install.ps1` route is IS3b and the
/// prebuilt release binaries are IS2. Uses a placeholder + replace rather than
/// `format!` so PowerShell's `{}` blocks need no brace-escaping.
pub fn render_install_ps1(release_base: &str) -> String {
    INSTALL_PS1_TEMPLATE.replace("__RELEASE_BASE__", release_base.trim_end_matches('/'))
}

const INSTALL_PS1_TEMPLATE: &str = r#"#Requires -Version 5
# claude-tunnel agent installer (#75). Piped from the portal one-liner:
#   $env:CT_JOIN_TOKEN='...'; $env:CT_AGENT_TOKEN='...'; irm <portal>/install.ps1 | iex
# Run this on the machine you want to expose (the origin), not your laptop.
$ErrorActionPreference = 'Stop'
if (-not $env:CT_JOIN_TOKEN)  { Write-Error 'ct-agent install: set CT_JOIN_TOKEN (from the portal install page)';  exit 1 }
if (-not $env:CT_AGENT_TOKEN) { Write-Error 'ct-agent install: set CT_AGENT_TOKEN (from the portal install page)'; exit 1 }
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { 'x86_64' }
  'ARM64' { 'aarch64' }
  default { Write-Error "ct-agent install: unsupported architecture '$($env:PROCESSOR_ARCHITECTURE)'"; exit 1 }
}
$asset = "ct-agent-windows-$arch.exe"
$url = "__RELEASE_BASE__/$asset"
$dir = Join-Path $env:TEMP ("ct-agent-" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$exe = Join-Path $dir $asset
Write-Host "ct-agent install: downloading $url"
Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing
# Tokens are inherited from the environment (never on the command line).
& $exe onboard
"#;

/// Serve `/install.sh` and `/install.ps1` (#75 IS3b) — the routes every portal
/// install one-liner (`curl -fsSL <portal>/install.sh | … sh`, `irm
/// <portal>/install.ps1 | iex`) fetches. Before this, both URLs 404'd and the
/// customer command dead-ended (the reported bug). `release_base` is the trusted
/// GitHub-Releases asset base the rendered scripts download the prebuilt
/// `ct-agent` from (IS2); it is config, never user input. Serving is read-only and
/// carries no secret — the tokens live only in the environment the one-liner sets.
pub fn installer_router(release_base: String) -> Router {
    Router::new()
        .route("/install.sh", get(serve_install_sh))
        .route("/install.ps1", get(serve_install_ps1))
        // #100: the A2A channel runner scripts, served the same way as the installer.
        .route("/channel.sh", get(serve_channel_sh))
        .route("/channel.ps1", get(serve_channel_ps1))
        .with_state(Arc::new(release_base))
}

async fn serve_install_sh(State(base): State<Arc<String>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        render_install_sh(&base),
    )
        .into_response()
}

async fn serve_install_ps1(State(base): State<Arc<String>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        render_install_ps1(&base),
    )
        .into_response()
}

async fn serve_channel_sh(State(base): State<Arc<String>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        render_channel_sh(&base),
    )
        .into_response()
}

async fn serve_channel_ps1(State(base): State<Arc<String>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        render_channel_ps1(&base),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_ps1_detects_arch_downloads_and_onboards() {
        let ps = render_install_ps1("https://github.com/scimbe/claude-tunnel/releases/latest/download/");
        assert!(ps.contains("#Requires -Version 5"), "PowerShell header");
        assert!(ps.contains("$ErrorActionPreference = 'Stop'"), "fail-fast");
        assert!(ps.contains("PROCESSOR_ARCHITECTURE"), "detects arch");
        assert!(ps.contains("'AMD64'") && ps.contains("'ARM64'") && ps.contains("x86_64") && ps.contains("aarch64"), "normalises arch");
        assert!(ps.contains(r#"$asset = "ct-agent-windows-$arch.exe""#), "per-arch windows asset");
        assert!(
            ps.contains(r#"$url = "https://github.com/scimbe/claude-tunnel/releases/latest/download/$asset""#),
            "downloads from the release base (trailing slash trimmed)"
        );
        assert!(ps.contains("$env:CT_JOIN_TOKEN") && ps.contains("$env:CT_AGENT_TOKEN"), "requires the env tokens");
        assert!(ps.contains("& $exe onboard"), "runs the agent onboarding");
        // No secret is ever a positional argument.
        assert!(!ps.contains("onboard $env:CT_JOIN_TOKEN"), "tokens stay in the env, not argv");
    }

    #[test]
    fn install_sh_detects_os_arch_downloads_and_onboards() {
        let sh = render_install_sh("https://github.com/scimbe/claude-tunnel/releases/latest/download/");
        // POSIX + fail-fast.
        assert!(sh.starts_with("#!/bin/sh"), "POSIX shebang");
        assert!(sh.contains("set -eu"), "fail-fast");
        // OS + arch detection with a normalised asset name.
        assert!(sh.contains("uname -s") && sh.contains("uname -m"), "detects OS + arch");
        assert!(sh.contains("aarch64") && sh.contains("x86_64"), "normalises arch aliases");
        assert!(sh.contains(r#"asset="ct-agent-${os}-${arch}""#), "per-OS/arch asset name");
        // Downloads from the release base (trailing slash trimmed — no `//`).
        assert!(
            sh.contains(r#"url="https://github.com/scimbe/claude-tunnel/releases/latest/download/${asset}""#),
            "downloads the matching binary from the release base"
        );
        // Requires the tokens from the env (not as args) and execs onboard.
        assert!(sh.contains("CT_JOIN_TOKEN:?") && sh.contains("CT_AGENT_TOKEN:?"), "requires the env tokens");
        assert!(sh.contains(r#"exec "$tmp/ct-agent" onboard"#), "execs the agent onboarding");
        // No secret is ever a positional argument.
        assert!(!sh.contains("onboard $CT_JOIN_TOKEN") && !sh.contains("onboard \""), "tokens stay in the env");
    }

    #[tokio::test]
    async fn channel_scripts_are_served_and_exec_ct_agent_channel() {
        // #100: /channel.sh + /channel.ps1 are served (like /install.sh) and run
        // `ct-agent channel`, requiring the CT_CHANNEL_* keys from the environment
        // (never argv) and downloading the agent from the release base.
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let base = "https://github.com/scimbe/claude-tunnel/releases/latest/download";

        // Content: POSIX script requires the channel env, execs the subcommand.
        let sh = render_channel_sh(base);
        assert!(sh.starts_with("#!/bin/sh") && sh.contains("set -eu"), "POSIX + fail-fast");
        assert!(sh.contains("CT_CHANNEL_ROLE:?") && sh.contains("CT_CHANNEL_NOISE_KEY:?"), "requires channel env");
        assert!(sh.contains(r#"exec "$tmp/ct-agent" channel"#), "execs ct-agent channel");
        assert!(sh.contains(&format!("{base}/${{asset}}")), "downloads from the release base");
        assert!(!sh.contains("channel $CT_CHANNEL_NOISE_KEY"), "keys stay in the env, not argv");
        let ps = render_channel_ps1(base);
        assert!(ps.contains("#Requires -Version 5") && ps.contains("& $exe channel"), "ps runs channel");
        assert!(ps.contains("$env:CT_CHANNEL_ROLE"), "ps requires the channel env");

        // Route: GET /channel.sh -> 200 serving exactly the rendered script.
        let app = installer_router(base.to_string());
        let resp = app
            .clone()
            .oneshot(Request::get("/channel.sh").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "/channel.sh is served");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(String::from_utf8(body.to_vec()).unwrap(), render_channel_sh(base), "serves the rendered script");
        let resp2 = app
            .oneshot(Request::get("/channel.ps1").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK, "/channel.ps1 is served");
    }

    #[test]
    fn channel_one_liner_renders_the_ct_agent_channel_command() {
        // #100: the copy-paste A2A one-liner. Keys ride in CT_CHANNEL_* env, never
        // argv; the responder needs no peer cert, the initiator carries one; the
        // command invokes `ct-agent channel`.
        let responder = ChannelOneLiner {
            side: ChannelSide::Responder,
            addr: "0.0.0.0:9443",
            own_noise_private_hex: "a1a1",
            peer_noise_public_hex: "b2b2",
            peer_cert_hex: None,
        };
        let sh = channel_one_liner(&responder, InstallOs::Unix);
        assert!(sh.starts_with("CT_CHANNEL_ROLE=accept "), "role prefix");
        assert!(sh.contains("CT_CHANNEL_ADDR=0.0.0.0:9443"), "bind addr");
        assert!(sh.contains("CT_CHANNEL_NOISE_KEY=a1a1") && sh.contains("CT_CHANNEL_PEER_NOISE_KEY=b2b2"), "keys in env");
        assert!(sh.trim_end().ends_with("ct-agent channel"), "invokes the subcommand");
        assert!(!sh.contains("CT_CHANNEL_PEER_CERT"), "responder needs no peer cert");
        // Secret hygiene: the private key is an env assignment, not a bare argv token.
        assert!(!sh.contains("channel a1a1"), "key never in argv");

        // Self-contained initiator: no peer cert (accept-any dial; Noise authenticates).
        let initiator = ChannelOneLiner {
            side: ChannelSide::Initiator,
            addr: "198.51.100.7:9443",
            own_noise_private_hex: "c3c3",
            peer_noise_public_hex: "d4d4",
            peer_cert_hex: None,
        };
        let sh_i = channel_one_liner(&initiator, InstallOs::Unix);
        assert!(sh_i.contains("CT_CHANNEL_ROLE=initiate"), "initiator role");
        assert!(!sh_i.contains("CT_CHANNEL_PEER_CERT"), "no cert needed — accept-any dial");
        assert!(sh_i.trim_end().ends_with("ct-agent channel"), "invokes the subcommand");

        // An optional pinned cert, if supplied, is included.
        let pinned = ChannelOneLiner { peer_cert_hex: Some("deadbeef"), ..initiator };
        assert!(channel_one_liner(&pinned, InstallOs::Unix).contains("CT_CHANNEL_PEER_CERT=deadbeef"), "optional pin");

        // Windows analog uses $env: assignments and the same subcommand.
        let ps = channel_one_liner(&initiator, InstallOs::Windows);
        assert!(ps.contains("$env:CT_CHANNEL_ROLE='initiate';"), "ps role");
        assert!(ps.trim_end().ends_with("ct-agent channel"), "ps invokes the subcommand");
    }

    #[test]
    fn parse_maps_os_aliases() {
        assert_eq!(InstallOs::parse("Linux"), Some(InstallOs::Unix));
        assert_eq!(InstallOs::parse("macos"), Some(InstallOs::Unix));
        assert_eq!(InstallOs::parse(" Windows "), Some(InstallOs::Windows));
        assert_eq!(InstallOs::parse("plan9"), None);
    }

    /// #75 IS5 — end-to-end: fetch `/install.sh` from the real route, then actually
    /// *run* it and prove the whole path works — OS/arch detection, the download
    /// step, and `exec ct-agent onboard` with the tokens inherited from the
    /// environment (never argv). Hermetic: a fake `curl` on `PATH` intercepts the
    /// binary download and drops a stub `ct-agent` (so no network / no published
    /// release is needed), and the stub records how it was invoked. Unix-only —
    /// the served script is POSIX `sh`.
    #[cfg(unix)]
    #[tokio::test]
    async fn served_install_sh_runs_end_to_end_with_tokens_from_the_env() {
        use axum::body::Body;
        use axum::http::Request;
        use http_body_util::BodyExt;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;
        use tower::ServiceExt;

        // The served script — fetched through the real route, not rendered inline.
        let app = installer_router("http://release.invalid/base".to_string());
        let resp = app
            .oneshot(Request::get("/install.sh").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let script = String::from_utf8(body.to_vec()).unwrap();

        // A private working dir (pid-scoped so parallel test runs don't collide).
        let dir = std::env::temp_dir().join(format!("ct-is5-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bin")).unwrap();
        let write_exec = |path: &std::path::Path, body: &str| {
            fs::write(path, body).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        };

        // Stub ct-agent: records "<argv1>|<join>|<agent>" so we can assert the
        // subcommand and that the secrets arrived via the environment.
        let stub = dir.join("ct-agent-stub");
        write_exec(&stub, "#!/bin/sh\necho \"$1|$CT_JOIN_TOKEN|$CT_AGENT_TOKEN\" > \"$CT_IS5_OUT\"\n");
        // Fake curl: ignore everything except `-o <target>`, into which it copies the
        // stub — standing in for downloading the release binary.
        write_exec(
            &dir.join("bin/curl"),
            "#!/bin/sh\nout=\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=$2; shift 2;; *) shift;; esac; done\ncp \"$CT_IS5_STUB\" \"$out\"\n",
        );
        let script_path = dir.join("install.sh");
        fs::write(&script_path, &script).unwrap();
        let out = dir.join("out.txt");

        let status = Command::new("sh")
            .arg(&script_path)
            .env("PATH", format!("{}/bin:{}", dir.display(), std::env::var("PATH").unwrap_or_default()))
            .env("CT_JOIN_TOKEN", "join-XYZ")
            .env("CT_AGENT_TOKEN", "agent-XYZ")
            .env("CT_IS5_STUB", &stub)
            .env("CT_IS5_OUT", &out)
            .status()
            .expect("run served install.sh");
        assert!(status.success(), "the served installer runs to completion");

        let recorded = fs::read_to_string(&out).expect("stub ct-agent ran");
        assert_eq!(
            recorded.trim(),
            "onboard|join-XYZ|agent-XYZ",
            "ct-agent is exec'd with `onboard` and both tokens inherited from the env (not argv)"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn installer_routes_serve_the_scripts_that_were_404ing() {
        // #75 IS3b (the reported bug): the portal one-liners curl/irm these two
        // URLs, which had no route and returned 404 live. Assert they now serve the
        // rendered scripts (200 + the matching renderer body + release base) so the
        // customer command no longer dead-ends.
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let base = "https://github.com/scimbe/claude-tunnel/releases/latest/download";
        let app = installer_router(base.to_string());

        // /install.sh -> 200 shell script.
        let resp = app
            .clone()
            .oneshot(Request::get("/install.sh").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "/install.sh is served, not 404");
        let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(ct.starts_with("text/x-shellscript"), "sh content-type: {ct}");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let sh = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(sh, render_install_sh(base), "serves exactly the rendered installer");
        assert!(sh.starts_with("#!/bin/sh") && sh.contains(base), "real script for this release base");

        // /install.ps1 -> 200 PowerShell script.
        let resp = app
            .clone()
            .oneshot(Request::get("/install.ps1").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "/install.ps1 is served, not 404");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let ps = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(ps, render_install_ps1(base), "serves exactly the rendered PowerShell installer");
        assert!(ps.contains("#Requires -Version 5") && ps.contains(base), "real ps1 for this release base");
    }

    #[test]
    fn one_liners_embed_both_tokens_via_env_per_os() {
        // #28/#27 RB2: dummy tokens only — never a real secret in tests.
        let jt = "dummy-join-token-xyz";
        let rt = "dummy-routing-token-abc";
        let base = "https://portal.example/"; // trailing slash must be trimmed

        let unix = install_one_liner(base, jt, rt, InstallOs::Unix);
        assert_eq!(
            unix,
            "curl -fsSL https://portal.example/install.sh | \
             CT_JOIN_TOKEN=dummy-join-token-xyz CT_AGENT_TOKEN=dummy-routing-token-abc sh"
        );
        // Tokens carried via env, not as positional arguments to sh.
        assert!(unix.contains("CT_JOIN_TOKEN=") && unix.contains("CT_AGENT_TOKEN="));
        assert!(!unix.contains("sh -s -- dummy"), "tokens are not CLI args");

        let win = install_one_liner(base, jt, rt, InstallOs::Windows);
        assert_eq!(
            win,
            "$env:CT_JOIN_TOKEN='dummy-join-token-xyz'; \
             $env:CT_AGENT_TOKEN='dummy-routing-token-abc'; irm https://portal.example/install.ps1 | iex"
        );

        // Each command embeds each token exactly once.
        for cmd in [&unix, &win] {
            assert_eq!(cmd.matches(jt).count(), 1);
            assert_eq!(cmd.matches(rt).count(), 1);
        }
    }

    #[test]
    fn bootstrap_one_liner_carries_only_the_bootstrap_token_not_the_real_secrets() {
        // #90/#97 SEC90b: the bootstrap form of the one-liner must NOT contain the
        // real join/routing tokens — only the short-lived bootstrap token. The real
        // secrets ride in the TLS redeem response, recovered via the bundle codec.
        let jt = "dummy-join-token-xyz";
        let rt = "dummy-routing-token-abc";
        let boot = "dummy-bootstrap-token-0123456789";
        let base = "https://portal.example/"; // trailing slash trimmed

        // The bundle the portal mints a bootstrap token over round-trips exactly.
        let bundle = install_bundle_secret(jt, rt);
        assert_eq!(parse_install_bundle(&bundle), Some((jt.to_string(), rt.to_string())));
        assert_eq!(parse_install_bundle("not json"), None);
        assert_eq!(parse_install_bundle(r#"{"join_token":"x"}"#), None, "missing routing_token -> None");

        let unix = install_one_liner_bootstrap(base, boot, InstallOs::Unix);
        assert_eq!(
            unix,
            "curl -fsSL https://portal.example/install.sh | CT_BOOTSTRAP=dummy-bootstrap-token-0123456789 sh"
        );
        let win = install_one_liner_bootstrap(base, boot, InstallOs::Windows);
        assert_eq!(
            win,
            "$env:CT_BOOTSTRAP='dummy-bootstrap-token-0123456789'; irm https://portal.example/install.ps1 | iex"
        );

        // The critical property: neither the real join nor routing token appears in
        // the shown command — only the bootstrap token does.
        for cmd in [&unix, &win] {
            assert!(!cmd.contains(jt), "join token must not appear in the one-liner");
            assert!(!cmd.contains(rt), "routing token must not appear in the one-liner");
            assert_eq!(cmd.matches(boot).count(), 1, "bootstrap token carried exactly once");
        }
    }
}
