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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn parse_maps_os_aliases() {
        assert_eq!(InstallOs::parse("Linux"), Some(InstallOs::Unix));
        assert_eq!(InstallOs::parse("macos"), Some(InstallOs::Unix));
        assert_eq!(InstallOs::parse(" Windows "), Some(InstallOs::Windows));
        assert_eq!(InstallOs::parse("plan9"), None);
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
}
