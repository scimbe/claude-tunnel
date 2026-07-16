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

#[cfg(test)]
mod tests {
    use super::*;

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
