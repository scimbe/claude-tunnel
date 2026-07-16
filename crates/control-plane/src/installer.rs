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
/// `portal_base` is the public portal origin (e.g. `https://portal.example`);
/// `join_token` is a freshly-minted, single-use join token supplied by the
/// caller. The token is carried in an environment variable so it never lands in
/// the piped shell's argument vector.
pub fn install_one_liner(portal_base: &str, join_token: &str, os: InstallOs) -> String {
    let base = portal_base.trim_end_matches('/');
    match os {
        // curl the installer, hand the token to it via the environment, run it.
        InstallOs::Unix => {
            format!("curl -fsSL {base}/install.sh | CT_JOIN_TOKEN={join_token} sh")
        }
        // Set the env var for the child scope, then fetch + invoke the script.
        InstallOs::Windows => {
            format!("$env:CT_JOIN_TOKEN='{join_token}'; irm {base}/install.ps1 | iex")
        }
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
    fn one_liners_embed_the_token_via_env_per_os() {
        // #28 PP1: dummy token only — never a real secret in tests.
        let tok = "dummy-join-token-xyz";
        let base = "https://portal.example/"; // trailing slash must be trimmed

        let unix = install_one_liner(base, tok, InstallOs::Unix);
        assert_eq!(
            unix,
            "curl -fsSL https://portal.example/install.sh | CT_JOIN_TOKEN=dummy-join-token-xyz sh"
        );
        // Token carried via env, not as a positional argument to sh.
        assert!(unix.contains("CT_JOIN_TOKEN="));
        assert!(!unix.contains("sh -s -- dummy-join-token"), "token is not a CLI arg");

        let win = install_one_liner(base, tok, InstallOs::Windows);
        assert_eq!(
            win,
            "$env:CT_JOIN_TOKEN='dummy-join-token-xyz'; irm https://portal.example/install.ps1 | iex"
        );

        // Each command embeds the given token exactly once.
        assert_eq!(unix.matches(tok).count(), 1);
        assert_eq!(win.matches(tok).count(), 1);
    }
}
