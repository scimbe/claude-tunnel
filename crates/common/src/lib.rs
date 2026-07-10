//! Shared types for Claude Tunnel.
//!
//! P0.1 provides only the crate skeleton; the wire types (`RoutingToken`,
//! `OriginIdentity`, `Capability`, …) land in P0.2. See `docs/planning/`.

/// Stable crate identifier, used by the P0.1 smoke test.
pub const CRATE_NAME: &str = "ct-common";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(super::CRATE_NAME, "ct-common");
    }
}
