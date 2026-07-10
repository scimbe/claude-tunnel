//! Claude Tunnel Agent — customer-run, outbound-only. Custodian of the Origin
//! key; mints Capabilities. P0.1 is the crate skeleton; transport lands in P1.2.

/// Stable crate identifier, used by the P0.1 smoke test.
pub const CRATE_NAME: &str = "ct-agent";

#[cfg(test)]
mod tests {
    #[test]
    fn depends_on_common() {
        assert_eq!(ct_common::CRATE_NAME, "ct-common");
        assert_eq!(super::CRATE_NAME, "ct-agent");
    }
}
