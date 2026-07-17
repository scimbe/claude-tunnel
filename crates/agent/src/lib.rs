//! Claude Tunnel Agent — customer-run, outbound-only. Custodian of the Origin
//! key; mints Capabilities. See ADR-0004 (transport), ADR-0005 (identity).

pub mod acme;
pub mod capability;
pub mod config;
pub mod identity;
pub mod observe;
pub mod onboard;
pub mod origin;
pub mod reconnect;
pub mod serve;
pub mod transport;

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
