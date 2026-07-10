//! Claude Tunnel Edge — operator-run, public. Coordinates Rendezvous and relays
//! ciphertext only as fallback; never in the trust path. P0.1 is the skeleton;
//! the QUIC listener lands in P1.1.

/// Stable crate identifier, used by the P0.1 smoke test.
pub const CRATE_NAME: &str = "ct-edge";

#[cfg(test)]
mod tests {
    #[test]
    fn depends_on_common() {
        assert_eq!(ct_common::CRATE_NAME, "ct-common");
        assert_eq!(super::CRATE_NAME, "ct-edge");
    }
}
