//! Claude Tunnel Control Plane — thin, self-hostable-ready coordination:
//! enrollment, Tunnel Registry, Rendezvous, billing. Holds no trust material or
//! payload. See ADR-0005 (enrollment), ADR-0017 (thin control plane).

pub mod enrollment;

/// Stable crate identifier, used by the P0.1 smoke test.
pub const CRATE_NAME: &str = "ct-control-plane";

#[cfg(test)]
mod tests {
    #[test]
    fn depends_on_common() {
        assert_eq!(ct_common::CRATE_NAME, "ct-common");
        assert_eq!(super::CRATE_NAME, "ct-control-plane");
    }
}
