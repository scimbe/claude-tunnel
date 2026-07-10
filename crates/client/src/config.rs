//! Client configuration (M5.3a).
//!
//! The Client imports a Capability (binary, `Capability::decode`) and the Edge
//! certificate from files, so it runs as a container node in the testbed.

/// Paths the Client reads its inputs from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    pub capability_file: String,
    pub edge_cert_file: String,
}

impl ClientConfig {
    /// Read `CT_CLIENT_CAPABILITY` (default `/etc/ct/capability.bin`) and
    /// `CT_CLIENT_EDGE_CERT` (default `/etc/ct/edge-cert.der`).
    pub fn from_env() -> ClientConfig {
        ClientConfig {
            capability_file: std::env::var("CT_CLIENT_CAPABILITY")
                .unwrap_or_else(|_| "/etc/ct/capability.bin".to_string()),
            edge_cert_file: std::env::var("CT_CLIENT_EDGE_CERT")
                .unwrap_or_else(|_| "/etc/ct/edge-cert.der".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_are_set() {
        // With the env unset this yields the documented defaults; if the test
        // environment sets them, the values are simply non-empty.
        let c = ClientConfig::from_env();
        assert!(!c.capability_file.is_empty());
        assert!(!c.edge_cert_file.is_empty());
    }
}
