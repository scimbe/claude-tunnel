//! Edge daemon configuration (M5.1a).
//!
//! Parsed from environment variables so the Edge runs as a configurable
//! container node in the Docker testbed.

use std::net::SocketAddr;

/// Runtime configuration for the Edge daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeConfig {
    /// UDP/TCP address to listen on (e.g. `0.0.0.0:4433`).
    pub listen: SocketAddr,
    /// Proof-of-work difficulty (leading zero bits) required at rendezvous.
    pub pow_difficulty: u8,
}

impl EdgeConfig {
    /// Parse from explicit strings (used by tests and by [`EdgeConfig::from_env`]).
    pub fn parse(listen: &str, difficulty: &str) -> Result<EdgeConfig, String> {
        let listen = listen
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid CT_EDGE_LISTEN '{listen}': {e}"))?;
        let pow_difficulty = difficulty
            .parse::<u8>()
            .map_err(|e| format!("invalid CT_EDGE_POW_DIFFICULTY '{difficulty}': {e}"))?;
        Ok(EdgeConfig {
            listen,
            pow_difficulty,
        })
    }

    /// Read from `CT_EDGE_LISTEN` (default `0.0.0.0:4433`) and
    /// `CT_EDGE_POW_DIFFICULTY` (default `16`).
    pub fn from_env() -> Result<EdgeConfig, String> {
        let listen = std::env::var("CT_EDGE_LISTEN").unwrap_or_else(|_| "0.0.0.0:4433".to_string());
        let difficulty = std::env::var("CT_EDGE_POW_DIFFICULTY").unwrap_or_else(|_| "16".to_string());
        Self::parse(&listen, &difficulty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_config() {
        let c = EdgeConfig::parse("127.0.0.1:4433", "18").unwrap();
        assert_eq!(c.listen, "127.0.0.1:4433".parse().unwrap());
        assert_eq!(c.pow_difficulty, 18);
    }

    #[test]
    fn rejects_bad_listen() {
        assert!(EdgeConfig::parse("not-an-addr", "16").is_err());
    }

    #[test]
    fn rejects_bad_difficulty() {
        assert!(EdgeConfig::parse("127.0.0.1:4433", "300").is_err());
    }
}
