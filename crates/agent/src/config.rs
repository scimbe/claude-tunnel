//! Agent daemon configuration (M5.2a).
//!
//! Parsed from environment variables so the Agent runs as a configurable
//! container node in the Docker testbed.

use std::net::SocketAddr;

/// Runtime configuration for the Agent daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    /// Edge address to dial (outbound).
    pub edge: SocketAddr,
    /// Local Origin service to expose through the tunnel.
    pub origin: SocketAddr,
}

impl AgentConfig {
    pub fn parse(edge: &str, origin: &str) -> Result<AgentConfig, String> {
        let edge = edge
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid CT_AGENT_EDGE '{edge}': {e}"))?;
        let origin = origin
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid CT_AGENT_ORIGIN '{origin}': {e}"))?;
        Ok(AgentConfig { edge, origin })
    }

    /// Read from `CT_AGENT_EDGE` (default `127.0.0.1:4433`) and
    /// `CT_AGENT_ORIGIN` (default `127.0.0.1:8080`).
    pub fn from_env() -> Result<AgentConfig, String> {
        let edge = std::env::var("CT_AGENT_EDGE").unwrap_or_else(|_| "127.0.0.1:4433".to_string());
        let origin =
            std::env::var("CT_AGENT_ORIGIN").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        Self::parse(&edge, &origin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_config() {
        let c = AgentConfig::parse("10.0.0.2:4433", "127.0.0.1:8080").unwrap();
        assert_eq!(c.edge, "10.0.0.2:4433".parse().unwrap());
        assert_eq!(c.origin, "127.0.0.1:8080".parse().unwrap());
    }

    #[test]
    fn rejects_bad_edge() {
        assert!(AgentConfig::parse("nope", "127.0.0.1:8080").is_err());
    }

    #[test]
    fn rejects_bad_origin() {
        assert!(AgentConfig::parse("10.0.0.2:4433", "nope").is_err());
    }
}
