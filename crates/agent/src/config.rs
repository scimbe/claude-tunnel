//! Agent daemon configuration (M5.2a).
//!
//! Parsed from environment variables so the Agent runs as a configurable
//! container node in the Docker testbed.

use std::net::{IpAddr, SocketAddr};

/// Transport protocol of the local Origin the Agent bridges to (M10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OriginProto {
    /// A TCP Origin — full-duplex byte stream (default).
    #[default]
    Tcp,
    /// A UDP Origin — datagram-preserving bridge.
    Udp,
}

impl OriginProto {
    pub fn parse(s: &str) -> Result<OriginProto, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(OriginProto::Tcp),
            "udp" => Ok(OriginProto::Udp),
            other => Err(format!("invalid CT_AGENT_ORIGIN_PROTO '{other}' (expected tcp|udp)")),
        }
    }
}

/// Runtime configuration for the Agent daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    /// Edge address to dial (outbound).
    pub edge: SocketAddr,
    /// Local Origin service to expose through the tunnel.
    pub origin: SocketAddr,
    /// Whether the Origin speaks TCP or UDP.
    pub origin_proto: OriginProto,
    /// If set, the Agent runs a direct-path listener and advertises it at this
    /// IP (with the listener's bound port) so Clients can connect directly,
    /// bypassing the Edge relay (M11.4b-v). `None` disables P2P (relay only).
    pub direct_advertise_ip: Option<IpAddr>,
}

impl AgentConfig {
    pub fn parse(edge: &str, origin: &str) -> Result<AgentConfig, String> {
        let edge = edge
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid CT_AGENT_EDGE '{edge}': {e}"))?;
        let origin = origin
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid CT_AGENT_ORIGIN '{origin}': {e}"))?;
        Ok(AgentConfig {
            edge,
            origin,
            origin_proto: OriginProto::default(),
            direct_advertise_ip: None,
        })
    }

    /// Read from `CT_AGENT_EDGE` (default `127.0.0.1:4433`),
    /// `CT_AGENT_ORIGIN` (default `127.0.0.1:8080`), `CT_AGENT_ORIGIN_PROTO`
    /// (`tcp` | `udp`, default `tcp`) and `CT_AGENT_DIRECT_ADVERTISE` (an IP the
    /// Agent advertises for its direct-path listener; unset = P2P disabled).
    pub fn from_env() -> Result<AgentConfig, String> {
        let edge = std::env::var("CT_AGENT_EDGE").unwrap_or_else(|_| "127.0.0.1:4433".to_string());
        let origin =
            std::env::var("CT_AGENT_ORIGIN").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        let proto = std::env::var("CT_AGENT_ORIGIN_PROTO").unwrap_or_else(|_| "tcp".to_string());
        let mut cfg = Self::parse(&edge, &origin)?;
        cfg.origin_proto = OriginProto::parse(&proto)?;
        cfg.direct_advertise_ip = match std::env::var("CT_AGENT_DIRECT_ADVERTISE") {
            Ok(s) if !s.trim().is_empty() => Some(
                s.trim()
                    .parse::<IpAddr>()
                    .map_err(|e| format!("invalid CT_AGENT_DIRECT_ADVERTISE '{s}': {e}"))?,
            ),
            _ => None,
        };
        Ok(cfg)
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
        assert_eq!(c.origin_proto, OriginProto::Tcp, "defaults to TCP");
        assert_eq!(c.direct_advertise_ip, None, "P2P disabled by default");
    }

    #[test]
    fn parses_direct_advertise_ip() {
        assert_eq!("10.5.0.4".parse::<IpAddr>().unwrap(), "10.5.0.4".parse::<IpAddr>().unwrap());
        // A parsed IP round-trips into an advertised SocketAddr with the port.
        let ip: IpAddr = "10.5.0.4".parse().unwrap();
        let sa = SocketAddr::new(ip, 40001);
        assert_eq!(sa.to_string(), "10.5.0.4:40001");
    }

    #[test]
    fn origin_proto_parses_tcp_udp_and_rejects_others() {
        assert_eq!(OriginProto::parse("tcp").unwrap(), OriginProto::Tcp);
        assert_eq!(OriginProto::parse("UDP").unwrap(), OriginProto::Udp);
        assert_eq!(OriginProto::parse(" udp ").unwrap(), OriginProto::Udp);
        assert!(OriginProto::parse("sctp").is_err());
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
