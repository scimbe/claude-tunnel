//! Claude Tunnel Client tool (M5.4c).
//!
//! Waits for the Edge cert and the Agent's Capability on shared paths, dials the
//! Edge, tunnels a payload to the Origin, and verifies the round-trip.

use std::net::SocketAddr;
use std::time::Duration;

use ct_client::config::ClientConfig;
use ct_client::transport::{client_tunnel, dial_edge, load_cert};
use ct_common::Capability;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = ClientConfig::from_env();
    let payload = std::env::var("CT_CLIENT_PAYLOAD").unwrap_or_else(|_| "hello-tunnel".to_string());

    // Wait for the Edge cert.
    let edge_cert = loop {
        match load_cert(&config.edge_cert_file) {
            Ok(cert) => break cert,
            Err(_) => {
                eprintln!("ct-client: waiting for edge cert ...");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    // Wait for the Agent's Capability.
    let cap = loop {
        match std::fs::read(&config.capability_file)
            .ok()
            .and_then(|b| Capability::decode(&b).ok())
        {
            Some(cap) => break cap,
            None => {
                eprintln!("ct-client: waiting for capability ...");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    let edge_addr: SocketAddr = cap.edge_addr.parse()?;
    let conn = dial_edge(edge_addr, edge_cert).await?;
    let response = client_tunnel(&conn, &cap.token, payload.as_bytes()).await?;
    println!(
        "ct-client: sent {:?}, received {:?}",
        payload,
        String::from_utf8_lossy(&response)
    );

    if response == payload.as_bytes() {
        eprintln!("ct-client: tunnel round-trip OK");
        Ok(())
    } else {
        Err("tunnel response mismatch".into())
    }
}
