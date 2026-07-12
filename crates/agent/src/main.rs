//! Claude Tunnel Agent daemon (M5.4c).
//!
//! Waits for the Edge cert on a shared path, mints a Capability (written to the
//! shared volume for the Client), registers its tunnel, and serves the Origin.

use std::time::Duration;

use ct_agent::capability::mint_capability;
use ct_agent::config::AgentConfig;
use ct_agent::onboard::OnboardEnv;
use ct_agent::origin::OriginKey;
use ct_agent::serve::run_agent;
use ct_agent::transport::load_cert;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // One-command onboarding: if a join token is present (env or `onboard`
    // subcommand), auto-enroll against the control plane before serving. This
    // is the "install -> enroll -> tunnel" single step — the operator supplies
    // only a control-plane URL and a single-use join token.
    let onboarding = std::env::args().nth(1).as_deref() == Some("onboard")
        || std::env::var("CT_AGENT_JOIN_TOKEN").is_ok();
    let config = if onboarding {
        let env = OnboardEnv::from_env()?;
        let edge = env.config.edge;
        let cp_url = env.cp_url.clone();
        let onboarded = env.onboard().await?;
        eprintln!(
            "ct-agent: onboarded agent={} tenant={} via {} (edge={})",
            onboarded.agent_id.0, onboarded.tenant.0, cp_url, edge
        );
        onboarded.config
    } else {
        AgentConfig::from_env()?
    };
    let cert_path =
        std::env::var("CT_AGENT_EDGE_CERT").unwrap_or_else(|_| "/shared/edge-cert.der".to_string());
    let cap_out = std::env::var("CT_AGENT_CAPABILITY_OUT")
        .unwrap_or_else(|_| "/shared/capability.bin".to_string());

    // Wait for the Edge to publish its certificate.
    let edge_cert = loop {
        match load_cert(&cert_path) {
            Ok(cert) => break cert,
            Err(_) => {
                eprintln!("ct-agent: waiting for edge cert at {cert_path} ...");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    // Mint a Capability carrying the real Origin Identity (M8.1). The Agent is
    // custodian of the Origin static Noise keypair; only its public half travels
    // in the Capability. The private half stays here to terminate the E2E
    // handshake (M8.3).
    let origin_key = OriginKey::generate();
    let cap = mint_capability(origin_key.origin_identity(), config.edge.to_string());
    std::fs::write(&cap_out, cap.encode())?;
    eprintln!(
        "ct-agent: edge={} origin={} capability -> {}",
        config.edge, config.origin, cap_out
    );

    run_agent(&config, edge_cert, cap.token, origin_key.private_bytes()).await
}
