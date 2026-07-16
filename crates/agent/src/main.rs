//! Claude Tunnel Agent daemon (M5.4c).
//!
//! Waits for the Edge cert on a shared path, mints a Capability (written to the
//! shared volume for the Client), registers its tunnel, and serves the Origin.

use std::time::Duration;

use ct_agent::capability::{parse_routing_token_hex, resolve_serving_identity_with_token};
use ct_agent::config::AgentConfig;
use ct_agent::onboard::OnboardEnv;
use ct_agent::serve::run_agent;
use ct_agent::transport::load_cert;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // `rotate` subcommand (#12 K4): rotate the origin key while KEEPING the
    // routing token, then exit. Re-mints the capability (same token, new origin),
    // retires the old key into CT_AGENT_ORIGIN_KEY_DIR, and promotes the new key.
    // Restart the agent (with that dir set) to serve both identities.
    if std::env::args().nth(1).as_deref() == Some("rotate") {
        let key_path = std::env::var("CT_AGENT_ORIGIN_KEY")
            .map_err(|_| "rotate requires CT_AGENT_ORIGIN_KEY (the primary key path)")?;
        let cap_out = std::env::var("CT_AGENT_CAPABILITY_OUT")
            .unwrap_or_else(|_| "/shared/capability.bin".to_string());
        let dir = std::env::var("CT_AGENT_ORIGIN_KEY_DIR")
            .map_err(|_| "rotate requires CT_AGENT_ORIGIN_KEY_DIR (the retired-key dir)")?;
        let new_cap = ct_agent::capability::rotate_origin_key(&key_path, &cap_out, &dir)?;
        eprintln!(
            "ct-agent: rotated origin key — new capability at {cap_out} (same token, new origin); \
             old key retired to {dir}. Restart the agent to serve both, then distribute the new \
             capability and remove the retired key once the window closes."
        );
        let _ = new_cap;
        return Ok(());
    }

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

    // Obtain the Edge CA root. With CT_AGENT_EDGE_CERT_URL set, fetch it from the
    // control plane's published /pki/ca (#11 C2) — self-serve cross-host, no
    // out-of-band copy. Otherwise wait for it on the shared-volume path.
    let edge_cert = if let Ok(url) = std::env::var("CT_AGENT_EDGE_CERT_URL") {
        let der = ct_control_plane::client::ControlPlaneClient::new(url.clone())
            .fetch_edge_cert()
            .await
            .map_err(|e| format!("ct-agent: fetch edge cert from {url}: {e:?}"))?;
        eprintln!("ct-agent: fetched edge cert from {url} ({} bytes)", der.len());
        rustls::pki_types::CertificateDer::from(der)
    } else {
        loop {
            match load_cert(&cert_path) {
                Ok(cert) => break cert,
                Err(_) => {
                    eprintln!("ct-agent: waiting for edge cert at {cert_path} ...");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    };

    // Resolve the serving identity (Capability + Origin static key). The Agent is
    // custodian of the Origin static Noise keypair; only its public half travels
    // in the Capability. The private half stays here to terminate the E2E
    // handshake (M8.3). With CT_AGENT_ORIGIN_KEY set, the key + capability are
    // persisted/shared so multiple agents can serve one tunnel (redundancy, #8).
    // With CT_AGENT_ORIGIN_KEY_DIR set, additional (retired) origin keys in that
    // directory are also served, so old capabilities keep working during a key
    // rotation window (#12).
    let origin_key_path = std::env::var("CT_AGENT_ORIGIN_KEY").ok();
    let origin_key_dir = std::env::var("CT_AGENT_ORIGIN_KEY_DIR").ok();
    // #27 RB2b: if the portal supplied the tunnel's routing token (CT_AGENT_TOKEN,
    // set by the install one-liner), register at the edge under THAT token so a
    // revocation can find and drop this tunnel. Otherwise mint a random token.
    let forced_token = std::env::var("CT_AGENT_TOKEN")
        .ok()
        .and_then(|s| parse_routing_token_hex(&s));
    let identity = resolve_serving_identity_with_token(
        origin_key_path.as_deref(),
        &cap_out,
        &config.edge.to_string(),
        origin_key_dir.as_deref(),
        forced_token,
    )?;
    eprintln!(
        "ct-agent: edge={} origin={} capability -> {} (serving {} origin identit{}){}",
        config.edge,
        config.origin,
        cap_out,
        identity.origin_keys.len(),
        if identity.origin_keys.len() == 1 { "y" } else { "ies" },
        match &origin_key_path {
            Some(p) => format!(", shared origin key {p}"),
            None => String::new(),
        }
    );

    run_agent(
        &config,
        edge_cert,
        identity.cap.token,
        std::sync::Arc::new(identity.origin_keys),
    )
    .await
}
