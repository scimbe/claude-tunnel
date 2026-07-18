//! Control-plane self-test (M13.4b).
//!
//! Drives the hosted control-plane service end to end from inside the testbed:
//! enroll (issue → redeem), register a tunnel, then resolve it — all over HTTP
//! against a *running* `ct-control-plane` container. Prints `OK` and exits 0 on
//! success; any failure propagates as a non-zero exit so compose's
//! `--exit-code-from selftest` fails the smoke.

use std::time::Duration;

use ct_common::{AgentId, RoutingToken, TenantId};
use ct_control_plane::client::ControlPlaneClient;
use ed25519_dalek::{Signer, SigningKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = std::env::var("CT_CONTROL_PLANE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8090".to_string());
    let cp = ControlPlaneClient::new(url.clone());

    let tenant = TenantId("tenant-smoke".to_string());
    let agent = AgentId("agent-smoke".to_string());

    // Wait for the service to accept connections (compose only orders start,
    // not readiness): retry the first call for up to ~10s.
    let mut join = None;
    let mut last_err = None;
    for _ in 0..50 {
        match cp.issue_join_token(&tenant).await {
            Ok(t) => {
                join = Some(t);
                break;
            }
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    let join =
        join.ok_or_else(|| format!("control-plane never became reachable: {last_err:?}"))?;

    // Agent enrolls: redeem the join token to bind the tenant, proving possession
    // of the identity key (#88 SEC88c) by signing the join token.
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let proof = sk.sign(&join).to_bytes();
    let bound = cp.redeem(&join, &agent, &sk.verifying_key().to_bytes(), &proof).await?;
    if bound.0 != "tenant-smoke" {
        return Err(format!("redeem bound the wrong tenant: {}", bound.0).into());
    }

    // Agent registers its tunnel's routing token.
    let token = RoutingToken([0x7c; 32]);
    cp.register(&token, &bound, &agent).await?;

    // Client resolves it via Rendezvous.
    let (t, a) = cp.resolve(&token).await?;
    if (t.0.as_str(), a.0.as_str()) != ("tenant-smoke", "agent-smoke") {
        return Err(format!("resolve returned the wrong binding: ({}, {})", t.0, a.0).into());
    }

    println!("control-plane selftest OK: enroll -> register -> resolve ({}, {}) via {url}", t.0, a.0);
    Ok(())
}
