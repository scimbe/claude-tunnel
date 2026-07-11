//! HTTP surface for the control plane (M13.1).
//!
//! Wraps the in-memory [`Enrollment`] service in a small JSON API so Agents can
//! enroll against a running control-plane service (ADR-0017 — thin, holds no
//! trust material or payload). This packet exposes enrollment; the Tunnel
//! Registry and Rendezvous endpoints follow (M13.2).

use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::enrollment::{Enrollment, JoinToken};
use crate::registry::{TunnelInfo, TunnelRegistry};
use ct_common::{AgentId, RoutingToken, TenantId};

/// Shared enrollment state behind the HTTP handlers.
pub type SharedEnrollment = Arc<Mutex<Enrollment>>;

/// Build the enrollment HTTP router: `POST /enroll/issue`, `POST /enroll/redeem`.
pub fn enrollment_router(state: SharedEnrollment) -> Router {
    Router::new()
        .route("/enroll/issue", post(issue))
        .route("/enroll/redeem", post(redeem))
        .with_state(state)
}

#[derive(Deserialize)]
struct IssueReq {
    tenant: String,
}
#[derive(Serialize, Deserialize)]
struct IssueResp {
    token: String,
}

async fn issue(State(enr): State<SharedEnrollment>, Json(req): Json<IssueReq>) -> Json<IssueResp> {
    let token = enr.lock().unwrap().issue_join_token(TenantId(req.tenant));
    Json(IssueResp {
        token: hex_encode(&token.0),
    })
}

#[derive(Deserialize)]
struct RedeemReq {
    token: String,
    agent: String,
    pubkey: String,
}
#[derive(Serialize, Deserialize)]
struct RedeemResp {
    tenant: String,
}

async fn redeem(
    State(enr): State<SharedEnrollment>,
    Json(req): Json<RedeemReq>,
) -> Result<Json<RedeemResp>, (StatusCode, String)> {
    let token = hex_decode_32(&req.token)
        .ok_or((StatusCode::BAD_REQUEST, "malformed token".to_string()))?;
    let pubkey = hex_decode_32(&req.pubkey)
        .ok_or((StatusCode::BAD_REQUEST, "malformed pubkey".to_string()))?;
    let tenant = enr
        .lock()
        .unwrap()
        .redeem(&JoinToken(token), AgentId(req.agent), pubkey)
        .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    Ok(Json(RedeemResp { tenant: tenant.0 }))
}

/// Build the full control-plane router (M13.3): enrollment + registry/rendezvous
/// on one app, each with its own shared state.
pub fn control_plane_router(enrollment: SharedEnrollment, registry: SharedRegistry) -> Router {
    enrollment_router(enrollment).merge(registry_router(registry))
}

/// Shared Tunnel Registry behind the HTTP handlers.
pub type SharedRegistry = Arc<Mutex<TunnelRegistry>>;

/// Build the registry router: `POST /registry/register`,
/// `GET /registry/resolve/:token` (the Rendezvous lookup).
pub fn registry_router(state: SharedRegistry) -> Router {
    Router::new()
        .route("/registry/register", post(register_tunnel))
        .route("/registry/resolve/:token", get(resolve_tunnel))
        .with_state(state)
}

#[derive(Deserialize)]
struct RegisterReq {
    token: String,
    tenant: String,
    agent: String,
}

async fn register_tunnel(
    State(reg): State<SharedRegistry>,
    Json(req): Json<RegisterReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let token = hex_decode_32(&req.token)
        .ok_or((StatusCode::BAD_REQUEST, "malformed token".to_string()))?;
    reg.lock().unwrap().register(
        RoutingToken(token),
        TunnelInfo {
            tenant: TenantId(req.tenant),
            agent: AgentId(req.agent),
        },
    );
    Ok(StatusCode::OK)
}

#[derive(Serialize, Deserialize)]
struct ResolveResp {
    tenant: String,
    agent: String,
}

async fn resolve_tunnel(
    State(reg): State<SharedRegistry>,
    Path(token_hex): Path<String>,
) -> Result<Json<ResolveResp>, StatusCode> {
    let token = hex_decode_32(&token_hex).ok_or(StatusCode::BAD_REQUEST)?;
    let guard = reg.lock().unwrap();
    let info = guard.lookup(&RoutingToken(token)).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(ResolveResp {
        tenant: info.tenant.0.clone(),
        agent: info.agent.0.clone(),
    }))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn post_json(app: Router, path: &str, body: String) -> (StatusCode, Vec<u8>) {
        let resp = app
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, bytes)
    }

    #[tokio::test]
    async fn issue_then_redeem_binds_the_tenant() {
        let state = Arc::new(Mutex::new(Enrollment::new()));
        let app = enrollment_router(state);

        // Issue a join token.
        let (status, body) =
            post_json(app.clone(), "/enroll/issue", r#"{"tenant":"tenant-1"}"#.into()).await;
        assert_eq!(status, StatusCode::OK);
        let issued: IssueResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(issued.token.len(), 64, "32-byte token as hex");

        // Redeem it → binds the tenant.
        let redeem = format!(
            r#"{{"token":"{}","agent":"agent-1","pubkey":"{}"}}"#,
            issued.token,
            "11".repeat(32)
        );
        let (status, body) = post_json(app.clone(), "/enroll/redeem", redeem.clone()).await;
        assert_eq!(status, StatusCode::OK);
        let redeemed: RedeemResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(redeemed.tenant, "tenant-1");

        // A second redemption of the same token is rejected.
        let (status, _) = post_json(app, "/enroll/redeem", redeem).await;
        assert_eq!(status, StatusCode::CONFLICT, "single-use join token");
    }

    #[tokio::test]
    async fn register_then_resolve_tunnel() {
        let reg = Arc::new(Mutex::new(TunnelRegistry::new()));
        let app = registry_router(reg);
        let token = "44".repeat(32);

        // Register a tunnel.
        let body = format!(r#"{{"token":"{token}","tenant":"t","agent":"a"}}"#);
        let (status, _) = post_json(app.clone(), "/registry/register", body).await;
        assert_eq!(status, StatusCode::OK);

        // Resolve it.
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/registry/resolve/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let r: ResolveResp = serde_json::from_slice(&bytes).unwrap();
        assert_eq!((r.tenant.as_str(), r.agent.as_str()), ("t", "a"));

        // An unknown token → 404.
        let resp = app
            .oneshot(
                Request::get(format!("/registry/resolve/{}", "55".repeat(32)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn merged_router_serves_enrollment_and_registry() {
        let enr = Arc::new(Mutex::new(Enrollment::new()));
        let reg = Arc::new(Mutex::new(TunnelRegistry::new()));
        let app = control_plane_router(enr, reg);

        let (s, _) = post_json(app.clone(), "/enroll/issue", r#"{"tenant":"t"}"#.into()).await;
        assert_eq!(s, StatusCode::OK, "enrollment route served");

        let body = format!(r#"{{"token":"{}","tenant":"t","agent":"a"}}"#, "66".repeat(32));
        let (s, _) = post_json(app, "/registry/register", body).await;
        assert_eq!(s, StatusCode::OK, "registry route served");
    }

    #[tokio::test]
    async fn redeem_unknown_token_conflicts() {
        let state = Arc::new(Mutex::new(Enrollment::new()));
        let app = enrollment_router(state);
        let redeem = format!(
            r#"{{"token":"{}","agent":"a","pubkey":"{}"}}"#,
            "22".repeat(32),
            "33".repeat(32)
        );
        let (status, _) = post_json(app, "/enroll/redeem", redeem).await;
        assert_eq!(status, StatusCode::CONFLICT, "unknown token rejected");
    }
}
