//! HTTP surface for the control plane (M13.1).
//!
//! Wraps the in-memory [`Enrollment`] service in a small JSON API so Agents can
//! enroll against a running control-plane service (ADR-0017 — thin, holds no
//! trust material or payload). This packet exposes enrollment; the Tunnel
//! Registry and Rendezvous endpoints follow (M13.2).

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::enrollment::{Enrollment, JoinToken};
use ct_common::{AgentId, TenantId};

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
