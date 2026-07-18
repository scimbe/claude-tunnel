//! Agent Fabric — edge-side channel-authorize resolver (#81 SEC81c-c c-ii).
//!
//! The live broker's admission gate needs `authorize(channel, holder) ->
//! Option<operator_pubkey>` — the operator key iff the holder is a current member — but
//! the channel registry lives in the control plane. This queries the CP's
//! `POST /internal/channel/authorize` (c-i), presenting the shared edge↔CP admin token,
//! and maps the response to `Option<[u8; 32]>`. It is **fail-closed**: any non-member
//! (404), bad token (401), or transport/parse error resolves to `None`, so an
//! unresolvable authorization denies admission at the gate rather than opening it.

use ct_common::channel::ChannelId;
use serde::{Deserialize, Serialize};

fn hex(bytes: &[u8]) -> String {
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
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[derive(Serialize)]
struct AuthorizeReq {
    channel: String,
    holder: String,
}

#[derive(Deserialize)]
struct AuthorizeResp {
    operator_pubkey: String,
}

/// Resolves channel-join authorization by querying the control plane's c-i endpoint.
#[derive(Clone)]
pub struct ChannelAuthorizer {
    client: reqwest::Client,
    url: String,
    admin_token_hex: String,
}

impl ChannelAuthorizer {
    /// `cp_base` is the control-plane base URL (e.g. `http://control-plane:8090`);
    /// `admin_token` is the shared edge↔CP admin secret the CP verifies.
    pub fn new(cp_base: &str, admin_token: &[u8; 32]) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: format!(
                "{}/internal/channel/authorize",
                cp_base.trim_end_matches('/')
            ),
            admin_token_hex: hex(admin_token),
        }
    }

    /// The operator public key iff `holder` is a current member of `channel`, else
    /// `None` (fail-closed on non-member / bad token / transport error).
    pub async fn authorize(&self, channel: &ChannelId, holder: &[u8; 32]) -> Option<[u8; 32]> {
        let resp = self
            .client
            .post(&self.url)
            .header("x-ct-admin-token", &self.admin_token_hex)
            .json(&AuthorizeReq {
                channel: hex(&channel.0),
                holder: hex(holder),
            })
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body: AuthorizeResp = resp.json().await.ok()?;
        hex_decode_32(&body.operator_pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::Value;

    // A minimal stand-in for the CP's c-i endpoint: requires the admin token, returns
    // the operator key for the one known member, 404 otherwise.
    async fn mock_authorize(
        headers: axum::http::HeaderMap,
        Json(body): Json<Value>,
    ) -> Result<Json<Value>, axum::http::StatusCode> {
        if headers.get("x-ct-admin-token").and_then(|v| v.to_str().ok()) != Some(&hex(&[0x7au8; 32]))
        {
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        }
        let holder = body.get("holder").and_then(|v| v.as_str()).unwrap_or("");
        if holder == hex(&[0x33u8; 32]) {
            Ok(Json(serde_json::json!({ "operator_pubkey": hex(&[0xEEu8; 32]) })))
        } else {
            Err(axum::http::StatusCode::NOT_FOUND)
        }
    }

    async fn spawn_mock_cp() -> String {
        let app = Router::new().route("/internal/channel/authorize", post(mock_authorize));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn resolver_returns_operator_key_only_for_a_member_with_the_admin_token() {
        let base = spawn_mock_cp().await;
        let channel = ChannelId([0xC5u8; 32]);

        // Correct token + member -> the operator key.
        let good = ChannelAuthorizer::new(&base, &[0x7au8; 32]);
        assert_eq!(
            good.authorize(&channel, &[0x33u8; 32]).await,
            Some([0xEEu8; 32]),
            "member resolves the operator key"
        );
        // Correct token, non-member -> None (fail-closed on 404).
        assert_eq!(good.authorize(&channel, &[0x44u8; 32]).await, None, "non-member denied");
        // Wrong admin token -> None (fail-closed on 401).
        let bad = ChannelAuthorizer::new(&base, &[0u8; 32]);
        assert_eq!(bad.authorize(&channel, &[0x33u8; 32]).await, None, "bad token denied");
        // Unreachable CP -> None (fail-closed on transport error).
        let down = ChannelAuthorizer::new("http://127.0.0.1:1", &[0x7au8; 32]);
        assert_eq!(down.authorize(&channel, &[0x33u8; 32]).await, None, "unreachable CP denied");
    }
}
