//! Customer self-service portal (#25) — server-rendered, self-contained HTML
//! (CSP-safe, no external assets), distinct from the operator status page at `/`.
//!
//! PP1 (this file): the portal shell (`GET /portal`) plus the SSO-login entry
//! (`GET /portal/login`), which starts the OIDC Authorization Code flow by
//! redirecting to the IdP's authorize endpoint. The code→token callback, the
//! session cookie and CSRF-`state` validation land in PP2; logout in PP3.

use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::get;
use axum::Router;

/// OIDC login configuration for the Authorization Code flow (#25). Built from
/// env at startup. The client **secret** is deliberately NOT held here — it is
/// only needed at the callback token exchange (PP2) and read from the
/// environment then, never logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortalOidc {
    /// The IdP authorize endpoint (Keycloak: `<issuer>/protocol/openid-connect/auth`).
    pub authorize_url: String,
    pub client_id: String,
    pub redirect_uri: String,
}

impl PortalOidc {
    /// Read the login config from `CT_OIDC_CLIENT_ID`, `CT_OIDC_REDIRECT_URI`,
    /// and either `CT_OIDC_AUTHORIZE_URL` or (derived) `CT_OIDC_ISSUER`. Returns
    /// `None` if login is not fully configured — the portal then shows the shell
    /// but the login button reports "SSO not configured".
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable core of [`from_env`]: resolve the config from a variable lookup.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let nonempty = |k: &str| get(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let client_id = nonempty("CT_OIDC_CLIENT_ID")?;
        let redirect_uri = nonempty("CT_OIDC_REDIRECT_URI")?;
        let authorize_url = nonempty("CT_OIDC_AUTHORIZE_URL").or_else(|| {
            nonempty("CT_OIDC_ISSUER")
                .map(|iss| format!("{}/protocol/openid-connect/auth", iss.trim_end_matches('/')))
        })?;
        Some(Self {
            authorize_url,
            client_id,
            redirect_uri,
        })
    }

    /// Build the Authorization Code redirect URL, carrying a CSRF `state`.
    fn authorize_redirect(&self, state: &str) -> String {
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid&state={}",
            self.authorize_url,
            urlencode(&self.client_id),
            urlencode(&self.redirect_uri),
            urlencode(state),
        )
    }
}

/// Build the customer portal router (#25 PP1): `GET /portal` (shell) and
/// `GET /portal/login` (SSO Authorization Code redirect).
pub fn portal_router(oidc: Option<PortalOidc>) -> Router {
    Router::new()
        .route("/portal", get(portal_home))
        .route("/portal/login", get(portal_login))
        .with_state(oidc)
}

async fn portal_home() -> Html<&'static str> {
    Html(PORTAL_HTML)
}

async fn portal_login(State(oidc): State<Option<PortalOidc>>) -> axum::response::Response {
    match oidc {
        Some(cfg) => Redirect::to(&cfg.authorize_redirect(&random_state())).into_response(),
        None => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "SSO login is not configured on this deployment",
        )
            .into_response(),
    }
}

/// A fresh, unpredictable CSRF `state` value. PP2 will bind it to a cookie and
/// validate it at the callback; here it simply makes the redirect single-use-ish.
fn random_state() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Percent-encode a query-parameter value (encode everything but the RFC 3986
/// unreserved set), so `redirect_uri` (with `:` and `/`) survives intact.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The customer portal shell (logged-out state): a self-contained, CSP-safe HTML
/// page with a "Sign in with SSO" call to action. Themed like the operator page.
const PORTAL_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>claude-tunnel — customer portal</title>
<style>
 body{font-family:system-ui,sans-serif;margin:0;background:#0e1116;color:#e6edf3;
      display:flex;min-height:100vh;align-items:center;justify-content:center}
 .card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:2.5rem;max-width:420px;text-align:center}
 h1{font-size:1.4rem;margin:.2rem 0 .4rem} .sub{color:#8b949e;font-size:.95rem;margin-bottom:1.6rem}
 a.btn{display:inline-block;background:#238636;color:#fff;text-decoration:none;padding:.7rem 1.4rem;
       border-radius:8px;font-weight:600} a.btn:hover{background:#2ea043}
 .foot{color:#8b949e;font-size:.8rem;margin-top:1.6rem}
</style></head><body>
<div class="card">
 <h1>claude-tunnel</h1>
 <div class="sub">Sign in to manage your account and tunnels.</div>
 <a class="btn" href="/portal/login">Sign in with SSO</a>
 <div class="foot">Provider-blind tunnels — the operator never sees your payload.</div>
</div>
</body></html>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[test]
    fn from_lookup_derives_authorize_url_from_issuer() {
        let cfg = PortalOidc::from_lookup(|k| {
            match k {
                "CT_OIDC_CLIENT_ID" => Some("ct-portal".into()),
                "CT_OIDC_REDIRECT_URI" => Some("https://portal.example/portal/callback".into()),
                "CT_OIDC_ISSUER" => Some("https://kc.example/realms/ct/".into()),
                _ => None,
            }
        })
        .expect("configured");
        assert_eq!(
            cfg.authorize_url,
            "https://kc.example/realms/ct/protocol/openid-connect/auth"
        );
        // Missing redirect_uri -> not configured.
        assert!(PortalOidc::from_lookup(|k| (k == "CT_OIDC_CLIENT_ID").then(|| "x".into())).is_none());
    }

    #[tokio::test]
    async fn portal_home_renders_the_sso_cta() {
        let app = portal_router(None);
        let resp = app
            .oneshot(Request::get("/portal").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Sign in with SSO"), "login CTA present");
        assert!(html.contains("href=\"/portal/login\""), "links to the login route");
        assert!(!html.contains("http://") && !html.contains("https://cdn"), "self-contained, no external assets");
    }

    #[tokio::test]
    async fn login_redirects_to_the_authorize_endpoint() {
        let cfg = PortalOidc {
            authorize_url: "https://kc.example/realms/ct/protocol/openid-connect/auth".into(),
            client_id: "ct-portal".into(),
            redirect_uri: "https://portal.example/portal/callback".into(),
        };
        let app = portal_router(Some(cfg));
        let resp = app
            .oneshot(Request::get("/portal/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(loc.starts_with("https://kc.example/realms/ct/protocol/openid-connect/auth?"));
        assert!(loc.contains("response_type=code"));
        assert!(loc.contains("client_id=ct-portal"));
        assert!(loc.contains("redirect_uri=https%3A%2F%2Fportal.example%2Fportal%2Fcallback"));
        assert!(loc.contains("scope=openid"));
        assert!(loc.contains("state="), "carries a CSRF state");
    }

    #[tokio::test]
    async fn login_without_config_reports_unconfigured() {
        let app = portal_router(None);
        let resp = app
            .oneshot(Request::get("/portal/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
