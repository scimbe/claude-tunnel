//! Customer self-service portal (#25) — server-rendered, self-contained HTML
//! (CSP-safe, no external assets), distinct from the operator status page at `/`.
//!
//! PP1 (this file): the portal shell (`GET /portal`) plus the SSO-login entry
//! (`GET /portal/login`), which starts the OIDC Authorization Code flow by
//! redirecting to the IdP's authorize endpoint. The code→token callback, the
//! session cookie and CSRF-`state` validation land in PP2; logout in PP3.

use axum::extract::{Query, State};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

/// Name of the single-use CSRF cookie that binds the `state` in the authorize
/// redirect to the browser, so the callback can reject a forged/replayed `state`.
const STATE_COOKIE: &str = "ct_portal_state";

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
        .route("/portal/callback", get(portal_callback))
        .with_state(oidc)
}

async fn portal_home() -> Html<&'static str> {
    Html(PORTAL_HTML)
}

async fn portal_login(State(oidc): State<Option<PortalOidc>>) -> Response {
    match oidc {
        Some(cfg) => {
            // Mint the CSRF `state`, carry it BOTH in the authorize redirect and
            // in a single-use HttpOnly cookie so the callback can prove the
            // response came back to the same browser we sent out.
            let state = random_state();
            let mut resp = Redirect::to(&cfg.authorize_redirect(&state)).into_response();
            set_cookie(&mut resp, &state_cookie(&state));
            resp
        }
        None => sso_unconfigured(),
    }
}

/// Query parameters the IdP appends to the `redirect_uri` on success.
#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

/// `GET /portal/callback` (#25 PP2): the OIDC Authorization Code redirect target.
///
/// This sub-packet enforces the **CSRF `state` binding**: the `state` echoed by
/// the IdP must equal the one in the single-use cookie set at login, else the
/// request is rejected before anything else happens. On a valid `state` the
/// single-use cookie is cleared. The code→token exchange and the session cookie
/// land in PP3 — `code` is intentionally not consumed yet.
async fn portal_callback(
    State(oidc): State<Option<PortalOidc>>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    if oidc.is_none() {
        return sso_unconfigured();
    }
    let code = q.code.as_deref().unwrap_or("");
    let state = q.state.as_deref().unwrap_or("");
    if code.is_empty() || state.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing code or state").into_response();
    }
    // The `state` must match the single-use cookie from login (CSRF defence).
    if cookie_value(&headers, STATE_COOKIE).as_deref() != Some(state) {
        return (StatusCode::FORBIDDEN, "invalid or missing CSRF state").into_response();
    }
    // Valid. PP3: exchange `code` at the token endpoint and mint a session
    // cookie. For now, retire the single-use state cookie and show an interstitial.
    let mut resp = Html(CALLBACK_HTML).into_response();
    set_cookie(&mut resp, &cleared_state_cookie());
    resp
}

fn sso_unconfigured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "SSO login is not configured on this deployment",
    )
        .into_response()
}

/// Attach a `Set-Cookie` header (skipped silently if the value is not a valid
/// header — it never is for our fixed, percent-safe cookie strings).
fn set_cookie(resp: &mut Response, cookie: &str) {
    if let Ok(v) = HeaderValue::from_str(cookie) {
        resp.headers_mut().append(SET_COOKIE, v);
    }
}

/// The single-use CSRF state cookie: HttpOnly (no JS access), Secure (HTTPS
/// only), SameSite=Lax (sent on the top-level IdP redirect back), scoped to
/// `/portal`, expiring in 10 minutes.
fn state_cookie(state: &str) -> String {
    format!("{STATE_COOKIE}={state}; Path=/portal; Max-Age=600; HttpOnly; Secure; SameSite=Lax")
}

/// The same cookie with an immediate expiry, to retire it after the callback.
fn cleared_state_cookie() -> String {
    format!("{STATE_COOKIE}=; Path=/portal; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

/// Read a named cookie from the request `Cookie` header, if present.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|part| {
        let part = part.trim();
        part.strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
            .map(|v| v.to_string())
    })
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

/// Interstitial shown after a valid callback while the session is established.
/// PP3 replaces this with the token exchange + a redirect to the customer home.
const CALLBACK_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>claude-tunnel — signing in</title>
<style>
 body{font-family:system-ui,sans-serif;margin:0;background:#0e1116;color:#e6edf3;
      display:flex;min-height:100vh;align-items:center;justify-content:center}
 .card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:2.5rem;max-width:420px;text-align:center}
 .sub{color:#8b949e;font-size:.95rem}
</style></head><body>
<div class="card">
 <h1>Signing you in…</h1>
 <div class="sub">Your sign-in was verified. Completing your session.</div>
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

    fn cfg() -> PortalOidc {
        PortalOidc {
            authorize_url: "https://kc.example/realms/ct/protocol/openid-connect/auth".into(),
            client_id: "ct-portal".into(),
            redirect_uri: "https://portal.example/portal/callback".into(),
        }
    }

    #[tokio::test]
    async fn login_binds_state_in_an_httponly_cookie_matching_the_redirect() {
        // #25 PP2: the CSRF state travels both in the redirect and a single-use cookie.
        let app = portal_router(Some(cfg()));
        let resp = app
            .oneshot(Request::get("/portal/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
        let cookie = resp
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(cookie.contains("ct_portal_state="), "sets the state cookie");
        assert!(cookie.contains("HttpOnly"), "not readable by JS");
        assert!(cookie.contains("Secure"), "HTTPS only");
        assert!(cookie.contains("SameSite=Lax"), "sent on the IdP top-level redirect back");
        // The cookie's state must equal the redirect's state.
        let from_cookie = cookie
            .split(';')
            .next()
            .unwrap()
            .trim_start_matches("ct_portal_state=")
            .to_string();
        assert!(
            loc.contains(&format!("state={from_cookie}")),
            "redirect state matches the cookie"
        );
    }

    #[tokio::test]
    async fn callback_rejects_missing_params_and_mismatched_state() {
        let app = portal_router(Some(cfg()));

        // Missing code/state -> 400.
        let resp = app
            .clone()
            .oneshot(Request::get("/portal/callback?code=abc").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // State present but no cookie -> 403 (CSRF).
        let resp = app
            .clone()
            .oneshot(
                Request::get("/portal/callback?code=abc&state=s1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // State present but cookie differs -> 403 (CSRF).
        let resp = app
            .oneshot(
                Request::get("/portal/callback?code=abc&state=s1")
                    .header("cookie", "ct_portal_state=OTHER")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn callback_accepts_matching_state_and_clears_the_cookie() {
        let app = portal_router(Some(cfg()));
        let resp = app
            .oneshot(
                Request::get("/portal/callback?code=abc&state=s1")
                    .header("cookie", "ct_portal_state=s1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(cookie.starts_with("ct_portal_state=;"), "state cookie is cleared");
        assert!(cookie.contains("Max-Age=0"), "single-use cookie retired");
    }

    #[tokio::test]
    async fn callback_reports_unconfigured_without_oidc() {
        let app = portal_router(None);
        let resp = app
            .oneshot(
                Request::get("/portal/callback?code=abc&state=s1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
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
