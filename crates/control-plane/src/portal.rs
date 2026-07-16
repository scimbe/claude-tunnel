//! Customer self-service portal (#25) — server-rendered, self-contained HTML
//! (CSP-safe, no external assets), distinct from the operator status page at `/`.
//!
//! - PP1: the portal shell (`GET /portal`) + SSO-login entry (`GET /portal/login`)
//!   that starts the OIDC Authorization Code flow.
//! - PP2: `GET /portal/callback` with the CSRF-`state` cookie binding.
//! - PP3 (this addition): the **signed session** primitive — a tamper-proof
//!   session cookie, the logged-in customer home (`GET /portal/home`) gated on it,
//!   and logout (`GET /portal/logout`). The code→token exchange that mints a
//!   session at the callback lands in PP4.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

/// Name of the single-use CSRF cookie that binds the `state` in the authorize
/// redirect to the browser, so the callback can reject a forged/replayed `state`.
const STATE_COOKIE: &str = "ct_portal_state";

/// Name of the signed session cookie identifying the logged-in customer.
const SESSION_COOKIE: &str = "ct_portal_session";

/// Session lifetime (8 hours).
const SESSION_TTL_SECS: u64 = 8 * 60 * 60;

/// Router state: the OIDC login config plus the key that signs session cookies.
#[derive(Clone)]
struct PortalState {
    oidc: Option<PortalOidc>,
    session_key: Arc<[u8]>,
}

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
pub fn portal_router(oidc: Option<PortalOidc>, session_key: &[u8]) -> Router {
    let state = PortalState {
        oidc,
        session_key: Arc::from(session_key.to_vec()),
    };
    Router::new()
        .route("/portal", get(portal_home))
        .route("/portal/login", get(portal_login))
        .route("/portal/callback", get(portal_callback))
        .route("/portal/home", get(portal_home_authed))
        .route("/portal/logout", get(portal_logout))
        .with_state(state)
}

async fn portal_home() -> Html<&'static str> {
    Html(PORTAL_HTML)
}

async fn portal_login(State(st): State<PortalState>) -> Response {
    match st.oidc {
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
    State(st): State<PortalState>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    if st.oidc.is_none() {
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

/// `GET /portal/home` (#25 PP3): the logged-in customer home. Gated on a valid
/// signed session cookie; without one the visitor is bounced to the shell.
async fn portal_home_authed(State(st): State<PortalState>, headers: HeaderMap) -> Response {
    match session_subject(&st, &headers) {
        Some(sub) => Html(home_html(&sub)).into_response(),
        None => Redirect::to("/portal").into_response(),
    }
}

/// `GET /portal/logout` (#25 PP3): clear the session cookie and return to the shell.
async fn portal_logout() -> Response {
    let mut resp = Redirect::to("/portal").into_response();
    set_cookie(&mut resp, &cleared_session_cookie());
    resp
}

fn sso_unconfigured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "SSO login is not configured on this deployment",
    )
        .into_response()
}

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation label mixed into every session MAC, so the signing key can
/// never be confused with another use of the same secret.
const SESSION_CTX: &[u8] = b"ct-portal-session-v1";

fn session_mac(key: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(SESSION_CTX);
    m.update(payload);
    m.finalize().into_bytes().to_vec()
}

/// Mint a signed session token for `subject`, valid until `exp` (unix seconds).
/// Format: `<hex(subject)>:<exp>.<hex(hmac)>` — opaque, tamper-evident, and the
/// subject carries no secret. Consumed by the PP4 token-exchange callback (which
/// mints a session once it has the verified subject); exercised now by tests.
#[allow(dead_code)]
fn sign_session(key: &[u8], subject: &str, exp: u64) -> String {
    let payload = format!("{}:{exp}", hex(subject.as_bytes()));
    format!("{payload}.{}", hex(&session_mac(key, payload.as_bytes())))
}

/// Verify a session token and return its subject if the MAC checks out and it
/// has not expired (`now` in unix seconds). Constant-time MAC comparison.
fn verify_session(key: &[u8], token: &str, now: u64) -> Option<String> {
    let (payload, tag_hex) = token.rsplit_once('.')?;
    let (sub_hex, exp_str) = payload.split_once(':')?;
    if exp_str.parse::<u64>().ok()? <= now {
        return None;
    }
    if !ct_eq(&session_mac(key, payload.as_bytes()), &unhex(tag_hex)?) {
        return None;
    }
    String::from_utf8(unhex(sub_hex)?).ok()
}

/// Constant-time byte-slice equality, so MAC verification leaks no timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Resolve the subject of the request's session cookie, if valid and unexpired.
fn session_subject(st: &PortalState, headers: &HeaderMap) -> Option<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    verify_session(&st.session_key, &cookie_value(headers, SESSION_COOKIE)?, now)
}

/// The session cookie: HttpOnly, Secure, SameSite=Lax, scoped to `/portal`.
/// Set by the PP4 callback once a session is minted; exercised now by tests.
#[allow(dead_code)]
fn session_cookie(token: &str) -> String {
    format!("{SESSION_COOKIE}={token}; Path=/portal; Max-Age={SESSION_TTL_SECS}; HttpOnly; Secure; SameSite=Lax")
}

fn cleared_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/portal; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

#[allow(dead_code)] // used by sign_session (PP4 mint) + tests
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// HTML-escape untrusted text before embedding it in the page.
fn escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '"' => "&quot;".chars().collect(),
            '\'' => "&#39;".chars().collect(),
            other => vec![other],
        })
        .collect()
}

/// The logged-in customer home page (self-contained, CSP-safe).
fn home_html(subject: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>claude-tunnel — your account</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:0;background:#0e1116;color:#e6edf3;
      display:flex;min-height:100vh;align-items:center;justify-content:center}}
 .card{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:2.5rem;max-width:480px}}
 h1{{font-size:1.3rem;margin:.2rem 0 1rem}} .sub{{color:#8b949e;font-size:.9rem;word-break:break-all}}
 a.btn{{display:inline-block;margin-top:1.4rem;background:#21262d;color:#e6edf3;text-decoration:none;
       padding:.55rem 1.1rem;border-radius:8px;border:1px solid #30363d}} a.btn:hover{{background:#30363d}}
</style></head><body>
<div class="card">
 <h1>Signed in</h1>
 <div class="sub">Subject: {subject}</div>
 <a class="btn" href="/portal/logout">Sign out</a>
</div>
</body></html>"#,
        subject = escape(subject)
    )
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

    const TEST_KEY: &[u8] = b"portal-test-session-key";

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
        let app = portal_router(None, TEST_KEY);
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
        let app = portal_router(Some(cfg), TEST_KEY);
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
        let app = portal_router(Some(cfg()), TEST_KEY);
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
        let app = portal_router(Some(cfg()), TEST_KEY);

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
        let app = portal_router(Some(cfg()), TEST_KEY);
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
        let app = portal_router(None, TEST_KEY);
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
        let app = portal_router(None, TEST_KEY);
        let resp = app
            .oneshot(Request::get("/portal/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn session_sign_verify_roundtrips_and_rejects_tampering() {
        // #25 PP3: a signed session yields its subject; any tampering fails.
        let now = 1_000_000u64;
        let tok = sign_session(TEST_KEY, "kc-user-7", now + SESSION_TTL_SECS);
        assert_eq!(verify_session(TEST_KEY, &tok, now).as_deref(), Some("kc-user-7"));

        // Wrong key -> rejected.
        assert!(verify_session(b"other-key", &tok, now).is_none());
        // Expired -> rejected.
        assert!(verify_session(TEST_KEY, &tok, now + SESSION_TTL_SECS + 1).is_none());
        // Flipped MAC byte -> rejected.
        let mut bad = tok.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'a' { 'b' } else { 'a' });
        assert!(verify_session(TEST_KEY, &bad, now).is_none());
        // Garbage -> rejected, no panic.
        assert!(verify_session(TEST_KEY, "not-a-token", now).is_none());
    }

    #[tokio::test]
    async fn home_requires_a_valid_session_else_redirects() {
        let app = portal_router(Some(cfg()), TEST_KEY);

        // No session cookie -> bounce to the shell.
        let resp = app
            .clone()
            .oneshot(Request::get("/portal/home").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/portal");

        // A valid session cookie -> the logged-in home showing the subject.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let tok = sign_session(TEST_KEY, "kc-user-7", now + SESSION_TTL_SECS);
        let resp = app
            .oneshot(
                Request::get("/portal/home")
                    .header("cookie", format!("{SESSION_COOKIE}={tok}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("kc-user-7"), "shows the signed-in subject");
        assert!(html.contains("/portal/logout"), "offers sign-out");
    }

    #[tokio::test]
    async fn logout_clears_the_session_cookie() {
        let app = portal_router(Some(cfg()), TEST_KEY);
        let resp = app
            .oneshot(Request::get("/portal/logout").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/portal");
        let cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(cookie.starts_with("ct_portal_session=;"), "session cookie cleared");
        assert!(cookie.contains("Max-Age=0"));
    }

    #[test]
    fn session_cookie_carries_the_hardening_flags() {
        let c = session_cookie("tok123");
        assert!(c.starts_with("ct_portal_session=tok123;"));
        for flag in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/portal"] {
            assert!(c.contains(flag), "cookie sets {flag}");
        }
    }
}
