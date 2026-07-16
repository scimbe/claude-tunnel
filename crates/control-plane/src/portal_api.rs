//! Authenticated customer-portal API (#26–#29) — the logged-in surface behind
//! the SSO session (#25). Every endpoint resolves the caller's subject from the
//! signed session cookie via [`crate::portal::session_subject_for`]; without a
//! valid session the visitor is bounced to the portal shell. All pages are
//! server-rendered, self-contained, CSP-safe HTML, and every subject only ever
//! sees or changes their own data.

use std::sync::Arc;

use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;

use crate::accounts::AccountId;
use crate::installer::{install_one_liner, InstallOs};
use crate::portal::{escape, session_subject_for};
use crate::storage::{GrantError, SqliteEnrollment, SqliteLedger, SqliteTunnelStore};
use ct_common::TenantId;

/// Shared state for the authed portal API.
#[derive(Clone)]
struct ApiState {
    session_key: Arc<[u8]>,
    ledger: Arc<SqliteLedger>,
    tunnels: Arc<SqliteTunnelStore>,
    enrollment: Arc<SqliteEnrollment>,
    /// Public portal origin (e.g. `https://portal.example`) baked into installers.
    portal_base: Arc<str>,
}

/// Build the authenticated portal API router (#26 account, #27 tunnels, #28 install).
pub fn portal_api_router(
    session_key: &[u8],
    ledger: Arc<SqliteLedger>,
    tunnels: Arc<SqliteTunnelStore>,
    enrollment: Arc<SqliteEnrollment>,
    portal_base: &str,
) -> Router {
    let state = ApiState {
        session_key: Arc::from(session_key.to_vec()),
        ledger,
        tunnels,
        enrollment,
        portal_base: Arc::from(portal_base),
    };
    Router::new()
        .route("/portal/account", get(account_page))
        .route("/portal/account/credits", post(buy_credits))
        .route("/portal/tunnels", get(tunnels_page).post(create_tunnel))
        .route("/portal/tunnels/:id/delete", post(delete_tunnel))
        .route("/portal/tunnels/:id/install", get(install_page))
        .route("/portal/tunnels/:id/grants", get(grants_page).post(add_grant))
        .route("/portal/tunnels/:id/grants/:grantee/delete", post(delete_grant))
        .with_state(state)
}

/// Resolve the caller's account from the session, or an early response
/// (redirect to the shell when unauthenticated, 500 on a store error).
fn account_for_session(st: &ApiState, headers: &HeaderMap) -> Result<(String, AccountId), Response> {
    let subject = session_subject_for(&st.session_key, headers)
        .ok_or_else(|| Redirect::to("/portal").into_response())?;
    let account = st
        .ledger
        .account_for_subject(&subject)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?;
    Ok((subject, account))
}

/// `GET /portal/account` (#26 PP2): the logged-in customer's account page —
/// account id, credit balance (Guthaben) and subject. Self-scoped: the subject
/// comes from the session, so a caller only ever sees their own account.
async fn account_page(State(st): State<ApiState>, headers: HeaderMap) -> Response {
    let (subject, account) = match account_for_session(&st, &headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let balance = st.ledger.balance(&account).unwrap_or(0);
    Html(account_html(&subject, &hex(&account.0), balance)).into_response()
}

/// Credits to add, from the buy-credits form.
#[derive(Deserialize)]
struct BuyCreditsForm {
    credits: u64,
}

/// `POST /portal/account/credits` (#26): create a payment intent for the
/// caller's own account against the existing billing surface. Actual crediting
/// happens only via the signature-verified provider webhook (never here), so
/// this just registers the intent the customer then pays.
async fn buy_credits(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Form(form): Form<BuyCreditsForm>,
) -> Response {
    let (_subject, account) = match account_for_session(&st, &headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if form.credits == 0 {
        return (StatusCode::BAD_REQUEST, "credits must be > 0").into_response();
    }
    let intent = match st.ledger.create_intent(&account, form.credits) {
        Ok(id) => id,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let body = format!(
        r#"<h1>Payment intent created</h1>
<div class="row"><span class="k">Credits</span><span class="v">{credits}</span></div>
<div class="row"><span class="k">Intent&nbsp;ID</span><span class="v"><code>{intent}</code></span></div>
<h2>Next</h2>
<p class="k">Pay this intent with your provider. Your balance updates once the
provider's signed webhook confirms the payment.</p>
<a class="btn sec" href="/portal/account">Back to account</a>"#,
        credits = form.credits,
        intent = escape(&hex(&intent.0)),
    );
    Html(page("buy credits", &body)).into_response()
}

/// A new tunnel from the create form.
#[derive(Deserialize)]
struct CreateTunnelForm {
    name: String,
    hostname: Option<String>,
}

/// `GET /portal/tunnels` (#27): list the caller's own tunnels + a create form.
async fn tunnels_page(State(st): State<ApiState>, headers: HeaderMap) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    match st.tunnels.list_for_subject(&subject) {
        Ok(tunnels) => Html(tunnels_html(&tunnels)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// `POST /portal/tunnels` (#27): create a tunnel owned by the caller.
async fn create_tunnel(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Form(form): Form<CreateTunnelForm>,
) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let name = form.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "tunnel name required").into_response();
    }
    let hostname = form
        .hostname
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Err(e) = st.tunnels.create(&subject, name, hostname) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    Redirect::to("/portal/tunnels").into_response()
}

/// `POST /portal/tunnels/{id}/delete` (#27): revoke one of the caller's tunnels.
/// Self-scoped: `revoke` only removes a row owned by this subject.
async fn delete_tunnel(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let _ = st.tunnels.revoke(&subject, &id);
    Redirect::to("/portal/tunnels").into_response()
}

/// Which OS installer to show; absent = show all.
#[derive(Deserialize)]
struct InstallQuery {
    os: Option<String>,
}

/// `GET /portal/tunnels/:id/install` (#28): render the copy-paste one-liner(s)
/// that install + onboard an agent for one of the caller's own tunnels. A fresh,
/// single-use join token is minted per request and embedded via an env var.
///
/// The token is a secret: it is shown once to the authenticated owner and never
/// logged, cached or persisted anywhere in cleartext.
async fn install_page(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<InstallQuery>,
) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    // The tunnel's routing token doubles as the ownership gate: `None` when the
    // tunnel is unknown or owned by someone else (only the owner may onboard).
    let routing_token = match st.tunnels.routing_token(&subject, &id) {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such tunnel").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    // Mint a fresh single-use join token bound to the customer (subject as tenant).
    let token = match st.enrollment.issue_join_token(&TenantId(subject.clone())) {
        Ok(t) => hex(&t.0),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let oses = match q.os.as_deref().and_then(InstallOs::parse) {
        Some(os) => vec![os],
        None => vec![InstallOs::Unix, InstallOs::Windows],
    };
    let blocks = oses
        .iter()
        .map(|os| {
            let label = match os {
                InstallOs::Unix => "Linux / macOS",
                InstallOs::Windows => "Windows (PowerShell)",
            };
            let cmd = install_one_liner(&st.portal_base, &token, &routing_token, *os);
            format!("<h2>{label}</h2><pre><code>{}</code></pre>", escape(&cmd))
        })
        .collect::<String>();
    let body = format!(
        r#"<h1>Install an agent</h1>
<p class="k"><strong>Single-use token — copy the command now; it is shown only once.</strong></p>
{blocks}
<a class="btn sec" href="/portal/tunnels">Back to tunnels</a>"#,
    );
    Html(page("install", &body)).into_response()
}

/// A subject to grant tunnel access to.
#[derive(Deserialize)]
struct GrantForm {
    grantee: String,
}

/// Map a grant-management result: `NotOwner` (or unknown tunnel) -> 404 so a
/// non-owner cannot even probe a tunnel's sharing; DB errors -> 500.
fn grant_err(e: GrantError) -> Response {
    match e {
        GrantError::NotOwner => (StatusCode::NOT_FOUND, "no such tunnel").into_response(),
        GrantError::Db(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// `GET /portal/tunnels/:id/grants` (#29): list the subjects a tunnel is shared
/// with + an add form. Owner-only.
async fn grants_page(State(st): State<ApiState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    match st.tunnels.list_grants(&subject, &id) {
        Ok(grantees) => Html(grants_html(&id, &grantees)).into_response(),
        Err(e) => grant_err(e),
    }
}

/// `POST /portal/tunnels/:id/grants` (#29): grant a subject access. Owner-only.
async fn add_grant(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<GrantForm>,
) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let grantee = form.grantee.trim();
    if grantee.is_empty() {
        return (StatusCode::BAD_REQUEST, "grantee required").into_response();
    }
    match st.tunnels.grant(&subject, &id, grantee) {
        Ok(()) => Redirect::to(&format!("/portal/tunnels/{id}/grants")).into_response(),
        Err(e) => grant_err(e),
    }
}

/// `POST /portal/tunnels/:id/grants/:grantee/delete` (#29): revoke a grant. Owner-only.
async fn delete_grant(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path((id, grantee)): Path<(String, String)>,
) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    match st.tunnels.revoke_grant(&subject, &id, &grantee) {
        Ok(_) => Redirect::to(&format!("/portal/tunnels/{id}/grants")).into_response(),
        Err(e) => grant_err(e),
    }
}

fn grants_html(id: &str, grantees: &[String]) -> String {
    let rows = if grantees.is_empty() {
        "<p class=\"k\">Not shared with anyone yet.</p>".to_string()
    } else {
        grantees
            .iter()
            .map(|g| {
                format!(
                    r#"<div class="row"><span class="v">{g}</span>
 <form class="inline" method="post" action="/portal/tunnels/{id}/grants/{ge}/delete">
  <button class="sec" type="submit">Revoke</button></form></div>"#,
                    g = escape(g),
                    id = escape(id),
                    ge = escape(g),
                )
            })
            .collect::<String>()
    };
    let body = format!(
        r#"<h1>Share this tunnel</h1>
<p class="k">Grant other signed-in subjects access to this tunnel.</p>
{rows}
<h2>Add a subject</h2>
<form method="post" action="/portal/tunnels/{id}/grants">
 <input type="text" name="grantee" placeholder="subject" required>
 <button type="submit">Grant</button>
</form>
<a class="btn sec" href="/portal/tunnels">Back to tunnels</a>"#,
        id = escape(id),
    );
    page("share tunnel", &body)
}

fn tunnels_html(tunnels: &[crate::storage::SubjectTunnel]) -> String {
    let rows = if tunnels.is_empty() {
        "<p class=\"k\">No tunnels yet. Create one below.</p>".to_string()
    } else {
        tunnels
            .iter()
            .map(|t| {
                let host = t
                    .hostname
                    .as_deref()
                    .map(|h| format!(" · <code>{}</code>", escape(h)))
                    .unwrap_or_default();
                format!(
                    r#"<div class="row"><span class="v">{name}{host}</span><span>
 <a class="btn sec" href="/portal/tunnels/{id}/install">Install</a>
 <a class="btn sec" href="/portal/tunnels/{id}/grants">Share</a>
 <form class="inline" method="post" action="/portal/tunnels/{id}/delete">
  <button class="sec" type="submit">Revoke</button></form>
</span></div>"#,
                    name = escape(&t.name),
                    host = host,
                    id = escape(&t.id),
                )
            })
            .collect::<String>()
    };
    let body = format!(
        r#"<h1>Your tunnels</h1>
{rows}
<h2>Create a tunnel</h2>
<form method="post" action="/portal/tunnels">
 <input type="text" name="name" placeholder="name" required>
 <input type="text" name="hostname" placeholder="hostname (optional, browser plane)">
 <button type="submit">Create</button>
</form>"#,
    );
    page("your tunnels", &body)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Shared page chrome: dark card layout, a title and body. `body` is trusted
/// (built from escaped parts by the caller).
pub(crate) fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>claude-tunnel — {title}</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:0;background:#0e1116;color:#e6edf3;
      display:flex;min-height:100vh;align-items:flex-start;justify-content:center;padding:3rem 1rem}}
 .card{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:2rem;max-width:640px;width:100%}}
 h1{{font-size:1.3rem;margin:.1rem 0 1rem}} h2{{font-size:1rem;color:#8b949e;margin:1.4rem 0 .6rem}}
 .row{{display:flex;justify-content:space-between;padding:.5rem 0;border-bottom:1px solid #21262d}}
 .k{{color:#8b949e}} .v{{word-break:break-all}}
 nav a{{color:#58a6ff;text-decoration:none;margin-right:1rem;font-size:.9rem}} nav{{margin-bottom:1.2rem}}
 a.btn,button{{background:#238636;color:#fff;border:0;border-radius:8px;padding:.5rem 1rem;
      font:inherit;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block}}
 a.btn.sec,button.sec{{background:#21262d;border:1px solid #30363d;color:#e6edf3;font-weight:500}}
 input,select{{background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:8px;padding:.5rem;font:inherit}}
 code{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:.15rem .4rem}}
 form.inline{{display:inline}}
</style></head><body>
<div class="card">
<nav><a href="/portal/account">Account</a><a href="/portal/tunnels">Tunnels</a><a href="/portal/logout">Sign out</a></nav>
{body}
</div>
</body></html>"#
    )
}

fn account_html(subject: &str, account_hex: &str, balance: u64) -> String {
    let body = format!(
        r#"<h1>Your account</h1>
<div class="row"><span class="k">Subject</span><span class="v">{subject}</span></div>
<div class="row"><span class="k">Account&nbsp;ID</span><span class="v">{account}</span></div>
<div class="row"><span class="k">Credit&nbsp;balance</span><span class="v">{balance}</span></div>
<h2>Buy credits</h2>
<form method="post" action="/portal/account/credits">
 <input type="number" name="credits" min="1" value="100" required>
 <button type="submit">Create payment intent</button>
</form>"#,
        subject = escape(subject),
        account = escape(account_hex),
        balance = balance,
    );
    page("your account", &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal::sign_session_for_test;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    const KEY: &[u8] = b"portal-api-test-key";

    fn session_header(subject: &str) -> String {
        format!("ct_portal_session={}", sign_session_for_test(KEY, subject))
    }

    fn test_app() -> Router {
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        portal_api_router(KEY, ledger, tunnels, enrollment, "https://portal.example")
    }

    #[tokio::test]
    async fn account_page_requires_a_session() {
        let app = test_app();
        let resp = app
            .oneshot(Request::get("/portal/account").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/portal");
    }

    #[tokio::test]
    async fn account_page_shows_self_scoped_account_and_balance() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::get("/portal/account")
                    .header("cookie", session_header("kc-user-1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("kc-user-1"), "shows the subject");
        assert!(html.contains("Credit&nbsp;balance"), "shows the balance row");
        assert!(html.contains("/portal/account/credits"), "offers buy-credits");
        assert!(html.contains("/portal/logout"), "offers sign-out");
    }

    #[tokio::test]
    async fn buy_credits_creates_an_intent_for_the_callers_account() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::post("/portal/account/credits")
                    .header("cookie", session_header("kc-user-1"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("credits=250"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Payment intent created"));
        assert!(html.contains("250"), "echoes the credit amount");
    }

    #[tokio::test]
    async fn buy_credits_requires_a_session() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::post("/portal/account/credits")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("credits=250"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    async fn get(app: &Router, path: &str, subject: Option<&str>) -> (StatusCode, String) {
        let mut req = Request::get(path);
        if let Some(s) = subject {
            req = req.header("cookie", session_header(s));
        }
        let resp = app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    async fn post_form(app: &Router, path: &str, subject: &str, form: &str) -> StatusCode {
        app.clone()
            .oneshot(
                Request::post(path)
                    .header("cookie", session_header(subject))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    fn first_id(html: &str) -> String {
        html.split("/portal/tunnels/")
            .nth(1)
            .and_then(|s| s.split('/').next())
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn tunnels_are_created_listed_and_revoked_self_scoped() {
        let app = test_app();
        let count = |h: &str| h.matches("/delete").count();

        // Unauthenticated -> bounced.
        assert_eq!(get(&app, "/portal/tunnels", None).await.0, StatusCode::SEE_OTHER);

        // alice creates two tunnels (one with a browser-plane hostname); bob one.
        assert_eq!(
            post_form(&app, "/portal/tunnels", "alice", "name=web&hostname=app.example").await,
            StatusCode::SEE_OTHER
        );
        assert_eq!(post_form(&app, "/portal/tunnels", "alice", "name=ssh").await, StatusCode::SEE_OTHER);
        assert_eq!(post_form(&app, "/portal/tunnels", "bob", "name=db").await, StatusCode::SEE_OTHER);

        // alice sees exactly her two; bob sees exactly his one.
        let (_s, html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert_eq!(count(&html), 2, "alice sees her two tunnels");
        assert!(html.contains("web") && html.contains("app.example") && html.contains("ssh"));
        assert_eq!(count(&get(&app, "/portal/tunnels", Some("bob")).await.1), 1, "bob sees only his own");

        // alice revokes one of her tunnels -> one remains.
        assert_eq!(
            post_form(&app, &format!("/portal/tunnels/{}/delete", first_id(&html)), "alice", "").await,
            StatusCode::SEE_OTHER
        );
        let (_s, after) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert_eq!(count(&after), 1, "one tunnel removed");

        // bob cannot revoke alice's remaining tunnel (self-scoped) — it survives.
        post_form(&app, &format!("/portal/tunnels/{}/delete", first_id(&after)), "bob", "").await;
        assert_eq!(
            count(&get(&app, "/portal/tunnels", Some("alice")).await.1),
            1,
            "self-scoped: bob cannot revoke alice's tunnel"
        );
    }

    #[tokio::test]
    async fn create_tunnel_rejects_an_empty_name() {
        let app = test_app();
        assert_eq!(
            post_form(&app, "/portal/tunnels", "alice", "name=%20").await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn install_page_is_owner_only_and_renders_per_os_one_liners() {
        let app = test_app();
        post_form(&app, "/portal/tunnels", "alice", "name=web").await;
        let id = first_id(&get(&app, "/portal/tunnels", Some("alice")).await.1);

        // Non-owner (bob) is refused; unauthenticated is bounced.
        assert_eq!(
            get(&app, &format!("/portal/tunnels/{id}/install"), Some("bob")).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get(&app, &format!("/portal/tunnels/{id}/install"), None).await.0,
            StatusCode::SEE_OTHER
        );

        // Owner sees both one-liners with the portal base and env-carried token.
        let (status, html) = get(&app, &format!("/portal/tunnels/{id}/install"), Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("curl -fsSL https://portal.example/install.sh"));
        assert!(html.contains("CT_JOIN_TOKEN="), "join token carried via env");
        assert!(html.contains("CT_AGENT_TOKEN="), "tunnel routing token carried via env (#27 RB2)");
        assert!(html.contains("irm https://portal.example/install.ps1 | iex"));
        assert!(html.contains("single-use") || html.contains("Single-use"), "warns token is single-use");

        // os filter renders just one block.
        let (_s, only_win) = get(&app, &format!("/portal/tunnels/{id}/install?os=windows"), Some("alice")).await;
        assert!(only_win.contains("irm ") && !only_win.contains("curl -fsSL"));
    }

    #[tokio::test]
    async fn grants_are_owner_managed_via_http() {
        let app = test_app();
        post_form(&app, "/portal/tunnels", "alice", "name=web").await;
        let id = first_id(&get(&app, "/portal/tunnels", Some("alice")).await.1);

        // Non-owner cannot even view the sharing page.
        assert_eq!(
            get(&app, &format!("/portal/tunnels/{id}/grants"), Some("bob")).await.0,
            StatusCode::NOT_FOUND
        );
        // Non-owner cannot grant.
        assert_eq!(
            post_form(&app, &format!("/portal/tunnels/{id}/grants"), "bob", "grantee=mallory").await,
            StatusCode::NOT_FOUND
        );

        // Owner grants bob, then sees him listed.
        assert_eq!(
            post_form(&app, &format!("/portal/tunnels/{id}/grants"), "alice", "grantee=bob").await,
            StatusCode::SEE_OTHER
        );
        let (status, html) = get(&app, &format!("/portal/tunnels/{id}/grants"), Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("bob"), "grantee listed");

        // Owner revokes bob -> no longer listed.
        assert_eq!(
            post_form(&app, &format!("/portal/tunnels/{id}/grants/bob/delete"), "alice", "").await,
            StatusCode::SEE_OTHER
        );
        let (_s, after) = get(&app, &format!("/portal/tunnels/{id}/grants"), Some("alice")).await;
        assert!(after.contains("Not shared with anyone"), "grant removed");
    }

    #[tokio::test]
    async fn add_grant_rejects_empty_subject() {
        let app = test_app();
        post_form(&app, "/portal/tunnels", "alice", "name=web").await;
        let id = first_id(&get(&app, "/portal/tunnels", Some("alice")).await.1);
        assert_eq!(
            post_form(&app, &format!("/portal/tunnels/{id}/grants"), "alice", "grantee=%20").await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn install_mints_a_fresh_single_use_token_each_request() {
        let app = test_app();
        post_form(&app, "/portal/tunnels", "alice", "name=web").await;
        let id = first_id(&get(&app, "/portal/tunnels", Some("alice")).await.1);
        let extract = |h: &str| {
            h.split("CT_JOIN_TOKEN=")
                .nth(1)
                .and_then(|s| s.split(|c| c == ' ' || c == '<').next())
                .unwrap()
                .to_string()
        };
        let a = extract(&get(&app, &format!("/portal/tunnels/{id}/install?os=linux"), Some("alice")).await.1);
        let b = extract(&get(&app, &format!("/portal/tunnels/{id}/install?os=linux"), Some("alice")).await.1);
        assert_ne!(a, b, "a fresh token is minted per request");
        assert!(!a.is_empty());
    }
}
