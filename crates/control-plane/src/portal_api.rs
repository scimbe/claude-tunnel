//! Authenticated customer-portal API (#26–#29) — the logged-in surface behind
//! the SSO session (#25). Every endpoint resolves the caller's subject from the
//! signed session cookie via [`crate::portal::session_subject_for`]; without a
//! valid session the visitor is bounced to the portal shell. All pages are
//! server-rendered, self-contained, CSP-safe HTML, and every subject only ever
//! sees or changes their own data.

use std::sync::Arc;

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;

use crate::accounts::AccountId;
use crate::portal::{escape, session_subject_for};
use crate::storage::SqliteLedger;

/// Shared state for the authed portal API.
#[derive(Clone)]
struct ApiState {
    session_key: Arc<[u8]>,
    ledger: Arc<SqliteLedger>,
}

/// Build the authenticated portal API router (#26: account page + buy credits).
pub fn portal_api_router(session_key: &[u8], ledger: Arc<SqliteLedger>) -> Router {
    let state = ApiState {
        session_key: Arc::from(session_key.to_vec()),
        ledger,
    };
    Router::new()
        .route("/portal/account", get(account_page))
        .route("/portal/account/credits", post(buy_credits))
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

    #[tokio::test]
    async fn account_page_requires_a_session() {
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let app = portal_api_router(KEY, ledger);
        let resp = app
            .oneshot(Request::get("/portal/account").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/portal");
    }

    #[tokio::test]
    async fn account_page_shows_self_scoped_account_and_balance() {
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let app = portal_api_router(KEY, ledger);
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
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let app = portal_api_router(KEY, ledger);
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
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let app = portal_api_router(KEY, ledger);
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
}
