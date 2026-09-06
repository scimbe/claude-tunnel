//! #780: time-boxed share links for a login-gated hostname -- the owner-facing half.
//!
//! A share link is a signed-by-hash, expiring, optionally single-use token that,
//! presented once to the gate (`crate::gate`'s `GET /gate/share`), sets the visitor's
//! `ct_gate_session` cookie for that ONE hostname -- no account needed. It therefore
//! covers exactly what the login gate covers: every Gelb hostname the edge terminates
//! and Caddy `forward_auth`s to `/gate/check`. A Grün (passthrough) hostname never
//! reaches the gate, so it cannot be share-linked here; the agent-side counterpart for
//! that tier is ct-agent#185.
//!
//! This module adds, per owned tunnel with a hostname, a "Share links" block to the
//! tunnel card (rendered by [`card_blocks`], placed right after the login-gate block),
//! `POST /portal/tunnels/:id/share-links` (mint; answers with a `no-store` page that
//! shows the full URL exactly once) and `POST /portal/tunnels/:id/share-links/:link_id/
//! revoke`. The store (`SqliteTunnelStore::mint_share_link` & co.) keeps only the
//! token's SHA-256; audit rows name the link id, never the token.
//!
//! A child module of `portal_api` (like `uptime`/`fleet`) so it can use that module's
//! private `ApiState`, `page`, `internal_error`, `utc_ymd_hm` and `unix_now` without
//! widening any of their visibility. Every value rendered here that originates outside
//! this process (labels, hostnames, ids) goes through [`escape`].

use super::*;
use crate::storage::{ShareLinkMint, ShareLinkRow, MAX_ACTIVE_SHARE_LINKS_PER_TUNNEL};
use axum::http::header::CACHE_CONTROL;
use axum::http::HeaderValue;

/// The share-link routes, merged onto the base portal-API router by
/// `portal_api_router_with_verifier`.
pub(super) fn routes() -> Router<ApiState> {
    Router::new()
        .route("/portal/tunnels/:id/share-links", post(mint_share_link_route))
        .route("/portal/tunnels/:id/share-links/:link_id/revoke", post(revoke_share_link_route))
}

/// Longest label kept; the form's `maxlength` matches, this is the server-side bound.
const MAX_LABEL_CHARS: usize = 60;

/// The TTL choices the mint form offers, as `(form value, seconds, human label)`.
const TTL_CHOICES: [(&str, u64, &str); 3] =
    [("1h", 3_600, "1 hour"), ("24h", 86_400, "24 hours"), ("7d", 604_800, "7 days")];

fn ttl_secs_for(value: &str) -> Option<u64> {
    TTL_CHOICES.iter().find(|(v, _, _)| *v == value).map(|(_, secs, _)| *secs)
}

/// The URL a recipient opens: the control plane's own public origin (where the whole
/// `/gate/*` router lives -- `gate_check` redirects to `/gate/start` on that same host
/// today), naming the gated hostname and the token. The gate's session cookie is
/// `Domain=`-scoped to the shared zone, which is why a cookie set from this origin is
/// then sent to `https://<hostname>/`.
fn share_url(portal_base: &str, hostname: &str, token: &str) -> String {
    format!(
        "{}/gate/share?host={}&token={}",
        portal_base.trim_end_matches('/'),
        crate::portal::urlencode(hostname),
        crate::portal::urlencode(token)
    )
}

fn audit(st: &ApiState, claims: &crate::portal::SessionClaims, action: &str, tunnel_id: &str, detail: &str) {
    if let Some(log) = &st.audit {
        // Best-effort by that store's own contract (its doc: never fail the action).
        let _ = log.record(&claims.subject, action, Some(tunnel_id), Some(detail));
    }
}

#[derive(Deserialize)]
struct ShareLinkForm {
    #[serde(default)]
    label: String,
    ttl: String,
    /// Present (any value) when the checkbox was checked -- standard HTML checkbox
    /// semantics, same as `LoginPolicyForm`.
    single_use: Option<String>,
}

/// `POST /portal/tunnels/:id/share-links` (session required): mint a share link for a
/// tunnel the caller owns. `404` for a foreign/unknown tunnel ("existence leaks
/// nothing", like every owner-scoped tunnel action); `400` when the login gate is off
/// (a link only works while it is on -- the message says so and where to turn it on),
/// when the tunnel has no hostname, on an unknown TTL, or once the tunnel holds
/// [`MAX_ACTIVE_SHARE_LINKS_PER_TUNNEL`] active links. On success answers with the
/// confirmation page showing the full URL exactly once, `Cache-Control: no-store`.
async fn mint_share_link_route(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ShareLinkForm>,
) -> Response {
    let Some(claims) = session_claims_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let Some(ttl_secs) = ttl_secs_for(&form.ttl) else {
        return (StatusCode::BAD_REQUEST, "ttl must be one of 1h, 24h, 7d".to_string()).into_response();
    };
    let label: String = form.label.trim().chars().take(MAX_LABEL_CHARS).collect();
    let single_use = form.single_use.is_some();
    match st.tunnels.require_login(&claims.subject, &id) {
        Ok(Some(true)) => {}
        Ok(Some(false)) => {
            return (
                StatusCode::BAD_REQUEST,
                "A share link only works while \"Require login\" is on for this tunnel. Turn it on in the \
                 login-gate section of the tunnel card (POST /portal/tunnels/<id>/require-login), then \
                 create the share link."
                    .to_string(),
            )
                .into_response();
        }
        Ok(None) => return (StatusCode::NOT_FOUND, "unknown tunnel".to_string()).into_response(),
        Err(e) => return internal_error("mint_share_link/require_login", e).into_response(),
    }
    let now = unix_now();
    match st.tunnels.mint_share_link(&claims.subject, &id, Some(label.as_str()), ttl_secs, single_use, now) {
        Ok(ShareLinkMint::Minted { link_id, token, hostname }) => {
            audit(
                &st,
                &claims,
                "share_link_minted",
                &id,
                &format!("link={link_id} host={hostname} ttl_secs={ttl_secs} single_use={single_use}"),
            );
            let url = share_url(&st.portal_base, &hostname, &token);
            let body = link_once_html(&url, &hostname, (now + ttl_secs) as i64, single_use, &label);
            let mut resp = Html(page("share link", &body, claims.email.as_deref())).into_response();
            resp.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(ShareLinkMint::NotEligible) => (
            StatusCode::BAD_REQUEST,
            "this tunnel has no hostname yet -- there is nothing a share link could open".to_string(),
        )
            .into_response(),
        Ok(ShareLinkMint::TooMany) => (
            StatusCode::BAD_REQUEST,
            format!(
                "this tunnel already has {MAX_ACTIVE_SHARE_LINKS_PER_TUNNEL} active share links -- revoke one first"
            ),
        )
            .into_response(),
        Err(e) => internal_error("mint_share_link/mint", e).into_response(),
    }
}

/// `POST /portal/tunnels/:id/share-links/:link_id/revoke` (session required): revoke
/// one link of a tunnel the caller owns. Also ends every gate session already minted
/// from it (the gate re-checks the link on each request). `404` if the link is
/// unknown, foreign, belongs to another tunnel, or is already revoked.
async fn revoke_share_link_route(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path((id, link_id)): Path<(String, String)>,
) -> Response {
    let Some(claims) = session_claims_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    match st.tunnels.revoke_share_link(&claims.subject, &id, &link_id, unix_now()) {
        Ok(true) => {
            audit(&st, &claims, "share_link_revoked", &id, &format!("link={link_id}"));
            Redirect::to("/portal/tunnels").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "unknown share link".to_string()).into_response(),
        Err(e) => internal_error("revoke_share_link", e).into_response(),
    }
}

/// The per-tunnel "Share links" card blocks for the tunnels page, keyed by tunnel id
/// -- one store read per tunnel, bounded by the account's tunnel quota like the
/// sibling `crate::alerts::card_blocks`. `require_logins` is the page's own
/// `(require_login, allow_any_login)` map: the mint form is only offered while the
/// gate is on (a link minted otherwise could never be redeemed), existing links are
/// listed either way so a revoke is always reachable.
pub(super) fn card_blocks(
    store: &SqliteTunnelStore,
    subject: &str,
    tunnel_ids: &[&str],
    require_logins: &HashMap<String, (bool, bool)>,
) -> HashMap<String, String> {
    let now = unix_now() as i64;
    tunnel_ids
        .iter()
        .map(|id| {
            let links = store.share_links_for(subject, id).unwrap_or_default();
            let gate_on = require_logins.get(*id).map(|(on, _)| *on).unwrap_or(false);
            (id.to_string(), card_html(id, &links, gate_on, now))
        })
        .collect()
}

/// A link's one-word state for the card, as of `now`.
fn state_label(link: &ShareLinkRow, now: i64) -> &'static str {
    if link.revoked_at.is_some() {
        "revoked"
    } else if link.single_use && link.used_at.is_some() {
        "used"
    } else if link.expires_at <= now {
        "expired"
    } else if link.used_at.is_some() {
        "active, opened"
    } else {
        "active"
    }
}

/// One card block. Reuses the page's existing `details.history`/`table.history`
/// styling, like the dead-man alert block, so it needs no CSS of its own.
fn card_html(tunnel_id: &str, links: &[ShareLinkRow], gate_on: bool, now: i64) -> String {
    let id = escape(tunnel_id);
    let active = links.iter().filter(|l| l.is_active(now)).count();
    let rows = links
        .iter()
        .map(|l| {
            let link_id = escape(&l.id);
            let label = l.label.as_deref().filter(|s| !s.is_empty()).map(escape).unwrap_or_else(|| "&ndash;".to_string());
            let kind = if l.single_use { "single use" } else { "reusable" };
            let revoke = if l.is_active(now) {
                format!(
                    r#"<form class="inline fade-out-submit" method="post" action="/portal/tunnels/{id}/share-links/{link_id}/revoke">
 <button class="sec" type="submit">Revoke</button></form>"#
                )
            } else {
                String::new()
            };
            format!(
                "<tr><td>{label}</td><td>{expires}</td><td>{kind}</td><td>{state}</td><td>{revoke}</td></tr>",
                expires = utc_ymd_hm(l.expires_at),
                state = state_label(l, now),
            )
        })
        .collect::<String>();
    let table = if links.is_empty() {
        r#"<p class="help">No share links yet.</p>"#.to_string()
    } else {
        format!(
            r#"<table class="history"><thead><tr><th>Label</th><th>Expires (UTC)</th><th>Type</th><th>State</th><th></th></tr></thead>
<tbody>{rows}</tbody></table>"#
        )
    };
    let form = if gate_on {
        let options = TTL_CHOICES
            .iter()
            .map(|(value, _, human)| {
                let selected = if *value == "24h" { " selected" } else { "" };
                format!(r#"<option value="{value}"{selected}>{human}</option>"#)
            })
            .collect::<String>();
        format!(
            r#"<form class="inline" method="post" action="/portal/tunnels/{id}/share-links">
 <input type="text" name="label" placeholder="label (optional)" maxlength="{MAX_LABEL_CHARS}" size="18">
 <select name="ttl">{options}</select>
 <label><input type="checkbox" name="single_use" value="1"> Single use</label>
 <button class="sec" type="submit">Create share link</button>
</form>"#
        )
    } else {
        r#"<p class="help">Turn on "Require login" above to create share links &mdash; a share link only works while the login gate is on.</p>"#.to_string()
    };
    format!(
        r#"<details class="history"><summary>Share links ({active} active)</summary>
<p class="help">A share link opens this tunnel's site without an account until it expires (or once, for a single-use link).
It only works while "Require login" is on, and only for a hostname the edge terminates (Gelb); a passthrough (Gr&uuml;n)
hostname is gated on the agent instead. At most {MAX_ACTIVE_SHARE_LINKS_PER_TUNNEL} active links per tunnel.</p>
{table}
{form}
</details>"#
    )
}

/// The mint confirmation page: the URL, shown here and never again.
fn link_once_html(url: &str, hostname: &str, expires_at: i64, single_use: bool, label: &str) -> String {
    let scope = if single_use {
        "The first person to open it gets in; the link is spent after that."
    } else {
        "Anyone who has it can open the site until it expires, as often as they like."
    };
    let label_line = if label.is_empty() {
        String::new()
    } else {
        format!("<p>Label: <code>{}</code></p>", escape(label))
    };
    format!(
        r#"<h1>Share link created</h1>
<p>This link opens <code>{host}</code> without an account until <strong>{expires} UTC</strong>. {scope}</p>
{label_line}
<div class="warn">The link is shown <strong>once</strong> and cannot be displayed again. Copy it now; to hand it out
later, create a new one.</div>
<div class="code-block">
 <div class="code-block-head"><span>share link</span><button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>
 <pre><code>{url}</code></pre>
</div>
<p class="help">Revoke it any time from the tunnel card; that also ends any visit already opened with it. The link stops
working the moment "Require login" is turned off for this tunnel (the site is public then anyway).</p>
<p><a class="btn sec" href="/portal/tunnels">Back to tunnels</a></p>"#,
        host = escape(hostname),
        expires = utc_ymd_hm(expires_at),
        url = escape(url),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal::sign_session_for_test;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    const KEY: &[u8] = b"share-test-key";

    /// The parent module's test fixtures are private to its own `tests` module, so this
    /// child carries its own copy (same shape as `alerts.rs`'s `portal_app`).
    fn portal_app() -> (Router, Arc<SqliteTunnelStore>) {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let edge_mesh = EdgeMeshHandle::new(
            Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap()),
            Arc::from("test-edge"),
        );
        let app = portal_api_router(
            KEY,
            Arc::new(SqliteLedger::open_in_memory().unwrap()),
            tunnels.clone(),
            Arc::new(SqliteEnrollment::open_in_memory().unwrap()),
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example/",
            None,
            None,
            None,
            None,
            edge_mesh,
            None,
        );
        (app, tunnels)
    }

    fn cookie(subject: &str) -> String {
        format!("ct_portal_session={}", sign_session_for_test(KEY, subject))
    }

    async fn post_form(app: &Router, path: &str, subject: &str, form: &str) -> axum::response::Response {
        app.clone()
            .oneshot(
                Request::post(path)
                    .header("cookie", cookie(subject))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn text(resp: axum::response::Response) -> String {
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    async fn get_page(app: &Router, path: &str, subject: &str) -> (StatusCode, String) {
        let resp = app
            .clone()
            .oneshot(Request::get(path).header("cookie", cookie(subject)).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        (status, text(resp).await)
    }

    /// A gated, hostname-bearing tunnel owned by alice.
    fn gated_tunnel(tunnels: &SqliteTunnelStore) -> SubjectTunnel {
        let t = tunnels.create("alice", "demo", Some("demo.example")).unwrap().created().expect("hostname free");
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());
        t
    }

    /// The share URL from the confirmation page's `<code>` block.
    fn url_in(html: &str) -> String {
        let start = html.find("<pre><code>").expect("code block") + "<pre><code>".len();
        let end = html[start..].find("</code>").expect("code end") + start;
        html[start..end].replace("&amp;", "&")
    }

    #[test]
    fn share_url_names_the_control_plane_origin_the_host_and_the_token() {
        assert_eq!(
            share_url("https://bunsenbrenner.org/", "demo.bunsenbrenner.org", "abc_-123"),
            "https://bunsenbrenner.org/gate/share?host=demo.bunsenbrenner.org&token=abc_-123"
        );
    }

    #[tokio::test]
    async fn mint_shows_the_url_once_the_card_lists_it_without_the_token_and_revoke_ends_it_780() {
        let (app, tunnels) = portal_app();
        let t = gated_tunnel(&tunnels);
        let path = format!("/portal/tunnels/{}/share-links", t.id);

        let resp = post_form(&app, &path, "alice", "label=reviewers&ttl=24h&single_use=1").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(CACHE_CONTROL).unwrap(), "no-store", "the one-time page must not be cached");
        let html = text(resp).await;
        assert!(html.contains("Share link created"), "{html}");
        assert!(html.contains("copyCode(this)"), "a Copy button");
        assert!(html.contains("shown <strong>once</strong>"), "{html}");
        let url = url_in(&html);
        assert!(
            url.starts_with("https://portal.example/gate/share?host=demo.example&token="),
            "the URL points at the gate's redeem route on the control plane's own origin: {url}"
        );
        let token = url.rsplit("token=").next().unwrap().to_string();
        assert_eq!(token.len(), 43, "32 random bytes as unpadded base64url: {token}");
        // The token in the page is the real one: the store redeems it for that hostname.
        let redeemed = tunnels.redeem_share_link("demo.example", &token, unix_now()).unwrap().expect("valid");
        assert!(redeemed.single_use);
        assert_eq!(redeemed.tunnel_id, t.id);

        // The tunnel card lists it -- label, type, state -- but never the token.
        let (status, page) = get_page(&app, "/portal/tunnels", "alice").await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("Share links (0 active)"), "spent by the redeem above: {page}");
        assert!(page.contains("<td>reviewers</td>"), "{page}");
        assert!(page.contains("<td>single use</td>") && page.contains("<td>used</td>"), "{page}");
        assert!(!page.contains(&token), "the token is shown once, never on the list");
        assert!(page.contains("Create share link"), "mint form offered while the gate is on");

        // A second, reusable link: listed as active with a Revoke button, then revoked.
        let resp = post_form(&app, &path, "alice", "label=&ttl=1h").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let token2 = url_in(&text(resp).await).rsplit("token=").next().unwrap().to_string();
        let (_, page) = get_page(&app, "/portal/tunnels", "alice").await;
        assert!(page.contains("Share links (1 active)"), "{page}");
        assert!(page.contains("<td>reusable</td>") && page.contains("<td>active</td>"), "{page}");
        let link2 = tunnels.share_links_for("alice", &t.id).unwrap().into_iter().find(|l| l.is_active(unix_now() as i64)).unwrap();
        assert!(page.contains(&format!("/share-links/{}/revoke", link2.id)), "Revoke button for the active link: {page}");

        let revoke_path = format!("/portal/tunnels/{}/share-links/{}/revoke", t.id, link2.id);
        let resp = post_form(&app, &revoke_path, "bob", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "foreign revoke is a 404");
        let resp = post_form(&app, &revoke_path, "alice", "").await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(tunnels.redeem_share_link("demo.example", &token2, unix_now()).unwrap().is_none(), "revoked");
        let (_, page) = get_page(&app, "/portal/tunnels", "alice").await;
        assert!(page.contains("Share links (0 active)") && page.contains("<td>revoked</td>"), "{page}");
        assert!(!page.contains(&format!("/share-links/{}/revoke", link2.id)), "no Revoke button on a revoked link");
        let resp = post_form(&app, &revoke_path, "alice", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "already revoked");
    }

    #[tokio::test]
    async fn mint_is_400_without_the_login_gate_or_a_hostname_404_foreign_and_400_on_a_bad_ttl_780() {
        let (app, tunnels) = portal_app();
        let open = tunnels.create("alice", "open", Some("open.example")).unwrap().created().expect("hostname free");
        let path = format!("/portal/tunnels/{}/share-links", open.id);

        let resp = post_form(&app, &path, "alice", "ttl=24h").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "login gate is off");
        let body = text(resp).await;
        assert!(body.contains("only works while \"Require login\" is on"), "{body}");
        assert!(body.contains("require-login"), "says where to turn it on: {body}");
        assert!(tunnels.share_links_for("alice", &open.id).unwrap().is_empty(), "nothing minted");
        let (_, page) = get_page(&app, "/portal/tunnels", "alice").await;
        assert!(page.contains("Turn on \"Require login\" above to create share links"), "{page}");
        assert!(!page.contains("Create share link"), "no mint form while the gate is off: {page}");

        assert!(tunnels.set_require_login("alice", &open.id, true).unwrap());
        let resp = post_form(&app, &path, "alice", "ttl=2h").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "unknown TTL");
        let resp = post_form(&app, &path, "bob", "ttl=24h").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "foreign tunnel");
        let resp = post_form(&app, "/portal/tunnels/no-such-tunnel/share-links", "alice", "ttl=24h").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let bare = tunnels.create("alice", "mesh-only", None).unwrap().created().expect("hostname free");
        assert!(tunnels.set_require_login("alice", &bare.id, true).unwrap());
        let resp = post_form(&app, &format!("/portal/tunnels/{}/share-links", bare.id), "alice", "ttl=24h").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "no hostname");
        assert!(text(resp).await.contains("no hostname"));

        // Signed out: bounced to the portal shell, nothing minted.
        let resp = app
            .clone()
            .oneshot(
                Request::post(path.as_str())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("ttl=24h"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(tunnels.share_links_for("alice", &open.id).unwrap().is_empty());
    }

    #[tokio::test]
    async fn mint_is_400_once_the_tunnel_has_fifty_active_links_780() {
        let (app, tunnels) = portal_app();
        let t = gated_tunnel(&tunnels);
        let path = format!("/portal/tunnels/{}/share-links", t.id);
        let now = unix_now();
        for _ in 0..MAX_ACTIVE_SHARE_LINKS_PER_TUNNEL {
            assert!(matches!(
                tunnels.mint_share_link("alice", &t.id, None, 3_600, false, now).unwrap(),
                ShareLinkMint::Minted { .. }
            ));
        }
        let resp = post_form(&app, &path, "alice", "ttl=24h").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(text(resp).await.contains("50 active share links"));
        let (_, page) = get_page(&app, "/portal/tunnels", "alice").await;
        assert!(page.contains("Share links (50 active)"), "{page}");
    }
}
