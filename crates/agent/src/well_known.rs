//! #144 ①: serve an agent's holder-signed [`AgentCard`] at the RFC 8615 well-known path.
//!
//! An agent stands up a subdomain (`<role>-<hash>.agents.<zone>`) with a real certificate;
//! serving its signed card at `/.well-known/agent-card.json` makes the subdomain+cert+card chain
//! fetchable in one hop, so a peer (or the future searchable registry, #144 ②) can DISCOVER and
//! cryptographically VERIFY the agent's identity when networks form. The trust anchor is the
//! card's ed25519 **holder signature**, never the transport: a fetcher parses the JSON back into
//! an [`AgentCard`] and re-checks [`AgentCard::is_valid`]. This is the responder core; mounting it
//! as a first-class `ct-agent onboard --mode browser` output is the wiring follow.

use axum::response::{IntoResponse, Response};
use ct_common::channel::AgentCard;

/// The RFC 8615 path an agent serves its holder-signed [`AgentCard`] at.
pub const AGENT_CARD_WELL_KNOWN_PATH: &str = "/.well-known/agent-card.json";

/// The canonical `application/json` body served at [`AGENT_CARD_WELL_KNOWN_PATH`] — the card as
/// its JSON profile (hex-string byte fields). Trust is the signature, not the transport.
pub fn agent_card_well_known_body(card: &AgentCard) -> String {
    serde_json::to_string(card).expect("AgentCard serializes to JSON")
}

/// The HTTP response an origin serves at [`AGENT_CARD_WELL_KNOWN_PATH`]: `200 OK`,
/// `content-type: application/json`, body = the signed card's JSON. Axum-handler-shaped so the
/// browser-mode origin can mount it directly.
pub fn agent_card_response(card: &AgentCard) -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        agent_card_well_known_body(card),
    )
        .into_response()
}

/// An axum [`Router`](axum::Router) that serves the agent's holder-signed card at
/// [`AGENT_CARD_WELL_KNOWN_PATH`] (and 404s any other path). Direction-agnostic: the origin
/// helper — or `ct-agent onboard --mode browser` — mounts it and binds it to a TLS listener on
/// the agent's subdomain. The card is served **at the origin** because browser mode is raw TLS
/// passthrough (the agent forwards opaque bytes and never sees the request path); binding + the
/// subdomain cert are the onboard integration follow.
pub fn agent_card_router(card: AgentCard) -> axum::Router {
    axum::Router::new().route(
        AGENT_CARD_WELL_KNOWN_PATH,
        axum::routing::get(move || {
            let card = card.clone();
            async move { agent_card_response(&card) }
        }),
    )
}

/// #144 ①-wiring (central's option **(ii)** — *emit a runnable helper, don't bake an HTTP server
/// into ct-agent*): write the agent's holder-signed card to `<out_dir>/.well-known/agent-card.json`
/// so the operator drops it under their **existing** origin (the subdomain that already terminates
/// TLS), serving it at the well-known path with zero HTTP surface added to `ct-agent`. The card is
/// self-authenticating (holder signature), so the file needs no further protection. Returns the
/// written path. `ct-agent onboard --mode browser` calls this + prints where it landed.
pub fn write_agent_card_for_origin(
    card: &AgentCard,
    out_dir: &std::path::Path,
) -> std::io::Result<std::path::PathBuf> {
    let wk_dir = out_dir.join(".well-known");
    std::fs::create_dir_all(&wk_dir)?;
    let path = wk_dir.join("agent-card.json");
    std::fs::write(&path, agent_card_well_known_body(card))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::channel::{CellId, ChannelId, Skill};
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_card() -> AgentCard {
        let sk = SigningKey::from_bytes(&[0x51u8; 32]);
        let holder = sk.verifying_key().to_bytes();
        let role_tags = vec!["source".to_string()];
        let skills = vec![Skill {
            id: "fire_transfer_test".to_string(),
            description: "trigger a live A2A transfer".to_string(),
            examples: vec![],
        }];
        let cells = vec![CellId([0x33u8; 32])];
        let channels = vec![ChannelId([0x9bu8; 32])];
        let (issued, expires) = (1_000u64, 5_000u64);
        AgentCard {
            holder_pubkey: holder,
            role_tags: role_tags.clone(),
            skills: skills.clone(),
            cells: cells.clone(),
            channels: channels.clone(),
            issued_at: issued,
            expires_at: expires,
            signature: sk
                .sign(&AgentCard::signing_bytes(&holder, &role_tags, &skills, &cells, &channels, issued, expires))
                .to_bytes(),
        }
    }

    #[test]
    fn well_known_path_is_the_rfc8615_agent_card_path() {
        assert_eq!(AGENT_CARD_WELL_KNOWN_PATH, "/.well-known/agent-card.json");
    }

    #[test]
    fn well_known_body_is_a_verifiable_json_card() {
        // #144 ①: the served body round-trips into a card whose holder signature STILL verifies —
        // a discovering peer trusts the SIGNATURE it fetched, not the origin that served it.
        let card = signed_card();
        let body = agent_card_well_known_body(&card);
        assert!(body.contains("\"holder_pubkey\":\""), "hex-string JSON profile fields");
        let back: AgentCard = serde_json::from_str(&body).expect("well-known body parses back");
        assert_eq!(back, card, "the served body is the exact signed card (lossless)");
        assert!(back.is_valid(1_000), "the holder signature verifies from the served body");
        // A tampered served body fails the signature — the served card is authenticated.
        let tampered = body.replace("trigger a live A2A transfer", "do something else");
        let bad: AgentCard = serde_json::from_str(&tampered).expect("still valid JSON");
        assert!(!bad.is_valid(1_000), "editing the served card breaks the holder signature");
    }

    #[test]
    fn well_known_response_is_200_application_json() {
        let resp = agent_card_response(&signed_card());
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert_eq!(
            resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
            "application/json",
        );
    }

    #[tokio::test]
    async fn well_known_router_serves_the_card_and_404s_elsewhere() {
        // #144 ①-wiring: the mountable router serves the signed card over HTTP at the well-known
        // path (verifiable after the round-trip) and 404s everything else.
        use axum::body::{to_bytes, Body};
        use axum::http::{header::CONTENT_TYPE, Request, StatusCode};
        use tower::ServiceExt;

        let card = signed_card();
        let resp = agent_card_router(card.clone())
            .oneshot(Request::get(AGENT_CARD_WELL_KNOWN_PATH).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(CONTENT_TYPE).unwrap(), "application/json");
        let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
        let back: AgentCard = serde_json::from_slice(&body).expect("served body parses");
        assert_eq!(back, card, "the router serves the exact signed card");
        assert!(back.is_valid(1_000), "the card fetched over HTTP still verifies");

        let miss = agent_card_router(signed_card())
            .oneshot(Request::get("/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(miss.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn write_agent_card_for_origin_drops_a_verifiable_well_known_file() {
        // #144 ①-wiring (option ii): the card is written at `<dir>/.well-known/agent-card.json`
        // for the operator's origin to serve — and the file round-trips into a card whose holder
        // signature still verifies (self-authenticating; the file needs no further protection).
        let card = signed_card();
        let dir = std::env::temp_dir().join(format!("ct-agent-card-{}-{}", std::process::id(), "wk"));
        let _ = std::fs::remove_dir_all(&dir);
        let path = write_agent_card_for_origin(&card, &dir).expect("card written");
        assert!(path.ends_with(".well-known/agent-card.json"), "RFC-8615 path, got {path:?}");
        assert!(path.exists(), "the file exists");
        let bytes = std::fs::read(&path).expect("read back");
        let back: AgentCard = serde_json::from_slice(&bytes).expect("parses");
        assert_eq!(back, card, "the served file is the exact signed card");
        assert!(back.is_valid(1_000), "the written card still verifies");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
