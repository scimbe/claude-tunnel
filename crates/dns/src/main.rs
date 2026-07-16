//! `ct-dns` daemon — authoritative DNS-01 responder for the SaaS (#31 AD3).
//!
//! Serves `_acme-challenge` TXT over public UDP+TCP `:53`, and exposes a
//! loopback-only mutation API the co-located ACME client drives. Config:
//! - `CT_DNS_LISTEN`     — DNS listener (default `0.0.0.0:53`; needs privilege).
//! - `CT_DNS_API_LISTEN` — mutation API (default `127.0.0.1:8053`; keep loopback).
//! - `CT_DNS_API_TOKEN`  — optional `x-ct-dns-token` shared secret (defence-in-depth).

use std::net::SocketAddr;
use std::sync::Arc;

use ct_dns::store::AcmeDnsStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dns_listen: SocketAddr = std::env::var("CT_DNS_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:53".to_string())
        .parse()?;
    let api_listen: SocketAddr = std::env::var("CT_DNS_API_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8053".to_string())
        .parse()?;
    let token = std::env::var("CT_DNS_API_TOKEN").ok().filter(|s| !s.is_empty());

    if !api_listen.ip().is_loopback() {
        eprintln!("ct-dns: WARNING — API listener {api_listen} is not loopback; the mutation API should stay private");
    }
    eprintln!(
        "ct-dns: authoritative DNS on {dns_listen} (udp+tcp), mutation API on {api_listen}{}",
        if token.is_some() { " (token required)" } else { "" }
    );

    let store = Arc::new(AcmeDnsStore::new());
    tokio::try_join!(
        ct_dns::server::serve_udp(store.clone(), dns_listen),
        ct_dns::server::serve_tcp(store.clone(), dns_listen),
        ct_dns::api::serve_api(store.clone(), token, api_listen),
    )?;
    Ok(())
}
