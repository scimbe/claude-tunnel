//! Client-side PoW-gated rendezvous (M5.3a).
//!
//! The counterpart to the Edge's `resolve_rendezvous_gated`: read the Edge's
//! challenge, solve the proof of work, present `solution | token`, and await OK.

use ct_common::pow::{build_request, Challenge};
use ct_common::RoutingToken;
use quinn::Connection;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Perform PoW-gated rendezvous for `token` on `conn`. Returns `Ok(())` when the
/// Edge accepts the token.
pub async fn client_rendezvous(conn: &Connection, token: &RoutingToken) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut chal = [0u8; 17];
    recv.read_exact(&mut chal).await?;
    let challenge = Challenge {
        nonce: chal[..16].try_into().unwrap(),
        difficulty: chal[16],
    };
    let req = build_request(&challenge, token);
    send.write_all(&req).await?;
    send.finish()?;
    let ack = recv.read_to_end(8).await?;
    if ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected rendezvous".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::dial_edge;

    #[tokio::test]
    async fn client_completes_pow_gated_rendezvous() {
        let token = RoutingToken([7u8; 32]);
        let challenge = Challenge {
            nonce: [0x11; 16],
            difficulty: 10,
        };
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        let token_e = token.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            ct_edge::rendezvous::resolve_rendezvous_gated(&server, chal_e, move |t| *t == token_e)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });

        let conn = dial_edge(addr, cert).await.expect("dial");
        client_rendezvous(&conn, &token)
            .await
            .expect("client completes rendezvous");
        conn.close(0u32.into(), b"done");
        edge.await.unwrap().expect("edge resolved");
    }
}
