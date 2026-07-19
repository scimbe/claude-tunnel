//! Agent Fabric — the **libp2p connectivity seam** (#121 B2-libp2p-seam).
//!
//! This module introduces **libp2p** as the connectivity *substrate* underneath the
//! A2A channel. It is deliberately thin: libp2p supplies a raw, bidirectional byte
//! stream between two peers — over an in-process `MemoryTransport`
//! ([`connected_memory_stream_pair`], #121 B2-libp2p-seam), a real loopback TCP
//! socket ([`connected_tcp_stream_pair`], #121 B2-libp2p-tcp), or a **Circuit-Relay v2**
//! circuit through a third relay node ([`connected_relayed_stream_pair`], #121
//! C-circuit-relay-transport) — and our existing transport-agnostic session
//! ([`crate::channel_run::run_channel_session_on_stream`]) runs the `Noise_IK`
//! handshake + encrypted pump *inside* that stream.
//!
//! ## Trust boundary (the whole point of the seam)
//!
//! - **Invariant #1 — authorization stays our grant, never the libp2p `PeerId`.**
//!   The libp2p transport, its own connection-security (its Noise handshake), and the
//!   `PeerId` it authenticates are **untrusted plumbing**. Admission to a channel is
//!   decided *solely* by the operator-signed grant + the members' channel-attested
//!   Noise static keys, exactly as on every other transport. Nothing in this module
//!   consults the `PeerId` for authorization — it only names the dial target.
//! - **Invariant #2 — confidentiality/integrity are our `Noise_IK`, over the libp2p
//!   stream.** The bytes libp2p carries are already our end-to-end ciphertext; a
//!   compromised or malicious libp2p layer sees only that ciphertext.
//!
//! The Circuit-Relay v2 path ([`connected_relayed_stream_pair`]) proves the relay
//! *mechanism*: two peers reach each other through a third relay node and form the Noise
//! tunnel. The relay stood up here is deliberately **unguarded** — it relays any circuit —
//! which is safe **only** because it is test-only and in-process. Enforcing invariant #3
//! (a superpeer relays a circuit only for a channel it is a grant-member of) is the next
//! slice, `C-membership-gate`. **⚠️ This unguarded relay MUST NOT be wired to a
//! live/public relay node before the membership gate lands.** Later slices (DCUtR
//! hole-punch — which upgrades a relayed connection to direct — and Kademlia discovery)
//! build on this same seam; those are not implemented here.

use std::time::Duration;

use libp2p::core::transport::MemoryTransport;
use libp2p::core::upgrade::Version;
use libp2p::futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{noise, relay, yamux, Multiaddr, StreamProtocol, Swarm, SwarmBuilder, Transport};
use libp2p_stream as stream;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The libp2p application-protocol name our channel stream negotiates. This names the
/// *substream protocol*, not an identity — it carries no authorization meaning.
const CT_CHANNEL_PROTOCOL: StreamProtocol = StreamProtocol::new("/ct/channel/1.0.0");

/// A libp2p [`libp2p::Stream`] adapted from `futures`' async-IO traits to Tokio's, so
/// it satisfies the `AsyncRead + AsyncWrite + Unpin` bound of
/// [`crate::channel_run::run_channel_session_on_stream`]. This is the raw, *untrusted*
/// duplex; our `Noise_IK` session runs on top of it.
pub type P2pDuplex = Compat<libp2p::Stream>;

/// Build a minimal libp2p swarm for the in-memory seam: `MemoryTransport`, upgraded
/// with libp2p-noise (connection security) + yamux (stream multiplexing), driving a
/// single [`stream::Behaviour`] so we can open/accept raw substreams. Every peer gets a
/// fresh libp2p identity; that identity is plumbing — it never gates channel admission
/// (invariant #1).
fn build_memory_swarm() -> Result<Swarm<stream::Behaviour>, BoxError> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_other_transport(|keypair| {
            Ok::<_, BoxError>(
                MemoryTransport::default()
                    .upgrade(Version::V1)
                    .authenticate(noise::Config::new(keypair)?)
                    .multiplex(yamux::Config::default()),
            )
        })?
        .with_behaviour(|_| stream::Behaviour::new())?
        .build();
    Ok(swarm)
}

/// Connect two in-process libp2p peers over `MemoryTransport` and open a single raw
/// stream between them, returning each side as an `AsyncRead + AsyncWrite + Unpin`
/// duplex (the `(dialer, listener)` pair). The two swarms are then driven forever on
/// detached tasks so the underlying yamux connection keeps flowing for the lifetime of
/// the returned streams; dropping both streams (and the returned duplexes) lets the
/// test runtime reap those tasks on shutdown.
///
/// The libp2p `PeerId` here is used *only* to name the dial target — it is not, and
/// must not become, an authorization input (invariant #1). Callers layer
/// [`crate::channel_run::run_channel_session_on_stream`] on top for auth + encryption.
pub async fn connected_memory_stream_pair() -> Result<(P2pDuplex, P2pDuplex), BoxError> {
    let mut dialer = build_memory_swarm()?;
    let mut listener = build_memory_swarm()?;

    let listener_peer = *listener.local_peer_id();

    // Control handles drive substreams; the swarms themselves must be polled for the
    // controls to make progress (done in the detached drivers below).
    let mut dialer_control = dialer.behaviour().new_control();
    let mut incoming = listener
        .behaviour()
        .new_control()
        .accept(CT_CHANNEL_PROTOCOL)?;

    // A private in-process memory port; random so concurrent tests never collide.
    let port: u64 = rand::random();
    let listen_addr: Multiaddr = format!("/memory/{port}").parse()?;
    listener.listen_on(listen_addr.clone())?;

    // Listener side: pump the swarm and hand back the first inbound stream.
    let (inbound_tx, inbound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut inbound_tx = Some(inbound_tx);
        loop {
            tokio::select! {
                _ = listener.next() => {}
                Some((_peer, stream)) = incoming.next() => {
                    if let Some(tx) = inbound_tx.take() {
                        let _ = tx.send(stream);
                    }
                }
            }
        }
    });

    // Dialer side: dial the listener, wait until the connection is established, then
    // open the substream while continuing to pump the swarm.
    let (outbound_tx, outbound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if dialer.dial(listen_addr).is_err() {
            return;
        }
        // Open only once connected: open_stream requires a live connection to the peer.
        loop {
            match dialer.next().await {
                Some(SwarmEvent::ConnectionEstablished { .. }) => break,
                Some(_) => {}
                None => return,
            }
        }
        let open = dialer_control.open_stream(listener_peer, CT_CHANNEL_PROTOCOL);
        tokio::pin!(open);
        let mut outbound_tx = Some(outbound_tx);
        loop {
            tokio::select! {
                _ = dialer.next() => {}
                res = &mut open, if outbound_tx.is_some() => {
                    if let (Ok(stream), Some(tx)) = (res, outbound_tx.take()) {
                        let _ = tx.send(stream);
                    }
                }
            }
        }
    });

    let dialer_stream = outbound_rx.await?;
    let listener_stream = inbound_rx.await?;
    Ok((dialer_stream.compat(), listener_stream.compat()))
}

/// Build a libp2p swarm for the real-TCP seam: a Tokio TCP transport upgraded with
/// libp2p-noise (connection security) + yamux (muxer), driving a single
/// [`stream::Behaviour`]. Structurally identical to [`build_memory_swarm`] except the
/// transport is real loopback TCP instead of `MemoryTransport`. As on every transport,
/// the fresh libp2p identity is plumbing — it never gates channel admission (invariant #1).
fn build_tcp_swarm() -> Result<Swarm<stream::Behaviour>, BoxError> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            Default::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|_| stream::Behaviour::new())?
        .build();
    Ok(swarm)
}

/// Connect two libp2p peers over a **real loopback TCP transport** and open a single raw
/// stream between them, returning each side as an `AsyncRead + AsyncWrite + Unpin` duplex
/// (the `(dialer, listener)` pair). This is the real-network counterpart of
/// [`connected_memory_stream_pair`]: peer A (the listener) binds `127.0.0.1:0`, and once
/// the OS assigns a port we learn the concrete listen [`Multiaddr`] from
/// `NewListenAddr`; peer B then **dials that multiaddr** and opens the substream. Both
/// swarms are driven forever on detached tasks so the yamux connection keeps flowing for
/// the lifetime of the returned streams.
///
/// Real sockets add connection-setup timing the in-memory path doesn't: we await the
/// listen address before dialing and await `ConnectionEstablished` before `open_stream`
/// (which requires a live connection), so nothing races. As on the memory path, the
/// libp2p `PeerId` only names the dial target — it is never an authorization input
/// (invariant #1); callers layer
/// [`crate::channel_run::run_channel_session_on_stream`] on top for auth + encryption.
pub async fn connected_tcp_stream_pair() -> Result<(P2pDuplex, P2pDuplex), BoxError> {
    let mut dialer = build_tcp_swarm()?;
    let mut listener = build_tcp_swarm()?;

    let listener_peer = *listener.local_peer_id();

    // Control handles drive substreams; the swarms themselves must be polled for the
    // controls to make progress (done in the detached drivers below).
    let mut dialer_control = dialer.behaviour().new_control();
    let mut incoming = listener
        .behaviour()
        .new_control()
        .accept(CT_CHANNEL_PROTOCOL)?;

    // Bind loopback with an OS-assigned port; the concrete address isn't known until the
    // transport reports `NewListenAddr`.
    listener.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
    let listen_addr: Multiaddr = loop {
        match listener.next().await {
            Some(SwarmEvent::NewListenAddr { address, .. }) => break address,
            Some(_) => {}
            None => return Err("listener swarm closed before reporting a listen address".into()),
        }
    };
    // The multiaddr B dials, with A's peer id appended (`…/tcp/<port>/p2p/<peer>`). The
    // `PeerId` here only names/verifies the dial target — never an authz input.
    let dial_addr = listen_addr
        .with_p2p(listener_peer)
        .map_err(|_| "append /p2p/<peer> to the listen multiaddr")?;

    // Listener side: pump the swarm and hand back the first inbound stream.
    let (inbound_tx, inbound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut inbound_tx = Some(inbound_tx);
        loop {
            tokio::select! {
                _ = listener.next() => {}
                Some((_peer, stream)) = incoming.next() => {
                    if let Some(tx) = inbound_tx.take() {
                        let _ = tx.send(stream);
                    }
                }
            }
        }
    });

    // Dialer side: dial the listener's multiaddr, wait until the connection is
    // established, then open the substream while continuing to pump the swarm.
    let (outbound_tx, outbound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if dialer.dial(dial_addr).is_err() {
            return;
        }
        loop {
            match dialer.next().await {
                Some(SwarmEvent::ConnectionEstablished { .. }) => break,
                Some(_) => {}
                None => return,
            }
        }
        let open = dialer_control.open_stream(listener_peer, CT_CHANNEL_PROTOCOL);
        tokio::pin!(open);
        let mut outbound_tx = Some(outbound_tx);
        loop {
            tokio::select! {
                _ = dialer.next() => {}
                res = &mut open, if outbound_tx.is_some() => {
                    if let (Ok(stream), Some(tx)) = (res, outbound_tx.take()) {
                        let _ = tx.send(stream);
                    }
                }
            }
        }
    });

    let dialer_stream = outbound_rx.await?;
    let listener_stream = inbound_rx.await?;
    Ok((dialer_stream.compat(), listener_stream.compat()))
}

/// The behaviour a **relay client** peer runs: the libp2p Circuit-Relay v2 client
/// (installed by `SwarmBuilder::with_relay_client`, which also splices its relayed
/// transport in alongside TCP) composed with the raw-substream [`stream::Behaviour`] we
/// open our channel stream over. Neither the relay client nor its `PeerId` is an
/// authorization input (invariant #1) — they only route bytes.
#[derive(NetworkBehaviour)]
struct RelayClientBehaviour {
    relay_client: relay::client::Behaviour,
    stream: stream::Behaviour,
}

/// Build the **relay node**'s swarm: a Tokio TCP transport upgraded with libp2p-noise +
/// yamux, driving the Circuit-Relay v2 **server** [`relay::Behaviour`]. This node forwards
/// circuits between clients; it terminates none of our channel traffic and never sees
/// anything but our end-to-end ciphertext (invariant #2).
///
/// ⚠️ This relay is **unguarded** — `relay::Config::default()` accepts a reservation/circuit
/// from any peer. That is safe **only** because this helper is test-only and in-process; a
/// live/public relay MUST first gain the invariant-#3 membership gate (`C-membership-gate`).
fn build_relay_swarm() -> Result<Swarm<relay::Behaviour>, BoxError> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(Default::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| relay::Behaviour::new(key.public().to_peer_id(), relay::Config::default()))?
        // Keep an otherwise-idle connection (a held reservation carries no app substream)
        // alive long enough for the relayed dial + substream to complete.
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();
    Ok(swarm)
}

/// Build a **relay client**'s swarm: TCP + noise + yamux, plus the Circuit-Relay v2 client
/// transport (`with_relay_client`) so this peer can make a reservation on / dial through a
/// relay, driving the composite [`RelayClientBehaviour`]. As on every transport, the fresh
/// libp2p identity is plumbing — it never gates channel admission (invariant #1).
fn build_relay_client_swarm() -> Result<Swarm<RelayClientBehaviour>, BoxError> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(Default::default(), noise::Config::new, yamux::Config::default)?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|_key, relay_client| RelayClientBehaviour {
            relay_client,
            stream: stream::Behaviour::new(),
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();
    Ok(swarm)
}

/// Connect two libp2p peers **through a third Circuit-Relay v2 relay node** and open a
/// single raw stream between them, returning each side as an `AsyncRead + AsyncWrite +
/// Unpin` duplex (the `(dialer, listener)` pair). Three in-process nodes run over TCP
/// loopback: a **relay** ([`build_relay_swarm`]) and two **clients** A and B
/// ([`build_relay_client_swarm`]). Client A (the listener/destination) makes a
/// **reservation** on the relay — `listen_on(<relay>/p2p-circuit)`, awaiting
/// `relay::client::Event::ReservationReqAccepted` before anything dials — and listens on its
/// relayed address; client B (the dialer/source) **dials A via the relay**
/// (`<relay>/p2p-circuit/p2p/<A-peerid>`) and, once the relayed connection to A is
/// established, opens the `/ct/channel/1.0.0` substream. The multi-step reservation → dial →
/// substream timing is awaited event-by-event so nothing races. All three swarms are then
/// driven forever on detached tasks so the circuit keeps flowing for the lifetime of the
/// returned streams.
///
/// The relay is **unguarded** (relays any circuit) — safe only because it is test-only and
/// in-process; see [`build_relay_swarm`] and the module-level guardrail. As on the direct
/// paths, the libp2p `PeerId` only names/routes the dial target — never an authorization
/// input (invariant #1); callers layer
/// [`crate::channel_run::run_channel_session_on_stream`] on top for auth + encryption.
pub async fn connected_relayed_stream_pair() -> Result<(P2pDuplex, P2pDuplex), BoxError> {
    // --- Relay node: bind loopback, learn its concrete listen address, then drive it
    // forever so it can route circuits for the lifetime of the returned streams. ---
    let mut relay = build_relay_swarm()?;
    let relay_peer = *relay.local_peer_id();
    relay.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
    let relay_addr: Multiaddr = loop {
        match relay.next().await {
            Some(SwarmEvent::NewListenAddr { address, .. }) => break address,
            Some(_) => {}
            None => return Err("relay swarm closed before reporting a listen address".into()),
        }
    };
    // The Circuit-Relay v2 server advertises *its own external addresses* in the reservation
    // it grants; with none registered it returns an empty set and the client rejects the
    // reservation (`NoAddressesInReservation`). On loopback there is no identify/AutoNAT to
    // discover it, so confirm the bound address explicitly.
    relay.add_external_address(relay_addr.clone());
    tokio::spawn(async move {
        loop {
            relay.next().await;
        }
    });

    // The circuit addresses. `relay_circuit` = `<relay-addr>/p2p/<relay>/p2p-circuit` is what
    // A reserves + listens on; `a_via_relay` appends `/p2p/<A>` — the address B dials to reach
    // A through the relay. The `PeerId`s here only name/route the hop, never authorize.
    let mut client_a = build_relay_client_swarm()?;
    let a_peer = *client_a.local_peer_id();
    let relay_circuit = relay_addr
        .with(Protocol::P2p(relay_peer))
        .with(Protocol::P2pCircuit);
    let a_via_relay = relay_circuit.clone().with(Protocol::P2p(a_peer));

    // Client A accepts inbound `/ct/channel/1.0.0` substreams and makes its reservation.
    let mut a_incoming = client_a.behaviour().stream.new_control().accept(CT_CHANNEL_PROTOCOL)?;
    client_a.listen_on(relay_circuit)?;

    // A driver: signal once the reservation is accepted (so B doesn't dial before the relay
    // knows how to reach A), then keep pumping the swarm and hand back the first inbound
    // stream once B's circuit opens one.
    let (reserved_tx, reserved_rx) = tokio::sync::oneshot::channel();
    let (inbound_tx, inbound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut reserved_tx = Some(reserved_tx);
        let mut inbound_tx = Some(inbound_tx);
        loop {
            tokio::select! {
                ev = client_a.next() => {
                    if let Some(SwarmEvent::Behaviour(RelayClientBehaviourEvent::RelayClient(
                        relay::client::Event::ReservationReqAccepted { .. },
                    ))) = ev
                    {
                        if let Some(tx) = reserved_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                }
                Some((_peer, stream)) = a_incoming.next() => {
                    if let Some(tx) = inbound_tx.take() {
                        let _ = tx.send(stream);
                    }
                }
            }
        }
    });

    // Gate B's dial on A's reservation being live end to end (reservation → dial → substream).
    reserved_rx
        .await
        .map_err(|_| "client A driver ended before its relay reservation was accepted")?;

    // Client B dials A **through the relay**, waits for the relayed connection to A (not the
    // hop to the relay), then opens the substream while continuing to pump the swarm.
    let mut client_b = build_relay_client_swarm()?;
    let mut b_control = client_b.behaviour().stream.new_control();
    let (outbound_tx, outbound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if client_b.dial(a_via_relay).is_err() {
            return;
        }
        loop {
            match client_b.next().await {
                Some(SwarmEvent::ConnectionEstablished { peer_id, .. }) if peer_id == a_peer => break,
                Some(_) => {}
                None => return,
            }
        }
        let open = b_control.open_stream(a_peer, CT_CHANNEL_PROTOCOL);
        tokio::pin!(open);
        let mut outbound_tx = Some(outbound_tx);
        loop {
            tokio::select! {
                _ = client_b.next() => {}
                res = &mut open, if outbound_tx.is_some() => {
                    if let (Ok(stream), Some(tx)) = (res, outbound_tx.take()) {
                        let _ = tx.send(stream);
                    }
                }
            }
        }
    });

    let dialer_stream = outbound_rx.await?;
    let listener_stream = inbound_rx.await?;
    Ok((dialer_stream.compat(), listener_stream.compat()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel_run::{run_channel_session_on_stream, ChannelRole};
    use ct_common::noise::generate_static_keypair;
    use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn channel_noise_session_runs_over_a_libp2p_memory_stream() {
        // #121 B2-libp2p-seam (frozen): our channel `Noise_IK` session runs *inside* a
        // libp2p stream. Two in-process libp2p peers connect over `MemoryTransport`,
        // open a raw substream, and each side runs the EXISTING transport-agnostic
        // `run_channel_session_on_stream` over its half.
        //
        // Invariant #1 (authz = the grant, NOT the libp2p PeerId): admission here is
        // purely key-based — each side is keyed *only* by the members' channel-attested
        // Noise static keys (`a_priv`/`b_pub`, `b_priv`/`a_pub`). The libp2p PeerId is
        // never consulted for authorization; it is untrusted plumbing that only routed
        // the bytes. Invariant #2: the Noise tunnel is formed over the libp2p stream —
        // a real payload round-trips in BOTH directions, proving our end-to-end
        // encryption sits on top of libp2p, not libp2p's own transport security.

        // Channel-attested member Noise keys — the ONLY admission input.
        let a = generate_static_keypair();
        let b = generate_static_keypair();
        let (a_priv, a_pub) = (a.private, a.public);
        let (b_priv, b_pub) = (b.private, b.public);

        // The libp2p in-memory stream: untrusted plumbing carrying our ciphertext.
        let (dialer_stream, listener_stream) = connected_memory_stream_pair()
            .await
            .expect("two in-process libp2p peers connect over MemoryTransport");

        // Each member's local plaintext side (the CLI's stdio stand-in).
        let (mut a_app, a_local) = tokio::io::duplex(16 * 1024);
        let (mut b_app, b_local) = tokio::io::duplex(16 * 1024);

        let a_task = tokio::spawn(async move {
            let (ar, aw) = split(dialer_stream);
            // Initiator: keyed only by its own Noise key + the peer's pinned Noise key.
            run_channel_session_on_stream(aw, ar, ChannelRole::Initiate, &a_priv, &b_pub, a_local).await
        });
        let b_task = tokio::spawn(async move {
            let (br, bw) = split(listener_stream);
            // Responder: keyed only by its own Noise key. No PeerId is consulted.
            run_channel_session_on_stream(bw, br, ChannelRole::Accept, &b_priv, &a_pub, b_local).await
        });

        // A -> B over the Noise tunnel formed inside the libp2p stream.
        a_app.write_all(b"ping-A-to-B").await.expect("a writes");
        let mut got = [0u8; 11];
        b_app.read_exact(&mut got).await.expect("b reads A's bytes");
        assert_eq!(&got, b"ping-A-to-B", "A's plaintext arrives decrypted at B over the libp2p stream");

        // B -> A: prove the tunnel round-trips both directions.
        b_app.write_all(b"pong-B-to-A").await.expect("b writes");
        let mut got2 = [0u8; 11];
        a_app.read_exact(&mut got2).await.expect("a reads B's bytes");
        assert_eq!(&got2, b"pong-B-to-A", "B's plaintext arrives decrypted at A");

        // Flush + close cleanly before drop so the last frame isn't dropped, then let
        // both session tasks unwind.
        a_app.shutdown().await.ok();
        b_app.shutdown().await.ok();
        drop(a_app);
        drop(b_app);
        let _ = a_task.await;
        let _ = b_task.await;
    }

    #[tokio::test]
    async fn channel_noise_session_runs_over_a_libp2p_tcp_stream() {
        // #121 B2-libp2p-tcp (frozen): the SAME proof as the memory seam, but over a
        // **real loopback TCP transport with dial-by-multiaddr**. Peer B dials peer A's
        // OS-assigned listen `Multiaddr`, opens a raw substream, and each side runs the
        // EXISTING transport-agnostic `run_channel_session_on_stream` over its half. This
        // real-socket path is the prerequisite for the later DCUtR hole-punch / Circuit-
        // Relay slices, which need real network addresses.
        //
        // Invariant #1 (authz = the grant, NOT the libp2p PeerId): admission here is
        // purely key-based — each side is keyed *only* by the members' channel-attested
        // Noise static keys (`a_priv`/`b_pub`, `b_priv`/`a_pub`). The libp2p PeerId only
        // named the TCP dial target; it is never consulted for authorization. Invariant
        // #2: the Noise tunnel is formed over the real TCP stream — a real payload round-
        // trips in BOTH directions, proving our end-to-end encryption sits on top of the
        // TCP transport, not on libp2p's own connection security.

        // Channel-attested member Noise keys — the ONLY admission input.
        let a = generate_static_keypair();
        let b = generate_static_keypair();
        let (a_priv, a_pub) = (a.private, a.public);
        let (b_priv, b_pub) = (b.private, b.public);

        // The libp2p real-TCP stream: untrusted plumbing carrying our ciphertext.
        let (dialer_stream, listener_stream) = connected_tcp_stream_pair()
            .await
            .expect("two libp2p peers connect over real loopback TCP (B dials A's multiaddr)");

        // Each member's local plaintext side (the CLI's stdio stand-in).
        let (mut a_app, a_local) = tokio::io::duplex(16 * 1024);
        let (mut b_app, b_local) = tokio::io::duplex(16 * 1024);

        let a_task = tokio::spawn(async move {
            let (ar, aw) = split(dialer_stream);
            // Initiator: keyed only by its own Noise key + the peer's pinned Noise key.
            run_channel_session_on_stream(aw, ar, ChannelRole::Initiate, &a_priv, &b_pub, a_local).await
        });
        let b_task = tokio::spawn(async move {
            let (br, bw) = split(listener_stream);
            // Responder: keyed only by its own Noise key. No PeerId is consulted.
            run_channel_session_on_stream(bw, br, ChannelRole::Accept, &b_priv, &a_pub, b_local).await
        });

        // A -> B over the Noise tunnel formed inside the real TCP stream.
        a_app.write_all(b"ping-A-to-B").await.expect("a writes");
        let mut got = [0u8; 11];
        b_app.read_exact(&mut got).await.expect("b reads A's bytes");
        assert_eq!(&got, b"ping-A-to-B", "A's plaintext arrives decrypted at B over the TCP stream");

        // B -> A: prove the tunnel round-trips both directions over real sockets.
        b_app.write_all(b"pong-B-to-A").await.expect("b writes");
        let mut got2 = [0u8; 11];
        a_app.read_exact(&mut got2).await.expect("a reads B's bytes");
        assert_eq!(&got2, b"pong-B-to-A", "B's plaintext arrives decrypted at A");

        // Flush + close cleanly before drop so the last frame isn't dropped on a real
        // socket, then let both session tasks unwind.
        a_app.shutdown().await.ok();
        b_app.shutdown().await.ok();
        drop(a_app);
        drop(b_app);
        let _ = a_task.await;
        let _ = b_task.await;
    }

    #[tokio::test]
    async fn channel_noise_session_runs_over_a_libp2p_circuit_relay() {
        // #121 C-circuit-relay-transport (frozen): the SAME proof as the direct seams, but
        // the two peers reach each other **through a third libp2p Circuit-Relay v2 relay
        // node** instead of dialing one another directly. Relay + A + B run in-process on
        // TCP loopback; A reserves a slot on the relay and B dials A *via the relay*
        // (`…/p2p-circuit/p2p/<A>`), opens a raw substream, and each side runs the EXISTING
        // transport-agnostic `run_channel_session_on_stream` over its half. A working relayed
        // circuit is the prerequisite for the DCUtR hole-punch slice (B2-dcutr), which
        // upgrades a relayed connection to a direct one.
        //
        // Invariant #1 (authz = the grant, NOT the libp2p PeerId): admission here is purely
        // key-based — each side is keyed *only* by the members' channel-attested Noise static
        // keys (`a_priv`/`b_pub`, `b_priv`/`a_pub`). The relay's PeerId and the clients'
        // PeerIds only named/routed the circuit hop; none is ever consulted for authorization.
        // (The relay itself is deliberately UNGUARDED here — it relays any circuit — which is
        // safe only because it is test-only and in-process; the invariant-#3 membership gate
        // is the next slice, `C-membership-gate`.) Invariant #2: the Noise tunnel is formed
        // over the relayed stream — a real payload round-trips in BOTH directions, proving our
        // end-to-end encryption sits on top of the relay, which sees only ciphertext.

        // Channel-attested member Noise keys — the ONLY admission input.
        let a = generate_static_keypair();
        let b = generate_static_keypair();
        let (a_priv, a_pub) = (a.private, a.public);
        let (b_priv, b_pub) = (b.private, b.public);

        // The multi-step relayed setup (reservation → relayed dial → substream) is fully
        // event-driven, but a regression that stalled any of those steps would otherwise hang
        // forever (`cargo test` has no per-test timeout). Bound the whole path so a deadlock
        // FAILS FAST instead of wedging the gate. 15s is ~100x the in-process happy path.
        tokio::time::timeout(Duration::from_secs(15), async move {
            // The libp2p relayed stream: untrusted plumbing (relay + two clients) carrying our
            // ciphertext. B reached A through the relay.
            let (dialer_stream, listener_stream) = connected_relayed_stream_pair()
                .await
                .expect("two libp2p peers connect THROUGH a Circuit-Relay v2 relay (B dials A via the relay)");

            // Each member's local plaintext side (the CLI's stdio stand-in).
            let (mut a_app, a_local) = tokio::io::duplex(16 * 1024);
            let (mut b_app, b_local) = tokio::io::duplex(16 * 1024);

            let a_task = tokio::spawn(async move {
                let (ar, aw) = split(listener_stream);
                // Responder: keyed only by its own Noise key. No PeerId is consulted.
                run_channel_session_on_stream(aw, ar, ChannelRole::Accept, &a_priv, &b_pub, a_local).await
            });
            let b_task = tokio::spawn(async move {
                let (br, bw) = split(dialer_stream);
                // Initiator: keyed only by its own Noise key + the peer's pinned Noise key.
                run_channel_session_on_stream(bw, br, ChannelRole::Initiate, &b_priv, &a_pub, b_local).await
            });

            // B -> A over the Noise tunnel formed inside the relayed stream.
            b_app.write_all(b"ping-B-to-A").await.expect("b writes");
            let mut got = [0u8; 11];
            a_app.read_exact(&mut got).await.expect("a reads B's bytes");
            assert_eq!(&got, b"ping-B-to-A", "B's plaintext arrives decrypted at A through the relay");

            // A -> B: prove the tunnel round-trips both directions through the relay.
            a_app.write_all(b"pong-A-to-B").await.expect("a writes");
            let mut got2 = [0u8; 11];
            b_app.read_exact(&mut got2).await.expect("b reads A's bytes");
            assert_eq!(&got2, b"pong-A-to-B", "A's plaintext arrives decrypted at B");

            // Flush + close cleanly before drop so the last frame isn't dropped on the relayed
            // path, then let both session tasks unwind.
            a_app.shutdown().await.ok();
            b_app.shutdown().await.ok();
            drop(a_app);
            drop(b_app);
            let _ = a_task.await;
            let _ = b_task.await;
        })
        .await
        .expect("the relayed Noise round-trip completes within 15s (a hang here is a deadlock)");
    }
}
