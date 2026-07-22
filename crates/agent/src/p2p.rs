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
//! live/public relay node before the membership gate lands.**
//!
//! The DCUtR path ([`connected_dcutr_stream_pair`], #121 B2-dcutr) layers libp2p's
//! **Direct Connection Upgrade through Relay** ([`dcutr::Behaviour`]) onto the relay-client
//! swarms: once two peers are connected *through* the relay, DCUtR coordinates a **direct**
//! connection upgrade (the hole-punch), leaving the relay needed only for setup. This
//! module wires that machinery and proves — on **loopback**, where both peers are already
//! directly reachable, so the upgrade completes trivially or is a no-op — that enabling
//! DCUtR does **not** break the relayed `Noise_IK` session (invariants #1/#2 still hold).
//! The actual *cross-NAT* hole-punch (real NAT'd hosts, no direct reachability) cannot be
//! exercised on loopback and is verified by a **live** real-NAT test, not the cargo gate.
//!
//! The **Kademlia discovery** slice ([`kademlia_publish_and_resolve`], #121 D-kademlia) layers
//! a libp2p `kad` DHT onto the same tokio/TCP transport so a peer can *find* another peer's
//! reachability coordinates by [`ChannelId`] instead of being handed a multiaddr out of band.
//! The DHT record is a `ChannelId → coordinates` mapping whose **value is holder-signed**
//! ([`SignedCoordinateRecord`], **invariant #4**): the channel member signs
//! `domain || channel_id || holder || coordinates` with its ed25519 **holder** key, and a
//! reader **verifies that signature against the record's holder pubkey before trusting the
//! coordinates** ([`SignedCoordinateRecord::verified_coordinates`]). A poisoned record —
//! tampered coordinates or a substituted holder — fails verification and is rejected, so the
//! DHT (like the libp2p `PeerId`, invariant #1) is untrusted plumbing: trust flows only from
//! the holder signature, never from the DHT itself. Only the in-process, loopback-only
//! two-node put/get is exercised by the cargo gate; the real cross-host DHT bootstrap (a
//! central node seeded as the bootstrap peer) is a **live** step, not the cargo gate.

use std::time::Duration;

use ct_common::channel::{verify, ChannelId, GrantError, SignedChannelGrant, UnixSeconds};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use libp2p::core::transport::MemoryTransport;
use libp2p::core::upgrade::Version;
use libp2p::futures::StreamExt;
use libp2p::kad::{self, store::MemoryStore, Quorum, Record, RecordKey};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{dcutr, identify, noise, relay, yamux, Multiaddr, StreamProtocol, Swarm, SwarmBuilder, Transport};
use libp2p_stream as stream;
use tokio::io::{AsyncRead, AsyncWrite};
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

/// The **relay node**'s behaviour: the Circuit-Relay v2 *server* plus an `identify` server. The
/// identify server is essential for the cross-NAT punch (#136) — when a client connects to the
/// relay over QUIC, identify reports back the client's **observed reflexive** (public NAT-mapped)
/// address, which the client then advertises as its DCUtR punch candidate. Without it a client
/// knows only its private listen addr and the direct upgrade fails `NoAddresses`.
#[derive(NetworkBehaviour)]
struct RelayServerBehaviour {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
}

/// Build the **relay node**'s swarm: a Tokio TCP transport upgraded with libp2p-noise +
/// yamux, driving the Circuit-Relay v2 **server** [`relay::Behaviour`]. This node forwards
/// circuits between clients; it terminates none of our channel traffic and never sees
/// anything but our end-to-end ciphertext (invariant #2).
///
/// ⚠️ This relay is **unguarded** — `relay::Config::default()` accepts a reservation/circuit
/// from any peer. That is safe **only** because this helper is test-only and in-process; a
/// live/public relay MUST first gain the invariant-#3 membership gate (`C-membership-gate`).
fn build_relay_swarm() -> Result<Swarm<RelayServerBehaviour>, BoxError> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(Default::default(), noise::Config::new, yamux::Config::default)?
        // #136: also relay over QUIC. If clients reach the relay over QUIC, `identify` observes
        // (and shares) their QUIC reflexive address — the candidate DCUtR punches toward. Over a
        // TCP-only relay leg, identify only surfaces TCP addresses and the QUIC punch has none
        // (`dcutr NoAddresses`).
        .with_quic()
        // #136: the relay MUST run an identify SERVER. That is what tells a connecting client its
        // own **observed reflexive** (public NAT-mapped) QUIC address — the only address DCUtR can
        // punch toward. Without identify on the relay the client learns only its private listen
        // addr and the upgrade dies `NoAddresses` (confirmed in the netns lab). Same protocol
        // string as the client so the exchange is symmetric.
        .with_behaviour(|key| RelayServerBehaviour {
            relay: relay::Behaviour::new(key.public().to_peer_id(), relay::Config::default()),
            identify: identify::Behaviour::new(identify::Config::new(
                "/ct-dcutr-id/1.0.0".to_string(),
                key.public(),
            )),
        })?
        // Keep an otherwise-idle connection (a held reservation carries no app substream)
        // alive long enough for the relayed dial + substream to complete.
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();
    Ok(swarm)
}

/// #136 N-rig-2b (**test-only**, `nat-lab` cargo feature): run the Circuit-Relay v2 relay node
/// as a standalone process for the Docker 2-NAT hole-punch lab. It listens on `listen`, prints
/// each bound multiaddr as `<addr>/p2p/<peerid>` on its own stdout line (so the lab's punch
/// clients can reserve on / dial through it), then drives the swarm forever.
///
/// **NEVER a production capability.** This relay is unguarded ([`build_relay_swarm`] uses
/// `relay::Config::default()`; invariant #3's `C-membership-gate` is not wired here), so it is
/// compiled ONLY under `--features nat-lab` (the `natlab` bin), never exposed as a `ct-agent`
/// subcommand — shipping an open relay would be a footgun.
#[cfg(any(test, feature = "nat-lab"))]
pub async fn nat_lab_relay(listen: &str) -> Result<(), BoxError> {
    let mut swarm = build_relay_swarm()?;
    let peer = *swarm.local_peer_id();
    swarm.listen_on(listen.parse::<Multiaddr>()?)?;
    eprintln!("nat-lab relay: peer {peer}, requested listen {listen}");
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            // The Circuit-Relay v2 server MUST advertise its own external address or a client's
            // reservation is refused (`NoAddressesInReservation`) — confirm the bound address
            // explicitly (as the in-process harness does). Without this the punch clients never
            // reserve. (The relay now ALSO runs an identify server — see `RelayServerBehaviour` —
            // so a connecting client learns its own reflexive address for the DCUtR punch.)
            swarm.add_external_address(address.clone());
            println!("{address}/p2p/{peer}");
        }
    }
}

/// #136 DCUtR **sequencing**: connect to the relay and pump events until identify reports our
/// **reflexive** (public NAT-mapped) external address, confirming it as an external address
/// BEFORE we become dialable / dial the peer. This is the standard libp2p DCUtR ordering: the
/// hole-punch auto-fires the moment the relayed peer connection forms, and DCUtR's `Connect`
/// carries only the external addresses confirmed *at that instant*. If identify hasn't yet run,
/// the Connect goes out address-less and the upgrade dies `NoAddresses` — exactly what the lab
/// showed. Waiting here guarantees the address is in hand first.
#[cfg(any(test, feature = "nat-lab"))]
async fn await_reflexive_via_relay(
    swarm: &mut Swarm<DcutrRelayClientBehaviour>,
    relay: Multiaddr,
) -> Result<(), BoxError> {
    swarm.dial(relay)?;
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return Err("nat-lab: no reflexive address from the relay within 20s".into()),
            ev = swarm.select_next_some() => {
                if let SwarmEvent::Behaviour(DcutrRelayClientBehaviourEvent::Identify(
                    identify::Event::Received { info, .. },
                )) = ev
                {
                    if !info.observed_addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
                        eprintln!("reflexive confirmed via relay: {}", info.observed_addr);
                        swarm.add_external_address(info.observed_addr);
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// #136 N-rig-2b part 2 (**test-only**, `nat-lab` feature): the **listen** punch client — the
/// relay-only peer that *accepts* a punch. Builds a DCUtR client, listens on QUIC (a punchable
/// UDP reflexive address), reserves a slot on `relay` (`<relay>/p2p/<relay-id>`), prints its
/// dialable via-relay address (`LISTEN-ADDR <relay-circuit>/p2p/<self>`) once reserved, then
/// waits for DCUtR to upgrade the relayed connection to **direct** — printing `PUNCH-OK` and
/// exiting on `dcutr::Event { result: Ok(_) }`. Times out (non-zero) if no upgrade occurs.
#[cfg(any(test, feature = "nat-lab"))]
pub async fn nat_lab_listen(relay: Multiaddr) -> Result<(), BoxError> {
    let mut swarm = build_dcutr_relay_client_swarm()?;
    let me = *swarm.local_peer_id();
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?; // punchable QUIC reflexive address
    // #136 sequencing: learn+confirm our reflexive addr from the relay BEFORE reserving (becoming
    // dialable), so the punch that follows has a confirmed external addr to advertise.
    await_reflexive_via_relay(&mut swarm, relay.clone()).await?;
    let relay_circuit = relay.with(Protocol::P2pCircuit);
    swarm.listen_on(relay_circuit.clone())?; // reserve on the relay
    let deadline = tokio::time::sleep(Duration::from_secs(40));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return Err("nat-lab listen: no direct upgrade within 40s".into()),
            ev = swarm.select_next_some() => match ev {
                // Advertise our DIRECT (non-relayed) QUIC listen addresses as external candidates
                // so DCUtR has something to punch toward — without this the inbound side reports
                // NoAddresses and the upgrade fails.
                SwarmEvent::NewListenAddr { address, .. }
                    if !address.iter().any(|p| matches!(p, Protocol::P2pCircuit)) =>
                {
                    swarm.add_external_address(address);
                }
                // The relay observed our PUBLIC reflexive QUIC endpoint over the port-reused QUIC
                // socket (libp2p's quinn Endpoint listens + dials on the same UDP port, so the
                // observed source == our listener's NAT mapping). Feeding it as an external
                // candidate gives DCUtR a *punchable* address to offer — without it the swarm only
                // knows its private `10.0.x.2` listen addr and the upgrade dies with `NoAddresses`.
                SwarmEvent::Behaviour(DcutrRelayClientBehaviourEvent::Identify(
                    identify::Event::Received { info, .. },
                )) if !info.observed_addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) => {
                    eprintln!("listen: relay-observed reflexive {}", info.observed_addr);
                    swarm.add_external_address(info.observed_addr);
                }
                SwarmEvent::Behaviour(DcutrRelayClientBehaviourEvent::RelayClient(
                    relay::client::Event::ReservationReqAccepted { .. },
                )) => println!("LISTEN-ADDR {}/p2p/{}", relay_circuit, me),
                SwarmEvent::Behaviour(DcutrRelayClientBehaviourEvent::Dcutr(e)) => {
                    eprintln!("listen: dcutr event: {e:?}");
                    if matches!(e, dcutr::Event { result: Ok(_), .. }) {
                        println!("PUNCH-OK");
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
    }
}

/// #136 N-rig-2b part 2 (**test-only**, `nat-lab` feature): the **dial** punch client — dials
/// the listener through the relay (`peer_via_relay` = `<relay>/p2p-circuit/p2p/<listener>`),
/// listening on QUIC so it too has a punchable reflexive address, then waits for DCUtR to
/// upgrade the relayed connection to **direct** — printing `PUNCH-OK` and exiting on
/// `dcutr::Event { result: Ok(_) }`. Times out (non-zero) if no upgrade occurs.
#[cfg(any(test, feature = "nat-lab"))]
pub async fn nat_lab_dial(peer_via_relay: Multiaddr) -> Result<(), BoxError> {
    let mut swarm = build_dcutr_relay_client_swarm()?;
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?; // punchable QUIC reflexive address
    // #136 sequencing: confirm our reflexive addr from the relay BEFORE dialing the peer. The
    // relay addr is the prefix of `peer_via_relay` up to the `/p2p-circuit` hop.
    let relay_addr: Multiaddr = peer_via_relay
        .iter()
        .take_while(|p| !matches!(p, Protocol::P2pCircuit))
        .collect();
    await_reflexive_via_relay(&mut swarm, relay_addr).await?;
    swarm.dial(peer_via_relay)?; // dial the listener through the relay
    let deadline = tokio::time::sleep(Duration::from_secs(40));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return Err("nat-lab dial: no direct upgrade within 40s".into()),
            ev = swarm.select_next_some() => {
                // Advertise our direct QUIC listen addresses as external candidates (as the
                // listener does) so DCUtR can punch in both directions.
                if let SwarmEvent::NewListenAddr { address, .. } = &ev {
                    if !address.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
                        swarm.add_external_address(address.clone());
                    }
                }
                // Feed the relay-observed PUBLIC reflexive QUIC endpoint as an external candidate
                // (see the listener) so DCUtR punches toward our NAT mapping, not our private addr.
                if let SwarmEvent::Behaviour(DcutrRelayClientBehaviourEvent::Identify(
                    identify::Event::Received { info, .. },
                )) = &ev
                {
                    if !info.observed_addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
                        eprintln!("dial: relay-observed reflexive {}", info.observed_addr);
                        swarm.add_external_address(info.observed_addr.clone());
                    }
                }
                if let SwarmEvent::Behaviour(DcutrRelayClientBehaviourEvent::Dcutr(e)) = &ev {
                    eprintln!("dial: dcutr event: {e:?}");
                }
                if let SwarmEvent::Behaviour(DcutrRelayClientBehaviourEvent::Dcutr(
                    dcutr::Event { result: Ok(_), .. },
                )) = ev
                {
                    println!("PUNCH-OK");
                    return Ok(());
                }
            }
        }
    }
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

/// The behaviour a **DCUtR-enabled relay client** peer runs: the same Circuit-Relay v2
/// client + raw-substream [`stream::Behaviour`] as [`RelayClientBehaviour`], plus libp2p's
/// [`dcutr::Behaviour`] (Direct Connection Upgrade through Relay — the hole-punch). DCUtR
/// observes the relayed connection and coordinates a **direct** connection upgrade so the
/// relay is only needed for setup. Neither the relay client, DCUtR, nor any `PeerId` is an
/// authorization input (invariant #1) — they only route/upgrade bytes; our `Noise_IK` still
/// runs end-to-end inside the `/ct/channel/1.0.0` substream (invariant #2).
#[derive(NetworkBehaviour)]
pub(crate) struct DcutrRelayClientBehaviour {
    relay_client: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    // #136: `identify` is what lets each peer learn its own **reflexive** (observed public)
    // address — the address DCUtR advertises + punches toward. On loopback it is redundant (the
    // local address is already reachable), but a real cross-NAT hole-punch cannot start without
    // it: with no observed address there is nothing for the peer to tell the other to punch to.
    identify: identify::Behaviour,
    stream: stream::Behaviour,
}

/// Build a **DCUtR-enabled relay client**'s swarm: identical to [`build_relay_client_swarm`]
/// (TCP + noise + yamux + the Circuit-Relay v2 client transport) except its behaviour also
/// carries [`dcutr::Behaviour`], constructed with this peer's own id, so a relayed connection
/// can be upgraded toward a direct one. The DCUtR machinery is wired here; the *cross-NAT*
/// hole-punch it enables is only exercised by a live real-NAT test, never on loopback (where
/// both peers are already directly reachable, so the upgrade is a trivial no-op). As on every
/// transport, the fresh libp2p identity is plumbing — it never gates channel admission
/// (invariant #1).
fn build_dcutr_relay_client_swarm() -> Result<Swarm<DcutrRelayClientBehaviour>, BoxError> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(Default::default(), noise::Config::new, yamux::Config::default)?
        // #136: also carry the QUIC/UDP transport. TCP hole-punching through stateful NAT is
        // unreliable/often infeasible; DCUtR's direct upgrade prefers QUIC (UDP), where the
        // hole-punch actually works — the client must therefore have a QUIC transport + listen
        // address to punch toward. The relay coordination leg can remain TCP.
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| DcutrRelayClientBehaviour {
            relay_client,
            dcutr: dcutr::Behaviour::new(key.public().to_peer_id()),
            // Advertise/observe addresses so DCUtR can discover the reflexive address to punch.
            identify: identify::Behaviour::new(identify::Config::new(
                "/ct-dcutr-id/1.0.0".to_string(),
                key.public(),
            )),
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

/// Connect two **DCUtR-enabled** libp2p peers through a Circuit-Relay v2 relay node and open
/// a single raw stream between them, returning each side as an `AsyncRead + AsyncWrite +
/// Unpin` duplex (the `(dialer, listener)` pair). Structurally identical to
/// [`connected_relayed_stream_pair`] — a **relay** ([`build_relay_swarm`]) plus clients A and
/// B — except the two clients run [`build_dcutr_relay_client_swarm`], so their behaviour also
/// carries [`dcutr::Behaviour`]. A reserves a slot on the relay
/// (`relay::client::Event::ReservationReqAccepted`), B dials A through the relay
/// (`<relay>/p2p-circuit/p2p/<A>`), and once the relayed connection is established B opens the
/// `/ct/channel/1.0.0` substream.
///
/// With DCUtR in the behaviour, once the relayed connection forms the peers may attempt a
/// **direct** connection upgrade (the hole-punch). On loopback both peers are already directly
/// reachable, so that upgrade completes trivially or is a no-op — it never disturbs the
/// relayed substream this helper yields. All swarms are driven forever on detached tasks so
/// the circuit (and any direct upgrade) keeps flowing for the lifetime of the returned
/// streams. As on the plain relay path, the relay is **unguarded** (test-only, in-process),
/// and no `PeerId` is ever an authorization input (invariant #1); callers layer
/// [`crate::channel_run::run_channel_session_on_stream`] on top for auth + encryption
/// (invariant #2).
pub async fn connected_dcutr_stream_pair() -> Result<(P2pDuplex, P2pDuplex), BoxError> {
    // --- Relay node: bind loopback, learn its concrete listen address, then drive it forever
    // so it can route the circuit (and DCUtR's coordination) for the lifetime of the streams. ---
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
    // As on the plain relay path, the Circuit-Relay v2 server must advertise its own external
    // address or the client rejects the reservation (`NoAddressesInReservation`); on loopback
    // there is no identify/AutoNAT to discover it, so confirm the bound address explicitly.
    relay.add_external_address(relay_addr.clone());
    tokio::spawn(async move {
        loop {
            relay.next().await;
        }
    });

    // The circuit addresses (identical shape to `connected_relayed_stream_pair`): `relay_circuit`
    // is what A reserves + listens on; `a_via_relay` appends `/p2p/<A>` — the address B dials to
    // reach A through the relay. The `PeerId`s only name/route the hop, never authorize.
    let client_a = build_dcutr_relay_client_swarm()?;
    let a_peer = *client_a.local_peer_id();
    let relay_circuit = relay_addr
        .with(Protocol::P2p(relay_peer))
        .with(Protocol::P2pCircuit);
    let a_via_relay = relay_circuit.clone().with(Protocol::P2p(a_peer));

    // Client A reserves + accepts inbound substreams — via the production reserve/accept primitive
    // (#136 N136.1), extracted so the LIVE relay-only agent can call the identical logic against a
    // REAL relay. Awaiting it gates B's dial on A's reservation being live end to end.
    let inbound_rx = dcutr_reserve_and_accept(client_a, relay_circuit).await?;

    // Client B dials A **through the relay** and opens the substream — via the production dialer
    // primitive (#136 N136.1), extracted so the LIVE agent path can call the identical logic
    // against a REAL relay instead of this in-process one.
    let client_b = build_dcutr_relay_client_swarm()?;
    let dialer_stream = dcutr_dial_via_relay(client_b, a_via_relay, a_peer).await?;
    let listener_stream = inbound_rx.await?;
    Ok((dialer_stream, listener_stream))
}

/// Reserve a slot on a **Circuit-Relay v2 relay** and accept the first inbound `/ct/channel/1.0.0`
/// substream a peer opens through it (#136 N136.1 — the reserve/accept side of NAT-to-NAT, the
/// relay-only peer's half). `relay_circuit` is `<relay>/p2p-circuit`; the caller advertises its own
/// via-relay address (`relay_circuit.with(P2p(own_peer))`) so a peer can dial it. Awaits the
/// reservation being accepted (so a dial can't race ahead of it), then drives the swarm forever on a
/// detached task — routing DCUtR's upgrade coordination — and delivers the first inbound stream on
/// the returned channel. Extracted from [`connected_dcutr_stream_pair`] so the live relay-only agent
/// uses the identical logic against the real edge relay. Callers layer
/// [`crate::a2a::establish_direct_over_duplex`] on top for auth + encryption (invariant #2); the
/// `PeerId` only names/routes the hop, never authorizes (invariant #1).
pub(crate) async fn dcutr_reserve_and_accept(
    mut client: Swarm<DcutrRelayClientBehaviour>,
    relay_circuit: Multiaddr,
) -> Result<tokio::sync::oneshot::Receiver<P2pDuplex>, BoxError> {
    let mut incoming = client.behaviour().stream.new_control().accept(CT_CHANNEL_PROTOCOL)?;
    client.listen_on(relay_circuit)?;
    let (reserved_tx, reserved_rx) = tokio::sync::oneshot::channel();
    let (inbound_tx, inbound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut reserved_tx = Some(reserved_tx);
        let mut inbound_tx = Some(inbound_tx);
        loop {
            tokio::select! {
                ev = client.next() => {
                    if let Some(SwarmEvent::Behaviour(DcutrRelayClientBehaviourEvent::RelayClient(
                        relay::client::Event::ReservationReqAccepted { .. },
                    ))) = ev
                    {
                        if let Some(tx) = reserved_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                }
                Some((_peer, stream)) = incoming.next() => {
                    if let Some(tx) = inbound_tx.take() {
                        let _ = tx.send(stream.compat());
                    }
                }
            }
        }
    });
    reserved_rx
        .await
        .map_err(|_| "client driver ended before its relay reservation was accepted")?;
    Ok(inbound_rx)
}

/// Dial a DCUtR-enabled peer **through a Circuit-Relay v2 relay** and open the `/ct/channel/1.0.0`
/// substream, returning it as an `AsyncRead + AsyncWrite` duplex (#136 N136.1 — the dialer side of
/// NAT-to-NAT). `client` is a DCUtR relay-client swarm ([`build_dcutr_relay_client_swarm`]);
/// `peer_via_relay` is the target's circuit address (`<relay>/p2p-circuit/p2p/<target>`);
/// `target_peer` names the relayed connection to wait for. The swarm is driven forever on a detached
/// task so the circuit — and any DCUtR **direct upgrade** (the hole-punch) — keeps flowing for the
/// returned stream's lifetime.
///
/// Extracted from the in-process test harness ([`connected_dcutr_stream_pair`]) so the **live** agent
/// path can dial a relay-only peer through the edge's Circuit-Relay v2 leg (#136, coordination-only,
/// per central's decision) instead of only in tests. Callers layer
/// [`crate::a2a::establish_direct_over_duplex`] on top for auth + encryption (invariant #2); no
/// `PeerId` is ever an authorization input (invariant #1) — it only names the dial/route target.
pub(crate) async fn dcutr_dial_via_relay(
    mut client: Swarm<DcutrRelayClientBehaviour>,
    peer_via_relay: Multiaddr,
    target_peer: libp2p::PeerId,
) -> Result<P2pDuplex, BoxError> {
    let mut control = client.behaviour().stream.new_control();
    let (outbound_tx, outbound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if client.dial(peer_via_relay).is_err() {
            return;
        }
        // Wait for the RELAYED connection to the target (not the hop to the relay) before opening.
        loop {
            match client.next().await {
                Some(SwarmEvent::ConnectionEstablished { peer_id, .. }) if peer_id == target_peer => break,
                Some(_) => {}
                None => return,
            }
        }
        let open = control.open_stream(target_peer, CT_CHANNEL_PROTOCOL);
        tokio::pin!(open);
        let mut outbound_tx = Some(outbound_tx);
        loop {
            tokio::select! {
                _ = client.next() => {}
                res = &mut open, if outbound_tx.is_some() => {
                    if let (Ok(stream), Some(tx)) = (res, outbound_tx.take()) {
                        let _ = tx.send(stream);
                    }
                }
            }
        }
    });
    Ok(outbound_rx.await?.compat())
}

/// **#136 N136.3 relay-pinning guard** — validate the peer-conveyed DCUtR upgrade address before the
/// responder dials it. In the NAT-to-NAT upgrade the initiator advertises its via-relay circuit
/// address (`<relay>/p2p-circuit/p2p/<initiator>`) in-band over the relay pump, exactly as the
/// plain-QUIC path advertises a `SocketAddr` — so it is untrusted, and the SSRF concern of #137
/// recurs in a new shape: a malicious initiator could advertise a circuit routed through an
/// **attacker-controlled relay**. Pin it: the `offered` address must be EXACTLY the responder's own
/// `trusted_circuit` (its configured edge Circuit-Relay v2 leg) followed by a single `/p2p/<target>`.
/// Returns the target [`libp2p::PeerId`] to dial ONLY if the relay prefix matches; `None`
/// (unparseable, wrong/extra relay, or no trailing target peer) refuses the upgrade → stay on relay.
// Live via the N-wire DCUtR join (run_channel_session_upgradable_dcutr's responder relay-pin).
pub(crate) fn dcutr_upgrade_target(offered: &str, trusted_circuit: &Multiaddr) -> Option<libp2p::PeerId> {
    let addr: Multiaddr = offered.parse().ok()?;
    let mut protos: Vec<Protocol> = addr.iter().collect();
    // The trailing component must name the target peer; everything before it must be our relay.
    let target = match protos.pop()? {
        Protocol::P2p(peer) => peer,
        _ => return None,
    };
    let prefix: Multiaddr = protos.into_iter().collect();
    (&prefix == trusted_circuit).then_some(target)
}

/// **#136 N136.3 — the NAT-to-NAT upgradable session.** Run one side of an A2A channel over the base
/// relay stream (`relay_send`/`relay_recv`, the edge Noise pump halves) as an UPGRADABLE session that
/// opportunistically hole-punches to a **direct** link via DCUtR and cuts the byte stream over — for
/// two peers that are *both* NAT'd (neither has a dialable `SocketAddr`, so the #104 plain-QUIC path
/// can't help them). Composes [`ct_common::upgrade::run_upgradable_session_initiator`]/`_responder`
/// (transport-agnostic orchestration) with the DCUtR primitives: the **initiator** reserves a slot on
/// `circuit_relay` (its configured edge Circuit-Relay v2 leg) via [`dcutr_reserve_and_accept`],
/// advertises its `<relay>/p2p-circuit/p2p/<self>` address in-band (the Offer), and on `Ready` accepts
/// the incoming DCUtR stream + [`ct_common::a2a::establish_direct_over_duplex`] as the direct-Noise
/// RESPONDER; the **responder** validates the offered address against its own `circuit_relay`
/// ([`dcutr_upgrade_target`], the #137-analog relay pin), dials it via [`dcutr_dial_via_relay`], and
/// establishes as the direct-Noise INITIATOR. Hole-punch failure stays on the relay; the relay leg is
/// end-to-end throughout. The live cross-NAT punch is proven on the deploy (#136 N136.4); this over an
/// in-process relay on loopback.
#[allow(clippy::too_many_arguments)]
// #136 N-wire: live via `channel_run::join_via_relay_dcutr` (relay-only members with a
// `CT_CHANNEL_CIRCUIT_RELAY` configured); the cross-NAT punch is proven in the Docker 2-NAT lab.
pub(crate) async fn run_channel_session_upgradable_dcutr<RW, RR, P>(
    relay_send: RW,
    relay_recv: RR,
    local: P,
    role: crate::channel_run::ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    circuit_relay: Multiaddr,
) -> Result<(), BoxError>
where
    RW: AsyncWrite + Unpin,
    RR: AsyncRead + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    use ct_common::upgrade::{
        run_upgradable_session_initiator, run_upgradable_session_responder, Role, UpgradeCoordinator,
    };
    // The relay handshake borrows these; the direct-establishment closures need owned copies.
    let (relay_priv, relay_peer) = (*own_noise_private, *peer_noise_public);
    let (direct_priv, direct_peer) = (*own_noise_private, *peer_noise_public);

    match role {
        crate::channel_run::ChannelRole::Initiate => {
            // Reserve on the relay up front → we know our advertised circuit address, and the inbound
            // DCUtR stream (from the responder's dial) arrives on `inbound_rx` later.
            let client = build_dcutr_relay_client_swarm()?;
            let own_peer = *client.local_peer_id();
            let advertise = circuit_relay.clone().with(Protocol::P2p(own_peer)).to_string();
            let inbound_rx = dcutr_reserve_and_accept(client, circuit_relay).await?;
            let coord = UpgradeCoordinator::with_backoff(Role::Initiator, 0, 1, 100);
            run_upgradable_session_initiator(
                relay_send,
                relay_recv,
                local,
                &relay_priv,
                &relay_peer,
                coord,
                1,
                || async move { Some(advertise) },
                move || async move {
                    let stream = inbound_rx.await.ok()?;
                    ct_common::a2a::establish_direct_over_duplex(stream, false, &direct_priv, &direct_peer)
                        .await
                        .ok()
                },
            )
            .await
            .map_err(Into::into)
        }
        crate::channel_run::ChannelRole::Accept => {
            let client = build_dcutr_relay_client_swarm()?;
            let coord = UpgradeCoordinator::with_backoff(Role::Responder, 0, 1, 100);
            run_upgradable_session_responder(
                relay_send,
                relay_recv,
                local,
                &relay_priv,
                coord,
                1,
                {
                    let trusted = circuit_relay.clone();
                    move |ep: String| async move { dcutr_upgrade_target(&ep, &trusted).is_some() }
                },
                move |ep: String| async move {
                    // Relay-pin the peer-conveyed circuit address, then dial the target through it.
                    let target = dcutr_upgrade_target(&ep, &circuit_relay)?;
                    let addr: Multiaddr = ep.parse().ok()?;
                    let stream = dcutr_dial_via_relay(client, addr, target).await.ok()?;
                    ct_common::a2a::establish_direct_over_duplex(stream, true, &direct_priv, &direct_peer)
                        .await
                        .ok()
                },
            )
            .await
            .map_err(Into::into)
        }
    }
}

/// The domain-separation tag for a DHT coordinate record's signing preimage. A distinct,
/// versioned prefix keeps this signature from ever being confused with a grant, an
/// invitation, or the member-Noise attestation (`ct-a2a-noise-attest-v1`) — exactly as the
/// rest of `ct_common::channel` domain-separates every signed message.
const COORDINATE_RECORD_DOMAIN: &[u8] = b"ct-a2a-dht-coordinate-v1";

/// A **holder-signed** Kademlia DHT record mapping a [`ChannelId`] to a channel member's
/// reachability `coordinates` (#121 D-kademlia, **invariant #4**).
///
/// Discovery answers "where do I reach the peer for this channel?" — but the DHT that answers
/// it is untrusted plumbing (any node can inject a record for any key), so the *answer* must
/// authenticate itself. The channel member signs `domain || channel_id || holder ||
/// coordinates` with its ed25519 **holder** key (the same key that authorizes its channel
/// membership and attests its Noise static key, `ct_common::channel::member_noise_attest_bytes`);
/// a reader **must** call [`verified_coordinates`](Self::verified_coordinates) and trust the
/// coordinates **only if** the signature verifies against the record's `holder` pubkey. A
/// poisoned record — tampered `coordinates`, or a `holder` swapped for someone else's key —
/// fails that check and is rejected, so a DHT node cannot forge a peer's location. Trust flows
/// from the holder signature, never from the DHT or the libp2p `PeerId` (invariant #1).
///
/// The record travels as the *value* of a libp2p [`Record`] keyed by the raw [`ChannelId`]
/// bytes; [`encode`](Self::encode)/[`decode`](Self::decode) are the wire form:
/// `holder(32) || signature(64) || coordinates(rest)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCoordinateRecord {
    /// The channel member's ed25519 **holder** public key — the identity the signature is
    /// checked against. NOT a libp2p `PeerId`.
    pub holder: [u8; 32],
    /// The reachability coordinates the holder is publishing for the channel (e.g. an
    /// advertised multiaddr). Opaque bytes here — only their authenticity matters at this seam.
    pub coordinates: Vec<u8>,
    /// The holder's ed25519 signature over [`signing_bytes`](Self::signing_bytes).
    pub signature: [u8; 64],
}

impl SignedCoordinateRecord {
    /// The canonical, domain-separated preimage the holder signs: `domain || channel_id ||
    /// holder || coordinates`. Binding `channel` and `holder` into the preimage (not just the
    /// coordinates) means a record can't be replayed onto a different channel and a substituted
    /// `holder` can't validate — the signature only verifies for the exact `(channel, holder,
    /// coordinates)` triple.
    fn signing_bytes(channel: &ChannelId, holder: &[u8; 32], coordinates: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(COORDINATE_RECORD_DOMAIN.len() + 32 + 32 + coordinates.len());
        m.extend_from_slice(COORDINATE_RECORD_DOMAIN);
        m.extend_from_slice(&channel.0);
        m.extend_from_slice(holder);
        m.extend_from_slice(coordinates);
        m
    }

    /// Sign `coordinates` for `channel` with the member's ed25519 **holder** `SigningKey`,
    /// producing a record a reader can authenticate without trusting the DHT (invariant #4).
    pub fn sign(channel: &ChannelId, coordinates: &[u8], holder_key: &SigningKey) -> Self {
        let holder = holder_key.verifying_key().to_bytes();
        let signature = holder_key
            .sign(&Self::signing_bytes(channel, &holder, coordinates))
            .to_bytes();
        Self {
            holder,
            coordinates: coordinates.to_vec(),
            signature,
        }
    }

    /// The wire form stored as the libp2p [`Record`] value:
    /// `holder(32) || signature(64) || coordinates(rest)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 64 + self.coordinates.len());
        v.extend_from_slice(&self.holder);
        v.extend_from_slice(&self.signature);
        v.extend_from_slice(&self.coordinates);
        v
    }

    /// Parse a record from its wire form. Returns `None` on a truncated buffer (fewer than the
    /// fixed `32 + 64` header bytes). Decoding does **not** authenticate — the caller must still
    /// call [`verified_coordinates`](Self::verified_coordinates); a decodable record can still be
    /// a poisoned one.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 96 {
            return None;
        }
        let mut holder = [0u8; 32];
        holder.copy_from_slice(&bytes[..32]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[32..96]);
        Some(Self {
            holder,
            coordinates: bytes[96..].to_vec(),
            signature,
        })
    }

    /// Whether the holder signature verifies for `channel` — i.e. the record is authentic
    /// (invariant #4). `false` on a malformed `holder` key, a wrong `(channel, holder,
    /// coordinates)` binding, or a bad signature.
    pub fn verify(&self, channel: &ChannelId) -> bool {
        match VerifyingKey::from_bytes(&self.holder) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(channel, &self.holder, &self.coordinates),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }

    /// The trusted coordinates — `Some` **only if** the holder signature verifies for `channel`
    /// (invariant #4), `None` for a poisoned/unauthentic record. This is the single gate a
    /// reader uses before acting on a discovered location: never read `coordinates` directly.
    pub fn verified_coordinates(&self, channel: &ChannelId) -> Option<&[u8]> {
        if self.verify(channel) {
            Some(&self.coordinates)
        } else {
            None
        }
    }
}

/// Build a minimal libp2p **Kademlia** swarm over loopback TCP (noise + yamux), driving a
/// single `kad::Behaviour` backed by an in-memory record store. Structurally identical to
/// [`build_tcp_swarm`] except the behaviour is the DHT. The node is put into
/// [`kad::Mode::Server`] so it actually stores and serves records on our controlled two-node
/// loopback net (a node otherwise stays a client until it confirms an external address, which
/// never happens without identify/AutoNAT here). As on every transport, the fresh libp2p
/// identity is plumbing — it never gates channel admission (invariant #1); the record's holder
/// signature is the only trust input (invariant #4).
fn build_kad_swarm() -> Result<Swarm<kad::Behaviour<MemoryStore>>, BoxError> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(Default::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();
            let mut kad = kad::Behaviour::new(peer_id, MemoryStore::new(peer_id));
            kad.set_mode(Some(kad::Mode::Server));
            kad
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();
    Ok(swarm)
}

/// Publish a coordinate record on an in-process Kademlia DHT from node A and **resolve it by
/// [`ChannelId`] from a second node B** — the discovery counterpart of the connectivity seams
/// above (#121 D-kademlia). Two in-process nodes run over TCP loopback: node A
/// ([`build_kad_swarm`]) `put_record`s `record_value` under the key `channel`; node B is
/// bootstrapped to A (A's listen address added to B's routing table) and issues a
/// `get_record` for the same `channel`, returning the **raw record bytes** it retrieved from
/// the DHT. Both swarms are polled together to completion — a common bug is polling only the
/// querying swarm so A never answers and the query stalls.
///
/// This returns *untrusted* plumbing output, exactly like [`connected_tcp_stream_pair`]
/// returns an untrusted duplex: the caller MUST [`decode`](SignedCoordinateRecord::decode) +
/// [`verified_coordinates`](SignedCoordinateRecord::verified_coordinates) the bytes and reject
/// a record whose holder signature does not verify (invariant #4). The libp2p `PeerId`s only
/// route the queries; none authorizes anything (invariant #1). Loopback-only — the real
/// cross-host bootstrap (a central node seeded as the bootstrap peer) is a live step.
pub async fn kademlia_publish_and_resolve(
    channel: &ChannelId,
    record_value: Vec<u8>,
) -> Result<Vec<u8>, BoxError> {
    let key = RecordKey::new(&channel.0);

    // --- Node A (publisher): bind loopback, learn its concrete listen address, then store the
    // record locally under `key`. `put_record` inserts into A's own store synchronously, so the
    // record is resolvable as soon as B can reach A — no put/get race. ---
    let mut node_a = build_kad_swarm()?;
    let a_peer = *node_a.local_peer_id();
    node_a.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
    let a_addr: Multiaddr = loop {
        match node_a.next().await {
            Some(SwarmEvent::NewListenAddr { address, .. }) => break address,
            Some(_) => {}
            None => return Err("kad node A closed before reporting a listen address".into()),
        }
    };
    node_a.behaviour_mut().put_record(
        Record {
            key: key.clone(),
            value: record_value,
            publisher: Some(a_peer),
            expires: None,
        },
        Quorum::One,
    )?;

    // --- Node B (resolver): learn A as a peer (bootstrap seed), then query the ChannelId. ---
    let mut node_b = build_kad_swarm()?;
    node_b.behaviour_mut().add_address(&a_peer, a_addr);
    // Bootstrap populates B's routing table from the seed; ignore `NoKnownPeers` — `add_address`
    // already gave B the one peer it needs, and `get_record` dials A on its own.
    let _ = node_b.behaviour_mut().bootstrap();
    node_b.behaviour_mut().get_record(key);

    // Drive BOTH swarms so A answers B's query. Return the first record B resolves; surface a
    // lookup failure rather than hanging (the test's outer timeout is the last-resort guard).
    loop {
        tokio::select! {
            _ = node_a.next() => {}
            ev = node_b.next() => {
                match ev {
                    Some(SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))),
                        ..
                    })) => {
                        return Ok(peer_record.record.value);
                    }
                    Some(SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::GetRecord(Err(err)),
                        ..
                    })) => {
                        return Err(format!("kad get_record failed: {err:?}").into());
                    }
                    None => return Err("kad node B swarm closed before resolving the record".into()),
                    _ => {}
                }
            }
        }
    }
}

/// Why a peer may **not** use a superpeer's Circuit-Relay for a given channel
/// ([`authorize_relay_circuit`], invariant #3). Distinct variants so a relay can log
/// *which* containment rule refused a circuit without leaking grant contents.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayCircuitError {
    /// The **relay's own** grant is invalid (bad operator signature, expired, …): a node
    /// with no authentic membership must never relay at all.
    RelayGrantInvalid(GrantError),
    /// The relay's grant is authentic but for a **different channel** than the circuit —
    /// invariant #3: a superpeer relays ONLY channels it is itself a grant-member of, so
    /// it can learn nothing beyond membership it already holds.
    RelayNotMember,
    /// The **requester's** grant is invalid — a peer with no authentic membership can't
    /// use the relay.
    RequesterGrantInvalid(GrantError),
    /// The requester's grant is authentic but for a **different channel** than the circuit
    /// it is asking to open — it has not proven co-membership on this channel.
    RequesterChannelMismatch,
}

impl std::fmt::Display for RelayCircuitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayCircuitError::RelayGrantInvalid(e) => write!(f, "relay's own grant invalid: {e}"),
            RelayCircuitError::RelayNotMember => {
                write!(f, "relay is not a grant-member of the circuit's channel")
            }
            RelayCircuitError::RequesterGrantInvalid(e) => {
                write!(f, "requester grant invalid: {e}")
            }
            RelayCircuitError::RequesterChannelMismatch => {
                write!(f, "requester grant is for a different channel than the circuit")
            }
        }
    }
}

impl std::error::Error for RelayCircuitError {}

/// **Invariant #3 admission gate for a superpeer's Circuit-Relay.** A superpeer (any
/// member the operator lets relay) must forward a circuit **only** for a channel it is
/// itself a grant-member of, and only to a peer that proves co-membership on that same
/// channel — so the relay learns nothing beyond membership it already holds, and an
/// unguarded open relay can't be abused to forward arbitrary peers' circuits.
///
/// The `C-circuit-relay-transport` slice's libp2p relay is deliberately UNGUARDED
/// (it relays any circuit) and is therefore test-only; this predicate is the check that
/// makes a live/public relay safe to run. It is the exact analog of the broker's
/// [`ct_edge`-side `authorize_channel_pair`], applied to relay *use* instead of a direct
/// pairing.
///
/// Enforced, in order:
/// 1. the **relay's** grant `relay_grant` verifies against `operator_pubkey` at `now`
///    (authentic + unexpired) — else [`RelayCircuitError::RelayGrantInvalid`];
/// 2. that grant is for **this** `circuit_channel` — else
///    [`RelayCircuitError::RelayNotMember`] (invariant #3: relay only your own channels);
/// 3. the **requester's** grant `requester_grant` verifies — else
///    [`RelayCircuitError::RequesterGrantInvalid`];
/// 4. it too is for `circuit_channel` — else [`RelayCircuitError::RequesterChannelMismatch`].
///
/// The libp2p `PeerId` is **never** consulted (invariant #1): authorization is purely the
/// operator-signed grants, exactly as everywhere else. Like [`verify`], this does NOT
/// check holder *possession* — that is a connect-time challenge (as in the broker's
/// `admit_channel_join_on_duplex`) layered on when this predicate is wired to the live
/// relayed substream; here it establishes both grants are authentic and co-membership on
/// the circuit's channel.
pub fn authorize_relay_circuit(
    operator_pubkey: &[u8; 32],
    relay_grant: &SignedChannelGrant,
    requester_grant: &SignedChannelGrant,
    circuit_channel: &ChannelId,
    now: UnixSeconds,
) -> Result<(), RelayCircuitError> {
    // 1–2. The relay must itself hold an authentic grant FOR THIS channel (invariant #3).
    verify(operator_pubkey, relay_grant, now).map_err(RelayCircuitError::RelayGrantInvalid)?;
    if relay_grant.grant.channel != *circuit_channel {
        return Err(RelayCircuitError::RelayNotMember);
    }
    // 3–4. The requester must prove co-membership on the same channel.
    verify(operator_pubkey, requester_grant, now)
        .map_err(RelayCircuitError::RequesterGrantInvalid)?;
    if requester_grant.grant.channel != *circuit_channel {
        return Err(RelayCircuitError::RequesterChannelMismatch);
    }
    Ok(())
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

    #[tokio::test]
    async fn channel_noise_session_runs_with_dcutr_enabled_over_the_relay() {
        // #121 B2-dcutr (frozen): the SAME relayed proof as
        // `channel_noise_session_runs_over_a_libp2p_circuit_relay`, but both clients now carry
        // libp2p's **DCUtR** (Direct Connection Upgrade through Relay — the hole-punch) in
        // their behaviour. Relay + A + B run in-process on TCP loopback; A reserves a slot on
        // the relay, B dials A *via the relay*, opens a raw substream, and each side runs the
        // EXISTING transport-agnostic `run_channel_session_on_stream` over its half. With DCUtR
        // wired, once the relayed connection forms the peers may attempt a **direct** upgrade;
        // on loopback both are already directly reachable, so that upgrade completes trivially
        // or is a no-op. The POINT of this test is that **enabling DCUtR does not break the
        // relayed session** — the machinery is wired end to end.
        //
        // We do NOT assert a DCUtR upgrade event: on loopback (no NAT, no identify-observed
        // addresses) whether/when DCUtR fires is timing-dependent, so asserting it would be
        // flaky. The real *cross-NAT* hole-punch — DCUtR's actual value — needs real NAT'd
        // hosts and is verified by a LIVE test, not this cargo gate.
        //
        // Invariant #1 (authz = the grant, NOT any libp2p PeerId): admission is purely
        // key-based — each side is keyed *only* by the members' channel-attested Noise static
        // keys (`a_priv`/`b_pub`, `b_priv`/`a_pub`). The relay's, the clients', and DCUtR's
        // PeerIds only named/routed/upgraded the hop; none is ever consulted for authorization.
        // Invariant #2: the Noise tunnel is formed over the relayed stream — a real payload
        // round-trips in BOTH directions, proving our end-to-end encryption sits on top of the
        // relay + DCUtR plumbing, which sees only ciphertext.

        // Channel-attested member Noise keys — the ONLY admission input.
        let a = generate_static_keypair();
        let b = generate_static_keypair();
        let (a_priv, a_pub) = (a.private, a.public);
        let (b_priv, b_pub) = (b.private, b.public);

        // The multi-step relayed setup (reservation → relayed dial → substream) plus DCUtR's
        // upgrade coordination is fully event-driven, but a regression that stalled any step —
        // including a DCUtR stall — would otherwise hang forever (`cargo test` has no per-test
        // timeout). Bound the whole path so a deadlock FAILS FAST instead of wedging the gate.
        // 15s is ~100x the in-process happy path.
        tokio::time::timeout(Duration::from_secs(15), async move {
            // The libp2p relayed stream with DCUtR-enabled clients: untrusted plumbing carrying
            // our ciphertext. B reached A through the relay.
            let (dialer_stream, listener_stream) = connected_dcutr_stream_pair()
                .await
                .expect("two DCUtR-enabled libp2p peers connect THROUGH a Circuit-Relay v2 relay");

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

            // B -> A over the Noise tunnel formed inside the relayed stream (DCUtR enabled).
            b_app.write_all(b"ping-B-to-A").await.expect("b writes");
            let mut got = [0u8; 11];
            a_app.read_exact(&mut got).await.expect("a reads B's bytes");
            assert_eq!(&got, b"ping-B-to-A", "B's plaintext arrives decrypted at A with DCUtR wired");

            // A -> B: prove the tunnel round-trips both directions with DCUtR enabled.
            a_app.write_all(b"pong-A-to-B").await.expect("a writes");
            let mut got2 = [0u8; 11];
            b_app.read_exact(&mut got2).await.expect("b reads A's bytes");
            assert_eq!(&got2, b"pong-A-to-B", "A's plaintext arrives decrypted at B");

            // Flush + close cleanly before drop so the last frame isn't dropped, then let both
            // session tasks unwind.
            a_app.shutdown().await.ok();
            b_app.shutdown().await.ok();
            drop(a_app);
            drop(b_app);
            let _ = a_task.await;
            let _ = b_task.await;
        })
        .await
        .expect("the DCUtR-enabled relayed Noise round-trip completes within 15s (a hang here is a deadlock)");
    }

    #[tokio::test]
    async fn direct_establishment_adapter_completes_over_a_dcutr_stream() {
        // #136 N136.2 (frozen): the #104 upgrade's *direct-establishment adapter*
        // (`establish_direct_over_duplex` → `establish_direct_session`) completes over a real
        // DCUtR-hole-punched stream and yields the pump-ready `(TransportState, read, write)` — the
        // EXACT op the NAT-to-NAT wire-in (N136.3) injects in place of the plain-QUIC
        // `dial_peer_direct`. Distinct from the full-session test above: this exercises the handshake
        // adapter that feeds the multiplexed pump's late-bind one-shot. Loopback (punch trivial); the
        // live cross-NAT punch is N136.4. Bounded so a stall fails fast instead of wedging the gate.
        use ct_common::a2a::{a2a_recv, a2a_send, establish_direct_over_duplex};
        use ct_common::noise::generate_static_keypair;
        tokio::time::timeout(Duration::from_secs(15), async move {
            let (dialer_stream, listener_stream) = connected_dcutr_stream_pair()
                .await
                .expect("two DCUtR-enabled peers connect through the relay");
            let a = generate_static_keypair();
            let b = generate_static_keypair();
            // The dialer (initiator) pins the peer's `b_pub`; the responder needs no peer key.
            let (a_priv, b_priv, b_pub) = (a.private, b.private, b.public);

            // The dialer opened the substream (writes first), so it is the direct-Noise INITIATOR.
            let dialer_task = tokio::spawn(async move {
                establish_direct_over_duplex(dialer_stream, true, &a_priv, &b_pub).await
            });
            let (mut lts, mut lr, mut lw) =
                establish_direct_over_duplex(listener_stream, false, &b_priv, &[0u8; 32])
                    .await
                    .expect("listener establishes the direct session over DCUtR");
            let (mut dts, mut dr, mut dw) = dialer_task
                .await
                .expect("join")
                .expect("dialer establishes the direct session over DCUtR");

            // The returned transports + halves form a working encrypted tunnel in both directions.
            a2a_send(&mut dw, &mut dts, b"ping-dcutr").await.expect("dialer sends");
            assert_eq!(a2a_recv(&mut lr, &mut lts).await.expect("listener recv"), b"ping-dcutr");
            a2a_send(&mut lw, &mut lts, b"pong-dcutr").await.expect("listener sends");
            assert_eq!(a2a_recv(&mut dr, &mut dts).await.expect("dialer recv"), b"pong-dcutr");
        })
        .await
        .expect("the DCUtR direct-establishment adapter round-trips within 15s (a hang here is a deadlock)");
    }

    #[tokio::test]
    async fn kademlia_resolves_a_holder_signed_coordinate_record() {
        // #121 D-kademlia (frozen): DISCOVERY, not connectivity. Node A publishes a holder-signed
        // `ChannelId → coordinates` record on an in-process libp2p Kademlia DHT; node B, bootstrapped
        // to A, resolves the ChannelId, GETS the record, and VERIFIES the holder signature before
        // trusting the coordinates. Then the SECURITY property (invariant #4): a poisoned record —
        // tampered coordinates or a substituted holder — is REJECTED by the verify gate, so a DHT
        // node cannot forge a peer's location.
        //
        // Invariant #1 (authz/trust is NOT the libp2p PeerId): the DHT and its PeerIds are untrusted
        // plumbing that only route the put/get queries. Invariant #4 (records are holder-signed):
        // trust flows solely from the channel member's ed25519 holder signature over
        // `domain || channel_id || holder || coordinates` — never from the DHT itself.

        // A deterministic holder key (no rng in tests) — the channel member's ed25519 holder
        // identity, exactly the key that authorizes its membership elsewhere in ct_common.
        let holder_key = SigningKey::from_bytes(&[9u8; 32]);
        let channel = ChannelId([0x11u8; 32]);
        let coordinates = b"/ip4/198.51.100.7/tcp/4242".to_vec();

        // The authentic, holder-signed record A will publish.
        let record = SignedCoordinateRecord::sign(&channel, &coordinates, &holder_key);

        // The multi-step DHT setup (listen → put → bootstrap → get) is fully event-driven, but a
        // regression that stalled any step — classically polling only the querying swarm so A never
        // answers — would otherwise hang forever (`cargo test` has no per-test timeout). Bound the
        // whole path so a deadlock FAILS FAST instead of wedging the gate. 15s is ~orders of
        // magnitude over the in-process happy path.
        tokio::time::timeout(Duration::from_secs(15), async {
            // Node A publishes; node B (bootstrapped to A) resolves the ChannelId and gets the raw
            // record bytes back out of the DHT — untrusted plumbing output until verified.
            let fetched = kademlia_publish_and_resolve(&channel, record.encode())
                .await
                .expect("node B resolves the ChannelId and gets A's published record from the DHT");

            let decoded = SignedCoordinateRecord::decode(&fetched)
                .expect("the retrieved DHT record decodes to a coordinate record");

            // The coordinates round-tripped through the DHT unchanged...
            assert_eq!(
                decoded.coordinates, coordinates,
                "the resolved coordinates match what A published"
            );
            // ...AND — the whole point (invariant #4) — the holder signature verifies, so B may trust
            // them: `verified_coordinates` returns exactly the published bytes.
            assert_eq!(
                decoded.verified_coordinates(&channel),
                Some(coordinates.as_slice()),
                "the resolved record's holder signature verifies, so its coordinates are trusted (#4)"
            );
        })
        .await
        .expect("the Kademlia publish→resolve completes within 15s (a hang here is a deadlock)");

        // --- Security property (invariant #4): a poisoned record is REJECTED by the verify gate. ---

        // (a) TAMPERED COORDINATES: keep A's valid signature but flip the coordinates the reader
        // sees. The signature no longer matches the `(channel, holder, coordinates)` preimage, so
        // `verified_coordinates` returns None — the forged location cannot be trusted.
        let mut poisoned = record.clone();
        poisoned.coordinates = b"/ip4/203.0.113.66/tcp/9999".to_vec(); // attacker's endpoint
        assert!(
            !poisoned.verify(&channel),
            "a record with tampered coordinates must fail holder-signature verification (#4)"
        );
        assert_eq!(
            poisoned.verified_coordinates(&channel),
            None,
            "a poisoned (tampered-coordinates) record is rejected, not trusted (#4)"
        );

        // (b) SUBSTITUTED HOLDER: an attacker signs coordinates with its OWN key but stamps the
        // victim's holder pubkey on the record. The signature can't validate against the claimed
        // holder, so it is rejected — a DHT operator can't impersonate a member's coordinate record.
        let attacker_key = SigningKey::from_bytes(&[13u8; 32]);
        let mut wrong_holder = SignedCoordinateRecord::sign(&channel, &coordinates, &attacker_key);
        wrong_holder.holder = holder_key.verifying_key().to_bytes(); // claim to be the victim
        assert!(
            !wrong_holder.verify(&channel),
            "a record whose holder pubkey was swapped for the victim's must fail verification (#4)"
        );
        assert_eq!(
            wrong_holder.verified_coordinates(&channel),
            None,
            "a poisoned (substituted-holder) record is rejected, not trusted (#4)"
        );
    }

    // ---- C-membership-gate: invariant #3 relay authorization ------------------------------

    /// Sign a grant for `channel`/`holder` under the deterministic operator key `op` (byte
    /// fill), returning the operator pubkey and the signed grant. Pure — no rng in tests.
    fn grant_for(op: u8, channel: [u8; 32], holder: [u8; 32]) -> ([u8; 32], SignedChannelGrant) {
        use ct_common::channel::{ChannelGrant, Direction, Rights};
        let sk = SigningKey::from_bytes(&[op; 32]);
        let grant = ChannelGrant {
            channel: ChannelId(channel),
            holder,
            direction: Direction::Both,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 10_000,
        };
        let signature = sk.sign(&grant.signing_bytes()).to_bytes();
        (sk.verifying_key().to_bytes(), SignedChannelGrant { grant, signature })
    }

    #[test]
    fn relay_circuit_authz_enforces_invariant_3_membership_containment() {
        // #121 C-membership-gate (frozen): a superpeer's Circuit-Relay admits a circuit ONLY
        // for a channel it is itself a grant-member of, and only for a requester that proves
        // co-membership on that same channel (invariant #3 — the relay learns nothing beyond
        // membership it already holds, and an open relay can't be abused). Authorization is
        // purely the operator-signed grants; the libp2p PeerId is never an input (invariant
        // #1 — structurally, `authorize_relay_circuit` has no PeerId parameter).
        let now = 1_000;
        let ch_a = [0x11u8; 32]; // the circuit's channel
        let ch_b = [0x22u8; 32]; // a DIFFERENT channel
        let relay_holder = [0xa1u8; 32];
        let requester_holder = [0xb2u8; 32];

        // Operator `op=7` runs channel A; both the relay and the requester hold grants for A.
        let (operator, relay_grant) = grant_for(7, ch_a, relay_holder);
        let (_op2, requester_grant) = grant_for(7, ch_a, requester_holder);

        // (1) HAPPY PATH: relay is an A-member, requester proves A-co-membership → admitted.
        assert_eq!(
            authorize_relay_circuit(&operator, &relay_grant, &requester_grant, &ChannelId(ch_a), now),
            Ok(()),
            "an A-member relay admits an A-co-member's circuit for channel A"
        );

        // (2) RELAY NOT A MEMBER (invariant #3 core): the relay's authentic grant is for
        // channel B, but the circuit is for A → refuse. A superpeer must not relay a channel
        // it doesn't itself belong to (it would learn membership metadata it has no claim to).
        let (op_b, relay_grant_b) = grant_for(7, ch_b, relay_holder);
        assert_eq!(op_b, operator, "same operator key across channels in this test");
        assert_eq!(
            authorize_relay_circuit(&operator, &relay_grant_b, &requester_grant, &ChannelId(ch_a), now),
            Err(RelayCircuitError::RelayNotMember),
            "a relay holding only a channel-B grant must not relay a channel-A circuit (#3)"
        );

        // (3) REQUESTER NOT A CO-MEMBER: the requester's authentic grant is for channel B, not
        // the circuit's channel A → refuse. Proving membership of *some* channel is not enough.
        let (_opb, requester_grant_b) = grant_for(7, ch_b, requester_holder);
        assert_eq!(
            authorize_relay_circuit(&operator, &relay_grant, &requester_grant_b, &ChannelId(ch_a), now),
            Err(RelayCircuitError::RequesterChannelMismatch),
            "a requester with only a channel-B grant can't open a channel-A circuit"
        );

        // (4) FORGED RELAY GRANT: the relay presents a grant signed by a DIFFERENT operator key
        // (op=8) — it doesn't verify against channel A's operator → refuse before anything else.
        let (_wrong_op, forged_relay) = grant_for(8, ch_a, relay_holder);
        assert_eq!(
            authorize_relay_circuit(&operator, &forged_relay, &requester_grant, &ChannelId(ch_a), now),
            Err(RelayCircuitError::RelayGrantInvalid(GrantError::BadSignature)),
            "a relay grant not signed by the channel operator is rejected"
        );

        // (5) FORGED REQUESTER GRANT: relay is a valid A-member, but the requester's grant is
        // signed by a foreign operator → refuse. A stranger can't use an honest relay.
        let (_wrong_op2, forged_requester) = grant_for(9, ch_a, requester_holder);
        assert_eq!(
            authorize_relay_circuit(&operator, &relay_grant, &forged_requester, &ChannelId(ch_a), now),
            Err(RelayCircuitError::RequesterGrantInvalid(GrantError::BadSignature)),
            "a requester grant not signed by the channel operator is rejected"
        );

        // (6) EXPIRED RELAY GRANT: authentic but past `expires_at` (10_000) → refuse. Fail-static
        // is bounded by grant/staple TTL (invariant #7); an expired membership can't relay.
        assert_eq!(
            authorize_relay_circuit(&operator, &relay_grant, &requester_grant, &ChannelId(ch_a), 10_000),
            Err(RelayCircuitError::RelayGrantInvalid(GrantError::Expired)),
            "an expired relay grant may not relay (TTL-bounded, invariant #7)"
        );
    }

    #[test]
    fn dcutr_upgrade_target_pins_the_trusted_relay_and_extracts_the_peer() {
        // #136 N136.3 (frozen): the relay-pinning guard for the peer-conveyed DCUtR upgrade address
        // (the #137 SSRF analog for NAT-to-NAT). Only an address that is EXACTLY the responder's own
        // trusted edge circuit + a target peer is accepted; a circuit routed through a different
        // (attacker-controlled) relay, one with no target peer, or a malformed string is refused.
        use libp2p::PeerId;
        let relay = PeerId::random();
        let target = PeerId::random();
        let trusted: Multiaddr = "/ip4/127.0.0.1/tcp/4001"
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(relay))
            .with(Protocol::P2pCircuit);

        // Valid: our trusted circuit + the target peer → returns the target to dial.
        let offered = trusted.clone().with(Protocol::P2p(target));
        assert_eq!(dcutr_upgrade_target(&offered.to_string(), &trusted), Some(target));

        // Attacker relay: a DIFFERENT relay circuit + the same target → refused (relay not pinned).
        let evil_relay = PeerId::random();
        let evil = "/ip4/10.0.0.9/tcp/4001"
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(evil_relay))
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(target));
        assert_eq!(dcutr_upgrade_target(&evil.to_string(), &trusted), None, "a foreign relay must be refused");

        // No trailing target peer (just the bare circuit) → refused.
        assert_eq!(dcutr_upgrade_target(&trusted.to_string(), &trusted), None, "a circuit with no target peer is refused");

        // Malformed → refused.
        assert_eq!(dcutr_upgrade_target("not-a-multiaddr", &trusted), None, "an unparseable address is refused");
    }

    #[tokio::test]
    async fn upgradable_dcutr_session_delivers_byte_exact_across_the_nat_to_nat_composition() {
        // #136 N136.3 (frozen, loopback analog of N136.4): two relay-only agents run the NAT-to-NAT
        // upgradable session over an in-memory base relay leg, hole-punching to a direct link THROUGH
        // an in-process Circuit-Relay v2 relay (DCUtR) — exercising the whole composition (initiator
        // reserve/accept + advertise, responder relay-pinned dial, establish over the DCUtR stream,
        // cutover) — and a payload arrives byte-exact. Loopback punch is trivial; the live cross-NAT
        // punch is N136.4. Bounded so a stall fails fast instead of wedging the gate.
        use crate::channel_run::ChannelRole;
        use ct_common::noise::generate_static_keypair;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        tokio::time::timeout(Duration::from_secs(20), async move {
            // In-process Circuit-Relay v2 relay — the DCUtR coordination leg both agents use.
            let mut relay = build_relay_swarm().unwrap();
            let relay_peer = *relay.local_peer_id();
            relay.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
            let relay_addr: Multiaddr = loop {
                match relay.next().await {
                    Some(SwarmEvent::NewListenAddr { address, .. }) => break address,
                    Some(_) => {}
                    None => panic!("relay swarm closed before a listen address"),
                }
            };
            relay.add_external_address(relay_addr.clone());
            tokio::spawn(async move {
                loop {
                    relay.next().await;
                }
            });
            let circuit: Multiaddr = relay_addr.with(Protocol::P2p(relay_peer)).with(Protocol::P2pCircuit);

            let a = generate_static_keypair(); // channel initiator
            let b = generate_static_keypair(); // channel responder
            let (a_priv, a_pub, b_priv, b_pub) = (a.private, a.public, b.private, b.public);

            // Base relay leg (in-memory): a→b and b→a.
            let (a2b_w, a2b_r) = tokio::io::duplex(1 << 16);
            let (b2a_w, b2a_r) = tokio::io::duplex(1 << 16);

            // App endpoints: test → initiator source; responder sink → test.
            let (ini_app, ini_test) = tokio::io::duplex(1 << 16);
            let (_ini_r, mut ini_feed) = tokio::io::split(ini_test);
            let (resp_app, resp_test) = tokio::io::duplex(1 << 16);
            let (mut resp_out, _resp_w) = tokio::io::split(resp_test);

            let circ_i = circuit.clone();
            let init = tokio::spawn(async move {
                run_channel_session_upgradable_dcutr(a2b_w, b2a_r, ini_app, ChannelRole::Initiate, &a_priv, &b_pub, circ_i).await
            });
            let resp = tokio::spawn(async move {
                run_channel_session_upgradable_dcutr(b2a_w, a2b_r, resp_app, ChannelRole::Accept, &b_priv, &a_pub, circuit).await
            });

            let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
            ini_feed.write_all(&payload).await.unwrap();
            ini_feed.flush().await.unwrap();
            ini_feed.shutdown().await.unwrap();

            let mut got = vec![0u8; payload.len()];
            resp_out.read_exact(&mut got).await.expect("responder receives the full payload");
            assert_eq!(got, payload, "NAT-to-NAT relay→direct(DCUtR) upgradable session delivered byte-exact (#136)");

            init.abort();
            resp.abort();
        })
        .await
        .expect("the DCUtR upgradable session delivers within 20s (a hang here is a deadlock)");
    }
}
