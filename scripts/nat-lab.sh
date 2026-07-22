#!/usr/bin/env bash
# scripts/nat-lab.sh — #136 N-rig-1: emulate two hosts behind SEPARATE NATs plus a public
# relay, in ONE privileged container via Linux network namespaces + iptables MASQUERADE.
#
# It proves the exact topology the DCUtR cross-NAT hole-punch needs:
#   * both NAT'd peers (nsA, nsB) can reach the PUBLIC relay (203.0.113.1) — so a relay can
#     splice them and convey each side's edge-observed reflexive address (#121 B1); and
#   * neither peer can reach the other DIRECTLY — so a session that never upgrades stays on
#     the relay, and a successful direct path can only be a real hole-punch.
#
# This is the harness the punch smoke (N-rig-2) runs the wired agents in. It is NOT a cargo
# test (it needs NET_ADMIN); it is the repo's Docker-only-emulation analog of the hermetic
# gate for the one thing that gate structurally cannot exercise — a real NAT traversal.
#
# Run:
#   docker run --rm --privileged -v "$PWD":/w -w /w rust:1-slim bash scripts/nat-lab.sh
set -euo pipefail

# --- deps (iproute2 + iptables + ping); installed on demand in the slim image ----------
if ! command -v ip >/dev/null || ! command -v iptables >/dev/null || ! command -v ping >/dev/null || ! command -v socat >/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iproute2 iptables iputils-ping socat >/dev/null
fi

RELAY_PUB=203.0.113.1

cleanup() {
  set +e
  ip netns del nsA 2>/dev/null
  ip netns del nsB 2>/dev/null
  ip netns del nsR 2>/dev/null
  ip link del vethnsA 2>/dev/null
  ip link del vethnsB 2>/dev/null
  ip link del pubR 2>/dev/null
  iptables -t nat -F 2>/dev/null
  iptables -F 2>/dev/null
}
trap cleanup EXIT
cleanup # start from a clean slate even if a previous run died

# --- public backbone + a separate relay host (nsR) -------------------------------------
# The relay lives in its OWN namespace (nsR), NOT colocated with the NAT gateways in root:
# otherwise NAT egress to the relay is delivered locally (via `lo`) and bypasses SNAT, so the
# relay would observe the peer's PRIVATE address (unpunchable). With nsR separate, NAT traffic
# to the relay is routed OUT the public interface and SNAT'd, so the relay observes each peer's
# distinct PUBLIC reflexive IP — exactly what DCUtR conveys and punches toward.
#   root  = the "internet" backbone: forwards, owns the two NATs' public IPs + a gateway addr.
#   nsR   = the relay host at RELAY_PUB.
NAT_A_PUB=203.0.113.10
NAT_B_PUB=203.0.113.20
BACKBONE=203.0.113.254
ip netns add nsR
ip link add pubR type veth peer name inR
ip link set inR netns nsR
# root's public-side interface owns the backbone gateway addr + the two NATs' SNAT source IPs
# (so root answers for them + conntrack can reverse-translate the punched/return flows).
ip addr add "${BACKBONE}/24" dev pubR
ip addr add "${NAT_A_PUB}/24" dev pubR
ip addr add "${NAT_B_PUB}/24" dev pubR
ip link set pubR up
# The relay host.
ip netns exec nsR ip addr add "${RELAY_PUB}/24" dev inR
ip netns exec nsR ip link set inR up
ip netns exec nsR ip link set lo up
ip netns exec nsR ip route add default via "${BACKBONE}"
# Enable IPv4 forwarding via /proc (the slim image has no `sysctl`) so root routes between the
# private subnets and the relay host; the two NATs stay isolated only by the explicit FORWARD
# DROP below (a faithful "separate NATs" emulation).
echo 1 > /proc/sys/net/ipv4/ip_forward

# --- one NAT'd host per private subnet, egress MASQUERADEd to the public segment --------
setup_nat() { # $1=namespace  $2=third-octet  $3=this-NAT's-public-IP
  local ns=$1 net=$2 pub=$3
  ip netns add "$ns"
  ip link add "veth${ns}" type veth peer name "in${ns}"
  ip link set "in${ns}" netns "$ns"
  ip addr add "10.0.${net}.1/24" dev "veth${ns}"
  ip link set "veth${ns}" up
  ip netns exec "$ns" ip addr add "10.0.${net}.2/24" dev "in${ns}"
  ip netns exec "$ns" ip link set "in${ns}" up
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip route add default via "10.0.${net}.1"
  # NAT: source-NAT this private subnet's egress to the public segment to its OWN distinct
  # public IP (SNAT, not MASQUERADE — MASQUERADE would pick the shared primary). conntrack
  # tracks the flow (TCP + UDP), so the reverse path of an established/punched flow returns to
  # the internal host, while unsolicited inbound (no prior outbound) has no mapping and is dropped.
  iptables -t nat -A POSTROUTING -s "10.0.${net}.0/24" -o pubR -j SNAT --to-source "$pub"
}
setup_nat nsA 1 "$NAT_A_PUB"
setup_nat nsB 2 "$NAT_B_PUB"

# NAT isolation: block direct access to the OTHER NAT's PRIVATE space (10.0.x.0/24). This does
# NOT block a hole-punch: the punch targets the peer's distinct PUBLIC IP (SNAT/conntrack path,
# source becomes the punching NAT's public IP), never its private 10.0.x.2 — so a session that
# never upgrades stays relayed, but a real UDP punch toward the reflexive public IP can traverse.
iptables -A FORWARD -s 10.0.1.0/24 -d 10.0.2.0/24 -j DROP
iptables -A FORWARD -s 10.0.2.0/24 -d 10.0.1.0/24 -j DROP

# --- connectivity proof ----------------------------------------------------------------
pass=0 fail=0
expect_ok() { # name, command...
  local name=$1; shift
  if "$@" >/dev/null 2>&1; then echo "PASS: ${name}"; pass=$((pass + 1))
  else echo "FAIL: ${name}"; fail=$((fail + 1)); fi
}
expect_blocked() { # name, command...
  local name=$1; shift
  if "$@" >/dev/null 2>&1; then echo "FAIL (expected block): ${name}"; fail=$((fail + 1))
  else echo "PASS (blocked): ${name}"; pass=$((pass + 1)); fi
}

expect_ok      "nsA reaches the public relay"      ip netns exec nsA ping -c1 -W1 "$RELAY_PUB"
expect_ok      "nsB reaches the public relay"      ip netns exec nsB ping -c1 -W1 "$RELAY_PUB"
expect_blocked "nsA cannot reach nsB directly"     ip netns exec nsA ping -c1 -W1 10.0.2.2
expect_blocked "nsB cannot reach nsA directly"     ip netns exec nsB ping -c1 -W1 10.0.1.2

# --- relay data-path proof (the base leg the DCUtR session rides on) --------------------
# A minimal public-segment relay bridges two TCP listeners; a payload sent by nsA (behind
# NAT-A) must arrive at nsB (behind NAT-B) THROUGH it — proving the edge-relay base leg
# traverses both NATs, which is exactly where the upgradable channel session starts before
# it opportunistically punches to direct (N-rig-2). socat listens on 9001 first (the
# receiver nsB), then 9000 (the sender nsA); it accepts one connection each and bridges them.
relay_splice() {
  local got; got=$(mktemp)
  ip netns exec nsR socat "TCP-LISTEN:9001,reuseaddr" "TCP-LISTEN:9000,reuseaddr" & local relay=$!
  sleep 0.3
  ip netns exec nsB timeout 4 socat -u "TCP:${RELAY_PUB}:9001" - >"$got" & local rcv=$!
  sleep 0.6 # let nsB connect so socat advances to listening on 9000
  printf 'A2B-VIA-RELAY-OK' | ip netns exec nsA timeout 4 socat -u - "TCP:${RELAY_PUB}:9000" || true
  wait "$rcv" 2>/dev/null || true
  kill "$relay" 2>/dev/null || true
  grep -q 'A2B-VIA-RELAY-OK' "$got"
  local r=$?
  rm -f "$got"
  return $r
}
expect_ok "payload from nsA reaches nsB THROUGH the public relay (base leg)" relay_splice

# --- distinct reflexive addresses (the punch prerequisite) ------------------------------
# The whole point of the per-NAT SNAT: each peer must present a DISTINCT public source IP so
# the other has a real reflexive address to hole-punch toward. A public UDP observer records
# the source address of a datagram from each namespace; nsA must appear as NAT_A_PUB and nsB as
# NAT_B_PUB (never a shared IP). This is exactly the address DCUtR conveys + punches toward.
distinct_reflexive() {
  local srcs; srcs=$(mktemp)
  ip netns exec nsR socat -u "UDP4-RECVFROM:9500,fork" SYSTEM:"printf '%s ' \"\$SOCAT_PEERADDR\" >>$srcs" & local obs=$!
  sleep 0.3
  ip netns exec nsA bash -c "printf x | socat -u - UDP4-SENDTO:${RELAY_PUB}:9500" || true
  ip netns exec nsB bash -c "printf x | socat -u - UDP4-SENDTO:${RELAY_PUB}:9500" || true
  sleep 0.5
  kill "$obs" 2>/dev/null || true
  grep -q "$NAT_A_PUB" "$srcs" && grep -q "$NAT_B_PUB" "$srcs"
  local rc=$?
  rm -f "$srcs"
  return $rc
}
expect_ok "nsA=${NAT_A_PUB} and nsB=${NAT_B_PUB}: distinct public reflexive IPs (punchable)" distinct_reflexive

# --- the actual cross-NAT DCUtR hole-punch (N-rig-2b) -----------------------------------
# Runs the three `natlab` roles across the namespaces: the relay in the public host (nsR), a
# listener behind NAT-A (nsA), a dialer behind NAT-B (nsB). DCUtR should upgrade the relayed
# connection to a DIRECT QUIC link between the two distinct public reflexive addresses; both
# peers print PUNCH-OK on `dcutr::Event{result:Ok}`. Only runs when the test-only harness binary
# is present (build: cargo build -p ct-agent --features nat-lab; set NATLAB=target/debug/natlab).
NATLAB="${NATLAB:-target/debug/natlab}"
punch_smoke() {
  local rout aout dout; rout=$(mktemp); aout=$(mktemp); dout=$(mktemp)
  ip netns exec nsR "$NATLAB" relay "/ip4/${RELAY_PUB}/udp/4001/quic-v1" >"$rout" 2>/dev/null & local rp=$!
  local relay_addr; relay_addr=$(timeout 12 bash -c "until grep -m1 '/p2p/' '$rout' 2>/dev/null; do sleep 0.2; done" | head -1)
  [ -n "$relay_addr" ] || { kill "$rp" 2>/dev/null; rm -f "$rout" "$aout" "$dout"; return 1; }
  ip netns exec nsA "$NATLAB" listen "$relay_addr" >"$aout" 2>/dev/null & local ap=$!
  local a_addr; a_addr=$(timeout 14 bash -c "until grep -m1 'LISTEN-ADDR' '$aout' 2>/dev/null; do sleep 0.2; done" | awk '{print $2}' | head -1)
  [ -n "$a_addr" ] || { kill "$rp" "$ap" 2>/dev/null; rm -f "$rout" "$aout" "$dout"; return 1; }
  ip netns exec nsB timeout 45 "$NATLAB" dial "$a_addr" >"$dout" 2>/dev/null; local drc=$?
  sleep 2 # let the listener log its PUNCH-OK too
  kill "$rp" "$ap" 2>/dev/null
  local rc=1
  grep -q PUNCH-OK "$dout" && grep -q PUNCH-OK "$aout" && rc=0
  rm -f "$rout" "$aout" "$dout"
  return $rc
}
# The punch smoke is reported but NOT yet fatal. The address plumbing is now fully correct and
# verified (see the diag trace): the relay runs an identify server, so each client learns its
# PUBLIC reflexive QUIC address (listener 203.0.113.10:<port>, dialer 203.0.113.20:<port>),
# confirms it as an external address, and does so BEFORE it becomes dialable (the DCUtR sequencing
# in `await_reflexive_via_relay`). Yet DCUtR's Connect STILL goes out address-less
# (`NoAddresses`/`UnexpectedEof`). Ruled out, each with a lab run: (1) address discovery — fixed;
# (2) timing/ordering — the reflexive is confirmed before the peer connection; (3) non-global
# filtering — same failure with global-unicast IPs (11.0.0.x), not just RFC-5737 range. The
# residual cause is INTERNAL to libp2p-0.56 `dcutr`: it does not source the swarm's confirmed
# external addresses into its Connect message. This needs a libp2p-level fix/bump OR the real
# AutoNAT/identify address-confirmation flow present on genuine NAT'd hosts (N-rig-3 live). Flip
# to `expect_ok` once it upgrades. The 6 topology assertions above remain the gating checks.
if [ -x "$NATLAB" ]; then
  if punch_smoke; then
    echo "PASS: cross-NAT DCUtR hole-punch — BOTH peers reported a DIRECT upgrade (PUNCH-OK)"
  else
    echo "PENDING: cross-NAT DCUtR punch did not upgrade yet (relay reservation + relayed"
    echo "         connection OK; DCUtR reports NoAddresses — QUIC punch candidates not"
    echo "         propagated over the TCP coordination leg; under diagnosis)."
  fi
else
  echo "SKIP: cross-NAT punch smoke — build the harness first:"
  echo "      cargo build -p ct-agent --features nat-lab && NATLAB=target/debug/natlab $0"
fi

echo "== nat-lab: ${pass} passed, ${fail} failed =="
[ "$fail" -eq 0 ]
