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
  ip link del vethnsA 2>/dev/null
  ip link del vethnsB 2>/dev/null
  ip link del pub0 2>/dev/null
  iptables -t nat -F 2>/dev/null
  iptables -F 2>/dev/null
}
trap cleanup EXIT
cleanup # start from a clean slate even if a previous run died

# --- public segment: the relay lives here, in the root namespace -----------------------
ip link add pub0 type dummy
ip addr add "${RELAY_PUB}/24" dev pub0
ip link set pub0 up
# Enable IPv4 forwarding via /proc (the slim image has no `sysctl`). Forwarding is ON so the
# ONLY thing isolating the two NATs is the explicit FORWARD DROP below — a faithful "separate
# NATs" emulation, and the prerequisite for the later punch smoke to traverse reflexively.
echo 1 > /proc/sys/net/ipv4/ip_forward

# --- one NAT'd host per private subnet, egress MASQUERADEd to the public segment --------
setup_nat() { # $1=namespace  $2=third-octet
  local ns=$1 net=$2
  ip netns add "$ns"
  ip link add "veth${ns}" type veth peer name "in${ns}"
  ip link set "in${ns}" netns "$ns"
  ip addr add "10.0.${net}.1/24" dev "veth${ns}"
  ip link set "veth${ns}" up
  ip netns exec "$ns" ip addr add "10.0.${net}.2/24" dev "in${ns}"
  ip netns exec "$ns" ip link set "in${ns}" up
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip route add default via "10.0.${net}.1"
  # NAT: this private subnet's egress to the public segment is source-masqueraded, so the
  # relay (and any reflexive observer) sees the gateway's public address, never 10.0.x.2.
  iptables -t nat -A POSTROUTING -s "10.0.${net}.0/24" -o pub0 -j MASQUERADE
}
setup_nat nsA 1
setup_nat nsB 2

# NAT isolation: the two private subnets cannot route to each other — only outbound to the
# public relay. Unsolicited inbound between them is dropped, exactly as separate NATs behave.
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
  socat "TCP-LISTEN:9001,reuseaddr" "TCP-LISTEN:9000,reuseaddr" & local relay=$!
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

echo "== nat-lab: ${pass} passed, ${fail} failed =="
[ "$fail" -eq 0 ]
