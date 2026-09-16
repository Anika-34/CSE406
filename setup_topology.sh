#!/bin/bash
# Phase P0 — Topology setup for the ICMP blind reset / PMTU-reduction lab.
# Creates three Linux network namespaces (client, server, attacker) joined by
# a software bridge (br0), and mirrors bridge traffic to the attacker's port
# so it can observe the live client<->server TCP state (P3) without being
# an active man-in-the-middle.
#
# Usage: sudo ./setup_topology.sh
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./setup_topology.sh)" >&2
    exit 1
fi

# veth pairs have no physical link, so an unshaped client<->server path runs
# at tens of Gbps (memory-copy speed) inside the VM. That's unrealistic for a
# TCP experiment and generates unmanageably large pcaps, so cap it to a LAN-
# like rate. Override with: LINK_RATE=10mbit sudo ./setup_topology.sh
LINK_RATE="${LINK_RATE:-100mbit}"

# --- Teardown (idempotent re-run) ---
ip netns del client   2>/dev/null || true
ip netns del server   2>/dev/null || true
ip netns del attacker 2>/dev/null || true
ip link del br0       2>/dev/null || true

# --- Bridge ---
ip link add br0 type bridge
ip link set br0 up

create_node() {
    local ns=$1 veth=$2 veth_br=$3 ip_addr=$4

    ip netns add "$ns"
    ip link add "$veth" type veth peer name "$veth_br"
    ip link set "$veth" netns "$ns"
    ip link set "$veth_br" master br0
    ip link set "$veth_br" up

    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" ip link set "$veth" up
    ip netns exec "$ns" ip addr add "$ip_addr/24" dev "$veth"
}

# --- Client / Server / Attacker ---
create_node client   veth-cl veth-cl-br 10.0.0.1
create_node server   veth-sv veth-sv-br 10.0.0.2
create_node attacker veth-at veth-at-br 10.0.0.3

# --- Rate-limit the client/server link to something LAN-realistic ---
ip netns exec client tc qdisc add dev veth-cl root tbf rate "$LINK_RATE" burst 32kbit latency 400ms
ip netns exec server tc qdisc add dev veth-sv root tbf rate "$LINK_RATE" burst 32kbit latency 400ms

# --- rp_filter: disable source-address validation (allows IP spoofing in lab) ---
for NS in client server attacker; do
    ip netns exec "$NS" sysctl -qw net.ipv4.conf.all.rp_filter=0
    ip netns exec "$NS" sysctl -qw net.ipv4.conf.default.rp_filter=0
done

# --- tc mirred traffic mirroring (P0) ---
# The bridge normally forwards unicast client<->server frames only to those
# two ports. Mirror ingress traffic on the client- and server-facing bridge
# ports to the attacker-facing port, so a tcpdump inside the attacker
# namespace on veth-at can see the live TCP stream (needed for P3: reading
# the client's ephemeral port and current ACK/SEQ numbers).
mirror_to_attacker() {
    local src_br_if=$1
    tc qdisc add dev "$src_br_if" handle ffff: ingress
    tc filter add dev "$src_br_if" parent ffff: protocol ip u32 \
        match u32 0 0 \
        action mirred egress mirror dev veth-at-br
}

mirror_to_attacker veth-cl-br
mirror_to_attacker veth-sv-br

echo "Topology ready. Verify with:"
echo "  sudo ip netns exec client ping -c2 10.0.0.2"
echo "  sudo ip netns exec client ping -c2 10.0.0.3"
echo "  sudo ip netns exec client ip route"
echo "  sudo ip netns exec attacker tcpdump -i veth-at -n"
