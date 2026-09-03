#!/bin/bash
set -e

# --- Teardown ---
ip netns del client   2>/dev/null || true
ip netns del server   2>/dev/null || true
ip netns del attacker 2>/dev/null || true
ip link del br0       2>/dev/null || true

# --- Namespaces ---
ip netns add client
ip netns add server
ip netns add attacker

# --- Bridge ---
ip link add br0 type bridge
ip link set br0 up

# --- Client ---
ip link add veth-cl type veth peer name veth-cl-br
ip link set veth-cl netns client
ip link set veth-cl-br master br0 && ip link set veth-cl-br up
ip netns exec client ip link set lo up
ip netns exec client ip link set veth-cl up
ip netns exec client ip addr add 10.0.0.1/24 dev veth-cl
# No default route needed — connected route is auto-created

# --- Server ---
ip link add veth-sv type veth peer name veth-sv-br
ip link set veth-sv netns server
ip link set veth-sv-br master br0 && ip link set veth-sv-br up
ip netns exec server ip link set lo up
ip netns exec server ip link set veth-sv up
ip netns exec server ip addr add 10.0.0.2/24 dev veth-sv

# --- Attacker ---
ip link add veth-at type veth peer name veth-at-br
ip link set veth-at netns attacker
ip link set veth-at-br master br0 && ip link set veth-at-br up
ip netns exec attacker ip link set lo up
ip netns exec attacker ip link set veth-at up
ip netns exec attacker ip addr add 10.0.0.3/24 dev veth-at

# --- rp_filter: disable source-address validation (allows IP spoofing in lab) ---
# This is specifically about ingress source-address filtering, not raw socket access
for NS in client server attacker; do
    ip netns exec $NS sysctl -qw net.ipv4.conf.all.rp_filter=0
    ip netns exec $NS sysctl -qw net.ipv4.conf.default.rp_filter=0
done

echo "Topology ready. Verify with:"
echo "  sudo ip netns exec client ping -c2 10.0.0.2"
echo "  sudo ip netns exec client ping -c2 10.0.0.3"
echo "  sudo ip netns exec client ip route"

#crlf fixed
#sed -i 's/\r$//' setup_topology.sh
# chmod +x setup_topology.sh
# sudo ./setup_topology.sh