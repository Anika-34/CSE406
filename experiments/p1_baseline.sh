#!/bin/bash
# Phase P1 — Baseline measurement (no attack).
# Runs a 30s iperf3 TCP transfer client(10.0.0.1) -> server(10.0.0.2),
# capturing the flow with tcpdump and recording throughput/RTT/retransmits.
# Run this AFTER setup_topology.sh, from the root namespace (needs sudo).
#
# Usage: sudo ./experiments/p1_baseline.sh [duration_seconds]
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./experiments/p1_baseline.sh)" >&2
    exit 1
fi

DURATION="${1:-30}"
OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/results"
mkdir -p "$OUT_DIR"
PCAP="$OUT_DIR/p1_baseline.pcap"
JSON="$OUT_DIR/p1_baseline.json"

for ns in client server attacker; do
    ip netns list | grep -qw "$ns" || { echo "Namespace '$ns' not found — run setup_topology.sh first." >&2; exit 1; }
done

echo "== Starting iperf3 server in 'server' namespace =="
ip netns exec server pkill -f "iperf3 -s" 2>/dev/null || true
ip netns exec server iperf3 -s -D --logfile /tmp/iperf3_server.log
sleep 1

echo "== Starting tcpdump capture on server's veth-sv =="
# Header-only capture (-s 96): plenty for TCP seq/ack/MSS analysis, and keeps
# the pcap small — iperf3 payload bytes aren't needed and balloon file size.
ip netns exec server tcpdump -i veth-sv -s 96 -w "$PCAP" tcp and port 5201 >/tmp/tcpdump_p1.log 2>&1 &
TCPDUMP_PID=$!
sleep 1

echo "== Running iperf3 client for ${DURATION}s (client -> server) =="
ip netns exec client iperf3 -c 10.0.0.2 -t "$DURATION" -i 1 --json > "$JSON"

sleep 1
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
ip netns exec server pkill -f "iperf3 -s" 2>/dev/null || true

echo
echo "== Summary =="
python3 - "$JSON" <<'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

end = data["end"]
sent = end["sum_sent"]
recv = end["sum_received"]

print(f"Avg throughput (sender):   {sent['bits_per_second'] / 1e6:.2f} Mbps")
print(f"Avg throughput (receiver): {recv['bits_per_second'] / 1e6:.2f} Mbps")
print(f"Retransmits:               {sent.get('retransmits', 'n/a')}")

streams = end.get("streams", [])
if streams and "sender" in streams[0] and "rtt" in streams[0]["sender"]:
    rtt_us = streams[0]["sender"]["rtt"]
    print(f"RTT (from TCP_INFO):       {rtt_us / 1000:.3f} ms")
else:
    print("RTT (from TCP_INFO):       not reported by this iperf3 build")
PYEOF

echo
echo "Raw JSON:  $JSON"
echo "Capture:   $PCAP"
echo
echo "Independent RTT check:"
ip netns exec client ping -c5 -q 10.0.0.2
