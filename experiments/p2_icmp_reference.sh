#!/bin/bash
# Phase P2 — Real ICMP reference.
# Sends a UDP packet from the client to a closed port on the server so the
# server's own kernel generates a genuine ICMP Type 3 Code 3 (Port
# Unreachable) message. Captured here as ground-truth: P3/P4's Scapy-crafted
# packets should match this real on-the-wire structure (RFC 792 — original
# IP header + first 8 bytes of the original datagram).
#
# Usage: sudo ./experiments/p2_icmp_reference.sh [closed_port]
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./experiments/p2_icmp_reference.sh)" >&2
    exit 1
fi

CLOSED_PORT="${1:-55555}"
OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/results"
mkdir -p "$OUT_DIR"
PCAP="$OUT_DIR/p2_icmp_reference.pcap"

for ns in client server; do
    ip netns list | grep -qw "$ns" || { echo "Namespace '$ns' not found — run setup_topology.sh first." >&2; exit 1; }
done

echo "== Capturing ICMP on client's veth-cl (where the reply will land) =="
ip netns exec client tcpdump -i veth-cl -w "$PCAP" icmp >/tmp/tcpdump_p2.log 2>&1 &
TCPDUMP_PID=$!
sleep 1

echo "== Sending UDP packet to closed port $CLOSED_PORT on server (10.0.0.2) =="
ip netns exec client python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'probe-closed-port', ('10.0.0.2', $CLOSED_PORT))
s.close()
"

sleep 1
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo
echo "== tcpdump summary =="
tcpdump -r "$PCAP" -nn -vv 2>/dev/null

echo
echo "== Field breakdown (scapy ground truth) =="
python3 - "$PCAP" <<'PYEOF'
import sys
from scapy.all import rdpcap, ICMP, IP, UDP

pkts = rdpcap(sys.argv[1])
icmp_pkts = [p for p in pkts if p.haslayer(ICMP)]

if not icmp_pkts:
    print("No ICMP packet captured — check that nothing is really listening on that port.")
    sys.exit(1)

pkt = icmp_pkts[0]
icmp = pkt[ICMP]
print(f"Outer IP:  src={pkt[IP].src} dst={pkt[IP].dst} proto={pkt[IP].proto}")
print(f"ICMP:      type={icmp.type} code={icmp.code} chksum={hex(icmp.chksum)}")

# Embedded original datagram: RFC 792 requires the original IP header
# plus the first 8 bytes of the original IP payload (the UDP/TCP header).
payload = bytes(icmp.payload)
print(f"Embedded payload ({len(payload)} bytes): {payload.hex()}")

inner = IP(payload)
print(f"Embedded IP:  src={inner.src} dst={inner.dst} proto={inner.proto}")
if inner.haslayer(UDP):
    print(f"Embedded UDP: sport={inner[UDP].sport} dport={inner[UDP].dport}")

print()
pkt.show2()
PYEOF

echo
echo "Capture saved to: $PCAP"
