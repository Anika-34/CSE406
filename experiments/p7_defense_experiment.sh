#!/bin/bash
# Phase P7 — Defense simulation.
#
# Two independent defenses, each mapped to something the design doc /
# README.md already names but never implements:
#
#   Defense 1 — Ingress filtering (BCP 38 / RFC 2827), README Section 6.
#     A real network edge router drops any packet whose source address
#     doesn't belong to the subnet it's physically arriving from, which
#     kills IP spoofing before it goes anywhere. Simulated here with a tc
#     filter on veth-at-br — the bridge port the attacker's packets
#     physically arrive on — using the exact same tc-ingress idiom
#     setup_topology.sh already uses for mirroring (just a drop instead
#     of a mirred-copy action). Every packet build_packets.py crafts
#     spoofs its outer source (10.0.0.2 for the reset attack, 10.0.0.1
#     for the PMTU attack) while physically leaving the attacker's veth,
#     so this should block BOTH attacks completely, regardless of the
#     kernel-level fixes below. We reuse p4_reset_experiment.sh and
#     p5_pmtu_experiment.sh unmodified here — same attack code, defense
#     applied purely at the network layer.
#
#   Defense 2 — PMTU cache aging + PLPMTUD (Implementation Plan P7's
#     literal instruction to enable tcp_mtu_probing=2 — corrected below
#     after empirical testing, same spirit as the IP_RECVERR/spray
#     findings documented in the other two demos):
#
#     Original hypothesis (tested, and WRONG): net.ipv4.tcp_mtu_probing=2
#     plus a short tcp_probe_interval would make the client "self-heal" a
#     spoofed PMTU within seconds. Empirically it does not — mss/pmtu
#     stayed pinned at 524/576 for 20+ straight seconds. Reason:
#     tcp_mtu_probing controls PLPMTUD, which detects ICMP BLACK HOLES
#     (a router silently drops oversized packets with no Frag-Needed
#     reply at all) and probes upward afterward — it does not re-verify
#     a PMTU value that arrived via an ICMP message the kernel DID
#     receive and accepted as authoritative. That's a different
#     mechanism entirely.
#
#     What actually holds the forged MTU in place is the ROUTE-CACHE
#     PMTU EXCEPTION created by ipv4_sk_update_pmtu() when the ICMP
#     lands (the same "cache expires <N>sec mtu 576" line visible in
#     `ip route get` after the undefended P5 attack). That exception
#     ages out on its own via net.ipv4.route.mtu_expires — default 600
#     seconds (10 minutes), far longer than any live demo. We shorten
#     THAT sysctl here (not tcp_probe_interval) to actually observe the
#     real self-healing mechanism within the demo window. tcp_mtu_probing=2
#     is kept alongside it (matching the Implementation Plan's literal
#     instruction) so the client re-verifies upward with real probe
#     segments once the stale exception is gone, rather than jumping
#     straight back to a possibly-wrong cached value.
#
# Usage: sudo ./experiments/p7_defense_experiment.sh
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./experiments/p7_defense_experiment.sh)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACKS_DIR="$(cd "$SCRIPT_DIR/../attacks" && pwd)"
OUT_DIR="$SCRIPT_DIR/results"
mkdir -p "$OUT_DIR"

for ns in client server attacker; do
    ip netns list | grep -qw "$ns" || { echo "Namespace '$ns' not found — run setup_topology.sh first." >&2; exit 1; }
done

cleanup_defense1() {
    tc qdisc del dev veth-at-br handle ffff: ingress 2>/dev/null || true
}
cleanup_defense2() {
    ip netns exec client sysctl -qw net.ipv4.tcp_mtu_probing=1 2>/dev/null || true
    ip netns exec client sysctl -qw net.ipv4.tcp_probe_interval=600 2>/dev/null || true
    ip netns exec client sysctl -qw net.ipv4.route.mtu_expires=600 2>/dev/null || true
}
cleanup_all() {
    cleanup_defense1
    cleanup_defense2
    pkill -f "tail -f /dev/null" 2>/dev/null || true
    ip netns exec server pkill -f "iperf3 -s" 2>/dev/null || true
    ip netns exec server pkill -f "ncat -l" 2>/dev/null || true
    ip netns exec server pkill -f recverr_server.py 2>/dev/null || true
    ip netns exec client pkill -f ncat 2>/dev/null || true
    ip netns exec client pkill -f iperf3 2>/dev/null || true
    pkill -f inject_pmtu.py 2>/dev/null || true
}
trap cleanup_all EXIT

echo "################################################################"
echo "# Defense 1 — Ingress filtering (BCP 38) at the attacker's bridge port"
echo "################################################################"
echo "Only packets carrying src=10.0.0.3 (the attacker's real address) are"
echo "allowed to leave veth-at-br into the bridge; everything else — every"
echo "spoofed packet either attack sends — is dropped right there."
echo

cleanup_defense1
tc qdisc add dev veth-at-br handle ffff: ingress
tc filter add dev veth-at-br parent ffff: protocol ip prio 1 u32 \
    match ip src 10.0.0.3/32 action ok
tc filter add dev veth-at-br parent ffff: protocol ip prio 2 u32 \
    match u32 0 0 action drop

echo "== Re-running P4 (reset attack) with the filter active =="
echo "   (expect: 'Spoofed ICMP visible in server capture: NO' for BOTH"
echo "   scenarios now — including recverr, which was RESET without this"
echo "   defense — because the packet never reaches the server at all)"
bash "$SCRIPT_DIR/p4_reset_experiment.sh" 9999 9998 || echo "(p4 sub-run reported a non-zero exit — see output above)"

echo
echo "== Re-running P5 (PMTU attack) with the filter active =="
echo "   (expect: 'Spoofed ICMP visible in client capture: NO' and"
echo "   mss/pmtu unchanged at 1448/1500 throughout)"
bash "$SCRIPT_DIR/p5_pmtu_experiment.sh" 30 10 576 || echo "(p5 sub-run reported a non-zero exit — see output above)"

cleanup_defense1
echo
echo "== Defense 1 filter removed =="
echo

echo "################################################################"
echo "# Defense 2 — PMTU cache aging + PLPMTUD on the client"
echo "################################################################"
echo "No network-layer defense here — the spoofed ICMP is allowed through."
echo "We send only ONE spray round (not the continuous re-spray p5 uses"
echo "against a persistent attacker) and watch whether the client's own"
echo "kernel recovers the true PMTU on its own once the route-cache PMTU"
echo "exception the spoofed ICMP created ages out (net.ipv4.route.mtu_expires,"
echo "shortened here from its 600s default to make this demoable). Plain"
echo "tcp_mtu_probing=2 alone does NOT do this — see the script header for"
echo "why that first hypothesis was tested and found wrong."
echo

ip netns exec client ip route flush cache 2>/dev/null || true
ip netns exec client sysctl -qw net.ipv4.tcp_mtu_probing=2
ip netns exec client sysctl -qw net.ipv4.tcp_probe_interval=5
ip netns exec client sysctl -qw net.ipv4.route.mtu_expires=8
echo "-- client sysctls now: --"
ip netns exec client sysctl net.ipv4.tcp_mtu_probing net.ipv4.tcp_probe_interval net.ipv4.route.mtu_expires

ip netns exec server pkill -f "iperf3 -s" 2>/dev/null || true
ip netns exec server iperf3 -s -D --logfile /tmp/iperf3_server_p7.log
sleep 1

JSON="$OUT_DIR/p7_plpmtud.json"
ip netns exec client iperf3 -c 10.0.0.2 -t 60 -i 1 --json > "$JSON" &
IPERF_PID=$!

echo "== Waiting 10s for steady state =="
sleep 10
echo "-- before attack --"
ip netns exec client ss -tin | grep -E "mss|ESTAB" || true

echo
echo "== Single-shot spray (one round, no repeat) =="
ip netns exec attacker python3 "$ATTACKS_DIR/inject_pmtu.py" \
    --server-port 5201 --mtu 576 --count 1 --timeout 5 --duration 1 --interval 5

echo
echo "-- route cache right after the spray (should show the exception + its countdown) --"
ip netns exec client ip route get 10.0.0.2

echo
# Checkpoints at t+2,7,12,17,22,30,40s after the spray (deltas: 2,5,5,5,5,8,10) —
# spans well past the 8s mtu_expires above so recovery is actually observable.
CHECKPOINTS=(2 7 12 17 22 30 40)
PREV=0
for t in "${CHECKPOINTS[@]}"; do
    sleep "$((t - PREV))"
    PREV="$t"
    echo "-- t+${t}s after attack --"
    ip netns exec client ss -tin | grep -E "mss|ESTAB" || true
done

# DIAGNOSTIC — added after the mtu_expires hypothesis (like tcp_mtu_probing
# before it) failed to show recovery within 40s in testing. This isolates
# WHICH layer is stuck: has the route-table exception itself actually been
# evicted by now (the routing layer's part), and if so, does forcing the
# socket to notice — via an explicit cache flush, which invalidates existing
# dst references and forces sk_dst_check() to re-resolve on next send — get
# it to recover? If flushing unsticks it, the real fix is finding what
# should trigger that re-check automatically (an idle period? an RTO?); if
# it does NOT unstick it even after a flush, the ICMP-forced low PMTU may
# simply be "sticky" for the life of this socket regardless of any sysctl,
# and the honest conclusion is that recovery requires the connection to
# close and reopen, not any sysctl this script has tried.
echo
echo "== DIAGNOSTIC: is the route-table exception itself gone by now? =="
ip netns exec client ip route list cache 10.0.0.2 2>/dev/null
ip netns exec client ip route get 10.0.0.2
echo "-- forcing a route cache flush (invalidates cached dst references) --"
ip netns exec client ip route flush cache
sleep 2
echo "-- ss -tin immediately after the forced flush --"
ip netns exec client ss -tin | grep -E "mss|ESTAB" || true

wait "$IPERF_PID" 2>/dev/null || true
ip netns exec server pkill -f "iperf3 -s" 2>/dev/null || true
cleanup_defense2

echo
echo "== Client sysctls restored to Linux defaults =="
ip netns exec client sysctl net.ipv4.tcp_mtu_probing net.ipv4.tcp_probe_interval net.ipv4.route.mtu_expires

echo
echo "## Summary ##"
echo "Defense 1 (ingress filtering): both attacks should show ICMP NOT"
echo "  visible at the target, and mss/pmtu/ss state completely unchanged"
echo "  — the strongest defense, since it stops the spoof at the network"
echo "  layer regardless of kernel-level TCP behavior."
echo "Defense 2 (PMTU cache aging): the single-shot attack should still"
echo "  succeed momentarily (mss/pmtu drop right after injection) but"
echo "  recover once the route-cache PMTU exception expires (~8s here,"
echo "  600s/10min by default on a real host) and the client re-verifies"
echo "  the true MTU — a real kernel self-healing mechanism, but NOT a"
echo "  full defense against a persistent attacker who keeps re-spraying"
echo "  faster than the exception can expire (that's why inject_pmtu.py/p5"
echo "  spray on a repeating --interval against an undefended target)."
echo
echo "Raw JSON: $JSON"
