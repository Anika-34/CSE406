#!/bin/bash
# Phase P4 — Reset experiment.
#
# Runs the ICMP Type 3/Code 3 blind-reset attack against TWO targets and
# reports both outcomes, because a single "does it work?" run against a
# default Linux install without a defense to compare against confused the
# picture. Verified against Ubuntu 22.04 / kernel 5.15 (see build_packets.py
# and VM_COMMANDS.md for how this was traced down):
#
#   Scenario A (realistic) — an idle connection held with plain `ncat`.
#     Linux's tcp_v4_err() only treats this ICMP as an immediately-fatal
#     RFC 1122 hard error for an ESTABLISHED socket if the application set
#     IP_RECVERR. `ncat` doesn't, so the socket is expected to SURVIVE
#     (the error is downgraded to a non-fatal sk_err_soft). This is a real
#     defense worth adding to Section 6 of the design doc, distinct from
#     the sequence-number validation it already lists.
#
#   Scenario B (positive control) — the same attack against
#     recverr_server.py, which does set IP_RECVERR (representing "a
#     vulnerable stack/app" per the design doc's own qualifier). This is
#     expected to SUCCEED, proving the crafted packet, sequence number,
#     and embedded-header direction are all correct.
#
# Usage: sudo ./experiments/p4_reset_experiment.sh [ncat_port] [recverr_port]
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./experiments/p4_reset_experiment.sh)" >&2
    exit 1
fi

NCAT_PORT="${1:-9999}"
RECVERR_PORT="${2:-9998}"
CLIENT_IP="10.0.0.1"
SERVER_IP="10.0.0.2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACKS_DIR="$(cd "$SCRIPT_DIR/../attacks" && pwd)"
OUT_DIR="$SCRIPT_DIR/results"
mkdir -p "$OUT_DIR"

for ns in client server attacker; do
    ip netns list | grep -qw "$ns" || { echo "Namespace '$ns' not found — run setup_topology.sh first." >&2; exit 1; }
done

cleanup() {
    kill "$SERVER_PID" "$CLIENT_PID" "$TCPDUMP_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    # kill/tail's pipeline children aren't reached by killing $SERVER_PID/$CLIENT_PID
    # alone (they're separate processes joined by a pipe), so sweep by name too.
    ip netns exec server pkill -f "tail -f /dev/null" 2>/dev/null || true
    ip netns exec server pkill -f "ncat -l" 2>/dev/null || true
    ip netns exec server pkill -f recverr_server.py 2>/dev/null || true
    ip netns exec client pkill -f "tail -f /dev/null" 2>/dev/null || true
    ip netns exec client pkill -f ncat 2>/dev/null || true
}

run_scenario() {
    local label="$1" port="$2" server_cmd="$3" client_cmd="$4" inject_log="$5"
    trap cleanup EXIT

    echo "== [$label] Starting server on port $port =="
    ip netns exec server bash -c "$server_cmd" > "/tmp/${label}_server.log" 2>&1 &
    SERVER_PID=$!
    sleep 1

    local pcap="$OUT_DIR/p4_${label}.pcap"
    ip netns exec server tcpdump -i veth-sv -s 128 -w "$pcap" "icmp or (tcp and port $port)" \
        > "/tmp/${label}_tcpdump.log" 2>&1 &
    TCPDUMP_PID=$!
    sleep 1

    echo "== [$label] Attacker sniffing the server's own segments in the background =="
    ip netns exec attacker python3 "$ATTACKS_DIR/inject_reset.py" \
        --server-port "$port" --count 1 --timeout 10 > "$inject_log" 2>&1 &
    INJECT_PID=$!
    sleep 1

    echo "== [$label] Establishing client<->server connection (its SYN-ACK is what gets sniffed) =="
    ip netns exec client bash -c "$client_cmd" > "/tmp/${label}_client.log" 2>&1 &
    CLIENT_PID=$!
    sleep 1

    echo "-- [$label] before attack: server ss -tn --"
    ip netns exec server ss -tn | grep -E "State|:$port " || true

    wait "$INJECT_PID" || echo "[$label] WARNING: injector exited non-zero (see log below)"
    echo "-- [$label] injector output --"
    cat "$inject_log"

    sleep 1
    kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true

    SS_OUT=$(ip netns exec server ss -tn)
    echo "-- [$label] after attack: server ss -tn --"
    echo "$SS_OUT"
    echo "-- [$label] server app log --"
    cat "/tmp/${label}_server.log"

    ICMP_SEEN=$(tcpdump -r "$pcap" -nn icmp 2>/dev/null | wc -l | tr -d ' ')
    if [ "$ICMP_SEEN" -gt 0 ]; then
        echo "[$label] Spoofed ICMP visible in server capture: YES ($ICMP_SEEN packet(s), $pcap)"
    else
        echo "[$label] Spoofed ICMP visible in server capture: NO"
    fi

    # A successful abort doesn't necessarily vanish from `ss -tn` instantly —
    # the local side still runs through its own close sequence (e.g.
    # FIN-WAIT-2) before the socket fully disappears. Anything other than
    # ESTAB (or no entry at all) counts as a successful reset.
    PORT_LINE=$(echo "$SS_OUT" | grep ":$port " || true)
    if [ -z "$PORT_LINE" ]; then
        echo "[$label] RESULT: connection was RESET (socket gone)"
    elif echo "$PORT_LINE" | grep -q "^ESTAB"; then
        echo "[$label] RESULT: connection SURVIVED (still ESTABLISHED)"
    else
        STATE=$(echo "$PORT_LINE" | awk '{print $1}')
        echo "[$label] RESULT: connection was RESET (now $STATE)"
    fi

    cleanup
    trap - EXIT
    echo
}

echo "############################################################"
echo "# Scenario A — realistic target: plain ncat (no IP_RECVERR) #"
echo "############################################################"
run_scenario "ncat" "$NCAT_PORT" \
    "tail -f /dev/null | ncat -l $NCAT_PORT" \
    "tail -f /dev/null | ncat $SERVER_IP $NCAT_PORT" \
    "/tmp/inject_ncat.log"

echo "################################################################"
echo "# Scenario B — positive control: recverr_server.py (IP_RECVERR) #"
echo "################################################################"
run_scenario "recverr" "$RECVERR_PORT" \
    "python3 $SCRIPT_DIR/recverr_server.py $RECVERR_PORT" \
    "tail -f /dev/null | ncat $SERVER_IP $RECVERR_PORT" \
    "/tmp/inject_recverr.log"

echo "== Summary (design doc Section 5.1, re-examined) =="
echo "Scenario A (ncat, realistic):        expected to SURVIVE — hard error downgraded to soft"
echo "                                      error for ESTABLISHED sockets without IP_RECVERR."
echo "Scenario B (recverr_server, control): expected to be RESET — proves the packet itself"
echo "                                      (direction, seq, checksums) is correctly crafted."
