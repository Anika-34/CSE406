#!/usr/bin/env python3
"""
Minimal TCP echo-ish server that opts into IP_RECVERR.

Used as a positive control for P4: Linux only treats an ICMP Type 3/Code 3
as an immediately-fatal RFC 1122 hard error for an ESTABLISHED socket if
the application requested IP_RECVERR (see tcp_v4_err() in
net/ipv4/tcp_ipv4.c). Ordinary tools like `ncat` don't set this, so they
survive a perfectly-crafted reset packet; this server represents "a
vulnerable stack/app" per the design doc's own qualifier, to prove the
injected packet is otherwise correctly formed.

Usage: sudo ip netns exec server python3 experiments/recverr_server.py [port]
"""
import socket
import sys

IP_RECVERR = 11  # linux/in.h — not exposed as a socket.* constant on all builds

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_IP, IP_RECVERR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.0.0.2", port))
s.listen(1)
print(f"listening on 10.0.0.2:{port} with IP_RECVERR set", flush=True)

conn, addr = s.accept()
print(f"accepted {addr}", flush=True)
try:
    while True:
        data = conn.recv(1024)
        if not data:
            print("peer closed", flush=True)
            break
except OSError as e:
    print(f"socket error (this is what a successful reset looks like): {e!r}", flush=True)
print("server exiting", flush=True)
