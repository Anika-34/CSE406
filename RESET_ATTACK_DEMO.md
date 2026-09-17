# Demo: ICMP Blind Connection-Reset Attack (Attack 1)

This is a script for live-demonstrating the attack from `Design_doc.pdf`
Section 1.1 / 3.2 / 5.1, using the topology from `setup_topology.sh` and the
tooling in `attacks/` and `experiments/`.

## What you're demonstrating

The attacker spoofs an **ICMP Type 3, Code 3** (Port Unreachable) message
and injects it into the bridge. If accepted, RFC 1122 treats this as a
**hard error**, and the target's TCP stack aborts the connection.

Two things worth calling out live, because they're more interesting than a
plain "yes it works":

1. **A packet-direction subtlety.** ICMP errors are always delivered to the
   *original sender* of the embedded packet (that's the only host that can
   match it to one of its own sockets). To kill the **server's** socket,
   the embedded header inside the ICMP must claim `src=SERVER, dst=CLIENT`
   — i.e. it must look like a packet the *server itself* sent — not
   `src=CLIENT, dst=SERVER`. `attacks/build_packets.py` has the full
   reasoning in its module docstring.
2. **A real kernel-level defense, beyond what the design doc lists.**
   Linux only treats this ICMP as *immediately fatal* for an already-
   ESTABLISHED connection if the application opted into the `IP_RECVERR`
   socket option (see `tcp_v4_err()` in `net/ipv4/tcp_ipv4.c`). Ordinary
   tools like `ncat` don't set it, so the connection **survives** a
   perfectly-crafted packet. This demo shows both that realistic outcome
   and a positive-control case that succeeds, to prove the packet itself
   is correct.

## Prerequisites

The lab VM must be up with the topology already applied:

```bash
multipass start cse406-lab
multipass exec cse406-lab -- sudo bash /home/ubuntu/setup_topology.sh
```

(See `VM_COMMANDS.md` if the VM or its file sync needs setting up from
scratch.)

---

## Option A — one-shot automated demo

Runs both scenarios back-to-back and prints a full before/after report:

```bash
multipass exec cse406-lab -- sudo bash /home/ubuntu/experiments/p4_reset_experiment.sh
```

Expected tail of the output:

```
[ncat] Spoofed ICMP visible in server capture: YES (1 packet(s), .../p4_ncat.pcap)
[ncat] RESULT: connection SURVIVED (still ESTABLISHED)
...
[recverr] Spoofed ICMP visible in server capture: YES (1 packet(s), .../p4_recverr.pcap)
[recverr] RESULT: connection was RESET (now FIN-WAIT-2)

== Summary (design doc Section 5.1, re-examined) ==
Scenario A (ncat, realistic):        expected to SURVIVE — hard error downgraded to soft
                                      error for ESTABLISHED sockets without IP_RECVERR.
Scenario B (recverr_server, control): expected to be RESET — proves the packet itself
                                      (direction, seq, checksums) is correctly crafted.
```

This is enough to show a grader end-to-end. Use Option B below if you want
to walk through it live, step by step, across separate terminals.

---

## Option B — manual walkthrough (3 terminals)

Open three shells into the VM:

```bash
multipass shell cse406-lab   # x3
```

### Terminal 1 — Server

Hold an idle connection open (no data flood — see `VM_COMMANDS.md`'s disk
warning) and watch its state:

```bash
sudo ip netns exec server bash -c "tail -f /dev/null | ncat -l 9999"
```

In a second server-side check (can reuse Terminal 1 after backgrounding, or
just narrate this), you'd normally run:

```bash
sudo ip netns exec server ss -tn
```

### Terminal 2 — Client

```bash
sudo ip netns exec client bash -c "tail -f /dev/null | ncat 10.0.0.2 9999"
```

At this point `ss -tn` on the server (Terminal 1) shows:

```
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port
ESTAB  0      0      10.0.0.2:9999       10.0.0.1:<ephemeral>
```

### Terminal 3 — Attacker

Sniff the server's own SYN-ACK/segments to the client and inject the
spoofed reset:

```bash
sudo ip netns exec attacker python3 /home/ubuntu/attacks/inject_reset.py --server-port 9999
```

Expected output:

```
Sniffing veth-at for 10.0.0.2:9999 -> 10.0.0.1 traffic...
Captured: client_port=<port> server_seq=<seq>
Injecting spoofed ICMP Type 3, Code 3 (Port Unreachable)...
Sent.
```

### Back to Terminal 1 — observe the result

```bash
sudo ip netns exec server ss -tn
```

With plain `ncat`, this **still shows ESTAB** — the connection survives.
That's the real, documented Linux behavior, not a failed attack.

### Positive control — prove the packet is correct

Kill the ncat pair (Ctrl-C in Terminals 1 & 2), then repeat with the
`IP_RECVERR`-enabled test server instead of `ncat`:

```bash
# Terminal 1
sudo ip netns exec server python3 /home/ubuntu/experiments/recverr_server.py 9998

# Terminal 2
sudo ip netns exec client bash -c "tail -f /dev/null | ncat 10.0.0.2 9998"

# Terminal 3
sudo ip netns exec attacker python3 /home/ubuntu/attacks/inject_reset.py --server-port 9998
```

Terminal 1 now prints:

```
listening on 10.0.0.2:9998 with IP_RECVERR set
accepted ('10.0.0.1', <port>)
socket error (this is what a successful reset looks like): ConnectionRefusedError(111, 'Connection refused')
server exiting
```

and `sudo ip netns exec server ss -tn` shows the socket has moved out of
`ESTAB` (typically `FIN-WAIT-2`, then gone) — the connection was killed.

---

## Talking points for the write-up / defense

- The spoofed ICMP is visible in the server's own `tcpdump` capture in
  both scenarios (design doc Section 5.1, item 1) — the packet delivery
  and in-window sequence number are correct either way.
- Item 3 of Section 5.1 ("server's TCP stack aborts the connection") only
  holds for sockets with `IP_RECVERR` set. Cite `tcp_v4_err()` and
  RFC 1122 §4.2.3.9 in the report, and add this to Section 6 (Defense
  Ideas) as a third, already-built-in mitigation beyond sequence
  validation and ingress filtering.
- Cleanup between manual runs, if something is left running:
  ```bash
  sudo pkill -f "tail -f /dev/null"; sudo pkill -f ncat; sudo pkill -f recverr_server
  ```
