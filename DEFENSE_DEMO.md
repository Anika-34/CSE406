# Demo: Defense Simulation (Phase P7)

This is a script for live-demonstrating the two defenses named in
`README.md` Section 6 / the Implementation Plan's P7 row, against the
attacks from `RESET_ATTACK_DEMO.md` and `PMTU_ATTACK_DEMO.md`, using the
same topology and tooling.

## What you're demonstrating

Two independent defenses, at two different layers:

1. **Ingress filtering (BCP 38 / RFC 2827)** — a network-layer defense.
   A real border router drops any packet whose source address doesn't
   belong to the subnet it physically arrived from, which kills IP
   spoofing before the forged packet goes anywhere. Simulated with a
   `tc` filter on `veth-at-br` (the bridge port the attacker's traffic
   physically arrives on): only `src=10.0.0.3` (the attacker's real
   address) is let through; everything else is dropped. Since **every**
   packet `build_packets.py` crafts spoofs its outer source (`10.0.0.2`
   for the reset attack, `10.0.0.1` for the PMTU attack), this should
   block **both** attacks completely — it doesn't matter whether the
   target's TCP stack would otherwise have been vulnerable.

2. **PMTU cache aging + PLPMTUD** — a kernel-layer defense, specific to
   Attack 2. **Important correction, found by actually running this**:
   the first hypothesis tested here was that `tcp_mtu_probing=2` alone
   (plus a short `tcp_probe_interval`) would make the client "self-heal"
   a spoofed PMTU within seconds. It doesn't — `mss`/`pmtu` stayed
   pinned at the forged value for 20+ seconds straight in testing.
   `tcp_mtu_probing` governs PLPMTUD, which detects ICMP **black holes**
   (a router silently drops oversized packets with *no* Frag-Needed
   reply at all) and probes upward afterward — it does not re-verify a
   PMTU value that arrived via an ICMP message the kernel *did* receive
   and accept as authoritative. What actually holds the forged MTU in
   place is the **route-cache PMTU exception** itself (the same
   `cache expires <N>sec mtu 576` line seen in `ip route get` after the
   undefended attack), which ages out on its own via
   `net.ipv4.route.mtu_expires` — 600 seconds (10 minutes) by default.
   Shortened here to 8s so the recovery is actually observable live.
   `tcp_mtu_probing=2` is kept alongside it (matching the Implementation
   Plan's literal instruction) so the client re-verifies upward with
   real probe segments once the stale exception is gone. This is a
   mitigation against a *one-shot* attack, not a complete defense
   against a persistent one — `inject_pmtu.py`/`p5_pmtu_experiment.sh`
   re-spray on a repeating interval against an undefended target
   precisely because a real attacker needs to keep re-injecting faster
   than the exception can expire to have any lasting effect.

## Prerequisites

Topology already applied (namespaces are kernel state — check with
`sudo ip netns list`; rebuild if empty):

```bash
sudo bash setup_topology.sh
```

---

## Option A — one-shot automated demo

Runs both defenses back-to-back, reusing the exact same `p4_reset_experiment.sh`
and `p5_pmtu_experiment.sh` used for the undefended attacks, plus a
dedicated PLPMTUD recovery check:

```bash
sudo bash experiments/p7_defense_experiment.sh
```

Expected tail of Defense 1 (ingress filtering) — contrast this with your
earlier undefended runs, where `recverr` was RESET and the PMTU attack
succeeded:

```
[ncat]    Spoofed ICMP visible in server capture: NO
[ncat]    RESULT: connection SURVIVED (still ESTABLISHED)
[recverr] Spoofed ICMP visible in server capture: NO
[recverr] RESULT: connection SURVIVED (still ESTABLISHED)
...
[1] Spoofed ICMP visible in client capture: NO
[2] ip route get shows mtu 576 (PMTU cache updated): NO
[3] TCP segment sizes: avg stays ~1448 the whole run
[4] iperf3 throughput: no measurable before/after difference
```

The key change from the undefended P4 run: **`recverr` now survives too**
— proving the filter stops the attack at the network layer, independent
of the target's own TCP-stack behavior.

Expected shape of Defense 2 (PMTU cache aging), watching `ss -tin` over
time — note the checkpoints now run out to t+40s, since recovery is
gated by `net.ipv4.route.mtu_expires` (shortened to 8s here), not by
`tcp_probe_interval`:

```
-- before attack --
ESTAB ... mss:1441 pmtu:1500 ...   <- forcing tcp_mtu_probing=2 can leave this
                                       a little under the usual 1448; that's a
                                       real, harmless quirk of forced probing,
                                       not a bug

== Single-shot spray (one round, no repeat) ==
Sniffing veth-at for 10.0.0.1 -> 10.0.0.2:5201 traffic...
Captured: client_port=... base_seq=...
Spraying 300 candidates, step=50000B, covering +15.0MB (MTU=576)...
Sent.

-- route cache right after the spray --
... cache expires 8sec mtu 576

-- t+2s after attack --
ESTAB ... mss:524 pmtu:576 ...     <- attack landed, as expected
-- t+7s after attack --
ESTAB ... mss:524 pmtu:576 ...     <- exception hasn't expired yet (8s)
-- t+12s after attack --
ESTAB ... mss:1441 pmtu:1500 ...   <- exception expired ~4s ago, client
                                       re-verified the real MTU on its own
-- t+17s after attack --
ESTAB ... mss:1441 pmtu:1500 ...
-- t+22s after attack --
ESTAB ... mss:1441 pmtu:1500 ...
-- t+30s / t+40s --
ESTAB ... mss:1441 pmtu:1500 ...   <- stays recovered
```

Exact timing of the recovery step can land at t+12s or t+17s depending on
scheduling — what matters is that it **does** climb back to the full MSS
within a few seconds of the 8-second `mtu_expires` window, without any
further attacker action or network-layer defense.

**Status: this exact prediction was tested and did NOT hold.** In an
actual run, `mss`/`pmtu` stayed pinned at `524/576` all the way to
t+40s even though `ip route get` confirmed the exception really was
created with the shortened 8s timer. So — like the `tcp_mtu_probing`
hypothesis before it — "the route-cache exception aging out is enough"
turned out to be incomplete: an already-established, continuously busy
socket appears to keep reusing its own cached PMTU (`icsk_pmtu_cookie`)
without necessarily re-checking the route table just because an
exception elsewhere expired. `p7_defense_experiment.sh` now ends this
scenario with a diagnostic block — checking whether the route-table
exception itself is gone by t+40s, then forcibly flushing the route
cache to see if *that* is what's needed to unstick the socket. Treat
the timing/mechanism described above as **the current best hypothesis,
not a confirmed result** — re-run the script and check the diagnostic
output before citing exact numbers in a report. If even the forced
flush doesn't recover it, the honest conclusion is that this defense
may require the connection to close and reopen, not any sysctl alone.

---

## Option B — manual walkthrough

### Defense 1 — ingress filtering

**Apply the filter** (root namespace, one terminal):
```bash
sudo tc qdisc add dev veth-at-br handle ffff: ingress
sudo tc filter add dev veth-at-br parent ffff: protocol ip prio 1 u32 match ip src 10.0.0.3/32 action ok
sudo tc filter add dev veth-at-br parent ffff: protocol ip prio 2 u32 match u32 0 0 action drop
```

**Repeat the reset attack exactly as in `RESET_ATTACK_DEMO.md` Option B**
(server ncat / client ncat / attacker `inject_reset.py`, including the
`recverr_server.py` positive control) — this time expect the injector to
report `Sent.` as before (it doesn't know the packet was dropped — the
drop happens downstream, at the bridge), but the server's `tcpdump`
capture and `ss -tn` should show **no ICMP arrived and no state change**,
for both the plain-`ncat` case (already survived before) and — the
important contrast — the `recverr_server.py` case (which **used to
reset**, and now shouldn't).

**Repeat the PMTU attack exactly as in `PMTU_ATTACK_DEMO.md` Option B** —
expect `ss -tin` on the client to stay at `mss:1448 pmtu:1500` throughout,
regardless of how many spray rounds the attacker sends.

**Remove the filter when done:**
```bash
sudo tc qdisc del dev veth-at-br handle ffff: ingress
```

### Defense 2 — PMTU cache aging

**Terminal 1 — Server:**
```bash
sudo ip netns exec server iperf3 -s
```

**Terminal 2 — Client**, with the defense enabled first — note it's
`net.ipv4.route.mtu_expires`, not `tcp_probe_interval`, that actually
controls recovery time (see "What you're demonstrating" above for why):
```bash
sudo ip netns exec client sysctl -w net.ipv4.tcp_mtu_probing=2
sudo ip netns exec client sysctl -w net.ipv4.route.mtu_expires=8
sudo ip netns exec client iperf3 -c 10.0.0.2 -t 60 -i 5
```

**Terminal 3 — Attacker**, a *single* spray only (no `--duration`/`--interval` repeat):
```bash
cd /home/tirtha/CSE406
sudo ip netns exec attacker python3 attacks/inject_pmtu.py --server-port 5201 --mtu 576 --duration 1
```

**Terminal 4 — watch the recovery** (run every few seconds):
```bash
sudo ip netns exec client ss -tin | grep -E "mss|ESTAB"
sudo ip netns exec client ip route get 10.0.0.2   # watch the exception's own countdown
```
Expect `mss:524 pmtu:576` immediately after the spray, staying there
until the route-cache exception's ~8-second countdown reaches zero, then
climbing back to `mss:1441/1448 pmtu:1500` within a few seconds after
that (so roughly 10-15s after the spray, not the 5s a `tcp_probe_interval`
reading might suggest — that sysctl doesn't govern this recovery).

**Restore defaults when done:**
```bash
sudo ip netns exec client sysctl -w net.ipv4.tcp_mtu_probing=1
sudo ip netns exec client sysctl -w net.ipv4.tcp_probe_interval=600
sudo ip netns exec client sysctl -w net.ipv4.route.mtu_expires=600
```

---

## Talking points for the write-up / defense

- **Defense 1 is the only complete fix.** It stops the spoofed packet at
  the network edge, before either attack's TCP-stack-specific behavior
  even comes into play. It maps directly to README Section 6's "Ingress
  filtering (BCP 38)" row, which until now was listed but never
  implemented or measured.
- **Defense 2 is a real, already-built-in Linux mitigation, not a
  complete defense — and worth a paragraph on its own for what it
  actually is.** The natural instinct is to reach for `tcp_mtu_probing`
  (PLPMTUD) since it's the literal name in the Implementation Plan's P7
  row, but testing it directly shows it does nothing here — it defends
  against ICMP being *filtered out* (a black hole), not against a
  forged-but-delivered ICMP being *accepted* as truth. The actual
  self-healing mechanism is the route-cache PMTU exception's own aging
  timer (`net.ipv4.route.mtu_expires`, 10 minutes by default). Either
  way, it only helps against a *single* spoofed ICMP; a persistent
  attacker who keeps re-spraying (as `p5_pmtu_experiment.sh` already
  does against an undefended target) re-triggers the MSS drop faster
  than any real-world `mtu_expires` value could recover it. Worth
  citing alongside the `IP_RECVERR` finding from `RESET_ATTACK_DEMO.md`
  as a second example of "the real Linux kernel already has partial
  defenses beyond what the design doc's Section 6 lists" — and, just
  as importantly, an example of a plausible-sounding defense
  (`tcp_mtu_probing`) that turned out not to be the actual mechanism
  once tested, which is itself worth reporting.
- Combined picture for the report: **sequence-number validation** (why
  P5 needed a spray instead of one guess), **`IP_RECVERR` gating**
  (why P4 survives against `ncat`), **PMTU cache aging** (why a
  persistent attacker needs repeated injection, not one packet), and
  **ingress filtering** (the one defense that stops the root cause —
  spoofing itself) together form a complete Section 6.
- Cleanup between manual runs:
  ```bash
  sudo tc qdisc del dev veth-at-br handle ffff: ingress 2>/dev/null
  sudo ip netns exec client sysctl -w net.ipv4.tcp_mtu_probing=1
  sudo ip netns exec client sysctl -w net.ipv4.tcp_probe_interval=600
  sudo ip netns exec client sysctl -w net.ipv4.route.mtu_expires=600
  sudo pkill -f iperf3; sudo pkill -f ncat; sudo pkill -f inject_pmtu; sudo pkill -f recverr_server
  ```
