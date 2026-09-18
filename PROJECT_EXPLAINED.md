# The Whole Project, Explained From Zero

This explains the CSE 406 project — **ICMP Blind Connection-Reset & Blind
Throughput Reduction Attack Against TCP** (Anika Morshed 2105068, Diganta
Saha Tirtha 2105081) — assuming you know nothing about TCP internals,
ICMP, or the lab tooling. It covers what `Design_doc.pdf` proposed, what
was actually built, and — importantly — several places where testing the
real thing turned up different behavior than the design doc assumed.

---

## 1. The one-sentence version

Two attacks that mess with someone else's TCP connection **without being
on the connection at all** — just by sending one forged "error" packet
that *claims* to be from the other side, and two matching defenses that
try to stop it.

---

## 2. Background you need first

### 2.1 A normal TCP connection

Two computers ("client" and "server") talk over TCP. Before any data
flows, they do a **3-way handshake**:

```
Client                          Server
  | ---------- SYN ----------->  |   "I want to connect"
  | <------- SYN-ACK ----------  |   "OK, here's my starting number"
  | ---------- ACK ----------->  |   "Confirmed"
  |                               |
  | <====== data flows =======>  |
```

Every byte sent over a TCP connection is numbered (a **sequence
number**). Both sides track "which numbers have I sent/received so far,
and what's the window of numbers I'll currently accept." This
**in-window check** matters a lot later — a huge part of both attacks is
about sneaking a fake packet's numbers into that acceptable window.

A connection normally ends politely (`FIN`) or is killed abruptly by an
**RST (reset)** packet — the TCP equivalent of "hang up immediately,
something's wrong."

### 2.2 What ICMP is, and why it can kill a TCP connection

**ICMP** is the "little brother" protocol IP uses for control messages —
"host unreachable," "port unreachable," "your packet was too big," etc.
It's not part of TCP at all, but here's the trick this whole project is
built on: **RFC 1122 says that certain ICMP error messages are "hard
errors,"** and when a host's kernel receives one that matches an open
connection, it's allowed to **kill that connection immediately**, without
the two endpoints exchanging a single TCP packet about it.

Two specific ICMP messages matter here — both are sub-types of "ICMP
Type 3: Destination Unreachable":

| ICMP Type/Code | Name | Meaning | Effect on TCP |
|---|---|---|---|
| Type 3, Code 3 | Port Unreachable | "Nobody is listening on that port" | RFC 1122 hard error → **abort the connection** |
| Type 3, Code 4 | Fragmentation Needed, DF Set | "Your packet was too big for the next hop, and you told me not to fragment it (DF = Don't Fragment); here's the biggest size that *will* fit (Next-Hop MTU)" | Sender shrinks its **Path MTU** for that destination |

**How does the receiving computer know *which* connection an ICMP error
is about**, since ICMP isn't TCP? RFC 792 answers this: every ICMP error
message must carry, as its payload, **the original IP header plus the
first 8 bytes of the original packet** (which for TCP is exactly enough
to get the source port, destination port, and sequence number). The
receiving kernel unpacks that embedded mini-header and matches it against
its own open sockets — "oh, this error is about *my* connection to
*that* port, with *that* sequence number."

**This embedded header is the entire attack surface.** If an attacker
can *forge* an ICMP packet whose embedded header looks like it's
describing a real, live connection, the receiving kernel has no way to
tell the difference between that and a genuine error from a real router
— **unless it's spoofing-protected at the network level, or it validates
the sequence number carefully.** That's the whole idea behind both
attacks in this project.

### 2.3 MTU, MSS, and Path MTU Discovery

- **MTU** (Maximum Transmission Unit): the biggest single packet a link
  can carry. Ethernet's usual MTU is 1500 bytes.
- **MSS** (Maximum Segment Size): how much *TCP payload* fits in one
  packet once you subtract IP/TCP headers — roughly `MTU - 40`.
- **PMTU** (Path MTU): the smallest MTU along the *entire* route to a
  destination — you might have a 1500-byte MTU locally, but if some
  router in the middle only supports 576 bytes, your PMTU to that
  destination is 576.
- **PMTU Discovery (RFC 1191):** senders find this out by setting the
  "Don't Fragment" flag and sending normal-sized packets. If a router
  along the way can't forward it without fragmenting, it drops the
  packet and sends back exactly the ICMP Type 3/Code 4 message above,
  telling the sender the real limit. The sender then shrinks its MSS and
  caches the new, smaller PMTU for that destination.

**Attack 2 abuses this discovery mechanism directly**: if you can forge
that same ICMP message, you can make a healthy connection *believe* the
path suddenly got much narrower — even though nothing on the real path
changed.

### 2.4 IP spoofing — the missing ingredient both attacks need

None of this works unless the attacker can put a **fake source address**
on the packets they send (pretending the ICMP came from the server, or
from a router near the server, rather than from the attacker's own
machine). This is called **IP spoofing**, and it's what makes both
attacks "blind" — the attacker never has to be *on-path* for the real
connection, they just need to guess/observe enough details to forge a
convincing packet and get it delivered.

### 2.5 Why simulate this on one machine (network namespaces)

You obviously can't ethically test IP spoofing against a real server
online. This project builds a **tiny private network entirely inside one
Linux machine**, using **network namespaces** — Linux's way of giving a
process group its own private set of network interfaces, IP addresses,
and routing table, completely isolated from the rest of the system (and
from each other) even though they're all really running on the same
kernel.

Three namespaces are created — `client`, `server`, `attacker` — each
with one virtual Ethernet interface (`veth`), all plugged into one
software **bridge** (`br0`), which behaves like a physical Ethernet
switch connecting them. See §4 for exactly how.

---

## 3. What the design doc proposed (`Design_doc.pdf`)

The submitted design report laid out the project in seven sections. This
is what it says, faithfully:

### 3.1 Overview
- **Attack 1**: spoof ICMP Type 3/Code 3 at the server, embedding a
  fake TCP header, to trigger RFC 1122's hard-error abort.
- **Attack 2**: spoof ICMP Type 3/Code 4 at whichever side is sending
  bulk data, advertising a small Next-Hop MTU (e.g. 576 bytes), to force
  it to shrink its MSS and lose throughput.

### 3.2 Topology
Three namespaces (`client` 10.0.0.1, `server` 10.0.0.2, `attacker`
10.0.0.3) on one bridge `br0`, all inside one Ubuntu 22.04 VM.

### 3.3 Timing diagrams (as designed)

**Attack 1:**
```
Client -- SYN --> Server
Client <- SYN-ACK - Server
Client -- ACK --> Server
   (bulk data flows; attacker sniffs seq#/port via tcpdump)
Attacker -- spoofed ICMP Type3/Code3 (claims src=Server) --> Client
   (kernel checks: is the seq# in-window? if yes ->)
Server -- RST --> Client       Client sees ECONNRESET
```

**Attack 2:**
```
Client <==== high-throughput data flow ====> Server
Attacker -- ICMP Type3/Code4, next-hop MTU=576 --> (target)
   target shrinks PMTU, resizes segments smaller
   throughput degrades
   (repeated every few seconds, since it can otherwise recover)
```

### 3.4 Designed packet structure (RFC 792 skeleton)

| Layer | Field |
|---|---|
| Ethernet | src = attacker MAC, dst = bridge MAC |
| Outer IP | src = *forged* (server/router), dst = client, proto = 1 (ICMP) |
| ICMP | Type / Code / Checksum / type-specific field |
| Embedded IP | src = client, dst = server, proto = 6 (TCP) |
| Embedded TCP (8 bytes) | source port, dest port, sequence number |

The doc's own field tables for each attack (Sections 3.2/3.3) originally
described the *embedded* header as `src=Client, dst=Server` in both
cases — **this exact detail turned out to be backwards**, and fixing it
was the single most important correction made during implementation (see
§5.2 below).

### 3.5 Implementation plan (P0–P7)

| Phase | Goal |
|---|---|
| P0 | Topology setup |
| P1 | Baseline `iperf3` measurement, no attack |
| P2 | Capture a *real* kernel-generated ICMP error as ground truth |
| P3 | Sniff the live connection's port/seq from the attacker's vantage point |
| P4 | Run the reset attack |
| P5 | Run the PMTU attack |
| P6 | Collect metrics from P1/P4/P5 |
| P7 | Enable `tcp_mtu_probing=2` as a defense, repeat P4/P5 |

### 3.6 Expected outcomes (as designed)

**Attack 1** success = ICMP visible in capture → seq in-window → server
aborts → `ss -tn` shows the socket gone → client sees a broken pipe.

**Attack 2** success = ICMP visible in capture → `ip route get` shows
`mtu 576` → segment sizes drop to ≤536 bytes → `iperf3` throughput drops.

### 3.7 Defense ideas (as designed)

| Defense | Mechanism | Effect |
|---|---|---|
| Sequence-number validation | Modern kernels require the embedded seq# to be in-window before acting on the ICMP | Makes blind guessing much harder |
| Ingress filtering (BCP 38) | Routers drop packets whose source IP doesn't belong to the network they arrived from | Prevents IP spoofing at the edge entirely |

### 3.8 References
RFC 792 (ICMP), RFC 1122 (host requirements / hard errors), RFC 1191
(Path MTU Discovery), RFC 2385 (TCP MD5, mentioned for context), Watson
2004 (*Slipping in the Window*, the original blind TCP reset research),
RFC 5961 (in-window validation hardening), RFC 6633 (ICMP Source Quench
deprecation, for context).

---

## 4. The lab environment, exactly as built

`setup_topology.sh` builds this (run with `sudo`):

```
        veth-cl  veth-cl-br┐              ┌veth-sv-br  veth-sv
 client ─────────┤          ├──── br0 ─────┤          ├───────── server
 10.0.0.1        └──────────┘   (bridge)   └──────────┘         10.0.0.2
                                   │
                       veth-at-br ├─────────┐
                                   └─────────┤ veth-at
                                              attacker
                                              10.0.0.3
```

- Each namespace gets one half of a `veth` pair; the other half plugs
  into the bridge `br0`.
- The client↔server link is **rate-limited to 100mbit** (`tc qdisc tbf`)
  — otherwise two processes on the same kernel would exchange data at
  effectively unlimited (memory-copy) speed, which is unrealistic for a
  TCP experiment and produces unmanageably huge packet captures.
- **`rp_filter` (reverse-path source filtering) is disabled** on all
  three namespaces — this is Linux's own built-in *anti-spoofing* check;
  it has to be turned off for the lab to demonstrate spoofing at all
  (real defended networks would have this on, which is part of why
  ingress filtering as a *defense* — §7 — matters).
- **Traffic mirroring**: `tc filter ... action mirred` copies every
  packet that enters the bridge from the client's or server's port over
  to the attacker's port too. This is how the attacker can "see" the
  live client↔server conversation with `tcpdump` **without being an
  active man-in-the-middle** — it's a passive copy, not an interception.

---

## 5. Attack 1 — ICMP Blind Connection-Reset, in full

### 5.1 The idea

Hold an ordinary TCP connection open. From a third machine (the
attacker), forge one ICMP "Port Unreachable" packet that looks like it's
reporting a problem with that exact connection, and get the server to
believe it and drop the connection — even though the client and server
never had any real problem.

### 5.2 The correction that had to be made (important!)

The design doc's packet table said the *embedded* header inside the ICMP
should be `src=Client, dst=Server` — i.e. describing the connection
exactly as it looks from the client's point of view.

**Testing this literally never worked.** The reason, once traced down:
**ICMP errors are always delivered to the original sender of the
embedded packet** — that's the only way a receiving host can match the
error to one of *its own* sockets. To make the **server's** kernel act
on the forgery, the embedded header must look like something the
**server itself** sent — i.e. `src=Server, dst=Client` — the *opposite*
of the design doc's table. The sequence number must also come from a
packet the **server** actually sent (sniffed from server→client
traffic), not the client's.

This fix lives in `attacks/build_packets.py`'s `build_reset_packet()`
function, with the full reasoning in its module docstring.

### 5.3 The actual packet, as built

| Layer | Field | Value |
|---|---|---|
| Outer IP | src | 10.0.0.2 (spoofed — pretending to be the **server**) |
| Outer IP | dst | 10.0.0.2 (the real server — this **is** the target) |
| ICMP | Type/Code | 3 / 3 (Port Unreachable) |
| Embedded IP | src → dst | 10.0.0.2 → 10.0.0.1 (server → client, as if the server sent it) |
| Embedded TCP | sport/dport | server's port → client's ephemeral port |
| Embedded TCP | seq | sniffed from the server's own live outgoing segment |

### 5.4 How the code actually does it, step by step

1. **`build_packets.py::capture_live_state()`** runs `tcpdump` on the
   attacker's interface, filtered for the server's own outgoing traffic
   to the client, and parses out the current sequence number from a
   SYN/data segment (only these carry a `seq` value in tcpdump's text
   output — pure ACKs don't).
2. **`build_packets.py::build_reset_packet()`** assembles the spoofed
   packet with Scapy, using the direction from §5.2.
3. **`inject_reset.py`** ties these together: sniff, build, `send()`.
4. **`experiments/p4_reset_experiment.sh`** orchestrates a full
   before/after test: starts a server, starts the attacker's sniffer
   *before* the client even connects (timing matters — see §5.6), starts
   the client, waits for the injection, then checks `ss -tn` on the
   server and counts ICMP packets in a `tcpdump` capture.

### 5.5 The second real finding: it doesn't actually kill a normal connection

Running this against a plain `ncat`-held connection, the spoofed packet
**arrives, passes every check, and the connection survives anyway.**
Digging into the Linux kernel source (`tcp_v4_err()` in
`net/ipv4/tcp_ipv4.c`) explains why: for an **already-ESTABLISHED**
socket, this ICMP is only treated as an immediately-fatal RFC 1122 hard
error if the application explicitly opted in with the `IP_RECVERR`
socket option. Plain `ncat` doesn't set it, so the kernel silently
downgrades the "hard error" to a harmless `sk_err_soft` and the
connection keeps going.

To prove the *packet itself* is correctly crafted (not that the attack
concept is broken), `experiments/recverr_server.py` is a tiny test
server that **does** set `IP_RECVERR`. Against that server, the exact
same packet **reliably kills the connection** — `ConnectionRefusedError`
on the server side, socket moves out of `ESTAB` (typically to
`FIN-WAIT-2`).

**This `IP_RECVERR` gate is a real, already-built-in Linux defense**,
distinct from anything the design doc's Section 6 mentions, and worth
reporting as an addition to it.

### 5.6 A timing subtlety worth knowing

The sniffer only ever sees a `seq` number during the SYN/SYN-ACK
handshake or an actual data transfer — an idle connection (as used here
on purpose, to avoid flooding the lab's small disk) never sends anything
else. So **the attacker's sniffer must already be running before the
client connects**, or it misses the only seq-bearing packet that will
ever exist and times out. `p4_reset_experiment.sh` gets this right
internally (starts the injector, waits 1s, *then* connects the client).

### 5.7 Confirmed results (real test run)

| Scenario | ICMP delivered? | Result |
|---|---|---|
| Plain `ncat` (no `IP_RECVERR`) | Yes, visible in capture | **SURVIVED** (still `ESTAB`) |
| `recverr_server.py` (`IP_RECVERR` set) | Yes, visible in capture | **RESET** (`ConnectionRefusedError`, socket left `ESTAB`) |

---

## 6. Attack 2 — ICMP Blind PMTU Throughput Reduction, in full

### 6.1 The idea

While a bulk file transfer is happening (client sending to server via
`iperf3`), forge one ICMP "Fragmentation Needed" message claiming the
path can now only carry 576-byte packets. If the sender believes it, it
shrinks its MSS from ~1448 bytes down to ~524 bytes, sending smaller
segments — and, because more of each capped-rate packet is now spent on
fixed header overhead, throughput drops.

### 6.2 Same directional fix as Attack 1, opposite target

Attack 1 targets the **server** (the connection's receiver in that
scenario). Attack 2 targets the **client**, because the client is the
one doing the *sending* in this lab's `iperf3` test — and MSS is a
per-sender cache, so you have to shrink the *sender's* MSS to reduce its
throughput. The embedded header must look like something the **client**
itself sent to the server (`src=Client, dst=Server` — this direction the
design doc actually had right for this attack, since here the target and
the "connection as seen by its own sender" happen to coincide).

### 6.3 The packet, as built

| Layer | Field | Value |
|---|---|---|
| Outer IP | src | 10.0.0.1 (spoofed — pretending to be near the **client**'s path) |
| Outer IP | dst | 10.0.0.1 (the real client — the target, since it's the sender) |
| ICMP | Type/Code | 3 / 4 (Fragmentation Needed, DF Set) |
| ICMP | Next-Hop MTU | 576 |
| Embedded IP | src → dst | 10.0.0.1 → 10.0.0.2 (client → server, as the client's own packet) |
| Embedded TCP | sport/dport | client's ephemeral port → server's `iperf3` port (5201) |
| Embedded TCP | seq | sniffed from the client's own live outgoing traffic |

### 6.4 The finding that matters most for this attack: one guess isn't enough

Attack 1's target connection was **idle**, so a sequence number sniffed
once stays valid forever (the window never moves). Attack 2's target is
an **active bulk transfer** — the kernel's in-window check
(`between(seq, snd_una, snd_nxt)`) still applies (it runs for *every*
ICMP type/code, not just the reset one), but now that window is only
`cwnd * mss` wide (~100–150KB observed) and it slides forward at the
full transfer rate. By the time a sniffed sequence number has gone
through `tcpdump` → Python → Scapy's `send()`, it's almost always
**already ACKed and out of window** — confirmed directly via the
`TcpExt:OutOfWindowIcmps` counter in `/proc/net/netstat`.

**The fix — implemented in `attacks/inject_pmtu.py` — is to spray, not
guess.** Instead of sending one packet with one sequence number, it
sends **300 candidate packets**, spaced 50,000 bytes apart in sequence
space, covering ~15MB — guaranteeing at least one lands inside the live
window regardless of the latency above. This is the same technique real
blind-injection attacks use (Watson 2004's original TCP reset research),
and matches the design doc's own "sampled seq numbers" (plural) wording.

`inject_pmtu.py` also **repeats this spray every few seconds** for the
whole attack duration, because Linux's own Packetization-Layer PMTU
Discovery can otherwise rediscover the true PMTU mid-transfer and undo
the attack partway through (see §7.3 for exactly how complicated that
turned out to be).

### 6.5 Confirmed results (real test run)

| Metric | Before | After |
|---|---|---|
| `ss -tin` on client | `mss:1448 pmtu:1500` | `mss:524 pmtu:576` |
| `ip route get 10.0.0.2` | no cached mtu | `cache expires ...sec mtu 576` |
| Avg TCP segment size | 1448 bytes | ~531–542 bytes |
| `iperf3` throughput | ~92–95 Mbps | ~87–90 Mbps (≈ 5–7% drop) |
| ICMP packets seen (8 spray rounds × 300) | — | exactly 2400–2700, matching round count |

**Why the throughput drop is modest, not dramatic:** the lab's
client↔server link is rate-capped at 100mbit (`tc tbf`, a byte-rate
limiter). At a fixed byte rate, a smaller MSS just means a bigger slice
of every packet goes to the fixed 40-byte header instead of payload
(~97% efficient at MSS 1448 vs ~93% at MSS 536) — a real, explainable
effect, not a measurement error.

---

## 7. Defenses — what was proposed, what was built, and what was actually found

### 7.1 Sequence-number validation (design doc idea #1) — already inherent, already seen in action

This isn't a separate script — it's the very kernel behavior that made
§6.4's spray technique *necessary* in the first place. Modern Linux
already refuses to act on an ICMP error whose embedded sequence number
is outside the connection's current window. The PMTU attack's "spray 300
candidates" workaround is direct, practical proof this defense is real
and already deployed by default — it's *why* a single guess doesn't
work, not an optional add-on.

### 7.2 Ingress filtering (BCP 38 / RFC 2827) — implemented, and it fully works

**What it is:** a border router refuses to forward any packet whose
source address doesn't belong to the network segment it physically
arrived from. If every network did this, IP spoofing (which *every*
attack in this project depends on) would be impossible on the public
internet.

**How it's simulated:** a `tc` filter on `veth-at-br` — the bridge port
the attacker's traffic physically arrives on — drops anything that
*isn't* `src=10.0.0.3` (the attacker's real, honest address):

```bash
tc qdisc add dev veth-at-br handle ffff: ingress
tc filter add dev veth-at-br parent ffff: protocol ip prio 1 u32 match ip src 10.0.0.3/32 action ok
tc filter add dev veth-at-br parent ffff: protocol ip prio 2 u32 match u32 0 0 action drop
```

**Confirmed result:** re-running both attacks with this filter active
blocks them completely — no ICMP ever arrives at either target,
`mss`/`pmtu` never change, throughput is unaffected. Critically, the
`recverr_server.py` scenario — which *always* gets reset without this
filter — **survives** with it on. This is the strongest defense tested:
it stops the root cause (spoofing) rather than reacting to its symptoms,
so it works regardless of which attack, or which quirk of the target's
TCP stack, is in play.

### 7.3 PLPMTUD / PMTU cache aging (design doc idea, Implementation Plan P7) — the honest, unresolved part

The Implementation Plan literally says: *"Enable `tcp_mtu_probing=2`.
Repeat P4 and P5. Record whether kernel rejects the forged ICMP
messages."* Building and testing this honestly took **two wrong
hypotheses in a row** — both are worth recording, because "a defense
that sounds right on paper doesn't automatically work" is itself a real
finding.

**Hypothesis 1 (tested, wrong):** `net.ipv4.tcp_mtu_probing=2` plus a
short `net.ipv4.tcp_probe_interval` would make the client "self-heal" a
spoofed PMTU within seconds. **Result: it did not.** `mss`/`pmtu` stayed
pinned at the forged value for 20+ seconds straight.
**Why it was wrong:** `tcp_mtu_probing` (PLPMTUD) is designed to detect
ICMP **black holes** — a router that silently drops oversized packets
and never sends *any* Frag-Needed reply. It has nothing to do with
re-verifying a PMTU value that arrived via an ICMP message the kernel
*did* receive and *did* accept as legitimate.

**Hypothesis 2 (tested, also wrong so far):** what actually holds the
forged MTU in place is the **route-cache PMTU exception** created when
the ICMP lands (the same `cache expires <N>sec mtu 576` line visible in
`ip route get`). That exception has its own aging timer,
`net.ipv4.route.mtu_expires` (600 seconds / 10 minutes by default),
which was shortened to 8 seconds to make it demoable. **Result: still no
recovery**, even out to 40 seconds, even though `ip route get` confirmed
the shortened exception really was created.

**Where this stands right now:** `experiments/p7_defense_experiment.sh`
ends this scenario with a diagnostic — checking whether the route-table
exception is actually gone by t+40s, then forcibly flushing the route
cache to see whether *that* external nudge is what an already-busy
socket needs to notice the change (Linux caches a socket's last-known
PMTU and may only re-check it opportunistically, not automatically just
because a route-table entry aged out elsewhere). **This part of the
project is an open, honestly-reported finding, not a confirmed
result** — see `DEFENSE_DEMO.md` for the exact diagnostic output to
watch for next.

### 7.4 Summary table — design doc's defenses vs. what was actually found

| Defense (design doc) | Status | What was actually found |
|---|---|---|
| Sequence-number validation | ✅ Confirmed, inherent | This is *why* Attack 2 needs a spray of 300 packets instead of one guess |
| Ingress filtering (BCP 38) | ✅ Confirmed, implemented | Blocks both attacks completely; the one defense that stops the root cause |
| `tcp_mtu_probing=2` (P7's literal instruction) | ❌ Tested, does not work | Governs black-hole detection, not recovery from an *accepted* ICMP |
| *(not in design doc)* `IP_RECVERR` | ✅ Discovered during testing | Real Linux kernel behavior: Attack 1 fails against any app that doesn't set this socket option |
| *(not in design doc)* PMTU route-cache aging | 🟡 Still being diagnosed | Shortening `mtu_expires` alone didn't produce recovery within 40s either |

---

## 8. The directory, file by file

```
CSE406/
├── Design_doc.pdf              the original submitted design report (§3 above)
├── README.md                   a Markdown mirror of the design doc
├── setup_topology.sh            builds the 3-namespace + bridge lab (§4)
│
├── attacks/
│   ├── build_packets.py         crafts both spoofed ICMP packets (Scapy) — the
│   │                            corrected embedded-header direction lives here
│   ├── inject_reset.py          Attack 1: sniff + build + send one reset packet
│   └── inject_pmtu.py           Attack 2: sniff + spray 300 PMTU packets, repeating
│
├── experiments/
│   ├── p1_baseline.sh           P1: iperf3 baseline, no attack
│   ├── p2_icmp_reference.sh     P2: capture a real kernel ICMP error as ground truth
│   ├── p4_reset_experiment.sh   P4: automated Attack 1 demo (ncat + recverr scenarios)
│   ├── p5_pmtu_experiment.sh    P5: automated Attack 2 demo (60s iperf3 + injection)
│   ├── p7_defense_experiment.sh P7: automated defense demo (§7.2, §7.3)
│   ├── recverr_server.py        the IP_RECVERR-enabled positive-control server (§5.5)
│   └── results/                 pcaps/JSON output from running the above (gitignored)
│
├── RESET_ATTACK_DEMO.md         walkthrough script for presenting Attack 1 live
├── PMTU_ATTACK_DEMO.md          walkthrough script for presenting Attack 2 live
├── DEFENSE_DEMO.md              walkthrough script for presenting both defenses live
├── COMMANDS.md                  bare command list for all of the above, no commentary
├── PROJECT_EXPLAINED.md          this file
└── VM_COMMANDS.md               notes from when this ran inside a Multipass VM
                                  (not needed on WSL — everything here runs natively)
```

---

## 9. How to actually run any of this

See **`COMMANDS.md`** for the exact commands (setup, both attacks,
both defenses, cleanup, full teardown) with no extra explanation. See
**`RESET_ATTACK_DEMO.md`**, **`PMTU_ATTACK_DEMO.md`**, and
**`DEFENSE_DEMO.md`** for the same material *with* explanation, expected
output, and talking points for a live presentation or the write-up.

Everything runs directly under WSL2 (no VM needed) — the notes in
`VM_COMMANDS.md` about Multipass/macOS are historical, from before the
project moved to this machine.

---

## 10. Glossary

| Term | Meaning |
|---|---|
| **TCP handshake** | The SYN / SYN-ACK / ACK exchange that opens a connection |
| **Sequence number** | A running count of bytes sent, used to detect loss/reordering and (here) to validate that an ICMP error is legitimate |
| **RST** | A TCP packet that immediately, unilaterally kills a connection |
| **ICMP** | IP's control-message protocol; carries errors like "port unreachable" or "too big, fragmentation needed" |
| **Hard error (RFC 1122)** | An ICMP error type serious enough that a TCP stack is allowed to abort the connection on the spot |
| **MTU** | Biggest packet size a network link can carry |
| **MSS** | Biggest amount of TCP *payload* that fits in one packet on a given path |
| **PMTU** | The smallest MTU anywhere along a full path to a destination |
| **PMTU Discovery** | The (legitimate) process of finding the real PMTU via "too big" ICMP replies |
| **IP spoofing** | Putting a false source address on a packet |
| **Blind attack** | An attack performed without being on-path for the real connection — success depends on guessing/observing enough detail to forge a convincing packet |
| **Network namespace** | Linux's isolated, private copy of the networking stack for a group of processes |
| **veth** | A virtual Ethernet cable connecting two network namespaces (or a namespace to a bridge) |
| **Bridge (`br0`)** | A virtual Ethernet switch connecting multiple veth interfaces |
| **`tc` (traffic control)** | Linux's tool for rate-limiting, mirroring, and filtering traffic on an interface |
| **`IP_RECVERR`** | A socket option that makes a hard ICMP error immediately fatal to an established connection |
| **PLPMTUD** | Packetization-Layer PMTU Discovery — Linux's mechanism for recovering from ICMP black holes |
| **Route-cache PMTU exception** | The kernel's cached "the path to X is only N bytes wide" record, created when a Frag-Needed ICMP is accepted |
| **BCP 38 / RFC 2827** | The standard recommending that networks filter out packets with spoofed source addresses at their edge |
