# Multipass VM — Local Commands (not tracked in git)

Lab VM name: `cse406-lab` (Ubuntu 22.04, created via Multipass)
Project mount: `/Users/anika/cse406-vm-share` -> `/home/ubuntu/CSE406` inside the VM
(Desktop/Documents/Downloads can't be mounted directly — macOS TCC blocks `multipassd`
from reading them, so the project is copied/synced into `~/cse406-vm-share` first.)

## Start multipass daemon + VM

```bash
# Start the multipass background service (usually already running as a launchd daemon)
sudo launchctl start com.canonical.multipassd

# Start the VM (boots from its saved disk state)
multipass start cse406-lab

# Re-mount the project dir if the mount didn't persist across a stop/start
multipass mount /Users/anika/cse406-vm-share cse406-lab:/home/ubuntu/CSE406

# Confirm it's up
multipass list
multipass info cse406-lab
```

## Shell / run commands in the VM

```bash
multipass shell cse406-lab
multipass exec cse406-lab -- <command>
```

## Re-run the topology setup script

Needed after every VM restart — namespaces are kernel state, not disk state,
so they don't survive `multipass stop`/`start`.

```bash
multipass exec cse406-lab -- bash -c "cp /home/ubuntu/CSE406/setup_topology.sh /home/ubuntu/setup_topology.sh && chmod +x /home/ubuntu/setup_topology.sh && sudo bash /home/ubuntu/setup_topology.sh"

# Optional: override the shaped link rate (default 100mbit)
multipass exec cse406-lab -- bash -c "cp /home/ubuntu/CSE406/setup_topology.sh /home/ubuntu/setup_topology.sh && chmod +x /home/ubuntu/setup_topology.sh && sudo LINK_RATE=10mbit bash /home/ubuntu/setup_topology.sh"
```

## Sync a script from the Mac into the VM (general pattern)

The sshfs mount (`/home/ubuntu/CSE406`) can't reliably execute scripts —
copy into the VM's own filesystem first, then run:

```bash
# 1. Copy from Desktop/CSE406 into the unprotected share dir on the Mac
cp /Users/anika/Desktop/CSE406/<path/to/script> /Users/anika/cse406-vm-share/<path/to/script>

# 2. Copy from the sshfs mount into the VM's local disk, then chmod
multipass exec cse406-lab -- bash -c "mkdir -p /home/ubuntu/<dir> && cp /home/ubuntu/CSE406/<path/to/script> /home/ubuntu/<path/to/script> && chmod +x /home/ubuntu/<path/to/script>"

# 3. Run it
multipass exec cse406-lab -- sudo bash /home/ubuntu/<path/to/script>
```

**Caution — disk is only 8GB:** the client/server veth link is shaped to
100mbit (see setup_topology.sh), but anything that ignores that and floods
data directly (e.g. `yes | ncat ...`, or tcpdump without `-s <snaplen>`) can
still fill the disk in seconds. Check with `multipass exec cse406-lab -- df -h /`
if a capture command hangs or a script behaves oddly — "No space left on
device" errors are often silent inside nested `bash -c` calls.

## P1 — baseline iperf3 measurement

```bash
multipass exec cse406-lab -- bash -c "cp /home/ubuntu/CSE406/experiments/p1_baseline.sh /home/ubuntu/experiments/p1_baseline.sh && chmod +x /home/ubuntu/experiments/p1_baseline.sh"
multipass exec cse406-lab -- sudo bash /home/ubuntu/experiments/p1_baseline.sh 30   # duration in seconds

# Pull results back to the git-tracked (but gitignored) results folder
multipass transfer cse406-lab:/home/ubuntu/experiments/results/p1_baseline.json /Users/anika/Desktop/CSE406/experiments/results/p1_baseline.json
multipass transfer cse406-lab:/home/ubuntu/experiments/results/p1_baseline.pcap /Users/anika/Desktop/CSE406/experiments/results/p1_baseline.pcap
```

## P2 — real ICMP reference (ground truth)

```bash
multipass exec cse406-lab -- bash -c "cp /home/ubuntu/CSE406/experiments/p2_icmp_reference.sh /home/ubuntu/experiments/ && chmod +x /home/ubuntu/experiments/p2_icmp_reference.sh"
multipass exec cse406-lab -- sudo bash /home/ubuntu/experiments/p2_icmp_reference.sh 55555   # closed port

multipass transfer cse406-lab:/home/ubuntu/experiments/results/p2_icmp_reference.pcap /Users/anika/Desktop/CSE406/experiments/results/p2_icmp_reference.pcap
```

## P3 — live state retrieval + packet crafting

Needs a live client<->server TCP connection for the attacker to sniff. Start
a persistent, idle listener (do NOT flood data — see disk-space warning
above) then trigger a short connection from the client:

```bash
# Sync build_packets.py into the VM
multipass exec cse406-lab -- bash -c "mkdir -p /home/ubuntu/attacks && cp /home/ubuntu/CSE406/attacks/build_packets.py /home/ubuntu/attacks/"

# 1. Persistent idle listener on the server (safe: -k accepts repeat connections, no data flood)
multipass exec cse406-lab -- sudo bash -c "nohup ip netns exec server ncat -k -l 9999 -o /dev/null > /tmp/server_ncat.log 2>&1 & echo pid=\$!"

# 2. Run the attacker's live capture + packet builder in the background...
multipass exec cse406-lab -- sudo bash -c "nohup ip netns exec attacker python3 /home/ubuntu/attacks/build_packets.py --count 5 --timeout 12 > /tmp/build_packets_out.log 2>&1 & echo pid=\$!"

# 3. ...then immediately trigger one short client connection to generate a SYN to sniff
multipass exec cse406-lab -- sudo bash -c "ip netns exec client bash -c 'printf ping-data\\\\n | ncat -w3 10.0.0.2 9999'"

# 4. Check the result
multipass exec cse406-lab -- cat /tmp/build_packets_out.log

# Cleanup
multipass exec cse406-lab -- sudo pkill -f "ncat -k -l 9999"
multipass exec cse406-lab -- sudo rm -f /tmp/server_ncat.log /tmp/build_packets_out.log
```

**Important correction found during P3/P4 testing:** the design doc's own
Section 3.2/3.3 packet tables have the *embedded* IP/TCP header backwards.
ICMP errors are always delivered to the original sender of the embedded
packet (outer destination == embedded source) — a receiving host can only
match a socket where the embedded header looks like something *it* sent.
To kill the SERVER's socket, the embedded packet must claim
`src=SERVER dst=CLIENT` (not `src=CLIENT dst=SERVER` as the table states),
and the embedded seq must come from the SERVER's own send sequence space
(sniff server->client segments, not client->server). `build_packets.py`
and `inject_reset.py` implement the corrected direction — see the
docstring at the top of `attacks/build_packets.py` for the full reasoning.

## P4 — reset experiment (two scenarios)

```bash
multipass exec cse406-lab -- bash -c "
cp /home/ubuntu/CSE406/attacks/build_packets.py /home/ubuntu/attacks/build_packets.py
cp /home/ubuntu/CSE406/attacks/inject_reset.py /home/ubuntu/attacks/inject_reset.py
cp /home/ubuntu/CSE406/experiments/p4_reset_experiment.sh /home/ubuntu/experiments/p4_reset_experiment.sh
cp /home/ubuntu/CSE406/experiments/recverr_server.py /home/ubuntu/experiments/recverr_server.py
chmod +x /home/ubuntu/attacks/inject_reset.py /home/ubuntu/experiments/p4_reset_experiment.sh /home/ubuntu/experiments/recverr_server.py
"

multipass exec cse406-lab -- sudo bash /home/ubuntu/experiments/p4_reset_experiment.sh   # [ncat_port] [recverr_port], default 9999/9998

multipass transfer cse406-lab:/home/ubuntu/experiments/results/p4_ncat.pcap /Users/anika/Desktop/CSE406/experiments/results/p4_ncat.pcap
multipass transfer cse406-lab:/home/ubuntu/experiments/results/p4_recverr.pcap /Users/anika/Desktop/CSE406/experiments/results/p4_recverr.pcap
```

**Real finding, not a bug in the script:** against a plain `ncat`-held
connection, the reset packet arrives and passes the in-window seq check,
but the connection **survives** — Linux's `tcp_v4_err()` downgrades this
RFC 1122 hard error to a non-fatal `sk_err_soft` for any ESTABLISHED
socket unless the application set `IP_RECVERR`. `recverr_server.py` is a
positive control that does set it, confirming the crafted packet is
otherwise correct: that connection reliably dies
(`ConnectionRefusedError`, socket moves to `FIN-WAIT-2`). Worth citing as
an additional defense in Section 6 of the report.

**Cleanup between runs** (the script's own trap normally handles this,
but if a run is interrupted):
```bash
multipass exec cse406-lab -- sudo pkill -f "tail -f /dev/null"
multipass exec cse406-lab -- sudo pkill -f ncat
multipass exec cse406-lab -- sudo pkill -f recverr_server
multipass exec cse406-lab -- sudo pkill -f tcpdump
```

## P5 — PMTU (throughput reduction) experiment

```bash
multipass exec cse406-lab -- bash -c "
cp /home/ubuntu/CSE406/attacks/build_packets.py /home/ubuntu/attacks/build_packets.py
cp /home/ubuntu/CSE406/attacks/inject_pmtu.py /home/ubuntu/attacks/inject_pmtu.py
cp /home/ubuntu/CSE406/experiments/p5_pmtu_experiment.sh /home/ubuntu/experiments/p5_pmtu_experiment.sh
chmod +x /home/ubuntu/attacks/inject_pmtu.py /home/ubuntu/experiments/p5_pmtu_experiment.sh
"

multipass exec cse406-lab -- sudo bash /home/ubuntu/experiments/p5_pmtu_experiment.sh   # [duration] [inject_at] [mtu], default 60/15/576
# Takes ~60-75s: iperf3 runs for `duration` seconds, the attack injects at `inject_at`.

multipass transfer cse406-lab:/home/ubuntu/experiments/results/p5_pmtu.json /Users/anika/Desktop/CSE406/experiments/results/p5_pmtu.json
multipass transfer cse406-lab:/home/ubuntu/experiments/results/p5_pmtu.pcap /Users/anika/Desktop/CSE406/experiments/results/p5_pmtu.pcap
```

**Second real finding, distinct from P4's:** a single sniffed sequence
number — which worked fine for the *idle* reset-attack connection — fails
almost every time here, because this is an *active* bulk transfer. The
kernel's in-window check (`between(seq, tp->snd_una, tp->snd_nxt)`) runs
for Type 3/Code 4 too, not just the reset's Type 3/Code 3, and for a fast
connection that window is only `cwnd*mss` wide (~100-150KB observed here)
and slides forward at the full transfer rate — a value sniffed via
tcpdump is almost always already ACKed and out of window by the time it
gets through Python + Scapy's `send()`. `inject_pmtu.py` fixes this by
**spraying** ~300 candidate sequence numbers in steps smaller than the
in-flight window (confirmed via `TcpExt:OutOfWindowIcmps` in
`/proc/net/netstat` — a single guess reliably increments it; a spray
reliably lands one inside the window). This is the standard technique
from Watson's original blind-injection attacks, and matches the design
doc's own "sampled seq numbers" (plural) wording.

Confirmed results (60s run, inject at 15s, MTU=576):
- `ss -tin` on the client: `mss:1448 pmtu:1500` before -> `mss:524
  pmtu:576` after the very first spray round
- `ip route get 10.0.0.2` on the client: shows `mtu 576` in the cache
  after the attack
- TCP payload size per segment (from tcpdump text output, not Scapy —
  see below): avg 1448 bytes before -> avg ~542 bytes after
- iperf3 throughput: ~96 Mbps before -> ~89 Mbps after (roughly 5-7%
  across repeated runs) — modest but real and consistent, since our
  100mbit `tc` shaping (see `setup_topology.sh`) is a byte-rate limiter,
  so most of the effect comes from the *smaller* MSS spending a bigger
  fraction of each capped-rate packet on the fixed 40-byte header rather
  than from any raw bandwidth ceiling change

**Also worth noting for the report:** don't analyze the resulting pcap
with Scapy's `rdpcap()`/`PcapReader()` for anything longer than a few
seconds of bulk traffic — a 60s capture at this rate is 500K+ packets,
and Scapy's per-packet Python object overhead took 2+ minutes and once
had to be killed. `p5_pmtu_experiment.sh`'s segment-size analysis instead
parses `tcpdump`'s own text output with `awk`, which does the same job on
the same file in about 4 seconds.

**Cleanup between runs:**
```bash
multipass exec cse406-lab -- sudo pkill -f iperf3
multipass exec cse406-lab -- sudo pkill -f tcpdump
multipass exec cse406-lab -- sudo pkill -f inject_pmtu
```

## Stop the VM (state is saved to disk, resumes where it left off)

```bash
multipass stop cse406-lab
```

## Resume from previous state

```bash
multipass start cse406-lab
```

## Stop the multipass daemon entirely (frees RAM/CPU when not using any VMs)

```bash
# Stop all running VMs first
multipass stop --all

# Stop the daemon
sudo launchctl stop com.canonical.multipassd
```

## Restart the daemon later

```bash
sudo launchctl start com.canonical.multipassd
multipass start cse406-lab
```

## Full teardown (only if you want to delete the VM entirely)

```bash
multipass delete cse406-lab
multipass purge
```
