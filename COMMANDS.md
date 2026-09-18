# Command Reference

## Setup

```bash
cd /home/tirtha/CSE406
sudo bash setup_topology.sh
```

```bash
sudo ip netns list
```

---

## Attack 1 — ICMP Blind Connection-Reset

### Option A — automated

```bash
sudo bash experiments/p4_reset_experiment.sh
```

### Option B — manual (3 terminals)

**Terminal 1 — Server**
```bash
sudo ip netns exec server bash -c "tail -f /dev/null | ncat -l 9999"
```

**Terminal 2 — Attacker (start before the client connects)**
```bash
cd /home/tirtha/CSE406
sudo ip netns exec attacker python3 attacks/inject_reset.py --server-port 9999
```

**Terminal 3 — Client**
```bash
sudo ip netns exec client bash -c "tail -f /dev/null | ncat 10.0.0.2 9999"
```

**Check result**
```bash
sudo ip netns exec server ss -tn
```

**Positive control (IP_RECVERR)**

Terminal 1:
```bash
sudo ip netns exec server python3 experiments/recverr_server.py 9998
```

Terminal 2 (attacker, before client connects):
```bash
sudo ip netns exec attacker python3 attacks/inject_reset.py --server-port 9998
```

Terminal 3:
```bash
sudo ip netns exec client bash -c "tail -f /dev/null | ncat 10.0.0.2 9998"
```

### Cleanup

```bash
sudo pkill -f "tail -f /dev/null"; sudo pkill -f ncat; sudo pkill -f recverr_server; sudo pkill -f tcpdump; sudo pkill -f inject_reset.py
```

---

## Attack 2 — ICMP Blind PMTU Throughput Reduction

### Option A — automated

```bash
sudo bash experiments/p5_pmtu_experiment.sh
```

```bash
sudo bash experiments/p5_pmtu_experiment.sh 60 15 576
```

### Option B — manual (3 terminals)

**Terminal 1 — Server**
```bash
sudo ip netns exec server iperf3 -s
```

**Terminal 2 — Client**
```bash
sudo ip netns exec client iperf3 -c 10.0.0.2 -t 60 -i 5
```

**Terminal 3 — Attacker**
```bash
cd /home/tirtha/CSE406
sudo ip netns exec attacker python3 attacks/inject_pmtu.py --server-port 5201 --mtu 576 --duration 20 --interval 5
```

**Check result (any extra terminal)**
```bash
sudo ip netns exec client ss -tin | grep -E "mss|ESTAB"
```

```bash
sudo ip netns exec client ip route get 10.0.0.2
```

### Cleanup

```bash
sudo pkill -f iperf3; sudo pkill -f tcpdump; sudo pkill -f inject_pmtu
```

---

## Defense — Ingress Filtering (BCP 38)

### Automated (re-runs both attacks with the filter active)

```bash
sudo bash experiments/p7_defense_experiment.sh
```

### Manual

**Apply filter**
```bash
sudo tc qdisc add dev veth-at-br handle ffff: ingress
sudo tc filter add dev veth-at-br parent ffff: protocol ip prio 1 u32 match ip src 10.0.0.3/32 action ok
sudo tc filter add dev veth-at-br parent ffff: protocol ip prio 2 u32 match u32 0 0 action drop
```

**Re-run Attack 1 / Attack 2 commands above to observe the blocked result**

**Remove filter**
```bash
sudo tc qdisc del dev veth-at-br handle ffff: ingress
```

### Cleanup

```bash
sudo tc qdisc del dev veth-at-br handle ffff: ingress 2>/dev/null
```

---

## Defense — PMTU Cache Aging / PLPMTUD

### Manual

**Terminal 1 — Server**
```bash
sudo ip netns exec server iperf3 -s
```

**Terminal 2 — Client**
```bash
sudo ip netns exec client sysctl -w net.ipv4.tcp_mtu_probing=2
sudo ip netns exec client sysctl -w net.ipv4.route.mtu_expires=8
sudo ip netns exec client iperf3 -c 10.0.0.2 -t 60 -i 5
```

**Terminal 3 — Attacker (single shot)**
```bash
cd /home/tirtha/CSE406
sudo ip netns exec attacker python3 attacks/inject_pmtu.py --server-port 5201 --mtu 576 --duration 1
```

**Watch recovery (any extra terminal)**
```bash
sudo ip netns exec client ss -tin | grep -E "mss|ESTAB"
sudo ip netns exec client ip route get 10.0.0.2
```

**Diagnostic — force route cache flush**
```bash
sudo ip netns exec client ip route flush cache
sudo ip netns exec client ss -tin | grep -E "mss|ESTAB"
```

### Cleanup

```bash
sudo ip netns exec client sysctl -w net.ipv4.tcp_mtu_probing=1
sudo ip netns exec client sysctl -w net.ipv4.tcp_probe_interval=600
sudo ip netns exec client sysctl -w net.ipv4.route.mtu_expires=600
sudo pkill -f iperf3; sudo pkill -f inject_pmtu
```

---

## Full Teardown

```bash
sudo pkill -f "tail -f /dev/null"; sudo pkill -f ncat; sudo pkill -f recverr_server; sudo pkill -f iperf3; sudo pkill -f tcpdump; sudo pkill -f inject_reset.py; sudo pkill -f inject_pmtu.py
sudo tc qdisc del dev veth-at-br handle ffff: ingress 2>/dev/null
sudo ip netns del client
sudo ip netns del server
sudo ip netns del attacker
sudo ip link del br0
```
