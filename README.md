# ICMP Blind Connection-Reset & Blind Throughput Reduction Attack Against TCP
**CSE 406 — Computer Security Sessional**
Anika Morshed (2105068) · Diganta Saha Tirtha (2105081)

---

## Table of Contents
1. [Overview of the Project Idea](#1-overview-of-the-project-idea)
2. [Network Topology, Components, and Timing Diagram](#2-network-topology-components-and-timing-diagram)
3. [Packet Structure](#3-packet-structure)
4. [Implementation Plan](#4-implementation-plan)
5. [Expected Outcome of a Successful Attack](#5-expected-outcome-of-a-successful-attack)
6. [Defense Ideas](#6-defense-ideas)

---

## 1. Overview of the Project Idea

### 1.1 Attack 1 — ICMP Blind Connection-Reset

The attacker sends a spoofed **ICMP Type 3, Code 3** (Destination Unreachable — Port Unreachable) message addressed to the server. The ICMP payload embeds the IP and TCP headers of an existing client–server TCP connection. Because Code 3 is a **hard error** under RFC 1122, a vulnerable TCP stack will immediately abort the connection.

### 1.2 Attack 2 — ICMP Blind Throughput Reduction

The attacker sends a spoofed **ICMP Type 3, Code 4** (Fragmentation Needed, DF Set) message. Per RFC 1191, the ICMP payload includes a **Next-Hop MTU** field. If accepted by the server's TCP stack, the Path MTU (PMTU) cache is updated to the advertised (artificially small) value. The TCP sender then reduces its Maximum Segment Size (MSS), sending smaller segments and achieving lower throughput.

---

## 2. Network Topology, Components, and Timing Diagram

### 2.1 Network Topology

The lab uses three Linux network namespaces connected via a software bridge, all running inside a single Ubuntu 22.04 virtual machine.




### 2.2 Components

| Node     | IP Address | Namespace | Role                                              |
|----------|------------|-----------|---------------------------------------------------|
| Client   | 10.0.0.1   | client    | Holds the TCP connection being targeted           |
| Server   | 10.0.0.2   | server    | Receives spoofed ICMP; TCP state is observed here |
| Attacker | 10.0.0.3   | attacker  | Crafts and injects forged ICMP packets            |
| Bridge   | —          | root      | br0 connects all three veth pairs                 |



---

## 3. Packet Structure

### 3.1 ICMP Error Packet Structure (RFC 792)

Both attack packets follow the same outer structure defined by RFC 792. An ICMP error message is carried inside an IP datagram. Its payload must contain the **original IP header plus the first 8 bytes** of the original IP datagram (i.e., the first 8 bytes of the TCP header).

| Layer / Header        | Details / Fields                                      |
|-----------------------|-------------------------------------------------------|
| Ethernet Header       | src=attacker MAC, dst=bridge MAC                      |
| IP Header             | src=forged (Server/Router), dst=Client, proto=1 (ICMP)|
| ICMP Header           | Type / Code / Checksum / Type-specific field          |
| Embedded IP Header    | src=Client, dst=Server, proto=6                       |
| Embedded TCP Header (8 B) | sport, dport, seq#                               |

### 3.2 Attack 1 — ICMP Type 3, Code 3 (Connection Reset)

| Layer    | Field          | Value / Notes                                        |
|----------|----------------|------------------------------------------------------|
| Outer IP | Source IP      | 10.0.0.1 (spoofed — attacker impersonates client)   |
|          | Destination IP | 10.0.0.2 (server)                                   |
|          | Protocol       | 1 (ICMP)                                             |
| ICMP     | Type           | 3 (Destination Unreachable)                          |
|          | Code           | 3 (Port Unreachable)                                 |
|          | Unused field   | 0                                                    |
| Inner IP | Source IP      | 10.0.0.1 (original connection client IP)            |
|          | Destination IP | 10.0.0.2 (original connection server IP)            |
|          | Protocol       | 6 (TCP)                                              |
| Inner TCP (8B) | Source Port | Client ephemeral port (e.g. 43146)              |
|          | Dest Port      | Server port (9999)                                   |
|          | Seq Number     | Must fall in server's receive window                 |

### 3.3 Attack 2 — ICMP Type 3, Code 4 (PMTU Reduction)

| Layer    | Field          | Value / Notes                                        |
|----------|----------------|------------------------------------------------------|
| Outer IP | Source IP      | 10.0.0.1 (spoofed)                                  |
|          | Destination IP | 10.0.0.2                                            |
|          | Protocol       | 1 (ICMP)                                             |
| ICMP     | Type           | 3 (Destination Unreachable)                          |
|          | Code           | 4 (Fragmentation Needed, DF Set)                     |
|          | Next-Hop MTU   | Advertised small MTU (e.g. 576 bytes per RFC 1191)  |
| Inner IP | —              | Matches the live iperf3 connection's IP header       |
| Inner TCP (8B) | Source Port | Client ephemeral iperf3 port                    |
|          | Dest Port      | 5201 (iperf3)                                        |
|          | Seq Number     | Sampled from sequence space                          |

---

## 4. Implementation Plan

The implementation follows a phased approach. Each phase builds on the previous one, and no attack code is run before the infrastructure is verified.

| Phase | Goal                    | Actions                                                                                                                                                 |
|-------|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| P0    | Topology setup          | Create three network namespaces (client, server, attacker), bridge br0, and veth pairs. Configure `tc mirred` traffic mirroring. Verify with `ping` and `ip route`. |
| P1    | Baseline measurement    | Run `iperf3` client→server for 30 seconds. Record average throughput, RTT, and retransmissions. Capture with `tcpdump`.                                 |
| P2    | Real ICMP reference     | Send UDP to a closed port on server. Capture the kernel-generated ICMP Port Unreachable. Use as ground-truth for comparing Scapy output.                |
| P3    | Live State Retrieval    | From the attacker namespace, run `tcpdump` on the bridge interface to capture the client's ephemeral source port and current ACK/SEQ numbers. Parse in Python with `subprocess`/`re` and pass to the packet-crafting function. |
| P4    | Reset experiment        | Hold TCP connection with `ncat`. Inject ICMP Type 3 Code 3 packets with sampled seq numbers. Observe `ss -tn` and `tcpdump` on server.                |
| P5    | PMTU experiment         | Run `iperf3` for 60 seconds. After 15 s, inject ICMP Type 3 Code 4 (MTU=576). Check `ip route get` for PMTU change. Compare per-second throughput before and after. |
| P6    | Metrics collection      | Record: PMTU cache state, TCP segment sizes (pcap), iperf3 throughput, RTT, retransmissions.                                                           |
| P7    | Defense                 | Enable `tcp_mtu_probing=2`. Repeat P4 and P5. Record whether kernel rejects the forged ICMP messages.                                                  |

---

## 5. Expected Outcome of a Successful Attack

### 5.1 Attack 1 — Connection Reset

A successful experiment produces the following observable chain of events:

1. The spoofed ICMP Type 3 Code 3 packet is visible in the server's `tcpdump` capture.
2. The embedded sequence number falls within the server's current receive window.
3. The server's TCP stack aborts the connection (RFC 1122 hard error behavior).
4. `ss -tn | grep 9999` returns empty on the server — the socket no longer exists.
5. The `ncat` process on the client reports a broken pipe or connection reset.

### 5.2 Attack 2 — PMTU Throughput Reduction

A successful PMTU attack follows this causal chain — each step must be independently verified:

1. ICMP Type 3 Code 4 packet visible in server's `tcpdump`.
2. `ip route get 10.0.0.1` on server shows `mtu 576` (PMTU cache updated).
3. TCP segment sizes in pcap decrease from ~1460 bytes to ≤ 576 − 40 = **536 bytes**.
4. `iperf3` per-second throughput shows measurable decrease.

---

## 6. Defense Ideas

| Defense Mechanism              | Effect                                                                          |
|--------------------------------|---------------------------------------------------------------------------------|
| Sequence number validation     | Modern kernels (RFC 5961 influenced) require the embedded sequence number to be within the receive window before acting on ICMP errors. Makes blind seq-number guessing much harder. |
| Ingress filtering (BCP 38)     | Routers drop packets whose source IP does not belong to the originating network. Prevents IP spoofing at the network edge entirely. |

---

