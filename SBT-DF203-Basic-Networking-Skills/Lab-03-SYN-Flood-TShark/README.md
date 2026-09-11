I can't fetch that GitHub URL directly, but based on the structure of your **README.txt** (from Clement Modebe's repository) that you shared earlier, I understand the format you want. Below is your **Lab 3 report** restructured in that professional GitHub style — with **Executive Summary**, **Lab Objectives**, and **Tools and Resources Used** added, and everything ready to copy-paste.

---

# 🧪 Lab 3 — SYN Flood Pattern Investigation Using TShark

**International Cybersecurity and Digital Forensics Academy (ICDFA)**  
**School of Basic Vocational Training (SVT)**

---

## 👤 Author

| Field | Value |
|-------|-------|
| **Student Name** | Ibrahim Ishaku |
| **Student ID** | 2025/FWSD/11334 |
| **Programme** | Fellowship in Web Application Security & Digital Forensics |
| **Course** | SBT-DF203 — Basic Networking Skills for Digital Forensics |
| **Lab Title** | SYN Flood Pattern Investigation Using TShark |
| **Instructor** | Aminu Idris, AMCPN |
| **Date** | 11th September, 2026 |

---

## 📌 Executive Summary

This lab investigates **TCP SYN Flood patterns** — a form of Denial-of-Service (DoS) attack where an attacker sends repeated SYN packets without completing the TCP three-way handshake. Using a local Apache web server and the loopback interface (`lo`), a **normal HTTP handshake baseline** was first established and captured. A **bounded Scapy simulation** was then executed to generate four controlled SYN packets, reproducing the suspicious packet pattern in a safe, authorized training environment.

Traffic was captured with **TShark** and analyzed using display filters to isolate SYN, SYN-ACK, ACK, and RST packets. Key forensic indicators — including **incomplete handshakes**, **multiple ephemeral source ports**, and **RST responses** — were identified and quantified. All evidence was preserved with **SHA-256 hashes** and a **chain-of-custody worksheet** to maintain integrity.

**Key finding:** The capture proves a *pattern* of incomplete TCP handshakes was generated, but it does **not** prove service denial or malicious intent. A real SYN flood is defined by **scale, rate, persistence, and service impact** — four training packets are not a DoS event.

---

## 📑 Table of Contents

1. [Executive Summary](#-executive-summary)
2. [Lab Objectives](#-lab-objectives)
3. [Tools and Resources Used](#-tools-and-resources-used)
4. [Introduction](#1-introduction)
5. [Lab Folder Structure and Evidence Preparation](#2-lab-folder-structure-and-evidence-preparation)
6. [Part A — Establish a Normal Handshake Baseline](#3-part-a--establish-a-normal-handshake-baseline)
7. [Part B — Conduct the Bounded Loopback Simulation](#4-part-b--conduct-the-bounded-loopback-simulation)
8. [Part C — Identify SYN Indicators with TShark](#5-part-c--identify-syn-indicators-with-tshark)
9. [Part D — Quantify and Correlate the Activity](#6-part-d--quantify-and-correlate-the-activity)
10. [Part E — Compare Normal and Suspicious Sessions](#7-part-e--compare-normal-and-suspicious-sessions)
11. [Required Forensic Findings](#8-required-forensic-findings)
12. [Detection and Mitigation Recommendations](#9-detection-and-mitigation-recommendations)
13. [Conclusion](#10-conclusion)
14. [References](#11-references)
15. [Appendix — Screenshot Reference List](#12-appendix--screenshot-reference-list)

---

## 🎯 Lab Objectives

Upon completion of this lab, the following objectives were achieved:

1. **Understand TCP Three-Way Handshake** — Analyze the SYN, SYN-ACK, ACK sequence that establishes a reliable connection.
2. **Identify Half-Open Connections** — Detect incomplete handshakes where the final ACK is never sent.
3. **Recognize SYN Flood Attack Patterns** — Understand resource exhaustion caused by many incomplete handshakes.
4. **Apply TShark Display Filters** — Isolate SYN, SYN-ACK, ACK, and RST packets for forensic analysis.
5. **Conduct a Bounded Simulation** — Use Scapy to generate a controlled four-packet SYN simulation for training purposes.
6. **Preserve Digital Evidence** — Apply cryptographic hashing (SHA-256) and chain-of-custody documentation.
7. **Quantify Suspicious Activity** — Count SYNs, unique source ports, and correlate with expert analysis.
8. **Distinguish Pattern from Proof** — Differentiate between packet pattern evidence and proof of service denial.
9. **Document Detection & Mitigation** — Recommend controls for SYN flood detection and mitigation.
10. **Prepare a Professional Forensic Report** — Document all findings in a reproducible, professional format.

---

## 🛠️ Tools and Resources Used

| Category | Tool / Resource | Purpose |
|----------|----------------|---------|
| **Packet Capture** | TShark (CLI) | Capture and analyze network traffic on the `lo` interface |
| **Packet Analysis** | Wireshark | Graphical packet inspection and verification |
| **Traffic Generation** | Scapy (Python 3) | Craft and send bounded SYN packets for simulation |
| **Web Server** | Apache2 | Local HTTP service on port 80 for baseline traffic |
| **Operating System** | Kali Linux (Forensics VM) | Lab environment for capture and analysis |
| **Virtualization** | Oracle VirtualBox | Host environment for the Kali Linux VM |
| **Hashing** | sha256sum | Generate SHA-256 hashes for evidence integrity |
| **Scripting** | Bash, Python 3 | Automation, filtering, and simulation scripts |
| **Capture Format** | pcapng | Standard packet capture file format |
| **Documentation** | Markdown, TSV | Report generation and tabular analysis outputs |
| **Training Capture** | GitHub — frankwuxu/digital-forensics-lab | Optional external SYN flood training capture |
| **Course Materials** | ICDFA SBT-DF203 Module 2 & Lab 3 Manual | Foundational theory and lab instructions |

**Lab Environment:**

- **Interface:** Loopback (`lo`)
- **Target:** `127.0.0.1:80` (Local Apache service)
- **Capture Duration:** ~15 seconds (baseline), ~0.01 seconds (bounded SYN burst)
- **Evidence Files:** `normal_http.pcapng`, `bounded_syn_activity.pcapng`, `mySYNFloodCapture.pcap`

---

## 1. Introduction

Network forensics involves the capture, recording, and analysis of network traffic to investigate security incidents and gather digital evidence. This lab focuses on **TCP SYN Flood patterns**, a common type of Denial-of-Service (DoS) attack where an attacker sends repeated SYN packets without completing the TCP three-way handshake.

### Key Concepts Covered

| Concept | Description |
|---------|-------------|
| **TCP Three-Way Handshake** | SYN, SYN-ACK, ACK sequence that establishes a reliable connection |
| **Half-Open Connections** | Incomplete handshakes where the final ACK is never sent |
| **SYN Flood Attack** | Resource exhaustion caused by many incomplete handshakes |
| **TShark Filtering** | Using display filters to isolate SYN, SYN-ACK, ACK, and RST packets |
| **Bounded Simulation** | A controlled four-packet Scapy simulation for training purposes |

The lab uses a local Apache web server and the loopback interface (`lo`) to capture traffic. A normal HTTP handshake baseline is established first, followed by a bounded SYN simulation to identify suspicious patterns.

---

## 2. Lab Folder Structure and Evidence Preparation

### 2.1 Create the Lab Folder Structure

```bash
mkdir -p ~/SBT-DF203-Lab3/{evidence,working,exported,reports,screenshots,scripts}
cd ~/SBT-DF203-Lab3
pwd
find . -maxdepth 1 -type d -print
```

**Directory Structure:**

| Directory | Purpose |
|-----------|---------|
| `evidence/` | Original capture files (preserved) |
| `working/` | Verified working copies for analysis |
| `exported/` | Exported objects from captures |
| `reports/` | Analysis outputs (TSV, TXT) |
| `screenshots/` | Lab evidence screenshots |
| `scripts/` | Scapy simulation scripts |

### 2.2 Install Required Tools

```bash
sudo apt update
sudo apt install -y apache2 tshark wireshark python3-scapy
sudo systemctl enable --now apache2
```

*Figure 1.2: Required tools installed and verified.*

### 2.3 Download the Training Capture (Optional)

**Command Attempted (Initial Failure):**

```bash
wget -O evidence/mySYNFloodCapture.pcap \
https://raw.githubusercontent.com/frankwuxu/digital-forensics-lab/main/Illegal_Possession_Images/lab_files/SYN_Flood/mySYNFloodCapture.pcap
sha256sum evidence/mySYNFloodCapture.pcap | tee reports/syn_capture_sha256.txt
```

**Error Encountered:**

```
evidence/mySYNFloodCapture.pcap: No such file or directory
tee: reports/syn_capture_sha256.txt: No such file or directory
sha256sum: evidence/mySYNFloodCapture.pcap: No such file or directory
```

**Root Cause:** The `wget` command failed because the `evidence/` and `reports/` directories did not exist at the time the command was run.

**Manual Download Alternative:** The file was manually downloaded from the GitHub repository and placed in the `evidence/` directory.

```bash
ls -lh evidence/mySYNFloodCapture.pcap
file evidence/mySYNFloodCapture.pcap
sha256sum evidence/mySYNFloodCapture.pcap | tee reports/syn_capture_sha256.txt
```

*Figure 1.3: Evidence file details and SHA-256 hash.*

| Property | Value |
|----------|-------|
| **Filename** | mySYNFloodCapture.pcap |
| **Source** | GitHub — frankwuxu/digital-forensics-lab |
| **Download Method** | Manual browser download |
| **File Size** | 255.1 KiB (261,265 bytes) |
| **File Type** | pcapng capture file - version 1.0 |
| **Permissions** | -rw-rw-r-- (ibrahim:ibrahim) |

**SHA-256 Hash:**

| File | SHA-256 Hash |
|------|--------------|
| `evidence/mySYNFloodCapture.pcap` | `14765b029a72e9c41dd8b4d32f5b1d2c7d9efe0f084949151f183a39baa55f5` |

### 2.4 Mini Chain-of-Custody / Evidence Worksheet

| Field | Value |
|-------|-------|
| **Case/Lab Identifier** | SBT-DF203-Lab3-Ibrahim-Ishaku |
| **Trainee Name** | Ibrahim Ishaku |
| **Date and Time Started** | 11th September, 2026 |
| **Evidence File Name(s)** | mySYNFloodCapture.pcap, bounded_syn_activity.pcapng |
| **Source or Generation Method** | GitHub training capture, Local Apache capture on lo interface, Scapy simulation |
| **Original (mySYNFloodCapture.pcap)** | `14765b029a72e9c41dd8b4d32f5b1d2c7d9efe0f084949151f183a39baa55f5` |
| **Original (normal_http.pcapng)** | SHA-256 [Hash calculated after capture] |
| **Original (bounded_syn_activity.pcapng)** | `4d387247414ee7cd0719503f775f731294eba5e640685f253b91dd2ccce5bbc4` |

**Chain of Custody Notes:**

| # | Activity | Date/Time | Performed By | Purpose |
|---|----------|-----------|--------------|---------|
| 1 | Created lab folder structure | 11th September, 2026 | Ibrahim Ishaku | Evidence organization |
| 2 | Installed required tools | 11th September, 2026 | Ibrahim Ishaku | Environment preparation |
| 3 | Downloaded training capture | 11th September, 2026 | Ibrahim Ishaku | Evidence acquisition |
| 4 | Generated SHA-256 hash | 11th September, 2026 | Ibrahim Ishaku | Integrity verification |
| 5 | Captured normal HTTP baseline | 11th September, 2026 | Ibrahim Ishaku | Baseline evidence generation |
| 6 | Generated bounded SYN activity | 11th September, 2026 | Ibrahim Ishaku | Suspicious traffic simulation |
| 7 | Preserved captures with verified copies | 11th September, 2026 | Ibrahim Ishaku | Evidence preservation |

---

## 3. Part A — Establish a Normal Handshake Baseline

### 3.1 Capture Normal HTTP Handshake

```bash
sudo tshark -i lo -f 'tcp port 80' -a duration:15 -w evidence/normal_http.pcapng &
sleep 2
curl --no-keepalive http://127.0.0.1/ > /dev/null
wait
```

### 3.2 Extract Normal Handshake Flags

```bash
tshark -r evidence/normal_http.pcapng -Y 'tcp.flags.syn==1 || tcp.flags.fin==1' -T fields \
-e frame.number -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags \
| tee reports/normal_handshake_flags.tsv
```

*Figure 2.1: Normal handshake in the baseline capture.*

| Frame | Time | Source | Source Port | Destination | Dest Port | Flags | Interpretation |
|-------|------|--------|-------------|-------------|-----------|-------|----------------|
| 1 | 2026-09-11T10:23:59.342785877-0400 | 127.0.0.1 | 54680 | 127.0.0.1 | 80 | 0x0002 | SYN — Client initiates connection |
| 2 | 2026-09-11T10:23:59.342805485-0400 | 127.0.0.1 | 80 | 127.0.0.1 | 54680 | 0x0012 | SYN, ACK — Server acknowledges |
| 3 | 2026-09-11T10:23:59.3428... | 127.0.0.1 | 54680 | 127.0.0.1 | 80 | 0x0010 | ACK — Connection established |
| 8 | 2026-09-11T10:23:59.346112157-0400 | 127.0.0.1 | 54680 | 127.0.0.1 | 80 | 0x0011 | FIN, ACK — Connection termination |
| 9 | 2026-09-11T10:23:59.347725087-0400 | 127.0.0.1 | 80 | 127.0.0.1 | 54680 | 0x0011 | FIN, ACK — Server close |

**TCP Flag Values Reference:**

| Flag | Value | Binary | Meaning |
|------|-------|--------|---------|
| SYN | 0x0002 | 000010 | SYN |
| SYN, ACK | 0x0012 | 010010 | SYN, ACK |
| ACK | 0x0010 | 010000 | ACK |
| FIN, ACK | 0x0011 | 010001 | FIN, ACK |

**Key Observations:**

| # | Observation | Technical Implication |
|---|-------------|----------------------|
| i. | Complete three-way handshake observed | SYN (Frame 1), SYN-ACK (Frame 2), ACK (Frame 3) sequence fully captured |
| ii. | Connection established after third packet | Client and server ready for data transfer |
| iii. | HTTP data transferred successfully | curl retrieved 10,703 bytes from the Apache server |
| iv. | Connection properly terminated | FIN/ACK sequence (Frames 8 and 9) shows graceful closure |
| v. | Ephemeral client port 54680 | OS-assigned port for this connection |
| vi. | No RST packets observed | Normal, expected behavior for a clean connection |

**Normal Handshake Sequence Diagram:**

```
Client (127.0.0.1:54680)                    Server (127.0.0.1:80)
        |                                            |
        | ---------- SYN (Seq=0) ------------------> |  Frame 1 (0x0002)
        |                                            |
        | <-------- SYN, ACK (Seq=0, Ack=1) -------- |  Frame 2 (0x0012)
        |                                            |
        | ---------- ACK (Seq=1, Ack=1) ----------> |  Frame 3 (0x0010)
        |                                            |
        | ============ CONNECTION ESTABLISHED ====== |
        |                                            |
        | ---------- HTTP GET / -------------------> |  HTTP Request
        |                                            |
        | <-------- HTTP 200 OK -------------------- |  HTTP Response (10,703 bytes)
        |                                            |
        | ---------- FIN, ACK ---------------------> |  Frame 8 (0x0011)
        |                                            |
        | <-------- FIN, ACK ----------------------- |  Frame 9 (0x0011)
        |                                            |
        | ---------- ACK --------------------------> |  Final ACK
        |                                            |
```

---

## 4. Part B — Conduct the Bounded Loopback Simulation

### 4.1 Create the Scapy Simulation Script

```python
# scripts/syn_probe_lab.py
from scapy.all import IP, TCP, RandShort, send

TARGET = '127.0.0.1'
PORT = 80
COUNT = 4

packets = [IP(dst=TARGET)/TCP(sport=RandShort(), dport=PORT, flags='S') for _ in range(COUNT)]
send(packets, verbose=False)
print(f'Sent {COUNT} authorized training SYN packets to {TARGET}:{PORT}')
```

*Figure 3.1: Bounded Scapy script showing target and count.*

### 4.2 Capture the Bounded SYN Activity

**Terminal 1 (Capture):**

```bash
sudo tshark -i lo -f 'tcp port 80' -c 20 -w evidence/bounded_syn_activity.pcapng
```

**Terminal 2 (Simulation):**

```bash
sudo python3 scripts/syn_probe_lab.py
```

*Figure 3.2: Bounded simulation execution.*

### 4.3 Preserve the Capture

```bash
cd ~/SBT-DF203-Lab3
sudo chown ibrahim:ibrahim evidence/bounded_syn_activity.pcapng
sudo chmod 644 evidence/bounded_syn_activity.pcapng
cp --preserve=timestamps evidence/bounded_syn_activity.pcapng working/bounded_syn_activity_working.pcapng
sha256sum evidence/bounded_syn_activity.pcapng working/bounded_syn_activity_working.pcapng | tee reports/bounded_capture_hashes.txt
```

**Verification:**

```bash
ls -lh evidence/bounded_syn_activity.pcapng
file evidence/bounded_syn_activity.pcapng
```

*Figure 3.3: Bounded capture hashes.*

**SHA-256 Hashes:**

| File | SHA-256 Hash |
|------|--------------|
| `evidence/bounded_syn_activity.pcapng` | `4d387247414ee7cd0719503f775f731294eba5e640685f253b91dd2ccce5bbc4` |
| `working/bounded_syn_activity_working.pcapng` | `4d387247414ee7cd0719503f775f731294eba5e640685f253b91dd2ccce5bbc4` |

**Integrity Verification:**

| # | Verification Check | Result |
|---|-------------------|--------|
| 1 | Hashes match | ✅ Confirmed |
| 2 | Working copy is exact duplicate | ✅ Confirmed |
| 3 | No data corruption during copy | ✅ Confirmed |
| 4 | Evidence properly preserved | ✅ Confirmed |

---

## 5. Part C — Identify SYN Indicators with TShark

### 5.1 Extract Initial SYN Packets

```bash
PCAP=working/bounded_syn_activity_working.pcapng

tshark -r "$PCAP" -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields \
-e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.seq \
| tee reports/initial_syn.tsv
```

*Figure 4.1: Initial SYN packet list.*

| Frame | Time (Epoch) | Source | Source Port | Destination | Dest Port | Seq # |
|-------|-------------|--------|-------------|-------------|-----------|-------|
| 1 | 1789138563.383492161 | 127.0.0.1 | 11123 | 127.0.0.1 | 80 | 0 |
| 4 | 1789138563.386292193 | 127.0.0.1 | 17231 | 127.0.0.1 | 80 | 0 |
| 7 | 1789138563.389629973 | 127.0.0.1 | 52980 | 127.0.0.1 | 80 | 0 |
| 10 | 1789138563.392453289 | 127.0.0.1 | 61395 | 127.0.0.1 | 80 | 0 |

### 5.2 Extract SYN-ACK Responses

```bash
tshark -r "$PCAP" -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 1' -T fields \
-e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.ack \
| tee reports/syn_ack_responses.tsv
```

*Figure 4.2: SYN-ACK response list.*

### 5.3 Extract ACK and RST Candidates

```bash
tshark -r "$PCAP" -Y 'tcp.flags.reset == 1 || (tcp.flags.ack == 1 && tcp.len == 0)' -T fields \
-e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags \
| tee reports/ack_reset_candidates.tsv
```

*Figure 4.3: Any ACK or RST behaviour.*

| Frame | Time (Epoch) | Source | Source Port | Destination | Dest Port | Flags | Meaning |
|-------|-------------|--------|-------------|-------------|-----------|-------|---------|
| 2 | 1789138563.383547888 | 127.0.0.1 | 80 | 127.0.0.1 | 11123 | 0x0012 | SYN, ACK |
| 3 | 1789138563.383553580 | 127.0.0.1 | 11123 | 127.0.0.1 | 80 | 0x0004 | RST |
| 5 | 1789138563.386314273 | 127.0.0.1 | 80 | 127.0.0.1 | 17231 | 0x0012 | SYN, ACK |
| 6 | 1789138563.386318550 | 127.0.0.1 | 17231 | 127.0.0.1 | 80 | 0x0004 | RST |
| 8 | 1789138563.389639951 | 127.0.0.1 | 80 | 127.0.0.1 | 52980 | 0x0012 | SYN, ACK |
| 9 | 1789138563.390256301 | 127.0.0.1 | 52980 | 127.0.0.1 | 80 | 0x0004 | RST |
| 11 | 1789138563.392465361 | 127.0.0.1 | 80 | 127.0.0.1 | 61395 | 0x0012 | SYN, ACK |
| 12 | 1789138563.393280167 | 127.0.0.1 | 61395 | 127.0.0.1 | 80 | 0x0004 | RST |

> **Key Observation:** The client sent RST packets (0x0004) in response to the SYN-ACK packets. This is because the Scapy script sent raw SYN packets without a corresponding socket, so the OS did not recognize the SYN-ACK responses and reset the connections.

---

## 6. Part D — Quantify and Correlate the Activity

### 6.1 Counts by Source and Destination

```bash
tshark -r "$PCAP" -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields \
-e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -nr \
| tee reports/syn_counts_by_pair.txt
```

*Figure 4.4: Counts by source/destination.*

**SYN Counts by Pair:**

| Count | Source | Destination | Dest Port |
|-------|--------|-------------|-----------|
| 4 | 127.0.0.1 | 127.0.0.1 | 80 |

### 6.2 Unique Client Source Ports

```bash
tshark -r "$PCAP" -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e tcp.srcport \
| sort -n | uniq | tee reports/unique_syn_source_ports.txt
```

*Figure 4.5: Unique source ports.*

**Unique Source Ports:**

| Source Port |
|-------------|
| 11123 |
| 17231 |
| 52980 |
| 61395 |

**Total Unique Ports:** 4

### 6.3 Expert Information and TCP Analysis

```bash
tshark -r "$PCAP" -q -z expert | tee reports/expert_info.txt
```

*Figure 4.6: Expert information.*

**Expert Analysis Summary:**

| Category | Frequency | Group | Protocol | Summary |
|----------|-----------|-------|----------|---------|
| Warning | 4 | Sequence | TCP | Connection reset (RST) |
| Notes | 4 | Protocol | TCP | The SYN packet does not contain a SACK PERM option |
| Chats | 4 | Sequence | TCP | Connection establish request (SYN): server port 80 |
| Chats | 4 | Sequence | TCP | Connection establish (SYN+ACK): server port 80 |

```bash
tshark -r "$PCAP" -Y 'tcp.analysis.retransmission || tcp.analysis.lost_segment || tcp.analysis.duplicate_ack' \
-T fields -e frame.number -e frame.time -e _ws.col.Info | tee reports/tcp_analysis_events.tsv
```

---

## 7. Part E — Compare Normal and Suspicious Sessions

### 7.1 Normal vs. Bounded SYN Activity Comparison

| Indicator | Normal Session (HTTP) | Bounded Activity (SYN) | Forensic Meaning |
|-----------|----------------------|------------------------|------------------|
| Initial SYN count | 1 | 4 | Multiple SYNs from same source |
| SYN-ACK count | 1 | 4 | Server responded to each SYN |
| Completed handshakes | 1 | 0 | No final ACK sent |
| Unique client source ports | 1 | 4 | Random ephemeral ports |
| HTTP request present? | Yes | No | No application data |
| RST packets | 0 | 4 | Connections rejected by client OS |
| Observed duration | ~0.005 s | ~0.01 s | Brief burst vs. sustained |

*Figure 5.1: Normal-versus-suspicious comparison table.*

| Aspect | Assessment |
|--------|------------|
| **What the capture proves** | A pattern of incomplete TCP handshakes (SYN, SYN-ACK, RST) was generated |
| **What the capture does NOT prove** | Service denial, sustained attack, or malicious intent |
| **Why the bounded simulation is not a flood** | Four packets is insufficient to exhaust server resources |
| **Evidence required for flood conclusion** | High volume, sustained rate, service impact, corroborating logs |

> **Key Note from Lab Manual:** A real SYN flood is defined by **scale, rate, persistence, and service impact**. Four training packets are not a denial-of-service event; they reproduce the packet pattern in a safe way so that analysts can learn the indicators.

---

## 8. Required Forensic Findings

| Finding | Value/Observation |
|---------|-------------------|
| Normal handshake baseline | Complete SYN, SYN-ACK, ACK sequence captured |
| Bounded simulation | 4 SYN packets sent to 127.0.0.1:80 |
| Initial SYN count | 4 |
| SYN-ACK count | 4 |
| Completed handshakes | 0 |
| Unique source ports | 4 (11123, 17231, 52980, 61395) |
| RST packets | 4 |
| HTTP requests present | No |
| Capture duration | ~0.01 seconds |
| Evidence hashes | SHA-256 recorded for all capture files |

---

## 9. Detection and Mitigation Recommendations

### 9.1 Detection Controls

| Control | Description |
|---------|-------------|
| **SYN-to-Completed-Handshake Ratio** | Alert when initial SYN count significantly exceeds completed handshakes per source |
| **SYN Backlog Monitoring** | Monitor SYN-RECEIVED queue growth and exhaustion |
| **Rate-Based Detection** | Alert on SYN rates exceeding baseline thresholds |

### 9.2 Mitigation Controls

| Control | Description |
|---------|-------------|
| **SYN Cookies** | Enable SYN cookies to avoid allocating resources for incomplete connections |
| **Backlog Tuning** | Adjust TCP backlog and timeout parameters appropriately |
| **Upstream Rate Limiting** | Implement rate limiting at network edge |
| **DDoS Protection** | Deploy dedicated DDoS mitigation services where appropriate |

### 9.3 Forensic Recommendations

| Recommendation | Rationale |
|----------------|-----------|
| **Retain Full Packet Capture** | Preserve evidence for detailed analysis |
| **Synchronize System Clocks** | Ensure accurate timeline reconstruction |
| **Correlate with Logs** | Cross-reference with web server, firewall, and load balancer logs |
| **Document Chain of Custody** | Maintain evidence integrity throughout investigation |

---

## 10. Conclusion

This lab provided practical experience in SYN Flood pattern investigation using TShark. I successfully:

1. Created a local Apache webpage and verified the web service.
2. Established a normal HTTP handshake baseline capturing SYN, SYN-ACK, and ACK packets.
3. Developed and executed a bounded Scapy simulation sending four SYN packets to the local Apache service.
4. Captured the bounded SYN activity and preserved evidence with SHA-256 hashes.
5. Extracted initial SYN packets, SYN-ACK responses, and ACK/RST candidates using TShark filters.
6. Quantified the activity through SYN counts, unique source ports, and expert analysis.
7. Compared normal and suspicious sessions to identify incomplete-handshake indicators.
8. Assessed the forensic significance of the evidence, distinguishing packet patterns from proof of service denial.
9. Documented detection and mitigation recommendations for SYN flood activity.
10. Prepared a comprehensive network forensic report documenting all findings.

These skills are essential for any digital forensics professional, as they provide the foundation for network traffic analysis, incident investigation, and evidence documentation.

---

## 11. References

1. ICDFA. (2026). *SBT-DF203 — Module 2: HTTP, tshark, SYN Flood — Course Materials.*
2. ICDFA. (2026). *SBT-DF203 Lab 3 — SYN Flood Pattern Investigation Using TShark — Official Lab Manual.*
3. Wireshark Documentation. (2026). *Wireshark User Guide.* https://www.wireshark.org/docs/
4. TShark Documentation. (2026). *TShark — Terminal-based Wireshark.* https://www.wireshark.org/docs/man-pages/tshark.html
5. RFC 793. (1981). *Transmission Control Protocol.* https://tools.ietf.org/html/rfc793
6. RFC 4987. (2007). *TCP SYN Flooding Attacks and Common Mitigations.* https://tools.ietf.org/html/rfc4987

---

## 12. Appendix — Screenshot Reference List

| Figure | Description |
|--------|-------------|
| Figure 1.1 | Lab folder structure created successfully |
| Figure 1.2 | Required tools installed and verified |
| Figure 1.3 | Evidence file details and SHA-256 hash |
| Figure 2.1 | Normal handshake in the baseline capture |
| Figure 3.1 | Bounded Scapy script showing target and count |
| Figure 3.2 | Bounded simulation execution |
| Figure 3.3 | Bounded capture hashes |
| Figure 4.1 | Initial SYN packet list |
| Figure 4.2 | SYN-ACK response list |
| Figure 4.3 | ACK/RST candidates |
| Figure 4.4 | Counts by source/destination |
| Figure 4.5 | Unique source ports |
| Figure 4.6 | Expert information |
| Figure 5.1 | Normal-versus-suspicious comparison table |

*(All screenshots were captured during the practical lab and are submitted.)*

---

## 📄 Declaration

I, **Ibrahim Ishaku**, confirm that this lab report is based on my own practical work conducted in the ICDFA lab environment. All packet captures, traffic analysis, TCP handshake examination, Scapy simulation, and quantitative analysis tasks are my own original work. I confirm that the original packet capture was preserved and that all analysis was performed on verified working copies with cryptographic hashes.

**Signature:** ______________________  
**Date:** 11th September, 2026

---

## 🎓 Academic Notice

This lab report was completed as part of the **Fellowship in Web Application Security & Digital Forensics** at the **International Cybersecurity and Digital Forensics Academy (ICDFA)**.

- All work is the author's original submission for academic purposes.
- Content is shared for **educational and portfolio use only**.
- All labs were performed in controlled environments using test data and virtual machines.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

**End of Lab Report**
