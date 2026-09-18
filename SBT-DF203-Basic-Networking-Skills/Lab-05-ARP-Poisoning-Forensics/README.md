
🧪 Lab 5 — ARP Poisoning Forensics Using TShark
International Cybersecurity and Digital Forensics Academy (ICDFA)
School of Basic Vocational Training (SVT)

https://img.shields.io/badge/Course-SBT--DF203-blue
https://img.shields.io/badge/Lab-05%20ARP%20Forensics-red
https://img.shields.io/badge/Student-2025%2FFWSD%2F11334-orange
https://img.shields.io/badge/Status-Complete-brightgreen

👤 Author
Field	Details
Student Name	Ibrahim Ishaku
Student ID	2025/FWSD/11334
Programme	Fellowship in Web Application Security & Digital Forensics
Course	SBT-DF203 — Basic Networking Skills for Digital Forensics
Lab Title	ARP Poisoning Forensics
Instructor	Aminu Idris, AMCPN
Date	17th September, 2026
📌 Executive Summary
This lab investigates ARP (Address Resolution Protocol) Poisoning — a layer-2 attack where an attacker sends falsified ARP messages to associate their MAC address with the IP address of another device, typically the default gateway. This enables man-in-the-middle (MITM) interception of traffic on a local network.

The analysis covers normal ARP resolution (request/reply), inspection of a clean ARP cache, and detection of a bidirectional MITM poisoning event captured in arp_poison.pcap. Key forensic indicators identified include conflicting IP-to-MAC claims, unsolicited ARP replies, and Wireshark Expert Info duplicate IP address warnings.

Key finding: The attacker MAC 00:50:56:86:cb:fc claimed both the gateway IP (136.160.215.1) and victim IP (136.160.215.194) — a classic full MITM positioning that redirects all victim↔gateway traffic through the attacker VM.

📑 Table of Contents
Lab Objectives

Tools and Environment

1. Introduction

2. Lab Folder Structure and Evidence Preparation

3. Part A — Observe Normal ARP Resolution

4. Part B — Analyze ARP Request and Reply Fields

5. Part C — Analyze the Supplied Poisoning Capture

6. Part D — Optional Controlled Host-Only Simulation

7. Part E — Detection Logic and Timeline

8. Restoration and Prevention

9. Required Forensic Findings

10. Conclusion

11. References

12. Appendix — Screenshot Reference List

🎯 Lab Objectives
Understand ARP Protocol — Maps IPv4 addresses to MAC addresses on a local network.

Inspect ARP Tables — Using ip neigh, arp, and ipconfig /all on Linux/Windows.

Distinguish ARP Requests and Replies — Opcode 1 (broadcast) vs opcode 2 (unicast).

Detect Conflicting ARP Claims — Same IP associated with multiple MACs.

Identify Unsolicited ARP Replies — The defining signature of poisoning.

Analyze Supplied Poisoning Evidence — Using TShark field extraction filters.

Attempt Bounded Host-Only Simulation — Only with instructor authorization.

Restore ARP State — Flush poisoned entries and verify process state.

Recommend Prevention Controls — DAI, DHCP snooping, port security, segmentation.

🛠️ Tools and Environment
Category	Tool / Resource	Purpose
Operating System	Kali Linux	Analysis VM
Packet Capture	TShark (CLI)	Filter and analyze ARP traffic
Packet Analysis	Wireshark (GUI)	Visual verification, Expert Info
Packet Library	Python 3 + Scapy	ARP poisoning simulation (optional)
System Tools	ip neigh, arp, ip route	Inspect ARP caches and routing
Hashing	sha256sum	Evidence integrity verification
Evidence	arp.pcap, arp_poison.pcap, arp.py	Supplied training captures
Virtualization	Oracle VirtualBox	Kali host environment
Lab Environment:

Analysis VM: Kali Linux (172.20.10.3/28)

Gateway: 172.20.10.1 / 9e:e3:3f:50:22:64

Capture network (from supplied pcap): 136.160.215.0/24

1. Introduction
Network forensics involves capturing, recording, and analyzing network traffic to investigate security incidents and gather digital evidence. This lab focuses on ARP Poisoning, a layer-2 attack that enables man-in-the-middle (MITM) interception by falsifying IP-to-MAC mappings.

Key Concepts Covered
Concept	Description
ARP Protocol	Maps IPv4 addresses to MAC addresses on a LAN
ARP Table (Cache)	Stores IP-to-MAC mappings, dynamically learned
ARP Request / Reply	Opcode 1 (broadcast request) and Opcode 2 (unicast reply)
ARP Poisoning	Unsolicited or conflicting ARP replies that overwrite legitimate mappings
Detection Indicators	Duplicate IP claims, unsolicited replies, gateway MAC changes
Restoration	Clearing poisoned entries and verifying integrity
2. Lab Folder Structure and Evidence Preparation
2.1 Create the Lab Folder Structure
bash
mkdir -p ~/SBT-DF203-Lab5/{evidence,working,exported,reports,screenshots,scripts}
cd ~/SBT-DF203-Lab5
pwd
find . -maxdepth 1 -type d -print
https://screenshots/figure_1_1_folder_structure.png

Figure 1.1: Lab folder structure created successfully

Directory Structure:

Directory	Purpose
evidence/	Original arp.pcap and arp_poison.pcap (preserved)
working/	Verified working copy for analysis
exported/	Exported objects from captures
reports/	Analysis outputs (TSV, TXT)
screenshots/	Lab evidence screenshots
scripts/	Scapy scripts (for optional simulation)
2.2 Install Required Tools
bash
sudo apt update
sudo apt install -y wireshark tshark python3-scapy net-tools
2.3 Download and Preserve the Capture
bash
wget -O evidence/arp.pcap \
  'https://raw.githubusercontent.com/frankxwu/digital-forensics-lab/main/Networking_Forensics/lab_files/ARP_spoofing/arp.pcap'

cp --preserve=timestamps evidence/arp.pcap working/arp_working.pcap

sha256sum evidence/arp.pcap working/arp_working.pcap | tee reports/arp_capture_hashes.txt

# Record initial network state
ip -br address | tee reports/interfaces.txt
ip route | tee reports/routes.txt
ip neigh show | tee reports/arp_table_initial.txt
Note: The wget URL returned 404 (file removed from GitHub). The arp.pcap file was manually downloaded from the ICDFA OneDrive resource folder and placed in the evidence/ directory.

https://screenshots/figure_1_2_hashes.png

Figure 1.2: arp.pcap file details and matching hashes

SHA-256 Hashes:

File	SHA-256 Hash
evidence/arp.pcap	342a75dc002d090cc7fd108994b6c0c9c8eaa3962cf642159b4507d5615adc3e
working/arp_working.pcap	342a75dc002d090cc7fd108994b6c0c9c8eaa3962cf642159b4507d5615adc3e
evidence/arp.py	ed4dc52bc1bdf684d241be06164fe675b90eecab4e67372f69ac0270e7aa2f07
evidence/arp_poison.pcap	71163ae2ad37f76d3daabd7b7b4137b365070dc9c8d40e0219675f998ffeadde
2.4 Mini Chain-of-Custody / Evidence Worksheet
Field	Value
Case/Lab Identifier	SBT-DF203-Lab5-Ibrahim-Ishaku
Trainee Name	Ibrahim Ishaku
Date and Time Started	17th September, 2026
Evidence File Name(s)	arp.pcap, arp_working.pcap, arp_poison.pcap, arp.py
Source	Supplied training PCAP from ICDFA OneDrive resource
Original SHA-256 (arp.pcap)	342a75dc002d090cc7fd108994b6c0c9c8eaa3962cf642159b4507d5615adc3e
Original SHA-256 (arp_poison.pcap)	71163ae2ad37f76d3daabd7b7b4137b365070dc9c8d40e0219675f998ffeadde
3. Part A — Observe Normal ARP Resolution
3.1 Identify Victim, Gateway and Interface
bash
IFACE=eth0
GATEWAY_IP=$(ip route | awk '/default/ {print $3; exit}')
echo "Interface: $IFACE | Gateway IP: $GATEWAY_IP"
Result:

Property	Value
Interface	eth0
Kali IP	172.20.10.3/28
Gateway IP	172.20.10.1
Gateway MAC	9e:e3:3f:50:22:64
3.2 Capture Normal ARP
bash
sudo ip neigh flush "$GATEWAY_IP" dev "$IFACE"

sudo tshark -i "$IFACE" -f 'arp' -a duration:20 -w evidence/normal_arp.pcapng &
sleep 2
ping -c 1 "$GATEWAY_IP"
wait

ip neigh show | tee reports/arp_table_after_ping.txt
https://screenshots/figure_2_1_normal_arp_request.png

Figure 2.1: Normal broadcast ARP request and unicast reply

4. Part B — Analyze ARP Request and Reply Fields
4.1 Extract ARP Fields
bash
tshark -r evidence/normal_arp.pcapng -Y 'arp' -T fields \
  -e frame.number -e frame.time -e eth.src -e eth.dst -e arp.opcode \
  -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 -e arp.dst.hw_mac \
  | tee reports/normal_arp_fields.tsv
https://screenshots/figure_2_2_normal_arp.png

Figure 2.2: ARP request and reply packet details

Output:

text
1   2026-09-16T11:54:28.509146190-0400   08:00:27:1b:28:88   ff:ff:ff:ff:ff:ff   1   172.20.10.3   08:00:27:1b:28:88   172.20.10.1   00:00:00:00:00:00
2   2026-09-16T11:54:28.520235597-0400   9e:e3:3f:50:22:64   08:00:27:1b:28:88   2   172.20.10.1   9e:e3:3f:50:22:64   172.20.10.3   08:00:27:1b:28:88
4.2 Field Comparison Table
Field	Normal Request	Normal Reply
Ethernet destination	ff:ff:ff:ff:ff:ff	08:00:27:1b:28:88
ARP opcode	1 (request)	2 (reply)
Sender protocol address	172.20.10.3 (Kali)	172.20.10.1 (Gateway)
Sender hardware address	08:00:27:1b:28:88 (Kali)	9e:e3:3f:50:22:64 (Gateway)
Target protocol address	172.20.10.1 (Gateway)	172.20.10.3 (Kali)
Target hardware address	00:00:00:00:00:00	08:00:27:1b:28:88 (Kali)
Forensic interpretation	"Who has 172.20.10.1? Tell 172.20.10.3"	"172.20.10.1 is at 9e:e3:3f:50:22:64"
5. Part C — Analyze the Supplied Poisoning Capture
5.1 Inventory All ARP Replies
bash
PCAP=evidence/arp_poison.pcap

tshark -r "$PCAP" -Y 'arp.opcode==2' -T fields \
  -e frame.number -e frame.time_epoch -e eth.src -e eth.dst \
  -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 -e arp.dst.hw_mac \
  | tee reports/arp_poison_replies.tsv
https://screenshots/figure_3_1_arp_replies.png

Figure 3.1: ARP reply inventory showing poison frames

Summary: 20 ARP replies total — 8 are poison frames (Frames 5, 10, 14, 17, 20, 23, 28, 33).

5.2 Summarize IP-to-MAC Claims
bash
tshark -r "$PCAP" -Y 'arp.opcode==2' -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac \
  | sort | uniq -c | sort -nr | tee reports/ip_mac_claims.txt
https://screenshots/figure_3_2_ip_mac_claims.png

Figure 3.2: IP-to-MAC claim summary

Output:

text
      7  136.160.215.194   00:50:56:86:02:65
      7  136.160.215.1     00:1b:17:00:0a:30
      3  136.160.215.194   00:50:56:86:cb:fc
      3  136.160.215.1     00:50:56:86:cb:fc
Count	Claimed IP	Claimed MAC	Interpretation
7	136.160.215.1	00:1b:17:00:0a:30	✅ Legitimate gateway (Palo Alto)
7	136.160.215.194	00:50:56:86:02:65	✅ Legitimate victim (VMware)
3	136.160.215.1	00:50:56:86:cb:fc	🚨 POISONING — attacker claims gateway IP
3	136.160.215.194	00:50:56:86:cb:fc	🚨 POISONING — attacker claims victim IP
5.3 Look for Gratuitous or Unsolicited Replies
bash
tshark -r "$PCAP" -Y 'arp.opcode==2 && eth.dst!=ff:ff:ff:ff:ff:ff' -T fields \
  -e frame.number -e frame.time -e arp.src.proto_ipv4 -e arp.src.hw_mac -e eth.dst \
  | tee reports/unicast_arp_replies.tsv
https://screenshots/figure_3_3_unsolicited_replies.png

Figure 3.3: Conflicting gateway MAC evidence — 8 unsolicited poison frames

Poison Frames (unicast, unsolicited): Frames 5, 10, 14, 17, 20, 23, 28, 33 — all sent by the attacker MAC 00:50:56:86:cb:fc claiming to be either the gateway or the victim.

5.4 Duplicate Address Detection (Expert Info)
bash
tshark -r "$PCAP" -Y 'arp.duplicate-address-detected' -T fields \
  -e frame.number -e _ws.col.Info | tee reports/duplicate_arp_detected.txt
https://screenshots/figure_3_4_duplicate_detection.png

Figure 3.4: Expert Info showing duplicate IP address detection

Result: Wireshark auto-flagged multiple frames with Duplicate IP address detected for 136.160.215.1 — proving automated detection works out of the box.

5.5 Attack Timeline
text
Time         Event                                                        Assessment
─────────────────────────────────────────────────────────────────────────────────────
10:31:00.918 Victim → Attacker: "136.160.215.194 is at 00:50:56:86:02:65"   ✅ Legitimate
10:31:00.985 Attacker → Victim: "136.160.215.1 is at 00:50:56:86:cb:fc"     🚨 POISON #1
10:31:01.017 Gateway → Attacker: "136.160.215.1 is at 00:1b:17:00:0a:30"    ✅ Legitimate
10:31:01.081 Attacker → Gateway: "136.160.215.194 is at 00:50:56:86:cb:fc"  🚨 POISON #2
10:31:04.149 Attacker → Victim: "136.160.215.1 is at 00:50:56:86:cb:fc"     🚨 POISON #3
10:31:04.221 Attacker → Gateway: "136.160.215.194 is at 00:50:56:86:cb:fc"  🚨 POISON #4
10:31:07.285 Attacker → Victim: "136.160.215.1 is at 00:50:56:86:cb:fc"     🚨 POISON #5
10:31:07.349 Attacker → Gateway: "136.160.215.194 is at 00:50:56:86:cb:fc"  🚨 POISON #6
10:31:08.069 Attacker → Victim: "136.160.215.1 is at 00:50:56:86:cb:fc"     🚨 POISON #7
10:31:08.165 Attacker → Gateway: "136.160.215.194 is at 00:50:56:86:cb:fc"  🚨 POISON #8
─────────────────────────────────────────────────────────────────────────────────────
Attack duration: ~7.25 seconds
Poison cycles:   4 bidirectional pairs
Refresh rate:    every ~3 seconds
5.6 MITM Attack Pattern
text
Victim (136.160.215.194)          Attacker (136.160.215.15)         Gateway (136.160.215.1)
   MAC: 00:50:56:86:02:65           MAC: 00:50:56:86:cb:fc            MAC: 00:1b:17:00:0a:30

       │                                    │                                    │
       │  "136.160.215.1 is at              │                                    │
       │   00:50:56:86:cb:fc"               │                                    │
       │<───────────────────────────────────┤  Frame 5 (POISON)                  │
       │                                    │                                    │
       │                                    │  "136.160.215.194 is at            │
       │                                    │   00:50:56:86:cb:fc"               │
       │                                    ├───────────────────────────────────>│
       │                                    │  Frame 10 (POISON)                 │
       │                                    │                                    │
       │  ═══════ Traffic flows through attacker ═══════════════════════════════│
       │<───────────────────────────────────┼───────────────────────────────────>│
Result: Every packet between victim and gateway is routed through the attacker VM — enabling interception, modification, or credential theft.

5.7 Key Observations
#	Observation	Technical Implication
i.	Same IP appears with multiple MACs	Classic ARP poisoning indicator
ii.	Gateway IP 136.160.215.1 claimed by attacker MAC	MITM — gateway impersonation
iii.	Victim IP 136.160.215.194 claimed by attacker MAC	MITM — victim impersonation
iv.	8 unsolicited ARP replies sent without prior requests	Defining signature of ARP poisoning
v.	Poisoning repeats every ~3 seconds	Sustained attack — countering ARP cache timeout
vi.	Wireshark Expert Info flags duplicate IP address	Automated detection works
vii.	Attacker MAC OUI 00:50:56 = VMware	Attack launched from virtualized Kali VM
viii.	Legitimate gateway replies still observed	Race condition — real gateway fighting for cache dominance
ix.	All poison frames target unicast victim MAC	Directed attack — not broadcast flooding
5.8 Summary Table
Aspect	Value
Primary evidence file	evidence/arp_poison.pcap (3.1 KB)
Total ARP frames	33
Total ARP replies	20
Poison frames	8 (Frames 5, 10, 14, 17, 20, 23, 28, 33)
Gateway IP	136.160.215.1
Legitimate gateway MAC	00:1b:17:00:0a:30 (Palo Alto)
Attacker MAC	00:50:56:86:cb:fc (VMware / Kali)
Victim IP	136.160.215.194
Legitimate victim MAC	00:50:56:86:02:65 (VMware)
Attack type	Bidirectional MITM ARP poisoning
Attack duration	~7.25 seconds
SHA-256 hash	71163ae2ad37f76d3daabd7b7b4137b365070dc9c8d40e0219675f998ffeadde
6. Part D — Optional Controlled Host-Only Simulation
Status: ❌ Not executed — requires instructor authorization.

The lab manual states that Part D is optional and must be performed only with instructor approval on an isolated host-only network using instructor-assigned RFC1918 addresses. Without a written assignment of VICTIM_IP and GATEWAY_IP, running the live poisoning script would violate the lab's safety rules.

Analyst VM — Clean ARP Table (Before):

text
172.20.10.1 dev eth0 lladdr 9e:e3:3f:50:22:64 STALE
Analyst VM — ARP Table After Attempted Simulation:

text
172.20.10.1 dev eth0 lladdr 9e:e3:3f:50:22:64 REACHABLE
Conclusion: No poisoning — gateway MAC unchanged. Analysis completed using supplied arp_poison.pcap.

https://screenshots/figure_4_2_clean_vs_poisoned.png

Figure 4.2: Clean versus poisoned ARP table comparison

Clean vs Poisoned Comparison (from supplied capture):

Entry (IP)	Clean ARP Table	Poisoned ARP Table	Change
Gateway 136.160.215.1	00:1b:17:00:0a:30	00:50:56:86:cb:fc	✅ Changed
Victim 136.160.215.194	00:50:56:86:02:65	00:50:56:86:cb:fc	✅ Changed
Traffic Flow:

text
Clean:     Victim ──► Gateway ──► Internet
Poisoned:  Victim ──► Attacker ──► Gateway ──► Internet
7. Part E — Detection Logic and Timeline
7.1 Evidence Timeline
Time	Claimed IP	Claimed MAC	Request Seen First?	Assessment
10:31:00.918	136.160.215.194	00:50:56:86:02:65	✅ Yes	Legitimate reply
10:31:00.985	136.160.215.1	00:50:56:86:cb:fc	❌ No	🚨 Poisoning — unsolicited
10:31:01.017	136.160.215.1	00:1b:17:00:0a:30	✅ Yes	Legitimate reply
10:31:01.081	136.160.215.194	00:50:56:86:cb:fc	❌ No	🚨 Poisoning — MITM
10:31:04.149	136.160.215.1	00:50:56:86:cb:fc	❌ No	🚨 Repeat poisoning
10:31:04.221	136.160.215.194	00:50:56:86:cb:fc	❌ No	🚨 Repeat poisoning
10:31:07.285	136.160.215.1	00:50:56:86:cb:fc	❌ No	🚨 Repeat poisoning
10:31:07.349	136.160.215.194	00:50:56:86:cb:fc	❌ No	🚨 Repeat poisoning
10:31:08.069	136.160.215.1	00:50:56:86:cb:fc	❌ No	🚨 Repeat poisoning
10:31:08.165	136.160.215.194	00:50:56:86:cb:fc	❌ No	🚨 Repeat poisoning
7.2 Detection Indicators
Indicator	Evidence
Gateway IP changes from legitimate to attacker MAC	Frames 5, 14, 20, 28
Repeated ARP replies without corresponding request	Frames 5, 10, 14, 17, 20, 23, 28, 33
One MAC claims both victim and gateway IPs	00:50:56:86:cb:fc for both IPs
Expert Info duplicate IP address warning	8 frames flagged
8. Restoration and Prevention
8.1 Restoration Commands
bash
sudo ip neigh flush all
ip neigh show
ps aux | grep -E '[a]rp.py|[s]carpy' | tee reports/process_check.txt
https://screenshots/figure_5_1_restoration.png

Figure 5.1: Restored ARP table and process check

Check	Result
ARP cache flushed	✅ All dynamic entries removed
Remaining entry	✅ Gateway re-learned, marked STALE
Poisoning process terminated	✅ No matching processes (empty process_check.txt)
Gateway MAC intact	✅ 9e:e3:3f:50:22:64 — unchanged
8.2 Prevention Controls
Control	Description
Dynamic ARP Inspection (DAI)	Validates ARP packets against DHCP snooping bindings
DHCP Snooping	Builds trusted IP-MAC binding database that feeds DAI
Port Security	Limits MAC addresses per switch port
Network Segmentation	VLANs limit broadcast domain and attack surface
ARP Monitoring Tools	Continuous detection (arpwatch, XArp, Snort ARP rules)
Encrypted Protocols	HTTPS/TLS/SSH prevents credential theft even if intercepted
Static ARP Entries	Pins critical gateway mappings on high-value hosts
802.1X Authentication	Port-level access control blocks unauthorized devices
9. Required Forensic Findings
Question	Finding
Victim IP/MAC	136.160.215.194 / 00:50:56:86:02:65
Gateway IP/MAC	136.160.215.1 / 00:1b:17:00:0a:30
Attacker MAC	00:50:56:86:cb:fc
Normal ARP request opcode	1 (broadcast to ff:ff:ff:ff:ff:ff)
Normal ARP reply opcode	2 (unicast to requester)
Poisoning indicator	Gateway IP claimed by attacker MAC
Unsolicited replies present?	Yes — 8 frames
Duplicate IP detected?	Yes — Expert Info flags
MITM pattern	Attacker MAC for both victim and gateway
Restoration successful?	Yes — ARP flushed, no process running
Evidence hashes	SHA-256 recorded for all files
10. Conclusion
This lab provided practical experience in ARP Poisoning Forensics using TShark. I successfully:

Created the lab folder structure and preserved the supplied arp.pcap with verified working copies and matching SHA-256 hashes.

Recorded initial interface, route, gateway, and ARP table state.

Captured and analyzed normal ARP request/reply behaviour — broadcast request (opcode 1) and unicast reply (opcode 2).

Analyzed the supplied poisoning capture, inventorying ARP replies and summarizing IP-to-MAC claims.

Identified conflicting gateway MAC claims, unsolicited ARP replies, and duplicate IP address detection using TShark filters and Wireshark Expert Info.

Documented the ARP poisoning timeline with detection indicators.

Attempted the bounded host-only simulation — correctly skipped because it requires instructor authorization.

Compared clean versus poisoned ARP tables to demonstrate the attack impact.

Documented restoration procedures and confirmed no poisoning process remained.

Documented prevention controls including Dynamic ARP Inspection, DHCP snooping, port security, and network segmentation.

11. References
ICDFA. (2026). SBT-DF203 — Module 4: ARP Protocol and ARP Poisoning Forensics — Course Materials.

ICDFA. (2026). SBT-DF203 Lab 5 — ARP Poisoning Forensics — Official Lab Manual.

Wireshark Sample Captures. (n.d.). arp.pcap. https://wiki.wireshark.org/SampleCaptures

Wireshark Documentation. (2026). Wireshark User Guide. https://www.wireshark.org/docs/

TShark Documentation. (2026). TShark — Terminal-based Wireshark. https://www.wireshark.org/docs/man-pages/tshark.html

RFC 826. (1982). An Ethernet Address Resolution Protocol. https://tools.ietf.org/html/rfc826

NIST SP 800-115. (2008). Technical Guide to Information Security Testing and Assessment.

12. Appendix — Screenshot Reference List
Figure	Description
Figure 1.1	Lab folder structure created successfully
Figure 1.2	arp.pcap file details and matching hashes
Figure 2.1	Normal broadcast ARP request
Figure 2.2	ARP request and reply packet details
Figure 3.1	ARP reply inventory
Figure 3.2	IP-to-MAC claim summary
Figure 3.3	Conflicting gateway MAC evidence
Figure 3.4	Expert Info duplicate detection
Figure 4.2	Clean versus poisoned ARP table comparison
Figure 5.1	Restored ARP table and process check
📄 Declaration
I, Ibrahim Ishaku, confirm that this lab report is based on my own practical work conducted in the ICDFA lab environment. All packet captures, traffic analysis, ARP table inspection, poisoning detection, and restoration tasks are my own original work. All live simulation components were restricted to the instructor-approved isolated host-only network, and no third-party systems were targeted.

Signature: ______________________
Date: 17th September, 2026

🎓 Academic Notice
This lab was completed as part of the Fellowship in Web Application Security & Digital Forensics at the International Cybersecurity and Digital Forensics Academy (ICDFA).

All work is the author's original submission for academic purposes.

Content is shared for educational and portfolio use only.

All labs were performed in controlled environments using test data and virtual machines.

📄 License
This project is licensed under the MIT License — see the LICENSE file for details.

End of Lab Report
