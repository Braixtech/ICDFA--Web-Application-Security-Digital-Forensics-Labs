# 🧪 Lab 8 — DNS Spoofing Forensics

**International Cybersecurity and Digital Forensics Academy (ICDFA)**
*School of Basic Vocational Training (SVT)*

![Course](https://img.shields.io/badge/Course-SBT--DF203-blue)
![Lab](https://img.shields.io/badge/Lab-08%20DNS%20Spoofing-red)
![Student](https://img.shields.io/badge/Student-2025%2FFWSD%2F11334-informational)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![Tools](https://img.shields.io/badge/Tools-Scapy%20%7C%20TShark%20%7C%20ARP-informational)

---

## 👤 Author

| Field | Details |
|---|---|
| **Student Name** | Ibrahim Ishaku |
| **Student ID** | 2025/FWSD/11334 |
| **Programme** | Fellowship in Web Application Security & Digital Forensics |
| **Course** | SBT-DF203 — Basic Networking Skills for Digital Forensics |
| **Lab Title** | DNS Spoofing Forensics |
| **Instructor** | Aminu Idris, AMCPN |
| **Date** | 24th September, 2026 |

---

## 📌 Executive Summary

This lab investigates **DNS Spoofing** — a man-in-the-middle attack where an attacker intercepts DNS queries and returns forged responses, redirecting victims to attacker-controlled IP addresses.

**Workflow covered:**

1. Baseline documentation — legitimate DNS/ARP behaviour recorded before simulation
2. Authorized simulation preparation — instructor scripts reviewed and edited
3. Controlled event capture — bounded ARP + DNS spoofing under lab conditions
4. Forensic detection — forged-response indicators identified in the PCAP
5. Baseline-versus-spoof comparison — evidential differences documented
6. Cleanup and restoration — processes stopped, ARP cache cleared

**Key finding:** The controlled simulation demonstrated classic DNS spoofing indicators: the victim received a forged DNS response from the attacker's MAC address pointing to the replacement IP, and subsequently connected to the forged IP. DNSSEC validation and HTTPS certificate checking would detect and prevent this attack in production.

---

## 📑 Table of Contents

1. [Lab Objectives](#-lab-objectives)
2. [Tools and Environment](#-tools-and-environment)
3. [1. Introduction](#1-introduction)
4. [2. Lab Folder Structure and Evidence Preparation](#2-lab-folder-structure-and-evidence-preparation)
5. [3. Part A — Document the Baseline](#3-part-a--document-the-baseline)
6. [4. Part B — Prepare the Authorized Simulation](#4-part-b--prepare-the-authorized-simulation)
7. [5. Part C — Capture the Controlled Spoofing Event](#5-part-c--capture-the-controlled-spoofing-event)
8. [6. Part D — Detect DNS Spoofing Indicators](#6-part-d--detect-dns-spoofing-indicators)
9. [7. Part E — Baseline-versus-Spoof Comparison](#7-part-e--baseline-versus-spoof-comparison)
10. [8. Part F — Cleanup and Verification](#8-part-f--cleanup-and-verification)
11. [9. Detection and Defensive Recommendations](#9-detection-and-defensive-recommendations)
12. [10. Required Forensic Findings](#10-required-forensic-findings)
13. [11. Conclusion](#11-conclusion)
14. [12. References](#12-references)
15. [13. Appendix — Screenshot Reference List](#13-appendix--screenshot-reference-list)

---

## 🎯 Lab Objectives

- Explain the ARP/MITM/DNS-spoofing relationship
- Capture normal DNS and ARP baseline evidence
- Detect conflicting answers and abnormal responder MAC/IP information
- Correlate DNS response with subsequent connection
- Distinguish spoofing from legitimate DNS variation
- Document cleanup and defences

---

## 🛠️ Tools and Environment

| Category | Tool / Resource | Purpose |
|---|---|---|
| Operating System | Kali Linux | Analyst VM |
| Victim System | Linux network namespace | Receives spoofed DNS |
| Web Server | Apache2 on analyst VM | Hosts harmless training page |
| Capture Tools | Wireshark / TShark | Capture DNS, ARP, and HTTP traffic |
| Packet Tools | Python3-Scapy | Craft and send spoofed packets |
| DNS Tool | dig | Query legitimate and spoofed DNS |
| Hasher | sha256sum | Evidence integrity |
| Test Domain | portal.icdfa.test | Reserved training domain |

### Lab Network

| Role | Device | IP |
|---|---|---|
| Analyst VM | Kali Linux | 192.168.56.2 |
| Victim | Namespace `victim` | 192.168.56.20 |
| Trusted DNS | legit_dns.py on Kali | 192.168.56.10 |
| Test Domain | portal.icdfa.test | 192.168.56.100 (legit) / 192.168.56.2 (forged) |

---

## 1. Introduction

Network forensics involves capturing, recording, and analyzing network traffic to investigate security incidents and gather digital evidence. This lab focuses on **DNS Spoofing** — a man-in-the-middle attack where an attacker intercepts DNS queries and returns forged responses, redirecting victims to malicious IP addresses.

### Key Concepts

| Concept | Description |
|---|---|
| DNS Spoofing | Forging DNS responses to redirect victims |
| ARP Poisoning | Manipulating ARP tables to become man-in-the-middle |
| MITM Positioning | Intercepting traffic between victim and gateway |
| Forged Response Indicators | Abnormal MAC, conflicting answers, timing anomalies |
| DNSSEC | DNS Security Extensions providing origin authentication |
| HTTPS Certificate Validation | Detecting forged DNS through TLS verification |

---

## 2. Lab Folder Structure and Evidence Preparation

### 2.1 Create the Lab Folder Structure

```bash
mkdir -p ~/SBT-DF203-Lab8/{evidence,working,exported,reports,screenshots,scripts}
cd ~/SBT-DF203-Lab8
