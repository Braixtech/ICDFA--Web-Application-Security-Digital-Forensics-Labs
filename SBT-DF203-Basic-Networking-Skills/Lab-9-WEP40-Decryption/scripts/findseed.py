#!/usr/bin/env python3
"""Recover the WEP40 PRNG seed from the known key bytes."""
key = [0xA4, 0x3D, 0xF6, 0xF3, 0x74]
a, c, m = 0x000343FD, 0x00269EC3, 0x00FFFFFF

print("[*] Brute-forcing 2^24 seeds...")
for seed in range(1 << 24):
    x = seed
    ok = True
    for k in key:
        x = (a * x + c) & m
        if (x >> 16) != k:
            ok = False
            break
    if ok:
        print(f"[+] Seed found: {seed:06X}")
        print(f"[+] Seed bytes: {(seed >> 16) & 0xFF:02X} {(seed >> 8) & 0xFF:02X} {seed & 0xFF:02X} ??")
