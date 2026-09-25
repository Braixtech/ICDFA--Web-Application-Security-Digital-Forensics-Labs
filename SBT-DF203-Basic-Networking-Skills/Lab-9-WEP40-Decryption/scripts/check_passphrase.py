#!/usr/bin/env python3
"""Verify that the recovered passphrase matches the CTF SHA-1 prefix constraint."""
import hashlib

# Recovered passphrase from the CTF challenge
passphrase = "cgwepkeyxz"
expected_prefix = "ff7b948953ac"

sha1_hash = hashlib.sha1(passphrase.encode()).hexdigest()
print(f"[*] Candidate passphrase: {passphrase}")
print(f"[*] SHA-1 hash:          {sha1_hash}")
print(f"[*] Expected prefix:     {expected_prefix}")
print(f"[*] Match:               {'✅ YES' if sha1_hash.startswith(expected_prefix) else '❌ NO'}")
