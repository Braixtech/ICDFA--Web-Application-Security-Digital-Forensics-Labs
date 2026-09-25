#!/usr/bin/env python3
"""Clean DNS responder - produces well-formed responses"""
import socket, struct

LEGIT_IP = "192.168.56.100"
BIND_ADDR = "192.168.56.10"
BIND_PORT = 53

def parse_question(data):
    """Parse qname, qtype, qclass from offset 12"""
    parts = []
    offset = 12
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        parts.append(data[offset+1:offset+1+length])
        offset += 1 + length
    qname = b".".join(parts) + b"."
    qtype = struct.unpack('>H', data[offset:offset+2])[0]
    qclass = struct.unpack('>H', data[offset+2:offset+4])[0]
    q_end = offset + 4
    return qname, qtype, qclass, q_end

def build_response(query):
    """Build a clean DNS response with one A record."""
    txn_id = query[0:2]
    # Flags: QR=1, AA=1, RD=1, RA=1  ->  0x85 0x80
    flags = b'\x85\x80'
    # QD=1, AN=1, NS=0, AR=0
    counts = b'\x00\x01\x00\x01\x00\x00\x00\x00'
    # Question section (echo)
    qname, qtype, qclass, q_end = parse_question(query)
    question = query[12:q_end]
    # Answer: use compression pointer to offset 12
    ans_name = b'\xc0\x0c'
    ans_type = struct.pack('>H', 1)      # A
    ans_class = struct.pack('>H', 1)     # IN
    ans_ttl = struct.pack('>I', 300)
    ans_rdlen = struct.pack('>H', 4)
    ans_rdata = socket.inet_aton(LEGIT_IP)
    answer = ans_name + ans_type + ans_class + ans_ttl + ans_rdlen + ans_rdata
    return txn_id + flags + counts + question + answer

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((BIND_ADDR, BIND_PORT))
print(f"[legit-dns] Bound UDP {BIND_ADDR}:{BIND_PORT}")

while True:
    try:
        data, addr = sock.recvfrom(1024)
        if len(data) < 12:
            continue
        try:
            qname, qtype, qclass, q_end = parse_question(data)
        except Exception as e:
            print(f"[legit-dns] Parse error: {e}")
            continue
        print(f"[legit-dns] Query from {addr[0]}:{addr[1]} -> {qname.decode(errors='replace')}")
        if b"portal.icdfa.test" in qname:
            resp = build_response(data)
            sock.sendto(resp, addr)
            print(f"[legit-dns] Replied with {LEGIT_IP}")
    except Exception as e:
        print(f"[legit-dns] Error: {e}")
