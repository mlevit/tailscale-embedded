#!/usr/bin/env python3
"""Writes test/stun_vectors.h: the STUN responses from Tailscale's own net/stun/stun_test.go, for stun_test.c.

Usage: python3 tools/stun_vectors.py stun_test.go > test/stun_vectors.h

The source isn't ours: responseTests in tailscale/tailscale's net/stun/stun_test.go (BSD-3-Clause), real responses
captured from Google, sipgate, powervoip, pion, stuntman (IPv6) and others, with the transaction ID, address and port
Go's ParseResponse must read from each. Each case is copied byte for byte, so a rerun on the same file writes the same
header.
"""
import ipaddress
import re
import sys

text = open(sys.argv[1]).read()
block = text[text.index("var responseTests"):text.index("func TestParseResponse")]


def go_bytes(s):
    return bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", s))


cases = []
for m in re.finditer(r"\{\s*name:\s*\"([^\"]+)\",(.*?)wantPort:\s*(\d+),\s*\}", block, re.S):
    name, body, port = m.group(1), m.group(2), int(m.group(3))
    hexm = re.search(r"hex\.DecodeString\(\"([0-9a-f]+)\"\)", body)
    if hexm:
        data = bytes.fromhex(hexm.group(1))
    else:
        data = go_bytes(body[body.index("data:"):body.index("wantTID:")])
    tidpart = body[body.index("wantTID:"):body.index("wantAddr:")]
    tid = bytes(int(x, 0) for x in re.findall(r"0x[0-9a-fA-F]{2}|\b\d+\b", tidpart.split("{", 1)[1]))
    addrpart = body[body.index("wantAddr:"):]
    a4 = re.search(r"AddrFrom4\(\[4\]byte\{([^}]*)\}\)", addrpart)
    if a4:
        addr = ipaddress.ip_address(bytes(int(x) for x in a4.group(1).split(",")))
    else:
        addr = ipaddress.ip_address(re.search(r"MustParseAddr\(\"([^\"]+)\"\)", addrpart).group(1))
    assert len(tid) == 12, name
    cases.append((name, data, tid, addr, port))


def c(b):
    return "{" + ", ".join("0x%02x" % x for x in b) + "}"


print("// Written by tools/stun_vectors.py from tailscale's net/stun/stun_test.go (responseTests). Don't edit.")
print("typedef struct {")
print("    const char *name;")
print("    const uint8_t *data;")
print("    size_t len;")
print("    uint8_t tid[12];")
print("    uint8_t ip[16]; // IPv4 as ::ffff:a.b.c.d")
print("    uint16_t port;")
print("} stun_vector_t;")
for i, (name, data, tid, addr, port) in enumerate(cases):
    print("static const uint8_t stun_data_%d[] = %s;" % (i, c(data)))
print("static const stun_vector_t stun_vectors[] = {")
for i, (name, data, tid, addr, port) in enumerate(cases):
    ip16 = addr.packed if addr.version == 6 else b"\x00" * 10 + b"\xff\xff" + addr.packed
    print("    {\"%s\", stun_data_%d, %d, %s,\n     %s, %d}," % (name, i, len(data), c(tid), c(ip16), port))
print("};")
