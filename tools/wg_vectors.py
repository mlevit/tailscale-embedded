#!/usr/bin/env python3
"""Writes test/wg_vectors.h: WireGuard handshake, transport and cookie vectors for wg_test.c.

Usage: uv run --with cryptography==50.0.2 --with pynacl==1.5.0 python3 tools/wg_vectors.py > test/wg_vectors.h

An independent reference, written from the WireGuard paper (section 5.4, "Protocol & Cryptography") rather than from
wireguard-go, on other libraries: X25519 and ChaCha20-Poly1305 from `cryptography` (OpenSSL), BLAKE2s from hashlib,
XChaCha20-Poly1305 from PyNaCl (libsodium). Every key, ephemeral, index and timestamp comes from a fixed seed, so a
rerun writes the same file. The initiation's mac2 is zero (no cookie); the cookie vector is a reply to that
initiation and the mac2 it makes for the next one.
"""
import hashlib
import hmac
import random
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

rng = random.Random(1942)


def rand(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def clamp(k):
    b = bytearray(k)
    b[0] &= 248
    b[31] = (b[31] & 127) | 64
    return bytes(b)


def pub(priv):
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def dh(priv, pub_):
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(pub_))


def h(*parts):
    return hashlib.blake2s(b"".join(parts)).digest()


def mac(key, data):  # MAC(key, input) = Keyed-Blake2s(key, input), 16 bytes
    return hashlib.blake2s(data, key=key, digest_size=16).digest()


def hmac_(key, data):
    return hmac.new(key, data, hashlib.blake2s).digest()


def kdf(n, key, data):  # KDF_n(key, input), the paper's HKDF
    t0 = hmac_(key, data)
    out, prev = [], b""
    for i in range(1, n + 1):
        prev = hmac_(t0, prev + bytes([i]))
        out.append(prev)
    return out


def aead(key, counter, plain, ad):  # AEAD(key, counter, plain, auth): ChaCha20-Poly1305, nonce = 4 zeros || LE64
    return ChaCha20Poly1305(key).encrypt(b"\0" * 4 + struct.pack("<Q", counter), plain, ad)


CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"


def tai64n(secs, nanos):
    return struct.pack(">QI", 0x400000000000000A + secs, nanos & ~0xFFFFFF)  # wireguard-go whitens the low 24 bits


def c_bytes(name, b):
    body = ", ".join("0x%02x" % x for x in b)
    lines = []
    line = "   "
    for item in body.split(", "):
        if len(line) + len(item) + 2 > 116:
            lines.append(line)
            line = "   "
        line += " " + item + ","
    lines.append(line)
    return "static const uint8_t %s[%d] = {\n%s\n};\n" % (name, len(b), "\n".join(lines))


# The two sides: an initiator (i) and a responder (r), and their ephemerals.
s_i, s_r = clamp(rand(32)), clamp(rand(32))
e_i, e_r = clamp(rand(32)), clamp(rand(32))
S_i, S_r, E_i, E_r = pub(s_i), pub(s_r), pub(e_i), pub(e_r)
psk = b"\0" * 32  # Tailscale sets no preshared key
idx_i, idx_r = rng.getrandbits(32), rng.getrandbits(32)
ts = tai64n(1792719090, 123456789)

# Initiation (paper 5.4.2)
C = h(CONSTRUCTION)
H = h(C, IDENTIFIER)
H = h(H, S_r)
C = kdf(1, C, E_i)[0]
H = h(H, E_i)
C, k = kdf(2, C, dh(e_i, S_r))
enc_static = aead(k, 0, S_i, H)
H = h(H, enc_static)
C, k = kdf(2, C, dh(s_i, S_r))
enc_ts = aead(k, 0, ts, H)
H = h(H, enc_ts)
init = struct.pack("<II", 1, idx_i) + E_i + enc_static + enc_ts
mac1_key_r = h(LABEL_MAC1, S_r)
mac1 = mac(mac1_key_r, init)
init += mac1 + b"\0" * 16
assert len(init) == 148

# Response (paper 5.4.3)
H = h(H, E_r)
C = kdf(1, C, E_r)[0]
C = kdf(1, C, dh(e_r, E_i))[0]
C = kdf(1, C, dh(e_r, S_i))[0]
C, tau, k = kdf(3, C, psk)
H = h(H, tau)
enc_empty = aead(k, 0, b"", H)
H = h(H, enc_empty)
resp = struct.pack("<III", 2, idx_r, idx_i) + E_r + enc_empty
mac1_key_i = h(LABEL_MAC1, S_i)
resp += mac(mac1_key_i, resp) + b"\0" * 16
assert len(resp) == 92

# Transport keys (paper 5.4.5): the initiator sends with the first, receives with the second.
t_send_i, t_recv_i = kdf(2, C, b"")

# Transport messages (5.4.6): from the initiator, counters 0 and 1, padded to 16; a keepalive (empty).
def transport(key, receiver, counter, payload):
    padded = payload + b"\0" * (-len(payload) % 16)
    return struct.pack("<IIQ", 4, receiver, counter) + aead(key, counter, padded, b"")


payload = rand(37)
tr0 = transport(t_send_i, idx_r, 0, payload)
tr1 = transport(t_send_i, idx_r, 1, b"")

# Cookie (5.4.7): the responder, under load, answers the initiation with a cookie for source "src"; the initiator's
# next initiation (the same bytes, standing in for a new one) then carries mac2.
cookie_secret = rand(32)
src = bytes([192, 0, 2, 3, 0xA2, 0xE9])  # an IPv4 address and port, as wireguard-go's src bytes are
cookie = mac(cookie_secret, src)
cookie_key_i = h(LABEL_COOKIE, S_r)  # the responder encrypts with its own key: Hash(LABEL_COOKIE || S_r)
xnonce = rand(24)
enc_cookie = crypto_aead_xchacha20poly1305_ietf_encrypt(cookie, mac1, xnonce, cookie_key_i)
cookie_reply = struct.pack("<II", 3, idx_i) + xnonce + enc_cookie
assert len(cookie_reply) == 64
init2 = init[:116] + mac1
init2 += mac(cookie, init2)

print("// Generated by tools/wg_vectors.py: an independent WireGuard reference (the paper's section 5.4 on OpenSSL,")
print("// hashlib and libsodium), not wireguard-go. Don't edit by hand.")
print("#pragma once")
print("#include <stdint.h>\n")
for name, value in [
    ("WG_S_I", s_i), ("WG_S_R", s_r), ("WG_E_I", e_i), ("WG_E_R", e_r), ("WG_TIMESTAMP", ts),
    ("WG_INITIATION", init), ("WG_RESPONSE", resp), ("WG_SEND_I", t_send_i), ("WG_RECV_I", t_recv_i),
    ("WG_PAYLOAD", payload), ("WG_TRANSPORT0", tr0), ("WG_TRANSPORT1", tr1), ("WG_COOKIE_SECRET", cookie_secret),
    ("WG_COOKIE_SRC", src), ("WG_COOKIE", cookie), ("WG_COOKIE_REPLY", cookie_reply), ("WG_INITIATION2", init2),
]:
    print(c_bytes(name, value))
print("#define WG_IDX_I 0x%08xu" % idx_i)
print("#define WG_IDX_R 0x%08xu" % idx_r)
