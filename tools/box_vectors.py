#!/usr/bin/env python3
"""Writes test/box_vectors.h: NaCl box vectors (X25519, HSalsa20, XSalsa20-Poly1305) for crypto_test.c.

Usage: uv run --with pynacl==1.5.0 python3 tools/box_vectors.py > test/box_vectors.h

The source isn't ours: PyNaCl's Box (libsodium's crypto_box_curve25519xsalsa20poly1305), the same construction as Go's
golang.org/x/crypto/nacl/box that key.NodePrivate.SealTo uses. Each vector is a key pair for each side, the shared key
(box.Precompute, libsodium's beforenm), a nonce, a message, and the sealed bytes after the nonce (the tag, then the
ciphertext), at lengths around the Salsa20 and Poly1305 block edges. The keys come from a fixed seed, so a rerun writes
the same file.
"""
import random

from nacl.public import Box, PrivateKey

rng = random.Random(1885)


def rand(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def c(b):
    return "{" + ", ".join("0x%02x" % x for x in b) + "}"


print("// Written by tools/box_vectors.py (PyNaCl 1.5.0, libsodium's crypto_box). Don't edit.")
print("typedef struct {")
print("    uint8_t a_priv[32], b_pub[32], shared[32], nonce[24];")
print("    const uint8_t *msg;")
print("    size_t len;")
print("    const uint8_t *sealed; // the tag, then the ciphertext: len + 16 bytes")
print("} box_vector_t;")
vecs = []
for i, n in enumerate([0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65, 100, 127, 128, 129, 1000]):
    a = PrivateKey(rand(32))
    b = PrivateKey(rand(32))
    nonce = rand(24)
    msg = rand(n)
    box = Box(a, b.public_key)
    sealed = box.encrypt(msg, nonce)[24:]  # PyNaCl puts the nonce first, as SealTo does
    assert len(sealed) == n + 16
    assert Box(b, a.public_key).decrypt(sealed, nonce) == msg
    print("static const uint8_t box_msg_%d[] = %s;" % (i, c(msg) if n else "{0}"))
    print("static const uint8_t box_sealed_%d[] = %s;" % (i, c(sealed)))
    vecs.append("    {%s,\n     %s,\n     %s,\n     %s,\n     box_msg_%d, %d, box_sealed_%d}," % (
        c(bytes(a)), c(bytes(b.public_key)), c(box.shared_key()), c(nonce), i, n, i))
print("static const box_vector_t box_vectors[] = {")
print("\n".join(vecs))
print("};")
