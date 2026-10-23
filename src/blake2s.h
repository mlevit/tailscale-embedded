#pragma once
// BLAKE2s (RFC 7693), the hash of Tailscale's Noise protocols. Written from the RFC's algorithm and reference code (section
// 3 and appendix C); checked against RFC 7693 appendix B and CPython's hashlib in test/crypto_test.c.
#include <stddef.h>
#include <stdint.h>

#define TSNET_BLAKE2S_BLOCK 64
#define TSNET_BLAKE2S_OUT_MAX 32

typedef struct {
    uint8_t b[TSNET_BLAKE2S_BLOCK]; // input buffer
    uint32_t h[8];                  // chained state
    uint32_t t[2];                  // total bytes, low and high
    size_t c;                       // bytes in b
    size_t outlen;                  // digest size, 1 to 32
} tsnet_blake2s_t;

// Starts a hash of `outlen` bytes (1 to 32), keyed if `key_len` > 0 (at most 32 bytes). Returns 0, or -1 on a bad size.
int tsnet_blake2s_init(tsnet_blake2s_t *s, size_t outlen, const void *key, size_t key_len);
void tsnet_blake2s_update(tsnet_blake2s_t *s, const void *in, size_t len);
// Writes the digest (outlen bytes) and wipes the state.
void tsnet_blake2s_final(tsnet_blake2s_t *s, void *out);

// One call: out = BLAKE2s(key, in), outlen bytes. Returns 0 or -1.
int tsnet_blake2s(void *out, size_t outlen, const void *key, size_t key_len, const void *in, size_t len);
