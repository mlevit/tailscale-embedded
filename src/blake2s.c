// BLAKE2s, from RFC 7693 (section 3 and the reference code in appendix C).
#include "blake2s.h"
#include <string.h>
#include "crypto.h"

static const uint32_t IV[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                               0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};

static const uint8_t SIGMA[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

static uint32_t rotr32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t load32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// The mixing function G (RFC 7693 section 3.1), rotations 16, 12, 8, 7.
#define G(a, b, c, d, x, y)                     \
    do {                                        \
        v[a] = v[a] + v[b] + (x);               \
        v[d] = rotr32(v[d] ^ v[a], 16);         \
        v[c] = v[c] + v[d];                     \
        v[b] = rotr32(v[b] ^ v[c], 12);         \
        v[a] = v[a] + v[b] + (y);               \
        v[d] = rotr32(v[d] ^ v[a], 8);          \
        v[c] = v[c] + v[d];                     \
        v[b] = rotr32(v[b] ^ v[c], 7);          \
    } while (0)

// The compression function F (section 3.2).
static void compress(tsnet_blake2s_t *s, int last)
{
    uint32_t v[16], m[16];
    for (int i = 0; i < 8; i++) {
        v[i] = s->h[i];
        v[i + 8] = IV[i];
    }
    v[12] ^= s->t[0];
    v[13] ^= s->t[1];
    if (last) {
        v[14] = ~v[14];
    }
    for (int i = 0; i < 16; i++) {
        m[i] = load32(&s->b[4 * i]);
    }
    for (int r = 0; r < 10; r++) {
        const uint8_t *z = SIGMA[r];
        G(0, 4, 8, 12, m[z[0]], m[z[1]]);
        G(1, 5, 9, 13, m[z[2]], m[z[3]]);
        G(2, 6, 10, 14, m[z[4]], m[z[5]]);
        G(3, 7, 11, 15, m[z[6]], m[z[7]]);
        G(0, 5, 10, 15, m[z[8]], m[z[9]]);
        G(1, 6, 11, 12, m[z[10]], m[z[11]]);
        G(2, 7, 8, 13, m[z[12]], m[z[13]]);
        G(3, 4, 9, 14, m[z[14]], m[z[15]]);
    }
    for (int i = 0; i < 8; i++) {
        s->h[i] ^= v[i] ^ v[i + 8];
    }
    tsnet_wipe(v, sizeof v);
    tsnet_wipe(m, sizeof m);
}

int tsnet_blake2s_init(tsnet_blake2s_t *s, size_t outlen, const void *key, size_t key_len)
{
    if (outlen == 0 || outlen > TSNET_BLAKE2S_OUT_MAX || key_len > 32) {
        return -1;
    }
    for (int i = 0; i < 8; i++) {
        s->h[i] = IV[i];
    }
    s->h[0] ^= 0x01010000 ^ ((uint32_t)key_len << 8) ^ (uint32_t)outlen; // parameter block: fanout 1, depth 1
    s->t[0] = 0;
    s->t[1] = 0;
    s->c = 0;
    s->outlen = outlen;
    memset(s->b, 0, sizeof s->b);
    if (key_len > 0) {
        tsnet_blake2s_update(s, key, key_len);
        s->c = TSNET_BLAKE2S_BLOCK; // the key is a whole block of its own
    }
    return 0;
}

void tsnet_blake2s_update(tsnet_blake2s_t *s, const void *in, size_t len)
{
    const uint8_t *p = in;
    for (size_t i = 0; i < len; i++) {
        if (s->c == TSNET_BLAKE2S_BLOCK) { // a full block: compress it, but only once more input arrives (the last block
            s->t[0] += (uint32_t)s->c;     // is compressed by final, flagged)
            if (s->t[0] < s->c) {
                s->t[1]++;
            }
            compress(s, 0);
            s->c = 0;
        }
        s->b[s->c++] = p[i];
    }
}

void tsnet_blake2s_final(tsnet_blake2s_t *s, void *out)
{
    s->t[0] += (uint32_t)s->c;
    if (s->t[0] < s->c) {
        s->t[1]++;
    }
    while (s->c < TSNET_BLAKE2S_BLOCK) {
        s->b[s->c++] = 0;
    }
    compress(s, 1);
    uint8_t *o = out;
    for (size_t i = 0; i < s->outlen; i++) {
        o[i] = (uint8_t)(s->h[i >> 2] >> (8 * (i & 3)));
    }
    tsnet_wipe(s, sizeof *s);
}

int tsnet_blake2s(void *out, size_t outlen, const void *key, size_t key_len, const void *in, size_t len)
{
    tsnet_blake2s_t s;
    if (tsnet_blake2s_init(&s, outlen, key, key_len) != 0) {
        return -1;
    }
    tsnet_blake2s_update(&s, in, len);
    tsnet_blake2s_final(&s, out);
    return 0;
}
