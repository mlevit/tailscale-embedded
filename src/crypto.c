// tsnet's primitives: mbedTLS for X25519 and ChaCha20-Poly1305, RFC 7693 BLAKE2s, and the RFC 2104 / Noise
// constructions on top; TweetNaCl for NaCl box's HSalsa20 and XSalsa20-Poly1305. See crypto.h.
#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include "blake2s.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/ecp.h"
#include "mbedtls/platform_util.h"
#include "platform.h"
#include "tweetnacl.h"

void tsnet_wipe(void *p, size_t len)
{
    mbedtls_platform_zeroize(p, len);
}

// mbedTLS's random callback (it randomises the ladder's coordinates against side channels).
static int rng(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    return tsnet_random(buf, len) == 0 ? 0 : -1;
}

int tsnet_x25519(uint8_t out[TSNET_KEY_LEN], const uint8_t scalar[TSNET_KEY_LEN], const uint8_t point[TSNET_KEY_LEN])
{
    uint8_t k[TSNET_KEY_LEN];
    memcpy(k, scalar, sizeof k);
    k[0] &= 248; // RFC 7748 section 5: clamp
    k[31] &= 127;
    k[31] |= 64;

    mbedtls_ecp_group grp;
    mbedtls_ecp_point p, r;
    mbedtls_mpi d;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&p);
    mbedtls_ecp_point_init(&r);
    mbedtls_mpi_init(&d);
    size_t olen = 0;
    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary_le(&d, k, sizeof k);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_point_read_binary(&grp, &p, point, TSNET_KEY_LEN); // masks the top bit, as RFC 7748 says
    }
    if (ret == 0) {
        ret = mbedtls_ecp_mul(&grp, &r, &d, &p, rng, NULL);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_point_write_binary(&grp, &r, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, out, TSNET_KEY_LEN);
    }
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&r);
    mbedtls_ecp_point_free(&p);
    mbedtls_ecp_group_free(&grp);
    tsnet_wipe(k, sizeof k);

    uint8_t any = 0;
    for (size_t i = 0; ret == 0 && i < TSNET_KEY_LEN; i++) {
        any |= out[i];
    }
    if (ret != 0 || olen != TSNET_KEY_LEN || any == 0) {
        memset(out, 0, TSNET_KEY_LEN);
        return -1;
    }
    return 0;
}

int tsnet_x25519_public(uint8_t pub[TSNET_KEY_LEN], const uint8_t priv[TSNET_KEY_LEN])
{
    static const uint8_t base[TSNET_KEY_LEN] = {9};
    return tsnet_x25519(pub, priv, base);
}

int tsnet_aead_seal(uint8_t *out, const uint8_t key[TSNET_KEY_LEN], const uint8_t nonce[TSNET_AEAD_NONCE_LEN],
                    const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t len)
{
    mbedtls_chachapoly_context c;
    mbedtls_chachapoly_init(&c);
    int ret = mbedtls_chachapoly_setkey(&c, key);
    if (ret == 0) {
        ret = mbedtls_chachapoly_encrypt_and_tag(&c, len, nonce, ad, ad_len, in, out, out + len);
    }
    mbedtls_chachapoly_free(&c);
    return ret == 0 ? 0 : -1;
}

int tsnet_aead_open(uint8_t *out, const uint8_t key[TSNET_KEY_LEN], const uint8_t nonce[TSNET_AEAD_NONCE_LEN],
                    const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t len)
{
    mbedtls_chachapoly_context c;
    mbedtls_chachapoly_init(&c);
    int ret = mbedtls_chachapoly_setkey(&c, key);
    if (ret == 0) {
        ret = mbedtls_chachapoly_auth_decrypt(&c, len, nonce, ad, ad_len, in + len, in, out);
    }
    mbedtls_chachapoly_free(&c);
    if (ret != 0) {
        if (len > 0) {
            memset(out, 0, len);
        }
        return -1;
    }
    return 0;
}

void tsnet_hmac_blake2s(uint8_t out[TSNET_KEY_LEN], const uint8_t *key, size_t key_len, const uint8_t *data, size_t len)
{
    uint8_t k0[TSNET_BLAKE2S_BLOCK] = {0};
    if (key_len > TSNET_BLAKE2S_BLOCK) {
        tsnet_blake2s(k0, TSNET_KEY_LEN, NULL, 0, key, key_len); // a long key is hashed first (RFC 2104)
    } else if (key_len > 0) {
        memcpy(k0, key, key_len);
    }
    uint8_t pad[TSNET_BLAKE2S_BLOCK], inner[TSNET_KEY_LEN];
    tsnet_blake2s_t s;

    for (size_t i = 0; i < sizeof pad; i++) {
        pad[i] = k0[i] ^ 0x36;
    }
    tsnet_blake2s_init(&s, TSNET_KEY_LEN, NULL, 0);
    tsnet_blake2s_update(&s, pad, sizeof pad);
    tsnet_blake2s_update(&s, data, len);
    tsnet_blake2s_final(&s, inner);

    for (size_t i = 0; i < sizeof pad; i++) {
        pad[i] = k0[i] ^ 0x5c;
    }
    tsnet_blake2s_init(&s, TSNET_KEY_LEN, NULL, 0);
    tsnet_blake2s_update(&s, pad, sizeof pad);
    tsnet_blake2s_update(&s, inner, sizeof inner);
    tsnet_blake2s_final(&s, out);

    tsnet_wipe(k0, sizeof k0);
    tsnet_wipe(pad, sizeof pad);
    tsnet_wipe(inner, sizeof inner);
}

void tsnet_hkdf(const uint8_t ck[TSNET_KEY_LEN], const uint8_t *ikm, size_t ikm_len, uint8_t out1[TSNET_KEY_LEN],
                uint8_t out2[TSNET_KEY_LEN], uint8_t out3[TSNET_KEY_LEN])
{
    // Noise section 4.3: temp_key = HMAC(ck, ikm); output_i = HMAC(temp_key, output_{i-1} || byte(i)).
    uint8_t temp[TSNET_KEY_LEN], prev[TSNET_KEY_LEN + 1], o[TSNET_KEY_LEN];
    uint8_t *outs[3] = {out1, out2, out3};
    int last = out3 ? 3 : out2 ? 2 : out1 ? 1 : 0;
    tsnet_hmac_blake2s(temp, ck, TSNET_KEY_LEN, ikm, ikm_len);
    size_t prev_len = 0;
    for (int i = 1; i <= last; i++) {
        prev[prev_len] = (uint8_t)i;
        tsnet_hmac_blake2s(o, temp, sizeof temp, prev, prev_len + 1);
        if (outs[i - 1]) {
            memcpy(outs[i - 1], o, TSNET_KEY_LEN);
        }
        memcpy(prev, o, TSNET_KEY_LEN);
        prev_len = TSNET_KEY_LEN;
    }
    tsnet_wipe(temp, sizeof temp);
    tsnet_wipe(prev, sizeof prev);
    tsnet_wipe(o, sizeof o);
}

// TweetNaCl's key-pair functions call this. tsnet never calls them (its keys come from identity.c), but the symbol must
// exist to link. A key from a failed random source would be guessable, so failing stops the program.
void randombytes(unsigned char *buf, unsigned long long len)
{
    if (tsnet_random(buf, (size_t)len) != 0) {
        abort();
    }
}

int tsnet_box_shared(uint8_t shared[TSNET_KEY_LEN], const uint8_t priv[TSNET_KEY_LEN], const uint8_t peer[TSNET_KEY_LEN])
{
    // box.Precompute: curve25519.ScalarMult, then HSalsa20 of the result with a zero nonce and Salsa20's sigma.
    static const uint8_t zero[16] = {0}, sigma[16] = {'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
                                                      '2', '-', 'b', 'y', 't', 'e', ' ', 'k'};
    uint8_t s[TSNET_KEY_LEN];
    int ret = tsnet_x25519(s, priv, peer);
    if (ret == 0) {
        crypto_core_hsalsa20(shared, zero, s, sigma);
    }
    tsnet_wipe(s, sizeof s);
    return ret;
}

// TweetNaCl's secretbox takes the message after 32 zero bytes and writes 16 zero bytes, the tag and the ciphertext;
// Go's box (and libsodium's _easy calls) drop the padding. So both go through a padded copy.
int tsnet_box_seal(uint8_t *out, const uint8_t shared[TSNET_KEY_LEN], const uint8_t nonce[TSNET_BOX_NONCE_LEN],
                   const uint8_t *in, size_t len)
{
    size_t n = len + 32;
    uint8_t *m = tsnet_calloc(1, n), *c = tsnet_malloc(n);
    int ret = -1;
    if (m && c) {
        memcpy(m + 32, in, len);
        ret = crypto_secretbox(c, m, n, nonce, shared);
        memcpy(out, c + 16, len + TSNET_BOX_TAG_LEN);
    }
    if (m) {
        tsnet_wipe(m, n);
    }
    free(m);
    free(c);
    return ret;
}

int tsnet_box_open(uint8_t *out, const uint8_t shared[TSNET_KEY_LEN], const uint8_t nonce[TSNET_BOX_NONCE_LEN],
                   const uint8_t *in, size_t len)
{
    if (len < TSNET_BOX_TAG_LEN) {
        return -1;
    }
    size_t n = len + 16;
    uint8_t *c = tsnet_calloc(1, n), *m = tsnet_malloc(n);
    int ret = -1;
    if (c && m) {
        memcpy(c + 16, in, len);
        ret = crypto_secretbox_open(m, c, n, nonce, shared);
        if (ret == 0) {
            memcpy(out, m + 32, len - TSNET_BOX_TAG_LEN);
        } else {
            memset(out, 0, len - TSNET_BOX_TAG_LEN);
        }
    }
    if (m) {
        tsnet_wipe(m, n);
    }
    free(c);
    free(m);
    return ret;
}
