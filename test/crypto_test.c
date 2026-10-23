// Host test of tsnet's primitives. The vectors are RFC 7748 (X25519), RFC 8439 (ChaCha20-Poly1305) and RFC 7693
// (BLAKE2s), each checked against an independent implementation (Python's cryptography, which wraps OpenSSL); the
// keyed BLAKE2s, HMAC-BLAKE2s and Noise-HKDF values come from CPython's hashlib (the BLAKE2 reference code). NaCl box's
// come from PyNaCl (libsodium), written to box_vectors.h by tools/box_vectors.py.
#include <stdio.h>
#include <string.h>
#include "blake2s.h"
#include "crypto.h"
#include "box_vectors.h" // after crypto.h, for its types

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static size_t unhex(uint8_t *out, size_t cap, const char *hex)
{
    size_t n = 0;
    for (; hex[0] && hex[1] && n < cap; hex += 2) {
        unsigned v;
        sscanf(hex, "%2x", &v);
        out[n++] = (uint8_t)v;
    }
    return n;
}

static int eq_hex(const uint8_t *got, size_t len, const char *hex)
{
    uint8_t want[512];
    size_t n = unhex(want, sizeof want, hex);
    return n == len && memcmp(got, want, len) == 0;
}

static void x25519_vectors(void)
{
    uint8_t k[32], u[32], out[32];
    // RFC 7748 section 5.2, single step.
    unhex(k, 32, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    unhex(u, 32, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    EXPECT(tsnet_x25519(out, k, u) == 0);
    EXPECT(eq_hex(out, 32, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
    unhex(k, 32, "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    unhex(u, 32, "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"); // top bit set: masked
    EXPECT(tsnet_x25519(out, k, u) == 0);
    EXPECT(eq_hex(out, 32, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"));

    // Iterated: k = u = 9, then k, u = X25519(k, u), k. After 1 and 1,000 iterations.
    uint8_t kk[32] = {9}, uu[32] = {9}, next[32];
    for (int i = 1; i <= 1000; i++) {
        EXPECT(tsnet_x25519(next, kk, uu) == 0);
        memcpy(uu, kk, 32);
        memcpy(kk, next, 32);
        if (i == 1) {
            EXPECT(eq_hex(kk, 32, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"));
        }
    }
    EXPECT(eq_hex(kk, 32, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"));

    // Section 6.1: Diffie-Hellman.
    uint8_t a[32], b[32], apub[32], bpub[32], s1[32], s2[32];
    unhex(a, 32, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    unhex(b, 32, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    EXPECT(tsnet_x25519_public(apub, a) == 0);
    EXPECT(eq_hex(apub, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    EXPECT(tsnet_x25519_public(bpub, b) == 0);
    EXPECT(eq_hex(bpub, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    EXPECT(tsnet_x25519(s1, a, bpub) == 0);
    EXPECT(tsnet_x25519(s2, b, apub) == 0);
    EXPECT(eq_hex(s1, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
    EXPECT(memcmp(s1, s2, 32) == 0);

    // A low-order point gives an all-zero result, which must be refused (u = 0 and u = 1 are of low order).
    uint8_t zero[32] = {0}, one[32] = {1};
    memset(out, 0xaa, sizeof out);
    EXPECT(tsnet_x25519(out, a, zero) == -1);
    EXPECT(memcmp(out, zero, 32) == 0);
    EXPECT(tsnet_x25519(out, a, one) == -1);
}

static void aead_vectors(void)
{
    // RFC 8439 section 2.8.2.
    static const char PT[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
                             "sunscreen would be it.";
    static const char CT[] = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da"
                             "92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585"
                             "808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
    uint8_t key[32], nonce[12], aad[12], buf[256], back[256];
    size_t len = strlen(PT);
    unhex(key, 32, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    unhex(nonce, 12, "070000004041424344454647");
    unhex(aad, 12, "50515253c0c1c2c3c4c5c6c7");
    EXPECT(tsnet_aead_seal(buf, key, nonce, aad, sizeof aad, (const uint8_t *)PT, len) == 0);
    EXPECT(eq_hex(buf, len, CT));
    EXPECT(eq_hex(buf + len, 16, "1ae10b594f09e26a7e902ecbd0600691"));
    EXPECT(tsnet_aead_open(back, key, nonce, aad, sizeof aad, buf, len) == 0);
    EXPECT(memcmp(back, PT, len) == 0);

    // A flipped bit anywhere (ciphertext, tag, additional data) fails, and leaves no plaintext behind.
    buf[3] ^= 1;
    memset(back, 0x55, len);
    EXPECT(tsnet_aead_open(back, key, nonce, aad, sizeof aad, buf, len) == -1);
    uint8_t zeros[256] = {0};
    EXPECT(memcmp(back, zeros, len) == 0);
    buf[3] ^= 1;
    buf[len + 15] ^= 0x80;
    EXPECT(tsnet_aead_open(back, key, nonce, aad, sizeof aad, buf, len) == -1);
    buf[len + 15] ^= 0x80;
    aad[0] ^= 1;
    EXPECT(tsnet_aead_open(back, key, nonce, aad, sizeof aad, buf, len) == -1);
    aad[0] ^= 1;

    // In place, and empty plaintext with no additional data (Noise seals empty payloads).
    memcpy(buf, PT, len);
    EXPECT(tsnet_aead_seal(buf, key, nonce, aad, sizeof aad, buf, len) == 0);
    EXPECT(eq_hex(buf, len, CT));
    uint8_t tag_only[16];
    EXPECT(tsnet_aead_seal(tag_only, key, nonce, NULL, 0, NULL, 0) == 0);
    EXPECT(tsnet_aead_open(NULL, key, nonce, NULL, 0, tag_only, 0) == 0);
    tag_only[0] ^= 1;
    EXPECT(tsnet_aead_open(NULL, key, nonce, NULL, 0, tag_only, 0) == -1);
}

static void blake2s_vectors(void)
{
    uint8_t out[32], in[256], key[32];
    for (int i = 0; i < 256; i++) {
        in[i] = (uint8_t)i;
    }
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)i;
    }
    // RFC 7693 appendix B.
    EXPECT(tsnet_blake2s(out, 32, NULL, 0, "abc", 3) == 0);
    EXPECT(eq_hex(out, 32, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"));
    // Unkeyed, input 00 01 02 ...: around the 64-byte block edge.
    EXPECT(tsnet_blake2s(out, 32, NULL, 0, in, 0) == 0);
    EXPECT(eq_hex(out, 32, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"));
    EXPECT(tsnet_blake2s(out, 32, NULL, 0, in, 64) == 0);
    EXPECT(eq_hex(out, 32, "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e"));
    EXPECT(tsnet_blake2s(out, 32, NULL, 0, in, 200) == 0);
    EXPECT(eq_hex(out, 32, "6d244e1a06ce4ef578dd0f63aff0936706735119ca9c8d22d86c801414ab9741"));
    // Keyed (key 00..1f, the BLAKE2 KAT's key).
    static const struct {
        size_t len;
        const char *hex;
    } KEYED[] = {
        {0, "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"},
        {1, "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1"},
        {63, "c65382513f07460da39833cb666c5ed82e61b9e998f4b0c4287cee56c3cc9bcd"},
        {64, "8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4"},
        {65, "21fe0ceb0052be7fb0f004187cacd7de67fa6eb0938d927677f2398c132317a8"},
        {255, "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd"},
    };
    for (size_t i = 0; i < sizeof KEYED / sizeof KEYED[0]; i++) {
        EXPECT(tsnet_blake2s(out, 32, key, 32, in, KEYED[i].len) == 0);
        EXPECT(eq_hex(out, 32, KEYED[i].hex));
    }
    // Fed in uneven pieces, the same as all at once.
    tsnet_blake2s_t s;
    EXPECT(tsnet_blake2s_init(&s, 32, key, 32) == 0);
    tsnet_blake2s_update(&s, in, 1);
    tsnet_blake2s_update(&s, in + 1, 63);
    tsnet_blake2s_update(&s, in + 64, 0);
    tsnet_blake2s_update(&s, in + 64, 191);
    tsnet_blake2s_final(&s, out);
    EXPECT(eq_hex(out, 32, "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd"));
    // Bad sizes are refused.
    EXPECT(tsnet_blake2s(out, 0, NULL, 0, in, 1) == -1);
    EXPECT(tsnet_blake2s(out, 33, NULL, 0, in, 1) == -1);
    EXPECT(tsnet_blake2s(out, 32, in, 33, in, 1) == -1);
}

static void hmac_hkdf_vectors(void)
{
    uint8_t out[32], key[100], data[256];
    for (int i = 0; i < 100; i++) {
        key[i] = (uint8_t)i;
    }
    for (int i = 0; i < 256; i++) {
        data[i] = (uint8_t)i;
    }
    tsnet_hmac_blake2s(out, key, 32, (const uint8_t *)"hello", 5);
    EXPECT(eq_hex(out, 32, "ca3386d2021b8c299b42476827e7e729b48255da7aee060261072790ea0fc3fa"));
    tsnet_hmac_blake2s(out, key, 100, data, 256); // a key longer than a block is hashed first
    EXPECT(eq_hex(out, 32, "09114dbf2167debc8c48934d70a106c6ec554ea116f64d85068a84fc328cdc3f"));

    // Noise's HKDF from the chaining key Tailscale's handshakes start with: the protocol name is 33 bytes, longer than
    // HASHLEN, so Noise's InitializeSymmetric sets h = ck = HASH("Noise_IK_25519_ChaChaPoly_BLAKE2s").
    uint8_t ck[32], o1[32], o2[32], o3[32];
    static const char NAME[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
    EXPECT(strlen(NAME) == 33);
    EXPECT(tsnet_blake2s(ck, 32, NULL, 0, NAME, strlen(NAME)) == 0);
    EXPECT(eq_hex(ck, 32, "bbea022b948cf3bc5857d70804229179e1116bc40cb8cc074835349c464bca36"));
    tsnet_hkdf(ck, key, 32, o1, o2, o3);
    EXPECT(eq_hex(o1, 32, "d6c8db9d60f7cc6250043f8765ad17667f831b9294262a60d9d6fa92b75771c7"));
    EXPECT(eq_hex(o2, 32, "872d10ac2deb53cbebb2f567005133f16b3918b6d57fd1a6f1121a4715abb144"));
    EXPECT(eq_hex(o3, 32, "279a03f7a7acfaaee26c7fc89e380109903358186886f5ad3c6aaa14381beea2"));
    tsnet_hkdf(ck, NULL, 0, o1, o2, NULL);
    EXPECT(eq_hex(o1, 32, "26937cb281910d8b8fd9937e44450633ee3c908791cc8d50b45a7f4126a3c054"));
    EXPECT(eq_hex(o2, 32, "c7ff3af72c3e5fc94f8c3f84fd52f9e5568a8ef4dd46e2ca0d7e99969decd81f"));
    // Skipping an output still chains through it.
    memset(o2, 0, 32);
    tsnet_hkdf(ck, key, 32, NULL, o2, NULL);
    EXPECT(eq_hex(o2, 32, "872d10ac2deb53cbebb2f567005133f16b3918b6d57fd1a6f1121a4715abb144"));
}

// NaCl box against PyNaCl's (libsodium's crypto_box), from tools/box_vectors.py.
static void box_vectors_check(void)
{
    uint8_t shared[32], out[1100], back[1100];
    for (size_t i = 0; i < sizeof box_vectors / sizeof box_vectors[0]; i++) {
        const box_vector_t *v = &box_vectors[i];
        EXPECT(tsnet_box_shared(shared, v->a_priv, v->b_pub) == 0);
        EXPECT(memcmp(shared, v->shared, 32) == 0);
        EXPECT(tsnet_box_seal(out, shared, v->nonce, v->msg, v->len) == 0);
        EXPECT(memcmp(out, v->sealed, v->len + 16) == 0);
        EXPECT(tsnet_box_open(back, shared, v->nonce, v->sealed, v->len + 16) == 0);
        EXPECT(memcmp(back, v->msg, v->len) == 0);
        // Any byte changed (tag or ciphertext) fails, and leaves no plaintext behind.
        for (size_t j = 0; j < v->len + 16; j++) {
            memcpy(out, v->sealed, v->len + 16);
            out[j] ^= 0x01;
            memset(back, 0xaa, sizeof back);
            EXPECT(tsnet_box_open(back, shared, v->nonce, out, v->len + 16) == -1);
            for (size_t k = 0; k < v->len; k++) {
                EXPECT(back[k] == 0);
            }
        }
        uint8_t nonce[24];
        memcpy(nonce, v->nonce, 24);
        nonce[23] ^= 0x80;
        EXPECT(tsnet_box_open(back, shared, nonce, v->sealed, v->len + 16) == -1);
    }
    EXPECT(tsnet_box_open(back, shared, box_vectors[0].nonce, box_vectors[0].sealed, 15) == -1); // shorter than a tag
    // A low-order public key gives an all-zero X25519 result, which is refused.
    static const uint8_t zero[32] = {0};
    EXPECT(tsnet_box_shared(shared, box_vectors[0].a_priv, zero) == -1);
}

int main(void)
{
    x25519_vectors();
    aead_vectors();
    blake2s_vectors();
    hmac_hkdf_vectors();
    box_vectors_check();
    if (failures == 0) {
        printf("tsnet crypto_test: ok\n");
    }
    return failures != 0;
}
