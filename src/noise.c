// The client side of Tailscale's control/controlbase. See noise.h; the Go it follows is cited at each step.
#include "noise.h"
#include <stdio.h>
#include <string.h>
#include "blake2s.h"
#include "platform.h"

// handshake.go
static const char PROTOCOL_NAME[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
static const char PROLOGUE_PREFIX[] = "Tailscale Control Protocol v"; // protocolVersionPrefix

// messages.go
enum { MSG_INITIATION = 1, MSG_RESPONSE = 2, MSG_ERROR = 3, MSG_RECORD = 4 };
#define INIT_HEADER_LEN 5 // initiationHeaderLen: 2 version + 1 type + 2 length

#define INVALID_NONCE UINT64_MAX // handshake.go invalidNonce = ^uint64(0)

static void put16be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint16_t get16be(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

// symmetricState.MixHash: h = BLAKE2s(h || data).
static void mix_hash(tsnet_noise_client_t *c, const void *data, size_t len)
{
    tsnet_blake2s_t s;
    tsnet_blake2s_init(&s, TSNET_KEY_LEN, NULL, 0);
    tsnet_blake2s_update(&s, c->h, sizeof c->h);
    tsnet_blake2s_update(&s, data, len);
    tsnet_blake2s_final(&s, c->h);
}

// symmetricState.MixDH: ck, k = HKDF(ck, X25519(priv, pub)). Go's hkdf.New(newBLAKE2s, keyData, ck, nil) is RFC 5869 with
// salt ck and no info, which is exactly Noise's HKDF (tsnet_hkdf). curve25519.X25519 refuses a low-order point; so does
// tsnet_x25519.
static int mix_dh(tsnet_noise_client_t *c, const uint8_t priv[TSNET_KEY_LEN], const uint8_t pub[TSNET_KEY_LEN],
                  uint8_t k[TSNET_KEY_LEN])
{
    uint8_t dh[TSNET_KEY_LEN];
    if (tsnet_x25519(dh, priv, pub) != 0) {
        return -1;
    }
    tsnet_hkdf(c->ck, dh, sizeof dh, c->ck, k, NULL);
    tsnet_wipe(dh, sizeof dh);
    return 0;
}

// The handshake's single-use ciphers (newSingleUseCHP) seal with an all-zero nonce, the hash as additional data.
static const uint8_t ZERO_NONCE[TSNET_AEAD_NONCE_LEN] = {0};

// symmetricState.EncryptAndHash: out = Seal(k, 0, h, plaintext); MixHash(out).
static void encrypt_and_hash(tsnet_noise_client_t *c, const uint8_t k[TSNET_KEY_LEN], uint8_t *out, const uint8_t *pt,
                             size_t len)
{
    tsnet_aead_seal(out, k, ZERO_NONCE, c->h, sizeof c->h, pt, len);
    mix_hash(c, out, len + TSNET_AEAD_TAG_LEN);
}

// symmetricState.DecryptAndHash: pt = Open(k, 0, h, ciphertext); MixHash(ciphertext).
static int decrypt_and_hash(tsnet_noise_client_t *c, const uint8_t k[TSNET_KEY_LEN], uint8_t *pt, const uint8_t *ct,
                            size_t len)
{
    if (tsnet_aead_open(pt, k, ZERO_NONCE, c->h, sizeof c->h, ct, len) != 0) {
        return -1;
    }
    mix_hash(c, ct, len + TSNET_AEAD_TAG_LEN);
    return 0;
}

int tsnet_noise_client_start_with(tsnet_noise_client_t *c, const uint8_t machine_priv[TSNET_KEY_LEN],
                                  const uint8_t control_pub[TSNET_KEY_LEN], uint16_t version,
                                  const uint8_t ephemeral_priv[TSNET_KEY_LEN], uint8_t init[TSNET_NOISE_INIT_LEN])
{
    memcpy(c->machine, machine_priv, TSNET_KEY_LEN);
    memcpy(c->control_pub, control_pub, TSNET_KEY_LEN);
    memcpy(c->ephemeral, ephemeral_priv, TSNET_KEY_LEN);

    // Initialize: h = ck = BLAKE2s(protocolName). (33 bytes, longer than the hash, so it is hashed.)
    tsnet_blake2s(c->h, TSNET_KEY_LEN, NULL, 0, PROTOCOL_NAME, sizeof PROTOCOL_NAME - 1);
    memcpy(c->ck, c->h, TSNET_KEY_LEN);
    // MixHash(protocolVersionPrologue(version)): the prefix and the version in decimal.
    char prologue[sizeof PROLOGUE_PREFIX + 5];
    int n = snprintf(prologue, sizeof prologue, "%s%u", PROLOGUE_PREFIX, (unsigned)version);
    mix_hash(c, prologue, (size_t)n);
    // IK's pre-message: the responder's static key.
    mix_hash(c, control_pub, TSNET_KEY_LEN);

    // mkInitiationMessage: version, type, payload length (96), all big-endian.
    put16be(init, version);
    init[2] = MSG_INITIATION;
    put16be(init + 3, TSNET_NOISE_INIT_LEN - INIT_HEADER_LEN);
    uint8_t *eph_pub = init + INIT_HEADER_LEN;    // 32 bytes, in the clear
    uint8_t *machine_ct = eph_pub + TSNET_KEY_LEN; // 32 + 16
    uint8_t *tag = machine_ct + TSNET_KEY_LEN + TSNET_AEAD_TAG_LEN;

    uint8_t machine_pub[TSNET_KEY_LEN], k[TSNET_KEY_LEN];
    int ok = tsnet_x25519_public(eph_pub, c->ephemeral) == 0 && tsnet_x25519_public(machine_pub, c->machine) == 0;
    if (ok) {
        mix_hash(c, eph_pub, TSNET_KEY_LEN);                          // e
        ok = mix_dh(c, c->ephemeral, control_pub, k) == 0;            // es
    }
    if (ok) {
        encrypt_and_hash(c, k, machine_ct, machine_pub, TSNET_KEY_LEN); // s
        ok = mix_dh(c, c->machine, control_pub, k) == 0;              // ss
    }
    if (ok) {
        encrypt_and_hash(c, k, tag, NULL, 0); // the empty payload's tag
    }
    tsnet_wipe(k, sizeof k);
    if (!ok) {
        tsnet_wipe(c, sizeof *c);
        return -1;
    }
    return 0;
}

int tsnet_noise_client_start(tsnet_noise_client_t *c, const uint8_t machine_priv[TSNET_KEY_LEN],
                             const uint8_t control_pub[TSNET_KEY_LEN], uint16_t version,
                             uint8_t init[TSNET_NOISE_INIT_LEN])
{
    uint8_t eph[TSNET_KEY_LEN];
    if (tsnet_random(eph, sizeof eph) != 0) {
        return -1;
    }
    int ret = tsnet_noise_client_start_with(c, machine_priv, control_pub, version, eph, init);
    tsnet_wipe(eph, sizeof eph);
    return ret;
}

int tsnet_noise_client_finish(tsnet_noise_client_t *c, const uint8_t *frame, size_t len, tsnet_noise_conn_t *conn)
{
    int ret = -1;
    uint8_t k[TSNET_KEY_LEN];
    if (len >= TSNET_NOISE_HEADER_LEN && frame[0] == MSG_ERROR) {
        ret = TSNET_NOISE_SERVER_ERROR; // the server refused us; the payload is its message
        goto out;
    }
    // continueClientHandshake: the type must be msgTypeResponse and the length exactly the payload's.
    if (len != TSNET_NOISE_RESP_LEN || frame[0] != MSG_RESPONSE ||
        get16be(frame + 1) != TSNET_NOISE_RESP_LEN - TSNET_NOISE_HEADER_LEN) {
        goto out;
    }
    const uint8_t *control_eph = frame + TSNET_NOISE_HEADER_LEN;
    const uint8_t *tag = control_eph + TSNET_KEY_LEN;
    mix_hash(c, control_eph, TSNET_KEY_LEN);                     // e
    if (mix_dh(c, c->ephemeral, control_eph, k) != 0) {          // ee (its cipher is unused)
        goto out;
    }
    if (mix_dh(c, c->machine, control_eph, k) != 0) {            // se
        goto out;
    }
    if (decrypt_and_hash(c, k, NULL, tag, 0) != 0) {             // the empty payload's tag
        goto out;
    }
    // Split: c1, c2 = HKDF(ck, nil); the client sends with c1 and receives with c2.
    tsnet_hkdf(c->ck, NULL, 0, conn->tx.key, conn->rx.key, NULL);
    conn->tx.nonce = 0;
    conn->rx.nonce = 0;
    ret = 0;
out:
    tsnet_wipe(k, sizeof k);
    tsnet_wipe(c, sizeof *c);
    return ret;
}

// conn.go nonce: 4 zero bytes, then the counter big-endian (not little-endian as in WireGuard). Valid while the counter
// isn't invalidNonce.
static int next_nonce(tsnet_noise_cipher_t *ci, uint8_t nonce[TSNET_AEAD_NONCE_LEN])
{
    if (ci->nonce == INVALID_NONCE) {
        return -1;
    }
    memset(nonce, 0, 4);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (uint8_t)(ci->nonce >> (56 - 8 * i));
    }
    ci->nonce++;
    return 0;
}

size_t tsnet_noise_seal(tsnet_noise_conn_t *conn, uint8_t *out, const uint8_t *plaintext, size_t len)
{
    uint8_t nonce[TSNET_AEAD_NONCE_LEN];
    if (len > TSNET_NOISE_MAX_PLAINTEXT || next_nonce(&conn->tx, nonce) != 0) {
        return 0;
    }
    out[0] = MSG_RECORD;
    put16be(out + 1, (uint16_t)(len + TSNET_AEAD_TAG_LEN));
    if (tsnet_aead_seal(out + TSNET_NOISE_HEADER_LEN, conn->tx.key, nonce, NULL, 0, plaintext, len) != 0) {
        return 0;
    }
    return TSNET_NOISE_HEADER_LEN + len + TSNET_AEAD_TAG_LEN;
}

int tsnet_noise_open(tsnet_noise_conn_t *conn, uint8_t *plaintext, const uint8_t *frame, size_t len)
{
    // conn.go decryptOneLocked: the type must be msgTypeRecord; the length is the header's.
    if (len < TSNET_NOISE_HEADER_LEN + TSNET_AEAD_TAG_LEN || len > TSNET_NOISE_MAX_MESSAGE || frame[0] != MSG_RECORD ||
        get16be(frame + 1) != len - TSNET_NOISE_HEADER_LEN) {
        return -1;
    }
    uint8_t nonce[TSNET_AEAD_NONCE_LEN];
    if (next_nonce(&conn->rx, nonce) != 0) {
        return -1;
    }
    size_t pt_len = len - TSNET_NOISE_HEADER_LEN - TSNET_AEAD_TAG_LEN;
    if (tsnet_aead_open(plaintext, conn->rx.key, nonce, NULL, 0, frame + TSNET_NOISE_HEADER_LEN, pt_len) != 0) {
        return -1;
    }
    return (int)pt_len;
}

void tsnet_noise_conn_wipe(tsnet_noise_conn_t *conn)
{
    tsnet_wipe(conn, sizeof *conn);
}

size_t tsnet_noise_framer_feed(tsnet_noise_framer_t *f, const uint8_t *data, size_t len)
{
    size_t want = TSNET_NOISE_HEADER_LEN; // first the header, then up to the frame's end
    if (f->have >= TSNET_NOISE_HEADER_LEN) {
        if (tsnet_noise_framer_frame(f) < 0) {
            return 0; // a bad header takes nothing more
        }
        want = TSNET_NOISE_HEADER_LEN + get16be(f->buf + 1);
    }
    size_t taken = 0;
    while (taken < len && f->have < want) {
        f->buf[f->have++] = data[taken++];
        if (f->have == TSNET_NOISE_HEADER_LEN) { // the header is in: now we know the frame's length
            if (tsnet_noise_framer_frame(f) < 0) {
                return taken;
            }
            want = TSNET_NOISE_HEADER_LEN + get16be(f->buf + 1);
        }
    }
    return taken;
}

int tsnet_noise_framer_frame(const tsnet_noise_framer_t *f)
{
    if (f->have < TSNET_NOISE_HEADER_LEN) {
        return 0;
    }
    size_t total = TSNET_NOISE_HEADER_LEN + get16be(f->buf + 1);
    if (total > TSNET_NOISE_MAX_MESSAGE) {
        return -1;
    }
    return f->have == total ? (int)total : 0;
}

void tsnet_noise_framer_reset(tsnet_noise_framer_t *f)
{
    f->have = 0;
}
