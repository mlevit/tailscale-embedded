// WireGuard's messages. See wg.h; the Go is Tailscale's wireguard-go fork, device/noise-protocol.go and
// cookie.go, replay/replay.go and tai64n/tai64n.go.
#include "wg.h"
#include <string.h>
#include "blake2s.h"
#include "crypto.h"
#include "monocypher.h"
#include "platform.h"

static const char CONSTRUCTION[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char IDENTIFIER[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static const char LABEL_MAC1[] = "mac1----";
static const char LABEL_COOKIE[] = "cookie--";
static const uint8_t ZERO_NONCE[TSNET_AEAD_NONCE_LEN];
static const uint8_t ZERO_PSK[32]; // Tailscale sets no preshared key

static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

static uint64_t get64(const uint8_t *p)
{
    return (uint64_t)get32(p) | (uint64_t)get32(p + 4) << 32;
}

static bool is_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc |= p[i];
    }
    return acc == 0;
}

static bool ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc |= a[i] ^ b[i];
    }
    return acc == 0;
}

void tsnet_wg_kdf(const uint8_t *key, size_t key_len, const uint8_t *in, size_t len, uint8_t t0[32], uint8_t t1[32],
                  uint8_t t2[32])
{
    uint8_t prk[32], a[32], b[33];
    tsnet_hmac_blake2s(prk, key, key_len, in, len);
    b[0] = 0x1;
    tsnet_hmac_blake2s(a, prk, 32, b, 1);
    memcpy(t0, a, 32);
    if (t1 || t2) {
        memcpy(b, a, 32);
        b[32] = 0x2;
        tsnet_hmac_blake2s(a, prk, 32, b, 33);
        if (t1) {
            memcpy(t1, a, 32);
        }
        if (t2) {
            memcpy(b, a, 32);
            b[32] = 0x3;
            tsnet_hmac_blake2s(t2, prk, 32, b, 33);
        }
    }
    tsnet_wipe(prk, sizeof prk);
    tsnet_wipe(a, sizeof a);
    tsnet_wipe(b, sizeof b);
}

void tsnet_wg_tai64n(uint8_t out[TSNET_WG_TIMESTAMP_LEN], int64_t unix_secs, uint32_t nanos)
{
    uint64_t secs = 0x400000000000000aULL + (uint64_t)unix_secs;
    uint32_t n = nanos & ~(uint32_t)0xffffff; // whitenerMask
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(secs >> (56 - 8 * i));
    }
    for (int i = 0; i < 4; i++) {
        out[8 + i] = (uint8_t)(n >> (24 - 8 * i));
    }
}

// mixHash: h = BLAKE2s(h || data).
static void mix_hash(uint8_t h[32], const uint8_t *data, size_t len)
{
    tsnet_blake2s_t s;
    tsnet_blake2s_init(&s, 32, NULL, 0);
    tsnet_blake2s_update(&s, h, 32);
    tsnet_blake2s_update(&s, data, len);
    tsnet_blake2s_final(&s, h);
}

// mixKey: ck = KDF1(ck, data).
static void mix_key(uint8_t ck[32], const uint8_t *data, size_t len)
{
    tsnet_wg_kdf(ck, 32, data, len, ck, NULL, NULL);
}

// InitialChainKey and InitialHash.
static void initial(uint8_t ck[32], uint8_t h[32])
{
    tsnet_blake2s(ck, 32, NULL, 0, CONSTRUCTION, sizeof CONSTRUCTION - 1);
    memcpy(h, ck, 32);
    mix_hash(h, (const uint8_t *)IDENTIFIER, sizeof IDENTIFIER - 1);
}

// newPrivateKey: random, clamped. Or the one given (tests).
static int ephemeral(uint8_t out[32], const uint8_t *given)
{
    if (given) {
        memcpy(out, given, 32);
    } else if (tsnet_random(out, 32) != 0) {
        return -1;
    }
    out[0] &= 248;
    out[31] = (uint8_t)((out[31] & 127) | 64);
    return 0;
}

int tsnet_wg_handshake_init(tsnet_wg_handshake_t *hs, const uint8_t local_priv[32], const uint8_t remote_pub[32])
{
    memset(hs, 0, sizeof *hs);
    memcpy(hs->remote_static, remote_pub, 32);
    if (tsnet_x25519(hs->ss, local_priv, remote_pub) != 0) {
        memset(hs->ss, 0, sizeof hs->ss);
        return -1;
    }
    return 0;
}

void tsnet_wg_handshake_clear(tsnet_wg_handshake_t *hs)
{
    tsnet_wipe(hs->local_eph, sizeof hs->local_eph);
    tsnet_wipe(hs->remote_eph, sizeof hs->remote_eph);
    tsnet_wipe(hs->ck, sizeof hs->ck);
    tsnet_wipe(hs->hash, sizeof hs->hash);
    hs->local_index = 0;
    hs->state = TSNET_WG_HS_ZEROED;
}

int tsnet_wg_create_initiation(tsnet_wg_handshake_t *hs, const uint8_t local_pub[32], uint32_t local_index,
                               const uint8_t *eph, const uint8_t timestamp[TSNET_WG_TIMESTAMP_LEN],
                               uint8_t out[TSNET_WG_INITIATION_LEN])
{
    uint8_t ss[32], key[32];
    int rc = -1;
    memset(out, 0, TSNET_WG_INITIATION_LEN);
    initial(hs->ck, hs->hash);
    if (ephemeral(hs->local_eph, eph) != 0) {
        goto done;
    }
    mix_hash(hs->hash, hs->remote_static, 32);
    put32(out, TSNET_WG_INITIATION);
    put32(out + 4, local_index);
    uint8_t *e = out + 8, *st = out + 40, *ts = out + 88;
    if (tsnet_x25519_public(e, hs->local_eph) != 0) {
        goto done;
    }
    mix_key(hs->ck, e, 32);
    mix_hash(hs->hash, e, 32);
    // The static key, encrypted.
    if (tsnet_x25519(ss, hs->local_eph, hs->remote_static) != 0) {
        goto done;
    }
    tsnet_wg_kdf(hs->ck, 32, ss, 32, hs->ck, key, NULL);
    tsnet_aead_seal(st, key, ZERO_NONCE, hs->hash, 32, local_pub, 32);
    mix_hash(hs->hash, st, 48);
    // The timestamp, encrypted.
    if (is_zero(hs->ss, 32)) {
        goto done; // errInvalidPublicKey
    }
    tsnet_wg_kdf(hs->ck, 32, hs->ss, 32, hs->ck, key, NULL);
    tsnet_aead_seal(ts, key, ZERO_NONCE, hs->hash, 32, timestamp, TSNET_WG_TIMESTAMP_LEN);
    hs->local_index = local_index;
    mix_hash(hs->hash, ts, 28);
    hs->state = TSNET_WG_HS_INITIATION_CREATED;
    rc = 0;
done:
    tsnet_wipe(ss, sizeof ss);
    tsnet_wipe(key, sizeof key);
    return rc;
}

int tsnet_wg_open_initiation(const uint8_t local_priv[32], const uint8_t local_pub[32],
                             const uint8_t msg[TSNET_WG_INITIATION_LEN], tsnet_wg_initiation_t *st)
{
    uint8_t ss[32], key[32], c0[32];
    int rc = -1;
    memset(st, 0, sizeof *st);
    if (get32(msg) != TSNET_WG_INITIATION) {
        return -1;
    }
    const uint8_t *e = msg + 8, *enc_static = msg + 40;
    initial(c0, st->hash);
    mix_hash(st->hash, local_pub, 32);
    mix_hash(st->hash, e, 32);
    memcpy(st->ck, c0, 32);
    mix_key(st->ck, e, 32);
    if (tsnet_x25519(ss, local_priv, e) != 0) {
        goto done;
    }
    tsnet_wg_kdf(st->ck, 32, ss, 32, st->ck, key, NULL);
    if (tsnet_aead_open(st->remote_static, key, ZERO_NONCE, st->hash, 32, enc_static, 32) != 0) {
        goto done;
    }
    mix_hash(st->hash, enc_static, 48);
    memcpy(st->remote_eph, e, 32);
    st->sender = get32(msg + 4);
    rc = 0;
done:
    tsnet_wipe(ss, sizeof ss);
    tsnet_wipe(key, sizeof key);
    if (rc != 0) {
        tsnet_wipe(st, sizeof *st);
    }
    return rc;
}

int tsnet_wg_accept_initiation(tsnet_wg_handshake_t *hs, tsnet_wg_initiation_t *st,
                               const uint8_t msg[TSNET_WG_INITIATION_LEN], uint64_t now_ms)
{
    uint8_t key[32], ts[TSNET_WG_TIMESTAMP_LEN];
    int rc = -1;
    if (is_zero(hs->ss, 32) || memcmp(st->remote_static, hs->remote_static, 32) != 0) {
        goto done;
    }
    const uint8_t *enc_ts = msg + 88;
    tsnet_wg_kdf(st->ck, 32, hs->ss, 32, st->ck, key, NULL);
    if (tsnet_aead_open(ts, key, ZERO_NONCE, st->hash, 32, enc_ts, TSNET_WG_TIMESTAMP_LEN) != 0) {
        goto done;
    }
    mix_hash(st->hash, enc_ts, 28);
    // Against replays (a timestamp not newer than the last) and floods (initiations under 50 ms apart).
    bool replay = memcmp(ts, hs->last_timestamp, TSNET_WG_TIMESTAMP_LEN) <= 0;
    bool flood = hs->last_init_ms != 0 && now_ms - hs->last_init_ms <= TSNET_WG_INIT_RATE_MS;
    if (replay || flood) {
        goto done;
    }
    memcpy(hs->hash, st->hash, 32);
    memcpy(hs->ck, st->ck, 32);
    hs->remote_index = st->sender;
    memcpy(hs->remote_eph, st->remote_eph, 32);
    memcpy(hs->last_timestamp, ts, TSNET_WG_TIMESTAMP_LEN);
    hs->last_init_ms = now_ms ? now_ms : 1;
    hs->state = TSNET_WG_HS_INITIATION_CONSUMED;
    rc = 0;
done:
    tsnet_wipe(key, sizeof key);
    tsnet_wipe(st, sizeof *st);
    return rc;
}

int tsnet_wg_create_response(tsnet_wg_handshake_t *hs, uint32_t local_index, const uint8_t *eph,
                             uint8_t out[TSNET_WG_RESPONSE_LEN])
{
    uint8_t ss[32], tau[32], key[32];
    int rc = -1;
    memset(out, 0, TSNET_WG_RESPONSE_LEN);
    if (hs->state != TSNET_WG_HS_INITIATION_CONSUMED) {
        return -1; // the initiation must be consumed first
    }
    hs->local_index = local_index;
    put32(out, TSNET_WG_RESPONSE);
    put32(out + 4, local_index);
    put32(out + 8, hs->remote_index);
    uint8_t *e = out + 12, *empty = out + 44;
    if (ephemeral(hs->local_eph, eph) != 0 || tsnet_x25519_public(e, hs->local_eph) != 0) {
        goto done;
    }
    mix_hash(hs->hash, e, 32);
    mix_key(hs->ck, e, 32);
    if (tsnet_x25519(ss, hs->local_eph, hs->remote_eph) != 0) {
        goto done;
    }
    mix_key(hs->ck, ss, 32);
    if (tsnet_x25519(ss, hs->local_eph, hs->remote_static) != 0) {
        goto done;
    }
    mix_key(hs->ck, ss, 32);
    tsnet_wg_kdf(hs->ck, 32, ZERO_PSK, 32, hs->ck, tau, key);
    mix_hash(hs->hash, tau, 32);
    tsnet_aead_seal(empty, key, ZERO_NONCE, hs->hash, 32, NULL, 0);
    mix_hash(hs->hash, empty, 16);
    hs->state = TSNET_WG_HS_RESPONSE_CREATED;
    rc = 0;
done:
    tsnet_wipe(ss, sizeof ss);
    tsnet_wipe(tau, sizeof tau);
    tsnet_wipe(key, sizeof key);
    return rc;
}

int tsnet_wg_consume_response(tsnet_wg_handshake_t *hs, const uint8_t local_priv[32],
                              const uint8_t msg[TSNET_WG_RESPONSE_LEN])
{
    uint8_t h[32], ck[32], ss[32], tau[32], key[32];
    int rc = -1;
    if (get32(msg) != TSNET_WG_RESPONSE || hs->state != TSNET_WG_HS_INITIATION_CREATED ||
        get32(msg + 8) != hs->local_index) {
        return -1;
    }
    const uint8_t *e = msg + 12, *empty = msg + 44;
    memcpy(h, hs->hash, 32);
    memcpy(ck, hs->ck, 32);
    mix_hash(h, e, 32);
    mix_key(ck, e, 32);
    if (tsnet_x25519(ss, hs->local_eph, e) != 0) {
        goto done;
    }
    mix_key(ck, ss, 32);
    if (tsnet_x25519(ss, local_priv, e) != 0) {
        goto done;
    }
    mix_key(ck, ss, 32);
    tsnet_wg_kdf(ck, 32, ZERO_PSK, 32, ck, tau, key);
    mix_hash(h, tau, 32);
    uint8_t nothing[1];
    if (tsnet_aead_open(nothing, key, ZERO_NONCE, h, 32, empty, 0) != 0) {
        goto done; // the transcript doesn't authenticate
    }
    mix_hash(h, empty, 16);
    memcpy(hs->hash, h, 32);
    memcpy(hs->ck, ck, 32);
    hs->remote_index = get32(msg + 4);
    hs->state = TSNET_WG_HS_RESPONSE_CONSUMED;
    rc = 0;
done:
    tsnet_wipe(h, sizeof h);
    tsnet_wipe(ck, sizeof ck);
    tsnet_wipe(ss, sizeof ss);
    tsnet_wipe(tau, sizeof tau);
    tsnet_wipe(key, sizeof key);
    return rc;
}

int tsnet_wg_derive_keys(tsnet_wg_handshake_t *hs, tsnet_wg_keys_t *keys)
{
    memset(keys, 0, sizeof *keys);
    if (hs->state == TSNET_WG_HS_RESPONSE_CONSUMED) {
        tsnet_wg_kdf(hs->ck, 32, NULL, 0, keys->send, keys->recv, NULL);
        keys->initiator = true;
    } else if (hs->state == TSNET_WG_HS_RESPONSE_CREATED) {
        tsnet_wg_kdf(hs->ck, 32, NULL, 0, keys->recv, keys->send, NULL);
    } else {
        return -1;
    }
    keys->local_index = hs->local_index;
    keys->remote_index = hs->remote_index;
    tsnet_wipe(hs->ck, sizeof hs->ck);
    tsnet_wipe(hs->hash, sizeof hs->hash);
    tsnet_wipe(hs->local_eph, sizeof hs->local_eph);
    hs->state = TSNET_WG_HS_ZEROED;
    return 0;
}

// BLAKE2s(label || pk): the mac1 key and the cookie encryption key.
static void labelled(uint8_t out[32], const char *label, const uint8_t pk[32])
{
    tsnet_blake2s_t s;
    tsnet_blake2s_init(&s, 32, NULL, 0);
    tsnet_blake2s_update(&s, label, 8);
    tsnet_blake2s_update(&s, pk, 32);
    tsnet_blake2s_final(&s, out);
}

void tsnet_wg_cookiegen_init(tsnet_wg_cookiegen_t *g, const uint8_t remote_pub[32])
{
    memset(g, 0, sizeof *g);
    labelled(g->mac1_key, LABEL_MAC1, remote_pub);
    labelled(g->cookie_key, LABEL_COOKIE, remote_pub);
}

static bool fresh(uint64_t set_ms, uint64_t now_ms)
{
    return set_ms != 0 && now_ms - set_ms <= TSNET_WG_COOKIE_REFRESH_MS;
}

void tsnet_wg_add_macs(tsnet_wg_cookiegen_t *g, uint8_t *msg, size_t len, uint64_t now_ms)
{
    uint8_t *mac1 = msg + len - 32, *mac2 = msg + len - 16;
    tsnet_blake2s(mac1, 16, g->mac1_key, 32, msg, len - 32);
    memcpy(g->last_mac1, mac1, 16);
    g->has_last_mac1 = true;
    if (!fresh(g->cookie_set_ms, now_ms)) {
        return; // no cookie, or a stale one: mac2 stays as it is
    }
    tsnet_blake2s(mac2, 16, g->cookie, 16, msg, len - 16);
}

bool tsnet_wg_consume_cookie_reply(tsnet_wg_cookiegen_t *g, const uint8_t msg[TSNET_WG_COOKIE_REPLY_LEN],
                                   uint64_t now_ms)
{
    if (!g->has_last_mac1 || get32(msg) != TSNET_WG_COOKIE_REPLY) {
        return false;
    }
    uint8_t cookie[16];
    if (crypto_aead_unlock(cookie, msg + 48, g->cookie_key, msg + 8, g->last_mac1, 16, msg + 32, 16) != 0) {
        return false;
    }
    memcpy(g->cookie, cookie, 16);
    g->cookie_set_ms = now_ms ? now_ms : 1;
    tsnet_wipe(cookie, sizeof cookie);
    return true;
}

void tsnet_wg_cookiecheck_init(tsnet_wg_cookiecheck_t *c, const uint8_t local_pub[32])
{
    memset(c, 0, sizeof *c);
    labelled(c->mac1_key, LABEL_MAC1, local_pub);
    labelled(c->cookie_key, LABEL_COOKIE, local_pub);
}

bool tsnet_wg_check_mac1(const tsnet_wg_cookiecheck_t *c, const uint8_t *msg, size_t len)
{
    if (len < 32) {
        return false;
    }
    uint8_t mac1[16];
    tsnet_blake2s(mac1, 16, c->mac1_key, 32, msg, len - 32);
    return ct_equal(mac1, msg + len - 32, 16);
}

bool tsnet_wg_check_mac2(const tsnet_wg_cookiecheck_t *c, const uint8_t *msg, size_t len, const uint8_t *src,
                         size_t src_len, uint64_t now_ms)
{
    if (len < 32 || !fresh(c->secret_set_ms, now_ms)) {
        return false;
    }
    uint8_t cookie[16], mac2[16];
    tsnet_blake2s(cookie, 16, c->secret, 32, src, src_len);
    tsnet_blake2s(mac2, 16, cookie, 16, msg, len - 16);
    return ct_equal(mac2, msg + len - 16, 16);
}

int tsnet_wg_create_cookie_reply(tsnet_wg_cookiecheck_t *c, const uint8_t *msg, size_t len, uint32_t receiver,
                                 const uint8_t *src, size_t src_len, uint64_t now_ms, const uint8_t *nonce,
                                 uint8_t out[TSNET_WG_COOKIE_REPLY_LEN])
{
    if (len < 32) {
        return -1;
    }
    if (!fresh(c->secret_set_ms, now_ms)) {
        if (tsnet_random(c->secret, sizeof c->secret) != 0) {
            return -1;
        }
        c->secret_set_ms = now_ms ? now_ms : 1;
    }
    uint8_t cookie[16];
    tsnet_blake2s(cookie, 16, c->secret, 32, src, src_len);
    put32(out, TSNET_WG_COOKIE_REPLY);
    put32(out + 4, receiver);
    if (nonce) {
        memcpy(out + 8, nonce, 24);
    } else if (tsnet_random(out + 8, 24) != 0) {
        return -1;
    }
    crypto_aead_lock(out + 32, out + 48, c->cookie_key, out + 8, msg + len - 32, 16, cookie, 16);
    tsnet_wipe(cookie, sizeof cookie);
    return 0;
}

void tsnet_wg_replay_reset(tsnet_wg_replay_t *f)
{
    f->last = 0;
    f->ring[0] = 0;
}

#define BLOCK_BITS 64
#define RING_BLOCKS 128
#define WINDOW_SIZE ((RING_BLOCKS - 1) * BLOCK_BITS)

bool tsnet_wg_replay_check(tsnet_wg_replay_t *f, uint64_t counter, uint64_t limit)
{
    if (counter >= limit) {
        return false;
    }
    uint64_t index_block = counter >> 6;
    if (counter > f->last) { // move the window forward
        uint64_t current = f->last >> 6;
        uint64_t diff = index_block - current;
        if (diff > RING_BLOCKS) {
            diff = RING_BLOCKS; // clear the whole ring at most
        }
        for (uint64_t i = current + 1; i <= current + diff; i++) {
            f->ring[i & (RING_BLOCKS - 1)] = 0;
        }
        f->last = counter;
    } else if (f->last - counter > WINDOW_SIZE) { // behind the window
        return false;
    }
    index_block &= RING_BLOCKS - 1;
    uint64_t bit = (uint64_t)1 << (counter & (BLOCK_BITS - 1));
    uint64_t old = f->ring[index_block];
    f->ring[index_block] = old | bit;
    return old != (old | bit);
}

static void transport_nonce(uint8_t nonce[TSNET_AEAD_NONCE_LEN], uint64_t counter)
{
    memset(nonce, 0, 4);
    put64(nonce + 4, counter);
}

size_t tsnet_wg_padding(size_t len, size_t mtu)
{
    size_t last = len;
    if (mtu == 0) {
        return ((last + 15) & ~(size_t)15) - last;
    }
    if (last > mtu) {
        last %= mtu;
    }
    size_t padded = (last + 15) & ~(size_t)15;
    if (padded > mtu) {
        padded = mtu;
    }
    return padded - last;
}

int tsnet_wg_seal(uint8_t *out, size_t cap, const uint8_t key[32], uint32_t receiver, uint64_t counter,
                  const uint8_t *payload, size_t len, size_t mtu)
{
    size_t padded = len + tsnet_wg_padding(len, mtu);
    size_t total = TSNET_WG_TRANSPORT_HEADER + padded + TSNET_AEAD_TAG_LEN;
    if (cap < total) {
        return -1;
    }
    put32(out, TSNET_WG_TRANSPORT);
    put32(out + 4, receiver);
    put64(out + 8, counter);
    uint8_t *body = out + TSNET_WG_TRANSPORT_HEADER;
    if (len) {
        memmove(body, payload, len);
    }
    memset(body + len, 0, padded - len);
    uint8_t nonce[TSNET_AEAD_NONCE_LEN];
    transport_nonce(nonce, counter);
    if (tsnet_aead_seal(body, key, nonce, NULL, 0, body, padded) != 0) {
        return -1;
    }
    return (int)total;
}

int tsnet_wg_transport_header(const uint8_t *pkt, size_t len, uint32_t *receiver, uint64_t *counter)
{
    if (len < TSNET_WG_KEEPALIVE_LEN || get32(pkt) != TSNET_WG_TRANSPORT) {
        return -1;
    }
    *receiver = get32(pkt + 4);
    *counter = get64(pkt + 8);
    return 0;
}

int tsnet_wg_open(uint8_t *out, size_t cap, const uint8_t key[32], const uint8_t *pkt, size_t len)
{
    uint32_t receiver;
    uint64_t counter;
    if (tsnet_wg_transport_header(pkt, len, &receiver, &counter) != 0) {
        return -1;
    }
    size_t n = len - TSNET_WG_TRANSPORT_HEADER - TSNET_AEAD_TAG_LEN;
    if (cap < n) {
        return -1;
    }
    uint8_t nonce[TSNET_AEAD_NONCE_LEN];
    transport_nonce(nonce, counter);
    if (tsnet_aead_open(out, key, nonce, NULL, 0, pkt + TSNET_WG_TRANSPORT_HEADER, n) != 0) {
        return -1;
    }
    return (int)n;
}
