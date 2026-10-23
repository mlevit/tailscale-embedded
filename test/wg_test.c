// Host test of WireGuard's messages: wireguard-go's own KDF vectors (device/kdf_test.go) and replay cases
// (replay/replay_test.go, from the Linux kernel's); then an independent reference's handshake, keys, transport and
// cookie, byte for byte (test/wg_vectors.h, tools/wg_vectors.py: the WireGuard paper on OpenSSL and libsodium); every
// changed byte; replays and floods; and a round trip with fresh ephemerals.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "platform.h"
#include "wg.h"
#include "wg_vectors.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static size_t unhex(uint8_t *out, const char *s)
{
    size_t n = 0;
    for (; s[0] && s[1]; s += 2) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t)v;
    }
    return n;
}

static void kdf(void)
{
    struct {
        const char *key, *input, *t0, *t1, *t2;
    } tests[] = {
        {"746573742d6b6579", "746573742d696e707574", "6f0e5ad38daba1bea8a0d213688736f19763239305e0f58aba697f9ffc41c633",
         "df1194df20802a4fe594cde27e92991c8cae66c366e8106aaa937a55fa371e8a",
         "fac6e2745a325f5dc5d11a5b165aad08b0ada28e7b4e666b7c077934a4d76c24"},
        {"776972656775617264", "776972656775617264", "491d43bbfdaa8750aaf535e334ecbfe5129967cd64635101c566d4caefda96e8",
         "1e71a379baefd8a79aa4662212fcafe19a23e2b609a3db7d6bcba8f560e3d25f",
         "31e1ae48bddfbe5de38f295e5452b1909a1b4e38e183926af3780b0c1e1f0160"},
        {"", "", "8387b46bf43eccfcf349552a095d8315c4055beb90208fb1be23b894bc2ed5d0",
         "58a0e5f6faefccf4807bff1f05fa8a9217945762040bcec2f4b4a62bdfe0e86e",
         "0ce6ea98ec548f8e281e93e32db65621c45eb18dc6f0a7ad94178610a2f7338e"},
    };
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        uint8_t key[32], in[32], w0[32], w1[32], w2[32], t0[32], t1[32], t2[32];
        size_t kl = unhex(key, tests[i].key), il = unhex(in, tests[i].input);
        unhex(w0, tests[i].t0);
        unhex(w1, tests[i].t1);
        unhex(w2, tests[i].t2);
        tsnet_wg_kdf(key, kl, in, il, t0, t1, t2);
        EXPECT(!memcmp(t0, w0, 32) && !memcmp(t1, w1, 32) && !memcmp(t2, w2, 32));
        tsnet_wg_kdf(key, kl, in, il, t0, t1, NULL); // KDF2
        EXPECT(!memcmp(t0, w0, 32) && !memcmp(t1, w1, 32));
        tsnet_wg_kdf(key, kl, in, il, t0, NULL, NULL); // KDF1
        EXPECT(!memcmp(t0, w0, 32));
    }
}

// TestReplay, the Linux kernel's cases as wireguard-go ports them.
#define REJECT_AFTER_MESSAGES (UINT64_MAX - ((uint64_t)1 << 13)) // 1<<64 - 1<<13 - 1
#define WINDOW ((128 - 1) * 64)
static tsnet_wg_replay_t filter;
static int replay_n;
static void T(uint64_t n, bool expected)
{
    replay_n++;
    if (tsnet_wg_replay_check(&filter, n, REJECT_AFTER_MESSAGES) != expected) {
        printf("replay test %d failed: %llu, want %d\n", replay_n, (unsigned long long)n, expected);
        failures++;
    }
}

static void replay(void)
{
    const uint64_t L = WINDOW + 1, R = REJECT_AFTER_MESSAGES;
    memset(&filter, 0, sizeof filter);
    tsnet_wg_replay_reset(&filter);
    T(0, true), T(1, true), T(1, false), T(9, true), T(8, true), T(7, true), T(7, false), T(L, true), T(L - 1, true);
    T(L - 1, false), T(L - 2, true), T(2, true), T(2, false), T(L + 16, true), T(3, false), T(L + 16, false);
    T(L * 4, true), T(L * 4 - (L - 1), true), T(10, false), T(L * 4 - L, false), T(L * 4 - (L + 1), false);
    T(L * 4 - (L - 2), true), T(L * 4 + 1 - L, false), T(0, false), T(R, false), T(R - 1, true), T(R, false);
    T(R - 1, false), T(R - 2, true), T(R + 1, false), T(R + 2, false), T(R - 2, false), T(R - 3, true), T(0, false);
    // The bulk tests.
    tsnet_wg_replay_reset(&filter);
    for (uint64_t i = 1; i <= WINDOW; i++) {
        T(i, true);
    }
    T(0, true), T(0, false);
    tsnet_wg_replay_reset(&filter);
    for (uint64_t i = 2; i <= WINDOW + 1; i++) {
        T(i, true);
    }
    T(1, true), T(0, false);
    tsnet_wg_replay_reset(&filter);
    for (uint64_t i = WINDOW + 1; i > 0; i--) {
        T(i, true);
    }
    tsnet_wg_replay_reset(&filter);
    for (uint64_t i = WINDOW + 2; i > 1; i--) {
        T(i, true);
    }
    T(0, false);
    tsnet_wg_replay_reset(&filter);
    for (uint64_t i = WINDOW; i > 0; i--) {
        T(i, true);
    }
    T(WINDOW + 1, true), T(0, false);
    tsnet_wg_replay_reset(&filter);
    for (uint64_t i = WINDOW; i > 0; i--) {
        T(i, true);
    }
    T(0, true), T(WINDOW + 1, true);
}

static void tai64n(void)
{
    uint8_t ts[12];
    tsnet_wg_tai64n(ts, 1792719090, 123456789);
    EXPECT(!memcmp(ts, WG_TIMESTAMP, 12)); // the low 24 bits of the nanoseconds whitened
}

// calculatePaddingSize: up to a multiple of 16, but never past the MTU.
static void padding(void)
{
    EXPECT(tsnet_wg_padding(0, 1280) == 0);    // a keepalive
    EXPECT(tsnet_wg_padding(37, 1280) == 11);  // to 48
    EXPECT(tsnet_wg_padding(48, 1280) == 0);
    EXPECT(tsnet_wg_padding(1275, 1280) == 5); // to 1280, the MTU
    EXPECT(tsnet_wg_padding(1279, 1280) == 1);
    EXPECT(tsnet_wg_padding(1280, 1280) == 0);
    EXPECT(tsnet_wg_padding(1273, 1278) == 5); // 1280 would pass this MTU: 1278 instead
    EXPECT(tsnet_wg_padding(1290, 1280) == 6); // over the MTU: the last unit (10) to 16
    EXPECT(tsnet_wg_padding(1275, 0) == 5);    // no MTU: to 1280 all the same
    EXPECT(tsnet_wg_padding(1281, 0) == 15);
}

// The reference's handshake, byte for byte, then its keys, transport and cookie.
static void vectors(void)
{
    const uint64_t now = 1000000;
    uint8_t pub_i[32], pub_r[32], msg[TSNET_WG_INITIATION_LEN], resp[TSNET_WG_RESPONSE_LEN];
    tsnet_x25519_public(pub_i, WG_S_I);
    tsnet_x25519_public(pub_r, WG_S_R);

    // The initiator.
    tsnet_wg_handshake_t hi, hr;
    EXPECT(tsnet_wg_handshake_init(&hi, WG_S_I, pub_r) == 0);
    EXPECT(tsnet_wg_create_initiation(&hi, pub_i, WG_IDX_I, WG_E_I, WG_TIMESTAMP, msg) == 0);
    tsnet_wg_cookiegen_t gen_i;
    tsnet_wg_cookiegen_init(&gen_i, pub_r);
    tsnet_wg_add_macs(&gen_i, msg, sizeof msg, now);
    EXPECT(memcmp(msg, WG_INITIATION, sizeof msg) == 0);

    // The responder: mac1, then the static key names the peer, then the rest.
    tsnet_wg_cookiecheck_t chk_r;
    tsnet_wg_cookiecheck_init(&chk_r, pub_r);
    EXPECT(tsnet_wg_check_mac1(&chk_r, WG_INITIATION, sizeof WG_INITIATION));
    tsnet_wg_initiation_t st;
    EXPECT(tsnet_wg_open_initiation(WG_S_R, pub_r, WG_INITIATION, &st) == 0);
    EXPECT(memcmp(st.remote_static, pub_i, 32) == 0 && st.sender == WG_IDX_I);
    EXPECT(tsnet_wg_handshake_init(&hr, WG_S_R, pub_i) == 0);
    EXPECT(tsnet_wg_accept_initiation(&hr, &st, WG_INITIATION, now) == 0);
    EXPECT(hr.state == TSNET_WG_HS_INITIATION_CONSUMED && hr.remote_index == WG_IDX_I);
    EXPECT(tsnet_wg_create_response(&hr, WG_IDX_R, WG_E_R, resp) == 0);
    tsnet_wg_cookiegen_t gen_r;
    tsnet_wg_cookiegen_init(&gen_r, pub_i);
    tsnet_wg_add_macs(&gen_r, resp, sizeof resp, now);
    EXPECT(memcmp(resp, WG_RESPONSE, sizeof resp) == 0);

    // The initiator takes the response; both derive the transport keys, each the other's mirror.
    EXPECT(tsnet_wg_consume_response(&hi, WG_S_I, WG_RESPONSE) == 0 && hi.remote_index == WG_IDX_R);
    tsnet_wg_keys_t ki, kr;
    EXPECT(tsnet_wg_derive_keys(&hi, &ki) == 0 && ki.initiator && hi.state == TSNET_WG_HS_ZEROED);
    EXPECT(tsnet_wg_derive_keys(&hr, &kr) == 0 && !kr.initiator);
    EXPECT(!memcmp(ki.send, WG_SEND_I, 32) && !memcmp(ki.recv, WG_RECV_I, 32));
    EXPECT(!memcmp(kr.send, WG_RECV_I, 32) && !memcmp(kr.recv, WG_SEND_I, 32));
    EXPECT(ki.local_index == WG_IDX_I && ki.remote_index == WG_IDX_R && kr.remote_index == WG_IDX_I);
    EXPECT(tsnet_wg_derive_keys(&hi, &ki) == -1); // zeroed: no second derivation

    // Transport: the payload (padded to 48) at counter 0, a keepalive at 1.
    uint8_t pkt[128], plain[128];
    int n = tsnet_wg_seal(pkt, sizeof pkt, WG_SEND_I, WG_IDX_R, 0, WG_PAYLOAD, sizeof WG_PAYLOAD, TSNET_WG_TUN_MTU);
    EXPECT(n == (int)sizeof WG_TRANSPORT0 && !memcmp(pkt, WG_TRANSPORT0, sizeof WG_TRANSPORT0));
    n = tsnet_wg_seal(pkt, sizeof pkt, WG_SEND_I, WG_IDX_R, 1, NULL, 0, TSNET_WG_TUN_MTU);
    EXPECT(n == TSNET_WG_KEEPALIVE_LEN && !memcmp(pkt, WG_TRANSPORT1, sizeof WG_TRANSPORT1));
    uint32_t receiver;
    uint64_t counter;
    EXPECT(tsnet_wg_transport_header(WG_TRANSPORT0, sizeof WG_TRANSPORT0, &receiver, &counter) == 0 &&
           receiver == WG_IDX_R && counter == 0);
    n = tsnet_wg_open(plain, sizeof plain, kr.recv, WG_TRANSPORT0, sizeof WG_TRANSPORT0);
    EXPECT(n == 48 && !memcmp(plain, WG_PAYLOAD, sizeof WG_PAYLOAD) && plain[47] == 0);
    EXPECT(tsnet_wg_open(plain, sizeof plain, kr.recv, WG_TRANSPORT1, sizeof WG_TRANSPORT1) == 0);
    EXPECT(tsnet_wg_seal(pkt, 40, WG_SEND_I, WG_IDX_R, 0, WG_PAYLOAD, sizeof WG_PAYLOAD, TSNET_WG_TUN_MTU) == -1); // doesn't fit

    // The cookie: the responder, under load, replies to the initiation for `src`; the initiator takes it, and its next
    // message carries mac2, which the responder checks for that source only, and only for 120 s.
    memcpy(chk_r.secret, WG_COOKIE_SECRET, 32);
    chk_r.secret_set_ms = now;
    uint8_t reply[TSNET_WG_COOKIE_REPLY_LEN];
    EXPECT(tsnet_wg_create_cookie_reply(&chk_r, WG_INITIATION, sizeof WG_INITIATION, WG_IDX_I, WG_COOKIE_SRC,
                                        sizeof WG_COOKIE_SRC, now, WG_COOKIE_REPLY + 8, reply) == 0);
    EXPECT(memcmp(reply, WG_COOKIE_REPLY, sizeof reply) == 0);
    EXPECT(tsnet_wg_consume_cookie_reply(&gen_i, WG_COOKIE_REPLY, now) && !memcmp(gen_i.cookie, WG_COOKIE, 16));
    memcpy(msg, WG_INITIATION, sizeof msg);
    tsnet_wg_add_macs(&gen_i, msg, sizeof msg, now + 1000);
    EXPECT(memcmp(msg, WG_INITIATION2, sizeof msg) == 0);
    EXPECT(tsnet_wg_check_mac1(&chk_r, msg, sizeof msg));
    EXPECT(tsnet_wg_check_mac2(&chk_r, msg, sizeof msg, WG_COOKIE_SRC, sizeof WG_COOKIE_SRC, now + 1000));
    uint8_t other_src[6];
    memcpy(other_src, WG_COOKIE_SRC, 6);
    other_src[5] ^= 1;
    EXPECT(!tsnet_wg_check_mac2(&chk_r, msg, sizeof msg, other_src, 6, now + 1000));
    EXPECT(!tsnet_wg_check_mac2(&chk_r, msg, sizeof msg, WG_COOKIE_SRC, 6, now + TSNET_WG_COOKIE_REFRESH_MS + 1));
    EXPECT(!tsnet_wg_check_mac2(&chk_r, WG_INITIATION, sizeof WG_INITIATION, WG_COOKIE_SRC, 6, now)); // no mac2
    // A stale cookie isn't used: mac2 left as it was.
    memcpy(msg, WG_INITIATION, sizeof msg);
    tsnet_wg_add_macs(&gen_i, msg, sizeof msg, now + TSNET_WG_COOKIE_REFRESH_MS + 1);
    EXPECT(memcmp(msg, WG_INITIATION, sizeof msg) == 0);
    // A reply for a different mac1 doesn't open; nor does any changed byte.
    tsnet_wg_cookiegen_t fresh;
    tsnet_wg_cookiegen_init(&fresh, pub_r);
    EXPECT(!tsnet_wg_consume_cookie_reply(&fresh, WG_COOKIE_REPLY, now)); // no message sent yet
    for (size_t i = 0; i < sizeof reply; i++) {
        memcpy(reply, WG_COOKIE_REPLY, sizeof reply);
        reply[i] ^= 0x01;
        tsnet_wg_cookiegen_t g = gen_i;
        if (i >= 4 && i < 8) {
            continue; // the receiver index: the caller's routing, not covered by the box
        }
        EXPECT(!tsnet_wg_consume_cookie_reply(&g, reply, now));
    }
}

// Every changed byte of the initiation and the response fails (mac1 by its own check), as does any truncation of a
// transport message; the same initiation twice is a replay, and a newer one within 50 ms a flood.
static void tampering(void)
{
    const uint64_t now = 1000000;
    uint8_t pub_i[32], pub_r[32], msg[TSNET_WG_INITIATION_LEN];
    tsnet_x25519_public(pub_i, WG_S_I);
    tsnet_x25519_public(pub_r, WG_S_R);
    tsnet_wg_cookiecheck_t chk_r;
    tsnet_wg_cookiecheck_init(&chk_r, pub_r);
    for (size_t i = 0; i < 116; i++) {
        memcpy(msg, WG_INITIATION, sizeof msg);
        msg[i] ^= 0x04;
        tsnet_wg_initiation_t st;
        tsnet_wg_handshake_t hr;
        tsnet_wg_handshake_init(&hr, WG_S_R, pub_i);
        bool ok = tsnet_wg_check_mac1(&chk_r, msg, sizeof msg) && tsnet_wg_open_initiation(WG_S_R, pub_r, msg, &st) == 0 &&
                  tsnet_wg_accept_initiation(&hr, &st, msg, now) == 0;
        EXPECT(!ok);
    }
    for (size_t i = 116; i < 132; i++) { // mac1 itself
        memcpy(msg, WG_INITIATION, sizeof msg);
        msg[i] ^= 0x04;
        EXPECT(!tsnet_wg_check_mac1(&chk_r, msg, sizeof msg));
    }
    // Replay and flood.
    tsnet_wg_handshake_t hr;
    tsnet_wg_handshake_init(&hr, WG_S_R, pub_i);
    tsnet_wg_initiation_t st;
    EXPECT(tsnet_wg_open_initiation(WG_S_R, pub_r, WG_INITIATION, &st) == 0 &&
           tsnet_wg_accept_initiation(&hr, &st, WG_INITIATION, now) == 0);
    EXPECT(tsnet_wg_open_initiation(WG_S_R, pub_r, WG_INITIATION, &st) == 0 &&
           tsnet_wg_accept_initiation(&hr, &st, WG_INITIATION, now + 10000) == -1); // the same timestamp: a replay
    tsnet_wg_handshake_t hi;
    tsnet_wg_handshake_init(&hi, WG_S_I, pub_r);
    uint8_t ts[12];
    tsnet_wg_tai64n(ts, 1792719091, 0); // a second later
    EXPECT(tsnet_wg_create_initiation(&hi, pub_i, 7, NULL, ts, msg) == 0);
    EXPECT(tsnet_wg_open_initiation(WG_S_R, pub_r, msg, &st) == 0 &&
           tsnet_wg_accept_initiation(&hr, &st, msg, now + TSNET_WG_INIT_RATE_MS) == -1); // a flood
    EXPECT(tsnet_wg_open_initiation(WG_S_R, pub_r, msg, &st) == 0 &&
           tsnet_wg_accept_initiation(&hr, &st, msg, now + TSNET_WG_INIT_RATE_MS + 1) == 0);
    // An initiation for a peer whose handshake isn't the one it names.
    tsnet_wg_handshake_t wrong;
    uint8_t other[32];
    tsnet_x25519_public(other, WG_E_R);
    tsnet_wg_handshake_init(&wrong, WG_S_R, other);
    EXPECT(tsnet_wg_open_initiation(WG_S_R, pub_r, WG_INITIATION, &st) == 0 &&
           tsnet_wg_accept_initiation(&wrong, &st, WG_INITIATION, now) == -1);

    // The response: every byte up to and including mac1. The sender index (bytes 4 to 7) is outside the AEAD, as the
    // initiation's is: mac1 covers it, so a receiver checks mac1 first, as wireguard-go's RoutineHandshake does.
    tsnet_wg_cookiecheck_t chk_i;
    tsnet_wg_cookiecheck_init(&chk_i, pub_i);
    EXPECT(tsnet_wg_check_mac1(&chk_i, WG_RESPONSE, sizeof WG_RESPONSE));
    for (size_t i = 0; i < 76; i++) {
        uint8_t resp[TSNET_WG_RESPONSE_LEN];
        memcpy(resp, WG_RESPONSE, sizeof resp);
        resp[i] ^= 0x04;
        tsnet_wg_handshake_t h;
        tsnet_wg_handshake_init(&h, WG_S_I, pub_r);
        tsnet_wg_create_initiation(&h, pub_i, WG_IDX_I, WG_E_I, WG_TIMESTAMP, msg);
        EXPECT(!(tsnet_wg_check_mac1(&chk_i, resp, sizeof resp) && tsnet_wg_consume_response(&h, WG_S_I, resp) == 0));
    }
    // A response with no initiation outstanding.
    tsnet_wg_handshake_t idle;
    tsnet_wg_handshake_init(&idle, WG_S_I, pub_r);
    EXPECT(tsnet_wg_consume_response(&idle, WG_S_I, WG_RESPONSE) == -1);
    EXPECT(tsnet_wg_create_response(&idle, 1, NULL, msg) == -1);

    // Transport: every changed byte past the type and every truncation.
    uint8_t plain[128], pkt[128];
    for (size_t i = 4; i < sizeof WG_TRANSPORT0; i++) {
        memcpy(pkt, WG_TRANSPORT0, sizeof WG_TRANSPORT0);
        pkt[i] ^= 0x80;
        if (i >= 4 && i < 8) {
            continue; // the receiver index picks the keypair; the box doesn't cover it
        }
        EXPECT(tsnet_wg_open(plain, sizeof plain, WG_SEND_I, pkt, sizeof WG_TRANSPORT0) == -1);
    }
    for (size_t len = 0; len < sizeof WG_TRANSPORT0; len++) {
        EXPECT(tsnet_wg_open(plain, sizeof plain, WG_SEND_I, WG_TRANSPORT0, len) == -1);
    }
}

// Both roles with fresh ephemerals and a real clock's timestamp: the keys match and data goes both ways.
static void round_trip(void)
{
    uint8_t si[32], sr[32], pi[32], pr[32], msg[TSNET_WG_INITIATION_LEN], resp[TSNET_WG_RESPONSE_LEN], ts[12];
    tsnet_random(si, 32);
    tsnet_random(sr, 32);
    si[0] &= 248, si[31] = (uint8_t)((si[31] & 127) | 64);
    sr[0] &= 248, sr[31] = (uint8_t)((sr[31] & 127) | 64);
    tsnet_x25519_public(pi, si);
    tsnet_x25519_public(pr, sr);
    tsnet_wg_tai64n(ts, 1792719090, 0);
    tsnet_wg_handshake_t hi, hr;
    tsnet_wg_handshake_init(&hi, si, pr);
    tsnet_wg_handshake_init(&hr, sr, pi);
    EXPECT(tsnet_wg_create_initiation(&hi, pi, 11, NULL, ts, msg) == 0);
    tsnet_wg_initiation_t st;
    EXPECT(tsnet_wg_open_initiation(sr, pr, msg, &st) == 0 && tsnet_wg_accept_initiation(&hr, &st, msg, 5) == 0);
    EXPECT(tsnet_wg_create_response(&hr, 22, NULL, resp) == 0);
    EXPECT(tsnet_wg_consume_response(&hi, si, resp) == 0);
    tsnet_wg_keys_t ki, kr;
    EXPECT(tsnet_wg_derive_keys(&hi, &ki) == 0 && tsnet_wg_derive_keys(&hr, &kr) == 0);
    EXPECT(!memcmp(ki.send, kr.recv, 32) && !memcmp(ki.recv, kr.send, 32) && memcmp(ki.send, ki.recv, 32) != 0);
    uint8_t pkt[1600], back[1600], data[1400];
    tsnet_random(data, sizeof data);
    int n = tsnet_wg_seal(pkt, sizeof pkt, kr.send, ki.local_index, 42, data, sizeof data, 0);
    EXPECT(n == TSNET_WG_TRANSPORT_HEADER + 1408 + 16);
    EXPECT(tsnet_wg_open(back, sizeof back, ki.recv, pkt, (size_t)n) == 1408 && !memcmp(back, data, sizeof data));
    EXPECT(tsnet_wg_open(back, sizeof back, ki.send, pkt, (size_t)n) == -1); // the wrong direction's key
}

int main(void)
{
    kdf();
    replay();
    tai64n();
    padding();
    vectors();
    tampering();
    round_trip();
    if (failures == 0) {
        printf("tsnet wg_test: ok\n");
    }
    return failures != 0;
}
