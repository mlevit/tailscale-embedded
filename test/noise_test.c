// Host test of tsnet's controlbase client, against the separately written responder in responder.h. The
// byte-exact check against Tailscale itself is the live probe (probe.c).
#include <stdio.h>
#include <string.h>
#include "blake2s.h"
#include "crypto.h"
#include "noise.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

#include "responder.h"

static void key(uint8_t k[32], uint8_t seed)
{
    for (int i = 0; i < 32; i++) {
        k[i] = (uint8_t)(seed + 7 * i);
    }
}

int main(void)
{
    uint8_t machine[32], machine_pub[32], control[32], control_pub[32], c_eph[32], s_eph[32];
    key(machine, 1);
    key(control, 2);
    key(c_eph, 3);
    key(s_eph, 4);
    tsnet_x25519_public(machine_pub, machine);
    tsnet_x25519_public(control_pub, control);

    // A full handshake: the server learns our machine key, both ends agree on the keys.
    tsnet_noise_client_t c;
    uint8_t init[TSNET_NOISE_INIT_LEN], resp[TSNET_NOISE_RESP_LEN], got_machine[32];
    tsnet_noise_conn_t cc, sc;
    EXPECT(tsnet_noise_client_start_with(&c, machine, control_pub, 131, c_eph, init) == 0);
    EXPECT(init[0] == 0 && init[1] == 131 && init[2] == 1 && init[3] == 0 && init[4] == 96); // version, type, length
    EXPECT(serve(131, control, s_eph, init, resp, got_machine, &sc) == 0);
    EXPECT(memcmp(got_machine, machine_pub, 32) == 0);
    EXPECT(tsnet_noise_client_finish(&c, resp, sizeof resp, &cc) == 0);
    EXPECT(memcmp(cc.tx.key, sc.rx.key, 32) == 0);
    EXPECT(memcmp(cc.rx.key, sc.tx.key, 32) == 0);
    EXPECT(memcmp(cc.tx.key, cc.rx.key, 32) != 0);

    // Records both ways, in order; each uses the next nonce.
    uint8_t rec[TSNET_NOISE_MAX_MESSAGE], pt[TSNET_NOISE_MAX_MESSAGE];
    const char *msgs[] = {"PRI * HTTP/2.0", "", "third"};
    for (int i = 0; i < 3; i++) {
        size_t n = tsnet_noise_seal(&cc, rec, (const uint8_t *)msgs[i], strlen(msgs[i]));
        EXPECT(n == strlen(msgs[i]) + 19);
        EXPECT(rec[0] == 4 && rec[1] == ((n - 3) >> 8) && rec[2] == ((n - 3) & 0xff));
        EXPECT(tsnet_noise_open(&sc, pt, rec, n) == (int)strlen(msgs[i]));
        EXPECT(memcmp(pt, msgs[i], strlen(msgs[i])) == 0);
        n = tsnet_noise_seal(&sc, rec, (const uint8_t *)msgs[i], strlen(msgs[i]));
        EXPECT(tsnet_noise_open(&cc, pt, rec, n) == (int)strlen(msgs[i]));
    }
    EXPECT(cc.tx.nonce == 3 && cc.rx.nonce == 3);

    // The nonce is 4 zero bytes then the counter big-endian: a record sealed as nonce 1 with that layout opens.
    {
        tsnet_noise_conn_t a = cc, b = sc; // a sends as nonce 3
        uint8_t nonce[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}, buf[64];
        tsnet_aead_seal(buf, a.tx.key, nonce, NULL, 0, (const uint8_t *)"x", 1);
        size_t n = tsnet_noise_seal(&a, rec, (const uint8_t *)"x", 1);
        EXPECT(n == 20 && memcmp(rec + 3, buf, 17) == 0);
        EXPECT(tsnet_noise_open(&b, pt, rec, n) == 1);
    }

    // Out of order or replayed: the nonce doesn't match, so it fails.
    {
        tsnet_noise_conn_t a = cc, b = sc;
        uint8_t r1[64], r2[64];
        size_t n1 = tsnet_noise_seal(&a, r1, (const uint8_t *)"one", 3);
        size_t n2 = tsnet_noise_seal(&a, r2, (const uint8_t *)"two", 3);
        EXPECT(tsnet_noise_open(&b, pt, r2, n2) == -1);
        tsnet_noise_conn_t b2 = sc;
        EXPECT(tsnet_noise_open(&b2, pt, r1, n1) == 3);
        EXPECT(tsnet_noise_open(&b2, pt, r1, n1) == -1);
    }

    // Sizes: the largest record, one byte over, a wrong type, a length that doesn't match, a flipped bit.
    {
        tsnet_noise_conn_t a = cc, b = sc;
        static uint8_t big[TSNET_NOISE_MAX_PLAINTEXT + 1];
        memset(big, 0x5a, sizeof big);
        EXPECT(tsnet_noise_seal(&a, rec, big, TSNET_NOISE_MAX_PLAINTEXT + 1) == 0);
        EXPECT(a.tx.nonce == cc.tx.nonce); // a refused record uses no nonce
        size_t n = tsnet_noise_seal(&a, rec, big, TSNET_NOISE_MAX_PLAINTEXT);
        EXPECT(n == TSNET_NOISE_MAX_MESSAGE);
        EXPECT(tsnet_noise_open(&b, pt, rec, n) == TSNET_NOISE_MAX_PLAINTEXT);
        uint8_t r[64];
        tsnet_noise_conn_t a2 = cc, b2 = sc;
        n = tsnet_noise_seal(&a2, r, (const uint8_t *)"abc", 3);
        r[0] = 3;
        EXPECT(tsnet_noise_open(&b2, pt, r, n) == -1);
        r[0] = 4;
        b2 = sc;
        EXPECT(tsnet_noise_open(&b2, pt, r, n - 1) == -1);
        b2 = sc;
        r[5] ^= 1;
        EXPECT(tsnet_noise_open(&b2, pt, r, n) == -1);
    }

    // An exhausted nonce refuses to seal or open (conn.go errCipherExhausted).
    {
        tsnet_noise_conn_t a = cc, b = sc;
        a.tx.nonce = UINT64_MAX;
        EXPECT(tsnet_noise_seal(&a, rec, (const uint8_t *)"x", 1) == 0);
        a.tx.nonce = UINT64_MAX - 1;
        b.rx.nonce = UINT64_MAX - 1;
        size_t n = tsnet_noise_seal(&a, rec, (const uint8_t *)"x", 1);
        EXPECT(n == 20 && a.tx.nonce == UINT64_MAX);
        EXPECT(tsnet_noise_open(&b, pt, rec, n) == 1);
        EXPECT(tsnet_noise_open(&b, pt, rec, n) == -1); // the counter is now invalidNonce
    }

    // Handshake failures: a tampered response, the wrong control key, a wrong type or length, an error message.
    {
        uint8_t r2[TSNET_NOISE_RESP_LEN];
        tsnet_noise_conn_t x;
        for (int i = 3; i < TSNET_NOISE_RESP_LEN; i++) { // any bit of the key or the tag
            EXPECT(tsnet_noise_client_start_with(&c, machine, control_pub, 131, c_eph, init) == 0);
            memcpy(r2, resp, sizeof r2);
            r2[i] ^= 0x10;
            EXPECT(tsnet_noise_client_finish(&c, r2, sizeof r2, &x) == -1);
        }
        uint8_t wrong_pub[32], wrong[32];
        key(wrong, 9);
        tsnet_x25519_public(wrong_pub, wrong);
        EXPECT(tsnet_noise_client_start_with(&c, machine, wrong_pub, 131, c_eph, init) == 0);
        EXPECT(serve(131, control, s_eph, init, r2, got_machine, &sc) == -1); // the server can't read it
        EXPECT(tsnet_noise_client_start_with(&c, machine, control_pub, 130, c_eph, init) == 0);
        EXPECT(serve(131, control, s_eph, init, r2, got_machine, &sc) == -1); // nor another version's
        EXPECT(tsnet_noise_client_start_with(&c, machine, control_pub, 131, c_eph, init) == 0);
        memcpy(r2, resp, sizeof r2);
        r2[0] = 4;
        EXPECT(tsnet_noise_client_finish(&c, r2, sizeof r2, &x) == -1);
        EXPECT(tsnet_noise_client_start_with(&c, machine, control_pub, 131, c_eph, init) == 0);
        EXPECT(tsnet_noise_client_finish(&c, resp, sizeof resp - 1, &x) == -1);
        static const uint8_t ERR[] = {3, 0, 4, 'n', 'o', 'p', 'e'};
        EXPECT(tsnet_noise_client_start_with(&c, machine, control_pub, 131, c_eph, init) == 0);
        EXPECT(tsnet_noise_client_finish(&c, ERR, sizeof ERR, &x) == TSNET_NOISE_SERVER_ERROR);
        // A low-order "ephemeral key" from the server is refused.
        EXPECT(tsnet_noise_client_start_with(&c, machine, control_pub, 131, c_eph, init) == 0);
        memcpy(r2, resp, sizeof r2);
        memset(r2 + 3, 0, 32);
        EXPECT(tsnet_noise_client_finish(&c, r2, sizeof r2, &x) == -1);
    }

    // The framer, split at every point: two frames back to back come out whole and in order.
    {
        uint8_t stream[200];
        tsnet_noise_conn_t a = cc;
        size_t n1 = tsnet_noise_seal(&a, stream, (const uint8_t *)"hello", 5);
        size_t n2 = tsnet_noise_seal(&a, stream + n1, (const uint8_t *)"world!", 6);
        size_t total = n1 + n2;
        for (size_t cut = 0; cut <= total; cut++) {
            tsnet_noise_framer_t f = {0};
            size_t frames = 0, pos = 0;
            const size_t parts[2][2] = {{0, cut}, {cut, total}};
            for (int p = 0; p < 2; p++) {
                pos = parts[p][0];
                while (pos < parts[p][1]) {
                    pos += tsnet_noise_framer_feed(&f, stream + pos, parts[p][1] - pos);
                    int len = tsnet_noise_framer_frame(&f);
                    if (len > 0) {
                        EXPECT((size_t)len == (frames == 0 ? n1 : n2));
                        EXPECT(memcmp(f.buf, stream + (frames == 0 ? 0 : n1), (size_t)len) == 0);
                        frames++;
                        tsnet_noise_framer_reset(&f);
                    }
                }
            }
            EXPECT(frames == 2);
        }
        // A header over the maximum is an error and takes nothing more.
        tsnet_noise_framer_t f = {0};
        const uint8_t bad[] = {4, 0x10, 0x00, 1, 2, 3}; // 4096 + 3 bytes announced
        EXPECT(tsnet_noise_framer_feed(&f, bad, sizeof bad) == 3);
        EXPECT(tsnet_noise_framer_frame(&f) == -1);
        EXPECT(tsnet_noise_framer_feed(&f, bad + 3, 3) == 0);
        // Exactly the maximum is fine.
        tsnet_noise_framer_reset(&f);
        const uint8_t max_hdr[] = {4, 0x0f, 0xfd}; // 4093
        EXPECT(tsnet_noise_framer_feed(&f, max_hdr, 3) == 3);
        EXPECT(tsnet_noise_framer_frame(&f) == 0);
    }

    // The randomised start works and differs each time (fresh ephemeral keys).
    {
        uint8_t i1[TSNET_NOISE_INIT_LEN], i2[TSNET_NOISE_INIT_LEN];
        EXPECT(tsnet_noise_client_start(&c, machine, control_pub, 131, i1) == 0);
        EXPECT(tsnet_noise_client_start(&c, machine, control_pub, 131, i2) == 0);
        EXPECT(memcmp(i1 + 5, i2 + 5, 32) != 0);
        EXPECT(serve(131, control, s_eph, i2, resp, got_machine, &sc) == 0);
        EXPECT(tsnet_noise_client_finish(&c, resp, sizeof resp, &cc) == 0);
        EXPECT(memcmp(cc.tx.key, sc.rx.key, 32) == 0);
    }

    if (failures == 0) {
        printf("tsnet noise_test: ok\n");
    }
    return failures != 0;
}
