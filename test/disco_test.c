// Host test of disco's messages and packets: Go's own TestMarshalAndParse vectors (disco/disco_test.go) for
// Ping, Pong and CallMeMaybe, marshalled and parsed back; packets sealed by one side and opened by the other; and
// every truncation and byte change.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "disco.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static int hexeq(const uint8_t *b, int n, const char *want)
{
    char got[1024];
    size_t len = 0;
    for (int i = 0; i < n && len < sizeof got - 4; i++) {
        len += (size_t)snprintf(got + len, sizeof got - len, "%s%02x", i ? " " : "", b[i]);
    }
    if (strcmp(got, want) != 0) {
        printf("got  %s\nwant %s\n", got, want);
        return 0;
    }
    return 1;
}

static const uint8_t TX[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
static uint8_t key_1_2_30_31[32]; // key.NodePublicFromRaw32(mem.B([]byte{1: 1, 2: 2, 30: 30, 31: 31}))

static void vectors(void)
{
    uint8_t out[256];
    tsnet_disco_msg_t m;
    int n;

    n = tsnet_disco_ping(out, sizeof out, TX, NULL, 0);
    EXPECT(hexeq(out, n, "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c"));
    EXPECT(tsnet_disco_parse(out, (size_t)n, &m) == 0 && m.type == 1 && !memcmp(m.txid, TX, 12) && !m.has_node_key &&
           m.padding == 0);

    n = tsnet_disco_ping(out, sizeof out, TX, key_1_2_30_31, 0);
    EXPECT(hexeq(out, n, "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                         "00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f"));
    EXPECT(tsnet_disco_parse(out, (size_t)n, &m) == 0 && m.has_node_key && !memcmp(m.node_key, key_1_2_30_31, 32) &&
           m.padding == 0);

    n = tsnet_disco_ping(out, sizeof out, TX, NULL, 3);
    EXPECT(hexeq(out, n, "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 00 00"));
    EXPECT(tsnet_disco_parse(out, (size_t)n, &m) == 0 && !m.has_node_key && m.padding == 3);

    n = tsnet_disco_ping(out, sizeof out, TX, key_1_2_30_31, 3);
    EXPECT(hexeq(out, n, "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                         "00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 00 00"));
    EXPECT(tsnet_disco_parse(out, (size_t)n, &m) == 0 && m.has_node_key && m.padding == 3);
    // 40 bytes of padding and no key: the zeros are padding, not a key.
    n = tsnet_disco_ping(out, sizeof out, TX, NULL, 40);
    EXPECT(tsnet_disco_parse(out, (size_t)n, &m) == 0 && !m.has_node_key && m.padding == 40);

    uint8_t v4[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 2, 3, 4, 5};
    n = tsnet_disco_pong(out, sizeof out, TX, v4, 1234);
    EXPECT(hexeq(out, n, "02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 00 00 00 00 00 00 00 00 00 ff ff 02 03 04 05 04 d2"));
    EXPECT(tsnet_disco_parse(out, (size_t)n, &m) == 0 && m.type == 2 && !memcmp(m.src_ip, v4, 16) && m.src_port == 1234);

    uint8_t v6[16] = {0xfe, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12};
    n = tsnet_disco_pong(out, sizeof out, TX, v6, 6666);
    EXPECT(hexeq(out, n, "02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c fe d0 00 00 00 00 00 00 00 00 00 00 00 00 00 12 1a 0a"));

    n = tsnet_disco_call_me_maybe(out, sizeof out, NULL, 0);
    EXPECT(hexeq(out, n, "03 00"));
    EXPECT(tsnet_disco_parse(out, (size_t)n, &m) == 0 && m.type == 3 && m.n_eps == 0);

    tsnet_disco_ep_t eps[2] = {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4}, 567},
                               {{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x34, 0x56}, 789}};
    n = tsnet_disco_call_me_maybe(out, sizeof out, eps, 2);
    EXPECT(hexeq(out, n, "03 00 00 00 00 00 00 00 00 00 00 00 ff ff 01 02 03 04 02 37 20 01 00 00 00 00 00 00 00 00 "
                         "00 00 00 00 34 56 03 15"));
    EXPECT(tsnet_disco_parse(out, (size_t)n, &m) == 0 && m.n_eps == 2 && m.eps[0].port == 567 && m.eps[1].port == 789 &&
           !memcmp(m.eps[1].ip, eps[1].ip, 16));
    // parseCallMeMaybe is lax: a version it doesn't know, or a length that isn't whole endpoints, gives none.
    out[1] = 1;
    EXPECT(tsnet_disco_parse(out, (size_t)n, &m) == 0 && m.n_eps == 0);
    out[1] = 0;
    EXPECT(tsnet_disco_parse(out, (size_t)n - 1, &m) == 0 && m.n_eps == 0);

    // Short and unknown messages are errors; the relay messages are recognised.
    EXPECT(tsnet_disco_parse(out, 1, &m) == -1);
    uint8_t short_ping[13] = {1, 0};
    EXPECT(tsnet_disco_parse(short_ping, sizeof short_ping, &m) == -1);
    uint8_t short_pong[31] = {2, 0};
    EXPECT(tsnet_disco_parse(short_pong, sizeof short_pong, &m) == -1);
    uint8_t unknown[4] = {0x0a, 0};
    EXPECT(tsnet_disco_parse(unknown, sizeof unknown, &m) == -1);
    uint8_t relay[4] = {0x04, 0};
    EXPECT(tsnet_disco_parse(relay, sizeof relay, &m) == 0 && m.type == 4);
    EXPECT(tsnet_disco_ping(out, 13, TX, NULL, 0) == -1); // doesn't fit
}

static void packets(void)
{
    uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32], ab[32], ba[32], nonce[24];
    for (int i = 0; i < 32; i++) {
        a_priv[i] = (uint8_t)(7 * i + 1);
        b_priv[i] = (uint8_t)(11 * i + 2);
    }
    for (int i = 0; i < 24; i++) {
        nonce[i] = (uint8_t)(0x30 + i);
    }
    tsnet_x25519_public(a_pub, a_priv);
    tsnet_x25519_public(b_pub, b_priv);
    EXPECT(tsnet_box_shared(ab, a_priv, b_pub) == 0 && tsnet_box_shared(ba, b_priv, a_pub) == 0);
    EXPECT(memcmp(ab, ba, 32) == 0); // both sides get the same shared key

    uint8_t msg[64], pkt[256], back[256];
    int mlen = tsnet_disco_ping(msg, sizeof msg, TX, key_1_2_30_31, 0);
    int plen = tsnet_disco_seal(pkt, sizeof pkt, a_pub, ab, nonce, msg, (size_t)mlen);
    EXPECT(plen == TSNET_DISCO_WRAPPER_LEN + 16 + mlen);
    EXPECT(tsnet_disco_looks_like(pkt, (size_t)plen) && memcmp(tsnet_disco_source(pkt), a_pub, 32) == 0);
    int n = tsnet_disco_open(pkt, (size_t)plen, ba, back, sizeof back);
    EXPECT(n == mlen && memcmp(back, msg, (size_t)mlen) == 0);
    tsnet_disco_msg_t m;
    EXPECT(tsnet_disco_parse(back, (size_t)n, &m) == 0 && m.type == 1 && m.has_node_key);
    // A wrong key, any changed byte past the magic and key, and every truncation fail to open.
    uint8_t wrong[32];
    memcpy(wrong, ba, 32);
    wrong[0] ^= 1;
    EXPECT(tsnet_disco_open(pkt, (size_t)plen, wrong, back, sizeof back) == -1);
    for (int i = TSNET_DISCO_MAGIC_LEN + 32; i < plen; i++) {
        uint8_t bad[256];
        memcpy(bad, pkt, (size_t)plen);
        bad[i] ^= 0x10;
        EXPECT(tsnet_disco_open(bad, (size_t)plen, ba, back, sizeof back) == -1);
    }
    for (int len = 0; len < plen; len++) {
        EXPECT(tsnet_disco_open(pkt, (size_t)len, ba, back, sizeof back) == -1);
    }
    EXPECT(!tsnet_disco_looks_like(pkt, TSNET_DISCO_WRAPPER_LEN - 1));
    pkt[0] ^= 1;
    EXPECT(!tsnet_disco_looks_like(pkt, (size_t)plen));
    EXPECT(tsnet_disco_seal(pkt, (size_t)plen - 1, a_pub, ab, nonce, msg, (size_t)mlen) == -1);
}

// Random messages: parse never reads past the end (ASan), whatever comes out.
static void garbage(void)
{
    srand(1933);
    for (int round = 0; round < 20000; round++) {
        uint8_t p[96];
        size_t len = (size_t)rand() % sizeof p;
        for (size_t i = 0; i < len; i++) {
            p[i] = (uint8_t)rand();
        }
        if (len > 0) {
            p[0] = (uint8_t)(rand() % 11);
        }
        uint8_t *heap = malloc(len ? len : 1);
        memcpy(heap, p, len);
        tsnet_disco_msg_t m;
        tsnet_disco_parse(heap, len, &m);
        free(heap);
    }
}

int main(void)
{
    key_1_2_30_31[1] = 1;
    key_1_2_30_31[2] = 2;
    key_1_2_30_31[30] = 30;
    key_1_2_30_31[31] = 31;
    vectors();
    packets();
    garbage();
    if (failures == 0) {
        printf("tsnet disco_test: ok\n");
    }
    return failures != 0;
}
