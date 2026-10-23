// A mutation fuzzer for the parsers other tests don't feed random input, under ASan and UBSan: STUN responses and
// binding requests, the HTTP/1 response parser (fed in random splits), the packet filter's decode (in, out, TSMP
// reject and pong), and wgdev_receive on WireGuard-shaped garbage. Seeds are valid messages; each round flips,
// inserts, deletes or truncates bytes. A crash or sanitizer report is the finding. The security review's first run
// found an undefined shift in wgdev_receive's message type. test.sh runs 20,000 rounds; TSNET_FUZZ_ROUNDS and
// TSNET_FUZZ_SEED run more (1,300,000 rounds over three seeds were clean).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "filter.h"
#include "http1.h"
#include "stun.h"
#include "wg.h"
#include "wgdev.h"

static uint64_t rng;
static uint32_t rnd(void)
{
    rng ^= rng << 13, rng ^= rng >> 7, rng ^= rng << 17;
    return (uint32_t)rng;
}

// Mutates b (len bytes, up to cap) in place; returns the new length.
static size_t mutate(uint8_t *b, size_t len, size_t cap)
{
    int n = 1 + (int)(rnd() % 8);
    for (int i = 0; i < n; i++) {
        switch (rnd() % 6) {
        case 0: // flip a byte
            if (len) {
                b[rnd() % len] ^= (uint8_t)(1 + rnd() % 255);
            }
            break;
        case 1: // an interesting value
            if (len) {
                static const uint8_t v[] = {0, 1, 0x7f, 0x80, 0xff, 0xfe, 0x40, 0x20};
                b[rnd() % len] = v[rnd() % sizeof v];
            }
            break;
        case 2: // insert
            if (len < cap) {
                size_t at = len ? rnd() % len : 0;
                memmove(b + at + 1, b + at, len - at);
                b[at] = (uint8_t)rnd();
                len++;
            }
            break;
        case 3: // delete
            if (len) {
                size_t at = rnd() % len;
                memmove(b + at, b + at + 1, len - at - 1);
                len--;
            }
            break;
        case 4: // truncate
            if (len) {
                len = rnd() % len;
            }
            break;
        case 5: // a 16-bit length field set big
            if (len >= 2) {
                size_t at = rnd() % (len - 1);
                b[at] = 0xff, b[at + 1] = (uint8_t)rnd();
            }
            break;
        }
    }
    return len;
}

static void fuzz_stun(void)
{
    uint8_t txid[TSNET_STUN_TXID_LEN] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, ip[16] = {0}, out[16];
    ip[10] = ip[11] = 0xff, ip[12] = 203, ip[15] = 7;
    uint8_t seed[512], b[512];
    int n = tsnet_stun_response(seed, sizeof seed, txid, ip, 41641);
    uint8_t req[TSNET_STUN_REQUEST_LEN];
    tsnet_stun_request(req, txid);
    const uint8_t *s = rnd() & 1 ? seed : req;
    size_t len = rnd() & 1 ? (size_t)n : sizeof req;
    memcpy(b, s, len);
    len = mutate(b, len, sizeof b);
    uint8_t *heap = malloc(len ? len : 1); // exact-size copy so ASan sees an over-read
    memcpy(heap, b, len);
    uint16_t port;
    (void)tsnet_stun_is(heap, len);
    (void)tsnet_stun_parse_response(heap, len, txid, out, &port);
    (void)tsnet_stun_parse_binding_request(heap, len, txid);
    free(heap);
}

static void fuzz_http1(void)
{
    static const char *seeds[] = {
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\nConnection: upgrade\r\n\r\nXYZ",
        "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world",
        "HTTP/1.0 404 Not Found\r\n\r\nbody until close",
    };
    const char *s = seeds[rnd() % 4];
    uint8_t b[1024];
    size_t len = strlen(s);
    memcpy(b, s, len);
    len = mutate(b, len, sizeof b);
    tsnet_http1_resp_t *r = malloc(sizeof *r);
    tsnet_http1_resp_init(r);
    uint8_t body[64];
    size_t body_len = 0, at = 0;
    while (at < len) {
        size_t chunk = 1 + rnd() % (len - at);
        uint8_t *heap = malloc(chunk);
        memcpy(heap, b + at, chunk);
        size_t took = tsnet_http1_resp_feed(r, heap, chunk, body, sizeof body, &body_len);
        free(heap);
        if (took == 0 || took > chunk) {
            break;
        }
        at += took;
        if (body_len > sizeof body) {
            printf("http1: body_len %zu past its cap\n", body_len);
            abort();
        }
    }
    tsnet_http1_resp_eof(r);
    free(r);
}

static tsnet_filter_t *filt;

static void fuzz_filter(void)
{
    uint8_t b[256];
    // a TCP SYN, a UDP datagram, an ICMP echo, a TSMP ping: 100.64.0.2 -> 100.64.0.1
    static const uint8_t base[20] = {0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 100, 64, 0, 2, 100, 64, 0, 1};
    memcpy(b, base, 20);
    memset(b + 20, 0, 40);
    int kind = (int)(rnd() % 4);
    static const uint8_t protos[] = {6, 17, 1, 99};
    b[9] = protos[kind];
    b[33] = 0x02; // SYN for TCP
    b[20] = kind == 3 ? 'p' : b[20];
    size_t len = mutate(b, 60, sizeof b);
    uint8_t *heap = malloc(len ? len : 1);
    memcpy(heap, b, len);
    uint8_t out[64];
    (void)tsnet_filter_in(filt, heap, len);
    (void)tsnet_filter_out(filt, heap, len);
    (void)tsnet_tsmp_reject(heap, len, TSNET_REJECT_ACLS, out);
    (void)tsnet_tsmp_pong(heap, len, out);
    free(heap);
}

static tsnet_wgdev_t *wg;
static uint8_t wg_peer[32];

static void wg_send(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    (void)ctx, (void)peer, (void)pkt, (void)len;
}

static void wg_deliver(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    (void)ctx, (void)peer, (void)pkt, (void)len;
}

static void fuzz_wg(uint64_t now)
{
    uint8_t b[1600];
    static const size_t lens[] = {TSNET_WG_INITIATION_LEN, TSNET_WG_RESPONSE_LEN, TSNET_WG_COOKIE_REPLY_LEN,
                                  TSNET_WG_KEEPALIVE_LEN + 64};
    int t = (int)(rnd() % 4);
    size_t len = lens[t];
    for (size_t i = 0; i < len; i++) {
        b[i] = (uint8_t)rnd();
    }
    b[0] = (uint8_t)(t + 1), b[1] = b[2] = b[3] = 0;
    len = mutate(b, len, sizeof b);
    uint8_t *heap = malloc(len ? len : 1);
    memcpy(heap, b, len);
    uint8_t src[18] = {0};
    tsnet_wgdev_receive(wg, heap, len, src, sizeof src, now);
    free(heap);
}

int main(void)
{
    long rounds = getenv("TSNET_FUZZ_ROUNDS") ? atol(getenv("TSNET_FUZZ_ROUNDS")) : 20000;
    rng = getenv("TSNET_FUZZ_SEED") ? strtoull(getenv("TSNET_FUZZ_SEED"), NULL, 10) : 88172645463325252ULL;
    filt = tsnet_filter_new();
    tsnet_prefix_t local;
    tsnet_prefix_parse(&local, "100.64.0.1/32");
    tsnet_filter_set(filt, "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}]}]",
                     &local, 1);
    uint8_t priv[32];
    for (int i = 0; i < 32; i++) {
        priv[i] = (uint8_t)(i * 3 + 1);
        wg_peer[i] = (uint8_t)(i * 5 + 9);
    }
    tsnet_wgdev_cfg_t wc = {.priv = priv, .send = wg_send, .deliver = wg_deliver};
    wg = tsnet_wgdev_new(&wc);
    tsnet_wgdev_add_peer(wg, wg_peer, 1000);
    for (long i = 0; i < rounds; i++) {
        fuzz_stun();
        fuzz_http1();
        fuzz_filter();
        fuzz_wg(1000 + (uint64_t)i);
    }
    tsnet_wgdev_free(wg);
    tsnet_filter_free(filt);
    printf("tsnet fuzz_test: ok (%ld rounds each)\n", rounds);
    return 0;
}
