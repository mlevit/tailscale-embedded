// Host test of STUN: Go's own response vectors (stun_vectors.h, from net/stun/stun_test.go), its Is and
// Response cases, a request checked against one built with Python's zlib CRC-32, every truncation and byte change of
// each vector, and a loopback round trip over the platform's UDP socket.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include "stun.h"
#include "stun_vectors.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static void vectors(void)
{
    uint8_t tid[12], ip[16], buf[256];
    uint16_t port;
    for (size_t i = 0; i < sizeof stun_vectors / sizeof stun_vectors[0]; i++) {
        const stun_vector_t *v = &stun_vectors[i];
        int r = tsnet_stun_parse_response(v->data, v->len, tid, ip, &port);
        if (r != 0 || memcmp(tid, v->tid, 12) != 0 || memcmp(ip, v->ip, 16) != 0 || port != v->port) {
            printf("vector %s: r %d port %u\n", v->name, r, port);
            failures++;
        }
        // Cut short anywhere: an error (never a read past the end, under ASan), or, past the attributes the header
        // counts, the same answer.
        for (size_t n = 0; n < v->len; n++) {
            memcpy(buf, v->data, n);
            r = tsnet_stun_parse_response(buf, n, tid, ip, &port);
            EXPECT(r != 0 || n >= TSNET_STUN_HEADER_LEN + (size_t)(v->data[2] << 8 | v->data[3]));
        }
        // Any byte changed: any answer, no crash.
        for (size_t j = 0; j < v->len; j++) {
            memcpy(buf, v->data, v->len);
            buf[j] ^= 0x5a;
            tsnet_stun_parse_response(buf, v->len, tid, ip, &port);
            tsnet_stun_parse_binding_request(buf, v->len, tid);
        }
    }
}

static void is_cases(void)
{
    // TestIs.
    uint8_t p[24] = {0};
    EXPECT(!tsnet_stun_is(p, 0));
    EXPECT(!tsnet_stun_is(p, 20)); // no cookie
    memcpy(p + 4, "\x21\x12\xa4\x42", 4);
    EXPECT(!tsnet_stun_is(p, 19));
    EXPECT(tsnet_stun_is(p, 20));
    EXPECT(tsnet_stun_is(p, 23));
    p[0] = 0xf0;
    EXPECT(!tsnet_stun_is(p, 20));
    p[0] = 0x40;
    EXPECT(!tsnet_stun_is(p, 20));
    p[0] = 0x20; // non-zero, but not the high bits
    EXPECT(tsnet_stun_is(p, 20));
}

static void requests(void)
{
    uint8_t tx[12], req[TSNET_STUN_REQUEST_LEN], got[12];
    for (int i = 0; i < 12; i++) {
        tx[i] = (uint8_t)i;
    }
    tsnet_stun_request(req, tx);
    // The same request built with Python's zlib.crc32 for the fingerprint.
    static const char WANT[] = "000100142112a442000102030405060708090a0b802200087461696c6e6f6465802800048aabad90";
    char hex[81];
    for (int i = 0; i < 40; i++) {
        snprintf(hex + 2 * i, 3, "%02x", req[i]);
    }
    EXPECT(strcmp(hex, WANT) == 0);
    // TestAttrOrderForXdpDERP: SOFTWARE first, "tailnode".
    EXPECT(req[20] == 0x80 && req[21] == 0x22 && memcmp(req + 24, "tailnode", 8) == 0);
    // TestParseBindingRequest, then each way it is refused.
    EXPECT(tsnet_stun_parse_binding_request(req, sizeof req, got) == 0 && memcmp(got, tx, 12) == 0);
    uint8_t bad[TSNET_STUN_REQUEST_LEN];
    memcpy(bad, req, sizeof bad);
    bad[39] ^= 1;
    EXPECT(tsnet_stun_parse_binding_request(bad, sizeof bad, got) == TSNET_STUN_WRONG_FINGERPRINT);
    memcpy(bad, req, sizeof bad);
    bad[24] = 'T';
    EXPECT(tsnet_stun_parse_binding_request(bad, sizeof bad, got) == TSNET_STUN_WRONG_SOFTWARE);
    EXPECT(tsnet_stun_parse_binding_request(req, 32, got) == TSNET_STUN_NO_FINGERPRINT); // ends after SOFTWARE
    memcpy(bad, req, sizeof bad);
    bad[1] = 0x02;
    EXPECT(tsnet_stun_parse_binding_request(bad, sizeof bad, got) == TSNET_STUN_NOT_BINDING_REQUEST);
    EXPECT(tsnet_stun_parse_binding_request(req, 36, got) == TSNET_STUN_MALFORMED); // the fingerprint cut short
    // A request isn't a response.
    uint8_t ip[16];
    uint16_t port;
    EXPECT(tsnet_stun_parse_response(req, sizeof req, got, ip, &port) == TSNET_STUN_NOT_SUCCESS);
}

static void responses(void)
{
    // TestResponse: 1.2.3.4 and 1::4, ports 254 and 257.
    uint8_t v4[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4};
    uint8_t v6[16] = {0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4};
    const uint8_t *addrs[4] = {v4, v4, v6, v6};
    uint16_t ports[4] = {254, 257, 254, 257};
    for (int t = 0; t < 4; t++) {
        uint8_t tx[12], out[64], got_tx[12], got_ip[16];
        memset(tx, t + 1, sizeof tx);
        uint16_t got_port;
        int n = tsnet_stun_response(out, sizeof out, tx, addrs[t], ports[t]);
        EXPECT(n == (t < 2 ? 32 : 44));
        EXPECT(tsnet_stun_parse_response(out, (size_t)n, got_tx, got_ip, &got_port) == 0);
        EXPECT(memcmp(got_tx, tx, 12) == 0 && memcmp(got_ip, addrs[t], 16) == 0 && got_port == ports[t]);
    }
    // MAPPED-ADDRESS alone is the fallback; XOR-MAPPED-ADDRESS wins when both are there.
    uint8_t tx[12] = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}, pkt[64], ip[16];
    uint16_t port;
    uint8_t mapped[12] = {0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x1f, 0x90, 192, 0, 2, 3};
    memcpy(pkt, "\x01\x01\x00\x0c\x21\x12\xa4\x42", 8);
    memcpy(pkt + 8, tx, 12);
    memcpy(pkt + 20, mapped, 12);
    EXPECT(tsnet_stun_parse_response(pkt, 32, tx, ip, &port) == 0 && port == 8080 && ip[12] == 192 && ip[15] == 3);
    int n = tsnet_stun_response(pkt, sizeof pkt, tx, v4, 254);
    memcpy(pkt + n, mapped, 12);
    pkt[3] = (uint8_t)(pkt[3] + 12);
    EXPECT(tsnet_stun_parse_response(pkt, (size_t)n + 12, tx, ip, &port) == 0 && port == 254 && ip[12] == 1);
    // An unknown family, and no address at all, are malformed.
    memcpy(pkt + 20, mapped, 12);
    pkt[3] = 12;
    pkt[25] = 0x03;
    EXPECT(tsnet_stun_parse_response(pkt, 32, tx, ip, &port) == TSNET_STUN_MALFORMED);
    pkt[3] = 0;
    EXPECT(tsnet_stun_parse_response(pkt, 20, tx, ip, &port) == TSNET_STUN_MALFORMED);
    // The header counting more attribute bytes than there are.
    pkt[3] = 40;
    EXPECT(tsnet_stun_parse_response(pkt, 32, tx, ip, &port) == TSNET_STUN_MALFORMED);
    EXPECT(tsnet_stun_response(pkt, 31, tx, v4, 1) == -1);
}

// A request from one UDP socket to another on loopback, answered with a response the first one parses.
static void loopback(void)
{
    int a = tsnet_udp_open(0), b = tsnet_udp_open(0);
    EXPECT(a >= 0 && b >= 0);
    uint16_t pb = tsnet_udp_port(b);
    EXPECT(pb != 0 && tsnet_udp_port(a) != 0);
    uint8_t lo[16];
    EXPECT(tsnet_resolve4("127.0.0.1", lo) == 0 && lo[10] == 0xff && lo[12] == 127 && lo[15] == 1);
    uint8_t tx[12] = {1, 2, 3}, req[TSNET_STUN_REQUEST_LEN], buf[128], from[16];
    uint16_t from_port;
    tsnet_stun_request(req, tx);
    EXPECT(tsnet_udp_recv(b, buf, sizeof buf, from, &from_port) == 0); // nothing yet
    EXPECT(tsnet_udp_send(a, lo, pb, req, sizeof req) == (int)sizeof req);
    tsnet_poll_t p = {.fd = b};
    EXPECT(tsnet_poll(&p, 1, 1000) == 1 && p.readable);
    int n = tsnet_udp_recv(b, buf, sizeof buf, from, &from_port);
    uint8_t got[12];
    EXPECT(n == (int)sizeof req && tsnet_stun_parse_binding_request(buf, (size_t)n, got) == 0);
    EXPECT(from_port == tsnet_udp_port(a) && from[12] == 127);
    n = tsnet_stun_response(buf, sizeof buf, got, from, from_port);
    EXPECT(tsnet_udp_send(b, from, from_port, buf, (size_t)n) == n);
    p.fd = a;
    EXPECT(tsnet_poll(&p, 1, 1000) == 1);
    uint8_t ip[16];
    uint16_t port;
    n = tsnet_udp_recv(a, buf, sizeof buf, from, &from_port);
    EXPECT(n > 0 && tsnet_stun_parse_response(buf, (size_t)n, got, ip, &port) == 0);
    EXPECT(memcmp(got, tx, 12) == 0 && port == tsnet_udp_port(a) && ip[12] == 127);
    uint8_t v6[16] = {0x20, 0x01};
    EXPECT(tsnet_udp_send(a, v6, 1, req, sizeof req) == -1); // IPv6 isn't done yet
    tsnet_sock_close(a);
    tsnet_sock_close(b);
}

int main(void)
{
    vectors();
    is_cases();
    requests();
    responses();
    loopback();
    if (failures == 0) {
        printf("tsnet stun_test: ok\n");
    }
    return failures != 0;
}
