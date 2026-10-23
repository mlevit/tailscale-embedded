// Host test of tsnet's HTTP/1.1 reader and base64: RFC 4648's vectors, and responses fed in two pieces at every
// split point, the way a socket hands them over.
#include <stdio.h>
#include <string.h>
#include "http1.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

// Feeds `text` in two pieces cut at `cut`, as a caller would: head first (stopping at its end), then the body.
static tsnet_http1_resp_t parse(const char *text, size_t len, size_t cut, uint8_t *body, size_t cap, size_t *body_len,
                               size_t *after_head)
{
    tsnet_http1_resp_t r;
    tsnet_http1_resp_init(&r);
    *body_len = 0;
    *after_head = 0;
    const size_t parts[2][2] = {{0, cut}, {cut, len}};
    for (int p = 0; p < 2; p++) {
        size_t pos = parts[p][0];
        while (pos < parts[p][1] && r.state != TSNET_HTTP1_ERROR && r.state != TSNET_HTTP1_DONE) {
            tsnet_http1_state_t before = r.state;
            size_t n = tsnet_http1_resp_feed(&r, (const uint8_t *)text + pos, parts[p][1] - pos, body, cap, body_len);
            pos += n;
            if (before == TSNET_HTTP1_HEAD && r.state != TSNET_HTTP1_HEAD) {
                *after_head = pos;
            }
            if (n == 0) {
                break;
            }
        }
    }
    return r;
}

int main(void)
{
    // RFC 4648 section 10.
    static const char *B64[][2] = {{"", ""}, {"f", "Zg=="}, {"fo", "Zm8="}, {"foo", "Zm9v"},
                                   {"foob", "Zm9vYg=="}, {"fooba", "Zm9vYmE="}, {"foobar", "Zm9vYmFy"}};
    for (size_t i = 0; i < sizeof B64 / sizeof B64[0]; i++) {
        char out[16];
        tsnet_base64(out, (const uint8_t *)B64[i][0], strlen(B64[i][0]));
        EXPECT(strcmp(out, B64[i][1]) == 0);
    }
    // The 101-byte Noise initiation encodes to 136 characters: 33 full groups and one of 2 bytes, so one '='.
    uint8_t init[101];
    memset(init, 0xff, sizeof init);
    char enc[140];
    tsnet_base64(enc, init, sizeof init);
    EXPECT(strlen(enc) == 136 && enc[135] == '=' && enc[134] != '=');

    uint8_t body[256];
    size_t body_len, after;

    // A 101 upgrade: the head is taken alone, so the Noise bytes after it stay with the caller.
    static const char UP[] = "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nupgrade:  tailscale-control-protocol \r\n"
                             "\r\n\x02\x00\x30rest";
    size_t up_len = sizeof UP - 1;
    size_t head_end = strstr(UP, "\r\n\r\n") - UP + 4;
    for (size_t cut = 0; cut <= up_len; cut++) {
        tsnet_http1_resp_t r = parse(UP, up_len, cut, body, sizeof body, &body_len, &after);
        EXPECT(r.status == 101);
        EXPECT(strcmp(r.upgrade, "tailscale-control-protocol") == 0); // case-insensitive name, trimmed value
        EXPECT(after == head_end);
    }

    // A Content-Length body, and nothing taken past it.
    static const char CL[] = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"a\":\"bcd\"}EXTRA";
    for (size_t cut = 0; cut <= sizeof CL - 1; cut++) {
        tsnet_http1_resp_t r = parse(CL, sizeof CL - 1, cut, body, sizeof body, &body_len, &after);
        EXPECT(r.state == TSNET_HTTP1_DONE && r.status == 200);
        EXPECT(body_len == 11 && memcmp(body, "{\"a\":\"bcd\"}", 11) == 0);
    }

    // Chunked, with an extension and a trailer; a Content-Length alongside is ignored (RFC 9112 6.3).
    static const char CH[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"
                             "4;x=y\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: 1\r\n\r\nNEXT";
    for (size_t cut = 0; cut <= sizeof CH - 1; cut++) {
        tsnet_http1_resp_t r = parse(CH, sizeof CH - 1, cut, body, sizeof body, &body_len, &after);
        EXPECT(r.state == TSNET_HTTP1_DONE);
        EXPECT(body_len == 9 && memcmp(body, "Wikipedia", 9) == 0);
    }

    // Errors: a bad status line, a non-numeric status, a negative or junk Content-Length, junk chunk sizes, data not
    // followed by CRLF, a body bigger than the buffer, a head bigger than the limit.
    static const char *BAD[] = {
        "HTTP/2 200 OK\r\n\r\n",
        "HTTP/1.1 2x0 OK\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 12a\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1234567890123456\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\nabc",
    };
    for (size_t i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        tsnet_http1_resp_t r = parse(BAD[i], strlen(BAD[i]), strlen(BAD[i]), body, sizeof body, &body_len, &after);
        EXPECT(r.state == TSNET_HTTP1_ERROR);
    }
    static const char BIG_BODY[] = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789";
    {
        tsnet_http1_resp_t r = parse(BIG_BODY, sizeof BIG_BODY - 1, 0, body, 9, &body_len, &after);
        EXPECT(r.state == TSNET_HTTP1_ERROR);
    }
    {
        static char big[TSNET_HTTP1_HEAD_MAX + 64];
        memset(big, 'a', sizeof big);
        memcpy(big, "HTTP/1.1 200 OK\r\nX: ", 20);
        tsnet_http1_resp_t r;
        tsnet_http1_resp_init(&r);
        size_t n = tsnet_http1_resp_feed(&r, (const uint8_t *)big, sizeof big, body, sizeof body, &body_len);
        EXPECT(r.state == TSNET_HTTP1_ERROR && n < sizeof big);
    }
    // A 200 with Content-Length 0 is done at once; a 101 with none stays in BODY (the new protocol's).
    {
        static const char Z[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        tsnet_http1_resp_t r = parse(Z, sizeof Z - 1, 5, body, sizeof body, &body_len, &after);
        EXPECT(r.state == TSNET_HTTP1_DONE && body_len == 0);
        tsnet_http1_resp_t u = parse(UP, head_end, 7, body, sizeof body, &body_len, &after);
        EXPECT(u.state == TSNET_HTTP1_BODY && body_len == 0);
    }
    // A bare CR inside a header line, or a status line ending in CR without LF, is malformed.
    {
        static const char CR1[] = "HTTP/1.1 200 OK\r\nX: a\rb\r\nContent-Length: 0\r\n\r\n";
        static const char CR2[] = "HTTP/1.1 200 OK\rX\r\nContent-Length: 0\r\n\r\n";
        tsnet_http1_resp_t r = parse(CR1, sizeof CR1 - 1, 0, body, sizeof body, &body_len, &after);
        EXPECT(r.state == TSNET_HTTP1_ERROR);
        r = parse(CR2, sizeof CR2 - 1, 0, body, sizeof body, &body_len, &after);
        EXPECT(r.state == TSNET_HTTP1_ERROR);
    }
    // No length: the body runs to the close. A Content-Length or chunked body cut short by the close is an error.
    {
        static const char NL[] = "HTTP/1.1 200 OK\r\n\r\nall of it";
        tsnet_http1_resp_t r = parse(NL, sizeof NL - 1, 3, body, sizeof body, &body_len, &after);
        EXPECT(r.state == TSNET_HTTP1_BODY && body_len == 9);
        tsnet_http1_resp_eof(&r);
        EXPECT(r.state == TSNET_HTTP1_DONE);
        r = parse(BIG_BODY, sizeof BIG_BODY - 3, 0, body, sizeof body, &body_len, &after);
        EXPECT(r.state == TSNET_HTTP1_BODY);
        tsnet_http1_resp_eof(&r);
        EXPECT(r.state == TSNET_HTTP1_ERROR);
        r = parse(CH, 80, 0, body, sizeof body, &body_len, &after);
        tsnet_http1_resp_eof(&r);
        EXPECT(r.state == TSNET_HTTP1_ERROR);
    }
    // The requests, byte for byte.
    {
        char req[512];
        const uint8_t three[3] = {'a', 'b', 'c'};
        int n = tsnet_http1_upgrade_request(req, sizeof req, "controlplane.tailscale.com", 80, three, 3);
        static const char WANT[] = "POST /ts2021 HTTP/1.1\r\nHost: controlplane.tailscale.com:80\r\nUser-Agent: tsnet\r\n"
                                   "Content-Length: 0\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\n"
                                   "X-Tailscale-Handshake: YWJj\r\n\r\n";
        EXPECT(n == (int)strlen(WANT) && strcmp(req, WANT) == 0);
        EXPECT(tsnet_http1_upgrade_request(req, 100, "controlplane.tailscale.com", 80, init, sizeof init) == -1);
        EXPECT(tsnet_http1_upgrade_request(req, sizeof req, "h", 80, init, 102) == -1);
        n = tsnet_http1_get_request(req, sizeof req, "controlplane.tailscale.com", "/key?v=131");
        EXPECT(n > 0 && strcmp(req, "GET /key?v=131 HTTP/1.1\r\nHost: controlplane.tailscale.com\r\nUser-Agent: tsnet\r\n"
                                     "Connection: close\r\n\r\n") == 0);
    }

    if (failures == 0) {
        printf("tsnet http1_test: ok\n");
    }
    return failures != 0;
}
