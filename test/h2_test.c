// Host test of tsnet's HTTP/2 client. A scripted server: frames built by hand, fed whole and split at every byte,
// and what the client sends parsed back, under ASan and UBSan. The check against Go's real server is probe.c.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "h2.h"
#include "hpack.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

// ---- what the callbacks saw ----
typedef struct {
    char log[8192]; // "head 1 200|field 1 a=b|end 1 0|"
    size_t log_len;
    uint8_t body[1 << 17];
    size_t body_len;
} seen_t;

static void logf_(seen_t *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#include <stdarg.h>
static void logf_(seen_t *s, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(s->log + s->log_len, sizeof s->log - s->log_len, fmt, ap);
    va_end(ap);
    if (n > 0 && s->log_len + (size_t)n < sizeof s->log) {
        s->log_len += (size_t)n;
    }
}

static void on_field(void *ctx, uint32_t st, const char *n, size_t nl, const char *v, size_t vl)
{
    logf_(ctx, "field %u %.*s=%.*s|", (unsigned)st, (int)nl, n, (int)vl, v);
}
static void on_head(void *ctx, uint32_t st, int status)
{
    logf_(ctx, "head %u %d|", (unsigned)st, status);
}
static void on_data(void *ctx, uint32_t st, const uint8_t *d, size_t len)
{
    seen_t *s = ctx;
    (void)st;
    if (s->body_len + len <= sizeof s->body) {
        memcpy(s->body + s->body_len, d, len);
        s->body_len += len;
    }
}
static void on_end(void *ctx, uint32_t st, int err)
{
    logf_(ctx, "end %u %d|", (unsigned)st, err);
}

static seen_t seen;
static tsnet_h2_t *open_h2(int early)
{
    memset(&seen, 0, sizeof seen);
    tsnet_h2_cb_t cb = {&seen, on_field, on_head, on_data, on_end};
    return tsnet_h2_new(&cb, early);
}

// ---- building the server's bytes ----
typedef struct {
    uint8_t b[1 << 18];
    size_t len;
} buf_t;

static void frame(buf_t *o, uint8_t type, uint8_t flags, uint32_t stream, const void *p, size_t len)
{
    uint8_t *q = o->b + o->len;
    q[0] = (uint8_t)(len >> 16), q[1] = (uint8_t)(len >> 8), q[2] = (uint8_t)len;
    q[3] = type, q[4] = flags;
    q[5] = (uint8_t)(stream >> 24), q[6] = (uint8_t)(stream >> 16), q[7] = (uint8_t)(stream >> 8), q[8] = (uint8_t)stream;
    if (len) {
        memcpy(q + 9, p, len);
    }
    o->len += 9 + len;
}

static void settings(buf_t *o, const uint32_t (*kv)[2], size_t n)
{
    uint8_t p[60];
    for (size_t i = 0; i < n; i++) {
        p[6 * i] = (uint8_t)(kv[i][0] >> 8), p[6 * i + 1] = (uint8_t)kv[i][0];
        p[6 * i + 2] = (uint8_t)(kv[i][1] >> 24), p[6 * i + 3] = (uint8_t)(kv[i][1] >> 16);
        p[6 * i + 4] = (uint8_t)(kv[i][1] >> 8), p[6 * i + 5] = (uint8_t)kv[i][1];
    }
    frame(o, 4, 0, 0, p, 6 * n);
}

static size_t block(uint8_t *out, const char *const *fields)
{
    size_t n = 0;
    for (; fields[0]; fields += 2) {
        tsnet_hpack_encode(out, 4096, &n, fields[0], fields[1]);
    }
    return n;
}

static void u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24), p[1] = (uint8_t)(v >> 16), p[2] = (uint8_t)(v >> 8), p[3] = (uint8_t)v;
}

// ---- reading what the client sent ----
typedef struct {
    uint8_t type, flags;
    uint32_t stream, len;
    const uint8_t *p;
} fr_t;

static uint8_t sent[1 << 18];
static size_t sent_len;

static void drain(tsnet_h2_t *h)
{
    const uint8_t *p;
    size_t n;
    while ((n = tsnet_h2_pending(h, &p)) > 0) {
        if (sent_len + n <= sizeof sent) {
            memcpy(sent + sent_len, p, n);
            sent_len += n;
        }
        tsnet_h2_sent(h, n);
    }
}

// The client's frames since the last call (the preface skipped).
static int frames(fr_t *out, int max)
{
    static size_t pos;
    if (sent_len == 0) {
        pos = 0;
    }
    if (pos == 0 && sent_len >= 24 && memcmp(sent, "PRI * HTTP/2.0", 14) == 0) {
        pos = 24;
    }
    int n = 0;
    while (pos + 9 <= sent_len && n < max) {
        fr_t *f = &out[n++];
        f->len = (uint32_t)sent[pos] << 16 | (uint32_t)sent[pos + 1] << 8 | sent[pos + 2];
        f->type = sent[pos + 3], f->flags = sent[pos + 4];
        f->stream = (uint32_t)(sent[pos + 5] & 0x7f) << 24 | (uint32_t)sent[pos + 6] << 16 | (uint32_t)sent[pos + 7] << 8 |
                    sent[pos + 8];
        f->p = sent + pos + 9;
        pos += 9 + f->len;
    }
    return n;
}

static void reset_sent(void)
{
    sent_len = 0;
    fr_t f[1];
    frames(f, 0);
}

static uint32_t g32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

// Is there a frame of this type (and stream, and first payload word) in what the client sent?
static int sent_has(uint8_t type, uint32_t stream, int64_t word)
{
    fr_t f[256];
    size_t save = sent_len;
    (void)save;
    int n;
    static fr_t all[1024];
    static int all_n;
    while ((n = frames(f, 256)) > 0) {
        for (int i = 0; i < n && all_n < 1024; i++) {
            all[all_n++] = f[i];
        }
    }
    for (int i = 0; i < all_n; i++) {
        if (all[i].type == type && all[i].stream == stream && (word < 0 || (all[i].len >= 4 && g32(all[i].p) == word))) {
            return 1;
        }
    }
    if (type == 0xff) { // forget
        all_n = 0;
    }
    return 0;
}

static void forget_sent(void)
{
    sent_has(0xff, 0, -1);
    reset_sent();
}

// The error code of the GOAWAY the client sent (its second word), or -1 if it sent none.
static int64_t goaway_code(void)
{
    size_t pos = sent_len >= 24 && memcmp(sent, "PRI * HTTP/2.0", 14) == 0 ? 24 : 0;
    int64_t code = -1;
    while (pos + 9 <= sent_len) {
        uint32_t len = (uint32_t)sent[pos] << 16 | (uint32_t)sent[pos + 1] << 8 | sent[pos + 2];
        if (sent[pos + 3] == 7 && len >= 8 && pos + 9 + len <= sent_len) {
            code = g32(sent + pos + 9 + 4);
        }
        pos += 9 + len;
    }
    return code;
}

// The server's half of setup: its SETTINGS (empty) and an ACK of ours.
static void server_hello(buf_t *o)
{
    settings(o, NULL, 0);
    frame(o, 4, 1, 0, NULL, 0);
}

static void ignore_fields(void *ctx, const char *n, size_t nl, const char *v, size_t vl)
{
    char *out = ctx;
    size_t l = strlen(out);
    snprintf(out + l, 2048 - l, "%.*s: %.*s\n", (int)nl, n, (int)vl, v);
}

int main(void)
{
    // What a new connection sends: the preface, SETTINGS as Go's (push off, 4 MB stream window, 1 MB frames, our header
    // list size) and a 1 GB connection WINDOW_UPDATE.
    {
        forget_sent();
        tsnet_h2_t *h = open_h2(0);
        drain(h);
        static const uint8_t WANT[] = {'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0', '\r', '\n',
                                       '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n',
                                       0, 0, 24, 4, 0, 0, 0, 0, 0,
                                       0, 2, 0, 0, 0, 0, 0, 4, 0, 0x40, 0, 0, 0, 5, 0, 0x10, 0, 0, 0, 6, 0, 0, 0x40, 0,
                                       0, 0, 4, 8, 0, 0, 0, 0, 0, 0x40, 0, 0, 0};
        EXPECT(sent_len == sizeof WANT && memcmp(sent, WANT, sizeof WANT) == 0);
        tsnet_h2_free(h);
    }

    // A request's HEADERS: Go's field order, :scheme https, content-length for the body, then the body with END_STREAM.
    {
        forget_sent();
        tsnet_h2_t *h = open_h2(0);
        buf_t *o = calloc(1, sizeof *o);
        server_hello(o);
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
        tsnet_h2_header_t hd[] = {{"content-type", "application/json"}};
        uint32_t id = tsnet_h2_request(h, "POST", "controlplane.tailscale.com", "/machine/register", hd, 1,
                                       (const uint8_t *)"{}", 2);
        uint32_t id2 = tsnet_h2_request(h, "GET", "controlplane.tailscale.com", "/x", NULL, 0, NULL, 0);
        EXPECT(id == 1 && id2 == 3);
        drain(h);
        fr_t f[16];
        int n = frames(f, 16);
        // SETTINGS, WINDOW_UPDATE, our ACK of theirs, HEADERS 1, DATA 1, HEADERS 3
        int hi = -1, di = -1, h3 = -1;
        for (int i = 0; i < n; i++) {
            if (f[i].type == 1 && f[i].stream == 1) hi = i;
            if (f[i].type == 0 && f[i].stream == 1) di = i;
            if (f[i].type == 1 && f[i].stream == 3) h3 = i;
        }
        EXPECT(hi >= 0 && di > hi && h3 > di);
        if (hi >= 0 && di >= 0 && h3 >= 0) {
            static tsnet_hpack_dec_t d;
            tsnet_hpack_dec_init(&d, 4096);
            char got[2048] = "";
            EXPECT(f[hi].flags == 0x4); // END_HEADERS, no END_STREAM: a body follows
            EXPECT(tsnet_hpack_decode(&d, f[hi].p, f[hi].len, ignore_fields, got) == 0);
            EXPECT(strcmp(got, ":authority: controlplane.tailscale.com\n:method: POST\n:path: /machine/register\n"
                               ":scheme: https\ncontent-type: application/json\ncontent-length: 2\nuser-agent: tsnet\n") == 0);
            EXPECT(f[di].flags == 0x1 && f[di].len == 2 && memcmp(f[di].p, "{}", 2) == 0);
            got[0] = '\0';
            EXPECT(f[h3].flags == 0x5); // END_HEADERS | END_STREAM: no body, no content-length for a GET
            EXPECT(tsnet_hpack_decode(&d, f[h3].p, f[h3].len, ignore_fields, got) == 0);
            EXPECT(strcmp(got, ":authority: controlplane.tailscale.com\n:method: GET\n:path: /x\n:scheme: https\n"
                               "user-agent: tsnet\n") == 0);
        }
        free(o);
        tsnet_h2_free(h);
    }

    // A response fed at every split point: SETTINGS, a 100 Continue, the head (padded, with priority, across a
    // CONTINUATION), padded DATA, an empty DATA ending it. Same callbacks every time.
    {
        buf_t *o = calloc(1, sizeof *o);
        server_hello(o);
        uint8_t b[4096];
        static const char *const CONT[] = {":status", "100", NULL};
        size_t n = block(b, CONT);
        frame(o, 1, 0x4, 1, b, n);
        static const char *const HEAD[] = {":status", "200", "content-type", "application/json", "content-length", "11",
                                           NULL};
        n = block(b, HEAD);
        uint8_t hp[4200];
        size_t hl = 0;
        hp[hl++] = 3; // pad length
        memset(hp + hl, 0, 5); // priority: depends on 0, weight 0
        hl += 5;
        memcpy(hp + hl, b, 4); // the first 4 bytes of the block
        hl += 4;
        memset(hp + hl, 0, 3);
        hl += 3;
        frame(o, 1, 0x8 | 0x20, 1, hp, hl);        // HEADERS, PADDED | PRIORITY, no END_HEADERS
        frame(o, 9, 0x4, 1, b + 4, n - 4);         // CONTINUATION, END_HEADERS
        uint8_t dp[32];
        dp[0] = 2;
        memcpy(dp + 1, "hello world", 11);
        dp[12] = dp[13] = 0;
        frame(o, 0, 0x8, 1, dp, 14);               // DATA, PADDED
        frame(o, 0, 0x1, 1, NULL, 0);              // DATA, END_STREAM
        const char *want = "field 1 content-type=application/json|field 1 content-length=11|head 1 200|end 1 0|";
        for (size_t cut = 0; cut <= o->len; cut++) {
            tsnet_h2_t *h = open_h2(0);
            EXPECT(tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0) == 1);
            int r1 = tsnet_h2_feed(h, o->b, cut), r2 = tsnet_h2_feed(h, o->b + cut, o->len - cut);
            if (r1 != 0 || r2 != 0 || strcmp(seen.log, want) != 0 || seen.body_len != 11 ||
                memcmp(seen.body, "hello world", 11) != 0) {
                printf("split at %zu: %s (body %zu)\n", cut, seen.log, seen.body_len);
                failures++;
                tsnet_h2_free(h);
                break;
            }
            tsnet_h2_free(h);
        }
        free(o);
    }

    // The early payload: read and dropped before HTTP/2; without its magic the bytes are HTTP/2's.
    {
        static const char JSON[] = "{\"nodeKeyChallenge\":\"chalpub:00\"}";
        buf_t *o = calloc(1, sizeof *o);
        memcpy(o->b, "\xff\xff\xffTS", 5);
        u32(o->b + 5, sizeof JSON - 1);
        memcpy(o->b + 9, JSON, sizeof JSON - 1);
        o->len = 9 + sizeof JSON - 1;
        server_hello(o);
        frame(o, 6, 0, 0, "12345678", 8); // a PING after
        for (size_t cut = 0; cut <= o->len; cut++) {
            forget_sent();
            tsnet_h2_t *h = open_h2(1);
            EXPECT(tsnet_h2_feed(h, o->b, cut) == 0 && tsnet_h2_feed(h, o->b + cut, o->len - cut) == 0);
            drain(h);
            EXPECT(sent_has(6, 0, -1)); // the PING was answered: HTTP/2 came through
            tsnet_h2_free(h);
        }
        forget_sent();
        tsnet_h2_t *h = open_h2(1); // no early payload at all
        EXPECT(tsnet_h2_feed(h, o->b + 9 + sizeof JSON - 1, o->len - 9 - (sizeof JSON - 1)) == 0);
        tsnet_h2_free(h);
        h = open_h2(1); // not JSON
        o->b[9] = '!';
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == -1);
        tsnet_h2_free(h);
        h = open_h2(1); // too long
        u32(o->b + 5, TSNET_H2_EARLY_MAX + 1);
        EXPECT(tsnet_h2_feed(h, o->b, 9) == -1);
        tsnet_h2_free(h);
        free(o);
    }

    // PING is echoed with ACK; flow control comes back as Go's inflow.add gives it: nothing under 4096 bytes, then
    // WINDOW_UPDATEs for the connection and the stream.
    {
        forget_sent();
        tsnet_h2_t *h = open_h2(0);
        buf_t *o = calloc(1, sizeof *o);
        server_hello(o);
        frame(o, 6, 0, 0, "pingpong", 8);
        tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0);
        uint8_t b[64];
        static const char *const HEAD[] = {":status", "200", NULL};
        size_t n = block(b, HEAD);
        frame(o, 1, 0x4, 1, b, n);
        static uint8_t data[5000];
        memset(data, 'd', sizeof data);
        frame(o, 0, 0, 1, data, 4000);
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
        drain(h);
        fr_t f[32];
        int k = frames(f, 32), pong = 0, wu = 0;
        for (int i = 0; i < k; i++) {
            if (f[i].type == 6 && f[i].flags == 1 && memcmp(f[i].p, "pingpong", 8) == 0) pong = 1;
            if (f[i].type == 8 && f[i].stream != 0) wu = 1;
            if (f[i].type == 8 && f[i].stream == 0 && g32(f[i].p) != (1u << 30)) wu = 1;
        }
        EXPECT(pong && !wu); // 4000 bytes: under the refresh minimum
        o->len = 0;
        frame(o, 0, 0, 1, data, 1000);
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
        drain(h);
        k = frames(f, 32);
        int conn = 0, strm = 0;
        for (int i = 0; i < k; i++) {
            if (f[i].type == 8 && f[i].stream == 0 && g32(f[i].p) == 5000) conn = 1;
            if (f[i].type == 8 && f[i].stream == 1 && g32(f[i].p) == 5000) strm = 1;
        }
        EXPECT(conn && strm && seen.body_len == 5000);
        free(o);
        tsnet_h2_free(h);
    }

    // Sending a body as the windows allow: the server's INITIAL_WINDOW_SIZE of 10 lets 10 bytes out, its WINDOW_UPDATE
    // the rest; a body bigger than a frame goes in 16 KB DATA frames.
    {
        forget_sent();
        tsnet_h2_t *h = open_h2(0);
        buf_t *o = calloc(1, sizeof *o);
        static const uint32_t SMALL[][2] = {{4, 10}};
        settings(o, SMALL, 1);
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
        static uint8_t body[40000];
        for (size_t i = 0; i < sizeof body; i++) {
            body[i] = (uint8_t)i;
        }
        EXPECT(tsnet_h2_request(h, "POST", "a", "/", NULL, 0, body, 25) == 1);
        drain(h);
        fr_t f[32];
        int k = frames(f, 32);
        uint32_t sent_data = 0;
        for (int i = 0; i < k; i++) {
            if (f[i].type == 0) sent_data += f[i].len;
        }
        EXPECT(sent_data == 10);
        o->len = 0;
        uint8_t inc[4];
        u32(inc, 100);
        frame(o, 8, 0, 1, inc, 4);
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
        drain(h);
        k = frames(f, 32);
        int ended = 0;
        for (int i = 0; i < k; i++) {
            if (f[i].type == 0) {
                sent_data += f[i].len;
                ended = f[i].flags & 1;
            }
        }
        EXPECT(sent_data == 25 && ended);
        tsnet_h2_free(h);

        // Big windows: 40000 bytes go as 16384 + 16384 + 7232, limited by the connection's 65535.
        forget_sent();
        h = open_h2(0);
        o->len = 0;
        static const uint32_t BIG[][2] = {{4, 1000000}};
        settings(o, BIG, 1);
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
        EXPECT(tsnet_h2_request(h, "POST", "a", "/", NULL, 0, body, sizeof body) == 1);
        drain(h);
        k = frames(f, 32);
        uint32_t sizes[8], ns = 0;
        for (int i = 0; i < k; i++) {
            if (f[i].type == 0 && ns < 8) sizes[ns++] = f[i].len;
        }
        EXPECT(ns == 3 && sizes[0] == 16384 && sizes[1] == 16384 && sizes[2] == 7232);
        tsnet_h2_free(h);
        free(o);
    }

    // RST_STREAM ends the stream with the server's code; GOAWAY ends the streams it doesn't cover, and no new ones start.
    {
        tsnet_h2_t *h = open_h2(0);
        buf_t *o = calloc(1, sizeof *o);
        server_hello(o);
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
        tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0); // 1
        tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0); // 3
        tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0); // 5
        o->len = 0;
        uint8_t p[8];
        u32(p, 8);
        frame(o, 3, 0, 1, p, 4); // RST_STREAM 1 CANCEL
        u32(p, 3);
        u32(p + 4, 0);
        frame(o, 7, 0, 0, p, 8); // GOAWAY last 3
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
        EXPECT(strcmp(seen.log, "end 1 8|end 5 -1|") == 0);
        EXPECT(!tsnet_h2_usable(h) && tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0) == 0);
        tsnet_h2_closed(h); // and the connection closing ends 3
        EXPECT(strcmp(seen.log, "end 1 8|end 5 -1|end 3 -2|") == 0);
        free(o);
        tsnet_h2_free(h);
    }

    // A cancelled stream: RST_STREAM CANCEL sent, its later frames dropped (its header block still decoded, so the
    // table stays in step: the next response uses an entry it added).
    {
        forget_sent();
        tsnet_h2_t *h = open_h2(0);
        buf_t *o = calloc(1, sizeof *o);
        server_hello(o);
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
        tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0); // 1
        tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0); // 3
        tsnet_h2_cancel(h, 1);
        drain(h);
        EXPECT(sent_has(3, 1, 8));
        o->len = 0;
        // stream 1: ":status 200" indexed, and "x-a: b" with incremental indexing (entry 62)
        uint8_t b1[] = {0x88, 0x40, 0x03, 'x', '-', 'a', 0x01, 'b'};
        frame(o, 1, 0x4, 1, b1, sizeof b1);
        frame(o, 0, 0x1, 1, "gone", 4);
        uint8_t b3[] = {0x88, 0xbe}; // stream 3: :status 200, then entry 62
        frame(o, 1, 0x5, 3, b3, sizeof b3);
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
        EXPECT(strcmp(seen.log, "field 3 x-a=b|head 3 200|end 3 0|") == 0 && seen.body_len == 0);
        free(o);
        tsnet_h2_free(h);
    }

    // Stream errors: a head without :status, DATA beyond the content-length; each sends RST_STREAM PROTOCOL_ERROR.
    {
        forget_sent();
        tsnet_h2_t *h = open_h2(0);
        buf_t *o = calloc(1, sizeof *o);
        server_hello(o);
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
        tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0); // 1
        tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0); // 3
        o->len = 0;
        uint8_t nostatus[] = {0x00, 0x01, 'x', 0x01, 'y'};
        frame(o, 1, 0x4, 1, nostatus, sizeof nostatus);
        uint8_t b[64];
        static const char *const H3[] = {":status", "200", "content-length", "2", NULL};
        size_t n = block(b, H3);
        frame(o, 1, 0x4, 3, b, n);
        frame(o, 0, 0, 3, "abc", 3);
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
        drain(h);
        EXPECT(strcmp(seen.log, "end 1 -3|field 3 content-length=2|head 3 200|end 3 -3|") == 0);
        EXPECT(sent_has(3, 1, 1) && sent_has(3, 3, 1));
        EXPECT(tsnet_h2_usable(h)); // the connection lives on
        free(o);
        tsnet_h2_free(h);
    }

    // Connection errors: each sends GOAWAY with its code and ends every stream.
    {
        static const struct {
            const char *what;
            uint8_t type, flags;
            uint32_t stream;
            uint8_t p[16];
            uint32_t len;
            uint32_t code;
        } BAD[] = {
            {"PUSH_PROMISE", 5, 0x4, 1, {0, 0, 0, 2, 0x88}, 5, 1},
            {"DATA on stream 0", 0, 0, 0, {'x'}, 1, 1},
            {"SETTINGS not a multiple of 6", 4, 0, 0, {0, 1, 0, 0, 0}, 5, 6},
            {"SETTINGS on a stream", 4, 0, 1, {0}, 0, 1},
            {"a SETTINGS ACK with a payload", 4, 1, 0, {0, 1, 0, 0, 0, 0}, 6, 6},
            {"an unasked-for SETTINGS ACK", 4, 1, 0, {0}, 0, 1},
            {"ENABLE_PUSH 2", 4, 0, 0, {0, 2, 0, 0, 0, 2}, 6, 1},
            {"MAX_FRAME_SIZE under 16384", 4, 0, 0, {0, 5, 0, 0, 0x3f, 0xff}, 6, 1},
            {"INITIAL_WINDOW_SIZE over 2^31-1", 4, 0, 0, {0, 4, 0x80, 0, 0, 0}, 6, 3},
            {"PING of 7 bytes", 6, 0, 0, {0}, 7, 6},
            {"PING on a stream", 6, 0, 1, {0}, 8, 1},
            {"WINDOW_UPDATE of 0 on the connection", 8, 0, 0, {0, 0, 0, 0}, 4, 1},
            {"WINDOW_UPDATE of 3 bytes", 8, 0, 0, {0, 0, 1}, 3, 6},
            {"RST_STREAM on stream 0", 3, 0, 0, {0, 0, 0, 8}, 4, 1},
            {"GOAWAY of 7 bytes", 7, 0, 0, {0}, 7, 6},
            {"CONTINUATION without HEADERS", 9, 0x4, 1, {0x88}, 1, 1},
            {"PRIORITY of 4 bytes", 2, 0, 1, {0}, 4, 6},
            {"HPACK garbage", 1, 0x4, 1, {0x80}, 1, 9},
            {"DATA for a stream never opened", 0, 0, 9, {'x'}, 1, 1},
            {"a padded DATA frame too short for its pad length", 0, 0x8, 1, {0}, 0, 6},
            {"a pad length past the payload", 0, 0x8, 1, {5, 'x'}, 2, 1},
        };
        for (size_t i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
            forget_sent();
            tsnet_h2_t *h = open_h2(0);
            buf_t *o = calloc(1, sizeof *o);
            server_hello(o);
            EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
            tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0); // 1, open
            o->len = 0;
            frame(o, BAD[i].type, BAD[i].flags, BAD[i].stream, BAD[i].p, BAD[i].len);
            int r = tsnet_h2_feed(h, o->b, o->len);
            drain(h);
            if (r != -1 || goaway_code() != BAD[i].code || strstr(seen.log, "end 1 -2|") == NULL) {
                printf("connection error wrong: %s (feed %d, GOAWAY code %lld, want %u; %s)\n", BAD[i].what, r,
                       (long long)goaway_code(), (unsigned)BAD[i].code, seen.log);
                failures++;
            }
            free(o);
            tsnet_h2_free(h);
        }
        // More, each with its GOAWAY code: the server's first frame isn't SETTINGS; a frame over our 1 MB
        // MAX_FRAME_SIZE; another frame inside a header block; a header block over the size we advertised; trailers
        // without END_STREAM.
        buf_t *o = calloc(1, sizeof *o);
        tsnet_h2_t *h;
#define CONN_CASE(setup, want_code)                                                                \
    do {                                                                                           \
        forget_sent();                                                                             \
        h = open_h2(0);                                                                            \
        o->len = 0;                                                                                \
        setup;                                                                                     \
        int r_ = tsnet_h2_feed(h, o->b, o->len);                                                   \
        drain(h);                                                                                  \
        if (r_ != -1 || goaway_code() != (want_code)) {                                            \
            printf("%s:%d: feed %d, GOAWAY code %lld, want %d\n", __FILE__, __LINE__, r_,          \
                   (long long)goaway_code(), (int)(want_code));                                    \
            failures++;                                                                            \
        }                                                                                          \
        tsnet_h2_free(h);                                                                          \
    } while (0)
        CONN_CASE(frame(o, 6, 0, 0, "12345678", 8), 1);
        static const uint8_t BIG[9] = {0x10, 0, 1, 0, 0, 0, 0, 0, 1}; // DATA of 1 MB + 1 on stream 1
        CONN_CASE((server_hello(o), tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0),
                   memcpy(o->b + o->len, BIG, 9), o->len += 9),
                  6);
        CONN_CASE((server_hello(o), tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0),
                   frame(o, 1, 0, 1, "\x88", 1), frame(o, 6, 0, 0, "12345678", 8)),
                  1);
        static uint8_t huge[TSNET_H2_HEADER_BLOCK_MAX + 1];
        memset(huge, 0x88, sizeof huge);
        CONN_CASE((server_hello(o), tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0),
                   frame(o, 1, 0x4, 1, huge, sizeof huge)),
                  1);
        CONN_CASE((server_hello(o), tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0),
                   frame(o, 1, 0x4, 1, "\x88", 1), frame(o, 1, 0x4, 1, "\x88", 1)),
                  1);

        // The windows: 65 frames of 64 KB, past the stream's 4 MB window, are fine, as each is read as it comes and its
        // window given back (Go's Read does the same). So FLOW_CONTROL_ERROR can't be reached by a server whose frames
        // keep to our 1 MB MAX_FRAME_SIZE: at a frame's start the windows are never short by more than 4 KB unreturned.
        // The check stays, as Go's does (takeInflows).
        h = open_h2(0);
        o->len = 0;
        server_hello(o);
        tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0);
        frame(o, 1, 0x4, 1, "\x88", 1);
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
        static uint8_t lots[65536];
        int ok = 1;
        for (int i = 0; i < 65 && ok; i++) {
            o->len = 0;
            frame(o, 0, 0, 1, lots, sizeof lots);
            ok = tsnet_h2_feed(h, o->b, o->len) == 0;
        }
        EXPECT(ok && seen.body_len == sizeof seen.body); // (the test keeps only the first 128 KB)
        tsnet_h2_free(h);

        // A caller that never sends what's queued: WINDOW_UPDATEs pile up until the queue is full, and then the
        // connection fails rather than drop one and stall the stream silently. (No GOAWAY fits either: the caller
        // sees -1 and closes the transport.)
        forget_sent();
        h = open_h2(0);
        o->len = 0;
        server_hello(o);
        tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0);
        frame(o, 1, 0x4, 1, "\x88", 1);
        EXPECT(tsnet_h2_feed(h, o->b, o->len) == 0);
        int r = 0, frames_fed = 0;
        while (r == 0 && frames_fed < 20000) { // 4 KB frames: a WINDOW_UPDATE for the connection and one for the stream each
            o->len = 0;
            frame(o, 0, 0, 1, lots, 4096);
            r = tsnet_h2_feed(h, o->b, o->len);
            frames_fed++;
        }
        EXPECT(r == -1 && strstr(seen.log, "end 1 -2|") != NULL);
        // Every WINDOW_UPDATE that went into the queue is there: count them against the frames fed before the failure.
        drain(h);
        int wu = 0;
        fr_t f[256];
        int k;
        while ((k = frames(f, 256)) > 0) {
            for (int i = 0; i < k; i++) {
                wu += f[i].type == 8 && f[i].stream != 0;
            }
        }
        EXPECT(wu == frames_fed - 1);
        tsnet_h2_free(h);
        free(o);
    }

    // Garbage after a good start: random frames must end in a connection error or nothing, never a memory error.
    {
        uint32_t seed = 7;
        static uint8_t g[512];
        for (int round = 0; round < 3000; round++) {
            tsnet_h2_t *h = open_h2(round & 1);
            buf_t *o = calloc(1, sizeof *o);
            if (!(round & 1)) {
                server_hello(o);
            }
            tsnet_h2_feed(h, o->b, o->len);
            tsnet_h2_request(h, "GET", "a", "/", NULL, 0, NULL, 0);
            for (int k = 0; k < 8; k++) {
                size_t len = (seed = seed * 1103515245 + 12345) % sizeof g;
                for (size_t j = 0; j < len; j++) {
                    seed = seed * 1103515245 + 12345;
                    g[j] = (uint8_t)(seed >> 16);
                }
                if (len >= 9 && (seed & 3)) { // mostly a plausible frame header
                    size_t plen = len - 9;
                    g[0] = 0, g[1] = (uint8_t)(plen >> 8), g[2] = (uint8_t)plen;
                    g[3] = (uint8_t)(g[3] % 11);
                    g[5] = g[6] = g[7] = 0;
                    g[8] &= 7;
                }
                tsnet_h2_feed(h, g, len);
                drain(h);
            }
            free(o);
            tsnet_h2_free(h);
            reset_sent();
        }
    }

    if (failures == 0) {
        printf("tsnet h2_test: ok\n");
    }
    return failures != 0;
}
