// Host test of tsnet's map message framing and zstd decoding, on test/fixtures/zstd (tools/zstd_fixtures.sh:
// headscale's own frames, and the reference CLI's from a real message), under ASan and UBSan.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mapmsg.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static const char *root;

static unsigned char *slurp(const char *rel, size_t *len)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", root, rel);
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        printf("can't read %s\n", path);
        failures++;
        *len = 0;
        return calloc(1, 1);
    }
    fseek(f, 0, SEEK_END);
    *len = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(*len + 1);
    *len = fread(b, 1, *len, f);
    fclose(f);
    return b;
}

// What the callback saw.
typedef struct {
    int n, keep_alives;
    char last[32768];
    size_t last_len;
    size_t total;
} seen_t;

static void on_msg(void *ctx, const char *json, size_t len, bool keep_alive)
{
    seen_t *s = ctx;
    s->n++;
    s->keep_alives += keep_alive;
    s->total += len;
    s->last_len = len < sizeof s->last ? len : sizeof s->last;
    memcpy(s->last, json, s->last_len);
}

// A message on the wire: its 4-byte little-endian size, then it.
static size_t frame(unsigned char *out, const unsigned char *msg, size_t len)
{
    out[0] = (unsigned char)len, out[1] = (unsigned char)(len >> 8), out[2] = (unsigned char)(len >> 16);
    out[3] = (unsigned char)(len >> 24);
    memcpy(out + 4, msg, len);
    return 4 + len;
}

static int feed_one(bool zstd, const unsigned char *msg, size_t len, seen_t *s)
{
    unsigned char *wire = malloc(len + 4);
    size_t n = frame(wire, msg, len);
    tsnet_mapmsg_t *m = tsnet_mapmsg_new(zstd);
    memset(s, 0, sizeof *s);
    int r = tsnet_mapmsg_feed(m, wire, n, on_msg, s);
    tsnet_mapmsg_free(m);
    free(wire);
    return r;
}

int main(int argc, char **argv)
{
    root = argc > 1 ? argv[1] : "test/fixtures";
    seen_t s;

    // Uncompressed: two messages back to back, split at every byte, come out whole and in order.
    {
        static const char A[] = "{\"KeepAlive\":true}", B[] = "{\"ControlTime\":\"2026-10-23T01:31:30Z\"}";
        unsigned char wire[256];
        size_t n = frame(wire, (const unsigned char *)A, sizeof A - 1);
        n += frame(wire + n, (const unsigned char *)B, sizeof B - 1);
        for (size_t cut = 0; cut <= n; cut++) {
            tsnet_mapmsg_t *m = tsnet_mapmsg_new(false);
            memset(&s, 0, sizeof s);
            int r = tsnet_mapmsg_feed(m, wire, cut, on_msg, &s) | tsnet_mapmsg_feed(m, wire + cut, n - cut, on_msg, &s);
            EXPECT(r == 0 && s.n == 2 && s.last_len == sizeof B - 1 && memcmp(s.last, B, s.last_len) == 0 &&
                   s.total == sizeof A - 1 + sizeof B - 1 && s.keep_alives == 0);
            tsnet_mapmsg_free(m);
        }
    }

    // zstd: the real message (re-encoded single-segment with a checksum) decodes to the JSON exactly.
    {
        size_t zl, jl;
        unsigned char *z = slurp("zstd/map-01.zst", &zl), *j = slurp("headscale/map-01.json", &jl);
        EXPECT(feed_one(true, z, zl, &s) == 0 && s.n == 1 && s.total == jl);
        tsnet_mapmsg_t *m = tsnet_mapmsg_new(true);
        unsigned char *wire = malloc(zl + 4);
        size_t n = frame(wire, z, zl);
        // fed a byte at a time
        memset(&s, 0, sizeof s);
        int r = 0;
        for (size_t i = 0; i < n; i++) {
            r |= tsnet_mapmsg_feed(m, wire + i, 1, on_msg, &s);
        }
        EXPECT(r == 0 && s.n == 1 && s.total == jl);
        tsnet_mapmsg_free(m);
        // a flipped byte in the compressed data: the frame doesn't decode or its checksum fails
        wire[4 + zl / 2] ^= 0x40;
        m = tsnet_mapmsg_new(true);
        EXPECT(tsnet_mapmsg_feed(m, wire, n, on_msg, &s) == -1);
        tsnet_mapmsg_free(m);
        free(wire);
        free(z);
        free(j);
    }

    // headscale's own zstd frames (the encoder Tailscale's code uses too).
    {
        size_t zl;
        unsigned char *z = slurp("zstd/headscale-map-02.zst", &zl);
        EXPECT(feed_one(true, z, zl, &s) == 0 && s.n == 1 && s.last_len > 15 && memcmp(s.last, "{\"ControlTime\":", 15) == 0);
        free(z);
    }

    // The keep-alive fast path: decoded once, then recognised by its compressed bytes.
    {
        size_t zl;
        unsigned char *z = slurp("zstd/keepalive.zst", &zl), wire[128];
        size_t n = frame(wire, z, zl);
        n += frame(wire + n, z, zl);
        n += frame(wire + n, z, zl);
        tsnet_mapmsg_t *m = tsnet_mapmsg_new(true);
        memset(&s, 0, sizeof s);
        EXPECT(tsnet_mapmsg_feed(m, wire, n, on_msg, &s) == 0 && s.n == 3 && s.keep_alives == 2);
        EXPECT(s.last_len == 18 && memcmp(s.last, "{\"KeepAlive\":true}", 18) == 0);
        tsnet_mapmsg_free(m);
        free(z);
    }

    // Two frames in one message decode as one, as zstdframe.AppendDecode does.
    {
        size_t zl;
        unsigned char *z = slurp("zstd/two-frames.zst", &zl);
        EXPECT(feed_one(true, z, zl, &s) == 0 && s.n == 1 &&
               s.last_len == 38 && memcmp(s.last, "{\"ControlTime\":\"2026-10-23T01:31:30Z\"}", 38) == 0);
        free(z);
    }

    // The limits: a bomb past the decoded cap, a window past the cap, a size over the wire cap (no allocation), a
    // truncated frame, garbage.
    {
        size_t zl;
        unsigned char *z = slurp("zstd/bomb.zst", &zl);
        EXPECT(feed_one(true, z, zl, &s) == -1 && s.n == 0);
        free(z);
        z = slurp("zstd/big-window.zst", &zl);
        EXPECT(feed_one(true, z, zl, &s) == -1 && s.n == 0);
        free(z);
        const unsigned char huge[4] = {0x01, 0x00, 0x40, 0x00}; // 4 MB + 1
        tsnet_mapmsg_t *m = tsnet_mapmsg_new(false);
        EXPECT(tsnet_mapmsg_feed(m, huge, 4, on_msg, &s) == -1);
        EXPECT(tsnet_mapmsg_feed(m, (const unsigned char *)"x", 1, on_msg, &s) == -1); // stays failed
        tsnet_mapmsg_free(m);
        z = slurp("zstd/map-01.zst", &zl);
        EXPECT(feed_one(true, z, zl / 2, &s) == -1 && s.n == 0); // half a frame, sized as a whole message
        free(z);
        EXPECT(feed_one(true, (const unsigned char *)"{\"KeepAlive\":true}", 18, &s) == -1); // not zstd
    }

    // Garbage of every length as compressed messages: an error or a message, never a memory error.
    {
        uint32_t seed = 3;
        unsigned char g[600];
        for (int i = 0; i < 20000; i++) {
            size_t len = (seed = seed * 1103515245 + 12345) % sizeof g;
            for (size_t k = 0; k < len; k++) {
                seed = seed * 1103515245 + 12345;
                g[k] = (unsigned char)(seed >> 16);
            }
            if (len > 4 && (seed & 1)) { // often a valid zstd magic, so the frame parser runs
                g[0] = 0x28, g[1] = 0xb5, g[2] = 0x2f, g[3] = 0xfd;
            }
            feed_one(true, g, len, &s);
        }
    }

    if (failures == 0) {
        printf("tsnet mapmsg_test: ok\n");
    }
    return failures != 0;
}
