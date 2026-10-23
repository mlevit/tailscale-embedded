// Host test of tsnet's HPACK: RFC 7541 Appendix C and Python hpack's blocks (hpack_vectors.h), every error the
// RFC names, the encoder by round trip, and garbage, under ASan and UBSan.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hpack.h"
#include "hpack_vectors.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

// The fields a decode produced, joined as "name: value\n".
typedef struct {
    char text[8192];
    size_t len;
    int n;
} got_t;

static void collect(void *ctx, const char *name, size_t name_len, const char *value, size_t value_len)
{
    got_t *g = ctx;
    if (g->len + name_len + value_len + 3 < sizeof g->text) {
        memcpy(g->text + g->len, name, name_len);
        g->len += name_len;
        memcpy(g->text + g->len, ": ", 2);
        g->len += 2;
        memcpy(g->text + g->len, value, value_len);
        g->len += value_len;
        g->text[g->len++] = '\n';
    }
    g->n++;
}

static void ignore(void *ctx, const char *name, size_t name_len, const char *value, size_t value_len)
{
    (void)ctx, (void)name, (void)name_len, (void)value, (void)value_len;
}

static int decode(tsnet_hpack_dec_t *d, const uint8_t *b, size_t len, got_t *g)
{
    memset(g, 0, sizeof *g);
    return tsnet_hpack_decode(d, b, len, collect, g);
}

static tsnet_hpack_dec_t d; // 12 KB: off the stack

int main(void)
{
    // Every sequence decodes block by block to its header list, the table carried between blocks.
    for (size_t s = 0; s < sizeof HV_SEQS / sizeof HV_SEQS[0]; s++) {
        tsnet_hpack_dec_init(&d, HV_SEQS[s].table);
        for (size_t b = 0; b < HV_SEQS[s].nblocks; b++) {
            const hv_block_t *hb = &HV_SEQS[s].blocks[b];
            got_t g;
            char want[8192];
            size_t wl = 0;
            for (size_t f = 0; f < hb->nfields; f++) {
                wl += (size_t)snprintf(want + wl, sizeof want - wl, "%s: %s\n", hb->fields[2 * f], hb->fields[2 * f + 1]);
            }
            int r = decode(&d, hb->block, hb->len, &g);
            if (r != 0 || g.n != (int)hb->nfields || g.len != wl || memcmp(g.text, want, wl) != 0) {
                printf("%s, block %zu: decoded wrong\n", HV_SEQS[s].name, b + 1);
                failures++;
            }
        }
    }
    // RFC 7541 C.5.3's table afterwards: three entries, 215 bytes (the RFC's "Table size: 215").
    tsnet_hpack_dec_init(&d, 256);
    for (size_t b = 0; b < HV_SEQS[2].nblocks; b++) {
        got_t g;
        decode(&d, HV_SEQS[2].blocks[b].block, HV_SEQS[2].blocks[b].len, &g);
    }
    EXPECT(d.n == 3 && d.used == 215);

    // Huffman: RFC 7541 C.4.1's "www.example.com", then the errors 5.2 names.
    {
        static const uint8_t WWW[] = {0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
        char out[64];
        int n = tsnet_hpack_huffman_decode(out, sizeof out, WWW, sizeof WWW);
        EXPECT(n == 15 && memcmp(out, "www.example.com", 15) == 0);
        EXPECT(tsnet_hpack_huffman_decode(out, 14, WWW, sizeof WWW) == -1);         // doesn't fit
        static const uint8_t PAD8[] = {0xff};                                        // 8 bits of padding
        EXPECT(tsnet_hpack_huffman_decode(out, sizeof out, PAD8, 1) == -1);
        static const uint8_t PAD0[] = {0x18};                                        // 'a' (00011), then 000
        EXPECT(tsnet_hpack_huffman_decode(out, sizeof out, PAD0, 1) == -1);
        static const uint8_t A_OK[] = {0x1f};                                        // 'a', then 111
        EXPECT(tsnet_hpack_huffman_decode(out, sizeof out, A_OK, 1) == 1 && out[0] == 'a');
        static const uint8_t EOS[] = {0xff, 0xff, 0xff, 0xfc};                       // EOS's 30 ones, then 00
        EXPECT(tsnet_hpack_huffman_decode(out, sizeof out, EOS, 4) == -1);
        static const uint8_t EOS2[] = {0x1f, 0xff, 0xff, 0xff, 0xe0};                // 'a', EOS
        EXPECT(tsnet_hpack_huffman_decode(out, sizeof out, EOS2, 5) == -1);
        EXPECT(tsnet_hpack_huffman_decode(out, sizeof out, NULL, 0) == 0);
    }

    // Representations that are errors (4.2, 5.1, 6.1, 6.2, 6.3).
    {
        static const struct {
            const char *what;
            uint8_t b[12];
            size_t len;
        } BAD[] = {
            {"index 0", {0x80}, 1},
            {"index past the tables", {0xbe}, 1},
            {"an integer over 2^31", {0xff, 0xff, 0xff, 0xff, 0xff, 0x0f}, 6},
            {"too many continuation bytes", {0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 7},
            {"an integer cut short", {0xff, 0x80}, 2},
            {"a size update over the maximum (5000)", {0x3f, 0xe9, 0x26}, 3},
            {"a size update after a field", {0x82, 0x20}, 2},
            {"a literal name cut short", {0x40, 0x05, 'a', 'b'}, 4},
            {"a literal value cut short", {0x40, 0x01, 'a', 0x03, 'b'}, 5},
            {"a literal with a bad name index", {0x7f, 0x10, 0x01, 'x'}, 4},
            {"a string longer than the block", {0x00, 0x7f, 0x80, 0x01}, 4},
            {"a bad Huffman string", {0x00, 0x81, 0xff, 0x81, 0x1f}, 5},
        };
        for (size_t i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
            tsnet_hpack_dec_init(&d, 4096);
            got_t g;
            if (decode(&d, BAD[i].b, BAD[i].len, &g) != -1) {
                printf("accepted %s\n", BAD[i].what);
                failures++;
            }
        }
        // Size updates at the start are fine, several of them too, and they evict.
        tsnet_hpack_dec_init(&d, 4096);
        got_t g;
        static const uint8_t ADD[] = {0x40, 0x01, 'a', 0x01, 'b'}; // a: b, indexed
        EXPECT(decode(&d, ADD, sizeof ADD, &g) == 0 && d.n == 1 && d.used == 34);
        static const uint8_t SHRINK[] = {0x20, 0x3f, 0xe1, 0x1f, 0xbe}; // size 0, size 4096, then index 62: gone
        EXPECT(decode(&d, SHRINK, sizeof SHRINK, &g) == -1);
        EXPECT(d.n == 0 && d.used == 0);
    }

    // An entry bigger than the table empties it (4.4) without an error, and the field is still delivered.
    {
        tsnet_hpack_dec_init(&d, 256);
        uint8_t b[400];
        size_t n = 0;
        static const uint8_t SMALL[] = {0x40, 0x01, 'k', 0x01, 'v'};
        memcpy(b, SMALL, sizeof SMALL);
        n = sizeof SMALL;
        b[n++] = 0x40; // big: 1 + 300 + 32 > 256
        b[n++] = 0x01;
        b[n++] = 'x';
        b[n++] = 0x7f; // the length 300: 127, then 173 = 0x2d | continuation, then 1
        b[n++] = 0xad;
        b[n++] = 0x01;
        memset(b + n, 'y', 300);
        n += 300;
        got_t g;
        EXPECT(decode(&d, b, n, &g) == 0 && g.n == 2 && d.n == 0 && d.used == 0);
        static const uint8_t AGAIN[] = {0xbe}; // index 62: nothing there now
        EXPECT(decode(&d, AGAIN, 1, &g) == -1);
    }

    // The encoder, by round trip through the decoder: static fields, indexed names, new names, a long value.
    {
        uint8_t b[1024];
        size_t n = 0;
        char long_value[300];
        memset(long_value, 'z', sizeof long_value - 1);
        long_value[sizeof long_value - 1] = '\0';
        EXPECT(tsnet_hpack_encode(b, sizeof b, &n, ":method", "POST") == 0 && n == 1 && b[0] == 0x83);
        EXPECT(tsnet_hpack_encode(b, sizeof b, &n, ":scheme", "http") == 0 && b[1] == 0x86);
        EXPECT(tsnet_hpack_encode(b, sizeof b, &n, ":path", "/machine/map") == 0 && b[2] == 0x04 && b[3] == 12);
        EXPECT(tsnet_hpack_encode(b, sizeof b, &n, ":authority", "controlplane.tailscale.com") == 0);
        EXPECT(tsnet_hpack_encode(b, sizeof b, &n, "x-foo", "bar") == 0);
        EXPECT(tsnet_hpack_encode(b, sizeof b, &n, "content-type", long_value) == 0);
        got_t g;
        tsnet_hpack_dec_init(&d, 4096);
        char want[1024];
        snprintf(want, sizeof want,
                 ":method: POST\n:scheme: http\n:path: /machine/map\n:authority: controlplane.tailscale.com\nx-foo: bar\n"
                 "content-type: %s\n",
                 long_value);
        EXPECT(decode(&d, b, n, &g) == 0 && g.n == 6 && g.len == strlen(want) && memcmp(g.text, want, g.len) == 0);
        EXPECT(d.n == 0); // nothing indexed
        size_t m = 5;
        EXPECT(tsnet_hpack_encode(b, 10, &m, "x-foo", "bar") == -1 && m == 5); // doesn't fit: nothing written
    }

    // Garbage: random blocks, and every vector with each byte changed, decode or fail without a memory error.
    {
        uint32_t seed = 1;
        uint8_t b[96];
        for (int i = 0; i < 200000; i++) {
            size_t len = (seed = seed * 1103515245 + 12345) % sizeof b;
            for (size_t j = 0; j < len; j++) {
                seed = seed * 1103515245 + 12345;
                b[j] = (uint8_t)(seed >> 16);
            }
            if (i % 1000 == 0) {
                tsnet_hpack_dec_init(&d, (seed >> 8) % 4097);
            }
            tsnet_hpack_decode(&d, b, len, ignore, NULL);
        }
        for (size_t s = 0; s < sizeof HV_SEQS / sizeof HV_SEQS[0]; s++) {
            const hv_block_t *hb = &HV_SEQS[s].blocks[0];
            uint8_t m[2048];
            if (hb->len > sizeof m) {
                continue;
            }
            for (size_t j = 0; j < hb->len; j++) {
                for (int v = 0; v < 256; v += 51) {
                    memcpy(m, hb->block, hb->len);
                    m[j] = (uint8_t)v;
                    tsnet_hpack_dec_init(&d, HV_SEQS[s].table);
                    tsnet_hpack_decode(&d, m, hb->len, ignore, NULL);
                    tsnet_hpack_decode(&d, m, j, ignore, NULL); // and cut short there
                }
            }
        }
    }

    if (failures == 0) {
        printf("tsnet hpack_test: ok\n");
    }
    return failures != 0;
}
