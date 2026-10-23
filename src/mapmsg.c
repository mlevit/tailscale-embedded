// The map response's messages. See mapmsg.h; the Go is direct.go's readMapResponseMessage and decodeMsg.
#include "mapmsg.h"
#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include "zstd.h"

static const char KEEP_ALIVE[] = "{\"KeepAlive\":true}"; // justKeepAliveStr

struct tsnet_mapmsg {
    bool zstd, dead;
    uint8_t size[4];
    size_t size_have;
    uint32_t want;    // the current message's size
    uint8_t *msg;     // its bytes so far
    size_t have, cap;
    uint8_t *out;     // the decoded JSON
    size_t out_cap;
    ZSTD_DCtx *dctx;
    uint8_t *keep_alive_z; // the compressed keep-alive message, once seen (ms.keepAliveZ)
    size_t keep_alive_z_len;
};

tsnet_mapmsg_t *tsnet_mapmsg_new(bool zstd)
{
    tsnet_mapmsg_t *m = tsnet_calloc(1, sizeof *m);
    if (m == NULL) {
        return NULL;
    }
    m->zstd = zstd;
    if (zstd) {
        m->dctx = ZSTD_createDCtx();
        if (m->dctx == NULL ||
            ZSTD_isError(ZSTD_DCtx_setParameter(m->dctx, ZSTD_d_windowLogMax, TSNET_MAPMSG_WINDOW_LOG))) {
            tsnet_mapmsg_free(m);
            return NULL;
        }
    }
    return m;
}

void tsnet_mapmsg_free(tsnet_mapmsg_t *m)
{
    if (m == NULL) {
        return;
    }
    ZSTD_freeDCtx(m->dctx);
    free(m->msg);
    free(m->out);
    free(m->keep_alive_z);
    free(m);
}

// Grows a buffer to hold `need` bytes, doubling, never past `max`. Returns 0 or -1.
static int grow(uint8_t **buf, size_t *cap, size_t need, size_t max)
{
    if (need <= *cap) {
        return 0;
    }
    size_t n = *cap ? *cap : 4096;
    while (n < need) {
        n *= 2;
    }
    if (n > max) {
        n = max;
    }
    if (n < need) {
        return -1;
    }
    uint8_t *p = tsnet_realloc(*buf, n);
    if (p == NULL) {
        return -1;
    }
    *buf = p;
    *cap = n;
    return 0;
}

// zstdframe.AppendDecode with MaxDecodedSize: every frame in the message, streamed into a buffer that grows up to the
// cap. Returns the decoded length, or -1.
static long decode(tsnet_mapmsg_t *m)
{
    ZSTD_DCtx_reset(m->dctx, ZSTD_reset_session_only);
    ZSTD_inBuffer in = {m->msg, m->have, 0};
    size_t out_len = 0, last = 1;
    while (in.pos < in.size || last != 0) {
        if (out_len == m->out_cap && grow(&m->out, &m->out_cap, out_len + 1, TSNET_MAPMSG_DECODED_MAX) != 0) {
            tsnet_log(TSNET_LOG_WARN, "map message decodes to more than %u bytes", (unsigned)TSNET_MAPMSG_DECODED_MAX);
            return -1;
        }
        ZSTD_outBuffer out = {m->out, m->out_cap, out_len};
        last = ZSTD_decompressStream(m->dctx, &out, &in);
        if (ZSTD_isError(last)) {
            tsnet_log(TSNET_LOG_WARN, "map message: zstd: %s", ZSTD_getErrorName(last));
            return -1;
        }
        if (out.pos == out_len && in.pos == in.size && last != 0 && out.pos < out.size) {
            tsnet_log(TSNET_LOG_WARN, "map message: zstd frame cut short");
            return -1; // no progress, input used up, frame unfinished
        }
        out_len = out.pos;
    }
    return (long)out_len;
}

// One whole message is in m->msg.
static int message(tsnet_mapmsg_t *m, tsnet_mapmsg_fn fn, void *ctx)
{
    if (!m->zstd) {
        fn(ctx, (const char *)m->msg, m->have, false);
        return 0;
    }
    // decodeMsg's fast path: the keep-alive's compressed bytes, once seen, are recognised without decoding.
    if (m->keep_alive_z && m->have == m->keep_alive_z_len && memcmp(m->msg, m->keep_alive_z, m->have) == 0) {
        fn(ctx, KEEP_ALIVE, sizeof KEEP_ALIVE - 1, true);
        return 0;
    }
    long n = decode(m);
    if (n < 0) {
        return -1;
    }
    if ((size_t)n == sizeof KEEP_ALIVE - 1 && memcmp(m->out, KEEP_ALIVE, (size_t)n) == 0 && m->keep_alive_z == NULL) {
        m->keep_alive_z = tsnet_malloc(m->have);
        if (m->keep_alive_z) {
            memcpy(m->keep_alive_z, m->msg, m->have);
            m->keep_alive_z_len = m->have;
        }
    }
    fn(ctx, (const char *)m->out, (size_t)n, false);
    return 0;
}

int tsnet_mapmsg_feed(tsnet_mapmsg_t *m, const uint8_t *data, size_t len, tsnet_mapmsg_fn fn, void *ctx)
{
    size_t i = 0;
    while (i < len && !m->dead) {
        if (m->size_have < 4) {
            m->size[m->size_have++] = data[i++];
            if (m->size_have < 4) {
                continue;
            }
            m->want = (uint32_t)m->size[0] | (uint32_t)m->size[1] << 8 | (uint32_t)m->size[2] << 16 |
                      (uint32_t)m->size[3] << 24;
            if (m->want > TSNET_MAPMSG_WIRE_MAX) { // before any allocation, as Go checks
                tsnet_log(TSNET_LOG_WARN, "map message of %u bytes is over %u", (unsigned)m->want,
                          (unsigned)TSNET_MAPMSG_WIRE_MAX);
                m->dead = true;
                break;
            }
            m->have = 0;
        }
        size_t take = len - i < m->want - m->have ? len - i : m->want - m->have;
        if (grow(&m->msg, &m->cap, m->have + take, TSNET_MAPMSG_WIRE_MAX) != 0) {
            m->dead = true;
            break;
        }
        if (take > 0) { // an empty message leaves m->msg NULL, and memcpy's pointers may not be NULL (glibc's nonnull)
            memcpy(m->msg + m->have, data + i, take);
        }
        m->have += take;
        i += take;
        if (m->have == m->want) {
            m->size_have = 0;
            if (message(m, fn, ctx) != 0) {
                m->dead = true;
            }
        }
    }
    return m->dead ? -1 : 0;
}
