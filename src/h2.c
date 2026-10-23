// The HTTP/2 client of the control protocol. See h2.h. The Go it follows is golang.org/x/net/http2
// (transport.go, frame.go, flow.go) and control/ts2021/conn.go; RFC 9113 where Go leaves it to the spec.
#include "h2.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "json.h"
#include "hpack.h"
#include "platform.h"

// RFC 9113 section 6.
enum { F_DATA = 0, F_HEADERS = 1, F_PRIORITY = 2, F_RST_STREAM = 3, F_SETTINGS = 4, F_PUSH_PROMISE = 5, F_PING = 6,
       F_GOAWAY = 7, F_WINDOW_UPDATE = 8, F_CONTINUATION = 9 };
enum { FL_END_STREAM = 0x1, FL_ACK = 0x1, FL_END_HEADERS = 0x4, FL_PADDED = 0x8, FL_PRIORITY = 0x20 };
enum { S_HEADER_TABLE_SIZE = 1, S_ENABLE_PUSH = 2, S_MAX_CONCURRENT_STREAMS = 3, S_INITIAL_WINDOW_SIZE = 4,
       S_MAX_FRAME_SIZE = 5, S_MAX_HEADER_LIST_SIZE = 6, S_ENABLE_CONNECT_PROTOCOL = 8 };

#define INITIAL_WINDOW 65535          // http2.go initialWindowSize
#define CONN_FLOW (1 << 30)           // transport.go transportDefaultConnFlow
#define STREAM_FLOW (4 << 20)         // transportDefaultStreamFlow
#define MAX_READ_FRAME (1 << 20)      // http2.go defaultMaxReadFrameSize
#define MIN_REFRESH 4096              // flow.go inflowMinRefresh
#define MAX_WINDOW 0x7fffffff         // maxFlowWindow
#define INITIAL_MAX_CONCURRENT 100    // initialMaxConcurrentStreams
#define DEFAULT_MAX_CONCURRENT 1000   // defaultMaxConcurrentStreams
#define SEND_CHUNK 16384              // our DATA frames: the smallest MAX_FRAME_SIZE, so always allowed
#define OUT_MAX (3 * (9 + SEND_CHUNK)) // queued bytes to send
#define CONTROL_ROOM 1024             // kept free in the queue for SETTINGS ACKs, PINGs, WINDOW_UPDATEs, RST_STREAMs
#define EARLY_MAGIC "\xff\xff\xffTS"   // ts2021 EarlyPayloadMagic

static const char PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// flow.go inflow: the window we've given the peer, and what it has used that we haven't given back yet.
typedef struct {
    int32_t avail, unsent;
} inflow_t;

// flow.go inflow.add: returns the WINDOW_UPDATE to send now, if any.
static int32_t inflow_add(inflow_t *f, int32_t n)
{
    int32_t unsent = f->unsent + n;
    f->unsent = unsent;
    if (f->unsent < MIN_REFRESH && f->unsent < f->avail) {
        return 0;
    }
    f->avail += f->unsent;
    f->unsent = 0;
    return unsent;
}

typedef struct {
    uint32_t id; // 0: free
    int past_headers, past_trailers;
    int64_t content_left; // the body bytes the content-length still promises, or -1
    inflow_t in;
    int64_t out; // our send window
    uint8_t *body;
    size_t body_len, body_sent;
    int end_sent; // END_STREAM went out
} stream_t;

struct tsnet_h2 {
    tsnet_h2_cb_t cb;
    int dead, goaway;
    uint32_t goaway_last;
    // ts2021's early payload: 0 reading its 9-byte header, 1 reading the JSON, 2 done (or none)
    int early;
    uint8_t early_hdr[9];
    size_t early_have;
    uint32_t early_len;
    char early_json[TSNET_H2_EARLY_MAX];
    // the frame being read
    uint8_t fh[9];
    size_t fh_have;
    uint32_t f_len, f_stream, f_got;
    uint8_t f_type, f_flags;
    int f_pad;        // the padding length, or -1 until read
    uint32_t f_data;  // DATA: the payload bytes that are data
    stream_t *f_target; // DATA: the stream the data goes to, or NULL to drop it
    uint8_t small[8]; // the first bytes of a small frame, or the setting being read
    size_t small_have;
    int got_settings, seen_settings, want_settings_ack, seen_max_concurrent;
    // a header block being gathered
    int in_block, block_end_stream;
    uint32_t block_stream;
    size_t block_len;
    uint8_t block[TSNET_H2_HEADER_BLOCK_MAX];
    tsnet_hpack_dec_t hdec;
    // flow control and limits
    inflow_t in;
    int64_t out;
    uint32_t peer_initial_window, peer_max_frame, max_concurrent, next_stream;
    stream_t streams[TSNET_H2_STREAMS];
    // to send
    uint8_t out_buf[OUT_MAX];
    size_t out_off, out_len;
};

// ---- sending ----

static size_t out_room(tsnet_h2_t *h)
{
    return OUT_MAX - (h->out_len - h->out_off);
}

static int put_frame(tsnet_h2_t *h, uint8_t type, uint8_t flags, uint32_t stream, const uint8_t *payload, size_t len)
{
    if (9 + len > out_room(h)) {
        return -1;
    }
    if (h->out_len + 9 + len > OUT_MAX) { // compact: the unsent bytes to the front
        memmove(h->out_buf, h->out_buf + h->out_off, h->out_len - h->out_off);
        h->out_len -= h->out_off;
        h->out_off = 0;
    }
    uint8_t *p = h->out_buf + h->out_len;
    p[0] = (uint8_t)(len >> 16);
    p[1] = (uint8_t)(len >> 8);
    p[2] = (uint8_t)len;
    p[3] = type;
    p[4] = flags;
    p[5] = (uint8_t)(stream >> 24 & 0x7f);
    p[6] = (uint8_t)(stream >> 16);
    p[7] = (uint8_t)(stream >> 8);
    p[8] = (uint8_t)stream;
    if (len) {
        memcpy(p + 9, payload, len);
    }
    h->out_len += 9 + len;
    return 0;
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void conn_error(tsnet_h2_t *h, uint32_t code);

// A control frame (WINDOW_UPDATE, RST_STREAM, a SETTINGS or PING ACK) must not be lost: a lost WINDOW_UPDATE would stall
// the stream for good with no error. If the caller lets the queue fill (it isn't sending), the connection fails instead,
// which shows as a reconnect.
static void control(tsnet_h2_t *h, uint8_t type, uint8_t flags, uint32_t stream, const uint8_t *payload, size_t len)
{
    if (!h->dead && put_frame(h, type, flags, stream, payload, len) != 0) {
        tsnet_log(TSNET_LOG_WARN, "HTTP/2 send queue full: closing the connection");
        conn_error(h, TSNET_H2_INTERNAL_ERROR);
    }
}

static void window_update(tsnet_h2_t *h, uint32_t stream, int32_t n)
{
    uint8_t p[4];
    put32(p, (uint32_t)n & MAX_WINDOW);
    control(h, F_WINDOW_UPDATE, 0, stream, p, 4);
}

static void rst_stream(tsnet_h2_t *h, uint32_t stream, uint32_t code)
{
    uint8_t p[4];
    put32(p, code);
    control(h, F_RST_STREAM, 0, stream, p, 4);
}

static stream_t *find(tsnet_h2_t *h, uint32_t id)
{
    for (int i = 0; i < TSNET_H2_STREAMS; i++) {
        if (h->streams[i].id == id && id != 0) {
            return &h->streams[i];
        }
    }
    return NULL;
}

// A request body can hold a secret (a register's auth key): wiped before it's freed.
static void body_free(stream_t *s)
{
    if (s->body) {
        tsnet_wipe(s->body, s->body_len);
        free(s->body);
        s->body = NULL;
    }
}

static void stream_free(stream_t *s)
{
    body_free(s);
    memset(s, 0, sizeof *s);
}

// Ends a stream: tells the caller and frees it.
static void stream_end(tsnet_h2_t *h, stream_t *s, int err)
{
    uint32_t id = s->id;
    if (id == 0) {
        return; // already ended (a connection error on the way here ended every stream)
    }
    if (h->f_target == s) {
        h->f_target = NULL;
    }
    stream_free(s);
    h->cb.end(h->cb.ctx, id, err);
}

// A stream error (RFC 9113 5.4.2): RST_STREAM to the server, the stream over for the caller (Go: endStreamError).
static void stream_error(tsnet_h2_t *h, stream_t *s, uint32_t code)
{
    rst_stream(h, s->id, code);
    stream_end(h, s, TSNET_H2_ERR_RESPONSE);
}

// A connection error (5.4.1): GOAWAY with the code (Go's readLoop: WriteGoAway(0, code)), every stream over.
static void conn_error(tsnet_h2_t *h, uint32_t code)
{
    if (h->dead) {
        return;
    }
    tsnet_log(TSNET_LOG_WARN, "HTTP/2 connection error 0x%x (frame type %u, stream %u)", (unsigned)code,
              (unsigned)h->f_type, (unsigned)h->f_stream);
    h->dead = 1;
    uint8_t p[8];
    put32(p, 0);
    put32(p + 4, code);
    put_frame(h, F_GOAWAY, 0, 0, p, 8);
    for (int i = 0; i < TSNET_H2_STREAMS; i++) {
        if (h->streams[i].id) {
            stream_end(h, &h->streams[i], TSNET_H2_ERR_CONN);
        }
    }
}

// Sends what the windows and the queue allow of each stream's body (Go: writeRequestBody, one frame at a time).
static void pump(tsnet_h2_t *h)
{
    for (int i = 0; i < TSNET_H2_STREAMS && !h->dead; i++) {
        stream_t *s = &h->streams[i];
        while (s->id && !s->end_sent) {
            size_t left = s->body_len - s->body_sent, n = left;
            int64_t window = s->out < h->out ? s->out : h->out;
            if ((int64_t)n > window) {
                n = window > 0 ? (size_t)window : 0;
            }
            if (n > SEND_CHUNK) {
                n = SEND_CHUNK;
            }
            if (n > h->peer_max_frame) {
                n = h->peer_max_frame;
            }
            size_t room = out_room(h);
            if (room < 9 + CONTROL_ROOM + n) {
                n = room > 9 + CONTROL_ROOM ? room - 9 - CONTROL_ROOM : 0;
            }
            if (n == 0 && left > 0) {
                break; // wait for a window or room
            }
            int last = n == left;
            put_frame(h, F_DATA, last ? FL_END_STREAM : 0, s->id, s->body + s->body_sent, n);
            s->body_sent += n;
            s->out -= (int64_t)n;
            h->out -= (int64_t)n;
            if (last) {
                s->end_sent = 1;
                body_free(s);
            }
        }
    }
}

// ---- receiving ----

typedef struct {
    tsnet_h2_t *h;
    stream_t *s;
    int status, saw_regular, invalid, deliver;
    int64_t content_length;
} head_ctx_t;

// A response head's field (Go's framer checks and handleResponse): pseudo-headers first and only :status, names in
// lower case; the regular fields go to the caller once the status says this is the final response.
static void head_field(void *ctx, const char *name, size_t name_len, const char *value, size_t value_len)
{
    head_ctx_t *c = ctx;
    if (name_len > 0 && name[0] == ':') {
        if (c->saw_regular || c->status >= 0 || strcmp(name, ":status") != 0 || value_len != 3) {
            c->invalid = 1;
            return;
        }
        int v = 0;
        for (int i = 0; i < 3; i++) {
            if (value[i] < '0' || value[i] > '9') {
                c->invalid = 1;
                return;
            }
            v = v * 10 + (value[i] - '0');
        }
        c->status = v;
        c->deliver = v >= 200;
        return;
    }
    c->saw_regular = 1;
    for (size_t i = 0; i < name_len; i++) {
        if (name[i] >= 'A' && name[i] <= 'Z') {
            c->invalid = 1; // RFC 9113 8.2.1: field names in lower case
            return;
        }
    }
    if (c->status < 0) {
        c->invalid = 1;
        return;
    }
    if (!c->deliver || c->invalid) {
        return;
    }
    if (strcmp(name, "content-length") == 0) {
        // handleResponse: a valid one is used; conflicting or bad ones are dropped (the length is then unknown).
        char *end;
        long long n = value_len > 0 && value_len < 19 ? strtoll(value, &end, 10) : -1;
        int ok = n >= 0 && end == value + value_len;
        if (c->content_length == -1 && ok) {
            c->content_length = n;
        } else if (c->content_length != -2 && (!ok || n != c->content_length)) {
            c->content_length = -2; // conflicting: unknown
        }
    }
    c->h->cb.field(c->h->cb.ctx, c->s->id, name, name_len, value, value_len);
}

static void ignore_field(void *ctx, const char *name, size_t name_len, const char *value, size_t value_len)
{
    (void)ctx, (void)name, (void)name_len, (void)value, (void)value_len;
}

// A whole header block has arrived (Go: processHeaders, handleResponse, processTrailers).
static void header_block(tsnet_h2_t *h)
{
    stream_t *s = find(h, h->block_stream);
    if (s == NULL || s->past_trailers) {
        // A stream we cancelled or finished: decode it anyway, or HPACK's table would drift from the server's.
        if (tsnet_hpack_decode(&h->hdec, h->block, h->block_len, ignore_field, NULL) != 0) {
            conn_error(h, TSNET_H2_COMPRESSION_ERROR);
        }
        return;
    }
    if (s->past_headers) { // trailers
        if (tsnet_hpack_decode(&h->hdec, h->block, h->block_len, ignore_field, NULL) != 0) {
            conn_error(h, TSNET_H2_COMPRESSION_ERROR);
            return;
        }
        if (!h->block_end_stream) {
            conn_error(h, TSNET_H2_PROTOCOL_ERROR); // processTrailers: trailers must end the stream
            return;
        }
        s->past_trailers = 1;
        stream_end(h, s, s->content_left > 0 ? TSNET_H2_ERR_RESPONSE : 0);
        return;
    }
    head_ctx_t c = {h, s, -1, 0, 0, 0, -1};
    if (tsnet_hpack_decode(&h->hdec, h->block, h->block_len, head_field, &c) != 0) {
        conn_error(h, TSNET_H2_COMPRESSION_ERROR);
        return;
    }
    if (c.invalid || c.status < 0) {
        stream_error(h, s, TSNET_H2_PROTOCOL_ERROR);
        return;
    }
    if (c.status < 200) { // 1xx: skipped, the real head follows (handleResponse returns nil, nil)
        if (h->block_end_stream) {
            stream_error(h, s, TSNET_H2_PROTOCOL_ERROR);
        }
        return;
    }
    s->past_headers = 1;
    s->content_left = c.content_length >= 0 ? c.content_length : -1;
    h->cb.head(h->cb.ctx, s->id, c.status);
    if (h->block_end_stream) {
        stream_end(h, s, s->content_left > 0 ? TSNET_H2_ERR_RESPONSE : 0); // a promised body missing
    }
}

// The 9-byte header of a frame is in: check it and set up reading its payload.
static void frame_start(tsnet_h2_t *h)
{
    h->f_len = (uint32_t)h->fh[0] << 16 | (uint32_t)h->fh[1] << 8 | h->fh[2];
    h->f_type = h->fh[3];
    h->f_flags = h->fh[4];
    h->f_stream = get32(h->fh + 5) & MAX_WINDOW;
    h->f_got = 0;
    h->f_pad = -1;
    h->small_have = 0;
    h->f_target = NULL;
    if (h->f_len > MAX_READ_FRAME) {
        conn_error(h, TSNET_H2_FRAME_SIZE_ERROR); // ErrFrameTooLarge
        return;
    }
    // checkFrameOrder: a header block's CONTINUATIONs come straight after it, on its stream.
    if (h->in_block ? (h->f_type != F_CONTINUATION || h->f_stream != h->block_stream) : h->f_type == F_CONTINUATION) {
        conn_error(h, TSNET_H2_PROTOCOL_ERROR);
        return;
    }
    // readLoop.run: the server's SETTINGS (any SETTINGS frame) come first.
    if (!h->got_settings && h->f_type != F_SETTINGS) {
        conn_error(h, TSNET_H2_PROTOCOL_ERROR);
        return;
    }
    h->got_settings = 1;
    uint32_t prefix = 0; // DATA's and HEADERS' fields before the content (readByte/readUint32 fail if they're missing)
    if ((h->f_type == F_DATA || h->f_type == F_HEADERS) && (h->f_flags & FL_PADDED)) {
        prefix = 1;
    }
    if (h->f_type == F_HEADERS && (h->f_flags & FL_PRIORITY)) {
        prefix += 5;
    }
    switch (h->f_type) {
    case F_DATA:
        if (h->f_stream == 0) {
            conn_error(h, TSNET_H2_PROTOCOL_ERROR);
        } else if (prefix > h->f_len) {
            conn_error(h, TSNET_H2_FRAME_SIZE_ERROR);
        }
        break;
    case F_PRIORITY: // parsePriorityFrame; then ignored, as Go's Transport does
        if (h->f_stream == 0) {
            conn_error(h, TSNET_H2_PROTOCOL_ERROR);
        } else if (h->f_len != 5) {
            conn_error(h, TSNET_H2_FRAME_SIZE_ERROR);
        }
        break;
    case F_HEADERS:
        if (h->f_stream == 0) {
            conn_error(h, TSNET_H2_PROTOCOL_ERROR);
            return;
        }
        if (prefix > h->f_len) {
            conn_error(h, TSNET_H2_FRAME_SIZE_ERROR);
            return;
        }
        h->in_block = 1;
        h->block_stream = h->f_stream;
        h->block_len = 0;
        h->block_end_stream = h->f_flags & FL_END_STREAM;
        break;
    case F_SETTINGS:
        if (h->f_stream != 0) {
            conn_error(h, TSNET_H2_PROTOCOL_ERROR);
        } else if (h->f_flags & FL_ACK ? h->f_len != 0 : h->f_len % 6 != 0) {
            conn_error(h, TSNET_H2_FRAME_SIZE_ERROR);
        } else if (h->f_flags & FL_ACK) {
            if (!h->want_settings_ack) {
                conn_error(h, TSNET_H2_PROTOCOL_ERROR); // processSettingsNoWrite: an ACK we didn't ask for
            }
            h->want_settings_ack = 0;
        }
        break;
    case F_PING:
        if (h->f_len != 8) {
            conn_error(h, TSNET_H2_FRAME_SIZE_ERROR);
        } else if (h->f_stream != 0) {
            conn_error(h, TSNET_H2_PROTOCOL_ERROR);
        }
        break;
    case F_GOAWAY:
        if (h->f_stream != 0) {
            conn_error(h, TSNET_H2_PROTOCOL_ERROR);
        } else if (h->f_len < 8) {
            conn_error(h, TSNET_H2_FRAME_SIZE_ERROR);
        }
        break;
    case F_WINDOW_UPDATE:
        if (h->f_len != 4) {
            conn_error(h, TSNET_H2_FRAME_SIZE_ERROR);
        }
        break;
    case F_RST_STREAM:
        if (h->f_len != 4) {
            conn_error(h, TSNET_H2_FRAME_SIZE_ERROR);
        } else if (h->f_stream == 0) {
            conn_error(h, TSNET_H2_PROTOCOL_ERROR);
        }
        break;
    case F_PUSH_PROMISE:
        conn_error(h, TSNET_H2_PROTOCOL_ERROR); // processPushPromise: we said ENABLE_PUSH 0
        break;
    default: // PRIORITY, CONTINUATION (checked above) and unknown types: their payload is read or skipped below
        break;
    }
}

// DATA's checks once its padding length (if any) is known (Go: parseDataFrame, processData).
static void data_start(tsnet_h2_t *h)
{
    uint32_t prefix = (h->f_flags & FL_PADDED) ? 1 : 0;
    if ((uint32_t)h->f_pad + prefix > h->f_len) {
        conn_error(h, TSNET_H2_PROTOCOL_ERROR); // pad size larger than the payload
        return;
    }
    h->f_data = h->f_len - prefix - (uint32_t)h->f_pad;
    stream_t *s = find(h, h->f_stream);
    if (s == NULL) {
        if (h->f_stream >= h->next_stream) {
            conn_error(h, TSNET_H2_PROTOCOL_ERROR); // DATA for a stream we never opened
            return;
        }
        // One we cancelled or finished: drop it, but return the connection's flow control.
        if (h->f_len > 0) {
            if ((uint32_t)h->in.avail < h->f_len) {
                conn_error(h, TSNET_H2_FLOW_CONTROL_ERROR);
                return;
            }
            h->in.avail -= (int32_t)h->f_len;
            int32_t add = inflow_add(&h->in, (int32_t)h->f_len);
            if (add) {
                window_update(h, 0, add);
            }
        }
        return;
    }
    if (!s->past_headers || s->past_trailers) {
        stream_error(h, s, TSNET_H2_PROTOCOL_ERROR); // DATA before the head, or after the end
        return;
    }
    if (h->f_len > 0) {
        // takeInflows: both windows must hold the whole frame.
        if ((uint32_t)h->in.avail < h->f_len || (uint32_t)s->in.avail < h->f_len) {
            conn_error(h, TSNET_H2_FLOW_CONTROL_ERROR);
            return;
        }
        h->in.avail -= (int32_t)h->f_len;
        s->in.avail -= (int32_t)h->f_len;
        // The padding is returned now; it will never be "read".
        int32_t refund = (int32_t)(h->f_len - h->f_data);
        if (refund) {
            int32_t c = inflow_add(&h->in, refund), st = inflow_add(&s->in, refund);
            if (c) {
                window_update(h, 0, c);
            }
            if (st) {
                window_update(h, s->id, st);
            }
        }
    }
    h->f_target = s;
}

// Some of a DATA frame's data: to the caller, then its flow control back (Go: transportResponseBody.Read).
static void data_bytes(tsnet_h2_t *h, const uint8_t *p, size_t n)
{
    stream_t *s = h->f_target;
    if (s == NULL || n == 0) {
        return;
    }
    if (s->content_left >= 0) {
        if ((int64_t)n > s->content_left) {
            stream_error(h, s, TSNET_H2_PROTOCOL_ERROR); // more than the content-length
            return;
        }
        s->content_left -= (int64_t)n;
    }
    uint32_t id = s->id;
    h->cb.data(h->cb.ctx, id, p, n);
    int32_t c = inflow_add(&h->in, (int32_t)n);
    int32_t st = (h->f_flags & FL_END_STREAM) ? 0 : inflow_add(&s->in, (int32_t)n);
    if (c) {
        window_update(h, 0, c);
    }
    if (st) {
        window_update(h, id, st);
    }
}

// One SETTINGS entry (Go: Setting.Valid, processSettingsNoWrite).
static void setting(tsnet_h2_t *h, uint16_t id, uint32_t v)
{
    switch (id) {
    case S_ENABLE_PUSH:
    case S_ENABLE_CONNECT_PROTOCOL:
        if (v > 1) {
            conn_error(h, TSNET_H2_PROTOCOL_ERROR);
        }
        break;
    case S_INITIAL_WINDOW_SIZE: {
        if (v > MAX_WINDOW) {
            conn_error(h, TSNET_H2_FLOW_CONTROL_ERROR);
            return;
        }
        // changeInitialWindowSize: every stream's send window moves by the difference.
        int64_t delta = (int64_t)v - h->peer_initial_window;
        for (int i = 0; i < TSNET_H2_STREAMS; i++) {
            if (h->streams[i].id && h->streams[i].out + delta > MAX_WINDOW) {
                conn_error(h, TSNET_H2_FLOW_CONTROL_ERROR);
                return;
            }
        }
        for (int i = 0; i < TSNET_H2_STREAMS; i++) {
            if (h->streams[i].id) {
                h->streams[i].out += delta;
            }
        }
        h->peer_initial_window = v;
        break;
    }
    case S_MAX_FRAME_SIZE:
        if (v < 16384 || v > (1u << 24) - 1) {
            conn_error(h, TSNET_H2_PROTOCOL_ERROR);
            return;
        }
        h->peer_max_frame = v;
        break;
    case S_MAX_CONCURRENT_STREAMS:
        h->max_concurrent = v;
        h->seen_max_concurrent = 1;
        break;
    default: // HEADER_TABLE_SIZE (our encoder keeps no table), MAX_HEADER_LIST_SIZE, unknown: nothing to do
        break;
    }
}

// The whole payload is in: act on the small frames (their bytes are in h->small).
static void frame_end(tsnet_h2_t *h)
{
    switch (h->f_type) {
    case F_DATA:
        if ((h->f_flags & FL_END_STREAM) && h->f_target != NULL) {
            stream_t *s = h->f_target;
            stream_end(h, s, s->content_left > 0 ? TSNET_H2_ERR_RESPONSE : 0);
        }
        break;
    case F_HEADERS:
    case F_CONTINUATION:
        if (h->f_flags & FL_END_HEADERS) {
            h->in_block = 0;
            header_block(h);
        }
        break;
    case F_SETTINGS:
        if (!(h->f_flags & FL_ACK)) {
            if (!h->seen_settings && !h->seen_max_concurrent) {
                h->max_concurrent = DEFAULT_MAX_CONCURRENT; // the first SETTINGS didn't limit streams
            }
            h->seen_settings = 1;
            control(h, F_SETTINGS, FL_ACK, 0, NULL, 0);
            pump(h);
        }
        break;
    case F_PING:
        if (!(h->f_flags & FL_ACK)) {
            control(h, F_PING, FL_ACK, 0, h->small, 8); // processPing: echo it
        }
        break;
    case F_GOAWAY: {
        // processGoAway, setGoAway: no new streams; the ones past LastStreamID won't be answered.
        h->goaway = 1;
        h->goaway_last = get32(h->small) & MAX_WINDOW;
        uint32_t code = get32(h->small + 4);
        tsnet_log(code ? TSNET_LOG_WARN : TSNET_LOG_INFO, "HTTP/2 GOAWAY (last stream %u, code 0x%x)",
                  (unsigned)h->goaway_last, (unsigned)code);
        for (int i = 0; i < TSNET_H2_STREAMS; i++) {
            if (h->streams[i].id > h->goaway_last) {
                stream_end(h, &h->streams[i], TSNET_H2_ERR_GOAWAY);
            }
        }
        break;
    }
    case F_WINDOW_UPDATE: {
        uint32_t inc = get32(h->small) & MAX_WINDOW;
        stream_t *s = h->f_stream ? find(h, h->f_stream) : NULL;
        if (inc == 0) {
            if (h->f_stream == 0) {
                conn_error(h, TSNET_H2_PROTOCOL_ERROR);
            } else if (s) {
                stream_error(h, s, TSNET_H2_PROTOCOL_ERROR);
            }
            return;
        }
        if (h->f_stream == 0) {
            if (h->out + inc > MAX_WINDOW) {
                conn_error(h, TSNET_H2_FLOW_CONTROL_ERROR);
                return;
            }
            h->out += inc;
        } else if (s) {
            if (s->out + inc > MAX_WINDOW) {
                stream_error(h, s, TSNET_H2_FLOW_CONTROL_ERROR);
                return;
            }
            s->out += inc;
        }
        pump(h);
        break;
    }
    case F_RST_STREAM: {
        stream_t *s = find(h, h->f_stream);
        if (s) {
            // processResetStream: the server's code, a StreamError even for NO_ERROR. Here 0 means a whole response,
            // so a reset with code 0 (or one past int) is a malformed one.
            uint32_t code = get32(h->small);
            stream_end(h, s, code == 0 || code > 0x7fffffff ? TSNET_H2_ERR_RESPONSE : (int)code);
        }
        break;
    }
    default:
        break;
    }
}

// Feeds payload bytes of the current frame. Returns how many it took.
static size_t frame_payload(tsnet_h2_t *h, const uint8_t *p, size_t n)
{
    size_t left = h->f_len - h->f_got;
    if (n > left) {
        n = left;
    }
    size_t i = 0;
    switch (h->f_type) {
    case F_DATA:
        if (h->f_pad < 0) {
            if (h->f_flags & FL_PADDED) {
                if (n == 0) {
                    return 0;
                }
                h->f_pad = p[i++];
            } else {
                h->f_pad = 0;
            }
            data_start(h);
            if (h->dead) {
                return i;
            }
        }
        {
            uint32_t prefix = (h->f_flags & FL_PADDED) ? 1 : 0;
            uint32_t pos = h->f_got + (uint32_t)i - prefix; // position within data + padding
            if (pos < h->f_data) {
                size_t take = n - i;
                if (take > h->f_data - pos) {
                    take = h->f_data - pos;
                }
                data_bytes(h, p + i, take);
                i += take;
            }
            i = n; // the rest is padding
        }
        break;
    case F_HEADERS:
    case F_CONTINUATION:
        for (; i < n; i++) {
            uint32_t at = h->f_got + (uint32_t)i;
            uint32_t prefix = 0;
            if (h->f_type == F_HEADERS) {
                if (h->f_flags & FL_PADDED) {
                    if (at == 0) {
                        h->f_pad = p[i];
                        continue;
                    }
                    prefix = 1;
                }
                if (h->f_flags & FL_PRIORITY) {
                    if (at < prefix + 5) {
                        continue; // the priority fields, ignored as Go does
                    }
                    prefix += 5;
                }
                uint32_t pad = h->f_pad > 0 ? (uint32_t)h->f_pad : 0;
                if (prefix + pad > h->f_len) {
                    // frame.go makes this a stream error, leaving the block undecoded and HPACK's table out of step;
                    // shortcut: a connection error instead, the safe choice for a case a real server never sends.
                    conn_error(h, TSNET_H2_PROTOCOL_ERROR);
                    return i;
                }
                if (at >= h->f_len - pad) {
                    continue; // padding
                }
            }
            if (h->block_len >= sizeof h->block) {
                conn_error(h, TSNET_H2_PROTOCOL_ERROR); // over the header list size we advertised
                return i;
            }
            h->block[h->block_len++] = p[i];
        }
        break;
    case F_SETTINGS:
        for (; i < n; i++) {
            h->small[h->small_have++] = p[i];
            if (h->small_have == 6) {
                setting(h, (uint16_t)(h->small[0] << 8 | h->small[1]), get32(h->small + 2));
                h->small_have = 0;
                if (h->dead) {
                    return i + 1;
                }
            }
        }
        break;
    case F_PING:
    case F_GOAWAY:
    case F_WINDOW_UPDATE:
    case F_RST_STREAM:
        for (; i < n; i++) {
            if (h->small_have < sizeof h->small) {
                h->small[h->small_have++] = p[i]; // GOAWAY's debug data past its first 8 bytes is skipped
            }
        }
        break;
    default:
        i = n; // PRIORITY and unknown types: skipped
        break;
    }
    h->f_got += (uint32_t)i;
    return i;
}

// ts2021 conn.go readHeader: an optional early payload before HTTP/2. Returns how many bytes it took.
static size_t early(tsnet_h2_t *h, const uint8_t *p, size_t n, int *redo)
{
    size_t i = 0;
    *redo = 0;
    if (h->early == 0) {
        while (i < n && h->early_have < 9) {
            h->early_hdr[h->early_have++] = p[i++];
        }
        if (h->early_have < 9) {
            return i;
        }
        if (memcmp(h->early_hdr, EARLY_MAGIC, 5) != 0) {
            h->early = 2; // no early payload: these 9 bytes are HTTP/2's (MultiReader)
            *redo = 1;
            return i;
        }
        h->early_len = get32(h->early_hdr + 5);
        if (h->early_len > TSNET_H2_EARLY_MAX) {
            tsnet_log(TSNET_LOG_WARN, "ts2021 early payload of %u bytes is too big", (unsigned)h->early_len);
            conn_error(h, TSNET_H2_PROTOCOL_ERROR);
            return i;
        }
        h->early = 1;
        h->early_have = 0;
    }
    while (i < n && h->early_have < h->early_len) {
        h->early_json[h->early_have++] = (char)p[i++];
    }
    if (h->early_have == h->early_len) {
        // json.Unmarshal into tailcfg.EarlyNoise: it must parse. Nothing reads it (only Tailscale's tests call
        // GetEarlyPayload), so it is checked and dropped.
        cJSON *j = tsnet_json_parse(h->early_json, h->early_len);
        if (j == NULL) {
            tsnet_log(TSNET_LOG_WARN, "ts2021 early payload isn't JSON");
            conn_error(h, TSNET_H2_PROTOCOL_ERROR);
        }
        cJSON_Delete(j);
        h->early = 2;
    }
    return i;
}

static size_t feed_frames(tsnet_h2_t *h, const uint8_t *data, size_t len)
{
    size_t i = 0;
    while (i < len && !h->dead) {
        if (h->fh_have < 9) {
            h->fh[h->fh_have++] = data[i++];
            if (h->fh_have < 9) {
                continue;
            }
            frame_start(h);
            if (h->dead) {
                break;
            }
        }
        i += frame_payload(h, data + i, len - i);
        if (h->dead) {
            break;
        }
        if (h->f_got == h->f_len) {
            frame_end(h);
            h->fh_have = 0;
        }
    }
    return i;
}

int tsnet_h2_feed(tsnet_h2_t *h, const uint8_t *data, size_t len)
{
    size_t i = 0;
    while (i < len && !h->dead && h->early < 2) {
        int redo;
        i += early(h, data + i, len - i, &redo);
        if (redo) {
            feed_frames(h, h->early_hdr, 9);
        }
    }
    if (i < len && !h->dead) {
        feed_frames(h, data + i, len - i);
    }
    return h->dead ? -1 : 0;
}

void tsnet_h2_closed(tsnet_h2_t *h)
{
    h->dead = 1;
    for (int i = 0; i < TSNET_H2_STREAMS; i++) {
        if (h->streams[i].id) {
            stream_end(h, &h->streams[i], TSNET_H2_ERR_CONN);
        }
    }
}

tsnet_h2_t *tsnet_h2_new(const tsnet_h2_cb_t *cb, int early_payload)
{
    tsnet_h2_t *h = tsnet_calloc(1, sizeof *h);
    if (h == NULL) {
        return NULL;
    }
    h->cb = *cb;
    h->early = early_payload ? 0 : 2;
    tsnet_hpack_dec_init(&h->hdec, TSNET_HPACK_TABLE_MAX);
    h->in.avail = CONN_FLOW + INITIAL_WINDOW; // cc.inflow.init(MaxUploadBufferPerConnection + initialWindowSize)
    h->out = INITIAL_WINDOW;
    h->peer_initial_window = INITIAL_WINDOW;
    h->peer_max_frame = 16384;
    h->max_concurrent = INITIAL_MAX_CONCURRENT;
    h->next_stream = 1;
    h->want_settings_ack = 1;
    // newClientConn: the preface, SETTINGS, the connection WINDOW_UPDATE.
    memcpy(h->out_buf, PREFACE, sizeof PREFACE - 1);
    h->out_len = sizeof PREFACE - 1;
    uint8_t s[24];
    const uint32_t SETTINGS[4][2] = {{S_ENABLE_PUSH, 0},
                                     {S_INITIAL_WINDOW_SIZE, STREAM_FLOW},
                                     {S_MAX_FRAME_SIZE, MAX_READ_FRAME},
                                     {S_MAX_HEADER_LIST_SIZE, TSNET_H2_HEADER_BLOCK_MAX}};
    for (int i = 0; i < 4; i++) {
        s[6 * i] = (uint8_t)(SETTINGS[i][0] >> 8);
        s[6 * i + 1] = (uint8_t)SETTINGS[i][0];
        put32(s + 6 * i + 2, SETTINGS[i][1]);
    }
    put_frame(h, F_SETTINGS, 0, 0, s, sizeof s);
    window_update(h, 0, CONN_FLOW);
    return h;
}

void tsnet_h2_free(tsnet_h2_t *h)
{
    if (h == NULL) {
        return;
    }
    for (int i = 0; i < TSNET_H2_STREAMS; i++) {
        body_free(&h->streams[i]);
    }
    tsnet_wipe(h, sizeof *h); // out_buf holds frames in plaintext, a register's body among them
    free(h);
}

size_t tsnet_h2_pending(tsnet_h2_t *h, const uint8_t **out)
{
    *out = h->out_buf + h->out_off;
    return h->out_len - h->out_off;
}

void tsnet_h2_sent(tsnet_h2_t *h, size_t n)
{
    h->out_off += n;
    if (h->out_off >= h->out_len) {
        h->out_off = h->out_len = 0;
    }
    pump(h);
}

int tsnet_h2_usable(const tsnet_h2_t *h)
{
    return !h->dead && !h->goaway && h->next_stream < MAX_WINDOW;
}

uint32_t tsnet_h2_request(tsnet_h2_t *h, const char *method, const char *authority, const char *path,
                          const tsnet_h2_header_t *headers, size_t n_headers, const uint8_t *body, size_t body_len)
{
    if (!tsnet_h2_usable(h) || body_len > TSNET_H2_BODY_MAX) {
        return 0;
    }
    stream_t *s = NULL;
    uint32_t open = 0;
    for (int i = 0; i < TSNET_H2_STREAMS; i++) {
        if (h->streams[i].id) {
            open++;
        } else if (s == NULL) {
            s = &h->streams[i];
        }
    }
    if (s == NULL || open >= h->max_concurrent) {
        return 0;
    }
    // httpcommon.EncodeHeaders' order.
    uint8_t block[2048];
    size_t n = 0;
    char clen[24];
    int ok = tsnet_hpack_encode(block, sizeof block, &n, ":authority", authority) == 0 &&
             tsnet_hpack_encode(block, sizeof block, &n, ":method", method) == 0 &&
             tsnet_hpack_encode(block, sizeof block, &n, ":path", path) == 0 &&
             tsnet_hpack_encode(block, sizeof block, &n, ":scheme", "https") == 0; // ts2021 requests https://host/path
    for (size_t i = 0; ok && i < n_headers; i++) {
        ok = tsnet_hpack_encode(block, sizeof block, &n, headers[i].name, headers[i].value) == 0;
    }
    // shouldSendReqContentLength: a body, or an empty POST, PUT or PATCH.
    if (ok && (body_len > 0 || !strcmp(method, "POST") || !strcmp(method, "PUT") || !strcmp(method, "PATCH"))) {
        snprintf(clen, sizeof clen, "%zu", body_len);
        ok = tsnet_hpack_encode(block, sizeof block, &n, "content-length", clen) == 0;
    }
    ok = ok && tsnet_hpack_encode(block, sizeof block, &n, "user-agent", "tsnet") == 0;
    if (!ok || n + 9 * (1 + n / SEND_CHUNK) + CONTROL_ROOM > out_room(h)) {
        return 0;
    }
    if (body_len > 0 && (s->body = tsnet_malloc(body_len)) == NULL) {
        return 0;
    }
    s->id = h->next_stream;
    h->next_stream += 2;
    s->content_left = -1;
    s->in.avail = STREAM_FLOW;
    s->out = h->peer_initial_window;
    if (body_len > 0) {
        memcpy(s->body, body, body_len);
    }
    s->body_len = body_len;
    s->end_sent = body_len == 0;
    // writeHeaders: HEADERS, then CONTINUATIONs past the peer's frame size; END_STREAM on HEADERS when there's no body.
    size_t off = 0;
    do {
        size_t chunk = n - off < h->peer_max_frame ? n - off : h->peer_max_frame;
        int first = off == 0, last = off + chunk == n;
        uint8_t flags = (uint8_t)((last ? FL_END_HEADERS : 0) | (first && body_len == 0 ? FL_END_STREAM : 0));
        put_frame(h, first ? F_HEADERS : F_CONTINUATION, flags, s->id, block + off, chunk);
        off += chunk;
    } while (off < n);
    pump(h);
    return s->id;
}

void tsnet_h2_cancel(tsnet_h2_t *h, uint32_t stream)
{
    stream_t *s = find(h, stream);
    if (s == NULL) {
        return;
    }
    rst_stream(h, s->id, TSNET_H2_CANCEL);
    if (h->f_target == s) {
        h->f_target = NULL;
    }
    stream_free(s);
}
