#pragma once
// The HTTP/2 client of the control protocol: Go's net/http2 Transport as control/ts2021 uses it, over the Noise
// connection (controlhttp.h). Pure: tsnet_h2_feed() takes the plaintext the server sent, tsnet_h2_pending()/sent() give
// the bytes to send, and callbacks report each response. Before HTTP/2 it reads ts2021's optional early payload.
//
// As Go's client: the preface, SETTINGS (ENABLE_PUSH 0, INITIAL_WINDOW_SIZE 4 MB, MAX_FRAME_SIZE 1 MB), a connection
// WINDOW_UPDATE of 1 GB, the same flow-control refresh rule (inflow.add), odd stream ids from 1, PINGs answered and none
// sent (ts2021 sets no ReadIdleTimeout), GOAWAY ending only the streams it doesn't cover, a connection error answered
// with GOAWAY. Different, for the device's memory: MAX_HEADER_LIST_SIZE is TSNET_H2_HEADER_BLOCK_MAX (Go: 10 MB), a
// request body is at most TSNET_H2_BODY_MAX, and no "accept-encoding: gzip" (there's no gzip here; the server then
// sends identity). DATA is streamed to the callback, never buffered, so the big windows cost no memory.
#include <stddef.h>
#include <stdint.h>

#define TSNET_H2_STREAMS 8              // open at once; the control client uses two or three
#define TSNET_H2_HEADER_BLOCK_MAX 16384 // one response header block (HEADERS + CONTINUATION)
#define TSNET_H2_BODY_MAX 61440         // one request body; MapRequest and RegisterRequest are a few KB
#define TSNET_H2_EARLY_MAX 4096         // the early payload's JSON (Go allows 10 MB; Tailscale's is ~95 bytes)

// RFC 9113 section 7.
enum {
    TSNET_H2_NO_ERROR = 0x0,
    TSNET_H2_PROTOCOL_ERROR = 0x1,
    TSNET_H2_INTERNAL_ERROR = 0x2,
    TSNET_H2_FLOW_CONTROL_ERROR = 0x3,
    TSNET_H2_STREAM_CLOSED = 0x5,
    TSNET_H2_FRAME_SIZE_ERROR = 0x6,
    TSNET_H2_REFUSED_STREAM = 0x7,
    TSNET_H2_CANCEL = 0x8,
    TSNET_H2_COMPRESSION_ERROR = 0x9,
};
// The end callback's `err`: 0 for a whole response, an RFC 9113 code from the server's RST_STREAM, or one of these.
#define TSNET_H2_ERR_GOAWAY (-1)   // the server's GOAWAY didn't cover the stream (Go: errClientConnGotGoAway)
#define TSNET_H2_ERR_CONN (-2)     // the connection failed or closed
#define TSNET_H2_ERR_RESPONSE (-3) // a malformed response, or a body that doesn't match its content-length

typedef struct {
    const char *name, *value; // names in lower case
} tsnet_h2_header_t;

// Called from tsnet_h2_feed (and tsnet_h2_closed); they must not call any tsnet_h2 function.
typedef struct {
    void *ctx;
    // A field of the final response's head (not 1xx or trailers), in order, after its :status is known.
    void (*field)(void *ctx, uint32_t stream, const char *name, size_t name_len, const char *value, size_t value_len);
    // The head is complete.
    void (*head)(void *ctx, uint32_t stream, int status);
    // Body bytes, as they arrive.
    void (*data)(void *ctx, uint32_t stream, const uint8_t *data, size_t len);
    // The stream is over (and its id free); no more callbacks for it.
    void (*end)(void *ctx, uint32_t stream, int err);
} tsnet_h2_cb_t;

typedef struct tsnet_h2 tsnet_h2_t;

// A new connection (heap, ~65 KB). `early`: expect ts2021's early payload first (true for the control server). The
// preface, SETTINGS and WINDOW_UPDATE are queued at once. NULL if out of memory.
tsnet_h2_t *tsnet_h2_new(const tsnet_h2_cb_t *cb, int early);
void tsnet_h2_free(tsnet_h2_t *h);

// Takes what the server sent. Returns 0, or -1 once the connection has failed (a GOAWAY is then queued for the server,
// and every stream has ended with TSNET_H2_ERR_CONN).
int tsnet_h2_feed(tsnet_h2_t *h, const uint8_t *data, size_t len);
// The transport closed: every open stream ends with TSNET_H2_ERR_CONN.
void tsnet_h2_closed(tsnet_h2_t *h);

// The bytes waiting to be sent; after sending some, say how many.
size_t tsnet_h2_pending(tsnet_h2_t *h, const uint8_t **out);
void tsnet_h2_sent(tsnet_h2_t *h, size_t n);

// Starts a request (Go's encodeRequestHeaders order: :authority, :method, :path, :scheme "https", the headers,
// content-length for a body or a POST, user-agent). The body is copied and sent as flow control allows. Returns the
// stream id, or 0 if no request can start now (the connection failed or got GOAWAY, all streams busy, too big).
uint32_t tsnet_h2_request(tsnet_h2_t *h, const char *method, const char *authority, const char *path,
                          const tsnet_h2_header_t *headers, size_t n_headers, const uint8_t *body, size_t body_len);
// Abandons a stream: RST_STREAM CANCEL, and no more callbacks for it.
void tsnet_h2_cancel(tsnet_h2_t *h, uint32_t stream);
// 1 while new requests can start (not failed, no GOAWAY).
int tsnet_h2_usable(const tsnet_h2_t *h);
