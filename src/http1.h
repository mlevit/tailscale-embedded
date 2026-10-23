#pragma once
// The little HTTP/1.1 the dial needs: controlhttp's upgrade request (POST /ts2021) and the GET of the server's key
// (/key), and reading their responses. Pure and bounded: it parses what arrives in any split, and refuses a head over
// TSNET_HTTP1_HEAD_MAX instead of growing.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TSNET_HTTP1_HEAD_MAX 4096

// Standard base64 (RFC 4648, with padding), as Go's base64.StdEncoding: controlhttp puts the Noise initiation in the
// X-Tailscale-Handshake header this way. Writes a NUL-terminated string; `out` needs 4 * ((len + 2) / 3) + 1 bytes.
void tsnet_base64(char *out, const uint8_t *in, size_t len);

#define TSNET_NOISE_INIT_MAX 101 // the Noise initiation (noise.h TSNET_NOISE_INIT_LEN)

// controlhttp's upgrade request (client.go tryURLUpgrade): POST /ts2021 with Upgrade: tailscale-control-protocol,
// Connection: upgrade and the initiation in X-Tailscale-Handshake. Writes it to `out` and returns its length, or -1 if it
// doesn't fit.
int tsnet_http1_upgrade_request(char *out, size_t cap, const char *host, uint16_t port, const uint8_t *init,
                                size_t init_len);
// A plain GET (the server's key, controlclient loadServerPubKeys; netcheck's latency check), asking the server to
// close after it. -1 if it doesn't fit or the host has a character a host name can't.
int tsnet_http1_get_request(char *out, size_t cap, const char *host, const char *path);
// DERP's upgrade request (derphttp connect): GET /derp with Upgrade: DERP and Connection: Upgrade, and
// Ideal-Node when given (the region's first node, when the connection went to another). `host` is the Host header
// (host, or host:port). Returns -1 if it doesn't fit, or if a name has a character a host name can't (the DERP map comes
// from the server).
int tsnet_http1_derp_request(char *out, size_t cap, const char *host, const char *ideal_node);

// A response's head (status line and headers) and then its body. Feed it bytes; it says how many it took.
typedef enum {
    TSNET_HTTP1_HEAD,  // reading the head
    TSNET_HTTP1_BODY,  // the head is in: status and headers are set; body bytes follow
    TSNET_HTTP1_DONE,  // the whole body is in (a Content-Length or chunked body); not for an upgrade
    TSNET_HTTP1_ERROR, // malformed, or over the limits
} tsnet_http1_state_t;

typedef struct {
    tsnet_http1_state_t state;
    int status;                // e.g. 101, 200
    char upgrade[48];          // the Upgrade header's value, or ""
    long long content_length;  // -1 if none
    bool chunked;              // Transfer-Encoding: chunked
    // internals
    char head[TSNET_HTTP1_HEAD_MAX];
    size_t head_len;
    long long left;            // body bytes left in the current chunk or Content-Length
    int chunk_state;
    char chunk_line[24];
    size_t chunk_line_len;
} tsnet_http1_resp_t;

void tsnet_http1_resp_init(tsnet_http1_resp_t *r);

// Feeds received bytes. Head bytes are consumed into the head; once it is complete the state becomes BODY and the call
// returns, having taken only the head's bytes, so for a 101 upgrade the rest is the new protocol's and the caller keeps
// it. In BODY, body bytes are copied to `body` (at most `body_cap` in all; *body_len counts them, and more is an error)
// until the body ends (DONE). Returns how many bytes it took.
size_t tsnet_http1_resp_feed(tsnet_http1_resp_t *r, const uint8_t *data, size_t len, uint8_t *body, size_t body_cap,
                             size_t *body_len);
// The peer closed: a body with no length ends here (DONE); anything else unfinished is an ERROR.
void tsnet_http1_resp_eof(tsnet_http1_resp_t *r);
