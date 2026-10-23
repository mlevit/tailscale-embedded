#pragma once
// derphttp's connect: derp/derphttp/derphttp_client.go, one connection to one DERP region, as a non-blocking
// step for an event loop. It goes:
//   1. A TCP dial to each of the region's nodes in order, skipping STUN-only ones, 1.5 s each (dialRegion, dialNode).
//      The address is the node's IPv4 when set, else its host name; the port is DERPPort, else 443 (3340 over HTTP).
//   2. TLS to the node's host name, with the certificate and the name checked (tlsClient, net/tlsdial). A node marked
//      InsecureForTests skips the check.
//   3. GET /derp with Upgrade: DERP, and Ideal-Node when the node isn't the region's first; a 101 is required.
//   4. DERP's handshake (derp.h). The connection is up once ClientInfo is sent (connect returns there), and the server
//      is known to have accepted it when ServerInfo arrives (magicsock's "derp-N connected").
// Steps 1 to 4 have 10 s in all (connect's timeout). Once up, no read for 120 s fails it (Recv's deadline), and a
// server ping is answered with a pong (magicsock's runDerpReader, with CanAckPings). A connection that fails stays
// failed: the owner makes a new one, after its backoff.
//
// Plain HTTP (no TLS) only when `use_http` is set: Go's TS_DEBUG_USE_DERP_HTTP, which the harness uses.
// Not yet: fast start (the TLS 1.3 meta certificate, parseMetaCert and Derp-Fast-Start: a round trip saved, the server
// behaves the same without it), a node's CertName (such a node fails here), IPv6, proxies and websockets.
#include <stdbool.h>
#include <stdint.h>
#include "derp.h"
#include "mapresp.h"
#include "platform.h"

#define TSNET_DERPHTTP_CONNECT_MS 10000 // connect's timeout
#define TSNET_DERPHTTP_NODE_DIAL_MS 1500 // dialNodeTimeout
#define TSNET_DERPHTTP_READ_MS 120000   // Recv's read deadline
#define TSNET_DERPHTTP_OUT 8192         // frames queued to send; a packet that doesn't fit is dropped

typedef enum {
    TSNET_DERPHTTP_CONNECTING, // dialing, TLS, the upgrade, the greeting
    TSNET_DERPHTTP_UP,         // ClientInfo sent: packets can go
    TSNET_DERPHTTP_FAILED,
    TSNET_DERPHTTP_MEASURED,   // latency_check: done, tsnet_derphttp_latency_us has the result
} tsnet_derphttp_state_t;

typedef struct {
    const tsnet_derp_region_t *region; // copied
    const uint8_t *node_priv;          // the node key (copied); unused for a latency check
    bool use_http;                     // TS_DEBUG_USE_DERP_HTTP
    // netcheck's measureHTTPSLatency: TLS always (DialRegionTLS), then GET /derp/latency-check; the time from
    // the request to a 2xx response's head is the latency. No DERP handshake.
    bool latency_check;
    bool preferred;                    // NotePreferred at connect: this is the home region
    // Every message but the greeting and server pings, which are handled here. Runs inside step, and must not call
    // tsnet_derphttp_step or _free.
    tsnet_derp_cb_t on_msg;
    void *ctx;
} tsnet_derphttp_cfg_t;

typedef struct tsnet_derphttp tsnet_derphttp_t;

// Starts connecting. NULL if out of memory or the region has no node to dial.
tsnet_derphttp_t *tsnet_derphttp_connect(const tsnet_derphttp_cfg_t *cfg);
void tsnet_derphttp_free(tsnet_derphttp_t *c);

// The socket to wait on (0 or 1 entries in `p`) and the most to wait before stepping again.
int tsnet_derphttp_poll(const tsnet_derphttp_t *c, tsnet_poll_t *p, int *wait_ms);
// Moves the connection on as far as the socket allows. Never blocks (bar DNS when a dial starts).
void tsnet_derphttp_step(tsnet_derphttp_t *c);

tsnet_derphttp_state_t tsnet_derphttp_state(const tsnet_derphttp_t *c);
// ServerInfo is in: the server accepted the client.
bool tsnet_derphttp_accepted(const tsnet_derphttp_t *c);
// The node it connected to (an index into the region's nodes), or -1.
int tsnet_derphttp_node(const tsnet_derphttp_t *c);
// A latency check's result once MEASURED (microseconds, at least 1), else 0.
uint32_t tsnet_derphttp_latency_us(const tsnet_derphttp_t *c);

// Queue a frame: a packet for `dst` (Send), a ping, or NotePreferred. A frame queued while connecting goes once the
// handshake is done (magicsock's writes wait in the region's writeCh while Send connects). 0, or -1 when the connection
// has failed or the queue is full (the frame is dropped, as magicsock drops a packet when a region's queue is full).
int tsnet_derphttp_send(tsnet_derphttp_t *c, const uint8_t dst[TSNET_KEY_LEN], const uint8_t *pkt, size_t len);
int tsnet_derphttp_ping(tsnet_derphttp_t *c, const uint8_t data[8]);
int tsnet_derphttp_note_preferred(tsnet_derphttp_t *c, bool preferred);
