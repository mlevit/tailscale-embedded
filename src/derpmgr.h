#pragma once
// magicsock's DERP connections: wgengine/magicsock/derp.go, which DERP regions a node is connected to and
// what happens when a connection breaks. Over derphttp.h, one connection per region:
//   - The home region (setNearestDERP): connected for as long as it is home, and told so (NotePreferred). magicsock
//     sets it from each netcheck report (magicsock.h); with no preferred region, pickDERPFallback's: the current home,
//     else a random region.
//   - A peer's region, opened on demand when a packet goes there (derpWriteChanForRegion). If the node already heard
//     from that peer over another region, the packet goes back that way instead (derpRoute).
//   - A broken connection is dialed again after runDerpReader's backoff (n² × 10 ms, at most 5 s, reset by any
//     message). Packets sent during the backoff are dropped. A server that sends a message resets the backoff.
//   - A connection that isn't the home one closes after 60 s with nothing written to it, checked every 15 s
//     (cleanStaleDerp).
//   - A DERP map that redefines or drops a region closes its connection (setDERPMap); if it was home, the home is
//     cleared until the ReSTUN that follows sets one. No map means no DERP.
//   - PeerGone and a broken connection remove the peer routes learned over that connection.
// Not yet: closing connections on a link change (maybeCloseDERPsOnRebind) and the health tracker.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "derphttp.h"
#include "mapresp.h"
#include "platform.h"

#define TSNET_DERPMGR_REGIONS 8 // connections at once (Go's activeDerp is a map): the home and a few peers' regions
#define TSNET_DERPMGR_ROUTES 64 // peers heard over DERP (derpRoute); the oldest is forgotten when full

typedef struct {
    const uint8_t *node_priv; // the node key (copied)
    bool use_http;            // TS_DEBUG_USE_DERP_HTTP
    void *ctx;
    // A packet from a peer over DERP. Runs inside step; it may call tsnet_derpmgr_send.
    void (*on_packet)(void *ctx, int region, const uint8_t src[TSNET_KEY_LEN], const uint8_t *data, size_t len);
} tsnet_derpmgr_cfg_t;

typedef struct tsnet_derpmgr tsnet_derpmgr_t;

tsnet_derpmgr_t *tsnet_derpmgr_new(const tsnet_derpmgr_cfg_t *cfg);
void tsnet_derpmgr_free(tsnet_derpmgr_t *m);

// setDERPMap: the netmap's DERP map (copied), or NULL for none. A redefined or dropped region closes; a home that went
// is cleared. It picks no home itself: as in Go, the ReSTUN that follows (magicsock.h) sets one.
void tsnet_derpmgr_set_map(tsnet_derpmgr_t *m, const tsnet_derp_map_t *dm);
// maybeSetNearestDERP: `region` as home, or the fallback for 0. Returns the home, 0 if there is none (no map).
int tsnet_derpmgr_set_home(tsnet_derpmgr_t *m, int region);
int tsnet_derpmgr_home(const tsnet_derpmgr_t *m);

// SendDERPPacketTo: a packet for the peer `dst` via `region` (its home, from the netmap). 0 if queued, -1 if dropped
// (no such region, the queue is full, no room for another connection, or backing off after a failure).
int tsnet_derpmgr_send(tsnet_derpmgr_t *m, int region, const uint8_t dst[TSNET_KEY_LEN], const uint8_t *pkt,
                       size_t len);

// The event loop, as the other modules: the sockets (up to `max`) and the most to wait, then step.
int tsnet_derpmgr_poll(const tsnet_derpmgr_t *m, tsnet_poll_t *p, int max, int *wait_ms);
void tsnet_derpmgr_step(tsnet_derpmgr_t *m);

// The regions with a connection (open or waiting to dial again), sorted; returns how many (at most `max`).
int tsnet_derpmgr_regions(const tsnet_derpmgr_t *m, int *regions, int max);
// The region's current connection has had ServerInfo.
bool tsnet_derpmgr_connected(const tsnet_derpmgr_t *m, int region);
// When a frame last came from the region (health's GetDERPRegionReceivedTime: recorded at most every 5 s), in
// tsnet_now_ms's time, or 0. What netcheck's GetLastDERPActivity reads.
uint64_t tsnet_derpmgr_last_frame(const tsnet_derpmgr_t *m, int region);
// derphttp's connGen for the region: how many connections were made to it (failed dials don't count), 0 if none.
unsigned tsnet_derpmgr_conngen(const tsnet_derpmgr_t *m, int region);
