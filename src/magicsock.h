#pragma once
// magicsock: wgengine/magicsock's Conn, the part
// that owns the node's UDP socket, its DERP connections (derpmgr.h) and its netcheck (netcheck.h).
//   - ReSTUN: a netcheck report (updateNetInfo), whose preferred region becomes the DERP home (maybeSetNearestDERP:
//     while not connected to control, a home already set stays); a ReSTUN asked for while one runs runs after it.
//   - ReSTUN runs on a DERP map change (setDERPMap), when the first peer arrives ("non-zero-peers"), and every 20 to
//     26 s while there are peers and traffic (periodicReSTUN; shouldDoPeriodicReSTUNLocked stops it after 45 s with
//     no packet sent or received, the idle time wgengine gives Go's magicsock).
//   - A STUN binding packet arriving on the socket goes to netcheck (packetLooksLike), and a disco packet, over UDP
//     or DERP, to handleDiscoMessage; any other is WireGuard's, for on_packet. Disco from a disco key no peer
//     has is dropped. A Ping gets a Pong the way it came; a Pong measures a path (endpoint.h); a CallMeMaybe, only
//     over DERP from the peer whose disco key sealed it, pings the endpoints it lists.
//   - NetInfo (the preferred DERP, whether UDP works, the mapping, the latencies) is reported when it changes as
//     BasicallyEqual sees it (not the latencies), for the control client (tsnet_client_set_netinfo).
//   - Endpoints: after each report, this node's endpoints (selfeps.h, determineEndpoints); reported when the
//     set changes (setEndpoints), for the control client (tsnet_client_set_endpoints). With no STUN endpoint and no
//     DERP map yet there's nothing to report. A CallMeMaybe a peer's discovery wants lists them; endpoints older than
//     27 s ReSTUN first ("refresh-for-peering") and it goes when the report is in (enqueueCallMeMaybe).
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "derpmgr.h"
#include "endpoint.h"
#include "netcheck.h"
#include "platform.h"
#include "selfeps.h"

typedef struct {
    const uint8_t *node_priv; // the node key (copied)
    // The disco key (copied), made before the control client starts so its first MapRequest carries it (Go's
    // Options.DiscoPublicKey). NULL makes a new one here.
    const uint8_t *disco_priv;
    uint16_t port; // the UDP port to bind (tailscaled's --port; 0 for any)
    bool use_http;            // TS_DEBUG_USE_DERP_HTTP, for the DERP connections
    void *ctx;
    // NetInfo changed. Runs inside step.
    void (*on_netinfo)(void *ctx, const tsnet_net_info_t *ni);
    // This node's endpoints changed (epFunc). Runs inside step.
    void (*on_endpoints)(void *ctx, const tsnet_selfep_t *eps, size_t n);
    // The first answer to tsnet_magicsock_ping for the peer `key`; `region` is the DERP region it came over (0 for
    // UDP). Runs inside step. May be NULL.
    void (*on_ping)(void *ctx, const uint8_t key[TSNET_KEY_LEN], const tsnet_ping_result_t *res, int region);
    // A packet from a peer that is neither STUN nor disco (WireGuard's), over UDP or DERP: `src` is the
    // sender's address (16 bytes and a 2-byte big-endian port) over UDP, its node key over DERP. Runs inside step.
    void (*on_packet)(void *ctx, const uint8_t *data, size_t len, const uint8_t *src, size_t src_len);
    // A STUN packet as netcheck is about to send it: return false to drop it (for tests: UDP blocked). May be NULL.
    bool (*stun_filter)(void *ctx);
} tsnet_magicsock_cfg_t;

typedef struct tsnet_magicsock tsnet_magicsock_t;

// Binds the UDP socket. NULL if it can't.
tsnet_magicsock_t *tsnet_magicsock_new(const tsnet_magicsock_cfg_t *cfg);
void tsnet_magicsock_free(tsnet_magicsock_t *m);

// The netmap's DERP map (NULL: none). A change ReSTUNs ("derp-map-update").
void tsnet_magicsock_set_derp_map(tsnet_magicsock_t *m, const tsnet_derp_map_t *dm);
// The netmap's peers (updateFromNode): node key, disco key, home DERP and endpoints (endpoint.h). A peer keeps its
// paths across calls, unless its disco key changed. Going from no peers to some ReSTUNs ("non-zero-peers"), and
// periodic ReSTUN runs while there are some.
void tsnet_magicsock_set_peers(tsnet_magicsock_t *m, const tsnet_node_t *peers, size_t n);
// endpoint.send for the peer with node key `key`: the packet goes to its best UDP address while that's trusted, else
// to it (if any) and to the peer's home DERP (or the region it last reached us over), starting path discovery. What
// WireGuard calls. 0, or -1 for no such peer, an expired one (errExpired) or no way to reach it.
int tsnet_magicsock_send(tsnet_magicsock_t *m, const uint8_t key[TSNET_KEY_LEN], const uint8_t *pkt, size_t len);
// Conn.Ping's disco ping ("tailscale ping", endpoint.h's cli_ping): over the peer's DERP home while there's no
// trusted path, and to its trusted path or every endpoint. The first pong goes to on_ping. -1 for no such peer, an
// expired one, one without a disco key, or nothing to ping.
int tsnet_magicsock_ping(tsnet_magicsock_t *m, const uint8_t key[TSNET_KEY_LEN]);
// The peer's path: 1 for a trusted direct UDP path (ip and port set), 0 for one that goes over DERP too (ip and port
// set if there's an untrusted UDP one), -1 for no such peer.
int tsnet_magicsock_peer_path(const tsnet_magicsock_t *m, const uint8_t key[TSNET_KEY_LEN], uint8_t ip[16],
                              uint16_t *port);
// Whether the control client is in a map poll (health's GetInPollNetMap), for maybeSetNearestDERP.
void tsnet_magicsock_set_control(tsnet_magicsock_t *m, bool in_map_poll);
void tsnet_magicsock_restun(tsnet_magicsock_t *m, const char *why);

int tsnet_magicsock_poll(const tsnet_magicsock_t *m, tsnet_poll_t *p, int max, int *wait_ms);
void tsnet_magicsock_step(tsnet_magicsock_t *m);

uint16_t tsnet_magicsock_port(const tsnet_magicsock_t *m);
// The node's disco public key (key.NewDisco): new each start, never stored. The MapRequest carries it.
const uint8_t *tsnet_magicsock_disco_public(const tsnet_magicsock_t *m);
tsnet_derpmgr_t *tsnet_magicsock_derp(tsnet_magicsock_t *m);
const tsnet_netcheck_report_t *tsnet_magicsock_report(const tsnet_magicsock_t *m);
