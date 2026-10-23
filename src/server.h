#pragma once
// A tailnet node in one call: what Go's tsnet.Server sets up, tsnet's pieces run together in one event loop.
// - The control client (client.h) keeps the node registered and its netmap current.
// - magicsock (magicsock.h) finds paths to peers. It starts at the first netmap, once the node key is registered.
// - WireGuard (wgdev.h) runs over magicsock with the node key.
// - The tun (tun.h) puts lwIP's netif on the node's tailnet address, behind the packet filter (filter.h).
//
// Each netmap sets the WireGuard peers, the routes from their AllowedIPs, the node's address and the filter's rules.
// The disco key is made before the client starts, so its first MapRequest carries it (Options.DiscoPublicKey).
//
// What the app must do:
// - Set the wall clock first (SNTP on the device). Control's TLS checks certificate dates, and a peer refuses a
//   WireGuard initiation dated before the last one it took from this node.
// - Run poll, tsnet_poll and step in one task. Its stack needs room for the measured peaks: about 5.5 KB of locals
//   on magicsock's receive path and about 4 KB at the end of a report, besides TLS and the Noise handshake.
// - Call lwip_init first with NO_SYS (the host), or run it in ESP-IDF's tcpip thread (the device).
// Each netmap peer that isn't expired is a WireGuard peer, with only its own Tailscale addresses as AllowedIPs (no
// exit node's /0, no subnet routes). A peer that expires or leaves the netmap is removed.
// shortcut: every such peer is configured up front; Go's wgengine configures them lazily and trims idle ones. Upgrade
// when a tailnet has more peers than the device's memory takes.
#include <stdbool.h>
#include <stddef.h>
#include "client.h"
#include "magicsock.h"
#include "tun.h"
#include "wgdev.h"

#define TSNET_SERVER_POLL_MAX (4 + 16 + 1) // the client's sockets, magicsock's, and the tun's wake fd

typedef struct tsnet_server tsnet_server_t;

typedef struct {
    // The control client's settings. Its ctx and callbacks are the server's: the app's are below.
    tsnet_client_cfg_t client;
    bool use_derp_http;             // TS_DEBUG_USE_DERP_HTTP
    bool (*stun_filter)(void *ctx); // see magicsock.h; ctx is the server's ctx below. May be NULL.
    // How lwIP takes a packet: ip_input with NO_SYS (the host), tcpip_input on the device.
    netif_input_fn input;
    void *ctx;
    // The callbacks run inside step and must not call back into the server. Each may be NULL.
    void (*on_netmap)(void *ctx, const tsnet_netmap_t *nm, int changed); // after the server applied it
    void (*on_state)(void *ctx, tsnet_client_state_t state, const char *detail);
    void (*on_netinfo)(void *ctx, const tsnet_net_info_t *ni);
    void (*on_endpoints)(void *ctx, size_t n); // how many: the addresses are this network's
    void (*on_ping)(void *ctx, const uint8_t key[TSNET_KEY_LEN], const tsnet_ping_result_t *res, int region);
    // A decrypted packet from a peer, before the tun's checks: for tools that print what arrives.
    void (*on_deliver)(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len);
} tsnet_server_cfg_t;

// NULL if the identity can't be loaded, or there's no memory.
tsnet_server_t *tsnet_server_new(const tsnet_server_cfg_t *cfg);
void tsnet_server_free(tsnet_server_t *s);

// The event loop: poll fills up to TSNET_SERVER_POLL_MAX sockets and the most to wait (ms, -1 for no limit), the app
// waits (tsnet_poll), then calls step. lwIP's timers are the app's (sys_check_timeouts with NO_SYS).
int tsnet_server_poll(tsnet_server_t *s, tsnet_poll_t *p, int max, int *wait_ms);
void tsnet_server_step(tsnet_server_t *s);

tsnet_client_t *tsnet_server_client(tsnet_server_t *s);
tsnet_magicsock_t *tsnet_server_magicsock(tsnet_server_t *s); // NULL before the first netmap
tsnet_wgdev_t *tsnet_server_wgdev(tsnet_server_t *s);         // NULL before the first netmap
