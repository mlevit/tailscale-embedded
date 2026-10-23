#pragma once
// tsnet's control client: control/controlclient's Auto and Direct as one event loop. It keeps the node
// registered and its netmap current over one ts2021 connection (controlhttp + h2):
//   - login (authRoutine, doLogin): the server's key, then a register that refreshes the stored node key, with the auth
//     key when there is one, a new node key when the server says the old one expired, Retry-After on 429/503.
//   - the map poll (mapRoutine, sendMapRequest): a streaming MapRequest asking for zstd, each message decoded (mapmsg),
//     applied (netmap), and given to the app; the 120 s watchdog, reset per message; on any end a new poll after the map
//     backoff, on the same connection (measured on the official client); a 404 reports the node removed.
//   - PingRequest with no type and a Noise URL: answered with a HEAD over the connection (answerHeadPing).
// The connection is dialed when needed and after it fails, with the dial's own forced-443 rule.
//   - What magicsock reports (the disco key, the endpoints, NetInfo) goes in every MapRequest and register; a change
//     sends a lite map update (updateRoutine: OmitPeers, no stream) once logged in, with Retry-After on 429/503 and
//     the 30 s backoff on other errors.
// Not yet: the Tailnet Lock re-sign, waiting on an AuthURL, the
// RST_STREAM+PING Go sends when it cancels a stream that has read no frame, and pausing while no network interface
// is up (ipnlocal's linkChange). Untested: how soon a path that dies without a reset is dialed again (docs/design.md).
#include <stdbool.h>
#include <stdint.h>
#include "identity.h"
#include "netmap.h"
#include "platform.h"

typedef enum {
    TSNET_CLIENT_STARTING,      // fetching the key, dialing, registering
    TSNET_CLIENT_NEEDS_AUTH,    // a refused auth key, a login URL, or a netmap whose self node expired (detail says)
    TSNET_CLIENT_LOGGED_IN,     // registered; the map poll is starting or retrying
    TSNET_CLIENT_RUNNING,       // a netmap is in from the current poll
    TSNET_CLIENT_NODE_REMOVED,  // the map said 404: the node was deleted (tailscaled's NeedsLogin); polls go on
} tsnet_client_state_t;

typedef struct {
    const char *server_url; // "https://controlplane.tailscale.com", or e.g. "http://127.0.0.1:8090"
    // Sent with a first register and with a new node key only: a registered node's restart logs in with its stored node
    // key alone, so an image with a key built in doesn't send it on every boot. Copied, and wiped on free.
    const char *auth_key;
    bool ephemeral;
    const char *hostname, *ipn_version, *os, *os_version, *machine; // Hostinfo (tailcfg.h)
    // The callbacks run inside tsnet_client_step and must not call any tsnet_client function.
    void *ctx;
    // The netmap changed (TSNET_NM_* flags). The netmap is valid during the call.
    void (*on_netmap)(void *ctx, const tsnet_netmap_t *nm, int changed);
    // The state changed, with a short reason.
    void (*on_state)(void *ctx, tsnet_client_state_t state, const char *detail);
} tsnet_client_cfg_t;

typedef struct tsnet_client tsnet_client_t;

// Loads the identity (identity.h) and starts. NULL if the identity can't be loaded or kept, or the URL is bad.
tsnet_client_t *tsnet_client_new(const tsnet_client_cfg_t *cfg);
void tsnet_client_free(tsnet_client_t *c);

// The event loop: tsnet_client_poll fills up to `max` sockets to wait on and the most to wait (ms), the app waits
// (tsnet_poll, or its own select with these and its other sockets), then calls tsnet_client_step. Step never blocks
// (bar DNS when a dial starts).
int tsnet_client_poll(tsnet_client_t *c, tsnet_poll_t *p, int max, int *wait_ms);
void tsnet_client_step(tsnet_client_t *c);
// Both, for `ms` milliseconds: for tools and tests.
void tsnet_client_run_for(tsnet_client_t *c, int ms);

tsnet_client_state_t tsnet_client_state(const tsnet_client_t *c);
// A map poll is open and its 200 is in. It goes false between polls, while the state stays RUNNING (tailscaled's
// backend stays Running too, and reports "not in map poll" as a separate health warning).
bool tsnet_client_in_map_poll(const tsnet_client_t *c);
// magicsock's reports (Auto's SetDiscoPublicKey, UpdateEndpoints, SetNetInfo). Each that changes something sends a
// lite map update once logged in; the next MapRequest carries it too. Endpoints past 32 are dropped.
void tsnet_client_set_disco_key(tsnet_client_t *c, const uint8_t pub[TSNET_KEY_LEN]);
void tsnet_client_set_endpoints(tsnet_client_t *c, const tsnet_addrport_t *eps, const int *types, size_t n);
void tsnet_client_set_netinfo(tsnet_client_t *c, const tsnet_net_info_t *ni);
const tsnet_identity_t *tsnet_client_identity(const tsnet_client_t *c);
