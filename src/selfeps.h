#pragma once
// This node's own endpoints, pure: what magicsock's determineEndpoints tells control, so peers can try a
// direct path. (A peer's endpoints are endpoint.h's.) Addresses are 16 bytes, IPv4 as ::ffff:a.b.c.d.
//   - STUN: the netcheck report's GetGlobalAddrs (the address the fastest server saw, then any other seen more than
//     once), and, behind a NAT whose mapping varies by server with a fixed UDP port, the first one with that port
//     (EndpointSTUN4LocalPort).
//   - endpointTracker: a STUN endpoint stays advertised for 5 min 10 s after a report last saw it, so one report that
//     misses it doesn't withdraw it. At most 6 per address (the oldest go).
//   - Local: the interfaces' addresses on the UDP port (netmon.LocalAddresses): up interfaces, not Tailscale's own
//     addresses, not IPv6 link-local, at most 2 IPv6 per subnet; IPv4 link-local and IPv6 ULA only when there's
//     nothing else; loopback only when there's nothing at all.
// Not here: port mapping (UPnP, NAT-PMP, PCP), cloud metadata addresses, static endpoints, and IPv6 STUN (netcheck
// has no IPv6).
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "netcheck.h"

// tailcfg.EndpointType
#define TSNET_EPT_LOCAL 1
#define TSNET_EPT_STUN 2
#define TSNET_EPT_PORTMAPPED 3
#define TSNET_EPT_STUN4LOCALPORT 4
#define TSNET_EPT_EXPLICIT 5

#define TSNET_SELFEPS_MAX 32       // endpoints advertised
#define TSNET_TRACKER_SLOTS 24     // endpoints cached (Go's map grows; 4 addresses' worth of 6)
#define TSNET_TRACKER_PER_ADDR 6   // endpointTrackerMaxPerAddr
#define TSNET_TRACKER_LIFETIME_MS (5 * 60 * 1000 + 10 * 1000) // endpointTrackerLifetime

typedef struct {
    uint8_t ip[16];
    uint16_t port;
    int type; // TSNET_EPT_*
} tsnet_selfep_t;

typedef struct {
    struct {
        bool used;
        tsnet_selfep_t ep;
        uint64_t until; // ms
    } e[TSNET_TRACKER_SLOTS];
} tsnet_tracker_t;

// endpointTracker.update: the endpoints given, then any cached ones not among them and not expired (a time past
// `until` has expired). Writes at most `cap` to `out` and returns how many.
size_t tsnet_tracker_update(tsnet_tracker_t *t, uint64_t now_ms, const tsnet_selfep_t *in, size_t n, tsnet_selfep_t *out,
                            size_t cap);

// endpointSetsEqual: the same endpoints (address, port and type), in any order and with any repeats.
bool tsnet_selfeps_equal(const tsnet_selfep_t *a, size_t na, const tsnet_selfep_t *b, size_t nb);

// netmon.LocalAddresses (the interfaces' addresses are platform.h's tsnet_ifaddrs): the regular addresses and the loopback ones, each sorted (netip.Addr.Less: IPv4 first).
void tsnet_local_addresses(const tsnet_ifaddr_t *ifs, size_t n, uint8_t (*regular)[16], size_t *n_regular,
                           uint8_t (*loopback)[16], size_t *n_loopback, size_t cap);

// determineEndpoints. `r` may be NULL (no report yet). `fixed_port` is the port asked for (tailscaled's --port, 0
// for any) and `local_port` the one bound. Returns how many went to `out`.
size_t tsnet_determine_endpoints(const tsnet_netcheck_report_t *r, uint16_t fixed_port, uint16_t local_port,
                                 const tsnet_ifaddr_t *ifs, size_t n_ifs, tsnet_tracker_t *t, uint64_t now_ms,
                                 tsnet_selfep_t *out, size_t cap);

// setEndpoints' first rule: with no STUN endpoint and no DERP map yet, there's nothing worth telling control.
bool tsnet_selfeps_any_stun(const tsnet_selfep_t *eps, size_t n);

// The endpoints as the MapRequest takes them (tailcfg.h's address form and the types), for tsnet_client_set_endpoints.
void tsnet_selfeps_wire(const tsnet_selfep_t *eps, size_t n, tsnet_addrport_t *out, int *types);
