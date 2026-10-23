#pragma once
// netcheck: net/netcheck/netcheck.go's GetReport, as a non-blocking step. A report sends STUN probes to the
// DERP map's nodes on the plan ncplan.h makes, over a UDP socket the caller owns (magicsock sends STUN on the socket
// WireGuard and disco use), and the caller hands back each STUN packet that arrives on it. Then:
//   - a probe answered gives its region a latency (the time from the send), the address the server saw (GlobalV4,
//     with a count per address), and MappingVariesByDestIP once two servers have answered;
//   - the first answer in a region stops its other probes, and a probe that wouldn't add anything isn't sent
//     (probeWouldHelp);
//   - once 3 regions have answered, the rest get as long as the slowest so far (twice that in a full report);
//   - STUN ends after 3 s, the report after 5 s;
//   - if no STUN probe was answered (UDP blocked), each region still without a latency gets one over HTTPS
//     (measureHTTPSLatency, derphttp.h's latency check);
//   - the report goes into the history, which picks the preferred DERP (ncplan.h).
// A full report (every region) happens first, every 5 minutes, and when asked for; the others probe the 3 fastest
// regions and the home.
// Not here: ICMP, IPv6, port mapping (UPnP, NAT-PMP, PCP) and captive portal detection. A node's host name is resolved
// when its probe is sent (the platform's DNS, which blocks; Tailscale's DERP map gives addresses).
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mapresp.h"
#include "ncplan.h"
#include "platform.h"

#define TSNET_NC_GLOBALS 8 // addresses counted (GlobalV4Counters)

typedef struct {
    tsnet_nc_report_t base; // the latencies, when it finished, the preferred DERP
    bool udp;               // a STUN round trip completed
    bool ipv4;              // an IPv4 STUN round trip completed
    bool ipv4_can_send;     // an IPv4 STUN packet could be sent
    int mapping_varies;     // MappingVariesByDestIP: -1 unknown, 0 or 1
    bool has_global_v4;
    uint8_t global_v4[16];  // GlobalV4: the first address a server saw
    uint16_t global_v4_port;
    struct {
        uint8_t ip[16];
        uint16_t port;
        int count;
    } globals[TSNET_NC_GLOBALS]; // GlobalV4Counters
    size_t n_globals;
} tsnet_netcheck_report_t;

typedef struct {
    // Sends one STUN packet on the caller's UDP socket. Returns the bytes sent, 0 if the socket was full, -1 on error.
    int (*send)(void *ctx, const uint8_t ip[16], uint16_t port, const uint8_t *pkt, size_t len);
    // GetLastDERPActivity (ms on tsnet_now_ms's clock, 0 for never). May be NULL.
    uint64_t (*last_activity)(void *ctx, int region);
    void *ctx;
    int forced; // ForcePreferredDERP, or 0
} tsnet_netcheck_cfg_t;

typedef struct tsnet_netcheck tsnet_netcheck_t;

tsnet_netcheck_t *tsnet_netcheck_new(const tsnet_netcheck_cfg_t *cfg);
void tsnet_netcheck_free(tsnet_netcheck_t *nc);

// Starts a report over this DERP map (copied). -1 if one is running or there's no map.
int tsnet_netcheck_start(tsnet_netcheck_t *nc, const tsnet_derp_map_t *dm);
// MakeNextReportFull.
void tsnet_netcheck_make_next_full(tsnet_netcheck_t *nc);
// ReceiveSTUNPacket: a STUN packet that arrived on the caller's socket. Ignored when no report is running.
void tsnet_netcheck_stun(tsnet_netcheck_t *nc, const uint8_t *pkt, size_t len, const uint8_t ip[16], uint16_t port);

// The event loop: the sockets of HTTPS latency checks under way (up to `max`) and the most to wait, then step.
int tsnet_netcheck_poll(const tsnet_netcheck_t *nc, tsnet_poll_t *p, int max, int *wait_ms);
// Returns true when a report has just finished (once per report).
bool tsnet_netcheck_step(tsnet_netcheck_t *nc);

bool tsnet_netcheck_running(const tsnet_netcheck_t *nc);
// The last finished report, or NULL.
const tsnet_netcheck_report_t *tsnet_netcheck_report(const tsnet_netcheck_t *nc);
