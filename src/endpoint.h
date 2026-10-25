#pragma once
// A peer's paths, pure: wgengine/magicsock/endpoint.go's endpoint, without the sockets. magicsock.c seals,
// sends and receives; this file decides. Times are tsnet_now_us's. Addresses are 16 bytes, IPv4 as ::ffff:a.b.c.d.
//   - The endpoints: the netmap's (setEndpointsLocked), ones a peer pinged from (addCandidateEndpoint), and ones a
//     CallMeMaybe listed (handleCallMeMaybe). A pinged-from one expires 45 s after its last ping; a CallMeMaybe one is
//     replaced by the next CallMeMaybe; a netmap one goes when the netmap drops it.
//   - The best address (bestAddr) is a UDP endpoint that answered a ping. A pong trusts it for 6.5 s
//     (trustUDPAddrDuration). A pong from a better address (betterAddr), or from any while the best is untrusted,
//     replaces it. A ping that times out to an untrusted best clears it.
//   - Sending (endpoint.send, what WireGuard calls): to the best address while it's trusted; else to it (if
//     any) and to the peer's home DERP, and every endpoint gets a discovery ping (sendDiscoPingsLocked, at most one
//     per endpoint per 5 s). A send starts the heartbeat: every 3 s, a ping to the best address and a full round of
//     pings when wantFullPingLocked says so, until 45 s pass without a send.
// Not in Go's sense here: UDP relay (Geneve) paths, peer MTU probing (off by default in Go: TS_DEBUG_ENABLE_PMTUD),
// WireGuard-only peers, UDP lifetime probes and the pong history (Go keeps 64 pongs per endpoint but reads them only
// for WireGuard-only peers and status). Fixed caps where Go grows: TSNET_EP_STATES endpoints per peer (Go prunes at
// 100) and TSNET_EP_PINGS pings in flight (the oldest is forgotten).
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "disco.h" // tsnet_disco_ep_t: an address and port

#define TSNET_HEARTBEAT_US 3000000ULL           // heartbeatInterval
#define TSNET_TRUST_UDP_US 6500000ULL           // trustUDPAddrDuration
#define TSNET_SESSION_ACTIVE_US 45000000ULL     // sessionActiveTimeout
#define TSNET_UPGRADE_DIRECT_US 60000000ULL     // upgradeUDPDirectInterval
#define TSNET_PING_TIMEOUT_US 5000000ULL        // pingTimeoutDuration (tsconst.DefaultPingTimeout)
#define TSNET_DISCO_PING_INTERVAL_US 5000000ULL // discoPingInterval (tsconst.DefaultPingInterval)
#define TSNET_GOOD_ENOUGH_LATENCY_US 5000ULL    // goodEnoughLatency
#define TSNET_CMM_MIN_INTERVAL_US 2000000ULL    // at most one CallMeMaybe handled per peer per 2 s (not in Go)
#define TSNET_SAFE_WIRE_MTU 1360                // tstun.SafeWireMTU (1280 + 80): a ping of size 0's wireMTU

#define TSNET_EP_STATES 16
#define TSNET_EP_PINGS 32
#define TSNET_GOT_TXIDS 32 // ping txids remembered per peer, to answer a ping once

// addrQuality: a UDP address (or none), its latency and the path MTU it was probed at.
typedef struct {
    bool valid;
    uint8_t ip[16];
    uint16_t port;
    uint64_t latency_us;
    uint16_t wire_mtu;
} tsnet_addrq_t;

// betterAddr: whether a is a better address to send to than b. Each starts with points for how much faster it is
// than the slower one (in percent), plus 50 for loopback, 30 for link-local, 20 for any other private address, and 10
// for IPv6. Under 1% better is no better. The same address is better only with a larger MTU.
bool tsnet_better_addr(const tsnet_addrq_t *a, const tsnet_addrq_t *b);

// netip.Addr's IsLoopback, IsLinkLocalUnicast, IsPrivate and Is6 (an IPv4-mapped address is IPv4).
bool tsnet_ip_loopback(const uint8_t ip[16]);
bool tsnet_ip_link_local(const uint8_t ip[16]);
bool tsnet_ip_private(const uint8_t ip[16]);
bool tsnet_ip_is6(const uint8_t ip[16]);

typedef struct {
    bool used;
    uint8_t ip[16];
    uint16_t port;
    bool in_netmap;          // index != indexSentinelDeleted
    uint64_t last_ping;      // when we last pinged it, 0 never
    uint64_t last_got_ping;  // when it last pinged us, 0 for a netmap endpoint
    uint64_t call_me_maybe;  // when a CallMeMaybe last listed it, 0 never
    bool cmm;                // in isCallMeMaybeEP: the last CallMeMaybe listed it
} tsnet_epstate_t;

typedef enum { TSNET_PING_DISCOVERY, TSNET_PING_HEARTBEAT, TSNET_PING_CLI } tsnet_ping_purpose_t;

typedef struct {
    bool used;
    uint8_t txid[12];
    bool derp; // sent over DERP (a CLI ping): ip and port unused
    uint8_t ip[16];
    uint16_t port;
    uint64_t at;
    tsnet_ping_purpose_t purpose;
    uint32_t cli; // the CLI ping it belongs to (cli_seq), 0 for none
} tsnet_sentping_t;

typedef struct {
    tsnet_epstate_t st[TSNET_EP_STATES];
    tsnet_sentping_t sent[TSNET_EP_PINGS];
    tsnet_addrq_t best;
    uint64_t trust_until, last_full_ping, last_send_ext, last_cmm; // 0: never
    uint8_t got_tx[TSNET_GOT_TXIDS][12];                           // the txids of the last pings the peer sent
    uint8_t got_tx_n, got_tx_next;
    bool heartbeat;                                     // heartBeatTimer is set
    uint64_t heartbeat_at;
    uint32_t cli_seq, cli_answered; // the latest CLI ping, and the latest one answered (pingResultAndCallback.taken)
} tsnet_endpoint_t;

// What the caller is to do: pings to send (the txid is recorded already; `derp` ones go over the peer's DERP home),
// and whether to send a CallMeMaybe over DERP.
typedef struct {
    struct {
        uint8_t txid[12];
        bool derp;
        uint8_t ip[16];
        uint16_t port;
    } ping[TSNET_EP_STATES + 1];
    int n_ping;
    bool call_me_maybe;
} tsnet_ep_actions_t;

// The first answer to a CLI ping (ipnstate.PingResult): its latency, and the path (DERP, or the UDP address it was
// sent to).
typedef struct {
    bool answered; // this pong answered the latest CLI ping, for the first time
    uint64_t latency_us;
    bool via_derp;
    uint8_t ip[16];
    uint16_t port;
} tsnet_ping_result_t;

void tsnet_endpoint_init(tsnet_endpoint_t *e);
// setEndpointsLocked: the netmap's endpoints for the peer. Endpoints no longer wanted go (shouldDeleteLocked).
void tsnet_endpoint_set_netmap(tsnet_endpoint_t *e, uint64_t now, const tsnet_disco_ep_t *eps, size_t n);
// The peer's disco key changed (changedActiveDiscoLocked, resetLocked): no best address, nothing in flight.
void tsnet_endpoint_reset(tsnet_endpoint_t *e);

// endpoint.send: where a packet goes now. `udp` (if valid) and/or DERP (`*derp` true). Fills `a` with the pings.
void tsnet_endpoint_send(tsnet_endpoint_t *e, uint64_t now, tsnet_addrq_t *udp, bool *derp, tsnet_ep_actions_t *a);
// addrForSendLocked alone, for status: the same answer as send gives, changing nothing.
void tsnet_endpoint_addr_for_send(const tsnet_endpoint_t *e, uint64_t now, tsnet_addrq_t *udp, bool *derp);
// addCandidateEndpoint: the peer pinged us from ip:port with txid. True if txid is one of its last 32 (no pong), from
// any address (Go remembers one per endpoint). A new candidate never evicts one, but the netmap's and a
// CallMeMaybe's endpoints evict the oldest candidate when the table is full.
bool tsnet_endpoint_got_ping(tsnet_endpoint_t *e, uint64_t now, const uint8_t ip[16], uint16_t port,
                             const uint8_t txid[12]);
// handlePongConnLocked. False if the txid isn't one of this peer's pings. A pong over DERP only ends its ping; one over
// UDP can make the address it was sent to the best. `res` (may be NULL) says whether it answered a CLI ping.
bool tsnet_endpoint_pong(tsnet_endpoint_t *e, uint64_t now, const uint8_t txid[12], bool via_derp,
                         tsnet_ping_result_t *res);
// discoPing ("tailscale ping"): over DERP (`has_derp`: the peer has a home) while there's no trusted path; to the
// trusted path alone if there is one, else to every endpoint, with no 5 s limit. The first pong answers it (`res` of
// tsnet_endpoint_pong). It counts as a send: the heartbeat starts.
void tsnet_endpoint_cli_ping(tsnet_endpoint_t *e, uint64_t now, bool has_derp, tsnet_ep_actions_t *a);
// handleCallMeMaybe: the endpoints listed replace the last CallMeMaybe's, and every endpoint gets a ping now. Not as
// in Go: one within 2 s of the last is ignored, and unspecified, loopback, multicast, broadcast, link-local
// and port 0 targets are dropped.
void tsnet_endpoint_call_me_maybe(tsnet_endpoint_t *e, uint64_t now, const tsnet_disco_ep_t *eps, size_t n,
                                  tsnet_ep_actions_t *a);
// The timers: ping timeouts (discoPingTimeout) and the heartbeat. Fills `a` with the pings.
void tsnet_endpoint_step(tsnet_endpoint_t *e, uint64_t now, tsnet_ep_actions_t *a);
// When step next has work, or 0 for none.
uint64_t tsnet_endpoint_next(const tsnet_endpoint_t *e);
// wantFullPingLocked.
bool tsnet_endpoint_want_full_ping(const tsnet_endpoint_t *e, uint64_t now);
