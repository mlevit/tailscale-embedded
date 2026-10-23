#pragma once
// The packet filter: wgengine/filter at v1.104.1, for IPv4. It is pure, so the host tests it.
// - The rules come from the netmap's packet filter (tailcfg.FilterRule JSON, parsed as
//   filter.MatchesFromFilterRules does).
// - The local addresses come from the node's own addresses (ipnlocal's localNets).
// - Inbound, as Filter.RunIn does:
//   - A packet for an address that isn't local is dropped.
//   - ICMP echo replies and errors pass. Other ICMP passes if any rule lets its source reach that address.
//   - A TCP packet that isn't a SYN passes. A SYN passes only if a rule allows its port.
//   - UDP passes if a rule allows it, or if it answers a flow this node started.
// - Outbound (Filter.RunOut) only drops junk, and records each UDP flow for its replies.
// - The flow cache is an LRU of 512 flows, like Go's, and a rule update keeps it (New's shareStateWith).
// Before the first rules, nothing passes inbound (NewAllowNone).
// A jailed peer's packets go through tsnet_filter_in_jailed (the tun knows which peers are).
// shortcut: peer capabilities ("cap:" sources, srcIPHasCap) never match, so those rules drop. Upgrade when the netmap
// keeps peers' CapMap.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "tailcfg.h"

#define TSNET_FILTER_FLOWS 512 // lruMax
#define TSNET_TSMP_REJECT_LEN 27 // an IPv4 header and TailscaleRejectedHeader's 7 bytes
#define TSNET_TSMP_PONG_LEN 31   // an IPv4 header and TSMPPongReply's 11 bytes

typedef struct tsnet_filter tsnet_filter_t;

tsnet_filter_t *tsnet_filter_new(void);
void tsnet_filter_free(tsnet_filter_t *f);

// The netmap's rules (a JSON array, tsnet_netmap_filter_rules_json; NULL for none) and the node's own addresses.
// The flow cache is kept. Returns 0, or -1 if some entries didn't parse: the rest apply, as in Go. A rule with SrcBits
// or DstPorts[].Bits leaves no rules at all, as Go does for a control server too old for this client.
int tsnet_filter_set(tsnet_filter_t *f, const char *rules_json, const tsnet_prefix_t *local, size_t n_local);

// Whether an IPv4 packet from a peer may reach the stack (RunIn).
bool tsnet_filter_in(tsnet_filter_t *f, const uint8_t *pkt, size_t len);
// The same for a jailed peer (IsJailed): no rule matches (Go's jailed filter, NewShieldsUpFilter), so only replies
// and flows this node started pass, never a new connection.
bool tsnet_filter_in_jailed(tsnet_filter_t *f, const uint8_t *pkt, size_t len);
// Whether an IPv4 packet from the stack may go to a peer (RunOut). It records a UDP flow.
bool tsnet_filter_out(tsnet_filter_t *f, const uint8_t *pkt, size_t len);
// The same for a packet to a jailed peer: its flow goes in the jailed filter's own cache, as Go's jailed Filter keeps
// one of its own.
bool tsnet_filter_out_jailed(tsnet_filter_t *f, const uint8_t *pkt, size_t len);

// The TSMP messages tstun sends back, each written to out from the packet's destination to its source. Each returns
// the message's length, or 0 when the packet isn't one it answers.
// - For an IPv4 TCP packet with SYN set: this node rejected it (TailscaleRejectedHeader) for `reason`. tstun sends
//   TSNET_REJECT_ACLS, or TSNET_REJECT_SHIELDS when the filter was shields-up (a jailed peer's).
#define TSNET_REJECT_ACLS 'A'    // RejectedDueToACLs
#define TSNET_REJECT_SHIELDS 'S' // RejectedDueToShieldsUp
size_t tsnet_tsmp_reject(const uint8_t *pkt, size_t len, char reason, uint8_t out[TSNET_TSMP_REJECT_LEN]);
// - For a TSMP ping ("tailscale ping --tsmp"): its pong (injectOutboundPong), with PeerAPI port 0 (there's none).
size_t tsnet_tsmp_pong(const uint8_t *pkt, size_t len, uint8_t out[TSNET_TSMP_PONG_LEN]);
