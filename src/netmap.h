#pragma once
// The netmap across a map stream: control/controlclient/map.go's mapSession, which applies each MapResponse to the
// state the earlier ones built. Pure: give it decoded messages (mapresp.h) and read the state.
//
// Applied in map.go's order: updatePeersStateFromResponse (Peers replaces all and nothing else that turn; otherwise
// PeersRemoved, PeersChanged, PeerSeenChange, OnlineChange, PeersChangedPatch), then updateStateFromResponse (the self
// node, the DERP map's merge, the named packet filters, the domain). Not kept, as in mapresp.h: DNS config, SSH policy,
// user profiles, health and display messages, TKA info.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mapresp.h"

// What a message changed (tsnet_netmap_apply's result).
enum {
    TSNET_NM_SELF = 1 << 0,
    TSNET_NM_PEERS = 1 << 1,
    TSNET_NM_DERP = 1 << 2,
    TSNET_NM_FILTER = 1 << 3,
    TSNET_NM_DOMAIN = 1 << 4,
};

typedef struct {
    char name[128];
    char *rules_json; // the FilterRule list, raw
} tsnet_named_filter_t;

typedef struct {
    bool has_node;        // a non-keep-alive message has carried Node
    tsnet_node_t node;    // the self node (lastNode)
    tsnet_node_t *peers;  // sorted by id (sortedPeers)
    size_t n_peers, cap_peers;
    tsnet_derp_map_t *derp_map; // lastDERPMap, merged, or NULL
    tsnet_named_filter_t *filters; // namedPacketFilters, sorted by name
    size_t n_filters;
    char domain[256];
    int64_t control_time;
} tsnet_netmap_t;

void tsnet_netmap_init(tsnet_netmap_t *nm);
void tsnet_netmap_free(tsnet_netmap_t *nm);

// Applies one decoded message, taking what it keeps out of `r` (the caller still calls tsnet_map_response_free).
// `now` is the unix time PeerSeenChange's "seen" records. Returns the TSNET_NM_* flags of what changed (0 for a
// keep-alive), or -1 if this is the stream's first non-keep-alive message and it lacks Node (sendMapRequest's "initial
// MapResponse lacked node": the poll ends).
int tsnet_netmap_apply(tsnet_netmap_t *nm, tsnet_map_resp_t *r, int64_t now);

// Lookups: by node ID, by node key, by an address of the peer's (its Addresses, not routes). NULL if none.
const tsnet_node_t *tsnet_netmap_peer(const tsnet_netmap_t *nm, int64_t id);
const tsnet_node_t *tsnet_netmap_peer_by_key(const tsnet_netmap_t *nm, const uint8_t key[TSNET_KEY_LEN]);
const tsnet_node_t *tsnet_netmap_peer_by_ip(const tsnet_netmap_t *nm, const tsnet_ip_t *ip);
// By MagicDNS name: the short name ("server", the FQDN's first label) or the FQDN, with or without its trailing dot.
const tsnet_node_t *tsnet_netmap_peer_by_name(const tsnet_netmap_t *nm, const char *name);

// The packet filter rules, the named lists concatenated in name order as map.go does, as one JSON array. malloc'd, or
// NULL when there are none.
char *tsnet_netmap_filter_rules_json(const tsnet_netmap_t *nm);
