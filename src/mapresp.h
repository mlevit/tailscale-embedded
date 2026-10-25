#pragma once
// A MapResponse decoded: tailcfg.MapResponse's fields that control/controlclient's mapSession uses, as C. Node
// fields are normalised as upgradeNode does (LegacyDERPString to HomeDERP, AllowedIPs from Addresses when absent or when
// UnsignedPeerAPIOnly). The packet filters and the self node's CapMap are kept as their raw JSON for the modules that
// will read them (the data plane, the knobs). Not kept: DNSConfig, SSHPolicy, UserProfiles, Health, DisplayMessages,
// TKAInfo, Debug, ClientVersion, CollectServices; MapSessionHandle/Seq.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "tailcfg.h"

// The most peers a netmap keeps, and the most nodes one message's Peers or PeersChanged list is decoded for. A
// node is about 0.7 KB with its arrays, so 1,024 peers is under 1 MB of the device's PSRAM, and a home tailnet is a few
// hundred nodes at most.
#define TSNET_NETMAP_PEERS_MAX 1024

typedef struct {
    int64_t id;
    char stable_id[64];
    char name[256]; // FQDN with its trailing dot
    int64_t user;
    uint8_t key[TSNET_KEY_LEN];
    int64_t key_expiry; // unix seconds, 0 if it doesn't expire
    bool has_key_signature;
    uint8_t machine[TSNET_KEY_LEN];
    uint8_t disco[TSNET_KEY_LEN];
    bool has_disco;
    tsnet_prefix_t *addresses;
    size_t n_addresses;
    tsnet_prefix_t *allowed_ips;
    size_t n_allowed_ips;
    tsnet_addrport_t *endpoints;
    size_t n_endpoints;
    int home_derp;
    int cap;
    int online;        // Online: -1 when absent (nil), else 0 or 1
    int64_t last_seen; // LastSeen: 0 when absent
    bool machine_authorized, expired, unsigned_peer_api_only, is_wireguard_only, is_jailed;
    char hostname[64]; // Hostinfo.Hostname
    char *cap_map_json; // CapMap's raw JSON, or NULL (kept for the self node only)
} tsnet_node_t;

// tailcfg.PeerChange: only the fields in `have` were sent.
enum {
    TSNET_PC_DERP = 1 << 0,
    TSNET_PC_CAP = 1 << 1,
    TSNET_PC_ENDPOINTS = 1 << 2,
    TSNET_PC_KEY = 1 << 3,
    TSNET_PC_DISCO = 1 << 4,
    TSNET_PC_ONLINE = 1 << 5,
    TSNET_PC_LAST_SEEN = 1 << 6,
    TSNET_PC_KEY_EXPIRY = 1 << 7,
    TSNET_PC_KEY_SIGNATURE = 1 << 8,
    TSNET_PC_CAP_MAP = 1 << 9,
};
typedef struct {
    int64_t node_id;
    unsigned have;
    int derp_region, cap;
    tsnet_addrport_t *endpoints;
    size_t n_endpoints;
    uint8_t key[TSNET_KEY_LEN], disco[TSNET_KEY_LEN];
    bool online;
    int64_t last_seen, key_expiry;
} tsnet_peer_change_t;

typedef struct {
    int64_t id;
    bool value;
} tsnet_id_bool_t;

typedef struct {
    char name[32];
    int region_id;
    char host_name[256], cert_name[256];
    char ipv4[16], ipv6[48], stun_test_ip[48];
    int stun_port, derp_port;
    bool stun_only, insecure_for_tests, can_port80;
} tsnet_derp_node_t;

typedef struct {
    int region_id;
    char code[32], name[64];
    double latitude, longitude;
    bool avoid, no_measure_no_home;
    tsnet_derp_node_t *nodes;
    size_t n_nodes;
} tsnet_derp_region_t;

typedef struct {
    int region_id;
    double score;
} tsnet_region_score_t;

typedef struct {
    bool has_regions; // Regions sent (null or absent means unchanged, map.go)
    tsnet_derp_region_t *regions;
    size_t n_regions;
    bool omit_default_regions;
    bool has_home_params, has_region_score;
    tsnet_region_score_t *region_score;
    size_t n_region_score;
} tsnet_derp_map_t;

typedef struct {
    bool keep_alive;
    tsnet_node_t *node; // the self node, or NULL
    tsnet_node_t *peers;
    size_t n_peers;
    tsnet_node_t *peers_changed;
    size_t n_peers_changed;
    int64_t *peers_removed;
    size_t n_peers_removed;
    tsnet_peer_change_t *patches;
    size_t n_patches;
    tsnet_id_bool_t *online_change, *seen_change;
    size_t n_online_change, n_seen_change;
    tsnet_derp_map_t *derp_map; // or NULL
    char *packet_filter_json;   // PacketFilter (the old single list), raw, or NULL
    char *packet_filters_json;  // PacketFilters (named lists), raw, or NULL
    char domain[256];
    int64_t control_time; // unix seconds, 0 when absent
    bool has_ping;
    char ping_url[512], ping_types[64];
    bool ping_url_is_noise, ping_log;
    char *dial_plan_json; // ControlDialPlan, raw, or NULL
} tsnet_map_resp_t;

// Decodes one map message's JSON. Returns 0, or -1 if it isn't a JSON object or a field has the wrong form (a bad key,
// address or time is an error, as json.Unmarshal's would be). On -1 nothing needs freeing.
int tsnet_map_response_parse(tsnet_map_resp_t *m, const char *json, size_t len);
void tsnet_map_response_free(tsnet_map_resp_t *m);

// Frees a node's arrays (not the node).
void tsnet_node_free(tsnet_node_t *n);
// Frees a DERP map and everything in it (NULL is fine).
void tsnet_derp_map_free(tsnet_derp_map_t *dm);
// A deep copy (regions, their nodes, the region scores), freed with tsnet_derp_map_free. NULL if out of memory.
tsnet_derp_map_t *tsnet_derp_map_copy(const tsnet_derp_map_t *dm);

// time.Time's text (RFC 3339, fraction and offset allowed) to unix seconds; Go's zero time is 0. Returns 0 or -1.
int tsnet_time_parse(int64_t *out, const char *s);
