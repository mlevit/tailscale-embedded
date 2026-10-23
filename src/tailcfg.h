#pragma once
// tailcfg's wire types for tsnet's control client: what the client sends (RegisterRequest, MapRequest, Hostinfo)
// and what it reads (RegisterResponse, MapResponse), as JSON. Field names and forms are tailcfg.go's; what the client
// fills is direct.go's (doLogin, sendMapRequest). Pure and bounded: the decoders take untrusted text and give bounded
// structs, and the JSON tree is freed before they return.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

// The capability version tsnet sends everywhere the official client sends tailcfg.CurrentCapabilityVersion: /key?v=, the
// Noise prologue, RegisterRequest.Version and MapRequest.Version. It promises what tailcfg.go's notes list up to it, so
// it is chosen for what tsnet implements, not set to Go's current (149). 131 is a version Tailscale's control server
// accepts from embedded clients. Promises at or below it that tsnet doesn't keep yet:
// PingRequest's disco/TSMP/ICMP/peerapi pings (12, 31), c2n requests (45-128), peer-relay disco messages (120, 121),
// seamless key renewal (126). docs/design.md, "The capability version", keeps the list.
#define TSNET_CAPVER 131

// ---- keys and addresses ----

// key's text forms: a prefix and 64 lowercase hex digits (key/node.go, disco.go, machine.go, tka.go).
#define TSNET_KEY_NODE "nodekey:"
#define TSNET_KEY_DISCO "discokey:"
#define TSNET_KEY_MACHINE "mkey:"
#define TSNET_KEY_NL "nlpub:"
#define TSNET_KEY_TEXT_MAX 80

// Writes prefix + hex into out (TSNET_KEY_TEXT_MAX bytes).
void tsnet_key_text(char *out, const char *prefix, const uint8_t key[TSNET_KEY_LEN]);
// Parses one; hex of either case, exactly 64 digits. Returns 0 or -1.
int tsnet_key_parse(uint8_t key[TSNET_KEY_LEN], const char *prefix, const char *text);

// netip.Addr / Prefix / AddrPort. IPv4 is kept as itself (is6 0, the first 4 bytes); IPv6 in 16 bytes. A zone isn't kept.
typedef struct {
    uint8_t ip[16];
    uint8_t is6;
} tsnet_ip_t;
typedef struct {
    tsnet_ip_t ip;
    uint8_t bits;
} tsnet_prefix_t;
typedef struct {
    tsnet_ip_t ip;
    uint16_t port;
} tsnet_addrport_t;

int tsnet_ip_parse(tsnet_ip_t *ip, const char *s);             // "100.64.0.1", "fd7a:115c:a1e0::1"
int tsnet_prefix_parse(tsnet_prefix_t *p, const char *s);      // "100.64.0.1/32"; bits within the family
int tsnet_addrport_parse(tsnet_addrport_t *a, const char *s);  // "1.2.3.4:41641", "[::1]:41641"
void tsnet_addrport_text(char *out, size_t cap, const tsnet_addrport_t *a);

// ---- what the client sends ----

// The Hostinfo an embedded node fills (hostinfo.New's fields that apply; the rest are omitzero and left out).
typedef struct {
    const char *ipn_version;    // IPNVersion
    const char *backend_log_id; // BackendLogID: required by the official client (doLogin, sendMapRequest)
    const char *os;             // OS
    const char *os_version;     // OSVersion
    const char *hostname;       // Hostname
    const char *machine;        // Machine (uname -m's role)
    const struct tsnet_net_info *net_info; // NetInfo, or NULL for none yet
} tsnet_hostinfo_t;

#define TSNET_NETINFO_LATENCIES 32
// tailcfg.NetInfo as magicsock's updateNetInfo fills it on an embedded node: WorkingIPv6, OSHasIPv6 and WorkingICMPv4 are false
// (netcheck has neither IPv6 nor ICMP), and there's no port mapping, link type or firewall mode.
typedef struct tsnet_net_info {
    int preferred_derp; // PreferredDERP, 0 for none (left out)
    bool working_udp;   // WorkingUDP
    int mapping_varies; // MappingVariesByDestIP: -1 unknown (left out), 0 or 1
    struct {
        int region;
        double seconds;
    } derp_latency[TSNET_NETINFO_LATENCIES]; // DERPLatency, as "<region>-v4"
    size_t n_derp_latency;
} tsnet_net_info_t;

typedef struct {
    uint16_t version;
    uint8_t node_key[TSNET_KEY_LEN];
    uint8_t old_node_key[TSNET_KEY_LEN]; // all zero when none (Go writes the zero key)
    const uint8_t *nl_key;               // NLKey's 32 bytes, or NULL to leave it out
    const char *auth_key;                // Auth.AuthKey, or NULL
    const char *followup;                // Followup URL, or NULL
    int64_t timestamp;                   // unix seconds, or 0 when the wall clock isn't known (Timestamp is omitempty)
    int64_t expiry;                      // unix seconds, or 0 for Go's zero time (logout sends 123)
    bool ephemeral;
    const tsnet_hostinfo_t *hostinfo;
} tsnet_register_req_t;

typedef struct {
    uint16_t version;
    uint8_t node_key[TSNET_KEY_LEN];
    uint8_t disco_key[TSNET_KEY_LEN];
    const char *compress; // "zstd" or "" (sendMapRequest always sends "zstd")
    bool keep_alive, stream, omit_peers;
    const tsnet_addrport_t *endpoints;
    const int *endpoint_types; // tailcfg.EndpointType per endpoint
    size_t n_endpoints;
    const tsnet_hostinfo_t *hostinfo;
} tsnet_map_req_t;

// Each returns a malloc'd NUL-terminated JSON string (free() it), or NULL.
char *tsnet_register_request_json(const tsnet_register_req_t *r);
char *tsnet_map_request_json(const tsnet_map_req_t *r);

// ---- what the client reads ----

typedef struct {
    char error[256];     // Error: the server refused
    char auth_url[512];  // AuthURL: authorization pending
    bool node_key_expired, machine_authorized;
    bool has_node_key_signature; // NodeKeySignature non-empty (doLogin: a re-sign is needed)
    char login_name[128];        // Login.LoginName
} tsnet_register_resp_t;

int tsnet_register_response_parse(tsnet_register_resp_t *r, const char *json, size_t len);
