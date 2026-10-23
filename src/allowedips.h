#pragma once
// AllowedIPs, pure: wireguard-go's device/allowedips.go, the routing table between IP addresses and WireGuard
// peers. Each prefix names one peer (inserting a prefix again gives it to the later peer); a lookup is the longest
// match. It is a flat table, not wireguard-go's trie: an embedded node has a handful of peers and routes, so a scan is cheap and
// leaves less to get wrong. Addresses are tailcfg.h's form: IPv4 in the first 4 bytes with `is6` false.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t ip[16]; // the prefix's address, masked to its length
    bool is6;
    uint8_t bits;
    uint8_t peer[32]; // the peer's node key (its WireGuard key)
} tsnet_aip_t;

typedef struct {
    tsnet_aip_t *e;
    size_t n, cap;
} tsnet_aips_t;

void tsnet_aips_init(tsnet_aips_t *t);
void tsnet_aips_free(tsnet_aips_t *t);
// Insert: the prefix (masked to `bits`) routes to `peer`, replacing whoever had it. -1 for no memory or a bad length.
int tsnet_aips_insert(tsnet_aips_t *t, const uint8_t *ip, bool is6, uint8_t bits, const uint8_t peer[32]);
// RemoveByPeer: every prefix of the peer goes.
void tsnet_aips_remove_peer(tsnet_aips_t *t, const uint8_t peer[32]);
// Lookup: the peer of the longest prefix holding `ip`, or NULL.
const uint8_t *tsnet_aips_lookup(const tsnet_aips_t *t, const uint8_t *ip, bool is6);
// The receive check (RoutineSequentialReceiver): the longest prefix holding `ip` is the peer's. A decrypted packet's
// source must pass it, or the packet is dropped.
bool tsnet_aips_allowed(const tsnet_aips_t *t, const uint8_t peer[32], const uint8_t *ip, bool is6);
