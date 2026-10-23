#pragma once
// STUN: Tailscale's net/stun/stun.go, the binding request netcheck sends to DERP nodes and the response that
// tells a node its address as the server saw it. Pure. Addresses are 16 bytes, an IPv4 one as ::ffff:a.b.c.d (Go's
// netip.Addr.Unmap gives the same address for both forms).
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TSNET_STUN_TXID_LEN 12
#define TSNET_STUN_HEADER_LEN 20
#define TSNET_STUN_REQUEST_LEN 40 // the header, SOFTWARE "tailnode" (4 + 8) and FINGERPRINT (4 + 4)

// The errors (Go's ErrNotSTUN and the rest).
enum {
    TSNET_STUN_NOT_STUN = -1,
    TSNET_STUN_NOT_SUCCESS = -2,
    TSNET_STUN_MALFORMED = -3,
    TSNET_STUN_NOT_BINDING_REQUEST = -4,
    TSNET_STUN_WRONG_SOFTWARE = -5,
    TSNET_STUN_NO_FINGERPRINT = -6,
    TSNET_STUN_WRONG_FINGERPRINT = -7,
};

// Request: a binding request with SOFTWARE "tailnode" and a FINGERPRINT. `txid`: 12 random bytes (NewTxID).
void tsnet_stun_request(uint8_t out[TSNET_STUN_REQUEST_LEN], const uint8_t txid[TSNET_STUN_TXID_LEN]);
// Is: at least a header, the top two bits zero, and the magic cookie.
bool tsnet_stun_is(const uint8_t *b, size_t len);
// ParseResponse: a success response's XOR-MAPPED-ADDRESS (or 0x8020, which servers send too; the last one wins), else
// its MAPPED-ADDRESS. Returns 0, or one of the errors. `txid` is filled whenever the packet is STUN, as Go fills it
// (not for malformed attributes, where Go returns a zero ID).
int tsnet_stun_parse_response(const uint8_t *b, size_t len, uint8_t txid[TSNET_STUN_TXID_LEN], uint8_t ip[16],
                              uint16_t *port);
// ParseBindingRequest: Tailscale's own binding request (SOFTWARE "tailnode", ending in a good FINGERPRINT).
int tsnet_stun_parse_binding_request(const uint8_t *b, size_t len, uint8_t txid[TSNET_STUN_TXID_LEN]);
// Response: a binding success with one XOR-MAPPED-ADDRESS (what a STUN server sends; for tests). Returns its length,
// or -1 if it doesn't fit.
int tsnet_stun_response(uint8_t *out, size_t cap, const uint8_t txid[TSNET_STUN_TXID_LEN], const uint8_t ip[16],
                        uint16_t port);
