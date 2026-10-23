#pragma once
// Disco: Tailscale's disco/disco.go, the messages nodes exchange to find a path to each other, and the sealed
// packet they travel in. Pure. A packet is the magic "TS💬", the sender's disco public key, a 24-byte nonce, and a
// NaCl box of the message sealed with the two disco keys' shared key (key.DiscoShared, crypto.h's box). The disco key
// is a new random key each start (key.NewDisco), never stored.
//
// Messages: Ping (a TxID, the sender's node key, padding to probe the path MTU), Pong (the TxID, and the address the
// ping came from) and CallMeMaybe (the sender's endpoints). The UDP relay messages (types 4 to 9) are recognised and
// not decoded: tsnet doesn't do peer relays yet. Addresses are 16 bytes, IPv4 as ::ffff:a.b.c.d (stun.h's form).
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

#define TSNET_DISCO_MAGIC_LEN 6
#define TSNET_DISCO_WRAPPER_LEN (TSNET_DISCO_MAGIC_LEN + TSNET_KEY_LEN + TSNET_BOX_NONCE_LEN) // LooksLikeDiscoWrapper
#define TSNET_DISCO_TXID_LEN 12
#define TSNET_DISCO_EPS 64 // a CallMeMaybe's endpoints kept (Go keeps them all; a packet of 1.5 KB holds 83)

enum {
    TSNET_DISCO_PING = 0x01,
    TSNET_DISCO_PONG = 0x02,
    TSNET_DISCO_CALL_ME_MAYBE = 0x03,
    // 0x04 to 0x09: the UDP relay messages.
};

typedef struct {
    uint8_t ip[16];
    uint16_t port;
} tsnet_disco_ep_t;

typedef struct {
    int type; // TSNET_DISCO_*, or 4 to 9 for a relay message (not decoded)
    uint8_t txid[TSNET_DISCO_TXID_LEN];
    // Ping:
    bool has_node_key;
    uint8_t node_key[TSNET_KEY_LEN];
    size_t padding;
    // Pong:
    uint8_t src_ip[16];
    uint16_t src_port;
    // CallMeMaybe:
    tsnet_disco_ep_t eps[TSNET_DISCO_EPS];
    size_t n_eps;
} tsnet_disco_msg_t;

// LooksLikeDiscoWrapper.
bool tsnet_disco_looks_like(const uint8_t *pkt, size_t len);
// Source: the sender's disco public key in a packet that looks like disco.
const uint8_t *tsnet_disco_source(const uint8_t *pkt);

// Parse: a message from inside the box. Returns 0, or -1 for a short or unknown message.
int tsnet_disco_parse(const uint8_t *p, size_t len, tsnet_disco_msg_t *m);
// AppendMarshal for each message: writes it to `out` and returns its length, or -1 if it doesn't fit. A zero or NULL
// node key leaves it out, as Go does.
int tsnet_disco_ping(uint8_t *out, size_t cap, const uint8_t txid[TSNET_DISCO_TXID_LEN],
                     const uint8_t node_key[TSNET_KEY_LEN], size_t padding);
int tsnet_disco_pong(uint8_t *out, size_t cap, const uint8_t txid[TSNET_DISCO_TXID_LEN], const uint8_t ip[16],
                     uint16_t port);
int tsnet_disco_call_me_maybe(uint8_t *out, size_t cap, const tsnet_disco_ep_t *eps, size_t n);

// sendDiscoMessage's packet: the wrapper around `msg`, sealed with `shared` and `nonce` (24 random bytes). Returns the
// packet's length, or -1 if it doesn't fit.
int tsnet_disco_seal(uint8_t *out, size_t cap, const uint8_t my_disco_pub[TSNET_KEY_LEN],
                     const uint8_t shared[TSNET_KEY_LEN], const uint8_t nonce[TSNET_BOX_NONCE_LEN], const uint8_t *msg,
                     size_t len);
// handleDiscoMessage's open: the message inside a packet from the peer whose shared key is `shared`. Writes it to `out`
// (at least len - TSNET_DISCO_WRAPPER_LEN - 16 bytes) and returns its length, or -1 if it isn't disco or doesn't open.
int tsnet_disco_open(const uint8_t *pkt, size_t len, const uint8_t shared[TSNET_KEY_LEN], uint8_t *out, size_t cap);
