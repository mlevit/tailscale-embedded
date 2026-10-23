#pragma once
// WireGuard's messages, pure: Tailscale's wireguard-go fork at the commit v1.104.1 pins (417aef361226):
// device/noise-protocol.go, noise-helpers.go, cookie.go, replay/replay.go and tai64n. The peer state machine (index
// table, keypair rotation, timers, queues) is wgdev.h's; this file makes and checks messages.
//   - The handshake, Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s with WireGuard's identifier: the initiation (148 bytes) and
//     the response (92), in both roles, and the transport keys both sides derive. Tailscale sets no preshared key: it
//     is all zeros here.
//   - mac1 and mac2 (the cookie): what every handshake message carries, the checks a responder makes, and the cookie
//     reply (64 bytes, XChaCha20-Poly1305 from Monocypher) a responder under load sends and an initiator consumes.
//   - Transport data: the 16-byte header (type 4, the receiver's index, a 64-bit counter), ChaCha20-Poly1305 with the
//     counter as the nonce, the plaintext padded to 16 bytes; and the replay filter (RFC 6479, a 8128-message window).
// Numbers are little-endian on the wire, as wireguard-go marshals them.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TSNET_WG_INITIATION 1
#define TSNET_WG_RESPONSE 2
#define TSNET_WG_COOKIE_REPLY 3
#define TSNET_WG_TRANSPORT 4

#define TSNET_WG_INITIATION_LEN 148
#define TSNET_WG_RESPONSE_LEN 92
#define TSNET_WG_COOKIE_REPLY_LEN 64
#define TSNET_WG_TRANSPORT_HEADER 16
#define TSNET_WG_KEEPALIVE_LEN (TSNET_WG_TRANSPORT_HEADER + 16)
#define TSNET_WG_TIMESTAMP_LEN 12
#define TSNET_WG_COOKIE_REFRESH_MS 120000 // CookieRefreshTime
#define TSNET_WG_INIT_RATE_MS 50          // HandshakeInitationRate: initiations closer than this are a flood

// KDF1/2/3 (noise-helpers.go): HMAC-BLAKE2s, a key of any length; t1 and t2 may be NULL.
void tsnet_wg_kdf(const uint8_t *key, size_t key_len, const uint8_t *in, size_t len, uint8_t t0[32], uint8_t t1[32],
                  uint8_t t2[32]);

// tai64n.stamp: seconds since 1970 and nanoseconds, the nanoseconds' low 24 bits cleared (wireguard-go whitens them).
void tsnet_wg_tai64n(uint8_t out[TSNET_WG_TIMESTAMP_LEN], int64_t unix_secs, uint32_t nanos);

typedef enum {
    TSNET_WG_HS_ZEROED,
    TSNET_WG_HS_INITIATION_CREATED,
    TSNET_WG_HS_INITIATION_CONSUMED,
    TSNET_WG_HS_RESPONSE_CREATED,
    TSNET_WG_HS_RESPONSE_CONSUMED,
} tsnet_wg_hs_state_t;

// A peer's handshake (device.Handshake).
typedef struct {
    tsnet_wg_hs_state_t state;
    uint8_t hash[32], ck[32];
    uint8_t local_eph[32];   // the ephemeral private key
    uint8_t remote_static[32], remote_eph[32];
    uint8_t ss[32];          // precomputedStaticStatic: X25519(our static, theirs), zero if low-order
    uint32_t local_index, remote_index;
    uint8_t last_timestamp[TSNET_WG_TIMESTAMP_LEN]; // the newest initiation's, against replays
    uint64_t last_init_ms;   // when we last consumed an initiation (ms), against floods; 0 never
} tsnet_wg_handshake_t;

// The transport keys of a finished handshake (BeginSymmetricSession's derivation; rotation is wgdev.h's).
typedef struct {
    uint8_t send[32], recv[32];
    bool initiator;
    uint32_t local_index, remote_index;
} tsnet_wg_keys_t;

// For a peer: our static key and its public key (SetPeerPublicKey's precomputation). -1 if the shared secret is zero
// (a low-order key): such a peer can't handshake, as in wireguard-go.
int tsnet_wg_handshake_init(tsnet_wg_handshake_t *hs, const uint8_t local_priv[32], const uint8_t remote_pub[32]);
// Wipes the handshake's secrets (Handshake.Clear); the peer's keys and the replay and flood state stay.
void tsnet_wg_handshake_clear(tsnet_wg_handshake_t *hs);

// CreateMessageInitiation, mac1 and mac2 not yet added (tsnet_wg_add_macs). `eph` NULL makes a fresh ephemeral key;
// `timestamp` is now's TAI64N. Writes TSNET_WG_INITIATION_LEN bytes. Returns 0 or -1.
int tsnet_wg_create_initiation(tsnet_wg_handshake_t *hs, const uint8_t local_pub[32], uint32_t local_index,
                               const uint8_t *eph, const uint8_t timestamp[TSNET_WG_TIMESTAMP_LEN],
                               uint8_t out[TSNET_WG_INITIATION_LEN]);

// ConsumeMessageInitiation in its two halves, as the peer lookup sits between them.
typedef struct {
    uint8_t hash[32], ck[32];
    uint8_t remote_static[32], remote_eph[32];
    uint32_t sender;
} tsnet_wg_initiation_t;
// The first: decrypts the sender's static key. Returns 0 (`st->remote_static` names the peer), or -1.
int tsnet_wg_open_initiation(const uint8_t local_priv[32], const uint8_t local_pub[32],
                             const uint8_t msg[TSNET_WG_INITIATION_LEN], tsnet_wg_initiation_t *st);
// The second, with that peer's handshake: decrypts the timestamp, refuses a replay (a timestamp not after the last)
// and a flood (an initiation within TSNET_WG_INIT_RATE_MS of the last), and takes the handshake to
// INITIATION_CONSUMED. Returns 0 or -1. `st` is wiped.
int tsnet_wg_accept_initiation(tsnet_wg_handshake_t *hs, tsnet_wg_initiation_t *st,
                               const uint8_t msg[TSNET_WG_INITIATION_LEN], uint64_t now_ms);

// CreateMessageResponse (after an initiation was accepted), mac1 and mac2 not yet added. `eph` NULL makes a fresh
// ephemeral key. Returns 0 or -1.
int tsnet_wg_create_response(tsnet_wg_handshake_t *hs, uint32_t local_index, const uint8_t *eph,
                             uint8_t out[TSNET_WG_RESPONSE_LEN]);
// ConsumeMessageResponse, with the handshake its receiver index names (the caller's index table). Returns 0 or -1.
int tsnet_wg_consume_response(tsnet_wg_handshake_t *hs, const uint8_t local_priv[32],
                              const uint8_t msg[TSNET_WG_RESPONSE_LEN]);
// The transport keys, after RESPONSE_CONSUMED (the initiator) or RESPONSE_CREATED (the responder). The handshake is
// zeroed. Returns 0, or -1 in another state.
int tsnet_wg_derive_keys(tsnet_wg_handshake_t *hs, tsnet_wg_keys_t *keys);

// mac1 and mac2 for messages to a peer (CookieGenerator): keyed by the peer's public key.
typedef struct {
    uint8_t mac1_key[32], cookie_key[32];
    uint8_t cookie[16];
    uint64_t cookie_set_ms; // 0: none
    bool has_last_mac1;
    uint8_t last_mac1[16];
} tsnet_wg_cookiegen_t;
void tsnet_wg_cookiegen_init(tsnet_wg_cookiegen_t *g, const uint8_t remote_pub[32]);
// AddMacs: the last 32 bytes of the message are mac1 and mac2; mac2 is set only with a cookie under 120 s old.
void tsnet_wg_add_macs(tsnet_wg_cookiegen_t *g, uint8_t *msg, size_t len, uint64_t now_ms);
// ConsumeReply: the cookie in a reply to the last message we sent. True if it opened.
bool tsnet_wg_consume_cookie_reply(tsnet_wg_cookiegen_t *g, const uint8_t msg[TSNET_WG_COOKIE_REPLY_LEN],
                                   uint64_t now_ms);

// The checks on messages to us (CookieChecker): keyed by our public key.
typedef struct {
    uint8_t mac1_key[32], cookie_key[32];
    uint8_t secret[32];
    uint64_t secret_set_ms; // 0: none
} tsnet_wg_cookiecheck_t;
void tsnet_wg_cookiecheck_init(tsnet_wg_cookiecheck_t *c, const uint8_t local_pub[32]);
bool tsnet_wg_check_mac1(const tsnet_wg_cookiecheck_t *c, const uint8_t *msg, size_t len);
// mac2 from the cookie for `src` (the sender's address bytes), only while our secret is under 120 s old.
bool tsnet_wg_check_mac2(const tsnet_wg_cookiecheck_t *c, const uint8_t *msg, size_t len, const uint8_t *src,
                         size_t src_len, uint64_t now_ms);
// CreateReply: a cookie reply to `msg` (from `src`, to the sender's index `receiver`), a fresh secret every 120 s.
// `nonce` NULL is random. Returns 0 or -1.
int tsnet_wg_create_cookie_reply(tsnet_wg_cookiecheck_t *c, const uint8_t *msg, size_t len, uint32_t receiver,
                                 const uint8_t *src, size_t src_len, uint64_t now_ms, const uint8_t *nonce,
                                 uint8_t out[TSNET_WG_COOKIE_REPLY_LEN]);

// replay.Filter (RFC 6479): 128 blocks of 64 bits.
typedef struct {
    uint64_t last;
    uint64_t ring[128];
} tsnet_wg_replay_t;
void tsnet_wg_replay_reset(tsnet_wg_replay_t *f);
// ValidateCounter: false for a counter at or over `limit`, one too far behind, or one seen before.
bool tsnet_wg_replay_check(tsnet_wg_replay_t *f, uint64_t counter, uint64_t limit);

#define TSNET_WG_TUN_MTU 1280 // tstun.DefaultTUNMTU: the safe MTU, as Tailscale's PMTUD is off by default

// calculatePaddingSize: the zeros a payload of `len` gets, up to a multiple of 16 but never past the MTU (0: no cap).
size_t tsnet_wg_padding(size_t len, size_t mtu);
// A transport message: the payload padded (tsnet_wg_padding, with the TUN `mtu`), sealed with `key` and `counter`,
// for the peer's `receiver` index. Writes TSNET_WG_TRANSPORT_HEADER + padded + 16 bytes and returns that, or -1 if
// `cap` is short.
int tsnet_wg_seal(uint8_t *out, size_t cap, const uint8_t key[32], uint32_t receiver, uint64_t counter,
                  const uint8_t *payload, size_t len, size_t mtu);
// A transport message's receiver index and counter. -1 if it's shorter than a keepalive or not type 4.
int tsnet_wg_transport_header(const uint8_t *pkt, size_t len, uint32_t *receiver, uint64_t *counter);
// Opens one with `key`: writes the padded plaintext and returns its length (0 for a keepalive), or -1 for a bad tag.
// The replay check is the caller's, after it opens (as RoutineDecryption then RoutineSequentialReceiver do).
int tsnet_wg_open(uint8_t *out, size_t cap, const uint8_t key[32], const uint8_t *pkt, size_t len);
