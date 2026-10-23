#pragma once
// WireGuard's device and peers: Tailscale's wireguard-go fork at the commit v1.104.1 pins (417aef361226),
// device/peer.go, timers.go, send.go, receive.go and keypair.go, as one state machine with no threads. Messages are
// wg.h's. Times are tsnet_now_ms's; the caller steps the timers (tsnet_wgdev_next, tsnet_wgdev_step).
//   - Peers by static key; a peer can be lazy (PeerLookupFunc's deleteOnIdle): made when an initiation arrives from a
//     key the lookup callback accepts, removed when its keys are zeroed after 540 s without a session.
//   - Keypairs: current, previous and next, rotated as BeginSymmetricSession and ReceivedWithKeypair do (a responder's
//     keypair is "next" until the first data packet confirms it). Receive with any of the three; send with current.
//   - Sending an IP packet stages it (at most TSNET_WG_STAGED; the oldest goes) and sends what's staged with the
//     current keypair, or starts a handshake when there's none or it's too old (RejectAfterTime 180 s, or out of
//     nonces). A handshake initiation goes at most every 5 s (RekeyTimeout).
//   - The timers: a retransmit 5 s (plus up to 334 ms of jitter) after an initiation, giving up after 18 retries, when
//     staged packets are dropped; a keepalive 10 s after data arrived with nothing sent back; a new handshake 15 s
//     after data was sent with nothing heard; the keys zeroed 540 s after the last session (3 × RejectAfterTime).
//   - Keys kept fresh: the initiator rekeys after 120 s (RekeyAfterTime) or 2^60 messages, and once more 165 s in on
//     receiving (keepKeyFreshReceiving). ScheduleHandshakeOnUserSend asks for one after the next send.
// Not here: persistent keepalive (Tailscale sets none; magicsock's heartbeat keeps paths up), the under-load cookie
// path (wireguard-go counts 128 queued handshakes; this loop handles each as it arrives, so it is never under load,
// though it answers a cookie reply), the padding cap at the MTU, and AllowedIPs: a decrypted packet's
// source is the IP side's to check.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "wg.h"

#define TSNET_WG_REKEY_AFTER_MESSAGES ((uint64_t)1 << 60)
#define TSNET_WG_REJECT_AFTER_MESSAGES (UINT64_MAX - ((uint64_t)1 << 13)) // 1<<64 - 1<<13 - 1
#define TSNET_WG_REKEY_AFTER_MS 120000
#define TSNET_WG_REKEY_TIMEOUT_MS 5000
#define TSNET_WG_REKEY_JITTER_MS 334
#define TSNET_WG_MAX_HANDSHAKES 18 // MaxTimerHandshakes: RekeyAttemptTime 90 s / RekeyTimeout
#define TSNET_WG_REJECT_AFTER_MS 180000
#define TSNET_WG_KEEPALIVE_MS 10000
#define TSNET_WG_STAGED 16   // packets staged per peer while there's no session (wireguard-go: 128)
#define TSNET_WG_MAX_PACKET 1500

typedef struct tsnet_wgdev tsnet_wgdev_t;

// The callbacks must not call back into a device: queue what they get, as tsnet's event loop does.
typedef struct {
    const uint8_t *priv; // our static key (copied)
    void *ctx;
    // A WireGuard message for the peer: to magicsock. Runs inside the call that made it.
    void (*send)(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len);
    // A decrypted IP packet from the peer, cut to its IP length: to the IP side.
    void (*deliver)(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len);
    // An initiation from a key with no peer (PeerLookupFunc): true makes it a lazy peer. May be NULL (refuse).
    bool (*lookup)(void *ctx, const uint8_t peer[32]);
    // The wall clock, for an initiation's TAI64N timestamp (tai64n.Now). NULL is the system's (CLOCK_REALTIME). A peer
    // refuses an initiation whose timestamp isn't after the last it took from us, so a clock that isn't set yet (a
    // device before SNTP) gets refused until it is, by a peer that saw a later one.
    void (*wall)(void *ctx, int64_t *secs, uint32_t *nanos);
} tsnet_wgdev_cfg_t;

tsnet_wgdev_t *tsnet_wgdev_new(const tsnet_wgdev_cfg_t *cfg);
void tsnet_wgdev_free(tsnet_wgdev_t *d);

// NewPeer then Start. 0, 1 if it exists already, or -1 (no memory, or a key with a low-order shared secret).
int tsnet_wgdev_add_peer(tsnet_wgdev_t *d, const uint8_t pub[32], uint64_t now);
void tsnet_wgdev_remove_peer(tsnet_wgdev_t *d, const uint8_t pub[32]);
bool tsnet_wgdev_has_peer(const tsnet_wgdev_t *d, const uint8_t pub[32]);

// An IP packet for the peer (RoutineReadFromTUN, StagePackets, SendStagedPackets). -1 for no such peer or a packet
// over TSNET_WG_MAX_PACKET.
int tsnet_wgdev_send(tsnet_wgdev_t *d, const uint8_t pub[32], const uint8_t *pkt, size_t len, uint64_t now);
// A WireGuard message from the network (RoutineReceiveIncoming, RoutineHandshake, RoutineSequentialReceiver). `src`
// is the sender's address bytes, for a cookie.
void tsnet_wgdev_receive(tsnet_wgdev_t *d, const uint8_t *pkt, size_t len, const uint8_t *src, size_t src_len,
                         uint64_t now);
// ScheduleHandshakeOnUserSend: a handshake after the peer's next data packet, if it has key material.
void tsnet_wgdev_handshake_on_send(tsnet_wgdev_t *d, const uint8_t pub[32]);

void tsnet_wgdev_step(tsnet_wgdev_t *d, uint64_t now);
// When step next has work, 0 for none.
uint64_t tsnet_wgdev_next(const tsnet_wgdev_t *d);

// The peer's status: whether it has a current keypair, and when its last handshake finished (0 never).
bool tsnet_wgdev_session(const tsnet_wgdev_t *d, const uint8_t pub[32], uint64_t *last_handshake);
