#pragma once
// DERP's frame protocol, the client side: derp/derp.go and derp/derp_client.go. Pure: tsnet_derp_feed() takes
// what the server sent once derphttp's upgrade is done, and reports each message; the writers build the frames
// to send. A frame is a type byte, a big-endian uint32 length, and the payload.
//
// As Go's client:
//   - the first frame must be the server's key (FrameServerKey, the "DERP🔑" magic, at most 1 KB), else the connection
//     fails (recvServerKey); the caller then sends tsnet_derp_client_info(): the node's public key and a NaCl box of
//     {"version":2,"CanAckPings":true} sealed to the server's key (sendClientKey, with what magicsock sets);
//   - FrameServerInfo is opened from the server's key and its JSON read; a box or JSON that fails ends the connection
//     (parseServerInfo);
//   - each other frame is parsed as Recv parses it, a short one dropped as Recv drops it, an unknown type skipped;
//   - a frame over 1 MB ends the connection (recvTimeout).
// Different, for the device's memory: a frame over TSNET_DERP_BUF is skipped, where Go allocates for it. WireGuard and
// disco packets are under 1.5 KB, as Recv's own comment says. The server's token bucket (ServerInfo) is reported, but
// sends aren't held to it yet (Go's setSendRateLimiter drops sends over it).
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

#define TSNET_DERP_HEADER_LEN 5              // FrameHeaderLen
#define TSNET_DERP_MAX_PACKET (64 << 10)     // MaxPacketSize
#define TSNET_DERP_MAX_FRAME (1 << 20)       // recvTimeout's limit
#define TSNET_DERP_MAX_GREETING (1 << 10)    // recvServerKey's limit
#define TSNET_DERP_BUF 4096                  // the biggest frame delivered (Go's bufio.Reader size in derphttp)
#define TSNET_DERP_PROTOCOL_VERSION 2        // ProtocolVersion

// FrameType (derp.go).
enum {
    TSNET_DERP_FRAME_SERVER_KEY = 0x01,
    TSNET_DERP_FRAME_CLIENT_INFO = 0x02,
    TSNET_DERP_FRAME_SERVER_INFO = 0x03,
    TSNET_DERP_FRAME_SEND_PACKET = 0x04,
    TSNET_DERP_FRAME_RECV_PACKET = 0x05,
    TSNET_DERP_FRAME_KEEP_ALIVE = 0x06,
    TSNET_DERP_FRAME_NOTE_PREFERRED = 0x07,
    TSNET_DERP_FRAME_PEER_GONE = 0x08,
    TSNET_DERP_FRAME_PEER_PRESENT = 0x09,
    TSNET_DERP_FRAME_PING = 0x12,
    TSNET_DERP_FRAME_PONG = 0x13,
    TSNET_DERP_FRAME_HEALTH = 0x14,
    TSNET_DERP_FRAME_RESTARTING = 0x15,
};

// PeerGoneReasonType.
enum {
    TSNET_DERP_GONE_DISCONNECTED = 0x00, // the peer disconnected from this server
    TSNET_DERP_GONE_NOT_HERE = 0x01,     // the server doesn't know the peer
};

typedef enum {
    TSNET_DERP_SERVER_KEY,   // the greeting is in: send tsnet_derp_client_info() now
    TSNET_DERP_SERVER_INFO,  // ServerInfoMessage: the connection is up
    TSNET_DERP_PACKET,       // ReceivedPacket
    TSNET_DERP_KEEP_ALIVE,   // KeepAliveMessage
    TSNET_DERP_PEER_GONE,    // PeerGoneMessage
    TSNET_DERP_PEER_PRESENT, // PeerPresentMessage (sent to mesh watchers only)
    TSNET_DERP_PING,         // PingMessage: answer with a pong of the same 8 bytes
    TSNET_DERP_PONG,         // PongMessage
    TSNET_DERP_HEALTH,       // HealthMessage
    TSNET_DERP_RESTARTING,   // ServerRestartingMessage
} tsnet_derp_msg_type_t;

typedef struct {
    tsnet_derp_msg_type_t type;
    uint8_t key[TSNET_KEY_LEN];  // PACKET: the sender; PEER_GONE, PEER_PRESENT: the peer
    const uint8_t *data;         // PACKET: the packet; HEALTH: the problem, empty when healthy again (valid in the call)
    size_t len;
    uint8_t reason;              // PEER_GONE: TSNET_DERP_GONE_*, DISCONNECTED when the server didn't send one
    uint8_t ping[8];             // PING, PONG
    uint32_t reconnect_in_ms;    // RESTARTING: when to reconnect
    uint32_t try_for_ms;         // RESTARTING: how long to try
    int64_t bytes_per_second;    // SERVER_INFO: TokenBucketBytesPerSecond, 0 when unspecified
    int64_t bytes_burst;         // SERVER_INFO: TokenBucketBytesBurst
    bool has_addr, has_flags;    // PEER_PRESENT: which optional fields the server sent
    uint8_t ip[16];              // PEER_PRESENT: the client's address, IPv4 as ::ffff:a.b.c.d
    uint16_t port;
    uint8_t flags;               // PeerPresentFlags
    char app_name[33];           // PEER_PRESENT: empty unless sent and valid (ValidAppName)
} tsnet_derp_msg_t;

// Called from tsnet_derp_feed for each message; it must not call tsnet_derp_feed.
typedef void (*tsnet_derp_cb_t)(void *ctx, const tsnet_derp_msg_t *msg);

typedef struct {
    uint8_t priv[TSNET_KEY_LEN], pub[TSNET_KEY_LEN];
    uint8_t server_key[TSNET_KEY_LEN];
    uint8_t shared[TSNET_KEY_LEN]; // box.Precompute of the node key and the server's key
    bool greeted;                  // the server's key is in
    bool failed;                   // sticky, as Recv's readErr
    uint8_t hdr[TSNET_DERP_HEADER_LEN];
    size_t hdr_len;
    uint32_t len, got; // the frame being read
    uint8_t buf[TSNET_DERP_BUF];
} tsnet_derp_t;

// Starts a connection's reader, for the node's private key (the DERP client's key is the node key). Returns 0 or -1.
int tsnet_derp_init(tsnet_derp_t *d, const uint8_t priv[TSNET_KEY_LEN]);
// Wipes the keys.
void tsnet_derp_wipe(tsnet_derp_t *d);

// Takes what the server sent. Returns 0, or -1 once the connection has failed (then always -1).
int tsnet_derp_feed(tsnet_derp_t *d, const uint8_t *data, size_t len, tsnet_derp_cb_t cb, void *ctx);

// The writers put one frame in `out` and return its length, or -1 if it doesn't fit in `cap` (or is invalid).
// ClientInfo, after the greeting. `nonce`: 24 random bytes (SealTo's).
int tsnet_derp_client_info(const tsnet_derp_t *d, uint8_t *out, size_t cap, const uint8_t nonce[TSNET_BOX_NONCE_LEN]);
// A packet for the node with public key `dst` (Send): at most TSNET_DERP_MAX_PACKET bytes.
int tsnet_derp_send_packet(uint8_t *out, size_t cap, const uint8_t dst[TSNET_KEY_LEN], const uint8_t *pkt, size_t len);
int tsnet_derp_ping(uint8_t *out, size_t cap, const uint8_t data[8]);
int tsnet_derp_pong(uint8_t *out, size_t cap, const uint8_t data[8]);
// Whether this server is the node's home (NotePreferred).
int tsnet_derp_note_preferred(uint8_t *out, size_t cap, bool preferred);
