#pragma once
// The map response's messages, from control/controlclient/direct.go: readMapResponseMessage (a little-endian
// uint32 size, then the message) and decodeMsg (zstd, as the client asks with Compress "zstd", with the keep-alive fast
// path). Pure: feed it the response body as it arrives and it hands back each message's JSON.
//
// Limits, smaller than Go's for the device (Go: 256 MB a message on the wire, 1 GB decoded): a message over
// TSNET_MAPMSG_WIRE_MAX or decoding past TSNET_MAPMSG_DECODED_MAX is an error, checked before allocating. The zstd window
// is capped at TSNET_MAPMSG_WINDOW_LOG (Tailscale's zstdframe writes single-segment frames, whose window is the message).
// A message's buffers over TSNET_MAPMSG_KEEP are freed once it is handled, so one big netmap doesn't hold its memory
// for the rest of the poll.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// A real netmap is about 1.5 KB of JSON a peer, so these hold a tailnet of well over a thousand nodes.
#define TSNET_MAPMSG_WIRE_MAX (2u << 20)    // zstd shrinks a netmap 5 to 10 times, so 2 MB covers the decoded cap
#define TSNET_MAPMSG_DECODED_MAX (4u << 20) // 4 MB of JSON: about 2,500 peers, twice TSNET_NETMAP_PEERS_MAX
#define TSNET_MAPMSG_WINDOW_LOG 22          // 4 MB, the decoded cap
#define TSNET_MAPMSG_KEEP (64u << 10)       // a buffer past 64 KB is freed after its message, not held between messages

typedef struct tsnet_mapmsg tsnet_mapmsg_t;

// A message's JSON (not NUL-terminated; valid during the call). `keep_alive` is true when it was recognised as the
// keep-alive message without decoding (decodeMsg's fast path); json is then {"KeepAlive":true}.
typedef void (*tsnet_mapmsg_fn)(void *ctx, const char *json, size_t len, bool keep_alive);

// `zstd`: the request said Compress "zstd". NULL if out of memory.
tsnet_mapmsg_t *tsnet_mapmsg_new(bool zstd);
void tsnet_mapmsg_free(tsnet_mapmsg_t *m);

// Takes body bytes, in any split. Calls `fn` for each whole message, in order. Returns 0, or -1 once a message is over a
// limit or doesn't decode (the stream is then unusable, as Go returns the error and ends the poll).
int tsnet_mapmsg_feed(tsnet_mapmsg_t *m, const uint8_t *data, size_t len, tsnet_mapmsg_fn fn, void *ctx);
