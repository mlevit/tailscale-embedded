// Host test of DERP's frame protocol. It plays a server written from derp_client.go's side of the protocol (the
// greeting, ServerInfo sealed to the client, ClientInfo opened, every frame type Recv handles, fed whole and split at
// every byte), so it checks the parser against that reading. Tailscale's real derpserver checks it in the harness.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "derp.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static const uint8_t MAGIC[8] = {0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91};
static uint8_t client_priv[32], client_pub[32], server_priv[32], server_pub[32], server_shared[32];

// A stream of frames, built as the server writes them.
static uint8_t stream[16384];
static size_t stream_len;

static void put(uint8_t type, const uint8_t *payload, size_t len)
{
    stream[stream_len++] = type;
    stream[stream_len++] = (uint8_t)(len >> 24);
    stream[stream_len++] = (uint8_t)(len >> 16);
    stream[stream_len++] = (uint8_t)(len >> 8);
    stream[stream_len++] = (uint8_t)len;
    if (len) {
        memcpy(stream + stream_len, payload, len);
    }
    stream_len += len;
}

static void put_greeting(size_t extra)
{
    uint8_t p[64] = {0};
    memcpy(p, MAGIC, 8);
    memcpy(p + 8, server_pub, 32);
    put(0x01, p, 40 + extra);
}

// The server's sendServerInfo: a nonce, then the JSON boxed to the client.
static void put_server_info(const char *json, int flip)
{
    uint8_t p[512];
    size_t n = strlen(json);
    for (int i = 0; i < 24; i++) {
        p[i] = (uint8_t)(0x40 + i);
    }
    tsnet_box_seal(p + 24, server_shared, p, (const uint8_t *)json, n);
    if (flip) {
        p[30] ^= 1;
    }
    put(0x03, p, 24 + 16 + n);
}

// What the callback saw, as text, to compare runs.
static char seen[8192];
static size_t seen_len;

static void on_msg(void *ctx, const tsnet_derp_msg_t *m)
{
    (void)ctx;
    char line[256];
    int n = 0;
    switch (m->type) {
    case TSNET_DERP_SERVER_KEY:
        n = snprintf(line, sizeof line, "key %02x%02x;", m->key[0], m->key[31]);
        break;
    case TSNET_DERP_SERVER_INFO:
        n = snprintf(line, sizeof line, "info %lld/%lld;", (long long)m->bytes_per_second, (long long)m->bytes_burst);
        break;
    case TSNET_DERP_PACKET:
        n = snprintf(line, sizeof line, "packet from %02x len %zu first %02x;", m->key[0], m->len, m->len ? m->data[0] : 0);
        break;
    case TSNET_DERP_KEEP_ALIVE:
        n = snprintf(line, sizeof line, "keepalive;");
        break;
    case TSNET_DERP_PEER_GONE:
        n = snprintf(line, sizeof line, "gone %02x reason %u;", m->key[0], m->reason);
        break;
    case TSNET_DERP_PEER_PRESENT:
        n = snprintf(line, sizeof line, "present %02x addr %d %u.%u.%u.%u:%u flags %d %u name '%s';", m->key[0], m->has_addr,
                     m->ip[12], m->ip[13], m->ip[14], m->ip[15], m->port, m->has_flags, m->flags, m->app_name);
        break;
    case TSNET_DERP_PING:
    case TSNET_DERP_PONG:
        n = snprintf(line, sizeof line, "%s %02x%02x;", m->type == TSNET_DERP_PING ? "ping" : "pong", m->ping[0], m->ping[7]);
        break;
    case TSNET_DERP_HEALTH:
        n = snprintf(line, sizeof line, "health '%.*s';", (int)m->len, (const char *)m->data);
        break;
    case TSNET_DERP_RESTARTING:
        n = snprintf(line, sizeof line, "restarting %u %u;", m->reconnect_in_ms, m->try_for_ms);
        break;
    }
    if (n > 0 && seen_len + (size_t)n < sizeof seen) {
        memcpy(seen + seen_len, line, (size_t)n);
        seen_len += (size_t)n;
        seen[seen_len] = 0;
    }
}

static int feed_all(tsnet_derp_t *d, const uint8_t *data, size_t len, size_t split)
{
    seen_len = 0;
    seen[0] = 0;
    EXPECT(tsnet_derp_init(d, client_priv) == 0);
    int r = 0;
    for (size_t at = 0; at < len && r == 0; at += split) {
        size_t n = len - at < split ? len - at : split;
        r = tsnet_derp_feed(d, data + at, n, on_msg, NULL);
    }
    return r;
}

static void build_good_stream(void)
{
    stream_len = 0;
    put_greeting(3); // a longer greeting is allowed, for the future
    put_server_info("{\"version\":2,\"TokenBucketBytesPerSecond\":1000,\"tokenbucketbytesburst\":2000}", 0);
    put(0x06, NULL, 0);
    uint8_t p[6000];
    memset(p, 0xa1, 32);
    p[32] = 0x45;
    put(0x05, p, 32 + 60); // a packet from a1…
    put(0x05, p, 32);      // an empty packet
    uint8_t ping[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    put(0x12, ping, 8);
    put(0x13, ping, 8);
    memset(p, 0xb2, 33);
    put(0x08, p, 32); // peer gone, no reason byte
    p[32] = 0x01;
    put(0x08, p, 33); // not here
    memset(p, 0xc3, 32);
    put(0x09, p, 32); // present, an old server's: the key only
    memset(p + 32, 0, 18);
    p[32 + 10] = 0xff;
    p[32 + 11] = 0xff;
    p[32 + 12] = 192;
    p[32 + 13] = 0;
    p[32 + 14] = 2;
    p[32 + 15] = 3;
    p[32 + 16] = 0x1f;
    p[32 + 17] = 0x90;
    put(0x09, p, 50); // with the address
    p[50] = 0x01;
    put(0x09, p, 51); // and flags
    p[51] = 5;
    memcpy(p + 52, "myapp", 5);
    put(0x09, p, 57); // and an app name
    p[51] = 9;
    put(0x09, p, 57); // a name longer than what's left: dropped, the rest kept
    p[51] = 2;
    p[52] = 0x07;
    put(0x09, p, 57); // a name that isn't printable: dropped
    put(0x14, (const uint8_t *)"duplicate", 9);
    put(0x14, NULL, 0); // healthy again
    uint8_t rs[8] = {0, 0, 0x03, 0xe8, 0, 0, 0x13, 0x88};
    put(0x15, rs, 8);
    put(0x31, p, 10); // an unknown type: skipped
    put(0x01, p, 40); // a second server key: skipped, as Recv's default case does
    // Short frames Recv drops, the connection staying up.
    put(0x08, p, 31);
    put(0x09, p, 31);
    put(0x05, p, 31);
    put(0x12, p, 7);
    put(0x13, p, 7);
    put(0x15, p, 7);
    // A frame bigger than the buffer: skipped, and the stream goes on.
    memset(p, 0xd4, sizeof p);
    put(0x05, p, 5000);
    put(0x12, ping, 8);
}

static const char WANT[] =
    "key %02x%02x;info 1000/2000;keepalive;packet from a1 len 60 first 45;packet from a1 len 0 first 00;ping 0108;"
    "pong 0108;gone b2 reason 0;gone b2 reason 1;present c3 addr 0 0.0.0.0:0 flags 0 0 name '';"
    "present c3 addr 1 192.0.2.3:8080 flags 0 0 name '';present c3 addr 1 192.0.2.3:8080 flags 1 1 name '';"
    "present c3 addr 1 192.0.2.3:8080 flags 1 1 name 'myapp';present c3 addr 1 192.0.2.3:8080 flags 1 1 name '';"
    "present c3 addr 1 192.0.2.3:8080 flags 1 1 name '';health 'duplicate';health '';restarting 1000 5000;ping 0108;";

static void frames(void)
{
    build_good_stream();
    char want[sizeof WANT + 8];
    snprintf(want, sizeof want, WANT, server_pub[0], server_pub[31]);
    static tsnet_derp_t d;
    for (size_t split = 1; split <= stream_len; split++) {
        int r = feed_all(&d, stream, stream_len, split);
        if (r != 0 || strcmp(seen, want) != 0) {
            printf("split %zu: r %d, saw\n  %s\nwant\n  %s\n", split, r, seen, want);
            failures++;
            break;
        }
    }
    EXPECT(memcmp(d.server_key, server_pub, 32) == 0);
}

static void client_info(void)
{
    static tsnet_derp_t d;
    stream_len = 0;
    put_greeting(0);
    uint8_t out[256], nonce[24];
    EXPECT(tsnet_derp_init(&d, client_priv) == 0);
    EXPECT(tsnet_derp_client_info(&d, out, sizeof out, nonce) == -1); // not before the greeting
    EXPECT(feed_all(&d, stream, stream_len, stream_len) == 0);
    for (int i = 0; i < 24; i++) {
        nonce[i] = (uint8_t)(0x90 + i);
    }
    static const char JSON[] = "{\"version\":2,\"CanAckPings\":true}";
    size_t json_len = sizeof JSON - 1;
    int n = tsnet_derp_client_info(&d, out, sizeof out, nonce);
    EXPECT(n == (int)(5 + 32 + 24 + 16 + json_len));
    EXPECT(tsnet_derp_client_info(&d, out, (size_t)n - 1, nonce) == -1);
    // The server's side (derpserver recvClientKey): the key, then a box it opens from that key.
    EXPECT(out[0] == 0x02 && out[1] == 0 && out[2] == 0 && out[3] == 0 && out[4] == n - 5);
    EXPECT(memcmp(out + 5, client_pub, 32) == 0);
    EXPECT(memcmp(out + 37, nonce, 24) == 0);
    uint8_t shared[32], plain[64];
    EXPECT(tsnet_box_shared(shared, server_priv, client_pub) == 0);
    EXPECT(tsnet_box_open(plain, shared, nonce, out + 61, 16 + json_len) == 0);
    EXPECT(memcmp(plain, JSON, json_len) == 0);
}

static void fatal(const char *what, int r)
{
    if (r != -1) {
        printf("%s: expected the connection to fail\n", what);
        failures++;
    }
}

static void failures_end_it(void)
{
    static tsnet_derp_t d;
    uint8_t p[64] = {0};
    // The greeting.
    stream_len = 0;
    put(0x03, p, 40);
    fatal("a first frame that isn't the server key", feed_all(&d, stream, stream_len, 1));
    stream_len = 0;
    put_greeting(0);
    stream[5] ^= 1;
    fatal("a wrong magic", feed_all(&d, stream, stream_len, 1));
    stream_len = 0;
    memcpy(p, MAGIC, 8);
    put(0x01, p, 39);
    fatal("a short greeting", feed_all(&d, stream, stream_len, 1));
    uint8_t big[5] = {0x01, 0, 0, 0x04, 0x01}; // 1025 bytes
    fatal("a greeting over 1 KB", feed_all(&d, big, sizeof big, 5));
    stream_len = 0;
    memset(p + 8, 0, 32);
    put(0x01, p, 40);
    fatal("a low-order server key", feed_all(&d, stream, stream_len, 7));
    // ServerInfo.
    const char *bad_json[] = {"{\"version\":2", "[1]", "{\"version\":\"2\"}", "{\"TokenBucketBytesPerSecond\":1.5}", "7"};
    for (size_t i = 0; i < sizeof bad_json / sizeof bad_json[0]; i++) {
        stream_len = 0;
        put_greeting(0);
        put_server_info(bad_json[i], 0);
        fatal(bad_json[i], feed_all(&d, stream, stream_len, 3));
    }
    stream_len = 0;
    put_greeting(0);
    put_server_info("{}", 1);
    fatal("a server info box that doesn't open", feed_all(&d, stream, stream_len, 3));
    stream_len = 0;
    put_greeting(0);
    put(0x03, p, 39);
    fatal("a short server info", feed_all(&d, stream, stream_len, 3));
    stream_len = 0;
    put_greeting(0);
    put_server_info("null", 0); // json.Unmarshal takes null
    EXPECT(feed_all(&d, stream, stream_len, 3) == 0);
    // A frame over 1 MB, after the greeting; and every feed after a failure fails.
    stream_len = 0;
    put_greeting(0);
    uint8_t huge[5] = {0x05, 0, 0x10, 0, 0x01};
    memcpy(stream + stream_len, huge, 5);
    stream_len += 5;
    fatal("a frame over 1 MB", feed_all(&d, stream, stream_len, 4));
    uint8_t ka[5] = {0x06, 0, 0, 0, 0};
    fatal("a feed after a failure", tsnet_derp_feed(&d, ka, 5, on_msg, NULL));
    // Exactly 1 MB is allowed (and skipped, being bigger than the buffer).
    stream_len = 0;
    put_greeting(0);
    uint8_t mb[5] = {0x05, 0, 0x10, 0, 0};
    EXPECT(feed_all(&d, stream, stream_len, stream_len) == 0);
    EXPECT(tsnet_derp_feed(&d, mb, 5, on_msg, NULL) == 0);
    uint8_t *zeros = calloc(1, 1 << 20);
    EXPECT(zeros && tsnet_derp_feed(&d, zeros, 1 << 20, on_msg, NULL) == 0);
    free(zeros);
    seen_len = 0;
    EXPECT(tsnet_derp_feed(&d, ka, 5, on_msg, NULL) == 0);
    EXPECT(strcmp(seen, "keepalive;") == 0);
}

static void writers(void)
{
    uint8_t out[128], dst[32], pkt[40];
    memset(dst, 0xee, sizeof dst);
    memset(pkt, 0x77, sizeof pkt);
    EXPECT(tsnet_derp_send_packet(out, sizeof out, dst, pkt, 40) == 77);
    EXPECT(out[0] == 0x04 && out[4] == 72 && out[5] == 0xee && out[36] == 0xee && out[37] == 0x77 && out[76] == 0x77);
    EXPECT(tsnet_derp_send_packet(out, 76, dst, pkt, 40) == -1);
    static uint8_t big[(64 << 10) + 64], src[(64 << 10) + 1];
    EXPECT(tsnet_derp_send_packet(big, sizeof big, dst, src, 64 << 10) == 5 + 32 + (64 << 10));
    EXPECT(tsnet_derp_send_packet(big, sizeof big, dst, src, (64 << 10) + 1) == -1); // MaxPacketSize
    uint8_t data[8] = {9, 8, 7, 6, 5, 4, 3, 2};
    EXPECT(tsnet_derp_ping(out, sizeof out, data) == 13 && out[0] == 0x12 && out[4] == 8 && out[5] == 9 && out[12] == 2);
    EXPECT(tsnet_derp_pong(out, sizeof out, data) == 13 && out[0] == 0x13);
    EXPECT(tsnet_derp_pong(out, 12, data) == -1);
    EXPECT(tsnet_derp_note_preferred(out, sizeof out, true) == 6 && out[0] == 0x07 && out[4] == 1 && out[5] == 1);
    EXPECT(tsnet_derp_note_preferred(out, sizeof out, false) == 6 && out[5] == 0);
}

// Changed bytes anywhere in a good stream: whatever happens, nothing reads out of bounds (ASan), and a failure sticks.
static void flipped(void)
{
    build_good_stream();
    static uint8_t copy[sizeof stream];
    static tsnet_derp_t d;
    srand(1918);
    for (int round = 0; round < 3000; round++) {
        memcpy(copy, stream, stream_len);
        for (int k = 0; k < 1 + round % 4; k++) {
            copy[(size_t)rand() % stream_len] ^= (uint8_t)(1 + rand() % 255);
        }
        int r = feed_all(&d, copy, stream_len, 1 + (size_t)rand() % 64);
        EXPECT(r == 0 || d.failed);
    }
}

int main(void)
{
    for (int i = 0; i < 32; i++) {
        client_priv[i] = (uint8_t)(i * 7 + 1);
        server_priv[i] = (uint8_t)(i * 13 + 5);
    }
    tsnet_x25519_public(client_pub, client_priv);
    tsnet_x25519_public(server_pub, server_priv);
    tsnet_box_shared(server_shared, server_priv, client_pub);
    frames();
    client_info();
    failures_end_it();
    writers();
    flipped();
    if (failures == 0) {
        printf("tsnet derp_test: ok\n");
    }
    return failures != 0;
}
