// DERP's frame protocol, the client side. See derp.h.
#include "derp.h"
#include <math.h>
#include <string.h>
#include "cJSON.h"
#include "json.h"
#include "platform.h"

// Magic: "DERP" and the key emoji, U+1F511 in UTF-8.
static const uint8_t MAGIC[8] = {0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91};

static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

int tsnet_derp_init(tsnet_derp_t *d, const uint8_t priv[TSNET_KEY_LEN])
{
    memset(d, 0, sizeof *d);
    memcpy(d->priv, priv, TSNET_KEY_LEN);
    return tsnet_x25519_public(d->pub, d->priv);
}

void tsnet_derp_wipe(tsnet_derp_t *d)
{
    tsnet_wipe(d->priv, sizeof d->priv);
    tsnet_wipe(d->shared, sizeof d->shared);
}

static int fail(tsnet_derp_t *d, const char *why)
{
    tsnet_log(TSNET_LOG_WARN, "derp: %s", why);
    d->failed = true;
    return -1;
}

// recvServerKey: the magic, then the server's public key, then maybe more (allowed, for the future).
static int greeting(tsnet_derp_t *d, uint8_t type, tsnet_derp_cb_t cb, void *ctx)
{
    if (type != TSNET_DERP_FRAME_SERVER_KEY || d->len < sizeof MAGIC + TSNET_KEY_LEN ||
        memcmp(d->buf, MAGIC, sizeof MAGIC) != 0) {
        return fail(d, "invalid server greeting");
    }
    memcpy(d->server_key, d->buf + sizeof MAGIC, TSNET_KEY_LEN);
    if (tsnet_box_shared(d->shared, d->priv, d->server_key) != 0) {
        return fail(d, "unusable server key");
    }
    d->greeted = true;
    tsnet_derp_msg_t m = {.type = TSNET_DERP_SERVER_KEY};
    memcpy(m.key, d->server_key, TSNET_KEY_LEN);
    cb(ctx, &m);
    return 0;
}

// A JSON int field as Go's json.Unmarshal fills one: absent is 0, and anything but an integer is an error.
static int json_int(const cJSON *root, const char *name, int64_t *out)
{
    const cJSON *v = cJSON_GetObjectItem(root, name); // case-insensitive, as encoding/json matches field names
    if (!v || cJSON_IsNull(v)) {
        return 0;
    }
    if (!cJSON_IsNumber(v) || v->valuedouble != floor(v->valuedouble) || fabs(v->valuedouble) > 9.2e18) {
        return -1;
    }
    *out = (int64_t)v->valuedouble;
    return 0;
}

// parseServerInfo: a 24-byte nonce, then a box of JSON from the server's key.
static int server_info(tsnet_derp_t *d, tsnet_derp_cb_t cb, void *ctx)
{
    if (d->len < TSNET_BOX_NONCE_LEN + TSNET_BOX_TAG_LEN) {
        return fail(d, "invalid server info frame: short");
    }
    // Opened in place: the JSON lands at the start of the buffer.
    uint8_t nonce[TSNET_BOX_NONCE_LEN];
    memcpy(nonce, d->buf, sizeof nonce);
    size_t n = d->len - TSNET_BOX_NONCE_LEN - TSNET_BOX_TAG_LEN;
    if (tsnet_box_open(d->buf, d->shared, nonce, d->buf + TSNET_BOX_NONCE_LEN, d->len - TSNET_BOX_NONCE_LEN) != 0) {
        return fail(d, "invalid server info frame: failed to open naclbox from server key");
    }
    tsnet_derp_msg_t m = {.type = TSNET_DERP_SERVER_INFO};
    cJSON *root = tsnet_json_parse((const char *)d->buf, n);
    int ok = root && (cJSON_IsObject(root) || cJSON_IsNull(root)) &&
             json_int(root, "TokenBucketBytesPerSecond", &m.bytes_per_second) == 0 &&
             json_int(root, "TokenBucketBytesBurst", &m.bytes_burst) == 0;
    int64_t version = 0;
    ok = ok && json_int(root, "version", &version) == 0;
    cJSON_Delete(root);
    if (!ok) {
        return fail(d, "invalid server info frame: invalid JSON");
    }
    cb(ctx, &m);
    return 0;
}

// ValidAppName: at most 32 bytes of printable ASCII.
static bool valid_app_name(const uint8_t *s, size_t n)
{
    if (n > 32) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (s[i] < ' ' || s[i] > '~') {
            return false;
        }
    }
    return true;
}

// The cases of Recv's switch, after the greeting.
static int dispatch(tsnet_derp_t *d, uint8_t type, tsnet_derp_cb_t cb, void *ctx)
{
    const uint8_t *b = d->buf;
    uint32_t n = d->len;
    tsnet_derp_msg_t m;
    memset(&m, 0, sizeof m);
    switch (type) {
    case TSNET_DERP_FRAME_SERVER_INFO:
        return server_info(d, cb, ctx);
    case TSNET_DERP_FRAME_KEEP_ALIVE:
        m.type = TSNET_DERP_KEEP_ALIVE;
        break;
    case TSNET_DERP_FRAME_PEER_GONE:
        if (n < TSNET_KEY_LEN) {
            tsnet_log(TSNET_LOG_WARN, "derp: [unexpected] dropping short peerGone frame from DERP server");
            return 0;
        }
        m.type = TSNET_DERP_PEER_GONE;
        memcpy(m.key, b, TSNET_KEY_LEN);
        m.reason = n > TSNET_KEY_LEN ? b[TSNET_KEY_LEN] : TSNET_DERP_GONE_DISCONNECTED;
        break;
    case TSNET_DERP_FRAME_PEER_PRESENT: {
        if (n < TSNET_KEY_LEN) {
            tsnet_log(TSNET_LOG_WARN, "derp: [unexpected] dropping short peerPresent frame from DERP server");
            return 0;
        }
        m.type = TSNET_DERP_PEER_PRESENT;
        memcpy(m.key, b, TSNET_KEY_LEN);
        uint32_t at = TSNET_KEY_LEN;
        if (n - at >= 18) { // an older server didn't send the address, the flags or the app name
            memcpy(m.ip, b + at, 16);
            m.port = (uint16_t)(b[at + 16] << 8 | b[at + 17]);
            m.has_addr = true;
            at += 18;
            if (n - at >= 1) {
                m.flags = b[at++];
                m.has_flags = true;
                if (n - at >= 1) {
                    uint32_t name_len = b[at++];
                    if (n - at < name_len) {
                        tsnet_log(TSNET_LOG_WARN, "derp: [unexpected] short peerPresent app name from DERP server");
                    } else if (valid_app_name(b + at, name_len)) {
                        memcpy(m.app_name, b + at, name_len);
                    }
                }
            }
        }
        break;
    }
    case TSNET_DERP_FRAME_RECV_PACKET:
        if (n < TSNET_KEY_LEN) {
            tsnet_log(TSNET_LOG_WARN, "derp: [unexpected] dropping short packet from DERP server");
            return 0;
        }
        m.type = TSNET_DERP_PACKET;
        memcpy(m.key, b, TSNET_KEY_LEN);
        m.data = b + TSNET_KEY_LEN;
        m.len = n - TSNET_KEY_LEN;
        break;
    case TSNET_DERP_FRAME_PING:
    case TSNET_DERP_FRAME_PONG:
        if (n < 8) {
            tsnet_log(TSNET_LOG_WARN, "derp: [unexpected] dropping short ping frame");
            return 0;
        }
        m.type = type == TSNET_DERP_FRAME_PING ? TSNET_DERP_PING : TSNET_DERP_PONG;
        memcpy(m.ping, b, 8);
        break;
    case TSNET_DERP_FRAME_HEALTH:
        m.type = TSNET_DERP_HEALTH;
        m.data = b;
        m.len = n;
        break;
    case TSNET_DERP_FRAME_RESTARTING:
        if (n < 8) {
            tsnet_log(TSNET_LOG_WARN, "derp: [unexpected] dropping short server restarting frame");
            return 0;
        }
        m.type = TSNET_DERP_RESTARTING;
        m.reconnect_in_ms = be32(b);
        m.try_for_ms = be32(b + 4);
        break;
    default:
        return 0; // a type this client doesn't know, or one meant for servers
    }
    cb(ctx, &m);
    return 0;
}

int tsnet_derp_feed(tsnet_derp_t *d, const uint8_t *data, size_t len, tsnet_derp_cb_t cb, void *ctx)
{
    if (d->failed) {
        return -1;
    }
    while (len > 0) {
        if (d->hdr_len < TSNET_DERP_HEADER_LEN) {
            size_t take = TSNET_DERP_HEADER_LEN - d->hdr_len;
            take = take < len ? take : len;
            memcpy(d->hdr + d->hdr_len, data, take);
            d->hdr_len += take;
            data += take;
            len -= take;
            if (d->hdr_len < TSNET_DERP_HEADER_LEN) {
                break;
            }
            d->len = be32(d->hdr + 1);
            d->got = 0;
            if (d->len > (d->greeted ? TSNET_DERP_MAX_FRAME : TSNET_DERP_MAX_GREETING)) {
                return fail(d, d->greeted ? "unexpectedly large frame" : "invalid server greeting: too large");
            }
        }
        // The payload, kept up to the buffer's size (the rest of a bigger frame is read past).
        size_t take = d->len - d->got;
        take = take < len ? take : len;
        if (d->got < TSNET_DERP_BUF) {
            size_t keep = TSNET_DERP_BUF - d->got;
            memcpy(d->buf + d->got, data, keep < take ? keep : take);
        }
        d->got += (uint32_t)take;
        data += take;
        len -= take;
        if (d->got < d->len) {
            break;
        }
        uint8_t type = d->hdr[0];
        d->hdr_len = 0;
        int r;
        if (!d->greeted) {
            r = greeting(d, type, cb, ctx);
        } else if (d->len > TSNET_DERP_BUF) {
            tsnet_log(TSNET_LOG_WARN, "derp: skipped a frame of type 0x%02x and %u bytes", type, (unsigned)d->len);
            r = 0;
        } else {
            r = dispatch(d, type, cb, ctx);
        }
        if (r != 0) {
            return -1;
        }
    }
    return 0;
}

static int frame(uint8_t *out, size_t cap, uint8_t type, size_t len)
{
    if (cap < TSNET_DERP_HEADER_LEN + len) {
        return -1;
    }
    out[0] = type;
    out[1] = (uint8_t)(len >> 24);
    out[2] = (uint8_t)(len >> 16);
    out[3] = (uint8_t)(len >> 8);
    out[4] = (uint8_t)len;
    return TSNET_DERP_HEADER_LEN + (int)len;
}

int tsnet_derp_client_info(const tsnet_derp_t *d, uint8_t *out, size_t cap, const uint8_t nonce[TSNET_BOX_NONCE_LEN])
{
    // ClientInfo as json.Marshal writes it, with what magicsock sets (SetCanAckPings(true), no mesh key or app name).
    static const char JSON[] = "{\"version\":2,\"CanAckPings\":true}";
    size_t json_len = sizeof JSON - 1;
    size_t len = TSNET_KEY_LEN + TSNET_BOX_NONCE_LEN + TSNET_BOX_TAG_LEN + json_len;
    int n = d->greeted ? frame(out, cap, TSNET_DERP_FRAME_CLIENT_INFO, len) : -1;
    if (n < 0) {
        return -1;
    }
    uint8_t *p = out + TSNET_DERP_HEADER_LEN;
    memcpy(p, d->pub, TSNET_KEY_LEN);
    memcpy(p + TSNET_KEY_LEN, nonce, TSNET_BOX_NONCE_LEN);
    if (tsnet_box_seal(p + TSNET_KEY_LEN + TSNET_BOX_NONCE_LEN, d->shared, nonce, (const uint8_t *)JSON, json_len) != 0) {
        return -1;
    }
    return n;
}

int tsnet_derp_send_packet(uint8_t *out, size_t cap, const uint8_t dst[TSNET_KEY_LEN], const uint8_t *pkt, size_t len)
{
    int n = len <= TSNET_DERP_MAX_PACKET ? frame(out, cap, TSNET_DERP_FRAME_SEND_PACKET, TSNET_KEY_LEN + len) : -1;
    if (n > 0) {
        memcpy(out + TSNET_DERP_HEADER_LEN, dst, TSNET_KEY_LEN);
        memcpy(out + TSNET_DERP_HEADER_LEN + TSNET_KEY_LEN, pkt, len);
    }
    return n;
}

static int eight(uint8_t *out, size_t cap, uint8_t type, const uint8_t data[8])
{
    int n = frame(out, cap, type, 8);
    if (n > 0) {
        memcpy(out + TSNET_DERP_HEADER_LEN, data, 8);
    }
    return n;
}

int tsnet_derp_ping(uint8_t *out, size_t cap, const uint8_t data[8])
{
    return eight(out, cap, TSNET_DERP_FRAME_PING, data);
}

int tsnet_derp_pong(uint8_t *out, size_t cap, const uint8_t data[8])
{
    return eight(out, cap, TSNET_DERP_FRAME_PONG, data);
}

int tsnet_derp_note_preferred(uint8_t *out, size_t cap, bool preferred)
{
    int n = frame(out, cap, TSNET_DERP_FRAME_NOTE_PREFERRED, 1);
    if (n > 0) {
        out[TSNET_DERP_HEADER_LEN] = preferred ? 0x01 : 0x00;
    }
    return n;
}
