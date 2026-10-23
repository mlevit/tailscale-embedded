// Disco. See disco.h; the Go is disco/disco.go and magicsock's sendDiscoMessage and handleDiscoMessage.
#include "disco.h"
#include <string.h>

static const uint8_t MAGIC[TSNET_DISCO_MAGIC_LEN] = {0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac}; // "TS" and U+1F4AC
#define EP_LEN 18                                                                            // 16-byte IP, 2-byte port
#define PONG_LEN (12 + 16 + 2)

bool tsnet_disco_looks_like(const uint8_t *pkt, size_t len)
{
    return len >= TSNET_DISCO_WRAPPER_LEN && memcmp(pkt, MAGIC, sizeof MAGIC) == 0;
}

const uint8_t *tsnet_disco_source(const uint8_t *pkt)
{
    return pkt + TSNET_DISCO_MAGIC_LEN;
}

static bool all_zero(const uint8_t *p, size_t n)
{
    uint8_t any = 0;
    for (size_t i = 0; i < n; i++) {
        any |= p[i];
    }
    return any == 0;
}

int tsnet_disco_parse(const uint8_t *p, size_t len, tsnet_disco_msg_t *m)
{
    memset(m, 0, sizeof *m);
    if (len < 2) {
        return -1; // errShort
    }
    uint8_t type = p[0], ver = p[1];
    p += 2;
    len -= 2;
    m->type = type;
    switch (type) {
    case TSNET_DISCO_PING:
        if (len < TSNET_DISCO_TXID_LEN) {
            return -1;
        }
        memcpy(m->txid, p, TSNET_DISCO_TXID_LEN);
        m->padding = len - TSNET_DISCO_TXID_LEN;
        // Lax on longer messages, for the future. Trailing zeros are padding, not a node key (AppendMarshal omits a zero
        // key).
        if (len - TSNET_DISCO_TXID_LEN >= TSNET_KEY_LEN && !all_zero(p + TSNET_DISCO_TXID_LEN, TSNET_KEY_LEN)) {
            memcpy(m->node_key, p + TSNET_DISCO_TXID_LEN, TSNET_KEY_LEN);
            m->has_node_key = true;
            m->padding -= TSNET_KEY_LEN;
        }
        return 0;
    case TSNET_DISCO_PONG:
        if (len < PONG_LEN) {
            return -1;
        }
        memcpy(m->txid, p, TSNET_DISCO_TXID_LEN);
        memcpy(m->src_ip, p + 12, 16);
        m->src_port = (uint16_t)(p[28] << 8 | p[29]);
        return 0;
    case TSNET_DISCO_CALL_ME_MAYBE:
        // A version, or a length, it doesn't understand: no endpoints (not an error).
        if (len % EP_LEN != 0 || ver != 0 || len == 0) {
            return 0;
        }
        for (size_t at = 0; at < len && m->n_eps < TSNET_DISCO_EPS; at += EP_LEN) {
            memcpy(m->eps[m->n_eps].ip, p + at, 16);
            m->eps[m->n_eps].port = (uint16_t)(p[at + 16] << 8 | p[at + 17]);
            m->n_eps++;
        }
        return 0;
    case 0x04: // the UDP relay messages: recognised, not decoded (no peer relays yet)
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
        return 0;
    default:
        return -1; // unknown message type
    }
}

static int header(uint8_t *out, size_t cap, uint8_t type, size_t data_len)
{
    if (cap < 2 + data_len) {
        return -1;
    }
    out[0] = type;
    out[1] = 0; // v0
    memset(out + 2, 0, data_len);
    return (int)(2 + data_len);
}

int tsnet_disco_ping(uint8_t *out, size_t cap, const uint8_t txid[TSNET_DISCO_TXID_LEN],
                     const uint8_t node_key[TSNET_KEY_LEN], size_t padding)
{
    bool has_key = node_key && !all_zero(node_key, TSNET_KEY_LEN);
    int n = header(out, cap, TSNET_DISCO_PING, TSNET_DISCO_TXID_LEN + (has_key ? TSNET_KEY_LEN : 0) + padding);
    if (n > 0) {
        memcpy(out + 2, txid, TSNET_DISCO_TXID_LEN);
        if (has_key) {
            memcpy(out + 2 + TSNET_DISCO_TXID_LEN, node_key, TSNET_KEY_LEN);
        }
    }
    return n;
}

int tsnet_disco_pong(uint8_t *out, size_t cap, const uint8_t txid[TSNET_DISCO_TXID_LEN], const uint8_t ip[16],
                     uint16_t port)
{
    int n = header(out, cap, TSNET_DISCO_PONG, PONG_LEN);
    if (n > 0) {
        memcpy(out + 2, txid, TSNET_DISCO_TXID_LEN);
        memcpy(out + 14, ip, 16);
        out[30] = (uint8_t)(port >> 8);
        out[31] = (uint8_t)port;
    }
    return n;
}

int tsnet_disco_call_me_maybe(uint8_t *out, size_t cap, const tsnet_disco_ep_t *eps, size_t n_eps)
{
    int n = header(out, cap, TSNET_DISCO_CALL_ME_MAYBE, EP_LEN * n_eps);
    for (size_t i = 0; n > 0 && i < n_eps; i++) {
        uint8_t *p = out + 2 + i * EP_LEN;
        memcpy(p, eps[i].ip, 16);
        p[16] = (uint8_t)(eps[i].port >> 8);
        p[17] = (uint8_t)eps[i].port;
    }
    return n;
}

int tsnet_disco_seal(uint8_t *out, size_t cap, const uint8_t my_disco_pub[TSNET_KEY_LEN],
                     const uint8_t shared[TSNET_KEY_LEN], const uint8_t nonce[TSNET_BOX_NONCE_LEN], const uint8_t *msg,
                     size_t len)
{
    size_t total = TSNET_DISCO_WRAPPER_LEN + TSNET_BOX_TAG_LEN + len;
    if (cap < total) {
        return -1;
    }
    memcpy(out, MAGIC, sizeof MAGIC);
    memcpy(out + TSNET_DISCO_MAGIC_LEN, my_disco_pub, TSNET_KEY_LEN);
    memcpy(out + TSNET_DISCO_MAGIC_LEN + TSNET_KEY_LEN, nonce, TSNET_BOX_NONCE_LEN); // key.DiscoShared.Seal: the nonce
    if (tsnet_box_seal(out + TSNET_DISCO_WRAPPER_LEN, shared, nonce, msg, len) != 0) {
        return -1;
    }
    return (int)total;
}

int tsnet_disco_open(const uint8_t *pkt, size_t len, const uint8_t shared[TSNET_KEY_LEN], uint8_t *out, size_t cap)
{
    if (!tsnet_disco_looks_like(pkt, len) || len < TSNET_DISCO_WRAPPER_LEN + TSNET_BOX_TAG_LEN) {
        return -1;
    }
    size_t n = len - TSNET_DISCO_WRAPPER_LEN - TSNET_BOX_TAG_LEN;
    if (cap < n) {
        return -1;
    }
    const uint8_t *nonce = pkt + TSNET_DISCO_MAGIC_LEN + TSNET_KEY_LEN;
    if (tsnet_box_open(out, shared, nonce, pkt + TSNET_DISCO_WRAPPER_LEN, len - TSNET_DISCO_WRAPPER_LEN) != 0) {
        return -1;
    }
    return (int)n;
}
