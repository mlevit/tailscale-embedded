// STUN. See stun.h; the Go is net/stun/stun.go.
#include "stun.h"
#include <string.h>

#define ATTR_SOFTWARE 0x8022
#define ATTR_FINGERPRINT 0x8028
#define ATTR_MAPPED_ADDRESS 0x0001
#define ATTR_XOR_MAPPED_ADDRESS 0x0020
#define ATTR_XOR_MAPPED_ADDRESS_ALT 0x8020 // not in the RFC, but servers send it
#define LEN_FINGERPRINT 8

static const uint8_t COOKIE[4] = {0x21, 0x12, 0xa4, 0x42};
static const char SOFTWARE[8] = {'t', 'a', 'i', 'l', 'n', 'o', 'd', 'e'}; // 8 bytes, so no padding

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

// CRC-32 (IEEE, as Go's crc32.ChecksumIEEE), bit by bit: it runs over 32 bytes per request.
static uint32_t crc32_ieee(const uint8_t *p, size_t n)
{
    uint32_t crc = 0xffffffffu;
    while (n--) {
        crc ^= *p++;
        for (int k = 0; k < 8; k++) {
            crc = crc >> 1 ^ (0xedb88320u & (0u - (crc & 1)));
        }
    }
    return ~crc;
}

static uint32_t fingerprint(const uint8_t *b, size_t n)
{
    return crc32_ieee(b, n) ^ 0x5354554eu;
}

void tsnet_stun_request(uint8_t out[TSNET_STUN_REQUEST_LEN], const uint8_t txid[TSNET_STUN_TXID_LEN])
{
    // The header (RFC 5389 section 6), SOFTWARE and FINGERPRINT (section 15.5).
    out[0] = 0x00;
    out[1] = 0x01; // binding request
    put16(out + 2, 4 + sizeof SOFTWARE + LEN_FINGERPRINT);
    memcpy(out + 4, COOKIE, 4);
    memcpy(out + 8, txid, TSNET_STUN_TXID_LEN);
    put16(out + 20, ATTR_SOFTWARE);
    put16(out + 22, sizeof SOFTWARE);
    memcpy(out + 24, SOFTWARE, sizeof SOFTWARE);
    uint32_t fp = fingerprint(out, 32);
    put16(out + 32, ATTR_FINGERPRINT);
    put16(out + 34, 4);
    out[36] = (uint8_t)(fp >> 24);
    out[37] = (uint8_t)(fp >> 16);
    out[38] = (uint8_t)(fp >> 8);
    out[39] = (uint8_t)fp;
}

bool tsnet_stun_is(const uint8_t *b, size_t len)
{
    return len >= TSNET_STUN_HEADER_LEN && (b[0] & 0xc0) == 0 && memcmp(b + 4, COOKIE, 4) == 0;
}

typedef int (*attr_fn)(void *ctx, uint16_t type, const uint8_t *a, size_t len);

// foreachAttr: each attribute, its value without the padding to 4 bytes.
static int foreach_attr(const uint8_t *b, size_t len, attr_fn fn, void *ctx)
{
    while (len > 0) {
        if (len < 4) {
            return TSNET_STUN_MALFORMED;
        }
        uint16_t type = be16(b), alen = be16(b + 2);
        size_t padded = ((size_t)alen + 3) & ~(size_t)3;
        b += 4;
        len -= 4;
        if (padded > len) {
            return TSNET_STUN_MALFORMED;
        }
        int r = fn(ctx, type, b, alen);
        if (r != 0) {
            return r;
        }
        b += padded;
        len -= padded;
    }
    return 0;
}

static size_t family_len(uint8_t fam)
{
    return fam == 0x01 ? 4 : fam == 0x02 ? 16 : 0;
}

// The address as 16 bytes, Unmap'd forms being one: an IPv4 address goes in as ::ffff:a.b.c.d.
static void to16(uint8_t ip[16], const uint8_t *addr, size_t n)
{
    if (n == 4) {
        memset(ip, 0, 10);
        ip[10] = ip[11] = 0xff;
        memcpy(ip + 12, addr, 4);
    } else {
        memcpy(ip, addr, 16);
    }
}

typedef struct {
    const uint8_t *txid;
    bool have, have_fallback;
    uint8_t ip[16], fb_ip[16];
    uint16_t port, fb_port;
} resp_t;

static int resp_attr(void *ctx, uint16_t type, const uint8_t *a, size_t len)
{
    resp_t *r = ctx;
    if (type == ATTR_XOR_MAPPED_ADDRESS || type == ATTR_XOR_MAPPED_ADDRESS_ALT) {
        // XOR-MAPPED-ADDRESS (RFC 5389 section 15.2): the port XORed with the cookie's top half, the address with the
        // cookie and then the transaction ID.
        if (len < 4) {
            return TSNET_STUN_MALFORMED;
        }
        size_t n = family_len(a[1]);
        if (n == 0 || len - 4 < n) {
            return TSNET_STUN_MALFORMED;
        }
        uint8_t addr[16];
        for (size_t i = 0; i < n; i++) {
            addr[i] = a[4 + i] ^ (i < 4 ? COOKIE[i] : r->txid[i - 4]);
        }
        to16(r->ip, addr, n);
        r->port = be16(a + 2) ^ 0x2112;
        r->have = true;
    } else if (type == ATTR_MAPPED_ADDRESS) {
        if (len < 4) {
            return TSNET_STUN_MALFORMED;
        }
        size_t n = family_len(a[1]);
        if (n == 0 || len - 4 < n) {
            return TSNET_STUN_MALFORMED;
        }
        to16(r->fb_ip, a + 4, n);
        r->fb_port = be16(a + 2);
        r->have_fallback = true;
    }
    return 0;
}

int tsnet_stun_parse_response(const uint8_t *b, size_t len, uint8_t txid[TSNET_STUN_TXID_LEN], uint8_t ip[16],
                              uint16_t *port)
{
    if (!tsnet_stun_is(b, len)) {
        return TSNET_STUN_NOT_STUN;
    }
    memcpy(txid, b + 8, TSNET_STUN_TXID_LEN);
    if (b[0] != 0x01 || b[1] != 0x01) {
        return TSNET_STUN_NOT_SUCCESS;
    }
    size_t attrs = be16(b + 2);
    if (attrs > len - TSNET_STUN_HEADER_LEN) {
        return TSNET_STUN_MALFORMED;
    }
    resp_t r = {.txid = txid}; // the trailing packet bytes past the attributes are trimmed
    int err = foreach_attr(b + TSNET_STUN_HEADER_LEN, attrs, resp_attr, &r);
    if (err != 0) {
        memset(txid, 0, TSNET_STUN_TXID_LEN);
        return err;
    }
    if (r.have) {
        memcpy(ip, r.ip, 16);
        *port = r.port;
        return 0;
    }
    if (r.have_fallback) {
        memcpy(ip, r.fb_ip, 16);
        *port = r.fb_port;
        return 0;
    }
    memset(txid, 0, TSNET_STUN_TXID_LEN);
    return TSNET_STUN_MALFORMED;
}

typedef struct {
    bool software_ok;
    uint16_t last;
    uint32_t fp;
} req_t;

static int req_attr(void *ctx, uint16_t type, const uint8_t *a, size_t len)
{
    req_t *r = ctx;
    r->last = type;
    if (type == ATTR_SOFTWARE && len == sizeof SOFTWARE && memcmp(a, SOFTWARE, len) == 0) {
        r->software_ok = true;
    }
    if (type == ATTR_FINGERPRINT && len == 4) {
        r->fp = (uint32_t)a[0] << 24 | (uint32_t)a[1] << 16 | (uint32_t)a[2] << 8 | a[3];
    }
    return 0;
}

int tsnet_stun_parse_binding_request(const uint8_t *b, size_t len, uint8_t txid[TSNET_STUN_TXID_LEN])
{
    if (!tsnet_stun_is(b, len)) {
        return TSNET_STUN_NOT_STUN;
    }
    if (b[0] != 0x00 || b[1] != 0x01) {
        return TSNET_STUN_NOT_BINDING_REQUEST;
    }
    req_t r = {0};
    int err = foreach_attr(b + TSNET_STUN_HEADER_LEN, len - TSNET_STUN_HEADER_LEN, req_attr, &r);
    if (err != 0) {
        return err;
    }
    if (!r.software_ok) {
        return TSNET_STUN_WRONG_SOFTWARE;
    }
    if (r.last != ATTR_FINGERPRINT) {
        return TSNET_STUN_NO_FINGERPRINT;
    }
    if (r.fp != fingerprint(b, len - LEN_FINGERPRINT)) {
        return TSNET_STUN_WRONG_FINGERPRINT;
    }
    memcpy(txid, b + 8, TSNET_STUN_TXID_LEN);
    return 0;
}

int tsnet_stun_response(uint8_t *out, size_t cap, const uint8_t txid[TSNET_STUN_TXID_LEN], const uint8_t ip[16],
                        uint16_t port)
{
    static const uint8_t MAPPED[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    bool v4 = memcmp(ip, MAPPED, 12) == 0;
    size_t n = v4 ? 4 : 16, attrs = 8 + n;
    if (cap < TSNET_STUN_HEADER_LEN + attrs) {
        return -1;
    }
    out[0] = 0x01;
    out[1] = 0x01; // success
    put16(out + 2, (uint16_t)attrs);
    memcpy(out + 4, COOKIE, 4);
    memcpy(out + 8, txid, TSNET_STUN_TXID_LEN);
    uint8_t *a = out + TSNET_STUN_HEADER_LEN;
    put16(a, ATTR_XOR_MAPPED_ADDRESS);
    put16(a + 2, (uint16_t)(4 + n));
    a[4] = 0;
    a[5] = v4 ? 1 : 2;
    put16(a + 6, port ^ 0x2112);
    const uint8_t *src = v4 ? ip + 12 : ip;
    for (size_t i = 0; i < n; i++) {
        a[8 + i] = src[i] ^ (i < 4 ? COOKIE[i] : txid[i - 4]);
    }
    return (int)(TSNET_STUN_HEADER_LEN + attrs);
}
