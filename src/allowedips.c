// AllowedIPs. See allowedips.h; the Go is wireguard-go's device/allowedips.go.
#include "platform.h"
#include "allowedips.h"
#include <stdlib.h>
#include <string.h>

void tsnet_aips_init(tsnet_aips_t *t)
{
    memset(t, 0, sizeof *t);
}

void tsnet_aips_free(tsnet_aips_t *t)
{
    free(t->e);
    memset(t, 0, sizeof *t);
}

static void mask(uint8_t out[16], const uint8_t *ip, size_t len, uint8_t bits)
{
    memset(out, 0, 16);
    for (size_t i = 0; i < len; i++) {
        int keep = (int)bits - (int)(8 * i);
        uint8_t m = keep >= 8 ? 0xff : keep <= 0 ? 0 : (uint8_t)(0xff << (8 - keep));
        out[i] = ip[i] & m;
    }
}

// The prefix holds the address: the first `bits` bits agree.
static bool holds(const tsnet_aip_t *e, const uint8_t *ip, bool is6)
{
    if (e->is6 != is6) {
        return false;
    }
    uint8_t m[16];
    mask(m, ip, is6 ? 16 : 4, e->bits);
    return memcmp(m, e->ip, is6 ? 16 : 4) == 0;
}

int tsnet_aips_insert(tsnet_aips_t *t, const uint8_t *ip, bool is6, uint8_t bits, const uint8_t peer[32])
{
    if (bits > (is6 ? 128 : 32)) {
        return -1;
    }
    uint8_t m[16];
    mask(m, ip, is6 ? 16 : 4, bits);
    for (size_t i = 0; i < t->n; i++) {
        if (t->e[i].is6 == is6 && t->e[i].bits == bits && memcmp(t->e[i].ip, m, 16) == 0) {
            memcpy(t->e[i].peer, peer, 32); // the prefix moves to this peer
            return 0;
        }
    }
    if (t->n == t->cap) {
        size_t cap = t->cap ? 2 * t->cap : 8;
        tsnet_aip_t *e = tsnet_realloc(t->e, cap * sizeof *e);
        if (!e) {
            return -1;
        }
        t->e = e;
        t->cap = cap;
    }
    tsnet_aip_t *e = &t->e[t->n++];
    memcpy(e->ip, m, 16);
    e->is6 = is6;
    e->bits = bits;
    memcpy(e->peer, peer, 32);
    return 0;
}

void tsnet_aips_remove_peer(tsnet_aips_t *t, const uint8_t peer[32])
{
    size_t k = 0;
    for (size_t i = 0; i < t->n; i++) {
        if (memcmp(t->e[i].peer, peer, 32) != 0) {
            t->e[k++] = t->e[i];
        }
    }
    t->n = k;
}

const uint8_t *tsnet_aips_lookup(const tsnet_aips_t *t, const uint8_t *ip, bool is6)
{
    const tsnet_aip_t *best = NULL;
    for (size_t i = 0; i < t->n; i++) {
        if (holds(&t->e[i], ip, is6) && (!best || t->e[i].bits > best->bits)) {
            best = &t->e[i];
        }
    }
    return best ? best->peer : NULL;
}

// RoutineSequentialReceiver: `allowedips.Lookup(src) != peer` drops the packet. The longest match decides, so a peer
// holding a wide prefix (an exit node's /0) can't claim an address another peer holds more narrowly.
bool tsnet_aips_allowed(const tsnet_aips_t *t, const uint8_t peer[32], const uint8_t *ip, bool is6)
{
    const uint8_t *owner = tsnet_aips_lookup(t, ip, is6);
    return owner && memcmp(owner, peer, 32) == 0;
}
