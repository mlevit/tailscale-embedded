// This node's own endpoints. See selfeps.h; the Go is wgengine/magicsock (determineEndpoints,
// endpointSetsEqual, endpoint_tracker.go) and net/netmon (LocalAddresses).
#include "selfeps.h"
#include <string.h>

static const uint8_t V4_MAPPED[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

static bool is4(const uint8_t ip[16])
{
    return memcmp(ip, V4_MAPPED, sizeof V4_MAPPED) == 0;
}

static bool same_ep(const tsnet_selfep_t *a, const tsnet_selfep_t *b)
{
    return a->port == b->port && a->type == b->type && memcmp(a->ip, b->ip, 16) == 0;
}

static bool same_addrport(const tsnet_selfep_t *a, const tsnet_selfep_t *b)
{
    return a->port == b->port && memcmp(a->ip, b->ip, 16) == 0;
}

size_t tsnet_tracker_update(tsnet_tracker_t *t, uint64_t now_ms, const tsnet_selfep_t *in, size_t n, tsnet_selfep_t *out,
                            size_t cap)
{
    uint64_t until = now_ms + TSNET_TRACKER_LIFETIME_MS;
    // Extend what's cached first, so nothing that would survive is removed below.
    for (size_t k = 0; k < n; k++) {
        for (int i = 0; i < TSNET_TRACKER_SLOTS; i++) {
            if (t->e[i].used && same_ep(&t->e[i].ep, &in[k])) {
                t->e[i].until = until;
            }
        }
    }
    for (int i = 0; i < TSNET_TRACKER_SLOTS; i++) {
        if (t->e[i].used && now_ms > t->e[i].until) {
            t->e[i].used = false; // expired
        }
    }
    for (size_t k = 0; k < n; k++) {
        bool found = false;
        for (int i = 0; i < TSNET_TRACKER_SLOTS && !found; i++) {
            found = t->e[i].used && same_ep(&t->e[i].ep, &in[k]);
        }
        if (found) {
            continue;
        }
        int slot = -1, oldest = -1;
        for (int i = 0; i < TSNET_TRACKER_SLOTS; i++) {
            if (!t->e[i].used) {
                slot = i;
                break;
            }
            if (oldest < 0 || t->e[i].until < t->e[oldest].until) {
                oldest = i;
            }
        }
        if (slot < 0) {
            slot = oldest; // shortcut: all slots full, the oldest goes (Go's map grows); 24 is 4 addresses' worth
        }
        t->e[slot].used = true;
        t->e[slot].ep = in[k];
        t->e[slot].until = until;
        // At most TSNET_TRACKER_PER_ADDR for one address: the oldest go.
        for (;;) {
            int count = 0, old = -1;
            for (int i = 0; i < TSNET_TRACKER_SLOTS; i++) {
                if (t->e[i].used && memcmp(t->e[i].ep.ip, in[k].ip, 16) == 0) {
                    count++;
                    if (old < 0 || t->e[i].until < t->e[old].until) {
                        old = i;
                    }
                }
            }
            if (count <= TSNET_TRACKER_PER_ADDR) {
                break;
            }
            t->e[old].used = false;
        }
    }
    size_t m = 0;
    for (size_t k = 0; k < n && m < cap; k++) {
        out[m++] = in[k];
    }
    for (int i = 0; i < TSNET_TRACKER_SLOTS && m < cap; i++) {
        if (!t->e[i].used || now_ms > t->e[i].until) {
            continue;
        }
        bool given = false;
        for (size_t k = 0; k < n && !given; k++) {
            given = same_addrport(&t->e[i].ep, &in[k]);
        }
        if (!given) {
            out[m++] = t->e[i].ep;
        }
    }
    return m;
}

static bool contains(const tsnet_selfep_t *s, size_t n, const tsnet_selfep_t *e)
{
    for (size_t i = 0; i < n; i++) {
        if (same_ep(&s[i], e)) {
            return true;
        }
    }
    return false;
}

bool tsnet_selfeps_equal(const tsnet_selfep_t *a, size_t na, const tsnet_selfep_t *b, size_t nb)
{
    for (size_t i = 0; i < na; i++) {
        if (!contains(b, nb, &a[i])) {
            return false;
        }
    }
    for (size_t i = 0; i < nb; i++) {
        if (!contains(a, na, &b[i])) {
            return false;
        }
    }
    return true;
}

// tsaddr.IsTailscaleIP: 100.64.0.0/10 but not ChromeOS's 100.115.92.0/23, or fd7a:115c:a1e0::/48.
static bool tailscale_ip(const uint8_t ip[16])
{
    if (is4(ip)) {
        bool cgnat = ip[12] == 100 && (ip[13] & 0xc0) == 64;
        bool chromeos = ip[12] == 100 && ip[13] == 115 && (ip[14] & 0xfe) == 92;
        return cgnat && !chromeos;
    }
    static const uint8_t ULA[6] = {0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0};
    return memcmp(ip, ULA, sizeof ULA) == 0;
}

static bool loopback_ip(const uint8_t ip[16])
{
    static const uint8_t ONE[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    return is4(ip) ? ip[12] == 127 : memcmp(ip, ONE, 16) == 0;
}

static bool link_local_ip(const uint8_t ip[16])
{
    return is4(ip) ? ip[12] == 169 && ip[13] == 254 : ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80;
}

// netip.Addr.Less: IPv4 before IPv6, then by value.
static int addr_cmp(const uint8_t a[16], const uint8_t b[16])
{
    if (is4(a) != is4(b)) {
        return is4(a) ? -1 : 1;
    }
    return memcmp(a, b, 16);
}

static void sort_addrs(uint8_t (*s)[16], size_t n)
{
    for (size_t i = 1; i < n; i++) { // insertion sort: a handful of addresses
        for (size_t j = i; j > 0 && addr_cmp(s[j - 1], s[j]) > 0; j--) {
            uint8_t tmp[16];
            memcpy(tmp, s[j], 16);
            memcpy(s[j], s[j - 1], 16);
            memcpy(s[j - 1], tmp, 16);
        }
    }
}

static void push(uint8_t (*s)[16], size_t *n, size_t cap, const uint8_t ip[16])
{
    if (*n < cap) {
        memcpy(s[(*n)++], ip, 16);
    }
}

void tsnet_local_addresses(const tsnet_ifaddr_t *ifs, size_t n, uint8_t (*regular)[16], size_t *n_regular,
                           uint8_t (*loopback)[16], size_t *n_loopback, size_t cap)
{
    // Up to `cap` of each kind; the IPv6 subnets seen, for the 2-per-subnet rule.
    uint8_t r4[16][16], r6[16][16], ll4[16][16], ula6[16][16], subnets[16][16];
    size_t nr4 = 0, nr6 = 0, nll4 = 0, nula6 = 0, nsub = 0;
    int sub_count[16] = {0};
    *n_loopback = 0;
    for (size_t i = 0; i < n; i++) {
        const tsnet_ifaddr_t *a = &ifs[i];
        // Skip down interfaces and ZeroTier and NetBird's (isProblematicInterface).
        if (!a->up || strncmp(a->name, "zt", 2) == 0 || strcmp(a->name, "wt0") == 0) {
            continue;
        }
        if (tailscale_ip(a->ip)) {
            continue;
        }
        if (loopback_ip(a->ip) || a->loopback) {
            push(loopback, n_loopback, cap, a->ip);
        } else if (link_local_ip(a->ip)) {
            if (is4(a->ip)) {
                push(ll4, &nll4, 16, a->ip); // IPv6 link-local is never reported
            }
        } else if (!is4(a->ip) && (a->ip[0] & 0xfe) == 0xfc) {
            push(ula6, &nula6, 16, a->ip);
        } else if (is4(a->ip)) {
            push(r4, &nr4, 16, a->ip);
        } else {
            uint8_t mask[16] = {0};
            for (int b = 0; b < a->prefix_len && b < 128; b++) {
                mask[b / 8] |= (uint8_t)(0x80 >> (b % 8));
            }
            uint8_t net[16];
            for (int b = 0; b < 16; b++) {
                net[b] = a->ip[b] & mask[b];
            }
            size_t s = 0;
            while (s < nsub && memcmp(subnets[s], net, 16) != 0) {
                s++;
            }
            if (s == nsub && nsub < 16) {
                memcpy(subnets[nsub++], net, 16);
            }
            if (s < 16 && sub_count[s] < 2) {
                push(r6, &nr6, 16, a->ip); // at most 2 per subnet
            }
            if (s < 16) {
                sub_count[s]++;
            }
        }
    }
    if (nr4 == 0 && nr6 == 0) {
        // Nothing usable: IPv4 link-local and IPv6 ULA will do (some clouds NAT them).
        memcpy(r4, ll4, sizeof ll4);
        nr4 = nll4;
        memcpy(r6, ula6, sizeof ula6);
        nr6 = nula6;
    }
    *n_regular = 0;
    for (size_t i = 0; i < nr4; i++) {
        push(regular, n_regular, cap, r4[i]);
    }
    for (size_t i = 0; i < nr6; i++) {
        push(regular, n_regular, cap, r6[i]);
    }
    sort_addrs(regular, *n_regular);
    sort_addrs(loopback, *n_loopback);
}

static void add(tsnet_selfep_t *out, size_t *n, size_t cap, const uint8_t ip[16], uint16_t port, int type)
{
    static const uint8_t ZERO[16];
    if (port == 0 || memcmp(ip, ZERO, 16) == 0 || *n >= cap) {
        return; // not a valid AddrPort
    }
    tsnet_selfep_t e = {.port = port, .type = type};
    memcpy(e.ip, ip, 16);
    for (size_t i = 0; i < *n; i++) {
        if (same_addrport(&out[i], &e)) {
            return; // already there, found another way
        }
    }
    out[(*n)++] = e;
}

size_t tsnet_determine_endpoints(const tsnet_netcheck_report_t *r, uint16_t fixed_port, uint16_t local_port,
                                 const tsnet_ifaddr_t *ifs, size_t n_ifs, tsnet_tracker_t *t, uint64_t now_ms,
                                 tsnet_selfep_t *out, size_t cap)
{
    tsnet_selfep_t found[TSNET_SELFEPS_MAX];
    size_t n = 0;
    if (r) {
        // GetGlobalAddrs: the fastest server's view first, then any other seen more than once.
        if (r->has_global_v4) {
            add(found, &n, TSNET_SELFEPS_MAX, r->global_v4, r->global_v4_port, TSNET_EPT_STUN);
        }
        for (size_t i = 0; i < r->n_globals; i++) {
            bool best = r->has_global_v4 && r->globals[i].port == r->global_v4_port &&
                        memcmp(r->globals[i].ip, r->global_v4, 16) == 0;
            if (!best && r->globals[i].count > 1) {
                add(found, &n, TSNET_SELFEPS_MAX, r->globals[i].ip, r->globals[i].port, TSNET_EPT_STUN);
            }
        }
        // A hard NAT with a fixed local port: maybe there's a static port mapping to that port on the router.
        if (n >= 1 && r->mapping_varies == 1 && fixed_port != 0) {
            add(found, &n, TSNET_SELFEPS_MAX, found[0].ip, fixed_port, TSNET_EPT_STUN4LOCALPORT);
        }
    }
    size_t m = tsnet_tracker_update(t, now_ms, found, n, out, cap);
    // The socket is bound to every interface: offer each interface's address.
    uint8_t regular[16][16], loopback[16][16];
    size_t nr, nl;
    tsnet_local_addresses(ifs, n_ifs, regular, &nr, loopback, &nl, 16);
    if (nr == 0 && m == 0) {
        // No interfaces at all and no public address: loopback, for testing on a plane.
        memcpy(regular, loopback, sizeof loopback);
        nr = nl;
    }
    for (size_t i = 0; i < nr; i++) {
        add(out, &m, cap, regular[i], local_port, TSNET_EPT_LOCAL);
    }
    return m;
}

void tsnet_selfeps_wire(const tsnet_selfep_t *eps, size_t n, tsnet_addrport_t *out, int *types)
{
    for (size_t i = 0; i < n; i++) {
        memset(&out[i], 0, sizeof out[i]);
        if (is4(eps[i].ip)) {
            memcpy(out[i].ip.ip, eps[i].ip + 12, 4); // tailcfg.h keeps IPv4 as itself
        } else {
            out[i].ip.is6 = 1;
            memcpy(out[i].ip.ip, eps[i].ip, 16);
        }
        out[i].port = eps[i].port;
        types[i] = eps[i].type;
    }
}

bool tsnet_selfeps_any_stun(const tsnet_selfep_t *eps, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (eps[i].type == TSNET_EPT_STUN) {
            return true;
        }
    }
    return false;
}
