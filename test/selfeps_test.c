// Host test of this node's endpoints: Go's own TestEndpointTracker, TestEndpointTrackerMaxNum
// (endpoint_tracker_test.go) and TestEndpointSetsEqual (magicsock_test.go), then netmon.LocalAddresses' rules and
// determineEndpoints.
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "selfeps.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

// An address as netip.ParseAddr does, IPv4 mapped.
static void ip_of(uint8_t ip[16], const char *s)
{
    memset(ip, 0, 16);
    if (strchr(s, ':')) {
        inet_pton(AF_INET6, s, ip);
    } else {
        ip[10] = ip[11] = 0xff;
        inet_pton(AF_INET, s, ip + 12);
    }
}

static tsnet_selfep_t ep(const char *ip, uint16_t port, int type)
{
    tsnet_selfep_t e = {.port = port, .type = type};
    ip_of(e.ip, ip);
    return e;
}

// The same set, as Go's tests compare after sorting (the tracker's output order isn't fixed).
static bool same_set(const tsnet_selfep_t *got, size_t ng, const tsnet_selfep_t *want, size_t nw)
{
    return ng == nw && tsnet_selfeps_equal(got, ng, want, nw);
}

#define MIN (60 * 1000ULL)

static void tracker(void)
{
    tsnet_selfep_t local = ep("192.168.1.1", 12345, TSNET_EPT_LOCAL), stun4_1 = ep("1.2.3.4", 12345, TSNET_EPT_STUN),
                   stun4_2 = ep("5.6.7.8", 12345, TSNET_EPT_STUN),
                   stun6_1 = ep("2a09:8280:1::1111", 12345, TSNET_EPT_STUN),
                   stun6_2 = ep("2a09:8280:1::2222", 12345, TSNET_EPT_STUN);
    const uint64_t start = 1681503440000ULL;
    struct {
        const char *name;
        uint64_t now;
        tsnet_selfep_t eps[4];
        size_t n;
        tsnet_selfep_t want[5];
        size_t nw;
    } steps[] = {
        {"initial endpoints", start, {local, stun4_1, stun6_1}, 3, {local, stun4_1, stun6_1}, 3},
        {"no change", start + 1 * MIN, {local, stun4_1, stun6_1}, 3, {local, stun4_1, stun6_1}, 3},
        {"missing stun4", start + 2 * MIN, {local, stun6_1}, 2, {local, stun4_1, stun6_1}, 3},
        {"missing stun6", start + 3 * MIN, {local, stun4_1}, 2, {local, stun4_1, stun6_1}, 3},
        {"multiple STUN addresses within timeout", start + 4 * MIN, {local, stun4_2, stun6_2}, 3,
         {local, stun4_1, stun4_2, stun6_1, stun6_2}, 5},
        // stun4_1 had its lifetime extended by "missing stun6"; stun6_1 expired a minute sooner.
        {"endpoint extended", start + 3 * MIN + TSNET_TRACKER_LIFETIME_MS - 1, {local}, 1,
         {local, stun4_2, stun6_2, stun4_1}, 4},
        {"after timeout", start + 4 * MIN + TSNET_TRACKER_LIFETIME_MS + 1, {local, stun4_2, stun6_2}, 3,
         {local, stun4_2, stun6_2}, 3},
        {"after timeout still caches", start + 4 * MIN + TSNET_TRACKER_LIFETIME_MS + 1 * MIN, {local}, 1,
         {local, stun4_2, stun6_2}, 3},
    };
    tsnet_tracker_t t;
    memset(&t, 0, sizeof t);
    for (size_t i = 0; i < sizeof steps / sizeof steps[0]; i++) {
        tsnet_selfep_t got[TSNET_SELFEPS_MAX];
        size_t n = tsnet_tracker_update(&t, steps[i].now, steps[i].eps, steps[i].n, got, TSNET_SELFEPS_MAX);
        if (!same_set(got, n, steps[i].want, steps[i].nw)) {
            printf("tracker step \"%s\": got %zu endpoints, want %zu\n", steps[i].name, n, steps[i].nw);
            failures++;
        }
    }
}

static void tracker_max(void)
{
    const uint64_t start = 1681503440000ULL;
    tsnet_selfep_t all[16];
    size_t n_all = 0;
    tsnet_tracker_t t;
    memset(&t, 0, sizeof t);
    tsnet_selfep_t got[TSNET_SELFEPS_MAX];
    // More endpoints than the limit, a second apart.
    for (int i = 0; i <= TSNET_TRACKER_PER_ADDR; i++) {
        all[n_all] = ep("1.2.3.4", (uint16_t)(10000 + i), TSNET_EPT_STUN);
        tsnet_tracker_update(&t, start + (uint64_t)i * 1000, &all[n_all++], 1, got, TSNET_SELFEPS_MAX);
    }
    // Two more, slightly later: the last 6 of all come back (one address, so the first ones were dropped).
    all[n_all++] = ep("1.2.3.4", 10100, TSNET_EPT_STUN);
    all[n_all++] = ep("1.2.3.4", 10101, TSNET_EPT_STUN);
    size_t n = tsnet_tracker_update(&t, start + MIN, &all[n_all - 2], 2, got, TSNET_SELFEPS_MAX);
    EXPECT(same_set(got, n, &all[n_all - TSNET_TRACKER_PER_ADDR], TSNET_TRACKER_PER_ADDR));
    // More than the limit given at once all come back, even for one address.
    tsnet_selfep_t in[TSNET_TRACKER_PER_ADDR + 5];
    for (int i = 0; i < TSNET_TRACKER_PER_ADDR + 5; i++) {
        in[i] = ep("1.2.3.4", (uint16_t)(10200 + i), TSNET_EPT_STUN);
    }
    n = tsnet_tracker_update(&t, start + 2 * MIN, in, TSNET_TRACKER_PER_ADDR + 5, got, TSNET_SELFEPS_MAX);
    EXPECT(same_set(got, n, in, TSNET_TRACKER_PER_ADDR + 5));
}

static void sets_equal(void)
{
    // s(ports...): endpoints with the zero address and those ports.
    struct {
        uint16_t a[4], b[4];
        size_t na, nb;
        bool want;
    } tests[] = {
        {{0}, {0}, 0, 0, true},
        {{1, 2, 3}, {1, 2, 3}, 3, 3, true},
        {{1, 2}, {2, 1}, 2, 2, true},
        {{1, 2}, {2, 1, 1}, 2, 3, true},
        {{1, 2, 2}, {2, 1}, 3, 2, true},
        {{1, 2, 2}, {2, 1, 1}, 3, 3, true},
        {{1, 2, 2, 3}, {2, 1, 1}, 4, 3, false},
        {{1, 2, 2}, {2, 1, 1, 3}, 3, 4, false},
    };
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        tsnet_selfep_t a[4], b[4];
        memset(a, 0, sizeof a);
        memset(b, 0, sizeof b);
        for (size_t k = 0; k < tests[i].na; k++) {
            a[k].port = tests[i].a[k];
        }
        for (size_t k = 0; k < tests[i].nb; k++) {
            b[k].port = tests[i].b[k];
        }
        if (tsnet_selfeps_equal(a, tests[i].na, b, tests[i].nb) != tests[i].want) {
            printf("endpointSetsEqual case %zu: got %d\n", i, !tests[i].want);
            failures++;
        }
    }
    // The type counts too.
    tsnet_selfep_t x = ep("1.2.3.4", 1, TSNET_EPT_STUN), y = ep("1.2.3.4", 1, TSNET_EPT_LOCAL);
    EXPECT(!tsnet_selfeps_equal(&x, 1, &y, 1));
}

static tsnet_ifaddr_t ifa(const char *name, const char *ip, int prefix, bool up, bool loopback)
{
    tsnet_ifaddr_t a = {.up = up, .loopback = loopback, .prefix_len = (uint8_t)prefix};
    snprintf(a.name, sizeof a.name, "%s", name);
    ip_of(a.ip, ip);
    return a;
}

static bool has(uint8_t (*s)[16], size_t n, const char *ip)
{
    uint8_t want[16];
    ip_of(want, ip);
    for (size_t i = 0; i < n; i++) {
        if (memcmp(s[i], want, 16) == 0) {
            return true;
        }
    }
    return false;
}

static void local_addresses(void)
{
    uint8_t reg[16][16], loop[16][16];
    size_t nr, nl;
    tsnet_ifaddr_t ifs[] = {
        ifa("lo0", "127.0.0.1", 8, true, true),
        ifa("lo0", "::1", 128, true, true),
        ifa("en0", "fe80::1", 64, true, false),          // IPv6 link-local: never
        ifa("en0", "192.0.2.3", 24, true, false),        // regular
        ifa("en0", "2001:db8::1", 64, true, false),      // regular, subnet 1
        ifa("en0", "2001:db8::2", 64, true, false),      // regular, subnet 1
        ifa("en0", "2001:db8::3", 64, true, false),      // a third in subnet 1: left out
        ifa("en0", "fd00::5", 64, true, false),          // ULA: only when nothing else
        ifa("en1", "198.51.100.9", 24, false, false),    // down
        ifa("zt0", "10.147.17.1", 24, true, false),      // ZeroTier
        ifa("utun4", "100.101.102.103", 32, true, false), // a Tailscale address
        ifa("en2", "100.115.92.5", 23, true, false),     // ChromeOS's range isn't Tailscale's
        ifa("en3", "169.254.7.7", 16, true, false),      // IPv4 link-local: only when nothing else
    };
    tsnet_local_addresses(ifs, sizeof ifs / sizeof ifs[0], reg, &nr, loop, &nl, 16);
    EXPECT(nr == 4 && has(reg, nr, "100.115.92.5") && has(reg, nr, "192.0.2.3") && has(reg, nr, "2001:db8::1") &&
           has(reg, nr, "2001:db8::2"));
    EXPECT(nl == 2 && has(loop, nl, "127.0.0.1") && has(loop, nl, "::1"));
    // Sorted: IPv4 first, then by value.
    uint8_t first[16];
    ip_of(first, "100.115.92.5");
    EXPECT(memcmp(reg[0], first, 16) == 0);
    ip_of(first, "127.0.0.1");
    EXPECT(memcmp(loop[0], first, 16) == 0);
    // Nothing regular: IPv4 link-local and the ULA instead.
    tsnet_ifaddr_t only[] = {ifs[0], ifs[2], ifs[7], ifs[12]};
    tsnet_local_addresses(only, 4, reg, &nr, loop, &nl, 16);
    EXPECT(nr == 2 && has(reg, nr, "169.254.7.7") && has(reg, nr, "fd00::5"));
}

static void determine(void)
{
    tsnet_netcheck_report_t r;
    memset(&r, 0, sizeof r);
    r.has_global_v4 = true;
    ip_of(r.global_v4, "203.0.113.7");
    r.global_v4_port = 41641;
    r.mapping_varies = 0;
    // GlobalV4Counters: the best (seen twice), one other seen twice, one seen once.
    ip_of(r.globals[0].ip, "203.0.113.7");
    r.globals[0].port = 41641;
    r.globals[0].count = 2;
    ip_of(r.globals[1].ip, "203.0.113.7");
    r.globals[1].port = 50000;
    r.globals[1].count = 2;
    ip_of(r.globals[2].ip, "203.0.113.7");
    r.globals[2].port = 50001;
    r.globals[2].count = 1;
    r.n_globals = 3;
    tsnet_ifaddr_t ifs[] = {ifa("lo0", "127.0.0.1", 8, true, true), ifa("en0", "192.0.2.3", 24, true, false)};
    tsnet_tracker_t t;
    memset(&t, 0, sizeof t);
    tsnet_selfep_t out[TSNET_SELFEPS_MAX];
    const uint64_t now = 1000000;
    size_t n = tsnet_determine_endpoints(&r, 0, 12345, ifs, 2, &t, now, out, TSNET_SELFEPS_MAX);
    tsnet_selfep_t want[] = {ep("203.0.113.7", 41641, TSNET_EPT_STUN), ep("203.0.113.7", 50000, TSNET_EPT_STUN),
                             ep("192.0.2.3", 12345, TSNET_EPT_LOCAL)};
    bool in_order = n == 3;
    for (size_t i = 0; i < 3 && in_order; i++) {
        in_order = tsnet_selfeps_equal(&out[i], 1, &want[i], 1);
    }
    EXPECT(in_order); // STUN first, the best first, then local
    EXPECT(tsnet_selfeps_any_stun(out, n));

    // A hard NAT with a fixed port: the best address with that port too.
    r.mapping_varies = 1;
    n = tsnet_determine_endpoints(&r, 41641 + 1, 41642, ifs, 2, &t, now, out, TSNET_SELFEPS_MAX);
    EXPECT(n == 4 && out[2].type == TSNET_EPT_STUN4LOCALPORT && out[2].port == 41642);
    // Without a fixed port, no new guess; with a fresh tracker that means none at all.
    tsnet_tracker_t t2;
    memset(&t2, 0, sizeof t2);
    n = tsnet_determine_endpoints(&r, 0, 41642, ifs, 2, &t2, now, out, TSNET_SELFEPS_MAX);
    bool guessed = false;
    for (size_t i = 0; i < n; i++) {
        guessed |= out[i].type == TSNET_EPT_STUN4LOCALPORT;
    }
    EXPECT(n == 3 && !guessed);

    // A report that sees nothing: the tracker keeps the STUN endpoints for 5 min 10 s.
    tsnet_netcheck_report_t none;
    memset(&none, 0, sizeof none);
    n = tsnet_determine_endpoints(&none, 0, 12345, ifs, 2, &t, now + 60000, out, TSNET_SELFEPS_MAX);
    EXPECT(tsnet_selfeps_any_stun(out, n));
    n = tsnet_determine_endpoints(&none, 0, 12345, ifs, 2, &t, now + TSNET_TRACKER_LIFETIME_MS + 1, out,
                                  TSNET_SELFEPS_MAX);
    EXPECT(n == 1 && out[0].type == TSNET_EPT_LOCAL);

    // No report and no interfaces but loopback: loopback, for testing offline.
    tsnet_tracker_t fresh;
    memset(&fresh, 0, sizeof fresh);
    n = tsnet_determine_endpoints(NULL, 0, 12345, ifs, 1, &fresh, now, out, TSNET_SELFEPS_MAX);
    EXPECT(n == 1 && out[0].type == TSNET_EPT_LOCAL && out[0].ip[12] == 127 && !tsnet_selfeps_any_stun(out, n));
}

// The host's own interfaces: at least loopback, up, with 127.0.0.1 among its addresses. (Nothing is printed: these
// are this machine's addresses.)
static void real_interfaces(void)
{
    tsnet_ifaddr_t ifs[64];
    int n = tsnet_ifaddrs(ifs, 64);
    bool lo = false;
    for (int i = 0; i < n; i++) {
        lo |= ifs[i].up && ifs[i].loopback && ifs[i].ip[10] == 0xff && ifs[i].ip[12] == 127 && ifs[i].prefix_len == 8;
    }
    EXPECT(n >= 1 && lo);
}

int main(void)
{
    real_interfaces();
    tracker();
    tracker_max();
    sets_equal();
    local_addresses();
    determine();
    if (failures == 0) {
        printf("tsnet selfeps_test: ok\n");
    }
    return failures != 0;
}
