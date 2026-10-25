// Host test of a peer's paths: Go's own cases for betterAddr (magicsock_test.go TestBetterAddr),
// discoPingTimeout and handlePongConnLocked (endpoint_test.go), less the UDP relay (Geneve) ones tsnet has no paths
// for; then the trust window, what starts pings, the heartbeat, the endpoints' lifetimes and the caps.
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "endpoint.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

#define MS 1000ULL
#define SEC 1000000ULL
#define T0 (100000 * SEC) // a clock far enough in that "an hour ago" doesn't wrap

// "a.b.c.d:port" or "[v6]:port", as netip.MustParseAddrPort, IPv4 mapped into 16 bytes.
static tsnet_addrq_t al(const char *s, uint64_t latency_us)
{
    tsnet_addrq_t q = {.valid = true, .latency_us = latency_us};
    char host[64];
    const char *colon = s[0] == '[' ? strchr(s, ']') + 1 : strrchr(s, ':');
    size_t hl = (size_t)(colon - s);
    memcpy(host, s, hl);
    host[hl] = 0;
    q.port = (uint16_t)atoi(colon + 1);
    if (s[0] == '[') {
        host[hl - 1] = 0;
        inet_pton(AF_INET6, host + 1, q.ip);
    } else {
        q.ip[10] = q.ip[11] = 0xff;
        inet_pton(AF_INET, host, q.ip + 12);
    }
    return q;
}

static tsnet_addrq_t almtu(const char *s, uint64_t latency_us, uint16_t mtu)
{
    tsnet_addrq_t q = al(s, latency_us);
    q.wire_mtu = mtu;
    return q;
}

static void better_addr(void)
{
    const tsnet_addrq_t zero = {0};
    const char *publicV4 = "1.2.3.4:555", *publicV4_2 = "5.6.7.8:999", *publicV6 = "[2001::5]:123",
               *privateV4 = "10.0.0.2:123";
    struct {
        tsnet_addrq_t a, b;
        bool want;
    } tests[] = {
        {zero, zero, false},
        {al(publicV4, 5 * MS), zero, true},
        {zero, al(publicV4, 5 * MS), false},
        {al(publicV4, 5 * MS), al(publicV4_2, 10 * MS), true},
        {al(publicV4, 5 * MS), al(publicV4, 10 * MS), false}, // same IPPort
        // Don't prefer b to a if it's not substantially better.
        {al(publicV4, 100 * MS), al(publicV4_2, 100 * MS), false},
        {al(publicV4, 100 * MS), al(publicV4_2, 101 * MS), false},
        {al(publicV4, 100 * MS), al(publicV4_2, 103 * MS), true},
        // Latencies of zero don't result in a divide-by-zero
        {al(publicV4, 0), al(publicV4_2, 0), false},
        // Prefer private IPs to public IPs if roughly equivalent...
        {al(privateV4, 100 * MS), al(publicV4, 91 * MS), true},
        {al(publicV4, 91 * MS), al(privateV4, 100 * MS), false},
        // ... but not if the private IP is slower.
        {al(privateV4, 100 * MS), al(publicV4, 30 * MS), false},
        {al(publicV4, 30 * MS), al(privateV4, 100 * MS), true},
        // Prefer IPv6 if roughly equivalent:
        {al(publicV6, 100 * MS), al(publicV4, 91 * MS), true},
        {al(publicV4, 91 * MS), al(publicV6, 100 * MS), false},
        // But not if IPv4 is much faster:
        {al(publicV6, 100 * MS), al(publicV4, 30 * MS), false},
        {al(publicV4, 30 * MS), al(publicV6, 100 * MS), true},
        // If addresses are equal, prefer larger MTU
        {almtu(publicV4, 30 * MS, 1500), almtu(publicV4, 30 * MS, 0), true},
        // Private IPs are preferred over public IPs even if the public IP is IPv6.
        {al("192.168.0.1:555", 100 * MS), al("[2001::5]:123", 101 * MS), true},
        {al("[2001::5]:123", 101 * MS), al("192.168.0.1:555", 100 * MS), false},
        // Link-local unicast addresses are preferred over other private IPs, but not as much as localhost addresses.
        {al("[fe80::ce8:474a:a27e:113b]:555", 101 * MS), al("[fd89:1a8a:8888:9999:aaaa:bbbb:cccc:dddd]:555", 100 * MS),
         true},
        {al("[fe80::ce8:474a:a27e:113b]:555", 101 * MS), al("[::1]:555", 100 * MS), false},
        // (Go's last two prefer a direct path to a Geneve one: tsnet has no Geneve paths.)
    };
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        bool got = tsnet_better_addr(&tests[i].a, &tests[i].b);
        if (got != tests[i].want) {
            printf("[%zu] betterAddr = %d, want %d\n", i, got, tests[i].want);
            failures++;
            continue;
        }
        EXPECT(!(got && tsnet_better_addr(&tests[i].b, &tests[i].a))); // never both ways
    }
    // The address classes, IPv4 mapped.
    tsnet_addrq_t v4 = al("172.16.0.1:1", 0), v4b = al("172.32.0.1:1", 0), ll = al("169.254.1.1:1", 0);
    EXPECT(tsnet_ip_private(v4.ip) && !tsnet_ip_private(v4b.ip) && !tsnet_ip_is6(v4.ip));
    EXPECT(tsnet_ip_link_local(ll.ip) && tsnet_ip_loopback(al("127.9.9.9:1", 0).ip));
}

// An endpoint state for ip:port, as the netmap would add it.
static int add_state(tsnet_endpoint_t *e, const tsnet_addrq_t *q)
{
    for (int i = 0; i < TSNET_EP_STATES; i++) {
        if (!e->st[i].used) {
            e->st[i].used = true;
            e->st[i].in_netmap = true;
            memcpy(e->st[i].ip, q->ip, 16);
            e->st[i].port = q->port;
            return i;
        }
    }
    return -1;
}

static const uint8_t TX[12] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2};

static void sent_ping(tsnet_endpoint_t *e, const tsnet_addrq_t *to, uint64_t at)
{
    e->sent[0] = (tsnet_sentping_t){.used = true, .port = to->port, .at = at, .purpose = TSNET_PING_DISCOVERY};
    memcpy(e->sent[0].txid, TX, 12);
    memcpy(e->sent[0].ip, to->ip, 16);
}

static bool same(const tsnet_addrq_t *a, const tsnet_addrq_t *b)
{
    return a->valid == b->valid && (!a->valid || (memcmp(a->ip, b->ip, 16) == 0 && a->port == b->port));
}

// Test_endpoint_discoPingTimeout's direct cases: a ping to the best address that times out clears it, only when the
// best isn't trusted.
static void ping_timeout(void)
{
    const uint64_t now = T0;
    tsnet_addrq_t a = al("192.0.2.1:7", 0), b = al("192.0.2.3:7", 0);
    struct {
        const char *name;
        uint64_t trust_until;
        const tsnet_addrq_t *to;
        bool cleared;
    } tests[] = {
        {"direct-udp-path-trust-expired", now - 3600 * SEC, &a, true},
        {"direct-udp-path-trust-valid", now + 3600 * SEC, &a, false},
        {"ping-to-different-direct-addr-trust-expired", now - 3600 * SEC, &b, false},
    };
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        int before = failures;
        tsnet_endpoint_t e;
        tsnet_endpoint_init(&e);
        e.best = a;
        e.trust_until = tests[i].trust_until;
        sent_ping(&e, tests[i].to, now - TSNET_PING_TIMEOUT_US);
        tsnet_ep_actions_t act;
        tsnet_endpoint_step(&e, now, &act);
        if (tests[i].cleared) {
            EXPECT(!e.best.valid && e.trust_until == 0);
        } else {
            EXPECT(same(&e.best, &a));
        }
        EXPECT(!e.sent[0].used);
        if (failures != before) {
            printf("  in %s\n", tests[i].name);
        }
    }
    // Not yet 5 s: nothing happens.
    tsnet_endpoint_t e;
    tsnet_endpoint_init(&e);
    sent_ping(&e, &a, now - TSNET_PING_TIMEOUT_US + 1);
    tsnet_ep_actions_t act;
    tsnet_endpoint_step(&e, now, &act);
    EXPECT(e.sent[0].used && tsnet_endpoint_next(&e) == now + 1);
}

// Test_endpoint_handlePongConnLocked's cases.
static void pong(void)
{
    const uint64_t now = T0, good = 50 * MS, bad = 100 * MS;
    const uint64_t expired = now - 3600 * SEC, valid = now + 3600 * SEC;
    tsnet_addrq_t a = al("192.0.2.1:7", 0), b = al("192.0.2.2:8", 0);
    struct {
        const char *name;
        const tsnet_addrq_t *best;
        uint64_t best_latency, trust_until;
        const tsnet_addrq_t *from; // NULL: over DERP
        uint64_t latency;
        const tsnet_addrq_t *want;
    } tests[] = {
        {"better-latency-trust-valid", &a, bad, valid, &b, good, &b},
        {"worse-latency-trust-valid", &a, good, valid, &b, bad, &a},
        {"worse-latency-trust-expired", &a, good, expired, &b, bad, &b},
        {"same-path-trust-expired", &a, bad, expired, &a, good, &a},
        {"derp-pong-trust-expired", &a, bad, expired, NULL, good, &a},
        {"better-latency-trust-expired", &a, bad, expired, &b, good, &b},
    };
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        int before = failures;
        tsnet_endpoint_t e;
        tsnet_endpoint_init(&e);
        e.best = *tests[i].best;
        e.best.latency_us = tests[i].best_latency;
        e.trust_until = tests[i].trust_until;
        add_state(&e, &a);
        if (tests[i].from && tests[i].from != &a) {
            add_state(&e, tests[i].from);
        }
        tsnet_addrq_t derp = al("127.3.3.40:0", 0);
        sent_ping(&e, tests[i].from ? tests[i].from : &derp, now - tests[i].latency);
        EXPECT(tsnet_endpoint_pong(&e, now, TX, tests[i].from == NULL, NULL));
        EXPECT(same(&e.best, tests[i].want));
        if (tests[i].from == tests[i].best) {
            EXPECT(e.best.latency_us == tests[i].latency);
        }
        if (tests[i].from) {
            EXPECT(e.trust_until >= now); // trusted after a UDP pong (refreshed, or still valid)
        }
        EXPECT(!e.sent[0].used);
        EXPECT(!tsnet_endpoint_pong(&e, now, TX, false, NULL)); // the same pong again: not ours any more
        if (failures != before) {
            printf("  in %s\n", tests[i].name);
        }
    }
    // A pong for an endpoint no longer wanted ends the ping and changes nothing.
    tsnet_endpoint_t e;
    tsnet_endpoint_init(&e);
    sent_ping(&e, &b, now - good);
    EXPECT(tsnet_endpoint_pong(&e, now, TX, false, NULL) && !e.best.valid);
}

static tsnet_disco_ep_t ep_of(const tsnet_addrq_t *q)
{
    tsnet_disco_ep_t ep = {.port = q->port};
    memcpy(ep.ip, q->ip, 16);
    return ep;
}

static void netmap(tsnet_endpoint_t *e, uint64_t now, const tsnet_addrq_t *qs, size_t n)
{
    tsnet_disco_ep_t eps[8];
    for (size_t i = 0; i < n; i++) {
        eps[i] = ep_of(&qs[i]);
    }
    tsnet_endpoint_set_netmap(e, now, eps, n);
}

static int count_states(const tsnet_endpoint_t *e)
{
    int n = 0;
    for (int i = 0; i < TSNET_EP_STATES; i++) {
        n += e->st[i].used;
    }
    return n;
}

static int find_state(const tsnet_endpoint_t *e, const tsnet_addrq_t *q)
{
    for (int i = 0; i < TSNET_EP_STATES; i++) {
        if (e->st[i].used && e->st[i].port == q->port && memcmp(e->st[i].ip, q->ip, 16) == 0) {
            return i;
        }
    }
    return -1;
}

// addrForSendLocked's trust window, and what a send starts (endpoint.send): pings to every endpoint not pinged in the
// last 5 s, a CallMeMaybe with them, and the heartbeat.
static void send_and_heartbeat(void)
{
    uint64_t now = 1000 * SEC;
    tsnet_addrq_t eps[2] = {al("192.0.2.1:7", 0), al("192.0.2.2:8", 0)};
    tsnet_endpoint_t e;
    tsnet_endpoint_init(&e);
    netmap(&e, now, eps, 2);
    EXPECT(count_states(&e) == 2);

    tsnet_addrq_t udp;
    bool derp;
    tsnet_ep_actions_t act;
    tsnet_endpoint_send(&e, now, &udp, &derp, &act);
    EXPECT(!udp.valid && derp); // no path yet: DERP
    EXPECT(act.n_ping == 2 && act.call_me_maybe);
    EXPECT(e.heartbeat && e.heartbeat_at == now + TSNET_HEARTBEAT_US);
    // Another send a second later: still DERP, but no new pings (5 s apart) and so no CallMeMaybe.
    tsnet_endpoint_send(&e, now + SEC, &udp, &derp, &act);
    EXPECT(derp && act.n_ping == 0 && !act.call_me_maybe);

    // Endpoint 2 answers in 2 ms: it becomes the best, trusted for 6.5 s, and sends go to it alone.
    uint8_t tx2[12];
    for (int i = 0; i < TSNET_EP_PINGS; i++) {
        if (e.sent[i].used && e.sent[i].port == 8) {
            memcpy(tx2, e.sent[i].txid, 12);
        }
    }
    now += 2 * MS;
    EXPECT(tsnet_endpoint_pong(&e, now, tx2, false, NULL));
    EXPECT(same(&e.best, &eps[1]) && e.best.latency_us == 2 * MS);
    tsnet_endpoint_addr_for_send(&e, now + TSNET_TRUST_UDP_US, &udp, &derp);
    EXPECT(same(&udp, &eps[1]) && !derp); // the last moment of trust
    tsnet_endpoint_addr_for_send(&e, now + TSNET_TRUST_UDP_US + 1, &udp, &derp);
    EXPECT(same(&udp, &eps[1]) && derp); // trust over: both

    // The heartbeat at 3 s: a ping to the best address; the latency is good enough, so no full round.
    tsnet_endpoint_step(&e, 1000 * SEC + TSNET_HEARTBEAT_US, &act);
    EXPECT(act.n_ping == 1 && act.ping[0].port == 8 && !act.call_me_maybe);
    EXPECT(same(&e.best, &eps[1]));

    // No send for 45 s: the heartbeats stop.
    tsnet_endpoint_t idle = e;
    uint64_t t = 1000 * SEC + SEC + TSNET_SESSION_ACTIVE_US + 1;
    idle.heartbeat_at = t;
    tsnet_endpoint_step(&idle, t, &act);
    EXPECT(!idle.heartbeat && act.n_ping == 0);
}

// wantFullPingLocked.
static void want_full_ping(void)
{
    const uint64_t now = 1000 * SEC;
    tsnet_endpoint_t e;
    tsnet_endpoint_init(&e);
    EXPECT(tsnet_endpoint_want_full_ping(&e, now)); // no direct path
    e.best = al("192.0.2.1:7", 20 * MS);
    EXPECT(tsnet_endpoint_want_full_ping(&e, now)); // never done
    e.last_full_ping = now - 30 * SEC;
    e.trust_until = now + SEC;
    EXPECT(!tsnet_endpoint_want_full_ping(&e, now)); // trusted, a full round 30 s ago
    e.last_full_ping = now - TSNET_UPGRADE_DIRECT_US;
    EXPECT(tsnet_endpoint_want_full_ping(&e, now)); // a minute: look for better
    e.best.latency_us = TSNET_GOOD_ENOUGH_LATENCY_US;
    EXPECT(!tsnet_endpoint_want_full_ping(&e, now)); // good enough already
    e.trust_until = now - 1;
    EXPECT(tsnet_endpoint_want_full_ping(&e, now)); // trust over
}

// addCandidateEndpoint and the endpoints' lifetimes.
static void endpoints(void)
{
    uint64_t now = 1000 * SEC;
    tsnet_addrq_t nm = al("192.0.2.1:7", 0), cand = al("198.51.100.9:4000", 0);
    tsnet_endpoint_t e;
    tsnet_endpoint_init(&e);
    netmap(&e, now, &nm, 1);
    // A ping from a new address adds it; the same ping again is a duplicate; a new ping isn't.
    EXPECT(!tsnet_endpoint_got_ping(&e, now, cand.ip, cand.port, TX));
    EXPECT(count_states(&e) == 2);
    EXPECT(tsnet_endpoint_got_ping(&e, now, cand.ip, cand.port, TX));
    uint8_t tx2[12] = {1};
    EXPECT(!tsnet_endpoint_got_ping(&e, now + SEC, cand.ip, cand.port, tx2));
    // A ping from a netmap endpoint keeps it a netmap one.
    uint8_t tx3[12] = {3};
    EXPECT(!tsnet_endpoint_got_ping(&e, now, nm.ip, nm.port, tx3));
    EXPECT(e.st[0].last_got_ping == 0);
    // 45 s after its last ping the candidate goes; the netmap one stays while the netmap has it.
    netmap(&e, now + SEC + TSNET_SESSION_ACTIVE_US, &nm, 1);
    EXPECT(count_states(&e) == 2);
    netmap(&e, now + SEC + TSNET_SESSION_ACTIVE_US + 1, &nm, 1);
    EXPECT(count_states(&e) == 1);
    // The netmap drops its endpoint: it goes, and so does the best address that was it.
    e.best = nm;
    netmap(&e, now + 60 * SEC, NULL, 0);
    EXPECT(count_states(&e) == 0 && !e.best.valid);

    // A CallMeMaybe's endpoints are pinged now, even ones pinged under 5 s ago; the next CallMeMaybe replaces them.
    tsnet_endpoint_init(&e);
    netmap(&e, now, &nm, 1);
    tsnet_addrq_t udp;
    bool derp;
    tsnet_ep_actions_t act;
    tsnet_endpoint_send(&e, now, &udp, &derp, &act); // pings the netmap endpoint
    tsnet_addrq_t c1 = al("198.51.100.1:1", 0), c2 = al("198.51.100.2:2", 0), ll = al("[fe80::1]:3", 0);
    tsnet_disco_ep_t cmm[3] = {ep_of(&c1), ep_of(&c2), ep_of(&ll)};
    tsnet_endpoint_call_me_maybe(&e, now + SEC, cmm, 3, &act);
    EXPECT(count_states(&e) == 3);                 // IPv6 link-local is left out
    EXPECT(act.n_ping == 3 && !act.call_me_maybe); // the netmap one again too
    tsnet_endpoint_call_me_maybe(&e, now + 3 * SEC, cmm + 1, 1, &act);
    EXPECT(count_states(&e) == 2 && act.n_ping == 2); // c1 is gone

    // reset (a new disco key): no best, nothing in flight, no session.
    e.best = c2;
    e.trust_until = now + 100 * SEC;
    tsnet_endpoint_reset(&e);
    EXPECT(!e.best.valid && e.trust_until == 0 && e.last_send_ext == 0 && tsnet_endpoint_next(&e) == e.heartbeat_at);
}

// #1978: a CallMeMaybe's bad targets get no ping, good ones do, and a burst from one peer is limited.
static void call_me_maybe_filter(void)
{
    uint64_t now = 1000 * SEC;
    const char *bad[] = {"0.0.0.0:5",    "127.0.0.1:5",        "127.9.9.9:5",  "224.0.0.251:5", "239.255.255.250:5",
                         "255.255.255.255:5", "169.254.169.254:80", "169.254.1.1:5", "[::]:5",      "[::1]:5",
                         "[ff02::fb]:5", "[fe80::1]:5",        "198.51.100.1:0"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        tsnet_endpoint_t e;
        tsnet_endpoint_init(&e);
        tsnet_addrq_t q = al(bad[i], 0);
        tsnet_disco_ep_t eps[1] = {ep_of(&q)};
        tsnet_ep_actions_t act;
        tsnet_endpoint_call_me_maybe(&e, now, eps, 1, &act);
        EXPECT(act.n_ping == 0 && count_states(&e) == 0);
    }
    // Good ones (LAN, public, IPv6 global) beside a bad one: only the good get pings.
    tsnet_endpoint_t e;
    tsnet_endpoint_init(&e);
    tsnet_addrq_t g1 = al("192.168.1.20:41641", 0), g2 = al("203.0.113.5:9", 0), g3 = al("[2001:db8::1]:7", 0),
                  b1 = al("127.0.0.1:5", 0);
    tsnet_disco_ep_t mix[4] = {ep_of(&b1), ep_of(&g1), ep_of(&g2), ep_of(&g3)};
    tsnet_ep_actions_t act;
    tsnet_endpoint_call_me_maybe(&e, now, mix, 4, &act);
    EXPECT(act.n_ping == 3 && count_states(&e) == 3);
    for (int i = 0; i < act.n_ping; i++) {
        EXPECT(act.ping[i].port != 5);
    }
    // A burst: within 2 s the next one is ignored (no pings, nothing replaced); at 2 s it's handled.
    tsnet_endpoint_call_me_maybe(&e, now + SEC, mix + 1, 1, &act);
    EXPECT(act.n_ping == 0 && count_states(&e) == 3);
    tsnet_endpoint_call_me_maybe(&e, now + TSNET_CMM_MIN_INTERVAL_US, mix + 1, 1, &act);
    EXPECT(act.n_ping == 1 && count_states(&e) == 1);
    // The limit is per peer.
    tsnet_endpoint_t other;
    tsnet_endpoint_init(&other);
    tsnet_endpoint_call_me_maybe(&other, now + TSNET_CMM_MIN_INTERVAL_US, mix + 1, 1, &act);
    EXPECT(act.n_ping == 1);
}

// #1979: a ping replayed from spoofed sources can't fill the table against the netmap's endpoints or draw pongs.
static void eviction_and_replay(void)
{
    uint64_t now = 1000 * SEC;
    tsnet_endpoint_t e;
    tsnet_endpoint_init(&e);
    // One captured ping, replayed from 16 spoofed sources: the first is answered, the other 15 aren't, and none adds
    // a candidate beyond the first.
    uint8_t cap[12] = {0xca, 0xfe};
    int pongs = 0;
    for (int i = 0; i < TSNET_EP_STATES; i++) {
        tsnet_addrq_t q = al("198.51.100.1:1", 0);
        q.port = (uint16_t)(2000 + i);
        pongs += !tsnet_endpoint_got_ping(&e, now + (uint64_t)i, q.ip, q.port, cap);
    }
    EXPECT(pongs == 1 && count_states(&e) == 1);
    // Alternating replays of two captured pings: still only the first of each is answered.
    uint8_t cap2[12] = {0xbe, 0xef};
    pongs = 0;
    for (int i = 0; i < 20; i++) {
        tsnet_addrq_t q = al("198.51.100.2:1", 0);
        q.port = (uint16_t)(3000 + i);
        pongs += !tsnet_endpoint_got_ping(&e, now + SEC, q.ip, q.port, i % 2 ? cap : cap2);
    }
    EXPECT(pongs == 1);
    // Normal pings (fresh txids) still get pongs, and fill the table with candidates.
    tsnet_endpoint_init(&e);
    pongs = 0;
    for (int i = 0; i < TSNET_EP_STATES; i++) {
        tsnet_addrq_t q = al("198.51.100.1:1", 0);
        q.port = (uint16_t)(2000 + i);
        uint8_t tx[12] = {1, (uint8_t)i};
        pongs += !tsnet_endpoint_got_ping(&e, now + (uint64_t)i, q.ip, q.port, tx);
    }
    EXPECT(pongs == TSNET_EP_STATES && count_states(&e) == TSNET_EP_STATES);
    // The txid ring is bounded: a ping older than TSNET_GOT_TXIDS others is forgotten.
    uint8_t old[12] = {1, 0}; // the first of those above
    for (int i = 0; i < TSNET_GOT_TXIDS; i++) {
        uint8_t tx[12] = {2, (uint8_t)i};
        tsnet_endpoint_got_ping(&e, now + 20 * SEC, al("198.51.100.1:1", 0).ip, 2000, tx);
    }
    EXPECT(!tsnet_endpoint_got_ping(&e, now + 20 * SEC, al("198.51.100.1:1", 0).ip, 2000, old));

    // Full of candidates: a new candidate finds no room, but a netmap endpoint evicts the oldest candidate.
    tsnet_endpoint_init(&e);
    for (int i = 0; i < TSNET_EP_STATES; i++) {
        tsnet_addrq_t q = al("198.51.100.1:1", 0);
        q.port = (uint16_t)(2000 + i);
        uint8_t tx[12] = {1, (uint8_t)i};
        tsnet_endpoint_got_ping(&e, now + (uint64_t)i, q.ip, q.port, tx);
    }
    uint8_t txn[12] = {7};
    tsnet_addrq_t extra = al("198.51.100.3:9", 0);
    tsnet_endpoint_got_ping(&e, now + SEC, extra.ip, extra.port, txn);
    EXPECT(count_states(&e) == TSNET_EP_STATES && find_state(&e, &extra) < 0);
    tsnet_addrq_t nm = al("192.0.2.1:7", 0), nm2 = al("192.0.2.2:7", 0);
    tsnet_addrq_t both[2] = {nm, nm2};
    netmap(&e, now + 2 * SEC, both, 2);
    EXPECT(find_state(&e, &nm) >= 0 && find_state(&e, &nm2) >= 0 && count_states(&e) == TSNET_EP_STATES);
    tsnet_addrq_t oldest = al("198.51.100.1:2000", 0), oldest2 = al("198.51.100.1:2001", 0),
                  third = al("198.51.100.1:2002", 0);
    EXPECT(find_state(&e, &oldest) < 0 && find_state(&e, &oldest2) < 0 && find_state(&e, &third) >= 0);
    // A netmap endpoint is never evicted by later candidates' pings or another netmap.
    netmap(&e, now + 3 * SEC, both, 2);
    EXPECT(find_state(&e, &nm) >= 0 && find_state(&e, &nm2) >= 0);
    // A CallMeMaybe endpoint evicts a candidate too.
    tsnet_addrq_t c1 = al("203.0.113.1:1", 0);
    tsnet_disco_ep_t cmm[1] = {ep_of(&c1)};
    tsnet_ep_actions_t act;
    tsnet_endpoint_call_me_maybe(&e, now + 4 * SEC, cmm, 1, &act);
    EXPECT(find_state(&e, &c1) >= 0 && find_state(&e, &third) < 0);
    // Only candidates are evicted: a table of netmap endpoints refuses another.
    tsnet_endpoint_init(&e);
    tsnet_addrq_t full[TSNET_EP_STATES + 1];
    for (int i = 0; i < TSNET_EP_STATES + 1; i++) {
        full[i] = al("192.0.2.1:1", 0);
        full[i].port = (uint16_t)(100 + i);
    }
    tsnet_disco_ep_t many[TSNET_EP_STATES + 1];
    for (int i = 0; i < TSNET_EP_STATES + 1; i++) {
        many[i] = ep_of(&full[i]);
    }
    tsnet_endpoint_set_netmap(&e, now, many, TSNET_EP_STATES + 1);
    EXPECT(count_states(&e) == TSNET_EP_STATES);
}

// The caps: more candidates than TSNET_EP_STATES are dropped while the others are live; more pings than
// TSNET_EP_PINGS forget the oldest.
static void caps(void)
{
    uint64_t now = 1000 * SEC;
    tsnet_endpoint_t e;
    tsnet_endpoint_init(&e);
    for (int i = 0; i < TSNET_EP_STATES + 4; i++) {
        tsnet_addrq_t q = al("198.51.100.1:1", 0);
        q.port = (uint16_t)(1000 + i);
        uint8_t tx[12] = {(uint8_t)i};
        tsnet_endpoint_got_ping(&e, now, q.ip, q.port, tx);
    }
    EXPECT(count_states(&e) == TSNET_EP_STATES);
    // Once they're stale, a new one finds room.
    tsnet_addrq_t late = al("198.51.100.2:2", 0);
    EXPECT(!tsnet_endpoint_got_ping(&e, now + TSNET_SESSION_ACTIVE_US + 1, late.ip, late.port, TX));
    EXPECT(count_states(&e) == 1);

    tsnet_endpoint_init(&e);
    tsnet_addrq_t a = al("192.0.2.1:7", 0);
    netmap(&e, now, &a, 1);
    tsnet_ep_actions_t act;
    uint8_t first[12];
    for (int i = 0; i < TSNET_EP_PINGS + 1; i++) {
        e.st[0].last_ping = 0;
        tsnet_addrq_t udp;
        bool derp;
        tsnet_endpoint_send(&e, now + (uint64_t)i, &udp, &derp, &act);
        if (i == 0) {
            memcpy(first, act.ping[0].txid, 12);
        }
    }
    int used = 0;
    for (int i = 0; i < TSNET_EP_PINGS; i++) {
        used += e.sent[i].used;
    }
    EXPECT(used == TSNET_EP_PINGS);
    EXPECT(!tsnet_endpoint_pong(&e, now + 100, first, false, NULL)); // the oldest was forgotten
}

// discoPing ("tailscale ping"): with no trusted path, over DERP and to every endpoint at once (even ones pinged under
// 5 s ago); the first pong answers it, later ones don't; with a trusted path, that path alone.
static void cli_ping(void)
{
    uint64_t now = T0;
    tsnet_addrq_t eps[2] = {al("192.0.2.1:7", 0), al("192.0.2.2:8", 0)};
    tsnet_endpoint_t e;
    tsnet_endpoint_init(&e);
    netmap(&e, now, eps, 2);
    tsnet_addrq_t udp;
    bool derp;
    tsnet_ep_actions_t act;
    tsnet_endpoint_send(&e, now, &udp, &derp, &act); // pings both: the CLI ping mustn't wait 5 s for them
    tsnet_endpoint_cli_ping(&e, now + MS, true, &act);
    EXPECT(act.n_ping == 3 && act.ping[0].derp && !act.ping[1].derp && !act.ping[2].derp);
    uint8_t derp_tx[12], udp_tx[12];
    memcpy(derp_tx, act.ping[0].txid, 12);
    memcpy(udp_tx, act.ping[2].txid, 12);
    // The UDP pong comes first: it answers, and the path becomes the best. The DERP pong after it doesn't answer.
    tsnet_ping_result_t res;
    EXPECT(tsnet_endpoint_pong(&e, now + 3 * MS, udp_tx, false, &res));
    EXPECT(res.answered && !res.via_derp && res.port == act.ping[2].port && res.latency_us == 2 * MS);
    EXPECT(e.best.valid && e.best.port == act.ping[2].port);
    EXPECT(tsnet_endpoint_pong(&e, now + 4 * MS, derp_tx, true, &res) && !res.answered);
    // A discovery pong isn't an answer.
    uint8_t disc_tx[12];
    for (int i = 0; i < TSNET_EP_PINGS; i++) {
        if (e.sent[i].used && e.sent[i].purpose == TSNET_PING_DISCOVERY) {
            memcpy(disc_tx, e.sent[i].txid, 12);
        }
    }
    EXPECT(tsnet_endpoint_pong(&e, now + 5 * MS, disc_tx, false, &res) && !res.answered);
    // Trusted now: the next CLI ping goes to the best alone, not over DERP.
    tsnet_endpoint_cli_ping(&e, now + 6 * MS, true, &act);
    EXPECT(act.n_ping == 1 && !act.ping[0].derp && act.ping[0].port == e.best.port);

    // No endpoints, a DERP home: over DERP alone, and the pong over DERP answers. It starts the heartbeat.
    tsnet_endpoint_init(&e);
    tsnet_endpoint_cli_ping(&e, now, true, &act);
    EXPECT(act.n_ping == 1 && act.ping[0].derp && e.heartbeat);
    EXPECT(tsnet_endpoint_pong(&e, now + 9 * MS, act.ping[0].txid, true, &res) && res.answered && res.via_derp);
    EXPECT(!e.best.valid); // DERP is no path
    // No endpoints and no DERP home: nothing to ping.
    tsnet_endpoint_init(&e);
    tsnet_endpoint_cli_ping(&e, now, false, &act);
    EXPECT(act.n_ping == 0);
}

int main(void)
{
    better_addr();
    ping_timeout();
    pong();
    send_and_heartbeat();
    want_full_ping();
    endpoints();
    call_me_maybe_filter();
    eviction_and_replay();
    caps();
    cli_ping();
    if (failures == 0) {
        printf("tsnet endpoint_test: ok\n");
    }
    return failures != 0;
}
