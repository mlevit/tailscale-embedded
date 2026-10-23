// Host test of the packet filter, ported from wgengine/filter/filter_test.go at v1.104.1: TestFilter's IPv4
// rows in its order (with runOut after each, so its UDP state builds up as Go's does), TestUDPState, TestPreFilter,
// TestParseIPSet, TestMatchesFromFilterRules and TestMatchesMatchProtoAndIPsOnlyIfAllPorts, through the rules' JSON.
// Then what's tsnet's own: the TSMP reject's and pong's bytes (tsmp.go's Marshal), the flow LRU, rules that keep the
// flows, and SrcBits leaving no rules.
#include <stdio.h>
#include <string.h>
#include "filter.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

enum { TCP = 6, UDP = 17, ICMP = 1, SCTP = 132, ALLOWED = 116, DENIED = 127 }; // testAllowedProto, testDeniedProto

// An IPv4 packet from src:sport to dst:dport: TCP with SYN set (as Go's parsed() sets it), UDP, an ICMP echo request,
// SCTP, or any other protocol with no transport header.
static size_t pkt(uint8_t *b, int proto, const char *src, const char *dst, uint16_t sport, uint16_t dport)
{
    size_t t = proto == TCP ? 20 : proto == UDP || proto == ICMP ? 8 : proto == SCTP ? 12 : 0;
    memset(b, 0, 20 + t);
    tsnet_ip_t s, d;
    tsnet_ip_parse(&s, src);
    tsnet_ip_parse(&d, dst);
    b[0] = 0x45;
    b[3] = (uint8_t)(20 + t);
    b[8] = 64;
    b[9] = (uint8_t)proto;
    memcpy(b + 12, s.ip, 4);
    memcpy(b + 16, d.ip, 4);
    uint8_t *x = b + 20;
    if (proto == ICMP) {
        x[0] = 8;
    } else if (t) {
        x[0] = (uint8_t)(sport >> 8), x[1] = (uint8_t)sport;
        x[2] = (uint8_t)(dport >> 8), x[3] = (uint8_t)dport;
        if (proto == TCP) {
            x[12] = 0x50;
            x[13] = 0x02; // SYN
        }
    }
    return 20 + t;
}

static bool in(tsnet_filter_t *f, int proto, const char *src, const char *dst, uint16_t sport, uint16_t dport)
{
    uint8_t b[64];
    return tsnet_filter_in(f, b, pkt(b, proto, src, dst, sport, dport));
}

static bool out(tsnet_filter_t *f, int proto, const char *src, const char *dst, uint16_t sport, uint16_t dport)
{
    uint8_t b[64];
    return tsnet_filter_out(f, b, pkt(b, proto, src, dst, sport, dport));
}

static size_t local_nets(tsnet_prefix_t *p, const char *const *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        tsnet_prefix_parse(&p[i], s[i]);
    }
    return n;
}

// newFilter's matches, as the control server's JSON.
static const char *RULES =
    "[{\"SrcIPs\":[\"8.1.1.1\",\"8.2.2.2\"],\"DstPorts\":[{\"IP\":\"1.2.3.4\",\"Ports\":{\"First\":22,\"Last\":22}},"
    "{\"IP\":\"5.6.7.8\",\"Ports\":{\"First\":23,\"Last\":24}}]},"
    "{\"SrcIPs\":[\"9.1.1.1\",\"9.2.2.2\"],\"IPProto\":[132],\"DstPorts\":[{\"IP\":\"1.2.3.4\",\"Ports\":{\"First\":22,"
    "\"Last\":22}},{\"IP\":\"5.6.7.8\",\"Ports\":{\"First\":23,\"Last\":24}}]},"
    "{\"SrcIPs\":[\"8.1.1.1\",\"8.2.2.2\"],\"DstPorts\":[{\"IP\":\"5.6.7.8\",\"Ports\":{\"First\":27,\"Last\":28}}]},"
    "{\"SrcIPs\":[\"2.2.2.2\"],\"DstPorts\":[{\"IP\":\"8.1.1.1\",\"Ports\":{\"First\":22,\"Last\":22}}]},"
    "{\"SrcIPs\":[\"0.0.0.0/0\"],\"DstPorts\":[{\"IP\":\"100.122.98.50\",\"Ports\":{\"First\":0,\"Last\":65535}}]},"
    "{\"SrcIPs\":[\"0.0.0.0/0\"],\"DstPorts\":[{\"IP\":\"0.0.0.0/0\",\"Ports\":{\"First\":443,\"Last\":443}}]},"
    "{\"SrcIPs\":[\"153.1.1.1\",\"153.1.1.2\",\"153.3.3.3\"],\"DstPorts\":[{\"IP\":\"1.2.3.4\",\"Ports\":{\"First\":999,"
    "\"Last\":999}}]},"
    "{\"SrcIPs\":[\"::1\",\"::2\"],\"DstPorts\":[{\"IP\":\"2001::1\",\"Ports\":{\"First\":22,\"Last\":22}},"
    "{\"IP\":\"2001::2\",\"Ports\":{\"First\":22,\"Last\":22}}]},"
    "{\"SrcIPs\":[\"::/0\"],\"DstPorts\":[{\"IP\":\"::/0\",\"Ports\":{\"First\":443,\"Last\":443}}]},"
    "{\"SrcIPs\":[\"0.0.0.0/0\"],\"IPProto\":[116],\"DstPorts\":[{\"IP\":\"0.0.0.0/0\",\"Ports\":{\"First\":0,"
    "\"Last\":65535}}]},"
    "{\"SrcIPs\":[\"::/0\"],\"IPProto\":[116],\"DstPorts\":[{\"IP\":\"::/0\",\"Ports\":{\"First\":0,\"Last\":65535}}]},"
    "{\"SrcIPs\":[\"cap:cap-hit-1234-ssh\"],\"DstPorts\":[{\"IP\":\"1.2.3.4\",\"Ports\":{\"First\":22,\"Last\":22}}]}]";

static const char *const LOCAL[] = {"100.122.98.50/32", "1.2.3.4/32", "5.6.7.8/32", "102.102.102.102/32",
                                    "119.119.119.119/32", "8.1.0.0/16", "2001::/16"};

static tsnet_filter_t *new_filter(void)
{
    tsnet_filter_t *f = tsnet_filter_new();
    tsnet_prefix_t local[7];
    EXPECT(tsnet_filter_set(f, RULES, local, local_nets(local, LOCAL, 7)) == 0);
    return f;
}

typedef struct {
    bool want;
    int proto;
    const char *src, *dst;
    uint16_t sport, dport;
} row_t;

static void test_filter(void)
{
    tsnet_filter_t *f = new_filter();
    static const row_t rows[] = {
        // allow 8.1.1.1 => 1.2.3.4:22
        {true, TCP, "8.1.1.1", "1.2.3.4", 999, 22},
        {true, ICMP, "8.1.1.1", "1.2.3.4", 0, 0},
        {false, TCP, "8.1.1.1", "1.2.3.4", 0, 0},
        {true, TCP, "8.1.1.1", "1.2.3.4", 0, 22},
        {false, TCP, "8.1.1.1", "1.2.3.4", 0, 21},
        // allow 8.2.2.2. => 1.2.3.4:22
        {true, TCP, "8.2.2.2", "1.2.3.4", 0, 22},
        {false, TCP, "8.2.2.2", "1.2.3.4", 0, 23},
        {false, TCP, "8.3.3.3", "1.2.3.4", 0, 22},
        // allow 8.1.1.1 => 5.6.7.8:23-24
        {true, TCP, "8.1.1.1", "5.6.7.8", 0, 23},
        {true, TCP, "8.1.1.1", "5.6.7.8", 0, 24},
        {false, TCP, "8.1.1.3", "5.6.7.8", 0, 24},
        {false, TCP, "8.1.1.1", "5.6.7.8", 0, 22},
        // allow * => *:443
        {true, TCP, "17.34.51.68", "8.1.34.51", 0, 443},
        {false, TCP, "17.34.51.68", "8.1.34.51", 0, 444},
        // allow * => 100.122.98.50:*
        {true, TCP, "17.34.51.68", "100.122.98.50", 0, 999},
        {true, TCP, "17.34.51.68", "100.122.98.50", 0, 0},
        // localNets prefilter: accepted by policy filter, but unexpected dst IP
        {false, TCP, "8.1.1.1", "16.32.48.64", 0, 443},
        // Don't allow protocols not specified by filter
        {false, SCTP, "8.1.1.1", "1.2.3.4", 999, 22},
        // But SCTP is allowed for 9.1.1.1
        {true, SCTP, "9.1.1.1", "1.2.3.4", 999, 22},
        // Unknown protocol is allowed if all its ports are allowed.
        {true, ALLOWED, "1.2.3.4", "5.6.7.8", 0, 0},
        {false, DENIED, "1.2.3.4", "5.6.7.8", 0, 0},
        // Node capabilities: Go accepts 10.0.0.1 (it has the cap). tsnet's shortcut matches no cap, so both drop.
        {false, TCP, "10.0.0.1", "1.2.3.4", 30000, 22},
        {false, TCP, "10.0.0.2", "1.2.3.4", 30000, 22},
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        const row_t *r = &rows[i];
        if (in(f, r->proto, r->src, r->dst, r->sport, r->dport) != r->want) {
            printf("TestFilter #%zu: RunIn got %d\n", i, !r->want);
            failures++;
        }
        int proto = r->proto;
        if (proto == TCP) { // TCP and UDP are treated equivalently in the filter
            proto = UDP;
            if (in(f, proto, r->src, r->dst, r->sport, r->dport) != r->want) {
                printf("TestFilter #%zu: RunIn (UDP) got %d\n", i, !r->want);
                failures++;
            }
        }
        out(f, proto, r->src, r->dst, r->sport, r->dport); // update UDP state
    }
    tsnet_filter_free(f);
}

static void test_udp_state(void)
{
    tsnet_filter_t *f = new_filter();
    EXPECT(!in(f, UDP, "119.119.119.119", "102.102.102.102", 4242, 4343)); // unsolicited UDP traffic gets dropped
    EXPECT(out(f, UDP, "102.102.102.102", "119.119.119.119", 4343, 4242)); // we talk to that peer
    EXPECT(in(f, UDP, "119.119.119.119", "102.102.102.102", 4242, 4343));  // now the same packet is allowed back
    tsnet_filter_free(f);
}

static void test_pre_filter(void)
{
    tsnet_filter_t *f = tsnet_filter_new(); // NewAllowNone: no rules, no local addresses
    uint8_t b[64];
    EXPECT(tsnet_filter_in(f, b, 0)); // empty: a keepalive
    EXPECT(!tsnet_filter_in(f, (const uint8_t *)"short", 5));
    size_t n = pkt(b, UDP, "8.8.8.8", "8.8.8.8", 53, 53);
    memset(b + n, 0, 12); // raw4default's 12-byte payload
    n += 12;
    b[3] = (uint8_t)n;
    EXPECT(!tsnet_filter_in(f, b, 10)); // short-junk
    EXPECT(!tsnet_filter_in(f, b, 21)); // long-junk: cut off before its length
    b[7] = 255;                          // fragment: a later fragment's offset
    EXPECT(tsnet_filter_in(f, b, 40));
    b[7] = 9; // an offset that could be inside a transport header: unknown
    EXPECT(!tsnet_filter_in(f, b, 40));
    b[7] = 0;
    EXPECT(!tsnet_filter_in(f, b, n)); // no verdict from pre, and nothing is local: dropped
    tsnet_filter_free(f);
}

// parseIPSet through a rule: SrcIPs `set` to 1.2.3.4:22.
static tsnet_filter_t *src_rule(const char *set, int *ret)
{
    char json[256];
    snprintf(json, sizeof json,
             "[{\"SrcIPs\":[\"%s\"],\"DstPorts\":[{\"IP\":\"1.2.3.4\",\"Ports\":{\"First\":22,\"Last\":22}}]}]", set);
    tsnet_filter_t *f = tsnet_filter_new();
    tsnet_prefix_t local;
    tsnet_prefix_parse(&local, "1.2.3.4/32");
    *ret = tsnet_filter_set(f, json, &local, 1);
    return f;
}

static void test_parse_ip_set(void)
{
    static const struct {
        const char *set, *yes, *no;
        int ret;
    } cases[] = {
        {"8.8.8.8", "8.8.8.8", "8.8.8.9", 0},
        {"8.8.8.0/24", "8.8.8.255", "8.8.9.0", 0},
        {"8.8.8.8/24", NULL, "8.8.8.8", -1}, // contains non-network bits set
        {"1.0.0.0-1.255.255.255", "1.128.0.0", "2.0.0.0", 0},
        {"1.0.0.0-2.1.2.3", "2.1.2.3", "2.1.2.4", 0},
        {"1.0.0.2-1.0.0.1", NULL, "1.0.0.1", -1}, // invalid IP range
        {"*", "203.0.113.7", NULL, 0},
        {"1::2", NULL, "1.0.0.2", 0},                 // IPv6: no IPv4 half, so no rule
        {"cap:people-in-8.8.8.0/24", NULL, "8.8.8.1", 0}, // a cap ("/" after "cap:" doesn't make it a prefix)
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int ret;
        tsnet_filter_t *f = src_rule(cases[i].set, &ret);
        if (ret != cases[i].ret || (cases[i].yes && !in(f, TCP, cases[i].yes, "1.2.3.4", 1, 22)) ||
            (cases[i].no && in(f, TCP, cases[i].no, "1.2.3.4", 1, 22))) {
            printf("TestParseIPSet %s: wrong\n", cases[i].set);
            failures++;
        }
        tsnet_filter_free(f);
    }
}

static void test_matches_from_rules(void)
{
    tsnet_filter_t *f = tsnet_filter_new();
    tsnet_prefix_t local;
    tsnet_prefix_parse(&local, "1.2.3.4/32");
    // implicit_protos: TCP, UDP and ICMP
    EXPECT(tsnet_filter_set(f, "[{\"SrcIPs\":[\"100.64.1.1\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":22,"
                               "\"Last\":22}}]}]", &local, 1) == 0);
    EXPECT(in(f, TCP, "100.64.1.1", "1.2.3.4", 1, 22) && in(f, UDP, "100.64.1.1", "1.2.3.4", 1, 22));
    EXPECT(in(f, ICMP, "100.64.1.1", "1.2.3.4", 0, 0) && !in(f, SCTP, "100.64.1.1", "1.2.3.4", 1, 22));
    // explicit_protos: TCP only
    EXPECT(tsnet_filter_set(f, "[{\"IPProto\":[6],\"SrcIPs\":[\"100.64.1.1\"],\"DstPorts\":[{\"IP\":\"1.2.0.0/16\","
                               "\"Ports\":{\"First\":22,\"Last\":22}}]}]", &local, 1) == 0);
    EXPECT(in(f, TCP, "100.64.1.1", "1.2.3.4", 1, 22) && !in(f, UDP, "100.64.1.1", "1.2.3.4", 1, 22));
    // ICMP passes if any rule reaches the address, whatever its protocol (matchIPsOnly)
    EXPECT(in(f, ICMP, "100.64.1.1", "1.2.3.4", 0, 0) && !in(f, ICMP, "100.64.1.2", "1.2.3.4", 0, 0));
    // A rule with SrcBits: no rules at all
    EXPECT(tsnet_filter_set(f, "[{\"SrcIPs\":[\"*\"],\"SrcBits\":[32],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{"
                               "\"First\":0,\"Last\":65535}}]}]", &local, 1) == -1);
    EXPECT(!in(f, TCP, "100.64.1.1", "1.2.3.4", 1, 22));
    tsnet_filter_free(f);
}

static void test_all_ports(void)
{
    tsnet_filter_t *f = tsnet_filter_new();
    tsnet_prefix_t local;
    tsnet_prefix_parse(&local, "5.6.7.8/32");
    EXPECT(tsnet_filter_set(f, "[{\"SrcIPs\":[\"0.0.0.0/0\"],\"IPProto\":[116],\"DstPorts\":[{\"IP\":\"0.0.0.0/0\","
                               "\"Ports\":{\"First\":0,\"Last\":65535}}]}]", &local, 1) == 0);
    EXPECT(in(f, ALLOWED, "1.2.3.4", "5.6.7.8", 0, 0));  // all_ports_okay
    EXPECT(!in(f, DENIED, "1.2.3.4", "5.6.7.8", 0, 0));  // all_ports_match_but_packet_wrong_proto
    EXPECT(tsnet_filter_set(f, "[{\"SrcIPs\":[\"0.0.0.0/0\"],\"IPProto\":[116],\"DstPorts\":[{\"IP\":\"0.0.0.0/0\","
                               "\"Ports\":{\"First\":12345,\"Last\":12345}}]}]", &local, 1) == 0);
    EXPECT(!in(f, ALLOWED, "1.2.3.4", "5.6.7.8", 0, 0)); // ports_requirements_dont_match_unknown_proto
    tsnet_filter_free(f);
}

static void test_reject(void)
{
    uint8_t b[64], r[TSNET_TSMP_REJECT_LEN];
    size_t n = pkt(b, TCP, "100.64.0.2", "100.64.0.1", 40000, 7);
    static const uint8_t want[TSNET_TSMP_REJECT_LEN] = {
        0x45, 0, 0, 27, 0, 0, 0, 0, 64, 99, 0xb1, 0xfd, 100, 64, 0, 1, 100, 64, 0, 2, // IPv4, TSMP, this node to the peer
        '!', 6, 'A', 0x9c, 0x40, 0, 7,                                                // rejected, TCP, ACLs, 40000, 7
    };
    EXPECT(tsnet_tsmp_reject(b, n, TSNET_REJECT_ACLS, r) == TSNET_TSMP_REJECT_LEN && memcmp(r, want, sizeof want) == 0);
    n = pkt(b, UDP, "100.64.0.2", "100.64.0.1", 40000, 7);
    EXPECT(tsnet_tsmp_reject(b, n, TSNET_REJECT_ACLS, r) == 0);
}

// A TSMP ping's pong (TSMPPongReply.Marshal after IP4Header.ToResponse).
static void test_pong(void)
{
    uint8_t b[64], r[TSNET_TSMP_PONG_LEN];
    size_t n = pkt(b, 99, "100.64.0.2", "100.64.0.1", 0, 0);
    b[3] = (uint8_t)(n + 9);
    b[4] = 0x12, b[5] = 0x34; // the request's IPID
    const uint8_t ping[9] = {'p', 1, 2, 3, 4, 5, 6, 7, 8};
    memcpy(b + n, ping, 9);
    static const uint8_t want[TSNET_TSMP_PONG_LEN] = {
        0x45, 0, 0, 31, 0xed, 0xcb, 0, 0, 64, 99, 0xc4, 0x2d, 100, 64, 0, 1, 100, 64, 0, 2, // the IPID's bits flipped
        'o', 1, 2, 3, 4, 5, 6, 7, 8, 0, 0,                                                   // the data, PeerAPI port 0
    };
    EXPECT(tsnet_tsmp_pong(b, n + 9, r) == TSNET_TSMP_PONG_LEN && memcmp(r, want, sizeof want) == 0);
    b[n] = 'o'; // a pong isn't answered
    EXPECT(tsnet_tsmp_pong(b, n + 9, r) == 0);
    b[n] = 'p';
    b[3] = (uint8_t)(n + 8); // too short for a ping
    EXPECT(tsnet_tsmp_pong(b, n + 8, r) == 0);
}

// The flow cache: an LRU of TSNET_FILTER_FLOWS, kept across rule updates.
static void test_flows(void)
{
    tsnet_filter_t *f = tsnet_filter_new();
    tsnet_prefix_t local;
    tsnet_prefix_parse(&local, "100.64.0.1/32");
    tsnet_filter_set(f, NULL, &local, 1);
    for (int i = 0; i < TSNET_FILTER_FLOWS; i++) {
        out(f, UDP, "100.64.0.1", "100.64.0.2", 1000, (uint16_t)(2000 + i));
    }
    EXPECT(in(f, UDP, "100.64.0.2", "100.64.0.1", 2000, 1000)); // the oldest, now the most recently used
    out(f, UDP, "100.64.0.1", "100.64.0.2", 1000, 9999);         // one past the cap: the least recently used goes
    EXPECT(!in(f, UDP, "100.64.0.2", "100.64.0.1", 2001, 1000));
    EXPECT(in(f, UDP, "100.64.0.2", "100.64.0.1", 2000, 1000) && in(f, UDP, "100.64.0.2", "100.64.0.1", 9999, 1000));
    tsnet_filter_set(f, "[]", &local, 1); // new rules keep the flows
    EXPECT(in(f, UDP, "100.64.0.2", "100.64.0.1", 2002, 1000));
    EXPECT(!in(f, UDP, "100.64.0.2", "100.64.0.1", 2002, 1001)); // another flow
    tsnet_filter_free(f);
}

int main(void)
{
    test_filter();
    test_udp_state();
    test_pre_filter();
    test_parse_ip_set();
    test_matches_from_rules();
    test_all_ports();
    test_reject();
    test_pong();
    test_flows();
    if (failures == 0) {
        printf("tsnet filter_test: ok\n");
    }
    return failures != 0;
}
