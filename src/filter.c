// The packet filter. See filter.h. Go: wgengine/filter (filter.go, match.go, tailcfg.go), net/packet's decode4,
// net/flowtrack, and tsmp.go's TailscaleRejectedHeader, all at v1.104.1.
#include "filter.h"
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "json.h"
#include "platform.h"

// An IPv4 set as an inclusive range: a prefix, "a-b", or "*". Go splits a range into prefixes; containment is the same.
typedef struct {
    uint32_t lo, hi;
} range_t;

typedef struct {
    range_t net;
    uint16_t first, last;
} dst_t;

// filtertype.Match, its IPv4 half (matchesFamily).
typedef struct {
    uint8_t protos[32]; // a bit per IP protocol number
    range_t *srcs;
    size_t n_srcs;
    dst_t *dsts;
    size_t n_dsts;
} match_t;

// flowtrack.Tuple, with when it was last used for the LRU.
typedef struct {
    uint32_t src, dst, used;
    uint16_t sport, dport;
    uint8_t proto;
} flow_t;

// flowtrack.Cache: grown as used, up to TSNET_FILTER_FLOWS.
typedef struct {
    flow_t *e;
    size_t n, cap;
    uint32_t clock;
} flowtab_t;

struct tsnet_filter {
    match_t *m;
    size_t n;
    range_t *local;
    size_t n_local;
    // The flow caches: one for peers' packets, one for jailed peers' (Go's jailed filter is a Filter of its own, with
    // its own flows, so a flow from before a peer was jailed doesn't let its packets in).
    flowtab_t flows, jflows;
};

enum {
    P_UNKNOWN = 0, // ipproto.Unknown: a packet that didn't parse
    P_ICMP = 1,
    P_IGMP = 2,
    P_TCP = 6,
    P_UDP = 17,
    P_ICMP6 = 58,
    P_TSMP = 99,
    P_SCTP = 132,
    P_FRAGMENT = 0x100, // ipproto.Fragment, internal: a fragment after the first (a real protocol 255 is unknown)
};

// packet.Parsed, for IPv4.
typedef struct {
    int proto;
    uint32_t src, dst;
    uint16_t sport, dport;
    uint8_t tcp_flags;
    size_t subofs;
    const uint8_t *b;
    size_t len;
} parsed_t;

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}

static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

// Parsed.Decode for IPv4 (decode4). Anything else is unknown, which `pre` drops.
static void decode(parsed_t *q, const uint8_t *b, size_t len)
{
    memset(q, 0, sizeof *q);
    q->b = b;
    q->len = len;
    if (len < 20 || b[0] >> 4 != 4) {
        return;
    }
    q->proto = b[9];
    size_t length = be16(b + 2);
    if (len < length) {
        q->proto = P_UNKNOWN; // cut off before its full length
        return;
    }
    q->src = be32(b + 12);
    q->dst = be32(b + 16);
    size_t subofs = (size_t)(b[0] & 0x0f) << 2;
    // A header shorter than 20 bytes (IHL < 5) isn't IPv4: its ports would be read from inside the IP header. Go reads
    // them anyway, and the OS stack drops the packet; here it's unknown, so dropped before it reaches lwIP.
    if (subofs < 20 || subofs > length) {
        q->proto = P_UNKNOWN;
        return;
    }
    q->subofs = subofs;
    const uint8_t *sub = b + subofs;
    size_t sublen = len - subofs;
    uint16_t frag = be16(b + 6);
    bool more = frag & 0x2000;
    uint16_t ofs = frag & 0x1fff;
    if (ofs != 0) {
        // A later fragment has no transport header. One that starts inside where it could be is refused
        // (minFragBlks: a 60-byte IP header and a 20-byte TCP header, in 8-byte blocks).
        q->proto = ofs < (60 + 20) / 8 ? P_UNKNOWN : P_FRAGMENT;
        return;
    }
    // The first fragment must hold a whole transport header (fragment confusion).
    switch (q->proto) {
    case P_ICMP:
        if (sublen < 4) {
            q->proto = P_UNKNOWN;
        }
        break;
    case P_IGMP:
        if (sublen < 8) {
            q->proto = P_UNKNOWN;
        }
        break;
    case P_TCP:
        if (sublen < 20) {
            q->proto = P_UNKNOWN;
            break;
        }
        q->sport = be16(sub);
        q->dport = be16(sub + 2);
        q->tcp_flags = sub[13];
        break;
    case P_UDP:
    case P_SCTP:
        if (sublen < (q->proto == P_UDP ? 8u : 12u)) {
            q->proto = P_UNKNOWN;
            break;
        }
        q->sport = be16(sub);
        q->dport = be16(sub + 2);
        break;
    case P_TSMP:
        if (more || sublen < 7) {
            q->proto = P_UNKNOWN;
        }
        break;
    case 255:
        q->proto = P_UNKNOWN;
        break;
    }
}

static bool icmp_type_is(const parsed_t *q, uint8_t a, uint8_t b, uint8_t c, bool code0)
{
    if (q->proto != P_ICMP || q->len < q->subofs + 8) {
        return false;
    }
    uint8_t t = q->b[q->subofs];
    return (t == a || t == b || t == c) && (!code0 || q->b[q->subofs + 1] == 0);
}

static bool is_echo_response(const parsed_t *q)
{
    return icmp_type_is(q, 0, 0, 0, true);
}

static bool is_error(const parsed_t *q)
{
    return icmp_type_is(q, 3, 11, 12, false); // unreachable, time exceeded, parameter problem
}

static bool is_tcp_syn(const parsed_t *q)
{
    return (q->tcp_flags & 0x12) == 0x02; // SYN without ACK
}

static bool in_ranges(const range_t *r, size_t n, uint32_t ip)
{
    for (size_t i = 0; i < n; i++) {
        if (ip >= r[i].lo && ip <= r[i].hi) {
            return true;
        }
    }
    return false;
}

static bool has_proto(const match_t *m, int proto)
{
    return proto >= 0 && proto < 256 && (m->protos[proto >> 3] >> (proto & 7) & 1);
}

// matches.match.
static bool match(const tsnet_filter_t *f, const parsed_t *q)
{
    for (size_t i = 0; i < f->n; i++) {
        const match_t *m = &f->m[i];
        if (!has_proto(m, q->proto) || !in_ranges(m->srcs, m->n_srcs, q->src)) {
            continue;
        }
        for (size_t d = 0; d < m->n_dsts; d++) {
            const dst_t *dst = &m->dsts[d];
            if (q->dst >= dst->net.lo && q->dst <= dst->net.hi && q->dport >= dst->first && q->dport <= dst->last) {
                return true;
            }
        }
    }
    return false;
}

// matches.matchIPsOnly: any rule from the source to the address, whatever its protocol and ports.
static bool match_ips_only(const tsnet_filter_t *f, const parsed_t *q)
{
    for (size_t i = 0; i < f->n; i++) {
        const match_t *m = &f->m[i];
        if (!in_ranges(m->srcs, m->n_srcs, q->src)) {
            continue;
        }
        for (size_t d = 0; d < m->n_dsts; d++) {
            if (q->dst >= m->dsts[d].net.lo && q->dst <= m->dsts[d].net.hi) {
                return true;
            }
        }
    }
    return false;
}

// matches.matchProtoAndIPsOnlyIfAllPorts.
static bool match_all_ports(const tsnet_filter_t *f, const parsed_t *q)
{
    for (size_t i = 0; i < f->n; i++) {
        const match_t *m = &f->m[i];
        if (!has_proto(m, q->proto) || !in_ranges(m->srcs, m->n_srcs, q->src)) {
            continue;
        }
        for (size_t d = 0; d < m->n_dsts; d++) {
            const dst_t *dst = &m->dsts[d];
            if (dst->first == 0 && dst->last == 65535 && q->dst >= dst->net.lo && q->dst <= dst->net.hi) {
                return true;
            }
        }
    }
    return false;
}

static flow_t *flow_find(flowtab_t *f, const flow_t *k)
{
    for (size_t i = 0; i < f->n; i++) {
        flow_t *e = &f->e[i];
        if (e->proto == k->proto && e->src == k->src && e->dst == k->dst && e->sport == k->sport &&
            e->dport == k->dport) {
            return e;
        }
    }
    return NULL;
}

// flowtrack.Cache.Get: a hit moves the flow to the front.
static bool flow_get(flowtab_t *f, const flow_t *k)
{
    flow_t *e = flow_find(f, k);
    if (e) {
        e->used = ++f->clock;
    }
    return e != NULL;
}

// flowtrack.Cache.Add: past TSNET_FILTER_FLOWS, the least recently used flow goes.
static void flow_add(flowtab_t *f, const flow_t *k)
{
    flow_t *e = flow_find(f, k);
    if (!e && f->n < f->cap) {
        e = &f->e[f->n++];
    } else if (!e && f->cap < TSNET_FILTER_FLOWS) {
        size_t cap = f->cap ? f->cap * 2 : 16;
        flow_t *grown = tsnet_realloc(f->e, cap * sizeof *grown);
        if (!grown) {
            return; // the reply will need a rule
        }
        f->e = grown;
        f->cap = cap;
        e = &f->e[f->n++];
    } else if (!e) {
        e = &f->e[0];
        for (size_t i = 1; i < f->n; i++) {
            if (f->e[i].used < e->used) {
                e = &f->e[i];
            }
        }
    }
    *e = *k;
    e->used = ++f->clock;
}

// Filter.pre: 1 accept, -1 drop, 0 no verdict yet.
static int pre(const parsed_t *q)
{
    if (q->len == 0) {
        return 1; // a WireGuard keepalive
    }
    if (q->len < 20 || q->proto == P_UNKNOWN) {
        return -1;
    }
    if (q->dst >> 28 == 0xe) {
        return -1; // multicast
    }
    if (q->dst >> 16 == 0xa9fe && q->dst != 0xa9fea9fe) {
        return -1; // link-local unicast, except GCP's metadata address 169.254.169.254
    }
    if (q->proto == P_FRAGMENT) {
        return 1;
    }
    return 0;
}

// runIn4. With `rules` false, no rule matches: NewShieldsUpFilter, the filter Go gives a jailed peer's packets.
static bool run_in(tsnet_filter_t *f, const uint8_t *pkt, size_t len, bool rules)
{
    parsed_t q;
    decode(&q, pkt, len);
    int r = pre(&q);
    if (r != 0) {
        return r > 0;
    }
    // A compromised peer could send packets for addresses this node never advertised.
    if (!in_ranges(f->local, f->n_local, q.dst)) {
        return false;
    }
    switch (q.proto) {
    case P_ICMP: // any open port opens ICMP
        return is_echo_response(&q) || is_error(&q) || (rules && match_ips_only(f, &q));
    case P_TCP:
        return !is_tcp_syn(&q) || (rules && match(f, &q)); // a new connection starts with a SYN
    case P_UDP:
    case P_SCTP: {
        flow_t k = {.proto = (uint8_t)q.proto, .src = q.src, .sport = q.sport, .dst = q.dst, .dport = q.dport};
        return flow_get(rules ? &f->flows : &f->jflows, &k) || (rules && match(f, &q));
    }
    case P_TSMP:
        return true;
    default:
        return rules && match_all_ports(f, &q);
    }
}

bool tsnet_filter_in(tsnet_filter_t *f, const uint8_t *pkt, size_t len)
{
    return run_in(f, pkt, len, true);
}

bool tsnet_filter_in_jailed(tsnet_filter_t *f, const uint8_t *pkt, size_t len)
{
    return run_in(f, pkt, len, false);
}

static bool run_out(flowtab_t *flows, const uint8_t *pkt, size_t len)
{
    parsed_t q;
    decode(&q, pkt, len);
    int r = pre(&q);
    if (r != 0) {
        return r > 0;
    }
    if (q.proto == P_UDP || q.proto == P_SCTP) {
        // The reply's tuple: source and destination swapped.
        flow_t k = {.proto = (uint8_t)q.proto, .src = q.dst, .sport = q.dport, .dst = q.src, .dport = q.sport};
        flow_add(flows, &k);
    }
    return true;
}

bool tsnet_filter_out(tsnet_filter_t *f, const uint8_t *pkt, size_t len)
{
    return run_out(&f->flows, pkt, len);
}

bool tsnet_filter_out_jailed(tsnet_filter_t *f, const uint8_t *pkt, size_t len)
{
    return run_out(&f->jflows, pkt, len);
}

// IP4Header.Marshal for a TSMP message of `len` bytes in all, from the packet's destination (this node) to its source.
static void tsmp_header(uint8_t *out, size_t len, const uint8_t *pkt, uint16_t ipid)
{
    memset(out, 0, 20);
    out[0] = 0x45;
    out[3] = (uint8_t)len; // total length; flags and offset stay 0
    out[4] = (uint8_t)(ipid >> 8), out[5] = (uint8_t)ipid;
    out[8] = 64; // TTL
    out[9] = P_TSMP;
    memcpy(out + 12, pkt + 16, 4);
    memcpy(out + 16, pkt + 12, 4);
    uint32_t s = 0;
    for (int i = 0; i < 20; i += 2) {
        s += be16(out + i);
    }
    while (s >> 16) {
        s = (s & 0xffff) + (s >> 16);
    }
    out[10] = (uint8_t)(~s >> 8);
    out[11] = (uint8_t)~s;
}

size_t tsnet_tsmp_pong(const uint8_t *pkt, size_t len, uint8_t out[TSNET_TSMP_PONG_LEN])
{
    parsed_t q;
    decode(&q, pkt, len);
    // AsTSMPPing: the payload (to the IP total length) is 'p' and 8 bytes.
    if (q.proto != P_TSMP || be16(pkt + 2) < q.subofs + 9 || pkt[q.subofs] != 'p') {
        return 0;
    }
    tsmp_header(out, TSNET_TSMP_PONG_LEN, pkt, (uint16_t)~be16(pkt + 4)); // ToResponse flips the IPID's bits
    out[20] = 'o';                                                        // TSMPTypePong
    memcpy(out + 21, pkt + q.subofs + 1, 8);
    out[29] = out[30] = 0; // PeerAPIPort
    return TSNET_TSMP_PONG_LEN;
}

size_t tsnet_tsmp_reject(const uint8_t *pkt, size_t len, char reason, uint8_t out[TSNET_TSMP_REJECT_LEN])
{
    parsed_t q;
    decode(&q, pkt, len);
    if (q.proto != P_TCP || !(q.tcp_flags & 0x02)) {
        return 0;
    }
    tsmp_header(out, TSNET_TSMP_REJECT_LEN, pkt, 0);
    uint8_t *t = out + 20;
    t[0] = '!'; // TSMPTypeRejectedConn
    t[1] = P_TCP;
    t[2] = (uint8_t)reason;
    t[3] = (uint8_t)(q.sport >> 8), t[4] = (uint8_t)q.sport; // the rejected flow's own ports
    t[5] = (uint8_t)(q.dport >> 8), t[6] = (uint8_t)q.dport;
    return TSNET_TSMP_REJECT_LEN;
}

// ---- the rules ----

static void free_matches(tsnet_filter_t *f)
{
    for (size_t i = 0; i < f->n; i++) {
        free(f->m[i].srcs);
        free(f->m[i].dsts);
    }
    free(f->m);
    f->m = NULL;
    f->n = 0;
}

static range_t ip4_range(const uint8_t ip[4], int bits)
{
    uint32_t a = be32(ip), mask = bits == 0 ? 0 : 0xffffffffu << (32 - bits);
    return (range_t){a & mask, (a & mask) | ~mask};
}

// parseIPSet. Returns 1 with an IPv4 range in *r, 0 for a set with nothing IPv4 in it (IPv6, or "cap:"), -1 if it
// doesn't parse. "*" is every IPv4 address (and every IPv6 one, which this skips). *cap says it was "cap:".
static int parse_set(const char *s, range_t *r, bool *cap)
{
    *cap = false;
    if (strcmp(s, "*") == 0) {
        *r = (range_t){0, 0xffffffffu};
        return 1;
    }
    if (strncmp(s, "cap:", 4) == 0) {
        *cap = true;
        return 0;
    }
    if (strchr(s, '/')) {
        tsnet_prefix_t p;
        if (tsnet_prefix_parse(&p, s) != 0) {
            return -1;
        }
        if (p.ip.is6) {
            return 0;
        }
        *r = ip4_range(p.ip.ip, p.bits);
        return be32(p.ip.ip) == r->lo ? 1 : -1; // "contains non-network bits set"
    }
    const char *dash = strchr(s, '-');
    if (dash && !strchr(dash + 1, '-')) {
        char a[64];
        size_t n = (size_t)(dash - s);
        if (n >= sizeof a) {
            return -1;
        }
        memcpy(a, s, n);
        a[n] = '\0';
        tsnet_ip_t lo, hi;
        if (tsnet_ip_parse(&lo, a) != 0 || tsnet_ip_parse(&hi, dash + 1) != 0 || lo.is6 != hi.is6) {
            return -1;
        }
        if (lo.is6) {
            return memcmp(lo.ip, hi.ip, 16) <= 0 ? 0 : -1;
        }
        *r = (range_t){be32(lo.ip), be32(hi.ip)};
        return r->lo <= r->hi ? 1 : -1; // "invalid IP range"
    }
    tsnet_ip_t ip;
    if (tsnet_ip_parse(&ip, s) != 0) {
        return -1;
    }
    if (ip.is6) {
        return 0;
    }
    *r = ip4_range(ip.ip, 32);
    return 1;
}

static bool has_bits(const cJSON *o, const char *name)
{
    const cJSON *b = cJSON_GetObjectItemCaseSensitive(o, name);
    return b && !cJSON_IsNull(b) && !(cJSON_IsArray(b) && cJSON_GetArraySize(b) == 0);
}

// MatchesFromFilterRules, then matchesFamily's IPv4 half. Returns 0, -1 if an entry didn't parse (it's skipped), or -2
// for SrcBits or DstPorts[].Bits (then no rules).
static int parse_rules(tsnet_filter_t *f, const cJSON *rules)
{
    int err = 0;
    const cJSON *rule;
    cJSON_ArrayForEach(rule, rules)
    {
        if (has_bits(rule, "SrcBits")) {
            return -2;
        }
        const cJSON *srcs = cJSON_GetObjectItemCaseSensitive(rule, "SrcIPs");
        const cJSON *dsts = cJSON_GetObjectItemCaseSensitive(rule, "DstPorts");
        const cJSON *protos = cJSON_GetObjectItemCaseSensitive(rule, "IPProto");
        match_t m = {0};
        int n_srcs = cJSON_GetArraySize(srcs), n_dsts = cJSON_GetArraySize(dsts);
        m.srcs = tsnet_malloc(sizeof *m.srcs * (size_t)(n_srcs ? n_srcs : 1));
        m.dsts = tsnet_malloc(sizeof *m.dsts * (size_t)(n_dsts ? n_dsts : 1));
        match_t *grown = tsnet_realloc(f->m, sizeof *grown * (f->n + 1));
        if (!m.srcs || !m.dsts || !grown) {
            free(m.srcs);
            free(m.dsts);
            if (grown) {
                f->m = grown;
            }
            return -1;
        }
        f->m = grown;
        if (cJSON_GetArraySize(protos) == 0) {
            static const int defaults[] = {P_TCP, P_UDP, P_ICMP, P_ICMP6}; // defaultProtos
            for (size_t i = 0; i < sizeof defaults / sizeof defaults[0]; i++) {
                m.protos[defaults[i] >> 3] |= (uint8_t)(1 << (defaults[i] & 7));
            }
        }
        const cJSON *e;
        cJSON_ArrayForEach(e, protos)
        {
            if (cJSON_IsNumber(e) && e->valueint >= 0 && e->valueint <= 0xff) {
                m.protos[e->valueint >> 3] |= (uint8_t)(1 << (e->valueint & 7));
            }
        }
        cJSON_ArrayForEach(e, srcs)
        {
            range_t r;
            bool cap;
            int ok = cJSON_IsString(e) ? parse_set(e->valuestring, &r, &cap) : -1;
            if (ok < 0) {
                err = -1;
            } else if (ok > 0) {
                m.srcs[m.n_srcs++] = r;
            }
        }
        cJSON_ArrayForEach(e, dsts)
        {
            if (has_bits(e, "Bits")) {
                free(m.srcs);
                free(m.dsts);
                return -2;
            }
            const cJSON *ip = cJSON_GetObjectItemCaseSensitive(e, "IP");
            const cJSON *ports = cJSON_GetObjectItemCaseSensitive(e, "Ports");
            const cJSON *first = cJSON_GetObjectItemCaseSensitive(ports, "First");
            const cJSON *last = cJSON_GetObjectItemCaseSensitive(ports, "Last");
            range_t r;
            bool cap;
            int ok = cJSON_IsString(ip) ? parse_set(ip->valuestring, &r, &cap) : -1;
            if (ok < 0 || cap) {
                err = -1; // a capability can't be a destination
            } else if (ok > 0) {
                m.dsts[m.n_dsts++] = (dst_t){r, (uint16_t)(cJSON_IsNumber(first) ? first->valueint : 0),
                                             (uint16_t)(cJSON_IsNumber(last) ? last->valueint : 0)};
            }
        }
        if (m.n_srcs > 0 && m.n_dsts > 0) {
            f->m[f->n++] = m;
        } else {
            free(m.srcs);
            free(m.dsts);
        }
    }
    return err;
}

int tsnet_filter_set(tsnet_filter_t *f, const char *rules_json, const tsnet_prefix_t *local, size_t n_local)
{
    free_matches(f);
    free(f->local);
    f->local = NULL;
    f->n_local = 0;
    if (n_local > 0 && !(f->local = tsnet_malloc(sizeof *f->local * n_local))) {
        return -1;
    }
    for (size_t i = 0; i < n_local; i++) {
        if (!local[i].ip.is6) {
            f->local[f->n_local++] = ip4_range(local[i].ip.ip, local[i].bits);
        }
    }
    if (!rules_json) {
        return 0;
    }
    cJSON *rules = tsnet_json_parse(rules_json, rules_json ? strlen(rules_json) : 0);
    int r = cJSON_IsArray(rules) ? parse_rules(f, rules) : -1;
    cJSON_Delete(rules);
    if (r == -2) {
        free_matches(f);
        tsnet_log(TSNET_LOG_WARN, "filter: SrcBits or DstPorts Bits from control: no rules");
    } else if (r < 0) {
        tsnet_log(TSNET_LOG_WARN, "filter: some rule entries didn't parse and were skipped");
    }
    return r < 0 ? -1 : 0;
}

tsnet_filter_t *tsnet_filter_new(void)
{
    return tsnet_calloc(1, sizeof(tsnet_filter_t));
}

void tsnet_filter_free(tsnet_filter_t *f)
{
    if (!f) {
        return;
    }
    free_matches(f);
    free(f->local);
    free(f->flows.e);
    free(f->jflows.e);
    free(f);
}
