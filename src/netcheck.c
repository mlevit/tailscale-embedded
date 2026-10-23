// netcheck. See netcheck.h; the Go is net/netcheck/netcheck.go.
#include "platform.h"
#include "netcheck.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "derphttp.h"
#include "stun.h"

#define MAX_PROBES 160 // a full plan is 3 per region: 84 for Tailscale's 28 regions on 2026-10-23
#define ENOUGH_REGIONS 3 // enoughRegions
#define MAX_HTTPS 4      // latency checks at once (Go starts one per region together; each holds a TLS connection here)

typedef struct {
    tsnet_nc_probe_t p;
    bool fired, inflight;
    uint8_t txid[TSNET_STUN_TXID_LEN];
    uint64_t sent_us;
} probe_t;

struct tsnet_netcheck {
    tsnet_netcheck_cfg_t cfg;
    tsnet_nc_history_t hist;
    bool next_full, have_full, have_last;
    uint64_t last_full_ms;
    tsnet_netcheck_report_t last;
    // The report under way.
    bool running, incremental, stun_over;
    tsnet_derp_map_t *dm;
    uint64_t start_ms;
    probe_t probes[MAX_PROBES];
    size_t n_probes;
    tsnet_nc_probe_t plan[MAX_PROBES]; // the plan, before it becomes probes (kept off the stack)
    int done_sets[TSNET_NC_REGIONS]; // regions whose probe set is finished (cancelSet)
    size_t n_done_sets;
    tsnet_netcheck_report_t cur;
    bool enough_armed;
    uint64_t enough_at_us;
    int https_need[TSNET_NC_REGIONS]; // regions still to measure over HTTPS
    size_t n_need, next_need;
    tsnet_derphttp_t *https[MAX_HTTPS];
    int https_region[MAX_HTTPS];
};

static const tsnet_derp_region_t *region_of(const tsnet_derp_map_t *dm, int id)
{
    for (size_t i = 0; dm && i < dm->n_regions; i++) {
        if (dm->regions[i].region_id == id) {
            return &dm->regions[i];
        }
    }
    return NULL;
}

tsnet_netcheck_t *tsnet_netcheck_new(const tsnet_netcheck_cfg_t *cfg)
{
    tsnet_netcheck_t *nc = tsnet_calloc(1, sizeof *nc);
    if (nc) {
        nc->cfg = *cfg;
    }
    return nc;
}

static void stop_https(tsnet_netcheck_t *nc)
{
    for (int i = 0; i < MAX_HTTPS; i++) {
        tsnet_derphttp_free(nc->https[i]);
        nc->https[i] = NULL;
    }
}

void tsnet_netcheck_free(tsnet_netcheck_t *nc)
{
    if (!nc) {
        return;
    }
    stop_https(nc);
    tsnet_derp_map_free(nc->dm);
    free(nc);
}

void tsnet_netcheck_make_next_full(tsnet_netcheck_t *nc)
{
    nc->next_full = true;
}

bool tsnet_netcheck_running(const tsnet_netcheck_t *nc)
{
    return nc->running;
}

const tsnet_netcheck_report_t *tsnet_netcheck_report(const tsnet_netcheck_t *nc)
{
    return nc->have_last ? &nc->last : NULL;
}

int tsnet_netcheck_start(tsnet_netcheck_t *nc, const tsnet_derp_map_t *dm)
{
    if (nc->running || !dm) {
        return -1; // "invalid concurrent call to GetReport", "DERP map is nil"
    }
    nc->dm = tsnet_derp_map_copy(dm);
    if (!nc->dm) {
        return -1;
    }
    uint64_t now = tsnet_now_ms();
    int preferred = nc->have_last ? nc->last.base.preferred : 0;
    bool full = nc->next_full || !nc->have_full || now - nc->last_full_ms > TSNET_NC_FULL_MS;
    if (full) {
        nc->next_full = false;
        nc->have_full = true;
        nc->last_full_ms = now;
    }
    nc->incremental = !full && nc->have_last;
    tsnet_nc_probe_t *plan = nc->plan;
    size_t n = tsnet_nc_plan(nc->dm, nc->incremental ? &nc->last.base : NULL, preferred, plan, MAX_PROBES);
    if (n == MAX_PROBES || dm->n_regions > TSNET_NC_REGIONS) {
        tsnet_log(TSNET_LOG_WARN, "netcheck: the DERP map's %zu regions are more than this report can probe or keep",
                  dm->n_regions);
    }
    memset(nc->probes, 0, sizeof nc->probes);
    for (size_t i = 0; i < n; i++) {
        nc->probes[i].p = plan[i];
    }
    nc->n_probes = n;
    nc->n_done_sets = 0;
    memset(&nc->cur, 0, sizeof nc->cur);
    nc->cur.mapping_varies = -1;
    nc->enough_armed = false;
    nc->stun_over = false;
    nc->n_need = nc->next_need = 0;
    nc->start_ms = now;
    nc->running = true;
    tsnet_log(TSNET_LOG_DEBUG, "netcheck: starting a %s report, %zu probes", full ? "full" : "incremental", n);
    return 0;
}

static bool set_done(const tsnet_netcheck_t *nc, int region)
{
    for (size_t i = 0; i < nc->n_done_sets; i++) {
        if (nc->done_sets[i] == region) {
            return true;
        }
    }
    return false;
}

// cancelSet: the region's other probes aren't sent.
static void cancel_set(tsnet_netcheck_t *nc, int region)
{
    if (!set_done(nc, region) && nc->n_done_sets < TSNET_NC_REGIONS) {
        nc->done_sets[nc->n_done_sets++] = region;
    }
}

// probeWouldHelp: a region with no latency yet, or a second server's view of our address (MappingVariesByDestIP).
static bool would_help(const tsnet_netcheck_t *nc, int region)
{
    return tsnet_nc_latency(&nc->cur.base, region) == 0 || nc->cur.mapping_varies == -1;
}

// nodeAddrPort for IPv4: the STUN port (0 is 3478, negative turns STUN off), STUNTestIP, IPv4, or the host name.
static bool node_addr(const tsnet_derp_node_t *n, uint8_t ip[16], uint16_t *port)
{
    if (n->stun_port < 0 || n->stun_port > 65535) {
        return false;
    }
    *port = n->stun_port ? (uint16_t)n->stun_port : 3478;
    if (n->stun_test_ip[0]) {
        return strchr(n->stun_test_ip, ':') == NULL && tsnet_resolve4(n->stun_test_ip, ip) == 0;
    }
    if (n->ipv4[0]) {
        return strchr(n->ipv4, ':') == NULL && tsnet_resolve4(n->ipv4, ip) == 0;
    }
    if (tsnet_resolve4(n->host_name, ip) != 0) {
        tsnet_log(TSNET_LOG_WARN, "netcheck: DNS lookup error for %s (node %s region %d)", n->host_name, n->name,
                  n->region_id);
        return false;
    }
    return true;
}

// addNodeLatency.
static void add_node_latency(tsnet_netcheck_t *nc, int region, const uint8_t ip[16], uint16_t port, uint64_t d_us)
{
    tsnet_netcheck_report_t *r = &nc->cur;
    uint32_t d = d_us == 0 ? 1 : d_us > UINT32_MAX ? UINT32_MAX : (uint32_t)d_us;
    r->udp = true;
    tsnet_nc_add_latency(&r->base, region, d);
    // Once 3 regions have answered, the rest get as long as the slowest so far (twice that in a full report). Go adds
    // a timer each time an answer finds 3 regions (a late retry's answer can), and the first one stops the probes.
    if (r->base.n_lat == ENOUGH_REGIONS && !nc->enough_armed) {
        uint64_t slowest = 0;
        for (size_t i = 0; i < r->base.n_lat; i++) {
            slowest = r->base.lat[i].us > slowest ? r->base.lat[i].us : slowest;
        }
        nc->enough_armed = true;
        nc->enough_at_us = tsnet_now_us() + (nc->incremental ? slowest : 2 * slowest);
    }
    r->ipv4_can_send = true; // an answer proves the probe went out
    r->ipv4 = true;
    size_t i;
    for (i = 0; i < r->n_globals; i++) {
        if (memcmp(r->globals[i].ip, ip, 16) == 0 && r->globals[i].port == port) {
            break;
        }
    }
    if (i == r->n_globals && i < TSNET_NC_GLOBALS) {
        memcpy(r->globals[i].ip, ip, 16);
        r->globals[i].port = port;
        r->n_globals++;
    }
    if (i < r->n_globals) {
        r->globals[i].count++;
    }
    if (!r->has_global_v4) {
        r->has_global_v4 = true;
        memcpy(r->global_v4, ip, 16);
        r->global_v4_port = port;
    } else if (memcmp(r->global_v4, ip, 16) != 0 || r->global_v4_port != port) {
        r->mapping_varies = 1;
    } else if (r->mapping_varies == -1) {
        r->mapping_varies = 0;
    }
}

void tsnet_netcheck_stun(tsnet_netcheck_t *nc, const uint8_t *pkt, size_t len, const uint8_t ip[16], uint16_t port)
{
    (void)ip;
    (void)port;
    if (!nc->running) {
        return;
    }
    uint8_t tx[TSNET_STUN_TXID_LEN], addr[16];
    uint16_t addr_port;
    if (tsnet_stun_parse_response(pkt, len, tx, addr, &addr_port) != 0) {
        uint8_t ignored[TSNET_STUN_TXID_LEN];
        if (tsnet_stun_parse_binding_request(pkt, len, ignored) != 0) {
            tsnet_log(TSNET_LOG_DEBUG, "netcheck: received unexpected STUN message response"); // any host can send these
        }
        return; // a late hairpin check of an older version, perhaps
    }
    for (size_t i = 0; i < nc->n_probes; i++) {
        probe_t *p = &nc->probes[i];
        if (p->inflight && memcmp(p->txid, tx, sizeof tx) == 0) {
            p->inflight = false;
            add_node_latency(nc, p->p.region, addr, addr_port, tsnet_now_us() - p->sent_us);
            cancel_set(nc, p->p.region);
            return;
        }
    }
}

// runProbe, for the probes whose time has come.
static void run_probes(tsnet_netcheck_t *nc, uint64_t elapsed_ms)
{
    for (size_t i = 0; i < nc->n_probes; i++) {
        probe_t *p = &nc->probes[i];
        if (p->fired || elapsed_ms < p->p.delay_ms) {
            continue;
        }
        p->fired = true;
        if (set_done(nc, p->p.region)) {
            continue;
        }
        if (!would_help(nc, p->p.region)) {
            cancel_set(nc, p->p.region);
            continue;
        }
        const tsnet_derp_region_t *reg = region_of(nc->dm, p->p.region);
        const tsnet_derp_node_t *node = &reg->nodes[p->p.node];
        uint8_t ip[16];
        uint16_t port;
        if (!node_addr(node, ip, &port)) {
            tsnet_log(TSNET_LOG_DEBUG, "netcheck.runProbe: named node %s has no v4 address", node->name);
            continue;
        }
        uint8_t req[TSNET_STUN_REQUEST_LEN];
        if (tsnet_random(p->txid, sizeof p->txid) != 0) {
            continue;
        }
        tsnet_stun_request(req, p->txid);
        p->sent_us = tsnet_now_us();
        p->inflight = true;
        int n = nc->cfg.send ? nc->cfg.send(nc->cfg.ctx, ip, port, req, sizeof req) : -1;
        if (n == (int)sizeof req || n == 0) { // sent, or dropped by a full socket (TreatAsLostUDP)
            nc->cur.ipv4_can_send = true;
        }
    }
}

// The regions to measure over HTTPS when no STUN probe was answered: no latency yet, a DERP node, not avoided.
static void plan_https(tsnet_netcheck_t *nc)
{
    nc->n_need = nc->next_need = 0;
    for (size_t i = 0; i < nc->dm->n_regions && nc->n_need < TSNET_NC_REGIONS; i++) {
        const tsnet_derp_region_t *reg = &nc->dm->regions[i];
        bool has_derp = false;
        for (size_t j = 0; j < reg->n_nodes; j++) {
            has_derp = has_derp || !reg->nodes[j].stun_only;
        }
        if (has_derp && !reg->avoid && !reg->no_measure_no_home &&
            tsnet_nc_latency(&nc->cur.base, reg->region_id) == 0) {
            nc->https_need[nc->n_need++] = reg->region_id;
        }
    }
    if (nc->n_need > 0) {
        tsnet_log(TSNET_LOG_INFO, "netcheck: UDP is blocked, trying HTTPS");
    }
}

static void start_https(tsnet_netcheck_t *nc)
{
    for (int i = 0; i < MAX_HTTPS && nc->next_need < nc->n_need; i++) {
        if (nc->https[i]) {
            continue;
        }
        int region = nc->https_need[nc->next_need++];
        tsnet_derphttp_cfg_t dc = {.region = region_of(nc->dm, region), .latency_check = true};
        nc->https[i] = tsnet_derphttp_connect(&dc);
        nc->https_region[i] = region;
    }
}

static void log_report(const tsnet_netcheck_t *nc)
{
    const tsnet_netcheck_report_t *r = &nc->cur;
    char dist[256];
    size_t len = 0;
    dist[0] = 0;
    for (size_t i = 0; i < r->base.n_lat && len < sizeof dist - 32; i++) {
        len += (size_t)snprintf(dist + len, sizeof dist - len, "%s%dv4:%ums", i ? "," : "", r->base.lat[i].region,
                                (unsigned)((r->base.lat[i].us + 500) / 1000));
    }
    tsnet_log(TSNET_LOG_INFO, "netcheck: report: udp=%s v4=%s mapvarydest=%s derp=%d derpdist=%s",
              r->udp ? "true" : "false", r->ipv4 ? "true" : "false",
              r->mapping_varies < 0 ? "" : r->mapping_varies ? "true" : "false", r->base.preferred, dist);
}

static void finish(tsnet_netcheck_t *nc)
{
    stop_https(nc);
    nc->cur.base.at_ms = tsnet_now_ms();
    tsnet_nc_opts_t o = {.start_ms = nc->start_ms, .forced = nc->cfg.forced, .last_activity = nc->cfg.last_activity,
                         .ctx = nc->cfg.ctx};
    tsnet_nc_add_report(&nc->hist, &nc->cur.base, nc->dm, &o);
    log_report(nc);
    nc->last = nc->cur;
    nc->have_last = true;
    nc->running = false;
    tsnet_derp_map_free(nc->dm);
    nc->dm = NULL;
}

bool tsnet_netcheck_step(tsnet_netcheck_t *nc)
{
    if (!nc->running) {
        return false;
    }
    uint64_t elapsed = tsnet_now_ms() - nc->start_ms;
    if (!nc->stun_over) {
        run_probes(nc, elapsed);
        bool all_done = nc->n_probes == 0;
        if (!all_done) {
            all_done = true;
            for (size_t i = 0; i < nc->n_probes && all_done; i++) {
                all_done = set_done(nc, nc->probes[i].p.region);
            }
        }
        bool enough = nc->enough_armed && tsnet_now_us() >= nc->enough_at_us;
        if (elapsed >= TSNET_NC_STUN_MS || all_done || enough) {
            nc->stun_over = true;
            if (!nc->cur.udp) {
                plan_https(nc);
            }
        }
    }
    if (nc->stun_over) {
        start_https(nc);
        bool busy = false;
        for (int i = 0; i < MAX_HTTPS; i++) {
            tsnet_derphttp_t *c = nc->https[i];
            if (!c) {
                continue;
            }
            tsnet_derphttp_step(c);
            tsnet_derphttp_state_t st = tsnet_derphttp_state(c);
            if (st == TSNET_DERPHTTP_MEASURED) {
                tsnet_nc_add_latency(&nc->cur.base, nc->https_region[i], tsnet_derphttp_latency_us(c));
                nc->cur.ipv4 = true; // HTTPS went over IPv4 (Go sets it from the connection's address)
            } else if (st == TSNET_DERPHTTP_FAILED) {
                tsnet_log(TSNET_LOG_DEBUG, "netcheck: measuring HTTPS latency of region %d failed", nc->https_region[i]);
            } else {
                busy = true;
                continue;
            }
            tsnet_derphttp_free(c);
            nc->https[i] = NULL;
            start_https(nc);
            busy = busy || nc->https[i] != NULL;
        }
        if ((!busy && nc->next_need >= nc->n_need) || elapsed >= TSNET_NC_REPORT_MS) {
            finish(nc);
            return true;
        }
    }
    return false;
}

int tsnet_netcheck_poll(const tsnet_netcheck_t *nc, tsnet_poll_t *p, int max, int *wait_ms)
{
    *wait_ms = -1;
    if (!nc->running) {
        return 0;
    }
    uint64_t now = tsnet_now_ms();
    uint64_t until = nc->start_ms + TSNET_NC_REPORT_MS;
    if (!nc->stun_over) {
        uint64_t stun_end = nc->start_ms + TSNET_NC_STUN_MS;
        until = stun_end < until ? stun_end : until;
        for (size_t i = 0; i < nc->n_probes; i++) {
            if (!nc->probes[i].fired) {
                uint64_t at = nc->start_ms + nc->probes[i].p.delay_ms;
                until = at < until ? at : until;
            }
        }
        if (nc->enough_armed) {
            uint64_t at = (nc->enough_at_us + 999) / 1000;
            until = at < until ? at : until;
        }
    }
    int n = 0;
    for (int i = 0; i < MAX_HTTPS; i++) {
        if (nc->https[i] && n < max) {
            int w;
            n += tsnet_derphttp_poll(nc->https[i], &p[n], &w);
            if (w >= 0 && now + (uint64_t)w < until) {
                until = now + (uint64_t)w;
            }
        }
    }
    *wait_ms = until > now ? (int)(until - now) : 0;
    return n;
}
