// netcheck's decisions. See ncplan.h; the Go is net/netcheck/netcheck.go.
#include "platform.h"
#include "ncplan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_INCREMENTAL_REGIONS 3  // numIncrementalRegions
#define INITIAL_RETRANSMIT_MS 100  // defaultInitialRetransmitTime
#define ACTIVE_RETRANSMIT_US 200000 // defaultActiveRetransmitTime
#define ABSOLUTE_DIFF_US 10000     // preferredDERPAbsoluteDiff
#define HISTORY_MAX_AGE_MS (TSNET_NC_FULL_MS + TSNET_NC_REPORT_MS) // addReportAndPruneExpired's maxAge

uint32_t tsnet_nc_latency(const tsnet_nc_report_t *r, int region)
{
    for (size_t i = 0; r && i < r->n_lat; i++) {
        if (r->lat[i].region == region) {
            return r->lat[i].us;
        }
    }
    return 0;
}

bool tsnet_nc_add_latency(tsnet_nc_report_t *r, int region, uint32_t us)
{
    for (size_t i = 0; i < r->n_lat; i++) {
        if (r->lat[i].region == region) {
            if (us < r->lat[i].us) {
                r->lat[i].us = us;
            }
            return true;
        }
    }
    if (r->n_lat == TSNET_NC_REGIONS) {
        return false;
    }
    r->lat[r->n_lat].region = region;
    r->lat[r->n_lat].us = us;
    r->n_lat++;
    return true;
}

// nodeMight4: an empty IPv4 means maybe (DNS), anything else must be an IPv4 address.
static bool might4(const tsnet_derp_node_t *n)
{
    if (n->ipv4[0] == '\0') {
        return true;
    }
    unsigned a, b, c, d;
    char extra;
    return sscanf(n->ipv4, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) == 4 && a < 256 && b < 256 && c < 256 && d < 256;
}

static bool add(tsnet_nc_probe_t *out, size_t max, size_t *n, int region, int node, uint32_t delay_ms)
{
    if (*n == max) {
        return false;
    }
    out[*n].region = region;
    out[*n].node = node;
    out[*n].delay_ms = delay_ms;
    (*n)++;
    return true;
}

typedef struct {
    const tsnet_derp_region_t *reg;
    uint32_t lat;
} sorted_t;

// sortRegions' order: regions with a latency first, fastest first; then the rest. Ties by region ID (Go's sort.Slice
// leaves them in map order).
static int by_latency(const void *a, const void *b)
{
    const sorted_t *x = a, *y = b;
    if ((x->lat == 0) != (y->lat == 0)) {
        return x->lat == 0 ? 1 : -1;
    }
    if (x->lat != y->lat) {
        return x->lat < y->lat ? -1 : 1;
    }
    return x->reg->region_id < y->reg->region_id ? -1 : x->reg->region_id > y->reg->region_id; // no overflow
}

static int by_region(const void *a, const void *b)
{
    const tsnet_nc_probe_t *x = a, *y = b;
    if (x->region != y->region) {
        return x->region < y->region ? -1 : 1; // not a subtraction: control's IDs could overflow it
    }
    return x->delay_ms < y->delay_ms ? -1 : x->delay_ms > y->delay_ms ? 1 : 0;
}

size_t tsnet_nc_plan(const tsnet_derp_map_t *dm, const tsnet_nc_report_t *last, int preferred, tsnet_nc_probe_t *out,
                     size_t max)
{
    size_t n = 0;
    if (!dm || dm->n_regions == 0) {
        return 0;
    }
    if (!last || last->n_lat == 0) {
        // makeProbePlanInitial: every region that can be home, 3 tries 100 ms apart, cycling through its nodes.
        for (size_t i = 0; i < dm->n_regions; i++) {
            const tsnet_derp_region_t *reg = &dm->regions[i];
            if (reg->no_measure_no_home || reg->n_nodes == 0) {
                continue;
            }
            for (int t = 0; t < 3; t++) {
                const tsnet_derp_node_t *node = &reg->nodes[t % reg->n_nodes];
                if (strcmp(node->ipv4, "none") != 0 && might4(node)) {
                    add(out, max, &n, reg->region_id, t % (int)reg->n_nodes, (uint32_t)t * INITIAL_RETRANSMIT_MS);
                }
            }
        }
        qsort(out, n, sizeof *out, by_region);
        return n;
    }
    sorted_t *regs = tsnet_calloc(dm->n_regions, sizeof *regs);
    if (!regs) {
        return 0;
    }
    size_t nr = 0;
    for (size_t i = 0; i < dm->n_regions; i++) {
        const tsnet_derp_region_t *reg = &dm->regions[i];
        if (reg->no_measure_no_home || (reg->avoid && reg->region_id != preferred)) {
            continue; // an otherwise avoided region stays in when it is home
        }
        regs[nr].reg = reg;
        regs[nr].lat = tsnet_nc_latency(last, reg->region_id);
        nr++;
    }
    qsort(regs, nr, sizeof *regs, by_latency);
    // The three fastest regions and the home (#13969: always probe the home, so one slow sample can't move it).
    bool plan_has_home = preferred == 0;
    for (size_t ri = 0; ri < nr; ri++) {
        const tsnet_derp_region_t *reg = regs[ri].reg;
        bool is_home = reg->region_id == preferred;
        if (ri >= NUM_INCREMENTAL_REGIONS) {
            if (plan_has_home) {
                break;
            }
            if (!is_home) {
                continue;
            }
        }
        int tries = 1; // one STUN packet per node, except the fastest two of last time
        if (ri < 2 || is_home) {
            tries = 2;
        }
        if (is_home) {
            tries = 4; // try extra hard for the home, so it doesn't flip-flop
            plan_has_home = true;
        }
        for (int t = 0; t < tries; t++) {
            if (reg->n_nodes == 0) {
                continue;
            }
            const tsnet_derp_node_t *node = &reg->nodes[t % reg->n_nodes];
            uint64_t prev = regs[ri].lat ? (uint64_t)regs[ri].lat * 120 / 100 : ACTIVE_RETRANSMIT_US;
            uint64_t delay_us = (uint64_t)t * prev;
            if (t > 1) {
                delay_us += (uint64_t)t * 50000;
            }
            if (strcmp(node->ipv4, "none") != 0) {
                add(out, max, &n, reg->region_id, t % (int)reg->n_nodes, (uint32_t)(delay_us / 1000));
            }
        }
    }
    free(regs);
    qsort(out, n, sizeof *out, by_region);
    return n;
}

uint32_t tsnet_nc_best_recent(const tsnet_nc_history_t *h, int region)
{
    uint32_t best = 0;
    for (size_t i = 0; i < h->n; i++) {
        uint32_t d = tsnet_nc_latency(&h->prev[i], region);
        if (d && (best == 0 || d < best)) {
            best = d;
        }
    }
    return best;
}

static double score_of(const tsnet_derp_map_t *dm, int region)
{
    for (size_t i = 0; dm && dm->has_home_params && i < dm->n_region_score; i++) {
        if (dm->region_score[i].region_id == region) {
            return dm->region_score[i].score;
        }
    }
    return 0;
}

static uint32_t scaled(const tsnet_derp_map_t *dm, int region, uint32_t us)
{
    double s = score_of(dm, region), v = (double)us * s;
    return s > 0 ? (v < 4294967295.0 ? (uint32_t)v : UINT32_MAX) : us; // a cast past uint32 is undefined
}

// t.After(ref), where 0 is the zero time (never after anything).
static bool after(uint64_t t, int64_t ref)
{
    return t != 0 && (int64_t)t > ref;
}

int tsnet_nc_add_report(tsnet_nc_history_t *h, tsnet_nc_report_t *r, const tsnet_derp_map_t *dm,
                        const tsnet_nc_opts_t *o)
{
    int prev = h->last_preferred;
    int64_t now = (int64_t)r->at_ms;
    r->preferred = 0;

    // addReportAndPruneExpired: keyed by time (a report at the same time replaces it), then the old ones dropped.
    size_t i;
    for (i = 0; i < h->n && h->prev[i].at_ms != r->at_ms; i++) {
    }
    if (i == h->n) {
        if (h->n == TSNET_NC_HISTORY) {
            memmove(h->prev, h->prev + 1, (h->n - 1) * sizeof *h->prev);
            h->n--;
            i = h->n;
        }
        h->n++;
    }
    h->prev[i] = *r;
    size_t kept = 0;
    for (size_t j = 0; j < h->n; j++) {
        if (now - (int64_t)h->prev[j].at_ms <= HISTORY_MAX_AGE_MS) {
            h->prev[kept++] = h->prev[j];
        }
    }
    h->n = kept;

    // The current report's region with the best recent latency (each scaled by RegionScore).
    uint32_t best_any = 0, old_cur = 0;
    for (size_t j = 0; j < r->n_lat; j++) {
        int region = r->lat[j].region;
        uint32_t d = scaled(dm, region, r->lat[j].us);
        if (region == prev) {
            old_cur = d;
        }
        uint32_t best = scaled(dm, region, tsnet_nc_best_recent(h, region));
        if (r->preferred == 0 || best < best_any) {
            best_any = best;
            r->preferred = region;
        }
    }

    // Stickiness: keep the old home while it is reachable, unless the new one is 10 ms and a third better.
    uint64_t prev_heard = o && o->last_activity ? o->last_activity(o->ctx, prev) : 0;
    bool changing = prev != 0 && r->preferred != prev;
    bool heard_recently = changing && (after(prev_heard, (int64_t)(o ? o->start_ms : 0)) ||
                                       after(prev_heard, now - TSNET_NC_FRAME_MS));
    bool keep_old = false;
    if (changing && (old_cur != 0 || heard_recently)) {
        // Signed, as Go's durations (an old home heard from but with no latency gives a negative difference; the next
        // test keeps the old home then anyway).
        if ((int64_t)old_cur - (int64_t)best_any < ABSOLUTE_DIFF_US) {
            keep_old = true;
        }
        if (best_any > old_cur / 3 * 2) {
            keep_old = true;
        }
    }
    if (keep_old) {
        r->preferred = prev;
    }
    if (o && o->forced) {
        uint64_t heard = o->last_activity ? o->last_activity(o->ctx, o->forced) : 0;
        bool recent = after(heard, (int64_t)o->start_ms) || after(heard, now - TSNET_NC_FRAME_MS);
        if (tsnet_nc_latency(r, o->forced) != 0 || recent) {
            r->preferred = o->forced;
        }
    }
    // No data, but the home's DERP connection has been alive within 2 keep-alives: keep it.
    if (r->preferred == 0 && after(prev_heard, now - TSNET_NC_KEEPALIVE_MS)) {
        r->preferred = prev;
    }
    h->last_preferred = r->preferred;
    return r->preferred;
}
