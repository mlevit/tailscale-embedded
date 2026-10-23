// Host test of netcheck's decisions: Go's own cases from net/netcheck/netcheck_test.go, ported.
// TestAddReportHistoryAndSetPreferredDERP (every case), TestRecentReportsRetainFullNetcheck, and TestMakeProbePlan's
// IPv4 cases (tsnet has no IPv6 yet, so the plans are Go's with no IPv6 interface, which its v4 lines match).
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "ncplan.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

#define SEC 1000000u // microseconds
#define MS 1000u

// report("d1", 2 s, "d2", 3 s, ...): region, latency pairs, ended by 0.
static tsnet_nc_report_t report(int region, ...)
{
    tsnet_nc_report_t r;
    memset(&r, 0, sizeof r);
    va_list ap;
    va_start(ap, region);
    while (region != 0) {
        uint32_t us = va_arg(ap, uint32_t);
        tsnet_nc_add_latency(&r, region, us);
        region = va_arg(ap, int);
    }
    va_end(ap);
    return r;
}

typedef struct {
    uint64_t after_ms;
    tsnet_nc_report_t r;
} step_t;

// GetLastDERPActivity from a table: lda[region] (ms), 0 for never.
static uint64_t lda[8];
static uint64_t last_activity(void *ctx, int region)
{
    (void)ctx;
    return region >= 0 && region < 8 ? lda[region] : 0;
}

static const uint64_t START = 123000; // time.Unix(123, 0)

// Runs the steps as the Go test does (rs.start is 100 ms before each step's time) and checks the last report's
// preferred DERP and the history's length.
static void run(const char *name, step_t *steps, size_t n, const tsnet_derp_map_t *dm, bool use_lda, int forced,
                int want_derp, size_t want_prev)
{
    tsnet_nc_history_t h;
    memset(&h, 0, sizeof h);
    uint64_t t = START;
    int got = -1;
    for (size_t i = 0; i < n; i++) {
        t += steps[i].after_ms;
        steps[i].r.at_ms = t;
        tsnet_nc_opts_t o = {.start_ms = t - 100, .forced = forced, .last_activity = use_lda ? last_activity : NULL};
        got = tsnet_nc_add_report(&h, &steps[i].r, dm, &o);
    }
    if (got != want_derp || h.n != want_prev) {
        printf("%s: preferred %d (want %d), history %zu (want %zu)\n", name, got, want_derp, h.n, want_prev);
        failures++;
    }
}

#define RUN(name, dm, use_lda, forced, want_derp, want_prev, ...)                                                    \
    do {                                                                                                             \
        step_t s[] = {__VA_ARGS__};                                                                                  \
        run(name, s, sizeof s / sizeof s[0], dm, use_lda, forced, want_derp, want_prev);                             \
    } while (0)

static void preferred(void)
{
    tsnet_derp_map_t none = {0};
    RUN("first_reading", &none, false, 0, 1, 1, {0, report(1, 2 * SEC, 2, 3 * SEC, 0)});
    RUN("with_two", &none, false, 0, 1, 2, {0, report(1, 2 * SEC, 2, 3 * SEC, 0)}, {1000, report(1, 4 * SEC, 2, 3 * SEC, 0)});
    RUN("but_now_d1_gone", &none, false, 0, 2, 3, {0, report(1, 2 * SEC, 2, 3 * SEC, 0)},
        {1000, report(1, 4 * SEC, 2, 3 * SEC, 0)}, {2000, report(2, 3 * SEC, 0)});
    RUN("d1_is_back", &none, false, 0, 1, 4, {0, report(1, 2 * SEC, 2, 3 * SEC, 0)},
        {1000, report(1, 4 * SEC, 2, 3 * SEC, 0)}, {2000, report(2, 3 * SEC, 0)}, {3000, report(1, 4 * SEC, 2, 3 * SEC, 0)});
    RUN("things_clean_up", &none, false, 0, 3, 1, {0, report(1, 1 * SEC, 2, 2 * SEC, 0)},
        {1000, report(1, 1 * SEC, 2, 2 * SEC, 0)}, {2000, report(1, 1 * SEC, 2, 2 * SEC, 0)},
        {3000, report(1, 1 * SEC, 2, 2 * SEC, 0)}, {600000, report(3, 3 * SEC, 0)});
    RUN("preferred_derp_hysteresis_no_switch", &none, false, 0, 1, 2, {0, report(1, 4 * SEC, 2, 5 * SEC, 0)},
        {1000, report(1, 4 * SEC, 2, 3 * SEC, 0)});
    RUN("preferred_derp_hysteresis_no_switch_absolute", &none, false, 0, 1, 2, {0, report(1, 4 * MS, 2, 5 * MS, 0)},
        {1000, report(1, 4 * MS, 2, 1 * MS, 0)});
    RUN("preferred_derp_hysteresis_do_switch", &none, false, 0, 2, 2, {0, report(1, 4 * SEC, 2, 5 * SEC, 0)},
        {1000, report(1, 4 * SEC, 2, 1 * SEC, 0)});

    tsnet_region_score_t s66[1] = {{1, 2.0 / 3}};
    tsnet_derp_map_t hp = {.has_home_params = true, .has_region_score = true, .region_score = s66, .n_region_score = 1};
    RUN("derp_home_params", &hp, false, 0, 1, 1, {1000, report(1, 10 * SEC, 2, 8 * SEC, 0)});
    RUN("derp_home_params_high_latency", &hp, false, 0, 2, 1, {1000, report(1, 100 * SEC, 2, 10 * SEC, 0)});
    tsnet_region_score_t bad[2] = {{1, 0.0}, {2, -1.0}};
    tsnet_derp_map_t hp_bad = {.has_home_params = true, .has_region_score = true, .region_score = bad, .n_region_score = 2};
    RUN("derp_home_params_invalid", &hp_bad, false, 0, 1, 1, {1000, report(1, 4 * SEC, 2, 5 * SEC, 0)});

    memset(lda, 0, sizeof lda);
    lda[1] = START + 2000 + TSNET_NC_FRAME_MS / 2; // within step 3's active window
    RUN("saw_derp_traffic", &none, true, 0, 1, 3, {0, report(1, 2 * SEC, 2, 3 * SEC, 0)},
        {2000, report(1, 4 * SEC, 2, 3 * SEC, 0)}, {2000, report(2, 3 * SEC, 0)});
    lda[1] = START + 4000 - TSNET_NC_FRAME_MS - 1; // not within it
    RUN("saw_derp_traffic_history", &none, true, 0, 2, 3, {0, report(1, 2 * SEC, 2, 3 * SEC, 0)},
        {2000, report(1, 4 * SEC, 2, 3 * SEC, 0)}, {2000, report(2, 3 * SEC, 0)});
    RUN("preferred_derp_hysteresis_no_switch_pct", &none, false, 0, 1, 2, {0, report(1, 34 * MS, 2, 35 * MS, 0)},
        {1000, report(1, 34 * MS, 2, 23 * MS, 0)});
    RUN("forced_two", &none, false, 2, 2, 2, {1000, report(1, 2 * SEC, 2, 3 * SEC, 0)},
        {2000, report(1, 4 * SEC, 2, 3 * SEC, 0)});
    RUN("forced_two_unavailable", &none, false, 2, 1, 2, {1000, report(1, 2 * SEC, 2, 1 * SEC, 0)},
        {2000, report(1, 4 * SEC, 0)});
    memset(lda, 0, sizeof lda);
    lda[1] = START;
    lda[2] = START + 1000;
    RUN("forced_two_no_probe_recent_activity", &none, true, 2, 2, 2, {1000, report(1, 2 * SEC, 0)},
        {2000, report(1, 4 * SEC, 0)});
    lda[2] = START;
    RUN("forced_two_no_probe_no_recent_activity", &none, true, 2, 1, 2, {1000, report(1, 2 * SEC, 0)},
        {TSNET_NC_FRAME_MS + 1000, report(1, 4 * SEC, 0)});
    memset(lda, 0, sizeof lda);
    lda[1] = START;
    RUN("no_data_keep_home", &none, true, 0, 1, 6, {0, report(1, 2 * SEC, 2, 3 * SEC, 0)}, {30000, report(0)},
        {2000, report(0)}, {2000, report(0)}, {2000, report(0)}, {2000, report(0)});
    RUN("no_data_home_expires", &none, true, 0, 0, 3, {0, report(1, 2 * SEC, 2, 3 * SEC, 0)}, {30000, report(0)},
        {TSNET_NC_KEEPALIVE_MS, report(0)});
}

// TestRecentReportsRetainFullNetcheck: one report a minute for an hour, full every 5 minutes; the history always
// keeps a full one, so every region has a recent latency.
static void retains_full(void)
{
    tsnet_derp_map_t none = {0};
    tsnet_nc_history_t h;
    memset(&h, 0, sizeof h);
    uint64_t start = 1700000000000ull, last_full = 0;
    bool have_full = false;
    for (int i = 0; i < 60; i++) {
        uint64_t now = start + (uint64_t)i * 60000;
        bool full = !have_full || now - last_full > TSNET_NC_FULL_MS;
        tsnet_nc_report_t r = full ? report(1, 10 * MS, 2, 10 * MS, 3, 10 * MS, 0) : report(1, 10 * MS, 2, 10 * MS, 0);
        if (full) {
            last_full = now;
            have_full = true;
        }
        r.at_ms = now;
        tsnet_nc_opts_t o = {.start_ms = now};
        tsnet_nc_add_report(&h, &r, &none, &o);
        for (int region = 1; region <= 3; region++) {
            if (tsnet_nc_best_recent(&h, region) == 0) {
                printf("retains_full: report %d: region %d has no recent latency\n", i, region);
                failures++;
                return;
            }
        }
    }
}

// TestMakeProbePlan's map: regions 1 to 6, region N with N nodes ("1a", "2a" "2b", ...), region 6 NoMeasureNoHome.
static tsnet_derp_node_t nodes[6][6];
static tsnet_derp_region_t regions[6];
static tsnet_derp_map_t basic = {.has_regions = true, .regions = regions, .n_regions = 6};

static void build_basic(void)
{
    for (int r = 1; r <= 6; r++) {
        for (int n = 0; n < r; n++) {
            tsnet_derp_node_t *node = &nodes[r - 1][n];
            snprintf(node->name, sizeof node->name, "%d%c", r, 'a' + n);
            node->region_id = r;
            snprintf(node->host_name, sizeof node->host_name, "derp%d-%d", r, n);
            snprintf(node->ipv4, sizeof node->ipv4, "%d.0.0.%d", r, n);
            snprintf(node->ipv6, sizeof node->ipv6, "%d::%d", r, n);
        }
        regions[r - 1].region_id = r;
        regions[r - 1].nodes = nodes[r - 1];
        regions[r - 1].n_nodes = (size_t)r;
        regions[r - 1].no_measure_no_home = r == 6;
    }
}

// The plan as text, Go's probe String form for v4: "1a-v4 1a-v4@12ms ..." per region on a line.
static void plan_text(const tsnet_nc_probe_t *p, size_t n, char *out, size_t cap)
{
    size_t len = 0;
    out[0] = 0;
    for (size_t i = 0; i < n; i++) {
        const tsnet_derp_region_t *reg = &regions[p[i].region - 1];
        if (i == 0 || p[i].region != p[i - 1].region) {
            len += (size_t)snprintf(out + len, cap - len, "%s[region-%d-v4]", i ? "\n" : "", p[i].region);
        }
        len += (size_t)snprintf(out + len, cap - len, " %s-v4", reg->nodes[p[i].node].name);
        if (p[i].delay_ms) {
            len += (size_t)snprintf(out + len, cap - len, "@%ums", p[i].delay_ms);
        }
    }
}

static void check_plan(const char *name, const tsnet_nc_report_t *last, int preferred, const char *want)
{
    tsnet_nc_probe_t p[64];
    size_t n = tsnet_nc_plan(&basic, last, preferred, p, 64);
    char got[2048];
    plan_text(p, n, got, sizeof got);
    if (strcmp(got, want) != 0) {
        printf("%s: plan\n%s\nwant\n%s\n", name, got, want);
        failures++;
    }
}

static void plans(void)
{
    build_basic();
    check_plan("initial_no_v6", NULL, 0,
               "[region-1-v4] 1a-v4 1a-v4@100ms 1a-v4@200ms\n"
               "[region-2-v4] 2a-v4 2b-v4@100ms 2a-v4@200ms\n"
               "[region-3-v4] 3a-v4 3b-v4@100ms 3c-v4@200ms\n"
               "[region-4-v4] 4a-v4 4b-v4@100ms 4c-v4@200ms\n"
               "[region-5-v4] 5a-v4 5b-v4@100ms 5c-v4@200ms");
    tsnet_nc_report_t last = report(1, 10 * MS, 2, 20 * MS, 3, 30 * MS, 4, 40 * MS, 0); // pretend 5 is missing
    check_plan("second_v4_no_6if", &last, 0,
               "[region-1-v4] 1a-v4 1a-v4@12ms\n"
               "[region-2-v4] 2a-v4 2b-v4@24ms\n"
               "[region-3-v4] 3a-v4");
    check_plan("try_harder_for_preferred_derp (v4)", &last, 1,
               "[region-1-v4] 1a-v4 1a-v4@12ms 1a-v4@124ms 1a-v4@186ms\n"
               "[region-2-v4] 2a-v4 2b-v4@24ms\n"
               "[region-3-v4] 3a-v4");
    tsnet_nc_report_t slow_home = report(1, 50 * MS, 2, 20 * MS, 3, 30 * MS, 4, 40 * MS, 0);
    check_plan("ensure_home_region_inclusion (v4)", &slow_home, 1,
               "[region-1-v4] 1a-v4 1a-v4@60ms 1a-v4@220ms 1a-v4@330ms\n"
               "[region-2-v4] 2a-v4 2b-v4@24ms\n"
               "[region-3-v4] 3a-v4 3b-v4@36ms\n"
               "[region-4-v4] 4a-v4");
    // Not in Go's table: an avoided region stays out unless it is home; IPv4 "none" and a node with an IPv6 in its
    // IPv4 field are skipped in the initial plan.
    regions[1].avoid = true;
    check_plan("avoid", &last, 0,
               "[region-1-v4] 1a-v4 1a-v4@12ms\n"
               "[region-3-v4] 3a-v4 3b-v4@36ms\n"
               "[region-4-v4] 4a-v4");
    check_plan("avoid_but_home", &last, 2,
               "[region-1-v4] 1a-v4 1a-v4@12ms\n"
               "[region-2-v4] 2a-v4 2b-v4@24ms 2a-v4@148ms 2b-v4@222ms\n"
               "[region-3-v4] 3a-v4");
    regions[1].avoid = false;
    snprintf(nodes[0][0].ipv4, sizeof nodes[0][0].ipv4, "none");
    snprintf(nodes[1][1].ipv4, sizeof nodes[1][1].ipv4, "2::1");
    tsnet_nc_probe_t p[64];
    size_t n = tsnet_nc_plan(&basic, NULL, 0, p, 64);
    char got[2048];
    plan_text(p, n, got, sizeof got);
    EXPECT(strncmp(got, "[region-2-v4] 2a-v4 2a-v4@200ms\n[region-3-v4]", 44) == 0);
    EXPECT(tsnet_nc_plan(&basic, NULL, 0, p, 3) == 3); // bounded by max
    tsnet_derp_map_t empty = {0};
    EXPECT(tsnet_nc_plan(&empty, NULL, 0, p, 64) == 0);
}

int main(void)
{
    preferred();
    retains_full();
    plans();
    if (failures == 0) {
        printf("tsnet ncplan_test: ok\n");
    }
    return failures != 0;
}
