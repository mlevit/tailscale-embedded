#pragma once
// netcheck's decisions, pure: net/netcheck/netcheck.go's probe plan (makeProbePlan, makeProbePlanInitial,
// sortRegions) and its report history and preferred DERP (addReportHistoryAndSetPreferredDERP). IPv4 only, as tsnet's
// UDP is: the plan has no IPv6 probes (Go's with no IPv6 interface).
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mapresp.h"

#define TSNET_NC_REGIONS 48       // regions a report keeps a latency for (Tailscale's map had 28 on 2026-10-23)
#define TSNET_NC_HISTORY 32       // reports kept (Go keeps every report of the last 5 min 5 s: one per 20-26 s)
#define TSNET_NC_FULL_MS 300000   // fullReportInterval
#define TSNET_NC_REPORT_MS 5000   // ReportTimeout
#define TSNET_NC_STUN_MS 3000     // stunProbeTimeout
#define TSNET_NC_FRAME_MS 8000    // PreferredDERPFrameTime
#define TSNET_NC_KEEPALIVE_MS 120000 // PreferredDERPKeepAliveTimeout: 2 × derp.KeepAlive

// One STUN probe: a node of a region, sent `delay_ms` after the report starts. The probes of one region are a set:
// the first answer stops the rest.
typedef struct {
    int region;
    int node; // an index into the region's nodes
    uint32_t delay_ms;
} tsnet_nc_probe_t;

typedef struct {
    int region;
    uint32_t us; // latency, microseconds
} tsnet_nc_latency_t;

// What the plan and the history read of a report.
typedef struct {
    uint64_t at_ms; // when it finished (Report.Now)
    tsnet_nc_latency_t lat[TSNET_NC_REGIONS];
    size_t n_lat;
    int preferred; // PreferredDERP, or 0
} tsnet_nc_report_t;

// The latency for a region in a report, or 0 when it has none.
uint32_t tsnet_nc_latency(const tsnet_nc_report_t *r, int region);
// updateLatency: keeps the lower of the two. Returns false when the report has no room for another region.
bool tsnet_nc_add_latency(tsnet_nc_report_t *r, int region, uint32_t us);

// makeProbePlan: the probes for a report, written to `out` (at most `max`), sorted by region and then by delay.
// `last` NULL (or with no latencies) is a full report's plan (makeProbePlanInitial); `preferred` is the current home.
size_t tsnet_nc_plan(const tsnet_derp_map_t *dm, const tsnet_nc_report_t *last, int preferred, tsnet_nc_probe_t *out,
                     size_t max);

typedef struct {
    tsnet_nc_report_t prev[TSNET_NC_HISTORY]; // c.prev, oldest first
    size_t n;
    int last_preferred; // c.last.PreferredDERP
} tsnet_nc_history_t;

// The inputs to the preferred DERP besides the report.
typedef struct {
    uint64_t start_ms; // when the report started (rs.start)
    int forced;        // ForcePreferredDERP, or 0
    // GetLastDERPActivity: when the region was last heard from over DERP, 0 for never. May be NULL.
    uint64_t (*last_activity)(void *ctx, int region);
    void *ctx;
} tsnet_nc_opts_t;

// addReportHistoryAndSetPreferredDERP: adds `r` (finished at r->at_ms) to the history, drops reports older than
// 5 min 5 s, and sets r->preferred: the region with the best latency over the history (scaled by the map's
// HomeParams.RegionScore), unless the old home is still reachable and the new one isn't 10 ms and a third better;
// the forced region when it answered or was heard from; the old home when there's no data but DERP was heard from it in
// the last 2 minutes. Returns r->preferred.
int tsnet_nc_add_report(tsnet_nc_history_t *h, tsnet_nc_report_t *r, const tsnet_derp_map_t *dm,
                        const tsnet_nc_opts_t *o);
// bestRecentLatencyLocked's value for a region over the history, or 0.
uint32_t tsnet_nc_best_recent(const tsnet_nc_history_t *h, int region);
