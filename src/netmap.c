// The netmap across a map stream. See netmap.h; the Go is control/controlclient/map.go.
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#elif !defined(ESP_PLATFORM)
#define _DEFAULT_SOURCE // strdup under -std=c11 on glibc
#endif
#include "platform.h"
#include "netmap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "json.h"

void tsnet_netmap_init(tsnet_netmap_t *nm)
{
    memset(nm, 0, sizeof *nm);
    nm->node.online = -1;
}

static void filters_clear(tsnet_netmap_t *nm)
{
    for (size_t i = 0; i < nm->n_filters; i++) {
        free(nm->filters[i].rules_json);
    }
    free(nm->filters);
    nm->filters = NULL;
    nm->n_filters = 0;
}

void tsnet_netmap_free(tsnet_netmap_t *nm)
{
    tsnet_node_free(&nm->node);
    for (size_t i = 0; i < nm->n_peers; i++) {
        tsnet_node_free(&nm->peers[i]);
    }
    free(nm->peers);
    tsnet_derp_map_free(nm->derp_map);
    filters_clear(nm);
    tsnet_netmap_init(nm);
}

// Moves a node out of a response: the response keeps a zeroed node, which frees as nothing.
static tsnet_node_t take(tsnet_node_t *src)
{
    tsnet_node_t n = *src;
    memset(src, 0, sizeof *src);
    src->online = -1;
    return n;
}

// The index of the peer with `id`, or where it would go (peers are sorted by id).
static size_t find(const tsnet_netmap_t *nm, int64_t id, bool *found)
{
    size_t lo = 0, hi = nm->n_peers;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (nm->peers[mid].id < id) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    *found = lo < nm->n_peers && nm->peers[lo].id == id;
    return lo;
}

// ms.peers[n.ID] = n. Returns 0, -1 out of memory, or 1 when the peer is new and the netmap already has
// TSNET_NETMAP_PEERS_MAX: the peer is then not kept, and the caller still owns it.
static int upsert(tsnet_netmap_t *nm, tsnet_node_t *n)
{
    bool found;
    size_t i = find(nm, n->id, &found);
    if (found) {
        tsnet_node_free(&nm->peers[i]);
        nm->peers[i] = take(n);
        return 0;
    }
    if (nm->n_peers >= TSNET_NETMAP_PEERS_MAX) {
        return 1;
    }
    if (nm->n_peers == nm->cap_peers) {
        size_t cap = nm->cap_peers ? nm->cap_peers * 2 : 8;
        tsnet_node_t *p = tsnet_realloc(nm->peers, cap * sizeof *p);
        if (p == NULL) {
            return -1;
        }
        nm->peers = p;
        nm->cap_peers = cap;
    }
    memmove(&nm->peers[i + 1], &nm->peers[i], (nm->n_peers - i) * sizeof *nm->peers);
    nm->peers[i] = take(n);
    nm->n_peers++;
    return 0;
}

static bool remove_peer(tsnet_netmap_t *nm, int64_t id)
{
    bool found;
    size_t i = find(nm, id, &found);
    if (!found) {
        return false;
    }
    tsnet_node_free(&nm->peers[i]);
    memmove(&nm->peers[i], &nm->peers[i + 1], (nm->n_peers - i - 1) * sizeof *nm->peers);
    nm->n_peers--;
    return true;
}

static tsnet_node_t *peer_mut(tsnet_netmap_t *nm, int64_t id)
{
    bool found;
    size_t i = find(nm, id, &found);
    return found ? &nm->peers[i] : NULL;
}

static void refuse_log(size_t refused)
{
    if (refused > 0) {
        tsnet_log(TSNET_LOG_WARN, "netmap: %zu peers not kept, the netmap is at TSNET_NETMAP_PEERS_MAX (%d)", refused,
                  TSNET_NETMAP_PEERS_MAX);
    }
}

// updatePeersStateFromResponse. Returns whether the peers changed, or -1 out of memory.
static int peers(tsnet_netmap_t *nm, tsnet_map_resp_t *r, int64_t now)
{
    int changed = 0;
    size_t refused = 0; // new peers not kept, for being past TSNET_NETMAP_PEERS_MAX
    if (r->n_peers > 0) { // not delta encoded: the new set replaces the old, and nothing else applies this turn
        for (size_t i = 0; i < nm->n_peers; i++) {
            tsnet_node_free(&nm->peers[i]);
        }
        nm->n_peers = 0;
        for (size_t i = 0; i < r->n_peers; i++) {
            int u = upsert(nm, &r->peers[i]);
            if (u < 0) {
                return -1;
            }
            refused += (size_t)u;
        }
        refuse_log(refused);
        return 1;
    }
    for (size_t i = 0; i < r->n_peers_removed; i++) {
        changed |= remove_peer(nm, r->peers_removed[i]);
    }
    for (size_t i = 0; i < r->n_peers_changed; i++) {
        int u = upsert(nm, &r->peers_changed[i]);
        if (u < 0) {
            return -1;
        }
        refused += (size_t)u;
        changed = 1;
    }
    refuse_log(refused);
    for (size_t i = 0; i < r->n_seen_change; i++) {
        tsnet_node_t *p = peer_mut(nm, r->seen_change[i].id);
        if (p) {
            p->last_seen = r->seen_change[i].value ? now : 0; // seen: now; not seen: LastSeen = nil
            changed = 1;
        }
    }
    for (size_t i = 0; i < r->n_online_change; i++) {
        tsnet_node_t *p = peer_mut(nm, r->online_change[i].id);
        if (p) {
            p->online = r->online_change[i].value ? 1 : 0;
            changed = 1;
        }
    }
    for (size_t i = 0; i < r->n_patches; i++) {
        tsnet_peer_change_t *pc = &r->patches[i];
        tsnet_node_t *p = peer_mut(nm, pc->node_id);
        if (p == NULL) {
            continue;
        }
        changed = 1;
        if (pc->have & TSNET_PC_DERP) {
            p->home_derp = pc->derp_region;
        }
        if (pc->have & TSNET_PC_CAP) {
            p->cap = pc->cap;
        }
        if (pc->have & TSNET_PC_ENDPOINTS) {
            free(p->endpoints);
            p->endpoints = pc->endpoints;
            p->n_endpoints = pc->n_endpoints;
            pc->endpoints = NULL;
            pc->n_endpoints = 0;
        }
        if (pc->have & TSNET_PC_KEY) {
            memcpy(p->key, pc->key, TSNET_KEY_LEN);
        }
        if (pc->have & TSNET_PC_DISCO) {
            memcpy(p->disco, pc->disco, TSNET_KEY_LEN);
            p->has_disco = true;
        }
        if (pc->have & TSNET_PC_ONLINE) {
            p->online = pc->online ? 1 : 0;
        }
        if (pc->have & TSNET_PC_LAST_SEEN) {
            p->last_seen = pc->last_seen;
        }
        if (pc->have & TSNET_PC_KEY_EXPIRY) {
            p->key_expiry = pc->key_expiry;
        }
        if (pc->have & TSNET_PC_KEY_SIGNATURE) {
            p->has_key_signature = true;
        }
        // CapMap: a peer's CapMap isn't kept (mapresp.h).
    }
    return changed;
}

// updateStateFromResponse's DERP map: zero-valued fields mean "unchanged, use the previous ones".
static void derp(tsnet_netmap_t *nm, tsnet_map_resp_t *r)
{
    tsnet_derp_map_t *dm = r->derp_map, *last = nm->derp_map;
    r->derp_map = NULL;
    if (last) {
        if (!dm->has_regions) {
            dm->has_regions = last->has_regions;
            dm->regions = last->regions;
            dm->n_regions = last->n_regions;
            dm->omit_default_regions = last->omit_default_regions;
            last->regions = NULL;
            last->n_regions = 0;
        }
        bool take_score = false;
        if (!dm->has_home_params) {
            dm->has_home_params = last->has_home_params;
            take_score = true;
        } else if (last->has_home_params && !dm->has_region_score) {
            take_score = true; // HomeParams' sub-fields propagate too
        }
        if (take_score) {
            dm->has_region_score = last->has_region_score;
            dm->region_score = last->region_score;
            dm->n_region_score = last->n_region_score;
            last->region_score = NULL;
            last->n_region_score = 0;
        }
        tsnet_derp_map_free(last);
    }
    nm->derp_map = dm;
}

// namedPacketFilters[name] = rules (NULL rules: delete).
static void filter_set(tsnet_netmap_t *nm, const char *name, const char *rules)
{
    if (strlen(name) >= sizeof nm->filters[0].name) {
        // A name stored cut would never match itself again, and every message would add another copy.
        tsnet_log(TSNET_LOG_WARN, "netmap: a packet filter name longer than %zu bytes: ignored",
                  sizeof nm->filters[0].name - 1);
        return;
    }
    size_t i = 0;
    while (i < nm->n_filters && strcmp(nm->filters[i].name, name) < 0) {
        i++;
    }
    bool found = i < nm->n_filters && strcmp(nm->filters[i].name, name) == 0;
    if (rules == NULL) {
        if (found) {
            free(nm->filters[i].rules_json);
            memmove(&nm->filters[i], &nm->filters[i + 1], (nm->n_filters - i - 1) * sizeof *nm->filters);
            nm->n_filters--;
        }
        return;
    }
    char *copy = strdup(rules);
    if (copy == NULL) {
        return;
    }
    if (found) {
        free(nm->filters[i].rules_json);
        nm->filters[i].rules_json = copy;
        return;
    }
    tsnet_named_filter_t *f = tsnet_realloc(nm->filters, (nm->n_filters + 1) * sizeof *f);
    if (f == NULL) {
        free(copy);
        return;
    }
    nm->filters = f;
    memmove(&nm->filters[i + 1], &nm->filters[i], (nm->n_filters - i) * sizeof *nm->filters);
    snprintf(nm->filters[i].name, sizeof nm->filters[i].name, "%s", name);
    nm->filters[i].rules_json = copy;
    nm->n_filters++;
}

// The older single list is the filter named "base"; the newer named lists follow, a "*": null clearing them all.
static bool filters(tsnet_netmap_t *nm, const tsnet_map_resp_t *r)
{
    bool changed = false;
    if (r->packet_filter_json) {
        filter_set(nm, "base", r->packet_filter_json);
        changed = true;
    }
    if (r->packet_filters_json) {
        changed = true;
        cJSON *m = tsnet_json_parse(r->packet_filters_json, strlen(r->packet_filters_json));
        if (!cJSON_IsObject(m)) { // named lists by name: an array's members have no names
            cJSON_Delete(m);
            return changed;
        }
        const cJSON *star = cJSON_GetObjectItemCaseSensitive(m, "*");
        if (star && cJSON_IsNull(star)) {
            filters_clear(nm);
        }
        const cJSON *e;
        cJSON_ArrayForEach(e, m)
        {
            if (strcmp(e->string, "*") == 0) {
                continue;
            }
            if (cJSON_IsNull(e)) {
                filter_set(nm, e->string, NULL);
            } else {
                char *raw = cJSON_PrintUnformatted(e);
                filter_set(nm, e->string, raw);
                free(raw);
            }
        }
        cJSON_Delete(m);
    }
    return changed;
}

int tsnet_netmap_apply(tsnet_netmap_t *nm, tsnet_map_resp_t *r, int64_t now)
{
    if (r->control_time) {
        nm->control_time = r->control_time; // read before the keep-alive check, as sendMapRequest does
    }
    if (r->keep_alive) {
        return 0;
    }
    if (!nm->has_node && r->node == NULL) {
        return -1; // initial MapResponse lacked node
    }
    int flags = 0;
    int p = peers(nm, r, now);
    if (p < 0) {
        return -1;
    }
    flags |= p ? TSNET_NM_PEERS : 0;
    if (r->node) {
        tsnet_node_free(&nm->node);
        nm->node = take(r->node);
        nm->has_node = true;
        flags |= TSNET_NM_SELF;
    }
    if (r->derp_map) {
        derp(nm, r);
        flags |= TSNET_NM_DERP;
    }
    flags |= filters(nm, r) ? TSNET_NM_FILTER : 0;
    if (r->domain[0] && strcmp(r->domain, nm->domain) != 0) {
        snprintf(nm->domain, sizeof nm->domain, "%s", r->domain);
        flags |= TSNET_NM_DOMAIN;
    }
    return flags;
}

const tsnet_node_t *tsnet_netmap_peer(const tsnet_netmap_t *nm, int64_t id)
{
    bool found;
    size_t i = find(nm, id, &found);
    return found ? &nm->peers[i] : NULL;
}

const tsnet_node_t *tsnet_netmap_peer_by_key(const tsnet_netmap_t *nm, const uint8_t key[TSNET_KEY_LEN])
{
    for (size_t i = 0; i < nm->n_peers; i++) {
        if (memcmp(nm->peers[i].key, key, TSNET_KEY_LEN) == 0) {
            return &nm->peers[i];
        }
    }
    return NULL;
}

const tsnet_node_t *tsnet_netmap_peer_by_ip(const tsnet_netmap_t *nm, const tsnet_ip_t *ip)
{
    size_t len = ip->is6 ? 16 : 4;
    for (size_t i = 0; i < nm->n_peers; i++) {
        for (size_t k = 0; k < nm->peers[i].n_addresses; k++) {
            const tsnet_ip_t *a = &nm->peers[i].addresses[k].ip;
            if (a->is6 == ip->is6 && memcmp(a->ip, ip->ip, len) == 0) {
                return &nm->peers[i];
            }
        }
    }
    return NULL;
}

const tsnet_node_t *tsnet_netmap_peer_by_name(const tsnet_netmap_t *nm, const char *name)
{
    size_t n = strlen(name);
    if (n > 0 && name[n - 1] == '.') {
        n--; // "server.example.ts.net." and "server.example.ts.net" are one name
    }
    for (size_t i = 0; i < nm->n_peers; i++) {
        const char *fqdn = nm->peers[i].name;
        const char *dot = strchr(fqdn, '.');
        size_t label = dot ? (size_t)(dot - fqdn) : strlen(fqdn), full = strlen(fqdn);
        if (full > 0 && fqdn[full - 1] == '.') {
            full--;
        }
        if (n > 0 && ((n == label || n == full) && strncmp(fqdn, name, n) == 0)) {
            return &nm->peers[i];
        }
    }
    return NULL;
}

char *tsnet_netmap_filter_rules_json(const tsnet_netmap_t *nm)
{
    if (nm->n_filters == 0) {
        return NULL;
    }
    cJSON *all = cJSON_CreateArray();
    for (size_t i = 0; all && i < nm->n_filters; i++) { // sorted by name, as slices.Sorted(maps.Keys(...))
        const char *rj = nm->filters[i].rules_json;
        cJSON *rules = tsnet_json_parse(rj, rj ? strlen(rj) : 0);
        cJSON *e = rules ? rules->child : NULL;
        while (e) {
            cJSON *next = e->next;
            cJSON_AddItemToArray(all, cJSON_DetachItemViaPointer(rules, e));
            e = next;
        }
        cJSON_Delete(rules);
    }
    char *s = all ? cJSON_PrintUnformatted(all) : NULL;
    cJSON_Delete(all);
    return s;
}
