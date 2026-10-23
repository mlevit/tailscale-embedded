// A MapResponse decoded. See mapresp.h; field names are tailcfg.go's and derpmap.go's.
#include "platform.h"
#include "mapresp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "json.h"

#define DERP_MAGIC_IP "127.3.3.40" // tailcfg.DerpMagicIP

// ---- time ----

// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm), for timegm without a libc that has it.
static int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

int tsnet_time_parse(int64_t *out, const char *s)
{
    int y, mo, d, h, mi, sec, n = 0;
    if (s == NULL || sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d%n", &y, &mo, &d, &h, &mi, &sec, &n) != 6 || n != 19) {
        return -1;
    }
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || sec > 60) {
        return -1;
    }
    const char *p = s + 19;
    if (*p == '.') { // a fraction: dropped
        p++;
        if (*p < '0' || *p > '9') {
            return -1;
        }
        while (*p >= '0' && *p <= '9') {
            p++;
        }
    }
    int64_t offset = 0;
    if (*p == 'Z') {
        p++;
    } else if (*p == '+' || *p == '-') {
        int oh, om, k = 0;
        if (sscanf(p + 1, "%2d:%2d%n", &oh, &om, &k) != 2 || k != 5 || oh > 23 || om > 59) {
            return -1;
        }
        offset = (*p == '+' ? 1 : -1) * (oh * 3600 + om * 60);
        p += 6;
    } else {
        return -1;
    }
    if (*p != '\0') {
        return -1;
    }
    if (y == 1 && mo == 1 && d == 1 && h == 0 && mi == 0 && sec == 0 && offset == 0) {
        *out = 0; // Go's zero time
        return 0;
    }
    *out = days_from_civil(y, (unsigned)mo, (unsigned)d) * 86400 + h * 3600 + mi * 60 + sec - offset;
    return 0;
}

// ---- helpers ----

typedef struct {
    int bad; // a field had the wrong form
} ctx_t;

static const cJSON *get(const cJSON *o, const char *name)
{
    return cJSON_GetObjectItemCaseSensitive(o, name);
}

static void str(ctx_t *c, char *out, size_t cap, const cJSON *o, const char *name)
{
    const cJSON *v = get(o, name);
    out[0] = '\0';
    if (v == NULL || cJSON_IsNull(v)) {
        return;
    }
    if (!cJSON_IsString(v)) {
        c->bad = 1;
        return;
    }
    snprintf(out, cap, "%s", v->valuestring);
}

static int64_t num(ctx_t *c, const cJSON *o, const char *name)
{
    const cJSON *v = get(o, name);
    if (v == NULL || cJSON_IsNull(v)) {
        return 0;
    }
    // A number past int64 (1e400 parses as inf) would make the cast undefined: Go's decode fails it too.
    if (!cJSON_IsNumber(v) || !(v->valuedouble >= -9.2e18 && v->valuedouble <= 9.2e18)) {
        c->bad = 1;
        return 0;
    }
    return (int64_t)v->valuedouble;
}

static bool flag(ctx_t *c, const cJSON *o, const char *name)
{
    const cJSON *v = get(o, name);
    if (v == NULL || cJSON_IsNull(v)) {
        return false;
    }
    if (!cJSON_IsBool(v)) {
        c->bad = 1;
        return false;
    }
    return cJSON_IsTrue(v);
}

// A key field: absent or null leaves it zero and returns 0; a wrong form sets bad.
static int key(ctx_t *c, uint8_t out[TSNET_KEY_LEN], const cJSON *o, const char *name, const char *prefix)
{
    const cJSON *v = get(o, name);
    memset(out, 0, TSNET_KEY_LEN);
    if (v == NULL || cJSON_IsNull(v)) {
        return 0;
    }
    if (!cJSON_IsString(v) || tsnet_key_parse(out, prefix, v->valuestring) != 0) {
        c->bad = 1;
        return 0;
    }
    return 1;
}

static int64_t when(ctx_t *c, const cJSON *o, const char *name, int *present)
{
    const cJSON *v = get(o, name);
    int64_t t = 0;
    if (present) {
        *present = 0;
    }
    if (v == NULL || cJSON_IsNull(v)) {
        return 0;
    }
    if (!cJSON_IsString(v) || tsnet_time_parse(&t, v->valuestring) != 0) {
        c->bad = 1;
        return 0;
    }
    if (present) {
        *present = 1;
    }
    return t;
}

static char *raw(const cJSON *v)
{
    return v == NULL || cJSON_IsNull(v) ? NULL : cJSON_PrintUnformatted(v);
}

static tsnet_prefix_t *prefixes(ctx_t *c, const cJSON *a, size_t *n)
{
    *n = 0;
    if (a == NULL || cJSON_IsNull(a)) {
        return NULL;
    }
    if (!cJSON_IsArray(a)) {
        c->bad = 1;
        return NULL;
    }
    size_t count = (size_t)cJSON_GetArraySize(a);
    tsnet_prefix_t *out = count ? tsnet_calloc(count, sizeof *out) : NULL;
    if (count && out == NULL) {
        c->bad = 1;
        return NULL;
    }
    const cJSON *e;
    cJSON_ArrayForEach(e, a)
    {
        if (!cJSON_IsString(e) || tsnet_prefix_parse(&out[*n], e->valuestring) != 0) {
            c->bad = 1;
            break;
        }
        (*n)++;
    }
    return out;
}

static tsnet_addrport_t *addrports(ctx_t *c, const cJSON *a, size_t *n)
{
    *n = 0;
    if (a == NULL || cJSON_IsNull(a)) {
        return NULL;
    }
    if (!cJSON_IsArray(a)) {
        c->bad = 1;
        return NULL;
    }
    size_t count = (size_t)cJSON_GetArraySize(a);
    tsnet_addrport_t *out = count ? tsnet_calloc(count, sizeof *out) : NULL;
    if (count && out == NULL) {
        c->bad = 1;
        return NULL;
    }
    const cJSON *e;
    cJSON_ArrayForEach(e, a)
    {
        if (!cJSON_IsString(e) || tsnet_addrport_parse(&out[*n], e->valuestring) != 0) {
            c->bad = 1;
            break;
        }
        (*n)++;
    }
    return out;
}

// An integer map key: NodeID and DERPRegionID are JSON object keys in decimal.
static int id_key(const char *s, int64_t *out)
{
    char *end;
    long long v = strtoll(s, &end, 10);
    if (s[0] == '\0' || *end != '\0') {
        return -1;
    }
    *out = v;
    return 0;
}

// ---- nodes ----

void tsnet_node_free(tsnet_node_t *n)
{
    free(n->addresses);
    free(n->allowed_ips);
    free(n->endpoints);
    free(n->cap_map_json);
    n->addresses = n->allowed_ips = NULL;
    n->endpoints = NULL;
    n->cap_map_json = NULL;
}

static void node(ctx_t *c, tsnet_node_t *n, const cJSON *o, bool self)
{
    memset(n, 0, sizeof *n);
    n->online = -1;
    if (!cJSON_IsObject(o)) {
        c->bad = 1;
        return;
    }
    n->id = num(c, o, "ID");
    str(c, n->stable_id, sizeof n->stable_id, o, "StableID");
    str(c, n->name, sizeof n->name, o, "Name");
    n->user = num(c, o, "User");
    key(c, n->key, o, "Key", TSNET_KEY_NODE);
    n->key_expiry = when(c, o, "KeyExpiry", NULL);
    const cJSON *sig = get(o, "KeySignature");
    n->has_key_signature = cJSON_IsString(sig) && sig->valuestring[0];
    key(c, n->machine, o, "Machine", TSNET_KEY_MACHINE);
    n->has_disco = key(c, n->disco, o, "DiscoKey", TSNET_KEY_DISCO);
    n->addresses = prefixes(c, get(o, "Addresses"), &n->n_addresses);
    const cJSON *allowed = get(o, "AllowedIPs");
    n->unsigned_peer_api_only = flag(c, o, "UnsignedPeerAPIOnly");
    // upgradeNode: no AllowedIPs (nil, not empty) means the Addresses; so does an unsigned peer's, whatever it says.
    if (allowed == NULL || cJSON_IsNull(allowed) || n->unsigned_peer_api_only) {
        if (n->n_addresses) {
            n->allowed_ips = tsnet_malloc(n->n_addresses * sizeof *n->allowed_ips);
            if (n->allowed_ips == NULL) {
                c->bad = 1;
            } else {
                memcpy(n->allowed_ips, n->addresses, n->n_addresses * sizeof *n->allowed_ips);
                n->n_allowed_ips = n->n_addresses;
            }
        }
    } else {
        n->allowed_ips = prefixes(c, allowed, &n->n_allowed_ips);
    }
    n->endpoints = addrports(c, get(o, "Endpoints"), &n->n_endpoints);
    n->home_derp = (int)num(c, o, "HomeDERP");
    char legacy[64];
    str(c, legacy, sizeof legacy, o, "DERP"); // upgradeNode: "127.3.3.40:N" means region N, when HomeDERP is unset
    if (legacy[0] && n->home_derp == 0) {
        size_t ml = strlen(DERP_MAGIC_IP);
        char *end;
        long region = strncmp(legacy, DERP_MAGIC_IP, ml) == 0 && legacy[ml] == ':' ? strtol(legacy + ml + 1, &end, 10) : 0;
        if (region > 0 && *end == '\0') {
            n->home_derp = (int)region;
        }
    }
    n->cap = (int)num(c, o, "Cap");
    n->last_seen = when(c, o, "LastSeen", NULL);
    const cJSON *online = get(o, "Online");
    if (online && !cJSON_IsNull(online)) {
        n->online = flag(c, o, "Online") ? 1 : 0;
    }
    n->machine_authorized = flag(c, o, "MachineAuthorized");
    n->expired = flag(c, o, "Expired");
    n->is_wireguard_only = flag(c, o, "IsWireGuardOnly");
    n->is_jailed = flag(c, o, "IsJailed");
    const cJSON *hi = get(o, "Hostinfo");
    if (cJSON_IsObject(hi)) {
        str(c, n->hostname, sizeof n->hostname, hi, "Hostname");
    }
    if (self) {
        n->cap_map_json = raw(get(o, "CapMap"));
    }
}

static tsnet_node_t *nodes(ctx_t *c, const cJSON *a, size_t *n)
{
    *n = 0;
    if (a == NULL || cJSON_IsNull(a)) {
        return NULL;
    }
    if (!cJSON_IsArray(a)) {
        c->bad = 1;
        return NULL;
    }
    size_t count = (size_t)cJSON_GetArraySize(a);
    tsnet_node_t *out = count ? tsnet_calloc(count, sizeof *out) : NULL;
    if (count && out == NULL) {
        c->bad = 1;
        return NULL;
    }
    const cJSON *e;
    cJSON_ArrayForEach(e, a)
    {
        node(c, &out[(*n)++], e, false);
    }
    return out;
}

// ---- the rest ----

static void patch(ctx_t *c, tsnet_peer_change_t *p, const cJSON *o)
{
    memset(p, 0, sizeof *p);
    if (!cJSON_IsObject(o)) {
        c->bad = 1;
        return;
    }
    p->node_id = num(c, o, "NodeID");
    // omitzero: a zero DERPRegion or Cap means unchanged (updatePeersStateFromResponse tests != 0).
    if ((p->derp_region = (int)num(c, o, "DERPRegion")) != 0) {
        p->have |= TSNET_PC_DERP;
    }
    if ((p->cap = (int)num(c, o, "Cap")) != 0) {
        p->have |= TSNET_PC_CAP;
    }
    const cJSON *eps = get(o, "Endpoints");
    if (eps && !cJSON_IsNull(eps)) {
        p->endpoints = addrports(c, eps, &p->n_endpoints);
        p->have |= TSNET_PC_ENDPOINTS;
    }
    if (key(c, p->key, o, "Key", TSNET_KEY_NODE)) {
        p->have |= TSNET_PC_KEY;
    }
    if (key(c, p->disco, o, "DiscoKey", TSNET_KEY_DISCO)) {
        p->have |= TSNET_PC_DISCO;
    }
    const cJSON *online = get(o, "Online");
    if (online && !cJSON_IsNull(online)) {
        p->online = flag(c, o, "Online");
        p->have |= TSNET_PC_ONLINE;
    }
    int present;
    p->last_seen = when(c, o, "LastSeen", &present);
    p->have |= present ? TSNET_PC_LAST_SEEN : 0;
    p->key_expiry = when(c, o, "KeyExpiry", &present);
    p->have |= present ? TSNET_PC_KEY_EXPIRY : 0;
    const cJSON *sig = get(o, "KeySignature");
    if (cJSON_IsString(sig) && sig->valuestring[0]) {
        p->have |= TSNET_PC_KEY_SIGNATURE;
    }
    const cJSON *cm = get(o, "CapMap");
    if (cm && !cJSON_IsNull(cm)) {
        p->have |= TSNET_PC_CAP_MAP;
    }
}

static tsnet_id_bool_t *id_bools(ctx_t *c, const cJSON *o, size_t *n)
{
    *n = 0;
    if (o == NULL || cJSON_IsNull(o)) {
        return NULL;
    }
    if (!cJSON_IsObject(o)) {
        c->bad = 1;
        return NULL;
    }
    size_t count = (size_t)cJSON_GetArraySize(o);
    tsnet_id_bool_t *out = count ? tsnet_calloc(count, sizeof *out) : NULL;
    if (count && out == NULL) {
        c->bad = 1;
        return NULL;
    }
    const cJSON *e;
    cJSON_ArrayForEach(e, o)
    {
        if (id_key(e->string, &out[*n].id) != 0 || !cJSON_IsBool(e)) {
            c->bad = 1;
            break;
        }
        out[(*n)++].value = cJSON_IsTrue(e);
    }
    return out;
}

static void derp_node(ctx_t *c, tsnet_derp_node_t *d, const cJSON *o)
{
    memset(d, 0, sizeof *d);
    if (!cJSON_IsObject(o)) {
        c->bad = 1;
        return;
    }
    str(c, d->name, sizeof d->name, o, "Name");
    d->region_id = (int)num(c, o, "RegionID");
    str(c, d->host_name, sizeof d->host_name, o, "HostName");
    str(c, d->cert_name, sizeof d->cert_name, o, "CertName");
    str(c, d->ipv4, sizeof d->ipv4, o, "IPv4");
    str(c, d->ipv6, sizeof d->ipv6, o, "IPv6");
    str(c, d->stun_test_ip, sizeof d->stun_test_ip, o, "STUNTestIP");
    d->stun_port = (int)num(c, o, "STUNPort");
    d->derp_port = (int)num(c, o, "DERPPort");
    d->stun_only = flag(c, o, "STUNOnly");
    d->insecure_for_tests = flag(c, o, "InsecureForTests");
    d->can_port80 = flag(c, o, "CanPort80");
}

void tsnet_derp_map_free(tsnet_derp_map_t *dm)
{
    if (dm == NULL) {
        return;
    }
    for (size_t i = 0; i < dm->n_regions; i++) {
        free(dm->regions[i].nodes);
    }
    free(dm->regions);
    free(dm->region_score);
    free(dm);
}

tsnet_derp_map_t *tsnet_derp_map_copy(const tsnet_derp_map_t *src)
{
    tsnet_derp_map_t *dm = tsnet_calloc(1, sizeof *dm);
    if (!dm) {
        return NULL;
    }
    *dm = *src;
    dm->regions = NULL;
    dm->region_score = NULL;
    dm->n_regions = dm->n_region_score = 0;
    dm->regions = tsnet_calloc(src->n_regions ? src->n_regions : 1, sizeof *dm->regions);
    dm->region_score = tsnet_calloc(src->n_region_score ? src->n_region_score : 1, sizeof *dm->region_score);
    if (!dm->regions || !dm->region_score) {
        tsnet_derp_map_free(dm);
        return NULL;
    }
    memcpy(dm->region_score, src->region_score, src->n_region_score * sizeof *dm->region_score);
    dm->n_region_score = src->n_region_score;
    for (size_t i = 0; i < src->n_regions; i++) {
        tsnet_derp_region_t *r = &dm->regions[i];
        *r = src->regions[i];
        r->nodes = tsnet_malloc((r->n_nodes ? r->n_nodes : 1) * sizeof *r->nodes);
        if (!r->nodes) {
            tsnet_derp_map_free(dm);
            return NULL;
        }
        memcpy(r->nodes, src->regions[i].nodes, r->n_nodes * sizeof *r->nodes);
        dm->n_regions = i + 1;
    }
    return dm;
}

static tsnet_derp_map_t *derp_map(ctx_t *c, const cJSON *o)
{
    if (o == NULL || cJSON_IsNull(o)) {
        return NULL;
    }
    tsnet_derp_map_t *dm = tsnet_calloc(1, sizeof *dm);
    if (!cJSON_IsObject(o) || dm == NULL) {
        c->bad = 1;
        free(dm);
        return NULL;
    }
    dm->omit_default_regions = flag(c, o, "omitDefaultRegions");
    const cJSON *regions = get(o, "Regions");
    if (regions && !cJSON_IsNull(regions)) {
        dm->has_regions = true;
        size_t count = cJSON_IsObject(regions) ? (size_t)cJSON_GetArraySize(regions) : 0;
        if (!cJSON_IsObject(regions) || (count && (dm->regions = tsnet_calloc(count, sizeof *dm->regions)) == NULL)) {
            c->bad = 1;
            return dm;
        }
        const cJSON *e;
        cJSON_ArrayForEach(e, regions)
        {
            int64_t id;
            if (id_key(e->string, &id) != 0) {
                c->bad = 1;
                break;
            }
            if (cJSON_IsNull(e)) {
                continue; // map.go: a nil region (headscale was seen to send one) is dropped
            }
            tsnet_derp_region_t *r = &dm->regions[dm->n_regions++];
            if (!cJSON_IsObject(e)) {
                c->bad = 1;
                break;
            }
            r->region_id = (int)num(c, e, "RegionID");
            // A region under another region's ID, or one ID twice, is refused: netcheck finds a region by its ID.
            bool dup = r->region_id != id;
            for (size_t k = 0; k + 1 < dm->n_regions && !dup; k++) {
                dup = dm->regions[k].region_id == r->region_id;
            }
            if (dup) {
                c->bad = 1;
                break;
            }
            str(c, r->code, sizeof r->code, e, "RegionCode");
            str(c, r->name, sizeof r->name, e, "RegionName");
            const cJSON *lat = get(e, "Latitude"), *lon = get(e, "Longitude");
            r->latitude = cJSON_IsNumber(lat) ? lat->valuedouble : 0;
            r->longitude = cJSON_IsNumber(lon) ? lon->valuedouble : 0;
            r->avoid = flag(c, e, "Avoid");
            r->no_measure_no_home = flag(c, e, "NoMeasureNoHome");
            const cJSON *ns = get(e, "Nodes");
            size_t nn = cJSON_IsArray(ns) ? (size_t)cJSON_GetArraySize(ns) : 0;
            if ((ns && !cJSON_IsNull(ns) && !cJSON_IsArray(ns)) || (nn && (r->nodes = tsnet_calloc(nn, sizeof *r->nodes)) == NULL)) {
                c->bad = 1;
                break;
            }
            const cJSON *dn;
            cJSON_ArrayForEach(dn, ns)
            {
                derp_node(c, &r->nodes[r->n_nodes++], dn);
            }
        }
    }
    const cJSON *hp = get(o, "HomeParams");
    if (hp && !cJSON_IsNull(hp)) {
        dm->has_home_params = true;
        const cJSON *rs = cJSON_IsObject(hp) ? get(hp, "RegionScore") : NULL;
        if (!cJSON_IsObject(hp) || (rs && !cJSON_IsNull(rs) && !cJSON_IsObject(rs))) {
            c->bad = 1;
            return dm;
        }
        if (rs && !cJSON_IsNull(rs)) {
            dm->has_region_score = true;
            size_t count = (size_t)cJSON_GetArraySize(rs);
            if (count && (dm->region_score = tsnet_calloc(count, sizeof *dm->region_score)) == NULL) {
                c->bad = 1;
                return dm;
            }
            const cJSON *e;
            cJSON_ArrayForEach(e, rs)
            {
                int64_t id;
                // A score is a finite multiplier near 1: ncplan scales latencies by it.
                if (id_key(e->string, &id) != 0 || !cJSON_IsNumber(e) || !(e->valuedouble >= 0 && e->valuedouble <= 1e6)) {
                    c->bad = 1;
                    break;
                }
                dm->region_score[dm->n_region_score++] = (tsnet_region_score_t){(int)id, e->valuedouble};
            }
        }
    }
    return dm;
}

void tsnet_map_response_free(tsnet_map_resp_t *m)
{
    if (m->node) {
        tsnet_node_free(m->node);
        free(m->node);
    }
    for (size_t i = 0; i < m->n_peers; i++) {
        tsnet_node_free(&m->peers[i]);
    }
    for (size_t i = 0; i < m->n_peers_changed; i++) {
        tsnet_node_free(&m->peers_changed[i]);
    }
    for (size_t i = 0; i < m->n_patches; i++) {
        free(m->patches[i].endpoints);
    }
    free(m->peers);
    free(m->peers_changed);
    free(m->peers_removed);
    free(m->patches);
    free(m->online_change);
    free(m->seen_change);
    tsnet_derp_map_free(m->derp_map);
    free(m->packet_filter_json);
    free(m->packet_filters_json);
    free(m->dial_plan_json);
    memset(m, 0, sizeof *m);
}

int tsnet_map_response_parse(tsnet_map_resp_t *m, const char *json, size_t len)
{
    memset(m, 0, sizeof *m);
    cJSON *root = tsnet_json_parse(json, len);
    if (!cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return -1;
    }
    ctx_t c = {0};
    m->keep_alive = flag(&c, root, "KeepAlive");
    const cJSON *self = get(root, "Node");
    if (self && !cJSON_IsNull(self)) {
        m->node = tsnet_malloc(sizeof *m->node);
        if (m->node == NULL) {
            c.bad = 1;
        } else {
            node(&c, m->node, self, true);
        }
    }
    m->peers = nodes(&c, get(root, "Peers"), &m->n_peers);
    m->peers_changed = nodes(&c, get(root, "PeersChanged"), &m->n_peers_changed);
    const cJSON *removed = get(root, "PeersRemoved");
    if (removed && !cJSON_IsNull(removed)) {
        size_t count = cJSON_IsArray(removed) ? (size_t)cJSON_GetArraySize(removed) : 0;
        if (!cJSON_IsArray(removed) || (count && (m->peers_removed = tsnet_calloc(count, sizeof *m->peers_removed)) == NULL)) {
            c.bad = 1;
        } else {
            const cJSON *e;
            cJSON_ArrayForEach(e, removed)
            {
                if (!cJSON_IsNumber(e) || !(e->valuedouble >= -9.2e18 && e->valuedouble <= 9.2e18)) {
                    c.bad = 1; // past int64, the cast would be undefined
                    break;
                }
                m->peers_removed[m->n_peers_removed++] = (int64_t)e->valuedouble;
            }
        }
    }
    const cJSON *patches = get(root, "PeersChangedPatch");
    if (patches && !cJSON_IsNull(patches)) {
        size_t count = cJSON_IsArray(patches) ? (size_t)cJSON_GetArraySize(patches) : 0;
        if (!cJSON_IsArray(patches) || (count && (m->patches = tsnet_calloc(count, sizeof *m->patches)) == NULL)) {
            c.bad = 1;
        } else {
            const cJSON *e;
            cJSON_ArrayForEach(e, patches)
            {
                patch(&c, &m->patches[m->n_patches++], e);
            }
        }
    }
    m->online_change = id_bools(&c, get(root, "OnlineChange"), &m->n_online_change);
    m->seen_change = id_bools(&c, get(root, "PeerSeenChange"), &m->n_seen_change);
    m->derp_map = derp_map(&c, get(root, "DERPMap"));
    // []FilterRule and map[string][]FilterRule: another type fails the message, as Go's decode does.
    const cJSON *pf = get(root, "PacketFilter"), *pfs = get(root, "PacketFilters");
    if ((pf && !cJSON_IsNull(pf) && !cJSON_IsArray(pf)) || (pfs && !cJSON_IsNull(pfs) && !cJSON_IsObject(pfs))) {
        c.bad = 1;
    }
    m->packet_filter_json = raw(pf);
    m->packet_filters_json = raw(pfs);
    str(&c, m->domain, sizeof m->domain, root, "Domain");
    m->control_time = when(&c, root, "ControlTime", NULL);
    const cJSON *ping = get(root, "PingRequest");
    if (ping && !cJSON_IsNull(ping)) {
        if (!cJSON_IsObject(ping)) {
            c.bad = 1;
        } else {
            m->has_ping = true;
            str(&c, m->ping_url, sizeof m->ping_url, ping, "URL");
            str(&c, m->ping_types, sizeof m->ping_types, ping, "Types");
            m->ping_url_is_noise = flag(&c, ping, "URLIsNoise");
            m->ping_log = flag(&c, ping, "Log");
        }
    }
    m->dial_plan_json = raw(get(root, "ControlDialPlan"));
    cJSON_Delete(root);
    if (c.bad) {
        tsnet_map_response_free(m);
        return -1;
    }
    return 0;
}
