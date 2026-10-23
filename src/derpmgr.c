// magicsock's DERP connections. See derpmgr.h; the Go is wgengine/magicsock/derp.go.
#include "platform.h"
#include "derpmgr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "policy.h"

typedef struct {
    int region;          // 0: a free slot
    tsnet_derphttp_t *c; // NULL while waiting to dial again
    unsigned gen;        // connGen: this region's connections made, so a route learned on an old one can be told apart
    tsnet_backoff_t bo;
    uint64_t retry_at;   // when c is NULL: when to dial again
    uint64_t last_write; // lastWrite: the last time a packet was routed here
    uint64_t created;
    uint64_t last_frame; // health's NoteDERPRegionReceivedFrame: recorded at most every 5 s (frameReceiveRecordRate)
    bool connected;      // ServerInfo in on the current connection
} slot_t;

typedef struct {
    uint8_t peer[TSNET_KEY_LEN];
    int region; // 0: unused
    unsigned gen;
    uint64_t at;
} route_t;

struct tsnet_derpmgr {
    tsnet_derpmgr_cfg_t cfg;
    uint8_t priv[TSNET_KEY_LEN];
    tsnet_derp_map_t *map; // derpMap, copied; NULL: no DERP
    int home;              // myDerp
    slot_t slots[TSNET_DERPMGR_REGIONS];
    route_t routes[TSNET_DERPMGR_ROUTES];
    bool clean_armed; // derpCleanupTimerArmed
    uint64_t clean_at;
    slot_t *reading; // the slot whose connection is being stepped (for its callbacks)
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

static bool node_equal(const tsnet_derp_node_t *a, const tsnet_derp_node_t *b)
{
    return strcmp(a->name, b->name) == 0 && a->region_id == b->region_id && strcmp(a->host_name, b->host_name) == 0 &&
           strcmp(a->cert_name, b->cert_name) == 0 && strcmp(a->ipv4, b->ipv4) == 0 && strcmp(a->ipv6, b->ipv6) == 0 &&
           strcmp(a->stun_test_ip, b->stun_test_ip) == 0 && a->stun_port == b->stun_port &&
           a->derp_port == b->derp_port && a->stun_only == b->stun_only &&
           a->insecure_for_tests == b->insecure_for_tests && a->can_port80 == b->can_port80;
}

// reflect.DeepEqual of two regions (either may be NULL).
static bool region_equal(const tsnet_derp_region_t *a, const tsnet_derp_region_t *b)
{
    if (!a || !b) {
        return a == b;
    }
    if (a->region_id != b->region_id || strcmp(a->code, b->code) != 0 || strcmp(a->name, b->name) != 0 ||
        a->latitude != b->latitude || a->longitude != b->longitude || a->avoid != b->avoid ||
        a->no_measure_no_home != b->no_measure_no_home || a->n_nodes != b->n_nodes) {
        return false;
    }
    for (size_t i = 0; i < a->n_nodes; i++) {
        if (!node_equal(&a->nodes[i], &b->nodes[i])) {
            return false;
        }
    }
    return true;
}

static slot_t *slot_of(tsnet_derpmgr_t *m, int region)
{
    for (int i = 0; i < TSNET_DERPMGR_REGIONS; i++) {
        if (region != 0 && m->slots[i].region == region) {
            return &m->slots[i];
        }
    }
    return NULL;
}

// removeDerpPeerRoute for every peer learned on this slot's current connection (runDerpReader's peerPresent).
static void forget_routes(tsnet_derpmgr_t *m, const slot_t *s)
{
    for (int i = 0; i < TSNET_DERPMGR_ROUTES; i++) {
        if (m->routes[i].region == s->region && m->routes[i].gen == s->gen) {
            m->routes[i].region = 0;
        }
    }
}

static void close_slot(tsnet_derpmgr_t *m, slot_t *s, const char *why)
{
    uint64_t now = tsnet_now_ms();
    tsnet_log(TSNET_LOG_INFO, "magicsock: closing connection to derp-%d (%s), age %us", s->region, why,
              (unsigned)((now - s->created) / 1000));
    forget_routes(m, s);
    tsnet_derphttp_free(s->c);
    memset(s, 0, sizeof *s);
}

static uint32_t rnd32(void)
{
    uint32_t r = 0;
    tsnet_random(&r, sizeof r);
    return r;
}

static void on_msg(void *ctx, const tsnet_derp_msg_t *msg);

static void connect_slot(tsnet_derpmgr_t *m, slot_t *s)
{
    tsnet_derphttp_cfg_t dc = {
        .region = region_of(m->map, s->region),
        .node_priv = m->priv,
        .use_http = m->cfg.use_http,
        .preferred = s->region == m->home,
        .on_msg = on_msg,
        .ctx = m,
    };
    s->connected = false;
    s->c = dc.region ? tsnet_derphttp_connect(&dc) : NULL;
    if (!s->c) {
        s->retry_at = tsnet_now_ms() + tsnet_backoff_fail(&s->bo, rnd32());
    }
}

static void schedule_clean(tsnet_derpmgr_t *m)
{
    if (!m->clean_armed) {
        m->clean_armed = true;
        m->clean_at = tsnet_now_ms() + TSNET_DERP_CLEAN_MS;
    }
}

// derpWriteChanForRegion: the slot for a region, opening its connection when there is none. `peer` may be NULL.
static slot_t *slot_for(tsnet_derpmgr_t *m, int region, const uint8_t *peer)
{
    if (!m->map || !region_of(m->map, region)) {
        return NULL;
    }
    uint64_t now = tsnet_now_ms();
    slot_t *s = slot_of(m, region);
    if (s) {
        s->last_write = now;
        return s;
    }
    // A reply to a peer we heard over another region goes back the way it came (issue 150).
    for (int i = 0; peer && i < TSNET_DERPMGR_ROUTES; i++) {
        route_t *r = &m->routes[i];
        if (r->region && memcmp(r->peer, peer, TSNET_KEY_LEN) == 0) {
            slot_t *rs = slot_of(m, r->region);
            if (rs && rs->gen == r->gen) {
                rs->last_write = now;
                return rs;
            }
        }
    }
    for (int i = 0; i < TSNET_DERPMGR_REGIONS; i++) {
        if (m->slots[i].region == 0) {
            s = &m->slots[i];
            break;
        }
    }
    if (!s) {
        tsnet_log(TSNET_LOG_WARN, "magicsock: no room for a connection to derp-%d", region);
        return NULL;
    }
    char why[24] = "home-keep-alive";
    if (peer) {
        snprintf(why, sizeof why, "[%02x%02x%02x]", peer[0], peer[1], peer[2]);
    }
    tsnet_log(TSNET_LOG_INFO, "magicsock: adding connection to derp-%d for %s", region, why);
    s->region = region;
    s->created = s->last_write = now;
    tsnet_backoff_init(&s->bo, TSNET_DERP_BACKOFF_MAX_MS);
    connect_slot(m, s);
    schedule_clean(m);
    return s;
}

// addDerpPeerRoute: the peer's entry, else a free one, else the oldest.
static route_t *route_entry(tsnet_derpmgr_t *m, const uint8_t *peer)
{
    route_t *free_one = NULL, *oldest = &m->routes[0];
    for (int i = 0; i < TSNET_DERPMGR_ROUTES; i++) {
        route_t *e = &m->routes[i];
        if (e->region && memcmp(e->peer, peer, TSNET_KEY_LEN) == 0) {
            return e;
        }
        if (!free_one && e->region == 0) {
            free_one = e;
        }
        if (e->at < oldest->at) {
            oldest = e;
        }
    }
    return free_one ? free_one : oldest;
}

static void on_msg(void *ctx, const tsnet_derp_msg_t *msg)
{
    tsnet_derpmgr_t *m = ctx;
    slot_t *s = m->reading;
    if (!s) {
        return;
    }
    tsnet_backoff_reset(&s->bo); // runDerpReader: bo.BackOff(ctx, nil) after each message
    uint64_t now = tsnet_now_ms();
    if (s->last_frame == 0 || now - s->last_frame > 5000) {
        s->last_frame = now;
    }
    switch (msg->type) {
    case TSNET_DERP_SERVER_INFO:
        // derphttp's connGen counts connections made, not attempts: failed dials leave it alone.
        s->connected = true;
        s->gen++;
        tsnet_log(TSNET_LOG_INFO, "magicsock: derp-%d connected; connGen=%u", s->region, s->gen);
        break;
    case TSNET_DERP_PACKET: {
        route_t *r = route_entry(m, msg->key); // the sender can be reached back over this connection
        memcpy(r->peer, msg->key, TSNET_KEY_LEN);
        r->region = s->region;
        r->gen = s->gen;
        r->at = tsnet_now_ms();
        if (m->cfg.on_packet) {
            m->cfg.on_packet(m->cfg.ctx, s->region, msg->key, msg->data, msg->len);
        }
        break;
    }
    case TSNET_DERP_PEER_GONE:
        if (msg->reason == TSNET_DERP_GONE_NOT_HERE) {
            tsnet_log(TSNET_LOG_INFO, "magicsock: derp-%d does not know about peer [%02x%02x%02x], removing route",
                      s->region, msg->key[0], msg->key[1], msg->key[2]);
        } else if (msg->reason != TSNET_DERP_GONE_DISCONNECTED) {
            tsnet_log(TSNET_LOG_WARN, "magicsock: [unexpected] derp-%d peer gone, reason %u, removing route", s->region,
                      msg->reason);
        }
        for (int i = 0; i < TSNET_DERPMGR_ROUTES; i++) {
            route_t *r = &m->routes[i];
            if (r->region == s->region && r->gen == s->gen && memcmp(r->peer, msg->key, TSNET_KEY_LEN) == 0) {
                r->region = 0;
            }
        }
        break;
    case TSNET_DERP_HEALTH:
        if (msg->len) {
            // The server's text, printable ASCII only and cut, so it can't forge log lines.
            char text[128];
            size_t n = msg->len < sizeof text - 1 ? msg->len : sizeof text - 1;
            for (size_t i = 0; i < n; i++) {
                text[i] = msg->data[i] >= 0x20 && msg->data[i] < 0x7f ? (char)msg->data[i] : '?';
            }
            text[n] = '\0';
            tsnet_log(TSNET_LOG_WARN, "magicsock: derp-%d health: %s", s->region, text);
        }
        break;
    default:
        break;
    }
}

tsnet_derpmgr_t *tsnet_derpmgr_new(const tsnet_derpmgr_cfg_t *cfg)
{
    tsnet_derpmgr_t *m = tsnet_calloc(1, sizeof *m);
    if (!m) {
        return NULL;
    }
    m->cfg = *cfg;
    memcpy(m->priv, cfg->node_priv, TSNET_KEY_LEN);
    m->cfg.node_priv = NULL;
    return m;
}

void tsnet_derpmgr_free(tsnet_derpmgr_t *m)
{
    if (!m) {
        return;
    }
    for (int i = 0; i < TSNET_DERPMGR_REGIONS; i++) {
        tsnet_derphttp_free(m->slots[i].c);
    }
    tsnet_derp_map_free(m->map);
    tsnet_wipe(m->priv, sizeof m->priv);
    free(m);
}

int tsnet_derpmgr_set_home(tsnet_derpmgr_t *m, int region)
{
    if (!m->map) {
        m->home = 0; // setNearestDERP: !wantDerpLocked
        return 0;
    }
    if (region == 0) {
        // pickDERPFallback.
        int ids[64];
        size_t n = 0;
        for (size_t i = 0; i < m->map->n_regions && n < 64; i++) {
            ids[n++] = m->map->regions[i].region_id;
        }
        region = tsnet_derp_fallback(ids, n, m->home, rnd32());
    }
    if (region == m->home) {
        return region;
    }
    m->home = region;
    if (region == 0) {
        return 0;
    }
    // setNearestDERP: a region the map lacks is still set (and logged); derpWriteChanForRegion then opens nothing.
    const tsnet_derp_region_t *r = region_of(m->map, region);
    if (r) {
        tsnet_log(TSNET_LOG_INFO, "magicsock: home is now derp-%d (%s)", region, r->code);
    } else {
        tsnet_log(TSNET_LOG_WARN, "magicsock: [unexpected] derpMap.Regions[%d] is nil", region);
    }
    for (int i = 0; i < TSNET_DERPMGR_REGIONS; i++) {
        if (m->slots[i].c) {
            tsnet_derphttp_note_preferred(m->slots[i].c, m->slots[i].region == region);
        }
    }
    slot_for(m, region, NULL); // goDerpConnect
    return region;
}

int tsnet_derpmgr_home(const tsnet_derpmgr_t *m)
{
    return m->home;
}

void tsnet_derpmgr_set_map(tsnet_derpmgr_t *m, const tsnet_derp_map_t *dm)
{
    // Unchanged: nothing to do (reflect.DeepEqual).
    if (dm && m->map && dm->n_regions == m->map->n_regions) {
        bool same = true;
        for (size_t i = 0; same && i < dm->n_regions; i++) {
            same = region_equal(&dm->regions[i], region_of(m->map, dm->regions[i].region_id));
        }
        if (same) {
            return;
        }
    }
    tsnet_derp_map_t *old = m->map;
    m->map = dm ? tsnet_derp_map_copy(dm) : NULL;
    for (int i = 0; i < TSNET_DERPMGR_REGIONS; i++) {
        slot_t *s = &m->slots[i];
        if (s->region == 0) {
            continue;
        }
        if (!m->map) {
            close_slot(m, s, "derp-disabled");
        } else if (!region_equal(region_of(old, s->region), region_of(m->map, s->region))) {
            if (s->region == m->home) {
                m->home = 0;
            }
            close_slot(m, s, "derp-region-redefined");
        }
    }
    if (old && m->map && region_of(old, m->home) && !region_of(m->map, m->home)) {
        m->home = 0; // a home with no connection open, gone from the map
    }
    tsnet_derp_map_free(old);
    if (!m->map) {
        m->home = 0;
    }
    // The home is picked by the caller: magicsock's ReSTUN, whose netcheck report goes to tsnet_derpmgr_set_home.
}

int tsnet_derpmgr_send(tsnet_derpmgr_t *m, int region, const uint8_t dst[TSNET_KEY_LEN], const uint8_t *pkt,
                       size_t len)
{
    slot_t *s = slot_for(m, region, dst);
    if (s && !s->c) {
        // derphttp's Send connects first: a write during the reader's backoff dials at once (the backoff only spaces
        // out reconnects when nothing is written).
        connect_slot(m, s);
    }
    if (!s || !s->c) {
        return -1; // no such region, no room, or no node to dial
    }
    return tsnet_derphttp_send(s->c, dst, pkt, len);
}

// cleanStaleDerp.
static void clean_stale(tsnet_derpmgr_t *m, uint64_t now)
{
    m->clean_armed = false;
    bool some_non_home = false;
    for (int i = 0; i < TSNET_DERPMGR_REGIONS; i++) {
        slot_t *s = &m->slots[i];
        if (s->region == 0 || s->region == m->home) {
            continue;
        }
        if (tsnet_derp_idle(s->region, m->home, s->last_write, now)) {
            close_slot(m, s, "idle");
        } else {
            some_non_home = true;
        }
    }
    if (some_non_home) {
        schedule_clean(m);
    }
}

void tsnet_derpmgr_step(tsnet_derpmgr_t *m)
{
    for (int i = 0; i < TSNET_DERPMGR_REGIONS; i++) {
        slot_t *s = &m->slots[i];
        if (s->region == 0) {
            continue;
        }
        if (!s->c) {
            if (tsnet_now_ms() >= s->retry_at) {
                connect_slot(m, s);
            }
            continue;
        }
        m->reading = s;
        tsnet_derphttp_step(s->c);
        m->reading = NULL;
        if (s->region != 0 && s->c && tsnet_derphttp_state(s->c) == TSNET_DERPHTTP_FAILED) {
            // runDerpReader: forget this connection's peer routes, back off, then dial again.
            forget_routes(m, s);
            tsnet_derphttp_free(s->c);
            s->c = NULL;
            s->connected = false;
            uint32_t wait = tsnet_backoff_fail(&s->bo, rnd32());
            s->retry_at = tsnet_now_ms() + wait;
            tsnet_log(TSNET_LOG_INFO, "magicsock: derp-%d: dialing again in %u ms", s->region, (unsigned)wait);
        }
    }
    uint64_t now = tsnet_now_ms();
    if (m->clean_armed && now >= m->clean_at) {
        clean_stale(m, now);
    }
}

int tsnet_derpmgr_poll(const tsnet_derpmgr_t *m, tsnet_poll_t *p, int max, int *wait_ms)
{
    uint64_t now = tsnet_now_ms();
    int64_t until = -1;
    int n = 0;
    for (int i = 0; i < TSNET_DERPMGR_REGIONS; i++) {
        const slot_t *s = &m->slots[i];
        if (s->region == 0) {
            continue;
        }
        int64_t t;
        if (s->c) {
            int w;
            if (n < max) {
                n += tsnet_derphttp_poll(s->c, &p[n], &w);
            } else {
                tsnet_derphttp_poll(s->c, &(tsnet_poll_t){0}, &w);
            }
            t = w < 0 ? -1 : (int64_t)(now + (uint64_t)w);
        } else {
            t = (int64_t)s->retry_at;
        }
        if (t >= 0 && (until < 0 || t < until)) {
            until = t;
        }
    }
    if (m->clean_armed && (until < 0 || (int64_t)m->clean_at < until)) {
        until = (int64_t)m->clean_at;
    }
    *wait_ms = until < 0 ? -1 : until <= (int64_t)now ? 0 : (int)(until - (int64_t)now);
    return n;
}

int tsnet_derpmgr_regions(const tsnet_derpmgr_t *m, int *regions, int max)
{
    int n = 0;
    for (int i = 0; i < TSNET_DERPMGR_REGIONS && n < max; i++) {
        if (m->slots[i].region != 0) {
            int r = m->slots[i].region, j = n++;
            for (; j > 0 && regions[j - 1] > r; j--) {
                regions[j] = regions[j - 1];
            }
            regions[j] = r;
        }
    }
    return n;
}

uint64_t tsnet_derpmgr_last_frame(const tsnet_derpmgr_t *m, int region)
{
    for (int i = 0; i < TSNET_DERPMGR_REGIONS; i++) {
        if (m->slots[i].region == region && region != 0) {
            return m->slots[i].last_frame;
        }
    }
    return 0;
}

unsigned tsnet_derpmgr_conngen(const tsnet_derpmgr_t *m, int region)
{
    for (int i = 0; i < TSNET_DERPMGR_REGIONS; i++) {
        if (m->slots[i].region == region && region != 0) {
            return m->slots[i].gen;
        }
    }
    return 0;
}

bool tsnet_derpmgr_connected(const tsnet_derpmgr_t *m, int region)
{
    for (int i = 0; i < TSNET_DERPMGR_REGIONS; i++) {
        if (m->slots[i].region == region && region != 0) {
            return m->slots[i].connected && m->slots[i].c && tsnet_derphttp_accepted(m->slots[i].c);
        }
    }
    return false;
}
