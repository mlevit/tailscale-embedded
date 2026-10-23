// A tailnet node in one call. See server.h. The wiring follows ipnlocal and wgengine: magicsock's reports go
// to the control client, its non-disco packets to WireGuard, WireGuard's packets to magicsock and the tun, and each
// netmap to all of them.
#include "platform.h"
#include "server.h"
#include <stdlib.h>
#include <string.h>
#include "crypto.h"

struct tsnet_server {
    tsnet_server_cfg_t cfg;
    tsnet_client_t *client;
    const tsnet_identity_t *id;
    tsnet_magicsock_t *ms;
    tsnet_wgdev_t *wg;
    tsnet_tun_t *tun;
    uint8_t disco_priv[TSNET_KEY_LEN];
    // The WireGuard peers the last netmap configured, so the next one can remove those it drops.
    uint8_t (*wg_keys)[TSNET_KEY_LEN];
    size_t n_wg;
};

// A peer's AllowedIPs as WireGuard takes them, for a node that uses no exit node and accepts no subnet routes (tsnet
// does neither): its own Tailscale addresses only (tsaddr.IsTailscaleIP: 100.64.0.0/10, fd7a:115c:a1e0::/48). Go's
// WireGuard config leaves out an exit node's /0 unless that exit node is selected, and subnet routes unless routes are
// accepted. Otherwise a peer holding them would own every address no other peer holds more narrowly. Returns how many
// it kept in `out` (room for n_allowed_ips).
static size_t wg_allowed_ips(const tsnet_node_t *n, tsnet_prefix_t *out)
{
    static const uint8_t ula[6] = {0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0};
    size_t k = 0;
    for (size_t i = 0; i < n->n_allowed_ips; i++) {
        const tsnet_prefix_t *p = &n->allowed_ips[i];
        bool ts = p->ip.is6 ? memcmp(p->ip.ip, ula, sizeof ula) == 0 : p->ip.ip[0] == 100 && (p->ip.ip[1] & 0xc0) == 64;
        if (p->bits > 0 && ts) {
            out[k++] = *p;
        }
    }
    return k;
}

static bool in_keys(const uint8_t (*keys)[TSNET_KEY_LEN], size_t n, const uint8_t key[TSNET_KEY_LEN])
{
    for (size_t i = 0; i < n; i++) {
        if (memcmp(keys[i], key, TSNET_KEY_LEN) == 0) {
            return true;
        }
    }
    return false;
}

// The netmap's peers become WireGuard's, each with its routes. A peer that is expired, or that left the netmap, is
// removed, its keys wiped, as Go's WireGuard config leaves out an expired peer and drops a deleted one at once.
static void set_wg_peers(tsnet_server_t *s, const tsnet_netmap_t *nm)
{
    uint8_t (*keys)[TSNET_KEY_LEN] = tsnet_calloc(nm->n_peers ? nm->n_peers : 1, TSNET_KEY_LEN);
    if (!keys) {
        return; // the old set stays until a netmap that fits
    }
    size_t n = 0;
    for (size_t i = 0; i < nm->n_peers; i++) {
        const tsnet_node_t *p = &nm->peers[i];
        if (p->expired) {
            continue;
        }
        tsnet_prefix_t *routes = tsnet_calloc(p->n_allowed_ips ? p->n_allowed_ips : 1, sizeof *routes);
        if (!routes) {
            continue;
        }
        tsnet_wgdev_add_peer(s->wg, p->key, tsnet_now_ms());
        tsnet_tun_set_routes(s->tun, p->key, routes, wg_allowed_ips(p, routes));
        tsnet_tun_set_jailed(s->tun, p->key, p->is_jailed);
        free(routes);
        memcpy(keys[n++], p->key, TSNET_KEY_LEN);
    }
    for (size_t i = 0; i < s->n_wg; i++) {
        if (!in_keys(keys, n, s->wg_keys[i])) {
            tsnet_wgdev_remove_peer(s->wg, s->wg_keys[i]);
            tsnet_tun_remove_peer(s->tun, s->wg_keys[i]);
        }
    }
    free(s->wg_keys);
    s->wg_keys = keys;
    s->n_wg = n;
}

static void wg_send(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    tsnet_server_t *s = ctx;
    tsnet_magicsock_send(s->ms, peer, pkt, len);
}

static void wg_deliver(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    tsnet_server_t *s = ctx;
    if (s->cfg.on_deliver) {
        s->cfg.on_deliver(s->cfg.ctx, peer, pkt, len);
    }
    tsnet_tun_deliver(s->tun, peer, pkt, len);
}

static void tun_send(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    tsnet_server_t *s = ctx;
    if (s->wg) {
        tsnet_wgdev_send(s->wg, peer, pkt, len, tsnet_now_ms());
    }
}

static void ms_packet(void *ctx, const uint8_t *pkt, size_t len, const uint8_t *src, size_t src_len)
{
    tsnet_server_t *s = ctx;
    tsnet_wgdev_receive(s->wg, pkt, len, src, src_len, tsnet_now_ms());
}

// NetInfo and the endpoints go to control, as ipnlocal passes magicsock's callbacks to the control client.
static void on_netinfo(void *ctx, const tsnet_net_info_t *ni)
{
    tsnet_server_t *s = ctx;
    tsnet_client_set_netinfo(s->client, ni);
    if (s->cfg.on_netinfo) {
        s->cfg.on_netinfo(s->cfg.ctx, ni);
    }
}

static void on_endpoints(void *ctx, const tsnet_selfep_t *eps, size_t n)
{
    tsnet_server_t *s = ctx;
    tsnet_addrport_t wire[TSNET_SELFEPS_MAX];
    int types[TSNET_SELFEPS_MAX];
    tsnet_selfeps_wire(eps, n, wire, types);
    tsnet_client_set_endpoints(s->client, wire, types, n);
    if (s->cfg.on_endpoints) {
        s->cfg.on_endpoints(s->cfg.ctx, n);
    }
}

static void on_ping(void *ctx, const uint8_t key[TSNET_KEY_LEN], const tsnet_ping_result_t *res, int region)
{
    tsnet_server_t *s = ctx;
    if (s->cfg.on_ping) {
        s->cfg.on_ping(s->cfg.ctx, key, res, region);
    }
}

static bool stun_filter(void *ctx)
{
    tsnet_server_t *s = ctx;
    return s->cfg.stun_filter(s->cfg.ctx);
}

static void on_state(void *ctx, tsnet_client_state_t state, const char *detail)
{
    tsnet_server_t *s = ctx;
    if (s->cfg.on_state) {
        s->cfg.on_state(s->cfg.ctx, state, detail);
    }
}

// The first netmap: the node key is registered by now, so magicsock and WireGuard can start.
static bool start_data_plane(tsnet_server_t *s)
{
    tsnet_magicsock_cfg_t mc = {
        .node_priv = s->id->node,
        .disco_priv = s->disco_priv,
        .use_http = s->cfg.use_derp_http,
        .ctx = s,
        .on_netinfo = on_netinfo,
        .on_endpoints = on_endpoints,
        .on_ping = on_ping,
        .on_packet = ms_packet,
        .stun_filter = s->cfg.stun_filter ? stun_filter : NULL,
    };
    s->ms = tsnet_magicsock_new(&mc);
    tsnet_wgdev_cfg_t wc = {.priv = s->id->node, .ctx = s, .send = wg_send, .deliver = wg_deliver};
    s->wg = s->ms ? tsnet_wgdev_new(&wc) : NULL;
    if (!s->wg) {
        tsnet_log(TSNET_LOG_ERROR, "server: can't start magicsock or WireGuard");
        tsnet_magicsock_free(s->ms);
        s->ms = NULL;
        return false;
    }
    return true;
}

static void on_netmap(void *ctx, const tsnet_netmap_t *nm, int changed)
{
    tsnet_server_t *s = ctx;
    if (!s->ms) {
        if (!start_data_plane(s)) {
            return; // tried again at the next netmap
        }
        changed |= TSNET_NM_DERP;
    }
    set_wg_peers(s, nm);
    if (nm->has_node) {
        for (size_t i = 0; i < nm->node.n_addresses; i++) {
            if (!nm->node.addresses[i].ip.is6) {
                tsnet_tun_set_addr(s->tun, nm->node.addresses[i].ip.ip);
                break;
            }
        }
        // The packet filter: the netmap's rules, and the node's own addresses as its local ones.
        char *rules = tsnet_netmap_filter_rules_json(nm);
        tsnet_tun_set_filter(s->tun, rules, nm->node.addresses, nm->node.n_addresses);
        free(rules);
    }
    if ((changed & TSNET_NM_DERP) && nm->derp_map) {
        tsnet_magicsock_set_derp_map(s->ms, nm->derp_map);
    }
    tsnet_magicsock_set_peers(s->ms, nm->peers, nm->n_peers);
    if (s->cfg.on_netmap) {
        s->cfg.on_netmap(s->cfg.ctx, nm, changed);
    }
}

tsnet_server_t *tsnet_server_new(const tsnet_server_cfg_t *cfg)
{
    tsnet_server_t *s = tsnet_calloc(1, sizeof *s);
    if (!s) {
        return NULL;
    }
    s->cfg = *cfg;
    tsnet_tun_cfg_t tc = {.ctx = s, .send = tun_send, .input = cfg->input};
    s->tun = tsnet_tun_new(&tc);
    tsnet_client_cfg_t cc = cfg->client;
    cc.ctx = s;
    cc.on_netmap = on_netmap;
    cc.on_state = on_state;
    s->client = s->tun ? tsnet_client_new(&cc) : NULL;
    uint8_t disco_pub[TSNET_KEY_LEN];
    if (!s->client || tsnet_new_x25519_key(s->disco_priv) != 0 || tsnet_x25519_public(disco_pub, s->disco_priv) != 0) {
        tsnet_server_free(s);
        return NULL;
    }
    s->id = tsnet_client_identity(s->client);
    tsnet_client_set_disco_key(s->client, disco_pub); // before the first poll, so its MapRequest carries it
    return s;
}

void tsnet_server_free(tsnet_server_t *s)
{
    if (!s) {
        return;
    }
    tsnet_tun_free(s->tun);
    tsnet_wgdev_free(s->wg);
    tsnet_magicsock_free(s->ms);
    tsnet_client_free(s->client);
    tsnet_wipe(s->disco_priv, sizeof s->disco_priv);
    free(s->wg_keys);
    free(s);
}

int tsnet_server_poll(tsnet_server_t *s, tsnet_poll_t *p, int max, int *wait_ms)
{
    int n = tsnet_client_poll(s->client, p, max < 4 ? max : 4, wait_ms);
    if (s->ms && max - n > 1) {
        int mwait = -1;
        n += tsnet_magicsock_poll(s->ms, &p[n], max - n - 1 < 16 ? max - n - 1 : 16, &mwait);
        if (mwait >= 0 && (*wait_ms < 0 || mwait < *wait_ms)) {
            *wait_ms = mwait;
        }
        uint64_t next = tsnet_wgdev_next(s->wg), now = tsnet_now_ms();
        if (next) {
            int until = next > now ? (int)(next - now) : 0;
            *wait_ms = *wait_ms < 0 || until < *wait_ms ? until : *wait_ms;
        }
    }
    if (tsnet_tun_pending(s->tun)) {
        *wait_ms = 0;
    }
    if (n < max) {
        p[n++] = (tsnet_poll_t){.fd = tsnet_tun_fd(s->tun)}; // lwIP has packets for the tunnel
    }
    return n;
}

void tsnet_server_step(tsnet_server_t *s)
{
    tsnet_client_step(s->client);
    if (s->ms) {
        tsnet_magicsock_set_control(s->ms, tsnet_client_in_map_poll(s->client));
        tsnet_magicsock_step(s->ms);
        tsnet_wgdev_step(s->wg, tsnet_now_ms());
    }
    tsnet_tun_step(s->tun);
}

tsnet_client_t *tsnet_server_client(tsnet_server_t *s)
{
    return s->client;
}

tsnet_magicsock_t *tsnet_server_magicsock(tsnet_server_t *s)
{
    return s->ms;
}

tsnet_wgdev_t *tsnet_server_wgdev(tsnet_server_t *s)
{
    return s->wg;
}
