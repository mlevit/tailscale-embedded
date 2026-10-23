// magicsock. See magicsock.h; the Go is wgengine/magicsock/magicsock.go and derp.go.
#include "platform.h"
#include "magicsock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "disco.h"
#include "endpoint.h"
#include "identity.h"
#include "stun.h"

#define RESTUN_MIN_MS 20000 // periodicReSTUN: between 20 and 26 s, just under a common 30 s UDP NAT timeout
#define RESTUN_MAX_MS 26000
#define ENDPOINTS_FRESH_MS 27000 // endpointsFreshEnoughDuration
#define SESSION_ACTIVE_MS 45000  // sessionActiveTimeout, against the idle time

// A peer (peerMap's endpoint): its keys from the netmap, the disco shared key (discoInfo), and its paths.
typedef struct {
    uint8_t key[TSNET_KEY_LEN];
    uint8_t disco[TSNET_KEY_LEN];
    bool has_disco;
    uint8_t shared[TSNET_KEY_LEN]; // with has_disco: this node's disco key with the peer's
    int home_derp;                 // HomeDERP, 0 none
    int last_derp;                 // the region it last sent from over DERP (fallbackDERPRegionForPeer)
    bool expired;                  // its node key expired: nothing is sent to it (errExpired)
    bool cmm_pending;              // a CallMeMaybe waits for fresh endpoints (onEndpointRefreshed)
    tsnet_endpoint_t ep;
} ms_peer_t;

struct tsnet_magicsock {
    tsnet_magicsock_cfg_t cfg;
    int fd;
    tsnet_derpmgr_t *derp;
    tsnet_netcheck_t *nc;
    tsnet_derp_map_t *dm; // the current map, for netcheck
    ms_peer_t *peers;
    size_t peers_n;
    uint8_t node_pub[TSNET_KEY_LEN]; // a Ping's NodeKey
    bool in_map_poll;
    bool want_restun;         // wantEndpointsUpdate: a ReSTUN asked for during a report
    char want_why[32];
    bool periodic;            // the periodic ReSTUN timer is set
    uint64_t periodic_at;
    bool have_netinfo;
    tsnet_net_info_t netinfo; // netInfoLast
    tsnet_tracker_t tracker;  // endpointTracker
    tsnet_selfep_t eps[TSNET_SELFEPS_MAX]; // lastEndpoints
    size_t n_eps;
    uint64_t eps_time; // lastEndpointsTime (ms), 0 never
    uint64_t last_traffic; // the last packet (not STUN or disco) sent or received: the idle time's start (ms)
    uint8_t disco_priv[TSNET_KEY_LEN], disco_pub[TSNET_KEY_LEN];
};

static int send_stun(void *ctx, const uint8_t ip[16], uint16_t port, const uint8_t *pkt, size_t len)
{
    tsnet_magicsock_t *m = ctx;
    if (m->cfg.stun_filter && !m->cfg.stun_filter(m->cfg.ctx)) {
        return (int)len; // dropped, as a network that blocks UDP would
    }
    return tsnet_udp_send(m->fd, ip, port, pkt, len);
}

static uint64_t last_activity(void *ctx, int region)
{
    tsnet_magicsock_t *m = ctx;
    return tsnet_derpmgr_last_frame(m->derp, region);
}

static void derp_packet(void *ctx, int region, const uint8_t src[TSNET_KEY_LEN], const uint8_t *data, size_t len);

tsnet_magicsock_t *tsnet_magicsock_new(const tsnet_magicsock_cfg_t *cfg)
{
    tsnet_magicsock_t *m = tsnet_calloc(1, sizeof *m);
    if (!m) {
        return NULL;
    }
    m->cfg = *cfg;
    m->fd = tsnet_udp_open(cfg->port);
    tsnet_derpmgr_cfg_t dc = {.node_priv = cfg->node_priv, .use_http = cfg->use_http, .ctx = m,
                              .on_packet = derp_packet};
    tsnet_netcheck_cfg_t ncc = {.send = send_stun, .last_activity = last_activity, .ctx = m};
    m->derp = tsnet_derpmgr_new(&dc);
    m->nc = tsnet_netcheck_new(&ncc);
    bool key_ok = tsnet_x25519_public(m->node_pub, cfg->node_priv) == 0;
    m->cfg.node_priv = NULL;
    // key.NewDisco: a new disco key each start, never stored (tailscaled doesn't store it either).
    if (cfg->disco_priv) {
        memcpy(m->disco_priv, cfg->disco_priv, TSNET_KEY_LEN);
        m->cfg.disco_priv = NULL;
    } else {
        key_ok = key_ok && tsnet_new_x25519_key(m->disco_priv) == 0;
    }
    key_ok = key_ok && tsnet_x25519_public(m->disco_pub, m->disco_priv) == 0;
    if (m->fd < 0 || !m->derp || !m->nc || !key_ok) {
        tsnet_magicsock_free(m);
        return NULL;
    }
    m->last_traffic = tsnet_now_ms(); // the tunnel's idle time counts from its start
    tsnet_log(TSNET_LOG_INFO, "magicsock: UDP bound to port %u", (unsigned)tsnet_udp_port(m->fd));
    return m;
}

void tsnet_magicsock_free(tsnet_magicsock_t *m)
{
    if (!m) {
        return;
    }
    tsnet_netcheck_free(m->nc);
    tsnet_derpmgr_free(m->derp);
    tsnet_derp_map_free(m->dm);
    if (m->fd >= 0) {
        tsnet_sock_close(m->fd);
    }
    tsnet_wipe(m->disco_priv, sizeof m->disco_priv);
    if (m->peers) {
        tsnet_wipe(m->peers, m->peers_n * sizeof *m->peers);
    }
    free(m->peers);
    free(m);
}

void tsnet_magicsock_restun(tsnet_magicsock_t *m, const char *why)
{
    if (tsnet_netcheck_running(m->nc)) {
        // An endpoint update is active: another one later.
        m->want_restun = true;
        snprintf(m->want_why, sizeof m->want_why, "%s", why);
        return;
    }
    if (!m->dm) {
        return; // updateNetInfo with no DERP map: an empty report, nothing to do
    }
    tsnet_log(TSNET_LOG_DEBUG, "magicsock: starting endpoint update (%s)", why);
    tsnet_netcheck_start(m->nc, m->dm);
}

void tsnet_magicsock_set_derp_map(tsnet_magicsock_t *m, const tsnet_derp_map_t *dm)
{
    tsnet_derpmgr_set_map(m->derp, dm);
    tsnet_derp_map_free(m->dm);
    m->dm = dm ? tsnet_derp_map_copy(dm) : NULL;
    if (m->dm) {
        tsnet_magicsock_restun(m, "derp-map-update");
    }
}

// The first 4 bytes of a key in hex, for logs (Go's ShortString is base64; the key is public either way).
static const char *short_key(char buf[12], const uint8_t key[TSNET_KEY_LEN])
{
    snprintf(buf, 12, "[%02x%02x%02x%02x]", key[0], key[1], key[2], key[3]);
    return buf;
}

static ms_peer_t *peer_by_key(tsnet_magicsock_t *m, const uint8_t key[TSNET_KEY_LEN])
{
    for (size_t i = 0; i < m->peers_n; i++) {
        if (memcmp(m->peers[i].key, key, TSNET_KEY_LEN) == 0) {
            return &m->peers[i];
        }
    }
    return NULL;
}

static void to16(uint8_t out[16], const tsnet_ip_t *ip)
{
    if (ip->is6) {
        memcpy(out, ip->ip, 16);
        return;
    }
    static const uint8_t MAPPED[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    memcpy(out, MAPPED, 12);
    memcpy(out + 12, ip->ip, 4);
}

void tsnet_magicsock_set_peers(tsnet_magicsock_t *m, const tsnet_node_t *nodes, size_t n)
{
    size_t before = m->peers_n;
    ms_peer_t *peers = n ? tsnet_calloc(n, sizeof *peers) : NULL;
    if (n && !peers) {
        tsnet_log(TSNET_LOG_ERROR, "magicsock: out of memory for %zu peers", n);
        return; // the old peers stay
    }
    uint64_t now = tsnet_now_us();
    for (size_t i = 0; i < n; i++) {
        const tsnet_node_t *nd = &nodes[i];
        ms_peer_t *p = &peers[i];
        const ms_peer_t *old = peer_by_key(m, nd->key);
        if (old) {
            *p = *old; // its paths carry on (updateFromNode)
        } else {
            memcpy(p->key, nd->key, TSNET_KEY_LEN);
            tsnet_endpoint_init(&p->ep);
        }
        bool disco_changed = p->has_disco != nd->has_disco ||
                             (nd->has_disco && memcmp(p->disco, nd->disco, TSNET_KEY_LEN) != 0);
        if (disco_changed) {
            p->has_disco = nd->has_disco;
            memcpy(p->disco, nd->disco, TSNET_KEY_LEN);
            if (p->has_disco && tsnet_box_shared(p->shared, m->disco_priv, p->disco) != 0) {
                p->has_disco = false; // a key X25519 refuses (all zero, say): no disco with it
            }
            if (old) {
                char k[12];
                tsnet_log(TSNET_LOG_INFO, "magicsock: disco: node %s changed its disco key", short_key(k, p->key));
                tsnet_endpoint_reset(&p->ep); // changedActiveDiscoLocked: start path discovery again
            }
        }
        p->home_derp = nd->home_derp;
        p->expired = nd->expired;
        // setEndpointsLocked: at most TSNET_EP_STATES of them fit; the rest wait for a ping or CallMeMaybe.
        tsnet_disco_ep_t eps[TSNET_EP_STATES];
        size_t k = 0;
        for (size_t j = 0; j < nd->n_endpoints && k < TSNET_EP_STATES; j++) {
            if (nd->endpoints[j].port == 0) {
                continue; // not a valid AddrPort ("bogus netmap endpoint")
            }
            to16(eps[k].ip, &nd->endpoints[j].ip);
            eps[k++].port = nd->endpoints[j].port;
        }
        tsnet_endpoint_set_netmap(&p->ep, now, eps, k);
    }
    if (m->peers) {
        tsnet_wipe(m->peers, m->peers_n * sizeof *m->peers);
    }
    free(m->peers);
    m->peers = peers;
    m->peers_n = n;
    if (before == 0 && n > 0) {
        tsnet_magicsock_restun(m, "non-zero-peers");
    }
}

// sendDiscoMessage: the message sealed with `shared` (the recipient's disco key with ours), to ip:port over UDP or,
// with `region`, over DERP to the node `dst`.
static void send_disco(tsnet_magicsock_t *m, const uint8_t shared[TSNET_KEY_LEN], const uint8_t dst[TSNET_KEY_LEN],
                       const uint8_t ip[16], uint16_t port, int region, const uint8_t *msg, size_t len)
{
    uint8_t nonce[TSNET_BOX_NONCE_LEN], pkt[TSNET_DISCO_WRAPPER_LEN + 16 + 2 + TSNET_SELFEPS_MAX * 18];
    if (tsnet_random(nonce, sizeof nonce) != 0) {
        return; // never a nonce that could repeat (platform.h)
    }
    int n = tsnet_disco_seal(pkt, sizeof pkt, m->disco_pub, shared, nonce, msg, len);
    if (n < 0) {
        return;
    }
    if (region) {
        tsnet_derpmgr_send(m->derp, region, dst, pkt, (size_t)n);
    } else {
        tsnet_udp_send(m->fd, ip, port, pkt, (size_t)n);
    }
}

static void enqueue_call_me_maybe(tsnet_magicsock_t *m, ms_peer_t *p);

// What the peer's endpoint decided: its pings over UDP, and a CallMeMaybe over DERP.
static void run_actions(tsnet_magicsock_t *m, ms_peer_t *p, const tsnet_ep_actions_t *a)
{
    for (int i = 0; i < a->n_ping; i++) {
        uint8_t msg[64];
        int n = tsnet_disco_ping(msg, sizeof msg, a->ping[i].txid, m->node_pub, 0);
        if (n <= 0) {
            continue;
        }
        if (a->ping[i].derp) {
            if (p->home_derp) {
                send_disco(m, p->shared, p->key, NULL, 0, p->home_derp, msg, (size_t)n);
            }
        } else {
            send_disco(m, p->shared, p->key, a->ping[i].ip, a->ping[i].port, 0, msg, (size_t)n);
        }
    }
    if (a->call_me_maybe) {
        enqueue_call_me_maybe(m, p);
    }
}

// The DERP magic address for a region (tailcfg.DerpMagicIPAddr, 127.3.3.40, with the region as the port): what a
// Pong to a ping that came over DERP says it came from.
static void derp_magic(uint8_t ip[16])
{
    static const uint8_t MAGIC[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 3, 3, 40};
    memcpy(ip, MAGIC, 16);
}

// handleDiscoMessage: a disco packet over UDP from ip:port, or over DERP (`region` non-zero) from the node `derp_src`.
static void handle_disco(tsnet_magicsock_t *m, const uint8_t *pkt, size_t len, const uint8_t ip[16], uint16_t port,
                         int region, const uint8_t *derp_src)
{
    const uint8_t *sender = tsnet_disco_source(pkt);
    ms_peer_t *first = NULL;
    for (size_t i = 0; i < m->peers_n && !first; i++) {
        if (m->peers[i].has_disco && memcmp(m->peers[i].disco, sender, TSNET_KEY_LEN) == 0) {
            first = &m->peers[i];
        }
    }
    char k[12];
    if (!first) {
        tsnet_log(TSNET_LOG_DEBUG, "magicsock: disco: ignoring disco-looking frame, don't know of key %s",
                  short_key(k, sender));
        return;
    }
    uint8_t msg[1536]; // disco packets fit a UDP packet (MaxDiscoPingSize); a bigger one doesn't open
    int n = tsnet_disco_open(pkt, len, first->shared, msg, sizeof msg);
    tsnet_disco_msg_t dm;
    if (n < 0 || tsnet_disco_parse(msg, (size_t)n, &dm) != 0) {
        return; // for an old disco key, or a message from a newer version: not worth a log, as Go says
    }
    uint64_t now = tsnet_now_us();
    switch (dm.type) {
    case TSNET_DISCO_PING: {
        // handlePingLocked: answer with a Pong saying where the ping came from, the way it came.
        uint8_t src_ip[16];
        uint16_t src_port = port;
        const ms_peer_t *to = first;
        if (region) {
            to = derp_src ? peer_by_key(m, derp_src) : NULL;
            derp_magic(src_ip);
            src_port = (uint16_t)region;
        } else {
            memcpy(src_ip, ip, 16);
            int nodes = 0;
            for (size_t i = 0; i < m->peers_n; i++) {
                ms_peer_t *p = &m->peers[i];
                if (p->has_disco && memcmp(p->disco, sender, TSNET_KEY_LEN) == 0) {
                    if (tsnet_endpoint_got_ping(&p->ep, now, ip, port, dm.txid)) {
                        return; // the same ping again
                    }
                    nodes++;
                }
            }
            if (nodes == 0) {
                to = NULL;
            }
        }
        if (!to) {
            tsnet_log(TSNET_LOG_WARN, "magicsock: [unexpected] got disco ping from %s for node not in peers",
                      short_key(k, sender));
            return;
        }
        uint8_t pong[64];
        int pn = tsnet_disco_pong(pong, sizeof pong, dm.txid, src_ip, src_port);
        if (pn > 0) {
            // Sealed for the sender's disco key; over DERP, to the node that sent it.
            send_disco(m, first->shared, to->key, ip, port, region, pong, (size_t)pn);
        }
        break;
    }
    case TSNET_DISCO_PONG:
        // Each peer with the sender's disco key is asked, until one sent the ping.
        for (size_t i = 0; i < m->peers_n; i++) {
            ms_peer_t *p = &m->peers[i];
            tsnet_ping_result_t res;
            if (p->has_disco && memcmp(p->disco, sender, TSNET_KEY_LEN) == 0 &&
                tsnet_endpoint_pong(&p->ep, now, dm.txid, region != 0, &res)) {
                if (res.answered && m->cfg.on_ping) {
                    m->cfg.on_ping(m->cfg.ctx, p->key, &res, region);
                }
                break;
            }
        }
        break;
    case TSNET_DISCO_CALL_ME_MAYBE: {
        if (!region || !derp_src) {
            tsnet_log(TSNET_LOG_WARN, "magicsock: [unexpected] CallMeMaybe packets should only come via DERP");
            return;
        }
        ms_peer_t *p = peer_by_key(m, derp_src);
        if (!p) {
            char k2[12];
            tsnet_log(TSNET_LOG_INFO, "magicsock: disco: ignoring CallMeMaybe from %s; %s is unknown",
                      short_key(k, sender), short_key(k2, derp_src));
            return;
        }
        if (!p->has_disco || memcmp(p->disco, sender, TSNET_KEY_LEN) != 0) {
            tsnet_log(TSNET_LOG_WARN,
                      "magicsock: [unexpected] CallMeMaybe from peer via DERP whose netmap discokey != disco source");
            return;
        }
        tsnet_ep_actions_t a;
        tsnet_endpoint_call_me_maybe(&p->ep, now, dm.eps, dm.n_eps, &a);
        run_actions(m, p, &a);
        break;
    }
    default:
        break; // the relay messages: tsnet has no UDP relay paths
    }
}

static void derp_packet(void *ctx, int region, const uint8_t src[TSNET_KEY_LEN], const uint8_t *data, size_t len)
{
    tsnet_magicsock_t *m = ctx;
    ms_peer_t *p = peer_by_key(m, src);
    if (p) {
        p->last_derp = region;
    }
    if (tsnet_disco_looks_like(data, len)) {
        handle_disco(m, data, len, NULL, 0, region, src);
        return;
    }
    m->last_traffic = tsnet_now_ms();
    if (m->cfg.on_packet) {
        m->cfg.on_packet(m->cfg.ctx, data, len, src, TSNET_KEY_LEN);
    }
}

int tsnet_magicsock_send(tsnet_magicsock_t *m, const uint8_t key[TSNET_KEY_LEN], const uint8_t *pkt, size_t len)
{
    ms_peer_t *p = peer_by_key(m, key);
    if (!p || p->expired) {
        return -1;
    }
    tsnet_addrq_t udp;
    bool derp;
    tsnet_ep_actions_t a;
    tsnet_endpoint_send(&p->ep, tsnet_now_us(), &udp, &derp, &a);
    if (p->has_disco) {
        run_actions(m, p, &a);
    }
    int region = derp ? p->home_derp : 0;
    if (!udp.valid && region == 0) {
        region = p->last_derp; // they reached us over that DERP, so they can be reached over it
    }
    if (!udp.valid && region == 0) {
        return -1; // errNoUDPOrDERP
    }
    m->last_traffic = tsnet_now_ms();
    if (udp.valid) {
        tsnet_udp_send(m->fd, udp.ip, udp.port, pkt, len);
    }
    if (region) {
        tsnet_derpmgr_send(m->derp, region, p->key, pkt, len);
    }
    return 0;
}

int tsnet_magicsock_ping(tsnet_magicsock_t *m, const uint8_t key[TSNET_KEY_LEN])
{
    ms_peer_t *p = peer_by_key(m, key);
    if (!p || p->expired || !p->has_disco) {
        return -1; // discoPing: errExpired, or no disco key to ping with
    }
    tsnet_ep_actions_t a;
    tsnet_endpoint_cli_ping(&p->ep, tsnet_now_us(), p->home_derp != 0, &a);
    run_actions(m, p, &a);
    return a.n_ping > 0 ? 0 : -1;
}

int tsnet_magicsock_peer_path(const tsnet_magicsock_t *m, const uint8_t key[TSNET_KEY_LEN], uint8_t ip[16],
                              uint16_t *port)
{
    for (size_t i = 0; i < m->peers_n; i++) {
        if (memcmp(m->peers[i].key, key, TSNET_KEY_LEN) == 0) {
            tsnet_addrq_t udp;
            bool derp;
            tsnet_endpoint_addr_for_send(&m->peers[i].ep, tsnet_now_us(), &udp, &derp);
            if (udp.valid) {
                memcpy(ip, udp.ip, 16);
                *port = udp.port;
            }
            return udp.valid && !derp ? 1 : 0;
        }
    }
    return -1;
}

void tsnet_magicsock_set_control(tsnet_magicsock_t *m, bool in_map_poll)
{
    m->in_map_poll = in_map_poll;
}

// maybeSetNearestDERP: while not connected to control, a home already set stays (peers couldn't learn of a change);
// any home is better than none, though.
static int maybe_set_nearest(tsnet_magicsock_t *m, const tsnet_netcheck_report_t *r)
{
    int home = tsnet_derpmgr_home(m->derp);
    if (!m->in_map_poll && home != 0) {
        return home;
    }
    return tsnet_derpmgr_set_home(m->derp, r->base.preferred); // 0: pickDERPFallback
}

// updateNetInfo's end: NetInfo, reported when it changed as BasicallyEqual sees it.
static void netinfo(tsnet_magicsock_t *m, const tsnet_netcheck_report_t *r)
{
    tsnet_net_info_t ni = {.preferred_derp = maybe_set_nearest(m, r), .working_udp = r->udp,
                           .mapping_varies = r->mapping_varies};
    for (size_t i = 0; i < r->base.n_lat && ni.n_derp_latency < TSNET_NETINFO_LATENCIES; i++) {
        ni.derp_latency[ni.n_derp_latency].region = r->base.lat[i].region;
        ni.derp_latency[ni.n_derp_latency++].seconds = r->base.lat[i].us / 1e6;
    }
    if (m->have_netinfo && ni.preferred_derp == m->netinfo.preferred_derp &&
        ni.working_udp == m->netinfo.working_udp && ni.mapping_varies == m->netinfo.mapping_varies) {
        return;
    }
    m->netinfo = ni;
    m->have_netinfo = true;
    tsnet_log(TSNET_LOG_INFO, "magicsock: NetInfo: derp=#%d udp=%s mapvarydest=%s", ni.preferred_derp,
              ni.working_udp ? "true" : "false", ni.mapping_varies < 0 ? "" : ni.mapping_varies ? "true" : "false");
    if (m->cfg.on_netinfo) {
        m->cfg.on_netinfo(m->cfg.ctx, &ni);
    }
}

static const char *ep_type_name(int t)
{
    switch (t) {
    case TSNET_EPT_LOCAL: return "local";
    case TSNET_EPT_STUN: return "stun";
    case TSNET_EPT_STUN4LOCALPORT: return "stun4localport";
    default: return "?";
    }
}

// enqueueCallMeMaybe: this node's endpoints, over DERP to the peer's home, so it pings them now that our firewall
// has seen traffic to it. Endpoints older than 27 s are refreshed first (a ReSTUN), and it goes when that's done.
static void enqueue_call_me_maybe(tsnet_magicsock_t *m, ms_peer_t *p)
{
    if (!p->has_disco || !p->home_derp) {
        return; // sendDiscoPingsLocked sends one only to a peer with a DERP home
    }
    uint64_t now = tsnet_now_ms();
    if (m->eps_time == 0 || now - m->eps_time >= ENDPOINTS_FRESH_MS) {
        tsnet_log(TSNET_LOG_DEBUG, "magicsock: want call-me-maybe but endpoints stale; restunning");
        p->cmm_pending = true; // onEndpointRefreshed
        tsnet_magicsock_restun(m, "refresh-for-peering");
        return;
    }
    tsnet_disco_ep_t eps[TSNET_SELFEPS_MAX];
    for (size_t i = 0; i < m->n_eps; i++) {
        memcpy(eps[i].ip, m->eps[i].ip, 16);
        eps[i].port = m->eps[i].port;
    }
    uint8_t msg[2 + TSNET_SELFEPS_MAX * 18];
    int n = tsnet_disco_call_me_maybe(msg, sizeof msg, eps, m->n_eps);
    if (n > 0) {
        send_disco(m, p->shared, p->key, NULL, 0, p->home_derp, msg, (size_t)n);
        char k[12];
        tsnet_log(TSNET_LOG_DEBUG, "magicsock: disco: sent call-me-maybe to %s, %zu endpoints", short_key(k, p->key),
                  m->n_eps);
    }
}

// updateEndpoints after the report: determineEndpoints, then setEndpoints.
static void update_endpoints(tsnet_magicsock_t *m, const tsnet_netcheck_report_t *r)
{
    tsnet_ifaddr_t ifs[16];
    int n_ifs = tsnet_ifaddrs(ifs, 16);
    if (n_ifs < 0) {
        tsnet_log(TSNET_LOG_WARN, "magicsock: endpoint update failed: can't list the interfaces");
        return;
    }
    uint64_t now = tsnet_now_ms();
    tsnet_selfep_t eps[TSNET_SELFEPS_MAX];
    size_t n = tsnet_determine_endpoints(r, m->cfg.port, tsnet_udp_port(m->fd), ifs, (size_t)n_ifs, &m->tracker, now,
                                         eps, TSNET_SELFEPS_MAX);
    if (!tsnet_selfeps_any_stun(eps, n) && !m->dm) {
        // Starting up: a DERP map should come soon with more to report. This saves a map update.
        tsnet_log(TSNET_LOG_DEBUG, "magicsock: ignoring pre-DERP map, STUN-less endpoint update");
        return;
    }
    m->eps_time = now;
    bool changed = !tsnet_selfeps_equal(eps, n, m->eps, m->n_eps);
    if (changed) {
        memcpy(m->eps, eps, n * sizeof eps[0]);
        m->n_eps = n;
        // logEndpointChange, without the addresses: they are this node's own (public and LAN).
        char types[160] = "";
        size_t used = 0;
        for (size_t i = 0; i < n && used < sizeof types - 20; i++) {
            used += (size_t)snprintf(types + used, sizeof types - used, "%s%s", i ? "," : "", ep_type_name(eps[i].type));
        }
        tsnet_log(TSNET_LOG_INFO, "magicsock: endpoints changed: %zu (%s)", n, types);
    }
    // onEndpointRefreshed: the CallMeMaybes that waited for fresh endpoints.
    for (size_t i = 0; i < m->peers_n; i++) {
        if (m->peers[i].cmm_pending) {
            m->peers[i].cmm_pending = false;
            enqueue_call_me_maybe(m, &m->peers[i]);
        }
    }
    if (changed && m->cfg.on_endpoints) {
        m->cfg.on_endpoints(m->cfg.ctx, m->eps, m->n_eps);
    }
}

static void receive(tsnet_magicsock_t *m)
{
    uint8_t buf[2048], ip[16];
    uint16_t port;
    int n;
    while ((n = tsnet_udp_recv(m->fd, buf, sizeof buf, ip, &port)) > 0) {
        // packetLooksLike: a STUN binding message goes to netcheck, a disco packet to handleDiscoMessage, and the rest
        // to WireGuard (on_packet), with the sender's address and port as its source.
        if (tsnet_stun_is(buf, (size_t)n) && buf[1] == 0x01) {
            tsnet_netcheck_stun(m->nc, buf, (size_t)n, ip, port);
        } else if (tsnet_disco_looks_like(buf, (size_t)n)) {
            handle_disco(m, buf, (size_t)n, ip, port, 0, NULL);
        } else {
            m->last_traffic = tsnet_now_ms();
            if (m->cfg.on_packet) {
                uint8_t src[18];
                memcpy(src, ip, 16);
                src[16] = (uint8_t)(port >> 8);
                src[17] = (uint8_t)port;
                m->cfg.on_packet(m->cfg.ctx, buf, (size_t)n, src, sizeof src);
            }
        }
    }
}

void tsnet_magicsock_step(tsnet_magicsock_t *m)
{
    receive(m);
    tsnet_derpmgr_step(m->derp);
    if (tsnet_netcheck_step(m->nc)) {
        netinfo(m, tsnet_netcheck_report(m->nc));
        update_endpoints(m, tsnet_netcheck_report(m->nc));
        // updateEndpoints' end: a ReSTUN asked for meanwhile runs now; else periodic ReSTUN while there are peers and
        // traffic (shouldDoPeriodicReSTUNLocked: not after 45 s idle).
        if (m->want_restun) {
            m->want_restun = false;
            tsnet_magicsock_restun(m, m->want_why);
        } else if (m->peers_n > 0 && tsnet_now_ms() - m->last_traffic <= SESSION_ACTIVE_MS) {
            uint32_t r = 0;
            tsnet_random(&r, sizeof r);
            m->periodic = true;
            m->periodic_at = tsnet_now_ms() + RESTUN_MIN_MS + r % (RESTUN_MAX_MS - RESTUN_MIN_MS);
        } else {
            m->periodic = false;
        }
    }
    if (m->periodic && tsnet_now_ms() >= m->periodic_at) {
        m->periodic = false;
        tsnet_magicsock_restun(m, "periodic");
    }
    // Each peer's ping timeouts and heartbeat.
    uint64_t now = tsnet_now_us();
    for (size_t i = 0; i < m->peers_n; i++) {
        ms_peer_t *p = &m->peers[i];
        uint64_t next = tsnet_endpoint_next(&p->ep);
        if (next != 0 && now >= next) {
            tsnet_ep_actions_t a;
            tsnet_endpoint_step(&p->ep, now, &a);
            if (p->has_disco) {
                run_actions(m, p, &a);
            }
        }
    }
}

int tsnet_magicsock_poll(const tsnet_magicsock_t *m, tsnet_poll_t *p, int max, int *wait_ms)
{
    int n = 0, w = -1, w2;
    if (max > 0) {
        p[n++] = (tsnet_poll_t){.fd = m->fd};
    }
    n += tsnet_derpmgr_poll(m->derp, p + n, max - n, &w);
    n += tsnet_netcheck_poll(m->nc, p + n, max - n, &w2);
    if (w2 >= 0 && (w < 0 || w2 < w)) {
        w = w2;
    }
    if (m->periodic) {
        uint64_t now = tsnet_now_ms();
        int until = m->periodic_at > now ? (int)(m->periodic_at - now) : 0;
        if (w < 0 || until < w) {
            w = until;
        }
    }
    uint64_t now_us = tsnet_now_us();
    for (size_t i = 0; i < m->peers_n; i++) {
        uint64_t next = tsnet_endpoint_next(&m->peers[i].ep);
        if (next != 0) {
            int until = next > now_us ? (int)((next - now_us + 999) / 1000) : 0;
            if (w < 0 || until < w) {
                w = until;
            }
        }
    }
    *wait_ms = w;
    return n;
}

uint16_t tsnet_magicsock_port(const tsnet_magicsock_t *m)
{
    return tsnet_udp_port(m->fd);
}

tsnet_derpmgr_t *tsnet_magicsock_derp(tsnet_magicsock_t *m)
{
    return m->derp;
}

const uint8_t *tsnet_magicsock_disco_public(const tsnet_magicsock_t *m)
{
    return m->disco_pub;
}

const tsnet_netcheck_report_t *tsnet_magicsock_report(const tsnet_magicsock_t *m)
{
    return tsnet_netcheck_report(m->nc);
}
