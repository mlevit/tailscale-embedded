// Host test of magicsock's netcheck wiring: two STUN servers on loopback (one per region, answering after 5 and
// 30 ms) and DERP nodes where nothing listens (their connections fail and back off; this test doesn't need them).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "magicsock.h"
#include "stun.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static int srv[2], delay_ms[2] = {30, 5};
static struct {
    bool queued;
    uint64_t due;
    uint8_t to[16], tx[12];
    uint16_t port;
} q[2];
static int netinfos, last_preferred = -1, reports;

static void on_netinfo(void *ctx, const tsnet_net_info_t *ni)
{
    (void)ctx;
    netinfos++;
    last_preferred = ni->preferred_derp;
}

// This node's endpoints as magicsock reports them. (Never printed: the local ones are this machine's addresses.)
static int endpoint_reports, last_stun, last_local;
static uint16_t last_stun_port;
static void on_endpoints(void *ctx, const tsnet_selfep_t *eps, size_t n)
{
    (void)ctx;
    endpoint_reports++;
    last_stun = last_local = 0;
    for (size_t i = 0; i < n; i++) {
        if (eps[i].type == TSNET_EPT_STUN) {
            last_stun++;
            last_stun_port = eps[i].port;
        }
        last_local += eps[i].type == TSNET_EPT_LOCAL;
    }
}

// Steps magicsock and serves the STUN servers until `until` is true or `ms` pass.
static bool run(tsnet_magicsock_t *m, int ms, bool (*until)(tsnet_magicsock_t *m))
{
    uint64_t end = tsnet_now_ms() + (uint64_t)ms;
    const tsnet_netcheck_report_t *seen = tsnet_magicsock_report(m);
    uint64_t seen_at = seen ? seen->base.at_ms : 0;
    while (tsnet_now_ms() < end) {
        tsnet_poll_t p[16];
        int wait;
        int n = tsnet_magicsock_poll(m, p, 12, &wait);
        p[n++] = (tsnet_poll_t){.fd = srv[0]};
        p[n++] = (tsnet_poll_t){.fd = srv[1]};
        tsnet_poll(p, n, q[0].queued || q[1].queued ? 0 : wait < 0 || wait > 5 ? 5 : wait); // see netcheck_test
        for (int i = 0; i < 2; i++) {
            uint8_t buf[256], ip[16], tx[12];
            uint16_t port;
            int len;
            while ((len = tsnet_udp_recv(srv[i], buf, sizeof buf, ip, &port)) > 0) {
                if (tsnet_stun_parse_binding_request(buf, (size_t)len, tx) == 0 && !q[i].queued) {
                    q[i].queued = true;
                    q[i].due = tsnet_now_ms() + (uint64_t)delay_ms[i];
                    memcpy(q[i].to, ip, 16);
                    memcpy(q[i].tx, tx, 12);
                    q[i].port = port;
                }
            }
            if (q[i].queued && tsnet_now_ms() >= q[i].due) {
                q[i].queued = false;
                len = tsnet_stun_response(buf, sizeof buf, q[i].tx, q[i].to, q[i].port);
                tsnet_udp_send(srv[i], q[i].to, q[i].port, buf, (size_t)len);
            }
        }
        tsnet_magicsock_step(m);
        const tsnet_netcheck_report_t *r = tsnet_magicsock_report(m);
        if (r && r->base.at_ms != seen_at) {
            seen_at = r->base.at_ms;
            reports++;
        }
        if (until && until(m)) {
            return true;
        }
    }
    return until == NULL;
}

static int want_reports;
static bool reports_done(tsnet_magicsock_t *m)
{
    (void)m;
    return reports >= want_reports;
}

// Disco between magicsocks on loopback, with no DERP: each is a node, and set_peers tells it of the others.
typedef struct {
    tsnet_magicsock_t *ms;
    uint8_t key[32];
} node_t;

static node_t node_new(uint8_t seed)
{
    uint8_t priv[32];
    for (int i = 0; i < 32; i++) {
        priv[i] = (uint8_t)(seed * 7 + i);
    }
    node_t n;
    tsnet_x25519_public(n.key, priv);
    tsnet_magicsock_cfg_t cfg = {.node_priv = priv};
    n.ms = tsnet_magicsock_new(&cfg);
    return n;
}

// Tells `self` of the peer `other`, at 127.0.0.1 on its UDP port.
static void know(node_t *self, const node_t *other)
{
    tsnet_addrport_t ep = {.ip = {.ip = {127, 0, 0, 1}}, .port = tsnet_magicsock_port(other->ms)};
    tsnet_node_t peer;
    memset(&peer, 0, sizeof peer);
    memcpy(peer.key, other->key, 32);
    memcpy(peer.disco, tsnet_magicsock_disco_public(other->ms), 32);
    peer.has_disco = true;
    peer.endpoints = &ep;
    peer.n_endpoints = 1;
    tsnet_magicsock_set_peers(self->ms, &peer, 1);
}

// Steps the nodes for `ms` milliseconds, or until a's path to b is direct (`until_direct`).
static bool pump(node_t **nodes, int n, int ms, const node_t *a, const node_t *b, bool until_direct)
{
    uint64_t end = tsnet_now_ms() + (uint64_t)ms;
    while (tsnet_now_ms() < end) {
        tsnet_poll_t p[32];
        int np = 0, wait = 5;
        for (int i = 0; i < n; i++) {
            int w;
            np += tsnet_magicsock_poll(nodes[i]->ms, p + np, 8, &w);
            if (w >= 0 && w < wait) {
                wait = w;
            }
        }
        tsnet_poll(p, np, wait);
        for (int i = 0; i < n; i++) {
            tsnet_magicsock_step(nodes[i]->ms);
        }
        uint8_t ip[16];
        uint16_t port;
        if (until_direct && tsnet_magicsock_peer_path(a->ms, b->key, ip, &port) == 1) {
            return true;
        }
    }
    return !until_direct;
}

static void disco_paths(void)
{
    node_t a = node_new(1), b = node_new(2), c = node_new(3);
    EXPECT(a.ms && b.ms && c.ms);
    know(&a, &b);
    know(&b, &a);
    know(&c, &b); // b doesn't know c
    node_t *all[3] = {&a, &b, &c};
    uint8_t ip[16];
    uint16_t port;
    const uint8_t hello[] = "not WireGuard";

    // No path yet, and no DERP: the first send has nowhere to go but starts discovery. a pings b's endpoint, b
    // answers, and a's path to b is direct on b's port.
    EXPECT(tsnet_magicsock_peer_path(a.ms, b.key, ip, &port) == 0);
    EXPECT(tsnet_magicsock_send(a.ms, b.key, hello, sizeof hello) == -1);
    EXPECT(pump(all, 3, 1000, &a, &b, true));
    EXPECT(tsnet_magicsock_peer_path(a.ms, b.key, ip, &port) == 1 && port == tsnet_magicsock_port(b.ms));
    EXPECT(tsnet_magicsock_send(a.ms, b.key, hello, sizeof hello) == 0);
    // b never sent to a, so b has no path of its own yet; its first send finds one.
    EXPECT(tsnet_magicsock_peer_path(b.ms, a.key, ip, &port) == 0);
    tsnet_magicsock_send(b.ms, a.key, hello, sizeof hello);
    EXPECT(pump(all, 3, 1000, &b, &a, true));

    // c pings b, which doesn't know c's disco key: no pong, no path.
    tsnet_magicsock_send(c.ms, b.key, hello, sizeof hello);
    pump(all, 3, 500, NULL, NULL, false);
    EXPECT(tsnet_magicsock_peer_path(c.ms, b.key, ip, &port) == 0);

    // The heartbeat (every 3 s while a sent in the last 45 s) keeps a's path trusted past the 6.5 s a pong gives.
    pump(all, 3, 7000, NULL, NULL, false);
    EXPECT(tsnet_magicsock_peer_path(a.ms, b.key, ip, &port) == 1);

    // b restarts: a new disco key on a new port. The netmap's change resets a's paths to b, and a send finds b again.
    tsnet_magicsock_free(b.ms);
    b = node_new(2);
    know(&b, &a);
    know(&a, &b);
    EXPECT(tsnet_magicsock_peer_path(a.ms, b.key, ip, &port) == 0);
    tsnet_magicsock_send(a.ms, b.key, hello, sizeof hello);
    EXPECT(pump(all, 3, 1000, &a, &b, true));
    EXPECT(tsnet_magicsock_peer_path(a.ms, b.key, ip, &port) == 1 && port == tsnet_magicsock_port(b.ms));

    // b's node key expires: nothing more is sent to it (errExpired), though its path is still known.
    tsnet_node_t expired;
    memset(&expired, 0, sizeof expired);
    memcpy(expired.key, b.key, 32);
    memcpy(expired.disco, tsnet_magicsock_disco_public(b.ms), 32);
    expired.has_disco = true;
    expired.expired = true;
    tsnet_magicsock_set_peers(a.ms, &expired, 1);
    EXPECT(tsnet_magicsock_send(a.ms, b.key, hello, sizeof hello) == -1);

    tsnet_magicsock_free(a.ms);
    tsnet_magicsock_free(b.ms);
    tsnet_magicsock_free(c.ms);
}

int main(void)
{
    tsnet_derp_node_t nodes[2];
    tsnet_derp_region_t regions[2];
    memset(nodes, 0, sizeof nodes);
    memset(regions, 0, sizeof regions);
    for (int i = 0; i < 2; i++) {
        srv[i] = tsnet_udp_open(0);
        snprintf(nodes[i].name, sizeof nodes[i].name, "%da", i + 1);
        snprintf(nodes[i].host_name, sizeof nodes[i].host_name, "127.0.0.1");
        snprintf(nodes[i].ipv4, sizeof nodes[i].ipv4, "127.0.0.1");
        nodes[i].region_id = i + 1;
        nodes[i].stun_port = tsnet_udp_port(srv[i]);
        nodes[i].derp_port = 1;
        regions[i].region_id = i + 1;
        regions[i].nodes = &nodes[i];
        regions[i].n_nodes = 1;
    }
    tsnet_derp_map_t dm = {.has_regions = true, .regions = regions, .n_regions = 2};
    uint8_t priv[32];
    for (int i = 0; i < 32; i++) {
        priv[i] = (uint8_t)(i * 3 + 1);
    }
    tsnet_magicsock_cfg_t cfg = {.node_priv = priv, .use_http = true, .on_netinfo = on_netinfo,
                                 .on_endpoints = on_endpoints};
    tsnet_magicsock_t *m = tsnet_magicsock_new(&cfg);
    EXPECT(m != NULL && tsnet_magicsock_port(m) != 0);
    tsnet_magicsock_set_control(m, true);

    // The map triggers a report ("derp-map-update"), and its preferred region, the faster one, becomes home.
    tsnet_magicsock_set_derp_map(m, &dm);
    want_reports = 1;
    EXPECT(run(m, 6000, reports_done));
    EXPECT(tsnet_derpmgr_home(tsnet_magicsock_derp(m)) == 2);
    EXPECT(netinfos == 1 && last_preferred == 2);
    // The report's endpoints: the STUN servers (on loopback) saw this socket's port, so one STUN endpoint on it, and
    // the interfaces' addresses on it too.
    EXPECT(endpoint_reports == 1 && last_stun == 1 && last_stun_port == tsnet_magicsock_port(m) && last_local >= 1);
    // A ReSTUN asked for during a report runs after it.
    tsnet_magicsock_restun(m, "test-1");
    tsnet_magicsock_restun(m, "test-2"); // queued behind the one running
    want_reports = 3;
    EXPECT(run(m, 8000, reports_done));
    EXPECT(netinfos == 1);         // NetInfo unchanged: not reported again
    EXPECT(endpoint_reports == 1); // and the same endpoints aren't either

    // Region 1 gets faster than region 2 by more than the stickiness allows; while out of contact with control, the
    // home stays.
    delay_ms[0] = 1;
    delay_ms[1] = 60;
    tsnet_magicsock_set_control(m, false);
    tsnet_magicsock_restun(m, "test-3");
    want_reports = 4;
    EXPECT(run(m, 6000, reports_done));
    EXPECT(tsnet_derpmgr_home(tsnet_magicsock_derp(m)) == 2);
    // Back in contact: the next report moves it.
    tsnet_magicsock_set_control(m, true);
    tsnet_magicsock_restun(m, "test-4");
    want_reports = 5;
    EXPECT(run(m, 6000, reports_done));
    EXPECT(tsnet_derpmgr_home(tsnet_magicsock_derp(m)) == 1 && last_preferred == 1);

    // The first peer triggers a report ("non-zero-peers"); a second doesn't.
    tsnet_node_t peers[2];
    memset(peers, 0, sizeof peers);
    peers[0].key[0] = 1;
    peers[1].key[0] = 2;
    tsnet_magicsock_set_peers(m, peers, 1);
    want_reports = 6;
    EXPECT(run(m, 6000, reports_done));
    tsnet_magicsock_set_peers(m, peers, 2);
    int before = reports;
    EXPECT(run(m, 1000, NULL));
    EXPECT(reports == before); // the next one is the periodic ReSTUN, 20 to 26 s away

    // The disco key (key.NewDisco): not zero, and new each start (a second magicsock's differs).
    tsnet_magicsock_t *m2 = tsnet_magicsock_new(&cfg);
    static const uint8_t ZERO[32];
    EXPECT(m2 != NULL && memcmp(tsnet_magicsock_disco_public(m), ZERO, 32) != 0 &&
           memcmp(tsnet_magicsock_disco_public(m), tsnet_magicsock_disco_public(m2), 32) != 0);
    tsnet_magicsock_free(m2);

    tsnet_magicsock_free(m);
    tsnet_sock_close(srv[0]);
    tsnet_sock_close(srv[1]);

    disco_paths();
    if (failures == 0) {
        printf("tsnet magicsock_test: ok\n");
    }
    return failures != 0;
}
