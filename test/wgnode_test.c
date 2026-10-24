// Host test of WireGuard over magicsock: two nodes on loopback, each a magicsock and a wgdev joined as
// magicsock_run joins them (wgdev's messages go out with tsnet_magicsock_send; magicsock's non-disco packets go to
// tsnet_wgdev_receive). With a direct path found by disco, an IP packet from A reaches B through a real handshake, and
// B's answer comes back; a packet whose WireGuard message is garbage is dropped; a cookie reply reaches a UDP source.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "magicsock.h"
#include "wgdev.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

typedef struct node {
    tsnet_magicsock_t *ms;
    tsnet_wgdev_t *wg;
    uint8_t key[32];
    int delivered;
    uint8_t last[256];
    size_t last_len;
} node_t;

static void wg_send(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    node_t *n = ctx;
    tsnet_magicsock_send(n->ms, peer, pkt, len);
}

static void wg_deliver(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    (void)peer;
    node_t *n = ctx;
    n->delivered++;
    memcpy(n->last, pkt, len < sizeof n->last ? len : sizeof n->last);
    n->last_len = len;
}

static void ms_packet(void *ctx, const uint8_t *pkt, size_t len, const uint8_t *src, size_t src_len)
{
    node_t *n = ctx;
    tsnet_wgdev_receive(n->wg, pkt, len, src, src_len, tsnet_now_ms());
}

static void node_init(node_t *n, uint8_t seed)
{
    memset(n, 0, sizeof *n);
    uint8_t priv[32];
    for (int i = 0; i < 32; i++) {
        priv[i] = (uint8_t)(seed * 13 + i);
    }
    priv[0] &= 248;
    priv[31] = (uint8_t)((priv[31] & 127) | 64);
    tsnet_x25519_public(n->key, priv);
    tsnet_magicsock_cfg_t mc = {.node_priv = priv, .ctx = n, .on_packet = ms_packet};
    n->ms = tsnet_magicsock_new(&mc);
    tsnet_wgdev_cfg_t wc = {.priv = priv, .ctx = n, .send = wg_send, .deliver = wg_deliver}; // the node key is the WireGuard key
    n->wg = tsnet_wgdev_new(&wc);
}

// Tells `self` of `other` (at 127.0.0.1 on its port), in magicsock and in WireGuard.
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
    tsnet_wgdev_add_peer(self->wg, other->key, tsnet_now_ms());
}

// Runs both nodes' event loops for `ms` milliseconds, or until `done` is true.
static bool run(node_t *a, node_t *b, int ms, bool (*done)(node_t *a, node_t *b))
{
    uint64_t end = tsnet_now_ms() + (uint64_t)ms;
    node_t *nodes[2] = {a, b};
    while (tsnet_now_ms() < end) {
        tsnet_poll_t p[16];
        int np = 0, wait = 5;
        for (int i = 0; i < 2; i++) {
            int w;
            np += tsnet_magicsock_poll(nodes[i]->ms, p + np, 8, &w);
            if (w >= 0 && w < wait) {
                wait = w;
            }
        }
        tsnet_poll(p, np, wait);
        for (int i = 0; i < 2; i++) {
            tsnet_magicsock_step(nodes[i]->ms);
            tsnet_wgdev_step(nodes[i]->wg, tsnet_now_ms());
        }
        if (done && done(a, b)) {
            return true;
        }
    }
    return done == NULL;
}

static bool direct(node_t *a, node_t *b)
{
    uint8_t ip[16];
    uint16_t port;
    return tsnet_magicsock_peer_path(a->ms, b->key, ip, &port) == 1;
}

static bool b_got_one(node_t *a, node_t *b)
{
    (void)a;
    return b->delivered >= 1;
}

static bool a_got_one(node_t *a, node_t *b)
{
    (void)b;
    return a->delivered >= 1;
}

static size_t ip4(uint8_t *out, uint8_t fill)
{
    memset(out, 0, 40);
    out[0] = 0x45;
    out[3] = 40; // total length
    memset(out + 20, fill, 20);
    return 40;
}

int main(void)
{
    node_t a, b;
    node_init(&a, 1);
    node_init(&b, 2);
    EXPECT(a.ms && a.wg && b.ms && b.wg);
    know(&a, &b);
    know(&b, &a);

    // Direct paths both ways first (a disco ping each way), so WireGuard's messages have somewhere to go: with no DERP
    // here, a node with no trusted path can't answer (Go's would answer over DERP).
    tsnet_magicsock_ping(a.ms, b.key);
    tsnet_magicsock_ping(b.ms, a.key);
    EXPECT(run(&a, &b, 2000, direct));
    EXPECT(run(&b, &a, 2000, direct));

    // A's IP packet: staged, a handshake over the path, then the packet itself; B delivers it.
    uint8_t pkt[64];
    size_t n = ip4(pkt, 0xa1);
    EXPECT(tsnet_wgdev_send(a.wg, b.key, pkt, n, tsnet_now_ms()) == 0);
    EXPECT(run(&a, &b, 2000, b_got_one));
    EXPECT(b.delivered == 1 && b.last_len == n && b.last[20] == 0xa1);
    EXPECT(tsnet_wgdev_session(a.wg, b.key, NULL) && tsnet_wgdev_session(b.wg, a.key, NULL));
    // B answers.
    n = ip4(pkt, 0xb2);
    EXPECT(tsnet_wgdev_send(b.wg, a.key, pkt, n, tsnet_now_ms()) == 0);
    EXPECT(run(&a, &b, 2000, a_got_one));
    EXPECT(a.delivered == 1 && a.last[20] == 0xb2);

    // Garbage that isn't STUN or disco goes to WireGuard, which drops it: nothing more is delivered.
    int fd = tsnet_udp_open(0);
    uint8_t lo[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1};
    uint8_t junk[48];
    memset(junk, 4, sizeof junk); // type 4, but no keypair has that index
    tsnet_udp_send(fd, lo, tsnet_magicsock_port(b.ms), junk, sizeof junk);
    run(&a, &b, 200, NULL);
    EXPECT(b.delivered == 1);

    // A cookie reply to a UDP source goes straight from A's socket (tsnet_magicsock_reply, as server.c wires it). A
    // source that is neither a node key nor an address and port is refused.
    uint8_t src[18], reply[TSNET_WG_COOKIE_REPLY_LEN], got[128], from[16];
    uint16_t fd_port = tsnet_udp_port(fd), from_port = 0;
    memcpy(src, lo, 16);
    src[16] = (uint8_t)(fd_port >> 8);
    src[17] = (uint8_t)fd_port;
    memset(reply, 3, sizeof reply);
    EXPECT(tsnet_magicsock_reply(a.ms, src, sizeof src, reply, sizeof reply) == 0);
    EXPECT(tsnet_magicsock_reply(a.ms, src, 3, reply, sizeof reply) == -1);
    int got_n = 0;
    for (uint64_t end = tsnet_now_ms() + 1000; got_n == 0 && tsnet_now_ms() < end;) {
        got_n = tsnet_udp_recv(fd, got, sizeof got, from, &from_port);
    }
    EXPECT(got_n == (int)sizeof reply && got[0] == 3 && from_port == tsnet_magicsock_port(a.ms));
    tsnet_sock_close(fd);

    tsnet_wgdev_free(a.wg);
    tsnet_wgdev_free(b.wg);
    tsnet_magicsock_free(a.ms);
    tsnet_magicsock_free(b.ms);
    if (failures == 0) {
        printf("tsnet wgnode_test: ok\n");
    }
    return failures != 0;
}
