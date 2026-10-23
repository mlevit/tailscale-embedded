// The tunnel's IP side. See tun.h; the Go it stands for is net/tstun's wrapper and wireguard-go's
// RoutineReadFromTUN (route by destination) and RoutineSequentialReceiver (AllowedPeerSourceIP).
#include "tun.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "lwip/ip4_addr.h"
#include "lwip/pbuf.h"
#include "platform.h"
#include "wg.h"

typedef struct {
    uint8_t *data;
    size_t len;
} pkt_t;

typedef struct {
    pkt_t q[TSNET_TUN_QUEUE];
    int head, n;
} queue_t;

// Threads: `in`, `inject`, `aips`, `filter` and `up` belong to tsnet's task. `out` and the netif belong to
// lwIP's context (on the device its tcpip thread), which tsnet's task reaches only through tsnet_ip_exec. The netif's
// output signals `wake`.
struct tsnet_tun {
    tsnet_tun_cfg_t cfg;
    struct netif netif;
    bool up;
    tsnet_aips_t aips;
    tsnet_filter_t *filter;
    queue_t in, out;
    queue_t inject; // tsnet's own packets to peers (TSMP rejects and pongs), past the filter as Go's InjectOutbound
    uint8_t (*jailed)[32]; // the peers whose packets go through the jailed filter (IsJailed)
    size_t n_jailed;
    tsnet_wake_t wake;
};

static bool push(queue_t *q, const uint8_t *data, size_t len)
{
    if (q->n == TSNET_TUN_QUEUE) {
        return false; // full: the newest is dropped
    }
    uint8_t *copy = tsnet_malloc(len);
    if (!copy) {
        return false;
    }
    memcpy(copy, data, len);
    q->q[(q->head + q->n++) % TSNET_TUN_QUEUE] = (pkt_t){copy, len};
    return true;
}

static bool pop(queue_t *q, pkt_t *p)
{
    if (q->n == 0) {
        return false;
    }
    *p = q->q[q->head];
    q->head = (q->head + 1) % TSNET_TUN_QUEUE;
    q->n--;
    return true;
}

static void drain(queue_t *q)
{
    pkt_t p;
    while (pop(q, &p)) {
        free(p.data);
    }
}

// The netif's output, in lwIP's context: an IPv4 packet for the tailnet. It's copied (a pbuf can be a chain), queued,
// and tsnet's loop woken. It must never call tsnet_ip_exec (platform.h).
// The tun that holds `netif`. Its `state` stays NULL: ESP-IDF's esp_netif treats any netif's state as its own
// esp_netif_t (without LWIP_ESP_NETIF_DATA) and skips a netif whose state is NULL. A tun pointer there was written
// through on the device.
static tsnet_tun_t *tun_of(struct netif *netif)
{
    return (tsnet_tun_t *)((char *)netif - offsetof(tsnet_tun_t, netif));
}

static err_t output(struct netif *netif, struct pbuf *p, const ip4_addr_t *dst)
{
    (void)dst; // the packet's own destination routes it, in step
    tsnet_tun_t *t = tun_of(netif);
    if (p->tot_len > TSNET_WG_TUN_MTU) {
        return ERR_BUF;
    }
    uint8_t buf[TSNET_WG_TUN_MTU];
    u16_t n = pbuf_copy_partial(p, buf, p->tot_len, 0);
    if (!push(&t->out, buf, n)) {
        return ERR_MEM;
    }
    tsnet_wake_signal(&t->wake);
    return ERR_OK;
}

static err_t netif_init_cb(struct netif *netif)
{
    netif->name[0] = 't';
    netif->name[1] = 's';
    netif->output = output;
    netif->mtu = TSNET_WG_TUN_MTU;
    netif->flags = NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

tsnet_tun_t *tsnet_tun_new(const tsnet_tun_cfg_t *cfg)
{
    tsnet_tun_t *t = tsnet_calloc(1, sizeof *t);
    if (!t) {
        return NULL;
    }
    t->cfg = *cfg;
    tsnet_aips_init(&t->aips);
    t->filter = tsnet_filter_new();
    if (!t->filter || tsnet_wake_open(&t->wake) != 0) {
        tsnet_filter_free(t->filter);
        free(t);
        return NULL;
    }
    return t;
}

static int remove_netif(void *ctx)
{
    netif_remove(&((tsnet_tun_t *)ctx)->netif);
    return 0;
}

void tsnet_tun_free(tsnet_tun_t *t)
{
    if (!t) {
        return;
    }
    if (t->up) {
        tsnet_ip_exec(remove_netif, t); // first: then lwIP's context can't call output on what's freed below
    }
    drain(&t->in);
    drain(&t->out);
    drain(&t->inject);
    tsnet_aips_free(&t->aips);
    free(t->jailed);
    tsnet_filter_free(t->filter);
    tsnet_wake_close(&t->wake);
    free(t);
}

typedef struct {
    tsnet_tun_t *t;
    ip4_addr_t ip, mask, gw;
} set_addr_t;

// In lwIP's context.
static int set_addr(void *ctx)
{
    set_addr_t *s = ctx;
    if (s->t->up) {
        netif_set_addr(&s->t->netif, &s->ip, &s->mask, &s->gw);
        return 0;
    }
    if (!netif_add(&s->t->netif, &s->ip, &s->mask, &s->gw, NULL, netif_init_cb, s->t->cfg.input)) { // tun_of
        return -1;
    }
    netif_set_up(&s->t->netif);
    return 0;
}

int tsnet_tun_set_addr(tsnet_tun_t *t, const uint8_t ip4[4])
{
    set_addr_t s = {.t = t};
    IP4_ADDR(&s.ip, ip4[0], ip4[1], ip4[2], ip4[3]);
    IP4_ADDR(&s.mask, 255, 192, 0, 0); // 100.64.0.0/10, Tailscale's CGNAT range: the tailnet routes to this netif
    ip4_addr_set_zero(&s.gw);
    if (tsnet_ip_exec(set_addr, &s) != 0) {
        return -1;
    }
    t->up = true;
    return 0;
}

int tsnet_tun_set_routes(tsnet_tun_t *t, const uint8_t peer[32], const tsnet_prefix_t *routes, size_t n)
{
    tsnet_aips_remove_peer(&t->aips, peer);
    for (size_t i = 0; i < n; i++) {
        if (tsnet_aips_insert(&t->aips, routes[i].ip.ip, routes[i].ip.is6, routes[i].bits, peer) != 0) {
            return -1;
        }
    }
    return 0;
}

static size_t jailed_at(const tsnet_tun_t *t, const uint8_t peer[32])
{
    size_t i = 0;
    while (i < t->n_jailed && memcmp(t->jailed[i], peer, 32) != 0) {
        i++;
    }
    return i; // n_jailed when it isn't there
}

int tsnet_tun_set_jailed(tsnet_tun_t *t, const uint8_t peer[32], bool jailed)
{
    size_t i = jailed_at(t, peer);
    if (!jailed && i < t->n_jailed) {
        memcpy(t->jailed[i], t->jailed[--t->n_jailed], 32);
    } else if (jailed && i == t->n_jailed) {
        uint8_t(*grown)[32] = tsnet_realloc(t->jailed, (t->n_jailed + 1) * 32);
        if (!grown) {
            return -1;
        }
        t->jailed = grown;
        memcpy(t->jailed[t->n_jailed++], peer, 32);
    }
    return 0;
}

void tsnet_tun_remove_peer(tsnet_tun_t *t, const uint8_t peer[32])
{
    tsnet_aips_remove_peer(&t->aips, peer);
    tsnet_tun_set_jailed(t, peer, false);
}

int tsnet_tun_set_filter(tsnet_tun_t *t, const char *rules_json, const tsnet_prefix_t *local, size_t n_local)
{
    return tsnet_filter_set(t->filter, rules_json, local, n_local);
}

void tsnet_tun_deliver(tsnet_tun_t *t, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    if (len < 20 || pkt[0] >> 4 != 4) {
        return; // IPv4 only for now
    }
    if (!tsnet_aips_allowed(&t->aips, peer, pkt + 12, false)) {
        tsnet_log(TSNET_LOG_DEBUG, "tun: IPv4 packet with disallowed source address from a peer");
        return;
    }
    // TSMP is tailscaled's own, never the stack's (filterPacketInboundFromWireGuard): a ping gets its pong, whatever
    // the filter says, and the rest goes nowhere.
    if (pkt[9] == 99) {
        uint8_t pong[TSNET_TSMP_PONG_LEN];
        if (tsnet_tsmp_pong(pkt, len, pong)) {
            push(&t->inject, pong, sizeof pong);
        }
        return;
    }
    bool jailed = jailed_at(t, peer) < t->n_jailed;
    if (!(jailed ? tsnet_filter_in_jailed(t->filter, pkt, len) : tsnet_filter_in(t->filter, pkt, len))) {
        // A refused TCP SYN: tell the sender why, as tstun does, so its CLI can show the rejection.
        uint8_t rej[TSNET_TSMP_REJECT_LEN];
        if (tsnet_tsmp_reject(pkt, len, jailed ? TSNET_REJECT_SHIELDS : TSNET_REJECT_ACLS, rej)) {
            push(&t->inject, rej, sizeof rej);
        }
        return;
    }
    push(&t->in, pkt, len);
}

// Sends a packet to the peer whose AllowedIPs has its destination, or drops it.
static void route(tsnet_tun_t *t, const pkt_t *p)
{
    const uint8_t *peer = p->len >= 20 ? tsnet_aips_lookup(&t->aips, p->data + 16, false) : NULL;
    if (peer && t->cfg.send) {
        t->cfg.send(t->cfg.ctx, peer, p->data, p->len);
    }
}

typedef struct {
    tsnet_tun_t *t;
    queue_t taken;
} take_t;

// In lwIP's context: moves the whole out queue to tsnet's task.
static int take_out(void *ctx)
{
    take_t *k = ctx;
    k->taken = k->t->out;
    memset(&k->t->out, 0, sizeof k->t->out);
    return 0;
}

void tsnet_tun_step(tsnet_tun_t *t)
{
    pkt_t p;
    while (t->up && pop(&t->in, &p)) {
        struct pbuf *pb = pbuf_alloc(PBUF_RAW, (u16_t)p.len, PBUF_RAM);
        if (pb) {
            pbuf_take(pb, p.data, (u16_t)p.len);
            // The netif's input: tcpip_input on the device (it posts to lwIP's thread), ip_input on the host.
            if (t->netif.input(pb, &t->netif) != ERR_OK) {
                pbuf_free(pb); // the input didn't take it
            }
        }
        free(p.data);
    }
    // Cleared before the take: an output after it signals again, so no packet waits for a wake-up that came early.
    tsnet_wake_clear(&t->wake);
    take_t k = {.t = t};
    if (tsnet_ip_exec(take_out, &k) != 0) {
        return;
    }
    while (pop(&k.taken, &p)) {
        // The filter drops junk and records UDP flows for their replies: a jailed peer's in the jailed filter's cache.
        const uint8_t *peer = p.len >= 20 ? tsnet_aips_lookup(&t->aips, p.data + 16, false) : NULL;
        bool jailed = peer && jailed_at(t, peer) < t->n_jailed;
        if (jailed ? tsnet_filter_out_jailed(t->filter, p.data, p.len) : tsnet_filter_out(t->filter, p.data, p.len)) {
            route(t, &p);
        }
        free(p.data);
    }
    while (pop(&t->inject, &p)) {
        route(t, &p);
        free(p.data);
    }
}

bool tsnet_tun_pending(const tsnet_tun_t *t)
{
    return t->in.n > 0 || t->inject.n > 0; // `out` isn't tsnet's task's to read: the wake fd stands for it
}

int tsnet_tun_fd(const tsnet_tun_t *t)
{
    return t->wake.rfd;
}
