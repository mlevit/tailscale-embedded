// A peer's paths. See endpoint.h; the Go is wgengine/magicsock/endpoint.go.
#include "endpoint.h"
#include <string.h>
#include "platform.h"

static const uint8_t V4_MAPPED[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

bool tsnet_ip_is6(const uint8_t ip[16])
{
    return memcmp(ip, V4_MAPPED, sizeof V4_MAPPED) != 0;
}

bool tsnet_ip_loopback(const uint8_t ip[16])
{
    if (!tsnet_ip_is6(ip)) {
        return ip[12] == 127; // 127.0.0.0/8
    }
    static const uint8_t ONE[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}; // ::1
    return memcmp(ip, ONE, 16) == 0;
}

bool tsnet_ip_link_local(const uint8_t ip[16])
{
    if (!tsnet_ip_is6(ip)) {
        return ip[12] == 169 && ip[13] == 254; // 169.254.0.0/16
    }
    return ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80; // fe80::/10
}

bool tsnet_ip_private(const uint8_t ip[16])
{
    if (!tsnet_ip_is6(ip)) {
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918)
        return ip[12] == 10 || (ip[12] == 172 && (ip[13] & 0xf0) == 16) || (ip[12] == 192 && ip[13] == 168);
    }
    return (ip[0] & 0xfe) == 0xfc; // fc00::/7 (RFC 4193)
}

static int boost(const uint8_t ip[16])
{
    int p = 0;
    if (tsnet_ip_loopback(ip)) {
        p += 50;
    } else if (tsnet_ip_link_local(ip)) {
        p += 30;
    } else if (tsnet_ip_private(ip)) {
        p += 20;
    }
    if (tsnet_ip_is6(ip)) {
        p += 10; // IPv6 is a bit more robust, as long as the latencies are about the same
    }
    return p;
}

static bool same_addr(const tsnet_addrq_t *a, const uint8_t ip[16], uint16_t port)
{
    return a->valid && memcmp(a->ip, ip, 16) == 0 && a->port == port;
}

bool tsnet_better_addr(const tsnet_addrq_t *a, const tsnet_addrq_t *b)
{
    if (a->valid == b->valid && (!a->valid || same_addr(a, b->ip, b->port))) {
        return a->wire_mtu > b->wire_mtu;
    }
    if (!b->valid) {
        return true;
    }
    if (!a->valid) {
        return false;
    }
    // Points: how much faster (percent) than the slower one.
    int ap = 0, bp = 0;
    if (a->latency_us > b->latency_us && a->latency_us > 0) {
        bp = (int)(100 - (b->latency_us * 100) / a->latency_us);
    } else if (b->latency_us > 0) {
        ap = (int)(100 - (a->latency_us * 100) / b->latency_us);
    }
    ap += boost(a->ip);
    bp += boost(b->ip);
    // Under 1% better: no change (stickiness, so two about-equal endpoints don't flap).
    if (ap <= 1 && bp == 0) {
        return false;
    }
    return ap > bp;
}

void tsnet_endpoint_init(tsnet_endpoint_t *e)
{
    memset(e, 0, sizeof *e);
}

static int find(const tsnet_endpoint_t *e, const uint8_t ip[16], uint16_t port)
{
    for (int i = 0; i < TSNET_EP_STATES; i++) {
        if (e->st[i].used && e->st[i].port == port && memcmp(e->st[i].ip, ip, 16) == 0) {
            return i;
        }
    }
    return -1;
}

// shouldDeleteLocked
static bool should_delete(const tsnet_epstate_t *st, uint64_t now)
{
    if (st->call_me_maybe != 0) {
        return false;
    }
    if (st->last_got_ping == 0) {
        return !st->in_netmap; // from the netmap: is it still there?
    }
    return now - st->last_got_ping > TSNET_SESSION_ACTIVE_US; // found at runtime
}

// deleteEndpointLocked
static void delete_at(tsnet_endpoint_t *e, int i)
{
    if (same_addr(&e->best, e->st[i].ip, e->st[i].port)) {
        memset(&e->best, 0, sizeof e->best);
    }
    memset(&e->st[i], 0, sizeof e->st[i]);
}

static void prune(tsnet_endpoint_t *e, uint64_t now)
{
    for (int i = 0; i < TSNET_EP_STATES; i++) {
        if (e->st[i].used && should_delete(&e->st[i], now)) {
            delete_at(e, i);
        }
    }
}

// A new endpoint state for ip:port, pruning first if full. With `evict` (a netmap or CallMeMaybe endpoint) a
// full table then drops its oldest ping-learned candidate: a peer's pings from spoofed addresses can't fill the table
// and keep the real endpoints out (Go's map holds 100 and always admits the netmap's). -1 if there's still no room.
static int add(tsnet_endpoint_t *e, uint64_t now, const uint8_t ip[16], uint16_t port, bool evict)
{
    for (int pass = 0; pass < 3; pass++) {
        for (int i = 0; i < TSNET_EP_STATES; i++) {
            if (!e->st[i].used) {
                e->st[i].used = true;
                memcpy(e->st[i].ip, ip, 16);
                e->st[i].port = port;
                return i;
            }
        }
        if (pass == 0) {
            prune(e, now);
        } else if (evict) {
            int victim = -1;
            for (int i = 0; i < TSNET_EP_STATES; i++) {
                const tsnet_epstate_t *st = &e->st[i];
                if (st->last_got_ping != 0 && !st->in_netmap && st->call_me_maybe == 0 &&
                    (victim < 0 || st->last_got_ping < e->st[victim].last_got_ping)) {
                    victim = i;
                }
            }
            if (victim < 0) {
                return -1;
            }
            delete_at(e, victim);
        } else {
            break;
        }
    }
    return -1;
}

void tsnet_endpoint_set_netmap(tsnet_endpoint_t *e, uint64_t now, const tsnet_disco_ep_t *eps, size_t n)
{
    for (int i = 0; i < TSNET_EP_STATES; i++) {
        e->st[i].in_netmap = false; // assume deleted until seen below
    }
    // First the ones already here, so making room for a new one never evicts one the netmap still lists.
    for (size_t k = 0; k < n; k++) {
        int i = find(e, eps[k].ip, eps[k].port);
        if (i >= 0) {
            e->st[i].in_netmap = true;
        }
    }
    for (size_t k = 0; k < n; k++) {
        int i = find(e, eps[k].ip, eps[k].port);
        if (i < 0) {
            i = add(e, now, eps[k].ip, eps[k].port, true);
        }
        if (i >= 0) {
            e->st[i].in_netmap = true;
        }
    }
    prune(e, now);
}

static void clear_best(tsnet_endpoint_t *e)
{
    memset(&e->best, 0, sizeof e->best);
    e->trust_until = 0;
}

void tsnet_endpoint_reset(tsnet_endpoint_t *e)
{
    clear_best(e);
    e->last_send_ext = 0;
    e->last_full_ping = 0;
    for (int i = 0; i < TSNET_EP_STATES; i++) {
        e->st[i].last_ping = 0;
    }
    memset(e->sent, 0, sizeof e->sent);
}

void tsnet_endpoint_addr_for_send(const tsnet_endpoint_t *e, uint64_t now, tsnet_addrq_t *udp, bool *derp)
{
    *udp = e->best;
    // A trusted best address alone; else both it (if any) and DERP.
    *derp = !(e->best.valid && now <= e->trust_until);
}

// startDiscoPingLocked's record: the ping, to ip:port or (`derp`) over DERP, added to `a`.
static void start_ping_to(tsnet_endpoint_t *e, uint64_t now, bool derp, const uint8_t ip[16], uint16_t port,
                          tsnet_ping_purpose_t purpose, tsnet_ep_actions_t *a)
{
    if (a->n_ping >= (int)(sizeof a->ping / sizeof a->ping[0])) {
        return;
    }
    int slot = 0;
    for (int i = 0; i < TSNET_EP_PINGS; i++) {
        if (!e->sent[i].used) {
            slot = i;
            break;
        }
        if (e->sent[i].at < e->sent[slot].at) {
            slot = i; // full: the oldest is forgotten
        }
    }
    tsnet_sentping_t *sp = &e->sent[slot];
    memset(sp, 0, sizeof *sp);
    sp->used = true;
    tsnet_random(sp->txid, sizeof sp->txid);
    sp->derp = derp;
    if (!derp) {
        memcpy(sp->ip, ip, 16);
        sp->port = port;
    }
    sp->at = now;
    sp->purpose = purpose;
    sp->cli = purpose == TSNET_PING_CLI ? e->cli_seq : 0;
    memcpy(a->ping[a->n_ping].txid, sp->txid, 12);
    a->ping[a->n_ping].derp = derp;
    memcpy(a->ping[a->n_ping].ip, sp->ip, 16);
    a->ping[a->n_ping].port = sp->port;
    a->n_ping++;
}

// startDiscoPingLocked to an endpoint: its lastPing is now.
static void start_ping(tsnet_endpoint_t *e, uint64_t now, int st, tsnet_ping_purpose_t purpose, tsnet_ep_actions_t *a)
{
    e->st[st].last_ping = now;
    start_ping_to(e, now, false, e->st[st].ip, e->st[st].port, purpose, a);
}

// noteTxActivityExtTriggerLocked: a send (or a CLI ping) keeps the session active and starts the heartbeat.
static void note_tx(tsnet_endpoint_t *e, uint64_t now)
{
    e->last_send_ext = now;
    if (!e->heartbeat) {
        e->heartbeat = true;
        e->heartbeat_at = now + TSNET_HEARTBEAT_US;
    }
}

void tsnet_endpoint_cli_ping(tsnet_endpoint_t *e, uint64_t now, bool has_derp, tsnet_ep_actions_t *a)
{
    memset(a, 0, sizeof *a);
    e->cli_seq++;
    note_tx(e, now);
    bool trusted = e->best.valid && now <= e->trust_until;
    if (!trusted && has_derp) {
        start_ping_to(e, now, true, NULL, 0, TSNET_PING_CLI, a);
    }
    if (trusted) {
        // The trusted direct path alone, so the answer doesn't bounce between two equally close endpoints.
        start_ping_to(e, now, false, e->best.ip, e->best.port, TSNET_PING_CLI, a);
        return;
    }
    // Every candidate, now: a CLI ping isn't held to the heartbeat or the 5 s limit, and doesn't set lastPing.
    for (int i = 0; i < TSNET_EP_STATES; i++) {
        if (e->st[i].used) {
            start_ping_to(e, now, false, e->st[i].ip, e->st[i].port, TSNET_PING_CLI, a);
        }
    }
}

// sendDiscoPingsLocked: a discovery ping to every endpoint not pinged in the last 5 s.
static void send_pings(tsnet_endpoint_t *e, uint64_t now, bool call_me_maybe, tsnet_ep_actions_t *a)
{
    e->last_full_ping = now;
    bool sent_any = false;
    for (int i = 0; i < TSNET_EP_STATES; i++) {
        if (!e->st[i].used) {
            continue;
        }
        if (should_delete(&e->st[i], now)) {
            delete_at(e, i);
            continue;
        }
        if (e->st[i].last_ping != 0 && now - e->st[i].last_ping < TSNET_DISCO_PING_INTERVAL_US) {
            continue;
        }
        sent_any = true;
        start_ping(e, now, i, TSNET_PING_DISCOVERY, a);
    }
    if (sent_any && call_me_maybe) {
        a->call_me_maybe = true; // the caller sends it if the peer has a DERP home
    }
}

void tsnet_endpoint_send(tsnet_endpoint_t *e, uint64_t now, tsnet_addrq_t *udp, bool *derp, tsnet_ep_actions_t *a)
{
    memset(a, 0, sizeof *a);
    tsnet_endpoint_addr_for_send(e, now, udp, derp);
    if (!udp->valid || now > e->trust_until) {
        send_pings(e, now, true, a);
    }
    note_tx(e, now);
}

bool tsnet_endpoint_got_ping(tsnet_endpoint_t *e, uint64_t now, const uint8_t ip[16], uint16_t port,
                             const uint8_t txid[12])
{
    // A txid seen before is a replay, from any address: no pong, and it doesn't refresh or add an endpoint.
    // Go remembers one txid per endpoint, so a captured ping replayed from alternating addresses drew a pong each time.
    for (int k = 0; k < e->got_tx_n; k++) {
        if (memcmp(e->got_tx[k], txid, 12) == 0) {
            return true;
        }
    }
    memcpy(e->got_tx[e->got_tx_next], txid, 12);
    e->got_tx_next = (e->got_tx_next + 1) % TSNET_GOT_TXIDS;
    if (e->got_tx_n < TSNET_GOT_TXIDS) {
        e->got_tx_n++;
    }
    int i = find(e, ip, port);
    if (i >= 0) {
        if (e->st[i].last_got_ping != 0) {
            e->st[i].last_got_ping = now; // a netmap endpoint stays one
        }
        return false;
    }
    i = add(e, now, ip, port, false); // a new candidate: waits for room, never evicts
    if (i >= 0) {
        e->st[i].last_got_ping = now;
    }
    return false;
}

bool tsnet_endpoint_pong(tsnet_endpoint_t *e, uint64_t now, const uint8_t txid[12], bool via_derp,
                         tsnet_ping_result_t *res)
{
    if (res) {
        memset(res, 0, sizeof *res);
    }
    int k = -1;
    for (int i = 0; i < TSNET_EP_PINGS; i++) {
        if (e->sent[i].used && memcmp(e->sent[i].txid, txid, 12) == 0) {
            k = i;
            break;
        }
    }
    if (k < 0) {
        return false; // not a ping we sent
    }
    tsnet_sentping_t sp = e->sent[k];
    memset(&e->sent[k], 0, sizeof e->sent[k]);
    // The first pong to the latest CLI ping answers it (resCB.reply).
    if (res && sp.cli != 0 && sp.cli == e->cli_seq && e->cli_answered != e->cli_seq) {
        e->cli_answered = e->cli_seq;
        res->answered = true;
        res->latency_us = now - sp.at;
        res->via_derp = via_derp;
        memcpy(res->ip, sp.ip, 16);
        res->port = sp.port;
    }
    if (via_derp || sp.derp) {
        return true; // no path to measure: DERP isn't one
    }
    if (find(e, sp.ip, sp.port) < 0) {
        return true; // no longer an endpoint we care about
    }
    tsnet_addrq_t this_pong = {.valid = true, .port = sp.port, .latency_us = now - sp.at,
                               .wire_mtu = TSNET_SAFE_WIRE_MTU};
    memcpy(this_pong.ip, sp.ip, 16);
    bool untrusted = now > e->trust_until;
    if (tsnet_better_addr(&this_pong, &e->best) || untrusted) {
        tsnet_log(TSNET_LOG_INFO, "magicsock: disco: now using a new path (port %u, %llu us)", (unsigned)sp.port,
                  (unsigned long long)this_pong.latency_us);
        e->best = this_pong;
    }
    if (same_addr(&e->best, sp.ip, sp.port)) {
        e->best.latency_us = this_pong.latency_us;
        e->trust_until = now + TSNET_TRUST_UDP_US;
    }
    return true;
}

// Whether a CallMeMaybe may name this address. Divergence from Go: Go drops only IPv6 link-local, so any peer
// could aim our pings at loopback, multicast, broadcast or 169.254.169.254. LAN and public addresses stay: a direct
// path over the LAN is the normal case.
static bool cmm_target_ok(const tsnet_disco_ep_t *ep)
{
    static const uint8_t ZERO[16] = {0};
    if (ep->port == 0 || memcmp(ep->ip, ZERO, 16) == 0 || tsnet_ip_loopback(ep->ip) || tsnet_ip_link_local(ep->ip)) {
        return false;
    }
    if (!tsnet_ip_is6(ep->ip)) {
        // 0.0.0.0/8 is "this network", 224.0.0.0/4 is multicast, 240.0.0.0/4 holds 255.255.255.255 (and is reserved).
        return ep->ip[12] != 0 && ep->ip[12] < 224;
    }
    return ep->ip[0] != 0xff; // ff00::/8
}

void tsnet_endpoint_call_me_maybe(tsnet_endpoint_t *e, uint64_t now, const tsnet_disco_ep_t *eps, size_t n,
                                  tsnet_ep_actions_t *a)
{
    memset(a, 0, sizeof *a);
    // At most one per peer per 2 s. A peer sends one when its pings go unanswered, at most once per 3 s
    // heartbeat, so this never delays a real path upgrade, but it caps a hostile peer at 16 pings per 2 s.
    if (e->last_cmm != 0 && now - e->last_cmm < TSNET_CMM_MIN_INTERVAL_US) {
        return;
    }
    e->last_cmm = now;
    bool want[TSNET_EP_STATES] = {false};
    for (size_t k = 0; k < n; k++) {
        if (!cmm_target_ok(&eps[k])) {
            continue;
        }
        int i = find(e, eps[k].ip, eps[k].port);
        if (i < 0) {
            i = add(e, now, eps[k].ip, eps[k].port, true);
        }
        if (i >= 0) {
            e->st[i].call_me_maybe = now;
            e->st[i].cmm = true;
            want[i] = true;
        }
    }
    // The last CallMeMaybe's endpoints that this one left out go.
    for (int i = 0; i < TSNET_EP_STATES; i++) {
        if (e->st[i].used && e->st[i].cmm && !want[i]) {
            delete_at(e, i);
        }
    }
    // Ping everything now, even what was pinged in the last 5 s.
    for (int i = 0; i < TSNET_EP_STATES; i++) {
        e->st[i].last_ping = 0;
    }
    send_pings(e, now, false, a);
}

bool tsnet_endpoint_want_full_ping(const tsnet_endpoint_t *e, uint64_t now)
{
    if (!e->best.valid || e->last_full_ping == 0) {
        return true;
    }
    if (now > e->trust_until) {
        return true;
    }
    if (e->best.latency_us <= TSNET_GOOD_ENOUGH_LATENCY_US) {
        return false;
    }
    return now - e->last_full_ping >= TSNET_UPGRADE_DIRECT_US;
}

void tsnet_endpoint_step(tsnet_endpoint_t *e, uint64_t now, tsnet_ep_actions_t *a)
{
    memset(a, 0, sizeof *a);
    // discoPingTimeout: no pong in 5 s. A ping to an untrusted best address that times out clears it.
    for (int i = 0; i < TSNET_EP_PINGS; i++) {
        tsnet_sentping_t *sp = &e->sent[i];
        if (sp->used && now - sp->at >= TSNET_PING_TIMEOUT_US) {
            if (same_addr(&e->best, sp->ip, sp->port) && now > e->trust_until) {
                clear_best(e);
            }
            memset(sp, 0, sizeof *sp);
        }
    }
    if (!e->heartbeat || now < e->heartbeat_at) {
        return;
    }
    e->heartbeat = false;
    if (e->last_send_ext == 0 || now - e->last_send_ext > TSNET_SESSION_ACTIVE_US) {
        return; // the session's idle: no more heartbeats
    }
    if (e->best.valid) {
        int i = find(e, e->best.ip, e->best.port);
        if (i >= 0) {
            start_ping(e, now, i, TSNET_PING_HEARTBEAT, a);
        }
    }
    if (tsnet_endpoint_want_full_ping(e, now)) {
        send_pings(e, now, true, a);
    }
    e->heartbeat = true;
    e->heartbeat_at = now + TSNET_HEARTBEAT_US;
}

uint64_t tsnet_endpoint_next(const tsnet_endpoint_t *e)
{
    uint64_t next = e->heartbeat ? e->heartbeat_at : 0;
    for (int i = 0; i < TSNET_EP_PINGS; i++) {
        if (e->sent[i].used) {
            uint64_t t = e->sent[i].at + TSNET_PING_TIMEOUT_US;
            if (next == 0 || t < next) {
                next = t;
            }
        }
    }
    return next;
}
