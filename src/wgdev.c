// WireGuard's device and peers. See wgdev.h; the Go is wireguard-go's device/peer.go, timers.go, send.go,
// receive.go and noise-protocol.go's BeginSymmetricSession and ReceivedWithKeypair.
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#elif !defined(ESP_PLATFORM)
#define _DEFAULT_SOURCE // clock_gettime under -std=c11 on glibc
#endif
#include "wgdev.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto.h"
#include "platform.h"

#define ZERO_KEY_MS (TSNET_WG_REJECT_AFTER_MS * 3)

typedef struct {
    bool used;
    uint8_t send[32], recv[32];
    bool initiator;
    uint32_t local_index, remote_index;
    uint64_t send_nonce;
    tsnet_wg_replay_t replay;
    uint64_t created;
} keypair_t;

typedef struct {
    uint8_t *data; // malloc'd; a keepalive is NULL with len 0
    size_t len;
} staged_t;

typedef struct {
    uint8_t pub[32];
    bool lazy; // deleteOnIdle
    tsnet_wg_handshake_t hs;
    tsnet_wg_cookiegen_t gen;
    keypair_t current, previous, next;
    staged_t staged[TSNET_WG_STAGED];
    int n_staged;
    // The timers: 0 is not pending.
    uint64_t retransmit_at, keepalive_at, new_handshake_at, zero_key_at;
    uint32_t handshake_attempts;
    bool need_another_keepalive, sent_last_minute_handshake, handshake_on_user_send;
    bool sent_handshake; // lastSentHandshake is set
    uint64_t last_sent_handshake, last_handshake;
} peer_t;

struct tsnet_wgdev {
    tsnet_wgdev_cfg_t cfg;
    uint8_t priv[32], pub[32];
    tsnet_wg_cookiecheck_t check;
    peer_t **peers;
    size_t n_peers;
};

static void wipe_keypair(keypair_t *k)
{
    tsnet_wipe(k, sizeof *k);
}

static void flush_staged(peer_t *p)
{
    for (int i = 0; i < p->n_staged; i++) {
        free(p->staged[i].data);
    }
    p->n_staged = 0;
}

static void free_peer(peer_t *p)
{
    flush_staged(p);
    tsnet_wipe(p, sizeof *p);
    free(p);
}

tsnet_wgdev_t *tsnet_wgdev_new(const tsnet_wgdev_cfg_t *cfg)
{
    tsnet_wgdev_t *d = tsnet_calloc(1, sizeof *d);
    if (!d) {
        return NULL;
    }
    d->cfg = *cfg;
    memcpy(d->priv, cfg->priv, 32);
    d->cfg.priv = NULL;
    if (tsnet_x25519_public(d->pub, d->priv) != 0) {
        tsnet_wgdev_free(d);
        return NULL;
    }
    tsnet_wg_cookiecheck_init(&d->check, d->pub);
    return d;
}

void tsnet_wgdev_free(tsnet_wgdev_t *d)
{
    if (!d) {
        return;
    }
    for (size_t i = 0; i < d->n_peers; i++) {
        free_peer(d->peers[i]);
    }
    free(d->peers);
    tsnet_wipe(d, sizeof *d);
    free(d);
}

static peer_t *find_peer(const tsnet_wgdev_t *d, const uint8_t pub[32])
{
    for (size_t i = 0; i < d->n_peers; i++) {
        if (memcmp(d->peers[i]->pub, pub, 32) == 0) {
            return d->peers[i];
        }
    }
    return NULL;
}

// The index table: a local index names a peer's handshake, or one of its keypairs.
static bool index_used(const tsnet_wgdev_t *d, uint32_t idx)
{
    for (size_t i = 0; i < d->n_peers; i++) {
        const peer_t *p = d->peers[i];
        if ((p->hs.local_index == idx && p->hs.state != TSNET_WG_HS_ZEROED) ||
            (p->current.used && p->current.local_index == idx) ||
            (p->previous.used && p->previous.local_index == idx) || (p->next.used && p->next.local_index == idx)) {
            return true;
        }
    }
    return false;
}

// NewIndexForHandshake: a random index no one uses (0 included, as in wireguard-go). -1 if the random source fails or
// 64 tries all collide (a few dozen indexes are in use at most), never an endless loop.
static int new_index(const tsnet_wgdev_t *d, uint32_t *out)
{
    for (int tries = 0; tries < 64; tries++) {
        if (tsnet_random(out, sizeof *out) != 0) {
            return -1;
        }
        if (!index_used(d, *out)) {
            return 0;
        }
    }
    return -1;
}

static uint32_t jitter(void)
{
    uint32_t r = 0;
    tsnet_random(&r, sizeof r);
    return r % TSNET_WG_REKEY_JITTER_MS;
}

static peer_t *add_peer(tsnet_wgdev_t *d, const uint8_t pub[32], bool lazy, uint64_t now)
{
    peer_t *p = tsnet_calloc(1, sizeof *p);
    peer_t **grown = p ? tsnet_realloc(d->peers, (d->n_peers + 1) * sizeof *grown) : NULL;
    if (!grown) {
        free(p);
        return NULL;
    }
    d->peers = grown;
    if (tsnet_wg_handshake_init(&p->hs, d->priv, pub) != 0) {
        free_peer(p);
        return NULL; // a low-order key: no handshake possible
    }
    memcpy(p->pub, pub, 32);
    p->lazy = lazy;
    tsnet_wg_cookiegen_init(&p->gen, pub);
    if (lazy) {
        p->zero_key_at = now + ZERO_KEY_MS; // reaped if it never completes a handshake (Peer.Start)
    }
    d->peers[d->n_peers++] = p;
    return p;
}

int tsnet_wgdev_add_peer(tsnet_wgdev_t *d, const uint8_t pub[32], uint64_t now)
{
    if (find_peer(d, pub)) {
        return 1;
    }
    return add_peer(d, pub, false, now) ? 0 : -1;
}

void tsnet_wgdev_remove_peer(tsnet_wgdev_t *d, const uint8_t pub[32])
{
    for (size_t i = 0; i < d->n_peers; i++) {
        if (memcmp(d->peers[i]->pub, pub, 32) == 0) {
            free_peer(d->peers[i]);
            d->peers[i] = d->peers[--d->n_peers];
            return;
        }
    }
}

bool tsnet_wgdev_has_peer(const tsnet_wgdev_t *d, const uint8_t pub[32])
{
    return find_peer(d, pub) != NULL;
}

// timersAnyAuthenticatedPacketSent: any authenticated packet sent cancels a pending keepalive.
static void any_sent(peer_t *p)
{
    p->keepalive_at = 0;
}

// timersAnyAuthenticatedPacketReceived: anything heard cancels the new-handshake timer.
static void any_received(peer_t *p)
{
    p->new_handshake_at = 0;
}

static void emit(tsnet_wgdev_t *d, peer_t *p, const uint8_t *pkt, size_t len)
{
    if (d->cfg.send) {
        d->cfg.send(d->cfg.ctx, p->pub, pkt, len);
    }
}

// The wall clock's TAI64N, for an initiation's timestamp.
static void now_tai64n(const tsnet_wgdev_t *d, uint8_t ts[TSNET_WG_TIMESTAMP_LEN])
{
    int64_t secs;
    uint32_t nanos;
    if (d->cfg.wall) {
        d->cfg.wall(d->cfg.ctx, &secs, &nanos);
    } else {
        struct timespec t;
        clock_gettime(CLOCK_REALTIME, &t);
        secs = (int64_t)t.tv_sec;
        nanos = (uint32_t)t.tv_nsec;
    }
    tsnet_wg_tai64n(ts, secs, nanos);
}

// SendHandshakeInitiation: at most one every RekeyTimeout.
static void send_initiation(tsnet_wgdev_t *d, peer_t *p, bool retry, uint64_t now)
{
    if (!retry) {
        p->handshake_attempts = 0;
    }
    if (p->sent_handshake && now - p->last_sent_handshake < TSNET_WG_REKEY_TIMEOUT_MS) {
        return;
    }
    p->handshake_on_user_send = false;
    p->sent_handshake = true;
    p->last_sent_handshake = now;
    uint8_t msg[TSNET_WG_INITIATION_LEN], ts[TSNET_WG_TIMESTAMP_LEN];
    now_tai64n(d, ts);
    p->hs.local_index = 0; // the old index goes (indexTable.Delete)
    uint32_t idx;
    if (new_index(d, &idx) != 0 || tsnet_wg_create_initiation(&p->hs, d->pub, idx, NULL, ts, msg) != 0) {
        tsnet_log(TSNET_LOG_ERROR, "wireguard: can't create an initiation");
        return;
    }
    tsnet_wg_add_macs(&p->gen, msg, sizeof msg, now);
    any_sent(p);
    emit(d, p, msg, sizeof msg);
    p->retransmit_at = now + TSNET_WG_REKEY_TIMEOUT_MS + jitter(); // timersHandshakeInitiated
}

// BeginSymmetricSession's keypair rotation.
static void begin_session(peer_t *p, const tsnet_wg_keys_t *k, uint64_t now)
{
    keypair_t kp = {.used = true, .initiator = k->initiator, .local_index = k->local_index,
                    .remote_index = k->remote_index, .created = now};
    memcpy(kp.send, k->send, 32);
    memcpy(kp.recv, k->recv, 32);
    tsnet_wg_replay_reset(&kp.replay);
    memset(kp.replay.ring, 0, sizeof kp.replay.ring);
    if (k->initiator) {
        if (p->next.used) {
            wipe_keypair(&p->previous);
            p->previous = p->next;
            memset(&p->next, 0, sizeof p->next);
            wipe_keypair(&p->current);
        } else {
            wipe_keypair(&p->previous);
            p->previous = p->current;
        }
        p->current = kp;
    } else {
        wipe_keypair(&p->next);
        p->next = kp;
        wipe_keypair(&p->previous);
    }
    tsnet_wipe(&kp, sizeof kp);
}

// timersSessionDerived (the session-expired timer is only state for status, so only the zeroing one is kept).
static void session_derived(peer_t *p, uint64_t now)
{
    p->zero_key_at = now + ZERO_KEY_MS;
}

// timersHandshakeComplete
static void handshake_complete(peer_t *p, uint64_t now)
{
    p->retransmit_at = 0;
    p->handshake_attempts = 0;
    p->sent_last_minute_handshake = false;
    p->last_handshake = now;
}

static void send_staged(tsnet_wgdev_t *d, peer_t *p, uint64_t now);

// StagePackets: the oldest goes when it's full.
static void stage(peer_t *p, const uint8_t *pkt, size_t len)
{
    if (p->n_staged == TSNET_WG_STAGED) {
        free(p->staged[0].data);
        memmove(&p->staged[0], &p->staged[1], (TSNET_WG_STAGED - 1) * sizeof p->staged[0]);
        p->n_staged--;
    }
    uint8_t *copy = NULL;
    if (len) {
        copy = tsnet_malloc(len);
        if (!copy) {
            return;
        }
        memcpy(copy, pkt, len);
    }
    p->staged[p->n_staged++] = (staged_t){copy, len};
}

// SendKeepalive: an empty packet, unless data is staged anyway.
static void send_keepalive(tsnet_wgdev_t *d, peer_t *p, uint64_t now)
{
    if (p->n_staged == 0) {
        stage(p, NULL, 0);
    }
    send_staged(d, p, now);
}

static bool usable(const keypair_t *k, uint64_t now)
{
    return k->used && k->send_nonce < TSNET_WG_REJECT_AFTER_MESSAGES && now - k->created < TSNET_WG_REJECT_AFTER_MS;
}

// SendStagedPackets, then RoutineSequentialSender's timers and keepKeyFreshSending.
static void send_staged(tsnet_wgdev_t *d, peer_t *p, uint64_t now)
{
    if (p->n_staged == 0) {
        return;
    }
    keypair_t *kp = &p->current;
    if (!usable(kp, now)) {
        send_initiation(d, p, false, now);
        return;
    }
    bool data_sent = false;
    static uint8_t out[TSNET_WG_TRANSPORT_HEADER + TSNET_WG_MAX_PACKET + 16 + 16];
    for (int i = 0; i < p->n_staged; i++) {
        uint64_t nonce = kp->send_nonce++;
        int n = tsnet_wg_seal(out, sizeof out, kp->send, kp->remote_index, nonce, p->staged[i].data, p->staged[i].len,
                              TSNET_WG_TUN_MTU);
        if (n > 0) {
            emit(d, p, out, (size_t)n);
        }
        data_sent |= p->staged[i].len > 0;
    }
    flush_staged(p);
    any_sent(p);
    if (data_sent && p->new_handshake_at == 0) {
        // timersDataSent: nothing heard back in 15 s (and some jitter) starts a new handshake.
        p->new_handshake_at = now + TSNET_WG_KEEPALIVE_MS + TSNET_WG_REKEY_TIMEOUT_MS + jitter();
    }
    // keepKeyFreshSending
    if (p->handshake_on_user_send || kp->send_nonce > TSNET_WG_REKEY_AFTER_MESSAGES ||
        (kp->initiator && now - kp->created > TSNET_WG_REKEY_AFTER_MS)) {
        send_initiation(d, p, false, now);
    }
}

int tsnet_wgdev_send(tsnet_wgdev_t *d, const uint8_t pub[32], const uint8_t *pkt, size_t len, uint64_t now)
{
    peer_t *p = find_peer(d, pub);
    if (!p || len == 0 || len > TSNET_WG_MAX_PACKET) {
        return -1;
    }
    stage(p, pkt, len);
    send_staged(d, p, now);
    return 0;
}

void tsnet_wgdev_handshake_on_send(tsnet_wgdev_t *d, const uint8_t pub[32])
{
    peer_t *p = find_peer(d, pub);
    if (p && (p->current.used || p->previous.used || p->next.used || p->hs.state != TSNET_WG_HS_ZEROED)) {
        p->handshake_on_user_send = true; // hasKeyMaterial
    }
}

// An initiation: mac1 checked, the static key decrypted, its peer found (or made lazily), then a response.
static void on_initiation(tsnet_wgdev_t *d, const uint8_t *pkt, uint64_t now)
{
    tsnet_wg_initiation_t st;
    if (tsnet_wg_open_initiation(d->priv, d->pub, pkt, &st) != 0) {
        return;
    }
    peer_t *p = find_peer(d, st.remote_static);
    if (!p && d->cfg.lookup && d->cfg.lookup(d->cfg.ctx, st.remote_static)) {
        p = add_peer(d, st.remote_static, true, now);
    }
    if (!p || tsnet_wg_accept_initiation(&p->hs, &st, pkt, now) != 0) {
        tsnet_wipe(&st, sizeof st);
        return;
    }
    any_received(p);
    // SendHandshakeResponse
    p->sent_handshake = true;
    p->last_sent_handshake = now;
    uint8_t resp[TSNET_WG_RESPONSE_LEN];
    uint32_t idx;
    if (new_index(d, &idx) != 0 || tsnet_wg_create_response(&p->hs, idx, NULL, resp) != 0) {
        tsnet_wg_handshake_clear(&p->hs); // the accepted handshake's chaining key, hash and ephemeral go
        return;
    }
    tsnet_wg_add_macs(&p->gen, resp, sizeof resp, now);
    tsnet_wg_keys_t keys;
    if (tsnet_wg_derive_keys(&p->hs, &keys) != 0) {
        return;
    }
    begin_session(p, &keys, now);
    tsnet_wipe(&keys, sizeof keys);
    session_derived(p, now);
    any_sent(p);
    emit(d, p, resp, sizeof resp);
}

// The handshake (or keypair) a local index names.
static peer_t *by_index(const tsnet_wgdev_t *d, uint32_t idx, bool handshake)
{
    for (size_t i = 0; i < d->n_peers; i++) {
        peer_t *p = d->peers[i];
        if (handshake ? (p->hs.state == TSNET_WG_HS_INITIATION_CREATED && p->hs.local_index == idx)
                      : ((p->current.used && p->current.local_index == idx) ||
                         (p->previous.used && p->previous.local_index == idx) ||
                         (p->next.used && p->next.local_index == idx))) {
            return p;
        }
    }
    return NULL;
}

static void on_response(tsnet_wgdev_t *d, const uint8_t *pkt, uint64_t now)
{
    uint32_t receiver = (uint32_t)pkt[8] | (uint32_t)pkt[9] << 8 | (uint32_t)pkt[10] << 16 | (uint32_t)pkt[11] << 24;
    peer_t *p = by_index(d, receiver, true);
    if (!p || tsnet_wg_consume_response(&p->hs, d->priv, pkt) != 0) {
        return;
    }
    any_received(p);
    tsnet_wg_keys_t keys;
    if (tsnet_wg_derive_keys(&p->hs, &keys) != 0) {
        return;
    }
    begin_session(p, &keys, now);
    tsnet_wipe(&keys, sizeof keys);
    session_derived(p, now);
    handshake_complete(p, now);
    send_keepalive(d, p, now);
}

static void on_cookie_reply(tsnet_wgdev_t *d, const uint8_t *pkt, uint64_t now)
{
    uint32_t receiver = (uint32_t)pkt[4] | (uint32_t)pkt[5] << 8 | (uint32_t)pkt[6] << 16 | (uint32_t)pkt[7] << 24;
    peer_t *p = by_index(d, receiver, true);
    if (!p) {
        p = by_index(d, receiver, false);
    }
    if (p) {
        tsnet_wg_consume_cookie_reply(&p->gen, pkt, now);
    }
}

// The IP packet's own length (4: Total Length; 6: Payload Length + 40), or 0 if it isn't a whole one.
static size_t ip_length(const uint8_t *pkt, size_t len)
{
    if (len >= 20 && pkt[0] >> 4 == 4) {
        size_t total = (size_t)pkt[2] << 8 | pkt[3];
        return total >= 20 && total <= len ? total : 0;
    }
    if (len >= 40 && pkt[0] >> 4 == 6) {
        size_t total = ((size_t)pkt[4] << 8 | pkt[5]) + 40;
        return total <= len ? total : 0;
    }
    return 0;
}

static void on_transport(tsnet_wgdev_t *d, const uint8_t *pkt, size_t len, uint64_t now)
{
    uint32_t receiver;
    uint64_t counter;
    if (tsnet_wg_transport_header(pkt, len, &receiver, &counter) != 0) {
        return;
    }
    peer_t *p = by_index(d, receiver, false);
    if (!p) {
        return;
    }
    keypair_t *kp = p->current.used && p->current.local_index == receiver   ? &p->current
                    : p->previous.used && p->previous.local_index == receiver ? &p->previous
                                                                             : &p->next;
    if (now - kp->created > TSNET_WG_REJECT_AFTER_MS) {
        return; // the keypair has expired
    }
    static uint8_t plain[TSNET_WG_MAX_PACKET + 32];
    int n = tsnet_wg_open(plain, sizeof plain, kp->recv, pkt, len);
    if (n < 0 || !tsnet_wg_replay_check(&kp->replay, counter, TSNET_WG_REJECT_AFTER_MESSAGES)) {
        return;
    }
    // ReceivedWithKeypair: the first data under "next" confirms it.
    if (kp == &p->next) {
        wipe_keypair(&p->previous);
        p->previous = p->current;
        p->current = p->next;
        memset(&p->next, 0, sizeof p->next);
        handshake_complete(p, now);
        send_staged(d, p, now);
    }
    // Any authenticated packet that isn't a keepalive is data (dataPacketReceived), even one that then fails the IP
    // checks; only a whole IP packet is delivered.
    bool data = n > 0;
    if (data) {
        size_t ip = ip_length(plain, (size_t)n);
        if (ip && d->cfg.deliver) {
            d->cfg.deliver(d->cfg.ctx, p->pub, plain, ip);
        }
    }
    // keepKeyFreshReceiving: an initiator's keypair near its end gets one last handshake.
    if (!p->sent_last_minute_handshake && p->current.used && p->current.initiator &&
        now - p->current.created > TSNET_WG_REJECT_AFTER_MS - TSNET_WG_KEEPALIVE_MS - TSNET_WG_REKEY_TIMEOUT_MS) {
        p->sent_last_minute_handshake = true;
        send_initiation(d, p, false, now);
    }
    any_received(p);
    if (data) {
        // timersDataReceived: answer within 10 s, with a keepalive if nothing else goes.
        if (p->keepalive_at == 0) {
            p->keepalive_at = now + TSNET_WG_KEEPALIVE_MS;
        } else {
            p->need_another_keepalive = true;
        }
    }
}

void tsnet_wgdev_receive(tsnet_wgdev_t *d, const uint8_t *pkt, size_t len, const uint8_t *src, size_t src_len,
                         uint64_t now)
{
    (void)src;
    (void)src_len; // for a cookie reply, which this loop never sends (it is never under load)
    if (len < TSNET_WG_KEEPALIVE_LEN) {
        return;
    }
    switch ((uint32_t)pkt[0] | (uint32_t)pkt[1] << 8 | (uint32_t)pkt[2] << 16 | (uint32_t)pkt[3] << 24) {
    case TSNET_WG_TRANSPORT:
        on_transport(d, pkt, len, now);
        break;
    case TSNET_WG_INITIATION:
        if (len == TSNET_WG_INITIATION_LEN && tsnet_wg_check_mac1(&d->check, pkt, len)) {
            on_initiation(d, pkt, now);
        }
        break;
    case TSNET_WG_RESPONSE:
        if (len == TSNET_WG_RESPONSE_LEN && tsnet_wg_check_mac1(&d->check, pkt, len)) {
            on_response(d, pkt, now);
        }
        break;
    case TSNET_WG_COOKIE_REPLY:
        if (len == TSNET_WG_COOKIE_REPLY_LEN) {
            on_cookie_reply(d, pkt, now);
        }
        break;
    default:
        break; // a message of an unknown type
    }
}

// ZeroAndFlushAll
static void zero_and_flush(peer_t *p)
{
    wipe_keypair(&p->previous);
    wipe_keypair(&p->current);
    wipe_keypair(&p->next);
    tsnet_wg_handshake_clear(&p->hs);
    flush_staged(p);
}

static void step_peer(tsnet_wgdev_t *d, peer_t *p, uint64_t now, bool *remove)
{
    if (p->retransmit_at && now >= p->retransmit_at) {
        p->retransmit_at = 0;
        if (p->handshake_attempts > TSNET_WG_MAX_HANDSHAKES) {
            // Give up: no keepalive, the staged packets dropped, the keys zeroed after 540 s, until new data.
            tsnet_log(TSNET_LOG_INFO, "wireguard: handshake did not complete after %d attempts, giving up",
                      TSNET_WG_MAX_HANDSHAKES + 2);
            p->keepalive_at = 0;
            flush_staged(p);
            if (p->zero_key_at == 0) {
                p->zero_key_at = now + ZERO_KEY_MS;
            }
        } else {
            p->handshake_attempts++;
            send_initiation(d, p, true, now);
        }
    }
    if (p->keepalive_at && now >= p->keepalive_at) {
        p->keepalive_at = 0;
        send_keepalive(d, p, now);
        if (p->need_another_keepalive) {
            p->need_another_keepalive = false;
            p->keepalive_at = now + TSNET_WG_KEEPALIVE_MS;
        }
    }
    if (p->new_handshake_at && now >= p->new_handshake_at) {
        p->new_handshake_at = 0;
        send_initiation(d, p, false, now); // we stopped hearing back after 15 s
    }
    if (p->zero_key_at && now >= p->zero_key_at) {
        p->zero_key_at = 0;
        zero_and_flush(p);
        *remove = p->lazy; // an idle lazy peer goes
    }
}

void tsnet_wgdev_step(tsnet_wgdev_t *d, uint64_t now)
{
    for (size_t i = 0; i < d->n_peers;) {
        bool remove = false;
        step_peer(d, d->peers[i], now, &remove);
        if (remove) {
            free_peer(d->peers[i]);
            d->peers[i] = d->peers[--d->n_peers];
        } else {
            i++;
        }
    }
}

uint64_t tsnet_wgdev_next(const tsnet_wgdev_t *d)
{
    uint64_t next = 0;
    for (size_t i = 0; i < d->n_peers; i++) {
        const peer_t *p = d->peers[i];
        uint64_t t[4] = {p->retransmit_at, p->keepalive_at, p->new_handshake_at, p->zero_key_at};
        for (int k = 0; k < 4; k++) {
            if (t[k] && (next == 0 || t[k] < next)) {
                next = t[k];
            }
        }
    }
    return next;
}

bool tsnet_wgdev_session(const tsnet_wgdev_t *d, const uint8_t pub[32], uint64_t *last_handshake)
{
    const peer_t *p = find_peer(d, pub);
    if (last_handshake) {
        *last_handshake = p ? p->last_handshake : 0;
    }
    return p && p->current.used;
}
