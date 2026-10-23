// Host test of WireGuard's device and peers: two devices, A and B, joined by a queue that can drop packets, on a
// fake clock. A handshake on demand and data both ways; the responder's keypair confirmed by the first data; a
// keepalive answering data; rekeying at 120 s, the old keypair still taking packets; a keypair refused past 180 s;
// retransmits every 5 s and giving up after 20 initiations; a replayed packet dropped; a lazy peer made by its
// initiation and reaped at 540 s; the staged queue's cap.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "wgdev.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

#define SEC 1000ULL

typedef struct {
    int to; // 0: A, 1: B
    uint8_t data[1600];
    size_t len;
} msg_t;

static msg_t queue[256];
static int q_head, q_tail;
static bool drop[2];          // drop everything sent to A (0) or B (1)
static int sent_types[2][5];  // what each side sent, by message type
static int delivered[2];      // IP packets delivered on each side
static uint8_t last_delivered[2][1600];
static size_t last_delivered_len[2];
static bool accept_lazy;
static uint8_t a_pub[32], b_pub[32];
static tsnet_wgdev_t *dev[2];
static uint8_t last_sent[2][1600];
static size_t last_sent_len[2];

static void on_send(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    (void)peer;
    int from = (int)(intptr_t)ctx, to = 1 - from;
    if (pkt[0] >= 1 && pkt[0] <= 4) {
        sent_types[from][pkt[0]]++;
    }
    memcpy(last_sent[from], pkt, len);
    last_sent_len[from] = len;
    if (drop[to]) {
        return;
    }
    msg_t *m = &queue[q_tail++ % 256];
    m->to = to;
    memcpy(m->data, pkt, len);
    m->len = len;
}

static void on_deliver(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    int at = (int)(intptr_t)ctx;
    EXPECT(memcmp(peer, at == 0 ? b_pub : a_pub, 32) == 0);
    delivered[at]++;
    memcpy(last_delivered[at], pkt, len);
    last_delivered_len[at] = len;
}

static bool on_lookup(void *ctx, const uint8_t peer[32])
{
    (void)ctx;
    (void)peer;
    return accept_lazy;
}

// A wall clock that moves 20 ms per reading (more than TAI64N's whitened 16.7 ms): each initiation's timestamp is
// newer than the last, as on a real clock where initiations are seconds apart.
static void on_wall(void *ctx, int64_t *secs, uint32_t *nanos)
{
    (void)ctx;
    static uint64_t ms;
    ms += 20;
    *secs = 1792719090 + (int64_t)(ms / 1000);
    *nanos = (uint32_t)(ms % 1000) * 1000000;
}

// Hands every queued message over, and the ones those make, at time `now`.
static void pump(uint64_t now)
{
    while (q_head != q_tail) {
        msg_t m = queue[q_head++ % 256];
        tsnet_wgdev_receive(dev[m.to], m.data, m.len, (const uint8_t *)"src", 3, now);
    }
}

// Steps both devices' timers from `from` to `to` (each timer at its own time), pumping as it goes.
static void advance(uint64_t from, uint64_t to)
{
    uint64_t now = from;
    for (;;) {
        uint64_t n0 = tsnet_wgdev_next(dev[0]), n1 = tsnet_wgdev_next(dev[1]), next = 0;
        if (n0 && (next == 0 || n0 < next)) {
            next = n0;
        }
        if (n1 && (next == 0 || n1 < next)) {
            next = n1;
        }
        if (next == 0 || next > to) {
            break;
        }
        now = next > now ? next : now;
        tsnet_wgdev_step(dev[0], now);
        tsnet_wgdev_step(dev[1], now);
        pump(now);
    }
}

// A minimal IPv4 packet: a 20-byte header with its total length, then the payload byte repeated.
static size_t ip4(uint8_t *out, size_t payload, uint8_t fill)
{
    memset(out, 0, 20);
    out[0] = 0x45;
    out[2] = (uint8_t)((20 + payload) >> 8);
    out[3] = (uint8_t)(20 + payload);
    memset(out + 20, fill, payload);
    return 20 + payload;
}

static void reset_world(bool lazy_b)
{
    for (int i = 0; i < 2; i++) {
        tsnet_wgdev_free(dev[i]);
        sent_types[i][1] = sent_types[i][2] = sent_types[i][3] = sent_types[i][4] = 0;
        delivered[i] = 0;
        drop[i] = false;
    }
    q_head = q_tail = 0;
    uint8_t a_priv[32], b_priv[32];
    for (int i = 0; i < 32; i++) {
        a_priv[i] = (uint8_t)(3 * i + 7);
        b_priv[i] = (uint8_t)(5 * i + 11);
    }
    tsnet_x25519_public(a_pub, a_priv);
    tsnet_x25519_public(b_pub, b_priv);
    tsnet_wgdev_cfg_t ca = {.priv = a_priv, .ctx = (void *)0, .send = on_send, .deliver = on_deliver,
                            .wall = on_wall};
    tsnet_wgdev_cfg_t cb = {.priv = b_priv, .ctx = (void *)1, .send = on_send, .deliver = on_deliver,
                            .lookup = on_lookup, .wall = on_wall};
    dev[0] = tsnet_wgdev_new(&ca);
    dev[1] = tsnet_wgdev_new(&cb);
    EXPECT(tsnet_wgdev_add_peer(dev[0], b_pub, 0) == 0);
    if (!lazy_b) {
        EXPECT(tsnet_wgdev_add_peer(dev[1], a_pub, 0) == 0);
    }
}

static void session(void)
{
    const uint64_t t0 = 1000 * SEC;
    reset_world(false);
    uint8_t pkt[1600];
    size_t n = ip4(pkt, 30, 0xaa);
    // A sends: no session yet, so the packet is staged and an initiation goes; B responds; A's keepalive is the staged
    // data itself, under the new keypair, which confirms B's.
    EXPECT(tsnet_wgdev_send(dev[0], b_pub, pkt, n, t0) == 0);
    EXPECT(sent_types[0][1] == 1 && sent_types[0][4] == 0);
    pump(t0);
    EXPECT(sent_types[1][2] == 1);
    EXPECT(delivered[1] == 1 && last_delivered_len[1] == n && last_delivered[1][20] == 0xaa);
    uint64_t hs;
    EXPECT(tsnet_wgdev_session(dev[0], b_pub, &hs) && hs == t0);
    EXPECT(tsnet_wgdev_session(dev[1], a_pub, &hs) && hs == t0); // B confirmed by the data: next became current
    // B answers at once with the current keypair: no new handshake.
    n = ip4(pkt, 5, 0xbb);
    EXPECT(tsnet_wgdev_send(dev[1], a_pub, pkt, n, t0 + 10) == 0);
    pump(t0 + 10);
    EXPECT(delivered[0] == 1 && last_delivered[0][20] == 0xbb && sent_types[1][1] == 0);
    // A replayed transport packet is dropped.
    uint8_t copy[1600];
    size_t clen = last_sent_len[1];
    memcpy(copy, last_sent[1], clen);
    tsnet_wgdev_receive(dev[0], copy, clen, NULL, 0, t0 + 20);
    EXPECT(delivered[0] == 1);
    // A got data and sent nothing back: a keepalive 10 s later (B sent data at t0 + 10).
    int before = sent_types[0][4];
    advance(t0 + 20, t0 + 10 + TSNET_WG_KEEPALIVE_MS);
    EXPECT(sent_types[0][4] == before + 1);
    EXPECT(delivered[1] == 1); // a keepalive delivers nothing

    // B seals a packet under the current keypair, held back (dropped on the way, a copy kept) until after the rekey.
    uint64_t t1 = t0 + TSNET_WG_REKEY_AFTER_MS + 1;
    drop[0] = true;
    n = ip4(pkt, 3, 0xdd);
    tsnet_wgdev_send(dev[1], a_pub, pkt, n, t1 - 1);
    uint8_t held[1600];
    size_t held_len = last_sent_len[1];
    memcpy(held, last_sent[1], held_len);
    drop[0] = false;
    // At 120 s the initiator (A) rekeys on its next send; the packet still goes under the old keypair.
    int inits = sent_types[0][1];
    n = ip4(pkt, 8, 0xcc);
    EXPECT(tsnet_wgdev_send(dev[0], b_pub, pkt, n, t1) == 0);
    EXPECT(sent_types[0][1] == inits + 1);
    pump(t1);
    EXPECT(delivered[1] == 2 && last_delivered[1][20] == 0xcc);
    EXPECT(tsnet_wgdev_session(dev[0], b_pub, &hs) && hs == t1);
    // The held packet, sealed under the old keypair, arrives after the rekey: A kept that keypair as previous.
    tsnet_wgdev_receive(dev[0], held, held_len, NULL, 0, t1 + 1);
    EXPECT(delivered[0] == 2 && last_delivered[0][20] == 0xdd);
}

static void reject_after(void)
{
    const uint64_t t0 = 1000 * SEC;
    reset_world(false);
    uint8_t pkt[1600];
    size_t n = ip4(pkt, 10, 0x11);
    tsnet_wgdev_send(dev[0], b_pub, pkt, n, t0);
    pump(t0);
    EXPECT(delivered[1] == 1);
    // B (the responder) never rekeys by time; past 180 s its keypair is unusable, so a send starts a handshake.
    int inits = sent_types[1][1];
    uint64_t late = t0 + TSNET_WG_REJECT_AFTER_MS + 1;
    tsnet_wgdev_send(dev[1], a_pub, pkt, n, late);
    EXPECT(sent_types[1][1] == inits + 1 && sent_types[1][4] == 0);
    pump(late);
    EXPECT(delivered[0] == 1); // the staged packet went once the new session was up
}

static void retransmit_and_give_up(void)
{
    const uint64_t t0 = 1000 * SEC;
    reset_world(false);
    drop[1] = true; // B never hears anything
    uint8_t pkt[1600];
    size_t n = ip4(pkt, 10, 0x22);
    tsnet_wgdev_send(dev[0], b_pub, pkt, n, t0);
    EXPECT(sent_types[0][1] == 1);
    // Retransmits every 5 s (plus jitter): expiries 1 to 19 each send one, and the 20th gives up. That's 20
    // initiations in all, the "after 20 attempts" (MaxTimerHandshakes + 2) wireguard-go logs.
    advance(t0, t0 + 200 * SEC);
    EXPECT(sent_types[0][1] == 1 + TSNET_WG_MAX_HANDSHAKES + 1);
    // Nothing staged any more: a new send starts over (handshake_attempts reset), and B, now listening, answers.
    drop[1] = false;
    uint64_t t1 = t0 + 300 * SEC;
    tsnet_wgdev_send(dev[0], b_pub, pkt, n, t1);
    pump(t1);
    EXPECT(delivered[1] == 1); // only the new packet: the first was dropped with the staged queue
}

static void lazy_peer(void)
{
    const uint64_t t0 = 1000 * SEC;
    reset_world(true); // B has no peer for A
    uint8_t pkt[1600];
    size_t n = ip4(pkt, 10, 0x33);
    // B refuses an unknown key...
    accept_lazy = false;
    tsnet_wgdev_send(dev[0], b_pub, pkt, n, t0);
    pump(t0);
    EXPECT(!tsnet_wgdev_has_peer(dev[1], a_pub) && sent_types[1][2] == 0);
    // ...until its lookup says yes: then the peer is made, and the session runs.
    accept_lazy = true;
    uint64_t t1 = t0 + TSNET_WG_REKEY_TIMEOUT_MS + 1000;
    advance(t0, t1); // A's retransmit
    EXPECT(tsnet_wgdev_has_peer(dev[1], a_pub) && delivered[1] == 1);
    // Idle for 540 s after the session: its keys are zeroed and, being lazy, it goes. A's peer (not lazy) stays.
    advance(t1, t1 + 3 * TSNET_WG_REJECT_AFTER_MS + 2 * SEC);
    EXPECT(!tsnet_wgdev_has_peer(dev[1], a_pub));
    EXPECT(tsnet_wgdev_has_peer(dev[0], b_pub) && !tsnet_wgdev_session(dev[0], b_pub, NULL));
}

static void staged_cap(void)
{
    const uint64_t t0 = 1000 * SEC;
    reset_world(false);
    drop[1] = true;
    uint8_t pkt[1600];
    for (int i = 0; i < TSNET_WG_STAGED + 4; i++) {
        size_t n = ip4(pkt, 4, (uint8_t)i);
        tsnet_wgdev_send(dev[0], b_pub, pkt, n, t0 + (uint64_t)i);
    }
    EXPECT(sent_types[0][1] == 1); // one initiation for them all (5 s apart at most)
    drop[1] = false;
    uint64_t t1 = t0 + TSNET_WG_REKEY_TIMEOUT_MS + TSNET_WG_REKEY_JITTER_MS;
    advance(t0, t1);
    // The oldest four went: the rest arrive, in order, the first being packet 4.
    EXPECT(delivered[1] == TSNET_WG_STAGED && last_delivered[1][20] == TSNET_WG_STAGED + 3);
    // Bad input: no such peer, an empty or an oversized packet.
    uint8_t other[32] = {9};
    EXPECT(tsnet_wgdev_send(dev[0], other, pkt, 24, t1) == -1);
    EXPECT(tsnet_wgdev_send(dev[0], b_pub, pkt, 0, t1) == -1);
    EXPECT(tsnet_wgdev_send(dev[0], b_pub, pkt, TSNET_WG_MAX_PACKET + 1, t1) == -1);
}

// Both sides initiate at once: the handshakes cross, and still a session comes up and data flows both ways.
static void crossing(void)
{
    const uint64_t t0 = 1000 * SEC;
    reset_world(false);
    uint8_t pkt[1600];
    size_t n = ip4(pkt, 6, 0x44);
    tsnet_wgdev_send(dev[0], b_pub, pkt, n, t0);
    tsnet_wgdev_send(dev[1], a_pub, pkt, n, t0);
    pump(t0);
    advance(t0, t0 + 30 * SEC);
    EXPECT(delivered[0] >= 1 && delivered[1] >= 1);
    EXPECT(tsnet_wgdev_session(dev[0], b_pub, NULL) && tsnet_wgdev_session(dev[1], a_pub, NULL));
}

// Brings a session up at t0, A the initiator, and lets B's keepalive answer A's data at t0 + 10 s, which cancels A's
// new-handshake timer: a quiet, settled session by t0 + 11 s.
static void up(uint64_t t0)
{
    uint8_t pkt[1600];
    size_t n = ip4(pkt, 4, 0x01);
    tsnet_wgdev_send(dev[0], b_pub, pkt, n, t0);
    pump(t0);
    advance(t0, t0 + TSNET_WG_KEEPALIVE_MS + SEC);
    EXPECT(tsnet_wgdev_session(dev[0], b_pub, NULL) && tsnet_wgdev_session(dev[1], a_pub, NULL));
    EXPECT(tsnet_wgdev_next(dev[0]) == 0 || tsnet_wgdev_next(dev[0]) > t0 + 60 * SEC); // only the zero-key timer
}

// timersDataSent: A's data goes unanswered (B's packets to A dropped), so 15 s later (and some jitter) A initiates.
static void new_handshake(void)
{
    const uint64_t t0 = 1000 * SEC;
    reset_world(false);
    up(t0);
    drop[0] = true;
    uint8_t pkt[1600];
    size_t n = ip4(pkt, 4, 0x02);
    uint64_t t1 = t0 + 60 * SEC;
    tsnet_wgdev_send(dev[0], b_pub, pkt, n, t1);
    int inits = sent_types[0][1];
    advance(t1, t1 + TSNET_WG_KEEPALIVE_MS + TSNET_WG_REKEY_TIMEOUT_MS - 1);
    EXPECT(sent_types[0][1] == inits);
    advance(t1, t1 + TSNET_WG_KEEPALIVE_MS + TSNET_WG_REKEY_TIMEOUT_MS + TSNET_WG_REKEY_JITTER_MS);
    EXPECT(sent_types[0][1] == inits + 1);
}

// keepKeyFreshReceiving: A (the initiator) sends nothing; data from B arriving 166 s into the keypair makes A
// initiate, once: a packet a second later doesn't start another.
static void rekey_on_receive(void)
{
    const uint64_t t0 = 1000 * SEC;
    reset_world(false);
    up(t0);
    drop[1] = true; // A's initiation doesn't reach B: the handshake stays open
    uint8_t pkt[1600];
    size_t n = ip4(pkt, 4, 0x03);
    int inits = sent_types[0][1];
    uint64_t late = t0 + TSNET_WG_REJECT_AFTER_MS - TSNET_WG_KEEPALIVE_MS - TSNET_WG_REKEY_TIMEOUT_MS + SEC;
    tsnet_wgdev_send(dev[1], a_pub, pkt, n, late); // B's keypair is still usable at 166 s
    pump(late);
    EXPECT(delivered[0] == 1 && sent_types[0][1] == inits + 1);
    tsnet_wgdev_send(dev[1], a_pub, pkt, n, late + SEC);
    pump(late + SEC);
    EXPECT(delivered[0] == 2 && sent_types[0][1] == inits + 1);
    // Before 165 s no such initiation: a fresh session, data at 100 s.
    reset_world(false);
    up(t0);
    inits = sent_types[0][1];
    tsnet_wgdev_send(dev[1], a_pub, pkt, n, t0 + 100 * SEC);
    pump(t0 + 100 * SEC);
    EXPECT(sent_types[0][1] == inits);
}

// ScheduleHandshakeOnUserSend: ignored with no key material; with a session, the next send is followed by an initiation.
static void handshake_on_send(void)
{
    const uint64_t t0 = 1000 * SEC;
    reset_world(false);
    tsnet_wgdev_handshake_on_send(dev[0], b_pub); // no key material yet: ignored
    up(t0);
    uint8_t pkt[1600];
    size_t n = ip4(pkt, 4, 0x04);
    int inits = sent_types[0][1];
    tsnet_wgdev_send(dev[0], b_pub, pkt, n, t0 + 20 * SEC);
    pump(t0 + 20 * SEC);
    EXPECT(sent_types[0][1] == inits); // the ignored request left nothing armed
    tsnet_wgdev_handshake_on_send(dev[0], b_pub);
    tsnet_wgdev_send(dev[0], b_pub, pkt, n, t0 + 30 * SEC);
    EXPECT(sent_types[0][1] == inits + 1 && sent_types[0][4] >= 2);
}

int main(void)
{
    session();
    new_handshake();
    rekey_on_receive();
    handshake_on_send();
    reject_after();
    retransmit_and_give_up();
    lazy_peer();
    staged_cap();
    crossing();
    tsnet_wgdev_free(dev[0]);
    tsnet_wgdev_free(dev[1]);
    if (failures == 0) {
        printf("tsnet wgdev_test: ok\n");
    }
    return failures != 0;
}
