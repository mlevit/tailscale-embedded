// Host test of the tunnel's IP side: node A runs ESP-IDF's lwIP (NO_SYS) behind its tun, node B is a bare
// wgdev that builds IPv4 packets by hand; their WireGuard messages pass through a queue. B's ICMP echo request to A's
// tailnet address gets lwIP's reply, routed back to B by AllowedIPs; a UDP datagram to A's echo service comes back; a
// packet whose source isn't B's is dropped (AllowedPeerSourceIP); a packet lwIP sends to an address no peer has goes
// nowhere; and lwIP's output wakes the loop through the tun's fd. The packet filter lets nothing in
// before its first rules, and refuses a SYN its rules don't allow with a TSMP reject. (lwIP keeps one stack a process,
// so only A has one.)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "lwip/init.h"
#include "lwip/timeouts.h"
#include "lwip/udp.h"
#include "platform.h"
#include "tun.h"
#include "wgdev.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static const uint8_t A_IP[4] = {100, 64, 0, 1}, B_IP[4] = {100, 64, 0, 2};
static uint8_t a_pub[32], b_pub[32];
static tsnet_wgdev_t *wa, *wb;
static tsnet_tun_t *tun;

typedef struct {
    int to; // 0: A, 1: B
    uint8_t data[1600];
    size_t len;
} msg_t;
static msg_t q[64];
static int qh, qt;
static int b_got;
static uint8_t b_last[1600];
static size_t b_last_len;

static void wg_send(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    (void)peer;
    msg_t *m = &q[qt++ % 64];
    m->to = ctx == (void *)0 ? 1 : 0;
    memcpy(m->data, pkt, len);
    m->len = len;
}

static void a_deliver(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    (void)ctx;
    tsnet_tun_deliver(tun, peer, pkt, len);
}

static void b_deliver(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    (void)ctx;
    (void)peer;
    b_got++;
    memcpy(b_last, pkt, len);
    b_last_len = len;
}

static void tun_send(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    (void)ctx;
    tsnet_wgdev_send(wa, peer, pkt, len, tsnet_now_ms());
}

static bool readable(int fd)
{
    tsnet_poll_t p = {.fd = fd};
    return tsnet_poll(&p, 1, 0) == 1 && p.readable;
}

// Runs everything until nothing moves.
static void pump(void)
{
    for (int rounds = 0; rounds < 100; rounds++) {
        bool moved = false;
        while (qh != qt) {
            msg_t m = q[qh++ % 64];
            tsnet_wgdev_receive(m.to == 0 ? wa : wb, m.data, m.len, NULL, 0, tsnet_now_ms());
            moved = true;
        }
        if (tsnet_tun_pending(tun) || readable(tsnet_tun_fd(tun))) {
            tsnet_tun_step(tun);
            moved = true;
        }
        sys_check_timeouts();
        if (!moved) {
            return;
        }
    }
}

static uint16_t csum(const uint8_t *p, size_t len)
{
    uint32_t s = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        s += (uint32_t)p[i] << 8 | p[i + 1];
    }
    if (len & 1) {
        s += (uint32_t)p[len - 1] << 8;
    }
    while (s >> 16) {
        s = (s & 0xffff) + (s >> 16);
    }
    return (uint16_t)~s;
}

// An IPv4 header from src to A, protocol `proto`, carrying `payload` bytes after it.
static void ip4_header(uint8_t *p, const uint8_t src[4], uint8_t proto, size_t payload)
{
    memset(p, 0, 20);
    p[0] = 0x45;
    p[2] = (uint8_t)((20 + payload) >> 8);
    p[3] = (uint8_t)(20 + payload);
    p[8] = 64;
    p[9] = proto;
    memcpy(p + 12, src, 4);
    memcpy(p + 16, A_IP, 4);
    uint16_t c = csum(p, 20);
    p[10] = (uint8_t)(c >> 8);
    p[11] = (uint8_t)c;
}

static size_t icmp_echo(uint8_t *p, const uint8_t src[4], uint16_t seq)
{
    ip4_header(p, src, 1, 8 + 16);
    uint8_t *i = p + 20;
    memset(i, 0, 8 + 16);
    i[0] = 8;
    i[6] = (uint8_t)(seq >> 8);
    i[7] = (uint8_t)seq;
    memset(i + 8, 0x42, 16);
    uint16_t c = csum(i, 8 + 16);
    i[2] = (uint8_t)(c >> 8);
    i[3] = (uint8_t)c;
    return 20 + 8 + 16;
}

static size_t udp_dgram(uint8_t *p, const uint8_t src[4], uint16_t port, const char *text)
{
    size_t n = strlen(text);
    ip4_header(p, src, 17, 8 + n);
    uint8_t *u = p + 20;
    u[0] = 0x30, u[1] = 0x39; // from port 12345
    u[2] = (uint8_t)(port >> 8), u[3] = (uint8_t)port;
    u[4] = (uint8_t)((8 + n) >> 8), u[5] = (uint8_t)(8 + n);
    u[6] = u[7] = 0; // no checksum (allowed over IPv4)
    memcpy(u + 8, text, n);
    return 20 + 8 + n;
}

// A's UDP echo service on port 7.
static int echo_calls, echo_err;
static void echo(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
    (void)arg;
    echo_calls++;
    echo_err = udp_sendto(pcb, p, addr, port);
    pbuf_free(p);
}

int main(void)
{
    lwip_init();
    uint8_t a_priv[32], b_priv[32];
    for (int i = 0; i < 32; i++) {
        a_priv[i] = (uint8_t)(i * 7 + 1);
        b_priv[i] = (uint8_t)(i * 11 + 3);
    }
    tsnet_x25519_public(a_pub, a_priv);
    tsnet_x25519_public(b_pub, b_priv);
    tsnet_wgdev_cfg_t ca = {.priv = a_priv, .ctx = (void *)0, .send = wg_send, .deliver = a_deliver};
    tsnet_wgdev_cfg_t cb = {.priv = b_priv, .ctx = (void *)1, .send = wg_send, .deliver = b_deliver};
    wa = tsnet_wgdev_new(&ca);
    wb = tsnet_wgdev_new(&cb);
    tsnet_wgdev_add_peer(wa, b_pub, tsnet_now_ms());
    tsnet_wgdev_add_peer(wb, a_pub, tsnet_now_ms());
    tsnet_tun_cfg_t tc = {.send = tun_send, .input = ip_input};
    tun = tsnet_tun_new(&tc);
    EXPECT(tun && tsnet_tun_set_addr(tun, A_IP) == 0);
    tsnet_prefix_t b_route = {.ip = {.ip = {100, 64, 0, 2}}, .bits = 32};
    EXPECT(tsnet_tun_set_routes(tun, b_pub, &b_route, 1) == 0);
    struct udp_pcb *pcb = udp_new();
    udp_bind(pcb, IP_ADDR_ANY, 7);
    udp_recv(pcb, echo, NULL);

    // Before the first rules, the filter lets nothing in: the handshake runs, the request doesn't reach lwIP.
    uint8_t pkt[256];
    size_t n = icmp_echo(pkt, B_IP, 1);
    EXPECT(tsnet_wgdev_send(wb, a_pub, pkt, n, tsnet_now_ms()) == 0);
    pump();
    EXPECT(b_got == 0);
    // headscale's allow-all policy.
    tsnet_prefix_t a_local = {.ip = {.ip = {100, 64, 0, 1}}, .bits = 32};
    EXPECT(tsnet_tun_set_filter(tun, "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,"
                                     "\"Last\":65535}}]}]", &a_local, 1) == 0);

    // B pings A: the request in, lwIP's reply out through AllowedIPs to B.
    EXPECT(tsnet_wgdev_send(wb, a_pub, pkt, n, tsnet_now_ms()) == 0);
    pump();
    EXPECT(b_got == 1 && b_last_len == n && b_last[9] == 1 && b_last[20] == 0); // an ICMP echo reply
    EXPECT(memcmp(b_last + 12, A_IP, 4) == 0 && memcmp(b_last + 16, B_IP, 4) == 0 && b_last[27] == 1); // seq 1

    // UDP to A's echo service comes back.
    n = udp_dgram(pkt, B_IP, 7, "tsnet");
    tsnet_wgdev_send(wb, a_pub, pkt, n, tsnet_now_ms());
    pump();
    EXPECT(echo_calls == 1 && echo_err == ERR_OK); // routed by subnet to the tun's netif
    EXPECT(b_got == 2 && b_last[9] == 17 && b_last_len == n && memcmp(b_last + 28, "tsnet", 5) == 0);

    // A source that isn't B's (B's AllowedIPs is 100.64.0.2/32) is dropped before lwIP sees it.
    const uint8_t spoof[4] = {100, 64, 0, 9};
    n = icmp_echo(pkt, spoof, 2);
    tsnet_wgdev_send(wb, a_pub, pkt, n, tsnet_now_ms());
    pump();
    EXPECT(b_got == 2);

    // lwIP sends to an address no peer has: tun drops it, nothing reaches WireGuard.
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, 4, PBUF_RAM);
    pbuf_take(p, "lost", 4);
    ip_addr_t nobody;
    IP_ADDR4(&nobody, 100, 64, 0, 77);
    int before = qt;
    udp_sendto(pcb, p, &nobody, 9);
    pbuf_free(p);
    pump();
    EXPECT(qt == before && b_got == 2);

    // The wake-up: lwIP's output makes the tun's fd readable; step sends the packet and clears it; the next
    // output signals again.
    EXPECT(!readable(tsnet_tun_fd(tun)));
    for (int i = 0; i < 2; i++) {
        p = pbuf_alloc(PBUF_TRANSPORT, 4, PBUF_RAM);
        pbuf_take(p, "wake", 4);
        ip_addr_t b;
        IP_ADDR4(&b, 100, 64, 0, 2);
        udp_sendto(pcb, p, &b, 9);
        pbuf_free(p);
        EXPECT(readable(tsnet_tun_fd(tun)) && !tsnet_tun_pending(tun));
        tsnet_tun_step(tun);
        EXPECT(!readable(tsnet_tun_fd(tun)));
        pump();
        EXPECT(b_got == 3 + i && b_last[9] == 17 && memcmp(b_last + 28, "wake", 4) == 0);
    }

    // A policy that opens only UDP port 7 to B. B's TCP SYN to port 80 is refused before lwIP, and B gets a TSMP
    // reject ('!', TCP, 'A' for the ACLs). ICMP still passes (any open port opens it), and so does UDP to port 7.
    EXPECT(tsnet_tun_set_filter(tun, "[{\"SrcIPs\":[\"100.64.0.2\"],\"IPProto\":[17],\"DstPorts\":[{\"IP\":"
                                     "\"100.64.0.1\",\"Ports\":{\"First\":7,\"Last\":7}}]}]", &a_local, 1) == 0);
    ip4_header(pkt, B_IP, 6, 20);
    memset(pkt + 20, 0, 20);
    pkt[22] = 0, pkt[23] = 80;
    pkt[32] = 0x50, pkt[33] = 0x02; // SYN
    tsnet_wgdev_send(wb, a_pub, pkt, 40, tsnet_now_ms());
    pump();
    EXPECT(b_got == 5 && b_last_len == TSNET_TSMP_REJECT_LEN && b_last[9] == 99);
    EXPECT(b_last[20] == '!' && b_last[21] == 6 && b_last[22] == 'A' && b_last[25] == 0 && b_last[26] == 80);
    n = icmp_echo(pkt, B_IP, 3);
    tsnet_wgdev_send(wb, a_pub, pkt, n, tsnet_now_ms());
    pump();
    EXPECT(b_got == 6 && b_last[9] == 1);
    n = udp_dgram(pkt, B_IP, 7, "open");
    tsnet_wgdev_send(wb, a_pub, pkt, n, tsnet_now_ms());
    pump();
    EXPECT(b_got == 7 && b_last[9] == 17 && memcmp(b_last + 28, "open", 4) == 0);
    // A TSMP ping gets its pong whatever the rules say, and never reaches lwIP.
    ip4_header(pkt, B_IP, 99, 9);
    memcpy(pkt + 20, "p12345678", 9);
    tsnet_wgdev_send(wb, a_pub, pkt, 29, tsnet_now_ms());
    pump();
    EXPECT(b_got == 8 && b_last_len == TSNET_TSMP_PONG_LEN && b_last[9] == 99 && b_last[20] == 'o');
    EXPECT(memcmp(b_last + 21, "12345678", 8) == 0);

    // A jailed peer (IsJailed) gets the shields-up filter even with everything open: its UDP to port 7 doesn't reach
    // lwIP, and its SYN gets a reject with reason 'S'. Released, it gets through again.
    EXPECT(tsnet_tun_set_filter(tun, "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,"
                                     "\"Last\":65535}}]}]", &a_local, 1) == 0);
    EXPECT(tsnet_tun_set_jailed(tun, b_pub, true) == 0);
    n = udp_dgram(pkt, B_IP, 7, "jail");
    tsnet_wgdev_send(wb, a_pub, pkt, n, tsnet_now_ms());
    pump();
    EXPECT(b_got == 8);
    ip4_header(pkt, B_IP, 6, 20);
    memset(pkt + 20, 0, 20);
    pkt[23] = 80, pkt[32] = 0x50, pkt[33] = 0x02;
    tsnet_wgdev_send(wb, a_pub, pkt, 40, tsnet_now_ms());
    pump();
    EXPECT(b_got == 9 && b_last[9] == 99 && b_last[20] == '!' && b_last[22] == 'S');
    EXPECT(tsnet_tun_set_jailed(tun, b_pub, false) == 0);
    n = udp_dgram(pkt, B_IP, 7, "free");
    tsnet_wgdev_send(wb, a_pub, pkt, n, tsnet_now_ms());
    pump();
    EXPECT(b_got == 10 && memcmp(b_last + 28, "free", 4) == 0);

    udp_remove(pcb);
    tsnet_tun_free(tun);
    tsnet_wgdev_free(wa);
    tsnet_wgdev_free(wb);
    if (failures == 0) {
        printf("tsnet tun_test: ok\n");
    }
    return failures != 0;
}
