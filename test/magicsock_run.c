// Runs a tailnet node (server.h) for the harness's scenarios, the same code the device runs. Built by test.sh:
//
//   TSNET_STATE_DIR=<dir> [TSNET_HOSTNAME=<name>] [TS_DEBUG_USE_DERP_HTTP=1] [TSNET_DROP_STUN=1]
//       magicsock_run <server URL> <seconds> [auth key]
//
// The node registers, magicsock runs netcheck and sets the DERP home from it. TSNET_DROP_STUN=1 drops every STUN
// packet netcheck sends, as a network that blocks UDP would.
// TSNET_PING=<hostname> disco-pings that peer every 2 s (tsnet_magicsock_ping, "tailscale ping") and prints each
// answer's path (a DERP region, or a UDP port: never an address) and latency.
// WireGuard runs over magicsock with the node key. TSNET_ICMP=<hostname> sends that peer an ICMP echo request
// every 2 s, from this node's tailnet IPv4 address to the peer's, through the tunnel; each ICMP echo that comes back
// through it (a reply, or a request the peer started) is printed.
// Behind the tunnel runs lwIP (tun.h) on the node's tailnet address: it answers ICMP echo requests, and serves
// TCP echo on port 7, printing what each connection sends. The netmap's packet filter decides what reaches it.
// magicsock and netcheck log what they do; this prints each NetInfo. It exits 0 when the home is connected at the end.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lwip/init.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "server.h"

static tsnet_server_t *srv;

// TSNET_ICMP: the peer to send ICMP echoes to, and the two tailnet IPv4 addresses.
static const char *icmp_host;
static uint8_t icmp_key[TSNET_KEY_LEN], self_ip4[4], peer_ip4[4];
static bool have_icmp;
static uint16_t icmp_seq;

static uint16_t checksum(const uint8_t *p, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (uint32_t)p[i] << 8 | p[i + 1];
    }
    if (len & 1) {
        sum += (uint32_t)p[len - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

// An IPv4 ICMP echo request (RFC 792): a 20-byte header, then type 8, code 0, identifier "ts", the sequence, 32 bytes.
static size_t icmp_echo(uint8_t *out, uint16_t seq)
{
    const size_t total = 20 + 8 + 32;
    memset(out, 0, total);
    out[0] = 0x45;
    out[2] = 0;
    out[3] = (uint8_t)total;
    out[8] = 64; // TTL
    out[9] = 1;  // ICMP
    memcpy(out + 12, self_ip4, 4);
    memcpy(out + 16, peer_ip4, 4);
    uint16_t c = checksum(out, 20);
    out[10] = (uint8_t)(c >> 8);
    out[11] = (uint8_t)c;
    uint8_t *icmp = out + 20;
    icmp[0] = 8;
    icmp[4] = 't';
    icmp[5] = 's';
    icmp[6] = (uint8_t)(seq >> 8);
    icmp[7] = (uint8_t)seq;
    memset(icmp + 8, 0x5a, 32);
    c = checksum(icmp, 8 + 32);
    icmp[2] = (uint8_t)(c >> 8);
    icmp[3] = (uint8_t)c;
    return total;
}

// A packet out of the tunnel: an ICMP echo (reply or request) is printed, with the peer's tailnet address.
static void on_deliver(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len)
{
    (void)ctx;
    (void)peer;
    if (len >= 28 && pkt[0] >> 4 == 4 && pkt[9] == 1) {
        size_t ihl = (size_t)(pkt[0] & 0xf) * 4;
        const uint8_t *icmp = pkt + ihl;
        if (len >= ihl + 8 && (icmp[0] == 0 || icmp[0] == 8)) {
            printf("magicsock_run: icmp echo %s from %u.%u.%u.%u seq %u\n", icmp[0] == 0 ? "reply" : "request", pkt[12],
                   pkt[13], pkt[14], pkt[15], (unsigned)(icmp[6] << 8 | icmp[7]));
            fflush(stdout);
        }
    }
}

// TCP echo on port 7: each connection's bytes go back, and their count is printed.
static err_t echo_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    (void)arg;
    (void)err;
    if (!p) {
        tcp_close(pcb); // the other side closed
        return ERR_OK;
    }
    printf("magicsock_run: tcp echo: %u bytes\n", (unsigned)p->tot_len);
    fflush(stdout);
    for (struct pbuf *q = p; q; q = q->next) {
        tcp_write(pcb, q->payload, q->len, TCP_WRITE_FLAG_COPY);
    }
    tcp_output(pcb);
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t echo_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
    (void)arg;
    if (err != ERR_OK || !pcb) {
        return ERR_VAL;
    }
    printf("magicsock_run: tcp echo: connection\n");
    fflush(stdout);
    tcp_recv(pcb, echo_recv);
    return ERR_OK;
}

// The node's first IPv4 address, from its netmap addresses. False if it has none.
static bool first_ip4(const tsnet_node_t *n, uint8_t out[4])
{
    for (size_t i = 0; i < n->n_addresses; i++) {
        if (!n->addresses[i].ip.is6) {
            memcpy(out, n->addresses[i].ip.ip, 4);
            return true;
        }
    }
    return false;
}

static void on_netinfo(void *ctx, const tsnet_net_info_t *ni)
{
    (void)ctx;
    printf("magicsock_run: NetInfo derp=%d udp=%d\n", ni->preferred_derp, ni->working_udp);
    fflush(stdout);
}

// TSNET_PING: the peer to ping, by hostname, once the netmap has it.
static const char *ping_host;
static uint8_t ping_key[TSNET_KEY_LEN];
static bool have_ping_key;

static void on_ping(void *ctx, const uint8_t key[TSNET_KEY_LEN], const tsnet_ping_result_t *res, int region)
{
    (void)ctx;
    (void)key;
    // The path, not the address: a direct one is this network's.
    if (res->via_derp) {
        printf("magicsock_run: pong from %s via derp-%d in %.1f ms\n", ping_host, region, res->latency_us / 1000.0);
    } else {
        printf("magicsock_run: pong from %s via udp port %u in %.1f ms\n", ping_host, (unsigned)res->port,
               res->latency_us / 1000.0);
    }
    fflush(stdout);
}

static void on_endpoints(void *ctx, size_t n)
{
    (void)ctx;
    printf("magicsock_run: %zu endpoints\n", n); // the count only: the addresses are this machine's
    fflush(stdout);
}

static bool drop_stun(void *ctx)
{
    (void)ctx;
    return false;
}

static void on_netmap(void *ctx, const tsnet_netmap_t *nm, int changed)
{
    (void)ctx;
    (void)changed;
    if (nm->has_node) {
        char *rules = tsnet_netmap_filter_rules_json(nm);
        printf("magicsock_run: packet filter: %zu bytes of rules\n", rules ? strlen(rules) : 0);
        fflush(stdout);
        free(rules);
    }
    have_icmp = false;
    const tsnet_node_t *p = icmp_host && nm->has_node ? tsnet_netmap_peer_by_name(nm, icmp_host) : NULL;
    if (p && first_ip4(p, peer_ip4) && first_ip4(&nm->node, self_ip4)) {
        memcpy(icmp_key, p->key, TSNET_KEY_LEN);
        have_icmp = true;
    }
    p = ping_host ? tsnet_netmap_peer_by_name(nm, ping_host) : NULL;
    have_ping_key = p != NULL;
    if (p) {
        memcpy(ping_key, p->key, TSNET_KEY_LEN);
    }
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: TSNET_STATE_DIR=<dir> magicsock_run <server URL> <seconds> [auth key]\n");
        return 2;
    }
    // lwIP behind the tunnel (NO_SYS: this loop drives its timers), with TCP echo on port 7.
    lwip_init();
    const char *http = getenv("TS_DEBUG_USE_DERP_HTTP"), *drop = getenv("TSNET_DROP_STUN");
    tsnet_server_cfg_t cfg = {
        .client =
            {
                .server_url = argv[1],
                .auth_key = argc > 3 ? argv[3] : NULL,
                .hostname = getenv("TSNET_HOSTNAME") ? getenv("TSNET_HOSTNAME") : "tsnet-magicsock",
                .ipn_version = "tsnet-dev",
                .os = "linux",
                .os_version = "tsnet",
                .machine = "esp32p4",
            },
        .use_derp_http = http && strcmp(http, "1") == 0,
        .stun_filter = drop && strcmp(drop, "1") == 0 ? drop_stun : NULL,
        .input = ip_input,
        .on_netmap = on_netmap,
        .on_netinfo = on_netinfo,
        .on_endpoints = on_endpoints,
        .on_ping = on_ping,
        .on_deliver = on_deliver,
    };
    srv = tsnet_server_new(&cfg);
    struct tcp_pcb *listener = tcp_new();
    if (!srv || !listener || tcp_bind(listener, IP_ADDR_ANY, 7) != ERR_OK) {
        fprintf(stderr, "magicsock_run: can't start the node\n");
        return 2;
    }
    listener = tcp_listen(listener);
    tcp_accept(listener, echo_accept);
    ping_host = getenv("TSNET_PING");
    icmp_host = getenv("TSNET_ICMP");
    uint64_t next_ping = 0, next_icmp = 0;
    uint64_t end = tsnet_now_ms() + (uint64_t)atoi(argv[2]) * 1000;
    while (tsnet_now_ms() < end) {
        tsnet_poll_t p[TSNET_SERVER_POLL_MAX];
        int wait = have_ping_key || have_icmp ? 200 : 1000;
        int n = tsnet_server_poll(srv, p, TSNET_SERVER_POLL_MAX, &wait);
        u32_t lwip_wait = sys_timeouts_sleeptime();
        if (lwip_wait != SYS_TIMEOUTS_SLEEPTIME_INFINITE && (wait < 0 || (int)lwip_wait < wait)) {
            wait = (int)lwip_wait;
        }
        tsnet_poll(p, n, wait < 0 ? 1000 : wait);
        tsnet_server_step(srv);
        sys_check_timeouts();
        tsnet_wgdev_t *wg = tsnet_server_wgdev(srv);
        if (wg && have_icmp && tsnet_now_ms() >= next_icmp) {
            next_icmp = tsnet_now_ms() + 2000;
            uint8_t pkt[64];
            size_t len = icmp_echo(pkt, ++icmp_seq);
            if (tsnet_wgdev_send(wg, icmp_key, pkt, len, tsnet_now_ms()) == 0) {
                printf("magicsock_run: icmp echo request to %s seq %u\n", icmp_host, (unsigned)icmp_seq);
                fflush(stdout);
            }
        }
        tsnet_magicsock_t *ms = tsnet_server_magicsock(srv);
        if (ms && have_ping_key && tsnet_now_ms() >= next_ping) {
            next_ping = tsnet_now_ms() + 2000;
            if (tsnet_magicsock_ping(ms, ping_key) != 0) {
                printf("magicsock_run: can't ping %s\n", ping_host);
            }
        }
    }
    tsnet_magicsock_t *ms = tsnet_server_magicsock(srv);
    int home = ms ? tsnet_derpmgr_home(tsnet_magicsock_derp(ms)) : 0;
    bool up = ms && home && tsnet_derpmgr_connected(tsnet_magicsock_derp(ms), home);
    const tsnet_netcheck_report_t *r = ms ? tsnet_magicsock_report(ms) : NULL;
    printf("magicsock_run: done: home derp-%d connected %d, last report udp %d with %zu latencies\n", home, up,
           r ? r->udp : 0, r ? r->base.n_lat : 0);
    tsnet_server_free(srv);
    return up ? 0 : 1;
}
