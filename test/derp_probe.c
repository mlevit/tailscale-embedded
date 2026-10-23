// The live check of derphttp's TLS against a real DERP server: `derp_probe <host> [port]` connects to one node
// over TLS with the certificate and host name checked (net/tlsdial's rules), sends GET /derp and the handshake with a
// throwaway node key, and exits 0 once the server's greeting is in. A server that verifies clients (derpserver's
// verifyClient) then closes on an unknown key without ServerInfo, so ServerInfo is reported, not required. A host with
// a bad certificate fails at TLS (exit 1). `derp_probe <host> latency` is netcheck's HTTPS latency check instead, and
// `derp_probe <host> stun` one STUN request to the node's port 3478. Run by test.sh with TSNET_LIVE=1.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "derphttp.h"
#include "stun.h"

static bool info;
static void on_msg(void *ctx, const tsnet_derp_msg_t *m)
{
    (void)ctx;
    if (m->type == TSNET_DERP_SERVER_INFO) {
        info = true;
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: derp_probe <host> [port | latency]\n");
        return 2;
    }
    tsnet_derp_node_t node;
    memset(&node, 0, sizeof node);
    snprintf(node.name, sizeof node.name, "probe");
    snprintf(node.host_name, sizeof node.host_name, "%s", argv[1]);
    bool latency = argc > 2 && strcmp(argv[2], "latency") == 0;
    if (argc > 2 && strcmp(argv[2], "stun") == 0) {
        // One STUN binding request to the node's STUN port (3478); the mapped address isn't printed (it's ours).
        uint8_t ip[16], tx[TSNET_STUN_TXID_LEN], req[TSNET_STUN_REQUEST_LEN], buf[512], from[16], got[12], mapped[16];
        uint16_t from_port, port;
        int fd = tsnet_resolve4(argv[1], ip) == 0 ? tsnet_udp_open(0) : -1;
        if (fd < 0) {
            printf("derp_probe: %s: STUN FAILED (resolve or socket)\n", argv[1]);
            return 1;
        }
        tsnet_random(tx, sizeof tx);
        tsnet_stun_request(req, tx);
        uint64_t t0 = tsnet_now_us();
        tsnet_udp_send(fd, ip, 3478, req, sizeof req);
        tsnet_poll_t p = {.fd = fd};
        int n = tsnet_poll(&p, 1, 3000) == 1 ? tsnet_udp_recv(fd, buf, sizeof buf, from, &from_port) : 0;
        bool ok = n > 0 && tsnet_stun_parse_response(buf, (size_t)n, got, mapped, &port) == 0 && memcmp(got, tx, 12) == 0;
        uint64_t us = tsnet_now_us() - t0;
        printf("derp_probe: %s: STUN %s (%llu.%03llu ms)\n", argv[1], ok ? "ok" : "FAILED",
               (unsigned long long)(us / 1000), (unsigned long long)(us % 1000));
        tsnet_sock_close(fd);
        return ok ? 0 : 1;
    }
    node.derp_port = argc > 2 && !latency ? atoi(argv[2]) : 0;
    tsnet_derp_region_t reg = {.region_id = 1, .nodes = &node, .n_nodes = 1};
    if (latency) {
        // netcheck's HTTPS fallback (measureHTTPSLatency): verified TLS, GET /derp/latency-check, a 2xx.
        tsnet_derphttp_cfg_t lc = {.region = &reg, .latency_check = true};
        tsnet_derphttp_t *c = tsnet_derphttp_connect(&lc);
        uint64_t end = tsnet_now_ms() + 10000;
        while (c && tsnet_now_ms() < end && tsnet_derphttp_state(c) == TSNET_DERPHTTP_CONNECTING) {
            tsnet_poll_t p;
            int wait;
            int n = tsnet_derphttp_poll(c, &p, &wait);
            tsnet_poll(&p, n, wait < 0 || wait > 200 ? 200 : wait);
            tsnet_derphttp_step(c);
        }
        uint32_t us = c ? tsnet_derphttp_latency_us(c) : 0;
        printf("derp_probe: %s: latency check %s (%u.%03u ms)\n", argv[1], us ? "ok" : "FAILED", us / 1000, us % 1000);
        tsnet_derphttp_free(c);
        return us ? 0 : 1;
    }
    uint8_t priv[TSNET_KEY_LEN];
    tsnet_random(priv, sizeof priv);
    tsnet_derphttp_cfg_t cfg = {.region = &reg, .node_priv = priv, .on_msg = on_msg};
    tsnet_derphttp_t *c = tsnet_derphttp_connect(&cfg);
    if (!c) {
        printf("derp_probe: %s: FAIL, can't start\n", argv[1]);
        return 1;
    }
    bool up = false;
    uint64_t end = tsnet_now_ms() + 15000;
    while (tsnet_now_ms() < end && tsnet_derphttp_state(c) != TSNET_DERPHTTP_FAILED && !info) {
        tsnet_poll_t p;
        int wait;
        int n = tsnet_derphttp_poll(c, &p, &wait);
        tsnet_poll(&p, n, wait < 0 || wait > 200 ? 200 : wait);
        tsnet_derphttp_step(c);
        up = up || tsnet_derphttp_state(c) == TSNET_DERPHTTP_UP;
    }
    printf("derp_probe: %s: %s; ServerInfo %s\n", argv[1],
           up ? "TLS verified, 101, and the server's greeting" : "FAIL before the greeting",
           info ? "received (the key was accepted)" : "not received (a server that verifies clients closes here)");
    tsnet_derphttp_free(c);
    tsnet_wipe(priv, sizeof priv);
    return up ? 0 : 1;
}
