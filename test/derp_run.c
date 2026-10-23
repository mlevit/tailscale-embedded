// Connects to a DERP server as a registered node and checks it end to end. Built by test.sh; the harness runs
// it (harness/README.md):
//
//   TSNET_STATE_DIR=<dir> [TS_DEBUG_USE_DERP_HTTP=1] derp_run <server URL> <seconds> [auth key]
//
// It runs the control client until a netmap with a DERP map is in (the DERP server only accepts registered nodes,
// derpserver's verifyClient), then connects to the map's first region with the node key, keeping the control client
// running. Once the server has sent ServerInfo it sends:
//   - a ping, and expects the pong (derpserver's handleFramePing);
//   - a packet to itself, and expects it back from itself;
//   - a disco-shaped packet to a key nobody has, and expects PeerGone with reason NotHere (derpserver sends that only
//     for a packet that LooksLikeDiscoWrapper).
// TS_DEBUG_USE_DERP_HTTP=1 speaks plain HTTP, as Go's knob of that name does. It exits 0 when all four were seen.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "client.h"
#include "derphttp.h"

static tsnet_derp_region_t region; // the first region of the DERP map, copied
static bool have_region, pong, self_packet, not_here;
static uint8_t node_pub[TSNET_KEY_LEN], nobody[TSNET_KEY_LEN];
static const uint8_t PING[8] = {'t', 's', 'n', 'e', 't', '1', '9', '!'};

static void on_netmap(void *ctx, const tsnet_netmap_t *nm, int changed)
{
    (void)ctx;
    (void)changed;
    if (have_region || !nm->derp_map) {
        return;
    }
    for (size_t i = 0; i < nm->derp_map->n_regions; i++) {
        const tsnet_derp_region_t *r = &nm->derp_map->regions[i];
        if (r->n_nodes == 0) {
            continue;
        }
        region = *r;
        region.nodes = malloc(r->n_nodes * sizeof *r->nodes);
        memcpy(region.nodes, r->nodes, r->n_nodes * sizeof *r->nodes);
        have_region = true;
        printf("derp_run: region %d (%s), %zu nodes, first %s:%d\n", r->region_id, r->code, r->n_nodes,
               r->nodes[0].host_name, r->nodes[0].derp_port);
        fflush(stdout);
        return;
    }
}

static void on_msg(void *ctx, const tsnet_derp_msg_t *m)
{
    (void)ctx;
    switch (m->type) {
    case TSNET_DERP_SERVER_INFO:
        printf("derp_run: server info (token bucket %lld/%lld)\n", (long long)m->bytes_per_second,
               (long long)m->bytes_burst);
        break;
    case TSNET_DERP_PONG:
        pong = pong || memcmp(m->ping, PING, 8) == 0;
        printf("derp_run: pong\n");
        break;
    case TSNET_DERP_PACKET:
        self_packet = self_packet || (memcmp(m->key, node_pub, TSNET_KEY_LEN) == 0 && m->len == 5 &&
                                      memcmp(m->data, "hello", 5) == 0);
        printf("derp_run: packet of %zu bytes\n", m->len);
        break;
    case TSNET_DERP_PEER_GONE:
        not_here = not_here || (memcmp(m->key, nobody, TSNET_KEY_LEN) == 0 && m->reason == TSNET_DERP_GONE_NOT_HERE);
        printf("derp_run: peer gone, reason %u\n", m->reason);
        break;
    case TSNET_DERP_KEEP_ALIVE:
        printf("derp_run: keep-alive\n");
        break;
    default:
        printf("derp_run: message %d\n", (int)m->type);
        break;
    }
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: TSNET_STATE_DIR=<dir> derp_run <server URL> <seconds> [auth key]\n");
        return 2;
    }
    tsnet_client_cfg_t cfg = {
        .server_url = argv[1],
        .auth_key = argc > 3 ? argv[3] : NULL,
        .hostname = getenv("TSNET_HOSTNAME") ? getenv("TSNET_HOSTNAME") : "tsnet-derp",
        .ipn_version = "tsnet-dev",
        .os = "linux",
        .os_version = "tsnet",
        .machine = "esp32p4",
        .on_netmap = on_netmap,
    };
    tsnet_client_t *c = tsnet_client_new(&cfg);
    if (c == NULL) {
        fprintf(stderr, "derp_run: can't start the control client\n");
        return 2;
    }
    const char *http = getenv("TS_DEBUG_USE_DERP_HTTP");
    bool use_http = http && strcmp(http, "1") == 0;
    tsnet_random(nobody, sizeof nobody);
    tsnet_derphttp_t *d = NULL;
    bool sent = false;
    uint64_t end = tsnet_now_ms() + (uint64_t)atoi(argv[2]) * 1000;
    while (tsnet_now_ms() < end && !(pong && self_packet && not_here)) {
        tsnet_poll_t p[4];
        int wait = 1000, dwait = 1000;
        int n = tsnet_client_poll(c, p, 3, &wait);
        if (d) {
            n += tsnet_derphttp_poll(d, &p[n], &dwait);
            wait = dwait < wait ? dwait : wait;
        }
        tsnet_poll(p, n, wait < 0 ? 1000 : wait);
        tsnet_client_step(c);
        if (!d && have_region) {
            const tsnet_identity_t *id = tsnet_client_identity(c);
            tsnet_x25519_public(node_pub, id->node);
            tsnet_derphttp_cfg_t dc = {.region = &region, .node_priv = id->node, .use_http = use_http, .preferred = true,
                                       .on_msg = on_msg};
            d = tsnet_derphttp_connect(&dc);
            if (!d) {
                fprintf(stderr, "derp_run: can't start the DERP connection\n");
                break;
            }
        }
        if (d) {
            tsnet_derphttp_step(d);
            if (tsnet_derphttp_state(d) == TSNET_DERPHTTP_FAILED) {
                printf("derp_run: the connection failed\n");
                break;
            }
            if (!sent && tsnet_derphttp_accepted(d)) {
                // A disco wrapper: the magic "TS" and U+1F4AC, a disco key, a nonce, then the box (here random bytes).
                uint8_t disco[6 + 32 + 24 + 16] = {0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac};
                tsnet_random(disco + 6, sizeof disco - 6);
                sent = tsnet_derphttp_ping(d, PING) == 0 &&
                       tsnet_derphttp_send(d, node_pub, (const uint8_t *)"hello", 5) == 0 &&
                       tsnet_derphttp_send(d, nobody, disco, sizeof disco) == 0;
                printf("derp_run: sent the ping and two packets: %s\n", sent ? "ok" : "FAILED");
            }
        }
    }
    printf("derp_run: done: accepted %d, pong %d, packet from itself %d, not here %d\n",
           d ? tsnet_derphttp_accepted(d) : 0, pong, self_packet, not_here);
    tsnet_derphttp_free(d);
    tsnet_client_free(c);
    free(region.nodes);
    return pong && self_packet && not_here ? 0 : 1;
}
