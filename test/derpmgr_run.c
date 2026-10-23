// Runs the control client with the DERP manager, for the harness's DERP scenario. Built by test.sh:
//
//   TSNET_STATE_DIR=<dir> [TSNET_HOSTNAME=<name>] [TS_DEBUG_USE_DERP_HTTP=1] [TSNET_DERP_TO=<peer hostname>]
//       derpmgr_run <server URL> <seconds> [auth key]
//
// Each netmap's DERP map goes to the manager, and the home is pickDERPFallback's (no netcheck here; magicsock_run has
// one). Every packet that arrives over DERP is
// printed. With TSNET_DERP_TO, once that peer is in the netmap, it sends the peer "relay <n>" every 2 s for 10 s, over
// the peer's home region (or this node's home when the peer reports none), and once "alt" over a region that isn't
// home, which then sits idle until cleanStaleDerp closes it. The manager's own lines (connections added, connected,
// dialed again, closed) are its log on stderr. It exits 0 if the home is connected at the end.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "client.h"
#include "derpmgr.h"

static tsnet_derpmgr_t *mgr;
static tsnet_derpmgr_cfg_t mgr_cfg;
static const tsnet_identity_t *id; // the client's, read (not called) from the netmap callback
static const char *to_name;
static uint8_t to_key[TSNET_KEY_LEN];
static int to_region = -1; // -1 until the peer is in the netmap

static void on_netmap(void *ctx, const tsnet_netmap_t *nm, int changed)
{
    (void)ctx;
    if (!mgr) { // the first netmap: the node key is registered by now
        mgr_cfg.node_priv = id->node;
        mgr = tsnet_derpmgr_new(&mgr_cfg);
        changed |= TSNET_NM_DERP;
    }
    if (mgr && (changed & TSNET_NM_DERP) && nm->derp_map) {
        tsnet_derpmgr_set_map(mgr, nm->derp_map);
        tsnet_derpmgr_set_home(mgr, 0); // no netcheck in this tool: the home is pickDERPFallback's
    }
    for (size_t i = 0; to_name && i < nm->n_peers; i++) {
        if (strcmp(nm->peers[i].hostname, to_name) == 0) {
            memcpy(to_key, nm->peers[i].key, TSNET_KEY_LEN);
            to_region = nm->peers[i].home_derp;
        }
    }
}

static void on_packet(void *ctx, int region, const uint8_t src[TSNET_KEY_LEN], const uint8_t *data, size_t len)
{
    (void)ctx;
    printf("derpmgr_run: packet from [%02x%02x%02x] over derp-%d: %.*s\n", src[0], src[1], src[2], region, (int)len,
           (const char *)data);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: TSNET_STATE_DIR=<dir> derpmgr_run <server URL> <seconds> [auth key]\n");
        return 2;
    }
    tsnet_client_cfg_t cfg = {
        .server_url = argv[1],
        .auth_key = argc > 3 ? argv[3] : NULL,
        .hostname = getenv("TSNET_HOSTNAME") ? getenv("TSNET_HOSTNAME") : "tsnet-derpmgr",
        .ipn_version = "tsnet-dev",
        .os = "linux",
        .os_version = "tsnet",
        .machine = "esp32p4",
        .on_netmap = on_netmap,
    };
    to_name = getenv("TSNET_DERP_TO");
    tsnet_client_t *c = tsnet_client_new(&cfg);
    if (c == NULL) {
        fprintf(stderr, "derpmgr_run: can't start the control client\n");
        return 2;
    }
    const char *http = getenv("TS_DEBUG_USE_DERP_HTTP");
    id = tsnet_client_identity(c);
    mgr_cfg.use_http = http && strcmp(http, "1") == 0;
    mgr_cfg.on_packet = on_packet;
    uint64_t end = tsnet_now_ms() + (uint64_t)atoi(argv[2]) * 1000, next_send = 0;
    int sent = 0;
    bool alt_sent = false;
    while (tsnet_now_ms() < end) {
        tsnet_poll_t p[3 + TSNET_DERPMGR_REGIONS];
        int wait = 1000, mwait = -1;
        int n = tsnet_client_poll(c, p, 3, &wait);
        if (mgr) {
            n += tsnet_derpmgr_poll(mgr, &p[n], TSNET_DERPMGR_REGIONS, &mwait);
            if (mwait >= 0 && mwait < wait) {
                wait = mwait;
            }
        }
        tsnet_poll(p, n, wait < 0 ? 1000 : wait);
        tsnet_client_step(c);
        if (!mgr) {
            continue;
        }
        tsnet_derpmgr_step(mgr);
        int home = tsnet_derpmgr_home(mgr);
        uint64_t now = tsnet_now_ms();
        if (to_region >= 0 && home && tsnet_derpmgr_connected(mgr, home) && sent < 5 && now >= next_send) {
            char msg[32];
            int len = snprintf(msg, sizeof msg, "relay %d", ++sent);
            int via = to_region ? to_region : home;
            int r = tsnet_derpmgr_send(mgr, via, to_key, (const uint8_t *)msg, (size_t)len);
            printf("derpmgr_run: sent \"%s\" to %s via derp-%d: %s\n", msg, to_name, via, r == 0 ? "queued" : "dropped");
            next_send = now + 2000;
            if (!alt_sent) {
                int alt = home == 900 ? 901 : 900; // the harness map's two regions (harness/derp.yaml)
                r = tsnet_derpmgr_send(mgr, alt, to_key, (const uint8_t *)"alt", 3);
                printf("derpmgr_run: sent \"alt\" via derp-%d: %s\n", alt, r == 0 ? "queued" : "dropped");
                alt_sent = true;
            }
            fflush(stdout);
        }
    }
    int home = mgr ? tsnet_derpmgr_home(mgr) : 0;
    bool up = mgr && home && tsnet_derpmgr_connected(mgr, home);
    int regions[TSNET_DERPMGR_REGIONS], nr = mgr ? tsnet_derpmgr_regions(mgr, regions, TSNET_DERPMGR_REGIONS) : 0;
    printf("derpmgr_run: done: home derp-%d connected %d, %d regions open:", home, up, nr);
    for (int i = 0; i < nr; i++) {
        printf(" derp-%d", regions[i]);
    }
    printf("\n");
    tsnet_derpmgr_free(mgr);
    tsnet_client_free(c);
    return up ? 0 : 1;
}
