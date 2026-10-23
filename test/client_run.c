// Runs tsnet's control client against a server for a while, printing its state changes and netmaps. Built by
// test.sh; the harness scenarios run it (harness/README.md):
//
//   TSNET_STATE_DIR=<dir> [TSNET_HOSTNAME=<name>] client_run <server URL> <seconds> [auth key]
//
// The identity lives in TSNET_STATE_DIR, so a second run with the same directory and no key is the same node
// restarting. The hostname is tsnet-client unless TSNET_HOSTNAME says otherwise. It exits 0 if the client is RUNNING
// at the end, else 1.
#include <stdio.h>
#include <stdlib.h>
#include "client.h"

static void on_state(void *ctx, tsnet_client_state_t s, const char *detail)
{
    (void)ctx;
    static const char *NAMES[] = {"STARTING", "NEEDS_AUTH", "LOGGED_IN", "RUNNING", "NODE_REMOVED"};
    printf("client_run: state %s (%s)\n", NAMES[s], detail);
    fflush(stdout);
}

static void on_netmap(void *ctx, const tsnet_netmap_t *nm, int changed)
{
    (void)ctx;
    printf("client_run: netmap changed 0x%x: self %s, %zu peers", (unsigned)changed, nm->has_node ? nm->node.name : "-",
           nm->n_peers);
    for (size_t i = 0; i < nm->n_peers; i++) {
        printf("%s%s", i ? ", " : ": ", nm->peers[i].name);
    }
    printf("\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: TSNET_STATE_DIR=<dir> client_run <server URL> <seconds> [auth key]\n");
        return 2;
    }
    tsnet_client_cfg_t cfg = {
        .server_url = argv[1],
        .auth_key = argc > 3 ? argv[3] : NULL,
        .hostname = getenv("TSNET_HOSTNAME") ? getenv("TSNET_HOSTNAME") : "tsnet-client",
        .ipn_version = "tsnet-dev",
        .os = "linux",
        .os_version = "tsnet",
        .machine = "esp32p4",
        .on_state = on_state,
        .on_netmap = on_netmap,
    };
    tsnet_client_t *c = tsnet_client_new(&cfg);
    if (c == NULL) {
        fprintf(stderr, "client_run: can't start (bad URL, or TSNET_STATE_DIR unset or unwritable)\n");
        return 2;
    }
    tsnet_client_run_for(c, atoi(argv[2]) * 1000);
    tsnet_client_state_t s = tsnet_client_state(c);
    printf("client_run: done: state %d, in map poll %d, node ID %s\n", (int)s, tsnet_client_in_map_poll(c),
           tsnet_client_identity(c)->node_id);
    tsnet_client_free(c);
    return s == TSNET_CLIENT_RUNNING ? 0 : 1;
}
