// Captures a control server's real responses as test fixtures: registers a throwaway node with an auth key,
// then opens the streaming map poll and saves each map message as it arrives (the 4-byte little-endian size stripped).
// Built by test.sh; run by hand against the harness (harness/harness.sh key mints the key):
//
//   capture <server URL> <auth key> <out dir> [compress: "" | zstd] [messages] [nlkey: 0|1]
//
// Writes <out dir>/register.json and map-01.bin, map-02.bin, ... It uses the capability version the client sends
// (TSNET_CAPVER), so the fixtures are the conversation tsnet will have.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "controlhttp.h"
#include "controlkey.h"
#include "h2.h"
#include "mapmsg.h"
#include "mapresp.h"
#include "netmap.h"
#include "noise.h"
#include "platform.h"
#include "tailcfg.h"

#define TIMEOUT_MS 20000

typedef struct {
    int status, ended, err;
    uint8_t *body;
    size_t len, cap;
} resp_t;
static resp_t resp[8];

static void on_field(void *ctx, uint32_t st, const char *n, size_t nl, const char *v, size_t vl)
{
    (void)ctx, (void)st, (void)n, (void)nl, (void)v, (void)vl;
}
static void on_head(void *ctx, uint32_t st, int status)
{
    (void)ctx;
    resp[st % 8].status = status;
}
static void on_data(void *ctx, uint32_t st, const uint8_t *d, size_t len)
{
    (void)ctx;
    resp_t *r = &resp[st % 8];
    if (r->len + len > r->cap) {
        r->cap = (r->len + len) * 2;
        r->body = realloc(r->body, r->cap);
    }
    memcpy(r->body + r->len, d, len);
    r->len += len;
}
static void on_end(void *ctx, uint32_t st, int err)
{
    (void)ctx;
    resp[st % 8].ended = 1;
    resp[st % 8].err = err;
}

static int flush(tsnet_ctrl_conn_t *c, tsnet_h2_t *h)
{
    const uint8_t *p;
    size_t n;
    while ((n = tsnet_h2_pending(h, &p)) > 0) {
        if (tsnet_ctrl_write(c, p, n) != 0) {
            return -1;
        }
        tsnet_h2_sent(h, n);
    }
    return 0;
}

// Feeds records until `done` says stop, or the timeout. Returns 0 or -1.
static int pump(tsnet_ctrl_conn_t *c, tsnet_h2_t *h, int (*done)(void *), void *arg)
{
    static uint8_t pt[TSNET_NOISE_MAX_PLAINTEXT];
    uint64_t deadline = tsnet_now_ms() + TIMEOUT_MS;
    while (!done(arg)) {
        if (tsnet_now_ms() >= deadline) {
            return -1;
        }
        int n = tsnet_ctrl_read(c, pt, sizeof pt);
        if (n < 0) {
            return -1;
        }
        if (n == 0) {
            tsnet_ctrl_wait(c, 200);
            continue;
        }
        if (tsnet_h2_feed(h, pt, (size_t)n) != 0 || flush(c, h) != 0) {
            return -1;
        }
    }
    return 0;
}

static int stream_ended(void *arg)
{
    return resp[*(uint32_t *)arg % 8].ended;
}

typedef struct {
    uint32_t id;
    int want;
} map_wait_t;

// How many whole map messages the body holds so far.
static int messages_in(const resp_t *r)
{
    size_t pos = 0;
    int n = 0;
    while (pos + 4 <= r->len) {
        uint32_t size = (uint32_t)r->body[pos] | (uint32_t)r->body[pos + 1] << 8 | (uint32_t)r->body[pos + 2] << 16 |
                        (uint32_t)r->body[pos + 3] << 24;
        if (pos + 4 + size > r->len) {
            break;
        }
        pos += 4 + size;
        n++;
    }
    return n;
}

static int map_done(void *arg)
{
    map_wait_t *w = arg;
    return resp[w->id % 8].ended || messages_in(&resp[w->id % 8]) >= w->want;
}

// Each message as tsnet decodes it, applied to a netmap session (ctx) as the client will.
static void decoded(void *ctx, const char *json, size_t len, bool keep_alive)
{
    tsnet_netmap_t *nm = ctx;
    tsnet_map_resp_t m;
    if (tsnet_map_response_parse(&m, json, len) != 0) {
        printf("capture: a message didn't parse: %.*s\n", (int)(len < 120 ? len : 120), json);
        return;
    }
    printf("capture: decoded %zu bytes%s: node %s, %zu peers, DERP regions %zu, control time %lld\n", len,
           keep_alive ? " (keep-alive, not decoded)" : "", m.node ? m.node->name : "-", m.n_peers,
           m.derp_map ? m.derp_map->n_regions : 0, (long long)m.control_time);
    int f = tsnet_netmap_apply(nm, &m, 0);
    printf("capture: netmap: changed 0x%x, self %s, %zu peers, %zu filters\n", (unsigned)f,
           nm->has_node ? nm->node.name : "-", nm->n_peers, nm->n_filters);
    tsnet_map_response_free(&m);
}

static int write_file(const char *dir, const char *name, const void *p, size_t n)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (f == NULL || fwrite(p, 1, n, f) != n) {
        fprintf(stderr, "capture: can't write %s\n", path);
        if (f) {
            fclose(f);
        }
        return -1;
    }
    fclose(f);
    printf("capture: wrote %s (%zu bytes)\n", path, n);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: capture <server URL> <auth key> <out dir> [compress] [messages] [nlkey 0|1]\n");
        return 2;
    }
    const char *url = argv[1], *auth = argv[2], *dir = argv[3];
    const char *compress = argc > 4 ? argv[4] : "";
    int want = argc > 5 ? atoi(argv[5]) : 3;
    int with_nl = argc > 6 && argv[6][0] == '1';
    int https = strncmp(url, "https://", 8) == 0;
    char host[256];
    unsigned port = 0;
    if (sscanf(url + (https ? 8 : 7), "%255[^:/]:%u", host, &port) < 1) {
        return 2;
    }
    int http_port, https_port;
    tsnet_ts2021_ports(https, host, (uint16_t)port, &http_port, &https_port);

    // A throwaway identity.
    uint8_t machine[32], node[32], node_pub[32], disco[32], disco_pub[32], nl[32], log_id[32];
    tsnet_random(machine, 32);
    tsnet_random(node, 32);
    tsnet_random(disco, 32);
    tsnet_random(nl, 32); // shortcut: random bytes standing in for an Ed25519 public key
    tsnet_random(log_id, 32);
    tsnet_x25519_public(node_pub, node);
    tsnet_x25519_public(disco_pub, disco);
    char log_hex[80];
    tsnet_key_text(log_hex, "", log_id);

    uint8_t control_pub[32];
    if (tsnet_control_key_fetch(host, (uint16_t)(port ? port : https ? 443 : 80), https, TSNET_CAPVER, control_pub,
                                TIMEOUT_MS) != 0) {
        return 1;
    }
    tsnet_ctrl_conn_t *c = tsnet_controlhttp_dial(host, http_port, https_port, machine, control_pub, TSNET_CAPVER, TIMEOUT_MS);
    if (c == NULL) {
        return 1;
    }
    tsnet_h2_cb_t cb = {NULL, on_field, on_head, on_data, on_end};
    tsnet_h2_t *h = tsnet_h2_new(&cb, 1);
    if (h == NULL || flush(c, h) != 0) {
        return 1;
    }

    tsnet_hostinfo_t hi = {"tsnet-capture", log_hex, "linux", "tsnet", "tsnet-capture", "esp32p4", NULL};
    tsnet_register_req_t reg = {.version = TSNET_CAPVER, .nl_key = with_nl ? nl : NULL, .auth_key = auth, .hostinfo = &hi};
    memcpy(reg.node_key, node_pub, 32);
    char *body = tsnet_register_request_json(&reg);
    char lb[TSNET_KEY_TEXT_MAX];
    tsnet_key_text(lb, TSNET_KEY_NODE, node_pub);
    tsnet_h2_header_t hd[] = {{"content-type", "application/json"}, {"ts-lb", lb}};
    uint32_t id = tsnet_h2_request(h, "POST", host, "/machine/register", hd, 2, (const uint8_t *)body, strlen(body));
    free(body);
    if (id == 0 || flush(c, h) != 0 || pump(c, h, stream_ended, &id) != 0) {
        fprintf(stderr, "capture: register failed\n");
        return 1;
    }
    printf("capture: register: HTTP %d: %.*s\n", resp[id % 8].status, (int)resp[id % 8].len, (char *)resp[id % 8].body);
    write_file(dir, "register.json", resp[id % 8].body, resp[id % 8].len);
    tsnet_register_resp_t rr;
    if (resp[id % 8].status != 200 || tsnet_register_response_parse(&rr, (char *)resp[id % 8].body, resp[id % 8].len) != 0 ||
        rr.error[0] || !rr.machine_authorized) {
        fprintf(stderr, "capture: not authorized\n");
        return 1;
    }

    tsnet_map_req_t mr = {.version = TSNET_CAPVER, .compress = compress, .keep_alive = true, .stream = true, .hostinfo = &hi};
    memcpy(mr.node_key, node_pub, 32);
    memcpy(mr.disco_key, disco_pub, 32);
    body = tsnet_map_request_json(&mr);
    uint32_t mid = tsnet_h2_request(h, "POST", host, "/machine/map", hd, 2, (const uint8_t *)body, strlen(body));
    free(body);
    map_wait_t w = {mid, want};
    if (mid == 0 || flush(c, h) != 0) {
        return 1;
    }
    pump(c, h, map_done, &w); // up to `want` messages, or the timeout
    resp_t *r = &resp[mid % 8];
    printf("capture: map: HTTP %d, %zu bytes, %d messages\n", r->status, r->len, messages_in(r));
    size_t pos = 0;
    for (int i = 1; pos + 4 <= r->len; i++) {
        uint32_t size = (uint32_t)r->body[pos] | (uint32_t)r->body[pos + 1] << 8 | (uint32_t)r->body[pos + 2] << 16 |
                        (uint32_t)r->body[pos + 3] << 24;
        if (pos + 4 + size > r->len) {
            break;
        }
        char name[32];
        snprintf(name, sizeof name, "map-%02d.bin", i);
        write_file(dir, name, r->body + pos + 4, size);
        pos += 4 + size;
    }
    // And through tsnet's own decoding, as the client will: the framing, zstd when asked for, the MapResponse.
    tsnet_mapmsg_t *mm = tsnet_mapmsg_new(compress[0] != '\0');
    tsnet_netmap_t nm;
    tsnet_netmap_init(&nm);
    int ok = mm && tsnet_mapmsg_feed(mm, r->body, r->len, decoded, &nm) == 0 && nm.has_node;
    tsnet_netmap_free(&nm);
    tsnet_mapmsg_free(mm);
    printf("capture: tsnet decoded the stream: %s\n", ok ? "yes" : "NO");
    tsnet_h2_free(h);
    tsnet_ctrl_close(c);
    return ok ? 0 : 1;
}
