// tsnet's live check against a real control server, on the host: fetch the server's key, dial /ts2021,
// finish the Noise handshake, then speak HTTP/2 with tsnet's client: it checks and drops the early payload
// (control/ts2021 conn.go), and three requests on one connection (two GETs, a POST with a body) must come back as
// responses. That proves both directions
// of the transport and HPACK's Huffman decoding against the real server. Not its dynamic table: measured on 2026-10-23,
// the server sends every response field as a literal it doesn't index (24 Huffman strings, no table lookup), so the
// table is covered by hpack_test's vectors only.
//
// Usage: probe [server URL] [capver] [80|443]   (default https://controlplane.tailscale.com TSNET_CAPVER, the ports ts2021
// picks for the URL; 80 or 443 keeps only that one). Needs a server, so test.sh runs it only with TSNET_LIVE=1
// (Tailscale's) or TSNET_HARNESS=1 (the harness's headscale, http://127.0.0.1:8090). The machine key is fresh each run
// and the requests can't register anything: the server learns nothing it can keep.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "controlhttp.h"
#include "controlkey.h"
#include "h2.h"
#include "noise.h"
#include "platform.h"
#include "tailcfg.h"

#define TIMEOUT_MS 15000

typedef struct {
    int status, ended, err, fields;
    size_t body;
} resp_t;

static resp_t resp[8];

static void on_field(void *ctx, uint32_t st, const char *n, size_t nl, const char *v, size_t vl)
{
    (void)ctx;
    printf("probe:   stream %u: %.*s: %.*s\n", (unsigned)st, (int)nl, n, (int)(vl < 80 ? vl : 80), v);
    resp[st % 8].fields++;
}

static void on_head(void *ctx, uint32_t st, int status)
{
    (void)ctx;
    resp[st % 8].status = status;
}

static void on_data(void *ctx, uint32_t st, const uint8_t *d, size_t len)
{
    (void)ctx;
    printf("probe:   stream %u body: %.*s\n", (unsigned)st, (int)(len < 160 ? len : 160), (const char *)d);
    resp[st % 8].body += len;
}

static void on_end(void *ctx, uint32_t st, int err)
{
    (void)ctx;
    resp[st % 8].ended = 1;
    resp[st % 8].err = err;
}

// Sends what the HTTP/2 client has queued.
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

// Feeds records to the client until stream `id` ends, or the timeout.
static int wait_for(tsnet_ctrl_conn_t *c, tsnet_h2_t *h, uint32_t id)
{
    static uint8_t pt[TSNET_NOISE_MAX_PLAINTEXT];
    uint64_t deadline = tsnet_now_ms() + TIMEOUT_MS;
    while (!resp[id % 8].ended) {
        if (tsnet_now_ms() >= deadline) {
            fprintf(stderr, "probe: timed out waiting for stream %u\n", (unsigned)id);
            return -1;
        }
        int n = tsnet_ctrl_read(c, pt, sizeof pt);
        if (n < 0) {
            fprintf(stderr, "probe: read failed (closed, or a record didn't decrypt)\n");
            return -1;
        }
        if (n == 0) {
            tsnet_ctrl_wait(c, 200);
            continue;
        }
        if (tsnet_h2_feed(h, pt, (size_t)n) != 0 || flush(c, h) != 0) {
            flush(c, h); // the GOAWAY
            fprintf(stderr, "probe: HTTP/2 connection error\n");
            return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *url = argc > 1 ? argv[1] : "https://controlplane.tailscale.com";
    uint16_t version = (uint16_t)(argc > 2 ? atoi(argv[2]) : TSNET_CAPVER);
    const char *mode = argc > 3 ? argv[3] : "both";
    // The URL: http(s)://host[:port], nothing after.
    int https = strncmp(url, "https://", 8) == 0;
    if (!https && strncmp(url, "http://", 7) != 0) {
        fprintf(stderr, "probe: the server URL must be http:// or https://\n");
        return 2;
    }
    char host[256];
    unsigned port = 0;
    if (sscanf(url + (https ? 8 : 7), "%255[^:/]:%u", host, &port) < 1 || port > 65535) {
        fprintf(stderr, "probe: can't read %s\n", url);
        return 2;
    }
    int http_port, https_port;
    tsnet_ts2021_ports(https, host, (uint16_t)port, &http_port, &https_port);
    if (strcmp(mode, "80") == 0) {
        https_port = TSNET_NO_PORT;
    } else if (strcmp(mode, "443") == 0) {
        http_port = TSNET_NO_PORT;
    }

    uint8_t control_pub[TSNET_KEY_LEN], machine[TSNET_KEY_LEN];
    uint16_t key_port = (uint16_t)(port ? port : https ? 443 : 80);
    if (tsnet_control_key_fetch(host, key_port, https, version, control_pub, TIMEOUT_MS) != 0) {
        fprintf(stderr, "probe: FAIL fetching the server's key\n");
        return 1;
    }
    printf("probe: server key mkey:%02x%02x%02x%02x…\n", control_pub[0], control_pub[1], control_pub[2], control_pub[3]);
    tsnet_random(machine, sizeof machine);
    tsnet_ctrl_conn_t *c = tsnet_controlhttp_dial(host, http_port, https_port, machine, control_pub, version, TIMEOUT_MS);
    if (c == NULL) {
        fprintf(stderr, "probe: FAIL dialing\n");
        return 1;
    }
    printf("probe: handshake done on port %u (the server's response tag verified)\n", (unsigned)tsnet_ctrl_port(c));

    tsnet_h2_cb_t cb = {NULL, on_field, on_head, on_data, on_end};
    tsnet_h2_t *h = tsnet_h2_new(&cb, 1);
    int ok = h != NULL && flush(c, h) == 0;
    // Two GETs, then a POST with a JSON body as the control client's will be (DATA with END_STREAM, content-length):
    // an empty RegisterRequest, which the server reads and refuses (no node key, no auth), so the answer shows it got
    // the body. (A POST to an unknown path is stopped earlier, by a check on Sec-Fetch-Site.)
    const tsnet_h2_header_t json[] = {{"content-type", "application/json"}};
    for (int i = 0; ok && i < 3; i++) {
        uint32_t id = i < 2 ? tsnet_h2_request(h, "GET", host, "/tsnet-probe", NULL, 0, NULL, 0)
                            : tsnet_h2_request(h, "POST", host, "/machine/register", json, 1, (const uint8_t *)"{}", 2);
        ok = id != 0 && flush(c, h) == 0 && wait_for(c, h, id) == 0;
        if (ok) {
            resp_t *r = &resp[id % 8];
            printf("probe: stream %u: HTTP %d, %d header fields, %zu body bytes, end %d\n", (unsigned)id, r->status,
                   r->fields, r->body, r->err);
            ok = r->status >= 200 && r->err == 0 && r->fields > 0;
        }
    }
    if (ok) {
        printf("probe: the early payload was checked, and all three requests were answered over HTTP/2\n");
    }
    tsnet_h2_free(h);
    tsnet_ctrl_close(c);
    printf("probe: %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
