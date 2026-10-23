// derphttp's connect. See derphttp.h; the Go is derp/derphttp/derphttp_client.go.
#include "platform.h"
#include "derphttp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "http1.h"
#include "tls.h"

typedef enum { S_DIAL, S_TLS, S_SEND_REQ, S_HEAD, S_DERP, S_FAILED, S_MEASURED } step_t;

#define TSNET_DERPHTTP_HEAD_ROOM 160 // ClientInfo (5 + 32 + 24 + 16 + 32 bytes) and NotePreferred (6)

struct tsnet_derphttp {
    tsnet_derphttp_cfg_t cfg;
    tsnet_derp_region_t region; // the copy, with its own nodes
    step_t st;
    int node;      // the node being dialed, or connected to
    int fd;
    bool use_tls, tls_live, up, accepted;
    tsnet_tls_t tls;
    uint64_t deadline;      // connect's 10 s, then nothing (the read deadline takes over)
    uint64_t node_deadline; // this node's 1.5 s dial
    uint64_t last_read;
    char req[512];
    size_t req_len, req_sent;
    uint64_t sent_us;    // latency_check: when the request started
    uint32_t latency_us; // latency_check: the result
    tsnet_http1_resp_t resp;
    tsnet_derp_t derp;
    uint8_t out[TSNET_DERPHTTP_OUT];
    size_t out_off, out_len;
};

static void fail(tsnet_derphttp_t *c, const char *why)
{
    if (c->st == S_FAILED || c->st == S_MEASURED) {
        return;
    }
    tsnet_log(TSNET_LOG_WARN, "derp-%d: %s", c->region.region_id, why);
    if (c->tls_live) {
        tsnet_tls_free(&c->tls);
        c->tls_live = false;
    }
    tsnet_sock_close(c->fd);
    c->fd = -1;
    c->up = false;
    c->st = S_FAILED;
}

static int io_read(tsnet_derphttp_t *c, void *buf, size_t len)
{
    return c->use_tls ? tsnet_tls_read(&c->tls, buf, len) : tsnet_sock_read(c->fd, buf, len);
}

static int io_write(tsnet_derphttp_t *c, const void *buf, size_t len)
{
    return c->use_tls ? tsnet_tls_write(&c->tls, buf, len) : tsnet_sock_write(c->fd, buf, len);
}

// Appends a frame the writer built (`n` from a tsnet_derp_* writer, which wrote it at the end of the queue).
static int queue(tsnet_derphttp_t *c, int n)
{
    if (n < 0) {
        return -1;
    }
    c->out_len += (size_t)n;
    return 0;
}

// Room at the end of the queue, compacting first.
static uint8_t *room(tsnet_derphttp_t *c, size_t *cap)
{
    if (c->out_off > 0) {
        memmove(c->out, c->out + c->out_off, c->out_len - c->out_off);
        c->out_len -= c->out_off;
        c->out_off = 0;
    }
    *cap = sizeof c->out - c->out_len;
    return c->out + c->out_len;
}

// shouldDialProto for IPv4: an empty field means dial the host name; otherwise it must be an IPv4 address.
static bool is_ipv4(const char *s)
{
    unsigned a, b, d, e;
    char extra;
    return sscanf(s, "%u.%u.%u.%u%c", &a, &b, &d, &e, &extra) == 4 && a < 256 && b < 256 && d < 256 && e < 256;
}

// dialRegion: the next node that can be dialed, from `from`. Starts its TCP dial; returns false when none is left.
static bool dial_next(tsnet_derphttp_t *c, int from)
{
    for (int i = from; i < (int)c->region.n_nodes; i++) {
        const tsnet_derp_node_t *n = &c->region.nodes[i];
        if (n->stun_only) {
            continue;
        }
        if (n->cert_name[0]) {
            tsnet_log(TSNET_LOG_WARN, "derp-%d: node %s has a CertName, not supported yet", c->region.region_id, n->name);
            continue;
        }
        const char *addr = n->ipv4[0] ? n->ipv4 : n->host_name;
        if (n->ipv4[0] && !is_ipv4(n->ipv4)) {
            continue; // IPv4 turned off for this node ("both IPv4 and IPv6 are explicitly disabled": no IPv6 here yet)
        }
        int port = n->derp_port ? n->derp_port : c->cfg.use_http ? 3340 : 443;
        c->node = i;
        c->fd = tsnet_tcp_connect(addr, (uint16_t)port);
        if (c->fd < 0) {
            continue;
        }
        c->node_deadline = tsnet_now_ms() + TSNET_DERPHTTP_NODE_DIAL_MS;
        c->st = S_DIAL;
        return true;
    }
    return false;
}

// The request for the node it connected to (urlString: the host, and the port when it isn't the scheme's default).
static bool build_request(tsnet_derphttp_t *c)
{
    const tsnet_derp_node_t *n = &c->region.nodes[c->node];
    int def = c->cfg.use_http ? 80 : 443;
    char host[300];
    bool v6 = strchr(n->host_name, ':') != NULL;
    if (n->derp_port && n->derp_port != def) {
        snprintf(host, sizeof host, v6 ? "[%s]:%d" : "%s:%d", n->host_name, n->derp_port);
    } else {
        snprintf(host, sizeof host, v6 ? "[%s]" : "%s", n->host_name);
    }
    const char *ideal = c->node != 0 ? c->region.nodes[0].name : NULL;
    // measureHTTPSLatency asks for "https://" + HostName + "/derp/latency-check": the name alone in Host.
    int len = c->cfg.latency_check ? tsnet_http1_get_request(c->req, sizeof c->req, n->host_name, "/derp/latency-check")
                                   : tsnet_http1_derp_request(c->req, sizeof c->req, host, ideal);
    if (len < 0) {
        return false;
    }
    c->req_len = (size_t)len;
    return true;
}

static void on_derp(void *ctx, const tsnet_derp_msg_t *m)
{
    tsnet_derphttp_t *c = ctx;
    size_t cap;
    uint8_t *at;
    switch (m->type) {
    case TSNET_DERP_SERVER_KEY: {
        // newClient's sendClientKey, then NotePreferred(true) when this is the home region; connect returns here. They
        // go ahead of anything queued while connecting (magicsock's writes wait in writeCh until Send has connected).
        uint8_t nonce[TSNET_BOX_NONCE_LEN], head[TSNET_DERPHTTP_HEAD_ROOM];
        if (tsnet_random(nonce, sizeof nonce) != 0) {
            fail(c, "no random nonce");
            return;
        }
        int n = tsnet_derp_client_info(&c->derp, head, sizeof head, nonce);
        int p = n > 0 && c->cfg.preferred ? tsnet_derp_note_preferred(head + n, sizeof head - (size_t)n, true) : 0;
        room(c, &cap); // compacts the queue to the start
        if (n < 0 || p < 0 || cap < (size_t)(n + p)) {
            fail(c, "can't send the client info");
            return;
        }
        memmove(c->out + n + p, c->out, c->out_len);
        memcpy(c->out, head, (size_t)(n + p));
        c->out_len += (size_t)(n + p);
        c->up = true;
        c->deadline = 0;
        tsnet_log(TSNET_LOG_INFO, "derp-%d: connected to %s", c->region.region_id, c->region.nodes[c->node].name);
        return;
    }
    case TSNET_DERP_PING:
        at = room(c, &cap);
        if (queue(c, tsnet_derp_pong(at, cap, m->ping)) != 0) {
            tsnet_log(TSNET_LOG_WARN, "derp-%d: SendPong: the queue is full", c->region.region_id);
        }
        return;
    case TSNET_DERP_SERVER_INFO:
        c->accepted = true;
        break;
    default:
        break;
    }
    if (c->cfg.on_msg) {
        c->cfg.on_msg(c->cfg.ctx, m);
    }
}

tsnet_derphttp_t *tsnet_derphttp_connect(const tsnet_derphttp_cfg_t *cfg)
{
    tsnet_derphttp_t *c = tsnet_calloc(1, sizeof *c);
    if (!c) {
        return NULL;
    }
    c->cfg = *cfg;
    if (cfg->latency_check) {
        c->cfg.use_http = false; // DialRegionTLS
    }
    c->region = *cfg->region;
    c->region.nodes = tsnet_calloc(cfg->region->n_nodes ? cfg->region->n_nodes : 1, sizeof *c->region.nodes);
    if (!c->region.nodes || (!cfg->latency_check && tsnet_derp_init(&c->derp, cfg->node_priv) != 0)) {
        tsnet_derphttp_free(c);
        return NULL;
    }
    c->cfg.region = NULL;
    c->cfg.node_priv = NULL;
    memcpy(c->region.nodes, cfg->region->nodes, cfg->region->n_nodes * sizeof *c->region.nodes);
    c->fd = -1;
    c->node = -1;
    c->use_tls = !c->cfg.use_http;
    tsnet_http1_resp_init(&c->resp);
    c->deadline = tsnet_now_ms() + TSNET_DERPHTTP_CONNECT_MS;
    if (!dial_next(c, 0)) {
        tsnet_log(TSNET_LOG_WARN, "derp-%d: no node to dial", c->region.region_id);
        tsnet_derphttp_free(c);
        return NULL;
    }
    return c;
}

void tsnet_derphttp_free(tsnet_derphttp_t *c)
{
    if (!c) {
        return;
    }
    if (c->tls_live) {
        tsnet_tls_free(&c->tls);
    }
    tsnet_sock_close(c->fd);
    tsnet_derp_wipe(&c->derp);
    free(c->region.nodes);
    free(c);
}

static void step_once(tsnet_derphttp_t *c, bool *progress)
{
    *progress = false;
    switch (c->st) {
    case S_DIAL: {
        int r = tsnet_tcp_connected(c->fd);
        if (r == 0 && tsnet_now_ms() < c->node_deadline) {
            return;
        }
        if (r <= 0) {
            tsnet_log(TSNET_LOG_INFO, "derp-%d: dial of node %s %s", c->region.region_id, c->region.nodes[c->node].name,
                      r < 0 ? "failed" : "timed out");
            tsnet_sock_close(c->fd);
            c->fd = -1;
            if (!dial_next(c, c->node + 1)) {
                fail(c, "no node of the region could be dialed");
            }
            *progress = c->st != S_FAILED;
            return;
        }
        if (!build_request(c)) {
            fail(c, "a node name in the DERP map isn't usable");
            return;
        }
        if (c->use_tls) {
            const tsnet_derp_node_t *n = &c->region.nodes[c->node];
            if (tsnet_tls_start(&c->tls, c->fd, n->host_name, n->insecure_for_tests ? TSNET_TLS_LOG_ONLY : TSNET_TLS_VERIFY) !=
                0) {
                fail(c, "TLS setup failed");
                return;
            }
            c->tls_live = true;
            c->st = S_TLS;
        } else {
            c->st = S_SEND_REQ;
        }
        *progress = true;
        return;
    }
    case S_TLS: {
        int r = tsnet_tls_handshake(&c->tls);
        if (r < 0) {
            fail(c, "TLS handshake failed");
        } else if (r > 0) {
            c->st = S_SEND_REQ;
            *progress = true;
        }
        return;
    }
    case S_SEND_REQ: {
        if (c->req_sent == 0) {
            c->sent_us = tsnet_now_us(); // measureHTTPSLatency's startTime, just before the request
        }
        int n = io_write(c, c->req + c->req_sent, c->req_len - c->req_sent);
        if (n < 0) {
            fail(c, "send failed");
        } else if (n > 0) {
            c->req_sent += (size_t)n;
            if (c->req_sent == c->req_len) {
                c->st = S_HEAD;
            }
            *progress = true;
        }
        return;
    }
    case S_HEAD:
    case S_DERP: {
        uint8_t buf[2048];
        int n = io_read(c, buf, sizeof buf);
        if (n < 0) {
            fail(c, c->st == S_HEAD ? "closed before the HTTP response" : "connection closed");
            return;
        }
        if (n == 0) {
            return;
        }
        c->last_read = tsnet_now_ms();
        *progress = true;
        size_t pos = 0;
        if (c->st == S_HEAD) {
            size_t none = 0;
            pos = tsnet_http1_resp_feed(&c->resp, buf, (size_t)n, NULL, 0, &none);
            if (c->resp.state == TSNET_HTTP1_ERROR) {
                fail(c, "bad HTTP response");
                return;
            }
            if (c->resp.state == TSNET_HTTP1_HEAD) {
                return;
            }
            if (c->cfg.latency_check) {
                // A DERP server answers with a nominal status; anything over 299 is likely a proxy refusing.
                if (c->resp.status > 299) {
                    char why[64];
                    snprintf(why, sizeof why, "latency check: unexpected status code %d", c->resp.status);
                    fail(c, why);
                    return;
                }
                uint64_t d = tsnet_now_us() - c->sent_us;
                c->latency_us = d == 0 ? 1 : d > UINT32_MAX ? UINT32_MAX : (uint32_t)d;
                tsnet_tls_free(&c->tls);
                c->tls_live = false;
                tsnet_sock_close(c->fd);
                c->fd = -1;
                c->st = S_MEASURED;
                return;
            }
            if (c->resp.status != 101) {
                char why[64];
                snprintf(why, sizeof why, "GET failed: HTTP %d", c->resp.status);
                fail(c, why);
                return;
            }
            c->st = S_DERP;
        }
        if (tsnet_derp_feed(&c->derp, buf + pos, (size_t)n - pos, on_derp, c) != 0) {
            fail(c, "derp.Recv failed");
        }
        return;
    }
    default:
        return;
    }
}

static void flush(tsnet_derphttp_t *c)
{
    while (c->up && c->st == S_DERP && c->out_off < c->out_len) {
        int n = io_write(c, c->out + c->out_off, c->out_len - c->out_off);
        if (n < 0) {
            fail(c, "write failed");
            return;
        }
        if (n == 0) {
            return;
        }
        c->out_off += (size_t)n;
    }
    if (c->out_off == c->out_len) {
        c->out_off = c->out_len = 0;
    }
}

void tsnet_derphttp_step(tsnet_derphttp_t *c)
{
    bool progress = true;
    while (progress && c->st != S_FAILED) {
        step_once(c, &progress);
        flush(c);
    }
    uint64_t now = tsnet_now_ms();
    if (c->st != S_FAILED && !c->up && now >= c->deadline) {
        fail(c, "connect timed out");
    } else if (c->st != S_FAILED && c->up && now - c->last_read >= TSNET_DERPHTTP_READ_MS) {
        fail(c, "derp.Recv: no frame in 120 s");
    }
}

int tsnet_derphttp_poll(const tsnet_derphttp_t *c, tsnet_poll_t *p, int *wait_ms)
{
    if (c->st == S_FAILED || c->st == S_MEASURED) {
        *wait_ms = -1;
        return 0;
    }
    uint64_t now = tsnet_now_ms(), until;
    if (!c->up) {
        until = c->deadline;
        if (c->st == S_DIAL && c->node_deadline < until) {
            until = c->node_deadline;
        }
    } else {
        until = c->last_read + TSNET_DERPHTTP_READ_MS;
    }
    *wait_ms = until > now ? (int)(until - now) : 0;
    p->fd = c->fd;
    p->want_write = c->st == S_DIAL || c->st == S_SEND_REQ || (c->up && c->out_off < c->out_len);
    p->readable = p->writable = 0;
    // TLS can hold decrypted bytes the socket no longer shows; step again soon after a read.
    if (c->use_tls && c->tls_live && mbedtls_ssl_get_bytes_avail(&c->tls.ssl) > 0) {
        *wait_ms = 0;
    }
    return 1;
}

tsnet_derphttp_state_t tsnet_derphttp_state(const tsnet_derphttp_t *c)
{
    if (c->st == S_MEASURED) {
        return TSNET_DERPHTTP_MEASURED;
    }
    return c->st == S_FAILED ? TSNET_DERPHTTP_FAILED : c->up ? TSNET_DERPHTTP_UP : TSNET_DERPHTTP_CONNECTING;
}

bool tsnet_derphttp_accepted(const tsnet_derphttp_t *c)
{
    return c->accepted && c->st != S_FAILED;
}

int tsnet_derphttp_node(const tsnet_derphttp_t *c)
{
    return c->node;
}

uint32_t tsnet_derphttp_latency_us(const tsnet_derphttp_t *c)
{
    return c->st == S_MEASURED ? c->latency_us : 0;
}

// Room for a frame queued now. While connecting, ClientInfo and NotePreferred still have to go in front of it.
static uint8_t *send_room(tsnet_derphttp_t *c, size_t *cap)
{
    uint8_t *at = room(c, cap);
    size_t keep = c->up ? 0 : TSNET_DERPHTTP_HEAD_ROOM;
    *cap = *cap > keep ? *cap - keep : 0;
    return at;
}

int tsnet_derphttp_send(tsnet_derphttp_t *c, const uint8_t dst[TSNET_KEY_LEN], const uint8_t *pkt, size_t len)
{
    if (c->st == S_FAILED) {
        return -1;
    }
    size_t cap;
    uint8_t *at = send_room(c, &cap);
    return queue(c, tsnet_derp_send_packet(at, cap, dst, pkt, len));
}

int tsnet_derphttp_ping(tsnet_derphttp_t *c, const uint8_t data[8])
{
    if (c->st == S_FAILED) {
        return -1;
    }
    size_t cap;
    uint8_t *at = send_room(c, &cap);
    return queue(c, tsnet_derp_ping(at, cap, data));
}

int tsnet_derphttp_note_preferred(tsnet_derphttp_t *c, bool preferred)
{
    c->cfg.preferred = preferred; // for a connect still under way, as derphttp keeps c.preferred
    if (!c->up || c->st == S_FAILED) {
        return 0;
    }
    size_t cap;
    uint8_t *at = room(c, &cap);
    return queue(c, tsnet_derp_note_preferred(at, cap, preferred));
}
