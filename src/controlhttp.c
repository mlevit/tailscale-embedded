// The dial to the control server. See controlhttp.h; the Go is control/controlhttp/client.go.
#include "controlhttp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "http1.h"
#include "noise.h"
#include "platform.h"
#include "tls.h"

#define FALLBACK_MS 500                            // httpsFallbackDelay
#define UPGRADE_VALUE "tailscale-control-protocol" // controlhttpcommon.UpgradeHeaderValue
#define WRITE_WAIT_MS 10000

typedef enum { A_IDLE, A_CONNECTING, A_TLS, A_SEND, A_HEAD, A_NOISE, A_DONE, A_FAILED } astate_t;

// One attempt, and once it wins, the connection.
struct tsnet_ctrl_conn {
    astate_t st;
    uint16_t port;
    int fd;
    int use_tls, tls_live;
    tsnet_tls_t tls;
    tsnet_noise_client_t hs;
    char req[512];
    size_t req_len, sent;
    tsnet_http1_resp_t resp;
    tsnet_noise_framer_t framer;
    uint8_t in[1024]; // bytes read and not yet framed
    size_t in_len, in_pos;
    tsnet_noise_conn_t noise;
    uint8_t out[TSNET_NOISE_MAX_MESSAGE]; // a sealed record...
    size_t out_off, out_len;              // ...and how much of it the socket has taken
};

static int io_read(tsnet_ctrl_conn_t *a, void *buf, size_t len)
{
    return a->use_tls ? tsnet_tls_read(&a->tls, buf, len) : tsnet_sock_read(a->fd, buf, len);
}

static int io_write(tsnet_ctrl_conn_t *a, const void *buf, size_t len)
{
    return a->use_tls ? tsnet_tls_write(&a->tls, buf, len) : tsnet_sock_write(a->fd, buf, len);
}

static void a_close(tsnet_ctrl_conn_t *a)
{
    if (a->tls_live) {
        tsnet_tls_free(&a->tls);
        a->tls_live = 0;
    }
    tsnet_sock_close(a->fd);
    a->fd = -1;
    tsnet_wipe(&a->hs, sizeof a->hs);
    tsnet_noise_conn_wipe(&a->noise);
}

static void a_fail(tsnet_ctrl_conn_t *a, const char *why)
{
    tsnet_log(TSNET_LOG_WARN, "control dial on port %u: %s", (unsigned)a->port, why);
    a_close(a);
    a->st = A_FAILED;
}

static void a_start(tsnet_ctrl_conn_t *a, const char *host, uint16_t port, int use_tls, const uint8_t *machine,
                    const uint8_t *control_pub, uint16_t version)
{
    a->port = port;
    a->use_tls = use_tls;
    a->fd = -1;
    uint8_t init[TSNET_NOISE_INIT_LEN];
    if (tsnet_noise_client_start(&a->hs, machine, control_pub, version, init) != 0) {
        a_fail(a, "no handshake");
        return;
    }
    int n = tsnet_http1_upgrade_request(a->req, sizeof a->req, host, port, init, sizeof init);
    if (n < 0) {
        a_fail(a, "host name too long");
        return;
    }
    a->req_len = (size_t)n;
    tsnet_http1_resp_init(&a->resp);
    a->fd = tsnet_tcp_connect(host, port);
    if (a->fd < 0) {
        a_fail(a, "can't connect");
        return;
    }
    a->st = A_CONNECTING;
}

// Bytes after the HTTP head: the server's first Noise frame, then whatever it sent after it (kept for reading).
static void a_noise(tsnet_ctrl_conn_t *a, const uint8_t *buf, size_t n)
{
    size_t pos = tsnet_noise_framer_feed(&a->framer, buf, n);
    int f = tsnet_noise_framer_frame(&a->framer);
    if (f < 0) {
        a_fail(a, "oversized Noise frame");
        return;
    }
    if (f == 0) {
        return;
    }
    int r = tsnet_noise_client_finish(&a->hs, a->framer.buf, (size_t)f, &a->noise);
    if (r == TSNET_NOISE_SERVER_ERROR) {
        char msg[128];
        size_t len = (size_t)f - TSNET_NOISE_HEADER_LEN < sizeof msg - 1 ? (size_t)f - TSNET_NOISE_HEADER_LEN : sizeof msg - 1;
        for (size_t i = 0; i < len; i++) {
            uint8_t c = a->framer.buf[TSNET_NOISE_HEADER_LEN + i];
            msg[i] = c >= 0x20 && c < 0x7f ? (char)c : '?';
        }
        msg[len] = '\0';
        tsnet_log(TSNET_LOG_WARN, "control server refused the handshake: %s", msg);
        a_fail(a, "server error");
        return;
    }
    if (r != 0) {
        a_fail(a, "bad Noise response");
        return;
    }
    tsnet_noise_framer_reset(&a->framer);
    memcpy(a->in, buf + pos, n - pos); // n is at most sizeof a->in
    a->in_len = n - pos;
    a->in_pos = 0;
    a->st = A_DONE;
}

// Moves an attempt on as far as the socket allows.
static void a_step(tsnet_ctrl_conn_t *a, const char *host)
{
    for (;;) {
        switch (a->st) {
        case A_CONNECTING: {
            int r = tsnet_tcp_connected(a->fd);
            if (r < 0) {
                a_fail(a, "connect failed");
            }
            if (r <= 0) {
                return;
            }
            if (!a->use_tls) {
                a->st = A_SEND;
            } else if (tsnet_tls_start(&a->tls, a->fd, host, TSNET_TLS_LOG_ONLY) != 0) {
                a_fail(a, "TLS setup failed");
                return;
            } else {
                a->tls_live = 1;
                a->st = A_TLS;
            }
            break;
        }
        case A_TLS: {
            int r = tsnet_tls_handshake(&a->tls);
            if (r < 0) {
                a_fail(a, "TLS handshake failed");
            }
            if (r <= 0) {
                return;
            }
            a->st = A_SEND;
            break;
        }
        case A_SEND: {
            int n = io_write(a, a->req + a->sent, a->req_len - a->sent);
            if (n < 0) {
                a_fail(a, "send failed");
            }
            if (n <= 0) {
                return;
            }
            a->sent += (size_t)n;
            if (a->sent == a->req_len) {
                a->st = A_HEAD;
            }
            break;
        }
        case A_HEAD:
        case A_NOISE: {
            uint8_t buf[sizeof a->in];
            int n = io_read(a, buf, sizeof buf);
            if (n < 0) {
                a_fail(a, a->st == A_HEAD ? "closed before the HTTP response" : "closed before the Noise response");
            }
            if (n <= 0) {
                return;
            }
            size_t pos = 0;
            if (a->st == A_HEAD) {
                size_t none = 0;
                pos = tsnet_http1_resp_feed(&a->resp, buf, (size_t)n, NULL, 0, &none);
                if (a->resp.state == TSNET_HTTP1_ERROR) {
                    a_fail(a, "bad HTTP response");
                    return;
                }
                if (a->resp.state == TSNET_HTTP1_HEAD) {
                    break;
                }
                // tryURLUpgrade: 101, and exactly our protocol in Upgrade.
                if (a->resp.status != 101) {
                    tsnet_log(TSNET_LOG_WARN, "control dial on port %u: HTTP %d", (unsigned)a->port, a->resp.status);
                    a_fail(a, "unexpected HTTP response");
                    return;
                }
                if (strcmp(a->resp.upgrade, UPGRADE_VALUE) != 0) {
                    a_fail(a, "server switched to an unexpected protocol");
                    return;
                }
                a->st = A_NOISE;
            }
            a_noise(a, buf + pos, (size_t)n - pos);
            if (a->st != A_NOISE) {
                return; // done or failed
            }
            break;
        }
        default:
            return;
        }
    }
}

static int active(const tsnet_ctrl_conn_t *a)
{
    return a->st != A_IDLE && a->st != A_DONE && a->st != A_FAILED;
}

// The dial in progress: the two attempts and the timing between them (dialHostOpt).
struct tsnet_dial {
    tsnet_ctrl_conn_t *a80, *a443, *won;
    char host[256];
    uint16_t p443;
    uint8_t machine[TSNET_KEY_LEN], control_pub[TSNET_KEY_LEN];
    uint16_t version;
    uint64_t t0, deadline, at443;
    int timeout_ms, result; // 1 won, -1 failed, 0 still going
};

static void dial_close(tsnet_ctrl_conn_t *a)
{
    if (a) {
        a_close(a);
        free(a);
    }
}

// health.Tracker.LastNoiseDialWasRecent: when the previous dial (any outcome) was less than 2 minutes ago. Each dial
// notes its own time.
#define RECENT_DIAL_MS 120000
static uint64_t last_dial_ms;
static bool dialed_before;

void tsnet_dial_forget_recent(void)
{
    dialed_before = false;
}

tsnet_dial_t *tsnet_dial_start(const char *host, int http_port, int https_port, const uint8_t machine_priv[TSNET_KEY_LEN],
                               const uint8_t control_pub[TSNET_KEY_LEN], uint16_t version, int timeout_ms)
{
    if ((http_port == TSNET_NO_PORT && https_port == TSNET_NO_PORT) || strlen(host) >= 256) {
        return NULL;
    }
    uint64_t now = tsnet_now_ms();
    bool recent = dialed_before && now - last_dial_ms < RECENT_DIAL_MS;
    last_dial_ms = now;
    dialed_before = true;
    // forceNoise443: "If we dialed recently, assume there was a recent failure and fall back to HTTPS dials for the
    // subsequent retries" (port 80 can work for a while after the upgrade and then be closed by a middlebox). Only when
    // there is an HTTPS port: without one (an http:// URL on a private host) port 80 is still tried, as dialHostOpt does.
    if (recent && https_port != TSNET_NO_PORT && http_port != TSNET_NO_PORT) {
        tsnet_log(TSNET_LOG_INFO, "control dial: forcing port %d, the previous dial being recent",
                  https_port > 0 ? https_port : 443);
        http_port = TSNET_NO_PORT;
    }
    tsnet_dial_t *d = tsnet_calloc(1, sizeof *d);
    tsnet_ctrl_conn_t *a80 = tsnet_calloc(1, sizeof *a80), *a443 = tsnet_calloc(1, sizeof *a443);
    if (d == NULL || a80 == NULL || a443 == NULL) {
        free(d);
        free(a80);
        free(a443);
        return NULL;
    }
    d->a80 = a80;
    d->a443 = a443;
    snprintf(d->host, sizeof d->host, "%s", host);
    d->p443 = (uint16_t)(https_port > 0 ? https_port : 443);
    memcpy(d->machine, machine_priv, TSNET_KEY_LEN);
    memcpy(d->control_pub, control_pub, TSNET_KEY_LEN);
    d->version = version;
    d->timeout_ms = timeout_ms;
    d->t0 = tsnet_now_ms();
    d->deadline = d->t0 + (uint64_t)timeout_ms;
    d->at443 = d->t0 + (http_port != TSNET_NO_PORT ? FALLBACK_MS : 0);
    a80->st = a443->st = A_IDLE;
    a80->fd = a443->fd = -1;
    if (http_port != TSNET_NO_PORT) {
        a_start(a80, host, (uint16_t)(http_port > 0 ? http_port : 80), 0, machine_priv, control_pub, version);
    } else {
        a80->st = A_FAILED;
    }
    if (https_port == TSNET_NO_PORT) {
        a443->st = A_FAILED;
    }
    return d;
}

int tsnet_dial_step(tsnet_dial_t *d)
{
    if (d->result != 0) {
        return d->result;
    }
    uint64_t now = tsnet_now_ms();
    // "Connecting over plain HTTP failed ... see if we can get through over HTTPS": 443 at once, else after the delay.
    if (d->a443->st == A_IDLE && (now >= d->at443 || d->a80->st == A_FAILED)) {
        a_start(d->a443, d->host, d->p443, 1, d->machine, d->control_pub, d->version);
    }
    a_step(d->a80, d->host);
    a_step(d->a443, d->host);
    if (d->a80->st == A_DONE || d->a443->st == A_DONE) {
        d->won = d->a80->st == A_DONE ? d->a80 : d->a443;
        // The loser is closed: dialHostOpt's cancel stops the other attempt.
        if (d->won == d->a80) {
            dial_close(d->a443);
        } else {
            dial_close(d->a80);
        }
        d->a80 = d->a443 = NULL;
        tsnet_log(TSNET_LOG_INFO, "control connection to %s:%u in %u ms", d->host, (unsigned)d->won->port,
                  (unsigned)(now - d->t0));
        return d->result = 1;
    }
    if (d->a80->st == A_FAILED && d->a443->st == A_FAILED) {
        tsnet_log(TSNET_LOG_WARN, "control dial: all connection attempts failed");
        return d->result = -1;
    }
    if (now >= d->deadline) {
        tsnet_log(TSNET_LOG_WARN, "control dial: timed out after %d ms", d->timeout_ms);
        return d->result = -1;
    }
    return 0;
}

int tsnet_dial_poll(const tsnet_dial_t *d, tsnet_poll_t p[2])
{
    int n = 0;
    const tsnet_ctrl_conn_t *as[2] = {d->a80, d->a443};
    for (int i = 0; i < 2; i++) {
        if (d->result == 0 && as[i] && active(as[i])) {
            p[n++] = (tsnet_poll_t){as[i]->fd, as[i]->st == A_CONNECTING || as[i]->st == A_SEND, 0, 0};
        }
    }
    return n;
}

int tsnet_dial_wait_ms(const tsnet_dial_t *d)
{
    uint64_t now = tsnet_now_ms();
    if (d->result != 0 || now >= d->deadline) {
        return 0;
    }
    uint64_t wait = d->deadline - now;
    if (d->a443 && d->a443->st == A_IDLE && d->at443 > now && d->at443 - now < wait) {
        wait = d->at443 - now;
    }
    // A short cap: TLS can want to write in any state, which the poll doesn't watch for.
    return (int)(wait < 50 ? wait : 50);
}

tsnet_ctrl_conn_t *tsnet_dial_take(tsnet_dial_t *d)
{
    tsnet_ctrl_conn_t *c = d->won;
    d->won = NULL;
    return c;
}

void tsnet_dial_free(tsnet_dial_t *d)
{
    if (d == NULL) {
        return;
    }
    dial_close(d->a80);
    dial_close(d->a443);
    dial_close(d->won);
    tsnet_wipe(d->machine, sizeof d->machine);
    free(d);
}

tsnet_ctrl_conn_t *tsnet_controlhttp_dial(const char *host, int http_port, int https_port,
                                          const uint8_t machine_priv[TSNET_KEY_LEN],
                                          const uint8_t control_pub[TSNET_KEY_LEN], uint16_t version, int timeout_ms)
{
    tsnet_dial_t *d = tsnet_dial_start(host, http_port, https_port, machine_priv, control_pub, version, timeout_ms);
    if (d == NULL) {
        return NULL;
    }
    int r;
    while ((r = tsnet_dial_step(d)) == 0) {
        tsnet_poll_t p[2];
        tsnet_poll(p, tsnet_dial_poll(d, p), tsnet_dial_wait_ms(d));
    }
    tsnet_ctrl_conn_t *c = r == 1 ? tsnet_dial_take(d) : NULL;
    tsnet_dial_free(d);
    return c;
}

// netip.Addr IsPrivate (RFC 1918, fc00::/7) or IsLoopback (127/8, ::1).
static int private_host(const char *host)
{
    if (strcmp(host, "localhost") == 0) {
        return 1;
    }
    unsigned a, b, c, d;
    char tail;
    if (sscanf(host, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) == 4 && a < 256 && b < 256 && c < 256 && d < 256) {
        return a == 10 || a == 127 || (a == 172 && (b & 0xf0) == 16) || (a == 192 && b == 168);
    }
    if (strchr(host, ':') != NULL) { // IPv6: ::1, or fc00::/7 (its first group fc.. or fd..)
        if (strcmp(host, "::1") == 0) {
            return 1;
        }
        unsigned g;
        return sscanf(host, "%x:", &g) == 1 && strchr(host, ':') - host <= 4 && (g & 0xfe00) == 0xfc00;
    }
    return 0;
}

void tsnet_ts2021_ports(int https, const char *host, uint16_t port, int *http_port, int *https_port)
{
    *http_port = 80;
    *https_port = 443;
    int priv = private_host(host);
    if (port != 0) {
        if (https) {
            *https_port = port; // httpPort "" there, which controlhttp's strDef makes 80
        } else {
            *http_port = port;
            *https_port = priv ? TSNET_NO_PORT : 443;
        }
    } else if (!https && priv) {
        *https_port = TSNET_NO_PORT;
    }
}

uint16_t tsnet_ctrl_port(const tsnet_ctrl_conn_t *c)
{
    return c->port;
}

int tsnet_ctrl_read(tsnet_ctrl_conn_t *c, uint8_t *pt, size_t cap)
{
    if (cap < TSNET_NOISE_MAX_PLAINTEXT) {
        return -1;
    }
    for (;;) {
        int f = tsnet_noise_framer_frame(&c->framer);
        if (f < 0) {
            return -1;
        }
        if (f > 0) {
            int n = tsnet_noise_open(&c->noise, pt, c->framer.buf, (size_t)f);
            tsnet_noise_framer_reset(&c->framer);
            if (n != 0) {
                return n; // a record, or -1; an empty record is skipped, as conn.go Read does
            }
            continue;
        }
        if (c->in_pos < c->in_len) {
            c->in_pos += tsnet_noise_framer_feed(&c->framer, c->in + c->in_pos, c->in_len - c->in_pos);
            continue;
        }
        int n = io_read(c, c->in, sizeof c->in);
        if (n <= 0) {
            return n;
        }
        c->in_len = (size_t)n;
        c->in_pos = 0;
    }
}

int tsnet_ctrl_wait(tsnet_ctrl_conn_t *c, int timeout_ms)
{
    if (tsnet_ctrl_buffered(c)) {
        return 1;
    }
    tsnet_poll_t p = {c->fd, 0, 0, 0};
    int r = tsnet_poll(&p, 1, timeout_ms);
    return r < 0 ? -1 : p.readable;
}

// Sends what's left of the queued record. Returns 1 when it's all gone, 0 when the socket is full, -1 on an error.
// mbedTLS wants a WANT_WRITE retried with the same data, which the queued record is.
static int flush(tsnet_ctrl_conn_t *c)
{
    while (c->out_off < c->out_len) {
        int n = io_write(c, c->out + c->out_off, c->out_len - c->out_off);
        if (n < 0) {
            return -1;
        }
        if (n == 0) {
            return 0;
        }
        c->out_off += (size_t)n;
    }
    c->out_off = c->out_len = 0;
    return 1;
}

int tsnet_ctrl_write_some(tsnet_ctrl_conn_t *c, const uint8_t *data, size_t len)
{
    int f = flush(c);
    if (f <= 0) {
        return f; // a record is still queued: nothing new is taken
    }
    if (len == 0) {
        return 0;
    }
    size_t chunk = len < TSNET_NOISE_MAX_PLAINTEXT ? len : TSNET_NOISE_MAX_PLAINTEXT; // conn.go Write's split
    size_t n = tsnet_noise_seal(&c->noise, c->out, data, chunk);
    if (n == 0) {
        return -1;
    }
    c->out_len = n;
    return flush(c) < 0 ? -1 : (int)chunk; // taken: sealed, and sent or queued
}

int tsnet_ctrl_flush(tsnet_ctrl_conn_t *c)
{
    return flush(c);
}

int tsnet_ctrl_fd(const tsnet_ctrl_conn_t *c)
{
    return c->fd;
}

int tsnet_ctrl_pending_write(const tsnet_ctrl_conn_t *c)
{
    return c->out_off < c->out_len;
}

int tsnet_ctrl_buffered(const tsnet_ctrl_conn_t *c)
{
    return tsnet_noise_framer_frame(&c->framer) != 0 || c->in_pos < c->in_len ||
           (c->use_tls && mbedtls_ssl_get_bytes_avail(&c->tls.ssl) > 0);
}

int tsnet_ctrl_write(tsnet_ctrl_conn_t *c, const uint8_t *data, size_t len)
{
    uint64_t deadline = tsnet_now_ms() + WRITE_WAIT_MS;
    while (len > 0 || tsnet_ctrl_pending_write(c)) {
        int n = tsnet_ctrl_write_some(c, data, len);
        if (n < 0 || tsnet_now_ms() >= deadline) {
            return -1;
        }
        if (n == 0) {
            tsnet_poll_t p = {c->fd, 1, 0, 0};
            tsnet_poll(&p, 1, 100);
            continue;
        }
        data += n;
        len -= (size_t)n;
    }
    return 0;
}

void tsnet_ctrl_close(tsnet_ctrl_conn_t *c)
{
    if (c != NULL) {
        a_close(c);
        free(c);
    }
}
