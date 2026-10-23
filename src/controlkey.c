// The control server's Noise key. See controlkey.h.
#include "controlkey.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "json.h"
#include "http1.h"
#include "platform.h"
#include "tls.h"

#define BODY_MAX 4096 // Go allows 64 KB (httpbody.LimitSizeTo); the real body is ~180 bytes

static int hexval(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int tsnet_control_key_parse(const char *body, size_t len, uint8_t pub[TSNET_KEY_LEN])
{
    cJSON *root = tsnet_json_parse(body, len);
    const cJSON *k = cJSON_GetObjectItemCaseSensitive(root, "publicKey");
    int ret = -1;
    // key.MachinePublic's text form: "mkey:" then 64 hex digits (either case, as hex.Decode takes).
    if (cJSON_IsString(k) && strlen(k->valuestring) == 5 + 2 * TSNET_KEY_LEN && strncmp(k->valuestring, "mkey:", 5) == 0) {
        const char *h = k->valuestring + 5;
        uint8_t any = 0;
        ret = 0;
        for (int i = 0; i < TSNET_KEY_LEN && ret == 0; i++) {
            int hi = hexval(h[2 * i]), lo = hexval(h[2 * i + 1]);
            if (hi < 0 || lo < 0) {
                ret = -1;
            } else {
                pub[i] = (uint8_t)(hi << 4 | lo);
                any |= pub[i];
            }
        }
        if (any == 0) {
            ret = -1; // a zero key: the server has no Noise key for us
        }
    }
    cJSON_Delete(root);
    return ret;
}

// A fetch of the key in progress.
struct tsnet_keyfetch {
    char host[256], authority[288], req[384];
    int req_len, sent, fd, use_tls, connected, tls_live, result;
    uint64_t deadline;
    tsnet_tls_t tls;
    tsnet_http1_resp_t resp;
    char body[BODY_MAX + 1];
    size_t body_len;
    uint8_t pub[TSNET_KEY_LEN];
};

tsnet_keyfetch_t *tsnet_keyfetch_start(const char *host, uint16_t port, int use_tls, uint16_t version, int timeout_ms)
{
    tsnet_keyfetch_t *k = tsnet_calloc(1, sizeof *k);
    if (k == NULL || strlen(host) >= sizeof k->host) {
        free(k);
        return NULL;
    }
    snprintf(k->host, sizeof k->host, "%s", host);
    char path[32];
    snprintf(path, sizeof path, "/key?v=%u", (unsigned)version);
    // Go's Host is the URL's: the port only when it isn't the scheme's default.
    if (port == (use_tls ? 443 : 80)) {
        snprintf(k->authority, sizeof k->authority, "%s", host);
    } else {
        snprintf(k->authority, sizeof k->authority, "%s:%u", host, (unsigned)port);
    }
    k->req_len = tsnet_http1_get_request(k->req, sizeof k->req, k->authority, path);
    k->use_tls = use_tls;
    k->deadline = tsnet_now_ms() + (uint64_t)timeout_ms;
    tsnet_http1_resp_init(&k->resp);
    k->fd = k->req_len < 0 ? -1 : tsnet_tcp_connect(host, port);
    if (k->fd < 0) {
        k->result = -1;
    }
    return k;
}

static int keyfetch_fail(tsnet_keyfetch_t *k, const char *why)
{
    if (why) {
        tsnet_log(TSNET_LOG_WARN, "control key: %s", why);
    }
    return k->result = -1;
}

int tsnet_keyfetch_step(tsnet_keyfetch_t *k)
{
    if (k->result != 0) {
        return k->result;
    }
    if (tsnet_now_ms() >= k->deadline) {
        return keyfetch_fail(k, "timed out");
    }
    if (!k->connected) {
        int c = tsnet_tcp_connected(k->fd);
        if (c < 0 || (c == 1 && k->use_tls && tsnet_tls_start(&k->tls, k->fd, k->host, TSNET_TLS_VERIFY) != 0)) {
            tsnet_log(TSNET_LOG_WARN, "control key: can't connect to %s", k->authority);
            return keyfetch_fail(k, NULL);
        }
        if (c == 0) {
            return 0;
        }
        k->connected = 1;
        k->tls_live = k->use_tls;
    }
    if (k->use_tls) {
        int h = tsnet_tls_handshake(&k->tls);
        if (h < 0) {
            return keyfetch_fail(k, NULL);
        }
        if (h == 0) {
            return 0;
        }
    }
    while (k->sent < k->req_len) {
        int n = k->use_tls ? tsnet_tls_write(&k->tls, k->req + k->sent, (size_t)(k->req_len - k->sent))
                           : tsnet_sock_write(k->fd, k->req + k->sent, (size_t)(k->req_len - k->sent));
        if (n < 0) {
            return keyfetch_fail(k, NULL);
        }
        if (n == 0) {
            return 0;
        }
        k->sent += n;
    }
    uint8_t buf[1024];
    int n;
    while ((n = k->use_tls ? tsnet_tls_read(&k->tls, buf, sizeof buf) : tsnet_sock_read(k->fd, buf, sizeof buf)) > 0) {
        size_t pos = 0;
        while (pos < (size_t)n && k->resp.state != TSNET_HTTP1_ERROR && k->resp.state != TSNET_HTTP1_DONE) {
            size_t took =
                tsnet_http1_resp_feed(&k->resp, buf + pos, (size_t)n - pos, (uint8_t *)k->body, BODY_MAX, &k->body_len);
            if (took == 0) {
                break;
            }
            pos += took;
        }
    }
    if (n < 0) {
        tsnet_http1_resp_eof(&k->resp); // Connection: close ends a body without a length
    }
    if (k->resp.state == TSNET_HTTP1_ERROR) {
        return keyfetch_fail(k, "bad HTTP response");
    }
    if (k->resp.state != TSNET_HTTP1_DONE) {
        return 0;
    }
    k->body[k->body_len] = '\0';
    if (k->resp.status != 200) {
        tsnet_log(TSNET_LOG_WARN, "control key: HTTP %d", k->resp.status);
        return keyfetch_fail(k, NULL);
    }
    if (tsnet_control_key_parse(k->body, k->body_len, k->pub) != 0) {
        return keyfetch_fail(k, "no Noise key in the response");
    }
    return k->result = 1;
}

int tsnet_keyfetch_poll(const tsnet_keyfetch_t *k, tsnet_poll_t *p)
{
    if (k->result != 0) {
        return 0;
    }
    // Wait to write only while connecting or with the request unsent: a connected socket is always writable, and
    // waiting on it during the TLS handshake would spin.
    int ready = k->connected && (!k->use_tls || k->tls.done);
    *p = (tsnet_poll_t){k->fd, !k->connected || (ready && k->sent < k->req_len), 0, 0};
    return 1;
}

int tsnet_keyfetch_wait_ms(const tsnet_keyfetch_t *k)
{
    uint64_t now = tsnet_now_ms();
    if (k->result != 0 || now >= k->deadline) {
        return 0;
    }
    return k->deadline - now < 50 ? (int)(k->deadline - now) : 50; // TLS can want to write, which the poll doesn't watch
}

void tsnet_keyfetch_key(const tsnet_keyfetch_t *k, uint8_t pub[TSNET_KEY_LEN])
{
    memcpy(pub, k->pub, TSNET_KEY_LEN);
}

void tsnet_keyfetch_free(tsnet_keyfetch_t *k)
{
    if (k == NULL) {
        return;
    }
    if (k->tls_live) {
        tsnet_tls_free(&k->tls);
    }
    tsnet_sock_close(k->fd);
    free(k);
}

int tsnet_control_key_fetch(const char *host, uint16_t port, int use_tls, uint16_t version, uint8_t pub[TSNET_KEY_LEN],
                            int timeout_ms)
{
    tsnet_keyfetch_t *k = tsnet_keyfetch_start(host, port, use_tls, version, timeout_ms);
    if (k == NULL) {
        return -1;
    }
    int r;
    while ((r = tsnet_keyfetch_step(k)) == 0) {
        tsnet_poll_t p;
        tsnet_poll(&p, tsnet_keyfetch_poll(k, &p), tsnet_keyfetch_wait_ms(k));
    }
    if (r == 1) {
        tsnet_keyfetch_key(k, pub);
    }
    tsnet_keyfetch_free(k);
    return r == 1 ? 0 : -1;
}
