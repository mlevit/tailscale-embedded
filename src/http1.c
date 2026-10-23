// The dial's HTTP/1.1. See http1.h.
#include "http1.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

void tsnet_base64(char *out, const uint8_t *in, size_t len)
{
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < len) {
            v |= (uint32_t)in[i + 1] << 8;
        }
        if (i + 2 < len) {
            v |= in[i + 2];
        }
        out[o++] = A[(v >> 18) & 63];
        out[o++] = A[(v >> 12) & 63];
        out[o++] = i + 1 < len ? A[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < len ? A[v & 63] : '=';
    }
    out[o] = '\0';
}

int tsnet_http1_upgrade_request(char *out, size_t cap, const char *host, uint16_t port, const uint8_t *init,
                                size_t init_len)
{
    char b64[4 * ((TSNET_NOISE_INIT_MAX + 2) / 3) + 1];
    if (init_len > TSNET_NOISE_INIT_MAX) {
        return -1;
    }
    tsnet_base64(b64, init, init_len);
    // controlhttp tryURLUpgrade's request, as Go's transport writes it: Host is the URL's host:port, a POST with no
    // body says Content-Length: 0, and DisableCompression leaves out Accept-Encoding.
    int n = snprintf(out, cap,
                     "POST /ts2021 HTTP/1.1\r\nHost: %s:%u\r\nUser-Agent: tsnet\r\nContent-Length: 0\r\n"
                     "Connection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nX-Tailscale-Handshake: %s\r\n\r\n",
                     host, (unsigned)port, b64);
    return n > 0 && (size_t)n < cap ? n : -1;
}

static int safe_name(const char *s);

int tsnet_http1_get_request(char *out, size_t cap, const char *host, const char *path)
{
    if (!safe_name(host)) {
        return -1;
    }
    int n = snprintf(out, cap, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: tsnet\r\nConnection: close\r\n\r\n", path,
                     host);
    return n > 0 && (size_t)n < cap ? n : -1;
}

// A host or node name from the DERP map, which the control server sends: letters, digits and ".-_:[]" only, so it can't
// end the line or add a header.
static int safe_name(const char *s)
{
    if (!*s) {
        return 0;
    }
    for (; *s; s++) {
        char c = *s;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strchr(".-_:[]", c))) {
            return 0;
        }
    }
    return 1;
}

int tsnet_http1_derp_request(char *out, size_t cap, const char *host, const char *ideal_node)
{
    // derphttp connect's request, as Go's Request.Write puts it: Host and User-Agent, then the headers in key order.
    if (!safe_name(host) || (ideal_node && !safe_name(ideal_node))) {
        return -1;
    }
    int n = snprintf(out, cap, "GET /derp HTTP/1.1\r\nHost: %s\r\nUser-Agent: tsnet\r\nConnection: Upgrade\r\n%s%s%s"
                               "Upgrade: DERP\r\n\r\n",
                     host, ideal_node ? "Ideal-Node: " : "", ideal_node ? ideal_node : "", ideal_node ? "\r\n" : "");
    return n > 0 && (size_t)n < cap ? n : -1;
}

void tsnet_http1_resp_eof(tsnet_http1_resp_t *r)
{
    // RFC 9112 6.3: with neither Content-Length nor chunked, the body runs to the close (Go reads it to EOF). Any other
    // body cut short by the close is an error.
    if (r->state == TSNET_HTTP1_BODY && !r->chunked && r->content_length < 0) {
        r->state = TSNET_HTTP1_DONE;
    } else if (r->state != TSNET_HTTP1_DONE) {
        r->state = TSNET_HTTP1_ERROR;
    }
}

void tsnet_http1_resp_init(tsnet_http1_resp_t *r)
{
    memset(r, 0, sizeof *r);
    r->state = TSNET_HTTP1_HEAD;
    r->content_length = -1;
}

// Copies a header value, trimmed, into dst (cut to fit).
static void copy_value(char *dst, size_t cap, const char *v, size_t len)
{
    while (len > 0 && (*v == ' ' || *v == '\t')) {
        v++;
        len--;
    }
    while (len > 0 && (v[len - 1] == ' ' || v[len - 1] == '\t')) {
        len--;
    }
    if (len >= cap) {
        len = cap - 1;
    }
    memcpy(dst, v, len);
    dst[len] = '\0';
}

// Parses the complete head (head[0 .. head_len), ending in CRLF CRLF). Returns 0 or -1.
static int parse_head(tsnet_http1_resp_t *r)
{
    char *p = r->head, *end = r->head + r->head_len;
    char *eol = memchr(p, '\r', (size_t)(end - p));
    if (eol == NULL || eol - p < 12 || strncmp(p, "HTTP/1.", 7) != 0 || p[8] != ' ') {
        return -1;
    }
    if (!isdigit((unsigned char)p[9]) || !isdigit((unsigned char)p[10]) || !isdigit((unsigned char)p[11])) {
        return -1;
    }
    r->status = (p[9] - '0') * 100 + (p[10] - '0') * 10 + (p[11] - '0');
    p = eol + 2;
    if (eol[1] != '\n') {
        return -1;
    }
    while (p < end && !(p[0] == '\r' && p + 1 < end && p[1] == '\n')) {
        eol = memchr(p, '\r', (size_t)(end - p));
        if (eol == NULL || eol + 1 >= end || eol[1] != '\n') {
            return -1;
        }
        char *colon = memchr(p, ':', (size_t)(eol - p));
        if (colon != NULL) {
            size_t name_len = (size_t)(colon - p);
            const char *v = colon + 1;
            size_t vlen = (size_t)(eol - v);
            if (name_len == 7 && strncasecmp(p, "Upgrade", 7) == 0) {
                copy_value(r->upgrade, sizeof r->upgrade, v, vlen);
            } else if (name_len == 14 && strncasecmp(p, "Content-Length", 14) == 0) {
                char num[24];
                copy_value(num, sizeof num, v, vlen);
                char *e;
                long long n = strtoll(num, &e, 10);
                if (num[0] == '\0' || *e != '\0' || n < 0) {
                    return -1;
                }
                r->content_length = n;
            } else if (name_len == 17 && strncasecmp(p, "Transfer-Encoding", 17) == 0) {
                char te[48];
                copy_value(te, sizeof te, v, vlen);
                r->chunked = strcasecmp(te, "chunked") == 0;
            }
        }
        p = eol + 2;
    }
    if (r->chunked) {
        r->content_length = -1; // RFC 9112 6.3: chunked wins over a Content-Length
    }
    r->left = r->content_length;
    return 0;
}

enum { CHUNK_SIZE, CHUNK_DATA, CHUNK_DATA_END, CHUNK_TRAILER };

// Appends body bytes, refusing more than the caller's buffer holds.
static int put_body(const uint8_t *src, size_t n, uint8_t *body, size_t cap, size_t *body_len)
{
    if (n > cap - *body_len) {
        return -1;
    }
    memcpy(body + *body_len, src, n);
    *body_len += n;
    return 0;
}

// One line of the chunked framing (a size line, the CRLF after data, a trailer line) is gathered in chunk_line.
static int chunk_line_byte(tsnet_http1_resp_t *r, uint8_t c, bool *line_done)
{
    *line_done = false;
    if (c == '\n') {
        if (r->chunk_line_len == 0 || r->chunk_line[r->chunk_line_len - 1] != '\r') {
            return -1;
        }
        r->chunk_line[--r->chunk_line_len] = '\0';
        *line_done = true;
        return 0;
    }
    if (r->chunk_line_len + 1 >= sizeof r->chunk_line) {
        return -1;
    }
    r->chunk_line[r->chunk_line_len++] = (char)c;
    return 0;
}

size_t tsnet_http1_resp_feed(tsnet_http1_resp_t *r, const uint8_t *data, size_t len, uint8_t *body, size_t body_cap,
                             size_t *body_len)
{
    size_t i = 0;
    if (r->state == TSNET_HTTP1_HEAD) {
        while (i < len) {
            if (r->head_len + 1 >= sizeof r->head) {
                r->state = TSNET_HTTP1_ERROR;
                return i;
            }
            r->head[r->head_len++] = (char)data[i++];
            if (r->head_len >= 4 && memcmp(r->head + r->head_len - 4, "\r\n\r\n", 4) == 0) {
                r->head[r->head_len] = '\0';
                r->state = parse_head(r) == 0 ? TSNET_HTTP1_BODY : TSNET_HTTP1_ERROR;
                if (r->state == TSNET_HTTP1_BODY && r->content_length == 0) {
                    r->state = TSNET_HTTP1_DONE;
                }
                return i; // only the head's bytes: what follows a 101 is the new protocol's
            }
        }
        return i;
    }
    if (r->state != TSNET_HTTP1_BODY) {
        return 0;
    }
    if (!r->chunked) {
        size_t n = len - i;
        if (r->left >= 0 && (long long)n > r->left) {
            n = (size_t)r->left;
        }
        if (put_body(data + i, n, body, body_cap, body_len) != 0) {
            r->state = TSNET_HTTP1_ERROR;
            return i;
        }
        i += n;
        if (r->left >= 0) {
            r->left -= (long long)n;
            if (r->left == 0) {
                r->state = TSNET_HTTP1_DONE;
            }
        }
        return i;
    }
    while (i < len && r->state == TSNET_HTTP1_BODY) {
        bool line_done;
        switch (r->chunk_state) {
        case CHUNK_SIZE:
            if (chunk_line_byte(r, data[i++], &line_done) != 0) {
                r->state = TSNET_HTTP1_ERROR;
                break;
            }
            if (line_done) {
                char *semi = strchr(r->chunk_line, ';'); // chunk extensions are ignored
                if (semi) {
                    *semi = '\0';
                }
                char *e;
                long long n = strtoll(r->chunk_line, &e, 16);
                if (r->chunk_line[0] == '\0' || *e != '\0' || n < 0 || strlen(r->chunk_line) > 15) {
                    r->state = TSNET_HTTP1_ERROR;
                    break;
                }
                r->chunk_line_len = 0;
                r->left = n;
                r->chunk_state = n == 0 ? CHUNK_TRAILER : CHUNK_DATA;
            }
            break;
        case CHUNK_DATA: {
            size_t n = len - i;
            if ((long long)n > r->left) {
                n = (size_t)r->left;
            }
            if (put_body(data + i, n, body, body_cap, body_len) != 0) {
                r->state = TSNET_HTTP1_ERROR;
                break;
            }
            i += n;
            r->left -= (long long)n;
            if (r->left == 0) {
                r->chunk_state = CHUNK_DATA_END;
            }
            break;
        }
        case CHUNK_DATA_END:
            if (chunk_line_byte(r, data[i++], &line_done) != 0) {
                r->state = TSNET_HTTP1_ERROR;
                break;
            }
            if (line_done) {
                if (r->chunk_line[0] != '\0') { // the data must end with exactly CRLF
                    r->state = TSNET_HTTP1_ERROR;
                    break;
                }
                r->chunk_state = CHUNK_SIZE;
            }
            break;
        case CHUNK_TRAILER:
            if (chunk_line_byte(r, data[i++], &line_done) != 0) {
                r->state = TSNET_HTTP1_ERROR;
                break;
            }
            if (line_done) {
                if (r->chunk_line[0] == '\0') {
                    r->state = TSNET_HTTP1_DONE; // the empty line after any trailers
                }
                r->chunk_line_len = 0;
            }
            break;
        }
    }
    return i;
}
