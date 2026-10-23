// The control client's timing decisions. See policy.h.
#include "policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void tsnet_backoff_init(tsnet_backoff_t *b, uint32_t max_ms)
{
    b->n = 0;
    b->max_ms = max_ms;
}

uint32_t tsnet_backoff_fail(tsnet_backoff_t *b, uint32_t rnd)
{
    if (b->n < 100000) {
        b->n++;
    }
    uint64_t d = (uint64_t)b->n * (uint64_t)b->n * 10; // n^2 backoff timer is a little smoother than 2^n
    if (d > b->max_ms) {
        d = b->max_ms;
    }
    // Randomize the delay between 0.5-1.5 x msec: d * (0.5 + rnd / 2^32).
    return (uint32_t)(d / 2 + (d * (uint64_t)rnd >> 32));
}

void tsnet_backoff_reset(tsnet_backoff_t *b)
{
    b->n = 0;
}

bool tsnet_derp_idle(int region, int home, uint64_t last_write_ms, uint64_t now_ms)
{
    return region != home && now_ms > TSNET_DERP_INACTIVE_MS && last_write_ms < now_ms - TSNET_DERP_INACTIVE_MS;
}

int tsnet_derp_fallback(const int *ids, size_t n, int home, uint32_t rnd)
{
    if (home != 0) {
        return home;
    }
    return n == 0 ? 0 : ids[rnd % n];
}

bool tsnet_rate_limited(int status, bool has_retry_after)
{
    return status == 429 || (status == 503 && has_retry_after);
}

tsnet_login_outcome_t tsnet_login_outcome(int status, bool has_retry_after, const tsnet_register_resp_t *resp,
                                          bool regen)
{
    if (tsnet_rate_limited(status, has_retry_after)) {
        return TSNET_LOGIN_RATE_LIMITED;
    }
    if (status != 200 || resp == NULL) {
        return TSNET_LOGIN_FAILED; // "register request: http %d" and decode errors
    }
    if (resp->error[0]) {
        return TSNET_LOGIN_REFUSED;
    }
    if (resp->has_node_key_signature || resp->node_key_expired) {
        // A first attempt regenerates. On the regen attempt Go errors for NodeKeyExpired ("weird: regen=true but server
        // says NodeKeyExpired"). For NodeKeySignature it ignores the second mustRegen without keeping the key, a Tailnet
        // Lock re-sign tsnet doesn't do: a failure here too.
        return regen ? TSNET_LOGIN_FAILED : TSNET_LOGIN_REGEN;
    }
    if (resp->auth_url[0]) {
        return TSNET_LOGIN_AUTH_URL;
    }
    return TSNET_LOGIN_OK;
}

bool tsnet_self_expired(const tsnet_node_t *self, int64_t now_unix)
{
    return self != NULL && self->key_expiry != 0 && self->key_expiry < now_unix;
}

tsnet_map_outcome_t tsnet_map_outcome(int status, bool has_retry_after)
{
    if (tsnet_rate_limited(status, has_retry_after)) {
        return TSNET_MAP_RATE_LIMITED;
    }
    return status == 404 ? TSNET_MAP_REMOVED : TSNET_MAP_ENDED;
}

static int month(const char *m)
{
    static const char *M[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    for (int i = 0; i < 12; i++) {
        if (strncmp(m, M[i], 3) == 0 && m[3] == '\0') {
            return i + 1;
        }
    }
    return 0;
}

static int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

int tsnet_http_date(const char *s, int64_t *out)
{
    char wd[16], mon[4], tz[4];
    int d, y, h, mi, sec, n = 0;
    if (s == NULL) {
        return -1;
    }
    int ok = 0;
    // RFC 1123: "Mon, 02 Jan 2006 15:04:05 GMT"
    if (sscanf(s, "%3[A-Za-z], %2d %3s %4d %2d:%2d:%2d %3s%n", wd, &d, mon, &y, &h, &mi, &sec, tz, &n) == 8 && s[n] == '\0') {
        ok = 1;
    }
    // RFC 850: "Monday, 02-Jan-06 15:04:05 GMT" (a two-digit year: 69 and later is 19xx, as Go's)
    n = 0;
    if (!ok && sscanf(s, "%15[A-Za-z], %2d-%3s-%2d %2d:%2d:%2d %3s%n", wd, &d, mon, &y, &h, &mi, &sec, tz, &n) == 8 &&
        s[n] == '\0') {
        y += y >= 69 ? 1900 : 2000;
        ok = 1;
    }
    // asctime: "Mon Jan  2 15:04:05 2006"
    n = 0;
    if (!ok && sscanf(s, "%3[A-Za-z] %3s %d %2d:%2d:%2d %4d%n", wd, mon, &d, &h, &mi, &sec, &y, &n) == 7 && s[n] == '\0') {
        strcpy(tz, "GMT");
        ok = 1;
    }
    if (!ok) {
        return -1;
    }
    int m = month(mon);
    if (m == 0 || strcmp(tz, "GMT") != 0 || d < 1 || d > 31 || h > 23 || mi > 59 || sec > 60 || y < 1) {
        return -1;
    }
    *out = days_from_civil(y, (unsigned)m, (unsigned)d) * 86400 + h * 3600 + mi * 60 + sec;
    return 0;
}

uint32_t tsnet_retry_after_ms(const char *header, int64_t now_unix, uint32_t rnd)
{
    int64_t ms = 0;
    if (header && header[0]) {
        char *end;
        long long secs = strtoll(header, &end, 10);
        int64_t t;
        if (end != header && *end == '\0') { // strconv.Atoi
            ms = secs > INT64_MAX / 1000 || secs < INT64_MIN / 1000 ? -1 : secs * 1000;
        } else if (tsnet_http_date(header, &t) == 0) {
            ms = (t - now_unix) * 1000; // time.Until
        }
    }
    // If the server didn't give us a valid Retry-After, 5 s plus up to 5 s at random.
    if (ms <= 0 || ms > 3600000) {
        ms = 5000 + (int64_t)(((uint64_t)rnd * 5000) >> 32);
    }
    return ms > TSNET_RETRY_WINDOW_MS ? TSNET_RETRY_WINDOW_MS : (uint32_t)ms;
}
