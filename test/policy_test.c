// Host test of tsnet's control-client timing: util/backoff's formula, direct.go's rate-limit rules and
// auto.go's cap, under ASan and UBSan. HTTP dates are checked against Python's email.utils.
#include <stdio.h>
#include <string.h>
#include "policy.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

int main(void)
{
    // Backoff: n^2 * 10 ms, capped at 30 s, times [0.5, 1.5): rnd 0 gives half, 2^31 exactly the base, near 2^32 1.5x.
    tsnet_backoff_t b;
    tsnet_backoff_init(&b, TSNET_BACKOFF_MAX_MS);
    EXPECT(tsnet_backoff_fail(&b, 0x80000000u) == 10);   // n=1: 10 ms
    EXPECT(tsnet_backoff_fail(&b, 0x80000000u) == 40);   // n=2: 40 ms
    EXPECT(tsnet_backoff_fail(&b, 0) == 45);             // n=3: 90 ms, x0.5
    EXPECT(tsnet_backoff_fail(&b, 0xffffffffu) == 239);  // n=4: 160 ms, x1.5 less a hair
    for (int i = 0; i < 100; i++) {
        tsnet_backoff_fail(&b, 0x80000000u);
    }
    EXPECT(tsnet_backoff_fail(&b, 0x80000000u) == 30000); // capped
    EXPECT(tsnet_backoff_fail(&b, 0xffffffffu) == 44999); // the jitter comes after the cap
    tsnet_backoff_reset(&b);
    EXPECT(tsnet_backoff_fail(&b, 0x80000000u) == 10);   // a success starts over
    // n=55 is the first capped step (55^2 * 10 = 30250).
    tsnet_backoff_init(&b, TSNET_BACKOFF_MAX_MS);
    for (int i = 0; i < 54; i++) {
        tsnet_backoff_fail(&b, 0x80000000u);
    }
    EXPECT(b.n == 54 && tsnet_backoff_fail(&b, 0x80000000u) == 30000);

    // Which responses are rate limits.
    EXPECT(tsnet_rate_limited(429, false) && tsnet_rate_limited(429, true));
    EXPECT(tsnet_rate_limited(503, true) && !tsnet_rate_limited(503, false));
    EXPECT(!tsnet_rate_limited(500, true) && !tsnet_rate_limited(404, true) && !tsnet_rate_limited(200, true));

    // HTTP dates: the three forms http.ParseTime takes.
    int64_t t;
    EXPECT(tsnet_http_date("Wed, 21 Oct 2026 07:28:00 GMT", &t) == 0 && t == 1792567680);
    EXPECT(tsnet_http_date("Wednesday, 21-Oct-26 07:28:00 GMT", &t) == 0 && t == 1792567680);
    EXPECT(tsnet_http_date("Wed Oct 21 07:28:00 2026", &t) == 0 && t == 1792567680);
    EXPECT(tsnet_http_date("Thu Jan  1 00:00:10 1970", &t) == 0 && t == 10);
    static const char *BAD[] = {"", "tomorrow", "Wed, 21 Oct 2026 07:28:00 PST", "Wed, 21 Foo 2026 07:28:00 GMT",
                                "Wed, 21 Oct 2026 07:28:00 GMT x", "Wed, 32 Oct 2026 07:28:00 GMT", "Wed, 21 Oct 2026"};
    for (size_t i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        EXPECT(tsnet_http_date(BAD[i], &t) == -1);
    }

    // Retry-After: seconds, a date, the 5-10 s default for anything else, the 5-minute cap.
    const int64_t now = 1792567680;
    EXPECT(tsnet_retry_after_ms("7", now, 0) == 7000);
    EXPECT(tsnet_retry_after_ms("Wed, 21 Oct 2026 07:28:30 GMT", now, 0) == 30000);
    EXPECT(tsnet_retry_after_ms("1800", now, 0) == TSNET_RETRY_WINDOW_MS); // 30 min, capped at 5
    EXPECT(tsnet_retry_after_ms("3600", now, 0) == TSNET_RETRY_WINDOW_MS); // an hour is still valid, then capped
    EXPECT(tsnet_retry_after_ms("3601", now, 0) == 5000);                  // over an hour: the default
    EXPECT(tsnet_retry_after_ms("0", now, 0) == 5000 && tsnet_retry_after_ms("-5", now, 0) == 5000);
    EXPECT(tsnet_retry_after_ms(NULL, now, 0xffffffffu) == 9999);         // 5 s + up to 5 s
    EXPECT(tsnet_retry_after_ms("soon", now, 0x80000000u) == 7500);
    EXPECT(tsnet_retry_after_ms("Wed, 21 Oct 2026 07:27:00 GMT", now, 0) == 5000); // in the past
    // A clock that isn't set yet (1970) turns a real date into hours away: the default, as in Go.
    EXPECT(tsnet_retry_after_ms("Wed, 21 Oct 2026 07:28:30 GMT", 0, 0) == 5000);
    EXPECT(tsnet_retry_after_ms("99999999999999999999", now, 0) == 5000); // doesn't parse as a number

    // A register's response (doLogin's order: rate limit, status, Error, NodeKeySignature/NodeKeyExpired, AuthURL).
    tsnet_register_resp_t ok = {0}, refused = {0}, expired = {0}, signed_ = {0}, url = {0}, both = {0};
    snprintf(refused.error, sizeof refused.error, "invalid key");
    expired.node_key_expired = true;
    signed_.has_node_key_signature = true;
    snprintf(url.auth_url, sizeof url.auth_url, "https://login.example/a/1");
    snprintf(both.error, sizeof both.error, "no");
    both.node_key_expired = true;
    EXPECT(tsnet_login_outcome(200, false, &ok, false) == TSNET_LOGIN_OK);
    EXPECT(tsnet_login_outcome(200, false, &ok, true) == TSNET_LOGIN_OK);
    EXPECT(tsnet_login_outcome(429, false, NULL, false) == TSNET_LOGIN_RATE_LIMITED);
    EXPECT(tsnet_login_outcome(503, true, NULL, false) == TSNET_LOGIN_RATE_LIMITED);
    EXPECT(tsnet_login_outcome(503, false, NULL, false) == TSNET_LOGIN_FAILED);
    EXPECT(tsnet_login_outcome(0, false, NULL, false) == TSNET_LOGIN_FAILED);   // no response
    EXPECT(tsnet_login_outcome(500, false, &ok, false) == TSNET_LOGIN_FAILED); // a body doesn't make a 500 good
    EXPECT(tsnet_login_outcome(200, false, NULL, false) == TSNET_LOGIN_FAILED); // didn't parse
    EXPECT(tsnet_login_outcome(200, false, &refused, false) == TSNET_LOGIN_REFUSED);
    EXPECT(tsnet_login_outcome(200, false, &both, false) == TSNET_LOGIN_REFUSED); // Error comes first
    EXPECT(tsnet_login_outcome(200, false, &expired, false) == TSNET_LOGIN_REGEN);
    EXPECT(tsnet_login_outcome(200, false, &expired, true) == TSNET_LOGIN_FAILED);
    EXPECT(tsnet_login_outcome(200, false, &signed_, false) == TSNET_LOGIN_REGEN);
    EXPECT(tsnet_login_outcome(200, false, &signed_, true) == TSNET_LOGIN_FAILED);
    EXPECT(tsnet_login_outcome(200, false, &url, false) == TSNET_LOGIN_AUTH_URL);

    // The self node's key expiry (ipnlocal keyExpired), and headscale's placeholder for a deleted node.
    tsnet_node_t self = {0};
    EXPECT(!tsnet_self_expired(NULL, now));
    EXPECT(!tsnet_self_expired(&self, now)); // 0: doesn't expire
    self.key_expiry = now + 1;
    EXPECT(!tsnet_self_expired(&self, now));
    self.key_expiry = now - 1;
    EXPECT(tsnet_self_expired(&self, now));
    self.key_expiry = 1; // headscale's "1970-01-01T00:00:01Z"
    EXPECT(tsnet_self_expired(&self, now));
    EXPECT(!tsnet_self_expired(&self, 0)); // a device clock that isn't set yet can't tell
    self.key_expiry = 0;
    self.expired = true;
    EXPECT(!tsnet_self_expired(&self, now)); // ipnlocal reads only the key expiry

    // The end of a map poll.
    EXPECT(tsnet_map_outcome(200, false) == TSNET_MAP_ENDED);
    EXPECT(tsnet_map_outcome(0, false) == TSNET_MAP_ENDED);
    EXPECT(tsnet_map_outcome(500, false) == TSNET_MAP_ENDED);
    EXPECT(tsnet_map_outcome(404, false) == TSNET_MAP_REMOVED);
    EXPECT(tsnet_map_outcome(429, false) == TSNET_MAP_RATE_LIMITED);
    EXPECT(tsnet_map_outcome(503, true) == TSNET_MAP_RATE_LIMITED);
    EXPECT(tsnet_map_outcome(503, false) == TSNET_MAP_ENDED);

    // magicsock's DERP: the reader's backoff caps at 5 s; a non-home region closes after more than 60 s unwritten.
    tsnet_backoff_init(&b, TSNET_DERP_BACKOFF_MAX_MS);
    for (int i = 0; i < 30; i++) {
        tsnet_backoff_fail(&b, 0x80000000u);
    }
    EXPECT(tsnet_backoff_fail(&b, 0x80000000u) == 5000);
    EXPECT(!tsnet_derp_idle(2, 1, 1000, 61000));  // exactly 60 s: not yet (lastWrite.Before(tooOld))
    EXPECT(tsnet_derp_idle(2, 1, 999, 61000));    // a millisecond more
    EXPECT(!tsnet_derp_idle(1, 1, 0, 1000000));   // the home region never goes idle
    EXPECT(!tsnet_derp_idle(2, 1, 0, 30000));     // early in the clock: no wrap
    // pickDERPFallback: the home region when there is one, else one of the map's.
    int ids[3] = {1, 2, 10};
    EXPECT(tsnet_derp_fallback(ids, 3, 2, 7) == 2);
    EXPECT(tsnet_derp_fallback(ids, 3, 0, 7) == 2);  // 7 % 3
    EXPECT(tsnet_derp_fallback(ids, 3, 0, 9) == 1);
    EXPECT(tsnet_derp_fallback(ids, 0, 0, 9) == 0);  // no regions

    if (failures == 0) {
        printf("tsnet policy_test: ok\n");
    }
    return failures != 0;
}
