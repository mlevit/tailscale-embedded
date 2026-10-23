#pragma once
// The control client's timing decisions, pure: util/backoff's Backoff, and direct.go's rate-limit rules
// (isRateLimitedResponse, parseRateLimitError) with auto.go's cap (maxRetryWindow).
#include <stdbool.h>
#include <stdint.h>
#include "mapresp.h"
#include "tailcfg.h"

#define TSNET_BACKOFF_MAX_MS 30000      // each routine's NewBackoff(..., 30*time.Second)
#define TSNET_RETRY_WINDOW_MS 300000    // maxRetryWindow
#define TSNET_WATCHDOG_MS 120000        // direct.go watchdogTimeout

typedef struct {
    int n; // consecutive failures
    uint32_t max_ms;
} tsnet_backoff_t;

void tsnet_backoff_init(tsnet_backoff_t *b, uint32_t max_ms);
// Backoff.BackOff with an error: one more failure, and the wait before the next try: min(n²·10 ms, max), then times a
// random factor in [0.5, 1.5) (after the cap, as Go does, so up to 1.5·max). `rnd` is a random 32-bit value.
uint32_t tsnet_backoff_fail(tsnet_backoff_t *b, uint32_t rnd);
// Backoff.Reset (and BackOff with no error).
void tsnet_backoff_reset(tsnet_backoff_t *b);

// isRateLimitedResponse: 429, or 503 with a Retry-After header.
bool tsnet_rate_limited(int status, bool has_retry_after);
// parseRateLimitError, then waitRetryAfter's cap: Retry-After in seconds or as an HTTP date (http.ParseTime's three
// forms) against `now_unix`; missing, unparseable, not in the future or over an hour gives 5 to 10 s (from `rnd`); the
// result is at most TSNET_RETRY_WINDOW_MS.
uint32_t tsnet_retry_after_ms(const char *header, int64_t now_unix, uint32_t rnd);

// What a register's response means (doLogin, then authRoutine).
typedef enum {
    TSNET_LOGIN_OK,           // commit the node key: logged in
    TSNET_LOGIN_RATE_LIMITED, // wait Retry-After (tsnet_retry_after_ms), not the backoff
    TSNET_LOGIN_FAILED,       // back off and try again
    TSNET_LOGIN_REFUSED,      // the server's Error (an auth key it won't take): needs auth, back off
    TSNET_LOGIN_REGEN,        // doLoginOrRegen's mustRegen: again at once with a new node key
    TSNET_LOGIN_AUTH_URL,     // a person must visit AuthURL: needs auth, back off (an embedded node can't wait on the URL)
} tsnet_login_outcome_t;
// `status` is 0 when the request failed before a response. `resp` is the parsed 200 body, or NULL if it didn't parse.
tsnet_login_outcome_t tsnet_login_outcome(int status, bool has_retry_after, const tsnet_register_resp_t *resp,
                                          bool regen);

// What the end of a map poll means (sendMapRequest's errors, then mapRoutine). Every end backs off, except a rate
// limit, which waits Retry-After.
typedef enum {
    TSNET_MAP_ENDED,        // the stream ended or failed: back off, poll again
    TSNET_MAP_RATE_LIMITED, // wait Retry-After
    TSNET_MAP_REMOVED,      // 404, ErrNodeRemoved: report it, back off, poll again
} tsnet_map_outcome_t;
tsnet_map_outcome_t tsnet_map_outcome(int status, bool has_retry_after);

// ipnlocal's keyExpired: the netmap's self node has a key expiry before `now_unix` (SelfKeyExpiry; the node's Expired
// flag isn't read, as ipnlocal doesn't). headscale answers a deleted node's poll this way (a placeholder node, expired
// in 1970), where Tailscale's server answers 404. NULL (no self node yet) is not expired.
bool tsnet_self_expired(const tsnet_node_t *self, int64_t now_unix);

// magicsock's DERP decisions (wgengine/magicsock/derp.go).
#define TSNET_DERP_BACKOFF_MAX_MS 5000 // runDerpReader's backoff.NewBackoff(..., 5*time.Second)
#define TSNET_DERP_INACTIVE_MS 60000   // derpInactiveCleanupTime
#define TSNET_DERP_CLEAN_MS 15000      // derpCleanStaleInterval

// cleanStaleDerp: a connection to a region that isn't the home one closes once nothing was written to it for more
// than 60 s (lastWrite before now - derpInactiveCleanupTime).
bool tsnet_derp_idle(int region, int home, uint64_t last_write_ms, uint64_t now_ms);
// pickDERPFallback: the home region if there is one; else one of the map's regions (`ids`), picked by `rnd`; 0 when
// the map has none. (Go picks with a seed from the Conn's address, so a node keeps its pick; the caller keeps it too,
// as the home.)
int tsnet_derp_fallback(const int *ids, size_t n, int home, uint32_t rnd);

// http.ParseTime: RFC 1123 ("Mon, 02 Jan 2006 15:04:05 GMT"), RFC 850 ("Monday, 02-Jan-06 15:04:05 GMT") or asctime
// ("Mon Jan  2 15:04:05 2006"). Returns 0 with unix seconds, or -1.
int tsnet_http_date(const char *s, int64_t *out);
