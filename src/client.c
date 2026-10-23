// tsnet's control client. See client.h. The Go it follows is control/controlclient (auto.go's authRoutine and
// mapRoutine, direct.go's doLogin, sendMapRequest and answerPing) and control/ts2021 (the connection).
//
// The h2 callbacks only record what they saw (they mustn't call tsnet_h2). The step acts on it after the feed returns.
#include "platform.h"
#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "controlhttp.h"
#include "controlkey.h"
#include "h2.h"
#include "mapmsg.h"
#include "mapresp.h"
#include "noise.h"
#include "policy.h"
#include "tailcfg.h"

#define DIAL_TIMEOUT_MS 10000 // ts2021 dial with no dial plan: 5 s, plus 5 s for the handshake
#define KEY_TIMEOUT_MS 30000
#define PING_TIMEOUT_MS 15000 // answerHeadPing
#define BODY_KEEP 2048        // a register response, or the start of an error body
#define POLL_MAX_WAIT_MS 1000
#define TSNET_CLIENT_EPS 32 // endpoints kept for the MapRequest (selfeps.h's TSNET_SELFEPS_MAX)

// One request on the connection, and what its callbacks saw.
typedef struct {
    uint32_t id; // 0: none
    int status;  // 0 until the head arrives
    bool ended;
    int err; // tsnet_h2's end code (0: the whole response)
    bool has_retry_after;
    char retry_after[64];
    uint8_t body[BODY_KEEP + 1];
    size_t body_len;
} rq_t;

struct tsnet_client {
    // configuration
    char host[256], authority[264]; // authority: the URL's host[:port] as written (Go's request URL)
    uint16_t port;
    int https, http_port, https_port;
    char auth_key[256];
    char hostname[64], ipn_version[64], os[32], os_version[64], machine[32];
    tsnet_client_cfg_t cfg;
    tsnet_identity_t id;
    tsnet_client_state_t state;
    char detail[128]; // the reason given with the state
    // the server's key (fetched once, as Direct caches serverNoiseKey)
    bool have_key;
    uint8_t control_pub[TSNET_KEY_LEN];
    tsnet_keyfetch_t *kf;
    // the connection (ts2021's single conn)
    tsnet_dial_t *dial;
    tsnet_ctrl_conn_t *conn;
    tsnet_h2_t *h2;
    // login (authRoutine)
    bool logged_in, regen;
    uint64_t auth_next;
    tsnet_backoff_t auth_bo;
    rq_t reg;
    uint8_t try_key[TSNET_KEY_LEN], old_key[TSNET_KEY_LEN];
    // the map poll (mapRoutine)
    rq_t map;
    uint64_t map_next, watchdog;
    tsnet_backoff_t map_bo;
    tsnet_mapmsg_t *mm;
    tsnet_netmap_t nm;
    bool map_bad;     // a message didn't decode, or the first lacked Node: the poll ends
    bool in_map_poll; // a 200 is in for the current poll
    // PingRequest's HEAD
    rq_t ping;
    uint64_t ping_deadline;
    char ping_url[512], ping_pending[512];
    // What magicsock tells control (Direct's discoPubKey, endpoints and netinfo). A change is a lite map update
    // (updateRoutine): `gen` counts changes, `informed` is the last the server took, `sent` the one in flight.
    uint8_t disco_pub[TSNET_KEY_LEN];
    tsnet_addrport_t eps[TSNET_CLIENT_EPS];
    int ep_types[TSNET_CLIENT_EPS];
    size_t n_eps;
    bool have_netinfo;
    tsnet_net_info_t netinfo;
    uint64_t gen, informed, sent;
    rq_t upd;
    uint64_t upd_next;
    tsnet_backoff_t upd_bo;
    uint8_t pt[TSNET_NOISE_MAX_PLAINTEXT];
};

static uint32_t rnd32(void)
{
    uint32_t r = 0;
    tsnet_random(&r, sizeof r);
    return r;
}

// Tells the app of a new state, or of NEEDS_AUTH for a new reason.
static void set_state(tsnet_client_t *c, tsnet_client_state_t s, const char *detail)
{
    if (c->state == s && (s != TSNET_CLIENT_NEEDS_AUTH || strncmp(c->detail, detail, sizeof c->detail - 1) == 0)) {
        return;
    }
    c->state = s;
    snprintf(c->detail, sizeof c->detail, "%s", detail);
    tsnet_log(TSNET_LOG_INFO, "control: state %d (%s)", (int)s, detail);
    if (c->cfg.on_state) {
        c->cfg.on_state(c->cfg.ctx, s, detail);
    }
}

static bool zero(const uint8_t k[TSNET_KEY_LEN])
{
    static const uint8_t Z[TSNET_KEY_LEN];
    return memcmp(k, Z, TSNET_KEY_LEN) == 0;
}

static void public_of(uint8_t pub[TSNET_KEY_LEN], const uint8_t priv[TSNET_KEY_LEN])
{
    if (zero(priv)) {
        memset(pub, 0, TSNET_KEY_LEN); // Go sends the zero key for "none", not a key made from zero
    } else {
        tsnet_x25519_public(pub, priv);
    }
}

// hostInfoLocked: the Hostinfo with the latest NetInfo.
static tsnet_hostinfo_t hostinfo(const tsnet_client_t *c)
{
    tsnet_hostinfo_t h = {c->ipn_version, c->id.backend_log_id, c->os,     c->os_version,
                          c->hostname,    c->machine,          c->have_netinfo ? &c->netinfo : NULL};
    return h;
}

// sendMapRequest's MapRequest, with the disco key and endpoints magicsock gave. The caller sets what differs.
static tsnet_map_req_t map_request(const tsnet_client_t *c, const tsnet_hostinfo_t *hi)
{
    tsnet_map_req_t req = {.version = TSNET_CAPVER, .compress = "zstd", .keep_alive = true, .hostinfo = hi,
                           .endpoints = c->eps, .endpoint_types = c->ep_types, .n_endpoints = c->n_eps};
    public_of(req.node_key, c->id.node);
    memcpy(req.disco_key, c->disco_pub, TSNET_KEY_LEN);
    return req;
}

// ---- backoffs ----

static void auth_fail(tsnet_client_t *c, const char *why)
{
    uint32_t d = tsnet_backoff_fail(&c->auth_bo, rnd32());
    c->auth_next = tsnet_now_ms() + d;
    c->regen = false; // the next doLoginOrRegen starts from the stored key again
    tsnet_log(TSNET_LOG_WARN, "control: login: %s (retry in %u ms)", why, (unsigned)d);
}

static void map_fail(tsnet_client_t *c, const char *why)
{
    uint32_t d = tsnet_backoff_fail(&c->map_bo, rnd32());
    c->map_next = tsnet_now_ms() + d;
    tsnet_log(TSNET_LOG_WARN, "control: map poll: %s (backoff %u ms)", why, (unsigned)d);
}

// ---- the h2 callbacks: they record only ----

static rq_t *rq_of(tsnet_client_t *c, uint32_t stream)
{
    rq_t *all[4] = {&c->reg, &c->map, &c->ping, &c->upd};
    for (int i = 0; i < 4; i++) {
        if (stream != 0 && all[i]->id == stream) {
            return all[i];
        }
    }
    return NULL;
}

static void on_field(void *ctx, uint32_t stream, const char *name, size_t name_len, const char *value, size_t value_len)
{
    rq_t *r = rq_of(ctx, stream);
    if (r && name_len == 11 && memcmp(name, "retry-after", 11) == 0) {
        r->has_retry_after = true;
        snprintf(r->retry_after, sizeof r->retry_after, "%.*s", (int)value_len, value);
    }
}

static void on_head(void *ctx, uint32_t stream, int status)
{
    tsnet_client_t *c = ctx;
    rq_t *r = rq_of(c, stream);
    if (r) {
        r->status = status;
    }
    if (r == &c->map && status == 200) {
        c->in_map_poll = true;
        c->watchdog = tsnet_now_ms() + TSNET_WATCHDOG_MS; // sendMapRequest: watchdogTimer.Reset after the 200
    }
}

// Each map message (mapmsg's callback): decoded, applied to this poll's netmap, given to the app.
static void on_message(void *ctx, const char *json, size_t len, bool keep_alive)
{
    tsnet_client_t *c = ctx;
    if (c->map_bad) {
        return; // the poll is ending: the rest of the chunk is dropped
    }
    c->watchdog = tsnet_now_ms() + TSNET_WATCHDOG_MS; // reset before the next message read
    if (keep_alive) {
        return; // mapmsg's fast path: the exact bytes of {"KeepAlive":true}, nothing else in it
    }
    tsnet_map_resp_t r;
    if (tsnet_map_response_parse(&r, json, len) != 0) {
        tsnet_log(TSNET_LOG_WARN, "control: a map message didn't decode");
        c->map_bad = true;
        return;
    }
    // answerPing, for a new URL only (isUniquePingRequest). It is sent once the feed returns.
    if (r.has_ping && r.ping_url[0] && strcmp(r.ping_url, c->ping_url) != 0) {
        snprintf(c->ping_url, sizeof c->ping_url, "%s", r.ping_url);
        if (r.ping_types[0] == '\0' && r.ping_url_is_noise) {
            snprintf(c->ping_pending, sizeof c->ping_pending, "%s", r.ping_url);
        } else {
            // shortcut: HEAD pings over plain HTTPS, c2n and disco/TSMP/ICMP/peerapi pings wait for later modules.
            tsnet_log(TSNET_LOG_INFO, "control: ping request of type \"%s\"%s not answered yet", r.ping_types,
                      r.ping_url_is_noise ? "" : " (not over Noise)");
        }
    }
    bool keep_alive_msg = r.keep_alive;
    char sid[64] = "";
    if (r.node) {
        snprintf(sid, sizeof sid, "%s", r.node->stable_id); // netmap_apply takes r.node
    }
    int flags = tsnet_netmap_apply(&c->nm, &r, (int64_t)time(NULL));
    tsnet_map_response_free(&r);
    if (flags < 0) {
        tsnet_log(TSNET_LOG_WARN, "control: initial MapResponse lacked node");
        c->map_bad = true;
        return;
    }
    if (keep_alive_msg) {
        return;
    }
    tsnet_backoff_reset(&c->map_bo); // UpdateFullNetmap: "Reset the backoff timer if we got a netmap"
    if (tsnet_self_expired(c->nm.has_node ? &c->nm.node : NULL, (int64_t)time(NULL))) {
        set_state(c, TSNET_CLIENT_NEEDS_AUTH, "node key expired"); // ipnlocal: keyExpired is NeedsLogin; polls go on
    } else {
        set_state(c, TSNET_CLIENT_RUNNING, "netmap received");
    }
    if (sid[0] && tsnet_identity_set_node_id(&c->id, sid) != 0) { // onSelfNodeChanged: Persist.NodeID
        tsnet_log(TSNET_LOG_WARN, "control: can't keep the node ID");
    }
    if (flags && c->cfg.on_netmap) {
        c->cfg.on_netmap(c->cfg.ctx, &c->nm, flags);
    }
}

static void on_data(void *ctx, uint32_t stream, const uint8_t *data, size_t len)
{
    tsnet_client_t *c = ctx;
    rq_t *r = rq_of(c, stream);
    if (r == NULL) {
        return;
    }
    if (r == &c->map && r->status == 200) {
        if (!c->map_bad && tsnet_mapmsg_feed(c->mm, data, len, on_message, c) != 0) {
            tsnet_log(TSNET_LOG_WARN, "control: a map message's framing or compression is bad");
            c->map_bad = true;
        }
        return;
    }
    if (r == &c->upd && r->status == 200) {
        return; // a lite update's response: io.Copy(io.Discard, res.Body)
    }
    size_t take = len < BODY_KEEP - r->body_len ? len : BODY_KEEP - r->body_len;
    memcpy(r->body + r->body_len, data, take);
    r->body_len += take;
}

static void on_end(void *ctx, uint32_t stream, int err)
{
    rq_t *r = rq_of(ctx, stream);
    if (r) {
        r->ended = true;
        r->err = err;
    }
}

// ---- requests ----

// A POST as direct.go makes it: no Content-Type, a ts-lb header per non-zero key (ts2021.AddLBHeader).
static uint32_t post(tsnet_client_t *c, const char *path, const uint8_t *lb1, const uint8_t *lb2, const char *body)
{
    char k1[TSNET_KEY_TEXT_MAX], k2[TSNET_KEY_TEXT_MAX];
    tsnet_h2_header_t hd[2];
    size_t n = 0;
    if (lb1 && !zero(lb1)) {
        tsnet_key_text(k1, TSNET_KEY_NODE, lb1);
        hd[n++] = (tsnet_h2_header_t){"ts-lb", k1};
    }
    if (lb2 && !zero(lb2)) {
        tsnet_key_text(k2, TSNET_KEY_NODE, lb2);
        hd[n++] = (tsnet_h2_header_t){"ts-lb", k2};
    }
    return tsnet_h2_request(c->h2, "POST", c->authority, path, hd, n, (const uint8_t *)body, strlen(body));
}

static void rq_start(rq_t *r, uint32_t id)
{
    memset(r, 0, sizeof *r);
    r->id = id;
}

// doLogin: the register with the stored node key (or a new one when regenerating).
static void start_register(tsnet_client_t *c)
{
    if (tsnet_identity_try_node_key(&c->id, c->regen, c->try_key, c->old_key) != 0) {
        auth_fail(c, "no randomness for a node key");
        return;
    }
    // The auth key goes with a first register, and with a new node key. A restart of a registered node logs in with its
    // stored node key alone, so a key built into an image isn't sent on every boot.
    bool send_key = c->auth_key[0] && (zero(c->id.node) || c->regen);
    tsnet_hostinfo_t hi = hostinfo(c);
    tsnet_register_req_t req = {.version = TSNET_CAPVER, .nl_key = c->id.nl_pub, .hostinfo = &hi,
                                .auth_key = send_key ? c->auth_key : NULL, .ephemeral = c->cfg.ephemeral};
    public_of(req.node_key, c->try_key);
    public_of(req.old_node_key, c->old_key);
    time_t now = time(NULL);
    req.timestamp = now > 1700000000 ? (int64_t)now : 0; // Timestamp only with a set clock (it's omitempty)
    char *body = tsnet_register_request_json(&req);
    uint32_t id = body ? post(c, "/machine/register", req.old_node_key, req.node_key, body) : 0;
    if (body) {
        tsnet_wipe(body, strlen(body)); // it may hold the auth key
    }
    free(body);
    if (id == 0) {
        auth_fail(c, "couldn't send the register request");
        return;
    }
    rq_start(&c->reg, id);
    tsnet_log(TSNET_LOG_INFO, "control: doLogin(regen=%d, auth key %s)", c->regen, send_key ? "sent" : "not sent");
}

// sendMapRequest: a streaming poll with keep-alives, asking for zstd, in a new map session.
static void start_map(tsnet_client_t *c)
{
    tsnet_hostinfo_t hi = hostinfo(c);
    tsnet_map_req_t req = map_request(c, &hi);
    req.stream = true;
    tsnet_mapmsg_t *mm = tsnet_mapmsg_new(true);
    char *body = mm ? tsnet_map_request_json(&req) : NULL;
    uint32_t id = body ? post(c, "/machine/map", req.node_key, NULL, body) : 0;
    free(body);
    if (id == 0) {
        tsnet_mapmsg_free(mm);
        map_fail(c, "couldn't send the map request");
        return;
    }
    rq_start(&c->map, id);
    tsnet_mapmsg_free(c->mm);
    c->mm = mm;
    tsnet_netmap_free(&c->nm);
    tsnet_netmap_init(&c->nm);
    c->map_bad = false;
    c->in_map_poll = false;
    c->watchdog = tsnet_now_ms() + TSNET_WATCHDOG_MS; // the watchdog covers the initial request too
}

// SendUpdate: a lite map update, sendMapRequest with OmitPeers and no stream. It tells the server the latest disco key,
// endpoints and NetInfo; the response is read and dropped.
static void start_update(tsnet_client_t *c)
{
    tsnet_hostinfo_t hi = hostinfo(c);
    tsnet_map_req_t req = map_request(c, &hi);
    req.omit_peers = true;
    char *body = tsnet_map_request_json(&req);
    uint32_t id = body ? post(c, "/machine/map", req.node_key, NULL, body) : 0;
    free(body);
    if (id == 0) {
        c->upd_next = tsnet_now_ms() + tsnet_backoff_fail(&c->upd_bo, rnd32());
        return;
    }
    rq_start(&c->upd, id);
    c->sent = c->gen;
    tsnet_log(TSNET_LOG_DEBUG, "control: lite map update (%zu endpoints)", c->n_eps);
}

// answerHeadPing over the Noise connection: a HEAD to the URL's host and path.
static void start_ping(tsnet_client_t *c)
{
    char authority[256] = "";
    const char *url = c->ping_pending, *host = strstr(url, "://");
    const char *path = host ? strchr(host + 3, '/') : NULL;
    if (path && (size_t)(path - host - 3) < sizeof authority) {
        memcpy(authority, host + 3, (size_t)(path - host - 3));
        authority[path - host - 3] = '\0';
        uint32_t id = tsnet_h2_request(c->h2, "HEAD", authority, path, NULL, 0, NULL, 0);
        if (id) {
            rq_start(&c->ping, id);
            c->ping_deadline = tsnet_now_ms() + PING_TIMEOUT_MS;
        }
    } else {
        tsnet_log(TSNET_LOG_WARN, "control: a ping URL without a host and path");
    }
    c->ping_pending[0] = '\0';
}

// ---- what a finished request means ----

static uint32_t retry_after(const rq_t *r)
{
    return tsnet_retry_after_ms(r->has_retry_after ? r->retry_after : NULL, (int64_t)time(NULL), rnd32());
}

static void register_done(tsnet_client_t *c)
{
    rq_t *r = &c->reg;
    r->id = 0;
    r->body[r->body_len] = '\0';
    tsnet_register_resp_t resp;
    bool parsed = r->status == 200 && r->err == 0 &&
                  tsnet_register_response_parse(&resp, (const char *)r->body, r->body_len) == 0;
    char why[300];
    switch (tsnet_login_outcome(r->status, r->has_retry_after, parsed ? &resp : NULL, c->regen)) {
    case TSNET_LOGIN_RATE_LIMITED: {
        uint32_t d = retry_after(r);
        c->auth_next = tsnet_now_ms() + d; // waitRetryAfter, not the backoff
        tsnet_log(TSNET_LOG_WARN, "control: register rate limited, retry in %u ms", (unsigned)d);
        return;
    }
    case TSNET_LOGIN_FAILED:
        if (r->status == 0) {
            snprintf(why, sizeof why, "register request failed (%d)", r->err);
        } else {
            snprintf(why, sizeof why, "register request: http %d: %.200s", r->status, (char *)r->body);
        }
        auth_fail(c, why);
        return;
    case TSNET_LOGIN_REFUSED:
        set_state(c, TSNET_CLIENT_NEEDS_AUTH, resp.error);
        auth_fail(c, resp.error);
        return;
    case TSNET_LOGIN_REGEN:
        tsnet_log(TSNET_LOG_INFO, "control: the server wants a new node key");
        c->regen = true;
        c->auth_next = tsnet_now_ms();
        return;
    case TSNET_LOGIN_AUTH_URL:
        set_state(c, TSNET_CLIENT_NEEDS_AUTH, resp.auth_url);
        auth_fail(c, "the server wants a login URL visited");
        return;
    case TSNET_LOGIN_OK:
        break;
    }
    if (tsnet_identity_commit_node_key(&c->id, c->try_key, c->old_key) != 0) {
        auth_fail(c, "can't keep the node key");
        return;
    }
    c->logged_in = true;
    c->regen = false;
    tsnet_backoff_reset(&c->auth_bo);
    set_state(c, TSNET_CLIENT_LOGGED_IN, "registered");
    c->map_next = tsnet_now_ms(); // restartMap
}

static void map_done(tsnet_client_t *c)
{
    rq_t *r = &c->map;
    r->id = 0;
    c->in_map_poll = false;
    tsnet_mapmsg_free(c->mm);
    c->mm = NULL;
    r->body[r->body_len] = '\0';
    char why[300];
    switch (tsnet_map_outcome(r->status, r->has_retry_after)) {
    case TSNET_MAP_RATE_LIMITED: {
        uint32_t d = retry_after(r);
        c->map_next = tsnet_now_ms() + d;
        tsnet_log(TSNET_LOG_WARN, "control: map poll rate limited, retry in %u ms", (unsigned)d);
        return;
    }
    case TSNET_MAP_REMOVED:
        set_state(c, TSNET_CLIENT_NODE_REMOVED, "node removed from tailnet"); // ErrNodeRemoved
        break;
    case TSNET_MAP_ENDED:
        break;
    }
    // The state stays RUNNING across polls, as tailscaled's backend stays Running: tsnet_client_in_map_poll says more.
    if (r->status != 200 && r->status != 0) {
        snprintf(why, sizeof why, "initial fetch failed %d: %.200s", r->status, (char *)r->body);
    } else {
        snprintf(why, sizeof why, "ended (%d)", r->err);
    }
    map_fail(c, why);
}

// updateRoutine after SendUpdate: a 200 informs the server of that update; a rate limit waits Retry-After; anything
// else backs off (30 s at most).
static void update_done(tsnet_client_t *c)
{
    rq_t *r = &c->upd;
    r->id = 0;
    if (r->status == 200 && r->err == 0) {
        tsnet_backoff_reset(&c->upd_bo);
        c->informed = c->sent;
        tsnet_log(TSNET_LOG_DEBUG, "control: successful lite map update");
        return;
    }
    uint32_t d;
    if (tsnet_rate_limited(r->status, r->has_retry_after)) {
        d = retry_after(r);
    } else {
        d = tsnet_backoff_fail(&c->upd_bo, rnd32());
    }
    c->upd_next = tsnet_now_ms() + d;
    tsnet_log(TSNET_LOG_WARN, "control: lite map update error (http %d, end %d), again in %u ms", r->status, r->err,
              (unsigned)d);
}

static void act_on_streams(tsnet_client_t *c)
{
    if (c->upd.id && c->upd.ended) {
        update_done(c);
    }
    if (c->reg.id && c->reg.ended) {
        register_done(c);
    }
    if (c->map.id && c->map_bad && !c->map.ended) {
        if (c->h2) {
            tsnet_h2_cancel(c->h2, c->map.id);
        }
        c->map.ended = true;
        c->map.err = TSNET_H2_ERR_RESPONSE;
    }
    if (c->map.id && c->map.ended) {
        map_done(c);
    }
    if (c->ping.id && c->ping.ended) {
        c->ping.id = 0;
    }
}

// ---- the connection ----

// Ends the connection and settles every request on it.
static void conn_close(tsnet_client_t *c, const char *why)
{
    tsnet_log(TSNET_LOG_WARN, "control: connection closed: %s", why);
    if (c->h2) {
        tsnet_h2_closed(c->h2); // ends its open streams through on_end
    }
    tsnet_h2_free(c->h2);
    tsnet_ctrl_close(c->conn);
    c->h2 = NULL;
    c->conn = NULL;
    rq_t *all[4] = {&c->reg, &c->map, &c->ping, &c->upd};
    for (int i = 0; i < 4; i++) {
        if (all[i]->id && !all[i]->ended) {
            all[i]->ended = true;
            all[i]->err = TSNET_H2_ERR_CONN;
        }
    }
    act_on_streams(c);
}

// Reads every record that has arrived into h2, then acts on what ended.
static void conn_read(tsnet_client_t *c)
{
    for (;;) {
        int n = tsnet_ctrl_read(c->conn, c->pt, sizeof c->pt);
        if (n == 0) {
            break;
        }
        if (n < 0) {
            conn_close(c, "read failed");
            return;
        }
        if (tsnet_h2_feed(c->h2, c->pt, (size_t)n) != 0) {
            const uint8_t *p;
            size_t len = tsnet_h2_pending(c->h2, &p);
            if (len) {
                tsnet_ctrl_write_some(c->conn, p, len); // its GOAWAY, if the socket takes it
            }
            conn_close(c, "HTTP/2 error");
            return;
        }
    }
    act_on_streams(c);
}

// Sends what h2 queued: the queued record first, then more records while the socket takes them.
static void conn_write(tsnet_client_t *c)
{
    while (c->conn) {
        if (tsnet_ctrl_pending_write(c->conn)) {
            int f = tsnet_ctrl_flush(c->conn);
            if (f < 0) {
                conn_close(c, "write failed");
                return;
            }
            if (f == 0) {
                return; // the socket is full: poll waits for it
            }
        }
        const uint8_t *p;
        size_t len = tsnet_h2_pending(c->h2, &p);
        if (len == 0) {
            return;
        }
        int n = tsnet_ctrl_write_some(c->conn, p, len);
        if (n < 0) {
            conn_close(c, "write failed");
            return;
        }
        if (n == 0) {
            return; // can't happen with nothing queued; don't spin if it does
        }
        tsnet_h2_sent(c->h2, (size_t)n);
    }
}

// ---- the loop ----

static void fail_routine(tsnet_client_t *c, const char *why)
{
    if (c->logged_in) {
        map_fail(c, why);
    } else {
        auth_fail(c, why);
    }
}

static void step_key_and_dial(tsnet_client_t *c)
{
    if (c->kf) { // doLogin's loadServerPubKeys, once
        int r = tsnet_keyfetch_step(c->kf);
        if (r == 1) {
            tsnet_keyfetch_key(c->kf, c->control_pub);
            c->have_key = true;
        }
        if (r != 0) {
            tsnet_keyfetch_free(c->kf);
            c->kf = NULL;
            if (r < 0) {
                auth_fail(c, "fetching the server's key failed");
            }
        }
    }
    if (c->dial) {
        int r = tsnet_dial_step(c->dial);
        if (r == 1) {
            c->conn = tsnet_dial_take(c->dial);
            tsnet_h2_cb_t cb = {c, on_field, on_head, on_data, on_end}; // tsnet_h2_new copies it
            c->h2 = tsnet_h2_new(&cb, 1);
            if (c->h2 == NULL) {
                tsnet_ctrl_close(c->conn);
                c->conn = NULL;
            }
        }
        if (r != 0) {
            tsnet_dial_free(c->dial);
            c->dial = NULL;
            if (c->conn == NULL) {
                fail_routine(c, "dial failed");
            }
        }
    }
}

void tsnet_client_step(tsnet_client_t *c)
{
    step_key_and_dial(c);
    if (c->conn) {
        conn_read(c);
    }
    uint64_t now = tsnet_now_ms();
    // The watchdog: "map response long-poll timed out!", then the stream reset and a new poll after the map backoff, on
    // the same connection (measured on the official client).
    if (c->map.id && !c->map.ended && now >= c->watchdog) {
        tsnet_log(TSNET_LOG_WARN, "control: map response long-poll timed out!");
        if (c->h2) {
            tsnet_h2_cancel(c->h2, c->map.id);
        }
        c->map.ended = true;
        c->map.err = TSNET_H2_ERR_CONN;
        act_on_streams(c);
    }
    if (c->ping.id && now >= c->ping_deadline) {
        if (c->h2) {
            tsnet_h2_cancel(c->h2, c->ping.id);
        }
        c->ping.id = 0;
    }
    // What's due.
    bool want_login = !c->logged_in && c->reg.id == 0 && now >= c->auth_next;
    bool want_map = c->logged_in && c->map.id == 0 && now >= c->map_next;
    bool want_update = c->logged_in && c->gen != c->informed && c->upd.id == 0 && now >= c->upd_next;
    if (c->h2 && !tsnet_h2_usable(c->h2) && c->reg.id == 0 && c->map.id == 0 && c->ping.id == 0 && c->upd.id == 0) {
        conn_close(c, "GOAWAY"); // no new streams on it: the next request dials again
    }
    if (want_login && !c->have_key) {
        if (c->kf == NULL) {
            c->kf = tsnet_keyfetch_start(c->host, c->port, c->https, TSNET_CAPVER, KEY_TIMEOUT_MS);
            if (c->kf == NULL) {
                auth_fail(c, "can't start fetching the server's key");
            }
        }
    } else if ((want_login || want_map || want_update) && c->conn == NULL && c->dial == NULL) {
        c->dial = tsnet_dial_start(c->host, c->http_port, c->https_port, c->id.machine, c->control_pub, TSNET_CAPVER,
                                   DIAL_TIMEOUT_MS);
        if (c->dial == NULL) {
            fail_routine(c, "can't start a dial");
        }
    }
    if (c->h2 && tsnet_h2_usable(c->h2)) {
        if (want_login) {
            start_register(c);
        } else if (want_map) {
            start_map(c);
        }
        if (c->ping_pending[0] && c->ping.id == 0) {
            start_ping(c);
        }
        if (want_update) {
            start_update(c);
        }
    }
    conn_write(c);
}

int tsnet_client_poll(tsnet_client_t *c, tsnet_poll_t *p, int max, int *wait_ms)
{
    int n = 0;
    uint64_t now = tsnet_now_ms(), until = now + POLL_MAX_WAIT_MS;
    if (c->kf && n < max) {
        n += tsnet_keyfetch_poll(c->kf, &p[n]);
        uint64_t w = now + (uint64_t)tsnet_keyfetch_wait_ms(c->kf);
        until = w < until ? w : until;
    }
    if (c->dial && n + 2 <= max) {
        n += tsnet_dial_poll(c->dial, &p[n]);
        uint64_t w = now + (uint64_t)tsnet_dial_wait_ms(c->dial);
        until = w < until ? w : until;
    }
    if (c->conn && n < max) {
        const uint8_t *q;
        bool w = tsnet_ctrl_pending_write(c->conn) || (c->h2 && tsnet_h2_pending(c->h2, &q) > 0);
        p[n++] = (tsnet_poll_t){tsnet_ctrl_fd(c->conn), w, 0, 0};
        if (tsnet_ctrl_buffered(c->conn)) {
            until = now; // bytes already read are waiting
        }
    }
    // The routines' timers, only while nothing is under way that they wait for (a key fetch or a dial has its own wait;
    // a due timer then would spin the loop).
    bool idle = c->kf == NULL && c->dial == NULL;
    uint64_t timers[5] = {
        idle && !c->logged_in && c->reg.id == 0 ? c->auth_next : UINT64_MAX,
        idle && c->logged_in && c->map.id == 0 ? c->map_next : UINT64_MAX,
        c->map.id ? c->watchdog : UINT64_MAX,
        c->ping.id ? c->ping_deadline : UINT64_MAX,
        idle && c->logged_in && c->upd.id == 0 && c->gen != c->informed ? c->upd_next : UINT64_MAX,
    };
    for (int i = 0; i < 5; i++) {
        if (timers[i] < until) {
            until = timers[i] > now ? timers[i] : now;
        }
    }
    *wait_ms = (int)(until - now);
    return n;
}

void tsnet_client_run_for(tsnet_client_t *c, int ms)
{
    uint64_t end = tsnet_now_ms() + (uint64_t)ms;
    for (uint64_t now = tsnet_now_ms(); now < end; now = tsnet_now_ms()) {
        tsnet_poll_t p[4];
        int wait;
        int n = tsnet_client_poll(c, p, 4, &wait);
        int left = (int)(end - now);
        tsnet_poll(p, n, wait < left ? wait : left);
        tsnet_client_step(c);
    }
}

// ts2021.NewClient's URL handling: http or https, a host, an optional port, an optional path (ignored).
static int parse_url(tsnet_client_t *c, const char *url)
{
    c->https = strncmp(url, "https://", 8) == 0;
    if (!c->https && strncmp(url, "http://", 7) != 0) {
        return -1;
    }
    const char *a = url + (c->https ? 8 : 7);
    size_t alen = strcspn(a, "/");
    if (alen == 0 || alen >= sizeof c->authority) {
        return -1;
    }
    memcpy(c->authority, a, alen);
    c->authority[alen] = '\0';
    unsigned port = 0;
    char extra;
    int got = sscanf(c->authority, "%255[^:]:%u%c", c->host, &port, &extra);
    if (got < 1 || got > 2 || port > 65535 || (got == 2 && port == 0) ||
        (got == 1 && strchr(c->authority, ':') != NULL)) {
        return -1; // shortcut: no IPv6 literals in the server URL
    }
    tsnet_ts2021_ports(c->https, c->host, (uint16_t)port, &c->http_port, &c->https_port);
    c->port = (uint16_t)(port ? port : c->https ? 443 : 80);
    return 0;
}

tsnet_client_t *tsnet_client_new(const tsnet_client_cfg_t *cfg)
{
    tsnet_client_t *c = tsnet_calloc(1, sizeof *c);
    if (c == NULL) {
        return NULL;
    }
    if (cfg->server_url == NULL || parse_url(c, cfg->server_url) != 0) {
        tsnet_log(TSNET_LOG_ERROR, "control: bad server URL");
        free(c);
        return NULL;
    }
    if (tsnet_identity_load(&c->id) != 0) {
        tsnet_wipe(&c->id, sizeof c->id); // a partly loaded identity can hold the machine key
        free(c);
        return NULL;
    }
    c->cfg = *cfg;
    c->cfg.auth_key = NULL; // kept in c->auth_key only
    snprintf(c->auth_key, sizeof c->auth_key, "%s", cfg->auth_key ? cfg->auth_key : "");
    snprintf(c->hostname, sizeof c->hostname, "%s", cfg->hostname ? cfg->hostname : "");
    snprintf(c->ipn_version, sizeof c->ipn_version, "%s", cfg->ipn_version ? cfg->ipn_version : "");
    snprintf(c->os, sizeof c->os, "%s", cfg->os ? cfg->os : "");
    snprintf(c->os_version, sizeof c->os_version, "%s", cfg->os_version ? cfg->os_version : "");
    snprintf(c->machine, sizeof c->machine, "%s", cfg->machine ? cfg->machine : "");
    tsnet_backoff_init(&c->auth_bo, TSNET_BACKOFF_MAX_MS);
    tsnet_backoff_init(&c->map_bo, TSNET_BACKOFF_MAX_MS);
    tsnet_backoff_init(&c->upd_bo, TSNET_BACKOFF_MAX_MS);
    tsnet_netmap_init(&c->nm);
    c->auth_next = tsnet_now_ms();
    c->state = TSNET_CLIENT_STARTING;
    return c;
}

void tsnet_client_free(tsnet_client_t *c)
{
    if (c == NULL) {
        return;
    }
    tsnet_keyfetch_free(c->kf);
    tsnet_dial_free(c->dial);
    tsnet_h2_free(c->h2); // not tsnet_h2_closed: no callbacks while freeing
    tsnet_ctrl_close(c->conn);
    tsnet_mapmsg_free(c->mm);
    tsnet_netmap_free(&c->nm);
    tsnet_wipe(&c->id, sizeof c->id);
    tsnet_wipe(c->try_key, sizeof c->try_key);
    tsnet_wipe(c->old_key, sizeof c->old_key);
    tsnet_wipe(c->auth_key, sizeof c->auth_key);
    free(c);
}

tsnet_client_state_t tsnet_client_state(const tsnet_client_t *c)
{
    return c->state;
}

bool tsnet_client_in_map_poll(const tsnet_client_t *c)
{
    return c->in_map_poll;
}

void tsnet_client_set_disco_key(tsnet_client_t *c, const uint8_t pub[TSNET_KEY_LEN])
{
    if (memcmp(c->disco_pub, pub, TSNET_KEY_LEN) != 0) {
        memcpy(c->disco_pub, pub, TSNET_KEY_LEN);
        c->gen++;
    }
}

void tsnet_client_set_endpoints(tsnet_client_t *c, const tsnet_addrport_t *eps, const int *types, size_t n)
{
    if (n > TSNET_CLIENT_EPS) {
        n = TSNET_CLIENT_EPS;
    }
    // newEndpoints: slices.Equal, so the order counts.
    bool same = n == c->n_eps;
    for (size_t i = 0; i < n && same; i++) {
        same = types[i] == c->ep_types[i] && eps[i].port == c->eps[i].port && eps[i].ip.is6 == c->eps[i].ip.is6 &&
               memcmp(eps[i].ip.ip, c->eps[i].ip.ip, 16) == 0;
    }
    if (same) {
        return;
    }
    for (size_t i = 0; i < n; i++) {
        c->eps[i] = eps[i];
        c->ep_types[i] = types[i];
    }
    c->n_eps = n;
    c->gen++;
}

static bool same_netinfo(const tsnet_net_info_t *a, const tsnet_net_info_t *b)
{
    if (a->preferred_derp != b->preferred_derp || a->working_udp != b->working_udp ||
        a->mapping_varies != b->mapping_varies || a->n_derp_latency != b->n_derp_latency) {
        return false;
    }
    for (size_t i = 0; i < a->n_derp_latency; i++) {
        if (a->derp_latency[i].region != b->derp_latency[i].region ||
            a->derp_latency[i].seconds != b->derp_latency[i].seconds) {
            return false;
        }
    }
    return true;
}

void tsnet_client_set_netinfo(tsnet_client_t *c, const tsnet_net_info_t *ni)
{
    if (c->have_netinfo && same_netinfo(&c->netinfo, ni)) {
        return; // SetNetInfo: reflect.DeepEqual
    }
    c->netinfo = *ni;
    if (c->netinfo.n_derp_latency > TSNET_NETINFO_LATENCIES) {
        c->netinfo.n_derp_latency = TSNET_NETINFO_LATENCIES;
    }
    c->have_netinfo = true;
    c->gen++;
}

const tsnet_identity_t *tsnet_client_identity(const tsnet_client_t *c)
{
    return &c->id;
}
