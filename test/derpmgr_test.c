// Host test of magicsock's DERP connections against two DERP servers on loopback, one per region. Each is a
// forked accept loop with a child per connection: 101 and the greeting, ServerInfo after ClientInfo, and each packet
// sent back as if its destination answered; a packet saying "bye" closes the connection. The 60 s idle cleanup is
// policy_test's rule and the harness's scenario.
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _DEFAULT_SOURCE
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "derpmgr.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static uint8_t server_priv[32], server_pub[32], node_priv[32];

static int listener(uint16_t *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof a;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 8) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &len) != 0) {
        return -1;
    }
    *port = ntohs(a.sin_port);
    return fd;
}

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) {
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = read(fd, buf, len);
        if (n <= 0) {
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static size_t frame(uint8_t *out, uint8_t type, const uint8_t *p, size_t len)
{
    out[0] = type;
    out[1] = (uint8_t)(len >> 24);
    out[2] = (uint8_t)(len >> 16);
    out[3] = (uint8_t)(len >> 8);
    out[4] = (uint8_t)len;
    memcpy(out + 5, p, len);
    return 5 + len;
}

// One connection, in its own process.
static void conn(int fd)
{
    char req[1024];
    size_t n = 0;
    while (n < sizeof req - 1 && !strstr(req, "\r\n\r\n")) {
        ssize_t r = read(fd, req + n, sizeof req - 1 - n);
        if (r <= 0) {
            _exit(1);
        }
        n += (size_t)r;
        req[n] = 0;
    }
    uint8_t out[512], p[512];
    static const char R[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n";
    memcpy(out, R, sizeof R - 1);
    memcpy(p, "DERP\xf0\x9f\x94\x91", 8);
    memcpy(p + 8, server_pub, 32);
    write_all(fd, out, sizeof R - 1 + frame(out + sizeof R - 1, 0x01, p, 40));
    uint8_t shared[32];
    for (;;) {
        uint8_t h[5], buf[512];
        if (read_all(fd, h, 5) != 0) {
            _exit(0);
        }
        uint32_t len = (uint32_t)h[1] << 24 | (uint32_t)h[2] << 16 | (uint32_t)h[3] << 8 | h[4];
        if (len > sizeof buf || read_all(fd, buf, len) != 0) {
            _exit(1);
        }
        if (h[0] == 0x02) { // ClientInfo: answer with ServerInfo
            tsnet_box_shared(shared, server_priv, buf);
            static const char INFO[] = "{\"version\":2}";
            uint8_t nonce[24] = {9};
            memcpy(p, nonce, 24);
            tsnet_box_seal(p + 24, shared, nonce, (const uint8_t *)INFO, sizeof INFO - 1);
            write_all(fd, out, frame(out, 0x03, p, 24 + 16 + sizeof INFO - 1));
        } else if (h[0] == 0x04 && len >= 32) { // a packet: "bye" closes, anything else comes back from its peer
            if (len == 35 && memcmp(buf + 32, "bye", 3) == 0) {
                _exit(0);
            }
            write_all(fd, out, frame(out, 0x05, buf, len));
        }
    }
}

static pid_t serve(int lfd)
{
    pid_t pid = fork();
    if (pid == 0) {
        signal(SIGCHLD, SIG_IGN); // the connection processes reap themselves
        for (;;) {
            int fd = accept(lfd, NULL, NULL);
            if (fd < 0) {
                continue;
            }
            if (fork() == 0) {
                conn(fd);
            }
            close(fd);
        }
    }
    return pid;
}

static int last_region;
static uint8_t last_src[32];
static char last_data[16];
static void on_packet(void *ctx, int region, const uint8_t src[32], const uint8_t *data, size_t len)
{
    (void)ctx;
    last_region = region;
    memcpy(last_src, src, 32);
    snprintf(last_data, sizeof last_data, "%.*s", (int)len, (const char *)data);
}

// Steps until `done` or `ms` pass.
static bool run_until(tsnet_derpmgr_t *m, int ms, bool (*done)(tsnet_derpmgr_t *m))
{
    uint64_t end = tsnet_now_ms() + (uint64_t)ms;
    while (tsnet_now_ms() < end) {
        if (done(m)) {
            return true;
        }
        tsnet_poll_t p[TSNET_DERPMGR_REGIONS];
        int wait;
        int n = tsnet_derpmgr_poll(m, p, TSNET_DERPMGR_REGIONS, &wait);
        tsnet_poll(p, n, wait < 0 || wait > 50 ? 50 : wait);
        tsnet_derpmgr_step(m);
    }
    return done(m);
}

static bool home_connected(tsnet_derpmgr_t *m)
{
    return tsnet_derpmgr_connected(m, tsnet_derpmgr_home(m));
}
static bool home_down(tsnet_derpmgr_t *m)
{
    return !tsnet_derpmgr_connected(m, tsnet_derpmgr_home(m));
}
static bool got_hi(tsnet_derpmgr_t *m)
{
    (void)m;
    return strcmp(last_data, "hi") == 0;
}
static bool got_again(tsnet_derpmgr_t *m)
{
    (void)m;
    return strcmp(last_data, "again") == 0;
}

static tsnet_derp_node_t node(const char *name, int region, int port)
{
    tsnet_derp_node_t n;
    memset(&n, 0, sizeof n);
    snprintf(n.name, sizeof n.name, "%s", name);
    snprintf(n.host_name, sizeof n.host_name, "127.0.0.1");
    n.region_id = region;
    n.derp_port = port;
    return n;
}

int main(void)
{
    for (int i = 0; i < 32; i++) {
        server_priv[i] = (uint8_t)(3 + 17 * i);
        node_priv[i] = (uint8_t)(1 + 19 * i);
    }
    tsnet_x25519_public(server_pub, server_priv);
    uint16_t p1, p2;
    int l1 = listener(&p1), l2 = listener(&p2);
    pid_t s1 = serve(l1), s2 = serve(l2);

    tsnet_derp_node_t n1 = node("1a", 1, p1), n2 = node("2a", 2, p2), n3 = node("3a", 3, p2);
    tsnet_derp_region_t regions[3] = {{.region_id = 1, .nodes = &n1, .n_nodes = 1},
                                      {.region_id = 2, .nodes = &n2, .n_nodes = 1},
                                      {.region_id = 3, .nodes = &n3, .n_nodes = 1}};
    snprintf(regions[0].code, sizeof regions[0].code, "one");
    snprintf(regions[1].code, sizeof regions[1].code, "two");
    snprintf(regions[2].code, sizeof regions[2].code, "three");
    tsnet_derp_map_t map = {.has_regions = true, .regions = regions, .n_regions = 3};

    tsnet_derpmgr_cfg_t cfg = {.node_priv = node_priv, .use_http = true, .on_packet = on_packet};
    tsnet_derpmgr_t *m = tsnet_derpmgr_new(&cfg);
    int got[TSNET_DERPMGR_REGIONS];

    // No map: no home, no DERP.
    EXPECT(tsnet_derpmgr_set_home(m, 1) == 0);
    uint8_t peer[32];
    memset(peer, 0x5e, sizeof peer);
    EXPECT(tsnet_derpmgr_send(m, 1, peer, (const uint8_t *)"x", 1) == -1);

    // A map alone picks no home (setDERPMap; the ReSTUN after it does). The fallback, as a report with no preferred
    // region gives it, is here the only region, and it connects.
    tsnet_derp_map_t map1 = {.has_regions = true, .regions = regions, .n_regions = 1};
    tsnet_derpmgr_set_map(m, &map1);
    EXPECT(tsnet_derpmgr_home(m) == 0 && tsnet_derpmgr_regions(m, got, 8) == 0);
    EXPECT(tsnet_derpmgr_set_home(m, 0) == 1);
    EXPECT(run_until(m, 3000, home_connected));
    EXPECT(tsnet_derpmgr_conngen(m, 1) == 1);
    // A bigger map with region 1 unchanged keeps the home and its connection, and opens nothing else.
    tsnet_derpmgr_set_map(m, &map);
    EXPECT(tsnet_derpmgr_home(m) == 1 && tsnet_derpmgr_connected(m, 1));
    EXPECT(tsnet_derpmgr_regions(m, got, 8) == 1 && got[0] == 1);
    EXPECT(tsnet_derpmgr_set_home(m, 0) == 1); // the fallback keeps the home there is
    // Setting the same map again changes nothing.
    tsnet_derpmgr_set_map(m, &map);
    EXPECT(tsnet_derpmgr_home(m) == 1 && tsnet_derpmgr_connected(m, 1));

    // A packet for a peer whose home is region 2 opens region 2 on demand (and is queued while it connects); the
    // answer comes back from that peer over region 2.
    EXPECT(tsnet_derpmgr_send(m, 2, peer, (const uint8_t *)"hi", 2) == 0);
    EXPECT(run_until(m, 3000, got_hi));
    EXPECT(last_region == 2 && memcmp(last_src, peer, 32) == 0);
    // Having heard the peer over region 2, a packet for it via region 3 goes back over region 2 (derpRoute), and region
    // 3 isn't opened.
    last_data[0] = 0;
    EXPECT(tsnet_derpmgr_send(m, 3, peer, (const uint8_t *)"again", 5) == 0);
    EXPECT(run_until(m, 3000, got_again));
    EXPECT(last_region == 2);
    int n = tsnet_derpmgr_regions(m, got, 8);
    EXPECT(n == 2 && got[0] == 1 && got[1] == 2); // not 3

    // The home connection breaks: it is dialed again after the backoff and is connected again.
    EXPECT(tsnet_derpmgr_send(m, 1, peer, (const uint8_t *)"bye", 3) == 0);
    EXPECT(run_until(m, 3000, home_down));
    EXPECT(run_until(m, 3000, home_connected));
    EXPECT(tsnet_derpmgr_conngen(m, 1) == 2);
    // It breaks again. A packet sent during the backoff (5-15 ms here) is dropped instead of dialing: the
    // dropping server below counts the dials, since this window is too short to time. After the backoff the home
    // reconnects and a packet goes.
    EXPECT(tsnet_derpmgr_send(m, 1, peer, (const uint8_t *)"bye", 3) == 0);
    EXPECT(run_until(m, 3000, home_down));
    EXPECT(run_until(m, 3000, home_connected));
    EXPECT(tsnet_derpmgr_conngen(m, 1) == 3);
    last_data[0] = 0;
    EXPECT(tsnet_derpmgr_send(m, 1, peer, (const uint8_t *)"hi", 2) == 0);
    EXPECT(run_until(m, 3000, got_hi) && last_region == 1);
    // A home the map lacks is set anyway, as setNearestDERP does, and opens nothing; then back to region 1.
    n = tsnet_derpmgr_regions(m, got, 8);
    EXPECT(tsnet_derpmgr_set_home(m, 99) == 99 && tsnet_derpmgr_regions(m, got, 8) == n);
    EXPECT(tsnet_derpmgr_set_home(m, 1) == 1);

    // Region 2 redefined (its name changed): its connection closes. Home stays.
    snprintf(regions[1].name, sizeof regions[1].name, "renamed");
    tsnet_derpmgr_set_map(m, &map);
    n = tsnet_derpmgr_regions(m, got, 8);
    EXPECT(n >= 1 && got[0] == 1 && got[n - 1] != 2);
    EXPECT(tsnet_derpmgr_home(m) == 1);

    // The home's region dropped from the map: the home is cleared, and the next pick comes from what's left.
    tsnet_derp_map_t map23 = {.has_regions = true, .regions = regions + 1, .n_regions = 2};
    tsnet_derpmgr_set_map(m, &map23);
    EXPECT(tsnet_derpmgr_home(m) == 0);
    int home = tsnet_derpmgr_set_home(m, 0);
    EXPECT(home == 2 || home == 3);
    EXPECT(run_until(m, 3000, home_connected));
    n = tsnet_derpmgr_regions(m, got, 8);
    for (int i = 0; i < n; i++) {
        EXPECT(got[i] != 1);
    }

    // A region where nothing listens: its dials fail, again and again after the backoff (10, 40, 90 ms, ...), and none
    // of them counts as a connection (Go's connGen counts connections made).
    uint16_t closed_port;
    int closed = listener(&closed_port);
    close(closed);
    tsnet_derp_node_t n5 = node("5a", 5, closed_port);
    tsnet_derp_region_t region5 = {.region_id = 5, .nodes = &n5, .n_nodes = 1};
    tsnet_derp_map_t map5 = {.has_regions = true, .regions = &region5, .n_regions = 1};
    tsnet_derpmgr_set_map(m, &map5);
    EXPECT(tsnet_derpmgr_set_home(m, 0) == 5);
    EXPECT(!run_until(m, 400, home_connected));
    EXPECT(tsnet_derpmgr_conngen(m, 5) == 0);

    // A server that accepts each connection and drops it before any frame, while packets keep coming: the
    // dials follow the backoff, not the packets. The server writes a byte to a pipe for each connection it accepts.
    uint16_t drop_port;
    int drop = listener(&drop_port);
    int accepted[2];
    if (drop >= 0 && pipe(accepted) == 0) {
        pid_t drop_srv = fork();
        if (drop_srv == 0) {
            close(accepted[0]);
            for (int i = 0; i < 15; i++) { // without the fix, 1 s of packets dials far more than 15 times
                int fd = accept(drop, NULL, NULL);
                if (fd >= 0) {
                    close(fd);
                    (void)write(accepted[1], "x", 1);
                }
            }
            _exit(0);
        }
        close(accepted[1]);
        // Set up a region for this server, with a fresh manager.
        tsnet_derpmgr_free(m);
        m = tsnet_derpmgr_new(&cfg);
        tsnet_derp_node_t n_drop = node("drop", 6, drop_port);
        tsnet_derp_region_t region_drop = {.region_id = 6, .nodes = &n_drop, .n_nodes = 1};
        tsnet_derp_map_t map_drop = {.has_regions = true, .regions = &region_drop, .n_regions = 1};
        tsnet_derpmgr_set_map(m, &map_drop);
        tsnet_derpmgr_set_home(m, 0);
        // First send must dial at once (fresh slot, retry_at = 0).
        EXPECT(tsnet_derpmgr_send(m, 6, peer, (const uint8_t *)"first", 5) == 0);
        // A packet every few ms for 1 s.
        tsnet_poll_t p[TSNET_DERPMGR_REGIONS];
        int wait = 0;
        uint64_t end_ms = tsnet_now_ms() + 1000;
        while (tsnet_now_ms() < end_ms) {
            tsnet_derpmgr_send(m, 6, peer, (const uint8_t *)"msg", 3);
            int np = tsnet_derpmgr_poll(m, p, TSNET_DERPMGR_REGIONS, &wait);
            tsnet_poll(p, np, wait < 0 || wait > 5 ? 5 : wait);
            tsnet_derpmgr_step(m);
        }
        tsnet_derpmgr_free(m);
        m = tsnet_derpmgr_new(&cfg);
        kill(drop_srv, SIGKILL);
        waitpid(drop_srv, NULL, 0);
        close(drop);
        char buf[32];
        ssize_t dials = read(accepted[0], buf, sizeof buf); // the child is gone, so this doesn't block
        close(accepted[0]);
        // The backoff after the n-th failure is n² × 10 ms, at least half that with jitter: 1 s holds the first dial
        // and at most 8 retries, however fast the loop runs. More than one shows it does retry.
        EXPECT(dials >= 2 && dials <= 10);
    }

    // No map: everything closes, and there's no home.
    tsnet_derpmgr_set_map(m, NULL);
    EXPECT(tsnet_derpmgr_home(m) == 0 && tsnet_derpmgr_regions(m, got, 8) == 0);

    tsnet_derpmgr_free(m);
    kill(s1, SIGKILL);
    kill(s2, SIGKILL);
    waitpid(s1, NULL, 0);
    waitpid(s2, NULL, 0);
    close(l1);
    close(l2);
    if (failures == 0) {
        printf("tsnet derpmgr_test: ok\n");
    }
    return failures != 0;
}
