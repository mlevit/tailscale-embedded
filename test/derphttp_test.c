// Host test of derphttp's connect against a DERP server on loopback: a forked child plays the server over plain
// HTTP (the use_http knob). It checks the request, answers 101 with the greeting in the same write, opens ClientInfo,
// sends ServerInfo and a ping, and echoes a packet. Tailscale's real derpserver is the harness's (derp_run.c), and TLS
// is the live probe's.
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _DEFAULT_SOURCE
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "derphttp.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

enum { OK, STATUS_426, CLOSE_AFTER_GREETING };

static uint8_t server_priv[32], server_pub[32], node_priv[32], node_pub[32];
static char want_host[64], want_ideal[64];
static bool early; // the client queues a packet before the connection is up

static int listener(uint16_t *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof a;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 4) != 0 ||
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

// One frame from the client: its type, and its payload in `buf` (at most cap bytes). Returns the length or -1.
static int read_frame(int fd, uint8_t *type, uint8_t *buf, size_t cap)
{
    uint8_t h[5];
    if (read_all(fd, h, 5) != 0) {
        return -1;
    }
    uint32_t len = (uint32_t)h[1] << 24 | (uint32_t)h[2] << 16 | (uint32_t)h[3] << 8 | h[4];
    if (len > cap || read_all(fd, buf, len) != 0) {
        return -1;
    }
    *type = h[0];
    return (int)len;
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

#define CHECK(cond)                                         \
    do {                                                    \
        if (!(cond)) {                                      \
            printf("server: line %d: %s\n", __LINE__, #cond); \
            return 1;                                       \
        }                                                   \
    } while (0)

static int server(int lfd, int mode)
{
    int fd = accept(lfd, NULL, NULL);
    CHECK(fd >= 0);
    char req[1024];
    size_t n = 0;
    while (n < sizeof req - 1 && !strstr(req, "\r\n\r\n")) {
        ssize_t r = read(fd, req + n, sizeof req - 1 - n);
        CHECK(r > 0);
        n += (size_t)r;
        req[n] = 0;
    }
    char want[160];
    snprintf(want, sizeof want, "GET /derp HTTP/1.1\r\nHost: %s\r\n", want_host);
    CHECK(strncmp(req, want, strlen(want)) == 0);
    CHECK(strstr(req, "\r\nConnection: Upgrade\r\n") && strstr(req, "\r\nUpgrade: DERP\r\n"));
    if (want_ideal[0]) {
        snprintf(want, sizeof want, "\r\nIdeal-Node: %s\r\n", want_ideal);
        CHECK(strstr(req, want));
    } else {
        CHECK(!strstr(req, "Ideal-Node"));
    }
    if (mode == STATUS_426) {
        static const char R[] = "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n";
        write_all(fd, R, sizeof R - 1);
        close(fd);
        return 0;
    }
    // The 101 and the greeting in one write: the bytes after the head are DERP's.
    uint8_t out[512], p[256];
    static const char R[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n";
    memcpy(out, R, sizeof R - 1);
    memcpy(p, "DERP\xf0\x9f\x94\x91", 8);
    memcpy(p + 8, server_pub, 32);
    size_t len = sizeof R - 1 + frame(out + sizeof R - 1, 0x01, p, 40);
    CHECK(write_all(fd, out, len) == 0);
    if (mode == CLOSE_AFTER_GREETING) {
        close(fd);
        return 0;
    }
    // ClientInfo, opened as derpserver's recvClientKey does; then NotePreferred(true).
    uint8_t type, buf[256], shared[32], json[64];
    int fl = read_frame(fd, &type, buf, sizeof buf);
    CHECK(fl > 32 + 24 + 16 && type == 0x02 && memcmp(buf, node_pub, 32) == 0);
    CHECK(tsnet_box_shared(shared, server_priv, buf) == 0);
    CHECK(tsnet_box_open(json, shared, buf + 32, buf + 56, (size_t)fl - 56) == 0);
    CHECK(fl - 72 == 32 && memcmp(json, "{\"version\":2,\"CanAckPings\":true}", 32) == 0);
    fl = read_frame(fd, &type, buf, sizeof buf);
    CHECK(fl == 1 && type == 0x07 && buf[0] == 0x01);
    if (early) { // a packet queued while connecting comes after the handshake's frames
        fl = read_frame(fd, &type, buf, sizeof buf);
        CHECK(fl == 32 + 5 && type == 0x04 && memcmp(buf + 32, "early", 5) == 0);
    }
    // ServerInfo, then a ping the client must answer.
    static const char INFO[] = "{\"version\":2}";
    uint8_t nonce[24] = {7};
    memcpy(p, nonce, 24);
    CHECK(tsnet_box_seal(p + 24, shared, nonce, (const uint8_t *)INFO, sizeof INFO - 1) == 0);
    len = frame(out, 0x03, p, 24 + 16 + sizeof INFO - 1);
    static const uint8_t PING[8] = {'s', 'e', 'r', 'v', 'e', 'r', '!', '?'};
    len += frame(out + len, 0x12, PING, 8);
    CHECK(write_all(fd, out, len) == 0);
    fl = read_frame(fd, &type, buf, sizeof buf);
    CHECK(fl == 8 && type == 0x13 && memcmp(buf, PING, 8) == 0);
    // A packet sent to anyone comes back from the node itself (as a relay to itself would).
    fl = read_frame(fd, &type, buf, sizeof buf);
    CHECK(fl == 32 + 4 && type == 0x04 && memcmp(buf + 32, "echo", 4) == 0);
    memcpy(p, node_pub, 32);
    memcpy(p + 32, "echo", 4);
    len = frame(out, 0x05, p, 36);
    CHECK(write_all(fd, out, len) == 0);
    // Wait for the client to close.
    if (read(fd, buf, 1) < 0) {
        printf("server: read after the echo failed\n");
    }
    close(fd);
    return 0;
}

static pid_t spawn(int lfd, int mode)
{
    pid_t pid = fork();
    if (pid == 0) {
        _exit(server(lfd, mode));
    }
    return pid;
}

static int reap(pid_t pid)
{
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static bool got_info, got_echo;
static void on_msg(void *ctx, const tsnet_derp_msg_t *m)
{
    (void)ctx;
    if (m->type == TSNET_DERP_SERVER_INFO) {
        got_info = true;
    }
    if (m->type == TSNET_DERP_PACKET && m->len == 4 && memcmp(m->data, "echo", 4) == 0 &&
        memcmp(m->key, node_pub, 32) == 0) {
        got_echo = true;
    }
}

// Runs a connection until it fails, gets the echo, or `ms` pass.
static tsnet_derphttp_state_t run(tsnet_derphttp_t *c, int ms)
{
    uint64_t end = tsnet_now_ms() + (uint64_t)ms;
    bool sent = false;
    while (tsnet_now_ms() < end && tsnet_derphttp_state(c) != TSNET_DERPHTTP_FAILED && !got_echo) {
        tsnet_poll_t p;
        int wait;
        int n = tsnet_derphttp_poll(c, &p, &wait);
        tsnet_poll(&p, n, wait < 0 || wait > 100 ? 100 : wait);
        tsnet_derphttp_step(c);
        if (!sent && tsnet_derphttp_accepted(c)) {
            uint8_t anyone[32] = {1};
            EXPECT(tsnet_derphttp_send(c, anyone, (const uint8_t *)"echo", 4) == 0);
            sent = true;
        }
    }
    return tsnet_derphttp_state(c);
}

static tsnet_derp_node_t node(const char *name, const char *host, int port)
{
    tsnet_derp_node_t n;
    memset(&n, 0, sizeof n);
    snprintf(n.name, sizeof n.name, "%s", name);
    snprintf(n.host_name, sizeof n.host_name, "%s", host);
    n.region_id = 900;
    n.derp_port = port;
    return n;
}

int main(void)
{
    for (int i = 0; i < 32; i++) {
        server_priv[i] = (uint8_t)(3 + 11 * i);
        node_priv[i] = (uint8_t)(5 + 13 * i);
    }
    tsnet_x25519_public(server_pub, server_priv);
    tsnet_x25519_public(node_pub, node_priv);
    tsnet_derp_region_t reg = {.region_id = 900};

    // The whole connect, through a node list: a STUN-only node and one with a CertName are skipped, a refused node is
    // passed over, and the request then names the region's first node in Ideal-Node.
    {
        uint16_t port, closed_port;
        int lfd = listener(&port), closed = listener(&closed_port);
        close(closed);
        tsnet_derp_node_t nodes[4] = {node("900a", "127.0.0.1", closed_port), node("900b", "127.0.0.1", port),
                                      node("900c", "127.0.0.1", port), node("900d", "127.0.0.1", port)};
        nodes[1].stun_only = true;
        snprintf(nodes[2].cert_name, sizeof nodes[2].cert_name, "derp.example");
        reg.nodes = nodes;
        reg.n_nodes = 4;
        snprintf(want_host, sizeof want_host, "127.0.0.1:%u", port);
        snprintf(want_ideal, sizeof want_ideal, "900a");
        pid_t pid = spawn(lfd, OK);
        tsnet_derphttp_cfg_t cfg = {.region = &reg, .node_priv = node_priv, .use_http = true, .preferred = true,
                                    .on_msg = on_msg};
        tsnet_derphttp_t *c = tsnet_derphttp_connect(&cfg);
        EXPECT(c != NULL);
        got_info = got_echo = false;
        EXPECT(run(c, 5000) == TSNET_DERPHTTP_UP);
        EXPECT(got_info && got_echo && tsnet_derphttp_accepted(c) && tsnet_derphttp_node(c) == 3);
        tsnet_derphttp_free(c);
        EXPECT(reap(pid) == 0);
        close(lfd);
    }
    // The first node answers: no Ideal-Node. A packet queued before the connection is up goes after the handshake.
    {
        uint16_t port;
        int lfd = listener(&port);
        tsnet_derp_node_t nodes[1] = {node("900a", "127.0.0.1", port)};
        reg.nodes = nodes;
        reg.n_nodes = 1;
        snprintf(want_host, sizeof want_host, "127.0.0.1:%u", port);
        want_ideal[0] = 0;
        early = true;
        pid_t pid = spawn(lfd, OK);
        tsnet_derphttp_cfg_t cfg = {.region = &reg, .node_priv = node_priv, .use_http = true, .preferred = true,
                                    .on_msg = on_msg};
        tsnet_derphttp_t *c = tsnet_derphttp_connect(&cfg);
        EXPECT(tsnet_derphttp_state(c) == TSNET_DERPHTTP_CONNECTING);
        EXPECT(tsnet_derphttp_send(c, node_pub, (const uint8_t *)"early", 5) == 0);
        got_info = got_echo = false;
        EXPECT(run(c, 5000) == TSNET_DERPHTTP_UP && got_echo);
        tsnet_derphttp_free(c);
        EXPECT(reap(pid) == 0);
        close(lfd);
        early = false;
    }
    // Not a 101: the connect fails ("GET failed"). The server closing after the greeting fails it too.
    for (int mode = STATUS_426; mode <= CLOSE_AFTER_GREETING; mode++) {
        uint16_t port;
        int lfd = listener(&port);
        tsnet_derp_node_t nodes[1] = {node("900a", "127.0.0.1", port)};
        reg.nodes = nodes;
        reg.n_nodes = 1;
        snprintf(want_host, sizeof want_host, "127.0.0.1:%u", port);
        pid_t pid = spawn(lfd, mode);
        tsnet_derphttp_cfg_t cfg = {.region = &reg, .node_priv = node_priv, .use_http = true, .on_msg = on_msg};
        tsnet_derphttp_t *c = tsnet_derphttp_connect(&cfg);
        got_info = got_echo = false;
        EXPECT(run(c, 5000) == TSNET_DERPHTTP_FAILED && !got_info);
        EXPECT(tsnet_derphttp_send(c, node_pub, (const uint8_t *)"x", 1) == -1);
        tsnet_derphttp_free(c);
        EXPECT(reap(pid) == 0);
        close(lfd);
    }
    // No node to dial: every node STUN-only, or every node refused.
    {
        tsnet_derp_node_t nodes[1] = {node("900a", "127.0.0.1", 1)};
        nodes[0].stun_only = true;
        reg.nodes = nodes;
        reg.n_nodes = 1;
        tsnet_derphttp_cfg_t cfg = {.region = &reg, .node_priv = node_priv, .use_http = true};
        EXPECT(tsnet_derphttp_connect(&cfg) == NULL);
        uint16_t closed_port;
        int closed = listener(&closed_port);
        close(closed);
        nodes[0] = node("900a", "127.0.0.1", closed_port);
        tsnet_derphttp_t *c = tsnet_derphttp_connect(&cfg);
        EXPECT(c == NULL || run(c, 3000) == TSNET_DERPHTTP_FAILED);
        tsnet_derphttp_free(c);
    }
    // A host name that would add a header is refused before anything is sent.
    {
        uint16_t port;
        int lfd = listener(&port);
        tsnet_derp_node_t nodes[1] = {node("900a", "127.0.0.1", port)};
        snprintf(nodes[0].ipv4, sizeof nodes[0].ipv4, "127.0.0.1");
        snprintf(nodes[0].host_name, sizeof nodes[0].host_name, "evil\r\nX-Injected: 1");
        reg.nodes = nodes;
        reg.n_nodes = 1;
        tsnet_derphttp_cfg_t cfg = {.region = &reg, .node_priv = node_priv, .use_http = true};
        tsnet_derphttp_t *c = tsnet_derphttp_connect(&cfg);
        EXPECT(c != NULL && run(c, 3000) == TSNET_DERPHTTP_FAILED);
        tsnet_derphttp_free(c);
        close(lfd);
    }
    if (failures == 0) {
        printf("tsnet derphttp_test: ok\n");
    }
    return failures != 0;
}
