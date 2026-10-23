// Host test of tsnet's dial against a control server on loopback: a forked child plays the server with the
// responder in responder.h, over plain HTTP on an ephemeral port (the Dialer's HTTPPort). TLS and the real server are the
// live probe's (probe.c).
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _DEFAULT_SOURCE
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "controlhttp.h"
#include "platform.h"
#include "responder.h"

#define SMALL_BUF (64 * 1024) // both ends' socket buffers for the bulk (SO_RCVBUF, SO_SNDBUF)

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

enum { OK, ERROR_FRAME, STATUS_200, WRONG_UPGRADE, SILENT };

static uint8_t control[32], control_pub[32], machine[32];

// A listening socket on 127.0.0.1 and an ephemeral port.
static int listener(uint16_t *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    // A small receive buffer, which accepted sockets inherit, so the bulk below fills the path on any OS. Linux
    // otherwise autotunes loopback buffers to megabytes, and 2 MB went through without a stall.
    int buf = SMALL_BUF;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);
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

static int b64val(char c)
{
    const char *A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char *p = c ? strchr(A, c) : NULL;
    return p ? (int)(p - A) : -1;
}

// Decodes standard base64 up to '\r' or '='. Returns the byte count.
static size_t unb64(uint8_t *out, const char *s)
{
    size_t n = 0;
    uint32_t acc = 0;
    int bits = 0, v;
    while ((v = b64val(*s++)) >= 0) {
        acc = acc << 6 | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[n++] = (uint8_t)(acc >> bits);
        }
    }
    return n;
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

#define BULK (2u << 20) // far more than the two sockets' buffers hold (SMALL_BUF), so the sender must queue

// Reads records until `want` plaintext bytes are in `out`, keeping bytes read past a record for the next call.
static int read_plain(int fd, tsnet_noise_conn_t *sc, uint8_t *out, size_t want)
{
    static tsnet_noise_framer_t f;
    static uint8_t buf[8192];
    static size_t bl, bp;
    static uint8_t pt[TSNET_NOISE_MAX_PLAINTEXT];
    size_t have = 0;
    while (have < want) {
        int fl = tsnet_noise_framer_frame(&f);
        if (fl < 0) {
            return -1;
        }
        if (fl > 0) {
            int n = tsnet_noise_open(sc, pt, f.buf, (size_t)fl);
            tsnet_noise_framer_reset(&f);
            if (n < 0 || have + (size_t)n > want) {
                return -1;
            }
            memcpy(out + have, pt, (size_t)n);
            have += (size_t)n;
            continue;
        }
        if (bp < bl) {
            bp += tsnet_noise_framer_feed(&f, buf + bp, bl - bp);
            continue;
        }
        ssize_t r = read(fd, buf, sizeof buf);
        if (r <= 0) {
            return -1;
        }
        bl = (size_t)r;
        bp = 0;
    }
    return 0;
}

// The server, in the child: one connection, then the exit status says whether it saw what it should.
static int server(int lfd, int mode)
{
    int fd = accept(lfd, NULL, NULL);
    if (fd < 0) {
        return 10;
    }
    if (mode == SILENT) {
        pause(); // the parent kills it
    }
    char req[2048];
    size_t have = 0;
    while (have < sizeof req - 1 && (have < 4 || memcmp(req + have - 4, "\r\n\r\n", 4) != 0)) {
        ssize_t n = read(fd, req + have, 1);
        if (n <= 0) {
            return 11;
        }
        have++;
    }
    req[have] = '\0';
    // controlhttp's request, as Tailscale's server reads it.
    if (strncmp(req, "POST /ts2021 HTTP/1.1\r\n", 23) != 0 || !strstr(req, "\r\nUpgrade: tailscale-control-protocol\r\n") ||
        !strstr(req, "\r\nConnection: upgrade\r\n")) {
        return 12;
    }
    const char *h = strstr(req, "\r\nX-Tailscale-Handshake: ");
    uint8_t init[128];
    if (h == NULL || unb64(init, h + 25) != TSNET_NOISE_INIT_LEN) {
        return 13;
    }
    uint8_t s_eph[32], resp[TSNET_NOISE_RESP_LEN], got_machine[32], machine_pub[32];
    memset(s_eph, 0x42, sizeof s_eph);
    tsnet_noise_conn_t sc;
    if (serve(131, control, s_eph, init, resp, got_machine, &sc) != 0) {
        return 14;
    }
    tsnet_x25519_public(machine_pub, machine);
    if (memcmp(got_machine, machine_pub, 32) != 0) {
        return 15;
    }
    static const char UP[] = "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n";
    static uint8_t out[8192];
    size_t n = 0;
    switch (mode) {
    case OK:
        // The head, the Noise response and a first record in one write: the client must keep what follows the head.
        memcpy(out, UP, sizeof UP - 1);
        n = sizeof UP - 1;
        memcpy(out + n, resp, sizeof resp);
        n += sizeof resp;
        n += tsnet_noise_seal(&sc, out + n, (const uint8_t *)"hello", 5);
        break;
    case ERROR_FRAME: {
        static const uint8_t ERR[] = {3, 0, 4, 'n', 'o', 'p', 'e'};
        memcpy(out, UP, sizeof UP - 1);
        memcpy(out + sizeof UP - 1, ERR, sizeof ERR);
        n = sizeof UP - 1 + sizeof ERR;
        break;
    }
    case STATUS_200:
        n = (size_t)snprintf((char *)out, sizeof out, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        break;
    case WRONG_UPGRADE:
        n = (size_t)snprintf((char *)out, sizeof out, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n");
        memcpy(out + n, resp, sizeof resp);
        n += sizeof resp;
        break;
    }
    if (write_all(fd, out, n) != 0) {
        return 16;
    }
    if (mode != OK) {
        return 0;
    }
    // The client's reply: a record that opens with the server's receive key as "ping".
    uint8_t ping[4];
    if (read_plain(fd, &sc, ping, 4) != 0 || memcmp(ping, "ping", 4) != 0) {
        return 18;
    }
    // Then a bulk the client pushes with write_some while this end reads late, so its socket fills and it must queue.
    usleep(300000);
    uint8_t *bulk = malloc(BULK);
    if (bulk == NULL || read_plain(fd, &sc, bulk, BULK) != 0) {
        return 19;
    }
    for (size_t i = 0; i < BULK; i++) {
        if (bulk[i] != (uint8_t)(i * 7)) {
            return 20;
        }
    }
    free(bulk);
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

int main(void)
{
    for (int i = 0; i < 32; i++) {
        control[i] = (uint8_t)(2 + 7 * i);
        machine[i] = (uint8_t)(1 + 7 * i);
    }
    tsnet_x25519_public(control_pub, control);

    // ts2021.NewClient's ports for a server URL.
    {
        static const struct {
            int https;
            const char *host;
            uint16_t port;
            int http_port, https_port;
        } P[] = {
            {1, "controlplane.tailscale.com", 0, 80, 443},
            {1, "controlplane.tailscale.com", 8443, 80, 8443}, // HTTPPort "" -> strDef "80"
            {0, "headscale.example", 0, 80, 443},
            {0, "headscale.example", 8080, 8080, 443},
            {0, "127.0.0.1", 8090, 8090, TSNET_NO_PORT},
            {0, "192.168.1.2", 0, 80, TSNET_NO_PORT},
            {0, "10.1.2.3", 0, 80, TSNET_NO_PORT},
            {0, "172.31.0.1", 0, 80, TSNET_NO_PORT},
            {0, "172.32.0.1", 0, 80, 443},
            {0, "localhost", 0, 80, TSNET_NO_PORT},
            {0, "::1", 0, 80, TSNET_NO_PORT},
            {0, "fd7a:115c:a1e0::1", 0, 80, TSNET_NO_PORT},
            {0, "2001:db8::1", 0, 80, 443},
            {0, "100.64.0.1", 0, 80, 443}, // CGNAT isn't private to netip
            {1, "127.0.0.1", 0, 80, 443},
        };
        for (size_t i = 0; i < sizeof P / sizeof P[0]; i++) {
            int h, s;
            tsnet_ts2021_ports(P[i].https, P[i].host, P[i].port, &h, &s);
            if (h != P[i].http_port || s != P[i].https_port) {
                printf("ports for %s://%s:%u: %d/%d, want %d/%d\n", P[i].https ? "https" : "http", P[i].host,
                       (unsigned)P[i].port, h, s, P[i].http_port, P[i].https_port);
                failures++;
            }
        }
    }

    // The handshake, a record each way, and the bytes after the head kept for reading.
    {
        uint16_t port;
        int lfd = listener(&port);
        EXPECT(lfd >= 0);
        pid_t pid = spawn(lfd, OK);
        close(lfd);
        tsnet_ctrl_conn_t *c = tsnet_controlhttp_dial("127.0.0.1", port, TSNET_NO_PORT, machine, control_pub, 131, 5000);
        EXPECT(c != NULL);
        if (c != NULL) {
            EXPECT(tsnet_ctrl_port(c) == port);
            static uint8_t pt[TSNET_NOISE_MAX_PLAINTEXT];
            int n = 0;
            for (int tries = 0; tries < 50 && n == 0; tries++) {
                n = tsnet_ctrl_read(c, pt, sizeof pt);
                if (n == 0) {
                    tsnet_ctrl_wait(c, 100);
                }
            }
            EXPECT(n == 5 && memcmp(pt, "hello", 5) == 0);
            EXPECT(tsnet_ctrl_write(c, (const uint8_t *)"ping", 4) == 0);
            int buf = SMALL_BUF;
            setsockopt(tsnet_ctrl_fd(c), SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
            // 2 MB through write_some while the server reads late: the socket fills, a record waits in the queue (0
            // taken, pending write), and everything arrives whole and in order once the server reads.
            uint8_t *bulk = malloc(BULK);
            for (size_t i = 0; i < BULK; i++) {
                bulk[i] = (uint8_t)(i * 7);
            }
            size_t sent = 0;
            int stalls = 0, err = 0;
            uint64_t deadline = tsnet_now_ms() + 10000;
            while ((sent < BULK || tsnet_ctrl_pending_write(c)) && !err && tsnet_now_ms() < deadline) {
                int k = tsnet_ctrl_write_some(c, bulk + sent, BULK - sent);
                if (k < 0) {
                    err = 1;
                } else if (k == 0) {
                    stalls += tsnet_ctrl_pending_write(c);
                    tsnet_poll_t p = {tsnet_ctrl_fd(c), 1, 0, 0};
                    tsnet_poll(&p, 1, 100);
                } else {
                    EXPECT(k <= TSNET_NOISE_MAX_PLAINTEXT);
                    sent += (size_t)k;
                }
            }
            EXPECT(!err && sent == BULK && !tsnet_ctrl_pending_write(c) && stalls > 0);
            free(bulk);
        }
        EXPECT(reap(pid) == 0);
        tsnet_ctrl_close(c);
    }

    // Each way the server can say no: an error frame, a 200, another protocol.
    const int REFUSALS[] = {ERROR_FRAME, STATUS_200, WRONG_UPGRADE};
    for (size_t i = 0; i < sizeof REFUSALS / sizeof REFUSALS[0]; i++) {
        uint16_t port;
        int lfd = listener(&port);
        pid_t pid = spawn(lfd, REFUSALS[i]);
        close(lfd);
        tsnet_ctrl_conn_t *c = tsnet_controlhttp_dial("127.0.0.1", port, TSNET_NO_PORT, machine, control_pub, 131, 5000);
        EXPECT(c == NULL);
        EXPECT(reap(pid) == 0);
        tsnet_ctrl_close(c);
    }

    // Both ports refused: HTTP fails at once, so HTTPS starts at once (not after 500 ms), and the dial fails fast.
    {
        uint16_t p1, p2;
        int l1 = listener(&p1), l2 = listener(&p2);
        close(l1);
        close(l2); // now nothing listens on either
        uint64_t t0 = tsnet_now_ms();
        tsnet_ctrl_conn_t *c = tsnet_controlhttp_dial("127.0.0.1", p1, p2, machine, control_pub, 131, 5000);
        uint64_t took = tsnet_now_ms() - t0;
        EXPECT(c == NULL && took < 400);
    }

    // A dial within 2 minutes of the previous one goes to the HTTPS port only (forceNoise443): port 80 here is a silent
    // listener, so trying it would wait out the timeout, while the refused HTTPS port fails at once.
    {
        uint16_t p443, p80;
        int closed = listener(&p443);
        close(closed); // nothing listens on p443
        int quiet = listener(&p80);
        pid_t pid = spawn(quiet, SILENT);
        close(quiet);
        tsnet_dial_forget_recent();
        // The first dial after a reset tries port 80: it waits out its timeout on the silent server.
        uint64_t t0 = tsnet_now_ms();
        tsnet_ctrl_conn_t *c = tsnet_controlhttp_dial("127.0.0.1", p80, p443, machine, control_pub, 131, 600);
        uint64_t took = tsnet_now_ms() - t0;
        EXPECT(c == NULL && took >= 600);
        // A retry straight after: HTTPS only, refused at once, port 80 not tried.
        t0 = tsnet_now_ms();
        c = tsnet_controlhttp_dial("127.0.0.1", p80, p443, machine, control_pub, 131, 600);
        took = tsnet_now_ms() - t0;
        EXPECT(c == NULL && took < 300);
        // Without an HTTPS port (an http:// URL on a private host), port 80 is still tried however recent.
        t0 = tsnet_now_ms();
        c = tsnet_controlhttp_dial("127.0.0.1", p80, TSNET_NO_PORT, machine, control_pub, 131, 400);
        took = tsnet_now_ms() - t0;
        EXPECT(c == NULL && took >= 400);
        kill(pid, SIGKILL);
        reap(pid);
    }

    // A server that never answers: the dial gives up at its timeout.
    {
        uint16_t port;
        int lfd = listener(&port);
        pid_t pid = spawn(lfd, SILENT);
        close(lfd);
        uint64_t t0 = tsnet_now_ms();
        tsnet_ctrl_conn_t *c = tsnet_controlhttp_dial("127.0.0.1", port, TSNET_NO_PORT, machine, control_pub, 131, 300);
        uint64_t took = tsnet_now_ms() - t0;
        EXPECT(c == NULL && took >= 300 && took < 1500);
        kill(pid, SIGKILL);
        reap(pid);
    }

    if (failures == 0) {
        printf("tsnet controlhttp_test: ok\n");
    }
    return failures != 0;
}
