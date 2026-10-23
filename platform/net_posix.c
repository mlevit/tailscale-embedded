// tsnet's TCP and UDP on the BSD socket API, shared by the host and ESP-IDF (lwIP provides the same calls).
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#elif !defined(ESP_PLATFORM)
#define _DEFAULT_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "platform.h"

int tsnet_tcp_connect(const char *host, uint16_t port)
{
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char service[8];
    snprintf(service, sizeof service, "%u", (unsigned)port);
    if (getaddrinfo(host, service, &hints, &res) != 0 || res == NULL) {
        tsnet_log(TSNET_LOG_WARN, "resolving %s failed", host);
        return -1;
    }
    struct addrinfo *pick = res;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        if (a->ai_family == AF_INET) {
            pick = a;
            break;
        }
    }
    int fd = socket(pick->ai_family, pick->ai_socktype, pick->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one); // Go's net.Dial sets TCP_NODELAY by default
    // TCP keep-alive, as tailscaled's dialer (netns.NewDialer: netknob.PlatformTCPKeepAlive, 30 s) gets it from Go's net
    // package (newTCPConn: Idle 30 s, then defaultTCPKeepAliveInterval 15 s and defaultTCPKeepAliveCount 9). Nothing at
    // the HTTP/2 layer pings the control connection.
    int idle = 30, intvl = 15, cnt = 9;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
#if defined(__APPLE__)
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &idle, sizeof idle);
#else
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
#endif
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
    int r = connect(fd, pick->ai_addr, pick->ai_addrlen);
    freeaddrinfo(res);
    if (r != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

int tsnet_tcp_connected(int fd)
{
    fd_set w;
    FD_ZERO(&w);
    FD_SET(fd, &w);
    struct timeval tv = {0, 0};
    if (select(fd + 1, NULL, &w, NULL, &tv) <= 0) {
        return 0;
    }
    int err = 0;
    socklen_t len = sizeof err;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
        return -1;
    }
    return 1;
}

int tsnet_sock_read(int fd, void *buf, size_t len)
{
    ssize_t n = recv(fd, buf, len, 0);
    if (n > 0) {
        return (int)n;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        return 0;
    }
    return -1; // 0 bytes: the peer closed
}

int tsnet_sock_write(int fd, const void *buf, size_t len)
{
#if defined(MSG_NOSIGNAL)
    ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
#else
    ssize_t n = send(fd, buf, len, 0);
#endif
    if (n >= 0) {
        return (int)n;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return 0;
    }
    return -1;
}

void tsnet_sock_close(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
}

int tsnet_udp_open(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    return fd;
}

uint16_t tsnet_udp_port(int fd)
{
    struct sockaddr_in a = {0};
    socklen_t len = sizeof a;
    if (getsockname(fd, (struct sockaddr *)&a, &len) != 0) {
        return 0;
    }
    return ntohs(a.sin_port);
}

static const uint8_t V4_MAPPED[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

int tsnet_udp_send(int fd, const uint8_t ip[16], uint16_t port, const void *buf, size_t len)
{
    if (memcmp(ip, V4_MAPPED, sizeof V4_MAPPED) != 0) {
        return -1; // IPv6 isn't done yet
    }
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    memcpy(&a.sin_addr, ip + 12, 4);
    a.sin_port = htons(port);
    ssize_t n = sendto(fd, buf, len, 0, (struct sockaddr *)&a, sizeof a);
    if (n >= 0) {
        return (int)n;
    }
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ENOBUFS ? 0 : -1;
}

int tsnet_udp_recv(int fd, void *buf, size_t cap, uint8_t ip[16], uint16_t *port)
{
    struct sockaddr_in a = {0};
    socklen_t alen = sizeof a;
    ssize_t n = recvfrom(fd, buf, cap, 0, (struct sockaddr *)&a, &alen);
    if (n < 0) {
        return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1;
    }
    memcpy(ip, V4_MAPPED, sizeof V4_MAPPED);
    memcpy(ip + 12, &a.sin_addr, 4);
    *port = ntohs(a.sin_port);
    return (int)n;
}

int tsnet_resolve4(const char *host, uint8_t ip[16])
{
    // An IPv4 literal (what Tailscale's DERP map gives) needs no resolver, whose first call can take tens of ms.
    struct in_addr lit;
    if (inet_pton(AF_INET, host, &lit) == 1) {
        memcpy(ip, V4_MAPPED, sizeof V4_MAPPED);
        memcpy(ip + 12, &lit, 4);
        return 0;
    }
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || res == NULL) {
        return -1;
    }
    memcpy(ip, V4_MAPPED, sizeof V4_MAPPED);
    memcpy(ip + 12, &((struct sockaddr_in *)res->ai_addr)->sin_addr, 4);
    freeaddrinfo(res);
    return 0;
}

int tsnet_poll(tsnet_poll_t *p, int n, int timeout_ms)
{
    fd_set r, w;
    FD_ZERO(&r);
    FD_ZERO(&w);
    int maxfd = -1;
    for (int i = 0; i < n; i++) {
        p[i].readable = p[i].writable = 0;
        if (p[i].fd < 0) {
            continue;
        }
        FD_SET(p[i].fd, &r);
        if (p[i].want_write) {
            FD_SET(p[i].fd, &w);
        }
        if (p[i].fd > maxfd) {
            maxfd = p[i].fd;
        }
    }
    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    int ready = select(maxfd + 1, &r, &w, NULL, &tv);
    if (ready <= 0) {
        return ready < 0 && errno == EINTR ? 0 : ready;
    }
    for (int i = 0; i < n; i++) {
        if (p[i].fd >= 0) {
            p[i].readable = FD_ISSET(p[i].fd, &r) != 0;
            p[i].writable = FD_ISSET(p[i].fd, &w) != 0;
        }
    }
    return ready;
}
