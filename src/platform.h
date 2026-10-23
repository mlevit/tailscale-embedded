#pragma once
// tsnet's platform layer: the only calls the portable core makes to the system it runs on. platform/esp/ has the
// ESP-IDF back end (ESP32 boards; run on an ESP32-P4), platform/host/ the macOS and Linux one (host tests and the conformance harness). A module
// that needs more of the system (sockets, storage) adds it here when it is written, with both back ends.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Milliseconds on a clock that never goes back (not the wall clock), from an arbitrary start.
uint64_t tsnet_now_ms(void);
// The same clock in microseconds, for latencies (netcheck's are a millisecond or less on a LAN).
uint64_t tsnet_now_us(void);

// Fills `buf` with `len` bytes from the system's cryptographic random source. Returns 0, or -1 if it failed (then
// nothing that needs the bytes may go on).
int tsnet_random(void *buf, size_t len);

typedef enum {
    TSNET_LOG_ERROR = 1,
    TSNET_LOG_WARN,
    TSNET_LOG_INFO,
    TSNET_LOG_DEBUG,
} tsnet_log_level_t;

// One log line under the tag "tsnet" (no trailing newline needed). On the device it goes through esp_log, so it reaches
// the serial log and the app's own log ring.
void tsnet_log(tsnet_log_level_t level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

// ---- Memory ----
// tsnet's own allocations. On the device they prefer PSRAM: internal RAM is the wifi link's (its receive buffers),
// and ESP-IDF serves any allocation under 16 KB from it otherwise, which starved the link on the first device run.
// The C library's on the host. free() releases them on both.
void *tsnet_malloc(size_t n);
void *tsnet_calloc(size_t n, size_t size);
void *tsnet_realloc(void *p, size_t n);

// ---- TCP ----
// tsnet runs as one event loop over non-blocking sockets (the C counterpart of tailscaled's goroutines): every protocol
// piece is a state machine that reads and writes when it can and waits in tsnet_poll otherwise. The BSD socket API is the
// same on the host and in ESP-IDF's lwIP, so platform/net_posix.c serves both.

// Resolves `host` (getaddrinfo, which blocks) and starts a non-blocking connect to its first IPv4 address (else its first
// address). Returns the socket, or -1. Unlike Go's dialer it doesn't race the addresses (Happy Eyeballs).
int tsnet_tcp_connect(const char *host, uint16_t port);
// 1 once the connect has finished, 0 while it is under way, -1 if it failed.
int tsnet_tcp_connected(int fd);
// Read and write: the bytes moved (> 0), 0 if none can move now, -1 if the socket is closed or failed.
int tsnet_sock_read(int fd, void *buf, size_t len);
int tsnet_sock_write(int fd, const void *buf, size_t len);
void tsnet_sock_close(int fd);

typedef struct {
    int fd;
    int want_write;           // also wait for room to write (a connect under way, data queued)
    int readable, writable;   // set by tsnet_poll
} tsnet_poll_t;
// Waits up to `timeout_ms` until one of the sockets is ready. Returns how many are, 0 on timeout, -1 on error.
int tsnet_poll(tsnet_poll_t *p, int n, int timeout_ms);

// ---- UDP ----
// IPv4 only for now. An address is 16 bytes, IPv4 as ::ffff:a.b.c.d (stun.h's form).

// A non-blocking UDP socket bound to `port` on every IPv4 address (0: any free port). Returns the socket, or -1.
int tsnet_udp_open(uint16_t port);
// The port the socket is bound to, or 0.
uint16_t tsnet_udp_port(int fd);
// Sends one datagram. Returns the bytes sent, 0 if the socket can't take it now (the datagram is dropped, as a full
// UDP buffer drops it), -1 on an error or an address that isn't IPv4.
int tsnet_udp_send(int fd, const uint8_t ip[16], uint16_t port, const void *buf, size_t len);
// Receives one datagram into buf (a longer one is cut to `cap`) and who sent it. Returns its length, 0 if none is
// waiting (or it was empty), -1 on an error.
int tsnet_udp_recv(int fd, void *buf, size_t cap, uint8_t ip[16], uint16_t *port);
// Resolves `host` to its first IPv4 address (getaddrinfo, which blocks; an IPv4 literal doesn't). Returns 0 or -1.
int tsnet_resolve4(const char *host, uint8_t ip[16]);

// ---- Interface addresses ----
// One address of a network interface, for this node's local endpoints (selfeps.h, netmon.LocalAddresses).
typedef struct {
    char name[16];
    bool up, loopback; // the interface's flags
    uint8_t ip[16];
    uint8_t prefix_len; // the subnet's length, of 128 bits for IPv6 (the device's IPv6 addresses count as /64)
} tsnet_ifaddr_t;
// The interfaces' addresses (getifaddrs on the host, esp_netif on the device), at most `max`. Returns how many, or
// -1 on an error.
int tsnet_ifaddrs(tsnet_ifaddr_t *out, int max);

// ---- The IP stack ----
// tsnet's tun (tun.h) gives lwIP a netif. On the device, lwIP runs in its own tcpip thread (NO_SYS=0). The apps
// build it without core locking (CONFIG_LWIP_TCPIP_CORE_LOCKING is off), so LOCK_TCPIP_CORE isn't there.
// tsnet calls lwIP's raw API only through tsnet_ip_exec. On the host, lwIP is NO_SYS and runs in tsnet's own thread.

// Runs fn(ctx) in lwIP's context and returns its result. The device uses esp_netif_tcpip_exec, which waits for it.
// The host calls fn directly. Never call it from lwIP's context, such as a netif's output: it would wait on itself.
int tsnet_ip_exec(int (*fn)(void *ctx), void *ctx);

// A wake-up for tsnet's loop from another thread: after a signal, `rfd` is readable in tsnet_poll until a clear.
// The device uses an eventfd (rfd == wfd), and the host a non-blocking pipe.
typedef struct {
    int rfd, wfd;
} tsnet_wake_t;
// Returns 0, or -1 (then w holds -1 for both).
int tsnet_wake_open(tsnet_wake_t *w);
// From any thread. It never blocks, and signals beyond the first before a clear are merged.
void tsnet_wake_signal(const tsnet_wake_t *w);
void tsnet_wake_clear(const tsnet_wake_t *w);
void tsnet_wake_close(tsnet_wake_t *w);

// ---- TLS trust ----
// Gives an mbedTLS client config the certificate authorities to verify servers with: ESP-IDF's certificate bundle on the
// device, the system's CA file on the host. Returns 0 or -1. (The type is mbedTLS's; tls.c is its only caller.)
struct mbedtls_ssl_config;
int tsnet_tls_trust(struct mbedtls_ssl_config *conf);

// ---- storage ----
// tsnet's own small values (its keys), kept across restarts: NVS namespace "tsnet" on the device (the app has
// initialised NVS), files in $TSNET_STATE_DIR (default "tsnet-state") on the host. A name is at most 15 characters,
// NVS's limit. Nothing else's storage is read.

// Reads `name` into buf (cap bytes); *len is its length. Returns 0, 1 if there is no such value, -1 on an error or a
// value longer than cap.
int tsnet_store_get(const char *name, void *buf, size_t cap, size_t *len);
// Writes `name`, replacing any value, durably before it returns. Returns 0 or -1.
int tsnet_store_set(const char *name, const void *data, size_t len);
