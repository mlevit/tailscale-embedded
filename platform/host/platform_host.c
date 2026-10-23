// tsnet's platform layer on the host, macOS or Linux: host tests and the conformance harness.
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _DEFAULT_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "mbedtls/ssl.h"
#include "platform.h"

uint64_t tsnet_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

uint64_t tsnet_now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

int tsnet_random(void *buf, size_t len)
{
#if defined(__APPLE__)
    arc4random_buf(buf, len); // the kernel's CSPRNG; it cannot fail
    return 0;
#else
    unsigned char *p = buf;
    while (len > 0) { // getentropy() gives at most 256 bytes a call
        size_t n = len < 256 ? len : 256;
        if (getentropy(p, n) != 0) {
            return -1;
        }
        p += n;
        len -= n;
    }
    return 0;
#endif
}

int tsnet_tls_trust(struct mbedtls_ssl_config *conf)
{
    // The system's roots, as Go's crypto/x509 loads them (root_darwin uses the keychain; this file is its export).
    // shortcut: no baked-in ISRG Root X1 fallback (net/tlsdial bakedroots); add it if a host without a CA file needs one.
    static const char *FILES[] = {"/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"};
    static mbedtls_x509_crt roots;
    static int loaded;
    if (!loaded) {
        mbedtls_x509_crt_init(&roots);
        for (size_t i = 0; i < sizeof FILES / sizeof FILES[0] && !loaded; i++) {
            loaded = mbedtls_x509_crt_parse_file(&roots, FILES[i]) >= 0 && roots.version != 0;
        }
        if (!loaded) {
            return -1;
        }
    }
    mbedtls_ssl_conf_ca_chain(conf, &roots, NULL);
    return 0;
}

// The file for a stored value: $TSNET_STATE_DIR/<name>. A name is a plain word (letters, digits, '_' and '-').
static const char *state_dir(void)
{
    const char *dir = getenv("TSNET_STATE_DIR");
    return dir && dir[0] ? dir : "tsnet-state";
}

// The directory holds private keys: it must be a real directory (not a symlink), this user's, and closed to others.
// Made 0700 if it isn't there.
static int state_dir_ok(void)
{
    const char *dir = state_dir();
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    struct stat st;
    if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 077) != 0) {
        tsnet_log(TSNET_LOG_ERROR, "store: %s must be a directory of this user's with mode 0700", dir);
        return -1;
    }
    return 0;
}

static int store_path(char *out, size_t cap, const char *name)
{
    if (name[0] == '\0' || strlen(name) > 15 || strspn(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                                            "0123456789_-") != strlen(name)) {
        return -1;
    }
    int n = snprintf(out, cap, "%s/%s", state_dir(), name);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

int tsnet_store_get(const char *name, void *buf, size_t cap, size_t *len)
{
    char path[1024];
    if (store_path(path, sizeof path, name) != 0 || state_dir_ok() != 0) {
        return -1;
    }
    int fd = open(path, O_RDONLY | O_NOFOLLOW); // a symlink planted for a key file is refused
    if (fd < 0) {
        return errno == ENOENT ? 1 : -1;
    }
    FILE *f = fdopen(fd, "rb");
    if (f == NULL) {
        close(fd);
        return -1;
    }
    size_t n = fread(buf, 1, cap, f);
    int extra = fgetc(f); // a value longer than cap is an error, as NVS's
    int bad = ferror(f) || extra != EOF;
    fclose(f);
    if (bad) {
        return -1;
    }
    *len = n;
    return 0;
}

int tsnet_store_set(const char *name, const void *data, size_t len)
{
    char path[1024], tmp[1040];
    if (store_path(path, sizeof path, name) != 0 || state_dir_ok() != 0) {
        return -1;
    }
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    // Written whole to a temporary file, synced, then renamed over the old one: a crash leaves the old value or the new.
    // The temporary file is always a new one (O_EXCL, never a symlink or a file left there), so it is 0600.
    unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return -1;
    }
    int ok = write(fd, data, len) == (ssize_t)len && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    if (!ok || rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    int dfd = open(state_dir(), O_RDONLY); // the rename durable too, as platform.h promises
    if (dfd >= 0) {
        fsync(dfd);
        close(dfd);
    }
    return 0;
}

void tsnet_log(tsnet_log_level_t level, const char *fmt, ...)
{
    static const char LETTER[] = "?EWID";
    static int quiet = -1; // TSNET_LOG_QUIET=1: errors only (a test that makes thousands of warnings on purpose)
    if (quiet < 0) {
        const char *q = getenv("TSNET_LOG_QUIET");
        quiet = q != NULL && q[0] == '1';
    }
    if (quiet && level > TSNET_LOG_ERROR) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%c tsnet: ", level <= TSNET_LOG_DEBUG ? LETTER[level] : '?');
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static int prefix_bits(const uint8_t *mask, int len)
{
    int bits = 0;
    for (int i = 0; i < len; i++) {
        for (uint8_t b = mask[i]; b; b <<= 1) {
            bits += (b & 0x80) != 0;
        }
    }
    return bits;
}

int tsnet_ifaddrs(tsnet_ifaddr_t *out, int max)
{
    struct ifaddrs *list;
    if (getifaddrs(&list) != 0) {
        return -1;
    }
    int n = 0;
    for (struct ifaddrs *i = list; i && n < max; i = i->ifa_next) {
        if (!i->ifa_addr || (i->ifa_addr->sa_family != AF_INET && i->ifa_addr->sa_family != AF_INET6)) {
            continue;
        }
        tsnet_ifaddr_t *a = &out[n];
        memset(a, 0, sizeof *a);
        snprintf(a->name, sizeof a->name, "%s", i->ifa_name);
        a->up = (i->ifa_flags & IFF_UP) != 0;
        a->loopback = (i->ifa_flags & IFF_LOOPBACK) != 0;
        if (i->ifa_addr->sa_family == AF_INET) {
            a->ip[10] = a->ip[11] = 0xff;
            memcpy(a->ip + 12, &((struct sockaddr_in *)i->ifa_addr)->sin_addr, 4);
            if (i->ifa_netmask) {
                a->prefix_len = (uint8_t)prefix_bits((uint8_t *)&((struct sockaddr_in *)i->ifa_netmask)->sin_addr, 4);
            }
        } else {
            memcpy(a->ip, &((struct sockaddr_in6 *)i->ifa_addr)->sin6_addr, 16);
            if (i->ifa_netmask) {
                a->prefix_len =
                    (uint8_t)prefix_bits((uint8_t *)&((struct sockaddr_in6 *)i->ifa_netmask)->sin6_addr, 16);
            }
        }
        n++;
    }
    freeifaddrs(list);
    return n;
}

void *tsnet_malloc(size_t n)
{
    return malloc(n);
}

void *tsnet_calloc(size_t n, size_t size)
{
    return calloc(n, size);
}

void *tsnet_realloc(void *p, size_t n)
{
    return realloc(p, n);
}

// The host's lwIP is NO_SYS, in tsnet's own thread.
int tsnet_ip_exec(int (*fn)(void *ctx), void *ctx)
{
    return fn(ctx);
}

int tsnet_wake_open(tsnet_wake_t *w)
{
    int fds[2];
    w->rfd = w->wfd = -1;
    if (pipe(fds) != 0) {
        return -1;
    }
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    fcntl(fds[1], F_SETFL, O_NONBLOCK);
    w->rfd = fds[0];
    w->wfd = fds[1];
    return 0;
}

void tsnet_wake_signal(const tsnet_wake_t *w)
{
    char b = 1;
    (void)!write(w->wfd, &b, 1); // a full pipe (EAGAIN) is already signalled
}

void tsnet_wake_clear(const tsnet_wake_t *w)
{
    char buf[64];
    while (read(w->rfd, buf, sizeof buf) > 0) {
    }
}

void tsnet_wake_close(tsnet_wake_t *w)
{
    if (w->rfd >= 0) {
        close(w->rfd);
        close(w->wfd);
    }
    w->rfd = w->wfd = -1;
}
