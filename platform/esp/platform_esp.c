// tsnet's platform layer on ESP-IDF.
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_vfs_eventfd.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "sdkconfig.h"
#include "esp_timer.h"
#include "nvs.h"
#include "platform.h"

uint64_t tsnet_now_ms(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000);
}

uint64_t tsnet_now_us(void)
{
    return (uint64_t)esp_timer_get_time();
}

int tsnet_random(void *buf, size_t len)
{
    // True random on the ESP32-P4: it has no radio of its own, so ESP-IDF keeps the SAR ADC entropy source enabled from
    // boot (docs/en/api-reference/system/random.rst, "Startup"). An app that calls bootloader_random_disable() to use the
    // ADC loses that, and must make its keys first.
    esp_fill_random(buf, len);
    return 0;
}

int tsnet_tls_trust(struct mbedtls_ssl_config *conf)
{
    // ESP-IDF's certificate bundle (the app's sdkconfig picks it; it must hold ISRG Root X1, the root of Tailscale's control and DERP certificates).
    return esp_crt_bundle_attach(conf) == ESP_OK ? 0 : -1;
}

#define STORE_NS "tsnet" // tsnet's own NVS namespace: it never reads another's

int tsnet_store_get(const char *name, void *buf, size_t cap, size_t *len)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(STORE_NS, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return 1; // the namespace doesn't exist yet: nothing stored
    }
    if (err != ESP_OK) {
        return -1;
    }
    size_t n = cap;
    err = nvs_get_blob(h, name, buf, &n);
    nvs_close(h);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return 1;
    }
    if (err != ESP_OK) {
        return -1; // including ESP_ERR_NVS_INVALID_LENGTH: longer than cap
    }
    *len = n;
    return 0;
}

int tsnet_store_set(const char *name, const void *data, size_t len)
{
    nvs_handle_t h;
    if (nvs_open(STORE_NS, NVS_READWRITE, &h) != ESP_OK) {
        return -1;
    }
    esp_err_t err = nvs_set_blob(h, name, data, len);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err == ESP_OK ? 0 : -1;
}

typedef struct {
    tsnet_ifaddr_t *out;
    int max, n;
} ifaddrs_ctx_t;

// Runs in lwIP's context (esp_netif_tcpip_exec), where walking the interfaces is safe.
static esp_err_t list_ifaddrs(void *arg)
{
    ifaddrs_ctx_t *c = arg;
    for (esp_netif_t *nif = esp_netif_next_unsafe(NULL); nif && c->n < c->max; nif = esp_netif_next_unsafe(nif)) {
        char name[8] = "";
        esp_netif_get_netif_impl_name(nif, name);
        bool up = esp_netif_is_netif_up(nif);
        esp_netif_ip_info_t info;
        if (esp_netif_get_ip_info(nif, &info) == ESP_OK && info.ip.addr != 0) {
            tsnet_ifaddr_t *a = &c->out[c->n++];
            memset(a, 0, sizeof *a);
            snprintf(a->name, sizeof a->name, "%s", name);
            a->up = up;
            a->ip[10] = a->ip[11] = 0xff;
            memcpy(a->ip + 12, &info.ip.addr, 4); // lwIP keeps it in network order
            a->prefix_len = (uint8_t)__builtin_popcount(info.netmask.addr);
        }
#if CONFIG_LWIP_IPV6
        esp_ip6_addr_t v6[CONFIG_LWIP_IPV6_NUM_ADDRESSES];
        int k = esp_netif_get_all_ip6(nif, v6);
        for (int i = 0; i < k && c->n < c->max; i++) {
            tsnet_ifaddr_t *a = &c->out[c->n++];
            memset(a, 0, sizeof *a);
            snprintf(a->name, sizeof a->name, "%s", name);
            a->up = up;
            memcpy(a->ip, v6[i].addr, 16);
            a->prefix_len = 64; // esp_netif doesn't say; SLAAC addresses are /64
        }
#endif
    }
    return ESP_OK;
}

int tsnet_ifaddrs(tsnet_ifaddr_t *out, int max)
{
    ifaddrs_ctx_t c = {.out = out, .max = max};
    return esp_netif_tcpip_exec(list_ifaddrs, &c) == ESP_OK ? c.n : -1;
}

// PSRAM first, internal RAM if PSRAM is full (platform.h).
void *tsnet_malloc(size_t n)
{
    return heap_caps_malloc_prefer(n, 2, MALLOC_CAP_SPIRAM, MALLOC_CAP_DEFAULT);
}

void *tsnet_calloc(size_t n, size_t size)
{
    return heap_caps_calloc_prefer(n, size, 2, MALLOC_CAP_SPIRAM, MALLOC_CAP_DEFAULT);
}

void *tsnet_realloc(void *p, size_t n)
{
    return heap_caps_realloc_prefer(p, n, 2, MALLOC_CAP_SPIRAM, MALLOC_CAP_DEFAULT);
}

typedef struct {
    int (*fn)(void *ctx);
    void *ctx;
    int ret;
} ip_exec_t;

static esp_err_t ip_exec_cb(void *arg)
{
    ip_exec_t *e = arg;
    e->ret = e->fn(e->ctx);
    return ESP_OK;
}

// esp_netif_tcpip_exec, not LOCK_TCPIP_CORE: the apps build lwIP without core locking (platform.h).
int tsnet_ip_exec(int (*fn)(void *ctx), void *ctx)
{
    ip_exec_t e = {.fn = fn, .ctx = ctx, .ret = -1};
    return esp_netif_tcpip_exec(ip_exec_cb, &e) == ESP_OK ? e.ret : -1;
}

// ESP-IDF's eventfd: a write adds to its counter and a read takes it to 0, and neither blocks. select sees it next to
// lwIP's sockets (CONFIG_VFS_SUPPORT_SELECT).
int tsnet_wake_open(tsnet_wake_t *w)
{
    w->rfd = w->wfd = -1;
    esp_vfs_eventfd_config_t cfg = ESP_VFS_EVENTD_CONFIG_DEFAULT(); // 5 eventfds: tsnet has one
    esp_err_t err = esp_vfs_eventfd_register(&cfg);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) { // INVALID_STATE: already registered
        return -1;
    }
    int fd = eventfd(0, 0);
    if (fd < 0) {
        return -1;
    }
    w->rfd = w->wfd = fd;
    return 0;
}

void tsnet_wake_signal(const tsnet_wake_t *w)
{
    uint64_t one = 1;
    (void)!write(w->wfd, &one, sizeof one);
}

void tsnet_wake_clear(const tsnet_wake_t *w)
{
    uint64_t n;
    (void)!read(w->rfd, &n, sizeof n);
}

void tsnet_wake_close(tsnet_wake_t *w)
{
    if (w->rfd >= 0) {
        close(w->rfd);
    }
    w->rfd = w->wfd = -1;
}

void tsnet_log(tsnet_log_level_t level, const char *fmt, ...)
{
    char line[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    switch (level) {
    case TSNET_LOG_ERROR: ESP_LOGE("tsnet", "%s", line); break;
    case TSNET_LOG_WARN: ESP_LOGW("tsnet", "%s", line); break;
    case TSNET_LOG_INFO: ESP_LOGI("tsnet", "%s", line); break;
    default: ESP_LOGD("tsnet", "%s", line); break;
    }
}
