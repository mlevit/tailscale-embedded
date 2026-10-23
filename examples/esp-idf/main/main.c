// A tailnet node on an ESP32-P4: connect the network, set the clock, start tsnet's server and log the netmap.
// Once it's RUNNING, `tailscale ping --icmp <hostname>` from another node gets answers from lwIP behind the tunnel.
#include <stdio.h>
#include <string.h>
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/tcpip.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include "server.h"

// TLS to control and DERP, the Noise handshake, and tsnet's own peaks (server.h).
#define TASK_STACK (24 * 1024)

static const char *TAG = "example";
static tsnet_server_t *srv;

static void on_state(void *ctx, tsnet_client_state_t state, const char *detail)
{
    (void)ctx;
    static const char *names[] = {
        [TSNET_CLIENT_STARTING] = "starting",
        [TSNET_CLIENT_NEEDS_AUTH] = "needs auth",
        [TSNET_CLIENT_LOGGED_IN] = "logged in",
        [TSNET_CLIENT_RUNNING] = "running",
        [TSNET_CLIENT_NODE_REMOVED] = "node removed",
    };
    // With no auth key, "needs auth" carries the URL to visit to log the node in.
    ESP_LOGI(TAG, "state: %s %s", names[state], detail ? detail : "");
}

static void on_netmap(void *ctx, const tsnet_netmap_t *nm, int changed)
{
    (void)ctx;
    (void)changed;
    for (size_t i = 0; nm->has_node && i < nm->node.n_addresses; i++) {
        const tsnet_ip_t *ip = &nm->node.addresses[i].ip;
        if (!ip->is6) {
            ESP_LOGI(TAG, "this node: %u.%u.%u.%u", ip->ip[0], ip->ip[1], ip->ip[2], ip->ip[3]);
        }
    }
    for (size_t i = 0; i < nm->n_peers; i++) {
        ESP_LOGI(TAG, "peer: %s", nm->peers[i].name);
    }
}

// tsnet's event loop: one task runs poll, wait and step. lwIP runs in ESP-IDF's tcpip thread.
static void tsnet_task(void *arg)
{
    (void)arg;
    for (;;) {
        tsnet_poll_t p[TSNET_SERVER_POLL_MAX];
        int wait = 1000;
        int n = tsnet_server_poll(srv, p, TSNET_SERVER_POLL_MAX, &wait);
        tsnet_poll(p, n, wait < 0 || wait > 1000 ? 1000 : wait);
        tsnet_server_step(srv);
    }
}

void app_main(void)
{
    // tsnet keeps its keys in NVS (namespace "tsnet"). Turn on flash and NVS encryption for a device that leaves you.
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(example_connect()); // Ethernet or Wi-Fi, as menuconfig's "Example Connection Configuration" says

    // TLS checks certificate dates, and peers refuse a WireGuard initiation dated before the last one: set the clock.
    esp_sntp_config_t sntp = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    esp_netif_sntp_init(&sntp);
    if (esp_netif_sntp_sync_wait(pdMS_TO_TICKS(15000)) != ESP_OK) {
        ESP_LOGW(TAG, "clock not synced: peers may ignore handshakes");
    }

    tsnet_server_cfg_t cfg = {
        .client =
            {
                .server_url = CONFIG_EXAMPLE_CONTROL_URL,
                // Sent only to register a new node; after that the stored node key logs in. Empty: log in by URL.
                .auth_key = CONFIG_EXAMPLE_AUTH_KEY[0] ? CONFIG_EXAMPLE_AUTH_KEY : NULL,
                .hostname = CONFIG_EXAMPLE_HOSTNAME,
                .ipn_version = "tailscale-embedded-example",
                .os = "linux",
                .os_version = "ESP-IDF",
                .machine = "esp32p4",
            },
        .input = tcpip_input,
        .on_netmap = on_netmap,
        .on_state = on_state,
    };
    srv = tsnet_server_new(&cfg);
    if (srv == NULL) {
        ESP_LOGE(TAG, "tsnet_server_new failed");
        return;
    }
    // The stack is in PSRAM, which is safe here because sdkconfig.defaults runs the firmware from PSRAM
    // (CONFIG_SPIRAM_XIP_FROM_PSRAM). Without that, use xTaskCreate: an NVS write turns the cache off under it.
    if (xTaskCreateWithCaps(tsnet_task, "tsnet", TASK_STACK, NULL, 5, NULL, MALLOC_CAP_SPIRAM) != pdPASS) {
        ESP_LOGE(TAG, "no memory for tsnet's task");
    }
}
