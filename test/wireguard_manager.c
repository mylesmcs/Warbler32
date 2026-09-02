#include "wireguard_manager.h"
#include "app_config.h"

#include "esp_wireguard.h"
#include "esp_log.h"
#include <stdio.h>
#include <time.h>

static const char *TAG = "wireguard";

static wireguard_ctx_t s_ctx = {0};
static bool s_started = false;

// e.g. 24 -> "255.255.255.0". The library wants a netmask string, we store
// a CIDR prefix — this is the conversion between the two.
static void prefix_to_netmask(uint8_t prefix, char *out, size_t outsz)
{
    uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
    snprintf(out, outsz, "%u.%u.%u.%u",
             (unsigned)(mask >> 24) & 0xFF, (unsigned)(mask >> 16) & 0xFF,
             (unsigned)(mask >> 8) & 0xFF,  (unsigned)mask & 0xFF);
}

esp_err_t wireguard_manager_start(void)
{
    if (!g_config.wg_enabled) {
        ESP_LOGI(TAG, "disabled, skipping");
        return ESP_OK;
    }

    char netmask_str[16];
    prefix_to_netmask(g_config.wg_local_prefix, netmask_str, sizeof(netmask_str));

    wireguard_config_t wg_config = ESP_WIREGUARD_CONFIG_DEFAULT();
    wg_config.private_key     = g_config.wg_private_key;
    wg_config.public_key      = g_config.wg_peer_public_key;
    wg_config.endpoint        = g_config.wg_peer_endpoint;
    wg_config.port            = g_config.wg_peer_port;
    wg_config.address = g_config.wg_local_addr;
    wg_config.netmask = netmask_str;
    if (g_config.wg_keepalive_sec > 0) {
        wg_config.persistent_keepalive = g_config.wg_keepalive_sec;
    }

    esp_err_t err = esp_wireguard_init(&wg_config, &s_ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "init failed: %s — tunnel disabled this boot", esp_err_to_name(err));
        return ESP_OK;
    }

    err = esp_wireguard_connect(&s_ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "connect failed: %s — tunnel disabled this boot", esp_err_to_name(err));
        return ESP_OK;
    }

    s_started = true;
    ESP_LOGI(TAG, "tunnel starting: local=%s/%u peer=%s:%u",
             g_config.wg_local_addr, g_config.wg_local_prefix,
             g_config.wg_peer_endpoint, g_config.wg_peer_port);
    return ESP_OK;
}

bool wireguard_manager_is_up(void)
{
    if (!s_started) return false;
    return esp_wireguardif_peer_is_up(&s_ctx) == ESP_OK;
}

int wireguard_manager_seconds_since_handshake(void)
{
    if (!s_started) return -1;
    time_t last = 0;
    if (esp_wireguard_latest_handshake(&s_ctx, &last) != ESP_OK || last == 0) {
        return -1;
    }
    return (int)(time(NULL) - last);
}