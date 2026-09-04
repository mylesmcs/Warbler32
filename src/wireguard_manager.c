#include "wireguard_manager.h"
#include "app_config.h"

#include "esp_wireguard.h"
#include "esp_log.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char *TAG = "wireguard";

static wireguard_ctx_t s_ctx = {0};
static bool s_started = false;

// e.g. 24 -> "255.255.255.0". The library wants netmask strings, we store
// CIDR prefixes — this is the conversion between the two, shared by both
// the interface's own address and every allowed-subnet entry below.
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
    wg_config.private_key = g_config.wg_private_key;
    wg_config.public_key  = g_config.wg_peer_public_key;
    wg_config.endpoint    = g_config.wg_peer_endpoint;
    wg_config.port        = g_config.wg_peer_port;
    wg_config.address     = g_config.wg_local_addr;
    wg_config.netmask     = netmask_str;
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

    // Peer-level AllowedIPs — separate from our own address above. Without
    // this, the tunnel comes up but nothing actually routes through it.
    // Requires ctx.netif to already exist, hence this runs after connect.
    if (g_config.wg_allowed_subnets[0]) {
        // strtok_r writes into the string it's given — work on a throwaway
        // copy so g_config's own field (shown back in the web UI) isn't
        // silently mangled.
        char subnets_buf[sizeof(g_config.wg_allowed_subnets)];
        strlcpy(subnets_buf, g_config.wg_allowed_subnets, sizeof(subnets_buf));

        char *saveptr = NULL;
        char *tok = strtok_r(subnets_buf, ",", &saveptr);
        while (tok) {
            while (*tok == ' ') tok++;  // tolerate "a/24, b/24"

            char *slash = strchr(tok, '/');
            if (slash) {
                *slash = '\0';
                int prefix = atoi(slash + 1);
                if (prefix < 0)  prefix = 0;
                if (prefix > 32) prefix = 32;

                char mask_str[16];
                prefix_to_netmask((uint8_t)prefix, mask_str, sizeof(mask_str));

                esp_err_t aerr = esp_wireguard_add_allowed_ip(&s_ctx, tok, mask_str);
                if (aerr != ESP_OK) {
                    ESP_LOGW(TAG, "add_allowed_ip(%s/%d) failed: %s",
                             tok, prefix, esp_err_to_name(aerr));
                }
            } else {
                ESP_LOGW(TAG, "skipping malformed allowed subnet (missing /prefix): %s", tok);
            }
            tok = strtok_r(NULL, ",", &saveptr);
        }
    } else {
        ESP_LOGW(TAG, "no allowed subnets configured — tunnel is up but nothing will route through it");
    }

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