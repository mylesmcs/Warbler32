#pragma once

#include "esp_err.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Brings up the wg0 tunnel from g_config.wg_* fields. No-op (returns ESP_OK)
// if g_config.wg_enabled is 0. Call after wifi_manager_start() and
// time_sync_start() — WireGuard's handshake relies on a timestamp, and a
// working network is obviously required before a tunnel over it can exist.
// Never returns a fatal error for a bad/unreachable config — logs and
// leaves the tunnel down instead, so a typo'd key can't boot-loop the device.
esp_err_t wireguard_manager_start(void);

// True once the handshake with the peer has actually completed — not just
// "we asked it to connect".
bool wireguard_manager_is_up(void);

// Seconds since the last successful handshake, or -1 if there's never been
// one (disabled, or peer unreachable so far).
int wireguard_manager_seconds_since_handshake(void);

#ifdef __cplusplus
}
#endif