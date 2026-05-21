#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

#define CONFIG_DRIVER_LINUX_TAP      "linux_tap"
#define CONFIG_DRIVER_WIREGUARD_SRV  "wireguard_server"

typedef enum {
    DRIVER_NONE,
    DRIVER_LINUX_TAP,
    DRIVER_WIREGUARD_SERVER
} config_driver_t;

typedef struct {
    config_driver_t driver;
    char            tap_addr[64];   // e.g. "127.0.0.1"
    unsigned short  tap_port;       // e.g. 12345
    // (WireGuard config is still read from wireguard.conf)
} app_config_t;

// Load config from radmin.conf beside the DLL.
// If file missing, create it with defaults and return zero.
// On success returns 0, on error -1.
int config_load(const char *dll_path, app_config_t *cfg, void (*logfn)(const char *fmt, ...));

#endif