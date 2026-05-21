#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static int config_parse_line(const char *line, app_config_t *cfg) {
    char key[64], value[256];
    if (sscanf(line, "%63[^=]=%255s", key, value) != 2)
        return -1;

    if (_stricmp(key, "driver") == 0) {
        if (_stricmp(value, "linux_tap") == 0)
            cfg->driver = DRIVER_LINUX_TAP;
        else if (_stricmp(value, "wireguard_server") == 0)
            cfg->driver = DRIVER_WIREGUARD_SERVER;
        else
            return -1;
    } else if (_stricmp(key, "tap_addr") == 0) {
        strncpy(cfg->tap_addr, value, sizeof(cfg->tap_addr)-1);
    } else if (_stricmp(key, "tap_port") == 0) {
        cfg->tap_port = (unsigned short)atoi(value);
    }
    return 0;
}

static void config_write_defaults(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# Radmin VPN emulation driver config\n");
    fprintf(f, "# driver = linux_tap or wireguard_server\n");
    fprintf(f, "driver=linux_tap\n");
    fprintf(f, "# When driver=linux_tap, these are used:\n");
    fprintf(f, "tap_addr=127.0.0.1\n");
    fprintf(f, "tap_port=12345\n");
    fclose(f);
}

int config_load(const char *dll_path, app_config_t *cfg, void (*logfn)(const char *fmt, ...)) {
    char cfg_path[MAX_PATH];
    snprintf(cfg_path, sizeof(cfg_path), "%s\\radmin.conf", dll_path);

    // Defaults
    memset(cfg, 0, sizeof(*cfg));
    cfg->driver    = DRIVER_LINUX_TAP;
    cfg->tap_port  = 12345;
    strcpy(cfg->tap_addr, "127.0.0.1");

    FILE *f = fopen(cfg_path, "r");
    if (!f) {
        if (logfn) logfn("radmin.conf not found, creating default.");
        config_write_defaults(cfg_path);
        return 0;   // use defaults
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // skip comments / empty lines
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        config_parse_line(p, cfg);
    }
    fclose(f);
    return 0;
}