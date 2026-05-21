/*
 * linux_tap.c – TAP device ↔ Wine injector bridge over UDP
 *
 * - Single-threaded, uses poll() to read from TAP and UDP socket.
 * - Control commands are identified by the 2‑byte magic 0xFFFF.
 * - All configuration is sent from the injector (via tap_client_udp.c).
 *
 * Compile: gcc -o linux_tap linux_tap.c -lpthread   (no -lpthread needed, but harmless)
 *           gcc -DDEBUG=1 -o linux_tap linux_tap.c
 * Usage:   ./linux_tap <tap_iface> <listen_port>
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include "tap_client.h"
/* ------------------------------------------------------------------------- */
/*  Debug toggle – set to 1 to print hex dumps                               */
/* ------------------------------------------------------------------------- */
#ifndef DEBUG
#define DEBUG 1
#endif

static int tap_fd = -1;
static int udp_sock = -1;
static int running = 1;
static char ifname[IFNAMSIZ];

/* Client address – learned from the first received packet */
static struct sockaddr_in client_addr;
static int client_addr_set = 0;

/* ------------------------------------------------------------------------- */
/*  Logging                                                                  */
/* ------------------------------------------------------------------------- */
void log_msg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

#if DEBUG
static void debug_hex(const char *prefix, const uint8_t *data, int len) {
    fprintf(stderr, "%s (%d bytes): ", prefix, len);
    for (int i = 0; i < len; i++) fprintf(stderr, "%02X ", data[i]);
    fprintf(stderr, "\n");
}
#else
#define debug_hex(prefix, data, len) do {} while(0)
#endif

/* ------------------------------------------------------------------------- */
/*  Helper: create a temporary socket for interface ioctls                   */
/* ------------------------------------------------------------------------- */
static int get_iface_socket(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) perror("socket for ioctl");
    return s;
}

/* ------------------------------------------------------------------------- */
/*  Control command handlers – now receive data as buffer                    */
/* ------------------------------------------------------------------------- */

static int handle_set_ipv4(const uint8_t *data) {
    // data[0..3] = IPv4 addr, data[4] = prefix
    struct in_addr addr;
    memcpy(&addr, data, 4);
    uint8_t prefix = data[4];

    int s = get_iface_socket();
    if (s < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    sin->sin_addr = addr;
    if (ioctl(s, SIOCSIFADDR, &ifr) < 0) {
        perror("SIOCSIFADDR"); close(s); return -1;
    }

    uint32_t mask = (prefix == 0) ? 0 : htonl(~((1ULL << (32 - prefix)) - 1));
    sin->sin_addr.s_addr = mask;
    if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0) {
        perror("SIOCSIFNETMASK"); close(s); return -1;
    }

    close(s);
    log_msg("Set IPv4: %s/%u", inet_ntoa(addr), prefix);
    return 0;
}

static int handle_set_ipv4_gw(const uint8_t *data) {
    struct in_addr gw;
    memcpy(&gw, data, 4);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip route replace default via %s dev %s 2>/dev/null",
             inet_ntoa(gw), ifname);
    int ret = system(cmd);
    if (ret != 0)
        log_msg("Warning: failed to set gateway via %s (ret=%d)", inet_ntoa(gw), ret);
    else
        log_msg("Set default gateway: %s", inet_ntoa(gw));
    return 0;
}

static int handle_set_ipv6(const uint8_t *data) {
    struct in6_addr addr;
    memcpy(&addr, data, 16);
    uint8_t prefix = data[16];

    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr, addr_str, sizeof(addr_str));

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip -6 addr replace %s/%u dev %s 2>/dev/null",
             addr_str, prefix, ifname);
    int ret = system(cmd);
    if (ret != 0)
        log_msg("Warning: failed to set IPv6 address (ret=%d)", ret);
    else
        log_msg("Set IPv6: %s/%u", addr_str, prefix);
    return 0;
}

static int handle_set_mac(const uint8_t *data) {
    int s = get_iface_socket();
    if (s < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(ifr.ifr_hwaddr.sa_data, data, 6);

    if (ioctl(s, SIOCSIFHWADDR, &ifr) < 0) {
        perror("SIOCSIFHWADDR"); close(s); return -1;
    }
    close(s);
    log_msg("Set MAC: %02x:%02x:%02x:%02x:%02x:%02x",
            data[0], data[1], data[2], data[3], data[4], data[5]);
    return 0;
}

static int handle_link_up(void) {
    int s = get_iface_socket();
    if (s < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS"); close(s); return -1;
    }
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        perror("SIOCSIFFLAGS (UP)"); close(s); return -1;
    }
    close(s);
    log_msg("Interface %s is UP", ifname);
    return 0;
}

static int handle_link_down(void) {
    int s = get_iface_socket();
    if (s < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS"); close(s); return -1;
    }
    ifr.ifr_flags &= ~IFF_UP;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        perror("SIOCSIFFLAGS (DOWN)"); close(s); return -1;
    }
    close(s);
    log_msg("Interface %s is DOWN", ifname);
    return 0;
}

/* ------------------------------------------------------------------------- */
/*  TAP allocation                                                           */
/* ------------------------------------------------------------------------- */
static int tap_alloc(const char *dev) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); return -1; }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF"); close(fd); return -1; }
    log_msg("TAP interface %s created", dev);
    return fd;
}

#define MAX_CLIENTS 32
struct sockaddr_in clients[MAX_CLIENTS];
int nclients = 0;

/* ------------------------------------------------------------------------- */
/*  Main loop using poll()                                                   */
/* ------------------------------------------------------------------------- */
int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <tap_iface> <listen_port>\n", argv[0]);
        return 1;
    }
    const char *tap_name = argv[1];
    int port = atoi(argv[2]);

    strncpy(ifname, tap_name, sizeof(ifname) - 1);
    ifname[sizeof(ifname) - 1] = '\0';

    tap_fd = tap_alloc(tap_name);
    if (tap_fd < 0) return 1;

    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(udp_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }

    log_msg("UDP TAP bridge listening on 127.0.0.1:%u", port);

    struct pollfd fds[2];
    fds[0].fd = tap_fd;
    fds[0].events = POLLIN;
    fds[1].fd = udp_sock;
    fds[1].events = POLLIN;

    uint8_t buf[2048];

    while (running) {
        int ret = poll(fds, 2, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll"); break;
        }

        // ----- TAP → UDP -----
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(tap_fd, buf + 1, sizeof(buf) - 1);  // leave room for type
            if (n < 0) {
                perror("read tap");
                if (errno == EIO || errno == ENETDOWN) continue;
                break;
            }
            if (n == 0) {
                log_msg("EOF on TAP"); break;
            }

            buf[0] = 0x00;   // data frame type
            debug_hex("TAP -> UDP", buf + 1, n);

            // Broadcast to every known client
            for (int i = 0; i < nclients; i++) {
                if (sendto(udp_sock, buf, n + 1, 0,
                        (struct sockaddr*)&clients[i],
                        sizeof(clients[i])) < 0) {
                    perror("sendto");
                }
            }
        }

        // ----- UDP → TAP -----
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            ssize_t n = recvfrom(udp_sock, buf, sizeof(buf), 0,
                                (struct sockaddr*)&from, &fromlen);
            if (n < 0) { perror("recvfrom"); continue; }

            // Update client list: if already present, do nothing; otherwise add (overwrite oldest if full)
            int found = 0;
            for (int i = 0; i < nclients; i++) {
                if (memcmp(&clients[i], &from, sizeof(from)) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                if (nclients < MAX_CLIENTS) {
                    clients[nclients++] = from;          // there's room
                } else {
                    // Array is full – overwrite the oldest slot (index 0) and shift the rest
                    memmove(&clients[0], &clients[1], (MAX_CLIENTS - 1) * sizeof(clients[0]));
                    clients[MAX_CLIENTS - 1] = from;    // place new client at the end
                }
            }

            if (n < 1) {
                log_msg("Datagram too short (%zd bytes)", n);
                continue;
            }

            uint8_t type = buf[0];

            if (type == 0x01) {
                // ---------- control command ----------
                if (n < 2) {
                    log_msg("Invalid control frame (no command byte)");
                    continue;
                }
                uint8_t cmd = buf[1];
                const uint8_t *data = buf + 2;
                int datalen = n - 2;

                log_msg("Control command 0x%02X, datalen=%d", cmd, datalen);
                switch (cmd) {
                    case TAP_CTRL_SET_IPV4:    handle_set_ipv4(data); break;
                    case TAP_CTRL_SET_IPV4_GW: handle_set_ipv4_gw(data); break;
                    case TAP_CTRL_SET_IPV6:    handle_set_ipv6(data); break;
                    case TAP_CTRL_SET_MAC:     handle_set_mac(data); break;
                    case TAP_CTRL_LINK_UP:     handle_link_up(); break;
                    case TAP_CTRL_LINK_DOWN:   handle_link_down(); break;
                    default: log_msg("Unknown control command 0x%02X", cmd);
                }
            }
            else if (type == 0x00) {
                // ---------- regular Ethernet frame ----------
                const uint8_t *frame = buf + 1;
                int frame_len = n - 1;

                debug_hex("UDP -> TAP", frame, frame_len);

                ssize_t written = write(tap_fd, frame, frame_len);
                if (written < 0) {
                    perror("write tap");
                    if (errno == EIO || errno == ENETDOWN) continue;
                    break;
                }
                if (written != frame_len) {
                    fprintf(stderr, "Short write: %zd/%d\n", written, frame_len);
                }
            }
            else {
                log_msg("Unknown datagram type 0x%02X (%zd bytes)", type, n);
            }
        }
    }

    close(udp_sock);
    close(tap_fd);
    return 0;
}