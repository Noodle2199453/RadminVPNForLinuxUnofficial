#ifndef TAP_CLIENT_H
#define TAP_CLIENT_H

#include <stdint.h>

/* ---------- control command IDs (shared by both sides) ---------- */
#define TAP_CTRL_SET_IPV4      0x01
#define TAP_CTRL_SET_IPV4_GW   0x02
#define TAP_CTRL_SET_IPV6      0x03
#define TAP_CTRL_SET_MAC       0x04
#define TAP_CTRL_LINK_UP       0x10
#define TAP_CTRL_LINK_DOWN     0x11

/* ---------- platform‑specific socket type ---------- */
#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET tap_socket_t;
  #define TAP_INVALID_SOCKET  INVALID_SOCKET
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  typedef int tap_socket_t;
  #define TAP_INVALID_SOCKET  (-1)
#endif

/* ---------- common function declarations ---------- */
#ifdef __cplusplus
extern "C" {
#endif

int  TapClientInit(const char *ip, unsigned short port);
void TapClientShutdown(void);
int  TapClientIsActive(void);

int  TapClientSendFrame(const uint8_t *frame, int len);

int TapClientSetIPv4(const uint8_t ip[4], uint8_t prefix);
int TapClientSetIPv4Gateway(const uint8_t ip[4]);
int TapClientSetIPv6(const uint8_t ip[16], uint8_t prefix);
int TapClientSetMAC(const uint8_t mac[6]);
int TapClientSetLinkUp(void);
int TapClientSetLinkDown(void);

#ifdef __cplusplus
}
#endif

#endif /* TAP_CLIENT_H */