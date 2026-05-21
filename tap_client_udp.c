/*
 * tap_client_udp.c – Radmin VPN ↔ Linux TAP bridge over UDP
 *
 * Simplified: no persistent socket. Every send operation creates
 * a new UDP socket, connects to the bridge, sends the packet,
 * and closes the socket. Receiving is handled directly in inject.c
 * on per‑request sockets – no global receive function needed.
 */

#include <stdint.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>
#include <ws2tcpip.h>
#include "log.h"
#include "tap_client.h"
#pragma comment(lib, "ws2_32.lib")

/* ---------- control command IDs ---------- */


/* ------------------------------------------------------------------------- */
/*  Globals (only active flag and bridge address)                            */
/* ------------------------------------------------------------------------- */
int   g_active        = 0;
char  g_bridge_ip[64] = {0};
unsigned short g_bridge_port = 0;

int TapClientIsActive(void) {
    return g_active;
}

/* ------------------------------------------------------------------------- */
/*  Helper: create a socket, connect, send one datagram, close               */
/* ------------------------------------------------------------------------- */
static int send_one_datagram(const void *buf, int len)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) {
        LogMsg("send_one_datagram: socket failed");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_bridge_port);
    addr.sin_addr.s_addr = inet_addr(g_bridge_ip);

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        LogMsg("send_one_datagram: connect failed (err=%d)", WSAGetLastError());
        closesocket(s);
        return -1;
    }

    int ret = send(s, (const char*)buf, len, 0);
    if (ret == SOCKET_ERROR) {
        LogMsg("send_one_datagram: send failed (err=%d)", WSAGetLastError());
        closesocket(s);
        return -1;
    }

    closesocket(s);
    return 0;
}

/* ------------------------------------------------------------------------- */
/*  Public API                                                               */
/* ------------------------------------------------------------------------- */

int TapClientInit(const char *ip, unsigned short port)
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    strncpy(g_bridge_ip, ip, sizeof(g_bridge_ip)-1);
    g_bridge_port = port;
    g_active = 1;
    LogMsg("TapClientInit: bridge at %s:%u", g_bridge_ip, g_bridge_port);
    return 0;
}

void TapClientShutdown(void)
{
    g_active = 0;
}

/* Send one Ethernet frame as a UDP datagram (type 0x00 + raw frame). */
int TapClientSendFrame(const uint8_t *frame, int len)
{
    if (!g_active) {
        LogMsg("TapClientSendFrame: driver not active");
        return -1;
    }
    if (len <= 0 || len > 2048) {
        LogMsg("TapClientSendFrame: invalid length %d", len);
        return -1;
    }
    if (!frame) {
        LogMsg("TapClientSendFrame: NULL frame pointer");
        return -1;
    }

    // Build packet: 1 byte type + Ethernet frame
    uint8_t *pkt = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, 1 + len);
    if (!pkt) return -1;
    pkt[0] = 0x00;
    memcpy(pkt + 1, frame, len);

    LogMsg("TapClientSendFrame: sending %d bytes (total %d)", len, 1+len);
    LogHex(frame, min(len, 64), "  TX frame");

    if (len >= 14) {
        uint16_t ethertype = (frame[12] << 8) | frame[13];
        const char *etype_str = "Unknown";
        if (ethertype == 0x0800) etype_str = "IPv4";
        else if (ethertype == 0x0806) etype_str = "ARP";
        else if (ethertype == 0x86DD) etype_str = "IPv6";

        LogMsg("  EtherType: 0x%04X (%s), Dst: %02X:%02X:%02X:%02X:%02X:%02X, Src: %02X:%02X:%02X:%02X:%02X:%02X",
               ethertype, etype_str,
               frame[0], frame[1], frame[2], frame[3], frame[4], frame[5],
               frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]);
    }

    int result = send_one_datagram(pkt, 1 + len);
    HeapFree(GetProcessHeap(), 0, pkt);

    if (result < 0) {
        LogMsg("TapClientSendFrame: send failed");
        return -1;
    }
    LogMsg("TapClientSendFrame: sent successfully");
    return 0;
}

/* ------------------------------------------------------------------------- */
/*  Configuration commands (sent via temporary sockets)                      */
/* ------------------------------------------------------------------------- */

static int send_control(uint8_t cmd, const void *data, int datalen)
{
    uint8_t *buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, 2 + datalen);
    if (!buf) return -1;
    buf[0] = 0x01;          // control type
    buf[1] = cmd;
    if (data && datalen > 0)
        memcpy(buf + 2, data, datalen);

    int result = send_one_datagram(buf, 2 + datalen);
    HeapFree(GetProcessHeap(), 0, buf);
    return result;
}

int TapClientSetIPv4(const uint8_t ip[4], uint8_t prefix) {
    uint8_t buf[5];
    memcpy(buf, ip, 4);
    buf[4] = prefix;
    return send_control(TAP_CTRL_SET_IPV4, buf, 5);
}

int TapClientSetIPv4Gateway(const uint8_t ip[4]) {
    return send_control(TAP_CTRL_SET_IPV4_GW, ip, 4);
}

int TapClientSetIPv6(const uint8_t ip[16], uint8_t prefix) {
    uint8_t buf[17];
    memcpy(buf, ip, 16);
    buf[16] = prefix;
    return send_control(TAP_CTRL_SET_IPV6, buf, 17);
}

int TapClientSetMAC(const uint8_t mac[6]) {
    return send_control(TAP_CTRL_SET_MAC, mac, 6);
}

int TapClientSetLinkUp(void) {
    return send_control(TAP_CTRL_LINK_UP, NULL, 0);
}

int TapClientSetLinkDown(void) {
    return send_control(TAP_CTRL_LINK_DOWN, NULL, 0);
}