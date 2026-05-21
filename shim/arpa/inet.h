#ifndef _ARPA_INET_H_SHIM_
#define _ARPA_INET_H_SHIM_

/*
 * MinGW-w64 does not have arpa/inet.h.
 * This shim provides the few functions and types that
 * the wireguard-c library expects, using Winsock2.
 */

#include <winsock2.h>
#include <ws2tcpip.h>   /* for inet_pton / inet_ntop if needed */

/* Required typedef for lwIP compatibility */
typedef unsigned long in_addr_t;

/* These macros are usually defined in netinet/in.h; provide them */
#ifndef IPPROTO_IP
#define IPPROTO_IP 0
#endif
#ifndef INADDR_ANY
#define INADDR_ANY ((unsigned long)0x00000000)
#endif

#endif /* _ARPA_INET_H_SHIM_ */