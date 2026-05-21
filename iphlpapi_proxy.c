/*
 * iphlpapi_proxy.c – Complete stub/proxy iphlpapi.dll for Radmin VPN on Wine.
 * Compile for 32‑bit with:  i686-w64-mingw32-gcc -shared -o iphlpapi.dll iphlpapi_proxy.c -s -static-libgcc -Wl,--kill-at
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <iptypes.h>
#include <iprtrmib.h>
#include <ipexport.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
/* ---------- helpers ---------- */
static DWORD set_last_error(DWORD err) { SetLastError(err); return err; }

/* ---------- Missing flags (not in all MinGW headers) ---------- */
#ifndef IP_ADAPTER_LOOPBACK
#define IP_ADAPTER_LOOPBACK        0x00000004
#endif
#ifndef IP_ADAPTER_IPV4_ENABLED
#define IP_ADAPTER_IPV4_ENABLED    0x00000010
#endif
#ifndef IP_ADAPTER_IPV6_ENABLED
#define IP_ADAPTER_IPV6_ENABLED    0x00000020
#endif

/* ---------- Real implementation of GetAdaptersAddresses ---------- */
DWORD WINAPI GetAdaptersAddresses(
    ULONG Family,
    ULONG Flags,
    PVOID Reserved,
    PIP_ADAPTER_ADDRESSES AdapterAddresses,
    PULONG SizePointer)
{
    if (!SizePointer) return ERROR_INVALID_PARAMETER;

    /* We only provide the loopback adapter (one entry) */
    #define LOOPBACK_MTU 1500
    #define LOOPBACK_IF_INDEX 1
    #define LOOPBACK_NAME "Loopback Pseudo-Interface 1"
    #define LOOPBACK_FRIENDLY L"Loopback"
    #define LOOPBACK_DESC L"Software Loopback Interface"

    /* Calculate size: sizeof(IP_ADAPTER_ADDRESSES) + string lengths */
    DWORD name_len    = (lstrlenA(LOOPBACK_NAME) + 1) * sizeof(CHAR);     /* narrow string */
    DWORD friendly_len = (lstrlenW(LOOPBACK_FRIENDLY) + 1) * sizeof(WCHAR);
    DWORD desc_len    = (lstrlenW(LOOPBACK_DESC) + 1) * sizeof(WCHAR);
    DWORD total_size  = sizeof(IP_ADAPTER_ADDRESSES_LH) + name_len + friendly_len + desc_len;

    if (*SizePointer < total_size) {
        *SizePointer = total_size;
        return ERROR_BUFFER_OVERFLOW;
    }

    /* Clear buffer */
    memset(AdapterAddresses, 0, total_size);

    PIP_ADAPTER_ADDRESSES aa = AdapterAddresses;
    aa->Length = sizeof(IP_ADAPTER_ADDRESSES_LH);
    aa->IfIndex = LOOPBACK_IF_INDEX;
    aa->IfType  = IF_TYPE_SOFTWARE_LOOPBACK;
    aa->OperStatus = IfOperStatusUp;
    aa->Mtu = LOOPBACK_MTU;
    aa->PhysicalAddressLength = 0;  /* loopback has no MAC */
    aa->Flags = IP_ADAPTER_LOOPBACK | IP_ADAPTER_IPV4_ENABLED | IP_ADAPTER_IPV6_ENABLED;

    /* Fill strings (AdapterName is PCHAR, FriendlyName & Description are PWCHAR) */
    aa->AdapterName = (PCHAR)((BYTE*)aa + aa->Length);
    memcpy(aa->AdapterName, LOOPBACK_NAME, name_len);
    aa->FriendlyName = (LPWSTR)((BYTE*)aa + aa->Length + name_len);
    memcpy(aa->FriendlyName, LOOPBACK_FRIENDLY, friendly_len);
    aa->Description = (LPWSTR)((BYTE*)aa + aa->Length + name_len + friendly_len);
    memcpy(aa->Description, LOOPBACK_DESC, desc_len);

    /* Next adapter pointer is NULL */
    aa->Next = NULL;

    *SizePointer = total_size;
    return NO_ERROR;
}

/* ---------- GetAdaptersInfo (older version, similar data) ---------- */
DWORD WINAPI GetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer)
{
    if (!SizePointer) return ERROR_INVALID_PARAMETER;

    /* We'll return one loopback entry – strings go directly into the structure */
    DWORD total_size = sizeof(IP_ADAPTER_INFO);

    if (*SizePointer < total_size) {
        *SizePointer = total_size;
        return ERROR_BUFFER_OVERFLOW;
    }

    memset(AdapterInfo, 0, total_size);
    PIP_ADAPTER_INFO ai = AdapterInfo;
    ai->Index = 1;
    ai->Type = MIB_IF_TYPE_LOOPBACK;
    ai->DhcpEnabled = 0;
    ai->AddressLength = 4;
    ai->IpAddressList.IpAddress.String[0] = 0;  /* no real IP */
    ai->IpAddressList.IpMask.String[0] = 0;
    ai->IpAddressList.Context = 0;
    ai->GatewayList.IpAddress.String[0] = 0;
    ai->DhcpServer.IpAddress.String[0] = 0;
    ai->HaveWins = FALSE;

    /* Copy strings into the fixed arrays */
    strncpy(ai->AdapterName, "\\DEVICE\\TCPIP_{LOOPBACK}", sizeof(ai->AdapterName) - 1);
    ai->AdapterName[sizeof(ai->AdapterName) - 1] = '\0';
    strncpy(ai->Description, "MS TCP Loopback interface", sizeof(ai->Description) - 1);
    ai->Description[sizeof(ai->Description) - 1] = '\0';

    ai->Next = NULL;

    *SizePointer = total_size;
    return ERROR_SUCCESS;
}

/* ---------- GetIfTable ---------- */
DWORD WINAPI GetIfTable(PMIB_IFTABLE pIfTable, PULONG pdwSize, BOOL bOrder)
{
    if (!pdwSize) return ERROR_INVALID_PARAMETER;

    DWORD needed = sizeof(MIB_IFTABLE) + sizeof(MIB_IFROW);  /* one entry */
    if (*pdwSize < needed) {
        *pdwSize = needed;
        return ERROR_INSUFFICIENT_BUFFER;
    }

    memset(pIfTable, 0, needed);
    pIfTable->dwNumEntries = 1;
    pIfTable->table[0].dwIndex = 1;
    wcscpy(pIfTable->table[0].wszName, L"Loopback");
    pIfTable->table[0].dwType = MIB_IF_TYPE_LOOPBACK;
    pIfTable->table[0].dwMtu = 1500;
    pIfTable->table[0].dwSpeed = 10000000;  /* 10 Mbps */
    pIfTable->table[0].dwPhysAddrLen = 0;
    pIfTable->table[0].dwOperStatus = MIB_IF_OPER_STATUS_OPERATIONAL;
    pIfTable->table[0].dwDescrLen = 0;  /* no description needed */

    *pdwSize = needed;
    return NO_ERROR;
}

/* ---------- GetIpAddrTable ---------- */
DWORD WINAPI GetIpAddrTable(PMIB_IPADDRTABLE pIpAddrTable, PULONG pdwSize, BOOL bOrder)
{
    if (!pdwSize) return ERROR_INVALID_PARAMETER;

    DWORD needed = sizeof(MIB_IPADDRTABLE) + sizeof(MIB_IPADDRROW);
    if (*pdwSize < needed) {
        *pdwSize = needed;
        return ERROR_INSUFFICIENT_BUFFER;
    }

    memset(pIpAddrTable, 0, needed);
    pIpAddrTable->dwNumEntries = 1;
    pIpAddrTable->table[0].dwAddr = inet_addr("127.0.0.1");
    pIpAddrTable->table[0].dwIndex = 1;
    pIpAddrTable->table[0].dwMask = inet_addr("255.0.0.0");
    pIpAddrTable->table[0].dwBCastAddr = 1;
    pIpAddrTable->table[0].dwReasmSize = 65535;

    *pdwSize = needed;
    return NO_ERROR;
}

/* ---------- GetIpNetTable (ARP) ---------- */
ULONG WINAPI GetIpNetTable(PMIB_IPNETTABLE IpNetTable, PULONG SizePointer, BOOL Order)
{
    if (!SizePointer) return ERROR_INVALID_PARAMETER;

    DWORD needed = sizeof(MIB_IPNETTABLE) + sizeof(MIB_IPNETROW);
    if (*SizePointer < needed) {
        *SizePointer = needed;
        return ERROR_INSUFFICIENT_BUFFER;
    }

    memset(IpNetTable, 0, needed);
    IpNetTable->dwNumEntries = 0;  /* empty ARP table */
    *SizePointer = needed;
    return NO_ERROR;
}

/* ---------- GetNetworkParams ---------- */
DWORD WINAPI GetNetworkParams(PFIXED_INFO pFixedInfo, PULONG pOutBufLen)
{
    if (!pOutBufLen) return ERROR_INVALID_PARAMETER;

    DWORD needed = sizeof(FIXED_INFO);
    if (*pOutBufLen < needed) {
        *pOutBufLen = needed;
        return ERROR_BUFFER_OVERFLOW;
    }

    memset(pFixedInfo, 0, needed);
    strcpy(pFixedInfo->HostName, "localhost");
    strcpy(pFixedInfo->DomainName, "");
    pFixedInfo->CurrentDnsServer = NULL;  /* no DNS */
    pFixedInfo->DnsServerList.IpAddress.String[0] = 0;
    pFixedInfo->NodeType = BROADCAST_NODETYPE;      /* correct constant */
    strcpy(pFixedInfo->ScopeId, "");
    pFixedInfo->EnableRouting = 0;
    pFixedInfo->EnableProxy = 0;
    pFixedInfo->EnableDns = 0;

    *pOutBufLen = needed;
    return NO_ERROR;
}

/* ---------- Generic stubs for everything else ---------- */
#define STUB_FUNC(ret, name, ...) \
    __declspec(dllexport) ret WINAPI name(__VA_ARGS__) { \
        SetLastError(ERROR_NOT_SUPPORTED); \
        return (ret)ERROR_NOT_SUPPORTED; \
    }

#define STUB_VOID(name, ...) \
    __declspec(dllexport) void WINAPI name(__VA_ARGS__) { }

/* Now generate all stubs (removed those with missing Vista+ types) */
STUB_FUNC(DWORD, AddIPAddress, IPAddr Address, IPMask IpMask, DWORD IfIndex, PULONG NTEContext, PULONG NTEInstance)
STUB_FUNC(DWORD, AllocateAndGetArpEntTableFromStack, PVOID *ppTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags, DWORD dwFamily)
STUB_FUNC(DWORD, AllocateAndGetIfTableFromStack, PMIB_IFTABLE *ppIfTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
STUB_FUNC(DWORD, AllocateAndGetIpAddrTableFromStack, PMIB_IPADDRTABLE *ppIpAddrTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
STUB_FUNC(DWORD, AllocateAndGetIpForwardTableFromStack, PMIB_IPFORWARDTABLE *ppIpForwardTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
STUB_FUNC(DWORD, AllocateAndGetIpNetTableFromStack, PMIB_IPNETTABLE *ppIpNetTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
STUB_FUNC(DWORD, AllocateAndGetTcpExTableFromStack, PVOID *ppTcpTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags, DWORD dwFamily)
STUB_FUNC(DWORD, AllocateAndGetTcpTableFromStack, PMIB_TCPTABLE *ppTcpTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
STUB_FUNC(DWORD, AllocateAndGetUdpTableFromStack, PMIB_UDPTABLE *ppUdpTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
STUB_FUNC(BOOL, CancelIPChangeNotify, LPOVERLAPPED notifyOverlapped)
STUB_FUNC(DWORD, CancelMibChangeNotify2, HANDLE hNotification)
STUB_FUNC(DWORD, ConvertGuidToStringA, const GUID *Guid, LPSTR String, DWORD Length)
STUB_FUNC(DWORD, ConvertGuidToStringW, const GUID *Guid, LPWSTR String, DWORD Length)
STUB_FUNC(DWORD, ConvertInterfaceAliasToLuid, const WCHAR *Alias, NET_LUID *Luid)
STUB_FUNC(DWORD, ConvertInterfaceGuidToLuid, const GUID *Guid, NET_LUID *Luid)
STUB_FUNC(DWORD, ConvertInterfaceIndexToLuid, NET_IFINDEX IfIndex, NET_LUID *Luid)
STUB_FUNC(DWORD, ConvertInterfaceLuidToAlias, const NET_LUID *Luid, PWSTR Alias, SIZE_T Length)
STUB_FUNC(DWORD, ConvertInterfaceLuidToGuid, const NET_LUID *Luid, GUID *Guid)
STUB_FUNC(DWORD, ConvertInterfaceLuidToIndex, const NET_LUID *Luid, NET_IFINDEX *IfIndex)
STUB_FUNC(DWORD, ConvertInterfaceLuidToNameA, const NET_LUID *Luid, LPSTR Name, SIZE_T Length)
STUB_FUNC(DWORD, ConvertInterfaceLuidToNameW, const NET_LUID *Luid, LPWSTR Name, SIZE_T Length)
STUB_FUNC(DWORD, ConvertInterfaceNameToLuidA, const CHAR *Name, NET_LUID *Luid)
STUB_FUNC(DWORD, ConvertInterfaceNameToLuidW, const WCHAR *Name, NET_LUID *Luid)
STUB_FUNC(DWORD, ConvertLengthToIpv4Mask, ULONG Length, ULONG *Mask)
STUB_FUNC(DWORD, ConvertStringToGuidW, const WCHAR *String, GUID *Guid)
STUB_FUNC(DWORD, CreateIpForwardEntry, PMIB_IPFORWARDROW pRoute)
STUB_FUNC(DWORD, CreateIpNetEntry, PMIB_IPNETROW pArpEntry)
STUB_FUNC(DWORD, CreateProxyArpEntry, DWORD dwAddress, DWORD dwMask, DWORD dwIfIndex)
STUB_FUNC(DWORD, CreateSortedAddressPairs, PSOCKADDR_IN6 SourceAddr, ULONG SourceCount, PSOCKADDR_IN6 DestAddr, ULONG DestCount, DWORD Options, PSOCKADDR_IN6_PAIR *Pairs, ULONG *PairCount)
STUB_FUNC(DWORD, DeleteIPAddress, ULONG NTEContext)
STUB_FUNC(DWORD, DeleteIpForwardEntry, PMIB_IPFORWARDROW pRoute)
STUB_FUNC(DWORD, DeleteIpNetEntry, PMIB_IPNETROW pArpEntry)
STUB_FUNC(DWORD, DeleteProxyArpEntry, DWORD dwAddress, DWORD dwMask, DWORD dwIfIndex)
STUB_FUNC(DWORD, EnableRouter, HANDLE *pHandle, OVERLAPPED *pOverlapped)
STUB_FUNC(DWORD, FlushIpNetTable, DWORD dwIfIndex)
STUB_FUNC(DWORD, FlushIpNetTableFromStack, DWORD dwIfIndex)
STUB_VOID(FreeMibTable, PVOID Memory)
STUB_FUNC(DWORD, GetAdapterIndex, LPWSTR AdapterName, PULONG IfIndex)
STUB_FUNC(PIP_ADAPTER_ORDER_MAP, GetAdapterOrderMap, VOID)
STUB_FUNC(DWORD, GetBestInterface, IPAddr dwDestAddr, PDWORD pdwBestIfIndex)
STUB_FUNC(DWORD, GetBestInterfaceEx, struct sockaddr *pDestAddr, PDWORD pdwBestIfIndex)
STUB_FUNC(DWORD, GetBestInterfaceFromStack, IPAddr dwDestAddr, PDWORD pdwBestIfIndex)
STUB_FUNC(DWORD, GetBestRoute, DWORD dwDestAddr, DWORD dwSourceAddr, PMIB_IPFORWARDROW pBestRoute)
STUB_FUNC(DWORD, GetBestRouteFromStack, IPAddr dwDestAddr, PMIB_IPFORWARDROW pBestRoute)
STUB_FUNC(DWORD, GetExtendedTcpTable, PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, TCP_TABLE_CLASS TableClass, ULONG Reserved)
STUB_FUNC(DWORD, GetExtendedUdpTable, PVOID pUdpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, UDP_TABLE_CLASS TableClass, ULONG Reserved)
STUB_FUNC(DWORD, GetFriendlyIfIndex, DWORD IfIndex)
STUB_FUNC(ULONG, GetIcmpStatisticsEx, PMIB_ICMP_EX Statistics, ULONG Family)
STUB_FUNC(ULONG, GetIcmpStatistics, PMIB_ICMP Statistics)
STUB_FUNC(DWORD, GetIcmpStatsFromStack, PMIB_ICMP_EX Statistics, ULONG Family)
STUB_FUNC(DWORD, GetIfEntry, PMIB_IFROW pIfRow)
STUB_FUNC(DWORD, GetIfEntryFromStack, PMIB_IFROW pIfRow)
STUB_FUNC(DWORD, GetIfTableFromStack, PMIB_IFTABLE *ppIfTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
STUB_FUNC(DWORD, GetInterfaceInfo, PIP_INTERFACE_INFO pIfTable, PULONG dwOutBufLen)
STUB_FUNC(DWORD, GetIpAddrTableFromStack, PMIB_IPADDRTABLE *ppIpAddrTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
STUB_FUNC(DWORD, GetIpForwardTable, PMIB_IPFORWARDTABLE pIpForwardTable, PULONG pdwSize, BOOL bOrder)
STUB_FUNC(DWORD, GetIpForwardTableFromStack, PMIB_IPFORWARDTABLE *ppIpForwardTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
STUB_FUNC(DWORD, GetIpNetTableFromStack, PMIB_IPNETTABLE *ppIpNetTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
STUB_FUNC(ULONG, GetIpStatisticsEx, PMIB_IPSTATS Statistics, ULONG Family)
STUB_FUNC(ULONG, GetIpStatistics, PMIB_IPSTATS Statistics)
STUB_FUNC(DWORD, GetIpStatsFromStack, PMIB_IPSTATS Statistics, ULONG Family)
STUB_FUNC(DWORD, GetNumberOfInterfaces, PDWORD pdwNumIf)
STUB_FUNC(DWORD, GetOwnerModuleFromTcp6Entry, PMIB_TCP6ROW_OWNER_MODULE pTcpEntry, TCPIP_OWNER_MODULE_INFO_CLASS Class, PVOID pBuffer, PDWORD pdwSize)
STUB_FUNC(DWORD, GetOwnerModuleFromTcpEntry, PMIB_TCPROW_OWNER_MODULE pTcpEntry, TCPIP_OWNER_MODULE_INFO_CLASS Class, PVOID pBuffer, PDWORD pdwSize)
STUB_FUNC(DWORD, GetPerAdapterInfo, ULONG IfIndex, PIP_PER_ADAPTER_INFO pPerAdapterInfo, PULONG pOutBufLen)
STUB_FUNC(ULONG, GetPerTcp6ConnectionEStats, PMIB_TCP6ROW Row, TCP_ESTATS_TYPE EstatsType, PUCHAR Rw, ULONG RwVersion, ULONG RwSize, PUCHAR Ros, ULONG RosVersion, ULONG RosSize, PUCHAR Rod, ULONG RodVersion, ULONG RodSize)
STUB_FUNC(ULONG, GetPerTcpConnectionEStats, PMIB_TCPROW Row, TCP_ESTATS_TYPE EstatsType, PUCHAR Rw, ULONG RwVersion, ULONG RwSize, PUCHAR Ros, ULONG RosVersion, ULONG RosSize, PUCHAR Rod, ULONG RodVersion, ULONG RodSize)
STUB_FUNC(BOOL, GetRTTAndHopCount, IPAddr DestIpAddress, PULONG HopCount, ULONG MaxHops, PULONG RTT)
STUB_FUNC(ULONG, GetTcp6Table, PMIB_TCP6TABLE TcpTable, PULONG SizePointer, BOOL Order)
STUB_FUNC(ULONG, GetTcp6Table2, PMIB_TCP6TABLE2 TcpTable, PULONG SizePointer, BOOL Order)
STUB_FUNC(ULONG, GetTcpStatisticsEx, PMIB_TCPSTATS Statistics, ULONG Family)
STUB_FUNC(ULONG, GetTcpStatistics, PMIB_TCPSTATS Statistics)
STUB_FUNC(DWORD, GetTcpStatsFromStack, PMIB_TCPSTATS Statistics, ULONG Family)
STUB_FUNC(ULONG, GetTcpTable, PMIB_TCPTABLE TcpTable, PULONG SizePointer, BOOL Order)
STUB_FUNC(ULONG, GetTcpTable2, PMIB_TCPTABLE2 TcpTable, PULONG SizePointer, BOOL Order)
STUB_FUNC(DWORD, GetTcpTableFromStack, PMIB_TCPTABLE *ppTcpTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
STUB_FUNC(ULONG, GetUdp6Table, PMIB_UDP6TABLE Udp6Table, PULONG SizePointer, BOOL Order)
STUB_FUNC(ULONG, GetUdpStatisticsEx, PMIB_UDPSTATS Statistics, ULONG Family)
STUB_FUNC(ULONG, GetUdpStatistics, PMIB_UDPSTATS Stats)
STUB_FUNC(DWORD, GetUdpStatsFromStack, PMIB_UDPSTATS Statistics, ULONG Family)
STUB_FUNC(ULONG, GetUdpTable, PMIB_UDPTABLE UdpTable, PULONG SizePointer, BOOL Order)
STUB_FUNC(DWORD, GetUdpTableFromStack, PMIB_UDPTABLE *ppUdpTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
STUB_FUNC(DWORD, GetUniDirectionalAdapterInfo, PIP_UNIDIRECTIONAL_ADAPTER_ADDRESS pIPIfInfo, PULONG dwOutBufLen)
STUB_FUNC(HANDLE, Icmp6CreateFile, VOID)
STUB_FUNC(DWORD, Icmp6ParseReplies, LPVOID ReplyBuffer, DWORD ReplySize)
STUB_FUNC(BOOL, IcmpCloseHandle, HANDLE IcmpHandle)
STUB_FUNC(HANDLE, IcmpCreateFile, VOID)
STUB_FUNC(DWORD, IcmpParseReplies, LPVOID ReplyBuffer, DWORD ReplySize)
STUB_FUNC(DWORD, IcmpSendEcho, HANDLE IcmpHandle, IPAddr DestinationAddress, LPVOID RequestData, WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout)
STUB_FUNC(PCHAR, if_indextoname, NET_IFINDEX InterfaceIndex, PCHAR InterfaceName)
STUB_FUNC(NET_IFINDEX, if_nametoindex, PCSTR InterfaceName)
STUB_FUNC(DWORD, InternalCreateIpForwardEntry, PMIB_IPFORWARDROW pRoute)
STUB_FUNC(DWORD, InternalCreateIpNetEntry, PMIB_IPNETROW pArpEntry)
STUB_FUNC(DWORD, InternalDeleteIpForwardEntry, PMIB_IPFORWARDROW pRoute)
STUB_FUNC(DWORD, InternalDeleteIpNetEntry, PMIB_IPNETROW pArpEntry)
STUB_FUNC(DWORD, InternalGetIfTable, PMIB_IFTABLE *ppIfTable, PULONG pdwSize, BOOL bOrder)
STUB_FUNC(DWORD, InternalGetIpAddrTable, PMIB_IPADDRTABLE *ppIpAddrTable, PULONG pdwSize, BOOL bOrder)
STUB_FUNC(DWORD, InternalGetIpForwardTable, PMIB_IPFORWARDTABLE *ppIpForwardTable, PULONG pdwSize, BOOL bOrder)
STUB_FUNC(DWORD, InternalGetIpNetTable, PMIB_IPNETTABLE *ppIpNetTable, PULONG pdwSize, BOOL bOrder)
STUB_FUNC(DWORD, InternalGetTcpTable, PMIB_TCPTABLE *ppTcpTable, PULONG pdwSize, BOOL bOrder)
STUB_FUNC(DWORD, InternalGetUdpTable, PMIB_UDPTABLE *ppUdpTable, PULONG pdwSize, BOOL bOrder)
STUB_FUNC(DWORD, InternalSetIfEntry, PMIB_IFROW pIfRow)
STUB_FUNC(DWORD, InternalSetIpForwardEntry, PMIB_IFROW pRoute)
STUB_FUNC(DWORD, InternalSetIpNetEntry, PMIB_IPNETROW pArpEntry)
STUB_FUNC(DWORD, InternalSetIpStats, PMIB_IPSTATS pIpStats)
STUB_FUNC(DWORD, InternalSetTcpEntry, PMIB_TCPROW pTcpRow)
STUB_FUNC(DWORD, IpReleaseAddress, PIP_ADAPTER_INDEX_MAP AdapterInfo)
STUB_FUNC(DWORD, IpRenewAddress, PIP_ADAPTER_INDEX_MAP AdapterInfo)
STUB_FUNC(BOOL, IsLocalAddress, IPAddr Address)
STUB_FUNC(DWORD, NhGetGuidFromInterfaceName, const WCHAR *Name, GUID *Guid)
STUB_FUNC(DWORD, NhGetInterfaceNameFromGuid, const GUID *Guid, PWSTR Name, SIZE_T Length)
STUB_FUNC(DWORD, NhpAllocateAndGetInterfaceInfoFromStack, IP_INTERFACE_NAME_INFO **ppTable, PDWORD pdwCount, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
STUB_FUNC(DWORD, NhpGetInterfaceIndexFromStack, const WCHAR *Name, PULONG IfIndex)
STUB_FUNC(DWORD, NotifyAddrChange, PHANDLE Handle, LPOVERLAPPED overlapped)
STUB_FUNC(DWORD, NotifyRouteChange, PHANDLE Handle, LPOVERLAPPED overlapped)
STUB_FUNC(DWORD, SendARP, IPAddr DestIP, IPAddr SrcIP, PVOID pMacAddr, PULONG PhyAddrLen)
STUB_FUNC(DWORD, SetAdapterIpAddress, const WCHAR *AdapterName, IPAddr Address, IPMask Mask)
STUB_FUNC(DWORD, SetBlockRoutes, BOOL bBlock)
STUB_FUNC(DWORD, SetIfEntry, PMIB_IFROW pIfRow)
STUB_FUNC(DWORD, SetIfEntryToStack, PMIB_IFROW pIfRow)
STUB_FUNC(DWORD, SetIpForwardEntry, PMIB_IPFORWARDROW pRoute)
STUB_FUNC(DWORD, SetIpForwardEntryToStack, PMIB_IPFORWARDROW pRoute)
STUB_FUNC(DWORD, SetIpMultihopRouteEntryToStack, PMIB_IPFORWARDROW pRoute)
STUB_FUNC(DWORD, SetIpNetEntry, PMIB_IPNETROW pArpEntry)
STUB_FUNC(DWORD, SetIpNetEntryToStack, PMIB_IPNETROW pArpEntry)
STUB_FUNC(DWORD, SetIpRouteEntryToStack, PMIB_IPFORWARDROW pRoute)
STUB_FUNC(DWORD, SetIpStatistics, PMIB_IPSTATS pIpStats)
STUB_FUNC(DWORD, SetIpStatsToStack, PMIB_IPSTATS Statistics, ULONG Family)
STUB_FUNC(DWORD, SetIpTTL, UINT nTTL)
STUB_FUNC(ULONG, SetPerTcp6ConnectionEStats, PMIB_TCP6ROW Row, TCP_ESTATS_TYPE EstatsType, PUCHAR Rw, ULONG RwVersion, ULONG RwSize, ULONG Offset)
STUB_FUNC(ULONG, SetPerTcpConnectionEStats, PMIB_TCPROW Row, TCP_ESTATS_TYPE EstatsType, PUCHAR Rw, ULONG RwVersion, ULONG RwSize, ULONG Offset)
STUB_FUNC(DWORD, SetProxyArpEntryToStack, PMIB_IPNETROW pArpEntry)
STUB_FUNC(DWORD, SetRouteWithRef, PMIB_IPFORWARDROW pRoute, BOOL bAdd)
STUB_FUNC(DWORD, SetTcpEntry, PMIB_TCPROW pTcpRow)
STUB_FUNC(DWORD, SetTcpEntryToStack, PMIB_TCPROW pTcpRow)
STUB_FUNC(DWORD, UnenableRouter, OVERLAPPED *pOverlapped, LPDWORD lpdwEnableCount)


static void InjectHooks(void)
{
    InitLog();
    LogMsg("Hello iphlpapi_proxy");
}

/* ---------- DllMain ---------- */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    // InjectHooks();
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpvReserved;
    return TRUE;
}