/*
 * adapter_info.c – list every network connection with all properties.
 * Now includes GetAdaptersAddresses (IP Helper) in addition to COM/WMI.
 *
 * Compile (MinGW):
 *   gcc -o adapter_info.exe adapter_info.c -lole32 -loleaut32 -liphlpapi -lws2_32
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <ole2.h>
#include <oleauto.h>
#include <initguid.h>

/* ------------------------------------------------------------------
 * GUIDs we need
 * ------------------------------------------------------------------ */
DEFINE_GUID(CLSID_NetSharingManager,
    0x5C63C1AD,0x3956,0x4FF8,0x84,0x86,0x40,0x03,0x47,0x58,0x31,0x5B);
DEFINE_GUID(IID_INetSharingManager,
    0xC08956B7,0x1CD3,0x11D1,0xB1,0xC5,0x00,0x80,0x5F,0xC1,0x27,0x0E);

/* IID_IEnumVARIANT is from oaidl.idl */
DEFINE_GUID(IID_IEnumVARIANT,
    0x00020404,0x0000,0x0000,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46);

/* INetConnection (standard, from netcon.h) */
DEFINE_GUID(IID_INetConnection,
    0xC08956A1,0x1CD3,0x11D1,0xB1,0xC5,0x00,0x80,0x5F,0xC1,0x27,0x0E);

/* INetConnection (HNetCfg type library – fallback) */
static const GUID IID_INetConnection_HNetCfg =
    {0xC08956A1,0x1CD3,0x11D1,{0xB1,0xC5,0x00,0x80,0x5F,0xC1,0x27,0x0E}};

    /* WMI GUIDs */
DEFINE_GUID(CLSID_WbemLocator,
    0x4590F811,0x1D3A,0x11D0,0x89,0x1F,0x00,0xAA,0x00,0x4B,0x2E,0x24);
DEFINE_GUID(IID_IWbemLocator,
    0xDC12A687,0x737F,0x11CF,0x88,0x4D,0x00,0xAA,0x00,0x4B,0x2E,0x24);
DEFINE_GUID(IID_IWbemServices,
    0x9556DC99,0x828C,0x11CF,0x8F,0x2E,0x00,0xAA,0x00,0x4B,0x2E,0x24);
DEFINE_GUID(IID_IEnumWbemClassObject,
    0x027947E1,0xD731,0x11CE,0x80,0x57,0x00,0xAA,0x00,0x4B,0x2E,0x24);

/* Locator methods (index 3 = ConnectServer) */
#define IWbemLocator_ConnectServer(p, strResource, strUser, strPassword, strLocale, \
                                  lSecurityFlags, strAuthority, pCtx, ppNS) \
    ((HRESULT (__stdcall *)(void*, const BSTR,const BSTR,const BSTR,const BSTR, \
                            LONG,const BSTR,IUnknown*,void**)) get_vtbl(p)[3]) \
        ((p),(strResource),(strUser),(strPassword),(strLocale), \
         (lSecurityFlags),(strAuthority),(pCtx),(ppNS))

/* Services methods */
#define IWbemServices_ExecQuery(p, strQL, strQry, lFlags, pCtx, ppEnum) \
    ((HRESULT (__stdcall *)(void*, const BSTR,const BSTR, LONG, IUnknown*, void**)) get_vtbl(p)[20]) \
        ((p),(strQL),(strQry),(lFlags),(pCtx),(ppEnum))

/* IEnumWbemClassObject methods */
#define IEnumWbemClassObject_Next(p, lTimeout, uCount, apObjects, puReturned) \
    ((HRESULT (__stdcall *)(void*, LONG, ULONG, void**, ULONG*)) get_vtbl(p)[4]) \
        ((p),(lTimeout),(uCount),(apObjects),(puReturned))

/* IWbemClassObject methods */
/* IWbemClassObject::Get (pass NULL for pType since we don't need it) */
#define IWbemClassObject_Get(p, wszName, lFlags, pVal, pType, plFlavor) \
    ((HRESULT (__stdcall *)(void*, LPCWSTR, LONG, VARIANT*, LONG*, LONG*)) get_vtbl(p)[4]) \
        ((p),(wszName),(lFlags),(pVal),NULL,(plFlavor))
/* ------------------------------------------------------------------
 * Structure NETCON_PROPERTIES (taken from netcon.h, using DWORD
 * for the enum types to guarantee portable layout)
 * ------------------------------------------------------------------ */
typedef struct tagNETCON_PROPERTIES {
    GUID   guidId;
    LPWSTR pszwName;
    LPWSTR pszwDeviceName;
    DWORD  Status;       /* NETCON_STATUS */
    DWORD  MediaType;    /* NETCON_MEDIATYPE */
    DWORD  dwCharacter;  /* NETCON_CHARACTERISTIC_FLAGS */
    CLSID  clsidThisObject;
    CLSID  clsidUiObject;
} NETCON_PROPERTIES;

/* ------------------------------------------------------------------
 * Vtable helpers – call any method by index
 * ------------------------------------------------------------------ */
static inline void** get_vtbl(void *p) { return *(void***)p; }

/* IUnknown */
#define IUnknown_QueryInterface(p, riid, ppv) \
    ((HRESULT (__stdcall *)(void*, REFIID, void**)) get_vtbl(p)[0])((p), (riid), (ppv))
#define IUnknown_Release(p) \
    ((ULONG (__stdcall *)(void*)) get_vtbl(p)[2])((p))

/* IEnumVARIANT */
#define IEnumVARIANT_Next(p, celt, rgVar, pcFetched) \
    ((HRESULT (__stdcall *)(void*,ULONG,VARIANT*,ULONG*)) get_vtbl(p)[3])((p),(celt),(rgVar),(pcFetched))

/* INetSharingManager – vtable index 11 = get_EnumEveryConnection */
#define INetSharingManager_GetEnumEveryConnection(p, ppColl) \
    ((HRESULT (__stdcall *)(void*, void**)) get_vtbl(p)[11])((p),(ppColl))

/* INetSharingEveryConnectionCollection – vtable index 7 = get__NewEnum */
#define INetSharingEveryConnectionCollection_GetNewEnum(p, ppEnum) \
    ((HRESULT (__stdcall *)(void*, IUnknown**)) get_vtbl(p)[7])((p),(ppEnum))

/* INetConnection – vtable index 7 = GetProperties */
#define INetConnection_GetProperties(p, ppProps) \
    ((HRESULT (__stdcall *)(void*, NETCON_PROPERTIES**)) get_vtbl(p)[7])((p),(ppProps))

    /* Network List Manager GUIDs */
DEFINE_GUID(CLSID_NetworkListManager,
    0xDCB00C01,0x570F,0x4A9B,0x8D,0x69,0x19,0x9F,0xDB,0xA5,0x72,0x3B);
DEFINE_GUID(IID_INetworkListManager,
    0xDCB00000,0x570F,0x4A9B,0x8D,0x69,0x19,0x9F,0xDB,0xA5,0x72,0x3B);
DEFINE_GUID(IID_IEnumNetworkConnections,
    0xDCB00003,0x570F,0x4A9B,0x8D,0x69,0x19,0x9F,0xDB,0xA5,0x72,0x3B);

/* INetworkListManager methods */
#define INetworkListManager_GetNetworkConnections(p, ppEnum) \
    ((HRESULT (__stdcall *)(void*,void**)) get_vtbl(p)[11])((p),(ppEnum))

/* IEnumNetworkConnections methods */
#define IEnumNetworkConnections_Next(p, celt, rgConn, pcFetched) \
    ((HRESULT (__stdcall *)(void*,ULONG,void**,ULONG*)) get_vtbl(p)[3])((p),(celt),(rgConn),(pcFetched))

/* INetworkConnection::GetConnectionId (vtable index 11, offset 0x2C) */
#define INetworkConnection_GetConnectionId(p, ppGuid) \
    ((HRESULT (__stdcall *)(void*, GUID*)) get_vtbl(p)[11])((p), (ppGuid))
/* ------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------ */
static void PrintGuid(const GUID *guid, const char *label)
{
    wchar_t str[40];
    StringFromGUID2(guid, str, 40);
    printf("%s: %ls\n", label, str);
}

/* Convert a SOCKET_ADDRESS to a human readable string */
static void PrintSocketAddress(SOCKET_ADDRESS *addr)
{
    if (!addr || !addr->lpSockaddr)
    {
        printf("(null)");
        return;
    }

    if (addr->lpSockaddr->sa_family == AF_INET)
    {
        struct sockaddr_in *sa = (struct sockaddr_in *)addr->lpSockaddr;
        char ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip)))
            printf("%s", ip);
        else
            printf("(invalid IPv4)");
    }
    else if (addr->lpSockaddr->sa_family == AF_INET6)
    {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)addr->lpSockaddr;
        char ip[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &sa6->sin6_addr, ip, sizeof(ip)))
            printf("%s", ip);
        else
            printf("(invalid IPv6)");
    }
    else
    {
        printf("(family %d)", addr->lpSockaddr->sa_family);
    }
}

/* ------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------ */
int main(void)
{
    /* COM initialisation – if it fails we simply skip COM‑based methods */
    HRESULT hrCOM = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    BOOL comOk = SUCCEEDED(hrCOM);
    if (!comOk)
        printf("CoInitializeEx failed: 0x%08lX – COM methods will be skipped.\n", hrCOM);

    /* ========== 1. NetSharingManager ========== */
    if (comOk)
    {
        HRESULT hr;
        void *pNSM = NULL;
        hr = CoCreateInstance(&CLSID_NetSharingManager, NULL, CLSCTX_ALL,
                              &IID_INetSharingManager, &pNSM);
        if (SUCCEEDED(hr))
        {
            void *pColl = NULL;
            hr = INetSharingManager_GetEnumEveryConnection(pNSM, &pColl);
            IUnknown_Release(pNSM);
            if (SUCCEEDED(hr))
            {
                IUnknown *pEnumUnk = NULL;
                hr = INetSharingEveryConnectionCollection_GetNewEnum(pColl, &pEnumUnk);
                IUnknown_Release(pColl);
                if (SUCCEEDED(hr))
                {
                    IEnumVARIANT *pEnum = NULL;
                    hr = IUnknown_QueryInterface(pEnumUnk, &IID_IEnumVARIANT, (void**)&pEnum);
                    IUnknown_Release(pEnumUnk);
                    if (SUCCEEDED(hr))
                    {
                        ULONG nCount = 0;
                        VARIANT var;
                        VariantInit(&var);
                        while (IEnumVARIANT_Next(pEnum, 1, &var, NULL) == S_OK)
                        {
                            if (V_VT(&var) == VT_UNKNOWN)
                            {
                                IUnknown *pConnUnk = V_UNKNOWN(&var);
                                void *pConn = NULL;
                                hr = IUnknown_QueryInterface(pConnUnk, &IID_INetConnection, &pConn);
                                if (FAILED(hr))
                                    hr = IUnknown_QueryInterface(pConnUnk, &IID_INetConnection_HNetCfg, &pConn);
                                if (SUCCEEDED(hr) && pConn)
                                {
                                    nCount++;
                                    printf("\n===== Connection #%lu (NetSharingManager) =====\n", nCount);
                                    NETCON_PROPERTIES *pProps = NULL;
                                    hr = INetConnection_GetProperties(pConn, &pProps);
                                    if (SUCCEEDED(hr) && pProps)
                                    {
                                        PrintGuid(&pProps->guidId, "Adapter GUID");
                                        printf("Name         : %ls\n", pProps->pszwName ? pProps->pszwName : L"(null)");
                                        printf("Device Name  : %ls\n", pProps->pszwDeviceName ? pProps->pszwDeviceName : L"(null)");
                                        printf("Status       : %u (0x%X)\n", (unsigned)pProps->Status, (unsigned)pProps->Status);
                                        printf("MediaType    : %u (0x%X)\n", (unsigned)pProps->MediaType, (unsigned)pProps->MediaType);
                                        printf("Characteristics: 0x%X\n", (unsigned)pProps->dwCharacter);
                                        PrintGuid(&pProps->clsidThisObject, "CLSID This Obj");
                                        PrintGuid(&pProps->clsidUiObject, "CLSID UI Obj");
                                        CoTaskMemFree(pProps);
                                    }
                                    else
                                        printf("GetProperties failed: 0x%08lX\n", hr);
                                    IUnknown_Release(pConn);
                                }
                                else
                                {
                                    nCount++;
                                    printf("\n===== Connection #%lu (NetSharingManager) =====\n", nCount);
                                    printf("  (skipped: QI for INetConnection failed: 0x%08lX)\n", hr);
                                }
                            }
                            VariantClear(&var);
                            VariantInit(&var);
                        }
                        IUnknown_Release(pEnum);
                        if (nCount == 0)
                            printf("No connections returned by NetSharingManager.\n");
                    }
                    else
                        printf("QueryInterface(IEnumVARIANT) failed: 0x%08lX\n", hr);
                }
                else
                    printf("get__NewEnum failed: 0x%08lX\n", hr);
            }
            else
                printf("get_EnumEveryConnection failed: 0x%08lX\n", hr);
        }
        else
            printf("CoCreateInstance(NetSharingManager) failed: 0x%08lX\n", hr);
    }

    /* ========== 2. NetworkListManager (like Radmin checks) ========== */
    // if (comOk)
    // {
    //     HRESULT hr;
    //     void *pNLM = NULL;
    //     hr = CoCreateInstance(&CLSID_NetworkListManager, NULL, CLSCTX_ALL,
    //                           &IID_INetworkListManager, &pNLM);
    //     if (SUCCEEDED(hr))
    //     {
    //         void *pEnumNets = NULL;
    //         hr = INetworkListManager_GetNetworkConnections(pNLM, &pEnumNets);
    //         IUnknown_Release(pNLM);
    //         if (SUCCEEDED(hr))
    //         {
    //             void *pConn = NULL;
    //             ULONG fetched = 0;
    //             ULONG idx = 0;
    //             printf("\n=== Connections via INetworkListManager ===\n");
    //             while (IEnumNetworkConnections_Next(pEnumNets, 1, &pConn, &fetched) == S_OK)
    //             {
    //                 if (pConn)
    //                 {
    //                     idx++;
    //                     GUID guid;
    //                     hr = INetworkConnection_GetConnectionId(pConn, &guid);
    //                     if (SUCCEEDED(hr))
    //                     {
    //                         wchar_t guidStr[40];
    //                         StringFromGUID2(&guid, guidStr, 40);
    //                         printf("[%2lu] ConnectionId: %ls\n", idx, guidStr);
    //                         printf("     First 12 bytes: ");
    //                         BYTE *b = (BYTE*)&guid;
    //                         for (int i = 0; i < 12; i++)
    //                             printf("%02X ", b[i]);
    //                         printf("\n\n");
    //                     }
    //                     else
    //                         printf("[%2lu] GetConnectionId failed: 0x%08lX\n", idx, hr);
    //                     IUnknown_Release(pConn);
    //                 }
    //             }
    //             IUnknown_Release(pEnumNets);
    //         }
    //         else
    //             printf("GetNetworkConnections failed: 0x%08lX\n", hr);
    //     }
    //     else
    //         printf("CoCreateInstance(NetworkListManager) failed: 0x%08lX – maybe service not running?\n", hr);
    // }

    /* ========== 3. WMI (Win32_NetworkAdapter) ========== */
    if (comOk)
    {
        HRESULT hr;
        void *pLocator = NULL;
        hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_ALL,
                              &IID_IWbemLocator, &pLocator);
        if (SUCCEEDED(hr))
        {
            void *pSvc = NULL;
            BSTR bstrNamespace = SysAllocString(L"ROOT\\CIMV2");
            hr = IWbemLocator_ConnectServer(pLocator, bstrNamespace,
                                            NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
            SysFreeString(bstrNamespace);
            IUnknown_Release(pLocator);

            if (SUCCEEDED(hr) && pSvc)
            {
                BSTR bstrWQL = SysAllocString(L"WQL");
                BSTR bstrQuery = SysAllocString(L"SELECT * FROM Win32_NetworkAdapter");
                void *pEnum = NULL;

                hr = IWbemServices_ExecQuery(pSvc, bstrWQL, bstrQuery,
                                             0x30,   // WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY
                                             NULL, &pEnum);
                SysFreeString(bstrWQL);
                SysFreeString(bstrQuery);

                if (SUCCEEDED(hr) && pEnum)
                {
                    void *apObjects[10];
                    ULONG uReturned = 0;
                    ULONG idx = 0;
                    printf("\n=== Adapters via WMI (Win32_NetworkAdapter) ===\n");

                    while (IEnumWbemClassObject_Next(pEnum, 10000, 1, apObjects, &uReturned) == S_OK)
                    {
                        if (uReturned == 1 && apObjects[0])
                        {
                            idx++;
                            VARIANT v;
                            VariantInit(&v);

                            hr = IWbemClassObject_Get(apObjects[0], L"SettingID", 0, &v, NULL, NULL);
                            if (SUCCEEDED(hr) && V_VT(&v) == VT_BSTR)
                            {
                                VARIANT vName;
                                VariantInit(&vName);
                                HRESULT hrName = IWbemClassObject_Get(apObjects[0], L"Name", 0, &vName, NULL, NULL);
                                printf("[%2lu] Name: %ls\n", idx,
                                       (SUCCEEDED(hrName) && V_VT(&vName) == VT_BSTR) ? vName.bstrVal : L"(unknown)");
                                printf("     SettingID: %ls\n\n", V_BSTR(&v));
                                VariantClear(&vName);
                            }
                            else
                                printf("[%2lu] SettingID retrieval failed: 0x%08lX\n", idx, hr);
                            VariantClear(&v);
                            IUnknown_Release(apObjects[0]);
                        }
                    }
                    IUnknown_Release(pEnum);
                }
                else
                    printf("WMI ExecQuery failed: 0x%08lX\n", hr);
                IUnknown_Release(pSvc);
            }
            else
                printf("IWbemLocator::ConnectServer failed: 0x%08lX\n", hr);
        }
        else
            printf("CoCreateInstance(WbemLocator) failed: 0x%08lX\n", hr);
    }

    /* ========== 4. GetAdaptersAddresses (IP Helper) – always runs ========== */
    {
        ULONG family = AF_UNSPEC;
        ULONG flags = GAA_FLAG_INCLUDE_PREFIX |
                      GAA_FLAG_INCLUDE_WINS_INFO |
                      GAA_FLAG_INCLUDE_GATEWAYS;
        ULONG size = 15000;
        PIP_ADAPTER_ADDRESSES pAdapterAddresses = NULL;
        DWORD ret = 0;

        for (int attempt = 0; attempt < 3; ++attempt)
        {
            pAdapterAddresses = (PIP_ADAPTER_ADDRESSES)malloc(size);
            if (!pAdapterAddresses)
            {
                printf("GetAdaptersAddresses: allocation failed\n");
                break;
            }
            ret = GetAdaptersAddresses(family, flags, NULL, pAdapterAddresses, &size);
            if (ret == ERROR_BUFFER_OVERFLOW)
            {
                free(pAdapterAddresses);
                pAdapterAddresses = NULL;
                continue;
            }
            break;
        }

        if (ret == NO_ERROR && pAdapterAddresses)
        {
            ULONG idx = 0;
            PIP_ADAPTER_ADDRESSES pCurr = pAdapterAddresses;
            printf("\n=== Adapters via GetAdaptersAddresses ===\n");

            while (pCurr)
            {
                ++idx;
                printf("\n--- Adapter #%lu ---\n", idx);

                /* Basic identification */
                printf("AdapterName : %s\n", pCurr->AdapterName ? pCurr->AdapterName : "(null)");
                printf("Description : %ls\n", pCurr->Description ? pCurr->Description : L"(null)");
                printf("FriendlyName: %ls\n", pCurr->FriendlyName ? pCurr->FriendlyName : L"(null)");

                /* Physical address */
                printf("PhysicalAddress: ");
                for (ULONG i = 0; i < pCurr->PhysicalAddressLength; ++i)
                    printf("%02X ", pCurr->PhysicalAddress[i]);
                printf("\n");

                /* General properties */
                printf("Mtu         : %u\n", pCurr->Mtu);
                printf("IfType      : %u\n", pCurr->IfType);
                printf("OperStatus  : %u\n", pCurr->OperStatus);
                printf("IfIndex     : %u\n", pCurr->IfIndex);
                printf("Ipv6IfIndex : %u\n", pCurr->Ipv6IfIndex);
                printf("Ipv4Metric  : %u, Ipv6Metric : %u\n", pCurr->Ipv4Metric, pCurr->Ipv6Metric);
                printf("Flags       : 0x%X\n", pCurr->Flags);
                printf("Luid        : 0x%I64X\n", pCurr->Luid.Value);

                /* Network GUID */
                wchar_t guidStr[40];
                StringFromGUID2(&pCurr->NetworkGuid, guidStr, 40);
                printf("NetworkGuid : %ls\n", guidStr);
                printf("CompartmentId: %u\n", pCurr->CompartmentId);
                printf("ConnectionType: %d, TunnelType: %d\n",
                       pCurr->ConnectionType, pCurr->TunnelType);

                /* DHCP servers */
                printf("Dhcpv4Server: ");
                PrintSocketAddress(&pCurr->Dhcpv4Server);
                printf("\nDhcpv6Server: ");
                PrintSocketAddress(&pCurr->Dhcpv6Server);
                printf("\n");

                /* Unicast addresses */
                PIP_ADAPTER_UNICAST_ADDRESS pUni = pCurr->FirstUnicastAddress;
                if (pUni) printf("  Unicast addresses:\n");
                while (pUni)
                {
                    printf("    ");
                    PrintSocketAddress(&pUni->Address);
                    printf("\n");
                    pUni = pUni->Next;
                }

                /* Anycast addresses */
                PIP_ADAPTER_ANYCAST_ADDRESS pAny = pCurr->FirstAnycastAddress;
                if (pAny) printf("  Anycast addresses:\n");
                while (pAny)
                {
                    printf("    ");
                    PrintSocketAddress(&pAny->Address);
                    printf("\n");
                    pAny = pAny->Next;
                }

                /* Multicast addresses */
                PIP_ADAPTER_MULTICAST_ADDRESS pMulti = pCurr->FirstMulticastAddress;
                if (pMulti) printf("  Multicast addresses:\n");
                while (pMulti)
                {
                    printf("    ");
                    PrintSocketAddress(&pMulti->Address);
                    printf("\n");
                    pMulti = pMulti->Next;
                }

                /* DNS servers */
                PIP_ADAPTER_DNS_SERVER_ADDRESS pDns = pCurr->FirstDnsServerAddress;
                if (pDns) printf("  DNS servers:\n");
                while (pDns)
                {
                    printf("    ");
                    PrintSocketAddress(&pDns->Address);
                    printf("\n");
                    pDns = pDns->Next;
                }

                /* Gateways */
                PIP_ADAPTER_GATEWAY_ADDRESS pGw = pCurr->FirstGatewayAddress;
                if (pGw) printf("  Gateways:\n");
                while (pGw)
                {
                    printf("    ");
                    PrintSocketAddress(&pGw->Address);
                    printf("\n");
                    pGw = pGw->Next;
                }

                /* WINS servers */
                PIP_ADAPTER_WINS_SERVER_ADDRESS pWins = pCurr->FirstWinsServerAddress;
                if (pWins) printf("  WINS servers:\n");
                while (pWins)
                {
                    printf("    ");
                    PrintSocketAddress(&pWins->Address);
                    printf("\n");
                    pWins = pWins->Next;
                }

                /* Prefixes */
                PIP_ADAPTER_PREFIX pPref = pCurr->FirstPrefix;
                if (pPref) printf("  Prefixes:\n");
                while (pPref)
                {
                    printf("    ");
                    PrintSocketAddress(&pPref->Address);
                    printf(" /%u\n", pPref->PrefixLength);
                    pPref = pPref->Next;
                }

                /* DNS suffixes (Vista SP1+) */
#if (NTDDI_VERSION >= 0x06000100)
                PIP_ADAPTER_DNS_SUFFIX pSuffix = pCurr->FirstDnsSuffix;
                if (pSuffix) printf("  DNS suffixes:\n");
                while (pSuffix)
                {
                    printf("    %ls\n", pSuffix->String);
                    pSuffix = pSuffix->Next;
                }
#endif

                pCurr = pCurr->Next;
            }
            free(pAdapterAddresses);
        }
        else
        {
            printf("GetAdaptersAddresses failed: %lu\n", ret);
            if (pAdapterAddresses)
                free(pAdapterAddresses);
        }
    }

    if (comOk)
        CoUninitialize();

    return 0;
}