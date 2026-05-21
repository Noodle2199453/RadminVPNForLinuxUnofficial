/*
 * emulate_driver_running.c – Fake Radmin VPN driver presence
 *
 * Hooks advapi32, setupapi, ole32, and COM vtable methods to make the
 * target application believe the driver is installed, running, and bound.
 */

#include <minwindef.h>
#include <winsock2.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <winsvc.h>
#include <setupapi.h>
#include <ole2.h>
#include <wbemcli.h>          // IWbemLocator, IWbemServices, IWbemClassObject, etc.
#include <netcfgx.h>          // INetCfg, IEnumNetCfgComponent, INetCfgComponent, etc.
#include <devguid.h>
#include <netcon.h>   // for INetConnection
#include <netlistmgr.h> // for INetworkListManager
#include <iphlpapi.h>   // for GetAdaptersInfo, GetAdaptersAddresses, IP_ADAPTER_INFO, etc.
#include <iptypes.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include "tap_client.h"
// #define REGISTER_HOOKS_REAL 1
#ifdef REGISTER_HOOKS_REAL
#include "register_proxy.c"
#else
#include "register.c"
#endif


/* _ReturnAddress() replacement for MSVC / GCC / Clang */
#if defined(_MSC_VER)
  #include <intrin.h>
  #define GET_RETURN_ADDRESS() _ReturnAddress()
#elif defined(__GNUC__) || defined(__clang__)
  #define GET_RETURN_ADDRESS() __builtin_return_address(0)
#else
  #error "Unsupported compiler – please provide a return‑address intrinsic"
#endif

DEFINE_GUID(CLSID_NetSharingManager, 0x5C63C1AD,0x3956,0x4FF8,0x84,0x86,0x40,0x03,0x47,0x58,0x31,0x5B);
DEFINE_GUID(IID_INetSharingManager, 0x9475C538,0xC2CA,0x11d2,0x9F,0xB5,0x00,0xC0,0x4F,0xC3,0x27,0x17);
DEFINE_GUID(IID_INetSharingConfiguration, 0x9475C53A,0xC2CA,0x11d2,0x9F,0xB5,0x00,0xC0,0x4F,0xC3,0x27,0x17);

static INetConnection* CreateFakeNetConnection(void);
#define BLOCK_REAL 1   // set to 0 to use real COM objects, 1 for pure fake
#define PROXY 0

// External functions provided by inject.c
extern void LogMsg(const char *fmt, ...);
extern void LogHex(const BYTE *data, DWORD len, const char *prefix);
extern void* GetIATEntry(HMODULE module, const char *dllName, const char *funcName);
extern BOOL PatchIAT(void *iatEntry, void *hookFunc);

// Forward declarations for helper functions
static BSTR ExtractDeviceIDFromPath(const BSTR path);
static BSTR ExtractGuidFromQuery(const BSTR strQuery);
static IWbemClassObject* CreateFakeNetAdapterObject(BSTR guid);

typedef struct {
    void *lpVtbl;
    LONG refCount;
    INetConnection *fakeConnection;
    BOOL alreadyReturned;
} FakeVarEnumerator;

// ----- IDispatch wrapper for the enumerator -----
typedef struct {
    void *lpVtbl;               // IDispatch vtable
    LONG refCount;
    INetConnection *connection; // the fake connection to return
} VarEnumIDispatch;

static void* g_VarEnumIDispatchVtable[7] = {0};
// Forward declarations for proxy wrappers
static IEnumWbemClassObject* CreateProxyEnumWbem(IEnumWbemClassObject *realEnum);
static IWbemClassObject* CreateProxyWbemClassObject(IWbemClassObject *realObj);
static HRESULT STDMETHODCALLTYPE VarEnumIDispatch_QueryInterface(IDispatch *pThis, REFIID riid, void **ppvObj) {
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IDispatch)) {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    *ppvObj = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE VarEnumIDispatch_AddRef(IDispatch *pThis) {
    return InterlockedIncrement(&((VarEnumIDispatch*)pThis)->refCount);
}
static ULONG STDMETHODCALLTYPE VarEnumIDispatch_Release(IDispatch *pThis) {
    VarEnumIDispatch *w = (VarEnumIDispatch*)pThis;
    LONG ref = InterlockedDecrement(&w->refCount);
    if (ref == 0) {
        if (w->connection)
            w->connection->lpVtbl->Release(w->connection);
        HeapFree(GetProcessHeap(), 0, w);
    }
    return ref;
}
static HRESULT STDMETHODCALLTYPE VarEnumIDispatch_GetTypeInfoCount(IDispatch *pThis, UINT *pctinfo) { return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE VarEnumIDispatch_GetTypeInfo(IDispatch *pThis, UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo) { return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE VarEnumIDispatch_GetIDsOfNames(IDispatch *pThis, REFIID riid, OLECHAR **rgszNames, UINT cNames, LCID lcid, DISPID *rgDispId) { return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE VarEnumIDispatch_Invoke(IDispatch *pThis, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr) {
    LogMsg("VarEnum::IDispatch::Invoke called: dispId=%ld", dispIdMember);
    VarEnumIDispatch *w = (VarEnumIDispatch*)pThis;
    if (dispIdMember == 0) {  // DISPID_VALUE
        if (pVarResult) {
            VariantInit(pVarResult);
            V_VT(pVarResult) = VT_UNKNOWN;
            V_UNKNOWN(pVarResult) = (IUnknown*)w->connection;
            w->connection->lpVtbl->AddRef(w->connection);
            return S_OK;
        }
    }
    return E_NOTIMPL;
}

static void InitVarEnumIDispatchVtable(void) {
    if (g_VarEnumIDispatchVtable[0]) return;
    g_VarEnumIDispatchVtable[0] = &VarEnumIDispatch_QueryInterface;
    g_VarEnumIDispatchVtable[1] = &VarEnumIDispatch_AddRef;
    g_VarEnumIDispatchVtable[2] = &VarEnumIDispatch_Release;
    g_VarEnumIDispatchVtable[3] = &VarEnumIDispatch_GetTypeInfoCount;
    g_VarEnumIDispatchVtable[4] = &VarEnumIDispatch_GetTypeInfo;
    g_VarEnumIDispatchVtable[5] = &VarEnumIDispatch_GetIDsOfNames;
    g_VarEnumIDispatchVtable[6] = &VarEnumIDispatch_Invoke;
}

static IDispatch* CreateVarEnumIDispatch(INetConnection *conn) {
    InitVarEnumIDispatchVtable();
    VarEnumIDispatch *w = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*w));
    if (!w) return NULL;
    w->lpVtbl = g_VarEnumIDispatchVtable;
    w->refCount = 1;
    w->connection = conn;
    conn->lpVtbl->AddRef(conn);
    return (IDispatch*)w;
}

static HRESULT STDMETHODCALLTYPE VarEnum_QueryInterface(IEnumVARIANT *pThis, REFIID riid, void **ppvObj);

static ULONG STDMETHODCALLTYPE VarEnum_AddRef(IEnumVARIANT *pThis) {
    return InterlockedIncrement(&((FakeVarEnumerator*)pThis)->refCount);
}
static ULONG STDMETHODCALLTYPE VarEnum_Release(IEnumVARIANT *pThis) {
    FakeVarEnumerator *e = (FakeVarEnumerator*)pThis;
    LONG ref = InterlockedDecrement(&e->refCount);
    if (ref == 0) {
        if (e->fakeConnection)
            e->fakeConnection->lpVtbl->Release(e->fakeConnection);
        HeapFree(GetProcessHeap(), 0, e);
    }
    return ref;
}

// IUnknown for the IDispatch interface (delegates to the enumerator's IUnknown via the same object)
static HRESULT STDMETHODCALLTYPE VarEnum_IDispatch_QueryInterface(IDispatch *pThis, REFIID riid, void **ppvObj) {
    // Forward back to the enumerator's main QueryInterface
    return VarEnum_QueryInterface((IEnumVARIANT*)pThis, riid, ppvObj);
}
static ULONG STDMETHODCALLTYPE VarEnum_IDispatch_AddRef(IDispatch *pThis) {
    return VarEnum_AddRef((IEnumVARIANT*)pThis);
}
static ULONG STDMETHODCALLTYPE VarEnum_IDispatch_Release(IDispatch *pThis) {
    return VarEnum_Release((IEnumVARIANT*)pThis);
}
static HRESULT STDMETHODCALLTYPE VarEnum_IDispatch_GetTypeInfoCount(IDispatch *pThis, UINT *pctinfo) {
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE VarEnum_IDispatch_GetTypeInfo(IDispatch *pThis, UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo) {
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE VarEnum_IDispatch_GetIDsOfNames(IDispatch *pThis, REFIID riid, OLECHAR **rgszNames, UINT cNames, LCID lcid, DISPID *rgDispId) {
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE VarEnum_IDispatch_Invoke(IDispatch *pThis, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr) {
    LogMsg("VarEnum::IDispatch::Invoke called: dispId=%ld", dispIdMember);
    FakeVarEnumerator *e = (FakeVarEnumerator*)pThis;
    if (dispIdMember == 0) {  // DISPID_VALUE
        if (pVarResult) {
            VariantInit(pVarResult);
            V_VT(pVarResult) = VT_UNKNOWN;
            V_UNKNOWN(pVarResult) = (IUnknown*)e->fakeConnection;
            e->fakeConnection->lpVtbl->AddRef(e->fakeConnection);
            return S_OK;
        }
    }
    return E_NOTIMPL;
}


// ----------------------------------------------------------------
// 1. Forward declarations & GUIDs (put these near the top of the file)
// ----------------------------------------------------------------
DEFINE_GUID(CLSID_NetSharingManager, 0x5C63C1AD, 0x3956, 0x4FF8, 0x84,0x86, 0x40,0x03,0x47,0x58,0x31,0x5B);
DEFINE_GUID(IID_INetSharingManager, 0x9475C538, 0xC2CA, 0x11d2, 0x9F,0xB5, 0x00,0xC0,0x4F,0xC3,0x27,0x17);
DEFINE_GUID(IID_INetSharingConfiguration, 0x9475C53A, 0xC2CA, 0x11d2, 0x9F,0xB5, 0x00,0xC0,0x4F,0xC3,0x27,0x17);
DEFINE_GUID(IID_INetSharingEveryConnectionCollection, 0x9475C539, 0xC2CA, 0x11d2, 0x9F,0xB5, 0x00,0xC0,0x4F,0xC3,0x27,0x17);

// ----------------------------------------------------------------
// 2. Fake INetConnection (already exists, keep it as is – 12 methods)
// ----------------------------------------------------------------
// (Your existing CreateFakeNetConnection, InitFakeConnectionVtable, etc.)

static INetConnection* GetOrCreateFakeRadminConnection(void) {
    static INetConnection* g_FakeRadminConnection = NULL;
    if (!g_FakeRadminConnection) {
        g_FakeRadminConnection = CreateFakeNetConnection();   // from your earlier code
    }
    return g_FakeRadminConnection;
}

// ----------------------------------------------------------------
// 3. IEnumVARIANT enumerator (renamed to VarEnum_* to avoid conflicts)
// ----------------------------------------------------------------



typedef struct {
    void *lpVtbl;
    LONG refCount;
} FakeNetSharingConfiguration;

static void* g_FakeSharingConfigVtable[14] = {0};

const GUID IID_IEnumNetSharingEveryConnection = 
    {0xC08956B8, 0x1CD3, 0x11D1, {0xB1, 0xC5, 0x00, 0x80, 0x5F, 0xC1, 0x27, 0x0E}};
static HRESULT STDMETHODCALLTYPE VarEnum_QueryInterface(IEnumVARIANT *pThis, REFIID riid, void **ppvObj)
{
    OLECHAR szIID[64];
    StringFromGUID2(riid, szIID, 64);
    LogMsg("VarEnum::QI(%ls)", szIID);

    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IEnumVARIANT)) {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }

    // Support the custom HNetCfg enumerator interface (same vtable layout as IEnumVARIANT)
    if (IsEqualIID(riid, &IID_IEnumNetSharingEveryConnection)) {
        LogMsg("-> IID_IEnumNetSharingEveryConnection");
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }

    // If you already added IDispatch, keep that block as well

    *ppvObj = NULL;
    return E_NOINTERFACE;
}

static HRESULT STDMETHODCALLTYPE VarEnum_Next(IEnumVARIANT *pThis, ULONG celt, VARIANT *rgVar, ULONG *pCeltFetched) {
    FakeVarEnumerator *e = (FakeVarEnumerator*)pThis;
    LogMsg("VarEnum::Next called: celt=%u", celt);
    if (!e->alreadyReturned && celt >= 1) {
        VariantInit(rgVar);
        V_VT(rgVar) = VT_UNKNOWN;
        V_UNKNOWN(rgVar) = (IUnknown*)e->fakeConnection;
        e->fakeConnection->lpVtbl->AddRef(e->fakeConnection);
        e->alreadyReturned = TRUE;
        if (pCeltFetched) *pCeltFetched = 1;
        return S_OK;
    }
    if (pCeltFetched) *pCeltFetched = 0;
    return S_FALSE;
}
static HRESULT STDMETHODCALLTYPE VarEnum_Skip(IEnumVARIANT *pThis, ULONG celt) { return S_OK; }
static HRESULT STDMETHODCALLTYPE VarEnum_Reset(IEnumVARIANT *pThis) { ((FakeVarEnumerator*)pThis)->alreadyReturned = FALSE; return S_OK; }
static HRESULT STDMETHODCALLTYPE VarEnum_Clone(IEnumVARIANT *pThis, IEnumVARIANT **ppEnum) { return E_NOTIMPL; }

static void* g_VarEnumVtable[7] = {0};

static void InitVarEnumVtable(void) {
    if (g_VarEnumVtable[0]) return;
    g_VarEnumVtable[0] = &VarEnum_QueryInterface;
    g_VarEnumVtable[1] = &VarEnum_AddRef;
    g_VarEnumVtable[2] = &VarEnum_Release;
    g_VarEnumVtable[3] = &VarEnum_Next;
    g_VarEnumVtable[4] = &VarEnum_Skip;
    g_VarEnumVtable[5] = &VarEnum_Reset;
    g_VarEnumVtable[6] = &VarEnum_Clone;
}

static IEnumVARIANT* CreateVarEnumerator(INetConnection *adapter) {
    InitVarEnumVtable();
    FakeVarEnumerator *en = (FakeVarEnumerator*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FakeVarEnumerator));
    if (!en) return NULL;
    en->lpVtbl = g_VarEnumVtable;
    en->refCount = 1;
    en->fakeConnection = adapter;
    adapter->lpVtbl->AddRef(adapter);
    return (IEnumVARIANT*)en;
}

// ----------------------------------------------------------------
// 4. INetSharingEveryConnectionCollection (correct vtable, 9 methods)
// ----------------------------------------------------------------
typedef struct {
    void *lpVtbl;
    LONG refCount;
    INetConnection *fakeConnection;
} FakeConnectionCollection;

// IUnknown
static HRESULT STDMETHODCALLTYPE Coll_QueryInterface(INetSharingEveryConnectionCollection *pThis, REFIID riid, void **ppvObj) {
    LogMsg("FakeCollection::QueryInterface");
    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_INetSharingEveryConnectionCollection) ||
        IsEqualIID(riid, &IID_IDispatch))
    {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    *ppvObj = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE Coll_AddRef(INetSharingEveryConnectionCollection *pThis) {
    LogMsg("FakeCollection::AddRef");
    return InterlockedIncrement(&((FakeConnectionCollection*)pThis)->refCount);
}
static ULONG STDMETHODCALLTYPE Coll_Release(INetSharingEveryConnectionCollection *pThis) {
    LogMsg("FakeCollection::Release");
    FakeConnectionCollection *c = (FakeConnectionCollection*)pThis;
    LONG ref = InterlockedDecrement(&c->refCount);
    if (ref == 0) {
        if (c->fakeConnection)
            c->fakeConnection->lpVtbl->Release(c->fakeConnection);
        HeapFree(GetProcessHeap(), 0, c);
    }
    return ref;
}
// IDispatch stubs
static HRESULT STDMETHODCALLTYPE Coll_GetTypeInfoCount(INetSharingEveryConnectionCollection *pThis, UINT *pctinfo) { return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE Coll_GetTypeInfo(INetSharingEveryConnectionCollection *pThis, UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo) { return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE Coll_GetIDsOfNames(INetSharingEveryConnectionCollection *pThis, REFIID riid, LPOLESTR *rgszNames, UINT cNames, LCID lcid, DISPID *rgDispId) { return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE Coll_Invoke(
    INetSharingEveryConnectionCollection *pThis, DISPID dispIdMember,
    REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS *pDispParams,
    VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr)
{
    LogMsg("FakeCollection::Invoke called: dispId=%ld", dispIdMember);
    FakeConnectionCollection *c = (FakeConnectionCollection*)pThis;
    if (dispIdMember == 0) {  // DISPID_VALUE
        if (pVarResult) {
            VariantInit(pVarResult);
            V_VT(pVarResult) = VT_UNKNOWN;
            V_UNKNOWN(pVarResult) = (IUnknown*)c->fakeConnection;
            c->fakeConnection->lpVtbl->AddRef(c->fakeConnection);
            return S_OK;
        }
    }
    return E_NOTIMPL;
}

// Custom methods
static HRESULT STDMETHODCALLTYPE Coll_get__NewEnum(INetSharingEveryConnectionCollection *pThis, IUnknown **pVal) {
    LogMsg("FakeCollection::get__NewEnum");
    FakeConnectionCollection *c = (FakeConnectionCollection*)pThis;
    *pVal = (IUnknown*)CreateVarEnumerator(c->fakeConnection);
    return (*pVal) ? S_OK : E_OUTOFMEMORY;
}
static HRESULT STDMETHODCALLTYPE Coll_get_Count(INetSharingEveryConnectionCollection *pThis, __LONG32 *pVal) {
    LogMsg("FakeCollection::get_Count -> 1");
    if (pVal) *pVal = 1;
    return S_OK;
}

static void* g_CollectionVtable[9] = {0};

static void InitCollectionVtable(void) {
    if (g_CollectionVtable[0]) return;
    g_CollectionVtable[0] = &Coll_QueryInterface;
    g_CollectionVtable[1] = &Coll_AddRef;
    g_CollectionVtable[2] = &Coll_Release;
    g_CollectionVtable[3] = &Coll_GetTypeInfoCount;
    g_CollectionVtable[4] = &Coll_GetTypeInfo;
    g_CollectionVtable[5] = &Coll_GetIDsOfNames;
    g_CollectionVtable[6] = &Coll_Invoke;
    g_CollectionVtable[7] = &Coll_get__NewEnum;
    g_CollectionVtable[8] = &Coll_get_Count;
}

static INetSharingEveryConnectionCollection* CreateConnectionCollection(INetConnection *adapter) {
    InitCollectionVtable();
    FakeConnectionCollection *coll = (FakeConnectionCollection*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FakeConnectionCollection));
    if (!coll) return NULL;
    coll->lpVtbl = g_CollectionVtable;
    coll->refCount = 1;
    coll->fakeConnection = adapter;
    adapter->lpVtbl->AddRef(adapter);
    return (INetSharingEveryConnectionCollection*)coll;
}

// Forward declaration – defined later
static INetSharingConfiguration* CreateFakeNetSharingConfiguration(void);

// ----------------------------------------------------------------
// 5. INetSharingManager proxy (wraps real, overrides get_EnumEveryConnection)
// ----------------------------------------------------------------
typedef struct {
    void *lpVtbl;
    LONG refCount;
    INetSharingManager *realManager;
} FakeNetSharingManager;

// Helper stubs
static HRESULT STDMETHODCALLTYPE SM_Stub(void) { return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE SM_Stub1(IUnknown*, REFIID, void**) { return E_NOTIMPL; } // not used, just placeholders

// IUnknown
static HRESULT STDMETHODCALLTYPE SM_QueryInterface(INetSharingManager *pThis, REFIID riid, void **ppvObj) {
    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_INetSharingManager) ||
        IsEqualIID(riid, &IID_IDispatch))
    {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    FakeNetSharingManager *f = (FakeNetSharingManager*)pThis;
    return f->realManager->lpVtbl->QueryInterface(f->realManager, riid, ppvObj);
}
static ULONG STDMETHODCALLTYPE SM_AddRef(INetSharingManager *pThis) {
    return InterlockedIncrement(&((FakeNetSharingManager*)pThis)->refCount);
}
static ULONG STDMETHODCALLTYPE SM_Release(INetSharingManager *pThis) {
    FakeNetSharingManager *f = (FakeNetSharingManager*)pThis;
    LONG ref = InterlockedDecrement(&f->refCount);
    if (ref == 0) {
        if (f->realManager)
            f->realManager->lpVtbl->Release(f->realManager);
        HeapFree(GetProcessHeap(), 0, f);
    }
    return ref;
}
// IDispatch stubs (we never use them; forward to real if you like, but stubs are fine)
static HRESULT STDMETHODCALLTYPE SM_GetTypeInfoCount(INetSharingManager *pThis, UINT *pctinfo) {
    FakeNetSharingManager *f = (FakeNetSharingManager*)pThis;
    return f->realManager->lpVtbl->GetTypeInfoCount(f->realManager, pctinfo);
}
static HRESULT STDMETHODCALLTYPE SM_GetTypeInfo(INetSharingManager *pThis, UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo) {
    FakeNetSharingManager *f = (FakeNetSharingManager*)pThis;
    return f->realManager->lpVtbl->GetTypeInfo(f->realManager, iTInfo, lcid, ppTInfo);
}
static HRESULT STDMETHODCALLTYPE SM_GetIDsOfNames(INetSharingManager *pThis, REFIID riid, LPOLESTR *rgszNames, UINT cNames, LCID lcid, DISPID *rgDispId) {
    FakeNetSharingManager *f = (FakeNetSharingManager*)pThis;
    return f->realManager->lpVtbl->GetIDsOfNames(f->realManager, riid, rgszNames, cNames, lcid, rgDispId);
}
static HRESULT STDMETHODCALLTYPE SM_Invoke(INetSharingManager *pThis, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr) {
    FakeNetSharingManager *f = (FakeNetSharingManager*)pThis;
    return f->realManager->lpVtbl->Invoke(f->realManager, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);
}
// Custom INetSharingManager methods
static HRESULT STDMETHODCALLTYPE SM_get_SharingInstalled(INetSharingManager *pThis, VARIANT_BOOL *pbInstalled) {
    LogMsg("FakeSharingManager::get_SharingInstalled -> TRUE");
    if (pbInstalled) *pbInstalled = VARIANT_TRUE;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE SM_get_EnumPublicConnections(INetSharingManager *pThis, SHARINGCONNECTION_ENUM_FLAGS Flags, INetSharingPublicConnectionCollection **ppColl) {
    LogMsg("FakeSharingManager::get_EnumPublicConnections");
    *ppColl = NULL;
    return S_FALSE;
}
static HRESULT STDMETHODCALLTYPE SM_get_EnumPrivateConnections(INetSharingManager *pThis, SHARINGCONNECTION_ENUM_FLAGS Flags, INetSharingPrivateConnectionCollection **ppColl) {
    LogMsg("FakeSharingManager::get_EnumPrivateConnections");
    *ppColl = NULL;
    return S_FALSE;
}
static HRESULT STDMETHODCALLTYPE SM_get_INetSharingConfigurationForINetConnection(INetSharingManager *pThis, INetConnection *pNetConnection, INetSharingConfiguration **ppNetSharingConfiguration) {
    LogMsg("FakeSharingManager::get_INetSharingConfigurationForINetConnection");
    *ppNetSharingConfiguration = CreateFakeNetSharingConfiguration();   // you already have this from earlier
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE SM_get_EnumEveryConnection(INetSharingManager *pThis, INetSharingEveryConnectionCollection **ppColl) {
    LogMsg("FakeSharingManager::get_EnumEveryConnection -> returning collection");
    INetConnection *adapter = GetOrCreateFakeRadminConnection();
    *ppColl = CreateConnectionCollection(adapter);
    return (*ppColl) ? S_OK : E_OUTOFMEMORY;
}
static HRESULT STDMETHODCALLTYPE SM_get_NetConnectionProps(INetSharingManager *pThis, INetConnection *pNetConnection, INetConnectionProps **ppProps) {
    LogMsg("FakeSharingManager::get_NetConnectionProps -> E_NOTIMPL");
    return E_NOTIMPL;
}

// Vtable array (14 entries: 3 IUnknown + 4 IDispatch + 7 INetSharingManager)
static void* g_FakeSharingManagerVtable[14] = {0};

// ----------------------------------------------------------------
// Fake INetSharingConfiguration (14 methods: 3 IUnknown + 4 IDispatch + 7 custom)
// ----------------------------------------------------------------

// IUnknown
static HRESULT STDMETHODCALLTYPE Cfg_QueryInterface(INetSharingConfiguration *pThis, REFIID riid, void **ppvObj) {
    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_INetSharingConfiguration) ||
        IsEqualIID(riid, &IID_IDispatch))
    {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    *ppvObj = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE Cfg_AddRef(INetSharingConfiguration *pThis) {
    return InterlockedIncrement(&((FakeNetSharingConfiguration*)pThis)->refCount);
}
static ULONG STDMETHODCALLTYPE Cfg_Release(INetSharingConfiguration *pThis) {
    FakeNetSharingConfiguration *c = (FakeNetSharingConfiguration*)pThis;
    LONG ref = InterlockedDecrement(&c->refCount);
    if (ref == 0) HeapFree(GetProcessHeap(), 0, c);
    return ref;
}

// IDispatch stubs (never actually used, but must exist)
static HRESULT STDMETHODCALLTYPE Cfg_GetTypeInfoCount(INetSharingConfiguration *pThis, UINT *pctinfo) { return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE Cfg_GetTypeInfo(INetSharingConfiguration *pThis, UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo) { return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE Cfg_GetIDsOfNames(INetSharingConfiguration *pThis, REFIID riid, LPOLESTR *rgszNames, UINT cNames, LCID lcid, DISPID *rgDispId) { return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE Cfg_Invoke(INetSharingConfiguration *pThis, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr) { return E_NOTIMPL; }

// Custom INetSharingConfiguration methods
static HRESULT STDMETHODCALLTYPE Cfg_get_SharingEnabled(INetSharingConfiguration *pThis, VARIANT_BOOL *pbEnabled) {
    LogMsg("FakeSharingCfg::get_SharingEnabled -> FALSE");
    if (pbEnabled) *pbEnabled = VARIANT_FALSE;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE Cfg_get_SharingConnectionType(INetSharingConfiguration *pThis, SHARINGCONNECTIONTYPE *pType) {
    LogMsg("FakeSharingCfg::get_SharingConnectionType -> ICSSHARINGTYPE_PUBLIC");
    if (pType) *pType = ICSSHARINGTYPE_PUBLIC;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE Cfg_DisableSharing(INetSharingConfiguration *pThis) {
    LogMsg("FakeSharingCfg::DisableSharing");
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE Cfg_EnableSharing(INetSharingConfiguration *pThis, SHARINGCONNECTIONTYPE Type) {
    LogMsg("FakeSharingCfg::EnableSharing(%d)", Type);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE Cfg_get_InternetFirewallEnabled(INetSharingConfiguration *pThis, VARIANT_BOOL *pbEnabled) {
    LogMsg("FakeSharingCfg::get_InternetFirewallEnabled -> FALSE");
    if (pbEnabled) *pbEnabled = VARIANT_FALSE;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE Cfg_DisableInternetFirewall(INetSharingConfiguration *pThis) {
    LogMsg("FakeSharingCfg::DisableInternetFirewall");
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE Cfg_EnableInternetFirewall(INetSharingConfiguration *pThis) {
    LogMsg("FakeSharingCfg::EnableInternetFirewall");
    return S_OK;
}

// Vtable initialization

static void InitFakeSharingConfigVtable(void) {
    if (g_FakeSharingConfigVtable[0]) return;
    g_FakeSharingConfigVtable[0] = &Cfg_QueryInterface;
    g_FakeSharingConfigVtable[1] = &Cfg_AddRef;
    g_FakeSharingConfigVtable[2] = &Cfg_Release;
    g_FakeSharingConfigVtable[3] = &Cfg_GetTypeInfoCount;
    g_FakeSharingConfigVtable[4] = &Cfg_GetTypeInfo;
    g_FakeSharingConfigVtable[5] = &Cfg_GetIDsOfNames;
    g_FakeSharingConfigVtable[6] = &Cfg_Invoke;
    g_FakeSharingConfigVtable[7] = &Cfg_get_SharingEnabled;        // index 7
    g_FakeSharingConfigVtable[8] = &Cfg_get_SharingConnectionType; // index 8
    g_FakeSharingConfigVtable[9] = &Cfg_DisableSharing;            // index 9
    g_FakeSharingConfigVtable[10] = &Cfg_EnableSharing;            // index 10
    g_FakeSharingConfigVtable[11] = &Cfg_get_InternetFirewallEnabled; // index 11
    g_FakeSharingConfigVtable[12] = &Cfg_DisableInternetFirewall;  // index 12
    g_FakeSharingConfigVtable[13] = &Cfg_EnableInternetFirewall;   // index 13
}

static INetSharingConfiguration* CreateFakeNetSharingConfiguration(void) {
    InitFakeSharingConfigVtable();
    FakeNetSharingConfiguration *cfg = (FakeNetSharingConfiguration*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FakeNetSharingConfiguration));
    if (!cfg) return NULL;
    cfg->lpVtbl = g_FakeSharingConfigVtable;
    cfg->refCount = 1;
    return (INetSharingConfiguration*)cfg;
}

static void InitFakeSharingManagerVtable(void) {
    if (g_FakeSharingManagerVtable[0]) return;
    g_FakeSharingManagerVtable[0] = &SM_QueryInterface;
    g_FakeSharingManagerVtable[1] = &SM_AddRef;
    g_FakeSharingManagerVtable[2] = &SM_Release;
    g_FakeSharingManagerVtable[3] = &SM_GetTypeInfoCount;
    g_FakeSharingManagerVtable[4] = &SM_GetTypeInfo;
    g_FakeSharingManagerVtable[5] = &SM_GetIDsOfNames;
    g_FakeSharingManagerVtable[6] = &SM_Invoke;
    g_FakeSharingManagerVtable[7] = &SM_get_SharingInstalled;
    g_FakeSharingManagerVtable[8] = &SM_get_EnumPublicConnections;
    g_FakeSharingManagerVtable[9] = &SM_get_EnumPrivateConnections;
    g_FakeSharingManagerVtable[10] = &SM_get_INetSharingConfigurationForINetConnection;
    g_FakeSharingManagerVtable[11] = &SM_get_EnumEveryConnection;
    g_FakeSharingManagerVtable[12] = &SM_get_NetConnectionProps;
    g_FakeSharingManagerVtable[13] = &SM_Stub;   // probably unused slot
}

static INetSharingManager* CreateFakeNetSharingManager(INetSharingManager *realManager) {
    InitFakeSharingManagerVtable();
    FakeNetSharingManager *f = (FakeNetSharingManager*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FakeNetSharingManager));
    if (!f) return NULL;
    f->lpVtbl = g_FakeSharingManagerVtable;
    f->refCount = 1;
    f->realManager = realManager;
    realManager->lpVtbl->AddRef(realManager);
    return (INetSharingManager*)f;
}
// ------------------------------------------------------------------
// Base dummy COM infrastructure (immortal objects, safe QI)
// ------------------------------------------------------------------

typedef struct {
    void *lpVtbl;
    LONG refCount;
} FakeCOMObject;

static void* g_dummyVtable[32] = {0};

// Immortal AddRef/Release (object never freed, refcount never < 1)
static ULONG STDMETHODCALLTYPE Safe_AddRef(IUnknown *pThis) {
    ULONG ref = InterlockedIncrement(&((FakeCOMObject*)pThis)->refCount);
    LogMsg("Safe_AddRef: ref=%d", ref);
    return ref;
}

static ULONG STDMETHODCALLTYPE Safe_Release(IUnknown *pThis) {
    FakeCOMObject *obj = (FakeCOMObject*)pThis;
    LONG ref = obj->refCount;
    if (ref > 1) {
        InterlockedDecrement(&obj->refCount);
    }
    LogMsg("Safe_Release: ref=%d", obj->refCount);
    return obj->refCount;
}

// Base QueryInterface – only returns IUnknown, refuses everything else
static HRESULT STDMETHODCALLTYPE Dummy_Base_QueryInterface(IUnknown *pThis, REFIID riid, void **ppvObj) {
    if (IsEqualIID(riid, &IID_IUnknown)) {
        *ppvObj = pThis;
        Safe_AddRef(pThis);
        return S_OK;
    }
    *ppvObj = NULL;
    return E_NOINTERFACE;
}

static void InitDummyVtable() {
    if (g_dummyVtable[0]) return;
    g_dummyVtable[0] = &Dummy_Base_QueryInterface;
    g_dummyVtable[1] = &Safe_AddRef;
    g_dummyVtable[2] = &Safe_Release;
    // Remaining slots deliberately NULL – they must be replaced by specific fake objects.
}

static IUnknown* CreateFakeCOMObject() {
    InitDummyVtable();
    FakeCOMObject *obj = (FakeCOMObject*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FakeCOMObject));
    if (!obj) return NULL;
    obj->lpVtbl = g_dummyVtable;
    obj->refCount = 1;
    return (IUnknown*)obj;
}

// ------------------------------------------------------------------
// Specific QueryInterface implementations for each fake object type
// ------------------------------------------------------------------

// IWbemLocator
static HRESULT STDMETHODCALLTYPE FakeWbemLocator_QueryInterface(IWbemLocator *pThis, REFIID riid, void **ppvObj)
{
    OLECHAR szIID[64];
    StringFromGUID2(riid, szIID, 64);
    LogMsg("FakeWbemLocator::QI(%ls)", szIID);
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IWbemLocator)) {
        *ppvObj = pThis;
        Safe_AddRef((IUnknown*)pThis);
        LogMsg("  -> S_OK");
        return S_OK;
    }

    LogMsg("  -> E_NOINTERFACE");
    *ppvObj = NULL;
    return E_NOINTERFACE;
}

// IWbemServices
static HRESULT STDMETHODCALLTYPE FakeWbemServices_QueryInterface(IWbemServices *pThis, REFIID riid, void **ppvObj) {
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IWbemServices)) {
        *ppvObj = pThis;
        Safe_AddRef((IUnknown*)pThis);
        return S_OK;
    }
    *ppvObj = NULL;
    return E_NOINTERFACE;
}

// IWbemCallResult (already exists, but ensure it only supports its own IID)
// (Your existing FakeCallResult_QueryInterface is fine – keep it)

// Add these prototypes after the external function declarations
ULONG STDMETHODCALLTYPE FakeWbemClass_AddRef(IWbemClassObject *pThis);
static HRESULT STDMETHODCALLTYPE Hook_IWbemServices_GetObject(
    IWbemServices *pThis, const BSTR strObjectPath, LONG lFlags,
    IWbemContext *pCtx, IWbemClassObject **ppObject,
    IWbemCallResult **ppCallResult);


/* ===================================================================
 * Original API pointers (advapi32, setupapi, ole32)
 * =================================================================== */
typedef BOOL   (WINAPI *QueryServiceStatus_t)(SC_HANDLE, LPSERVICE_STATUS);
typedef BOOL   (WINAPI *QueryServiceConfigW_t)(SC_HANDLE, LPQUERY_SERVICE_CONFIGW, DWORD, LPDWORD);
typedef SC_HANDLE (WINAPI *OpenSCManagerW_t)(LPCWSTR, LPCWSTR, DWORD);
typedef SC_HANDLE (WINAPI *OpenServiceW_t)(SC_HANDLE, LPCWSTR, DWORD);
typedef BOOL   (WINAPI *StartServiceW_t)(SC_HANDLE, DWORD, LPWSTR*);

typedef HDEVINFO (WINAPI *SetupDiGetClassDevsW_t)(const GUID*, PCWSTR, HWND, DWORD);
typedef BOOL   (WINAPI *SetupDiEnumDeviceInfo_t)(HDEVINFO, DWORD, PSP_DEVINFO_DATA);
typedef BOOL   (WINAPI *SetupDiGetDeviceRegistryPropertyW_t)(HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD);
typedef HRESULT (WINAPI *CoCreateInstance_t)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);

static QueryServiceStatus_t              Real_QueryServiceStatus           = NULL;
static QueryServiceConfigW_t             Real_QueryServiceConfigW          = NULL;
static OpenSCManagerW_t                  Real_OpenSCManagerW               = NULL;
static OpenServiceW_t                    Real_OpenServiceW                 = NULL;
static StartServiceW_t                   Real_StartServiceW                = NULL;

static SetupDiGetClassDevsW_t            Real_SetupDiGetClassDevsW         = NULL;
static SetupDiEnumDeviceInfo_t           Real_SetupDiEnumDeviceInfo        = NULL;
static SetupDiGetDeviceRegistryPropertyW_t Real_SetupDiGetDeviceRegistryPropertyW = NULL;
static CoCreateInstance_t                Real_CoCreateInstance             = NULL;

// Forward declarations for IWbemCallResult fake
HRESULT STDMETHODCALLTYPE FakeCallResult_QueryInterface(IWbemCallResult *pThis, REFIID riid, void **ppvObj);
ULONG   STDMETHODCALLTYPE FakeCallResult_AddRef(IWbemCallResult *pThis);
ULONG   STDMETHODCALLTYPE FakeCallResult_Release(IWbemCallResult *pThis);
HRESULT STDMETHODCALLTYPE FakeCallResult_GetCallStatus(IWbemCallResult *pThis, LONG lTimeoutFlags, HRESULT *phrStatus);
HRESULT STDMETHODCALLTYPE FakeCallResult_GetResultObject(IWbemCallResult *pThis, LONG lTimeoutFlags, IWbemClassObject **ppResultObject);
HRESULT STDMETHODCALLTYPE FakeCallResult_GetResultString(IWbemCallResult *pThis, LONG lTimeoutFlags, BSTR *pstrResultString);
HRESULT STDMETHODCALLTYPE FakeCallResult_GetResultServices(IWbemCallResult *pThis, LONG lTimeoutFlags, IWbemServices **ppServices);

/* ===================================================================
 * Hooks for advapi32 & registry (as before)
 * =================================================================== */


BOOL WINAPI Hook_QueryServiceStatus(SC_HANDLE hService, LPSERVICE_STATUS lpServiceStatus)
{
    LogMsg("QueryServiceStatus -> faking SERVICE_RUNNING");
    if (lpServiceStatus) {
        memset(lpServiceStatus, 0, sizeof(*lpServiceStatus));
        lpServiceStatus->dwCurrentState = SERVICE_RUNNING;
    }
    return TRUE;
}

BOOL WINAPI Hook_QueryServiceConfigW(SC_HANDLE hService, LPQUERY_SERVICE_CONFIGW lpServiceConfig,
                                     DWORD cbBufSize, LPDWORD pcbBytesNeeded)
{
    LogMsg("QueryServiceConfigW -> faking config");
    if (lpServiceConfig && cbBufSize >= sizeof(QUERY_SERVICE_CONFIGW)) {
        memset(lpServiceConfig, 0, sizeof(QUERY_SERVICE_CONFIGW));
        lpServiceConfig->dwServiceType = SERVICE_KERNEL_DRIVER;
        lpServiceConfig->dwStartType   = SERVICE_SYSTEM_START;
        lpServiceConfig->dwErrorControl = SERVICE_ERROR_NORMAL;
        static const wchar_t fakePath[] = L"\\SystemRoot\\System32\\drivers\\rvpnnetmp.sys";
        lpServiceConfig->lpBinaryPathName = (LPWSTR)fakePath;
        lpServiceConfig->lpLoadOrderGroup = L"NDIS";
        if (pcbBytesNeeded) *pcbBytesNeeded = sizeof(QUERY_SERVICE_CONFIGW);
        return TRUE;
    }
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    if (pcbBytesNeeded) *pcbBytesNeeded = sizeof(QUERY_SERVICE_CONFIGW);
    return FALSE;
}

SC_HANDLE WINAPI Hook_OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess)
{
    LogMsg("OpenSCManagerW(%ls, %ls, access=0x%lx)", 
           lpMachineName ? lpMachineName : L"NULL", 
           lpDatabaseName ? lpDatabaseName : L"NULL", 
           dwDesiredAccess);

    // Always call the real function – we no longer return a fake handle
    if (Real_OpenSCManagerW)
        return Real_OpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess);

    SetLastError(ERROR_ACCESS_DENIED);
    return NULL;
}

SC_HANDLE WINAPI Hook_OpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess)
{
    LogMsg("OpenServiceW(%ls)", lpServiceName);
    if (lpServiceName && (wcsstr(lpServiceName, L"RVPNNETMP") || wcsstr(lpServiceName, L"RadminVPN"))) {
        return (SC_HANDLE)(ULONG_PTR)0xBEEF0002;
    }
    return Real_OpenServiceW ? Real_OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess) : NULL;
}
// ------------- Proxy IEnumWbemClassObject (wraps real enumerator) -------------
typedef struct {
    void *lpVtbl;
    LONG refCount;
    IEnumWbemClassObject *realEnum;
} ProxyEnumWbemClassObject;

static void* g_ProxyEnumWbemVtable[8] = {0};

// Forward methods
static HRESULT STDMETHODCALLTYPE ProxyEnumWbem_QueryInterface(IEnumWbemClassObject *pThis, REFIID riid, void **ppvObj) {
    ProxyEnumWbemClassObject *proxy = (ProxyEnumWbemClassObject*)pThis;
    OLECHAR szIID[64];
    StringFromGUID2(riid, szIID, 64);
    LogMsg("ProxyEnumWbem::QI(%ls)", szIID);
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IEnumWbemClassObject)) {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    if (IsEqualIID(riid, &IID_IEnumVARIANT)) {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    // Fallback to real enumerator's QI for other interfaces
    return proxy->realEnum->lpVtbl->QueryInterface(proxy->realEnum, riid, ppvObj);
}
static ULONG STDMETHODCALLTYPE ProxyEnumWbem_AddRef(IEnumWbemClassObject *pThis) {
    return InterlockedIncrement(&((ProxyEnumWbemClassObject*)pThis)->refCount);
}
static ULONG STDMETHODCALLTYPE ProxyEnumWbem_Release(IEnumWbemClassObject *pThis) {
    ProxyEnumWbemClassObject *proxy = (ProxyEnumWbemClassObject*)pThis;
    LONG ref = InterlockedDecrement(&proxy->refCount);
    if (ref == 0) {
        proxy->realEnum->lpVtbl->Release(proxy->realEnum);
        HeapFree(GetProcessHeap(), 0, proxy);
    }
    return ref;
}
static HRESULT STDMETHODCALLTYPE ProxyEnumWbem_Reset(IEnumWbemClassObject *pThis) {
    LogMsg("ProxyEnumWbem::Reset");
    return ((ProxyEnumWbemClassObject*)pThis)->realEnum->lpVtbl->Reset(
        ((ProxyEnumWbemClassObject*)pThis)->realEnum);
}
static HRESULT STDMETHODCALLTYPE ProxyEnumWbem_Next(IEnumWbemClassObject *pThis, LONG lTimeout, ULONG celt,
                                                   IWbemClassObject **ppObjects, ULONG *pcReturned) {
    LogMsg("ProxyEnumWbem::Next (celt=%u)", celt);
    ProxyEnumWbemClassObject *proxy = (ProxyEnumWbemClassObject*)pThis;
    // Let real enumerator fetch objects
    HRESULT hr = proxy->realEnum->lpVtbl->Next(proxy->realEnum, lTimeout, celt, ppObjects, pcReturned);
    if (SUCCEEDED(hr) && ppObjects && *ppObjects && pcReturned && *pcReturned > 0) {
        // Wrap each real object in a ProxyWbemClassObject (see below)
        for (ULONG i = 0; i < *pcReturned; i++) {
            IWbemClassObject *realObj = ppObjects[i];
            // Create proxy wrapper that logs Get calls
            IWbemClassObject *wrapped = CreateProxyWbemClassObject(realObj);
            if (wrapped) {
                // Release the original object (proxy holds its own ref)
                realObj->lpVtbl->Release(realObj);
                ppObjects[i] = wrapped;
            }
        }
    }
    return hr;
}
static HRESULT STDMETHODCALLTYPE ProxyEnumWbem_NextAsync(IEnumWbemClassObject *pThis, ULONG uCount, IWbemObjectSink *pSink) {
    LogMsg("ProxyEnumWbem::NextAsync (uCount=%u)", uCount);
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE ProxyEnumWbem_Skip(IEnumWbemClassObject *pThis, LONG lTimeout, ULONG nCount) {
    LogMsg("ProxyEnumWbem::Skip (nCount=%u)", nCount);
    return ((ProxyEnumWbemClassObject*)pThis)->realEnum->lpVtbl->Skip(
        ((ProxyEnumWbemClassObject*)pThis)->realEnum, lTimeout, nCount);
}
static HRESULT STDMETHODCALLTYPE ProxyEnumWbem_Clone(IEnumWbemClassObject *pThis, IEnumWbemClassObject **ppEnum) {
    LogMsg("ProxyEnumWbem::Clone");
    // For simplicity, delegate to real clone and wrap result
    ProxyEnumWbemClassObject *proxy = (ProxyEnumWbemClassObject*)pThis;
    IEnumWbemClassObject *realClone = NULL;
    HRESULT hr = proxy->realEnum->lpVtbl->Clone(proxy->realEnum, &realClone);
    if (SUCCEEDED(hr) && realClone) {
        *ppEnum = CreateProxyEnumWbem(realClone);
        if (!*ppEnum) {
            realClone->lpVtbl->Release(realClone);
            return E_OUTOFMEMORY;
        }
    }
    return hr;
}

static void InitProxyEnumWbemVtable(void) {
    if (g_ProxyEnumWbemVtable[0]) return;
    g_ProxyEnumWbemVtable[0] = &ProxyEnumWbem_QueryInterface;
    g_ProxyEnumWbemVtable[1] = &ProxyEnumWbem_AddRef;
    g_ProxyEnumWbemVtable[2] = &ProxyEnumWbem_Release;
    g_ProxyEnumWbemVtable[3] = &ProxyEnumWbem_Reset;
    g_ProxyEnumWbemVtable[4] = &ProxyEnumWbem_Next;
    g_ProxyEnumWbemVtable[5] = &ProxyEnumWbem_NextAsync;
    g_ProxyEnumWbemVtable[6] = &ProxyEnumWbem_Clone;
    g_ProxyEnumWbemVtable[7] = &ProxyEnumWbem_Skip;
}

static IEnumWbemClassObject* CreateProxyEnumWbem(IEnumWbemClassObject *realEnum) {
    InitProxyEnumWbemVtable();
    ProxyEnumWbemClassObject *proxy = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*proxy));
    if (!proxy) return NULL;
    proxy->lpVtbl = g_ProxyEnumWbemVtable;
    proxy->refCount = 1;
    proxy->realEnum = realEnum;
    realEnum->lpVtbl->AddRef(realEnum);
    return (IEnumWbemClassObject*)proxy;
}

// ------------- Proxy IWbemClassObject (wraps real adapter/config object) -------------
typedef struct {
    void *lpVtbl;
    LONG refCount;
    IWbemClassObject *realObj;
} ProxyWbemClassObject;

static void* g_ProxyWbemClassVtable[32] = {0};   // as large as needed, we'll fill all 32

// IUnknown forwarders
static HRESULT STDMETHODCALLTYPE ProxyWbemCls_QueryInterface(IWbemClassObject *pThis, REFIID riid, void **ppvObj) {
    ProxyWbemClassObject *proxy = (ProxyWbemClassObject*)pThis;
    OLECHAR szIID[64]; StringFromGUID2(riid, szIID, 64);
    LogMsg("ProxyWbemCls::QI(%ls)", szIID);
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IWbemClassObject)) {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    // Let the real object handle other interfaces (e.g., IEnumVARIANT, IDispatch, etc.)
    return proxy->realObj->lpVtbl->QueryInterface(proxy->realObj, riid, ppvObj);
}
static ULONG STDMETHODCALLTYPE ProxyWbemCls_AddRef(IWbemClassObject *pThis) {
    return InterlockedIncrement(&((ProxyWbemClassObject*)pThis)->refCount);
}
static ULONG STDMETHODCALLTYPE ProxyWbemCls_Release(IWbemClassObject *pThis) {
    ProxyWbemClassObject *proxy = (ProxyWbemClassObject*)pThis;
    LONG ref = InterlockedDecrement(&proxy->refCount);
    if (ref == 0) {
        proxy->realObj->lpVtbl->Release(proxy->realObj);
        HeapFree(GetProcessHeap(), 0, proxy);
    }
    return ref;
}

// Logging wrapper for Get
static HRESULT STDMETHODCALLTYPE ProxyWbemCls_Get(IWbemClassObject *pThis, LPCWSTR wszName, LONG lFlags,
                                                 VARIANT *pVal, CIMTYPE *pType, LONG *plFlavor) {
    ProxyWbemClassObject *proxy = (ProxyWbemClassObject*)pThis;
    
    // Delegate to real object first
    HRESULT hr = proxy->realObj->lpVtbl->Get(proxy->realObj, wszName, lFlags, pVal, pType, plFlavor);
    
    // Log the result with type information
    if (SUCCEEDED(hr) && pVal) {
        VARTYPE vt = V_VT(pVal);
        const char *typeName = "UNKNOWN";
        
        switch (vt) {
            case VT_BSTR: {
                typeName = "BSTR";
                LogMsg("ProxyWbemCls::Get(%ls) [%s] = \"%ls\"", 
                       wszName ? wszName : L"(null)", 
                       typeName,
                       V_BSTR(pVal) ? V_BSTR(pVal) : L"");
                break;
            }
            case VT_BOOL: {
                typeName = "BOOL";
                LogMsg("ProxyWbemCls::Get(%ls) [%s] = %s", 
                       wszName ? wszName : L"(null)", 
                       typeName,
                       V_BOOL(pVal) ? "TRUE" : "FALSE");
                break;
            }
            case VT_I4: {
                typeName = "I4";
                LogMsg("ProxyWbemCls::Get(%ls) [%s] = %ld", 
                       wszName ? wszName : L"(null)", 
                       typeName,
                       V_I4(pVal));
                break;
            }
            case VT_UI4: {
                typeName = "UI4";
                LogMsg("ProxyWbemCls::Get(%ls) [%s] = %lu", 
                       wszName ? wszName : L"(null)", 
                       typeName,
                       V_UI4(pVal));
                break;
            }
            case VT_I2: {
                typeName = "I2";
                LogMsg("ProxyWbemCls::Get(%ls) [%s] = %d", 
                       wszName ? wszName : L"(null)", 
                       typeName,
                       V_I2(pVal));
                break;
            }
            case VT_UI2: {
                typeName = "UI2";
                LogMsg("ProxyWbemCls::Get(%ls) [%s] = %u", 
                       wszName ? wszName : L"(null)", 
                       typeName,
                       V_UI2(pVal));
                break;
            }
            case VT_I8: {
                typeName = "I8";
                LogMsg("ProxyWbemCls::Get(%ls) [%s] = %lld", 
                       wszName ? wszName : L"(null)", 
                       typeName,
                       V_I8(pVal));
                break;
            }
            case VT_UI8: {
                typeName = "UI8";
                LogMsg("ProxyWbemCls::Get(%ls) [%s] = %llu", 
                       wszName ? wszName : L"(null)", 
                       typeName,
                       V_UI8(pVal));
                break;
            }
            case VT_R4: {
                typeName = "R4";
                LogMsg("ProxyWbemCls::Get(%ls) [%s] = %f", 
                       wszName ? wszName : L"(null)", 
                       typeName,
                       V_R4(pVal));
                break;
            }
            case VT_R8: {
                typeName = "R8";
                LogMsg("ProxyWbemCls::Get(%ls) [%s] = %lf", 
                       wszName ? wszName : L"(null)", 
                       typeName,
                       V_R8(pVal));
                break;
            }
            case VT_NULL: {
                typeName = "NULL";
                LogMsg("ProxyWbemCls::Get(%ls) [%s]", 
                       wszName ? wszName : L"(null)", 
                       typeName);
                break;
            }
            case VT_EMPTY: {
                typeName = "EMPTY";
                LogMsg("ProxyWbemCls::Get(%ls) [%s]", 
                       wszName ? wszName : L"(null)", 
                       typeName);
                break;
            }
            case (VT_ARRAY | VT_BSTR): {
                typeName = "ARRAY|BSTR";
                SAFEARRAY *psa = V_ARRAY(pVal);
                if (psa) {
                    LONG lbound, ubound;
                    SafeArrayGetLBound(psa, 1, &lbound);
                    SafeArrayGetUBound(psa, 1, &ubound);
                    LONG count = ubound - lbound + 1;
                    
                    LogMsg("ProxyWbemCls::Get(%ls) [%s] = ARRAY[%ld]", 
                           wszName ? wszName : L"(null)", 
                           typeName,
                           count);
                    
                    for (LONG i = lbound; i <= ubound; i++) {
                        BSTR elem;
                        if (SUCCEEDED(SafeArrayGetElement(psa, &i, &elem))) {
                            LogMsg("  [%ld] = \"%ls\"", i - lbound, elem ? elem : L"");
                            SysFreeString(elem);
                        }
                    }
                } else {
                    LogMsg("ProxyWbemCls::Get(%ls) [%s] = (null array)", 
                           wszName ? wszName : L"(null)", 
                           typeName);
                }
                break;
            }
            case (VT_ARRAY | VT_I4): {
                typeName = "ARRAY|I4";
                SAFEARRAY *psa = V_ARRAY(pVal);
                if (psa) {
                    LONG lbound, ubound;
                    SafeArrayGetLBound(psa, 1, &lbound);
                    SafeArrayGetUBound(psa, 1, &ubound);
                    LONG count = ubound - lbound + 1;
                    
                    LogMsg("ProxyWbemCls::Get(%ls) [%s] = ARRAY[%ld]", 
                           wszName ? wszName : L"(null)", 
                           typeName,
                           count);
                    
                    for (LONG i = lbound; i <= ubound; i++) {
                        LONG elem;
                        if (SUCCEEDED(SafeArrayGetElement(psa, &i, &elem))) {
                            LogMsg("  [%ld] = %ld", i - lbound, elem);
                        }
                    }
                } else {
                    LogMsg("ProxyWbemCls::Get(%ls) [%s] = (null array)", 
                           wszName ? wszName : L"(null)", 
                           typeName);
                }
                break;
            }
            case (VT_ARRAY | VT_UI4): {
                typeName = "ARRAY|UI4";
                SAFEARRAY *psa = V_ARRAY(pVal);
                if (psa) {
                    LONG lbound, ubound;
                    SafeArrayGetLBound(psa, 1, &lbound);
                    SafeArrayGetUBound(psa, 1, &ubound);
                    LONG count = ubound - lbound + 1;
                    
                    LogMsg("ProxyWbemCls::Get(%ls) [%s] = ARRAY[%ld]", 
                           wszName ? wszName : L"(null)", 
                           typeName,
                           count);
                    
                    for (LONG i = lbound; i <= ubound; i++) {
                        ULONG elem;
                        if (SUCCEEDED(SafeArrayGetElement(psa, &i, &elem))) {
                            LogMsg("  [%ld] = %lu", i - lbound, elem);
                        }
                    }
                } else {
                    LogMsg("ProxyWbemCls::Get(%ls) [%s] = (null array)", 
                           wszName ? wszName : L"(null)", 
                           typeName);
                }
                break;
            }
            default: {
                // For any other array types or unknown types, just show the hex type
                if (vt & VT_ARRAY) {
                    LogMsg("ProxyWbemCls::Get(%ls) [ARRAY|0x%04X] = (array type 0x%04X)", 
                           wszName ? wszName : L"(null)", 
                           vt & ~VT_ARRAY, vt);
                } else {
                    LogMsg("ProxyWbemCls::Get(%ls) [0x%04X] = (unknown type)", 
                           wszName ? wszName : L"(null)", 
                           vt);
                }
                break;
            }
        }
        
        // Also log CIMTYPE if available
        if (pType && *pType != CIM_ILLEGAL) {
            char cimTypeStr[64] = {0};
            if (*pType & CIM_FLAG_ARRAY) strcat(cimTypeStr, "ARRAY|");
            switch (*pType & ~CIM_FLAG_ARRAY) {
                case CIM_SINT8:   strcat(cimTypeStr, "SINT8"); break;
                case CIM_UINT8:   strcat(cimTypeStr, "UINT8"); break;
                case CIM_SINT16:  strcat(cimTypeStr, "SINT16"); break;
                case CIM_UINT16:  strcat(cimTypeStr, "UINT16"); break;
                case CIM_SINT32:  strcat(cimTypeStr, "SINT32"); break;
                case CIM_UINT32:  strcat(cimTypeStr, "UINT32"); break;
                case CIM_SINT64:  strcat(cimTypeStr, "SINT64"); break;
                case CIM_UINT64:  strcat(cimTypeStr, "UINT64"); break;
                case CIM_REAL32:  strcat(cimTypeStr, "REAL32"); break;
                case CIM_REAL64:  strcat(cimTypeStr, "REAL64"); break;
                case CIM_BOOLEAN: strcat(cimTypeStr, "BOOLEAN"); break;
                case CIM_STRING:  strcat(cimTypeStr, "STRING"); break;
                case CIM_DATETIME: strcat(cimTypeStr, "DATETIME"); break;
                case CIM_REFERENCE: strcat(cimTypeStr, "REFERENCE"); break;
                case CIM_CHAR16:  strcat(cimTypeStr, "CHAR16"); break;
                case CIM_OBJECT:  strcat(cimTypeStr, "OBJECT"); break;
                default: strcat(cimTypeStr, "UNKNOWN"); break;
            }
            LogMsg("  CIMTYPE = %s (0x%08lX)", cimTypeStr, *pType);
        }
        
    } else if (FAILED(hr)) {
        LogMsg("ProxyWbemCls::Get(%ls) FAILED (hr=0x%08lX)", 
               wszName ? wszName : L"(null)", hr);
    } else {
        LogMsg("ProxyWbemCls::Get(%ls) = (null output)", 
               wszName ? wszName : L"(null)");
    }
    
    return hr;
}

// Similarly log GetNames, ExecMethod_, etc. But for a minimal solution, just forward everything else.
// We'll create a generic forwarder that logs the method name (but without arguments for simplicity).

// To avoid writing 30+ forwarding stubs, we can use a helper that calls the real vtable method.
// However, we must ensure the correct function signature for each slot.
// The easiest is to manually write the few methods we care about and let the rest go via a "fallback" that does not log but still forwards.
// Because the real object is fully functional, we can set the vtable to point to the real function pointers for most slots.

// Approach: In InitProxyWbemClassVtable, fill every slot with the corresponding real object's method pointer,
// but override the ones we want to log (like Get, GetNames, etc.) with our custom proxies that call the original after logging.

// We need a way to find the original method pointer for each slot. Since we wrap an existing real object,
// we can just use the same function pointer from the real object's vtable.

static void InitProxyWbemClassVtable(void) {
    if (g_ProxyWbemClassVtable[0]) return;
    // Start by copying IUnknown pointers from dummy
    g_ProxyWbemClassVtable[0] = &ProxyWbemCls_QueryInterface;
    g_ProxyWbemClassVtable[1] = &ProxyWbemCls_AddRef;
    g_ProxyWbemClassVtable[2] = &ProxyWbemCls_Release;
    // We will fill the rest dynamically when creating the first wrapper (see factory function)
}

static IWbemClassObject* CreateProxyWbemClassObject(IWbemClassObject *realObj) {
    InitProxyWbemClassVtable();
    // Allocate memory
    ProxyWbemClassObject *proxy = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*proxy));
    if (!proxy) return NULL;
    proxy->lpVtbl = g_ProxyWbemClassVtable;
    proxy->refCount = 1;
    proxy->realObj = realObj;
    realObj->lpVtbl->AddRef(realObj);

    // Now populate the vtable: for slots 3..31, we want to forward directly to the real object's methods.
    // We can just copy the whole real vtable, then overwrite slots 4 (Get) and maybe 7 (GetNames) with our logging versions.
    // However, the vtable is an array of function pointers, and we must know the slot layout.
    // From the debugger we know: index 4 = Get, index 7 = GetNames.
    // So we copy the real vtable into our proxy vtable, then replace index 4 and 7 with our wrappers.
    // But our proxy vtable is shared by all ProxyWbemClassObject instances! So we can't just copy per-instance real vtable.
    // Instead, we need a global vtable that uses the real methods, which we can set once using any real object's vtable.
    // Since all IWbemClassObject vtables for a given process are likely the same (the WMI implementation), we can grab one from any real object.
    static BOOL vtableFilled = FALSE;
    if (!vtableFilled) {
        void **realVtbl = *(void***)realObj;
        // Copy the entire vtable into our proxy slots (starting at index 0)
        // But we must preserve our custom IUnknown at indices 0-2. The real IUnknown is different,
        // but we don't want to use it because they may not handle our proxy reference count properly.
        // So we manually copy indices 3..31.
        for (int i = 3; i < 32; i++) {
            g_ProxyWbemClassVtable[i] = realVtbl[i];
        }
        // Now replace the methods we want to intercept
        g_ProxyWbemClassVtable[4] = &ProxyWbemCls_Get;   // Get
        // Optionally add GetNames, BeginEnumeration, Next, etc.
        vtableFilled = TRUE;
    }
    // That's it; the vtable is ready.
    return (IWbemClassObject*)proxy;
}


BOOL WINAPI Hook_StartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPWSTR *lpServiceArgVectors)
{
    LogMsg("StartServiceW -> faking success");
    return TRUE;
}

static BOOL EnableRestorePrivilege(void)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_PRIVILEGES tp;
    LUID luid;
    // Use the explicit wide string "SeRestorePrivilege"
    if (!LookupPrivilegeValueW(NULL, L"SeRestorePrivilege", &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    return result && (err == ERROR_SUCCESS);
}

#include <aclapi.h>       // for SetSecurityInfo, SE_OBJECT_TYPE


/* ===================================================================
 * SetupAPI hooks – fake Radmin virtual adapter
 * =================================================================== */
#define FAKE_DEVICE_TAG  0x5250564E  // 'RVPN'

HDEVINFO WINAPI Hook_SetupDiGetClassDevsW(const GUID *ClassGuid, PCWSTR Enumerator, HWND hwndParent, DWORD Flags)
{
    LogMsg("SetupDiGetClassDevsW");
    return Real_SetupDiGetClassDevsW(ClassGuid, Enumerator, hwndParent, Flags);
}

BOOL WINAPI Hook_SetupDiEnumDeviceInfo(HDEVINFO DeviceInfoSet, DWORD MemberIndex, PSP_DEVINFO_DATA DeviceInfoData)
{
    if (MemberIndex == 0) {
        if (!DeviceInfoData) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        memset(DeviceInfoData, 0, sizeof(*DeviceInfoData));
        DeviceInfoData->cbSize = sizeof(SP_DEVINFO_DATA);
        DeviceInfoData->Reserved = (ULONG_PTR)FAKE_DEVICE_TAG;
        LogMsg("SetupDiEnumDeviceInfo -> injecting fake device");
        return TRUE;
    }
    return Real_SetupDiEnumDeviceInfo(DeviceInfoSet, MemberIndex - 1, DeviceInfoData);
}

BOOL WINAPI Hook_SetupDiGetDeviceRegistryPropertyW(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData,
    DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize)
{
    if (DeviceInfoData && DeviceInfoData->Reserved == (ULONG_PTR)FAKE_DEVICE_TAG) {
        if (Property == SPDRP_HARDWAREID) {
            static const wchar_t fakeHwid[] = L"rvpnnetmp";
            DWORD neededBytes = sizeof(fakeHwid);
            if (PropertyBufferSize >= neededBytes) {
                memcpy(PropertyBuffer, fakeHwid, neededBytes);
                if (RequiredSize) *RequiredSize = neededBytes;
                if (PropertyRegDataType) *PropertyRegDataType = REG_SZ;
                LogMsg("SetupDiGetDeviceRegistryProperty -> fake HWID");
                return TRUE;
            } else {
                if (RequiredSize) *RequiredSize = neededBytes;
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            }
        }
        SetLastError(ERROR_NOT_FOUND);
        return FALSE;
    }
    return Real_SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet, DeviceInfoData, Property,
        PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);
}

// ---------- Fake IWbemCallResult ----------
typedef struct {
    void *lpVtbl;
    LONG refCount;
} FakeWbemCallResult;

static void* g_FakeCallResultVtable[8] = {0};

// IWbemCallResult methods
HRESULT STDMETHODCALLTYPE FakeCallResult_QueryInterface(IWbemCallResult *pThis, REFIID riid, void **ppvObj) {
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IWbemCallResult)) {
        *ppvObj = pThis;
        FakeCallResult_AddRef(pThis);
        return S_OK;
    }
    *ppvObj = NULL;
    return E_NOINTERFACE;
}
ULONG STDMETHODCALLTYPE FakeCallResult_AddRef(IWbemCallResult *pThis) {
    return InterlockedIncrement(&((FakeWbemCallResult*)pThis)->refCount);
}
ULONG STDMETHODCALLTYPE FakeCallResult_Release(IWbemCallResult *pThis)
{
    FakeWbemCallResult *obj = (FakeWbemCallResult*)pThis;
    LONG ref = obj->refCount;
    if (ref > 1) {
        InterlockedDecrement(&obj->refCount);
    }
    LogMsg("FakeCallResult::Release (ref=%d)", obj->refCount);
    return obj->refCount;
}
HRESULT STDMETHODCALLTYPE FakeCallResult_GetCallStatus(IWbemCallResult *pThis, LONG lTimeoutFlags, HRESULT *phrStatus) {
    LogMsg("FakeCallResult::GetCallStatus");
    if (phrStatus) *phrStatus = S_OK;   // indicate completion
    return S_OK;
}
HRESULT STDMETHODCALLTYPE FakeCallResult_GetResultObject(IWbemCallResult *pThis, LONG lTimeoutFlags, IWbemClassObject **ppResultObject) {
    LogMsg("FakeCallResult::GetResultObject");
    return WBEM_E_NOT_FOUND;
}
HRESULT STDMETHODCALLTYPE FakeCallResult_GetResultString(IWbemCallResult *pThis, LONG lTimeoutFlags, BSTR *pstrResultString) {
    LogMsg("FakeCallResult::GetResultString");
    return WBEM_E_NOT_FOUND;
}
HRESULT STDMETHODCALLTYPE FakeCallResult_GetResultServices(IWbemCallResult *pThis, LONG lTimeoutFlags, IWbemServices **ppServices) {
    LogMsg("FakeCallResult::GetResultServices");
    return WBEM_E_NOT_FOUND;
}

static void InitFakeCallResultVtable() {
    if (g_FakeCallResultVtable[0]) return;
    g_FakeCallResultVtable[0] = &FakeCallResult_QueryInterface;
    g_FakeCallResultVtable[1] = &FakeCallResult_AddRef;
    g_FakeCallResultVtable[2] = &FakeCallResult_Release;
    g_FakeCallResultVtable[3] = &FakeCallResult_GetCallStatus;
    g_FakeCallResultVtable[4] = &FakeCallResult_GetResultObject;
    g_FakeCallResultVtable[5] = &FakeCallResult_GetResultString;
    g_FakeCallResultVtable[6] = &FakeCallResult_GetResultServices;
}

static FakeWbemCallResult g_FakeCallResult = { g_FakeCallResultVtable, 1 };

static IWbemCallResult* GetFakeCallResult() {
    InitFakeCallResultVtable();
    return (IWbemCallResult*)&g_FakeCallResult;
}
/* ===================================================================
 * WMI hooks – fake Win32_NetworkAdapterConfiguration
 * =================================================================== */
// VTable method signatures
typedef HRESULT (STDMETHODCALLTYPE *IWbemLocator_ConnectServer_t)(
    IWbemLocator *pThis, const BSTR strNetworkResource, const BSTR strUser,
    const BSTR strPassword, const BSTR strLocale, LONG lSecurityFlags,
    const BSTR strAuthority, IWbemContext *pCtx, IWbemServices **ppNamespace);

typedef HRESULT (STDMETHODCALLTYPE *IWbemServices_GetObject_t)(
    IWbemServices *pThis, const BSTR strObjectPath, LONG lFlags,
    IWbemContext *pCtx, IWbemClassObject **ppObject, IWbemCallResult **ppCallResult);

// We'll need a fake IWbemClassObject with properties
static IWbemClassObject* CreateFakeWbemClassObject(void);

/* ------------------------------------------------------------------
 * Proxy IWbemServices – wraps a real IWbemServices, logs every call,
 * and overrides only the Radmin‑specific methods.
 * ------------------------------------------------------------------ */
typedef struct {
    IWbemServicesVtbl *lpVtbl;
    LONG refCount;
    IWbemServices *realService;   /* the actual WMI service */
} ProxyWbemServices;

/* Forward declarations of helpers used by the proxy (defined later) */
static IEnumWbemClassObject* CreateFakeEnumWbemClassObject(IWbemClassObject *fakeObject);
static BSTR ExtractGuidFromQuery(const BSTR strQuery);
static IWbemClassObject* CreateFakeNetAdapterObject(BSTR guid);

/* Forward declaration for Proxy_ExecMethod (implemented after the other proxy methods) */
static HRESULT STDMETHODCALLTYPE Proxy_ExecMethod(
    IWbemServices *pThis, BSTR strObjectPath, BSTR strMethodName,
    LONG lFlags, IWbemContext *pCtx,
    IWbemClassObject *pInParams, IWbemClassObject **ppOutParams,
    IWbemCallResult **ppCallResult);

static ULONG STDMETHODCALLTYPE Proxy_AddRef(IWbemServices *pThis) {
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    return InterlockedIncrement(&proxy->refCount);
}

static HRESULT STDMETHODCALLTYPE Proxy_QueryInterface(
    IWbemServices *pThis, REFIID riid, void **ppvObj)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;

    OLECHAR szIID[64];
    StringFromGUID2(riid, szIID, 64);
    LogMsg("Proxy::QueryInterface(%ls)", szIID);

    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IWbemServices)) {
        *ppvObj = pThis;
        Proxy_AddRef(pThis);
        return S_OK;
    }

    // Forward everything else to the real service – it may support IWbemServicesSecurity, etc.
    return proxy->realService->lpVtbl->QueryInterface(proxy->realService, riid, ppvObj);
}

static ULONG STDMETHODCALLTYPE Proxy_Release(IWbemServices *pThis) {
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LONG ref = InterlockedDecrement(&proxy->refCount);
    if (ref == 0) {
        /* release the real service */
        if (proxy->realService)
            proxy->realService->lpVtbl->Release(proxy->realService);
        HeapFree(GetProcessHeap(), 0, proxy);
    }
    return ref;
}

/* Generic forwarding stubs – log then call the real service */

static HRESULT STDMETHODCALLTYPE Proxy_OpenNamespace(
    IWbemServices *pThis, BSTR strNamespace, LONG lFlags,
    IWbemContext *pCtx, IWbemServices **ppWorkingNamespace,
    IWbemCallResult **ppResult)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::OpenNamespace(%ls)", strNamespace);
    return proxy->realService->lpVtbl->OpenNamespace(
        proxy->realService, strNamespace, lFlags, pCtx,
        ppWorkingNamespace, ppResult);
}

static HRESULT STDMETHODCALLTYPE Proxy_CancelAsyncCall(
    IWbemServices *pThis, IWbemObjectSink *pSink)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::CancelAsyncCall");
    return proxy->realService->lpVtbl->CancelAsyncCall(
        proxy->realService, pSink);
}

static HRESULT STDMETHODCALLTYPE Proxy_QueryObjectSink(
    IWbemServices *pThis, LONG lFlags, IWbemObjectSink **ppResponseHandler)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::QueryObjectSink");
    return proxy->realService->lpVtbl->QueryObjectSink(
        proxy->realService, lFlags, ppResponseHandler);
}

static HRESULT STDMETHODCALLTYPE Proxy_GetObjectAsync(
    IWbemServices *pThis, BSTR strObjectPath, LONG lFlags,
    IWbemContext *pCtx, IWbemObjectSink *pResponseHandler)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::GetObjectAsync(%ls)", strObjectPath);
    return proxy->realService->lpVtbl->GetObjectAsync(
        proxy->realService, strObjectPath, lFlags, pCtx, pResponseHandler);
}

static HRESULT STDMETHODCALLTYPE Proxy_PutClass(
    IWbemServices *pThis, IWbemClassObject *pObject, LONG lFlags,
    IWbemContext *pCtx, IWbemCallResult **ppCallResult)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::PutClass");
    return proxy->realService->lpVtbl->PutClass(
        proxy->realService, pObject, lFlags, pCtx, ppCallResult);
}

static HRESULT STDMETHODCALLTYPE Proxy_PutClassAsync(
    IWbemServices *pThis, IWbemClassObject *pObject, LONG lFlags,
    IWbemContext *pCtx, IWbemObjectSink *pResponseHandler)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::PutClassAsync");
    return proxy->realService->lpVtbl->PutClassAsync(
        proxy->realService, pObject, lFlags, pCtx, pResponseHandler);
}

static HRESULT STDMETHODCALLTYPE Proxy_DeleteClass(
    IWbemServices *pThis, BSTR strClass, LONG lFlags,
    IWbemContext *pCtx, IWbemCallResult **ppCallResult)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::DeleteClass(%ls)", strClass);
    return proxy->realService->lpVtbl->DeleteClass(
        proxy->realService, strClass, lFlags, pCtx, ppCallResult);
}

static HRESULT STDMETHODCALLTYPE Proxy_DeleteClassAsync(
    IWbemServices *pThis, BSTR strClass, LONG lFlags,
    IWbemContext *pCtx, IWbemObjectSink *pResponseHandler)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::DeleteClassAsync(%ls)", strClass);
    return proxy->realService->lpVtbl->DeleteClassAsync(
        proxy->realService, strClass, lFlags, pCtx, pResponseHandler);
}

static HRESULT STDMETHODCALLTYPE Proxy_CreateClassEnum(
    IWbemServices *pThis, BSTR strSuperclass, LONG lFlags,
    IWbemContext *pCtx, IEnumWbemClassObject **ppEnum)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::CreateClassEnum(%ls)", strSuperclass);
    return proxy->realService->lpVtbl->CreateClassEnum(
        proxy->realService, strSuperclass, lFlags, pCtx, ppEnum);
}

static HRESULT STDMETHODCALLTYPE Proxy_CreateClassEnumAsync(
    IWbemServices *pThis, BSTR strSuperclass, LONG lFlags,
    IWbemContext *pCtx, IWbemObjectSink *pResponseHandler)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::CreateClassEnumAsync(%ls)", strSuperclass);
    return proxy->realService->lpVtbl->CreateClassEnumAsync(
        proxy->realService, strSuperclass, lFlags, pCtx, pResponseHandler);
}

static HRESULT STDMETHODCALLTYPE Proxy_PutInstance(
    IWbemServices *pThis, IWbemClassObject *pInst, LONG lFlags,
    IWbemContext *pCtx, IWbemCallResult **ppCallResult)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::PutInstance");
    return proxy->realService->lpVtbl->PutInstance(
        proxy->realService, pInst, lFlags, pCtx, ppCallResult);
}

static HRESULT STDMETHODCALLTYPE Proxy_PutInstanceAsync(
    IWbemServices *pThis, IWbemClassObject *pInst, LONG lFlags,
    IWbemContext *pCtx, IWbemObjectSink *pResponseHandler)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::PutInstanceAsync");
    return proxy->realService->lpVtbl->PutInstanceAsync(
        proxy->realService, pInst, lFlags, pCtx, pResponseHandler);
}

static HRESULT STDMETHODCALLTYPE Proxy_DeleteInstance(
    IWbemServices *pThis, BSTR strObjectPath, LONG lFlags,
    IWbemContext *pCtx, IWbemCallResult **ppCallResult)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::DeleteInstance(%ls)", strObjectPath);
    return proxy->realService->lpVtbl->DeleteInstance(
        proxy->realService, strObjectPath, lFlags, pCtx, ppCallResult);
}

static HRESULT STDMETHODCALLTYPE Proxy_DeleteInstanceAsync(
    IWbemServices *pThis, BSTR strObjectPath, LONG lFlags,
    IWbemContext *pCtx, IWbemObjectSink *pResponseHandler)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::DeleteInstanceAsync(%ls)", strObjectPath);
    return proxy->realService->lpVtbl->DeleteInstanceAsync(
        proxy->realService, strObjectPath, lFlags, pCtx, pResponseHandler);
}

static HRESULT STDMETHODCALLTYPE Proxy_CreateInstanceEnumAsync(
    IWbemServices *pThis, BSTR strFilter, LONG lFlags,
    IWbemContext *pCtx, IWbemObjectSink *pResponseHandler)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::CreateInstanceEnumAsync(%ls)", strFilter);
    return proxy->realService->lpVtbl->CreateInstanceEnumAsync(
        proxy->realService, strFilter, lFlags, pCtx, pResponseHandler);
}

static HRESULT STDMETHODCALLTYPE Proxy_ExecQueryAsync(
    IWbemServices *pThis, BSTR strQueryLanguage, BSTR strQuery,
    LONG lFlags, IWbemContext *pCtx, IWbemObjectSink *pResponseHandler)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::ExecQueryAsync");
    return proxy->realService->lpVtbl->ExecQueryAsync(
        proxy->realService, strQueryLanguage, strQuery, lFlags, pCtx, pResponseHandler);
}

static HRESULT STDMETHODCALLTYPE Proxy_ExecNotificationQuery(
    IWbemServices *pThis, BSTR strQueryLanguage, BSTR strQuery,
    LONG lFlags, IWbemContext *pCtx, IEnumWbemClassObject **ppEnum)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::ExecNotificationQuery");
    return proxy->realService->lpVtbl->ExecNotificationQuery(
        proxy->realService, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);
}

static HRESULT STDMETHODCALLTYPE Proxy_ExecNotificationQueryAsync(
    IWbemServices *pThis, BSTR strQueryLanguage, BSTR strQuery,
    LONG lFlags, IWbemContext *pCtx, IWbemObjectSink *pResponseHandler)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::ExecNotificationQueryAsync");
    return proxy->realService->lpVtbl->ExecNotificationQueryAsync(
        proxy->realService, strQueryLanguage, strQuery, lFlags, pCtx, pResponseHandler);
}

static HRESULT STDMETHODCALLTYPE Proxy_ExecMethodAsync(
    IWbemServices *pThis, BSTR strObjectPath, BSTR strMethodName,
    LONG lFlags, IWbemContext *pCtx,
    IWbemClassObject *pInParams, IWbemObjectSink *pResponseHandler)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::ExecMethodAsync(%ls, %ls)", strObjectPath, strMethodName);
    return proxy->realService->lpVtbl->ExecMethodAsync(
        proxy->realService, strObjectPath, strMethodName, lFlags,
        pCtx, pInParams, pResponseHandler);
}

/* -------- Intercepted GetObject ---------- */
static HRESULT STDMETHODCALLTYPE Proxy_GetObject(
    IWbemServices *pThis, BSTR strObjectPath, LONG lFlags,
    IWbemContext *pCtx, IWbemClassObject **ppObject,
    IWbemCallResult **ppCallResult)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::GetObject(%ls)", strObjectPath);

#if BLOCK_REAL
    if (wcsstr(strObjectPath, L"Win32_NetworkAdapterConfiguration")) {
        *ppObject = CreateFakeWbemClassObject();
        if (ppCallResult) *ppCallResult = NULL;
        return S_OK;
    }
    if (wcsstr(strObjectPath, L"Win32_NetworkAdapter")) {
        BSTR guid = ExtractDeviceIDFromPath(strObjectPath);
        IWbemClassObject *fakeAdapter = CreateFakeNetAdapterObject(guid);
        SysFreeString(guid);
        if (!fakeAdapter) return E_OUTOFMEMORY;
        *ppObject = fakeAdapter;
        if (ppCallResult) *ppCallResult = NULL;
        return S_OK;
    }
#endif

    return proxy->realService->lpVtbl->GetObject(
        proxy->realService, strObjectPath, lFlags, pCtx, ppObject, ppCallResult);
}

/* -------- Intercepted CreateInstanceEnum ---------- */
static HRESULT STDMETHODCALLTYPE Proxy_CreateInstanceEnum(
    IWbemServices *pThis, BSTR strFilter, LONG lFlags,
    IWbemContext *pCtx, IEnumWbemClassObject **ppEnum)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::CreateInstanceEnum(%ls)", strFilter);

#if BLOCK_REAL
    if (strFilter && _wcsicmp(strFilter, L"Win32_NetworkAdapterConfiguration") == 0) {
        IWbemClassObject *fakeObj = CreateFakeWbemClassObject();
        if (!fakeObj) return E_OUTOFMEMORY;
        *ppEnum = CreateFakeEnumWbemClassObject(fakeObj);
        fakeObj->lpVtbl->Release(fakeObj);
        return (*ppEnum) ? WBEM_S_NO_ERROR : E_OUTOFMEMORY;
    }
#endif

    return proxy->realService->lpVtbl->CreateInstanceEnum(
        proxy->realService, strFilter, lFlags, pCtx, ppEnum);
}

/* -------- Intercepted ExecQuery ---------- */
/* -------- Intercepted ExecQuery ---------- */
static HRESULT STDMETHODCALLTYPE Proxy_ExecQuery(
    IWbemServices *pThis, BSTR strQueryLanguage, BSTR strQuery,
    LONG lFlags, IWbemContext *pCtx, IEnumWbemClassObject **ppEnum)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::ExecQuery(%ls)", strQuery);

#if BLOCK_REAL
    // ---------- Full fake mode ----------
    if (wcsstr(strQuery, L"Win32_NetworkAdapterConfiguration")) {
        LogMsg("  -> matched Win32_NetworkAdapterConfiguration – creating fake object");
        IWbemClassObject *fakeObj = CreateFakeWbemClassObject();
        if (!fakeObj) {
            LogMsg("  -> CreateFakeWbemClassObject failed");
            return E_OUTOFMEMORY;
        }
        *ppEnum = CreateFakeEnumWbemClassObject(fakeObj);
        fakeObj->lpVtbl->Release(fakeObj);
        if (*ppEnum) {
            LogMsg("  -> returning fake enumerator (0x%p)", *ppEnum);
            return WBEM_S_NO_ERROR;
        } else {
            LogMsg("  -> CreateFakeEnumWbemClassObject failed");
            return E_OUTOFMEMORY;
        }
    }

    if (wcsstr(strQuery, L"Win32_NetworkAdapter")) {
        LogMsg("  -> matched Win32_NetworkAdapter – extracting GUID");
        BSTR guid = ExtractGuidFromQuery(strQuery);
        if (guid) {
            wchar_t guidStr[64];
            StringFromGUID2((const GUID*)guid, guidStr, 64);
            LogMsg("  -> extracted GUID: %ls", guidStr);
        } else {
            LogMsg("  -> no GUID found, using default");
        }
        IWbemClassObject *fakeObj = CreateFakeNetAdapterObject(guid);
        SysFreeString(guid);
        if (!fakeObj) {
            LogMsg("  -> CreateFakeNetAdapterObject failed");
            return E_OUTOFMEMORY;
        }
        *ppEnum = CreateFakeEnumWbemClassObject(fakeObj);
        fakeObj->lpVtbl->Release(fakeObj);
        if (*ppEnum) {
            LogMsg("  -> returning fake enumerator (0x%p)", *ppEnum);
            return WBEM_S_NO_ERROR;
        } else {
            LogMsg("  -> CreateFakeEnumWbemClassObject failed");
            return E_OUTOFMEMORY;
        }
    }

    LogMsg("  -> not a Radmin query – forwarding to real service");
    return proxy->realService->lpVtbl->ExecQuery(
        proxy->realService, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);
#else
    // ---------- Proxy mode (BLOCK_REAL=0) ----------
    // 1. Execute real query on real service
    HRESULT hr = proxy->realService->lpVtbl->ExecQuery(
        proxy->realService, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);
    
    LogMsg("  -> real ExecQuery returned 0x%08lX, ppEnum=%p", hr, ppEnum ? *ppEnum : NULL);
    
    // 2. If successful and we got an enumerator, wrap it with proxy
    if (SUCCEEDED(hr) && ppEnum && *ppEnum) {
        IEnumWbemClassObject *realEnum = *ppEnum;
        *ppEnum = CreateProxyEnumWbem(realEnum);
        if (!*ppEnum) {
            LogMsg("  -> CreateProxyEnumWbem failed");
            // If wrapper creation fails, we can still return the real one,
            // but we'd lose logging. Better to release real and return error.
            realEnum->lpVtbl->Release(realEnum);
            return E_OUTOFMEMORY;
        }
        LogMsg("  -> real enumerator wrapped in proxy");
    }
    
    return hr;
#endif
}

static IWbemServicesVtbl g_proxyVtbl = {0};

static void InitProxyVtbl(void) {
    if (g_proxyVtbl.QueryInterface) return;

    g_proxyVtbl.QueryInterface          = Proxy_QueryInterface;
    g_proxyVtbl.AddRef                  = Proxy_AddRef;
    g_proxyVtbl.Release                 = Proxy_Release;
    g_proxyVtbl.OpenNamespace           = Proxy_OpenNamespace;
    g_proxyVtbl.CancelAsyncCall         = Proxy_CancelAsyncCall;
    g_proxyVtbl.QueryObjectSink         = Proxy_QueryObjectSink;
    g_proxyVtbl.GetObject               = Proxy_GetObject;          /* intercepted */
    g_proxyVtbl.GetObjectAsync          = Proxy_GetObjectAsync;
    g_proxyVtbl.PutClass                = Proxy_PutClass;
    g_proxyVtbl.PutClassAsync           = Proxy_PutClassAsync;
    g_proxyVtbl.DeleteClass             = Proxy_DeleteClass;
    g_proxyVtbl.DeleteClassAsync        = Proxy_DeleteClassAsync;
    g_proxyVtbl.CreateClassEnum         = Proxy_CreateClassEnum;
    g_proxyVtbl.CreateClassEnumAsync    = Proxy_CreateClassEnumAsync;
    g_proxyVtbl.PutInstance             = Proxy_PutInstance;
    g_proxyVtbl.PutInstanceAsync        = Proxy_PutInstanceAsync;
    g_proxyVtbl.DeleteInstance          = Proxy_DeleteInstance;
    g_proxyVtbl.DeleteInstanceAsync     = Proxy_DeleteInstanceAsync;
    g_proxyVtbl.CreateInstanceEnum      = Proxy_CreateInstanceEnum; /* intercepted */
    g_proxyVtbl.CreateInstanceEnumAsync = Proxy_CreateInstanceEnumAsync;
    g_proxyVtbl.ExecQuery               = Proxy_ExecQuery;          /* intercepted */
    g_proxyVtbl.ExecQueryAsync          = Proxy_ExecQueryAsync;
    g_proxyVtbl.ExecNotificationQuery   = Proxy_ExecNotificationQuery;
    g_proxyVtbl.ExecNotificationQueryAsync = Proxy_ExecNotificationQueryAsync;
    g_proxyVtbl.ExecMethod              = Proxy_ExecMethod;         /* intercepted */
    g_proxyVtbl.ExecMethodAsync         = Proxy_ExecMethodAsync;
}

static IWbemServices* CreateProxyWbemServices(IWbemServices *realService) {
    InitProxyVtbl();
    ProxyWbemServices *proxy = (ProxyWbemServices*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ProxyWbemServices));
    if (!proxy) return NULL;
    proxy->lpVtbl = &g_proxyVtbl;
    proxy->refCount = 1;
    proxy->realService = realService;
    realService->lpVtbl->AddRef(realService); /* keep it alive */
    return (IWbemServices*)proxy;
}

/* -------- Intercepted ExecMethod ---------- */
static HRESULT STDMETHODCALLTYPE Proxy_ExecMethod(
    IWbemServices *pThis, BSTR strObjectPath, BSTR strMethodName,
    LONG lFlags, IWbemContext *pCtx,
    IWbemClassObject *pInParams, IWbemClassObject **ppOutParams,
    IWbemCallResult **ppCallResult)
{
    ProxyWbemServices *proxy = (ProxyWbemServices*)pThis;
    LogMsg("Proxy::ExecMethod(%ls, %ls)", strObjectPath, strMethodName);

#if BLOCK_REAL
    if (wcsstr(strObjectPath, L"Win32_NetworkAdapterConfiguration") ||
        wcsstr(strObjectPath, L"Win32_NetworkAdapter"))
    {
        if (ppOutParams) *ppOutParams = NULL;
        if (ppCallResult) *ppCallResult = NULL;
        return WBEM_S_NO_ERROR;
    }
#endif

    return proxy->realService->lpVtbl->ExecMethod(
        proxy->realService, strObjectPath, strMethodName, lFlags,
        pCtx, pInParams, ppOutParams, ppCallResult);
}

static void* g_patchedLocatorVtable[4];
static IWbemLocator_ConnectServer_t Real_IWbemLocator_ConnectServer = NULL;

// We'll store the real GetObject globally for use in the hook
static IWbemServices_GetObject_t Real_IWbemServices_GetObject = NULL;

static BSTR ExtractDeviceIDFromPath(const BSTR path) {
    const wchar_t *start = wcsstr(path, L"DeviceID=\"");
    if (!start) return NULL;
    start += 10;   // skip "DeviceID=\""
    const wchar_t *end = wcschr(start, L'\"');
    if (!end) return NULL;
    size_t len = end - start;
    return SysAllocStringLen(start, (UINT)len);
}

static HRESULT STDMETHODCALLTYPE Hook_IWbemServices_GetObject(
    IWbemServices *pThis, const BSTR strObjectPath, LONG lFlags,
    IWbemContext *pCtx, IWbemClassObject **ppObject,
    IWbemCallResult **ppCallResult)
{
    if (wcsstr(strObjectPath, L"Win32_NetworkAdapterConfiguration")) {
        *ppObject = CreateFakeWbemClassObject();
        if (ppCallResult) *ppCallResult = NULL;
        return S_OK;
    }

    // *** NEW ***
    if (wcsstr(strObjectPath, L"Win32_NetworkAdapter")) {
        BSTR guid = ExtractDeviceIDFromPath(strObjectPath);  // see helper below
        IWbemClassObject *fakeAdapter = CreateFakeNetAdapterObject(guid);
        SysFreeString(guid);
        if (!fakeAdapter) return E_OUTOFMEMORY;
        *ppObject = fakeAdapter;
        if (ppCallResult) *ppCallResult = NULL;
        return S_OK;
    }

    // fallback (real WMI)
    return Real_IWbemServices_GetObject(pThis, strObjectPath, lFlags, pCtx,
                                        ppObject, ppCallResult);
}

// ----------------------------------------------------------------------
// Fake IWbemClassObject – minimal implementation
// ----------------------------------------------------------------------
typedef struct {
    void *lpVtbl;
    LONG refCount;
} FakeWbemClassObject;

// Property values we want to expose
static const wchar_t *fake_serviceName = L"RvNetMP60";
static const wchar_t *fake_description = L"Famatech Radmin VPN Ethernet Adapter";
static wchar_t fake_FriendlyName[128] = L"Radmin VPN Adapter";
static wchar_t fake_settingID[64] = L"{00000000-0000-0000-0000-000000000000}";
static BOOL fake_settingID_initialized = FALSE;

static NETCON_STATUS g_FakeConnectionStatus = NCS_DISCONNECTED;
static wchar_t fake_ipAddress[64] = L"26.0.0.2";
static wchar_t g_fakeIPv6Address[64] = L"fdfd::0000:0002";   // default if none parsed
static BOOL g_hasIPv6Address = FALSE;
static wchar_t fake_ipSubnet[64]  = L"255.0.0.0";
static wchar_t fake_gateway[64]   = L"26.0.0.1";
static wchar_t fake_dns[64]       = L"8.8.8.8";
// MAC address buffer (will be filled by GetFakeLocalMac)
static BYTE fake_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static BOOL fake_mac_initialized = FALSE;

int GetFakeMacAddress(uint8_t out_mac[6])
{
    memcpy(out_mac, fake_mac, 6);
    return TRUE;
}

typedef struct _HANDLE_CONTEXT HANDLE_CONTEXT;
extern BOOL GetFakeLocalMac(HANDLE_CONTEXT *ctx, uint8_t *macOut);

#define RANDOMIZE 0
static BOOL GetRadminAdapterIdFromRegistry(wchar_t *outGuid, DWORD outSize);
void InitFakeMac(void)
{
    if (fake_mac_initialized) return;
    fake_mac_initialized = TRUE;
    fake_settingID_initialized = TRUE;

// #if RANDOMIZE
    // Generate random MAC
    // First byte must have locally administered bit (bit 1) set, and unicast (bit 0) cleared.
    fake_mac[0] = 0x02;
    fake_mac[1] = 0x50;
    fake_mac[2] = rand() % 256;
    fake_mac[3] = rand() % 256;
    fake_mac[4] = rand() % 256;
    fake_mac[5] = rand() % 256;
    LogMsg("InitFakeMac: randomized MAC %02X:%02X:%02X:%02X:%02X:%02X",
           fake_mac[0], fake_mac[1], fake_mac[2], fake_mac[3], fake_mac[4], fake_mac[5]);

    // --- Generate random GUID for SettingID ---
    GUID rndGuid;
    HRESULT hr = CoCreateGuid(&rndGuid);
    if (SUCCEEDED(hr)) {
        // Force version 4 and RFC 4122 variant, just to be 100% sure
        // Byte 7: top 4 bits = version = 4  =>  0 1 0 0
        // Byte 8: top 2 bits = variant = 1 0  (binary 10xx xxxx)
        BYTE* p = (BYTE*)&rndGuid;
        p[7] = (p[7] & 0x0F) | 0x40;   // version 4
        p[8] = (p[8] & 0x3F) | 0x80;   // variant 10xx xxxx

        // Log the GUID and its version
        unsigned char version = (p[7] >> 4) & 0x0F;
        unsigned char variant = (p[8] >> 6) & 0x03;   // 2 = 10, standard
        LogMsg("InitFakeMac: CoCreateGuid returned Version=%d, Variant=%d", version, variant);
    } else {
        // Fallback: manual random generation with version 4
        LogMsg("InitFakeMac: CoCreateGuid failed (0x%08lX), generating manual V4 GUID", hr);
        BYTE* p = (BYTE*)&rndGuid;
        for (int i = 0; i < 16; i++) p[i] = (BYTE)(rand() % 256);
        p[7] = (p[7] & 0x0F) | 0x40;
        p[8] = (p[8] & 0x3F) | 0x80;
    }

    // Convert to string
    wchar_t guidStr[40];
    StringFromGUID2(&rndGuid, guidStr, 40);
    wcscpy(fake_settingID, guidStr);
    LogMsg("InitFakeMac: randomized SettingID %ls", fake_settingID);
    TapClientSetMAC(fake_mac);
// #else
    // if (GetFakeLocalMac(NULL, fake_mac)) {
    //     LogMsg("InitFakeMac: using local MAC %02X:%02X:%02X:%02X:%02X:%02X",
    //            fake_mac[0], fake_mac[1], fake_mac[2], fake_mac[3], fake_mac[4], fake_mac[5]);
    // } else {
    //     LogMsg("InitFakeMac: GetFakeLocalMac failed, keeping default");
    // }
    // SettingID remains default or registry value (if InitFakeSettingID is called later)
    // But since fake_settingID_initialized is set to TRUE, InitFakeSettingID won't run.
    // So we must handle setting SettingID here as well if we want registry value.
    // If we want to keep the registry behavior for non-randomized, we can call GetRadminAdapterIdFromRegistry.
    // Actually, InitFakeSettingID was separate; now we disabled it by setting the flag. We need to still read registry if we want real GUID.
    // if (!GetRadminAdapterIdFromRegistry(fake_settingID, sizeof(fake_settingID))) {
    //     LogMsg("InitFakeMac: Could not read AdapterId from registry, using default");
    // }
// #endif
}

// IWbemClassObject method stubs
HRESULT STDMETHODCALLTYPE FakeWbemClass_QueryInterface(IWbemClassObject *pThis, REFIID riid, void **ppvObj) {
    LogMsg("FakeWbemClass::QueryInterface");

    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IWbemClassObject)) {
        *ppvObj = pThis;
        FakeWbemClass_AddRef(pThis);
        return S_OK;
    }
    *ppvObj = NULL;
    return E_NOINTERFACE;
}
ULONG STDMETHODCALLTYPE FakeWbemClass_AddRef(IWbemClassObject *pThis) {
    LogMsg("FakeWbemClass::AddRef");

    return InterlockedIncrement(&((FakeWbemClassObject*)pThis)->refCount);
}
ULONG STDMETHODCALLTYPE FakeWbemClass_Release(IWbemClassObject *pThis)
{
    FakeWbemClassObject *obj = (FakeWbemClassObject*)pThis;
    LONG ref = obj->refCount;
    if (ref > 1) {
        InterlockedDecrement(&obj->refCount);
    }
    LogMsg("FakeWbemClass::Release (ref=%d)", obj->refCount);
    return obj->refCount;
}

// Returns TRUE if the registry value was read successfully
static BOOL GetRadminAdapterIdFromRegistry(wchar_t *outGuid, DWORD outSize)
{
    HKEY hKey;
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\WOW6432Node\\Famatech\\RadminVPN\\1.0\\Firewall",
        0,
        KEY_READ | KEY_WOW64_32KEY,   // explicitly ask for 32-bit view on 64-bit OS
        &hKey);

    if (result != ERROR_SUCCESS) {
        // Try the non-WOW6432Node path as fallback
        result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Famatech\\RadminVPN\\1.0\\Firewall",
            0,
            KEY_READ,
            &hKey);
    }

    if (result != ERROR_SUCCESS) {
        LogMsg("GetRadminAdapterIdFromRegistry: RegOpenKeyEx failed (error %ld)", result);
        return FALSE;
    }

    DWORD type = REG_SZ;
    result = Real_RegQueryValueExW(hKey, L"AdapterId", NULL, &type, (BYTE*)outGuid, &outSize);

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        LogMsg("GetRadminAdapterIdFromRegistry: RegQueryValueEx failed (error %ld)", result);
        return FALSE;
    }

    if (type != REG_SZ) {
        LogMsg("GetRadminAdapterIdFromRegistry: unexpected type %lu (expected REG_SZ)", type);
        return FALSE;
    }

    LogMsg("GetRadminAdapterIdFromRegistry: found AdapterId = %ls", outGuid);
    return TRUE;
}



HRESULT STDMETHODCALLTYPE FakeWbemClass_Get(IWbemClassObject *pThis, LPCWSTR wszName, LONG lFlags,
                                            VARIANT *pVal, CIMTYPE *pType, LONG *plFlavor)
{
    LogMsg("IWbemClassObject::Get(%ls)", wszName);
    if (!wszName || !pVal) return E_INVALIDARG;
    VariantInit(pVal);
    if (wcscmp(wszName, L"ServiceName") == 0) {
        V_VT(pVal) = VT_BSTR;
        V_BSTR(pVal) = SysAllocString(fake_serviceName);
    } else if (wcscmp(wszName, L"Description") == 0) {
        V_VT(pVal) = VT_BSTR;
        V_BSTR(pVal) = SysAllocString(fake_description);
    } else if (wcscmp(wszName, L"SettingID") == 0) {
        V_VT(pVal) = VT_BSTR;
        // Initialize fake_settingID if not yet done
        if (!fake_settingID_initialized) {
            fake_settingID_initialized = TRUE; // mark first to avoid re-entry
            if (!GetRadminAdapterIdFromRegistry(fake_settingID, sizeof(fake_settingID))) {
                LogMsg("InitFakeSettingID: Could not read AdapterId from registry, using default");
                // fake_settingID already contains the default value
            }
        }
        V_BSTR(pVal) = SysAllocString(fake_settingID);
    } else if (wcscmp(wszName, L"DHCPEnabled") == 0) {
        V_VT(pVal) = VT_BOOL;
        V_BOOL(pVal) = VARIANT_FALSE;
    } else if (wcscmp(wszName, L"IPAddress") == 0) {
        SAFEARRAY *psa = SafeArrayCreateVector(VT_BSTR, 0, 1);
        if (psa) {
            BSTR bstr = SysAllocString(fake_ipAddress);
            LONG idx = 0;
            SafeArrayPutElement(psa, &idx, bstr);
            V_VT(pVal) = VT_ARRAY | VT_BSTR;
            V_ARRAY(pVal) = psa;
        }
    } else if (wcscmp(wszName, L"IPSubnet") == 0) {
        SAFEARRAY *psa = SafeArrayCreateVector(VT_BSTR, 0, 1);
        if (psa) {
            BSTR bstr = SysAllocString(fake_ipSubnet);
            LONG idx = 0;
            SafeArrayPutElement(psa, &idx, bstr);
            V_VT(pVal) = VT_ARRAY | VT_BSTR;
            V_ARRAY(pVal) = psa;
        }
    } else if (wcscmp(wszName, L"DefaultIPGateway") == 0) {
        SAFEARRAY *psa = SafeArrayCreateVector(VT_BSTR, 0, 1);
        if (psa) {
            BSTR bstr = SysAllocString(fake_gateway);
            LONG idx = 0;
            SafeArrayPutElement(psa, &idx, bstr);
            V_VT(pVal) = VT_ARRAY | VT_BSTR;
            V_ARRAY(pVal) = psa;
        }
    } else if (wcscmp(wszName, L"DNSServerSearchOrder") == 0) {
        SAFEARRAY *psa = SafeArrayCreateVector(VT_BSTR, 0, 1);
        if (psa) {
            BSTR bstr = SysAllocString(fake_dns);
            LONG idx = 0;
            SafeArrayPutElement(psa, &idx, bstr);
            V_VT(pVal) = VT_ARRAY | VT_BSTR;
            V_ARRAY(pVal) = psa;
        }
    } else if (wcscmp(wszName, L"MACAddress") == 0) {
        InitFakeMac();
        V_VT(pVal) = VT_BSTR;
        wchar_t macStr[18];
        swprintf(macStr, 18, L"%02X:%02X:%02X:%02X:%02X:%02X",
                fake_mac[0], fake_mac[1], fake_mac[2],
                fake_mac[3], fake_mac[4], fake_mac[5]);
        LogMsg("WMI MACAddress: returning %ls", macStr);
        V_BSTR(pVal) = SysAllocString(macStr);
    } else {
        V_VT(pVal) = VT_NULL;
    }
    if (pType) *pType = CIM_STRING;
    if (plFlavor) *plFlavor = 0;
    return S_OK;
}

// Other methods just return E_NOTIMPL
static HRESULT STDMETHODCALLTYPE Stub_NotImpl(void) { return E_NOTIMPL; }

// IWbemClassObject::GetNames
HRESULT STDMETHODCALLTYPE FakeWbemClass_GetNames(
    IWbemClassObject *pThis,
    LPCWSTR wszQualifierName,
    LONG lFlags,
    VARIANT *pQualifierVal,
    SAFEARRAY **pNames)
{
    LogMsg("FakeWbemClass::GetNames – returning property list");
    static const wchar_t *props[] = {
        L"ServiceName", L"Description", L"SettingID", L"DHCPEnabled",
        L"IPAddress", L"IPSubnet", L"DefaultIPGateway", L"DNSServerSearchOrder",
        L"MACAddress"
    };
    int count = sizeof(props)/sizeof(props[0]);
    SAFEARRAY *sa = SafeArrayCreateVector(VT_BSTR, 0, count);
    if (!sa) return E_OUTOFMEMORY;
    for (int i = 0; i < count; i++) {
        BSTR b = SysAllocString(props[i]);
        LONG idx = i;
        SafeArrayPutElement(sa, &idx, b);
        SysFreeString(b);
    }
    *pNames = sa;
    return S_OK;
}

// IWbemClassObject::BeginEnumeration
HRESULT STDMETHODCALLTYPE FakeWbemClass_BeginEnumeration(
    IWbemClassObject *pThis,
    LONG lEnumFlags)
{
    LogMsg("FakeWbemClass::BeginEnumeration");
    return WBEM_S_NO_ERROR;
}

// IWbemClassObject::Next
HRESULT STDMETHODCALLTYPE FakeWbemClass_Next(
    IWbemClassObject *pThis,
    LONG lFlags,
    BSTR *strName,
    VARIANT *pVal,
    CIMTYPE *pType,
    LONG *plFlavor)
{
    LogMsg("FakeWbemClass::Next – no more properties");
    return WBEM_S_NO_MORE_DATA;
}

// IWbemClassObject::EndEnumeration
HRESULT STDMETHODCALLTYPE FakeWbemClass_EndEnumeration(
    IWbemClassObject *pThis)
{
    LogMsg("FakeWbemClass::EndEnumeration");
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE FakeWbemClass_SafeStub(void) {
    LogMsg("FakeWbemClass stub called – returning S_OK");
    return S_OK;   // ← changed from E_NOTIMPL
}

// ---------- Properly typed stubs for every IWbemClassObject method ----------
#define DEFINE_CLASS_STUB(name, ...) \
static HRESULT STDMETHODCALLTYPE FakeWbemClass_##name(__VA_ARGS__) { \
    LogMsg("FakeWbemClass::" #name " called (E_NOTIMPL)"); \
    return E_NOTIMPL; \
}

DEFINE_CLASS_STUB(GetQualifierSet,   IWbemClassObject *pThis, IWbemQualifierSet **ppQualifierSet)
DEFINE_CLASS_STUB(Put,               IWbemClassObject *pThis, LPCWSTR wszName, LONG lFlags, VARIANT *pVal, CIMTYPE Type)
DEFINE_CLASS_STUB(Delete,            IWbemClassObject *pThis, LPCWSTR wszName)
DEFINE_CLASS_STUB(GetPropertyQualifierSet, IWbemClassObject *pThis, LPCWSTR wszProperty, IWbemQualifierSet **ppQualifierSet)
DEFINE_CLASS_STUB(Clone,              IWbemClassObject *pThis, IWbemClassObject **ppCopy)
DEFINE_CLASS_STUB(GetObjectText,      IWbemClassObject *pThis, LONG lFlags, BSTR *pstrObjectText)
DEFINE_CLASS_STUB(SpawnDerivedClass,  IWbemClassObject *pThis, LONG lFlags, IWbemClassObject **ppNewClass)
DEFINE_CLASS_STUB(SpawnInstance,      IWbemClassObject *pThis, LONG lFlags, IWbemClassObject **ppNewInstance)
DEFINE_CLASS_STUB(CompareTo,          IWbemClassObject *pThis, LONG lFlags, IWbemClassObject *pCompareTo)
DEFINE_CLASS_STUB(GetPropertyOrigin,  IWbemClassObject *pThis, LPCWSTR wszName, BSTR *pstrClassName)
DEFINE_CLASS_STUB(InheritsFrom,       IWbemClassObject *pThis, LPCWSTR strAncestor)
DEFINE_CLASS_STUB(GetMethod,          IWbemClassObject *pThis, LPCWSTR wszName, LONG lFlags, IWbemClassObject **ppInSignature, IWbemClassObject **ppOutSignature)
DEFINE_CLASS_STUB(PutMethod,          IWbemClassObject *pThis, LPCWSTR wszName, LONG lFlags, IWbemClassObject *pInSignature, IWbemClassObject *pOutSignature)
DEFINE_CLASS_STUB(DeleteMethod,       IWbemClassObject *pThis, LPCWSTR wszName)
DEFINE_CLASS_STUB(BeginMethodEnumeration, IWbemClassObject *pThis, LONG lEnumFlags)
DEFINE_CLASS_STUB(NextMethod,         IWbemClassObject *pThis, LONG lFlags, BSTR *pstrName, IWbemClassObject **ppInSignature, IWbemClassObject **ppOutSignature)
DEFINE_CLASS_STUB(EndMethodEnumeration, IWbemClassObject *pThis)
DEFINE_CLASS_STUB(GetMethodQualifierSet, IWbemClassObject *pThis, LPCWSTR wszMethod, IWbemQualifierSet **ppQualifierSet)
DEFINE_CLASS_STUB(PutMethodQualifierSet, IWbemClassObject *pThis, LPCWSTR wszMethod, IWbemQualifierSet *pQualifierSet)
DEFINE_CLASS_STUB(DeleteMethodQualifierSet, IWbemClassObject *pThis, LPCWSTR wszMethod)
// ----- Corrected vtable initialisation -----
static void InitFakeWbemClassObjectVTable(void **vtable) {
    // Fill all 32 slots with a safe stub that matches the method signature.
    // We'll overwrite the ones we implement.
    // To start, set every entry to NULL – we will explicitly assign each.
    memset(vtable, 0, 32 * sizeof(void*));

    // IUnknown
    vtable[0] = &FakeWbemClass_QueryInterface;
    vtable[1] = &FakeWbemClass_AddRef;
    vtable[2] = &FakeWbemClass_Release;

    // IWbemClassObject methods we fully implement (with meaningful behaviour)
    vtable[4]  = &FakeWbemClass_Get;                 // Get (index 4)
    vtable[7]  = &FakeWbemClass_GetNames;            // GetNames
    vtable[8]  = &FakeWbemClass_BeginEnumeration;    // BeginEnumeration
    vtable[9]  = &FakeWbemClass_Next;                // Next
    vtable[10] = &FakeWbemClass_EndEnumeration;      // EndEnumeration

    // All other slots must point to a correctly‑typed stub (not a generic no‑arg)
    vtable[3]  = &FakeWbemClass_GetQualifierSet;              // GetQualifierSet
    vtable[5]  = &FakeWbemClass_Put;                          // Put
    vtable[6]  = &FakeWbemClass_Delete;                       // Delete
    vtable[11] = &FakeWbemClass_GetPropertyQualifierSet;      // GetPropertyQualifierSet
    vtable[12] = &FakeWbemClass_Clone;                        // Clone
    vtable[13] = &FakeWbemClass_GetObjectText;                // GetObjectText
    vtable[14] = &FakeWbemClass_SpawnDerivedClass;            // SpawnDerivedClass
    vtable[15] = &FakeWbemClass_SpawnInstance;                // SpawnInstance
    vtable[16] = &FakeWbemClass_CompareTo;                    // CompareTo
    vtable[17] = &FakeWbemClass_GetPropertyOrigin;            // GetPropertyOrigin
    vtable[18] = &FakeWbemClass_InheritsFrom;                 // InheritsFrom
    vtable[19] = &FakeWbemClass_GetMethod;                    // GetMethod
    vtable[20] = &FakeWbemClass_PutMethod;                    // PutMethod
    vtable[21] = &FakeWbemClass_DeleteMethod;                 // DeleteMethod
    vtable[22] = &FakeWbemClass_BeginMethodEnumeration;       // BeginMethodEnumeration
    vtable[23] = &FakeWbemClass_NextMethod;                   // NextMethod
    vtable[24] = &FakeWbemClass_EndMethodEnumeration;         // EndMethodEnumeration
    vtable[25] = &FakeWbemClass_GetMethodQualifierSet;        // GetMethodQualifierSet
    vtable[26] = &FakeWbemClass_PutMethodQualifierSet;        // PutMethodQualifierSet
    vtable[27] = &FakeWbemClass_DeleteMethodQualifierSet;     // DeleteMethodQualifierSet
    // 28..31 remain NULL – these are beyond the documented interface (unlikely to be called)
}

// ----- Corrected factory function -----
static IWbemClassObject* CreateFakeWbemClassObject(void) {
    static void *vtable[32] = {0};
    static BOOL vtableInit = FALSE;
    if (!vtableInit) {
        InitFakeWbemClassObjectVTable(vtable);
        vtableInit = TRUE;
        LogMsg("FakeWbemClassObject vtable initialized at %p", vtable);
    }

    FakeWbemClassObject *obj = (FakeWbemClassObject*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FakeWbemClassObject));
    if (!obj) {
        LogMsg("ERROR: HeapAlloc for FakeWbemClassObject failed");
        return NULL;
    }
    obj->lpVtbl = vtable;
    obj->refCount = 1;
    LogMsg("FakeWbemClassObject created at %p, vtable=%p", obj, vtable);
    return (IWbemClassObject*)obj;
}

// ------------------------------------------------------------------
// Complete fake IWbemServices vtable with stubs for every method
// ------------------------------------------------------------------

// IUnknown methods for the fake services object
static HRESULT STDMETHODCALLTYPE FakeSvcs_QueryInterface(IWbemServices *pThis, REFIID riid, void **ppvObj) {
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IWbemServices)) {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    *ppvObj = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE FakeSvcs_AddRef(IWbemServices *pThis) {
    return InterlockedIncrement(&((FakeCOMObject*)pThis)->refCount);
}
static ULONG STDMETHODCALLTYPE FakeSvcs_Release(IWbemServices *pThis) {
    LONG ref = InterlockedDecrement(&((FakeCOMObject*)pThis)->refCount);
    if (ref == 0) {
        LogMsg("FakeSvcs_Release – freeing fake services object");
        HeapFree(GetProcessHeap(), 0, pThis);
    }
    return ref;
}

// Generic stub for any method not explicitly implemented
static HRESULT STDMETHODCALLTYPE Stub_NotImpl_Svcs(void) {
    LogMsg("Fake IWbemServices stub called – returning E_NOTIMPL");
    return E_NOTIMPL;
}

// Specific stubs that may need special handling (like OpenNamespace, etc.)
static HRESULT STDMETHODCALLTYPE FakeSvcs_OpenNamespace(IWbemServices *pThis, const BSTR strNamespace,
    LONG lFlags, IWbemContext *pCtx, IWbemServices **ppWorkingNamespace, IWbemCallResult **ppResult)
{
    LogMsg("FakeSvcs::OpenNamespace(%ls) – returning E_NOTIMPL", strNamespace);
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE FakeSvcs_CancelAsyncCall(IWbemServices *pThis, IWbemObjectSink *pSink) {
    LogMsg("FakeSvcs::CancelAsyncCall – returning S_OK");
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FakeSvcs_QueryObjectSink(IWbemServices *pThis, LONG lFlags, IWbemObjectSink **ppSink) {
    LogMsg("FakeSvcs::QueryObjectSink – returning E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE FakeSvcs_GetObjectAsync(IWbemServices *pThis, const BSTR strObjectPath,
    LONG lFlags, IWbemContext *pCtx, IWbemObjectSink *pSink) {
    LogMsg("FakeSvcs::GetObjectAsync(%ls) – returning E_NOTIMPL", strObjectPath);
    return E_NOTIMPL;
}

static void* g_fakeWbemServicesVtable[26] = {0};

// ------------------------------------------------------------------
// Fake IEnumWbemClassObject – yields exactly one object then stops
// ------------------------------------------------------------------
typedef struct {
    void *lpVtbl;
    LONG refCount;
    IWbemClassObject *fakeObject;
    BOOL alreadyReturned;
} FakeEnumWbemClassObject;

static void* g_fakeEnumWbemVtable[8] = {0};

static HRESULT STDMETHODCALLTYPE FakeEnumWbem_QueryInterface(IEnumWbemClassObject *pThis, REFIID riid, void **ppvObj) {
    // Log the IID as a string
    OLECHAR szIID[64];
    StringFromGUID2(riid, szIID, 64);
    LogMsg("FakeEnumWbem_QueryInterface: IID=%ls", szIID);
    if (IsEqualIID(riid, &IID_IEnumVARIANT)) {
        // IEnumVARIANT has the same vtable layout as IEnumWbemClassObject
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IEnumWbemClassObject)) {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    *ppvObj = NULL;
    LogMsg("  -> Unsupported interface, returning E_NOINTERFACE");
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE FakeEnumWbem_AddRef(IEnumWbemClassObject *pThis) {
    return InterlockedIncrement(&((FakeEnumWbemClassObject*)pThis)->refCount);
}
static ULONG STDMETHODCALLTYPE FakeEnumWbem_Release(IEnumWbemClassObject *pThis) {
    FakeEnumWbemClassObject *e = (FakeEnumWbemClassObject*)pThis;
    LONG ref = InterlockedDecrement(&e->refCount);
    if (ref == 0) {
        if (e->fakeObject) e->fakeObject->lpVtbl->Release(e->fakeObject);
        HeapFree(GetProcessHeap(), 0, e);
    }
    return ref;
}
static HRESULT STDMETHODCALLTYPE FakeEnumWbem_Next(IEnumWbemClassObject *pThis, LONG lTimeout, ULONG celt,
                                                   IWbemClassObject **ppObjects, ULONG *pcReturned) {
                                                    LogMsg("FakeEnumWbem_Next called: celt=%u", celt);
    FakeEnumWbemClassObject *e = (FakeEnumWbemClassObject*)pThis;
    if (!e->alreadyReturned && celt >= 1) {
        *ppObjects = e->fakeObject;
        e->fakeObject->lpVtbl->AddRef(e->fakeObject);
        if (pcReturned) *pcReturned = 1;
        e->alreadyReturned = TRUE;
        return WBEM_S_NO_ERROR;
    }
    if (pcReturned) *pcReturned = 0;
    return WBEM_S_FALSE;
}
static HRESULT STDMETHODCALLTYPE FakeEnumWbem_NextAsync(
    IEnumWbemClassObject *pThis,
    ULONG uCount,
    IWbemObjectSink *pSink)
{
    LogMsg("FakeEnumWbem::NextAsync called (uCount=%u) – returning WBEM_S_FALSE", uCount);
    return WBEM_S_FALSE;
}
static HRESULT STDMETHODCALLTYPE FakeEnumWbem_Reset(IEnumWbemClassObject *pThis) {
    LogMsg("FakeEnumWbem::Reset called");
    ((FakeEnumWbemClassObject*)pThis)->alreadyReturned = FALSE;
    return WBEM_S_NO_ERROR;
}

static HRESULT STDMETHODCALLTYPE FakeEnumWbem_Skip(IEnumWbemClassObject *pThis, LONG lTimeout, ULONG nCount) {
    LogMsg("FakeEnumWbem::Skip called (lTimeout=%d, nCount=%u)", lTimeout, nCount);
    return WBEM_S_FALSE;
}

static HRESULT STDMETHODCALLTYPE FakeEnumWbem_Clone(IEnumWbemClassObject *pThis, IEnumWbemClassObject **ppEnum) {
    LogMsg("FakeEnumWbem::Clone called – returning E_NOTIMPL");
    if (ppEnum) *ppEnum = NULL;
    return E_NOTIMPL;
}

static void InitFakeEnumWbemVtable(void) {
    if (g_fakeEnumWbemVtable[0]) return;

    g_fakeEnumWbemVtable[0] = &FakeEnumWbem_QueryInterface;   // QueryInterface
    g_fakeEnumWbemVtable[1] = &FakeEnumWbem_AddRef;
    g_fakeEnumWbemVtable[2] = &FakeEnumWbem_Release;
    g_fakeEnumWbemVtable[3] = &FakeEnumWbem_Reset;            // Reset
    g_fakeEnumWbemVtable[4] = &FakeEnumWbem_Next;             // Next
    g_fakeEnumWbemVtable[5] = &FakeEnumWbem_NextAsync;        // NextAsync
    g_fakeEnumWbemVtable[6] = &FakeEnumWbem_Clone;            // Clone
    g_fakeEnumWbemVtable[7] = &FakeEnumWbem_Skip;             // Skip
}

static IEnumWbemClassObject* CreateFakeEnumWbemClassObject(IWbemClassObject *fakeObject) {
    InitFakeEnumWbemVtable();
    FakeEnumWbemClassObject *e = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*e));
    if (!e) return NULL;
    e->lpVtbl = g_fakeEnumWbemVtable;
    e->refCount = 1;
    e->fakeObject = fakeObject;
    e->alreadyReturned = FALSE;
    fakeObject->lpVtbl->AddRef(fakeObject);
    return (IEnumWbemClassObject*)e;
}

static HRESULT STDMETHODCALLTYPE FakeSvcs_CreateInstanceEnum(IWbemServices *pThis,
    const BSTR strFilter, LONG lFlags, IWbemContext *pCtx, IEnumWbemClassObject **ppEnum)
{
    LogMsg("FakeSvcs::CreateInstanceEnum(%ls)", strFilter);
    *ppEnum = NULL;
    if (strFilter && _wcsicmp(strFilter, L"Win32_NetworkAdapterConfiguration") == 0) {
        IWbemClassObject *fakeObj = CreateFakeWbemClassObject();
        if (!fakeObj) return E_OUTOFMEMORY;
        *ppEnum = CreateFakeEnumWbemClassObject(fakeObj);
        fakeObj->lpVtbl->Release(fakeObj);
        return (*ppEnum) ? WBEM_S_NO_ERROR : E_OUTOFMEMORY;
    }
    if (strFilter && _wcsicmp(strFilter, L"Win32_NetworkAdapter") == 0) {
        // For unqualified query, we would need a GUID, so return empty to be safe
        *ppEnum = NULL;
        return WBEM_S_FALSE;
    }
    return WBEM_S_FALSE;
}

// Extract GUID from "SELECT * FROM Win32_NetworkAdapter WHERE GUID='{...}'"
static BSTR ExtractGuidFromQuery(const BSTR strQuery) {
    if (!strQuery) return NULL;
    const wchar_t *prefix = L"GUID='";
    const wchar_t *start = wcsstr(strQuery, prefix);
    if (!start) return NULL;
    start += wcslen(prefix);
    const wchar_t *end = wcschr(start, L'\'');
    if (!end) return NULL;
    size_t len = end - start;
    BSTR guid = SysAllocStringLen(start, (UINT)len);
    return guid;
}

static IWbemClassObject* CreateFakeNetAdapterObject(BSTR guid);

static HRESULT STDMETHODCALLTYPE FakeSvcs_ExecQuery(IWbemServices *pThis,
    const BSTR strQueryLanguage, const BSTR strQuery, LONG lFlags,
    IWbemContext *pCtx, IEnumWbemClassObject **ppEnum)
{
    LogMsg("FakeSvcs::ExecQuery(%ls)", strQuery ? strQuery : L"(null)");
    *ppEnum = NULL;

    if (!strQuery) return WBEM_S_FALSE;

    // Check for Win32_NetworkAdapterConfiguration
    if (wcsstr(strQuery, L"Win32_NetworkAdapter")) {
        BSTR guid = ExtractGuidFromQuery(strQuery);

        // If a specific GUID is requested, check it against our adapter
        if (guid) {
            // Normalize to include braces for comparison
            wchar_t queryGuid[64];
            if (guid[0] != L'{') {
                swprintf(queryGuid, 64, L"{%ls}", guid);
            } else {
                wcscpy(queryGuid, guid);
            }

            if (_wcsicmp(queryGuid, fake_settingID) != 0) {
                // GUID does NOT match – return empty
                LogMsg("  -> GUID mismatch (query=%ls, our=%ls), returning empty",
                    queryGuid, fake_settingID);
                SysFreeString(guid);
                *ppEnum = NULL;
                return WBEM_S_FALSE;
            }
            SysFreeString(guid);
        }

        // No GUID filter, or it matches – return our fake adapter object
        IWbemClassObject *fakeObj = CreateFakeNetAdapterObject(fake_settingID);
        if (!fakeObj) return E_OUTOFMEMORY;
        *ppEnum = CreateFakeEnumWbemClassObject(fakeObj);
        fakeObj->lpVtbl->Release(fakeObj);
        return (*ppEnum) ? WBEM_S_NO_ERROR : E_OUTOFMEMORY;
    }

    // Check for Win32_NetworkAdapter with GUID filter
    if (wcsstr(strQuery, L"Win32_NetworkAdapter")) {
        BSTR guid = ExtractGuidFromQuery(strQuery);
        // If no GUID in query, still return a default adapter (with a placeholder GUID)
        IWbemClassObject *fakeObj = CreateFakeNetAdapterObject(guid ? guid : L"{00000000-0000-0000-0000-000000000000}");
        SysFreeString(guid);
        if (!fakeObj) return E_OUTOFMEMORY;
        *ppEnum = CreateFakeEnumWbemClassObject(fakeObj);
        fakeObj->lpVtbl->Release(fakeObj);
        return (*ppEnum) ? WBEM_S_NO_ERROR : E_OUTOFMEMORY;
    }

    return WBEM_S_FALSE;
}

typedef struct {
    void *lpVtbl;
    LONG refCount;
    BSTR guid;          // stored GUID to return
} FakeNetAdapterObject;

static void* g_fakeNetAdapterVtable[32] = {0};

static ULONG STDMETHODCALLTYPE FakeNetAdapter_AddRef(IWbemClassObject *pThis) {
    return InterlockedIncrement(&((FakeNetAdapterObject*)pThis)->refCount);
}
static HRESULT STDMETHODCALLTYPE FakeNetAdapter_QueryInterface(IWbemClassObject *pThis, REFIID riid, void **ppvObj) {
    OLECHAR szIID[64];
    StringFromGUID2(riid, szIID, 64);
    LogMsg("FakeNetAdapter::QI(%ls)", szIID);

    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IWbemClassObject)) {
        *ppvObj = pThis;
        FakeNetAdapter_AddRef(pThis);
        LogMsg("  -> S_OK");
        return S_OK;
    }
    LogMsg("  -> E_NOINTERFACE");
    *ppvObj = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE FakeNetAdapter_Release(IWbemClassObject *pThis) {
    FakeNetAdapterObject *obj = (FakeNetAdapterObject*)pThis;
    LONG ref = InterlockedDecrement(&obj->refCount);
    if (ref == 0) {
        SysFreeString(obj->guid);
        HeapFree(GetProcessHeap(), 0, obj);
    }
    return ref;
}

static HRESULT STDMETHODCALLTYPE FakeNetAdapter_Get(
    IWbemClassObject *pThis, LPCWSTR wszName, LONG lFlags,
    VARIANT *pVal, CIMTYPE *pType, LONG *plFlavor)
{
    LogMsg("FakeNetAdapter::Get(%ls)", wszName);
    FakeNetAdapterObject *obj = (FakeNetAdapterObject*)pThis;
    VariantInit(pVal);

    if (wcscmp(wszName, L"GUID") == 0) {
        V_VT(pVal) = VT_BSTR;
        V_BSTR(pVal) = SysAllocString(obj->guid ? obj->guid : L"{00000000-0000-0000-0000-000000000000}");        
    }
    else if (wcscmp(wszName, L"ServiceName") == 0) {
        V_VT(pVal) = VT_BSTR;
        V_BSTR(pVal) = SysAllocString(fake_serviceName);
    }
    else if (wcscmp(wszName, L"MACAddress") == 0) {
        V_VT(pVal) = VT_BSTR;
        wchar_t macStr[18];
        InitFakeMac();
        swprintf(macStr, 18, L"%02X:%02X:%02X:%02X:%02X:%02X",
                fake_mac[0], fake_mac[1], fake_mac[2],
                fake_mac[3], fake_mac[4], fake_mac[5]);
        LogMsg("WMI MACAddress: returning %ls", macStr);
        V_BSTR(pVal) = SysAllocString(macStr);
    }
    else if (wcscmp(wszName, L"Index") == 0) {
        V_VT(pVal) = VT_I4;
        V_I4(pVal) = 1;
    }
    else if (wcscmp(wszName, L"Name") == 0) {
        V_VT(pVal) = VT_BSTR;
        V_BSTR(pVal) = SysAllocString(fake_FriendlyName);
    }
    else if (wcscmp(wszName, L"PNPDeviceID") == 0) {
        V_VT(pVal) = VT_BSTR;
        V_BSTR(pVal) = SysAllocString(L"ROOT\\NET\\0000");
    }
    else if (wcscmp(wszName, L"SettingID") == 0) {
        V_VT(pVal) = VT_BSTR;
        V_BSTR(pVal) = SysAllocString(fake_settingID);
    }
    else if (wcscmp(wszName, L"DeviceID") == 0) {
        // DeviceID must be the GUID with curly braces
        V_VT(pVal) = VT_BSTR;
        V_BSTR(pVal) = SysAllocString(obj->guid ? obj->guid : L"{00000000-0000-0000-0000-000000000000}");
    }
    else if (wcscmp(wszName, L"__PATH") == 0) {
        // Construct the full WMI object path
        const wchar_t *guid = obj->guid ? obj->guid : L"{00000000-0000-0000-0000-000000000000}";
        wchar_t path[256];
        _snwprintf(path, 255, L"\\\\localhost\\ROOT\\CIMV2:Win32_NetworkAdapter.DeviceID=\"%s\"", guid);
        V_VT(pVal) = VT_BSTR;
        V_BSTR(pVal) = SysAllocString(path);
    } else if (wcscmp(wszName, L"NetEnabled") == 0) {
    V_VT(pVal) = VT_BOOL;
    V_BOOL(pVal) = VARIANT_TRUE;
}
    else if (wcscmp(wszName, L"NetConnectionStatus") == 0) {
        V_VT(pVal) = VT_I4;
        V_I4(pVal) = 2;   // 2 = Connected
    }
    else if (wcscmp(wszName, L"ConfigManagerErrorCode") == 0) {
        V_VT(pVal) = VT_I4;
        V_I4(pVal) = 0;   // Device working properly
    }
    else if (wcscmp(wszName, L"Status") == 0) {
        V_VT(pVal) = VT_BSTR;
        V_BSTR(pVal) = SysAllocString(L"OK");
    }
    else if (wcscmp(wszName, L"Availability") == 0) {
        V_VT(pVal) = VT_I4;
        V_I4(pVal) = 3;   // Running/Full Power
    }
    else if (wcscmp(wszName, L"NetConnectionID") == 0) {
        V_VT(pVal) = VT_BSTR;
        V_BSTR(pVal) = SysAllocString(fake_FriendlyName);  // must match the interface name it tries to enable
    }
    else {
        V_VT(pVal) = VT_NULL;
    }
    return S_OK;
}
// All other IWbemClassObject methods use the same stubs as the configuration object
static void InitFakeNetAdapterVtable(void) {
    if (g_fakeNetAdapterVtable[0]) return;
    memcpy(g_fakeNetAdapterVtable, g_dummyVtable, 3 * sizeof(void*)); // IUnknown
    g_fakeNetAdapterVtable[4] = &FakeNetAdapter_Get;   // index 4 is Get
    // The rest we fill with the same stubs used for the configuration object
    for (int i = 0; i < 32; i++) {
        if (!g_fakeNetAdapterVtable[i])
            g_fakeNetAdapterVtable[i] = &FakeWbemClass_SafeStub; // use existing stub
    }
}
static IWbemClassObject* CreateFakeNetAdapterObject(BSTR guid) {
    InitFakeNetAdapterVtable();
    FakeNetAdapterObject *obj = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*obj));
    if (!obj) return NULL;
    obj->lpVtbl = g_fakeNetAdapterVtable;
    obj->refCount = 1;
    obj->guid = SysAllocString(guid ? guid : L"{00000000-0000-0000-0000-000000000000}");
    return (IWbemClassObject*)obj;
}


HRESULT STDMETHODCALLTYPE FakeSvcs_ExecMethod(
    IWbemServices *pThis,
    const BSTR strObjectPath,
    const BSTR strMethodName,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemClassObject *pInParams,
    IWbemClassObject **ppOutParams,
    IWbemCallResult **ppCallResult)
{
    LogMsg("FakeSvcs::ExecMethod(%ls, %ls)", strObjectPath, strMethodName);

    // Handle Win32_NetworkAdapter methods (Enable/Disable)
    if (wcsstr(strObjectPath, L"Win32_NetworkAdapter"))
    {
        if (strMethodName)
        {
            if (_wcsicmp(strMethodName, L"Enable") == 0 || _wcsicmp(strMethodName, L"EnableDevice") == 0)
            {
                LogMsg("  -> Enabling adapter, setting status to NCS_CONNECTED");
                g_FakeConnectionStatus = NCS_CONNECTED;
            }
            else if (_wcsicmp(strMethodName, L"Disable") == 0 || _wcsicmp(strMethodName, L"DisableDevice") == 0)
            {
                LogMsg("  -> Disabling adapter, setting status to NCS_DISCONNECTED");
                g_FakeConnectionStatus = NCS_DISCONNECTED;
            }
        }
        if (ppOutParams) *ppOutParams = NULL;
        if (ppCallResult) *ppCallResult = NULL;
        return WBEM_S_NO_ERROR;
    }

    if (wcsstr(strObjectPath, L"Win32_NetworkAdapterConfiguration"))
    {
        if (ppOutParams) *ppOutParams = NULL;
        if (ppCallResult) *ppCallResult = NULL;
        return WBEM_S_NO_ERROR;
    }

    // For any other classes, succeed silently
    if (ppOutParams) *ppOutParams = NULL;
    if (ppCallResult) *ppCallResult = NULL;
    return WBEM_S_NO_ERROR;
}

/* ------------------------------------------------------------------
 * Correctly‑typed stubs for every IWbemServices method
 * (from wbemcli.h: IWbemServicesVtbl).
 * Unused methods return E_NOTIMPL safely without stack corruption.
 * ------------------------------------------------------------------ */

// IUnknown methods already implemented: FakeSvcs_QueryInterface, FakeSvcs_AddRef, FakeSvcs_Release.

static HRESULT STDMETHODCALLTYPE Stub_OpenNamespace(IWbemServices *pThis, const BSTR strNamespace, LONG lFlags, IWbemContext *pCtx, IWbemServices **ppWorkingNamespace, IWbemCallResult **ppResult) {
    LogMsg("FakeSvcs::OpenNamespace(%ls) – E_NOTIMPL", strNamespace);
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_CancelAsyncCall(IWbemServices *pThis, IWbemObjectSink *pSink) {
    LogMsg("FakeSvcs::CancelAsyncCall");
    return S_OK;   // safe to succeed
}
static HRESULT STDMETHODCALLTYPE Stub_QueryObjectSink(IWbemServices *pThis, LONG lFlags, IWbemObjectSink **ppResponseHandler) {
    LogMsg("FakeSvcs::QueryObjectSink");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_GetObjectAsync(IWbemServices *pThis, const BSTR strObjectPath, LONG lFlags, IWbemContext *pCtx, IWbemObjectSink *pResponseHandler) {
    LogMsg("FakeSvcs::GetObjectAsync(%ls)", strObjectPath);
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_PutClass(IWbemServices *pThis, IWbemClassObject *pObject, LONG lFlags, IWbemContext *pCtx, IWbemCallResult **ppCallResult) {
    LogMsg("FakeSvcs::PutClass");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_PutClassAsync(IWbemServices *pThis, IWbemClassObject *pObject, LONG lFlags, IWbemContext *pCtx, IWbemObjectSink *pResponseHandler) {
    LogMsg("FakeSvcs::PutClassAsync");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_DeleteClass(IWbemServices *pThis, const BSTR strClass, LONG lFlags, IWbemContext *pCtx, IWbemCallResult **ppCallResult) {
    LogMsg("FakeSvcs::DeleteClass(%ls)", strClass);
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_DeleteClassAsync(IWbemServices *pThis, const BSTR strClass, LONG lFlags, IWbemContext *pCtx, IWbemObjectSink *pResponseHandler) {
    LogMsg("FakeSvcs::DeleteClassAsync(%ls)", strClass);
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_CreateClassEnum(IWbemServices *pThis, const BSTR strSuperclass, LONG lFlags, IWbemContext *pCtx, IEnumWbemClassObject **ppEnum) {
    LogMsg("FakeSvcs::CreateClassEnum(%ls)", strSuperclass);
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_CreateClassEnumAsync(IWbemServices *pThis, const BSTR strSuperclass, LONG lFlags, IWbemContext *pCtx, IWbemObjectSink *pResponseHandler) {
    LogMsg("FakeSvcs::CreateClassEnumAsync(%ls)", strSuperclass);
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_PutInstance(IWbemServices *pThis, IWbemClassObject *pInst, LONG lFlags, IWbemContext *pCtx, IWbemCallResult **ppCallResult) {
    LogMsg("FakeSvcs::PutInstance");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_PutInstanceAsync(IWbemServices *pThis, IWbemClassObject *pInst, LONG lFlags, IWbemContext *pCtx, IWbemObjectSink *pResponseHandler) {
    LogMsg("FakeSvcs::PutInstanceAsync");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_DeleteInstance(IWbemServices *pThis, const BSTR strObjectPath, LONG lFlags, IWbemContext *pCtx, IWbemCallResult **ppCallResult) {
    LogMsg("FakeSvcs::DeleteInstance(%ls)", strObjectPath);
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_DeleteInstanceAsync(IWbemServices *pThis, const BSTR strObjectPath, LONG lFlags, IWbemContext *pCtx, IWbemObjectSink *pResponseHandler) {
    LogMsg("FakeSvcs::DeleteInstanceAsync(%ls)", strObjectPath);
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_CreateInstanceEnumAsync(IWbemServices *pThis, const BSTR strFilter, LONG lFlags, IWbemContext *pCtx, IWbemObjectSink *pResponseHandler) {
    LogMsg("FakeSvcs::CreateInstanceEnumAsync(%ls)", strFilter);
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_ExecQueryAsync(IWbemServices *pThis, const BSTR strQueryLanguage, const BSTR strQuery, LONG lFlags, IWbemContext *pCtx, IWbemObjectSink *pResponseHandler) {
    LogMsg("FakeSvcs::ExecQueryAsync");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_ExecNotificationQuery(IWbemServices *pThis, const BSTR strQueryLanguage, const BSTR strQuery, LONG lFlags, IWbemContext *pCtx, IEnumWbemClassObject **ppEnum) {
    LogMsg("FakeSvcs::ExecNotificationQuery");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_ExecNotificationQueryAsync(IWbemServices *pThis, const BSTR strQueryLanguage, const BSTR strQuery, LONG lFlags, IWbemContext *pCtx, IWbemObjectSink *pResponseHandler) {
    LogMsg("FakeSvcs::ExecNotificationQueryAsync");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE Stub_ExecMethodAsync(IWbemServices *pThis, const BSTR strObjectPath, const BSTR strMethodName, LONG lFlags, IWbemContext *pCtx, IWbemClassObject *pInParams, IWbemObjectSink *pResponseHandler) {
    LogMsg("FakeSvcs::ExecMethodAsync(%ls, %ls)", strObjectPath, strMethodName);
    return E_NOTIMPL;
}

/* ------------------------------------------------------------------
 * Initialize the fake IWbemServices vtable with all 26 methods.
 * ------------------------------------------------------------------ */
static void InitFakeWbemServicesVtable(void) {
    if (g_fakeWbemServicesVtable[0]) return;

    g_fakeWbemServicesVtable[0]  = &FakeSvcs_QueryInterface;
    g_fakeWbemServicesVtable[1]  = &FakeSvcs_AddRef;
    g_fakeWbemServicesVtable[2]  = &FakeSvcs_Release;
    g_fakeWbemServicesVtable[3]  = &Stub_OpenNamespace;
    g_fakeWbemServicesVtable[4]  = &Stub_CancelAsyncCall;
    g_fakeWbemServicesVtable[5]  = &Stub_QueryObjectSink;
    g_fakeWbemServicesVtable[6]  = &Hook_IWbemServices_GetObject;   // our custom GetObject
    g_fakeWbemServicesVtable[7]  = &Stub_GetObjectAsync;
    g_fakeWbemServicesVtable[8]  = &Stub_PutClass;
    g_fakeWbemServicesVtable[9]  = &Stub_PutClassAsync;
    g_fakeWbemServicesVtable[10] = &Stub_DeleteClass;
    g_fakeWbemServicesVtable[11] = &Stub_DeleteClassAsync;
    g_fakeWbemServicesVtable[12] = &Stub_CreateClassEnum;
    g_fakeWbemServicesVtable[13] = &Stub_CreateClassEnumAsync;
    g_fakeWbemServicesVtable[14] = &Stub_PutInstance;
    g_fakeWbemServicesVtable[15] = &Stub_PutInstanceAsync;
    g_fakeWbemServicesVtable[16] = &Stub_DeleteInstance;
    g_fakeWbemServicesVtable[17] = &Stub_DeleteInstanceAsync;
    g_fakeWbemServicesVtable[18] = &FakeSvcs_CreateInstanceEnum;   // custom enum creator
    g_fakeWbemServicesVtable[19] = &Stub_CreateInstanceEnumAsync;
    g_fakeWbemServicesVtable[20] = &FakeSvcs_ExecQuery;            // custom query
    g_fakeWbemServicesVtable[21] = &Stub_ExecQueryAsync;
    g_fakeWbemServicesVtable[22] = &Stub_ExecNotificationQuery;
    g_fakeWbemServicesVtable[23] = &Stub_ExecNotificationQueryAsync;
    g_fakeWbemServicesVtable[24] = &FakeSvcs_ExecMethod;           // custom ExecMethod (vtable index 24)
    g_fakeWbemServicesVtable[25] = &Stub_ExecMethodAsync;
}

// ------------------------------------------------------------------
// Log adapter details from a *real* IWbemServices (not fake).
// Called right after the real ConnectServer succeeds.
// ------------------------------------------------------------------
void LogAllRealAdapterDetailsFromServices(IWbemServices *pSvc)
{
    HRESULT hr;
    IEnumWbemClassObject *pEnum = NULL;
    BSTR bstrWQL = SysAllocString(L"WQL");
    BSTR bstrQuery = SysAllocString(L"SELECT * FROM Win32_NetworkAdapter");

    // IWbemServices::ExecQuery (vtable index 20)
    hr = ((HRESULT (__stdcall *)(IWbemServices*, const BSTR, const BSTR, LONG,
                                 IWbemContext*, IEnumWbemClassObject**))
          (*(void***)pSvc)[20])
        (pSvc, bstrWQL, bstrQuery, 0x30, NULL, &pEnum);

    SysFreeString(bstrWQL);
    SysFreeString(bstrQuery);
    if (FAILED(hr) || !pEnum) {
        LogMsg("LogAdapters: ExecQuery failed 0x%08lX", hr);
        return;
    }

    IWbemClassObject *apObjects[10];
    ULONG uReturned = 0;
    ULONG idx = 0;

    // IEnumWbemClassObject::Next (vtable index 4)
    while (((HRESULT (__stdcall *)(IEnumWbemClassObject*, LONG, ULONG,
                                    IWbemClassObject**, ULONG*))
            (*(void***)pEnum)[4])(pEnum, 10000, 1, apObjects, &uReturned) == S_OK)
    {
        if (uReturned == 1 && apObjects[0]) {
            idx++;
            VARIANT v;
            VariantInit(&v);

            // IWbemClassObject::Get (vtable index 4)
            #define WbemObj_Get(p, name, pv) \
                ((HRESULT (__stdcall *)(IWbemClassObject*, LPCWSTR, LONG, VARIANT*, LONG*, LONG*)) \
                 (*(void***)p)[4])((p), (name), 0, (pv), NULL, NULL)

            hr = WbemObj_Get(apObjects[0], L"ServiceName", &v);
            if (SUCCEEDED(hr) && V_VT(&v) == VT_BSTR)
                LogMsg("[Adapter %lu] ServiceName: %ls", idx, V_BSTR(&v));
            else
                LogMsg("[Adapter %lu] ServiceName: (unavailable)", idx);
            VariantClear(&v);

            hr = WbemObj_Get(apObjects[0], L"MACAddress", &v);
            if (SUCCEEDED(hr) && V_VT(&v) == VT_BSTR)
                LogMsg("          MACAddress : %ls", V_BSTR(&v));
            else
                LogMsg("          MACAddress : (unavailable)");
            VariantClear(&v);

            hr = WbemObj_Get(apObjects[0], L"SettingID", &v);
            if (SUCCEEDED(hr) && V_VT(&v) == VT_BSTR)
                LogMsg("          SettingID  : %ls", V_BSTR(&v));
            else
                LogMsg("          SettingID  : (unavailable)");
            VariantClear(&v);

            // IUnknown::Release (vtable index 2)
            ((ULONG (__stdcall *)(IWbemClassObject*)) (*(void***)apObjects[0])[2])(apObjects[0]);
        }
    }

    // IEnumWbemClassObject::Release (vtable index 2)
    ((ULONG (__stdcall *)(IEnumWbemClassObject*)) (*(void***)pEnum)[2])(pEnum);

    LogMsg("=== Real adapter enumeration complete ===");
}

static HRESULT STDMETHODCALLTYPE Hook_IWbemLocator_ConnectServer(
    IWbemLocator *pThis,
    const BSTR strNetworkResource, const BSTR strUser,
    const BSTR strPassword, const BSTR strLocale,
    LONG lSecurityFlags, const BSTR strAuthority,
    IWbemContext *pCtx, IWbemServices **ppNamespace)
{
    LogMsg("IWbemLocator::ConnectServer(%ls)", strNetworkResource);

    // For fake locator (BLOCK_REAL 1), fall back to the old code
    if (Real_IWbemLocator_ConnectServer == NULL) {
        LogMsg("  -> fake locator, creating fake IWbemServices");
        IUnknown *fakeServices = CreateFakeCOMObject();
        if (!fakeServices) return E_OUTOFMEMORY;
        InitFakeWbemServicesVtable();
        *(void***)fakeServices = g_fakeWbemServicesVtable;
        *ppNamespace = (IWbemServices*)fakeServices;
        return S_OK;
    }

    // BLOCK_REAL 0: use real ConnectServer, then wrap the result
    HRESULT hr = Real_IWbemLocator_ConnectServer(
        pThis, strNetworkResource, strUser, strPassword,
        strLocale, lSecurityFlags, strAuthority, pCtx, ppNamespace);
    LogMsg("  -> real ConnectServer returned 0x%08lX, ppNamespace=%p",
           hr, ppNamespace ? *ppNamespace : NULL);

           if (SUCCEEDED(hr) && ppNamespace && *ppNamespace) {
               // Wrap the real service with our proxy (no vtable patching!)
               *ppNamespace = CreateProxyWbemServices(*ppNamespace);
               if (!*ppNamespace) return E_OUTOFMEMORY;
               LogMsg("  -> real service wrapped in proxy");
               LogAllRealAdapterDetailsFromServices(*ppNamespace);
    }
    return hr;
}

// Patch the locator when created
static void PatchWbemLocator(IWbemLocator *pLocator)
{
    void **vtable = *(void***)pLocator;

    // Save the real ConnectServer method (index 3)
    Real_IWbemLocator_ConnectServer = (IWbemLocator_ConnectServer_t)vtable[3];

    static void *patchedLocatorVtable[8];
    memcpy(patchedLocatorVtable, vtable, sizeof(patchedLocatorVtable));

    patchedLocatorVtable[0] = &FakeWbemLocator_QueryInterface;   // <-- kept for proper QI
    patchedLocatorVtable[3] = &Hook_IWbemLocator_ConnectServer;

    *(void***)pLocator = patchedLocatorVtable;
    LogMsg("Patched IWbemLocator vtable (real locator with saved ConnectServer)");
}

/* ===================================================================
 * Network Configuration hooks – fake INetCfg component
 * =================================================================== */
// Forward declarations for fake component/enumerator
typedef HRESULT (STDMETHODCALLTYPE *INetCfg_EnumComponents_t)(INetCfg *pThis, const GUID *pguidClass,
    IEnumNetCfgComponent **ppenumComponent);
static INetCfg_EnumComponents_t Real_INetCfg_EnumComponents = NULL;

// Fake IEnumNetCfgComponent that inserts a fake component
typedef struct {
    void *lpVtbl;
    LONG refCount;
    IEnumNetCfgComponent *realEnum;
    INetCfgComponent *fakeComponent;
    BOOL fakeReturned;
} FakeComponentEnumerator;

// The fake Radmin component object
typedef struct {
    void *lpVtbl;
    LONG refCount;
    INetCfgComponentBindings *bindings;  // we'll create a fake bindings object
} FakeNetCfgComponent;

// Fake INetCfgComponentBindings (empty, just needs EnumBindingPaths)
typedef struct {
    void *lpVtbl;
    LONG refCount;
} FakeComponentBindings;

// Global vtables
static void* g_FakeEnumVtable[7] = {0};
static void* g_FakeComponentVtable[32] = {0};
static void* g_FakeBindingsVtable[16] = {0};

// --- FakeNetCfgComponent methods ---
HRESULT STDMETHODCALLTYPE FakeComponent_QueryInterface(INetCfgComponent *pThis, REFIID riid, void **ppvObj) {
    FakeNetCfgComponent *comp = (FakeNetCfgComponent*)pThis;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_INetCfgComponent)) {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    } else if (IsEqualIID(riid, &IID_INetCfgComponentBindings)) {
        *ppvObj = comp->bindings;
        ((IUnknown*)comp->bindings)->lpVtbl->AddRef((IUnknown*)comp->bindings);
        return S_OK;
    } else if (IsEqualIID(riid, &IID_INetConnection)) {
        // Create a fake INetConnection on demand
        INetConnection *conn = CreateFakeNetConnection();
        if (!conn) return E_OUTOFMEMORY;
        *ppvObj = conn;
        return S_OK;
    }
    *ppvObj = NULL;
    return E_NOINTERFACE;
}
ULONG STDMETHODCALLTYPE FakeComponent_AddRef(INetCfgComponent *pThis) {
    return InterlockedIncrement(&((FakeNetCfgComponent*)pThis)->refCount);
}
ULONG STDMETHODCALLTYPE FakeComponent_Release(INetCfgComponent *pThis) {
    FakeNetCfgComponent *c = (FakeNetCfgComponent*)pThis;
    LONG ref = InterlockedDecrement(&c->refCount);
    if (ref == 0) {
        if (c->bindings) ((IUnknown*)c->bindings)->lpVtbl->Release((IUnknown*)c->bindings);
        HeapFree(GetProcessHeap(), 0, c);
    }
    return ref;
}
HRESULT STDMETHODCALLTYPE FakeComponent_GetDisplayName(INetCfgComponent *pThis, LPWSTR *ppszwDisplayName) {
    LogMsg("FakeComponent::GetDisplayName called");
    // static const wchar_t name[] = L"Famatech Radmin VPN Ethernet Adapter";
    // *ppszwDisplayName = CoTaskMemAlloc(sizeof(name));
    if (*ppszwDisplayName) wcscpy(*ppszwDisplayName, fake_FriendlyName);
    return S_OK;
}
// Other methods (23 of them) are stubbed with Stub_NotImpl
static HRESULT STDMETHODCALLTYPE FakeComponent_Stub(void) { return E_NOTIMPL; }

// --- FakeComponentBindings ---
HRESULT STDMETHODCALLTYPE FakeBindings_QueryInterface(INetCfgComponentBindings *pThis, REFIID riid, void **ppvObj) {
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_INetCfgComponentBindings)) {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    return E_NOINTERFACE;
}
ULONG STDMETHODCALLTYPE FakeBindings_AddRef(INetCfgComponentBindings *pThis) {
    return InterlockedIncrement(&((FakeComponentBindings*)pThis)->refCount);
}
ULONG STDMETHODCALLTYPE FakeBindings_Release(INetCfgComponentBindings *pThis) {
    FakeComponentBindings *b = (FakeComponentBindings*)pThis;
    LONG ref = InterlockedDecrement(&b->refCount);
    if (ref == 0) HeapFree(GetProcessHeap(), 0, b);
    return ref;
}
HRESULT STDMETHODCALLTYPE FakeBindings_EnumBindingPaths(
    INetCfgComponentBindings *pThis,
    IEnumNetCfgBindingPath **ppenum)
{
    LogMsg("FakeBindings::EnumBindingPaths - returning empty");
    *ppenum = NULL;
    return S_FALSE;
}
// (For now, we'll implement an empty IEnumNetCfgBindingPath that always returns S_FALSE)

// --- FakeComponentEnumerator (IEnumNetCfgComponent) ---
HRESULT STDMETHODCALLTYPE FakeEnum_QueryInterface(IEnumNetCfgComponent *pThis, REFIID riid, void **ppvObj) {
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IEnumNetCfgComponent)) {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    return E_NOINTERFACE;
}
ULONG STDMETHODCALLTYPE FakeEnum_AddRef(IEnumNetCfgComponent *pThis) {
    return InterlockedIncrement(&((FakeComponentEnumerator*)pThis)->refCount);
}
ULONG STDMETHODCALLTYPE FakeEnum_Release(IEnumNetCfgComponent *pThis) {
    FakeComponentEnumerator *e = (FakeComponentEnumerator*)pThis;
    LONG ref = InterlockedDecrement(&e->refCount);
    if (ref == 0) {
        if (e->realEnum) e->realEnum->lpVtbl->Release(e->realEnum);
        if (e->fakeComponent) ((IUnknown*)e->fakeComponent)->lpVtbl->Release((IUnknown*)e->fakeComponent);
        HeapFree(GetProcessHeap(), 0, e);
    }
    return ref;
}
HRESULT STDMETHODCALLTYPE FakeEnum_Next(IEnumNetCfgComponent *pThis, ULONG celt,
                                        INetCfgComponent **rgelt, ULONG *pceltFetched) {
                                            LogMsg("FakeEnum::Next");
    FakeComponentEnumerator *e = (FakeComponentEnumerator*)pThis;
    if (!e->fakeReturned && celt > 0) {
        *rgelt = e->fakeComponent;
        ((IUnknown*)e->fakeComponent)->lpVtbl->AddRef((IUnknown*)e->fakeComponent);
        e->fakeReturned = TRUE;
        if (pceltFetched) *pceltFetched = 1;
        return S_OK;
    }
    // Delegate to real enumerator
    LogMsg("FakeEnum_Next -> delegating to real enumerator");
    return e->realEnum->lpVtbl->Next(e->realEnum, celt, rgelt, pceltFetched);
}
HRESULT STDMETHODCALLTYPE FakeEnum_Skip(IEnumNetCfgComponent *pThis, ULONG celt) { return S_OK; }
HRESULT STDMETHODCALLTYPE FakeEnum_Reset(IEnumNetCfgComponent *pThis) { return S_OK; }
HRESULT STDMETHODCALLTYPE FakeEnum_Clone(IEnumNetCfgComponent *pThis, IEnumNetCfgComponent **ppenum) { return E_NOTIMPL; }

// ---------- Fake INetConnection (full vtable) ----------
static void* g_FakeConnectionVtable[10] = {0};   // exactly 10 entries


typedef struct {
    void *lpVtbl;
    LONG refCount;
} FakeNetConnection;

// {C08956A1-1CD3-11D1-B1C5-00805FC1270E}  – INetConnection from HNetCfg typelib
const GUID IID_INetConnection_HNetCfg = 
    {0xC08956A1, 0x1CD3, 0x11D1, {0xB1, 0xC5, 0x00, 0x80, 0x5F, 0xC1, 0x27, 0x0E}};



// ----------------------------------------------------------------
// Wrapper that implements the HNetCfg INetConnection
// (IID = {C08956A1-1CD3-11D1-B1C5-00805FC1270E})
// ----------------------------------------------------------------
typedef struct {
    void *lpVtbl;                     // vtable for HNetCfg INetConnection
    LONG refCount;
    INetConnection *realConn;         // the original fake connection (standard one)
    GUID adapterGuid;                 // copy of the Radmin adapter GUID
} HNetCfgNetConnection;

static void* g_HNetCfgConnVtable[8] = {0};   // at least 8 entries (indices 0-7)

// ---------- IUnknown ----------

static HRESULT STDMETHODCALLTYPE HNC_QueryInterface(IUnknown *pThis, REFIID riid, void **ppvObj)
{
    OLECHAR szIID[64];
    StringFromGUID2(riid, szIID, 64);
    LogMsg("HNetCfgConn::QI(%ls)", szIID);

    HNetCfgNetConnection *w = (HNetCfgNetConnection*)pThis;

    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_INetConnection_HNetCfg)) {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }

    // For any other interface, delegate to the real (standard) connection
    HRESULT hr = w->realConn->lpVtbl->QueryInterface(w->realConn, riid, ppvObj);
    LogMsg("HNetCfgConn::QI delegating to real connection -> 0x%08lX", hr);
    return hr;
}

static ULONG STDMETHODCALLTYPE HNC_AddRef(IUnknown *pThis)
{
    ULONG ref = InterlockedIncrement(&((HNetCfgNetConnection*)pThis)->refCount);
    LogMsg("HNetCfgConn::AddRef -> %lu", ref);
    return ref;
}

static ULONG STDMETHODCALLTYPE HNC_Release(IUnknown *pThis)
{
    HNetCfgNetConnection *w = (HNetCfgNetConnection*)pThis;
    LONG ref = InterlockedDecrement(&w->refCount);
    LogMsg("HNetCfgConn::Release -> %ld", ref);
    if (ref == 0) {
        w->realConn->lpVtbl->Release(w->realConn);
        HeapFree(GetProcessHeap(), 0, w);
    }
    return ref;
}

// ---------- Forwarding helpers (indices 3-6) ----------
// These redirect to the same method on the real (standard) fake connection

// Index 3 – GetProperties
static HRESULT STDMETHODCALLTYPE HNC_GetProperties(INetConnection *pThis, NETCON_PROPERTIES **ppProps) {
    HNetCfgNetConnection *w = (HNetCfgNetConnection*)pThis;
    LogMsg("HNetCfgConn::GetProperties");
    return w->realConn->lpVtbl->GetProperties(w->realConn, ppProps);
}
// Index 4 – Rename
static HRESULT STDMETHODCALLTYPE HNC_Rename(INetConnection *pThis, LPCWSTR pszwNewName) {
    HNetCfgNetConnection *w = (HNetCfgNetConnection*)pThis;
    LogMsg("HNetCfgConn::Rename");
    return w->realConn->lpVtbl->Rename(w->realConn, pszwNewName);
}
// Index 5 – GetUiObjectClassId
static HRESULT STDMETHODCALLTYPE HNC_GetUiObjectClassId(INetConnection *pThis, CLSID *pclsid) {
    HNetCfgNetConnection *w = (HNetCfgNetConnection*)pThis;
    LogMsg("HNetCfgConn::GetUiObjectClassId");
    return w->realConn->lpVtbl->GetUiObjectClassId(w->realConn, pclsid);
}
// Index 6 – Connect (the standard method at index 6 is Connect)
static HRESULT STDMETHODCALLTYPE HNC_Connect(INetConnection *pThis) {
    HNetCfgNetConnection *w = (HNetCfgNetConnection*)pThis;
    LogMsg("HNetCfgConn::Connect");
    return w->realConn->lpVtbl->Connect(w->realConn);
}

// ---------- Method at vtable index 7 (0x1C) – returns the adapter GUID ----------
// Radmin adapter GUID used in the comparison (from WMI queries)
static HRESULT STDMETHODCALLTYPE HNC_GetConnectionId(IUnknown *pThis, void **ppIdent)
{
    LogMsg("HNetCfgConn::GetConnectionId -> returning fake_settingID GUID");
    if (ppIdent) {
        HNetCfgNetConnection *w = (HNetCfgNetConnection*)pThis;
        // Always refresh from the current fake_settingID (may have changed via netsh etc.)
        CLSIDFromString(fake_settingID, &w->adapterGuid);
        *ppIdent = &w->adapterGuid;
        return S_OK;
    }
    return E_POINTER;
}

// ---------- Vtable initialisation ----------

static void InitHNetCfgConnVtable(void) {
    if (g_HNetCfgConnVtable[0]) return;
    g_HNetCfgConnVtable[0] = &HNC_QueryInterface;    // IUnknown
    g_HNetCfgConnVtable[1] = &HNC_AddRef;
    g_HNetCfgConnVtable[2] = &HNC_Release;
    g_HNetCfgConnVtable[3] = &HNC_GetProperties;     // index 3
    g_HNetCfgConnVtable[4] = &HNC_Rename;             // index 4
    g_HNetCfgConnVtable[5] = &HNC_GetUiObjectClassId; // index 5
    g_HNetCfgConnVtable[6] = &HNC_Connect;            // index 6
    g_HNetCfgConnVtable[7] = &HNC_GetConnectionId;    // our custom method returns the GUID
}
static HRESULT STDMETHODCALLTYPE FakeConn_QueryInterface(INetConnection *pThis, REFIID riid, void **ppvObj)
{
    OLECHAR szIID[64];
    StringFromGUID2(riid, szIID, 64);
    LogMsg("FakeConn::QI(%ls)", szIID);

    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_INetConnection)) {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }

    *ppvObj = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE FakeConn_AddRef(INetConnection *pThis) {
    return InterlockedIncrement(&((FakeNetConnection*)pThis)->refCount);
}
static ULONG STDMETHODCALLTYPE FakeConn_Release(INetConnection *pThis) {
    FakeNetConnection *c = (FakeNetConnection*)pThis;
    LONG ref = InterlockedDecrement(&c->refCount);
    if (ref == 0) HeapFree(GetProcessHeap(), 0, c);
    return ref;
}
static HRESULT STDMETHODCALLTYPE FakeConn_GetProperties(INetConnection *pThis, NETCON_PROPERTIES **ppProps)
{
    LogMsg("FakeConn::GetProperties – returning full fake properties");

    if (!ppProps) return E_POINTER;

    // Allocate the structure itself (caller will free with CoTaskMemFree)
    NETCON_PROPERTIES *props = (NETCON_PROPERTIES*)CoTaskMemAlloc(sizeof(NETCON_PROPERTIES));
    if (!props) return E_OUTOFMEMORY;
    ZeroMemory(props, sizeof(NETCON_PROPERTIES));

    // // ---------- GUID identifier (Radmin adapter GUID) ----------
    // props->guidId = g_RadminAdapterGuid;

    // ---------- GUID identifier (Radmin adapter GUID) ----------
    CLSIDFromString(fake_settingID, &props->guidId);
    LogMsg("FakeConn::GetProperties - guidId = %ls", fake_settingID);

    // ---------- Connection name (visible in network properties) ----------
    size_t len = (wcslen(fake_FriendlyName) + 1) * sizeof(wchar_t);
    props->pszwName = (LPWSTR)CoTaskMemAlloc(len);
    if (!props->pszwName) { CoTaskMemFree(props); return E_OUTOFMEMORY; }
    memcpy(props->pszwName, fake_FriendlyName, len);

    // ---------- Device name (driver path or hardware ID) ----------
    static const wchar_t device[] = L"Famatech Radmin VPN Ethernet Adapter";
    props->pszwDeviceName = (LPWSTR)CoTaskMemAlloc(sizeof(device));
    if (!props->pszwDeviceName) {
        CoTaskMemFree(props->pszwName);
        CoTaskMemFree(props);
        return E_OUTOFMEMORY;
    }
    memcpy(props->pszwDeviceName, device, sizeof(device));

    // ---------- Connection status ----------
    props->Status = NCS_CONNECTED;

    // ---------- Media type (Ethernet/LAN) ----------
    props->MediaType = NCM_LAN;

    // ---------- Characteristics flags ----------
    // Set typical flags that a real adapter would have:
    props->dwCharacter = NCCF_ALL_USERS          // 0x0001
                    | NCCF_ALLOW_RENAME       // 0x0008
                    | NCCF_HOMENET_CAPABLE;   // 0x1000

    // ---------- Object CLSID (usually unused) ----------
    CLSIDFromString(L"{BA126ADB-2166-11D1-B1D0-00805FC1270E}", &props->clsidThisObject);
    CLSIDFromString(L"{7007ACC5-3202-11D1-AAD2-00805FC1270E}", &props->clsidUiObject);

    *ppProps = props;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FakeConn_Rename(INetConnection *pThis, LPCWSTR pszwNewName) {
    LogMsg("FakeConn::Rename(%ls)", pszwNewName);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FakeConn_GetUiObjectClassId(INetConnection *pThis, CLSID *pclsid) {
    LogMsg("FakeConn::GetUiObjectClassId – E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE FakeConn_Connect(INetConnection *pThis) {
    LogMsg("FakeConn::Connect – success");
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FakeConn_Disconnect(INetConnection *pThis) {
    LogMsg("FakeConn::Disconnect – success");
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FakeConn_Delete(INetConnection *pThis) {
    LogMsg("FakeConn::Delete – success");
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FakeConn_Duplicate(INetConnection *pThis, LPCWSTR pszwDuplicateName, INetConnection **ppConnection) {
    LogMsg("FakeConn::Duplicate – E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE FakeConn_GetConnectionStatus(INetConnection *pThis, NETCON_STATUS *pStatus) {
    LogMsg("FakeConn::GetConnectionStatus – NCS_CONNECTED");
    if (pStatus) *pStatus = NCS_CONNECTED;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FakeConn_GetAdapterId(INetConnection *pThis, GUID *pguid) {
    LogMsg("FakeConn::GetAdapterId – returning Radmin adapter GUID");
    if (pguid) {
        // Use the exact GUID from the WMI queries
        CLSIDFromString(fake_settingID, pguid);
    }
    return S_OK;
}

static void InitFakeConnectionVtable(void)
{
    if (g_FakeConnectionVtable[0]) return;

    // IUnknown
    g_FakeConnectionVtable[0] = &FakeConn_QueryInterface;
    g_FakeConnectionVtable[1] = &FakeConn_AddRef;
    g_FakeConnectionVtable[2] = &FakeConn_Release;

    // INetConnection methods in the order they appear in netcon.h
    g_FakeConnectionVtable[3] = &FakeConn_Connect;             // index 3
    g_FakeConnectionVtable[4] = &FakeConn_Disconnect;          // index 4
    g_FakeConnectionVtable[5] = &FakeConn_Delete;              // index 5
    g_FakeConnectionVtable[6] = &FakeConn_Duplicate;           // index 6
    g_FakeConnectionVtable[7] = &FakeConn_GetProperties;       // index 7  <-- the crucial one
    g_FakeConnectionVtable[8] = &FakeConn_GetUiObjectClassId;  // index 8
    g_FakeConnectionVtable[9] = &FakeConn_Rename;              // index 9
}

static INetConnection* CreateFakeNetConnection(void) {
    InitFakeConnectionVtable();
    FakeNetConnection *conn = (FakeNetConnection*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FakeNetConnection));
    if (!conn) return NULL;
    conn->lpVtbl = g_FakeConnectionVtable;
    conn->refCount = 1;
    return (INetConnection*)conn;
}

// Initialization of vtables (called once)
static void InitFakeEnumVtable() {
    if (g_FakeEnumVtable[0]) return;
    g_FakeEnumVtable[0] = &FakeEnum_QueryInterface;
    g_FakeEnumVtable[1] = &FakeEnum_AddRef;
    g_FakeEnumVtable[2] = &FakeEnum_Release;
    g_FakeEnumVtable[3] = &FakeEnum_Next;
    g_FakeEnumVtable[4] = &FakeEnum_Skip;
    g_FakeEnumVtable[5] = &FakeEnum_Reset;
    g_FakeEnumVtable[6] = &FakeEnum_Clone;
}
static void InitFakeComponentVtable() {
    if (g_FakeComponentVtable[0]) return;
    // Fill all with FakeComponent_Stub
    for (int i = 0; i < 32; i++) g_FakeComponentVtable[i] = &FakeComponent_Stub;
    g_FakeComponentVtable[0] = &FakeComponent_QueryInterface;
    g_FakeComponentVtable[1] = &FakeComponent_AddRef;
    g_FakeComponentVtable[2] = &FakeComponent_Release;
    g_FakeComponentVtable[3] = &FakeComponent_GetDisplayName;  // index 3
    // GetId, GetHelpText, etc. are stubbed (no crash)
}
static void InitFakeBindingsVtable() {
    if (g_FakeBindingsVtable[0]) return;
    for (int i = 0; i < 16; i++) g_FakeBindingsVtable[i] = &FakeComponent_Stub;
    g_FakeBindingsVtable[0] = &FakeBindings_QueryInterface;
    g_FakeBindingsVtable[1] = &FakeBindings_AddRef;
    g_FakeBindingsVtable[2] = &FakeBindings_Release;
    g_FakeBindingsVtable[8] = &FakeBindings_EnumBindingPaths; // index 8
}

// Factory for fake component enumerator
static IEnumNetCfgComponent* CreateFakeComponentEnumerator(IEnumNetCfgComponent *realEnum) {
    InitFakeEnumVtable();
    InitFakeComponentVtable();
    InitFakeBindingsVtable();

    // Create fake component
    FakeNetCfgComponent *comp = (FakeNetCfgComponent*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*comp));
    if (!comp) return NULL;
    comp->lpVtbl = g_FakeComponentVtable;
    comp->refCount = 1;
    // Create fake bindings
    FakeComponentBindings *bind = (FakeComponentBindings*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*bind));
    if (!bind) { HeapFree(GetProcessHeap(), 0, comp); return NULL; }
    bind->lpVtbl = g_FakeBindingsVtable;
    bind->refCount = 1;
    comp->bindings = (INetCfgComponentBindings*)bind;

    // Create enumerator
    FakeComponentEnumerator *enumW = (FakeComponentEnumerator*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*enumW));
    if (!enumW) { /* cleanup */ return NULL; }
    enumW->lpVtbl = g_FakeEnumVtable;
    enumW->refCount = 1;
    enumW->realEnum = realEnum;
    enumW->fakeComponent = (INetCfgComponent*)comp;
    enumW->fakeReturned = FALSE;

    LogMsg("Fake component enumerator created (realEnum=%p, fakeComponent=%p)", realEnum, comp);
    return (IEnumNetCfgComponent*)enumW;
}

// Hook for INetCfg::EnumComponents
static HRESULT STDMETHODCALLTYPE Hook_INetCfg_EnumComponents(INetCfg *pThis, const GUID *pguidClass,
                                                             IEnumNetCfgComponent **ppenumComponent)
{
    LogMsg("INetCfg::EnumComponents()");
    // Real_EnumComponents was stored from original vtable
    HRESULT hr = Real_INetCfg_EnumComponents(pThis, pguidClass, ppenumComponent);
    if (SUCCEEDED(hr)) {
        *ppenumComponent = CreateFakeComponentEnumerator(*ppenumComponent);
    }
    return hr;
}

// Patch the INetCfg object when created
static void PatchCNetCfg(INetCfg *pNetCfg) {
    void **realVtbl = *(void***)pNetCfg;
    // We need a persistent copy of the vtable for this specific object,
    // but since we create a new one each time, we can use a static buffer.
    static void *patchedVtable[16];
    memcpy(patchedVtable, realVtbl, sizeof(patchedVtable));
    Real_INetCfg_EnumComponents = (INetCfg_EnumComponents_t)realVtbl[5];
    patchedVtable[5] = &Hook_INetCfg_EnumComponents;
    *(void***)pNetCfg = patchedVtable;
}

static INetworkListManager* CreateFakeNetworkListManager(void);
/* ===================================================================
 * CoCreateInstance hook – dispatches to WMI or NetCfg patching
 * =================================================================== */
HRESULT WINAPI Hook_CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext,
                                     REFIID riid, LPVOID *ppv)
{
    HRESULT hr;
    BOOL needFake = FALSE;

    // --- Pre‑call logging (always performed) -----------------------------------
    wchar_t clsid_str[39], iid_str[39];
    StringFromGUID2(rclsid, clsid_str, 39);
    StringFromGUID2(riid, iid_str, 39);

    LogMsg("CoCreateInstance: CLSID=%ls, IID=%ls", clsid_str, iid_str);

    // --- Determine whether to create a completely fake locator ---------------
    if (BLOCK_REAL && IsEqualGUID(rclsid, &CLSID_WbemLocator)) {
        needFake = TRUE;
    }

    // --- Perform the real or fake creation -----------------------------------
    if (needFake) {
        IUnknown *fake = CreateFakeCOMObject();
        if (!fake) {
            LogMsg("  => FAKE creation FAILED (out of memory)");
            return E_OUTOFMEMORY;
        }
        *ppv = fake;
        hr = S_OK;
    } else {
        hr = Real_CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
    }

    // --- Post‑call logging (always performed) ---------------------------------
    if (SUCCEEDED(hr) && ppv && *ppv) {
        LogMsg("  => %s (ppv=%p)", needFake ? "FAKE" : "REAL", *ppv);
    } else {
        LogMsg("  => FAILED (hr=0x%08lX, ppv=%p)", hr, ppv ? *ppv : NULL);
        return hr;      // no special handling for failures
    }

    // ===== Special handling for known CLSIDs (ONLY when creation succeeded) =====

    // ---------- IWbemLocator ----------
    if (IsEqualGUID(rclsid, &CLSID_WbemLocator)) {
        LogMsg("  => IWbemLocator captured");
        PatchWbemLocator((IWbemLocator*)*ppv);
    }
    // ---------- INetCfg ----------
    else if (IsEqualGUID(rclsid, &CLSID_CNetCfg)) {
        // LogMsg("  => INetCfg captured – patching EnumComponents");
        // PatchCNetCfg((INetCfg*)*ppv);
    }
    // ---------- NetSharingManager ----------
    else if (IsEqualGUID(rclsid, &CLSID_NetSharingManager)) {
#if PROXY
        LogMsg("  => NetSharingManager captured – wrapping with proxy");
        #else
        *ppv = CreateFakeNetSharingManager((INetSharingManager*)*ppv);
        LogMsg("  => NetSharingManager captured – using real (PROXY=0)");
#endif
    }
    // ---------- NetworkListManager (early return) ----------
    else if (IsEqualGUID(rclsid, &CLSID_NetworkListManager) &&
             IsEqualGUID(riid, &IID_INetworkListManager))
    {
        LogMsg("  => NetworkListManager requested – returning fake");
        #if REAL
        #else
        *ppv = CreateFakeNetworkListManager();
        #endif
        if (*ppv) {
            // refcount already 1, nothing else
        } else {
            LogMsg("  => CreateFakeNetworkListManager FAILED");
            hr = E_OUTOFMEMORY;
            return hr;
        }
        // For this case we intentionally skip the rest of the function
        return S_OK;
    }

    return hr;
}

// Original function pointer
typedef BOOL (WINAPI *CreateProcessW_t)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
static CreateProcessW_t Real_CreateProcessW = NULL;


// ===== helper functions =====

static int MaskToPrefix(const wchar_t *maskStr) {
    // Simple conversion for common masks; you can extend with inet_pton.
    // Assume maskStr is like L"255.255.255.0"
    unsigned int octets[4];
    if (swscanf_s(maskStr, L"%u.%u.%u.%u", &octets[0], &octets[1], &octets[2], &octets[3]) != 4)
        return -1;

    uint32_t mask = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    // Count leading 1 bits
    int prefix = 0;
    while (prefix < 32 && (mask & (1 << (31 - prefix))))
        prefix++;
    return prefix;
}

static int ParseIPv6Prefix(const wchar_t *addrStr, uint8_t *ipv6, uint8_t *prefix) {
    // Try to split "address/prefix" notation
    wchar_t buf[64];
    wcscpy(buf, addrStr);
    wchar_t *slash = wcschr(buf, L'/');
    if (slash) {
        *slash = 0;
        *prefix = (uint8_t)_wtoi(slash + 1);
    } else {
        *prefix = 64;   // default if missing
    }
    // Convert the address part to binary (use inet_pton)
    char addrA[64];
    WideCharToMultiByte(CP_ACP, 0, buf, -1, addrA, sizeof(addrA), NULL, NULL);
    return inet_pton(AF_INET6, addrA, ipv6) == 1 ? 0 : -1;
}

// Structure to hold parsed netsh configuration
typedef struct {
    wchar_t interfaceName[256];
    wchar_t newName[256];
    wchar_t address[64];
    wchar_t mask[64];
    wchar_t gateway[64];
    wchar_t nexthop[64];
    wchar_t prefix[64];
    int metric;
    int gwmetric;
    BOOL hasAddress;
    BOOL hasMask;
    BOOL hasGateway;
    BOOL hasNexthop;
    BOOL hasMetric;
    BOOL hasPrefix;
    BOOL enableAdapter;      // TRUE if netsh is enabling the interface
    BOOL disableAdapter;     // TRUE if netsh is disabling the interface
    BOOL enableIPv4;         // TRUE if netsh is enabling IPv4
    BOOL hasNewName;
} NetshConfig;

// Global to store the latest parsed config
static NetshConfig g_LastNetshConfig = {0};

static void ParseNetshCommand(LPCWSTR cmd) {
    NetshConfig config = {0};
    wcscpy(config.interfaceName, L"Radmin VPN");
    
        // ===== Detect ENABLE / DISABLE commands =====
    // ===== Detect rename: newname="..." =====
    const wchar_t *newNamePos = wcsstr(cmd, L"newname=\"");
    if (newNamePos) {
        newNamePos += 9;  // skip "newname=\""
        int i = 0;
        while (*newNamePos && *newNamePos != L'"' && i < 255) {
            config.newName[i++] = *newNamePos++;
        }
        config.newName[i] = 0;
        config.hasNewName = TRUE;
        LogMsg("    Detected rename to: \"%ls\"", config.newName);
    }
    // Pattern: "interface set interface \"...\" ENABLE" or "ENABLED"
    const wchar_t *setIfPos = wcsstr(cmd, L"interface set interface");
    if (setIfPos) {
        if (wcsstr(cmd, L"ENABLE") && !wcsstr(cmd, L"DISABLE")) {
            config.enableAdapter = TRUE;
            LogMsg("    Detected: ENABLE adapter");
        }
        if (wcsstr(cmd, L"DISABLE")) {
            config.disableAdapter = TRUE;
            LogMsg("    Detected: DISABLE adapter");
        }
    }
    
    // Pattern: "interface ipv4 set interface ... ENABLE"
    const wchar_t *ipv4Pos = wcsstr(cmd, L"interface ipv4 set interface");
    if (ipv4Pos) {
        if (wcsstr(cmd, L"ENABLE") && !wcsstr(cmd, L"DISABLE")) {
            config.enableIPv4 = TRUE;
            LogMsg("    Detected: ENABLE IPv4 on adapter");
        }
    }

    // Parse: addr=X  or  address=X  (handle both IPv4 and IPv6)
    const wchar_t *addrPos = wcsstr(cmd, L"addr=");
    if (!addrPos) addrPos = wcsstr(cmd, L"address=");
    if (addrPos) {
        if (wcsstr(cmd, L"addr="))      addrPos += 5;  // "addr="
        else                            addrPos += 8;  // "address="
        if (*addrPos == L'"') addrPos++;
        int i = 0;
        while (*addrPos && *addrPos != L' ' && *addrPos != L'"' && i < 63) {
            config.address[i++] = *addrPos++;
        }
        config.address[i] = 0;
        config.hasAddress = TRUE;
        LogMsg("    Parsed address: %ls", config.address);

        // --- Update the fake globals ---
        if (wcsstr(cmd, L"ipv6") || wcschr(config.address, L':')) {
            wcscpy(g_fakeIPv6Address, config.address);
            g_hasIPv6Address = TRUE;
            LogMsg("    => Updated fake IPv6 address to %ls", g_fakeIPv6Address);
        } else {
            wcscpy(fake_ipAddress, config.address);
            LogMsg("    => Updated fake IPv4 address to %ls", fake_ipAddress);
        }
    }
    
    // Parse: mask=X
    const wchar_t *maskPos = wcsstr(cmd, L"mask=");
    if (maskPos) {
        maskPos += 5;
        if (*maskPos == L'"') maskPos++;
        int i = 0;
        while (*maskPos && *maskPos != L' ' && *maskPos != L'"' && i < 63) {
            config.mask[i++] = *maskPos++;
        }
        config.mask[i] = 0;
        config.hasMask = TRUE;
        LogMsg("    Parsed mask: %ls", config.mask);
    }
    
    // Parse: gateway=X
    const wchar_t *gwPos = wcsstr(cmd, L"gateway=");
    if (gwPos) {
        gwPos += 8;
        if (*gwPos == L'"') gwPos++;
        int i = 0;
        while (*gwPos && *gwPos != L' ' && *gwPos != L'"' && i < 63) {
            config.gateway[i++] = *gwPos++;
        }
        config.gateway[i] = 0;
        config.hasGateway = TRUE;
        LogMsg("    Parsed gateway: %ls", config.gateway);
    }
    
    // Parse: nexthop=X
    const wchar_t *nhPos = wcsstr(cmd, L"nexthop=");
    if (nhPos) {
        nhPos += 8;
        if (*nhPos == L'"') nhPos++;
        int i = 0;
        while (*nhPos && *nhPos != L' ' && *nhPos != L'"' && i < 63) {
            config.nexthop[i++] = *nhPos++;
        }
        config.nexthop[i] = 0;
        config.hasNexthop = TRUE;
        LogMsg("    Parsed nexthop: %ls", config.nexthop);
    }
    
    // Parse: prefix=X (route prefix)
    const wchar_t *prefixPos = wcsstr(cmd, L"prefix=");
    if (prefixPos) {
        prefixPos += 7;
        if (*prefixPos == L'"') prefixPos++;
        int i = 0;
        while (*prefixPos && *prefixPos != L' ' && *prefixPos != L'"' && i < 63) {
            config.prefix[i++] = *prefixPos++;
        }
        config.prefix[i] = 0;
        config.hasPrefix = TRUE;
        LogMsg("    Parsed prefix: %ls", config.prefix);
    }
    
    // Parse: metric=N
    const wchar_t *metricPos = wcsstr(cmd, L"metric=");
    if (metricPos) {
        metricPos += 7;
        config.metric = _wtoi(metricPos);
        config.hasMetric = TRUE;
        LogMsg("    Parsed metric: %d", config.metric);
    }
    
    // Parse: gwmetric=N
    const wchar_t *gwmetricPos = wcsstr(cmd, L"gwmetric=");
    if (gwmetricPos) {
        gwmetricPos += 9;
        config.gwmetric = _wtoi(gwmetricPos);
        LogMsg("    Parsed gwmetric: %d", config.gwmetric);
    }
    
    // Parse: interface="..."
    const wchar_t *ifPos = wcsstr(cmd, L"interface=");
    if (ifPos) {
        ifPos += 10;
        if (*ifPos == L'"') ifPos++;
        int i = 0;
        while (*ifPos && *ifPos != L' ' && *ifPos != L'"' && i < 255) {
            config.interfaceName[i++] = *ifPos++;
        }
        config.interfaceName[i] = 0;
        LogMsg("    Parsed interface: %ls", config.interfaceName);
    }
    
       // ===== Apply ENABLE/DISABLE to connection status =====
    if (config.enableAdapter) {
        g_FakeConnectionStatus = NCS_CONNECTED;
        LogMsg("    => Setting fake connection status to NCS_CONNECTED");
    }
    if (config.disableAdapter) {
        g_FakeConnectionStatus = NCS_DISCONNECTED;
        LogMsg("    => Setting fake connection status to NCS_DISCONNECTED");
    }
    if (config.enableIPv4) {
        g_FakeConnectionStatus = NCS_CONNECTED;
        LogMsg("    => IPv4 enabled, setting fake connection status to NCS_CONNECTED");
    }
    if (config.hasNewName) {
        wcsncpy(fake_FriendlyName, config.newName, 127);
        fake_FriendlyName[127] = L'\0';   // ensure null termination
        LogMsg("    Updated fake adapter display name to: %ls", fake_FriendlyName);
    }
    if (config.hasMask) {
        wcscpy(fake_ipSubnet, config.mask);
        LogMsg("    => Updated fake subnet to %ls", fake_ipSubnet);
    }
    if (config.hasGateway) {
        wcscpy(fake_gateway, config.gateway);
        LogMsg("    => Updated fake gateway to %ls", fake_gateway);
    }

        // ========== Forward configuration to TAP client ==========
        // 1. IPv4 address + mask → set IPv4
    if (config.hasAddress) {
        wchar_t *addr = config.address;
        // Check if it's an IPv4 address (contains no colon)
        if (wcschr(addr, L':') == NULL) {
            // IPv4: requires a mask
            if (config.hasMask) {
                char ipA[64];
                WideCharToMultiByte(CP_ACP, 0, addr, -1, ipA, sizeof(ipA), NULL, NULL);
                struct in_addr in4;
                if (inet_pton(AF_INET, ipA, &in4) == 1) {
                    int prefix = MaskToPrefix(config.mask);
                    if (prefix >= 0 && prefix <= 32) {
                        uint8_t ip_bin[4];
                        memcpy(ip_bin, &in4, 4);   // network byte order already
                        TapClientSetIPv4(ip_bin, (uint8_t)prefix);
                        LogMsg("TAP: set IPv4 %s/%d", ipA, prefix);
                    }
                }
            } else {
                LogMsg("TAP: IPv4 address %ls has no mask – skipping", addr);
            }
        } else {
            // IPv6: no mask required (prefix can be inside addr or default)
            uint8_t ip6[16];
            uint8_t prefix;
            if (ParseIPv6Prefix(addr, ip6, &prefix) == 0) {
                TapClientSetIPv6(ip6, prefix);
                TapClientSetLinkUp();
                LogMsg("TAP: set IPv6 %ls/%u", addr, prefix);
            } else {
                LogMsg("TAP: failed to parse IPv6 address %ls", addr);
            }
        }
    }

    // Bring the link up once at the end, not inside each address block
    // if ((config.hasAddress || config.hasGateway) && config.enableAdapter) {
    //     TapClientSetLinkUp();
    //     LogMsg("TAP: link UP");
    // }

        // 2. IPv4 gateway (only if driver is TAP; gateway is optional)
        if (config.hasGateway) {
            char ipA[64];
            WideCharToMultiByte(CP_ACP, 0, config.gateway, -1, ipA, sizeof(ipA), NULL, NULL);
            struct in_addr in4;
            if (inet_pton(AF_INET, ipA, &in4) == 1) {
                uint8_t gw[4];
                memcpy(gw, &in4, 4);
                // TapClientSetIPv4Gateway(gw);
                LogMsg("TAP: set gateway %s", ipA);
            }
        }

        // 3. Link up / down
        if (config.enableAdapter) {
            TapClientSetLinkUp();
            LogMsg("TAP: link UP");
        }
        if (config.disableAdapter) {
            TapClientSetLinkDown();
            LogMsg("TAP: link DOWN");
        }
        // Note: enableIPv4 does not directly map to a TAP control,
        // but if you want to bring the link up when IPv4 is enabled:
        // if (config.enableIPv4) TapClientSetLinkUp();
    // }

    // Store the parsed configuration
    memcpy(&g_LastNetshConfig, &config, sizeof(NetshConfig));
}

BOOL WINAPI Hook_CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    LPCWSTR cmdToCheck = lpCommandLine ? lpCommandLine : lpApplicationName;
    
    if (cmdToCheck && wcsstr(cmdToCheck, L"netsh")) {
        LogMsg("CreateProcessW(netsh): cmd=\"%ls\"", cmdToCheck);
        
        // Check for Radmin adapter references
        if (wcsstr(cmdToCheck, L"Radmin VPN") || 
            wcsstr(cmdToCheck, L"RadminVPN") ||
            wcsstr(cmdToCheck, L"Famatech Radmin")) {
            
            LogMsg("  => Detected Radmin netsh call, parsing arguments...");
            
            // Parse and log configuration details
            ParseNetshCommand(cmdToCheck);
            
            LogMsg("  => Blocking real execution, returning dummy success");
            
            // Prepare a harmless command that always succeeds
            static const wchar_t dummyCmd[] = L"cmd.exe /c \"exit 0\"";
            LPWSTR newCmd = _wcsdup(dummyCmd);
            if (newCmd) {
                BOOL result = Real_CreateProcessW(NULL, newCmd, lpProcessAttributes,
                    lpThreadAttributes, bInheritHandles, 
                    dwCreationFlags | CREATE_NO_WINDOW,
                    lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
                free(newCmd);
                return result;
            }
            
            // Fallback
            return Real_CreateProcessW(L"cmd.exe", (LPWSTR)L"/c exit 0", lpProcessAttributes,
                lpThreadAttributes, bInheritHandles, 
                dwCreationFlags | CREATE_NO_WINDOW,
                lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        }
    }
    
    // Not a Radmin netsh call → pass through to original
    return Real_CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

// Original function pointer
typedef BOOL (WINAPI *CreateProcessAsUserW_t)(HANDLE hToken, LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
static CreateProcessAsUserW_t Real_CreateProcessAsUserW = NULL;

BOOL WINAPI Hook_CreateProcessAsUserW(HANDLE hToken, LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    LPCWSTR cmdToCheck = lpCommandLine ? lpCommandLine : lpApplicationName;
    if (cmdToCheck && wcsstr(cmdToCheck, L"netsh") &&
        (wcsstr(cmdToCheck, L"Famatech Radmin VPN Ethernet Adapter") ||
         wcsstr(cmdToCheck, L"RadminVPN")))
    {
        LogMsg("CreateProcessAsUserW netsh intercepted: \"%ls\"", cmdToCheck);
        LogMsg("  -> replacing with dummy success command");

        wchar_t dummyCmd[] = L"cmd.exe /c exit 0";
        LPWSTR writableCmd = _wcsdup(dummyCmd);
        if (!writableCmd) {
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }
        BOOL result = Real_CreateProcessAsUserW(hToken, NULL, writableCmd,
            lpProcessAttributes, lpThreadAttributes, bInheritHandles,
            dwCreationFlags | CREATE_NO_WINDOW, lpEnvironment,
            lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        free(writableCmd);
        return result;
    }

    // Not a Radmin netsh call → original behaviour
    return Real_CreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes, bInheritHandles,
        dwCreationFlags, lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);
}

// ------------------------------------------------------------
// Call‑site hook for sub_46c5a0 (thiscall) – no inline asm
// ------------------------------------------------------------

// global variables used by the trampoline
static DWORD g_OrigCallTarget = 0;   // runtime address of sub_46c5a0
static DWORD g_ReturnAddr   = 0;     // runtime address after the call (0x4B4C61)

// Simple logger
static void LogSub46c5a0Call(void)
{
    LogMsg("sub_46c5a0 (netshell.dll) is about to be called!");
}

// The trampoline – we will build it dynamically
static BYTE* g_Trampoline = NULL;     // executable memory

static void BuildTrampoline(void)
{
    // Allocate executable memory (we need enough space for the code below)
    g_Trampoline = VirtualAlloc(NULL, 64, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!g_Trampoline) return;

    BYTE* p = g_Trampoline;

    // pushad (1 byte)
    *p++ = 0x60;

    // call LogSub46c5a0Call (relative call, 5 bytes)
    *p++ = 0xE8;
    DWORD rel = (DWORD_PTR)LogSub46c5a0Call - (DWORD_PTR)p - 4;
    memcpy(p, &rel, 4); p += 4;

    // popad (1 byte)
    *p++ = 0x61;

    // push dword ptr [g_ReturnAddr] (6 bytes: FF 35 xxxxxxxx)
    *p++ = 0xFF;
    *p++ = 0x35;
    memcpy(p, &g_ReturnAddr, 4); p += 4;

    // jmp dword ptr [g_OrigCallTarget] (6 bytes: FF 25 xxxxxxxx)
    *p++ = 0xFF;
    *p++ = 0x25;
    memcpy(p, &g_OrigCallTarget, 4); p += 4;
}

// Signature of the original function (fastcall: ECX = arg1)
typedef void* (__fastcall *Sub4624e0_t)(void* arg1);
static Sub4624e0_t Real_sub_4624e0 = NULL;


static void InstallSub46c5a0CallSiteHook(void)
{
    HMODULE hMod = GetModuleHandleW(NULL);
    DWORD_PTR base = (DWORD_PTR)hMod;
    DWORD_PTR callSite = base + 0xB4C5C;   // 0x004B4C5C - 0x00400000
    DWORD_PTR returnAddr = base + 0xB4C61; // 0x004B4C61 - 0x00400000

    // Save the global addresses
    g_ReturnAddr = (DWORD)returnAddr;

    // Read the original relative offset from the call instruction
    BYTE* callInstr = (BYTE*)callSite;
    DWORD origRel = *(DWORD*)(callInstr + 1);
    g_OrigCallTarget = (DWORD)(callSite + 5) + (INT)origRel;  // signed addition

    // Build the trampoline once
    BuildTrampoline();
    if (!g_Trampoline) return;

    // Now patch the call site: replace `E8 xx xx xx xx` with `E9 xx xx xx xx` (JMP to trampoline)
    DWORD oldProt;
    VirtualProtect(callInstr, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    callInstr[0] = 0xE9;
    DWORD newRel = (DWORD)g_Trampoline - (DWORD)(callSite + 5);
    memcpy(callInstr + 1, &newRel, 4);
    VirtualProtect(callInstr, 5, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), callInstr, 5);

    LogMsg("Hook installed at call site for sub_46c5a0");
}

// ------------------------------------------------------------------
// Fake INetworkListManager (14 vtable slots)
// ------------------------------------------------------------------
typedef struct {
    void *lpVtbl;
    LONG refCount;
} FakeNetworkListManager;

static INetworkConnection* CreateFakeNetworkConnection(void);
static IEnumNetworkConnections* CreateFakeEnumNetworkConnections(void);

static void* g_FakeNetworkListManagerVtable[14] = {0};

// IUnknown
static HRESULT STDMETHODCALLTYPE NLM_QueryInterface(INetworkListManager *pThis, REFIID riid, void **ppvObj)
{
    OLECHAR szIID[64];
    StringFromGUID2(riid, szIID, 64);
    LogMsg("FakeNLM::QI(%ls)", szIID);

    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_IDispatch) ||
        IsEqualIID(riid, &IID_INetworkListManager))
    {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        LogMsg("  -> S_OK");
        return S_OK;
    }
    LogMsg("  -> E_NOINTERFACE");
    *ppvObj = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE NLM_AddRef(INetworkListManager *pThis) {
    ULONG ref = InterlockedIncrement(&((FakeNetworkListManager*)pThis)->refCount);
    LogMsg("FakeNLM::AddRef -> %lu", ref);
    return ref;
}

static ULONG STDMETHODCALLTYPE NLM_Release(INetworkListManager *pThis) {
    FakeNetworkListManager *nlm = (FakeNetworkListManager*)pThis;
    if (nlm->refCount > 1) InterlockedDecrement(&nlm->refCount);
    LogMsg("FakeNLM::Release -> %lu", nlm->refCount);
    return nlm->refCount;
}

// IDispatch stubs
static HRESULT STDMETHODCALLTYPE NLM_GetTypeInfoCount(IDispatch *pThis, UINT *pctinfo) {
    LogMsg("FakeNLM::GetTypeInfoCount -> E_NOTIMPL");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE NLM_GetTypeInfo(IDispatch *pThis, UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo) {
    LogMsg("FakeNLM::GetTypeInfo(iTInfo=%u) -> E_NOTIMPL", iTInfo);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE NLM_GetIDsOfNames(IDispatch *pThis, REFIID riid, OLECHAR **rgszNames, UINT cNames, LCID lcid, DISPID *rgDispId) {
    LogMsg("FakeNLM::GetIDsOfNames(cNames=%u) -> E_NOTIMPL", cNames);
    if (cNames > 0 && rgszNames && rgszNames[0])
        LogMsg("  first name: %ls", rgszNames[0]);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE NLM_Invoke(IDispatch *pThis, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr) {
    LogMsg("FakeNLM::Invoke(dispId=%ld, flags=0x%04X) -> E_NOTIMPL", dispIdMember, wFlags);
    return E_NOTIMPL;
}
// INetworkListManager methods
static HRESULT STDMETHODCALLTYPE NLM_GetNetworks(INetworkListManager *pThis, NLM_ENUM_NETWORK Flags, IEnumNetworks **ppEnumNetwork) {
    LogMsg("FakeNLM::GetNetworks (Flags=0x%x) -> empty", Flags);
    *ppEnumNetwork = NULL;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE NLM_GetNetwork(INetworkListManager *pThis, GUID gdNetworkId, INetwork **ppNetwork) {
    LogMsg("FakeNLM::GetNetwork -> E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE NLM_GetNetworkConnections(INetworkListManager *pThis, IEnumNetworkConnections **ppEnum) {
    LogMsg("FakeNLM::GetNetworkConnections -> returning one fake connection");
    *ppEnum = CreateFakeEnumNetworkConnections();
    return (*ppEnum) ? S_OK : E_OUTOFMEMORY;
}



typedef struct {
    void *lpVtbl;
    LONG refCount;
    INetworkConnection *fakeConnection;
    BOOL alreadyReturned;
} FakeEnumNetworkConnections;


static HRESULT STDMETHODCALLTYPE FENC_QueryInterface(IEnumNetworkConnections *pThis, REFIID riid, void **ppvObj) {
    OLECHAR szIID[64];
    StringFromGUID2(riid, szIID, 64);
    LogMsg("FakeEnumNetConns::QI(%ls)", szIID);
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IEnumNetworkConnections)) {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    *ppvObj = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE FENC_AddRef(IEnumNetworkConnections *pThis) {
    ULONG ref = InterlockedIncrement(&((FakeEnumNetworkConnections*)pThis)->refCount);
    LogMsg("FakeEnumNetConns::AddRef -> %lu", ref);
    return ref;
}

static ULONG STDMETHODCALLTYPE FENC_Release(IEnumNetworkConnections *pThis) {
    FakeEnumNetworkConnections *e = (FakeEnumNetworkConnections*)pThis;
    LONG ref = InterlockedDecrement(&e->refCount);
    LogMsg("FakeEnumNetConns::Release -> %ld", ref);
    if (ref == 0) {
        if (e->fakeConnection) e->fakeConnection->lpVtbl->Release(e->fakeConnection);
        HeapFree(GetProcessHeap(), 0, e);
    }
    return ref;
}

// Next, Skip, Reset, Clone already have logging or are trivial – keep as is.
static HRESULT STDMETHODCALLTYPE FENC_Next(IEnumNetworkConnections *pThis, ULONG celt, INetworkConnection **rgelt, ULONG *pceltFetched) {
    LogMsg("FakeEnumNetConns::Next (celt=%lu)", celt);
    FakeEnumNetworkConnections *e = (FakeEnumNetworkConnections*)pThis;
    if (!e->alreadyReturned && celt >= 1) {
        *rgelt = e->fakeConnection;
        e->fakeConnection->lpVtbl->AddRef(e->fakeConnection);
        e->alreadyReturned = TRUE;
        if (pceltFetched) *pceltFetched = 1;
        return S_OK;
    }
    if (pceltFetched) *pceltFetched = 0;
    return S_FALSE;
}

static HRESULT STDMETHODCALLTYPE FENC_Skip(IEnumNetworkConnections *pThis, ULONG celt) {
    LogMsg("FakeEnumNetConns::Skip(celt=%lu)", celt);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE FENC_Reset(IEnumNetworkConnections *pThis) {
    LogMsg("FakeEnumNetConns::Reset");
    ((FakeEnumNetworkConnections*)pThis)->alreadyReturned = FALSE;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE FENC_Clone(IEnumNetworkConnections *pThis, IEnumNetworkConnections **ppEnum) {
    LogMsg("FakeEnumNetConns::Clone -> E_NOTIMPL");
    if (ppEnum) *ppEnum = NULL;
    return E_NOTIMPL;
}

// IDispatch stubs for enumerator
static HRESULT STDMETHODCALLTYPE FENC_GetTypeInfoCount(IEnumNetworkConnections *pThis, UINT *pctinfo) {
    LogMsg("FakeEnumNetConns::GetTypeInfoCount -> E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE FENC_GetTypeInfo(IEnumNetworkConnections *pThis, UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo) {
    LogMsg("FakeEnumNetConns::GetTypeInfo -> E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE FENC_GetIDsOfNames(IEnumNetworkConnections *pThis, REFIID riid, OLECHAR **rgszNames, UINT cNames, LCID lcid, DISPID *rgDispId) {
    LogMsg("FakeEnumNetConns::GetIDsOfNames -> E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE FENC_Invoke(IEnumNetworkConnections *pThis, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr) {
    LogMsg("FakeEnumNetConns::Invoke(dispId=%ld) -> E_NOTIMPL", dispIdMember);
    return E_NOTIMPL;
}

// get__NewEnum stub
static HRESULT STDMETHODCALLTYPE FENC_get_NewEnum(IEnumNetworkConnections *pThis, IEnumVARIANT **ppEnumVar) {
    LogMsg("FakeEnumNetConns::get__NewEnum -> E_NOTIMPL");
    if (ppEnumVar) *ppEnumVar = NULL;
    return E_NOTIMPL;
}

// ---------- Corrected Fake IEnumNetworkConnections (12 methods) ----------
static void* g_FakeEnumNetworkConnectionsVtable[12] = {0};

static void InitFakeEnumNetworkConnectionsVtable(void) {
    if (g_FakeEnumNetworkConnectionsVtable[0]) return;

    // IUnknown
    g_FakeEnumNetworkConnectionsVtable[0]  = &FENC_QueryInterface;
    g_FakeEnumNetworkConnectionsVtable[1]  = &FENC_AddRef;
    g_FakeEnumNetworkConnectionsVtable[2]  = &FENC_Release;

    // IDispatch stubs
    g_FakeEnumNetworkConnectionsVtable[3]  = &FENC_GetTypeInfoCount;
    g_FakeEnumNetworkConnectionsVtable[4]  = &FENC_GetTypeInfo;
    g_FakeEnumNetworkConnectionsVtable[5]  = &FENC_GetIDsOfNames;
    g_FakeEnumNetworkConnectionsVtable[6]  = &FENC_Invoke;

    // IEnumNetworkConnections methods
    g_FakeEnumNetworkConnectionsVtable[7]  = &FENC_get_NewEnum;   // get__NewEnum
    g_FakeEnumNetworkConnectionsVtable[8]  = &FENC_Next;          // Next
    g_FakeEnumNetworkConnectionsVtable[9]  = &FENC_Skip;          // Skip
    g_FakeEnumNetworkConnectionsVtable[10] = &FENC_Reset;         // Reset
    g_FakeEnumNetworkConnectionsVtable[11] = &FENC_Clone;         // Clone
}

static IEnumNetworkConnections* CreateFakeEnumNetworkConnections(void) {
    InitFakeEnumNetworkConnectionsVtable();
    INetworkConnection *conn = CreateFakeNetworkConnection();
    if (!conn) return NULL;
    FakeEnumNetworkConnections *e = (FakeEnumNetworkConnections*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FakeEnumNetworkConnections));
    if (!e) {
        conn->lpVtbl->Release(conn);
        return NULL;
    }
    e->lpVtbl = g_FakeEnumNetworkConnectionsVtable;
    e->refCount = 1;
    e->fakeConnection = conn;
    e->alreadyReturned = FALSE;
    return (IEnumNetworkConnections*)e;
}


typedef struct {
    void *lpVtbl;
    LONG refCount;
} FakeNetworkConnection;

// ---------- IUnknown ----------
static HRESULT STDMETHODCALLTYPE FNC_QueryInterface(INetworkConnection *pThis, REFIID riid, void **ppvObj)
{
    OLECHAR szIID[64];
    StringFromGUID2(riid, szIID, 64);
    LogMsg("FakeNetConn::QI(%ls)", szIID);

    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_IDispatch) ||
        IsEqualIID(riid, &IID_INetworkConnection))
    {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    *ppvObj = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE FNC_AddRef(INetworkConnection *pThis) {
    ULONG ref = InterlockedIncrement(&((FakeNetworkConnection*)pThis)->refCount);
    LogMsg("FakeNetConn::AddRef -> %lu", ref);
    return ref;
}
static ULONG STDMETHODCALLTYPE FNC_Release(INetworkConnection *pThis) {
    FakeNetworkConnection *c = (FakeNetworkConnection*)pThis;
    LONG ref = InterlockedDecrement(&c->refCount);
    if (ref == 0) {
        HeapFree(GetProcessHeap(), 0, c);
    }
    LogMsg("FakeNetConn::Release -> %ld", ref);
    return ref;
}




// ----------------------------------------------------------------
// Minimal fake INetwork (vtable matches netlistmgr.h)
// ----------------------------------------------------------------
typedef struct {
    void *lpVtbl;
    LONG refCount;
} FakeNetwork;

static void* g_FakeNetworkVtable[20] = {0};   // 3 IUnknown + 4 IDispatch + 13 INetwork

// ---------- IUnknown ----------
static HRESULT STDMETHODCALLTYPE FN_QueryInterface(INetwork *pThis, REFIID riid, void **ppvObj)
{
    OLECHAR szIID[64];
    StringFromGUID2(riid, szIID, 64);
    LogMsg("FakeNetwork::QI(%ls)", szIID);
    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_IDispatch) ||
        IsEqualIID(riid, &IID_INetwork))
    {
        *ppvObj = pThis;
        ((IUnknown*)pThis)->lpVtbl->AddRef((IUnknown*)pThis);
        return S_OK;
    }
    *ppvObj = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE FN_AddRef(INetwork *pThis) {
    ULONG ref = InterlockedIncrement(&((FakeNetwork*)pThis)->refCount);
    LogMsg("FakeNetwork::AddRef -> %lu", ref);
    return ref;
}
static ULONG STDMETHODCALLTYPE FN_Release(INetwork *pThis) {
    FakeNetwork *n = (FakeNetwork*)pThis;
    LONG ref = InterlockedDecrement(&n->refCount);
    LogMsg("FakeNetwork::Release -> %ld", ref);
    if (ref == 0) HeapFree(GetProcessHeap(), 0, n);
    return ref;
}

// ---------- IDispatch stubs (with logging) ----------
static HRESULT STDMETHODCALLTYPE FN_GetTypeInfoCount(INetwork *pThis, UINT *pctinfo) {
    LogMsg("FakeNetwork::GetTypeInfoCount -> E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE FN_GetTypeInfo(INetwork *pThis, UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo) {
    LogMsg("FakeNetwork::GetTypeInfo -> E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE FN_GetIDsOfNames(INetwork *pThis, REFIID riid, OLECHAR **rgszNames, UINT cNames, LCID lcid, DISPID *rgDispId) {
    LogMsg("FakeNetwork::GetIDsOfNames -> E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE FN_Invoke(INetwork *pThis, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr) {
    LogMsg("FakeNetwork::Invoke(dispId=%ld) -> E_NOTIMPL", dispIdMember);
    return E_NOTIMPL;
}

// ---------- INetwork methods ----------
static HRESULT STDMETHODCALLTYPE FN_GetName(INetwork *pThis, BSTR *pszNetworkName) {
    LogMsg("FakeNetwork::GetName");
    if (pszNetworkName) *pszNetworkName = SysAllocString(fake_FriendlyName);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FN_SetName(INetwork *pThis, BSTR szNetworkNewName) {
    LogMsg("FakeNetwork::SetName -> E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE FN_GetDescription(INetwork *pThis, BSTR *pszDescription) {
    LogMsg("FakeNetwork::GetDescription -> E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE FN_SetDescription(INetwork *pThis, BSTR szDescription) {
    LogMsg("FakeNetwork::SetDescription -> E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE FN_GetNetworkId(INetwork *pThis, GUID *pgdGuidNetworkId) {
    LogMsg("FakeNetwork::GetNetworkId");
    if (pgdGuidNetworkId) CLSIDFromString(fake_settingID, pgdGuidNetworkId);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FN_GetDomainType(INetwork *pThis, NLM_DOMAIN_TYPE *pNetworkType) {
    LogMsg("FakeNetwork::GetDomainType -> NLM_DOMAIN_TYPE_DOMAIN_AUTHENTICATED");
    if (pNetworkType) *pNetworkType = NLM_DOMAIN_TYPE_DOMAIN_AUTHENTICATED;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FN_GetNetworkConnections(INetwork *pThis, IEnumNetworkConnections **ppEnumNetworkConnection) {
    LogMsg("FakeNetwork::GetNetworkConnections -> empty");
    if (ppEnumNetworkConnection) *ppEnumNetworkConnection = NULL;
    return S_FALSE;
}
static HRESULT STDMETHODCALLTYPE FN_GetTimeCreatedAndConnected(INetwork *pThis, DWORD *pdwLowDateTimeCreated, DWORD *pdwHighDateTimeCreated, DWORD *pdwLowDateTimeConnected, DWORD *pdwHighDateTimeConnected) {
    LogMsg("FakeNetwork::GetTimeCreatedAndConnected -> E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE FN_get_IsConnectedToInternet(INetwork *pThis, VARIANT_BOOL *pbIsConnected) {
    LogMsg("FakeNetwork::get_IsConnectedToInternet -> TRUE");
    if (pbIsConnected) *pbIsConnected = VARIANT_TRUE;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FN_get_IsConnected(INetwork *pThis, VARIANT_BOOL *pbIsConnected) {
    LogMsg("FakeNetwork::get_IsConnected -> TRUE");
    if (pbIsConnected) *pbIsConnected = VARIANT_TRUE;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FN_GetConnectivity(INetwork *pThis, NLM_CONNECTIVITY *pConnectivity) {
    LogMsg("FakeNetwork::GetConnectivity -> full");
    if (pConnectivity) *pConnectivity = NLM_CONNECTIVITY_IPV4_INTERNET | NLM_CONNECTIVITY_IPV4_LOCALNETWORK;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FN_GetCategory(INetwork *pThis, NLM_NETWORK_CATEGORY *pCategory) {
    LogMsg("FakeNetwork::GetCategory -> Private");
    if (pCategory) *pCategory = NLM_NETWORK_CATEGORY_PRIVATE;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FN_SetCategory(INetwork *pThis, NLM_NETWORK_CATEGORY NewCategory) {
    LogMsg("FakeNetwork::SetCategory -> E_NOTIMPL");
    return E_NOTIMPL;
}

// ---------- Vtable initialisation ----------
static void InitFakeNetworkVtable(void) {
    if (g_FakeNetworkVtable[0]) return;
    g_FakeNetworkVtable[0]  = &FN_QueryInterface;
    g_FakeNetworkVtable[1]  = &FN_AddRef;
    g_FakeNetworkVtable[2]  = &FN_Release;
    g_FakeNetworkVtable[3]  = &FN_GetTypeInfoCount;
    g_FakeNetworkVtable[4]  = &FN_GetTypeInfo;
    g_FakeNetworkVtable[5]  = &FN_GetIDsOfNames;
    g_FakeNetworkVtable[6]  = &FN_Invoke;
    g_FakeNetworkVtable[7]  = &FN_GetName;
    g_FakeNetworkVtable[8]  = &FN_SetName;
    g_FakeNetworkVtable[9]  = &FN_GetDescription;
    g_FakeNetworkVtable[10] = &FN_SetDescription;
    g_FakeNetworkVtable[11] = &FN_GetNetworkId;
    g_FakeNetworkVtable[12] = &FN_GetDomainType;
    g_FakeNetworkVtable[13] = &FN_GetNetworkConnections;
    g_FakeNetworkVtable[14] = &FN_GetTimeCreatedAndConnected;
    g_FakeNetworkVtable[15] = &FN_get_IsConnectedToInternet;
    g_FakeNetworkVtable[16] = &FN_get_IsConnected;
    g_FakeNetworkVtable[17] = &FN_GetConnectivity;
    g_FakeNetworkVtable[18] = &FN_GetCategory;
    g_FakeNetworkVtable[19] = &FN_SetCategory;
}

// ---------- Factory ----------
static INetwork* CreateFakeNetwork(void) {
    InitFakeNetworkVtable();
    FakeNetwork *obj = (FakeNetwork*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FakeNetwork));
    if (!obj) return NULL;
    obj->lpVtbl = g_FakeNetworkVtable;
    obj->refCount = 1;
    return (INetwork*)obj;
}






// ---------- IDispatch stubs ----------
static HRESULT STDMETHODCALLTYPE FNC_GetTypeInfoCount(INetworkConnection *pThis, UINT *pctinfo) {
    LogMsg("FakeNetConn::GetTypeInfoCount -> E_NOTIMPL");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE FNC_GetTypeInfo(INetworkConnection *pThis, UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo) {
    LogMsg("FakeNetConn::GetTypeInfo(iTInfo=%u) -> E_NOTIMPL", iTInfo);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE FNC_GetIDsOfNames(INetworkConnection *pThis, REFIID riid, OLECHAR **rgszNames, UINT cNames, LCID lcid, DISPID *rgDispId) {
    LogMsg("FakeNetConn::GetIDsOfNames(cNames=%u) -> E_NOTIMPL", cNames);
    if (cNames > 0 && rgszNames && rgszNames[0])
        LogMsg("  first name: %ls", rgszNames[0]);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE FNC_Invoke(INetworkConnection *pThis, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr) {
    LogMsg("FakeNetConn::Invoke(dispId=%ld, flags=0x%04X) -> E_NOTIMPL", dispIdMember, wFlags);
    return E_NOTIMPL;
}

// ---------- INetworkConnection methods ----------
static HRESULT STDMETHODCALLTYPE FNC_GetNetwork(INetworkConnection *pThis, INetwork **ppNetwork) {
    LogMsg("FakeNetConn::GetNetwork -> returning fake INetwork");
    if (ppNetwork) {
        *ppNetwork = CreateFakeNetwork();
        return (*ppNetwork) ? S_OK : E_OUTOFMEMORY;
    }
    return E_POINTER;
}
static HRESULT STDMETHODCALLTYPE FNC_IsConnectedToInternet(INetworkConnection *pThis, VARIANT_BOOL *pbIsConnected) {
    LogMsg("FakeNetConn::IsConnectedToInternet -> TRUE");
    if (pbIsConnected) *pbIsConnected = VARIANT_TRUE;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FNC_IsConnected(INetworkConnection *pThis, VARIANT_BOOL *pbIsConnected) {
    LogMsg("FakeNetConn::IsConnected -> TRUE");
    if (pbIsConnected) *pbIsConnected = VARIANT_TRUE;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FNC_GetAdapterId(INetworkConnection *pThis, GUID *pgdAdapterId) {
    LogMsg("FakeNetConn::GetAdapterId -> Radmin GUID");
    if (pgdAdapterId) CLSIDFromString(fake_settingID, pgdAdapterId);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FNC_GetDomainType(INetworkConnection *pThis, NLM_DOMAIN_TYPE *pDomainType) {
    LogMsg("FakeNetConn::GetDomainType -> NLM_DOMAIN_TYPE_AUTHENTICATED");
    if (pDomainType) *pDomainType = NLM_DOMAIN_TYPE_DOMAIN_AUTHENTICATED;  // 2 = authenticated network
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FNC_GetConnectionId(INetworkConnection *pThis, GUID *pgdConnectionId) {
    LogMsg("FakeNetConn::GetConnectionId -> Radmin GUID");
    if (pgdConnectionId) CLSIDFromString(fake_settingID, pgdConnectionId);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FNC_GetConnectivity(INetworkConnection *pThis, NLM_CONNECTIVITY *pConnectivity) {
    LogMsg("FakeNetConn::GetConnectivity -> full");
    if (pConnectivity) *pConnectivity = NLM_CONNECTIVITY_IPV4_INTERNET | NLM_CONNECTIVITY_IPV4_LOCALNETWORK;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE FNC_get_IsConnectedToInternet(INetworkConnection *pThis, VARIANT_BOOL *pbIsConnected) {
    LogMsg("FakeNetConn::get_IsConnectedToInternet -> TRUE");
    if (pbIsConnected) *pbIsConnected = VARIANT_TRUE;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE FNC_get_IsConnected(INetworkConnection *pThis, VARIANT_BOOL *pbIsConnected) {
    LogMsg("FakeNetConn::get_IsConnected -> TRUE");
    if (pbIsConnected) *pbIsConnected = VARIANT_TRUE;
    return S_OK;
}

static const INetworkConnectionVtbl g_FakeNetworkConnectionVtbl = {
    &FNC_QueryInterface,            // QueryInterface
    &FNC_AddRef,                    // AddRef
    &FNC_Release,                   // Release
    &FNC_GetTypeInfoCount,          // GetTypeInfoCount
    &FNC_GetTypeInfo,               // GetTypeInfo
    &FNC_GetIDsOfNames,             // GetIDsOfNames
    &FNC_Invoke,                    // Invoke
    &FNC_GetNetwork,                // GetNetwork
    &FNC_get_IsConnectedToInternet, // get_IsConnectedToInternet
    &FNC_get_IsConnected,           // get_IsConnected
    &FNC_GetConnectivity,           // GetConnectivity
    &FNC_GetConnectionId,           // GetConnectionId
    &FNC_GetAdapterId,              // GetAdapterId
    &FNC_GetDomainType              // GetDomainType
};

static INetworkConnection* CreateFakeNetworkConnection(void) {
    FakeNetworkConnection *obj = (FakeNetworkConnection*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FakeNetworkConnection));
    if (!obj) return NULL;
    obj->lpVtbl = (void*)&g_FakeNetworkConnectionVtbl;
    obj->refCount = 1;
    LogMsg("Created fake INetworkConnection");
    return (INetworkConnection*)obj;
}



static HRESULT STDMETHODCALLTYPE NLM_GetNetworkConnection(INetworkListManager *pThis, GUID gdNetworkConnectionId, INetworkConnection **ppNetworkConnection) {
    LogMsg("FakeNLM::GetNetworkConnection -> E_NOTIMPL");
    return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE NLM_IsConnectedToInternet(INetworkListManager *pThis, VARIANT_BOOL *pbIsConnected) {
    LogMsg("FakeNLM::IsConnectedToInternet -> TRUE");
    if (pbIsConnected) *pbIsConnected = VARIANT_TRUE;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE NLM_IsConnected(INetworkListManager *pThis, VARIANT_BOOL *pbIsConnected) {
    LogMsg("FakeNLM::IsConnected -> TRUE");
    if (pbIsConnected) *pbIsConnected = VARIANT_TRUE;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE NLM_GetConnectivity(INetworkListManager *pThis, NLM_CONNECTIVITY *pConnectivity) {
    LogMsg("FakeNLM::GetConnectivity -> full connectivity");
    // Full IPv4/IPv6 internet + local connectivity
    if (pConnectivity) *pConnectivity = (NLM_CONNECTIVITY)0;
    // NLM_CONNECTIVITY_IPV4_INTERNET = 0x40, IPV4_LOCALNETWORK = 0x10, etc.
    // For simplicity, we can set 0x40 | 0x10 = 0x50
    *pConnectivity = 0x50;
    return S_OK;
}

static void InitFakeNetworkListManagerVtable(void) {
    if (g_FakeNetworkListManagerVtable[0]) return;

    g_FakeNetworkListManagerVtable[0]  = &NLM_QueryInterface;
    g_FakeNetworkListManagerVtable[1]  = &NLM_AddRef;
    g_FakeNetworkListManagerVtable[2]  = &NLM_Release;
    // IDispatch (indexes 3-6)
    g_FakeNetworkListManagerVtable[3]  = &NLM_GetTypeInfoCount;
    g_FakeNetworkListManagerVtable[4]  = &NLM_GetTypeInfo;
    g_FakeNetworkListManagerVtable[5]  = &NLM_GetIDsOfNames;
    g_FakeNetworkListManagerVtable[6]  = &NLM_Invoke;
    // INetworkListManager (indexes 7-13)
    g_FakeNetworkListManagerVtable[7]  = &NLM_GetNetworks;
    g_FakeNetworkListManagerVtable[8]  = &NLM_GetNetwork;
    g_FakeNetworkListManagerVtable[9]  = &NLM_GetNetworkConnections;
    g_FakeNetworkListManagerVtable[10] = &NLM_GetNetworkConnection;
    g_FakeNetworkListManagerVtable[11] = &NLM_IsConnectedToInternet;
    g_FakeNetworkListManagerVtable[12] = &NLM_IsConnected;
    g_FakeNetworkListManagerVtable[13] = &NLM_GetConnectivity;
}

static INetworkListManager* CreateFakeNetworkListManager(void) {
    InitFakeNetworkListManagerVtable();
    FakeNetworkListManager *nlm = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*nlm));
    if (!nlm) return NULL;
    nlm->lpVtbl = g_FakeNetworkListManagerVtable;
    nlm->refCount = 1;
    return (INetworkListManager*)nlm;
}

// ----------------------------------------------------------------
// Global hook for VariantInit (oleaut32.dll) – no inline assembly
// ----------------------------------------------------------------
static void (WINAPI *TrueVariantInit)(VARIANTARG*) = NULL;
static BYTE* g_VariantInitTrampoline = NULL;

// ----------------------------------------------------------------
// Completely replace VariantInit with our own implementation
// ----------------------------------------------------------------
void WINAPI Fake_VariantInit(VARIANTARG *pvarg)
{
    if (pvarg) {
        LogMsg("Fake_VariantInit (pvarg=%p)", pvarg);
        V_VT(pvarg) = VT_EMPTY;         // the only thing the real function does
    }
}

void InstallVariantInitGlobalHook()
{
    HMODULE hMod = GetModuleHandleW(L"oleaut32.dll");
    if (!hMod) return;

    BYTE* realFunc = (BYTE*)GetProcAddress(hMod, "VariantInit");
    if (!realFunc) return;

    // Change memory protection to writable
    DWORD oldProtect;
    VirtualProtect(realFunc, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Write JMP rel32 (E9 xx xx xx xx) to Fake_VariantInit
    realFunc[0] = 0xE9;
    DWORD rel = (DWORD)Fake_VariantInit - ((DWORD)realFunc + 5);
    memcpy(realFunc + 1, &rel, 4);

    // Restore original protection
    VirtualProtect(realFunc, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), realFunc, 5);

    LogMsg("VariantInit now fully replaced (no real call)");
}

typedef void (WINAPI *ExitProcess_t)(UINT uExitCode);
typedef BOOL (WINAPI *TerminateProcess_t)(HANDLE hProcess, UINT uExitCode);
static ExitProcess_t Real_ExitProcess = NULL;
static TerminateProcess_t Real_TerminateProcess = NULL;

void WINAPI Hook_ExitProcess(UINT uExitCode)
{
    LogMsg("ExitProcess called with code %lu from 0x%p", uExitCode, GET_RETURN_ADDRESS());
    Real_ExitProcess(uExitCode);
}

BOOL WINAPI Hook_TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    LogMsg("TerminateProcess called with code %lu on handle %p from 0x%p", uExitCode, hProcess, GET_RETURN_ADDRESS());
    return Real_TerminateProcess(hProcess, uExitCode);
}

// ----------------------------------------------------------------
// Keep the service alive by blocking WaitForSingleObject on our
// fake driver handle (mimicking a real driver wait).
// ----------------------------------------------------------------

// Access the per‑handle context list from inject.c
typedef struct _HANDLE_CONTEXT {
    HANDLE  h;
    uint8_t mac[6];
    int     mac_set;
    OVERLAPPED* pending_read;
    struct _HANDLE_CONTEXT *next;
} HANDLE_CONTEXT;
extern HANDLE_CONTEXT* GetHandleContext(HANDLE h);

// Global event that never gets signaled (keeps the wait alive).
static HANDLE g_NeverSignaledEvent = NULL;

static HANDLE GetNeverSignaledEvent(void) {
    if (!g_NeverSignaledEvent)
        g_NeverSignaledEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    return g_NeverSignaledEvent;
}

typedef DWORD (WINAPI *WaitForSingleObject_t)(HANDLE hHandle, DWORD dwMilliseconds);
static WaitForSingleObject_t Real_WaitForSingleObject = NULL;

DWORD WINAPI Hook_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
{
    // Check if this handle is one of our emulated driver handles
    if (GetHandleContext(hHandle)) {
        LogMsg("WaitForSingleObject(h=0x%p, timeout=%lu) on driver handle – blocking forever",
               hHandle, dwMilliseconds);
        // Block the thread forever, just like the real driver would.
        Real_WaitForSingleObject(GetNeverSignaledEvent(), INFINITE);
        // Never reached – keeps the service process alive.
        return WAIT_OBJECT_0;   // unreachable
    }
    return Real_WaitForSingleObject(hHandle, dwMilliseconds);
}

// ------------------------------------------------------------
// Hook for sub_464650 in RvControlSvc.exe
// Logs MAC addresses as they are processed.
// ------------------------------------------------------------

// Signature of the original function (thiscall, returns int, takes two args)
typedef int (__thiscall *Sub464650_t)(void* ecx, void* edx);
static Sub464650_t Real_sub_464650 = NULL;

// Prototype of the internal formatting function sub_464520
// It takes: dest buffer, max chars, format string, 6 bytes...
typedef int (__cdecl *FormatMAC_t)(char* dest, int maxChars, const char* fmt,
                                   unsigned char b0, unsigned char b1,
                                   unsigned char b2, unsigned char b3,
                                   unsigned char b4, unsigned char b5);

// Replacement function – exact same signature as original
// int __thiscall Hook_sub_464650(void* dest, void* src)
// {
//     if (!src) return 0;                 // original null check

//     // 1. Copy 6 bytes from src to dest
//     memcpy(dest, src, 6);

//     unsigned char* mac = (unsigned char*)dest;

//     // 2. Log the raw bytes
//     LogMsg("RvControlSvc MAC raw: %02X:%02X:%02X:%02X:%02X:%02X",
//            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

//     // 3. Call the original formatting function (absolute address)
//     DWORD base = (DWORD)GetModuleHandle(NULL);
//     FormatMAC_t pFormat = (FormatMAC_t)(base + 0x464520);

//     char* formatted = (char*)dest + 6;          // destination buffer for string
//     pFormat(formatted, 0x12,                   // max 18 chars
//             "%02X:%02X:%02X:%02X:%02X:%02X",
//             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

//     // 4. Log the final formatted string
//     LogMsg("RvControlSvc MAC formatted: %s", formatted);

//     return 1;   // original success return
// }
#include <windows.h>
#include <psapi.h>                     // for MODULEINFO, GetModuleInformation
#pragma comment(lib, "psapi.lib")      // link against psapi
// Helper: find the .text section boundaries
BOOL GetTextSectionBounds(HMODULE hModule, BYTE** pBase, DWORD* pSize)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (memcmp(sec->Name, ".text", 5) == 0)  // careful: not null-terminated
        {
            *pBase = (BYTE*)hModule + sec->VirtualAddress;
            *pSize = sec->Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;  // .text section not found
}
// Helper: find .text section boundaries
BOOL GetTextSection(HMODULE hMod, BYTE** base, DWORD* size)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (memcmp(sec->Name, ".text", 5) == 0)
        {
            *base = (BYTE*)hMod + sec->VirtualAddress;
            *size = sec->Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}
BYTE* FindSub464650(void)
{
    HMODULE hExe = GetModuleHandle(NULL);
    if (!hExe) return NULL;

    BYTE *textBase;
    DWORD textSize;
    if (!GetTextSection(hExe, &textBase, &textSize)) return NULL;

    // Signature: ret 4 + start of the else branch
    BYTE sig[] = { 0xC2, 0x04, 0x00, 0x8B, 0x02, 0x89, 0x01 };

    for (DWORD i = 0; i < textSize - sizeof(sig); i++)
    {
        if (memcmp(textBase + i, sig, sizeof(sig)) == 0)
        {
            // Signature found at offset i → prologue is 0xD bytes earlier
            BYTE* candidate = textBase + i - 0x0D;
            // Optional sanity check: verify prologue starts with 55 8B EC
            if (candidate[0] == 0x55 && candidate[1] == 0x8B && candidate[2] == 0xEC)
                return candidate;
        }
    }
    return NULL;  // Not found
}
// Global to hold the resolved address of sub_464520
static FormatMAC_t g_pFormat = NULL;

int __thiscall Hook_sub_464650(void* dest, void* src)
{
    static volatile LONG inHook = 0;
    if (InterlockedExchange(&inHook, 1)) return 0;

    if (!src) {
        InterlockedExchange(&inHook, 0);
        return 0;
    }

    // 1. Copy 6 bytes
    memcpy(dest, src, 6);
    unsigned char* mac = (unsigned char*)dest;

    // 2. Log raw bytes
    LogMsg("RvControlSvc MAC raw: %02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // 3. Use the pre-resolved formatting function
    if (!g_pFormat) {
        LogMsg("RvControlSvc MAC hook: ERROR - sub_464520 not resolved!");
        InterlockedExchange(&inHook, 0);
        return 0;
    }

    // 4. Call the formatting function
    char* formatted = (char*)dest + 6;
    g_pFormat(formatted, 0x12,
              "%02X:%02X:%02X:%02X:%02X:%02X",
              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    LogMsg("RvControlSvc MAC formatted: %s", formatted);

    InterlockedExchange(&inHook, 0);
    return 1;
}

// Resolve sub_464520 from the original bytes at the call site
static FormatMAC_t ResolveSub464520(BYTE* pSub464650)
{
    // The `call sub_464520` is at pSub464650 + 0x44 (based on your disassembly)
    BYTE* callSite = pSub464650 + 0x44;
    
    // Verify it's actually an E8 call instruction
    if (callSite[0] != 0xE8) {
        LogMsg("RvControlSvc MAC hook: ERROR - expected E8 at %p, got 0x%02X", 
               callSite, callSite[0]);
        return NULL;
    }
    
    // Read the relative displacement
    INT rel32;
    memcpy(&rel32, callSite + 1, 4);
    
    // Calculate the absolute address
    FormatMAC_t pFormat = (FormatMAC_t)(callSite + 5 + rel32);
    
    LogMsg("RvControlSvc MAC hook: sub_464520 resolved to 0x%p (call at 0x%p, rel=0x%X)", 
           pFormat, callSite, rel32);
    
    return pFormat;
}

typedef void* (__fastcall *Sub4624e0_t)(void* arg1);

// ------------------------------------------------------------
// Replacement for sub_4624e0 – logs args, returns correct value
// ------------------------------------------------------------
static void* g_Data4ffd40 = NULL;   // address of data_4ffd40 (runtime)


static void* __fastcall Hook_sub_4624e0(void* arg1)
{
    // Get caller's return address - GCC/Clang compatible
    void* retAddr = __builtin_return_address(0);
    
    LogMsg("sub_4624e0(0x%p) called", arg1);
    
    // Log which module the caller belongs to
    if (retAddr != NULL) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(retAddr, &mbi, sizeof(mbi))) {
            HMODULE hCaller = (HMODULE)mbi.AllocationBase;
            wchar_t modName[MAX_PATH] = {0};
            if (GetModuleFileNameW(hCaller, modName, MAX_PATH)) {
                // Extract just the filename from full path
                wchar_t* fileName = wcsrchr(modName, L'\\');
                if (fileName) {
                    fileName++; // Skip the backslash
                } else {
                    fileName = modName;
                }
                LogMsg("  called from 0x%p [%ls+0x%X]", 
                       retAddr, 
                       fileName,
                       (DWORD)((BYTE*)retAddr - (BYTE*)hCaller));
            } else {
                LogMsg("  called from 0x%p [unknown module+0x%X]", 
                       retAddr,
                       (DWORD)((BYTE*)retAddr - (BYTE*)hCaller));
            }
        } else {
            LogMsg("  called from 0x%p [unable to query module]", retAddr);
        }
    }

    if (arg1 != NULL) {
        DWORD val4 = *(DWORD*)((BYTE*)arg1 + 4);
        DWORD val8 = *(DWORD*)((BYTE*)arg1 + 8);
        LogMsg("  [arg1+4]=0x%08lX, [arg1+8]=0x%08lX", val4, val8);

        const BYTE* data = (const BYTE*)arg1;
        const DWORD dumpLen = 128;
        LogMsg("  arg1 bytes (first %lu):", dumpLen);
        LogHex(data, dumpLen, "    ");

        char ascii[129];
        for (DWORD i = 0; i < dumpLen; i++) {
            unsigned char c = data[i];
            ascii[i] = (c >= 32 && c <= 126) ? c : '.';
        }
        ascii[dumpLen] = '\0';
        LogMsg("  ASCII: \"%s\"", ascii);
    }

    void* result = NULL;
    if (arg1 != NULL) {
        DWORD val4 = *(DWORD*)((BYTE*)arg1 + 4);
        DWORD val8 = *(DWORD*)((BYTE*)arg1 + 8);
        if (val8 && val4)
            result = (void*)val8;
        else
            result = g_Data4ffd40;
    } else {
        result = g_Data4ffd40;
    }

    LogMsg("  returned 0x%p", result);

    if (result != NULL) {
        // __try {
            const BYTE* retData = (const BYTE*)result;
            LogMsg("  return data (first 128 bytes):");
            LogHex(retData, 128, "    ");
            char retAscii[129];
            for (int i = 0; i < 128; i++) {
                unsigned char c = retData[i];
                retAscii[i] = (c >= 32 && c <= 126) ? c : '.';
            }
            retAscii[128] = '\0';
            LogMsg("  return ASCII: \"%s\"", retAscii);
        // } __except(EXCEPTION_EXECUTE_HANDLER) {
        //     LogMsg("  return data: (unreadable)");
        // }
    }

    return result;
}
void InstallRvControlSvcMacHook(void)
{
    BYTE* pOriginal = FindSub464650();
    
    if (!pOriginal) 
    {
        LogMsg("RvControlSvc MAC hook: ERROR - sub_464650 not found in .text section");
        return;
    }
    
    LogMsg("RvControlSvc MAC hook: sub_464650 found at 0x%p (offset 0x%X from base)", 
           pOriginal, 
           (DWORD)(pOriginal - (BYTE*)GetModuleHandle(NULL)));

    // Resolve sub_464520 BEFORE installing the hook
    // (so we read the original bytes, not our patched JMP)
    g_pFormat = ResolveSub464520(pOriginal);
    if (!g_pFormat) {
        LogMsg("RvControlSvc MAC hook: ERROR - failed to resolve sub_464520");
        return;
    }

    // Hook function address
    BYTE* pHook = (BYTE*)Hook_sub_464650;

    DWORD oldProtect;
    VirtualProtect(pOriginal, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    pOriginal[0] = 0xE9;
    INT rel = (INT)(pHook - (pOriginal + 5));
    memcpy(pOriginal + 1, &rel, 4);
    VirtualProtect(pOriginal, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), pOriginal, 5);

    LogMsg("RvControlSvc MAC hook: installed successfully, JMP 0x%p -> 0x%p", 
           pOriginal, pHook);

{
    // --- Compute absolute address of data_4ffd40 ---
g_Data4ffd40 = (void*)((BYTE*)GetModuleHandle(NULL) + 0x4FFD40);

// --- Hook sub_4624e0 ---
BYTE* pSub4624e0 = pOriginal + (0x4624e0 - 0x464650);   // -0x2170
LogMsg("RvControlSvc: sub_4624e0 at 0x%p (offset 0x%X from sub_464650)",
       pSub4624e0, (DWORD)(pSub4624e0 - pOriginal));

// Overwrite first 5 bytes with JMP to Hook_sub_4624e0
DWORD oldProtect;
VirtualProtect(pSub4624e0, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
pSub4624e0[0] = 0xE9;
DWORD rel = (DWORD)Hook_sub_4624e0 - (DWORD)(pSub4624e0 + 5);
memcpy(pSub4624e0 + 1, &rel, 4);
VirtualProtect(pSub4624e0, 5, oldProtect, &oldProtect);
FlushInstructionCache(GetCurrentProcess(), pSub4624e0, 5);

LogMsg("RvControlSvc: sub_4624e0 hook installed (replacement)");
}
}

// IPHLPAPI hooks
typedef DWORD (WINAPI *GetAdaptersInfo_t)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen);
typedef DWORD (WINAPI *GetAdaptersAddresses_t)(ULONG Family, ULONG Flags, PVOID Reserved,
                                               PIP_ADAPTER_ADDRESSES pAdapterAddresses, PULONG pOutBufLen);

static GetAdaptersInfo_t        Real_GetAdaptersInfo        = NULL;
static GetAdaptersAddresses_t   Real_GetAdaptersAddresses   = NULL;

DWORD WINAPI Hook_GetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen)
{
    LogMsg("GetAdaptersInfo called (BufSize=%lu)", pOutBufLen ? *pOutBufLen : 0);

#if BLOCK_REAL
    // ---------- Fake mode ----------
    InitFakeMac();   // ensure MAC is set

    const DWORD needed = sizeof(IP_ADAPTER_INFO) + 256;
    if (!pAdapterInfo || *pOutBufLen < needed) {
        *pOutBufLen = needed;
        LogMsg("  -> returning ERROR_BUFFER_OVERFLOW, needed=%lu", needed);
        return ERROR_BUFFER_OVERFLOW;
    }

    ZeroMemory(pAdapterInfo, needed);
    PIP_ADAPTER_INFO pInfo = pAdapterInfo;

    pInfo->Next = NULL;
    pInfo->ComboIndex = 0;

    // Convert fake_settingID (wchar_t) to ANSI for AdapterName
    char ansiGuid[64];
    WideCharToMultiByte(CP_ACP, 0, fake_settingID, -1, ansiGuid, sizeof(ansiGuid), NULL, NULL);
    strncpy(pInfo->AdapterName, ansiGuid, MAX_ADAPTER_NAME_LENGTH);
    pInfo->AdapterName[MAX_ADAPTER_NAME_LENGTH - 1] = '\0';

    // Convert fake_description (wchar_t) to ANSI for Description
    char ansiDesc[256];
    WideCharToMultiByte(CP_ACP, 0, fake_description, -1, ansiDesc, sizeof(ansiDesc), NULL, NULL);
    strncpy(pInfo->Description, ansiDesc, MAX_ADAPTER_DESCRIPTION_LENGTH);
    pInfo->Description[MAX_ADAPTER_DESCRIPTION_LENGTH - 1] = '\0';

    pInfo->AddressLength = 6;
    memcpy(pInfo->Address, fake_mac, 6);
    pInfo->Index = 1;
    pInfo->Type = MIB_IF_TYPE_ETHERNET;
    pInfo->DhcpEnabled = 0;
    pInfo->CurrentIpAddress = NULL;

    // Convert our fake IP strings to ANSI
    char ipBuf[16], maskBuf[16], gwBuf[16];
    WideCharToMultiByte(CP_ACP, 0, fake_ipAddress, -1, ipBuf, 16, NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, fake_ipSubnet, -1, maskBuf, 16, NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, fake_gateway, -1, gwBuf, 16, NULL, NULL);

    pInfo->IpAddressList.Next = NULL;
    strcpy(pInfo->IpAddressList.IpAddress.String, ipBuf);
    strcpy(pInfo->IpAddressList.IpMask.String, maskBuf);
    pInfo->IpAddressList.Context = 0;

    pInfo->GatewayList.Next = NULL;
    strcpy(pInfo->GatewayList.IpAddress.String, gwBuf);
    strcpy(pInfo->GatewayList.IpMask.String, "0.0.0.0");
    pInfo->GatewayList.Context = 0;

    pInfo->DhcpServer.Next = NULL;
    pInfo->DhcpServer.IpAddress.String[0] = 0;
    pInfo->DhcpServer.IpMask.String[0] = 0;
    pInfo->DhcpServer.Context = 0;

    pInfo->HaveWins = FALSE;
    pInfo->PrimaryWinsServer.Next = NULL;
    pInfo->SecondaryWinsServer.Next = NULL;
    pInfo->LeaseObtained = 0;
    pInfo->LeaseExpires = 0;

    LogMsg("  -> returning fake adapter (IP=%ls, MAC=%02X:%02X:%02X:%02X:%02X:%02X)",
           fake_ipAddress, fake_mac[0], fake_mac[1], fake_mac[2], fake_mac[3], fake_mac[4], fake_mac[5]);
    return ERROR_SUCCESS;
#else
    // ---------- Proxy mode ----------
    DWORD ret = Real_GetAdaptersInfo(pAdapterInfo, pOutBufLen);
    LogMsg("  -> real GetAdaptersInfo returned %lu", ret);
    if (ret == ERROR_SUCCESS && pAdapterInfo) {
        PIP_ADAPTER_INFO p = pAdapterInfo;
        while (p) {
            LogMsg("    Adapter: %s, IP=%s, Mask=%s, MAC=%02X:%02X:%02X:%02X:%02X:%02X",
                   p->Description,
                   p->IpAddressList.IpAddress.String,
                   p->IpAddressList.IpMask.String,
                   p->Address[0], p->Address[1], p->Address[2],
                   p->Address[3], p->Address[4], p->Address[5]);
            p = p->Next;
        }
    }
    return ret;
#endif
}

DWORD WINAPI Hook_GetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved,
                                       PIP_ADAPTER_ADDRESSES pAdapterAddresses, PULONG pOutBufLen)
{
    LogMsg("GetAdaptersAddresses called (Family=%lu, Flags=0x%lx, BufSize=%lu)",
           Family, Flags, pOutBufLen ? *pOutBufLen : 0);

#if BLOCK_REAL
    // ---------- Fake mode ----------
    InitFakeMac();

    if (Family != AF_INET && Family != AF_INET6 && Family != AF_UNSPEC) {
        if (pOutBufLen) *pOutBufLen = 0;
        return ERROR_NO_DATA;
    }

    // Calculate required buffer size
    const DWORD adapterSize = sizeof(IP_ADAPTER_ADDRESSES) + 256;
    const DWORD ipv4Size = (Family == AF_INET || Family == AF_UNSPEC) ? 
        (sizeof(IP_ADAPTER_UNICAST_ADDRESS) + sizeof(SOCKADDR_IN) + 16) : 0;
    const DWORD ipv6Size = (g_hasIPv6Address && (Family == AF_INET6 || Family == AF_UNSPEC)) ? 
        (sizeof(IP_ADAPTER_UNICAST_ADDRESS) + sizeof(SOCKADDR_IN6) + 16) : 0;
    const DWORD total = adapterSize + ipv4Size + ipv6Size;

    if (!pAdapterAddresses || *pOutBufLen < total) {
        *pOutBufLen = total;
        LogMsg("  -> returning ERROR_BUFFER_OVERFLOW, needed=%lu", total);
        return ERROR_BUFFER_OVERFLOW;
    }

    ZeroMemory(pAdapterAddresses, total);
    PIP_ADAPTER_ADDRESSES pAddr = pAdapterAddresses;

    pAddr->Length = sizeof(IP_ADAPTER_ADDRESSES);
    pAddr->IfIndex = 1;
    pAddr->Next = NULL;

    // AdapterName (ANSI GUID)
    pAddr->AdapterName = (char*)((BYTE*)pAddr + sizeof(IP_ADAPTER_ADDRESSES));
    char ansiGuid[64];
    WideCharToMultiByte(CP_ACP, 0, fake_settingID, -1, ansiGuid, sizeof(ansiGuid), NULL, NULL);
    strncpy(pAddr->AdapterName, ansiGuid, MAX_ADAPTER_NAME_LENGTH);
    pAddr->AdapterName[MAX_ADAPTER_NAME_LENGTH - 1] = '\0';

    // FriendlyName (Unicode)
    pAddr->FriendlyName = (wchar_t*)((BYTE*)pAddr->AdapterName + 64);
    wcscpy(pAddr->FriendlyName, fake_FriendlyName);

    // Description (Unicode)
    pAddr->Description = (wchar_t*)((BYTE*)pAddr->FriendlyName + 128);
    wcscpy(pAddr->Description, fake_description);

    pAddr->PhysicalAddressLength = 6;
    memcpy(pAddr->PhysicalAddress, fake_mac, 6);
    pAddr->IfType = IF_TYPE_ETHERNET_CSMACD;
    pAddr->OperStatus = IfOperStatusUp;
    pAddr->Flags = IP_ADAPTER_DDNS_ENABLED | IP_ADAPTER_DHCP_ENABLED;

    // --- IPv4 Unicast Address ---
    PIP_ADAPTER_UNICAST_ADDRESS pUni4 = NULL;
    if (Family == AF_INET || Family == AF_UNSPEC) {
        pUni4 = (PIP_ADAPTER_UNICAST_ADDRESS)((BYTE*)pAddr + adapterSize);
        pUni4->Length = sizeof(IP_ADAPTER_UNICAST_ADDRESS);
        pUni4->Next = NULL;
        pUni4->Address.lpSockaddr = (LPSOCKADDR)((BYTE*)pUni4 + sizeof(IP_ADAPTER_UNICAST_ADDRESS));
        LPSOCKADDR_IN pSock4 = (LPSOCKADDR_IN)pUni4->Address.lpSockaddr;
        pSock4->sin_family = AF_INET;
        pSock4->sin_port = 0;

        char ipAnsi[16];
        WideCharToMultiByte(CP_ACP, 0, fake_ipAddress, -1, ipAnsi, 16, NULL, NULL);
        pSock4->sin_addr.s_addr = inet_addr(ipAnsi);
        pUni4->Flags = IP_ADAPTER_ADDRESS_DNS_ELIGIBLE;

#if (_WIN32_WINNT >= 0x0600)
        // Determine prefix length from subnet mask string
        char maskAnsi[16];
        WideCharToMultiByte(CP_ACP, 0, fake_ipSubnet, -1, maskAnsi, 16, NULL, NULL);
        ULONG maskAddr = inet_addr(maskAnsi);
        // Count consecutive 1 bits (simple for /8, /16, /24, etc.)
        int prefixLen = 0;
        ULONG bit = 0x80000000;
        while (bit && (maskAddr & bit)) { prefixLen++; bit >>= 1; }
        pUni4->OnLinkPrefixLength = prefixLen;
#endif

        pAddr->FirstUnicastAddress = pUni4;
    } else {
        pAddr->FirstUnicastAddress = NULL;
    }

    // --- IPv6 Unicast Address (if available) ---
    if (g_hasIPv6Address && (Family == AF_INET6 || Family == AF_UNSPEC)) {
        PIP_ADAPTER_UNICAST_ADDRESS pUni6 = (PIP_ADAPTER_UNICAST_ADDRESS)(
            (BYTE*)pAddr + adapterSize + ipv4Size);
        pUni6->Length = sizeof(IP_ADAPTER_UNICAST_ADDRESS);
        pUni6->Next = NULL;
        pUni6->Address.lpSockaddr = (LPSOCKADDR)((BYTE*)pUni6 + sizeof(IP_ADAPTER_UNICAST_ADDRESS));
        LPSOCKADDR_IN6 pSock6 = (LPSOCKADDR_IN6)pUni6->Address.lpSockaddr;
        pSock6->sin6_family = AF_INET6;
        pSock6->sin6_port = 0;

        char ipv6Ansi[46];
        WideCharToMultiByte(CP_ACP, 0, g_fakeIPv6Address, -1, ipv6Ansi, sizeof(ipv6Ansi), NULL, NULL);
        inet_pton(AF_INET6, ipv6Ansi, &pSock6->sin6_addr);
        pUni6->Flags = IP_ADAPTER_ADDRESS_DNS_ELIGIBLE;
#if (_WIN32_WINNT >= 0x0600)
        pUni6->OnLinkPrefixLength = 64;   // typical /64 for IPv6
#endif

        // Link IPv4 -> IPv6 if both exist, otherwise set as first
        if (pUni4) {
            pUni4->Next = pUni6;
        } else {
            pAddr->FirstUnicastAddress = pUni6;
        }
    }

    pAddr->FirstAnycastAddress = NULL;
    pAddr->FirstMulticastAddress = NULL;
    pAddr->FirstDnsServerAddress = NULL;
    pAddr->DnsSuffix = NULL;

    // --- Gateway Address (IPv4 only for now) ---
    if (Family == AF_INET || Family == AF_UNSPEC) {
        PIP_ADAPTER_GATEWAY_ADDRESS pGateway = (PIP_ADAPTER_GATEWAY_ADDRESS)(
            (BYTE*)pAddr + adapterSize + ipv4Size + ipv6Size);
        pGateway->Length = sizeof(IP_ADAPTER_GATEWAY_ADDRESS);
        pGateway->Next = NULL;
        pGateway->Address.lpSockaddr = (LPSOCKADDR)((BYTE*)pGateway + sizeof(IP_ADAPTER_GATEWAY_ADDRESS));
        LPSOCKADDR_IN pGwSock = (LPSOCKADDR_IN)pGateway->Address.lpSockaddr;
        pGwSock->sin_family = AF_INET;
        pGwSock->sin_port = 0;

        char gwAnsi[16];
        WideCharToMultiByte(CP_ACP, 0, fake_gateway, -1, gwAnsi, 16, NULL, NULL);
        pGwSock->sin_addr.s_addr = inet_addr(gwAnsi);
        pAddr->FirstGatewayAddress = pGateway;
    } else {
        pAddr->FirstGatewayAddress = NULL;
    }

    LogMsg("  -> returning fake adapter (IPv4=%ls/%ls gw=%ls IPv6=%ls)",
           fake_ipAddress, fake_ipSubnet, fake_gateway,
           g_hasIPv6Address ? g_fakeIPv6Address : L"none");
    return ERROR_SUCCESS;
#else
    // ---------- Proxy mode ----------
    DWORD ret = Real_GetAdaptersAddresses(Family, Flags, Reserved, pAdapterAddresses, pOutBufLen);
    LogMsg("  -> real GetAdaptersAddresses returned %lu", ret);
    if (ret == ERROR_SUCCESS && pAdapterAddresses) {
        PIP_ADAPTER_ADDRESSES p = pAdapterAddresses;
        while (p) {
            LogMsg("    Adapter: %ls, Status=%d, MAC=%02X:%02X:%02X:%02X:%02X:%02X",
                   p->FriendlyName, p->OperStatus,
                   p->PhysicalAddress[0], p->PhysicalAddress[1], p->PhysicalAddress[2],
                   p->PhysicalAddress[3], p->PhysicalAddress[4], p->PhysicalAddress[5]);
            PIP_ADAPTER_UNICAST_ADDRESS ua = p->FirstUnicastAddress;
            while (ua) {
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    LPSOCKADDR_IN sin = (LPSOCKADDR_IN)ua->Address.lpSockaddr;
                    LogMsg("      IPv4: %s", inet_ntoa(sin->sin_addr));
                } else if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
                    LPSOCKADDR_IN6 sin6 = (LPSOCKADDR_IN6)ua->Address.lpSockaddr;
                    char ipv6Str[46];
                    inet_ntop(AF_INET6, &sin6->sin6_addr, ipv6Str, sizeof(ipv6Str));
                    LogMsg("      IPv6: %s", ipv6Str);
                }
                ua = ua->Next;
            }
            p = p->Next;
        }
    }
    return ret;
#endif
}


// ---------- Security hook definitions ----------
typedef LONG (WINAPI *RegSetKeySecurity_t)(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
typedef DWORD (WINAPI *SetSecurityInfo_t)(HANDLE, SE_OBJECT_TYPE, SECURITY_INFORMATION,
                                          PSID, PSID, PACL, PACL);

static SetSecurityInfo_t   Real_SetSecurityInfo   = NULL;



LSTATUS WINAPI Hook_RegGetKeySecurity(HKEY hKey, SECURITY_INFORMATION SecurityInformation,
                                       PSECURITY_DESCRIPTOR pSecurityDescriptor,
                                       LPDWORD lpcbSecurityDescriptor)
{
    LogMsg("RegGetKeySecurity(hKey=0x%p, si=0x%lx) -> access denied", hKey, SecurityInformation);
    // Simulate "access denied" to prevent the caller from trying to read security
    SetLastError(ERROR_ACCESS_DENIED);
    return ERROR_ACCESS_DENIED;
}

DWORD WINAPI Hook_SetSecurityInfo(HANDLE handle, SE_OBJECT_TYPE ObjectType,
                                  SECURITY_INFORMATION SecurityInfo,
                                  PSID psidOwner, PSID psidGroup,
                                  PACL pDacl, PACL pSacl)
{
    LogMsg("SetSecurityInfo(handle=0x%p, type=%u) -> BLOCKED", handle, ObjectType);
    return ERROR_SUCCESS;
}

// Helper to install a trampoline hook (plain C)
static void InstallTrampolineHook(const char* funcName, LPVOID hookFunc, LPVOID* realFuncOut)
{
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    if (!hAdvapi32) return;

    BYTE* target = (BYTE*)GetProcAddress(hAdvapi32, funcName);
    if (!target) {
        LogMsg("SecurityHook: %s not found in advapi32.dll", funcName);
        return;
    }

    // Create trampoline (copy first 5 bytes, then JMP back)
    BYTE* tramp = (BYTE*)VirtualAlloc(NULL, 10, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!tramp) {
        LogMsg("SecurityHook: VirtualAlloc failed for %s", funcName);
        return;
    }
    memcpy(tramp, target, 5);
    tramp[5] = 0xE9;   // JMP rel32
    DWORD relBack = (DWORD)(target + 5) - (DWORD)(tramp + 10);
    memcpy(tramp + 6, &relBack, 4);
    FlushInstructionCache(GetCurrentProcess(), tramp, 10);

    // Save real function (trampoline)
    *realFuncOut = tramp;

    // Patch original entry: JMP to hook
    DWORD oldProtect;
    VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    target[0] = 0xE9;
    DWORD relHook = (DWORD)hookFunc - (DWORD)(target + 5);
    memcpy(target + 1, &relHook, 4);
    VirtualProtect(target, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), target, 5);

    LogMsg("SecurityHook: %s hooked (trampoline at 0x%p)", funcName, tramp);
}

// ---- Security Descriptor low‑level APIs ----
typedef BOOL (WINAPI *InitializeSecurityDescriptor_t)(PSECURITY_DESCRIPTOR, DWORD);
typedef BOOL (WINAPI *InitializeAcl_t)(PACL, DWORD, DWORD);
typedef DWORD (WINAPI *GetLengthSid_t)(PSID);
typedef BOOL (WINAPI *IsValidSid_t)(PSID);
typedef BOOL (WINAPI *AddAccessAllowedAce_t)(PACL, DWORD, DWORD, PSID);
typedef BOOL (WINAPI *SetSecurityDescriptorDacl_t)(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL);
typedef BOOL (WINAPI *SetSecurityDescriptorOwner_t)(PSECURITY_DESCRIPTOR, PSID, BOOL);
typedef BOOL (WINAPI *IsValidSecurityDescriptor_t)(PSECURITY_DESCRIPTOR);

// Macro switch – set to 0 for fake, 1 for real
#define SECURITY_HOOKS_REAL 1

// ------------------------------------------------------------------
// Pointers to the real Advapi32 functions (must be initialised once)
// ------------------------------------------------------------------
typedef BOOL (WINAPI *Real_InitializeSecurityDescriptor_t)(PSECURITY_DESCRIPTOR, DWORD);
typedef BOOL (WINAPI *Real_InitializeAcl_t)(PACL, DWORD, DWORD);
typedef DWORD (WINAPI *Real_GetLengthSid_t)(PSID);
typedef BOOL (WINAPI *Real_IsValidSid_t)(PSID);
typedef BOOL (WINAPI *Real_AddAccessAllowedAce_t)(PACL, DWORD, DWORD, PSID);
typedef BOOL (WINAPI *Real_SetSecurityDescriptorDacl_t)(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL);
typedef BOOL (WINAPI *Real_SetSecurityDescriptorOwner_t)(PSECURITY_DESCRIPTOR, PSID, BOOL);
typedef BOOL (WINAPI *Real_IsValidSecurityDescriptor_t)(PSECURITY_DESCRIPTOR);

Real_InitializeSecurityDescriptor_t     Real_InitializeSecurityDescriptor     = NULL;
Real_InitializeAcl_t                    Real_InitializeAcl                    = NULL;
Real_GetLengthSid_t                     Real_GetLengthSid                     = NULL;
Real_IsValidSid_t                       Real_IsValidSid                       = NULL;
Real_AddAccessAllowedAce_t              Real_AddAccessAllowedAce              = NULL;
Real_SetSecurityDescriptorDacl_t        Real_SetSecurityDescriptorDacl        = NULL;
Real_SetSecurityDescriptorOwner_t       Real_SetSecurityDescriptorOwner       = NULL;
Real_IsValidSecurityDescriptor_t        Real_IsValidSecurityDescriptor        = NULL;

void InitRealSecurityHooks()
{
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    if (!hAdvapi32) return;

    Real_InitializeSecurityDescriptor  = (Real_InitializeSecurityDescriptor_t)
        GetProcAddress(hAdvapi32, "InitializeSecurityDescriptor");
    Real_InitializeAcl                 = (Real_InitializeAcl_t)
        GetProcAddress(hAdvapi32, "InitializeAcl");
    Real_GetLengthSid                  = (Real_GetLengthSid_t)
        GetProcAddress(hAdvapi32, "GetLengthSid");
    Real_IsValidSid                    = (Real_IsValidSid_t)
        GetProcAddress(hAdvapi32, "IsValidSid");
    Real_AddAccessAllowedAce           = (Real_AddAccessAllowedAce_t)
        GetProcAddress(hAdvapi32, "AddAccessAllowedAce");
    Real_SetSecurityDescriptorDacl     = (Real_SetSecurityDescriptorDacl_t)
        GetProcAddress(hAdvapi32, "SetSecurityDescriptorDacl");
    Real_SetSecurityDescriptorOwner    = (Real_SetSecurityDescriptorOwner_t)
        GetProcAddress(hAdvapi32, "SetSecurityDescriptorOwner");
    Real_IsValidSecurityDescriptor     = (Real_IsValidSecurityDescriptor_t)
        GetProcAddress(hAdvapi32, "IsValidSecurityDescriptor");
}

// ------------------------------------------------------------------
// Hooked functions – behaviour depends on SECURITY_HOOKS_REAL
// ------------------------------------------------------------------
BOOL WINAPI Hook_InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR pSD, DWORD dwRevision)
{
#if SECURITY_HOOKS_REAL
    LogMsg("--> Real InitializeSecurityDescriptor(pSD=%p, rev=%lu)", pSD, dwRevision);
    BOOL res = Real_InitializeSecurityDescriptor(pSD, dwRevision);
    LogMsg("<-- Real InitializeSecurityDescriptor returned %d", res);
    return res;
#else
    LogMsg("InitializeSecurityDescriptor(pSD=%p, rev=%lu)", pSD, dwRevision);
    return TRUE;
#endif
}

BOOL WINAPI Hook_InitializeAcl(PACL pAcl, DWORD nAclLength, DWORD dwAclRevision)
{
#if SECURITY_HOOKS_REAL
    LogMsg("--> Real InitializeAcl(pAcl=%p, len=%lu, rev=%lu)", pAcl, nAclLength, dwAclRevision);
    BOOL res = Real_InitializeAcl(pAcl, nAclLength, dwAclRevision);
    LogMsg("<-- Real InitializeAcl returned %d", res);
    return res;
#else
    LogMsg("InitializeAcl(pAcl=%p, len=%lu, rev=%lu)", pAcl, nAclLength, dwAclRevision);
    return TRUE;
#endif
}

DWORD WINAPI Hook_GetLengthSid(PSID pSid)
{
#if SECURITY_HOOKS_REAL
    LogMsg("--> Real GetLengthSid(pSid=%p)", pSid);
    DWORD res = Real_GetLengthSid(pSid);
    LogMsg("<-- Real GetLengthSid returned %lu", res);
    return res;
#else
    LogMsg("GetLengthSid(pSid=%p)", pSid);
    return 12;   // smallest valid SID (1 sub-authority)
#endif
}

BOOL WINAPI Hook_IsValidSid(PSID pSid)
{
#if SECURITY_HOOKS_REAL
    LogMsg("--> Real IsValidSid(pSid=%p)", pSid);
    BOOL res = Real_IsValidSid(pSid);
    LogMsg("<-- Real IsValidSid returned %d", res);
    return res;
#else
    LogMsg("IsValidSid(pSid=%p)", pSid);
    return TRUE;
#endif
}

BOOL WINAPI Hook_AddAccessAllowedAce(PACL pAcl, DWORD dwAceRevision, DWORD AccessMask, PSID pSid)
{
#if SECURITY_HOOKS_REAL
    LogMsg("--> Real AddAccessAllowedAce(pAcl=%p, rev=%lu, mask=0x%lX, sid=%p)",
           pAcl, dwAceRevision, AccessMask, pSid);
    BOOL res = Real_AddAccessAllowedAce(pAcl, dwAceRevision, AccessMask, pSid);
    LogMsg("<-- Real AddAccessAllowedAce returned %d", res);
    return res;
#else
    LogMsg("AddAccessAllowedAce(pAcl=%p, rev=%lu, mask=0x%lX, sid=%p)",
           pAcl, dwAceRevision, AccessMask, pSid);
    return TRUE;
#endif
}

BOOL WINAPI Hook_SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSD, BOOL bDaclPresent,
                                           PACL pDacl, BOOL bDaclDefaulted)
{
#if SECURITY_HOOKS_REAL
    LogMsg("--> Real SetSecurityDescriptorDacl(pSD=%p, present=%d, acl=%p, defaulted=%d)",
           pSD, bDaclPresent, pDacl, bDaclDefaulted);
    BOOL res = Real_SetSecurityDescriptorDacl(pSD, bDaclPresent, pDacl, bDaclDefaulted);
    LogMsg("<-- Real SetSecurityDescriptorDacl returned %d", res);
    return res;
#else
    LogMsg("SetSecurityDescriptorDacl(pSD=%p, present=%d, acl=%p, defaulted=%d)",
           pSD, bDaclPresent, pDacl, bDaclDefaulted);
    return TRUE;
#endif
}

BOOL WINAPI Hook_SetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR pSD, PSID pOwner,
                                            BOOL bOwnerDefaulted)
{
#if SECURITY_HOOKS_REAL
    LogMsg("--> Real SetSecurityDescriptorOwner(pSD=%p, owner=%p, defaulted=%d)",
           pSD, pOwner, bOwnerDefaulted);
    BOOL res = Real_SetSecurityDescriptorOwner(pSD, pOwner, bOwnerDefaulted);
    LogMsg("<-- Real SetSecurityDescriptorOwner returned %d", res);
    return res;
#else
    LogMsg("SetSecurityDescriptorOwner(pSD=%p, owner=%p, defaulted=%d)",
           pSD, pOwner, bOwnerDefaulted);
    return TRUE;
#endif
}

BOOL WINAPI Hook_IsValidSecurityDescriptor(PSECURITY_DESCRIPTOR pSD)
{
#if SECURITY_HOOKS_REAL
    LogMsg("--> Real IsValidSecurityDescriptor(pSD=%p)", pSD);
    BOOL res = Real_IsValidSecurityDescriptor(pSD);
    LogMsg("<-- Real IsValidSecurityDescriptor returned %d", res);
    return res;
#else
    LogMsg("IsValidSecurityDescriptor(pSD=%p) => TRUE", pSD);
    return TRUE;
#endif
}

typedef BOOL (WINAPI *AddAccessDeniedAce_t)(PACL, DWORD, DWORD, PSID);
typedef PVOID (WINAPI *FreeSid_t)(PSID);

// Optional – only needed if you want to store the real pointer (not used by the fakes)
static AddAccessDeniedAce_t Real_AddAccessDeniedAce = NULL;
static FreeSid_t           Real_FreeSid = NULL;

BOOL WINAPI Hook_AddAccessDeniedAce(PACL pAcl, DWORD dwAceRevision, DWORD AccessMask, PSID pSid)
{
    LogMsg("AddAccessDeniedAce(pAcl=%p, rev=%lu, mask=0x%lX, sid=%p) => TRUE", pAcl, dwAceRevision, AccessMask, pSid);
    return TRUE;
}

PVOID WINAPI Hook_FreeSid(PSID pSid)
{
    LogMsg("FreeSid(pSid=%p) => NULL (no-op)", pSid);
    // FreeSid normally returns NULL on success (weird, but that's the spec).
    // Since we don't allocate anything, we just return NULL.
    return NULL;
}


#ifdef REGISTER_HOOKS_REAL
typedef LSTATUS (WINAPI *RegGetKeySecurity_t)(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, LPDWORD);
typedef LSTATUS (WINAPI *RegSetKeySecurity_t)(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
static RegSetKeySecurity_t   Real_RegSetKeySecurity = NULL;
static RegGetKeySecurity_t   Real_RegGetKeySecurity = NULL;
LONG WINAPI Hook_RegSetKeySecurity(HKEY hKey, SECURITY_INFORMATION SecurityInformation,
                                   PSECURITY_DESCRIPTOR pSecurityDescriptor)
{
    LogMsg("RegSetKeySecurity(hKey=0x%p, si=0x%lX) -> BLOCKED", hKey, SecurityInformation);
    return ERROR_SUCCESS;
}
#endif

static void InstallSecurityHooks(HMODULE hAdvapi32)
{
    #ifdef REGISTER_HOOKS_REAL
        Real_RegSetKeySecurity   = (RegSetKeySecurity_t)GetProcAddress(hAdvapi32, "RegSetKeySecurity");
        Real_RegGetKeySecurity   = (RegGetKeySecurity_t)GetProcAddress(hAdvapi32, "RegGetKeySecurity");
    #endif
    InstallTrampolineHook("RegSetKeySecurity", Hook_RegSetKeySecurity, (LPVOID*)&Real_RegSetKeySecurity);
    InstallTrampolineHook("SetSecurityInfo",   Hook_SetSecurityInfo,   (LPVOID*)&Real_SetSecurityInfo);

    // Also patch IAT if present in the main executable
    HMODULE hExe = GetModuleHandle(NULL);
    if (Real_RegSetKeySecurity) {
        void* p = GetIATEntry(hExe, "advapi32.dll", "RegSetKeySecurity");
        if (p) PatchIAT(p, Hook_RegSetKeySecurity);
    }
    if (Real_SetSecurityInfo) {
        void* p = GetIATEntry(hExe, "advapi32.dll", "SetSecurityInfo");
        if (p) PatchIAT(p, Hook_SetSecurityInfo);
    }
    // Resolve real functions
    Real_InitializeSecurityDescriptor = (InitializeSecurityDescriptor_t)
        GetProcAddress(hAdvapi32, "InitializeSecurityDescriptor");
    Real_InitializeAcl = (InitializeAcl_t)
        GetProcAddress(hAdvapi32, "InitializeAcl");
    Real_GetLengthSid = (GetLengthSid_t)
        GetProcAddress(hAdvapi32, "GetLengthSid");
    Real_IsValidSid = (IsValidSid_t)
        GetProcAddress(hAdvapi32, "IsValidSid");
    Real_AddAccessAllowedAce = (AddAccessAllowedAce_t)
        GetProcAddress(hAdvapi32, "AddAccessAllowedAce");
    Real_SetSecurityDescriptorDacl = (SetSecurityDescriptorDacl_t)
        GetProcAddress(hAdvapi32, "SetSecurityDescriptorDacl");
    Real_SetSecurityDescriptorOwner = (SetSecurityDescriptorOwner_t)
        GetProcAddress(hAdvapi32, "SetSecurityDescriptorOwner");
    Real_IsValidSecurityDescriptor = (IsValidSecurityDescriptor_t)
        GetProcAddress(hAdvapi32, "IsValidSecurityDescriptor");

    // Install trampoline hooks
    if (Real_InitializeSecurityDescriptor)
        InstallTrampolineHook("InitializeSecurityDescriptor", Hook_InitializeSecurityDescriptor,
                              (LPVOID*)&Real_InitializeSecurityDescriptor);
    if (Real_InitializeAcl)
        InstallTrampolineHook("InitializeAcl", Hook_InitializeAcl,
                              (LPVOID*)&Real_InitializeAcl);
    if (Real_GetLengthSid)
        InstallTrampolineHook("GetLengthSid", Hook_GetLengthSid,
                              (LPVOID*)&Real_GetLengthSid);
    if (Real_IsValidSid)
        InstallTrampolineHook("IsValidSid", Hook_IsValidSid,
                              (LPVOID*)&Real_IsValidSid);
    if (Real_AddAccessAllowedAce)
        InstallTrampolineHook("AddAccessAllowedAce", Hook_AddAccessAllowedAce,
                              (LPVOID*)&Real_AddAccessAllowedAce);
    if (Real_SetSecurityDescriptorDacl)
        InstallTrampolineHook("SetSecurityDescriptorDacl", Hook_SetSecurityDescriptorDacl,
                              (LPVOID*)&Real_SetSecurityDescriptorDacl);
    if (Real_SetSecurityDescriptorOwner)
        InstallTrampolineHook("SetSecurityDescriptorOwner", Hook_SetSecurityDescriptorOwner,
                              (LPVOID*)&Real_SetSecurityDescriptorOwner);
    if (Real_IsValidSecurityDescriptor)
        InstallTrampolineHook("IsValidSecurityDescriptor", Hook_IsValidSecurityDescriptor,
                              (LPVOID*)&Real_IsValidSecurityDescriptor);

                                 // Resolve and store (optional, not needed for fakes)
    Real_AddAccessDeniedAce = (AddAccessDeniedAce_t)GetProcAddress(hAdvapi32, "AddAccessDeniedAce");
    Real_FreeSid = (FreeSid_t)GetProcAddress(hAdvapi32, "FreeSid");

    // Trampoline hooks (if your framework supports it)
    if (Real_AddAccessDeniedAce)
        InstallTrampolineHook("AddAccessDeniedAce", Hook_AddAccessDeniedAce, (LPVOID*)&Real_AddAccessDeniedAce);
    if (Real_FreeSid)
        InstallTrampolineHook("FreeSid", Hook_FreeSid, (LPVOID*)&Real_FreeSid);

    // Also patch the IAT of the main executable if you want to catch static imports
    #define PATCH_IAT_IF_NEEDED(name) \
        if (Real_##name) { \
            void* p = GetIATEntry(hExe, "advapi32.dll", #name); \
            if (p) PatchIAT(p, Hook_##name); \
        }

    PATCH_IAT_IF_NEEDED(InitializeSecurityDescriptor);
    PATCH_IAT_IF_NEEDED(InitializeAcl);
    PATCH_IAT_IF_NEEDED(GetLengthSid);
    PATCH_IAT_IF_NEEDED(IsValidSid);
    PATCH_IAT_IF_NEEDED(AddAccessAllowedAce);
    PATCH_IAT_IF_NEEDED(SetSecurityDescriptorDacl);
    PATCH_IAT_IF_NEEDED(SetSecurityDescriptorOwner);
    PATCH_IAT_IF_NEEDED(IsValidSecurityDescriptor);
    #undef PATCH_IAT_IF_NEEDED
}





#define PATCH_IAT_ENTRY(module, dll, func, hook)                     \
    do {                                                             \
        void *_p = GetIATEntry((module), (dll), (func));             \
        if (_p) {                                                    \
            PatchIAT(_p, (hook));                                    \
            LogMsg("Patched %s in %s", (func), #module);             \
        } else {                                                     \
            LogMsg("WARNING: %s not found in IAT of %s", (func), #module); \
        }                                                            \
    } while(0)
/* ===================================================================
 * Installation of all hooks
 * =================================================================== */

// #ifndef REGISTER_HOOKS_REAL
// static void SyncIPFromRegistry(void)
// {
//     RegKey* key = NavigatePath(g_regRoot, L"SOFTWARE\\Famatech\\RadminVPN\\1.0", FALSE);
//     if (!key) {
//         LogMsg("SyncIPFromRegistry: key not found");
//         return;
//     }

//     DWORD type, size;

//     // ----- IPv4 (REG_DWORD, network byte order) -----
//     if (GetValue(key, L"IPv4", &type, NULL, &size) && type == REG_DWORD && size == sizeof(DWORD))
//     {
//         DWORD ipDword;
//         if (GetValue(key, L"IPv4", NULL, (BYTE*)&ipDword, &size))
//         {
//             // Build the IP string from the raw bytes of the DWORD
//             BYTE b1 = (BYTE)(ipDword >> 24);
//             BYTE b2 = (BYTE)(ipDword >> 16);
//             BYTE b3 = (BYTE)(ipDword >> 8);
//             BYTE b4 = (BYTE)(ipDword);
//             swprintf(fake_ipAddress, 64, L"%u.%u.%u.%u", b1, b2, b3, b4);
//             LogMsg("SyncIPFromRegistry: IPv4 updated to %ls", fake_ipAddress);
//         }
//     }
//         // ----- IPv6 (REG_BINARY, 16 bytes) -----
//     if (GetValue(key, L"IPv6", &type, NULL, &size) && type == REG_BINARY && size == 16)
//     {
//         BYTE ip6[16];
//         if (GetValue(key, L"IPv6", NULL, ip6, &size))
//         {
//             char ip6str[INET6_ADDRSTRLEN];
//             inet_ntop(AF_INET6, ip6, ip6str, sizeof(ip6str));
//             MultiByteToWideChar(CP_ACP, 0, ip6str, -1, g_fakeIPv6Address, 64);
//             g_hasIPv6Address = TRUE;
//             LogMsg("SyncIPFromRegistry: IPv6 updated to %ls", g_fakeIPv6Address);
//         }
//     }
// }
// #endif

void EmulateDriverRunning_InstallHooks(HMODULE hOriginalDll)
{

    if (EnableRestorePrivilege()) {
        LogMsg("SeRestorePrivilege enabled — can read protected registry keys");
    } else {
        LogMsg("WARNING: SeRestorePrivilege not available (error %lu)", GetLastError());
    }

    if (hOriginalDll == NULL) {
        const wchar_t* wszOriginalDllName = L"RvROLClient.dll"; // adjust if name differs
        hOriginalDll = GetModuleHandleW(wszOriginalDllName);
        if (hOriginalDll == NULL) {
            hOriginalDll = LoadLibraryW(wszOriginalDllName);
            if (hOriginalDll == NULL) {
                LogMsg("ERROR: Cannot load original DLL %ls (error %lu)",
                       wszOriginalDllName, GetLastError());
                // Continue without patching the original DLL;
                // the macros will simply skip the hOriginalDll branch.
            } else {
                LogMsg("Loaded original DLL %ls, hModule = %p", wszOriginalDllName, hOriginalDll);
            }
        } else {
            LogMsg("Original DLL %ls already loaded, hModule = %p", wszOriginalDllName, hOriginalDll);
        }
    }


    HMODULE hExe = GetModuleHandle(NULL);

    // New macro: patches both the main executable and the original DLL (if valid)
    #define PATCH_IAT_EXE_AND_DLL(dll, func, hook)                      \
        do {                                                             \
            PATCH_IAT_ENTRY(hExe, dll, func, hook);                     \
            if (hOriginalDll) {                                          \
                PATCH_IAT_ENTRY(hOriginalDll, dll, func, hook);         \
            }                                                            \
        } while(0)


    #define PATCH_IAT_EXE_AND_DLL_AND_SELF(dll, func, hook)                      \
    do {                                                                      \
        PATCH_IAT_ENTRY(hExe, dll, func, hook);                              \
        if (hOriginalDll) {                                                   \
            PATCH_IAT_ENTRY(hOriginalDll, dll, func, hook);                  \
        }                                                                     \
        HMODULE hSelf = NULL;                                                 \
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |          \
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,     \
                           (LPCWSTR)&hook, &hSelf);                           \
        if (hSelf) {                                                          \
            PATCH_IAT_ENTRY(hSelf, dll, func, hook);                         \
        }                                                                     \
    } while(0)

    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    HMODULE hSetupapi = LoadLibraryW(L"setupapi.dll");
    HMODULE hOle32     = GetModuleHandleW(L"ole32.dll");


    Real_QueryServiceStatus     = (QueryServiceStatus_t)GetProcAddress(hAdvapi32, "QueryServiceStatus");
    Real_QueryServiceConfigW    = (QueryServiceConfigW_t)GetProcAddress(hAdvapi32, "QueryServiceConfigW");
    Real_OpenSCManagerW         = (OpenSCManagerW_t)GetProcAddress(hAdvapi32, "OpenSCManagerW");
    Real_OpenServiceW           = (OpenServiceW_t)GetProcAddress(hAdvapi32, "OpenServiceW");
    Real_StartServiceW          = (StartServiceW_t)GetProcAddress(hAdvapi32, "StartServiceW");

    Real_SetupDiGetClassDevsW            = (SetupDiGetClassDevsW_t)GetProcAddress(hSetupapi, "SetupDiGetClassDevsW");
    Real_SetupDiEnumDeviceInfo           = (SetupDiEnumDeviceInfo_t)GetProcAddress(hSetupapi, "SetupDiEnumDeviceInfo");
    Real_SetupDiGetDeviceRegistryPropertyW = (SetupDiGetDeviceRegistryPropertyW_t)GetProcAddress(hSetupapi, "SetupDiGetDeviceRegistryPropertyW");
    Real_CoCreateInstance = (CoCreateInstance_t)GetProcAddress(hOle32, "CoCreateInstance");


    // ===== Unified patches for service/registry (advapi32) =====
    PATCH_IAT_EXE_AND_DLL("advapi32.dll", "QueryServiceStatus", Hook_QueryServiceStatus);
    PATCH_IAT_EXE_AND_DLL("advapi32.dll", "QueryServiceConfigW", Hook_QueryServiceConfigW);
    PATCH_IAT_EXE_AND_DLL("advapi32.dll", "OpenSCManagerW", Hook_OpenSCManagerW);
    PATCH_IAT_EXE_AND_DLL("advapi32.dll", "OpenServiceW", Hook_OpenServiceW);
    PATCH_IAT_EXE_AND_DLL("advapi32.dll", "StartServiceW", Hook_StartServiceW);

#ifdef REGISTER_HOOKS_REAL   // ---------- log + real ----------
    PATCH_IAT_EXE_AND_DLL("advapi32.dll", "RegOpenKeyW",         Proxy_RegOpenKeyW);
    PATCH_IAT_EXE_AND_DLL("advapi32.dll", "RegOpenKeyExW",       Proxy_RegOpenKeyExW);
    PATCH_IAT_EXE_AND_DLL("advapi32.dll", "RegQueryValueExW",    Proxy_RegQueryValueExW);
    PATCH_IAT_EXE_AND_DLL("advapi32.dll", "RegCloseKey",         Proxy_RegCloseKey);
    PATCH_IAT_EXE_AND_DLL("advapi32.dll", "RegCreateKeyExW", Proxy_RegCreateKeyExW);
    PATCH_IAT_EXE_AND_DLL("advapi32.dll", "RegSetValueExW",  Proxy_RegSetValueExW);

    // Main‑exe‑only special cases
    void *p;
    p = GetIATEntry(hExe, "advapi32.dll", "RegDeleteValueW");
    if (p && Real_RegDeleteValueW) PatchIAT(p, Proxy_RegDeleteValueW);

    p = GetIATEntry(hExe, "advapi32.dll", "RegNotifyChangeKeyValue");
    if (p && Real_RegNotifyChangeKeyValue) PatchIAT(p, Proxy_RegNotifyChangeKeyValue);

#else                         // ---------- fake (emulated) ----------
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegOpenKeyW",            Hook_RegOpenKeyW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegOpenKeyExW",          Hook_RegOpenKeyExW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegQueryValueExW",       Hook_RegQueryValueExW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegCloseKey",            Hook_RegCloseKey);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegCreateKeyExW",        Hook_RegCreateKeyExW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegSetValueExW",         Hook_RegSetValueExW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegDeleteValueW",        Hook_RegDeleteValueW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegNotifyChangeKeyValue",Hook_RegNotifyChangeKeyValue);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegCreateKeyW",          Hook_RegCreateKeyW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegDeleteKeyW",          Hook_RegDeleteKeyW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegDeleteKeyExW",        Hook_RegDeleteKeyExW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegEnumKeyW",            Hook_RegEnumKeyW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegEnumKeyExW",          Hook_RegEnumKeyExW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegEnumValueW",          Hook_RegEnumValueW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegGetValueW",           Hook_RegGetValueW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegSetKeySecurity",      Hook_RegSetKeySecurity);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegGetKeySecurity",      Hook_RegGetKeySecurity);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegQueryInfoKeyW",       Hook_RegQueryInfoKeyW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegDeleteTreeW",         Hook_RegDeleteTreeW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegCopyTreeW",           Hook_RegCopyTreeW);
#endif

    #if REGISTER_HOOKS_REAL
        InitRealRegistryHooks();
    #else
        Register_InstallHooks(hOriginalDll, hAdvapi32); // It's for Wine (don't remove this comment)
        // Register_InstallHooks(hOriginalDll); // It's for Wine (don't remove this comment)
    #endif

    // ===== SetupAPI & COM hooks =====
    PATCH_IAT_EXE_AND_DLL("setupapi.dll", "SetupDiGetClassDevsW", Hook_SetupDiGetClassDevsW);
    PATCH_IAT_EXE_AND_DLL("setupapi.dll", "SetupDiEnumDeviceInfo", Hook_SetupDiEnumDeviceInfo);
    PATCH_IAT_EXE_AND_DLL("setupapi.dll", "SetupDiGetDeviceRegistryPropertyW", Hook_SetupDiGetDeviceRegistryPropertyW);
    PATCH_IAT_EXE_AND_DLL("ole32.dll", "CoCreateInstance", Hook_CoCreateInstance);

    // ===== Kernel32 hooks (CreateProcess) =====
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");

    Real_CreateProcessW = (CreateProcessW_t)GetProcAddress(hKernel32, "CreateProcessW");
    if (Real_CreateProcessW) {
        PATCH_IAT_EXE_AND_DLL("kernel32.dll", "CreateProcessW", Hook_CreateProcessW);
    }

    Real_CreateProcessAsUserW = (CreateProcessAsUserW_t)GetProcAddress(hKernel32, "CreateProcessAsUserW");
    if (Real_CreateProcessAsUserW) {
        PATCH_IAT_EXE_AND_DLL("kernel32.dll", "CreateProcessAsUserW", Hook_CreateProcessAsUserW);
    }

    InstallVariantInitGlobalHook();

    Real_ExitProcess = (ExitProcess_t)GetProcAddress(hKernel32, "ExitProcess");
    if (Real_ExitProcess) {
        PATCH_IAT_EXE_AND_DLL("kernel32.dll", "ExitProcess", Hook_ExitProcess);
    }
    Real_TerminateProcess = (TerminateProcess_t)GetProcAddress(hKernel32, "TerminateProcess");
    if (Real_TerminateProcess) {
        PATCH_IAT_EXE_AND_DLL("kernel32.dll", "TerminateProcess", Hook_TerminateProcess);
    }

    // WaitForSingleObject hook – keeps the service alive
    Real_WaitForSingleObject = (WaitForSingleObject_t)GetProcAddress(hKernel32, "WaitForSingleObject");
    if (Real_WaitForSingleObject) {
        PATCH_IAT_EXE_AND_DLL("kernel32.dll", "WaitForSingleObject", Hook_WaitForSingleObject);
    }

    // ===== IPHLPAPI hooks =====
    HMODULE hIphlpapi = GetModuleHandleW(L"iphlpapi.dll");
    if (hIphlpapi) {
        Real_GetAdaptersInfo = (GetAdaptersInfo_t)GetProcAddress(hIphlpapi, "GetAdaptersInfo");
        Real_GetAdaptersAddresses = (GetAdaptersAddresses_t)GetProcAddress(hIphlpapi, "GetAdaptersAddresses");
    }

    if (Real_GetAdaptersInfo) {
        PATCH_IAT_EXE_AND_DLL("iphlpapi.dll", "GetAdaptersInfo", Hook_GetAdaptersInfo);
    }
    if (Real_GetAdaptersAddresses) {
        PATCH_IAT_EXE_AND_DLL("iphlpapi.dll", "GetAdaptersAddresses", Hook_GetAdaptersAddresses);
    }



    // ===== Additional checks for specific executables =====
    wchar_t modName[MAX_PATH];
    GetModuleFileNameW(hExe, modName, MAX_PATH);
    if (wcsstr(modName, L"RvControlSvc.exe"))
    {
        // InstallRvControlSvcMacHook(); // TODO: only for testing
    }

    InstallSecurityHooks(hAdvapi32); 
    #ifndef REGISTER_HOOKS_REAL
    // SyncIPFromRegistry();
    #endif
    LogMsg("EmulateDriverRunning hooks installed.");
}