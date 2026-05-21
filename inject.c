/*
 * inject.c – Radmin VPN emulation with  tunneling
 *
 * Hooks device I/O to \\.\RVPNNETMP and bridges it to
 * a userspace server.
 * Logs everything to %TEMP%\rvpn_inject.log (and console).
 */

#include "config.h"
#include <winsock2.h>        // for UDP socket
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wbemcli.h>
#include <netcfgx.h>
#include <netcfgn.h>
#include "iat_helpers.c"
#include "log.c"
#include "tap_client.h"   // new
#define USE_REAL_AND_PROXY 0

SOCKET g_SharedDataSocket = INVALID_SOCKET;   // created once in InitDriver
static app_config_t  g_AppCfg;
#define RADMIN_HEADER_SIZE  8

static volatile int g_TapCompletionActive = 0;

// Single completion thread
static HANDLE  g_hCompletionThread = NULL;
static volatile LONG g_CompletionActive = 0;

// Captured "no‑status‑change" message from real Radmin driver
static const uint8_t g_StatusPayload[] = {
    0x55, 0x00, 0x68, 0x2E, 0xC4, 0x05, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
};
static const DWORD g_StatusPayloadLen = sizeof(g_StatusPayload);

// Build the 8-byte header: 4 zero bytes + little‑endian frame length
static void radmin_header_write(uint8_t *hdr, uint32_t frame_len) {
    memset(hdr, 0, 4);
    hdr[4] = (uint8_t)(frame_len);
    hdr[5] = (uint8_t)(frame_len >> 8);
    hdr[6] = (uint8_t)(frame_len >> 16);
    hdr[7] = (uint8_t)(frame_len >> 24);
}

// Parse the header: return the Ethernet frame length, or 0 if invalid
static uint32_t radmin_header_read(const uint8_t *hdr) {
    // First 4 bytes are ignored; next 4 little‑endian length
    return hdr[4] | ((uint32_t)hdr[5] << 8) |
           ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 24);
}

int GetFakeMacAddress(uint8_t out_mac[6]);

static CRITICAL_SECTION g_HandleListLock;
/* ===================================================================
 * Per‑handle context (linked list)
 * =================================================================== */

typedef struct _PENDING_READ {
    OVERLAPPED *ov;
    LPVOID      buffer;
    DWORD       buflen;
    SOCKET      sock;          // <-- dedicated socket for this read
    struct _PENDING_READ *next;
} PENDING_READ;
typedef struct _HANDLE_CONTEXT {
    HANDLE   h;
    HANDLE   real_handle;
    uint8_t  mac[6];
    int      mac_set;
    PENDING_READ *pending_head;   // oldest
    PENDING_READ *pending_tail;   // newest
    HANDLE   ready_event;

    OVERLAPPED* pending_read;
    // For proxy logging of overlapped completion:
    LPVOID   pending_buffer;      // buffer from ReadFile
    DWORD    pending_buflen;      // number of bytes requested
    struct _HANDLE_CONTEXT *next;
} HANDLE_CONTEXT;

static HANDLE_CONTEXT* g_HandleList = NULL;

static LONG g_NextHandleId = 0x1000;

#if USE_REAL_AND_PROXY
    #include "proxy_real.c"
#endif

static int g_isAnyTAPDriverActive = 0;
static uint8_t g_TapMac[6] = {0};   // MAC of the TAP interface learned from incoming frames

#include "reg_read.c"

/* ===================================================================
 * Original API pointers (only kernel32, no advapi32)
 * =================================================================== */
typedef HANDLE (WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *ReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *CloseHandle_t)(HANDLE);
typedef BOOL   (WINAPI *DeviceIoControl_t)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);

CreateFileW_t    Real_CreateFileW    = NULL;
ReadFile_t       Real_ReadFile       = NULL;
WriteFile_t      Real_WriteFile      = NULL;
CloseHandle_t    Real_CloseHandle    = NULL;
DeviceIoControl_t Real_DeviceIoControl = NULL;

typedef BOOL (WINAPI *GetOverlappedResult_t)(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
GetOverlappedResult_t Real_GetOverlappedResult = NULL;

static void DriverSendPacket(const uint8_t *frame, int len, const uint8_t *src_mac) {
    TapClientSendFrame(frame, len);
}

void InitHandleList(void) {
    InitializeCriticalSection(&g_HandleListLock);
}

HANDLE_CONTEXT* AddFakeHandle(void) {
    HANDLE h = (HANDLE)(ULONG_PTR)InterlockedIncrement(&g_NextHandleId);
    HANDLE_CONTEXT* ctx = (HANDLE_CONTEXT*)HeapAlloc(GetProcessHeap(), 0, sizeof(HANDLE_CONTEXT));
    if (!ctx) return NULL;
    ctx->ready_event = CreateEvent(NULL, FALSE, FALSE, NULL);  // auto‑reset
    memset(ctx, 0, sizeof(*ctx));
    ctx->h = h;
    // real_handle is already 0
    EnterCriticalSection(&g_HandleListLock);
    ctx->next = g_HandleList;
    g_HandleList = ctx;
    LeaveCriticalSection(&g_HandleListLock);
    return ctx;
}

void RemoveFakeHandle(HANDLE h) {
    EnterCriticalSection(&g_HandleListLock);
    HANDLE_CONTEXT** pp = &g_HandleList;
    while (*pp) {
        if ((*pp)->h == h) {
            HANDLE_CONTEXT* toFree = *pp;
            *pp = toFree->next;
            LeaveCriticalSection(&g_HandleListLock);
            if (toFree->ready_event) CloseHandle(toFree->ready_event);
            if (toFree->real_handle != NULL && toFree->real_handle != INVALID_HANDLE_VALUE)
                Real_CloseHandle(toFree->real_handle);   // close the real driver handle
            HeapFree(GetProcessHeap(), 0, toFree);
            return;
        }
        pp = &((*pp)->next);
    }
    LeaveCriticalSection(&g_HandleListLock);
}

HANDLE_CONTEXT* GetHandleContext(HANDLE h) {
    EnterCriticalSection(&g_HandleListLock);
    for (HANDLE_CONTEXT* ctx = g_HandleList; ctx; ctx = ctx->next) {
        if (ctx->h == h) {
            LeaveCriticalSection(&g_HandleListLock);
            return ctx;
        }
    }
    LeaveCriticalSection(&g_HandleListLock);
    return NULL;
}

// Logging callback for config parser
void config_log(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    LogMsg("%s", buf);
}

static int InitDriver(void) {
  char dllPath[MAX_PATH];
  HMODULE hMod;
  GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                         GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                     (LPCSTR)&InitDriver, &hMod);
  GetModuleFileNameA(hMod, dllPath, sizeof(dllPath));
  char *p = strrchr(dllPath, '\\');
  if (p)
    *p = 0;
  char *dll_dir = dllPath;

  // 1. Load driver choice
  if (config_load(dll_dir, &g_AppCfg, config_log) != 0) {
    LogMsg("config_load failed");
    return -1;
  }
  // 3. Linux TAP backend – connect to the external process
  if (TapClientInit(g_AppCfg.tap_addr, g_AppCfg.tap_port) < 0) {
    LogMsg("TAP: connection failed");
    return -1;
  }
  LogMsg("TAP: connected to %s:%u", g_AppCfg.tap_addr, g_AppCfg.tap_port);

  // Start only the completion thread – no receiver thread needed.
  g_TapCompletionActive = 1;
  g_isAnyTAPDriverActive = 1;
  LogMsg("TAP active");
  return 0;
}

/* ===================================================================
 * Helper: check if a destination MAC matches the handle filter
 * =================================================================== */
static BOOL is_mac_match(const uint8_t *dest_mac, HANDLE_CONTEXT *ctx) {
    // If no MAC filter is set, reject everything (driver not configured)
    if (!ctx->mac_set)
        return FALSE;

    // Accept frames destined to the handle's specific MAC
    if (memcmp(dest_mac, ctx->mac, 6) == 0)
        return TRUE;

    // Accept all multicast/broadcast frames (bit 0 of first byte set)
    if (dest_mac[0] & 0x01)
        return TRUE;

    return FALSE;
}

/* ===================================================================
 * Hooked API implementations – EMULATION MODE (USE_REAL_AND_PROXY == 0)
 * =================================================================== */

#if USE_REAL_AND_PROXY == 0

HANDLE WINAPI Hook_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    if (lpFileName && wcscmp(lpFileName, L"\\\\.\\RVPNNETMP") == 0)
    {
        LogMsg("CreateFileW(RVPNNETMP)");

        // ---------- one‑time lazy init (after loader lock is free) ----------
        static volatile LONG initDone = 0;
        if (InterlockedCompareExchange(&initDone, 1, 0) == 0)
        {
            LogMsg("First CreateFileW – initialising driver & completion thread");
            // if (InitDriver() == 0)
            // {
            //     // g_CompletionActive = 1;
            //     // g_hCompletionThread = CreateThread(NULL, 0, TapCompletionThread, NULL, 0, NULL);
            //     LogMsg("Completion thread started");
            // }
            // else
            // {
            //     LogMsg("InitDriver failed");
            // }
        }

        HANDLE_CONTEXT* ctx = AddFakeHandle();
        if (!ctx)
        {
            LogMsg("CreateFileW(RVPNNETMP) -> error: out of memory");
            SetLastError(ERROR_OUTOFMEMORY);
            return INVALID_HANDLE_VALUE;
        }
        LogMsg("CreateFileW -> fake handle 0x%p", ctx->h);
        return ctx->h;
    }
    return Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                            lpSecurityAttributes, dwCreationDisposition,
                            dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI Hook_CloseHandle(HANDLE hObject) {
    HANDLE_CONTEXT* ctx = GetHandleContext(hObject);
    if (ctx) {
        LogMsg("CloseHandle(0x%p) -> device closed", hObject);
        RemoveFakeHandle(hObject);
        return TRUE;
    }
    return Real_CloseHandle(hObject);
}

BOOL GetFakeLocalMac(HANDLE_CONTEXT *ctx, uint8_t *macOut);

BOOL WINAPI Hook_ReadFile(
    HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    HANDLE_CONTEXT* ctx = GetHandleContext(hFile);
    if (ctx)
    {
        LogMsg("ReadFile(h=0x%p, len=%u)", hFile, nNumberOfBytesToRead);

        if (!g_isAnyTAPDriverActive)
        {
            SetLastError(ERROR_NO_DATA);
            if (lpNumberOfBytesRead) *lpNumberOfBytesRead = 0;
            return FALSE;
        }

        if (!lpOverlapped)
        {
            SetLastError(ERROR_NOT_SUPPORTED);
            return FALSE;
        }

        PENDING_READ *req = HeapAlloc(GetProcessHeap(), 0, sizeof(*req));
        if (!req)
        {
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }
        req->ov     = lpOverlapped;
        req->buffer = lpBuffer;
        req->buflen = nNumberOfBytesToRead;
        req->next   = NULL;
        req->sock   = INVALID_SOCKET;

        // Create a dedicated socket for EVERY read (no size check)
        SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s != INVALID_SOCKET)
        {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(g_AppCfg.tap_port);
            addr.sin_addr.s_addr = inet_addr(g_AppCfg.tap_addr);

            if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0)
            {
                u_long mode = 1;
                ioctlsocket(s, FIONBIO, &mode);
                WSAEventSelect(s, lpOverlapped->hEvent, FD_READ);
                req->sock = s;
                uint8_t regPacket[2] = {0x01, 0xFF};  // control, unused cmd
                send(s, (const char*)regPacket, sizeof(regPacket), 0);
                LogMsg("ReadFile: created socket for handle 0x%p", (void*)s);
            }
            else
            {
                LogMsg("ReadFile: socket connect failed (err=%d)", WSAGetLastError());
                closesocket(s);
                req->sock = INVALID_SOCKET;
            }
        }
        else
        {
            req->sock = INVALID_SOCKET;
        }

        EnterCriticalSection(&g_HandleListLock);
        if (ctx->pending_tail)
        {
            ctx->pending_tail->next = req;
            ctx->pending_tail = req;
        }
        else
        {
            ctx->pending_head = ctx->pending_tail = req;
        }
        LeaveCriticalSection(&g_HandleListLock);

        lpOverlapped->Internal = STATUS_PENDING;
        SetLastError(ERROR_IO_PENDING);
        return FALSE;
    }
    return Real_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead,
                         lpNumberOfBytesRead, lpOverlapped);
}

BOOL WINAPI Hook_WriteFile(
    HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    HANDLE_CONTEXT* ctx = GetHandleContext(hFile);
    if (ctx)
    {
        LogMsg("WriteFile(h=0x%p, len=%u)", hFile, nNumberOfBytesToWrite);
        LogHex((const BYTE*)lpBuffer, min(nNumberOfBytesToWrite, 64), "  Data");

        if (g_isAnyTAPDriverActive && nNumberOfBytesToWrite >= RADMIN_HEADER_SIZE)
        {
            const uint8_t *buf = (const uint8_t*)lpBuffer;
            uint32_t frame_len = radmin_header_read(buf);

            if (frame_len + RADMIN_HEADER_SIZE <= nNumberOfBytesToWrite)
            {
                const uint8_t *frame = buf + RADMIN_HEADER_SIZE;
                LogMsg("WriteFile: extracted Ethernet frame len=%u", frame_len);

                // ---- Send via a dedicated temporary socket ----
                SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
                if (s != INVALID_SOCKET)
                {
                    struct sockaddr_in addr;
                    memset(&addr, 0, sizeof(addr));
                    addr.sin_family = AF_INET;
                    addr.sin_port = htons(g_AppCfg.tap_port);
                    addr.sin_addr.s_addr = inet_addr(g_AppCfg.tap_addr);

                    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0)
                    {
                        // Build packet: 1 byte type (0x00) + Ethernet frame
                        uint8_t *pkt = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, 1 + frame_len);
                        if (pkt)
                        {
                            pkt[0] = 0x00;   // Ethernet frame type
                            memcpy(pkt + 1, frame, frame_len);
                            send(s, (const char*)pkt, 1 + frame_len, 0);
                            HeapFree(GetProcessHeap(), 0, pkt);
                        }
                    }
                    else
                    {
                        LogMsg("WriteFile: temporary socket connect failed (err=%d)", WSAGetLastError());
                    }
                    closesocket(s);
                }
                else
                {
                    LogMsg("WriteFile: socket creation failed (err=%d)", WSAGetLastError());
                }
            }
            else
            {
                LogMsg("WriteFile: header length %u exceeds buffer size %u",
                       frame_len, nNumberOfBytesToWrite - RADMIN_HEADER_SIZE);
            }
        }

        // Acknowledge the write synchronously
        if (lpNumberOfBytesWritten)
            *lpNumberOfBytesWritten = nNumberOfBytesToWrite;
        if (lpOverlapped)
        {
            lpOverlapped->Internal = 0;
            lpOverlapped->InternalHigh = nNumberOfBytesToWrite;
            SetEvent(lpOverlapped->hEvent);
        }
        return TRUE;
    }
    return Real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
                          lpNumberOfBytesWritten, lpOverlapped);
}

/**
 * GetFakeLocalMac – fills a 6‑byte buffer with the adapter’s current MAC.
 * Priority:
 *   1. The MAC explicitly set on this handle (IOCTL 0x228014).
 *   2. The WireGuard local MAC from wireguard.conf.
 * Returns TRUE on success.
 */
 BOOL GetFakeLocalMac(HANDLE_CONTEXT *ctx, uint8_t *macOut)
 {
     // 1. Use per‑handle MAC if available (only when a handle exists)
     if (ctx && ctx->mac_set) {
         memcpy(macOut, ctx->mac, 6);
         LogMsg("GetFakeLocalMac: using per‑handle MAC");
         return TRUE;
        }

    LogMsg("GetFakeLocalMac: no MAC available");
    return FALSE;
}
BOOL WINAPI Hook_DeviceIoControl(
    HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer,
    DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize,
    LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)
{
    HANDLE_CONTEXT* ctx = GetHandleContext(hDevice);

    if (!ctx)
        return Real_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer,
                                    nInBufferSize, lpOutBuffer, nOutBufferSize,
                                    lpBytesReturned, lpOverlapped);

    LogMsg("DeviceIoControl(h=0x%p, code=0x%X, in=%u, out=%u)",
           hDevice, dwIoControlCode, nInBufferSize, nOutBufferSize);
    if (nInBufferSize) LogHex((const BYTE*)lpInBuffer, nInBufferSize, "  Input");

    BOOL ok = TRUE;
    DWORD bytesRet = 0;

    switch (dwIoControlCode) {
    case 0x22C004:
        if (nInBufferSize >= 8 && nOutBufferSize >= 12) {
            BYTE out[12] = {0};
            uint8_t mac[6];
            if (GetFakeMacAddress(mac)) {
                memcpy(out + 4, mac, 6);
                bytesRet = 12;
                memcpy(lpOutBuffer, out, 12);
                LogHex(out, 12, "  Output (MAC at offset 4)");
            } else {
                ok = FALSE;
                SetLastError(ERROR_NOT_READY);
                LogMsg("  ERROR: GetFakeMacAddress failed");
            }
        } else {
            ok = FALSE;
            SetLastError(ERROR_INVALID_PARAMETER);
        }
        break;

    case 0x228014:
        if (nInBufferSize == 6) {
            memcpy(ctx->mac, lpInBuffer, 6);
            ctx->mac_set = 1;
            LogHex(ctx->mac, 6, "  MAC filter set to");
        } else {
            ok = FALSE;
            SetLastError(ERROR_INVALID_PARAMETER);
        }
        break;

    case 0x22801C:
        if (nInBufferSize >= 4) {
            DWORD type = *(DWORD*)lpInBuffer;
            LogMsg("  Set filter type = %u", type);
        } else {
            ok = FALSE;
            SetLastError(ERROR_INVALID_PARAMETER);
        }
        break;

    case 0x224018:
        if (nOutBufferSize >= 4) {
            *(DWORD*)lpOutBuffer = 0;
            bytesRet = 4;
            LogMsg("  Status flag = 0");
        } else {
            ok = FALSE;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
        }
        break;

    case 0x224020:
        if (nOutBufferSize >= 1) {
            *(BYTE*)lpOutBuffer = 0;
            bytesRet = 1;
            LogMsg("  Notification flag = 0");
        } else {
            ok = FALSE;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
        }
        break;

    default:
        LogMsg("  Unknown IOCTL -> no-op success");
        break;
    }

    if (lpBytesReturned) *lpBytesReturned = bytesRet;
    if (lpOverlapped) {
        lpOverlapped->Internal = ok ? 0 : ERROR_INVALID_PARAMETER;
        lpOverlapped->InternalHigh = bytesRet;
        if (lpOverlapped->hEvent) SetEvent(lpOverlapped->hEvent);
    }
    if (!ok)
        LogMsg("  Error %lu", GetLastError());
    else
        LogMsg("  result=TRUE, bytesReturned=%u", bytesRet);
    return ok;
}

BOOL WINAPI Hook_GetOverlappedResult(
    HANDLE hFile, LPOVERLAPPED lpOverlapped,
    LPDWORD lpNumberOfBytesTransferred, BOOL bWait)
{
    HANDLE_CONTEXT* ctx = GetHandleContext(hFile);
    if (!ctx)
        return Real_GetOverlappedResult(hFile, lpOverlapped,
                                        lpNumberOfBytesTransferred, bWait);

    // Already completed?
    if (lpOverlapped->Internal != STATUS_PENDING)
    {
        DWORD bytes = (DWORD)lpOverlapped->InternalHigh;
        if (lpNumberOfBytesTransferred) *lpNumberOfBytesTransferred = bytes;
        return TRUE;
    }

    // Find the matching request (under lock)
    EnterCriticalSection(&g_HandleListLock);
    PENDING_READ *prev = NULL, *req = ctx->pending_head;
    while (req && req->ov != lpOverlapped)
    {
        prev = req;
        req = req->next;
    }
    if (req)
    {
        if (prev) prev->next = req->next;
        else      ctx->pending_head = req->next;
        if (req == ctx->pending_tail) ctx->pending_tail = prev;
    }
    LeaveCriticalSection(&g_HandleListLock);

    if (!req)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    DWORD copyLen = 0;
    BOOL completed = FALSE;

    // Try to receive from the dedicated socket with MAC filtering
    if (req->sock != INVALID_SOCKET)
    {
        uint8_t frame[2048];
        while (1)
        {
            int n = recv(req->sock, (char*)frame, sizeof(frame), 0);
            if (n >= 14)   // type byte + Ethernet header
            {
                uint8_t *ethFrame = frame + 1;  // skip the leading 0x00
                int ethLen = n - 1;
                // Filter by handle's MAC
                if (is_mac_match(ethFrame, ctx))
                {
                    uint8_t outbuf[2048 + RADMIN_HEADER_SIZE];
                    radmin_header_write(outbuf, ethLen);
                    memcpy(outbuf + RADMIN_HEADER_SIZE, ethFrame, ethLen);
                    DWORD total = RADMIN_HEADER_SIZE + ethLen;
                    copyLen = min(total, req->buflen);
                    memcpy(req->buffer, outbuf, copyLen);
                    completed = TRUE;
                    LogMsg("GetOverlappedResult: matched frame for handle 0x%p (%u bytes)", hFile, copyLen);
                    break;
                }
                else
                {
                    // Mismatch – discard and try next packet
                    LogMsg("GetOverlappedResult: discarded frame (MAC mismatch)");
                    continue;
                }
            }
            else if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK)
            {
                // No more data available right now
                break;
            }
            else
            {
                // Error or empty – stop trying
                LogMsg("GetOverlappedResult: recv error %d", WSAGetLastError());
                break;
            }
        }
    }

    if (!completed)
    {
        // Re‑insert the request so the caller can wait again
        EnterCriticalSection(&g_HandleListLock);
        req->next = NULL;
        if (ctx->pending_tail)
        {
            ctx->pending_tail->next = req;
            ctx->pending_tail = req;
        }
        else
        {
            ctx->pending_head = ctx->pending_tail = req;
        }
        LeaveCriticalSection(&g_HandleListLock);
        SetLastError(ERROR_IO_INCOMPLETE);
        return FALSE;
    }

    // Successfully completed
    lpOverlapped->Internal = 0;
    lpOverlapped->InternalHigh = copyLen;
    if (lpOverlapped->hEvent) SetEvent(lpOverlapped->hEvent);  // just in case

    if (lpNumberOfBytesTransferred) *lpNumberOfBytesTransferred = copyLen;

    // Close the socket (one‑shot per read)
    if (req->sock != INVALID_SOCKET)
    {
        closesocket(req->sock);
        req->sock = INVALID_SOCKET;
    }
    HeapFree(GetProcessHeap(), 0, req);
    return TRUE;
}

#endif // !USE_REAL_AND_PROXY

/* ===================================================================
 * Install hooks (no service control hooks)
 * =================================================================== */

void EmulateDriverRunning_InstallHooks(HMODULE hOriginal);
void InstallHooks(void)
{
    HMODULE hExe = GetModuleHandle(NULL);
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");

    if (hKernel32) {
        Real_CreateFileW     = (CreateFileW_t)GetProcAddress(hKernel32, "CreateFileW");
        Real_ReadFile        = (ReadFile_t)GetProcAddress(hKernel32, "ReadFile");
        Real_WriteFile       = (WriteFile_t)GetProcAddress(hKernel32, "WriteFile");
        Real_CloseHandle     = (CloseHandle_t)GetProcAddress(hKernel32, "CloseHandle");
        Real_DeviceIoControl = (DeviceIoControl_t)GetProcAddress(hKernel32, "DeviceIoControl");
        Real_GetOverlappedResult = (GetOverlappedResult_t)GetProcAddress(hKernel32, "GetOverlappedResult");
    }

    void* p;
    p = GetIATEntry(hExe, "kernel32.dll", "CreateFileW");     if (p) PatchIAT(p, Hook_CreateFileW);
    p = GetIATEntry(hExe, "kernel32.dll", "ReadFile");         if (p) PatchIAT(p, Hook_ReadFile);
    p = GetIATEntry(hExe, "kernel32.dll", "WriteFile");        if (p) PatchIAT(p, Hook_WriteFile);
    p = GetIATEntry(hExe, "kernel32.dll", "CloseHandle");      if (p) PatchIAT(p, Hook_CloseHandle);
    p = GetIATEntry(hExe, "kernel32.dll", "DeviceIoControl");  if (p) PatchIAT(p, Hook_DeviceIoControl);
    p = GetIATEntry(hExe, "kernel32.dll", "GetOverlappedResult"); if (p) PatchIAT(p, Hook_GetOverlappedResult);
}

static LONG WINAPI MyUnhandledExceptionFilter(EXCEPTION_POINTERS* ExceptionInfo)
{
    if (ExceptionInfo) {
        DWORD code = ExceptionInfo->ExceptionRecord->ExceptionCode;
        void* addr = ExceptionInfo->ExceptionRecord->ExceptionAddress;
        LogMsg("!!! UNHANDLED EXCEPTION 0x%08lX at address 0x%p !!!", code, addr);
    } else {
        LogMsg("!!! UNHANDLED EXCEPTION (no exception info) !!!");
    }
    if (g_LogFile) fflush(g_LogFile);
    return EXCEPTION_CONTINUE_SEARCH;  // let the process crash as usual
}

/* ===================================================================
 * Entry point called from DllMain
 * =================================================================== */
void InitFakeMac(void);
void run_injection(HMODULE hOriginal)
{
    InitLog();
    SetUnhandledExceptionFilter(MyUnhandledExceptionFilter);
    InitHandleList();
    LogMsg("Installing device I/O hooks...");
    InstallHooks();
    #if USE_REAL_AND_PROXY == 0
    EmulateDriverRunning_InstallHooks(hOriginal);

    LogMsg("Initializing network driver...");
    if (InitDriver() == 0) {
        LogMsg("Driver online – bridging Radmin VPN to selected backend.");
    } else {
        LogMsg("ERROR: Driver init failed – Radmin traffic will NOT be forwarded.");
    }
    InitFakeMac();
    #endif
    // Log Registration data
    // TODO: This fails with Wine, because it uses Real
    LogMsg("=== Radmin VPN Registration ===");
    LogRegistryFolder(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Famatech\\RadminVPN\\1.0\\Registration", 0);

    // Log Proxy settings
    LogMsg("=== Radmin VPN Proxy ===");
    LogRegistryFolder(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Famatech\\RadminVPN\\1.0\\Proxy", 0);
}