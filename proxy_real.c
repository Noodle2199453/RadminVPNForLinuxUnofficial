/*
 * proxy_real.c – Radmin VPN proxy hooks (USE_REAL_AND_PROXY=1)
 *
 * Forwards all device I/O to the real \\.\RVPNNETMP driver,
 * while still maintaining a fake handle for Radmin's bookkeeping.
 * All operations are logged in detail.
 */

#include <stdint.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

// ---------- types & globals shared with inject.c ----------
typedef struct _PENDING_READ {
    OVERLAPPED *ov;
    LPVOID      buffer;
    DWORD       buflen;
    SOCKET      sock;          // <-- new field
    struct _PENDING_READ *next;
} PENDING_READ;
typedef struct _HANDLE_CONTEXT {
    HANDLE   h;
    HANDLE   real_handle;
    uint8_t  mac[6];
    int      mac_set;
    PENDING_READ *pending_head;
    PENDING_READ *pending_tail;
    HANDLE   ready_event;
    OVERLAPPED* pending_read;
    LPVOID   pending_buffer;
    DWORD    pending_buflen;
    struct _HANDLE_CONTEXT *next;
} HANDLE_CONTEXT;

// ----- extern declarations (from inject.c) -----
extern CRITICAL_SECTION g_HandleListLock;
extern HANDLE_CONTEXT* g_HandleList;
extern LONG g_NextHandleId;

// Real API pointers (set in inject.c)
typedef HANDLE (WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *ReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *CloseHandle_t)(HANDLE);
typedef BOOL   (WINAPI *DeviceIoControl_t)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *GetOverlappedResult_t)(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);

extern CreateFileW_t      Real_CreateFileW;
extern ReadFile_t         Real_ReadFile;
extern WriteFile_t        Real_WriteFile;
extern CloseHandle_t      Real_CloseHandle;
extern DeviceIoControl_t  Real_DeviceIoControl;
extern GetOverlappedResult_t Real_GetOverlappedResult;

// Helper functions from inject.c
extern HANDLE_CONTEXT* AddFakeHandle(void);
extern void RemoveFakeHandle(HANDLE h);
extern HANDLE_CONTEXT* GetHandleContext(HANDLE h);

// Log functions from log.c
extern void LogMsg(const char *fmt, ...);
extern void LogHex(const BYTE *data, DWORD len, const char *prefix);

// ------------------------------------------------------------------
// Hook_CreateFileW – proxy: open real device, keep fake handle
// ------------------------------------------------------------------
HANDLE WINAPI Hook_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    if (lpFileName && wcscmp(lpFileName, L"\\\\.\\RVPNNETMP") == 0) {
        LogMsg("CreateFileW(RVPNNETMP) [proxy]");

        HANDLE_CONTEXT* ctx = AddFakeHandle();
        if (!ctx) {
            LogMsg("CreateFileW(RVPNNETMP) -> error: out of memory");
            SetLastError(ERROR_OUTOFMEMORY);
            return INVALID_HANDLE_VALUE;
        }

        HANDLE real = Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                                       lpSecurityAttributes, dwCreationDisposition,
                                       dwFlagsAndAttributes, hTemplateFile);
        if (real == INVALID_HANDLE_VALUE) {
            LogMsg("CreateFileW: real driver open FAILED (error %u)", GetLastError());
            RemoveFakeHandle(ctx->h);
            return INVALID_HANDLE_VALUE;
        }
        ctx->real_handle = real;
        LogMsg("CreateFileW -> fake handle 0x%p, real handle 0x%p", ctx->h, real);
        return ctx->h;
    }
    return Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                            lpSecurityAttributes, dwCreationDisposition,
                            dwFlagsAndAttributes, hTemplateFile);
}

// ------------------------------------------------------------------
// Hook_CloseHandle – proxy: close both handles
// ------------------------------------------------------------------
BOOL WINAPI Hook_CloseHandle(HANDLE hObject) {
    HANDLE_CONTEXT* ctx = GetHandleContext(hObject);
    if (ctx) {
        LogMsg("CloseHandle(0x%p) -> device closed [proxy]", hObject);
        RemoveFakeHandle(hObject);   // this also closes real_handle
        return TRUE;
    }
    return Real_CloseHandle(hObject);
}

// ------------------------------------------------------------------
// Hook_ReadFile – proxy: forward to real driver, log
// ------------------------------------------------------------------
BOOL WINAPI Hook_ReadFile(
    HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    HANDLE_CONTEXT* ctx = GetHandleContext(hFile);
    if (ctx) {
        BOOL result = Real_ReadFile(ctx->real_handle, lpBuffer, nNumberOfBytesToRead,
                                    lpNumberOfBytesRead, lpOverlapped);

        // Build a single log string (message + hex + ASCII)
        char logBuf[2048];
        int pos = 0;

        if (lpOverlapped && !result && GetLastError() == ERROR_IO_PENDING) {
            // Async pending
            pos = sprintf_s(logBuf, sizeof(logBuf),
                            "ReadFile(h=%p, buf=%p, ovlp=%p, len=%u) [proxy] -> async pending",
                            hFile, lpBuffer, lpOverlapped, nNumberOfBytesToRead);
            ctx->pending_buffer = lpBuffer;
            ctx->pending_buflen = nNumberOfBytesToRead;
        }
        else if (result && lpNumberOfBytesRead && *lpNumberOfBytesRead > 0) {
            DWORD bytesRead = *lpNumberOfBytesRead;
            DWORD displayLen = min(bytesRead, 256);

            // Main message with all handles and pointers
            pos = sprintf_s(logBuf, sizeof(logBuf),
                            "ReadFile(h=%p, buf=%p, ovlp=%p, req=%u) [proxy] -> %u bytes read\n  ReadData (%u bytes): ",
                            hFile, lpBuffer, lpOverlapped, nNumberOfBytesToRead, bytesRead, displayLen);

            // Append hex bytes
            for (DWORD i = 0; i < displayLen && pos < sizeof(logBuf) - 4; i++) {
                pos += sprintf_s(logBuf + pos, sizeof(logBuf) - pos,
                                "%02X ", ((const BYTE*)lpBuffer)[i]);
            }

            // Append ASCII dump
            pos += sprintf_s(logBuf + pos, sizeof(logBuf) - pos, "\n  ASCII: \"");
            for (DWORD i = 0; i < displayLen && pos < sizeof(logBuf) - 2; i++) {
                unsigned char c = ((const unsigned char*)lpBuffer)[i];
                logBuf[pos++] = (c >= 32 && c <= 126) ? c : '.';
            }
            logBuf[pos++] = '\"';
            logBuf[pos] = '\0';
        }
        else if (!result) {
            pos = sprintf_s(logBuf, sizeof(logBuf),
                            "ReadFile(h=%p, buf=%p, ovlp=%p, len=%u) [proxy] -> FAILED (error %u)",
                            hFile, lpBuffer, lpOverlapped, nNumberOfBytesToRead, GetLastError());
        }
        else {
            // Zero bytes, success
            pos = sprintf_s(logBuf, sizeof(logBuf),
                            "ReadFile(h=%p, buf=%p, ovlp=%p, len=%u) [proxy] -> 0 bytes read (success)",
                            hFile, lpBuffer, lpOverlapped, nNumberOfBytesToRead);
        }

        // Single log call – hybrid file/console output
        LogMsg("%s", logBuf);

        return result;
    }
    return Real_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead,
                         lpNumberOfBytesRead, lpOverlapped);
}

// ------------------------------------------------------------------
// Hook_WriteFile – proxy: log, then forward to real driver
// ------------------------------------------------------------------
BOOL WINAPI Hook_WriteFile(
    HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    HANDLE_CONTEXT* ctx = GetHandleContext(hFile);
    if (ctx) {
        LogMsgAndHex("WriteFile(h=0x%p, len=%u) [proxy]",
                     (const BYTE*)lpBuffer, min(nNumberOfBytesToWrite, 256),
                     "  WriteData",
                     hFile, nNumberOfBytesToWrite);
        
        return Real_WriteFile(ctx->real_handle, lpBuffer, nNumberOfBytesToWrite,
                              lpNumberOfBytesWritten, lpOverlapped);
    }
    return Real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
                          lpNumberOfBytesWritten, lpOverlapped);
}
// ------------------------------------------------------------------
// Hook_DeviceIoControl – proxy: forward to real driver, log i/o
// ------------------------------------------------------------------
BOOL WINAPI Hook_DeviceIoControl(
    HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer,
    DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize,
    LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)
{
    HANDLE_CONTEXT* ctx = GetHandleContext(hDevice);
    if (ctx) {
        LogMsg("DeviceIoControl(h=0x%p, code=0x%X, in=%u, out=%u) [proxy]",
               ctx->real_handle, dwIoControlCode, nInBufferSize, nOutBufferSize);
        if (nInBufferSize > 0)
            LogHex((const BYTE*)lpInBuffer, min(nInBufferSize, 256), "  Input");
    }

    BOOL ok = Real_DeviceIoControl(ctx->real_handle, dwIoControlCode, lpInBuffer,
                                   nInBufferSize, lpOutBuffer, nOutBufferSize,
                                   lpBytesReturned, lpOverlapped);

    if (ctx) {
        if (ok) {
            DWORD bytes = lpBytesReturned ? *lpBytesReturned : 0;
            LogMsg("DeviceIoControl succeeded, bytesReturned=%u", bytes);
            if (bytes > 0 && lpOutBuffer)
                LogHex((const BYTE*)lpOutBuffer, min(bytes, 256), "  Output");
        } else {
            LogMsg("DeviceIoControl FAILED (error %u)", GetLastError());
        }
    }
    return ok;
}

// ------------------------------------------------------------------
// Hook_GetOverlappedResult – proxy: forward, filter Radmin status msgs
// ------------------------------------------------------------------
BOOL WINAPI Hook_GetOverlappedResult(
    HANDLE hFile, LPOVERLAPPED lpOverlapped,
    LPDWORD lpNumberOfBytesTransferred, BOOL bWait)
{
    HANDLE_CONTEXT* ctx = GetHandleContext(hFile);
    if (ctx && ctx->real_handle != NULL) {
        BOOL result = Real_GetOverlappedResult(ctx->real_handle, lpOverlapped,
                                               lpNumberOfBytesTransferred, bWait);
        if (result && lpNumberOfBytesTransferred) {
            DWORD bytes = *lpNumberOfBytesTransferred;

            // ----- Filter out status messages -----
            BOOL is_status = FALSE;
            if (bytes >= 4 && ctx->pending_buffer) {
                uint32_t first_dword;
                memcpy(&first_dword, ctx->pending_buffer, sizeof(first_dword));
                if (first_dword != 0) {
                    is_status = TRUE;
                }
            }

            if (is_status) {
                LogMsgAndHex("GetOverlappedResult (proxy): hFile=%p, ovlp=%p, %u bytes - STATUS MESSAGE FILTERED",
                             (const BYTE*)ctx->pending_buffer, min(bytes, 64),
                             "  Filtered data",
                             hFile, lpOverlapped, bytes);   // params for fmt
                // Make the overlapped look pending again
                lpOverlapped->Internal = STATUS_PENDING;
                lpOverlapped->InternalHigh = 0;
                if (lpOverlapped->hEvent)
                    ResetEvent(lpOverlapped->hEvent);
                return FALSE;
            }

            // ----- Normal frame -----
            LogMsgAndHex("GetOverlappedResult (proxy): hFile=%p, ovlp=%p, %u bytes",
                         (const BYTE*)ctx->pending_buffer, bytes,
                         "  ReadData",
                         hFile, lpOverlapped, bytes);
            
            // Optional ASCII dump (still using LogMsg)
            if (ctx->pending_buffer) {
                char *ascii = (char*)HeapAlloc(GetProcessHeap(), 0, bytes + 1);
                if (ascii) {
                    for (DWORD i = 0; i < bytes; i++) {
                        unsigned char c = ((const unsigned char*)ctx->pending_buffer)[i];
                        ascii[i] = (c >= 32 && c <= 126) ? c : '.';
                    }
                    ascii[bytes] = '\0';
                    LogMsg("  ASCII: \"%s\"", ascii);
                    HeapFree(GetProcessHeap(), 0, ascii);
                }
                ctx->pending_buffer = NULL;
            }
        }
        return result;
    }

    return Real_GetOverlappedResult(hFile, lpOverlapped,
                                    lpNumberOfBytesTransferred, bWait);
}