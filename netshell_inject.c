/*
 * netshell_inject.c – Proxy netshell.dll with full logging stubs.
 *
 * Compile as a shared library (DLL).  Place the resulting netshell.dll
 * in the same directory as the target application.
 */

#include <windows.h>
#include <ole2.h>         // HRESULT, NETCON_PROPERTIES
#include <stdio.h>
#include <stdarg.h>
#include <netcon.h>

/* ===================================================================
 * Logging (console + file, identical to your existing code)
 * =================================================================== */
static FILE* g_LogFile = NULL;
static BOOL  g_ConsoleCreated = FALSE;

static void InitLog(void)
{
    if (AllocConsole()) {
        FILE* f;
        freopen_s(&f, "CONOUT$", "w", stdout);
        freopen_s(&f, "CONOUT$", "w", stderr);
        SetConsoleTitleW(L"Radmin VPN + WireGuard Emulation (netshell)");
        g_ConsoleCreated = TRUE;
    }

    char logPath[MAX_PATH];
    BOOL logOpened = FALSE;

    // Try temp directory first
    char tempPath[MAX_PATH];
    DWORD len = GetTempPathA(sizeof(tempPath), tempPath);
    if (len == 0 || len > MAX_PATH)
        strcpy_s(tempPath, sizeof(tempPath), "C:\\Windows\\Temp\\");

    sprintf_s(logPath, sizeof(logPath), "%srvpn_inject.log", tempPath);
    g_LogFile = fopen(logPath, "a");
    if (g_LogFile) {
        logOpened = TRUE;
    } else {
        // Fallback: log to the directory where this DLL is located
        HMODULE hMod;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)&InitLog, &hMod)) {
            char dllPath[MAX_PATH];
            if (GetModuleFileNameA(hMod, dllPath, sizeof(dllPath))) {
                char *lastSlash = strrchr(dllPath, '\\');
                if (lastSlash) {
                    *lastSlash = '\0';
                    sprintf_s(logPath, sizeof(logPath), "%s\\rvpn_inject.log", dllPath);
                    g_LogFile = fopen(logPath, "a");
                    if (g_LogFile) {
                        logOpened = TRUE;
                        if (g_ConsoleCreated)
                            printf("Logging to %s (temp path failed)\n", logPath);
                    }
                }
            }
        }
    }

    if (!g_LogFile) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_LogFile, "\n=== netshell proxy started (PID %lu) at %02d:%02d:%02d.%03d ===\n",
            GetCurrentProcessId(), st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    fflush(g_LogFile);
    if (g_ConsoleCreated)
        printf("=== netshell proxy started (PID %lu) ===\n", GetCurrentProcessId());
}

static void LogTimestamp(void)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    char ts[64];
    sprintf_s(ts, sizeof(ts), "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    if (g_LogFile) { fprintf(g_LogFile, "%s", ts); fflush(g_LogFile); }
    if (g_ConsoleCreated) printf("%s", ts);
}

static void LogMsg(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    char line[1024];
    vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);

    LogTimestamp();
    if (g_LogFile) { fprintf(g_LogFile, "%s\n", line); fflush(g_LogFile); }
    if (g_ConsoleCreated) printf("%s\n", line);
}

/* ================================================================
 * DllMain – initialise logging when loaded
 * ================================================================ */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        InitLog();
        LogMsg("netshell.dll proxy loaded");
    }
    return TRUE;
}

/* ================================================================
 * Export stubs (ordinals & names as listed)
 * ================================================================ */

// 1  DllCanUnloadNow
HRESULT WINAPI Fake_DllCanUnloadNow(void)
{
    LogMsg("DllCanUnloadNow -> S_OK");
    return S_OK;
}

// 2  DllGetClassObject
HRESULT WINAPI Fake_DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv)
{
    LogMsg("DllGetClassObject -> CLASS_E_CLASSNOTAVAILABLE");
    if (ppv) *ppv = NULL;
    return CLASS_E_CLASSNOTAVAILABLE;
}

// 3  DllRegisterServer
HRESULT WINAPI Fake_DllRegisterServer(void)
{
    LogMsg("DllRegisterServer -> S_OK");
    return S_OK;
}

// 4  DllUnregisterServer
HRESULT WINAPI Fake_DllUnregisterServer(void)
{
    LogMsg("DllUnregisterServer -> S_OK");
    return S_OK;
}

// 5  HrCreateDesktopIcon
HRESULT WINAPI Fake_HrCreateDesktopIcon(void)
{
    LogMsg("HrCreateDesktopIcon -> S_OK");
    return S_OK;
}

// 6  HrGetIconFromMediaType
HRESULT WINAPI Fake_HrGetIconFromMediaType(DWORD dwMediaType, HICON *phIcon)
{
    LogMsg("HrGetIconFromMediaType(%lu)", dwMediaType);
    if (phIcon) *phIcon = NULL;
    return E_NOTIMPL;
}

// 7  HrGetIconFromMediaTypeEx
HRESULT WINAPI Fake_HrGetIconFromMediaTypeEx(DWORD dwMediaType, DWORD dwFlags, HICON *phIcon)
{
    LogMsg("HrGetIconFromMediaTypeEx(%lu, 0x%lx)", dwMediaType, dwFlags);
    if (phIcon) *phIcon = NULL;
    return E_NOTIMPL;
}

// 8  HrLaunchConnection
HRESULT WINAPI Fake_HrLaunchConnection(void)
{
    LogMsg("HrLaunchConnection -> S_OK (suppressed)");
    return S_OK;
}

// 9  HrLaunchConnectionEx
HRESULT WINAPI Fake_HrLaunchConnectionEx(DWORD dwFlags)
{
    LogMsg("HrLaunchConnectionEx(0x%lx) -> S_OK", dwFlags);
    return S_OK;
}

// 10 HrLaunchPropertiesSheet
HRESULT WINAPI Fake_HrLaunchPropertiesSheet(void)
{
    LogMsg("HrLaunchPropertiesSheet -> S_OK");
    return S_OK;
}

// 11 HrRenameConnection
HRESULT WINAPI Fake_HrRenameConnection(void)
{
    LogMsg("HrRenameConnection -> S_OK");
    return S_OK;
}

// 12 NcFreeNetconProperties
HRESULT WINAPI Fake_NcFreeNetconProperties(NETCON_PROPERTIES *pProps)
{
    LogMsg("NcFreeNetconProperties(%p)", pProps);
    return S_OK;
}

// 13 NcIsValidConnectionName
BOOL WINAPI Fake_NcIsValidConnectionName(PCWSTR pszwConnectionName)
{
    LogMsg("NcIsValidConnectionName -> TRUE");
    return TRUE;
}

// 14 StartNCW
HRESULT WINAPI Fake_StartNCW(void)
{
    LogMsg("StartNCW -> S_OK");
    return S_OK;
}