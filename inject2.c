/*
 * inject2.c – Process‑specific injection for RvRvpnGui.exe
 *
 * This file is linked together with inject.c and version_proxy.c
 * to produce the fake version.dll proxy.  It is called from
 * version_proxy.c’s DllMain via run_injection2().
 */

#include <windows.h>
#include <stdio.h>
#include "register.h"
#include "iat_helpers.c"
#include "log.h"

/* The main registry‑hook installation function from inject.c          */
extern void Register_InstallHooks(HMODULE hOriginalDll,
                                  HMODULE hAdvapi32);



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
/* ------------------------------------------------------------------ */
/* run_injection2 – called by DllMain of version_proxy.c               */
/* ------------------------------------------------------------------ */
void run_injection2(void)
{
    wchar_t exePath[MAX_PATH];
    wchar_t *fileName;

    /* ---- 1. Get the current process name ---- */
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH))
        return;                         // should never fail

    fileName = wcsrchr(exePath, L'\\');
    if (fileName)
        fileName++;                     // skip the backslash
    else
        fileName = exePath;            // no path at all (unlikely)

    /* ---- 2. Initialise logging (console + file) ---- */
    InitLog();

    LogMsg("inject2: target process detected – installing registry hooks");

    /* ---- 3. Get advapi32.dll (already loaded in every process) ---- */
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    if (!hAdvapi32) {
        LogMsg("inject2: advapi32.dll not found, cannot install hooks");
        return;
    }

    /* ---- 4. Call the hook installer ---- */
    /*
     * hOriginalDll is not used by Register_InstallHooks,
     * so we can safely pass NULL.  If you want to keep symmetry,
     * pass the handle of this DLL (the fake version.dll).
     */


    #define PATCH_IAT_EXE_AND_DLL_AND_SELF(dll, func, hook)                      \
    do {                                                                      \
        PATCH_IAT_ENTRY(hExe, dll, func, hook);                              \
        HMODULE hSelf = NULL;                                                 \
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |          \
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,     \
                           (LPCWSTR)&hook, &hSelf);                           \
        if (hSelf) {                                                          \
            PATCH_IAT_ENTRY(hSelf, dll, func, hook);                         \
        }                                                                     \
    } while(0)

    HMODULE hExe = GetModuleHandle(NULL);
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
    // PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegSetKeySecurity",      Hook_RegSetKeySecurity);
    // PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegGetKeySecurity",      Hook_RegGetKeySecurity);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegQueryInfoKeyW",       Hook_RegQueryInfoKeyW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegDeleteTreeW",         Hook_RegDeleteTreeW);
    PATCH_IAT_EXE_AND_DLL_AND_SELF("advapi32.dll", "RegCopyTreeW",           Hook_RegCopyTreeW);
    Register_InstallHooks(NULL, hAdvapi32);

    LogMsg("inject2: hooks installed successfully");
}