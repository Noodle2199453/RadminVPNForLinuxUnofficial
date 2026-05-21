/*
 * version_proxy.c – version.dll proxy with emulation injection
 *
 * Compile together with inject.c to produce a version.dll
 * that:
 *   1. Forwards all real version.dll functions to System32\version.dll
 *   2. Forwards VerLanguageNameA/W to kernel32.dll (as real version.dll does)
 *   3. Calls run_injection() from inject.c to hook the process
 */

#include <windows.h>
#include <winver.h>        // for VerFindFileA, etc.

/* ===================================================================
 * Real DLL handles
 * =================================================================== */
static HMODULE g_hRealVersion = NULL;
static HMODULE g_hKernel32    = NULL;   // for VerLanguageNameA/W

/* ===================================================================
 * FORWARD macro (two lists: declaration and call arguments)
 * =================================================================== */
#define FORWARD(FUNC, RET, DECL, ARGS)                                 \
    RET WINAPI FUNC DECL {                                             \
        static RET (WINAPI *pReal) DECL = NULL;                       \
        if (!pReal) {                                                  \
            pReal = (RET (WINAPI *)DECL) GetProcAddress(g_hRealVersion, #FUNC); \
            if (!pReal) return (RET)0;                                 \
        }                                                              \
        return pReal ARGS;                                             \
    }

/* ===================================================================
 * Forwarded exports (from version.dll)
 * =================================================================== */
FORWARD(GetFileVersionInfoA,       BOOL,  (LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData), (lptstrFilename, dwHandle, dwLen, lpData))
FORWARD(GetFileVersionInfoW,       BOOL,  (LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData), (lptstrFilename, dwHandle, dwLen, lpData))
FORWARD(GetFileVersionInfoExA,     BOOL,  (DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData), (dwFlags, lpwstrFilename, dwHandle, dwLen, lpData))
FORWARD(GetFileVersionInfoExW,     BOOL,  (DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData), (dwFlags, lpwstrFilename, dwHandle, dwLen, lpData))
FORWARD(GetFileVersionInfoSizeA,   DWORD, (LPCSTR lptstrFilename, LPDWORD lpdwHandle), (lptstrFilename, lpdwHandle))
FORWARD(GetFileVersionInfoSizeW,   DWORD, (LPCWSTR lptstrFilename, LPDWORD lpdwHandle), (lptstrFilename, lpdwHandle))
FORWARD(GetFileVersionInfoSizeExA, DWORD, (DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle), (dwFlags, lpwstrFilename, lpdwHandle))
FORWARD(GetFileVersionInfoSizeExW, DWORD, (DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle), (dwFlags, lpwstrFilename, lpdwHandle))
FORWARD(VerFindFileA,              DWORD, (DWORD uFlags, LPSTR szFileName, LPSTR szWinDir, LPSTR szAppDir, LPSTR szCurDir, PUINT puCurDirLen, LPSTR szDestDir, PUINT puDestDirLen), (uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen))
FORWARD(VerFindFileW,              DWORD, (DWORD uFlags, LPWSTR szFileName, LPWSTR szWinDir, LPWSTR szAppDir, LPWSTR szCurDir, PUINT puCurDirLen, LPWSTR szDestDir, PUINT puDestDirLen), (uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen))
FORWARD(VerInstallFileA,           DWORD, (DWORD uFlags, LPSTR szSrcFileName, LPSTR szDestFileName, LPSTR szSrcDir, LPSTR szDestDir, LPSTR szCurDir, LPSTR szTmpFile, PUINT puTmpFileLen), (uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen))
FORWARD(VerInstallFileW,           DWORD, (DWORD uFlags, LPWSTR szSrcFileName, LPWSTR szDestFileName, LPWSTR szSrcDir, LPWSTR szDestDir, LPWSTR szCurDir, LPWSTR szTmpFile, PUINT puTmpFileLen), (uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen))FORWARD(VerQueryValueA,            BOOL,  (LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen), (pBlock, lpSubBlock, lplpBuffer, puLen))
FORWARD(VerQueryValueW,            BOOL,  (LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen), (pBlock, lpSubBlock, lplpBuffer, puLen))

/* ===================================================================
 * VerLanguageNameA/W – forwarded to kernel32.dll (not version.dll)
 * =================================================================== */
#define K32_FORWARD(FUNC, RET, DECL, ARGS)                             \
    RET WINAPI FUNC DECL {                                             \
        static RET (WINAPI *pReal) DECL = NULL;                       \
        if (!pReal) {                                                  \
            pReal = (RET (WINAPI *)DECL) GetProcAddress(g_hKernel32, #FUNC); \
            if (!pReal) return (RET)0;                                 \
        }                                                              \
        return pReal ARGS;                                             \
    }

K32_FORWARD(VerLanguageNameA, DWORD, (DWORD wLang, LPSTR szLang, DWORD cchLang), (wLang, szLang, cchLang))
K32_FORWARD(VerLanguageNameW, DWORD, (DWORD wLang, LPWSTR szLang, DWORD cchLang), (wLang, szLang, cchLang))

/* ===================================================================
 * DllMain – load real version.dll, kernel32, then inject
 * =================================================================== */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        char sysPath[MAX_PATH];
        GetSystemDirectoryA(sysPath, MAX_PATH);

        /* Load real version.dll */
        char verPath[MAX_PATH];
        strcpy_s(verPath, sizeof(verPath), sysPath);
        strcat_s(verPath, sizeof(verPath), "\\version.dll");
        g_hRealVersion = LoadLibraryA(verPath);
        if (!g_hRealVersion)
            return FALSE;

        /* Get kernel32 for VerLanguageNameA/W */
        g_hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!g_hKernel32)
            return FALSE;

        /* Run the injection code from inject.c */
        void run_injection2(void);   // declared in inject.c
        run_injection2();
    }
    else if (fdwReason == DLL_PROCESS_DETACH)
    {
        if (g_hRealVersion)
            FreeLibrary(g_hRealVersion);
    }
    return TRUE;
}