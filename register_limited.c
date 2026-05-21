#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

extern void LogMsg(const char *fmt, ...);
extern void LogHex(const BYTE *data, DWORD len, const char *prefix);
extern void* GetIATEntry(HMODULE module, const char *dllName, const char *funcName);
extern BOOL PatchIAT(void *iatEntry, void *hookFunc);

/* ---------- fake Registration key ---------- */
#define FAKE_REGISTRATION_KEY  ((HKEY)(ULONG_PTR)0x30000001)

static BYTE  g_serverPassword[256] = {0};
static DWORD g_serverPasswordSize = 0;
static DWORD g_serverPasswordType = REG_BINARY;   // default type


/* ---------- file persistence for ServerPassword ---------- */
static CRITICAL_SECTION g_passwordLock;            // protect in-memory copy
static wchar_t          g_passwordFilePath[MAX_PATH];

// Call once during initialisation to set the file path
static void InitPasswordFilePath(void)
{
    // Place the file next to the current module (e.g., the DLL that hooks)
    GetModuleFileNameW(NULL, g_passwordFilePath, MAX_PATH);
    wchar_t *p = wcsrchr(g_passwordFilePath, L'\\');
    if (p) *(p+1) = L'\0';
    wcscat(g_passwordFilePath, L"ServerPassword.dat");
}

// Load the stored password from disk
static void LoadServerPasswordFromFile(void)
{
    HANDLE hFile = CreateFileW(g_passwordFilePath, GENERIC_READ,
                                FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogMsg("ServerPassword.dat not found, starting with empty password");
        return;
    }

    // File format: [DWORD type][DWORD size][size bytes of data]
    DWORD type = 0, size = 0;
    DWORD read;
    if (!ReadFile(hFile, &type, sizeof(type), &read, NULL) || read != sizeof(type) ||
        !ReadFile(hFile, &size, sizeof(size), &read, NULL) || read != sizeof(size)) {
        LogMsg("Failed to read ServerPassword.dat header");
        CloseHandle(hFile);
        return;
    }

    if (size > sizeof(g_serverPassword)) {
        LogMsg("ServerPassword.dat data too large (%lu), truncating", size);
        size = sizeof(g_serverPassword);
    }

    if (!ReadFile(hFile, g_serverPassword, size, &read, NULL) || read != size) {
        LogMsg("Failed to read ServerPassword.dat data");
        CloseHandle(hFile);
        return;
    }

    g_serverPasswordType = type;
    g_serverPasswordSize = size;
    CloseHandle(hFile);
    LogMsg("Loaded ServerPassword (type=%lu, size=%lu)", type, size);
}

// Write the current password to disk (call after every change)
static void SaveServerPasswordToFile(void)
{
    HANDLE hFile = CreateFileW(g_passwordFilePath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogMsg("Cannot create ServerPassword.dat (error %lu)", GetLastError());
        return;
    }

    DWORD written;
    WriteFile(hFile, &g_serverPasswordType, sizeof(g_serverPasswordType), &written, NULL);
    WriteFile(hFile, &g_serverPasswordSize, sizeof(g_serverPasswordSize), &written, NULL);
    if (g_serverPasswordSize > 0)
        WriteFile(hFile, g_serverPassword, g_serverPasswordSize, &written, NULL);
    CloseHandle(hFile);
    LogMsg("ServerPassword saved to file");
}


/* ---------- real API pointers ---------- */
typedef LSTATUS (WINAPI *RegOpenKeyW_t)(HKEY, LPCWSTR, PHKEY);
typedef LSTATUS (WINAPI *RegOpenKeyExW_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS (WINAPI *RegCreateKeyExW_t)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM,
                                            const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LSTATUS (WINAPI *RegSetValueExW_t)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS (WINAPI *RegQueryValueExW_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS (WINAPI *RegCloseKey_t)(HKEY);
typedef LSTATUS (WINAPI *RegDeleteValueW_t)(HKEY, LPCWSTR);
typedef LSTATUS (WINAPI *RegNotifyChangeKeyValue_t)(HKEY, BOOL, DWORD, HANDLE, BOOL);

static RegOpenKeyW_t           Real_RegOpenKeyW           = NULL;
static RegOpenKeyExW_t         Real_RegOpenKeyExW         = NULL;
static RegCreateKeyExW_t       Real_RegCreateKeyExW       = NULL;
static RegSetValueExW_t        Real_RegSetValueExW        = NULL;
static RegQueryValueExW_t      Real_RegQueryValueExW      = NULL;
static RegCloseKey_t           Real_RegCloseKey           = NULL;
static RegDeleteValueW_t       Real_RegDeleteValueW       = NULL;
static RegNotifyChangeKeyValue_t Real_RegNotifyChangeKeyValue = NULL;

/* ---------- helper: case‑insensitive string compare ---------- */
static int StrCmpIW(LPCWSTR a, LPCWSTR b)
{
    if (!a && !b) return 0;
    if (!a || !b) return -1;
    while (*a && *b) {
        int diff = towlower(*a) - towlower(*b);
        if (diff) return diff;
        a++; b++;
    }
    return (*a != 0) - (*b != 0);
}

/* ---------- hook implementations ---------- */
LSTATUS WINAPI Hook_RegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
    LogMsg("RegOpenKeyW(hKey=0x%p, subKey=%ls)", hKey, lpSubKey ? lpSubKey : L"(null)");

    if (lpSubKey && StrCmpIW(lpSubKey, L"Registration") == 0) {
        *phkResult = FAKE_REGISTRATION_KEY;
        LogMsg("  -> fake Registration key 0x%p", *phkResult);
        return ERROR_SUCCESS;
    }

    LSTATUS result = Real_RegOpenKeyW ? Real_RegOpenKeyW(hKey, lpSubKey, phkResult)
                                      : ERROR_FILE_NOT_FOUND;
    LogMsg("  -> real result = %ld, handle = 0x%p", result, *phkResult);
    return result;
}

LSTATUS WINAPI Hook_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions,
                                  REGSAM samDesired, PHKEY phkResult)
{
    LogMsg("RegOpenKeyExW(hKey=0x%p, subKey=%ls, options=0x%lx, sam=0x%lx)",
           hKey, lpSubKey ? lpSubKey : L"(null)", ulOptions, samDesired);

    if (lpSubKey && StrCmpIW(lpSubKey, L"Registration") == 0) {
        *phkResult = FAKE_REGISTRATION_KEY;
        LogMsg("  -> fake Registration key 0x%p", *phkResult);
        return ERROR_SUCCESS;
    }

    LSTATUS result = Real_RegOpenKeyExW ? Real_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult)
                                        : ERROR_FILE_NOT_FOUND;
    LogMsg("  -> real result = %ld, handle = 0x%p", result, *phkResult);
    return result;
}

LSTATUS WINAPI Hook_RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved,
                                    LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired,
                                    const LPSECURITY_ATTRIBUTES lpSec, PHKEY phkResult,
                                    LPDWORD lpdwDisposition)
{
    LogMsg("RegCreateKeyExW(hKey=0x%p, subKey=%ls)", hKey, lpSubKey ? lpSubKey : L"(null)");

    if (lpSubKey && StrCmpIW(lpSubKey, L"Registration") == 0) {
        *phkResult = FAKE_REGISTRATION_KEY;
        if (lpdwDisposition) *lpdwDisposition = REG_OPENED_EXISTING_KEY;  // always "exists"
        LogMsg("  -> fake Registration key 0x%p", *phkResult);
        return ERROR_SUCCESS;
    }

    LSTATUS result = Real_RegCreateKeyExW ? Real_RegCreateKeyExW(hKey, lpSubKey, Reserved,
                                                                  lpClass, dwOptions, samDesired,
                                                                  lpSec, phkResult, lpdwDisposition)
                                          : ERROR_FILE_NOT_FOUND;
    LogMsg("  -> real result = %ld, handle = 0x%p, disposition = %lu",
           result, *phkResult, lpdwDisposition ? *lpdwDisposition : 0);
    return result;
}

LSTATUS WINAPI Hook_RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved,
                                   DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    LogMsg("RegSetValueExW(hKey=0x%p, value=%ls, type=%lu, size=%lu)",
           hKey, lpValueName ? lpValueName : L"(default)", dwType, cbData);

    if (hKey == FAKE_REGISTRATION_KEY) {
        
        if (lpValueName && StrCmpIW(lpValueName, L"ServerPassword") == 0) {
            if (cbData > sizeof(g_serverPassword)) {
                LogMsg("  -> data too large (%lu bytes), truncating", cbData);
                cbData = sizeof(g_serverPassword);
            }
            memcpy(g_serverPassword, lpData, cbData);
            g_serverPasswordSize = cbData;
            g_serverPasswordType = dwType;
            LogMsg("  -> ServerPassword stored (type=%lu, size=%lu)", dwType, cbData);
            SaveServerPasswordToFile();
            return ERROR_SUCCESS;
        } else {
            LogMsg("  -> value '%ls' not supported on fake Registration key", lpValueName);
            return ERROR_FILE_NOT_FOUND;
        }
    }

    LSTATUS result = Real_RegSetValueExW ? Real_RegSetValueExW(hKey, lpValueName, Reserved,
                                                                dwType, lpData, cbData)
                                         : ERROR_FILE_NOT_FOUND;
    LogMsg("  -> real result = %ld", result);
    return result;
}

LSTATUS WINAPI Hook_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved,
                                     LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    DWORD bufSize = lpcbData ? *lpcbData : 0;
    LogMsg("RegQueryValueExW(hKey=0x%p, value=%ls, bufSize=%lu)", hKey, lpValueName, bufSize);

    if (hKey == FAKE_REGISTRATION_KEY) {
        if (lpValueName && StrCmpIW(lpValueName, L"ServerPassword") == 0) {
            if (g_serverPasswordSize == 0) {
                LogMsg("  -> ServerPassword not set");
                return ERROR_FILE_NOT_FOUND;
            }
            if (lpType) *lpType = g_serverPasswordType;
            if (lpData) {
                if (bufSize < g_serverPasswordSize) {
                    *lpcbData = g_serverPasswordSize;
                    LogMsg("  -> buffer too small (need %lu)", g_serverPasswordSize);
                    return ERROR_MORE_DATA;
                }
                memcpy(lpData, g_serverPassword, g_serverPasswordSize);
            }
            *lpcbData = g_serverPasswordSize;
            LogMsg("  -> ServerPassword returned (type=%lu, size=%lu)", g_serverPasswordType, g_serverPasswordSize);
            return ERROR_SUCCESS;
        } else {
            LogMsg("  -> value '%ls' not found", lpValueName);
            return ERROR_FILE_NOT_FOUND;
        }
    }

    LSTATUS result = Real_RegQueryValueExW ? Real_RegQueryValueExW(hKey, lpValueName, lpReserved,
                                                                    lpType, lpData, lpcbData)
                                           : ERROR_FILE_NOT_FOUND;
    LogMsg("  -> real result = %ld", result);
    return result;
}

LSTATUS WINAPI Hook_RegCloseKey(HKEY hKey)
{
    LogMsg("RegCloseKey(hKey=0x%p)", hKey);
    if (hKey == FAKE_REGISTRATION_KEY) {
        LogMsg("  -> fake key, nothing to close");
        return ERROR_SUCCESS;
    }
    LSTATUS result = Real_RegCloseKey ? Real_RegCloseKey(hKey) : ERROR_SUCCESS;
    LogMsg("  -> real result = %ld", result);
    return result;
}

LSTATUS WINAPI Hook_RegDeleteValueW(HKEY hKey, LPCWSTR lpValueName)
{
    LogMsg("RegDeleteValueW(hKey=0x%p, value=%ls)", hKey, lpValueName);
    if (hKey == FAKE_REGISTRATION_KEY) {
        if (lpValueName && StrCmpIW(lpValueName, L"ServerPassword") == 0) {
            memset(g_serverPassword, 0, sizeof(g_serverPassword));
            g_serverPasswordSize = 0;
            LogMsg("  -> ServerPassword deleted");
            return ERROR_SUCCESS;
        }
        LogMsg("  -> value '%ls' not found", lpValueName);
        return ERROR_FILE_NOT_FOUND;
    }
    LSTATUS result = Real_RegDeleteValueW ? Real_RegDeleteValueW(hKey, lpValueName)
                                          : ERROR_FILE_NOT_FOUND;
    LogMsg("  -> real result = %ld", result);
    return result;
}

LSTATUS WINAPI Hook_RegNotifyChangeKeyValue(HKEY hKey, BOOL bWatchSubtree,
                                            DWORD dwNotifyFilter, HANDLE hEvent,
                                            BOOL fAsynchronous)
{
    LogMsg("RegNotifyChangeKeyValue(hKey=0x%p, subtree=%d, filter=0x%lx, event=0x%p, async=%d)",
           hKey, bWatchSubtree, dwNotifyFilter, hEvent, fAsynchronous);
    if (hKey == FAKE_REGISTRATION_KEY) {
        LogMsg("  -> fake key, no external changes");
        return ERROR_SUCCESS;
    }
    LSTATUS result = Real_RegNotifyChangeKeyValue
                        ? Real_RegNotifyChangeKeyValue(hKey, bWatchSubtree, dwNotifyFilter,
                                                       hEvent, fAsynchronous)
                        : ERROR_SUCCESS;
    LogMsg("  -> real result = %ld", result);
    return result;
}

/* ---------- installation ---------- */
void Register_InstallHooks(HMODULE hAdvapi32)
{
    // ---------- NEW: init password persistence ----------
    InitializeCriticalSection(&g_passwordLock);
    InitPasswordFilePath();
    LoadServerPasswordFromFile();
    // Grab real APIs
    Real_RegOpenKeyW           = (RegOpenKeyW_t)GetProcAddress(hAdvapi32, "RegOpenKeyW");
    Real_RegOpenKeyExW         = (RegOpenKeyExW_t)GetProcAddress(hAdvapi32, "RegOpenKeyExW");
    Real_RegCreateKeyExW       = (RegCreateKeyExW_t)GetProcAddress(hAdvapi32, "RegCreateKeyExW");
    Real_RegSetValueExW        = (RegSetValueExW_t)GetProcAddress(hAdvapi32, "RegSetValueExW");
    Real_RegQueryValueExW      = (RegQueryValueExW_t)GetProcAddress(hAdvapi32, "RegQueryValueExW");
    Real_RegCloseKey           = (RegCloseKey_t)GetProcAddress(hAdvapi32, "RegCloseKey");
    Real_RegDeleteValueW       = (RegDeleteValueW_t)GetProcAddress(hAdvapi32, "RegDeleteValueW");
    Real_RegNotifyChangeKeyValue = (RegNotifyChangeKeyValue_t)GetProcAddress(hAdvapi32, "RegNotifyChangeKeyValue");

    LogMsg("Registry hooks installed (Registration/ServerPassword only)");
}

/* You still need to call Register_InstallHooks from your DllMain or similar,
   and detour the above hook functions into the target process. */