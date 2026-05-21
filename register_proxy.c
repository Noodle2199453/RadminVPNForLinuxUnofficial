#include <windows.h>

extern void LogMsg(const char *fmt, ...);

typedef LSTATUS (WINAPI *Real_RegOpenKeyW_t)(HKEY, LPCWSTR, PHKEY);
typedef LSTATUS (WINAPI *Real_RegOpenKeyExW_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS (WINAPI *Real_RegQueryValueExW_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS (WINAPI *Real_RegCloseKey_t)(HKEY);
typedef LSTATUS (WINAPI *Real_RegCreateKeyExW_t)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM,
                                                 LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LSTATUS (WINAPI *Real_RegSetValueExW_t)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS (WINAPI *Real_RegDeleteValueW_t)(HKEY, LPCWSTR);
typedef LSTATUS (WINAPI *Real_RegNotifyChangeKeyValue_t)(HKEY, BOOL, DWORD, HANDLE, BOOL);

Real_RegOpenKeyW_t               Real_RegOpenKeyW               = NULL;
Real_RegOpenKeyExW_t             Real_RegOpenKeyExW             = NULL;
Real_RegQueryValueExW_t          Real_RegQueryValueExW          = NULL;
Real_RegCloseKey_t               Real_RegCloseKey               = NULL;
Real_RegCreateKeyExW_t           Real_RegCreateKeyExW           = NULL;
Real_RegSetValueExW_t            Real_RegSetValueExW            = NULL;
Real_RegDeleteValueW_t           Real_RegDeleteValueW           = NULL;
Real_RegNotifyChangeKeyValue_t   Real_RegNotifyChangeKeyValue   = NULL;

void InitRealRegistryHooks()
{
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    if (!hAdvapi32) return;

    Real_RegOpenKeyW            = (Real_RegOpenKeyW_t)
        GetProcAddress(hAdvapi32, "RegOpenKeyW");
    Real_RegOpenKeyExW          = (Real_RegOpenKeyExW_t)
        GetProcAddress(hAdvapi32, "RegOpenKeyExW");
    Real_RegQueryValueExW       = (Real_RegQueryValueExW_t)
        GetProcAddress(hAdvapi32, "RegQueryValueExW");
    Real_RegCloseKey            = (Real_RegCloseKey_t)
        GetProcAddress(hAdvapi32, "RegCloseKey");
    Real_RegCreateKeyExW        = (Real_RegCreateKeyExW_t)
        GetProcAddress(hAdvapi32, "RegCreateKeyExW");
    Real_RegSetValueExW         = (Real_RegSetValueExW_t)
        GetProcAddress(hAdvapi32, "RegSetValueExW");
    Real_RegDeleteValueW        = (Real_RegDeleteValueW_t)
        GetProcAddress(hAdvapi32, "RegDeleteValueW");
    Real_RegNotifyChangeKeyValue = (Real_RegNotifyChangeKeyValue_t)
        GetProcAddress(hAdvapi32, "RegNotifyChangeKeyValue");
}


LSTATUS WINAPI Proxy_RegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
    LogMsg("--> Proxy_RegOpenKeyW(hKey=%p, sub=%ls)", hKey, lpSubKey ? lpSubKey : L"(null)");
    LSTATUS res = Real_RegOpenKeyW(hKey, lpSubKey, phkResult);
    LogMsg("<-- Proxy_RegOpenKeyW returned %ld", res);
    return res;
}

LSTATUS WINAPI Proxy_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions,
                                   REGSAM samDesired, PHKEY phkResult)
{
    LogMsg("--> Proxy_RegOpenKeyExW(hKey=%p, sub=%ls, opts=%lu, sam=0x%lX)",
           hKey, lpSubKey ? lpSubKey : L"(null)", ulOptions, samDesired);
    LSTATUS res = Real_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    LogMsg("<-- Proxy_RegOpenKeyExW returned %ld", res);
    return res;
}

LSTATUS WINAPI Proxy_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved,
                                      LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    LogMsg("--> Proxy_RegQueryValueExW(hKey=%p, value=%ls)", hKey, lpValueName ? lpValueName : L"(null)");
    LSTATUS res = Real_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    LogMsg("<-- Proxy_RegQueryValueExW returned %ld", res);
    return res;
}

LSTATUS WINAPI Proxy_RegCloseKey(HKEY hKey)
{
    LogMsg("--> Proxy_RegCloseKey(hKey=%p)", hKey);
    LSTATUS res = Real_RegCloseKey(hKey);
    LogMsg("<-- Proxy_RegCloseKey returned %ld", res);
    return res;
}

LSTATUS WINAPI Proxy_RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved,
                                     LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired,
                                     LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                     PHKEY phkResult, LPDWORD lpdwDisposition)
{
    LogMsg("--> Proxy_RegCreateKeyExW(hKey=%p, sub=%ls, opts=%lu, sam=0x%lX)",
           hKey, lpSubKey ? lpSubKey : L"(null)", dwOptions, samDesired);
    LSTATUS res = Real_RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass,
                                       dwOptions, samDesired, lpSecurityAttributes,
                                       phkResult, lpdwDisposition);
    LogMsg("<-- Proxy_RegCreateKeyExW returned %ld", res);
    return res;
}

LSTATUS WINAPI Proxy_RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved,
                                    DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    LogMsg("--> Proxy_RegSetValueExW(hKey=%p, name=%ls, type=%lu, size=%lu)",
           hKey, lpValueName ? lpValueName : L"(null)", dwType, cbData);
    LSTATUS res = Real_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    LogMsg("<-- Proxy_RegSetValueExW returned %ld", res);
    return res;
}

LSTATUS WINAPI Proxy_RegDeleteValueW(HKEY hKey, LPCWSTR lpValueName)
{
    LogMsg("--> Proxy_RegDeleteValueW(hKey=%p, value=%ls)", hKey, lpValueName ? lpValueName : L"(null)");
    LSTATUS res = Real_RegDeleteValueW(hKey, lpValueName);
    LogMsg("<-- Proxy_RegDeleteValueW returned %ld", res);
    return res;
}

LSTATUS WINAPI Proxy_RegNotifyChangeKeyValue(HKEY hKey, BOOL bWatchSubtree,
                                             DWORD dwNotifyFilter, HANDLE hEvent,
                                             BOOL fAsynchronous)
{
    LogMsg("--> Proxy_RegNotifyChangeKeyValue(hKey=%p, subtree=%d, filter=0x%lX, event=%p, async=%d)",
           hKey, bWatchSubtree, dwNotifyFilter, hEvent, fAsynchronous);
    LSTATUS res = Real_RegNotifyChangeKeyValue(hKey, bWatchSubtree, dwNotifyFilter, hEvent, fAsynchronous);
    LogMsg("<-- Proxy_RegNotifyChangeKeyValue returned %ld", res);
    return res;
}