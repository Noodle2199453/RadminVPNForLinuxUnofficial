#ifndef REGISTER_H
#define REGISTER_H

#include <windows.h>
#include <fileapi.h>
#include <handleapi.h>
#include <libloaderapi.h>
#include <minwinbase.h>
#include <minwindef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations for logging functions (provided by log.h)
void LogMsg(const char* fmt, ...);
void LogHex(const BYTE *data, DWORD len, const char *prefix);

// Registry structures
typedef struct RegValue {
    wchar_t* name;
    DWORD    type;
    DWORD    size;
    BYTE*    data;
    struct RegValue* next;
} RegValue;

typedef struct RegKey {
    wchar_t* name;            // relative name of this key
    struct RegKey* parent;
    struct RegKey* child;     // first child
    struct RegKey* sibling;   // next sibling
    RegValue* values;         // linked list of values
} RegKey;

// Fake handle for service key
#define FAKE_SERVICE_KEY  ((HKEY)(ULONG_PTR)0x10000001)

// Function declarations
void DumpRealRegistryTree(HKEY hRoot, const wchar_t* lpSubKey);
void DumpRegistryTree(void);
void Register_InstallHooks(HMODULE hOriginalDll, HMODULE hAdvapi32);
void LogStackTrace(const char *reason, int framesToSkip);

// Hook declarations for registry API interception
LSTATUS WINAPI Hook_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, 
                                   REGSAM samDesired, PHKEY phkResult);
LSTATUS WINAPI Hook_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved,
                                      LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LSTATUS WINAPI Hook_RegCloseKey(HKEY hKey);
LSTATUS WINAPI Hook_RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, 
                                     LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired,
                                     const LPSECURITY_ATTRIBUTES lpSec, PHKEY phkResult, 
                                     LPDWORD lpdwDisposition);
LSTATUS WINAPI Hook_RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved,
                                    DWORD dwType, const BYTE* lpData, DWORD cbData);
LSTATUS WINAPI Hook_RegDeleteValueW(HKEY hKey, LPCWSTR lpValueName);
LSTATUS WINAPI Hook_RegNotifyChangeKeyValue(HKEY hKey, BOOL bWatchSubtree,
                                             DWORD dwNotifyFilter, HANDLE hEvent,
                                             BOOL fAsynchronous);
LSTATUS WINAPI Hook_RegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult);
LSTATUS WINAPI Hook_RegCreateKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult);
LSTATUS WINAPI Hook_RegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey);
LSTATUS WINAPI Hook_RegDeleteKeyExW(HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, DWORD Reserved);
LSTATUS WINAPI Hook_RegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName,
                                   LPDWORD lpcchName, LPDWORD lpReserved,
                                   LPWSTR lpClass, LPDWORD lpcchClass,
                                   PFILETIME lpftLastWriteTime);
LSTATUS WINAPI Hook_RegEnumKeyW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, DWORD cchName);
LSTATUS WINAPI Hook_RegEnumValueW(HKEY hKey, DWORD dwIndex, LPWSTR lpValueName,
                                   LPDWORD lpcchValueName, LPDWORD lpReserved,
                                   LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LSTATUS WINAPI Hook_RegGetValueW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue,
                                  DWORD dwFlags, LPDWORD pdwType,
                                  PVOID pvData, LPDWORD pcbData);
LSTATUS WINAPI Hook_RegSetKeySecurity(HKEY hKey, SECURITY_INFORMATION SecurityInformation,
                                       PSECURITY_DESCRIPTOR pSecurityDescriptor);
LSTATUS WINAPI Hook_RegGetKeySecurity(HKEY hKey, SECURITY_INFORMATION SecurityInformation,
                                       PSECURITY_DESCRIPTOR pSecurityDescriptor, LPDWORD lpcbSecurityDescriptor);
LSTATUS WINAPI Hook_RegQueryInfoKeyW(HKEY hKey, LPWSTR lpClass, LPDWORD lpcchClass,
                                      LPDWORD lpReserved, LPDWORD lpcSubKeys,
                                      LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen,
                                      LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen,
                                      LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor,
                                      PFILETIME lpftLastWriteTime);
LSTATUS WINAPI Hook_RegDeleteTreeW(HKEY hKey, LPCWSTR lpSubKey);
LSTATUS WINAPI Hook_RegCopyTreeW(HKEY hKeySrc, LPCWSTR lpSubKey, HKEY hKeyDest);

#ifdef __cplusplus
}
#endif

#endif // REGISTER_H