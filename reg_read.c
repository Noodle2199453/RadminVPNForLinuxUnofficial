#include <wchar.h>
#include <windows.h>
#include <winreg.h>

// Maximum lengths for names and data
#define MAX_KEY_NAME   256
#define MAX_VALUE_NAME 16384
#define MAX_VALUE_DATA 65536
void LogMsg(const char* fmt, ...);
void LogHex(const BYTE* data, DWORD len, const char* prefix);

// Log all values under an open key
static void LogRegistryValues(HKEY hKey, const wchar_t *fullPath)
{
    DWORD index = 0;
    wchar_t valueName[MAX_VALUE_NAME];
    BYTE data[MAX_VALUE_DATA];
    DWORD valueNameSize, dataSize, type;

    while (1) {
        valueNameSize = MAX_VALUE_NAME;
        dataSize = MAX_VALUE_DATA;
        LONG result = RegEnumValueW(hKey, index, valueName, &valueNameSize,
                                    NULL, &type, data, &dataSize);
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) {
            LogMsg("  [Value %lu] ERROR %ld enumerating value", index, result);
            index++;
            continue;
        }

        // Build log string depending on type
        switch (type) {
        case REG_SZ:
        case REG_EXPAND_SZ:
            LogMsg("  Value: %ls = \"%ls\" (REG_SZ)", valueName, (wchar_t*)data);
            break;
        case REG_DWORD:
            if (dataSize >= sizeof(DWORD))
                LogMsg("  Value: %ls = 0x%08lX (%lu) (REG_DWORD)", valueName,
                       *(DWORD*)data, *(DWORD*)data);
            else
                LogMsg("  Value: %ls = (REG_DWORD, size %lu)", valueName, dataSize);
            break;
        case REG_MULTI_SZ: {
            LogMsg("  Value: %ls = (REG_MULTI_SZ)", valueName);
            wchar_t *p = (wchar_t*)data;
            while (*p) {
                LogMsg("    \"%ls\"", p);
                p += wcslen(p) + 1;
            }
            break;
        }
        case REG_BINARY:
            LogMsg("  Value: %ls = (REG_BINARY, %lu bytes)", valueName, dataSize);
            LogHex(data, dataSize, "    ");
            break;
        default:
            LogMsg("  Value: %ls = (type %lu, %lu bytes)", valueName, type, dataSize);
            break;
        }
        index++;
    }
}

// Recursively enumerate subkeys and values
static void LogRegistryFolder(HKEY hRoot, const wchar_t *subPath, int depth)
{
    HKEY hKey;
    REGSAM samDesired = KEY_READ;

    // First try with KEY_WOW64_32KEY (for 64-bit process accessing 32-bit registry)
    LONG result = RegOpenKeyExW(hRoot, subPath, 0, samDesired | KEY_WOW64_32KEY, &hKey);
    if (result == ERROR_ACCESS_DENIED) {
        // Retry without WOW64 flag (maybe we're 32-bit already or it's a 64-bit key)
        result = RegOpenKeyExW(hRoot, subPath, 0, KEY_READ, &hKey);
    }
    if (result != ERROR_SUCCESS) {
        LogMsg("%*s[%ls] Cannot open (error %ld)", depth*2, "", subPath ? subPath : L"", result);
        return;
    }

    LogMsg("%*s[%ls]", depth*2, "", subPath ? subPath : L"");

    // Enumerate values
    LogRegistryValues(hKey, subPath);

    // Enumerate subkeys
    DWORD index = 0;
    wchar_t subKeyName[MAX_KEY_NAME];
    DWORD subKeyNameSize;
    while (1) {
        subKeyNameSize = MAX_KEY_NAME;
        result = RegEnumKeyExW(hKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL);
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) {
            LogMsg("  [Subkey %lu] ERROR %ld enumerating subkey", index, result);
            index++;
            continue;
        }

        wchar_t fullSubPath[512];
        swprintf(fullSubPath, 512, L"%ls\\%ls", subPath ? subPath : L"", subKeyName);
        LogRegistryFolder(hKey, fullSubPath, depth + 1);
        index++;
    }

    RegCloseKey(hKey);
}