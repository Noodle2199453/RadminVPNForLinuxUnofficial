#include <windows.h>
void LogMsg(const char* fmt, ...);
void LogHex(const BYTE *data, DWORD len, const char *prefix);

// ---------- In‑memory registry backing store ----------
#include <fileapi.h>
#include <handleapi.h>
#include <libloaderapi.h>
#include <minwinbase.h>
#include <minwindef.h>
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

static RegKey* g_regRoot = NULL;               // root of the fake registry tree
static HANDLE  g_regFile = INVALID_HANDLE_VALUE; // file handle for "register.reg"
static CRITICAL_SECTION g_regLock;             // synchronisation

static BOOL g_isWow64 = FALSE;   // TRUE if current process is 32‑bit on 64‑bit OS

#define FAKE_SERVICE_KEY  ((HKEY)(ULONG_PTR)0x10000001)

typedef LSTATUS (WINAPI *RegOpenKeyExW_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS (WINAPI *RegQueryValueExW_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS (WINAPI *RegCloseKey_t)(HKEY);
typedef LSTATUS (WINAPI *RegCreateKeyExW_t)(HKEY);
typedef LSTATUS (WINAPI *RegSetValueExW_t)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);

typedef LSTATUS (WINAPI *RegDeleteValueW_t)(HKEY hKey, LPCWSTR lpValueName);
typedef LSTATUS (WINAPI *RegNotifyChangeKeyValue_t)(HKEY hKey, BOOL bWatchSubtree,
                                                    DWORD dwNotifyFilter, HANDLE hEvent,
                                                    BOOL fAsynchronous);
                                                    // ---- Additional registry API declarations ----
typedef LSTATUS (WINAPI *RegCreateKeyW_t)(HKEY, LPCWSTR, PHKEY);
typedef LSTATUS (WINAPI *RegDeleteKeyW_t)(HKEY, LPCWSTR);
typedef LSTATUS (WINAPI *RegDeleteKeyExW_t)(HKEY, LPCWSTR, REGSAM, DWORD);
typedef LSTATUS (WINAPI *RegEnumKeyW_t)(HKEY, DWORD, LPWSTR, DWORD);
typedef LSTATUS (WINAPI *RegEnumKeyExW_t)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
typedef LSTATUS (WINAPI *RegEnumValueW_t)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS (WINAPI *RegGetValueW_t)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
typedef LSTATUS (WINAPI *RegSetKeySecurity_t)(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
typedef LSTATUS (WINAPI *RegGetKeySecurity_t)(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, LPDWORD);
typedef LSTATUS (WINAPI *RegQueryInfoKeyW_t)(HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
typedef LSTATUS (WINAPI *RegDeleteTreeW_t)(HKEY, LPCWSTR);
typedef LSTATUS (WINAPI *RegCopyTreeW_t)(HKEY, LPCWSTR, HKEY);

static RegCreateKeyW_t       Real_RegCreateKeyW = NULL;
static RegDeleteKeyW_t       Real_RegDeleteKeyW = NULL;
static RegDeleteKeyExW_t     Real_RegDeleteKeyExW = NULL;
static RegEnumKeyW_t         Real_RegEnumKeyW = NULL;
static RegEnumKeyExW_t       Real_RegEnumKeyExW = NULL;
static RegEnumValueW_t       Real_RegEnumValueW = NULL;
static RegGetValueW_t        Real_RegGetValueW = NULL;
static RegSetKeySecurity_t   Real_RegSetKeySecurity = NULL;
static RegGetKeySecurity_t   Real_RegGetKeySecurity = NULL;
static RegQueryInfoKeyW_t    Real_RegQueryInfoKeyW = NULL;
static RegDeleteTreeW_t      Real_RegDeleteTreeW = NULL;
static RegCopyTreeW_t        Real_RegCopyTreeW = NULL;
static RegDeleteValueW_t          Real_RegDeleteValueW          = NULL;
static RegNotifyChangeKeyValue_t  Real_RegNotifyChangeKeyValue  = NULL;

static RegOpenKeyExW_t                   Real_RegOpenKeyExW                = NULL;
static RegQueryValueExW_t                Real_RegQueryValueExW             = NULL;
static RegCloseKey_t                     Real_RegCloseKey                  = NULL;
static RegCreateKeyExW_t Real_RegCreateKeyExW = NULL;

static RegSetValueExW_t Real_RegSetValueExW = NULL;

// Fake handle management
static RegKey** g_fakeKeyTable = NULL;
static wchar_t** g_fakeKeyPaths = NULL;   // same index as g_fakeKeyTable
static DWORD    g_fakeKeyCount = 0;
static DWORD    g_fakeKeyCapacity = 256;
#define FAKE_HANDLE_BASE  0x30000000

// Magic for our file format
#define REGFILE_MAGIC  0x46424752   // "RGFB"


static wchar_t* RedirectSubKey(HKEY hKey, LPCWSTR lpSubKey)
{
    if (!lpSubKey) lpSubKey = L"";

    // Redirection only applies to HKLM in 32-bit processes
    if (hKey != HKEY_LOCAL_MACHINE || !g_isWow64)
        return _wcsdup(lpSubKey);

    // Check if the first component is "SOFTWARE" (case-insensitive)
    wchar_t temp[512];
    lstrcpynW(temp, lpSubKey, 512);
    wchar_t *ctx = NULL;
    wchar_t *first = wcstok_s(temp, L"\\", &ctx);

    if (first && _wcsicmp(first, L"SOFTWARE") == 0)
    {
        // Get remainder after first component
        const wchar_t *remainder = lpSubKey + wcslen(first);
        if (*remainder == L'\\') remainder++;

        // Extract second component to avoid double‑redirection
        wchar_t tmp2[256];
        lstrcpynW(tmp2, remainder, 256);
        wchar_t *ctx2 = NULL;
        wchar_t *second = wcstok_s(tmp2, L"\\", &ctx2);
        if (second && _wcsicmp(second, L"WOW6432Node") == 0)
        {
            // Already redirected – use original path
            return _wcsdup(lpSubKey);
        }

        // Build "SOFTWARE\\WOW6432Node[\\<rest>]"
        size_t totalLen = wcslen(L"SOFTWARE\\WOW6432Node") + 1 +
                          (remainder && *remainder ? wcslen(remainder) + 1 : 0) + 1;
        wchar_t *result = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, totalLen * sizeof(wchar_t));
        if (result)
        {
            wcscpy(result, L"SOFTWARE\\WOW6432Node");
            if (remainder && *remainder)
            {
                wcscat(result, L"\\");
                wcscat(result, remainder);
            }
            return result;
        }
        // fallback to original
        return _wcsdup(lpSubKey);
    }
    // no redirection needed
    return _wcsdup(lpSubKey);
}

static void DumpRealKey(HKEY hKey, const wchar_t* keyName, int depth);

LONG WINAPI Hook_RegSetKeySecurity(HKEY hKey, SECURITY_INFORMATION SecurityInformation,
                                   PSECURITY_DESCRIPTOR pSecurityDescriptor)
{
    LogMsg("RegSetKeySecurity(hKey=0x%p, si=0x%lX) -> BLOCKED", hKey, SecurityInformation);
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────
// Public entry point – supply a root and a subpath
// e.g. DumpRealRegistryTree(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Famatech");
// ────────────────────────────────────────────────────────────
void DumpRealRegistryTree(HKEY hRoot, const wchar_t* lpSubKey)
{
    HKEY hKey;
    LONG lr = RegOpenKeyExW(hRoot, lpSubKey, 0, KEY_READ, &hKey);
    if (lr != ERROR_SUCCESS) {
        LogMsg("DumpRealRegistryTree: cannot open \"%ls\" (error %ld)", lpSubKey, lr);
        return;
    }
    DumpRealKey(hKey, lpSubKey, 0);
    RegCloseKey(hKey);
}

// ────────────────────────────────────────────────────────────
// Recursive worker
// ────────────────────────────────────────────────────────────
static void DumpRealKey(HKEY hKey, const wchar_t* keyName, int depth)
{
    wchar_t indent[128] = { 0 };
    for (int i = 0; i < depth; i++) wcscat_s(indent, ARRAYSIZE(indent), L"  ");

    LogMsg("%s[Key] %ls", indent, keyName ? keyName : L"(unknown)");

    // ── Enumerate values ─────────────────────────────────
    DWORD valIndex = 0;
    wchar_t valName[256];
    DWORD valNameLen;
    DWORD valType;
    BYTE  valData[4096];
    DWORD valDataLen;
    LONG  lr;

    for (;;) {
        valNameLen = ARRAYSIZE(valName);
        valDataLen = sizeof(valData);
        lr = RegEnumValueW(hKey, valIndex, valName, &valNameLen,
                           NULL, &valType, valData, &valDataLen);
        if (lr == ERROR_NO_MORE_ITEMS) break;
        if (lr != ERROR_SUCCESS && lr != ERROR_MORE_DATA) {
            valIndex++;   // skip unreadable entries
            continue;
        }

        // name may be empty for the default value
        const wchar_t* vn = (valNameLen > 0) ? valName : L"(default)";

        switch (valType) {
        case REG_SZ:
        case REG_EXPAND_SZ:
        {
            // valDataLen includes the terminating null(s)
            const wchar_t* str = (valDataLen >= sizeof(wchar_t)) ? (const wchar_t*)valData : L"";
            LogMsg("%s  %ls = \"%ls\"", indent, vn, str);
            break;
        }
        case REG_DWORD:
            if (valDataLen >= sizeof(DWORD))
                LogMsg("%s  %ls = 0x%lX (%lu)", indent, vn,
                       *(DWORD*)valData, *(DWORD*)valData);
            else
                LogMsg("%s  %ls = <bad DWORD size %lu>", indent, vn, valDataLen);
            break;
        case REG_QWORD:
            if (valDataLen >= sizeof(ULONGLONG))
                LogMsg("%s  %ls = 0x%llX (%llu)", indent, vn,
                       *(ULONGLONG*)valData, *(ULONGLONG*)valData);
            else
                LogMsg("%s  %ls = <bad QWORD size %lu>", indent, vn, valDataLen);
            break;
        case REG_MULTI_SZ:
        {
            LogMsg("%s  %ls = MULTI_SZ:", indent, vn);
            const wchar_t* p = (const wchar_t*)valData;
            while (p && *p) {
                LogMsg("%s    \"%ls\"", indent, p);
                p += wcslen(p) + 1;
            }
            break;
        }
        case REG_BINARY:
            LogMsg("%s  %ls = BINARY (%lu bytes)", indent, vn, valDataLen);
            LogHex(valData, min(valDataLen, 32), "    ");   // your existing helper
            break;
        default:
            LogMsg("%s  %ls = type %lu, size %lu", indent, vn, valType, valDataLen);
            break;
        }
        valIndex++;
    }

    // ── Enumerate subkeys ────────────────────────────────
    DWORD subIdx = 0;
    wchar_t subName[256];
    DWORD subNameLen;
    for (;;) {
        subNameLen = ARRAYSIZE(subName);
        lr = RegEnumKeyExW(hKey, subIdx, subName, &subNameLen,
                           NULL, NULL, NULL, NULL);
        if (lr == ERROR_NO_MORE_ITEMS) break;
        if (lr != ERROR_SUCCESS) {
            subIdx++;
            continue;
        }

        HKEY hSubKey;
        lr = RegOpenKeyExW(hKey, subName, 0, KEY_READ, &hSubKey);
        if (lr == ERROR_SUCCESS) {
            DumpRealKey(hSubKey, subName, depth + 1);
            RegCloseKey(hSubKey);
        } else {
            LogMsg("%s  [SubKey] %ls (cannot open, error %ld)", indent, subName, lr);
        }
        subIdx++;
    }
}

void DumpRegistryTree(void)
{
    LogMsg("=== Registry tree dump ===");
    if (g_regRoot) DumpRealRegistryTree(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Famatech");
    else LogMsg("  (empty)");
    LogMsg("=== End of tree ===");
}


#define MAX_CACHED_HANDLES 512

typedef struct {
    wchar_t* path;
    HKEY     handle;
} CachedHandle;

static CachedHandle g_handleCache[MAX_CACHED_HANDLES];
static DWORD        g_cachedCount = 0;


static HKEY CacheLookup(const wchar_t* fullPath, HKEY newHandle)
{
    for (DWORD i = 0; i < g_cachedCount; i++) {
        if (g_handleCache[i].path && _wcsicmp(g_handleCache[i].path, fullPath) == 0) {
            // Found – return the existing handle (and ignore the new one)
            return g_handleCache[i].handle;
        }
    }
    // Not found – add to cache if there's room
    if (g_cachedCount < MAX_CACHED_HANDLES) {
        g_handleCache[g_cachedCount].path   = _wcsdup(fullPath);
        g_handleCache[g_cachedCount].handle = newHandle;
        g_cachedCount++;
    } else {
        LogMsg("WARNING: Handle cache full, not caching %ls", fullPath);
    }
    return newHandle;
}

static RegKey* FindKeyByPath(RegKey* root, const wchar_t* path)
{
    // path like L"SOFTWARE\\Famatech\\RadminVPN"
    if (!path || !*path) return root;

    wchar_t temp[256];
    lstrcpynW(temp, path, 256);

    wchar_t *context = NULL;
    wchar_t *token = wcstok_s(temp, L"\\", &context);

    RegKey* cur = root;
    while (token && cur) {
        RegKey* child = cur->child;
        while (child) {
            if (_wcsicmp(child->name, token) == 0) break;
            child = child->sibling;
        }
        cur = child;
        token = wcstok_s(NULL, L"\\", &context);
    }
    return cur;
}

static RegKey* CreateKey(RegKey* parent, const wchar_t* name)
{
    RegKey* key = (RegKey*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RegKey));
    key->name = (name && *name) ? _wcsdup(name) : NULL;
    key->parent = parent;
    if (parent) {
        key->sibling = parent->child;
        parent->child = key;
    }
    return key;
}

// Splits `path` on '\\' and walks/creates the hierarchy under `base`
// If `create` is TRUE, missing keys are auto‑created.
// Returns the final key, or NULL if not found and create==FALSE.
static RegKey* NavigatePath(RegKey* base, const wchar_t* path, BOOL create)
{
    if (!base) base = g_regRoot;
    if (!path || !*path) return base;   // empty path = open the base itself

    wchar_t temp[512];
    lstrcpynW(temp, path, 512);
    wchar_t *ctx = NULL;
    wchar_t *token = wcstok_s(temp, L"\\", &ctx);

    RegKey* cur = base;
    while (token && cur) {
        RegKey* child = cur->child;
        while (child) {
            if (_wcsicmp(child->name, token) == 0) break;
            child = child->sibling;
        }

        if (!child) {
            if (!create) return NULL;            // not found, and we mustn't create
            child = CreateKey(cur, token);        // auto‑create missing component
        }

        cur = child;
        token = wcstok_s(NULL, L"\\", &ctx);
    }
    return cur;
}

static void SetValue(RegKey* key, const wchar_t* name, DWORD type, const BYTE* data, DWORD size)
{
    RegValue* v = key->values;
    while (v) {
        if (_wcsicmp(v->name, name) == 0) break;
        v = v->next;
    }
    if (!v) {
        v = (RegValue*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RegValue));
        v->name = _wcsdup(name);
        v->next = key->values;
        key->values = v;
    }
    if (v->data) HeapFree(GetProcessHeap(), 0, v->data);
    v->type = type;
    v->size = size;
    v->data = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
    memcpy(v->data, data, size);
}

static BOOL GetValue(RegKey* key, const wchar_t* name, DWORD* type, BYTE* data, DWORD* size)
{
    RegValue* v = key->values;
    while (v) {
        if (_wcsicmp(v->name, name) == 0) break;
        v = v->next;
    }
    if (!v) return FALSE;
    if (type) *type = v->type;
    if (data && *size >= v->size) {
        memcpy(data, v->data, v->size);
        *size = v->size;
        return TRUE;
    } else if (!data) {
        *size = v->size;
        return TRUE;
    } else {
        *size = v->size;
        return FALSE; // buffer too small
    }
}

static RegKey* HandleToKey(HKEY hKey)
{
    if (hKey == FAKE_SERVICE_KEY) return NULL; // special
    DWORD idx = (DWORD)((ULONG_PTR)hKey - FAKE_HANDLE_BASE);
    if (idx < g_fakeKeyCount) return g_fakeKeyTable[idx];
    return NULL;
}

static HKEY AllocHandle(RegKey* key, const wchar_t* fullPath)
{
    if (g_fakeKeyCount >= g_fakeKeyCapacity) {
        g_fakeKeyCapacity *= 2;
        g_fakeKeyTable = (RegKey**)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                               g_fakeKeyTable,
                                               g_fakeKeyCapacity * sizeof(RegKey*));
        g_fakeKeyPaths = (wchar_t**)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                g_fakeKeyPaths,
                                                g_fakeKeyCapacity * sizeof(wchar_t*));
    }
    g_fakeKeyTable[g_fakeKeyCount] = key;
    g_fakeKeyPaths[g_fakeKeyCount] = fullPath ? _wcsdup(fullPath) : NULL;
    return (HKEY)(FAKE_HANDLE_BASE + g_fakeKeyCount++);
}
static wchar_t* GetKeyPath(HKEY hKey)
{
    if (hKey == FAKE_SERVICE_KEY) return NULL;
    if (!g_fakeKeyPaths) return NULL;   // safety
    DWORD idx = (DWORD)((ULONG_PTR)hKey - FAKE_HANDLE_BASE);
    if (idx < g_fakeKeyCount) return g_fakeKeyPaths[idx];
    return NULL;
}
// ---------- File I/O helpers ----------
static void WriteToFile(const void* data, DWORD size)
{
    DWORD written;
    WriteFile(g_regFile, data, size, &written, NULL);
}

static void ReadFromFile(void* data, DWORD size)
{
    DWORD read;
    ReadFile(g_regFile, data, size, &read, NULL);
}

static void WriteWideString(const wchar_t* str)
{
    DWORD len = (str ? (DWORD)wcslen(str) : 0) + 1;  // include null terminator
    WriteToFile(&len, sizeof(len));
    if (str) WriteToFile(str, len * sizeof(wchar_t));
}

static wchar_t* ReadWideString(void)
{
    DWORD len;
    ReadFromFile(&len, sizeof(len));
    if (len == 0) return NULL;
    wchar_t* buf = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, len * sizeof(wchar_t));
    ReadFromFile(buf, len * sizeof(wchar_t));
    return buf;
}

// ---------- Recursive file load ----------
static RegKey* LoadKeyFromFile(RegKey* parent)
{
    wchar_t* name = ReadWideString();
    if (!name) return NULL;

    RegKey* key = CreateKey(parent, name);
    HeapFree(GetProcessHeap(), 0, name);

    // Values
    DWORD valCount;
    ReadFromFile(&valCount, sizeof(valCount));
    for (DWORD i = 0; i < valCount; i++) {
        wchar_t* vname = ReadWideString();
        DWORD type, size;
        ReadFromFile(&type, sizeof(type));
        ReadFromFile(&size, sizeof(size));
        BYTE* data = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
        ReadFromFile(data, size);
        SetValue(key, vname, type, data, size);
        HeapFree(GetProcessHeap(), 0, vname);
        HeapFree(GetProcessHeap(), 0, data);
    }

    // Subkeys
    DWORD subCount;
    ReadFromFile(&subCount, sizeof(subCount));
    for (DWORD i = 0; i < subCount; i++) {
        LoadKeyFromFile(key);
    }
    return key;
}

static BOOL LoadRegistryFromFile(void)
{
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t* p = wcsrchr(path, L'\\');
    if (p) *(p+1) = L'\0';
    wcscat(path, L"register.reg");

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogMsg("Registry file not found, starting fresh");
        return FALSE;
    }

    DWORD magic;
    DWORD read;
    ReadFile(hFile, &magic, sizeof(magic), &read, NULL);
    if (magic != REGFILE_MAGIC) {
        CloseHandle(hFile);
        LogMsg("Invalid registry file magic");
        return FALSE;
    }

    g_regFile = hFile;   // temporarily use global file handle for reading
    // Load root (which is just a placeholder key with no name)
    // The root key's name is an empty string
    wchar_t* rootName = ReadWideString();  // should be empty string
    if (rootName) {
        if (*rootName) {
            // If root has a name, treat it as the first real key under empty root
            RegKey* firstKey = CreateKey(g_regRoot, rootName);
            // Load its values and subkeys recursively
            DWORD valCount;
            ReadFromFile(&valCount, sizeof(valCount));
            for (DWORD i = 0; i < valCount; i++) {
                wchar_t* vname = ReadWideString();
                DWORD type, size;
                ReadFromFile(&type, sizeof(type));
                ReadFromFile(&size, sizeof(size));
                BYTE* data = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
                ReadFromFile(data, size);
                SetValue(firstKey, vname, type, data, size);
                HeapFree(GetProcessHeap(), 0, vname);
                HeapFree(GetProcessHeap(), 0, data);
            }
            DWORD subCount;
            ReadFromFile(&subCount, sizeof(subCount));
            for (DWORD i = 0; i < subCount; i++) {
                LoadKeyFromFile(firstKey);
            }
            HeapFree(GetProcessHeap(), 0, rootName);
        } else {
            // Empty root name -> root key; load children
            HeapFree(GetProcessHeap(), 0, rootName);
            DWORD dummy;
            ReadFromFile(&dummy, sizeof(dummy)); // valCount (should be 0 for root)
            DWORD subCount;
            ReadFromFile(&subCount, sizeof(subCount));
            for (DWORD i = 0; i < subCount; i++) {
                LoadKeyFromFile(g_regRoot);
            }
        }
    }

    CloseHandle(g_regFile);
    g_regFile = INVALID_HANDLE_VALUE;
    LogMsg("Registry file loaded");
    return TRUE;
}

// ---------- Recursive file save ----------
static void SaveKeyToFile(RegKey* key)
{
    // Write key name
    WriteWideString(key->name ? key->name : L"");

    // Write values
    DWORD valCount = 0;
    for (RegValue* v = key->values; v; v = v->next) valCount++;
    WriteToFile(&valCount, sizeof(valCount));
    for (RegValue* v = key->values; v; v = v->next) {
        WriteWideString(v->name);
        WriteToFile(&v->type, sizeof(v->type));
        WriteToFile(&v->size, sizeof(v->size));
        WriteToFile(v->data, v->size);
    }

    // Write subkeys
    DWORD subCount = 0;
    for (RegKey* child = key->child; child; child = child->sibling) subCount++;
    WriteToFile(&subCount, sizeof(subCount));
    for (RegKey* child = key->child; child; child = child->sibling) {
        SaveKeyToFile(child);
    }
}

static BOOL SaveRegistryToFile(void)
{
    EnterCriticalSection(&g_regLock);

    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t* p = wcsrchr(path, L'\\');
    if (p) *(p+1) = L'\0';
    wcscat(path, L"register.reg");

    // Write to a temp file then rename for atomicity
    wchar_t tempPath[MAX_PATH];
    wcscpy(tempPath, path);
    wcscat(tempPath, L".tmp");

    HANDLE hFile = CreateFileW(tempPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_regLock);
        LogMsg("SaveRegistryToFile: cannot create temp file");
        return FALSE;
    }

    g_regFile = hFile;   // temporarily use global file handle for writing
    DWORD magic = REGFILE_MAGIC;
    WriteToFile(&magic, sizeof(magic));
    SaveKeyToFile(g_regRoot);
    CloseHandle(g_regFile);
    g_regFile = INVALID_HANDLE_VALUE;

    // Replace old file with temp
    if (!MoveFileExW(tempPath, path, MOVEFILE_REPLACE_EXISTING)) {
        LogMsg("SaveRegistryToFile: MoveFileEx failed (error %lu)", GetLastError());
        DeleteFileW(tempPath);
        LeaveCriticalSection(&g_regLock);
        return FALSE;
    }

    LeaveCriticalSection(&g_regLock);
    return TRUE;
}

// ---------- Hook helpers ----------
static void AutoSave(void)
{
    // Called after every modification
    SaveRegistryToFile();
}



LSTATUS WINAPI Hook_RegDeleteValueW(HKEY hKey, LPCWSTR lpValueName)
{
    LogMsg("RegDeleteValueW(hKey=0x%p, value=%ls)", hKey, lpValueName);

    if (hKey == FAKE_SERVICE_KEY) {
        LogMsg("  -> ignored (fake service key)");
        return ERROR_SUCCESS;
    }

    RegKey* key = HandleToKey(hKey);
    if (!key) {
        // Not our handle – forward to real API
        if (Real_RegDeleteValueW)
            return Real_RegDeleteValueW(hKey, lpValueName);
        SetLastError(ERROR_INVALID_HANDLE);
        return ERROR_INVALID_HANDLE;
    }

    // Find and remove the value from the linked list
    RegValue* prev = NULL;
    RegValue* v = key->values;
    while (v) {
        if (_wcsicmp(v->name, lpValueName ? lpValueName : L"") == 0)
            break;
        prev = v;
        v = v->next;
    }

    if (!v) {
        LogMsg("  -> value not found");
        SetLastError(ERROR_FILE_NOT_FOUND);
        return ERROR_FILE_NOT_FOUND;
    }

    if (prev)
        prev->next = v->next;
    else
        key->values = v->next;

    // Free the value
    HeapFree(GetProcessHeap(), 0, v->name);
    HeapFree(GetProcessHeap(), 0, v->data);
    HeapFree(GetProcessHeap(), 0, v);

    AutoSave();
    LogMsg("  -> deleted successfully");
    return ERROR_SUCCESS;
}

// LSTATUS WINAPI Hook_RegNotifyChangeKeyValue(HKEY hKey, BOOL bWatchSubtree,
//                                             DWORD dwNotifyFilter, HANDLE hEvent,
//                                             BOOL fAsynchronous)
// {
//     LogMsg("RegNotifyChangeKeyValue(hKey=0x%p, subtree=%d, filter=0x%lx, event=0x%p, async=%d)",
//            hKey, bWatchSubtree, dwNotifyFilter, hEvent, fAsynchronous);

//     if (hKey == FAKE_SERVICE_KEY || HandleToKey(hKey) != NULL) {
//         // It's our key – we know it never changes, so signal the event (if any) immediately.
//         if (hEvent && fAsynchronous) {
//             SetEvent(hEvent);
//         }
//         LogMsg("  -> fake success (no external changes)");
//         return ERROR_SUCCESS;
//     }

//     // Forward to real API if not our handle
//     if (Real_RegNotifyChangeKeyValue)
//         return Real_RegNotifyChangeKeyValue(hKey, bWatchSubtree, dwNotifyFilter, hEvent, fAsynchronous);

//     SetLastError(ERROR_INVALID_HANDLE);
//     return ERROR_INVALID_HANDLE;
// }

LSTATUS WINAPI Hook_RegNotifyChangeKeyValue(HKEY hKey, BOOL bWatchSubtree,
                                            DWORD dwNotifyFilter, HANDLE hEvent,
                                            BOOL fAsynchronous)
{
    LogMsg("RegNotifyChangeKeyValue(hKey=0x%p, subtree=%d, filter=0x%lx, event=0x%p, async=%d)",
           hKey, bWatchSubtree, dwNotifyFilter, hEvent, fAsynchronous);

    if (hKey == FAKE_SERVICE_KEY || HandleToKey(hKey) != NULL) {
        // This is our key. We do NOT signal the event – our registry never changes
        // unless we make a change (e.g., via SetValueEx). The service will wait.
        // If you later need to wake the service, you can store the event handle
        // and call SetEvent after a write.
        LogMsg("  -> notification registered (event will NOT be signaled)");
        return ERROR_SUCCESS;
    }

    // Forward to real API if not our handle
    if (Real_RegNotifyChangeKeyValue)
        return Real_RegNotifyChangeKeyValue(hKey, bWatchSubtree, dwNotifyFilter, hEvent, fAsynchronous);

    SetLastError(ERROR_INVALID_HANDLE);
    return ERROR_INVALID_HANDLE;
}

// Helper: build the full path for a newly opened/created key
static wchar_t* BuildFullPath(HKEY hKey, LPCWSTR lpSubKey)
{
    // Predefined root → just the subkey
    if (hKey == HKEY_LOCAL_MACHINE || hKey == HKEY_CURRENT_USER ||
        hKey == HKEY_CLASSES_ROOT || hKey == HKEY_USERS) {
        if (lpSubKey && *lpSubKey)
            return _wcsdup(lpSubKey);
        return _wcsdup(L"");
    }

    // Fake handle → combine base key’s path with subkey
    wchar_t* basePath = GetKeyPath(hKey);
    if (!basePath) return (lpSubKey && *lpSubKey) ? _wcsdup(lpSubKey) : _wcsdup(L"");

    size_t baseLen = wcslen(basePath);
    size_t subLen  = (lpSubKey && *lpSubKey) ? wcslen(lpSubKey) : 0;
    size_t total   = baseLen + (subLen ? 1 + subLen : 0) + 1;  // base + "\\" + sub + null

    wchar_t* full = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, total * sizeof(wchar_t));
    wcscpy(full, basePath);
    if (subLen) {
        wcscat(full, L"\\");
        wcscat(full, lpSubKey);
    }
    return full;
}

// ---------- Updated hooks ----------

#include <dbghelp.h>   // if you want symbol names (optional, requires dbghelp.lib)
#pragma comment(lib, "dbghelp.lib")

void LogStackTrace(const char *reason, int framesToSkip)
{
    void *stack[32];
    WORD frames = CaptureStackBackTrace(framesToSkip, 32, stack, NULL);
    LogMsg("=== Stack trace (%s) ===", reason);
    for (WORD i = 0; i < frames; i++) {
        DWORD64 addr = (DWORD64)stack[i];
        HMODULE hMod = NULL;
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(stack[i], &mbi, sizeof(mbi))) {
            hMod = (HMODULE)mbi.AllocationBase;
        }
        wchar_t modName[MAX_PATH] = L"<unknown>";
        DWORD64 offset = addr;
        if (hMod) {
            GetModuleFileNameW(hMod, modName, MAX_PATH);
            offset = addr - (DWORD64)hMod;
        }
        const wchar_t *modBaseName = wcsrchr(modName, L'\\');
        if (modBaseName) modBaseName++;
        else modBaseName = modName;

        LogMsg("  [%2u] 0x%p  %ls+0x%I64X", i, (void*)addr, modBaseName, offset);
    }
}

static BOOL KeyExists(RegKey* base, const wchar_t* path)
{
    if (!base) base = g_regRoot;
    if (!path || !*path) return TRUE;   // base itself always exists

    wchar_t temp[512];
    lstrcpynW(temp, path, 512);
    wchar_t *ctx = NULL;
    wchar_t *token = wcstok_s(temp, L"\\", &ctx);

    RegKey* cur = base;
    while (token && cur) {
        RegKey* child = cur->child;
        while (child) {
            if (_wcsicmp(child->name, token) == 0) break;
            child = child->sibling;
        }
        if (!child) return FALSE;   // a component is missing
        cur = child;
        token = wcstok_s(NULL, L"\\", &ctx);
    }
    return token == NULL;   // all components found
}

LSTATUS WINAPI Hook_RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass,
                                    DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSec,
                                    PHKEY phkResult, LPDWORD lpdwDisposition)
{
    // LogStackTrace("Hook_RegCreateKeyExW called", 0);
    LogMsg("RegCreateKeyExW(%ls)", lpSubKey);

    wchar_t *redirected = RedirectSubKey(hKey, lpSubKey);
    if (!redirected) return ERROR_OUTOFMEMORY;

    // Determine base key (same as before)
    RegKey* base = NULL;
    if (hKey == HKEY_LOCAL_MACHINE || hKey == HKEY_CURRENT_USER || hKey == HKEY_CLASSES_ROOT) {
        base = g_regRoot;
    } else {
        base = HandleToKey(hKey);
        if (!base) {
            LogMsg("RegCreateKeyExW(%ls) ERROR_INVALID_HANDLE", lpSubKey);
            SetLastError(ERROR_INVALID_HANDLE);
            HeapFree(GetProcessHeap(), 0, redirected);
            return ERROR_INVALID_HANDLE;
        }
    }

    BOOL existed = KeyExists(base, redirected);
    RegKey* key = NavigatePath(base, redirected, TRUE);
    if (!key) {
        SetLastError(ERROR_INVALID_PARAMETER);
        HeapFree(GetProcessHeap(), 0, redirected);
        return ERROR_INVALID_PARAMETER;
    }

    if (lpdwDisposition)
        *lpdwDisposition = existed ? REG_OPENED_EXISTING_KEY : REG_CREATED_NEW_KEY;

    wchar_t* fullPath = BuildFullPath(hKey, redirected);
    HKEY newHandle = AllocHandle(key, fullPath);
    HKEY cached = CacheLookup(fullPath, newHandle);
    *phkResult = cached;

    LogMsg("  -> handle 0x%p (path \"%ls\")", *phkResult, fullPath);
    HeapFree(GetProcessHeap(), 0, fullPath);
    HeapFree(GetProcessHeap(), 0, redirected);
    AutoSave();
    return ERROR_SUCCESS;
}

// ---------- Modified hooks to intercept everything ----------

LSTATUS WINAPI Hook_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    LogMsg("RegOpenKeyExW(hKey=0x%p, subKey=%ls, options=0x%lx, sam=0x%lx)",
           hKey, lpSubKey ? lpSubKey : L"(null)", ulOptions, samDesired);

    if (lpSubKey && wcsstr(lpSubKey, L"RVPNNETMP")) {
        *phkResult = FAKE_SERVICE_KEY;
        LogMsg("  -> fake service key 0x%p", *phkResult);
        return ERROR_SUCCESS;
    }

    wchar_t *redirected = RedirectSubKey(hKey, lpSubKey);
    if (!redirected) return ERROR_OUTOFMEMORY;

    RegKey* base = NULL;
    if (hKey == HKEY_LOCAL_MACHINE || hKey == HKEY_CURRENT_USER || hKey == HKEY_CLASSES_ROOT) {
        base = g_regRoot;
    } else {
        base = HandleToKey(hKey);
        if (!base) {
            LogMsg("  -> invalid handle");
            SetLastError(ERROR_INVALID_HANDLE);
            HeapFree(GetProcessHeap(), 0, redirected);
            return ERROR_INVALID_HANDLE;
        }
    }

    RegKey* key = NavigatePath(base, redirected, FALSE);   // use redirected path
    if (!key) {
        LogMsg("  -> key not found");
        SetLastError(ERROR_FILE_NOT_FOUND);
        HeapFree(GetProcessHeap(), 0, redirected);
        return ERROR_FILE_NOT_FOUND;
    }

    wchar_t* fullPath = BuildFullPath(hKey, redirected);    // build with redirected
    HKEY newHandle = AllocHandle(key, fullPath);
    HKEY cached = CacheLookup(fullPath, newHandle);
    *phkResult = cached;

    LogMsg("  -> returning handle 0x%p (path \"%ls\")", *phkResult, fullPath);
    HeapFree(GetProcessHeap(), 0, fullPath);
    HeapFree(GetProcessHeap(), 0, redirected);
    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved,
                                   DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    // LogStackTrace("Hook_RegSetValueExW called", 0);
    // Log everything about the call
    LogMsg("RegSetValueExW(hKey=0x%p, value=%ls, type=%lu, size=%lu)",
           hKey, lpValueName ? lpValueName : L"(default)", dwType, cbData);

    if (hKey == FAKE_SERVICE_KEY) {
        LogMsg("  -> ignored (fake service key)");
        return ERROR_SUCCESS;
    }

    RegKey* key = HandleToKey(hKey);
    if (!key) {
        LogMsg("  -> invalid handle");
        SetLastError(ERROR_INVALID_HANDLE);
        return ERROR_INVALID_HANDLE;
    }

    // Log the data content based on type
    if (lpData && cbData > 0) {
        switch (dwType) {
        case REG_SZ:
        case REG_EXPAND_SZ:
            LogMsg("  data = \"%ls\"", (const wchar_t*)lpData);
            break;
        case REG_DWORD:
            if (cbData >= sizeof(DWORD))
                LogMsg("  data = 0x%lX (%lu)", *(const DWORD*)lpData, *(const DWORD*)lpData);
            else
                LogMsg("  data = <bad DWORD size>");
            break;
        case REG_QWORD:   // 11
            if (cbData >= sizeof(ULONGLONG))
                LogMsg("  data = 0x%llX (%llu)", *(const ULONGLONG*)lpData, *(const ULONGLONG*)lpData);
            else
                LogMsg("  data = <bad QWORD size>");
            break;
        case REG_MULTI_SZ: {
            LogMsg("  data (multi-string):");
            const wchar_t* p = (const wchar_t*)lpData;
            while (*p) {
                LogMsg("    \"%ls\"", p);
                p += wcslen(p) + 1;
            }
            break;
        }
        case REG_BINARY:
            LogMsg("  data (binary, %lu bytes):", cbData);
            LogHex(lpData, cbData, "    ");
            break;
        default:
            LogMsg("  data (type %lu, size %lu)", dwType, cbData);
            LogHex(lpData, min(cbData, 64), "    ");
            break;
        }
    } else {
        LogMsg("  data = NULL or zero size");
    }

    // Always save the value – never block
    SetValue(key, lpValueName ? lpValueName : L"", dwType, lpData, cbData);
    AutoSave();
    LogMsg("  -> saved successfully");
    return ERROR_SUCCESS;
}


LSTATUS WINAPI Hook_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved,
                                     LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    DWORD bufSize = lpcbData ? *lpcbData : 0;
    LogMsg("RegQueryValueExW(hKey=0x%p, value=%ls, bufSize=%lu)", hKey, lpValueName, bufSize);

    RegKey* key = HandleToKey(hKey);
    if (!key) {
        // Maybe the handle was not created yet – try to resolve the path
        wchar_t* path = GetKeyPath(hKey);
        if (path) {
            LogMsg("  -> key 0x%p not in memory, auto-creating from path: %ls", hKey, path);
            // Create the full path in the store
            key = NavigatePath(g_regRoot, path, TRUE);
            if (key) {
                // Store the key in the handle table (replace old entry)
                DWORD idx = (DWORD)((ULONG_PTR)hKey - FAKE_HANDLE_BASE);
                if (idx < g_fakeKeyCount) {
                    g_fakeKeyTable[idx] = key;
                }
                // Proceed with the newly created key
            }
        }
        if (!key) {
            LogMsg("  -> invalid handle");
            SetLastError(ERROR_INVALID_HANDLE);
            return ERROR_INVALID_HANDLE;
        }
    }
        
    // --- Fake service key ---
    if (hKey == FAKE_SERVICE_KEY) {
        if (lpValueName && wcscmp(lpValueName, L"ImagePath") == 0) {
            static const wchar_t path[] = L"\\SystemRoot\\System32\\drivers\\rvpnnetmp.sys";
            DWORD needed = sizeof(path);
            if (lpData && bufSize >= needed) {
                memcpy(lpData, path, needed);
                *lpcbData = needed;
                if (lpType) *lpType = REG_EXPAND_SZ;
                LogMsg("  -> fake ImagePath = \"%ls\"", path);
                return ERROR_SUCCESS;
            } else {
                *lpcbData = needed;
                if (lpType) *lpType = REG_EXPAND_SZ;
                LogMsg("  -> fake ImagePath: buffer too small (need %lu)", needed);
                return ERROR_MORE_DATA;
            }
        }
        if (lpValueName && wcscmp(lpValueName, L"Start") == 0) {
            DWORD start = SERVICE_SYSTEM_START;
            DWORD needed = sizeof(start);
            if (lpData && bufSize >= needed) {
                memcpy(lpData, &start, needed);
                *lpcbData = needed;
                if (lpType) *lpType = REG_DWORD;
                LogMsg("  -> fake Start = %lu", start);
                return ERROR_SUCCESS;
            } else {
                *lpcbData = needed;
                if (lpType) *lpType = REG_DWORD;
                LogMsg("  -> fake Start: buffer too small (need %lu)", needed);
                return ERROR_MORE_DATA;
            }
        }
        // Unknown value on fake service key
        *lpcbData = 0;
        LogMsg("  -> unknown fake value, returning empty");
        return ERROR_SUCCESS;
    }

    // --- Our emulated key ---
    if (key) {
        DWORD type = 0, size = 0;
        if (!GetValue(key, lpValueName ? lpValueName : L"", &type, NULL, &size)) {
            LogMsg("  -> value not found");
            SetLastError(ERROR_FILE_NOT_FOUND);
            return ERROR_FILE_NOT_FOUND;
        }

        if (lpType) *lpType = type;

        if (lpData) {
            if (bufSize < size) {
                *lpcbData = size;
                LogMsg("  -> buffer too small (need %lu, have %lu)", size, bufSize);
                return ERROR_MORE_DATA;
            }
            GetValue(key, lpValueName ? lpValueName : L"", NULL, lpData, &size);
        }
        *lpcbData = size;

        // Log the returned data
        if (lpData && size > 0) {
            switch (type) {
            case REG_SZ:
            case REG_EXPAND_SZ:
                LogMsg("  -> REG_SZ = \"%ls\"", (wchar_t*)lpData);
                break;
            case REG_DWORD:
                LogMsg("  -> REG_DWORD = 0x%lX (%lu)", *(DWORD*)lpData, *(DWORD*)lpData);
                break;
            case REG_MULTI_SZ: {
                LogMsg("  -> REG_MULTI_SZ");
                const wchar_t* p = (const wchar_t*)lpData;
                while (*p) {
                    LogMsg("    \"%ls\"", p);
                    p += wcslen(p) + 1;
                }
                break;
            }
            case REG_BINARY:
                LogMsg("  -> REG_BINARY (%lu bytes)", size);
                LogHex(lpData, size, "    ");
                break;
            default:
                LogMsg("  -> type %lu, size %lu", type, size);
                break;
            }
        } else if (lpData == NULL) {
            LogMsg("  -> size query only (type=%lu, size=%lu)", type, size);
        }
        return ERROR_SUCCESS;
    }

    // --- Not one of our handles, forward to real API ---
    LSTATUS result;
    if (Real_RegQueryValueExW) {
        result = Real_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    } else {
        result = ERROR_FILE_NOT_FOUND;
    }

    // Log the result of the real call
    if (result == ERROR_SUCCESS && lpData && lpType && lpcbData) {
        switch (*lpType) {
        case REG_SZ:
        case REG_EXPAND_SZ:
            LogMsg("  real -> REG_SZ = \"%ls\"", (wchar_t*)lpData);
            break;
        case REG_DWORD:
            LogMsg("  real -> REG_DWORD = 0x%lX (%lu)", *(DWORD*)lpData, *(DWORD*)lpData);
            break;
        case REG_MULTI_SZ: {
            LogMsg("  real -> REG_MULTI_SZ");
            const wchar_t* p = (const wchar_t*)lpData;
            while (*p) {
                LogMsg("    \"%ls\"", p);
                p += wcslen(p) + 1;
            }
            break;
        }
        case REG_BINARY:
            LogMsg("  real -> REG_BINARY (%lu bytes)", *lpcbData);
            LogHex(lpData, *lpcbData, "    ");
            break;
        default:
            LogMsg("  real -> type %lu, size %lu", *lpType, *lpcbData);
            break;
        }
    } else if (result == ERROR_MORE_DATA) {
        LogMsg("  real -> buffer too small (need %lu)", lpcbData ? *lpcbData : 0);
    } else if (result != ERROR_SUCCESS) {
        LogMsg("  real -> error %ld", result);
    } else if (lpData == NULL) {
        LogMsg("  real -> size query (type=%lu, size=%lu)", lpType ? *lpType : 0, lpcbData ? *lpcbData : 0);
    }

    return result;
}

LSTATUS WINAPI Hook_RegCloseKey(HKEY hKey)
{
    LogMsg("RegCloseKey");
    if (hKey == FAKE_SERVICE_KEY) return ERROR_SUCCESS;
    RegKey* key = HandleToKey(hKey);
    if (key) {
        // We don't free the key; just return success (keys stay in memory)
        return ERROR_SUCCESS;
    }
    return Real_RegCloseKey ? Real_RegCloseKey(hKey) : ERROR_SUCCESS;
}

static void ResetHandleTable(void)
{
    for (DWORD i = 0; i < g_fakeKeyCount; i++) {
        if (g_fakeKeyPaths[i]) {
            HeapFree(GetProcessHeap(), 0, g_fakeKeyPaths[i]);
            g_fakeKeyPaths[i] = NULL;
        }
    }
    g_fakeKeyCount = 0;
    memset(g_handleCache, 0, sizeof(g_handleCache));
    g_cachedCount = 0;
}

// ---------- Declaration and hook for RegOpenKeyW ----------
typedef LSTATUS (WINAPI *RegOpenKeyW_t)(HKEY, LPCWSTR, PHKEY);
static RegOpenKeyW_t Real_RegOpenKeyW = NULL;

LSTATUS WINAPI Hook_RegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
    // Log the call with the same detail as Ex version
    LogMsg("RegOpenKeyW(hKey=0x%p, subKey=%ls)", hKey, lpSubKey ? lpSubKey : L"(null)");

    // Handle the special fake service key trigger (same as Ex)
    if (lpSubKey && wcsstr(lpSubKey, L"RVPNNETMP")) {
        *phkResult = FAKE_SERVICE_KEY;
        LogMsg("  -> fake service key 0x%p", *phkResult);
        return ERROR_SUCCESS;
    }

    // --- WOW64 Redirection ---
    wchar_t *redirected = RedirectSubKey(hKey, lpSubKey);
    if (!redirected) {
        SetLastError(ERROR_OUTOFMEMORY);
        return ERROR_OUTOFMEMORY;
    }
    if (wcscmp(redirected, lpSubKey ? lpSubKey : L"") != 0) {
        LogMsg("  -> WOW64 redirected to \"%ls\"", redirected);
    }

    // Determine the base key from the input handle
    RegKey* base = NULL;
    if (hKey == HKEY_LOCAL_MACHINE || hKey == HKEY_CURRENT_USER ||
        hKey == HKEY_CLASSES_ROOT || hKey == HKEY_USERS) {
        base = g_regRoot;
    } else {
        base = HandleToKey(hKey);
        if (!base) {
            // Not one of our handles – forward to the real API
            if (Real_RegOpenKeyW) {
                LSTATUS result = Real_RegOpenKeyW(hKey, lpSubKey, phkResult);
                LogMsg("  -> forwarded to real RegOpenKeyW, result=%ld", result);
                HeapFree(GetProcessHeap(), 0, redirected);
                return result;
            }
            LogMsg("  -> invalid handle and no real API available");
            SetLastError(ERROR_INVALID_HANDLE);
            HeapFree(GetProcessHeap(), 0, redirected);
            return ERROR_INVALID_HANDLE;
        }
    }

    // Open the key without creating, using the redirected path
    RegKey* key = NavigatePath(base, redirected, FALSE);
    if (!key) {
        LogMsg("  -> key not found (path=\"%ls\")", redirected);
        SetLastError(ERROR_FILE_NOT_FOUND);
        HeapFree(GetProcessHeap(), 0, redirected);
        return ERROR_FILE_NOT_FOUND;
    }

    // Build the full logical path using the redirected subkey
    wchar_t* fullPath = BuildFullPath(hKey, redirected);
    HKEY newHandle = AllocHandle(key, fullPath);
    HKEY cached = CacheLookup(fullPath, newHandle);
    *phkResult = cached;

    if (cached != newHandle) {
        LogMsg("  -> cache hit, reusing handle 0x%p for path \"%ls\"", cached, fullPath);
    } else {
        LogMsg("  -> new handle 0x%p (path \"%ls\")", *phkResult, fullPath);
    }

    HeapFree(GetProcessHeap(), 0, fullPath);
    HeapFree(GetProcessHeap(), 0, redirected);
    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegCreateKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
    LogMsg("RegCreateKeyW(hKey=0x%p, subKey=%ls)", hKey, lpSubKey ? lpSubKey : L"(null)");

    // --- WOW64 Redirection ---
    wchar_t *redirected = RedirectSubKey(hKey, lpSubKey);
    if (!redirected) {
        SetLastError(ERROR_OUTOFMEMORY);
        return ERROR_OUTOFMEMORY;
    }
    if (wcscmp(redirected, lpSubKey ? lpSubKey : L"") != 0) {
        LogMsg("  -> WOW64 redirected to \"%ls\"", redirected);
    }

    // Determine the base key
    RegKey* base = NULL;
    if (hKey == HKEY_LOCAL_MACHINE || hKey == HKEY_CURRENT_USER ||
        hKey == HKEY_CLASSES_ROOT || hKey == HKEY_USERS) {
        base = g_regRoot;
    } else {
        base = HandleToKey(hKey);
        if (!base) {
            // Not our handle – forward to real API
            if (Real_RegCreateKeyW) {
                LSTATUS result = Real_RegCreateKeyW(hKey, lpSubKey, phkResult);
                LogMsg("  -> forwarded to real RegCreateKeyW, result=%ld", result);
                HeapFree(GetProcessHeap(), 0, redirected);
                return result;
            }
            LogMsg("  -> invalid handle and no real API available");
            SetLastError(ERROR_INVALID_HANDLE);
            HeapFree(GetProcessHeap(), 0, redirected);
            return ERROR_INVALID_HANDLE;
        }
    }

    // Create the key (auto-create missing components), using the redirected path
    RegKey* key = NavigatePath(base, redirected, TRUE);
    if (!key) {
        LogMsg("  -> failed to create key (path=\"%ls\")", redirected);
        SetLastError(ERROR_INVALID_PARAMETER);
        HeapFree(GetProcessHeap(), 0, redirected);
        return ERROR_INVALID_PARAMETER;
    }

    // Build the full logical path using the redirected subkey
    wchar_t* fullPath = BuildFullPath(hKey, redirected);
    HKEY newHandle = AllocHandle(key, fullPath);
    HKEY cached = CacheLookup(fullPath, newHandle);
    *phkResult = cached;

    if (cached != newHandle) {
        LogMsg("  -> cache hit, reusing handle 0x%p for path \"%ls\"", cached, fullPath);
    } else {
        LogMsg("  -> new handle 0x%p (path \"%ls\")", *phkResult, fullPath);
    }

    HeapFree(GetProcessHeap(), 0, fullPath);
    HeapFree(GetProcessHeap(), 0, redirected);
    AutoSave();
    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey)
{
    LogMsg("RegDeleteKeyW(hKey=0x%p, subKey=%ls)", hKey, lpSubKey);

    if (hKey == FAKE_SERVICE_KEY) {
        LogMsg("  -> ignored (fake service key)");
        return ERROR_SUCCESS;
    }

    RegKey* base = HandleToKey(hKey);
    if (!base) {
        if (Real_RegDeleteKeyW)
            return Real_RegDeleteKeyW(hKey, lpSubKey);
        SetLastError(ERROR_INVALID_HANDLE);
        return ERROR_INVALID_HANDLE;
    }

    // Find the child key and remove it from the sibling list
    RegKey* prev = NULL;
    RegKey* child = base->child;
    while (child) {
        if (_wcsicmp(child->name, lpSubKey) == 0) break;
        prev = child;
        child = child->sibling;
    }

    if (!child) {
        LogMsg("  -> key not found");
        SetLastError(ERROR_FILE_NOT_FOUND);
        return ERROR_FILE_NOT_FOUND;
    }

    if (prev)
        prev->sibling = child->sibling;
    else
        base->child = child->sibling;

    // Free the key name (note: subkeys and values are leaked unless you add recursive cleanup)
    HeapFree(GetProcessHeap(), 0, child->name);
    HeapFree(GetProcessHeap(), 0, child);

    AutoSave();
    LogMsg("  -> deleted successfully");
    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegDeleteKeyExW(HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, DWORD Reserved)
{
    LogMsg("RegDeleteKeyExW(hKey=0x%p, subKey=%ls, sam=0x%lx)", hKey, lpSubKey, samDesired);
    // For our fake registry, samDesired and Reserved don't matter
    return Hook_RegDeleteKeyW(hKey, lpSubKey);
}

LSTATUS WINAPI Hook_RegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName,
                                   LPDWORD lpcchName, LPDWORD lpReserved,
                                   LPWSTR lpClass, LPDWORD lpcchClass,
                                   PFILETIME lpftLastWriteTime)
{
    LogMsg("RegEnumKeyExW(hKey=0x%p, index=%lu)", hKey, dwIndex);

    if (hKey == FAKE_SERVICE_KEY) {
        SetLastError(ERROR_NO_MORE_ITEMS);
        return ERROR_NO_MORE_ITEMS;
    }

    RegKey* key = HandleToKey(hKey);
    if (!key) {
        if (Real_RegEnumKeyExW)
            return Real_RegEnumKeyExW(hKey, dwIndex, lpName, lpcchName, lpReserved,
                                      lpClass, lpcchClass, lpftLastWriteTime);
        SetLastError(ERROR_INVALID_HANDLE);
        return ERROR_INVALID_HANDLE;
    }

    RegKey* child = key->child;
    DWORD i = 0;
    while (child && i < dwIndex) {
        child = child->sibling;
        i++;
    }

    if (!child) {
        SetLastError(ERROR_NO_MORE_ITEMS);
        return ERROR_NO_MORE_ITEMS;
    }

    if (child->name) {
        DWORD len = (DWORD)wcslen(child->name);
        if (*lpcchName <= len) {
            *lpcchName = len + 1;
            return ERROR_MORE_DATA;
        }
        lstrcpynW(lpName, child->name, *lpcchName);
        *lpcchName = len;
    } else {
        lpName[0] = L'\0';
        *lpcchName = 0;
    }

    if (lpcchClass) *lpcchClass = 0;
    if (lpReserved) *lpReserved = 0;
    if (lpftLastWriteTime) {
        // Fake: use current time
        SYSTEMTIME st;
        GetSystemTime(&st);
        SystemTimeToFileTime(&st, lpftLastWriteTime);
    }
    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegEnumKeyW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, DWORD cchName)
{
    LogMsg("RegEnumKeyW(hKey=0x%p, index=%lu)", hKey, dwIndex);

    if (hKey == FAKE_SERVICE_KEY) {
        SetLastError(ERROR_NO_MORE_ITEMS);
        return ERROR_NO_MORE_ITEMS;
    }

    RegKey* key = HandleToKey(hKey);
    if (!key) {
        if (Real_RegEnumKeyW)
            return Real_RegEnumKeyW(hKey, dwIndex, lpName, cchName);
        SetLastError(ERROR_INVALID_HANDLE);
        return ERROR_INVALID_HANDLE;
    }

    RegKey* child = key->child;
    DWORD i = 0;
    while (child && i < dwIndex) {
        child = child->sibling;
        i++;
    }

    if (!child) {
        SetLastError(ERROR_NO_MORE_ITEMS);
        return ERROR_NO_MORE_ITEMS;
    }

    if (child->name) {
        lstrcpynW(lpName, child->name, cchName);
    } else {
        lpName[0] = L'\0';
    }
    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegEnumValueW(HKEY hKey, DWORD dwIndex, LPWSTR lpValueName,
                                   LPDWORD lpcchValueName, LPDWORD lpReserved,
                                   LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    LogMsg("RegEnumValueW(hKey=0x%p, index=%lu)", hKey, dwIndex);

    if (hKey == FAKE_SERVICE_KEY) {
        SetLastError(ERROR_NO_MORE_ITEMS);
        return ERROR_NO_MORE_ITEMS;
    }

    RegKey* key = HandleToKey(hKey);
    if (!key) {
        if (Real_RegEnumValueW)
            return Real_RegEnumValueW(hKey, dwIndex, lpValueName, lpcchValueName,
                                      lpReserved, lpType, lpData, lpcbData);
        SetLastError(ERROR_INVALID_HANDLE);
        return ERROR_INVALID_HANDLE;
    }

    RegValue* v = key->values;
    DWORD i = 0;
    while (v && i < dwIndex) {
        v = v->next;
        i++;
    }

    if (!v) {
        SetLastError(ERROR_NO_MORE_ITEMS);
        return ERROR_NO_MORE_ITEMS;
    }

    if (lpcchValueName) {
        DWORD nameLen = (v->name && *v->name) ? (DWORD)wcslen(v->name) : 0;
        if (*lpcchValueName <= nameLen) {
            *lpcchValueName = nameLen + 1;
            return ERROR_MORE_DATA;
        }
        if (lpValueName) {
            lstrcpynW(lpValueName, v->name ? v->name : L"", *lpcchValueName);
        }
        *lpcchValueName = nameLen;
    }

    if (lpType) *lpType = v->type;
    if (lpReserved) *lpReserved = 0;

    if (lpData && lpcbData) {
        if (*lpcbData < v->size) {
            *lpcbData = v->size;
            return ERROR_MORE_DATA;
        }
        memcpy(lpData, v->data, v->size);
        *lpcbData = v->size;
    } else if (lpcbData) {
        *lpcbData = v->size;
    }

    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegQueryInfoKeyW(HKEY hKey, LPWSTR lpClass, LPDWORD lpcchClass,
                                      LPDWORD lpReserved, LPDWORD lpcSubKeys,
                                      LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen,
                                      LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen,
                                      LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor,
                                      PFILETIME lpftLastWriteTime)
{
    LogMsg("RegQueryInfoKeyW(hKey=0x%p)", hKey);

    if (hKey == FAKE_SERVICE_KEY) {
        if (lpcSubKeys) *lpcSubKeys = 0;
        if (lpcValues) *lpcValues = 0;
        if (lpcchClass) { lpClass[0] = L'\0'; *lpcchClass = 0; }
        return ERROR_SUCCESS;
    }

    RegKey* key = HandleToKey(hKey);
    if (!key) {
        if (Real_RegQueryInfoKeyW)
            return Real_RegQueryInfoKeyW(hKey, lpClass, lpcchClass, lpReserved,
                                         lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen,
                                         lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen,
                                         lpcbSecurityDescriptor, lpftLastWriteTime);
        SetLastError(ERROR_INVALID_HANDLE);
        return ERROR_INVALID_HANDLE;
    }

    // Count subkeys
    DWORD subKeys = 0;
    DWORD maxSubKeyLen = 0;
    for (RegKey* child = key->child; child; child = child->sibling) {
        subKeys++;
        DWORD len = (DWORD)(child->name ? wcslen(child->name) : 0);
        if (len > maxSubKeyLen) maxSubKeyLen = len;
    }

    // Count values
    DWORD values = 0;
    DWORD maxValueNameLen = 0;
    DWORD maxValueLen = 0;
    for (RegValue* v = key->values; v; v = v->next) {
        values++;
        DWORD nameLen = (DWORD)(v->name ? wcslen(v->name) : 0);
        if (nameLen > maxValueNameLen) maxValueNameLen = nameLen;
        if (v->size > maxValueLen) maxValueLen = v->size;
    }

    if (lpcSubKeys) *lpcSubKeys = subKeys;
    if (lpcbMaxSubKeyLen) *lpcbMaxSubKeyLen = maxSubKeyLen + 1;
    if (lpcValues) *lpcValues = values;
    if (lpcbMaxValueNameLen) *lpcbMaxValueNameLen = maxValueNameLen + 1;
    if (lpcbMaxValueLen) *lpcbMaxValueLen = maxValueLen;
    if (lpcbMaxClassLen) *lpcbMaxClassLen = 0;
    if (lpcbSecurityDescriptor) *lpcbSecurityDescriptor = 0;
    if (lpcchClass) { lpClass[0] = L'\0'; *lpcchClass = 0; }
    if (lpReserved) *lpReserved = 0;
    if (lpftLastWriteTime) {
        SYSTEMTIME st;
        GetSystemTime(&st);
        SystemTimeToFileTime(&st, lpftLastWriteTime);
    }
    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegDeleteTreeW(HKEY hKey, LPCWSTR lpSubKey)
{
    LogMsg("RegDeleteTreeW(hKey=0x%p, subKey=%ls) -> fake success", hKey, lpSubKey);
    // Just call RegDeleteKeyW – our fake implementation removes the node
    // (real RegDeleteTreeW recursively deletes subkeys; we ignore that here)
    return Hook_RegDeleteKeyW(hKey, lpSubKey);
}

LSTATUS WINAPI Hook_RegCopyTreeW(HKEY hKeySrc, LPCWSTR lpSubKey, HKEY hKeyDest)
{
    LogMsg("RegCopyTreeW(src=0x%p, subKey=%ls, dest=0x%p) -> fake success", hKeySrc, lpSubKey, hKeyDest);
    // We don't implement actual copying – return success
    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegGetValueW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue,
                                  DWORD dwFlags, LPDWORD pdwType,
                                  PVOID pvData, LPDWORD pcbData)
{
    LogMsg("RegGetValueW(hKey=0x%p, subKey=%ls, value=%ls, flags=0x%lx)",
           hKey, lpSubKey, lpValue, dwFlags);

    // If a subkey is specified, open it first
    HKEY hTargetKey = hKey;
    if (lpSubKey && *lpSubKey) {
        LONG lr = Hook_RegOpenKeyExW(hKey, lpSubKey, 0, KEY_READ, &hTargetKey);
        if (lr != ERROR_SUCCESS)
            return lr;
    }

    // Query the value using our existing hook
    LSTATUS result = Hook_RegQueryValueExW(hTargetKey, lpValue, NULL, pdwType,
                                            (LPBYTE)pvData, pcbData);

    // Close if we opened a subkey
    if (lpSubKey && *lpSubKey)
        Hook_RegCloseKey(hTargetKey);

    // RegGetValueW can expand REG_EXPAND_SZ automatically
    if (result == ERROR_SUCCESS && pdwType && *pdwType == REG_EXPAND_SZ && !(dwFlags & RRF_NOEXPAND)) {
        if (dwFlags & RRF_RT_REG_SZ) {
            // Caller wants plain REG_SZ; we could expand here but skip for now
            *pdwType = REG_SZ;
        }
    }

    return result;
}

// ---------- Installation ----------
void Register_InstallHooks(HMODULE hOriginalDll, HMODULE hAdvapi32)
{

    BOOL wow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &wow64);
    g_isWow64 = wow64;

    Real_RegOpenKeyW = (RegOpenKeyW_t)GetProcAddress(hAdvapi32, "RegOpenKeyW");
    Real_RegOpenKeyExW    = (RegOpenKeyExW_t)GetProcAddress(hAdvapi32, "RegOpenKeyExW");
    Real_RegQueryValueExW = (RegQueryValueExW_t)GetProcAddress(hAdvapi32, "RegQueryValueExW");
    Real_RegCloseKey      = (RegCloseKey_t)GetProcAddress(hAdvapi32, "RegCloseKey");
    Real_RegCreateKeyExW  = (RegCreateKeyExW_t)GetProcAddress(hAdvapi32, "RegCreateKeyExW");
    // Also save the real RegSetValueExW (missing earlier)
    Real_RegSetValueExW   = (RegSetValueExW_t)GetProcAddress(hAdvapi32, "RegSetValueExW");
    Real_RegDeleteValueW         = (RegDeleteValueW_t)GetProcAddress(hAdvapi32, "RegDeleteValueW");
    Real_RegNotifyChangeKeyValue = (RegNotifyChangeKeyValue_t)GetProcAddress(hAdvapi32, "RegNotifyChangeKeyValue");

    // Additional hooks
    Real_RegCreateKeyW       = (RegCreateKeyW_t)GetProcAddress(hAdvapi32, "RegCreateKeyW");
    Real_RegDeleteKeyW       = (RegDeleteKeyW_t)GetProcAddress(hAdvapi32, "RegDeleteKeyW");
    Real_RegDeleteKeyExW     = (RegDeleteKeyExW_t)GetProcAddress(hAdvapi32, "RegDeleteKeyExW");
    Real_RegEnumKeyW         = (RegEnumKeyW_t)GetProcAddress(hAdvapi32, "RegEnumKeyW");
    Real_RegEnumKeyExW       = (RegEnumKeyExW_t)GetProcAddress(hAdvapi32, "RegEnumKeyExW");
    Real_RegEnumValueW       = (RegEnumValueW_t)GetProcAddress(hAdvapi32, "RegEnumValueW");
    Real_RegGetValueW        = (RegGetValueW_t)GetProcAddress(hAdvapi32, "RegGetValueW");
    Real_RegSetKeySecurity   = (RegSetKeySecurity_t)GetProcAddress(hAdvapi32, "RegSetKeySecurity");
    Real_RegGetKeySecurity   = (RegGetKeySecurity_t)GetProcAddress(hAdvapi32, "RegGetKeySecurity");
    Real_RegQueryInfoKeyW    = (RegQueryInfoKeyW_t)GetProcAddress(hAdvapi32, "RegQueryInfoKeyW");
    Real_RegDeleteTreeW      = (RegDeleteTreeW_t)GetProcAddress(hAdvapi32, "RegDeleteTreeW");
    Real_RegCopyTreeW        = (RegCopyTreeW_t)GetProcAddress(hAdvapi32, "RegCopyTreeW");

    InitializeCriticalSection(&g_regLock);
    g_fakeKeyTable = (RegKey**)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                        g_fakeKeyCapacity * sizeof(RegKey*));
    g_fakeKeyPaths = (wchar_t**)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                        g_fakeKeyCapacity * sizeof(wchar_t*));
    g_regRoot = CreateKey(NULL, L"");
    LoadRegistryFromFile();
    ResetHandleTable();
    DumpRegistryTree();
}
