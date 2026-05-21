#include <stdio.h>
#include <windows.h>
/* ===================================================================
 * Logging (console + file in %TEMP%)
 * =================================================================== */
static FILE* g_LogFile = NULL;
static BOOL  g_ConsoleCreated = FALSE;
static BOOL g_LoggingEnabled = TRUE; 

void InitLog(void) {
    if (AllocConsole()) {
        FILE* f;
        freopen_s(&f, "CONOUT$", "w", stdout);
        freopen_s(&f, "CONOUT$", "w", stderr);
        SetConsoleTitleW(L"Radmin VPN + WireGuard Emulation");
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
                // Strip filename to get directory
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
    fprintf(g_LogFile, "\n=== Emulation + WireGuard started (PID %lu) at %02d:%02d:%02d.%03d ===\n",
            GetCurrentProcessId(), st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    fflush(g_LogFile);
    if (g_ConsoleCreated)
        printf("=== Emulation + WireGuard started (PID %lu) ===\n", GetCurrentProcessId());
}


// Implement the functions in your .c file
void DisableLog(void) {
    if(g_LoggingEnabled){
        g_LoggingEnabled = FALSE;
        
        // Optional: log that logging was disabled (if we can still log)
        // This will be skipped by the check in LogMsg, so we need to log directly
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        if (g_LogFile) {
            fprintf(g_LogFile, "\n=== Logging DISABLED at %02d:%02d:%02d.%03d ===\n",
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            fflush(g_LogFile);
        }
        if (g_ConsoleCreated) {
            printf("\n=== Logging DISABLED at %02d:%02d:%02d.%03d ===\n",
                   st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        }
    }
}

void EnableLog(void) {
    g_LoggingEnabled = TRUE;
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    if (g_LogFile) {
        fprintf(g_LogFile, "\n=== Logging ENABLED at %02d:%02d:%02d.%03d ===\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        fflush(g_LogFile);
    }
    if (g_ConsoleCreated) {
        printf("\n=== Logging ENABLED at %02d:%02d:%02d.%03d ===\n",
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    }
}

// Modify your existing LogTimestamp function to check logging state
void LogTimestamp(void) {
    if (!g_LoggingEnabled) return;
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    char ts[64];
    sprintf_s(ts, sizeof(ts), "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    if (g_LogFile) { fprintf(g_LogFile, "%s", ts); fflush(g_LogFile); }
    if (g_ConsoleCreated) printf("%s", ts);
}

// Modify your existing LogMsg function to check logging state
void LogMsg(const char* fmt, ...) {
    if (!g_LoggingEnabled) return;
    
    va_list args;
    va_start(args, fmt);
    char line[1024];
    vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);

    LogTimestamp();
    if (g_LogFile) { fprintf(g_LogFile, "%s\n", line); fflush(g_LogFile); }
    if (g_ConsoleCreated) printf("%s\n", line);
}

// Modify your existing LogHex function to check logging state
void LogHex(const BYTE* data, DWORD len, const char* prefix) {
    if (!g_LoggingEnabled) return;
    if (!data || !len) return;
    
    char hex[512];
    DWORD i, pos = 0;
    for (i = 0; i < len && pos < sizeof(hex)-4; i++) {
        pos += sprintf_s(hex + pos, sizeof(hex) - pos, "%02X ", data[i]);
    }
    LogMsg("%s (%u bytes): %s", prefix, len, hex);
}

void LogMsgAndHex(const char* fmt, const BYTE* data, DWORD dataLen, const char* hexPrefix, ...) {
    if (!g_LoggingEnabled) return;

    // 1. Print the message part
    va_list args;
    va_start(args, hexPrefix);
    char msgLine[1024];
    vsnprintf(msgLine, sizeof(msgLine), fmt, args);
    va_end(args);

    LogTimestamp();
    if (g_LogFile) { fprintf(g_LogFile, "%s\n", msgLine); fflush(g_LogFile); }
    if (g_ConsoleCreated) printf("%s\n", msgLine);

    // 2. If data is provided, print its hex
    if (data && dataLen) {
        char hex[512];
        DWORD pos = 0;
        for (DWORD i = 0; i < dataLen && pos < sizeof(hex) - 4; i++) {
            pos += sprintf_s(hex + pos, sizeof(hex) - pos, "%02X ", data[i]);
        }
        LogTimestamp();
        if (g_LogFile) { fprintf(g_LogFile, "%s (%u bytes): %s\n", hexPrefix, dataLen, hex); fflush(g_LogFile); }
        if (g_ConsoleCreated) printf("%s (%u bytes): %s\n", hexPrefix, dataLen, hex);
    }
}