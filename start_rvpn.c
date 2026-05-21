/*
 * start_rvpn.c  –  Improved launcher
 *
 * Launches RvRvpnGui.exe and inject.exe, then finds the child process
 * RvControlSvc.exe. Monitors all three; if any exits, the others are killed.
 *
 * Build: see previous instructions.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

static BOOL FileExists(LPCSTR path) {
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES &&
            !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

/*
 * Repeatedly scans for a process with given name and parent PID.
 * Returns PID, or 0 if not found within timeout_ms.
 */
static DWORD FindProcessByNameAndParent(LPCSTR exeName, DWORD parentPid,
                                        DWORD timeout_ms) {
    DWORD start = GetTickCount();
    while (1) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(hSnap, &pe)) {
            do {
                if (lstrcmpiA(pe.szExeFile, exeName) == 0 &&
                    pe.th32ParentProcessID == parentPid) {
                    CloseHandle(hSnap);
                    return pe.th32ProcessID;
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);

        if (GetTickCount() - start > timeout_ms)
            break;
        Sleep(300);
    }
    return 0;
}

int main(void) {
    // --- 1. Check required files ---
    const char *required[] = {
        "RvRvpnGui.exe", "inject.exe", "RvControlSvc.exe", "hooklib.dll"
    };
    char missing[1024] = "";
    int missingCount = 0;
    for (int i = 0; i < sizeof(required)/sizeof(required[0]); i++) {
        if (!FileExists(required[i])) {
            if (missingCount > 0) strcat(missing, "\n");
            strcat(missing, required[i]);
            missingCount++;
        }
    }
    if (missingCount > 0) {
        char msg[2048];
        snprintf(msg, sizeof(msg),
                 "Cannot start – missing files:\n\n%s\n\n"
                 "Make sure everything is in the same folder.",
                 missing);
        MessageBoxA(NULL, msg, "Start RVPN – Error", MB_ICONERROR);
        return 1;
    }

    // --- 2. Launch RvRvpnGui.exe ---
    STARTUPINFOA siGui = { sizeof(siGui) };
    PROCESS_INFORMATION piGui = { 0 };
    if (!CreateProcessA("RvRvpnGui.exe", NULL,
                        NULL, NULL, FALSE, 0, NULL, NULL,
                        &siGui, &piGui)) {
        MessageBoxA(NULL, "Failed to start RvRvpnGui.exe", "Error", MB_ICONERROR);
        return 1;
    }
    CloseHandle(piGui.hThread);   // we don't need the thread handle

    // --- 3. Launch inject.exe (keeps running) ---
    char injectCmd[512];
    snprintf(injectCmd, sizeof(injectCmd),
             "inject.exe RvControlSvc.exe hooklib.dll");
    STARTUPINFOA siInj = { sizeof(siInj) };
    PROCESS_INFORMATION piInj = { 0 };
    if (!CreateProcessA(NULL, injectCmd,
                        NULL, NULL, FALSE, 0, NULL, NULL,
                        &siInj, &piInj)) {
        TerminateProcess(piGui.hProcess, 1);
        CloseHandle(piGui.hProcess);
        MessageBoxA(NULL, "Failed to start inject.exe", "Error", MB_ICONERROR);
        return 1;
    }
    CloseHandle(piInj.hThread);

    // --- 4. Locate the child process RvControlSvc.exe ---
    DWORD targetPid = FindProcessByNameAndParent(
                        "RvControlSvc.exe",
                        piInj.dwProcessId,
                        10000);   // 10-second timeout
    if (targetPid == 0) {
        // Could not find the target – kill both started processes
        TerminateProcess(piGui.hProcess, 1);
        TerminateProcess(piInj.hProcess, 1);
        CloseHandle(piGui.hProcess);
        CloseHandle(piInj.hProcess);
        MessageBoxA(NULL,
                    "Could not find RvControlSvc.exe after launching inject.exe.",
                    "Error", MB_ICONERROR);
        return 1;
    }

    HANDLE hTarget = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE,
                                 FALSE, targetPid);
    if (!hTarget) {
        TerminateProcess(piGui.hProcess, 1);
        TerminateProcess(piInj.hProcess, 1);
        CloseHandle(piGui.hProcess);
        CloseHandle(piInj.hProcess);
        MessageBoxA(NULL,
                    "Failed to open RvControlSvc.exe process.",
                    "Error", MB_ICONERROR);
        return 1;
    }

    // --- 5. Wait for any of the three processes to exit ---
    HANDLE handles[3] = { piGui.hProcess, piInj.hProcess, hTarget };
    DWORD result = WaitForMultipleObjects(3, handles, FALSE, INFINITE);

    // --- 6. Terminate all processes (cleanup) ---
    // The process that just exited is already gone – TerminateProcess will
    // fail on it (harmless). We still call it to shut down the survivors.
    for (int i = 0; i < 3; i++) {
        if (handles[i] != NULL) {
            TerminateProcess(handles[i], 1);
            CloseHandle(handles[i]);
        }
    }

    return 0;
}