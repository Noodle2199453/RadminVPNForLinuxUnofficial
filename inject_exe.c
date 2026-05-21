// inject.c – 32‑bit injector for Wine/Windows
#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <target_exe> <dll_path>\n", argv[0]);
        return 1;
    }

    const char *targetExe = argv[1];
    const char *dllPath = argv[2];

    // Prepare the command line: <target_exe> /run   (to run as application, not service)
    char cmdLine[MAX_PATH * 2];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" /run", targetExe);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // Start the target suspended
    if (!CreateProcessA(
            NULL,           // application name (we pass full path in command line)
            cmdLine,        // command line
            NULL, NULL, FALSE,
            CREATE_SUSPENDED,
            NULL, NULL,
            &si, &pi))
    {
        fprintf(stderr, "CreateProcess failed (%lu)\n", GetLastError());
        return 1;
    }

    // Allocate memory for the DLL path in the target
    size_t dllPathLen = strlen(dllPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, dllPathLen,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem)
    {
        fprintf(stderr, "VirtualAllocEx failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    // Write the DLL path into the target
    if (!WriteProcessMemory(pi.hProcess, remoteMem, dllPath, dllPathLen, NULL))
    {
        fprintf(stderr, "WriteProcessMemory failed (%lu)\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    // Get address of LoadLibraryA in kernel32 (same in all processes)
    LPTHREAD_START_ROUTINE loadLibrary =
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibrary)
    {
        fprintf(stderr, "GetProcAddress(LoadLibraryA) failed\n");
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    // Create a remote thread that calls LoadLibraryA(remoteMem)
    HANDLE hRemoteThread = CreateRemoteThread(pi.hProcess, NULL, 0,
                                              loadLibrary, remoteMem, 0, NULL);
    if (!hRemoteThread)
    {
        fprintf(stderr, "CreateRemoteThread failed (%lu)\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    // Wait for the LoadLibrary call to finish
    WaitForSingleObject(hRemoteThread, INFINITE);
    DWORD exitCode;
    GetExitCodeThread(hRemoteThread, &exitCode);
    if (!exitCode)
        fprintf(stderr, "LoadLibraryA in target returned NULL – DLL might not be found\n");

    CloseHandle(hRemoteThread);
    VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);

    // Resume the main thread of the target
    ResumeThread(pi.hThread);

    printf("Injection done. Target is running.\n");

    // Wait for the target to exit (optional)
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}