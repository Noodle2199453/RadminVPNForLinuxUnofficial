// hooklib.c – injectable DLL for Radmin VPN on Wine
#include <windows.h>
#include "log.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        InitLog();
        LogMsg("Hello – hooklib injected successfully!");

        void run_injection(HMODULE hOriginal);
        run_injection(NULL);
        break;

    case DLL_PROCESS_DETACH:
        LogMsg("hooklib unloaded.");
        break;
    }
    return TRUE;
}