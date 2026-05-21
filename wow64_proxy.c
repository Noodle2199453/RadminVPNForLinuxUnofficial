#include <windows.h>
#include <winnt.h>

static HINSTANCE g_hInstance = NULL;

// ------------------------------------------------------------------
//  Macro to create a stub that can be patched later (10 NOP bytes)
// ------------------------------------------------------------------
#define DEF_EXPORT(name) \
    __declspec(dllexport) void __stdcall name(void) { \
        __asm__ volatile ( \
            "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n" \
        ); \
    }

// ------------------------------------------------------------------
//  All 28 exports from wow64.dll (the real function will replace these)
// ------------------------------------------------------------------
DEF_EXPORT(Wow64AllocThreadHeap)
DEF_EXPORT(Wow64AllocateHeap)
DEF_EXPORT(Wow64AllocateTemp)
DEF_EXPORT(Wow64ApcRoutine)
DEF_EXPORT(Wow64CheckIfNXEnabled)
DEF_EXPORT(Wow64EmulateAtlThunk)
DEF_EXPORT(Wow64FreeHeap)
DEF_EXPORT(Wow64FreeThreadHeap)
DEF_EXPORT(Wow64GetWow64ImageOption)
DEF_EXPORT(Wow64IsControlFlowGuardEnforced)
DEF_EXPORT(Wow64IsStackExtentsCheckEnforced)
DEF_EXPORT(Wow64KiUserCallbackDispatcher)
DEF_EXPORT(Wow64LdrpInitialize)
DEF_EXPORT(Wow64LogPrint)
DEF_EXPORT(Wow64NotifyUnsimulateComplete)
DEF_EXPORT(Wow64PassExceptionToGuest)
DEF_EXPORT(Wow64PrepareForDebuggerAttach)
DEF_EXPORT(Wow64PrepareForException)
DEF_EXPORT(Wow64ProcessPendingCrossProcessItems)
DEF_EXPORT(Wow64RaiseException)
DEF_EXPORT(Wow64ShallowThunkAllocObjectAttributes32TO64_FNC)
DEF_EXPORT(Wow64ShallowThunkAllocSecurityQualityOfService32TO64_FNC)
DEF_EXPORT(Wow64ShallowThunkSIZE_T32TO64)
DEF_EXPORT(Wow64ShallowThunkSIZE_T64TO32)
DEF_EXPORT(Wow64SuspendLocalThread)
DEF_EXPORT(Wow64SystemServiceEx)
DEF_EXPORT(Wow64ValidateUserCallTarget)
DEF_EXPORT(Wow64ValidateUserCallTargetFilter)

// ------------------------------------------------------------------
//  Patch every exported stub to jump to the real wow64.dll function
// ------------------------------------------------------------------
static void PatchAllExports(void)
{
    // Load the real wow64.dll from System32 (do not use any search path)
    wchar_t sysPath[MAX_PATH];
    if (GetSystemDirectoryW(sysPath, MAX_PATH) == 0) return;
    wcscat_s(sysPath, MAX_PATH, L"\\wow64.dll");
    HMODULE hReal = LoadLibraryExW(sysPath, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!hReal) return;

    HMODULE hSelf = g_hInstance;
    // Navigate PE headers
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hSelf;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hSelf + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)
        ((BYTE*)hSelf + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* pNames = (DWORD*)((BYTE*)hSelf + pExportDir->AddressOfNames);
    WORD* pOrdinals = (WORD*)((BYTE*)hSelf + pExportDir->AddressOfNameOrdinals);
    DWORD* pFunctions = (DWORD*)((BYTE*)hSelf + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)hSelf + pNames[i]);
        WORD ordinalIndex = pOrdinals[i];
        DWORD funcRVA = pFunctions[ordinalIndex];
        if (funcRVA == 0) continue;

        BYTE* pStub = (BYTE*)hSelf + funcRVA;

        // Find the matching function in the real DLL
        FARPROC realFunc = GetProcAddress(hReal, name);
        if (!realFunc) continue;

        // Write a JMP rel32 to the real function (5 bytes: E9 xx xx xx xx)
        DWORD oldProtect;
        VirtualProtect(pStub, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        pStub[0] = 0xE9;
        INT rel = (INT)((BYTE*)realFunc - (pStub + 5));
        memcpy(pStub + 1, &rel, sizeof(rel));
        VirtualProtect(pStub, 5, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), pStub, 5);
    }
}

// ------------------------------------------------------------------
//  Inject our main hook DLL
// ------------------------------------------------------------------
static void InjectHooks(void)
{
        /* Run the injection code from inject.c */
        void run_injection2(void);   // declared in inject.c
        run_injection2();
}

// ------------------------------------------------------------------
//  DLL Entry Point
// ------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hInstance = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);

        // Step 1: Redirect all exports to the real wow64.dll
        PatchAllExports();

        // Step 2: Load our hook DLL
        InjectHooks();
    }
    return TRUE;
}