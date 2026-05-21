/* ===================================================================
 * IAT hooking helpers
 * =================================================================== */
#include <memoryapi.h>
#include <minwindef.h>
#include <winnt.h>
void* GetIATEntry(HMODULE module, const char* dllName, const char* funcName)
{
    ULONG_PTR base = (ULONG_PTR)module;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* importDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(base + importDir->VirtualAddress);

    while (importDesc->Name) {
        const char* currentDll = (const char*)(base + importDesc->Name);
        if (_stricmp(currentDll, dllName) == 0) {
            IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(base + importDesc->FirstThunk);
            IMAGE_THUNK_DATA* originalThunk = (IMAGE_THUNK_DATA*)(base + importDesc->OriginalFirstThunk);
            while (originalThunk->u1.AddressOfData) {
                if (!(originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    IMAGE_IMPORT_BY_NAME* nameInfo = (IMAGE_IMPORT_BY_NAME*)(base + originalThunk->u1.AddressOfData);
                    if (strcmp(nameInfo->Name, funcName) == 0)
                        return &thunk->u1.Function;
                }
                thunk++;
                originalThunk++;
            }
        }
        importDesc++;
    }
    return NULL;
}

BOOL PatchIAT(void* iatEntry, void* hookFunc)
{
    DWORD oldProtect;
    VirtualProtect(iatEntry, sizeof(void*), PAGE_READWRITE, &oldProtect);
    *(void**)iatEntry = hookFunc;
    VirtualProtect(iatEntry, sizeof(void*), oldProtect, &oldProtect);
    return TRUE;
}