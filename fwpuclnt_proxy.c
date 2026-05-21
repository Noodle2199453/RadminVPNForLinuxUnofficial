#include <windows.h>

/* Minimal stub: return failure to avoid further WFP calls */
__declspec(dllexport) DWORD WINAPI FwpmEngineOpen0(
    const wchar_t* engineName,
    UINT32 flags,
    void* authIdentity,      /* SEC_WINNT_AUTH_IDENTITY_W* */
    const void* session,     /* FWPM_SESSION0* */
    HANDLE* engineHandle
)
{
    if (engineHandle) *engineHandle = NULL;
    return 0x80070032;   // ERROR_NOT_SUPPORTED
}