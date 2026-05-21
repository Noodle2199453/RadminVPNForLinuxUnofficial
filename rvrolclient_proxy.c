/*
 * Auto‑generated proxy for RvROLClient.dll.
 * Forwards every export to the original DLL using naked assembly jumps.
 */

#include <windows.h>
static HMODULE g_hOriginal = NULL;

/* Array of real function pointers, filled at load time */
static void *p_0;
static void *p_1;
static void *p_2;
static void *p_3;
static void *p_4;
static void *p_5;
static void *p_6;
static void *p_7;
static void *p_8;
static void *p_9;
static void *p_10;
static void *p_11;
static void *p_12;
static void *p_13;
static void *p_14;
static void *p_15;
static void *p_16;
static void *p_17;
static void *p_18;
static void *p_19;
static void *p_20;
static void *p_21;
static void *p_22;
static void *p_23;
static void *p_24;
static void *p_25;
static void *p_26;
static void *p_27;
static void *p_28;
static void *p_29;
static void *p_30;
static void *p_31;
static void *p_32;
static void *p_33;
static void *p_34;
static void *p_35;
static void *p_36;
static void *p_37;
static void *p_38;
static void *p_39;
static void *p_40;
static void *p_41;
static void *p_42;
static void *p_43;
static void *p_44;
static void *p_45;
static void *p_46;

/* ================================================================== */
__declspec(naked) static void ForwardStub(void) {
    __asm {
        mov eax, [esp+4]      /* stub index passed as first arg? We can't use args here.
                               Instead we'll use a table lookup inside the stub */
        jmp eax
    }
}


/* 0: ?g_DefaultCaCertPem@FamCurl@@3QBEB */
__declspec(naked) void stub_0(void) {
    __asm {
        mov eax, [p_0]
        jmp eax
    }
}

/* 1: ROLClient_CancelJoin */
__declspec(naked) void stub_1(void) {
    __asm {
        mov eax, [p_1]
        jmp eax
    }
}

/* 2: ROLClient_ChatCommand */
__declspec(naked) void stub_2(void) {
    __asm {
        mov eax, [p_2]
        jmp eax
    }
}

/* 3: ROLClient_CheckUpdates */
__declspec(naked) void stub_3(void) {
    __asm {
        mov eax, [p_3]
        jmp eax
    }
}

/* 4: ROLClient_Connect */
__declspec(naked) void stub_4(void) {
    __asm {
        mov eax, [p_4]
        jmp eax
    }
}

/* 5: ROLClient_ContinueConnect */
__declspec(naked) void stub_5(void) {
    __asm {
        mov eax, [p_5]
        jmp eax
    }
}

/* 6: ROLClient_DisableEncryption */
__declspec(naked) void stub_6(void) {
    __asm {
        mov eax, [p_6]
        jmp eax
    }
}

/* 7: ROLClient_EnableModuleEvents */
__declspec(naked) void stub_7(void) {
    __asm {
        mov eax, [p_7]
        jmp eax
    }
}

/* 8: ROLClient_EnumPublicNetworks */
__declspec(naked) void stub_8(void) {
    __asm {
        mov eax, [p_8]
        jmp eax
    }
}

/* 9: ROLClient_FreeChannel */
__declspec(naked) void stub_9(void) {
    __asm {
        mov eax, [p_9]
        jmp eax
    }
}

/* 10: ROLClient_FreeConnector */
__declspec(naked) void stub_10(void) {
    __asm {
        mov eax, [p_10]
        jmp eax
    }
}

/* 11: ROLClient_FreeDll */
__declspec(naked) void stub_11(void) {
    __asm {
        mov eax, [p_11]
        jmp eax
    }
}

/* 12: ROLClient_FreeMemory */
__declspec(naked) void stub_12(void) {
    __asm {
        mov eax, [p_12]
        jmp eax
    }
}

/* 13: ROLClient_GetChannelProductVersion */
__declspec(naked) void stub_13(void) {
    __asm {
        mov eax, [p_13]
        jmp eax
    }
}

/* 14: ROLClient_GetNodeRegionSupport */
__declspec(naked) void stub_14(void) {
    __asm {
        mov eax, [p_14]
        jmp eax
    }
}

/* 15: ROLClient_GetNodes */
__declspec(naked) void stub_15(void) {
    __asm {
        mov eax, [p_15]
        jmp eax
    }
}

/* 16: ROLClient_GetUnsendDataSize */
__declspec(naked) void stub_16(void) {
    __asm {
        mov eax, [p_16]
        jmp eax
    }
}

/* 17: ROLClient_InitConnector */
__declspec(naked) void stub_17(void) {
    __asm {
        mov eax, [p_17]
        jmp eax
    }
}

/* 18: ROLClient_InitDll */
__declspec(naked) void stub_18(void) {
    __asm {
        mov eax, [p_18]
        jmp eax
    }
}

/* 19: ROLClient_InitSRP */
__declspec(naked) void stub_19(void) {
    __asm {
        mov eax, [p_19]
        jmp eax
    }
}

/* 20: ROLClient_IsConnectorReadyToDie */
__declspec(naked) void stub_20(void) {
    __asm {
        mov eax, [p_20]
        jmp eax
    }
}

/* 21: ROLClient_IsReadyToDie */
__declspec(naked) void stub_21(void) {
    __asm {
        mov eax, [p_21]
        jmp eax
    }
}

/* 22: ROLClient_JoinNetwork */
__declspec(naked) void stub_22(void) {
    __asm {
        mov eax, [p_22]
        jmp eax
    }
}

/* 23: ROLClient_Listen */
__declspec(naked) void stub_23(void) {
    __asm {
        mov eax, [p_23]
        jmp eax
    }
}

/* 24: ROLClient_ListenVpn */
__declspec(naked) void stub_24(void) {
    __asm {
        mov eax, [p_24]
        jmp eax
    }
}

/* 25: ROLClient_ManageLicense */
__declspec(naked) void stub_25(void) {
    __asm {
        mov eax, [p_25]
        jmp eax
    }
}

/* 26: ROLClient_ManageNetwork */
__declspec(naked) void stub_26(void) {
    __asm {
        mov eax, [p_26]
        jmp eax
    }
}

/* 27: ROLClient_ManageNetwork2 */
__declspec(naked) void stub_27(void) {
    __asm {
        mov eax, [p_27]
        jmp eax
    }
}

/* 28: ROLClient_NeedMasterAddress */
__declspec(naked) void stub_28(void) {
    __asm {
        mov eax, [p_28]
        jmp eax
    }
}

/* 29: ROLClient_Receive */
__declspec(naked) void stub_29(void) {
    __asm {
        mov eax, [p_29]
        jmp eax
    }
}

/* 30: ROLClient_Register */
__declspec(naked) void stub_30(void) {
    __asm {
        mov eax, [p_30]
        jmp eax
    }
}

/* 31: ROLClient_RejectConnect */
__declspec(naked) void stub_31(void) {
    __asm {
        mov eax, [p_31]
        jmp eax
    }
}

/* 32: ROLClient_ReportIpConflict */
__declspec(naked) void stub_32(void) {
    __asm {
        mov eax, [p_32]
        jmp eax
    }
}

/* 33: ROLClient_ReportLanguage */
__declspec(naked) void stub_33(void) {
    __asm {
        mov eax, [p_33]
        jmp eax
    }
}

/* 34: ROLClient_ReportSessionSummary */
__declspec(naked) void stub_34(void) {
    __asm {
        mov eax, [p_34]
        jmp eax
    }
}

/* 35: ROLClient_Send */
__declspec(naked) void stub_35(void) {
    __asm {
        mov eax, [p_35]
        jmp eax
    }
}

/* 36: ROLClient_SetCompression */
__declspec(naked) void stub_36(void) {
    __asm {
        mov eax, [p_36]
        jmp eax
    }
}

/* 37: ROLClient_SetMaxPacketSize */
__declspec(naked) void stub_37(void) {
    __asm {
        mov eax, [p_37]
        jmp eax
    }
}

/* 38: ROLClient_SetPriority */
__declspec(naked) void stub_38(void) {
    __asm {
        mov eax, [p_38]
        jmp eax
    }
}

/* 39: ROLClient_SetVirtualAddresses */
__declspec(naked) void stub_39(void) {
    __asm {
        mov eax, [p_39]
        jmp eax
    }
}

/* 40: ROLClient_ShutdownChannel */
__declspec(naked) void stub_40(void) {
    __asm {
        mov eax, [p_40]
        jmp eax
    }
}

/* 41: ROLClient_ShutdownConnector */
__declspec(naked) void stub_41(void) {
    __asm {
        mov eax, [p_41]
        jmp eax
    }
}

/* 42: ROLClient_ShutdownDll */
__declspec(naked) void stub_42(void) {
    __asm {
        mov eax, [p_42]
        jmp eax
    }
}

/* 43: ROLClient_WaitForSend */
__declspec(naked) void stub_43(void) {
    __asm {
        mov eax, [p_43]
        jmp eax
    }
}

/* 44: ROLClient_WaitModuleEvent */
__declspec(naked) void stub_44(void) {
    __asm {
        mov eax, [p_44]
        jmp eax
    }
}

/* 45: ROLClient_WaitROLEvent */
__declspec(naked) void stub_45(void) {
    __asm {
        mov eax, [p_45]
        jmp eax
    }
}

/* 46: ROLClient_WaitThreads */
__declspec(naked) void stub_46(void) {
    __asm {
        mov eax, [p_46]
        jmp eax
    }
}

/* ================================================================== */
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        /* Load the original DLL we renamed */
        char path[MAX_PATH];
        GetModuleFileNameA(hinst, path, sizeof(path));
        char *p = strrchr(path, '\\');
        if (p) *p = 0;
        strcat_s(path, sizeof(path), "\\RvROLClient_orig.dll");
        g_hOriginal = LoadLibraryA(path);
        if (!g_hOriginal) return FALSE;

        /* Resolve all function pointers */
        p_0 = GetProcAddress(g_hOriginal, "?g_DefaultCaCertPem@FamCurl@@3QBEB");
        p_1 = GetProcAddress(g_hOriginal, "ROLClient_CancelJoin");
        p_2 = GetProcAddress(g_hOriginal, "ROLClient_ChatCommand");
        p_3 = GetProcAddress(g_hOriginal, "ROLClient_CheckUpdates");
        p_4 = GetProcAddress(g_hOriginal, "ROLClient_Connect");
        p_5 = GetProcAddress(g_hOriginal, "ROLClient_ContinueConnect");
        p_6 = GetProcAddress(g_hOriginal, "ROLClient_DisableEncryption");
        p_7 = GetProcAddress(g_hOriginal, "ROLClient_EnableModuleEvents");
        p_8 = GetProcAddress(g_hOriginal, "ROLClient_EnumPublicNetworks");
        p_9 = GetProcAddress(g_hOriginal, "ROLClient_FreeChannel");
        p_10 = GetProcAddress(g_hOriginal, "ROLClient_FreeConnector");
        p_11 = GetProcAddress(g_hOriginal, "ROLClient_FreeDll");
        p_12 = GetProcAddress(g_hOriginal, "ROLClient_FreeMemory");
        p_13 = GetProcAddress(g_hOriginal, "ROLClient_GetChannelProductVersion");
        p_14 = GetProcAddress(g_hOriginal, "ROLClient_GetNodeRegionSupport");
        p_15 = GetProcAddress(g_hOriginal, "ROLClient_GetNodes");
        p_16 = GetProcAddress(g_hOriginal, "ROLClient_GetUnsendDataSize");
        p_17 = GetProcAddress(g_hOriginal, "ROLClient_InitConnector");
        p_18 = GetProcAddress(g_hOriginal, "ROLClient_InitDll");
        p_19 = GetProcAddress(g_hOriginal, "ROLClient_InitSRP");
        p_20 = GetProcAddress(g_hOriginal, "ROLClient_IsConnectorReadyToDie");
        p_21 = GetProcAddress(g_hOriginal, "ROLClient_IsReadyToDie");
        p_22 = GetProcAddress(g_hOriginal, "ROLClient_JoinNetwork");
        p_23 = GetProcAddress(g_hOriginal, "ROLClient_Listen");
        p_24 = GetProcAddress(g_hOriginal, "ROLClient_ListenVpn");
        p_25 = GetProcAddress(g_hOriginal, "ROLClient_ManageLicense");
        p_26 = GetProcAddress(g_hOriginal, "ROLClient_ManageNetwork");
        p_27 = GetProcAddress(g_hOriginal, "ROLClient_ManageNetwork2");
        p_28 = GetProcAddress(g_hOriginal, "ROLClient_NeedMasterAddress");
        p_29 = GetProcAddress(g_hOriginal, "ROLClient_Receive");
        p_30 = GetProcAddress(g_hOriginal, "ROLClient_Register");
        p_31 = GetProcAddress(g_hOriginal, "ROLClient_RejectConnect");
        p_32 = GetProcAddress(g_hOriginal, "ROLClient_ReportIpConflict");
        p_33 = GetProcAddress(g_hOriginal, "ROLClient_ReportLanguage");
        p_34 = GetProcAddress(g_hOriginal, "ROLClient_ReportSessionSummary");
        p_35 = GetProcAddress(g_hOriginal, "ROLClient_Send");
        p_36 = GetProcAddress(g_hOriginal, "ROLClient_SetCompression");
        p_37 = GetProcAddress(g_hOriginal, "ROLClient_SetMaxPacketSize");
        p_38 = GetProcAddress(g_hOriginal, "ROLClient_SetPriority");
        p_39 = GetProcAddress(g_hOriginal, "ROLClient_SetVirtualAddresses");
        p_40 = GetProcAddress(g_hOriginal, "ROLClient_ShutdownChannel");
        p_41 = GetProcAddress(g_hOriginal, "ROLClient_ShutdownConnector");
        p_42 = GetProcAddress(g_hOriginal, "ROLClient_ShutdownDll");
        p_43 = GetProcAddress(g_hOriginal, "ROLClient_WaitForSend");
        p_44 = GetProcAddress(g_hOriginal, "ROLClient_WaitModuleEvent");
        p_45 = GetProcAddress(g_hOriginal, "ROLClient_WaitROLEvent");
        p_46 = GetProcAddress(g_hOriginal, "ROLClient_WaitThreads");

        /* Call your injection entry point */
        void run_injection(void);
        run_injection(g_hOriginal);
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_hOriginal) FreeLibrary(g_hOriginal);
    }
    return TRUE;
}
