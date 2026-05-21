#!/usr/bin/env python3
"""
gen_proxy.py – Generate a MinGW‑compatible proxy DLL for RvROLClient.dll.

Supports C++ mangled export names by using a .def file with aliases.
"""

import sys
import pefile

def generate_proxy(dll_path):
    pe = pefile.PE(dll_path)
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print("ERROR: No export table found.")
        return

    exports = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            exports.append(exp.name.decode())

    # Write the .def file with alias mapping
    with open('rvrolclient.def', 'w') as f:
        f.write("EXPORTS\n")
        for idx, name in enumerate(exports):
            f.write(f"    {name} = stub_{idx}\n")

    # Write the proxy C file
    with open('rvrolclient_proxy.c', 'w') as f:
        f.write('''/*
 * Auto‑generated proxy for RvROLClient.dll.
 * Exports are aliased via .def to stub functions.
 */

#include <windows.h>
#include <string.h>

static HMODULE g_hOriginal = NULL;

/* Pointers to real functions */
''')
        for idx in range(len(exports)):
            f.write(f"static void *p_{idx};\n")

        f.write('''
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        char path[MAX_PATH];
        GetModuleFileNameA(hinst, path, sizeof(path));
        char *p = strrchr(path, '\\\\');
        if (p) *p = 0;
        strcat_s(path, sizeof(path), "\\\\RvROLClient_orig.dll");
        g_hOriginal = LoadLibraryA(path);
        if (!g_hOriginal) return FALSE;

''')
        for idx, name in enumerate(exports):
            f.write(f'        p_{idx} = GetProcAddress(g_hOriginal, "{name}");\n')

        f.write('''
        void run_injection(HMODULE hOriginal);
        run_injection(g_hOriginal);
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_hOriginal) FreeLibrary(g_hOriginal);
    }
    return TRUE;
}

/* Naked stub functions – each one jumps to the real pointer */
''')
        for idx in range(len(exports)):
            f.write(f'''
__attribute__((naked)) void stub_{idx}(void) {{
    __asm__ volatile (
        "movl _p_{idx}, %eax\\n\\t"
        "jmp *%eax"
    );
}}
''')

    print("Generated rvrolclient.def and rvrolclient_proxy.c successfully.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <original_dll>")
        sys.exit(1)
    generate_proxy(sys.argv[1])