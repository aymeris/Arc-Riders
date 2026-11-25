// test_payload.cpp — minimal x64 DLL that writes a file in DllMain.
// build: cl /nologo /LD test_payload.cpp /link kernel32.lib
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static void hex_u32(DWORD v, char* out) {
    static const char* hx = "0123456789ABCDEF";
    for (int i = 7; i >= 0; --i) { out[i] = hx[v & 0xF]; v >>= 4; }
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE h = CreateFileA(
            "C:\\Users\\msayt\\Desktop\\mapper\\INJECTED.txt",
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            char line[] = "mapped ok pid=0x________\n";
            hex_u32(GetCurrentProcessId(), line + 16);
            DWORD w = 0;
            WriteFile(h, line, (DWORD)(sizeof(line) - 1), &w, NULL);
            CloseHandle(h);
        }
    }
    return TRUE;
}
