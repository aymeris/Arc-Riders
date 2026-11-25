// mapper_mm.cpp — c++17 x64 usermode manual-map DLL injector, Windows 10/11
// build: cl /std:c++17 /W4 /permissive- /EHsc /O2 /DUNICODE /D_UNICODE ^
//           mapper_mm.cpp /link psapi.lib advapi32.lib
// usage: mapper_mm.exe <pid> <dll_path>
//
// what it does:
//   - reads a .dll from disk
//   - allocates image_size bytes in target (VirtualAllocEx, RW)
//   - lays out headers + sections locally, resolves imports, applies 64-bit relocs
//   - writes the whole image into the target
//   - applies per-section PAGE_* protections
//   - runs each TLS callback in target via a 29-byte x64 shellcode trampoline
//   - calls DllMain(base, DLL_PROCESS_ATTACH, 0) via CreateRemoteThread + shellcode
//
// anti-cheat: EAC/BE/Ricochet territory — CreateRemoteThread + VirtualAllocEx + WPM
// are watched. survives on soft/no AC titles; for heavy AC swap to thread-hijack /
// NtCreateThreadEx(HIDE_FROM_DEBUGGER) / manual syscalls. this is MVP, not stealth.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// handle RAII
// ---------------------------------------------------------------------------
struct HandleCloser {
    void operator()(HANDLE h) const noexcept {
        if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
    }
};
using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleCloser>;

// ---------------------------------------------------------------------------
// read a file off disk into a byte vector
// ---------------------------------------------------------------------------
static bool read_file(const wchar_t* path, std::vector<std::uint8_t>& out) {
    UniqueHandle fh(::CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (fh.get() == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!::GetFileSizeEx(fh.get(), &sz)) return false;
    if (sz.QuadPart <= 0 || sz.QuadPart > (1LL << 30)) return false;
    out.resize(static_cast<std::size_t>(sz.QuadPart));
    DWORD rd = 0;
    if (!::ReadFile(fh.get(), out.data(), static_cast<DWORD>(out.size()), &rd, nullptr))
        return false;
    return rd == out.size();
}

// ---------------------------------------------------------------------------
// enumerate target's loaded modules and find one by basename (case-insensitive)
// ---------------------------------------------------------------------------
static bool get_remote_module_base(HANDLE proc, const char* basename, std::uint64_t& base_out)
{
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!::EnumProcessModulesEx(proc, mods, sizeof(mods), &needed, LIST_MODULES_64BIT))
        return false;
    const std::size_t n = needed / sizeof(HMODULE);
    for (std::size_t i = 0; i < n; ++i) {
        char fn[MAX_PATH] = {};
        if (!::GetModuleBaseNameA(proc, mods[i], fn, MAX_PATH)) continue;
        if (_stricmp(fn, basename) == 0) {
            base_out = reinterpret_cast<std::uint64_t>(mods[i]);
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// force a LoadLibraryA in target, then query its base
// ---------------------------------------------------------------------------
static bool remote_load_library(HANDLE proc, const char* dllname, std::uint64_t& base_out)
{
    if (get_remote_module_base(proc, dllname, base_out)) return true;

    const SIZE_T len = std::strlen(dllname) + 1;
    LPVOID str_mem = ::VirtualAllocEx(proc, nullptr, len,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!str_mem) return false;

    SIZE_T wrote = 0;
    if (!::WriteProcessMemory(proc, str_mem, dllname, len, &wrote) || wrote != len) {
        ::VirtualFreeEx(proc, str_mem, 0, MEM_RELEASE);
        return false;
    }

    HMODULE k32 = ::GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibraryA = k32 ? ::GetProcAddress(k32, "LoadLibraryA") : nullptr;
    if (!pLoadLibraryA) {
        ::VirtualFreeEx(proc, str_mem, 0, MEM_RELEASE);
        return false;
    }

    UniqueHandle th(::CreateRemoteThread(
        proc, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryA),
        str_mem, 0, nullptr));
    if (!th) {
        ::VirtualFreeEx(proc, str_mem, 0, MEM_RELEASE);
        return false;
    }
    ::WaitForSingleObject(th.get(), 10000);
    ::VirtualFreeEx(proc, str_mem, 0, MEM_RELEASE);

    return get_remote_module_base(proc, dllname, base_out);
}

// ---------------------------------------------------------------------------
// resolve imports in a local image buffer against the target's module bases.
// we load each imported DLL locally (DONT_RESOLVE_DLL_REFERENCES) just to walk
// its export table; we then shift resolved addresses by (remote_base-local_base).
// ---------------------------------------------------------------------------
static bool resolve_imports(HANDLE proc, std::uint8_t* image, IMAGE_NT_HEADERS64* nt)
{
    const auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dd.Size == 0 || dd.VirtualAddress == 0) return true;

    auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image + dd.VirtualAddress);
    for (; imp->Name; ++imp) {
        const char* dllname = reinterpret_cast<const char*>(image + imp->Name);

        std::uint64_t remote_base = 0;
        if (!remote_load_library(proc, dllname, remote_base)) {
            std::fprintf(stderr, "[-] remote_load_library(%s) failed\n", dllname);
            return false;
        }

        HMODULE local_mod = ::GetModuleHandleA(dllname);
        bool loaded_by_us = false;
        if (!local_mod) {
            local_mod = ::LoadLibraryExA(dllname, nullptr, DONT_RESOLVE_DLL_REFERENCES);
            loaded_by_us = (local_mod != nullptr);
        }
        if (!local_mod) {
            std::fprintf(stderr, "[-] cannot load %s locally for export walk\n", dllname);
            return false;
        }

        const std::int64_t delta =
            static_cast<std::int64_t>(remote_base)
          - static_cast<std::int64_t>(reinterpret_cast<std::uint64_t>(local_mod));

        auto* oft = (imp->OriginalFirstThunk
                     ? reinterpret_cast<IMAGE_THUNK_DATA64*>(image + imp->OriginalFirstThunk)
                     : reinterpret_cast<IMAGE_THUNK_DATA64*>(image + imp->FirstThunk));
        auto* ft  = reinterpret_cast<IMAGE_THUNK_DATA64*>(image + imp->FirstThunk);

        for (; oft->u1.AddressOfData; ++oft, ++ft) {
            FARPROC addr = nullptr;
            if (IMAGE_SNAP_BY_ORDINAL64(oft->u1.Ordinal)) {
                WORD ord = static_cast<WORD>(IMAGE_ORDINAL64(oft->u1.Ordinal));
                addr = ::GetProcAddress(local_mod, MAKEINTRESOURCEA(ord));
            } else {
                auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                    image + oft->u1.AddressOfData);
                addr = ::GetProcAddress(local_mod, ibn->Name);
            }
            if (!addr) {
                std::fprintf(stderr, "[-] import not found in %s\n", dllname);
                if (loaded_by_us) ::FreeLibrary(local_mod);
                return false;
            }
            ft->u1.Function =
                static_cast<std::uint64_t>(reinterpret_cast<std::uint64_t>(addr) + delta);
        }

        if (loaded_by_us) ::FreeLibrary(local_mod);
    }
    return true;
}

// ---------------------------------------------------------------------------
// base relocations for x64 — IMAGE_REL_BASED_DIR64 only; ABSOLUTE(0) is padding.
// ---------------------------------------------------------------------------
static void apply_relocs(std::uint8_t* image, IMAGE_NT_HEADERS64* nt,
                         std::uint64_t new_base)
{
    const auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dd.Size == 0 || dd.VirtualAddress == 0) return;
    const std::int64_t delta =
        static_cast<std::int64_t>(new_base)
      - static_cast<std::int64_t>(nt->OptionalHeader.ImageBase);
    if (delta == 0) return;

    DWORD processed = 0;
    auto* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image + dd.VirtualAddress);
    while (processed < dd.Size && reloc->SizeOfBlock) {
        if (reloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
        const DWORD count =
            (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto* list = reinterpret_cast<WORD*>(reloc + 1);
        for (DWORD i = 0; i < count; ++i) {
            const WORD type = static_cast<WORD>(list[i] >> 12);
            const WORD off  = static_cast<WORD>(list[i] & 0x0FFF);
            if (type == IMAGE_REL_BASED_DIR64) {
                auto* p = reinterpret_cast<std::uint64_t*>(
                    image + reloc->VirtualAddress + off);
                *p = static_cast<std::uint64_t>(static_cast<std::int64_t>(*p) + delta);
            }
            // IMAGE_REL_BASED_ABSOLUTE (0) = padding; nothing to do.
        }
        processed += reloc->SizeOfBlock;
        reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<std::uint8_t*>(reloc) + reloc->SizeOfBlock);
    }
    nt->OptionalHeader.ImageBase = new_base;
}

// ---------------------------------------------------------------------------
// section characteristics → VirtualProtect flag
// ---------------------------------------------------------------------------
static DWORD section_protection(DWORD c) {
    const bool r = (c & IMAGE_SCN_MEM_READ)    != 0;
    const bool w = (c & IMAGE_SCN_MEM_WRITE)   != 0;
    const bool x = (c & IMAGE_SCN_MEM_EXECUTE) != 0;
    if ( x &&  w &&  r) return PAGE_EXECUTE_READWRITE;
    if ( x &&  r)       return PAGE_EXECUTE_READ;
    if ( x)             return PAGE_EXECUTE;
    if ( w &&  r)       return PAGE_READWRITE;
    if ( w)             return PAGE_WRITECOPY;
    if ( r)             return PAGE_READONLY;
    return PAGE_NOACCESS;
}

// ---------------------------------------------------------------------------
// run one callback(hModule, DLL_PROCESS_ATTACH, 0) in the target via shellcode.
// shellcode is ~34 bytes; allocated PAGE_EXECUTE_READWRITE, freed after wait.
// ---------------------------------------------------------------------------
static bool run_remote_dllmain_style(HANDLE proc,
                                     std::uint64_t module_base,
                                     std::uint64_t callback_va)
{
    std::uint8_t sc[64];
    std::size_t p = 0;
    // sub rsp, 28h
    sc[p++] = 0x48; sc[p++] = 0x83; sc[p++] = 0xEC; sc[p++] = 0x28;
    // mov rcx, imm64  (hModule)
    sc[p++] = 0x48; sc[p++] = 0xB9;
    std::memcpy(sc + p, &module_base, 8); p += 8;
    // mov edx, 1  (DLL_PROCESS_ATTACH)
    sc[p++] = 0xBA; sc[p++] = 0x01; sc[p++] = 0x00; sc[p++] = 0x00; sc[p++] = 0x00;
    // xor r8, r8
    sc[p++] = 0x4D; sc[p++] = 0x31; sc[p++] = 0xC0;
    // mov rax, imm64  (callback_va)
    sc[p++] = 0x48; sc[p++] = 0xB8;
    std::memcpy(sc + p, &callback_va, 8); p += 8;
    // call rax
    sc[p++] = 0xFF; sc[p++] = 0xD0;
    // add rsp, 28h
    sc[p++] = 0x48; sc[p++] = 0x83; sc[p++] = 0xC4; sc[p++] = 0x28;
    // ret
    sc[p++] = 0xC3;

    LPVOID mem = ::VirtualAllocEx(proc, nullptr, p,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    if (!mem) return false;
    SIZE_T wrote = 0;
    if (!::WriteProcessMemory(proc, mem, sc, p, &wrote) || wrote != p) {
        ::VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
        return false;
    }
    UniqueHandle th(::CreateRemoteThread(
        proc, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(mem),
        nullptr, 0, nullptr));
    if (!th) {
        ::VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
        return false;
    }
    ::WaitForSingleObject(th.get(), 15000);
    ::VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
    return true;
}

// ---------------------------------------------------------------------------
// TLS callbacks — invoked in-order before DllMain. AddressOfCallBacks holds a
// pointer-to-array-of-VAs; after apply_relocs(new_base=remote_base), those VAs
// are target-side. In our local buffer they live at (VA - remote_base).
// ---------------------------------------------------------------------------
static void run_tls_callbacks(HANDLE proc, const std::uint8_t* local_image,
                              std::uint64_t remote_base, IMAGE_NT_HEADERS64* nt)
{
    const auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (dd.Size == 0 || dd.VirtualAddress == 0) return;

    auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(
        local_image + dd.VirtualAddress);
    const std::uint64_t cb_va = tls->AddressOfCallBacks;
    if (cb_va == 0) return;
    if (cb_va < remote_base) return; // sanity
    const std::uint64_t cb_rva = cb_va - remote_base;

    auto* cbs = reinterpret_cast<const std::uint64_t*>(local_image + cb_rva);
    for (int i = 0; i < 64 && cbs[i]; ++i) {
        std::printf("[*] TLS callback %d @ 0x%016" PRIx64 "\n", i, cbs[i]);
        if (!run_remote_dllmain_style(proc, remote_base, cbs[i])) {
            std::fprintf(stderr, "[-] TLS callback %d failed\n", i);
        }
    }
}

// ---------------------------------------------------------------------------
// elevate: acquire SeDebugPrivilege. Non-fatal on failure.
// ---------------------------------------------------------------------------
static void try_enable_debug_privilege() {
    HANDLE tok = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(),
                            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    if (::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ::AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    }
    ::CloseHandle(tok);
}

// ---------------------------------------------------------------------------
// usage
// ---------------------------------------------------------------------------
static void usage() {
    std::fprintf(stderr,
        "mapper_mm.exe <pid> <dll_path>\n"
        "  manual-maps a 64-bit DLL into the target. must run elevated.\n");
}

// ---------------------------------------------------------------------------
// entry
// ---------------------------------------------------------------------------
int wmain(int argc, wchar_t** argv) {
    if (argc < 3) { usage(); return 2; }

    DWORD pid = 0;
    {
        wchar_t* end = nullptr;
        unsigned long v = std::wcstoul(argv[1], &end, 0);
        if (!end || *end != 0 || v == 0) { usage(); return 2; }
        pid = static_cast<DWORD>(v);
    }
    const wchar_t* dll_path = argv[2];

    try_enable_debug_privilege();

    // --- 1. read DLL off disk ---
    std::vector<std::uint8_t> file;
    if (!read_file(dll_path, file)) {
        std::fprintf(stderr, "[-] read %ls failed: %lu\n", dll_path, ::GetLastError());
        return 1;
    }
    if (file.size() < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) {
        std::fprintf(stderr, "[-] file too small\n");
        return 1;
    }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::fprintf(stderr, "[-] bad DOS header\n"); return 1;
    }
    if (dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > file.size()) {
        std::fprintf(stderr, "[-] bad e_lfanew\n"); return 1;
    }
    auto* file_nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(file.data() + dos->e_lfanew);
    if (file_nt->Signature != IMAGE_NT_SIGNATURE) {
        std::fprintf(stderr, "[-] bad NT sig\n"); return 1;
    }
    if (file_nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::fprintf(stderr, "[-] not PE32+\n"); return 1;
    }
    if (file_nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        std::fprintf(stderr, "[-] not AMD64\n"); return 1;
    }
    if (!(file_nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        std::fprintf(stderr, "[-] not a DLL\n"); return 1;
    }

    const DWORD image_size = file_nt->OptionalHeader.SizeOfImage;
    const DWORD hdr_size   = file_nt->OptionalHeader.SizeOfHeaders;

    // --- 2. lay out image locally (headers + sections at their RVAs) ---
    std::vector<std::uint8_t> local(image_size, 0);
    std::memcpy(local.data(), file.data(), hdr_size);

    auto* file_sec = IMAGE_FIRST_SECTION(file_nt);
    for (WORD i = 0; i < file_nt->FileHeader.NumberOfSections; ++i, ++file_sec) {
        if (file_sec->SizeOfRawData == 0) continue;
        if (file_sec->PointerToRawData + file_sec->SizeOfRawData > file.size()) continue;
        std::memcpy(local.data() + file_sec->VirtualAddress,
                    file.data() + file_sec->PointerToRawData,
                    file_sec->SizeOfRawData);
    }

    // re-anchor header pointers to the local laid-out buffer
    auto* local_dos = reinterpret_cast<IMAGE_DOS_HEADER*>(local.data());
    auto* local_nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(local.data() + local_dos->e_lfanew);

    // --- 3. open target ---
    const DWORD need = PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
                     | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;
    UniqueHandle proc(::OpenProcess(need, FALSE, pid));
    if (!proc) {
        std::fprintf(stderr, "[-] OpenProcess(%lu) failed: %lu\n",
                     pid, ::GetLastError());
        return 1;
    }

    // --- 4. allocate image buffer in target ---
    LPVOID remote = ::VirtualAllocEx(proc.get(), nullptr, image_size,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        std::fprintf(stderr, "[-] VirtualAllocEx failed: %lu\n", ::GetLastError());
        return 1;
    }
    const std::uint64_t remote_base = reinterpret_cast<std::uint64_t>(remote);
    std::printf("[+] target: pid=%lu  base=0x%016" PRIx64 "  size=0x%x\n",
                pid, remote_base, image_size);

    // --- 5. resolve imports in local buffer (IAT entries → remote VAs) ---
    if (!resolve_imports(proc.get(), local.data(), local_nt)) {
        ::VirtualFreeEx(proc.get(), remote, 0, MEM_RELEASE);
        return 1;
    }

    // --- 6. apply relocations for the target allocation base ---
    apply_relocs(local.data(), local_nt, remote_base);

    // --- 7. push the whole image into the target ---
    SIZE_T wrote = 0;
    if (!::WriteProcessMemory(proc.get(), remote, local.data(), image_size, &wrote)
        || wrote != image_size) {
        std::fprintf(stderr, "[-] WriteProcessMemory failed: %lu\n", ::GetLastError());
        ::VirtualFreeEx(proc.get(), remote, 0, MEM_RELEASE);
        return 1;
    }

    // --- 8. per-section protections ---
    auto* sec = IMAGE_FIRST_SECTION(local_nt);
    for (WORD i = 0; i < local_nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->Misc.VirtualSize == 0) continue;
        DWORD old = 0;
        ::VirtualProtectEx(proc.get(),
                           reinterpret_cast<std::uint8_t*>(remote) + sec->VirtualAddress,
                           sec->Misc.VirtualSize,
                           section_protection(sec->Characteristics), &old);
    }
    DWORD old = 0;
    ::VirtualProtectEx(proc.get(), remote, hdr_size, PAGE_READONLY, &old);

    // --- 9. TLS callbacks ---
    run_tls_callbacks(proc.get(), local.data(), remote_base, local_nt);

    // --- 10. DllMain ---
    const DWORD ep_rva = local_nt->OptionalHeader.AddressOfEntryPoint;
    if (ep_rva == 0) {
        std::printf("[*] no entry point, image mapped without DllMain\n");
    } else {
        const std::uint64_t ep = remote_base + ep_rva;
        std::printf("[*] DllMain @ 0x%016" PRIx64 "\n", ep);
        if (!run_remote_dllmain_style(proc.get(), remote_base, ep)) {
            std::fprintf(stderr, "[-] DllMain thread failed: %lu\n", ::GetLastError());
            return 1;
        }
    }

    std::printf("[+] mapped 0x%016" PRIx64 "  (image kept alive in target)\n",
                remote_base);
    return 0;
}
