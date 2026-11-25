// pe.h — PE file layout + relocation + import resolution for manual mapping
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

namespace pe {

// ---------- read a file off disk into a byte vector --------------------------
inline bool read_file(const wchar_t* path, std::vector<std::uint8_t>& out) {
    HANDLE fh = ::CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!::GetFileSizeEx(fh, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (1LL<<30)) {
        ::CloseHandle(fh); return false;
    }
    out.resize(static_cast<std::size_t>(sz.QuadPart));
    DWORD rd = 0;
    bool ok = ::ReadFile(fh, out.data(), static_cast<DWORD>(out.size()), &rd, nullptr)
           && rd == out.size();
    ::CloseHandle(fh);
    return ok;
}

// ---------- validate + locate NT headers -------------------------------------
inline IMAGE_NT_HEADERS64* validate(std::vector<std::uint8_t>& file) {
    if (file.size() < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) return nullptr;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    if (dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > file.size()) return nullptr;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return nullptr;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return nullptr;
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) return nullptr;
    return nt;
}

// ---------- lay out sections at their RVAs in a local buffer -----------------
inline std::vector<std::uint8_t> layout(const std::vector<std::uint8_t>& file,
                                        IMAGE_NT_HEADERS64* nt)
{
    std::vector<std::uint8_t> img(nt->OptionalHeader.SizeOfImage, 0);
    std::memcpy(img.data(), file.data(), nt->OptionalHeader.SizeOfHeaders);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->SizeOfRawData == 0) continue;
        if (sec->PointerToRawData + sec->SizeOfRawData > file.size()) continue;
        std::memcpy(img.data() + sec->VirtualAddress,
                    file.data() + sec->PointerToRawData,
                    sec->SizeOfRawData);
    }
    return img;
}

// ---------- apply base relocations for new_base ------------------------------
inline void relocate(std::uint8_t* img, IMAGE_NT_HEADERS64* nt, std::uint64_t new_base) {
    const auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dd.Size == 0) return;
    const std::int64_t delta =
        static_cast<std::int64_t>(new_base) -
        static_cast<std::int64_t>(nt->OptionalHeader.ImageBase);
    if (delta == 0) {
        nt->OptionalHeader.ImageBase = new_base;
        return;
    }
    DWORD done = 0;
    auto* b = reinterpret_cast<IMAGE_BASE_RELOCATION*>(img + dd.VirtualAddress);
    while (done < dd.Size && b->SizeOfBlock) {
        if (b->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
        DWORD cnt = (b->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto* list = reinterpret_cast<WORD*>(b + 1);
        for (DWORD i = 0; i < cnt; ++i) {
            WORD type = static_cast<WORD>(list[i] >> 12);
            WORD off  = static_cast<WORD>(list[i] & 0xFFF);
            if (type == IMAGE_REL_BASED_DIR64) {
                auto* p = reinterpret_cast<std::uint64_t*>(img + b->VirtualAddress + off);
                *p = static_cast<std::uint64_t>(static_cast<std::int64_t>(*p) + delta);
            }
        }
        done += b->SizeOfBlock;
        b = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<std::uint8_t*>(b) + b->SizeOfBlock);
    }
    nt->OptionalHeader.ImageBase = new_base;
}

// ---------- import resolution via a {basename -> target_base} table -----------
// returns true if every imported symbol was resolved.
inline bool resolve_imports(std::uint8_t* img, IMAGE_NT_HEADERS64* nt,
                            const std::unordered_map<std::string, std::uint64_t>& modmap)
{
    const auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dd.Size == 0) return true;
    auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(img + dd.VirtualAddress);
    for (; imp->Name; ++imp) {
        const char* dll = reinterpret_cast<const char*>(img + imp->Name);
        std::string key = dll;
        for (auto& c : key) c = static_cast<char>(::tolower((unsigned char)c));

        auto it = modmap.find(key);
        if (it == modmap.end()) {
            std::fprintf(stderr, "[pe] import DLL not loaded in target: %s\n", dll);
            return false;
        }
        std::uint64_t remote_base = it->second;

        HMODULE local = ::GetModuleHandleA(dll);
        bool unload = false;
        if (!local) {
            local = ::LoadLibraryExA(dll, nullptr, DONT_RESOLVE_DLL_REFERENCES);
            unload = (local != nullptr);
        }
        if (!local) {
            std::fprintf(stderr, "[pe] cannot load %s locally for exports\n", dll);
            return false;
        }
        std::int64_t delta =
            static_cast<std::int64_t>(remote_base)
          - static_cast<std::int64_t>(reinterpret_cast<std::uint64_t>(local));

        auto* oft = imp->OriginalFirstThunk
            ? reinterpret_cast<IMAGE_THUNK_DATA64*>(img + imp->OriginalFirstThunk)
            : reinterpret_cast<IMAGE_THUNK_DATA64*>(img + imp->FirstThunk);
        auto* ft = reinterpret_cast<IMAGE_THUNK_DATA64*>(img + imp->FirstThunk);
        for (; oft->u1.AddressOfData; ++oft, ++ft) {
            FARPROC fn = nullptr;
            if (IMAGE_SNAP_BY_ORDINAL64(oft->u1.Ordinal)) {
                WORD ord = static_cast<WORD>(IMAGE_ORDINAL64(oft->u1.Ordinal));
                fn = ::GetProcAddress(local, MAKEINTRESOURCEA(ord));
            } else {
                auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                    img + oft->u1.AddressOfData);
                fn = ::GetProcAddress(local, ibn->Name);
            }
            if (!fn) {
                std::fprintf(stderr, "[pe] missing import in %s\n", dll);
                if (unload) ::FreeLibrary(local);
                return false;
            }
            ft->u1.Function =
                static_cast<std::uint64_t>(reinterpret_cast<std::uint64_t>(fn) + delta);
        }
        if (unload) ::FreeLibrary(local);
    }
    return true;
}

} // namespace pe
