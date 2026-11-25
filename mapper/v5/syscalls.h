// syscalls.h — direct syscall framework
// parses ntdll.dll on disk at startup, extracts SSNs from the clean file (no
// in-memory hook survives a disk read), then generates 12-byte stubs at runtime
// in a single RX page.
//
// standard x64 syscall stub:
//   4C 8B D1              mov r10, rcx
//   B8 XX XX XX XX        mov eax, SSN
//   0F 05                 syscall
//   C3                    ret
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

class Syscalls {
public:
    Syscalls() = default;
    Syscalls(const Syscalls&) = delete;
    Syscalls& operator=(const Syscalls&) = delete;
    ~Syscalls() {
        if (page_) ::VirtualFree(page_, 0, MEM_RELEASE);
    }

    bool init() {
        wchar_t sysdir[MAX_PATH]{};
        if (!::GetSystemDirectoryW(sysdir, MAX_PATH)) return false;
        std::wstring path = std::wstring(sysdir) + L"\\ntdll.dll";

        HANDLE fh = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (fh == INVALID_HANDLE_VALUE) return false;
        HANDLE mh = ::CreateFileMappingW(fh, nullptr, PAGE_READONLY, 0, 0, nullptr);
        ::CloseHandle(fh);
        if (!mh) return false;
        auto* base = static_cast<BYTE*>(::MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0));
        ::CloseHandle(mh);
        if (!base) return false;

        struct ViewGuard {
            BYTE* p;
            ~ViewGuard() { if (p) ::UnmapViewOfFile(p); }
        } g{ base };

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        auto rva2off = [&](DWORD rva) -> BYTE* {
            auto* sec = IMAGE_FIRST_SECTION(nt);
            for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
                if (rva >= sec->VirtualAddress &&
                    rva <  sec->VirtualAddress + sec->Misc.VirtualSize) {
                    return base + sec->PointerToRawData + (rva - sec->VirtualAddress);
                }
            }
            return nullptr;
        };

        const auto& edd =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (edd.Size == 0) return false;
        auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(rva2off(edd.VirtualAddress));
        if (!exp) return false;

        auto* names   = reinterpret_cast<DWORD*>(rva2off(exp->AddressOfNames));
        auto* ords    = reinterpret_cast<WORD*>(rva2off(exp->AddressOfNameOrdinals));
        auto* funcs   = reinterpret_cast<DWORD*>(rva2off(exp->AddressOfFunctions));
        if (!names || !ords || !funcs) return false;

        for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
            auto* nm = reinterpret_cast<const char*>(rva2off(names[i]));
            if (!nm) continue;
            // Nt* and Zw* share SSN; prefer Nt names.
            if (!(nm[0] == 'N' && nm[1] == 't')) continue;
            DWORD rva = funcs[ords[i]];
            BYTE* fn = rva2off(rva);
            if (!fn) continue;
            // sanity pattern: 4C 8B D1 B8 <SSN:4>
            if (fn[0] != 0x4C || fn[1] != 0x8B || fn[2] != 0xD1 || fn[3] != 0xB8) continue;
            DWORD ssn = *reinterpret_cast<DWORD*>(fn + 4);
            ssn_[nm] = ssn;
        }

        // one RX page for every generated stub
        page_ = ::VirtualAlloc(nullptr, 0x1000,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        return page_ != nullptr && !ssn_.empty();
    }

    std::uint32_t ssn(const char* name) const {
        auto it = ssn_.find(name);
        return (it == ssn_.end()) ? 0xFFFFFFFFu : it->second;
    }

    // build (or return cached) 12-byte syscall stub for `name`.
    void* make(const char* name) {
        auto it = stubs_.find(name);
        if (it != stubs_.end()) return it->second;
        std::uint32_t s = ssn(name);
        if (s == 0xFFFFFFFFu) return nullptr;
        if (next_ + 16 >= 0x1000) return nullptr;
        BYTE* p = static_cast<BYTE*>(page_) + next_;
        p[0] = 0x4C; p[1] = 0x8B; p[2] = 0xD1;               // mov r10, rcx
        p[3] = 0xB8; std::memcpy(p + 4, &s, 4);              // mov eax, SSN
        p[8] = 0x0F; p[9] = 0x05;                            // syscall
        p[10] = 0xC3; p[11] = 0x90; p[12] = 0x90;            // ret + pad
        p[13] = 0x90; p[14] = 0x90; p[15] = 0x90;
        next_ += 16;
        stubs_[name] = p;
        return p;
    }

    // after all `make` calls, lock the page RX.
    bool finalize() {
        DWORD old = 0;
        return ::VirtualProtect(page_, 0x1000, PAGE_EXECUTE_READ, &old) != 0;
    }

    // typed accessor
    template<class Fn>
    Fn get(const char* name) { return reinterpret_cast<Fn>(make(name)); }

    size_t stub_count() const { return stubs_.size(); }
    size_t ssn_count()  const { return ssn_.size(); }

private:
    std::unordered_map<std::string, std::uint32_t> ssn_;
    std::unordered_map<std::string, void*> stubs_;
    void* page_ = nullptr;
    size_t next_ = 0;
};

// ------------------------- NT type sketches we need ---------------------------
// (winternl.h defines some; we replicate what it misses or renames inconsistently)

using NTSTATUS_T = LONG;

struct CLIENT_ID_T { HANDLE UniqueProcess; HANDLE UniqueThread; };

struct OBJECT_ATTRIBUTES_T {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
};
inline void init_oa(OBJECT_ATTRIBUTES_T& oa) {
    std::memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
}

// prototypes for the stubs we build
using tNtOpenProcess = NTSTATUS_T (NTAPI*)(
    PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES_T*, CLIENT_ID_T*);
using tNtOpenThread  = NTSTATUS_T (NTAPI*)(
    PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES_T*, CLIENT_ID_T*);
using tNtClose       = NTSTATUS_T (NTAPI*)(HANDLE);
using tNtSuspendThread = NTSTATUS_T (NTAPI*)(HANDLE, PULONG);
using tNtResumeThread  = NTSTATUS_T (NTAPI*)(HANDLE, PULONG);
using tNtGetContextThread = NTSTATUS_T (NTAPI*)(HANDLE, PCONTEXT);
using tNtSetContextThread = NTSTATUS_T (NTAPI*)(HANDLE, PCONTEXT);
using tNtWriteVirtualMemory = NTSTATUS_T (NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using tNtReadVirtualMemory  = NTSTATUS_T (NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using tNtProtectVirtualMemory = NTSTATUS_T (NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
using tNtAllocateVirtualMemory = NTSTATUS_T (NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
using tNtQuerySystemInformation = NTSTATUS_T (NTAPI*)(ULONG, PVOID, ULONG, PULONG);

// SystemProcessInformation
constexpr ULONG kSystemProcessInformation = 5;

struct SYSTEM_THREAD_INFORMATION_T {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID_T ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
};

struct SYSTEM_PROCESS_INFORMATION_T {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION_T Threads[1];
};
