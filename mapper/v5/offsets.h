// offsets.h — build-dependent kernel struct offsets
// provenance: Win11 23H2 22631.* x64 — verify with windbg:
//   dt nt!_EPROCESS / _ETHREAD / _MMVAD_SHORT / _MMVAD / _CONTROL_AREA / _FILE_OBJECT
// a wrong offset gates its feature at runtime via sanity checks; nothing else stops.
#pragma once
#include <cstdint>

namespace ko {

// ------------------------------------------------------------------- EPROCESS
constexpr std::uint32_t EP_DirectoryTableBase = 0x0028;
constexpr std::uint32_t EP_UniqueProcessId    = 0x0440;
constexpr std::uint32_t EP_ActiveProcessLinks = 0x0448;
constexpr std::uint32_t EP_Peb                = 0x0550;
constexpr std::uint32_t EP_ImageFileName      = 0x05A8; // UCHAR[15]
constexpr std::uint32_t EP_ThreadListHead     = 0x05E0; // LIST_ENTRY
constexpr std::uint32_t EP_VadRoot            = 0x07D8; // RTL_AVL_TREE { Root }

// -------------------------------------------------------------------- ETHREAD
constexpr std::uint32_t ET_Cid                = 0x04A8; // CLIENT_ID { UniqueProcess, UniqueThread }
constexpr std::uint32_t ET_ThreadListEntry    = 0x0578; // links EPROCESS->ThreadListHead

// ------------------------------------------------------------------- MMVAD_SHORT
constexpr std::uint32_t VS_Left           = 0x0000;
constexpr std::uint32_t VS_Right          = 0x0008;
constexpr std::uint32_t VS_Parent         = 0x0010;
constexpr std::uint32_t VS_StartingVpn    = 0x0018; // DWORD
constexpr std::uint32_t VS_EndingVpn      = 0x001C; // DWORD
constexpr std::uint32_t VS_StartingVpnH   = 0x0020; // BYTE
constexpr std::uint32_t VS_EndingVpnH     = 0x0021; // BYTE
constexpr std::uint32_t VS_u_VadFlags     = 0x0030; // DWORD — Protection<<3 | VadType

// --------------------------------------------------------------------- MMVAD (full extras)
constexpr std::uint32_t VAD_Subsection    = 0x0048;

// ------------------------------------------------------------------- SUBSECTION
constexpr std::uint32_t SS_ControlArea    = 0x0000;

// ----------------------------------------------------------------- CONTROL_AREA
constexpr std::uint32_t CA_FilePointer    = 0x0040; // EX_FAST_REF (mask low 4)

// ------------------------------------------------------------------- FILE_OBJECT
constexpr std::uint32_t FO_FileName       = 0x0058; // UNICODE_STRING

// ------------------------------------------------------------------- VAD type enum
enum : unsigned {
    VadNone     = 0,
    VadDevice   = 1,
    VadImageMap = 2,
    VadAwe      = 3,
    VadWriteWatch = 4,
    VadLargePages = 5,
    VadRotate   = 6,
    VadLargePageSection = 7
};

// --------------------------------------------------------------- canonical KVA floor
constexpr std::uint64_t kKernelFloor = 0xFFFF800000000000ULL;

inline bool is_kva(std::uint64_t a) { return a >= kKernelFloor; }

} // namespace ko
