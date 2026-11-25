#pragma once

// arc raiders — all build-dependent values, FILL from Dumper-7 on the running build.
// nothing confirmed. every value compiles as 0 and gates its feature at runtime.
// provenance template (fill per value): [rva/off 0x... | build x.y.z | dumper-7 YYYY-MM-DD | verified live]

typedef unsigned __int8  u8;
typedef unsigned __int16 u16;
typedef unsigned __int32 u32;
typedef unsigned __int64 u64;
typedef __int8  i8;
typedef __int16 i16;
typedef __int32 i32;
typedef __int64 i64;
typedef u64 uptr;

namespace off {

// --- globals (RVA inside the main UE5 game module) ---
inline const u64 kGWorld_RVA        = 0; // FILL: GWorld signature -> RVA

// --- UObject (typical UE5 defaults, confirm per build) ---
inline const u32 UObj_ClassPrivate  = 0x10;
inline const u32 UObj_NamePrivate   = 0x18;
inline const u32 UObj_OuterPrivate  = 0x20;

// --- UWorld ---
inline const u32 UWorld_PersistentLevel    = 0; // FILL
inline const u32 UWorld_OwningGameInstance = 0; // FILL

// --- ULevel ---
inline const u32 ULevel_Actors             = 0; // FILL (TArray<AActor*>)

// --- UGameInstance ---
inline const u32 UGameInstance_LocalPlayers = 0; // FILL (TArray<ULocalPlayer*>)

// --- ULocalPlayer ---
inline const u32 ULocalPlayer_PlayerController = 0; // FILL

// --- APlayerController ---
inline const u32 APC_AcknowledgedPawn     = 0; // FILL
inline const u32 APC_PlayerCameraManager  = 0; // FILL

// --- APlayerCameraManager ---
inline const u32 APCM_CameraCachePrivate  = 0; // FILL (FCameraCacheEntry)
inline const u32 CameraCacheEntry_POV     = 0x10; // typical; confirm

// --- FMinimalViewInfo ---
inline const u32 POV_Location  = 0x00;
inline const u32 POV_Rotation  = 0x0C; // after FVector3f; if LWC set kLWC=1 -> use 0x18
inline const u32 POV_FOV       = 0;    // FILL (float; varies 5.0/5.3/5.4)

// --- AActor ---
inline const u32 AActor_RootComponent = 0; // FILL

// --- APawn ---
inline const u32 APawn_PlayerState    = 0; // FILL

// --- USceneComponent ---
inline const u32 USC_ComponentToWorld = 0; // FILL (FTransform)

// --- UE coordinate flavor ---
// 1 = Large World Coords (FVector = 24 bytes, double). 0 = float (FVector3f = 12 bytes).
// Confirm per build; w2s and transform reads switch on this.
inline const int kLWC = 0;

} // namespace off
