#pragma once
#include "util.h"

struct FVec { double x, y, z; };
struct FRot { double p, y, r; }; // degrees: pitch, yaw, roll

static __forceinline FVec read_pos_(uptr addr) {
    FVec v = { 0, 0, 0 };
    if (off::kLWC) {
        double d[3];
        if (kread(addr, *(decltype(d)*)d)) { v.x = d[0]; v.y = d[1]; v.z = d[2]; }
    } else {
        float d[3];
        if (kread(addr, *(decltype(d)*)d)) { v.x = d[0]; v.y = d[1]; v.z = d[2]; }
    }
    return v;
}

static __forceinline FRot read_rot_(uptr addr) {
    FRot v = { 0, 0, 0 };
    if (off::kLWC) {
        double d[3];
        if (kread(addr, *(decltype(d)*)d)) { v.p = d[0]; v.y = d[1]; v.r = d[2]; }
    } else {
        float d[3];
        if (kread(addr, *(decltype(d)*)d)) { v.p = d[0]; v.y = d[1]; v.r = d[2]; }
    }
    return v;
}

struct FTArr { uptr Data; i32 Num; i32 Max; };

static __forceinline FTArr read_tarr_(uptr addr) {
    FTArr a = { 0, 0, 0 };
    kread(addr, a);
    if (a.Num < 0 || a.Num > 100000) a.Num = 0;
    return a;
}

static __forceinline uptr obj_class_(uptr o) {
    return deref_(o, off::UObj_ClassPrivate);
}

static __forceinline uptr uworld_() {
    if (off::kGWorld_RVA == 0) return 0;
    uptr p = game_module() + off::kGWorld_RVA;
    return kread_or<uptr>(p, 0);
}

static __forceinline uptr persistent_level_(uptr w) {
    if (!w || off::UWorld_PersistentLevel == 0) return 0;
    return deref_(w, off::UWorld_PersistentLevel);
}

static __forceinline FTArr level_actors_(uptr level) {
    if (!level || off::ULevel_Actors == 0) return FTArr{ 0, 0, 0 };
    return read_tarr_(level + off::ULevel_Actors);
}

static __forceinline uptr local_pc_(uptr w) {
    if (!w) return 0;
    if (!off::UWorld_OwningGameInstance || !off::UGameInstance_LocalPlayers
        || !off::ULocalPlayer_PlayerController) return 0;
    uptr gi = deref_(w, off::UWorld_OwningGameInstance);
    if (!gi) return 0;
    FTArr arr = read_tarr_(gi + off::UGameInstance_LocalPlayers);
    if (!arr.Data || arr.Num <= 0) return 0;
    uptr lp = kread_or<uptr>(arr.Data, 0);
    if (!lp) return 0;
    return deref_(lp, off::ULocalPlayer_PlayerController);
}

static __forceinline uptr local_pawn_(uptr pc) {
    if (!pc || !off::APC_AcknowledgedPawn) return 0;
    return deref_(pc, off::APC_AcknowledgedPawn);
}

static __forceinline uptr camera_mgr_(uptr pc) {
    if (!pc || !off::APC_PlayerCameraManager) return 0;
    return deref_(pc, off::APC_PlayerCameraManager);
}

struct POV { FVec loc; FRot rot; float fov; };

static __forceinline bool read_pov_(uptr pcm, POV& o) {
    if (!pcm || !off::APCM_CameraCachePrivate || !off::POV_FOV) return false;
    uptr cache = pcm + off::APCM_CameraCachePrivate + off::CameraCacheEntry_POV;
    o.loc = read_pos_(cache + off::POV_Location);
    o.rot = read_rot_(cache + off::POV_Rotation);
    o.fov = kread_or<float>(cache + off::POV_FOV, 90.0f);
    if (o.fov < 10.0f || o.fov > 170.0f) return false;
    return true;
}

static __forceinline FVec actor_loc_(uptr a) {
    if (!a || !off::AActor_RootComponent || !off::USC_ComponentToWorld) return FVec{ 0, 0, 0 };
    uptr rc = deref_(a, off::AActor_RootComponent);
    if (!rc) return FVec{ 0, 0, 0 };
    // FTransform: FQuat (16B float / 32B LWC) then translation.
    uptr t = rc + off::USC_ComponentToWorld + (off::kLWC ? 0x20 : 0x10);
    return read_pos_(t);
}

static __forceinline uptr pawn_player_state_(uptr pawn) {
    if (!pawn || !off::APawn_PlayerState) return 0;
    return deref_(pawn, off::APawn_PlayerState);
}
