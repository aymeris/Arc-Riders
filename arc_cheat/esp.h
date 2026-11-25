#pragma once
#include "ue.h"
#include "overlay.h"
#include "features.h"

static __forceinline bool w2s_(const POV& p, const FVec& wld, int sw, int sh, V2& out) {
    float pitch = deg2rad_((float)p.rot.p);
    float yawr  = deg2rad_((float)p.rot.y);
    float roll  = deg2rad_((float)p.rot.r);

    float cp = fcos_(pitch), sp = fsin_(pitch);
    float cy = fcos_(yawr),  sy = fsin_(yawr);
    float cr = fcos_(roll),  sr = fsin_(roll);

    V3 fwd  = { cp * cy, cp * sy, sp };
    V3 right= { sr * sp * cy - cr * sy, sr * sp * sy + cr * cy, -sr * cp };
    V3 up   = { -(cr * sp * cy + sr * sy), cy * sr - cr * sp * sy, cr * cp };

    V3 d = {
        (float)(wld.x - p.loc.x),
        (float)(wld.y - p.loc.y),
        (float)(wld.z - p.loc.z)
    };
    float tx = d.x * right.x + d.y * right.y + d.z * right.z;
    float ty = d.x * up.x    + d.y * up.y    + d.z * up.z;
    float tz = d.x * fwd.x   + d.y * fwd.y   + d.z * fwd.z;
    if (tz < 1.0f) return false;

    float cxf = (float)sw * 0.5f;
    float cyf = (float)sh * 0.5f;
    float t = ftan_(deg2rad_(p.fov * 0.5f));
    if (t <= 0.00001f) return false;
    float proj = cxf / t;
    out.x = cxf + tx * (proj / tz);
    out.y = cyf - ty * (proj / tz);
    return true;
}

struct Target {
    uptr pawn;
    FVec loc;
    V2   head_s, feet_s;
    float dist_m;
};

static __forceinline int collect_targets(uptr level, uptr self_pawn, const POV& cam,
                                         int sw, int sh, Target* out, int cap) {
    if (!level) return 0;
    FTArr arr = level_actors_(level);
    if (!arr.Data || arr.Num <= 0) return 0;
    int n = 0;
    int cnt = arr.Num > 4096 ? 4096 : arr.Num;
    for (int i = 0; i < cnt && n < cap; ++i) {
        uptr a = kread_or<uptr>(arr.Data + (uptr)i * 8, 0);
        if (!a || a == self_pawn) continue;
        if (!off::APawn_PlayerState) continue;
        uptr ps = pawn_player_state_(a);
        if (!ps) continue;
        FVec feet = actor_loc_(a);
        if (feet.x == 0 && feet.y == 0 && feet.z == 0) continue;
        FVec head = { feet.x, feet.y, feet.z + 90.0 };
        float dx = (float)(feet.x - cam.loc.x);
        float dy = (float)(feet.y - cam.loc.y);
        float dz = (float)(feet.z - cam.loc.z);
        float d_u = fsqrtf_(dx * dx + dy * dy + dz * dz);
        float d_m = d_u * 0.01f;
        V2 fs, hs;
        if (!w2s_(cam, feet, sw, sh, fs)) continue;
        if (!w2s_(cam, head, sw, sh, hs)) continue;
        Target t;
        t.pawn = a; t.loc = feet; t.head_s = hs; t.feet_s = fs; t.dist_m = d_m;
        out[n++] = t;
    }
    return n;
}

static __forceinline void draw_target(Overlay& o, const Target& t, const Settings& s) {
    float hpx = t.feet_s.y - t.head_s.y;
    if (hpx < 10.0f) return;
    float wpx = hpx * 0.5f;
    int x = (int)(t.head_s.x - wpx * 0.5f);
    int y = (int)t.head_s.y;
    int iw = (int)wpx, ih = (int)hpx;
    COLORREF col = RGB(80, 220, 120);
    if (s.esp_box) dr_rect(o, x, y, iw, ih, col, 1);
    if (s.esp_line) {
        int mx = o.w / 2, my = o.h;
        dr_line(o, mx, my, (int)t.head_s.x, (int)t.head_s.y, col, 1);
    }
    if (s.esp_name) {
        dr_text(o, x, y - 14, RGB(230, 230, 255), L"Player");
    }
    if (s.esp_dist) {
        wchar_t buf[32];
        fmt_w(buf, 32, L"%dm", (int)t.dist_m);
        dr_text(o, x, y + ih + 2, RGB(200, 200, 200), buf);
    }
}
