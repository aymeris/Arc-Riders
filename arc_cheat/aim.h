#pragma once
#include "esp.h"

struct Aim { int last_idx; };

static __forceinline void aim_init(Aim& a) { a.last_idx = -1; }

static __forceinline void do_aim(Aim& a, const Target* ts, int n, const Settings& s,
                                 int sw, int sh) {
    if (!s.aim_enable) { a.last_idx = -1; return; }
    if (!(GetAsyncKeyState(s.aim_key) & 0x8000)) { a.last_idx = -1; return; }

    int best = -1;
    float bestd = 1.0e9f;
    float cx = (float)sw * 0.5f;
    float cy = (float)sh * 0.5f;
    float fov_px = s.aim_fov * ((float)sw / 90.0f);
    for (int i = 0; i < n; ++i) {
        V2 t = s.aim_target_head ? ts[i].head_s : ts[i].feet_s;
        if (!on_screen_(t, sw, sh)) continue;
        float dx = t.x - cx, dy = t.y - cy;
        float d = fsqrtf_(dx * dx + dy * dy);
        if (d > fov_px) continue;
        if (d < bestd) { bestd = d; best = i; }
    }
    if (best < 0) { a.last_idx = -1; return; }
    a.last_idx = best;
    V2 t = s.aim_target_head ? ts[best].head_s : ts[best].feet_s;
    float dx = t.x - cx;
    float dy = t.y - cy;
    float sm = s.aim_smooth > 0.5f ? s.aim_smooth : 1.0f;
    int mx = (int)(dx / sm);
    int my = (int)(dy / sm);
    if (mx == 0 && my == 0) return;
    INPUT in; __stosb((BYTE*)&in, 0, sizeof(in));
    in.type = INPUT_MOUSE;
    in.mi.dwFlags = MOUSEEVENTF_MOVE;
    in.mi.dx = mx;
    in.mi.dy = my;
    SendInput(1, &in, sizeof(in));
}
