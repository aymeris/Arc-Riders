// EAC territory - mapper_v5's stomp + header-wipe + hijack is the chosen approach; account risk remains.
#include <windows.h>

#include "config.h"
#include "util.h"
#include "ue.h"
#include "overlay.h"
#include "menu.h"
#include "features.h"
#include "esp.h"
#include "aim.h"

extern "C" int _fltused = 0;

static const char* kConfigPath = "C:\\Users\\msayt\\Desktop\\mapper\\arcr_cheat.cfg";

struct State {
    Overlay  o;
    MenuState m;
    Input    in;
    Settings s;
    Aim      aim;
    bool     stop;
    int      gworld_status; // 0 unknown, 1 ok, 2 FILL or unresolved
};

static State g_state;

static void draw_watermark_(Overlay& o, int gw_status, int ntargets, int fps) {
    wchar_t buf[128];
    const wchar_t* gw = (gw_status == 1) ? L"ok" : L"FILL";
    fmt_w(buf, 128, L"arcr  gworld=%s  tgt=%d  fps=%d", gw, ntargets, fps);
    dr_fill(o, 8, 8, 260, 20, RGB(20, 20, 30));
    dr_rect(o, 8, 8, 260, 20, RGB(80, 80, 110), 1);
    dr_text(o, 14, 11, RGB(200, 220, 255), buf);
}

static DWORD WINAPI arcr_thread(LPVOID) {
    settings_defaults(g_state.s);
    menu_init(g_state.m);
    input_init(g_state.in);
    aim_init(g_state.aim);
    load_settings(g_state.s, kConfigPath);

    if (!overlay_init(g_state.o)) return 0;

    ULONGLONG last_tick = GetTickCount64();
    int frames = 0, fps = 0;

    while (!g_state.stop) {
        overlay_sync(g_state.o);
        if (g_state.o.w <= 0 || g_state.o.h <= 0) { Sleep(10); continue; }

        input_update(g_state.in, g_state.o);
        menu_toggle_key(g_state.m);
        overlay_set_clickable(g_state.o, g_state.m.visible);

        uptr w = uworld_();
        g_state.gworld_status = (off::kGWorld_RVA == 0) ? 2 : (w ? 1 : 2);
        uptr level = persistent_level_(w);
        uptr pc    = local_pc_(w);
        uptr self  = local_pawn_(pc);
        uptr pcm   = camera_mgr_(pc);
        POV cam; bool cam_ok = read_pov_(pcm, cam);

        static Target ts[128];
        int nt = 0;
        if (level && cam_ok) {
            nt = collect_targets(level, self, cam, g_state.o.w, g_state.o.h, ts, 128);
        }

        overlay_begin(g_state.o);

        if (g_state.s.show_watermark)
            draw_watermark_(g_state.o, g_state.gworld_status, nt, fps);

        if (g_state.s.esp_enable && cam_ok) {
            for (int i = 0; i < nt; ++i) {
                if (ts[i].dist_m > (float)g_state.s.esp_max_dist) continue;
                draw_target(g_state.o, ts[i], g_state.s);
            }
        }

        if (cam_ok) do_aim(g_state.aim, ts, nt, g_state.s, g_state.o.w, g_state.o.h);

        if (g_state.m.visible) {
            menu_begin(g_state.m, g_state.o, g_state.in);
            switch (g_state.m.tab) {
            case 0:
                mcheck(g_state.m, g_state.o, g_state.in, L"Enable ESP", g_state.s.esp_enable);
                mcheck(g_state.m, g_state.o, g_state.in, L"Box", g_state.s.esp_box);
                mcheck(g_state.m, g_state.o, g_state.in, L"Name", g_state.s.esp_name);
                mcheck(g_state.m, g_state.o, g_state.in, L"Distance", g_state.s.esp_dist);
                mcheck(g_state.m, g_state.o, g_state.in, L"Snap line", g_state.s.esp_line);
                mslider_i(g_state.m, g_state.o, g_state.in, L"Max dist (m)",
                          g_state.s.esp_max_dist, 10, 1000);
                break;
            case 1:
                mcheck(g_state.m, g_state.o, g_state.in, L"Enable Aim", g_state.s.aim_enable);
                mcheck(g_state.m, g_state.o, g_state.in, L"Target head",
                       g_state.s.aim_target_head);
                mslider_f(g_state.m, g_state.o, g_state.in, L"FOV",
                          g_state.s.aim_fov, 1.0f, 30.0f);
                mslider_f(g_state.m, g_state.o, g_state.in, L"Smooth",
                          g_state.s.aim_smooth, 1.0f, 15.0f);
                mslider_i(g_state.m, g_state.o, g_state.in, L"Key (VK)",
                          g_state.s.aim_key, 1, 254);
                break;
            case 2:
                mcheck(g_state.m, g_state.o, g_state.in, L"Show FPS", g_state.s.show_fps);
                mcheck(g_state.m, g_state.o, g_state.in, L"Watermark", g_state.s.show_watermark);
                break;
            case 3:
                if (mbutton(g_state.m, g_state.o, g_state.in, L"Save config"))
                    save_settings(g_state.s, kConfigPath);
                if (mbutton(g_state.m, g_state.o, g_state.in, L"Reload config"))
                    load_settings(g_state.s, kConfigPath);
                if (mbutton(g_state.m, g_state.o, g_state.in, L"Unload"))
                    g_state.stop = true;
                break;
            }
        }

        overlay_end(g_state.o);

        frames++;
        ULONGLONG now = GetTickCount64();
        if (now - last_tick >= 1000) { fps = frames; frames = 0; last_tick = now; }

        Sleep(8);

        if (GetAsyncKeyState(VK_END) & 0x8000) g_state.stop = true;
    }

    save_settings(g_state.s, kConfigPath);
    overlay_destroy(g_state.o);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_ATTACH) {
        g_state.stop = false;
        g_state.gworld_status = 0;
        CreateThread(NULL, 0, arcr_thread, NULL, 0, NULL);
    }
    return TRUE;
}
