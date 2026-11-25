#pragma once
#include "overlay.h"

struct Input {
    int mx, my;
    bool ldown, lup, lheld, prev_l;
};

static __forceinline void input_init(Input& in) {
    in.mx = 0; in.my = 0;
    in.ldown = false; in.lup = false; in.lheld = false; in.prev_l = false;
}

static __forceinline void input_update(Input& in, Overlay& o) {
    POINT p; GetCursorPos(&p);
    if (o.game) ScreenToClient(o.game, &p);
    in.mx = p.x; in.my = p.y;
    bool cur = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
    in.ldown = cur && !in.prev_l;
    in.lup   = !cur && in.prev_l;
    in.lheld = cur;
    in.prev_l = cur;
}

struct MenuState {
    int tab;
    int x, y, w, h;
    bool visible;
    bool dragging;
    int  drag_dx, drag_dy;
    int  cursor_y;
    bool ins_prev;
};

static __forceinline void menu_init(MenuState& m) {
    m.tab = 0;
    m.x = 100; m.y = 100; m.w = 320; m.h = 360;
    m.visible = false;
    m.dragging = false;
    m.drag_dx = 0; m.drag_dy = 0;
    m.cursor_y = 0;
    m.ins_prev = false;
}

static __forceinline bool hit_(int mx, int my, int x, int y, int w, int h) {
    return mx >= x && my >= y && mx < x + w && my < y + h;
}

static __forceinline void menu_toggle_key(MenuState& m) {
    bool cur = (GetAsyncKeyState(VK_INSERT) & 0x8000) != 0;
    if (cur && !m.ins_prev) m.visible = !m.visible;
    m.ins_prev = cur;
}

static __forceinline void menu_begin(MenuState& m, Overlay& o, Input& in) {
    if (!m.visible) return;

    const int title_h = 22;
    if (in.ldown && hit_(in.mx, in.my, m.x, m.y, m.w, title_h)) {
        m.dragging = true;
        m.drag_dx = in.mx - m.x;
        m.drag_dy = in.my - m.y;
    }
    if (in.lup) m.dragging = false;
    if (m.dragging) {
        m.x = in.mx - m.drag_dx;
        m.y = in.my - m.drag_dy;
    }

    dr_fill(o, m.x, m.y, m.w, m.h, RGB(15, 15, 20));
    dr_rect(o, m.x, m.y, m.w, m.h, RGB(80, 80, 110), 1);
    dr_fill(o, m.x, m.y, m.w, title_h, RGB(40, 40, 70));
    dr_text(o, m.x + 8, m.y + 4, RGB(220, 220, 255), L"arcr  -  INSERT");

    const wchar_t* names[4] = { L"ESP", L"AIMBOT", L"MISC", L"CONFIG" };
    int tw = m.w / 4;
    for (int i = 0; i < 4; ++i) {
        int tx = m.x + i * tw;
        int ty = m.y + title_h;
        COLORREF bg = (m.tab == i) ? RGB(60, 60, 100) : RGB(25, 25, 40);
        dr_fill(o, tx, ty, tw, 20, bg);
        dr_text(o, tx + 10, ty + 3, RGB(230, 230, 255), names[i]);
        if (in.ldown && hit_(in.mx, in.my, tx, ty, tw, 20)) m.tab = i;
    }
    m.cursor_y = m.y + title_h + 24;
}

static __forceinline bool mbutton(MenuState& m, Overlay& o, Input& in, const wchar_t* lbl) {
    int x = m.x + 8, y = m.cursor_y, w = m.w - 16, h = 20;
    bool hv = hit_(in.mx, in.my, x, y, w, h);
    COLORREF bg = hv ? RGB(50, 50, 90) : RGB(30, 30, 50);
    dr_fill(o, x, y, w, h, bg);
    dr_rect(o, x, y, w, h, RGB(80, 80, 110), 1);
    dr_text(o, x + 6, y + 3, RGB(220, 220, 255), lbl);
    m.cursor_y += h + 4;
    return hv && in.ldown;
}

static __forceinline void mcheck(MenuState& m, Overlay& o, Input& in, const wchar_t* lbl, bool& val) {
    int x = m.x + 8, y = m.cursor_y, w = m.w - 16, h = 20;
    bool hv = hit_(in.mx, in.my, x, y, w, h);
    dr_fill(o, x, y, w, h, hv ? RGB(50, 50, 90) : RGB(30, 30, 50));
    int bx = x + 6, by = y + 4, bs = 12;
    dr_rect(o, bx, by, bs, bs, RGB(180, 180, 220), 1);
    if (val) dr_fill(o, bx + 2, by + 2, bs - 4, bs - 4, RGB(120, 220, 120));
    dr_text(o, x + 24, y + 3, RGB(220, 220, 255), lbl);
    if (hv && in.ldown) val = !val;
    m.cursor_y += h + 4;
}

static __forceinline void mslider_f(MenuState& m, Overlay& o, Input& in,
                                    const wchar_t* lbl, float& val, float lo, float hi) {
    int x = m.x + 8, y = m.cursor_y, w = m.w - 16, h = 24;
    dr_fill(o, x, y, w, h, RGB(30, 30, 50));
    dr_rect(o, x, y, w, h, RGB(80, 80, 110), 1);
    wchar_t buf[96];
    fmt_w(buf, 96, L"%s  %d", lbl, (int)(val * 100.0f));
    dr_text(o, x + 6, y + 5, RGB(220, 220, 255), buf);
    int track_x = x + 6, track_y = y + h - 6, track_w = w - 12;
    float t = (val - lo) / (hi - lo);
    if (t < 0) t = 0;
    if (t > 1) t = 1;
    dr_fill(o, track_x, track_y, (int)((float)track_w * t), 3, RGB(120, 180, 255));
    if (in.lheld && hit_(in.mx, in.my, track_x, track_y - 4, track_w, 12)) {
        float nt = (float)(in.mx - track_x) / (float)track_w;
        if (nt < 0) nt = 0;
        if (nt > 1) nt = 1;
        val = lo + nt * (hi - lo);
    }
    m.cursor_y += h + 4;
}

static __forceinline void mslider_i(MenuState& m, Overlay& o, Input& in,
                                    const wchar_t* lbl, int& val, int lo, int hi) {
    float f = (float)val;
    mslider_f(m, o, in, lbl, f, (float)lo, (float)hi);
    val = (int)(f + 0.5f);
}
