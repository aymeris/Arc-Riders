#pragma once
#include "util.h"

struct Overlay {
    HWND  hwnd;
    HWND  game;
    HDC   mem;
    HBITMAP bmp;
    HFONT font;
    int   w, h;
    bool  clickable;
};

static LRESULT CALLBACK arcr_wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_DESTROY) return 0;
    return DefWindowProcW(h, m, w, l);
}

struct FindS { DWORD pid; HWND out; };
static BOOL CALLBACK arcr_enum_proc(HWND h, LPARAM lp) {
    FindS* s = (FindS*)lp;
    DWORD p = 0;
    GetWindowThreadProcessId(h, &p);
    if (p == s->pid && IsWindowVisible(h)) {
        RECT r; GetClientRect(h, &r);
        if ((r.right - r.left) > 400 && (r.bottom - r.top) > 300) {
            s->out = h;
            return FALSE;
        }
    }
    return TRUE;
}

static __forceinline HWND find_game_window_() {
    FindS s = { GetCurrentProcessId(), NULL };
    EnumWindows(arcr_enum_proc, (LPARAM)&s);
    return s.out;
}

static __forceinline bool overlay_init(Overlay& o) {
    o.hwnd = 0; o.game = 0; o.mem = 0; o.bmp = 0; o.font = 0;
    o.w = 0; o.h = 0; o.clickable = false;

    WNDCLASSEXW wc; __stosb((BYTE*)&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = arcr_wndproc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"arcr_overlay_cls";
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    RegisterClassExW(&wc);

    o.hwnd = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
        L"arcr_overlay_cls", L"", WS_POPUP,
        0, 0, 100, 100, NULL, NULL, wc.hInstance, NULL);
    if (!o.hwnd) return false;
    SetLayeredWindowAttributes(o.hwnd, RGB(0, 0, 0), 0, LWA_COLORKEY);
    ShowWindow(o.hwnd, SW_SHOWNOACTIVATE);

    o.font = CreateFontW(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FF_DONTCARE, L"Consolas");
    return true;
}

static __forceinline void overlay_resize(Overlay& o, int w, int h) {
    if (w == o.w && h == o.h && o.mem) return;
    o.w = w; o.h = h;
    if (o.bmp) { DeleteObject(o.bmp); o.bmp = 0; }
    if (o.mem) { DeleteDC(o.mem); o.mem = 0; }
    HDC s = GetDC(o.hwnd);
    o.mem = CreateCompatibleDC(s);
    o.bmp = CreateCompatibleBitmap(s, w, h);
    SelectObject(o.mem, o.bmp);
    SelectObject(o.mem, o.font);
    SetBkMode(o.mem, TRANSPARENT);
    ReleaseDC(o.hwnd, s);
}

static __forceinline void overlay_sync(Overlay& o) {
    HWND g = find_game_window_();
    if (!g) return;
    o.game = g;
    RECT r; GetClientRect(g, &r);
    POINT tl = { 0, 0 };
    ClientToScreen(g, &tl);
    int w = r.right - r.left;
    int h = r.bottom - r.top;
    if (w <= 0 || h <= 0) return;
    SetWindowPos(o.hwnd, HWND_TOPMOST, tl.x, tl.y, w, h, SWP_NOACTIVATE);
    overlay_resize(o, w, h);
}

static __forceinline void overlay_begin(Overlay& o) {
    RECT r = { 0, 0, o.w, o.h };
    FillRect(o.mem, &r, (HBRUSH)GetStockObject(BLACK_BRUSH));
}

static __forceinline void overlay_end(Overlay& o) {
    HDC s = GetDC(o.hwnd);
    BitBlt(s, 0, 0, o.w, o.h, o.mem, 0, 0, SRCCOPY);
    ReleaseDC(o.hwnd, s);
}

static __forceinline void dr_line(Overlay& o, int x1, int y1, int x2, int y2, COLORREF c, int t) {
    HPEN p = CreatePen(PS_SOLID, t, c);
    HGDIOBJ old = SelectObject(o.mem, p);
    MoveToEx(o.mem, x1, y1, NULL);
    LineTo(o.mem, x2, y2);
    SelectObject(o.mem, old);
    DeleteObject(p);
}

static __forceinline void dr_rect(Overlay& o, int x, int y, int w, int h, COLORREF c, int t) {
    HPEN p = CreatePen(PS_SOLID, t, c);
    HGDIOBJ old = SelectObject(o.mem, p);
    HGDIOBJ oldB = SelectObject(o.mem, GetStockObject(NULL_BRUSH));
    Rectangle(o.mem, x, y, x + w, y + h);
    SelectObject(o.mem, old);
    SelectObject(o.mem, oldB);
    DeleteObject(p);
}

static __forceinline void dr_fill(Overlay& o, int x, int y, int w, int h, COLORREF c) {
    RECT r = { x, y, x + w, y + h };
    HBRUSH b = CreateSolidBrush(c);
    FillRect(o.mem, &r, b);
    DeleteObject(b);
}

static __forceinline void dr_text(Overlay& o, int x, int y, COLORREF c, const wchar_t* s) {
    SetTextColor(o.mem, c);
    TextOutW(o.mem, x, y, s, lstrlenW(s));
}

static __forceinline void overlay_set_clickable(Overlay& o, bool cl) {
    if (cl == o.clickable) return;
    o.clickable = cl;
    LONG ex = GetWindowLongW(o.hwnd, GWL_EXSTYLE);
    if (cl) ex &= ~WS_EX_TRANSPARENT;
    else    ex |=  WS_EX_TRANSPARENT;
    SetWindowLongW(o.hwnd, GWL_EXSTYLE, ex);
}

static __forceinline void overlay_destroy(Overlay& o) {
    if (o.bmp) DeleteObject(o.bmp);
    if (o.mem) DeleteDC(o.mem);
    if (o.font) DeleteObject(o.font);
    if (o.hwnd) DestroyWindow(o.hwnd);
    o.hwnd = 0; o.mem = 0; o.bmp = 0; o.font = 0; o.w = 0; o.h = 0;
}
