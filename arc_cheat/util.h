#pragma once
#include <windows.h>
#include <stdarg.h>
#include <intrin.h>
#include "config.h"

struct V3 { float x, y, z; };
struct V2 { float x, y; };

static __forceinline float fsqrtf_(float v) {
    return _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss(v)));
}
static __forceinline float fabsf_(float v) { return v < 0 ? -v : v; }

static __forceinline float fsin_(float x) {
    const float TAU = 6.28318531f;
    float k = x * (1.0f / TAU);
    int ki = (int)(k + (k < 0 ? -0.5f : 0.5f));
    x = x - (float)ki * TAU;
    float x2 = x * x;
    return x * (1.0f - x2 * (0.16666667f - x2 * (0.00833333f - x2 * 0.00019841270f)));
}
static __forceinline float fcos_(float x) { return fsin_(1.57079633f - x); }
static __forceinline float ftan_(float x) {
    float c = fcos_(x);
    return c == 0 ? 0.0f : fsin_(x) / c;
}
static __forceinline float deg2rad_(float d) { return d * 0.01745329252f; }

static __forceinline bool good_ptr_(const void* p, SIZE_T n) {
    uptr v = (uptr)p;
    if (v < 0x10000ULL) return false;
    if (v + n < v) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD ok = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ
             | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
    if (!(mbi.Protect & ok)) return false;
    uptr region_end = (uptr)mbi.BaseAddress + mbi.RegionSize;
    return (v + n) <= region_end;
}

template <class T>
static __forceinline bool kread(uptr addr, T& out) {
    if (!good_ptr_((void*)addr, sizeof(T))) return false;
    __movsb((BYTE*)&out, (const BYTE*)addr, sizeof(T));
    return true;
}
template <class T>
static __forceinline T kread_or(uptr addr, T def) {
    T v;
    return kread(addr, v) ? v : def;
}
static __forceinline uptr deref_(uptr base, u32 o) {
    if (base == 0 || o == 0) return 0;
    return kread_or<uptr>(base + o, 0);
}

static __forceinline uptr game_module() {
    return (uptr)GetModuleHandleW(NULL);
}

static __forceinline int fmt_a(char* buf, int cap, const char* f, ...) {
    va_list va; va_start(va, f);
    int n = wvsprintfA(buf, f, va);
    va_end(va);
    if (n < 0) n = 0;
    if (n >= cap) n = cap - 1;
    buf[n] = 0;
    return n;
}
static __forceinline int fmt_w(wchar_t* buf, int cap, const wchar_t* f, ...) {
    va_list va; va_start(va, f);
    int n = wvsprintfW(buf, f, va);
    va_end(va);
    if (n < 0) n = 0;
    if (n >= cap) n = cap - 1;
    buf[n] = 0;
    return n;
}

static __forceinline bool on_screen_(const V2& p, int w, int h) {
    return p.x >= 0 && p.y >= 0 && p.x < (float)w && p.y < (float)h;
}
