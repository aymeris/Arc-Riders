#pragma once
#include "util.h"

struct Settings {
    bool esp_enable, esp_box, esp_name, esp_dist, esp_line;
    int  esp_max_dist;
    bool aim_enable, aim_target_head;
    int  aim_key;
    float aim_fov, aim_smooth;
    bool show_fps, show_watermark;
};

static __forceinline void settings_defaults(Settings& s) {
    s.esp_enable = true;
    s.esp_box = true;
    s.esp_name = true;
    s.esp_dist = true;
    s.esp_line = false;
    s.esp_max_dist = 500;
    s.aim_enable = false;
    s.aim_target_head = true;
    s.aim_key = 0x02;        // VK_RBUTTON
    s.aim_fov = 8.0f;
    s.aim_smooth = 4.0f;
    s.show_fps = true;
    s.show_watermark = true;
}

static __forceinline void save_settings(const Settings& s, const char* path) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    char buf[1024];
    int n = fmt_a(buf, (int)sizeof(buf),
        "{\n"
        " \"esp_enable\":%d,\n \"esp_box\":%d,\n \"esp_name\":%d,\n \"esp_dist\":%d,\n"
        " \"esp_line\":%d,\n \"esp_max_dist\":%d,\n"
        " \"aim_enable\":%d,\n \"aim_target_head\":%d,\n \"aim_key\":%d,\n"
        " \"aim_fov\":%d,\n \"aim_smooth\":%d,\n"
        " \"show_fps\":%d,\n \"show_watermark\":%d\n}\n",
        (int)s.esp_enable, (int)s.esp_box, (int)s.esp_name, (int)s.esp_dist,
        (int)s.esp_line, s.esp_max_dist,
        (int)s.aim_enable, (int)s.aim_target_head, s.aim_key,
        (int)(s.aim_fov * 100.0f), (int)(s.aim_smooth * 100.0f),
        (int)s.show_fps, (int)s.show_watermark);
    DWORD w = 0;
    WriteFile(h, buf, n, &w, NULL);
    CloseHandle(h);
}

static __forceinline bool str_eq_(const char* a, const char* b, int n) {
    for (int i = 0; i < n; ++i) if (a[i] != b[i]) return false;
    return true;
}

static __forceinline int cfg_find_int_(const char* buf, const char* key, int def) {
    int klen = 0;
    while (key[klen]) ++klen;
    const char* p = buf;
    while (*p) {
        if (*p == '"' && str_eq_(p + 1, key, klen) && p[1 + klen] == '"') {
            const char* r = p + 1 + klen + 1;
            while (*r && *r != ':') ++r;
            if (*r != ':') return def;
            ++r;
            while (*r == ' ' || *r == '\t') ++r;
            int sign = 1;
            if (*r == '-') { sign = -1; ++r; }
            int v = 0;
            while (*r >= '0' && *r <= '9') { v = v * 10 + (*r - '0'); ++r; }
            return sign * v;
        }
        ++p;
    }
    return def;
}

static __forceinline void load_settings(Settings& s, const char* path) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    char buf[2048]; DWORD r = 0;
    ReadFile(h, buf, (DWORD)sizeof(buf) - 1, &r, NULL);
    buf[r] = 0;
    CloseHandle(h);
    s.esp_enable     = cfg_find_int_(buf, "esp_enable",      (int)s.esp_enable) != 0;
    s.esp_box        = cfg_find_int_(buf, "esp_box",         (int)s.esp_box) != 0;
    s.esp_name       = cfg_find_int_(buf, "esp_name",        (int)s.esp_name) != 0;
    s.esp_dist       = cfg_find_int_(buf, "esp_dist",        (int)s.esp_dist) != 0;
    s.esp_line       = cfg_find_int_(buf, "esp_line",        (int)s.esp_line) != 0;
    s.esp_max_dist   = cfg_find_int_(buf, "esp_max_dist",    s.esp_max_dist);
    s.aim_enable     = cfg_find_int_(buf, "aim_enable",      (int)s.aim_enable) != 0;
    s.aim_target_head= cfg_find_int_(buf, "aim_target_head", (int)s.aim_target_head) != 0;
    s.aim_key        = cfg_find_int_(buf, "aim_key",         s.aim_key);
    s.aim_fov        = cfg_find_int_(buf, "aim_fov",         (int)(s.aim_fov * 100.0f)) / 100.0f;
    s.aim_smooth     = cfg_find_int_(buf, "aim_smooth",      (int)(s.aim_smooth * 100.0f)) / 100.0f;
    s.show_fps       = cfg_find_int_(buf, "show_fps",        (int)s.show_fps) != 0;
    s.show_watermark = cfg_find_int_(buf, "show_watermark",  (int)s.show_watermark) != 0;
}
