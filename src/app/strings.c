/*
 * 고깃ZIP - user interface strings (Korean / English) and number formatting
 * shared by the GTK and Cocoa front ends. No C library.
 */
#define GZ_UI_STRINGS_IMPL 1   /* found next to this file: no <strings.h> chaining */
#include "strings.h"
#include "engine.h"

#define GZ_UI_SX_KO(id, ko, en) ko,
#define GZ_UI_SX_EN(id, ko, en) en,
static const char *const s_ko[STR__COUNT] = { GZ_UI_STRINGS(GZ_UI_SX_KO) };
static const char *const s_en[STR__COUNT] = { GZ_UI_STRINGS(GZ_UI_SX_EN) };

static const char *const *s_tab = s_en;

void gz_ui_set_korean(int korean) { s_tab = korean ? s_ko : s_en; }
int gz_ui_korean(void) { return s_tab == s_ko; }

int gz_ui_locale_korean(const char *l)
{
    if (!l) return 0;
    return (l[0] | 32) == 'k' && (l[1] | 32) == 'o' && (l[2] == 0 || l[2] == '_' || l[2] == '-' || l[2] == '.' ||
                                                       l[2] == '@');
}

const char *gz_ui_str(int id)
{
    if (id < 0 || id >= STR__COUNT) return "";
    return s_tab[id];
}

/* length of s[0..n) without a UTF-8 sequence cut short at its end */
static uint32_t utf8_trim(const char *s, uint32_t n)
{
    uint32_t k = n;
    while (k && ((unsigned char)s[k - 1] & 0xC0) == 0x80 && n - k < 3) k--;    /* continuation bytes */
    if (!k) return n;
    unsigned char lead = (unsigned char)s[k - 1];
    uint32_t len = lead < 0x80 ? 1 : lead >= 0xF0 ? 4 : lead >= 0xE0 ? 3 : lead >= 0xC0 ? 2 : 1;
    return k - 1 + len > n ? k - 1 : n;
}

void gz_ui_plain(char *out, uint32_t cap, const char *s)
{
    if (!cap) return;
    uint32_t o = 0;
    for (uint32_t i = 0; s[i]; i++) {
        char c = s[i];
        if (c == '_') {
            if (s[i + 1] == '_') { i++; }                        /* "__" = literal '_' */
            else {
                /* "(_F)" after text: drop the whole group, else drop the marker only */
                if (o && out[o - 1] == '(' && s[i + 1] && s[i + 2] == ')') {
                    o--;
                    while (o && out[o - 1] == ' ') o--;
                    i += 2;
                }
                continue;
            }
        }
        if (o + 1 >= cap) break;
        out[o++] = c;
    }
    out[utf8_trim(out, o)] = 0;
}

uint32_t gz_ui_format(char *out, uint32_t cap, const char *tmpl, const char *const *args, uint32_t n)
{
    if (!cap) return 0;
    uint32_t o = 0, k = 0;
    int full = 0;
    for (const char *p = tmpl; *p && !full; p++) {
        if (p[0] == '%' && p[1] == 's') {
            const char *a = k < n && args[k] ? args[k] : "";
            k++;
            p++;
            for (; *a; a++) {
                if (o + 1 >= cap) { full = 1; break; }
                out[o++] = *a;
            }
            continue;
        }
        if (p[0] == '%' && p[1] == '%') p++;
        if (o + 1 >= cap) { full = 1; break; }
        out[o++] = *p;
    }
    if (full) o = utf8_trim(out, o);
    out[o] = 0;
    return o;
}

const char *gz_ui_code_text(int code)
{
    static const int e[GZ_E_COUNT] = {
        STR_E_OK, STR_E_IO, STR_E_FORMAT, STR_E_DATA, STR_E_CRC, STR_E_METHOD, STR_E_PASSWORD, STR_E_NOMEM,
        STR_E_CANCEL, STR_E_TRUNC, STR_E_SKIP, STR_E_CREATE, STR_E_AUTH, STR_E_DISK, STR_E_VOLUME, STR_E_LIMIT
    };
    static const int nt[GZ_N_LAST - GZ_N_FIRST] = {
        STR_N_RENAMED, STR_N_SHORTENED, STR_N_PATH_LONG, STR_N_LINK_ABS, STR_N_LINK_ESCAPE, STR_N_LINK_THROUGH,
        STR_N_LINK_SKIP, STR_N_LINK_FAILED, STR_N_LINK_TARGET, STR_N_SPECIAL, STR_N_LOOP, STR_N_NOT_FOUND,
        STR_N_UNREADABLE, STR_N_ONE_FILE, STR_N_EXISTS, STR_N_NO_WRITER, STR_N_NO_FILES
    };
    if (code >= 0 && code < GZ_E_COUNT) return gz_ui_str(e[code]);
    if (code >= GZ_N_FIRST && code < GZ_N_LAST) return gz_ui_str(nt[code - GZ_N_FIRST]);
    return gz_ui_str(STR_E_IO);
}

const gz_ui_cp gz_ui_codepages[] = {
    { 0, STR_CP_AUTO }, { 65001, STR_CP_UTF8 }, { 949, STR_CP_949 }, { 932, STR_CP_932 }, { 936, STR_CP_936 },
    { 950, STR_CP_950 }, { 1252, STR_CP_1252 }, { 1250, STR_CP_1250 }, { 1251, STR_CP_1251 },
    { 437, STR_CP_437 }, { 850, STR_CP_850 }, { 866, STR_CP_866 },
};
const uint32_t gz_ui_ncodepages = sizeof gz_ui_codepages / sizeof gz_ui_codepages[0];

const char *gz_ui_cp_name(int cp)
{
    for (uint32_t i = 0; i < gz_ui_ncodepages; i++)
        if (gz_ui_codepages[i].cp == cp) return gz_ui_str(gz_ui_codepages[i].sid);
    return 0;
}

const char *gz_ui_method_name(int m)
{
    static const char *const n[GZ_WM_COUNT] = { "", "Store", "Deflate", "Deflate64", "BZip2", "LZMA", "LZMA2",
                                                "PPMd", "Zstandard" };
    if (m == GZ_WM_DEFAULT) return gz_ui_str(STR_C_DEFAULT);
    return m > 0 && m < GZ_WM_COUNT ? n[m] : "";
}

const uint8_t gz_ui_levels[6] = { 0, 1, 3, 5, 7, 9 };

const char *gz_ui_level_name(int level)
{
    static const int id[10] = { STR_LV_0, STR_LV_1, STR_LV_1, STR_LV_3, STR_LV_3, STR_LV_5, STR_LV_5, STR_LV_7,
                                STR_LV_7, STR_LV_9 };
    if (level < 0) level = 0;
    if (level > 9) level = 9;
    return gz_ui_str(id[level]);
}

/* ---------------- numbers ---------------- */

static void put(char *o, uint32_t cap, const char *s)
{
    if (!cap) return;
    uint32_t i = 0;
    for (; s[i] && i + 1 < cap; i++) o[i] = s[i];
    o[i] = 0;
}

static void cat(char *o, uint32_t cap, const char *s)
{
    uint32_t n = 0;
    while (n < cap && o[n]) n++;
    if (n < cap) put(o + n, cap - n, s);
}

void gz_ui_fmt_u64(char *o, uint32_t cap, uint64_t v)
{
    char t[24];
    int n = 0;
    do { t[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    char r[24];
    for (int i = 0; i < n; i++) r[i] = t[n - 1 - i];
    r[n] = 0;
    put(o, cap, r);
}

void gz_ui_fmt_thousands(char *o, uint32_t cap, uint64_t v)
{
    char t[32];
    int n = 0, g = 0;
    do {
        if (g == 3) { t[n++] = ','; g = 0; }
        t[n++] = (char)('0' + v % 10);
        v /= 10;
        g++;
    } while (v);
    char r[32];
    for (int i = 0; i < n; i++) r[i] = t[n - 1 - i];
    r[n] = 0;
    put(o, cap, r);
}

void gz_ui_fmt_size(char *o, uint32_t cap, uint64_t v)
{
    static const char *const units[] = { " B", " KB", " MB", " GB", " TB", " PB", " EB" };
    char num[40];
    if (v < 1024) {
        gz_ui_fmt_u64(num, sizeof num, v);
        cat(num, sizeof num, units[0]);
        put(o, cap, num);
        return;
    }
    int u = 0;
    uint64_t div = 1;
    while (v / div >= 1024 && u < 6) { div <<= 10; u++; }
    /* value * 100 / div without overflow: whole part and remainder separately */
    uint64_t whole = v / div, rem = v % div;
    uint64_t x100 = whole * 100 + (uint64_t)(((rem >> 4) * 100 + ((div >> 4) >> 1)) / (div >> 4));
    char d[24];
    if (x100 >= 10000) {                                 /* 100 .. 1023: no decimals */
        gz_ui_fmt_u64(num, sizeof num, (x100 + 50) / 100);
    } else if (x100 >= 1000) {                           /* 10.0 .. 99.9 */
        uint64_t x10 = (x100 + 5) / 10;
        gz_ui_fmt_u64(num, sizeof num, x10 / 10);
        d[0] = '.'; d[1] = (char)('0' + x10 % 10); d[2] = 0;
        cat(num, sizeof num, d);
    } else {                                             /* 1.00 .. 9.99 */
        gz_ui_fmt_u64(num, sizeof num, x100 / 100);
        d[0] = '.'; d[1] = (char)('0' + (x100 / 10) % 10); d[2] = (char)('0' + x100 % 10); d[3] = 0;
        cat(num, sizeof num, d);
    }
    cat(num, sizeof num, units[u]);
    put(o, cap, num);
}

void gz_ui_fmt_kb(char *o, uint32_t cap, uint64_t v)
{
    char t[40];
    gz_ui_fmt_thousands(t, sizeof t, v / 1024 + (v % 1024 != 0));
    cat(t, sizeof t, " KB");
    put(o, cap, t);
}

void gz_ui_fmt_speed(char *o, uint32_t cap, uint64_t bps)
{
    char t[48];
    gz_ui_fmt_size(t, sizeof t, bps);
    cat(t, sizeof t, "/s");
    put(o, cap, t);
}

static void two(char *o, uint64_t v) { o[0] = (char)('0' + (v / 10) % 10); o[1] = (char)('0' + v % 10); o[2] = 0; }

void gz_ui_fmt_duration(char *o, uint32_t cap, uint64_t s)
{
    char t[48], d[4];
    t[0] = 0;
    if (s >= 3600) {
        gz_ui_fmt_u64(t, sizeof t, s / 3600);
        cat(t, sizeof t, ":");
    }
    two(d, (s / 60) % 60);
    cat(t, sizeof t, d);
    cat(t, sizeof t, ":");
    two(d, s % 60);
    cat(t, sizeof t, d);
    put(o, cap, t);
}

void gz_ui_fmt_percent(char *o, uint32_t cap, uint64_t part, uint64_t whole)
{
    if (!whole || part == ~(uint64_t)0 || whole == ~(uint64_t)0) { put(o, cap, ""); return; }
    /* part * 100 / whole without overflow for huge sizes */
    uint64_t p = part <= ~(uint64_t)0 / 100 ? part * 100 / whole : part / (whole / 100 ? whole / 100 : 1);
    if (p > 999) p = 999;
    char t[24];
    gz_ui_fmt_u64(t, sizeof t, p);
    cat(t, sizeof t, "%");
    put(o, cap, t);
}

void gz_ui_fmt_hex32(char *o, uint32_t cap, uint32_t v)
{
    char t[9];
    for (int i = 0; i < 8; i++) t[i] = "0123456789ABCDEF"[(v >> (28 - 4 * i)) & 15];
    t[8] = 0;
    put(o, cap, t);
}
