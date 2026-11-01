/*
 * 고깃ZIP - UTF-8 / UTF-16 / Hangul helpers and time conversion
 */
#include "arc.h"

size_t gz_wcslen(const gzch *s) { const gzch *p = s; while (*p) p++; return (size_t)(p - s); }

int gz_wcscmp(const gzch *a, const gzch *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (int)*a - (int)*b;
}

static gzch lower_ascii(gzch c) { return (c >= 'A' && c <= 'Z') ? (gzch)(c + 32) : c; }

int gz_wcsicmp_ascii(const gzch *a, const gzch *b)
{
    while (*a && lower_ascii(*a) == lower_ascii(*b)) { a++; b++; }
    return (int)lower_ascii(*a) - (int)lower_ascii(*b);
}

const gzch *gz_wcsrchr(const gzch *s, gzch c)
{
    const gzch *r = 0;
    for (; *s; s++) if (*s == c) r = s;
    return r;
}

gzch *gz_wcsdup(const gzch *s)
{
    size_t n = gz_wcslen(s);
    gzch *d = (gzch *)gz_alloc((n + 1) * sizeof(gzch));
    if (d) __builtin_memcpy(d, s, (n + 1) * sizeof(gzch));
    return d;
}

int gz_wcs_endswith(const gzch *s, const char *ext)
{
    size_t n = gz_wcslen(s), m = 0;
    while (ext[m]) m++;
    if (m > n) return 0;
    const gzch *t = s + n - m;
    for (size_t i = 0; i < m; i++) {
        gzch c = lower_ascii(t[i]);
        char e = ext[i];
        if (e >= 'A' && e <= 'Z') e = (char)(e + 32);
        if (c != (gzch)(u8)e) return 0;
    }
    return 1;
}

u64 gz_unix_to_filetime(i64 t)
{
    return (u64)(t * 10000000LL + 116444736000000000LL);
}

i64 gz_filetime_to_unix(u64 ft)
{
    return (i64)(ft / 10000000ULL) - 11644473600LL;
}

/* DOS date/time (local) to a FILETIME-like value treated as UTC (no time zone info). */
u64 gz_dos_to_filetime(u32 dos)
{
    u32 d = dos >> 16, t = dos & 0xffff;
    int y = 1980 + (int)(d >> 9), mo = (int)((d >> 5) & 15), da = (int)(d & 31);
    int h = (int)(t >> 11), mi = (int)((t >> 5) & 63), s = (int)((t & 31) * 2);
    if (mo < 1) mo = 1;
    if (mo > 12) mo = 12;
    if (da < 1) da = 1;
    /* days from civil (Howard Hinnant) */
    int yy = y - (mo <= 2);
    int era = yy / 400;
    int yoe = yy - era * 400;
    int doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + da - 1;
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    i64 days = (i64)era * 146097 + doe - 719468;
    return gz_unix_to_filetime(days * 86400 + h * 3600 + mi * 60 + s);
}

/* ---------------- UTF-8 / UTF-16 ---------------- */

int gz_utf8_valid(const u8 *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        u8 c = s[i];
        if (c < 0x80) { i++; continue; }
        u32 need, cp;
        if (c >= 0xC2 && c <= 0xDF) { need = 1; cp = c & 0x1f; }
        else if (c >= 0xE0 && c <= 0xEF) { need = 2; cp = c & 0x0f; }
        else if (c >= 0xF0 && c <= 0xF4) { need = 3; cp = c & 0x07; }
        else return 0;
        if (n - i <= need) return 0;               /* truncated sequence */
        for (u32 k = 1; k <= need; k++) {
            if ((s[i + k] & 0xC0) != 0x80) return 0;
            cp = (cp << 6) | (s[i + k] & 0x3f);
        }
        if ((need == 2 && cp < 0x800) || (need == 3 && (cp < 0x10000 || cp > 0x10FFFF))) return 0;
        if (cp >= 0xD800 && cp <= 0xDFFF) return 0;
        i += need + 1;
    }
    return 1;
}

int gz_utf8_to_utf16(const u8 *s, size_t n, gzch *out)
{
    int o = 0;
    size_t i = 0;
    while (i < n) {
        u32 c = s[i], cp, need, k;
        if (c < 0x80) { out[o++] = (gzch)c; i++; continue; }
        if (c >= 0xC0 && c <= 0xDF) { cp = c & 0x1f; need = 1; }
        else if (c >= 0xE0 && c <= 0xEF) { cp = c & 0x0f; need = 2; }
        else if (c >= 0xF0 && c <= 0xF7) { cp = c & 0x07; need = 3; }
        else { out[o++] = 0xFFFD; i++; continue; }
        if (n - i <= need) { out[o++] = 0xFFFD; i++; continue; }
        for (k = 1; k <= need; k++) {
            if ((s[i + k] & 0xC0) != 0x80) break;
            cp = (cp << 6) | (s[i + k] & 0x3f);
        }
        if (k <= need) { out[o++] = 0xFFFD; i++; continue; }
        i += need + 1;
        if (cp >= 0x110000) cp = 0xFFFD;
        if (cp >= 0x10000) {
            cp -= 0x10000;
            out[o++] = (gzch)(0xD800 + (cp >> 10));
            out[o++] = (gzch)(0xDC00 + (cp & 0x3ff));
        } else {
            out[o++] = (gzch)cp;
        }
    }
    return o;
}

int gz_utf16_to_utf8(const gzch *s, size_t n, u8 *out)
{
    int o = 0;
    for (size_t i = 0; i < n; i++) {
        u32 c = s[i];
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < n && s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000) {
            c = 0x10000 + ((c - 0xD800) << 10) + (s[i + 1] - 0xDC00);
            i++;
        } else if (c >= 0xD800 && c < 0xE000) {
            c = 0xFFFD;
        }
        if (c < 0x80) out[o++] = (u8)c;
        else if (c < 0x800) { out[o++] = (u8)(0xC0 | (c >> 6)); out[o++] = (u8)(0x80 | (c & 63)); }
        else if (c < 0x10000) {
            out[o++] = (u8)(0xE0 | (c >> 12)); out[o++] = (u8)(0x80 | ((c >> 6) & 63));
            out[o++] = (u8)(0x80 | (c & 63));
        } else {
            out[o++] = (u8)(0xF0 | (c >> 18)); out[o++] = (u8)(0x80 | ((c >> 12) & 63));
            out[o++] = (u8)(0x80 | ((c >> 6) & 63)); out[o++] = (u8)(0x80 | (c & 63));
        }
    }
    return o;
}

/* Compose conjoining Hangul jamo (as produced by macOS NFD) into syllables. */
int gz_hangul_compose(gzch *s, int n)
{
    int o = 0;
    for (int i = 0; i < n; i++) {
        u32 c = s[i];
        if (o > 0) {
            u32 prev = s[o - 1];
            /* L + V -> LV */
            if (prev >= 0x1100 && prev <= 0x1112 && c >= 0x1161 && c <= 0x1175) {
                s[o - 1] = (gzch)(0xAC00 + ((prev - 0x1100) * 21 + (c - 0x1161)) * 28);
                continue;
            }
            /* LV + T -> LVT */
            if (prev >= 0xAC00 && prev <= 0xD7A3 && ((prev - 0xAC00) % 28) == 0 &&
                c >= 0x11A8 && c <= 0x11C2) {
                s[o - 1] = (gzch)(prev + (c - 0x11A7));
                continue;
            }
        }
        s[o++] = (gzch)c;
    }
    return o;
}
