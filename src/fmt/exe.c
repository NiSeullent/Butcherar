/*
 * 고깃ZIP - helpers shared by the executable readers (PE/TE, ELF, Mach-O)
 */
#include "exe.h"

void gz_xn_str(gz_xname *w, const char *s)
{
    while (*s && w->n < GZ_XNAME_MAX) w->b[w->n++] = *s++;
}

void gz_xn_num(gz_xname *w, u64 v)
{
    char t[24];
    int k = 0;
    do { t[k++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (k && w->n < GZ_XNAME_MAX) w->b[w->n++] = t[--k];
}

/* append one code point as UTF-8 (all or nothing) */
static void xn_cp(gz_xname *w, u32 c)
{
    u8 t[4];
    u32 k;
    if (c < 0x80) { t[0] = (u8)c; k = 1; }
    else if (c < 0x800) { t[0] = (u8)(0xC0 | c >> 6); t[1] = (u8)(0x80 | (c & 63)); k = 2; }
    else if (c < 0x10000) {
        t[0] = (u8)(0xE0 | c >> 12); t[1] = (u8)(0x80 | ((c >> 6) & 63)); t[2] = (u8)(0x80 | (c & 63)); k = 3;
    } else {
        t[0] = (u8)(0xF0 | c >> 18); t[1] = (u8)(0x80 | ((c >> 12) & 63));
        t[2] = (u8)(0x80 | ((c >> 6) & 63)); t[3] = (u8)(0x80 | (c & 63)); k = 4;
    }
    if (w->n + k > GZ_XNAME_MAX) { w->n = GZ_XNAME_MAX; return; }
    for (u32 i = 0; i < k; i++) w->b[w->n++] = (char)t[i];
}

static u32 part_cp(u32 c) { return c == '/' || c == '\\' ? '_' : c; }

/* a part that is empty, "." or ".." would vanish from the decoded path */
static void part_fix(gz_xname *w, u32 start)
{
    u32 len = w->n - start;
    int dots = 1;
    for (u32 i = start; i < w->n; i++) if (w->b[i] != '.') dots = 0;
    if (len == 0 || (dots && len <= 2)) {
        w->n = start;
        gz_xn_str(w, len == 0 ? "_" : len == 1 ? "_." : "_..");
    }
}

void gz_xn_part8(gz_xname *w, const u8 *p, u32 n)
{
    u32 st = w->n;
    for (u32 i = 0; i < n && p[i]; i++) xn_cp(w, part_cp(p[i]));
    part_fix(w, st);
}

void gz_xn_part16(gz_xname *w, const u8 *le, u32 n)
{
    u32 st = w->n;
    for (u32 i = 0; i < n; i++) {
        u32 c = rd16(le + 2 * i);
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < n) {
            u32 d = rd16(le + 2 * i + 2);
            if (d >= 0xDC00 && d < 0xE000) { c = 0x10000 + ((c - 0xD800) << 10) + (d - 0xDC00); i++; }
            else c = 0xFFFD;
        } else if (c >= 0xD800 && c < 0xE000) {
            c = 0xFFFD;
        }
        if (!c) c = '_';
        xn_cp(w, part_cp(c));
    }
    part_fix(w, st);
}

void gz_xn_ext_if_none(gz_xname *w, const char *ext)
{
    for (u32 i = w->n; i-- > 0;) {
        if (w->b[i] == '/') break;
        if (w->b[i] == '.' && i + 1 < w->n) return;
    }
    gz_xn_str(w, ext);
}

int gz_exe_add(gz_archive *a, const gz_xname *w, gz_entry **pe)
{
    return gz_arc_add_named(a, w->b, w->n, GZ_NE_UTF8, pe);
}

const char *gz_exe_sniff(const u8 *p, u32 n)
{
    if (n < 4) return 0;
    u32 m = rd32(p);
    if (n >= 8 && m == 0x474E5089u && rd32(p + 4) == 0x0A1A0A0Du) return ".png";
    if (n >= 6 && m == 0x38464947u && (p[4] == '7' || p[4] == '9') && p[5] == 'a') return ".gif";
    if (p[0] == 0xFF && p[1] == 0xD8 && p[2] == 0xFF) return ".jpg";
    if (m == 0x04034B50u || m == 0x08074B50u) return ".zip";
    if (n >= 6 && m == 0xAFBC7A37u && p[4] == 0x27 && p[5] == 0x1C) return ".7z";
    if (n >= 7 && m == 0x21726152u && p[4] == 0x1A && p[5] == 0x07) return ".rar";
    if (n >= 8 && m == 0x4643534Du && rd32(p + 4) == 0) return ".cab";
    if (n >= 6 && m == 0x587A37FDu && p[4] == 0x5A && p[5] == 0) return ".xz";
    if (p[0] == 0x1F && p[1] == 0x8B && p[2] == 8) return ".gz";
    if (p[0] == 'B' && p[1] == 'Z' && p[2] == 'h' && p[3] >= '1' && p[3] <= '9') return ".bz2";
    if (m == 0xFD2FB528u) return ".zst";
    if (m == 0x46445025u) return ".pdf";
    if (m == 0x74725C7Bu) return ".rtf";                        /* "{\rt" */
    if (m == 0xE011CFD0u && n >= 8 && rd32(p + 4) == 0xE11AB1A1u) return ".msi";
    if (m == 0x5446534Du) return ".tlb";                        /* "MSFT" type library */
    if (n >= 12 && m == 0x46464952u) {                          /* RIFF */
        u32 f = rd32(p + 8);
        if (f == 0x204E4F43u || f == 0x4E4F4341u) return ".ani";   /* "CON " / "ACON" */
        if (f == 0x20495641u) return ".avi";
        if (f == 0x45564157u) return ".wav";
    }
    if (m == 0x00010000u && n >= 6 && rd16(p + 4) && rd16(p + 4) < 256) return ".ico";
    const u8 *x = p;
    u32 xn = n;
    if (n >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF) { x += 3; xn -= 3; }
    if (xn >= 5 && x[0] == '<' && x[1] == '?' && x[2] == 'x' && x[3] == 'm' && x[4] == 'l') return ".xml";
    if (n >= 64 && p[0] == 'M' && p[1] == 'Z') return ".exe";
    if (m == 0x464C457Fu) return ".elf";
    return 0;
}

int gz_exe_add_overlay(gz_archive *a, gz_src *s, u64 off, u64 len, const char *name)
{
    if (!len || off >= s->size || len > s->size - off) return GZ_OK;
    u8 h[64];
    u32 hn = len < sizeof h ? (u32)len : (u32)sizeof h;
    if (gz_src_read_exact(s, off, h, hn)) return GZ_OK;
    if (len < 8) {
        u32 z = 0;
        for (u32 i = 0; i < hn; i++) z |= h[i];
        if (!z) return GZ_OK;
    }
    gz_xname w;
    gz_xn_reset(&w);
    gz_xn_str(&w, name);
    const char *ext = gz_exe_sniff(h, hn);
    if (ext) gz_xn_str(&w, ext);
    gz_entry *e;
    int r = gz_exe_add(a, &w, &e);
    if (r) return r;
    e->off = off;
    e->usize = e->csize = len;
    return GZ_OK;
}

int gz_exe_extract_range(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    return gz_extract_stored(a, s, idx, a->e[idx].off, out, c);
}

gz_src *gz_exe_view_range(gz_archive *a, gz_src *s, u32 idx)
{
    const gz_entry *e = &a->e[idx];
    if (e->is_dir || e->off > s->size || e->usize > s->size - e->off) return 0;
    return gz_src_sub(s, e->off, e->usize);
}
