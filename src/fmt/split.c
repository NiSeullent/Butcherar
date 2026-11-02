/*
 * 고깃ZIP - split files: name.ext.001, name.ext.002, ... (7-Zip -v, HJSplit,
 * split -d -a 3 --numeric-suffixes=1)
 *
 * The parts are joined into one entry ("name.ext") marked GZ_FMT_CONTAINER, so
 * the core opens the archive inside the joined data (7z, ZIP, RAR, ISO, ...)
 * and shows it as "7z (Split)". Nothing in the data identifies a split set: the
 * file name decides. open() only accepts the first part of a top-level archive
 * whose name ends with a number equal to 1 (".001") when the second part
 * exists, so the probe gives a low score for any data and lets every real
 * format try first. Data that clearly continues past the end of the part (a
 * CAB, ISO 9660 or tar header in a file that is too short for it) gets a high
 * score, otherwise such formats would open the first part alone. The same for
 * a tar or cpio file that lacks its end marker.
 *
 * Parts after the first must have the size of the first except the last one:
 * a shorter part ends the set without asking for one that does not exist.
 */
#include "arc.h"

#define SPLIT_MAX_PARTS 100000u

static int tar_cut(gz_src *s, const u8 *h, u32 n)
{
    /* ustar header at 0 but a size or an end that no whole tar file has */
    if (n < 512 || __builtin_memcmp(h + 257, "ustar", 5)) return 0;
    if (s->size < 1024 || (s->size & 511)) return 1;
    u8 t[512];
    if (gz_src_read_exact(s, s->size - 512, t, 512)) return 0;
    for (u32 i = 0; i < 512; i++) if (t[i]) return 1;
    return 0;
}

static int cpio_cut(gz_src *s, const u8 *h, u32 n)
{
    /* cpio header at 0 but no TRAILER!!! in the last KiB (GNU cpio pads to 512) */
    if (n < 6 || !((h[0] == 0xC7 && h[1] == 0x71) || (h[0] == 0x71 && h[1] == 0xC7) ||
                   (!__builtin_memcmp(h, "07070", 5) && (h[5] == '1' || h[5] == '2' || h[5] == '7'))))
        return 0;
    u8 t[1024];
    u32 k = s->size < sizeof t ? (u32)s->size : (u32)sizeof t;
    if (gz_src_read_exact(s, s->size - k, t, k)) return 0;
    for (u32 i = 0; i + 10 <= k; i++)
        if (t[i] == 'T' && !__builtin_memcmp(t + i, "TRAILER!!!", 10)) return 0;
    return 1;
}

static int split_probe(gz_src *s, const u8 *h, u32 n)
{
    /* CAB: cbCabinet beyond the end of this part */
    if (n >= 36 && !__builtin_memcmp(h, "MSCF", 4) && rd32(h + 8) > s->size) return 97;
    /* ISO 9660: volume space size beyond the end of this part */
    if (s->size > 0x8800) {
        u8 pvd[136];
        if (!gz_src_read_exact(s, 0x8000, pvd, sizeof pvd) && pvd[0] == 1 && !__builtin_memcmp(pvd + 1, "CD001", 5) &&
            (u64)rd32(pvd + 80) * rd16(pvd + 128) > s->size)
            return 97;
    }
    if (tar_cut(s, h, n) || cpio_cut(s, h, n)) return 97;
    return 30;
}

/* position of the numeric suffix if name ends with ".001" (3 to 5 digits) */
static size_t suffix_pos(const gzch *fn, size_t len)
{
    size_t d = len;
    while (d && fn[d - 1] >= '0' && fn[d - 1] <= '9') d--;
    size_t nd = len - d;
    if (nd < 3 || nd > 5 || d < 2 || fn[d - 1] != '.' || fn[len - 1] != '1') return 0;
    for (size_t i = d; i + 1 < len; i++) if (fn[i] != '0') return 0;
    if (fn[d - 2] == '/' || fn[d - 2] == '\\') return 0;
    return d;
}

static int split_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    if (a->parent || !o || !o->file_name || !o->open_volume || !s->size) return GZ_E_FORMAT;
    const gzch *fn = o->file_name;
    size_t len = gz_wcslen(fn), d = suffix_pos(fn, len);
    if (!d) return GZ_E_FORMAT;
    size_t width = len - d;
    gzch *nm = (gzch *)gz_alloc((d + 12) * sizeof(gzch));
    if (!nm) return GZ_E_NOMEM;
    __builtin_memcpy(nm, fn, d * sizeof(gzch));
    u64 total = s->size;
    int r = GZ_OK;
    u32 cap = 0;
    for (u32 k = 2; k <= SPLIT_MAX_PARTS; k++) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        char dig[12];
        u32 nd = 0;
        for (u32 v = k; v; v /= 10) dig[nd++] = (char)('0' + v % 10);
        while (nd < width) dig[nd++] = '0';
        for (u32 i = 0; i < nd; i++) nm[d + i] = (gzch)dig[nd - 1 - i];
        nm[d + nd] = 0;
        gz_src *v = 0;
        int vr = o->open_volume(o->user, nm, &v);
        if (vr || !v) break;                         /* missing (or refused): end of the set */
        if (!v->size) { gz_src_free(v); break; }
        if (a->nvols == cap) {
            u32 nc = cap ? cap * 2 : 16;
            gz_src **nv = (gz_src **)gz_realloc(a->vols, nc * sizeof(gz_src *));
            if (!nv) { gz_src_free(v); r = GZ_E_NOMEM; break; }
            a->vols = nv;
            cap = nc;
        }
        a->vols[a->nvols++] = v;
        total += v->size;
        if (v->size != s->size) break;              /* the last part */
    }
    gz_free(nm);
    if (r) return r;
    if (!a->nvols) return GZ_E_FORMAT;               /* a lone ".001" file */

    /* the joined entry: base name without the suffix */
    size_t b = d - 1;
    while (b && fn[b - 1] != '/' && fn[b - 1] != '\\') b--;
    size_t bl = d - 1 - b;
    u8 *u = (u8 *)gz_alloc(bl * 3 + 8);
    if (!u) return GZ_E_NOMEM;
    int un = gz_utf16_to_utf8(fn + b, bl, u);
    gz_entry *e;
    r = gz_arc_add_named(a, u, (u32)un, GZ_NE_UTF8, &e);
    gz_free(u);
    if (r) return r;
    e->usize = e->csize = total;
    e->attr = 0x20;
    e->aux32 = a->nvols + 1;
    return GZ_OK;
}

static gz_src *split_view(gz_archive *a, gz_src *s, u32 idx)
{
    (void)idx;
    u32 n = a->nvols + 1;
    gz_src **parts = (gz_src **)gz_alloc((size_t)n * sizeof(gz_src *));
    if (!parts) return 0;
    /* sub views: the joined source owns them, not the parts themselves */
    u32 k = 0;
    for (; k < n; k++) {
        gz_src *p = k ? a->vols[k - 1] : s;
        if (!(parts[k] = gz_src_sub(p, 0, p->size))) break;
    }
    gz_src *cat = k == n ? gz_src_concat(parts, n) : 0;
    if (!cat) for (u32 i = 0; i < k; i++) gz_src_free(parts[i]);
    gz_free(parts);
    return cat;
}

static int split_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    gz_src *v = split_view(a, s, idx);
    if (!v) return GZ_E_NOMEM;
    int r = out->open(out, idx);
    if (!r) {
        int st = gz_copy_range(v, 0, v->size, out, c, 0);
        int cr = out->close(out, idx, st);
        r = st ? st : cr;
    }
    gz_src_free(v);
    return r;
}

static void split_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    /* "Split:N" (number of parts) */
    char t[24] = "Split:";
    u32 k = 6, v = e->aux32, nd = 0;
    char dig[12];
    do { dig[nd++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (nd) t[k++] = dig[--nd];
    t[k] = 0;
    u32 i = 0;
    for (; t[i] && i + 1 < cap; i++) buf[i] = t[i];
    if (cap) buf[i] = 0;
}

GZ_FORMAT(gz_fmt_split)
const gz_format gz_fmt_split = {
    "Split", "001", GZ_FMT_CONTAINER, split_probe, split_open, 0, split_extract, 0, 0, split_method, split_view, 0
};
