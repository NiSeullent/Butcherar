/*
 * 고깃ZIP - Microsoft Virtual Hard Disk (VHD, Virtual PC / Hyper-V)
 *
 *   fixed         raw data followed by a 512-byte footer ("conectix")
 *   dynamic       footer copy at 0, dynamic header ("cxsparse"), block
 *                 allocation table; every block = sector bitmap + data
 *   differencing  like dynamic; sectors whose bitmap bit is clear (and
 *                 unallocated blocks) come from the parent disk, which is
 *                 found through the parent locators / parent name and opened
 *                 with o->open_volume (GZ_E_METHOD when it cannot be opened)
 *
 * All fields are big-endian. Sectors are 512 bytes.
 */
#include "vdisk.h"

enum { VHD_FIXED = 2, VHD_DYNAMIC = 3, VHD_DIFF = 4 };

typedef struct vhd_img {
    u64 vsize;
    u32 type;
    u32 bshift;               /* log2 block size                         */
    u32 bmp_bytes;            /* sector bitmap size on disk (n * 512)     */
    u32 nbat;
    u32 *bat;                 /* first sector of each block, ~0 = none    */
    u32 ts;                   /* footer time stamp (s since 2000-01-01)   */
    u8 uid[16];
    struct vhd_img *parent;
    gz_src *parent_src;       /* owned by the archive (a->vols)           */
} vhd_img;

typedef struct {
    gz_vd_view v;
    u8 *bmp;                  /* bitmap of block bmp_blk                  */
    u64 bmp_blk;
} vhd_vw;

static void img_free(vhd_img *im)
{
    while (im) {
        vhd_img *p = im->parent;
        gz_free(im->bat);
        gz_free(im);
        im = p;
    }
}

/* ---------------- footer / header ---------------- */

static int checksum_ok(const u8 *p, u32 n, u32 at)
{
    u32 sum = 0;
    for (u32 i = 0; i < n; i++) if (i < at || i >= at + 4) sum += p[i];
    return ~sum == rd32be(p + at);
}

static int footer_ok(const u8 *f)
{
    return !__builtin_memcmp(f, "conectix", 8) && checksum_ok(f, 512, 64);
}

/* Footer at the end (512 or old 511 bytes), else the copy at offset 0 of a
 * dynamic disk. *data_end = where the footer starts (end of usable data). */
static int read_footer(gz_src *s, u8 *f, u64 *data_end)
{
    int seen = 0;
    if (s->size < 512) return GZ_E_FORMAT;
    if (!gz_src_read_exact(s, s->size - 512, f, 512)) {
        if (footer_ok(f)) { *data_end = s->size - 512; return GZ_OK; }
        seen |= !__builtin_memcmp(f, "conectix", 8);
    }
    f[511] = 0;
    if (!gz_src_read_exact(s, s->size - 511, f, 511)) {
        if (footer_ok(f)) { *data_end = s->size - 511; return GZ_OK; }
        seen |= !__builtin_memcmp(f, "conectix", 8);
    }
    if (!gz_src_read_exact(s, 0, f, 512)) {
        u32 t = rd32be(f + 60);
        if (footer_ok(f) && (t == VHD_DYNAMIC || t == VHD_DIFF)) { *data_end = s->size; return GZ_OK; }
        seen |= !__builtin_memcmp(f, "conectix", 8);
    }
    return seen ? GZ_E_CRC : GZ_E_FORMAT;
}

static int vhd_parse(gz_archive *a, gz_src *s, const gz_open_opts *o, u32 depth, vhd_img **out);

/* Find and open the parent of a differencing disk (h = dynamic header). */
static int open_parent(gz_archive *a, vhd_img *im, const u8 *h, gz_src *s, const gz_open_opts *o, u32 depth)
{
    if (depth + 1 >= GZ_VD_MAX_DEPTH) return GZ_E_LIMIT;
    if (!o || !o->open_volume) return GZ_E_METHOD;
    gzch name[512];
    u8 buf[1024];
    /* candidates: locators W2ru (relative), W2ku (absolute), MacX (file URL), then the parent's name */
    for (int k = 0; k <= 8; k++) {
        u32 n = 0;
        if (k < 8) {
            const u8 *l = h + 576 + 24 * k;
            u32 code = rd32be(l), len = rd32be(l + 8);
            u64 off = rd64be(l + 16);
            if (!len || len > sizeof buf || off > s->size || len > s->size - off) continue;
            if (code == 0x57327275u || code == 0x57326B75u) {           /* "W2ru" / "W2ku" */
                if (gz_src_read_exact(s, off, buf, len)) continue;
                for (; n < len / 2 && rd16(buf + 2 * n); n++) name[n] = rd16(buf + 2 * n);
            } else if (code == 0x4D616358u) {                           /* "MacX": file:// URL */
                if (gz_src_read_exact(s, off, buf, len)) continue;
                u32 i = 0;
                if (len > 7 && !__builtin_memcmp(buf, "file://", 7)) {
                    i = 7;
                    while (i < len && buf[i] != '/') i++;               /* skip the host */
                }
                for (; i < len && buf[i] && n < 512; i++) name[n++] = buf[i];
            } else {
                continue;
            }
        } else {
            for (; n < 256 && rd16be(h + 64 + 2 * n); n++) name[n] = rd16be(h + 64 + 2 * n);
        }
        if (!n) continue;
        gz_src *ps;
        int r = gz_vd_open_file16(a, o, name, n, &ps);
        if (r == GZ_E_CANCEL || r == GZ_E_NOMEM || r == GZ_E_LIMIT) return r;
        if (r) continue;
        vhd_img *p = 0;
        r = vhd_parse(a, ps, o, depth + 1, &p);
        if (r == GZ_E_CANCEL || r == GZ_E_NOMEM || r == GZ_E_LIMIT) return r;
        if (r) continue;
        if (__builtin_memcmp(p->uid, h + 40, 16)) { img_free(p); continue; }   /* not our parent */
        im->parent = p;
        im->parent_src = ps;
        return GZ_OK;
    }
    return GZ_E_METHOD;
}

static int vhd_parse(gz_archive *a, gz_src *s, const gz_open_opts *o, u32 depth, vhd_img **out)
{
    u8 f[512];
    u64 dend;
    *out = 0;
    int r = read_footer(s, f, &dend);
    if (r) return r;
    vhd_img *im = (vhd_img *)gz_alloc(sizeof(vhd_img));
    if (!im) return GZ_E_NOMEM;
    im->type = rd32be(f + 60);
    im->vsize = rd64be(f + 48);
    im->ts = rd32be(f + 24);
    __builtin_memcpy(im->uid, f + 68, 16);
    if (im->vsize > GZ_VD_MAX_SIZE) { r = GZ_E_LIMIT; goto fail; }
    if (im->type == VHD_FIXED) {
        if (im->vsize > dend) { r = GZ_E_FORMAT; goto fail; }
        *out = im;
        return GZ_OK;
    }
    if (im->type != VHD_DYNAMIC && im->type != VHD_DIFF) { r = GZ_E_FORMAT; goto fail; }
    {
        u8 h[1024];
        u64 ho = rd64be(f + 16);
        r = GZ_E_FORMAT;
        if (ho > s->size || s->size - ho < 1024) goto fail;
        if ((r = gz_src_read_exact(s, ho, h, 1024))) goto fail;
        if (__builtin_memcmp(h, "cxsparse", 8)) { r = GZ_E_FORMAT; goto fail; }
        if (!checksum_ok(h, 1024, 36)) { r = GZ_E_CRC; goto fail; }
        u64 bat_off = rd64be(h + 16);
        u32 maxe = rd32be(h + 28), bs = rd32be(h + 32);
        r = GZ_E_FORMAT;
        if (!gz_vd_pow2(bs) || bs < 512 || bs > (1u << 28)) goto fail;
        im->bshift = gz_vd_log2(bs);
        if (im->vsize > ((u64)maxe << im->bshift)) goto fail;
        u64 nbat = (im->vsize + bs - 1) >> im->bshift;
        if (nbat * 4 > GZ_VD_MAX_TABLE) { r = GZ_E_LIMIT; goto fail; }
        if (bat_off > s->size || nbat * 4 > s->size - bat_off) goto fail;
        im->nbat = (u32)nbat;
        im->bat = (u32 *)gz_alloc((size_t)nbat * 4 + 4);
        if (!im->bat) { r = GZ_E_NOMEM; goto fail; }
        if (nbat && (r = gz_src_read_exact(s, bat_off, im->bat, (u32)nbat * 4))) goto fail;
        for (u32 i = 0; i < im->nbat; i++) im->bat[i] = __builtin_bswap32(im->bat[i]);
        im->bmp_bytes = ((((bs >> 9) + 7) >> 3) + 511) & ~511u;
        if (im->type == VHD_DIFF && (r = open_parent(a, im, h, s, o, depth))) goto fail;
    }
    *out = im;
    return GZ_OK;
fail:
    img_free(im);
    return r;
}

/* ---------------- view ---------------- */

/* first sector >= i (< n) whose bitmap bit differs from set (MSB first) */
static u32 run_end(const u8 *b, u32 i, u32 n, int set)
{
    while (i < n && (i & 7)) {
        if (((b[i >> 3] >> (7 - (i & 7))) & 1) != set) return i;
        i++;
    }
    u64 w = set ? ~(u64)0 : 0;
    while (i + 64 <= n && rd64(b + (i >> 3)) == w) i += 64;
    while (i + 8 <= n && b[i >> 3] == (u8)w) i += 8;
    while (i < n && ((b[i >> 3] >> (7 - (i & 7))) & 1) == set) i++;
    return i;
}

static int vhd_map(gz_vd_view *gv, u64 off, gz_vd_ext *x)
{
    vhd_vw *v = (vhd_vw *)gv;
    const vhd_img *im = (const vhd_img *)gv->img;
    if (im->type == VHD_FIXED) {
        x->kind = GZ_VD_RAW;
        x->pos = off;
        x->len = im->vsize - off;
        return GZ_OK;
    }
    u32 bs = 1u << im->bshift;
    u64 blk = off >> im->bshift;
    u32 within = (u32)off & (bs - 1);
    int miss = im->type == VHD_DIFF ? GZ_VD_PARENT : GZ_VD_ZERO;
    x->len = bs - within;
    if (blk >= im->nbat || im->bat[blk] == 0xFFFFFFFFu) { x->kind = miss; return GZ_OK; }
    u64 base = (u64)im->bat[blk] << 9;
    if (v->bmp_blk != blk) {
        v->bmp_blk = ~(u64)0;
        if (base > gv->file->size || im->bmp_bytes > gv->file->size - base) return GZ_E_TRUNC;
        int r = gz_src_read_exact(gv->file, base, v->bmp, im->bmp_bytes);
        if (r) return r;
        v->bmp_blk = blk;
    }
    u32 sec = within >> 9;
    int set = (v->bmp[sec >> 3] >> (7 - (sec & 7))) & 1;
    u32 end = run_end(v->bmp, sec, bs >> 9, set);
    x->len = ((u64)end << 9) - within;
    if (set) {
        x->kind = GZ_VD_RAW;
        x->pos = base + im->bmp_bytes + within;
    } else {
        x->kind = miss;
    }
    return GZ_OK;
}

static void vhd_fini(gz_vd_view *gv) { gz_free(((vhd_vw *)gv)->bmp); }

static gz_src *view_new(const vhd_img *im, gz_src *file)
{
    vhd_vw *v = (vhd_vw *)gz_vd_view_new(sizeof(vhd_vw), file, im, im->vsize, vhd_map);
    if (!v) return 0;
    v->v.fini = vhd_fini;
    v->bmp_blk = ~(u64)0;
    if (im->type != VHD_FIXED && !(v->bmp = (u8 *)gz_alloc(im->bmp_bytes))) { gz_src_free(&v->v.s); return 0; }
    if (im->parent && !(v->v.parent = view_new(im->parent, im->parent_src))) { gz_src_free(&v->v.s); return 0; }
    return &v->v.s;
}

/* ---------------- format ---------------- */

static int vhd_probe(gz_src *s, const u8 *h, u32 n)
{
    if (n >= 512 && !__builtin_memcmp(h, "conectix", 8)) return 95;
    u8 f[512];
    if (s->size >= 1024 && !gz_src_read_exact(s, s->size - 512, f, 512) && footer_ok(f)) return 90;
    return 0;
}

static int vhd_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)c;
    vhd_img *im;
    int r = vhd_parse(a, s, o, 0, &im);
    if (r) return r;
    a->priv = im;
    gz_entry *e;
    if ((r = gz_vd_add_disk(a, o, im->vsize, s->size, &e))) return r;
    e->method = (u16)im->type;
    e->mtime = gz_unix_to_filetime(946684800 + (i64)im->ts);
    e->mtime_kind = GZ_MT_FILETIME;
    return GZ_OK;
}

static void vhd_close(gz_archive *a)
{
    img_free((vhd_img *)a->priv);
    a->priv = 0;
}

static gz_src *vhd_view(gz_archive *a, gz_src *s, u32 idx)
{
    (void)idx;
    return a->priv ? view_new((const vhd_img *)a->priv, s) : 0;
}

static void vhd_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    gz_vd_method_str(buf, cap, e->method == VHD_FIXED ? "Fixed" : e->method == VHD_DYNAMIC ? "Dynamic" : "Differencing");
}

GZ_FORMAT(gz_fmt_vhd)
const gz_format gz_fmt_vhd = {
    "VHD", "vhd", GZ_FMT_CONTAINER,
    vhd_probe, vhd_open, vhd_close, gz_vd_extract, 0, 0, vhd_method, vhd_view, 0
};
