/*
 * 고깃ZIP - VMware virtual disks (VMDK)
 *
 *   hosted sparse extent  "KDMV" header, grain directory -> grain tables ->
 *                         grains (+ redundant directory)
 *   streamOptimized       same, grains Deflate-compressed (zlib) behind 12-byte
 *                         grain markers, directory in a footer at the end
 *   descriptor file       text "# Disk DescriptorFile" listing extents:
 *                         FLAT / VMFS (raw file + offset), SPARSE (KDMV file),
 *                         ZERO; extent files are opened with o->open_volume
 *                         (monolithicFlat, twoGbMaxExtentFlat/Sparse, vmfs ...)
 *
 * Delta disks (parentCID != ffffffff), ESX "COWD" sparse, SEsparse and raw
 * device mappings report GZ_E_METHOD. Little-endian, 512-byte sectors.
 */
#include "vdisk.h"

enum { EXT_ZERO = 0, EXT_FLAT, EXT_SPARSE };

#define KDMV 0x564D444Bu                /* "KDMV" */
#define GD_AT_END (~(u64)0)
#define MAX_EXTENTS 4096
#define MAX_DESC (1u << 20)
#define GT_SLOTS 16
#define DC_SLOTS 4                     /* decoded grains kept per view (small grains) */

typedef struct {
    u64 vstart, vlen;          /* virtual byte range                      */
    gz_src *src;               /* extent file, NULL = the image file      */
    int kind;
    u64 flat_off;              /* FLAT: byte offset in src                */
    u32 gshift;                /* SPARSE: log2 grain bytes                */
    u32 ngte;                  /* entries per grain table                 */
    u64 ngd;
    u32 *gd;                   /* sector of each grain table, 0 = none    */
    int compressed, markers;
} vmdk_ext;

typedef struct {
    u64 vsize;
    u32 next;
    vmdk_ext *ext;
    u32 max_ngte;              /* per-view cache sizes                    */
    u32 max_grain;             /* largest compressed grain (bytes)        */
    char kind[32];             /* createType for the method column        */
} vmdk_img;

typedef struct {
    gz_vd_view v;
    u32 *gt;                   /* GT_SLOTS grain tables                   */
    u64 gt_key[GT_SLOTS];      /* (extent << 48 | table) + 1, 0 = empty   */
    u8 *grain;                 /* dc_slots decoded grains (stride max_grain) */
    u64 grain_key[DC_SLOTS];   /* (extent << 48 | grain) + 1, 0 = empty   */
    u32 dc_slots;
} vmdk_vw;

static void img_free(vmdk_img *im)
{
    if (!im) return;
    for (u32 i = 0; i < im->next; i++) gz_free(im->ext[i].gd);
    gz_free(im->ext);
    gz_free(im);
}

static int add_ext(vmdk_img *im, vmdk_ext **pe)
{
    if (im->next >= MAX_EXTENTS) return GZ_E_LIMIT;
    if ((im->next & 15) == 0) {
        vmdk_ext *n = (vmdk_ext *)gz_realloc(im->ext, ((size_t)im->next + 16) * sizeof(vmdk_ext));
        if (!n) return GZ_E_NOMEM;
        im->ext = n;
    }
    vmdk_ext *e = &im->ext[im->next++];
    __builtin_memset(e, 0, sizeof *e);
    e->vstart = im->vsize;
    *pe = e;
    return GZ_OK;
}

/* ---------------- sparse extents ---------------- */

/* Read the sparse header (the footer copy for streamOptimized). */
static int sparse_header(gz_src *f, u8 *h)
{
    if (f->size < 512) return GZ_E_FORMAT;
    int r = gz_src_read_exact(f, 0, h, 512);
    if (r) return r;
    if (rd32(h) != KDMV) return GZ_E_FORMAT;
    if (rd64(h + 56) == GD_AT_END) {
        u8 *m = (u8 *)gz_alloc(1536);
        if (!m) return GZ_E_NOMEM;
        r = f->size >= 2048 ? gz_src_read_exact(f, f->size - 1536, m, 1536) : GZ_E_FORMAT;
        if (!r && (rd32(m + 8) != 0 || rd32(m + 12) != 3 || rd32(m + 512) != KDMV ||
                   rd64(m + 1024) != 0 || rd32(m + 1032) != 0 || rd32(m + 1036) != 0 ||
                   rd64(m + 512 + 56) == GD_AT_END))
            r = GZ_E_FORMAT;
        if (!r) __builtin_memcpy(h, m + 512, 512);
        gz_free(m);
    }
    return r;
}

/* invalid grain directory entries (pointing outside the file) */
static u64 gd_bad(const u32 *gd, u64 n, u32 ngte, u64 fsize)
{
    u64 bad = 0;
    for (u64 i = 0; i < n; i++)
        if (gd[i] && ((u64)gd[i] << 9) + (u64)ngte * 4 > fsize) bad++;
    return bad;
}

static int load_gd(gz_src *f, u64 sec, u64 n, u32 **out)
{
    *out = 0;
    if (!sec || sec > (f->size >> 9) || n * 4 > f->size - (sec << 9)) return GZ_E_FORMAT;
    u32 *gd = (u32 *)gz_alloc((size_t)n * 4 + 4);
    if (!gd) return GZ_E_NOMEM;
    int r = gz_src_read_exact(f, sec << 9, gd, (u32)(n * 4));
    if (r) { gz_free(gd); return r; }
    *out = gd;
    return GZ_OK;
}

/* Parse a KDMV extent: fills the sparse fields of e. *cap = capacity in bytes,
 * *desc / *dlen = embedded descriptor sector range (0 if none). */
static int sparse_open(vmdk_ext *e, gz_src *f, u64 *cap, u64 *dsec, u64 *dlen)
{
    u8 h[512];
    int r = sparse_header(f, h);
    if (r) return r;
    u32 ver = rd32(h + 4), flags = rd32(h + 8);
    u64 capacity = rd64(h + 12), grain = rd64(h + 20);
    u32 ngte = rd32(h + 44);
    if (ver < 1 || ver > 3) return GZ_E_METHOD;
    if ((flags & 1) && (h[73] != '\n' || h[74] != ' ' || h[75] != '\r' || h[76] != '\n'))
        return GZ_E_FORMAT;                                 /* text-mode transfer damage */
    e->compressed = (flags >> 16) & 1;
    e->markers = (flags >> 17) & 1;
    if (e->compressed && rd16(h + 77) != 1) return GZ_E_METHOD;
    if (!gz_vd_pow2(grain) || grain > (e->compressed ? (1u << 14) : (1u << 16))) return GZ_E_FORMAT;
    if (!ngte || ngte > 4096 || capacity > (GZ_VD_MAX_SIZE >> 9)) return GZ_E_FORMAT;
    e->gshift = 9 + gz_vd_log2(grain);
    e->ngte = ngte;
    u64 span = grain * ngte;                                /* sectors per grain table */
    e->ngd = (capacity + span - 1) / span;
    if (e->ngd * 4 > GZ_VD_MAX_TABLE) return GZ_E_LIMIT;
    *cap = capacity << 9;
    *dsec = rd64(h + 28);
    *dlen = rd64(h + 36);
    if (!e->ngd) return GZ_OK;
    /* primary directory; the redundant one when the primary is damaged */
    u64 gdo = rd64(h + 56), rgdo = (flags & 2) ? rd64(h + 48) : 0;
    u32 *gd = 0, *rgd = 0;
    r = load_gd(f, gdo, e->ngd, &gd);
    if (r == GZ_E_NOMEM) return r;
    u64 bad = gd ? gd_bad(gd, e->ngd, ngte, f->size) : ~(u64)0;
    if (bad && rgdo && load_gd(f, rgdo, e->ngd, &rgd) == GZ_OK) {
        if (gd_bad(rgd, e->ngd, ngte, f->size) < bad) { gz_free(gd); gd = rgd; }
        else gz_free(rgd);
    }
    if (!gd) return r ? r : GZ_E_FORMAT;
    e->gd = gd;
    return GZ_OK;
}

/* ---------------- descriptor ---------------- */

static int is_sp(u8 c) { return c == ' ' || c == '\t' || c == '\r'; }

static int word_is(const u8 *p, u32 n, const char *w)
{
    u32 k = 0;
    while (w[k]) { if (k >= n || p[k] != (u8)w[k]) return 0; k++; }
    return k == n;
}

static int parse_u64(const u8 *p, u32 n, u64 *v)
{
    u64 x = 0;
    if (!n) return 0;
    for (u32 i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9' || x > ((u64)1 << 58)) return 0;
        x = x * 10 + (p[i] - '0');
    }
    *v = x;
    return 1;
}

/* value of key="..." / key=... on a line (quotes stripped) */
static int key_value(const u8 *l, u32 n, const char *key, const u8 **v, u32 *vn)
{
    u32 k = 0;
    while (key[k]) { if (k >= n || l[k] != (u8)key[k]) return 0; k++; }
    while (k < n && is_sp(l[k])) k++;
    if (k >= n || l[k] != '=') return 0;
    k++;
    while (k < n && is_sp(l[k])) k++;
    u32 e = n;
    while (e > k && is_sp(l[e - 1])) e--;
    if (e - k >= 2 && l[k] == '"' && l[e - 1] == '"') { k++; e--; }
    *v = l + k;
    *vn = e - k;
    return 1;
}

/* Walk descriptor lines. extents == 0: only check the header keys (embedded
 * descriptor of a sparse file). */
static int parse_descriptor(gz_archive *a, const gz_open_opts *o, vmdk_img *im, const u8 *d, u32 n, int extents)
{
    u32 i = 0;
    int r = GZ_OK;
    while (i < n && !r) {
        u32 s = i;
        while (i < n && d[i] != '\n' && d[i]) i++;
        u32 e = i;
        if (i < n && d[i] == 0) n = i;                       /* text ends at NUL */
        i++;
        while (s < e && is_sp(d[s])) s++;
        while (e > s && is_sp(d[e - 1])) e--;
        const u8 *l = d + s;
        u32 ln = e - s;
        if (!ln || l[0] == '#') continue;
        const u8 *v;
        u32 vn;
        if (key_value(l, ln, "parentCID", &v, &vn)) {
            if (!word_is(v, vn, "ffffffff")) return GZ_E_METHOD;      /* delta disk */
            continue;
        }
        if (key_value(l, ln, "createType", &v, &vn)) {
            u32 k = 0;
            for (; k < vn && k + 1 < sizeof im->kind; k++) im->kind[k] = (char)(v[k] >= 0x20 && v[k] < 0x7F ? v[k] : '_');
            im->kind[k] = 0;
            if (word_is(v, vn, "fullDevice") || word_is(v, vn, "partitionedDevice") ||
                word_is(v, vn, "vmfsRaw") || word_is(v, vn, "vmfsRawDeviceMap") ||
                word_is(v, vn, "vmfsPassthroughRawDeviceMap"))
                return GZ_E_METHOD;
            continue;
        }
        if (!extents) continue;
        /* extent: ACCESS SECTORS TYPE ["file" [OFFSET]] */
        u32 p = 0, t0, t1;
        t0 = p; while (p < ln && !is_sp(l[p])) p++; t1 = p;
        if (!word_is(l + t0, t1 - t0, "RW") && !word_is(l + t0, t1 - t0, "RDONLY") && !word_is(l + t0, t1 - t0, "NOACCESS"))
            continue;
        int noaccess = word_is(l + t0, t1 - t0, "NOACCESS");
        while (p < ln && is_sp(l[p])) p++;
        t0 = p; while (p < ln && !is_sp(l[p])) p++;
        u64 sectors;
        if (!parse_u64(l + t0, p - t0, &sectors)) return GZ_E_FORMAT;
        while (p < ln && is_sp(l[p])) p++;
        t0 = p; while (p < ln && !is_sp(l[p])) p++; t1 = p;
        const u8 *ty = l + t0;
        u32 tn = t1 - t0;
        while (p < ln && is_sp(l[p])) p++;
        const u8 *fname = 0;
        u32 fnl = 0;
        u64 foff = 0;
        if (p < ln && l[p] == '"') {
            u32 q = ++p;
            while (p < ln && l[p] != '"') p++;
            if (p >= ln) return GZ_E_FORMAT;
            fname = l + q;
            fnl = p - q;
            p++;
            while (p < ln && is_sp(l[p])) p++;
            t0 = p; while (p < ln && !is_sp(l[p])) p++;
            if (p > t0 && !parse_u64(l + t0, p - t0, &foff)) return GZ_E_FORMAT;
        }
        if (sectors > (GZ_VD_MAX_SIZE >> 9) || im->vsize + (sectors << 9) > GZ_VD_MAX_SIZE) return GZ_E_LIMIT;
        if (!sectors) continue;
        vmdk_ext *x;
        if ((r = add_ext(im, &x))) return r;
        x->vlen = sectors << 9;
        im->vsize += x->vlen;
        if (word_is(ty, tn, "ZERO") || noaccess) { x->kind = EXT_ZERO; continue; }
        int flat = word_is(ty, tn, "FLAT") || word_is(ty, tn, "VMFS");
        if (!flat && !word_is(ty, tn, "SPARSE")) return GZ_E_METHOD;   /* VMFSSPARSE, SESPARSE, RDM ... */
        if (!fname || !fnl) return GZ_E_FORMAT;
        if ((r = gz_vd_open_file(a, o, fname, fnl, &x->src))) return r;
        if (flat) {
            if (foff > (GZ_VD_MAX_SIZE >> 9)) return GZ_E_FORMAT;
            x->kind = EXT_FLAT;
            x->flat_off = foff << 9;
        } else {
            u64 cap, ds, dl;
            x->kind = EXT_SPARSE;
            if ((r = sparse_open(x, x->src, &cap, &ds, &dl))) return r;
        }
    }
    return r;
}

static int read_text(gz_src *s, u64 off, u64 len, u8 **out, u32 *n)
{
    *out = 0;
    if (len > MAX_DESC) len = MAX_DESC;
    if (off > s->size) return GZ_E_FORMAT;
    if (len > s->size - off) len = s->size - off;
    u8 *d = (u8 *)gz_alloc((size_t)len + 1);
    if (!d) return GZ_E_NOMEM;
    int r = len ? gz_src_read_exact(s, off, d, (u32)len) : GZ_OK;
    if (r) { gz_free(d); return r; }
    *out = d;
    *n = (u32)len;
    return GZ_OK;
}

static int vmdk_parse(gz_archive *a, gz_src *s, const gz_open_opts *o, vmdk_img *im)
{
    u8 m[4];
    int r = gz_src_read_exact(s, 0, m, 4);
    if (r) return r;
    if (rd32(m) == KDMV) {
        vmdk_ext *x;
        if ((r = add_ext(im, &x))) return r;
        u64 cap, ds, dl;
        x->kind = EXT_SPARSE;
        if ((r = sparse_open(x, s, &cap, &ds, &dl))) return r;
        x->vlen = cap;
        im->vsize = cap;
        gz_vd_method_str(im->kind, sizeof im->kind, x->compressed ? "streamOptimized" : "monolithicSparse");
        if (ds && dl && ds <= (s->size >> 9)) {
            u8 *d;
            u32 n;
            if ((r = read_text(s, ds << 9, dl << 9, &d, &n))) return r;
            r = parse_descriptor(a, o, im, d, n, 0);
            gz_free(d);
            if (r) return r;
            if (x->compressed) gz_vd_method_str(im->kind, sizeof im->kind, "streamOptimized");
        }
        return GZ_OK;
    }
    if (rd32(m) == 0x44574F43u) return GZ_E_METHOD;              /* "COWD": ESX sparse */
    u8 *d;
    u32 n;
    if (s->size > MAX_DESC) return GZ_E_FORMAT;
    if ((r = read_text(s, 0, s->size, &d, &n))) return r;
    gz_vd_method_str(im->kind, sizeof im->kind, "Descriptor");
    r = parse_descriptor(a, o, im, d, n, 1);
    gz_free(d);
    if (!r && !im->next) r = GZ_E_FORMAT;
    return r;
}

/* ---------------- view ---------------- */

static int load_gt(vmdk_vw *v, u32 ei, const vmdk_ext *e, u64 gti, const u32 **out)
{
    const vmdk_img *im = (const vmdk_img *)v->v.img;
    u32 slot = (u32)((gti ^ ((u64)ei * 0x9E37u)) & (GT_SLOTS - 1));
    u64 key = (((u64)ei << 48) | gti) + 1;
    u32 *gt = v->gt + (size_t)slot * im->max_ngte;
    if (v->gt_key[slot] != key) {
        gz_src *f = e->src ? e->src : v->v.file;
        u64 pos = (u64)e->gd[gti] << 9;
        v->gt_key[slot] = 0;
        if (pos + (u64)e->ngte * 4 > f->size) return GZ_E_TRUNC;
        int r = gz_src_read_exact(f, pos, gt, e->ngte * 4);
        if (r) return r;
        v->gt_key[slot] = key;
    }
    *out = gt;
    return GZ_OK;
}

static int read_grain(vmdk_vw *v, u32 ei, const vmdk_ext *e, u64 g, u32 gte, const u8 **out)
{
    const vmdk_img *im = (const vmdk_img *)v->v.img;
    u64 key = (((u64)ei << 48) | g) + 1;
    u32 slot = (u32)(g & (v->dc_slots - 1));
    u8 *buf = v->grain + (size_t)slot * im->max_grain;
    *out = buf;
    if (v->grain_key[slot] == key) return GZ_OK;
    v->grain_key[slot] = 0;
    gz_src *f = e->src ? e->src : v->v.file;
    u32 gb = 1u << e->gshift;
    u64 pos = (u64)gte << 9, len;
    if (pos >= f->size) return GZ_E_TRUNC;
    if (e->markers) {
        u8 mk[12];
        int r = gz_src_read_exact(f, pos, mk, 12);
        if (r) return r;
        len = rd32(mk + 8);
        pos += 12;
        if (!len || len > 2 * (u64)gb + 4096) return GZ_E_DATA;
    } else {
        len = 2 * (u64)gb + 4096;
        if (len > f->size - pos) len = f->size - pos;
    }
    u32 got;
    int r = gz_vd_inflate(&v->v, f, pos, len, 1, buf, gb, &got);
    if (r) return r;
    if (got < gb) __builtin_memset(buf + got, 0, gb - got);
    v->grain_key[slot] = key;
    return GZ_OK;
}

static int vmdk_map(gz_vd_view *gv, u64 off, gz_vd_ext *x)
{
    vmdk_vw *v = (vmdk_vw *)gv;
    const vmdk_img *im = (const vmdk_img *)gv->img;
    u32 lo = 0, hi = im->next;
    while (hi - lo > 1) {
        u32 mid = (lo + hi) / 2;
        if (im->ext[mid].vstart <= off) lo = mid; else hi = mid;
    }
    const vmdk_ext *e = &im->ext[lo];
    u64 rel = off - e->vstart, rest = e->vlen - rel;
    x->len = rest;
    if (e->kind == EXT_ZERO) { x->kind = GZ_VD_ZERO; return GZ_OK; }
    if (e->kind == EXT_FLAT) {
        x->kind = GZ_VD_RAW;
        x->src = e->src;
        x->pos = e->flat_off + rel;
        return GZ_OK;
    }
    u64 gb = (u64)1 << e->gshift, g = rel >> e->gshift, within = rel & (gb - 1);
    u64 gti = g / e->ngte;
    x->kind = GZ_VD_ZERO;
    if (gti >= e->ngd) return GZ_OK;
    if (!e->gd[gti]) {                                    /* whole grain table missing */
        u64 end = ((gti + 1) * e->ngte) << e->gshift;
        if (end - rel < rest) x->len = end - rel;
        return GZ_OK;
    }
    if (gb - within < rest) x->len = gb - within;
    const u32 *gt;
    int r = load_gt(v, lo, e, gti, &gt);
    if (r) return r;
    u32 gte = gt[g % e->ngte];
    if (gte <= 1) return GZ_OK;                           /* 0 unallocated, 1 zeroed grain */
    if (e->compressed) {
        const u8 *gr;
        if ((r = read_grain(v, lo, e, g, gte, &gr))) return r;
        x->kind = GZ_VD_MEM;
        x->mem = gr + within;
        return GZ_OK;
    }
    x->kind = GZ_VD_RAW;
    x->src = e->src;
    x->pos = ((u64)gte << 9) + within;
    return GZ_OK;
}

static void vmdk_fini(gz_vd_view *gv)
{
    vmdk_vw *v = (vmdk_vw *)gv;
    gz_free(v->gt);
    gz_free(v->grain);
}

/* ---------------- format ---------------- */

static int vmdk_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n >= 4 && rd32(h) == KDMV) return 95;
    static const char sig[] = "# Disk DescriptorFile";
    u32 k = 0;
    if (n >= 3 && h[0] == 0xEF && h[1] == 0xBB && h[2] == 0xBF) k = 3;     /* UTF-8 BOM */
    if (n >= k + sizeof sig - 1 && !__builtin_memcmp(h + k, sig, sizeof sig - 1)) return 90;
    return 0;
}

static int vmdk_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)c;
    vmdk_img *im = (vmdk_img *)gz_alloc(sizeof(vmdk_img));
    if (!im) return GZ_E_NOMEM;
    a->priv = im;
    int r = vmdk_parse(a, s, o, im);
    if (r) return r;
    for (u32 i = 0; i < im->next; i++) {
        const vmdk_ext *e = &im->ext[i];
        if (e->kind != EXT_SPARSE) continue;
        if (e->ngte > im->max_ngte) im->max_ngte = e->ngte;
        if (e->compressed && (1u << e->gshift) > im->max_grain) im->max_grain = 1u << e->gshift;
    }
    u64 csize = s->size;                                  /* descriptor + extent files */
    for (u32 i = 0; i < a->nvols; i++) csize += a->vols[i]->size;
    return gz_vd_add_disk(a, o, im->vsize, csize, 0);
}

static void vmdk_close(gz_archive *a)
{
    img_free((vmdk_img *)a->priv);
    a->priv = 0;
}

static gz_src *vmdk_view(gz_archive *a, gz_src *s, u32 idx)
{
    (void)idx;
    const vmdk_img *im = (const vmdk_img *)a->priv;
    vmdk_vw *v = (vmdk_vw *)gz_vd_view_new(sizeof(vmdk_vw), s, im, im->vsize, vmdk_map);
    if (!v) return 0;
    v->v.fini = vmdk_fini;
    v->dc_slots = im->max_grain <= (256u << 10) ? DC_SLOTS : 1;
    if ((im->max_ngte && !(v->gt = (u32 *)gz_alloc((size_t)GT_SLOTS * im->max_ngte * 4))) ||
        (im->max_grain && !(v->grain = (u8 *)gz_alloc((size_t)v->dc_slots * im->max_grain)))) {
        gz_src_free(&v->v.s);
        return 0;
    }
    return &v->v.s;
}

static void vmdk_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)e;
    const vmdk_img *im = (const vmdk_img *)a->priv;
    gz_vd_method_str(buf, cap, im && im->kind[0] ? im->kind : "VMDK");
}

GZ_FORMAT(gz_fmt_vmdk)
const gz_format gz_fmt_vmdk = {
    "VMDK", "vmdk", GZ_FMT_CONTAINER,
    vmdk_probe, vmdk_open, vmdk_close, gz_vd_extract, 0, 0, vmdk_method, vmdk_view, 0
};
