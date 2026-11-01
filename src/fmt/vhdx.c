/*
 * 고깃ZIP - Hyper-V Virtual Hard Disk v2 (VHDX)
 *
 *   0       file identifier "vhdxfile"
 *   64K     header 1, 128K header 2 ("head", CRC-32C, sequence number, log)
 *   192K    region table 1, 256K region table 2 ("regi": BAT, metadata)
 *   metadata: block size, virtual size, logical sector size, parent flag
 *   BAT: 64-bit entries (state + offset in MiB); every chunk_ratio payload
 *   entries are followed by one sector-bitmap entry
 *
 * Differencing disks (HasParent) report GZ_E_METHOD. A log that was not
 * replayed is ignored (the data is read as it is) and noted in the comment.
 * Little-endian throughout.
 */
#include "vdisk.h"

typedef struct {
    u64 vsize;
    u64 nbat;
    u64 *bat;
    u32 bshift;               /* log2 block size         */
    u32 chunk;                /* payload blocks per chunk */
    int fixed;                /* LeaveBlocksAllocated     */
} vhdx_img;

#define MiB (1u << 20)
#define KiB (1u << 10)

/* ---------------- CRC-32C (Castagnoli), nibble table: only headers use it ---------------- */

static const u32 k_c32c[16] = {
    0x00000000, 0x105EC76F, 0x20BD8EDE, 0x30E349B1, 0x417B1DBC, 0x5125DAD3, 0x61C69362, 0x7198540D,
    0x82F63B78, 0x92A8FC17, 0xA24BB5A6, 0xB21572C9, 0xC38D26C4, 0xD3D3E1AB, 0xE330A81A, 0xF36E6F75
};

static u32 c32c_upd(u32 c, const u8 *p, size_t n)
{
    while (n--) {
        c ^= *p++;
        c = (c >> 4) ^ k_c32c[c & 15];
        c = (c >> 4) ^ k_c32c[c & 15];
    }
    return c;
}

/* CRC-32C of a structure whose checksum field (at offset 4) counts as zero */
static int c32c_ok(const u8 *p, size_t n)
{
    static const u8 z[4];
    u32 c = c32c_upd(~0u, p, 4);
    c = c32c_upd(c, z, 4);
    c = c32c_upd(c, p + 8, n - 8);
    return ~c == rd32(p + 4);
}

static int guid_is(const u8 *g, u32 d1, u16 d2, u16 d3, u64 d4)
{
    return rd32(g) == d1 && rd16(g + 4) == d2 && rd16(g + 6) == d3 && rd64be(g + 8) == d4;
}

#define G_BAT(g)    guid_is(g, 0x2DC27766, 0xF623, 0x4200, 0x9D64115E9BFD4A08ull)
#define G_META(g)   guid_is(g, 0x8B7CA206, 0x4790, 0x4B9A, 0xB8FE575F050F886Eull)
#define G_FPARAM(g) guid_is(g, 0xCAA16737, 0xFA36, 0x4D43, 0xB3B633F0AA44E76Bull)
#define G_VSIZE(g)  guid_is(g, 0x2FA54224, 0xCD1B, 0x4876, 0xB2115DBED83BF4B8ull)
#define G_VDID(g)   guid_is(g, 0xBECA12AB, 0xB2E6, 0x4523, 0x93EFC309E000C746ull)
#define G_LSS(g)    guid_is(g, 0x8141BF1D, 0xA96F, 0x4709, 0xBA47F233A8FAAB5Full)
#define G_PSS(g)    guid_is(g, 0xCDA348C7, 0x445D, 0x4471, 0x9CC9E9885251C556ull)
#define G_PLOC(g)   guid_is(g, 0xA8D35F2D, 0xB30B, 0x454D, 0xABF7D3D84834AB0Cull)

/* ---------------- open ---------------- */

static int read_meta(gz_src *s, u64 base, u32 rlen, const u8 *ent, u8 *dst, u32 n)
{
    u32 off = rd32(ent + 16), len = rd32(ent + 20);
    if (len < n || off < 64 * KiB || off > rlen || len > rlen - off) return GZ_E_FORMAT;
    return gz_src_read_exact(s, base + off, dst, n);
}

static int vhdx_parse(gz_archive *a, gz_src *s, vhdx_img *im)
{
    u8 h[4096], best[4096];
    u64 seq = 0;
    int have = 0, r;
    if (s->size < 1 * MiB) return GZ_E_FORMAT;
    for (int i = 0; i < 2; i++) {
        if (gz_src_read_exact(s, (u64)(64 + 64 * i) * KiB, h, 4096)) continue;
        if (rd32(h) != 0x64616568u || !c32c_ok(h, 4096)) continue;       /* "head" */
        if (!have || rd64(h + 8) > seq) { __builtin_memcpy(best, h, 4096); seq = rd64(h + 8); have = 1; }
    }
    if (!have) return GZ_E_CRC;
    if (rd16(best + 66) != 1) return GZ_E_METHOD;                         /* version */
    static const u8 zero16[16];
    if (__builtin_memcmp(best + 48, zero16, 16)) GZ_VD_NOTE(a, "VHDX log not replayed: the disk was not closed cleanly");

    /* region table (primary, else the copy) */
    u8 *rt = (u8 *)gz_alloc(64 * KiB);
    if (!rt) return GZ_E_NOMEM;
    int ok = 0;
    for (int i = 0; i < 2 && !ok; i++) {
        if (gz_src_read_exact(s, (u64)(192 + 64 * i) * KiB, rt, 64 * KiB)) continue;
        ok = rd32(rt) == 0x69676572u && rd32(rt + 8) <= 2047 && c32c_ok(rt, 64 * KiB);   /* "regi" */
    }
    u64 bat_off = 0, meta_off = 0;
    u32 bat_len = 0, meta_len = 0;
    r = ok ? GZ_OK : GZ_E_CRC;
    for (u32 i = 0; ok && i < rd32(rt + 8); i++) {
        const u8 *e = rt + 16 + 32 * i;
        u64 fo = rd64(e + 16);
        u32 len = rd32(e + 24);
        if (G_BAT(e)) { bat_off = fo; bat_len = len; }
        else if (G_META(e)) { meta_off = fo; meta_len = len; }
        else if (rd32(e + 28) & 1) { r = GZ_E_METHOD; break; }           /* unknown required region */
    }
    gz_free(rt);
    if (r) return r;
    if (!bat_len || !meta_len || bat_off > s->size || bat_len > s->size - bat_off ||
        meta_off > s->size || meta_len > s->size - meta_off || meta_len < 64 * KiB)
        return GZ_E_FORMAT;

    /* metadata table */
    u8 *mt = (u8 *)gz_alloc(64 * KiB);
    if (!mt) return GZ_E_NOMEM;
    u8 fp[8] = {0}, vs[8] = {0}, ls[4] = {0};
    int got = 0;
    r = gz_src_read_exact(s, meta_off, mt, 64 * KiB);
    if (!r && rd64(mt) != 0x617461646174656Dull) r = GZ_E_FORMAT;          /* "metadata" */
    u32 cnt = r ? 0 : rd16(mt + 10);
    if (cnt > 2047) r = GZ_E_FORMAT;
    for (u32 i = 0; !r && i < cnt; i++) {
        const u8 *e = mt + 32 + 32 * i;
        u32 fl = rd32(e + 24);
        if (G_FPARAM(e)) { r = read_meta(s, meta_off, meta_len, e, fp, 8); got |= 1; }
        else if (G_VSIZE(e)) { r = read_meta(s, meta_off, meta_len, e, vs, 8); got |= 2; }
        else if (G_LSS(e)) { r = read_meta(s, meta_off, meta_len, e, ls, 4); got |= 4; }
        else if (G_VDID(e) || G_PSS(e)) continue;
        else if (G_PLOC(e)) got |= 8;
        else if ((fl & 4) && !(fl & 1)) r = GZ_E_METHOD;                  /* unknown required system item */
    }
    gz_free(mt);
    if (r) return r;
    if ((got & 7) != 7) return GZ_E_FORMAT;
    if ((rd32(fp + 4) & 2) || (got & 8)) return GZ_E_METHOD;              /* differencing disk */
    u32 bs = rd32(fp), lss = rd32(ls);
    im->vsize = rd64(vs);
    if (!gz_vd_pow2(bs) || bs < 1 * MiB || bs > 256 * MiB || (lss != 512 && lss != 4096)) return GZ_E_FORMAT;
    if (im->vsize > ((u64)64 << 40) || im->vsize % lss) return GZ_E_FORMAT;
    im->bshift = gz_vd_log2(bs);
    im->fixed = rd32(fp + 4) & 1;
    im->chunk = (u32)(((u64)1 << 23) * lss / bs);
    u64 pb = (im->vsize + bs - 1) >> im->bshift;
    im->nbat = pb ? pb + (pb - 1) / im->chunk : 0;
    if (im->nbat * 8 > bat_len) return GZ_E_FORMAT;
    if (im->nbat * 8 > GZ_VD_MAX_TABLE) return GZ_E_LIMIT;
    im->bat = (u64 *)gz_alloc((size_t)im->nbat * 8 + 8);
    if (!im->bat) return GZ_E_NOMEM;
    if (im->nbat && (r = gz_src_read_exact(s, bat_off, im->bat, (u32)(im->nbat * 8)))) return r;
    return GZ_OK;
}

/* ---------------- view ---------------- */

static int vhdx_map(gz_vd_view *v, u64 off, gz_vd_ext *x)
{
    const vhdx_img *im = (const vhdx_img *)v->img;
    u64 blk = off >> im->bshift;
    u64 bs = (u64)1 << im->bshift;
    u64 within = off & (bs - 1);
    u64 idx = blk + blk / im->chunk;
    x->len = bs - within;
    if (idx >= im->nbat) return GZ_E_FORMAT;
    u64 e = im->bat[idx];
    switch (e & 7) {
    case 0: case 1: case 2: case 3:          /* not present, undefined, zero, unmapped */
        x->kind = GZ_VD_ZERO;
        return GZ_OK;
    case 6: {                                /* fully present */
        u64 fo = e & ~(u64)(MiB - 1);
        if (!fo || fo > v->file->size) return GZ_E_TRUNC;
        x->kind = GZ_VD_RAW;
        x->pos = fo + within;
        return GZ_OK;
    }
    }
    return GZ_E_FORMAT;                      /* partially present only exists in differencing disks */
}

/* ---------------- format ---------------- */

static int vhdx_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    return n >= 8 && !__builtin_memcmp(h, "vhdxfile", 8) ? 95 : 0;
}

static void vhdx_close(gz_archive *a)
{
    vhdx_img *im = (vhdx_img *)a->priv;
    if (im) gz_free(im->bat);
    gz_free(im);
    a->priv = 0;
}

static int vhdx_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)c;
    vhdx_img *im = (vhdx_img *)gz_alloc(sizeof(vhdx_img));
    if (!im) return GZ_E_NOMEM;
    a->priv = im;
    int r = vhdx_parse(a, s, im);
    if (r) return r;
    return gz_vd_add_disk(a, o, im->vsize, s->size, 0);
}

static gz_src *vhdx_view(gz_archive *a, gz_src *s, u32 idx)
{
    (void)idx;
    const vhdx_img *im = (const vhdx_img *)a->priv;
    gz_vd_view *v = gz_vd_view_new(sizeof(gz_vd_view), s, im, im->vsize, vhdx_map);
    return v ? &v->s : 0;
}

static void vhdx_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)e;
    const vhdx_img *im = (const vhdx_img *)a->priv;
    char t[24] = "Dynamic:";
    if (im && im->fixed) __builtin_memcpy(t, "Fixed:\0\0", 8);
    u32 k = (im && im->fixed) ? 6 : 8, mb = im ? (1u << im->bshift) >> 20 : 0;
    char d[8];
    int n = 0;
    do { d[n++] = (char)('0' + mb % 10); mb /= 10; } while (mb && n < 7);
    while (n) t[k++] = d[--n];
    t[k++] = 'M';
    t[k] = 0;
    gz_vd_method_str(buf, cap, t);
}

GZ_FORMAT(gz_fmt_vhdx)
const gz_format gz_fmt_vhdx = {
    "VHDX", "vhdx avhdx", GZ_FMT_CONTAINER,
    vhdx_probe, vhdx_open, vhdx_close, gz_vd_extract, 0, 0, vhdx_method, vhdx_view, 0
};
