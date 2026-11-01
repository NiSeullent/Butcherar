/*
 * 고깃ZIP - QEMU copy-on-write images: QCOW (v1) and QCOW2 (v2, v3)
 *
 *   header "QFI\xfb" (big-endian fields), L1 table -> L2 tables -> clusters
 *   v2/v3 L2 entry: bit 62 compressed, bit 0 reads-as-zero (v3), bits 9..55
 *   host offset; compressed descriptor = host offset + extra 512-byte sectors;
 *   v3 extended L2 entries add a 32-subcluster allocated / zero bitmap.
 *   v1 L2 entry: bit 63 compressed (size in the bits below), else offset.
 *   Compressed clusters are raw Deflate (zstd ones report GZ_E_METHOD).
 *
 * Backing files, encryption and external data files report GZ_E_METHOD;
 * unknown incompatible feature bits too. Dirty / corrupt flags only mean the
 * metadata may need a repair for writing: the image is read as it is.
 */
#include "vdisk.h"

#define L1_MASK 0x00fffffffffffe00ull
#define L2_MASK 0x00fffffffffffe00ull

typedef struct {
    u64 vsize;
    u64 nl1;
    u64 *l1;                  /* L2 table offsets (host order)          */
    u32 version;
    u32 cbits;                /* log2 cluster size                      */
    u32 l2bits;               /* log2 entries per L2 table              */
    u32 l2_bytes;
    u32 esz;                  /* bytes per L2 entry (8, 16 extended)    */
    int zstd;                 /* compression type 1                     */
    u32 cshift;               /* v2/v3 compressed descriptor layout     */
    u64 cmask, omask;
    u32 slots;                /* per-view L2 cache size                 */
} qcow_img;

#define MAX_SLOTS 16

typedef struct {
    gz_vd_view v;
    u8 *l2;                   /* slots * l2_bytes                       */
    u64 key[MAX_SLOTS];       /* L1 index + 1, 0 = empty                */
    u8 *cbuf;                 /* dc_slots decoded compressed clusters   */
    u64 ckey[4];              /* cluster index + 1, 0 = empty           */
    u32 dc_slots;
} qcow_vw;

static int qcow_parse(gz_src *s, qcow_img *im)
{
    u8 h[112];
    __builtin_memset(h, 0, sizeof h);
    if (s->size < 48) return GZ_E_FORMAT;
    int r = gz_src_read_exact(s, 0, h, s->size < sizeof h ? (u32)s->size : (u32)sizeof h);
    if (r) return r;
    if (rd32be(h) != 0x514649FBu) return GZ_E_FORMAT;
    im->version = rd32be(h + 4);
    u64 l1_off, need;
    if (im->version == 1) {
        if (rd64be(h + 8)) return GZ_E_METHOD;                     /* backing file */
        if (rd32be(h + 36)) return GZ_E_METHOD;                    /* AES */
        im->vsize = rd64be(h + 24);
        im->cbits = h[32];
        im->l2bits = h[33];
        l1_off = rd64be(h + 40);
        if (im->cbits < 9 || im->cbits > 16 || im->l2bits < 6 || im->l2bits > 13) return GZ_E_FORMAT;
        im->esz = 8;
        im->l2_bytes = 8u << im->l2bits;
        im->nl1 = 0;
    } else if (im->version == 2 || im->version == 3) {
        if (s->size < 72) return GZ_E_FORMAT;
        if (rd64be(h + 8) && rd32be(h + 16)) return GZ_E_METHOD;   /* backing file */
        im->cbits = rd32be(h + 20);
        im->vsize = rd64be(h + 24);
        if (rd32be(h + 32)) return GZ_E_METHOD;                    /* AES / LUKS */
        im->nl1 = rd32be(h + 36);
        l1_off = rd64be(h + 40);
        if (im->cbits < 9 || im->cbits > 21) return GZ_E_FORMAT;
        int ext = 0;
        if (im->version == 3) {
            if (s->size < 104) return GZ_E_FORMAT;
            u64 inc = rd64be(h + 72);
            u32 hl = rd32be(h + 100);
            if (hl < 104) return GZ_E_FORMAT;
            /* 0 dirty, 1 corrupt: fine for reading; 2 external data file */
            if (inc & ~(u64)0x1B) return GZ_E_METHOD;
            if (inc & 8) {                                         /* compression type field */
                if (hl < 105 || s->size < 105) return GZ_E_FORMAT;
                if (h[104] > 1) return GZ_E_METHOD;
                im->zstd = h[104] == 1;
            }
            ext = (inc & 16) != 0;
        }
        im->esz = ext ? 16 : 8;
        im->l2bits = im->cbits - (ext ? 4 : 3);
        im->l2_bytes = 1u << im->cbits;
        im->cshift = 62 - (im->cbits - 8);
        im->cmask = ((u64)1 << (im->cbits - 8)) - 1;
        im->omask = ((u64)1 << im->cshift) - 1;
        if (ext && im->cbits < 14) return GZ_E_FORMAT;             /* subclusters >= 512 bytes */
    } else {
        return GZ_E_METHOD;
    }
    if (im->vsize > GZ_VD_MAX_SIZE) return GZ_E_LIMIT;
    u32 span = im->cbits + im->l2bits;                             /* bytes covered by one L1 entry */
    need = (im->vsize + ((u64)1 << span) - 1) >> span;
    if (im->version == 1) im->nl1 = need;
    else if (im->nl1 < need) return GZ_E_FORMAT;
    im->nl1 = need;
    if (need * 8 > GZ_VD_MAX_TABLE) return GZ_E_LIMIT;
    if (l1_off > s->size || need * 8 > s->size - l1_off) return GZ_E_FORMAT;
    im->l1 = (u64 *)gz_alloc((size_t)need * 8 + 8);
    if (!im->l1) return GZ_E_NOMEM;
    if (need && (r = gz_src_read_exact(s, l1_off, im->l1, (u32)(need * 8)))) return r;
    for (u64 i = 0; i < need; i++) {
        im->l1[i] = __builtin_bswap64(im->l1[i]);
        if (im->version > 1) im->l1[i] &= L1_MASK;
    }
    im->slots = im->l2_bytes <= (64u << 10) ? 16 : im->l2_bytes <= (512u << 10) ? 4 : 2;
    return GZ_OK;
}

/* ---------------- view ---------------- */

static int load_l2(qcow_vw *v, const qcow_img *im, u64 l1i, const u8 **out)
{
    u32 slot = (u32)(l1i & (im->slots - 1));
    u8 *t = v->l2 + (size_t)slot * im->l2_bytes;
    if (v->key[slot] != l1i + 1) {
        u64 pos = im->l1[l1i];
        v->key[slot] = 0;
        if (pos > v->v.file->size || im->l2_bytes > v->v.file->size - pos) return GZ_E_TRUNC;
        int r = gz_src_read_exact(v->v.file, pos, t, im->l2_bytes);
        if (r) return r;
        v->key[slot] = l1i + 1;
    }
    *out = t;
    return GZ_OK;
}

static int read_compressed(qcow_vw *v, const qcow_img *im, u64 cl, u64 pos, u64 len, const u8 **out)
{
    u32 cs = 1u << im->cbits;
    if (!v->cbuf) {
        v->dc_slots = cs <= (256u << 10) ? 4 : 1;
        if (!(v->cbuf = (u8 *)gz_alloc((size_t)v->dc_slots * cs))) return GZ_E_NOMEM;
    }
    u32 slot = (u32)(cl & (v->dc_slots - 1));
    u8 *buf = v->cbuf + (size_t)slot * cs;
    *out = buf;
    if (v->ckey[slot] == cl + 1) return GZ_OK;
    if (im->zstd) return GZ_E_METHOD;
    v->ckey[slot] = 0;
    gz_src *f = v->v.file;
    if (pos >= f->size) return GZ_E_TRUNC;
    if (len > f->size - pos) len = f->size - pos;      /* the last sector may be short */
    u32 got;
    int r = gz_vd_inflate(&v->v, f, pos, len, 0, buf, cs, &got);
    if (r) return r;
    if (got < cs) __builtin_memset(buf + got, 0, cs - got);
    v->ckey[slot] = cl + 1;
    return GZ_OK;
}

static int qcow_map(gz_vd_view *gv, u64 off, gz_vd_ext *x)
{
    qcow_vw *v = (qcow_vw *)gv;
    const qcow_img *im = (const qcow_img *)gv->img;
    u64 cs = (u64)1 << im->cbits, within = off & (cs - 1);
    u64 l1i = off >> (im->cbits + im->l2bits);
    x->kind = GZ_VD_ZERO;
    x->len = cs - within;
    if (l1i >= im->nl1) return GZ_OK;
    if (!im->l1[l1i]) {                                   /* no L2 table: zeros to its end */
        x->len = (((l1i + 1) << (im->cbits + im->l2bits))) - off;
        return GZ_OK;
    }
    const u8 *l2;
    int r = load_l2(v, im, l1i, &l2);
    if (r) return r;
    u64 l2i = (off >> im->cbits) & (((u64)1 << im->l2bits) - 1);
    u64 e = rd64be(l2 + l2i * im->esz);
    if (im->version == 1) {
        if (e >> 63) {
            u32 sh = 63 - im->cbits;
            const u8 *cb;
            r = read_compressed(v, im, off >> im->cbits, e & (((u64)1 << sh) - 1), (e >> sh) & (cs - 1), &cb);
            if (r) return r;
            x->kind = GZ_VD_MEM;
            x->mem = cb + within;
        } else if (e) {
            x->kind = GZ_VD_RAW;
            x->pos = e + within;
        }
        return GZ_OK;
    }
    if ((e >> 62) & 1) {                                  /* compressed */
        u64 pos = e & im->omask;
        u64 len = (((e >> im->cshift) & im->cmask) + 1) * 512 - (pos & 511);
        const u8 *cb;
        r = read_compressed(v, im, off >> im->cbits, pos, len, &cb);
        if (r) return r;
        x->kind = GZ_VD_MEM;
        x->mem = cb + within;
        return GZ_OK;
    }
    u64 host = e & L2_MASK;
    if (im->esz == 16) {                                  /* subclusters */
        u64 bm = rd64be(l2 + l2i * 16 + 8);
        u64 sc = cs >> 5, i = within / sc;
        x->len = sc - within % sc;
        if ((bm >> (32 + i)) & 1) return GZ_OK;           /* reads as zero */
        if (!((bm >> i) & 1) || !host) return GZ_OK;      /* unallocated   */
    } else {
        if (im->version >= 3 && (e & 1)) return GZ_OK;    /* zero cluster  */
        if (!host) return GZ_OK;
    }
    x->kind = GZ_VD_RAW;
    x->pos = host + within;
    return GZ_OK;
}

static void qcow_fini(gz_vd_view *gv)
{
    qcow_vw *v = (qcow_vw *)gv;
    gz_free(v->l2);
    gz_free(v->cbuf);
}

/* ---------------- format ---------------- */

static int qcow_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 8 || rd32be(h) != 0x514649FBu) return 0;
    u32 v = rd32be(h + 4);
    return v >= 1 && v <= 3 ? 95 : 0;
}

static void qcow_close(gz_archive *a)
{
    qcow_img *im = (qcow_img *)a->priv;
    if (im) gz_free(im->l1);
    gz_free(im);
    a->priv = 0;
}

static int qcow_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)c;
    qcow_img *im = (qcow_img *)gz_alloc(sizeof(qcow_img));
    if (!im) return GZ_E_NOMEM;
    a->priv = im;
    int r = qcow_parse(s, im);
    if (r) return r;
    if (im->version == 1) gz_arc_set_type(a, "QCOW");
    return gz_vd_add_disk(a, o, im->vsize, s->size, 0);
}

static gz_src *qcow_view(gz_archive *a, gz_src *s, u32 idx)
{
    (void)idx;
    const qcow_img *im = (const qcow_img *)a->priv;
    qcow_vw *v = (qcow_vw *)gz_vd_view_new(sizeof(qcow_vw), s, im, im->vsize, qcow_map);
    if (!v) return 0;
    v->v.fini = qcow_fini;
    if (!(v->l2 = (u8 *)gz_alloc((size_t)im->slots * im->l2_bytes))) { gz_src_free(&v->v.s); return 0; }
    return &v->v.s;
}

static void qcow_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)e;
    const qcow_img *im = (const qcow_img *)a->priv;
    char t[32];
    u32 k = 0;
    if (im) {
        t[k++] = 'v';
        t[k++] = (char)('0' + im->version);
        t[k++] = ' ';
        u32 kb = (1u << im->cbits) >> 10;
        if (!kb) { t[k++] = '5'; t[k++] = '1'; t[k++] = '2'; }
        else {
            char d[8];
            int n = 0;
            do { d[n++] = (char)('0' + kb % 10); kb /= 10; } while (kb);
            while (n) t[k++] = d[--n];
            t[k++] = 'K';
        }
        if (im->zstd) { __builtin_memcpy(t + k, " zstd", 5); k += 5; }
        if (im->esz == 16) { __builtin_memcpy(t + k, " subcl", 6); k += 6; }
    }
    t[k] = 0;
    gz_vd_method_str(buf, cap, t);
}

GZ_FORMAT(gz_fmt_qcow)
const gz_format gz_fmt_qcow = {
    "QCOW2", "qcow2 qcow qcow2c img", GZ_FMT_CONTAINER,
    qcow_probe, qcow_open, qcow_close, gz_vd_extract, 0, 0, qcow_method, qcow_view, 0
};
