/*
 * 고깃ZIP - Android sparse images (img2simg / fastboot "simg")
 *
 *   file header (28+ bytes): magic 0xED26FF3A, version 1.x, header sizes,
 *   block size, total blocks, chunk count
 *   chunks (12+ byte header): RAW (data follows), FILL (4-byte pattern),
 *   DONT_CARE (zeros), CRC32 (checksum of everything expanded so far)
 *
 * The chunk list is indexed by output block for random access. A sequential
 * extract verifies the CRC32 chunks. Little-endian.
 */
#include "vdisk.h"
#include "crc32.h"

#define SPARSE_MAGIC 0xED26FF3Au
enum { CH_RAW = 0xCAC1, CH_FILL = 0xCAC2, CH_SKIP = 0xCAC3, CH_CRC = 0xCAC4 };

typedef struct {
    u64 out;                 /* first output byte          */
    u64 len;                 /* output bytes               */
    u64 data;                /* RAW: file offset of data    */
    u32 fill;                /* FILL: pattern / CRC: value  */
    u16 type;
} sp_chunk;

typedef struct {
    u64 vsize;
    u32 bsize;
    u32 n;                   /* data chunks (sorted by out) */
    sp_chunk *ch;
    u32 ncrc;                /* CRC32 chunks: out = position, fill = expected CRC */
    sp_chunk *crc;
} sp_img;

static int sp_header_ok(const u8 *h, u64 fsize)
{
    if (rd32(h) != SPARSE_MAGIC || rd16(h + 4) != 1) return 0;
    u16 fh = rd16(h + 8), chh = rd16(h + 10);
    u32 bs = rd32(h + 12);
    if (fh < 28 || chh < 12 || fh > 1024 || chh > 1024 || fh > fsize) return 0;
    if (!bs || (bs & 3) || bs > (64u << 20)) return 0;
    return 1;
}

static int sp_parse(gz_src *s, sp_img *im, gz_ctx *c)
{
    u8 h[28];
    if (s->size < 28) return GZ_E_FORMAT;
    int r = gz_src_read_exact(s, 0, h, 28);
    if (r) return r;
    if (!sp_header_ok(h, s->size)) return GZ_E_FORMAT;
    u32 fh = rd16(h + 8), chh = rd16(h + 10);
    im->bsize = rd32(h + 12);
    u64 total = rd32(h + 16);
    u32 nch = rd32(h + 20);
    im->vsize = total * im->bsize;
    if (im->vsize > GZ_VD_MAX_SIZE) return GZ_E_LIMIT;
    /* every chunk has a header in the file: bounds the count */
    if ((u64)nch * chh > s->size - fh) return GZ_E_FORMAT;
    if ((u64)nch * sizeof(sp_chunk) > GZ_VD_MAX_TABLE) return GZ_E_LIMIT;
    im->ch = (sp_chunk *)gz_alloc((size_t)nch * sizeof(sp_chunk) + sizeof(sp_chunk));
    if (!im->ch) return GZ_E_NOMEM;
    u64 pos = fh, blk = 0;
    for (u32 i = 0; i < nch; i++) {
        u8 ch[12];
        if ((i & 4095) == 0 && gz_cancelled(c)) return GZ_E_CANCEL;
        if ((r = gz_src_read_exact(s, pos, ch, 12))) return r;
        u16 type = rd16(ch);
        u32 cnt = rd32(ch + 4), tsz = rd32(ch + 8);
        if (tsz < chh || tsz > s->size - pos) return GZ_E_FORMAT;
        u64 body = tsz - chh, dpos = pos + chh;
        u64 olen = (u64)cnt * im->bsize;
        if (cnt > total - blk) return GZ_E_FORMAT;          /* more blocks than declared */
        sp_chunk *k = 0;
        if (type == CH_CRC) {
            if (cnt || body < 4) return GZ_E_FORMAT;
            if (!(im->ncrc & 63)) {
                sp_chunk *nc = (sp_chunk *)gz_realloc(im->crc, ((size_t)im->ncrc + 64) * sizeof(sp_chunk));
                if (!nc) return GZ_E_NOMEM;
                im->crc = nc;
            }
            k = &im->crc[im->ncrc++];
            __builtin_memset(k, 0, sizeof *k);
            k->out = blk * im->bsize;
            k->type = type;
            if ((r = gz_src_read_exact(s, dpos, ch, 4))) return r;
            k->fill = rd32(ch);
        } else {
            if (type == CH_RAW) { if (body != olen) return GZ_E_FORMAT; }
            else if (type == CH_FILL) { if (body < 4) return GZ_E_FORMAT; }
            else if (type != CH_SKIP) return GZ_E_FORMAT;
            if (cnt) {
                k = &im->ch[im->n++];
                k->out = blk * im->bsize;
                k->len = olen;
                k->data = dpos;
                k->type = type;
                k->fill = 0;
                if (type == CH_FILL) {
                    if ((r = gz_src_read_exact(s, dpos, ch, 4))) return r;
                    k->fill = rd32(ch);
                }
            }
            blk += cnt;
        }
        pos += tsz;
    }
    return GZ_OK;
}

static int sp_map(gz_vd_view *v, u64 off, gz_vd_ext *x)
{
    const sp_img *im = (const sp_img *)v->img;
    /* last chunk starting at or before off */
    u32 lo = 0, hi = im->n;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        if (im->ch[mid].out <= off) lo = mid + 1; else hi = mid;
    }
    x->kind = GZ_VD_ZERO;
    if (!lo) {                                    /* before the first chunk (none: all zero) */
        x->len = im->n ? im->ch[0].out - off : v->s.size - off;
        return GZ_OK;
    }
    const sp_chunk *k = &im->ch[lo - 1];
    u64 rel = off - k->out;
    if (rel >= k->len) {                          /* past the declared chunks */
        x->len = lo < im->n ? im->ch[lo].out - off : v->s.size - off;
        return GZ_OK;
    }
    x->len = k->len - rel;
    if (k->type == CH_RAW) { x->kind = GZ_VD_RAW; x->pos = k->data + rel; }
    else if (k->type == CH_FILL) { x->kind = GZ_VD_FILL; x->fill = k->fill; }
    return GZ_OK;
}

static int sp_probe(gz_src *s, const u8 *h, u32 n)
{
    return n >= 28 && sp_header_ok(h, s->size) ? 95 : 0;
}

static void sp_close(gz_archive *a)
{
    sp_img *im = (sp_img *)a->priv;
    if (im) { gz_free(im->ch); gz_free(im->crc); }
    gz_free(im);
    a->priv = 0;
}

static int sp_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    sp_img *im = (sp_img *)gz_alloc(sizeof(sp_img));
    if (!im) return GZ_E_NOMEM;
    a->priv = im;
    int r = sp_parse(s, im, c);
    if (r) return r;
    gz_arc_set_type(a, "Sparse");
    return gz_vd_add_disk(a, o, im->vsize, s->size, 0);
}

static gz_src *sp_view(gz_archive *a, gz_src *s, u32 idx)
{
    (void)idx;
    const sp_img *im = (const sp_img *)a->priv;
    gz_vd_view *v = gz_vd_view_new(sizeof(gz_vd_view), s, im, im->vsize, sp_map);
    return v ? &v->s : 0;
}

/* Sequential extract; CRC32 chunks are checked against the data before them. */
static int sp_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    const sp_img *im = (const sp_img *)a->priv;
    if (!im->ncrc) return gz_vd_extract(a, s, idx, out, c);
    gz_src *v = sp_view(a, s, idx);
    if (!v) return GZ_E_NOMEM;
    int st = out->open(out, idx);
    if (st) { gz_src_free(v); return st; }
    u8 *buf = gz_ctx_buffer(c, 256u << 10);
    u32 crc = 0, ci = 0;
    u64 pos = 0;
    if (!buf) st = GZ_E_NOMEM;
    while (!st) {
        while (ci < im->ncrc && im->crc[ci].out <= pos) {
            if (im->crc[ci].fill != crc) { st = GZ_E_CRC; break; }
            ci++;
        }
        if (st || pos >= v->size) break;
        if (gz_cancelled(c)) { st = GZ_E_CANCEL; break; }
        u64 end = ci < im->ncrc && im->crc[ci].out < v->size ? im->crc[ci].out : v->size;
        u32 n = end - pos < (256u << 10) ? (u32)(end - pos) : (256u << 10);
        if ((st = gz_src_read_exact(v, pos, buf, n))) break;
        crc = gz_crc32(crc, buf, n);
        st = out->write(out, buf, n);
        pos += n;
    }
    gz_src_free(v);
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static void sp_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)e;
    const sp_img *im = (const sp_img *)a->priv;
    gz_vd_method_str(buf, cap, im && im->ncrc ? "Sparse CRC32" : "Sparse");
}

GZ_FORMAT(gz_fmt_sparseimg)
const gz_format gz_fmt_sparseimg = {
    "Sparse", "simg img", GZ_FMT_CONTAINER,
    sp_probe, sp_open, sp_close, sp_extract, 0, 0, sp_method, sp_view, 0
};
