/*
 * 고깃ZIP - VirtualBox Disk Image (VDI 1.1)
 *
 *   0     "<<< ... VirtualBox Disk Image >>>" text, signature 0xBEDA107F at 64,
 *         version 0x00010001 at 68
 *   72    header 1.1: type, offsets of the block map and the data, disk size,
 *         block size, extra bytes per block, block counts, UUIDs
 *   block map: u32 per block = index of the block in the data area,
 *         0xFFFFFFFF free, 0xFFFFFFFE zero; both read as zeros
 *
 * Normal (dynamic) and fixed images are read; undo / differencing images
 * report GZ_E_METHOD. Little-endian.
 */
#include "vdisk.h"

enum { VDI_NORMAL = 1, VDI_FIXED = 2, VDI_UNDO = 3, VDI_DIFF = 4 };

typedef struct {
    u64 vsize;
    u64 data_off;
    u32 bshift;           /* log2 block size        */
    u32 stride;           /* extra + block size      */
    u32 extra;
    u32 nblocks;
    u32 *map;
    u32 type;
} vdi_img;

static int vdi_parse(gz_src *s, vdi_img *im)
{
    u8 h[512];
    if (s->size < 512) return GZ_E_FORMAT;
    int r = gz_src_read_exact(s, 0, h, 512);
    if (r) return r;
    if (rd32(h + 64) != 0xBEDA107Fu) return GZ_E_FORMAT;
    if ((rd32(h + 68) >> 16) != 1) return GZ_E_METHOD;            /* major version 1 */
    u32 hsize = rd32(h + 72);
    if (hsize < 384 || hsize > 4096) return GZ_E_FORMAT;
    im->type = rd32(h + 76);
    if (im->type == VDI_UNDO || im->type == VDI_DIFF) return GZ_E_METHOD;
    if (im->type != VDI_NORMAL && im->type != VDI_FIXED) return GZ_E_FORMAT;
    u64 map_off = rd32(h + 340);
    im->data_off = rd32(h + 344);
    im->vsize = rd64(h + 368);
    u32 bs = rd32(h + 376);
    im->extra = rd32(h + 380);
    im->nblocks = rd32(h + 384);
    if (!gz_vd_pow2(bs) || bs < 512 || bs > (1u << 28) || im->extra > bs) return GZ_E_FORMAT;
    im->bshift = gz_vd_log2(bs);
    im->stride = bs + im->extra;
    if (im->vsize > GZ_VD_MAX_SIZE || im->vsize > ((u64)im->nblocks << im->bshift)) return GZ_E_FORMAT;
    u64 need = (im->vsize + bs - 1) >> im->bshift;         /* entries we actually use */
    if (need * 4 > GZ_VD_MAX_TABLE) return GZ_E_LIMIT;
    if (map_off > s->size || need * 4 > s->size - map_off) return GZ_E_FORMAT;
    im->nblocks = (u32)need;
    im->map = (u32 *)gz_alloc((size_t)need * 4 + 4);
    if (!im->map) return GZ_E_NOMEM;
    return need ? gz_src_read_exact(s, map_off, im->map, (u32)need * 4) : GZ_OK;
}

static int vdi_map(gz_vd_view *v, u64 off, gz_vd_ext *x)
{
    const vdi_img *im = (const vdi_img *)v->img;
    u64 bs = (u64)1 << im->bshift;
    u64 blk = off >> im->bshift, within = off & (bs - 1);
    x->len = bs - within;
    u32 m = blk < im->nblocks ? im->map[blk] : 0xFFFFFFFFu;
    if (m >= 0xFFFFFFFEu) { x->kind = GZ_VD_ZERO; return GZ_OK; }
    x->kind = GZ_VD_RAW;
    x->pos = im->data_off + (u64)m * im->stride + im->extra + within;
    return GZ_OK;
}

static int vdi_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    return n >= 76 && rd32(h + 64) == 0xBEDA107Fu ? 90 : 0;
}

static void vdi_close(gz_archive *a)
{
    vdi_img *im = (vdi_img *)a->priv;
    if (im) gz_free(im->map);
    gz_free(im);
    a->priv = 0;
}

static int vdi_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)c;
    vdi_img *im = (vdi_img *)gz_alloc(sizeof(vdi_img));
    if (!im) return GZ_E_NOMEM;
    a->priv = im;
    int r = vdi_parse(s, im);
    if (r) return r;
    gz_entry *e;
    if ((r = gz_vd_add_disk(a, o, im->vsize, s->size, &e))) return r;
    e->method = (u16)im->type;
    return GZ_OK;
}

static gz_src *vdi_view(gz_archive *a, gz_src *s, u32 idx)
{
    (void)idx;
    const vdi_img *im = (const vdi_img *)a->priv;
    gz_vd_view *v = gz_vd_view_new(sizeof(gz_vd_view), s, im, im->vsize, vdi_map);
    return v ? &v->s : 0;
}

static void vdi_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    gz_vd_method_str(buf, cap, e->method == VDI_FIXED ? "Fixed" : "Dynamic");
}

GZ_FORMAT(gz_fmt_vdi)
const gz_format gz_fmt_vdi = {
    "VDI", "vdi", GZ_FMT_CONTAINER,
    vdi_probe, vdi_open, vdi_close, gz_vd_extract, 0, 0, vdi_method, vdi_view, 0
};
