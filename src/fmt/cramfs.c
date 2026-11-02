/*
 * 고깃ZIP - CramFS images (Linux compressed ROM file system)
 *
 *   Little- and big-endian images, superblock at 0 or at 512 (boot pad, -p), version 1
 *   and 2 (fsid with a CRC-32 of the image: checked at open for images up to 64 MiB, a
 *   mismatch makes every file report GZ_E_CRC after its data), symbolic links, zlib
 *   blocks behind block pointer tables, holes (-z: empty blocks), and the extended block
 *   pointers of newer kernels (bit 31 uncompressed block, bit 30 direct pointer: start
 *   >> 2, compressed length in the first two bytes). Devices, fifos and sockets are
 *   skipped; cramfs keeps no time stamps.
 *
 *   The block size is not stored (it is the target's page size): it is detected from the
 *   block tables of a few files (power of two, 1 KiB .. 64 KiB, 4 KiB first).
 *
 *   Hostile images: directories are read once (offset set) within a total budget of the
 *   image size, depth is limited, block pointers must stay inside the image and blocks
 *   decode to exactly the size the file needs.
 */
#include "fs1.h"
#include "sqfs.h"
#include "crc32.h"

#define CR_MAGIC        0x28CD3D45u
#define CR_SIG          "Compressed ROMFS"
#define CR_SB_SIZE      76u
#define CR_FL_V2        0x00000001u
#define CR_FL_SUPPORTED (0x000000FFu | 0x100u | 0x200u | 0x400u | 0x800u)
#define CR_BLK_RAW      0x80000000u
#define CR_BLK_DIRECT   0x40000000u
#define CR_BLK_FLAGS    (CR_BLK_RAW | CR_BLK_DIRECT)
#define CR_CRC_MAX      (64u << 20)
#define CR_WIN          (256u << 10)

typedef struct {
    int be;
    u32 base;                /* superblock offset (0 or 512) */
    u32 flags;
    u64 size;                /* image size */
    u32 bs, blog;
    int crc_bad;
} cr_priv;

typedef struct { u32 mode, uid, size, gid, namelen, off; } cr_ino;

static u32 c32(const cr_priv *pv, const u8 *p) { return pv->be ? rd32be(p) : rd32(p); }
static u32 c16(const cr_priv *pv, const u8 *p) { return pv->be ? rd16be(p) : rd16(p); }

static void cr_inode(int be, const u8 *p, cr_ino *x)
{
    if (be) {
        u32 w0 = rd32be(p), w1 = rd32be(p + 4), w2 = rd32be(p + 8);
        x->mode = w0 >> 16; x->uid = w0 & 0xFFFF;
        x->size = w1 >> 8;  x->gid = w1 & 0xFF;
        x->namelen = w2 >> 26; x->off = w2 & 0x03FFFFFF;
    } else {
        u32 w0 = rd32(p), w1 = rd32(p + 4), w2 = rd32(p + 8);
        x->mode = w0 & 0xFFFF; x->uid = w0 >> 16;
        x->size = w1 & 0x00FFFFFF; x->gid = w1 >> 24;
        x->namelen = w2 & 63; x->off = w2 >> 6;
    }
}

/* superblock at h (>= CR_SB_SIZE bytes): 1 little-endian, 2 big-endian, 0 none. The kernel
 * only checks the magic and that the root is a directory; the signature raises confidence. */
static int sb_kind(const u8 *h, int *sig)
{
    int k = rd32(h) == CR_MAGIC ? 1 : rd32be(h) == CR_MAGIC ? 2 : 0;
    u32 mode = k == 1 ? rd32(h + 64) & 0xFFFF : rd32be(h + 64) >> 16;
    if (!k || (mode & 0xF000) != 0x4000) return 0;
    *sig = !__builtin_memcmp(h + 16, CR_SIG, 16);
    return k;
}

static int cr_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    int sig;
    if (n >= CR_SB_SIZE && sb_kind(h, &sig)) return sig ? 95 : 60;
    if (n >= 512 + CR_SB_SIZE && sb_kind(h + 512, &sig)) return sig ? 85 : 50;
    return 0;
}

/* ---------------- block tables ---------------- */

typedef struct {
    const cr_priv *pv;
    gz_src *s;
    u64 off;                 /* block pointer table */
    u32 size, nb;
    u8 *ptr;                 /* nb pointers */
} cr_file;

/* Start, length and kind of block i (kernel cramfs_read_folio rules). len 0 = hole. */
static int cr_block(const cr_file *f, u32 i, u64 *start, u32 *len, int *raw)
{
    const cr_priv *pv = f->pv;
    u32 bs = pv->bs, p = c32(pv, f->ptr + 4 * i), fl = p & CR_BLK_FLAGS;
    u8 b[2];
    int r;
    p &= ~CR_BLK_FLAGS;
    *raw = (fl & CR_BLK_RAW) != 0;
    if (fl & CR_BLK_DIRECT) {
        *start = (u64)p << 2;
        if (*raw) {
            u64 left = f->size - (u64)i * bs;
            *len = left < bs ? (u32)left : bs;
        } else {
            if ((r = gz_src_read_exact(f->s, *start, b, 2))) return r;
            *len = c16(pv, b);
            *start += 2;
        }
    } else {
        u64 st = f->off + (u64)f->nb * 4;
        if (i) {
            u32 q = c32(pv, f->ptr + 4 * (i - 1));
            st = q & ~CR_BLK_FLAGS;
            if (q & CR_BLK_DIRECT) {               /* previous block given by a direct pointer */
                st <<= 2;
                if (q & CR_BLK_RAW) st += bs;
                else {
                    if ((r = gz_src_read_exact(f->s, st, b, 2))) return r;
                    st += 2 + (u64)c16(pv, b);
                }
            }
        }
        if (p < st) return GZ_E_DATA;
        *start = st;
        *len = (u32)(p - st);
    }
    if (*len > 2 * bs || (*raw && *len > bs)) return GZ_E_DATA;
    if (*len && (*start >= pv->size || *len > pv->size - *start)) return GZ_E_DATA;
    return GZ_OK;
}

static int cr_file_open(cr_file *f, const cr_priv *pv, gz_src *s, u64 off, u32 size)
{
    __builtin_memset(f, 0, sizeof *f);
    f->pv = pv;
    f->s = s;
    f->off = off;
    f->size = size;
    f->nb = (u32)(((u64)size + pv->bs - 1) >> pv->blog);
    if (!f->nb) return GZ_OK;
    if (off >= pv->size || (u64)f->nb * 4 > pv->size - off) return GZ_E_DATA;
    f->ptr = (u8 *)gz_alloc((size_t)f->nb * 4);
    if (!f->ptr) return GZ_E_NOMEM;
    return gz_src_read_exact(s, off, f->ptr, f->nb * 4);
}

/* read-ahead window over the image (cap >= 2 * block size) */
typedef struct { u8 *p; u32 cap, len; u64 off; } cr_win;

/* Decode block i into out (bs bytes, not overlapping the window); *on = file bytes it holds. */
static int cr_decode(const cr_file *f, u32 i, gz_inflater **z, cr_win *w, u8 *out, u32 *on)
{
    u64 start;
    u32 len, bs = f->pv->bs;
    int raw, r = cr_block(f, i, &start, &len, &raw);
    if (r) return r;
    u64 left = f->size - (u64)i * bs;
    u32 want = left < bs ? (u32)left : bs;
    *on = want;
    if (!len) { __builtin_memset(out, 0, want); return GZ_OK; }       /* hole */
    if (len > w->cap) return GZ_E_DATA;
    if (!w->len || start < w->off || start - w->off > w->len || len > w->len - (start - w->off)) {
        u64 n = f->pv->size - start;               /* >= len (checked by cr_block) */
        if (n > w->cap) n = w->cap;
        w->len = 0;
        if ((r = gz_src_read_exact(f->s, start, w->p, (u32)n))) return r;
        w->off = start;
        w->len = (u32)n;
    }
    const u8 *in = w->p + (start - w->off);
    if (raw) {                                     /* short stored blocks are zero-padded (kernel) */
        __builtin_memcpy(out, in, len < want ? len : want);
        if (len < want) __builtin_memset(out + len, 0, want - len);
        return GZ_OK;
    }
    u32 got = 0;
    if ((r = gz_sqfs_zlib(z, in, len, out, bs, &got))) return r;
    return got == want ? GZ_OK : GZ_E_DATA;
}

/* ---------------- open ---------------- */

typedef struct {
    gz_archive *a;
    gz_ctx *c;
    cr_priv *pv;
    gz_src *s;
    gz_fs1_tree t;
    gz_fs1_set seen;
    u64 budget;              /* directory bytes still allowed */
    size_t names_max;        /* cap of a->raw: deep trees amplify path bytes */
    u8 *buf;
    u32 cap;
} cr_walk;

static void cr_close(gz_archive *a)
{
    gz_free(a->priv);
    a->priv = 0;
}

static int cr_dir(cr_walk *w, i32 node)
{
    const cr_priv *pv = w->pv;
    u64 off = w->t.n[node].loc;
    u32 size = (u32)w->t.n[node].size;
    if (size > w->budget) size = (u32)w->budget;
    if (!size) return GZ_OK;
    if (off >= pv->size || size > pv->size - off) return GZ_E_FORMAT;
    w->budget -= size;
    if (size > w->cap) {
        u8 *nb = (u8 *)gz_realloc(w->buf, size);
        if (!nb) return GZ_E_NOMEM;
        w->buf = nb;
        w->cap = size;
    }
    int r = gz_src_read_exact(w->s, off, w->buf, size);
    if (r) return r;
    u32 pos = 0;
    while (size - pos >= 12) {
        const u8 *p = w->buf + pos;
        cr_ino x;
        cr_inode(pv->be, p, &x);
        u32 nl = x.namelen * 4;
        if (!nl || nl > size - pos - 12) return GZ_E_FORMAT;
        const u8 *nm = p + 12;
        pos += 12 + nl;
        while (nl && !nm[nl - 1]) nl--;
        u32 type = x.mode & 0xF000;
        if (!nl || (type != 0x4000 && type != 0x8000 && type != 0xA000)) continue;
        if (w->a->raw_len > w->names_max) return GZ_E_LIMIT;
        gz_entry *e;
        if ((r = gz_fs1_add_entry(w->a, &w->t, node, nm, nl, GZ_NE_LEGACY, &e))) return r;
        e->unix_mode = x.mode;
        e->is_dir = type == 0x4000;
        e->is_link = type == 0xA000;
        e->attr = (e->is_dir ? 0x10 : 0) | ((x.mode & 0200) ? 0 : 1);
        e->aux = x.uid | (u64)x.gid << 32;
        e->off = (u64)x.off << 2;
        e->usize = e->is_dir ? 0 : x.size;
        e->csize = 0;
        if (e->is_dir && x.size) {
            int nw = gz_fs1_set_add(&w->seen, e->off);
            if (nw < 0) return GZ_E_NOMEM;
            if (nw && gz_fs1_tree_add(&w->t, node, nm, nl, GZ_NE_LEGACY, e->off, x.size, 0) == -1) return GZ_E_NOMEM;
        }
    }
    return GZ_OK;
}

/* Does block size 1 << blog explain file (off, size)? The block table must be sane and the
 * first compressed block must decode to the expected size. */
static int bs_fits(cr_priv *pv, gz_src *s, u64 off, u32 size, u32 blog, gz_inflater **z, cr_win *w, u8 *out)
{
    pv->bs = 1u << blog;
    pv->blog = blog;
    cr_file f;
    int ok = !cr_file_open(&f, pv, s, off, size);
    for (u32 i = 0; ok && i < f.nb && i < 4; i++) {
        u64 st;
        u32 len, on;
        int raw;
        if (cr_block(&f, i, &st, &len, &raw)) ok = 0;
        else if (len && !raw) {
            ok = !cr_decode(&f, i, z, w, out, &on);
            break;
        }
    }
    gz_free(f.ptr);
    return ok;
}

static void detect_bs(cr_priv *pv, gz_archive *a, gz_src *s, gz_inflater **z, cr_win *w, u8 *out)
{
    static const u8 cand[] = { 12, 13, 14, 15, 16, 11, 10 };
    u32 best = 12;
    for (u32 k = 0; k < sizeof cand; k++) {
        u32 tested = 0, good = 1;
        for (u32 i = 0; i < a->n && tested < 8 && good; i++) {
            const gz_entry *e = &a->e[i];
            if (e->is_dir || e->is_link || e->usize <= 1024) continue;
            tested++;
            w->len = 0;
            good = bs_fits(pv, s, e->off, (u32)e->usize, cand[k], z, w, out);
        }
        if (good) { best = cand[k]; break; }
    }
    pv->blog = best;
    pv->bs = 1u << best;
    w->len = 0;
}

static int check_crc(cr_priv *pv, gz_src *s, gz_ctx *c, u32 want)
{
    u8 *buf = gz_ctx_buffer(c, 256u << 10);
    if (!buf) return GZ_E_NOMEM;
    u32 crc = 0;
    u64 pos = pv->base, crc_at = pv->base + 32;
    while (pos < pv->size) {
        if (gz_cancelled(c)) return GZ_E_CANCEL;
        u32 n = pv->size - pos < (256u << 10) ? (u32)(pv->size - pos) : (256u << 10);
        int r = gz_src_read_exact(s, pos, buf, n);
        if (r) return GZ_OK;                       /* short image: no verdict */
        if (crc_at >= pos && crc_at + 4 <= pos + n) __builtin_memset(buf + (crc_at - pos), 0, 4);
        crc = gz_crc32(crc, buf, n);
        pos += n;
    }
    pv->crc_bad = crc != want;
    return GZ_OK;
}

static int cr_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u8 h[512 + CR_SB_SIZE];
    u32 hn = s->size < sizeof h ? (u32)s->size : (u32)sizeof h;
    int r = gz_src_read_exact(s, 0, h, hn);
    if (r) return r;
    int sig, kind = hn >= CR_SB_SIZE ? sb_kind(h, &sig) : 0;
    u32 base = 0;
    if (!kind && hn >= 512 + CR_SB_SIZE && (kind = sb_kind(h + 512, &sig))) base = 512;
    if (!kind) return GZ_E_FORMAT;
    cr_priv *pv = (cr_priv *)gz_alloc(sizeof(cr_priv));
    if (!pv) return GZ_E_NOMEM;
    a->priv = pv;
    const u8 *sb = h + base;
    pv->be = kind == 2;
    pv->base = base;
    pv->flags = c32(pv, sb + 8);
    if (pv->flags & ~CR_FL_SUPPORTED) return GZ_E_METHOD;
    pv->size = s->size;
    if (pv->flags & CR_FL_V2) {
        u32 sz = c32(pv, sb + 4);
        if (sz < base + CR_SB_SIZE) return GZ_E_FORMAT;
        if (sz < pv->size) pv->size = sz;          /* trailing data is not part of the image */
    }
    cr_ino root;
    cr_inode(pv->be, sb + 64, &root);
    if ((root.mode & 0xF000) != 0x4000) return GZ_E_FORMAT;
    gz_arc_set_type(a, "CramFS");
    if ((pv->flags & CR_FL_V2) && pv->size <= CR_CRC_MAX && c32(pv, sb + 4) <= s->size &&
        (r = check_crc(pv, s, c, c32(pv, sb + 32))))
        return r;

    cr_walk w;
    __builtin_memset(&w, 0, sizeof w);
    w.a = a; w.c = c; w.pv = pv; w.s = s;
    w.budget = pv->size;
    w.names_max = pv->size < (64u << 20) ? (size_t)pv->size * 256 + (16u << 20) : (size_t)256 << 20;
    r = gz_fs1_tree_init(&w.t, GZ_NE_LEGACY, GZ_CP_UTF8);
    if (!r) {
        w.t.n[0].loc = (u64)root.off << 2;
        w.t.n[0].size = root.size;
        if (gz_fs1_set_add(&w.seen, w.t.n[0].loc) < 0) r = GZ_E_NOMEM;
    }
    for (u32 i = 0; !r && i < w.t.nn; i++) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        int rr = cr_dir(&w, (i32)i);
        if (rr == GZ_E_NOMEM || rr == GZ_E_CANCEL || rr == GZ_E_LIMIT || (rr && i == 0 && !a->n)) r = rr;
        if (c && c->progress && !(i & 63)) c->progress(c->progress_user, i, w.t.nn);
    }
    gz_fs1_tree_free(&w.t);
    gz_fs1_set_free(&w.seen);
    gz_free(w.buf);
    if (r) return r;

    /* block size, packed sizes and link targets */
    gz_inflater *z = 0;
    u8 *buf = (u8 *)gz_alloc(CR_WIN + (64u << 10));
    if (!buf) return GZ_E_NOMEM;
    cr_win win = { buf, CR_WIN, 0, 0 };
    u8 *out = buf + CR_WIN;
    detect_bs(pv, a, s, &z, &win, out);
    /* block tables read here: about the image size for real images; entries that share one
     * table (hostile) stop the scan instead of multiplying the work */
    u64 scan = pv->size * 2 + (1u << 20);
    for (u32 i = 0; i < a->n && !r; i++) {
        gz_entry *e = &a->e[i];
        if (e->is_dir || !e->usize) continue;
        u64 tb = (((u64)e->usize + pv->bs - 1) >> pv->blog) * 4;
        if (tb > scan) { e->csize = GZ_SIZE_UNKNOWN; continue; }
        scan -= tb;
        cr_file f;
        if (cr_file_open(&f, pv, s, e->off, (u32)e->usize)) { gz_free(f.ptr); continue; }
        u64 cs = (u64)f.nb * 4;
        for (u32 b = 0; b < f.nb; b++) {
            u64 st;
            u32 len;
            int raw;
            if (cr_block(&f, b, &st, &len, &raw)) { cs = GZ_SIZE_UNKNOWN; break; }
            cs += len;
        }
        e->csize = cs;
        if (e->is_link && e->usize <= pv->bs) {       /* target: the data of a one-block file */
            u32 on, lo;
            if (!cr_decode(&f, 0, &z, &win, out, &on) && on == e->usize) {
                r = gz_arc_raw_append(a, out, on, &lo);
                if (!r) { e->link_off = lo; e->link_len = on; e->usize = e->csize = 0; }
            }
        }
        gz_free(f.ptr);
    }
    if (z) gz_inflater_free(z);
    gz_free(buf);
    return r;
}

/* ---------------- extraction ---------------- */

static int cr_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    const cr_priv *pv = (const cr_priv *)a->priv;
    const gz_entry *e = &a->e[idx];
    int r = out->open(out, idx);
    if (r) return r;
    if (e->is_dir || (e->is_link && e->link_len) || !e->usize) return out->close(out, idx, GZ_OK);
    cr_file f;
    int st = cr_file_open(&f, pv, s, e->off, (u32)e->usize);
    u8 *buf = st ? 0 : gz_ctx_buffer(c, CR_WIN + pv->bs);
    gz_inflater *z = gz_ctx_inflater(c);
    if (!st && (!buf || !z)) st = GZ_E_NOMEM;
    cr_win win = { buf, CR_WIN, 0, 0 };
    for (u32 i = 0; !st && i < f.nb; i++) {
        if (gz_cancelled(c)) { st = GZ_E_CANCEL; break; }
        u32 on;
        if (!(st = cr_decode(&f, i, &z, &win, buf + CR_WIN, &on))) st = out->write(out, buf + CR_WIN, on);
    }
    gz_free(f.ptr);
    if (!st && pv->crc_bad) st = GZ_E_CRC;
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

/* ---------------- views ---------------- */

typedef struct {
    gz_src s;
    cr_priv pv;
    cr_file f;
    gz_inflater *z;
    cr_win w;
    u8 *blk;
    i64 cur;
} cr_view;

static int view_read(gz_src *src, u64 off, void *buf, u32 n, u32 *got)
{
    cr_view *v = (cr_view *)src;
    u8 *o = (u8 *)buf;
    *got = 0;
    if (off >= src->size) return GZ_OK;
    if (n > src->size - off) n = (u32)(src->size - off);
    while (n) {
        u32 b = (u32)(off >> v->pv.blog), in = (u32)(off & (v->pv.bs - 1)), on;
        if (v->cur != (i64)b) {
            v->cur = -1;
            int r = cr_decode(&v->f, b, &v->z, &v->w, v->blk, &on);
            if (r) return r;
            v->cur = b;
        }
        u64 bsz = src->size - ((u64)b << v->pv.blog);
        u32 have = (bsz < v->pv.bs ? (u32)bsz : v->pv.bs) - in, take = have < n ? have : n;
        __builtin_memcpy(o, v->blk + in, take);
        o += take;
        off += take;
        n -= take;
        *got += take;
    }
    return GZ_OK;
}

static void view_free(gz_src *src)
{
    cr_view *v = (cr_view *)src;
    if (v->z) gz_inflater_free(v->z);
    gz_free(v->f.ptr);
    gz_free(v->blk);
    gz_free(v);
}

static gz_src *cr_view_new(gz_archive *a, gz_src *s, u32 idx)
{
    const cr_priv *pv = (const cr_priv *)a->priv;
    const gz_entry *e = &a->e[idx];
    if (e->is_dir || e->is_link) return 0;
    if (!e->usize) return gz_src_sub(s, 0, 0);
    cr_view *v = (cr_view *)gz_alloc(sizeof(cr_view));
    if (!v) return 0;
    v->s.read_at = view_read;
    v->s.size = e->usize;
    v->s.free = view_free;
    v->pv = *pv;
    v->cur = -1;
    v->blk = (u8 *)gz_alloc(3 * pv->bs);           /* block + 2-block input window */
    v->w.p = v->blk ? v->blk + pv->bs : 0;
    v->w.cap = 2 * pv->bs;
    if (!v->blk || cr_file_open(&v->f, &v->pv, s, e->off, (u32)e->usize)) { view_free(&v->s); return 0; }
    return &v->s;
}

static void cr_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a; (void)e;
    const char *m = "Deflate";
    u32 i = 0;
    for (; m[i] && i + 1 < cap; i++) buf[i] = m[i];
    if (cap) buf[i] = 0;
}

GZ_FORMAT(gz_fmt_cramfs)
const gz_format gz_fmt_cramfs = {
    "CramFS", "cramfs cram img", 0, cr_probe, cr_open, cr_close, cr_extract, 0, 0, cr_method, cr_view_new, 0
};
