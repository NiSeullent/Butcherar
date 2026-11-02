/*
 * 고깃ZIP - compressed tarballs (TAR.GZ, TAR.BZ2, TAR.XZ, TAR.ZST) and single
 * compressed files (.gz, .bz2, .xz, .zst).
 *
 * Every writer is "input reader -> container encoder -> sink": the input is the
 * TAR generator (tar_write.h) or the one file, pulled by the codec through a
 * gz_stream_io read callback; the container code wraps the codec's output:
 *
 *   gzip   RFC 1952 member: header (original name + mtime for single files),
 *          raw Deflate (deflate_enc.h), CRC-32 + ISIZE trailer
 *   bzip2  the encoder's own stream (bzip2_enc.h)
 *   xz     stream header, LZMA2 blocks of at most 3 x dictionary (>= 1 MiB)
 *          with compressed/uncompressed sizes in their headers (the layout
 *          multi-threaded xz writes, so blocks can be decoded in parallel) and a
 *          CRC-64 check, index, footer. Store level: uncompressed LZMA2 chunks.
 *   zstd   one frame (zstd_enc.h) with XXH64 content checksum; single files also
 *          record their size in the frame header
 *
 * Levels (gz_wopts.level 0..9, method GZ_WM_STORE = level 0):
 *   gzip  Deflate level; 0 = stored blocks
 *   bzip2 block size 100k (0-1), 300k, 500k, 700k, 900k (5-9), like 7-Zip
 *   xz    LZMA2 preset 1..9 (xz -1..-9); 0 = stored; dict_size overrides
 *   zstd  0 store, 1 1, 2 1, 3 2, 4 3, 5 3, 6 7, 7 12, 8 16, 9 19 (zstd levels);
 *         dict_size sets the window
 *
 * Nothing seeks: write_at is never used, so the output can be a pipe.
 */
#include "gz_write.h"
#include "tar_write.h"
#include "crc32.h"
#include "crc64.h"
#include "deflate_enc.h"
#include "bzip2_enc.h"
#include "lzma_enc.h"
#include "zstd_enc.h"

enum { C_GZIP, C_BZIP2, C_XZ, C_ZSTD };

/* ---------------- plumbing ---------------- */

typedef int (*rd_fn)(void *ctx, u8 *buf, u32 cap, u32 *got);

/* one ctx for the codec's read (input) and write (sink) callbacks */
typedef struct pipe {
    rd_fn rd;
    void *rctx;
    gz_sink *out;
} pipe;

static int p_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    pipe *p = (pipe *)ctx;
    return p->rd(p->rctx, buf, cap, got);
}

static int p_write(void *ctx, const u8 *b, size_t n)
{
    return gz_sink_write(((pipe *)ctx)->out, b, n);
}

static int clamp_level(int l) { return l < 0 ? 5 : l > 9 ? 9 : l; }

static int is_store(const gz_wopts *o) { return o->method == GZ_WM_STORE || clamp_level(o->level) == 0; }

/* single input file: progress, cancel, errors; exact != GZ_SIZE_UNKNOWN delivers
 * exactly that many bytes (cut when the file grew, zero padded when it shrank) */
typedef struct fsrc {
    const gz_wopts *o;
    const gz_witem *it;
    gz_wsrc *w;
    gz_ctx *c;
    u64 done, exact;
    int bad;
} fsrc;

static int fs_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    fsrc *f = (fsrc *)ctx;
    const gz_wopts *o = f->o;
    *got = 0;
    if ((o->cancel && *o->cancel) || gz_cancelled(f->c)) return GZ_E_CANCEL;
    if (f->exact != GZ_SIZE_UNKNOWN) {
        if (f->done >= f->exact) return GZ_OK;
        if (f->exact - f->done < cap) cap = (u32)(f->exact - f->done);
    }
    u32 g = 0;
    if (!f->bad) {
        int r = f->w->read(f->w, buf, cap, &g);
        if (r == GZ_E_CANCEL) return r;
        if (r) {
            /* nothing to skip to in a single-file stream: report and abort */
            if (o->on_error) o->on_error(o->user, f->it, r);
            return r;
        }
        if (g > cap) g = cap;
        if (!g && f->exact != GZ_SIZE_UNKNOWN) {
            /* shrank below the size in the header: keep the stream valid */
            f->bad = GZ_E_TRUNC;
            r = o->on_error ? o->on_error(o->user, f->it, GZ_E_TRUNC) : GZ_E_TRUNC;
            if (r) return r;
        }
    }
    if (f->bad) {
        g = cap;
        __builtin_memset(buf, 0, g);
    }
    f->done += g;
    if (o->progress && g) o->progress(o->user, f->done, f->it->size);
    *got = g;
    return GZ_OK;
}

/* ---------------- gzip ---------------- */

static int put_gzip(const gz_wopts *o, pipe *p, const u8 *name, u32 nlen, u32 mtime)
{
    int lv = is_store(o) ? 0 : clamp_level(o->level);
    u8 h[10];
    h[0] = 0x1f;
    h[1] = 0x8b;
    h[2] = 8;
    h[3] = nlen ? 8 : 0;                         /* FNAME */
    wr32(h + 4, mtime);
    h[8] = lv >= 9 ? 2 : lv == 1 ? 4 : 0;        /* XFL: slowest / fastest */
#if defined(GZ_OS_WIN)
    h[9] = 0;                                    /* FAT/NTFS (Win32) */
#else
    h[9] = 3;                                    /* Unix */
#endif
    int r = gz_sink_write(p->out, h, 10);
    if (!r && nlen) r = gz_sink_write(p->out, name, nlen + 1);     /* with its NUL */
    if (r) return r;
    gz_deflate_enc *e = gz_deflate_enc_new(lv);
    if (!e) return GZ_E_NOMEM;
    gz_stream_io io = { p_read, p_write, p };
    u32 crc = 0;
    u64 in = 0;
    r = gz_deflate_encode(e, &io, &crc, &in, 0);
    gz_deflate_enc_free(e);
    if (r) return r;
    u8 t[8];
    wr32(t, crc);
    wr32(t + 4, (u32)in);
    return gz_sink_write(p->out, t, 8);
}

/* ---------------- bzip2 ---------------- */

static int put_bzip2(const gz_wopts *o, pipe *p)
{
    static const u8 blk[10] = { 1, 1, 3, 5, 7, 9, 9, 9, 9, 9 };
    int lv = blk[clamp_level(o->level)];
    if (o->dict_size) {                          /* block size in bytes, like 7-Zip -md */
        u32 b = o->dict_size / 100000u;
        lv = b < 1 ? 1 : b > 9 ? 9 : (int)b;
    }
    gz_bzip2_enc *e = gz_bzip2_enc_new(lv);
    if (!e) return GZ_E_NOMEM;
    gz_stream_io io = { p_read, p_write, p };
    int r = gz_bzip2_encode(e, &io);
    gz_bzip2_enc_free(e);
    return r;
}

/* ---------------- xz ---------------- */

#define XZ_STORE_BLOCK  (1u << 20)
#define XZ_STASH        (64u << 10)
#if UINTPTR_MAX > 0xFFFFFFFFu
#define XZ_BLOCK_MAX    ((u64)1 << 30)
#else
#define XZ_BLOCK_MAX    ((u64)64 << 20)
#endif

typedef struct xzw {
    pipe *p;
    /* input: a small look-ahead (to see whether another block follows) */
    u8 *stash;
    u32 sn, sp;
    int eof;
    /* current block */
    u64 blimit, bin, crc64;
    /* compressed block */
    u8 *ob;
    size_t on, ocap;
    /* index records: unpadded size, uncompressed size */
    u64 *rec;
    u32 nrec, rcap;
} xzw;

/* block input: stash first, then the source, at most blimit bytes */
static int xz_bread(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    xzw *x = (xzw *)ctx;
    *got = 0;
    if (x->bin >= x->blimit) return GZ_OK;
    if (x->blimit - x->bin < cap) cap = (u32)(x->blimit - x->bin);
    u32 g = 0;
    if (x->sp < x->sn) {
        g = x->sn - x->sp < cap ? x->sn - x->sp : cap;
        __builtin_memcpy(buf, x->stash + x->sp, g);
        x->sp += g;
    } else if (!x->eof) {
        int r = x->p->rd(x->p->rctx, buf, cap, &g);
        if (r) return r;
        if (g > cap) g = cap;
        if (!g) x->eof = 1;
    }
    x->crc64 = gz_crc64(x->crc64, buf, g);
    x->bin += g;
    *got = g;
    return GZ_OK;
}

static int xz_bwrite(void *ctx, const u8 *b, size_t n)
{
    xzw *x = (xzw *)ctx;
    if (n > x->ocap - x->on) {
        size_t nc = x->ocap ? x->ocap : (256u << 10);
        while (nc - x->on < n) {
            if (nc > ((size_t)-1) / 2) return GZ_E_NOMEM;
            nc *= 2;
        }
        u8 *np = (u8 *)gz_realloc(x->ob, nc);
        if (!np) return GZ_E_NOMEM;
        x->ob = np;
        x->ocap = nc;
    }
    __builtin_memcpy(x->ob + x->on, b, n);
    x->on += n;
    return GZ_OK;
}

/* is there more input? (fills the stash) */
static int xz_more(xzw *x, int *more)
{
    *more = 0;
    if (x->sp < x->sn) { *more = 1; return GZ_OK; }
    x->sp = x->sn = 0;
    while (!x->eof && !x->sn) {
        u32 g = 0;
        int r = x->p->rd(x->p->rctx, x->stash, XZ_STASH, &g);
        if (r) return r;
        if (g > XZ_STASH) g = XZ_STASH;
        if (!g) x->eof = 1;
        x->sn = g;
    }
    *more = x->sn != 0;
    return GZ_OK;
}

static u32 put_vli(u8 *o, u64 v)
{
    u32 n = 0;
    while (v >= 0x80) { o[n++] = (u8)(v | 0x80); v >>= 7; }
    o[n++] = (u8)v;
    return n;
}

/* LZMA2 stream of uncompressed chunks (store level) */
static int xz_store_block(xzw *x)
{
    u8 *buf = (u8 *)gz_alloc(65536);
    if (!buf) return GZ_E_NOMEM;
    int r = GZ_OK, first = 1;
    for (;;) {
        u32 n = 0, g;
        while (n < 65536) {
            r = xz_bread(x, buf + n, 65536 - n, &g);
            if (r || !g) break;
            n += g;
        }
        if (r || !n) break;
        u8 c[3] = { first ? 1 : 2, (u8)((n - 1) >> 8), (u8)(n - 1) };   /* 1: dictionary reset */
        first = 0;
        r = xz_bwrite(x, c, 3);
        if (!r) r = xz_bwrite(x, buf, n);
        if (r) break;
    }
    gz_free(buf);
    if (!r) {
        u8 end = 0;
        r = xz_bwrite(x, &end, 1);
    }
    return r;
}

static int put_xz(const gz_wopts *o, pipe *p, u64 size_hint)
{
    int store = is_store(o);
    gz_lzma_enc_opts lo;
    gz_lzma_enc_opts_init(&lo, clamp_level(o->level));
    if (o->dict_size) lo.dict_size = o->dict_size < GZ_MF_DICT_MIN ? GZ_MF_DICT_MIN : o->dict_size;
    u64 B = store ? XZ_STORE_BLOCK : (u64)lo.dict_size * 3;
    if (B < (1u << 20)) B = 1u << 20;
    if (B > XZ_BLOCK_MAX) B = XZ_BLOCK_MAX;
    lo.size_hint = size_hint && size_hint < B ? size_hint : B;
    gz_lzma_enc *e = 0;
    if (!store) {
        int r = gz_lzma_enc_check(&lo, 1);
        if (r) return r;
        e = gz_lzma_enc_new(&lo);
        if (!e) return GZ_E_NOMEM;
    }
    xzw x;
    __builtin_memset(&x, 0, sizeof x);
    x.p = p;
    x.stash = (u8 *)gz_alloc(XZ_STASH);
    int r = x.stash ? GZ_OK : GZ_E_NOMEM;

    u8 h[32];
    static const u8 magic[6] = { 0xFD, '7', 'z', 'X', 'Z', 0 };
    __builtin_memcpy(h, magic, 6);
    h[6] = 0;
    h[7] = 4;                                    /* check: CRC-64 */
    wr32(h + 8, gz_crc32(0, h + 6, 2));
    if (!r) r = gz_sink_write(p->out, h, 12);

    while (!r) {
        int more;
        r = xz_more(&x, &more);
        if (r || !more) break;
        x.blimit = B;
        x.bin = 0;
        x.crc64 = 0;
        x.on = 0;
        u8 dprop = 0;
        if (store) {
            r = xz_store_block(&x);
        } else {
            gz_stream_io io = { xz_bread, xz_bwrite, &x };
            r = gz_lzma2_encode(e, &io, &dprop);
        }
        if (r) break;
        /* block header: size, flags (1 filter, both sizes), sizes, LZMA2 filter, padding, CRC-32 */
        u32 k = 2;
        h[1] = 0xC0;
        k += put_vli(h + k, x.on);
        k += put_vli(h + k, x.bin);
        h[k++] = 0x21;
        h[k++] = 1;
        h[k++] = dprop;
        while (k & 3) h[k++] = 0;
        h[0] = (u8)((k + 4) / 4 - 1);
        wr32(h + k, gz_crc32(0, h, k));
        k += 4;
        r = gz_sink_write(p->out, h, k);
        if (!r) r = gz_sink_write(p->out, x.ob, x.on);
        u8 t[12] = { 0 };
        u32 pad = (u32)((4 - (x.on & 3)) & 3);
        wr64(t + pad, x.crc64);
        if (!r) r = gz_sink_write(p->out, t, pad + 8);
        if (r) break;
        if (x.nrec == x.rcap) {
            u32 nc = x.rcap ? x.rcap * 2 : 64;
            u64 *nr = (u64 *)gz_realloc(x.rec, (size_t)nc * 2 * sizeof(u64));
            if (!nr) { r = GZ_E_NOMEM; break; }
            x.rec = nr;
            x.rcap = nc;
        }
        x.rec[2 * x.nrec] = k + x.on + 8;        /* unpadded size */
        x.rec[2 * x.nrec + 1] = x.bin;
        x.nrec++;
    }

    /* index (built in pieces, CRC-32 over all of it) and stream footer */
    if (!r) {
        u32 crc = 0;
        u64 isize = 0;
        u32 k = 0;
        h[k++] = 0;
        k += put_vli(h + k, x.nrec);
        for (u32 i = 0; !r && i <= x.nrec; i++) {
            if (i < x.nrec) {
                k += put_vli(h + k, x.rec[2 * i]);
                k += put_vli(h + k, x.rec[2 * i + 1]);
            } else {
                while ((isize + k) & 3) h[k++] = 0;
            }
            crc = gz_crc32(crc, h, k);
            r = gz_sink_write(p->out, h, k);
            isize += k;
            k = 0;
        }
        if (!r) {
            wr32(h, crc);
            isize += 4;
            wr32(h + 8, (u32)(isize / 4 - 1));     /* backward size */
            h[12] = 0;
            h[13] = 4;
            wr32(h + 4, gz_crc32(0, h + 8, 6));
            h[14] = 'Y';
            h[15] = 'Z';
            r = gz_sink_write(p->out, h, 16);
        }
    }
    gz_lzma_enc_free(e);
    gz_free(x.stash);
    gz_free(x.ob);
    gz_free(x.rec);
    return r;
}

/* ---------------- zstd ---------------- */

static int put_zstd(const gz_wopts *o, pipe *p, u64 size_hint, u64 content_size)
{
    static const u8 map[10] = { 0, 1, 1, 2, 3, 3, 7, 12, 16, 19 };
    gz_zstd_enc_opts zo;
    gz_zstd_enc_opts_init(&zo, is_store(o) ? 0 : map[clamp_level(o->level)]);
    if (o->dict_size) {
        u32 wl = GZ_ZSTD_WINDOWLOG_MIN;
        while (wl < GZ_ZSTD_WINDOWLOG_MAX && ((u64)1 << wl) < o->dict_size) wl++;
        zo.window_log = wl;
    }
    zo.size_hint = size_hint;
    gz_zstd_enc *e = gz_zstd_enc_new(&zo);
    if (!e) return GZ_E_NOMEM;
    gz_stream_io io = { p_read, p_write, p };
    int r = gz_zstd_encode(e, &io, content_size);
    gz_zstd_enc_free(e);
    return r;
}

/* ---------------- writers ---------------- */

static int tarball(int kind, const gz_wopts *o, const gz_witem *items, u32 n, gz_sink *out, gz_ctx *c)
{
    gz_tar_reader *t = gz_tar_reader_new(o, items, n, c);
    if (!t) return GZ_E_NOMEM;
    pipe p = { gz_tar_reader_read, t, out };
    u64 hint = gz_tar_size_estimate(items, n);
    int r;
    switch (kind) {
    case C_GZIP:  r = put_gzip(o, &p, 0, 0, 0); break;
    case C_BZIP2: r = put_bzip2(o, &p); break;
    case C_XZ:    r = put_xz(o, &p, hint); break;
    default:      r = put_zstd(o, &p, hint, GZ_SIZE_UNKNOWN); break;
    }
    gz_tar_reader_free(t);
    return r;
}

static int single(int kind, const gz_wopts *o, const gz_witem *items, u32 n, gz_sink *out, gz_ctx *c)
{
    if (n != 1 || items[0].is_dir || items[0].is_link) {
        /* one file only: blame the extra item (or the directory / link) */
        if (n && o->on_error) o->on_error(o->user, &items[n > 1 ? 1 : 0], GZ_E_METHOD);
        return GZ_E_METHOD;
    }
    const gz_witem *it = &items[0];
    fsrc f;
    __builtin_memset(&f, 0, sizeof f);
    f.o = o;
    f.it = it;
    f.c = c;
    f.exact = GZ_SIZE_UNKNOWN;
    int r = o->open_item(o->user, it, &f.w);
    if (r) {
        if (r != GZ_E_CANCEL && o->on_error) o->on_error(o->user, it, r);
        return r;
    }
    pipe p = { fs_read, &f, out };
    if (kind == C_GZIP) {
        /* original name (last path component) and modification time */
        const gzch *nm = it->name, *s;
        for (s = nm; *s; s++) if (*s == '/') nm = s + 1;
        size_t wl = gz_wcslen(nm);
        u8 *name = 0;
        u32 nl = 0;
        if (wl && wl < 32768) {
            name = (u8 *)gz_alloc(wl * 3 + 1);
            if (name) nl = gz_tar_name_utf8(nm, wl, name);
        }
        i64 t = it->mtime ? gz_filetime_to_unix(it->mtime) : 0;
        u32 mt = t > 0 && t <= 0xFFFFFFFFll ? (u32)t : 0;
        r = put_gzip(o, &p, name, nl, mt);
        gz_free(name);
    } else if (kind == C_BZIP2) {
        r = put_bzip2(o, &p);
    } else if (kind == C_XZ) {
        r = put_xz(o, &p, it->size);
    } else {
        f.exact = it->size;
        r = put_zstd(o, &p, it->size, it->size);
    }
    o->close_item(o->user, it, f.w);
    if (!r && o->progress) o->progress(o->user, f.done, it->size);
    return r;
}

static int w_tgz(const gz_wopts *o, const gz_witem *i, u32 n, gz_sink *k, gz_ctx *c) { return tarball(C_GZIP, o, i, n, k, c); }
static int w_tbz(const gz_wopts *o, const gz_witem *i, u32 n, gz_sink *k, gz_ctx *c) { return tarball(C_BZIP2, o, i, n, k, c); }
static int w_txz(const gz_wopts *o, const gz_witem *i, u32 n, gz_sink *k, gz_ctx *c) { return tarball(C_XZ, o, i, n, k, c); }
static int w_tzs(const gz_wopts *o, const gz_witem *i, u32 n, gz_sink *k, gz_ctx *c) { return tarball(C_ZSTD, o, i, n, k, c); }
static int w_gz(const gz_wopts *o, const gz_witem *i, u32 n, gz_sink *k, gz_ctx *c) { return single(C_GZIP, o, i, n, k, c); }
static int w_bz(const gz_wopts *o, const gz_witem *i, u32 n, gz_sink *k, gz_ctx *c) { return single(C_BZIP2, o, i, n, k, c); }
static int w_xz(const gz_wopts *o, const gz_witem *i, u32 n, gz_sink *k, gz_ctx *c) { return single(C_XZ, o, i, n, k, c); }
static int w_zs(const gz_wopts *o, const gz_witem *i, u32 n, gz_sink *k, gz_ctx *c) { return single(C_ZSTD, o, i, n, k, c); }

#define M(x) (1u << GZ_WM_##x)
#define M_GZ   (M(DEFAULT) | M(STORE) | M(DEFLATE))
#define M_BZ2  (M(DEFAULT) | M(BZIP2))
#define M_XZ   (M(DEFAULT) | M(STORE) | M(LZMA2))
#define M_ZST  (M(DEFAULT) | M(STORE) | M(ZSTD))

GZ_WRITER(gz_wr_tgz)
const gz_writer gz_wr_tgz = { GZ_WF_TGZ, "TAR.GZ", "tar.gz", M_GZ, 0, w_tgz };
GZ_WRITER(gz_wr_tbz2)
const gz_writer gz_wr_tbz2 = { GZ_WF_TBZ2, "TAR.BZ2", "tar.bz2", M_BZ2, 0, w_tbz };
GZ_WRITER(gz_wr_txz)
const gz_writer gz_wr_txz = { GZ_WF_TXZ, "TAR.XZ", "tar.xz", M_XZ, 0, w_txz };
GZ_WRITER(gz_wr_tzst)
const gz_writer gz_wr_tzst = { GZ_WF_TZST, "TAR.ZST", "tar.zst", M_ZST, 0, w_tzs };
GZ_WRITER(gz_wr_gz)
const gz_writer gz_wr_gz = { GZ_WF_GZ, "GZIP", "gz", M_GZ, 0, w_gz };
GZ_WRITER(gz_wr_bz2)
const gz_writer gz_wr_bz2 = { GZ_WF_BZ2, "BZIP2", "bz2", M_BZ2, 0, w_bz };
GZ_WRITER(gz_wr_xz)
const gz_writer gz_wr_xz = { GZ_WF_XZ, "XZ", "xz", M_XZ, 0, w_xz };
GZ_WRITER(gz_wr_zst)
const gz_writer gz_wr_zst = { GZ_WF_ZST, "ZSTD", "zst", M_ZST, 0, w_zs };
