/*
 * 고깃ZIP - XZ (.xz .txz), LZMA-alone (.lzma) and lzip (.lz .tlz) streams
 *
 *   .xz   concatenated streams with stream padding; per stream: header flags,
 *         blocks (header CRC32, filter chain = up to three BCJ / Delta filters
 *         in front of LZMA2, optional compressed / uncompressed size fields,
 *         block padding, check None / CRC32 / CRC64 / SHA-256), the index
 *         (record count, every (unpadded, uncompressed) pair, padding, CRC32)
 *         and the footer (backward size, flags, CRC32) are all verified.
 *   .lzma 13-byte header (lc/lp/pb, dictionary, size or -1 = end marker).
 *   .lz   members "LZIP" + version + coded dictionary, LZMA (lc 3 lp 0 pb 2)
 *         ending with an end marker, trailer CRC32 / data size / member size.
 * ".tlz" is both lzip and LZMA tarball: the content (probe) decides.
 *
 * Decoding is a single forward pass over a pull reader, so the same code
 * serves the stream formats (bounded reader over a gz_src) and ZIP method 95
 * (decrypting entry reader). The LZMA decoder reads ahead of the end of its
 * stream; the input buffer keeps the last XI_KEEP consumed bytes so the
 * read-ahead is pushed back exactly (in_used) and parsing continues there.
 */
#include "streamfmt.h"
#include "xz.h"
#include "bcj.h"
#include "crc32.h"
#include "crc64.h"
#include "sha256.h"

#define XI_CAP      (256u << 10)       /* bytes pulled per read                    */
#define XI_KEEP     (96u << 10)        /* consumed bytes kept for push-back (> LZMA read-ahead) */
#define XZ_HDR_MAX  1024u              /* largest block header                     */
#define XZ_INFO_MAX (8u << 20)         /* info(): largest index read               */
#define XZ_INFO_STREAMS 100000u

static const u8 k_xz_magic[6] = { 0xFD, '7', 'z', 'X', 'Z', 0 };
/* bytes of the block check for each check type (xz spec 2.1.1.2) */
static const u8 k_check_size[16] = { 0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64 };

enum { K_XZ = 0, K_LZMA, K_LZIP };
enum { CK_NONE = 0, CK_CRC32 = 1, CK_CRC64 = 4, CK_SHA256 = 10 };

/* per-thread state in GZ_SLOT_LZMA */
typedef struct xz_cache {
    gz_lzma_dec *lz;
    u8 *ibuf;                          /* XI_KEEP + XI_CAP, allocated on first use */
    gz_filter_push fp[3];              /* non-last filters of a block              */
} xz_cache;

static void *xz_cache_new(void)
{
    xz_cache *k = (xz_cache *)gz_alloc(sizeof(xz_cache));
    if (!k) return 0;
    if (!(k->lz = gz_lzma_dec_new())) { gz_free(k); return 0; }
    return k;
}

static void xz_cache_free(void *p)
{
    xz_cache *k = (xz_cache *)p;
    if (!k) return;
    gz_lzma_dec_free(k->lz);
    gz_free(k->ibuf);
    gz_free(k);
}

gz_lzma_dec *gz_xz_lzma_dec(gz_ctx *c)
{
    xz_cache *k = (xz_cache *)gz_ctx_slot(c, GZ_SLOT_LZMA, xz_cache_new, xz_cache_free);
    if (!k) return 0;
    gz_lzma_dec_set_flags(k->lz, 0);
    gz_lzma_dec_set_limit(k->lz, 0);
    return k->lz;
}

/* ---------------- decoder state ---------------- */

typedef struct xzd {
    /* input: buf[pos..len) buffered, buf[0..pos) consumed (kept for push-back) */
    const gz_stream_io *io;
    u8 *buf;
    u32 pos, len;
    int eof;
    u64 total;                 /* bytes pulled from io                          */
    u64 lim;                   /* xd_read hands out at most this many more bytes */
    u64 handed;                /* bytes handed out by xd_read for this stream   */
    /* output */
    int (*sink)(void *user, const u8 *p, size_t n);
    void *user;
    gz_filter_push *head;      /* first filter after the decoder, NULL = none   */
    u64 produced, ulimit;
    u32 ck;                    /* check type                                    */
    u32 crc32;
    u64 crc64;
    gz_sha256 sha;
    xz_cache *k;
    gz_ctx *c;
} xzd;

static u32 xin_avail(const xzd *z) { return z->len - z->pos; }
static u64 xin_tell(const xzd *z) { return z->total - xin_avail(z); }

/* Buffer at least need (<= 4096) bytes unless the input ends first. */
static int xin_fill(xzd *z, u32 need)
{
    while (xin_avail(z) < need && !z->eof) {
        if (z->pos > XI_KEEP) {
            u32 from = z->pos - XI_KEEP;
            __builtin_memmove(z->buf, z->buf + from, z->len - from);
            z->pos -= from;
            z->len -= from;
        }
        u32 cap = XI_KEEP + XI_CAP - z->len, got = 0;
        int r = z->io->read(z->io->ctx, z->buf + z->len, cap, &got);
        if (r) return r;
        if (got > cap) return GZ_E_IO;
        if (!got) { z->eof = 1; break; }
        z->len += got;
        z->total += got;
    }
    return GZ_OK;
}

static int xin_need(xzd *z, u32 n)
{
    int r = xin_fill(z, n);
    if (r) return r;
    return xin_avail(z) < n ? GZ_E_TRUNC : GZ_OK;
}

/* gz_stream_io.read for the LZMA decoder */
static int xd_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    xzd *z = (xzd *)ctx;
    *got = 0;
    if (!z->lim) return GZ_OK;
    if (z->pos == z->len) {
        int r = xin_fill(z, 1);
        if (r) return r;
        if (z->pos == z->len) return GZ_OK;
    }
    u32 n = xin_avail(z);
    if (n > cap) n = cap;
    if (n > z->lim) n = (u32)z->lim;
    __builtin_memcpy(buf, z->buf + z->pos, n);
    z->pos += n;
    z->lim -= n;
    z->handed += n;
    *got = n;
    return GZ_OK;
}

/* the decoder consumed only `used` of the bytes handed out: push the rest back */
static int xin_unread(xzd *z, u64 used)
{
    if (used > z->handed) return GZ_E_DATA;
    u64 back = z->handed - used;
    if (back > z->pos) return GZ_E_DATA;      /* cannot happen: XI_KEEP > read-ahead */
    z->pos -= (u32)back;
    return GZ_OK;
}

/* final output stage: size limit, check, sink */
static int xd_out(void *ctx, const u8 *p, size_t n)
{
    xzd *z = (xzd *)ctx;
    if (n > z->ulimit - z->produced) return GZ_E_DATA;
    z->produced += n;
    switch (z->ck) {
    case CK_CRC32:  z->crc32 = gz_crc32(z->crc32, p, n); break;
    case CK_CRC64:  z->crc64 = gz_crc64(z->crc64, p, n); break;
    case CK_SHA256: gz_sha256_update(&z->sha, p, n); break;
    }
    return z->sink(z->user, p, n);
}

/* gz_stream_io.write for the LZMA decoder */
static int xd_write(void *ctx, const u8 *p, size_t n)
{
    xzd *z = (xzd *)ctx;
    return z->head ? gz_filter_push_write(z->head, p, n) : xd_out(z, p, n);
}

static void xd_start(xzd *z, u32 ck, u64 ulimit, u64 lim)
{
    z->ck = ck;
    z->crc32 = 0;
    z->crc64 = 0;
    if (ck == CK_SHA256) gz_sha256_init(&z->sha);
    z->produced = 0;
    z->ulimit = ulimit;
    z->lim = lim;
    z->handed = 0;
}

/* ---------------- .xz ---------------- */

/* Variable-length integer (1..9 bytes, minimal encoding) from p[*at..n). */
static int vli_get(const u8 *p, u32 n, u32 *at, u64 *v)
{
    u64 x = 0;
    u32 i = *at;
    for (u32 k = 0; k < 9; k++, i++) {
        if (i >= n) return GZ_E_TRUNC;
        u32 b = p[i];
        x |= (u64)(b & 0x7F) << (7 * k);
        if (!(b & 0x80)) {
            if (!b && k) return GZ_E_DATA;          /* not minimally encoded */
            *at = i + 1;
            *v = x;
            return GZ_OK;
        }
    }
    return GZ_E_DATA;
}

/* VLI from the input, CRC32 of its bytes added to *crc */
static int xin_vli(xzd *z, u64 *v, u32 *crc)
{
    int r = xin_fill(z, 9);
    if (r) return r;
    u32 at = 0;
    const u8 *p = z->buf + z->pos;
    r = vli_get(p, xin_avail(z), &at, v);
    if (r) return r;
    *crc = gz_crc32(*crc, p, at);
    z->pos += at;
    return GZ_OK;
}

/* Running summary of the blocks of a stream, compared with the index records. */
typedef struct { u64 n, hash; } xz_recs;

static void rec_add(xz_recs *s, u64 unpadded, u64 usize)
{
    u8 b[16];
    wr64(b, unpadded);
    wr64(b + 8, usize);
    s->hash = gz_crc64(s->hash, b, 16);
    s->n++;
}

static int xz_block(xzd *z, xz_recs *rs)
{
    int r = xin_fill(z, XZ_HDR_MAX);
    if (r) return r;
    const u8 *h = z->buf + z->pos;
    u32 hs = ((u32)h[0] + 1) * 4;
    if (xin_avail(z) < hs) return GZ_E_TRUNC;
    if (gz_crc32(0, h, hs - 4) != rd32(h + hs - 4)) return GZ_E_CRC;
    u32 fl = h[1], end = hs - 4, at = 2;
    if (fl & 0x3C) return GZ_E_METHOD;              /* reserved flags: unknown fields */
    u64 csize = GZ_SIZE_UNKNOWN, usize = GZ_SIZE_UNKNOWN;
    if ((fl & 0x40) && (vli_get(h, end, &at, &csize) || !csize)) return GZ_E_DATA;
    if ((fl & 0x80) && vli_get(h, end, &at, &usize)) return GZ_E_DATA;
    u32 nf = (fl & 3) + 1;
    int type[3] = { 0, 0, 0 };
    u32 param[3] = { 0, 0, 0 };
    u8 dprop = 0;
    for (u32 f = 0; f < nf; f++) {
        u64 id, ps;
        if (vli_get(h, end, &at, &id) || vli_get(h, end, &at, &ps) || ps > end - at) return GZ_E_DATA;
        const u8 *pp = h + at;
        at += (u32)ps;
        int t = gz_bcj_from_xz_id(id);
        if (f == nf - 1) {                          /* last filter: LZMA2 */
            if (id != 0x21) return t ? GZ_E_DATA : GZ_E_METHOD;
            if (ps != 1 || pp[0] > 40) return GZ_E_DATA;
            dprop = pp[0];
        } else {                                    /* BCJ family or Delta */
            if (!t) return id == 0x21 ? GZ_E_DATA : GZ_E_METHOD;
            u32 prm = 0;
            if (t == GZ_BCJ_DELTA) {
                if (ps != 1) return GZ_E_DATA;
                prm = (u32)pp[0] + 1;
            } else if (ps == 4) {
                prm = rd32(pp);
                if (prm & (gz_bcj_align(t) - 1)) return GZ_E_METHOD;
            } else if (ps) {
                return GZ_E_DATA;
            }
            type[f] = t;
            param[f] = prm;
        }
    }
    for (; at < end; at++) if (h[at]) return GZ_E_METHOD;   /* header padding */
    z->pos += hs;

    /* decoder -> filter nf-2 -> ... -> filter 0 -> check -> sink */
    z->head = 0;
    for (u32 f = 0; f + 1 < nf; f++) {
        if (!f) gz_filter_push_init(&z->k->fp[0], type[0], param[0], 0, xd_out, z);
        else gz_filter_push_init(&z->k->fp[f], type[f], param[f], 0, gz_filter_push_write, &z->k->fp[f - 1]);
        z->head = &z->k->fp[f];
    }
    xd_start(z, z->ck, usize, csize);
    gz_stream_io io = { xd_read, xd_write, z };
    u64 used = 0;
    r = gz_lzma2_decode(z->k->lz, dprop, &io, usize, &used);
    for (u32 f = nf - 1; !r && f-- > 0;) r = gz_filter_push_finish(&z->k->fp[f]);
    z->head = 0;
    if (r) return r == GZ_E_TRUNC && !z->lim ? GZ_E_DATA : r;   /* shorter than its size field */
    if ((r = xin_unread(z, used))) return r;
    if ((csize != GZ_SIZE_UNKNOWN && used != csize) || (usize != GZ_SIZE_UNKNOWN && z->produced != usize))
        return GZ_E_DATA;

    /* block padding + check */
    u64 unpadded = hs + used;
    u32 pad = (u32)(-unpadded & 3), cs = k_check_size[z->ck];
    if ((r = xin_need(z, pad + cs))) return r;
    const u8 *p = z->buf + z->pos;
    for (u32 i = 0; i < pad; i++) if (p[i]) return GZ_E_DATA;
    p += pad;
    if (z->ck == CK_CRC32 && rd32(p) != z->crc32) return GZ_E_CRC;
    if (z->ck == CK_CRC64 && rd64(p) != z->crc64) return GZ_E_CRC;
    if (z->ck == CK_SHA256) {
        u8 dg[32];
        gz_sha256_final(&z->sha, dg);
        if (__builtin_memcmp(dg, p, 32)) return GZ_E_CRC;
    }
    z->pos += pad + cs;
    rec_add(rs, unpadded + cs, z->produced);
    return GZ_OK;
}

/* index (the indicator byte is at the read position) + stream footer */
static int xz_index_footer(xzd *z, const xz_recs *rs, const u8 *flags)
{
    u64 start = xin_tell(z), cnt;
    u32 crc = gz_crc32(0, z->buf + z->pos, 1);
    z->pos++;
    int r = xin_vli(z, &cnt, &crc);
    if (r) return r;
    if (cnt != rs->n) return GZ_E_DATA;
    xz_recs got = { 0, 0 };
    for (u64 i = 0; i < cnt; i++) {
        if (!(i & 0xFFFF) && gz_cancelled(z->c)) return GZ_E_CANCEL;
        u64 unp, us;
        if ((r = xin_vli(z, &unp, &crc)) || (r = xin_vli(z, &us, &crc))) return r;
        if (unp < 5) return GZ_E_DATA;
        rec_add(&got, unp, us);
    }
    if (got.hash != rs->hash) return GZ_E_DATA;
    u64 size = xin_tell(z) - start;
    u32 pad = (u32)(-size & 3);
    if ((r = xin_need(z, pad + 4 + 12))) return r;
    const u8 *p = z->buf + z->pos;
    for (u32 i = 0; i < pad; i++) if (p[i]) return GZ_E_DATA;
    crc = gz_crc32(crc, p, pad);
    if (crc != rd32(p + pad)) return GZ_E_CRC;
    size += pad + 4;
    const u8 *f = p + pad + 4;                       /* footer */
    if (f[10] != 'Y' || f[11] != 'Z') return GZ_E_DATA;
    if (gz_crc32(0, f + 4, 6) != rd32(f)) return GZ_E_CRC;
    if (((u64)rd32(f + 4) + 1) * 4 != size || f[8] != flags[0] || f[9] != flags[1]) return GZ_E_DATA;
    z->pos += pad + 4 + 12;
    return GZ_OK;
}

static int xz_run(xzd *z)
{
    for (int first = 1;; first = 0) {
        int r = xin_fill(z, 12);
        if (r) return r;
        const u8 *h = z->buf + z->pos;
        u32 av = xin_avail(z);
        if (av < 6 || __builtin_memcmp(h, k_xz_magic, 6))
            return first ? GZ_E_FORMAT : GZ_OK;      /* trailing data after a stream */
        if (av < 12) return GZ_E_TRUNC;
        if (gz_crc32(0, h + 6, 2) != rd32(h + 8)) return GZ_E_CRC;
        if (h[6] || (h[7] & 0xF0)) return GZ_E_METHOD;
        u8 flags[2] = { h[6], h[7] };
        z->ck = h[7] & 0x0F;
        z->pos += 12;
        xz_recs rs = { 0, 0 };
        for (;;) {
            if (gz_cancelled(z->c)) return GZ_E_CANCEL;
            if ((r = xin_need(z, 1))) return r;
            if (!z->buf[z->pos]) break;              /* index indicator */
            if ((r = xz_block(z, &rs))) return r;
        }
        if ((r = xz_index_footer(z, &rs, flags))) return r;
        /* stream padding: zero bytes in groups of four, then the end, another
         * stream or (ignored) trailing data */
        for (;;) {
            if ((r = xin_fill(z, 4))) return r;
            u32 av = xin_avail(z);
            const u8 *p = z->buf + z->pos;
            u32 i = 0;
            while (i + 4 <= av && !rd32(p + i)) i += 4;
            z->pos += i;
            if (i + 4 <= av) break;                  /* non-zero group */
            if (av - i < 4 && z->eof) {
                for (u32 j = i; j < av; j++) if (p[j]) return GZ_OK;
                return av == i ? GZ_OK : GZ_E_DATA;   /* padding not a multiple of 4 */
            }
        }
    }
}

/* ---------------- .lzma (LZMA-alone) ---------------- */

static int lzma_run(xzd *z)
{
    int r = xin_fill(z, 13);
    if (r) return r;
    if (xin_avail(z) < 13) return GZ_E_FORMAT;
    const u8 *h = z->buf + z->pos;
    if (h[0] >= 9 * 5 * 5) return GZ_E_FORMAT;
    u8 props[5];
    __builtin_memcpy(props, h, 5);
    u64 usize = rd64(h + 5);                         /* ~0 = unknown: end marker */
    z->pos += 13;
    xd_start(z, CK_NONE, GZ_SIZE_UNKNOWN, GZ_SIZE_UNKNOWN);
    z->head = 0;
    gz_stream_io io = { xd_read, xd_write, z };
    return gz_lzma_decode(z->k->lz, props, &io, usize, 0);
}

/* ---------------- .lz (lzip) ---------------- */

/* coded dictionary size: 2^(b & 31) - (fraction b >> 5) * 2^(b & 31) / 16; 0 if invalid */
static u32 lzip_dict(u32 b)
{
    u32 bits = b & 0x1F;
    if (bits < 12 || bits > 29) return 0;
    u32 sz = 1u << bits;
    sz -= (sz >> 4) * (b >> 5);
    return sz >= 4096 ? sz : 0;
}

static int lzip_run(xzd *z)
{
    for (int first = 1;; first = 0) {
        if (gz_cancelled(z->c)) return GZ_E_CANCEL;
        int r = xin_fill(z, 6);
        if (r) return r;
        u32 av = xin_avail(z);
        const u8 *h = z->buf + z->pos;
        if (av < 4 || __builtin_memcmp(h, "LZIP", 4)) return first ? GZ_E_FORMAT : GZ_OK;   /* trailing data */
        if (av < 6) return GZ_E_TRUNC;
        u32 ver = h[4], dict = lzip_dict(h[5]);
        if (ver > 1) return GZ_E_METHOD;
        if (!dict) return GZ_E_DATA;
        z->pos += 6;
        u8 props[5] = { 0x5D, 0, 0, 0, 0 };          /* lc 3, lp 0, pb 2 */
        wr32(props + 1, dict);
        xd_start(z, CK_CRC32, GZ_SIZE_UNKNOWN, GZ_SIZE_UNKNOWN);
        z->head = 0;
        gz_stream_io io = { xd_read, xd_write, z };
        u64 used = 0;
        if ((r = gz_lzma_decode(z->k->lz, props, &io, GZ_SIZE_UNKNOWN, &used))) return r;
        if ((r = xin_unread(z, used))) return r;
        u32 ts = ver ? 20 : 12;                      /* version 0: no member size */
        if ((r = xin_need(z, ts))) return r;
        const u8 *t = z->buf + z->pos;
        if (rd32(t) != z->crc32) return GZ_E_CRC;
        if (rd64(t + 4) != z->produced || (ver && rd64(t + 12) != 6 + used + 20)) return GZ_E_DATA;
        z->pos += ts;
    }
}

/* ---------------- entry points ---------------- */

static int run(const gz_stream_io *in, int kind, int (*sink)(void *, const u8 *, size_t), void *user, gz_ctx *c)
{
    xz_cache *own = 0, *k;
    if (c) k = (xz_cache *)gz_ctx_slot(c, GZ_SLOT_LZMA, xz_cache_new, xz_cache_free);
    else k = own = (xz_cache *)xz_cache_new();
    if (!k) return GZ_E_NOMEM;
    gz_lzma_dec_set_flags(k->lz, 0);
    gz_lzma_dec_set_limit(k->lz, 0);
    int r = GZ_E_NOMEM;
    if (!k->ibuf) k->ibuf = (u8 *)gz_alloc(XI_KEEP + XI_CAP);
    if (k->ibuf) {
        xzd z;
        __builtin_memset(&z, 0, sizeof z);
        z.io = in;
        z.buf = k->ibuf;
        z.sink = sink;
        z.user = user;
        z.k = k;
        z.c = c;
        r = kind == K_XZ ? xz_run(&z) : kind == K_LZMA ? lzma_run(&z) : lzip_run(&z);
    }
    xz_cache_free(own);
    return r;
}

int gz_xz_decode_io(const gz_stream_io *in, int (*sink)(void *user, const u8 *p, size_t n),
                    void *user, gz_ctx *c)
{
    return run(in, K_XZ, sink, user, c);
}

static int src_run(gz_src *s, int kind, gz_sink_fn sink, void *user, gz_ctx *c)
{
    gz_range_reader rr = { s, 0, s->size, c ? c->cancel : 0 };
    gz_stream_io in = { gz_range_read, 0, &rr };
    return run(&in, kind, sink, user, c);
}

static int xz_decode(gz_src *s, gz_sink_fn sink, void *user, gz_ctx *c) { return src_run(s, K_XZ, sink, user, c); }
static int lzma_decode(gz_src *s, gz_sink_fn sink, void *user, gz_ctx *c) { return src_run(s, K_LZMA, sink, user, c); }
static int lzip_decode(gz_src *s, gz_sink_fn sink, void *user, gz_ctx *c) { return src_run(s, K_LZIP, sink, user, c); }

/* ---------------- info: sizes without decoding ---------------- */

/* .xz: walk the streams backwards through footer -> index -> header and add up
 * the uncompressed sizes of the index records */
static void xz_info(gz_src *s, gz_stream_info *inf, gz_ctx *c)
{
    u64 pos = s->size, total = 0;
    u8 b[4096];
    for (u32 ns = 0; pos; ns++) {
        if (ns >= XZ_INFO_STREAMS || gz_cancelled(c)) return;
        /* stream padding */
        for (u32 k = 0;; k++) {
            if (pos < 4 || k > 256) return;
            u32 n = pos < sizeof b ? (u32)pos & ~3u : (u32)sizeof b;
            if (gz_src_read_exact(s, pos - n, b, n)) return;
            u32 i = n;
            while (i && !rd32(b + i - 4)) i -= 4;
            pos -= n - i;
            if (i) break;
        }
        if (pos < 24 || gz_src_read_exact(s, pos - 12, b, 12)) return;
        u8 fl[2] = { b[8], b[9] };
        if (b[10] != 'Y' || b[11] != 'Z' || gz_crc32(0, b + 4, 6) != rd32(b)) return;
        u64 isize = ((u64)rd32(b + 4) + 1) * 4;
        if (isize > XZ_INFO_MAX || isize + 24 > pos) return;
        u64 istart = pos - 12 - isize;
        u8 *ix = (u8 *)gz_alloc((size_t)isize);
        if (!ix) return;
        u64 blocks = 0, us = 0, cnt = 0;
        int ok = !gz_src_read_exact(s, istart, ix, (u32)isize) && !ix[0] &&
                 gz_crc32(0, ix, (size_t)isize - 4) == rd32(ix + isize - 4);
        u32 at = 1, end = (u32)isize - 4;
        if (ok) ok = !vli_get(ix, end, &at, &cnt);
        for (u64 i = 0; ok && i < cnt; i++) {
            u64 unp, u;
            if (vli_get(ix, end, &at, &unp) || vli_get(ix, end, &at, &u) || unp < 5) { ok = 0; break; }
            unp = (unp + 3) & ~(u64)3;
            if (unp > (1ull << 62) - blocks || u > (1ull << 62) - us) { ok = 0; break; }
            blocks += unp;
            us += u;
        }
        if (ok && end - at > 3) ok = 0;                 /* index padding */
        for (u32 i = at; ok && i < end; i++) if (ix[i]) ok = 0;
        gz_free(ix);
        if (!ok || blocks + 12 > istart) return;
        u64 sstart = istart - blocks - 12;
        if (gz_src_read_exact(s, sstart, b, 12) || __builtin_memcmp(b, k_xz_magic, 6) ||
            b[6] != fl[0] || b[7] != fl[1] || gz_crc32(0, b + 6, 2) != rd32(b + 8))
            return;
        if (us > (1ull << 62) - total) return;
        total += us;
        pos = sstart;
    }
    inf->usize = total;
}

static void lzma_info(gz_src *s, gz_stream_info *inf, gz_ctx *c)
{
    (void)c;
    u8 h[13];
    if (!gz_src_read_exact(s, 0, h, 13) && rd64(h + 5) != ~(u64)0) inf->usize = rd64(h + 5);
}

/* .lz: walk the members backwards through the trailers' member sizes */
static void lzip_info(gz_src *s, gz_stream_info *inf, gz_ctx *c)
{
    u64 pos = s->size, total = 0;
    for (u32 k = 0; pos; k++) {
        if (k >= 1000000 || pos < 26 || ((k & 1023) == 1023 && gz_cancelled(c))) return;
        u8 t[20], h[6];
        if (gz_src_read_exact(s, pos - 20, t, 20)) return;
        u64 ds = rd64(t + 4), ms = rd64(t + 12);
        if (ms < 26 || ms > pos || ds > (1ull << 62) - total) return;
        if (gz_src_read_exact(s, pos - ms, h, 6) || __builtin_memcmp(h, "LZIP", 4) || h[4] != 1 || !lzip_dict(h[5]))
            return;
        total += ds;
        pos -= ms;
    }
    inf->usize = total;
}

/* ---------------- probes ---------------- */

static int xz_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 12 || __builtin_memcmp(h, k_xz_magic, 6)) return 0;
    if (h[6] || (h[7] & 0xF0) || gz_crc32(0, h + 6, 2) != rd32(h + 8)) return 60;   /* damaged header */
    return 95;
}

static int lzip_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 6 || __builtin_memcmp(h, "LZIP", 4)) return 0;
    return h[4] <= 1 && lzip_dict(h[5]) ? 95 : 60;
}

/* LZMA-alone has no magic: accept what xz / the LZMA SDK write (lc + lp <= 4,
 * dictionary 2^n or 2^n + 2^(n-1) >= 4 KiB, size unknown or < 256 GiB) and a
 * range coder that starts with its zero byte. */
static int lzma_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 14 || h[0] >= 9 * 5 * 5 || h[0] % 9 + h[0] / 9 % 5 > 4 || h[13]) return 0;
    u32 d = rd32(h + 1);
    if (d != 0xFFFFFFFFu) {
        if (d < 4096) return 0;
        u32 m = d - 1;
        m |= m >> 2; m |= m >> 3; m |= m >> 4; m |= m >> 8; m |= m >> 16;
        if (m + 1 != d) return 0;
    }
    u64 us = rd64(h + 5);
    if (us != ~(u64)0 && us >= (1ull << 38)) return 0;
    return 45;
}

static const gz_stream_codec xz_codec = { "TAR.XZ", "LZMA2", "txz", xz_decode, xz_info };
static const gz_stream_codec lzma_codec = { "TAR.LZMA", "LZMA", "tlz", lzma_decode, lzma_info };
static const gz_stream_codec lzip_codec = { "TAR.LZ", "LZMA", "tlz", lzip_decode, lzip_info };

GZ_FORMAT(gz_fmt_xz)
const gz_format gz_fmt_xz = GZ_STREAM_FORMAT("XZ", "xz txz", xz_probe, &xz_codec);
GZ_FORMAT(gz_fmt_lzma)
const gz_format gz_fmt_lzma = GZ_STREAM_FORMAT("LZMA", "lzma tlz", lzma_probe, &lzma_codec);
GZ_FORMAT(gz_fmt_lzip)
const gz_format gz_fmt_lzip = GZ_STREAM_FORMAT("LZIP", "lz tlz", lzip_probe, &lzip_codec);
