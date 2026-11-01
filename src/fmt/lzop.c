/*
 * 고깃ZIP - lzop files (.lzo, .tzo) via the shared stream-format code
 *
 * File: 9-byte magic, header (version, method, level, flags, [filter], mode, mtime,
 * name, Adler-32 or CRC-32 of the header), optional extra field, then blocks:
 *   u32be dst_len (0 = end), u32be src_len, [Adler-32/CRC-32 of the data],
 *   [Adler-32/CRC-32 of the compressed bytes when src_len < dst_len], data
 * src_len == dst_len means a stored block. Several files may be concatenated
 * (lzop -c a b); they decode back to back like gzip members.
 */
#include "streamfmt.h"
#include "crc32.h"
#include "lzo.h"

static const u8 lzop_magic[9] = { 0x89, 'L', 'Z', 'O', 0x00, 0x0d, 0x0a, 0x1a, 0x0a };

enum {
    F_ADLER32_D = 0x1, F_ADLER32_C = 0x2, F_H_EXTRA_FIELD = 0x40, F_CRC32_D = 0x100,
    F_CRC32_C = 0x200, F_H_FILTER = 0x800, F_H_CRC32 = 0x1000,
    F_CS_MASK = 0x00f00000, F_CS_UTF8 = 0x00500000
};
#define F_RESERVED  (~(0x3fffu | 0xff000000u | 0x00f00000u))
#define LZOP_VERSION 0x1040u            /* newest format lzop 1.04 writes  */
#define MAX_BLOCK   (64u << 20)         /* lzop's MAX_BLOCK_SIZE           */

typedef struct {
    u32 flags, filter, mode;
    u8 method;
    i64 mtime;
    u8 name[256];
    u32 name_len;
    u64 data;                           /* offset of the first block       */
} lzop_hdr;

static u32 adler32(u32 a, const u8 *p, size_t n)
{
    u32 s1 = a & 0xffff, s2 = a >> 16;
    while (n) {
        size_t k = n < 5552 ? n : 5552;    /* largest run without 32-bit overflow */
        n -= k;
        while (k >= 4) {
            s1 += p[0]; s2 += s1; s1 += p[1]; s2 += s1;
            s1 += p[2]; s2 += s1; s1 += p[3]; s2 += s1;
            p += 4;
            k -= 4;
        }
        while (k--) { s1 += *p++; s2 += s1; }
        s1 %= 65521;
        s2 %= 65521;
    }
    return s2 << 16 | s1;
}

static u32 lzop_sum(int crc, u32 v, const u8 *p, size_t n)
{
    return crc ? gz_crc32(v, p, n) : adler32(v, p, n);
}

/* parse the header of the file starting at off (magic included) */
static int lzop_header(gz_src *s, u64 off, lzop_hdr *h)
{
    u8 b[320];
    u32 got = 0;
    __builtin_memset(b, 0, sizeof b);
    if (off >= s->size) return GZ_E_TRUNC;
    if (s->read_at(s, off, b, sizeof b, &got)) return GZ_E_IO;
    if (got < 9 + 25 || __builtin_memcmp(b, lzop_magic, 9)) return GZ_E_FORMAT;
    __builtin_memset(h, 0, sizeof *h);
    u32 p = 9;
    u32 version = rd16be(b + p);
    p += 4;                                       /* version, library version */
    if (version < 0x0900) return GZ_E_FORMAT;
    if (version >= 0x0940) {
        u32 need = rd16be(b + p);
        p += 2;
        if (need < 0x0900) return GZ_E_FORMAT;
        if (need > LZOP_VERSION) return GZ_E_METHOD;
    }
    h->method = b[p++];
    if (version >= 0x0940) p++;                   /* level */
    h->flags = rd32be(b + p);
    p += 4;
    if (h->flags & F_H_FILTER) { h->filter = rd32be(b + p); p += 4; }
    h->mode = rd32be(b + p);
    u32 lo = rd32be(b + p + 4), hi = 0;
    p += 8;
    if (version >= 0x0940) { hi = rd32be(b + p); p += 4; }
    if (version < 0x0120 && lo == 0xffffffffu) lo = 0;
    h->mtime = (i64)((u64)hi << 32 | lo);
    h->name_len = b[p++];
    if (p + h->name_len + 4 > got) return GZ_E_TRUNC;
    __builtin_memcpy(h->name, b + p, h->name_len);
    p += h->name_len;
    int crc = (h->flags & F_H_CRC32) != 0;
    if (rd32be(b + p) != lzop_sum(crc, crc ? 0 : 1, b + 9, p - 9)) return GZ_E_CRC;
    p += 4;
    if (h->flags & F_RESERVED) return GZ_E_FORMAT;
    if (h->method < 1 || h->method > 3) return GZ_E_METHOD;   /* LZO1X-1, -1(15), -999 */
    if ((h->flags & F_H_FILTER) && h->filter > 16) return GZ_E_METHOD;
    u64 q = off + p;
    if (h->flags & F_H_EXTRA_FIELD) {
        /* not used by lzop; skipped after checking its checksum (which covers the length) */
        u8 x[4];
        int r = gz_src_read_exact(s, q, x, 4);
        if (r) return r;
        u32 len = rd32be(x), v = lzop_sum(crc, crc ? 0 : 1, x, 4);
        q += 4;
        if (len > s->size - q) return GZ_E_TRUNC;
        while (len) {
            u8 t[1024];
            u32 k = len < sizeof t ? len : (u32)sizeof t;
            if ((r = gz_src_read_exact(s, q, t, k))) return r;
            v = lzop_sum(crc, v, t, k);
            q += k;
            len -= k;
        }
        if ((r = gz_src_read_exact(s, q, x, 4))) return r;
        if (rd32be(x) != v) return GZ_E_CRC;
        q += 4;
    }
    h->data = q;
    return GZ_OK;
}

/* lzop's delta filter (--filter=n): undo per block, n byte lanes */
static void lzop_unfilter(u8 *p, size_t len, u32 n)
{
    if (n == 1) {
        u8 b = 0;
        for (size_t i = 0; i < len; i++) p[i] = b = (u8)(b + p[i]);
    } else if (len > n) {
        for (size_t i = n; i < len; i++) p[i] = (u8)(p[i] + p[i - n]);
    }
}

typedef struct { u8 *p; size_t cap; } lzop_buf;

static int buf_need(lzop_buf *b, size_t n)
{
    if (b->cap >= n) return GZ_OK;
    size_t cap = n < (1u << 20) ? (1u << 20) : n;
    u8 *q = (u8 *)gz_alloc_big(cap);
    if (!q) return GZ_E_NOMEM;
    if (b->p) gz_free_big(b->p, b->cap);
    b->p = q;
    b->cap = cap;
    return GZ_OK;
}

/* decode the blocks of one file starting at *off; *off = offset after the end marker */
static int lzop_blocks(gz_src *s, u64 *off, const lzop_hdr *h, gz_sink_fn sink, void *user, gz_ctx *c,
                       lzop_buf *buf)
{
    u64 q = *off;
    u32 fl = h->flags;
    for (;;) {
        if (gz_cancelled(c)) return GZ_E_CANCEL;
        u8 bh[24];
        int r = gz_src_read_exact(s, q, bh, 4);
        if (r) return r;
        u32 dlen = rd32be(bh);
        q += 4;
        if (!dlen) break;
        if (dlen == 0xffffffffu) return GZ_E_METHOD;     /* split file (never written) */
        if (dlen > MAX_BLOCK) return GZ_E_DATA;
        u32 nck = !!(fl & F_ADLER32_D) + !!(fl & F_CRC32_D);
        if ((r = gz_src_read_exact(s, q, bh + 4, 4))) return r;
        u32 slen = rd32be(bh + 4);
        if (!slen || slen > dlen) return GZ_E_DATA;
        u32 ncc = slen < dlen ? !!(fl & F_ADLER32_C) + !!(fl & F_CRC32_C) : 0;
        if ((r = gz_src_read_exact(s, q + 4, bh + 8, 4 * (nck + ncc)))) return r;
        q += 4 + 4 * (nck + ncc);
        const u8 *ck = bh + 8;
        u32 d_ad = 0, d_crc = 0, c_ad = 0, c_crc = 0;
        if (fl & F_ADLER32_D) { d_ad = rd32be(ck); ck += 4; }
        if (fl & F_CRC32_D) { d_crc = rd32be(ck); ck += 4; }
        if (ncc && (fl & F_ADLER32_C)) { c_ad = rd32be(ck); ck += 4; }
        if (ncc && (fl & F_CRC32_C)) { c_crc = rd32be(ck); ck += 4; }

        if (slen > s->size - q) return GZ_E_TRUNC;
        if ((r = buf_need(buf, (size_t)slen + dlen))) return r;
        u8 *cb = buf->p, *db = buf->p + slen;
        if ((r = gz_src_read_exact(s, q, cb, slen))) return r;
        q += slen;
        u8 *data = cb;
        if (slen < dlen) {
            if ((fl & F_ADLER32_C) && adler32(1, cb, slen) != c_ad) return GZ_E_CRC;
            if ((fl & F_CRC32_C) && gz_crc32(0, cb, slen) != c_crc) return GZ_E_CRC;
            size_t on, iu;
            r = gz_lzo1x_decode(cb, slen, db, dlen, &on, &iu);
            if (r == GZ_E_TRUNC) r = GZ_E_DATA;
            if (r) return r;
            if (on != dlen || iu != slen) return GZ_E_DATA;
            data = db;
        }
        if ((fl & F_H_FILTER) && h->filter) lzop_unfilter(data, dlen, h->filter);
        if ((fl & F_ADLER32_D) && adler32(1, data, dlen) != d_ad) return GZ_E_CRC;
        if ((fl & F_CRC32_D) && gz_crc32(0, data, dlen) != d_crc) return GZ_E_CRC;
        if ((r = sink(user, data, dlen))) return r;
    }
    *off = q;
    return GZ_OK;
}

static int lzop_decode(gz_src *s, gz_sink_fn sink, void *user, gz_ctx *c)
{
    lzop_hdr h;
    int r = lzop_header(s, 0, &h);
    if (r) return r;
    lzop_buf buf = { 0, 0 };
    for (;;) {
        u64 off = h.data;
        if ((r = lzop_blocks(s, &off, &h, sink, user, c, &buf))) break;
        /* another lzop file appended (lzop -c a b > ab.lzo)? */
        u8 m[9];
        if (off + 9 + 25 > s->size || gz_src_read_exact(s, off, m, 9) || __builtin_memcmp(m, lzop_magic, 9)) break;
        if ((r = lzop_header(s, off, &h))) break;
    }
    if (buf.p) gz_free_big(buf.p, buf.cap);
    return r;
}

/* header fields + total size from the block headers (no decompression) */
static void lzop_info(gz_src *s, gz_stream_info *inf, gz_ctx *c)
{
    lzop_hdr h;
    if (lzop_header(s, 0, &h)) return;
    __builtin_memcpy(inf->name, h.name, h.name_len);
    inf->name_len = h.name_len;
    inf->name_enc = (h.flags & F_CS_MASK) == F_CS_UTF8 ? GZ_NE_UTF8 : GZ_NE_LEGACY;
    if (h.mtime) { inf->mtime = h.mtime; inf->has_mtime = 1; }
    u64 total = 0, q = h.data;
    u32 fl = h.flags;
    for (u32 nblk = 0;; nblk++) {
        if (nblk >= (1u << 24) || gz_cancelled(c)) return;     /* size stays unknown */
        u8 bh[8];
        if (gz_src_read_exact(s, q, bh, 4)) return;
        u32 dlen = rd32be(bh);
        if (!dlen) {
            q += 4;
            u8 m[9];
            if (q + 9 + 25 > s->size || gz_src_read_exact(s, q, m, 9) || __builtin_memcmp(m, lzop_magic, 9)) break;
            if (lzop_header(s, q, &h)) return;
            q = h.data;
            fl = h.flags;
            continue;
        }
        if (gz_src_read_exact(s, q, bh, 8)) return;
        u32 slen = rd32be(bh + 4);
        if (dlen > MAX_BLOCK || !slen || slen > dlen) return;
        u32 nck = !!(fl & F_ADLER32_D) + !!(fl & F_CRC32_D);
        u32 ncc = slen < dlen ? !!(fl & F_ADLER32_C) + !!(fl & F_CRC32_C) : 0;
        q += 8 + 4 * (u64)(nck + ncc) + slen;
        total += dlen;
    }
    inf->usize = total;
}

static int lzop_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 9 + 25 || __builtin_memcmp(h, lzop_magic, 9)) return 0;
    return 95;
}

static const gz_stream_codec lzop_codec = {
    "TAR.LZO", "LZO1X", "tzo", lzop_decode, lzop_info
};

GZ_FORMAT(gz_fmt_lzop)
const gz_format gz_fmt_lzop = GZ_STREAM_FORMAT("LZO", "lzo tzo", lzop_probe, &lzop_codec);
