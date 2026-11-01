/*
 * 고깃ZIP - Zstandard decoder (RFC 8878)
 *
 * Data flow
 *   input : pulled in large chunks into ibuf. A block (<= 128 KiB) is made
 *           contiguous there before it is decoded, so the block decoder works on
 *           plain pointers; ibuf has Z_SLACK readable bytes after its end.
 *   output: decoded straight into the window buffer wbuf.
 *           - content size known and small enough: the buffer is exactly that big
 *             and never wraps (single segment frames, most files);
 *           - otherwise it holds window + 2 * (block + slack) bytes and wraps to
 *             its start when the next block does not fit. A match reaching before
 *             the start of the current segment reads from the tail of the previous
 *             segment, which cannot have been overwritten yet (that tail is at
 *             least window + block + slack long).
 *           The buffer starts small and doubles while the output grows, so a huge
 *           declared window costs memory only when the data really is that big.
 *           Output goes to the sink in >= 1 MiB pieces and before every wrap.
 *   Wild copies move 8/16 bytes at a time and may write up to 15 bytes past the
 *   logical end (and read past the literal end); every buffer has Z_SLACK bytes
 *   of room for that.
 *
 * Bit streams are read backwards with a 64-bit container (same layout as the
 * reference BIT_DStream), Huffman literals with a single-symbol 11-bit table
 * and four interleaved streams, sequences with combined FSE+baseline tables.
 */
#include "zstd.h"
#include "xxhash.h"
#include "cpu.h"

#define ZB_MAX   (128u << 10)        /* largest block                              */
#define Z_SLACK  64u                 /* wild-copy room after every buffer end      */
#define Z_ICAP   (512u << 10)        /* input buffer                               */
#define Z_FLUSH  ((size_t)1 << 20)   /* push output in pieces of at least this     */
#define Z_WMIN   ((u64)2 << 20)      /* smallest circular window buffer            */
#define Z_WINIT  ((size_t)8 << 20)   /* first window allocation (grows by doubling) */
#define Z_WKEEP  ((size_t)16 << 20)  /* bigger windows are released after a call   */
#define Z_BIGMEM ((size_t)1 << 20)   /* allocations above this use gz_alloc_big    */
#if UINTPTR_MAX > 0xffffffffu
#define Z_WCAP   ((u64)2 << 30)      /* largest window accepted                    */
#else
#define Z_WCAP   ((u64)512 << 20)
#endif
#define Z_STOP   (-1)                /* internal: out_size reached inside a frame   */

#define LL_LOG 9
#define ML_LOG 9
#define OF_LOG 8
#define LL_MAX 35
#define ML_MAX 52
#define OF_MAX 31

/* decoding table entry: next state base, state bits, extra bits, baseline */
typedef struct { u16 next; u8 nbits; u8 nadd; u32 base; } zsym;

struct gz_zstd_dec {
    /* input */
    u8 *ibuf, *ip, *iend;
    u64 in_total;
    int eof;
    /* window */
    u8 *wbuf;
    size_t walloc;                /* bytes allocated (usable + Z_SLACK)          */
    size_t wsize;                 /* usable size this frame needs                */
    size_t wcur;                  /* usable size allocated so far (<= wsize)     */
    size_t window;                /* largest offset allowed after a wrap         */
    u8 *op, *flushed;             /* write position, first byte not pushed yet   */
    const u8 *ext_end;            /* end of the previous segment (after a wrap)  */
    /* literals */
    u8 *lit;                      /* ZB_MAX + Z_SLACK                            */
    /* entropy state */
    const zsym *llp, *mlp, *ofp;
    u32 lllog, mllog, oflog;
    int huf_ok, seq_ok;
    size_t rep[3];
    /* output accounting */
    int check;
    int bmi2;                     /* use the BMI2 kernels                        */
    u64 out_total, out_size;
    gz_xxh64_state xh;
    /* tables */
    u16 huf[1 << 11];
    zsym llt[1 << LL_LOG], mlt[1 << ML_LOG], oft[1 << OF_LOG];
    zsym lld[64], mld[64], ofd[32];
};

/* ---------------- baselines and predefined distributions ---------------- */

static const u32 ll_base[LL_MAX + 1] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
    8192, 16384, 32768, 65536
};
static const u8 ll_bits[LL_MAX + 1] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16
};
static const u32 ml_base[ML_MAX + 1] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
    4099, 8195, 16387, 32771, 65539
};
static const u8 ml_bits[ML_MAX + 1] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16
};
/* offset code c: value = (1 << c) + c extra bits; stored as value - 3 for c >= 2,
 * codes 0 and 1 select repeat offsets (see z_seqs) */
static const u32 of_base[OF_MAX + 1] = {
    0, 1, 1, 5, 0xD, 0x1D, 0x3D, 0x7D, 0xFD, 0x1FD, 0x3FD, 0x7FD, 0xFFD, 0x1FFD, 0x3FFD, 0x7FFD,
    0xFFFD, 0x1FFFD, 0x3FFFD, 0x7FFFD, 0xFFFFD, 0x1FFFFD, 0x3FFFFD, 0x7FFFFD, 0xFFFFFD,
    0x1FFFFFD, 0x3FFFFFD, 0x7FFFFFD, 0xFFFFFFD, 0x1FFFFFFD, 0x3FFFFFFD, 0x7FFFFFFD
};
static const u8 of_bits[OF_MAX + 1] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};
static const i16 ll_def[LL_MAX + 1] = {
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1
};
static const i16 ml_def[ML_MAX + 1] = {
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
    -1, -1, -1, -1, -1
};
static const i16 of_def[29] = {
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1
};

GZ_INLINE u32 highbit(u32 v) { return 31 - (u32)__builtin_clz(v); }   /* v != 0 */
GZ_INLINE u32 rd24(const u8 *p) { return (u32)p[0] | (u32)p[1] << 8 | (u32)p[2] << 16; }
GZ_INLINE void cp8(u8 *d, const u8 *s) { __builtin_memcpy(d, s, 8); }
GZ_INLINE void cp16(u8 *d, const u8 *s) { __builtin_memcpy(d, s, 16); }

/* ---------------- backward bit reader ---------------- */

typedef struct { u64 c; u32 used; const u8 *p, *start; } zbits;
enum { ZB_MORE = 0, ZB_END = 1, ZB_DONE = 2, ZB_OVER = 3 };

/* The stream ends with a 1 bit marking its start (highest set bit of the last
 * byte). A stream shorter than 8 bytes is copied to tmp (zero-filled) so that an
 * 8-byte load at p is always valid and refills need no length checks. */
GZ_INLINE int zb_init(zbits *b, const u8 *src, size_t n, u8 *tmp)
{
    if (!n || !src[n - 1]) return -1;
    u32 pad = (u32)__builtin_clz((u32)src[n - 1]) - 23;      /* 8 - highbit */
    if (n >= 8) {
        b->start = src;
        b->p = src + n - 8;
        b->used = pad;
    } else {
        __builtin_memset(tmp, 0, 8);
        __builtin_memcpy(tmp, src, n);
        b->start = b->p = tmp;
        b->used = pad + (u32)(8 - n) * 8;
    }
    b->c = rd64(b->p);
    return 0;
}

/* n bits (0..57) from the top; shifts are masked so an overflowed reader yields
 * garbage instead of undefined behaviour (overflow is caught by zb_end) */
GZ_INLINE u64 zb_look(const zbits *b, u32 n)
{
    return ((b->c << (b->used & 63)) >> 1) >> ((63 - n) & 63);
}
GZ_INLINE u64 zb_read(zbits *b, u32 n)
{
    u64 v = zb_look(b, n);
    b->used += n;
    return v;
}
GZ_INLINE u64 zb_readfast(zbits *b, u32 n)   /* n >= 1 */
{
    u64 v = (b->c << (b->used & 63)) >> ((64 - n) & 63);
    b->used += n;
    return v;
}

/* Branch-free refill: afterwards either used <= 7 (57+ bits ready) or p is at the
 * start and the container holds every remaining bit. Valid streams therefore
 * never need a status check; corrupt ones read garbage and fail zb_end. */
GZ_INLINE void zb_refill(zbits *b)
{
    size_t nb = b->used >> 3, av = (size_t)(b->p - b->start);
    nb = nb < av ? nb : av;
    b->p -= nb;
    b->used -= (u32)nb << 3;
    b->c = rd64(b->p);
}

/* refill with the reference status codes (FSE-coded Huffman weights stop on overflow) */
static int zb_reload(zbits *b)
{
    if (b->used > 64) return ZB_OVER;
    size_t av = (size_t)(b->p - b->start), nb = b->used >> 3;
    int r = nb > av ? ZB_END : ZB_MORE;
    if (!av) return b->used < 64 ? ZB_END : ZB_DONE;
    zb_refill(b);
    return r;
}

/* every bit consumed, none more */
GZ_INLINE int zb_end(zbits *b)
{
    zb_refill(b);
    return b->p == b->start && b->used == 64;
}

/* ---------------- FSE tables ---------------- */

static u32 peek_le(const u8 *p, size_t n, size_t pos, u32 k)
{
    size_t i = pos >> 3;
    u32 v = 0;
    for (u32 j = 0; j < 4 && i + j < n; j++) v |= (u32)p[i + j] << (8 * j);
    return (v >> (pos & 7)) & ((1u << k) - 1);
}

/* FSE table description (RFC 8878 4.1.1): normalized counts of symbols 0..*maxsym.
 * Returns bytes used, 0 on error. On success *maxsym is the last symbol present. */
static size_t read_ncount(i16 *norm, u32 *maxsym, u32 *log, const u8 *p, size_t n, u32 maxlog)
{
    if (!n) return 0;
    u32 msym = *maxsym, al = (p[0] & 15) + 5;
    if (al > maxlog) return 0;
    size_t pos = 4, total = n * 8;
    int remaining = (1 << al) + 1, threshold = 1 << al, nb = (int)al + 1, prev0 = 0;
    u32 s = 0;
    for (u32 i = 0; i <= msym; i++) norm[i] = 0;
    while (remaining > 1) {
        if (prev0) {                    /* 2-bit repeat counts of zero probabilities */
            u32 r;
            do {
                r = peek_le(p, n, pos, 2);
                pos += 2;
                s += r;
            } while (r == 3 && s <= msym);
        }
        if (s > msym || pos > total) return 0;
        int max = (2 * threshold - 1) - remaining, count;
        u32 v = peek_le(p, n, pos, (u32)nb);
        if ((int)(v & (u32)(threshold - 1)) < max) {
            count = (int)(v & (u32)(threshold - 1));
            pos += (size_t)nb - 1;
        } else {
            count = (int)v;
            if (count >= threshold) count -= max;
            pos += (size_t)nb;
        }
        count--;                         /* -1 = "less than 1" */
        remaining -= count < 0 ? -count : count;
        norm[s++] = (i16)count;
        prev0 = !count;
        if (remaining < threshold) {
            if (remaining <= 1) break;
            nb = (int)highbit((u32)remaining) + 1;
            threshold = 1 << (nb - 1);
        }
    }
    if (remaining != 1 || pos > total) return 0;
    *maxsym = s - 1;
    *log = al;
    return (pos + 7) >> 3;
}

/* Decoding table from normalized counts; base/bits map each symbol to its
 * baseline and extra-bit count. Returns 0, or -1 if the spread does not close. */
static int build_fse(zsym *t, const i16 *norm, u32 maxsym, u32 log, const u32 *base, const u8 *bits)
{
    u32 size = 1u << log, high = size - 1, mask = size - 1, step = (size >> 1) + (size >> 3) + 3;
    u16 next[256];
    u8 sym[1 << LL_LOG];
    for (u32 s = 0; s <= maxsym; s++) {
        if (norm[s] == -1) {
            sym[high--] = (u8)s;
            next[s] = 1;
        } else {
            next[s] = (u16)norm[s];
        }
    }
    if (high == size - 1) {
        /* no "less than 1" symbols: lay the symbols out in runs, then scatter them
         * with the fixed stride (no data-dependent branches) */
        u8 runs[(1 << LL_LOG) + 8];
        u64 sv = 0;
        u32 pos = 0;
        for (u32 s = 0; s <= maxsym; s++, sv += 0x0101010101010101ull) {
            int n = norm[s];
            wr64(runs + pos, sv);
            for (int i = 8; i < n; i += 8) wr64(runs + pos + i, sv);
            pos += (u32)n;
        }
        if (pos != size) return -1;
        u32 p = 0;
        for (u32 i = 0; i < size; i += 2) {
            sym[p] = runs[i];
            sym[(p + step) & mask] = runs[i + 1];
            p = (p + 2 * step) & mask;
        }
    } else {
        u32 pos = 0;
        for (u32 s = 0; s <= maxsym; s++)
            for (int i = 0; i < norm[s]; i++) {
                sym[pos] = (u8)s;
                do pos = (pos + step) & mask; while (pos > high);
            }
        if (pos) return -1;
    }
    /* entry = next | nbits << 16 | nadd << 24 | base << 32 (zsym layout, little-endian) */
    u64 hi[256];
    for (u32 s = 0; s <= maxsym; s++) hi[s] = (u64)base[s] << 32 | (u64)bits[s] << 24;
    for (u32 u = 0; u < size; u++) {
        u32 s = sym[u], ns = next[s]++;
        u32 nb = log - highbit(ns);
        u64 e = hi[s] | (u64)nb << 16 | ((ns << nb) - size);
        __builtin_memcpy(&t[u], &e, 8);
    }
    return 0;
}

/* ---------------- Huffman ---------------- */

/* weights -> 11-bit single-symbol table: entry = symbol << 8 | code length */
static int huf_build(u16 *dt, u8 *w, u32 n)
{
    u32 rank[13] = { 0 }, total = 0;
    if (n > 255) return -1;
    for (u32 i = 0; i < n; i++) {
        if (w[i] > 11) return -1;
        rank[w[i]]++;
        total += (1u << w[i]) >> 1;
    }
    if (!total) return -1;
    u32 tl = highbit(total) + 1;
    if (tl > 11) return -1;
    u32 rest = (1u << tl) - total, lw = highbit(rest) + 1;
    if ((1u << (lw - 1)) != rest) return -1;             /* last weight must complete the tree */
    w[n++] = (u8)lw;
    rank[lw]++;
    if (rank[1] < 2 || (rank[1] & 1)) return -1;
    u32 start[13], pos = 0, sh = 11 - tl;
    for (u32 k = 1; k <= tl; k++) {
        start[k] = pos;
        pos += rank[k] << (k - 1);
    }
    for (u32 s = 0; s < n; s++) {
        u32 k = w[s];
        if (!k) continue;
        u32 len = (1u << (k - 1)) << sh, from = start[k] << sh;
        u16 e = (u16)((s << 8) | (tl + 1 - k));
        for (u32 j = 0; j < len; j++) dt[from + j] = e;
        start[k] += 1u << (k - 1);
    }
    return 0;
}

/* FSE-compressed weights: two interleaved states until the stream overflows */
static int huf_weights_fse(const u8 *p, size_t n, u8 *w, u32 *nw)
{
    i16 norm[256];
    zsym t[64];
    u32 ident[256], maxsym = 255, log;
    u8 zero[256];
    size_t h = read_ncount(norm, &maxsym, &log, p, n, 6);
    if (!h || h >= n) return -1;
    for (u32 i = 0; i <= maxsym; i++) {
        ident[i] = i;
        zero[i] = 0;
    }
    if (build_fse(t, norm, maxsym, log, ident, zero)) return -1;
    zbits b;
    u8 tmp[8];
    if (zb_init(&b, p + h, n - h, tmp)) return -1;
    u32 s1 = (u32)zb_read(&b, log);
    zb_reload(&b);
    u32 s2 = (u32)zb_read(&b, log);
    if (zb_reload(&b) == ZB_OVER) return -1;
    u8 *o = w, *omax = w + 255;
    for (;;) {
        if (o > omax - 2) return -1;
        *o++ = (u8)t[s1].base;
        s1 = t[s1].next + (u32)zb_read(&b, t[s1].nbits);
        if (zb_reload(&b) == ZB_OVER) { *o++ = (u8)t[s2].base; break; }
        if (o > omax - 2) return -1;
        *o++ = (u8)t[s2].base;
        s2 = t[s2].next + (u32)zb_read(&b, t[s2].nbits);
        if (zb_reload(&b) == ZB_OVER) { *o++ = (u8)t[s1].base; break; }
    }
    *nw = (u32)(o - w);
    return 0;
}

/* Huffman tree description; *used = bytes consumed */
static int huf_read(u16 *dt, const u8 *p, size_t n, size_t *used)
{
    u8 w[257];
    u32 nw;
    if (!n) return -1;
    u32 hb = p[0];
    if (hb >= 128) {                     /* direct 4-bit weights */
        nw = hb - 127;
        size_t bytes = (nw + 1) >> 1;
        if (1 + bytes > n) return -1;
        for (u32 i = 0; i < nw; i++) {
            u8 b = p[1 + (i >> 1)];
            w[i] = (i & 1) ? (b & 15) : (b >> 4);
        }
        *used = 1 + bytes;
    } else {
        if (!hb || 1 + (size_t)hb > n) return -1;
        if (huf_weights_fse(p + 1, hb, w, &nw)) return -1;
        *used = 1 + (size_t)hb;
    }
    return huf_build(dt, w, nw);
}

#define HUF_SYM(b, o, dt) do { \
        u32 e_ = (dt)[((b).c << ((b).used & 63)) >> 53]; \
        *(o)++ = (u8)(e_ >> 8); \
        (b).used += e_ & 0xff; \
    } while (0)

/* one stream into [o, oe), 4 symbols per refill (after a refill a valid stream
 * always has the bits of its next symbols in the container) */
GZ_INLINE void huf_tail(zbits *b, u8 *o, u8 *oe, const u16 *dt)
{
    zbits s = *b;
    while ((size_t)(oe - o) > 3) {
        zb_refill(&s);
        HUF_SYM(s, o, dt); HUF_SYM(s, o, dt); HUF_SYM(s, o, dt); HUF_SYM(s, o, dt);
    }
    zb_refill(&s);
    while (o < oe) HUF_SYM(s, o, dt);
    *b = s;
}

GZ_INLINE int huf_1x_body(const u16 *dt, u8 *dst, size_t rs, const u8 *src, size_t sn)
{
    zbits b;
    u8 tmp[8];
    if (zb_init(&b, src, sn, tmp)) return -1;
    huf_tail(&b, dst, dst + rs, dt);
    return zb_end(&b) ? 0 : -1;
}

GZ_INLINE int huf_4x_body(const u16 *dt, u8 *dst, size_t rs, const u8 *src, size_t sn)
{
    if (sn < 10) return -1;
    size_t l1 = rd16(src), l2 = rd16(src + 2), l3 = rd16(src + 4);
    if (6 + l1 + l2 + l3 >= sn) return -1;
    size_t l4 = sn - 6 - l1 - l2 - l3, seg = (rs + 3) >> 2;
    if (3 * seg > rs) return -1;
    const u8 *s1 = src + 6, *s2 = s1 + l1, *s3 = s2 + l2, *s4 = s3 + l3;
    u8 *o1 = dst, *o2 = o1 + seg, *o3 = o2 + seg, *o4 = o3 + seg, *oend = dst + rs;
    u8 *const e1 = o2, *const e2 = o3, *const e3 = o4;
    zbits b1, b2, b3, b4;
    u8 t1[8], t2[8], t3[8], t4[8];
    if (zb_init(&b1, s1, l1, t1) || zb_init(&b2, s2, l2, t2) || zb_init(&b3, s3, l3, t3) || zb_init(&b4, s4, l4, t4))
        return -1;
    /* 5 symbols (<= 55 bits) per stream and refill; stream 4 is the shortest, so
     * while it has 5+ symbols left the others do too */
    while ((size_t)(oend - o4) > 4) {
        HUF_SYM(b1, o1, dt); HUF_SYM(b2, o2, dt); HUF_SYM(b3, o3, dt); HUF_SYM(b4, o4, dt);
        HUF_SYM(b1, o1, dt); HUF_SYM(b2, o2, dt); HUF_SYM(b3, o3, dt); HUF_SYM(b4, o4, dt);
        HUF_SYM(b1, o1, dt); HUF_SYM(b2, o2, dt); HUF_SYM(b3, o3, dt); HUF_SYM(b4, o4, dt);
        HUF_SYM(b1, o1, dt); HUF_SYM(b2, o2, dt); HUF_SYM(b3, o3, dt); HUF_SYM(b4, o4, dt);
        HUF_SYM(b1, o1, dt); HUF_SYM(b2, o2, dt); HUF_SYM(b3, o3, dt); HUF_SYM(b4, o4, dt);
        zb_refill(&b1); zb_refill(&b2); zb_refill(&b3); zb_refill(&b4);
    }
    huf_tail(&b1, o1, e1, dt);
    huf_tail(&b2, o2, e2, dt);
    huf_tail(&b3, o3, e3, dt);
    huf_tail(&b4, o4, oend, dt);
    return (zb_end(&b1) & zb_end(&b2) & zb_end(&b3) & zb_end(&b4)) ? 0 : -1;
}

/* Kernels: the bit-extraction loops are compiled twice on x86-64, plain and with
 * BMI1/BMI2 (shlx/shrx/bzhi, about 10% faster), chosen per call from
 * g_cpu.active (the AVX2 tier implies BMI1+BMI2; forced lower tiers are honoured).
 * 32-bit builds emulate the 64-bit bit container and gain nothing measurable. */
#if defined(__x86_64__)
#define Z_HAVE_BMI2 1
#define Z_BMI2 __attribute__((target("bmi,bmi2")))
#endif

static int huf_1x(const u16 *dt, u8 *dst, size_t rs, const u8 *src, size_t sn)
{
    return huf_1x_body(dt, dst, rs, src, sn);
}
static int huf_4x(const u16 *dt, u8 *dst, size_t rs, const u8 *src, size_t sn)
{
    return huf_4x_body(dt, dst, rs, src, sn);
}
#ifdef Z_HAVE_BMI2
Z_BMI2 static int huf_1x_bmi2(const u16 *dt, u8 *dst, size_t rs, const u8 *src, size_t sn)
{
    return huf_1x_body(dt, dst, rs, src, sn);
}
Z_BMI2 static int huf_4x_bmi2(const u16 *dt, u8 *dst, size_t rs, const u8 *src, size_t sn)
{
    return huf_4x_body(dt, dst, rs, src, sn);
}
#endif

/* ---------------- buffers ---------------- */

static void *zmem_alloc(size_t n) { return n > Z_BIGMEM ? gz_alloc_big(n) : gz_alloc(n); }
static void zmem_free(void *p, size_t n)
{
    if (!p) return;
    if (n > Z_BIGMEM) gz_free_big(p, n); else gz_free(p);
}

gz_zstd_dec *gz_zstd_dec_new(void)
{
    gz_zstd_dec *d = (gz_zstd_dec *)gz_alloc(sizeof(gz_zstd_dec));
    if (!d) return 0;
    d->ibuf = (u8 *)gz_alloc(Z_ICAP + Z_SLACK);
    d->lit = (u8 *)gz_alloc(ZB_MAX + Z_SLACK);
    if (!d->ibuf || !d->lit) {
        gz_zstd_dec_free(d);
        return 0;
    }
    build_fse(d->lld, ll_def, LL_MAX, 6, ll_base, ll_bits);
    build_fse(d->mld, ml_def, ML_MAX, 6, ml_base, ml_bits);
    build_fse(d->ofd, of_def, 28, 5, of_base, of_bits);
    return d;
}

void gz_zstd_dec_free(gz_zstd_dec *d)
{
    if (!d) return;
    gz_free(d->ibuf);
    gz_free(d->lit);
    zmem_free(d->wbuf, d->walloc);
    gz_free(d);
}

/* make at least need bytes available at ip (GZ_E_TRUNC at end of input) */
static int z_need(gz_zstd_dec *d, const gz_stream_io *io, size_t need)
{
    size_t have = (size_t)(d->iend - d->ip);
    if (GZ_LIKELY(have >= need)) return GZ_OK;
    if (d->eof) return GZ_E_TRUNC;
    if (d->ip != d->ibuf) {
        __builtin_memmove(d->ibuf, d->ip, have);
        d->ip = d->ibuf;
        d->iend = d->ibuf + have;
    }
    while (have < need) {
        u32 got = 0;
        int r = io->read(io->ctx, d->iend, (u32)(Z_ICAP - have), &got);
        if (r) return r;
        if (!got || got > Z_ICAP - have) {
            d->eof = 1;
            return GZ_E_TRUNC;
        }
        d->iend += got;
        have += got;
        d->in_total += got;
    }
    return GZ_OK;
}

/* push [flushed, op) to the sink (checksummed in full, written up to out_size) */
static int z_flush(gz_zstd_dec *d, const gz_stream_io *io)
{
    size_t n = (size_t)(d->op - d->flushed);
    if (!n) return GZ_OK;
    const u8 *p = d->flushed;
    d->flushed = d->op;
    if (d->check) gz_xxh64_update(&d->xh, p, n);
    u64 w = n;
    if (d->out_size != GZ_SIZE_UNKNOWN && w > d->out_size - d->out_total) w = d->out_size - d->out_total;
    if (!w) return GZ_OK;
    d->out_total += w;
    return io->write(io->ctx, p, (size_t)w);
}

/* room for cap more bytes at op: grow the buffer, or wrap once it has full size */
static int z_room(gz_zstd_dec *d, const gz_stream_io *io, size_t cap)
{
    size_t used = (size_t)(d->op - d->wbuf);
    if (d->wcur < d->wsize) {
        size_t want = d->wcur * 2;
        if (want < used + cap) want = used + cap;
        if (want > d->wsize) want = d->wsize;
        u8 *nb = (u8 *)zmem_alloc(want + Z_SLACK);
        if (!nb) return GZ_E_NOMEM;
        __builtin_memcpy(nb, d->wbuf, used);
        d->flushed = nb + (d->flushed - d->wbuf);
        d->op = nb + used;
        zmem_free(d->wbuf, d->walloc);
        d->wbuf = nb;
        d->walloc = want + Z_SLACK;
        d->wcur = want;
        if (d->wcur - used >= cap) return GZ_OK;
    }
    int r = z_flush(d, io);
    if (r) return r;
    d->ext_end = d->op;
    d->op = d->flushed = d->wbuf;
    return GZ_OK;
}

/* ---------------- block decoding ---------------- */

static int z_literals(gz_zstd_dec *d, const u8 *ip, size_t n, size_t *used, const u8 **lit, size_t *litn)
{
    if (!n) return GZ_E_DATA;
    u32 type = ip[0] & 3, sf = (ip[0] >> 2) & 3;
    size_t hl, rs, cs;
    if (type < 2) {                      /* raw or RLE */
        if (sf == 1) {
            if (n < 2) return GZ_E_DATA;
            hl = 2;
            rs = rd16(ip) >> 4;
        } else if (sf == 3) {
            if (n < 3) return GZ_E_DATA;
            hl = 3;
            rs = rd24(ip) >> 4;
        } else {
            hl = 1;
            rs = ip[0] >> 3;
        }
        if (rs > ZB_MAX) return GZ_E_DATA;
        if (type == 0) {
            if (rs > n - hl) return GZ_E_DATA;
            *lit = ip + hl;              /* in ibuf: Z_SLACK readable bytes follow */
            *used = hl + rs;
        } else {
            if (n < hl + 1) return GZ_E_DATA;
            __builtin_memset(d->lit, ip[hl], rs);
            *lit = d->lit;
            *used = hl + 1;
        }
        *litn = rs;
        return GZ_OK;
    }
    if (sf < 2) {
        if (n < 3) return GZ_E_DATA;
        u32 h = rd24(ip);
        hl = 3; rs = (h >> 4) & 0x3FF; cs = (h >> 14) & 0x3FF;
    } else if (sf == 2) {
        if (n < 4) return GZ_E_DATA;
        u32 h = rd32(ip);
        hl = 4; rs = (h >> 4) & 0x3FFF; cs = h >> 18;
    } else {
        if (n < 5) return GZ_E_DATA;
        u64 h = rd32(ip) | (u64)ip[4] << 32;
        hl = 5; rs = (size_t)(h >> 4) & 0x3FFFF; cs = (size_t)(h >> 22) & 0x3FFFF;
    }
    if (rs > ZB_MAX || cs > n - hl) return GZ_E_DATA;
    const u8 *src = ip + hl;
    size_t sn = cs;
    if (type == 2) {
        size_t tu;
        d->huf_ok = 0;
        if (huf_read(d->huf, src, sn, &tu)) return GZ_E_DATA;
        d->huf_ok = 1;
        src += tu;
        sn -= tu;
    } else if (!d->huf_ok) {
        return GZ_E_DATA;                /* treeless without a previous tree */
    }
    int e;
#ifdef Z_HAVE_BMI2
    if (d->bmi2)
        e = sf ? huf_4x_bmi2(d->huf, d->lit, rs, src, sn) : huf_1x_bmi2(d->huf, d->lit, rs, src, sn);
    else
#endif
        e = sf ? huf_4x(d->huf, d->lit, rs, src, sn) : huf_1x(d->huf, d->lit, rs, src, sn);
    if (e) return GZ_E_DATA;
    *lit = d->lit;
    *litn = rs;
    *used = hl + cs;
    return GZ_OK;
}

/* one sequence table (mode: 0 predefined, 1 RLE, 2 FSE, 3 repeat) */
static int seq_table(gz_zstd_dec *d, u32 mode, const u8 **pp, const u8 *end, zsym *own, const zsym *def,
                     u32 deflog, u32 maxsym, u32 maxlog, const u32 *base, const u8 *bits,
                     const zsym **cur, u32 *curlog)
{
    if (mode == 0) {
        *cur = def;
        *curlog = deflog;
    } else if (mode == 1) {
        if (*pp >= end) return -1;
        u32 s = *(*pp)++;
        if (s > maxsym) return -1;
        own[0].next = 0;
        own[0].nbits = 0;
        own[0].nadd = bits[s];
        own[0].base = base[s];
        *cur = own;
        *curlog = 0;
    } else if (mode == 2) {
        i16 norm[64];
        u32 ms = maxsym, lg;
        size_t h = read_ncount(norm, &ms, &lg, *pp, (size_t)(end - *pp), maxlog);
        if (!h || build_fse(own, norm, ms, lg, base, bits)) return -1;
        *pp += h;
        *cur = own;
        *curlog = lg;
    } else if (!d->seq_ok) {
        return -1;
    }
    return 0;
}

/* overlapping match copy; writes up to 15 bytes past op + ml */
GZ_INLINE void copy_match(u8 *op, const u8 *m, size_t ml, size_t off)
{
    u8 *const e = op + ml;
    if (GZ_LIKELY(off >= 16)) {
        do { cp16(op, m); op += 16; m += 16; } while (op < e);
        return;
    }
    if (off < 8) {
        /* spread the first 8 bytes so the remaining distance is >= 8 */
        static const u8 add4[8] = { 0, 1, 2, 1, 4, 4, 4, 4 };
        static const u8 adv[8] = { 0, 1, 2, 2, 4, 3, 2, 1 };
        op[0] = m[0]; op[1] = m[1]; op[2] = m[2]; op[3] = m[3];
        __builtin_memcpy(op + 4, m + add4[off], 4);
        m += adv[off];
    } else {
        cp8(op, m);
        m += 8;
    }
    op += 8;
    while (op < e) { cp8(op, m); op += 8; m += 8; }
}

/* match that starts in the previous segment of a wrapped window */
static GZ_NOINLINE int match_ext(gz_zstd_dec *d, u8 *op, size_t ml, size_t off)
{
    size_t inseg = (size_t)(op - d->wbuf);
    if (!d->ext_end || off > d->window) return GZ_E_DATA;
    size_t back = off - inseg;
    const u8 *src = d->ext_end - back;
    if (ml <= back) {
        __builtin_memcpy(op, src, ml);
        return GZ_OK;
    }
    __builtin_memcpy(op, src, back);
    copy_match(op + back, d->wbuf, ml - back, off);
    return GZ_OK;
}

GZ_INLINE int z_seqs_body(gz_zstd_dec *d, const u8 *sp, size_t sn, u32 nbseq, const u8 *lit, size_t litn, u8 *oend)
{
    zbits b;
    u8 tmp[8];
    if (zb_init(&b, sp, sn, tmp)) return GZ_E_DATA;
    const zsym *const llt = d->llp, *const mlt = d->mlp, *const oft = d->ofp;
    u32 ls = (u32)zb_read(&b, d->lllog);
    zb_refill(&b);
    u32 os = (u32)zb_read(&b, d->oflog);
    zb_refill(&b);
    u32 ms = (u32)zb_read(&b, d->mllog);
    zb_refill(&b);
    size_t r0 = d->rep[0], r1 = d->rep[1], r2 = d->rep[2];
    u8 *op = d->op;
    u8 *const seg = d->wbuf;
    const u8 *const lend = lit + litn;
    for (;;) {
        const zsym *l = llt + ls, *m = mlt + ms, *o = oft + os;
        u32 ob = o->nadd, mb = m->nadd, lb = l->nadd;
        size_t off, ml, ll;
        /* decode: offset, match length, literal length bits, then the state updates */
        if (ob > 1) {
            off = o->base + (size_t)zb_readfast(&b, ob);
            r2 = r1; r1 = r0; r0 = off;
        } else {
            u32 ll0 = l->base == 0;
            if (ob == 0) {
                off = ll0 ? r1 : r0;
                if (ll0) { r1 = r0; r0 = off; }
            } else {
                u32 k = o->base + ll0 + (u32)zb_readfast(&b, 1);   /* 1..3 */
                off = k == 3 ? r0 - 1 : (k == 1 ? r1 : r2);
                if (k != 1) r2 = r1;
                r1 = r0; r0 = off;
                if (GZ_UNLIKELY(!off)) return GZ_E_DATA;
            }
        }
        ml = m->base;
        if (mb) ml += (size_t)zb_readfast(&b, mb);
        if (ob + mb + lb >= 31) zb_refill(&b);
        ll = l->base;
        if (lb) ll += (size_t)zb_readfast(&b, lb);
        if (--nbseq) {
            /* the three state updates (LL, ML, OF order) as one bit field */
            u32 lnb = l->nbits, mnb = m->nbits, onb = o->nbits;
            u64 v = zb_read(&b, lnb + mnb + onb);
            os = o->next + (u32)(v & ((1u << onb) - 1));
            v >>= onb;
            ms = m->next + (u32)(v & ((1u << mnb) - 1));
            ls = l->next + (u32)(v >> mnb);
            zb_refill(&b);
        }
        /* execute */
        if (GZ_UNLIKELY(ll > (size_t)(lend - lit) || ll + ml > (size_t)(oend - op))) return GZ_E_DATA;
        {
            u8 *e = op + ll;
            cp16(op, lit);
            if (GZ_UNLIKELY(ll > 16)) {
                u8 *q = op + 16;
                const u8 *s = lit + 16;
                do { cp16(q, s); q += 16; s += 16; } while (q < e);
            }
            op = e;
            lit += ll;
        }
        if (GZ_LIKELY(off <= (size_t)(op - seg))) {
            copy_match(op, op - off, ml, off);
        } else {
            int r = match_ext(d, op, ml, off);
            if (r) return r;
        }
        op += ml;
        if (!nbseq) break;
    }
    if (!zb_end(&b)) return GZ_E_DATA;
    size_t rest = (size_t)(lend - lit);
    if (rest > (size_t)(oend - op)) return GZ_E_DATA;
    __builtin_memcpy(op, lit, rest);
    d->op = op + rest;
    d->rep[0] = r0; d->rep[1] = r1; d->rep[2] = r2;
    return GZ_OK;
}

static int z_seqs(gz_zstd_dec *d, const u8 *sp, size_t sn, u32 nbseq, const u8 *lit, size_t litn, u8 *oend)
{
    return z_seqs_body(d, sp, sn, nbseq, lit, litn, oend);
}
#ifdef Z_HAVE_BMI2
Z_BMI2 static int z_seqs_bmi2(gz_zstd_dec *d, const u8 *sp, size_t sn, u32 nbseq, const u8 *lit, size_t litn, u8 *oend)
{
    return z_seqs_body(d, sp, sn, nbseq, lit, litn, oend);
}
#endif

/* compressed block [ip, ip + n) producing at most cap bytes at d->op */
static int z_block(gz_zstd_dec *d, const u8 *ip, size_t n, size_t cap)
{
    const u8 *const iend = ip + n, *lit;
    size_t litn, used;
    int r = z_literals(d, ip, n, &used, &lit, &litn);
    if (r) return r;
    if (litn > cap) return GZ_E_DATA;
    ip += used;
    if (ip >= iend) return GZ_E_DATA;
    u32 nb = *ip++;
    if (!nb) {
        if (ip != iend) return GZ_E_DATA;
        __builtin_memcpy(d->op, lit, litn);
        d->op += litn;
        return GZ_OK;
    }
    if (nb >= 128) {
        if (nb == 255) {
            if (iend - ip < 2) return GZ_E_DATA;
            nb = rd16(ip) + 0x7F00u;
            ip += 2;
        } else {
            if (ip >= iend) return GZ_E_DATA;
            nb = ((nb - 128) << 8) + *ip++;
        }
    }
    if (ip >= iend) return GZ_E_DATA;
    u32 modes = *ip++;
    if (modes & 3) return GZ_E_DATA;
    if (seq_table(d, modes >> 6, &ip, iend, d->llt, d->lld, 6, LL_MAX, LL_LOG, ll_base, ll_bits, &d->llp, &d->lllog) ||
        seq_table(d, (modes >> 4) & 3, &ip, iend, d->oft, d->ofd, 5, OF_MAX, OF_LOG, of_base, of_bits, &d->ofp, &d->oflog) ||
        seq_table(d, (modes >> 2) & 3, &ip, iend, d->mlt, d->mld, 6, ML_MAX, ML_LOG, ml_base, ml_bits, &d->mlp, &d->mllog))
        return GZ_E_DATA;
    d->seq_ok = 1;
#ifdef Z_HAVE_BMI2
    if (d->bmi2) return z_seqs_bmi2(d, ip, (size_t)(iend - ip), nb, lit, litn, d->op + cap);
#endif
    return z_seqs(d, ip, (size_t)(iend - ip), nb, lit, litn, d->op + cap);
}

/* ---------------- frames ---------------- */

int gz_zstd_frame_header(const u8 *p, size_t n, gz_zstd_frame_info *fi)
{
    static const u8 dsz[4] = { 0, 1, 2, 4 };
    if (n < 5) return GZ_E_TRUNC;
    if (rd32(p) != GZ_ZSTD_MAGIC || (p[4] & 8)) return GZ_E_FORMAT;   /* reserved bit */
    u32 fhd = p[4], single = (fhd >> 5) & 1, df = fhd & 3, ff = fhd >> 6;
    u32 fsz = ff ? (1u << ff) : single;
    u32 hl = 5 + !single + dsz[df] + fsz;
    if (n < hl) return GZ_E_TRUNC;
    const u8 *q = p + 5;
    u64 window = 0, fcs = GZ_SIZE_UNKNOWN;
    if (!single) {
        u32 wd = *q++;
        window = (u64)1 << (10 + (wd >> 3));
        window += (window >> 3) * (wd & 7);
    }
    u32 did = 0;
    if (df == 1) did = q[0];
    else if (df == 2) did = rd16(q);
    else if (df == 3) did = rd32(q);
    q += dsz[df];
    if (fsz == 1) fcs = q[0];
    else if (fsz == 2) fcs = rd16(q) + 256u;
    else if (fsz == 4) fcs = rd32(q);
    else if (fsz == 8) fcs = rd64(q);
    if (single) window = fcs;
    fi->content_size = fcs;
    fi->window = window;
    fi->header_len = hl;
    fi->dict_id = did;
    fi->single_segment = (u8)single;
    fi->has_checksum = (u8)((fhd >> 2) & 1);
    return GZ_OK;
}

static int z_frame(gz_zstd_dec *d, const gz_stream_io *io)
{
    gz_zstd_frame_info fi;
    int r = z_need(d, io, 18);                     /* largest header; a tiny last frame may be shorter */
    if (r && r != GZ_E_TRUNC) return r;
    r = gz_zstd_frame_header(d->ip, (size_t)(d->iend - d->ip), &fi);
    if (r) return r == GZ_E_FORMAT ? GZ_E_DATA : r;
    if (fi.dict_id) return GZ_E_METHOD;
    d->ip += fi.header_len;

    u64 fcs = fi.content_size, eff = fi.window;
    if (fcs != GZ_SIZE_UNKNOWN && fcs < eff) eff = fcs;
    if (eff > Z_WCAP) return GZ_E_LIMIT;
    size_t bmax = fi.window < ZB_MAX ? (size_t)fi.window : ZB_MAX;
    u64 S = eff + 2 * (u64)(bmax + Z_SLACK);
    if (S < Z_WMIN) S = Z_WMIN;
    if (fcs != GZ_SIZE_UNKNOWN && fcs < S) S = fcs;
    d->wsize = (size_t)S;
    d->window = (size_t)eff;
    size_t first = d->wsize <= Z_WINIT + Z_WINIT / 2 ? d->wsize : Z_WINIT;
    if (d->walloc < first + Z_SLACK) {
        zmem_free(d->wbuf, d->walloc);
        d->walloc = 0;
        d->wbuf = (u8 *)zmem_alloc(first + Z_SLACK);
        if (!d->wbuf) return GZ_E_NOMEM;
        d->walloc = first + Z_SLACK;
    }
    d->wcur = d->walloc - Z_SLACK < d->wsize ? d->walloc - Z_SLACK : d->wsize;
    d->op = d->flushed = d->wbuf;
    d->ext_end = 0;
    d->rep[0] = 1; d->rep[1] = 4; d->rep[2] = 8;
    d->huf_ok = d->seq_ok = 0;
    d->check = fi.has_checksum;
    if (d->check) gz_xxh64_init(&d->xh, 0);

    u64 fprod = 0;
    for (;;) {
        r = z_need(d, io, 3);
        if (r) return r;
        u32 bh = rd24(d->ip), last = bh & 1, type = (bh >> 1) & 3;
        size_t bs = bh >> 3, cap = bmax;
        d->ip += 3;
        if (fcs != GZ_SIZE_UNKNOWN && fcs - fprod < cap) cap = (size_t)(fcs - fprod);
        if ((size_t)(d->wbuf + d->wcur - d->op) < cap && (r = z_room(d, io, cap))) return r;
        u8 *start = d->op;
        if (type == 0) {
            if (bs > cap) return GZ_E_DATA;
            if ((r = z_need(d, io, bs))) return r;
            __builtin_memcpy(d->op, d->ip, bs);
            d->ip += bs;
            d->op += bs;
        } else if (type == 1) {
            if (bs > cap) return GZ_E_DATA;
            if ((r = z_need(d, io, 1))) return r;
            __builtin_memset(d->op, *d->ip++, bs);
            d->op += bs;
        } else if (type == 2) {
            if (bs > bmax) return GZ_E_DATA;
            if ((r = z_need(d, io, bs))) return r;
            if ((r = z_block(d, d->ip, bs, cap))) return r;
            d->ip += bs;
        } else {
            return GZ_E_DATA;
        }
        fprod += (u64)(d->op - start);
        if (d->out_size != GZ_SIZE_UNKNOWN && d->out_total + (u64)(d->op - d->flushed) >= d->out_size) {
            if ((r = z_flush(d, io))) return r;
            if (!last) return Z_STOP;
        } else if ((size_t)(d->op - d->flushed) >= Z_FLUSH) {
            if ((r = z_flush(d, io))) return r;
        }
        if (last) break;
    }
    if ((r = z_flush(d, io))) return r;
    if (fcs != GZ_SIZE_UNKNOWN && fprod != fcs) return GZ_E_DATA;
    if (d->check) {
        if ((r = z_need(d, io, 4))) return r;
        if (rd32(d->ip) != (u32)gz_xxh64_digest(&d->xh)) return GZ_E_CRC;
        d->ip += 4;
    }
    return GZ_OK;
}

static int z_skip(gz_zstd_dec *d, const gz_stream_io *io)
{
    int r = z_need(d, io, 8);
    if (r) return r;
    u64 n = rd32(d->ip + 4);
    d->ip += 8;
    for (;;) {
        size_t have = (size_t)(d->iend - d->ip);
        if (have >= n) {
            d->ip += n;
            return GZ_OK;
        }
        n -= have;
        d->ip = d->iend;
        if ((r = z_need(d, io, 1))) return r;
    }
}

int gz_zstd_decode_ex(gz_zstd_dec *d, const gz_stream_io *io, u64 out_size, u32 flags, u64 *in_used)
{
    int r = GZ_OK, any = 0;
    d->ip = d->iend = d->ibuf;
    d->eof = 0;
    d->in_total = 0;
    d->out_total = 0;
    d->out_size = out_size;
#ifdef Z_HAVE_BMI2
    d->bmi2 = g_cpu.active >= GZ_TIER_AVX2 && (g_cpu.features & CPUF_BMI2);
#endif
    for (;;) {
        if (any && out_size != GZ_SIZE_UNKNOWN && d->out_total >= out_size) break;
        r = z_need(d, io, 4);
        if (r == GZ_E_TRUNC && d->iend == d->ip) {
            r = any ? GZ_OK : GZ_E_TRUNC;      /* clean end between frames */
            break;
        }
        if (r) break;
        u32 magic = rd32(d->ip);
        if (magic == GZ_ZSTD_MAGIC) {
            r = z_frame(d, io);
            any = 1;
            if (r == Z_STOP) { r = GZ_OK; break; }
            if (r || (flags & GZ_ZSTD_ONE_FRAME)) break;
        } else if ((magic & 0xFFFFFFF0u) == GZ_ZSTD_SKIP_MAGIC) {
            r = z_skip(d, io);
            any = 1;
            if (r) break;
        } else if (magic >= 0xFD2FB51Eu && magic <= 0xFD2FB527u) {
            r = GZ_E_METHOD;                   /* legacy v0.1-v0.7 frame */
            break;
        } else {
            r = any ? GZ_E_DATA : GZ_E_FORMAT;
            break;
        }
    }
    if (!r && out_size != GZ_SIZE_UNKNOWN && d->out_total < out_size) r = GZ_E_DATA;
    if (in_used) *in_used = d->in_total - (u64)(d->iend - d->ip);
    if (d->walloc > Z_WKEEP) {
        zmem_free(d->wbuf, d->walloc);
        d->wbuf = 0;
        d->walloc = 0;
    }
    return r;
}

int gz_zstd_decode(gz_zstd_dec *d, const gz_stream_io *io, u64 out_size, u64 *in_used)
{
    return gz_zstd_decode_ex(d, io, out_size, 0, in_used);
}

/* ---------------- memory to memory ---------------- */

typedef struct { const u8 *p; size_t n; u8 *dst; size_t cap, len; } zmio;

static int zm_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    zmio *m = (zmio *)ctx;
    size_t k = m->n < cap ? m->n : cap;
    __builtin_memcpy(buf, m->p, k);
    m->p += k;
    m->n -= k;
    *got = (u32)k;
    return GZ_OK;
}

static int zm_write(void *ctx, const u8 *p, size_t n)
{
    zmio *m = (zmio *)ctx;
    if (n > m->cap - m->len) return GZ_E_DATA;
    __builtin_memcpy(m->dst + m->len, p, n);
    m->len += n;
    return GZ_OK;
}

int gz_zstd_decode_mem(gz_zstd_dec *d, const void *src, size_t sn, void *dst, size_t dcap, size_t *dn)
{
    zmio m = { (const u8 *)src, sn, (u8 *)dst, dcap, 0 };
    gz_stream_io io = { zm_read, zm_write, &m };
    int r = gz_zstd_decode_ex(d, &io, GZ_SIZE_UNKNOWN, 0, 0);
    if (dn) *dn = m.len;
    return r;
}
