/*
 * 고깃ZIP - Zstandard encoder (RFC 8878), see zstd_enc.h
 *
 * Window: one buffer, buf[0] is a dummy so that index 0 means "empty" in every
 * match table. Data of the current frame starts at index fstart; the parser
 * works at cur, input is read ahead up to end. When the buffer is full, the
 * last window's worth of data is moved to the front and every table entry is
 * rebased (the shift is a multiple of the chain/tree cycle so that cyclic slots
 * keep their meaning). Matches reach back at most 1 << wlog bytes.
 *
 * A block is parsed into sequences (literal length, offset, match length) with
 * literals copied aside; offsets are turned into repeat codes against the
 * decoder's repeat-offset state as they are stored. The entropy stage then
 * builds the literals section (raw, RLE, Huffman with a new or repeated table)
 * and the sequences section (per stream: predefined, RLE, computed FSE table or
 * repeat, chosen by estimated cost). A block that would not shrink is sent raw
 * (or RLE), and then none of the block's repeat offsets or tables are kept,
 * since the decoder never sees them.
 */
#include "zstd_enc.h"
#include "xxhash.h"

#define ZB        (128u << 10)          /* largest block                          */
#define SLACK     64u                   /* readable bytes after every buffer      */
#define NSEQ_MAX  (ZB / 3 + 16)         /* every sequence has a match of >= 3     */
#define OPT_NUM   (1u << 12)            /* optimal parser look-ahead              */
#define BT_CAP    (1u << 12)            /* byte comparisons per tree node         */
#define MAX_MATCHES 512u
#define OUT_FLUSH (512u << 10)
#define BIG       ((size_t)1 << 20)     /* allocations above this: gz_alloc_big   */
#define INF       0x3FFFFFFFu

enum { ST_STORE, ST_FAST, ST_DFAST, ST_GREEDY, ST_LAZY, ST_LAZY2, ST_BTLAZY2, ST_BTOPT, ST_BTULTRA };

/* window log, chain log, hash log, search log, min match, target length, strategy
 * (zstd's table for inputs > 256 KiB) */
typedef struct { u8 w, c, h, s, m; u16 t; u8 st; } zlv;
static const zlv k_lv[GZ_ZSTD_LEVEL_MAX + 1] = {
    { 17, 12, 13, 1, 6,   0, ST_STORE   },
    { 19, 13, 14, 1, 7,   0, ST_FAST    },
    { 20, 15, 16, 1, 6,   0, ST_FAST    },
    { 21, 16, 17, 1, 5,   0, ST_DFAST   },
    { 21, 18, 18, 1, 5,   0, ST_DFAST   },
    { 21, 18, 19, 3, 5,   2, ST_GREEDY  },
    { 21, 18, 19, 3, 5,   4, ST_LAZY    },
    { 21, 19, 20, 4, 5,   8, ST_LAZY    },
    { 21, 19, 20, 4, 5,  16, ST_LAZY2   },
    { 22, 20, 21, 4, 5,  16, ST_LAZY2   },
    { 22, 21, 22, 5, 5,  16, ST_LAZY2   },
    { 22, 21, 22, 6, 5,  16, ST_LAZY2   },
    { 22, 22, 23, 6, 5,  32, ST_LAZY2   },
    { 22, 22, 22, 4, 5,  32, ST_BTLAZY2 },
    { 22, 22, 23, 5, 5,  32, ST_BTLAZY2 },
    { 22, 23, 23, 6, 5,  32, ST_BTLAZY2 },
    { 22, 22, 22, 5, 5,  48, ST_BTOPT   },
    { 23, 23, 22, 5, 4,  64, ST_BTOPT   },
    { 23, 23, 22, 6, 3,  64, ST_BTULTRA },
    { 23, 24, 22, 7, 3, 256, ST_BTULTRA },
};

/* ---------------- code tables ---------------- */

#define LL_MAX 35
#define ML_MAX 52
#define OF_MAX 31

static const u8 ll_bits[LL_MAX + 1] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16
};
static const u8 ml_bits[ML_MAX + 1] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16
};
static const u8 ll_code_t[64] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21,
    22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24
};
static const u8 ml_code_t[128] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 32, 33, 33, 34, 34, 35, 35, 36, 36, 36, 36, 37, 37, 37, 37,
    38, 38, 38, 38, 38, 38, 38, 38, 39, 39, 39, 39, 39, 39, 39, 39,
    40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
    41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
    42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
    42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42
};
/* predefined distributions (RFC 8878 3.1.1.3.2.2) */
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

GZ_INLINE u32 highbit(u32 v) { return 31 - (u32)__builtin_clz(v); }      /* v != 0 */
GZ_INLINE u32 ll_code(u32 ll) { return ll > 63 ? highbit(ll) + 19 : ll_code_t[ll]; }
GZ_INLINE u32 ml_code(u32 mlb) { return mlb > 127 ? highbit(mlb) + 36 : ml_code_t[mlb]; }

/* ---------------- bit writer (forward, read backwards by the decoder) ---------------- */

typedef struct { u64 c; u32 n; u8 *p, *start; } zbw;

GZ_INLINE void bw_init(zbw *b, u8 *p) { b->c = 0; b->n = 0; b->p = b->start = p; }
GZ_INLINE void bw_add(zbw *b, u64 v, u32 nb) { b->c |= (v & (((u64)1 << nb) - 1)) << b->n; b->n += nb; }
GZ_INLINE void bw_addf(zbw *b, u64 v, u32 nb) { b->c |= v << b->n; b->n += nb; }   /* v < 2^nb */
GZ_INLINE void bw_flush(zbw *b)
{
    wr64(b->p, b->c);
    b->p += b->n >> 3;
    b->c >>= b->n & ~7u;            /* n <= 63 */
    b->n &= 7;
}
/* end mark + final bytes; returns the stream size */
GZ_INLINE size_t bw_close(zbw *b)
{
    bw_addf(b, 1, 1);
    bw_flush(b);
    return (size_t)(b->p - b->start) + (b->n > 0);
}

/* ---------------- FSE encoding tables ---------------- */

typedef struct { u32 dnb; i32 dfs; } ztt;
typedef struct { u16 st[512]; ztt tt[ML_MAX + 1]; u32 log; } zfse;
typedef struct { u32 v; } zfs;

static void fse_build(zfse *t, const i16 *norm, u32 maxsym, u32 log)
{
    u32 size = 1u << log, mask = size - 1, step = (size >> 1) + (size >> 3) + 3, high = size - 1;
    u8 sym[512];
    u32 cum[ML_MAX + 2];
    cum[0] = 0;
    for (u32 u = 1; u <= maxsym + 1; u++) {
        if (norm[u - 1] == -1) {
            cum[u] = cum[u - 1] + 1;
            sym[high--] = (u8)(u - 1);
        } else {
            cum[u] = cum[u - 1] + (u32)norm[u - 1];
        }
    }
    u32 pos = 0;
    for (u32 s = 0; s <= maxsym; s++)
        for (int k = 0; k < norm[s]; k++) {
            sym[pos] = (u8)s;
            do pos = (pos + step) & mask; while (pos > high);
        }
    for (u32 u = 0; u < size; u++) t->st[cum[sym[u]]++] = (u16)(size + u);
    u32 total = 0;
    for (u32 s = 0; s <= maxsym; s++) {
        int n = norm[s];
        if (n == 0) {
            t->tt[s].dnb = ((log + 1) << 16) - size;
            t->tt[s].dfs = 0;
        } else if (n == -1 || n == 1) {
            t->tt[s].dnb = (log << 16) - size;
            t->tt[s].dfs = (i32)total - 1;
            total++;
        } else {
            u32 mbo = log - highbit((u32)n - 1), msp = (u32)n << mbo;
            t->tt[s].dnb = (mbo << 16) - msp;
            t->tt[s].dfs = (i32)total - n;
            total += (u32)n;
        }
    }
    t->log = log;
}

static void fse_build_rle(zfse *t, u32 sym)
{
    t->st[0] = t->st[1] = 0;
    t->tt[sym].dnb = 0;
    t->tt[sym].dfs = 0;
    t->log = 0;
}

GZ_INLINE void fse_init2(zfs *s, const zfse *t, u32 sym)
{
    ztt tt = t->tt[sym];
    u32 nb = (tt.dnb + (1u << 15)) >> 16;
    u32 v = (nb << 16) - tt.dnb;
    s->v = t->st[(v >> nb) + (u32)tt.dfs];
}

GZ_INLINE void fse_enc(zbw *b, zfs *s, const zfse *t, u32 sym)
{
    ztt tt = t->tt[sym];
    u32 nb = (s->v + tt.dnb) >> 16;
    bw_add(b, s->v, nb);
    s->v = t->st[(s->v >> nb) + (u32)tt.dfs];
}

/* table log for n symbols with values 0..maxsym (FSE_optimalTableLog) */
static u32 fse_log(u32 maxlog, u32 n, u32 maxsym)
{
    u32 hb = highbit(n - 1 ? n - 1 : 1);
    u32 srcbits = hb > 2 ? hb - 2 : 0;
    u32 a = highbit(n) + 1, b = highbit(maxsym ? maxsym : 1) + 2;
    u32 minbits = a < b ? a : b;
    u32 log = maxlog;
    if (srcbits < log) log = srcbits;
    if (minbits > log) log = minbits;
    if (log < 5) log = 5;
    if (log > maxlog) log = maxlog;
    return log;
}

/* normalized counts summing to 1 << log (FSE_normalizeCount without "-1" cells);
 * every present symbol gets at least one cell */
static void fse_norm(i16 *norm, u32 log, const u32 *cnt, u32 total, u32 maxsym)
{
    static const u32 rtb[8] = { 0, 473195, 504333, 520860, 550000, 700000, 750000, 830000 };
    u32 scale = 62 - log;
    u64 step = ((u64)1 << 62) / total, vstep = (u64)1 << (scale - 20);
    int still = 1 << log;
    u32 low = total >> log, largest = 0;
    int largest_p = 0;
    for (u32 s = 0; s <= maxsym; s++) {
        if (!cnt[s]) { norm[s] = 0; continue; }
        if (cnt[s] <= low) {
            norm[s] = 1;
            still--;
            continue;
        }
        u64 v = cnt[s] * step;
        int p = (int)(v >> scale);
        if (p < 8) p += (v - ((u64)p << scale)) > vstep * rtb[p];
        if (p > largest_p) { largest_p = p; largest = s; }
        norm[s] = (i16)p;
        still -= p;
    }
    if (-still < (norm[largest] >> 1)) {
        norm[largest] = (i16)(norm[largest] + still);
        return;
    }
    while (still < 0) {          /* take cells from the largest counts */
        u32 m = 0;
        for (u32 s = 1; s <= maxsym; s++) if (norm[s] > norm[m]) m = s;
        norm[m]--;
        still++;
    }
    norm[largest] = (i16)(norm[largest] + still);
}

/* FSE table description (FSE_writeNCount); returns bytes written */
static size_t fse_write_ncount(u8 *out, const i16 *norm, u32 maxsym, u32 log)
{
    u8 *o = out;
    u32 size = 1u << log, bits = 0, nbits;
    int remaining = (int)size + 1, threshold = (int)size, prev0 = 0;
    u32 bc = 4, s = 0, alpha = maxsym + 1;
    bits = log - 5;
    nbits = log + 1;
    while (s < alpha && remaining > 1) {
        if (prev0) {
            u32 start = s;
            while (s < alpha && !norm[s]) s++;
            if (s == alpha) break;
            while (s >= start + 24) {
                start += 24;
                bits += 0xFFFFu << bc;
                o[0] = (u8)bits;
                o[1] = (u8)(bits >> 8);
                o += 2;
                bits >>= 16;
            }
            while (s >= start + 3) {
                start += 3;
                bits += 3u << bc;
                bc += 2;
            }
            bits += (s - start) << bc;
            bc += 2;
            if (bc > 16) {
                o[0] = (u8)bits;
                o[1] = (u8)(bits >> 8);
                o += 2;
                bits >>= 16;
                bc -= 16;
            }
        }
        int count = norm[s++];
        int max = (2 * threshold - 1) - remaining;
        remaining -= count < 0 ? -count : count;
        count++;
        if (count >= threshold) count += max;
        bits += (u32)count << bc;
        bc += nbits;
        bc -= count < max;
        prev0 = count == 1;
        while (remaining < threshold) {
            nbits--;
            threshold >>= 1;
        }
        if (bc > 16) {
            o[0] = (u8)bits;
            o[1] = (u8)(bits >> 8);
            o += 2;
            bits >>= 16;
            bc -= 16;
        }
    }
    o[0] = (u8)bits;
    o[1] = (u8)(bits >> 8);
    o += (bc + 7) / 8;
    return (size_t)(o - out);
}

/* log2(x) * 256 for x >= 1 (8 fraction bits by repeated squaring) */
static u32 lg8(u32 x)
{
    u32 hb = highbit(x), r = hb << 8;
    u64 m = ((u64)x << 16) >> hb;          /* [2^16, 2^17) */
    for (u32 bit = 128; bit; bit >>= 1) {
        m = (m * m) >> 16;
        if (m >= (1u << 17)) { m >>= 1; r += bit; }
    }
    return r;
}

/* bits * 256 to code cnt[0..maxsym] with a table, INF when a symbol is missing */
static u64 fse_cost(const i16 *norm, u32 nmax, u32 log, const u32 *cnt, u32 maxsym)
{
    u64 c = 0;
    if (maxsym > nmax) return INF;
    for (u32 s = 0; s <= maxsym; s++) {
        if (!cnt[s]) continue;
        int n = norm[s] == -1 ? 1 : norm[s];
        if (n <= 0) return INF;
        c += (u64)cnt[s] * ((log << 8) - lg8((u32)n));
    }
    return c;
}

/* ---------------- Huffman ---------------- */

typedef struct { u16 code[256]; u8 bits[256]; } zhuf;

/* in-place minimum-redundancy code lengths (Moffat & Katajainen); a[] ascending */
static void min_redundancy(u32 *a, int n)
{
    int root, leaf, next, avbl, used, dpth;
    if (n < 2) { a[0] = 1; return; }
    a[0] += a[1];
    root = 0;
    leaf = 2;
    for (next = 1; next < n - 1; next++) {
        if (leaf >= n || a[root] < a[leaf]) { a[next] = a[root]; a[root++] = (u32)next; }
        else a[next] = a[leaf++];
        if (leaf >= n || (root < next && a[root] < a[leaf])) { a[next] += a[root]; a[root++] = (u32)next; }
        else a[next] += a[leaf++];
    }
    a[n - 2] = 0;
    for (next = n - 3; next >= 0; next--) a[next] = a[a[next]] + 1;
    avbl = 1;
    used = dpth = 0;
    root = n - 2;
    next = n - 1;
    while (avbl > 0) {
        while (root >= 0 && a[root] == (u32)dpth) { used++; root--; }
        while (avbl > used) { a[next--] = (u32)dpth; avbl--; }
        avbl = 2 * used;
        dpth++;
        used = 0;
    }
}

/* length-limited Huffman code (max 11 bits) for 2+ symbols; returns the table log */
static u32 huf_build(zhuf *h, const u32 *cnt, u32 maxsym)
{
    u32 sym[256], a[256], num[16] = { 0 };
    int n = 0;
    a[0] = a[1] = 0;
    __builtin_memset(h->bits, 0, sizeof h->bits);     /* a repeated table must not see stale codes */
    for (u32 s = 0; s <= maxsym; s++) {
        if (!cnt[s]) continue;
        u32 c = cnt[s];
        int i = n++;
        while (i > 0 && cnt[sym[i - 1]] > c) { sym[i] = sym[i - 1]; i--; }
        sym[i] = s;
    }
    for (int i = 0; i < n; i++) a[i] = cnt[sym[i]];
    min_redundancy(a, n);
    for (int i = 0; i < n; i++) num[a[i] > 11 ? 11 : a[i]]++;
    u32 total = 0;
    for (u32 l = 1; l <= 11; l++) total += num[l] << (11 - l);
    while (total > (1u << 11)) {
        num[11]--;
        for (u32 l = 10; l > 0; l--)
            if (num[l]) { num[l]--; num[l + 1] += 2; break; }
        total--;
    }
    u32 log = 0;
    int i = 0;
    for (u32 l = 11; l >= 1; l--)
        for (u32 k = 0; k < num[l]; k++) {
            h->bits[sym[i++]] = (u8)l;
            if (l > log) log = l;
        }
    /* canonical codes as the decoder derives them from the weights */
    u16 nper[13] = { 0 }, val[13] = { 0 };
    for (u32 s = 0; s <= maxsym; s++) if (h->bits[s]) nper[h->bits[s]]++;
    u16 mn = 0;
    for (u32 l = log; l > 0; l--) {
        val[l] = mn;
        mn = (u16)(mn + nper[l]);
        mn >>= 1;
    }
    for (u32 s = 0; s <= maxsym; s++) if (h->bits[s]) h->code[s] = val[h->bits[s]]++;
    return log;
}

/* FSE-compressed weights (HUF_compressWeights): 0 = not compressible, 1 = RLE */
static size_t huf_weights_fse(u8 *out, const u8 *w, u32 nw)
{
    u32 cnt[16] = { 0 }, maxw = 0, maxc = 0;
    for (u32 i = 0; i < nw; i++) cnt[w[i]]++;
    for (u32 s = 0; s < 16; s++) if (cnt[s]) { maxw = s; if (cnt[s] > maxc) maxc = cnt[s]; }
    if (maxc == nw) return 1;
    if (maxc == 1) return 0;
    i16 norm[16];
    u32 log = fse_log(6, nw, maxw);
    fse_norm(norm, log, cnt, nw, maxw);
    size_t hs = fse_write_ncount(out, norm, maxw, log);
    zfse t;
    fse_build(&t, norm, maxw, log);
    /* two interleaved states (FSE_compress_usingCTable) */
    zbw b;
    zfs s1, s2;
    const u8 *ip = w + nw;
    if (nw <= 2) return 0;
    bw_init(&b, out + hs);
    if (nw & 1) {
        fse_init2(&s1, &t, *--ip);
        fse_init2(&s2, &t, *--ip);
        fse_enc(&b, &s1, &t, *--ip);
        bw_flush(&b);
    } else {
        fse_init2(&s2, &t, *--ip);
        fse_init2(&s1, &t, *--ip);
    }
    if ((nw - 2) & 2) {
        fse_enc(&b, &s2, &t, *--ip);
        fse_enc(&b, &s1, &t, *--ip);
        bw_flush(&b);
    }
    while (ip > w) {
        fse_enc(&b, &s2, &t, *--ip);
        fse_enc(&b, &s1, &t, *--ip);
        fse_enc(&b, &s2, &t, *--ip);
        fse_enc(&b, &s1, &t, *--ip);
        bw_flush(&b);
    }
    bw_add(&b, s2.v, log);
    bw_flush(&b);
    bw_add(&b, s1.v, log);
    bw_flush(&b);
    return hs + bw_close(&b);
}

/* tree description; returns bytes, 0 if the table cannot be described */
static size_t huf_write_table(u8 *out, const zhuf *h, u32 maxsym, u32 log)
{
    u8 w[257];
    u32 nw = maxsym;            /* the last symbol's weight is implied */
    for (u32 s = 0; s < nw; s++) w[s] = h->bits[s] ? (u8)(log + 1 - h->bits[s]) : 0;
    size_t hs = huf_weights_fse(out + 1, w, nw);
    if (hs > 1 && hs < nw / 2) {
        out[0] = (u8)hs;
        return hs + 1;
    }
    if (nw > 128) return 0;
    out[0] = (u8)(127 + nw);
    w[nw] = 0;
    for (u32 i = 0; i < nw; i += 2) out[1 + i / 2] = (u8)((w[i] << 4) | w[i + 1]);
    return 1 + (nw + 1) / 2;
}

/* one Huffman stream, symbols coded from the last to the first */
static size_t huf_stream(u8 *out, const u8 *src, size_t n, const zhuf *h)
{
    u64 c = 0;
    u32 nb = 0;
    u8 *p = out;
    size_t i = n;
#define HS(k) do { u32 s_ = src[k]; c |= (u64)h->code[s_] << nb; nb += h->bits[s_]; } while (0)
#define HF() do { wr64(p, c); p += nb >> 3; c >>= nb & ~7u; nb &= 7; } while (0)
    while (i & 3) { i--; HS(i); HF(); }
    while (i) {
        HS(i - 1); HS(i - 2); HS(i - 3); HS(i - 4);
        HF();
        i -= 4;
    }
    c |= (u64)1 << nb;
    nb++;
    HF();
#undef HS
#undef HF
    return (size_t)(p - out) + (nb > 0);
}

/* ---------------- encoder state ---------------- */

typedef struct { u32 ll, ml, ob; } zseq;     /* ob: offset + 3, or repeat code 1..3 */
typedef struct { u32 len, ob; } zmatch;
typedef struct { u32 price, ob, mlen, litlen, rep[3]; } znode;

/* one sequence stream's table: the committed one and the one built for a block */
typedef struct { zfse ct; i16 norm[ML_MAX + 1]; u32 max; int ok; } zfst;

typedef struct {
    u32 lit[256], ll[LL_MAX + 1], ml[ML_MAX + 1], of[OF_MAX + 1];
    u32 slit, sll, sml, sof;
    u32 plit, pll, pml, pof;
} zstats;

struct gz_zstd_enc {
    zlv p;
    int level, checksum;
    u32 wlog_alloc, wlog;
    /* window (indices into buf) */
    u8 *buf;
    size_t bsize;
    u32 lim, cur, end, fstart, nupd, low, cycle;
    int eof;
    /* match tables */
    u32 *ht, *ht2, *ct;
    size_t ht_n, ht2_n, ct_n;
    u8 *tags, *heads;               /* row match finder                       */
    u32 rlog;
    /* block parse */
    zseq *seq;
    u32 nseq;
    u8 *lit;
    u32 nlit;
    u32 rep[3], crep[3];
    u8 *codes;               /* ll, ml, of codes: 3 * NSEQ_MAX */
    /* entropy */
    zhuf huf, hufp;
    int hufp_ok;
    zfst fs[3][2];
    u8 fcur[3];
    /* output */
    u8 *blk, *obuf;
    size_t blk_cap, on, ocap;
    /* optimal parser */
    znode *nodes;
    zmatch *mt;
    zstats *st;
    u32 *path;
    /* accounting */
    u64 in_total, out_total, content;
    const gz_stream_io *io;
    gz_xxh64_state xh;
};

static void *big_alloc(size_t n) { return n > BIG ? gz_alloc_big(n) : gz_alloc(n); }
static void big_free(void *p, size_t n)
{
    if (!p) return;
    if (n > BIG) gz_free_big(p, n); else gz_free(p);
}

static int is_bt(int st) { return st >= ST_BTLAZY2; }
static int is_row(int st) { return st >= ST_GREEDY && st <= ST_LAZY2; }
static u32 row_log(const zlv *p) { return p->s < 4 ? 4 : p->s > 6 ? 6 : p->s; }

static u32 ceil_log2(u64 v)
{
    u32 l = 0;
    while (l < 63 && ((u64)1 << l) < v) l++;
    return l;
}

/* parameters of a level adjusted to the window */
static zlv params(const gz_zstd_enc_opts *o, u32 *wlog_out)
{
    int lv = o->level < 0 ? 3 : o->level > GZ_ZSTD_LEVEL_MAX ? GZ_ZSTD_LEVEL_MAX : o->level;
    zlv p = k_lv[lv];
    u32 w = o->window_log ? o->window_log : p.w;
    if (o->size_hint) {
        u32 need = ceil_log2(o->size_hint);
        if (need < GZ_ZSTD_WINDOWLOG_MIN) need = GZ_ZSTD_WINDOWLOG_MIN;
        if (need < w) w = need;
    }
    if (p.h > w + 1) p.h = (u8)(w + 1);
    u32 cyc = p.c - (is_bt(p.st) ? 1 : 0);
    if (cyc > w) p.c = (u8)(p.c - (cyc - w));
    if (p.m < 4 && !is_bt(p.st)) p.m = 4;      /* 3-byte matches: binary trees only */
    if (p.st != ST_FAST && p.st != ST_DFAST && p.m > 6) p.m = 6;
    p.w = (u8)w;
    *wlog_out = w;
    return p;
}

static size_t buf_size(const zlv *p)
{
    size_t w = (size_t)1 << p->w, cyc = is_bt(p->st) ? (size_t)1 << (p->c - 1) : 1;
    size_t ch = w > cyc ? w : cyc;
    if (ch < BIG) ch = p->st == ST_STORE ? ZB : BIG;     /* store: no matches, small read-ahead */
    return 1 + w + ch + 3 * (size_t)ZB + SLACK;
}

void gz_zstd_enc_opts_init(gz_zstd_enc_opts *o, int level)
{
    __builtin_memset(o, 0, sizeof *o);
    o->level = level;
    o->checksum = 1;
}

u64 gz_zstd_enc_memusage(const gz_zstd_enc_opts *o)
{
    u32 w;
    zlv p = params(o, &w);
    u64 m = sizeof(gz_zstd_enc) + buf_size(&p) + (u64)NSEQ_MAX * (sizeof(zseq) + 3 + 12) + (ZB + SLACK) +
            (2 * (u64)ZB + 1024) + (OUT_FLUSH + ZB + 64);
    if (p.st == ST_STORE) return m;
    m += ((u64)4 << p.h);
    if (p.st == ST_DFAST || is_bt(p.st)) m += (u64)4 << p.c;
    if (is_row(p.st)) m += ((u64)1 << p.h) + ((u64)1 << (p.h - row_log(&p)));
    if (is_bt(p.st)) m += MAX_MATCHES * sizeof(zmatch);
    if (p.st >= ST_BTOPT) m += (OPT_NUM + 1024) * (u64)sizeof(znode) + sizeof(zstats) + OPT_NUM * 12;
    return m;
}

void gz_zstd_enc_free(gz_zstd_enc *e)
{
    if (!e) return;
    big_free(e->buf, e->bsize);
    big_free(e->ht, e->ht_n * 4);
    big_free(e->ht2, e->ht2_n * 4);
    big_free(e->ct, e->ct_n * 4);
    big_free(e->tags, e->ht_n);
    big_free(e->heads, e->ht_n >> e->rlog);
    gz_free(e->seq);
    gz_free(e->lit);
    gz_free(e->codes);
    gz_free(e->blk);
    gz_free(e->obuf);
    gz_free(e->nodes);
    gz_free(e->mt);
    gz_free(e->st);
    gz_free(e->path);
    gz_free(e);
}

gz_zstd_enc *gz_zstd_enc_new(const gz_zstd_enc_opts *o)
{
    gz_zstd_enc_opts def;
    if (!o) { gz_zstd_enc_opts_init(&def, 3); o = &def; }
    if (o->window_log && (o->window_log < GZ_ZSTD_WINDOWLOG_MIN || o->window_log > GZ_ZSTD_WINDOWLOG_MAX)) return 0;
    gz_zstd_enc *e = (gz_zstd_enc *)gz_alloc(sizeof *e);
    if (!e) return 0;
    e->p = params(o, &e->wlog_alloc);
    e->level = o->level;
    e->checksum = o->checksum != 0;
    e->bsize = buf_size(&e->p);
    e->lim = (u32)(e->bsize - SLACK);
    e->cycle = is_bt(e->p.st) ? 1u << (e->p.c - 1) : 1;
    e->rlog = row_log(&e->p);
    e->buf = (u8 *)big_alloc(e->bsize);
    e->blk_cap = 2 * (size_t)ZB + (size_t)NSEQ_MAX * 12 + 1024;
    e->blk = (u8 *)gz_alloc(e->blk_cap);
    e->ocap = OUT_FLUSH + ZB + 64;
    e->obuf = (u8 *)gz_alloc(e->ocap);
    e->seq = (zseq *)gz_alloc(NSEQ_MAX * sizeof(zseq));
    e->lit = (u8 *)gz_alloc(ZB + SLACK);
    e->codes = (u8 *)gz_alloc(3 * (size_t)NSEQ_MAX);
    int ok = e->buf && e->blk && e->obuf && e->seq && e->lit && e->codes;
    if (ok && e->p.st != ST_STORE) {
        e->ht_n = (size_t)1 << e->p.h;
        e->ht = (u32 *)big_alloc(e->ht_n * 4);
        ok = e->ht != 0;
        if (ok && e->p.st == ST_DFAST) {
            e->ht2_n = (size_t)1 << e->p.c;
            e->ht2 = (u32 *)big_alloc(e->ht2_n * 4);
            ok = e->ht2 != 0;
        }
        if (ok && is_bt(e->p.st)) {
            e->ct_n = (size_t)1 << e->p.c;
            e->ct = (u32 *)big_alloc(e->ct_n * 4);
            ok = e->ct != 0;
        }
        if (ok && is_row(e->p.st)) {
            e->tags = (u8 *)big_alloc(e->ht_n);
            e->heads = (u8 *)big_alloc(e->ht_n >> e->rlog);
            ok = e->tags && e->heads;
        }
        if (ok && is_bt(e->p.st)) {
            e->mt = (zmatch *)gz_alloc(MAX_MATCHES * sizeof(zmatch));
            ok = e->mt != 0;
        }
        if (ok && e->p.st >= ST_BTOPT) {
            e->nodes = (znode *)gz_alloc((OPT_NUM + 1024) * sizeof(znode));
            e->st = (zstats *)gz_alloc(sizeof(zstats));
            e->path = (u32 *)gz_alloc(OPT_NUM * 3 * sizeof(u32));
            ok = e->nodes && e->st && e->path;
        }
    }
    if (!ok) { gz_zstd_enc_free(e); return 0; }
    e->cur = e->end = e->fstart = e->nupd = 1;
    return e;
}

u64 gz_zstd_enc_in_size(const gz_zstd_enc *e) { return e->in_total; }
u64 gz_zstd_enc_out_size(const gz_zstd_enc *e) { return e->out_total; }

/* ---------------- window ---------------- */

static void rebase(u32 *t, size_t n, u32 s)
{
    for (size_t i = 0; i < n; i++) {
        u32 v = t[i];
        t[i] = v > s ? v - s : 0;
    }
}

/* move the last window (and what follows) to the front of the buffer */
static void slide(gz_zstd_enc *e)
{
    u32 w = 1u << e->wlog;
    u32 keep = e->cur > w + 1 ? e->cur - w : 1;
    u32 s = (keep - 1) & ~(e->cycle - 1);
    if (!s) return;
    __builtin_memmove(e->buf + 1, e->buf + 1 + s, e->end - 1 - s);
    if (e->ht) rebase(e->ht, e->ht_n, s);
    if (e->ht2) rebase(e->ht2, e->ht2_n, s);
    if (e->ct) rebase(e->ct, e->ct_n, s);
    e->cur -= s;
    e->end -= s;
    e->nupd = e->nupd > s ? e->nupd - s : 1;
    e->fstart = e->fstart > s ? e->fstart - s : 1;
}

/* read until more than one block is buffered after cur, or the input ends */
static int load(gz_zstd_enc *e)
{
    while (!e->eof && e->end - e->cur <= ZB) {
        if (e->lim - e->end < ZB + 1) slide(e);
        u32 room = e->lim - e->end, got = 0;
        if (room < ZB) return GZ_E_LIMIT;       /* cannot happen: the buffer holds 2 windows */
        int r = e->io->read(e->io->ctx, e->buf + e->end, room, &got);
        if (r) return r;
        if (got > room) got = room;
        if (!got) { e->eof = 1; break; }
        if (e->checksum) gz_xxh64_update(&e->xh, e->buf + e->end, got);
        e->in_total += got;
        if (e->content != GZ_SIZE_UNKNOWN && e->in_total > e->content) return GZ_E_DATA;
        e->end += got;
    }
    return GZ_OK;
}

/* ---------------- match helpers ---------------- */

GZ_INLINE u32 zcount(const u8 *p, const u8 *q, const u8 *pend)
{
    const u8 *s = p;
    while (p + 8 <= pend) {
        u64 x = rd64(p) ^ rd64(q);
        if (x) return (u32)(p - s) + ((u32)__builtin_ctzll(x) >> 3);
        p += 8;
        q += 8;
    }
    while (p < pend && *p == *q) { p++; q++; }
    return (u32)(p - s);
}

/* hash of the first mls (4..8) bytes */
#define PRIME8 0xCF1BBCDCB7A56463ull
GZ_INLINE u32 zhash(const u8 *p, u32 shl, u32 shr) { return (u32)(((rd64(p) << shl) * PRIME8) >> shr); }

/* append a sequence: literals copied aside, offset turned into a repeat code
 * when possible (decoder semantics, RFC 8878 3.1.1.5) */
GZ_INLINE void store_seq(gz_zstd_enc *e, const u8 *lit, u32 ll, u32 off, u32 ml)
{
    u8 *d = e->lit + e->nlit;
    for (u32 i = 0; i < ll; i += 16) __builtin_memcpy(d + i, lit + i, 16);
    e->nlit += ll;
    u32 *rep = e->rep, ob;
    if (ll) ob = off == rep[0] ? 1 : off == rep[1] ? 2 : off == rep[2] ? 3 : off + 3;
    else ob = off == rep[1] ? 1 : off == rep[2] ? 2 : off == rep[0] - 1 ? 3 : off + 3;
    if (ob > 3) {
        rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = off;
    } else if (ob - 1 + (ll == 0)) {
        if (ob - 1 + (ll == 0) != 1) rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = off;
    }
    zseq *s = &e->seq[e->nseq++];
    s->ll = ll;
    s->ml = ml;
    s->ob = ob;
}

/* ---------------- fast: one hash table ---------------- */

static u32 parse_fast(gz_zstd_enc *e, u32 ip, u32 iend)
{
    const u8 *b = e->buf;
    u32 *ht = e->ht, low = e->low, anchor = ip, ilimit = iend - 8;
    u32 shl = 64 - 8 * e->p.m, shr = 64 - e->p.h;
    if (ip == e->fstart) ip++;
    while (ip < ilimit) {
        u32 h = zhash(b + ip, shl, shr), cand = ht[h], ml, off, start;
        ht[h] = ip;
        u32 r0 = e->rep[0];
        if (r0 <= ip + 1 - low && rd32(b + ip + 1) == rd32(b + ip + 1 - r0)) {
            start = ip + 1;
            off = r0;
            ml = zcount(b + start + 4, b + start + 4 - off, b + iend) + 4;
        } else if (cand >= low && rd32(b + cand) == rd32(b + ip)) {
            start = ip;
            off = ip - cand;
            ml = zcount(b + ip + 4, b + cand + 4, b + iend) + 4;
            while (start > anchor && cand > low && b[start - 1] == b[cand - 1]) { start--; cand--; ml++; }
        } else {
            ip += ((ip - anchor) >> 8) + 1;
            continue;
        }
        store_seq(e, b + anchor, start - anchor, off, ml);
        ip = anchor = start + ml;
        if (ip <= ilimit) {
            ht[zhash(b + start + 2, shl, shr)] = start + 2;
            ht[zhash(b + ip - 2, shl, shr)] = ip - 2;
            for (;;) {
                u32 r1 = e->rep[1];
                if (ip > ilimit || r1 > ip - low || rd32(b + ip) != rd32(b + ip - r1)) break;
                ml = zcount(b + ip + 4, b + ip + 4 - r1, b + iend) + 4;
                ht[zhash(b + ip, shl, shr)] = ip;
                store_seq(e, b + anchor, 0, r1, ml);
                ip = anchor = ip + ml;
            }
        }
    }
    return anchor;
}

/* ---------------- double fast: long (8-byte) + short hash tables ---------------- */

static u32 parse_dfast(gz_zstd_enc *e, u32 ip, u32 iend)
{
    const u8 *b = e->buf;
    u32 *hl = e->ht, *hs = e->ht2, low = e->low, anchor = ip, ilimit = iend - 8;
    u32 shs = 64 - 8 * e->p.m, srl = 64 - e->p.h, srs = 64 - e->p.c;
    if (ip == e->fstart) ip++;
    while (ip < ilimit) {
        u32 h1 = zhash(b + ip, 0, srl), h2 = zhash(b + ip, shs, srs);
        u32 cl = hl[h1], cs = hs[h2], ml, off, start = ip, cand;
        hl[h1] = hs[h2] = ip;
        u32 r0 = e->rep[0];
        if (r0 <= ip + 1 - low && rd32(b + ip + 1) == rd32(b + ip + 1 - r0)) {
            start = ip + 1;
            off = r0;
            ml = zcount(b + start + 4, b + start + 4 - off, b + iend) + 4;
            goto found;
        }
        if (cl >= low && rd64(b + cl) == rd64(b + ip)) {
            cand = cl;
            ml = zcount(b + ip + 8, b + cl + 8, b + iend) + 8;
        } else if (cs >= low && rd32(b + cs) == rd32(b + ip)) {
            u32 h3 = zhash(b + ip + 1, 0, srl), c3 = hl[h3];
            hl[h3] = ip + 1;
            if (c3 >= low && rd64(b + c3) == rd64(b + ip + 1)) {
                start = ip + 1;
                cand = c3;
                ml = zcount(b + start + 8, b + c3 + 8, b + iend) + 8;
            } else {
                cand = cs;
                ml = zcount(b + ip + 4, b + cs + 4, b + iend) + 4;
            }
        } else {
            ip += ((ip - anchor) >> 8) + 1;
            continue;
        }
        off = start - cand;
        while (start > anchor && cand > low && b[start - 1] == b[cand - 1]) { start--; cand--; ml++; }
    found:
        store_seq(e, b + anchor, start - anchor, off, ml);
        ip = anchor = start + ml;
        if (ip <= ilimit) {
            u32 k = start + 2;
            hl[zhash(b + k, 0, srl)] = k;
            hl[zhash(b + ip - 2, 0, srl)] = ip - 2;
            hs[zhash(b + k + 1, shs, srs)] = k + 1;
            hs[zhash(b + ip - 1, shs, srs)] = ip - 1;
            for (;;) {
                u32 r1 = e->rep[1];
                if (ip > ilimit || r1 > ip - low || rd32(b + ip) != rd32(b + ip - r1)) break;
                ml = zcount(b + ip + 4, b + ip + 4 - r1, b + iend) + 4;
                hs[zhash(b + ip, shs, srs)] = ip;
                hl[zhash(b + ip, 0, srl)] = ip;
                store_seq(e, b + anchor, 0, r1, ml);
                ip = anchor = ip + ml;
            }
        }
    }
    return anchor;
}

/* ---------------- rows of recent positions (greedy / lazy / lazy2) ----------------
 *
 * The hash of a position selects a row of 16..64 slots (newest at heads[row],
 * filled backwards) and an 8-bit tag. A search compares the whole row of tags
 * at once and only looks at the data of slots whose tag matches, newest first:
 * far fewer cache misses than walking a hash chain (zstd's row match finder). */

#if defined(__x86_64__)
#include <emmintrin.h>
GZ_INLINE u64 row_tags(const u8 *t, u32 tag, u32 n)        /* SSE2 is part of x86-64 */
{
    __m128i v = _mm_set1_epi8((char)tag);
    u64 m = 0;
    for (u32 i = 0; i < n; i += 16)
        m |= (u64)(u32)_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128((const __m128i *)(t + i)), v)) << i;
    return m;
}
#else
/* bit k set where byte k of w equals the byte of t8 (t8 = tag * 0x0101..) */
GZ_INLINE u64 tag_bits8(u64 w, u64 t8)
{
    u64 x = w ^ t8;
    u64 nz = ((x & 0x7F7F7F7F7F7F7F7Full) + 0x7F7F7F7F7F7F7F7Full) | x;
    return (((~nz & 0x8080808080808080ull) >> 7) * 0x0102040810204080ull) >> 56;
}

GZ_INLINE u64 row_tags(const u8 *t, u32 tag, u32 n)
{
    u64 t8 = tag * 0x0101010101010101ull, m = 0;
    for (u32 i = 0; i < n; i += 8) m |= tag_bits8(rd64(t + i), t8) << i;
    return m;
}
#endif

GZ_INLINE void row_insert(gz_zstd_enc *e, u32 i, u32 shl, u32 shr, u32 rlog)
{
    u32 h = zhash(e->buf + i, shl, shr), row = h >> 8;
    u32 hd = (e->heads[row] - 1u) & ((1u << rlog) - 1);
    size_t at = ((size_t)row << rlog) + hd;
    e->heads[row] = (u8)hd;
    e->tags[at] = (u8)h;
    e->ht[at] = i;
}

static u32 row_search(gz_zstd_enc *e, u32 ip, u32 iend, u32 *off)
{
    const u8 *b = e->buf;
    u32 rlog = e->rlog, n = 1u << rlog, rmask = n - 1;
    u32 shl = 64 - 8 * e->p.m, shr = 64 - (e->p.h - rlog + 8);
    u32 i = e->nupd;
    if (ip - i > 384) {               /* after a long match: its first and last positions only */
        for (u32 k = i + 96; i < k; i++) row_insert(e, i, shl, shr, rlog);
        i = ip - 32;
    }
    for (; i < ip; i++) row_insert(e, i, shl, shr, rlog);
    u32 h = zhash(b + ip, shl, shr), row = h >> 8, tag = h & 0xFF;
    size_t base = (size_t)row << rlog;
    const u32 *rp = e->ht + base;
    u32 head = e->heads[row];
    u64 m = row_tags(e->tags + base, tag, n);
    if (head) m = (m >> head) | (m << (n - head));           /* bit j: slot head + j, newest first */
    if (n < 64) m &= ((u64)1 << n) - 1;
    u32 nb = 1u << (e->p.s < rlog ? e->p.s : rlog), ml = 3, low = e->low;
    const u8 *p = b + ip, *pend = b + iend;
    for (; m && nb; m &= m - 1, nb--) {
        u32 c = rp[(head + (u32)__builtin_ctzll(m)) & rmask];
        if (c < low) break;            /* older slots follow */
        const u8 *q = b + c;
        if (rd32(q + ml - 3) == rd32(p + ml - 3)) {
            u32 len = zcount(p, q, pend);
            if (len > ml) {
                ml = len;
                *off = ip - c;
                if (p + len == pend) break;
            }
        }
    }
    row_insert(e, ip, shl, shr, rlog);
    e->nupd = ip + 1;
    return ml > 3 ? ml : 0;
}

/* ---------------- binary trees ---------------- */

/* insert idx into its tree; returns how many positions may be skipped */
static u32 bt_insert(gz_zstd_enc *e, u32 idx, u32 iend)
{
    const u8 *b = e->buf, *ip = b + idx;
    u32 lim = iend - idx > BT_CAP ? idx + BT_CAP : iend;
    const u8 *ilim = b + lim;
    u32 *bt = e->ct, mask = e->cycle - 1, dummy;
    u32 h = zhash(ip, 64 - 8 * e->p.m, 64 - e->p.h), m = e->ht[h];
    e->ht[h] = idx;
    u32 *smaller = bt + 2 * (idx & mask), *larger = smaller + 1;
    u32 cs = 0, cl = 0, low = e->low, bt_low = mask >= idx ? 0 : idx - mask;
    u32 nb = 1u << e->p.s, best = 8, mend = idx + 9;
    while (nb-- && m >= low) {
        u32 *nx = bt + 2 * (m & mask);
        u32 len = cs < cl ? cs : cl;
        len += zcount(ip + len, b + m + len, ilim);
        if (len > best) {
            best = len;
            if (len > mend - m) mend = m + len;
        }
        if (ip + len == ilim) break;      /* cannot order it: drop the rest of the tree */
        if (b[m + len] < ip[len]) {
            *smaller = m;
            cs = len;
            if (m <= bt_low) { smaller = &dummy; break; }
            smaller = nx + 1;
            m = nx[1];
        } else {
            *larger = m;
            cl = len;
            if (m <= bt_low) { larger = &dummy; break; }
            larger = nx;
            m = nx[0];
        }
    }
    *smaller = *larger = 0;
    u32 skip = best > 384 ? (best - 384 < 192 ? best - 384 : 192) : 0;
    u32 k = mend - (idx + 8);
    return skip > k ? skip : k;
}

/* insert the positions before target (inside long repetitive matches only some) */
static void bt_update(gz_zstd_enc *e, u32 target, u32 iend)
{
    u32 i = e->nupd;
    if (i >= target) return;
    while (i < target) i += bt_insert(e, i, iend);
    e->nupd = target;
}

/* matches at cur with strictly increasing lengths (repeat offsets first when
 * rep != NULL); inserts cur into the tree */
static u32 bt_matches(gz_zstd_enc *e, u32 cur, u32 iend, const u32 *rep, u32 ll0, zmatch *out, u32 suff)
{
    const u8 *b = e->buf, *ip = b + cur;
    u32 low = e->low, n = 0, mml = e->p.m, best = mml - 1, mmask = mml == 3 ? 0xFFFFFF : ~0u;
    if (rep) {
        for (u32 r = ll0; r < 3 + ll0; r++) {
            u32 ro = r == 3 ? rep[0] - 1 : rep[r];
            if (ro - 1 >= cur - low || ((rd32(ip) ^ rd32(ip - ro)) & mmask)) continue;
            u32 k = mml == 3 ? 3 : 4, len = zcount(ip + k, ip + k - ro, b + iend) + k;
            if (len > best) {
                best = len;
                out[n].len = len;
                out[n].ob = r - ll0 + 1;
                n++;
                if (len > suff || cur + len == iend) return n;      /* cur is inserted later */
            }
        }
    }
    u32 lim = iend - cur > BT_CAP ? cur + BT_CAP : iend;
    const u8 *ilim = b + lim;
    u32 *bt = e->ct, mask = e->cycle - 1, dummy;
    u32 h = zhash(ip, 64 - 8 * mml, 64 - e->p.h), m = e->ht[h];
    e->ht[h] = cur;
    u32 *smaller = bt + 2 * (cur & mask), *larger = smaller + 1;
    u32 cs = 0, cl = 0, bt_low = mask >= cur ? 0 : cur - mask;
    u32 nb = 1u << e->p.s, mend = cur + 9;
    while (nb-- && m >= low) {
        u32 *nx = bt + 2 * (m & mask);
        u32 len = cs < cl ? cs : cl;
        len += zcount(ip + len, b + m + len, ilim);
        if (len > best) {
            if (len > mend - m) mend = m + len;
            best = len;
            if (n < MAX_MATCHES) {
                out[n].len = len;
                out[n].ob = cur - m + 3;
                n++;
            }
        }
        if (ip + len == ilim) break;
        if (b[m + len] < ip[len]) {
            *smaller = m;
            cs = len;
            if (m <= bt_low) { smaller = &dummy; break; }
            smaller = nx + 1;
            m = nx[1];
        } else {
            *larger = m;
            cl = len;
            if (m <= bt_low) { larger = &dummy; break; }
            larger = nx;
            m = nx[0];
        }
    }
    *smaller = *larger = 0;
    e->nupd = mend > cur + 8 ? mend - 8 : cur + 1;
    return n;
}

static u32 bt_search(gz_zstd_enc *e, u32 ip, u32 iend, u32 *off)
{
    bt_update(e, ip, iend);
    if (e->nupd > ip) return 0;             /* inside a skipped repetitive run */
    zmatch *mt = e->mt;
    u32 n = bt_matches(e, ip, iend, 0, 0, mt, INF);
    if (!n) return 0;
    u32 len = mt[n - 1].len;
    *off = mt[n - 1].ob - 3;
    if (len >= BT_CAP) len += zcount(e->buf + ip + len, e->buf + ip + len - *off, e->buf + iend);
    return len;
}

/* ---------------- greedy / lazy / lazy2 (hash chains or trees) ---------------- */

GZ_INLINE u32 ob_of(const gz_zstd_enc *e, u32 off) { return off == e->rep[0] ? 1 : off + 3; }

static u32 parse_lazy(gz_zstd_enc *e, u32 ip, u32 iend, int depth, int bt)
{
    const u8 *b = e->buf;
    u32 anchor = ip, ilimit = iend - 8, low = e->low;
#define SEARCH(pos, o) (bt ? bt_search(e, pos, iend, o) : row_search(e, pos, iend, o))
    if (ip == e->fstart) ip++;
    while (ip < ilimit) {
        u32 ml = 0, off = 0, start = ip + 1, r0 = e->rep[0];
        if (r0 <= ip + 1 - low && rd32(b + ip + 1) == rd32(b + ip + 1 - r0)) {
            ml = zcount(b + ip + 5, b + ip + 5 - r0, b + iend) + 4;
            off = r0;
            if (!depth) goto store;
        }
        {
            u32 o2 = 0, m2 = SEARCH(ip, &o2);
            if (m2 > ml) { ml = m2; off = o2; start = ip; }
        }
        if (ml < 4) {
            ip += ((ip - anchor) >> 8) + 1;
            continue;
        }
        while (depth >= 1 && ip < ilimit) {
            ip++;
            r0 = e->rep[0];
            if (r0 <= ip - low && rd32(b + ip) == rd32(b + ip - r0)) {
                u32 mr = zcount(b + ip + 4, b + ip + 4 - r0, b + iend) + 4;
                int g2 = (int)(mr * 3), g1 = (int)(ml * 3 - highbit(ob_of(e, off)) + 1);
                if (g2 > g1) { ml = mr; off = r0; start = ip; }
            }
            {
                u32 o2 = 0, m2 = SEARCH(ip, &o2);
                int g2 = (int)(m2 * 4 - highbit(o2 + 3)), g1 = (int)(ml * 4 - highbit(ob_of(e, off)) + 4);
                if (m2 >= 4 && g2 > g1) { ml = m2; off = o2; start = ip; continue; }
            }
            if (depth == 2 && ip < ilimit) {
                ip++;
                r0 = e->rep[0];
                if (r0 <= ip - low && rd32(b + ip) == rd32(b + ip - r0)) {
                    u32 mr = zcount(b + ip + 4, b + ip + 4 - r0, b + iend) + 4;
                    int g2 = (int)(mr * 4), g1 = (int)(ml * 4 - highbit(ob_of(e, off)) + 1);
                    if (g2 > g1) { ml = mr; off = r0; start = ip; }
                }
                u32 o2 = 0, m2 = SEARCH(ip, &o2);
                int g2 = (int)(m2 * 4 - highbit(o2 + 3)), g1 = (int)(ml * 4 - highbit(ob_of(e, off)) + 7);
                if (m2 >= 4 && g2 > g1) { ml = m2; off = o2; start = ip; continue; }
            }
            break;
        }
        if (off != e->rep[0])
            while (start > anchor && start - off > low && b[start - 1] == b[start - off - 1]) { start--; ml++; }
    store:
        store_seq(e, b + anchor, start - anchor, off, ml);
        ip = anchor = start + ml;
        for (;;) {
            u32 r1 = e->rep[1];
            if (ip > ilimit || r1 > ip - low || rd32(b + ip) != rd32(b + ip - r1)) break;
            ml = zcount(b + ip + 4, b + ip + 4 - r1, b + iend) + 4;
            store_seq(e, b + anchor, 0, r1, ml);
            ip = anchor = ip + ml;
        }
    }
#undef SEARCH
    return anchor;
}

/* ---------------- optimal parser ---------------- */

#define BITCOST 256u
static const u8 base_ll_freq[LL_MAX + 1] = {
    4, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};
static const u8 base_of_freq[OF_MAX + 1] = {
    6, 2, 1, 1, 2, 3, 4, 4, 4, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};

GZ_INLINE u32 wgt(u32 stat, int frac)
{
    u32 s = stat + 1, hb = highbit(s);
    return frac ? hb * BITCOST + ((s << 8) >> hb) : hb * BITCOST;
}

static u32 down(u32 *t, u32 last, u32 shift, int base1)
{
    u32 sum = 0;
    for (u32 s = 0; s <= last; s++) {
        u32 v = (base1 ? 1 : (t[s] > 0)) + (t[s] >> shift);
        t[s] = v;
        sum += v;
    }
    return sum;
}

static u32 scale(u32 *t, u32 last, u32 sum, u32 logt)
{
    u32 f = sum >> logt;
    if (f <= 1) return sum;
    return down(t, last, highbit(f), 1);
}

static void stats_block(gz_zstd_enc *e, const u8 *src, u32 n)
{
    zstats *s = e->st;
    if (!s->sll) {             /* first block of the frame */
        __builtin_memset(s->lit, 0, sizeof s->lit);
        for (u32 i = 0; i < n; i++) s->lit[src[i]]++;
        s->slit = down(s->lit, 255, 8, 0);
        s->sll = 0;
        for (u32 i = 0; i <= LL_MAX; i++) s->sll += s->ll[i] = base_ll_freq[i];
        s->sml = 0;
        for (u32 i = 0; i <= ML_MAX; i++) s->sml += s->ml[i] = 1;
        s->sof = 0;
        for (u32 i = 0; i <= OF_MAX; i++) s->sof += s->of[i] = base_of_freq[i];
    } else {
        s->slit = scale(s->lit, 255, s->slit, 12);
        s->sll = scale(s->ll, LL_MAX, s->sll, 11);
        s->sml = scale(s->ml, ML_MAX, s->sml, 11);
        s->sof = scale(s->of, OF_MAX, s->sof, 11);
    }
}

static void stats_base(gz_zstd_enc *e, int frac)
{
    zstats *s = e->st;
    s->plit = wgt(s->slit, frac);
    s->pll = wgt(s->sll, frac);
    s->pml = wgt(s->sml, frac);
    s->pof = wgt(s->sof, frac);
}

GZ_INLINE u32 lit_price(const zstats *s, u32 c, int frac)
{
    u32 w = wgt(s->lit[c], frac), mx = s->plit - BITCOST;
    return s->plit - (w > mx ? mx : w);
}

GZ_INLINE u32 ll_price(const zstats *s, u32 ll, int frac)
{
    u32 c = ll_code(ll);
    return ll_bits[c] * BITCOST + s->pll - wgt(s->ll[c], frac);
}

GZ_INLINE u32 match_price(const zstats *s, u32 ob, u32 ml, int frac)
{
    u32 oc = highbit(ob), mc = ml_code(ml - 3);
    u32 p = oc * BITCOST + s->pof - wgt(s->of[oc], frac);
    if (!frac && oc >= 20) p += (oc - 19) * 2 * BITCOST;
    return p + ml_bits[mc] * BITCOST + s->pml - wgt(s->ml[mc], frac) + BITCOST / 5;
}

static void stats_add(gz_zstd_enc *e, const u8 *lit, u32 ll, u32 ob, u32 ml)
{
    zstats *s = e->st;
    for (u32 i = 0; i < ll; i++) s->lit[lit[i]] += 2;
    s->slit += 2 * ll;
    s->ll[ll_code(ll)]++;
    s->sll++;
    s->of[highbit(ob)]++;
    s->sof++;
    s->ml[ml_code(ml - 3)]++;
    s->sml++;
}

GZ_INLINE void rep_next(u32 *d, const u32 *r, u32 ob, u32 ll0)
{
    if (ob > 3) {
        d[0] = ob - 3; d[1] = r[0]; d[2] = r[1];
        return;
    }
    u32 i = ob - 1 + ll0;
    if (!i) { d[0] = r[0]; d[1] = r[1]; d[2] = r[2]; return; }
    d[0] = i == 3 ? r[0] - 1 : r[i];
    d[1] = r[0];
    d[2] = i == 1 ? r[2] : r[1];
}

GZ_INLINE u32 rep_off(const u32 *r, u32 ob, u32 ll0)
{
    if (ob > 3) return ob - 3;
    u32 i = ob - 1 + ll0;
    return i == 3 ? r[0] - 1 : r[i];
}

static u32 parse_opt(gz_zstd_enc *e, u32 ip, u32 iend)
{
    const u8 *b = e->buf;
    zstats *st = e->st;
    znode *opt = e->nodes;
    zmatch *mt = e->mt;
    int frac = e->p.st == ST_BTULTRA;
    u32 anchor = ip, ilimit = iend - 8, mml = e->p.m;
    u32 suff = e->p.t < OPT_NUM - 1 ? e->p.t : OPT_NUM - 1;
    stats_block(e, b + ip, iend - ip);
    stats_base(e, frac);
    if (ip == e->fstart) ip++;
    while (ip < ilimit) {
        u32 litlen = ip - anchor, nm, last = 0, fcur = 0, flen = 0, fob = 0, forced = 0;
        bt_update(e, ip, iend);
        if (e->nupd > ip) { ip++; continue; }
        nm = bt_matches(e, ip, iend, e->rep, litlen == 0, mt, suff);
        if (!nm) { ip++; continue; }
        opt[0].price = ll_price(st, litlen, frac);
        opt[0].mlen = 0;
        opt[0].ob = 0;
        opt[0].litlen = litlen;
        opt[0].rep[0] = e->rep[0];
        opt[0].rep[1] = e->rep[1];
        opt[0].rep[2] = e->rep[2];
        if (mt[nm - 1].len > suff) {
            forced = 1;
            flen = mt[nm - 1].len;
            fob = mt[nm - 1].ob;
            goto backtrack;
        }
        {
            u32 base = opt[0].price + ll_price(st, 0, frac), pos = 1;
            for (; pos < mml; pos++) opt[pos].price = INF;
            for (u32 k = 0; k < nm; k++) {
                for (; pos <= mt[k].len; pos++) {
                    opt[pos].price = base + match_price(st, mt[k].ob, pos, frac);
                    opt[pos].mlen = pos;
                    opt[pos].ob = mt[k].ob;
                    opt[pos].litlen = 0;
                }
            }
            last = pos - 1;
        }
        for (u32 cur = 1; cur <= last; cur++) {
            znode *pv = &opt[cur - 1], *nd = &opt[cur];
            u32 L = pv->litlen;
            u32 pr = pv->price + lit_price(st, b[ip + cur - 1], frac) + ll_price(st, L + 1, frac) - ll_price(st, L, frac);
            if (pr <= nd->price) {
                nd->price = pr;
                nd->mlen = 0;
                nd->ob = 0;
                nd->litlen = L + 1;
                nd->rep[0] = pv->rep[0];
                nd->rep[1] = pv->rep[1];
                nd->rep[2] = pv->rep[2];
            } else {
                znode *sn = &opt[cur - nd->mlen];
                rep_next(nd->rep, sn->rep, nd->ob, sn->litlen == 0);
            }
            if (ip + cur >= ilimit) continue;
            if (cur == last) break;
            if (!frac && opt[cur + 1].price <= nd->price + BITCOST / 2) continue;
            bt_update(e, ip + cur, iend);
            if (e->nupd > ip + cur) continue;
            nm = bt_matches(e, ip + cur, iend, nd->rep, nd->litlen == 0, mt, suff);
            if (!nm) continue;
            u32 maxml = mt[nm - 1].len;
            if (maxml > suff || cur + maxml >= OPT_NUM) {
                forced = 1;
                fcur = cur;
                flen = maxml;
                fob = mt[nm - 1].ob;
                goto backtrack;
            }
            u32 base = nd->price + ll_price(st, 0, frac);
            for (u32 k = 0; k < nm; k++) {
                u32 from = k ? mt[k - 1].len + 1 : mml;
                for (u32 len = mt[k].len; len >= from; len--) {
                    u32 pos = cur + len, p2 = base + match_price(st, mt[k].ob, len, frac);
                    if (pos > last || p2 < opt[pos].price) {
                        while (last < pos) opt[++last].price = INF;
                        opt[pos].price = p2;
                        opt[pos].mlen = len;
                        opt[pos].ob = mt[k].ob;
                        opt[pos].litlen = 0;
                    } else if (!frac) {
                        break;
                    }
                }
            }
        }
    backtrack:;
        /* path: (start, len, ob) triples from the end back to node 0 */
        u32 *path = e->path, np = 0, node;
        if (forced) {
            path[np++] = fcur;
            path[np++] = flen;
            path[np++] = fob;
            node = fcur;
        } else {
            node = last;
            while (node > 0 && !opt[node].mlen) node--;
            if (!node) { ip += last; continue; }
        }
        while (node > 0) {
            if (opt[node].mlen) {
                u32 s = node - opt[node].mlen;
                path[np++] = s;
                path[np++] = opt[node].mlen;
                path[np++] = opt[node].ob;
                node = s;
            } else {
                node--;
            }
        }
        while (np) {
            np -= 3;
            u32 s = path[np], len = path[np + 1], ob = path[np + 2];
            const znode *sn = &opt[s];
            u32 off = rep_off(sn->rep, ob, sn->litlen == 0);
            u32 at = ip + s;
            if (len >= BT_CAP) len += zcount(b + at + len, b + at + len - off, b + iend);
            u32 ll = at - anchor;
            store_seq(e, b + anchor, ll, off, len);
            stats_add(e, b + anchor, ll, e->seq[e->nseq - 1].ob, len);
            anchor = at + len;
        }
        ip = anchor;
        stats_base(e, frac);
    }
    return anchor;
}

/* ---------------- entropy stage ---------------- */

static size_t lit_hdr_raw(u8 *o, u32 type, u32 n)
{
    if (n < 32) { o[0] = (u8)(type | (n << 3)); return 1; }
    if (n < 4096) { wr16(o, (u16)(type | 4 | (n << 4))); return 2; }
    u32 v = type | 12 | (n << 4);
    o[0] = (u8)v; o[1] = (u8)(v >> 8); o[2] = (u8)(v >> 16);
    return 3;
}

/* literals section; *new_huf set when a new table was emitted */
static size_t enc_lits(gz_zstd_enc *e, u8 *out, int *new_huf)
{
    const u8 *src = e->lit;
    u32 n = e->nlit, cnt[256], maxsym = 0, maxc = 0;
    *new_huf = 0;
    if (!n) { out[0] = 0; return 1; }
    __builtin_memset(cnt, 0, sizeof cnt);
    {
        u32 c2[256], c3[256], c4[256], i = 0;
        __builtin_memset(c2, 0, sizeof c2);
        __builtin_memset(c3, 0, sizeof c3);
        __builtin_memset(c4, 0, sizeof c4);
        for (; i + 4 <= n; i += 4) { cnt[src[i]]++; c2[src[i + 1]]++; c3[src[i + 2]]++; c4[src[i + 3]]++; }
        for (; i < n; i++) cnt[src[i]]++;
        for (u32 s = 0; s < 256; s++) {
            cnt[s] += c2[s] + c3[s] + c4[s];
            if (cnt[s]) { maxsym = s; if (cnt[s] > maxc) maxc = cnt[s]; }
        }
    }
    if (maxc == n && n > 1) {
        size_t h = lit_hdr_raw(out, 1, n);
        out[h] = src[0];
        return h + 1;
    }
    u32 min_gain = (n >> 6) + 2;
    if (n < (e->hufp_ok ? 8u : 64u) || maxc == n) goto raw;
    {
        /* new table vs the previous block's one */
        u8 tbl[320];
        u32 log = huf_build(&e->huf, cnt, maxsym);
        size_t ts = huf_write_table(tbl, &e->huf, maxsym, log);
        u64 cnew = ts ? (u64)ts * 8 : ~(u64)0, crep = ~(u64)0;
        if (ts) for (u32 s = 0; s <= maxsym; s++) cnew += (u64)cnt[s] * e->huf.bits[s];
        if (e->hufp_ok) {
            crep = 0;
            for (u32 s = 0; s <= maxsym; s++) {
                if (!cnt[s]) continue;
                if (!e->hufp.bits[s]) { crep = ~(u64)0; break; }
                crep += (u64)cnt[s] * e->hufp.bits[s];
            }
        }
        if (cnew == ~(u64)0 && crep == ~(u64)0) goto raw;
        int rep = crep <= cnew;
        const zhuf *h = rep ? &e->hufp : &e->huf;
        u32 single = n < 256, hs = single ? 3 : 3 + (n >= 1024) + (n >= 16384);
        u8 *p = out + hs;
        if (!rep) { __builtin_memcpy(p, tbl, ts); p += ts; }
        if (single) {
            p += huf_stream(p, src, n, h);
        } else {
            u32 seg = (n + 3) / 4;
            u8 *jt = p;
            p += 6;
            for (u32 k = 0; k < 4; k++) {
                u32 a = k * seg, len = k < 3 ? seg : n - 3 * seg;
                size_t z = huf_stream(p, src + a, len, h);
                if (k < 3) {
                    if (z > 0xFFFF) goto raw;
                    wr16(jt + 2 * k, (u16)z);
                }
                p += z;
            }
        }
        u32 cs = (u32)(p - out - hs);
        if (cs + hs >= n - min_gain) goto raw;
        u32 type = rep ? 3 : 2;
        if (single) {
            u32 v = type | (n << 4) | (cs << 14);
            out[0] = (u8)v; out[1] = (u8)(v >> 8); out[2] = (u8)(v >> 16);
        } else if (hs == 3) {
            u32 v = type | 4 | (n << 4) | (cs << 14);
            out[0] = (u8)v; out[1] = (u8)(v >> 8); out[2] = (u8)(v >> 16);
        } else if (hs == 4) {
            wr32(out, type | 8 | (n << 4) | (cs << 18));
        } else {
            u64 v = type | 12 | ((u64)n << 4) | ((u64)cs << 22);
            wr32(out, (u32)v);
            out[4] = (u8)(v >> 32);
        }
        *new_huf = !rep;
        return (size_t)(p - out);
    }
raw:
    {
        size_t h = lit_hdr_raw(out, 0, n);
        __builtin_memcpy(out + h, src, n);
        return h + n;
    }
}

/* choose and describe the table of one sequence stream; returns the mode */
static u32 seq_table(gz_zstd_enc *e, int k, u8 **pp, const u8 *codes, u32 ns, u32 maxlog,
                     const i16 *def, u32 defmax, u32 deflog, zfst **use)
{
    u32 cnt[ML_MAX + 1], maxsym = 0, maxc = 0;
    __builtin_memset(cnt, 0, sizeof cnt);
    for (u32 i = 0; i < ns; i++) cnt[codes[i]]++;
    for (u32 s = 0; s <= ML_MAX; s++) if (cnt[s]) { maxsym = s; if (cnt[s] > maxc) maxc = cnt[s]; }
    zfst *prev = &e->fs[k][e->fcur[k]], *nx = &e->fs[k][e->fcur[k] ^ 1];
    int def_ok = maxsym <= defmax;
    if (maxc == ns && !(def_ok && ns <= 2)) {
        **pp = (u8)maxsym;
        (*pp)++;
        fse_build_rle(&nx->ct, maxsym);
        nx->ok = 0;
        *use = nx;
        return 1;
    }
    u64 c_def = def_ok ? fse_cost(def, defmax, deflog, cnt, maxsym) : INF;
    u64 c_rep = prev->ok ? fse_cost(prev->norm, prev->max, prev->ct.log, cnt, maxsym) : INF;
    u8 hdr[128];
    i16 norm[ML_MAX + 1];
    u32 log = fse_log(maxlog, ns, maxsym);
    u64 c_new = INF;
    size_t hn = 0;
    if (maxc < ns) {
        fse_norm(norm, log, cnt, ns, maxsym);
        hn = fse_write_ncount(hdr, norm, maxsym, log);
        c_new = (u64)hn * 8 * 256 + fse_cost(norm, maxsym, log, cnt, maxsym);
    }
    if (c_def <= c_rep && c_def <= c_new) {
        fse_build(&nx->ct, def, defmax, deflog);
        __builtin_memcpy(nx->norm, def, (defmax + 1) * sizeof(i16));
        nx->max = defmax;
        nx->ok = 1;
        *use = nx;
        return 0;
    }
    if (c_rep <= c_new) {
        *use = prev;
        return 3;
    }
    __builtin_memcpy(*pp, hdr, hn);
    *pp += hn;
    fse_build(&nx->ct, norm, maxsym, log);
    __builtin_memcpy(nx->norm, norm, (maxsym + 1) * sizeof(i16));
    nx->max = maxsym;
    nx->ok = 1;
    *use = nx;
    return 2;
}

static size_t enc_seqs(gz_zstd_enc *e, u8 *out, u32 modes[3])
{
    u32 ns = e->nseq;
    u8 *p = out;
    if (ns < 128) *p++ = (u8)ns;
    else if (ns < 0x7F00) { *p++ = (u8)((ns >> 8) + 128); *p++ = (u8)ns; }
    else { *p++ = 255; wr16(p, (u16)(ns - 0x7F00)); p += 2; }
    if (!ns) return (size_t)(p - out);
    u8 *llc = e->codes, *mlc = llc + NSEQ_MAX, *ofc = mlc + NSEQ_MAX;
    const zseq *sq = e->seq;
    u32 maxof = 0;
    for (u32 i = 0; i < ns; i++) {
        llc[i] = (u8)ll_code(sq[i].ll);
        mlc[i] = (u8)ml_code(sq[i].ml - 3);
        ofc[i] = (u8)highbit(sq[i].ob);
        maxof |= sq[i].ob;
    }
    (void)maxof;
    u8 *mp = p++;
    zfst *tl, *to, *tm;
    modes[0] = seq_table(e, 0, &p, llc, ns, 9, ll_def, LL_MAX, 6, &tl);
    modes[1] = seq_table(e, 1, &p, ofc, ns, 8, of_def, 28, 5, &to);
    modes[2] = seq_table(e, 2, &p, mlc, ns, 9, ml_def, ML_MAX, 6, &tm);
    *mp = (u8)(modes[0] << 6 | modes[1] << 4 | modes[2] << 2);
    const zfse *cl = &tl->ct, *co = &to->ct, *cm = &tm->ct;
    zbw bw;
    zfs sl, so, sm;
    bw_init(&bw, p);
    u32 n = ns - 1;
    fse_init2(&sm, cm, mlc[n]);
    fse_init2(&so, co, ofc[n]);
    fse_init2(&sl, cl, llc[n]);
    bw_add(&bw, sq[n].ll, ll_bits[llc[n]]);
    bw_add(&bw, sq[n].ml - 3, ml_bits[mlc[n]]);
    bw_flush(&bw);
    bw_add(&bw, sq[n].ob, ofc[n]);
    bw_flush(&bw);
    while (n-- > 0) {
        u32 a = llc[n], m = mlc[n], o = ofc[n];
        fse_enc(&bw, &so, co, o);
        fse_enc(&bw, &sm, cm, m);
        fse_enc(&bw, &sl, cl, a);
        bw_flush(&bw);
        bw_add(&bw, sq[n].ll, ll_bits[a]);
        bw_add(&bw, sq[n].ml - 3, ml_bits[m]);
        bw_flush(&bw);
        bw_add(&bw, sq[n].ob, o);
        bw_flush(&bw);
    }
    bw_add(&bw, sm.v, cm->log);
    bw_flush(&bw);
    bw_add(&bw, so.v, co->log);
    bw_flush(&bw);
    bw_add(&bw, sl.v, cl->log);
    bw_flush(&bw);
    p += bw_close(&bw);
    return (size_t)(p - out);
}

/* ---------------- blocks and frames ---------------- */

static int out_put(gz_zstd_enc *e, const void *p, size_t n)
{
    if (e->on + n > e->ocap) {
        int r = e->io->write(e->io->ctx, e->obuf, e->on);
        if (r) return r;
        e->out_total += e->on;
        e->on = 0;
        if (n > e->ocap) {
            r = e->io->write(e->io->ctx, (const u8 *)p, n);
            if (!r) e->out_total += n;
            return r;
        }
    }
    __builtin_memcpy(e->obuf + e->on, p, n);
    e->on += n;
    return GZ_OK;
}

static int out_flush(gz_zstd_enc *e)
{
    if (!e->on) return GZ_OK;
    int r = e->io->write(e->io->ctx, e->obuf, e->on);
    if (!r) e->out_total += e->on;
    e->on = 0;
    return r;
}

static int put_block(gz_zstd_enc *e, u32 type, u32 size, const u8 *data, size_t dn, int last)
{
    u8 h[3];
    u32 v = (u32)last | type << 1 | size << 3;
    h[0] = (u8)v; h[1] = (u8)(v >> 8); h[2] = (u8)(v >> 16);
    int r = out_put(e, h, 3);
    return r ? r : out_put(e, data, dn);
}

static int all_same(const u8 *p, u32 n)
{
    for (u32 i = 1; i < n; i++) if (p[i] != p[0]) return 0;
    return 1;
}

static int block(gz_zstd_enc *e, u32 bs, int last)
{
    const u8 *src = e->buf + e->cur;
    size_t cs = 0;
    if (e->p.st != ST_STORE && bs > 16) {
        u32 iend = e->cur + bs, w = 1u << e->wlog;
        e->low = iend > w + e->fstart ? iend - w : e->fstart;
        e->nseq = 0;
        e->nlit = 0;
        e->rep[0] = e->crep[0];
        e->rep[1] = e->crep[1];
        e->rep[2] = e->crep[2];
        u32 anchor;
        switch (e->p.st) {
        case ST_FAST:    anchor = parse_fast(e, e->cur, iend); break;
        case ST_DFAST:   anchor = parse_dfast(e, e->cur, iend); break;
        case ST_GREEDY:  anchor = parse_lazy(e, e->cur, iend, 0, 0); break;
        case ST_LAZY:    anchor = parse_lazy(e, e->cur, iend, 1, 0); break;
        case ST_LAZY2:   anchor = parse_lazy(e, e->cur, iend, 2, 0); break;
        case ST_BTLAZY2: anchor = parse_lazy(e, e->cur, iend, 2, 1); break;
        default:         anchor = parse_opt(e, e->cur, iend); break;
        }
        u32 tail = iend - anchor;
        __builtin_memcpy(e->lit + e->nlit, e->buf + anchor, tail);
        e->nlit += tail;
        int new_huf;
        u32 modes[3] = { 3, 3, 3 };
        size_t ln = enc_lits(e, e->blk, &new_huf);
        size_t sn = enc_seqs(e, e->blk + ln, modes);
        cs = ln + sn;
        if (cs >= bs - ((bs >> 6) + 2)) cs = 0;
        if (cs <= 24 && bs > 1 && all_same(src, bs)) cs = 0;     /* RLE block below */
        if (cs) {
            /* the decoder now has this block's repeat offsets and tables */
            e->crep[0] = e->rep[0];
            e->crep[1] = e->rep[1];
            e->crep[2] = e->rep[2];
            if (new_huf) { e->hufp = e->huf; e->hufp_ok = 1; }
            if (e->nseq)
                for (int k = 0; k < 3; k++) if (modes[k] != 3) e->fcur[k] ^= 1;
        }
    }
    if (cs) return put_block(e, 2, (u32)cs, e->blk, cs, last);
    if (bs > 1 && all_same(src, bs)) return put_block(e, 1, bs, src, 1, last);
    return put_block(e, 0, bs, src, bs, last);
}

int gz_zstd_encode(gz_zstd_enc *e, const gz_stream_io *io, u64 content_size)
{
    e->io = io;
    e->in_total = e->out_total = 0;
    e->on = 0;
    e->eof = 0;
    e->content = content_size;
    e->cur = e->fstart = e->nupd = e->end;     /* earlier frames are out of reach */
    e->rep[0] = e->crep[0] = 1;
    e->rep[1] = e->crep[1] = 4;
    e->rep[2] = e->crep[2] = 8;
    e->hufp_ok = 0;
    for (int k = 0; k < 3; k++) e->fs[k][0].ok = e->fs[k][1].ok = 0;
    if (e->st) __builtin_memset(e->st, 0, sizeof *e->st);
    if (e->checksum) gz_xxh64_init(&e->xh, 0);

    /* frame header */
    e->wlog = e->wlog_alloc;
    int single = 0;
    if (content_size != GZ_SIZE_UNKNOWN) {
        u32 need = ceil_log2(content_size);
        if (need < GZ_ZSTD_WINDOWLOG_MIN) need = GZ_ZSTD_WINDOWLOG_MIN;
        if (need < e->wlog) e->wlog = need;
        single = content_size <= ((u64)1 << e->wlog);
    }
    u8 h[18];
    u32 hn = 4, fcs = 0, fl = 0;
    wr32(h, 0xFD2FB528u);
    if (content_size != GZ_SIZE_UNKNOWN) {
        if (single && content_size < 256) { fcs = 0; fl = 1; }
        else if (content_size >= 256 && content_size < 65536 + 256) { fcs = 1; fl = 2; }
        else if (content_size <= 0xFFFFFFFFu) { fcs = 2; fl = 4; }
        else { fcs = 3; fl = 8; }
    }
    h[hn++] = (u8)(fcs << 6 | (u32)single << 5 | (u32)e->checksum << 2);
    if (!single) h[hn++] = (u8)((e->wlog - 10) << 3);
    if (fl == 1) h[hn++] = (u8)content_size;
    else if (fl == 2) { wr16(h + hn, (u16)(content_size - 256)); hn += 2; }
    else if (fl == 4) { wr32(h + hn, (u32)content_size); hn += 4; }
    else if (fl == 8) { wr64(h + hn, content_size); hn += 8; }
    int r = out_put(e, h, hn);
    u32 bmax = single || e->wlog >= 17 ? ZB : 1u << e->wlog;

    for (int first = 1; !r; first = 0) {
        r = load(e);
        if (r) break;
        u32 avail = e->end - e->cur, bs = avail < bmax ? avail : bmax;
        int last = e->eof && bs == avail;
        if (!bs && !first) break;               /* cannot happen: the last block ended the loop */
        r = block(e, bs, last);
        e->cur += bs;
        if (last) break;
    }
    if (!r && content_size != GZ_SIZE_UNKNOWN && e->in_total != content_size) r = GZ_E_DATA;
    if (!r && e->checksum) {
        u8 c[4];
        wr32(c, (u32)gz_xxh64_digest(&e->xh));
        r = out_put(e, c, 4);
    }
    if (!r) r = out_flush(e);
    if (r) e->cur = e->end;
    return r;
}
