/*
 * 고깃ZIP - BZip2 decoder (standard streams + the NSIS variant)
 *
 * Block pipeline:
 *   1. header: symbol map, Huffman tables (2..6), selectors
 *   2. symbols -> RLE2 runs + MTF -> L column in ll[], byte counts
 *   3. one pass builds tt[j] = i << 8 | L[j] (T vector) and lf[i] = LF(i) << 8 | L[i]
 *   4. inverse BWT: forward chain from origPtr over tt and backward chain over lf
 *      run interleaved (two independent cache-miss chains), result overwrites ll[]
 *   5. (randomized blocks) un-randomize, then RLE1 into the output buffer + CRC
 */
#include "bzip2.h"

#define BZ_MAXBLOCK    900000u
#define BZ_MAXSEL      18002u          /* 2 + 900000 / 50 */
#define BZ_GROUP       50u
#define BZ_MAXLEN      20u
#define BZ_HB          10u             /* primary Huffman lookup bits */
#define BZ_ICAP        (256u << 10)
#define BZ_IPAD        16u
#define BZ_OCAP        (1u << 20)
#define BZ_OPAD        512u            /* RLE1 runs are written with 256-byte stores */
#define BZ_FAST_MARGIN 256u            /* input bytes that cover any 50-symbol group */
#define BZ_ZERO_LIMIT  64u             /* virtual zero bytes allowed after end of input */

typedef struct {
    u16 fast[1u << BZ_HB];             /* sym | len << 9; len 0 = longer code or invalid */
    u64 lim[BZ_MAXLEN + 1];            /* end of the codes of each length, left-justified to 32 bits */
    i32 off[BZ_MAXLEN + 1];            /* perm index = off[len] + code */
    u16 perm[258];
    u32 maxlen;
} bz_huff;

struct gz_bzip2_dec {
    u32 crctab[8][256];
    bz_huff h[6];
    u8 sel[BZ_MAXSEL];
    u32 cnt[256];
    /* block arrays: tt[cap], lf[cap] (u32) and ll[cap] (bytes) in one mapping */
    u32 *tt, *lf;
    u8 *ll;
    void *blk;
    size_t blk_bytes;
    u32 cap;
    /* buffers */
    u8 *ib, *ob;
    void *buf;
    size_t buf_bytes;
    /* bit reader: bits are left-aligned in bb, bn of them valid */
    const gz_stream_io *io;
    const u8 *ip, *iend;
    u64 bb;
    u32 bn;
    u32 zeros;                         /* virtual zero bytes appended after end of input */
    int eof;
    u64 in_total;
    /* output */
    u8 *op;
    u64 out_left;                      /* bytes still allowed (out_size), ~0 = unlimited */
    int stop;                          /* out_size reached: stop decoding */
};

/* bzip2 0.9.0 "randomized" block masks (BZ2_rNums) */
const u16 gz_bzip2_rnums[512] = {
    619, 720, 127, 481, 931, 816, 813, 233, 566, 247, 985, 724, 205, 454, 863, 491,
    741, 242, 949, 214, 733, 859, 335, 708, 621, 574, 73, 654, 730, 472, 419, 436,
    278, 496, 867, 210, 399, 680, 480, 51, 878, 465, 811, 169, 869, 675, 611, 697,
    867, 561, 862, 687, 507, 283, 482, 129, 807, 591, 733, 623, 150, 238, 59, 379,
    684, 877, 625, 169, 643, 105, 170, 607, 520, 932, 727, 476, 693, 425, 174, 647,
    73, 122, 335, 530, 442, 853, 695, 249, 445, 515, 909, 545, 703, 919, 874, 474,
    882, 500, 594, 612, 641, 801, 220, 162, 819, 984, 589, 513, 495, 799, 161, 604,
    958, 533, 221, 400, 386, 867, 600, 782, 382, 596, 414, 171, 516, 375, 682, 485,
    911, 276, 98, 553, 163, 354, 666, 933, 424, 341, 533, 870, 227, 730, 475, 186,
    263, 647, 537, 686, 600, 224, 469, 68, 770, 919, 190, 373, 294, 822, 808, 206,
    184, 943, 795, 384, 383, 461, 404, 758, 839, 887, 715, 67, 618, 276, 204, 918,
    873, 777, 604, 560, 951, 160, 578, 722, 79, 804, 96, 409, 713, 940, 652, 934,
    970, 447, 318, 353, 859, 672, 112, 785, 645, 863, 803, 350, 139, 93, 354, 99,
    820, 908, 609, 772, 154, 274, 580, 184, 79, 626, 630, 742, 653, 282, 762, 623,
    680, 81, 927, 626, 789, 125, 411, 521, 938, 300, 821, 78, 343, 175, 128, 250,
    170, 774, 972, 275, 999, 639, 495, 78, 352, 126, 857, 956, 358, 619, 580, 124,
    737, 594, 701, 612, 669, 112, 134, 694, 363, 992, 809, 743, 168, 974, 944, 375,
    748, 52, 600, 747, 642, 182, 862, 81, 344, 805, 988, 739, 511, 655, 814, 334,
    249, 515, 897, 955, 664, 981, 649, 113, 974, 459, 893, 228, 433, 837, 553, 268,
    926, 240, 102, 654, 459, 51, 686, 754, 806, 760, 493, 403, 415, 394, 687, 700,
    946, 670, 656, 610, 738, 392, 760, 799, 887, 653, 978, 321, 576, 617, 626, 502,
    894, 679, 243, 440, 680, 879, 194, 572, 640, 724, 926, 56, 204, 700, 707, 151,
    457, 449, 797, 195, 791, 558, 945, 679, 297, 59, 87, 824, 713, 663, 412, 693,
    342, 606, 134, 108, 571, 364, 631, 212, 174, 643, 304, 329, 343, 97, 430, 751,
    497, 314, 983, 374, 822, 928, 140, 206, 73, 263, 980, 736, 876, 478, 430, 305,
    170, 514, 364, 692, 829, 82, 855, 953, 676, 246, 369, 970, 294, 750, 807, 827,
    150, 790, 288, 923, 804, 378, 215, 828, 592, 281, 565, 555, 710, 82, 896, 831,
    547, 261, 524, 462, 293, 465, 502, 56, 661, 821, 976, 991, 658, 869, 905, 758,
    745, 193, 768, 550, 608, 933, 378, 286, 215, 979, 792, 961, 61, 688, 793, 644,
    986, 403, 106, 366, 905, 644, 372, 567, 466, 434, 645, 210, 389, 550, 919, 135,
    780, 773, 635, 389, 707, 100, 626, 958, 165, 504, 920, 176, 193, 713, 857, 265,
    203, 50, 668, 108, 645, 990, 626, 197, 510, 357, 358, 850, 858, 364, 936, 638
};

/* ---------------- CRC (MSB first, slice-by-8) ---------------- */

void gz_bzip2_crc_table(u32 tab[8][256])
{
    for (u32 i = 0; i < 256; i++) {
        u32 c = i << 24;
        for (int k = 0; k < 8; k++) c = (c << 1) ^ ((c & 0x80000000u) ? 0x04c11db7u : 0);
        tab[0][i] = c;
    }
    for (u32 i = 0; i < 256; i++)
        for (int k = 1; k < 8; k++) tab[k][i] = (tab[k - 1][i] << 8) ^ tab[0][tab[k - 1][i] >> 24];
}

u32 gz_bzip2_crc_update(const u32 tab[8][256], u32 crc, const u8 *p, size_t n)
{
    while (n >= 8) {
        u32 a = crc ^ rd32be(p), b = rd32be(p + 4);
        crc = tab[7][a >> 24] ^ tab[6][(a >> 16) & 0xff] ^ tab[5][(a >> 8) & 0xff] ^ tab[4][a & 0xff] ^
              tab[3][b >> 24] ^ tab[2][(b >> 16) & 0xff] ^ tab[1][(b >> 8) & 0xff] ^ tab[0][b & 0xff];
        p += 8;
        n -= 8;
    }
    while (n--) crc = (crc << 8) ^ tab[0][(crc >> 24) ^ *p++];
    return crc;
}

/* ---------------- object ---------------- */

gz_bzip2_dec *gz_bzip2_dec_new(void)
{
    gz_bzip2_dec *d = (gz_bzip2_dec *)gz_alloc(sizeof(gz_bzip2_dec));
    if (!d) return 0;
    d->buf_bytes = BZ_ICAP + BZ_IPAD + BZ_OCAP + BZ_OPAD;
    d->buf = gz_alloc_big(d->buf_bytes);
    if (!d->buf) { gz_free(d); return 0; }
    d->ib = (u8 *)d->buf;
    d->ob = d->ib + BZ_ICAP + BZ_IPAD;
    gz_bzip2_crc_table(d->crctab);
    return d;
}

void gz_bzip2_dec_free(gz_bzip2_dec *d)
{
    if (!d) return;
    if (d->blk) gz_free_big(d->blk, d->blk_bytes);
    gz_free_big(d->buf, d->buf_bytes);
    gz_free(d);
}

static int ensure_block(gz_bzip2_dec *d, u32 maxblock)
{
    if (d->cap >= maxblock) return GZ_OK;
    if (d->blk) gz_free_big(d->blk, d->blk_bytes);
    d->cap = 0;
    d->blk_bytes = (size_t)maxblock * 9 + 64;
    d->blk = gz_alloc_big(d->blk_bytes);
    if (!d->blk) return GZ_E_NOMEM;
    d->tt = (u32 *)d->blk;
    d->lf = d->tt + maxblock;
    d->ll = (u8 *)(d->lf + maxblock);
    d->cap = maxblock;
    return GZ_OK;
}

/* ---------------- input ---------------- */

/* move unread bytes to the buffer start and append fresh input */
static int in_refill(gz_bzip2_dec *d)
{
    size_t keep = (size_t)(d->iend - d->ip);
    if (d->ip != d->ib) {
        if (keep) __builtin_memmove(d->ib, d->ip, keep);
        d->ip = d->ib;
        d->iend = d->ib + keep;
    }
    while (!d->eof && keep < BZ_ICAP) {
        u32 got = 0;
        int r = d->io->read(d->io->ctx, d->ib + keep, (u32)(BZ_ICAP - keep), &got);
        if (r) return r;
        if (!got) { d->eof = 1; break; }
        if (got > BZ_ICAP - keep) return GZ_E_IO;
        keep += got;
        d->in_total += got;
        d->iend = d->ib + keep;
        if (keep >= BZ_FAST_MARGIN) break;
    }
    return GZ_OK;
}

/* load bytes until more than 56 bits are buffered; zeros after end of input */
static GZ_NOINLINE int br_fill(gz_bzip2_dec *d)
{
    while (d->bn <= 56) {
        if (d->ip >= d->iend) {
            if (!d->eof) {
                int r = in_refill(d);
                if (r) return r;
                continue;
            }
            if (++d->zeros > BZ_ZERO_LIMIT) return GZ_E_TRUNC;
            d->bn += 8;
            continue;
        }
        d->bb |= (u64)*d->ip++ << (56 - d->bn);
        d->bn += 8;
    }
    return GZ_OK;
}

static int getbits(gz_bzip2_dec *d, u32 n, u32 *v)     /* 1 <= n <= 32 */
{
    if (d->bn < n) {
        int r = br_fill(d);
        if (r) return r;
    }
    *v = (u32)(d->bb >> (64 - n));
    d->bb <<= n;
    d->bn -= n;
    return GZ_OK;
}

/* some consumed bits were virtual zeros: the input is truncated */
static int overrun(const gz_bzip2_dec *d)
{
    return d->zeros * 8 > d->bn;
}

/* input bytes consumed so far (byte granular) */
static u64 consumed(const gz_bzip2_dec *d)
{
    u64 unread = (u64)(d->iend - d->ip) + d->bn / 8;
    unread = unread > d->zeros ? unread - d->zeros : 0;
    return d->in_total > unread ? d->in_total - unread : 0;
}

/* ---------------- output ---------------- */

static int out_flush(gz_bzip2_dec *d)
{
    size_t n = (size_t)(d->op - d->ob);
    d->op = d->ob;
    if (!n) return GZ_OK;
    if (n >= d->out_left) {
        n = (size_t)d->out_left;
        d->stop = 1;
    }
    d->out_left -= n;
    return n ? d->io->write(d->io->ctx, d->ob, n) : GZ_OK;
}

/* ---------------- Huffman ---------------- */

static int huff_build(bz_huff *h, const u8 *len, u32 n)
{
    u32 cnt[BZ_MAXLEN + 1], pos[BZ_MAXLEN + 1], first[BZ_MAXLEN + 1];
    for (u32 l = 0; l <= BZ_MAXLEN; l++) cnt[l] = 0;
    for (u32 i = 0; i < n; i++) cnt[len[i]]++;
    u32 code = 0, idx = 0;
    h->maxlen = 0;
    for (u32 l = 1; l <= BZ_MAXLEN; l++) {
        first[l] = code;
        pos[l] = idx;
        h->off[l] = (i32)idx - (i32)code;
        code += cnt[l];
        if (code > (1u << l)) return GZ_E_DATA;          /* over-subscribed */
        h->lim[l] = (u64)code << (32 - l);
        idx += cnt[l];
        if (cnt[l]) h->maxlen = l;
        code <<= 1;
    }
    for (u32 i = 0; i < n; i++) h->perm[pos[len[i]]++] = (u16)i;
    /* primary table; unfilled entries (long or unused codes) stay 0 */
    __builtin_memset(h->fast, 0, sizeof h->fast);
    idx = 0;
    for (u32 l = 1; l <= BZ_HB; l++) {
        u32 c = first[l];
        for (u32 k = 0; k < cnt[l]; k++, c++) {
            u16 e = (u16)(h->perm[idx++] | (l << 9));
            u32 a = c << (BZ_HB - l), b = (c + 1) << (BZ_HB - l);
            for (; a < b; a++) h->fast[a] = e;
        }
    }
    return GZ_OK;
}

/* codes longer than BZ_HB bits (or an invalid prefix); v = next 32 bits */
static GZ_NOINLINE int huff_long(const bz_huff *h, u32 v, u32 *sym, u32 *len)
{
    for (u32 l = BZ_HB + 1; l <= h->maxlen; l++) {
        if ((u64)v < h->lim[l]) {
            *sym = h->perm[h->off[l] + (i32)(v >> (32 - l))];
            *len = l;
            return GZ_OK;
        }
    }
    return GZ_E_DATA;
}

/* ---------------- MTF ---------------- */

/* move entry v (>= 1) of the 256-byte MTF list (8 bytes per word, entry 0 in the
 * low byte of W[0]) to the front, return it */
GZ_INLINE u32 mtf_move(u64 *W, u32 v)
{
    u32 w = v >> 3, sh = (v & 7) * 8;
    u64 x = W[w];
    u32 b = (u32)(x >> sh) & 0xff;
    u64 lo = x & (((u64)1 << sh) - 1);
    u64 hi = x & ((~(u64)0 << sh) << 8);
    x = (lo << 8) | hi;
    while (w) {
        u64 y = W[w - 1];
        W[w] = x | (y >> 56);
        x = y << 8;
        w--;
    }
    W[0] = x | b;
    return b;
}

/* ---------------- block ---------------- */

/* Huffman + RLE2 + MTF: fills ll[0..n) and cnt[] */
static int decode_syms(gz_bzip2_dec *d, const u8 *seq, u32 ninuse, u32 nsel, u32 maxblock, u32 *pn)
{
    u64 W[32];
    __builtin_memset(W, 0, sizeof W);
    for (u32 i = 0; i < ninuse; i++) W[i >> 3] |= (u64)seq[i] << ((i & 7) * 8);
    u32 *cnt = d->cnt;
    __builtin_memset(cnt, 0, sizeof d->cnt);
    u8 *ll = d->ll;
    const u32 eob = ninuse + 1;
    u32 nb = 0, run = 0, rsh = 0;
    u64 bb = d->bb;
    u32 bn = d->bn;
    const u8 *ip = d->ip;
    int r = GZ_E_DATA;

    /* one symbol: table lookup, then RUNA/RUNB (bijective base 2) or an MTF index */
#define BZ_SYMBOL() do {                                                              \
        u32 e_ = h->fast[bb >> (64 - BZ_HB)], sym_ = e_ & 511, len_ = e_ >> 9;        \
        if (GZ_UNLIKELY(!len_) && huff_long(h, (u32)(bb >> 32), &sym_, &len_)) {      \
            r = GZ_E_DATA; goto out;                                                   \
        }                                                                              \
        bb <<= len_;                                                                   \
        bn -= len_;                                                                    \
        if (sym_ <= 1) {                                                               \
            run += (sym_ + 1) << rsh;                                                  \
            rsh++;                                                                     \
            if (run > maxblock - nb) { r = GZ_E_DATA; goto out; }                      \
        } else {                                                                       \
            if (run) {                                                                 \
                u32 b_ = (u32)W[0] & 0xff;                                             \
                __builtin_memset(ll + nb, (int)b_, run);                               \
                cnt[b_] += run;                                                        \
                nb += run;                                                             \
                run = 0;                                                               \
                rsh = 0;                                                               \
            }                                                                          \
            if (sym_ == eob) { r = GZ_OK; goto out; }                                  \
            if (nb >= maxblock) { r = GZ_E_DATA; goto out; }                           \
            u32 b_ = mtf_move(W, sym_ - 1);                                            \
            ll[nb++] = (u8)b_;                                                         \
            cnt[b_]++;                                                                 \
        }                                                                              \
    } while (0)

    for (u32 g = 0;; g++) {
        if (g >= nsel) goto out;
        const bz_huff *h = &d->h[d->sel[g]];
        if ((size_t)(d->iend - ip) < BZ_FAST_MARGIN && !d->eof) {
            d->ip = ip;
            if ((r = in_refill(d))) goto out;
            ip = d->ip;
        }
        if (GZ_LIKELY((size_t)(d->iend - ip) >= BZ_FAST_MARGIN)) {
            /* the whole group is in the buffer: branchless refill (>= 56 bits) per two symbols */
            for (u32 k = 0; k < BZ_GROUP; k += 2) {
                bb |= rd64be(ip) >> bn;
                ip += (63 - bn) >> 3;
                bn |= 56;
                BZ_SYMBOL();
                BZ_SYMBOL();
            }
        } else {
            for (u32 k = 0; k < BZ_GROUP; k++) {
                if (bn < BZ_MAXLEN) {
                    d->bb = bb; d->bn = bn; d->ip = ip;
                    if ((r = br_fill(d))) return r;
                    bb = d->bb; bn = d->bn; ip = d->ip;
                }
                BZ_SYMBOL();
            }
        }
    }
#undef BZ_SYMBOL
out:
    d->bb = bb; d->bn = bn; d->ip = ip;
    *pn = nb;
    return r;
}

/* block body after the signature: returns the block length, origPtr and the randomized flag */
static int read_block(gz_bzip2_dec *d, u32 maxblock, int has_rand, u32 *pn, u32 *porig, u32 *prand)
{
    u32 v, rnd = 0, orig, used, ngroups, nsel;
    int r;
    if (has_rand && (r = getbits(d, 1, &rnd))) return r;
    if ((r = getbits(d, 24, &orig))) return r;
    if ((r = getbits(d, 16, &used))) return r;
    u8 seq[256];
    u32 ninuse = 0;
    for (u32 i = 0; i < 16; i++) {
        if (!(used & (0x8000u >> i))) continue;
        if ((r = getbits(d, 16, &v))) return r;
        for (u32 j = 0; j < 16; j++)
            if (v & (0x8000u >> j)) seq[ninuse++] = (u8)(i * 16 + j);
    }
    if (!ninuse) return GZ_E_DATA;
    const u32 alpha = ninuse + 2;
    if ((r = getbits(d, 3, &ngroups))) return r;
    if (ngroups < 2 || ngroups > 6) return GZ_E_DATA;
    if ((r = getbits(d, 15, &nsel))) return r;
    if (!nsel) return GZ_E_DATA;
    /* selectors: unary MTF indices; like bzip2 1.0.8, extra ones are read and dropped */
    u8 smtf[6] = { 0, 1, 2, 3, 4, 5 };
    for (u32 i = 0; i < nsel; i++) {
        u32 j = 0;
        for (;;) {
            if ((r = getbits(d, 1, &v))) return r;
            if (!v) break;
            if (++j >= ngroups) return GZ_E_DATA;
        }
        u8 t = smtf[j];
        for (; j; j--) smtf[j] = smtf[j - 1];
        smtf[0] = t;
        if (i < BZ_MAXSEL) d->sel[i] = t;
    }
    if (nsel > BZ_MAXSEL) nsel = BZ_MAXSEL;
    /* code lengths: 5-bit start, then delta coded, each within 1..20 */
    u8 len[258];
    for (u32 t = 0; t < ngroups; t++) {
        u32 cur;
        if ((r = getbits(d, 5, &cur))) return r;
        for (u32 s = 0; s < alpha; s++) {
            for (;;) {
                if (cur < 1 || cur > BZ_MAXLEN) return GZ_E_DATA;
                if ((r = getbits(d, 1, &v))) return r;
                if (!v) break;
                if ((r = getbits(d, 1, &v))) return r;
                cur = v ? cur - 1 : cur + 1;
            }
            len[s] = (u8)cur;
        }
        if ((r = huff_build(&d->h[t], len, alpha))) return r;
    }
    u32 n;
    if ((r = decode_syms(d, seq, ninuse, nsel, maxblock, &n))) return r;
    if (overrun(d)) return GZ_E_TRUNC;
    if (orig >= n) return GZ_E_DATA;
    *pn = n;
    *porig = orig;
    *prand = rnd;
    return GZ_OK;
}

/* steps 3 + 4: T / LF vectors, then both chains; the block text replaces ll[] */
static void inverse_bwt(gz_bzip2_dec *d, u32 n, u32 orig)
{
    u32 C[256], sum = 0;
    for (u32 i = 0; i < 256; i++) { C[i] = sum; sum += d->cnt[i]; }
    u32 *tt = d->tt, *lf = d->lf;
    u8 *ll = d->ll;
    for (u32 i = 0; i < n; i++) {
        u32 b = ll[i];
        u32 j = C[b]++;
        tt[j] = (i << 8) | ll[j];
        lf[i] = (j << 8) | b;
    }
    /* forward: text[0..), backward: text[n-1] down; meet in the middle */
    u32 p = tt[orig] >> 8, q = orig;
    u8 *f = ll, *bk = ll + n;
    for (u32 k = n >> 1; k; k--) {
        u32 x = tt[p], y = lf[q];
        *f++ = (u8)x;
        *--bk = (u8)y;
        p = x >> 8;
        q = y >> 8;
    }
    if (n & 1) *f = (u8)tt[p];
}

static void derandomize(u8 *s, u32 n)
{
    u32 base = 0, ri = 0;
    for (;;) {
        u32 m = base + gz_bzip2_rnums[ri] - 2;   /* the byte where the countdown hits 1 */
        if (m >= n) break;
        s[m] ^= 1;
        base += gz_bzip2_rnums[ri];
        ri = (ri + 1) & 511;
    }
}

/* step 5: RLE1 decode s[0..n) into the output buffer; block CRC into *pcrc.
 * Returns early (GZ_OK, d->stop set) when out_size is reached. */
static int emit_block(gz_bzip2_dec *d, const u8 *s, u32 n, u32 *pcrc)
{
    u32 crc = 0xffffffffu;
    u8 *o = d->op, *mark = o;
    u8 *const olim = d->ob + BZ_OCAP;
    const u8 *const se = s + n;
    const u8 *const sfast = n > 24 ? se - 24 : s;   /* fast scan reads up to s + 16 */
    const u8 *base = s;                  /* RLE state starts here (block start, after a count) */
    u32 prev = 256, run = 0;
    int tail = 0;
    for (;;) {
        if (!tail) {
            /* 8 bytes at a time: find the first i <= 5 with s[i] == s[i+1] == s[i+2] == s[i+3];
             * every run start before s was checked already, so the state is always "fresh" */
            while (s < sfast && o < olim) {
                u64 x = rd64(s), z = x ^ rd64(s + 1);
                u64 zb = ~(((z & 0x7f7f7f7f7f7f7f7full) + 0x7f7f7f7f7f7f7f7full) | z | 0x7f7f7f7f7f7f7f7full);
                u64 m = zb & (zb >> 8) & (zb >> 16);
                wr64(o, x);
                if (GZ_LIKELY(!m)) { o += 6; s += 6; continue; }
                u32 i = (u32)__builtin_ctzll(m) >> 3;
                wr64(o + 8, rd64(s + 8));
                o += i + 4;                  /* literals + the four run bytes */
                __builtin_memset(o, s[i], 256);
                o += s[i + 4];               /* count byte */
                s += i + 5;
                base = s;
            }
            if (s >= sfast) {
                /* byte loop for the tail: rebuild the run length before s (at most 3) */
                tail = 1;
                if (s > base) {
                    prev = s[-1];
                    run = 1;
                    while (run < 3 && s - run > base && s[-1 - (i32)run] == prev) run++;
                }
            }
        }
        if (tail) {
            while (s < se && o < olim) {
                u32 b = *s++;
                if (run == 4) {             /* count byte after four equal bytes */
                    __builtin_memset(o, (int)prev, 256);
                    o += b;
                    run = 0;
                    continue;
                }
                *o++ = (u8)b;
                run = b == prev ? run + 1 : 1;
                prev = b;
            }
        }
        crc = gz_bzip2_crc_update(d->crctab, crc, mark, (size_t)(o - mark));
        d->op = o;
        if (s >= se) break;
        int r = out_flush(d);
        if (r) return r;
        if (d->stop) return GZ_OK;
        o = mark = d->op;
    }
    *pcrc = ~crc;
    return GZ_OK;
}

/* ---------------- streams ---------------- */

static int dec_run(gz_bzip2_dec *d, const gz_stream_io *io, u64 out_size, int multi, int nsis, u64 *in_used)
{
    d->io = io;
    d->ip = d->iend = d->ib;
    d->bb = 0;
    d->bn = 0;
    d->zeros = 0;
    d->eof = 0;
    d->in_total = 0;
    d->op = d->ob;
    d->out_left = out_size;
    d->stop = 0;
    int at_limit = out_size == 0;      /* output reached out_size exactly at a block end */
    u64 used = 0;
    u32 v, w;
    int r;

    for (u32 nstreams = 0;; nstreams++) {
        u32 level = 9;
        if (!nsis) {
            if (nstreams) {
                /* another stream? anything else after a complete stream is ignored */
                if (at_limit || d->stop) break;
                if (d->bn < 32 && (r = br_fill(d)) && r != GZ_E_TRUNC) return r;
                v = (u32)(d->bb >> 32);
                if ((v >> 8) != 0x425a68u || (v & 0xff) < '1' || (v & 0xff) > '9' || d->bn < 32 + d->zeros * 8)
                    break;
                d->bb <<= 32;
                d->bn -= 32;
            } else {
                if ((r = getbits(d, 32, &v))) return r == GZ_E_TRUNC ? GZ_E_FORMAT : r;
                if ((v >> 8) != 0x425a68u || (v & 0xff) < '1' || (v & 0xff) > '9') return GZ_E_FORMAT;
                if (overrun(d)) return GZ_E_FORMAT;
            }
            level = (v & 0xff) - '0';
        }
        u32 maxblock = nsis ? BZ_MAXBLOCK : level * 100000u;
        if ((r = ensure_block(d, maxblock))) return r;
        u32 combined = 0;
        for (;;) {
            int is_end;
            u32 crc = 0;
            if (nsis) {
                if ((r = getbits(d, 8, &v))) return r;
                if (overrun(d)) return GZ_E_TRUNC;
                if (v != 0x31 && v != 0x17) return GZ_E_DATA;
                is_end = v == 0x17;
            } else {
                if ((r = getbits(d, 24, &v)) || (r = getbits(d, 24, &w))) return r;
                if (overrun(d)) return GZ_E_TRUNC;
                if (v == 0x314159u && w == 0x265359u) is_end = 0;
                else if (v == 0x177245u && w == 0x385090u) is_end = 1;
                else return GZ_E_DATA;
                if ((r = getbits(d, 32, &crc))) return r;
                if (overrun(d)) return GZ_E_TRUNC;
            }
            if (is_end) {
                if (!nsis && crc != combined) return GZ_E_CRC;
                break;
            }
            if (at_limit) goto finish;     /* more data than out_size: stop here */
            u32 n, orig, rnd;
            if ((r = read_block(d, maxblock, !nsis, &n, &orig, &rnd)))
                return r == GZ_E_DATA && overrun(d) ? GZ_E_TRUNC : r;   /* garbage came from past the end */
            inverse_bwt(d, n, orig);
            if (rnd) derandomize(d->ll, n);
            u32 bcrc;
            if ((r = emit_block(d, d->ll, n, &bcrc))) return r;
            if (d->stop) goto finish;
            if (!nsis) {
                if (bcrc != crc) return GZ_E_CRC;
                combined = ((combined << 1) | (combined >> 31)) ^ crc;
            }
            u64 have = (u64)(d->op - d->ob);
            if (have > d->out_left) goto finish;
            if (have == d->out_left) at_limit = 1;
        }
        d->bb <<= d->bn & 7;               /* streams end on a byte boundary */
        d->bn &= ~7u;
        if (overrun(d)) return GZ_E_TRUNC;
        used = consumed(d);
        if (!multi || nsis) break;
    }
    if ((r = out_flush(d))) return r;
    if (out_size != GZ_SIZE_UNKNOWN && d->out_left && !d->stop) return GZ_E_DATA;
    if (in_used) *in_used = used;
    return GZ_OK;
finish:
    used = consumed(d);
    if ((r = out_flush(d))) return r;
    if (in_used) *in_used = used;
    return GZ_OK;
}

int gz_bzip2_decode(gz_bzip2_dec *d, const gz_stream_io *io, u64 out_size, int multi_stream, u64 *in_used)
{
    return dec_run(d, io, out_size, multi_stream, 0, in_used);
}

int gz_bzip2_decode_nsis(gz_bzip2_dec *d, const gz_stream_io *io, u64 out_size, u64 *in_used)
{
    return dec_run(d, io, out_size, 0, 1, in_used);
}
