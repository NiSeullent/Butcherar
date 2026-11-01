/*
 * 고깃ZIP - LZMA / LZMA2 decoder
 *
 * Design (after 7-Zip's LzmaDec.c, public domain):
 *  - u16 probabilities in one array (base models + literal coders);
 *  - normalize-before-bit range decoder; the state between symbols is always
 *    normalized, so the number of input bytes consumed at a symbol boundary is
 *    exact (needed for *in_used);
 *  - the hot loop decodes whole symbols without input bound checks while at
 *    least LZ_REQ bytes are buffered. Near the real end of the input (end of
 *    file, or end of an LZMA2 chunk) it decodes one symbol at a time against
 *    LZ_IPAD zero bytes of padding and rejects any symbol that reads past the end;
 *  - the dictionary is a circular buffer of B = W + 16 bytes, W being the window
 *    (dictionary size, or the output size when smaller). Distances are checked
 *    against W, which lets match copies write up to 15 bytes past their end: a
 *    byte there is B - 15 > W positions behind any later write position until it
 *    is overwritten, so it is never referenced. B is a multiple of 16, so the
 *    buffer position also serves as the stream position for pos_state;
 *  - literal bits are decoded branch-free (cmov/csel), as they are unpredictable.
 */
#include "lzma.h"

#define LZ_ICAP      (64u << 10)      /* input buffer                              */
#define LZ_IPAD      64u              /* zero padding after the buffered input     */
#define LZ_REQ       32u              /* > max input bytes of one symbol (20)      */
#define LZ_OCHUNK    (1u << 20)       /* output flush granularity                  */
#define LZ_SLACK     16u              /* circular buffer bytes beyond the window   */
#define LZ_DIC_TAIL  32u              /* allocated beyond the circular buffer      */
#define LZ_DIC_MIN   (1u << 20)       /* smallest window when the output is larger */
#define LZ_BIG_ALLOC (1u << 20)       /* use gz_alloc_big above this               */

#define LZ_TOP       (1u << 24)
#define LZ_NBITS     11
#define LZ_PROB_INIT 1024u
#define LZ_MOVE      5

#define LZ_END       0x200u           /* remain value: end marker seen             */
#define LZ_ERR       0x400u           /* run result flag: bad distance             */

/* probability layout (u16 indices); the length coders pack choice/choice2 into
 * unused slots of the low trees, as in LzmaDec.c */
enum {
    P_ISMATCH    = 0,                 /* [pos_state << 4 | state]                  */
    P_ISREP0LONG = 256,
    P_ISREP      = 512,
    P_ISREPG0    = 524,
    P_ISREPG1    = 536,
    P_ISREPG2    = 548,
    P_POSSLOT    = 560,               /* 4 x 64                                    */
    P_SPECPOS    = 816,               /* 128, indexed by distance base + bits      */
    P_ALIGN      = 944,               /* 16                                        */
    P_LEN        = 960,               /* 512                                       */
    P_REPLEN     = 1472,              /* 512                                       */
    P_LIT        = 1984,              /* 0x300 << (lc + lp)                        */
    LEN_CHOICE   = 0,
    LEN_CHOICE2  = 8,
    LEN_LOW      = 0,                 /* + (pos_state << 4) (+ 8 for mid)          */
    LEN_HIGH     = 256
};

#define NUM_STATES   12
#define LIT_STATES   7

/* decoder state (reused across calls) */
struct gz_lzma_dec {
    /* model */
    u16 *probs;
    size_t probs_n;          /* allocated entries */
    u32 lc, lp, pb;
    u32 state, rep0, rep1, rep2, rep3;
    u32 remain;              /* bytes of the current match still to copy, or LZ_END */
    u32 range, code;

    /* dictionary: dic[0 .. B) circular, window W = B - LZ_SLACK */
    u8 *dic;
    size_t dic_alloc;        /* bytes allocated (B + LZ_DIC_TAIL)          */
    size_t B, W;
    size_t pos, flushed;
    size_t check;            /* 0 until the buffer wrapped once, then W    */

    /* input */
    u8 *ibuf;                /* LZ_ICAP + LZ_IPAD                          */
    const u8 *in_pos, *in_end;
    int in_eof;
    u64 in_total;            /* bytes read from io                         */
    const gz_stream_io *io;

    u64 limit;               /* largest window, 0 = default                */
    u32 flags;               /* GZ_LZMA_*                                  */
};

#define kBadRepCode (0xC0000000u - 0x400u)

/* ------------------------------------------------------------------ */
/* allocation                                                          */

static void *lz_alloc(size_t n) { return n > LZ_BIG_ALLOC ? gz_alloc_big(n) : gz_alloc(n); }
static void lz_free(void *p, size_t n)
{
    if (!p) return;
    if (n > LZ_BIG_ALLOC) gz_free_big(p, n); else gz_free(p);
}

gz_lzma_dec *gz_lzma_dec_new(void)
{
    gz_lzma_dec *d = (gz_lzma_dec *)gz_alloc(sizeof(gz_lzma_dec));
    if (!d) return 0;
    d->ibuf = (u8 *)gz_alloc(LZ_ICAP + LZ_IPAD);
    if (!d->ibuf) { gz_free(d); return 0; }
    return d;
}

void gz_lzma_dec_free(gz_lzma_dec *d)
{
    if (!d) return;
    lz_free(d->probs, d->probs_n * sizeof(u16));
    lz_free(d->dic, d->dic_alloc);
    gz_free(d->ibuf);
    gz_free(d);
}

void gz_lzma_dec_set_limit(gz_lzma_dec *d, u64 max_dict) { d->limit = max_dict; }
void gz_lzma_dec_set_flags(gz_lzma_dec *d, u32 flags) { d->flags = flags; }

static u64 lz_default_limit(void)
{
    return sizeof(size_t) < 8 ? (u64)3 << 29 /* 1.5 GiB */ : (u64)1 << 32;
}

/* Window and buffer for a dictionary of dict bytes producing out_size bytes. */
static int lz_alloc_dic(gz_lzma_dec *d, u64 dict, u64 out_size)
{
    u64 w = dict;
    if (w < LZ_DIC_MIN) w = LZ_DIC_MIN;          /* fewer, larger sink writes */
    if (out_size != GZ_SIZE_UNKNOWN && out_size < w) w = out_size;
    w = (w + 15) & ~(u64)15;
    if (w < 16) w = 16;
    u64 lim = d->limit ? d->limit : lz_default_limit();
    if (w > lim) return GZ_E_LIMIT;
    u64 need64 = w + LZ_SLACK + LZ_DIC_TAIL;
    if (need64 != (size_t)need64) return GZ_E_LIMIT;
    size_t need = (size_t)need64;
    if (d->dic && (d->dic_alloc < need || d->dic_alloc / 2 > need + ((size_t)4 << 20))) {
        lz_free(d->dic, d->dic_alloc);
        d->dic = 0;
        d->dic_alloc = 0;
    }
    if (!d->dic) {
        d->dic = (u8 *)lz_alloc(need);
        if (!d->dic) return GZ_E_NOMEM;
        d->dic_alloc = need;
    }
    d->W = (size_t)w;
    d->B = (size_t)w + LZ_SLACK;
    return GZ_OK;
}

static int lz_alloc_probs(gz_lzma_dec *d, u32 lclp)
{
    size_t n = P_LIT + ((size_t)0x300 << lclp);
    if (d->probs && d->probs_n >= n) return GZ_OK;
    lz_free(d->probs, d->probs_n * sizeof(u16));
    d->probs = (u16 *)lz_alloc(n * sizeof(u16));
    d->probs_n = d->probs ? n : 0;
    return d->probs ? GZ_OK : GZ_E_NOMEM;
}

/* ------------------------------------------------------------------ */
/* state                                                               */

static void lz_reset_state(gz_lzma_dec *d)
{
    size_t n = P_LIT + ((size_t)0x300 << (d->lc + d->lp));
    u16 *p = d->probs;
    for (size_t i = 0; i < n; i++) p[i] = LZ_PROB_INIT;
    d->state = 0;
    d->rep0 = d->rep1 = d->rep2 = d->rep3 = 1;
    d->remain = 0;
}

static void lz_reset_dic(gz_lzma_dec *d)
{
    d->pos = d->flushed = 0;
    d->check = 0;
    d->dic[d->B - 1] = 0;          /* "previous byte" of the first literal */
}

static int lz_parse_props(gz_lzma_dec *d, u32 b, u32 lclp_max)
{
    if (b >= 9 * 5 * 5) return GZ_E_DATA;
    d->lc = b % 9;
    b /= 9;
    d->lp = b % 5;
    d->pb = b / 5;
    if (d->lc + d->lp > lclp_max) return GZ_E_DATA;
    return GZ_OK;
}

/* ------------------------------------------------------------------ */
/* input                                                               */

static void lz_in_reset(gz_lzma_dec *d, const gz_stream_io *io)
{
    d->io = io;
    d->in_pos = d->in_end = d->ibuf;
    d->in_eof = 0;
    d->in_total = 0;
    __builtin_memset(d->ibuf, 0, LZ_IPAD);
}

/* Make at least need (<= LZ_ICAP) bytes available unless the input ends. */
static int lz_fill(gz_lzma_dec *d, size_t need)
{
    size_t have = (size_t)(d->in_end - d->in_pos);
    if (have >= need || d->in_eof) return GZ_OK;
    if (d->in_pos != d->ibuf) {
        __builtin_memmove(d->ibuf, d->in_pos, have);
        d->in_pos = d->ibuf;
        d->in_end = d->ibuf + have;
    }
    while (have < need) {
        u32 got = 0;
        u32 cap = (u32)(LZ_ICAP - have);
        int r = d->io->read(d->io->ctx, d->ibuf + have, cap, &got);
        if (r) return r;
        if (got > cap) return GZ_E_IO;
        if (!got) { d->in_eof = 1; break; }
        have += got;
        d->in_total += got;
    }
    d->in_end = d->ibuf + have;
    __builtin_memset(d->ibuf + have, 0, LZ_IPAD);
    return GZ_OK;
}

static u64 lz_in_used(const gz_lzma_dec *d)
{
    return d->in_total - (u64)(d->in_end - d->in_pos);
}

/* Range coder init: 5 bytes, the first one must be 0. *in_n: bytes left in the
 * chunk (LZMA2) or ~0. */
static int lz_rc_init(gz_lzma_dec *d, u64 *in_n)
{
    if (*in_n < 5) return GZ_E_DATA;
    int r = lz_fill(d, 5);
    if (r) return r;
    if (d->in_end - d->in_pos < 5) return GZ_E_TRUNC;
    const u8 *p = d->in_pos;
    if (p[0]) return GZ_E_DATA;
    d->code = rd32be(p + 1);
    d->range = 0xFFFFFFFFu;
    d->in_pos += 5;
    *in_n -= 5;
    return GZ_OK;
}

/* ------------------------------------------------------------------ */
/* output                                                              */

static int lz_flush(gz_lzma_dec *d)
{
    if (d->pos > d->flushed) {
        int r = d->io->write(d->io->ctx, d->dic + d->flushed, d->pos - d->flushed);
        d->flushed = d->pos;
        if (r) return r;
    }
    if (d->pos == d->B) {          /* wrap: from now on the whole window is valid */
        d->pos = d->flushed = 0;
        d->check = d->W;
    }
    return GZ_OK;
}

/* Copy up to limit - pos bytes of a pending match. */
static void lz_write_rem(gz_lzma_dec *d, size_t limit)
{
    size_t len = d->remain;
    if (len > limit - d->pos) len = limit - d->pos;
    if (!len) return;
    d->remain -= (u32)len;
    u8 *dic = d->dic;
    size_t pos = d->pos, B = d->B;
    size_t src = pos - d->rep0 + (pos < d->rep0 ? B : 0);
    do {
        dic[pos++] = dic[src];
        if (++src == B) src = 0;
    } while (--len);
    d->pos = pos;
}

/* ------------------------------------------------------------------ */
/* hot loop                                                            */

#define NORM if (range < LZ_TOP) { range <<= 8; code = (code << 8) | *buf++; }
#define IF_BIT_0(p) ttt = *(p); NORM; bound = (range >> LZ_NBITS) * ttt; if (code < bound)
#define UPDATE_0(p) range = bound; *(p) = (u16)(ttt + ((2048u - ttt) >> LZ_MOVE));
#define UPDATE_1(p) range -= bound; code -= bound; *(p) = (u16)(ttt - (ttt >> LZ_MOVE));
#define GET_BIT2(p, i, A0, A1) IF_BIT_0(p) { UPDATE_0(p) i = (i + i); A0; } \
                               else { UPDATE_1(p) i = (i + i) + 1; A1; }
#define TREE_BIT(pr, i) { GET_BIT2((pr) + (i), i, ;, ;) }
/* Branch-free bit for literals (their bits are unpredictable): select with masks
 * so compilers emit cmov / csel. m = all ones when the bit is 1. The update
 * p - ((p - T) >> 5) with T = 2017 (bit 0) or 0 (bit 1) equals the usual
 * p + ((2048 - p) >> 5) / p - (p >> 5) (arithmetic shift). */
#define LIT_BIT_M(pl, m) { \
    ttt = *(pl); NORM; bound = (range >> LZ_NBITS) * ttt; \
    m = 0u - (u32)(code >= bound); \
    range = (m & (range - bound)) | (~m & bound); \
    code -= bound & m; \
    *(pl) = (u16)(ttt - (u32)((int32_t)(ttt - (2017u & ~m)) >> LZ_MOVE)); }
#define LIT_BIT(pr, i) { u32 m_; LIT_BIT_M((pr) + (i), m_) i = (i << 1) - m_; }

#define REV_BIT(p, i, A0, A1) IF_BIT_0((p) + (i)) { UPDATE_0((p) + (i)) A0; } \
                              else { UPDATE_1((p) + (i)) A1; }
#define REV_BIT_VAR(p, i, m)   REV_BIT(p, i, i += m; m += m, m += m; i += m;)
#define REV_BIT_CONST(p, i, m) REV_BIT(p, i, i += m;, i += m * 2;)
#define REV_BIT_LAST(p, i, m)  REV_BIT(p, i, i -= m, ;)

/*
 * Decode symbols while pos < limit and buf < buf_limit (at least one symbol).
 * In : range coder normalized, pos < limit, remain == 0.
 * Out: range coder normalized; d->remain = bytes of a match cut by limit, or
 *      LZ_END after the end marker. Returns 0 or LZ_ERR (distance out of window).
 * The caller guarantees LZ_REQ readable bytes after any buf < buf_limit.
 */
static u32 lz_run(gz_lzma_dec *d, size_t limit, const u8 *buf_limit)
{
    u16 *const probs = d->probs;
    unsigned state = d->state;
    u32 rep0 = d->rep0, rep1 = d->rep1, rep2 = d->rep2, rep3 = d->rep3;
    const unsigned pb_mask = (1u << d->pb) - 1;
    const unsigned lc = d->lc;
    const unsigned lp_mask = (0x100u << d->lp) - (0x100u >> lc);
    u8 *const dic = d->dic;
    const size_t B = d->B;
    const size_t check = d->check;
    size_t pos = d->pos;
    const u8 *buf = d->in_pos;
    u32 range = d->range, code = d->code;
    u32 len = 0, err = 0;

    do {
        u16 *prob;
        u32 bound, ttt;
        const unsigned ps = ((unsigned)pos & pb_mask) << 4;

        prob = probs + P_ISMATCH + ps + state;
        IF_BIT_0(prob) {
            unsigned sym;
            UPDATE_0(prob)
            prob = probs + P_LIT;
            prob += 3u * (((((unsigned)pos << 8) + dic[(pos ? pos : B) - 1]) & lp_mask) << lc);
            if (state < LIT_STATES) {
                state -= state < 4 ? state : 3;
                sym = 1;
                LIT_BIT(prob, sym) LIT_BIT(prob, sym) LIT_BIT(prob, sym) LIT_BIT(prob, sym)
                LIT_BIT(prob, sym) LIT_BIT(prob, sym) LIT_BIT(prob, sym) LIT_BIT(prob, sym)
            } else {
                /* matched literal: follow the byte at rep0 while the bits agree */
                unsigned mb = dic[pos - rep0 + (pos < rep0 ? B : 0)];
                unsigned offs = 0x100, bit;
                u16 *pl;
                state -= state < 10 ? 3 : 6;
                sym = 1;
#define MATCHED_BIT { u32 m_; mb += mb; bit = offs; offs &= mb; pl = prob + (offs + bit + sym); \
                    LIT_BIT_M(pl, m_) sym = (sym << 1) - m_; offs ^= bit & ~m_; }
                MATCHED_BIT MATCHED_BIT MATCHED_BIT MATCHED_BIT
                MATCHED_BIT MATCHED_BIT MATCHED_BIT MATCHED_BIT
#undef MATCHED_BIT
            }
            dic[pos++] = (u8)sym;
            continue;
        }

        UPDATE_1(prob)
        prob = probs + P_ISREP + state;
        IF_BIT_0(prob) {
            UPDATE_0(prob)
            state += NUM_STATES;                /* marks "new distance follows" */
            prob = probs + P_LEN;
        } else {
            UPDATE_1(prob)
            prob = probs + P_ISREPG0 + state;
            IF_BIT_0(prob) {
                UPDATE_0(prob)
                prob = probs + P_ISREP0LONG + ps + state;
                IF_BIT_0(prob) {                /* short rep: one byte at rep0 */
                    UPDATE_0(prob)
                    dic[pos] = dic[pos - rep0 + (pos < rep0 ? B : 0)];
                    pos++;
                    state = state < LIT_STATES ? 9 : 11;
                    continue;
                }
                UPDATE_1(prob)
            } else {
                u32 dist;
                UPDATE_1(prob)
                prob = probs + P_ISREPG1 + state;
                IF_BIT_0(prob) {
                    UPDATE_0(prob)
                    dist = rep1;
                } else {
                    UPDATE_1(prob)
                    prob = probs + P_ISREPG2 + state;
                    IF_BIT_0(prob) {
                        UPDATE_0(prob)
                        dist = rep2;
                    } else {
                        UPDATE_1(prob)
                        dist = rep3;
                        rep3 = rep2;
                    }
                    rep2 = rep1;
                }
                rep1 = rep0;
                rep0 = dist;
            }
            state = state < LIT_STATES ? 8 : 11;
            prob = probs + P_REPLEN;
        }

        /* match length - 2 */
        {
            u16 *pl = prob + LEN_CHOICE;
            IF_BIT_0(pl) {
                UPDATE_0(pl)
                pl = prob + LEN_LOW + ps;
                len = 1;
                TREE_BIT(pl, len) TREE_BIT(pl, len) TREE_BIT(pl, len)
                len -= 8;
            } else {
                UPDATE_1(pl)
                pl = prob + LEN_CHOICE2;
                IF_BIT_0(pl) {
                    UPDATE_0(pl)
                    pl = prob + LEN_LOW + ps + 8;
                    len = 1;
                    TREE_BIT(pl, len) TREE_BIT(pl, len) TREE_BIT(pl, len)
                } else {
                    UPDATE_1(pl)
                    pl = prob + LEN_HIGH;
                    len = 1;
                    TREE_BIT(pl, len) TREE_BIT(pl, len) TREE_BIT(pl, len) TREE_BIT(pl, len)
                    TREE_BIT(pl, len) TREE_BIT(pl, len) TREE_BIT(pl, len) TREE_BIT(pl, len)
                    len -= 256 - 16;
                }
            }
        }

        if (state >= NUM_STATES) {
            u32 dist;
            prob = probs + P_POSSLOT + ((len < 4 ? len : 3) << 6);
            dist = 1;
            TREE_BIT(prob, dist) TREE_BIT(prob, dist) TREE_BIT(prob, dist)
            TREE_BIT(prob, dist) TREE_BIT(prob, dist) TREE_BIT(prob, dist)
            dist -= 0x40;
            if (dist >= 4) {
                unsigned slot = dist;
                unsigned nb = (dist >> 1) - 1;
                dist = 2 | (dist & 1);
                if (slot < 14) {
                    u32 m = 1;
                    dist <<= nb;
                    prob = probs + P_SPECPOS;
                    dist++;
                    do {
                        REV_BIT_VAR(prob, dist, m)
                    } while (--nb);
                    dist -= m;
                } else {
                    nb -= 4;
                    do {
                        u32 t;
                        NORM
                        range >>= 1;
                        code -= range;
                        t = 0 - (code >> 31);           /* all ones if bit is 0 */
                        dist = (dist << 1) + (t + 1);
                        code += range & t;
                    } while (--nb);
                    prob = probs + P_ALIGN;
                    dist <<= 4;
                    {
                        unsigned i = 1;
                        REV_BIT_CONST(prob, i, 1)
                        REV_BIT_CONST(prob, i, 2)
                        REV_BIT_CONST(prob, i, 4)
                        REV_BIT_LAST(prob, i, 8)
                        dist |= i;
                    }
                    if (dist == 0xFFFFFFFFu) {          /* end marker */
                        len = LZ_END;
                        state -= NUM_STATES;
                        break;
                    }
                }
            }
            rep3 = rep2;
            rep2 = rep1;
            rep1 = rep0;
            rep0 = dist + 1;
            state = state < NUM_STATES + LIT_STATES ? LIT_STATES : LIT_STATES + 3;
            if ((size_t)dist >= (check ? check : pos)) {
                err = LZ_ERR;
                len = 0;
                break;
            }
        }

        len += 2;
        {
            size_t rem = limit - pos;
            size_t cur = rem < len ? rem : len;
            size_t src = pos - rep0 + (pos < rep0 ? B : 0);
            len -= (u32)cur;
            if (rep0 >= 8 && cur <= B - src) {
                /* 16- or 8-byte steps; may write up to 15 bytes past the match (see top) */
                u8 *dp = dic + pos;
                const u8 *sp = dic + src;
                u8 *const de = dp + cur;
                pos += cur;
                if (rep0 >= 16) {
                    do {
                        u64 v[2];
                        __builtin_memcpy(v, sp, 16);
                        __builtin_memcpy(dp, v, 16);
                        dp += 16;
                        sp += 16;
                    } while (dp < de);
                } else {
                    do {
                        u64 v;
                        __builtin_memcpy(&v, sp, 8);
                        __builtin_memcpy(dp, &v, 8);
                        dp += 8;
                        sp += 8;
                    } while (dp < de);
                }
            } else if (src < pos && cur <= B - src) {
                /* short distance (1..7): the data repeats with period rep0. Copy
                 * bytes until a multiple of rep0 that is >= 8 back is available. */
                u8 *dp = dic + pos;
                u8 *const de = dp + cur;
                const unsigned per = rep0 == 1 ? 8 : rep0 * ((8 + rep0 - 1) / rep0);
                pos += cur;
                if (rep0 == 1) {
                    __builtin_memset(dp, dp[-1], cur);
                } else {
                    u8 *pe = dp + (per - rep0);
                    if (pe > de) pe = de;
                    while (dp < pe) { *dp = dp[-(ptrdiff_t)rep0]; dp++; }
                    while (dp < de) {
                        u64 v;
                        __builtin_memcpy(&v, dp - per, 8);
                        __builtin_memcpy(dp, &v, 8);
                        dp += 8;
                    }
                }
            } else {
                do {
                    dic[pos++] = dic[src];
                    if (++src == B) src = 0;
                } while (--cur);
            }
        }
    } while (pos < limit && buf < buf_limit);

    NORM

    d->in_pos = buf;
    d->range = range;
    d->code = code;
    d->remain = len;
    d->pos = pos;
    d->rep0 = rep0;
    d->rep1 = rep1;
    d->rep2 = rep2;
    d->rep3 = rep3;
    d->state = state;
    return err;
}

/* ------------------------------------------------------------------ */
/* driver                                                              */

/*
 * Decode until *out_n more bytes are produced or (lzma1 only) the end marker is
 * found, reading at most *in_n compressed bytes (an LZMA2 chunk, or ~0).
 * Both counters are decremented. Sets *ended when the end marker was seen
 * (an end marker inside an LZMA2 chunk is GZ_E_DATA).
 * Returns GZ_E_DATA / GZ_E_TRUNC on corrupt or short input, sink/read errors.
 */
static int lz_decode_part(gz_lzma_dec *d, u64 *out_n, u64 *in_n, int lzma1, int *ended)
{
    for (;;) {
        int r;
        if (d->pos == d->B || d->pos - d->flushed >= LZ_OCHUNK) {
            r = lz_flush(d);
            if (r) return r;
        }
        if (!*out_n) return GZ_OK;

        size_t lim = d->B;
        if (lim - d->flushed > LZ_OCHUNK) lim = d->flushed + LZ_OCHUNK;
        if (*out_n < lim - d->pos) lim = d->pos + (size_t)*out_n;

        if (d->remain) {
            size_t p0 = d->pos;
            lz_write_rem(d, lim);
            *out_n -= d->pos - p0;
            continue;
        }

        /* input window for this step */
        size_t avail = (size_t)(d->in_end - d->in_pos);
        if (avail <= LZ_REQ && *in_n > avail) {
            r = lz_fill(d, LZ_ICAP);
            if (r) return r;
            avail = (size_t)(d->in_end - d->in_pos);
        }
        if (avail > *in_n) avail = (size_t)*in_n;
        const u8 *start = d->in_pos;
        const u8 *real_end = start + avail;
        const u8 *buf_limit;
        int tail = avail <= LZ_REQ;
        if (tail) {
            /* last bytes of the stream / chunk: one symbol at a time, checked */
            buf_limit = real_end + 1;
        } else {
            buf_limit = real_end - LZ_REQ;
        }

        /* a rep match as the very first symbol would refer before the data */
        if (d->pos == 0 && d->check == 0 && d->code >= kBadRepCode) return GZ_E_DATA;

        size_t p0 = d->pos;
        u32 e = lz_run(d, lim, buf_limit);
        if (d->in_pos > real_end) {             /* the last symbol read past the end */
            d->in_pos = real_end;
            return lzma1 && d->in_eof ? GZ_E_TRUNC : GZ_E_DATA;
        }
        *in_n -= (u64)(d->in_pos - start);
        if (e) return GZ_E_DATA;
        if (d->remain == LZ_END) {
            /* the end marker writes nothing, but the symbol may have been cut */
            *out_n -= d->pos - p0;
            if (!lzma1) return GZ_E_DATA;
            *ended = 1;
            d->remain = 0;
            return GZ_OK;
        }
        *out_n -= d->pos - p0;
    }
}

static int lz_finish(gz_lzma_dec *d, u64 *in_used, int r)
{
    if (!r) r = lz_flush(d);
    if (in_used) *in_used = lz_in_used(d);
    d->io = 0;
    return r;
}

int gz_lzma_decode(gz_lzma_dec *d, const u8 props[5], const gz_stream_io *io,
                   u64 out_size, u64 *in_used)
{
    if (in_used) *in_used = 0;
    int r = lz_parse_props(d, props[0], 12);
    if (r) return r;
    u32 dict = rd32(props + 1);
    if (dict < 4096) dict = 4096;
    r = lz_alloc_dic(d, dict, out_size);
    if (!r) r = lz_alloc_probs(d, d->lc + d->lp);
    if (r) return r;

    lz_in_reset(d, io);
    lz_reset_dic(d);
    lz_reset_state(d);
    u64 in_n = ~(u64)0;
    r = lz_rc_init(d, &in_n);
    if (r) return lz_finish(d, in_used, r);

    const int known = out_size != GZ_SIZE_UNKNOWN;
    u64 out_n = known ? out_size : ~(u64)0;
    int ended = 0;
    r = lz_decode_part(d, &out_n, &in_n, 1, &ended);
    if (r) return lz_finish(d, in_used, r);
    if (known) {
        if (ended) return lz_finish(d, in_used, GZ_E_DATA);    /* shorter than declared */
        if (d->flags & GZ_LZMA_LENIENT_END) return lz_finish(d, in_used, GZ_OK);
        if (d->remain) return lz_finish(d, in_used, GZ_E_DATA); /* match crosses the end */
        if (d->code) {
            /* not finished: only an end marker may follow */
            r = lz_flush(d);
            if (r) return lz_finish(d, in_used, r);
            r = lz_fill(d, LZ_REQ + 1);
            if (r) return lz_finish(d, in_used, r);
            const u8 *real_end = d->in_end;
            if (d->in_pos >= real_end) return lz_finish(d, in_used, GZ_E_TRUNC);
            u32 e = lz_run(d, d->pos + 1, d->in_pos + 1);
            if (d->in_pos > real_end) {
                d->in_pos = real_end;
                return lz_finish(d, in_used, GZ_E_TRUNC);
            }
            if (e || d->remain != LZ_END) return lz_finish(d, in_used, GZ_E_DATA);
            d->remain = 0;
        }
    }
    if (d->code) return lz_finish(d, in_used, GZ_E_DATA);
    return lz_finish(d, in_used, GZ_OK);
}

u32 gz_lzma2_dict_size(u8 p)
{
    if (p > 40) return 0;
    if (p == 40) return 0xFFFFFFFFu;
    return (2u | (p & 1u)) << (p / 2 + 11);
}

int gz_lzma2_decode(gz_lzma_dec *d, u8 dict_prop, const gz_stream_io *io,
                    u64 out_size, u64 *in_used)
{
    if (in_used) *in_used = 0;
    if (dict_prop > 40) return GZ_E_DATA;
    int r = lz_alloc_dic(d, gz_lzma2_dict_size(dict_prop), out_size);
    if (!r) r = lz_alloc_probs(d, 4);
    if (r) return r;
    lz_in_reset(d, io);
    lz_reset_dic(d);
    d->lc = d->lp = d->pb = 0;

    const int known = out_size != GZ_SIZE_UNKNOWN;
    u64 out_left = known ? out_size : ~(u64)0;
    int need_dic = 1, need_props = 1;

    for (;;) {
        if (known && !out_left) {
            /* the end byte must follow directly (unless lenient) */
            if (d->flags & GZ_LZMA_LENIENT_END) break;
            r = lz_fill(d, 1);
            if (r) break;
            if (d->in_pos == d->in_end) r = GZ_E_TRUNC;
            else if (*d->in_pos) r = GZ_E_DATA;
            else d->in_pos++;
            break;
        }
        r = lz_fill(d, 6);
        if (r) break;
        const u8 *h = d->in_pos;
        size_t have = (size_t)(d->in_end - h);
        if (!have) { r = GZ_E_TRUNC; break; }
        u32 ctl = h[0];
        if (ctl == 0) {                                     /* end of stream */
            d->in_pos++;
            if (known) r = GZ_E_DATA;
            break;
        }
        if (ctl < 0x80) {
            /* uncompressed chunk: 1 = with dictionary reset, 2 = without */
            if (ctl > 2) { r = GZ_E_DATA; break; }
            if (have < 3) { r = GZ_E_TRUNC; break; }
            if (ctl == 1) {
                r = lz_flush(d);
                if (r) break;
                lz_reset_dic(d);
                need_dic = 0;
                need_props = 1;     /* as in 7-Zip and liblzma */
            } else if (need_dic) {
                r = GZ_E_DATA;
                break;
            }
            u32 n = ((u32)h[1] << 8 | h[2]) + 1;
            int cut = known && n > out_left;
            d->in_pos += 3;
            if (cut) n = (u32)out_left;
            while (n) {
                if (d->pos == d->B || d->pos - d->flushed >= LZ_OCHUNK) {
                    r = lz_flush(d);
                    if (r) break;
                }
                if (d->in_pos == d->in_end) {
                    r = lz_fill(d, LZ_ICAP);
                    if (r) break;
                    if (d->in_pos == d->in_end) { r = GZ_E_TRUNC; break; }
                }
                size_t k = (size_t)(d->in_end - d->in_pos);
                if (k > n) k = n;
                if (k > d->B - d->pos) k = d->B - d->pos;
                __builtin_memcpy(d->dic + d->pos, d->in_pos, k);
                d->pos += k;
                d->in_pos += k;
                n -= (u32)k;
                out_left -= k;
            }
            if (r) break;
            if (cut) {                      /* declared size reached inside the chunk */
                if (!(d->flags & GZ_LZMA_LENIENT_END)) r = GZ_E_DATA;
                break;
            }
            continue;
        }

        /* LZMA chunk */
        u32 mode = (ctl >> 5) & 3;
        size_t hl = mode >= 2 ? 6 : 5;
        if (have < hl) { r = GZ_E_TRUNC; break; }
        u64 unpack = (((u64)(ctl & 0x1F) << 16) | (u64)h[1] << 8 | h[2]) + 1;
        u64 pack = ((u64)h[3] << 8 | h[4]) + 1;
        if (mode == 3) {
            r = lz_flush(d);
            if (r) break;
            lz_reset_dic(d);
            need_dic = 0;
        } else if (need_dic) {
            r = GZ_E_DATA;
            break;
        }
        if (mode >= 2) {
            r = lz_parse_props(d, h[5], 4);
            if (r) break;
            if (d->pb > 4) { r = GZ_E_DATA; break; }
            need_props = 0;
        } else if (need_props) {
            r = GZ_E_DATA;
            break;
        }
        d->in_pos += hl;
        if (mode >= 1) lz_reset_state(d);
        else d->remain = 0;
        r = lz_rc_init(d, &pack);
        if (r) break;
        u64 out_n = unpack;
        int cut = known && out_n > out_left;
        if (cut) out_n = out_left;
        u64 want = out_n;
        int ended = 0;
        r = lz_decode_part(d, &out_n, &pack, 0, &ended);
        if (r) break;
        out_left -= want;
        if (cut) {                          /* declared size reached inside the chunk */
            if (!(d->flags & GZ_LZMA_LENIENT_END)) r = GZ_E_DATA;
            break;
        }
        if (pack || d->remain || d->code) { r = GZ_E_DATA; break; }
    }
    return lz_finish(d, in_used, r);
}

/* ------------------------------------------------------------------ */
/* in-memory helpers                                                   */

typedef struct {
    const u8 *p;
    size_t n;
    int (*sink)(void *, const u8 *, size_t);
    void *user;
} lz_mem_io;

static int lz_mem_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    lz_mem_io *m = (lz_mem_io *)ctx;
    size_t k = m->n < cap ? m->n : cap;
    __builtin_memcpy(buf, m->p, k);
    m->p += k;
    m->n -= k;
    *got = (u32)k;
    return GZ_OK;
}

static int lz_mem_write(void *ctx, const u8 *p, size_t n)
{
    lz_mem_io *m = (lz_mem_io *)ctx;
    return m->sink(m->user, p, n);
}

int gz_lzma_decode_mem(gz_lzma_dec *d, const u8 props[5], const u8 *in, size_t in_len,
                       u64 out_size, int (*sink)(void *, const u8 *, size_t), void *user,
                       u64 *in_used)
{
    lz_mem_io m = { in, in_len, sink, user };
    gz_stream_io io = { lz_mem_read, lz_mem_write, &m };
    return gz_lzma_decode(d, props, &io, out_size, in_used);
}

int gz_lzma2_decode_mem(gz_lzma_dec *d, u8 dict_prop, const u8 *in, size_t in_len,
                        u64 out_size, int (*sink)(void *, const u8 *, size_t), void *user,
                        u64 *in_used)
{
    lz_mem_io m = { in, in_len, sink, user };
    gz_stream_io io = { lz_mem_read, lz_mem_write, &m };
    return gz_lzma2_decode(d, dict_prop, &io, out_size, in_used);
}
