/*
 * 고깃ZIP - LZMA / LZMA2 encoder (see lzma_enc.h)
 *
 * The parsers and the price model follow Igor Pavlov's LzmaEnc.c (public
 * domain): range coder with 11-bit probabilities, prices in 1/16 bit from a
 * 128-entry table, optimal parsing over up to 4096 positions with backward
 * tracing, cached price tables refreshed after a number of uses.
 *
 * LZMA2 chunks: the encoder state (probabilities, state, reps) is saved before
 * each chunk; when the chunk does not shrink it is sent uncompressed and the
 * state is restored, so the next LZMA chunk continues without a reset (the
 * decoder keeps its state across uncompressed chunks). Chunks end only where
 * the parser has no pending decisions, so restoring is exact.
 */
#include "lzma_enc.h"

#define OPTS          (1u << 12)       /* optimal parser window                    */
#define INF_PRICE     (1u << 30)
#define NREPS         4
#define NSTATES       12
#define LEN_MIN       2
#define LEN_MAX       273
#define LEN_SYMS      (8 + 8 + 256)
#define SLOT_BITS     6
#define LEN_TO_POS    4
#define START_POS     4
#define END_POS       14
#define FULL_DIST     128
#define ALIGN_BITS    4
#define ALIGN_SIZE    16
#define ALIGN_MASK    15
#define LIT_SIZE      0x300
#define LIT_NONE      0xFFFFFFFFu      /* "back" of a literal                      */
#define PRICE_SHIFT   4                /* 1 bit = 16                               */

#define CHUNK_UNPACK  (1u << 21)       /* LZMA2 limits                             */
#define CHUNK_PACK    (1u << 16)
#define UNPACK_MARGIN (OPTS + 1024)    /* > bytes coded between two chunk checks   */
#define PACK_RESERVE  (OPTS * 2)
#define CHUNK_HDR     6
#define OBUF_SIZE     (CHUNK_HDR + 2 * CHUNK_PACK)   /* chunk + overflow slack      */
#define LZ2_KEEP_MIN  (64u << 10)

typedef u16 prob;

typedef struct {
    prob choice, choice2;
    prob low[16 << 3];
    prob mid[16 << 3];
    prob high[256];
} len_probs;

typedef struct {                 /* every member is a prob: initialised as an array */
    prob is_match[NSTATES][16];
    prob is_rep0_long[NSTATES][16];
    prob is_rep[NSTATES], is_rep_g0[NSTATES], is_rep_g1[NSTATES], is_rep_g2[NSTATES];
    prob slot[LEN_TO_POS][1 << SLOT_BITS];
    prob spec[1 + FULL_DIST - END_POS];   /* [0] unused: tree index base - slot >= 0 */
    prob align[ALIGN_SIZE];
    len_probs len, rep_len;
} lz_probs;

typedef struct {
    lz_probs p;
    u32 state;
    u32 reps[NREPS];
} lz_model;

typedef struct {
    u32 price;
    u32 pos_prev, back_prev;     /* back: LIT_NONE, rep index 0..3, distance + 4    */
    u32 pos_prev2, back_prev2;   /* match/rep before "literal + rep0"               */
    u32 backs[NREPS];
    u8  state, prev1_is_char, prev2, pad_;
} opt_t;

typedef struct {
    u64 low;
    u64 cache_size;
    u64 done;                    /* bytes moved out of the buffer                   */
    u32 range;
    u8  cache;
    u8 *p, *base, *lim;
    int overflow, err;
    const gz_stream_io *io;      /* NULL: chunk mode (buffer overflow is flagged)   */
} rc_enc;

struct gz_lzma_enc {
    gz_lzma_enc_opts o;
    u32 dict;                    /* effective dictionary size                       */
    u32 lc, lp, pb, lp_mask, pb_mask, nice;
    int fast;
    gz_lz_mf mf;
    rc_enc rc;
    lz_model m, saved;
    prob *lit, *lit_saved;
    size_t lit_n;
    /* parser */
    u32 add_off;                 /* bytes the match finder is ahead of the coder    */
    u32 longest_len, num_pairs, num_avail;
    u32 opt_cur, opt_end;
    u64 now_pos;
    int drain;                   /* fast parser: no look-ahead (chunk end near)     */
    opt_t *opt;
    u32 matches[LEN_MAX * 2 + 8];
    /* prices */
    u32 pp[2048 >> 4];
    u32 slot_prices[LEN_TO_POS][1 << SLOT_BITS];
    u32 dist_prices[LEN_TO_POS][FULL_DIST];
    u32 align_prices[ALIGN_SIZE];
    u32 len_prices[16][LEN_SYMS], rep_len_prices[16][LEN_SYMS];
    u32 len_cnt[16], rep_len_cnt[16];
    u32 len_table, dist_table_size;
    u32 match_price_count, align_price_count;
    /* LZMA2 */
    u32 max_unpack;
    /* output */
    u8 *obuf;
    u64 out_total;
};

static const u8 lit_next[NSTATES]   = { 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 4, 5 };
static const u8 match_next[NSTATES] = { 7, 7, 7, 7, 7, 7, 7, 10, 10, 10, 10, 10 };
static const u8 rep_next[NSTATES]   = { 8, 8, 8, 8, 8, 8, 8, 11, 11, 11, 11, 11 };
static const u8 srep_next[NSTATES]  = { 9, 9, 9, 9, 9, 9, 9, 11, 11, 11, 11, 11 };

/* ---------------- small helpers ---------------- */

GZ_INLINE u32 get_slot(u32 d)
{
    if (d < 4) return d;
    u32 n = 31 - (u32)__builtin_clz(d);
    return (n << 1) | ((d >> (n - 1)) & 1);
}

GZ_INLINE u32 len_to_pos(u32 len) { return len < LEN_TO_POS + 2 ? len - 2 : LEN_TO_POS - 1; }

#define match_ext gz_lz_match_len

/* ---------------- range encoder ---------------- */

static void rc_init(rc_enc *rc, u8 *buf, size_t cap, const gz_stream_io *io)
{
    rc->low = 0;
    rc->range = 0xFFFFFFFFu;
    rc->cache = 0;
    rc->cache_size = 1;
    rc->base = rc->p = buf;
    rc->lim = buf + cap;
    rc->done = 0;
    rc->overflow = 0;
    rc->err = 0;
    rc->io = io;
}

static GZ_NOINLINE void rc_spill(rc_enc *rc)
{
    size_t n = (size_t)(rc->p - rc->base);
    rc->done += n;
    rc->p = rc->base;
    if (!rc->io) { rc->overflow = 1; return; }
    if (n && !rc->err) {
        int r = rc->io->write(rc->io->ctx, rc->base, n);
        if (r) rc->err = r;
    }
}

static void rc_shift_low(rc_enc *rc)
{
    u32 lo = (u32)rc->low;
    if (lo < 0xFF000000u || (rc->low >> 32) != 0) {
        u8 carry = (u8)(rc->low >> 32), t = rc->cache;
        do {
            *rc->p++ = (u8)(t + carry);
            if (rc->p == rc->lim) rc_spill(rc);
            t = 0xFF;
        } while (--rc->cache_size != 0);
        rc->cache = (u8)(lo >> 24);
    }
    rc->cache_size++;
    rc->low = (u32)(lo << 8);
}

/* bytes the stream would have if flushed now */
GZ_INLINE u64 rc_size(const rc_enc *rc)
{
    return rc->done + (u64)(rc->p - rc->base) + rc->cache_size + 4;
}

static void rc_flush(rc_enc *rc)
{
    for (int i = 0; i < 5; i++) rc_shift_low(rc);
}

GZ_INLINE void rc_bit(rc_enc *rc, prob *pr, u32 bit)
{
    u32 p = *pr, bound = (rc->range >> 11) * p;
    if (bit) {
        rc->low += bound;
        rc->range -= bound;
        p -= p >> 5;
    } else {
        rc->range = bound;
        p += (2048 - p) >> 5;
    }
    *pr = (prob)p;
    if (rc->range < (1u << 24)) {
        rc->range <<= 8;
        rc_shift_low(rc);
    }
}

static void rc_tree(rc_enc *rc, prob *probs, u32 nbits, u32 sym)
{
    u32 m = 1;
    while (nbits) {
        u32 b = (sym >> --nbits) & 1;
        rc_bit(rc, probs + m, b);
        m = (m << 1) | b;
    }
}

static void rc_tree_rev(rc_enc *rc, prob *probs, u32 nbits, u32 sym)
{
    u32 m = 1;
    while (nbits--) {
        u32 b = sym & 1;
        sym >>= 1;
        rc_bit(rc, probs + m, b);
        m = (m << 1) | b;
    }
}

static void rc_direct(rc_enc *rc, u32 v, u32 n)
{
    do {
        rc->range >>= 1;
        n--;
        rc->low += rc->range & (0u - ((v >> n) & 1));
        if (rc->range < (1u << 24)) {
            rc->range <<= 8;
            rc_shift_low(rc);
        }
    } while (n);
}

static void lit_enc(rc_enc *rc, prob *probs, u32 sym)
{
    sym |= 0x100;
    do {
        rc_bit(rc, probs + (sym >> 8), (sym >> 7) & 1);
        sym <<= 1;
    } while (sym < 0x10000);
}

static void lit_enc_matched(rc_enc *rc, prob *probs, u32 sym, u32 mb)
{
    u32 offs = 0x100;
    sym |= 0x100;
    do {
        mb <<= 1;
        rc_bit(rc, probs + (offs + (mb & offs) + (sym >> 8)), (sym >> 7) & 1);
        sym <<= 1;
        offs &= ~(mb ^ sym);
    } while (sym < 0x10000);
}

static void len_enc(rc_enc *rc, len_probs *lp, u32 sym, u32 ps)
{
    if (sym < 8) {
        rc_bit(rc, &lp->choice, 0);
        rc_tree(rc, lp->low + (ps << 3), 3, sym);
    } else {
        rc_bit(rc, &lp->choice, 1);
        if (sym < 16) {
            rc_bit(rc, &lp->choice2, 0);
            rc_tree(rc, lp->mid + (ps << 3), 3, sym - 8);
        } else {
            rc_bit(rc, &lp->choice2, 1);
            rc_tree(rc, lp->high, 8, sym - 16);
        }
    }
}

/* ---------------- prices ---------------- */

#define P0(pp, p)    ((pp)[(p) >> 4])
#define P1(pp, p)    ((pp)[((p) ^ 2047) >> 4])
#define PB(pp, p, b) ((pp)[((p) ^ ((0u - (b)) & 2047)) >> 4])

static void init_prob_prices(u32 *pp)
{
    for (u32 i = 8; i < 2048; i += 16) {
        u32 w = i, bits = 0;
        for (int j = 0; j < 4; j++) {
            w = w * w;
            bits <<= 1;
            while (w >= (1u << 16)) {
                w >>= 1;
                bits++;
            }
        }
        pp[i >> 4] = (11u << 4) - 15 - bits;
    }
}

static u32 tree_price(const u32 *pp, const prob *probs, u32 nbits, u32 sym)
{
    u32 price = 0;
    sym |= 1u << nbits;
    while (sym != 1) {
        price += PB(pp, probs[sym >> 1], sym & 1);
        sym >>= 1;
    }
    return price;
}

static u32 tree_rev_price(const u32 *pp, const prob *probs, u32 nbits, u32 sym)
{
    u32 price = 0, m = 1;
    while (nbits--) {
        u32 b = sym & 1;
        sym >>= 1;
        price += PB(pp, probs[m], b);
        m = (m << 1) | b;
    }
    return price;
}

GZ_INLINE u32 lit_price(const u32 *pp, const prob *probs, u32 sym)
{
    u32 price = 0;
    sym |= 0x100;
    do {
        price += PB(pp, probs[sym >> 8], (sym >> 7) & 1);
        sym <<= 1;
    } while (sym < 0x10000);
    return price;
}

GZ_INLINE u32 lit_price_matched(const u32 *pp, const prob *probs, u32 sym, u32 mb)
{
    u32 price = 0, offs = 0x100;
    sym |= 0x100;
    do {
        mb <<= 1;
        price += PB(pp, probs[offs + (mb & offs) + (sym >> 8)], (sym >> 7) & 1);
        sym <<= 1;
        offs &= ~(mb ^ sym);
    } while (sym < 0x10000);
    return price;
}

static void len_set_prices(const u32 *pp, const len_probs *lp, u32 ps, u32 n, u32 *prices)
{
    u32 a0 = P0(pp, lp->choice), a1 = P1(pp, lp->choice);
    u32 b0 = a1 + P0(pp, lp->choice2), b1 = a1 + P1(pp, lp->choice2), i;
    for (i = 0; i < 8 && i < n; i++) prices[i] = a0 + tree_price(pp, lp->low + (ps << 3), 3, i);
    for (; i < 16 && i < n; i++) prices[i] = b0 + tree_price(pp, lp->mid + (ps << 3), 3, i - 8);
    for (; i < n; i++) prices[i] = b1 + tree_price(pp, lp->high, 8, i - 16);
}

static void fill_dist_prices(gz_lzma_enc *e)
{
    u32 temp[FULL_DIST];
    const u32 *pp = e->pp;
    for (u32 i = START_POS; i < FULL_DIST; i++) {
        u32 slot = get_slot(i), footer = (slot >> 1) - 1, base = (2 | (slot & 1)) << footer;
        temp[i] = tree_rev_price(pp, e->m.p.spec + base - slot, footer, i - base);
    }
    for (u32 lps = 0; lps < LEN_TO_POS; lps++) {
        const prob *enc = e->m.p.slot[lps];
        u32 *sp = e->slot_prices[lps], *dp = e->dist_prices[lps];
        for (u32 s = 0; s < e->dist_table_size; s++) sp[s] = tree_price(pp, enc, SLOT_BITS, s);
        for (u32 s = END_POS; s < e->dist_table_size; s++)
            sp[s] += (((s >> 1) - 1) - ALIGN_BITS) << PRICE_SHIFT;
        for (u32 i = 0; i < START_POS; i++) dp[i] = sp[i];
        for (u32 i = START_POS; i < FULL_DIST; i++) dp[i] = sp[get_slot(i)] + temp[i];
    }
    e->match_price_count = 0;
}

static void fill_align_prices(gz_lzma_enc *e)
{
    for (u32 i = 0; i < ALIGN_SIZE; i++)
        e->align_prices[i] = tree_rev_price(e->pp, e->m.p.align, ALIGN_BITS, i);
    e->align_price_count = 0;
}

static void init_prices(gz_lzma_enc *e)
{
    if (e->fast) return;
    fill_dist_prices(e);
    fill_align_prices(e);
    for (u32 ps = 0; ps < (1u << e->pb); ps++) {
        len_set_prices(e->pp, &e->m.p.len, ps, e->len_table, e->len_prices[ps]);
        len_set_prices(e->pp, &e->m.p.rep_len, ps, e->len_table, e->rep_len_prices[ps]);
        e->len_cnt[ps] = e->rep_len_cnt[ps] = e->len_table;
    }
}

GZ_INLINE u32 rep1_price(const gz_lzma_enc *e, u32 state, u32 ps)
{
    return P0(e->pp, e->m.p.is_rep_g0[state]) + P0(e->pp, e->m.p.is_rep0_long[state][ps]);
}

GZ_INLINE u32 pure_rep_price(const gz_lzma_enc *e, u32 idx, u32 state, u32 ps)
{
    const u32 *pp = e->pp;
    const lz_probs *p = &e->m.p;
    if (idx == 0) return P0(pp, p->is_rep_g0[state]) + P1(pp, p->is_rep0_long[state][ps]);
    u32 price = P1(pp, p->is_rep_g0[state]);
    if (idx == 1) return price + P0(pp, p->is_rep_g1[state]);
    return price + P1(pp, p->is_rep_g1[state]) + PB(pp, p->is_rep_g2[state], idx - 2);
}

GZ_INLINE u32 rep_price(const gz_lzma_enc *e, u32 idx, u32 len, u32 state, u32 ps)
{
    return e->rep_len_prices[ps][len - LEN_MIN] + pure_rep_price(e, idx, state, ps);
}

/* price of distance d (0-based) for length state lps */
GZ_INLINE u32 dist_price(const gz_lzma_enc *e, u32 d, u32 lps)
{
    if (d < FULL_DIST) return e->dist_prices[lps][d];
    return e->slot_prices[lps][get_slot(d)] + e->align_prices[d & ALIGN_MASK];
}

GZ_INLINE prob *lit_probs(gz_lzma_enc *e, u32 pos, u32 prev)
{
    return e->lit + (size_t)((((pos & e->lp_mask) << e->lc) + (prev >> (8 - e->lc))) * LIT_SIZE);
}

GZ_INLINE u32 lit_cost(gz_lzma_enc *e, u32 state, u32 position, const u8 *data, u32 match_byte)
{
    const prob *probs = lit_probs(e, position, data[-1]);
    return state >= 7 ? lit_price_matched(e->pp, probs, data[0], match_byte) : lit_price(e->pp, probs, data[0]);
}

/* ---------------- match finder glue ---------------- */

static u32 read_matches(gz_lzma_enc *e, u32 *np)
{
    u32 avail = gz_lz_mf_avail(&e->mf), len = 0;
    u32 n = gz_lz_mf_find(&e->mf, e->matches);
    e->num_avail = avail;
    if (n) {
        len = e->matches[n - 2];
        if (len == e->nice) {             /* the finder stops at nice: extend */
            const u8 *p = e->mf.cur - 1;
            len = match_ext(p, p - e->matches[n - 1] - 1, len, avail < LEN_MAX ? avail : LEN_MAX);
        }
    }
    e->add_off++;
    *np = n;
    return len;
}

GZ_INLINE void move_pos(gz_lzma_enc *e, u32 n)
{
    if (n) {
        e->add_off += n;
        gz_lz_mf_skip(&e->mf, n);
    }
}

/* ---------------- fast parser (greedy with one-step lazy check) ---------------- */

#define CHANGE_PAIR(small, big) (((big) >> 7) > (small))

static u32 opt_fast(gz_lzma_enc *e, u32 *back_res)
{
    u32 main_len, num_pairs, num_avail, rep_len = 0, rep_idx = 0, main_dist = 0;
    const u8 *data;
    const u32 *matches = e->matches;

    if (e->add_off == 0) main_len = read_matches(e, &num_pairs);
    else {
        main_len = e->longest_len;
        num_pairs = e->num_pairs;
    }
    num_avail = e->num_avail;
    *back_res = LIT_NONE;
    if (num_avail < 2) return 1;
    if (num_avail > LEN_MAX) num_avail = LEN_MAX;
    data = e->mf.cur - 1;

    for (u32 i = 0; i < NREPS; i++) {
        const u8 *d2 = data - e->m.reps[i] - 1;
        if (data[0] != d2[0] || data[1] != d2[1]) continue;
        u32 len = match_ext(data, d2, 2, num_avail);
        if (len >= e->nice) {
            *back_res = i;
            move_pos(e, len - 1);
            return len;
        }
        if (len > rep_len) {
            rep_idx = i;
            rep_len = len;
        }
    }
    if (main_len >= e->nice) {
        *back_res = matches[num_pairs - 1] + NREPS;
        move_pos(e, main_len - 1);
        return main_len;
    }
    if (main_len >= 2) {
        main_dist = matches[num_pairs - 1];
        while (num_pairs > 2 && main_len == matches[num_pairs - 4] + 1) {
            if (!CHANGE_PAIR(matches[num_pairs - 3], main_dist)) break;
            num_pairs -= 2;
            main_len = matches[num_pairs - 2];
            main_dist = matches[num_pairs - 1];
        }
        if (main_len == 2 && main_dist >= 0x80) main_len = 1;
    }
    if (rep_len >= 2 && (rep_len + 1 >= main_len ||
                         (rep_len + 2 >= main_len && main_dist >= (1u << 9)) ||
                         (rep_len + 3 >= main_len && main_dist >= (1u << 15)))) {
        *back_res = rep_idx;
        move_pos(e, rep_len - 1);
        return rep_len;
    }
    if (main_len < 2 || num_avail <= 2) return 1;
    if (e->drain) {                       /* chunk end near: no look-ahead */
        *back_res = main_dist + NREPS;
        move_pos(e, main_len - 1);
        return main_len;
    }

    e->longest_len = read_matches(e, &e->num_pairs);
    if (e->longest_len >= 2) {
        u32 nd = matches[e->num_pairs - 1], nl = e->longest_len;
        if ((nl >= main_len && nd < main_dist) ||
            (nl == main_len + 1 && !CHANGE_PAIR(main_dist, nd)) ||
            nl > main_len + 1 ||
            (nl + 1 >= main_len && main_len >= 3 && CHANGE_PAIR(nd, main_dist)))
            return 1;
    }
    data = e->mf.cur - 1;
    for (u32 i = 0; i < NREPS; i++) {
        const u8 *d2 = data - e->m.reps[i] - 1;
        if (data[0] != d2[0] || data[1] != d2[1]) continue;
        u32 limit = main_len - 1;
        if (match_ext(data, d2, 2, limit) >= limit) return 1;
    }
    *back_res = main_dist + NREPS;
    move_pos(e, main_len - 2);
    return main_len;
}

/* ---------------- optimal parser ---------------- */

GZ_INLINE void make_char(opt_t *o) { o->back_prev = LIT_NONE; o->prev1_is_char = 0; }
GZ_INLINE void make_short_rep(opt_t *o) { o->back_prev = 0; o->prev1_is_char = 0; }

static u32 backward(gz_lzma_enc *e, u32 *back_res, u32 cur)
{
    opt_t *o = e->opt;
    u32 pos_mem = o[cur].pos_prev, back_mem = o[cur].back_prev;
    e->opt_end = cur;
    do {
        if (o[cur].prev1_is_char) {
            make_char(&o[pos_mem]);
            o[pos_mem].pos_prev = pos_mem - 1;
            if (o[cur].prev2) {
                o[pos_mem - 1].prev1_is_char = 0;
                o[pos_mem - 1].pos_prev = o[cur].pos_prev2;
                o[pos_mem - 1].back_prev = o[cur].back_prev2;
            }
        }
        u32 pp = pos_mem, bc = back_mem;
        back_mem = o[pp].back_prev;
        pos_mem = o[pp].pos_prev;
        o[pp].back_prev = bc;
        o[pp].pos_prev = cur;
        cur = pp;
    } while (cur != 0);
    *back_res = o[0].back_prev;
    e->opt_cur = o[0].pos_prev;
    return e->opt_cur;
}

static u32 opt_normal(gz_lzma_enc *e, u32 position, u32 *back_res)
{
    opt_t *o = e->opt;
    const u32 *pp = e->pp;
    const lz_probs *pr = &e->m.p;
    u32 *matches = e->matches;
    u32 main_len, num_pairs, num_avail, rep_max = 0, state, pos_state, len_end, len, cur;
    u32 match_price, rep_match_price, reps[NREPS], rep_lens[NREPS];
    u32 cur_byte, match_byte;
    const u8 *data;

    if (e->opt_end != e->opt_cur) {
        const opt_t *op = &o[e->opt_cur];
        u32 l = op->pos_prev - e->opt_cur;
        *back_res = op->back_prev;
        e->opt_cur = op->pos_prev;
        return l;
    }
    e->opt_cur = e->opt_end = 0;

    if (e->add_off == 0) main_len = read_matches(e, &num_pairs);
    else {
        main_len = e->longest_len;
        num_pairs = e->num_pairs;
    }
    num_avail = e->num_avail;
    if (num_avail < 2) {
        *back_res = LIT_NONE;
        return 1;
    }
    if (num_avail > LEN_MAX) num_avail = LEN_MAX;
    data = e->mf.cur - 1;

    for (u32 i = 0; i < NREPS; i++) {
        reps[i] = e->m.reps[i];
        const u8 *d2 = data - reps[i] - 1;
        if (data[0] != d2[0] || data[1] != d2[1]) {
            rep_lens[i] = 0;
            continue;
        }
        rep_lens[i] = match_ext(data, d2, 2, num_avail);
        if (rep_lens[i] > rep_lens[rep_max]) rep_max = i;
    }
    if (rep_lens[rep_max] >= e->nice) {
        u32 l = rep_lens[rep_max];
        *back_res = rep_max;
        move_pos(e, l - 1);
        return l;
    }
    if (main_len >= e->nice) {
        *back_res = matches[num_pairs - 1] + NREPS;
        move_pos(e, main_len - 1);
        return main_len;
    }
    cur_byte = data[0];
    match_byte = *(data - reps[0] - 1);
    if (main_len < 2 && cur_byte != match_byte && rep_lens[rep_max] < 2) {
        *back_res = LIT_NONE;
        return 1;
    }

    state = e->m.state;
    o[0].state = (u8)state;
    pos_state = position & e->pb_mask;
    {
        const prob *probs = lit_probs(e, position, data[-1]);
        o[1].price = P0(pp, pr->is_match[state][pos_state]) +
                     (state >= 7 ? lit_price_matched(pp, probs, cur_byte, match_byte)
                                 : lit_price(pp, probs, cur_byte));
    }
    make_char(&o[1]);
    match_price = P1(pp, pr->is_match[state][pos_state]);
    rep_match_price = match_price + P1(pp, pr->is_rep[state]);
    if (match_byte == cur_byte) {
        u32 sp = rep_match_price + rep1_price(e, state, pos_state);
        if (sp < o[1].price) {
            o[1].price = sp;
            make_short_rep(&o[1]);
        }
    }
    len_end = main_len >= rep_lens[rep_max] ? main_len : rep_lens[rep_max];
    if (len_end < 2) {
        *back_res = o[1].back_prev;
        return 1;
    }
    o[1].pos_prev = 0;
    for (u32 i = 0; i < NREPS; i++) o[0].backs[i] = reps[i];
    len = len_end;
    do o[len--].price = INF_PRICE; while (len >= 2);

    for (u32 i = 0; i < NREPS; i++) {
        u32 rl = rep_lens[i];
        if (rl < 2) continue;
        u32 price = rep_match_price + pure_rep_price(e, i, state, pos_state);
        do {
            u32 cp = price + e->rep_len_prices[pos_state][rl - 2];
            opt_t *op = &o[rl];
            if (cp < op->price) {
                op->price = cp;
                op->pos_prev = 0;
                op->back_prev = i;
                op->prev1_is_char = 0;
            }
        } while (--rl >= 2);
    }

    {
        u32 nmp = match_price + P0(pp, pr->is_rep[state]);
        len = rep_lens[0] >= 2 ? rep_lens[0] + 1 : 2;
        if (len <= main_len) {
            u32 offs = 0;
            while (len > matches[offs]) offs += 2;
            for (;; len++) {
                u32 dist = matches[offs + 1], lps = len_to_pos(len);
                u32 cp = nmp + e->len_prices[pos_state][len - LEN_MIN];
                if (dist < FULL_DIST) cp += e->dist_prices[lps][dist];
                else cp += e->align_prices[dist & ALIGN_MASK] + e->slot_prices[lps][get_slot(dist)];
                opt_t *op = &o[len];
                if (cp < op->price) {
                    op->price = cp;
                    op->pos_prev = 0;
                    op->back_prev = dist + NREPS;
                    op->prev1_is_char = 0;
                }
                if (len == matches[offs]) {
                    offs += 2;
                    if (offs == num_pairs) break;
                }
            }
        }
    }

    cur = 0;
    for (;;) {
        u32 new_len, pos_prev, cur_price, cur_and1, avail_full, start_len;
        int next_is_char = 0, lit_done = 0;
        opt_t *cop, *nop;

        cur++;
        if (cur == len_end) return backward(e, back_res, cur);
        new_len = read_matches(e, &num_pairs);
        if (new_len >= e->nice) {
            e->num_pairs = num_pairs;
            e->longest_len = new_len;
            return backward(e, back_res, cur);
        }
        position++;
        cop = &o[cur];
        pos_prev = cop->pos_prev;
        if (cop->prev1_is_char) {
            pos_prev--;
            if (cop->prev2) {
                state = o[cop->pos_prev2].state;
                state = cop->back_prev2 < NREPS ? rep_next[state] : match_next[state];
            } else state = o[pos_prev].state;
            state = lit_next[state];
        } else state = o[pos_prev].state;

        if (pos_prev == cur - 1) {
            /* literal or short rep from cur - 1: reps carry over (still in reps[]) */
            state = cop->back_prev == 0 ? srep_next[state] : lit_next[state];
        } else {
            u32 pos;
            const opt_t *prev;
            if (cop->prev1_is_char && cop->prev2) {
                pos_prev = cop->pos_prev2;
                pos = cop->back_prev2;
                state = rep_next[state];
            } else {
                pos = cop->back_prev;
                state = pos < NREPS ? rep_next[state] : match_next[state];
            }
            prev = &o[pos_prev];
            if (pos < NREPS) {
                u32 i;
                reps[0] = prev->backs[pos];
                for (i = 1; i <= pos; i++) reps[i] = prev->backs[i - 1];
                for (; i < NREPS; i++) reps[i] = prev->backs[i];
            } else {
                reps[0] = pos - NREPS;
                for (u32 i = 1; i < NREPS; i++) reps[i] = prev->backs[i - 1];
            }
        }
        cop->state = (u8)state;
        for (u32 i = 0; i < NREPS; i++) cop->backs[i] = reps[i];

        cur_price = cop->price;
        data = e->mf.cur - 1;
        cur_byte = data[0];
        match_byte = *(data - reps[0] - 1);
        pos_state = position & e->pb_mask;

        /* the literal's own price is only needed when its prefix can still win */
        cur_and1 = cur_price + P0(pp, pr->is_match[state][pos_state]);
        nop = &o[cur + 1];
        if (cur_and1 < nop->price) {
            cur_and1 += lit_cost(e, state, position, data, match_byte);
            lit_done = 1;
            if (cur_and1 < nop->price) {
                nop->price = cur_and1;
                nop->pos_prev = cur;
                make_char(nop);
                next_is_char = 1;
            }
        }
        match_price = cur_price + P1(pp, pr->is_match[state][pos_state]);
        rep_match_price = match_price + P1(pp, pr->is_rep[state]);
        if (match_byte == cur_byte && !(nop->pos_prev < cur && nop->back_prev == 0)) {
            u32 sp = rep_match_price + rep1_price(e, state, pos_state);
            if (sp <= nop->price) {
                nop->price = sp;
                nop->pos_prev = cur;
                make_short_rep(nop);
                next_is_char = 1;
            }
        }
        avail_full = e->num_avail;
        if (OPTS - 1 - cur < avail_full) avail_full = OPTS - 1 - cur;
        if (avail_full < 2) continue;
        num_avail = avail_full <= e->nice ? avail_full : e->nice;

        if (!next_is_char && match_byte != cur_byte) {
            /* literal + rep0 */
            const u8 *d2 = data - reps[0] - 1;
            u32 limit = e->nice + 1;
            if (limit > avail_full) limit = avail_full;
            u32 l2 = match_ext(data, d2, 1, limit) - 1;
            if (l2 >= 2) {
                u32 st2 = lit_next[state], psn = (position + 1) & e->pb_mask;
                if (!lit_done) cur_and1 += lit_cost(e, state, position, data, match_byte);
                u32 nrmp = cur_and1 + P1(pp, pr->is_match[st2][psn]) + P1(pp, pr->is_rep[st2]);
                u32 off = cur + 1 + l2, cp;
                while (len_end < off) o[++len_end].price = INF_PRICE;
                cp = nrmp + rep_price(e, 0, l2, st2, psn);
                opt_t *op = &o[off];
                if (cp < op->price) {
                    op->price = cp;
                    op->pos_prev = cur + 1;
                    op->back_prev = 0;
                    op->prev1_is_char = 1;
                    op->prev2 = 0;
                }
            }
        }

        start_len = 2;
        for (u32 ri = 0; ri < NREPS; ri++) {
            const u8 *d2 = data - reps[ri] - 1;
            u32 lt, lt0, price;
            if (data[0] != d2[0] || data[1] != d2[1]) continue;
            lt0 = lt = match_ext(data, d2, 2, num_avail);
            while (len_end < cur + lt) o[++len_end].price = INF_PRICE;
            price = rep_match_price + pure_rep_price(e, ri, state, pos_state);
            do {
                u32 cp = price + e->rep_len_prices[pos_state][lt - 2];
                opt_t *op = &o[cur + lt];
                if (cp < op->price) {
                    op->price = cp;
                    op->pos_prev = cur;
                    op->back_prev = ri;
                    op->prev1_is_char = 0;
                }
            } while (--lt >= 2);
            lt = lt0;
            if (ri == 0) start_len = lt + 1;
            {
                /* rep + literal + rep0 */
                u32 limit = lt + 1 + e->nice, l2;
                if (limit > avail_full) limit = avail_full;
                l2 = lt + 1 < limit ? match_ext(data, d2, lt + 1, limit) - (lt + 1) : 0;
                if (l2 >= 2) {
                    u32 st2 = rep_next[state], psn = (position + lt) & e->pb_mask, cp;
                    u32 clc = price + e->rep_len_prices[pos_state][lt - 2] +
                              P0(pp, pr->is_match[st2][psn]) +
                              lit_price_matched(pp, lit_probs(e, position + lt, data[lt - 1]),
                                                data[lt], d2[lt]);
                    st2 = lit_next[st2];
                    psn = (position + lt + 1) & e->pb_mask;
                    u32 nrmp = clc + P1(pp, pr->is_match[st2][psn]) + P1(pp, pr->is_rep[st2]);
                    u32 off = cur + lt + 1 + l2;
                    while (len_end < off) o[++len_end].price = INF_PRICE;
                    cp = nrmp + rep_price(e, 0, l2, st2, psn);
                    opt_t *op = &o[off];
                    if (cp < op->price) {
                        op->price = cp;
                        op->pos_prev = cur + lt + 1;
                        op->back_prev = 0;
                        op->prev1_is_char = 1;
                        op->prev2 = 1;
                        op->pos_prev2 = cur;
                        op->back_prev2 = ri;
                    }
                }
            }
        }

        if (new_len > num_avail) {
            new_len = num_avail;
            for (num_pairs = 0; new_len > matches[num_pairs]; num_pairs += 2) {}
            matches[num_pairs] = new_len;
            num_pairs += 2;
        }
        if (new_len >= start_len) {
            u32 nmp = match_price + P0(pp, pr->is_rep[state]), offs = 0, cur_back, dp3;
            /* row indexed by len - LEN_MIN (start_len >= 2): a pointer biased by -LEN_MIN
             * would point before the array (UB, aborts clang -fsanitize=undefined builds) */
            const u32 *lpr = e->len_prices[pos_state];
            while (len_end < cur + new_len) o[++len_end].price = INF_PRICE;
            while (start_len > matches[offs]) offs += 2;
            cur_back = matches[offs + 1];
            dp3 = dist_price(e, cur_back, LEN_TO_POS - 1);   /* lengths >= 5 share it */
            for (u32 lt = start_len;; lt++) {
                u32 cp = nmp + lpr[lt - LEN_MIN] +
                         (lt < LEN_TO_POS + 1 ? dist_price(e, cur_back, lt - 2) : dp3);
                opt_t *op = &o[cur + lt];
                if (cp < op->price) {
                    op->price = cp;
                    op->pos_prev = cur;
                    op->back_prev = cur_back + NREPS;
                    op->prev1_is_char = 0;
                }
                if (lt == matches[offs]) {
                    /* match + literal + rep0 */
                    const u8 *d2 = data - cur_back - 1;
                    u32 limit = lt + 1 + e->nice, l2;
                    if (limit > avail_full) limit = avail_full;
                    l2 = lt + 1 < limit ? match_ext(data, d2, lt + 1, limit) - (lt + 1) : 0;
                    if (l2 >= 2) {
                        u32 st2 = match_next[state], psn = (position + lt) & e->pb_mask, cp2;
                        u32 clc = cp + P0(pp, pr->is_match[st2][psn]) +
                                  lit_price_matched(pp, lit_probs(e, position + lt, data[lt - 1]),
                                                    data[lt], d2[lt]);
                        st2 = lit_next[st2];
                        psn = (psn + 1) & e->pb_mask;
                        u32 nrmp = clc + P1(pp, pr->is_match[st2][psn]) + P1(pp, pr->is_rep[st2]);
                        u32 off = cur + lt + 1 + l2;
                        while (len_end < off) o[++len_end].price = INF_PRICE;
                        cp2 = nrmp + rep_price(e, 0, l2, st2, psn);
                        opt_t *op2 = &o[off];
                        if (cp2 < op2->price) {
                            op2->price = cp2;
                            op2->pos_prev = cur + lt + 1;
                            op2->back_prev = 0;
                            op2->prev1_is_char = 1;
                            op2->prev2 = 1;
                            op2->pos_prev2 = cur;
                            op2->back_prev2 = cur_back + NREPS;
                        }
                    }
                    offs += 2;
                    if (offs == num_pairs) break;
                    cur_back = matches[offs + 1];
                    dp3 = dist_price(e, cur_back, LEN_TO_POS - 1);
                }
            }
        }
    }
}

/* ---------------- symbol coding ---------------- */

static void len_enc_upd(gz_lzma_enc *e, len_probs *lp, u32 (*prices)[LEN_SYMS], u32 *cnt, u32 sym, u32 ps)
{
    len_enc(&e->rc, lp, sym, ps);
    if (!e->fast && --cnt[ps] == 0) {
        len_set_prices(e->pp, lp, ps, e->len_table, prices[ps]);
        cnt[ps] = e->len_table;
    }
}

static void encode_match(gz_lzma_enc *e, u32 len, u32 dist, u32 ps)
{
    rc_enc *rc = &e->rc;
    lz_model *m = &e->m;
    u32 slot = get_slot(dist);
    rc_bit(rc, &m->p.is_rep[m->state], 0);
    m->state = match_next[m->state];
    len_enc_upd(e, &m->p.len, e->len_prices, e->len_cnt, len - LEN_MIN, ps);
    rc_tree(rc, m->p.slot[len_to_pos(len)], SLOT_BITS, slot);
    if (slot >= START_POS) {
        u32 footer = (slot >> 1) - 1, base = (2 | (slot & 1)) << footer, red = dist - base;
        if (slot < END_POS) {
            rc_tree_rev(rc, m->p.spec + base - slot, footer, red);
        } else {
            rc_direct(rc, red >> ALIGN_BITS, footer - ALIGN_BITS);
            rc_tree_rev(rc, m->p.align, ALIGN_BITS, red & ALIGN_MASK);
            e->align_price_count++;
        }
    }
    m->reps[3] = m->reps[2];
    m->reps[2] = m->reps[1];
    m->reps[1] = m->reps[0];
    m->reps[0] = dist;
    e->match_price_count++;
}

static void encode_symbol(gz_lzma_enc *e, u32 len, u32 back)
{
    rc_enc *rc = &e->rc;
    lz_model *m = &e->m;
    u32 ps = (u32)e->now_pos & e->pb_mask, st = m->state;

    if (back == LIT_NONE) {
        const u8 *d = e->mf.cur - e->add_off;
        prob *probs = lit_probs(e, (u32)e->now_pos, d[-1]);
        rc_bit(rc, &m->p.is_match[st][ps], 0);
        if (st < 7) lit_enc(rc, probs, d[0]);
        else lit_enc_matched(rc, probs, d[0], d[-(ptrdiff_t)m->reps[0] - 1]);
        m->state = lit_next[st];
        return;
    }
    rc_bit(rc, &m->p.is_match[st][ps], 1);
    if (back >= NREPS) {
        encode_match(e, len, back - NREPS, ps);
        return;
    }
    rc_bit(rc, &m->p.is_rep[st], 1);
    if (back == 0) {
        rc_bit(rc, &m->p.is_rep_g0[st], 0);
        rc_bit(rc, &m->p.is_rep0_long[st][ps], len != 1);
    } else {
        u32 dist = m->reps[back];
        rc_bit(rc, &m->p.is_rep_g0[st], 1);
        if (back == 1) rc_bit(rc, &m->p.is_rep_g1[st], 0);
        else {
            rc_bit(rc, &m->p.is_rep_g1[st], 1);
            rc_bit(rc, &m->p.is_rep_g2[st], back - 2);
            if (back == 3) m->reps[3] = m->reps[2];
            m->reps[2] = m->reps[1];
        }
        m->reps[1] = m->reps[0];
        m->reps[0] = dist;
    }
    if (len == 1) m->state = srep_next[st];
    else {
        len_enc_upd(e, &m->p.rep_len, e->rep_len_prices, e->rep_len_cnt, len - LEN_MIN, ps);
        m->state = rep_next[st];
    }
}

static void write_end_marker(gz_lzma_enc *e)
{
    rc_enc *rc = &e->rc;
    lz_model *m = &e->m;
    u32 ps = (u32)e->now_pos & e->pb_mask;
    rc_bit(rc, &m->p.is_match[m->state][ps], 1);
    rc_bit(rc, &m->p.is_rep[m->state], 0);
    m->state = match_next[m->state];
    len_enc(rc, &m->p.len, 0, ps);
    rc_tree(rc, m->p.slot[0], SLOT_BITS, (1u << SLOT_BITS) - 1);
    rc_direct(rc, ((1u << 30) - 1) >> ALIGN_BITS, 30 - ALIGN_BITS);
    rc_tree_rev(rc, m->p.align, ALIGN_BITS, ALIGN_MASK);
}

/* Code symbols until the input ends or, with max_unpack != 0, until an LZMA2
 * chunk limit is near. Always stops where the parser has nothing pending
 * (add_off == 0), so a chunk boundary or a state restore is exact. */
static void enc_run(gz_lzma_enc *e, u32 max_unpack, u32 max_pack)
{
    rc_enc *rc = &e->rc;
    const u64 start = e->now_pos;

    if (e->now_pos == 0) {
        u32 np;
        if (gz_lz_mf_avail(&e->mf) == 0) return;
        read_matches(e, &np);
        rc_bit(rc, &e->m.p.is_match[e->m.state][0], 0);
        lit_enc(rc, e->lit, e->mf.cur[-(ptrdiff_t)e->add_off]);
        e->m.state = lit_next[e->m.state];
        e->add_off--;
        e->now_pos++;
        if (gz_lz_mf_avail(&e->mf) == 0) return;
    }
    for (;;) {
        u32 len, back;
        if (e->fast) len = opt_fast(e, &back);
        else len = opt_normal(e, (u32)e->now_pos, &back);
        encode_symbol(e, len, back);
        e->now_pos += len;
        e->add_off -= len;
        if (e->add_off == 0) {
            if (!e->fast) {
                if (e->match_price_count >= (1u << 7)) fill_dist_prices(e);
                if (e->align_price_count >= ALIGN_SIZE) fill_align_prices(e);
            }
            if (gz_lz_mf_avail(&e->mf) == 0 || rc->err || e->mf.err) break;
            if (max_unpack && ((u32)(e->now_pos - start) + UNPACK_MARGIN >= max_unpack ||
                               rc_size(rc) + PACK_RESERVE >= max_pack))
                break;
        } else if (max_unpack && e->fast && !e->drain) {
            if ((u32)(e->now_pos - start) + UNPACK_MARGIN >= max_unpack ||
                rc_size(rc) + PACK_RESERVE >= max_pack)
                e->drain = 1;
        }
    }
}

/* ---------------- setup ---------------- */

static u32 dict_round(u32 d)          /* up to 2^n or 3 * 2^n */
{
    if (d <= GZ_MF_DICT_MIN) return GZ_MF_DICT_MIN;
    for (u32 i = 11; i < 31; i++) {
        if (d <= (2u << i)) return 2u << i;
        if (d <= (3u << i)) return 3u << i;
    }
    return d;
}

static u32 eff_dict(const gz_lzma_enc_opts *o)
{
    u32 d = o->dict_size;
    if (o->size_hint && o->size_hint < d) d = (u32)o->size_hint;
    return dict_round(d);
}

static u32 auto_depth(const gz_lzma_enc_opts *o)
{
    if (o->depth) return o->depth;
    return o->mf == GZ_MF_BT4 ? 16 + o->nice_len / 2 : 4 + o->nice_len / 4;
}

static void mf_config(const gz_lzma_enc_opts *o, int lzma2, gz_lz_mf_cfg *c, u32 *max_unpack)
{
    u32 dict = eff_dict(o);
    size_t keep = (size_t)dict + 1 + OPTS + LEN_MAX + 64;
    c->dict_size = dict;
    c->nice_len = o->nice_len;
    c->depth = auto_depth(o);
    c->type = o->mf;
    c->norm_step = o->test_norm_step;
    *max_unpack = 0;
    if (lzma2) {
        /* the raw bytes of a chunk must stay in the window (uncompressed fallback) */
        u64 k = CHUNK_UNPACK;
        if (o->size_hint && o->size_hint < k) k = o->size_hint;
        if (k < LZ2_KEEP_MIN) k = LZ2_KEEP_MIN;
        if (keep < k) keep = (size_t)k;
        *max_unpack = keep < CHUNK_UNPACK ? (u32)keep : CHUNK_UNPACK;
    }
    c->keep_before = keep;
    /* look-ahead >= the parser's longest probe (match + literal + rep0), so the
     * output does not depend on how the input arrives */
    c->keep_after = 2 * LEN_MAX + 64;
    size_t block = keep / 2 > (1u << 20) ? keep / 2 : (1u << 20);
    if (o->size_hint && block > o->size_hint + 4096) {
        block = (size_t)o->size_hint + 4096;
        if (block < (64u << 10)) block = 64u << 10;
    }
    c->block = block;
}

void gz_lzma_enc_opts_init(gz_lzma_enc_opts *o, int level)
{
    static const u8 dict_log[10] = { 18, 20, 21, 22, 22, 23, 23, 24, 25, 26 };
    static const u16 nice[10] = { 128, 128, 273, 273, 16, 32, 64, 64, 96, 128 };
    static const u8 depth[10] = { 4, 8, 24, 48, 0, 0, 0, 0, 64, 128 };
    int extreme = level >= 0 && (level & GZ_LZMA_EXTREME) != 0;
    level = level < 0 ? 5 : level & 0xFF;      /* negative: the default level */
    if (level > 9) level = 9;
    __builtin_memset(o, 0, sizeof(*o));
    o->level = level;
    o->dict_size = 1u << dict_log[level];
    o->lc = 3;
    o->lp = 0;
    o->pb = 2;
    o->mode = level <= 3 ? GZ_LZMA_FAST : GZ_LZMA_NORMAL;
    o->mf = level <= 3 ? GZ_MF_HC4 : GZ_MF_BT4;
    o->nice_len = nice[level];
    o->depth = depth[level];
    if (extreme) {
        o->mode = GZ_LZMA_NORMAL;
        o->mf = GZ_MF_BT4;
        if (level == 3 || level == 5) {
            o->nice_len = 192;
            o->depth = 0;
        } else {
            o->nice_len = 273;
            o->depth = 512;
        }
    }
}

u64 gz_lzma_enc_memusage(const gz_lzma_enc_opts *o, int lzma2)
{
    gz_lz_mf_cfg c;
    u32 mu;
    mf_config(o, lzma2, &c, &mu);
    u64 lit = (u64)LIT_SIZE * 2 * 2 << (o->lc + o->lp);
    return gz_lz_mf_memusage(&c) + lit + sizeof(gz_lzma_enc) + (u64)OPTS * sizeof(opt_t) + OBUF_SIZE;
}

int gz_lzma_enc_check(const gz_lzma_enc_opts *o, int lzma2)
{
    if (o->lc > 8 || o->lp > 4 || o->pb > 4 || (lzma2 && o->lc + o->lp > 4)) return GZ_E_METHOD;
    if (o->mode > GZ_LZMA_NORMAL || o->mf > GZ_MF_BT4) return GZ_E_METHOD;
    if (o->nice_len < 5 || o->nice_len > LEN_MAX) return GZ_E_METHOD;
    if (o->dict_size < GZ_MF_DICT_MIN) return GZ_E_METHOD;
    if (o->dict_size > GZ_LZMA_DICT_MAX || o->depth > (1u << 30)) return GZ_E_LIMIT;
    if (gz_lzma_enc_memusage(o, lzma2) > GZ_LZMA_MEM_MAX) return GZ_E_LIMIT;
    return GZ_OK;
}

gz_lzma_enc *gz_lzma_enc_new(const gz_lzma_enc_opts *o)
{
    gz_lzma_enc_opts def;
    if (!o) {
        gz_lzma_enc_opts_init(&def, 5);
        o = &def;
    }
    if (gz_lzma_enc_check(o, 0) != GZ_OK) return 0;
    gz_lzma_enc *e = (gz_lzma_enc *)gz_alloc(sizeof(gz_lzma_enc));
    if (!e) return 0;
    e->o = *o;
    e->dict = eff_dict(o);
    e->lc = o->lc;
    e->lp = o->lp;
    e->pb = o->pb;
    e->lp_mask = (1u << o->lp) - 1;
    e->pb_mask = (1u << o->pb) - 1;
    e->nice = o->nice_len;
    e->fast = o->mode == GZ_LZMA_FAST;
    e->len_table = o->nice_len + 1 - LEN_MIN;
    {
        u32 i = 0;
        while (i < 32 && e->dict > (1u << i)) i++;
        e->dist_table_size = i * 2;
    }
    e->lit_n = (size_t)LIT_SIZE << (o->lc + o->lp);
    e->lit = (prob *)gz_alloc(e->lit_n * sizeof(prob));
    e->opt = (opt_t *)gz_alloc((size_t)OPTS * sizeof(opt_t));
    e->obuf = (u8 *)gz_alloc(OBUF_SIZE);
    if (!e->lit || !e->opt || !e->obuf) {
        gz_lzma_enc_free(e);
        return 0;
    }
    init_prob_prices(e->pp);
    return e;
}

void gz_lzma_enc_free(gz_lzma_enc *e)
{
    if (!e) return;
    gz_lz_mf_release(&e->mf);
    gz_free(e->lit);
    gz_free(e->lit_saved);
    gz_free(e->opt);
    gz_free(e->obuf);
    gz_free(e);
}

void gz_lzma_enc_props(const gz_lzma_enc *e, u8 props[5])
{
    props[0] = (u8)((e->pb * 5 + e->lp) * 9 + e->lc);
    wr32(props + 1, e->dict);
}

u8 gz_lzma2_enc_dict_prop(const gz_lzma_enc *e)
{
    u8 p = 0;
    while (p < 40 && ((2u | (p & 1)) << (p / 2 + 11)) < e->dict) p++;
    return p;
}

u64 gz_lzma_enc_in_size(const gz_lzma_enc *e) { return e->mf.in_total; }
u64 gz_lzma_enc_out_size(const gz_lzma_enc *e) { return e->out_total; }

static int enc_start(gz_lzma_enc *e, int lzma2, const gz_stream_io *io)
{
    gz_lz_mf_cfg c;
    int r;
    mf_config(&e->o, lzma2, &c, &e->max_unpack);
    if ((r = gz_lz_mf_alloc(&e->mf, &c)) != GZ_OK) return r;
    prob *q = (prob *)&e->m.p;
    for (size_t i = 0; i < sizeof(lz_probs) / sizeof(prob); i++) q[i] = 1024;
    for (size_t i = 0; i < e->lit_n; i++) e->lit[i] = 1024;
    e->m.state = 0;
    for (int i = 0; i < NREPS; i++) e->m.reps[i] = 0;
    e->add_off = 0;
    e->opt_cur = e->opt_end = 0;
    e->now_pos = 0;
    e->drain = 0;
    e->out_total = 0;
    e->match_price_count = e->align_price_count = 0;
    gz_lz_mf_start(&e->mf, io);
    return GZ_OK;
}

int gz_lzma_encode(gz_lzma_enc *e, const gz_stream_io *io, u8 props[5], int end_marker)
{
    int r;
    if (props) gz_lzma_enc_props(e, props);
    if ((r = enc_start(e, 0, io)) != GZ_OK) return r;
    rc_init(&e->rc, e->obuf, OBUF_SIZE, io);
    init_prices(e);
    enc_run(e, 0, 0);
    if (e->mf.err) return e->mf.err;
    if (e->rc.err) return e->rc.err;
    if (end_marker) write_end_marker(e);
    rc_flush(&e->rc);
    rc_spill(&e->rc);
    e->out_total = e->rc.done;
    return e->rc.err;
}

int gz_lzma2_encode(gz_lzma_enc *e, const gz_stream_io *io, u8 *dict_prop)
{
    int r, need_dict = 1, need_props = 1;
    u8 props = (u8)((e->pb * 5 + e->lp) * 9 + e->lc);
    if ((r = gz_lzma_enc_check(&e->o, 1)) != GZ_OK) return r;     /* lc + lp <= 4, memory cap */
    if (dict_prop) *dict_prop = gz_lzma2_enc_dict_prop(e);
    if (!e->lit_saved && !(e->lit_saved = (prob *)gz_alloc(e->lit_n * sizeof(prob)))) return GZ_E_NOMEM;
    if ((r = enc_start(e, 1, io)) != GZ_OK) return r;

    for (;;) {
        u64 p0 = e->now_pos, packed;
        u32 unpacked;
        e->saved = e->m;
        __builtin_memcpy(e->lit_saved, e->lit, e->lit_n * sizeof(prob));
        rc_init(&e->rc, e->obuf + CHUNK_HDR, OBUF_SIZE - CHUNK_HDR, 0);
        init_prices(e);
        e->drain = 0;
        enc_run(e, e->max_unpack, CHUNK_PACK);
        if (e->mf.err) return e->mf.err;
        unpacked = (u32)(e->now_pos - p0);
        if (!unpacked) break;
        rc_flush(&e->rc);
        packed = e->rc.done + (u64)(e->rc.p - e->rc.base);
        if (e->rc.overflow || packed > CHUNK_PACK || packed + 2 >= unpacked) {
            /* store: the raw bytes are still in the window (add_off == 0) */
            const u8 *src = e->mf.cur - unpacked;
            while (unpacked) {
                u32 u = unpacked < 65536 ? unpacked : 65536;
                u8 h[3] = { (u8)(need_dict ? 1 : 2), (u8)((u - 1) >> 8), (u8)(u - 1) };
                if ((r = io->write(io->ctx, h, 3)) != GZ_OK || (r = io->write(io->ctx, src, u)) != GZ_OK)
                    return r;
                need_dict = 0;
                e->out_total += 3 + u;
                src += u;
                unpacked -= u;
            }
            e->m = e->saved;
            __builtin_memcpy(e->lit, e->lit_saved, e->lit_n * sizeof(prob));
        } else {
            u32 u = unpacked - 1, pk = (u32)packed - 1;
            u32 reset = need_dict ? 3 : need_props ? 2 : 0;
            u32 hl = reset >= 2 ? 6 : 5;
            u8 *h = e->obuf + CHUNK_HDR - hl;
            h[0] = (u8)(0x80 | (reset << 5) | (u >> 16));
            h[1] = (u8)(u >> 8);
            h[2] = (u8)u;
            h[3] = (u8)(pk >> 8);
            h[4] = (u8)pk;
            if (hl == 6) h[5] = props;
            if ((r = io->write(io->ctx, h, hl + (size_t)packed)) != GZ_OK) return r;
            e->out_total += hl + packed;
            need_dict = need_props = 0;
        }
        if (gz_lz_mf_avail(&e->mf) == 0) break;
    }
    {
        u8 z = 0;
        if ((r = io->write(io->ctx, &z, 1)) != GZ_OK) return r;
        e->out_total++;
    }
    return GZ_OK;
}
