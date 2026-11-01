/*
 * 고깃ZIP - LZX decoder (CAB, CHM, WIM), see lzx.h
 *
 * Bit stream: 16-bit little-endian words, read MSB first. The bit buffer is
 * left aligned (next bit = top bit) and refilled with whole words, so the byte
 * position is always ip - cnt / 8. On 64-bit targets a refill loads 4 words at
 * once; bits of a partially loaded word sit below the valid bits and are simply
 * OR-ed again by the next refill (same values).
 *
 * Huffman codes are canonical (lengths 1..16, MSB first). Decoding uses a
 * primary table indexed by the next tb bits; longer codes and holes of
 * incomplete codes go to a short canonical search (limits per length).
 *
 * The window is a linear buffer of 2 * window bytes: frames are decoded at
 * d->pos and the last window's worth of history is moved down when the next
 * frame would not fit. Matches therefore never wrap and may overshoot by a few
 * bytes (MARGIN).
 */
#include "lzx.h"

#define MAX_SLOTS 50
#define MAIN_MAX  (256 + MAX_SLOTS * 8)
#define LEN_SYMS  249
#define ALN_SYMS  8
#define PRE_SYMS  20
#define MAXLEN    16

#define MAIN_TB 10
#define LEN_TB  8
#define ALN_TB  7
#define PRE_TB  6

#define MARGIN  64u

enum { BT_NONE = 0, BT_VERBATIM = 1, BT_ALIGNED = 2, BT_UNCOMP = 3 };

static const u8 k_extra[MAX_SLOTS] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
    12, 12, 13, 13, 14, 14, 15, 15, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17
};
static const u32 k_base[MAX_SLOTS] = {
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024,
    1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304,
    131072, 196608, 262144, 393216, 524288, 655360, 786432, 917504, 1048576, 1179648,
    1310720, 1441792, 1572864, 1703936, 1835008, 1966080
};
static const u8 k_slots[7] = { 30, 32, 34, 36, 38, 42, 50 };   /* window bits 15..21 */

typedef struct {
    u16 *tab;                 /* 1 << tb entries: sym << 5 | len; 0 = long code or hole */
    u16 *sorted;              /* symbols ordered by (length, symbol)                    */
    u32 tb, maxlen;
    u32 base[MAXLEN + 1];     /* first code of each length, 16-bit left aligned        */
    u32 limit[MAXLEN + 1];    /* end of the codes of length <= L, left aligned          */
    u16 offs[MAXLEN + 1];     /* index in sorted of the first code of each length       */
} huff;

struct gz_lzx_dec {
    u8 *win;                  /* 2 * wsize + MARGIN bytes                               */
    size_t win_alloc;
    u32 wbits, wsize, flags, main_syms;
    u32 cap;                  /* 2 * wsize                                              */
    u32 pos;                  /* write position; win[0..pos) is history                 */
    int header_read, bad;
    int e8_override;
    u32 e8_fixed, e8_size;
    u64 e8_pos;               /* output position since reset (E8 translation)            */
    u32 R0, R1, R2;
    int btype;
    u32 brem, blen;           /* bytes left in the block, block length                   */
    int pad_pending;          /* odd uncompressed block ended: skip one byte              */
    u32 pend_len, pend_off;   /* match continuing into the next frame                     */
    u8 main_len[MAIN_MAX], len_len[LEN_SYMS], aln_len[ALN_SYMS], pre_len[PRE_SYMS];
    u16 main_tab[1u << MAIN_TB], len_tab[1u << LEN_TB], aln_tab[1u << ALN_TB], pre_tab[1u << PRE_TB];
    u16 main_sorted[MAIN_MAX], len_sorted[LEN_SYMS], aln_sorted[ALN_SYMS], pre_sorted[PRE_SYMS];
    huff hmain, hlen, haln, hpre;
};

/* ---------------- bit reader ---------------- */

#if defined(__x86_64__) || defined(__aarch64__) || (defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 8)
typedef u64 bb_t;
#  define BB_BITS 64
#else
typedef u32 bb_t;
#  define BB_BITS 32
#endif

typedef struct {
    bb_t buf;                 /* valid bits at the top                                  */
    u32 cnt;                  /* number of valid bits                                   */
    u32 ip;                   /* next input byte (may run past n: zeros are read there)  */
    u32 n;
    const u8 *in;
} bitrd;

static GZ_NOINLINE void br_refill_slow(bitrd *b)
{
    while (b->cnt <= BB_BITS - 16) {
        u32 w = 0;
        if (b->ip + 1 < b->n) w = rd16(b->in + b->ip);
        else if (b->ip < b->n) w = b->in[b->ip];
        b->buf |= (bb_t)w << (BB_BITS - 16 - b->cnt);
        b->cnt += 16;
        if (b->ip < 0xfffff000u) b->ip += 2;
    }
}

/* afterwards cnt >= BB_BITS - 15 (49 or 17 bits) */
GZ_INLINE void br_refill(bitrd *b)
{
    if (b->cnt > BB_BITS - 16) return;
#if BB_BITS == 64
    if (GZ_LIKELY((u64)b->ip + 8 <= b->n)) {
        u64 x = rd64(b->in + b->ip);
        x = (x << 32) | (x >> 32);                                          /* word order */
        x = ((x & 0x0000ffff0000ffffull) << 16) | ((x >> 16) & 0x0000ffff0000ffffull);
        b->buf |= x >> b->cnt;
        u32 k = (64 - b->cnt) >> 4;
        b->ip += 2 * k;
        b->cnt += 16 * k;
        return;
    }
#else
    if (GZ_LIKELY(b->ip + 4 <= b->n)) {
        do {
            b->buf |= (bb_t)rd16(b->in + b->ip) << (16 - b->cnt);
            b->cnt += 16;
            b->ip += 2;
        } while (b->cnt <= 16);
        return;
    }
#endif
    br_refill_slow(b);
}

GZ_INLINE u32 br_peek16(const bitrd *b) { return (u32)(b->buf >> (BB_BITS - 16)); }
GZ_INLINE void br_drop(bitrd *b, u32 n) { b->buf <<= n; b->cnt -= n; }

/* n = 1..17, enough bits must be present */
GZ_INLINE u32 br_get(bitrd *b, u32 n)
{
    u32 v = (u32)(b->buf >> (BB_BITS - n));
    br_drop(b, n);
    return v;
}

/* slow-path read of 1..16 bits with refill (headers) */
static u32 br_bits(bitrd *b, u32 n)
{
    br_refill(b);
    return br_get(b, n);
}

/* ---------------- Huffman tables ---------------- */

static void huff_setup(huff *h, u16 *tab, u16 *sorted, u32 tb)
{
    h->tab = tab;
    h->sorted = sorted;
    h->tb = tb;
    h->maxlen = 0;
    __builtin_memset(tab, 0, sizeof(u16) << tb);
}

/* lens[i] <= 16. Incomplete codes are accepted (holes decode as errors),
 * over-subscribed ones are not. Returns 0 or -1. */
static int huff_build(huff *h, const u8 *lens, u32 n)
{
    u32 count[MAXLEN + 1], next[MAXLEN + 1];
    u32 i, L, maxlen = 0;
    for (i = 0; i <= MAXLEN; i++) count[i] = 0;
    for (i = 0; i < n; i++) count[lens[i]]++;
    count[0] = 0;
    u32 off = 0, code = 0;
    for (L = 1; L <= MAXLEN; L++) {
        h->offs[L] = (u16)off;
        next[L] = off;
        off += count[L];
        if (count[L]) maxlen = L;
        h->base[L] = code;
        code += count[L] << (16 - L);
        if (code > 65536) return -1;
        h->limit[L] = code;
    }
    for (i = 0; i < n; i++)
        if (lens[i]) h->sorted[next[lens[i]]++] = (u16)i;
    h->maxlen = maxlen;
    /* primary table: codes of length <= tb are contiguous from 0 */
    u32 tb = h->tb, p = 0, si = 0;
    u16 *t = h->tab;
    for (L = 1; L <= tb; L++) {
        u32 step = 1u << (tb - L);
        for (u32 k = 0; k < count[L]; k++, si++) {
            u16 e = (u16)((h->sorted[si] << 5) | L);
            for (u32 j = 0; j < step; j++) t[p + j] = e;
            p += step;
        }
    }
    for (; p < (1u << tb); p++) t[p] = 0;
    return 0;
}

static GZ_NOINLINE u32 huff_slow(const huff *h, u32 v)
{
    for (u32 L = h->tb + 1; L <= h->maxlen; L++)
        if (v < h->limit[L])
            return ((u32)h->sorted[h->offs[L] + ((v - h->base[L]) >> (16 - L))] << 5) | L;
    return 0;
}

/* next symbol as sym << 5 | len (not consumed); 0 = invalid code. Needs >= 16 bits. */
GZ_INLINE u32 huff_peek(const huff *h, u32 v16)
{
    u32 e = h->tab[v16 >> (16 - h->tb)];
    if (GZ_UNLIKELY(!(e & 31))) e = huff_slow(h, v16);
    return e;
}

static int huff_sym(const huff *h, bitrd *b, u32 *sym)
{
    br_refill(b);
    u32 e = huff_peek(h, br_peek16(b));
    if (!e) return GZ_E_DATA;
    br_drop(b, e & 31);
    *sym = e >> 5;
    return GZ_OK;
}

/* ---------------- block headers ---------------- */

/* Pretree-coded code lengths (delta to the previous block's lengths). */
static int read_lens(gz_lzx_dec *d, bitrd *b, u8 *lens, u32 first, u32 last)
{
    for (u32 i = 0; i < PRE_SYMS; i++) d->pre_len[i] = (u8)br_bits(b, 4);
    if (huff_build(&d->hpre, d->pre_len, PRE_SYMS)) return GZ_E_DATA;
    u32 x = first;
    while (x < last) {
        u32 z;
        if (huff_sym(&d->hpre, b, &z)) return GZ_E_DATA;
        if (z <= 16) {
            lens[x] = (u8)((lens[x] + 17 - z) % 17);
            x++;
            continue;
        }
        u32 run;
        u8 v = 0;
        if (z == 17) run = 4 + br_bits(b, 4);
        else if (z == 18) run = 20 + br_bits(b, 5);
        else {                                    /* 19: run of one delta-coded length */
            run = 4 + br_bits(b, 1);
            if (huff_sym(&d->hpre, b, &z) || z > 16) return GZ_E_DATA;
            v = (u8)((lens[x] + 17 - z) % 17);
        }
        if (run > last - x) return GZ_E_DATA;
        for (u32 k = 0; k < run; k++) lens[x + k] = v;
        x += run;
    }
    return GZ_OK;
}

static int read_block_header(gz_lzx_dec *d, bitrd *b)
{
    if (d->pad_pending) {                 /* raw mode: the bit buffer is empty */
        b->ip++;
        d->pad_pending = 0;
    }
    u32 type = br_bits(b, 3), size;
    if (d->flags & GZ_LZX_WIM) {
        if (br_bits(b, 1)) size = 32768;
        else {
            size = br_bits(b, 16);
            if (d->wbits >= 16) size = (size << 8) | br_bits(b, 8);
        }
    } else {
        size = br_bits(b, 16);
        size = (size << 8) | br_bits(b, 8);
    }
    switch (type) {
    case BT_ALIGNED:
        for (u32 i = 0; i < ALN_SYMS; i++) d->aln_len[i] = (u8)br_bits(b, 3);
        if (huff_build(&d->haln, d->aln_len, ALN_SYMS)) return GZ_E_DATA;
        /* fall through */
    case BT_VERBATIM:
        if (read_lens(d, b, d->main_len, 0, 256) ||
            read_lens(d, b, d->main_len, 256, d->main_syms) ||
            huff_build(&d->hmain, d->main_len, d->main_syms) ||
            read_lens(d, b, d->len_len, 0, LEN_SYMS) ||
            huff_build(&d->hlen, d->len_len, LEN_SYMS))
            return GZ_E_DATA;
        break;
    case BT_UNCOMP: {
        /* align to 16 bits; an already aligned stream skips a whole word */
        br_refill(b);
        u32 r = b->cnt & 15;
        br_drop(b, r ? r : 16);
        u32 ip = b->ip - b->cnt / 8;
        b->buf = 0;
        b->cnt = 0;
        if (ip > b->n || b->n - ip < 12) return GZ_E_DATA;
        d->R0 = rd32(b->in + ip);
        d->R1 = rd32(b->in + ip + 4);
        d->R2 = rd32(b->in + ip + 8);
        b->ip = ip + 12;
        break;
    }
    default:
        return GZ_E_DATA;
    }
    d->btype = (int)type;
    d->brem = d->blen = size;
    return GZ_OK;
}

/* ---------------- match copy ---------------- */

/* may write up to 7 bytes past op + len (window MARGIN) */
GZ_INLINE void copy_match(u8 *op, u32 off, u32 len)
{
    const u8 *src = op - off;
    u8 *e = op + len;
    if (GZ_LIKELY(off >= 8)) {
        do { wr64(op, rd64(src)); op += 8; src += 8; } while (op < e);
    } else if (off == 1) {
        u64 v = src[0] * 0x0101010101010101ull;
        do { wr64(op, v); op += 8; } while (op < e);
    } else if (off >= 4) {
        do { wr32(op, rd32(src)); op += 4; src += 4; } while (op < e);
    } else {
        do { *op++ = *src++; } while (op < e);
    }
}

/* ---------------- verbatim / aligned blocks ---------------- */

/* Decode symbols until d->pos reaches run_end (end of the block or the frame). */
static int decode_run(gz_lzx_dec *d, bitrd *bp, u32 run_end)
{
    bitrd b = *bp;
    u8 *const win = d->win;
    u8 *op = win + d->pos;
    u8 *const end = win + run_end;
    const u32 blk_end = d->pos + d->brem;   /* matches may not cross it */
    const u32 wsize = d->wsize;
    const huff *hm = &d->hmain, *hl = &d->hlen, *ha = &d->haln;
    const int aligned = d->btype == BT_ALIGNED;
    u32 R0 = d->R0, R1 = d->R1, R2 = d->R2;
    int err = GZ_OK;

    while (op < end) {
        br_refill(&b);
        u32 e = huff_peek(hm, br_peek16(&b));
        if (GZ_UNLIKELY(!e)) { err = GZ_E_DATA; break; }
        br_drop(&b, e & 31);
        u32 sym = e >> 5;
        if (sym < 256) {
            *op++ = (u8)sym;
#if BB_BITS == 64
            /* >= 33 bits left: one more symbol fits without a refill */
            if (op < end) {
                e = huff_peek(hm, br_peek16(&b));
                if (e && (e >> 5) < 256) {
                    br_drop(&b, e & 31);
                    *op++ = (u8)(e >> 5);
                }
            }
#endif
            continue;
        }
        sym -= 256;
        u32 len = sym & 7, slot = sym >> 3, off;
        if (len == 7) {
            br_refill(&b);
            e = huff_peek(hl, br_peek16(&b));
            if (GZ_UNLIKELY(!e)) { err = GZ_E_DATA; break; }
            br_drop(&b, e & 31);
            len += e >> 5;
        }
        len += 2;
        if (slot < 3) {
            if (slot == 0) off = R0;
            else if (slot == 1) { off = R1; R1 = R0; R0 = off; }
            else { off = R2; R2 = R0; R0 = off; }
        } else {
            u32 ex = k_extra[slot];
            off = k_base[slot] - 2;
            br_refill(&b);
            if (aligned && ex >= 3) {
                if (ex > 3) off += br_get(&b, ex - 3) << 3;
                br_refill(&b);
                e = huff_peek(ha, br_peek16(&b));
                if (GZ_UNLIKELY(!e)) { err = GZ_E_DATA; break; }
                br_drop(&b, e & 31);
                off += e >> 5;
            } else if (ex) {
                off += br_get(&b, ex);
            }
            R2 = R1; R1 = R0; R0 = off;
        }
        u32 have = (u32)(op - win);
        if (GZ_UNLIKELY(off - 1 >= (have < wsize ? have : wsize) || len > blk_end - have)) {
            err = GZ_E_DATA;
            break;
        }
        if (GZ_UNLIKELY(len > (u32)(end - op))) {
            /* runs past the frame end: finish it at the start of the next frame */
            u32 k = (u32)(end - op);
            copy_match(op, off, k);
            op = end;
            d->pend_len = len - k;
            d->pend_off = off;
            break;
        }
        copy_match(op, off, len);
        op += len;
    }
    d->brem -= (u32)(op - win) - d->pos;
    d->brem -= d->pend_len;                  /* the pending part belongs to this block too */
    d->pos = (u32)(op - win);
    d->R0 = R0; d->R1 = R1; d->R2 = R2;
    *bp = b;
    return err;
}

/* ---------------- E8 translation ---------------- */

static void e8_translate(u8 *p, u32 n, u32 start, i32 tsize)
{
    if (n <= 10) return;
    const u8 *end = p + n - 10;
    u8 *q = p;
    while (q < end) {
        if (*q != 0xE8) { q++; continue; }
        i32 cur = (i32)(start + (u32)(q - p));
        i32 a = (i32)rd32(q + 1);
        if (a >= -cur && a < tsize) {
            i32 rel = a >= 0 ? a - cur : a + tsize;
            wr32(q + 1, (u32)rel);
        }
        q += 5;
    }
}

/* ---------------- public API ---------------- */

int gz_lzx_init(gz_lzx_dec *d, u32 window_bits, u32 flags)
{
    if (window_bits < 15 || window_bits > 21) return GZ_E_METHOD;
    u32 wsize = 1u << window_bits;
    size_t need = (size_t)2 * wsize + MARGIN;
    if (d->win_alloc < need) {
        u8 *w = (u8 *)gz_alloc_big(need);
        if (!w) return GZ_E_NOMEM;
        if (d->win) gz_free_big(d->win, d->win_alloc);
        d->win = w;
        d->win_alloc = need;
    }
    d->wbits = window_bits;
    d->wsize = wsize;
    d->cap = 2 * wsize;
    d->flags = flags;
    d->main_syms = 256 + (u32)k_slots[window_bits - 15] * 8;
    d->e8_override = 0;
    d->e8_fixed = 0;
    huff_setup(&d->hmain, d->main_tab, d->main_sorted, MAIN_TB);
    huff_setup(&d->hlen, d->len_tab, d->len_sorted, LEN_TB);
    huff_setup(&d->haln, d->aln_tab, d->aln_sorted, ALN_TB);
    huff_setup(&d->hpre, d->pre_tab, d->pre_sorted, PRE_TB);
    gz_lzx_reset(d);
    return GZ_OK;
}

gz_lzx_dec *gz_lzx_new(u32 window_bits, u32 flags)
{
    gz_lzx_dec *d = (gz_lzx_dec *)gz_alloc(sizeof(gz_lzx_dec));
    if (!d) return 0;
    if (gz_lzx_init(d, window_bits, flags)) { gz_free(d); return 0; }
    return d;
}

void gz_lzx_free(gz_lzx_dec *d)
{
    if (!d) return;
    if (d->win) gz_free_big(d->win, d->win_alloc);
    gz_free(d);
}

void gz_lzx_reset(gz_lzx_dec *d)
{
    d->pos = 0;
    d->header_read = 0;
    d->bad = 0;
    d->e8_pos = 0;
    d->e8_size = d->e8_override ? d->e8_fixed : (d->flags & GZ_LZX_WIM) ? GZ_LZX_WIM_E8 : 0;
    d->R0 = d->R1 = d->R2 = 1;
    d->btype = BT_NONE;
    d->brem = d->blen = 0;
    d->pad_pending = 0;
    d->pend_len = d->pend_off = 0;
    __builtin_memset(d->main_len, 0, sizeof d->main_len);
    __builtin_memset(d->len_len, 0, sizeof d->len_len);
}

void gz_lzx_set_e8(gz_lzx_dec *d, u32 translation_size)
{
    d->e8_override = 1;
    d->e8_fixed = translation_size;
    d->e8_size = translation_size;
}

int gz_lzx_decode_frame(gz_lzx_dec *d, const u8 *in, u32 in_n, u32 *in_used, u8 *out, u32 out_n)
{
    if (d->bad) return GZ_E_DATA;
    if (!out_n) { if (in_used) *in_used = 0; return GZ_OK; }
    if (out_n > ((d->flags & GZ_LZX_WIM) ? d->wsize : GZ_LZX_FRAME)) return GZ_E_LIMIT;

    if (d->pos + out_n > d->cap) {            /* keep one window of history */
        u32 keep = d->pos < d->wsize ? d->pos : d->wsize;
        __builtin_memmove(d->win, d->win + d->pos - keep, keep);
        d->pos = keep;
    }
    const u32 fstart = d->pos, fend = d->pos + out_n;
    bitrd b;
    b.buf = 0;
    b.cnt = 0;
    b.ip = 0;
    b.n = in_n;
    b.in = in;
    int err = GZ_OK;

    if (!d->header_read) {
        if (!(d->flags & GZ_LZX_WIM)) {
            u32 sz = 0;
            if (br_bits(&b, 1)) {
                sz = br_bits(&b, 16) << 16;
                sz |= br_bits(&b, 16);
            }
            if (!d->e8_override) d->e8_size = sz;
        }
        d->header_read = 1;
    }

    while (d->pos < fend) {
        if (d->pend_len) {
            u32 k = d->pend_len < fend - d->pos ? d->pend_len : fend - d->pos;
            copy_match(d->win + d->pos, d->pend_off, k);
            d->pos += k;
            d->pend_len -= k;
            continue;
        }
        if (!d->brem) {
            if ((err = read_block_header(d, &b))) goto fail;
            continue;                          /* zero-sized blocks are allowed */
        }
        u32 run_end = d->pos + (d->brem < fend - d->pos ? d->brem : fend - d->pos);
        if (d->btype == BT_UNCOMP) {
            u32 k = run_end - d->pos;
            if (b.ip > in_n || in_n - b.ip < k) { err = GZ_E_DATA; goto fail; }
            __builtin_memcpy(d->win + d->pos, in + b.ip, k);
            b.ip += k;
            d->pos += k;
            d->brem -= k;
            if (!d->brem && (d->blen & 1)) d->pad_pending = 1;
        } else {
            if ((err = decode_run(d, &b, run_end))) goto fail;
        }
    }

    /* frame end: realign to 16 bits */
    u32 used;
    if (d->btype == BT_UNCOMP && !b.cnt) {
        if (!in_used && d->pad_pending && b.ip + 1 == in_n) {   /* pad stored with this frame */
            b.ip++;
            d->pad_pending = 0;
        }
        used = b.ip;
    } else {
        br_drop(&b, b.cnt & 15);
        used = b.ip - b.cnt / 8;
    }
    if (used > in_n) { err = GZ_E_DATA; goto fail; }
    if (in_used) *in_used = used;

    if (out) {
        __builtin_memcpy(out, d->win + fstart, out_n);
        if (d->e8_size && d->e8_pos < (1u << 30))
            e8_translate(out, out_n, (u32)d->e8_pos, (i32)d->e8_size);
    }
    d->e8_pos += out_n;
    return GZ_OK;

fail:
    d->bad = 1;
    return err;
}

int gz_lzx_decode_chunk(gz_lzx_dec *d, const u8 *in, u32 in_n, u8 *out, u32 out_n)
{
    gz_lzx_reset(d);
    return gz_lzx_decode_frame(d, in, in_n, 0, out, out_n);
}

void *gz_lzx_slot_new(void) { return gz_lzx_new(15, 0); }
void gz_lzx_slot_free(void *d) { gz_lzx_free((gz_lzx_dec *)d); }
