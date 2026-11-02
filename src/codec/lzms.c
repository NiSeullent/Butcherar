/*
 * 고깃ZIP - LZMS decoder, see lzms.h
 *
 * Written from the published format description (wimlib's LZMS documentation).
 * Compatibility details that are not obvious from a description:
 *
 *  - Adaptive bits: every probability entry remembers the last 64 bits coded with
 *    it; P(0) = zeros / 64, clamped to 1..63. Each decision (main, match, lz,
 *    lz_rep[2], delta, delta_rep[2]) indexes its entries by the last 4..6 bits
 *    decided there.
 *  - Huffman codes are never transmitted: both sides build them from symbol
 *    frequencies (all 1 at the start; every rebuild halves them, +1) with one
 *    specific length-limited construction (Huffman tree over symbols sorted by
 *    frequency then value, leaves preferred on ties, overlong nodes moved to the
 *    deepest free length). Any other construction desynchronises the stream.
 *  - Repeat queues lag one item: right after an LZ (delta) match, its own offset
 *    (pair) is not yet selectable, so the repeat index is shifted by one.
 *  - The x86 filter runs on every chunk and decides by itself where code is.
 */
#include "lzms.h"
#include "misc_lz.h"

#if defined(__SSE2__)
#include <emmintrin.h>
#elif defined(__aarch64__)
#include <arm_neon.h>
#endif

#define MAX_LEN_BITS   15                  /* longest codeword                  */
#define NUM_OFF_SLOTS  799
#define NUM_LEN_SLOTS  54
#define NUM_LIT        256
#define NUM_POW        8
#define TB             10                  /* primary decode table bits         */
#define TB_POW         7                   /* 8 symbols never exceed 7 bits     */
#define TB_LEN         8                   /* length code: rebuilt more often   */
#define SYM_BITS       10                  /* symbol field in the sort keys     */
#define X86_WINDOW     65535
#define X86_MAX_TRANS  1023

typedef struct { u64 recent; u32 zeros; u32 pad_; } lz_prob;

typedef struct {
    u32 *tab;              /* decode table: primary (1 << tb) + subtables          */
    u32 *freq;             /* nsyms + 1 entries (the 1-symbol code has 2 codewords)  */
    u32 nsyms, tb, rebuild, left;
} lz_huff;

struct gz_lzms_dec {
    lz_prob p_main[16], p_match[32], p_lz[64], p_lzrep[2][64], p_delta[64], p_deltarep[2][64];
    lz_huff lit, lzoff, len, doff, pow;
    u32 off_base[NUM_OFF_SLOTS + 1];
    u8  off_extra[NUM_OFF_SLOTS + 1];
    u32 t_lit[(1 << TB) + 6 * NUM_LIT];
    u32 t_lzoff[(1 << TB) + 6 * NUM_OFF_SLOTS];
    u32 t_len[(1 << TB_LEN) + 6 * NUM_LEN_SLOTS];
    u32 t_doff[(1 << TB) + 6 * NUM_OFF_SLOTS];
    u32 t_pow[1 << TB_POW];
    u32 f_lit[NUM_LIT + 1], f_lzoff[NUM_OFF_SLOTS + 1], f_len[NUM_LEN_SLOTS + 1];
    u32 f_doff[NUM_OFF_SLOTS + 1], f_pow[NUM_POW + 1];
    /* code construction scratch */
    u32 A[NUM_OFF_SLOTS + 1];
    u16 tmp[NUM_OFF_SLOTS + 1];
    u8  lens[NUM_OFF_SLOTS + 1];
    u32 x86_last[65536];       /* last position (x86_base + i) per 16-bit target */
    u32 x86_base;
};

/* Slot base values grow by runs of equal powers of two: run_len[k] slots step by 2^k. */
static const u8 off_runs[] = { 9, 0, 9, 7, 10, 15, 15, 20, 20, 30, 33, 40, 42, 45, 60, 73, 80, 85, 95, 105, 6 };

static const u32 len_base[NUM_LEN_SLOTS] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    29, 31, 33, 35, 39, 43, 47, 51, 55, 59, 67, 75, 83, 91, 107, 123, 139, 155, 171, 203, 235,
    299, 427, 683, 1195, 2219, 67755
};
static const u8 len_extra[NUM_LEN_SLOTS] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 5, 5, 6, 7, 8, 9, 10, 16, 30
};

/* ---------------- Huffman code construction ---------------- */

/* Huffman tree over A[0..n) (frequency << SYM_BITS | symbol, sorted ascending):
 * the n - 1 internal nodes overwrite A[0..n-2] with their parent index (root last). */
static void build_tree(u32 *A, u32 n)
{
    const u32 SM = (1u << SYM_BITS) - 1;
    u32 i = 0, b = 0, e = 0;
    do {
        u32 m, k;
        if (i != n && (b == e || (A[i] >> SYM_BITS) <= (A[b] >> SYM_BITS))) m = i++;
        else m = b++;
        if (i != n && (b == e || (A[i] >> SYM_BITS) <= (A[b] >> SYM_BITS))) k = i++;
        else k = b++;
        u32 f = (A[m] & ~SM) + (A[k] & ~SM);
        A[m] = (A[m] & SM) | (e << SYM_BITS);
        A[k] = (A[k] & SM) | (e << SYM_BITS);
        A[e] = (A[e] & SM) | f;
        e++;
    } while (n - e > 1);
}

/* Codeword counts per length from the tree; depths beyond MAX_LEN_BITS take the
 * deepest length that still has a leaf to split. */
static void length_counts(u32 *A, u32 root, u32 *lc)
{
    const u32 SM = (1u << SYM_BITS) - 1;
    for (u32 l = 0; l <= MAX_LEN_BITS; l++) lc[l] = 0;
    lc[1] = 2;
    A[root] &= SM;
    for (i32 node = (i32)root - 1; node >= 0; node--) {
        u32 parent = A[node] >> SYM_BITS;
        u32 depth = (A[parent] >> SYM_BITS) + 1;
        u32 len = depth;
        A[node] = (A[node] & SM) | (depth << SYM_BITS);
        if (len >= MAX_LEN_BITS) {
            len = MAX_LEN_BITS;
            do len--; while (!lc[len]);
        }
        lc[len]--;
        lc[len + 1] += 2;
    }
}

/* Code lengths for n >= 2 symbols with frequencies 1..4095. */
static void make_lengths(gz_lzms_dec *d, const u32 *freq, u32 n, u8 *lens)
{
    u32 *A = d->A;
    u16 *t = d->tmp;
    u32 cnt[64], lc[MAX_LEN_BITS + 1];
    /* stable LSD radix sort by frequency (2 x 6 bits): ties stay in symbol order */
    __builtin_memset(cnt, 0, sizeof cnt);
    for (u32 s = 0; s < n; s++) cnt[freq[s] & 63]++;
    for (u32 k = 0, sum = 0; k < 64; k++) { u32 c = cnt[k]; cnt[k] = sum; sum += c; }
    for (u32 s = 0; s < n; s++) t[cnt[freq[s] & 63]++] = (u16)s;
    __builtin_memset(cnt, 0, sizeof cnt);
    for (u32 s = 0; s < n; s++) cnt[(freq[s] >> 6) & 63]++;
    for (u32 k = 0, sum = 0; k < 64; k++) { u32 c = cnt[k]; cnt[k] = sum; sum += c; }
    for (u32 i = 0; i < n; i++) {
        u32 s = t[i];
        A[cnt[(freq[s] >> 6) & 63]++] = s | (freq[s] << SYM_BITS);
    }
    build_tree(A, n);
    length_counts(A, n - 2, lc);
    /* longest codes to the least frequent symbols */
    u32 i = 0;
    for (u32 l = MAX_LEN_BITS; l >= 1; l--)
        for (u32 c = lc[l]; c; c--) lens[A[i++] & ((1u << SYM_BITS) - 1)] = (u8)l;
}

/* Canonical MSB-first decode table. Primary entries: symbol << 16 | length, or
 * subtable start << 16 | 0x8000 | subtable bits; subtable entries: symbol << 16 |
 * (length - tb). The code is complete (built here, never read from the input). */
static void build_table(gz_lzms_dec *d, u32 *tab, u32 tb, const u8 *lens, u32 n)
{
    u32 count[MAX_LEN_BITS + 2], offs[MAX_LEN_BITS + 2];
    u16 *sorted = d->tmp;
    __builtin_memset(count, 0, sizeof count);
    for (u32 s = 0; s < n; s++) count[lens[s]]++;
    offs[1] = 0;
    for (u32 l = 1; l <= MAX_LEN_BITS; l++) offs[l + 1] = offs[l] + count[l];
    for (u32 s = 0; s < n; s++) sorted[offs[lens[s]]++] = (u16)s;

    u32 code = 0, idx = 0, l;
    for (l = 1; l <= tb; l++) {
        u32 fill = 1u << (tb - l);
        for (u32 k = 0; k < count[l]; k++) {
            u32 e = (u32)sorted[idx++] << 16 | l;
            u32 *p = tab + (code << (tb - l));
            for (u32 j = 0; j < fill; j++) p[j] = e;
            code++;
        }
        code <<= 1;
    }
    u32 next = 1u << tb, prefix = ~0u, start = 0, sb = 0;
    for (; l <= MAX_LEN_BITS; l++) {
        u32 lb = l - tb;
        for (u32 k = 0; k < count[l]; k++) {
            if ((code >> lb) != prefix) {
                /* new subtable: wide enough for the longest code under this prefix */
                prefix = code >> lb;
                sb = lb;
                i32 rem = (i32)(1u << sb) - (i32)(count[l] - k);
                while (rem > 0 && tb + sb < MAX_LEN_BITS) {
                    sb++;
                    rem = rem * 2 - (i32)count[tb + sb];
                }
                start = next;
                next += 1u << sb;
                tab[prefix] = start << 16 | 0x8000u | sb;
            }
            u32 e = (u32)sorted[idx++] << 16 | lb;
            u32 fill = 1u << (sb - lb);
            u32 *p = tab + start + ((code & ((1u << lb) - 1)) << (sb - lb));
            for (u32 j = 0; j < fill; j++) p[j] = e;
            code++;
        }
        code <<= 1;
    }
}

static void huff_build(gz_lzms_dec *d, lz_huff *h)
{
    u8 *lens = d->lens;
    u32 n = h->nsyms;
    if (n >= 2) {
        make_lengths(d, h->freq, n, lens);
    } else {
        /* one symbol: the smallest complete code pairs it with symbol 1 */
        lens[0] = lens[1] = 1;
        n = 2;
    }
    build_table(d, h->tab, h->tb, lens, n);
    h->left = h->rebuild;
}

static void huff_init(gz_lzms_dec *d, lz_huff *h, u32 nsyms)
{
    h->nsyms = nsyms;
    for (u32 s = 0; s <= nsyms; s++) h->freq[s] = 1;
    if (nsyms) huff_build(d, h);
}

static GZ_NOINLINE void huff_rebuild(gz_lzms_dec *d, lz_huff *h)
{
    huff_build(d, h);
    for (u32 s = 0; s < h->nsyms; s++) h->freq[s] = (h->freq[s] >> 1) + 1;
}

/* ---------------- input streams ---------------- */

typedef struct {
    u32 range, code;
    const u8 *next, *end;      /* forward 16-bit words */
} rdec;

typedef struct {
    u64 buf;                   /* next bits at the top */
    u32 n;                     /* valid bits in buf    */
    const u8 *p, *begin;       /* backward 16-bit words: next word at p - 2 */
} bitrd;

GZ_INLINE u32 rc_bit(rdec *rd, u32 *state, u32 mask, lz_prob *probs)
{
    lz_prob *pe = &probs[*state];
    u32 prob = pe->zeros;
    prob += (prob - 1) >> 31;          /* 0  -> 1  */
    prob -= prob >> 6;                 /* 64 -> 63 */
    if (rd->range < 0x10000u) {
        rd->range <<= 16;
        rd->code <<= 16;
        if (rd->next != rd->end) { rd->code |= rd16(rd->next); rd->next += 2; }
    }
    u32 bound = (rd->range >> 6) * prob, bit;
    if (rd->code < bound) {
        rd->range = bound;
        bit = 0;
    } else {
        rd->range -= bound;
        rd->code -= bound;
        bit = 1;
    }
    pe->zeros += (u32)(pe->recent >> 63) - bit;
    pe->recent = pe->recent << 1 | bit;
    *state = (*state << 1 | bit) & mask;
    return bit;
}

/* Called with n < 48 valid bits: adds whole 16-bit words (at least 32 bits for
 * n < 32); zeros once the stream start is reached. */
GZ_INLINE void br_refill(bitrd *b)
{
    if (GZ_LIKELY(b->p - b->begin >= 8)) {
        /* the 4 words before p, as a little-endian u64, are already in stream order */
        u32 nb = ((63 - b->n) >> 4) << 4;
        u64 v = rd64(b->p - 8) >> (64 - nb) << (64 - nb);
        b->buf |= v >> b->n;
        b->n += nb;
        b->p -= nb >> 3;
        return;
    }
    while (b->n <= 48) {
        if (b->p - b->begin >= 2) {
            b->p -= 2;
            b->buf |= (u64)rd16(b->p) << (48 - b->n);
        }
        b->n += 16;
    }
}

GZ_INLINE u32 br_bits(bitrd *b, u32 n)         /* n <= 32 */
{
    if (!n) return 0;
    if (b->n < n) br_refill(b);
    u32 v = (u32)(b->buf >> (64 - n));
    b->buf <<= n;
    b->n -= n;
    return v;
}

GZ_INLINE u32 huff_sym(gz_lzms_dec *d, lz_huff *h, bitrd *b, const u32 tb)
{
    if (b->n < MAX_LEN_BITS) br_refill(b);
    u32 e = h->tab[b->buf >> (64 - tb)];
    if (e & 0x8000u) {
        b->buf <<= tb;
        b->n -= tb;
        e = h->tab[(e >> 16) + (u32)(b->buf >> (64 - (e & 15)))];
    }
    b->buf <<= e & 15;
    b->n -= e & 15;
    u32 s = e >> 16;
    h->freq[s]++;
    if (GZ_UNLIKELY(--h->left == 0)) huff_rebuild(d, h);
    return s;
}

/* ---------------- x86 filter ---------------- */

static const u8 is_op[256] = { [0x48] = 1, [0x4C] = 1, [0xE8] = 1, [0xE9] = 1, [0xF0] = 1, [0xFF] = 1 };

/* Smallest j > i with a possible opcode byte at data[j]. The sentinel opcode at
 * data[size - 8] (> i) stops the scalar tail. */
GZ_INLINE i32 next_op(const u8 *data, i32 i, i32 size)
{
    i32 j = i + 1;
#if defined(__SSE2__)
    const __m128i c48 = _mm_set1_epi8(0x48), c4c = _mm_set1_epi8(0x4C), ce8 = _mm_set1_epi8((char)0xE8),
                  ce9 = _mm_set1_epi8((char)0xE9), cf0 = _mm_set1_epi8((char)0xF0), cff = _mm_set1_epi8((char)0xFF);
    for (; j <= size - 16; j += 16) {
        __m128i v = _mm_loadu_si128((const __m128i *)(data + j));
        __m128i m = _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(v, c48), _mm_cmpeq_epi8(v, c4c)),
                                 _mm_or_si128(_mm_cmpeq_epi8(v, ce8), _mm_cmpeq_epi8(v, ce9)));
        m = _mm_or_si128(m, _mm_or_si128(_mm_cmpeq_epi8(v, cf0), _mm_cmpeq_epi8(v, cff)));
        u32 bits = (u32)_mm_movemask_epi8(m);
        if (bits) return j + __builtin_ctz(bits);
    }
#elif defined(__aarch64__)
    for (; j <= size - 16; j += 16) {
        uint8x16_t v = vld1q_u8(data + j);
        uint8x16_t m = vorrq_u8(vorrq_u8(vceqq_u8(v, vdupq_n_u8(0x48)), vceqq_u8(v, vdupq_n_u8(0x4C))),
                                vorrq_u8(vceqq_u8(v, vdupq_n_u8(0xE8)), vceqq_u8(v, vdupq_n_u8(0xE9))));
        m = vorrq_u8(m, vorrq_u8(vceqq_u8(v, vdupq_n_u8(0xF0)), vceqq_u8(v, vdupq_n_u8(0xFF))));
        /* narrow to 4 bits per byte */
        u64 bits = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(m), 4)), 0);
        if (bits) return j + (i32)(__builtin_ctzll(bits) >> 2);
    }
#endif
    while (!is_op[data[j]]) j++;
    return j;
}

/* Undo the encoder's translation of relative x86 call/jump/rip-relative operands
 * into absolute ones. Code regions are recognised by two instructions referencing
 * the same (16-bit truncated) target within X86_WINDOW bytes. Target positions are
 * stored as x86_base + i, with x86_base moving past each chunk by more than the
 * window, so the 256 KiB table only needs clearing when the base would wrap. */
static void x86_filter(gz_lzms_dec *d, u8 *data, i32 size)
{
    if (size <= 17) return;
    u32 *last_target = d->x86_last, base = d->x86_base;
    if (!base || base > 0xFFFFFFFFu - (u32)size - 2 * (X86_WINDOW + 1)) {
        __builtin_memset(last_target, 0, sizeof d->x86_last);
        base = X86_WINDOW + 1;
    }
    d->x86_base = base + (u32)size + X86_WINDOW + 1;
    i32 tail = size - 16;
    u8 saved = data[tail + 8];
    data[tail + 8] = 0xE8;                     /* sentinel: ends the scan below */
    i32 last_x86 = -X86_MAX_TRANS - 1;
    i32 i = 0;                                 /* the first byte is never an opcode */
    for (;;) {
        i = next_op(data, i, size);
        if (i >= tail) break;
        i32 max_trans = X86_MAX_TRANS, opn;
        switch (data[i]) {
        case 0x48:
            if (data[i + 1] == 0x8B) {
                if (data[i + 2] == 0x05 || data[i + 2] == 0x0D) { opn = 3; goto have; }  /* mov r, [rip+x] */
            } else if (data[i + 1] == 0x8D) {
                if ((data[i + 2] & 7) == 5) { opn = 3; goto have; }                     /* lea r, [rip+x] */
            }
            continue;
        case 0x4C:
            if (data[i + 1] == 0x8D && (data[i + 2] & 7) == 5) { opn = 3; goto have; }
            continue;
        case 0xE8:                                     /* call rel32: needs more confidence */
            opn = 1;
            max_trans >>= 1;
            goto have;
        case 0xE9:                                     /* jmp rel32: skipped, not translated */
            i += 4;
            continue;
        case 0xF0:
            if (data[i + 1] == 0x83 && data[i + 2] == 0x05) { opn = 3; goto have; }   /* lock add [rip+x] */
            continue;
        default:                                       /* 0xFF */
            if (data[i + 1] == 0x15) { opn = 2; goto have; }                       /* call [rip+x] */
            continue;
        }
have:
        if (i - last_x86 <= max_trans) {
            u8 *q = data + i + opn;
            wr32(q, rd32(q) - (u32)i);
        }
        {
            u16 target = (u16)((u32)i + rd16(data + i + opn));
            i += opn + 3;
            u32 pos = base + (u32)i;
            if (pos - last_target[target] <= X86_WINDOW) last_x86 = i;
            last_target[target] = pos;
        }
    }
    data[tail + 8] = saved;
}

/* ---------------- decoder ---------------- */

static void huff_setup(lz_huff *h, u32 *tab, u32 *freq, u32 tb, u32 rebuild)
{
    h->tab = tab;
    h->freq = freq;
    h->tb = tb;
    h->rebuild = rebuild;
}

gz_lzms_dec *gz_lzms_new(void)
{
    gz_lzms_dec *d = (gz_lzms_dec *)gz_alloc(sizeof(gz_lzms_dec));
    if (!d) return 0;
    u32 slot = 0, base = 0;
    for (u32 k = 0; k < sizeof off_runs; k++)
        for (u32 r = 0; r < off_runs[k]; r++) {
            base += 1u << k;
            if (slot) d->off_extra[slot - 1] = (u8)k;
            d->off_base[slot++] = base;
        }
    d->off_extra[NUM_OFF_SLOTS - 1] = 30;
    d->off_base[NUM_OFF_SLOTS] = base + (1u << 30);
    huff_setup(&d->lit, d->t_lit, d->f_lit, TB, 1024);
    huff_setup(&d->lzoff, d->t_lzoff, d->f_lzoff, TB, 1024);
    huff_setup(&d->len, d->t_len, d->f_len, TB_LEN, 512);
    huff_setup(&d->doff, d->t_doff, d->f_doff, TB, 1024);
    huff_setup(&d->pow, d->t_pow, d->f_pow, TB_POW, 512);
    return d;
}

void gz_lzms_free(gz_lzms_dec *d) { gz_free(d); }
void *gz_lzms_slot_new(void) { return gz_lzms_new(); }
void gz_lzms_slot_free(void *d) { gz_lzms_free((gz_lzms_dec *)d); }

static void probs_init(lz_prob *p, u32 n)
{
    for (u32 k = 0; k < n; k++) {
        p[k].recent = 0x0000000055555555ull;   /* 48 zeros of 64 */
        p[k].zeros = 48;
    }
}

GZ_INLINE u32 read_offset(gz_lzms_dec *d, lz_huff *h, bitrd *b)
{
    u32 s = huff_sym(d, h, b, TB);
    return d->off_base[s] + br_bits(b, d->off_extra[s]);
}

int gz_lzms_decode(gz_lzms_dec *d, const u8 *in, size_t in_n, u8 *out, size_t out_n)
{
    if (!out_n) return GZ_OK;
    if (out_n > GZ_LZMS_MAX_CHUNK) return GZ_E_LIMIT;
    if (in_n < 4 || (in_n & 1)) return GZ_E_DATA;

    rdec rd = { 0xFFFFFFFFu, (u32)rd16(in) << 16 | rd16(in + 2), in + 4, in + in_n };
    bitrd br = { 0, 0, in + in_n, in };

    probs_init(d->p_main, 16);
    probs_init(d->p_match, 32);
    probs_init(d->p_lz, 64);
    probs_init(&d->p_lzrep[0][0], 128);
    probs_init(d->p_delta, 64);
    probs_init(&d->p_deltarep[0][0], 128);

    /* offset slots: those that can address a position inside this chunk */
    u32 nslots = 0;
    if (out_n >= 2) {
        u32 v = (u32)out_n - 1;
        while (nslots + 1 < NUM_OFF_SLOTS && d->off_base[nslots + 1] <= v) nslots++;
        nslots++;
    }
    huff_init(d, &d->lit, NUM_LIT);
    huff_init(d, &d->lzoff, nslots);
    huff_init(d, &d->len, NUM_LEN_SLOTS);
    huff_init(d, &d->doff, nslots);
    huff_init(d, &d->pow, NUM_POW);

    u32 s_main = 0, s_match = 0, s_lz = 0, s_delta = 0;
    u32 s_lzrep[2] = { 0, 0 }, s_deltarep[2] = { 0, 0 };
    u32 lz_rep[4] = { 1, 2, 3, 4 };
    u64 dl_rep[4] = { 1, 2, 3, 4 };       /* power << 32 | raw offset */
    u32 prev = 0;                          /* previous item: 0 literal, 1 LZ, 2 delta */
    u8 *o = out, *const oe = out + out_n;

    while (o < oe) {
        if (!rc_bit(&rd, &s_main, 15, d->p_main)) {
            *o++ = (u8)huff_sym(d, &d->lit, &br, TB);
            prev = 0;
            continue;
        }
        if (!rc_bit(&rd, &s_match, 31, d->p_match)) {
            /* LZ match */
            u32 off;
            if (!rc_bit(&rd, &s_lz, 63, d->p_lz)) {
                if (GZ_UNLIKELY(!nslots)) return GZ_E_DATA;
                off = read_offset(d, &d->lzoff, &br);
                lz_rep[3] = lz_rep[2];
                lz_rep[2] = lz_rep[1];
                lz_rep[1] = lz_rep[0];
            } else {
                u32 sh = prev & 1;
                if (!rc_bit(&rd, &s_lzrep[0], 63, d->p_lzrep[0])) {
                    off = lz_rep[sh];
                    lz_rep[sh] = lz_rep[0];
                } else if (!rc_bit(&rd, &s_lzrep[1], 63, d->p_lzrep[1])) {
                    off = lz_rep[1 + sh];
                    lz_rep[1 + sh] = lz_rep[1];
                    lz_rep[1] = lz_rep[0];
                } else {
                    off = lz_rep[2 + sh];
                    lz_rep[2 + sh] = lz_rep[2];
                    lz_rep[2] = lz_rep[1];
                    lz_rep[1] = lz_rep[0];
                }
            }
            lz_rep[0] = off;
            prev = 1;
            u32 ls = huff_sym(d, &d->len, &br, TB_LEN);
            size_t len = len_base[ls] + br_bits(&br, len_extra[ls]);
            if (GZ_UNLIKELY(off > (size_t)(o - out) || len > (size_t)(oe - o))) return GZ_E_DATA;
            gz_lz_match(o, off, len, oe);
            o += len;
        } else {
            /* delta match: out[i] = out[i - off] + out[i - span] - out[i - off - span] */
            u32 power, raw;
            if (!rc_bit(&rd, &s_delta, 63, d->p_delta)) {
                if (GZ_UNLIKELY(!nslots)) return GZ_E_DATA;
                power = huff_sym(d, &d->pow, &br, TB_POW);
                raw = read_offset(d, &d->doff, &br);
                dl_rep[3] = dl_rep[2];
                dl_rep[2] = dl_rep[1];
                dl_rep[1] = dl_rep[0];
            } else {
                u32 sh = prev >> 1;
                u64 v;
                if (!rc_bit(&rd, &s_deltarep[0], 63, d->p_deltarep[0])) {
                    v = dl_rep[sh];
                    dl_rep[sh] = dl_rep[0];
                } else if (!rc_bit(&rd, &s_deltarep[1], 63, d->p_deltarep[1])) {
                    v = dl_rep[1 + sh];
                    dl_rep[1 + sh] = dl_rep[1];
                    dl_rep[1] = dl_rep[0];
                } else {
                    v = dl_rep[2 + sh];
                    dl_rep[2 + sh] = dl_rep[2];
                    dl_rep[2] = dl_rep[1];
                    dl_rep[1] = dl_rep[0];
                }
                power = (u32)(v >> 32);
                raw = (u32)v;
            }
            dl_rep[0] = (u64)power << 32 | raw;
            prev = 2;
            u32 ls = huff_sym(d, &d->len, &br, TB_LEN);
            size_t len = len_base[ls] + br_bits(&br, len_extra[ls]);
            u64 span = (u64)1 << power, off = (u64)raw << power;
            if (GZ_UNLIKELY(off + span > (u64)(o - out) || len > (size_t)(oe - o))) return GZ_E_DATA;
            const u8 *m = o - off, *os = o - span, *ms = m - span;
            for (size_t k = 0; k < len; k++) o[k] = (u8)(m[k] + os[k] - ms[k]);
            o += len;
        }
    }
    x86_filter(d, out, (i32)out_n);
    return GZ_OK;
}
