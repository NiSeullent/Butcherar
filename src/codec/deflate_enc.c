/*
 * 고깃ZIP - streaming raw Deflate (RFC 1951) encoder
 *
 * Match finders, block splitting, Huffman construction and the near-optimal
 * parser follow the design of libdeflate (Eric Biggers, MIT license), adapted
 * to a bounded streaming buffer:
 *
 *   buf: [ >= 32 KiB history | current block | lookahead ... ]  (IN_CAP bytes)
 *
 * Before each block at least NEED bytes past the block start are buffered, or
 * the input has ended, so the parsers make the same decisions they would with
 * the whole input in memory. When the buffer runs low the tail is moved down
 * (keeping 32 KiB of history) and refilled. Match finder positions are int16
 * relative to in_base, a pointer that moves with the data, so moving the buffer
 * needs no table fix-up; every 32 KiB in_base advances and the tables are
 * rebased with a saturating subtract (SSE2 / AVX2 / NEON / SWAR kernels picked
 * at run time from g_cpu).
 *
 * Levels: 0 stored | 1-2 hash chains, greedy | 3-6 hash chains, lazy |
 *         7-9 binary trees + near-optimal parsing (min-cost path over all cached
 *         matches with an iterated Huffman cost model).
 * Every block is written as dynamic, fixed or stored, whichever is smallest.
 */
#include "deflate_enc.h"
#include "crc32.h"
#include "cpu.h"

#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#elif defined(__aarch64__)
#include <arm_neon.h>
#endif

/* ------------------------------------------------------------------------ */
/* Format constants and tuning                                              */

#define MIN_MATCH        3
#define MAX_MATCH        258
#define NUM_LITLEN       288
#define NUM_OFFSET       32
#define NUM_PRECODE      19
#define FIRST_LEN_SYM    257
#define EOB              256
#define MAX_LITLEN_LEN   14       /* 15 allowed; 14 costs nothing measurable */
#define MAX_OFFSET_LEN   15
#define MAX_PRE_LEN      7

#define MIN_BLOCK        5000     /* below this a new Huffman header rarely pays */
#define SOFT_MAX_BLOCK   300000
#define SEQ_STORE        50000
#define MAX_BLOCK        (SOFT_MAX_BLOCK + MIN_BLOCK - 1)
#define MATCH_CACHE      (SOFT_MAX_BLOCK * 5)
#define CACHE_SLACK      1024     /* > matches of one position + a skipped long match */
#define NODE_SLACK       (2 * MAX_MATCH + 8)

#define IN_CAP           (1u << 20)
#define IN_PAD           64
#define NEED             (SOFT_MAX_BLOCK + MIN_BLOCK + 1024)
#define OUT_CAP          (512u << 10)
#define OUT_RESERVE      (MAX_BLOCK + 6 * 5 + 64)    /* worst block: stored */
#define OUT_SLACK        16

#define NUM_OBS          10       /* 8 literal + 2 match observation types */
#define OBS_PER_CHECK    512

#define BIT_COST         16       /* near-optimal costs in 1/16 bit */
#define LIT_NOSTAT_BITS  13
#define LEN_NOSTAT_BITS  13
#define OFF_NOSTAT_BITS  10
#define OPT_LEN_MASK     511
#define OPT_OFF_SHIFT    9
#define COST_INF         0x40000000u   /* beyond the block end; sums stay < 2^31 */

/* match finder windows and hash sizes */
#define MF_WIN           32768
#define MF_INIT          ((mf_pos)-32768)
#define HC3_ORDER        15
#define HC4_ORDER        16
#define BT3_ORDER        16       /* 2-way */
#define BT4_ORDER        16
#define MF_REQ           5        /* bytes needed to hash the next position */

#define SYM_BITS         10
#define SYM_MASK         ((1u << SYM_BITS) - 1)

typedef i16 mf_pos;

#if UINTPTR_MAX > 0xffffffffu
typedef u64 mword;
#  define WBYTES 8
#  define ldw(p) rd64(p)
#  define stw(p, v) wr64((p), (v))
#  define ctzw(x) ((u32)__builtin_ctzll(x))
#else
typedef u32 mword;
#  define WBYTES 4
#  define ldw(p) rd32(p)
#  define stw(p, v) wr32((p), (v))
#  define ctzw(x) ((u32)__builtin_ctz(x))
#endif
#define BITBUF_BITS (8 * WBYTES - 1)
#define CAN_BUFFER(n) (7 + (n) <= BITBUF_BITS)

enum { F_STORE, F_GREEDY, F_LAZY, F_OPT };

static const u16 k_len_base[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
};
static const u8 k_len_extra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};
static const u16 k_off_base[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193,
    12289, 16385, 24577
};
static const u8 k_off_extra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};
static const u8 k_pre_perm[NUM_PRECODE] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};
static const u8 k_pre_extra[NUM_PRECODE] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7
};

/* per-level parameters */
static const struct {
    u8 family;
    u16 depth, nice;
    u8 passes, min_impr;        /* near-optimal: passes, min. gain (bits) to go on */
    u16 static_opt;             /* near-optimal: optimise for a static block up to N bytes */
} k_levels[10] = {
    { F_STORE,  0,   0,  0,  0,     0 },
    { F_GREEDY, 4,   16, 0,  0,     0 },
    { F_GREEDY, 8,   24, 0,  0,     0 },
    { F_LAZY,   12,  32, 0,  0,     0 },
    { F_LAZY,   16,  48, 0,  0,     0 },
    { F_LAZY,   32,  64, 0,  0,     0 },
    { F_LAZY,   128, 128, 0, 0,     0 },
    { F_OPT,    12,  32, 1, 32,     0 },
    { F_OPT,    16,  64, 1, 32,  1000 },
    { F_OPT,    24,  96, 2, 16,  1000 },
};

/* ------------------------------------------------------------------------ */
/* State                                                                    */

typedef struct { u32 litrun_len; u16 offset; u16 slot; } seq_t;   /* literals, then a match */
#define SEQ_LEN_SHIFT 23
#define SEQ_LIT_MASK  ((1u << SEQ_LEN_SHIFT) - 1)

typedef struct { u16 length, offset; } lz_match;

typedef struct {
    u32 cw[NUM_LITLEN + NUM_OFFSET];     /* litlen codes, then offset codes */
    u8 lens[NUM_LITLEN + NUM_OFFSET];
} codes_t;

typedef struct { u32 lit[256]; u32 len[MAX_MATCH + 1]; u32 off[NUM_OFFSET]; } costs_t;

typedef struct { u32 new_obs[NUM_OBS], obs[NUM_OBS], num_new, num; } split_t;

typedef void (*rebase_fn)(mf_pos *p, size_t n);
typedef struct gz_deflate_enc E;

struct gz_deflate_enc {
    /* configuration */
    int level, family;
    u32 depth, nice, passes, min_impr, static_opt;
    rebase_fn rebase;
    const char *kname;
    void (*block)(E *e);
    void *mem;
    size_t mem_size;

    /* stream */
    const gz_stream_io *io;
    u8 *buf;                    /* IN_CAP + IN_PAD bytes */
    u8 *in_end;                 /* end of buffered input */
    const u8 *in_base;          /* origin of match finder positions */
    const u8 *in_next;          /* next position to parse */
    const u8 *blk;              /* start of the next block */
    int eof, first_block, have_codes;
    u32 crc;
    u64 nin, nout;

    /* bit output */
    u8 *obuf, *out;
    mword bitbuf;
    u32 bitcount;

    /* block statistics and codes */
    u32 freq[NUM_LITLEN + NUM_OFFSET];   /* litlen, then offset */
    codes_t codes, fixed;
    split_t split;
    u32 pre_freq[NUM_PRECODE], pre_cw[NUM_PRECODE];
    u8 pre_lens[NUM_PRECODE];
    u32 pre_items[NUM_LITLEN + NUM_OFFSET];
    u32 n_items, n_lit_syms, n_off_syms, n_explicit;
    u32 len_cw[MAX_MATCH + 1];
    u8 len_bits[MAX_MATCH + 1];
    u8 len_slot[MAX_MATCH + 1];
    u8 off_slot_tab[512];

    /* match finders: one block of int16 tables, rebased together */
    mf_pos *mf, *hash3, *hash4, *chain;
    size_t mf_n, mf_heads;      /* entries in total / in the hash heads */
    u32 next_hashes[2];

    /* greedy / lazy */
    seq_t *seqs;

    /* near-optimal */
    lz_match *cache;
    u32 cache_len;              /* cached entries carried into the next block */
    u32 *ocost, *oitem;         /* per position: cost to block end, chosen item */
    u8 *off_slot_full;          /* offset 0..32768 -> slot */
    costs_t costs, costs_saved;
    u32 mlen_freq[MAX_MATCH + 1], new_mlen_freq[MAX_MATCH + 1];
    u32 prev_obs[NUM_OBS], prev_num_obs;
    int prev_only_lits;
    u8 lit_cost_tab[3][257];
    u8 len_sym_cost[3];
};

/* ------------------------------------------------------------------------ */
/* Small helpers                                                            */

GZ_INLINE u32 lz_hash(u32 seq, u32 order) { return (u32)(seq * 0x1E35A7BDu) >> (32 - order); }

GZ_INLINE u32 bsr32(u32 v) { return 31u - (u32)__builtin_clz(v); }

GZ_INLINE u32 off_slot(const E *e, u32 off)
{
    u32 x = off - 1;
    return x < 256 ? e->off_slot_tab[x] : e->off_slot_tab[256 + (x >> 7)];
}

/* length of the common prefix of s and m, from len up to max_len */
GZ_INLINE u32 lz_extend(const u8 *s, const u8 *m, u32 len, u32 max_len)
{
    mword v;
    if (GZ_LIKELY(max_len - len >= 4 * WBYTES)) {
        v = ldw(m + len) ^ ldw(s + len); if (v) goto diff; len += WBYTES;
        v = ldw(m + len) ^ ldw(s + len); if (v) goto diff; len += WBYTES;
        v = ldw(m + len) ^ ldw(s + len); if (v) goto diff; len += WBYTES;
        v = ldw(m + len) ^ ldw(s + len); if (v) goto diff; len += WBYTES;
    }
    while (len + WBYTES <= max_len) {
        v = ldw(m + len) ^ ldw(s + len);
        if (v) goto diff;
        len += WBYTES;
    }
    while (len < max_len && m[len] == s[len]) len++;
    return len;
diff:
    return len + (ctzw(v) >> 3);
}

#define PREFETCHW(p) __builtin_prefetch((p), 1)

/* ------------------------------------------------------------------------ */
/* Rebase kernels: subtract 32768 from every position with signed saturation */

static void rebase_c(mf_pos *p, size_t n)
{
    for (size_t i = 0; i < n; i += 2) {
        u32 v = rd32(p + i);
        u32 neg = (v >> 15) & 0x00010001u;          /* sign bit of each half */
        wr32(p + i, 0x80008000u | (v & ~(neg * 0xffffu)));
    }
}

#if defined(__i386__) || defined(__x86_64__)
__attribute__((target("sse2"))) static void rebase_sse2(mf_pos *p, size_t n)
{
    const __m128i k = _mm_set1_epi16((short)0x8000);
    __m128i *q = (__m128i *)p, *end = (__m128i *)(p + n);
    for (; q < end; q += 4) {
        _mm_store_si128(q + 0, _mm_adds_epi16(_mm_load_si128(q + 0), k));
        _mm_store_si128(q + 1, _mm_adds_epi16(_mm_load_si128(q + 1), k));
        _mm_store_si128(q + 2, _mm_adds_epi16(_mm_load_si128(q + 2), k));
        _mm_store_si128(q + 3, _mm_adds_epi16(_mm_load_si128(q + 3), k));
    }
}

__attribute__((target("avx2"))) static void rebase_avx2(mf_pos *p, size_t n)
{
    const __m256i k = _mm256_set1_epi16((short)0x8000);
    __m256i *q = (__m256i *)p, *end = (__m256i *)(p + n);
    for (; q < end; q += 2) {
        _mm256_store_si256(q + 0, _mm256_adds_epi16(_mm256_load_si256(q + 0), k));
        _mm256_store_si256(q + 1, _mm256_adds_epi16(_mm256_load_si256(q + 1), k));
    }
}
#endif

#if defined(__aarch64__)
static void rebase_neon(mf_pos *p, size_t n)
{
    const int16x8_t k = vdupq_n_s16(-32768);
    for (size_t i = 0; i < n; i += 32) {
        vst1q_s16(p + i +  0, vqaddq_s16(vld1q_s16(p + i +  0), k));
        vst1q_s16(p + i +  8, vqaddq_s16(vld1q_s16(p + i +  8), k));
        vst1q_s16(p + i + 16, vqaddq_s16(vld1q_s16(p + i + 16), k));
        vst1q_s16(p + i + 24, vqaddq_s16(vld1q_s16(p + i + 24), k));
    }
}
#endif

static void mf_fill_init(mf_pos *p, size_t n)
{
    for (size_t i = 0; i < n; i += 2) wr32(p + i, 0x80008000u);
}

/* cur_pos reached the window size: rebase the tables and move the origin */
static GZ_NOINLINE ptrdiff_t mf_advance(E *e, const u8 **in_base_p, ptrdiff_t cur_pos)
{
    do {
        e->rebase(e->mf, e->mf_n);
        *in_base_p += MF_WIN;
        cur_pos -= MF_WIN;
    } while (cur_pos >= MF_WIN);
    return cur_pos;
}

/* ------------------------------------------------------------------------ */
/* Huffman code construction (length-limited, canonical, bit-reversed)      */

static void sift_down(u32 *a, u32 n, u32 i)
{
    u32 v = a[i];
    for (;;) {
        u32 c = 2 * i + 1;
        if (c >= n) break;
        if (c + 1 < n && a[c + 1] > a[c]) c++;
        if (a[c] <= v) break;
        a[i] = a[c];
        i = c;
    }
    a[i] = v;
}

static void heap_sort(u32 *a, u32 n)
{
    if (n < 2) return;
    for (u32 i = n / 2; i-- > 0;) sift_down(a, n, i);
    while (n > 1) {
        u32 t = a[0]; a[0] = a[n - 1]; a[n - 1] = t;
        sift_down(a, --n, 0);
    }
}

/* Sort used symbols by (freq, sym) into a[] as freq << SYM_BITS | sym (counting
 * sort, heap sort for the high-frequency bucket). Zero-frequency symbols get
 * length 0. Returns the number of used symbols. */
static u32 sort_symbols(u32 nsym, const u32 *freq, u8 *lens, u32 *a)
{
    u32 counters[80];
    u32 nc = (((nsym + 3) / 4) + 3) & ~3u, used = 0;
    for (u32 i = 0; i < nc; i++) counters[i] = 0;
    for (u32 s = 0; s < nsym; s++) counters[GZ_MIN(freq[s], nc - 1)]++;
    for (u32 i = 1; i < nc; i++) {
        u32 c = counters[i];
        counters[i] = used;
        used += c;
    }
    for (u32 s = 0; s < nsym; s++) {
        u32 f = freq[s];
        if (f) a[counters[GZ_MIN(f, nc - 1)]++] = s | (f << SYM_BITS);
        else lens[s] = 0;
    }
    heap_sort(a + counters[nc - 2], counters[nc - 1] - counters[nc - 2]);
    return used;
}

/* In-place Huffman tree over the sorted leaves (Moffat-Katajainen): non-leaf
 * nodes overwrite a[0..n-2] and keep their parent index in the high bits. */
static void build_tree(u32 *a, u32 n)
{
    const u32 last = n - 1, fmask = ~SYM_MASK;
    u32 i = 0, b = 0, e = 0;
    do {
        u32 nf;
        if (i + 1 <= last && (b == e || (a[i + 1] & fmask) <= (a[b] & fmask))) {
            nf = (a[i] & fmask) + (a[i + 1] & fmask);            /* two leaves */
            i += 2;
        } else if (b + 2 <= e && (i > last || (a[b + 1] & fmask) < (a[i] & fmask))) {
            nf = (a[b] & fmask) + (a[b + 1] & fmask);            /* two non-leaves */
            a[b] = (e << SYM_BITS) | (a[b] & SYM_MASK);
            a[b + 1] = (e << SYM_BITS) | (a[b + 1] & SYM_MASK);
            b += 2;
        } else {
            nf = (a[i] & fmask) + (a[b] & fmask);                /* one of each */
            a[b] = (e << SYM_BITS) | (a[b] & SYM_MASK);
            b++;
            i++;
        }
        a[e] = nf | (a[e] & SYM_MASK);
    } while (++e < last);
}

/* Number of codewords per length, with lengths capped at max_len. */
static void length_counts(u32 *a, u32 root, u32 *cnt, u32 max_len)
{
    for (u32 l = 0; l <= max_len; l++) cnt[l] = 0;
    cnt[1] = 2;
    a[root] &= SYM_MASK;                                         /* depth 0 */
    for (int node = (int)root - 1; node >= 0; node--) {
        u32 parent = a[node] >> SYM_BITS;
        u32 depth = (a[parent] >> SYM_BITS) + 1;
        a[node] = (a[node] & SYM_MASK) | (depth << SYM_BITS);
        if (depth >= max_len) {                                  /* keep the code complete */
            depth = max_len;
            do depth--; while (cnt[depth] == 0);
        }
        cnt[depth]--;
        cnt[depth + 1] += 2;
    }
}

GZ_INLINE u32 rev_bits(u32 c, u32 len)
{
    c = ((c & 0x5555) << 1) | ((c & 0xaaaa) >> 1);
    c = ((c & 0x3333) << 2) | ((c & 0xcccc) >> 2);
    c = ((c & 0x0f0f) << 4) | ((c & 0xf0f0) >> 4);
    c = ((c & 0x00ff) << 8) | ((c & 0xff00) >> 8);
    return c >> (16 - len);
}

/* canonical, bit-reversed codewords from lengths */
static void gen_codewords(const u8 *lens, u32 nsym, u32 max_len, u32 *cw)
{
    u32 cnt[16] = { 0 }, next[16];
    for (u32 s = 0; s < nsym; s++) cnt[lens[s]]++;
    cnt[0] = 0;
    next[0] = next[1] = 0;
    for (u32 l = 2; l <= max_len; l++) next[l] = (next[l - 1] + cnt[l - 1]) << 1;
    for (u32 s = 0; s < nsym; s++) cw[s] = rev_bits(next[lens[s]]++, lens[s]);
}

static void make_code(u32 nsym, u32 max_len, const u32 *freq, u8 *lens, u32 *cw)
{
    u32 *a = cw, cnt[16];
    u32 n = sort_symbols(nsym, freq, lens, a);
    if (n < 2) {
        /* decoders want complete codes: always send two 1-bit codewords */
        u32 sym = n ? (a[0] & SYM_MASK) : 0;
        u32 other = sym ? sym : 1;
        lens[0] = 1; cw[0] = 0;
        lens[other] = 1; cw[other] = 1;
        return;
    }
    build_tree(a, n);
    length_counts(a, n - 2, cnt, max_len);
    /* longest codes go to the least frequent symbols */
    for (u32 i = 0, l = max_len; l >= 1; l--)
        for (u32 c = cnt[l]; c; c--) lens[a[i++] & SYM_MASK] = (u8)l;
    gen_codewords(lens, nsym, max_len, cw);
}

static void make_block_codes(E *e)
{
    make_code(NUM_LITLEN, MAX_LITLEN_LEN, e->freq, e->codes.lens, e->codes.cw);
    make_code(NUM_OFFSET, MAX_OFFSET_LEN, e->freq + NUM_LITLEN, e->codes.lens + NUM_LITLEN,
              e->codes.cw + NUM_LITLEN);
}

/* RLE items for the code lengths of the dynamic header (sym | extra << 5) */
static u32 precode_items(const u8 *lens, u32 n, u32 *freq, u32 *items)
{
    u32 *it = items, start = 0;
    for (u32 i = 0; i < NUM_PRECODE; i++) freq[i] = 0;
    do {
        u8 len = lens[start];
        u32 end = start;
        do end++; while (end != n && lens[end] == len);
        if (len == 0) {
            while (end - start >= 11) {
                u32 x = GZ_MIN(end - start - 11, 0x7f);
                freq[18]++;
                *it++ = 18 | (x << 5);
                start += 11 + x;
            }
            if (end - start >= 3) {
                u32 x = GZ_MIN(end - start - 3, 7);
                freq[17]++;
                *it++ = 17 | (x << 5);
                start += 3 + x;
            }
        } else if (end - start >= 4) {
            freq[len]++;
            *it++ = len;
            start++;
            do {
                u32 x = GZ_MIN(end - start - 3, 3);
                freq[16]++;
                *it++ = 16 | (x << 5);
                start += 3 + x;
            } while (end - start >= 3);
        }
        while (start != end) {
            freq[len]++;
            *it++ = len;
            start++;
        }
    } while (start != n);
    return (u32)(it - items);
}

static void precompute_header(E *e)
{
    u8 *lens = e->codes.lens;
    u32 nl = NUM_LITLEN, no = NUM_OFFSET;
    while (nl > 257 && !lens[nl - 1]) nl--;
    while (no > 1 && !lens[NUM_LITLEN + no - 1]) no--;
    e->n_lit_syms = nl;
    e->n_off_syms = no;
    /* make litlen and offset lengths contiguous for the RLE pass */
    if (nl != NUM_LITLEN) __builtin_memmove(lens + nl, lens + NUM_LITLEN, no);
    e->n_items = precode_items(lens, nl + no, e->pre_freq, e->pre_items);
    if (nl != NUM_LITLEN) {
        __builtin_memmove(lens + NUM_LITLEN, lens + nl, no);
        __builtin_memset(lens + nl, 0, NUM_LITLEN - nl);   /* unused litlen symbols */
    }
    make_code(NUM_PRECODE, MAX_PRE_LEN, e->pre_freq, e->pre_lens, e->pre_cw);
    u32 ne = NUM_PRECODE;
    while (ne > 4 && !e->pre_lens[k_pre_perm[ne - 1]]) ne--;
    e->n_explicit = ne;
}

/* ------------------------------------------------------------------------ */
/* Block output                                                             */

#define ADD_BITS(v, n) do { bitbuf |= (mword)(v) << bitcount; bitcount += (n); } while (0)
#define FLUSH_BITS() do {                                   \
        stw(out, bitbuf);                                   \
        out += bitcount >> 3;                               \
        bitbuf >>= bitcount & ~7u;                          \
        bitcount &= 7;                                      \
    } while (0)

#define WRITE_MATCH(codes_, len_, off_, slot_) do {                                   \
        ADD_BITS(e->len_cw[len_], e->len_bits[len_]);                                 \
        if (!CAN_BUFFER(MAX_LITLEN_LEN + 5 + MAX_OFFSET_LEN + 13)) FLUSH_BITS();      \
        ADD_BITS((codes_)->cw[NUM_LITLEN + (slot_)], (codes_)->lens[NUM_LITLEN + (slot_)]); \
        if (!CAN_BUFFER(MAX_OFFSET_LEN + 13)) FLUSH_BITS();                           \
        ADD_BITS((off_) - k_off_base[slot_], k_off_extra[slot_]);                     \
        FLUSH_BITS();                                                                 \
    } while (0)

/* length 3..258 -> litlen codeword + extra bits as one bit string */
static void full_len_codewords(E *e, const codes_t *c)
{
    for (u32 len = MIN_MATCH; len <= MAX_MATCH; len++) {
        u32 slot = e->len_slot[len], sym = FIRST_LEN_SYM + slot;
        e->len_cw[len] = c->cw[sym] | ((len - k_len_base[slot]) << c->lens[sym]);
        e->len_bits[len] = (u8)(c->lens[sym] + k_len_extra[slot]);
    }
}

/* Write one block of block_len bytes as stored, fixed or dynamic Huffman,
 * whichever is smallest. Symbols come from seqs, or from the optimum path
 * (e->oitem) when seqs is NULL. Codes in e->codes / freqs in e->freq. */
static void flush_block(E *e, const u8 *begin, u32 block_len, const seq_t *seqs, int final)
{
    const u32 *lf = e->freq, *of = e->freq + NUM_LITLEN;
    const u8 *dl = e->codes.lens, *fl = e->fixed.lens;
    u32 dyn = 3, fix = 3, sto = 3, best;
    const codes_t *codes;
    mword bitbuf = e->bitbuf;
    u32 bitcount = e->bitcount;
    u8 *out = e->out;

    precompute_header(e);
    dyn += 5 + 5 + 4 + 3 * e->n_explicit;
    for (u32 s = 0; s < NUM_PRECODE; s++) dyn += e->pre_freq[s] * (e->pre_lens[s] + k_pre_extra[s]);
    for (u32 s = 0; s < 257; s++) {
        dyn += lf[s] * dl[s];
        fix += lf[s] * fl[s];
    }
    for (u32 s = 0; s < 29; s++) {
        u32 f = lf[FIRST_LEN_SYM + s], x = k_len_extra[s];
        dyn += f * (dl[FIRST_LEN_SYM + s] + x);
        fix += f * (fl[FIRST_LEN_SYM + s] + x);
    }
    for (u32 s = 0; s < 30; s++) {
        dyn += of[s] * (dl[NUM_LITLEN + s] + k_off_extra[s]);
        fix += of[s] * (5 + k_off_extra[s]);
    }
    sto += (-(bitcount + 3) & 7) + 32 + 40 * ((block_len + 65534) / 65535 - 1) + 8 * block_len;
    best = GZ_MIN(dyn, GZ_MIN(fix, sto));

    if (best == sto) {
        const u8 *p = begin, *end = begin + block_len;
        do {
            u32 n = 65535, bf = 0;
            if ((size_t)(end - p) <= 65535) { n = (u32)(end - p); bf = (u32)final; }
            *out++ = (u8)((bf << bitcount) | (u32)bitbuf);
            if (bitcount > 5) *out++ = 0;
            bitbuf = 0;
            bitcount = 0;
            wr16(out, (u16)n);
            wr16(out + 2, (u16)~n);
            out += 4;
            __builtin_memcpy(out, p, n);
            out += n;
            p += n;
        } while (p != end);
        goto done;
    }

    if (best == fix) {
        codes = &e->fixed;
        ADD_BITS(final, 1);
        ADD_BITS(1, 2);
        FLUSH_BITS();
    } else {
        codes = &e->codes;
        ADD_BITS(final, 1);
        ADD_BITS(2, 2);
        ADD_BITS(e->n_lit_syms - 257, 5);
        ADD_BITS(e->n_off_syms - 1, 5);
        ADD_BITS(e->n_explicit - 4, 4);
        FLUSH_BITS();
        for (u32 i = 0; i < e->n_explicit; i++) {
            ADD_BITS(e->pre_lens[k_pre_perm[i]], 3);
            FLUSH_BITS();
        }
        for (u32 i = 0; i < e->n_items; i++) {
            u32 item = e->pre_items[i], sym = item & 0x1f;
            ADD_BITS(e->pre_cw[sym], e->pre_lens[sym]);
            ADD_BITS(item >> 5, k_pre_extra[sym]);
            FLUSH_BITS();
        }
    }

    full_len_codewords(e, codes);
    if (!seqs) {
        const u32 *it = e->oitem, *end = e->oitem + block_len;
        do {
            u32 len = *it & OPT_LEN_MASK, off = *it >> OPT_OFF_SHIFT;
            if (len == 1) {
                ADD_BITS(codes->cw[off], codes->lens[off]);
                FLUSH_BITS();
            } else {
                u32 slot = e->off_slot_full[off];
                WRITE_MATCH(codes, len, off, slot);
            }
            it += len;
        } while (it != end);
    } else {
        const u8 *in = begin;
        for (const seq_t *s = seqs;; s++) {
            u32 run = s->litrun_len & SEQ_LIT_MASK, len = s->litrun_len >> SEQ_LEN_SHIFT;
            if (CAN_BUFFER(4 * MAX_LITLEN_LEN)) {
                for (; run >= 4; run -= 4) {
                    u32 a = in[0], b = in[1], c = in[2], d = in[3];
                    ADD_BITS(codes->cw[a], codes->lens[a]);
                    ADD_BITS(codes->cw[b], codes->lens[b]);
                    ADD_BITS(codes->cw[c], codes->lens[c]);
                    ADD_BITS(codes->cw[d], codes->lens[d]);
                    FLUSH_BITS();
                    in += 4;
                }
                if (run) {
                    u32 a = *in++;
                    ADD_BITS(codes->cw[a], codes->lens[a]);
                    if (--run) {
                        a = *in++;
                        ADD_BITS(codes->cw[a], codes->lens[a]);
                        if (--run) {
                            a = *in++;
                            ADD_BITS(codes->cw[a], codes->lens[a]);
                        }
                    }
                    FLUSH_BITS();
                }
            } else {
                for (; run; run--) {
                    u32 a = *in++;
                    ADD_BITS(codes->cw[a], codes->lens[a]);
                    FLUSH_BITS();
                }
            }
            if (!len) break;
            WRITE_MATCH(codes, len, s->offset, s->slot);
            in += len;
        }
    }
    ADD_BITS(codes->cw[EOB], codes->lens[EOB]);
    FLUSH_BITS();
done:
    e->bitbuf = bitbuf;
    e->bitcount = bitcount;
    e->out = out;
}

/* ------------------------------------------------------------------------ */
/* Block splitting statistics                                               */

static void split_init(split_t *s)
{
    for (int i = 0; i < NUM_OBS; i++) s->new_obs[i] = s->obs[i] = 0;
    s->num_new = s->num = 0;
}

/* literal: top 2 bits + low bit; match: short / long */
GZ_INLINE void observe_lit(split_t *s, u32 lit) { s->new_obs[((lit >> 5) & 6) | (lit & 1)]++; s->num_new++; }
GZ_INLINE void observe_match(split_t *s, u32 len) { s->new_obs[8 + (len >= 9)]++; s->num_new++; }

static void split_merge(split_t *s)
{
    for (int i = 0; i < NUM_OBS; i++) {
        s->obs[i] += s->new_obs[i];
        s->new_obs[i] = 0;
    }
    s->num += s->num_new;
    s->num_new = 0;
}

/* End the block when the recent observations differ enough from the block so far. */
static int split_check(split_t *s, u32 block_len)
{
    if (s->num > 0) {
        /* compare probabilities scaled by num * num_new (no divisions) */
        u64 delta = 0, cutoff;
        u32 n = s->num + s->num_new;
        for (int i = 0; i < NUM_OBS; i++) {
            u64 expect = (u64)s->obs[i] * s->num_new, actual = (u64)s->new_obs[i] * s->num;
            delta += actual > expect ? actual - expect : expect - actual;
        }
        cutoff = (u64)(s->num_new * 200 / 512) * s->num;   /* sum of |p - q| >= 200/512 */
        if (block_len < 10000 && n < 8192) cutoff += cutoff * (8192 - n) / 8192;
        if (delta + (u64)(block_len / 4096) * s->num >= cutoff) return 1;
    }
    split_merge(s);
    return 0;
}

GZ_INLINE int split_ready(const split_t *s, const u8 *begin, const u8 *next, const u8 *end)
{
    return s->num_new >= OBS_PER_CHECK && next - begin >= MIN_BLOCK && end - next >= MIN_BLOCK;
}

GZ_INLINE int should_end_block(split_t *s, const u8 *begin, const u8 *next, const u8 *end)
{
    return split_ready(s, begin, next, end) && split_check(s, (u32)(next - begin));
}

/* ------------------------------------------------------------------------ */
/* Sequence helpers (greedy / lazy)                                         */

static void begin_block(E *e, seq_t *seq)
{
    __builtin_memset(e->freq, 0, sizeof(e->freq));
    seq->litrun_len = 0;
}

GZ_INLINE void choose_lit(E *e, u32 lit, int stats, seq_t *seq)
{
    e->freq[lit]++;
    if (stats) observe_lit(&e->split, lit);
    seq->litrun_len++;
}

GZ_INLINE void choose_match(E *e, u32 len, u32 off, int stats, seq_t **seq_p)
{
    seq_t *seq = *seq_p;
    u32 slot = off_slot(e, off);
    e->freq[FIRST_LEN_SYM + e->len_slot[len]]++;
    e->freq[NUM_LITLEN + slot]++;
    if (stats) observe_match(&e->split, len);
    seq->litrun_len |= len << SEQ_LEN_SHIFT;
    seq->offset = (u16)off;
    seq->slot = (u16)slot;
    seq++;
    seq->litrun_len = 0;
    *seq_p = seq;
}

static void finish_block(E *e, const u8 *begin, u32 len, int final)
{
    e->freq[EOB]++;
    make_block_codes(e);
    flush_block(e, begin, len, e->seqs, final);
}

/* Minimum match length for greedy/lazy parsing from the number of distinct
 * literals: with few literals, literals are cheap and short matches lose. */
static u32 min_len_for(u32 used_lits, u32 depth)
{
    static const u8 tab[80] = {
        9, 9, 9, 9, 9, 9, 8, 8, 7, 7, 6, 6, 6, 6, 6, 6,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4
    };
    if (used_lits >= 80) return 3;
    u32 m = tab[used_lits];
    if (depth < 16) {
        if (depth < 5) m = GZ_MIN(m, 4);
        else if (depth < 10) m = GZ_MIN(m, 5);
        else m = GZ_MIN(m, 7);
    }
    return m;
}

static u32 calc_min_len(const u8 *p, size_t n, u32 depth)
{
    u8 used[256];
    u32 cnt = 0;
    if (n < 512) return MIN_MATCH;
    if (n > 4096) n = 4096;
    __builtin_memset(used, 0, sizeof(used));
    for (size_t i = 0; i < n; i++) used[p[i]] = 1;
    for (u32 i = 0; i < 256; i++) cnt += used[i];
    return min_len_for(cnt, depth);
}

static u32 recalc_min_len(const E *e, u32 depth)
{
    u32 total = 0, cnt = 0, cutoff;
    for (u32 i = 0; i < 256; i++) total += e->freq[i];
    cutoff = total >> 10;
    for (u32 i = 0; i < 256; i++) cnt += e->freq[i] > cutoff;
    return min_len_for(cnt, depth);
}

GZ_INLINE const u8 *max_block_end(const u8 *begin, const u8 *end, size_t soft)
{
    return (size_t)(end - begin) < soft + MIN_BLOCK ? end : begin + soft;
}

GZ_INLINE void adjust_lens(u32 *max_len, u32 *nice_len, size_t remaining)
{
    if (GZ_UNLIKELY(remaining < MAX_MATCH)) {
        *max_len = (u32)remaining;
        *nice_len = GZ_MIN(*nice_len, *max_len);
    }
}

/* ------------------------------------------------------------------------ */
/* Levels 1-6: hash chains (3-byte table + 4-byte chains)                   */

GZ_INLINE u32 hc_longest(E *e, const u8 **in_base_p, const u8 *in_next, u32 best_len,
                         u32 max_len, u32 nice_len, u32 depth, u32 *next_hashes, u32 *off_ret)
{
    mf_pos *h3t = e->hash3, *h4t = e->hash4, *next = e->chain;
    ptrdiff_t cur = in_next - *in_base_p;
    if (GZ_UNLIKELY(cur >= MF_WIN)) cur = mf_advance(e, in_base_p, cur);
    const u8 *base = *in_base_p, *best = in_next, *m;
    i32 cutoff = (i32)cur - MF_WIN, node3, node4;
    u32 h3, h4, seq4, len;

    if (GZ_UNLIKELY(max_len < MF_REQ)) goto out;
    h3 = next_hashes[0];
    h4 = next_hashes[1];
    node3 = h3t[h3];
    node4 = h4t[h4];
    h3t[h3] = (mf_pos)cur;
    h4t[h4] = (mf_pos)cur;
    next[cur] = (mf_pos)node4;
    {
        u32 nseq = rd32(in_next + 1);
        next_hashes[0] = lz_hash(nseq & 0xffffff, HC3_ORDER);
        next_hashes[1] = lz_hash(nseq, HC4_ORDER);
        PREFETCHW(&h3t[next_hashes[0]]);
        PREFETCHW(&h4t[next_hashes[1]]);
    }

    if (best_len < 4) {
        if (node3 <= cutoff) goto out;
        seq4 = rd32(in_next);
        if (best_len < 3) {
            m = base + node3;
            if (((rd32(m) ^ seq4) & 0xffffff) == 0) { best_len = 3; best = m; }
        }
        if (node4 <= cutoff) goto out;
        for (;;) {
            m = base + node4;
            if (rd32(m) == seq4) break;
            node4 = next[node4 & (MF_WIN - 1)];
            if (node4 <= cutoff || !--depth) goto out;
        }
        best = m;
        best_len = lz_extend(in_next, m, 4, max_len);
        if (best_len >= nice_len) goto out;
        node4 = next[node4 & (MF_WIN - 1)];
        if (node4 <= cutoff || !--depth) goto out;
    } else if (node4 <= cutoff || best_len >= nice_len) {
        goto out;
    }

    for (;;) {
        for (;;) {
            m = base + node4;
            /* the byte that would make the match longer decides first */
            if (rd32(m + best_len - 3) == rd32(in_next + best_len - 3) && rd32(m) == rd32(in_next))
                break;
            node4 = next[node4 & (MF_WIN - 1)];
            if (node4 <= cutoff || !--depth) goto out;
        }
        len = lz_extend(in_next, m, 4, max_len);
        if (len > best_len) {
            best_len = len;
            best = m;
            if (best_len >= nice_len) goto out;
        }
        node4 = next[node4 & (MF_WIN - 1)];
        if (node4 <= cutoff || !--depth) goto out;
    }
out:
    *off_ret = (u32)(in_next - best);
    return best_len;
}

GZ_INLINE void hc_skip(E *e, const u8 **in_base_p, const u8 *in_next, const u8 *in_end,
                       u32 count, u32 *next_hashes)
{
    mf_pos *h3t = e->hash3, *h4t = e->hash4, *next = e->chain;
    if ((size_t)count + MF_REQ > (size_t)(in_end - in_next)) return;
    ptrdiff_t cur = in_next - *in_base_p;
    u32 h3 = next_hashes[0], h4 = next_hashes[1];
    do {
        if (GZ_UNLIKELY(cur >= MF_WIN)) cur = mf_advance(e, in_base_p, cur);
        h3t[h3] = (mf_pos)cur;
        next[cur] = h4t[h4];
        h4t[h4] = (mf_pos)cur;
        u32 nseq = rd32(++in_next);
        h3 = lz_hash(nseq & 0xffffff, HC3_ORDER);
        h4 = lz_hash(nseq, HC4_ORDER);
        cur++;
    } while (--count);
    PREFETCHW(&h3t[h3]);
    PREFETCHW(&h4t[h4]);
    next_hashes[0] = h3;
    next_hashes[1] = h4;
}

/* Is a length-3 match cheaper than its three literals? Estimated with the code
 * lengths of the previous block; for the first block: offset <= far. */
GZ_INLINE u32 sym_bits(u32 len) { return len ? len : 11; }
static int len3_ok(const E *e, const u8 *p, u32 off, u32 far)
{
    if (off <= 256) return 1;
    if (!e->have_codes) return off <= far;
    const u8 *l = e->codes.lens;
    u32 slot = off_slot(e, off);
    u32 mc = sym_bits(l[FIRST_LEN_SYM]) + sym_bits(l[NUM_LITLEN + slot]) + k_off_extra[slot];
    return mc < sym_bits(l[p[0]]) + sym_bits(l[p[1]]) + sym_bits(l[p[2]]);
}

static void block_greedy(E *e)
{
    const u8 *in_next = e->in_next, *in_end = e->in_end, *in_base = e->in_base;
    const u8 *begin = in_next, *max_end = max_block_end(in_next, in_end, SOFT_MAX_BLOCK);
    u32 max_len = MAX_MATCH, nice_len = GZ_MIN(e->nice, MAX_MATCH), depth = e->depth;
    u32 nh[2] = { e->next_hashes[0], e->next_hashes[1] };
    seq_t *seq = e->seqs, *seq_end = e->seqs + SEQ_STORE;
    u32 min_len;

    split_init(&e->split);
    begin_block(e, seq);
    min_len = calc_min_len(in_next, (size_t)(max_end - in_next), depth);
    do {
        u32 len, off;
        adjust_lens(&max_len, &nice_len, (size_t)(in_end - in_next));
        len = hc_longest(e, &in_base, in_next, min_len - 1, max_len, nice_len, depth, nh, &off);
        if (len >= min_len && (len > MIN_MATCH || len3_ok(e, in_next, off, 4096))) {
            choose_match(e, len, off, 1, &seq);
            hc_skip(e, &in_base, in_next + 1, in_end, len - 1, nh);
            in_next += len;
        } else {
            choose_lit(e, *in_next++, 1, seq);
        }
    } while (in_next < max_end && seq < seq_end && !should_end_block(&e->split, begin, in_next, in_end));

    finish_block(e, begin, (u32)(in_next - begin), in_next == in_end && e->eof);
    e->in_next = e->blk = in_next;
    e->in_base = in_base;
    e->next_hashes[0] = nh[0];
    e->next_hashes[1] = nh[1];
}

static void block_lazy(E *e)
{
    const u8 *in_next = e->in_next, *in_end = e->in_end, *in_base = e->in_base;
    const u8 *begin = in_next, *max_end = max_block_end(in_next, in_end, SOFT_MAX_BLOCK);
    const u8 *next_recalc = in_next + GZ_MIN((size_t)(in_end - in_next), 10000);
    u32 max_len = MAX_MATCH, nice_len = GZ_MIN(e->nice, MAX_MATCH), depth = e->depth;
    u32 nh[2] = { e->next_hashes[0], e->next_hashes[1] };
    seq_t *seq = e->seqs, *seq_end = e->seqs + SEQ_STORE;
    u32 min_len;

    split_init(&e->split);
    begin_block(e, seq);
    min_len = calc_min_len(in_next, (size_t)(max_end - in_next), depth);
    do {
        u32 cur_len, cur_off, next_len, next_off;

        if (in_next >= next_recalc) {
            min_len = recalc_min_len(e, depth);
            next_recalc += GZ_MIN((size_t)(in_end - next_recalc), (size_t)(in_next - begin));
        }
        adjust_lens(&max_len, &nice_len, (size_t)(in_end - in_next));
        cur_len = hc_longest(e, &in_base, in_next, min_len - 1, max_len, nice_len, depth, nh, &cur_off);
        if (cur_len < min_len || (cur_len == MIN_MATCH && !len3_ok(e, in_next, cur_off, 8192))) {
            choose_lit(e, *in_next++, 1, seq);
            continue;
        }
        in_next++;
have_cur:
        if (cur_len >= nice_len) {
            choose_match(e, cur_len, cur_off, 1, &seq);
            hc_skip(e, &in_base, in_next, in_end, cur_len - 1, nh);
            in_next += cur_len - 1;
            continue;
        }
        /* a better match one position later? (gain in length vs. offset cost) */
        adjust_lens(&max_len, &nice_len, (size_t)(in_end - in_next));
        next_len = hc_longest(e, &in_base, in_next++, cur_len - 1, max_len, nice_len, depth >> 1,
                              nh, &next_off);
        if (next_len >= cur_len &&
            4 * (int)(next_len - cur_len) + ((int)bsr32(cur_off) - (int)bsr32(next_off)) > 2) {
            choose_lit(e, in_next[-2], 1, seq);
            cur_len = next_len;
            cur_off = next_off;
            goto have_cur;
        }
        choose_match(e, cur_len, cur_off, 1, &seq);
        hc_skip(e, &in_base, in_next, in_end, cur_len - 2, nh);
        in_next += cur_len - 2;
    } while (in_next < max_end && seq < seq_end && !should_end_block(&e->split, begin, in_next, in_end));

    finish_block(e, begin, (u32)(in_next - begin), in_next == in_end && e->eof);
    e->in_next = e->blk = in_next;
    e->in_base = in_base;
    e->next_hashes[0] = nh[0];
    e->next_hashes[1] = nh[1];
}


/* ------------------------------------------------------------------------ */
/* Levels 7-9: binary trees + near-optimal parsing                          */

#define BT_LEFT(e, n)  (&(e)->chain[2 * ((n) & (MF_WIN - 1))])
#define BT_RIGHT(e, n) (&(e)->chain[2 * ((n) & (MF_WIN - 1)) + 1])

/* Insert the current position into its tree; when record, append the matches
 * found (strictly increasing lengths) to mp. Requires max_len >= MF_REQ and
 * nice_len <= max_len. */
GZ_INLINE lz_match *bt_advance(E *e, const u8 **in_base_p, const u8 *in_next, u32 max_len,
                               u32 nice_len, u32 depth, u32 *next_hashes, lz_match *mp, int record)
{
    mf_pos *h3t = e->hash3, *h4t = e->hash4;
    ptrdiff_t cur = in_next - *in_base_p;
    if (GZ_UNLIKELY(cur >= MF_WIN)) cur = mf_advance(e, in_base_p, cur);
    const u8 *base = *in_base_p, *m;
    i32 cutoff = (i32)cur - MF_WIN, node, node2;
    mf_pos *lt, *gt;
    u32 h3 = next_hashes[0], h4 = next_hashes[1], best_lt = 0, best_gt = 0, len = 0, best_len = 3;
    {
        u32 nseq = rd32(in_next + 1);
        next_hashes[0] = lz_hash(nseq & 0xffffff, BT3_ORDER);
        next_hashes[1] = lz_hash(nseq, BT4_ORDER);
        PREFETCHW(&h3t[2 * next_hashes[0]]);
        PREFETCHW(&h4t[next_hashes[1]]);
    }
    node = h3t[2 * h3];
    node2 = h3t[2 * h3 + 1];
    h3t[2 * h3] = (mf_pos)cur;
    h3t[2 * h3 + 1] = (mf_pos)node;
    if (record && node > cutoff) {
        u32 seq3 = rd32(in_next) & 0xffffff;
        if (seq3 == (rd32(base + node) & 0xffffff)) {
            mp->length = 3;
            mp->offset = (u16)(in_next - (base + node));
            mp++;
        } else if (node2 > cutoff && seq3 == (rd32(base + node2) & 0xffffff)) {
            mp->length = 3;
            mp->offset = (u16)(in_next - (base + node2));
            mp++;
        }
    }

    node = h4t[h4];
    h4t[h4] = (mf_pos)cur;
    /* the new node becomes the root: older strings below it are split into its
     * left (smaller) and right (larger) subtrees while descending */
    lt = BT_LEFT(e, cur);
    gt = BT_RIGHT(e, cur);
    if (node <= cutoff) {
        *lt = *gt = MF_INIT;
        return mp;
    }
    for (;;) {
        m = base + node;
        if (m[len] == in_next[len]) {
            len = lz_extend(in_next, m, len + 1, max_len);
            if (!record || len > best_len) {
                if (record) {
                    best_len = len;
                    mp->length = (u16)len;
                    mp->offset = (u16)(in_next - m);
                    mp++;
                }
                if (len >= nice_len) {
                    *lt = *BT_LEFT(e, node);
                    *gt = *BT_RIGHT(e, node);
                    return mp;
                }
            }
        }
        if (m[len] < in_next[len]) {
            *lt = (mf_pos)node;
            lt = BT_RIGHT(e, node);
            node = *lt;
            best_lt = len;
            if (best_gt < len) len = best_gt;
        } else {
            *gt = (mf_pos)node;
            gt = BT_LEFT(e, node);
            node = *gt;
            best_gt = len;
            if (best_lt < len) len = best_lt;
        }
        if (node <= cutoff || !--depth) {
            *lt = *gt = MF_INIT;
            return mp;
        }
    }
}

static void opt_init_stats(E *e)
{
    split_init(&e->split);
    __builtin_memset(e->mlen_freq, 0, sizeof(e->mlen_freq));
    __builtin_memset(e->new_mlen_freq, 0, sizeof(e->new_mlen_freq));
}

static void opt_merge_stats(E *e)
{
    split_merge(&e->split);
    for (u32 i = 0; i <= MAX_MATCH; i++) {
        e->mlen_freq[i] += e->new_mlen_freq[i];
        e->new_mlen_freq[i] = 0;
    }
}

static void opt_save_stats(E *e)
{
    for (int i = 0; i < NUM_OBS; i++) e->prev_obs[i] = e->split.obs[i];
    e->prev_num_obs = e->split.num;
}

static void opt_clear_old_stats(E *e)
{
    for (int i = 0; i < NUM_OBS; i++) e->split.obs[i] = 0;
    e->split.num = 0;
    __builtin_memset(e->mlen_freq, 0, sizeof(e->mlen_freq));
}

static void set_costs_from_codes(E *e, const u8 *lens)
{
    for (u32 i = 0; i < 256; i++)
        e->costs.lit[i] = (lens[i] ? lens[i] : LIT_NOSTAT_BITS) * BIT_COST;
    for (u32 i = MIN_MATCH; i <= MAX_MATCH; i++) {
        u32 slot = e->len_slot[i], l = lens[FIRST_LEN_SYM + slot];
        e->costs.len[i] = ((l ? l : LEN_NOSTAT_BITS) + k_len_extra[slot]) * BIT_COST;
    }
    for (u32 i = 0; i < 30; i++) {
        u32 l = lens[NUM_LITLEN + i];
        e->costs.off[i] = ((l ? l : OFF_NOSTAT_BITS) + k_off_extra[i]) * BIT_COST;
    }
}

GZ_INLINE u32 default_len_cost(const E *e, u32 len, u32 len_sym_cost)
{
    return len_sym_cost + k_len_extra[e->len_slot[len]] * BIT_COST;
}

/* all 30 offset slots assumed equally likely: log2(30) ~ 4.907 bits */
GZ_INLINE u32 default_off_cost(u32 slot) { return 4 * BIT_COST + (907 * BIT_COST) / 1000 + k_off_extra[slot] * BIT_COST; }

/* Rough literal / length symbol costs for the first pass, from the number of
 * distinct literals and the greedy match statistics gathered while matching. */
static void default_litlen_costs(E *e, const u8 *block, u32 n, u32 *lit_cost, u32 *len_sym_cost)
{
    u32 *lf = e->freq, used = 0, lit_freq = n, match_freq = 0, cutoff = n >> 11, i;
    __builtin_memset(lf, 0, 256 * sizeof(u32));
    for (i = 0; i < n; i++) lf[block[i]]++;
    for (i = 0; i < 256; i++) used += lf[i] > cutoff;
    if (!used) used = 1;
    for (i = min_len_for(used, e->depth); i <= MAX_MATCH; i++) {
        match_freq += e->mlen_freq[i];
        lit_freq -= i * e->mlen_freq[i];
    }
    if ((i32)lit_freq < 0) lit_freq = 0;
    i = match_freq > lit_freq ? 2 : match_freq * 4 > lit_freq ? 1 : 0;
    *lit_cost = e->lit_cost_tab[i][used];
    *len_sym_cost = e->len_sym_cost[i];
}

static void set_default_costs(E *e, u32 lit_cost, u32 len_sym_cost)
{
    for (u32 i = 0; i < 256; i++) e->costs.lit[i] = lit_cost;
    for (u32 i = MIN_MATCH; i <= MAX_MATCH; i++) e->costs.len[i] = default_len_cost(e, i, len_sym_cost);
    for (u32 i = 0; i < 30; i++) e->costs.off[i] = default_off_cost(i);
}

GZ_INLINE void adjust_cost(u32 *c, u32 def, int amount)
{
    if (amount == 0) *c = (def + 3 * *c) / 4;
    else if (amount == 1) *c = (def + *c) / 2;
    else if (amount == 2) *c = (5 * def + 3 * *c) / 8;
    else *c = (3 * def + *c) / 4;
}

/* Blend the previous block's costs with the defaults, depending on how much
 * the block statistics changed. */
static void adjust_costs(E *e, u32 lit_cost, u32 len_sym_cost)
{
    u64 delta = 0, cutoff;
    int amount;
    for (int i = 0; i < NUM_OBS; i++) {
        u64 prev = (u64)e->prev_obs[i] * e->split.num, cur = (u64)e->split.obs[i] * e->prev_num_obs;
        delta += prev > cur ? prev - cur : cur - prev;
    }
    cutoff = ((u64)e->prev_num_obs * e->split.num * 200) / 512;
    if (delta > 3 * cutoff) {
        set_default_costs(e, lit_cost, len_sym_cost);
        return;
    }
    amount = 4 * delta > 9 * cutoff ? 3 : 2 * delta > 3 * cutoff ? 2 : 2 * delta > cutoff ? 1 : 0;
    for (u32 i = 0; i < 256; i++) adjust_cost(&e->costs.lit[i], lit_cost, amount);
    for (u32 i = MIN_MATCH; i <= MAX_MATCH; i++)
        adjust_cost(&e->costs.len[i], default_len_cost(e, i, len_sym_cost), amount);
    for (u32 i = 0; i < 30; i++) adjust_cost(&e->costs.off[i], default_off_cost(i), amount);
}

static void tally_path(E *e, u32 block_len)
{
    const u32 *it = e->oitem, *end = e->oitem + block_len;
    __builtin_memset(e->freq, 0, sizeof(e->freq));
    do {
        u32 len = *it & OPT_LEN_MASK, off = *it >> OPT_OFF_SHIFT;
        if (len == 1) {
            e->freq[off]++;
        } else {
            e->freq[FIRST_LEN_SYM + e->len_slot[len]]++;
            e->freq[NUM_LITLEN + e->off_slot_full[off]]++;
        }
        it += len;
    } while (it != end);
    e->freq[EOB]++;
}

/* Backwards dynamic programming over the cached matches: cheapest way from each
 * position to the block end under e->costs. For each length only the smallest
 * offset that reaches it is considered. Then builds e->codes for the path. */
static void min_cost_path(E *e, u32 block_len, const lz_match *cp)
{
    const costs_t *c = &e->costs;
    const u8 *slot_of = e->off_slot_full;
    const u32 *lc = c->len;
    u32 *cost = e->ocost + block_len, *item = e->oitem + block_len;
    *cost = 0;
    do {
        u32 nm, lit, best, bi;
        cost--;
        item--;
        cp--;
        nm = cp->length;
        lit = cp->offset;
        best = c->lit[lit] + cost[1];
        bi = (lit << OPT_OFF_SHIFT) | 1;
        if (nm) {
            /* two independent min chains (lengths in increasing order in each) halve
             * the cmov dependency chain; ties resolve to the shorter length */
            const lz_match *m = cp - nm;
            u32 len = MIN_MATCH, best1 = 0x7fffffffu, bi1 = 0;
            for (; m != cp; m++) {
                u32 off = m->offset, oc = c->off[slot_of[off]], mlen = m->length;
                u32 tag = off << OPT_OFF_SHIFT;
                for (; len < mlen; len += 2) {
                    u32 x0 = oc + lc[len] + cost[len], x1 = oc + lc[len + 1] + cost[len + 1];
                    bi = x0 < best ? (len | tag) : bi;
                    best = x0 < best ? x0 : best;
                    bi1 = x1 < best1 ? ((len + 1) | tag) : bi1;
                    best1 = x1 < best1 ? x1 : best1;
                }
                if (len == mlen) {
                    u32 x0 = oc + lc[len] + cost[len];
                    bi = x0 < best ? (len | tag) : bi;
                    best = x0 < best ? x0 : best;
                    len++;
                }
            }
            if (best1 < best || (best1 == best && (bi1 & OPT_LEN_MASK) < (bi & OPT_LEN_MASK))) {
                best = best1;
                bi = bi1;
            }
            cp -= nm;
        }
        *cost = best;
        *item = bi;
    } while (cost != e->ocost);
    tally_path(e, block_len);
    make_block_codes(e);
}

/* exact bits of the block with the current codes (dynamic block, sans EOB tally) */
static u32 true_cost(E *e)
{
    const u32 *f = e->freq;
    const u8 *l = e->codes.lens;
    u32 cost, s;
    precompute_header(e);
    cost = 5 + 5 + 4 + 3 * e->n_explicit;
    for (s = 0; s < NUM_PRECODE; s++) cost += e->pre_freq[s] * (e->pre_lens[s] + k_pre_extra[s]);
    for (s = 0; s < FIRST_LEN_SYM; s++) cost += f[s] * l[s];
    for (s = 0; s < 29; s++) cost += f[FIRST_LEN_SYM + s] * (l[FIRST_LEN_SYM + s] + k_len_extra[s]);
    for (s = 0; s < 30; s++) cost += f[NUM_LITLEN + s] * (l[NUM_LITLEN + s] + k_off_extra[s]);
    return cost;
}

static void all_literals(E *e, const u8 *block, u32 n)
{
    __builtin_memset(e->freq, 0, sizeof(e->freq));
    for (u32 i = 0; i < n; i++) e->freq[block[i]]++;
    e->freq[EOB]++;
    make_block_codes(e);
}

static void optimize_and_flush(E *e, const u8 *begin, u32 block_len, const lz_match *cp, int first,
                               int final)
{
    u32 passes = e->passes, best_cost = 0xffffffffu, cost = 0, lits_cost, static_cost = 0xffffffffu;
    seq_t lit_seq = { 0, 0, 0 };
    const seq_t *seqs = 0;

    /* sometimes no matches at all is best */
    all_literals(e, begin, block_len);
    lits_cost = true_cost(e);

    /* matches running past the block end must not be chosen */
    for (u32 i = block_len; i <= block_len - 1 + MAX_MATCH; i++) e->ocost[i] = COST_INF;

    /* small blocks: the best parse for the fixed code may win */
    if (block_len <= e->static_opt) {
        e->costs_saved = e->costs;
        set_costs_from_codes(e, e->fixed.lens);
        min_cost_path(e, block_len, cp);
        static_cost = e->ocost[0] / BIT_COST + 7;
        e->costs = e->costs_saved;
    }

    {
        u32 lc, lsc;
        default_litlen_costs(e, begin, block_len, &lc, &lsc);
        if (first) set_default_costs(e, lc, lsc);
        else adjust_costs(e, lc, lsc);
    }

    do {
        min_cost_path(e, block_len, cp);
        cost = true_cost(e);
        if (cost + e->min_impr > best_cost) break;
        best_cost = cost;
        e->costs_saved = e->costs;
        set_costs_from_codes(e, e->codes.lens);
    } while (--passes);

    e->prev_only_lits = 0;
    if (GZ_MIN(lits_cost, static_cost) < best_cost) {
        if (lits_cost < static_cost) {
            all_literals(e, begin, block_len);
            set_costs_from_codes(e, e->codes.lens);
            lit_seq.litrun_len = block_len;
            seqs = &lit_seq;
            e->prev_only_lits = 1;
        } else {
            set_costs_from_codes(e, e->fixed.lens);
            min_cost_path(e, block_len, cp);
        }
    } else if (cost >= best_cost + e->min_impr) {
        /* an earlier pass was clearly better: redo its path */
        e->costs = e->costs_saved;
        min_cost_path(e, block_len, cp);
        set_costs_from_codes(e, e->codes.lens);
    }
    flush_block(e, begin, block_len, seqs, final);
}

static void block_opt(E *e)
{
    const u8 *in_next = e->in_next, *in_end = e->in_end, *in_base = e->in_base;
    const u8 *begin = e->blk, *max_end = max_block_end(begin, in_end, SOFT_MAX_BLOCK);
    const u8 *prev_check = 0, *next_obs = in_next;
    u32 max_len = MAX_MATCH, nice_len = GZ_MIN(e->nice, MAX_MATCH), depth = e->depth;
    u32 nh[2] = { e->next_hashes[0], e->next_hashes[1] };
    lz_match *cp = e->cache + e->cache_len, *cache_limit = e->cache + MATCH_CACHE;
    int change = 0, first = e->first_block;
    /* min_len only steers the statistics; the parse itself weighs every match */
    u32 min_len = e->prev_only_lits ? MAX_MATCH + 1
                                    : calc_min_len(begin, (size_t)(max_end - begin), depth);

    /* 1. find and cache the matches of every position until the block should end */
    while (in_next < max_end) {
        lz_match *matches = cp;
        u32 best_len = 0;
        adjust_lens(&max_len, &nice_len, (size_t)(in_end - in_next));
        if (GZ_LIKELY(max_len >= MF_REQ)) {
            cp = bt_advance(e, &in_base, in_next, max_len, nice_len, depth, nh, matches, 1);
            if (cp > matches) best_len = cp[-1].length;
        }
        if (in_next >= next_obs) {
            if (best_len >= min_len) {
                observe_match(&e->split, best_len);
                next_obs = in_next + best_len;
                e->new_mlen_freq[best_len]++;
            } else {
                observe_lit(&e->split, *in_next);
                next_obs = in_next + 1;
            }
        }
        cp->length = (u16)(cp - matches);           /* header: match count, literal */
        cp->offset = *in_next++;
        cp++;
        /* after a match >= nice_len, insert but do not search the positions inside */
        if (best_len >= MIN_MATCH && best_len >= nice_len) {
            u32 n = best_len - 1;
            do {
                adjust_lens(&max_len, &nice_len, (size_t)(in_end - in_next));
                /* only reaching nice_len matters when not recording */
                if (max_len >= MF_REQ) bt_advance(e, &in_base, in_next, nice_len, nice_len, depth, nh, 0, 0);
                cp->length = 0;
                cp->offset = *in_next++;
                cp++;
            } while (--n);
        }
        if (in_next >= max_end || cp >= cache_limit) break;
        if (!split_ready(&e->split, begin, in_next, in_end)) continue;
        if (split_check(&e->split, (u32)(in_next - begin))) {
            change = 1;
            break;
        }
        opt_merge_stats(e);
        prev_check = in_next;
    }

    /* 2. parse and write the block */
    if (change && prev_check) {
        /* the data changed in the last chunk: end the block before it and keep
         * the chunk's matches and statistics for the next block */
        lz_match *orig = cp;
        u32 block_len = (u32)(prev_check - begin), rewind = (u32)(in_next - prev_check);
        do {
            cp--;
            cp -= cp->length;
        } while (--rewind);
        optimize_and_flush(e, begin, block_len, cp, first, 0);
        e->cache_len = (u32)(orig - cp);
        __builtin_memmove(e->cache, cp, e->cache_len * sizeof(lz_match));
        opt_save_stats(e);
        opt_clear_old_stats(e);
        e->blk = prev_check;
    } else {
        u32 block_len = (u32)(in_next - begin);
        opt_merge_stats(e);
        optimize_and_flush(e, begin, block_len, cp, first, in_next == in_end && e->eof);
        e->cache_len = 0;
        opt_save_stats(e);
        opt_init_stats(e);
        e->blk = in_next;
    }
    e->first_block = 0;
    e->in_next = in_next;
    e->in_base = in_base;
    e->next_hashes[0] = nh[0];
    e->next_hashes[1] = nh[1];
}

/* ------------------------------------------------------------------------ */
/* Allocation and set-up                                                    */

#define ALIGN64(x) (((x) + 63) & ~(size_t)63)

typedef struct { size_t buf, obuf, mf, seqs, cache, nodes, slots, total, mf_n, mf_heads; } layout_t;

static void layout(int family, layout_t *L)
{
    size_t o = ALIGN64(sizeof(E));
    L->buf = o;  o += ALIGN64(IN_CAP + IN_PAD);
    L->obuf = o; o += ALIGN64(OUT_CAP + OUT_SLACK);
    L->mf_n = L->mf_heads = 0;
    L->seqs = L->cache = L->nodes = L->slots = 0;
    switch (family) {
    case F_GREEDY: case F_LAZY:
        L->mf_heads = ((size_t)1 << HC3_ORDER) + ((size_t)1 << HC4_ORDER);
        L->mf_n = L->mf_heads + MF_WIN;
        break;
    case F_OPT:
        L->mf_heads = ((size_t)2 << BT3_ORDER) + ((size_t)1 << BT4_ORDER);
        L->mf_n = L->mf_heads + 2 * MF_WIN;
        break;
    }
    L->mf = o;
    o += ALIGN64(L->mf_n * sizeof(mf_pos));
    if (family == F_GREEDY || family == F_LAZY) {
        L->seqs = o;
        o += ALIGN64((SEQ_STORE + 1) * sizeof(seq_t));
    } else if (family == F_OPT) {
        L->cache = o; o += ALIGN64((MATCH_CACHE + CACHE_SLACK) * sizeof(lz_match));
        L->nodes = o; o += 2 * ALIGN64((MAX_BLOCK + 1 + NODE_SLACK) * sizeof(u32));
        L->slots = o; o += ALIGN64(MF_WIN + 1);
    }
    L->total = o;
}

/* floor(16 * log2(x)) for x >= 1, integer only */
static u32 log2_x16(u32 x)
{
    u32 ip = bsr32(x), r = ip * 16;
    u64 y = ((u64)x << 16) >> ip;               /* x / 2^ip in 16.16 fixed point, in [1, 2) */
    for (u32 bit = 8; bit; bit >>= 1) {         /* 4 fractional bits */
        y = (y * y) >> 16;
        if (y >= ((u64)2 << 16)) { y >>= 1; r += bit; }
    }
    return r;
}

static void init_tables(E *e)
{
    for (u32 s = 0; s < 29; s++) {
        u32 hi = s == 28 ? MAX_MATCH : k_len_base[s + 1] - 1u;
        for (u32 l = k_len_base[s]; l <= hi; l++) e->len_slot[l] = (u8)s;
    }
    e->len_slot[MAX_MATCH] = 28;
    for (u32 s = 0; s < 30; s++) {
        u32 lo = k_off_base[s] - 1u, hi = lo + (1u << k_off_extra[s]);   /* x = off - 1 */
        for (u32 x = lo; x < hi; x++) {
            if (x < 256) e->off_slot_tab[x] = (u8)s;
            else e->off_slot_tab[256 + (x >> 7)] = (u8)s;
        }
    }
    /* fixed Huffman code */
    u8 *l = e->fixed.lens;
    for (u32 i = 0; i < 144; i++) l[i] = 8;
    for (u32 i = 144; i < 256; i++) l[i] = 9;
    for (u32 i = 256; i < 280; i++) l[i] = 7;
    for (u32 i = 280; i < 288; i++) l[i] = 8;
    for (u32 i = 0; i < NUM_OFFSET; i++) l[NUM_LITLEN + i] = 5;
    gen_codewords(l, NUM_LITLEN, 9, e->fixed.cw);
    gen_codewords(l + NUM_LITLEN, NUM_OFFSET, 5, e->fixed.cw + NUM_LITLEN);

    if (e->family == F_OPT) {
        for (u32 s = 0; s < 30; s++) {
            u32 lo = k_off_base[s], hi = GZ_MIN(lo + (1u << k_off_extra[s]), MF_WIN + 1u);
            for (u32 off = lo; off < hi; off++) e->off_slot_full[off] = (u8)s;
        }
        /* default literal costs for match probabilities 1/4, 1/2, 3/4:
         * lit = 16*log2(n_used / (1-p)), len symbol = 16*log2(29 / p) */
        static const u32 inv_q[3] = { 4, 2, 4 }, inv_qn[3] = { 3, 1, 1 };   /* 1/(1-p) */
        static const u32 lp_n[3] = { 116, 58, 116 }, lp_d[3] = { 1, 1, 3 };  /* 29/p */
        for (int i = 0; i < 3; i++) {
            for (u32 n = 0; n <= 256; n++) {
                u32 u = n ? n : 1;
                /* 16*log2(u * inv_q / inv_qn) */
                e->lit_cost_tab[i][n] = (u8)((log2_x16(u * inv_q[i] * 1024) - log2_x16(inv_qn[i] * 1024)));
            }
            e->len_sym_cost[i] = (u8)(log2_x16(lp_n[i] * 1024) - log2_x16(lp_d[i] * 1024));
        }
    }
}

size_t gz_deflate_enc_memory(int level)
{
    layout_t L;
    if (level < 0) level = 0;
    if (level > 9) level = 9;
    layout(k_levels[level].family, &L);
    return L.total;
}

gz_deflate_enc *gz_deflate_enc_new(int level)
{
    layout_t L;
    if (level < 0) level = 0;
    if (level > 9) level = 9;
    int fam = k_levels[level].family;
    layout(fam, &L);
    u8 *mem = (u8 *)gz_alloc_big(L.total);
    if (!mem) return 0;
    E *e = (E *)mem;
    __builtin_memset(e, 0, sizeof(*e));
    e->mem = mem;
    e->mem_size = L.total;
    e->level = level;
    e->family = fam;
    e->depth = k_levels[level].depth;
    e->nice = k_levels[level].nice;
    e->passes = k_levels[level].passes;
    e->min_impr = k_levels[level].min_impr;
    e->static_opt = k_levels[level].static_opt;
    e->buf = mem + L.buf;
    e->obuf = mem + L.obuf;
    e->mf = L.mf_n ? (mf_pos *)(mem + L.mf) : 0;
    e->mf_n = L.mf_n;
    e->mf_heads = L.mf_heads;
    e->seqs = L.seqs ? (seq_t *)(mem + L.seqs) : 0;
    e->cache = L.cache ? (lz_match *)(mem + L.cache) : 0;
    if (L.nodes) {
        e->ocost = (u32 *)(mem + L.nodes);
        e->oitem = (u32 *)(mem + L.nodes + ALIGN64((MAX_BLOCK + 1 + NODE_SLACK) * sizeof(u32)));
    }
    e->off_slot_full = L.slots ? mem + L.slots : 0;
    switch (fam) {
    case F_GREEDY: case F_LAZY:
        e->hash3 = e->mf;
        e->hash4 = e->mf + ((size_t)1 << HC3_ORDER);
        e->chain = e->hash4 + ((size_t)1 << HC4_ORDER);
        e->block = fam == F_GREEDY ? block_greedy : block_lazy;
        break;
    case F_OPT:
        e->hash3 = e->mf;
        e->hash4 = e->mf + ((size_t)2 << BT3_ORDER);
        e->chain = e->hash4 + ((size_t)1 << BT4_ORDER);
        e->block = block_opt;
        break;
    }

    /* kernel dispatch (no global state: each encoder keeps its pointers) */
    e->rebase = rebase_c;
    e->kname = "x86";
#if defined(__x86_64__)
    e->rebase = rebase_sse2;
    e->kname = "SSE2";
#elif defined(__i386__)
    if (g_cpu.active >= GZ_TIER_SSE2 && (g_cpu.features & CPUF_SSE2)) {
        e->rebase = rebase_sse2;
        e->kname = "SSE2";
    }
#endif
#if defined(__i386__) || defined(__x86_64__)
    if (g_cpu.active >= GZ_TIER_AVX2 && (g_cpu.features & CPUF_AVX2)) {
        e->rebase = rebase_avx2;
        e->kname = "AVX2";
    }
#elif defined(__aarch64__)
    e->rebase = rebase_neon;
    e->kname = "NEON";
#else
    e->kname = "C";
#endif
    init_tables(e);
    return e;
}

void gz_deflate_enc_free(gz_deflate_enc *e)
{
    if (e) gz_free_big(e->mem, e->mem_size);
}

const char *gz_deflate_enc_kernel(const gz_deflate_enc *e) { return e ? e->kname : "?"; }

/* ------------------------------------------------------------------------ */
/* Streaming driver                                                         */

/* read until the buffer is full or the input ends */
static int read_more(E *e)
{
    u8 *cap_end = e->buf + IN_CAP;
    while (!e->eof && e->in_end < cap_end) {
        u32 got = 0, cap = (u32)(cap_end - e->in_end);
        int r = e->io->read(e->io->ctx, e->in_end, cap, &got);
        if (r) return r;
        if (!got) { e->eof = 1; break; }
        if (got > cap) return GZ_E_IO;           /* misbehaving reader */
        e->crc = gz_crc32(e->crc, e->in_end, got);
        e->nin += got;
        e->in_end += got;
    }
    return GZ_OK;
}

/* make sure NEED bytes past the block start are buffered (or the input ended) */
static int refill(E *e)
{
    if (e->eof || (size_t)(e->in_end - e->blk) >= NEED) return GZ_OK;
    /* keep 32 KiB of history before the block; in_base never lags behind it */
    ptrdiff_t cur = e->in_next - e->in_base;
    if (cur >= MF_WIN) mf_advance(e, &e->in_base, cur);
    size_t d = (size_t)(e->blk - e->buf);
    d = d > MF_WIN ? d - MF_WIN : 0;
    d = GZ_MIN(d, (size_t)(e->in_base - e->buf));
    if (d) {
        __builtin_memmove(e->buf, e->buf + d, (size_t)(e->in_end - e->buf) - d);
        e->in_end -= d;
        e->in_base -= d;
        e->in_next -= d;
        e->blk -= d;
    }
    return read_more(e);
}

static int out_flush(E *e)
{
    size_t n = (size_t)(e->out - e->obuf);
    if (!n) return GZ_OK;
    e->nout += n;
    e->out = e->obuf;
    return e->io->write(e->io->ctx, e->obuf, n);
}

static int store_run(E *e)
{
    int r;
    for (;;) {
        size_t avail = (size_t)(e->in_end - e->in_next);
        if (avail < 65535 && !e->eof) {
            __builtin_memmove(e->buf, e->in_next, avail);
            e->in_next = e->buf;
            e->in_end = e->buf + avail;
            if ((r = read_more(e))) return r;
            continue;
        }
        u32 n = avail < 65535 ? (u32)avail : 65535u;
        int final = e->eof && n == avail;
        if ((size_t)(e->obuf + OUT_CAP - e->out) < n + 8u && (r = out_flush(e))) return r;
        u8 *o = e->out;
        o[0] = (u8)final;
        wr16(o + 1, (u16)n);
        wr16(o + 3, (u16)~n);
        __builtin_memcpy(o + 5, e->in_next, n);
        e->out = o + 5 + n;
        e->in_next += n;
        if (final) return out_flush(e);
    }
}

int gz_deflate_encode(gz_deflate_enc *e, const gz_stream_io *io, u32 *crc32_of_input, u64 *in_bytes,
                      u64 *out_bytes)
{
    int r = GZ_OK;
    e->io = io;
    e->in_end = e->buf;
    e->in_base = e->in_next = e->blk = e->buf;
    e->eof = 0;
    e->first_block = 1;
    e->have_codes = 0;
    e->crc = 0;
    e->nin = e->nout = 0;
    e->out = e->obuf;
    e->bitbuf = 0;
    e->bitcount = 0;
    e->next_hashes[0] = e->next_hashes[1] = 0;
    e->cache_len = 0;
    e->prev_only_lits = 0;
    if (e->mf) mf_fill_init(e->mf, e->mf_heads);  /* chains/trees are only reached via the heads */
    if (e->family == F_OPT) opt_init_stats(e);

    if (e->family == F_STORE) {
        r = store_run(e);
        goto out;
    }
    for (;;) {
        if ((r = refill(e))) goto out;
        if (e->blk == e->in_end) {               /* input ended on a block boundary */
            if (e->first_block) {
                /* empty input: one empty fixed-Huffman block */
                mword bitbuf = e->bitbuf;
                u32 bitcount = e->bitcount;
                u8 *out = e->out;
                ADD_BITS(1, 1);
                ADD_BITS(1, 2);
                ADD_BITS(0, 7);
                FLUSH_BITS();
                e->bitbuf = bitbuf;
                e->bitcount = bitcount;
                e->out = out;
            }
            break;
        }
        if ((size_t)(e->obuf + OUT_CAP - e->out) < OUT_RESERVE && (r = out_flush(e))) goto out;
        e->block(e);
        e->first_block = 0;
        e->have_codes = 1;
        if (e->blk == e->in_end && e->eof) break;   /* that was the final block */
    }
    if (e->bitcount) {                           /* pad the last byte */
        *e->out++ = (u8)e->bitbuf;
        e->bitbuf = 0;
        e->bitcount = 0;
    }
    r = out_flush(e);
out:
    if (crc32_of_input) *crc32_of_input = e->crc;
    if (in_bytes) *in_bytes = e->nin;
    if (out_bytes) *out_bytes = e->nout;
    return r;
}
