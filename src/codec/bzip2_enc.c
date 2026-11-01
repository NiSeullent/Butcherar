/*
 * 고깃ZIP - BZip2 encoder
 *
 * Block pipeline:
 *   1. RLE1 (runs of 4..255 -> 4 bytes + count) while computing the block CRC
 *   2. BWT: bzip2 sorts cyclic rotations. For a string that is its own minimal
 *      rotation, rotation order equals suffix order (a tie only between identical
 *      rotations, which the inverse transform does not care about), so the block
 *      is rotated to its minimal rotation and suffix-sorted with SA-IS
 *      (linear time, no worst case like bzip2's fallback sort).
 *   3. MTF + RLE2 (RUNA/RUNB), symbol frequencies
 *   4. 2..6 Huffman tables, 4 refinement passes over 50-symbol groups (like
 *      bzip2, so ratios match), MTF-coded selectors, delta-coded lengths.
 */
#include "bzip2_enc.h"
#include "bzip2.h"

#define BE_MAXSEL   18002u
#define BE_GROUP    50u
#define BE_MAXLEN   17u              /* bzip2 limits encoder code lengths to 17 */
#define BE_ITERS    4
#define BE_ICAP     (256u << 10)
#define BE_OCAP     (1u << 20)

struct gz_bzip2_enc {
    u32 crctab[8][256];
    int level, randomize;
    u32 bsize;                       /* level * 100000 */
    u32 nmax;                        /* RLE1 output limit per block */
    /* block memory: blk[bsize] (block, then L column), rot[bsize], sa[bsize] (i32, then u16 MTF values) */
    u8 *blk, *rot;
    i32 *sa;
    void *mem;
    size_t mem_bytes;
    /* input */
    u8 *in;
    u32 ipos, ilen;
    int ieof;
    /* bit writer: acc holds an bits (right-aligned) not yet stored */
    const gz_stream_io *io;
    u8 *ob, *op;
    u64 acc;
    u32 an;
    int werr;
    /* per-block coding state */
    u32 mfreq[258];
    u32 rfreq[6][258];
    u32 code[6][258];
    u8  len[6][258];
    u8  sel[BE_MAXSEL];
};

/* ---------------- object ---------------- */

gz_bzip2_enc *gz_bzip2_enc_new(int level)
{
    if (level < 1) level = 1;
    if (level > 9) level = 9;
    gz_bzip2_enc *e = (gz_bzip2_enc *)gz_alloc(sizeof(gz_bzip2_enc));
    if (!e) return 0;
    e->level = level;
    e->bsize = (u32)level * 100000u;
    e->nmax = e->bsize - 19;
    e->mem_bytes = (size_t)e->bsize * 6 + BE_ICAP + BE_OCAP + 256;
    e->mem = gz_alloc_big(e->mem_bytes);
    if (!e->mem) { gz_free(e); return 0; }
    e->sa = (i32 *)e->mem;
    e->blk = (u8 *)(e->sa + e->bsize);
    e->rot = e->blk + e->bsize;
    e->in = e->rot + e->bsize;
    e->ob = e->in + BE_ICAP;
    gz_bzip2_crc_table(e->crctab);
    return e;
}

void gz_bzip2_enc_free(gz_bzip2_enc *e)
{
    if (!e) return;
    gz_free_big(e->mem, e->mem_bytes);
    gz_free(e);
}

void gz_bzip2_enc_set_randomized(gz_bzip2_enc *e, int on)
{
    e->randomize = on != 0;
}

/* ---------------- bit writer (MSB first) ---------------- */

static GZ_NOINLINE void bw_flush(gz_bzip2_enc *e)
{
    size_t n = (size_t)(e->op - e->ob);
    e->op = e->ob;
    if (n && !e->werr) e->werr = e->io->write(e->io->ctx, e->ob, n);
}

GZ_INLINE void bw_put(gz_bzip2_enc *e, u32 nbits, u32 v)     /* nbits <= 32, v < 2^nbits */
{
    e->acc = (e->acc << nbits) | v;
    e->an += nbits;
    if (e->an >= 32) {
        e->an -= 32;
        wr32be(e->op, (u32)(e->acc >> e->an));
        e->op += 4;
        if (GZ_UNLIKELY(e->op >= e->ob + BE_OCAP)) bw_flush(e);
    }
}

static void bw_align(gz_bzip2_enc *e)            /* pad to a byte boundary and store everything */
{
    if (e->an & 7) bw_put(e, 8 - (e->an & 7), 0);
    while (e->an) {
        e->an -= 8;
        *e->op++ = (u8)(e->acc >> e->an);
    }
}

/* ---------------- SA-IS (virtual sentinel) ---------------- */

/* Text is t8 (bytes, w = 0) or t32 (reduced strings, w = 1); every helper is inlined
 * into the two instances. Types live in a bitmap (bit set = S-type), 64 per word. */
#define SA_EMPTY (-1)
#define TS(i)    ((ty[(i) >> 6] >> ((i) & 63)) & 1)

GZ_INLINE u32 tch(const u8 *t8, const i32 *t32, int w, i32 i)
{
    return w ? (u32)t32[i] : t8[i];
}

/* LMS positions (S-type after L-type) of bitmap word k */
GZ_INLINE u64 lms_bits(const u64 *ty, size_t k)
{
    u64 prev = k ? ty[k - 1] >> 63 : 1;          /* position 0 is never LMS */
    return ty[k] & ~((ty[k] << 1) | prev);
}

#define FOR_EACH_LMS(p, body)                                                    \
    for (size_t k_ = 0; k_ < nw; k_++)                                           \
        for (u64 m_ = lms_bits(ty, k_); m_; m_ &= m_ - 1) {                      \
            i32 p = (i32)(k_ * 64 + (u32)__builtin_ctzll(m_));                   \
            body                                                                 \
        }

static void get_buckets(const i32 *C, i32 *B, u32 K, int end)
{
    i32 sum = 0;
    for (u32 i = 0; i < K; i++) {
        sum += C[i];
        B[i] = end ? sum : sum - C[i];
    }
}

/* Induced sorting: L-type suffixes left to right (seeded by n-1, the sentinel's
 * neighbour), then S-type suffixes right to left. Types come from the text, not
 * the bitmap (one cache line instead of two random loads). For s = SA[i], j = s - 1:
 *  - L pass: SA holds only LMS and L-type suffixes, so j is L-type iff t[j] >= t[s];
 *  - S pass: j is S-type iff t[j] < t[s], or t[j] == t[s] and s is S-type, i.e. i lies
 *    in the S part of bucket t[s] (SS[c] = first S-type slot of bucket c).
 * The branches are well predicted on real data (BWT locality); a branch-free
 * version measured slower. */
GZ_INLINE void sa_induce(const u8 *t8, const i32 *t32, int w, i32 *SA, i32 n,
                         const i32 *C, i32 *B, const i32 *SS, u32 K)
{
    get_buckets(C, B, K, 0);
    SA[B[tch(t8, t32, w, n - 1)]++] = n - 1;
    for (i32 i = 0; i < n; i++) {
        i32 j = SA[i] - 1;
        if (j >= 0) {
            u32 c = tch(t8, t32, w, j);
            if (c >= tch(t8, t32, w, j + 1)) SA[B[c]++] = j;
        }
    }
    get_buckets(C, B, K, 1);
    for (i32 i = n - 1; i >= 0; i--) {
        i32 j = SA[i] - 1;
        if (j >= 0) {
            u32 c = tch(t8, t32, w, j), c1 = tch(t8, t32, w, j + 1);
            if (c < c1 || (c == c1 && i >= SS[c])) SA[--B[c]] = j;
        }
    }
}

static int sais_rec(const i32 *t32, i32 *SA, i32 n, u32 K, i32 fs);

/* suffix array of t[0..n) over the alphabet [0,K); SA[n..n+fs) is free scratch space */
GZ_INLINE int sais_core(const u8 *t8, const i32 *t32, int w, i32 *SA, i32 n, u32 K, i32 fs)
{
    if (n < 2) {
        if (n == 1) SA[0] = 0;
        return GZ_OK;
    }
    i32 Cs[256], Bs[256], Ss[256];
    i32 *C = Cs, *B = Bs, *SS = Ss;
    const size_t nw = ((size_t)n + 63) >> 6;
    u64 *ty = (u64 *)gz_alloc(nw * sizeof(u64));
    if (!ty) return GZ_E_NOMEM;
    if (K > 256) {
        /* big alphabets (reduced strings): use the parent's free gap when it fits */
        C = (size_t)K * 3 <= (size_t)fs ? SA + n : (i32 *)gz_alloc((size_t)K * 3 * sizeof(i32));
        if (!C) { gz_free(ty); return GZ_E_NOMEM; }
        __builtin_memset(C, 0, (size_t)K * 3 * sizeof(i32));
        B = C + K;
        SS = B + K;
    } else {
        for (u32 i = 0; i < K; i++) Cs[i] = Ss[i] = 0;
    }
    /* types: n-1 is L (the virtual sentinel is smaller), S if t[i] < t[i+1] or equal and S;
     * C = bucket sizes, SS = S-type count, then the first S-type slot of each bucket */
    {
        u32 next = tch(t8, t32, w, n - 1), nexts = 0;
        u64 acc = 0;
        C[next]++;
        for (i32 i = n - 2; i >= 0; i--) {
            u32 c = tch(t8, t32, w, i);
            u32 s = (c < next) | ((c == next) & nexts);
            C[c]++;
            SS[c] += (i32)s;
            acc |= (u64)s << (i & 63);
            if (!(i & 63)) { ty[i >> 6] = acc; acc = 0; }
            nexts = s;
            next = c;
        }
        i32 sum = 0;
        for (u32 c = 0; c < K; c++) { sum += C[c]; SS[c] = sum - SS[c]; }
    }
    /* stage 1: sort the LMS substrings */
    __builtin_memset(SA, 0xff, (size_t)n * sizeof(i32));          /* SA_EMPTY */
    get_buckets(C, B, K, 1);
    FOR_EACH_LMS(p, SA[--B[tch(t8, t32, w, p)]] = p;)
    sa_induce(t8, t32, w, SA, n, C, B, SS, K);
    i32 n1 = 0;
    for (i32 i = 0; i < n; i++) {
        i32 p = SA[i];
        if (p > 0 && TS(p) && !TS(p - 1)) SA[n1++] = p;
    }
    /* name them. LMS positions are >= 2 apart, so slot n1 + pos/2 is private to pos:
     * first the substring length (to the next LMS, inclusive; 0 = reaches the sentinel,
     * unique), then the name. Equal length + equal characters = equal substring (the
     * types follow from the characters, ending with the S-type LMS character). */
    __builtin_memset(SA + n1, 0xff, (size_t)(n - n1) * sizeof(i32));
    {
        i32 q = -1;
        FOR_EACH_LMS(p, if (q >= 0) SA[n1 + (q >> 1)] = p - q + 1; q = p;)
        if (q >= 0) SA[n1 + (q >> 1)] = 0;
    }
    i32 name = 0, prev = 0, prevlen = 0;
    for (i32 i = 0; i < n1; i++) {
        if (i + 24 < n1) {                     /* random slots: fetch ahead */
            i32 f = SA[i + 24];
            __builtin_prefetch(SA + n1 + (f >> 1), 1);
            if (w) __builtin_prefetch(t32 + f); else __builtin_prefetch(t8 + f);
        }
        i32 pos = SA[i], len = SA[n1 + (pos >> 1)];
        i32 same = len && len == prevlen;
        for (i32 d = 0; same && d < len; d++)
            same = tch(t8, t32, w, pos + d) == tch(t8, t32, w, prev + d);
        name += !same;
        prev = pos;
        prevlen = len;
        SA[n1 + (pos >> 1)] = name - 1;
    }
    for (i32 i = n - 1, j = n - 1; i >= n1; i--)
        if (SA[i] >= 0) SA[j--] = SA[i];
    /* stage 2: suffix array of the reduced string (names in text order at the end) */
    i32 *s1 = SA + n - n1;
    int r = GZ_OK;
    if (name < n1) r = sais_rec(s1, SA, n1, (u32)name, n - 2 * n1);   /* SA[n1..n-n1) is free */
    else for (i32 i = 0; i < n1; i++) SA[s1[i]] = i;
    if (r) goto done;
    /* stage 3: sorted LMS suffixes to the bucket ends, induce everything */
    {
        i32 j = 0;
        FOR_EACH_LMS(p, s1[j++] = p;)
    }
    for (i32 i = 0; i < n1; i++) SA[i] = s1[SA[i]];
    __builtin_memset(SA + n1, 0xff, (size_t)(n - n1) * sizeof(i32));
    get_buckets(C, B, K, 1);
    for (i32 i = n1 - 1; i >= 0; i--) {
        i32 j = SA[i];
        SA[i] = SA_EMPTY;
        SA[--B[tch(t8, t32, w, j)]] = j;
    }
    sa_induce(t8, t32, w, SA, n, C, B, SS, K);
done:
    if (C != Cs && C != SA + n) gz_free(C);
    gz_free(ty);
    return r;
}

static GZ_NOINLINE int sais_rec(const i32 *t32, i32 *SA, i32 n, u32 K, i32 fs)
{
    return sais_core(0, t32, 1, SA, n, K, fs);
}

static GZ_NOINLINE int sais8(const u8 *t, i32 *SA, i32 n)
{
    return sais_core(t, 0, 0, SA, n, 256, 0);
}

#undef TS
#undef FOR_EACH_LMS

/* start of the lexicographically smallest rotation (two-pointer, O(n)) */
static u32 min_rotation(const u8 *s, u32 n)
{
    u32 i = 0, j = 1, k = 0;
    while (i < n && j < n && k < n) {
        u32 a = i + k, b = j + k;
        if (a >= n) a -= n;
        if (b >= n) b -= n;
        if (s[a] == s[b]) { k++; continue; }
        if (s[a] > s[b]) i += k + 1;
        else j += k + 1;
        if (i == j) j++;
        k = 0;
    }
    return i < j ? i : j;
}

/* BWT of blk[0..n) (cyclic rotations, like bzip2); L column replaces blk, returns origPtr */
static int bwt(gz_bzip2_enc *e, u32 n, u32 *orig)
{
    u8 *T = e->blk, *R = e->rot;
    i32 *SA = e->sa;
    u32 r = min_rotation(T, n);
    __builtin_memcpy(R, T + r, n - r);
    __builtin_memcpy(R + n - r, T, r);
    int rc = sais8(R, SA, (i32)n);
    if (rc) return rc;
    u32 start = r ? n - r : 0, op = 0;       /* T[0] is R[start] */
    for (u32 k = 0; k < n; k++) {
        u32 p = (u32)SA[k];
        T[k] = R[p ? p - 1 : n - 1];
        if (p == start) op = k;
    }
    *orig = op;
    return GZ_OK;
}

/* ---------------- MTF + RLE2 ---------------- */

GZ_INLINE void mtf_front(u64 *W, u32 v)        /* move entry v (>= 1) to the front */
{
    u32 w = v >> 3, sh = (v & 7) * 8;
    u64 x = W[w];
    u64 b = (x >> sh) & 0xff;
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
}

/* MTF values of L (u16, into the SA area); returns their count, fills mfreq */
static u32 mtf_encode(gz_bzip2_enc *e, u32 n, const u8 *map, u32 ninuse)
{
    const u8 *L = e->blk;
    u16 *out = (u16 *)e->sa;
    u32 *freq = e->mfreq;
    const u32 eob = ninuse + 1;
    for (u32 i = 0; i <= eob; i++) freq[i] = 0;
    u64 W[32];
    __builtin_memset(W, 0, sizeof W);
    for (u32 i = 0; i < ninuse; i++) W[i >> 3] |= (u64)i << ((i & 7) * 8);
    u32 wr = 0, zpend = 0;
    for (u32 i = 0; i < n; i++) {
        u64 c = map[L[i]];
        if ((W[0] & 0xff) == c) { zpend++; continue; }
        if (zpend) {
            zpend--;
            for (;;) {
                u32 s = zpend & 1;                   /* RUNB = 1, RUNA = 0 */
                out[wr++] = (u16)s;
                freq[s]++;
                if (zpend < 2) break;
                zpend = (zpend - 2) >> 1;
            }
            zpend = 0;
        }
        /* find c: first zero byte of W[w] ^ c*0x01..01 */
        u64 pat = c * 0x0101010101010101ull;
        u32 w = 0, pos;
        for (;; w++) {
            u64 x = W[w] ^ pat;
            u64 z = (x - 0x0101010101010101ull) & ~x & 0x8080808080808080ull;
            if (z) { pos = w * 8 + ((u32)__builtin_ctzll(z) >> 3); break; }
        }
        mtf_front(W, pos);
        out[wr++] = (u16)(pos + 1);
        freq[pos + 1]++;
    }
    if (zpend) {
        zpend--;
        for (;;) {
            u32 s = zpend & 1;
            out[wr++] = (u16)s;
            freq[s]++;
            if (zpend < 2) break;
            zpend = (zpend - 2) >> 1;
        }
    }
    out[wr++] = (u16)eob;
    freq[eob]++;
    return wr;
}

/* ---------------- Huffman ---------------- */

/* bzip2's code length builder: Huffman tree with depth as tie breaker; if a code
 * is longer than maxlen, flatten the frequencies and retry */
static void make_lengths(u8 *len, const u32 *freq, u32 alpha, u32 maxlen)
{
    u32 heap[260], weight[516];
    i32 parent[516];
    for (u32 i = 0; i < alpha; i++) weight[i + 1] = (freq[i] ? freq[i] : 1) << 8;
    for (;;) {
        u32 nnodes = alpha, nheap = 0;
        heap[0] = 0;
        weight[0] = 0;
        parent[0] = -2;
        for (u32 i = 1; i <= alpha; i++) {
            parent[i] = -1;
            u32 z = ++nheap, t = i;
            heap[z] = i;
            while (weight[t] < weight[heap[z >> 1]]) { heap[z] = heap[z >> 1]; z >>= 1; }
            heap[z] = t;
        }
        while (nheap > 1) {
            u32 nn[2];
            for (int k = 0; k < 2; k++) {
                nn[k] = heap[1];
                heap[1] = heap[nheap--];
                u32 z = 1, t = heap[1];
                for (;;) {
                    u32 y = z << 1;
                    if (y > nheap) break;
                    if (y < nheap && weight[heap[y + 1]] < weight[heap[y]]) y++;
                    if (weight[t] < weight[heap[y]]) break;
                    heap[z] = heap[y];
                    z = y;
                }
                heap[z] = t;
            }
            nnodes++;
            parent[nn[0]] = parent[nn[1]] = (i32)nnodes;
            u32 d0 = weight[nn[0]] & 0xff, d1 = weight[nn[1]] & 0xff;
            weight[nnodes] = ((weight[nn[0]] & 0xffffff00u) + (weight[nn[1]] & 0xffffff00u)) | (1 + (d0 > d1 ? d0 : d1));
            parent[nnodes] = -1;
            u32 z = ++nheap, t = nnodes;
            heap[z] = nnodes;
            while (weight[t] < weight[heap[z >> 1]]) { heap[z] = heap[z >> 1]; z >>= 1; }
            heap[z] = t;
        }
        int too_long = 0;
        for (u32 i = 1; i <= alpha; i++) {
            u32 j = 0;
            i32 k = (i32)i;
            while (parent[k] >= 0) { k = parent[k]; j++; }
            len[i - 1] = (u8)j;
            if (j > maxlen) too_long = 1;
        }
        if (!too_long) break;
        for (u32 i = 1; i <= alpha; i++) weight[i] = (1 + ((weight[i] >> 8) >> 1)) << 8;
    }
}

static void assign_codes(u32 *code, const u8 *len, u32 alpha)
{
    u32 minl = 32, maxl = 0;
    for (u32 i = 0; i < alpha; i++) {
        if (len[i] > maxl) maxl = len[i];
        if (len[i] < minl) minl = len[i];
    }
    u32 v = 0;
    for (u32 l = minl; l <= maxl; l++) {
        for (u32 i = 0; i < alpha; i++)
            if (len[i] == l) code[i] = v++;
        v <<= 1;
    }
}

/* tables, selectors and the coded symbols of one block */
static void send_mtf(gz_bzip2_enc *e, const u16 *mtfv, u32 nmtf, u32 alpha)
{
    u32 ngroups = nmtf < 200 ? 2 : nmtf < 600 ? 3 : nmtf < 1200 ? 4 : nmtf < 2400 ? 5 : 6;
    /* initial tables: contiguous symbol ranges of about equal frequency */
    {
        u32 npart = ngroups, remf = nmtf, gs = 0;
        while (npart > 0) {
            u32 tfreq = remf / npart, afreq = 0;
            i32 ge = (i32)gs - 1;
            while (afreq < tfreq && ge < (i32)alpha - 1) { ge++; afreq += e->mfreq[ge]; }
            if (ge > (i32)gs && npart != ngroups && npart != 1 && ((ngroups - npart) & 1)) {
                afreq -= e->mfreq[ge];
                ge--;
            }
            for (u32 v = 0; v < alpha; v++)
                e->len[npart - 1][v] = (v >= gs && (i32)v <= ge) ? 0 : 15;
            npart--;
            gs = (u32)(ge + 1);
            remf -= afreq;
        }
    }
    /* refinement: pick the cheapest table per group, rebuild tables from the picks.
     * The six 10-bit costs of a symbol are packed into one u64 (50 * 20 < 1024). */
    u32 nsel = 0;
    u64 pack[258];
    for (int it = 0; it < BE_ITERS; it++) {
        for (u32 t = 0; t < ngroups; t++)
            for (u32 v = 0; v < alpha; v++) e->rfreq[t][v] = 0;
        for (u32 v = 0; v < alpha; v++) {
            u64 p = 0;
            for (u32 t = 0; t < ngroups; t++) p |= (u64)e->len[t][v] << (10 * t);
            pack[v] = p;
        }
        nsel = 0;
        for (u32 gs = 0; gs < nmtf; gs += BE_GROUP) {
            u32 ge = gs + BE_GROUP < nmtf ? gs + BE_GROUP : nmtf;
            u64 cost = 0;
            for (u32 i = gs; i < ge; i++) cost += pack[mtfv[i]];
            u32 bt = 0, bc = (u32)cost & 1023;
            for (u32 t = 1; t < ngroups; t++) {
                u32 c = (u32)(cost >> (10 * t)) & 1023;
                if (c < bc) { bc = c; bt = t; }
            }
            e->sel[nsel++] = (u8)bt;
            u32 *rf = e->rfreq[bt];
            for (u32 i = gs; i < ge; i++) rf[mtfv[i]]++;
        }
        for (u32 t = 0; t < ngroups; t++) make_lengths(e->len[t], e->rfreq[t], alpha, BE_MAXLEN);
    }
    for (u32 t = 0; t < ngroups; t++) assign_codes(e->code[t], e->len[t], alpha);

    bw_put(e, 3, ngroups);
    bw_put(e, 15, nsel);
    {
        u8 pos[6] = { 0, 1, 2, 3, 4, 5 };
        for (u32 i = 0; i < nsel; i++) {
            u32 s = e->sel[i], j = 0;
            while (pos[j] != s) j++;
            for (u32 k = j; k; k--) pos[k] = pos[k - 1];
            pos[0] = (u8)s;
            bw_put(e, j + 1, ((1u << j) - 1) << 1);      /* j ones, then a zero */
        }
    }
    for (u32 t = 0; t < ngroups; t++) {
        u32 cur = e->len[t][0];
        bw_put(e, 5, cur);
        for (u32 v = 0; v < alpha; v++) {
            while (cur < e->len[t][v]) { bw_put(e, 2, 2); cur++; }
            while (cur > e->len[t][v]) { bw_put(e, 2, 3); cur--; }
            bw_put(e, 1, 0);
        }
    }
    u32 g = 0;
    for (u32 gs = 0; gs < nmtf; gs += BE_GROUP, g++) {
        u32 ge = gs + BE_GROUP < nmtf ? gs + BE_GROUP : nmtf;
        const u32 *cd = e->code[e->sel[g]];
        const u8 *ln = e->len[e->sel[g]];
        for (u32 i = gs; i < ge; i++) bw_put(e, ln[mtfv[i]], cd[mtfv[i]]);
    }
}

/* ---------------- blocks ---------------- */

static void randomize(u8 *s, u32 n)
{
    u32 base = 0, ri = 0;
    for (;;) {
        u32 m = base + gz_bzip2_rnums[ri] - 2;
        if (m >= n) break;
        s[m] ^= 1;
        base += gz_bzip2_rnums[ri];
        ri = (ri + 1) & 511;
    }
}

static int compress_block(gz_bzip2_enc *e, u32 n, u32 crc)
{
    /* 48-bit block magic (pi), block CRC */
    bw_put(e, 24, 0x314159);
    bw_put(e, 24, 0x265359);
    bw_put(e, 32, crc);
    if (e->randomize) randomize(e->blk, n);
    u8 inuse[256];
    __builtin_memset(inuse, 0, sizeof inuse);
    for (u32 i = 0; i < n; i++) inuse[e->blk[i]] = 1;
    u32 orig;
    int r = bwt(e, n, &orig);
    if (r) return r;
    bw_put(e, 1, (u32)e->randomize);
    bw_put(e, 24, orig);
    /* symbol map */
    u8 map[256];
    u32 ninuse = 0, used16 = 0;
    for (u32 i = 0; i < 256; i++) {
        if (inuse[i]) { map[i] = (u8)ninuse++; used16 |= 0x8000u >> (i >> 4); }
    }
    bw_put(e, 16, used16);
    for (u32 i = 0; i < 16; i++) {
        if (!(used16 & (0x8000u >> i))) continue;
        u32 v = 0;
        for (u32 j = 0; j < 16; j++) if (inuse[i * 16 + j]) v |= 0x8000u >> j;
        bw_put(e, 16, v);
    }
    u32 nmtf = mtf_encode(e, n, map, ninuse);
    send_mtf(e, (const u16 *)e->sa, nmtf, ninuse + 2);
    return GZ_OK;
}

/* RLE1: append a run of len (1..255) bytes c to the block */
GZ_INLINE u32 put_run(u8 *b, u32 nb, u32 c, u32 len)
{
    if (len < 4) {
        b[nb] = b[nb + 1] = b[nb + 2] = (u8)c;     /* blk has slack after nmax */
        return nb + len;
    }
    b[nb] = b[nb + 1] = b[nb + 2] = b[nb + 3] = (u8)c;
    b[nb + 4] = (u8)(len - 4);
    return nb + 5;
}

int gz_bzip2_encode(gz_bzip2_enc *e, const gz_stream_io *io)
{
    e->io = io;
    e->op = e->ob;
    e->acc = 0;
    e->an = 0;
    e->werr = 0;
    e->ipos = e->ilen = 0;
    e->ieof = 0;
    bw_put(e, 32, 0x425a6830u + (u32)e->level);   /* "BZh1".."BZh9" */
    u32 combined = 0;
    int r = GZ_OK;
    for (;;) {
        /* fill one block */
        u32 nb = 0, ch = 256, rl = 0, crc = 0xffffffffu;
        u8 *blk = e->blk;
        const u32 nmax = e->nmax;
        for (;;) {
            if (e->ipos >= e->ilen) {
                if (e->ieof) break;
                u32 got = 0;
                r = io->read(io->ctx, e->in, BE_ICAP, &got);
                if (r) return r;
                if (got > BE_ICAP) return GZ_E_IO;
                e->ipos = 0;
                e->ilen = got;
                if (!got) { e->ieof = 1; break; }
            }
            const u8 *p = e->in + e->ipos, *pe = e->in + e->ilen, *p0 = p;
            while (p < pe && nb < nmax) {
                u32 c = *p++;
                if (c == ch && rl < 255) { rl++; continue; }
                if (rl) nb = put_run(blk, nb, ch, rl);
                ch = c;
                rl = 1;
            }
            crc = gz_bzip2_crc_update(e->crctab, crc, p0, (size_t)(p - p0));
            e->ipos = (u32)(p - e->in);
            if (nb >= nmax) break;
        }
        if (rl) nb = put_run(blk, nb, ch, rl);
        if (!nb) break;
        crc = ~crc;
        if ((r = compress_block(e, nb, crc))) return r;
        combined = ((combined << 1) | (combined >> 31)) ^ crc;
        if (e->werr) return e->werr;
    }
    bw_put(e, 24, 0x177245);                       /* end of stream (sqrt pi) */
    bw_put(e, 24, 0x385090);
    bw_put(e, 32, combined);
    bw_align(e);
    bw_flush(e);
    return e->werr;
}
