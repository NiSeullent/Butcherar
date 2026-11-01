/*
 * 고깃ZIP - LZFSE / LZVN decoders
 *
 * Bit-exact with Apple's reference decoder (lzfse 1.0) on valid streams; corrupt
 * input is rejected where the reference would read uninitialised data. Stricter
 * than the reference: a compressed block must produce exactly its n_raw_bytes and
 * a literal run must stay inside the block's decoded literals.
 */
#include "lzfse.h"
#include "misc_lz.h"

#define MAGIC_EOS  0x24787662u      /* bvx$ */
#define MAGIC_RAW  0x2d787662u      /* bvx- */
#define MAGIC_V1   0x31787662u      /* bvx1 */
#define MAGIC_V2   0x32787662u      /* bvx2 */
#define MAGIC_LZVN 0x6e787662u      /* bvxn */

enum { L_SYM = 20, M_SYM = 20, D_SYM = 64, LIT_SYM = 256, NFREQ = L_SYM + M_SYM + D_SYM + LIT_SYM };
enum { L_ST = 64, M_ST = 64, D_ST = 256, LIT_ST = 1024 };
enum { MAX_MATCHES = 10000, MAX_LITERALS = 40000, V1_HEADER = 772, V2_FIXED = 32 };

typedef struct { u8 k, sym; u16 delta; } lit_ent;                 /* FSE symbol decoder */
typedef struct { u8 total, vbits; u16 delta; i32 vbase; } val_ent; /* FSE value decoder  */

struct gz_lzfse_dec {
    lit_ent lit[LIT_ST];
    val_ent l[L_ST], m[M_ST], d[D_ST];
    u8 lits[MAX_LITERALS + 64];     /* + slack for 16-byte literal copies */
};

static const u8 l_bits[L_SYM] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 2,3,5,8 };
static const i32 l_base[L_SYM] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 16,20,28,60 };
static const u8 m_bits[M_SYM] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 3,5,8,11 };
static const i32 m_base[M_SYM] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 16,24,56,312 };
/* distances: 4 symbols per extra-bit count 0..15 */
static const u8 d_bits[D_SYM] = {
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
    8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11,
    12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
};
static const i32 d_base[D_SYM] = {
    0, 1, 2, 3, 4, 6, 8, 10,
    12, 16, 20, 24, 28, 36, 44, 52,
    60, 76, 92, 108, 124, 156, 188, 220,
    252, 316, 380, 444, 508, 636, 764, 892,
    1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580,
    4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332,
    16380, 20476, 24572, 28668, 32764, 40956, 49148, 57340,
    65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372,
};

gz_lzfse_dec *gz_lzfse_dec_new(void)
{
    return (gz_lzfse_dec *)gz_alloc(sizeof(gz_lzfse_dec));
}

void gz_lzfse_dec_free(gz_lzfse_dec *d)
{
    gz_free(d);
}

/* ---------------- FSE: backward 64-bit bit stream ---------------- */

typedef struct { u64 acc; int n; } fse_in;

/* start reading backwards from *pbuf; n = bits used in the last byte - 8 (-7..0) */
static int fse_init(fse_in *s, i32 n, const u8 **pbuf, const u8 *start)
{
    const u8 *buf = *pbuf;
    if (n) {
        if (n < -8 || n > 0 || (size_t)(buf - start) < 8) return -1;
        buf -= 8;
        s->acc = rd64(buf);
        s->n = (int)n + 64;
    } else {
        if ((size_t)(buf - start) < 7) return -1;
        buf -= 7;
        u64 v = 0;
        __builtin_memcpy(&v, buf, 7);
        s->acc = v;
        s->n = 56;
    }
    *pbuf = buf;
    if (s->n < 56 || s->n >= 64 || (s->acc >> s->n)) return -1;
    return 0;
}

/* refill to 56..63 bits */
GZ_INLINE int fse_flush(fse_in *s, const u8 **pbuf, const u8 *start)
{
    int nb = (63 - s->n) & -8;
    if (!nb) return 0;
    if ((size_t)(*pbuf - start) < (size_t)(nb >> 3)) return -1;
    const u8 *buf = *pbuf - (nb >> 3);
    *pbuf = buf;
    s->acc = (s->acc << nb) | (rd64(buf) & (((u64)1 << nb) - 1));
    s->n += nb;
    return 0;
}

GZ_INLINE u32 fse_pull(fse_in *s, int n)
{
    s->n -= n;
    u64 r = s->acc >> s->n;
    s->acc &= ((u64)1 << s->n) - 1;
    return (u32)r;
}

/* Decoder tables from normalised frequencies (sum <= nstates checked by the caller). */
static void fse_lit_table(const u16 *freq, lit_ent *t)
{
    int nclz = __builtin_clz(LIT_ST);
    u32 used = 0;
    for (int i = 0; i < LIT_SYM; i++) {
        int f = freq[i];
        if (!f) continue;
        int k = __builtin_clz((u32)f) - nclz;
        int j0 = ((2 * LIT_ST) >> k) - f;
        for (int j = 0; j < f; j++, used++) {
            lit_ent e;
            e.sym = (u8)i;
            if (j < j0) { e.k = (u8)k; e.delta = (u16)(((f + j) << k) - LIT_ST); }
            else { e.k = (u8)(k - 1); e.delta = (u16)((j - j0) << (k - 1)); }
            t[used] = e;
        }
    }
    __builtin_memset(t + used, 0, (LIT_ST - used) * sizeof *t);
}

static void fse_val_table(int nstates, int nsym, const u16 *freq, const u8 *vbits, const i32 *vbase, val_ent *t)
{
    int nclz = __builtin_clz((u32)nstates);
    int used = 0;
    for (int i = 0; i < nsym; i++) {
        int f = freq[i];
        if (!f) continue;
        int k = __builtin_clz((u32)f) - nclz;
        int j0 = ((2 * nstates) >> k) - f;
        for (int j = 0; j < f; j++, used++) {
            val_ent e;
            e.vbits = vbits[i];
            e.vbase = vbase[i];
            if (j < j0) { e.total = (u8)(k + e.vbits); e.delta = (u16)(((f + j) << k) - nstates); }
            else { e.total = (u8)(k - 1 + e.vbits); e.delta = (u16)((j - j0) << (k - 1)); }
            t[used] = e;
        }
    }
    __builtin_memset(t + used, 0, (size_t)(nstates - used) * sizeof *t);
}

GZ_INLINE u8 lit_decode(u32 *st, const lit_ent *t, fse_in *s)
{
    lit_ent e = t[*st];
    *st = (e.delta + fse_pull(s, e.k)) & (LIT_ST - 1);
    return e.sym;
}

GZ_INLINE i32 val_decode(u32 *st, const val_ent *t, u32 mask, fse_in *s)
{
    val_ent e = t[*st];
    u32 b = fse_pull(s, e.total);
    *st = (e.delta + (b >> e.vbits)) & mask;
    return e.vbase + (i32)(b & ((1u << e.vbits) - 1));
}

/* ---------------- block headers ---------------- */

typedef struct {
    u32 n_raw, n_literals, n_matches, n_lit_payload, n_lmd_payload;
    i32 literal_bits, lmd_bits;
    u32 lit_state[4], l_state, m_state, d_state;
    u16 freq[NFREQ];               /* l, m, d, literal */
} lzfse_hdr;

static int parse_v2(const u8 *p, size_t avail, lzfse_hdr *h, size_t *hsize)
{
    static const u8 fnb[32] = { 2,3,2,5,2,3,2,8,2,3,2,5,2,3,2,14, 2,3,2,5,2,3,2,8,2,3,2,5,2,3,2,14 };
    static const u8 fval[32] = { 0,2,1,4,0,3,1,0,0,2,1,5,0,3,1,0, 0,2,1,6,0,3,1,0,0,2,1,7,0,3,1,0 };
    if (avail < V2_FIXED) return GZ_E_TRUNC;
    u64 v0 = rd64(p + 8), v1 = rd64(p + 16), v2 = rd64(p + 24);
    size_t hs = (u32)v2;
    if (hs > avail) return GZ_E_TRUNC;
    if (hs < V2_FIXED) return GZ_E_DATA;
    h->n_raw = rd32(p + 4);
    h->n_literals = (u32)v0 & 0xfffff;
    h->n_lit_payload = (u32)(v0 >> 20) & 0xfffff;
    h->n_matches = (u32)(v0 >> 40) & 0xfffff;
    h->literal_bits = (i32)((v0 >> 60) & 7) - 7;
    for (int i = 0; i < 4; i++) h->lit_state[i] = (u32)(v1 >> (10 * i)) & 0x3ff;
    h->n_lmd_payload = (u32)(v1 >> 40) & 0xfffff;
    h->lmd_bits = (i32)((v1 >> 60) & 7) - 7;
    h->l_state = (u32)(v2 >> 32) & 0x3ff;
    h->m_state = (u32)(v2 >> 42) & 0x3ff;
    h->d_state = (u32)(v2 >> 52) & 0x3ff;
    *hsize = hs;
    const u8 *src = p + V2_FIXED, *se = p + hs;
    if (src == se) { __builtin_memset(h->freq, 0, sizeof h->freq); return GZ_OK; }
    u32 acc = 0;
    int an = 0;
    for (int i = 0; i < NFREQ; i++) {
        while (src < se && an + 8 <= 32) { acc |= (u32)*src++ << an; an += 8; }
        u32 b = acc & 31;
        int n = fnb[b];
        if (n > an) return GZ_E_DATA;
        h->freq[i] = (u16)(n == 8 ? 8 + ((acc >> 4) & 15) : n == 14 ? 24 + ((acc >> 4) & 0x3ff) : fval[b]);
        acc >>= n;
        an -= n;
    }
    return (an >= 8 || src != se) ? GZ_E_DATA : GZ_OK;
}

static int parse_v1(const u8 *p, size_t avail, lzfse_hdr *h, size_t *hsize)
{
    if (avail < V1_HEADER) return GZ_E_TRUNC;
    h->n_raw = rd32(p + 4);
    h->n_literals = rd32(p + 12);
    h->n_matches = rd32(p + 16);
    h->n_lit_payload = rd32(p + 20);
    h->n_lmd_payload = rd32(p + 24);
    h->literal_bits = (i32)rd32(p + 28);
    for (int i = 0; i < 4; i++) h->lit_state[i] = rd16(p + 32 + 2 * i);
    h->lmd_bits = (i32)rd32(p + 40);
    h->l_state = rd16(p + 44);
    h->m_state = rd16(p + 46);
    h->d_state = rd16(p + 48);
    for (int i = 0; i < NFREQ; i++) h->freq[i] = rd16(p + 50 + 2 * i);
    *hsize = V1_HEADER;
    return GZ_OK;
}

static int freq_ok(const u16 *f, int n, u32 nstates)
{
    u32 s = 0;
    for (int i = 0; i < n; i++) s += f[i];
    return s <= nstates;
}

static int check_hdr(const lzfse_hdr *h)
{
    if (h->n_literals > MAX_LITERALS || h->n_matches > MAX_MATCHES) return 0;
    for (int i = 0; i < 4; i++) if (h->lit_state[i] >= LIT_ST) return 0;
    if (h->l_state >= L_ST || h->m_state >= M_ST || h->d_state >= D_ST) return 0;
    return freq_ok(h->freq, L_SYM, L_ST) && freq_ok(h->freq + L_SYM, M_SYM, M_ST) &&
           freq_ok(h->freq + L_SYM + M_SYM, D_SYM, D_ST) &&
           freq_ok(h->freq + L_SYM + M_SYM + D_SYM, LIT_SYM, LIT_ST);
}

/* One bvx1/bvx2 block whose header starts at p. in = start of the whole input (the
 * reference bounds backward reads by it), out = start of the output (matches may
 * reach earlier blocks). */
static int fse_block(gz_lzfse_dec *d, const u8 *in, const u8 *p, const u8 *ie, u8 *out, u8 **pop,
                     u8 *oe, const u8 **pnext, int v2)
{
    lzfse_hdr h;
    size_t hs;
    int r = v2 ? parse_v2(p, (size_t)(ie - p), &h, &hs) : parse_v1(p, (size_t)(ie - p), &h, &hs);
    if (r) return r;
    if ((u64)hs + h.n_lit_payload + h.n_lmd_payload > (u64)(ie - p)) return GZ_E_TRUNC;
    if (!check_hdr(&h)) return GZ_E_DATA;
    u8 *op = *pop;
    if (h.n_raw > (size_t)(oe - op)) return GZ_E_DATA;

    fse_lit_table(h.freq + L_SYM + M_SYM + D_SYM, d->lit);
    fse_val_table(L_ST, L_SYM, h.freq, l_bits, l_base, d->l);
    fse_val_table(M_ST, M_SYM, h.freq + L_SYM, m_bits, m_base, d->m);
    fse_val_table(D_ST, D_SYM, h.freq + L_SYM + M_SYM, d_bits, d_base, d->d);

    /* literals: four interleaved FSE states, read backwards from the payload end */
    const u8 *lp = p + hs, *ls = lp + h.n_lit_payload, *buf = ls;
    fse_in in_s;
    if (fse_init(&in_s, h.literal_bits, &buf, in)) return GZ_E_DATA;
    u32 s0 = h.lit_state[0], s1 = h.lit_state[1], s2 = h.lit_state[2], s3 = h.lit_state[3];
    u8 *lit = d->lits;
    for (u32 i = 0; i < h.n_literals; i += 4) {
        if (fse_flush(&in_s, &buf, in)) return GZ_E_DATA;
        lit[i + 0] = lit_decode(&s0, d->lit, &in_s);
        lit[i + 1] = lit_decode(&s1, d->lit, &in_s);
        lit[i + 2] = lit_decode(&s2, d->lit, &in_s);
        lit[i + 3] = lit_decode(&s3, d->lit, &in_s);
    }

    /* L, M, D triples */
    const u8 *lit_end = lit + h.n_literals;
    buf = ls + h.n_lmd_payload;
    if (fse_init(&in_s, h.lmd_bits, &buf, ls)) return GZ_E_DATA;
    u32 ls_ = h.l_state, ms = h.m_state, ds = h.d_state;
    u8 *blk_end = op + h.n_raw;
    u32 D = 0xffffffffu;                    /* no previous distance yet */
    for (u32 i = 0; i < h.n_matches; i++) {
        if (fse_flush(&in_s, &buf, in)) return GZ_E_DATA;
        size_t L = (size_t)val_decode(&ls_, d->l, L_ST - 1, &in_s);
        size_t M = (size_t)val_decode(&ms, d->m, M_ST - 1, &in_s);
        u32 nd = (u32)val_decode(&ds, d->d, D_ST - 1, &in_s);
        if (nd) D = nd;
        if (L > (size_t)(lit_end - lit) || L + M > (size_t)(blk_end - op) ||
            D > (size_t)(op - out) + L) return GZ_E_DATA;
        if (GZ_LIKELY((size_t)(oe - op) >= L + M + 32)) {
            gz_cp16(op, lit);                       /* L <= 315; lits has 64 bytes of slack */
            for (size_t k = 16; k < L; k += 16) gz_cp16(op + k, lit + k);
        } else {
            __builtin_memcpy(op, lit, L);
        }
        op += L;
        lit += L;
        gz_lz_match(op, D, M, oe);                  /* D was checked even when M is 0 */
        op += M;
    }
    if (op != blk_end) return GZ_E_DATA;
    *pop = op;
    *pnext = ls + h.n_lmd_payload;
    return GZ_OK;
}

/* ---------------- LZVN ---------------- */

/* Decode LZVN from [ip, ie) into [op, oe) up to the end opcode. out = start of the
 * whole output (lower bound for distances). Every instruction except the end opcode
 * needs at least one more input byte after it (the stream must end with 0x06...). */
static int lzvn_run(const u8 *ip, const u8 *ie, u8 *out, u8 *op, u8 *oe, const u8 **pip, u8 **pop)
{
    /* threaded dispatch (GCC/clang labels as values), one entry per opcode:
     * each handler jumps straight to the next one */
#define SD &&sml_d
#define MD &&med_d
#define LD &&lrg_d
#define PD &&pre_d
#define SM &&sml_m
#define LM &&lrg_m
#define SL &&sml_l
#define LL &&lrg_l
#define NP &&nop
#define EO &&eos
#define UD &&udef
    static const void *const tbl[256] = {
        SD, SD, SD, SD, SD, SD, EO, LD, SD, SD, SD, SD, SD, SD, NP, LD,
        SD, SD, SD, SD, SD, SD, NP, LD, SD, SD, SD, SD, SD, SD, UD, LD,
        SD, SD, SD, SD, SD, SD, UD, LD, SD, SD, SD, SD, SD, SD, UD, LD,
        SD, SD, SD, SD, SD, SD, UD, LD, SD, SD, SD, SD, SD, SD, UD, LD,
        SD, SD, SD, SD, SD, SD, PD, LD, SD, SD, SD, SD, SD, SD, PD, LD,
        SD, SD, SD, SD, SD, SD, PD, LD, SD, SD, SD, SD, SD, SD, PD, LD,
        SD, SD, SD, SD, SD, SD, PD, LD, SD, SD, SD, SD, SD, SD, PD, LD,
        UD, UD, UD, UD, UD, UD, UD, UD, UD, UD, UD, UD, UD, UD, UD, UD,
        SD, SD, SD, SD, SD, SD, PD, LD, SD, SD, SD, SD, SD, SD, PD, LD,
        SD, SD, SD, SD, SD, SD, PD, LD, SD, SD, SD, SD, SD, SD, PD, LD,
        MD, MD, MD, MD, MD, MD, MD, MD, MD, MD, MD, MD, MD, MD, MD, MD,
        MD, MD, MD, MD, MD, MD, MD, MD, MD, MD, MD, MD, MD, MD, MD, MD,
        SD, SD, SD, SD, SD, SD, PD, LD, SD, SD, SD, SD, SD, SD, PD, LD,
        UD, UD, UD, UD, UD, UD, UD, UD, UD, UD, UD, UD, UD, UD, UD, UD,
        LL, SL, SL, SL, SL, SL, SL, SL, SL, SL, SL, SL, SL, SL, SL, SL,
        LM, SM, SM, SM, SM, SM, SM, SM, SM, SM, SM, SM, SM, SM, SM, SM,
    };
#undef SD
#undef MD
#undef LD
#undef PD
#undef SM
#undef LM
#undef SL
#undef LL
#undef NP
#undef EO
#undef UD
    size_t D = 0, L, M, oplen, sl;
    u32 opc;
    int r;
    /* every handler leaves at least one input byte (the stream ends with the end opcode) */
#define NEXT()                                                       \
    do {                                                             \
        sl = (size_t)(ie - ip);                                      \
        opc = *ip;                                                   \
        goto *tbl[opc];                                              \
    } while (0)
    if (ip >= ie) { r = GZ_E_TRUNC; goto done; }
    NEXT();
sml_d:                                          /* LLMMMDDD DDDDDDDD */
    oplen = 2; L = opc >> 6; M = ((opc >> 3) & 7) + 3;
    if (sl <= oplen + L) { r = GZ_E_TRUNC; goto done; }
    D = (size_t)(opc & 7) << 8 | ip[1];
    goto lit_match;
med_d: {                                        /* 101LLMMM DDDDDDMM DDDDDDDD */
    oplen = 3; L = (opc >> 3) & 3;
    if (sl <= oplen + L) { r = GZ_E_TRUNC; goto done; }
    u32 v = rd16(ip + 1);
    M = ((opc & 7) << 2 | (v & 3)) + 3;
    D = v >> 2;
    goto lit_match;
}
lrg_d:                                          /* LLMMM111 DDDDDDDD DDDDDDDD */
    oplen = 3; L = opc >> 6; M = ((opc >> 3) & 7) + 3;
    if (sl <= oplen + L) { r = GZ_E_TRUNC; goto done; }
    D = rd16(ip + 1);
    goto lit_match;
pre_d:                                          /* LLMMM110: previous distance */
    oplen = 1; L = opc >> 6; M = ((opc >> 3) & 7) + 3;
    if (sl <= oplen + L) { r = GZ_E_TRUNC; goto done; }
lit_match:                                      /* literal (0..3 bytes) then match (<= 34) */
    ip += oplen;
    if (GZ_LIKELY(oe - op >= 64 && sl >= oplen + 4)) {
        wr32(op, rd32(ip));
        op += L;
        ip += L;
        if (D - 1 >= (size_t)(op - out)) { r = GZ_E_DATA; goto done; }   /* also D == 0 */
        gz_lz_match(op, D, M, oe);
        op += M;
        NEXT();
    }
    if (L > (size_t)(oe - op)) { r = GZ_E_DATA; goto done; }
    for (size_t i = 0; i < L; i++) op[i] = ip[i];
    op += L;
    ip += L;
    if (D > (size_t)(op - out)) { r = GZ_E_DATA; goto done; }
    goto match;
sml_m:                                          /* 1111MMMM */
    if (sl <= 1) { r = GZ_E_TRUNC; goto done; }
    M = opc & 15;
    ip += 1;
    goto match;
lrg_m:                                          /* 11110000 MMMMMMMM */
    if (sl <= 2) { r = GZ_E_TRUNC; goto done; }
    M = (size_t)ip[1] + 16;
    ip += 2;
match:
    if (!D || M > (size_t)(oe - op)) { r = GZ_E_DATA; goto done; }
    gz_lz_match(op, D, M, oe);
    op += M;
    NEXT();
sml_l:                                          /* 1110LLLL */
    oplen = 1; L = opc & 15;
    goto lit;
lrg_l:                                          /* 11100000 LLLLLLLL */
    if (sl <= 2) { r = GZ_E_TRUNC; goto done; }
    oplen = 2; L = (size_t)ip[1] + 16;
lit:
    if (sl <= oplen + L) { r = GZ_E_TRUNC; goto done; }
    ip += oplen;
    if (L > (size_t)(oe - op)) { r = GZ_E_DATA; goto done; }
    gz_lz_lit(op, ip, L, oe, ie);
    op += L;
    ip += L;
    NEXT();
nop:
    if (sl <= 1) { r = GZ_E_TRUNC; goto done; }
    ip++;
    NEXT();
eos:
    if (sl < 8) { r = GZ_E_TRUNC; goto done; }
    ip += 8;
    r = GZ_OK;
    goto done;
udef:
    r = GZ_E_DATA;
done:
#undef NEXT
    *pip = ip;
    *pop = op;
    return r;
}

int gz_lzvn_decode(const u8 *in, size_t in_n, u8 *out, size_t out_cap, size_t *out_n, size_t *in_used)
{
    const u8 *ip;
    u8 *op;
    int r = lzvn_run(in, in + in_n, out, out, out + out_cap, &ip, &op);
    *out_n = (size_t)(op - out);
    if (in_used) *in_used = (size_t)(ip - in);
    return r;
}

/* ---------------- stream ---------------- */

int gz_lzfse_decode_ex(gz_lzfse_dec *d, const u8 *in, size_t in_n, u8 *out, size_t out_cap,
                       size_t *out_n, size_t *in_used)
{
    const u8 *ip = in, *ie = in + in_n;
    u8 *op = out, *oe = out + out_cap;
    gz_lzfse_dec *own = 0;
    int r;
    for (;;) {
        size_t avail = (size_t)(ie - ip);
        if (avail < 4) { r = GZ_E_TRUNC; break; }
        u32 magic = rd32(ip);
        if (magic == MAGIC_EOS) { ip += 4; r = GZ_OK; break; }
        if (magic == MAGIC_RAW) {
            if (avail < 8) { r = GZ_E_TRUNC; break; }
            size_t n = rd32(ip + 4);
            if (n > avail - 8) { r = GZ_E_TRUNC; break; }
            if (n > (size_t)(oe - op)) { r = GZ_E_DATA; break; }
            __builtin_memcpy(op, ip + 8, n);
            op += n;
            ip += 8 + n;
        } else if (magic == MAGIC_LZVN) {
            if (avail < 12) { r = GZ_E_TRUNC; break; }
            size_t n_raw = rd32(ip + 4), n_pay = rd32(ip + 8);
            if (n_pay > avail - 12) { r = GZ_E_TRUNC; break; }
            if (!n_raw || !n_pay || n_raw > (size_t)(oe - op)) { r = GZ_E_DATA; break; }
            const u8 *pe = ip + 12 + n_pay, *q;
            u8 *be = op + n_raw, *o2;
            r = lzvn_run(ip + 12, pe, out, op, be, &q, &o2);
            if (r || q != pe || o2 != be) { if (!r) r = GZ_E_DATA; break; }
            op = be;
            ip = pe;
        } else if (magic == MAGIC_V1 || magic == MAGIC_V2) {
            if (!d && !(d = own = gz_lzfse_dec_new())) { r = GZ_E_NOMEM; break; }
            const u8 *next;
            r = fse_block(d, in, ip, ie, out, &op, oe, &next, magic == MAGIC_V2);
            if (r) break;
            ip = next;
        } else {
            r = GZ_E_DATA;
            break;
        }
    }
    gz_lzfse_dec_free(own);
    *out_n = (size_t)(op - out);
    if (in_used) *in_used = (size_t)(ip - in);
    return r;
}

int gz_lzfse_decode(const u8 *in, size_t in_n, u8 *out, size_t out_cap, size_t *out_n, size_t *in_used)
{
    return gz_lzfse_decode_ex(0, in, in_n, out, out_cap, out_n, in_used);
}

int gz_lzfse_size(const u8 *in, size_t in_n, u64 *raw_size, size_t *in_used)
{
    size_t pos = 0;
    u64 total = 0;
    int r;
    for (;;) {
        size_t avail = in_n - pos;
        const u8 *p = in + pos;
        if (avail < 4) { r = GZ_E_TRUNC; break; }
        u32 magic = rd32(p);
        u64 skip, raw;
        if (magic == MAGIC_EOS) { pos += 4; r = GZ_OK; break; }
        if (magic == MAGIC_RAW) {
            if (avail < 8) { r = GZ_E_TRUNC; break; }
            raw = rd32(p + 4);
            skip = 8 + raw;
        } else if (magic == MAGIC_LZVN) {
            if (avail < 12) { r = GZ_E_TRUNC; break; }
            raw = rd32(p + 4);
            skip = 12 + (u64)rd32(p + 8);
        } else if (magic == MAGIC_V2) {
            if (avail < V2_FIXED) { r = GZ_E_TRUNC; break; }
            u64 v0 = rd64(p + 8), v1 = rd64(p + 16);
            u32 hs = rd32(p + 24);
            if (hs < V2_FIXED) { r = GZ_E_DATA; break; }
            raw = rd32(p + 4);
            skip = (u64)hs + ((v0 >> 20) & 0xfffff) + ((v1 >> 40) & 0xfffff);
        } else if (magic == MAGIC_V1) {
            if (avail < V1_HEADER) { r = GZ_E_TRUNC; break; }
            raw = rd32(p + 4);
            skip = (u64)V1_HEADER + rd32(p + 20) + rd32(p + 24);
        } else {
            r = GZ_E_DATA;
            break;
        }
        if (skip > avail) { r = GZ_E_TRUNC; break; }
        pos += (size_t)skip;
        total += raw;
    }
    *raw_size = total;
    if (in_used) *in_used = pos;
    return r;
}
