/*
 * 고깃ZIP - LZH family decoders: LHA -lh1/4/5/6/7-, LArc -lzs/-lz5-, ARJ 1-4,
 * MS SZDD / QBasic SZ LZSS, KWAJ LZH.
 *
 * All methods share one output window [64 KiB history | 1 MiB chunk | margin]
 * (lgbits.h). Ring-buffer formats with absolute positions (lzs, lz5, SZDD) are
 * mapped to relative distances: the ring's initial contents become the history
 * just before the first output byte, in ring order starting at the start
 * position, and position p at ring index r is distance ((r - p - 1) & mask) + 1.
 *
 * Huffman codes are MSB-first canonical codes (lower lengths first, then symbol
 * order). Tables: a primary lookup of tb bits; longer codes are decoded bit by
 * bit from the code counts (rare: lengths above 12 bits).
 */
#include "lzh.h"
#include "lgbits.h"

#define LZ_HIST  65536u
#define NC       510u                   /* 256 literals + 254 lengths (3..256) */
#define NT       19u                    /* code-length code symbols */

#define HM_SLOW  0xFFFEu
#define HM_BAD   0xFFFFu

typedef struct {
    u16 *fast;                          /* sym | len << 10, HM_SLOW, HM_BAD */
    u16 *sorted;                        /* symbols by (length, value)       */
    u16 cnt[17];
    u32 tb;
} hm_tree;

/* LZHUF adaptive Huffman (lh1): 314 symbols, nodes sorted by frequency */
#define AH_NCHAR 314u
#define AH_T     (AH_NCHAR * 2 - 1)
#define AH_R     (AH_T - 1)
#define AH_MAXF  0x8000u

/* KWAJ LZH tables */
enum { KW_MATCHLEN1, KW_MATCHLEN2, KW_LITLEN, KW_OFFSET, KW_LITERAL, KW_NTREES };

struct gz_lzh_dec {
    hm_tree ct, pt, tt;
    u16 c_fast[1u << 12], c_sorted[NC];
    u16 p_fast[1u << 8], p_sorted[32];
    u16 t_fast[1u << 8], t_sorted[32];
    hm_tree kt[KW_NTREES];
    u16 k_fast[KW_NTREES][1u << 10], k_sorted[KW_NTREES][256];
    u16 freq[AH_T + 1];
    u16 prnt[AH_T + AH_NCHAR];
    u16 son[AH_T];
    u8 d_code[256], d_len[256];
    u8 *ibuf, *obuf;
    size_t mem_size;
};

gz_lzh_dec *gz_lzh_dec_new(void)
{
    size_t hs = (sizeof(gz_lzh_dec) + 63) & ~(size_t)63;
    size_t is = GZ_LG_ICAP + GZ_LG_IPAD + 64;
    size_t total = hs + is + LZ_HIST + GZ_LG_OCHUNK + GZ_LG_OMARGIN;
    u8 *m = (u8 *)gz_alloc_big(total);
    if (!m) return 0;
    gz_lzh_dec *d = (gz_lzh_dec *)m;
    d->ibuf = m + hs;
    d->obuf = m + hs + is;
    d->mem_size = total;
    d->ct.fast = d->c_fast; d->ct.sorted = d->c_sorted; d->ct.tb = 12;
    d->pt.fast = d->p_fast; d->pt.sorted = d->p_sorted; d->pt.tb = 8;
    d->tt.fast = d->t_fast; d->tt.sorted = d->t_sorted; d->tt.tb = 8;
    for (u32 i = 0; i < KW_NTREES; i++) {
        d->kt[i].fast = d->k_fast[i];
        d->kt[i].sorted = d->k_sorted[i];
        d->kt[i].tb = i == KW_LITERAL ? 10 : 8;
    }
    return d;
}

void gz_lzh_dec_free(gz_lzh_dec *d)
{
    if (d) gz_free_big(d, d->mem_size);
}

void *gz_lzh_slot_new(void) { return gz_lzh_dec_new(); }
void gz_lzh_slot_free(void *d) { gz_lzh_dec_free((gz_lzh_dec *)d); }

/* ---------------- CRC-16 ---------------- */

static const u16 k_crc16[256] = {
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040,
};

/* Slice-by-8 for large buffers: t[k][v] is the CRC of byte v followed by k zero
 * bytes. The 4 KiB of tables are derived on the stack per call (1792 lookups),
 * which costs < 1% of a 1 MiB chunk and needs no global state. */
#define CRC16_SLICE_MIN 4096u

static GZ_NOINLINE u32 crc16_slice8(u32 c, const u8 *s, size_t n)
{
    u16 t[8][256];
    for (u32 i = 0; i < 256; i++) t[0][i] = k_crc16[i];
    for (u32 k = 1; k < 8; k++)
        for (u32 i = 0; i < 256; i++) t[k][i] = (u16)((t[k - 1][i] >> 8) ^ k_crc16[t[k - 1][i] & 0xff]);
    for (; n >= 8; s += 8, n -= 8) {
        u32 x = c ^ rd16(s);
        c = (u32)t[7][x & 0xff] ^ t[6][x >> 8] ^ t[5][s[2]] ^ t[4][s[3]] ^
            t[3][s[4]] ^ t[2][s[5]] ^ t[1][s[6]] ^ t[0][s[7]];
    }
    while (n--) c = (c >> 8) ^ k_crc16[(c ^ *s++) & 0xff];
    return c;
}

u16 gz_crc16(u16 crc, const void *p, size_t n)
{
    const u8 *s = (const u8 *)p;
    u32 c = crc;
    if (n >= CRC16_SLICE_MIN) return (u16)crc16_slice8(c, s, n);
    while (n--) c = (c >> 8) ^ k_crc16[(c ^ *s++) & 0xff];
    return (u16)c;
}

/* ---------------- canonical Huffman tables (MSB-first) ---------------- */

static int hm_build(hm_tree *t, const u8 *lens, u32 n)
{
    u16 offs[18];
    for (u32 l = 0; l < 17; l++) t->cnt[l] = 0;
    for (u32 i = 0; i < n; i++) {
        if (lens[i] > 16) return GZ_E_DATA;
        t->cnt[lens[i]]++;
    }
    t->cnt[0] = 0;
    int left = 1;
    for (u32 l = 1; l <= 16; l++) {
        left = left * 2 - t->cnt[l];
        if (left < 0) return GZ_E_DATA;            /* over-subscribed */
    }
    offs[1] = 0;
    for (u32 l = 1; l <= 16; l++) offs[l + 1] = (u16)(offs[l] + t->cnt[l]);
    for (u32 i = 0; i < n; i++)
        if (lens[i]) t->sorted[offs[lens[i]]++] = (u16)i;
    const u32 tb = t->tb, size = 1u << tb;
    for (u32 i = 0; i < size; i++) t->fast[i] = HM_BAD;   /* incomplete codes stay invalid */
    u32 code = 0, si = 0;
    for (u32 l = 1; l <= 16; l++) {
        for (u32 j = 0; j < t->cnt[l]; j++, si++) {
            u32 sym = t->sorted[si];
            if (l <= tb) {
                u32 st = code << (tb - l), e = st + (1u << (tb - l));
                u16 v = (u16)(sym | l << 10);
                for (u32 k = st; k < e; k++) t->fast[k] = v;
            } else {
                t->fast[code >> (l - tb)] = HM_SLOW;
            }
            code++;
        }
        code <<= 1;
    }
    return GZ_OK;
}

/* one symbol of zero length (LHA "n == 0" tables) */
static void hm_single(hm_tree *t, u32 sym)
{
    const u32 size = 1u << t->tb;
    for (u32 i = 0; i < size; i++) t->fast[i] = (u16)sym;
    for (u32 l = 0; l < 17; l++) t->cnt[l] = 0;
}

static GZ_NOINLINE int hm_slow(const hm_tree *t, gz_lg_in *in)
{
    u32 bits = gz_lg_peek_msb(in, 16);
    u32 code = 0, first = 0, index = 0;
    for (u32 l = 1; l <= 16; l++) {
        code |= (bits >> (16 - l)) & 1;
        u32 c = t->cnt[l];
        if (code < first + c) {
            gz_lg_drop_msb(in, l);
            return t->sorted[index + code - first];
        }
        index += c;
        first = (first + c) << 1;
        code <<= 1;
    }
    return -1;
}

/* needs >= 16 valid bits */
GZ_INLINE int hm_decode(const hm_tree *t, gz_lg_in *in)
{
    u32 e = t->fast[gz_lg_peek_msb(in, t->tb)];
    if (GZ_LIKELY(e < HM_SLOW)) {
        gz_lg_drop_msb(in, e >> 10);
        return (int)(e & 0x3ff);
    }
    if (e == HM_BAD) return -1;
    return hm_slow(t, in);
}

GZ_INLINE u32 getbits(gz_lg_in *in, u32 n)   /* n <= 32, bits must be available */
{
    u32 v = n ? gz_lg_peek_msb(in, n) : 0;
    gz_lg_drop_msb(in, n);
    return v;
}

/* ---------------- LHA / ARJ static Huffman ---------------- */

/* code lengths of the temp (nn = 19) or position tree */
static int read_pt_len(gz_lg_in *in, hm_tree *t, u32 nn, u32 nbit, u32 special)
{
    u8 lens[32];
    if (gz_lg_need_msb(in, 2 * nbit)) return in->err;
    u32 n = getbits(in, nbit);
    if (n == 0) {
        u32 c = getbits(in, nbit);
        if (c >= nn) return GZ_E_DATA;
        hm_single(t, c);
        return GZ_OK;
    }
    if (n > nn) return GZ_E_DATA;
    u32 i = 0;
    while (i < n) {
        if (gz_lg_need_msb(in, 24)) return in->err;
        u32 c = gz_lg_peek_msb(in, 3);
        if (c == 7) {
            u32 more = gz_lg_peek_msb(in, 16) << 3 & 0xffff;   /* bits after the first three */
            while (more & 0x8000) { c++; more <<= 1; if (c > 16) return GZ_E_DATA; }
            gz_lg_drop_msb(in, c - 3);                      /* 3 + ones + terminating zero */
        } else {
            gz_lg_drop_msb(in, 3);
        }
        lens[i++] = (u8)c;
        if (i == special) {
            u32 z = getbits(in, 2);
            while (z-- && i < nn) lens[i++] = 0;
        }
    }
    while (i < nn) lens[i++] = 0;
    return hm_build(t, lens, nn);
}

static int read_c_len(gz_lzh_dec *d, gz_lg_in *in)
{
    u8 lens[NC];
    if (gz_lg_need_msb(in, 18)) return in->err;
    u32 n = getbits(in, 9);
    if (n == 0) {
        u32 c = getbits(in, 9);
        if (c >= NC) return GZ_E_DATA;
        hm_single(&d->ct, c);
        return GZ_OK;
    }
    if (n > NC) return GZ_E_DATA;
    u32 i = 0;
    while (i < n) {
        if (gz_lg_need_msb(in, 32)) return in->err;
        int c = hm_decode(&d->tt, in);
        if (c < 0) return GZ_E_DATA;
        if (c <= 2) {
            u32 run = c == 0 ? 1 : c == 1 ? getbits(in, 4) + 3 : getbits(in, 9) + 20;
            while (run-- && i < n) lens[i++] = 0;
        } else {
            lens[i++] = (u8)(c - 2);
        }
    }
    while (i < NC) lens[i++] = 0;
    return hm_build(&d->ct, lens, NC);
}

static int lh_static(gz_lzh_dec *d, gz_lg_in *in, gz_lg_out *o, u32 np, u32 pbit)
{
    u32 blocksize = 0;
    for (;;) {
        if (o->out >= o->end) {
            int r = gz_lg_out_step(o);
            if (r) return r == 1 ? GZ_OK : r;
        }
        if (!blocksize) {
            int r;
            if (gz_lg_need_msb(in, 16)) return in->err;
            blocksize = getbits(in, 16);
            if ((r = read_pt_len(in, &d->tt, NT, 5, 3))) return r;
            if ((r = read_c_len(d, in))) return r;
            if ((r = read_pt_len(in, &d->pt, np, pbit, ~0u))) return r;
            continue;                /* a zero-sized block is followed by another header */
        }
        /* longest symbol: 16 (code) + 16 (position code) + 15 (extra) bits */
        if (gz_lg_need_msb(in, 48)) return in->err;
        blocksize--;
        int c = hm_decode(&d->ct, in);
        if (GZ_UNLIKELY(c < 0)) return GZ_E_DATA;
        u8 *out = o->out;
        if (c < 256) {
            *out = (u8)c;
            o->out = out + 1;
            continue;
        }
        u32 len = (u32)c - 253;
        int p = hm_decode(&d->pt, in);
        if (GZ_UNLIKELY(p < 0)) return GZ_E_DATA;
        u32 dist = (u32)p;
        if (dist > 1) dist = (1u << (dist - 1)) + getbits(in, dist - 1);
        dist++;                                     /* <= 65536 = history */
        if (o->left != GZ_SIZE_UNKNOWN && len > o->left - (u64)(out - o->flushed))
            len = (u32)(o->left - (u64)(out - o->flushed));
        o->out = gz_lg_copy(out, dist, len);
    }
}

/* ---------------- ARJ method 4 ---------------- */

static int arj_fast(gz_lg_in *in, gz_lg_out *o)
{
    for (;;) {
        if (o->out >= o->end) {
            int r = gz_lg_out_step(o);
            if (r) return r == 1 ? GZ_OK : r;
        }
        if (gz_lg_need_msb(in, 40)) return in->err;
        /* length: up to 7 one-bits (terminated by 0 unless 7), then as many raw bits;
         * the marker bit caps the count of leading ones */
        u32 ones = (u32)__builtin_clz(~(u32)(in->bb >> 32) | (1u << 24));
        gz_lg_drop_msb(in, ones + (ones < 7));
        u32 c = (1u << ones) - 1 + getbits(in, ones);
        u8 *out = o->out;
        if (c == 0) {
            *out = (u8)getbits(in, 8);
            o->out = out + 1;
            continue;
        }
        u32 len = c + 2;
        /* position: up to 4 one-bits, then 9..13 raw bits */
        u32 k = (u32)__builtin_clz(~(u32)(in->bb >> 32) | (1u << 27));
        gz_lg_drop_msb(in, k + (k < 4));
        u32 dist = 512u * ((1u << k) - 1) + getbits(in, 9 + k) + 1;
        if (o->left != GZ_SIZE_UNKNOWN && len > o->left - (u64)(out - o->flushed))
            len = (u32)(o->left - (u64)(out - o->flushed));
        o->out = gz_lg_copy(out, dist, len);
    }
}

/* ---------------- LHarc -lh1- (LZHUF adaptive Huffman) ---------------- */

static void ah_start(gz_lzh_dec *d)
{
    u16 *freq = d->freq, *son = d->son, *prnt = d->prnt;
    u32 i, j;
    for (i = 0; i < AH_NCHAR; i++) {
        freq[i] = 1;
        son[i] = (u16)(i + AH_T);
        prnt[i + AH_T] = (u16)i;
    }
    i = 0;
    j = AH_NCHAR;
    while (j <= AH_R) {
        freq[j] = (u16)(freq[i] + freq[i + 1]);
        son[j] = (u16)i;
        prnt[i] = prnt[i + 1] = (u16)j;
        i += 2;
        j++;
    }
    freq[AH_T] = 0xffff;
    prnt[AH_R] = 0;
    /* upper 6 position bits: canonical code with 1/3/8/12/24/16 codes of 3..8 bits */
    static const u8 cnt[6] = { 1, 3, 8, 12, 24, 16 };
    u32 code = 0, sym = 0;
    for (u32 l = 3; l <= 8; l++) {
        for (u32 k = 0; k < cnt[l - 3]; k++, sym++) {
            u32 st = code << (8 - l);
            for (u32 x = 0; x < (1u << (8 - l)); x++) {
                d->d_code[st + x] = (u8)sym;
                d->d_len[st + x] = (u8)l;
            }
            code++;
        }
        code <<= 1;
    }
}

/* rebuild the tree with halved frequencies (LZHUF reconst) */
static void ah_reconst(gz_lzh_dec *d)
{
    u16 *freq = d->freq, *son = d->son, *prnt = d->prnt;
    u32 i, j, k;
    j = 0;
    for (i = 0; i < AH_T; i++) {
        if (son[i] >= AH_T) {
            freq[j] = (u16)((freq[i] + 1) / 2);
            son[j] = son[i];
            j++;
        }
    }
    for (i = 0, j = AH_NCHAR; j < AH_T; i += 2, j++) {
        u32 f = (u32)freq[i] + freq[i + 1];
        freq[j] = (u16)f;
        for (k = j - 1; f < freq[k]; k--) {}
        k++;
        __builtin_memmove(&freq[k + 1], &freq[k], (j - k) * sizeof(u16));
        freq[k] = (u16)f;
        __builtin_memmove(&son[k + 1], &son[k], (j - k) * sizeof(u16));
        son[k] = (u16)i;
    }
    for (i = 0; i < AH_T; i++) {
        k = son[i];
        if (k >= AH_T) prnt[k] = (u16)i;
        else prnt[k] = prnt[k + 1] = (u16)i;
    }
}

static void ah_update(gz_lzh_dec *d, u32 c)
{
    u16 *freq = d->freq, *son = d->son, *prnt = d->prnt;
    if (freq[AH_R] == AH_MAXF) ah_reconst(d);
    c = prnt[c + AH_T];
    do {
        u32 k = ++freq[c];
        u32 l = c + 1;
        if (k > freq[l]) {
            while (k > freq[++l]) {}
            l--;
            freq[c] = freq[l];
            freq[l] = (u16)k;
            u32 i = son[c];
            prnt[i] = (u16)l;
            if (i < AH_T) prnt[i + 1] = (u16)l;
            u32 j = son[l];
            son[l] = (u16)i;
            prnt[j] = (u16)c;
            if (j < AH_T) prnt[j + 1] = (u16)c;
            son[c] = (u16)j;
            c = l;
        }
    } while ((c = prnt[c]) != 0);
}

static int lh1(gz_lzh_dec *d, gz_lg_in *in, gz_lg_out *o)
{
    ah_start(d);
    for (;;) {
        if (o->out >= o->end) {
            int r = gz_lg_out_step(o);
            if (r) return r == 1 ? GZ_OK : r;
        }
        /* the tree depth is bounded (Fibonacci) well below 32 by MAXF */
        if (gz_lg_need_msb(in, 32)) return in->err;
        u32 c = d->son[AH_R];
        while (c < AH_T) {
            c += (u32)(in->bb >> 63);
            gz_lg_drop_msb(in, 1);
            c = d->son[c];
            if (GZ_UNLIKELY(!in->bc) && gz_lg_need_msb(in, 32)) return in->err;
        }
        c -= AH_T;
        ah_update(d, c);
        u8 *out = o->out;
        if (c < 256) {
            *out = (u8)c;
            o->out = out + 1;
            continue;
        }
        u32 len = c - 253;
        if (gz_lg_need_msb(in, 16)) return in->err;
        u32 x = gz_lg_peek_msb(in, 8);
        gz_lg_drop_msb(in, d->d_len[x]);
        u32 dist = ((u32)d->d_code[x] << 6 | getbits(in, 6)) + 1;
        if (o->left != GZ_SIZE_UNKNOWN && len > o->left - (u64)(out - o->flushed))
            len = (u32)(o->left - (u64)(out - o->flushed));
        o->out = gz_lg_copy(out, dist, len);
    }
}

/* ---------------- LZSS with ring positions (lzs, lz5, SZDD) ---------------- */

/* end of input: an error if out_size bytes were expected */
static int lz_eof(const gz_lg_out *o)
{
    return o->left == GZ_SIZE_UNKNOWN ? GZ_OK : GZ_E_TRUNC;
}

/* flag-byte LZSS: 1 = literal byte, 0 = 12-bit ring position + 4-bit length (+3) */
static int lzss_bytes(gz_lg_in *in, gz_lg_out *o, u32 r)
{
    for (;;) {
        if (o->out >= o->end) {               /* done before the next flag byte? */
            int rr = gz_lg_out_step(o);
            if (rr) return rr == 1 ? GZ_OK : rr;
        }
        if (gz_lg_need_msb(in, 8)) return in->err;
        u32 flags = getbits(in, 8);
        if (in->pad && gz_lg_overrun(in)) return lz_eof(o);
        for (u32 k = 0; k < 8; k++, flags >>= 1) {
            if (o->out >= o->end) {
                int rr = gz_lg_out_step(o);
                if (rr) return rr == 1 ? GZ_OK : rr;
            }
            if (gz_lg_need_msb(in, 16)) return in->err;
            u8 *out = o->out;
            if (flags & 1) {
                u32 c = getbits(in, 8);
                if (in->pad && gz_lg_overrun(in)) return lz_eof(o);
                *out = (u8)c;
                o->out = out + 1;
                r++;
                continue;
            }
            u32 b0 = getbits(in, 8), b1 = getbits(in, 8);
            if (in->pad && gz_lg_overrun(in)) return lz_eof(o);
            u32 p = b0 | (b1 & 0xf0) << 4, len = (b1 & 15) + 3;
            u32 dist = ((r - p - 1) & 4095) + 1;
            r += len;
            if (o->left != GZ_SIZE_UNKNOWN && len > o->left - (u64)(out - o->flushed))
                len = (u32)(o->left - (u64)(out - o->flushed));
            o->out = gz_lg_copy(out, dist, len);
        }
    }
}

/* LArc -lzs-: 1 + 8 bits literal, or 0 + 11-bit ring position + 4-bit length (+2) */
static int lzs(gz_lg_in *in, gz_lg_out *o)
{
    u32 r = 2048 - 17;
    for (;;) {
        if (o->out >= o->end) {
            int rr = gz_lg_out_step(o);
            if (rr) return rr == 1 ? GZ_OK : rr;
        }
        if (gz_lg_need_msb(in, 16)) return in->err;
        u8 *out = o->out;
        if (getbits(in, 1)) {
            u32 c = getbits(in, 8);
            if (in->pad && gz_lg_overrun(in)) return lz_eof(o);
            *out = (u8)c;
            o->out = out + 1;
            r++;
            continue;
        }
        u32 p = getbits(in, 11), len = getbits(in, 4) + 2;
        if (in->pad && gz_lg_overrun(in)) return lz_eof(o);
        u32 dist = ((r - p - 1) & 2047) + 1;
        r += len;
        if (o->left != GZ_SIZE_UNKNOWN && len > o->left - (u64)(out - o->flushed))
            len = (u32)(o->left - (u64)(out - o->flushed));
        o->out = gz_lg_copy(out, dist, len);
    }
}

/* LArc -lz5- initial ring (LHarc slide.c / lhasa): runs, ramps, zeros, spaces;
 * written into the history in ring order from the start position 4096-18 */
static void lz5_history(u8 *h)
{
    u8 ring[4096];
    u8 *p = ring;
    for (u32 i = 0; i < 256; i++)
        for (u32 j = 0; j < 13; j++) *p++ = (u8)i;
    for (u32 i = 0; i < 256; i++) *p++ = (u8)i;
    for (u32 i = 0; i < 256; i++) *p++ = (u8)(255 - i);
    for (u32 i = 0; i < 128; i++) *p++ = 0;
    for (u32 i = 0; i < 110; i++) *p++ = ' ';
    for (u32 i = 0; i < 18; i++) *p++ = 0;
    for (u32 i = 0; i < 4096; i++) h[i] = ring[(4096 - 18 + i) & 4095];
}

/* ---------------- KWAJ method 3 ---------------- */

static int kwaj_lens(gz_lg_in *in, u32 type, u32 n, u8 *lens)
{
    u32 c, i;
    switch (type) {
    case 0:
        c = n == 16 ? 4 : n == 32 ? 5 : n == 64 ? 6 : 8;
        for (i = 0; i < n; i++) lens[i] = (u8)c;
        return GZ_OK;
    case 1:
        if (gz_lg_need_msb(in, 4)) return in->err;
        c = getbits(in, 4);
        lens[0] = (u8)c;
        for (i = 1; i < n; i++) {
            if (gz_lg_need_msb(in, 8)) return in->err;
            if (!getbits(in, 1)) lens[i] = (u8)c;
            else if (!getbits(in, 1)) lens[i] = (u8)++c;
            else { c = getbits(in, 4); lens[i] = (u8)c; }
            if (c > 16) return GZ_E_DATA;
        }
        return GZ_OK;
    case 2:
        if (gz_lg_need_msb(in, 4)) return in->err;
        c = getbits(in, 4);
        lens[0] = (u8)c;
        for (i = 1; i < n; i++) {
            if (gz_lg_need_msb(in, 8)) return in->err;
            u32 sel = getbits(in, 2);
            if (sel == 3) c = getbits(in, 4);
            else c += sel - 1;
            if (c > 16) return GZ_E_DATA;      /* also catches wrap-around below 0 */
            lens[i] = (u8)c;
        }
        return GZ_OK;
    case 3:
        for (i = 0; i < n; i++) {
            if (gz_lg_need_msb(in, 4)) return in->err;
            lens[i] = (u8)getbits(in, 4);
        }
        return GZ_OK;
    }
    return GZ_E_DATA;
}

/* KWAJ reads stop silently at the first symbol that runs past the input */
#define KW_SYM(tree, v) do { \
        if (gz_lg_need_msb(in, 16)) return in->err; \
        int s_ = hm_decode(&d->kt[tree], in); \
        if (in->pad && gz_lg_overrun(in)) return lz_eof(o); \
        if (s_ < 0) return GZ_E_DATA; \
        (v) = (u32)s_; \
    } while (0)

static int kwaj(gz_lzh_dec *d, gz_lg_in *in, gz_lg_out *o)
{
    static const u16 nsyms[KW_NTREES] = { 16, 16, 32, 64, 256 };
    u8 lens[256];
    u32 types[6];
    if (gz_lg_need_msb(in, 24)) return in->err;
    for (u32 i = 0; i < 6; i++) types[i] = getbits(in, 4);
    for (u32 t = 0; t < KW_NTREES; t++) {
        int r = kwaj_lens(in, types[t], nsyms[t], lens);
        if (r) return r;
        if (in->pad && gz_lg_overrun(in)) return lz_eof(o);
        if (hm_build(&d->kt[t], lens, nsyms[t])) return GZ_E_DATA;
    }
    int lit_run = 0;
    for (;;) {
        if (o->out >= o->end) {
            int rr = gz_lg_out_step(o);
            if (rr) return rr == 1 ? GZ_OK : rr;
        }
        u32 len, j;
        KW_SYM(lit_run ? KW_MATCHLEN2 : KW_MATCHLEN1, len);
        if (len) {
            u32 off;
            lit_run = 0;
            KW_SYM(KW_OFFSET, j);
            if (gz_lg_need_msb(in, 6)) return in->err;
            off = j << 6 | getbits(in, 6);
            if (in->pad && gz_lg_overrun(in)) return lz_eof(o);
            len += 2;
            u8 *out = o->out;
            if (o->left != GZ_SIZE_UNKNOWN && len > o->left - (u64)(out - o->flushed))
                len = (u32)(o->left - (u64)(out - o->flushed));
            o->out = gz_lg_copy(out, ((off - 1) & 4095) + 1, len);   /* offset 0 = 4096 back */
        } else {
            KW_SYM(KW_LITLEN, len);
            len++;
            lit_run = len != 32;
            while (len--) {
                if (o->out >= o->end) {
                    int rr = gz_lg_out_step(o);
                    if (rr) return rr == 1 ? GZ_OK : rr;
                }
                KW_SYM(KW_LITERAL, j);
                *o->out++ = (u8)j;
            }
        }
    }
}

/* ---------------- dispatch ---------------- */

int gz_lzh_decode(gz_lzh_dec *d, const gz_stream_io *io, u64 out_size, int method)
{
    gz_lg_in in;
    gz_lg_out o;
    gz_lg_in_init(&in, io, d->ibuf);
    int fill = method == GZ_LZH_ARJ || method == GZ_LZH_ARJ4 ? 0 : ' ';
    gz_lg_out_init(&o, io, d->obuf, LZ_HIST, out_size, fill);
    int st;
    switch (method) {
    case GZ_LZH_LH1:  st = lh1(d, &in, &o); break;
    case GZ_LZH_LH4:
    case GZ_LZH_LH5:  st = lh_static(d, &in, &o, 14, 4); break;
    case GZ_LZH_LH6:  st = lh_static(d, &in, &o, 16, 5); break;
    case GZ_LZH_LH7:
    case GZ_LZH_ARJ:  st = lh_static(d, &in, &o, 17, 5); break;
    case GZ_LZH_ARJ4: st = arj_fast(&in, &o); break;
    case GZ_LZH_LZS:  st = lzs(&in, &o); break;
    case GZ_LZH_LZ5:
        lz5_history(o.buf + LZ_HIST - 4096);
        st = lzss_bytes(&in, &o, 4096 - 18);
        break;
    case GZ_LZH_SZDD: st = lzss_bytes(&in, &o, 4096 - 16); break;
    case GZ_LZH_SZQB: st = lzss_bytes(&in, &o, 4096 - 18); break;
    case GZ_LZH_KWAJ: st = kwaj(d, &in, &o); break;
    default: return GZ_E_METHOD;
    }
    int r = gz_lg_out_finish(&o);
    if (st == GZ_OK) st = r;
    if (st == GZ_OK && out_size != GZ_SIZE_UNKNOWN && o.total < out_size) st = GZ_E_TRUNC;
    return st;
}
