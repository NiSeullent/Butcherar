/*
 * 고깃ZIP - [MS-XCA] Plain LZ77 and LZ77+Huffman decoders
 *
 * Plain LZ77: 32-bit flag words (MSB first, 1 = match); a match is a 16-bit word
 * (distance-1 << 3 | length-3), lengths >= 10 continue in a nibble shared by two
 * matches, then a byte, a 16-bit and a 32-bit value.
 *
 * LZ77+Huffman: per 64 KiB of output a 256-byte table of 512 code lengths
 * (canonical, max 15 bits), then a bit stream of 16-bit little-endian words read
 * MSB first. Symbols 0..255 are literals; 256 + (log2 distance << 4 | length-3)
 * are matches. Extra length bytes sit in the byte stream right after the 16-bit
 * words the specification's decoder has loaded at that point (it keeps 16..31 bits
 * buffered and loads one word as soon as fewer than 16 remain). The decoder here
 * buffers more words ahead in a machine word and, before reading length bytes or
 * the next block's table, returns the extra words so that its input position is
 * exactly the specification's.
 */
#include "xpress.h"
#include "misc_lz.h"

/* ---------------- Plain LZ77 ---------------- */

int gz_xpress_decode(const u8 *in, size_t in_n, u8 *out, size_t out_cap, size_t *out_n)
{
    const u8 *ip = in, *ie = in + in_n, *nib = 0;
    u8 *op = out, *oe = out + out_cap;
    u32 flags = 0;
    int nf = 0, r = GZ_OK;
    while (op < oe && ip < ie) {
        if (!nf) {
            if (ie - ip < 4) { r = GZ_E_TRUNC; break; }
            flags = rd32(ip);
            ip += 4;
            if (ip == ie) break;            /* flags for data that does not exist */
            nf = 32;
        }
        nf--;
        if (!((flags >> nf) & 1)) {
            /* literal run: this flag and the zero flags after it */
            u32 rest = nf ? flags << (32 - nf) : 0;
            size_t run = 1 + (size_t)(rest ? __builtin_clz(rest) : nf);
            if (run > (size_t)(ie - ip)) run = (size_t)(ie - ip);
            if (run > (size_t)(oe - op)) run = (size_t)(oe - op);
            gz_lz_lit(op, ip, run, oe, ie);
            op += run;
            ip += run;
            nf -= (int)run - 1;
            continue;
        }
        if (ie - ip < 2) { r = GZ_E_TRUNC; break; }
        u32 v = rd16(ip);
        ip += 2;
        size_t dist = (v >> 3) + 1;
        u64 len = v & 7;
        if (len == 7) {
            if (!nib) {
                if (ip >= ie) { r = GZ_E_TRUNC; break; }
                nib = ip;
                len = *ip++ & 15;
            } else {
                len = *nib >> 4;
                nib = 0;
            }
            if (len == 15) {
                if (ip >= ie) { r = GZ_E_TRUNC; break; }
                len = *ip++;
                if (len == 255) {
                    if (ie - ip < 2) { r = GZ_E_TRUNC; break; }
                    len = rd16(ip);
                    ip += 2;
                    if (!len) {
                        if (ie - ip < 4) { r = GZ_E_TRUNC; break; }
                        len = rd32(ip);
                        ip += 4;
                    }
                    if (len < 15 + 7) { r = GZ_E_DATA; break; }
                    len -= 15 + 7;
                }
                len += 15;
            }
            len += 7;
        }
        len += 3;
        if (dist > (size_t)(op - out) || len > (u64)(oe - op)) { r = GZ_E_DATA; break; }
        gz_lz_match(op, dist, (size_t)len, oe);
        op += len;
    }
    *out_n = (size_t)(op - out);
    return r;
}

/* ---------------- LZ77+Huffman ---------------- */

#define TB 11                               /* primary table bits; longer codes: slow path */

typedef struct {
    u16 tab[1 << TB];                       /* len << 12 | sym; 0x100 = code longer than TB */
    u16 sorted[512];                        /* symbols by (length, symbol) */
    u16 first[16], count[16], offs[16];     /* canonical code per length */
} huff_t;

static int huff_build(huff_t *h, const u8 *t)
{
    u8 lens[512];
    u32 cnt[16] = { 0 }, sum = 0;
    for (int i = 0; i < 256; i++) {
        u32 lo = t[i] & 15, hi = t[i] >> 4;
        lens[2 * i] = (u8)lo;
        lens[2 * i + 1] = (u8)hi;
        cnt[lo]++;
        cnt[hi]++;
    }
    for (int l = 1; l < 16; l++) sum += cnt[l] << (15 - l);
    if (sum != 1u << 15) return GZ_E_DATA;  /* over-subscribed or incomplete */
    u16 next[16];
    u32 code = 0, n = 0;
    for (int l = 1; l < 16; l++) {
        h->first[l] = (u16)code;
        h->offs[l] = next[l] = (u16)n;
        h->count[l] = (u16)cnt[l];
        n += cnt[l];
        code = (code + cnt[l]) << 1;
    }
    next[0] = (u16)n;                       /* unused symbols go after the used ones */
    for (int s = 0; s < 512; s++) h->sorted[next[lens[s]]++] = (u16)s;
    /* canonical codes left-aligned in the table: lengths <= TB fill a prefix of it,
     * the prefixes of longer codes are the rest */
    u16 *p = h->tab;
    for (int l = 1; l <= TB; l++) {
        u32 reps = 1u << (TB - l);
        const u16 *sy = h->sorted + h->offs[l];
        for (u32 k = 0; k < cnt[l]; k++) {
            u16 e = (u16)(l << 12 | sy[k]);
            if (reps >= 4) {
                u64 v = e * 0x0001000100010001ull;
                for (u32 j = 0; j < reps; j += 4) __builtin_memcpy(p + j, &v, 8);
            } else {
                p[0] = e;
                if (reps == 2) p[1] = e;
            }
            p += reps;
        }
    }
    /* 0x100: not a short-code literal; length 0: code longer than TB */
    while (p < h->tab + (1 << TB)) *p++ = 0x100;
    return GZ_OK;
}

/* Bit reader state lives in locals of gz_xpress_huff_decode (kept in registers):
 * buf holds cnt valid bits at the top (MSB first), pos is the next 16-bit word,
 * words counts the words loaded in this block, so 16 * words - cnt bits were used. */
typedef size_t bb_t;
#define BB ((int)(sizeof(bb_t) * 8))

/* 16-bit word at pos; zeros past the end (look-ahead beyond the data is allowed) */
GZ_INLINE u32 rd_word(const u8 *in, size_t in_n, size_t pos)
{
    if (GZ_LIKELY(pos + 2 <= in_n)) return rd16(in + pos);
    return pos < in_n ? in[pos] : 0;
}

#if SIZE_MAX > 0xffffffffu
/* four words at once; bits beyond the whole words taken belong to the true next word
 * and are ORed again, unchanged, when it is loaded */
#define XB_FILL()                                                                          \
    do {                                                                                   \
        if (GZ_LIKELY(pos + 8 <= in_n)) {                                                  \
            u64 v_ = rd64(in + pos);                                                       \
            u64 q_ = (v_ & 0xffff) << 48 | (v_ >> 16 & 0xffff) << 32 |                     \
                     (v_ >> 32 & 0xffff) << 16 | v_ >> 48;                                 \
            int k_ = (BB - cnt) >> 4;                                                      \
            buf |= (bb_t)(q_ >> cnt);                                                      \
            cnt += 16 * k_; pos += 2 * (size_t)k_; words += (u32)k_;                        \
        } else {                                                                           \
            while (cnt <= BB - 16) {                                                       \
                buf |= (bb_t)rd_word(in, in_n, pos) << (BB - 16 - cnt);                    \
                cnt += 16; pos += 2; words++;                                              \
            }                                                                              \
        }                                                                                  \
    } while (0)
#else
#define XB_FILL()                                                                          \
    do {                                                                                   \
        while (cnt <= BB - 16) {                                                           \
            buf |= (bb_t)rd_word(in, in_n, pos) << (BB - 16 - cnt);                        \
            cnt += 16; pos += 2; words++;                                                  \
        }                                                                                  \
    } while (0)
#endif

/* Return the words loaded beyond the specification's max(2, ceil((used + 16) / 16)),
 * so that pos is exactly where it reads length bytes or the next table. */
#define XB_SYNC()                                                                          \
    do {                                                                                   \
        u32 used_ = 16 * words - (u32)cnt, want_ = (used_ + 31) >> 4;                      \
        if (want_ < 2) want_ = 2;                                                          \
        while (words < want_) {                                                            \
            buf |= (bb_t)rd_word(in, in_n, pos) << (BB - 16 - cnt);                        \
            cnt += 16; pos += 2; words++;                                                  \
        }                                                                                  \
        pos -= 2 * (size_t)(words - want_);                                                \
        cnt -= 16 * (int)(words - want_);                                                  \
        words = want_;                                                                     \
        buf &= ~(bb_t)0 << (BB - cnt);              /* cnt is 16..32 here */               \
    } while (0)

int gz_xpress_huff_decode(const u8 *in, size_t in_n, u8 *out, size_t out_n)
{
    huff_t h;
    u8 *op = out, *const oe = out + out_n;
    size_t pos = 0;
    bb_t buf = 0;
    int cnt = 0;
    u32 words = 0;
    while (op < oe) {
        if (pos > in_n || in_n - pos < 256) return GZ_E_TRUNC;
        int r = huff_build(&h, in + pos);
        if (r) return r;
        pos += 256;
        buf = 0;
        cnt = 0;
        words = 0;
        XB_FILL();
        u8 *be = (size_t)(oe - op) > 65536 ? op + 65536 : oe;
        while (op < be) {
            if (cnt < 15) XB_FILL();
            u32 e = h.tab[buf >> (BB - TB)];
            if (GZ_LIKELY(!(e & 0x100))) {   /* literal with a short code: the common case */
                buf <<= e >> 12;
                cnt -= (int)(e >> 12);
                *op++ = (u8)e;
                continue;
            }
            u32 n = e >> 12, sym;
            if (GZ_LIKELY(n)) {
                sym = e & 0x1ff;
            } else {                         /* code of 12..15 bits */
                for (n = TB + 1;; n++) {
                    u32 c = (u32)(buf >> (BB - n)) - h.first[n];
                    if (c < h.count[n]) { sym = h.sorted[h.offs[n] + c]; break; }
                    if (n == 15) return GZ_E_DATA;      /* unreachable: code is complete */
                }
            }
            buf <<= n;
            cnt -= (int)n;
            if (sym < 256) {
                *op++ = (u8)sym;
                continue;
            }
            sym -= 256;
            u64 len = sym & 15;
            int ob = (int)(sym >> 4);
            if (len == 15) {
                XB_SYNC();
                if (pos >= in_n) return GZ_E_TRUNC;
                len = in[pos++];
                if (len == 255) {
                    if (in_n - pos < 2) return GZ_E_TRUNC;
                    len = rd16(in + pos);
                    pos += 2;
                    if (!len) {
                        if (in_n - pos < 4) return GZ_E_TRUNC;
                        len = rd32(in + pos);
                        pos += 4;
                    }
                } else {
                    len += 15;
                }
            }
            len += 3;
            size_t dist = (size_t)1 << ob;
            if (ob) {
                if (cnt < ob) XB_FILL();
                dist += (size_t)(buf >> (BB - ob));
                buf <<= ob;
                cnt -= ob;
            }
            if (dist > (size_t)(op - out) || len > (u64)(oe - op)) return GZ_E_DATA;
            gz_lz_match(op, dist, (size_t)len, oe);
            op += len;
        }
        XB_SYNC();                           /* the next table follows the words in use */
    }
    /* the bits used must come from real input; look-ahead words past the end are fine */
    if (pos > in_n && (pos - in_n) * 8 > (size_t)cnt) return GZ_E_TRUNC;
    return GZ_OK;
}
