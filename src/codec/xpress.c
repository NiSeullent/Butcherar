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
 * buffered and loads one word as soon as fewer than 16 remain), and so does the next
 * block's table. Each block is decoded by one of two bit readers that both keep that
 * position (see xh_spec / xh_wide), picked from the block's code lengths.
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

/* Two bit readers decode a block. Both leave the input position where the specification
 * has it when it matters: the specification's reader keeps 16..31 bits in a 32-bit
 * window (a 16-bit word is loaded as soon as fewer than 16 remain) and reads extra
 * length bytes and the next block's table right after the words it has loaded.
 *   xh_spec: that reader. Best when many matches carry length bytes (text).
 *   xh_wide: 64-bit hosts; loads four words at a time and gives back the surplus words
 *            before reading length bytes. Fewer refills: faster on literal-heavy data
 *            (binaries), slower when many matches need the give-back. */

/* 16-bit word at pos; zeros past the end (look-ahead beyond the data is allowed) */
GZ_INLINE u32 rd_word(const u8 *in, size_t in_n, size_t pos)
{
    if (GZ_LIKELY(pos + 2 <= in_n)) return rd16(in + pos);
    return pos < in_n ? in[pos] : 0;
}

/* Length bytes of a match whose 4-bit length is 15, at in[*ppos] (the reader is at the
 * specification's position). Returns the match length - 3, or ~0 if the input ends. */
GZ_INLINE u64 xh_long_len(const u8 *in, size_t in_n, size_t *ppos)
{
    size_t pos = *ppos;
    if (pos >= in_n) return ~(u64)0;
    u64 len = in[pos++];
    if (len == 255) {
        if (in_n - pos < 2) return ~(u64)0;
        len = rd16(in + pos);
        pos += 2;
        if (!len) {
            if (in_n - pos < 4) return ~(u64)0;
            len = rd32(in + pos);
            pos += 4;
        }
    } else {
        len += 15;
    }
    *ppos = pos;
    return len;
}

/* Symbol of a code longer than TB bits; the next 15 bits are at the top of v (vb bits). */
static int xh_long_sym(const huff_t *h, u64 v, int vb, u32 *pn)
{
    for (u32 n = TB + 1; n <= 15; n++) {
        u32 c = (u32)(v >> (vb - (int)n)) - h->first[n];
        if (c < h->count[n]) { *pn = n; return h->sorted[h->offs[n] + c]; }
    }
    return -1;                               /* unreachable: the code is complete */
}

/* Distance check and copy, shared by both readers. */
#define XH_COPY()                                                                          \
    do {                                                                                   \
        len += 3;                                                                          \
        if (dist > (size_t)(op - out) || len > (u64)(oe - op)) return GZ_E_DATA;           \
        gz_lz_match(op, dist, (size_t)len, oe);                                            \
        op += len;                                                                         \
    } while (0)

/* Decode one block's symbols from in[*ppos] (just after its table) into [*pop, be)
 * (a match may run past be, up to oe). */
static int xh_spec(const huff_t *h, const u8 *in, size_t in_n, size_t *ppos,
                   u8 *out, u8 **pop, u8 *be, u8 *oe)
{
    size_t pos = *ppos;
    u8 *op = *pop;
    u32 bits = rd_word(in, in_n, pos) << 16 | rd_word(in, in_n, pos + 2);
    int extra = 16;                          /* valid bits - 16 */
    pos += 4;
#define XS_REFILL()                                                                        \
    do {                                                                                   \
        if (extra < 0) {                                                                   \
            bits |= rd_word(in, in_n, pos) << -extra;                                      \
            pos += 2;                                                                      \
            extra += 16;                                                                   \
        }                                                                                  \
    } while (0)
    while (op < be) {
        u32 e = h->tab[bits >> (32 - TB)], n = e >> 12;
        int sym = (int)(e & 0x1ff);
        if (GZ_UNLIKELY(!n) && (sym = xh_long_sym(h, bits, 32, &n)) < 0) return GZ_E_DATA;
        bits <<= n;
        extra -= (int)n;
        XS_REFILL();
        if (sym < 256) {
            *op++ = (u8)sym;
            continue;
        }
        u64 len = (u32)sym & 15;
        int ob = (sym >> 4) & 15;
        if (len == 15 && (len = xh_long_len(in, in_n, &pos)) == ~(u64)0) return GZ_E_TRUNC;
        size_t dist = (size_t)1 << ob;
        if (ob) {
            dist += bits >> (32 - ob);
            bits <<= ob;
            extra -= ob;
            XS_REFILL();
        }
        XH_COPY();
    }
#undef XS_REFILL
    *ppos = pos;
    *pop = op;
    return GZ_OK;
}

#if SIZE_MAX > 0xffffffffu
static int xh_wide(const huff_t *h, const u8 *in, size_t in_n, size_t *ppos,
                   u8 *out, u8 **pop, u8 *be, u8 *oe)
{
    size_t pos = *ppos;
    u8 *op = *pop;
    u64 buf = 0;                             /* cnt valid bits at the top, MSB first */
    int cnt = 0;
#define XW_WORD()                                                                          \
    do {                                                                                   \
        buf |= (u64)rd_word(in, in_n, pos) << (48 - cnt);                                  \
        cnt += 16;                                                                         \
        pos += 2;                                                                          \
    } while (0)
    /* Up to four words at once. Bits beyond the whole words taken belong to the true
     * next word and are ORed again, unchanged, when it is loaded. */
#define XW_FILL()                                                                          \
    do {                                                                                   \
        if (GZ_LIKELY(pos + 8 <= in_n)) {                                                  \
            u64 v_ = rd64(in + pos);                                                       \
            v_ = v_ << 32 | v_ >> 32;                                                      \
            v_ = (v_ & 0x0000ffff0000ffffull) << 16 | (v_ >> 16 & 0x0000ffff0000ffffull);  \
            int k_ = (64 - cnt) >> 4;                                                      \
            buf |= v_ >> cnt;                                                              \
            cnt += 16 * k_;                                                                \
            pos += 2 * (size_t)k_;                                                         \
        } else {                                                                           \
            while (cnt <= 48) XW_WORD();                                                   \
        }                                                                                  \
    } while (0)
    /* Give back the whole words beyond the specification's 16..31-bit window: pos is
     * then the specification's position. At least one bit of the block was used, so
     * its minimum of two words loaded is met. */
#define XW_SYNC()                                                                          \
    do {                                                                                   \
        if (cnt < 16) XW_WORD();                                                           \
        int d_ = (cnt - 16) >> 4;                                                          \
        pos -= 2 * (size_t)d_;                                                             \
        cnt -= 16 * d_;                                                                    \
        buf &= ~(u64)0 << (64 - cnt);                                                      \
    } while (0)
    XW_FILL();
    while (op < be) {
        /* 31 bits: a code (<= 15) leaves >= 16 for XW_SYNC and the offset bits */
        if (cnt < 31) XW_FILL();
        u32 e = h->tab[buf >> (64 - TB)], n = e >> 12;
        if (GZ_LIKELY(!(e & 0x100))) {       /* literal with a short code: the common case */
            buf <<= n;
            cnt -= (int)n;
            *op++ = (u8)e;
            continue;
        }
        int sym = (int)(e & 0x1ff);
        if (GZ_UNLIKELY(!n) && (sym = xh_long_sym(h, buf, 64, &n)) < 0) return GZ_E_DATA;
        buf <<= n;
        cnt -= (int)n;
        if (sym < 256) {
            *op++ = (u8)sym;
            continue;
        }
        u64 len = (u32)sym & 15;
        int ob = (sym >> 4) & 15;
        if (len == 15) {
            XW_SYNC();
            if ((len = xh_long_len(in, in_n, &pos)) == ~(u64)0) return GZ_E_TRUNC;
        }
        size_t dist = (size_t)1 << ob;
        if (ob) {
            dist += (size_t)(buf >> (64 - ob));
            buf <<= ob;
            cnt -= ob;
        }
        XH_COPY();
    }
    XW_SYNC();                               /* the next table follows the words in use */
#undef XW_WORD
#undef XW_FILL
#undef XW_SYNC
    *ppos = pos;
    *pop = op;
    return GZ_OK;
}

/* Share of the code space (out of 1 << 15) taken by matches with length bytes:
 * symbols 256 + (k << 4 | 15), odd, so the high nibbles of table bytes 135..255. */
static u32 long_share(const u8 *t)
{
    u32 s = 0;
    for (u32 k = 0; k < 16; k++) {
        u32 l = t[(256 + (k << 4 | 15)) >> 1] >> 4;
        if (l) s += (1u << 15) >> l;
    }
    return s;
}
#endif

int gz_xpress_huff_decode(const u8 *in, size_t in_n, u8 *out, size_t out_n)
{
    huff_t h;
    u8 *op = out, *const oe = out + out_n;
    size_t pos = 0;
    while (op < oe) {
        if (pos > in_n || in_n - pos < 256) return GZ_E_TRUNC;
        const u8 *t = in + pos;
        int r = huff_build(&h, t);
        if (r) return r;
        pos += 256;
        u8 *be = (size_t)(oe - op) > 65536 ? op + 65536 : oe;
#if SIZE_MAX > 0xffffffffu
        if (long_share(t) < (1u << 15) / 16)
            r = xh_wide(&h, in, in_n, &pos, out, &op, be, oe);
        else
#endif
            r = xh_spec(&h, in, in_n, &pos, out, &op, be, oe);
        if (r) return r;
    }
    /* 16..31 bits are buffered unused, so the last word loaded holds no used bits; every
     * earlier word must be real input (a missing high byte is the first 8 bits of a word) */
    if (pos > in_n + 2) return GZ_E_TRUNC;
    return GZ_OK;
}
