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
 * words loaded so far, which is why the bit buffer follows the specification's
 * refill rule exactly (32-bit buffer, refill one word as soon as < 16 bits remain).
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
    u16 tab[1 << TB];                       /* len << 12 | sym, 0 = code longer than TB */
    u16 sorted[512];                        /* symbols by (length, symbol) */
    u16 first[16], count[16], offs[16];     /* canonical code per length */
} huff_t;

static int huff_build(huff_t *h, const u8 *t)
{
    u32 sum = 0;
    for (int l = 0; l < 16; l++) h->count[l] = 0;
    for (int i = 0; i < 256; i++) {
        h->count[t[i] & 15]++;
        h->count[t[i] >> 4]++;
    }
    for (int l = 1; l < 16; l++) sum += (u32)h->count[l] << (15 - l);
    if (sum != 1u << 15) return GZ_E_DATA;  /* over-subscribed or incomplete */
    u32 code = 0, n = 0;
    for (int l = 1; l < 16; l++) {
        h->first[l] = (u16)code;
        h->offs[l] = (u16)n;
        n += h->count[l];
        code = (code + h->count[l]) << 1;
    }
    u16 next[16];
    for (int l = 1; l < 16; l++) next[l] = h->offs[l];
    for (int s = 0; s < 512; s++) {
        int l = (t[s >> 1] >> ((s & 1) * 4)) & 15;
        if (l) h->sorted[next[l]++] = (u16)s;
    }
    __builtin_memset(h->tab, 0, sizeof h->tab);
    for (int l = 1; l <= TB; l++) {
        u32 c = h->first[l];
        for (u32 k = 0; k < h->count[l]; k++, c++) {
            u16 e = (u16)(l << 12 | h->sorted[h->offs[l] + k]);
            u16 *p = h->tab + (c << (TB - l));
            for (u32 j = 0; j < 1u << (TB - l); j++) p[j] = e;
        }
    }
    return GZ_OK;
}

/* 16-bit word at pos; zeros past the end (the specification may look ahead) */
GZ_INLINE u32 rd_word(const u8 *in, size_t in_n, size_t pos)
{
    if (GZ_LIKELY(pos + 2 <= in_n)) return rd16(in + pos);
    return pos < in_n ? in[pos] : 0;
}

int gz_xpress_huff_decode(const u8 *in, size_t in_n, u8 *out, size_t out_n)
{
    huff_t h;
    u8 *op = out, *const oe = out + out_n;
    size_t pos = 0;
    u32 bits = 0;
    int extra = 0;
    while (op < oe) {
        if (pos > in_n || in_n - pos < 256) return GZ_E_TRUNC;
        int r = huff_build(&h, in + pos);
        if (r) return r;
        pos += 256;
        bits = rd_word(in, in_n, pos) << 16 | rd_word(in, in_n, pos + 2);
        pos += 4;
        extra = 16;
        u8 *be = (size_t)(oe - op) > 65536 ? op + 65536 : oe;
        while (op < be) {
            u32 e = h.tab[bits >> (32 - TB)];
            u32 n = e >> 12, sym;
            if (GZ_LIKELY(n)) {
                sym = e & 0x1ff;
            } else {                         /* code of 12..15 bits */
                for (n = TB + 1;; n++) {
                    u32 c = (bits >> (32 - n)) - h.first[n];
                    if (c < h.count[n]) { sym = h.sorted[h.offs[n] + c]; break; }
                    if (n == 15) return GZ_E_DATA;      /* unreachable: code is complete */
                }
            }
            bits <<= n;
            extra -= (int)n;
            if (extra < 0) {
                bits |= rd_word(in, in_n, pos) << -extra;
                pos += 2;
                extra += 16;
            }
            if (sym < 256) {
                *op++ = (u8)sym;
                continue;
            }
            sym -= 256;
            u64 len = sym & 15;
            u32 ob = sym >> 4;
            if (len == 15) {
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
                dist += bits >> (32 - ob);
                bits <<= ob;
                extra -= (int)ob;
                if (extra < 0) {
                    bits |= rd_word(in, in_n, pos) << -extra;
                    pos += 2;
                    extra += 16;
                }
            }
            if (dist > (size_t)(op - out) || len > (u64)(oe - op)) return GZ_E_DATA;
            gz_lz_match(op, dist, (size_t)len, oe);
            op += len;
        }
    }
    /* the bits used must come from real input; look-ahead words past the end are fine */
    if (pos > in_n && (pos - in_n) * 8 > (size_t)(16 + extra)) return GZ_E_TRUNC;
    return GZ_OK;
}
