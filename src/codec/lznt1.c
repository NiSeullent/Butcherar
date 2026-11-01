/*
 * 고깃ZIP - LZNT1 decoder ([MS-XCA] 2.5, NTFS compression units)
 *
 * Chunk header: bits 0-11 = stored size - 1, bits 12-14 = signature (3, ignored),
 * bit 15 = compressed. A compressed chunk is a series of groups: one flag byte
 * (LSB first, 1 = match) then 8 tokens. A match token is 16 bits whose split
 * between distance and length depends on the position inside the chunk: with
 * pos bytes already written, the distance gets max(4, ceil(log2(pos))) bits.
 */
#include "lznt1.h"
#include "misc_lz.h"

#define CHUNK 4096u

/* Decode one compressed chunk [ip, ce) at op (chunk start). Writes stop at oe.
 * Returns GZ_OK (chunk done or output full) or GZ_E_DATA. */
static int lznt1_chunk(const u8 *ip, const u8 *ce, u8 *cs, u8 *oe, u8 **pop)
{
    u8 *op = cs;
    /* write limit for this chunk: 4096 bytes or the end of the output */
    u8 *lim = (size_t)(oe - cs) > CHUNK ? cs + CHUNK : oe;
    int r = GZ_OK;
    while (ip < ce) {
        u32 flags = *ip++;
        if (flags == 0 && ce - ip >= 8 && lim - op >= 8) {
            /* 8 literals: the common case in poorly compressible data */
            gz_cp8(op, ip);
            op += 8;
            ip += 8;
            continue;
        }
        for (int k = 0; k < 8 && ip < ce; k++, flags >>= 1) {
            size_t pos = (size_t)(op - cs);
            if (!(flags & 1)) {
                if (op >= lim) {
                    if (pos >= CHUNK) r = GZ_E_DATA;   /* else: output full */
                    goto out;
                }
                *op++ = *ip++;
                continue;
            }
            if (ce - ip < 2 || pos == 0) { r = GZ_E_DATA; goto out; }
            u32 v = rd16(ip);
            ip += 2;
            u32 x = (u32)pos - 1;
            u32 lg = x < 16 ? 0 : (u32)(31 - __builtin_clz(x)) - 3;
            size_t dist = (size_t)(v >> (12 - lg)) + 1;
            size_t len = (size_t)(v & (0xfffu >> lg)) + 3;
            if (dist > pos || pos + len > CHUNK) { r = GZ_E_DATA; goto out; }
            if (len > (size_t)(lim - op)) {          /* only when the output is full */
                gz_lz_match(op, dist, (size_t)(lim - op), oe);
                op = lim;
                goto out;
            }
            gz_lz_match(op, dist, len, oe);
            op += len;
        }
    }
out:
    *pop = op;
    return r;
}

int gz_lznt1_decode(const u8 *in, size_t in_n, u8 *out, size_t out_cap, size_t *out_n)
{
    const u8 *ip = in, *ie = in + in_n;
    u8 *op = out, *oe = out + out_cap;
    size_t pad = 0;                  /* zeros owed by the previous short chunk */
    int r = GZ_OK;
    while (ie - ip >= 2 && op < oe) {
        u32 h = rd16(ip);
        if (!h) break;
        if (pad) {
            size_t n = pad < (size_t)(oe - op) ? pad : (size_t)(oe - op);
            __builtin_memset(op, 0, n);
            op += n;
            pad = 0;
            if (op >= oe) break;
        }
        size_t clen = (h & 0xfff) + 1;
        ip += 2;
        if (clen > (size_t)(ie - ip)) { r = GZ_E_TRUNC; break; }
        u8 *cs = op;
        if (h & 0x8000) {
            r = lznt1_chunk(ip, ip + clen, cs, oe, &op);
            if (r) break;
        } else {
            size_t n = clen < (size_t)(oe - op) ? clen : (size_t)(oe - op);
            __builtin_memcpy(op, ip, n);
            op += n;
        }
        ip += clen;
        if ((size_t)(op - cs) < CHUNK) pad = CHUNK - (size_t)(op - cs);
    }
    *out_n = (size_t)(op - out);
    return r;
}
