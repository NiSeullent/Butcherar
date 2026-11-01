/*
 * 고깃ZIP - LZO1X decoder (bounded; same results as liblzo's lzo1x_decompress_safe)
 *
 * Instructions (state = literals copied right after the previous instruction):
 *   0000LLLL            state 0: literal run of L+3 (L=0: 15 + zero bytes*255 + next byte)
 *   0000DDLL HHHHHHHH   state 1..3: 2-byte match, distance 1 + D + H*4
 *                       state 4:    3-byte match, distance 0x801 + D + H*4
 *   1LLDDDLL HHHHHHHH   M2: L+1 (3..8) bytes at distance 1 + D + H*8
 *   001LLLLL [ext] DDDDDDLL DDDDDDDD   M3: L+2 bytes, distance 1 + D (<= 16384)
 *   0001HLLL [ext] DDDDDDLL DDDDDDDD   M4: L+2 bytes, distance 16384 + H*16384 + D,
 *                                      distance 16384 exactly = end of stream
 * The low 2 bits LL of the last distance byte give 0..3 literals that follow.
 */
#include "lzo.h"
#include "misc_lz.h"

#define MAX255 ((((size_t)~(size_t)0) / 255) - 2)

/* extended length: zero bytes count 255 each, then a non-zero byte */
GZ_INLINE int lzo_ext(const u8 **pip, const u8 *ie, size_t base, size_t *t)
{
    const u8 *ip = *pip, *z = ip;
    while (ip < ie && *ip == 0) ip++;
    if (ip >= ie) return GZ_E_TRUNC;
    if ((size_t)(ip - z) > MAX255) return GZ_E_DATA;
    *t = (size_t)(ip - z) * 255 + base + *ip;
    *pip = ip + 1;
    return GZ_OK;
}

int gz_lzo1x_decode(const u8 *in, size_t in_n, u8 *out, size_t out_cap, size_t *out_n, size_t *in_used)
{
    const u8 *ip = in, *const ie = in + in_n;
    u8 *op = out, *const oe = out + out_cap;
    size_t t, next, dist;
    unsigned state = 0;
    int r;

    if (ip >= ie) goto trunc;
    if (*ip > 17) {
        t = (size_t)*ip++ - 17;
        if (t < 4) { next = t; goto match_next; }
        goto copy_lit;
    }
    for (;;) {
        if (ip >= ie) goto trunc;
        t = *ip++;
        if (t < 16) {
            if (state == 0) {
                if (t == 0 && (r = lzo_ext(&ip, ie, 15, &t)) != GZ_OK) goto done;
                t += 3;
            copy_lit:
                if (t > (size_t)(oe - op)) goto bad;
                if (t > (size_t)(ie - ip)) goto trunc;
                gz_lz_lit(op, ip, t, oe, ie);
                op += t;
                ip += t;
                state = 4;
                continue;
            }
            if (ip >= ie) goto trunc;
            next = t & 3;
            if (state == 4) {
                dist = 0x801 + (t >> 2) + ((size_t)*ip++ << 2);
                t = 3;
            } else {
                dist = 1 + (t >> 2) + ((size_t)*ip++ << 2);
                t = 2;
            }
        } else if (t >= 64) {
            if (ip >= ie) goto trunc;
            next = t & 3;
            dist = 1 + ((t >> 2) & 7) + ((size_t)*ip++ << 3);
            t = (t >> 5) + 1;
        } else if (t >= 32) {
            t &= 31;
            if (t == 0 && (r = lzo_ext(&ip, ie, 31, &t)) != GZ_OK) goto done;
            t += 2;
            if (ie - ip < 2) goto trunc;
            u32 v = rd16(ip);
            ip += 2;
            dist = 1 + (v >> 2);
            next = v & 3;
        } else {
            size_t hi = (t & 8) << 11;
            t &= 7;
            if (t == 0 && (r = lzo_ext(&ip, ie, 7, &t)) != GZ_OK) goto done;
            t += 2;
            if (ie - ip < 2) goto trunc;
            u32 v = rd16(ip);
            ip += 2;
            dist = hi + (v >> 2);
            next = v & 3;
            if (dist == 0) { r = GZ_OK; goto done; }      /* end-of-stream marker */
            dist += 0x4000;
        }
        if (dist > (size_t)(op - out) || t > (size_t)(oe - op)) goto bad;
        gz_lz_match(op, dist, t, oe);
        op += t;
    match_next:
        state = (unsigned)next;
        if (next) {
            if (next > (size_t)(oe - op)) goto bad;
            if (next > (size_t)(ie - ip)) goto trunc;
            if (oe - op >= 4 && ie - ip >= 4) wr32(op, rd32(ip));
            else for (size_t i = 0; i < next; i++) op[i] = ip[i];
            op += next;
            ip += next;
        }
    }
trunc:
    r = GZ_E_TRUNC;
    goto done;
bad:
    r = GZ_E_DATA;
done:
    *out_n = (size_t)(op - out);
    if (in_used) *in_used = (size_t)(ip - in);
    return r;
}
