/*
 * 고깃ZIP - inline copy helpers shared by the small LZ block decoders
 * (ADC, LZNT1, LZO1X, LZFSE/LZVN, XPRESS). Internal header.
 *
 * Callers validate every length and distance first; these helpers only pick
 * a wide copy when the destination has slack for the overrun.
 */
#ifndef GZ_MISC_LZ_H
#define GZ_MISC_LZ_H
#include "base.h"

GZ_INLINE void gz_cp8(u8 *d, const u8 *s) { __builtin_memcpy(d, s, 8); }
GZ_INLINE void gz_cp16(u8 *d, const u8 *s) { __builtin_memcpy(d, s, 16); }

/* LZ77 match: op[i] = op[i - dist] for i < len (byte-by-byte semantics).
 * Requires 1 <= dist <= bytes already written and op + len <= oend. */
GZ_INLINE void gz_lz_match(u8 *op, size_t dist, size_t len, const u8 *oend)
{
    const u8 *s = op - dist;
    if (GZ_LIKELY((size_t)(oend - op) >= len + 16)) {
        u8 *e = op + len;
        if (dist >= 16) {
            do { gz_cp16(op, s); op += 16; s += 16; } while (op < e);
        } else if (dist >= 8) {
            do { gz_cp8(op, s); op += 8; s += 8; } while (op < e);
        } else {
            /* period dist < 8: seed 8 bytes, then copy from a multiple of dist >= 8 back */
            static const u8 step[8] = { 0, 8, 8, 9, 8, 10, 12, 14 };
            for (int i = 0; i < 8; i++) op[i] = s[i];
            size_t m = step[dist];
            for (u8 *p = op + 8; p < e; p += 8) gz_cp8(p, p - m);
        }
        return;
    }
    for (size_t i = 0; i < len; i++) op[i] = s[i];
}

/* Literal run: n bytes from ip to op. Requires op + n <= oend and ip + n <= iend. */
GZ_INLINE void gz_lz_lit(u8 *op, const u8 *ip, size_t n, const u8 *oend, const u8 *iend)
{
    if (n <= 16 && (size_t)(oend - op) >= 16 && (size_t)(iend - ip) >= 16) gz_cp16(op, ip);
    else __builtin_memcpy(op, ip, n);
}

#endif
