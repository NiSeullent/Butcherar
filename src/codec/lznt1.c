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

/* Decode one compressed chunk [ip, ce) at cs (chunk start); writes stop at oe.
 * Returns GZ_OK (chunk done or output full) or GZ_E_DATA. */
static int lznt1_chunk(const u8 *ip, const u8 *ce, u8 *cs, u8 *oe, u8 **pop)
{
    u8 *op = cs;
    int r = GZ_OK;
    while (ip < ce) {
        u32 flags = (u32)*ip++ | 0x100;         /* bit 8: end of this group of 8 tokens */
        if (ip >= ce) break;                    /* flag byte without tokens ends the chunk */
        for (;;) {
            /* literals up to the next match flag */
            u32 run = (u32)__builtin_ctz(flags);
            if (run) {
                size_t n = run < (size_t)(ce - ip) ? run : (size_t)(ce - ip);
                if ((size_t)(op - cs) + n > CHUNK) { r = GZ_E_DATA; goto out; }
                if (n > (size_t)(oe - op)) {     /* output full */
                    __builtin_memcpy(op, ip, (size_t)(oe - op));
                    op = oe;
                    goto out;
                }
                if (oe - op >= 8 && ce - ip >= 8) gz_cp8(op, ip);
                else for (size_t i = 0; i < n; i++) op[i] = ip[i];
                op += n;
                ip += n;
                if (ip >= ce) goto out;
                flags >>= run;
            }
            if (flags == 1) break;
            flags >>= 1;
            size_t pos = (size_t)(op - cs);
            if (ce - ip < 2 || pos == 0) { r = GZ_E_DATA; goto out; }
            u32 v = rd16(ip);
            ip += 2;
            u32 x = (u32)pos - 1;
            u32 lg = x < 16 ? 0 : (u32)(31 - __builtin_clz(x)) - 3;
            size_t dist = (size_t)(v >> (12 - lg)) + 1;
            size_t len = (size_t)(v & (0xfffu >> lg)) + 3;
            if (dist > pos || pos + len > CHUNK) { r = GZ_E_DATA; goto out; }
            if (len > (size_t)(oe - op)) {       /* output full */
                gz_lz_match(op, dist, (size_t)(oe - op), oe);
                op = oe;
                goto out;
            }
            gz_lz_match(op, dist, len, oe);
            op += len;
            if (ip >= ce) goto out;
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
