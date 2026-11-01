/*
 * 고깃ZIP - Apple Data Compression (ADC) decoder
 *
 *   1LLLLLLL                  literal run of L+1 bytes (1..128)
 *   01LLLLLL DDDDDDDD DDDDDDDD match of L+4 bytes (4..67), distance D+1 (1..65536)
 *   00LLLLDD DDDDDDDD          match of L+3 bytes (3..18), distance D+1 (1..1024)
 */
#include "adc.h"
#include "misc_lz.h"

int gz_adc_decode(const u8 *in, size_t in_n, u8 *out, size_t out_cap, size_t *out_n, size_t *in_used)
{
    const u8 *ip = in, *ie = in + in_n;
    u8 *op = out, *oe = out + out_cap;
    int r = GZ_OK;
    while (ip < ie && op < oe) {
        u32 b = *ip;
        size_t room = (size_t)(oe - op);
        if (b & 0x80) {
            size_t n = (b & 0x7f) + 1;
            if ((size_t)(ie - ip) <= n) { r = GZ_E_TRUNC; break; }
            if (n > room) n = room;
            gz_lz_lit(op, ip + 1, n, oe, ie);
            op += n;
            ip += (b & 0x7f) + 2;
            continue;
        }
        size_t len, dist;
        if (b & 0x40) {
            if (ie - ip < 3) { r = GZ_E_TRUNC; break; }
            len = (b & 0x3f) + 4;
            dist = ((size_t)ip[1] << 8 | ip[2]) + 1;
            ip += 3;
        } else {
            if (ie - ip < 2) { r = GZ_E_TRUNC; break; }
            len = (b >> 2) + 3;
            dist = ((size_t)(b & 3) << 8 | ip[1]) + 1;
            ip += 2;
        }
        if (dist > (size_t)(op - out)) { r = GZ_E_DATA; ip -= (b & 0x40) ? 3 : 2; break; }
        if (len > room) len = room;
        gz_lz_match(op, dist, len, oe);
        op += len;
    }
    *out_n = (size_t)(op - out);
    if (in_used) *in_used = (size_t)(ip - in);
    return r;
}
