/*
 * 고깃ZIP - LZW decoders: Unix compress (.Z) and ZIP Shrink
 *
 * compress: every table entry is "previous string + first byte of the current
 * one", so its bytes sit contiguously in the output at the position where the
 * previous string was written. Each code remembers that position (pos[]); while
 * it is still inside the output window the string is copied with wide moves
 * instead of walking the prefix chain byte by byte.
 */
#include "lzw.h"
#include "lgbits.h"

#define Z_HIST   (256u << 10)           /* output history kept for pos[] copies */
#define Z_NONE   0x80000000u            /* "far in the past" offset delta       */

struct gz_lzw_dec {
    u16 prefix[65536];
    u16 len[65536];                     /* string length (compress: 1..65281)    */
    u32 pos[65536];                     /* window offset of the string (see rel) */
    u8  suffix[65536];
    u8  mark[8192];                     /* Shrink: parent flags for partial clear */
    u8  stack[8192];                    /* Shrink: string being decoded          */
    u8 *ibuf;
    u8 *obuf;                           /* Z_HIST + GZ_LG_OCHUNK + GZ_LG_OMARGIN */
    size_t mem_size;
};

gz_lzw_dec *gz_lzw_dec_new(void)
{
    size_t hs = (sizeof(gz_lzw_dec) + 63) & ~(size_t)63;
    size_t is = GZ_LG_ICAP + GZ_LG_IPAD + 64;
    size_t total = hs + is + Z_HIST + GZ_LG_OCHUNK + GZ_LG_OMARGIN;
    u8 *m = (u8 *)gz_alloc_big(total);
    if (!m) return 0;
    gz_lzw_dec *d = (gz_lzw_dec *)m;
    d->ibuf = m + hs;
    d->obuf = m + hs + is;
    d->mem_size = total;
    return d;
}

void gz_lzw_dec_free(gz_lzw_dec *d)
{
    if (d) gz_free_big(d, d->mem_size);
}

/* ---------------- Unix compress ---------------- */

/* Skip the rest of the current group of 8 codes (ncompress reads codes in
 * groups of n_bits bytes and drops the remainder on a width change or CLEAR). */
static int skip_group(gz_lg_in *in, u32 ncodes, u32 nbits)
{
    u32 k = (8 - (ncodes & 7)) & 7;
    u32 bits = k * nbits;
    while (bits) {
        u32 n = bits > 32 ? 32 : bits;
        if (gz_lg_need_lsb(in, n)) return 1;
        gz_lg_drop_lsb(in, n);
        bits -= n;
    }
    return gz_lg_overrun(in) != 0;
}

int gz_lzw_decode(gz_lzw_dec *d, const gz_stream_io *io, u64 out_size, int flags)
{
    const u32 maxbits = (u32)flags & 0x1f;
    const int block = (flags & 0x80) != 0;
    if (maxbits < 9 || maxbits > 16) return GZ_E_METHOD;
    const u32 maxmax = 1u << maxbits;

    gz_lg_in in;
    gz_lg_in_init(&in, io, d->ibuf);
    gz_lg_out o;
    gz_lg_out_init(&o, io, d->obuf, Z_HIST, out_size, 0);

    /* window offsets: rel(p) = p - rbase (mod 2^32); rbase moves with the slides */
    uintptr_t rbase = (uintptr_t)o.buf;
    u32 flushes = 0;

    u32 nbits = 9, mask = 511;
    u32 maxcode = 511;                 /* ncompress: 511 even when maxbits == 9 */
    u32 free_ent = block ? 257 : 256;
    u32 ncodes = 0;                    /* codes read at this width since the group start */
    i32 oldcode = -1;
    u32 old_rel = 0;                   /* where the previous string starts */
    int st = GZ_OK;
    u16 *const prefix = d->prefix, *const len = d->len;
    u32 *const pos = d->pos;
    u8 *const suffix = d->suffix;

    for (;;) {
        if (free_ent > maxcode) {
            if (skip_group(&in, ncodes, nbits)) break;
            nbits++;
            maxcode = nbits == maxbits ? maxmax : (1u << nbits) - 1;
            mask = (1u << nbits) - 1;
            ncodes = 0;
            if (nbits > 16) { st = GZ_E_DATA; break; }
        }
        if (gz_lg_need_lsb(&in, nbits)) break;
        u32 code = gz_lg_peek_lsb(&in, nbits) & mask;
        gz_lg_drop_lsb(&in, nbits);
        ncodes++;
        if (GZ_UNLIKELY(in.pad) && gz_lg_overrun(&in)) break;     /* incomplete last code */

        if (o.out >= o.end) {
            u8 *before = o.out;
            int r = gz_lg_out_step(&o);
            if (r == 1) break;                                      /* out_size reached */
            if (r) { st = r; break; }
            if (o.out != before) {
                rbase -= (uintptr_t)(before - o.out);
                if (++flushes >= 512) {
                    /* every ~512 MiB: push stale offsets far into the past so they
                     * can never wrap around into the window */
                    flushes = 0;
                    u32 low = (u32)((uintptr_t)o.buf - rbase);
                    u32 span = (u32)(o.out - o.buf);
                    for (u32 i = 0; i < 65536; i++)
                        if ((u32)(pos[i] - low) >= span) pos[i] = low - Z_NONE;
                }
            }
        }

        u8 *out = o.out;
        u32 cur_rel = (u32)((uintptr_t)out - rbase);
        if (oldcode < 0) {
            if (code >= 256) { st = GZ_E_DATA; break; }
            *out++ = (u8)code;
            o.out = out;
            oldcode = (i32)code;
            old_rel = cur_rel;
            continue;
        }
        if (code == 256 && block) {
            free_ent = 256;            /* the next code fills dummy entry 256 */
            if (skip_group(&in, ncodes, nbits)) break;
            nbits = 9;
            mask = 511;
            maxcode = 511;
            ncodes = 0;
            continue;
        }

        u32 n;                          /* length of the current string */
        if (code < 256) {
            *out = (u8)code;
            n = 1;
        } else {
            u32 c = code, extra = 0;
            if (code >= free_ent) {
                if (code > free_ent) { st = GZ_E_DATA; break; }
                c = (u32)oldcode;      /* KwKwK: previous string + its first byte */
                extra = 1;
            }
            u32 cl = c < 256 ? 1 : len[c];
            n = cl + extra;
            u32 src = pos[c];
            if (c >= 256 && (u32)(src - (u32)((uintptr_t)o.buf - rbase)) < (u32)(out - o.buf)) {
                /* still in the window: forward copy (may overlap: src < out) */
                const u8 *s = (const u8 *)(rbase + src);
                u32 dist = (u32)(out - s);
                if (dist >= 8) {
                    for (u32 k = 0; k < cl; k += 8) {
                        u64 v;
                        __builtin_memcpy(&v, s + k, 8);
                        __builtin_memcpy(out + k, &v, 8);
                    }
                } else {
                    for (u32 k = 0; k < cl; k++) out[k] = s[k];
                }
            } else {
                u8 *q = out + cl;
                u32 x = c;
                while (x >= 256) { *--q = suffix[x]; x = prefix[x]; }
                *--q = (u8)x;
            }
            if (extra) out[cl] = out[0];
            if (c >= 256) pos[c] = cur_rel;    /* refresh: string is now here */
        }
        u8 first = out[0];
        if (free_ent < maxmax) {
            prefix[free_ent] = (u16)oldcode;
            suffix[free_ent] = first;
            len[free_ent] = (u16)(((u32)oldcode < 256 ? 1 : len[oldcode]) + 1);
            pos[free_ent] = old_rel;
            free_ent++;
        }
        oldcode = (i32)code;
        old_rel = cur_rel;
        if (GZ_UNLIKELY(o.left != GZ_SIZE_UNKNOWN) && n > o.left - (u64)(out - o.flushed))
            n = (u32)(o.left - (u64)(out - o.flushed));       /* out_size reached inside a string */
        o.out = out + n;
    }
    if (!st && in.err && in.err != GZ_E_TRUNC) st = in.err;
    int r = gz_lg_out_finish(&o);
    if (st == GZ_OK) st = r;
    return st;
}

/* ---------------- ZIP Shrink ---------------- */

#define SH_ITEMS 8192u
#define SH_EMPTY 256u

static int shrink_run(gz_lzw_dec *d, const gz_stream_io *io, u64 out_size)
{
    u16 *const parent = d->prefix;
    u8 *const suffix = d->suffix, *const stack = d->stack, *const mark = d->mark;
    for (u32 i = 0; i < SH_ITEMS; i++) parent[i] = SH_EMPTY;

    gz_lg_in in;
    gz_lg_in_init(&in, io, d->ibuf);
    gz_lg_out o;
    gz_lg_out_init(&o, io, d->obuf, 0, out_size, 0);

    u32 nbits = 9, head = 257;
    i32 last = -1;
    u8 last_char = 0;
    int st = GZ_OK;
    for (;;) {
        if (o.out >= o.end) {
            int r = gz_lg_out_step(&o);
            if (r == 1) break;
            if (r) { st = r; break; }
        }
        if (gz_lg_need_lsb(&in, nbits)) { st = in.err; break; }
        u32 sym = gz_lg_peek_lsb(&in, nbits);
        gz_lg_drop_lsb(&in, nbits);
        if (in.pad && gz_lg_overrun(&in)) { if (out_size != GZ_SIZE_UNKNOWN) st = GZ_E_TRUNC; break; }
        if (sym == 256) {
            if (gz_lg_need_lsb(&in, nbits)) { st = in.err; break; }
            sym = gz_lg_peek_lsb(&in, nbits);
            gz_lg_drop_lsb(&in, nbits);
            if (in.pad && gz_lg_overrun(&in)) { if (out_size != GZ_SIZE_UNKNOWN) st = GZ_E_TRUNC; break; }
            if (sym == 1) {
                if (nbits >= 13) { st = GZ_E_DATA; break; }
                nbits++;
            } else if (sym == 2) {
                /* partial clear: free every node that is nobody's parent */
                __builtin_memset(mark, 0, SH_ITEMS);
                for (u32 i = 257; i < SH_ITEMS; i++)
                    if (parent[i] != SH_EMPTY) mark[parent[i]] = 1;
                for (u32 i = 257; i < SH_ITEMS; i++)
                    if (!mark[i]) parent[i] = SH_EMPTY;
                head = 257;
            } else {
                st = GZ_E_DATA;
                break;
            }
            continue;
        }
        /* insert "previous string + ?" first; '?' is fixed once this string is known */
        int pending = 0;
        if (last >= 0 && head < SH_ITEMS) {
            while (head < SH_ITEMS && parent[head] != SH_EMPTY) head++;
            if (head < SH_ITEMS) {
                parent[head] = (u16)last;
                suffix[head] = last_char;
                head++;
                pending = 1;
            }
        }
        last = (i32)sym;
        u32 cur = sym, i = 0;
        while (cur >= 256) {
            if (cur == SH_EMPTY || i >= SH_ITEMS - 1) { st = GZ_E_DATA; goto done; }
            stack[i++] = suffix[cur];
            cur = parent[cur];
        }
        if (cur == SH_EMPTY) { st = GZ_E_DATA; break; }
        stack[i++] = (u8)cur;
        last_char = (u8)cur;
        if (pending) {
            suffix[head - 1] = (u8)cur;
            if (sym == head - 1) stack[0] = (u8)cur;     /* KwKwK */
        }
        u8 *out = o.out;
        /* stack holds the string reversed; clip at out_size */
        u32 n = i;
        if (o.left != GZ_SIZE_UNKNOWN && n > o.left - (u64)(out - o.flushed))
            n = (u32)(o.left - (u64)(out - o.flushed));
        for (u32 k = 0; k < n; k++) out[k] = stack[i - 1 - k];
        o.out = out + n;
    }
done:
    {
        int r = gz_lg_out_finish(&o);
        if (st == GZ_OK) st = r;
    }
    if (st == GZ_OK && out_size != GZ_SIZE_UNKNOWN && o.total < out_size) st = GZ_E_TRUNC;
    return st;
}

int gz_shrink_decode(gz_lzw_dec *d, const gz_stream_io *io, u64 out_size)
{
    if (d) return shrink_run(d, io, out_size);
    d = gz_lzw_dec_new();
    if (!d) return GZ_E_NOMEM;
    int r = shrink_run(d, io, out_size);
    gz_lzw_dec_free(d);
    return r;
}
