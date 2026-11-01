/*
 * 고깃ZIP - bit input and LZ output window shared by the legacy codecs
 * (lzw.c, implode.c, lzh.c). Internal header, not a public API.
 *
 * Input: a 64 KiB buffer refilled from io->read, a 64-bit bit buffer in either
 * order (LSB-first: compress/Shrink/Implode, MSB-first: LHA/ARJ/KWAJ). Past the
 * end of the input zero bytes are supplied (decoders look ahead); gz_lg_overrun()
 * tells how many of the consumed bits were such padding.
 *
 * Output: a linear window [history | chunk | margin]. The history part is
 * pre-filled (LHA uses spaces), so any distance up to `hist` is valid memory;
 * on flush the last `hist` bytes slide to the front.
 */
#ifndef GZ_LGBITS_H
#define GZ_LGBITS_H
#include "base.h"
#include "stream.h"

#define GZ_LG_ICAP   (64u << 10)
#define GZ_LG_IPAD   16u
#define GZ_LG_PADMAX 64u            /* zero bytes after the end before giving up */

typedef struct {
    const gz_stream_io *io;
    u8 *buf;                        /* GZ_LG_ICAP + GZ_LG_IPAD bytes */
    const u8 *p, *end;
    u64 bb;                         /* bit buffer */
    u32 bc;                         /* valid bits in bb */
    u32 pad;                        /* zero bytes supplied after the end of input */
    int eof;
    int err;                        /* read error or GZ_E_TRUNC (too much padding) */
    u64 nread;                      /* bytes obtained from io->read */
} gz_lg_in;

void gz_lg_in_init(gz_lg_in *b, const gz_stream_io *io, u8 *buf);
/* slow paths: top up to >= 57 bits; return 0, or the error (also left in b->err) */
int  gz_lg_fill_lsb(gz_lg_in *b);
int  gz_lg_fill_msb(gz_lg_in *b);

/* bits of zero padding consumed so far (0 = all consumed bits were real input) */
static inline u32 gz_lg_overrun(const gz_lg_in *b)
{
    u32 pb = b->pad * 8;
    return pb > b->bc ? pb - b->bc : 0;
}

/* ---- LSB-first ---- */
GZ_INLINE int gz_lg_need_lsb(gz_lg_in *b, u32 n)
{
    if (GZ_LIKELY(b->bc >= n)) return 0;
    if (GZ_LIKELY(b->end - b->p >= 8)) {
        b->bb |= rd64(b->p) << b->bc;
        b->p += (63 - b->bc) >> 3;
        b->bc |= 56;
        return 0;
    }
    return gz_lg_fill_lsb(b);
}
GZ_INLINE u32 gz_lg_peek_lsb(const gz_lg_in *b, u32 n) { return (u32)b->bb & ((1u << n) - 1); }
GZ_INLINE void gz_lg_drop_lsb(gz_lg_in *b, u32 n) { b->bb >>= n; b->bc -= n; }

/* ---- MSB-first (bits left-aligned in bb) ---- */
GZ_INLINE int gz_lg_need_msb(gz_lg_in *b, u32 n)
{
    if (GZ_LIKELY(b->bc >= n)) return 0;
    if (GZ_LIKELY(b->end - b->p >= 8)) {
        b->bb |= rd64be(b->p) >> b->bc;
        b->p += (63 - b->bc) >> 3;
        b->bc |= 56;
        return 0;
    }
    return gz_lg_fill_msb(b);
}
/* n in 1..32 */
GZ_INLINE u32 gz_lg_peek_msb(const gz_lg_in *b, u32 n) { return (u32)(b->bb >> (64 - n)); }
GZ_INLINE void gz_lg_drop_msb(gz_lg_in *b, u32 n) { b->bb <<= n; b->bc -= n; }

/* ---- output window ---- */

#define GZ_LG_OCHUNK (1u << 20)
#define GZ_LG_OMARGIN (65536u + 64u)

typedef struct {
    const gz_stream_io *io;
    u8 *buf;                        /* hist + GZ_LG_OCHUNK + GZ_LG_OMARGIN */
    u32 hist;
    u8 *out;                        /* next byte to produce */
    u8 *flushed;                    /* first byte not yet pushed */
    u8 *end;                        /* produce until here, then call gz_lg_out_step */
    u64 left;                       /* bytes still wanted after `flushed` (GZ_SIZE_UNKNOWN = no limit) */
    u64 total;                      /* bytes pushed so far */
} gz_lg_out;

/* fill: initial history byte value (spaces for LHA, zeros otherwise) */
void gz_lg_out_init(gz_lg_out *o, const gz_stream_io *io, u8 *buf, u32 hist, u64 out_size, int fill);
/* Called when out reached end: pushes data if the chunk is full and recomputes end.
 * Returns GZ_OK, a sink error, or 1 when out_size bytes have been produced. */
int  gz_lg_out_step(gz_lg_out *o);
/* push everything produced so far */
int  gz_lg_out_finish(gz_lg_out *o);

/* LZ77 copy of len bytes from dist back (dist <= out - buf, len <= end - out). */
GZ_INLINE u8 *gz_lg_copy(u8 *out, u32 dist, u32 len)
{
    const u8 *s = out - dist;
    if (dist >= 8) {
        u8 *e = out + len;
        do { u64 v; __builtin_memcpy(&v, s, 8); __builtin_memcpy(out, &v, 8); out += 8; s += 8; } while (out < e);
        return e;
    }
    while (len--) *out++ = *s++;
    return out;
}

#endif
