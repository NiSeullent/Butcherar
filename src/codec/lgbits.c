/*
 * 고깃ZIP - slow paths of the legacy codec bit reader and output window
 */
#include "lgbits.h"

void gz_lg_in_init(gz_lg_in *b, const gz_stream_io *io, u8 *buf)
{
    b->io = io;
    b->buf = buf;
    b->p = b->end = buf;
    b->bb = 0;
    b->bc = 0;
    b->pad = 0;
    b->eof = 0;
    b->err = 0;
    b->nread = 0;
}

/* next byte of input, or -1 at the end (after which zeros are padded) */
static int next_byte(gz_lg_in *b)
{
    if (b->p < b->end) return *b->p++;
    if (b->eof || b->err) return -1;
    u32 got = 0;
    int r = b->io->read(b->io->ctx, b->buf, GZ_LG_ICAP, &got);
    if (r) { b->err = r; return -1; }
    if (!got) { b->eof = 1; return -1; }
    b->nread += got;
    b->p = b->buf;
    b->end = b->buf + got;
    __builtin_memset(b->buf + got, 0, GZ_LG_IPAD);
    return *b->p++;
}

int gz_lg_fill_lsb(gz_lg_in *b)
{
    while (b->bc <= 56) {
        int c = next_byte(b);
        if (c < 0) {
            if (b->err) return b->err;
            if (++b->pad > GZ_LG_PADMAX) { b->err = GZ_E_TRUNC; return b->err; }
            b->bc += 8;               /* zero bits: bits above bc are already 0 */
            continue;
        }
        b->bb |= (u64)(u8)c << b->bc;
        b->bc += 8;
        /* fast refill again once the new buffer is there */
        if (b->end - b->p >= 8 && b->bc <= 56) {
            b->bb |= rd64(b->p) << b->bc;
            b->p += (63 - b->bc) >> 3;
            b->bc |= 56;
        }
    }
    return 0;
}

int gz_lg_fill_msb(gz_lg_in *b)
{
    while (b->bc <= 56) {
        int c = next_byte(b);
        if (c < 0) {
            if (b->err) return b->err;
            if (++b->pad > GZ_LG_PADMAX) { b->err = GZ_E_TRUNC; return b->err; }
            b->bc += 8;
            continue;
        }
        b->bb |= (u64)(u8)c << (56 - b->bc);
        b->bc += 8;
        if (b->end - b->p >= 8 && b->bc <= 56) {
            b->bb |= rd64be(b->p) >> b->bc;
            b->p += (63 - b->bc) >> 3;
            b->bc |= 56;
        }
    }
    return 0;
}

/* ---------------- output window ---------------- */

static void set_end(gz_lg_out *o)
{
    u8 *lim = o->buf + o->hist + GZ_LG_OCHUNK;
    o->end = lim;
    if (o->left != GZ_SIZE_UNKNOWN && o->left < (u64)(lim - o->flushed)) o->end = o->flushed + o->left;
}

void gz_lg_out_init(gz_lg_out *o, const gz_stream_io *io, u8 *buf, u32 hist, u64 out_size, int fill)
{
    o->io = io;
    o->buf = buf;
    o->hist = hist;
    if (hist) __builtin_memset(buf, fill, hist);
    o->out = o->flushed = buf + hist;
    o->left = out_size;
    o->total = 0;
    set_end(o);
}

static int push(gz_lg_out *o)
{
    size_t n = (size_t)(o->out - o->flushed);
    if (!n) return GZ_OK;
    int r = o->io->write(o->io->ctx, o->flushed, n);
    o->total += n;
    if (o->left != GZ_SIZE_UNKNOWN) o->left -= n;
    o->flushed = o->out;
    return r;
}

int gz_lg_out_step(gz_lg_out *o)
{
    if (o->left != GZ_SIZE_UNKNOWN && (u64)(o->out - o->flushed) >= o->left) return 1;
    if (o->out >= o->buf + o->hist + GZ_LG_OCHUNK) {
        int r = push(o);
        if (r) return r;
        /* slide the history to the front */
        __builtin_memmove(o->buf, o->out - o->hist, o->hist);
        o->out = o->flushed = o->buf + o->hist;
    }
    set_end(o);
    return GZ_OK;
}

int gz_lg_out_finish(gz_lg_out *o)
{
    return push(o);
}
