/*
 * 고깃ZIP - BCJ2 decoder (see bcj2.h; format as in 7-Zip's Bcj2.c, public domain)
 */
#include "bcj2.h"

#define B2_IBUF  4096u
#define B2_OBUF  32768u

enum { S_CALL, S_JUMP, S_RC };

typedef struct {
    const gz_stream_io *io;
    u32 pos, len;
    int eof;
    u8 buf[B2_IBUF];
} b2_in;

struct gz_bcj2_dec {
    b2_in in[3];
    u16 probs[2 + 256];          /* [0] Jcc, [1] E9, [2 + prev] E8 */
    u32 range, code;
    int rc_ready;
    u32 ip;                      /* output position, mod 2^32 */
    u64 out_size, out_done;
    u32 prev;                    /* previous output byte */
    int err;                     /* sticky error */
    int (*sink)(void *, const u8 *, size_t);
    void *sink_ctx;
    u32 on;
    u8 out[B2_OBUF];
};

gz_bcj2_dec *gz_bcj2_dec_new(void) { return (gz_bcj2_dec *)gz_alloc(sizeof(gz_bcj2_dec)); }
void gz_bcj2_dec_free(gz_bcj2_dec *d) { gz_free(d); }

int gz_bcj2_mem_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    gz_bcj2_mem *m = (gz_bcj2_mem *)ctx;
    size_t k = m->n < cap ? m->n : cap;
    __builtin_memcpy(buf, m->p, k);
    m->p += k;
    m->n -= k;
    *got = (u32)k;
    return GZ_OK;
}

int gz_bcj2_dec_init(gz_bcj2_dec *d, const gz_stream_io *call, const gz_stream_io *jump,
                     const gz_stream_io *rc, u64 out_size,
                     int (*sink)(void *ctx, const u8 *p, size_t n), void *sink_ctx)
{
    const gz_stream_io *ios[3] = { call, jump, rc };
    for (int i = 0; i < 3; i++) {
        d->in[i].io = ios[i];
        d->in[i].pos = d->in[i].len = 0;
        d->in[i].eof = 0;
    }
    for (u32 i = 0; i < GZ_COUNTOF(d->probs); i++) d->probs[i] = 1024;
    d->range = d->code = 0;
    d->rc_ready = 0;
    d->ip = 0;
    d->out_size = out_size;
    d->out_done = 0;
    d->prev = 0;
    d->err = 0;
    d->sink = sink;
    d->sink_ctx = sink_ctx;
    d->on = 0;
    return GZ_OK;
}

/* next byte of input stream s; GZ_E_DATA when it has ended */
static int b2_byte(gz_bcj2_dec *d, int s, u32 *v)
{
    b2_in *in = &d->in[s];
    if (in->pos == in->len) {
        if (in->eof) return GZ_E_DATA;
        u32 got = 0;
        int r = in->io->read(in->io->ctx, in->buf, B2_IBUF, &got);
        if (r) return r;
        if (got > B2_IBUF) return GZ_E_IO;
        in->pos = 0;
        in->len = got;
        if (!got) { in->eof = 1; return GZ_E_DATA; }
    }
    *v = in->buf[in->pos++];
    return GZ_OK;
}

static int b2_flush(gz_bcj2_dec *d)
{
    u32 n = d->on;
    d->on = 0;
    return n ? d->sink(d->sink_ctx, d->out, n) : GZ_OK;
}

static int b2_emit(gz_bcj2_dec *d, const u8 *p, size_t n)
{
    while (n) {
        size_t k = B2_OBUF - d->on;
        if (k > n) k = n;
        __builtin_memcpy(d->out + d->on, p, k);
        d->on += (u32)k;
        p += k;
        n -= k;
        if (d->on == B2_OBUF) {
            int r = b2_flush(d);
            if (r) return r;
        }
    }
    return GZ_OK;
}

/* one range coder bit with probability index i */
static int b2_bit(gz_bcj2_dec *d, u32 i, u32 *bit)
{
    u32 v;
    int r;
    if (!d->rc_ready) {
        u32 code = 0;
        for (int k = 0; k < 5; k++) {
            if ((r = b2_byte(d, S_RC, &v))) return r;
            if (k == 0 && v) return GZ_E_DATA;
            code = (code << 8) | v;
        }
        if (code == 0xFFFFFFFFu) return GZ_E_DATA;
        d->code = code;
        d->range = 0xFFFFFFFFu;
        d->rc_ready = 1;
    }
    if (d->range < (1u << 24)) {
        if ((r = b2_byte(d, S_RC, &v))) return r;
        d->range <<= 8;
        d->code = (d->code << 8) | v;
    }
    u32 ttt = d->probs[i];
    u32 bound = (d->range >> 11) * ttt;
    if (d->code < bound) {
        d->range = bound;
        d->probs[i] = (u16)(ttt + ((2048 - ttt) >> 5));
        *bit = 0;
    } else {
        d->range -= bound;
        d->code -= bound;
        d->probs[i] = (u16)(ttt - (ttt >> 5));
        *bit = 1;
    }
    return GZ_OK;
}

int gz_bcj2_dec_write(void *ctx, const u8 *p, size_t n)
{
    gz_bcj2_dec *d = (gz_bcj2_dec *)ctx;
    int r;
    if (d->err) return d->err;
    while (n) {
        u64 left = d->out_size - d->out_done;     /* GZ_SIZE_UNKNOWN: effectively unlimited */
        if (!left) return GZ_OK;
        size_t lim = left < n ? (size_t)left : n;

        /* copy up to the next marker: E8, E9, or 0F 8x */
        u32 prev = d->prev;
        size_t i = 0;
        while (i < lim) {
            u32 b = p[i];
            if ((b & 0xFE) == 0xE8 || (prev == 0x0F && (b & 0xF0) == 0x80)) break;
            prev = b;
            i++;
        }
        if (i == lim) {
            if ((r = b2_emit(d, p, i))) goto fail;
            d->prev = prev;
            d->out_done += i;
            d->ip += (u32)i;
            p += i;
            n -= i;
            continue;
        }
        const u32 b = p[i];
        i++;
        if ((r = b2_emit(d, p, i))) goto fail;
        d->out_done += i;
        d->ip += (u32)i;
        p += i;
        n -= i;
        if (d->out_done == d->out_size) { d->prev = b; return GZ_OK; }

        u32 bit;
        r = b2_bit(d, b == 0xE8 ? 2 + prev : b == 0xE9 ? 1 : 0, &bit);
        if (r) goto fail;
        if (!bit) { d->prev = b; continue; }

        /* converted: the absolute target comes from CALL (E8) or JUMP */
        int s = b == 0xE8 ? S_CALL : S_JUMP;
        u32 v = 0;
        b2_in *in = &d->in[s];
        if (in->len - in->pos >= 4) {
            v = rd32be(in->buf + in->pos);
            in->pos += 4;
        } else {
            for (int k = 0; k < 4; k++) {
                u32 c;
                if ((r = b2_byte(d, s, &c))) goto fail;
                v = (v << 8) | c;
            }
        }
        d->ip += 4;
        v -= d->ip;
        u8 t[4];
        wr32(t, v);
        u64 k = d->out_size - d->out_done;
        if (k > 4) k = 4;
        if ((r = b2_emit(d, t, (size_t)k))) goto fail;
        d->out_done += k;
        d->prev = v >> 24;
    }
    return GZ_OK;
fail:
    d->err = r;
    return r;
}

int gz_bcj2_dec_finish(gz_bcj2_dec *d)
{
    if (d->err) return d->err;
    int r = b2_flush(d);
    if (r) { d->err = r; return r; }
    if (d->out_size != GZ_SIZE_UNKNOWN && d->out_done != d->out_size) return GZ_E_DATA;
    return GZ_OK;
}
