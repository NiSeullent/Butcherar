/*
 * 고깃ZIP - ZIP Implode (method 6) decoder
 *
 * Stream layout (APPNOTE 5.3, Info-ZIP explode.c): the Shannon-Fano trees come
 * first as byte lists (count-1, then (codes-1) << 4 | (bits-1) per byte), then
 * LSB-first bit data: 1 = literal (tree or 8 raw bits), 0 = match: 6/7 raw low
 * distance bits, distance tree (high 6 bits), length tree (63 = +8 raw bits).
 * The codes are canonical Huffman codes with every bit inverted.
 */
#include "implode.h"
#include "lgbits.h"

#define IM_FB    10                     /* primary table bits */
#define IM_SLOW  0xFFFEu                /* code longer than IM_FB bits */
#define IM_BAD   0xFFFFu                /* no code */
#define IM_HIST  8192u

typedef struct {
    u16 fast[1u << IM_FB];              /* sym | len << 8 */
    u16 cnt[17];
    u16 sorted[256];
} im_tree;

struct gz_implode_dec {
    im_tree lit, len, dist;
    u8 *ibuf, *obuf;
    size_t mem_size;
};

gz_implode_dec *gz_implode_dec_new(void)
{
    size_t hs = (sizeof(gz_implode_dec) + 63) & ~(size_t)63;
    size_t is = GZ_LG_ICAP + GZ_LG_IPAD + 64;
    size_t total = hs + is + IM_HIST + GZ_LG_OCHUNK + GZ_LG_OMARGIN;
    u8 *m = (u8 *)gz_alloc_big(total);
    if (!m) return 0;
    gz_implode_dec *d = (gz_implode_dec *)m;
    d->ibuf = m + hs;
    d->obuf = m + hs + is;
    d->mem_size = total;
    return d;
}

void gz_implode_dec_free(gz_implode_dec *d)
{
    if (d) gz_free_big(d, d->mem_size);
}

void *gz_implode_slot_new(void) { return gz_implode_dec_new(); }
void gz_implode_slot_free(void *d) { gz_implode_dec_free((gz_implode_dec *)d); }

static u32 bitrev(u32 v, u32 n)
{
    u32 r = 0;
    while (n--) { r = (r << 1) | (v & 1); v >>= 1; }
    return r;
}

/* Read a tree description (n symbols) and build its decode table. */
static int im_tree_read(gz_lg_in *in, im_tree *t, u32 n)
{
    u8 lens[256];
    if (gz_lg_need_lsb(in, 8)) return in->err;
    u32 pairs = gz_lg_peek_lsb(in, 8) + 1, k = 0;
    gz_lg_drop_lsb(in, 8);
    while (pairs--) {
        if (gz_lg_need_lsb(in, 8)) return in->err;
        u32 b = gz_lg_peek_lsb(in, 8);
        gz_lg_drop_lsb(in, 8);
        u32 bits = (b & 15) + 1, cnt = (b >> 4) + 1;
        if (k + cnt > n) return GZ_E_DATA;
        while (cnt--) lens[k++] = (u8)bits;
    }
    if (k != n || gz_lg_overrun(in)) return GZ_E_DATA;

    u16 offs[18];
    for (u32 i = 0; i < 17; i++) t->cnt[i] = 0;
    for (u32 i = 0; i < n; i++) t->cnt[lens[i]]++;
    int left = 1;
    for (u32 l = 1; l <= 16; l++) {
        left = left * 2 - t->cnt[l];
        if (left < 0) return GZ_E_DATA;        /* over-subscribed */
    }
    offs[1] = 0;
    for (u32 l = 1; l <= 16; l++) offs[l + 1] = (u16)(offs[l] + t->cnt[l]);
    for (u32 i = 0; i < n; i++) t->sorted[offs[lens[i]]++] = (u16)i;

    for (u32 i = 0; i < (1u << IM_FB); i++) t->fast[i] = IM_BAD;
    u32 code = 0, si = 0;
    for (u32 l = 1; l <= 16; l++) {
        for (u32 j = 0; j < t->cnt[l]; j++, si++) {
            u32 sym = t->sorted[si];
            if (l <= IM_FB) {
                for (u32 x = bitrev(code, l); x < (1u << IM_FB); x += 1u << l)
                    t->fast[x] = (u16)(sym | l << 8);
            } else {
                t->fast[bitrev(code >> (l - IM_FB), IM_FB)] = IM_SLOW;
            }
            code++;
        }
        code <<= 1;
    }
    return GZ_OK;
}

/* Decode one symbol; bits must hold >= 16 valid bits. Returns symbol or -1. */
GZ_INLINE int im_decode(const im_tree *t, gz_lg_in *in)
{
    u32 inv = ~(u32)in->bb;                    /* the codes are stored inverted */
    u32 e = t->fast[inv & ((1u << IM_FB) - 1)];
    if (GZ_LIKELY(e < IM_SLOW)) {
        gz_lg_drop_lsb(in, e >> 8);
        return (int)(e & 0xff);
    }
    if (e == IM_BAD) return -1;
    /* canonical decode bit by bit (puff.c style) */
    u32 code = 0, first = 0, index = 0;
    for (u32 l = 1; l <= 16; l++) {
        code |= inv & 1;
        inv >>= 1;
        u32 c = t->cnt[l];
        if (code < first + c) {
            gz_lg_drop_lsb(in, l);
            return t->sorted[index + code - first];
        }
        index += c;
        first = (first + c) << 1;
        code <<= 1;
    }
    return -1;
}

static int implode_run(gz_implode_dec *d, const gz_stream_io *io, u64 out_size, int large, int three)
{
    gz_lg_in in;
    gz_lg_in_init(&in, io, d->ibuf);
    gz_lg_out o;
    gz_lg_out_init(&o, io, d->obuf, IM_HIST, out_size, 0);

    int st;
    if (three && (st = im_tree_read(&in, &d->lit, 256))) return st;
    if ((st = im_tree_read(&in, &d->len, 64))) return st;
    if ((st = im_tree_read(&in, &d->dist, 64))) return st;
    const u32 dl = large ? 7 : 6, minm = three ? 3 : 2;
    const u64 known = out_size;

    for (;;) {
        if (o.out >= o.end) {
            int r = gz_lg_out_step(&o);
            if (r == 1) break;
            if (r) { st = r; break; }
        }
        if (gz_lg_need_lsb(&in, 49)) { st = in.err; break; }
        if (GZ_UNLIKELY(in.pad) && gz_lg_overrun(&in)) {
            st = known != GZ_SIZE_UNKNOWN ? GZ_E_TRUNC : GZ_OK;
            break;
        }
        u32 flag = (u32)in.bb & 1;
        gz_lg_drop_lsb(&in, 1);
        if (flag) {
            int c;
            if (three) {
                c = im_decode(&d->lit, &in);
                if (c < 0) { st = GZ_E_DATA; break; }
            } else {
                c = (int)gz_lg_peek_lsb(&in, 8);
                gz_lg_drop_lsb(&in, 8);
            }
            if (GZ_UNLIKELY(in.pad) && gz_lg_overrun(&in) && known == GZ_SIZE_UNKNOWN) break;
            *o.out++ = (u8)c;
            continue;
        }
        u32 dist = gz_lg_peek_lsb(&in, dl);
        gz_lg_drop_lsb(&in, dl);
        int hi = im_decode(&d->dist, &in);
        int l = im_decode(&d->len, &in);
        if (hi < 0 || l < 0) { st = GZ_E_DATA; break; }
        dist += ((u32)hi << dl) + 1;
        u32 n = (u32)l;
        if (n == 63) {
            n += gz_lg_peek_lsb(&in, 8);
            gz_lg_drop_lsb(&in, 8);
        }
        n += minm;
        if (GZ_UNLIKELY(in.pad) && gz_lg_overrun(&in) && known == GZ_SIZE_UNKNOWN) break;
        if (o.left != GZ_SIZE_UNKNOWN && n > o.left - (u64)(o.out - o.flushed))
            n = (u32)(o.left - (u64)(o.out - o.flushed));
        o.out = gz_lg_copy(o.out, dist, n);    /* dist <= 8192 = history (zeros at start) */
    }
    int r = gz_lg_out_finish(&o);
    if (st == GZ_OK) st = r;
    if (st == GZ_OK && known != GZ_SIZE_UNKNOWN && o.total < known) st = GZ_E_TRUNC;
    return st;
}

int gz_implode_decode(gz_implode_dec *d, const gz_stream_io *io, u64 out_size,
                      int large_window, int three_trees)
{
    if (d) return implode_run(d, io, out_size, large_window, three_trees);
    d = gz_implode_dec_new();
    if (!d) return GZ_E_NOMEM;
    int r = implode_run(d, io, out_size, large_window, three_trees);
    gz_implode_dec_free(d);
    return r;
}
