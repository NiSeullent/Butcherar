/*
 * 고깃ZIP - RAR 5.0 unpacker (see rar5dec.h)
 *
 * Window: a power-of-two ring, positions are 64-bit stream offsets (pos)
 * and the window index is pos & mask. The hot loop (lz) decodes symbols
 * while the input pointer is below p_lim (enough buffered input and at least
 * 128 bits before the block end) and the window index is below wp_stop (no
 * wrap within one match, unflushed data within bounds). Everything else -
 * input refill, block headers and tables, flushing, window wrap - happens in
 * sync(), which also single-steps the loop near those borders.
 *
 * Bit input is MSB first: a 64-bit buffer refilled branch-free from
 * big-endian 8-byte loads (the input buffer has zero padding at its end).
 *
 * Filters keep stream positions; flush() writes plain window data up to a
 * filter's start, then the filtered copy once the filter's block has been
 * decoded completely, so window data stays unfiltered for later matches.
 */
#include "rar5dec.h"

#define NC        306
#define DC5       64
#define DC7       80
#define LDC       16
#define RC        44
#define BC        20
#define TAB_MAX   (NC + DC7 + LDC + RC)
#define MAXM      4100u            /* longest match: 0x1001 + 3 */
#define MIN_WIN   (1u << 18)
#define IN_CAP    (256u << 10)
#define IN_PAD    64u
#define MAX_FILTERS    8192u
#define MAX_FILTER_LEN (1u << 22)
#define R5_END    (-1)

/* quick-lookup widths (bits) per table */
#define QB_MAIN 10
#define QB_DIST 9
#define QB_LOW  7
#define QB_LEN  9
#define QB_BD   7

enum { F_DELTA = 0, F_E8 = 1, F_E8E9 = 2, F_ARM = 3 };

typedef struct {
    u32 lim[17];             /* left-justified 16-bit end of the codes of length <= L */
    u16 pos[17];             /* index in sym[] of the first code of length L          */
    u16 sym[NC];             /* symbols ordered by (length, value)                    */
    u16 quick[1 << QB_MAIN]; /* sym << 4 | length, 0 = longer than the quick width    */
} huff;

typedef struct { u64 start; u32 len; u8 type, ch; u8 pad_[2]; } r5_flt;

struct gz_rar5_dec {
    /* window */
    u8 *win;
    size_t wsize, wmask;
    size_t wp;               /* next window index to write                            */
    size_t wp_sync;          /* wp at the last sync                                   */
    size_t wp_stop;          /* the fast loop stops here                              */
    u64 pos;                 /* stream position of wp_sync                            */
    u64 wr;                  /* stream position written out                           */
    int full;                /* all window bytes hold decoded data                    */
    /* LZ state kept across solid files */
    u64 rep[4];
    u32 lastlen;
    int tables_ok, state_ok, v7, low_raw;
    huff tmain, tdist, tlow, tlen, tbd;
    /* bit input */
    u8 *in;
    const u8 *p, *in_end, *p_lim;
    u64 bb;
    u32 bc;
    int in_eof;
    u64 in_base;             /* packed stream offset of in[0]                         */
    u64 blk_end;             /* bit offset of the end of the current block            */
    int blk_last;
    /* filters (pending, in stream order) */
    r5_flt *flt;
    u32 nflt, fhead, fcap;
    u64 flt_end;
    u8 *fbuf;
    u32 fbuf_cap;
    /* current call */
    const gz_stream_io *io;
    u64 file_start, out_size, out_done, thresh;
};

/* length slot -> base / extra bits */
static const u16 lbase[RC] = {
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 18, 22, 26, 30, 34, 42, 50, 58, 66, 82, 98, 114,
    130, 162, 194, 226, 258, 322, 386, 450, 514, 642, 770, 898, 1026, 1282, 1538, 1794,
    2050, 2562, 3074, 3586 };
static const u8 lbits[RC] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4,
    5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 9, 9, 9, 9 };

/* ---------------- Huffman tables ---------------- */

static int huff_build(huff *h, const u8 *len, u32 n, u32 qb)
{
    u32 cnt[16], next[16];
    __builtin_memset(cnt, 0, sizeof cnt);
    for (u32 i = 0; i < n; i++) cnt[len[i]]++;
    u32 code = 0, idx = 0;
    h->lim[0] = 0;
    h->pos[0] = 0;
    for (u32 l = 1; l <= 15; l++) {
        h->pos[l] = (u16)idx;
        next[l] = idx;
        idx += cnt[l];
        if (code + cnt[l] > (1u << l)) return 0;          /* over-subscribed */
        h->lim[l] = (code + cnt[l]) << (16 - l);
        code = (code + cnt[l]) << 1;
    }
    h->lim[16] = h->lim[15];
    for (u32 i = 0; i < n; i++)
        if (len[i]) h->sym[next[len[i]]++] = (u16)i;
    __builtin_memset(h->quick, 0, sizeof(u16) << qb);
    for (u32 l = 1; l <= qb; l++) {
        u32 c = h->lim[l - 1] >> (16 - l), step = 1u << (qb - l);
        for (u32 j = 0; j < cnt[l]; j++, c++) {
            u16 v = (u16)(h->sym[h->pos[l] + j] << 4 | l);
            u16 *q = h->quick + (c << (qb - l));
            for (u32 t = 0; t < step; t++) q[t] = v;
        }
    }
    return 1;
}

/* code longer than the quick width (or invalid: 0) for the 16 bits v */
static GZ_NOINLINE u32 huff_slow(const huff *h, u32 v, u32 qb)
{
    for (u32 l = qb + 1; l <= 15; l++)
        if (v < h->lim[l]) return (u32)h->sym[h->pos[l] + ((v - h->lim[l - 1]) >> (16 - l))] << 4 | l;
    return 0;
}

/* ---------------- bit input ---------------- */

GZ_INLINE u64 rd64be_(const u8 *p) { return __builtin_bswap64(rd64(p)); }

#define REFILL()   do { bb |= rd64be_(p) >> bc; p += (63 - bc) >> 3; bc |= 56; } while (0)
#define GETBITS(n) ((bb >> (63 - (n))) >> 1)        /* n = 0..63 */
#define DROP(n)    do { bb <<= (n); bc -= (n); } while (0)
#define DECODE(h, qb, out) do { \
        u32 v_ = (u32)(bb >> 48); \
        u32 q_ = (h)->quick[v_ >> (16 - (qb))]; \
        if (GZ_UNLIKELY(!(q_ & 15))) { q_ = huff_slow((h), v_, (qb)); if (!q_) goto bad; } \
        DROP(q_ & 15); \
        (out) = q_ >> 4; \
    } while (0)
#define LOADBITS() const u8 *p = d->p; u64 bb = d->bb; u32 bc = d->bc
#define SAVEBITS() do { d->p = p; d->bb = bb; d->bc = bc; } while (0)

static u64 bitpos(const gz_rar5_dec *d)
{
    return (d->in_base + (u64)(d->p - d->in)) * 8 - d->bc;
}

static u64 in_end_bits(const gz_rar5_dec *d)
{
    return (d->in_base + (u64)(d->in_end - d->in)) * 8;
}

/* Keep the unread tail and read until the buffer is full or the input ends. */
static int fill(gz_rar5_dec *d)
{
    size_t keep = d->p < d->in_end ? (size_t)(d->in_end - d->p) : 0;
    if (d->p != d->in) {
        if (keep) __builtin_memmove(d->in, d->p, keep);
        d->in_base += (u64)(d->p - d->in);
        d->p = d->in;
    }
    u32 n = (u32)keep;
    while (!d->in_eof && n + 4096 <= IN_CAP) {
        u32 got = 0;
        int r = d->io->read(d->io->ctx, d->in + n, IN_CAP - n, &got);
        if (r) return r;
        if (!got) { d->in_eof = 1; break; }
        if (got > IN_CAP - n) return GZ_E_IO;
        n += got;
    }
    d->in_end = d->in + n;
    __builtin_memset(d->in + n, 0, IN_PAD);
    return GZ_OK;
}

static int need(gz_rar5_dec *d)
{
    return (!d->in_eof && d->p + 32 > d->in_end) ? fill(d) : GZ_OK;
}

/* ---------------- block header and tables ---------------- */

static int read_tables(gz_rar5_dec *d)
{
    u8 bl[BC], lens[TAB_MAX];
    int r;
    for (u32 i = 0; i < BC;) {
        if ((r = need(d))) return r;
        LOADBITS();
        REFILL();
        u32 l = (u32)GETBITS(4);
        DROP(4);
        if (l == 15) {
            u32 z = (u32)GETBITS(4);
            DROP(4);
            if (!z) bl[i++] = 15;
            else for (z += 2; z-- && i < BC;) bl[i++] = 0;
        } else {
            bl[i++] = (u8)l;
        }
        SAVEBITS();
    }
    if (!huff_build(&d->tbd, bl, BC, QB_BD)) return GZ_E_DATA;
    const u32 ndist = d->v7 ? DC7 : DC5, n = NC + ndist + LDC + RC;
    for (u32 i = 0; i < n;) {
        if ((r = need(d))) return r;
        LOADBITS();
        REFILL();
        u32 s;
        DECODE(&d->tbd, QB_BD, s);
        if (s < 16) {
            lens[i++] = (u8)s;
        } else {
            u32 c;
            if (s & 1) { c = (u32)GETBITS(7) + 11; DROP(7); }
            else { c = (u32)GETBITS(3) + 3; DROP(3); }
            u8 v = 0;
            if (s < 18) {
                if (!i) goto bad;
                v = lens[i - 1];
            }
            while (c-- && i < n) lens[i++] = v;
        }
        SAVEBITS();
        continue;
    bad:
        return GZ_E_DATA;
    }
    if (bitpos(d) > in_end_bits(d)) return GZ_E_DATA;
    if (!huff_build(&d->tmain, lens, NC, QB_MAIN) ||
        !huff_build(&d->tdist, lens + NC, ndist, QB_DIST) ||
        !huff_build(&d->tlow, lens + NC + ndist, LDC, QB_LOW) ||
        !huff_build(&d->tlen, lens + NC + ndist + LDC, RC, QB_LEN))
        return GZ_E_DATA;
    /* all low-distance codes 4 bits long: the code is the value itself */
    d->low_raw = 1;
    for (u32 i = 0; i < LDC; i++)
        if (lens[NC + ndist + i] != 4) d->low_raw = 0;
    d->tables_ok = 1;
    return GZ_OK;
}

/* Byte-aligned block header: flags, check byte, 1-3 size bytes; then tables. */
static int read_block(gz_rar5_dec *d)
{
    int r;
    d->bb <<= d->bc & 7;
    d->bc &= ~7u;
    if ((r = need(d))) return r;
    LOADBITS();
    REFILL();
    u32 flags = (u32)GETBITS(8);
    DROP(8);
    u32 chk = (u32)GETBITS(8);
    DROP(8);
    u32 nb = ((flags >> 3) & 3) + 1, size = 0;
    if (nb == 4) return GZ_E_DATA;
    for (u32 i = 0; i < nb; i++) {
        size |= (u32)GETBITS(8) << (8 * i);
        DROP(8);
    }
    SAVEBITS();
    if (((0x5A ^ flags ^ size ^ (size >> 8) ^ (size >> 16)) & 0xFF) != chk) return GZ_E_DATA;
    u64 start = bitpos(d);
    if (start > in_end_bits(d)) return GZ_E_DATA;
    u32 bits = (flags & 7) + 1;
    if ((u64)size * 8 + bits < 8) return GZ_E_DATA;
    d->blk_end = start + (u64)size * 8 + bits - 8;
    d->blk_last = (flags & 0x40) != 0;
    if (flags & 0x80) {
        if ((r = read_tables(d))) return r;
        if (bitpos(d) > d->blk_end) return GZ_E_DATA;
    } else if (!d->tables_ok && d->blk_end > start) {
        return GZ_E_DATA;
    }
    return GZ_OK;
}

/* ---------------- output and filters ---------------- */

static int emit(gz_rar5_dec *d, const u8 *p, size_t n)
{
    if (d->out_size != GZ_SIZE_UNKNOWN) {
        u64 rem = d->out_size - d->out_done;
        if (n > rem) n = (size_t)rem;
    }
    if (!n) return GZ_OK;
    d->out_done += n;
    return d->io->write(d->io->ctx, p, n);
}

static int emit_win(gz_rar5_dec *d, u64 from, u64 to)
{
    while (from < to) {
        size_t i = (size_t)from & d->wmask;
        u64 n = to - from;
        if (n > d->wsize - i) n = d->wsize - i;
        int r = emit(d, d->win + i, (size_t)n);
        if (r) return r;
        from += n;
    }
    return GZ_OK;
}

static void f_e8(u8 *b, u32 n, u32 off, int e9)
{
    if (n <= 4) return;
    const u8 c2 = e9 ? 0xE9 : 0xE8;
    /* E8 / E9 bytes are found 8 at a time: (x & m) ^ E8.. has a zero byte */
    const u64 m = e9 ? 0xFEFEFEFEFEFEFEFEull : ~0ull, k = 0xE8E8E8E8E8E8E8E8ull;
    const u64 lo = 0x0101010101010101ull, hi = 0x8080808080808080ull;
    for (u32 i = 0, lim = n - 4; i < lim;) {
        while (i + 8 <= lim) {
            u64 x = (rd64(b + i) & m) ^ k;
            if ((x - lo) & ~x & hi) break;
            i += 8;
        }
        if (i >= lim) break;
        u8 c = b[i++];
        if (c != 0xE8 && c != c2) continue;
        u32 o = (i + off) & 0xFFFFFFu, a = rd32(b + i);
        if (a < 0x1000000u) wr32(b + i, a - o);
        else if (a > 0xFFFFFFFFu - o) wr32(b + i, a + 0x1000000u);
        i += 4;
    }
}

static void f_arm(u8 *b, u32 n, u32 off)
{
    for (u32 i = 0; i + 3 < n; i += 4) {
        u8 *q = b + i;
        if (q[3] != 0xEB) continue;
        u32 v = ((u32)q[0] | (u32)q[1] << 8 | (u32)q[2] << 16) - ((off + i) >> 2);
        q[0] = (u8)v;
        q[1] = (u8)(v >> 8);
        q[2] = (u8)(v >> 16);
    }
}

static void f_delta(const u8 *s, u8 *o, u32 n, u32 ch)
{
    for (u32 c = 0; c < ch; c++) {
        u8 prev = 0;
        for (u32 i = c; i < n; i += ch) o[i] = prev = (u8)(prev - *s++);
    }
}

static int run_filter(gz_rar5_dec *d, const r5_flt *f)
{
    u32 n = f->len;
    if (d->fbuf_cap < 2 * n) {
        gz_free(d->fbuf);
        d->fbuf_cap = 0;
        d->fbuf = (u8 *)gz_alloc((size_t)2 * n);
        if (!d->fbuf) return GZ_E_NOMEM;
        d->fbuf_cap = 2 * n;
    }
    u8 *b = d->fbuf;
    size_t i = (size_t)f->start & d->wmask, first = d->wsize - i;
    if (first > n) first = n;
    __builtin_memcpy(b, d->win + i, first);
    if (n > first) __builtin_memcpy(b + first, d->win, n - first);
    u32 off = (u32)(f->start - d->file_start);
    switch (f->type) {
    case F_E8:   f_e8(b, n, off, 0); break;
    case F_E8E9: f_e8(b, n, off, 1); break;
    case F_ARM:  f_arm(b, n, off); break;
    default:     f_delta(b, b + n, n, f->ch); b += n; break;
    }
    return emit(d, b, n);
}

/* Write decoded data up to stream position `to`, applying filters. A filter
 * whose block is not complete yet holds back everything from its start. */
static int flush(gz_rar5_dec *d, u64 to)
{
    int r;
    while (d->wr < to) {
        if (d->fhead < d->nflt && d->flt[d->fhead].start < to) {
            const r5_flt *f = &d->flt[d->fhead];
            if (f->start > d->wr) {
                if ((r = emit_win(d, d->wr, f->start))) return r;
                d->wr = f->start;
            }
            if (f->start + f->len > to) break;
            if ((r = run_filter(d, f))) return r;
            d->wr += f->len;
            d->fhead++;
            continue;
        }
        if ((r = emit_win(d, d->wr, to))) return r;
        d->wr = to;
    }
    if (d->fhead == d->nflt) d->fhead = d->nflt = 0;
    return GZ_OK;
}

static void advance(gz_rar5_dec *d)
{
    d->pos += (u64)((d->wp - d->wp_sync) & d->wmask);
    d->wp_sync = d->wp;
    if (d->pos >= d->wsize) d->full = 1;
}

/* Filter symbol: start offset and length (1-4 byte numbers), type, channels. */
static GZ_NOINLINE int read_filter(gz_rar5_dec *d)
{
    u32 v[2];
    LOADBITS();
    for (int k = 0; k < 2; k++) {
        REFILL();
        u32 nb = (u32)GETBITS(2) + 1, x = 0;
        DROP(2);
        for (u32 i = 0; i < nb; i++) {
            x |= (u32)GETBITS(8) << (8 * i);
            DROP(8);
        }
        v[k] = x;
    }
    REFILL();
    u32 type = (u32)GETBITS(3), ch = 0;
    DROP(3);
    if (type == F_DELTA) {
        ch = (u32)GETBITS(5) + 1;
        DROP(5);
    }
    SAVEBITS();
    if (type > F_ARM || v[1] > MAX_FILTER_LEN) return GZ_E_DATA;
    advance(d);
    u64 start = d->pos + v[0];
    if (start < d->flt_end) return GZ_E_DATA;          /* overlapping / out of order */
    d->flt_end = start + v[1];
    if (!v[1]) return GZ_OK;
    if (d->nflt - d->fhead >= MAX_FILTERS) {
        int r = flush(d, d->pos);
        if (r) return r;
        if (d->nflt - d->fhead >= MAX_FILTERS) return GZ_E_DATA;
    }
    if (d->nflt == d->fcap) {
        if (d->fhead) {
            __builtin_memmove(d->flt, d->flt + d->fhead, (size_t)(d->nflt - d->fhead) * sizeof(r5_flt));
            d->nflt -= d->fhead;
            d->fhead = 0;
        }
        if (d->nflt == d->fcap) {
            u32 nc = d->fcap ? d->fcap * 2 : 64;
            r5_flt *nf = (r5_flt *)gz_realloc(d->flt, (size_t)nc * sizeof(r5_flt));
            if (!nf) return GZ_E_NOMEM;
            d->flt = nf;
            d->fcap = nc;
        }
    }
    r5_flt *f = &d->flt[d->nflt++];
    f->start = start;
    f->len = v[1];
    f->type = (u8)type;
    f->ch = (u8)ch;
    return GZ_OK;
}

/* ---------------- loop control ---------------- */

/* Account decoded bytes, refill input, switch blocks, flush, set the fast-loop
 * limits. GZ_OK: continue (single-step if still at a limit), R5_END, or error. */
static int sync(gz_rar5_dec *d)
{
    int r;
    const u64 w = d->wsize;
    advance(d);
    if (d->out_size != GZ_SIZE_UNKNOWN && d->pos - d->file_start > d->out_size) return GZ_E_DATA;
    if ((r = need(d))) return r;
    u64 cur = bitpos(d);
    if (cur > in_end_bits(d)) return GZ_E_DATA;
    while (cur >= d->blk_end) {
        if (cur > d->blk_end) return GZ_E_DATA;
        if (d->blk_last) return R5_END;
        if ((r = read_block(d))) return r;
        cur = bitpos(d);
    }
    u64 unfl = d->pos - d->wr;
    if (unfl >= d->thresh) {
        if ((r = flush(d, d->pos))) return r;
        unfl = d->pos - d->wr;
    }
    u64 room = unfl < d->thresh ? d->thresh - unfl : 0;
    if (!room) {
        /* a filter block holds back the output: use the rest of the window */
        u64 hard = w - 2 * MAXM;
        if (unfl >= hard) return GZ_E_DATA;
        room = hard - unfl;
    }
    size_t wlim = (size_t)w - MAXM;
    if (d->wp >= wlim) {
        d->wp_stop = 0;
    } else {
        u64 n = wlim - d->wp;
        d->wp_stop = d->wp + (size_t)(n < room ? n : room);
    }
    u64 avail = d->in_base + (u64)(d->in_end - d->in);
    u64 lim = avail > 32 ? avail - 32 : 0, be = d->blk_end >> 3;
    be = be > 16 ? be - 16 : 0;
    if (be < lim) lim = be;
    d->p_lim = lim > d->in_base ? d->in + (size_t)(lim - d->in_base) : d->in;
    return GZ_OK;
}

/* The LZ state lives in locals here: window stores through u8 pointers could
 * alias the decoder struct and force reloads otherwise. It is written back
 * before every call that reads it and on return. */
#define LZ_SAVE() do { \
        SAVEBITS(); d->wp = wp; d->lastlen = lastlen; \
        d->rep[0] = r0; d->rep[1] = r1; d->rep[2] = r2; d->rep[3] = r3; \
    } while (0)

static int lz(gz_rar5_dec *d)
{
    u8 *const win = d->win;
    const size_t mask = d->wmask, wsize = d->wsize;
    const huff *const tm = &d->tmain, *const td = &d->tdist, *const tl = &d->tlow, *const tr = &d->tlen;
    size_t wp = d->wp;
    LOADBITS();
    u64 r0 = d->rep[0], r1 = d->rep[1], r2 = d->rep[2], r3 = d->rep[3];
    u32 lastlen = d->lastlen;
    const u8 *p_lim = p;
    size_t wp_stop = 0, wfull = 0;
    int low_raw = d->low_raw, r;
    for (;;) {
        if (GZ_UNLIKELY(p >= p_lim || wp >= wp_stop)) {
            LZ_SAVE();
            if ((r = sync(d))) return r;
            p = d->p;
            bb = d->bb;
            bc = d->bc;
            p_lim = d->p_lim;
            wp_stop = d->wp_stop;
            wfull = d->full ? wsize : 0;
            low_raw = d->low_raw;
        }
        REFILL();
        u32 sym;
        DECODE(tm, QB_MAIN, sym);
        if (sym < 256) {
            win[wp] = (u8)sym;
            wp = (wp + 1) & mask;
            continue;
        }
        u32 len;
        u64 dist;
        if (sym >= 262) {
            u32 s = sym - 262;
            len = lbase[s] + (u32)GETBITS(lbits[s]);
            DROP(lbits[s]);
            REFILL();
            u32 ds;
            DECODE(td, QB_DIST, ds);
            if (ds < 4) {
                dist = ds + 1;
            } else {
                u32 nb = (ds >> 1) - 1;
                dist = ((u64)(2 | (ds & 1)) << nb) + 1;
                if (nb < 4) {
                    dist += GETBITS(nb);
                    DROP(nb);
                } else {
                    if (nb > 4) {
                        dist += GETBITS(nb - 4) << 4;
                        DROP(nb - 4);
                    }
                    if (bc < 16) REFILL();
                    if (low_raw) {
                        dist += GETBITS(4);
                        DROP(4);
                    } else {
                        u32 lo;
                        DECODE(tl, QB_LOW, lo);
                        dist += lo;
                    }
                }
                len += (dist > 0x100) + (dist > 0x2000) + (dist > 0x40000);
            }
            r3 = r2;
            r2 = r1;
            r1 = r0;
            r0 = dist;
        } else if (sym == 256) {
            LZ_SAVE();
            if ((r = read_filter(d))) return r;
            p = d->p;
            bb = d->bb;
            bc = d->bc;
            continue;
        } else if (sym == 257) {
            if (!lastlen) continue;
            len = lastlen;
            dist = r0;
        } else {
            /* repeated distance k moves to the front */
            if (sym == 258) {
                dist = r0;
            } else if (sym == 259) {
                dist = r1; r1 = r0;
            } else if (sym == 260) {
                dist = r2; r2 = r1; r1 = r0;
            } else {
                dist = r3; r3 = r2; r2 = r1; r1 = r0;
            }
            r0 = dist;
            u32 ls;
            DECODE(tr, QB_LEN, ls);
            len = lbase[ls] + (u32)GETBITS(lbits[ls]);
            DROP(lbits[ls]);
        }
        lastlen = len;
        if (GZ_UNLIKELY(dist > wp && dist > wfull)) goto bad;
        size_t src = (wp - (size_t)dist) & mask;
        /* fast copy: source behind the destination (dist >= 8: 8-byte steps are
         * exact LZ semantics), or a wrapped source that does not overlap */
        if (GZ_LIKELY(wp + len <= wsize && (src < wp || (src + len <= wsize && wp + len <= src)))) {
            u8 *o = win + wp;
            const u8 *s = win + src;
            if (dist >= 8 || src > wp) {
                if (len >= 8) {
                    u8 *e = o + len - 8;
                    const u8 *se = s + len - 8;
                    do { wr64(o, rd64(s)); o += 8; s += 8; } while (o < e);
                    wr64(e, rd64(se));
                } else if (len >= 4) {
                    u32 a = rd32(s), b = rd32(s + len - 4);
                    wr32(o, a);
                    wr32(o + len - 4, b);
                } else {
                    o[0] = s[0];
                    o[1] = s[1];
                    o[len - 1] = s[len - 1];
                }
            } else if (dist == 1 && len >= 8) {
                /* byte runs: 8-byte stores (the last one may overlap) */
                u64 v = 0x0101010101010101ull * s[0];
                u8 *e = o + len - 8;
                do { wr64(o, v); o += 8; } while (o < e);
                wr64(e, v);
            } else {
                for (u32 i = 0; i < len; i++) o[i] = s[i];
            }
            wp = (wp + len) & mask;
        } else {
            for (u32 i = 0; i < len; i++) {
                win[wp] = win[src];
                wp = (wp + 1) & mask;
                src = (src + 1) & mask;
            }
        }
    }
bad:
    LZ_SAVE();
    return GZ_E_DATA;
}

/* ---------------- public API ---------------- */

gz_rar5_dec *gz_rar5_dec_new(void)
{
    return (gz_rar5_dec *)gz_alloc(sizeof(gz_rar5_dec));
}

void gz_rar5_dec_trim(gz_rar5_dec *d, u64 keep)
{
    if (!d) return;
    if (d->win && d->wsize > keep) {
        gz_free_big(d->win, d->wsize);
        d->win = 0;
        d->wsize = d->wmask = 0;
        d->state_ok = 0;
    }
    if (d->fbuf && (d->fbuf_cap > (1u << 20) || !keep)) {
        gz_free(d->fbuf);
        d->fbuf = 0;
        d->fbuf_cap = 0;
    }
}

void gz_rar5_dec_free(gz_rar5_dec *d)
{
    if (!d) return;
    gz_rar5_dec_trim(d, 0);
    gz_free(d->in);
    gz_free(d->flt);
    gz_free(d);
}

u64 gz_rar5_window_size(u64 dict, u64 total)
{
    u64 w = dict;
    if (total < w) w = total;
    if (w <= MIN_WIN) return MIN_WIN;
    if (w > ((u64)1 << 62)) return (u64)1 << 63;
    u64 p = MIN_WIN;
    while (p < w) p <<= 1;
    return p;
}

/* Solid stream with a larger window: move the history to its new places. */
static int grow(gz_rar5_dec *d, size_t nw)
{
    u8 *n = (u8 *)gz_alloc_big(nw);
    if (!n) return GZ_E_NOMEM;
    const size_t om = d->wmask, nm = nw - 1;
    u64 keep = d->pos < d->wsize ? d->pos : d->wsize, from = d->pos - keep;
    while (from < d->pos) {
        size_t oi = (size_t)from & om, ni = (size_t)from & nm;
        u64 c = d->pos - from;
        if (c > d->wsize - oi) c = d->wsize - oi;
        if (c > nw - ni) c = nw - ni;
        __builtin_memcpy(n + ni, d->win + oi, (size_t)c);
        from += c;
    }
    gz_free_big(d->win, d->wsize);
    d->win = n;
    d->wsize = nw;
    d->wmask = nm;
    d->wp = d->wp_sync = (size_t)d->pos & nm;
    d->full = d->pos >= nw;
    return GZ_OK;
}

int gz_rar5_decode(gz_rar5_dec *d, const gz_stream_io *io, u64 out_size, const gz_rar5_params *pp)
{
    int r;
    u64 w = pp->window;
    if (w < MIN_WIN || (w & (w - 1)) || w > ((size_t)-1 >> 1) + (u64)1) return GZ_E_LIMIT;
    if (!d->in) {
        d->in = (u8 *)gz_alloc(IN_CAP + IN_PAD);
        if (!d->in) return GZ_E_NOMEM;
    }
    if (pp->solid) {
        if (!d->state_ok || !d->win) return GZ_E_DATA;
        d->state_ok = 0;
        if (w > d->wsize && (r = grow(d, (size_t)w))) return r;
        if (!pp->v7 != !d->v7) d->tables_ok = 0;
    } else {
        d->state_ok = 0;
        if (d->wsize != w) {
            if (d->win) gz_free_big(d->win, d->wsize);
            d->wsize = d->wmask = 0;
            d->win = (u8 *)gz_alloc_big((size_t)w);
            if (!d->win) return GZ_E_NOMEM;
            d->wsize = (size_t)w;
            d->wmask = (size_t)w - 1;
        }
        d->pos = 0;
        d->wp = d->wp_sync = 0;
        d->full = 0;
        d->rep[0] = d->rep[1] = d->rep[2] = d->rep[3] = ~(u64)0;
        d->lastlen = 0;
        d->tables_ok = 0;
    }
    d->v7 = pp->v7 != 0;
    d->io = io;
    d->out_size = out_size;
    d->out_done = 0;
    d->file_start = d->wr = d->pos;
    d->nflt = d->fhead = 0;
    d->flt_end = 0;
    d->thresh = d->wsize / 2 < (1u << 20) ? d->wsize / 2 : (1u << 20);
    d->in_base = 0;
    d->p = d->in_end = d->in;
    d->in_eof = 0;
    d->bb = 0;
    d->bc = 0;
    if ((r = fill(d))) return r;
    if ((r = read_block(d))) return r;
    r = lz(d);
    if (r != R5_END) return r;
    if ((r = flush(d, d->pos))) return r;
    if (d->wr != d->pos) return GZ_E_DATA;              /* a filter runs past the end */
    if (out_size != GZ_SIZE_UNKNOWN && d->pos - d->file_start != out_size) return GZ_E_DATA;
    d->state_ok = 1;
    return GZ_OK;
}
