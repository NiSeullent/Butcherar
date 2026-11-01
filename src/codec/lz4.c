/*
 * 고깃ZIP - LZ4 decoder
 *
 * lz4_block() is the single block kernel: a fast path for the common short
 * sequence (<= 14 literals, <= 18-byte match at distance >= 8: three fixed
 * copies, no length loops) taken while both buffers have a safety margin, and an
 * exact path near the ends, so callers need no slack after their buffers.
 *
 * Frame decoder: blocks are made contiguous in the input buffer, decoded into an
 * output buffer that keeps 64 KiB of history for linked blocks, and pushed to
 * the sink in >= 1 MiB pieces.
 */
#include "lz4.h"
#include "xxhash.h"

#define L_HIST    65536u
#define L_SLACK   64u
#define L_FLUSH   ((size_t)1 << 20)
#define L_BIGMEM  ((size_t)1 << 20)
#define L_LEG_BLK ((size_t)8 << 20)                       /* legacy frame block output */
#define L_LEG_MAX (L_LEG_BLK + L_LEG_BLK / 255 + 16)      /* LZ4_compressBound(8 MiB)   */
#define L_STOP    (-1)

GZ_INLINE void cp8(u8 *d, const u8 *s) { __builtin_memcpy(d, s, 8); }
GZ_INLINE void cp16(u8 *d, const u8 *s) { __builtin_memcpy(d, s, 16); }

/* overlapping match copy, writes up to 15 bytes past op + ml (caller checks room) */
GZ_INLINE void copy_match(u8 *op, const u8 *m, size_t ml, size_t off)
{
    u8 *const e = op + ml;
    if (GZ_LIKELY(off >= 16)) {
        do { cp16(op, m); op += 16; m += 16; } while (op < e);
        return;
    }
    if (off < 8) {
        static const u8 add4[8] = { 0, 1, 2, 1, 4, 4, 4, 4 };
        static const u8 adv[8] = { 0, 1, 2, 2, 4, 3, 2, 1 };
        op[0] = m[0]; op[1] = m[1]; op[2] = m[2]; op[3] = m[3];
        __builtin_memcpy(op + 4, m + add4[off], 4);
        m += adv[off];
    } else {
        cp8(op, m);
        m += 8;
    }
    op += 8;
    while (op < e) { cp8(op, m); op += 8; m += 8; }
}

/* Decode the block [ip, iend) into [op, oend); matches may reach back to lowest. */
static int lz4_block(const u8 *ip, const u8 *const iend, u8 *op, u8 *const oend, const u8 *const lowest, u8 **out)
{
    for (;;) {
        if (GZ_UNLIKELY(ip >= iend)) return GZ_E_DATA;      /* block must end with literals */
        u32 token = *ip++;
        size_t ll = token >> 4, ml, off;
        if (GZ_LIKELY(ll != 15) && GZ_LIKELY((size_t)(iend - ip) >= 32) && GZ_LIKELY((size_t)(oend - op) >= 64)) {
            cp16(op, ip);
            op += ll;
            ip += ll;
            off = rd16(ip);
            ip += 2;
            ml = token & 15;
            if (GZ_LIKELY(ml != 15) && off >= 8 && off <= (size_t)(op - lowest)) {
                const u8 *m = op - off;
                cp8(op, m); cp8(op + 8, m + 8); cp8(op + 16, m + 16);
                op += ml + 4;
                continue;
            }
        } else {
            if (ll == 15) {
                u32 b;
                do {
                    if (ip >= iend) return GZ_E_DATA;
                    b = *ip++;
                    ll += b;
                } while (b == 255 && ll <= (size_t)(iend - ip));
            }
            if (ll > (size_t)(iend - ip) || ll > (size_t)(oend - op)) return GZ_E_DATA;
            if ((size_t)(iend - ip) - ll >= 16 && (size_t)(oend - op) - ll >= 16) {
                u8 *e = op + ll;
                u8 *q = op;
                const u8 *s = ip;
                do { cp16(q, s); q += 16; s += 16; } while (q < e);
            } else {
                __builtin_memcpy(op, ip, ll);
            }
            op += ll;
            ip += ll;
            if (ip == iend) break;                           /* last literals */
            if ((size_t)(iend - ip) < 2) return GZ_E_DATA;
            off = rd16(ip);
            ip += 2;
            ml = token & 15;
        }
        if (ml == 15) {
            u32 b;
            do {
                if (ip >= iend) return GZ_E_DATA;
                b = *ip++;
                ml += b;
            } while (b == 255 && ml <= (size_t)(oend - op));
        }
        ml += 4;
        if (!off || off > (size_t)(op - lowest) || ml > (size_t)(oend - op)) return GZ_E_DATA;
        const u8 *m = op - off;
        if ((size_t)(oend - op) - ml >= 16) {
            copy_match(op, m, ml, off);
        } else {
            for (size_t i = 0; i < ml; i++) op[i] = m[i];
        }
        op += ml;
    }
    *out = op;
    return GZ_OK;
}

int gz_lz4_block_decode_ext(const u8 *src, size_t sn, u8 *dst, size_t dcap, size_t dict_len, size_t *dn)
{
    u8 *e = dst;
    int r = lz4_block(src, src + sn, dst, dst + dcap, dst - dict_len, &e);
    *dn = (size_t)(e - dst);
    return r;
}

int gz_lz4_block_decode(const u8 *src, u32 sn, u8 *dst, u32 dcap, u32 *dn)
{
    size_t n = 0;
    int r = gz_lz4_block_decode_ext(src, sn, dst, dcap, 0, &n);
    *dn = (u32)n;
    return r;
}

/* ---------------- frame decoder ---------------- */

typedef struct {
    const gz_stream_io *io;
    u8 *ibuf, *ip, *iend;
    size_t icap;                  /* usable input bytes (L_SLACK more allocated) */
    int eof;
    u64 in_total;
    u8 *obuf, *op, *flushed;
    size_t ocap;                  /* usable output bytes                         */
    u64 out_total, out_size;
    int cchk;
    gz_xxh32_state xh;
} lz4st;

static void *l_alloc(size_t n) { return n > L_BIGMEM ? gz_alloc_big(n) : gz_alloc(n); }
static void l_free(void *p, size_t n)
{
    if (!p) return;
    if (n > L_BIGMEM) gz_free_big(p, n); else gz_free(p);
}

static int l_need(lz4st *st, size_t need)
{
    size_t have = (size_t)(st->iend - st->ip);
    if (GZ_LIKELY(have >= need)) return GZ_OK;
    if (st->eof) return GZ_E_TRUNC;
    if (need > st->icap) {                  /* big blocks: grow, keeping what we have */
        size_t nc = 2 * need + (256u << 10);   /* room to read ahead: fewer remainder moves */
        u8 *nb = (u8 *)l_alloc(nc + L_SLACK);
        if (!nb) return GZ_E_NOMEM;
        __builtin_memcpy(nb, st->ip, have);
        l_free(st->ibuf, st->icap + L_SLACK);
        st->ibuf = nb;
        st->icap = nc;
        st->ip = nb;
        st->iend = nb + have;
    } else if (st->ip != st->ibuf) {
        __builtin_memmove(st->ibuf, st->ip, have);
        st->ip = st->ibuf;
        st->iend = st->ibuf + have;
    }
    while (have < need) {
        u32 room = st->icap - have > 0x40000000u ? 0x40000000u : (u32)(st->icap - have);
        u32 got = 0;
        int r = st->io->read(st->io->ctx, st->iend, room, &got);
        if (r) return r;
        if (!got || got > room) {
            st->eof = 1;
            return GZ_E_TRUNC;
        }
        st->iend += got;
        have += got;
        st->in_total += got;
    }
    return GZ_OK;
}

static int l_flush(lz4st *st)
{
    size_t n = (size_t)(st->op - st->flushed);
    if (!n) return GZ_OK;
    const u8 *p = st->flushed;
    st->flushed = st->op;
    if (st->cchk) gz_xxh32_update(&st->xh, p, n);
    u64 w = n;
    if (st->out_size != GZ_SIZE_UNKNOWN && w > st->out_size - st->out_total) w = st->out_size - st->out_total;
    if (!w) return GZ_OK;
    st->out_total += w;
    return st->io->write(st->io->ctx, p, (size_t)w);
}

/* fresh output buffer of at least need usable bytes (previous output is flushed) */
static int l_obuf(lz4st *st, size_t need)
{
    if (st->ocap < need) {
        l_free(st->obuf, st->ocap + L_SLACK);
        st->ocap = 0;
        st->obuf = (u8 *)l_alloc(need + L_SLACK);
        if (!st->obuf) return GZ_E_NOMEM;
        st->ocap = need;
    }
    st->op = st->flushed = st->obuf;
    return GZ_OK;
}

/* after a block: flush when enough output piled up or out_size is reached */
static int l_after_block(lz4st *st)
{
    if (st->out_size != GZ_SIZE_UNKNOWN && st->out_total + (u64)(st->op - st->flushed) >= st->out_size) {
        int r = l_flush(st);
        return r ? r : L_STOP;
    }
    if ((size_t)(st->op - st->flushed) >= L_FLUSH) return l_flush(st);
    return GZ_OK;
}

static int l_frame(lz4st *st)
{
    int r = l_need(st, 7);
    if (r) return r;
    u32 flg = st->ip[4], bd = st->ip[5];
    if ((flg >> 6) != 1 || (flg & 2) || (bd & 0x8F)) return GZ_E_DATA;   /* version 01, reserved bits */
    u32 bid = (bd >> 4) & 7;
    if (bid < 4) return GZ_E_DATA;
    size_t bmax = (size_t)1 << (2 * bid + 8);                 /* 64 KiB .. 4 MiB */
    int linked = !(flg & 0x20), bchk = (flg >> 4) & 1, cchk = (flg >> 2) & 1;
    size_t hl = 7 + ((flg & 8) ? 8 : 0) + ((flg & 1) ? 4 : 0);
    if ((r = l_need(st, hl))) return r;
    const u8 *h = st->ip;
    if (((gz_xxh32(h + 4, hl - 5, 0) >> 8) & 0xFF) != h[hl - 1]) return GZ_E_CRC;
    if ((flg & 1) && rd32(h + hl - 5)) return GZ_E_METHOD;    /* needs a dictionary */
    u64 csize = (flg & 8) ? rd64(h + 6) : GZ_SIZE_UNKNOWN;
    st->ip += hl;

    size_t hist = linked ? L_HIST : 0, span = bmax > L_FLUSH ? bmax : L_FLUSH;
    if ((r = l_obuf(st, hist + bmax + span))) return r;
    size_t usable = st->ocap;
    st->cchk = cchk;
    if (cchk) gz_xxh32_init(&st->xh, 0);
    u64 fprod = 0;
    for (;;) {
        if ((r = l_need(st, 4))) return r;
        u32 bs = rd32(st->ip);
        st->ip += 4;
        if (!bs) break;                                        /* end mark */
        u32 raw = bs >> 31;
        bs &= 0x7FFFFFFFu;
        if (bs > bmax) return GZ_E_DATA;
        size_t tot = bs + (bchk ? 4u : 0u);
        if ((r = l_need(st, tot))) return r;
        if (bchk && gz_xxh32(st->ip, bs, 0) != rd32(st->ip + bs)) return GZ_E_CRC;
        if ((size_t)(st->obuf + usable - st->op) < bmax) {
            if ((r = l_flush(st))) return r;
            size_t keep = (size_t)(st->op - st->obuf);
            if (keep > hist) keep = hist;
            __builtin_memmove(st->obuf, st->op - keep, keep);
            st->op = st->flushed = st->obuf + keep;
        }
        u8 *start = st->op;
        if (raw) {
            __builtin_memcpy(st->op, st->ip, bs);
            st->op += bs;
        } else {
            r = lz4_block(st->ip, st->ip + bs, st->op, st->op + bmax, linked ? st->obuf : st->op, &st->op);
            if (r) return r;
        }
        st->ip += tot;
        fprod += (u64)(st->op - start);
        if (csize != GZ_SIZE_UNKNOWN && fprod > csize) return GZ_E_DATA;
        if ((r = l_after_block(st))) return r;
    }
    if ((r = l_flush(st))) return r;
    if (cchk) {
        if ((r = l_need(st, 4))) return r;
        if (rd32(st->ip) != gz_xxh32_digest(&st->xh)) return GZ_E_CRC;
        st->ip += 4;
    }
    st->cchk = 0;
    if (csize != GZ_SIZE_UNKNOWN && fprod != csize) return GZ_E_DATA;
    return GZ_OK;
}

static int is_magic(u32 v)
{
    return v == GZ_LZ4_MAGIC || v == GZ_LZ4_LEGACY_MAGIC || (v & 0xFFFFFFF0u) == GZ_LZ4_SKIP_MAGIC;
}

/* legacy frame: independent blocks of up to 8 MiB, until end of input or a new magic */
static int l_legacy(lz4st *st)
{
    int r;
    st->ip += 4;
    st->cchk = 0;
    if ((r = l_obuf(st, L_LEG_BLK))) return r;
    for (;;) {
        r = l_need(st, 4);
        if (r == GZ_E_TRUNC && st->iend == st->ip) return GZ_OK;
        if (r) return r;
        u32 bs = rd32(st->ip);
        if (is_magic(bs)) return GZ_OK;
        st->ip += 4;
        if (!bs || bs > L_LEG_MAX) return GZ_E_DATA;
        if ((r = l_need(st, bs))) return r;
        st->op = st->flushed = st->obuf;
        if ((r = lz4_block(st->ip, st->ip + bs, st->obuf, st->obuf + L_LEG_BLK, st->obuf, &st->op))) return r;
        st->ip += bs;
        if ((r = l_after_block(st))) return r;
        if ((r = l_flush(st))) return r;
    }
}

static int l_skip(lz4st *st)
{
    int r = l_need(st, 8);
    if (r) return r;
    u64 n = rd32(st->ip + 4);
    st->ip += 8;
    for (;;) {
        size_t have = (size_t)(st->iend - st->ip);
        if (have >= n) {
            st->ip += n;
            return GZ_OK;
        }
        n -= have;
        st->ip = st->iend;
        if ((r = l_need(st, 1))) return r;
    }
}

int gz_lz4f_decode(const gz_stream_io *io, u64 out_size, u64 *in_used)
{
    lz4st st;
    __builtin_memset(&st, 0, sizeof st);
    st.io = io;
    st.out_size = out_size;
    st.icap = 256u << 10;
    st.ibuf = (u8 *)l_alloc(st.icap + L_SLACK);
    if (!st.ibuf) return GZ_E_NOMEM;
    st.ip = st.iend = st.ibuf;
    int r, any = 0;
    for (;;) {
        if (any && out_size != GZ_SIZE_UNKNOWN && st.out_total >= out_size) { r = GZ_OK; break; }
        r = l_need(&st, 4);
        if (r == GZ_E_TRUNC && st.iend == st.ip) {
            r = any ? GZ_OK : GZ_E_TRUNC;
            break;
        }
        if (r) break;
        u32 magic = rd32(st.ip);
        if (magic == GZ_LZ4_MAGIC) r = l_frame(&st);
        else if (magic == GZ_LZ4_LEGACY_MAGIC) r = l_legacy(&st);
        else if ((magic & 0xFFFFFFF0u) == GZ_LZ4_SKIP_MAGIC) r = l_skip(&st);
        else r = any ? GZ_E_DATA : GZ_E_FORMAT;
        any = 1;
        if (r == L_STOP) { r = GZ_OK; break; }
        if (r) break;
    }
    if (!r && out_size != GZ_SIZE_UNKNOWN && st.out_total < out_size) r = GZ_E_DATA;
    if (in_used) *in_used = st.in_total - (u64)(st.iend - st.ip);
    l_free(st.ibuf, st.icap + L_SLACK);
    l_free(st.obuf, st.ocap + L_SLACK);
    return r;
}
