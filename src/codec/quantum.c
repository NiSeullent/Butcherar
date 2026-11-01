/*
 * 고깃ZIP - Quantum decoder, see quantum.h
 *
 * Arithmetic coder: 16-bit H/L/C registers, code bits read MSB first from the
 * byte stream; offset and length extra bits are raw bits taken from the same
 * stream. Adaptive models: cumulative frequencies in decreasing order, +8 per
 * coded symbol, halved above 3800 and re-sorted every 50th time (the exact
 * update order matters: it is part of the format).
 *
 * The window is linear (one window of history kept when the next frame would
 * not fit) so matches never wrap.
 */
#include "quantum.h"

#define MAXSYM 64
#define MARGIN 16u

typedef struct { u16 sym, cf; } qsym;
typedef struct { int shifts, n; qsym s[MAXSYM + 1]; } qmodel;

static const u32 k_pbase[42] = {
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768,
    1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152,
    65536, 98304, 131072, 196608, 262144, 393216, 524288, 786432, 1048576, 1572864
};
static const u8 k_pextra[42] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10,
    11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18, 19, 19
};
static const u8 k_lbase[27] = {
    0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 18, 22, 26, 30, 38, 46, 54, 62, 78, 94, 110, 126, 158, 190, 222, 254
};
static const u8 k_lextra[27] = {
    0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};

struct gz_qtm_dec {
    u8 *win;
    size_t alloc;
    u32 wbits, wsize, cap, pos;
    int bad;
    qmodel lit[4], m4, m5, m6, m6len, m7;
};

static void model_init(qmodel *m, int start, int n)
{
    m->shifts = 4;
    m->n = n;
    for (int i = 0; i <= n; i++) {
        m->s[i].sym = (u16)(start + i);
        m->s[i].cf = (u16)(n - i);
    }
}

static void model_update(qmodel *m)
{
    int i, j, n = m->n;
    if (--m->shifts) {
        for (i = n - 1; i >= 0; i--) {
            m->s[i].cf >>= 1;
            if (m->s[i].cf <= m->s[i + 1].cf) m->s[i].cf = (u16)(m->s[i + 1].cf + 1);
        }
        return;
    }
    m->shifts = 50;
    for (i = 0; i < n; i++) {                 /* cumulative -> halved frequencies */
        m->s[i].cf = (u16)(m->s[i].cf - m->s[i + 1].cf);
        m->s[i].cf = (u16)((m->s[i].cf + 1) >> 1);
    }
    for (i = 0; i < n - 1; i++)               /* selection sort, decreasing (same stability) */
        for (j = i + 1; j < n; j++)
            if (m->s[i].cf < m->s[j].cf) {
                qsym t = m->s[i];
                m->s[i] = m->s[j];
                m->s[j] = t;
            }
    for (i = n - 1; i >= 0; i--) m->s[i].cf = (u16)(m->s[i].cf + m->s[i + 1].cf);
}

/* ---------------- bits + arithmetic decoder ---------------- */

typedef struct {
    const u8 *in;
    u32 n, ip;
    u32 buf;             /* MSB aligned */
    u32 cnt;
    u32 H, L, C;
} qdec;

GZ_INLINE void q_refill(qdec *q)
{
    while (q->cnt <= 24) {
        u32 b = q->ip < q->n ? q->in[q->ip] : 0;     /* zeros past the frame's data */
        q->ip++;
        q->buf |= b << (24 - q->cnt);
        q->cnt += 8;
    }
}

/* n = 0..19 raw bits */
static u32 q_bits(qdec *q, u32 n)
{
    if (!n) return 0;
    q_refill(q);
    u32 v = q->buf >> (32 - n);
    q->buf <<= n;
    q->cnt -= n;
    return v;
}

static u32 q_sym(qdec *q, qmodel *m)
{
    u32 range = ((q->H - q->L) & 0xffff) + 1;
    u32 total = m->s[0].cf;
    u32 symf = (((q->C - q->L + 1) * total) - 1) / range & 0xffff;
    int i;
    for (i = 1; i < m->n; i++)
        if (m->s[i].cf <= symf) break;
    u32 sym = m->s[i - 1].sym;
    u32 L = q->L;
    q->H = (L + (m->s[i - 1].cf * range) / total - 1) & 0xffff;
    q->L = (L + (m->s[i].cf * range) / total) & 0xffff;
    do { m->s[--i].cf += 8; } while (i > 0);
    if (m->s[0].cf > 3800) model_update(m);
    /* renormalise: at most ~32 steps even on garbage */
    for (int k = 0; k < 48; k++) {
        if ((q->L ^ q->H) & 0x8000) {
            if ((q->L & 0x4000) && !(q->H & 0x4000)) {      /* underflow */
                q->C ^= 0x4000;
                q->L &= 0x3fff;
                q->H |= 0x4000;
            } else {
                break;
            }
        }
        q->L = (q->L << 1) & 0xffff;
        q->H = ((q->H << 1) | 1) & 0xffff;
        q->C = ((q->C << 1) | q_bits(q, 1)) & 0xffff;
    }
    return sym;
}

/* ---------------- public API ---------------- */

int gz_qtm_init(gz_qtm_dec *d, u32 window_bits)
{
    if (window_bits < 10 || window_bits > 21) return GZ_E_METHOD;
    u32 ws = 1u << window_bits;
    u32 cap = ws + (ws > GZ_QTM_FRAME ? ws : GZ_QTM_FRAME);
    size_t need = (size_t)cap + MARGIN;
    if (d->alloc < need) {
        u8 *w = (u8 *)gz_alloc_big(need);
        if (!w) return GZ_E_NOMEM;
        if (d->win) gz_free_big(d->win, d->alloc);
        d->win = w;
        d->alloc = need;
    }
    d->wbits = window_bits;
    d->wsize = ws;
    d->cap = cap;
    gz_qtm_reset(d);
    return GZ_OK;
}

void gz_qtm_reset(gz_qtm_dec *d)
{
    int i = (int)d->wbits * 2;
    d->pos = 0;
    d->bad = 0;
    for (int k = 0; k < 4; k++) model_init(&d->lit[k], 64 * k, 64);
    model_init(&d->m4, 0, i > 24 ? 24 : i);
    model_init(&d->m5, 0, i > 36 ? 36 : i);
    model_init(&d->m6, 0, i);
    model_init(&d->m6len, 0, 27);
    model_init(&d->m7, 0, 7);
}

gz_qtm_dec *gz_qtm_new(u32 window_bits)
{
    gz_qtm_dec *d = (gz_qtm_dec *)gz_alloc(sizeof(gz_qtm_dec));
    if (!d) return 0;
    if (gz_qtm_init(d, window_bits)) { gz_free(d); return 0; }
    return d;
}

void gz_qtm_free(gz_qtm_dec *d)
{
    if (!d) return;
    if (d->win) gz_free_big(d->win, d->alloc);
    gz_free(d);
}

int gz_qtm_decode_frame(gz_qtm_dec *d, const u8 *in, u32 in_n, u8 *out, u32 out_n)
{
    if (d->bad) return GZ_E_DATA;
    if (!out_n) return GZ_OK;
    if (out_n > GZ_QTM_FRAME) return GZ_E_LIMIT;
    if (d->pos + out_n > d->cap) {            /* keep one window of history */
        u32 keep = d->pos < d->wsize ? d->pos : d->wsize;
        __builtin_memmove(d->win, d->win + d->pos - keep, keep);
        d->pos = keep;
    }
    qdec q;
    q.in = in;
    q.n = in_n;
    q.ip = 0;
    q.buf = 0;
    q.cnt = 0;
    q.H = 0xffff;
    q.L = 0;
    q.C = q_bits(&q, 16);
    u8 *const win = d->win;
    u32 pos = d->pos;
    const u32 fstart = pos, fend = pos + out_n, wsize = d->wsize;
    int err = GZ_OK;
    while (pos < fend) {
        u32 sel = q_sym(&q, &d->m7), len, off, sym;
        if (sel < 4) {
            win[pos++] = (u8)q_sym(&q, &d->lit[sel]);
            continue;
        }
        if (sel == 4) {
            sym = q_sym(&q, &d->m4);
            off = k_pbase[sym] + q_bits(&q, k_pextra[sym]) + 1;
            len = 3;
        } else if (sel == 5) {
            sym = q_sym(&q, &d->m5);
            off = k_pbase[sym] + q_bits(&q, k_pextra[sym]) + 1;
            len = 4;
        } else {
            sym = q_sym(&q, &d->m6len);
            len = k_lbase[sym] + q_bits(&q, k_lextra[sym]) + 5;
            sym = q_sym(&q, &d->m6);
            off = k_pbase[sym] + q_bits(&q, k_pextra[sym]) + 1;
        }
        /* matches stay inside the frame and the history */
        if (len > fend - pos || off > pos || off > wsize) { err = GZ_E_DATA; break; }
        const u8 *src = win + pos - off;
        u8 *dst = win + pos;
        for (u32 k = 0; k < len; k++) dst[k] = src[k];
        pos += len;
    }
    /* the coder's look-ahead may run a little past the frame's data, not more */
    if (!err && q.ip - q.cnt / 8 > in_n + 4) err = GZ_E_DATA;
    if (err) { d->bad = 1; return err; }
    d->pos = pos;
    if (out) __builtin_memcpy(out, win + fstart, out_n);
    return GZ_OK;
}
