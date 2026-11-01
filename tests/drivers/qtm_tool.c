/*
 * Quantum test tool (test driver, uses libc):
 *
 *   qtm_tool enc <in> <out.frames> <wbits> <seed> [pad]
 *       Quantum encoder producing CAB frames (32 KiB of output each): adaptive
 *       arithmetic coding with the decoder's models, greedy LZ77 matching.
 *       pad: number of zero bytes after each frame (0..4, -1 = random).
 *       Its output is verified with 7-Zip and cabextract through CAB files.
 *   qtm_tool dec <in.frames> <out> <wbits>        decode with gz_qtm
 *   qtm_tool fuzz <in.frames> <wbits> <iterations> <seed>
 *
 * .frames container (same as lzx_tool): "LZXF" u32 n, then per frame u32 csize,
 * u32 usize, data.
 */
#include "quantum.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static u8 *read_file(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb");
    if (!f) { perror(p); exit(2); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *b = malloc(sz + 16);
    if (fread(b, 1, sz, f) != (size_t)sz) { perror(p); exit(2); }
    fclose(f);
    *n = (size_t)sz;
    return b;
}

static u32 g_rng = 1;
static u32 rnd(void) { g_rng ^= g_rng << 13; g_rng ^= g_rng >> 17; g_rng ^= g_rng << 5; return g_rng; }

/* ---------------- models (identical to the decoder's) ---------------- */

typedef struct { u16 sym, cf; } qsym;
typedef struct { int shifts, n; qsym s[65]; } qmodel;

static const u32 k_pbase[43] = {
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768,
    1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152,
    65536, 98304, 131072, 196608, 262144, 393216, 524288, 786432, 1048576, 1572864, 2097152
};
static const u8 k_pextra[42] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10,
    11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18, 19, 19
};
static const u16 k_lbase[28] = {
    0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 18, 22, 26, 30, 38, 46, 54, 62, 78, 94, 110, 126, 158, 190, 222, 254, 255
};
static const u8 k_lextra[27] = {
    0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};

static void model_init(qmodel *m, int start, int n)
{
    m->shifts = 4;
    m->n = n;
    for (int i = 0; i <= n; i++) { m->s[i].sym = (u16)(start + i); m->s[i].cf = (u16)(n - i); }
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
    for (i = 0; i < n; i++) {
        m->s[i].cf = (u16)(m->s[i].cf - m->s[i + 1].cf);
        m->s[i].cf = (u16)((m->s[i].cf + 1) >> 1);
    }
    for (i = 0; i < n - 1; i++)
        for (j = i + 1; j < n; j++)
            if (m->s[i].cf < m->s[j].cf) { qsym t = m->s[i]; m->s[i] = m->s[j]; m->s[j] = t; }
    for (i = n - 1; i >= 0; i--) m->s[i].cf = (u16)(m->s[i].cf + m->s[i + 1].cf);
}

/* ---------------- arithmetic encoder with interleaved raw bits ---------------- */

typedef struct { u32 pos, val, n; } rawg;
typedef struct {
    u8 *code; size_t ncode, capc;       /* code bits, one per byte */
    rawg *raw; size_t nraw, capr;
    u32 H, L, pending;
} qenc;

static void emit(qenc *e, u32 b)
{
    if (e->ncode == e->capc) { e->capc = e->capc ? e->capc * 2 : 1 << 16; e->code = realloc(e->code, e->capc); }
    e->code[e->ncode++] = (u8)b;
}

static void enc_sym(qenc *e, qmodel *m, u32 sym)
{
    int k = 0;
    while (k < m->n && m->s[k].sym != sym) k++;
    if (k == m->n) { fprintf(stderr, "symbol %u not in model\n", sym); exit(1); }
    u32 range = ((e->H - e->L) & 0xffff) + 1, total = m->s[0].cf, L = e->L;
    e->H = (L + (m->s[k].cf * range) / total - 1) & 0xffff;
    e->L = (L + (m->s[k + 1].cf * range) / total) & 0xffff;
    int i = k + 1;
    do { m->s[--i].cf += 8; } while (i > 0);
    if (m->s[0].cf > 3800) model_update(m);
    for (;;) {
        if (!((e->L ^ e->H) & 0x8000)) {
            u32 b = e->L >> 15;
            emit(e, b);
            for (; e->pending; e->pending--) emit(e, !b);
        } else if ((e->L & 0x4000) && !(e->H & 0x4000)) {
            e->pending++;
            e->L &= 0x3fff;
            e->H |= 0x4000;
        } else {
            break;
        }
        e->L = (e->L << 1) & 0xffff;
        e->H = ((e->H << 1) | 1) & 0xffff;
    }
}

/* raw bits are read by the decoder after 16 + (renormalisations so far) code bits */
static void enc_raw(qenc *e, u32 val, u32 n)
{
    if (!n) return;
    if (e->nraw == e->capr) { e->capr = e->capr ? e->capr * 2 : 1024; e->raw = realloc(e->raw, e->capr * sizeof(rawg)); }
    e->raw[e->nraw].pos = (u32)(e->ncode + e->pending + 16);
    e->raw[e->nraw].val = val;
    e->raw[e->nraw].n = n;
    e->nraw++;
}

typedef struct { u8 *p; size_t n, cap; u32 acc, nacc; } bytes;
static void out_bit(bytes *o, u32 b)
{
    o->acc = (o->acc << 1) | b;
    if (++o->nacc == 8) {
        if (o->n == o->cap) { o->cap = o->cap ? o->cap * 2 : 1 << 16; o->p = realloc(o->p, o->cap); }
        o->p[o->n++] = (u8)o->acc;
        o->acc = o->nacc = 0;
    }
}

/* end the frame: the final code value is L (16 bits) + 2 bits, then merge code and raw bits */
static void enc_flush(qenc *e, bytes *o, int pad)
{
    u32 b = e->L >> 15;
    emit(e, b);
    for (; e->pending; e->pending--) emit(e, !b);
    for (int k = 14; k >= 0; k--) emit(e, (e->L >> k) & 1);
    /* 7-Zip reads two more bits after the last symbol and wants the block to end there */
    emit(e, 0);
    emit(e, 0);
    size_t ci = 0;
    for (size_t r = 0; r < e->nraw; r++) {
        while (ci < e->raw[r].pos && ci < e->ncode) out_bit(o, e->code[ci++]);
        for (int k = (int)e->raw[r].n - 1; k >= 0; k--) out_bit(o, (e->raw[r].val >> k) & 1);
    }
    while (ci < e->ncode) out_bit(o, e->code[ci++]);
    while (o->nacc) out_bit(o, 0);
    for (int k = 0; k < pad; k++) { out_bit(o, 0); out_bit(o, 0); out_bit(o, 0); out_bit(o, 0); out_bit(o, 0); out_bit(o, 0); out_bit(o, 0); out_bit(o, 0); }
    e->ncode = e->nraw = 0;
    e->H = 0xffff;
    e->L = 0;
    e->pending = 0;
}

#define HBITS 16
static u32 hash3(const u8 *p) { return ((u32)(p[0] << 16 | p[1] << 8 | p[2]) * 2654435761u) >> (32 - HBITS); }

static int enc_main(int argc, char **argv)
{
    if (argc < 6) return 2;
    size_t n;
    u8 *d = read_file(argv[2], &n);
    u32 wbits = (u32)atoi(argv[4]), ws = 1u << wbits;
    g_rng = (u32)atoi(argv[5]) * 2654435761u + 3;
    int padopt = argc > 6 ? atoi(argv[6]) : 0;
    if (wbits < 10 || wbits > 21) return 2;
    qmodel lit[4], m4, m5, m6, m6len, m7;
    int i2 = (int)wbits * 2;
    for (int k = 0; k < 4; k++) model_init(&lit[k], 64 * k, 64);
    model_init(&m4, 0, i2 > 24 ? 24 : i2);
    model_init(&m5, 0, i2 > 36 ? 36 : i2);
    model_init(&m6, 0, i2);
    model_init(&m6len, 0, 27);
    model_init(&m7, 0, 7);
    u32 max4 = k_pbase[m4.n], max5 = k_pbase[m5.n], max6 = k_pbase[m6.n];
    if (max4 > ws) max4 = ws;
    if (max5 > ws) max5 = ws;
    if (max6 > ws) max6 = ws;

    i32 *head = malloc(sizeof(i32) << HBITS), *prev = malloc(sizeof(i32) * (n + 1));
    for (u32 i = 0; i < (1u << HBITS); i++) head[i] = -1;
    qenc e = { 0 };
    e.H = 0xffff;
    bytes o = { 0 };
    size_t nframes = (n + 32767) / 32768;
    size_t *fend = calloc(nframes + 1, sizeof(size_t));
    size_t pos = 0, fr = 0;
    while (pos < n) {
        size_t fe = (fr + 1) * 32768 < n ? (fr + 1) * 32768 : n;
        while (pos < fe) {
            /* best match: length 3 (offset <= max4), 4 (<= max5), 5..259 (<= max6) */
            u32 best = 0, boff = 0, lim = fe - pos < 259 ? (u32)(fe - pos) : 259;
            if (pos + 3 <= n && lim >= 3) {
                i32 c = head[hash3(d + pos)];
                int depth = 32;
                while (c >= 0 && depth--) {
                    u32 off = (u32)(pos - (size_t)c);
                    if (off > max6) break;
                    u32 l = 0;
                    while (l < lim && d[pos + l] == d[c + l]) l++;
                    u32 ok = l >= 5 ? l : l == 4 ? (off <= max5 ? 4 : off <= max4 ? 3 : 0) : l == 3 && off <= max4 ? 3 : 0;
                    if (ok > best) { best = ok; boff = off; }
                    c = prev[c];
                }
            }
            if (best >= 3 && (rnd() & 15)) {
                u32 len = best;
                /* exercise the short selectors now and then */
                if (len >= 5 && boff <= max5 && !(rnd() & 7)) len = 4;
                if (len >= 4 && boff <= max4 && !(rnd() & 7)) len = 3;
                u32 v = boff - 1, sl = 0;
                while (k_pbase[sl + 1] <= v) sl++;
                if (len == 3) {
                    enc_sym(&e, &m7, 4);
                    enc_sym(&e, &m4, sl);
                    enc_raw(&e, v - k_pbase[sl], k_pextra[sl]);
                } else if (len == 4) {
                    enc_sym(&e, &m7, 5);
                    enc_sym(&e, &m5, sl);
                    enc_raw(&e, v - k_pbase[sl], k_pextra[sl]);
                } else {
                    u32 lv = len - 5, ls = 0;
                    while (k_lbase[ls + 1] <= lv) ls++;
                    enc_sym(&e, &m7, 6);
                    enc_sym(&e, &m6len, ls);
                    enc_raw(&e, lv - k_lbase[ls], k_lextra[ls]);
                    enc_sym(&e, &m6, sl);
                    enc_raw(&e, v - k_pbase[sl], k_pextra[sl]);
                }
                for (u32 k = 0; k < len; k++) {
                    if (pos + 3 <= n) { u32 h = hash3(d + pos); prev[pos] = head[h]; head[h] = (i32)pos; }
                    pos++;
                }
            } else {
                u32 b = d[pos];
                enc_sym(&e, &m7, b >> 6);
                enc_sym(&e, &lit[b >> 6], b);
                if (pos + 3 <= n) { u32 h = hash3(d + pos); prev[pos] = head[h]; head[h] = (i32)pos; }
                pos++;
            }
        }
        enc_flush(&e, &o, padopt < 0 ? (int)(rnd() % 5) : padopt);
        fend[fr++] = o.n;
    }
    FILE *f = fopen(argv[3], "wb");
    fwrite("LZXF", 1, 4, f);
    u32 nf = (u32)nframes;
    fwrite(&nf, 4, 1, f);
    size_t cs = 0;
    for (size_t i = 0; i < nframes; i++) {
        u32 c = (u32)(fend[i] - cs), u = (u32)((i + 1) * 32768 <= n ? 32768 : n - i * 32768);
        fwrite(&c, 4, 1, f);
        fwrite(&u, 4, 1, f);
        fwrite(o.p + cs, 1, c, f);
        cs = fend[i];
    }
    fclose(f);
    printf("frames=%zu in=%zu out=%zu\n", nframes, n, o.n);
    free(d); free(head); free(prev); free(e.code); free(e.raw); free(o.p); free(fend);
    return 0;
}

/* ---------------- decoder test ---------------- */

typedef struct { u32 n; u32 *cs, *us; size_t *off; u8 *buf; size_t len; } frames;

static void load_frames(const char *p, frames *f)
{
    f->buf = read_file(p, &f->len);
    if (f->len < 8 || memcmp(f->buf, "LZXF", 4)) { fprintf(stderr, "bad frames file\n"); exit(2); }
    memcpy(&f->n, f->buf + 4, 4);
    f->cs = calloc(f->n + 1, 4); f->us = calloc(f->n + 1, 4); f->off = calloc(f->n + 1, sizeof(size_t));
    size_t o = 8;
    for (u32 i = 0; i < f->n; i++) {
        memcpy(&f->cs[i], f->buf + o, 4);
        memcpy(&f->us[i], f->buf + o + 4, 4);
        f->off[i] = o + 8;
        o += 8 + f->cs[i];
        if (o > f->len) { fprintf(stderr, "truncated\n"); exit(2); }
    }
}

static int decode_all(gz_qtm_dec *d, frames *f, const u8 *data, FILE *fo)
{
    static u8 out[32768];
    gz_qtm_reset(d);
    for (u32 i = 0; i < f->n; i++) {
        int r = gz_qtm_decode_frame(d, data + f->off[i], f->cs[i], out, f->us[i]);
        if (r) return r;
        if (fo) fwrite(out, 1, f->us[i], fo);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "enc")) return enc_main(argc, argv);
    if (argc < 5) return 2;
    frames f;
    load_frames(argv[2], &f);
    if (!strcmp(argv[1], "dec")) {
        gz_qtm_dec *d = gz_qtm_new((u32)atoi(argv[4]));
        if (!d) return 1;
        FILE *fo = fopen(argv[3], "wb");
        int r = decode_all(d, &f, f.buf, fo);
        fclose(fo);
        gz_qtm_free(d);
        printf("DEC %d\n", r);
        free(f.buf); free(f.cs); free(f.us); free(f.off);
        return r ? 1 : 0;
    }
    if (!strcmp(argv[1], "fuzz") && argc >= 6) {
        gz_qtm_dec *d = gz_qtm_new((u32)atoi(argv[3]));
        int iters = atoi(argv[4]), errs = 0;
        g_rng = (u32)atoi(argv[5]) * 2654435761u + 9;
        u8 *data = malloc(f.len + 16);
        for (int it = 0; it < iters; it++) {
            memcpy(data, f.buf, f.len);
            int k = 1 + (int)(rnd() % 10);
            while (k--) data[8 + rnd() % (f.len - 8)] ^= (u8)(1u << (rnd() & 7));
            if (it % 3 == 2) { u32 i = rnd() % f.n; f.cs[i] = f.cs[i] ? rnd() % f.cs[i] : 0; }
            errs += decode_all(d, &f, data, 0) != 0;
        }
        printf("FUZZ %d iterations, %d rejected\n", iters, errs);
        gz_qtm_free(d);
        free(data); free(f.buf); free(f.cs); free(f.us); free(f.off);
        return 0;
    }
    return 2;
}
