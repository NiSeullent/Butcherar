/*
 * rar3_tool - RAR 1.5 - 4.x / RAR 1.4 test writer, checker and fuzzer (tests/cases/fmt_rar.py)
 *
 *   rar3_tool make <out.rar> [options] <entries...>
 *       entries: name=path (file), name/ (directory), L:name=target (Unix symlink),
 *                S:stream=path (NTFS stream of the previous file)
 *   rar3_tool check <archive> [password]       per entry: index status size crc32 name
 *   rar3_tool fuzz <archive> <iters> <seed> [password]
 *   rar3_tool bench <archive> <rounds>
 *
 * The encoders exist for tests only. They mirror the decoders' state machines
 * (unrar's unpack15/20/30) and are checked against 7-Zip and unar:
 *   29  LZ + Huffman blocks (every symbol kind, delta-coded tables, low-distance
 *       repeats, kept tables across solid files), PPMd blocks (escape codes for
 *       matches, filters, block and file ends, escape-char changes, model resets),
 *       RAR VM filters: the forward transform is applied and the filter is defined
 *       with byte code forged to the standard program's length + CRC32 (E8, E8E9,
 *       ITANIUM, DELTA, RGB, AUDIO; also stacked filters)
 *   20  LZ + Huffman and multimedia (audio) blocks, trailing table switches
 *   15  RAR 1.5 adaptive coding: literals, short / long / far matches, repeats,
 *       StMode (decide-then-emit: flag bytes are written before their items)
 * Archive: RAR 2.9 - 4.x headers (solid, volumes in both naming styles, AES /
 * RAR 2.0 / RAR 1.5 encryption, -hp, Unicode names, extended times, CMT and old
 * comments, STM and old stream sub-blocks, large-file fields, unknown sizes,
 * SFX stub with decoy markers) and RAR 1.4 archives.
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "crypto.h"
#include "ppmd7.h"
#include "rar3dec.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

static void die(const char *m)
{
    fprintf(stderr, "rar3_tool: %s\n", m);
    exit(2);
}

static void *xrealloc(void *p, size_t n)
{
    p = realloc(p, n ? n : 1);
    if (!p) die("out of memory");
    return p;
}

static void *xcalloc(size_t n)
{
    void *p = calloc(1, n ? n : 1);
    if (!p) die("out of memory");
    return p;
}

/* ---------------- byte vectors / bit writer ---------------- */

typedef struct { u8 *p; size_t n, cap; } vec;

static void vput(vec *v, const void *s, size_t n)
{
    if (v->n + n > v->cap) {
        v->cap = (v->n + n) * 2 + 256;
        v->p = (u8 *)xrealloc(v->p, v->cap);
    }
    if (n) memcpy(v->p + v->n, s, n);
    v->n += n;
}
static void v8(vec *v, u32 b) { u8 c = (u8)b; vput(v, &c, 1); }
static void v16(vec *v, u32 x) { v8(v, x); v8(v, x >> 8); }
static void v32(vec *v, u32 x) { v16(v, x); v16(v, x >> 16); }

typedef struct { vec v; u64 acc; int nb; } bw;

static void bwr(bw *w, u32 val, int n)
{
    if (n <= 0) return;
    w->acc = (w->acc << n) | (val & (n >= 32 ? 0xFFFFFFFFu : ((1u << n) - 1)));
    w->nb += n;
    while (w->nb >= 8) {
        w->nb -= 8;
        v8(&w->v, (u8)(w->acc >> w->nb));
    }
}
static void bw_align(bw *w) { if (w->nb) bwr(w, 0, 8 - w->nb); }

/* ---------------- random ---------------- */

static u32 rnd_state = 1;
static u32 rnd(void)
{
    u32 x = rnd_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return rnd_state = x ? x : 0x9E3779B9u;
}
static u32 rndn(u32 n) { return n ? rnd() % n : 0; }

/* ---------------- Huffman ---------------- */

/* code lengths <= maxbits from frequencies (scaled until they fit) */
static void hlens(const u32 *freq, int n, u8 *len, int maxbits)
{
    static u64 w[1200];
    static int par[1200], alive[1200];
    u32 f[600];
    for (int i = 0; i < n; i++) f[i] = freq[i];
    for (;;) {
        int nz = 0, last = -1;
        memset(len, 0, (size_t)n);
        for (int i = 0; i < n; i++)
            if (f[i]) { nz++; last = i; }
        if (!nz) return;
        if (nz == 1) { len[last] = 1; return; }
        int nn = n;
        for (int i = 0; i < n; i++) { w[i] = f[i]; alive[i] = f[i] != 0; par[i] = -1; }
        for (int cnt = nz; cnt > 1; cnt--) {
            int a = -1, b = -1;
            for (int j = 0; j < nn; j++) {
                if (!alive[j]) continue;
                if (a < 0 || w[j] < w[a]) { b = a; a = j; }
                else if (b < 0 || w[j] < w[b]) b = j;
            }
            w[nn] = w[a] + w[b];
            alive[nn] = 1;
            par[nn] = -1;
            alive[a] = alive[b] = 0;
            par[a] = par[b] = nn;
            nn++;
        }
        int maxl = 0;
        for (int i = 0; i < n; i++) {
            if (!f[i]) continue;
            int d = 0;
            for (int k = i; par[k] >= 0; k = par[k]) d++;
            len[i] = (u8)d;
            if (d > maxl) maxl = d;
        }
        if (maxl <= maxbits) return;
        for (int i = 0; i < n; i++)
            if (f[i]) f[i] = (f[i] >> 1) | 1;
    }
}

static void hcodes(const u8 *len, int n, u32 *code)
{
    u32 cnt[17] = { 0 }, next[17] = { 0 };
    for (int i = 0; i < n; i++) cnt[len[i]]++;
    cnt[0] = 0;
    u32 c = 0;
    for (int l = 1; l <= 16; l++) {
        c = (c + cnt[l - 1]) << 1;
        next[l] = c;
    }
    for (int i = 0; i < n; i++)
        if (len[i]) code[i] = next[len[i]]++;
}

/* ---------------- shared tables (as in the decoder) ---------------- */

static const u8 ldec[28] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224 };
static const u8 lbits[28] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5 };
static u32 ddec[60];
static u8 dbits[60];
static const u8 sddec[8] = { 0, 4, 8, 16, 32, 64, 128, 192 };
static const u8 sdbits[8] = { 2, 2, 3, 4, 5, 6, 6, 6 };

static void init_tables(void)
{
    static const u8 cnts[19] = { 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12 };
    u32 dist = 0, slot = 0;
    for (u32 bl = 0; bl < 19; bl++)
        for (u32 j = 0; j < cnts[bl]; j++, slot++, dist += 1u << bl) {
            ddec[slot] = dist;
            dbits[slot] = (u8)bl;
        }
}

static u32 lslot(u32 v)       /* length value 0..255 -> slot */
{
    u32 s = 27;
    while (ldec[s] > v) s--;
    return s;
}
static u32 dslot(u32 d, u32 nslots)   /* distance - 1 -> slot */
{
    u32 s = nslots - 1;
    while (ddec[s] > d) s--;
    return s;
}
static u32 sdslot(u32 d)
{
    u32 s = 7;
    while (sddec[s] > d) s--;
    return s;
}

/* ---------------- RAR VM standard filters: forged code + forward transforms ---------------- */

/* F_BOGUS: a valid program that is no standard filter (GZ_E_METHOD), F_BADXOR:
 * code whose XOR check fails (GZ_E_DATA); neither changes the data */
enum { F_NONE = 0, F_E8, F_E8E9, F_ITANIUM, F_DELTA, F_RGB, F_AUDIO, F_BOGUS, F_BADXOR, F_MIX };
static const struct { u32 len, crc; } stdf[9] = {
    { 0, 0 }, { 53, 0xAD576887u }, { 57, 0x3CD7E57Eu }, { 120, 0x3769893Fu },
    { 29, 0x0E06077Du }, { 149, 0x1C2C5DC8u }, { 216, 0xBC85E701u }, { 40, 0x12345678u }, { 30, 0 } };
static u8 fcode[9][256];

/* Bytes with the given length, CRC32 and XOR 0: random prefix, the last four
 * bytes solve the CRC (the table is a bijection on its top byte), retried
 * until the XOR works out. */
static void forge(u32 len, u32 crc, u8 *out)
{
    u8 rev[256];
    for (u32 i = 0; i < 256; i++) rev[gz_crc_table[0][i] >> 24] = (u8)i;
    for (u32 tries = 0;; tries++) {
        for (u32 i = 0; i < len - 4; i++) out[i] = (u8)rnd();
        out[1] &= 0x7F;                                 /* "no static data" for VM parsers */
        u32 r = ~gz_crc32(0, out, len - 4);             /* raw register after the prefix */
        u32 t = ~crc, idx[4];
        for (int i = 3; i >= 0; i--) {
            idx[i] = rev[t >> 24];
            t = (t ^ gz_crc_table[0][idx[i]]) << 8;
        }
        for (int i = 0; i < 4; i++) {
            out[len - 4 + i] = (u8)((r ^ idx[i]) & 0xFF);
            r = (r >> 8) ^ gz_crc_table[0][idx[i]];
        }
        u8 x = 0;
        for (u32 i = 0; i < len; i++) x ^= out[i];
        if (gz_crc32(0, out, len) != crc) die("crc forge failed");
        if (!x) return;
        if (tries > 100000) die("xor forge failed");
    }
}

/* the decoder's E8 map; the encoder inverts it point by point */
static u32 e8_dec(u32 a, u32 o)
{
    if (a & 0x80000000u) return ((a + o) & 0x80000000u) ? a : a + 0x1000000u;
    return a < 0x1000000u ? a - o : a;
}

static void fwd_e8(u8 *b, u32 n, u32 off, int e9)
{
    if (n <= 4) return;
    for (u32 i = 0; i < n - 4;) {
        u8 c = b[i++];
        if (c != 0xE8 && !(e9 && c == 0xE9)) continue;
        u32 o = i + off, x = rd32(b + i), a;
        if (e8_dec(x + o, o) == x) a = x + o;
        else if (e8_dec(x - 0x1000000u, o) == x) a = x - 0x1000000u;
        else a = x;
        if (e8_dec(a, o) != x) die("e8 not invertible");
        wr32(b + i, a);
        i += 4;
    }
}

static u32 ita_get(const u8 *p, u32 pos, u32 cnt)
{
    const u8 *q = p + (pos >> 3);
    u32 v = (u32)q[0] | (u32)q[1] << 8 | (u32)q[2] << 16 | (u32)q[3] << 24;
    return (v >> (pos & 7)) & (0xFFFFFFFFu >> (32 - cnt));
}
static void ita_set(u8 *p, u32 v, u32 pos, u32 cnt)
{
    u8 *q = p + (pos >> 3);
    u32 sh = pos & 7, am = ~((0xFFFFFFFFu >> (32 - cnt)) << sh);
    v <<= sh;
    for (u32 i = 0; i < 4; i++) {
        q[i] = (u8)((q[i] & am) | v);
        am = (am >> 8) | 0xFF000000u;
        v >>= 8;
    }
}
static void fwd_itanium(u8 *b, u32 n, u32 off)
{
    static const u8 masks[16] = { 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0 };
    if (n <= 21) return;
    u32 fo = off >> 4;
    for (u32 pos = 0; pos < n - 21; pos += 16, fo++) {
        u8 *q = b + pos;
        int t = (q[0] & 0x1F) - 0x10;
        if (t < 0) continue;
        for (u32 s = 0; s <= 2; s++) {
            if (!(masks[t] & (1u << s))) continue;
            u32 sp = s * 41 + 5;
            if (ita_get(q, sp + 37, 4) == 5) ita_set(q, (ita_get(q, sp + 13, 20) + fo) & 0xFFFFF, sp + 13, 20);
        }
    }
}
static void fwd_delta(u8 *b, u32 n, u32 ch)
{
    u8 *t = (u8 *)xcalloc(n);
    u32 k = 0;
    for (u32 c = 0; c < ch; c++) {
        u8 prev = 0;
        for (u32 i = c; i < n; i += ch) { t[k++] = (u8)(prev - b[i]); prev = b[i]; }
    }
    memcpy(b, t, n);
    free(t);
}
static void fwd_rgb(u8 *b, u32 n, u32 width, u32 posr)
{
    u8 *y = (u8 *)xcalloc(n), *s = (u8 *)xcalloc(n);
    memcpy(y, b, n);
    for (u32 i = posr; i + 2 < n; i += 3) {
        y[i] = (u8)(y[i] - y[i + 1]);
        y[i + 2] = (u8)(y[i + 2] - y[i + 1]);
    }
    u32 k = 0;
    for (u32 c = 0; c < 3; c++) {
        u32 prev = 0;
        for (u32 i = c; i < n; i += 3) {
            u32 pred = prev;
            if (i >= width) {
                int up = y[i - width + 3], ul = y[i - width], pr = (int)prev + up - ul;
                int pa = abs(pr - (int)prev), pb = abs(pr - up), pc = abs(pr - ul);
                if (pa <= pb && pa <= pc) pred = prev;
                else if (pb <= pc) pred = (u32)up;
                else pred = (u32)ul;
            }
            s[k++] = (u8)(pred - y[i]);
            prev = y[i];
        }
    }
    memcpy(b, s, n);
    free(y);
    free(s);
}
static void fwd_audio(u8 *b, u32 n, u32 ch)
{
    u8 *s = (u8 *)xcalloc(n);
    u32 k = 0;
    for (u32 c = 0; c < ch; c++) {
        u32 prev = 0, dif[7] = { 0 };
        int pdelta = 0, d1 = 0, d2 = 0, d3, k1 = 0, k2 = 0, k3 = 0;
        for (u32 i = c, cnt = 0; i < n; i += ch, cnt++) {
            d3 = d2;
            d2 = pdelta - d1;
            d1 = pdelta;
            u32 pred = 8 * prev + (u32)(k1 * d1) + (u32)(k2 * d2) + (u32)(k3 * d3);
            pred = (pred >> 3) & 0xFF;
            u32 cur = (pred - b[i]) & 0xFF;
            s[k++] = (u8)cur;
            u32 val = b[i];
            pdelta = (i8)(u8)(val - prev);
            prev = val;
            int dd = (i8)(u8)cur * 8;
            dif[0] += (u32)abs(dd);
            dif[1] += (u32)abs(dd - d1);
            dif[2] += (u32)abs(dd + d1);
            dif[3] += (u32)abs(dd - d2);
            dif[4] += (u32)abs(dd + d2);
            dif[5] += (u32)abs(dd - d3);
            dif[6] += (u32)abs(dd + d3);
            if (!(cnt & 0x1F)) {
                u32 md = dif[0], nm = 0;
                dif[0] = 0;
                for (u32 j = 1; j < 7; j++) {
                    if (dif[j] < md) { md = dif[j]; nm = j; }
                    dif[j] = 0;
                }
                switch (nm) {
                case 1: if (k1 >= -16) k1--; break;
                case 2: if (k1 < 16) k1++; break;
                case 3: if (k2 >= -16) k2--; break;
                case 4: if (k2 < 16) k2++; break;
                case 5: if (k3 >= -16) k3--; break;
                case 6: if (k3 < 16) k3++; break;
                }
            }
        }
    }
    memcpy(b, s, n);
    free(s);
}

/* filter definitions planned for one file */
typedef struct {
    u64 start;               /* absolute stream position of the block */
    u32 len, type, r0, r1;
    u64 emit_at;             /* define it once the encoder reaches this position */
    int done;
} fplan;

/* ---------------- match finder (hash chains over the whole stream) ---------------- */

typedef struct {
    const u8 *data;
    size_t size, sstart;     /* stream start (files before it are unreachable) */
    u32 *head, *prevp;
    size_t ins;
} mfind;

static u32 h3(const u8 *p) { return ((u32)p[0] << 10 ^ (u32)p[1] << 5 ^ p[2]) & 0xFFFF; }

static void mf_init(mfind *m, const u8 *data, size_t size)
{
    memset(m, 0, sizeof *m);
    m->data = data;
    m->size = size;
    m->head = (u32 *)xcalloc(65536 * sizeof(u32));
    m->prevp = (u32 *)xcalloc((size + 1) * sizeof(u32));
}

static void mf_free(mfind *m)
{
    free(m->head);
    free(m->prevp);
}

static void hash_upto(mfind *m, size_t pos)
{
    while (m->ins < pos) {
        if (m->ins + 3 <= m->size) {
            u32 h = h3(m->data + m->ins);
            m->prevp[m->ins] = m->head[h];
            m->head[h] = (u32)m->ins + 1;
        }
        m->ins++;
    }
}

static u32 mlen(const u8 *d, size_t pos, size_t dist, u32 max)
{
    u32 l = 0;
    while (l < max && d[pos + l] == d[pos - dist + l]) l++;
    return l;
}

/* longest match at pos (dist <= maxd) through the hash chain */
static u32 find_match(mfind *m, size_t pos, u32 max, u32 maxd, int depth, u32 *pdist)
{
    u32 best = 0;
    *pdist = 0;
    if (max < 3 || pos + 3 > m->size) return 0;
    u32 c = m->head[h3(m->data + pos)];
    while (c && depth--) {
        size_t cp = c - 1;
        if (cp >= pos || cp < m->sstart) break;
        size_t d = pos - cp;
        if (d > maxd) break;
        u32 l = mlen(m->data, pos, d, max);
        if (l > best) { best = l; *pdist = (u32)d; if (l == max) break; }
        c = m->prevp[cp];
    }
    return best;
}

/* ================= RAR 2.9 encoder ================= */

#define NC30 299
#define DC30 60
#define LDC30 17
#define RC30 28
#define BC30 20
#define T30 (NC30 + DC30 + LDC30 + RC30)

enum { T_MAIN = 0, T_DIST, T_LOW, T_LEN, T_RAW };
typedef struct { u8 t, nb; u16 sym; u32 bits; } sitem;

typedef struct {
    /* options */
    u32 dict;
    int blk;                 /* symbols per LZ block (0: one block per file part)  */
    int ppm;                 /* 0 LZ, 1 PPMd, 2 LZ and PPMd blocks mixed           */
    u32 ppm_order, ppm_mb;
    int variety;             /* use every symbol kind, random block options        */
    int lazy;
    mfind m;                 /* input (all files of a solid run, filters applied) */
    /* mirrored decoder state */
    u32 rep[4], lastlen, prev_low, low_rep;
    u8 old[T30];
    u8 clen[T30];
    u32 ccode[T30];
    int have_tables;         /* decoder's tables30 */
    int ppm_mode;
    gz_ppmd7 *pm;
    gz_stream_io pm_io;      /* the PPMd encoder keeps a pointer to it */
    int pm_ok, esc;
    u32 nfdef, last_filter;
    struct { u32 type, len; } fdef[64];
    /* current LZ block */
    sitem *it;
    size_t nit, capit;
    u32 freq[T30];
    int fixed;
    u32 blk_syms;
    bw w;
} e29;

static int pm_write(void *ctx, const u8 *p, size_t n)
{
    vput(&((e29 *)ctx)->w.v, p, n);
    return GZ_OK;
}

static const u32 toff[4] = { 0, NC30, NC30 + DC30, NC30 + DC30 + LDC30 };

static void it_add(e29 *e, int t, u32 sym, u32 bits, int nb)
{
    if (e->nit == e->capit) {
        e->capit = e->capit * 2 + 4096;
        e->it = (sitem *)xrealloc(e->it, e->capit * sizeof(sitem));
    }
    sitem *s = &e->it[e->nit++];
    s->t = (u8)t;
    s->sym = (u16)sym;
    s->bits = bits;
    s->nb = (u8)nb;
    if (t != T_RAW) e->freq[toff[t] + sym]++;
}

static int codable(const e29 *e, int t, u32 sym)
{
    return !e->fixed || e->clen[toff[t] + sym] != 0;
}

/* write the BD-coded table lengths (keep: delta against the old table) */
static void put_tables29(e29 *e, const u8 *lens, int keep)
{
    bw *w = &e->w;
    u8 sym[T30 + 8];
    u32 ex[T30 + 8], nsym = 0, bdf[BC30] = { 0 };
    u8 nbx[T30 + 8];
    for (u32 i = 0; i < T30;) {
        u32 run = 1;
        if (lens[i] == 0) {
            while (i + run < T30 && lens[i + run] == 0 && run < 138) run++;
            if (run >= 3 && (!e->variety || rndn(4))) {
                if (run <= 10) { sym[nsym] = 18; ex[nsym] = run - 3; nbx[nsym] = 3; }
                else { sym[nsym] = 19; ex[nsym] = run - 11; nbx[nsym] = 7; }
                bdf[sym[nsym++]]++;
                i += run;
                continue;
            }
        }
        run = 0;
        if (i > 0)
            while (i + run < T30 && lens[i + run] == lens[i - 1] && run < 138) run++;
        if (run >= 3 && (!e->variety || rndn(4))) {
            if (run <= 10) { sym[nsym] = 16; ex[nsym] = run - 3; nbx[nsym] = 3; }
            else { sym[nsym] = 17; ex[nsym] = run - 11; nbx[nsym] = 7; }
            bdf[sym[nsym++]]++;
            i += run;
            continue;
        }
        sym[nsym] = (u8)((lens[i] - (keep ? e->old[i] : 0)) & 15);
        nbx[nsym] = 0;
        bdf[sym[nsym++]]++;
        i++;
    }
    u8 bl[BC30];
    u32 bc[BC30];
    hlens(bdf, BC30, bl, 15);
    hcodes(bl, BC30, bc);
    bwr(w, 0, 1);                       /* LZ block */
    bwr(w, keep ? 1 : 0, 1);
    for (u32 i = 0; i < BC30;) {
        if (bl[i] == 0) {
            u32 z = 1;
            while (i + z < BC30 && bl[i + z] == 0 && z < 17) z++;
            if (z >= 3) {
                bwr(w, 15, 4);
                bwr(w, z - 2, 4);
                i += z;
                continue;
            }
        }
        bwr(w, bl[i], 4);
        if (bl[i] == 15) bwr(w, 0, 4);
        i++;
    }
    for (u32 k = 0; k < nsym; k++) {
        bwr(w, bc[sym[k]], bl[sym[k]]);
        bwr(w, ex[k], nbx[k]);
    }
}

/* finish the current LZ block: tables (unless fixed) and its symbols */
static void lz_flush(e29 *e)
{
    if (!e->fixed) {
        u8 lens[T30];
        for (int t = 0; t < 4; t++) {
            static const int nn[4] = { NC30, DC30, LDC30, RC30 };
            hlens(e->freq + toff[t], nn[t], lens + toff[t], 15);
        }
        int keep = e->variety ? (int)rndn(2) : 0;
        bw_align(&e->w);
        put_tables29(e, lens, keep);
        memcpy(e->clen, lens, T30);
        memcpy(e->old, lens, T30);
        for (int t = 0; t < 4; t++) {
            static const int nn[4] = { NC30, DC30, LDC30, RC30 };
            hcodes(lens + toff[t], nn[t], e->ccode + toff[t]);
        }
    }
    for (size_t i = 0; i < e->nit; i++) {
        const sitem *s = &e->it[i];
        if (s->t != T_RAW) {
            u32 k = toff[s->t] + s->sym;
            if (!e->clen[k]) die("symbol without code");
            bwr(&e->w, e->ccode[k], e->clen[k]);
        }
        bwr(&e->w, s->bits, s->nb);
    }
    e->nit = 0;
    memset(e->freq, 0, sizeof e->freq);
}

static void pm_sym(e29 *e, int s)
{
    if (gz_ppmd7_rar_enc_symbol(e->pm, s)) die("ppmd encode");
}

static void ppm_open(e29 *e)
{
    bw_align(&e->w);
    int reset = !e->pm_ok || (e->variety && rndn(4) == 0);
    int newesc = e->variety && rndn(3) == 0;
    u32 flags = 0x80, order = e->ppm_order, code;
    if (order <= 16) {
        code = order - 1;
    } else {
        u32 k = (order - 16 + 2) / 3;
        if (k > 16) k = 16;
        order = 16 + 3 * k;
        code = 15 + k;
    }
    if (reset) flags |= 0x20 | code;
    if (newesc) flags |= 0x40;
    v8(&e->w.v, flags);
    if (reset) v8(&e->w.v, e->ppm_mb);
    if (newesc) {
        e->esc = (int)rndn(256);
        v8(&e->w.v, (u32)e->esc);
    }
    e->pm_io.read = 0;
    e->pm_io.write = pm_write;
    e->pm_io.ctx = e;
    if (!e->pm && !(e->pm = gz_ppmd7_new())) die("ppmd new");
    int r = reset ? gz_ppmd7_rar_enc_begin(e->pm, order, (e->ppm_mb + 1) << 20, &e->pm_io)
                  : gz_ppmd7_rar_enc_begin_rc(e->pm, &e->pm_io);
    if (r) die("ppmd begin");
    e->pm_ok = 1;
    e->ppm_mode = 1;
    e->have_tables = 0;
    e->blk_syms = 0;
}

static void ppm_close(e29 *e)
{
    if (gz_ppmd7_rar_enc_end(e->pm)) die("ppmd end");
}

static void lz_open(e29 *e, int fixed)
{
    e->fixed = fixed;
    e->ppm_mode = 0;
    e->blk_syms = 0;
    if (!fixed) e->prev_low = e->low_rep = 0;     /* the decoder resets them with the tables */
    e->have_tables = 1;
}

static void open_block(e29 *e)
{
    int ppm = e->ppm == 1 || (e->ppm == 2 && rndn(2));
    if (ppm) ppm_open(e);
    else lz_open(e, 0);
}

/* end the current block (not the file) and start another */
static void switch_block(e29 *e)
{
    if (e->ppm_mode) {
        pm_sym(e, e->esc);
        pm_sym(e, 0);
        ppm_close(e);
    } else {
        it_add(e, T_MAIN, 256, 0, 0);
        it_add(e, T_RAW, 0, 1, 1);
        lz_flush(e);
    }
    open_block(e);
}

static void vm_data(bw *w, u32 v)
{
    if (v < 16) { bwr(w, 0, 2); bwr(w, v, 4); }
    else if (v < 256) { bwr(w, 1, 2); bwr(w, v, 8); }
    else if (v >= 0xFFFFFF00u) { bwr(w, 1, 2); bwr(w, 0, 4); bwr(w, v & 0xFF, 8); }
    else if (v < 65536) { bwr(w, 2, 2); bwr(w, v, 16); }
    else { bwr(w, 3, 2); bwr(w, v >> 16, 16); bwr(w, v & 0xFFFF, 16); }
}

/* filter definition (FirstByte + code bytes) for plan f with the encoder at pos */
static u32 make_vm(e29 *e, const fplan *f, u64 pos, int may_reset, u8 *out, u32 *pfirst)
{
    bw w;
    memset(&w, 0, sizeof w);
    u32 first = 0;
    int idx = -1;
    for (u32 i = 0; i < e->nfdef; i++)
        if (e->fdef[i].type == f->type) { idx = (int)i; break; }
    if (idx >= 0 && e->variety && !rndn(5)) idx = -1;
    int newf = idx < 0;
    if (newf && e->nfdef >= 60) may_reset = 2;
    u32 fpos;
    if (newf && may_reset && e->nfdef && (may_reset == 2 || (e->variety && !rndn(4)))) {
        first |= 0x80;
        vm_data(&w, 0);                    /* InitFilters: forget every definition */
        e->nfdef = 0;
        e->last_filter = 0;
        fpos = 0;
    } else {
        fpos = newf ? e->nfdef : (u32)idx;
        if (newf || fpos != e->last_filter || (e->variety && rndn(2))) {
            first |= 0x80;
            vm_data(&w, fpos + 1);
        }
    }
    u32 bstart = (u32)(f->start - pos);
    if (bstart >= 258 && e->variety && rndn(2)) {
        first |= 0x40;
        vm_data(&w, bstart - 258);
    } else {
        vm_data(&w, bstart);
    }
    u32 oldlen = newf ? 0 : e->fdef[fpos].len;
    if (f->len != oldlen || (e->variety && !rndn(3))) {
        first |= 0x20;
        vm_data(&w, f->len);
    }
    u32 mask = 0, reg[7] = { 0 };
    if (f->type == F_DELTA || f->type == F_AUDIO) { mask |= 1; reg[0] = f->r0; }
    if (f->type == F_RGB) { mask |= 3; reg[0] = f->r0; reg[1] = f->r1; }
    if (e->variety && !rndn(3)) {
        /* registers the standard filters ignore; R4 must stay the block length */
        if (rndn(2)) { mask |= 4; reg[2] = rnd(); }
        if (rndn(2)) { mask |= 8; reg[3] = rnd() & 0xFFFF; }
        if (rndn(2)) { mask |= 16; reg[4] = f->len; }
        if (rndn(2)) { mask |= 64; reg[6] = rnd() & 0xFF; }
    }
    if (mask) {
        first |= 0x10;
        bwr(&w, mask, 7);
        for (u32 i = 0; i < 7; i++)
            if (mask & (1u << i)) vm_data(&w, reg[i]);
    }
    if (newf) {
        vm_data(&w, stdf[f->type].len);
        for (u32 i = 0; i < stdf[f->type].len; i++) bwr(&w, fcode[f->type][i], 8);
    }
    if (e->variety && !rndn(4)) {
        u32 n = rndn(24);                  /* global data: ignored by the standard filters */
        first |= 0x08;
        vm_data(&w, n);
        for (u32 i = 0; i < n; i++) bwr(&w, rnd() & 0xFF, 8);
    }
    bw_align(&w);
    if (newf) {
        e->fdef[e->nfdef].type = f->type;
        e->fdef[e->nfdef].len = 0;
        e->nfdef++;
    }
    if (first & 0x20) e->fdef[fpos].len = f->len;
    e->last_filter = fpos;
    u32 n = (u32)w.v.n;
    memcpy(out, w.v.p, n);
    free(w.v.p);
    *pfirst = first;
    return n;
}

static void emit_vm(e29 *e, const fplan *f, u64 pos, int may_reset)
{
    u8 code[1024];
    if (!e->ppm_mode && !codable(e, T_MAIN, 257)) switch_block(e);
    u32 first, n = make_vm(e, f, pos, may_reset, code, &first);
    u32 lo = n <= 6 ? n - 1 : n < 7 + 256 ? 6 : 7;
    first |= lo;
    if (e->ppm_mode) {
        pm_sym(e, e->esc);
        pm_sym(e, 3);
        pm_sym(e, (int)first);
        if (lo == 6) pm_sym(e, (int)(n - 7));
        if (lo == 7) { pm_sym(e, (int)(n >> 8)); pm_sym(e, (int)(n & 0xFF)); }
        for (u32 i = 0; i < n; i++) pm_sym(e, code[i]);
        return;
    }
    it_add(e, T_MAIN, 257, 0, 0);
    it_add(e, T_RAW, 0, first, 8);
    if (lo == 6) it_add(e, T_RAW, 0, n - 7, 8);
    if (lo == 7) it_add(e, T_RAW, 0, n, 16);
    for (u32 i = 0; i < n; i++) it_add(e, T_RAW, 0, code[i], 8);
}

static u32 corr29(u32 dist) { return (dist >= 0x2000) + (dist >= 0x40000); }

/* one LZ decision at pos: returns the bytes it covers (0: switched to PPMd) */
static size_t lz_step(e29 *e, size_t pos, size_t fe)
{
    const u8 *d = e->m.data;
    size_t avail = pos - e->m.sstart;
    u32 maxlen = fe - pos < 257 ? (u32)(fe - pos) : 257;
    u32 maxd = avail < e->dict ? (u32)avail : e->dict;
    hash_upto(&e->m, pos);
    u32 rl[4] = { 0, 0, 0, 0 };
    for (int k = 0; k < 4; k++)
        if (e->rep[k] && e->rep[k] <= maxd) rl[k] = mlen(d, pos, e->rep[k], maxlen);
    u32 md = 0, ml = find_match(&e->m, pos, maxlen, maxd, e->lazy ? 64 : 16, &md);
    u32 bestrep = 0, brk = 0;
    for (int k = 0; k < 4; k++)
        if (rl[k] > bestrep) { bestrep = rl[k]; brk = (u32)k; }
    for (int attempt = 0; attempt < 2; attempt++) {
        /* options: 0 = 258 (last length, rep0), 1 = rep, 2 = new, 3 = short, then literal */
        int order[4] = { 0, 1, 2, 3 };
        if (e->variety) {
            for (int i = 0; i < 3; i++) {
                int j = i + (int)rndn((u32)(4 - i));
                int t = order[i]; order[i] = order[j]; order[j] = t;
            }
        } else if (ml > bestrep + 1) {
            order[0] = 2; order[1] = 1; order[2] = 0;
        }
        for (int oi = 0; oi < 5; oi++) {
            int opt = oi < 4 ? order[oi] : 4;
            if (opt == 0) {
                if (!e->lastlen || !e->rep[0] || rl[0] < e->lastlen) continue;
                if (!e->variety && e->lastlen < bestrep) continue;
                if (!codable(e, T_MAIN, 258)) continue;
                it_add(e, T_MAIN, 258, 0, 0);
                return e->lastlen;
            }
            if (opt == 1) {
                if (bestrep < 2) continue;
                u32 len = bestrep;
                if (e->variety && len > 2 && !rndn(3)) len = 2 + rndn(len - 1);
                u32 v = len - 2, s = lslot(v);
                if (!codable(e, T_MAIN, 259 + brk) || !codable(e, T_LEN, s)) continue;
                it_add(e, T_MAIN, 259 + brk, 0, 0);
                it_add(e, T_LEN, s, v - ldec[s], lbits[s]);
                u32 dist = e->rep[brk];
                for (u32 i = brk; i > 0; i--) e->rep[i] = e->rep[i - 1];
                e->rep[0] = dist;
                e->lastlen = len;
                return len;
            }
            if (opt == 2) {
                if (!md) continue;
                u32 len = ml, c = corr29(md);
                if (len < 3 + c) continue;
                if (e->variety && len > 3 + c && !rndn(3)) len = 3 + c + rndn(len - 2 - c);
                u32 v = len - 3 - c, s = lslot(v), dd = md - 1, ds = dslot(dd, 60), nb = dbits[ds];
                u32 ex = dd - ddec[ds], low = dd & 15;
                int use16 = 0;
                if (ds > 9) {
                    if (e->low_rep && low != e->prev_low) continue;
                    if (!e->low_rep) {
                        use16 = low == e->prev_low && e->variety && rndn(2);
                        if (!codable(e, T_LOW, use16 ? 16 : low)) continue;
                    }
                }
                if (!codable(e, T_MAIN, 271 + s) || !codable(e, T_DIST, ds)) continue;
                it_add(e, T_MAIN, 271 + s, v - ldec[s], lbits[s]);
                if (ds > 9) {
                    it_add(e, T_DIST, ds, nb > 4 ? ex >> 4 : 0, nb > 4 ? (int)nb - 4 : 0);
                    if (e->low_rep) {
                        e->low_rep--;
                    } else if (use16) {
                        it_add(e, T_LOW, 16, 0, 0);
                        e->low_rep = 15;
                    } else {
                        it_add(e, T_LOW, low, 0, 0);
                        e->prev_low = low;
                    }
                } else {
                    it_add(e, T_DIST, ds, ex, (int)nb);
                }
                e->rep[3] = e->rep[2];
                e->rep[2] = e->rep[1];
                e->rep[1] = e->rep[0];
                e->rep[0] = md;
                e->lastlen = len;
                return len;
            }
            if (opt == 3) {
                u32 sd = 0;
                if (md && md <= 256 && ml >= 2) sd = md;
                else if (maxlen >= 2)
                    for (u32 k = 1; k <= 256 && k <= maxd; k++)
                        if (d[pos] == d[pos - k] && d[pos + 1] == d[pos + 1 - k]) { sd = k; break; }
                if (!sd) continue;
                u32 dd = sd - 1, s = sdslot(dd);
                if (!codable(e, T_MAIN, 263 + s)) continue;
                it_add(e, T_MAIN, 263 + s, dd - sddec[s], sdbits[s]);
                e->rep[3] = e->rep[2];
                e->rep[2] = e->rep[1];
                e->rep[1] = e->rep[0];
                e->rep[0] = sd;
                e->lastlen = 2;
                return 2;
            }
            if (!codable(e, T_MAIN, d[pos])) break;
            it_add(e, T_MAIN, d[pos], 0, 0);
            return 1;
        }
        /* fixed tables without a usable code: a new block makes everything codable */
        switch_block(e);
        if (e->ppm_mode) return 0;
    }
    die("lz_step");
    return 0;
}

/* one PPMd decision at pos */
static size_t ppm_step(e29 *e, size_t pos, size_t fe)
{
    const u8 *d = e->m.data;
    size_t avail = pos - e->m.sstart;
    hash_upto(&e->m, pos);
    if (e->variety && !rndn(6) && avail) {
        u32 l = mlen(d, pos, 1, fe - pos < 259 ? (u32)(fe - pos) : 259);
        if (l >= 4) {
            pm_sym(e, e->esc);
            pm_sym(e, 5);
            pm_sym(e, (int)(l - 4));
            return l;
        }
        u32 maxd = avail < e->dict ? (u32)avail : e->dict, md;
        u32 ml = find_match(&e->m, pos, fe - pos < 287 ? (u32)(fe - pos) : 287, maxd, 32, &md);
        if (ml >= 32 && md >= 2) {
            u32 v = md - 2;
            pm_sym(e, e->esc);
            pm_sym(e, 4);
            pm_sym(e, (int)((v >> 16) & 0xFF));
            pm_sym(e, (int)((v >> 8) & 0xFF));
            pm_sym(e, (int)(v & 0xFF));
            pm_sym(e, (int)(ml - 32));
            return ml;
        }
    }
    int c = d[pos];
    pm_sym(e, c);
    if (c == e->esc) pm_sym(e, e->variety && !rndn(3) ? 6 + (int)rndn(250) : 1);   /* unknown codes: literal too */
    return 1;
}

/* Encode file [fs, fe) of the stream into out. Filter plans fp cover the file. */
static void enc29_file(e29 *e, size_t fs, size_t fe, int solid, fplan *fp, u32 nfp, vec *out)
{
    if (!solid) {
        memset(e->rep, 0, sizeof e->rep);
        e->lastlen = e->prev_low = e->low_rep = 0;
        e->have_tables = 0;
        memset(e->old, 0, sizeof e->old);
        e->esc = 2;
        e->pm_ok = 0;
        e->nfdef = 0;
        e->last_filter = 0;
        e->m.sstart = fs;
    }
    memset(&e->w, 0, sizeof e->w);
    e->nit = 0;
    memset(e->freq, 0, sizeof e->freq);
    if (!solid || !e->have_tables) open_block(e);
    else lz_open(e, 1);
    size_t pos = fs;
    int first_vm = 1;
    while (pos < fe) {
        for (u32 i = 0; i < nfp; i++) {
            fplan *f = &fp[i];
            if (f->done || (pos < f->emit_at && pos + 300 < f->start)) continue;
            emit_vm(e, f, pos, first_vm);
            first_vm = 0;
            f->done = 1;
        }
        if (e->blk && ++e->blk_syms > (u32)e->blk) switch_block(e);
        pos += e->ppm_mode ? ppm_step(e, pos, fe) : lz_step(e, pos, fe);
    }
    if (e->ppm_mode) {
        pm_sym(e, e->esc);
        pm_sym(e, 2);
        ppm_close(e);
    } else {
        u32 nt = e->variety ? rndn(2) : 0;
        if (!codable(e, T_MAIN, 256)) die("no end code");
        it_add(e, T_MAIN, 256, 0, 0);
        it_add(e, T_RAW, 0, 0, 1);
        it_add(e, T_RAW, 0, nt, 1);
        lz_flush(e);
        e->have_tables = !nt;
    }
    bw_align(&e->w);
    *out = e->w.v;
    memset(&e->w, 0, sizeof e->w);
}

/* ================= RAR 2.0 encoder ================= */

#define NC20 298
#define DC20 48
#define RC20 28
#define BC20 19
#define MC20 257
#define T20 (MC20 * 4)

typedef struct { int k[5], d[4], last_delta; u32 dif[11], count, last_char; } aud20;

typedef struct {
    u32 dict;
    int blk, variety;
    u32 audio;               /* channels for multimedia blocks (0: LZ only)   */
    mfind m;
    /* mirrored decoder state */
    u32 rep[4], rep_ptr, last_len, last_dist;
    u8 old[T20];
    int have_tables, amode;
    u32 nch, cur_ch;
    int cdelta;
    aud20 aud[4];
    u8 clen[T20];
    u32 ccode[T20];
    /* current block */
    sitem *it;
    size_t nit, capit;
    u32 freq[T20];
    int fixed;
    u32 blk_syms;
    bw w;
} e20;

static u32 off20(const e20 *e, int t)
{
    if (e->amode) return (u32)t * MC20;
    return t == 0 ? 0 : t == 1 ? NC20 : NC20 + DC20;
}

static void it20(e20 *e, int t, u32 sym, u32 bits, int nb)
{
    if (e->nit == e->capit) {
        e->capit = e->capit * 2 + 4096;
        e->it = (sitem *)xrealloc(e->it, e->capit * sizeof(sitem));
    }
    sitem *s = &e->it[e->nit++];
    s->t = (u8)t;
    s->sym = (u16)sym;
    s->bits = bits;
    s->nb = (u8)nb;
    if (t != T_RAW) e->freq[off20(e, t) + sym]++;
}

static int codable20(const e20 *e, int t, u32 sym)
{
    return !e->fixed || e->clen[off20(e, t) + sym] != 0;
}

/* header + tables for the block in mode amode (lens: table lengths) */
static void put_tables20(e20 *e, const u8 *lens, u32 n)
{
    bw *w = &e->w;
    int keep = e->variety ? (int)rndn(2) : 0;
    u8 sym[T20 + 8], nbx[T20 + 8];
    u32 ex[T20 + 8], ns = 0, bdf[BC20] = { 0 };
    for (u32 i = 0; i < n;) {
        u32 run = 1;
        if (!lens[i]) {
            while (i + run < n && !lens[i + run] && run < 138) run++;
            if (run >= 3 && (!e->variety || rndn(4))) {
                if (run <= 10) { sym[ns] = 17; ex[ns] = run - 3; nbx[ns] = 3; }
                else { sym[ns] = 18; ex[ns] = run - 11; nbx[ns] = 7; }
                bdf[sym[ns++]]++;
                i += run;
                continue;
            }
        }
        run = 0;
        if (i > 0)
            while (i + run < n && lens[i + run] == lens[i - 1] && run < 6) run++;
        if (run >= 3 && (!e->variety || rndn(4))) {
            sym[ns] = 16;
            ex[ns] = run - 3;
            nbx[ns] = 2;
            bdf[16]++;
            ns++;
            i += run;
            continue;
        }
        sym[ns] = (u8)((lens[i] - (keep ? e->old[i] : 0)) & 15);
        nbx[ns] = 0;
        bdf[sym[ns++]]++;
        i++;
    }
    u8 bl[BC20];
    u32 bc[BC20];
    hlens(bdf, BC20, bl, 15);
    hcodes(bl, BC20, bc);
    bwr(w, e->amode ? 1 : 0, 1);
    bwr(w, keep ? 1 : 0, 1);
    if (e->amode) bwr(w, e->nch - 1, 2);
    for (u32 i = 0; i < BC20; i++) bwr(w, bl[i], 4);
    for (u32 k = 0; k < ns; k++) {
        bwr(w, bc[sym[k]], bl[sym[k]]);
        bwr(w, ex[k], nbx[k]);
    }
    if (!keep) memset(e->old, 0, sizeof e->old);
    memcpy(e->old, lens, n);
}

static void set_tables20(e20 *e, const u8 *lens)
{
    u32 n = e->amode ? MC20 * e->nch : NC20 + DC20 + RC20;
    put_tables20(e, lens, n);
    memset(e->clen, 0, sizeof e->clen);
    memcpy(e->clen, lens, n);
    if (e->amode) {
        for (u32 c = 0; c < e->nch; c++) hcodes(lens + c * MC20, MC20, e->ccode + c * MC20);
    } else {
        hcodes(lens, NC20, e->ccode);
        hcodes(lens + NC20, DC20, e->ccode + NC20);
        hcodes(lens + NC20 + DC20, RC20, e->ccode + NC20 + DC20);
    }
}

static void flush20(e20 *e)
{
    if (!e->fixed) {
        u8 lens[T20];
        memset(lens, 0, sizeof lens);
        if (e->amode) {
            for (u32 c = 0; c < e->nch; c++) hlens(e->freq + c * MC20, MC20, lens + c * MC20, 15);
        } else {
            hlens(e->freq, NC20, lens, 15);
            hlens(e->freq + NC20, DC20, lens + NC20, 15);
            hlens(e->freq + NC20 + DC20, RC20, lens + NC20 + DC20, 15);
        }
        set_tables20(e, lens);
    }
    for (size_t i = 0; i < e->nit; i++) {
        const sitem *s = &e->it[i];
        if (s->t != T_RAW) {
            u32 k = off20(e, s->t) + s->sym;
            if (!e->clen[k]) die("symbol without code (2.0)");
            bwr(&e->w, e->ccode[k], e->clen[k]);
        }
        bwr(&e->w, s->bits, s->nb);
    }
    e->nit = 0;
    memset(e->freq, 0, sizeof e->freq);
}

/* new block in the chosen mode; the switch symbol must be counted in every table */
static void open20(e20 *e)
{
    int am = e->audio && (!e->variety || rndn(4)) ? 1 : 0;
    e->amode = am;
    if (am) {
        e->nch = e->variety ? 1 + rndn(e->audio) : e->audio;
        if (e->cur_ch >= e->nch) e->cur_ch = 0;
    }
    e->fixed = 0;
    e->blk_syms = 0;
    e->have_tables = 1;
    if (am) for (u32 c = 0; c < e->nch; c++) e->freq[c * MC20 + 256]++;
    else e->freq[269]++;
}

static void switch20(e20 *e)
{
    if (e->amode) it20(e, (int)e->cur_ch, 256, 0, 0);
    else it20(e, 0, 269, 0, 0);
    flush20(e);
    open20(e);
}

/* Unpack::DecodeAudio run forward: the delta that makes the decoder output x */
static u32 audio_delta(e20 *e, u32 x)
{
    aud20 *v = &e->aud[e->cur_ch];
    v->count++;
    v->d[3] = v->d[2];
    v->d[2] = v->d[1];
    v->d[1] = v->last_delta - v->d[0];
    v->d[0] = v->last_delta;
    u32 pch = 8 * v->last_char + (u32)(v->k[0] * v->d[0]) + (u32)(v->k[1] * v->d[1]) +
              (u32)(v->k[2] * v->d[2]) + (u32)(v->k[3] * v->d[3]) + (u32)(v->k[4] * e->cdelta);
    pch = (pch >> 3) & 0xFF;
    u32 delta = (pch - x) & 0xFF;
    int dd = (i8)(u8)delta * 8;
    int t[5] = { v->d[0], v->d[1], v->d[2], v->d[3], e->cdelta };
    v->dif[0] += (u32)abs(dd);
    for (u32 i = 0; i < 5; i++) {
        v->dif[1 + 2 * i] += (u32)abs(dd - t[i]);
        v->dif[2 + 2 * i] += (u32)abs(dd + t[i]);
    }
    e->cdelta = v->last_delta = (i8)(u8)(x - v->last_char);
    v->last_char = x;
    if (!(v->count & 0x1F)) {
        u32 md = v->dif[0], nm = 0;
        v->dif[0] = 0;
        for (u32 i = 1; i < 11; i++) {
            if (v->dif[i] < md) { md = v->dif[i]; nm = i; }
            v->dif[i] = 0;
        }
        if (nm) {
            int *k = &v->k[(nm - 1) >> 1];
            if (nm & 1) { if (*k >= -16) (*k)--; }
            else if (*k < 16) (*k)++;
        }
    }
    return delta;
}

static u32 corr20r(u32 dist) { return (dist >= 0x101) + (dist >= 0x2000) + (dist >= 0x40000); }

static void push20(e20 *e, u32 len, u32 dist)
{
    e->last_dist = e->rep[e->rep_ptr++ & 3] = dist;
    e->last_len = len;
}

static size_t lz20_step(e20 *e, size_t pos, size_t fe)
{
    const u8 *d = e->m.data;
    size_t avail = pos - e->m.sstart;
    u32 maxlen = fe - pos < 257 ? (u32)(fe - pos) : 257;
    u32 maxd = avail < e->dict ? (u32)avail : e->dict;
    if (maxd > 0x100000) maxd = 0x100000;
    hash_upto(&e->m, pos);
    if (e->amode) {
        u32 delta;
        aud20 save = e->aud[e->cur_ch];
        int sc = e->cdelta;
        delta = audio_delta(e, d[pos]);
        if (!codable20(e, (int)e->cur_ch, delta)) {
            e->aud[e->cur_ch] = save;
            e->cdelta = sc;
            switch20(e);
            return 0;
        }
        it20(e, (int)e->cur_ch, delta, 0, 0);
        if (++e->cur_ch == e->nch) e->cur_ch = 0;
        return 1;
    }
    u32 rl[4] = { 0, 0, 0, 0 };
    for (u32 k = 1; k <= 4; k++) {
        u32 dist = e->rep[(e->rep_ptr - k) & 3];
        if (dist && dist <= maxd) rl[k - 1] = mlen(d, pos, dist, maxlen);
    }
    u32 md = 0, ml = find_match(&e->m, pos, maxlen, maxd, 16, &md);
    int order[4] = { 0, 1, 2, 3 };
    if (e->variety) {
        for (int i = 0; i < 3; i++) {
            int j = i + (int)rndn((u32)(4 - i));
            int t = order[i]; order[i] = order[j]; order[j] = t;
        }
    } else {
        order[0] = 2; order[1] = 1; order[2] = 0;
    }
    for (int oi = 0; oi < 5; oi++) {
        int opt = oi < 4 ? order[oi] : 4;
        if (opt == 0) {                     /* 256: last length and distance again */
            if (!e->last_len || !e->last_dist || e->last_dist > maxd || e->last_len > maxlen) continue;
            if (mlen(d, pos, e->last_dist, e->last_len) < e->last_len || !codable20(e, 0, 256)) continue;
            it20(e, 0, 256, 0, 0);
            u32 len = e->last_len;
            push20(e, len, e->last_dist);
            return len;
        }
        if (opt == 1) {
            for (u32 k = 1; k <= 4; k++) {
                u32 dist = e->rep[(e->rep_ptr - k) & 3], len = rl[k - 1], c = corr20r(dist);
                if (len < 2 + c) continue;
                u32 v = len - 2 - c, s = lslot(v);
                if (!codable20(e, 0, 256 + k) || !codable20(e, 2, s)) continue;
                it20(e, 0, 256 + k, 0, 0);
                it20(e, 2, s, v - ldec[s], lbits[s]);
                push20(e, len, dist);
                return len;
            }
            continue;
        }
        if (opt == 2) {
            u32 c = (md >= 0x2000) + (md >= 0x40000);
            if (!md || ml < 3 + c) continue;
            u32 len = ml;
            if (e->variety && len > 3 + c && !rndn(3)) len = 3 + c + rndn(len - 2 - c);
            u32 v = len - 3 - c, s = lslot(v), dd = md - 1, ds = dslot(dd, DC20);
            if (!codable20(e, 0, 270 + s) || !codable20(e, 1, ds)) continue;
            it20(e, 0, 270 + s, v - ldec[s], lbits[s]);
            it20(e, 1, ds, dd - ddec[ds], dbits[ds]);
            push20(e, len, md);
            return len;
        }
        if (opt == 3) {
            u32 sd = 0;
            if (maxlen >= 2)
                for (u32 k = 1; k <= 256 && k <= maxd; k++)
                    if (d[pos] == d[pos - k] && d[pos + 1] == d[pos + 1 - k]) { sd = k; break; }
            if (!sd) continue;
            u32 dd = sd - 1, s = sdslot(dd);
            if (!codable20(e, 0, 261 + s)) continue;
            it20(e, 0, 261 + s, dd - sddec[s], sdbits[s]);
            push20(e, 2, sd);
            return 2;
        }
        if (!codable20(e, 0, d[pos])) break;
        it20(e, 0, d[pos], 0, 0);
        return 1;
    }
    switch20(e);
    return 0;
}

/* tables where every symbol has a code (for a table switch that ends a file) */
static void full_lens20(e20 *e, const u8 *p, size_t n, u8 *lens)
{
    u32 f[T20];
    for (u32 i = 0; i < T20; i++) f[i] = 1;
    for (size_t i = 0; i < n; i++) f[p[i]] += 4;
    memset(lens, 0, T20);
    if (e->amode) {
        for (u32 c = 0; c < e->nch; c++) hlens(f, MC20, lens + c * MC20, 15);
    } else {
        hlens(f, NC20, lens, 15);
        hlens(f + NC20, DC20, lens + NC20, 15);
        hlens(f + NC20 + DC20, RC20, lens + NC20 + DC20, 15);
    }
}

static void enc20_file(e20 *e, size_t fs, size_t fe, int solid, int next_solid, size_t next_end, vec *out)
{
    if (!solid) {
        memset(e->rep, 0, sizeof e->rep);
        e->rep_ptr = e->last_len = e->last_dist = 0;
        e->have_tables = 0;
        e->amode = 0;
        e->cdelta = 0;
        e->cur_ch = 0;
        e->nch = 1;
        memset(e->aud, 0, sizeof e->aud);
        memset(e->old, 0, sizeof e->old);
        e->m.sstart = fs;
    }
    memset(&e->w, 0, sizeof e->w);
    e->nit = 0;
    memset(e->freq, 0, sizeof e->freq);
    if (!solid || !e->have_tables) open20(e);
    else { e->fixed = 1; e->blk_syms = 0; }
    size_t pos = fs;
    while (pos < fe) {
        if (e->blk && ++e->blk_syms > (u32)e->blk) switch20(e);
        pos += lz20_step(e, pos, fe);
    }
    if (next_solid && e->variety && rndn(2) && next_end > fe) {
        /* ReadLastTables: the next file's tables right after this file's last symbol */
        if (e->amode) it20(e, (int)e->cur_ch, 256, 0, 0);
        else it20(e, 0, 269, 0, 0);
        flush20(e);
        e->amode = e->audio && rndn(2);
        if (e->amode) {
            e->nch = 1 + rndn(e->audio);
            if (e->cur_ch >= e->nch) e->cur_ch = 0;
        }
        u8 lens[T20];
        full_lens20(e, e->m.data + fe, next_end - fe, lens);
        set_tables20(e, lens);
        e->fixed = 1;
    } else {
        flush20(e);
    }
    bw_align(&e->w);
    *out = e->w.v;
    memset(&e->w, 0, sizeof e->w);
}

/* ================= RAR 1.5 encoder ================= */

/* the static codes of Unpack::DecodeNum (tables as in the decoder) */
static const u16 dl1[] = { 0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff };
static const u16 pl1[] = { 0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32 };
static const u16 dl2[] = { 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff };
static const u16 pl2[] = { 0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36 };
static const u16 dh0[] = { 0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff };
static const u16 ph0[] = { 0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33 };
static const u16 dh1[] = { 0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff };
static const u16 ph1[] = { 0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127 };
static const u16 dh2[] = { 0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff };
static const u16 ph2[] = { 0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0 };
static const u16 dh3[] = { 0x800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff };
static const u16 ph3[] = { 0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0 };
static const u16 dh4[] = { 0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff };
static const u16 ph4[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0 };

enum { N_L1, N_L2, N_H0, N_H1, N_H2, N_H3, N_H4, N_TABS };
static const struct { u32 start; const u16 *dec, *pos; } ntab[N_TABS] = {
    { 2, dl1, pl1 }, { 3, dl2, pl2 }, { 4, dh0, ph0 }, { 5, dh1, ph1 }, { 5, dh2, ph2 }, { 6, dh3, ph3 }, { 8, dh4, ph4 } };
static u16 ncode[N_TABS][257];
static u8 nlen[N_TABS][257];

/* inverse of DecodeNum by enumerating every 12-bit prefix */
static void init_num15(void)
{
    memset(nlen, 0, sizeof nlen);
    for (int t = 0; t < N_TABS; t++)
        for (u32 num = 0; num < 0x10000; num += 16) {
            u32 i = 0, start = ntab[t].start;
            for (; ntab[t].dec[i] <= num; i++) start++;
            u32 v = ((num - (i ? ntab[t].dec[i - 1] : 0)) >> (16 - start)) + ntab[t].pos[start];
            if (v <= 256 && !nlen[t][v]) {
                nlen[t][v] = (u8)start;
                ncode[t][v] = (u16)(num >> (16 - start));
            }
        }
}

typedef struct {
    u16 chset[256], chseta[256], chsetb[256], chsetc[256];
    u8 ntopl[256], ntoplb[256], ntoplc[256];
    u32 avr_plc, avr_plcb, avr_ln1, avr_ln2, avr_ln3, num_huf, buf60, max_dist3, nhfb, nlzb;
    int flags_cnt, st_mode, lcount;
    u32 flag_buf;
    u32 rep[4], rep_ptr, last_len, last_dist;
} s15;

enum { O_LIT, O_SHORT, O_REPLAST, O_REPLAST2, O_LONG, O_FAR, O_REPN, O_BUF60, O_STEXIT, O_STLIT, O_STSHORT };
typedef struct { u8 op, rn; u16 len; u32 dist; } op15;

typedef struct {
    s15 s;
    bw *w;                   /* NULL: decide pass (no output) */
    u8 *fb;                  /* flag bits in decode order */
    size_t nfb, capfb, fbpos;
} c15;

static void corr_huff(u16 *cs, u8 *ntp)
{
    for (int i = 7; i >= 0; i--)
        for (int j = 0; j < 32; j++, cs++) *cs = (u16)((*cs & ~0xFF) | i);
    memset(ntp, 0, 256);
    for (int i = 6; i >= 0; i--) ntp[i] = (u8)((7 - i) * 32);
}

static void s15_init(s15 *s, int solid)
{
    if (!solid) {
        memset(s->rep, 0, sizeof s->rep);
        s->rep_ptr = s->last_len = s->last_dist = 0;
        s->avr_plcb = s->avr_ln1 = s->avr_ln2 = s->avr_ln3 = s->num_huf = s->buf60 = 0;
        s->avr_plc = 0x3500;
        s->max_dist3 = 0x2001;
        s->nhfb = s->nlzb = 0x80;
        for (u32 i = 0; i < 256; i++) {
            s->chset[i] = s->chsetb[i] = (u16)(i << 8);
            s->chseta[i] = (u16)i;
            s->chsetc[i] = (u16)(((~i + 1) & 0xFF) << 8);
        }
        memset(s->ntopl, 0, 256);
        memset(s->ntoplb, 0, 256);
        memset(s->ntoplc, 0, 256);
        corr_huff(s->chsetb, s->ntoplb);
    }
    s->flags_cnt = 0;
    s->flag_buf = 0;
    s->st_mode = 0;
    s->lcount = 0;
}

static void put_num(c15 *c, int t, u32 v)
{
    if (v > 256 || !nlen[t][v]) die("value not codable (1.5)");
    if (c->w) bwr(c->w, ncode[t][v], nlen[t][v]);
}
static void put_bits15(c15 *c, u32 v, int n) { if (c->w) bwr(c->w, v, n); }

static void get_flags15(c15 *c)
{
    s15 *s = &c->s;
    if (!c->w) return;
    u32 f = 0;
    for (int i = 0; i < 8; i++) f = f << 1 | (c->fbpos < c->nfb ? c->fb[c->fbpos++] : 0);
    u32 fp = 0;
    while ((s->chsetc[fp] >> 8) != f) fp++;
    put_num(c, N_H2, fp);
    for (;;) {
        u32 fl = s->chsetc[fp];
        s->flag_buf = fl >> 8;
        u32 np = s->ntoplc[fl++ & 0xFF]++;
        if (fl & 0xFF) {
            s->chsetc[fp] = s->chsetc[np];
            s->chsetc[np] = (u16)fl;
            return;
        }
        corr_huff(s->chsetc, s->ntoplc);
    }
}

static void take_flag(c15 *c, int bit)
{
    s15 *s = &c->s;
    if (--s->flags_cnt < 0) {
        get_flags15(c);
        s->flags_cnt = 7;
    }
    if (c->w) {
        if (((s->flag_buf & 0x80) != 0) != bit) die("flag mismatch (1.5)");
    } else {
        if (c->nfb == c->capfb) {
            c->capfb = c->capfb * 2 + 4096;
            c->fb = (u8 *)xrealloc(c->fb, c->capfb);
        }
        c->fb[c->nfb++] = (u8)bit;
    }
    s->flag_buf <<= 1;
}

static int huff_tab(u32 avr)
{
    return avr > 0x75ff ? N_H4 : avr > 0x5dff ? N_H3 : avr > 0x35ff ? N_H2 : avr > 0x0dff ? N_H1 : N_H0;
}

/* HuffDecode body for byte place p (st: StMode coding) */
static void huff_body(c15 *c, u32 p, int st)
{
    s15 *s = &c->s;
    int t = huff_tab(s->avr_plc);
    if (st) put_num(c, t, p == 255 ? 256 : p + 1);
    else put_num(c, t, p);
    if (!st && s->num_huf++ >= 16 && s->flags_cnt == 0) s->st_mode = 1;
    s->avr_plc += p;
    s->avr_plc -= s->avr_plc >> 8;
    s->nhfb += 16;
    if (s->nhfb > 0xff) {
        s->nhfb = 0x90;
        s->nlzb >>= 1;
    }
    for (;;) {
        u32 cur = s->chset[p];
        u32 np = s->ntopl[cur++ & 0xFF]++;
        if ((cur & 0xFF) > 0xA1) {
            corr_huff(s->chset, s->ntopl);
        } else {
            s->chset[p] = s->chset[np];
            s->chset[np] = (u16)cur;
            return;
        }
    }
}

static const u8 sl1[16] = { 1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0 };
static const u8 sx1[16] = { 0, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0, 0 };
static const u8 sl2[16] = { 2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0 };
static const u8 sx2[16] = { 0, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0, 0 };

/* the ShortLZ length code k as the decoder scans it (k reachable only if not shadowed) */
static int short_code(const s15 *s, u32 k, u32 *code, u32 *nb)
{
    int t2 = s->avr_ln1 >= 37;
    const u8 *sl = t2 ? sl2 : sl1, *sx = t2 ? sx2 : sx1;
    u32 sp = t2 ? 3 : 1;
    u32 l = k == sp ? s->buf60 + 3 : sl[k];
    u32 bits = (u32)sx[k] >> (8 - l);
    u32 bf = bits << (8 - l);                 /* the decoder's view, zero filled */
    for (u32 j = 0; j < 16; j++) {
        u32 lj = j == sp ? s->buf60 + 3 : sl[j];
        if (!((bf ^ sx[j]) & ~(0xFFu >> lj) & 0xFF)) {
            if (j != k) return 0;
            break;
        }
    }
    *code = bits;
    *nb = l;
    return 1;
}

static void push15(s15 *s, u32 len, u32 dist)
{
    s->rep[s->rep_ptr & 3] = dist;
    s->rep_ptr = (s->rep_ptr + 1) & 3;
    s->last_len = len;
    s->last_dist = dist;
}

/* ShortLZ prefix: flags "00", the LCount==2 bit, the length code */
static void short_head(c15 *c, u32 k, int prefix_bit)
{
    s15 *s = &c->s;
    take_flag(c, 0);
    take_flag(c, 0);
    s->num_huf = 0;
    if (s->lcount == 2) {
        put_bits15(c, (u32)prefix_bit, 1);
        if (prefix_bit) return;
        s->lcount = 0;
    }
    u32 code, nb;
    if (!short_code(s, k, &code, &nb)) die("short code shadowed (1.5)");
    put_bits15(c, code, (int)nb);
}

/* LongLZ coded length (0..255) for len/dist, or -1 */
static int long_value(const s15 *s, u32 len, u32 dist)
{
    int v = (int)len - 3 - (dist >= s->max_dist3) - 8 * (dist <= 256);
    return v >= 0 && v <= 255 ? v : -1;
}

static void apply15(c15 *c, const op15 *o)
{
    s15 *s = &c->s;
    switch (o->op) {
    case O_LIT: {
        u32 p = 0;
        while ((s->chset[p] >> 8) != o->dist) p++;
        if (s->nlzb > s->nhfb) { take_flag(c, 0); take_flag(c, 1); }
        else take_flag(c, 1);
        huff_body(c, p, 0);
        break;
    }
    case O_STLIT: {
        u32 p = 0;
        while ((s->chset[p] >> 8) != o->dist) p++;
        huff_body(c, p, 1);
        break;
    }
    case O_STEXIT:
    case O_STSHORT:
        put_num(c, huff_tab(s->avr_plc), 0);
        if (o->op == O_STEXIT) {
            put_bits15(c, 1, 1);
            s->num_huf = 0;
            s->st_mode = 0;
        } else {
            put_bits15(c, 0, 1);
            put_bits15(c, o->len == 4, 1);
            put_num(c, N_H2, o->dist >> 5);
            put_bits15(c, o->dist & 31, 5);
        }
        break;
    case O_SHORT: {
        short_head(c, o->len - 2, 0);
        s->lcount = 0;
        s->avr_ln1 += (u32)(o->len - 2);
        s->avr_ln1 -= s->avr_ln1 >> 4;
        u32 p = 0;
        while (s->chseta[p] != o->dist - 1) p++;
        put_num(c, N_H2, p);
        if (p) {
            u16 t = s->chseta[p];
            s->chseta[p] = s->chseta[p - 1];
            s->chseta[p - 1] = t;
        }
        push15(s, o->len, o->dist);
        break;
    }
    case O_REPLAST:
        short_head(c, 9, 0);
        s->lcount++;
        break;
    case O_REPLAST2:
        short_head(c, 0, 1);
        break;
    case O_FAR:
        short_head(c, 14, 0);
        s->lcount = 0;
        put_num(c, N_L2, o->len - 5);
        put_bits15(c, o->dist & 0x7FFF, 15);
        s->last_len = o->len;
        s->last_dist = o->dist;
        break;
    case O_REPN:
    case O_BUF60: {
        u32 k = o->op == O_BUF60 ? 10 : 9 + o->rn;
        short_head(c, k, 0);
        s->lcount = 0;
        if (o->op == O_BUF60) {
            put_num(c, N_L1, 0x101 - 2);
            s->buf60 ^= 1;
            break;
        }
        u32 dist = s->rep[(s->rep_ptr - o->rn) & 3];
        u32 v = o->len - 2 - (dist > 256) - (dist >= s->max_dist3);
        put_num(c, N_L1, v);
        push15(s, o->len, dist);
        break;
    }
    case O_LONG: {
        if (s->nlzb > s->nhfb) take_flag(c, 1);
        else { take_flag(c, 0); take_flag(c, 1); }
        u32 dist = o->dist, len = o->len;
        int v = long_value(s, len, dist);
        if (v < 0) die("long length (1.5)");
        s->num_huf = 0;
        s->nlzb += 16;
        if (s->nlzb > 0xff) {
            s->nlzb = 0x90;
            s->nhfb >>= 1;
        }
        u32 old2 = s->avr_ln2;
        if (s->avr_ln2 >= 122) put_num(c, N_L2, (u32)v);
        else if (s->avr_ln2 >= 64) put_num(c, N_L1, (u32)v);
        else if (v < 8 && o->rn) { put_bits15(c, 0, v); put_bits15(c, 1, 1); }
        else put_bits15(c, (u32)v, 16);
        s->avr_ln2 += (u32)v;
        s->avr_ln2 -= s->avr_ln2 >> 5;
        u32 hb = dist >> 7, p = 0;
        while ((s->chsetb[p] >> 8) != hb) p++;
        put_num(c, s->avr_plcb > 0x28ff ? N_H2 : s->avr_plcb > 0x6ff ? N_H1 : N_H0, p);
        s->avr_plcb += p;
        s->avr_plcb -= s->avr_plcb >> 8;
        u32 dv, np;
        for (;;) {
            dv = s->chsetb[p];
            np = s->ntoplb[dv++ & 0xFF]++;
            if (dv & 0xFF) break;
            corr_huff(s->chsetb, s->ntoplb);
        }
        s->chsetb[p] = s->chsetb[np];
        s->chsetb[np] = (u16)dv;
        put_bits15(c, dist & 127, 7);
        u32 old3 = s->avr_ln3, l = (u32)v;
        if (l != 1 && l != 4) {
            if (l == 0 && dist <= s->max_dist3) {
                s->avr_ln3++;
                s->avr_ln3 -= s->avr_ln3 >> 8;
            } else if (s->avr_ln3 > 0) {
                s->avr_ln3--;
            }
        }
        s->max_dist3 = (old3 > 0xb0 || (s->avr_plc >= 0x2a00 && old2 < 0x40)) ? 0x7f00 : 0x2001;
        push15(s, len, dist);
        break;
    }
    }
}

typedef struct {
    int variety;
    mfind m;
    s15 st;                  /* state at the start of the next file (solid) */
} e15;

/* decide the next op at pos with the simulated state c->s */
static u32 decide15(e15 *e, c15 *c, size_t pos, size_t fe, op15 *o)
{
    s15 *s = &c->s;
    const u8 *d = e->m.data;
    size_t avail = pos - e->m.sstart;
    u32 maxlen = fe - pos < 260 ? (u32)(fe - pos) : 260;
    u32 maxd = avail < 0xFFFF ? (u32)avail : 0xFFFF;
    memset(o, 0, sizeof *o);
    hash_upto(&e->m, pos);
    if (s->st_mode) {
        if (e->variety && rndn(4)) {
            if (maxlen >= 3 && rndn(3) == 0)
                for (u32 dist = 1; dist <= maxd && dist <= 8223; dist++) {
                    u32 l = mlen(d, pos, dist, maxlen < 4 ? maxlen : 4);
                    if (l >= 3) { o->op = O_STSHORT; o->len = (u16)l; o->dist = dist; return l; }
                }
            o->op = O_STLIT;
            o->dist = d[pos];
            return 1;
        }
        o->op = O_STEXIT;
        return 0;
    }
    if (s->lcount == 2 && s->last_len && s->last_dist <= maxd && s->last_len <= maxlen &&
        mlen(d, pos, s->last_dist, s->last_len) == s->last_len && (!e->variety || rndn(2))) {
        o->op = O_REPLAST2;
        return s->last_len;
    }
    if (s->last_len && s->last_dist && s->last_dist <= maxd && s->last_len <= maxlen &&
        mlen(d, pos, s->last_dist, s->last_len) == s->last_len && (!e->variety || rndn(2))) {
        u32 code, nb;
        if (short_code(s, 9, &code, &nb)) { o->op = O_REPLAST; return s->last_len; }
    }
    if (e->variety && !rndn(4)) {
        for (u32 rn = 1; rn <= 4; rn++) {
            u32 dist = s->rep[(s->rep_ptr - rn) & 3], code, nb;
            if (!dist || dist > maxd || !short_code(s, 9 + rn, &code, &nb)) continue;
            u32 l = mlen(d, pos, dist, maxlen), c0 = (dist > 256) + (dist >= s->max_dist3);
            if (l < 2 + c0) continue;
            if (l - 2 - c0 > 254) l = 254 + 2 + c0;
            o->op = O_REPN;
            o->rn = (u8)rn;
            o->len = (u16)l;
            return l;
        }
    }
    u32 md = 0, ml = find_match(&e->m, pos, maxlen, maxd, 24, &md);
    if (ml >= 5 && md >= 0x8000) {
        u32 code, nb;
        if (!short_code(s, 14, &code, &nb)) {
            o->op = O_BUF60;              /* the far-match code needs Buf60 = 1 */
            return 0;
        }
        o->op = O_FAR;
        o->len = (u16)ml;
        o->dist = md;
        return ml;
    }
    if (md && md < 0x8000) {
        int lv = long_value(s, ml > 258 ? 258 : ml, md);
        if (md <= 256 && ml >= 2 && (ml <= 10 || (e->variety && rndn(2)) || lv < 0)) {
            o->op = O_SHORT;
            o->len = (u16)(ml > 10 ? 10 : ml);
            o->dist = md;
            return o->len;
        }
        if (lv >= 0) {
            o->op = O_LONG;
            o->len = (u16)(ml > 258 ? 258 : ml);
            o->dist = md;
            o->rn = e->variety ? (u8)rndn(2) : 0;
            return o->len;
        }
    }
    if (maxlen >= 2)
        for (u32 dist = 1; dist <= 256 && dist <= maxd; dist++)
            if (d[pos] == d[pos - dist] && d[pos + 1] == d[pos + 1 - dist]) {
                o->op = O_SHORT;
                o->len = 2;
                o->dist = dist;
                return 2;
            }
    if (e->variety && s->buf60 == 0 && !rndn(200)) { o->op = O_BUF60; return 0; }
    o->op = O_LIT;
    o->dist = d[pos];
    return 1;
}

static void enc15_file(e15 *e, size_t fs, size_t fe, int solid, vec *out)
{
    c15 c;
    memset(&c, 0, sizeof c);
    if (!solid) e->m.sstart = fs;
    c.s = e->st;
    s15_init(&c.s, solid);
    s15 start = c.s;
    op15 *ops = 0;
    size_t nops = 0, capops = 0;
    if (fe > fs) {
        /* pass 1: decide (flag bits recorded in decode order) */
        get_flags15(&c);
        c.s.flags_cnt = 8;
        for (size_t pos = fs; pos < fe;) {
            op15 o;
            u32 adv = decide15(e, &c, pos, fe, &o);
            if (nops == capops) {
                capops = capops * 2 + 1024;
                ops = (op15 *)xrealloc(ops, capops * sizeof(op15));
            }
            ops[nops++] = o;
            apply15(&c, &o);
            pos += adv;
        }
    }
    s15 end = c.s;
    /* pass 2: emit with the flag bytes known */
    bw w;
    memset(&w, 0, sizeof w);
    c.s = start;
    c.w = &w;
    c.fbpos = 0;
    if (fe > fs) {
        get_flags15(&c);
        c.s.flags_cnt = 8;
        for (size_t i = 0; i < nops; i++) apply15(&c, &ops[i]);
    }
    /* flag decoding state exists only in pass 2 */
    memcpy(end.chsetc, c.s.chsetc, sizeof end.chsetc);
    memcpy(end.ntoplc, c.s.ntoplc, sizeof end.ntoplc);
    end.flag_buf = c.s.flag_buf;
    if (memcmp(&c.s, &end, sizeof end)) die("1.5 passes disagree");
    e->st = c.s;
    bw_align(&w);
    *out = w.v;
    free(ops);
    free(c.fb);
}

/* ================= legacy ciphers (encrypt direction, as unrar crypt1/crypt2) ================= */

static const u8 subst20_init[256] = {
    215, 19, 149, 35, 73, 197, 192, 205, 249, 28, 16, 119, 48, 221, 2, 42,
    232, 1, 177, 233, 14, 88, 219, 25, 223, 195, 244, 90, 87, 239, 153, 137,
    255, 199, 147, 70, 92, 66, 246, 13, 216, 40, 62, 29, 217, 230, 86, 6,
    71, 24, 171, 196, 101, 113, 218, 123, 93, 91, 163, 178, 202, 67, 44, 235,
    107, 250, 75, 234, 49, 167, 125, 211, 83, 114, 157, 144, 32, 193, 143, 36,
    158, 124, 247, 187, 89, 214, 141, 47, 121, 228, 61, 130, 213, 194, 174, 251,
    97, 110, 54, 229, 115, 57, 152, 94, 105, 243, 212, 55, 209, 245, 63, 11,
    164, 200, 31, 156, 81, 176, 227, 21, 76, 99, 139, 188, 127, 17, 248, 51,
    207, 120, 189, 210, 8, 226, 41, 72, 183, 203, 135, 165, 166, 60, 98, 7,
    122, 38, 155, 170, 69, 172, 252, 238, 39, 134, 59, 128, 236, 27, 240, 80,
    131, 3, 85, 206, 145, 79, 154, 142, 159, 220, 201, 133, 74, 64, 20, 129,
    224, 185, 138, 103, 173, 182, 43, 34, 254, 82, 198, 151, 231, 180, 58, 10,
    118, 26, 102, 12, 50, 132, 22, 191, 136, 111, 162, 179, 45, 4, 148, 108,
    161, 56, 78, 126, 242, 222, 15, 175, 146, 23, 33, 241, 181, 190, 77, 225,
    0, 46, 169, 186, 68, 95, 237, 65, 53, 208, 253, 168, 9, 18, 100, 52,
    116, 184, 160, 96, 109, 37, 30, 106, 140, 104, 150, 5, 204, 117, 112, 84 };

typedef struct { u32 k20[4]; u8 sub[256]; u16 k15[4]; u8 k13[3]; } oldc;

static u32 rol32(u32 x, u32 n) { return (x << n) | (x >> (32 - n)); }
static u32 subst_long(const oldc *c, u32 t)
{
    return (u32)c->sub[t & 255] | (u32)c->sub[(t >> 8) & 255] << 8 |
           (u32)c->sub[(t >> 16) & 255] << 16 | (u32)c->sub[t >> 24] << 24;
}
static void enc_block20(oldc *c, u8 *b)
{
    u32 A = rd32(b) ^ c->k20[0], B = rd32(b + 4) ^ c->k20[1], C = rd32(b + 8) ^ c->k20[2], D = rd32(b + 12) ^ c->k20[3];
    for (int i = 0; i < 32; i++) {
        u32 t = (C + rol32(D, 11)) ^ c->k20[i & 3];
        u32 ta = A ^ subst_long(c, t);
        t = (D ^ rol32(C, 17)) + c->k20[i & 3];
        u32 tb = B ^ subst_long(c, t);
        A = C; B = D; C = ta; D = tb;
    }
    wr32(b, C ^ c->k20[0]);
    wr32(b + 4, D ^ c->k20[1]);
    wr32(b + 8, A ^ c->k20[2]);
    wr32(b + 12, B ^ c->k20[3]);
    for (u32 i = 0; i < 16; i += 4) {
        c->k20[0] ^= gz_crc_table[0][b[i]];
        c->k20[1] ^= gz_crc_table[0][b[i + 1]];
        c->k20[2] ^= gz_crc_table[0][b[i + 2]];
        c->k20[3] ^= gz_crc_table[0][b[i + 3]];
    }
}
static void setkey20(oldc *c, const char *pw)
{
    u8 psw[600];
    size_t n = strlen(pw);
    c->k20[0] = 0xD3A3B879u; c->k20[1] = 0x3F6D12F7u; c->k20[2] = 0x7515A235u; c->k20[3] = 0xA4E7F123u;
    memcpy(c->sub, subst20_init, 256);
    memset(psw, 0, sizeof psw);
    memcpy(psw, pw, n);
    for (u32 j = 0; j < 256; j++)
        for (size_t i = 0; i < n; i += 2) {
            u32 n1 = (u8)gz_crc_table[0][(psw[i] - j) & 0xFF];
            u32 n2 = (u8)gz_crc_table[0][(psw[i + 1] + j) & 0xFF];
            for (u32 k = 1; n1 != n2; n1 = (n1 + 1) & 0xFF, k++) {
                u8 t = c->sub[n1];
                c->sub[n1] = c->sub[(n1 + i + k) & 0xFF];
                c->sub[(n1 + i + k) & 0xFF] = t;
            }
        }
    for (size_t i = 0; i < n; i += 16) enc_block20(c, psw + i);
}
static u16 ror16(u32 x, u32 n) { x &= 0xFFFF; return (u16)((x >> n) | (x << (16 - n))); }
static void setkey15(oldc *c, const char *pw)
{
    size_t n = strlen(pw);
    u32 crc = ~gz_crc32(0, pw, n);
    c->k15[0] = (u16)crc; c->k15[1] = (u16)(crc >> 16); c->k15[2] = c->k15[3] = 0;
    for (size_t i = 0; i < n; i++) {
        u8 p = (u8)pw[i];
        c->k15[2] = (u16)(c->k15[2] ^ p ^ gz_crc_table[0][p]);
        c->k15[3] = (u16)(c->k15[3] + p + (gz_crc_table[0][p] >> 16));
    }
}
static void crypt15(oldc *c, u8 *b, size_t n)
{
    u16 *k = c->k15;
    for (size_t i = 0; i < n; i++) {
        k[0] = (u16)(k[0] + 0x1234);
        u32 t = gz_crc_table[0][(k[0] & 0x1FE) >> 1];
        k[1] = (u16)(k[1] ^ t);
        k[2] = (u16)(k[2] - (t >> 16));
        k[0] ^= k[2];
        k[3] = (u16)(ror16(k[3], 1) ^ k[1]);
        k[3] = ror16(k[3], 1);
        k[0] ^= k[3];
        b[i] ^= (u8)(k[0] >> 8);
    }
}
static void setkey13(oldc *c, const char *pw)
{
    c->k13[0] = c->k13[1] = c->k13[2] = 0;
    for (size_t i = 0; pw[i]; i++) {
        u8 p = (u8)pw[i];
        c->k13[0] = (u8)(c->k13[0] + p);
        c->k13[1] ^= p;
        c->k13[2] = (u8)(c->k13[2] + p);
        c->k13[2] = (u8)((c->k13[2] << 1) | (c->k13[2] >> 7));
    }
}
static void encrypt13(oldc *c, u8 *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        c->k13[1] = (u8)(c->k13[1] + c->k13[2]);
        c->k13[0] = (u8)(c->k13[0] + c->k13[1]);
        b[i] = (u8)(b[i] + c->k13[0]);
    }
}

static u32 sum14(u32 s, const u8 *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        s = (s + p[i]) & 0xFFFF;
        s = ((s << 1) | (s >> 15)) & 0xFFFF;
    }
    return s;
}

/* ================= archive writer ================= */

enum { K_FILE = 0, K_DIR, K_LINK, K_STREAM };

typedef struct {
    char *name;              /* UTF-8 path, '/' separated */
    int kind;
    u8 *data;
    size_t size;
    vec packed;
    int stored, solid;
    u32 crc;
    u8 salt[8];
    u32 ver, method;
} ent;

typedef struct {
    int fmt;                 /* 29, 20, 15 or 14 (RAR 1.4 archive) */
    int method;              /* 0..5 */
    u32 dictlog;             /* 16..22 */
    int solid, ppm, variety, blk, lazy;
    u32 ppm_order, ppm_mb;
    int filt[2];
    u32 flen, fparam;
    u32 audio;
    const char *pw;
    int hp;
    u64 vol;
    int vold, noend;
    const char *cmt;
    int cmt_unicode, cmt_store;
    int uni, exttime, host, large, unknown;
    u32 sfx;
    ent *e;
    u32 ne;
} opts;

static const u8 sig4[7] = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 };
#define DOS_TIME 0x50EF6534u   /* 2020-07-15 12:41:40 */

static int ftype_of(const char *s)
{
    static const char *n[] = { "none", "e8", "e8e9", "itanium", "delta", "rgb", "audio", "bogus", "badxor", "mix" };
    for (int i = 0; i < 10; i++)
        if (!strcmp(s, n[i])) return i;
    die("unknown filter");
    return 0;
}

/* plan filter blocks for file [fs, fe) and apply the forward transforms to buf */
static u32 plan_filters(opts *o, u8 *buf, size_t fs, size_t fe, fplan *fp, u32 cap)
{
    u32 n = 0;
    if (!o->filt[0] || o->fmt != 29) return 0;
    u32 flen = o->flen ? o->flen : 0x10000, k = 0;
    for (size_t b = fs; b < fe && n + 2 <= cap; b += flen, k++) {
        u32 len = fe - b < flen ? (u32)(fe - b) : flen;
        int types[2];
        int nt = 0;
        for (int s = 0; s < 2 && o->filt[s]; s++) {
            int t = o->filt[s];
            if (t == F_MIX) t = 1 + (int)((k + (u32)s * 3) % 6);
            types[nt++] = t;
        }
        /* forward transforms in reverse order of definition (decoders apply them in order) */
        u32 r0[2], r1[2];
        for (int s = nt - 1; s >= 0; s--) {
            u32 t = (u32)types[s];
            r0[s] = r1[s] = 0;
            if (t == F_DELTA) r0[s] = o->fparam ? o->fparam : 1 + k % 7;
            if (t == F_AUDIO) r0[s] = o->fparam ? o->fparam : 1 + k % 4;
            if (t == F_RGB) {
                r0[s] = o->fparam ? o->fparam : 3 * (8 + k % 40) + 3;
                r1[s] = k % 3;
                if (len < 3 || r0[s] > len) { types[s] = F_E8; t = F_E8; r0[s] = r1[s] = 0; }
            }
            u8 *p = buf + b;
            switch (t) {
            case F_E8: fwd_e8(p, len, (u32)(b - fs), 0); break;
            case F_E8E9: fwd_e8(p, len, (u32)(b - fs), 1); break;
            case F_ITANIUM: fwd_itanium(p, len, (u32)(b - fs)); break;
            case F_DELTA: fwd_delta(p, len, r0[s]); break;
            case F_RGB: fwd_rgb(p, len, r0[s], r1[s]); break;
            case F_AUDIO: fwd_audio(p, len, r0[s]); break;
            }
        }
        u64 lead = rndn(o->variety ? 2000 : 64);
        for (int s = 0; s < nt; s++) {
            fplan *f = &fp[n++];
            memset(f, 0, sizeof *f);
            f->start = b;
            f->len = len;
            f->type = (u32)types[s];
            f->r0 = r0[s];
            f->r1 = r1[s];
            f->emit_at = b > fs + lead ? b - lead : fs;
        }
    }
    return n;
}

/* compress (and encrypt) every entry; solid runs share one encoder */
static void encode_all(opts *o)
{
    size_t total = 0;
    for (u32 i = 0; i < o->ne; i++) total += o->e[i].size;
    u8 *stream = (u8 *)xcalloc(total + 8);
    u32 dict = 1u << o->dictlog;
    e29 *z29 = (e29 *)xcalloc(sizeof(e29));
    e20 *z20 = (e20 *)xcalloc(sizeof(e20));
    e15 *z15 = (e15 *)xcalloc(sizeof(e15));
    /* stream positions of the files that are compressed (streams of their own) */
    size_t pos = 0;
    int run_open = 0;
    i32 prev_comp = -1;
    for (u32 i = 0; i < o->ne; i++) {
        ent *e = &o->e[i];
        e->crc = o->fmt == 14 ? sum14(0, e->data, e->size) : gz_crc32(0, e->data, e->size);
        e->stored = !o->method || e->kind == K_DIR || e->kind == K_LINK || !e->size;
        e->ver = o->fmt == 14 ? 13 : o->fmt == 29 ? (e->stored ? 20 : 29) : (u32)o->fmt;
        if (o->pw && o->fmt == 29) e->ver = 29;
        e->method = e->stored ? 0 : (u32)o->method;
        if (e->kind == K_STREAM) continue;          /* packed on their own later */
        if (e->stored) {
            vput(&e->packed, e->data, e->size);
            continue;
        }
        /* streams of NTFS streams are never solid */
        int solid = o->solid && e->kind == K_FILE && run_open;
        e->solid = solid;
        if (!solid) pos = 0;
        size_t fs = pos, fe = pos + e->size;
        if (!solid) {
            /* a new stream: the buffer restarts */
            memcpy(stream, e->data, e->size);
        } else {
            memcpy(stream + fs, e->data, e->size);
        }
        fplan fp[512];
        u32 nfp = plan_filters(o, stream, fs, fe, fp, 512);
        /* next compressed file of the run (RAR 2.0 trailing table switch) */
        size_t next_end = fe;
        int next_solid = 0;
        for (u32 j = i + 1; j < o->ne; j++) {
            ent *n = &o->e[j];
            if (!o->method || n->kind != K_FILE || !n->size) continue;
            if (o->solid) {
                next_solid = 1;
                if (fe + n->size <= total) {
                    memcpy(stream + fe, n->data, n->size);
                    next_end = fe + n->size;
                }
            }
            break;
        }
        if (o->fmt == 29) {
            if (!solid) {
                mf_free(&z29->m);
                mf_init(&z29->m, stream, total);
            }
            z29->m.size = fe;
            z29->dict = dict;
            z29->blk = o->blk;
            z29->ppm = o->ppm;
            z29->ppm_order = o->ppm_order;
            z29->ppm_mb = o->ppm_mb;
            z29->variety = o->variety;
            z29->lazy = o->lazy;
            enc29_file(z29, fs, fe, solid, fp, nfp, &e->packed);
        } else if (o->fmt == 20) {
            if (!solid) {
                mf_free(&z20->m);
                mf_init(&z20->m, stream, total);
            }
            z20->m.size = next_end;
            z20->dict = dict > 0x100000 ? 0x100000 : dict;
            z20->blk = o->blk;
            z20->variety = o->variety;
            z20->audio = o->audio;
            enc20_file(z20, fs, fe, solid, next_solid, next_end, &e->packed);
        } else {
            if (!solid) {
                mf_free(&z15->m);
                mf_init(&z15->m, stream, total);
            }
            z15->m.size = fe;
            z15->variety = o->variety;
            enc15_file(z15, fs, fe, solid, &e->packed);
        }
        run_open = e->kind == K_FILE;
        prev_comp = (i32)i;
        pos = fe;
    }
    (void)prev_comp;
    /* encryption */
    for (u32 i = 0; o->pw && i < o->ne; i++) {
        ent *e = &o->e[i];
        if (e->kind == K_DIR || e->kind == K_STREAM) continue;
        vec *v = &e->packed;
        if (o->fmt == 29) {
            for (int k = 0; k < 8; k++) e->salt[k] = (u8)rnd();
            u8 pw16[512], key[16], iv[16];
            size_t pl = 0;
            gzch *w = gz_posix_wide(o->pw);
            for (; w[pl] && pl < 127; pl++) wr16(pw16 + 2 * pl, w[pl]);
            free(w);
            gz_rar3_kdf(pw16, pl * 2, e->salt, key, iv);
            while (v->n & 15) v8(v, rnd() & 0xFF);
            gz_aes a;
            gz_aes_set_encrypt_key(&a, key, 16);
            gz_aes_cbc_encrypt(&a, iv, v->p, v->n);
        } else if (o->fmt == 20) {
            oldc c;
            setkey20(&c, o->pw);
            while (v->n & 15) v8(v, rnd() & 0xFF);
            for (size_t k = 0; k < v->n; k += 16) enc_block20(&c, v->p + k);
        } else if (o->fmt == 15) {
            oldc c;
            setkey15(&c, o->pw);
            crypt15(&c, v->p, v->n);
        } else {
            oldc c;
            setkey13(&c, o->pw);
            encrypt13(&c, v->p, v->n);
        }
    }
    mf_free(&z29->m);
    mf_free(&z20->m);
    mf_free(&z15->m);
    if (z29->pm) gz_ppmd7_free(z29->pm);
    free(z29->it);
    free(z20->it);
    free(z29);
    free(z20);
    free(z15);
    free(stream);
}

/* a fresh, non-solid compressed copy (comments, streams) */
static void pack_fresh(opts *o, int fmt, const u8 *p, size_t n, vec *out)
{
    u8 *buf = (u8 *)xcalloc(n + 8);
    memcpy(buf, p, n);
    if (fmt == 29) {
        e29 *z = (e29 *)xcalloc(sizeof(e29));
        mf_init(&z->m, buf, n);
        z->dict = 0x10000;
        z->ppm = o->ppm;
        z->ppm_order = o->ppm_order;
        z->ppm_mb = o->ppm_mb;
        z->variety = o->variety;
        enc29_file(z, 0, n, 0, 0, 0, out);
        mf_free(&z->m);
        if (z->pm) gz_ppmd7_free(z->pm);
        free(z->it);
        free(z);
    } else if (fmt == 20) {
        e20 *z = (e20 *)xcalloc(sizeof(e20));
        mf_init(&z->m, buf, n);
        z->dict = 0x10000;
        z->variety = o->variety;
        enc20_file(z, 0, n, 0, 0, n, out);
        mf_free(&z->m);
        free(z->it);
        free(z);
    } else {
        e15 *z = (e15 *)xcalloc(sizeof(e15));
        mf_init(&z->m, buf, n);
        z->variety = o->variety;
        enc15_file(z, 0, n, 0, out);
        mf_free(&z->m);
        free(z);
    }
    free(buf);
}

/* ---- headers ---- */

static void hdr_fix(vec *h, int crc_len)
{
    wr16(h->p + 5, (u16)h->n);
    wr16(h->p, (u16)(gz_crc32(0, h->p + 2, crc_len ? (size_t)crc_len - 2 : h->n - 2) & 0xFFFF));
}

/* RAR 3 Unicode name: legacy bytes, NUL, compressed UTF-16 */
static void put_unicode_name(vec *h, const char *utf8)
{
    gzch *w = gz_posix_wide(utf8);
    size_t n = gz_wcslen(w);
    u32 cnt[256] = { 0 }, high = 0;
    for (size_t i = 0; i < n; i++)
        if (w[i] >= 0x100) cnt[w[i] >> 8]++;
    for (u32 i = 1; i < 256; i++)
        if (cnt[i] > cnt[high]) high = i;
    u8 corr = (u8)(rndn(200) + 20);
    u8 *legacy = (u8 *)xcalloc(n + 1);
    for (size_t i = 0; i < n; i++)
        legacy[i] = w[i] < 0x80 ? (u8)w[i] : (w[i] >> 8) == high ? (u8)((w[i] & 0xFF) - corr) : '_';
    vec enc;
    memset(&enc, 0, sizeof enc);
    v8(&enc, high);
    u8 ops[4], data[4][8];
    u32 dn[4], nops = 0;
    for (size_t i = 0; i < n || nops;) {
        if (i < n) {
            u32 op, k = 0;
            size_t run = 0;
            while (i + run < n && run < 129 && w[i + run] == legacy[i + run] && w[i + run] < 0x80) run++;
            size_t crun = 0;
            while (i + crun < n && crun < 129 && w[i + crun] >= 0x100 && (w[i + crun] >> 8) == high) crun++;
            if (run >= 3 && rndn(2)) {
                op = 3;
                data[nops][k++] = (u8)(run - 2);
                i += run;
            } else if (crun >= 2 && rndn(2)) {
                op = 3;
                data[nops][k++] = (u8)(0x80 | (crun - 2));
                data[nops][k++] = corr;
                i += crun;
            } else if (w[i] < 0x100 && rndn(4)) {
                op = 0;
                data[nops][k++] = (u8)w[i++];
            } else if ((w[i] >> 8) == high && rndn(4)) {
                op = 1;
                data[nops][k++] = (u8)w[i++];
            } else {
                op = 2;
                data[nops][k++] = (u8)w[i];
                data[nops][k++] = (u8)(w[i] >> 8);
                i++;
            }
            ops[nops] = (u8)op;
            dn[nops++] = k;
        }
        if (nops == 4 || (i >= n && nops)) {
            u32 f = 0;
            for (u32 j = 0; j < 4; j++) f |= (u32)(j < nops ? ops[j] : 0) << (6 - 2 * j);
            v8(&enc, f);
            for (u32 j = 0; j < nops; j++) vput(&enc, data[j], dn[j]);
            nops = 0;
        }
    }
    vput(h, legacy, n);
    v8(h, 0);
    vput(h, enc.p, enc.n);
    free(enc.p);
    free(legacy);
    free(w);
}

static u32 dict_flags(const opts *o, const ent *e)
{
    if (e->kind == K_DIR) return 0xE0;
    u32 lg = o->dictlog < 16 ? 16 : o->dictlog;
    return ((lg - 16) & 7) << 5;
}

/* file / service header (one part of a split file) */
static void file_header(const opts *o, const ent *e, vec *h, u32 type, u64 pack, u32 split, u32 crcfield)
{
    u32 fl = 0x8000 | split | dict_flags(o, e);
    int unix_host = o->host == 3 || e->kind == K_LINK;
    if (type == 0x74 && e->solid) fl |= 0x10;
    if (type == 0x7A && e->kind == K_STREAM) fl |= 0x10;
    if (o->pw && e->kind != K_DIR && o->fmt == 29) fl |= 0x04 | 0x400;
    else if (o->pw && e->kind != K_DIR) fl |= 0x04;
    int large = (o->large && type == 0x74) || pack > 0xFFFFFFFFu || e->size > 0xFFFFFFFFu;
    if (large) fl |= 0x100;
    int uni = type == 0x74 && o->uni;
    if (uni) fl |= 0x200;
    if (type == 0x74 && o->exttime) fl |= 0x1000;
    memset(h, 0, sizeof *h);
    v16(h, 0);
    v8(h, type);
    v16(h, fl);
    v16(h, 0);
    v32(h, (u32)pack);
    u32 lu = o->unknown && !e->stored && type == 0x74 ? 0xFFFFFFFFu : (u32)e->size;
    v32(h, lu);
    v8(h, unix_host ? 3 : 2);
    v32(h, crcfield);
    v32(h, DOS_TIME);
    v8(h, e->ver);
    v8(h, 0x30 + e->method);
    const char *nm0 = type == 0x7A ? (e->kind == K_STREAM ? "STM" : "CMT") : e->name;
    char *nm = strdup(nm0);
    for (char *q = nm; *q; q++)
        if (*q == '/') *q = '\\';            /* RAR 1.5 - 4.x separator, also on Unix hosts */
    vec nb;
    memset(&nb, 0, sizeof nb);
    if (uni) put_unicode_name(&nb, nm);
    else vput(&nb, nm, strlen(nm));
    free(nm);
    v16(h, (u32)nb.n);
    u32 attr = unix_host ? (e->kind == K_DIR ? 040755 : e->kind == K_LINK ? 0120777 : 0100644)
                         : (e->kind == K_DIR ? 0x10 : 0x20);
    if (type == 0x7A) attr = e->kind == K_STREAM ? 0 : (u32)o->cmt_unicode;
    v32(h, attr);
    if (large) {
        v32(h, (u32)(pack >> 32));
        v32(h, o->unknown && !e->stored && type == 0x74 ? 0xFFFFFFFFu : (u32)((u64)e->size >> 32));
    }
    vput(h, nb.p, nb.n);
    free(nb.p);
    if (type == 0x7A && e->kind == K_STREAM) {
        /* SubData: the stream name in UTF-16LE */
        gzch *w = gz_posix_wide(e->name);
        v16(h, ':');
        for (size_t i = 0; w[i]; i++) v16(h, w[i]);
        free(w);
    }
    if (fl & 0x400) vput(h, e->salt, 8);
    if (fl & 0x1000) {
        /* mtime with 3 remainder bytes and +1 s, ctime (1 byte), atime (none) */
        v16(h, (0x8 | 0x4 | 3) << 12 | (0x8 | 1) << 8 | 0x8 << 4);
        v8(h, 0x12); v8(h, 0x34); v8(h, 0x56);
        v32(h, DOS_TIME - 0x20);
        v8(h, 0x77);
        v32(h, DOS_TIME - 0x40);
    }
    hdr_fix(h, 0);
}

typedef struct {
    opts *o;
    vec *vols;
    u32 nvol;
    vec cur;
    u8 hsalt[8];
    u8 hkey[16], hiv[16];
} vw;

static void put_hdr(vw *w, vec *h)
{
    if (!w->o->hp) {
        vput(&w->cur, h->p, h->n);
        return;
    }
    u32 n = (u32)h->n, pad = (n + 15) & ~15u;
    u8 *b = (u8 *)xcalloc(pad);
    memcpy(b, h->p, n);
    gz_aes a;
    u8 iv[16];
    memcpy(iv, w->hiv, 16);
    gz_aes_set_encrypt_key(&a, w->hkey, 16);
    gz_aes_cbc_encrypt(&a, iv, b, pad);
    vput(&w->cur, w->hsalt, 8);
    vput(&w->cur, b, pad);
    free(b);
}

static u32 hdr_cost(const vw *w, u32 n) { return w->o->hp ? 8 + ((n + 15) & ~15u) : n; }

static void begin_volume(vw *w)
{
    opts *o = w->o;
    memset(&w->cur, 0, sizeof w->cur);
    if (!w->nvol && o->sfx) {
        /* executable stub with decoy markers */
        v8(&w->cur, 'M');
        v8(&w->cur, 'Z');
        for (u32 i = 2; i < o->sfx; i++) v8(&w->cur, rnd() & 0xFF);
        for (u32 k = 0; k < 4 && o->sfx > 64; k++) memcpy(w->cur.p + 16 + rndn(o->sfx - 32), sig4, 7);
    }
    vput(&w->cur, sig4, 7);
    vec h;
    memset(&h, 0, sizeof h);
    u32 fl = 0;
    if (o->vol) fl |= 0x01;
    if (o->solid) fl |= 0x08;
    if (o->vol && !o->vold && o->fmt == 29) fl |= 0x10;
    if (o->hp) fl |= 0x80;
    if (o->vol && !w->nvol && o->fmt == 29) fl |= 0x100;
    int oldcmt = o->cmt && !w->nvol && o->fmt != 29;
    if (oldcmt) fl |= 0x02;
    v16(&h, 0);
    v8(&h, 0x73);
    v16(&h, fl);
    v16(&h, 13);
    v16(&h, 0);
    v32(&h, 0);
    if (oldcmt) {
        /* RAR 1.5 / 2.x comment block inside the main header */
        size_t cl = strlen(o->cmt);
        vec pk;
        memset(&pk, 0, sizeof pk);
        int store = o->cmt_store;
        if (!store) pack_fresh(o, o->fmt, (const u8 *)o->cmt, cl, &pk);
        else vput(&pk, o->cmt, cl);
        size_t cs = h.n;
        v16(&h, 0);
        v8(&h, 0x75);
        v16(&h, 0);
        v16(&h, (u32)(13 + pk.n));
        v16(&h, (u32)cl);
        v8(&h, (u32)o->fmt);
        v8(&h, store ? 0x30 : 0x33);
        v16(&h, gz_crc32(0, o->cmt, cl) & 0xFFFF);
        wr16(h.p + cs, (u16)(gz_crc32(0, h.p + cs + 2, 11) & 0xFFFF));
        vput(&h, pk.p, pk.n);
        free(pk.p);
        wr16(h.p + 5, (u16)h.n);
        wr16(h.p, (u16)(gz_crc32(0, h.p + 2, 11) & 0xFFFF));
    } else {
        hdr_fix(&h, 0);
    }
    vput(&w->cur, h.p, h.n);
    free(h.p);
    if (o->cmt && !w->nvol && o->fmt == 29) {
        /* CMT service header */
        ent ce;
        memset(&ce, 0, sizeof ce);
        ce.kind = K_FILE;
        vec text;
        memset(&text, 0, sizeof text);
        if (o->cmt_unicode) {
            gzch *wc = gz_posix_wide(o->cmt);
            for (size_t i = 0; wc[i]; i++) v16(&text, wc[i]);
            free(wc);
        } else {
            vput(&text, o->cmt, strlen(o->cmt));
        }
        ce.data = text.p;
        ce.size = text.n;
        ce.stored = o->cmt_store;
        ce.ver = ce.stored ? 20 : 29;
        ce.method = ce.stored ? 0 : 3;
        if (!ce.stored) pack_fresh(o, 29, text.p, text.n, &ce.packed);
        else vput(&ce.packed, text.p, text.n);
        opts o2 = *o;
        o2.pw = 0;
        o2.large = 0;
        o2.unknown = 0;
        o2.dictlog = 16;
        vec ch;
        file_header(&o2, &ce, &ch, 0x7A, ce.packed.n, 0, gz_crc32(0, text.p, text.n));
        put_hdr(w, &ch);
        vput(&w->cur, ce.packed.p, ce.packed.n);
        free(ch.p);
        free(ce.packed.p);
        free(text.p);
    }
}

static void end_volume(vw *w, int last)
{
    opts *o = w->o;
    if (o->fmt != 14 && !(o->noend && o->fmt != 29)) {
        vec h;
        memset(&h, 0, sizeof h);
        u32 fl = 0x4000 | (last ? 0 : 0x01) | (o->vol ? 0x08 : 0);
        v16(&h, 0);
        v8(&h, 0x7B);
        v16(&h, fl);
        v16(&h, 7);
        if (fl & 0x08) v16(&h, w->nvol);
        hdr_fix(&h, 0);
        put_hdr(w, &h);
        free(h.p);
    }
    w->vols = (vec *)xrealloc(w->vols, (w->nvol + 1) * sizeof(vec));
    w->vols[w->nvol++] = w->cur;
    memset(&w->cur, 0, sizeof w->cur);
}

static u32 end_cost(const vw *w) { return hdr_cost(w, 9); }

/* one entry: header(s) + data, split across volumes when they are limited */
static void put_entry(vw *w, ent *e, u32 type)
{
    opts *o = w->o;
    size_t left = e->packed.n, done = 0;
    int first = 1;
    for (;;) {
        vec h;
        file_header(o, e, &h, type, 0, 0, 0);
        u32 hc = hdr_cost(w, (u32)h.n);
        free(h.p);
        size_t part = left;
        if (o->vol) {
            u64 used = w->cur.n + hc + end_cost(w);
            if (used + (left ? 1 : 0) > o->vol && w->cur.n > 40) {
                end_volume(w, 0);
                begin_volume(w);
                continue;
            }
            u64 room = o->vol > used ? o->vol - used : 0;
            if (part > room) part = room ? (size_t)room : 1;
        }
        int more = part < left;
        u32 split = (first ? 0 : 0x01) | (more ? 0x02 : 0);
        u32 crcf = more ? gz_crc32(0, e->packed.p + done, part) : e->crc;
        file_header(o, e, &h, type, part, split, crcf);
        put_hdr(w, &h);
        free(h.p);
        vput(&w->cur, e->packed.p + done, part);
        done += part;
        left -= part;
        first = 0;
        if (!left) return;
        end_volume(w, 0);
        begin_volume(w);
    }
}

/* RAR 2.x NTFS stream sub-block */
static void put_oldstream(vw *w, ent *e)
{
    vec h;
    memset(&h, 0, sizeof h);
    v16(&h, 0);
    v8(&h, 0x77);
    v16(&h, 0x8000);
    v16(&h, 0);
    v32(&h, (u32)e->packed.n);
    v16(&h, 0x105);
    v8(&h, 0);
    v32(&h, (u32)e->size);
    v8(&h, e->ver);
    v8(&h, 0x33);
    v32(&h, e->crc);
    v16(&h, (u32)strlen(e->name) + 1);
    v8(&h, ':');
    vput(&h, e->name, strlen(e->name));
    hdr_fix(&h, 0);
    vput(&w->cur, h.p, h.n);
    vput(&w->cur, e->packed.p, e->packed.n);
    free(h.p);
}

/* RAR 1.4 archive: "RE~^" main header, 21-byte file headers, no CRCs */
static void write14(opts *o, vw *w)
{
    for (;;) {
        memset(&w->cur, 0, sizeof w->cur);
        vec m;
        memset(&m, 0, sizeof m);
        vput(&m, "RE~^", 4);
        v16(&m, 0);
        v8(&m, 0);
        u32 fl = (o->vol ? 1 : 0) | (o->solid ? 8 : 0);
        if (o->cmt && !w->nvol) {
            fl |= 2;
            size_t cl = strlen(o->cmt);
            if (o->cmt_store) {
                v16(&m, (u32)cl);
                vput(&m, o->cmt, cl);
            } else {
                fl |= 0x10;
                vec pk;
                memset(&pk, 0, sizeof pk);
                pack_fresh(o, 15, (const u8 *)o->cmt, cl, &pk);
                oldc c;
                c.k13[0] = 0;
                c.k13[1] = 7;
                c.k13[2] = 77;
                encrypt13(&c, pk.p, pk.n);
                v16(&m, (u32)pk.n + 2);
                v16(&m, (u32)cl);
                vput(&m, pk.p, pk.n);
                free(pk.p);
            }
        }
        m.p[6] = (u8)fl;
        wr16(m.p + 4, (u16)m.n);
        vput(&w->cur, m.p, m.n);
        free(m.p);
        break;
    }
    for (u32 i = 0; i < o->ne; i++) {
        ent *e = &o->e[i];
        size_t left = e->packed.n, done = 0;
        int first = 1;
        do {
            size_t nl = strlen(e->name), hs = 21 + nl, part = left;
            if (o->vol) {
                u64 used = w->cur.n + hs;
                if (used + 1 > o->vol && w->cur.n > 40) {
                    end_volume(w, 0);
                    vec m;
                    memset(&m, 0, sizeof m);
                    vput(&m, "RE~^", 4);
                    v16(&m, 7);
                    v8(&m, 1 | (o->solid ? 8 : 0));
                    w->cur = m;
                    continue;
                }
                u64 room = o->vol - used;
                if (part > room) part = room ? (size_t)room : 1;
            }
            int more = part < left;
            vec h;
            memset(&h, 0, sizeof h);
            v32(&h, (u32)part);
            v32(&h, (u32)e->size);
            v16(&h, e->crc);
            v16(&h, (u32)hs);
            v32(&h, DOS_TIME);
            v8(&h, e->kind == K_DIR ? 0x10 : 0x20);
            v8(&h, (first ? 0 : 1) | (more ? 2 : 0) | (o->pw && e->kind != K_DIR ? 4 : 0));
            v8(&h, 2);
            v8(&h, (u32)nl);
            v8(&h, e->method);
            for (size_t c = 0; c < nl; c++) v8(&h, e->name[c] == '/' ? '\\' : (u8)e->name[c]);
            vput(&w->cur, h.p, h.n);
            free(h.p);
            vput(&w->cur, e->packed.p + done, part);
            done += part;
            left -= part;
            first = 0;
            if (left) {
                end_volume(w, 0);
                vec m;
                memset(&m, 0, sizeof m);
                vput(&m, "RE~^", 4);
                v16(&m, 7);
                v8(&m, 1 | (o->solid ? 8 : 0));
                w->cur = m;
            }
        } while (left);
    }
    w->vols = (vec *)xrealloc(w->vols, (w->nvol + 1) * sizeof(vec));
    w->vols[w->nvol++] = w->cur;
}

static u8 *read_file(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb");
    if (!f) { perror(p); exit(2); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *b = (u8 *)xcalloc((size_t)sz + 1);
    if (sz && fread(b, 1, (size_t)sz, f) != (size_t)sz) die("read");
    fclose(f);
    *n = (size_t)sz;
    return b;
}

static void write_file(const char *p, const u8 *b, size_t n)
{
    FILE *f = fopen(p, "wb");
    if (!f || (n && fwrite(b, 1, n, f) != n)) { perror(p); exit(2); }
    fclose(f);
}

static int cmd_make(int argc, char **argv)
{
    opts o;
    memset(&o, 0, sizeof o);
    o.fmt = 29;
    o.method = 3;
    o.dictlog = 20;
    o.ppm_order = 6;
    o.ppm_mb = 7;
    o.host = 2;
    const char *out = argv[2];
    u32 seed = 1;
    int i = 3;
    for (; i < argc && argv[i][0] == '-'; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : "";
#define OPT(n) (!strcmp(a, n))
        if (OPT("-fmt")) { o.fmt = atoi(v); i++; }
        else if (OPT("-m")) { o.method = atoi(v); i++; }
        else if (OPT("-d")) { o.dictlog = (u32)atoi(v); i++; }
        else if (OPT("-s")) o.solid = 1;
        else if (OPT("-ppm")) o.ppm = 1;
        else if (OPT("-mix")) o.ppm = 2;
        else if (OPT("-order")) { o.ppm_order = (u32)atoi(v); i++; }
        else if (OPT("-mb")) { o.ppm_mb = (u32)atoi(v); i++; }
        else if (OPT("-var")) o.variety = 1;
        else if (OPT("-lazy")) o.lazy = 1;
        else if (OPT("-blk")) { o.blk = atoi(v); i++; }
        else if (OPT("-f")) {
            char t[64];
            snprintf(t, sizeof t, "%s", v);
            char *plus = strchr(t, '+');
            if (plus) { *plus = 0; o.filt[1] = ftype_of(plus + 1); }
            o.filt[0] = ftype_of(t);
            i++;
        }
        else if (OPT("-flen")) { o.flen = (u32)strtoul(v, 0, 0); i++; }
        else if (OPT("-fparam")) { o.fparam = (u32)strtoul(v, 0, 0); i++; }
        else if (OPT("-audio")) { o.audio = (u32)atoi(v); i++; }
        else if (OPT("-p")) { o.pw = v; i++; }
        else if (OPT("-hp")) o.hp = 1;
        else if (OPT("-vol")) { o.vol = strtoull(v, 0, 0); i++; }
        else if (OPT("-vold")) o.vold = 1;
        else if (OPT("-noend")) o.noend = 1;
        else if (OPT("-cmt")) { o.cmt = v; i++; }
        else if (OPT("-cmtu")) o.cmt_unicode = 1;
        else if (OPT("-cmtstore")) o.cmt_store = 1;
        else if (OPT("-uni")) o.uni = 1;
        else if (OPT("-exttime")) o.exttime = 1;
        else if (OPT("-host")) { o.host = atoi(v); i++; }
        else if (OPT("-large")) o.large = 1;
        else if (OPT("-unknown")) o.unknown = 1;
        else if (OPT("-sfx")) { o.sfx = (u32)strtoul(v, 0, 0); i++; }
        else if (OPT("-seed")) { seed = (u32)strtoul(v, 0, 0); i++; }
        else die("unknown option");
#undef OPT
    }
    rnd_state = seed * 2654435761u + 1;
    if (o.hp && o.fmt != 29) die("-hp needs -fmt 29");
    if (o.hp && !o.pw) die("-hp needs -p");
    /* entries */
    o.e = (ent *)xcalloc((size_t)(argc - i + 1) * sizeof(ent));
    for (; i < argc; i++) {
        const char *a = argv[i];
        ent *e = &o.e[o.ne];
        memset(e, 0, sizeof *e);
        size_t al = strlen(a);
        if (!strncmp(a, "L:", 2)) {
            const char *eq = strchr(a, '=');
            if (!eq) die("L:name=target");
            e->kind = K_LINK;
            e->name = strndup(a + 2, (size_t)(eq - a - 2));
            e->data = (u8 *)strdup(eq + 1);
            e->size = strlen(eq + 1);
        } else if (!strncmp(a, "S:", 2)) {
            const char *eq = strchr(a, '=');
            if (!eq) die("S:stream=path");
            e->kind = K_STREAM;
            e->name = strndup(a + 2, (size_t)(eq - a - 2));
            e->data = read_file(eq + 1, &e->size);
        } else if (al && a[al - 1] == '/') {
            e->kind = K_DIR;
            e->name = strndup(a, al - 1);
            e->data = (u8 *)xcalloc(1);
        } else {
            const char *eq = strchr(a, '=');
            if (!eq) die("name=path");
            e->kind = K_FILE;
            e->name = strndup(a, (size_t)(eq - a));
            e->data = read_file(eq + 1, &e->size);
        }
        o.ne++;
    }
    encode_all(&o);
    /* solid archives flag every entry after the first, directories and stored
     * files included (7-Zip and unar start a new solid stream otherwise) */
    for (u32 k = 1; o.solid && o.fmt != 14 && k < o.ne; k++)
        if (o.e[k].kind != K_STREAM) o.e[k].solid = 1;
    /* NTFS streams: fresh non-solid data (old sub-blocks need compressed data) */
    for (u32 k = 0; k < o.ne; k++) {
        ent *e = &o.e[k];
        if (e->kind != K_STREAM) continue;
        if (o.fmt != 29 && !e->size) continue;
        free(e->packed.p);
        memset(&e->packed, 0, sizeof e->packed);
        e->stored = o.fmt == 29 && (!o.method || !e->size);
        e->method = e->stored ? 0 : 3;
        e->ver = o.fmt == 29 ? (e->stored ? 20 : 29) : (u32)o.fmt;
        if (o.pw && o.fmt == 29) e->ver = 29;
        if (e->stored) vput(&e->packed, e->data, e->size);
        else pack_fresh(&o, o.fmt == 29 ? 29 : o.fmt, e->data, e->size, &e->packed);
        if (o.pw && o.fmt == 29) {
            for (int b = 0; b < 8; b++) e->salt[b] = (u8)rnd();
            u8 pw16[512], key[16], iv[16];
            size_t pl = 0;
            gzch *w = gz_posix_wide(o.pw);
            for (; w[pl] && pl < 127; pl++) wr16(pw16 + 2 * pl, w[pl]);
            free(w);
            gz_rar3_kdf(pw16, pl * 2, e->salt, key, iv);
            while (e->packed.n & 15) v8(&e->packed, 0);
            gz_aes a;
            gz_aes_set_encrypt_key(&a, key, 16);
            gz_aes_cbc_encrypt(&a, iv, e->packed.p, e->packed.n);
        }
    }
    vw w;
    memset(&w, 0, sizeof w);
    w.o = &o;
    if (o.hp) {
        for (int k = 0; k < 8; k++) w.hsalt[k] = (u8)rnd();
        u8 pw16[512];
        size_t pl = 0;
        gzch *wc = gz_posix_wide(o.pw);
        for (; wc[pl] && pl < 127; pl++) wr16(pw16 + 2 * pl, wc[pl]);
        free(wc);
        gz_rar3_kdf(pw16, pl * 2, w.hsalt, w.hkey, w.hiv);
    }
    if (o.fmt == 14) {
        write14(&o, &w);
    } else {
        begin_volume(&w);
        for (u32 k = 0; k < o.ne; k++) {
            ent *e = &o.e[k];
            if (e->kind == K_STREAM) {
                if (o.fmt == 29) put_entry(&w, e, 0x7A);
                else if (e->size) put_oldstream(&w, e);
            } else {
                put_entry(&w, e, 0x74);
            }
        }
        end_volume(&w, 1);
    }
    /* names: base.rar alone, base.partN.rar or base.rar / base.r00 ... */
    size_t ol = strlen(out);
    if (ol < 4) die("output name");
    char *base = strndup(out, ol - 4);
    for (u32 k = 0; k < w.nvol; k++) {
        char nm[4096];
        if (w.nvol == 1 && !o.vol) snprintf(nm, sizeof nm, "%s", out);
        else if (o.fmt == 29 && !o.vold) snprintf(nm, sizeof nm, "%s.part%0*u.rar", base, w.nvol >= 100 ? 3 : w.nvol >= 10 ? 2 : 1, k + 1);
        else if (!k) snprintf(nm, sizeof nm, "%s.rar", base);
        else snprintf(nm, sizeof nm, "%s.%c%02u", base, 'r' + (k - 1) / 100, (k - 1) % 100);
        write_file(nm, w.vols[k].p, w.vols[k].n);
        free(w.vols[k].p);
    }
    printf("ok %u\n", w.nvol);
    free(base);
    free(w.vols);
    for (u32 k = 0; k < o.ne; k++) {
        free(o.e[k].name);
        free(o.e[k].data);
        free(o.e[k].packed.p);
    }
    free(o.e);
    return 0;
}

/* ================= check / bench / fuzz ================= */

typedef struct { gz_out o; u64 n, lim; } cnt_out;
static int c_open(gz_out *o, u32 idx) { (void)o; (void)idx; return 0; }
static int c_write(gz_out *o, const u8 *p, size_t n)
{
    cnt_out *c = (cnt_out *)o;
    volatile u8 s = 0;
    for (size_t i = 0; i < n; i += 4096) s ^= p[i];
    (void)s;
    c->n += n;
    return c->lim && c->n > c->lim ? GZ_E_CANCEL : GZ_OK;
}
static int c_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; (void)st; return 0; }

static gzch g_pw[256];
static int ask_pw(void *u, gzch *b, u32 cap, int retry)
{
    (void)u;
    if (retry || !g_pw[0]) return GZ_E_PASSWORD;
    u32 i = 0;
    for (; g_pw[i] && i + 1 < cap; i++) b[i] = g_pw[i];
    b[i] = 0;
    return GZ_OK;
}

static void set_pw(const char *s)
{
    gzch *w = gz_posix_wide(s);
    size_t n = gz_wcslen(w);
    if (n > 250) n = 250;
    memcpy(g_pw, w, n * sizeof(gzch));
    g_pw[n] = 0;
    free(w);
}

static int extract_all(gz_src *src, const gzch *fname, cnt_out *co, int *nent)
{
    gz_open_opts oo;
    memset(&oo, 0, sizeof oo);
    oo.file_name = fname;
    oo.password = g_pw[0] ? g_pw : 0;
    oo.ask_password = ask_pw;
    oo.open_volume = fname ? gz_posix_open_volume : 0;
    gz_ctx *c = gz_ctx_new();
    gz_archive *a = 0;
    int r = gz_arc_open(&a, src, &oo, c);
    if (r) { gz_ctx_free(c); return r; }
    c->password = g_pw[0] ? g_pw : a->password;
    *nent = (int)a->n;
    u8 *sel = (u8 *)malloc(a->n + 1);
    memset(sel, 1, a->n + 1);
    if (a->solid) {
        gz_arc_extract_solid(a, src, sel, &co->o, c);
    } else {
        for (u32 k = 0; k < a->n; k++) {
            gz_arc_check_password(a, src, k, c);
            gz_arc_extract(a, src, k, &co->o, c);
        }
    }
    if (a->n && a->solid) {
        u32 k = rnd() % a->n;
        gz_arc_check_password(a, src, k, c);
        gz_arc_extract(a, src, k, &co->o, c);
    }
    gzch m[64];
    for (u32 k = 0; k < a->n && k < 64; k++) gz_arc_method(a, &a->e[k], m, 64);
    gz_src_free(gz_arc_view(a, src, a->n ? rnd() % a->n : 0, c));
    free(sel);
    gz_arc_close(a);
    gz_ctx_free(c);
    return GZ_OK;
}

static void init_core(void)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
    init_tables();
    init_num15();
    for (int t = F_E8; t <= F_BOGUS; t++) forge(stdf[t].len, stdf[t].crc, fcode[t]);
    for (u32 i = 0; i < stdf[F_BADXOR].len; i++) fcode[F_BADXOR][i] = (u8)(i * 37 + 1);
    fcode[F_BADXOR][1] = 0;                 /* XOR of the bytes stays non-zero, static data bit clear */
}

static int cmd_bench(int argc, char **argv)
{
    if (argc > 4) set_pw(argv[4]);
    int rounds = atoi(argv[3]);
    gz_src *s = gz_posix_open_src(argv[2]);
    if (!s) die("cannot open");
    gzch *fn = gz_posix_wide(argv[2]);
    cnt_out co = { { c_open, c_write, c_close, 0 }, 0, 0 };
    struct timespec t0, t1;
    double best = 1e30;
    for (int k = 0; k < rounds; k++) {
        co.n = 0;
        int ne;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int r = extract_all(s, fn, &co, &ne);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (r) { printf("error %d\n", r); return 1; }
        double dt = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) * 1e-9;
        if (dt < best) best = dt;
    }
    printf("bytes %llu best %.4f s  %.1f MB/s\n", (unsigned long long)co.n, best, (double)co.n / best / 1e6);
    free(fn);
    gz_src_free(s);
    return 0;
}

/* walk the RAR 1.5 - 4.x headers and recompute their CRC16s (so that mutated
 * header fields get parsed instead of failing the checksum) */
static void fix_crcs(u8 *p, size_t n)
{
    size_t off = 0;
    while (off + 7 <= n && memcmp(p + off, sig4, 7)) off++;
    if (off + 7 > n) return;
    off += 7;
    for (int k = 0; k < 10000 && off + 7 <= n; k++) {
        u32 hs = rd16(p + off + 5), fl = rd16(p + off + 3);
        if (hs < 7 || off + hs > n) return;
        u32 crc_len = hs;
        if (p[off + 2] == 0x73 && (fl & 2) && hs > 13) crc_len = 13;
        wr16(p + off, (u16)(gz_crc32(0, p + off + 2, crc_len - 2) & 0xFFFF));
        u64 add = 0;
        if ((fl & 0x8000) && hs >= 11) add = rd32(p + off + 7);
        if (off + hs + add > n) return;
        off += hs + add;
    }
}

static void mutate(u8 *p, size_t *n)
{
    size_t len = *n;
    if (len < 2) return;
    int kind = (int)(rnd() % 10);
    int count = 1 + (int)(rnd() % 6);
    for (int k = 0; k < count; k++) {
        size_t pos = rnd() % 3 ? rnd() % (len < 512 ? len : 512) : rnd() % len;
        if (kind < 5) p[pos] ^= (u8)(1u << (rnd() % 8));
        else if (kind < 7) p[pos] = (u8)rnd();
        else if (kind < 9 && pos + 4 <= len) wr32(p + pos, (u32)rnd() >> (rnd() % 32));
        else p[pos] = 0xFF;
    }
    if (rnd() % 8 == 0) *n = 1 + rnd() % len;
}

static int cmd_fuzz(int argc, char **argv)
{
    if (argc > 5) set_pw(argv[5]);
    size_t n0;
    u8 *orig = read_file(argv[2], &n0);
    long iters = atol(argv[3]);
    rnd_state = (u32)strtoul(argv[4], 0, 0) * 2654435761u + 7;
    u8 *buf2 = (u8 *)malloc(n0 + 1);
    long opened = 0;
    for (long it = 0; it < iters; it++) {
        memcpy(buf2, orig, n0);
        size_t n = n0;
        mutate(buf2, &n);
        if (rnd() % 2) fix_crcs(buf2, n);
        gz_src *s = gz_src_mem(buf2, n, 0);
        cnt_out co = { { c_open, c_write, c_close, 0 }, 0, 64u << 20 };
        int ne;
        if (!extract_all(s, 0, &co, &ne)) opened++;
        gz_src_free(s);
    }
    printf("ok %ld opened=%ld\n", iters, opened);
    free(buf2);
    free(orig);
    return 0;
}

/* check: per-entry status, size and CRC-32 of the extracted data (to compare builds) */
typedef struct { gz_out o; u32 n, cur; u32 *crc; u64 *size; int *st; } chk_out;
static int k_open(gz_out *o, u32 idx)
{
    chk_out *k = (chk_out *)o;
    k->cur = idx;
    if (idx < k->n) { k->crc[idx] = 0; k->size[idx] = 0; }
    return 0;
}
static int k_write(gz_out *o, const u8 *p, size_t n)
{
    chk_out *k = (chk_out *)o;
    if (k->cur < k->n) { k->crc[k->cur] = gz_crc32(k->crc[k->cur], p, n); k->size[k->cur] += n; }
    return 0;
}
static int k_close(gz_out *o, u32 idx, int st)
{
    chk_out *k = (chk_out *)o;
    if (idx < k->n) k->st[idx] = st ? st : 100;
    return 0;
}

static int cmd_check(int argc, char **argv)
{
    if (argc > 3) set_pw(argv[3]);
    gz_src *s = gz_posix_open_src(argv[2]);
    if (!s) die("cannot open");
    gzch *fn = gz_posix_wide(argv[2]);
    gz_open_opts oo;
    memset(&oo, 0, sizeof oo);
    oo.file_name = fn;
    oo.password = g_pw[0] ? g_pw : 0;
    oo.ask_password = ask_pw;
    oo.open_volume = gz_posix_open_volume;
    gz_ctx *c = gz_ctx_new();
    gz_archive *a = 0;
    int r = gz_arc_open(&a, s, &oo, c);
    if (r) { printf("open %d\n", r); return 0; }
    c->password = g_pw[0] ? g_pw : a->password;
    chk_out k;
    memset(&k, 0, sizeof k);
    k.o.open = k_open; k.o.write = k_write; k.o.close = k_close;
    k.n = a->n;
    k.crc = (u32 *)calloc(a->n + 1, 4);
    k.size = (u64 *)calloc(a->n + 1, 8);
    k.st = (int *)calloc(a->n + 1, sizeof(int));
    if (a->solid) {
        u8 *sel = (u8 *)malloc(a->n + 1);
        memset(sel, 1, a->n + 1);
        gz_arc_extract_solid(a, s, sel, &k.o, c);
        free(sel);
    } else {
        for (u32 i = 0; i < a->n; i++) {
            int e = gz_arc_extract(a, s, i, &k.o, c);
            if (e && !k.st[i]) k.st[i] = e;
        }
    }
    printf("type %s n %u solid %d\n", gz_arc_type_name(a), a->n, a->solid);
    for (u32 i = 0; i < a->n; i++) {
        char *nm = gz_posix_utf8(a->e[i].name);
        gzch mw[64];
        gz_arc_method(a, &a->e[i], mw, 64);
        char *ms = gz_posix_utf8(mw);
        printf("%u %d %llu %08x %s [%s]\n", i, k.st[i] == 100 ? 0 : k.st[i], (unsigned long long)k.size[i], k.crc[i], nm, ms);
        free(nm);
        free(ms);
    }
    free(k.crc); free(k.size); free(k.st);
    gz_arc_close(a);
    gz_ctx_free(c);
    gz_src_free(s);
    free(fn);
    return 0;
}

int main(int argc, char **argv)
{
    init_core();
    if (argc >= 4 && !strcmp(argv[1], "make")) return cmd_make(argc, argv);
    if (argc >= 4 && !strcmp(argv[1], "bench")) return cmd_bench(argc, argv);
    if (argc >= 5 && !strcmp(argv[1], "fuzz")) return cmd_fuzz(argc, argv);
    if (argc >= 3 && !strcmp(argv[1], "check")) return cmd_check(argc, argv);
    fprintf(stderr, "usage: rar3_tool make|bench|fuzz|check ...\n");
    return 2;
}
