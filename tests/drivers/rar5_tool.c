/*
 * rar5_tool - RAR 5.0 test helper (writer for fixtures, benchmark, fuzzer)
 *
 *   rar5_tool make <out> [options] <entry>...
 *       Writes a RAR5 archive with its own LZ + Huffman encoder so that the
 *       decoder's features can be covered: every match kind (new distance,
 *       the four repeated distances, "last length"), long distances, block
 *       splitting with and without tables, DELTA/E8/E8E9/ARM filters at
 *       various offsets, solid streams, AES-256 data and header encryption
 *       (HMAC checksums), CRC32 / BLAKE2sp, volumes (new and old naming),
 *       comments, links, SFX stubs and the RAR7 (version 1) algorithm.
 *       Archives are checked with 7-Zip by the test module before use.
 *     options: -m N (0 store, 1-5)  -d LOG2 (17-32)  -v7  -s (solid)  -blk BYTES
 *              -reuse  -f e8|e8e9|arm|delta|mix  -flen N  -p PW  -hp  -lg2 N  -mac
 *              -b2 | -both  -vol BYTES  -vold  -sfx BYTES  -cmt TEXT  -seed N
 *              -host 0|1  -nosize  -depth N
 *     entries: name=path  dir/  L:name=target  H:name=target  C:name=target
 *     -vol: <out> holds one %d (e.g. a.part%d.rar); -vold: <out> is a.rar
 *   rar5_tool bench <archive> <rounds> [password]
 *       extracts every entry <rounds> times, prints MB/s of output
 *   rar5_tool fuzz <archive> <iterations> <seed> [password]
 *       mutates the archive in memory (bit flips, smashed vints / sizes,
 *       truncation) and extracts it; must not crash, hang or leak
 *   rar5_tool check <archive> [password]
 *       prints status, size and CRC-32 of every extracted entry (the test
 *       compares i386 / AArch64 builds with the host build)
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "crypto.h"
#include "rar5dec.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

static u64 g_rng = 88172645463325252ull;
static u64 rnd(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return g_rng;
}

static void die(const char *m) { fprintf(stderr, "rar5_tool: %s\n", m); exit(2); }

/* ---------------- byte buffers / bit writer ---------------- */

typedef struct { u8 *p; size_t n, cap; } buf;

static void b_put(buf *b, const void *p, size_t n)
{
    if (b->n + n > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 4096;
        while (nc < b->n + n) nc *= 2;
        b->p = (u8 *)realloc(b->p, nc);
        if (!b->p) die("out of memory");
        b->cap = nc;
    }
    if (n) memcpy(b->p + b->n, p, n);
    b->n += n;
}
static void b_u8(buf *b, u8 v) { b_put(b, &v, 1); }
static void b_u32(buf *b, u32 v) { u8 t[4]; wr32(t, v); b_put(b, t, 4); }
static void b_u64(buf *b, u64 v) { u8 t[8]; wr64(t, v); b_put(b, t, 8); }
static void b_vint(buf *b, u64 v)
{
    do { u8 c = (u8)(v & 0x7F); v >>= 7; if (v) c |= 0x80; b_u8(b, c); } while (v);
}

typedef struct { buf b; u64 acc; int nacc; u64 bits; } bitw;

static void bw_put(bitw *w, u32 v, int n)
{
    if (!n) return;
    w->acc = (w->acc << n) | (v & (n == 32 ? 0xFFFFFFFFu : ((1u << n) - 1)));
    w->nacc += n;
    w->bits += (u64)n;
    while (w->nacc >= 8) {
        w->nacc -= 8;
        b_u8(&w->b, (u8)(w->acc >> w->nacc));
    }
}
static void bw_put64(bitw *w, u64 v, int n)
{
    if (n > 32) { bw_put(w, (u32)(v >> 32), n - 32); n = 32; }
    bw_put(w, (u32)v, n);
}
static void bw_align(bitw *w) { if (w->nacc) bw_put(w, 0, 8 - w->nacc); }

/* ---------------- Huffman code construction ---------------- */

/* code lengths <= maxlen (frequencies are flattened until they fit) */
static void huff_lengths(const u32 *freq0, int n, int maxlen, u8 *len)
{
    u32 *f = (u32 *)malloc(n * sizeof(u32));
    int *par = (int *)malloc(2 * n * sizeof(int));
    u64 *w = (u64 *)malloc(2 * n * sizeof(u64));
    char *alive = (char *)malloc(2 * n);
    memcpy(f, freq0, n * sizeof(u32));
    for (;;) {
        memset(len, 0, n);
        int used = 0, last = -1;
        for (int i = 0; i < n; i++) if (f[i]) { used++; last = i; }
        if (used == 0) break;
        if (used == 1) { len[last] = 1; break; }
        int nn = n;
        for (int i = 0; i < n; i++) { w[i] = f[i]; alive[i] = f[i] != 0; par[i] = -1; }
        for (int left = used; left > 1; left--) {
            int a = -1, b = -1;
            for (int i = 0; i < nn; i++) {
                if (!alive[i]) continue;
                if (a < 0 || w[i] < w[a]) { b = a; a = i; }
                else if (b < 0 || w[i] < w[b]) b = i;
            }
            w[nn] = w[a] + w[b];
            alive[nn] = 1; par[nn] = -1;
            alive[a] = alive[b] = 0;
            par[a] = par[b] = nn;
            nn++;
        }
        int mx = 0;
        for (int i = 0; i < n; i++) {
            if (!f[i]) continue;
            int d = 0;
            for (int k = i; par[k] >= 0; k = par[k]) d++;
            len[i] = (u8)d;
            if (d > mx) mx = d;
        }
        if (mx <= maxlen) break;
        for (int i = 0; i < n; i++) if (f[i]) f[i] = (f[i] >> 1) | 1;
    }
    free(f); free(par); free(w); free(alive);
}

static void huff_codes(const u8 *len, int n, u32 *code)
{
    u32 cnt[16] = { 0 }, next[16];
    for (int i = 0; i < n; i++) cnt[len[i]]++;
    cnt[0] = 0;
    u32 c = 0;
    for (int l = 1; l <= 15; l++) { next[l] = c; c = (c + cnt[l]) << 1; }
    for (int i = 0; i < n; i++) if (len[i]) code[i] = next[len[i]]++;
}

/* ---------------- LZ encoder ---------------- */

#define NC 306
#define DC5 64
#define DC7 80
#define LDC 16
#define RC 44
#define TABX (NC + DC7 + LDC + RC)
#define HB 18
#define RING (1u << 20)

enum { T_LIT, T_MATCH, T_REP, T_LAST, T_FILT };
typedef struct { u8 kind, k; u16 pad; u32 len; u64 dist; u32 fs, fl, ft, fc; } tok;

typedef struct {
    u8 *h; u64 hn, hcap;      /* whole stream (filter-transformed data) */
    u32 *head, *prv;
    u64 rep[4];
    u32 lastlen;
    int tabs;
    u8 tl[TABX];
    u64 dict;
    int v7, depth;
} lzs;

typedef struct {
    int method, dlog, v7, solid, reuse, b2, both, hp, mac, host, nosize, depth;
    u32 blk, flen, lg2;
    const char *filt, *pw, *cmt;
    u64 vol, sfx;
    int vold;
} opts;

static void lz_init(lzs *z, const opts *o)
{
    memset(z, 0, sizeof *z);
    z->head = (u32 *)calloc(1u << HB, sizeof(u32));
    z->prv = (u32 *)calloc(RING, sizeof(u32));
    z->rep[0] = z->rep[1] = z->rep[2] = z->rep[3] = ~(u64)0;
    z->dict = (u64)1 << o->dlog;
    z->v7 = o->v7;
    z->depth = o->depth;
}

static u32 hash4(const u8 *p) { return (rd32(p) * 2654435761u) >> (32 - HB); }
static void lz_insert(lzs *z, u64 i)
{
    if (i + 4 > z->hn) return;
    u32 hv = hash4(z->h + i);
    z->prv[i & (RING - 1)] = z->head[hv];
    z->head[hv] = (u32)(i + 1);
}
static u32 mlen(const u8 *a, const u8 *b, u32 max)
{
    u32 n = 0;
    while (n < max && a[n] == b[n]) n++;
    return n;
}

/* forward transforms (the decoder applies the inverse) */
static void fw_e8(u8 *b, u32 n, u32 off, int e9)
{
    if (n <= 4) return;
    for (u32 i = 0; i < n - 4;) {
        u8 c = b[i++];
        if (c != 0xE8 && !(e9 && c == 0xE9)) continue;
        u32 o = (i + off) & 0xFFFFFF, a = rd32(b + i), e;
        if (a >= 0x1000000u && (o == 0 || a < 0u - o)) e = a;
        else if (a >= 0x1000000u - o && a < 0x1000000u) e = a - 0x1000000u;
        else e = a + o;
        wr32(b + i, e);
        i += 4;
    }
}
static void fw_arm(u8 *b, u32 n, u32 off)
{
    for (u32 i = 0; i + 3 < n; i += 4) {
        if (b[i + 3] != 0xEB) continue;
        u32 v = (b[i] | b[i + 1] << 8 | b[i + 2] << 16) + ((off + i) >> 2);
        b[i] = (u8)v; b[i + 1] = (u8)(v >> 8); b[i + 2] = (u8)(v >> 16);
    }
}
static void fw_delta(u8 *b, u32 n, u32 ch)
{
    u8 *t = (u8 *)malloc(n ? n : 1);
    u32 k = 0;
    for (u32 c = 0; c < ch; c++) {
        u8 prev = 0;
        for (u32 i = c; i < n; i += ch) { t[k++] = (u8)(prev - b[i]); prev = b[i]; }
    }
    memcpy(b, t, n);
    free(t);
}

typedef struct { u64 start; u32 len, type, ch; } fspec;

/* choose filter regions of a file and transform the data in place */
static int plan_filters(const opts *o, u8 *d, u64 n, fspec *fs, int maxf)
{
    if (!o->filt || n < 8) return 0;
    int nf = 0;
    u64 pos = rnd() % 64;
    while (pos + 8 < n && nf < maxf) {
        u32 len = 8 + (u32)(rnd() % o->flen);
        if (len > n - pos) len = (u32)(n - pos);
        u32 type;
        if (!strcmp(o->filt, "e8")) type = 1;
        else if (!strcmp(o->filt, "e8e9")) type = 2;
        else if (!strcmp(o->filt, "arm")) type = 3;
        else if (!strcmp(o->filt, "delta")) type = 0;
        else type = (u32)(rnd() % 4);
        u32 ch = type == 0 ? 1 + (u32)(rnd() % (rnd() % 2 ? 4 : 32)) : 0;
        if (type == 3) { pos = (pos + 3) & ~(u64)3; len &= ~3u; if (len < 8) len = 8; if (pos + len > n) break; }
        u8 *p = d + pos;
        if (type == 0) fw_delta(p, len, ch);
        else if (type == 3) fw_arm(p, len, (u32)pos);
        else fw_e8(p, len, (u32)pos, type == 2);
        fs[nf].start = pos;
        fs[nf].len = len;
        fs[nf].type = type;
        fs[nf].ch = ch;
        nf++;
        pos += len + rnd() % (rnd() % 3 ? 64 : 4096);
    }
    return nf;
}

static void push_tok(tok **t, size_t *n, size_t *cap, tok v)
{
    if (*n == *cap) { *cap = *cap ? *cap * 2 : 4096; *t = (tok *)realloc(*t, *cap * sizeof(tok)); }
    (*t)[(*n)++] = v;
}

/* tokens for z->h[from, z->hn); filter positions relative to `from` */
static tok *lz_parse(lzs *z, u64 from, const fspec *fs, int nf, size_t *ntok)
{
    tok *t = 0;
    size_t n = 0, cap = 0;
    int fi = 0;
    u64 fdelta = nf ? rnd() % 300 : 0;
    u64 i = from, end = z->hn;
    while (i < end) {
        /* filter symbol shortly before its block */
        if (fi < nf && i + fdelta >= from + fs[fi].start) {
            tok v = { T_FILT, 0, 0, 0, 0, (u32)(from + fs[fi].start - i), fs[fi].len, fs[fi].type, fs[fi].ch };
            push_tok(&t, &n, &cap, v);
            fi++;
            fdelta = rnd() % 300;
            continue;
        }
        u64 max = end - i < 4097 ? end - i : 4097;
        if (fi < nf && from + fs[fi].start > i && from + fs[fi].start - i < max) max = from + fs[fi].start - i;
        const u8 *cur = z->h + i;
        /* repeated distances */
        u32 bl = 0, bk = 0;
        for (u32 k = 0; k < 4; k++) {
            u64 d = z->rep[k];
            if (d == 0 || d > i || d > z->dict) continue;
            u32 l = mlen(cur, cur - d, (u32)max);
            if (l > bl) { bl = l; bk = k; }
        }
        /* new distance from the hash chains */
        u32 nl = 0;
        u64 nd = 0;
        if (max >= 4 && i + 4 <= end) {
            u32 cand = z->head[hash4(cur)];
            for (int dep = 0; cand && dep < z->depth; dep++) {
                u64 p = cand - 1;
                if (p >= i) break;
                u64 d = i - p;
                if (d > z->dict) break;
                u32 l = mlen(cur, z->h + p, (u32)max);
                u32 adj = (d > 0x100) + (d > 0x2000) + (d > 0x40000);
                if (l >= 4 && l >= 2 + adj && l > nl) { nl = l; nd = d; }
                if (i - p >= RING) break;
                cand = z->prv[p & (RING - 1)];
            }
        }
        u32 len;
        if (bl >= 2 && bl + 1 >= nl) {
            len = bl;
            u64 d = z->rep[bk];
            if (bk == 0 && z->lastlen && bl >= z->lastlen && rnd() % 3) {
                len = z->lastlen;
                tok v = { T_LAST, 0, 0, len, d, 0, 0, 0, 0 };
                push_tok(&t, &n, &cap, v);
            } else {
                tok v = { T_REP, (u8)bk, 0, len, d, 0, 0, 0, 0 };
                push_tok(&t, &n, &cap, v);
                for (u32 k = bk; k; k--) z->rep[k] = z->rep[k - 1];
                z->rep[0] = d;
                z->lastlen = len;
            }
        } else if (nl >= 4) {
            len = nl;
            tok v = { T_MATCH, 0, 0, len, nd, 0, 0, 0, 0 };
            push_tok(&t, &n, &cap, v);
            z->rep[3] = z->rep[2]; z->rep[2] = z->rep[1]; z->rep[1] = z->rep[0]; z->rep[0] = nd;
            z->lastlen = len;
        } else {
            len = 1;
            tok v = { T_LIT, 0, 0, cur[0], 0, 0, 0, 0, 0 };
            push_tok(&t, &n, &cap, v);
        }
        for (u32 k = 0; k < len; k++) lz_insert(z, i + k);
        i += len;
    }
    while (fi < nf) {   /* filters at the very end */
        tok v = { T_FILT, 0, 0, 0, 0, (u32)(from + fs[fi].start - i), fs[fi].len, fs[fi].type, fs[fi].ch };
        push_tok(&t, &n, &cap, v);
        fi++;
    }
    *ntok = n;
    return t;
}

static u32 len_slot(u32 l, u32 *eb, u32 *ev)
{
    l -= 2;
    if (l < 8) { *eb = 0; *ev = 0; return l; }
    u32 hb = 31 - (u32)__builtin_clz(l), lb = hb - 2;
    *eb = lb;
    *ev = l & ((1u << lb) - 1);
    return 4 * (lb + 1) + ((l >> lb) & 3);
}
static u32 dist_slot(u64 dist, u32 *db, u64 *dv)
{
    u64 d = dist - 1;
    if (d < 4) { *db = 0; *dv = 0; return (u32)d; }
    u32 hb = 63 - (u32)__builtin_clzll(d), b = hb - 1;
    *db = b;
    *dv = d & (((u64)1 << b) - 1);
    return 2 * hb + (u32)((d >> b) & 1);
}

static void filt_num(bitw *w, u32 v)
{
    u32 nb = v < 0x100 ? 1 : v < 0x10000 ? 2 : v < 0x1000000 ? 3 : 4;
    bw_put(w, nb - 1, 2);
    for (u32 i = 0; i < nb; i++) bw_put(w, (v >> (8 * i)) & 0xFF, 8);
}

/* code a token list as blocks; the stream's last block ends the file */
static void lz_blocks(lzs *z, const tok *t, size_t nt, u32 blk, int reuse, bitw *out)
{
    const int ndist = z->v7 ? DC7 : DC5, ntab = NC + ndist + LDC + RC;
    size_t i = 0;
    do {
        size_t j = i;
        u64 bytes = 0;
        while (j < nt && bytes < blk) { bytes += t[j].kind == T_LIT ? 1 : t[j].len; j++; }
        if (j < nt && rnd() % 7 == 0) j = i + (j - i) / 2;     /* uneven blocks */
        u32 fm[NC] = { 0 }, fd[DC7] = { 0 }, fl[LDC] = { 0 }, fr[RC] = { 0 };
        for (size_t k = i; k < j; k++) {
            const tok *v = &t[k];
            u32 eb, ev, db;
            u64 dv;
            switch (v->kind) {
            case T_LIT: fm[v->len]++; break;
            case T_FILT: fm[256]++; break;
            case T_LAST: fm[257]++; break;
            case T_REP: fm[258 + v->k]++; fr[len_slot(v->len, &eb, &ev)]++; break;
            default: {
                u32 adj = (v->dist > 0x100) + (v->dist > 0x2000) + (v->dist > 0x40000);
                fm[262 + len_slot(v->len - adj, &eb, &ev)]++;
                u32 ds = dist_slot(v->dist, &db, &dv);
                fd[ds]++;
                if (db >= 4) fl[dv & 15]++;
            }
            }
        }
        /* reuse the previous tables when they can code this block */
        int use_old = reuse && z->tabs && rnd() % 2;
        for (int k = 0; use_old && k < NC; k++) if (fm[k] && !z->tl[k]) use_old = 0;
        for (int k = 0; use_old && k < ndist; k++) if (fd[k] && !z->tl[NC + k]) use_old = 0;
        for (int k = 0; use_old && k < LDC; k++) if (fl[k] && !z->tl[NC + ndist + k]) use_old = 0;
        for (int k = 0; use_old && k < RC; k++) if (fr[k] && !z->tl[NC + ndist + LDC + k]) use_old = 0;
        bitw p;
        memset(&p, 0, sizeof p);
        if (!use_old) {
            u8 *L = z->tl;
            huff_lengths(fm, NC, 15, L);
            huff_lengths(fd, ndist, 15, L + NC);
            if (rnd() % 4 == 0) { for (int k = 0; k < LDC; k++) L[NC + ndist + k] = 4; }
            else huff_lengths(fl, LDC, 15, L + NC + ndist);
            huff_lengths(fr, RC, 15, L + NC + ndist + LDC);
            /* lengths -> bit-length code symbols (16/17 repeat, 18/19 zeros) */
            u32 sy[TABX], sx[TABX], ns = 0, fb[20] = { 0 };
            for (int k = 0; k < ntab;) {
                int r = 1;
                while (k + r < ntab && L[k + r] == L[k] && r < 138) r++;
                if (L[k] == 0 && r >= 3) {
                    if (r >= 11) { sy[ns] = 19; sx[ns++] = r - 11; } else { sy[ns] = 18; sx[ns++] = r - 3; }
                    k += r;
                } else if (k > 0 && L[k - 1] == L[k] && r >= 3) {
                    if (r >= 11) { sy[ns] = 17; sx[ns++] = r - 11; } else { sy[ns] = 16; sx[ns++] = r - 3; }
                    k += r;
                } else {
                    sy[ns] = L[k]; sx[ns++] = 0;
                    k++;
                }
            }
            for (u32 k = 0; k < ns; k++) fb[sy[k]]++;
            u8 bl[20];
            u32 bc[20];
            huff_lengths(fb, 20, 15, bl);
            huff_codes(bl, 20, bc);
            for (int k = 0; k < 20;) {
                int r = 1;
                while (k + r < 20 && bl[k + r] == 0 && bl[k] == 0 && r < 17) r++;
                if (bl[k] == 0 && r >= 3) { bw_put(&p, 15, 4); bw_put(&p, r - 2, 4); k += r; }
                else if (bl[k] == 15) { bw_put(&p, 15, 4); bw_put(&p, 0, 4); k++; }
                else { bw_put(&p, bl[k], 4); k++; }
            }
            for (u32 k = 0; k < ns; k++) {
                bw_put(&p, bc[sy[k]], bl[sy[k]]);
                if (sy[k] == 16 || sy[k] == 18) bw_put(&p, sx[k], 3);
                else if (sy[k] == 17 || sy[k] == 19) bw_put(&p, sx[k], 7);
            }
            z->tabs = 1;
        }
        u32 cm[NC], cd[DC7], cl[LDC], cr[RC];
        const u8 *L = z->tl;
        huff_codes(L, NC, cm);
        huff_codes(L + NC, ndist, cd);
        huff_codes(L + NC + ndist, LDC, cl);
        huff_codes(L + NC + ndist + LDC, RC, cr);
#define PUT(c, l, s) bw_put(&p, (c)[s], (l)[s])
        for (size_t k = i; k < j; k++) {
            const tok *v = &t[k];
            u32 eb, ev, db;
            u64 dv;
            switch (v->kind) {
            case T_LIT: PUT(cm, L, v->len); break;
            case T_LAST: PUT(cm, L, 257); break;
            case T_FILT:
                PUT(cm, L, 256);
                filt_num(&p, v->fs);
                filt_num(&p, v->fl);
                bw_put(&p, v->ft, 3);
                if (v->ft == 0) bw_put(&p, v->fc - 1, 5);
                break;
            case T_REP: {
                PUT(cm, L, 258 + v->k);
                u32 s = len_slot(v->len, &eb, &ev);
                PUT(cr, L + NC + ndist + LDC, s);
                bw_put(&p, ev, (int)eb);
                break;
            }
            default: {
                u32 adj = (v->dist > 0x100) + (v->dist > 0x2000) + (v->dist > 0x40000);
                u32 s = len_slot(v->len - adj, &eb, &ev);
                PUT(cm, L, 262 + s);
                bw_put(&p, ev, (int)eb);
                u32 ds = dist_slot(v->dist, &db, &dv);
                PUT(cd, L + NC, ds);
                if (db < 4) bw_put(&p, (u32)dv, (int)db);
                else {
                    bw_put64(&p, dv >> 4, (int)db - 4);
                    PUT(cl, L + NC + ndist, (u32)(dv & 15));
                }
            }
            }
        }
#undef PUT
        u64 bits = p.bits;
        bw_align(&p);
        u32 size = (u32)p.b.n, last = (u32)(bits - (u64)(size ? size - 1 : 0) * 8);
        if (!size) last = 8;
        u32 nb = size < 0x100 ? 1 : size < 0x10000 ? 2 : 3;
        if (size >= 0x1000000) die("block too large");
        u8 flags = (u8)((last - 1) | ((nb - 1) << 3) | (j >= nt ? 0x40 : 0) | (use_old ? 0 : 0x80));
        u8 chk = (u8)(0x5A ^ flags ^ size ^ (size >> 8) ^ (size >> 16));
        bw_align(out);
        bw_put(out, flags, 8);
        bw_put(out, chk, 8);
        for (u32 k = 0; k < nb; k++) bw_put(out, (size >> (8 * k)) & 0xFF, 8);
        b_put(&out->b, p.b.p, p.b.n);
        free(p.b.p);
        i = j;
    } while (i < nt);
}

/* compress one file (z keeps the solid stream) */
static void compress_file(lzs *z, const opts *o, const u8 *d, u64 n, buf *out)
{
    u64 from = z->hn;
    if (z->hn + n > z->hcap) {
        z->hcap = (z->hn + n) * 2 + 4096;
        z->h = (u8 *)realloc(z->h, z->hcap);
    }
    memcpy(z->h + from, d, n);
    fspec fs[4096];
    int nf = plan_filters(o, z->h + from, n, fs, 4096);
    if (getenv("R5_DUMP"))
        for (int k = 0; k < nf; k++)
            fprintf(stderr, "filter %d: start %llu len %u type %u ch %u\n", k, (unsigned long long)fs[k].start,
                    fs[k].len, fs[k].type, fs[k].ch);
    z->hn += n;
    size_t nt;
    tok *t = lz_parse(z, from, fs, nf, &nt);
    bitw w;
    memset(&w, 0, sizeof w);
    lz_blocks(z, t, nt, o->blk, o->reuse, &w);
    bw_align(&w);
    b_put(out, w.b.p, w.b.n);
    free(w.b.p);
    free(t);
}

/* ---------------- archive writer ---------------- */

enum { E_FILE, E_DIR, E_LINK, E_HARD, E_COPY };
typedef struct { int kind; const char *name; const char *path; } item;

typedef struct {
    const opts *o;
    const char *pattern;
    FILE *f;
    u64 vsize;
    u32 vol;
    gz_aes hk;              /* header key (-hp) */
    u8 pwb[512];
    u32 pwn;
    u8 salt[16], hsalt[16];
    u8 key[32], hkey[32], check[8];
} arcw;

static void rand_bytes(u8 *p, size_t n) { for (size_t i = 0; i < n; i++) p[i] = (u8)rnd(); }

static void out_raw(arcw *w, const void *p, size_t n)
{
    if (n && fwrite(p, 1, n, w->f) != n) die("write failed");
    w->vsize += n;
}

static void put_header(arcw *w, u32 type, u32 flags, const buf *fields, const buf *extra, int has_data, u64 dlen)
{
    buf h = { 0 }, all = { 0 };
    b_vint(&h, type);
    b_vint(&h, flags | (extra && extra->n ? 1 : 0) | (has_data ? 2 : 0));
    if (extra && extra->n) b_vint(&h, extra->n);
    if (has_data) b_vint(&h, dlen);
    if (fields) b_put(&h, fields->p, fields->n);
    if (extra && extra->n) b_put(&h, extra->p, extra->n);
    buf sz = { 0 };
    b_vint(&sz, h.n);
    b_u32(&all, 0);
    b_put(&all, sz.p, sz.n);
    b_put(&all, h.p, h.n);
    wr32(all.p, gz_crc32(0, all.p + 4, all.n - 4));
    if (w->o->hp && type != 4) {
        u8 iv[16];
        rand_bytes(iv, 16);
        size_t pad = (16 - all.n % 16) % 16;
        u8 z[16] = { 0 };
        b_put(&all, z, pad);
        out_raw(w, iv, 16);
        gz_aes_cbc_encrypt(&w->hk, iv, all.p, all.n);
    }
    out_raw(w, all.p, all.n);
    free(h.p); free(all.p); free(sz.p);
}

static void vol_name(arcw *w, char *o, size_t cap)
{
    if (!w->o->vol) { snprintf(o, cap, "%s", w->pattern); return; }
    if (!w->o->vold) { snprintf(o, cap, w->pattern, (int)w->vol + 1); return; }
    snprintf(o, cap, "%s", w->pattern);
    if (w->vol) {
        size_t n = strlen(o);
        if (n < 4) die("bad volume name");
        snprintf(o + n - 3, cap - (n - 3), "%c%02u", 'r' + (w->vol - 1) / 100, (w->vol - 1) % 100);
    }
}

static void open_volume(arcw *w)
{
    char nm[4096];
    vol_name(w, nm, sizeof nm);
    w->f = fopen(nm, "wb");
    if (!w->f) die("cannot create output");
    w->vsize = 0;
    if (!w->vol && w->o->sfx) {
        u8 *stub = (u8 *)malloc(w->o->sfx);
        rand_bytes(stub, w->o->sfx);
        stub[0] = 'M'; stub[1] = 'Z';
        for (u64 i = 2; i + 4 < w->o->sfx; i += 97) memcpy(stub + i, "Rar!", 4);   /* decoys */
        out_raw(w, stub, w->o->sfx);
        free(stub);
    }
    static const u8 sig[8] = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 };
    out_raw(w, sig, 8);
    if (w->o->hp) {
        buf f = { 0 };
        b_vint(&f, 0);
        b_vint(&f, 1);
        b_u8(&f, (u8)w->o->lg2);
        rand_bytes(w->hsalt, 16);
        b_put(&f, w->hsalt, 16);
        u8 k[32], chk[8], h[32];
        gz_rar5_kdf(w->pwb, w->pwn, w->hsalt, 16, w->o->lg2, k, 0, chk);
        gz_sha256_calc(chk, 8, h);
        b_put(&f, chk, 8);
        b_put(&f, h, 4);
        put_header(w, 4, 0, &f, 0, 0, 0);
        gz_aes_set_encrypt_key(&w->hk, k, 32);
        free(f.p);
    }
    buf f = { 0 }, x = { 0 };
    u32 af = (w->o->vol ? 1 : 0) | (w->vol ? 2 : 0) | (w->o->solid ? 4 : 0);
    b_vint(&f, af);
    if (w->vol) b_vint(&f, w->vol);
    if (rnd() % 2) {      /* locator record without offsets */
        buf r = { 0 };
        b_vint(&r, 1);
        b_vint(&r, 0);
        b_vint(&x, r.n);
        b_put(&x, r.p, r.n);
        free(r.p);
    }
    put_header(w, 1, 0, &f, &x, 0, 0);
    free(f.p); free(x.p);
}

static void close_volume(arcw *w, int more)
{
    buf f = { 0 };
    b_vint(&f, more ? 1 : 0);
    put_header(w, 5, 0, &f, 0, 0, 0);
    free(f.p);
    fclose(w->f);
    w->f = 0;
}

static u32 mac_crc(const u8 *hkey, u32 crc)
{
    u8 raw[4], d[32];
    wr32(raw, crc);
    gz_hmac_sha256_calc(hkey, 32, raw, 4, d);
    u32 v = 0;
    for (int i = 0; i < 32; i++) v ^= (u32)d[i] << ((i & 3) * 8);
    return v;
}

typedef struct {
    u32 type;            /* 2 file, 3 service */
    const char *name;
    u32 fflags;          /* dir, mtime, crc, nosize */
    u64 usize;
    u64 attr;
    u32 comp;
    u32 host;
    u32 crc;             /* final checksum (MAC'd if needed) */
    u8 b2[32];
    int has_b2;
    int enc;
    u8 iv[16];
    int redir;           /* 0 or 1..5 */
    const char *target;
    const char *sub;     /* service data */
    u64 mtime;
} fhead;

static void file_fields(arcw *w, const fhead *fh, u32 crc, const u8 *b2, buf *f, buf *x)
{
    b_vint(f, fh->fflags);
    b_vint(f, fh->usize);
    b_vint(f, fh->attr);
    if (fh->fflags & 2) b_u32(f, (u32)fh->mtime);
    if (fh->fflags & 4) b_u32(f, crc);
    b_vint(f, fh->comp);
    b_vint(f, fh->host);
    b_vint(f, strlen(fh->name));
    b_put(f, fh->name, strlen(fh->name));
    buf r = { 0 };
    if (fh->enc) {
        b_vint(&r, 1);
        b_vint(&r, 0);
        b_vint(&r, 1 | (w->o->mac ? 2 : 0));
        b_u8(&r, (u8)w->o->lg2);
        b_put(&r, w->salt, 16);
        b_put(&r, fh->iv, 16);
        u8 h[32];
        gz_sha256_calc(w->check, 8, h);
        b_put(&r, w->check, 8);
        b_put(&r, h, 4);
        b_vint(x, r.n); b_put(x, r.p, r.n); r.n = 0;
    }
    if (b2) {
        b_vint(&r, 2);
        b_vint(&r, 0);
        b_put(&r, b2, 32);
        b_vint(x, r.n); b_put(x, r.p, r.n); r.n = 0;
    }
    if (fh->type == 2 && !(fh->fflags & 2)) {
        u32 kind = (u32)(rnd() % 3);
        b_vint(&r, 3);
        if (kind == 0) { b_vint(&r, 2); b_u64(&r, gz_unix_to_filetime((i64)fh->mtime) + 1234567); }
        else if (kind == 1) { b_vint(&r, 3 | 8); b_u32(&r, (u32)fh->mtime); b_u32(&r, (u32)fh->mtime + 5); }
        else { b_vint(&r, 3 | 0x10); b_u32(&r, (u32)fh->mtime); b_u32(&r, 123456789); }
        b_vint(x, r.n); b_put(x, r.p, r.n); r.n = 0;
    }
    if (fh->redir) {
        b_vint(&r, 5);
        b_vint(&r, (u64)fh->redir);
        b_vint(&r, 0);
        b_vint(&r, strlen(fh->target));
        b_put(&r, fh->target, strlen(fh->target));
        b_vint(x, r.n); b_put(x, r.p, r.n); r.n = 0;
    }
    if (fh->type == 2 && fh->host == 1 && rnd() % 2) {   /* unix owner record */
        b_vint(&r, 6);
        b_vint(&r, 1 | 2 | 4 | 8);
        b_vint(&r, 4); b_put(&r, "user", 4);
        b_vint(&r, 5); b_put(&r, "group", 5);
        b_vint(&r, 1000); b_vint(&r, 100);
        b_vint(x, r.n); b_put(x, r.p, r.n); r.n = 0;
    }
    if (fh->sub) {
        b_vint(&r, 7);
        b_put(&r, fh->sub, strlen(fh->sub));
        b_vint(x, r.n); b_put(x, r.p, r.n); r.n = 0;
    }
    free(r.p);
}

/* write a file header and its data, splitting it across volumes when needed */
static void write_entry(arcw *w, const fhead *fh, const u8 *data, u64 dlen, int has_data)
{
    u64 done = 0;
    int first = 1;
    do {
        u64 part = dlen - done;
        int split_after = 0;
        if (w->o->vol && has_data) {
            u64 room = w->vsize + 512 < w->o->vol ? w->o->vol - w->vsize - 512 : 0;
            if (room < 64) room = 64;
            if (part > room) { part = room; split_after = 1; }
        }
        u32 crc = fh->crc;
        u8 b2[32];
        const u8 *pb2 = fh->has_b2 ? fh->b2 : 0;
        if (split_after) {
            /* parts that continue: checksums of the packed part */
            crc = gz_crc32(0, data + done, part);
            if (fh->has_b2) { gz_blake2sp_calc(data + done, part, b2); pb2 = b2; }
        }
        buf f = { 0 }, x = { 0 };
        file_fields(w, fh, crc, pb2, &f, &x);
        u32 hf = (first ? 0 : 0x08) | (split_after ? 0x10 : 0);
        put_header(w, fh->type, hf, &f, &x, has_data, part);
        free(f.p); free(x.p);
        out_raw(w, data + done, part);
        done += part;
        first = 0;
        if (split_after) {
            close_volume(w, 1);
            w->vol++;
            open_volume(w);
        }
    } while (done < dlen);
}

static u8 *read_file(const char *p, u64 *n)
{
    FILE *f = fopen(p, "rb");
    if (!f) die("cannot read input");
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *d = (u8 *)malloc(sz > 0 ? (size_t)sz : 1);
    if (sz > 0 && fread(d, 1, (size_t)sz, f) != (size_t)sz) die("read failed");
    fclose(f);
    *n = (u64)(sz > 0 ? sz : 0);
    return d;
}

static void encrypt_data(arcw *w, buf *b, u8 iv[16])
{
    size_t pad = (16 - b->n % 16) % 16;
    u8 z[16];
    rand_bytes(z, 16);
    b_put(b, z, pad);
    gz_aes a;
    gz_aes_set_encrypt_key(&a, w->key, 32);
    u8 v[16];
    memcpy(v, iv, 16);
    gz_aes_cbc_encrypt(&a, v, b->p, b->n);
}

static int cmd_make(int argc, char **argv)
{
    opts o;
    memset(&o, 0, sizeof o);
    o.method = 3; o.dlog = 22; o.blk = 256u << 10; o.flen = 65536; o.lg2 = 15; o.host = 1; o.depth = 16;
    int i = 3;
    for (; i < argc && argv[i][0] == '-'; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : "";
        if (!strcmp(a, "-m")) { o.method = atoi(v); i++; }
        else if (!strcmp(a, "-d")) { o.dlog = atoi(v); i++; }
        else if (!strcmp(a, "-v7")) o.v7 = 1;
        else if (!strcmp(a, "-s")) o.solid = 1;
        else if (!strcmp(a, "-blk")) { o.blk = (u32)strtoul(v, 0, 0); i++; }
        else if (!strcmp(a, "-reuse")) o.reuse = 1;
        else if (!strcmp(a, "-f")) { o.filt = v; i++; }
        else if (!strcmp(a, "-flen")) { o.flen = (u32)strtoul(v, 0, 0); i++; }
        else if (!strcmp(a, "-p")) { o.pw = v; i++; }
        else if (!strcmp(a, "-hp")) o.hp = 1;
        else if (!strcmp(a, "-lg2")) { o.lg2 = (u32)atoi(v); i++; }
        else if (!strcmp(a, "-mac")) o.mac = 1;
        else if (!strcmp(a, "-b2")) o.b2 = 1;
        else if (!strcmp(a, "-both")) o.both = 1;
        else if (!strcmp(a, "-vol")) { o.vol = strtoull(v, 0, 0); i++; }
        else if (!strcmp(a, "-vold")) o.vold = 1;
        else if (!strcmp(a, "-sfx")) { o.sfx = strtoull(v, 0, 0); i++; }
        else if (!strcmp(a, "-cmt")) { o.cmt = v; i++; }
        else if (!strcmp(a, "-seed")) { g_rng = strtoull(v, 0, 0) * 2654435761u + 1; i++; }
        else if (!strcmp(a, "-host")) { o.host = atoi(v); i++; }
        else if (!strcmp(a, "-nosize")) o.nosize = 1;
        else if (!strcmp(a, "-depth")) { o.depth = atoi(v); i++; }
        else die("unknown option");
    }
    if (o.hp && !o.pw) die("-hp needs -p");
    arcw w;
    memset(&w, 0, sizeof w);
    w.o = &o;
    w.pattern = argv[2];
    if (o.pw) {
        gzch *pw = gz_posix_wide(o.pw);
        w.pwn = (u32)gz_utf16_to_utf8(pw, gz_wcslen(pw), w.pwb);
        free(pw);
        rand_bytes(w.salt, 16);
        gz_rar5_kdf(w.pwb, w.pwn, w.salt, 16, o.lg2, w.key, w.hkey, w.check);
    }
    open_volume(&w);
    if (o.cmt) {
        fhead fh;
        memset(&fh, 0, sizeof fh);
        fh.type = 3;
        fh.name = "CMT";
        fh.fflags = 4;
        fh.usize = strlen(o.cmt);
        fh.host = (u32)o.host;
        fh.crc = gz_crc32(0, o.cmt, strlen(o.cmt));
        buf d = { 0 };
        b_put(&d, o.cmt, strlen(o.cmt));
        if (o.hp) {
            fh.enc = 1;
            rand_bytes(fh.iv, 16);
            if (o.mac) fh.crc = mac_crc(w.hkey, fh.crc);
            encrypt_data(&w, &d, fh.iv);
        }
        write_entry(&w, &fh, d.p, d.n, 1);
        free(d.p);
    }
    lzs z;
    lz_init(&z, &o);
    int first_comp = 1;
    for (; i < argc; i++) {
        char *spec = argv[i];
        item it;
        memset(&it, 0, sizeof it);
        char *eq = strchr(spec, '=');
        if (!strncmp(spec, "L:", 2) || !strncmp(spec, "H:", 2) || !strncmp(spec, "C:", 2)) {
            it.kind = spec[0] == 'L' ? E_LINK : spec[0] == 'H' ? E_HARD : E_COPY;
            if (!eq) die("link needs =");
            *eq = 0;
            it.name = spec + 2;
            it.path = eq + 1;
        } else if (spec[strlen(spec) - 1] == '/') {
            it.kind = E_DIR;
            spec[strlen(spec) - 1] = 0;
            it.name = spec;
        } else {
            it.kind = E_FILE;
            if (eq) { *eq = 0; it.name = spec; it.path = eq + 1; }
            else it.name = it.path = spec;
        }
        fhead fh;
        memset(&fh, 0, sizeof fh);
        fh.type = 2;
        fh.name = it.name;
        fh.host = (u32)o.host;
        fh.mtime = 1700000000u + (u32)(rnd() % 100000000);
        if (rnd() % 4 == 0) fh.fflags |= 2;
        fh.comp = ((u32)(o.dlog - 17) & 31) << 10;
        if (o.v7) fh.comp |= 1;
        if (it.kind == E_DIR) {
            fh.fflags |= 1;
            fh.attr = o.host ? 040755 : 0x10;
            fh.comp = 0;
            write_entry(&w, &fh, 0, 0, 0);
            continue;
        }
        if (it.kind != E_FILE) {
            fh.redir = it.kind == E_LINK ? 1 : it.kind == E_HARD ? 4 : 5;
            fh.target = it.path;
            fh.attr = it.kind == E_LINK ? (o.host ? 0120777 : 0x20) : (o.host ? 0100644 : 0x20);
            fh.usize = it.kind == E_LINK ? strlen(it.path) : 0;
            fh.fflags |= 4;
            fh.comp &= ~(7u << 7);
            write_entry(&w, &fh, 0, 0, 1);
            continue;
        }
        u64 n;
        u8 *d = read_file(it.path, &n);
        fh.usize = n;
        fh.attr = o.host ? 0100644 : 0x20;
        u32 crc = gz_crc32(0, d, n);
        int use_crc = !o.b2 || o.both;
        if (o.b2 || o.both) { gz_blake2sp_calc(d, n, fh.b2); fh.has_b2 = 1; }
        buf pk = { 0 };
        if (o.method == 0 || n == 0) {
            b_put(&pk, d, n);
        } else {
            if (o.solid && !first_comp) fh.comp |= 0x40;
            fh.comp |= (u32)o.method << 7;
            compress_file(&z, &o, d, n, &pk);
            first_comp = 0;
            if (o.nosize) fh.fflags |= 8;
            if (!o.solid) {      /* new stream per file */
                free(z.h); free(z.head); free(z.prv);
                lz_init(&z, &o);
            }
        }
        if (use_crc) fh.fflags |= 4;
        fh.crc = crc;
        if (o.pw) {
            fh.enc = 1;
            rand_bytes(fh.iv, 16);
            if (o.mac) {
                fh.crc = mac_crc(w.hkey, crc);
                if (fh.has_b2) gz_hmac_sha256_calc(w.hkey, 32, fh.b2, 32, fh.b2);
            }
            encrypt_data(&w, &pk, fh.iv);
        }
        write_entry(&w, &fh, pk.p, pk.n, 1);
        free(pk.p);
        free(d);
    }
    close_volume(&w, 0);
    free(z.h); free(z.head); free(z.prv);
    printf("ok %u\n", w.vol + 1);
    return 0;
}

/* ---------------- bench / fuzz ---------------- */

typedef struct { gz_out o; u64 n; u64 lim; } cnt_out;
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
        r = gz_arc_extract_solid(a, src, sel, &co->o, c);
    } else {
        for (u32 k = 0; k < a->n; k++) {
            gz_arc_check_password(a, src, k, c);
            gz_arc_extract(a, src, k, &co->o, c);
        }
    }
    /* random access into solid runs too */
    if (a->n && a->solid) gz_arc_extract(a, src, (u32)(rnd() % a->n), &co->o, c);
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
}

static int cmd_bench(int argc, char **argv)
{
    if (argc > 4) { gzch *w = gz_posix_wide(argv[4]); memcpy(g_pw, w, (gz_wcslen(w) + 1) * 2); free(w); }
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
        else if (kind < 8) p[pos] = (u8)(0x80 | rnd());          /* long vints */
        else if (kind < 9 && pos + 4 <= len) wr32(p + pos, (u32)rnd() >> (rnd() % 32));
        else p[pos] = 0xFF;
    }
    if (rnd() % 8 == 0) *n = 1 + rnd() % len;
}

static int cmd_fuzz(int argc, char **argv)
{
    if (argc > 5) { gzch *w = gz_posix_wide(argv[5]); memcpy(g_pw, w, (gz_wcslen(w) + 1) * 2); free(w); }
    u64 n0;
    u8 *orig = read_file(argv[2], &n0);
    long iters = atol(argv[3]);
    g_rng = strtoull(argv[4], 0, 0) * 0x9E3779B97F4A7C15ull + 1;
    u8 *buf2 = (u8 *)malloc(n0 + 1);
    long opened = 0;
    for (long it = 0; it < iters; it++) {
        memcpy(buf2, orig, n0);
        size_t n = n0;
        mutate(buf2, &n);
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
    if (argc > 3) { gzch *w = gz_posix_wide(argv[3]); memcpy(g_pw, w, (gz_wcslen(w) + 1) * 2); free(w); }
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
        printf("%u %d %llu %08x %s\n", i, k.st[i] == 100 ? 0 : k.st[i], (unsigned long long)k.size[i], k.crc[i], nm);
        free(nm);
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
    fprintf(stderr, "usage: rar5_tool make|bench|fuzz|check ...\n");
    return 2;
}
