/*
 * LZX test tool (test driver, uses libc):
 *
 *   lzx_tool enc <in> <out.lzxf> <wbits> <e8size> <mode> <bsize> <seed> [reset_frames] [chain]
 *       Reference-style LZX encoder producing 32 KiB frames (CAB / CHM framing).
 *       mode: v verbatim, a aligned, u uncompressed, r random mix of the three.
 *       bsize: LZX block size (0 = random 1..98304). e8size: 0 = no E8 header bit.
 *       reset_frames: reset the stream every N frames (CHM), 0 = never.
 *       The output is verified by cabextract / 7-Zip through CAB files built from it.
 *   lzx_tool dec <in.lzxf> <out> <wbits> [cont|wim] [reset_frames]
 *       Decode with gz_lzx: per frame (CAB style), or "cont" as one continuous stream
 *       using in_used (CHM style), or "wim" (each frame an independent WIM chunk).
 *   lzx_tool fuzz <in.lzxf> <wbits> <iterations> <seed> [wim]
 *       Decode corrupted copies (bit flips, truncation, random bytes); must not crash.
 *   lzx_tool bench <in.lzxf> <wbits> <rounds> [wim]
 *       Decode speed in memory (MB/s of output).
 *
 * .lzxf container: "LZXF" u32 nframes, then per frame u32 csize, u32 usize, data.
 */
#include "lzx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

/* ======================= encoder ======================= */

static const u8 k_extra[50] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
    12, 12, 13, 13, 14, 14, 15, 15, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17
};
static u32 k_base[51];
static const u8 k_slots[7] = { 30, 32, 34, 36, 38, 42, 50 };

typedef struct { u8 *p; size_t n, cap; u64 acc; u32 nacc; } bw;
static void bw_byte(bw *w, u8 b)
{
    if (w->n == w->cap) { w->cap = w->cap ? w->cap * 2 : 65536; w->p = realloc(w->p, w->cap); }
    w->p[w->n++] = b;
}
static void bw_put(bw *w, u32 v, u32 n)
{
    if (!n) return;
    w->acc = (w->acc << n) | (v & ((n == 32) ? 0xffffffffu : ((1u << n) - 1)));
    w->nacc += n;
    while (w->nacc >= 16) {
        u32 x = (u32)(w->acc >> (w->nacc - 16)) & 0xffff;
        bw_byte(w, (u8)x);
        bw_byte(w, (u8)(x >> 8));
        w->nacc -= 16;
    }
}
static void bw_align(bw *w) { if (w->nacc) bw_put(w, 0, 16 - w->nacc); }

/* Huffman code lengths limited to maxbits (frequency scaling until it fits).
 * Fewer than two used symbols get a second one so the code stays complete. */
static void huff_lengths(const u32 *freq_in, u32 n, u32 maxbits, u8 *len, int allow_empty)
{
    u32 f[700];
    u32 used = 0, first = 0;
    for (u32 i = 0; i < n; i++) { f[i] = freq_in[i]; if (f[i]) { if (!used) first = i; used++; } len[i] = 0; }
    if (!used) {
        if (allow_empty) return;
        f[0] = 1; f[1] = 1; used = 2;
    } else if (used == 1) {
        f[first == 0 ? 1 : 0] = 1;
        used = 2;
    }
    for (;;) {
        /* heap-based Huffman */
        u32 m = 0;
        static u32 node_f[1400], parent[1400];
        static u32 heap[1400];
        u32 hn = 0;
        u32 sym_node[700];
        for (u32 i = 0; i < n; i++) {
            if (!f[i]) continue;
            node_f[m] = f[i];
            parent[m] = ~0u;
            sym_node[i] = m;
            /* push */
            u32 k = hn++;
            heap[k] = m;
            while (k && node_f[heap[(k - 1) / 2]] > node_f[heap[k]]) {
                u32 t = heap[k]; heap[k] = heap[(k - 1) / 2]; heap[(k - 1) / 2] = t; k = (k - 1) / 2;
            }
            m++;
        }
        while (hn > 1) {
            u32 a2[2];
            for (int t = 0; t < 2; t++) {
                a2[t] = heap[0];
                heap[0] = heap[--hn];
                u32 k = 0;
                for (;;) {
                    u32 l = 2 * k + 1, r = l + 1, s = k;
                    if (l < hn && node_f[heap[l]] < node_f[heap[s]]) s = l;
                    if (r < hn && node_f[heap[r]] < node_f[heap[s]]) s = r;
                    if (s == k) break;
                    u32 tt = heap[k]; heap[k] = heap[s]; heap[s] = tt; k = s;
                }
            }
            node_f[m] = node_f[a2[0]] + node_f[a2[1]];
            parent[m] = ~0u;
            parent[a2[0]] = parent[a2[1]] = m;
            u32 k = hn++;
            heap[k] = m;
            while (k && node_f[heap[(k - 1) / 2]] > node_f[heap[k]]) {
                u32 t = heap[k]; heap[k] = heap[(k - 1) / 2]; heap[(k - 1) / 2] = t; k = (k - 1) / 2;
            }
            m++;
        }
        u32 maxl = 0;
        for (u32 i = 0; i < n; i++) {
            if (!f[i]) { len[i] = 0; continue; }
            u32 d = 0;
            for (u32 x = sym_node[i]; parent[x] != ~0u; x = parent[x]) d++;
            len[i] = (u8)d;
            if (d > maxl) maxl = d;
        }
        if (maxl <= maxbits) return;
        for (u32 i = 0; i < n; i++) if (f[i]) f[i] = (f[i] >> 1) | 1;
    }
}

static void huff_codes(const u8 *len, u32 n, u32 *code)
{
    u32 count[17] = { 0 }, next[18];
    for (u32 i = 0; i < n; i++) count[len[i]]++;
    count[0] = 0;
    /* canonical: the first code of length 1 is 0 */
    u32 c = 0;
    for (u32 l = 1; l <= 16; l++) { next[l] = c; c = (c + count[l]) << 1; }
    for (u32 i = 0; i < n; i++) if (len[i]) code[i] = next[len[i]]++;
}

/* write tree lengths new[first..last) as deltas against prev[] using a pretree */
static void write_lens(bw *w, u8 *prev, const u8 *nw, u32 first, u32 last)
{
    /* collect pretree symbols */
    u32 syms[1400], extra[1400], nsym = 0;
    for (u32 x = first; x < last;) {
        if (nw[x] == 0) {
            u32 r = 0;
            while (x + r < last && nw[x + r] == 0 && r < 51) r++;
            if (r >= 20) { syms[nsym] = 18; extra[nsym++] = r - 20; x += r; continue; }
            if (r >= 4) { syms[nsym] = 17; extra[nsym++] = r - 4; x += r; continue; }
        } else {
            u32 r = 0;
            while (x + r < last && nw[x + r] == nw[x] && r < 5) r++;
            if (r >= 4 && (rnd() & 1)) {
                syms[nsym] = 19; extra[nsym++] = r - 4;
                syms[nsym] = (prev[x] + 17 - nw[x]) % 17; extra[nsym++] = 0;
                x += r;
                continue;
            }
        }
        syms[nsym] = (prev[x] + 17 - nw[x]) % 17;
        extra[nsym++] = 0;
        x++;
    }
    u32 pf[20] = { 0 };
    for (u32 i = 0; i < nsym; i++) pf[syms[i]]++;
    u8 pl[20];
    u32 pc[20];
    huff_lengths(pf, 20, 15, pl, 0);
    huff_codes(pl, 20, pc);
    for (u32 i = 0; i < 20; i++) bw_put(w, pl[i], 4);
    int after19 = 0;
    for (u32 i = 0; i < nsym; i++) {
        u32 s = syms[i];
        bw_put(w, pc[s], pl[s]);
        if (after19) { after19 = 0; continue; }
        if (s == 17) bw_put(w, extra[i], 4);
        else if (s == 18) bw_put(w, extra[i], 5);
        else if (s == 19) { bw_put(w, extra[i], 1); after19 = 1; }
    }
    for (u32 x = first; x < last; x++) prev[x] = nw[x];
}

typedef struct { u32 lit_or_len; u32 off; u8 is_match; } token;

typedef struct {
    const u8 *d; size_t n;
    u32 wsize, wbits, nslots;
    i32 *head, *prev;
    u32 chain;
} mf;

#define HBITS 16
static u32 hash3(const u8 *p) { return ((u32)(p[0] << 16 | p[1] << 8 | p[2]) * 2654435761u) >> (32 - HBITS); }

static void mf_insert(mf *m, size_t pos)
{
    if (pos + 3 > m->n) return;
    u32 h = hash3(m->d + pos);
    m->prev[pos] = m->head[h];
    m->head[h] = (i32)pos;
}

static u32 common(const u8 *a, const u8 *b, u32 lim)
{
    u32 l = 0;
    while (l < lim && a[l] == b[l]) l++;
    return l;
}

/* best match at pos: returns length (0 = none), *off = offset */
static u32 mf_find(mf *m, size_t pos, size_t minpos, u32 lim, const u32 *R, u32 *off)
{
    u32 best = 0, boff = 0;
    for (int r = 0; r < 3; r++) {
        if (R[r] > pos - minpos || R[r] > m->wsize - 3) continue;
        u32 l = common(m->d + pos, m->d + pos - R[r], lim);
        if (l >= 2 && l > best) { best = l; boff = R[r]; }
    }
    if (pos + 3 <= m->n) {
        i32 c = m->head[hash3(m->d + pos)];
        u32 depth = m->chain;
        while (c >= 0 && (size_t)c >= minpos && pos - (size_t)c <= m->wsize - 3 && depth--) {
            u32 l = common(m->d + pos, m->d + c, lim);
            if (l >= 3 && l > best + 1) { best = l; boff = (u32)(pos - c); }
            c = m->prev[c];
        }
    }
    *off = boff;
    return best;
}

static int enc_main(int argc, char **argv)
{
    if (argc < 9) return 2;
    size_t n;
    u8 *orig = read_file(argv[2], &n);
    const char *outp = argv[3];
    u32 wbits = (u32)atoi(argv[4]);
    u32 e8size = (u32)strtoul(argv[5], 0, 0);
    char mode = argv[6][0];
    u32 bsize_opt = (u32)atoi(argv[7]);
    g_rng = (u32)atoi(argv[8]) * 2654435761u + 1;
    u32 reset_frames = argc > 9 ? (u32)atoi(argv[9]) : 0;
    u32 chain = argc > 10 ? (u32)atoi(argv[10]) : 24;
    if (wbits < 15 || wbits > 21) return 2;
    for (u32 i = 0, j = 0; i < 51; i++) { k_base[i] = j; j += 1u << (i < 50 ? k_extra[i] : 17); }

    /* E8 preprocessing per frame (relative to the stream / reset start) */
    u8 *d = malloc(n + 16);
    memcpy(d, orig, n);
    if (e8size) {
        for (size_t fs = 0; fs < n; fs += 32768) {
            size_t fn = n - fs < 32768 ? n - fs : 32768;
            size_t rs = reset_frames ? (fs / 32768) / reset_frames * reset_frames * 32768 : 0;
            if (fs - rs >= (1u << 30) || fn <= 10) continue;
            for (size_t i = 0; i + 10 < fn;) {
                if (d[fs + i] != 0xE8) { i++; continue; }
                i32 cur = (i32)(fs - rs + i);
                i32 rel;
                memcpy(&rel, d + fs + i + 1, 4);
                if (rel >= -cur && rel < (i32)e8size) {
                    i32 a = rel < (i32)e8size - cur ? rel + cur : rel - (i32)e8size;
                    memcpy(d + fs + i + 1, &a, 4);
                }
                i += 5;
            }
        }
    }

    mf m;
    m.d = d; m.n = n; m.wsize = 1u << wbits; m.wbits = wbits; m.nslots = k_slots[wbits - 15];
    m.head = malloc(sizeof(i32) << HBITS);
    m.prev = malloc(sizeof(i32) * (n + 1));
    m.chain = chain;
    for (u32 i = 0; i < (1u << HBITS); i++) m.head[i] = -1;
    u32 main_syms = 256 + m.nslots * 8;

    bw w = { 0 };
    size_t nframes = (n + 32767) / 32768;
    size_t *fend = calloc(nframes + 1, sizeof(size_t));   /* compressed end of each frame */
    u8 prev_main[700] = { 0 }, prev_len[256] = { 0 };
    u32 R[3] = { 1, 1, 1 };
    size_t pos = 0, frame = 0, reset_start = 0;
    size_t tok_cap = (bsize_opt ? bsize_opt : 98304) + 1;
    token *tok = malloc(sizeof(token) * tok_cap);
    int need_header = 1;

    while (pos < n) {
        if (need_header) {
            if (e8size) { bw_put(&w, 1, 1); bw_put(&w, e8size >> 16, 16); bw_put(&w, e8size & 0xffff, 16); }
            else bw_put(&w, 0, 1);
            need_header = 0;
        }
        /* block range */
        u32 bsize = bsize_opt ? bsize_opt : 1 + rnd() % 98304;
        size_t bend = pos + bsize;
        if (bend > n) bend = n;
        if (reset_frames) {
            size_t rend = (pos / 32768 / reset_frames + 1) * reset_frames * 32768;
            if (bend > rend) bend = rend;
        }
        bsize = (u32)(bend - pos);
        int type = mode == 'v' ? 1 : mode == 'a' ? 2 : mode == 'u' ? 3 : 1 + (int)(rnd() % 3);
        if (mode == 'r' && type == 3 && (rnd() & 3)) type = 1 + (int)(rnd() & 1);   /* fewer stored blocks */
        bw_put(&w, (u32)type, 3);
        bw_put(&w, bsize >> 8, 16);
        bw_put(&w, bsize & 0xff, 8);

        if (type == 3) {
            if (w.nacc == 0) bw_put(&w, 0, 16); else bw_align(&w);
            for (int r = 0; r < 3; r++) for (int k = 0; k < 4; k++) bw_byte(&w, (u8)(R[r] >> (8 * k)));
            while (pos < bend) {
                size_t fe = (frame + 1) * 32768;
                size_t take = (bend < fe ? bend : fe) - pos;
                for (size_t k = 0; k < take; k++) { bw_byte(&w, d[pos + k]); mf_insert(&m, pos + k); }
                pos += take;
                if (pos == bend && (bsize & 1)) bw_byte(&w, 0);    /* pad stays with this frame */
                if (pos == fe || pos == n) { fend[frame++] = w.n; }
            }
            if (reset_frames && pos % (32768 * reset_frames) == 0 && pos < n) {
                need_header = 1; R[0] = R[1] = R[2] = 1;
                memset(prev_main, 0, sizeof prev_main); memset(prev_len, 0, sizeof prev_len);
                reset_start = pos;
            }
            continue;
        }

        /* tokens for the block (matches stay inside the block and the frame) */
        size_t nt = 0;
        u32 Rb[3] = { R[0], R[1], R[2] };
        size_t p = pos;
        while (p < bend) {
            size_t fe = (p / 32768 + 1) * 32768;
            size_t lim = bend < fe ? bend : fe;
            u32 maxl = lim - p < 257 ? (u32)(lim - p) : 257;
            u32 off = 0, l = maxl >= 2 ? mf_find(&m, p, reset_start, maxl, Rb, &off) : 0;
            if (l >= 2 && (off == Rb[0] || off == Rb[1] || off == Rb[2] || l >= 3)) {
                tok[nt].is_match = 1; tok[nt].lit_or_len = l; tok[nt].off = off; nt++;
                for (u32 k = 0; k < l; k++) mf_insert(&m, p + k);
                /* update the repeated offset queue like the decoder */
                if (off == Rb[0]) {}
                else if (off == Rb[1]) { Rb[1] = Rb[0]; Rb[0] = off; }
                else if (off == Rb[2]) { Rb[2] = Rb[0]; Rb[0] = off; }
                else { Rb[2] = Rb[1]; Rb[1] = Rb[0]; Rb[0] = off; }
                p += l;
            } else {
                tok[nt].is_match = 0; tok[nt].lit_or_len = d[p]; nt++;
                mf_insert(&m, p);
                p++;
            }
        }
        /* symbols */
        u32 mf_[700] = { 0 }, lf[256] = { 0 }, af[8] = { 0 };
        u32 Rq[3] = { R[0], R[1], R[2] };
        for (size_t t = 0; t < nt; t++) {
            if (!tok[t].is_match) { mf_[tok[t].lit_or_len]++; continue; }
            u32 l = tok[t].lit_or_len, off = tok[t].off, slot;
            if (off == Rq[0]) slot = 0;
            else if (off == Rq[1]) { slot = 1; Rq[1] = Rq[0]; Rq[0] = off; }
            else if (off == Rq[2]) { slot = 2; Rq[2] = Rq[0]; Rq[0] = off; }
            else {
                u32 fo = off + 2;
                slot = 3;
                while (k_base[slot + 1] <= fo) slot++;
                Rq[2] = Rq[1]; Rq[1] = Rq[0]; Rq[0] = off;
                if (type == 2 && k_extra[slot] >= 3) af[(fo - k_base[slot]) & 7]++;
            }
            u32 lh = l - 2 < 7 ? l - 2 : 7;
            mf_[256 + slot * 8 + lh]++;
            if (lh == 7) lf[l - 9]++;
            tok[t].off = slot << 24 | (off & 0xffffff);
        }
        u8 ml[700], ll[256], al[8];
        u32 mc[700], lc[256], ac[8];
        huff_lengths(mf_, main_syms, 16, ml, 0);
        huff_lengths(lf, 249, 16, ll, 1);
        if (type == 2) {
            huff_lengths(af, 8, 7, al, 0);
            huff_codes(al, 8, ac);
            for (int i = 0; i < 8; i++) bw_put(&w, al[i], 3);
        }
        huff_codes(ml, main_syms, mc);
        huff_codes(ll, 249, lc);
        write_lens(&w, prev_main, ml, 0, 256);
        write_lens(&w, prev_main, ml, 256, main_syms);
        write_lens(&w, prev_len, ll, 0, 249);
        /* emit */
        p = pos;
        for (size_t t = 0; t < nt; t++) {
            if (!tok[t].is_match) {
                bw_put(&w, mc[tok[t].lit_or_len], ml[tok[t].lit_or_len]);
                p++;
            } else {
                u32 l = tok[t].lit_or_len, slot = tok[t].off >> 24, off = tok[t].off & 0xffffff;
                u32 lh = l - 2 < 7 ? l - 2 : 7;
                u32 s = 256 + slot * 8 + lh;
                bw_put(&w, mc[s], ml[s]);
                if (lh == 7) bw_put(&w, lc[l - 9], ll[l - 9]);
                if (slot >= 3) {
                    u32 fo = off + 2, ex = k_extra[slot], v = fo - k_base[slot];
                    if (type == 2 && ex >= 3) {
                        bw_put(&w, v >> 3, ex - 3);
                        bw_put(&w, ac[v & 7], al[v & 7]);
                    } else bw_put(&w, v, ex);
                }
                p += l;
            }
            if (p % 32768 == 0 || p == n) {   /* frame end: realign */
                bw_align(&w);
                fend[frame++] = w.n;
            }
        }
        R[0] = Rq[0]; R[1] = Rq[1]; R[2] = Rq[2];
        pos = bend;
        if (reset_frames && pos % (32768 * reset_frames) == 0 && pos < n) {
            need_header = 1; R[0] = R[1] = R[2] = 1;
            memset(prev_main, 0, sizeof prev_main); memset(prev_len, 0, sizeof prev_len);
            reset_start = pos;
        }
    }
    bw_align(&w);
    if (frame != nframes) { fprintf(stderr, "frame count %zu != %zu\n", frame, nframes); return 1; }
    fend[nframes - 1] = w.n;
    FILE *f = fopen(outp, "wb");
    fwrite("LZXF", 1, 4, f);
    u32 nf = (u32)nframes;
    fwrite(&nf, 4, 1, f);
    size_t cs = 0;
    for (size_t i = 0; i < nframes; i++) {
        u32 c = (u32)(fend[i] - cs), u = (u32)((i + 1) * 32768 <= n ? 32768 : n - i * 32768);
        fwrite(&c, 4, 1, f);
        fwrite(&u, 4, 1, f);
        fwrite(w.p + cs, 1, c, f);
        cs = fend[i];
    }
    fclose(f);
    printf("frames=%zu in=%zu out=%zu\n", nframes, n, w.n);
    free(orig); free(d); free(m.head); free(m.prev); free(fend); free(tok); free(w.p);
    return 0;
}

/* ======================= decoder test ======================= */

typedef struct { u32 n; u32 *cs, *us; size_t *off; u8 *buf; size_t len; } frames;

static void load_frames(const char *p, frames *f)
{
    f->buf = read_file(p, &f->len);
    if (f->len < 8 || memcmp(f->buf, "LZXF", 4)) { fprintf(stderr, "bad lzxf\n"); exit(2); }
    memcpy(&f->n, f->buf + 4, 4);
    f->cs = calloc(f->n + 1, 4); f->us = calloc(f->n + 1, 4); f->off = calloc(f->n + 1, sizeof(size_t));
    size_t o = 8;
    for (u32 i = 0; i < f->n; i++) {
        memcpy(&f->cs[i], f->buf + o, 4);
        memcpy(&f->us[i], f->buf + o + 4, 4);
        f->off[i] = o + 8;
        o += 8 + f->cs[i];
        if (o > f->len) { fprintf(stderr, "truncated lzxf\n"); exit(2); }
    }
}

/* returns 0 ok, else error code; writes output to fo when given */
static int decode_all(gz_lzx_dec *d, frames *f, const u8 *data, int mode, u32 reset_frames, FILE *fo, u8 *cont, size_t cont_n)
{
    static u8 out[1 << 21];
    gz_lzx_reset(d);
    size_t cpos = 0;
    for (u32 i = 0; i < f->n; i++) {
        int r;
        if (mode == 2) {
            if (f->us[i] > sizeof out) return GZ_E_LIMIT;
            if (f->cs[i] == f->us[i]) { memcpy(out, data + f->off[i], f->us[i]); r = 0; }   /* stored chunk */
            else r = gz_lzx_decode_chunk(d, data + f->off[i], f->cs[i], out, f->us[i]);
        } else if (mode == 1) {
            if (reset_frames && i && i % reset_frames == 0) {
                /* like a CHM reset table: reset frames start at a known offset */
                gz_lzx_reset(d);
                cpos = f->off[i] - f->off[0] - 8 * i;
            }
            u32 used = 0;
            r = gz_lzx_decode_frame(d, cont + cpos, (u32)(cont_n - cpos), &used, out, f->us[i]);
            /* an odd stored block's pad byte may be left for the next frame */
            if (!r && used != f->cs[i] && used + 1 != f->cs[i]) {
                fprintf(stderr, "frame %u: used %u, expected %u\n", i, used, f->cs[i]);
                return 99;
            }
            cpos += used;
        } else {
            if (reset_frames && i && i % reset_frames == 0) gz_lzx_reset(d);
            r = gz_lzx_decode_frame(d, data + f->off[i], f->cs[i], 0, out, f->us[i]);
        }
        if (r) return r;
        if (fo) fwrite(out, 1, f->us[i], fo);
    }
    return 0;
}

static int dec_main(int argc, char **argv)
{
    if (argc < 5) return 2;
    frames f;
    load_frames(argv[2], &f);
    u32 wbits = (u32)atoi(argv[4]);
    int mode = argc > 5 ? (!strcmp(argv[5], "cont") ? 1 : !strcmp(argv[5], "wim") ? 2 : 0) : 0;
    u32 reset_frames = argc > 6 ? (u32)atoi(argv[6]) : 0;
    gz_lzx_dec *d = gz_lzx_new(wbits, mode == 2 ? GZ_LZX_WIM : 0);
    if (!d) { fprintf(stderr, "new failed\n"); return 1; }
    u8 *cont = 0;
    size_t cn = 0;
    if (mode == 1) {
        for (u32 i = 0; i < f.n; i++) cn += f.cs[i];
        cont = malloc(cn + 1);
        size_t o = 0;
        for (u32 i = 0; i < f.n; i++) { memcpy(cont + o, f.buf + f.off[i], f.cs[i]); o += f.cs[i]; }
    }
    FILE *fo = fopen(argv[3], "wb");
    int r = decode_all(d, &f, f.buf, mode, reset_frames, fo, cont, cn);
    fclose(fo);
    gz_lzx_free(d);
    printf("DEC %d\n", r);
    free(cont); free(f.buf); free(f.cs); free(f.us); free(f.off);
    return r ? 1 : 0;
}

static int bench_main(int argc, char **argv)
{
    if (argc < 5) return 2;
    frames f;
    load_frames(argv[2], &f);
    u32 wbits = (u32)atoi(argv[3]);
    int rounds = atoi(argv[4]);
    int wim = argc > 5 && !strcmp(argv[5], "wim");
    gz_lzx_dec *d = gz_lzx_new(wbits, wim ? GZ_LZX_WIM : 0);
    u64 total = 0;
    for (u32 i = 0; i < f.n; i++) total += f.us[i];
    struct timespec t0, t1;
    double best = 1e9;
    for (int k = 0; k < rounds; k++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int r = decode_all(d, &f, f.buf, wim ? 2 : 0, 0, 0, 0, 0);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (r) { printf("BENCH error %d\n", r); return 1; }
        double dt = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) * 1e-9;
        if (dt < best) best = dt;
    }
    printf("BENCH %.1f MB/s (%llu bytes, best of %d: %.3f s)\n", (double)total / best / 1e6,
           (unsigned long long)total, rounds, best);
    gz_lzx_free(d);
    free(f.buf); free(f.cs); free(f.us); free(f.off);
    return 0;
}

static int fuzz_main(int argc, char **argv)
{
    if (argc < 6) return 2;
    frames f;
    load_frames(argv[2], &f);
    u32 wbits = (u32)atoi(argv[3]);
    int iters = atoi(argv[4]);
    g_rng = (u32)atoi(argv[5]) * 2654435761u + 7;
    int wim = argc > 6 && !strcmp(argv[6], "wim");
    gz_lzx_dec *d = gz_lzx_new(wbits, wim ? GZ_LZX_WIM : 0);
    u8 *data = malloc(f.len + 64);
    int errs = 0;
    for (int it = 0; it < iters; it++) {
        memcpy(data, f.buf, f.len);
        int kind = (int)(rnd() % 4);
        if (kind == 0) {              /* bit flips */
            int k = 1 + (int)(rnd() % 8);
            while (k--) { size_t o = 8 + rnd() % (f.len - 8); data[o] ^= (u8)(1u << (rnd() & 7)); }
        } else if (kind == 1) {       /* random bytes in one frame */
            u32 i = rnd() % f.n;
            for (u32 k = 0; k < f.cs[i] && k < 64; k++) data[f.off[i] + (rnd() % (f.cs[i] ? f.cs[i] : 1))] = (u8)rnd();
        } else if (kind == 2) {       /* everything random after a point */
            size_t o = 8 + rnd() % (f.len - 8);
            for (size_t k = o; k < f.len; k++) data[k] = (u8)rnd();
        } else {                      /* truncated frames */
            u32 i = rnd() % f.n;
            u32 save = f.cs[i];
            f.cs[i] = save ? rnd() % save : 0;
            errs += decode_all(d, &f, data, wim ? 2 : 0, 0, 0, 0, 0) != 0;
            f.cs[i] = save;
            continue;
        }
        errs += decode_all(d, &f, data, wim ? 2 : 0, 0, 0, 0, 0) != 0;
    }
    gz_lzx_free(d);
    printf("FUZZ %d iterations, %d rejected\n", iters, errs);
    free(data); free(f.buf); free(f.cs); free(f.us); free(f.off);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "enc")) return enc_main(argc, argv);
    if (!strcmp(argv[1], "dec")) return dec_main(argc, argv);
    if (!strcmp(argv[1], "fuzz")) return fuzz_main(argc, argv);
    if (!strcmp(argv[1], "bench")) return bench_main(argc, argv);
    return 2;
}
