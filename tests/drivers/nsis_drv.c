/*
 * nsis_drv - NSIS reader / NSIS Deflate test driver
 *
 *   nsis_drv list <archive>
 *       idx <TAB> name <TAB> usize <TAB> csize <TAB> method <TAB> filetime <TAB> attr
 *       (usize/csize -1 = unknown, filetime 0 = none)
 *   nsis_drv inflate <in> <out> <nsis>
 *       decode a raw Deflate stream (nsis 1: stored blocks without NLEN) into <out>;
 *       prints "ok <bytes>" or "err <code>"
 *   nsis_drv subsets <archive>
 *       CRC of every entry from a full pass ("C <TAB> idx <TAB> crc" lines), then from
 *       single-entry extraction and from extract_solid with several selections (incl.
 *       skipped and cancelled entries): all must agree; prints "ok <entries>"
 *   nsis_drv fuzz <archive> <iterations> <seed>
 *       mutation fuzzer (bit flips, smashed 32-bit fields, truncation) over open +
 *       extraction (solid pass, single entries); prints "ok <iterations> opened=<n>"
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "inflate.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static u8 *load(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    *n = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *p = (u8 *)malloc(*n + 1);
    if (fread(p, 1, *n, f) != *n) exit(2);
    fclose(f);
    return p;
}

static gz_archive *open_mem(gz_src *s, gz_ctx *c, int *err)
{
    gz_archive *a = 0;
    gz_open_opts o;
    memset(&o, 0, sizeof o);
    *err = gz_arc_open(&a, s, &o, c);
    return *err ? 0 : a;
}

/* ---- list ---- */

static int cmd_list(const char *path)
{
    size_t n;
    u8 *buf = load(path, &n);
    gz_src *s = gz_src_mem(buf, n, 1);
    gz_ctx *c = gz_ctx_new();
    int err;
    gz_archive *a = open_mem(s, c, &err);
    if (!a) { printf("OPEN_ERROR %d\n", err); return 1; }
    printf("TYPE\t%s\t%d\n", gz_arc_type_name(a), a->solid);
    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[i];
        char m[128];
        gzch mw[96];
        size_t wl = gz_wcslen(e->name);
        char *nm = (char *)malloc(wl * 3 + 1);
        int k = gz_utf16_to_utf8(e->name, wl, (u8 *)nm);
        nm[k] = 0;
        gz_arc_method(a, e, mw, 96);
        k = gz_utf16_to_utf8(mw, gz_wcslen(mw), (u8 *)m);
        m[k] = 0;
        printf("%u\t%s\t%lld\t%lld\t%s\t%llu\t%u\n", i, nm,
               e->usize == GZ_SIZE_UNKNOWN ? -1LL : (long long)e->usize,
               e->csize == GZ_SIZE_UNKNOWN ? -1LL : (long long)e->csize, m,
               e->mtime_kind == GZ_MT_FILETIME ? (unsigned long long)e->mtime : 0ULL, e->attr);
        free(nm);
    }
    gz_arc_close(a);
    gz_ctx_free(c);
    gz_src_free(s);
    return 0;
}

/* ---- inflate ---- */

typedef struct { const u8 *p; size_t n, pos; FILE *out; u64 total; } mem_io;
static int mi_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    mem_io *m = (mem_io *)ctx;
    /* odd chunk sizes to move refill boundaries around */
    size_t k = m->n - m->pos;
    if (k > cap) k = cap;
    if (k > 70001) k = 70001;
    memcpy(buf, m->p + m->pos, k);
    m->pos += k;
    *got = (u32)k;
    return 0;
}
static int mi_write(void *ctx, const u8 *p, size_t n)
{
    mem_io *m = (mem_io *)ctx;
    m->total += n;
    return fwrite(p, 1, n, m->out) == n ? 0 : GZ_E_IO;
}

static int cmd_inflate(const char *in, const char *out, int nsis)
{
    size_t n;
    u8 *buf = load(in, &n);
    mem_io m = { buf, n, 0, fopen(out, "wb"), 0 };
    if (!m.out) return 2;
    gz_inflater *z = gz_inflater_new();
    gz_stream_io io = { mi_read, mi_write, &m };
    int r = nsis ? gz_inflate_run_nsis(z, &io) : gz_inflate_run(z, &io, 0);
    fclose(m.out);
    if (r) printf("err %d\n", r); else printf("ok %llu\n", (unsigned long long)m.total);
    /* a following standard run must not inherit the NSIS flag */
    if (nsis && !r) {
        static const u8 stored[] = { 0x01, 0x01, 0x00, 0xFE, 0xFF, 'x' };
        mem_io m2 = { stored, sizeof stored, 0, fopen("/dev/null", "wb"), 0 };
        gz_stream_io io2 = { mi_read, mi_write, &m2 };
        int r2 = gz_inflate_run(z, &io2, 0);
        fclose(m2.out);
        if (r2 || m2.total != 1) { printf("stale nsis flag %d\n", r2); r = 1; }
    }
    gz_inflater_free(z);
    free(buf);
    return r ? 1 : 0;
}

/* ---- subsets ---- */

typedef struct { gz_out o; u32 *crc; int *st; u32 cur; u64 n; int skip_mod, cancel_at; u32 opened; } crc_out;
static int k_open(gz_out *o, u32 idx)
{
    crc_out *k = (crc_out *)o;
    if (k->skip_mod && idx % k->skip_mod == 1) return GZ_E_SKIP;
    k->opened++;
    if (k->cancel_at && k->opened == (u32)k->cancel_at) return GZ_E_CANCEL;
    k->cur = idx;
    k->crc[idx] = 0;
    return 0;
}
static int k_write(gz_out *o, const u8 *p, size_t n)
{
    crc_out *k = (crc_out *)o;
    k->crc[k->cur] = gz_crc32(k->crc[k->cur], p, n);
    k->n += n;
    return 0;
}
static int k_close(gz_out *o, u32 idx, int st)
{
    crc_out *k = (crc_out *)o;
    if (k->st) k->st[idx] = st ? st : 100;
    return 0;
}

static int cmd_subsets(const char *path)
{
    size_t n;
    u8 *buf = load(path, &n);
    gz_src *s = gz_src_mem(buf, n, 1);
    gz_ctx *c = gz_ctx_new();
    int err;
    gz_archive *a = open_mem(s, c, &err);
    if (!a) { printf("OPEN_ERROR %d\n", err); return 1; }
    u32 *ref = (u32 *)calloc(a->n + 1, 4), *crc = (u32 *)calloc(a->n + 1, 4);
    int *st = (int *)calloc(a->n + 1, sizeof(int));
    u8 *sel = (u8 *)calloc(a->n + 1, 1);
    int bad = 0;
    crc_out k = { { k_open, k_write, k_close, 0 }, ref, st, 0, 0, 0, 0, 0 };
    memset(sel, 1, a->n);
    int r = gz_arc_extract_solid(a, s, sel, &k.o, c);
    for (u32 i = 0; i < a->n; i++) {
        if (st[i] != 100) { printf("full pass: entry %u status %d (r=%d)\n", i, st[i], r); bad++; }
        printf("C\t%u\t%08x\n", i, ref[i]);
    }
    /* single entries, in reverse order */
    for (u32 i = a->n; i-- > 0;) {
        crc_out k1 = { { k_open, k_write, k_close, 0 }, crc, 0, 0, 0, 0, 0, 0 };
        r = gz_arc_extract(a, s, i, &k1.o, c);
        if (r || crc[i] != ref[i]) { printf("single %u: r=%d crc %08x/%08x\n", i, r, crc[i], ref[i]); bad++; }
    }
    /* selections: every 2nd / 3rd entry, last entry only, with skipped entries */
    for (int mode = 0; mode < 4; mode++) {
        memset(st, 0, (a->n + 1) * sizeof(int));
        for (u32 i = 0; i < a->n; i++) sel[i] = mode == 0 ? i % 2 == 0 : mode == 1 ? i % 3 == 1 : mode == 2 ? i + 1 == a->n : 1;
        crc_out k2 = { { k_open, k_write, k_close, 0 }, crc, st, 0, 0, mode == 3 ? 3 : 0, 0, 0 };
        r = gz_arc_extract_solid(a, s, sel, &k2.o, c);
        if (r) { printf("selection %d: r=%d\n", mode, r); bad++; }
        for (u32 i = 0; i < a->n; i++) {
            int skipped = mode == 3 && i % 3 == 1;
            if (!sel[i] || skipped) {
                if (st[i]) { printf("selection %d: entry %u not selected but closed\n", mode, i); bad++; }
                continue;
            }
            if (st[i] != 100 || crc[i] != ref[i]) { printf("selection %d: entry %u st=%d\n", mode, i, st[i]); bad++; }
        }
    }
    /* cancel from open(): returned unchanged */
    if (a->n > 2) {
        memset(sel, 1, a->n);
        crc_out k3 = { { k_open, k_write, k_close, 0 }, crc, 0, 0, 0, 0, 2, 0 };
        r = gz_arc_extract_solid(a, s, sel, &k3.o, c);
        if (r != GZ_E_CANCEL) { printf("cancel: r=%d\n", r); bad++; }
    }
    printf("%s %u\n", bad ? "BAD" : "ok", a->n);
    gz_arc_close(a);
    gz_ctx_free(c);
    gz_src_free(s);
    free(ref); free(crc); free(st); free(sel);
    return bad ? 1 : 0;
}

/* ---- fuzz ---- */

static u64 g_rng;
static u64 rnd(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return g_rng;
}

typedef struct { gz_out o; u64 n; } cap_out;
static int c_open(gz_out *o, u32 idx) { (void)idx; ((cap_out *)o)->n = 0; return 0; }
static int c_write(gz_out *o, const u8 *p, size_t n)
{
    cap_out *c = (cap_out *)o;
    volatile u8 sink = 0;
    for (size_t i = 0; i < n; i += 4096) sink ^= p[i];
    (void)sink;
    c->n += n;
    return c->n > (8u << 20) ? GZ_E_DISK : GZ_OK;
}
static int c_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; (void)st; return 0; }

/* NSIS headers are found at 512-byte boundaries: mutate near them more often */
static void mutate(u8 *p, size_t *n, size_t fh)
{
    size_t len = *n;
    if (!len) return;
    int kind = (int)(rnd() % 10);
    int count = 1 + (int)(rnd() % 6);
    for (int k = 0; k < count; k++) {
        size_t pos;
        u64 r = rnd() % 4;
        if (r < 2 && fh < len) pos = fh + rnd() % (len - fh < 8192 ? len - fh : 8192);   /* firstheader, header */
        else pos = rnd() % len;
        if (kind < 5) p[pos] ^= (u8)(1u << (rnd() % 8));
        else if (kind < 8) {
            static const u32 special[] = { 0, 1, 2, 0xFFFFFFFFu, 0x7FFFFFFFu, 0x80000000u, 0x80000004u, 0x10000, 28, 0xFFFFu };
            u32 v = (rnd() & 1) ? special[rnd() % 10] : (u32)(rnd() % (2 * (u64)len + 1));
            pos &= ~(size_t)3;
            if (pos + 4 <= len) memcpy(p + pos, &v, 4);
        } else {
            p[pos] = (u8)rnd();
        }
    }
    if (rnd() % 8 == 0) *n = fh + rnd() % (len - fh + 1);
}

static int cmd_fuzz(const char *path, int iters, u64 seed)
{
    size_t n;
    u8 *orig = load(path, &n);
    size_t fh = 0;
    for (size_t o = 0; o + 20 <= n; o += 512)
        if (!memcmp(orig + o + 4, "\xEF\xBE\xAD\xDENullsoftInst", 16)) { fh = o; break; }
    g_rng = seed * 0x9E3779B97F4A7C15ull + 1;
    u8 *buf = (u8 *)malloc(n + 1);
    int opened = 0;
    for (int it = 0; it < iters; it++) {
        size_t len = n;
        memcpy(buf, orig, n);
        if (it) mutate(buf, &len, fh);
        gz_src *s = gz_src_mem(buf, len, 0);
        gz_ctx *c = gz_ctx_new();
        int err;
        gz_archive *a = open_mem(s, c, &err);
        if (a) {
            opened++;
            cap_out co = { { c_open, c_write, c_close, 0 }, 0 };
            if (a->solid && a->n) {
                u8 *sel = (u8 *)calloc(a->n, 1);
                memset(sel, 1, a->n);
                gz_arc_extract_solid(a, s, sel, &co.o, c);
                free(sel);
                gz_arc_extract(a, s, (u32)(rnd() % a->n), &co.o, c);
            } else {
                for (u32 i = 0; i < a->n && i < 64; i++) gz_arc_extract(a, s, i, &co.o, c);
            }
            for (u32 i = 0; i < a->n && i < 64; i++) {
                gz_src *v = gz_arc_view(a, s, i, c);
                if (!v) continue;
                u8 tmp[4096];
                u32 got = 0;
                if (v->size) v->read_at(v, rnd() % v->size, tmp, sizeof tmp, &got);
                gz_src_free(v);
            }
            gz_arc_close(a);
        }
        gz_ctx_free(c);
        gz_src_free(s);
    }
    printf("ok %d opened=%d\n", iters, opened);
    free(buf);
    free(orig);
    return 0;
}

int main(int argc, char **argv)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
    if (argc == 3 && !strcmp(argv[1], "list")) return cmd_list(argv[2]);
    if (argc == 5 && !strcmp(argv[1], "inflate")) return cmd_inflate(argv[2], argv[3], atoi(argv[4]));
    if (argc == 3 && !strcmp(argv[1], "subsets")) return cmd_subsets(argv[2]);
    if (argc == 5 && !strcmp(argv[1], "fuzz")) return cmd_fuzz(argv[2], atoi(argv[3]), strtoull(argv[4], 0, 10));
    fprintf(stderr, "usage: nsis_drv list|inflate|subsets|fuzz ...\n");
    return 2;
}
