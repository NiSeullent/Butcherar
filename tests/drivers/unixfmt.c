/*
 * unixfmt - test driver for the CPIO / AR / RPM / XAR / pbzx / split readers
 *
 *   unixfmt dump <file>                 TYPE line, then one line per entry:
 *        idx <TAB> kind <TAB> mode <TAB> mtime <TAB> usize <TAB> name [<TAB> link]
 *        kind: d directory, f file, l symlink, h hard link; mtime: unix time or "-"
 *        (stderr: comment)
 *   unixfmt fuzz <file> <iterations> <seed>
 *        mutate a copy (bit flips, digits, smashed words, truncation), open it from
 *        memory, extract everything (solid pass when a->solid), read random ranges
 *        through the entry views. Must not crash, hang or leak. "ok N opened=M"
 *   unixfmt many <file>...              open + extract every file given (hostile sets)
 *   unixfmt threads <file>              4 threads extract every entry at once: the
 *        CRCs must match a single-threaded pass
 *   unixfmt bench <file> <rounds>       list + extract everything, prints MB/s
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

static u64 g_rng;
static u64 rnd(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return g_rng;
}

static void init_core(void)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
}

static void u8name(const gzch *w, char *o, size_t cap)
{
    size_t n = gz_wcslen(w);
    if (n * 3 + 1 > cap) n = (cap - 1) / 3;
    o[gz_utf16_to_utf8(w, n, (u8 *)o)] = 0;
}

static void opts(gz_open_opts *o, gzch *wname)
{
    memset(o, 0, sizeof *o);
    o->file_name = wname;
    o->open_volume = gz_posix_open_volume;
    if (getenv("GZ_NO_DESCEND")) o->flags |= GZ_OPEN_NO_DESCEND;
}

/* ---- capped / CRC sinks ---- */

typedef struct { gz_out o; u64 n; u32 crc; u32 *crcs; u32 nc; } cap_out;
static int c_open(gz_out *o, u32 idx) { cap_out *c = (cap_out *)o; (void)idx; c->n = 0; c->crc = 0; return 0; }
static int c_write(gz_out *o, const u8 *p, size_t n)
{
    cap_out *c = (cap_out *)o;
    c->crc = gz_crc32(c->crc, p, n);
    c->n += n;
    return c->n > (8u << 20) ? GZ_E_CANCEL : GZ_OK;
}
static int c_close(gz_out *o, u32 idx, int st)
{
    cap_out *c = (cap_out *)o;
    if (c->crcs && idx < c->nc) c->crcs[idx] = st ? 0xDEAD0000u | (u32)st : c->crc;
    return 0;
}

static void extract_all(gz_archive *a, gz_src *s, gz_ctx *c, u32 *crcs)
{
    cap_out co = { { c_open, c_write, c_close, 0 }, 0, 0, crcs, a->n };
    if (a->solid) {
        u8 *sel = (u8 *)calloc(1, a->n + 1);
        memset(sel, 1, a->n);
        gz_arc_extract_solid(a, s, sel, &co.o, c);
        /* and one entry alone (decodes up to it) */
        if (a->n) {
            memset(sel, 0, a->n);
            sel[rnd() % a->n] = 1;
            co.crcs = 0;
            gz_arc_extract_solid(a, s, sel, &co.o, c);
        }
        free(sel);
        return;
    }
    for (u32 i = 0; i < a->n && i < 256; i++) gz_arc_extract(a, s, i, &co.o, c);
}

static int poke_views(gz_archive *a, gz_src *s, gz_ctx *c)
{
    static u8 tmp[70000];
    for (u32 i = 0; i < a->n && i < 64; i++) {
        gz_src *v = gz_arc_view(a, s, i, c);
        if (!v) continue;
        for (int k = 0; k < 8 && v->size; k++) {
            u64 off = rnd() % v->size;
            u32 want = (u32)(rnd() % sizeof tmp), got = 0;
            v->read_at(v, off, tmp, want, &got);
            if (got > want) { fprintf(stderr, "read_at overrun\n"); return 3; }
        }
        gz_src_free(v);
    }
    return 0;
}

/* ---- dump ---- */

static int cmd_dump(const char *path)
{
    gz_src *s = gz_posix_open_src(path);
    if (!s) { perror(path); return 2; }
    gzch *wname = gz_posix_wide(path);
    gz_open_opts o;
    opts(&o, wname);
    gz_ctx *c = gz_ctx_new();
    gz_archive *a;
    int r = gz_arc_open(&a, s, &o, c);
    if (r) { printf("OPEN_ERROR %d\n", r); return 1; }
    printf("TYPE\t%s\t%u\t%d\n", gz_arc_type_name(a), a->n, a->solid);
    static char nm[65536 * 3], lk[65536];
    for (u32 i = 0; i < a->n; i++) {
        const gz_entry *e = &a->e[i];
        u8name(e->name, nm, sizeof nm);
        char kind = e->is_dir ? 'd' : e->is_link == 1 ? 'l' : e->is_link == 2 ? 'h' : 'f';
        char mt[32] = "-";
        if (e->mtime_kind == GZ_MT_FILETIME) snprintf(mt, sizeof mt, "%lld", (long long)gz_filetime_to_unix(e->mtime));
        long long us = e->usize == GZ_SIZE_UNKNOWN ? -1 : (long long)e->usize;
        printf("%u\t%c\t%o\t%s\t%lld\t%s", i, kind, e->unix_mode, mt, us, nm);
        if (e->is_link && e->link_len) {
            u32 n = e->link_len < sizeof lk - 1 ? e->link_len : (u32)sizeof lk - 1;
            memcpy(lk, a->raw + e->link_off, n);
            lk[n] = 0;
            printf("\t%s", lk);
        }
        printf("\n");
    }
    if (a->comment) { u8name(a->comment, nm, sizeof nm); fprintf(stderr, "comment: %s\n", nm); }
    gz_arc_close(a);
    gz_ctx_free(c);
    gz_src_free(s);
    free(wname);
    return 0;
}

/* ---- fuzz ---- */

static void mutate(u8 *p, size_t *n)
{
    size_t len = *n;
    if (!len) return;
    int kind = (int)(rnd() % 12), count = 1 + (int)(rnd() % 6);
    for (int k = 0; k < count; k++) {
        size_t pos;
        u64 r = rnd() % 4;
        if (r == 0) pos = rnd() % (len < 512 ? len : 512);                       /* headers */
        else if (r == 1) pos = len - 1 - rnd() % (len < 4096 ? len : 4096);
        else pos = rnd() % len;
        if (kind < 4) p[pos] ^= (u8)(1u << (rnd() % 8));
        else if (kind < 7) p[pos] = (u8)"0123456789abcdef 7/\n\0"[rnd() % 21];      /* text fields */
        else if (kind < 10) {
            static const u64 special[] = { 0, 1, 0xFFFFFFFFu, 0x7FFFFFFFu, 0x80000000u, ~(u64)0, 0x200, 0x10000 };
            u64 v = (rnd() & 1) ? special[rnd() % 8] : rnd() % (2 * (u64)len + 1);
            size_t w = (rnd() & 1) ? 8 : 4;
            if (rnd() & 1) v = w == 8 ? __builtin_bswap64(v) : __builtin_bswap32((u32)v);
            if (pos + w <= len) memcpy(p + pos, &v, w);
        } else p[pos] = (u8)rnd();
    }
    if (rnd() % 8 == 0) *n = rnd() % len;
}

static int open_extract(const u8 *buf, size_t len, gzch *wname, int *opened)
{
    for (int nd = 0; nd < 2; nd++) {
        gz_src *s = gz_src_mem(buf, len, 0);
        gz_open_opts o;
        opts(&o, wname);
        if (nd) o.flags |= GZ_OPEN_NO_DESCEND;
        gz_ctx *c = gz_ctx_new();
        gz_archive *a = 0;
        if (!gz_arc_open(&a, s, &o, c)) {
            (*opened)++;
            extract_all(a, s, c, 0);
            if (poke_views(a, s, c)) return 3;
            gz_arc_close(a);
        }
        gz_ctx_free(c);
        gz_src_free(s);
    }
    return 0;
}

static u8 *slurp(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 0; }
    fseek(f, 0, SEEK_END);
    *n = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *p = (u8 *)malloc(*n + 1);
    if (fread(p, 1, *n, f) != *n) { fclose(f); free(p); return 0; }
    fclose(f);
    return p;
}

static int cmd_fuzz(const char *path, int iters, u64 seed)
{
    size_t n;
    u8 *orig = slurp(path, &n);
    if (!orig) return 2;
    u8 *buf = (u8 *)malloc(n + 1);
    gzch *wname = gz_posix_wide(path);
    g_rng = seed * 0x9E3779B97F4A7C15ull + 1;
    int opened = 0;
    for (int it = 0; it < iters; it++) {
        size_t len = n;
        memcpy(buf, orig, n);
        if (it) mutate(buf, &len);
        if (open_extract(buf, len, wname, &opened)) return 3;
    }
    printf("ok %d opened=%d\n", iters, opened);
    free(buf);
    free(orig);
    free(wname);
    return 0;
}

static int cmd_many(int argc, char **argv)
{
    int opened = 0;
    g_rng = 12345;
    for (int i = 0; i < argc; i++) {
        size_t n;
        u8 *p = slurp(argv[i], &n);
        if (!p) return 2;
        gzch *wname = gz_posix_wide(argv[i]);
        if (open_extract(p, n, wname, &opened)) return 3;
        free(wname);
        free(p);
    }
    printf("ok %d opened=%d\n", argc, opened);
    return 0;
}

/* ---- threads ---- */

typedef struct { gz_archive *a; gz_src *s; const u32 *crc; int bad, seed; } th_arg;

static void *th_main(void *p)
{
    th_arg *t = (th_arg *)p;
    gz_ctx *c = gz_ctx_new();
    u32 *got = (u32 *)calloc(t->a->n + 1, 4);
    for (int round = 0; round < 3; round++) {
        memset(got, 0, (t->a->n + 1) * 4);
        if (t->a->solid) {
            cap_out co = { { c_open, c_write, c_close, 0 }, 0, 0, got, t->a->n };
            u8 *sel = (u8 *)calloc(1, t->a->n + 1);
            memset(sel, 1, t->a->n);
            gz_arc_extract_solid(t->a, t->s, sel, &co.o, c);
            free(sel);
        } else {
            for (u32 k = 0; k < t->a->n; k++) {
                u32 i = (k + (u32)t->seed * 7 + (u32)round) % t->a->n;
                cap_out co = { { c_open, c_write, c_close, 0 }, 0, 0, got, t->a->n };
                gz_arc_extract(t->a, t->s, i, &co.o, c);
            }
        }
        for (u32 i = 0; i < t->a->n; i++) if (got[i] != t->crc[i]) t->bad++;
    }
    free(got);
    gz_ctx_free(c);
    return 0;
}

static int cmd_threads(const char *path)
{
    gz_src *s = gz_posix_open_src(path);
    if (!s) return 2;
    gzch *wname = gz_posix_wide(path);
    gz_open_opts o;
    opts(&o, wname);
    gz_ctx *c = gz_ctx_new();
    gz_archive *a;
    if (gz_arc_open(&a, s, &o, c)) { printf("open failed\n"); return 1; }
    u32 *crc = (u32 *)calloc(a->n + 1, 4);
    cap_out co = { { c_open, c_write, c_close, 0 }, 0, 0, crc, a->n };
    if (a->solid) {
        u8 *sel = (u8 *)calloc(1, a->n + 1);
        memset(sel, 1, a->n);
        gz_arc_extract_solid(a, s, sel, &co.o, c);
        free(sel);
    } else {
        for (u32 i = 0; i < a->n; i++) gz_arc_extract(a, s, i, &co.o, c);
    }
    for (u32 i = 0; i < a->n; i++)
        if ((crc[i] & 0xFFFF0000u) == 0xDEAD0000u) { printf("extract %u failed %u\n", i, crc[i] & 0xffff); return 1; }
    pthread_t th[4];
    th_arg ta[4];
    for (int i = 0; i < 4; i++) {
        ta[i] = (th_arg){ a, s, crc, 0, i };
        pthread_create(&th[i], 0, th_main, &ta[i]);
    }
    int bad = 0;
    for (int i = 0; i < 4; i++) { pthread_join(th[i], 0); bad += ta[i].bad; }
    printf("%s %u entries threads=4 mismatches=%d\n", bad ? "BAD" : "ok", a->n, bad);
    gz_arc_close(a);
    gz_ctx_free(c);
    gz_src_free(s);
    free(crc);
    free(wname);
    return bad ? 1 : 0;
}

/* ---- bench ---- */

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

typedef struct { gz_out o; u64 n; } cnt_out;
static int n_open(gz_out *o, u32 idx) { (void)o; (void)idx; return 0; }
static int n_write(gz_out *o, const u8 *p, size_t n) { (void)p; ((cnt_out *)o)->n += n; return 0; }
static int n_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; return st; }

static int cmd_bench(const char *path, int rounds)
{
    gz_src *s = gz_posix_open_src(path);
    if (!s) return 2;
    gzch *wname = gz_posix_wide(path);
    double tl = 1e9, tx = 1e9;
    u64 bytes = 0;
    u32 n = 0;
    for (int k = 0; k < rounds; k++) {
        gz_open_opts o;
        opts(&o, wname);
        gz_ctx *c = gz_ctx_new();
        gz_archive *a;
        double t0 = now();
        if (gz_arc_open(&a, s, &o, c)) { printf("open failed\n"); return 1; }
        double t1 = now();
        cnt_out co = { { n_open, n_write, n_close, 0 }, 0 };
        if (a->solid) {
            u8 *sel = (u8 *)calloc(1, a->n + 1);
            memset(sel, 1, a->n);
            gz_arc_extract_solid(a, s, sel, &co.o, c);
            free(sel);
        } else {
            for (u32 i = 0; i < a->n; i++) gz_arc_extract(a, s, i, &co.o, c);
        }
        double t2 = now();
        if (t1 - t0 < tl) tl = t1 - t0;
        if (t2 - t1 < tx) tx = t2 - t1;
        bytes = co.n;
        n = a->n;
        gz_arc_close(a);
        gz_ctx_free(c);
    }
    printf("entries=%u bytes=%llu list=%.1fms extract=%.1fms (%.0f MB/s)\n", n, (unsigned long long)bytes,
           tl * 1e3, tx * 1e3, bytes / 1e6 / (tx > 0 ? tx : 1e-9));
    gz_src_free(s);
    free(wname);
    return 0;
}

int main(int argc, char **argv)
{
    init_core();
    if (argc >= 3 && !strcmp(argv[1], "dump")) return cmd_dump(argv[2]);
    if (argc >= 5 && !strcmp(argv[1], "fuzz")) return cmd_fuzz(argv[2], atoi(argv[3]), strtoull(argv[4], 0, 10));
    if (argc >= 3 && !strcmp(argv[1], "many")) return cmd_many(argc - 2, argv + 2);
    if (argc >= 3 && !strcmp(argv[1], "threads")) return cmd_threads(argv[2]);
    if (argc >= 4 && !strcmp(argv[1], "bench")) return cmd_bench(argv[2], atoi(argv[3]));
    return 2;
}
