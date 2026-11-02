/*
 * sqfs_drv - test driver for the SquashFS / CramFS readers (tests/cases/fmt_squashfs.py)
 *
 *   sqfs_drv crc <img>                   idx status size crc name for every file (one thread)
 *   sqfs_drv mt <img> <threads> <rounds> every thread (own gz_ctx and source) extracts every file
 *                                        in its own shuffled order and reads every view, rounds
 *                                        times; compares with single-threaded CRCs: "OK n" or
 *                                        MISMATCH lines
 *   sqfs_drv seq <img>...                one gz_ctx for all: open, extract everything, close each
 *                                        image in turn (twice over the list); per-thread caches must
 *                                        not leak from one archive into the next. Prints
 *                                        "pass img idx status crc name"
 *   sqfs_drv fuzz <img> <iters> <seed>   in-process mutations of the image (bit flips, byte sets,
 *                                        truncation): open, extract everything, read every view
 *                                        (output capped per entry); prints "fuzz n opened m files k"
 *   sqfs_drv bench <img> <name> [reps]   extraction speed of one entry: "size seconds MB/s crc"
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "plat_posix.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void init_core(void)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
}

static void to_utf8(const gzch *w, char *o, size_t cap)
{
    size_t n = gz_wcslen(w);
    if (n * 3 + 1 > cap) n = (cap - 1) / 3;
    int k = gz_utf16_to_utf8(w, n, (u8 *)o);
    o[k] = 0;
}

/* CRC sink with an output cap (fuzzed sizes may declare huge sparse files) */
typedef struct { gz_out o; u32 crc; u64 n, cap; } crc_out;
static int c_open(gz_out *o, u32 idx) { crc_out *c = (crc_out *)o; c->crc = 0; c->n = 0; (void)idx; return 0; }
static int c_write(gz_out *o, const u8 *p, size_t n)
{
    crc_out *c = (crc_out *)o;
    c->crc = gz_crc32(c->crc, p, n);
    c->n += n;
    return c->cap && c->n > c->cap ? GZ_E_CANCEL : 0;
}
static int c_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; return st; }
static void crc_init(crc_out *c, u64 cap) { memset(c, 0, sizeof *c); c->o.open = c_open; c->o.write = c_write; c->o.close = c_close; c->cap = cap; }

static int open_path(const char *path, gz_src **ps, gz_archive **pa, gz_ctx *c)
{
    gz_src *src = gz_posix_open_src(path);
    if (!src) { perror(path); return 1; }
    int r = gz_arc_open(pa, src, 0, c);
    if (r) { printf("OPEN_ERROR %d\n", r); gz_src_free(src); return 1; }
    *ps = src;
    return 0;
}

static int is_file(const gz_entry *e) { return !e->is_dir && !(e->is_link && e->link_len); }

static u32 view_crc(gz_src *v, u64 cap, int *err)
{
    static __thread u8 buf[200003];
    u32 crc = 0;
    u64 off = 0, size = v->size < cap ? v->size : cap;
    while (off < size) {
        u32 n = size - off < sizeof buf ? (u32)(size - off) : (u32)sizeof buf;
        if (gz_src_read_exact(v, off, buf, n)) { *err = 1; return 0; }
        crc = gz_crc32(crc, buf, n);
        off += n;
    }
    return crc;
}

/* ---------------- mt ---------------- */

typedef struct {
    const char *path;
    gz_archive *a;
    const u32 *crc;
    const int *st;
    int rounds, id, bad;
} mt_job;

static void *mt_run(void *p)
{
    mt_job *j = (mt_job *)p;
    gz_ctx *c = gz_ctx_new();
    gz_src *s = gz_posix_open_src(j->path);
    u32 n = j->a->n, *ord = (u32 *)malloc(sizeof(u32) * (n + 1)), seed = 7919u * (j->id + 1);
    crc_out o;
    crc_init(&o, 0);
    for (int r = 0; r < j->rounds; r++) {
        for (u32 i = 0; i < n; i++) ord[i] = i;
        for (u32 i = n; i > 1; i--) {
            seed = seed * 1103515245u + 12345u;
            u32 k = (seed >> 8) % i, t = ord[i - 1];
            ord[i - 1] = ord[k]; ord[k] = t;
        }
        for (u32 k = 0; k < n; k++) {
            u32 i = ord[k];
            if (!is_file(&j->a->e[i])) continue;
            int st = gz_arc_extract(j->a, s, i, &o.o, c);
            if (st != j->st[i] || (!st && o.crc != j->crc[i])) {
                printf("MISMATCH thread %d entry %u st %d/%d crc %08x/%08x\n", j->id, i, st, j->st[i], o.crc, j->crc[i]);
                j->bad++;
            }
            if ((k + r + j->id) % 3 == 0 && !j->st[i]) {
                gz_src *v = gz_arc_view(j->a, s, i, c);
                int err = 0;
                if (v) {
                    u32 vc = view_crc(v, ~(u64)0, &err);
                    if (err || vc != j->crc[i]) { printf("VIEW_MISMATCH thread %d entry %u\n", j->id, i); j->bad++; }
                    gz_src_free(v);
                }
            }
        }
    }
    free(ord);
    gz_src_free(s);
    gz_ctx_free(c);
    return 0;
}

static int cmd_mt(const char *path, int nt, int rounds)
{
    gz_ctx *c = gz_ctx_new();
    gz_src *src;
    gz_archive *a;
    if (open_path(path, &src, &a, c)) return 1;
    u32 *crc = (u32 *)calloc(a->n + 1, 4);
    int *st = (int *)calloc(a->n + 1, sizeof(int));
    crc_out o;
    crc_init(&o, 0);
    u32 files = 0;
    for (u32 i = 0; i < a->n; i++) {
        if (!is_file(&a->e[i])) continue;
        st[i] = gz_arc_extract(a, src, i, &o.o, c);
        crc[i] = o.crc;
        files++;
    }
    pthread_t th[64];
    mt_job jobs[64];
    if (nt > 64) nt = 64;
    for (int k = 0; k < nt; k++) {
        jobs[k] = (mt_job){ path, a, crc, st, rounds, k, 0 };
        pthread_create(&th[k], 0, mt_run, &jobs[k]);
    }
    int bad = 0;
    for (int k = 0; k < nt; k++) { pthread_join(th[k], 0); bad += jobs[k].bad; }
    if (!bad) printf("OK %u\n", files);
    gz_arc_close(a);
    gz_src_free(src);
    gz_ctx_free(c);
    free(crc);
    free(st);
    return bad ? 1 : 0;
}

/* ---------------- seq ---------------- */

static int cmd_seq(int argc, char **argv)
{
    gz_ctx *c = gz_ctx_new();
    char nm[8192];
    crc_out o;
    crc_init(&o, 0);
    for (int pass = 0; pass < 2; pass++) {
        for (int k = 0; k < argc; k++) {
            gz_src *src;
            gz_archive *a;
            if (open_path(argv[k], &src, &a, c)) continue;
            for (u32 i = 0; i < a->n; i++) {
                if (!is_file(&a->e[i])) continue;
                int st = gz_arc_extract(a, src, i, &o.o, c);
                to_utf8(a->e[i].name, nm, sizeof nm);
                printf("%d\t%d\t%u\t%d\t%08x\t%s\n", pass, k, i, st, o.crc, nm);
            }
            gz_arc_close(a);
            gz_src_free(src);
        }
    }
    gz_ctx_free(c);
    return 0;
}

/* ---------------- fuzz ---------------- */

static u32 rnd(u64 *s)
{
    *s = *s * 6364136223846793005ull + 1442695040888963407ull;
    return (u32)(*s >> 33);
}

static int cmd_fuzz(const char *path, int iters, u64 seed)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 1; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *orig = (u8 *)malloc(n + 1), *buf = (u8 *)malloc(n + 1);
    if (fread(orig, 1, n, f) != (size_t)n) { fclose(f); return 1; }
    fclose(f);
    /* metadata region: SquashFS tables from the inode table on, CramFS directories at the start */
    u64 meta = 0;
    if (n >= 96 && rd32(orig) == 0x73717368u) meta = rd64(orig + 64);
    if (meta >= (u64)n) meta = 0;
    u64 s = seed * 0x9E3779B97F4A7C15ull + 1;
    int opened = 0, files = 0;
    crc_out o;
    crc_init(&o, 64u << 20);
    for (int it = 0; it < iters; it++) {
        memcpy(buf, orig, n);
        long len = n;
        u32 kind = rnd(&s) % 10;
        if (kind == 9) {
            len = 1 + rnd(&s) % n;
        } else {
            int flips = 1 << (rnd(&s) % 5);
            for (int k = 0; k < flips; k++) {
                u32 w = rnd(&s) % 10;
                u64 pos;
                if (w < 3) pos = rnd(&s) % (n < 512 ? n : 512);               /* superblock area */
                else if (w < 8) pos = meta + rnd(&s) % (n - meta);            /* tables */
                else pos = rnd(&s) % n;
                if (rnd(&s) % 3 == 0) {
                    static const u8 v[] = { 0, 0xFF, 0x7F, 0x80, 1, 0x20 };
                    buf[pos] = v[rnd(&s) % sizeof v];
                } else {
                    buf[pos] ^= (u8)(1u << (rnd(&s) % 8));
                }
            }
        }
        gz_src *src = gz_src_mem(buf, (u64)len, 0);
        gz_ctx *c = gz_ctx_new();
        gz_archive *a = 0;
        if (!gz_arc_open(&a, src, 0, c)) {
            opened++;
            for (u32 i = 0; i < a->n; i++) {
                if (!is_file(&a->e[i])) continue;
                files++;
                gz_arc_extract(a, src, i, &o.o, c);
                gz_src *v = gz_arc_view(a, src, i, c);
                if (v) {
                    int err = 0;
                    view_crc(v, 64u << 20, &err);
                    gz_src_free(v);
                }
            }
            gz_arc_close(a);
        }
        gz_ctx_free(c);
        gz_src_free(src);
    }
    printf("fuzz %d opened %d files %d\n", iters, opened, files);
    free(orig);
    free(buf);
    return 0;
}

/* ---------------- bench / crc ---------------- */

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int cmd_bench(const char *path, const char *name, int reps)
{
    gz_ctx *c = gz_ctx_new();
    gz_src *src;
    gz_archive *a;
    if (open_path(path, &src, &a, c)) return 1;
    char nm[8192];
    int rc = 1;
    for (u32 i = 0; i < a->n; i++) {
        to_utf8(a->e[i].name, nm, sizeof nm);
        if (strcmp(nm, name)) continue;
        crc_out o;
        crc_init(&o, 0);
        double t0 = now();
        int st = 0;
        for (int k = 0; k < reps && !st; k++) st = gz_arc_extract(a, src, i, &o.o, c);
        double dt = (now() - t0) / reps;
        printf("%llu\t%.4f\t%.1f\t%08x\t%d\n", (unsigned long long)o.n, dt, o.n / dt / 1e6, o.crc, st);
        rc = st != 0;
        break;
    }
    gz_arc_close(a);
    gz_src_free(src);
    gz_ctx_free(c);
    return rc;
}

static int cmd_crc(const char *path)
{
    gz_ctx *c = gz_ctx_new();
    gz_src *src;
    gz_archive *a;
    if (open_path(path, &src, &a, c)) return 1;
    printf("TYPE\t%s\t%u\n", gz_arc_type_name(a), a->n);
    char nm[8192];
    crc_out o;
    crc_init(&o, 0);
    for (u32 i = 0; i < a->n; i++) {
        if (!is_file(&a->e[i])) continue;
        int st = gz_arc_extract(a, src, i, &o.o, c);
        to_utf8(a->e[i].name, nm, sizeof nm);
        printf("%u\t%d\t%llu\t%08x\t%s\n", i, st, (unsigned long long)o.n, o.crc, nm);
    }
    gz_arc_close(a);
    gz_src_free(src);
    gz_ctx_free(c);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    init_core();
    if (!strcmp(argv[1], "crc")) return cmd_crc(argv[2]);
    if (!strcmp(argv[1], "mt") && argc > 4) return cmd_mt(argv[2], atoi(argv[3]), atoi(argv[4]));
    if (!strcmp(argv[1], "seq")) return cmd_seq(argc - 2, argv + 2);
    if (!strcmp(argv[1], "fuzz") && argc > 4) return cmd_fuzz(argv[2], atoi(argv[3]), strtoull(argv[4], 0, 0));
    if (!strcmp(argv[1], "bench") && argc > 3) return cmd_bench(argv[2], argv[3], argc > 4 ? atoi(argv[4]) : 3);
    return 2;
}
