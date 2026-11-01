/*
 * imgfuzz - mutation fuzzer for disk image / partition map readers
 *
 *   imgfuzz <file> <iterations> <seed>
 *   imgfuzz -t <file>      4 threads extract every entry concurrently (shared
 *                          tables, per-view caches): CRCs must match
 *
 * Each iteration mutates a copy of the file (bit flips, smashed 32/64-bit
 * fields, truncation), opens it from memory with and without automatic
 * descent, extracts every entry into a sink that stops after 4 MiB and reads
 * random ranges through the entry views. Files referenced by the image
 * (parents, extents) are opened unmodified next to <file>. Must not crash,
 * hang or leak (run under ASan/UBSan). Prints "ok <iterations> opened=<n>".
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

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
    for (size_t i = 0; i < n; i += 4096) sink ^= p[i];     /* touch the data */
    (void)sink;
    c->n += n;
    return c->n > (4u << 20) ? GZ_E_CANCEL : GZ_OK;
}
static int c_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; (void)st; return 0; }

static void mutate(u8 *p, size_t *n)
{
    size_t len = *n;
    if (!len) return;
    int kind = (int)(rnd() % 12);
    int count = 1 + (int)(rnd() % 8);
    for (int k = 0; k < count; k++) {
        size_t pos;
        u64 r = rnd() % 4;
        if (r == 0) pos = rnd() % (len < 4096 ? len : 4096);                    /* header */
        else if (r == 1) pos = len - 1 - rnd() % (len < 4096 ? len : 4096);     /* footer */
        else pos = rnd() % len;
        if (kind < 5) p[pos] ^= (u8)(1u << (rnd() % 8));
        else if (kind >= 10) {
            /* plausible pointer: an offset / sector / cluster inside (or just past) the
             * file, written over a non-zero word (likely a table entry), either endian */
            pos &= ~(size_t)3;
            for (int t = 0; t < 64 && pos + 4 <= len && !memcmp(p + pos, "\0\0\0\0", 4); t++)
                pos = (rnd() % len) & ~(size_t)3;
            u64 v = rnd() % (2 * (u64)len + 1);
            int sh = (int)(rnd() % 4);
            v >>= sh == 1 ? 9 : sh == 2 ? 16 : 0;
            size_t w = (rnd() & 1) ? 8 : 4;
            if (rnd() & 1) v = w == 8 ? __builtin_bswap64(v) : __builtin_bswap32((u32)v);
            if (pos + w <= len) memcpy(p + pos, &v, w);
        } else if (kind < 8) {
            pos &= ~(size_t)3;
            u64 v = rnd();
            static const u64 special[] = { 0, 1, 0xFFFFFFFFu, 0x7FFFFFFFu, 0x80000000u, ~(u64)0, 0x200, 0x10000 };
            if (rnd() & 1) v = special[rnd() % 8];
            size_t w = (rnd() & 1) ? 8 : 4;
            if (pos + w <= len) memcpy(p + pos, &v, w);
        } else {
            p[pos] = (u8)rnd();
        }
    }
    if (rnd() % 8 == 0) *n = rnd() % len;                                       /* truncate */
}

/* ---- threads: one archive, every thread extracts all entries with its own context ---- */

typedef struct { gz_out o; u32 crc; } crc_out;
static int k_open(gz_out *o, u32 idx) { (void)idx; ((crc_out *)o)->crc = 0; return 0; }
static int k_write(gz_out *o, const u8 *p, size_t n) { crc_out *c = (crc_out *)o; c->crc = gz_crc32(c->crc, p, n); return 0; }

typedef struct { gz_archive *a; gz_src *s; u32 *crc; int bad; int seed; } th_arg;

static void *th_main(void *p)
{
    th_arg *t = (th_arg *)p;
    gz_ctx *c = gz_ctx_new();
    for (int round = 0; round < 3; round++)
        for (u32 k = 0; k < t->a->n; k++) {
            u32 i = (k + (u32)t->seed + (u32)round) % t->a->n;      /* different order per thread */
            crc_out co = { { k_open, k_write, c_close, 0 }, 0 };
            int r = gz_arc_extract(t->a, t->s, i, &co.o, c);
            if (r || co.crc != t->crc[i]) t->bad++;
        }
    gz_ctx_free(c);
    return 0;
}

static int threads_mode(const char *path)
{
    gz_src *s = gz_posix_open_src(path);
    if (!s) return 2;
    gz_open_opts o;
    memset(&o, 0, sizeof o);
    gzch *wname = gz_posix_wide(path);
    o.file_name = wname;
    o.open_volume = gz_posix_open_volume;
    gz_ctx *c = gz_ctx_new();
    gz_archive *a;
    if (gz_arc_open(&a, s, &o, c)) { printf("open failed\n"); return 1; }
    u32 *crc = (u32 *)calloc(a->n + 1, 4);
    for (u32 i = 0; i < a->n; i++) {
        crc_out co = { { k_open, k_write, c_close, 0 }, 0 };
        if (gz_arc_extract(a, s, i, &co.o, c)) { printf("extract %u failed\n", i); return 1; }
        crc[i] = co.crc;
    }
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

int main(int argc, char **argv)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
    if (argc == 3 && !strcmp(argv[1], "-t")) return threads_mode(argv[2]);
    if (argc < 4) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 2; }
    fseek(f, 0, SEEK_END);
    size_t n = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *orig = (u8 *)malloc(n + 1);
    if (fread(orig, 1, n, f) != n) return 2;
    fclose(f);
    int iters = atoi(argv[2]);
    g_rng = (u64)strtoull(argv[3], 0, 10) * 0x9E3779B97F4A7C15ull + 1;
    u8 *buf = (u8 *)malloc(n + 1);
    gzch *wname = gz_posix_wide(argv[1]);
    int opened = 0;
    for (int it = 0; it < iters; it++) {
        size_t len = n;
        memcpy(buf, orig, n);
        if (it) mutate(buf, &len);
        for (int nd = 0; nd < 2; nd++) {
            gz_src *s = gz_src_mem(buf, len, 0);
            gz_open_opts o;
            memset(&o, 0, sizeof o);
            o.flags = nd ? GZ_OPEN_NO_DESCEND : 0;
            o.file_name = wname;
            o.open_volume = gz_posix_open_volume;
            gz_ctx *c = gz_ctx_new();
            gz_archive *a = 0;
            if (!gz_arc_open(&a, s, &o, c)) {
                opened++;
                for (u32 i = 0; i < a->n && i < 64; i++) {
                    cap_out co = { { c_open, c_write, c_close, 0 }, 0 };
                    gz_arc_extract(a, s, i, &co.o, c);
                    gz_src *v = gz_arc_view(a, s, i, c);
                    if (!v) continue;
                    u8 tmp[70000];
                    for (int k = 0; k < 16 && v->size; k++) {
                        u64 off = rnd() % v->size;
                        u32 want = (u32)(rnd() % sizeof tmp), got = 0;
                        v->read_at(v, off, tmp, want, &got);
                        if (got > want) { fprintf(stderr, "read_at overrun\n"); return 3; }
                    }
                    gz_src_free(v);
                }
                gz_arc_close(a);
            }
            gz_ctx_free(c);
            gz_src_free(s);
        }
    }
    printf("ok %d opened=%d\n", iters, opened);
    free(buf);
    free(orig);
    free(wname);
    return 0;
}
