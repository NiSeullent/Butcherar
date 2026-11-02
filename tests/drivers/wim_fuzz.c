/*
 * wim_fuzz <file.wim> <iterations> <seed> - in-process fuzzer for the WIM reader
 * (driver for tests/cases/fmt_wim.py, meant to run under ASan/UBSan)
 *
 * Every iteration corrupts a copy of the file (bit flips anywhere, bytes in the
 * header / blob table / last 64 KiB (metadata, XML), truncation, a run of garbage),
 * opens it from memory, extracts every entry (solid pass when a->solid) into a
 * counting sink and closes it. Prints how many variants opened and extracted cleanly.
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long long rng;
static unsigned rnd(void)
{
    rng = rng * 6364136223846793005ull + 1442695040888963407ull;
    return (unsigned)(rng >> 33);
}

typedef struct { gz_out o; unsigned long long bytes; } n_out;
static int o_open(gz_out *o, u32 idx) { (void)o; (void)idx; return GZ_OK; }
static int o_write(gz_out *o, const u8 *p, size_t n)
{
    n_out *t = (n_out *)o;
    (void)p;
    t->bytes += n;
    return t->bytes > (256ull << 20) ? GZ_E_LIMIT : GZ_OK;   /* runaway output guard */
}
static int o_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; (void)st; return GZ_OK; }

int main(int argc, char **argv)
{
    if (argc < 4) return 2;
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 2; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *orig = (unsigned char *)malloc(n + 1);
    if (fread(orig, 1, n, f) != (size_t)n) return 2;
    fclose(f);
    int iters = atoi(argv[2]);
    rng = strtoull(argv[3], 0, 10);
    unsigned long long tlo = 0, thi = 0;
    if (n >= 208) { tlo = 0; memcpy(&tlo, orig + 0x38, 8); memcpy(&thi, orig + 0x30, 7); thi += tlo; }
    int opened = 0, clean = 0;
    gz_ctx *c = gz_ctx_new();
    unsigned char *b = (unsigned char *)malloc(n + 1);
    for (int it = 0; it < iters; it++) {
        long m = n;
        memcpy(b, orig, n);
        int kind = rnd() % 6, cnt = 1 + rnd() % 8;
        for (int k = 0; k < cnt; k++) {
            long pos;
            switch (kind) {
            case 0: pos = rnd() % n; break;                                  /* anywhere */
            case 1: pos = rnd() % (n < 208 ? n : 208); break;                /* header */
            case 2: pos = (tlo < (unsigned long long)n && thi > tlo) ? (long)(tlo + rnd() % (thi - tlo)) : rnd() % n; break;
            case 3: pos = n - 1 - (long)(rnd() % (n < 65536 ? n : 65536)); break;   /* metadata / XML */
            default: pos = rnd() % n; break;
            }
            if (pos >= n) pos = n - 1;
            if (kind == 4) b[pos] = (unsigned char)rnd();
            else b[pos] ^= (unsigned char)(1u << (rnd() % 8));
        }
        if (kind == 5) {
            if (rnd() & 1) m = rnd() % n;                                     /* truncation */
            else { long p = rnd() % n, l = rnd() % 256; while (l-- && p < n) b[p++] = (unsigned char)rnd(); }
        }
        if (n >= 8) memcpy(b, orig, 8);                  /* keep the magic: fuzz the WIM reader */
        gz_src *s = gz_src_mem(b, (u64)m, 0);
        gz_archive *a = 0;
        int r = gz_arc_open(&a, s, 0, c);
        if (!r) {
            opened++;
            n_out o = { { o_open, o_write, o_close, 0 }, 0 };
            int bad = 0;
            if (a->solid) {
                u8 *sel = (u8 *)malloc(a->n + 1);
                memset(sel, 1, a->n + 1);
                bad = gz_arc_extract_solid(a, s, sel, &o.o, c) != GZ_OK;
                free(sel);
            } else {
                for (u32 i = 0; i < a->n; i++) bad |= gz_arc_extract(a, s, i, &o.o, c) != GZ_OK;
            }
            clean += !bad;
            gz_arc_close(a);
        }
        gz_src_free(s);
    }
    gz_ctx_free(c);
    free(b);
    free(orig);
    printf("wim fuzz %d iterations: %d opened, %d extracted without errors\n", iters, opened, clean);
    return 0;
}
