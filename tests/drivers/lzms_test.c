/*
 * lzms_test - LZMS chunk decoder checks (driver for tests/cases/fmt_wim.py)
 *
 *   lzms_test dec   <records>             decode every record, compare with the expected data
 *   lzms_test bench <records> <reps>      decode speed (MB/s of output)
 *   lzms_test fuzz  <records> <n> <seed>  decode n corrupted variants (bit flips, truncation,
 *                                         garbage, wrong sizes); must not crash or hang
 *
 * records: repeated { u32 usize, u32 csize, csize bytes LZMS chunk, usize bytes original }
 * (written by fmt_wim.py with wimlib's own compressor).
 */
#include "lzms.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { unsigned usize, csize; unsigned char *c, *u; } rec;

static rec *load(const char *path, int *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    rec *r = 0;
    int k = 0, cap = 0;
    unsigned hdr[2];
    while (fread(hdr, 4, 2, f) == 2) {
        if (k == cap) { cap = cap ? cap * 2 : 64; r = (rec *)realloc(r, cap * sizeof(rec)); }
        r[k].usize = hdr[0];
        r[k].csize = hdr[1];
        r[k].c = (unsigned char *)malloc(hdr[1] + 1);
        r[k].u = (unsigned char *)malloc(hdr[0] + 1);
        if (fread(r[k].c, 1, hdr[1], f) != hdr[1] || fread(r[k].u, 1, hdr[0], f) != hdr[0]) {
            fprintf(stderr, "truncated record file\n");
            exit(2);
        }
        k++;
    }
    fclose(f);
    *n = k;
    return r;
}

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static unsigned long long rng;
static unsigned rnd(void)
{
    rng = rng * 6364136223846793005ull + 1442695040888963407ull;
    return (unsigned)(rng >> 33);
}

static int run(int argc, char **argv, rec *r, int n, gz_lzms_dec *d);

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    int n;
    rec *r = load(argv[2], &n);
    gz_lzms_dec *d = gz_lzms_new();
    if (!d) return 3;
    int rc = run(argc, argv, r, n, d);
    gz_lzms_free(d);
    for (int i = 0; i < n; i++) { free(r[i].c); free(r[i].u); }
    free(r);
    return rc;
}

static int run(int argc, char **argv, rec *r, int n, gz_lzms_dec *d)
{
    if (!strcmp(argv[1], "dec")) {
        int good = 0;
        for (int i = 0; i < n; i++) {
            unsigned char *o = (unsigned char *)malloc(r[i].usize + 1);
            int st = gz_lzms_decode(d, r[i].c, r[i].csize, o, r[i].usize);
            int ok = !st && !memcmp(o, r[i].u, r[i].usize);
            if (!ok) {
                unsigned at = 0;
                if (!st) while (at < r[i].usize && o[at] == r[i].u[at]) at++;
                printf("FAIL record %d usize %u csize %u status %d first diff %u\n", i, r[i].usize, r[i].csize, st, at);
            }
            good += ok;
            free(o);
        }
        printf("ok %d/%d\n", good, n);
        return good == n ? 0 : 1;
    }
    if (!strcmp(argv[1], "bench")) {
        int reps = argc > 3 ? atoi(argv[3]) : 3;
        double best = 1e9, total = 0;
        for (int i = 0; i < n; i++) total += r[i].usize;
        for (int k = 0; k < reps; k++) {
            double t = now();
            for (int i = 0; i < n; i++) {
                unsigned char *o = (unsigned char *)malloc(r[i].usize + 1);
                int st = gz_lzms_decode(d, r[i].c, r[i].csize, o, r[i].usize);
                free(o);
                if (st) return 1;
            }
            t = now() - t;
            if (t < best) best = t;
        }
        printf("lzms %.1f MB/s (%.1f MB)\n", total / best / 1e6, total / 1e6);
        return 0;
    }
    if (!strcmp(argv[1], "fuzz")) {
        int iters = argc > 3 ? atoi(argv[3]) : 1000;
        rng = argc > 4 ? strtoull(argv[4], 0, 10) : 1;
        int errs = 0, oks = 0;
        for (int it = 0; it < iters; it++) {
            rec *x = &r[rnd() % n];
            unsigned cs = x->csize, us = x->usize;
            unsigned char *c = (unsigned char *)malloc(cs + 64);
            memcpy(c, x->c, cs);
            switch (rnd() % 5) {
            case 0: case 1:                                   /* bit flips */
                for (unsigned k = 1 + rnd() % 8; k; k--) c[rnd() % cs] ^= (unsigned char)(1u << (rnd() % 8));
                break;
            case 2:                                           /* truncation (kept even) */
                cs = (rnd() % (cs + 1)) & ~1u;
                break;
            case 3:                                           /* garbage */
                for (unsigned k = 0; k < cs; k++) c[k] = (unsigned char)rnd();
                break;
            default:                                          /* wrong output size */
                us = rnd() % (us * 2 + 64);
                break;
            }
            unsigned char *o = (unsigned char *)malloc(us + 1);
            int st = gz_lzms_decode(d, c, cs, o, us);
            if (st) errs++; else oks++;
            free(o);
            free(c);
        }
        printf("fuzz %d iterations: %d errors, %d decoded\n", iters, errs, oks);
        return 0;
    }
    return 2;
}
