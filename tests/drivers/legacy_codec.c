/*
 * legacy_codec - raw stream driver for the legacy codecs (fmt_legacy.py)
 *
 *   legacy_codec shrink  <in> <out> <size>
 *   legacy_codec implode <in> <out> <size> <large 0|1> <three 0|1>
 *   legacy_codec lzh     <in> <out> <size> <GZ_LZH_* method number>
 *   legacy_codec lzw     <in> <out> <size> <flags byte>
 *   legacy_codec bench   <codec args as above, out ignored> <repeat>
 *
 * size: decimal or -1 (GZ_SIZE_UNKNOWN). Prints "status=<n> out=<bytes>".
 */
#include "lzw.h"
#include "implode.h"
#include "lzh.h"
#include "cpu.h"
#include "crc32.h"
#include "inflate.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { gz_range_reader rd; FILE *f; unsigned long long n; } drv_io;

static int w_cb(void *ctx, const u8 *p, size_t n)
{
    drv_io *x = (drv_io *)ctx;
    x->n += n;
    if (x->f && fwrite(p, 1, n, x->f) != n) return GZ_E_IO;
    return GZ_OK;
}

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(int argc, char **argv)
{
    if (argc < 5) return 2;
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_dispatch_init(-1);
    int bench = !strcmp(argv[1], "bench");
    char **a = argv + bench;
    int ac = argc - bench;
    int repeat = bench ? atoi(argv[argc - 1]) : 1;
    if (bench) ac--;
    const char *codec = a[1];
    gz_src *s = gz_posix_open_src(a[2]);
    if (!s) { perror(a[2]); return 2; }
    long long sz = atoll(a[4]);
    u64 out_size = sz < 0 ? GZ_SIZE_UNKNOWN : (u64)sz;
    gz_lzw_dec *lzw = gz_lzw_dec_new();
    gz_implode_dec *imp = gz_implode_dec_new();
    gz_lzh_dec *lzh = gz_lzh_dec_new();
    int st = 0;
    unsigned long long produced = 0;
    double t0 = now();
    for (int it = 0; it < repeat; it++) {
        drv_io x;
        memset(&x, 0, sizeof x);
        x.rd.src = s;
        x.rd.pos = 0;
        x.rd.end = s->size;
        x.f = bench ? 0 : fopen(a[3], "wb");
        gz_stream_io io = { gz_range_read, w_cb, &x };
        if (!strcmp(codec, "shrink")) st = gz_shrink_decode(it & 1 ? lzw : 0, &io, out_size);
        else if (!strcmp(codec, "implode") && ac > 6) st = gz_implode_decode(it & 1 ? 0 : imp, &io, out_size, atoi(a[5]), atoi(a[6]));
        else if (!strcmp(codec, "lzh") && ac > 5) st = gz_lzh_decode(lzh, &io, out_size, atoi(a[5]));
        else if (!strcmp(codec, "lzw") && ac > 5) st = gz_lzw_decode(lzw, &io, out_size, atoi(a[5]));
        else return 2;
        if (x.f) fclose(x.f);
        produced = x.n;
    }
    double dt = now() - t0;
    printf("status=%d out=%llu", st, produced);
    if (bench) printf(" MB/s=%.1f", produced * (double)repeat / dt / 1e6);
    printf("\n");
    gz_lzw_dec_free(lzw);
    gz_implode_dec_free(imp);
    gz_lzh_dec_free(lzh);
    gz_src_free(s);
    return 0;
}
