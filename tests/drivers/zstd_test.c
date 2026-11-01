/*
 * zstd_test - codec-level driver for the Zstandard / LZ4 / xxHash code
 *
 *   zstd_test dec   <file> <expected>      streaming decode (zstd or lz4 by magic) with several
 *                                          read chunk sizes, in_used, out_size limits; mem API
 *   zstd_test err   <file>                 print the decoder's return code (expected failures)
 *   zstd_test blk   <frame.lz4> <expected> decode each block of an LZ4 frame with the raw block API
 *   zstd_test fuzz  <file> <count> <seed>  in-process mutations; must not crash or hang
 *   zstd_test bench <file> <seconds>       decode to a null sink, print MB/s
 *   zstd_test xxh   <file>                 print XXH32 / XXH64 (seed 0) one-shot and streamed
 *
 * Prints "OK ..." on success; exit code 0 = pass.
 * ZT_TIER=n forces a CPU dispatch tier (0 = plain x86 kernels).
 * Built with -DZT_WRAP_BIG -Wl,--wrap=gz_alloc_big,--wrap=gz_free_big (GNU ld), the
 * page-granular allocations come from calloc so AddressSanitizer checks the window
 * buffers too.
 */
#include "zstd.h"
#include "lz4.h"
#include "xxhash.h"
#include "cpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef ZT_WRAP_BIG
void *__wrap_gz_alloc_big(size_t n);
void __wrap_gz_free_big(void *p, size_t n);
void *__wrap_gz_alloc_big(size_t n) { return calloc(1, n ? n : 1); }
void __wrap_gz_free_big(void *p, size_t n) { (void)n; free(p); }
#endif

static u8 *load(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *p = (u8 *)malloc((size_t)sz + 1);
    if (sz && fread(p, 1, (size_t)sz, f) != (size_t)sz) { perror(path); exit(2); }
    fclose(f);
    *n = (size_t)sz;
    return p;
}

/* reader handing out at most `chunk` bytes per call; sink collecting / comparing */
typedef struct {
    const u8 *in; size_t in_n, in_pos, chunk;
    const u8 *exp; size_t exp_n;       /* expected output (NULL: discard)   */
    u64 out_n, limit;                  /* limit: GZ_E_LIMIT after this many  */
    int mismatch;
} io_ctx;

static int t_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    io_ctx *c = (io_ctx *)ctx;
    size_t k = c->in_n - c->in_pos;
    if (k > cap) k = cap;
    if (k > c->chunk) k = c->chunk;
    memcpy(buf, c->in + c->in_pos, k);
    c->in_pos += k;
    *got = (u32)k;
    return GZ_OK;
}

static int t_write(void *ctx, const u8 *p, size_t n)
{
    io_ctx *c = (io_ctx *)ctx;
    if (c->exp) {
        if (c->out_n + n > c->exp_n || memcmp(c->exp + c->out_n, p, n)) c->mismatch = 1;
    } else if (n) {
        volatile u8 sink = p[0] ^ p[n - 1];   /* touch the data */
        (void)sink;
    }
    c->out_n += n;
    if (c->limit && c->out_n >= c->limit) return GZ_E_LIMIT;
    return GZ_OK;
}

static int is_lz4(const u8 *p, size_t n)
{
    if (n < 4) return 0;
    u32 m = rd32(p);
    if (m == GZ_LZ4_MAGIC || m == GZ_LZ4_LEGACY_MAGIC) return 1;
    /* skippable frames are shared: look past them */
    size_t off = 0;
    for (int i = 0; i < 16 && off + 8 <= n && (rd32(p + off) & 0xFFFFFFF0u) == GZ_LZ4_SKIP_MAGIC; i++)
        off += 8 + (size_t)rd32(p + off + 4);
    return off + 4 <= n && (rd32(p + off) == GZ_LZ4_MAGIC || rd32(p + off) == GZ_LZ4_LEGACY_MAGIC);
}

static int run_dec(gz_zstd_dec *d, int lz4, io_ctx *c, u64 out_size, u64 *used)
{
    gz_stream_io io = { t_read, t_write, c };
    return lz4 ? gz_lz4f_decode(&io, out_size, used) : gz_zstd_decode(d, &io, out_size, used);
}

static int cmd_dec(const char *file, const char *expf)
{
    size_t n, en;
    u8 *in = load(file, &n), *exp = load(expf, &en);
    int lz4 = is_lz4(in, n);
    gz_zstd_dec *d = gz_zstd_dec_new();
    static const size_t chunks[] = { (size_t)1 << 30, 1, 7, 4093, 65536 };
    int fails = 0;
    for (size_t k = 0; k < sizeof chunks / sizeof chunks[0]; k++) {
        if (chunks[k] < 4093 && n > (4u << 20)) continue;          /* tiny reads on big files: slow */
        io_ctx c = { in, n, 0, chunks[k], exp, en, 0, 0, 0 };
        u64 used = 0;
        int r = run_dec(d, lz4, &c, GZ_SIZE_UNKNOWN, &used);
        if (r || c.mismatch || c.out_n != en || used != n) {
            printf("FAIL chunk=%zu r=%d mismatch=%d out=%llu/%zu used=%llu/%zu\n", chunks[k], r, c.mismatch,
                   (unsigned long long)c.out_n, en, (unsigned long long)used, n);
            fails++;
        }
    }
    /* exact out_size: must succeed with all bytes */
    {
        io_ctx c = { in, n, 0, (size_t)1 << 30, exp, en, 0, 0, 0 };
        int r = run_dec(d, lz4, &c, en, 0);
        if (r || c.mismatch || c.out_n != en) { printf("FAIL out_size=exact r=%d\n", r); fails++; }
    }
    /* partial out_size: stops early with exactly that many bytes */
    if (en > 2) {
        u64 half = en / 2 + 1;
        io_ctx c = { in, n, 0, (size_t)1 << 30, exp, en, 0, 0, 0 };
        int r = run_dec(d, lz4, &c, half, 0);
        if (r || c.mismatch || c.out_n != half) {
            printf("FAIL out_size=%llu r=%d out=%llu\n", (unsigned long long)half, r, (unsigned long long)c.out_n);
            fails++;
        }
    }
    /* out_size larger than the content: GZ_E_DATA */
    {
        io_ctx c = { in, n, 0, (size_t)1 << 30, exp, en, 0, 0, 0 };
        int r = run_dec(d, lz4, &c, (u64)en + 1, 0);
        if (r != GZ_E_DATA) { printf("FAIL out_size=en+1 r=%d\n", r); fails++; }
    }
    /* sink error propagates unchanged */
    if (en > 0) {
        io_ctx c = { in, n, 0, (size_t)1 << 30, 0, 0, 0, 1, 0 };
        int r = run_dec(d, lz4, &c, GZ_SIZE_UNKNOWN, 0);
        if (r != GZ_E_LIMIT) { printf("FAIL sink error r=%d\n", r); fails++; }
    }
    /* memory API (zstd) */
    if (!lz4) {
        u8 *dst = (u8 *)malloc(en + 1);
        size_t dn = 0;
        int r = gz_zstd_decode_mem(d, in, n, dst, en, &dn);
        if (r || dn != en || memcmp(dst, exp, en)) { printf("FAIL mem r=%d dn=%zu\n", r, dn); fails++; }
        if (en) {
            r = gz_zstd_decode_mem(d, in, n, dst, en - 1, &dn);
            if (r != GZ_E_DATA) { printf("FAIL mem small r=%d\n", r); fails++; }
        }
        free(dst);
        /* ONE_FRAME reports where the first frame ends */
        io_ctx c = { in, n, 0, (size_t)1 << 30, 0, 0, 0, 0, 0 };
        gz_stream_io io = { t_read, t_write, &c };
        u64 used = 0;
        r = gz_zstd_decode_ex(d, &io, GZ_SIZE_UNKNOWN, GZ_ZSTD_ONE_FRAME, &used);
        if (r || used > n || c.out_n > en) { printf("FAIL one_frame r=%d used=%llu\n", r, (unsigned long long)used); fails++; }
    }
    gz_zstd_dec_free(d);
    if (!fails) printf("OK %zu -> %zu\n", n, en);
    free(in);
    free(exp);
    return fails ? 1 : 0;
}

static int cmd_err(const char *file)
{
    size_t n;
    u8 *in = load(file, &n);
    gz_zstd_dec *d = gz_zstd_dec_new();
    io_ctx c = { in, n, 0, (size_t)1 << 30, 0, 0, 0, 1u << 30, 0 };
    int r = run_dec(d, is_lz4(in, n), &c, GZ_SIZE_UNKNOWN, 0);
    printf("RESULT %d %llu\n", r, (unsigned long long)c.out_n);
    gz_zstd_dec_free(d);
    free(in);
    return 0;
}

/* walk an LZ4 frame (independent blocks) and decode every block with the raw API */
static int cmd_blk(const char *file, const char *expf)
{
    size_t n, en;
    u8 *in = load(file, &n), *exp = load(expf, &en);
    if (n < 7 || rd32(in) != GZ_LZ4_MAGIC) { printf("FAIL not a frame\n"); return 1; }
    u32 flg = in[4], bd = in[5];
    size_t bmax = (size_t)1 << (2 * ((bd >> 4) & 7) + 8), off = 7 + ((flg & 8) ? 8 : 0) + ((flg & 1) ? 4 : 0);
    u8 *dst = (u8 *)malloc(bmax);
    size_t pos = 0, blocks = 0;
    int fails = 0;
    while (off + 4 <= n) {
        u32 bs = rd32(in + off);
        off += 4;
        if (!bs) break;
        u32 raw = bs >> 31;
        bs &= 0x7FFFFFFF;
        u32 dn = 0;
        if (raw) {
            memcpy(dst, in + off, bs);
            dn = bs;
        } else {
            int r = gz_lz4_block_decode(in + off, bs, dst, (u32)bmax, &dn);
            if (r) { printf("FAIL block %zu r=%d\n", blocks, r); fails++; break; }
            /* exact-size output buffer must also work, one byte less must fail */
            u8 *tight = (u8 *)malloc(dn ? dn : 1);
            u32 dn2 = 0;
            if (gz_lz4_block_decode(in + off, bs, tight, dn, &dn2) || dn2 != dn || memcmp(tight, dst, dn)) {
                printf("FAIL tight block %zu\n", blocks); fails++;
            }
            if (dn && gz_lz4_block_decode(in + off, bs, tight, dn - 1, &dn2) != GZ_E_DATA) {
                printf("FAIL short block %zu\n", blocks); fails++;
            }
            free(tight);
        }
        if (pos + dn > en || memcmp(exp + pos, dst, dn)) { printf("FAIL data block %zu\n", blocks); fails++; break; }
        pos += dn;
        off += bs + ((flg & 0x10) ? 4 : 0);
        blocks++;
    }
    if (pos != en) { printf("FAIL total %zu/%zu\n", pos, en); fails++; }
    if (!fails) printf("OK %zu blocks\n", blocks);
    free(dst);
    free(in);
    free(exp);
    return fails ? 1 : 0;
}

static u64 rng;
static u32 rnd(void)
{
    rng = rng * 6364136223846793005ull + 1442695040888963407ull;
    return (u32)(rng >> 33);
}

static int cmd_fuzz(const char *file, int count, int seed)
{
    size_t n;
    u8 *orig = load(file, &n);
    if (!n) return 0;
    int lz4 = is_lz4(orig, n);
    gz_zstd_dec *d = gz_zstd_dec_new();
    u8 *buf = (u8 *)malloc(n + 64);
    int hist[GZ_E_COUNT + 1] = { 0 };
    rng = (u64)seed * 0x9E3779B97F4A7C15ull + 1;
    alarm(600);
    for (int it = 0; it < count; it++) {
        size_t m = n;
        memcpy(buf, orig, n);
        int kind = (int)(rnd() % 6), muts = 1 + (int)(rnd() % 4);
        if (kind == 0) {
            m = rnd() % n;                                     /* truncate */
        } else if (kind == 1) {
            for (int k = 0; k < muts; k++) buf[rnd() % n] ^= (u8)(1u << (rnd() % 8));
        } else if (kind == 2) {
            for (int k = 0; k < muts; k++) buf[rnd() % n] = (u8)rnd();
        } else if (kind == 3) {                                /* bit flips near the start (headers) */
            size_t span = n < 64 ? n : 64;
            for (int k = 0; k < muts; k++) buf[rnd() % span] ^= (u8)(1u << (rnd() % 8));
        } else if (kind == 4) {                                /* extreme values */
            for (int k = 0; k < muts; k++) buf[rnd() % n] = (rnd() & 1) ? 0xFF : 0x00;
        } else {                                               /* flips near the end (checksums, last block) */
            size_t span = n < 64 ? n : 64;
            for (int k = 0; k < muts; k++) buf[n - 1 - rnd() % span] ^= (u8)(1u << (rnd() % 8));
        }
        io_ctx c = { buf, m, 0, (rnd() & 3) ? (size_t)1 << 30 : 1 + rnd() % 5000, 0, 0, 0, 64u << 20, 0 };
        u64 out_size = (rnd() % 8) == 0 ? rnd() % (2 * n + 1) : GZ_SIZE_UNKNOWN;
        int r = run_dec(d, lz4, &c, out_size, 0);
        if (r < 0 || r >= GZ_E_COUNT) { printf("FAIL bad code %d\n", r); return 1; }
        hist[r]++;
        if (!lz4) {                                            /* memory API on the same input */
            u8 *dst = (u8 *)malloc(1 << 20);
            size_t dn;
            gz_zstd_decode_mem(d, buf, m, dst, 1 << 20, &dn);
            free(dst);
        } else {                                               /* raw block API on the whole input */
            u8 *dst = (u8 *)malloc(1 << 16);
            u32 dn;
            gz_lz4_block_decode(buf, (u32)m, dst, 1 << 16, &dn);
            free(dst);
        }
    }
    printf("OK %d runs:", count);
    for (int i = 0; i < GZ_E_COUNT; i++) if (hist[i]) printf(" e%d=%d", i, hist[i]);
    printf("\n");
    gz_zstd_dec_free(d);
    free(buf);
    free(orig);
    return 0;
}

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int cmd_bench(const char *file, double secs)
{
    size_t n;
    u8 *in = load(file, &n);
    int lz4 = is_lz4(in, n);
    gz_zstd_dec *d = gz_zstd_dec_new();
    double best = 1e9, t_end = now() + secs;
    u64 out = 0;
    int runs = 0;
    do {
        io_ctx c = { in, n, 0, (size_t)1 << 30, 0, 0, 0, 0, 0 };
        double t0 = now();
        int r = run_dec(d, lz4, &c, GZ_SIZE_UNKNOWN, 0);
        double t = now() - t0;
        if (r) { printf("FAIL r=%d\n", r); return 1; }
        if (t < best) best = t;
        out = c.out_n;
        runs++;
    } while (now() < t_end || runs < 2);
    printf("OK %.1f MB/s (%llu bytes, best of %d)\n", out / best / 1e6, (unsigned long long)out, runs);
    gz_zstd_dec_free(d);
    free(in);
    return 0;
}

static int cmd_xxh(const char *file)
{
    size_t n;
    u8 *in = load(file, &n);
    gz_xxh32_state s32;
    gz_xxh64_state s64;
    gz_xxh32_init(&s32, 0);
    gz_xxh64_init(&s64, 0);
    size_t pos = 0, step = 1;
    while (pos < n) {                                       /* uneven pieces */
        size_t k = n - pos < step ? n - pos : step;
        gz_xxh32_update(&s32, in + pos, k);
        gz_xxh64_update(&s64, in + pos, k);
        pos += k;
        step = step * 3 % 97 + 1;
    }
    printf("%08x %016llx %08x %016llx\n", gz_xxh32(in, n, 0), (unsigned long long)gz_xxh64(in, n, 0),
           gz_xxh32_digest(&s32), (unsigned long long)gz_xxh64_digest(&s64));
    free(in);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    gz_cpu_detect();
    gz_dispatch_init(getenv("ZT_TIER") ? atoi(getenv("ZT_TIER")) : -1);
    if (!strcmp(argv[1], "dec") && argc > 3) return cmd_dec(argv[2], argv[3]);
    if (!strcmp(argv[1], "err")) return cmd_err(argv[2]);
    if (!strcmp(argv[1], "blk") && argc > 3) return cmd_blk(argv[2], argv[3]);
    if (!strcmp(argv[1], "fuzz") && argc > 4) return cmd_fuzz(argv[2], atoi(argv[3]), atoi(argv[4]));
    if (!strcmp(argv[1], "bench") && argc > 3) return cmd_bench(argv[2], atof(argv[3]));
    if (!strcmp(argv[1], "xxh")) return cmd_xxh(argv[2]);
    return 2;
}
