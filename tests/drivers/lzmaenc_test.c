/*
 * lzmaenc_test - driver for the LZMA / LZMA2 encoder tests (tests/cases/codec_lzmaenc.py)
 *
 *   lzmaenc_test enc <fmt> <level> <in|-> <out|-> [key=value ...]
 *       fmt:  alone      .lzma file (13-byte header with the size; stdin: size -1 + end marker)
 *             alone-eos  .lzma file with size -1 and an end marker
 *             raw1       raw LZMA with end marker      (xz --format=raw --lzma1=...)
 *             raw1-noeos raw LZMA without end marker
 *             raw2       raw LZMA2 stream              (xz --format=raw --lzma2=dict=...)
 *       keys: dict lc lp pb nice depth mf=hc4|bt4 mode=fast|normal extreme=1 hint=N
 *             norm=N (renormalise every N positions)  rchunk=N (max bytes per read call)
 *             failread=N / failwrite=N (callback returns an error after N bytes)
 *             reuse=1 (encode twice with the same encoder, both outputs must match)
 *       stderr: "in=.. out=.. sec=.. rss_kb=.. props=.. dict=.. dprop=.."
 *       exit: 0 ok, 3 encode error (code printed), 4 reuse mismatch, 1 usage / io
 *   lzmaenc_test gen <text|random|zeros|mixed|binary> <size> <seed>    synthetic data to stdout
 *   lzmaenc_test selftest                                                 API checks
 *   lzmaenc_test stress <iterations> <seed>   random data + options in-process: LZMA2 chunk
 *                                             structure, read-size independence, reuse
 */
#include "lzma_enc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/stat.h>

#ifdef LZMAENC_STANDALONE
/* Built from the encoder sources alone (cross-architecture runs: -m32, AArch64 under
 * QEMU) instead of the host core objects: plain libc allocator. */
void *gz_alloc(size_t n) { return calloc(1, n ? n : 1); }
void *gz_realloc(void *p, size_t n) { return realloc(p, n); }
void gz_free(void *p) { free(p); }
void *gz_alloc_big(size_t n) { return calloc(1, n); }
void gz_free_big(void *p, size_t n) { (void)n; free(p); }
#endif

typedef struct {
    FILE *in, *out;
    const u8 *mem; size_t mem_n, mem_pos;    /* memory input when in == NULL */
    u8 *obuf; size_t on, ocap;               /* memory output when out == NULL */
    u64 nin, nout;
    u64 failread, failwrite;                 /* 0 = off */
    u32 rchunk;
} io_ctx;

static int rd(void *c, u8 *buf, u32 cap, u32 *got)
{
    io_ctx *x = (io_ctx *)c;
    *got = 0;
    if (x->rchunk && cap > x->rchunk) cap = x->rchunk;
    if (x->failread && x->nin >= x->failread) return GZ_E_IO;
    if (x->failread && x->nin + cap > x->failread) cap = (u32)(x->failread - x->nin);
    size_t n;
    if (x->in) {
        n = fread(buf, 1, cap, x->in);
        if (!n && ferror(x->in)) return GZ_E_IO;
    } else {
        n = x->mem_n - x->mem_pos;
        if (n > cap) n = cap;
        memcpy(buf, x->mem + x->mem_pos, n);
        x->mem_pos += n;
    }
    *got = (u32)n;
    x->nin += n;
    return GZ_OK;
}

static int wr(void *c, const u8 *p, size_t n)
{
    io_ctx *x = (io_ctx *)c;
    if (x->failwrite && x->nout + n > x->failwrite) return GZ_E_CANCEL;
    x->nout += n;
    if (x->out) return fwrite(p, 1, n, x->out) == n ? GZ_OK : GZ_E_IO;
    if (x->on + n > x->ocap) {
        size_t nc = (x->ocap ? x->ocap * 2 : 65536);
        while (nc < x->on + n) nc *= 2;
        x->obuf = realloc(x->obuf, nc);
        x->ocap = nc;
    }
    memcpy(x->obuf + x->on, p, n);
    x->on += n;
    return GZ_OK;
}

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static double cpu_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* ---------------- synthetic data ---------------- */

static u64 rng_s;
static u32 rnd(void)
{
    rng_s = rng_s * 6364136223846793005ull + 1442695040888963407ull;
    return (u32)(rng_s >> 33);
}

static const char *words[] = {
    "the", "of", "and", "archive", "compression", "dictionary", "match", "literal", "encoder",
    "고기", "삼겹살", "목살", "갈비", "압축", "파일", "폴더", "바이트", "range", "coder", "window",
    "Hangul", "UTF-8", "price", "optimal", "parser", "\n", ", ", ". ", "(", ")", "0x1F", "2048",
};

static void gen(const char *kind, u64 size, u64 seed)
{
    static u8 buf[1 << 16];
    rng_s = seed * 2654435761u + 7;
    u64 done = 0;
    int mode = !strcmp(kind, "random") ? 1 : !strcmp(kind, "zeros") ? 2 :
               !strcmp(kind, "mixed") ? 3 : !strcmp(kind, "binary") ? 4 : 0;
    int seg = 0;
    u32 seg_left = 0;
    while (done < size) {
        size_t n = 0;
        while (n < sizeof buf - 64) {
            int m = mode;
            if (mode == 3) {
                if (!seg_left) { seg = rnd() % 4; seg_left = 1000 + rnd() % 300000; }
                m = seg == 0 ? 0 : seg == 1 ? 1 : seg == 2 ? 4 : 2;
            }
            u32 k;
            if (m == 0) {
                const char *w = words[rnd() % (sizeof words / sizeof words[0])];
                k = (u32)strlen(w);
                memcpy(buf + n, w, k);
                if (w[0] != '\n') buf[n + k++] = ' ';
            } else if (m == 1) {
                u32 v = rnd();
                k = 4;
                memcpy(buf + n, &v, 4);
            } else if (m == 2) {
                k = 16;
                memset(buf + n, 0, 16);
            } else {
                /* structured binary: small integers, repeated records */
                u32 v = rnd();
                k = 8;
                u32 a = (v & 0xFF) < 200 ? (v >> 8) & 0xFF : v;
                memcpy(buf + n, &a, 4);
                u32 b = (u32)(done + n) / 64;
                memcpy(buf + n + 4, &b, 4);
            }
            n += k;
            if (seg_left) seg_left = seg_left > k ? seg_left - k : 0;
        }
        if (n > size - done) n = (size_t)(size - done);
        fwrite(buf, 1, n, stdout);
        done += n;
    }
}

/* ---------------- options ---------------- */

static int parse_opts(gz_lzma_enc_opts *o, io_ctx *x, int *reuse, int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        char *eq = strchr(argv[i], '=');
        if (!eq) return -1;
        *eq = 0;
        const char *k = argv[i], *v = eq + 1;
        unsigned long long n = strtoull(v, 0, 0);
        if (!strcmp(k, "dict")) o->dict_size = (u32)n;
        else if (!strcmp(k, "lc")) o->lc = (u8)n;
        else if (!strcmp(k, "lp")) o->lp = (u8)n;
        else if (!strcmp(k, "pb")) o->pb = (u8)n;
        else if (!strcmp(k, "nice")) o->nice_len = (u32)n;
        else if (!strcmp(k, "depth")) o->depth = (u32)n;
        else if (!strcmp(k, "mf")) o->mf = !strcmp(v, "bt4") ? GZ_MF_BT4 : GZ_MF_HC4;
        else if (!strcmp(k, "mode")) o->mode = !strcmp(v, "fast") ? GZ_LZMA_FAST : GZ_LZMA_NORMAL;
        else if (!strcmp(k, "hint")) o->size_hint = n;
        else if (!strcmp(k, "norm")) o->test_norm_step = (u32)n;
        else if (!strcmp(k, "rchunk")) x->rchunk = (u32)n;
        else if (!strcmp(k, "failread")) x->failread = n;
        else if (!strcmp(k, "failwrite")) x->failwrite = n;
        else if (!strcmp(k, "reuse")) *reuse = (int)n;
        else if (!strcmp(k, "extreme")) continue;    /* applied before the overrides */
        else return -1;
    }
    return 0;
}

static int do_encode(gz_lzma_enc *e, const char *fmt, io_ctx *x, u64 insize, u8 *props, u8 *dprop)
{
    gz_stream_io io = { rd, wr, x };
    if (!strcmp(fmt, "raw2")) return gz_lzma2_encode(e, &io, dprop);
    int eos = strcmp(fmt, "raw1-noeos") != 0;
    if (!strncmp(fmt, "alone", 5)) {
        u8 h[13];
        gz_lzma_enc_props(e, h);
        u64 sz = (!strcmp(fmt, "alone") && insize != ~0ull) ? insize : ~0ull;
        eos = sz == ~0ull;
        memcpy(h + 5, &sz, 8);
        int r = wr(x, h, 13);
        if (r) return r;
    }
    return gz_lzma_encode(e, &io, props, eos);
}

static int cmd_enc(int argc, char **argv)
{
    if (argc < 4) return 1;
    const char *fmt = argv[0];
    int level = atoi(argv[1]);
    gz_lzma_enc_opts o;
    io_ctx x;
    int reuse = 0;
    memset(&x, 0, sizeof x);
    gz_lzma_enc_opts_init(&o, level);
    for (int i = 4; i < argc; i++)
        if (!strcmp(argv[i], "extreme=1")) gz_lzma_enc_opts_init(&o, level | GZ_LZMA_EXTREME);
    if (parse_opts(&o, &x, &reuse, argc - 4, argv + 4)) { fprintf(stderr, "bad option\n"); return 1; }
    u64 insize = ~0ull;
    if (strcmp(argv[2], "-")) {
        struct stat st;
        x.in = fopen(argv[2], "rb");
        if (!x.in || fstat(fileno(x.in), &st)) { perror(argv[2]); return 1; }
        insize = (u64)st.st_size;
    } else x.in = stdin;
    x.out = strcmp(argv[3], "-") ? fopen(argv[3], "wb") : stdout;
    if (!x.out) { perror(argv[3]); return 1; }
    int chk = gz_lzma_enc_check(&o, !strcmp(fmt, "raw2"));
    gz_lzma_enc *e = gz_lzma_enc_new(&o);
    if (!e) { fprintf(stderr, "new failed (check=%d)\n", chk); printf("err=%d\n", chk ? chk : GZ_E_NOMEM); return 3; }
    u8 props[5] = { 0 }, dprop = 0xFF;
    double t0 = now(), c0 = cpu_now();
    int r = do_encode(e, fmt, &x, insize, props, &dprop);
    double t1 = now(), c1 = cpu_now();
    if (!r && reuse && x.in != stdin) {
        /* second pass with the same encoder into memory: must give the same bytes */
        FILE *o1 = x.out;
        fflush(o1);
        long n1 = ftell(o1);
        rewind(x.in);
        io_ctx y = x;
        y.out = 0; y.nin = y.nout = 0;
        r = do_encode(e, fmt, &y, insize, props, &dprop);
        FILE *chk_f = fopen(argv[3], "rb");
        u8 *a = malloc(n1 > 0 ? n1 : 1);
        size_t ga = chk_f ? fread(a, 1, n1, chk_f) : 0;
        if (chk_f) fclose(chk_f);
        if (!r && ((long)y.on != n1 || ga != (size_t)n1 || memcmp(a, y.obuf, n1))) {
            fprintf(stderr, "reuse mismatch %ld vs %zu\n", n1, y.on);
            return 4;
        }
        free(a);
        free(y.obuf);
    }
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    long rss = ru.ru_maxrss;      /* Linux keeps the parent's peak across exec: prefer VmHWM */
    FILE *ps = fopen("/proc/self/status", "r");
    if (ps) {
        char line[256];
        while (fgets(line, sizeof line, ps))
            if (!strncmp(line, "VmHWM:", 6)) rss = atol(line + 6);
        fclose(ps);
    }
    fprintf(stderr, "in=%llu out=%llu sec=%.4f cpu=%.4f rss_kb=%ld mem_kb=%llu props=%02x dict=%u dprop=%d enc_in=%llu enc_out=%llu\n",
            (unsigned long long)x.nin, (unsigned long long)x.nout, t1 - t0, c1 - c0, rss,
            (unsigned long long)(gz_lzma_enc_memusage(&o, !strcmp(fmt, "raw2")) >> 10), props[0],
            (unsigned)(props[1] | props[2] << 8 | props[3] << 16 | (u32)props[4] << 24), dprop,
            (unsigned long long)gz_lzma_enc_in_size(e), (unsigned long long)gz_lzma_enc_out_size(e));
    gz_lzma_enc_free(e);
    if (x.out != stdout) fclose(x.out);
    if (r) { printf("err=%d\n", r); return 3; }
    return 0;
}

/* ---------------- API self test ---------------- */

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

static u8 *enc_mem(gz_lzma_enc *e, int lz2, const u8 *in, size_t n, size_t *on, int *rc)
{
    io_ctx x;
    memset(&x, 0, sizeof x);
    x.mem = in; x.mem_n = n;
    gz_stream_io io = { rd, wr, &x };
    u8 props[5], dp;
    *rc = lz2 ? gz_lzma2_encode(e, &io, &dp) : gz_lzma_encode(e, &io, props, 1);
    *on = x.on;
    return x.obuf;
}

static int selftest(void)
{
    gz_lzma_enc_opts o;
    for (int lv = 0; lv <= 9; lv++) {
        gz_lzma_enc_opts_init(&o, lv);
        CHECK(gz_lzma_enc_check(&o, 1) == GZ_OK, "level %d defaults rejected", lv);
        CHECK(gz_lzma_enc_memusage(&o, 0) > o.dict_size, "memusage level %d", lv);
    }
    gz_lzma_enc_opts_init(&o, -1);
    CHECK(o.level == 5 && o.dict_size == 8u << 20 && o.nice_len == 32, "negative level -> 5");
    gz_lzma_enc_opts_init(&o, 100);
    CHECK(o.level == 9 && o.dict_size == 64u << 20, "level 100 -> 9");
    gz_lzma_enc_opts_init(&o, 9 | GZ_LZMA_EXTREME);
    CHECK(o.nice_len == 273 && o.depth == 512 && o.mf == GZ_MF_BT4, "9e");
    gz_lzma_enc_opts_init(&o, 1 | GZ_LZMA_EXTREME);
    CHECK(o.mode == GZ_LZMA_NORMAL && o.mf == GZ_MF_BT4 && o.dict_size == 1u << 20, "1e");
    gz_lzma_enc_opts_init(&o, 6);
    gz_lzma_enc_opts b = o; b.lc = 9; CHECK(gz_lzma_enc_check(&b, 0) == GZ_E_METHOD, "lc 9");
    b = o; b.lp = 5; CHECK(gz_lzma_enc_check(&b, 0) == GZ_E_METHOD, "lp 5");
    b = o; b.pb = 5; CHECK(gz_lzma_enc_check(&b, 0) == GZ_E_METHOD, "pb 5");
    b = o; b.nice_len = 4; CHECK(gz_lzma_enc_check(&b, 0) == GZ_E_METHOD, "nice 4");
    b = o; b.nice_len = 274; CHECK(gz_lzma_enc_check(&b, 0) == GZ_E_METHOD, "nice 274");
    b = o; b.dict_size = 1000; CHECK(gz_lzma_enc_check(&b, 0) == GZ_E_METHOD, "dict 1000");
    b = o; b.dict_size = GZ_LZMA_DICT_MAX + 1; CHECK(gz_lzma_enc_check(&b, 0) == GZ_E_LIMIT, "dict max");
    b = o; b.mode = 7; CHECK(gz_lzma_enc_check(&b, 0) == GZ_E_METHOD, "mode");
    b = o; b.mf = 9; CHECK(gz_lzma_enc_check(&b, 0) == GZ_E_METHOD, "mf");
    b = o; b.depth = (1u << 30) + 1; CHECK(gz_lzma_enc_check(&b, 0) == GZ_E_LIMIT, "depth");
#if UINTPTR_MAX <= 0xFFFFFFFFu
    /* 32-bit: 128 MiB BT4 needs ~1.3 GiB (over the cap), HC4 fits */
    b = o; b.dict_size = 128u << 20;
    CHECK(gz_lzma_enc_check(&b, 1) == GZ_E_LIMIT && gz_lzma_enc_new(&b) == NULL, "32-bit memory cap");
    b.mf = GZ_MF_HC4; b.mode = GZ_LZMA_FAST;
    CHECK(gz_lzma_enc_check(&b, 1) == GZ_OK, "32-bit HC4 128 MiB");
    CHECK(GZ_LZMA_DICT_MAX == 128u << 20, "32-bit dict max");
#else
    b = o; b.dict_size = GZ_LZMA_DICT_MAX;
    CHECK(gz_lzma_enc_check(&b, 1) == GZ_OK && gz_lzma_enc_memusage(&b, 1) > (u64)GZ_LZMA_DICT_MAX * 9,
          "64-bit 1.5 GiB dictionary");
#endif
    b = o; b.lc = 4; b.lp = 1;
    CHECK(gz_lzma_enc_check(&b, 0) == GZ_OK && gz_lzma_enc_check(&b, 1) == GZ_E_METHOD, "lc+lp lzma2");
    CHECK(gz_lzma_enc_new(&(gz_lzma_enc_opts){ 0 }) == NULL, "zeroed opts accepted");

    /* LZMA2 with lc + lp > 4 */
    {
        gz_lzma_enc *e = gz_lzma_enc_new(&b);
        CHECK(e != NULL, "new lc4 lp1");
        size_t on; int r;
        u8 *p = enc_mem(e, 1, (const u8 *)"abc", 3, &on, &r);
        CHECK(r == GZ_E_METHOD && on == 0, "lzma2 lc+lp>4 r=%d", r);
        free(p);
        p = enc_mem(e, 0, (const u8 *)"abc", 3, &on, &r);
        CHECK(r == GZ_OK && on > 5, "lzma lc4 lp1 r=%d", r);
        free(p);
        gz_lzma_enc_free(e);
    }
    /* properties */
    {
        gz_lzma_enc_opts_init(&o, 6);
        o.lc = 1; o.lp = 2; o.pb = 3; o.dict_size = 5000;
        gz_lzma_enc *e = gz_lzma_enc_new(&o);
        u8 pr[5];
        gz_lzma_enc_props(e, pr);
        CHECK(pr[0] == (3 * 5 + 2) * 9 + 1, "props byte %02x", pr[0]);
        CHECK(pr[1] == 0 && pr[2] == 0x18 && pr[3] == 0 && pr[4] == 0, "dict 5000 -> 6144");
        CHECK(gz_lzma2_enc_dict_prop(e) == 1, "dict prop %d", gz_lzma2_enc_dict_prop(e));
        gz_lzma_enc_free(e);
        gz_lzma_enc_opts_init(&o, 9);
        o.size_hint = 100000;
        e = gz_lzma_enc_new(&o);
        gz_lzma_enc_props(e, pr);
        CHECK(rd32(pr + 1) == 128 << 10, "hint dict %u", rd32(pr + 1));
        CHECK(gz_lzma2_enc_dict_prop(e) == 10, "hint dprop %d", gz_lzma2_enc_dict_prop(e));
        gz_lzma_enc_free(e);
        gz_lzma_enc_opts_init(&o, 9);
        e = gz_lzma_enc_new(&o);
        CHECK(gz_lzma2_enc_dict_prop(e) == 28, "L9 dprop %d", gz_lzma2_enc_dict_prop(e));
        gz_lzma_enc_free(e);
    }
    /* reuse: one encoder for many streams gives the same bytes as fresh encoders */
    {
        size_t n = 3 << 20;
        u8 *data = malloc(n);
        rng_s = 99;
        for (size_t i = 0; i < n; i++) data[i] = (i / 997) & 1 ? (u8)rnd() : (u8)"0123456789abcdef"[(i * 7 + i / 13) & 15];
        for (int lv = 1; lv <= 9; lv += 5) {
            for (int lz2 = 0; lz2 < 2; lz2++) {
                gz_lzma_enc_opts_init(&o, lv);
                o.dict_size = 1 << 20;
                gz_lzma_enc *e = gz_lzma_enc_new(&o);
                size_t sizes[3] = { n, 777, n / 2 }, on1, on2;
                for (int k = 0; k < 3; k++) {
                    int r1, r2;
                    u8 *a = enc_mem(e, lz2, data + k, sizes[k], &on1, &r1);
                    gz_lzma_enc *f = gz_lzma_enc_new(&o);
                    u8 *c = enc_mem(f, lz2, data + k, sizes[k], &on2, &r2);
                    gz_lzma_enc_free(f);
                    CHECK(!r1 && !r2 && on1 == on2 && !memcmp(a, c, on1), "reuse L%d lz2=%d k=%d", lv, lz2, k);
                    free(a); free(c);
                }
                gz_lzma_enc_free(e);
            }
        }
        /* error propagation */
        gz_lzma_enc_opts_init(&o, 5);
        gz_lzma_enc *e = gz_lzma_enc_new(&o);
        for (int lz2 = 0; lz2 < 2; lz2++) {
            io_ctx x;
            gz_stream_io io = { rd, wr, &x };
            u8 pr[5];
            memset(&x, 0, sizeof x); x.mem = data; x.mem_n = n; x.failread = 1500000;
            int r = lz2 ? gz_lzma2_encode(e, &io, 0) : gz_lzma_encode(e, &io, pr, 1);
            CHECK(r == GZ_E_IO, "read error lz2=%d r=%d", lz2, r);
            free(x.obuf);
            memset(&x, 0, sizeof x); x.mem = data; x.mem_n = n; x.failwrite = 20000;
            r = lz2 ? gz_lzma2_encode(e, &io, 0) : gz_lzma_encode(e, &io, pr, 1);
            CHECK(r == GZ_E_CANCEL, "write error lz2=%d r=%d", lz2, r);
            free(x.obuf);
            memset(&x, 0, sizeof x); x.mem = data; x.mem_n = n; x.failwrite = 1;
            r = lz2 ? gz_lzma2_encode(e, &io, 0) : gz_lzma_encode(e, &io, pr, 1);
            CHECK(r == GZ_E_CANCEL, "write error at start lz2=%d r=%d", lz2, r);
            free(x.obuf);
        }
        gz_lzma_enc_free(e);
        free(data);
    }
    gz_lzma_enc_free(NULL);
    fprintf(stderr, "selftest: %d failures\n", fails);
    return fails ? 2 : 0;
}

/* ---------------- in-process stress (run under ASan/UBSan) ---------------- */

/* LZMA2 chunk structure: limits, reset/property flags, the range coder's leading 0,
 * the encoder's "LZMA chunks shrink" rule and the total unpacked size. */
static const char *check_lzma2(const u8 *p, size_t n, u64 want, u8 props)
{
    size_t pos = 0;
    u64 total = 0;
    int first = 1, need_props = 1;
    for (;;) {
        if (pos >= n) return "no end byte";
        u32 c = p[pos];
        if (c == 0) return pos + 1 == n ? (total == want ? NULL : "unpacked total") : "data after end";
        if (c == 1 || c == 2) {
            if (first && c != 1) return "first chunk without dictionary reset";
            if (pos + 3 > n) return "truncated copy header";
            u32 u = ((u32)p[pos + 1] << 8 | p[pos + 2]) + 1;
            pos += 3 + (size_t)u;
            total += u;
            if (c == 1) need_props = 1;
        } else if (c >= 0x80) {
            if (first && c < 0xE0) return "first LZMA chunk without dictionary reset";
            if (need_props && c < 0xC0) return "LZMA chunk without properties";
            if (pos + 6 > n) return "truncated LZMA header";
            u32 u = ((c & 0x1F) << 16 | (u32)p[pos + 1] << 8 | p[pos + 2]) + 1;
            u32 pk = ((u32)p[pos + 3] << 8 | p[pos + 4]) + 1;
            size_t hl = c >= 0xC0 ? 6 : 5;
            if (hl == 6 && p[pos + 5] != props) return "properties byte";
            if (pk + 2 >= u) return "LZMA chunk does not shrink";
            if (pos + hl + pk > n || p[pos + hl] != 0) return "range coder start";
            pos += hl + pk;
            total += u;
            need_props = 0;
        } else return "bad control byte";
        first = 0;
    }
}

/* Test data: random bytes, runs, a small alphabet, counters and copies of earlier
 * pieces (near and far, long and short) so every match kind and rep shows up. */
static void stress_data(u8 *d, size_t n)
{
    size_t i = 0;
    while (i < n) {
        size_t k = 1 + rnd() % (rnd() % 8 ? 300 : 5000);
        if (k > n - i) k = n - i;
        u32 kind = rnd() % 6, a = rnd();
        if (kind == 0) for (size_t j = 0; j < k; j++) d[i + j] = (u8)rnd();
        else if (kind == 1) memset(d + i, (int)(a & 0xFF), k);
        else if (kind == 2) for (size_t j = 0; j < k; j++) d[i + j] = (u8)("ab\nc "[rnd() % 5]);
        else if (kind == 3) for (size_t j = 0; j < k; j++) d[i + j] = (u8)(a + j * (a >> 24 & 3));
        else if (i) {                                 /* copy, maybe overlapping, maybe edited */
            size_t dist = 1 + (kind == 4 ? rnd() % (i < 64 ? i : 64) : rnd() % i);
            for (size_t j = 0; j < k; j++) d[i + j] = d[i + j - dist];
            if (rnd() % 3 == 0) d[i + rnd() % k] ^= (u8)(1 + rnd() % 255);
        } else d[i] = (u8)a, k = 1;
        i += k;
    }
}

static int stress(int iters, u64 seed)
{
    static const u32 dicts[] = { 4096, 4097, 6000, 65536, 1u << 20, 3u << 20 };
    static const u32 nices[] = { 5, 6, 17, 32, 64, 128, 200, 272, 273 };
    static const u32 depths[] = { 0, 1, 2, 7, 48, 1000 };
    rng_s = seed * 0x9E3779B97F4A7C15ull + 1;
    for (int it = 0; it < iters; it++) {
        gz_lzma_enc_opts o;
        gz_lzma_enc_opts_init(&o, (int)(rnd() % 10) | (rnd() % 8 == 0 ? GZ_LZMA_EXTREME : 0));
        int lz2 = rnd() & 1;
        o.lc = (u8)(rnd() % 5);
        o.lp = (u8)(rnd() % (5 - o.lc));
        if (!lz2 && rnd() % 6 == 0) { o.lc = (u8)(rnd() % 9); o.lp = (u8)(rnd() % 5); }
        o.pb = (u8)(rnd() % 5);
        if (rnd() & 1) o.dict_size = dicts[rnd() % 6];
        if (rnd() & 1) o.nice_len = nices[rnd() % 9];
        if (rnd() & 1) o.depth = depths[rnd() % 6];
        if (rnd() % 4 == 0) o.mf = (u8)(rnd() & 1);
        if (rnd() % 4 == 0) o.mode = (u8)(rnd() & 1);
        size_t n = rnd() % 40 == 0 && o.mode == GZ_LZMA_FAST ? (2u << 20) + rnd() % 300000
                                                             : rnd() % (1u << (rnd() % 18));
        if (rnd() % 5 == 0) o.size_hint = (u64[]){ n, n / 3 + 1, n * 5 + 1, 1 }[rnd() % 4];
        if (rnd() % 5 == 0) o.test_norm_step = 1000 + rnd() % 70000;
        u8 *d = malloc(n + 1);
        stress_data(d, n);
        gz_lzma_enc *e = gz_lzma_enc_new(&o);
        if (!e) {
            fprintf(stderr, "stress #%d: new failed (check %d)\n", it, gz_lzma_enc_check(&o, 0));
            return 2;
        }
        u8 props[5] = { 0 }, dp = 0;
        int eos = (int)(rnd() & 1);
        u8 *out[2] = { 0 };
        size_t on[2] = { 0 };
        for (int pass = 0; pass < 2; pass++) {    /* same encoder, other read sizes: same bytes */
            io_ctx x;
            memset(&x, 0, sizeof x);
            x.mem = d; x.mem_n = n;
            x.rchunk = rnd() % 3 ? 0 : 1 + rnd() % (rnd() & 1 ? 7 : 70000);
            gz_stream_io io = { rd, wr, &x };
            int r = lz2 ? gz_lzma2_encode(e, &io, &dp) : gz_lzma_encode(e, &io, props, eos);
            if (r || (lz2 && gz_lzma_enc_in_size(e) != n) || gz_lzma_enc_out_size(e) != x.on) {
                fprintf(stderr, "stress #%d pass %d: r=%d in=%llu out=%llu/%zu\n", it, pass, r,
                        (unsigned long long)gz_lzma_enc_in_size(e), (unsigned long long)gz_lzma_enc_out_size(e), x.on);
                return 2;
            }
            out[pass] = x.obuf;
            on[pass] = x.on;
        }
        const char *why = NULL;
        if (lz2) why = check_lzma2(out[0], on[0], n, (u8)((o.pb * 5 + o.lp) * 9 + o.lc));
        else if (on[0] < 5 || out[0][0] != 0) why = "range coder start";
        if (!why && (on[0] != on[1] || memcmp(out[0], out[1], on[0]))) why = "not deterministic";
        if (why) {
            fprintf(stderr, "stress #%d (%s, %zu B, lc%u lp%u pb%u dict %u nice %u depth %u mf %u mode %u): %s\n",
                    it, lz2 ? "lzma2" : "lzma", n, o.lc, o.lp, o.pb, o.dict_size, o.nice_len, o.depth, o.mf,
                    o.mode, why);
            return 2;
        }
        free(out[0]);
        free(out[1]);
        free(d);
        gz_lzma_enc_free(e);
    }
    fprintf(stderr, "stress: %d runs ok\n", iters);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "enc")) return cmd_enc(argc - 2, argv + 2);
    if (argc >= 5 && !strcmp(argv[1], "gen")) {
        gen(argv[2], strtoull(argv[3], 0, 0), strtoull(argv[4], 0, 0));
        return 0;
    }
    if (argc >= 2 && !strcmp(argv[1], "selftest")) return selftest();
    if (argc >= 4 && !strcmp(argv[1], "stress")) return stress(atoi(argv[2]), strtoull(argv[3], 0, 0));
    fprintf(stderr, "usage: lzmaenc_test enc|gen|selftest|stress ...\n");
    return 1;
}
