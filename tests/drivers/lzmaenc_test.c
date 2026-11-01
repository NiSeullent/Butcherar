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
 */
#include "lzma_enc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/stat.h>

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

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "enc")) return cmd_enc(argc - 2, argv + 2);
    if (argc >= 5 && !strcmp(argv[1], "gen")) {
        gen(argv[2], strtoull(argv[3], 0, 0), strtoull(argv[4], 0, 0));
        return 0;
    }
    if (argc >= 2 && !strcmp(argv[1], "selftest")) return selftest();
    fprintf(stderr, "usage: lzmaenc_test enc|gen|selftest ...\n");
    return 1;
}
