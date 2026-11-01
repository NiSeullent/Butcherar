/*
 * PPMd codec test driver (tests/cases/codec_ppmd.py).
 *
 *   ppmd_test d7 ORDER MEM SIZE|u IN OUT       7z PPMd stream -> raw            (Ppmd7, 7z coder)
 *   ppmd_test e7 ORDER MEM IN OUT              raw -> 7z PPMd stream
 *   ppmd_test d8 SIZE|u IN OUT                 ZIP method 98 data -> raw        (Ppmd8)
 *   ppmd_test e8 ORDER MEM_MB RESTORE IN OUT   raw -> ZIP method 98 data
 *   ppmd_test zip IN.zip OUT                   single-entry ZIP, method 98 (CRC checked)
 *   ppmd_test 7z IN.7z OUT                     7z with one PPMd folder, -mhc=off layout
 *   ppmd_test erar SPEC ESC IN OUT             raw -> RAR 3.x packed data (PPM blocks only)
 *        SPEC = ORDER:MEM_MB:LEN,...  one PPM block per item (LEN bytes, 0 = rest);
 *        ORDER 0 continues the previous model (no reset, range coder re-initialised)
 *   ppmd_test drar SIZE IN OUT                 RAR 3.x PPM-only packed data -> raw
 *   ppmd_test rctest SEED N IN                 RAR range decoder op trace (for replay)
 *   ppmd_test level LEVEL SIZE|u               7-Zip's default 7z / ZIP parameters
 *   ppmd_test fuzz7 ORDER MEM SIZE ITERS SEED IN   truncated / bit-flipped 7z streams
 *   ppmd_test fuzz8 SIZE ITERS SEED IN             truncated / bit-flipped ZIP streams
 *   ppmd_test fuzzrar SIZE ITERS SEED IN           truncated / bit-flipped RAR PPM blocks
 *
 * Prints "rc=<code> in=<bytes used> out=<bytes> ms=<time>" and exits 0 when rc == 0,
 * 1 on a codec error, 2 on usage / IO problems.
 */
#include "ppmd7.h"
#include "ppmd8.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef PPMD_TEST_STANDALONE
/* Build without the host objects (gcc -m32, aarch64 under qemu):
 *   cc -std=gnu11 -O2 -DPPMD_TEST_STANDALONE -Isrc/core -Isrc/codec \
 *      tests/drivers/ppmd_test.c src/codec/ppmd7.c src/codec/ppmd8.c                    */
void *gz_alloc(size_t n) { return calloc(1, n ? n : 1); }
void *gz_realloc(void *p, size_t n) { return realloc(p, n); }
void gz_free(void *p) { free(p); }
void *gz_alloc_big(size_t n) { return calloc(1, n ? n : 1); }
void gz_free_big(void *p, size_t n) { (void)n; free(p); }
static u32 gz_crc32(u32 crc, const void *p, size_t n)
{
    const u8 *b = (const u8 *)p;
    crc = ~crc;
    while (n--) {
        int k;
        crc ^= *b++;
        for (k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1)));
    }
    return ~crc;
}
#else
#include "crc32.h"
#include "cpu.h"
#endif

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

/* buffers freed at exit, so that LeakSanitizer only reports codec leaks */
static void *g_ptrs[64];
static int g_np;
static void *track(void *p)
{
    if (g_np < (int)(sizeof g_ptrs / sizeof g_ptrs[0])) g_ptrs[g_np++] = p;
    return p;
}
static void free_all(void)
{
    while (g_np) free(g_ptrs[--g_np]);
}

static u8 *load(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    u8 *p;
    long sz;
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    p = (u8 *)track(malloc(sz ? (size_t)sz : 1));
    if (sz && fread(p, 1, (size_t)sz, f) != (size_t)sz) { perror(path); exit(2); }
    fclose(f);
    *n = (size_t)sz;
    return p;
}

/* memory reader (small random chunks to exercise refills) + memory sink */
typedef struct {
    const u8 *p;
    size_t n, pos;
    u32 chunk;
    u8 *out;
    size_t on, ocap;
    int fail_after;            /* sink error after this many writes (-1: never) */
    u32 crc;
} mio;

static int m_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    mio *m = (mio *)ctx;
    size_t k = m->n - m->pos;
    if (k > cap) k = cap;
    if (m->chunk && k > m->chunk) k = m->chunk;
    memcpy(buf, m->p + m->pos, k);
    m->pos += k;
    *got = (u32)k;
    return GZ_OK;
}

static int m_write(void *ctx, const u8 *p, size_t n)
{
    mio *m = (mio *)ctx;
    if (m->fail_after == 0) return GZ_E_SKIP;
    if (m->fail_after > 0) m->fail_after--;
    if (m->on + n > m->ocap) {
        while (m->on + n > m->ocap) m->ocap = m->ocap ? m->ocap * 2 : 1 << 16;
        m->out = (u8 *)realloc(m->out, m->ocap);
    }
    memcpy(m->out + m->on, p, n);
    m->on += n;
    m->crc = gz_crc32(m->crc, p, n);
    return GZ_OK;
}

static void save(const char *path, const u8 *p, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f || (n && fwrite(p, 1, n, f) != n)) { perror(path); exit(2); }
    fclose(f);
}

static u64 parse_size(const char *s) { return strcmp(s, "u") ? strtoull(s, 0, 10) : GZ_SIZE_UNKNOWN; }

static int report(int rc, u64 in_used, size_t out, double ms)
{
    printf("rc=%d in=%llu out=%llu ms=%.1f\n", rc, (unsigned long long)in_used, (unsigned long long)out, ms);
    return rc ? 1 : 0;
}

static void mio_init(mio *m, const u8 *p, size_t n)
{
    memset(m, 0, sizeof(*m));
    m->p = p;
    m->n = n;
    m->fail_after = -1;
    if (getenv("PPMD_CHUNK")) m->chunk = (u32)atoi(getenv("PPMD_CHUNK"));
    if (getenv("PPMD_FAIL_AFTER")) m->fail_after = atoi(getenv("PPMD_FAIL_AFTER"));
}

/* ---------------- 7z: minimal parser for one PPMd folder, plain header ---------------- */

static const u8 *zp, *zend;
static int zerr;
static u64 z_num(void)
{
    u8 first, mask = 0x80;
    u64 v = 0;
    int i;
    if (zp >= zend) { zerr = 1; return 0; }
    first = *zp++;
    for (i = 0; i < 8; i++) {
        if (!(first & mask)) return v | ((u64)(first & (mask - 1)) << (8 * i));
        if (zp >= zend) { zerr = 1; return 0; }
        v |= (u64)*zp++ << (8 * i);
        mask >>= 1;
    }
    return v;
}
static u8 z_byte(void) { if (zp >= zend) { zerr = 1; return 0; } return *zp++; }

static int cmd_7z(const char *in, const char *out)
{
    size_t n;
    u8 *f = load(in, &n);
    u64 hoff, hsize, packpos, packsize = 0, unpack = 0;
    u32 order = 0, mem = 0;
    int found = 0;
    if (n < 32 || memcmp(f, "7z\xBC\xAF\x27\x1C", 6)) { fprintf(stderr, "not 7z\n"); return 2; }
    hoff = rd64(f + 12);
    hsize = rd64(f + 20);
    if (32 + hoff + hsize > n) { fprintf(stderr, "bad header pos\n"); return 2; }
    zp = f + 32 + hoff;
    zend = zp + hsize;
    if (z_byte() != 0x01 || z_byte() != 0x04 || z_byte() != 0x06) { fprintf(stderr, "unexpected layout (need -mhc=off)\n"); return 2; }
    packpos = z_num();
    if (z_num() != 1) { fprintf(stderr, "need one pack stream\n"); return 2; }
    for (;;) {
        u8 id = z_byte();
        if (zerr || id == 0) break;
        if (id == 0x09) packsize = z_num();
        else if (id == 0x0A) { fprintf(stderr, "pack crc unsupported\n"); return 2; }
    }
    if (z_byte() != 0x07 || z_byte() != 0x0B || z_num() != 1 || z_byte() != 0) { fprintf(stderr, "bad unpack info\n"); return 2; }
    if (z_num() != 1) { fprintf(stderr, "need one coder\n"); return 2; }
    {
        u8 flags = z_byte();
        u32 idsize = flags & 0xF;
        u8 id[16];
        u32 i;
        for (i = 0; i < idsize; i++) id[i] = z_byte();
        if ((flags & 0x10) || !(flags & 0x20) || idsize != 3 || id[0] != 3 || id[1] != 4 || id[2] != 1) {
            fprintf(stderr, "coder is not PPMd\n"); return 2;
        }
        if (z_num() != 5) { fprintf(stderr, "bad props\n"); return 2; }
        u8 props[5];
        for (i = 0; i < 5; i++) props[i] = z_byte();
        if (gz_ppmd7z_props(props, 5, &order, &mem)) { fprintf(stderr, "bad props\n"); return 2; }
    }
    if (z_byte() != 0x0C) { fprintf(stderr, "no unpack size\n"); return 2; }
    unpack = z_num();
    found = !zerr;
    if (!found || 32 + packpos + packsize > n) { fprintf(stderr, "truncated header\n"); return 2; }
    {
        mio m;
        gz_ppmd7 *p = gz_ppmd7_new();
        gz_stream_io io = { m_read, m_write, &m };
        u64 used = 0;
        double t;
        int rc;
        mio_init(&m, f + 32 + packpos, packsize);
        t = now_ms();
        rc = gz_ppmd7z_decode_ex(p, order, mem, &io, unpack, &used);
        t = now_ms() - t;
        save(out, m.out, m.on);
        free(m.out);
        printf("order=%u mem=%u packed=%llu ", order, mem, (unsigned long long)packsize);
        gz_ppmd7_free(p);
        return report(rc, used, m.on, t);
    }
}

/* ---------------- ZIP: one entry, method 98 ---------------- */

static int cmd_zip(const char *in, const char *out)
{
    size_t n, i;
    u8 *f = load(in, &n);
    const u8 *eocd = 0, *cd, *lh;
    u32 crc, csize, usize, loff;
    for (i = n >= 22 ? n - 22 : 0; i + 1 > 0 && i + 22 <= n; i--) {
        if (rd32(f + i) == 0x06054b50) { eocd = f + i; break; }
        if (i == 0) break;
    }
    if (!eocd) { fprintf(stderr, "no EOCD\n"); return 2; }
    cd = f + rd32(eocd + 16);
    if (cd + 46 > f + n || rd32(cd) != 0x02014b50) { fprintf(stderr, "bad CD\n"); return 2; }
    if (rd16(cd + 10) != 98) { fprintf(stderr, "method %u is not PPMd\n", rd16(cd + 10)); return 2; }
    crc = rd32(cd + 16);
    csize = rd32(cd + 20);
    usize = rd32(cd + 24);
    loff = rd32(cd + 42);
    lh = f + loff;
    if (lh + 30 > f + n || rd32(lh) != 0x04034b50) { fprintf(stderr, "bad local header\n"); return 2; }
    lh += 30 + rd16(lh + 26) + rd16(lh + 28);
    if (lh + csize > f + n) { fprintf(stderr, "truncated data\n"); return 2; }
    {
        mio m;
        gz_ppmd8 *p = gz_ppmd8_new();
        gz_stream_io io = { m_read, m_write, &m };
        u64 used = 0;
        double t;
        int rc;
        mio_init(&m, lh, csize);
        t = now_ms();
        rc = gz_ppmd8_zip_decode_ex(p, &io, usize, &used);
        t = now_ms() - t;
        if (!rc && m.crc != crc) rc = GZ_E_CRC;
        save(out, m.out, m.on);
        free(m.out);
        printf("hdr=%04x packed=%u ", rd16(lh), csize);
        gz_ppmd8_free(p);
        return report(rc, used, m.on, t);
    }
}

/* ---------------- RAR 3.x PPM blocks ---------------- */

static int cmd_erar(const char *spec, int esc, const char *in, const char *out)
{
    size_t n, pos = 0;
    u8 *f = load(in, &n);
    mio m;
    gz_stream_io io = { m_read, m_write, &m };
    gz_ppmd7 *p = gz_ppmd7_new();
    const char *s = spec;
    int first = 1, rc = 0, have_model = 0;
    double t = now_ms();
    mio_init(&m, 0, 0);
    while (*s) {
        unsigned order = 0, mb = 1;
        unsigned long len = 0;
        int k = 0;
        u8 hdr[3];
        u32 flags = 0, nh = 0;
        if (sscanf(s, "%u:%u:%lu%n", &order, &mb, &len, &k) < 3) { fprintf(stderr, "bad spec\n"); return 2; }
        s += k;
        if (*s == ',') s++;
        if (!*s || !len || len > n - pos) len = n - pos;
        if (!first) {
            /* end of the previous PPM block: esc, 0 (then the block header follows) */
            gz_ppmd7_rar_enc_symbol(p, esc);
            gz_ppmd7_rar_enc_symbol(p, 0);
            if ((rc = gz_ppmd7_rar_enc_end(p))) break;
        }
        if (order) {
            u32 o = order;
            if (o > 16) {
                if ((o - 16) % 3) { fprintf(stderr, "order %u not codable\n", o); return 2; }
                o = (o - 16) / 3 + 16;
            }
            flags = 0x20 | (o - 1);
        } else if (!have_model) { fprintf(stderr, "first block needs a model\n"); return 2; }
        if (first) flags |= 0x40;            /* set the escape character once */
        hdr[nh++] = (u8)(0x80 | flags);
        if (flags & 0x20) hdr[nh++] = (u8)(mb - 1);
        if (flags & 0x40) hdr[nh++] = (u8)esc;
        m_write(&m, hdr, nh);
        if (order) {
            if ((rc = gz_ppmd7_rar_enc_begin(p, order, mb << 20, &io))) break;
            have_model = 1;
        } else {
            /* continue the model: only re-initialise the range encoder */
            if ((rc = gz_ppmd7_rar_enc_begin_rc(p, &io))) break;
        }
        for (; len; len--, pos++) {
            int c = f[pos];
            gz_ppmd7_rar_enc_symbol(p, c);
            if (c == esc) gz_ppmd7_rar_enc_symbol(p, 1);   /* literal escape char */
        }
        first = 0;
    }
    if (!rc) {
        gz_ppmd7_rar_enc_symbol(p, esc);
        gz_ppmd7_rar_enc_symbol(p, 2);                     /* end of file */
        rc = gz_ppmd7_rar_enc_end(p);
    }
    t = now_ms() - t;
    save(out, m.out, m.on);
    free(m.out);
    gz_ppmd7_free(p);
    return report(rc, n, m.on, t);
}

/* Decode RAR 3.x PPM-only packed data the way the RAR decoder will drive the codec
 * (see ppmd7.h). Returns the status; *on bytes went to o (capacity size). */
static int rar_decode_buf(gz_ppmd7 *p, const u8 *f, size_t n, u8 *o, u64 size, u64 *on_out,
                          int *blocks_out, size_t *used)
{
    gz_ppmd_in bi;
    u64 on = 0;
    int esc = 2, rc = 0, blocks = 0;
    memset(&bi, 0, sizeof(bi));
    bi.cur = f;
    bi.end = f + n;
    gz_ppmd7_rar_drop(p);                     /* a new non-solid file */
    for (;;) {
        /* PPM block header (byte-aligned): 1 flag bit + 7 bits flags [, maxMB][, esc] */
        u32 b = gz_ppmd_in_byte(&bi), flags, maxmb = 0;
        if (bi.extra || !(b & 0x80)) { rc = bi.extra ? GZ_E_TRUNC : GZ_E_DATA; break; }
        flags = b & 0x7F;
        if (flags & 0x20) maxmb = gz_ppmd_in_byte(&bi);
        else if (!gz_ppmd7_rar_ready(p)) { rc = GZ_E_DATA; break; }
        if (flags & 0x40) esc = (int)gz_ppmd_in_byte(&bi);
        if ((rc = gz_ppmd7_rar_rc_init(p, &bi)) != GZ_OK) break;
        if (flags & 0x20) {
            u32 order = (flags & 0x1F) + 1;
            if (order > 16) order = 16 + (order - 16) * 3;
            if (order == 1) { gz_ppmd7_rar_drop(p); rc = GZ_E_DATA; break; }
            if ((rc = gz_ppmd7_rar_model(p, order, (maxmb + 1) << 20))) break;
        }
        blocks++;
        for (;;) {
            int c = gz_ppmd7_rar_decode(p), c2;
            if (c < 0 || bi.extra) { rc = bi.extra ? GZ_E_TRUNC : GZ_E_DATA; goto end; }
            if (c == esc) {
                c2 = gz_ppmd7_rar_decode(p);
                if (c2 < 0 || bi.extra) { rc = bi.extra ? GZ_E_TRUNC : GZ_E_DATA; goto end; }
                if (c2 == 0) break;                 /* next block */
                if (c2 == 2) goto end;              /* end of file */
                if (c2 == 3 || c2 == 4 || c2 == 5) { rc = GZ_E_METHOD; goto end; }   /* not produced by erar */
            }
            if (on >= size) { rc = GZ_E_DATA; goto end; }
            o[on++] = (u8)c;
        }
    }
end:
    if (!rc && on != size) rc = GZ_E_DATA;
    *on_out = on;
    *blocks_out = blocks;
    *used = (size_t)(bi.cur - f);
    return rc;
}

static int cmd_drar(u64 size, const char *in, const char *out)
{
    size_t n, used;
    u8 *f = load(in, &n);
    gz_ppmd7 *p = gz_ppmd7_new();
    u8 *o = (u8 *)track(malloc(size ? size : 1));
    u64 on = 0;
    int rc, blocks = 0;
    double t = now_ms();
    rc = rar_decode_buf(p, f, n, o, size, &on, &blocks, &used);
    t = now_ms() - t;
    save(out, o, (size_t)on);
    printf("blocks=%d ", blocks);
    gz_ppmd7_free(p);
    return report(rc, used, (size_t)on, t);
}

static void rc_cb(void *user, const u32 r[8])
{
    (void)user;
    printf("%u %u %u %u %u %u %u %u\n", r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
}

static int cmd_rctest(u32 seed, u32 nops, const char *in)
{
    size_t n;
    u8 *f = load(in, &n);
    gz_ppmd_in bi;
    gz_ppmd7 *p = gz_ppmd7_new();
    memset(&bi, 0, sizeof(bi));
    bi.cur = f;
    bi.end = f + n;
    gz_ppmd7_rar_rc_test(p, &bi, seed, nops, rc_cb, 0);
    gz_ppmd7_free(p);
    return 0;
}

/* Truncate at many lengths and flip bits; must never crash or hang (run under ASan). */
static int cmd_fuzz(int kind, const char *in, u32 a, u32 b, u64 size, u32 iters, u32 seed)
{
    size_t n, i;
    u8 *f = load(in, &n);
    u8 *g = (u8 *)track(malloc(n + 1));
    gz_ppmd7 *p7 = gz_ppmd7_new();
    gz_ppmd8 *p8 = gz_ppmd8_new();
    u32 x = seed | 1, cnt[16] = { 0 };
    u8 *rbuf = 0;
#define RND() (x ^= x << 13, x ^= x >> 17, x ^= x << 5, x)
    for (i = 0; i < iters; i++) {
        mio m;
        gz_stream_io io = { m_read, m_write, &m };
        size_t len = n;
        int rc;
        memcpy(g, f, n);
        if (i % 3 == 0) len = RND() % (n + 1);                       /* truncation */
        else {
            u32 k, nf = 1 + RND() % 4;
            for (k = 0; k < nf && n; k++) {
                u32 at = RND() % (u32)n, bit = RND() & 7;
                g[at] ^= (u8)(1u << bit);
            }
        }
        mio_init(&m, g, len);
        m.chunk = 1 + RND() % 5000;
        if (kind == 7) rc = gz_ppmd7z_decode(p7, a, b, &io, (i & 1) ? size : GZ_SIZE_UNKNOWN);
        else if (kind == 8) rc = gz_ppmd8_zip_decode(p8, &io, (i & 1) ? size : GZ_SIZE_UNKNOWN);
        else {
            u64 on;
            int blocks;
            size_t used;
            if (!rbuf) rbuf = (u8 *)track(malloc(size ? size : 1));
            rc = rar_decode_buf(p7, g, len, rbuf, size, &on, &blocks, &used);
        }
        if (m.on > size + 16 && size != GZ_SIZE_UNKNOWN && (i & 1)) { printf("overrun\n"); return 1; }
        cnt[rc & 15]++;
        free(m.out);
    }
#undef RND
    printf("fuzz ok:");
    for (i = 0; i < 16; i++) if (cnt[i]) printf(" e%zu=%u", i, cnt[i]);
    printf("\n");
    gz_ppmd7_free(p7);
    gz_ppmd8_free(p8);
    return 0;
}

int main(int argc, char **argv)
{
    atexit(free_all);
#ifndef PPMD_TEST_STANDALONE
    gz_cpu_detect();
    gz_crc32_init();
    gz_dispatch_init(-1);
#endif
    if (argc >= 7 && !strcmp(argv[1], "d7")) {
        size_t n;
        u8 *f = load(argv[5], &n);
        mio m;
        gz_stream_io io = { m_read, m_write, &m };
        gz_ppmd7 *p = gz_ppmd7_new();
        u64 used = 0;
        int rc, rep = getenv("PPMD_REPEAT") ? atoi(getenv("PPMD_REPEAT")) : 1;
        double t = 0;
        do {
            mio_init(&m, f, n);
            t = now_ms();
            rc = gz_ppmd7z_decode_ex(p, (u32)atoi(argv[2]), (u32)strtoul(argv[3], 0, 10), &io,
                                     parse_size(argv[4]), &used);
            t = now_ms() - t;
            if (rep > 1) free(m.out);
        } while (--rep > 0);
        save(argv[6], m.out, m.on);
        free(m.out);
        gz_ppmd7_free(p);
        return report(rc, used, m.on, t);
    }
    if (argc >= 6 && !strcmp(argv[1], "e7")) {
        size_t n;
        u8 *f = load(argv[4], &n);
        mio m;
        gz_stream_io io = { m_read, m_write, &m };
        gz_ppmd7 *p = gz_ppmd7_new();
        u64 isz = 0, osz = 0;
        double t;
        int rc;
        mio_init(&m, f, n);
        t = now_ms();
        rc = gz_ppmd7z_encode_ex(p, (u32)atoi(argv[2]), (u32)strtoul(argv[3], 0, 10), &io, &isz, &osz);
        t = now_ms() - t;
        if (!rc && (isz != n || osz != m.on)) rc = 99;
        save(argv[5], m.out, m.on);
        free(m.out);
        gz_ppmd7_free(p);
        return report(rc, isz, m.on, t);
    }
    if (argc >= 5 && !strcmp(argv[1], "d8")) {
        size_t n;
        u8 *f = load(argv[3], &n);
        mio m;
        gz_stream_io io = { m_read, m_write, &m };
        gz_ppmd8 *p = gz_ppmd8_new();
        u64 used = 0;
        int rc, rep = getenv("PPMD_REPEAT") ? atoi(getenv("PPMD_REPEAT")) : 1;
        double t = 0;
        do {
            mio_init(&m, f, n);
            t = now_ms();
            rc = gz_ppmd8_zip_decode_ex(p, &io, parse_size(argv[2]), &used);
            t = now_ms() - t;
            if (rep > 1) free(m.out);
        } while (--rep > 0);
        save(argv[4], m.out, m.on);
        free(m.out);
        gz_ppmd8_free(p);
        return report(rc, used, m.on, t);
    }
    if (argc >= 7 && !strcmp(argv[1], "e8")) {
        size_t n;
        u8 *f = load(argv[5], &n);
        mio m;
        gz_stream_io io = { m_read, m_write, &m };
        gz_ppmd8 *p = gz_ppmd8_new();
        u64 isz = 0, osz = 0;
        double t;
        int rc;
        mio_init(&m, f, n);
        t = now_ms();
        rc = gz_ppmd8_zip_encode_ex(p, (u32)atoi(argv[2]), (u32)atoi(argv[3]), (u32)atoi(argv[4]), &io,
                                    &isz, &osz);
        t = now_ms() - t;
        if (!rc && (isz != n || osz != m.on)) rc = 99;
        save(argv[6], m.out, m.on);
        free(m.out);
        gz_ppmd8_free(p);
        return report(rc, isz, m.on, t);
    }
    if (argc >= 4 && !strcmp(argv[1], "level")) {     /* level LEVEL SIZE: 7-Zip's 7z and ZIP parameters */
        u32 o7, m7, o8, m8, r8;
        u64 size = parse_size(argv[3]);
        gz_ppmd7z_level(atoi(argv[2]), size, &o7, &m7);
        gz_ppmd8_zip_level(atoi(argv[2]), size, &o8, &m8, &r8);
        printf("7z %u %u zip %u %u %u\n", o7, m7, o8, m8, r8);
        return 0;
    }
    if (argc >= 4 && !strcmp(argv[1], "zip")) return cmd_zip(argv[2], argv[3]);
    if (argc >= 4 && !strcmp(argv[1], "7z")) return cmd_7z(argv[2], argv[3]);
    if (argc >= 6 && !strcmp(argv[1], "erar")) return cmd_erar(argv[2], atoi(argv[3]), argv[4], argv[5]);
    if (argc >= 5 && !strcmp(argv[1], "drar")) return cmd_drar(parse_size(argv[2]), argv[3], argv[4]);
    if (argc >= 5 && !strcmp(argv[1], "rctest")) return cmd_rctest((u32)strtoul(argv[2], 0, 10), (u32)atoi(argv[3]), argv[4]);
    /* fuzz7 ORDER MEM SIZE ITERS SEED IN / fuzz8 SIZE ITERS SEED IN */
    if (argc >= 8 && !strcmp(argv[1], "fuzz7"))
        return cmd_fuzz(7, argv[7], (u32)atoi(argv[2]), (u32)strtoul(argv[3], 0, 10), parse_size(argv[4]),
                        (u32)atoi(argv[5]), (u32)atoi(argv[6]));
    if (argc >= 6 && !strcmp(argv[1], "fuzz8"))
        return cmd_fuzz(8, argv[5], 0, 0, parse_size(argv[2]), (u32)atoi(argv[3]), (u32)atoi(argv[4]));
    if (argc >= 6 && !strcmp(argv[1], "fuzzrar"))     /* fuzzrar SIZE ITERS SEED IN */
        return cmd_fuzz(3, argv[5], 0, 0, parse_size(argv[2]), (u32)atoi(argv[3]), (u32)atoi(argv[4]));
    fprintf(stderr, "usage: see tests/drivers/ppmd_test.c\n");
    return 2;
}
