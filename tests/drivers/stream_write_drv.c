/*
 * Compressed tarball / single-file writers (src/fmt/stream_write.c) driven with
 * synthetic inputs: error paths, pipe sinks and a large generated input.
 *
 *   stream_write_drv cases
 *       one line per check: "ok <name>" or "FAIL <name>: why"; writes the archives
 *       of the shrink/grow checks to the current directory for the caller to verify
 *   stream_write_drv big FORMAT LEVEL GIB
 *       GIB GiB of generated, moderately compressible data as one member (tarballs)
 *       or one file (single formats) written to stdout through a pipe sink;
 *       stderr: "in=<bytes> out=<bytes> sec=<s>"
 */
#include "gz_write.h"
#include "cpu.h"
#include "crc32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>

static const char *fmt_names[] = { "", "zip", "7z", "tar", "tgz", "tbz2", "txz", "tzst", "gz", "bz2", "xz", "zst", "iso" };
static int fmt_id(const char *s)
{
    for (int i = 1; i < GZ_WF_COUNT; i++) if (!strcmp(s, fmt_names[i])) return i;
    return 0;
}

/* ---- synthetic input files: it->user points at a spec ---- */
typedef struct {
    u64 real;            /* bytes the source really yields                      */
    int fail_at;         /* >= 0: GZ_E_IO once this many bytes were read          */
    int open_err;        /* open_item fails with this                             */
    u32 seed;
} spec;

typedef struct { gz_wsrc w; spec *s; u64 pos; u32 x; } src;

/* text-like generator: words from a small vocabulary with numbers mixed in */
static void gen(u8 *p, u32 n, u64 pos, u32 *x)
{
    static const char *w[] = { "lorem ", "ipsum ", "dolor ", "sit ", "amet, ", "고깃집 ", "archive ", "zstd ",
                               "\n", "0x7f3a ", "deflate ", "bzip2 ", "lzma2 ", "tar ", "block ", "frame " };
    u32 i = 0;
    while (i < n) {
        *x = *x * 1664525u + 1013904223u;
        u32 r = *x >> 24;
        if (r < 16) {
            const char *s = w[r];
            while (*s && i < n) p[i++] = (u8)*s++;
        } else if (r < 40) {
            p[i++] = (u8)('0' + (r % 10));
        } else {
            p[i++] = (u8)((pos + i) * 31 >> 7);
        }
    }
}

static int s_read(gz_wsrc *w, u8 *buf, u32 cap, u32 *got)
{
    src *s = (src *)w;
    *got = 0;
    if (s->s->fail_at >= 0 && s->pos >= (u64)s->s->fail_at) return GZ_E_IO;
    u64 left = s->s->real - s->pos;
    u32 n = left < cap ? (u32)left : cap;
    if (s->s->fail_at >= 0 && s->pos + n > (u64)s->s->fail_at) n = (u32)(s->s->fail_at - s->pos);
    gen(buf, n, s->pos, &s->x);
    s->pos += n;
    *got = n;
    return GZ_OK;
}

static int open_item(void *user, const gz_witem *it, gz_wsrc **out)
{
    spec *sp = (spec *)it->user;
    if (sp && sp->open_err) return sp->open_err;
    src *s = (src *)calloc(1, sizeof *s);
    s->w.read = s_read;
    s->s = sp;
    s->x = sp ? sp->seed : 1;
    *out = &s->w;
    return GZ_OK;
}
static void close_item(void *user, const gz_witem *it, gz_wsrc *w) { (void)user; (void)it; free(w); }

typedef struct { int calls, last_err, ret; const gz_witem *last; } errlog;
static int on_error(void *user, const gz_witem *it, int err)
{
    errlog *l = (errlog *)user;
    l->calls++;
    l->last_err = err;
    l->last = it;
    return l->ret;
}

/* ---- sinks: memory (no write_at, like a pipe), or stdout ---- */
typedef struct { gz_sink k; u8 *p; size_t n, cap; int fail_after; long *cancel; size_t cancel_at; } msink;
static int m_write(gz_sink *k, const void *p, size_t n)
{
    msink *m = (msink *)k;
    if (m->fail_after >= 0 && m->n + n > (size_t)m->fail_after) return GZ_E_DISK;
    if (m->n + n > m->cap) {
        m->cap = (m->n + n) * 2;
        m->p = (u8 *)realloc(m->p, m->cap);
    }
    memcpy(m->p + m->n, p, n);
    m->n += n;
    if (m->cancel && m->n >= m->cancel_at) *m->cancel = 1;
    return GZ_OK;
}

typedef struct { gz_sink k; u64 n; } osink;
static int o_write(gz_sink *k, const void *p, size_t n)
{
    osink *o = (osink *)k;
    if (fwrite(p, 1, n, stdout) != n) return GZ_E_IO;
    o->n += n;
    return GZ_OK;
}

static int run(int fmt, int level, gz_witem *it, u32 n, msink *m, errlog *el, volatile long *cancel)
{
    gz_wopts o;
    memset(&o, 0, sizeof o);
    o.format = fmt;
    o.level = level;
    o.open_item = open_item;
    o.close_item = close_item;
    o.on_error = el ? on_error : 0;
    o.user = el;
    o.cancel = cancel;
    memset(m, 0, sizeof *m);
    m->k.write = m_write;            /* write_at stays NULL: a pipe */
    m->fail_after = -1;
    return gz_write_archive(&o, it, n, &m->k, 0);
}

static int fails;
static void check(int ok, const char *name, const char *why)
{
    if (ok) printf("ok %s\n", name);
    else { printf("FAIL %s: %s\n", name, why); fails++; }
}

static void save(const char *name, const msink *m)
{
    FILE *f = fopen(name, "wb");
    if (f) { fwrite(m->p, 1, m->n, f); fclose(f); }
}

static void item(gz_witem *it, const gzch *name, u64 size, spec *sp)
{
    memset(it, 0, sizeof *it);
    it->name = name;
    it->size = size;
    it->mtime = gz_unix_to_filetime(1700000000);
    it->attr = 0x20;
    it->user = sp;
}

static int cases(void)
{
    static const int all[] = { GZ_WF_TGZ, GZ_WF_TBZ2, GZ_WF_TXZ, GZ_WF_TZST, GZ_WF_GZ, GZ_WF_BZ2, GZ_WF_XZ, GZ_WF_ZST };
    char nm[128], why[256];
    for (u32 f = 0; f < sizeof all / sizeof all[0]; f++) {
        int fmt = all[f], single = fmt >= GZ_WF_GZ;
        const char *fn = fmt_names[fmt];
        msink m;
        errlog el;
        gz_witem it[3];
        spec sp[3];
        memset(sp, 0, sizeof sp);
        for (int i = 0; i < 3; i++) { sp[i].fail_at = -1; sp[i].seed = 7 + i; }

        /* writers never need write_at; level 1 and 9 */
        for (int lv = 1; lv <= 9; lv += 8) {
            sp[0].real = 300000;
            item(&it[0], u"data.txt", 300000, &sp[0]);
            int r = run(fmt, lv, it, 1, &m, 0, 0);
            snprintf(nm, sizeof nm, "%s pipe sink L%d", fn, lv);
            snprintf(why, sizeof why, "r=%d", r);
            check(!r && m.n > 0 && m.n < 300000, nm, why);
            snprintf(nm, sizeof nm, "pipe_%s_L%d.%s", fn, lv, fn);
            save(nm, &m);
            free(m.p);
        }

        /* the input shrinks after its size was taken: zero padded + reported
         * (tarballs, .zst), or just shorter (.gz .bz2 .xz) */
        sp[0].real = 1000;
        item(&it[0], u"shrunk.txt", 5000, &sp[0]);
        memset(&el, 0, sizeof el);
        int r = run(fmt, 3, it, 1, &m, &el, 0);
        int padded = !single || fmt == GZ_WF_ZST;
        snprintf(nm, sizeof nm, "%s shrinking input", fn);
        snprintf(why, sizeof why, "r=%d calls=%d err=%d", r, el.calls, el.last_err);
        check(!r && (padded ? el.calls == 1 && el.last_err == GZ_E_TRUNC : el.calls == 0), nm, why);
        snprintf(nm, sizeof nm, "shrink.%s", fn);
        save(nm, &m);
        free(m.p);

        /* the input grows: cut at the size in the header (tarballs, .zst) */
        sp[0].real = 9000;
        item(&it[0], u"grown.txt", 4000, &sp[0]);
        memset(&el, 0, sizeof el);
        r = run(fmt, 3, it, 1, &m, &el, 0);
        snprintf(nm, sizeof nm, "%s growing input", fn);
        snprintf(why, sizeof why, "r=%d calls=%d", r, el.calls);
        check(!r && !el.calls, nm, why);
        snprintf(nm, sizeof nm, "grow.%s", fn);
        save(nm, &m);
        free(m.p);

        /* read error in the middle of a file */
        sp[0].real = 200000;
        sp[0].fail_at = 70000;
        item(&it[0], u"bad.bin", 200000, &sp[0]);
        sp[1].real = 10;
        sp[1].fail_at = -1;
        item(&it[1], u"after.txt", 10, &sp[1]);
        memset(&el, 0, sizeof el);
        r = run(fmt, 3, it, single ? 1 : 2, &m, &el, 0);
        snprintf(nm, sizeof nm, "%s read error", fn);
        snprintf(why, sizeof why, "r=%d calls=%d err=%d", r, el.calls, el.last_err);
        /* tarballs: reported, padded, archive completed; single files: aborted with the error */
        check(el.calls == 1 && el.last_err == GZ_E_IO && (single ? r == GZ_E_IO : !r), nm, why);
        if (!single) { snprintf(nm, sizeof nm, "readerr.%s", fn); save(nm, &m); }
        free(m.p);
        sp[0].fail_at = -1;

        /* open error: skipped in tarballs, fatal for single files */
        sp[0].open_err = GZ_E_IO;
        sp[0].real = 100;
        item(&it[0], u"locked.txt", 100, &sp[0]);
        item(&it[1], u"after.txt", 10, &sp[1]);
        memset(&el, 0, sizeof el);
        r = run(fmt, 3, it, single ? 1 : 2, &m, &el, 0);
        snprintf(nm, sizeof nm, "%s open error", fn);
        snprintf(why, sizeof why, "r=%d calls=%d", r, el.calls);
        check(el.calls == 1 && (single ? r == GZ_E_IO : !r), nm, why);
        free(m.p);
        sp[0].open_err = 0;

        /* sink error is returned unchanged */
        sp[0].real = 2000000;
        item(&it[0], u"big.txt", 2000000, &sp[0]);
        {
            gz_wopts o;
            memset(&o, 0, sizeof o);
            o.format = fmt;
            o.level = 1;
            o.open_item = open_item;
            o.close_item = close_item;
            memset(&m, 0, sizeof m);
            m.k.write = m_write;
            m.fail_after = 5000;
            r = gz_write_archive(&o, it, 1, &m.k, 0);
            snprintf(nm, sizeof nm, "%s sink error", fn);
            snprintf(why, sizeof why, "r=%d", r);
            check(r == GZ_E_DISK, nm, why);
            free(m.p);
        }

        /* cancel during the job */
        {
            volatile long cancel = 0;
            gz_wopts o;
            memset(&o, 0, sizeof o);
            o.format = fmt;
            o.level = 1;
            o.open_item = open_item;
            o.close_item = close_item;
            o.cancel = &cancel;
            sp[0].real = 8000000;
            item(&it[0], u"long.txt", 8000000, &sp[0]);
            memset(&m, 0, sizeof m);
            m.k.write = m_write;
            m.fail_after = -1;
            m.cancel = (long *)&cancel;
            m.cancel_at = 1000;
            r = gz_write_archive(&o, it, 1, &m.k, 0);
            snprintf(nm, sizeof nm, "%s cancel", fn);
            snprintf(why, sizeof why, "r=%d", r);
            check(r == GZ_E_CANCEL, nm, why);
            free(m.p);
        }

        if (single) {
            /* exactly one file */
            item(&it[0], u"a.txt", 10, &sp[0]);
            item(&it[1], u"b.txt", 10, &sp[1]);
            memset(&el, 0, sizeof el);
            r = run(fmt, 3, it, 2, &m, &el, 0);
            snprintf(nm, sizeof nm, "%s two files rejected", fn);
            snprintf(why, sizeof why, "r=%d calls=%d", r, el.calls);
            check(r == GZ_E_METHOD && el.calls == 1 && el.last == &it[1] && el.last_err == GZ_E_METHOD && !m.n, nm, why);
            free(m.p);
            item(&it[0], u"dir", 0, 0);
            it[0].is_dir = 1;
            memset(&el, 0, sizeof el);
            r = run(fmt, 3, it, 1, &m, &el, 0);
            snprintf(nm, sizeof nm, "%s directory rejected", fn);
            snprintf(why, sizeof why, "r=%d calls=%d", r, el.calls);
            check(r == GZ_E_METHOD && el.calls == 1 && !m.n, nm, why);
            free(m.p);
            r = run(fmt, 3, it, 0, &m, 0, 0);
            snprintf(nm, sizeof nm, "%s no item rejected", fn);
            snprintf(why, sizeof why, "r=%d", r);
            check(r == GZ_E_METHOD, nm, why);
            free(m.p);
        } else {
            /* no items at all: an empty tarball */
            r = run(fmt, 3, it, 0, &m, 0, 0);
            snprintf(nm, sizeof nm, "%s empty tarball", fn);
            snprintf(why, sizeof why, "r=%d n=%zu", r, m.n);
            check(!r && m.n > 0, nm, why);
            snprintf(nm, sizeof nm, "empty.%s", fn);
            save(nm, &m);
            free(m.p);
        }
    }
    printf("%s\n", fails ? "FAILED" : "ALL OK");
    return fails ? 1 : 0;
}

static int big(const char *fs, int level, double gib)
{
    int fmt = fmt_id(fs);
    if (!fmt) return 2;
    spec sp;
    memset(&sp, 0, sizeof sp);
    sp.real = (u64)(gib * (1u << 30));
    sp.fail_at = -1;
    sp.seed = 3;
    gz_witem it;
    item(&it, u"big.bin", sp.real, &sp);
    gz_wopts o;
    memset(&o, 0, sizeof o);
    o.format = fmt;
    o.level = level;
    o.open_item = open_item;
    o.close_item = close_item;
    osink k;
    memset(&k, 0, sizeof k);
    k.k.write = o_write;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int r = gz_write_archive(&o, &it, 1, &k.k, 0);
    fflush(stdout);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    /* peak RSS of this program: VmHWM (ru_maxrss also counts the parent's RSS at fork time) */
    long rss = -1;
    FILE *st = fopen("/proc/self/status", "r");
    if (st) {
        char line[256];
        while (fgets(line, sizeof line, st))
            if (!strncmp(line, "VmHWM:", 6)) rss = atol(line + 6);
        fclose(st);
    }
    if (rss < 0) {
        struct rusage ru;
        getrusage(RUSAGE_SELF, &ru);
        rss = ru.ru_maxrss;
    }
    fprintf(stderr, "in=%llu out=%llu sec=%.2f rss_kb=%ld r=%d\n", (unsigned long long)sp.real,
            (unsigned long long)k.n, (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9, rss, r);
    return r ? 1 : 0;
}

int main(int argc, char **argv)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_dispatch_init(-1);
    if (argc >= 2 && !strcmp(argv[1], "cases")) return cases();
    if (argc >= 5 && !strcmp(argv[1], "big")) return big(argv[2], atoi(argv[3]), atof(argv[4]));
    return 2;
}
