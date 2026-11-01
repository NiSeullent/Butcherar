/*
 * Engine API checks for front-end authors: async open job, nested archives (view and
 * temporary copy), overwrite answers (rename-all, skip-all, cancel), pause, compression
 * job, helpers. Prints "ok <what>" / "FAIL <what>" lines.
 *   usage: app_engine <workdir containing outer.tar and outer.tar.gz>
 */
#include "engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

static int fails;
#define CHECK(cond, ...) do { int c_ = (cond); printf(c_ ? "ok " : "FAIL "); printf(__VA_ARGS__); \
                              printf("\n"); fflush(stdout); if (!c_) fails++; } while (0)

static char g_work[2048];

static gzch *W(const char *s) { return gz_os_path_wide(s); }

static gzch *WP(const char *rel)
{
    char p[4096];
    snprintf(p, sizeof p, "%s/%s", g_work, rel);
    return W(p);
}

static int weq(const gzch *a, const char *b)
{
    gzch *w = W(b);
    int r = !gz_wcscmp(a, w);
    gz_free(w);
    return r;
}

static char *read_file(const char *rel, size_t *n)
{
    char p[4096];
    snprintf(p, sizeof p, "%s/%s", g_work, rel);
    FILE *f = fopen(p, "rb");
    if (!f) return 0;
    char *b = (char *)malloc(1 << 20);
    *n = fread(b, 1, 1 << 20, f);
    fclose(f);
    return b;
}

static int file_is(const char *rel, const char *want)
{
    size_t n;
    char *b = read_file(rel, &n);
    int ok = b && n == strlen(want) && !memcmp(b, want, n);
    free(b);
    return ok;
}

static int exists(const char *rel)
{
    char p[4096];
    struct stat st;
    snprintf(p, sizeof p, "%s/%s", g_work, rel);
    return !lstat(p, &st);
}

/* ---- callbacks ---- */

typedef struct {
    int asks, answer, done_calls, done_result, progress_calls, logs, renamed;
    gz_job *job;              /* for answers that act on the job */
} rec;

static int a_ask(void *u, gz_ask *q)
{
    rec *r = (rec *)u;
    r->asks++;
    if (q->kind == GZ_ASK_PASSWORD) return GZ_ANS_NO;
    return r->answer;
}
static void a_progress(void *u, const gz_progress *p) { (void)p; ((rec *)u)->progress_calls++; }
static void a_log(void *u, const gz_log *l)
{
    rec *r = (rec *)u;
    r->logs++;
    if (l->code == GZ_N_RENAMED) r->renamed++;
}
static void a_done(void *u, int res) { rec *r = (rec *)u; r->done_calls++; r->done_result = res; }

static gz_callbacks cbs(rec *r) { gz_callbacks c = { r, a_ask, a_progress, a_log, a_done }; return c; }

static int find(gz_archive *a, const char *name)
{
    for (u32 i = 0; i < a->n; i++) if (weq(a->e[i].name, name)) return (int)i;
    return -1;
}

static int extract(gz_handle *h, const char *dest, int ow, rec *r)
{
    gzch *d = WP(dest);
    gz_extract_opts xo;
    memset(&xo, 0, sizeof xo);
    xo.dest = d;
    xo.overwrite = ow;
    gz_callbacks cb = cbs(r);
    gz_job *j = gz_extract_start(h, &xo, &cb);
    int res = j ? gz_job_wait(j) : GZ_E_NOMEM;
    gz_job_free(j);
    gz_free(d);
    return res;
}

static void helpers(void)
{
    static const char *const stems[][2] = {
        { "a.tar.gz", "a" }, { "b.part1.rar", "b" }, { "c.7z.001", "c" }, { "/x/y/d.zip", "d" },
        { "e.TGZ", "e" }, { "f.part01.rar", "f" }, { "g.rar", "g" }, { "h.tar.zst", "h" },
        { "noext", "noext" }, { ".hidden", ".hidden" }, { "z.zip.001", "z" }, { "my.photos.zip", "my.photos" },
    };
    int ok = 1;
    for (size_t i = 0; i < sizeof stems / sizeof *stems; i++) {
        gzch out[256];
        gzch *w = W(stems[i][0]);
        gz_archive_stem(w, out, 256);
        if (!weq(out, stems[i][1])) { ok = 0; printf("  stem %s\n", stems[i][0]); }
        gz_free(w);
    }
    CHECK(ok, "gz_archive_stem");
    static const struct { const char *n; int f; } fm[] = {
        { "x.tar.gz", GZ_WF_TGZ }, { "X.ZIP", GZ_WF_ZIP }, { "y.tbz2", GZ_WF_TBZ2 }, { "z.iso", GZ_WF_ISO },
        { "w.txt", 0 }, { "v.tar", GZ_WF_TAR }, { "u.7z", GZ_WF_7Z }, { "t.tar.xz", GZ_WF_TXZ }, { "s.zst", GZ_WF_ZST },
    };
    ok = 1;
    for (size_t i = 0; i < sizeof fm / sizeof *fm; i++) {
        gzch *w = W(fm[i].n);
        if (gz_format_from_name(w) != fm[i].f) { ok = 0; printf("  fmt %s\n", fm[i].n); }
        gz_free(w);
    }
    CHECK(ok, "gz_format_from_name");
}

static void nested(void)
{
    rec r;
    memset(&r, 0, sizeof r);
    gz_callbacks cb = cbs(&r);
    gzch *p = WP("outer.tar");
    gz_job *j = gz_open_start(p, 0, &cb);
    int res = gz_job_wait(j);
    gz_handle *h = gz_job_take_handle(j);
    CHECK(!res && h && r.done_calls == 1 && !r.done_result, "async open job (done called once)");
    gz_job_free(j);
    gz_free(p);
    if (!h) return;
    CHECK(!gz_smart_needs_folder(h->arc, 0, 0), "smart: single top folder");
    int idx = find(h->arc, "pack/inner.zip");
    gz_handle *c = 0;
    res = idx >= 0 ? gz_handle_open_child(&c, h, (u32)idx, 0, &cb) : GZ_E_FORMAT;
    CHECK(!res && c && !c->temp && c->parent == h && find(c->arc, "in/a.txt") >= 0, "child archive through a view");
    if (c) {
        memset(&r, 0, sizeof r);
        res = extract(c, "nest_view", GZ_OW_ALL, &r);
        CHECK(!res && file_is("nest_view/in/a.txt", "nested A"), "extract from the nested view");
        gz_handle_close(c);
    }
    gz_handle_close(h);

    p = WP("outer.tar.gz");
    res = gz_handle_open(&h, p, 0, &cb);
    gz_free(p);
    CHECK(!res, "open outer.tar.gz");
    if (res) return;
    idx = find(h->arc, "pack/inner.zip");
    c = 0;
    res = idx >= 0 ? gz_handle_open_child(&c, h, (u32)idx, 0, &cb) : GZ_E_FORMAT;
    char *tp = c ? gz_os_path_bytes(c->path) : 0;
    struct stat st;
    CHECK(!res && c && c->temp && tp && !stat(tp, &st), "child archive through a temporary copy");
    if (c) {
        memset(&r, 0, sizeof r);
        res = extract(c, "nest_tmp", GZ_OW_ALL, &r);
        CHECK(!res && file_is("nest_tmp/in/a.txt", "nested A"), "extract from the temporary copy");
        CHECK(weq(c->name, "outer.tar.gz/pack/inner.zip"), "child display name");
        gz_handle_close(c);
        CHECK(tp && stat(tp, &st), "temporary copy deleted on close");
    }
    gz_free(tp);
    gz_handle_close(h);
}

static void answers(void)
{
    gzch *p = WP("outer.tar");
    gz_handle *h;
    rec r;
    memset(&r, 0, sizeof r);
    gz_callbacks cb = cbs(&r);
    if (gz_handle_open(&h, p, 0, &cb)) { CHECK(0, "open outer.tar"); gz_free(p); return; }
    gz_free(p);
    int res = extract(h, "ans", GZ_OW_ASK, &r);
    CHECK(!res && r.asks == 0 && file_is("ans/pack/other.txt", "other"), "first extraction asks nothing");
    memset(&r, 0, sizeof r);
    r.answer = GZ_ANS_RENAME_ALL;
    res = extract(h, "ans", GZ_OW_ASK, &r);
    CHECK(!res && r.asks == 1 && r.renamed == 2 && file_is("ans/pack/other (2).txt", "other") &&
          exists("ans/pack/inner (2).zip"), "rename-all: one question, both renamed");
    memset(&r, 0, sizeof r);
    r.answer = GZ_ANS_NO_ALL;
    gzch *d = WP("ans");
    gz_extract_opts xo;
    memset(&xo, 0, sizeof xo);
    xo.dest = d;
    gz_callbacks c2 = cbs(&r);
    gz_job *j = gz_extract_start(h, &xo, &c2);
    res = gz_job_wait(j);
    gz_progress pr;
    gz_job_progress(j, &pr);
    CHECK(!res && r.asks == 1 && pr.skipped == 2 && !exists("ans/pack/other (3).txt") && r.done_calls == 1,
          "skip-all: one question, two skipped");
    gz_job_free(j);
    memset(&r, 0, sizeof r);
    r.answer = GZ_ANS_CANCEL;
    res = extract(h, "ans", GZ_OW_ASK, &r);
    CHECK(res == GZ_E_CANCEL && r.asks == 1 && r.done_result == GZ_E_CANCEL, "cancel at the question");
    memset(&r, 0, sizeof r);
    res = extract(h, "ans", GZ_OW_SKIP, &r);
    CHECK(!res && r.asks == 0, "overwrite mode skip asks nothing");
    gz_free(d);
    gz_handle_close(h);
}

static void compress_pause(void)
{
    /* make 3 x 12 MiB of input, compress with the job API, then extract while paused */
    char p[4096];
    snprintf(p, sizeof p, "%s/cin", g_work);
    mkdir(p, 0755);
    char *buf = (char *)malloc(12 << 20);
    for (int i = 0; i < (12 << 20); i++) buf[i] = (char)(i * 7 + (i >> 12));
    for (int k = 0; k < 3; k++) {
        snprintf(p, sizeof p, "%s/cin/f%d.bin", g_work, k);
        FILE *f = fopen(p, "wb");
        fwrite(buf, 1, 12 << 20, f);
        fclose(f);
    }
    free(buf);
    snprintf(p, sizeof p, "%s/cin/note.txt", g_work);
    FILE *f = fopen(p, "wb");
    fputs("note", f);
    fclose(f);
    rec r;
    memset(&r, 0, sizeof r);
    gz_callbacks cb = cbs(&r);
    gzch *in[2] = { WP("cin"), WP("outer.tar") };
    gzch *out = WP("made.tar");
    gz_compress_opts co;
    memset(&co, 0, sizeof co);
    co.out = out;
    co.inputs = (const gzch *const *)in;
    co.ninputs = 2;
    co.format = GZ_WF_TAR;
    co.overwrite = GZ_OW_ALL;
    gz_job *j = gz_compress_start(&co, &cb);
    int res = gz_job_wait(j);
    gz_progress pr;
    gz_job_progress(j, &pr);
    CHECK(!res && r.done_calls == 1 && pr.total_files == 5 && pr.done_bytes == pr.total_bytes &&
          pr.total_bytes > (36u << 20) + 4, "compress job (tar)");
    gz_job_free(j);

    /* cancelled compression leaves neither the archive nor a temporary file */
    gz_free(out);
    out = WP("cancelled.tar");
    co.out = out;
    j = gz_compress_start(&co, &cb);
    gz_job_cancel(j);
    res = gz_job_wait(j);
    gz_job_free(j);
    {
        int left = exists("cancelled.tar");
        DIR *dd = opendir(g_work);
        struct dirent *de;
        while (dd && (de = readdir(dd))) if (!strncmp(de->d_name, "cancelled.tar.tmp-", 18)) left = 1;
        if (dd) closedir(dd);
        CHECK((res == GZ_E_CANCEL && !left) || (res == GZ_OK && exists("cancelled.tar")),
              "cancelled compression cleans up");
    }
    gz_free(out);
    out = WP("made.tar");
    co.out = out;

    co.format = 999;                       /* no such writer */
    memset(&r, 0, sizeof r);
    j = gz_compress_start(&co, &cb);
    res = gz_job_wait(j);
    CHECK(res == GZ_E_METHOD && gz_job_log_count(j) == 1 && gz_job_log_at(j, 0)->code == GZ_N_NO_WRITER,
          "compress: missing writer reported");
    gz_job_free(j);

    gz_handle *h;
    if (gz_handle_open(&h, out, 0, &cb)) { CHECK(0, "open made.tar"); goto done; }
    CHECK(find(h->arc, "cin/f2.bin") >= 0 && find(h->arc, "outer.tar") >= 0, "compressed names relative to the common parent");
    gzch *d = WP("paused");
    gz_extract_opts xo;
    memset(&xo, 0, sizeof xo);
    xo.dest = d;
    xo.overwrite = GZ_OW_ALL;
    memset(&r, 0, sizeof r);
    j = gz_extract_start(h, &xo, &cb);
    gz_job_pause(j, 1);
    usleep(300000);
    gz_progress a, b;
    gz_job_progress(j, &a);
    usleep(300000);
    gz_job_progress(j, &b);
    int frozen = a.done_bytes == b.done_bytes;
    int finished = gz_job_wait_for(j, 0);
    gz_job_pause(j, 0);
    res = gz_job_wait(j);
    gz_job_progress(j, &b);
    CHECK(frozen && !res && b.done_bytes == b.total_bytes && (finished || a.done_bytes < a.total_bytes),
          "pause holds the workers, resume finishes");
    gz_job_free(j);
    j = gz_extract_start(h, &xo, &cb);
    gz_job_cancel(j);
    res = gz_job_wait(j);
    CHECK(res == GZ_E_CANCEL || res == GZ_OK, "cancel right after start");
    gz_job_free(j);
    gz_free(d);
    gz_handle_close(h);
done:
    gz_free(in[0]);
    gz_free(in[1]);
    gz_free(out);
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    snprintf(g_work, sizeof g_work, "%s", argv[1]);
    gz_engine_init(-1);
    helpers();
    nested();
    answers();
    compress_pause();
    printf("%s\n", fails ? "SOME FAILED" : "ALL OK");
    return fails ? 1 : 0;
}
