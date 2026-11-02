/*
 * 고깃ZIP - portable extraction / compression engine (successor of src/win/engine.c)
 *
 *   - every extraction worker owns a gz_ctx and its own handle to the archive;
 *     entries are handed out in archive order (folders first) for mostly
 *     sequential reads; output names that collide force a single worker
 *   - overwrite / password / volume questions are serialised by one lock and
 *     answered through gz_callbacks.ask; a generation counter lets workers
 *     notice a password typed while they were trying the previous one
 *   - output paths are built component by component under the destination:
 *     '.'/'..' never pass, over-long names are shortened with a hash suffix,
 *     Windows naming rules apply where the OS layer says so
 *   - links are created after every file has been written (so nothing is ever
 *     written through a link made by this extraction), never inside a linked
 *     folder, and only when their targets stay inside the destination (checked
 *     against the real file system, again after the last link is in place)
 *   - folder times and modes are restored at the very end, deepest first
 *
 * No C library: only os.h and the core.
 */
#include "engine.h"
#include "cpu.h"
#include "crc32.h"

#define SEP GZ_OS_SEP
#define PCAP 4096u                /* path buffers, UTF-16 units                  */
#define MAX_WORKERS 32
#define LINK_DATA_MAX 65536u      /* link target stored as entry data            */
#define LOG_KEEP 200000u          /* log entries kept for gz_job_log_at          */
#define WALK_DEPTH 1024           /* folder nesting followed when compressing    */

enum { JOB_OPEN = 1, JOB_EXTRACT, JOB_COMPRESS };
enum { W_NONE = 0, W_FILE, W_TEST, W_LINK };

/* ---------------- small string helpers ---------------- */

static size_t wlen(const gzch *s) { return gz_wcslen(s); }

static size_t wcopy(gzch *d, const gzch *s, size_t cap)
{
    size_t i = 0;
    if (!cap) return 0;
    for (; s[i] && i + 1 < cap; i++) d[i] = s[i];
    d[i] = 0;
    return i;
}

static gzch *wdup(const gzch *s) { return s ? gz_wcsdup(s) : 0; }

static gzch *wdupn(const gzch *s, size_t n)
{
    gzch *d = (gzch *)gz_alloc((n + 1) * sizeof(gzch));
    if (d && n) __builtin_memcpy(d, s, n * sizeof(gzch));
    return d;
}

/* a + sep + b (sep 0: none) */
static gzch *wjoin(const gzch *a, gzch sep, const gzch *b)
{
    size_t x = wlen(a), y = wlen(b);
    gzch *d = (gzch *)gz_alloc((x + y + 2) * sizeof(gzch));
    if (!d) return 0;
    __builtin_memcpy(d, a, x * sizeof(gzch));
    size_t o = x;
    if (sep) d[o++] = sep;
    __builtin_memcpy(d + o, b, y * sizeof(gzch));
    d[o + y] = 0;
    return d;
}

static gzch fold(gzch c) { return (c >= 'A' && c <= 'Z') ? (gzch)(c + 32) : c; }

static int prefix_eq(const gzch *s, const gzch *p, size_t n, int ci)
{
    for (size_t i = 0; i < n; i++) {
        if (!s[i]) return 0;
        if (ci ? fold(s[i]) != fold(p[i]) : s[i] != p[i]) return 0;
    }
    return 1;
}

static const gzch *base_name(const gzch *p)
{
    const gzch *b = p;
    for (; *p; p++) if (*p == '/' || *p == '\\') b = p + 1;
    return b;
}

static size_t last_sep(const gzch *p, size_t n)     /* index of the last SEP, n if none */
{
    for (size_t i = n; i-- > 0;) if (p[i] == SEP) return i;
    return n;
}

/* UTF-8 -> UTF-16, invalid bytes as U+DC80..U+DCFF (the OS layer maps them back) */
static size_t u8_to_w(const u8 *s, size_t n, gzch *out)
{
    size_t i = 0, o = 0;
    while (i < n) {
        u32 c = s[i];
        if (c < 0x80) { out[o++] = (gzch)c; i++; continue; }
        u32 need = 0, cp = 0;
        if (c >= 0xC2 && c <= 0xDF) { need = 1; cp = c & 0x1f; }
        else if (c >= 0xE0 && c <= 0xEF) { need = 2; cp = c & 0x0f; }
        else if (c >= 0xF0 && c <= 0xF4) { need = 3; cp = c & 0x07; }
        int ok = need && n - i > need;
        for (u32 k = 1; ok && k <= need; k++) {
            if ((s[i + k] & 0xC0) != 0x80) ok = 0;
            else cp = (cp << 6) | (s[i + k] & 0x3f);
        }
        if (ok && ((need == 2 && cp < 0x800) || (need == 3 && (cp < 0x10000 || cp > 0x10FFFF)) ||
                   (cp >= 0xD800 && cp <= 0xDFFF)))
            ok = 0;
        if (!ok) { out[o++] = (gzch)(0xDC00 + c); i++; continue; }
        i += need + 1;
        if (cp >= 0x10000) {
            cp -= 0x10000;
            out[o++] = (gzch)(0xD800 + (cp >> 10));
            out[o++] = (gzch)(0xDC00 + (cp & 0x3ff));
        } else {
            out[o++] = (gzch)cp;
        }
    }
    return o;
}

/* stable bottom-up merge sort of indices; less(ctx, a, b). 0 when out of memory (unsorted) */
typedef int (*less_fn)(void *ctx, u32 a, u32 b);
static int sort_u32(u32 *v, u32 n, less_fn less, void *ctx)
{
    if (n < 2) return 1;
    u32 *tmp = (u32 *)gz_alloc((size_t)n * sizeof(u32));
    if (!tmp) return 0;
    u32 *src = v, *dst = tmp;
    for (u32 width = 1; width < n; width = width > n / 2 ? n : width * 2) {
        for (u32 i = 0; i < n; i += 2 * width) {
            u32 lo = i, mid = n - i > width ? i + width : n;
            u32 hi = n - mid > width ? mid + width : n;
            u32 a = lo, b = mid, k = lo;
            while (a < mid && b < hi) dst[k++] = less(ctx, src[b], src[a]) ? src[b++] : src[a++];
            while (a < mid) dst[k++] = src[a++];
            while (b < hi) dst[k++] = src[b++];
        }
        u32 *t = src; src = dst; dst = t;
    }
    if (src != v) __builtin_memcpy(v, src, (size_t)n * sizeof(u32));
    gz_free(tmp);
    return 1;
}

/* ---------------- start-up & small helpers ---------------- */

void gz_engine_init(int tier)
{
    static volatile long once;
    if (!gz_atomic_xchg(&once, 1)) {
        gz_cpu_detect();
        gz_crc32_init();
        gz_inflate_init();
        gz_aes_init();
        gz_os_umask();
    }
    gz_dispatch_init(tier);
}

u64 gz_entry_time(const gz_entry *e)
{
    if (e->mtime_kind == GZ_MT_FILETIME) return e->mtime;
    if (e->mtime_kind == GZ_MT_DOS) return gz_os_dos_to_utc((u32)e->mtime);
    return 0;
}

/* link target bytes -> UTF-16 (UTF-8 with escapes, or the archive's legacy code page) */
static gzch *decode_target(const gz_archive *a, const u8 *p, u32 n)
{
    u32 k = 0;
    while (k < n && p[k]) k++;            /* a NUL ends the target */
    n = k;
    gzch *w = (gzch *)gz_alloc(((size_t)n * 2 + 4) * sizeof(gzch));
    if (!w) return 0;
    int m = 0;
    if (a->used_cp != GZ_CP_UTF8 && a->used_cp && !gz_utf8_valid(p, n))
        m = gz_plat_mb2wc(a->used_cp, p, (int)n, w, (int)n * 2 + 2);
    if (m <= 0) m = (int)u8_to_w(p, n, w);
    m = gz_hangul_compose(w, m);
    w[m] = 0;
    return w;
}

gzch *gz_entry_link_target(const gz_archive *a, const gz_entry *e)
{
    if (!e->is_link || !e->link_len || (size_t)e->link_off + e->link_len > a->raw_len) return 0;
    return decode_target(a, a->raw + e->link_off, e->link_len);
}

/* archive path written by a tool -> the same normalised form the core gives names */
static size_t sanitize_rel(gzch *s)
{
    size_t n = wlen(s), o = 0, i = 0;
    while (i < n) {
        while (i < n && (s[i] == '/' || s[i] == '\\')) i++;
        size_t st = i;
        while (i < n && s[i] != '/' && s[i] != '\\') i++;
        size_t len = i - st;
        if (!len || (len == 1 && s[st] == '.') || (len == 2 && s[st] == '.' && s[st + 1] == '.')) continue;
        if (!o && len == 2 && s[st + 1] == ':') continue;
        if (o) s[o++] = '/';
        for (size_t k = 0; k < len; k++) s[o++] = s[st + k] < 0x20 ? '_' : s[st + k];
    }
    s[o] = 0;
    return o;
}

static int ends_ci(const gzch *s, size_t n, const char *ext)
{
    size_t m = 0;
    while (ext[m]) m++;
    if (m >= n) return 0;
    for (size_t i = 0; i < m; i++) if (fold(s[n - m + i]) != (gzch)(u8)ext[i]) return 0;
    return 1;
}

void gz_archive_stem(const gzch *name, gzch *out, u32 cap)
{
    static const char *const dbl[] = { ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar.lz", ".tar.lzma",
                                       ".tar.z", ".tar.lz4", ".tar.br", ".tar.lzo", ".tar.zstd" };
    if (!cap) return;
    size_t n = wcopy(out, base_name(name), cap);
    size_t i;
    for (i = 0; i < GZ_COUNTOF(dbl); i++)
        if (ends_ci(out, n, dbl[i])) { n -= __builtin_strlen(dbl[i]); goto trim; }
    /* volumes: "a.7z.001", "a.part01.rar" */
    i = n;
    while (i && out[i - 1] >= '0' && out[i - 1] <= '9') i--;
    if (i && i < n && n - i >= 2 && out[i - 1] == '.') {
        n = i - 1;
    } else if (ends_ci(out, n, ".rar")) {
        size_t k = n - 4;
        while (k && out[k - 1] >= '0' && out[k - 1] <= '9') k--;
        if (k < n - 4 && k >= 5 && ends_ci(out, k, ".part")) { n = k - 5; goto trim; }
    }
    for (i = n; i-- > 1;) if (out[i] == '.') { n = i; break; }
trim:
    while (n && (out[n - 1] == '.' || out[n - 1] == ' ')) n--;
    out[n] = 0;
    if (!n) wcopy(out, u"archive", cap);
}

int gz_format_from_name(const gzch *name)
{
    static const struct { const char *ext; int fmt; } fx[] = {
        { ".tar.gz", GZ_WF_TGZ }, { ".tgz", GZ_WF_TGZ }, { ".tar.bz2", GZ_WF_TBZ2 }, { ".tbz2", GZ_WF_TBZ2 },
        { ".tbz", GZ_WF_TBZ2 }, { ".tar.xz", GZ_WF_TXZ }, { ".txz", GZ_WF_TXZ }, { ".tar.zst", GZ_WF_TZST },
        { ".tzst", GZ_WF_TZST }, { ".tar", GZ_WF_TAR }, { ".zip", GZ_WF_ZIP }, { ".7z", GZ_WF_7Z },
        { ".gz", GZ_WF_GZ }, { ".bz2", GZ_WF_BZ2 }, { ".xz", GZ_WF_XZ }, { ".zst", GZ_WF_ZST },
        { ".iso", GZ_WF_ISO },
    };
    size_t n = wlen(name);
    for (size_t i = 0; i < GZ_COUNTOF(fx); i++) if (ends_ci(name, n, fx[i].ext)) return fx[i].fmt;
    return 0;
}

int gz_smart_needs_folder(const gz_archive *a, const u8 *sel, const gzch *strip)
{
    const gzch *top = 0;
    size_t toplen = 0, sl = strip ? wlen(strip) : 0;
    for (u32 i = 0; i < a->n; i++) {
        const gz_entry *e = &a->e[i];
        if (sel && !sel[i]) continue;
        const gzch *n = e->name;
        if (!n || !n[0]) continue;
        if (sl) {
            if (!prefix_eq(n, strip, sl, a->case_fold) || n[sl] != '/') continue;
            n += sl + 1;
        }
        size_t l = 0;
        while (n[l] && n[l] != '/') l++;
        if (!top) { top = n; toplen = l; continue; }
        if (l != toplen || !prefix_eq(n, top, l, a->case_fold)) return 1;
    }
    return 0;
}

/* ---------------- jobs: common part ---------------- */

typedef struct dlink { u32 idx; gzch *target; } dlink;

typedef struct scratch {
    gzch path[PCAP], tpath[PCAP], tmp[PCAP], q[2 * PCAP];
} scratch;

struct gz_job {
    int kind;
    gz_callbacks cb;
    gz_os_mutex *lock;            /* counters, log, current name, deferred links  */
    gz_os_mutex *ask_lock;        /* questions and the password state             */
    gz_os_mutex *cb_lock;         /* serialises log / progress callbacks          */
    gz_os_cond *cond;             /* workers finished, pause released, job done   */
    gz_os_thread *thread;
    volatile long cancel, paused, next, wait_ms;
    int finished, result, first_err;
    /* progress */
    u64 total_bytes, done_bytes;
    u32 total_files, done_files, skipped, nerr, nwarn;
    gzch current[512];
    u64 t_start, t_end, last_emit;
    /* log */
    gz_log *logs; u32 nlog, caplog;
    /* extraction */
    gz_handle *h;
    gzch *dest; size_t dest_len;
    gzch *strip; size_t strip_len;
    u8 *sel; u32 *order; u32 count;
    int path_mode, overwrite, test, threads, ci;
    u32 flags, caps, name_max, umask, running;
    gzch pw[256]; int pw_set, pw_gen, pw_refused;
    dlink *links; u32 nlinks, caplinks;
    /* compression */
    gz_compress_opts co;
    gzch *c_out, **c_in, *c_pw, *c_label;
    /* open */
    gzch *o_path, *o_pw;
    gz_open_req oreq;
    gz_handle *o_h;
};

static int cancelled(gz_job *j) { return gz_atomic_load(&j->cancel) != 0; }

static void set_current(gz_job *j, const gzch *name)
{
    gz_os_mutex_lock(j->lock);
    wcopy(j->current, name ? name : u"", GZ_COUNTOF(j->current));
    gz_os_mutex_unlock(j->lock);
}

/* GZ_E_* standing for an engine note logged as an error */
static int note_error(int code)
{
    if (code > GZ_OK && code < GZ_E_COUNT) return code;
    switch (code) {
    case GZ_N_NO_WRITER: case GZ_N_ONE_FILE: return GZ_E_METHOD;
    case GZ_N_NO_FILES: case GZ_N_NOT_FOUND: case GZ_N_UNREADABLE: return GZ_E_IO;
    }
    return GZ_E_CREATE;
}

static void job_log(gz_job *j, int level, int code, const gzch *name, const gzch *detail)
{
    gz_log l;
    l.level = level;
    l.code = code;
    l.name = wdup(name ? name : u"");
    l.detail = wdup(detail);
    int kept = 0;
    gz_os_mutex_lock(j->lock);
    if (level == GZ_LOG_ERROR) {
        j->nerr++;
        if (!j->first_err || code == GZ_E_NOMEM) j->first_err = note_error(code);
    } else if (level == GZ_LOG_WARN) {
        j->nwarn++;
    }
    if (j->nlog < LOG_KEEP && l.name) {
        if (j->nlog == j->caplog) {
            u32 nc = j->caplog ? j->caplog * 2 : 32;
            gz_log *nl = (gz_log *)gz_realloc(j->logs, (size_t)nc * sizeof(gz_log));
            if (nl) { j->logs = nl; j->caplog = nc; }
        }
        if (j->nlog < j->caplog) { j->logs[j->nlog++] = l; kept = 1; }
    }
    gz_os_mutex_unlock(j->lock);
    if (j->cb.log) {
        gz_log v = l;
        if (!v.name) v.name = (gzch *)u"";
        gz_os_mutex_lock(j->cb_lock);
        j->cb.log(j->cb.user, &v);
        gz_os_mutex_unlock(j->cb_lock);
    }
    if (!kept) { gz_free(l.name); gz_free(l.detail); }
}

static void snapshot(gz_job *j, gz_progress *p, u64 now)
{
    __builtin_memset(p, 0, sizeof *p);
    p->done_bytes = j->done_bytes;
    p->total_bytes = j->total_bytes;
    p->done_files = j->done_files;
    p->total_files = j->total_files;
    p->errors = j->nerr;
    p->warnings = j->nwarn;
    p->skipped = j->skipped;
    u64 end = j->t_end ? j->t_end : now, w = (u64)gz_atomic_load(&j->wait_ms);
    p->elapsed_ms = end > j->t_start + w ? end - j->t_start - w : 0;
}

static void emit_progress(gz_job *j, int force)
{
    if (!j->cb.progress) return;
    u64 now = gz_os_ms();
    gz_progress p;
    gzch cur[512];
    gz_os_mutex_lock(j->lock);
    if (!force && now - j->last_emit < 100) { gz_os_mutex_unlock(j->lock); return; }
    j->last_emit = now;
    snapshot(j, &p, now);
    wcopy(cur, j->current, GZ_COUNTOF(cur));
    gz_os_mutex_unlock(j->lock);
    p.current = cur;
    gz_os_mutex_lock(j->cb_lock);
    j->cb.progress(j->cb.user, &p);
    gz_os_mutex_unlock(j->cb_lock);
}

static void add_progress(gz_job *j, u32 files, u64 bytes, u32 skipped)
{
    gz_os_mutex_lock(j->lock);
    j->done_files += files;
    j->done_bytes += bytes;
    j->skipped += skipped;
    gz_os_mutex_unlock(j->lock);
}

/* ask the front end (ask_lock held by the caller); time spent waiting is not "work" */
static int ask_ui(gz_job *j, gz_ask *q)
{
    if (!j->cb.ask) return -1;
    u64 t0 = gz_os_ms();
    int r = j->cb.ask(j->cb.user, q);
    gz_atomic_add(&j->wait_ms, (long)(gz_os_ms() - t0));
    return r;
}

static gz_job *job_alloc(int kind, const gz_callbacks *cb)
{
    gz_job *j = (gz_job *)gz_alloc(sizeof(gz_job));
    if (!j) return 0;
    j->kind = kind;
    if (cb) j->cb = *cb;
    j->lock = gz_os_mutex_new();
    j->ask_lock = gz_os_mutex_new();
    j->cb_lock = gz_os_mutex_new();
    j->cond = gz_os_cond_new();
    j->name_max = 255;
    if (!j->lock || !j->ask_lock || !j->cb_lock || !j->cond) {
        gz_os_mutex_free(j->lock);
        gz_os_mutex_free(j->ask_lock);
        gz_os_mutex_free(j->cb_lock);
        gz_os_cond_free(j->cond);
        gz_free(j);
        return 0;
    }
    return j;
}

static void job_finish(gz_job *j, int result)
{
    gz_os_mutex_lock(j->lock);
    j->t_end = gz_os_ms();
    j->result = result;
    gz_os_mutex_unlock(j->lock);
    emit_progress(j, 1);
    if (j->cb.done) j->cb.done(j->cb.user, result);
    gz_os_mutex_lock(j->lock);
    j->finished = 1;
    gz_os_cond_broadcast(j->cond);
    gz_os_mutex_unlock(j->lock);
}

static int job_launch(gz_job *j, int (*fn)(void *))
{
    j->t_start = gz_os_ms();
    j->thread = gz_os_thread_start(fn, j, 1u << 20);
    return j->thread != 0;
}

static int final_result(gz_job *j)
{
    if (cancelled(j)) return GZ_E_CANCEL;
    return j->nerr ? (j->first_err ? j->first_err : GZ_E_DATA) : GZ_OK;
}

/* ---------------- archives for browsing ---------------- */

typedef struct ocb {
    const gz_callbacks *cb;
    const gzch *name;
    const gzch *known;
    int used_known;
    u64 last;
    gz_ask q;
} ocb;

static int o_ask_pw(void *user, gzch *buf, u32 cap, int retry)
{
    ocb *x = (ocb *)user;
    if (!cap) return GZ_E_PASSWORD;
    if (x->known && x->known[0] && !x->used_known) {
        x->used_known = 1;
        wcopy(buf, x->known, cap);
        return GZ_OK;
    }
    if (!x->cb || !x->cb->ask) return GZ_E_PASSWORD;
    __builtin_memset(&x->q, 0, sizeof x->q);
    x->q.kind = GZ_ASK_PASSWORD;
    x->q.path = x->name;
    x->q.archive = x->name;
    x->q.retry = retry || x->used_known;
    x->used_known = 1;
    int a = x->cb->ask(x->cb->user, &x->q);
    if (a == GZ_ANS_CANCEL) return GZ_E_CANCEL;
    if (a != GZ_ANS_YES || !x->q.answer[0]) return GZ_E_PASSWORD;
    wcopy(buf, x->q.answer, cap);
    return GZ_OK;
}

static int o_volume(void *user, const gzch *name, gz_src **out)
{
    ocb *x = (ocb *)user;
    if (!gz_os_open_src(name, out)) return GZ_OK;
    if (!x->cb || !x->cb->ask) return GZ_E_VOLUME;
    for (int tries = 0; tries < 1000; tries++) {
        __builtin_memset(&x->q, 0, sizeof x->q);
        x->q.kind = GZ_ASK_VOLUME;
        x->q.path = name;
        x->q.archive = x->name;
        x->q.retry = tries > 0;
        int a = x->cb->ask(x->cb->user, &x->q);
        if (a == GZ_ANS_CANCEL) return GZ_E_CANCEL;
        if (a != GZ_ANS_YES) return GZ_E_VOLUME;
        if (!gz_os_open_src(x->q.answer[0] ? x->q.answer : name, out)) return GZ_OK;
    }
    return GZ_E_VOLUME;
}

static void o_progress(void *user, u64 done, u64 total)
{
    ocb *x = (ocb *)user;
    if (!x->cb || !x->cb->progress) return;
    u64 now = gz_os_ms();
    if (now - x->last < 100) return;
    x->last = now;
    gz_progress p;
    __builtin_memset(&p, 0, sizeof p);
    p.done_bytes = done;
    p.total_bytes = total;
    p.current = x->name;
    x->cb->progress(x->cb->user, &p);
}

static void make_open_opts(gz_open_opts *oo, ocb *x, const gz_open_req *req, const gz_callbacks *cb,
                           const gzch *file_name, const gzch *display)
{
    __builtin_memset(x, 0, sizeof *x);
    x->cb = cb;
    x->name = display;
    x->known = req->password;
    __builtin_memset(oo, 0, sizeof *oo);
    oo->codepage = req->codepage;
    oo->file_name = file_name;
    oo->cancel = req->cancel;
    oo->password = req->password;
    oo->ask_password = o_ask_pw;
    oo->open_volume = o_volume;
    oo->progress = o_progress;
    oo->user = x;
    oo->flags = req->flags;
}

void gz_handle_close(gz_handle *h)
{
    if (!h) return;
    gz_arc_close(h->arc);
    gz_src_free(h->src);
    if (h->temp && h->path) {
        gz_os_delete(h->path);
        size_t n = wlen(h->path), s = last_sep(h->path, n);
        if (s < n && s) {
            h->path[s] = 0;
            gz_os_delete(h->path);      /* the private temporary folder */
        }
    }
    gz_free(h->path);
    gz_free(h->name);
    gz_free(h->mark);
    gz_free(h);
}

static void handle_mark(gz_handle *h, const gzch *path)
{
    u8 buf[4096];
    u32 n = 0;
    if (!(gz_os_caps() & GZ_OSC_MARK)) return;
    if (gz_os_mark_get(path, buf, sizeof buf, &n) || !n) return;
    h->mark = (u8 *)gz_alloc(n);
    if (h->mark) { __builtin_memcpy(h->mark, buf, n); h->mark_n = n; }
}

static int handle_open_named(gz_handle **out, const gzch *path, const gzch *display, const gz_open_req *req,
                             const gz_callbacks *cb)
{
    gz_open_req def;
    __builtin_memset(&def, 0, sizeof def);
    if (!req) req = &def;
    *out = 0;
    gz_handle *h = (gz_handle *)gz_alloc(sizeof(gz_handle));
    if (!h) return GZ_E_NOMEM;
    h->path = wdup(path);
    h->name = wdup(display);
    if (!h->path || !h->name) { gz_handle_close(h); return GZ_E_NOMEM; }
    int e = gz_os_open_src(path, &h->src);
    if (e) { gz_handle_close(h); return gz_os_err_gz(e, GZ_E_IO); }
    gz_ctx *c = gz_ctx_new();
    if (!c) { gz_handle_close(h); return GZ_E_NOMEM; }
    ocb *x = (ocb *)gz_alloc(sizeof(ocb));
    if (!x) { gz_ctx_free(c); gz_handle_close(h); return GZ_E_NOMEM; }
    gz_open_opts oo;
    make_open_opts(&oo, x, req, cb, path, h->name);
    int r = gz_arc_open(&h->arc, h->src, &oo, c);
    gz_ctx_free(c);
    gz_free(x);
    if (r) { gz_handle_close(h); return r; }
    handle_mark(h, path);
    *out = h;
    return GZ_OK;
}

int gz_handle_open(gz_handle **out, const gzch *path, const gz_open_req *req, const gz_callbacks *cb)
{
    return handle_open_named(out, path, base_name(path), req, cb);
}

int gz_handle_set_codepage(gz_handle *h, int codepage)
{
    return gz_arc_set_codepage(h->arc, codepage);
}

/* plain output into one file (temporary copies of nested archives) */
typedef struct fout { gz_out o; gz_fd fd; int err; } fout;
static int fo_open(gz_out *o, u32 idx) { (void)o; (void)idx; return GZ_OK; }
static int fo_write(gz_out *o, const u8 *p, size_t n)
{
    fout *f = (fout *)o;
    int e = gz_os_write(f->fd, p, n);
    if (e) f->err = gz_os_err_gz(e, GZ_E_IO);
    return f->err;
}
static int fo_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; (void)st; return GZ_OK; }

/* extract entry idx of parent into tmp (password asked through cb when needed) */
static int copy_entry(gz_handle *parent, u32 idx, gz_fd fd, const gz_open_req *req, const gz_callbacks *cb)
{
    gz_archive *a = parent->arc;
    gz_ctx *c = gz_ctx_new();
    if (!c) return GZ_E_NOMEM;
    c->cancel = req->cancel;
    gzch *pw = (gzch *)gz_alloc(GZ_ASK_CAP * sizeof(gzch));
    gz_ask *q = (gz_ask *)gz_alloc(sizeof(gz_ask));
    int r = GZ_E_NOMEM;
    if (!pw || !q) goto out;
    if (req->password) wcopy(pw, req->password, GZ_ASK_CAP);
    else if (a->password) wcopy(pw, a->password, GZ_ASK_CAP);
    c->password = pw[0] ? pw : 0;
    for (int tries = 0; a->e[idx].enc && tries < 1000; tries++) {
        r = gz_arc_check_password(a, parent->src, idx, c);
        if (r != GZ_E_PASSWORD) break;
        if (!cb || !cb->ask) goto out;
        __builtin_memset(q, 0, sizeof *q);
        q->kind = GZ_ASK_PASSWORD;
        q->path = a->e[idx].name;
        q->archive = parent->name;
        q->retry = c->password != 0;
        int ans = cb->ask(cb->user, q);
        if (ans == GZ_ANS_CANCEL) { r = GZ_E_CANCEL; goto out; }
        if (ans != GZ_ANS_YES || !q->answer[0]) { r = GZ_E_PASSWORD; goto out; }
        wcopy(pw, q->answer, GZ_ASK_CAP);
        c->password = pw;
    }
    fout f = { { fo_open, fo_write, fo_close, 0 }, fd, 0 };
    r = gz_arc_extract(a, parent->src, idx, &f.o, c);
    if (!r && f.err) r = f.err;
out:
    gz_free(q);
    gz_free(pw);
    gz_ctx_free(c);
    return r;
}

int gz_handle_open_child(gz_handle **out, gz_handle *parent, u32 idx, const gz_open_req *req,
                         const gz_callbacks *cb)
{
    gz_open_req def;
    __builtin_memset(&def, 0, sizeof def);
    if (!req) req = &def;
    *out = 0;
    if (!parent || idx >= parent->arc->n) return GZ_E_FORMAT;
    const gz_entry *e = &parent->arc->e[idx];
    if (e->is_dir || !e->name[0]) return GZ_E_FORMAT;
    gzch *display = wjoin(parent->name, '/', e->name);
    if (!display) return GZ_E_NOMEM;

    /* 1) directly through a view of the parent */
    gz_ctx *c = gz_ctx_new();
    ocb *x = (ocb *)gz_alloc(sizeof(ocb));
    if (!c || !x) { gz_ctx_free(c); gz_free(x); gz_free(display); return GZ_E_NOMEM; }
    gz_open_opts oo;
    make_open_opts(&oo, x, req, cb, e->name, display);
    c->cancel = req->cancel;
    gz_archive *a = 0;
    int r = gz_arc_open_child(&a, parent->arc, parent->src, idx, &oo, c);
    gz_ctx_free(c);
    gz_free(x);
    if (!r) {
        gz_handle *h = (gz_handle *)gz_alloc(sizeof(gz_handle));
        if (!h) { gz_arc_close(a); gz_free(display); return GZ_E_NOMEM; }
        h->arc = a;
        h->name = display;
        h->parent = parent;
        h->path = wdup(parent->path);
        int oe = h->path ? gz_os_open_src(h->path, &h->src) : GZ_OSE_NOMEM;
        if (oe) { gz_handle_close(h); return gz_os_err_gz(oe, GZ_E_IO); }
        if (parent->mark_n && (h->mark = (u8 *)gz_alloc(parent->mark_n))) {
            __builtin_memcpy(h->mark, parent->mark, parent->mark_n);
            h->mark_n = parent->mark_n;
        }
        *out = h;
        return GZ_OK;
    }
    if (r != GZ_E_METHOD) { gz_free(display); return r; }

    /* 2) through a temporary copy in a private folder: <tmp>/gogitzip-XXXXXX/<name> */
    gzch *dir = (gzch *)gz_alloc(PCAP * sizeof(gzch));
    gzch *file = 0;
    gz_fd fd = GZ_FD_NONE;
    r = GZ_E_NOMEM;
    if (!dir || gz_os_temp_dir(dir, PCAP - 32)) { r = dir ? GZ_E_CREATE : r; goto fail; }
    {
        size_t n = wlen(dir);
        static const gzch pre[] = u"/gogitzip-";
        gzch prefix[PCAP];
        wcopy(prefix, dir, PCAP);
        wcopy(prefix + n, pre, PCAP - n);
        prefix[n] = SEP;
        int made = 0;
        for (int tries = 0; tries < 50 && !made; tries++) {
            if (gz_os_create_temp(prefix, dir, PCAP, &fd)) break;
            gz_os_close(fd);
            fd = GZ_FD_NONE;
            gz_os_delete(dir);
            made = !gz_os_mkdir(dir, 0700);
        }
        if (!made) { r = GZ_E_CREATE; goto fail; }
    }
    {
        const gzch *bn = base_name(e->name);
        size_t bl = wlen(bn);
        file = wjoin(dir, SEP, bl > 100 ? bn + bl - 100 : bn);   /* keeps the extension */
    }
    if (!file) goto fail_dir;
    {
        int ce = gz_os_create(file, 0600, &fd);
        if (ce) { r = gz_os_err_gz(ce, GZ_E_CREATE); goto fail_dir; }
    }
    r = copy_entry(parent, idx, fd, req, cb);
    {
        int ce = gz_os_close(fd);
        fd = GZ_FD_NONE;
        if (!r && ce) r = gz_os_err_gz(ce, GZ_E_IO);
    }
    if (!r) {
        gz_handle *h = 0;
        r = handle_open_named(&h, file, display, req, cb);
        if (!r) {
            h->temp = 1;
            if (!h->mark_n && parent->mark_n && (h->mark = (u8 *)gz_alloc(parent->mark_n))) {
                __builtin_memcpy(h->mark, parent->mark, parent->mark_n);
                h->mark_n = parent->mark_n;
            }
            gz_free(file);
            gz_free(dir);
            gz_free(display);
            *out = h;
            return GZ_OK;
        }
    }
    gz_os_delete(file);
fail_dir:
    gz_os_delete(dir);
fail:
    if (fd != GZ_FD_NONE) gz_os_close(fd);
    gz_free(file);
    gz_free(dir);
    gz_free(display);
    return r;
}

/* ---------------- extraction: output paths ---------------- */

static int lower3_eq(const gzch *c, const char *w)
{
    for (int i = 0; i < 3; i++) if ((c[i] | 32) != w[i]) return 0;
    return 1;
}

/* CON, PRN, AUX, NUL, COM1-9, LPT1-9 (also "NUL .txt", "COM¹") */
static int is_reserved(const gzch *c, size_t n)
{
    size_t b = 0;
    while (b < n && c[b] != '.') b++;
    while (b && c[b - 1] == ' ') b--;
    if (b == 3) return lower3_eq(c, "con") || lower3_eq(c, "prn") || lower3_eq(c, "aux") || lower3_eq(c, "nul");
    if (b == 4 && ((c[3] >= '1' && c[3] <= '9') || c[3] == 0x00B9 || c[3] == 0x00B2 || c[3] == 0x00B3))
        return lower3_eq(c, "com") || lower3_eq(c, "lpt");
    return 0;
}

/* Shorten the component c[0..n) in place to fit name_max native units:
 * "<start of the name>~<8 hex digits of a hash of the whole name><.ext>". */
static size_t shorten(gzch *c, size_t n, u32 name_max)
{
    u32 h = 2166136261u;
    for (size_t i = 0; i < n; i++) h = (h ^ c[i]) * 16777619u;
    size_t ext = n;
    for (size_t i = n; i-- > 1;) {
        if (c[i] == '.') { if (n - i <= 16) ext = i; break; }
    }
    size_t extn = n - ext, extb = gz_os_native_len(c + ext, extn);
    if (extb + 9 + 4 > name_max) { ext = n; extn = 0; extb = 0; }
    size_t budget = name_max - 9 - extb, used = 0, keep = 0;
    while (keep < ext) {
        size_t step = (c[keep] >= 0xD800 && c[keep] < 0xDC00 && keep + 1 < ext) ? 2 : 1;
        size_t b = gz_os_native_len(c + keep, step);
        if (used + b > budget) break;
        used += b;
        keep += step;
    }
    gzch e[17];
    for (size_t i = 0; i < extn; i++) e[i] = c[ext + i];
    size_t o = keep;
    c[o++] = '~';
    for (int i = 7; i >= 0; i--) c[o++] = (gzch)"0123456789abcdef"[(h >> (i * 4)) & 15];
    for (size_t i = 0; i < extn; i++) c[o++] = e[i];
    return o;
}

/* Append component c[0..n) to out (length *po). 1 = nothing to add, 0 = added, -1 = too long */
static int put_comp(gz_job *j, gzch *out, size_t *po, size_t cap, const gzch *c, size_t n, int *shortened)
{
    if (!n || (n == 1 && c[0] == '.') || (n == 2 && c[0] == '.' && c[1] == '.')) return 1;
    size_t o = *po;
    if (o + n + 48 >= cap) return -1;
    if (!o || out[o - 1] != SEP) out[o++] = SEP;
    size_t st = o;
    int win = (j->caps & GZ_OSC_WIN_NAMES) != 0;
    if (win && is_reserved(c, n)) out[o++] = '_';
    for (size_t i = 0; i < n; i++) {
        gzch ch = c[i];
        if (ch < 32 || ch == SEP || ch == '/') ch = '_';
        else if (win && (ch == '<' || ch == '>' || ch == ':' || ch == '"' || ch == '|' || ch == '?' ||
                         ch == '*' || ch == '\\'))
            ch = '_';
        out[o++] = ch;
    }
    if (win && (out[o - 1] == '.' || out[o - 1] == ' ')) out[o - 1] = '_';
    if (gz_os_native_len(out + st, o - st) > j->name_max) {
        o = st + shorten(out + st, o - st, j->name_max);
        *shortened = 1;
    }
    out[o] = 0;
    *po = o;
    return 0;
}

/* "<dest>/<sanitised path of name>". 1 ok, 0 nothing to write (outside the stripped
 * folder, folders without paths), -1 too long. */
static int build_out_path(gz_job *j, const gzch *name, int is_dir, gzch *out, size_t cap, int *shortened)
{
    int sh = 0;
    if (shortened) *shortened = 0;
    const gzch *rel = name;
    if (j->path_mode == GZ_PATH_STRIP && j->strip_len) {
        if (!prefix_eq(rel, j->strip, j->strip_len, j->ci) || rel[j->strip_len] != '/') return 0;
        rel += j->strip_len + 1;
    }
    if (!rel[0]) return 0;
    if (j->path_mode == GZ_PATH_NONE) {
        if (is_dir) return 0;
        rel = base_name(rel);
    }
    if (j->dest_len + 2 >= cap) return -1;
    __builtin_memcpy(out, j->dest, j->dest_len * sizeof(gzch));
    size_t o = j->dest_len;
    out[o] = 0;
    int added = 0;
    const gzch *p = rel;
    while (*p) {
        const gzch *st = p;
        while (*p && *p != '/') p++;
        int r = put_comp(j, out, &o, cap, st, (size_t)(p - st), &sh);
        if (r < 0) return -1;
        if (!r) added = 1;
        if (*p) p++;
    }
    if (shortened) *shortened = sh;
    return added;
}

/* "name.txt" -> "name (2).txt" ... the first free name. 0 ok, -1 none found */
static int unique_name(gzch *path, gzch *tmp)
{
    size_t n = wlen(path), b = last_sep(path, n);
    b = b < n ? b + 1 : 0;
    size_t dot = n;
    for (size_t i = n; i-- > b + 1;) if (path[i] == '.') { if (n - i < 60) dot = i; break; }
    gzch ext[64];
    size_t en = n - dot;
    for (size_t i = 0; i < en; i++) ext[i] = path[dot + i];
    wcopy(tmp, path, PCAP);
    for (u32 k = 2; k < 100000; k++) {
        gzch num[16];
        int d = 0;
        for (u32 v = k; v; v /= 10) num[d++] = (gzch)('0' + v % 10);
        size_t o = dot;
        if (o + d + 4 + en >= PCAP) return -1;
        tmp[o++] = ' ';
        tmp[o++] = '(';
        while (d) tmp[o++] = num[--d];
        tmp[o++] = ')';
        for (size_t i = 0; i < en; i++) tmp[o++] = ext[i];
        tmp[o] = 0;
        gz_os_info st;
        if (gz_os_stat(tmp, &st, 0) == GZ_OSE_NOENT) { wcopy(path, tmp, PCAP); return 0; }
    }
    return -1;
}

/* Is any folder of path below the destination a symbolic link? */
static int parent_has_link(gz_job *j, gzch *path)
{
    size_t n = wlen(path);
    for (size_t i = j->dest_len + 1; i < n; i++) {
        if (path[i] != SEP) continue;
        path[i] = 0;
        gz_os_info st;
        int r = gz_os_stat(path, &st, 0);
        path[i] = SEP;
        if (!r && st.type == GZ_FT_LINK) return 1;
        if (r) return 0;            /* missing: nothing deeper exists either */
    }
    return 0;
}

/* Would following target from the folder that holds linkpath leave the destination?
 * Links met on the way are followed (they are on disk); a missing component ends
 * the lookups (later ".." are counted lexically). Transient escapes count. */
static int link_escapes(gz_job *j, scratch *s, const gzch *linkpath, const gzch *target)
{
    if (target[0] == '/' || target[0] == '\\') return 1;
    gzch *buf = s->tmp, *q = s->q;
    size_t n = wlen(linkpath), cl = last_sep(linkpath, n);
    if (cl >= n) return 1;
    if (cl < j->dest_len) cl = j->dest_len;          /* destination "/" */
    __builtin_memcpy(buf, linkpath, cl * sizeof(gzch));
    buf[cl] = 0;
    long depth = 0;                                  /* folders below the destination */
    for (size_t i = j->dest_len; i < cl;) {
        while (i < cl && buf[i] == SEP) i++;
        if (i >= cl) break;
        depth++;
        while (i < cl && buf[i] != SEP) i++;
    }
    size_t ql = wcopy(q, target, 2 * PCAP), qp = 0;
    int hops = 0, missing = 0;
    long miss_depth = 0;
    while (qp < ql) {
        size_t st = qp;
        while (qp < ql && q[qp] != '/') qp++;
        size_t len = qp - st;
        if (qp < ql) qp++;
        if (!len || (len == 1 && q[st] == '.')) continue;
        if (len == 2 && q[st] == '.' && q[st + 1] == '.') {
            if (depth == 0) return 1;
            while (cl > j->dest_len && buf[cl - 1] != SEP) cl--;
            if (cl > j->dest_len) cl--;
            buf[cl] = 0;
            depth--;
            if (missing && depth < miss_depth) missing = 0;
            continue;
        }
        if (cl + len + 2 >= PCAP) return 1;
        size_t before = cl;
        if (!cl || buf[cl - 1] != SEP) buf[cl++] = SEP;
        __builtin_memcpy(buf + cl, q + st, len * sizeof(gzch));
        cl += len;
        buf[cl] = 0;
        depth++;
        if (missing) continue;
        gz_os_info sb;
        int r = gz_os_stat(buf, &sb, 0);
        if (r) { missing = 1; miss_depth = depth; continue; }
        if (sb.type != GZ_FT_LINK) continue;
        if (++hops > 40) return 1;
        gzch lt[1024];
        if (gz_os_readlink(buf, lt, GZ_COUNTOF(lt)) || !lt[0] || lt[0] == '/' || lt[0] == '\\') return 1;
        cl = before;                 /* replace the link by its target */
        buf[cl] = 0;
        depth--;
        size_t ltn = wlen(lt), rest = ql - qp;
        if (ltn + 1 + rest + 1 >= 2 * PCAP) return 1;
        /* q = lt + "/" + q[qp..ql) */
        __builtin_memmove(q + ltn + 1, q + qp, rest * sizeof(gzch));
        __builtin_memcpy(q, lt, ltn * sizeof(gzch));
        q[ltn] = '/';
        ql = ltn + 1 + rest;
        q[ql] = 0;
        qp = 0;
    }
    return 0;
}

/* ---------------- extraction: workers ---------------- */

typedef struct worker {
    gz_out o;
    gz_job *j;
    gz_src *src;
    gz_ctx *c;
    gz_os_thread *t;
    gz_fd fd;
    u32 idx;
    int opened, mode;
    u64 pending;
    gzch pw[256];
    int has_pw, pw_gen;
    u8 *lbuf; u32 llen, lcap; int lerr;
    size_t lastdir_len;
    gzch lastdir[PCAP];
    scratch s;
} worker;

static void flush_progress(worker *w)
{
    if (!w->pending) return;
    add_progress(w->j, 0, w->pending, 0);
    w->pending = 0;
}

static int decide_overwrite(gz_job *j, const gz_entry *e, const gzch *path, const gz_os_info *old)
{
    gz_os_mutex_lock(j->ask_lock);
    int mode = j->overwrite;
    if (mode == GZ_OW_NEWER) {
        u64 t = gz_entry_time(e);
        mode = (t && t / 10000000u > old->mtime / 10000000u) ? GZ_OW_ALL : GZ_OW_SKIP;
    }
    if (mode == GZ_OW_ASK && cancelled(j)) mode = -1;
    if (mode == GZ_OW_ASK) {
        gz_ask *q = (gz_ask *)gz_alloc(sizeof(gz_ask));
        if (!q) {
            mode = GZ_OW_SKIP;
        } else {
            q->kind = GZ_ASK_OVERWRITE;
            q->path = path;
            q->archive = j->h->name;
            q->entry = e->name;
            q->old_size = old->size;
            q->old_mtime = old->mtime;
            q->new_size = e->usize == GZ_SIZE_UNKNOWN ? 0 : e->usize;
            q->new_mtime = gz_entry_time(e);
            int r = ask_ui(j, q);
            gz_free(q);
            switch (r) {
            case -1: mode = GZ_OW_SKIP; break;
            case GZ_ANS_YES: mode = GZ_OW_ALL; break;
            case GZ_ANS_NO: mode = GZ_OW_SKIP; break;
            case GZ_ANS_YES_ALL: mode = j->overwrite = GZ_OW_ALL; break;
            case GZ_ANS_NO_ALL: mode = j->overwrite = GZ_OW_SKIP; break;
            case GZ_ANS_RENAME: mode = GZ_OW_RENAME; break;
            case GZ_ANS_RENAME_ALL: mode = j->overwrite = GZ_OW_RENAME; break;
            default: mode = -1; gz_atomic_store(&j->cancel, 1); break;
            }
        }
    }
    gz_os_mutex_unlock(j->ask_lock);
    return mode;
}

/* Something exists at path (st): decide, make room. 0 go on, GZ_E_SKIP, GZ_E_CANCEL or error */
static int make_room(gz_job *j, const gz_entry *e, gzch *path, gzch *tmp, const gz_os_info *st)
{
    int mode = st->type == GZ_FT_DIR ? GZ_OW_RENAME : decide_overwrite(j, e, path, st);
    if (mode < 0 || cancelled(j)) return GZ_E_CANCEL;
    if (mode == GZ_OW_SKIP) return GZ_E_SKIP;
    if (mode == GZ_OW_RENAME) {
        if (unique_name(path, tmp)) return GZ_E_CREATE;
        job_log(j, GZ_LOG_NOTE, GZ_N_RENAMED, e->name, path);
        return GZ_OK;
    }
    /* replace: remove what is there (never write through it) */
    int r = gz_os_delete(path);
    return r && r != GZ_OSE_NOENT ? gz_os_err_gz(r, GZ_E_CREATE) : GZ_OK;
}

static int ensure_parent(worker *w, gzch *path)
{
    gz_job *j = w->j;
    size_t n = wlen(path), s = last_sep(path, n);
    if (s >= n || s <= j->dest_len) return GZ_OSE_OK;
    if (s == w->lastdir_len && !__builtin_memcmp(w->lastdir, path, s * sizeof(gzch))) return GZ_OSE_OK;
    path[s] = 0;
    int e = gz_os_mkdirs(path);
    if (!e) { __builtin_memcpy(w->lastdir, path, s * sizeof(gzch)); w->lastdir_len = s; }
    path[s] = SEP;
    return e;
}

static void defer_link(gz_job *j, u32 idx, gzch *target)
{
    gz_os_mutex_lock(j->lock);
    if (j->nlinks == j->caplinks) {
        u32 nc = j->caplinks ? j->caplinks * 2 : 64;
        dlink *nl = (dlink *)gz_realloc(j->links, (size_t)nc * sizeof(dlink));
        if (nl) { j->links = nl; j->caplinks = nc; }
    }
    int ok = j->nlinks < j->caplinks;
    if (ok) { j->links[j->nlinks].idx = idx; j->links[j->nlinks].target = target; j->nlinks++; }
    gz_os_mutex_unlock(j->lock);
    if (!ok) { gz_free(target); job_log(j, GZ_LOG_ERROR, GZ_E_NOMEM, j->h->arc->e[idx].name, 0); }
}

/* entry finished without reaching close (skipped or failed in open) */
static int open_fail(worker *w, const gz_entry *e, int r)
{
    if (r == GZ_E_CANCEL) return r;
    if (!e->is_dir) add_progress(w->j, 1, e->usize == GZ_SIZE_UNKNOWN ? 0 : e->usize, r == GZ_E_SKIP);
    return r;
}

static int w_open(gz_out *o, u32 idx)
{
    worker *w = (worker *)o;
    gz_job *j = w->j;
    const gz_entry *e = &j->h->arc->e[idx];
    w->idx = idx;
    w->opened = 1;
    w->fd = GZ_FD_NONE;
    w->mode = W_NONE;
    w->llen = 0;
    w->lerr = 0;
    if (cancelled(j)) return GZ_E_CANCEL;
    set_current(j, e->name);

    if (j->test) { w->mode = W_TEST; return GZ_OK; }
    if (e->is_link) {
        if (!(j->caps & GZ_OSC_LINKS) || (j->flags & GZ_XF_NO_LINKS)) {
            job_log(j, GZ_LOG_WARN, GZ_N_LINK_UNSUPPORTED, e->name, 0);
            return open_fail(w, e, GZ_E_SKIP);
        }
        if (e->link_len) {
            gzch *t = gz_entry_link_target(j->h->arc, e);
            if (!t) { job_log(j, GZ_LOG_ERROR, GZ_E_NOMEM, e->name, 0); return open_fail(w, e, GZ_E_NOMEM); }
            defer_link(j, idx, t);
            add_progress(j, 1, 0, 0);
            return GZ_E_SKIP;          /* created after the files */
        }
        w->mode = W_LINK;              /* target is the entry's data */
        return GZ_OK;
    }
    int sh = 0;
    int b = build_out_path(j, e->name, e->is_dir, w->s.path, PCAP, &sh);
    if (b < 0) { job_log(j, GZ_LOG_ERROR, GZ_N_PATH_LONG, e->name, 0); return open_fail(w, e, GZ_E_CREATE); }
    if (!b) return open_fail(w, e, GZ_E_SKIP);
    if (sh) job_log(j, GZ_LOG_WARN, GZ_N_SHORTENED, e->name, w->s.path);

    if (e->is_dir) {
        int r = gz_os_mkdirs(w->s.path);
        if (r) {
            job_log(j, GZ_LOG_ERROR, gz_os_err_gz(r, GZ_E_CREATE), e->name, w->s.path);
            return open_fail(w, e, GZ_E_CREATE);
        }
        return GZ_OK;
    }
    int r = ensure_parent(w, w->s.path);
    if (r) {
        job_log(j, GZ_LOG_ERROR, gz_os_err_gz(r, GZ_E_CREATE), e->name, w->s.path);
        return open_fail(w, e, GZ_E_CREATE);
    }
    /* create exclusively; only when something is there already, decide what to do */
    for (int tries = 0;; tries++) {
        if (cancelled(j)) return GZ_E_CANCEL;
        r = gz_os_create(w->s.path, 0666, &w->fd);
        if (r != GZ_OSE_EXIST || tries >= 3) break;
        gz_os_info st;
        if (gz_os_stat(w->s.path, &st, 0)) continue;     /* gone meanwhile */
        r = make_room(j, e, w->s.path, w->s.tmp, &st);
        if (r == GZ_E_SKIP || r == GZ_E_CANCEL) return open_fail(w, e, r);
        if (r) { job_log(j, GZ_LOG_ERROR, r, e->name, w->s.path); return open_fail(w, e, r); }
    }
    if (r) {
        w->fd = GZ_FD_NONE;
        job_log(j, GZ_LOG_ERROR, gz_os_err_gz(r, GZ_E_CREATE), e->name, w->s.path);
        return open_fail(w, e, GZ_E_CREATE);
    }
    w->mode = W_FILE;
    return GZ_OK;
}

static void wait_unpaused(gz_job *j)
{
    gz_os_mutex_lock(j->lock);
    while (gz_atomic_load(&j->paused) && !cancelled(j)) gz_os_cond_wait(j->cond, j->lock);
    gz_os_mutex_unlock(j->lock);
}

static int w_write(gz_out *o, const u8 *p, size_t n)
{
    worker *w = (worker *)o;
    gz_job *j = w->j;
    if (gz_atomic_load(&j->paused)) wait_unpaused(j);
    if (cancelled(j)) return GZ_E_CANCEL;
    if (w->mode == W_FILE) {
        int e = gz_os_write(w->fd, p, n);
        if (e) return gz_os_err_gz(e, GZ_E_IO);
    } else if (w->mode == W_LINK) {
        if (w->llen + n > LINK_DATA_MAX) { w->lerr = GZ_E_LIMIT; return GZ_E_LIMIT; }
        if (w->llen + n > w->lcap) {
            u32 nc = w->lcap ? w->lcap : 256;
            while (nc < w->llen + n) nc *= 2;
            u8 *nb = (u8 *)gz_realloc(w->lbuf, nc);
            if (!nb) { w->lerr = GZ_E_NOMEM; return GZ_E_NOMEM; }
            w->lbuf = nb;
            w->lcap = nc;
        }
        __builtin_memcpy(w->lbuf + w->llen, p, n);
        w->llen += (u32)n;
    }
    w->pending += n;
    if (w->pending >= (256u << 10)) flush_progress(w);
    return GZ_OK;
}

static u32 entry_mode(gz_job *j, const gz_entry *e, int *apply)
{
    *apply = 0;
    if (!(j->caps & GZ_OSC_MODES) || (j->flags & GZ_XF_NO_PERMS)) return 0;
    u32 m = e->unix_mode & 07777;
    if (m) {
        if (!(j->flags & GZ_XF_SETUID)) m &= ~06000u;
        if (!e->is_dir) m &= ~01000u;
        m &= ~j->umask | 07000u;
        *apply = 1;
        return m;
    }
    if (e->attr & 1) {                     /* read-only DOS attribute */
        *apply = 1;
        return (e->is_dir ? 0777u : 0666u) & ~j->umask & ~0222u;
    }
    return 0;
}

static int w_close(gz_out *o, u32 idx, int st)
{
    worker *w = (worker *)o;
    gz_job *j = w->j;
    const gz_entry *e = &j->h->arc->e[idx];
    flush_progress(w);
    if (w->mode == W_FILE && w->fd != GZ_FD_NONE) {
        if (st == GZ_OK) {
            if (j->h->mark_n && (j->caps & GZ_OSC_MARK) && !(j->flags & GZ_XF_NO_MARK))
                gz_os_mark_set(w->fd, w->s.path, j->h->mark, j->h->mark_n);
            int apply;
            u32 m = entry_mode(j, e, &apply);
            if (apply && m != (0666u & ~j->umask)) gz_os_fset_mode(w->fd, m);   /* else as created */
            u64 t = (j->flags & GZ_XF_NO_TIMES) ? 0 : gz_entry_time(e);
            if (t) gz_os_fset_times(w->fd, t, 0);
            if ((j->caps & GZ_OSC_ATTRS) && (e->attr & 7) && !(j->flags & GZ_XF_NO_PERMS))
                gz_os_fset_attr(w->fd, w->s.path, e->attr & 7);    /* read-only, hidden, system */
        }
        int ce = gz_os_close(w->fd);
        w->fd = GZ_FD_NONE;
        if (ce && st == GZ_OK) st = gz_os_err_gz(ce, GZ_E_IO);
        if (st != GZ_OK && !(j->flags & GZ_XF_KEEP_BROKEN)) gz_os_delete(w->s.path);
    } else if (w->mode == W_LINK && st == GZ_OK) {
        gzch *t = decode_target(j->h->arc, w->lbuf ? w->lbuf : (const u8 *)"", w->llen);
        if (t) defer_link(j, idx, t);
        else st = GZ_E_NOMEM;
    }
    if (w->mode == W_LINK && st != GZ_OK && w->lerr) st = w->lerr;
    w->mode = W_NONE;
    if (!e->is_dir) add_progress(j, 1, 0, 0);
    if (st != GZ_OK && st != GZ_E_SKIP && st != GZ_E_CANCEL) job_log(j, GZ_LOG_ERROR, st, e->name, 0);
    return GZ_OK;
}

/* Try a password. 1 when extraction should go ahead with it: it is right, or the entry
 * fails for a reason that is not the password (extraction will report that). */
static int try_password(worker *w, u32 idx, const gzch *pw, int gen)
{
    w->c->password = pw;
    int rc = gz_arc_check_password(w->j->h->arc, w->src, idx, w->c);
    w->c->password = w->has_pw ? w->pw : 0;
    if (rc == GZ_E_PASSWORD) return 0;
    if (pw != w->pw) wcopy(w->pw, pw, GZ_COUNTOF(w->pw));
    w->has_pw = 1;
    w->pw_gen = gen;
    w->c->password = w->pw;
    return 1;
}

/* Make sure the worker holds a password for entry idx: GZ_OK, GZ_E_PASSWORD (none
 * available: the user declined) or GZ_E_CANCEL. */
static int ensure_password(worker *w, u32 idx)
{
    gz_job *j = w->j;
    gz_archive *a = j->h->arc;
    w->c->password = 0;
    if (gz_arc_check_password(a, w->src, idx, w->c) != GZ_E_PASSWORD) {
        w->c->password = w->has_pw ? w->pw : 0;
        return GZ_OK;
    }
    w->c->password = w->has_pw ? w->pw : 0;
    int tried_gen = -1;
    gzch cand[256];
    for (;;) {
        if (cancelled(j)) return GZ_E_CANCEL;
        gz_os_mutex_lock(j->ask_lock);
        int gen = j->pw_gen, have = j->pw_set;
        if (have) wcopy(cand, j->pw, GZ_COUNTOF(cand));
        gz_os_mutex_unlock(j->ask_lock);

        if (have && gen != tried_gen) {
            tried_gen = gen;
            if (w->pw_gen == gen && w->has_pw && try_password(w, idx, w->pw, gen)) return GZ_OK;
            if (try_password(w, idx, cand, gen)) return GZ_OK;
        }

        gz_os_mutex_lock(j->ask_lock);
        if (j->pw_gen != tried_gen && j->pw_set) { gz_os_mutex_unlock(j->ask_lock); continue; }
        if (cancelled(j)) { gz_os_mutex_unlock(j->ask_lock); return GZ_E_CANCEL; }
        if (j->pw_refused || !j->cb.ask) { gz_os_mutex_unlock(j->ask_lock); return GZ_E_PASSWORD; }
        gz_ask *q = (gz_ask *)gz_alloc(sizeof(gz_ask));
        if (!q) { gz_os_mutex_unlock(j->ask_lock); return GZ_E_PASSWORD; }
        q->kind = GZ_ASK_PASSWORD;
        q->path = a->e[idx].name;
        q->archive = j->h->name;
        q->entry = a->e[idx].name;
        q->retry = tried_gen >= 0;
        int r = ask_ui(j, q);
        if (r == GZ_ANS_CANCEL) {
            gz_atomic_store(&j->cancel, 1);
            gz_os_mutex_unlock(j->ask_lock);
            gz_free(q);
            return GZ_E_CANCEL;
        }
        if (r != GZ_ANS_YES || !q->answer[0]) {
            j->pw_refused = 1;
            gz_os_mutex_unlock(j->ask_lock);
            gz_free(q);
            return GZ_E_PASSWORD;
        }
        wcopy(j->pw, q->answer, GZ_COUNTOF(j->pw));
        j->pw_set = 1;
        j->pw_gen++;
        gz_os_mutex_unlock(j->ask_lock);
        gz_free(q);
    }
}

static int worker_main(void *arg)
{
    worker *w = (worker *)arg;
    gz_job *j = w->j;
    gz_archive *a = j->h->arc;

    if (a->solid) {
        int pr = GZ_OK;
        for (u32 k = 0; a->has_enc && k < j->count; k++) {
            const gz_entry *e = &a->e[j->order[k]];
            if (e->enc && !e->is_dir) { pr = ensure_password(w, j->order[k]); break; }
        }
        if (pr != GZ_E_CANCEL) {
            if (!w->has_pw) {
                gz_os_mutex_lock(j->ask_lock);
                if (j->pw_set) { wcopy(w->pw, j->pw, GZ_COUNTOF(w->pw)); w->has_pw = 1; }
                gz_os_mutex_unlock(j->ask_lock);
            }
            w->c->password = w->has_pw ? w->pw : a->password;
            u32 before = j->nerr;
            int r = gz_arc_extract_solid(a, w->src, j->sel, &w->o, w->c);
            if (r && r != GZ_E_CANCEL && r != GZ_E_SKIP && j->nerr == before)
                job_log(j, GZ_LOG_ERROR, r, j->h->name, 0);
        }
    } else {
        for (;;) {
            long k = gz_atomic_inc(&j->next) - 1;
            if ((u32)k >= j->count || cancelled(j)) break;
            u32 idx = j->order[k];
            gz_entry *e = &a->e[idx];
            if (e->enc && !e->is_dir) {
                int pr = ensure_password(w, idx);
                if (pr == GZ_E_CANCEL) break;
                if (pr) {
                    job_log(j, GZ_LOG_ERROR, GZ_E_PASSWORD, e->name, 0);
                    add_progress(j, 1, e->usize == GZ_SIZE_UNKNOWN ? 0 : e->usize, 0);
                    continue;
                }
            }
            w->opened = 0;
            int r = gz_arc_extract(a, w->src, idx, &w->o, w->c);
            if (r == GZ_E_PASSWORD && !w->opened && e->enc) {
                /* stale password (e.g. per-file passwords): ask again */
                gz_os_mutex_lock(j->ask_lock);
                if (j->pw_gen == w->pw_gen) { j->pw_set = 0; j->pw_gen++; }
                gz_os_mutex_unlock(j->ask_lock);
                int pr = ensure_password(w, idx);
                if (pr == GZ_E_CANCEL) break;
                if (!pr) r = gz_arc_extract(a, w->src, idx, &w->o, w->c);
            }
            if (r && r != GZ_E_SKIP && r != GZ_E_CANCEL && !w->opened) {
                job_log(j, GZ_LOG_ERROR, r, e->name, 0);
                add_progress(j, e->is_dir ? 0 : 1, e->usize == GZ_SIZE_UNKNOWN ? 0 : e->usize, 0);
            }
            if (r == GZ_E_CANCEL) break;
        }
    }
    gz_os_mutex_lock(j->lock);
    j->running--;
    gz_os_cond_broadcast(j->cond);
    gz_os_mutex_unlock(j->lock);
    return 0;
}

/* ---------------- extraction: links and folders after the files ---------------- */

static int link_less(void *ctx, u32 a, u32 b)
{
    const dlink *l = (const dlink *)ctx;
    return l[a].idx < l[b].idx;
}

/* copy a file (hard link fallback) */
static int copy_file(gz_job *j, const gzch *from, const gzch *to)
{
    gz_fd in, out;
    int e = gz_os_open_read(from, &in);
    if (e) return gz_os_err_gz(e, GZ_E_IO);
    e = gz_os_create(to, 0666, &out);
    if (e) { gz_os_close(in); return gz_os_err_gz(e, GZ_E_CREATE); }
    u8 *buf = (u8 *)gz_alloc(1u << 18);
    int r = buf ? GZ_OK : GZ_E_NOMEM;
    while (!r) {
        u32 got = 0;
        e = gz_os_read(in, buf, 1u << 18, &got);
        if (e) { r = GZ_E_IO; break; }
        if (!got) break;
        e = gz_os_write(out, buf, got);
        if (e) r = gz_os_err_gz(e, GZ_E_IO);
        if (cancelled(j)) r = GZ_E_CANCEL;
    }
    gz_os_info st;
    if (!r && !gz_os_fstat(in, &st)) {
        if (j->caps & GZ_OSC_MODES) gz_os_fset_mode(out, st.mode & 07777);
        gz_os_fset_times(out, st.mtime, 0);
    }
    gz_free(buf);
    gz_os_close(in);
    if (gz_os_close(out) && !r) r = GZ_E_IO;
    if (r) gz_os_delete(to);
    return r;
}

typedef struct made_link { gzch *path; gzch *target; u32 idx; } made_link;

static void links_phase(gz_job *j, scratch *s)
{
    gz_archive *a = j->h->arc;
    u32 n = j->nlinks;
    if (!n) return;
    u32 *ord = (u32 *)gz_alloc((size_t)n * sizeof(u32));
    made_link *made = (made_link *)gz_alloc((size_t)n * sizeof(made_link));
    if (!ord || !made) {
        gz_free(ord); gz_free(made);
        job_log(j, GZ_LOG_ERROR, GZ_E_NOMEM, j->h->name, 0);
        return;
    }
    for (u32 i = 0; i < n; i++) ord[i] = i;
    sort_u32(ord, n, link_less, j->links);
    int unsafe = (j->flags & GZ_XF_UNSAFE_LINKS) != 0;
    u32 nmade = 0;

    for (u32 k = 0; k < n && !cancelled(j); k++) {
        dlink *L = &j->links[ord[k]];
        const gz_entry *e = &a->e[L->idx];
        set_current(j, e->name);
        int sh;
        int b = build_out_path(j, e->name, 0, s->path, PCAP, &sh);
        if (b < 0) { job_log(j, GZ_LOG_ERROR, GZ_N_PATH_LONG, e->name, 0); continue; }
        if (!b) continue;
        if (sh) job_log(j, GZ_LOG_WARN, GZ_N_SHORTENED, e->name, s->path);
        if (parent_has_link(j, s->path)) { job_log(j, GZ_LOG_WARN, GZ_N_LINK_THROUGH, e->name, L->target); continue; }
        int hard = e->is_link == 2;
        if (hard) {
            gzch *tn = wdup(L->target);
            if (!tn) { job_log(j, GZ_LOG_ERROR, GZ_E_NOMEM, e->name, 0); continue; }
            sanitize_rel(tn);
            int tb = build_out_path(j, tn, 0, s->tpath, PCAP, 0);
            gz_free(tn);
            gz_os_info ts;
            if (tb <= 0 || gz_os_stat(s->tpath, &ts, 0) || (ts.type != GZ_FT_FILE && ts.type != GZ_FT_LINK)) {
                job_log(j, GZ_LOG_WARN, GZ_N_LINK_TARGET, e->name, L->target);
                continue;
            }
            if (!gz_wcscmp(s->tpath, s->path)) continue;           /* a link to itself */
            if (parent_has_link(j, s->tpath)) { job_log(j, GZ_LOG_WARN, GZ_N_LINK_THROUGH, e->name, L->target); continue; }
            if (ts.type == GZ_FT_LINK) {
                /* a second name for a symbolic link would read its relative target from the
                 * new place: create it as a symbolic link and check it like one */
                gzch lt[1024];
                gzch *nt = gz_os_readlink(s->tpath, lt, GZ_COUNTOF(lt)) ? 0 : wdup(lt);
                if (!nt) { job_log(j, GZ_LOG_WARN, GZ_N_LINK_TARGET, e->name, L->target); continue; }
                gz_free(L->target);
                L->target = nt;
                hard = 0;
            }
        }
        if (!hard) {
            if (!L->target[0]) { job_log(j, GZ_LOG_ERROR, GZ_E_FORMAT, e->name, 0); continue; }
            if (!unsafe && (L->target[0] == '/' || L->target[0] == '\\' ||
                            (L->target[1] == ':' && (j->caps & GZ_OSC_WIN_NAMES)))) {
                job_log(j, GZ_LOG_WARN, GZ_N_LINK_ABSOLUTE, e->name, L->target);
                continue;
            }
            if (!unsafe && link_escapes(j, s, s->path, L->target)) {
                job_log(j, GZ_LOG_WARN, GZ_N_LINK_ESCAPE, e->name, L->target);
                continue;
            }
        }
        size_t pn = wlen(s->path), ps = last_sep(s->path, pn);
        if (ps < pn && ps > j->dest_len) {
            s->path[ps] = 0;
            int me = gz_os_mkdirs(s->path);
            s->path[ps] = SEP;
            if (me) { job_log(j, GZ_LOG_ERROR, gz_os_err_gz(me, GZ_E_CREATE), e->name, s->path); continue; }
        }
        gz_os_info st;
        if (!gz_os_stat(s->path, &st, 0)) {
            int r = make_room(j, e, s->path, s->tmp, &st);
            if (r == GZ_E_CANCEL) break;
            if (r == GZ_E_SKIP) { add_progress(j, 0, 0, 1); continue; }
            if (r) { job_log(j, GZ_LOG_ERROR, r, e->name, s->path); continue; }
        }
        int r;
        if (hard) {
            r = gz_os_link(s->tpath, s->path);
            if (r && r != GZ_OSE_EXIST) r = copy_file(j, s->tpath, s->path) ? GZ_OSE_OTHER : 0;
        } else {
            r = gz_os_symlink(L->target, s->path);
        }
        if (r) { job_log(j, GZ_LOG_ERROR, GZ_E_CREATE, e->name, L->target); continue; }
        if (!hard) {
            u64 t = (j->flags & GZ_XF_NO_TIMES) ? 0 : gz_entry_time(e);
            if (t) gz_os_set_times(s->path, t, 0, 0);
            made[nmade].path = wdup(s->path);
            made[nmade].target = L->target;
            made[nmade].idx = L->idx;
            if (made[nmade].path) nmade++;
        }
    }

    /* A link checked early can be redirected by a link created after it: check every
     * link again with all of them in place, until nothing changes. */
    for (int round = 0; !unsafe && nmade && round < 16 && !cancelled(j); round++) {
        int changed = 0;
        for (u32 i = 0; i < nmade; i++) {
            if (!made[i].path || !link_escapes(j, s, made[i].path, made[i].target)) continue;
            gz_os_delete(made[i].path);
            job_log(j, GZ_LOG_WARN, GZ_N_LINK_ESCAPE, a->e[made[i].idx].name, made[i].target);
            gz_free(made[i].path);
            made[i].path = 0;
            changed = 1;
        }
        if (!changed) break;
        if (round == 15) {          /* still moving: do not trust any of them */
            for (u32 i = 0; i < nmade; i++) {
                if (!made[i].path) continue;
                gz_os_delete(made[i].path);
                job_log(j, GZ_LOG_WARN, GZ_N_LINK_ESCAPE, a->e[made[i].idx].name, made[i].target);
            }
        }
    }
    for (u32 i = 0; i < nmade; i++) gz_free(made[i].path);
    gz_free(made);
    gz_free(ord);
}

typedef struct depth_ctx { const gz_archive *a; } depth_ctx;
static u32 name_depth(const gzch *s) { u32 d = 0; for (; *s; s++) d += *s == '/'; return d; }
static int deeper(void *ctx, u32 x, u32 y)
{
    const gz_archive *a = ((depth_ctx *)ctx)->a;
    return name_depth(a->e[x].name) > name_depth(a->e[y].name);
}

static void dirs_phase(gz_job *j, scratch *s)
{
    gz_archive *a = j->h->arc;
    if (j->path_mode == GZ_PATH_NONE) return;
    u32 nd = 0;
    for (u32 k = 0; k < j->count; k++) nd += a->e[j->order[k]].is_dir;
    if (!nd) return;
    u32 *d = (u32 *)gz_alloc((size_t)nd * sizeof(u32));
    if (!d) return;
    nd = 0;
    for (u32 k = 0; k < j->count; k++) if (a->e[j->order[k]].is_dir) d[nd++] = j->order[k];
    depth_ctx dc = { a };
    sort_u32(d, nd, deeper, &dc);      /* children before parents */
    for (u32 k = 0; k < nd && !cancelled(j); k++) {
        const gz_entry *e = &a->e[d[k]];
        gz_os_info st;
        if (build_out_path(j, e->name, 1, s->path, PCAP, 0) <= 0) continue;
        if (gz_os_stat(s->path, &st, 0) || st.type != GZ_FT_DIR) continue;
        int apply;
        u32 m = entry_mode(j, e, &apply);
        if (apply) gz_os_set_mode(s->path, m);
        u64 t = (j->flags & GZ_XF_NO_TIMES) ? 0 : gz_entry_time(e);
        if (t) gz_os_set_times(s->path, t, 0, 0);
    }
    gz_free(d);
}

/* ---------------- extraction: controller ---------------- */

static int extract_main(void *arg)
{
    gz_job *j = (gz_job *)arg;
    gz_archive *a = j->h->arc;
    scratch *s = (scratch *)gz_alloc(sizeof(scratch));
    if (!s) { job_log(j, GZ_LOG_ERROR, GZ_E_NOMEM, j->h->name, 0); job_finish(j, GZ_E_NOMEM); return 0; }
    if (!j->test) {
        int e = gz_os_mkdirs(j->dest);
        if (e) {
            job_log(j, GZ_LOG_ERROR, gz_os_err_gz(e, GZ_E_CREATE), j->dest, 0);
            gz_free(s);
            job_finish(j, final_result(j));
            return 0;
        }
        j->name_max = gz_os_name_max(j->dest);
        if (j->name_max < 32) j->name_max = 32;
    }

    u32 nw = (u32)j->threads;
    if (a->solid) nw = 1;
    if (nw > j->count) nw = j->count ? j->count : 1;
    if (nw > MAX_WORKERS) nw = MAX_WORKERS;
    if (nw < 1) nw = 1;
    worker *ws = (worker *)gz_alloc(sizeof(worker) * nw);
    u32 started = 0;
    for (u32 i = 0; ws && i < nw; i++) {
        worker *w = &ws[i];
        w->o.open = w_open;
        w->o.write = w_write;
        w->o.close = w_close;
        w->j = j;
        w->fd = GZ_FD_NONE;
        w->c = gz_ctx_new();
        int oe = w->c ? gz_os_open_src(j->h->path, &w->src) : GZ_OSE_NOMEM;
        if (oe) {
            if (i == 0) job_log(j, GZ_LOG_ERROR, gz_os_err_gz(oe, GZ_E_IO), j->h->path, 0);
            gz_ctx_free(w->c);
            w->c = 0;
            break;
        }
        w->c->cancel = &j->cancel;
        gz_os_mutex_lock(j->lock);
        j->running++;
        gz_os_mutex_unlock(j->lock);
        w->t = gz_os_thread_start(worker_main, w, 2u << 20);
        if (!w->t) {
            gz_os_mutex_lock(j->lock);
            j->running--;
            gz_os_mutex_unlock(j->lock);
            gz_ctx_free(w->c);
            gz_src_free(w->src);
            w->c = 0;
            if (i == 0) job_log(j, GZ_LOG_ERROR, GZ_E_NOMEM, j->h->name, 0);
            break;
        }
        started++;
    }
    if (!ws) job_log(j, GZ_LOG_ERROR, GZ_E_NOMEM, j->h->name, 0);
    gz_os_mutex_lock(j->lock);
    while (j->running) {
        gz_os_cond_timedwait(j->cond, j->lock, 100);
        gz_os_mutex_unlock(j->lock);
        emit_progress(j, 0);
        gz_os_mutex_lock(j->lock);
    }
    gz_os_mutex_unlock(j->lock);
    for (u32 i = 0; i < started; i++) gz_os_thread_join(ws[i].t);
    for (u32 i = 0; i < started; i++) {
        gz_ctx_free(ws[i].c);
        gz_src_free(ws[i].src);
        gz_free(ws[i].lbuf);
    }
    gz_free(ws);
    if (!j->test && !cancelled(j)) links_phase(j, s);
    if (!j->test && !cancelled(j)) dirs_phase(j, s);
    gz_free(s);
    set_current(j, 0);
    job_finish(j, final_result(j));
    return 0;
}

/* ---------------- extraction: setup ---------------- */

static int order_less(void *ctx, u32 x, u32 y)
{
    const gz_archive *a = (const gz_archive *)ctx;
    const gz_entry *p = &a->e[x], *q = &a->e[y];
    if (p->is_dir != q->is_dir) return p->is_dir > q->is_dir;   /* folders first */
    return p->off < q->off;
}

static int in_scope(gz_job *j, const gz_entry *e)
{
    if (!e->name || !e->name[0]) return 0;
    if (j->path_mode != GZ_PATH_STRIP || !j->strip_len) return 1;
    return prefix_eq(e->name, j->strip, j->strip_len, j->ci) && e->name[j->strip_len] == '/';
}

/* Do two entries map to the same output file? Then one worker writes them in order. */
static int has_collisions(gz_job *j)
{
    gz_archive *a = j->h->arc;
    u32 cap = 16;
    while (cap < j->count * 2 + 2 && cap < (1u << 30)) cap <<= 1;
    u64 *tab = (u64 *)gz_alloc((size_t)cap * sizeof(u64));
    gzch *p = (gzch *)gz_alloc(PCAP * sizeof(gzch));
    int coll = !tab || !p;
    for (u32 k = 0; k < j->count && !coll; k++) {
        const gz_entry *e = &a->e[j->order[k]];
        if (e->is_dir || build_out_path(j, e->name, 0, p, PCAP, 0) <= 0) continue;
        u64 h = 1469598103934665603ULL;
        for (const gzch *c = p; *c; c++) h = (h ^ (j->ci ? fold(*c) : *c)) * 1099511628211ULL;
        if (!h) h = 1;
        u32 i = (u32)h & (cap - 1);
        while (tab[i]) {
            if (tab[i] == h) { coll = 1; break; }
            i = (i + 1) & (cap - 1);
        }
        tab[i] = h;
    }
    gz_free(tab);
    gz_free(p);
    return coll;
}

static gzch *norm_dir(const gzch *d)
{
    if (!d || !d[0]) d = u".";
    size_t n = wlen(d);
    while (n > 1 && (d[n - 1] == SEP || d[n - 1] == '/')) n--;
    return wdupn(d, n);
}

gz_job *gz_extract_start(gz_handle *h, const gz_extract_opts *o, const gz_callbacks *cb)
{
    gz_job *j = job_alloc(JOB_EXTRACT, cb);
    if (!j) return 0;
    gz_archive *a = h->arc;
    j->h = h;
    if (o->codepage) gz_arc_set_codepage(a, o->codepage < 0 ? GZ_CP_AUTO : o->codepage);
    j->caps = gz_os_caps();
    j->ci = (j->caps & GZ_OSC_CASE_FOLD) || a->case_fold;
    j->umask = gz_os_umask();
    j->path_mode = o->path_mode;
    j->overwrite = o->overwrite;
    j->test = o->test;
    j->flags = o->flags;
    j->threads = o->threads > 0 ? o->threads : gz_os_cpu_count();
    if (o->strip && o->strip[0]) {
        j->strip = wdup(o->strip);
        if (!j->strip) goto nomem;
        j->strip_len = sanitize_rel(j->strip);
    }
    if (j->path_mode == GZ_PATH_STRIP && !j->strip_len) j->path_mode = GZ_PATH_FULL;
    if (o->password && o->password[0]) wcopy(j->pw, o->password, GZ_COUNTOF(j->pw));
    else if (a->password) wcopy(j->pw, a->password, GZ_COUNTOF(j->pw));
    if (j->pw[0]) { j->pw_set = 1; j->pw_gen = 1; }

    j->order = (u32 *)gz_alloc((size_t)a->n * sizeof(u32) + 4);
    if (!j->order) goto nomem;
    for (u32 i = 0; i < a->n; i++) {
        const gz_entry *e = &a->e[i];
        if (o->sel && !o->sel[i]) continue;
        if (!in_scope(j, e)) continue;
        j->order[j->count++] = i;
        if (!e->is_dir) {
            j->total_files++;
            if (e->usize != GZ_SIZE_UNKNOWN) j->total_bytes += e->usize;
        }
    }
    if (!a->solid) sort_u32(j->order, j->count, order_less, a);
    j->sel = (u8 *)gz_alloc((size_t)a->n + 1);
    if (!j->sel) goto nomem;
    for (u32 k = 0; k < j->count; k++) j->sel[j->order[k]] = 1;

    j->dest = norm_dir(o->dest);
    if (!j->dest) goto nomem;
    if (o->smart && !j->test && gz_smart_needs_folder(a, j->sel, j->path_mode == GZ_PATH_STRIP ? j->strip : 0)) {
        gzch stem[512];
        gz_archive_stem(h->name, stem, GZ_COUNTOF(stem));
        gzch *nd = wjoin(j->dest, (j->dest[0] == SEP && !j->dest[1]) ? 0 : SEP, stem);
        if (!nd) goto nomem;
        gz_free(j->dest);
        j->dest = nd;
    }
    j->dest_len = wlen(j->dest);
    if (!a->solid && !j->test && j->threads > 1 && has_collisions(j)) j->threads = 1;
    if (!job_launch(j, extract_main)) goto nomem;
    return j;
nomem:
    gz_job_free(j);
    return 0;
}

/* ---------------- compression ---------------- */

typedef struct citem_src { gz_wsrc w; gz_fd fd; gz_job *j; } citem_src;

typedef struct walk {
    gz_job *j;
    gz_witem *it; u32 n, cap;
    gz_arena ar;
    u64 skip_dev[2], skip_ino[2]; int nskip;
    int follow, nfd;
    u64 total;
    gzch abs[PCAP], rel[PCAP];
} walk;

static gzch *arena_wdup(gz_arena *ar, const gzch *s, size_t n)
{
    gzch *d = (gzch *)gz_arena_alloc(ar, (n + 1) * sizeof(gzch));
    if (d) { __builtin_memcpy(d, s, n * sizeof(gzch)); d[n] = 0; }
    return d;
}

static int skip_file(walk *w, const gz_os_info *st)
{
    for (int i = 0; i < w->nskip; i++) if (w->skip_dev[i] == st->dev && w->skip_ino[i] == st->ino) return 1;
    return 0;
}

static int add_item(walk *w, const gzch *abs, const gzch *rel, const gz_os_info *st, const gzch *target)
{
    if (w->n == w->cap) {
        if (w->cap >= (1u << 27)) return GZ_E_LIMIT;
        u32 nc = w->cap ? w->cap * 2 : 256;
        gz_witem *ni = (gz_witem *)gz_realloc(w->it, (size_t)nc * sizeof(gz_witem));
        if (!ni) return GZ_E_NOMEM;
        w->it = ni;
        w->cap = nc;
    }
    gz_witem *it = &w->it[w->n];
    __builtin_memset(it, 0, sizeof *it);
    size_t rn = wlen(rel);
    gzch *nm = arena_wdup(&w->ar, rel, rn);
    gzch *src = arena_wdup(&w->ar, abs, wlen(abs));
    if (!nm || !src) return GZ_E_NOMEM;
    for (size_t i = 0; i < rn; i++) if (nm[i] == SEP) nm[i] = '/';
    if (w->nfd) nm[gz_hangul_compose(nm, (int)rn)] = 0;
    it->name = nm;
    it->user = src;
    it->is_dir = st->type == GZ_FT_DIR;
    it->is_link = target != 0;
    it->size = st->type == GZ_FT_FILE ? st->size : 0;
    it->mtime = st->mtime;
    it->atime = st->atime;
    it->ctime = st->ctime;
    it->attr = st->attr;
    it->unix_mode = st->mode;
    if (target) {
        size_t tn = wlen(target);
        gzch *t = arena_wdup(&w->ar, target, tn);
        if (!t) return GZ_E_NOMEM;
        if (w->nfd) t[gz_hangul_compose(t, (int)tn)] = 0;
        it->link_target = t;
    }
    w->n++;
    if (st->type == GZ_FT_FILE) w->total += st->size;
    if (st->type != GZ_FT_DIR) w->j->total_files++;
    return GZ_OK;
}

/* stat abs (following links when asked); classify; add; returns GZ_FT_DIR when the
 * caller should descend, GZ_FT_NONE otherwise; *err set on fatal errors */
static int visit(walk *w, const gzch *abs, const gzch *rel, int *err, gz_os_info *out)
{
    gz_job *j = w->j;
    gz_os_info st;
    int e = gz_os_stat(abs, &st, 0);
    if (e) {
        job_log(j, GZ_LOG_WARN, e == GZ_OSE_NOENT ? GZ_N_NOT_FOUND : GZ_N_UNREADABLE, abs, 0);
        return GZ_FT_NONE;
    }
    gzch *target = 0;
    gzch lt[1024];
    if (st.type == GZ_FT_LINK) {
        gz_os_info fs;
        if (w->follow && !gz_os_stat(abs, &fs, 1)) {
            st = fs;
        } else if (w->follow) {
            job_log(j, GZ_LOG_WARN, GZ_N_UNREADABLE, abs, 0);      /* dangling link */
            return GZ_FT_NONE;
        } else {
            if (gz_os_readlink(abs, lt, GZ_COUNTOF(lt))) {
                job_log(j, GZ_LOG_WARN, GZ_N_UNREADABLE, abs, 0);
                return GZ_FT_NONE;
            }
            target = lt;
        }
    }
    if (skip_file(w, &st)) return GZ_FT_NONE;
    if (st.type == GZ_FT_OTHER) { job_log(j, GZ_LOG_NOTE, GZ_N_SPECIAL, abs, 0); return GZ_FT_NONE; }
    int r = add_item(w, abs, rel, &st, target);
    if (r) { *err = r; return GZ_FT_NONE; }
    *out = st;
    return st.type == GZ_FT_DIR ? GZ_FT_DIR : GZ_FT_NONE;
}

typedef struct frame {
    gzch *abs, *rel;
    gzch *names; u32 *offs; u32 n, pos;
    u64 dev, ino;
} frame;

static int name_less(void *ctx, u32 a, u32 b)
{
    const gzch *n = (const gzch *)ctx;
    return gz_wcscmp(n + a, n + b) < 0;
}

/* read and sort the names in a folder */
static int frame_fill(gz_job *j, frame *f)
{
    gz_os_dir *d;
    int e = gz_os_dir_open(f->abs, &d);
    if (e) { job_log(j, GZ_LOG_WARN, GZ_N_UNREADABLE, f->abs, 0); return GZ_OK; }
    size_t used = 0, cap = 0;
    u32 ocap = 0;
    int r = GZ_OK;
    for (;;) {
        const gzch *nm;
        int type;
        e = gz_os_dir_next(d, &nm, &type);
        if (e) { job_log(j, GZ_LOG_WARN, GZ_N_UNREADABLE, f->abs, 0); break; }
        if (!nm) break;
        size_t l = wlen(nm);
        if (used + l + 1 > cap) {
            size_t nc = cap ? cap * 2 : 1024;
            while (nc < used + l + 1) nc *= 2;
            gzch *nb = (gzch *)gz_realloc(f->names, nc * sizeof(gzch));
            if (!nb) { r = GZ_E_NOMEM; break; }
            f->names = nb;
            cap = nc;
        }
        if (f->n == ocap) {
            if (ocap >= (1u << 26)) { r = GZ_E_LIMIT; break; }
            u32 nc = ocap ? ocap * 2 : 64;
            u32 *no = (u32 *)gz_realloc(f->offs, (size_t)nc * sizeof(u32));
            if (!no) { r = GZ_E_NOMEM; break; }
            f->offs = no;
            ocap = nc;
        }
        if (used > 0xffffffffu - l - 1) { r = GZ_E_LIMIT; break; }
        __builtin_memcpy(f->names + used, nm, (l + 1) * sizeof(gzch));
        f->offs[f->n++] = (u32)used;
        used += l + 1;
    }
    gz_os_dir_close(d);
    if (!r) sort_u32(f->offs, f->n, name_less, f->names);
    return r;
}

static void frame_free(frame *f)
{
    gz_free(f->abs);
    gz_free(f->rel);
    gz_free(f->names);
    gz_free(f->offs);
    __builtin_memset(f, 0, sizeof *f);
}

/* depth-first walk below a folder already added as an item */
static int walk_tree(walk *w, const gzch *abs, const gzch *rel, const gz_os_info *st)
{
    gz_job *j = w->j;
    frame *stk = (frame *)gz_alloc(WALK_DEPTH * sizeof(frame));
    if (!stk) return GZ_E_NOMEM;
    int sp = 0, r = GZ_OK;
    stk[0].abs = wdup(abs);
    stk[0].rel = wdup(rel);
    stk[0].dev = st->dev;
    stk[0].ino = st->ino;
    if (!stk[0].abs || !stk[0].rel) r = GZ_E_NOMEM;
    else { sp = 1; r = frame_fill(j, &stk[0]); }
    while (sp > 0 && !r) {
        if (cancelled(j)) { r = GZ_E_CANCEL; break; }
        frame *f = &stk[sp - 1];
        if (f->pos >= f->n) { frame_free(f); sp--; continue; }
        const gzch *nm = f->names + f->offs[f->pos++];
        size_t an = wlen(f->abs), rn = wlen(f->rel), nn = wlen(nm);
        if (an + nn + 2 >= PCAP || rn + nn + 2 >= PCAP) {
            job_log(j, GZ_LOG_WARN, GZ_N_PATH_LONG, f->abs, nm);
            continue;
        }
        __builtin_memcpy(w->abs, f->abs, an * sizeof(gzch));
        size_t o = an;
        if (!an || w->abs[an - 1] != SEP) w->abs[o++] = SEP;
        __builtin_memcpy(w->abs + o, nm, (nn + 1) * sizeof(gzch));
        __builtin_memcpy(w->rel, f->rel, rn * sizeof(gzch));
        w->rel[rn] = SEP;
        __builtin_memcpy(w->rel + rn + 1, nm, (nn + 1) * sizeof(gzch));
        gz_os_info cs;
        if (visit(w, w->abs, w->rel, &r, &cs) != GZ_FT_DIR) continue;
        int loop = 0;
        for (int i = 0; i < sp; i++) if (stk[i].dev == cs.dev && stk[i].ino == cs.ino) loop = 1;
        if (loop) { job_log(j, GZ_LOG_WARN, GZ_N_LOOP, w->abs, 0); continue; }
        if (sp >= WALK_DEPTH) { job_log(j, GZ_LOG_WARN, GZ_N_PATH_LONG, w->abs, 0); continue; }
        frame *c = &stk[sp];
        __builtin_memset(c, 0, sizeof *c);
        c->abs = wdup(w->abs);
        c->rel = wdup(w->rel);
        c->dev = cs.dev;
        c->ino = cs.ino;
        sp++;
        if (!c->abs || !c->rel) { r = GZ_E_NOMEM; break; }
        r = frame_fill(j, c);
    }
    while (sp > 0) frame_free(&stk[--sp]);
    gz_free(stk);
    return r;
}

/* length of the common parent folder of the inputs (names start after it + SEP) */
static size_t common_base(gzch **in, u32 n)
{
    size_t l0 = wlen(in[0]);
    size_t L = last_sep(in[0], l0);
    if (L >= l0) L = 0;
    for (u32 i = 1; i < n; i++) {
        size_t li = wlen(in[i]), Li = last_sep(in[i], li);
        if (Li >= li) Li = 0;
        size_t m = 0;
        while (m < L && m < Li && in[0][m] == in[i][m]) m++;
        if (m == L && m == Li) continue;
        if (m == L && in[i][m] == SEP) continue;
        if (m == Li && in[0][m] == SEP) { L = m; continue; }
        /* the parents differ at m: back up to the last folder boundary before it */
        if (m) { m--; while (m > 0 && in[0][m] != SEP) m--; }
        L = m;
    }
    return L;
}

/* writer callbacks */
static int c_read(gz_wsrc *ws, u8 *buf, u32 cap, u32 *got)
{
    citem_src *s = (citem_src *)ws;
    if (cancelled(s->j)) return GZ_E_CANCEL;
    if (gz_atomic_load(&s->j->paused)) wait_unpaused(s->j);
    int e = gz_os_read(s->fd, buf, cap, got);
    return e ? GZ_E_IO : GZ_OK;
}

static int c_open_item(void *user, const gz_witem *it, gz_wsrc **out)
{
    gz_job *j = (gz_job *)user;
    *out = 0;
    if (cancelled(j)) return GZ_E_CANCEL;
    set_current(j, it->name);
    citem_src *s = (citem_src *)gz_alloc(sizeof(citem_src));
    if (!s) return GZ_E_NOMEM;
    int e = gz_os_open_read((const gzch *)it->user, &s->fd);
    if (e) { gz_free(s); return gz_os_err_gz(e, GZ_E_IO); }
    s->w.read = c_read;
    s->j = j;
    *out = &s->w;
    add_progress(j, 1, 0, 0);
    return GZ_OK;
}

static void c_close_item(void *user, const gz_witem *it, gz_wsrc *src)
{
    (void)user; (void)it;
    citem_src *s = (citem_src *)src;
    if (!s) return;
    gz_os_close(s->fd);
    gz_free(s);
}

static int c_on_error(void *user, const gz_witem *it, int err)
{
    gz_job *j = (gz_job *)user;
    if (err == GZ_E_CANCEL || err == GZ_E_NOMEM || err == GZ_E_DISK) return err;
    job_log(j, GZ_LOG_WARN, err == GZ_E_IO ? GZ_N_UNREADABLE : err, (const gzch *)it->user, 0);
    return GZ_OK;
}

static void c_progress(void *user, u64 done, u64 total)
{
    gz_job *j = (gz_job *)user;
    gz_os_mutex_lock(j->lock);
    j->done_bytes = done;
    if (total) j->total_bytes = total;
    gz_os_mutex_unlock(j->lock);
    emit_progress(j, 0);
}

/* buffered archive output */
typedef struct fsink { gz_sink k; gz_job *j; gz_fd fd; u8 *buf; size_t n, cap; } fsink;

static int fs_flush(fsink *s)
{
    if (!s->n) return GZ_OK;
    int e = gz_os_write(s->fd, s->buf, s->n);
    s->n = 0;
    return e ? gz_os_err_gz(e, GZ_E_IO) : GZ_OK;
}

static int fs_write(gz_sink *k, const void *p, size_t n)
{
    fsink *s = (fsink *)k;
    if (cancelled(s->j)) return GZ_E_CANCEL;
    if (s->n + n > s->cap) {
        int r = fs_flush(s);
        if (r) return r;
    }
    if (n >= s->cap) {
        int e = gz_os_write(s->fd, p, n);
        return e ? gz_os_err_gz(e, GZ_E_IO) : GZ_OK;
    }
    __builtin_memcpy(s->buf + s->n, p, n);
    s->n += n;
    return GZ_OK;
}

static int fs_write_at(gz_sink *k, u64 off, const void *p, size_t n)
{
    fsink *s = (fsink *)k;
    int r = fs_flush(s);
    if (r) return r;
    int e = gz_os_pwrite(s->fd, off, p, n);
    return e ? gz_os_err_gz(e, GZ_E_IO) : GZ_OK;
}

static int is_single_stream(int f) { return f == GZ_WF_GZ || f == GZ_WF_BZ2 || f == GZ_WF_XZ || f == GZ_WF_ZST; }

static int compress_main(void *arg)
{
    gz_job *j = (gz_job *)arg;
    gz_compress_opts *co = &j->co;
    walk *w = (walk *)gz_alloc(sizeof(walk));
    gzch *tmp = (gzch *)gz_alloc(PCAP * sizeof(gzch));
    gzch *prefix = 0;
    gz_fd fd = GZ_FD_NONE;
    int r = GZ_OK, made_tmp = 0;
    fsink k;
    __builtin_memset(&k, 0, sizeof k);
    if (!w || !tmp) { r = GZ_E_NOMEM; job_log(j, GZ_LOG_ERROR, r, j->c_out, 0); goto out; }
    w->j = j;
    w->follow = (co->flags & GZ_CF_FOLLOW_LINKS) != 0;
    w->nfd = (gz_os_caps() & GZ_OSC_NFD_NAMES) != 0;

    {   /* writer available for these options? */
        const gz_writer *wr = gz_writer_find(co->format);
        if (!wr || (co->method && !(wr->methods & (1u << co->method))) ||
            (co->encryption && !(wr->encryptions & (1u << co->encryption)))) {
            r = GZ_E_METHOD;
            job_log(j, GZ_LOG_ERROR, GZ_N_NO_WRITER, j->c_out, 0);
            goto out;
        }
    }

    /* existing archive */
    gz_os_info ost;
    int out_exists = !gz_os_stat(j->c_out, &ost, 0);
    if (out_exists) {
        if (ost.type == GZ_FT_DIR) { r = GZ_E_CREATE; job_log(j, GZ_LOG_ERROR, GZ_E_CREATE, j->c_out, 0); goto out; }
        int mode = co->overwrite;
        if (mode == GZ_OW_ASK) {
            gz_ask *q = (gz_ask *)gz_alloc(sizeof(gz_ask));
            int a = -1;
            if (q) {
                q->kind = GZ_ASK_OVERWRITE;
                q->path = j->c_out;
                q->archive = j->c_out;
                q->entry = j->c_out;
                q->old_size = ost.size;
                q->old_mtime = ost.mtime;
                gz_os_mutex_lock(j->ask_lock);
                a = ask_ui(j, q);
                gz_os_mutex_unlock(j->ask_lock);
                gz_free(q);
            }
            if (a == GZ_ANS_CANCEL) gz_atomic_store(&j->cancel, 1);
            mode = (a == GZ_ANS_YES || a == GZ_ANS_YES_ALL) ? GZ_OW_ALL : GZ_OW_SKIP;
        }
        if (cancelled(j)) { r = GZ_E_CANCEL; goto out; }
        if (mode != GZ_OW_ALL) { r = GZ_E_CREATE; job_log(j, GZ_LOG_ERROR, GZ_N_EXISTS, j->c_out, 0); goto out; }
        w->skip_dev[w->nskip] = ost.dev;
        w->skip_ino[w->nskip++] = ost.ino;
    }

    /* temporary output next to the archive */
    prefix = wjoin(j->c_out, 0, u".tmp-");
    if (!prefix) { r = GZ_E_NOMEM; goto out; }
    {
        int e = gz_os_create_temp(prefix, tmp, PCAP, &fd);
        if (e) { r = gz_os_err_gz(e, GZ_E_CREATE); job_log(j, GZ_LOG_ERROR, r, j->c_out, 0); goto out; }
        made_tmp = 1;
        gz_os_info ts;
        if (!gz_os_fstat(fd, &ts)) { w->skip_dev[w->nskip] = ts.dev; w->skip_ino[w->nskip++] = ts.ino; }
    }

    /* enumerate */
    if (!co->ninputs) { r = GZ_E_FORMAT; job_log(j, GZ_LOG_ERROR, GZ_N_NO_FILES, j->c_out, 0); goto out; }
    {
        size_t L = common_base(j->c_in, co->ninputs);
        for (u32 i = 0; i < co->ninputs && !r; i++) {
            const gzch *in = j->c_in[i];
            size_t n = wlen(in);
            if (n <= L + 1) { job_log(j, GZ_LOG_WARN, GZ_N_NOT_FOUND, in, 0); continue; }
            gz_os_info st;
            set_current(j, in);
            if (visit(w, in, in + L + 1, &r, &st) == GZ_FT_DIR && !r) r = walk_tree(w, in, in + L + 1, &st);
            if (cancelled(j)) r = GZ_E_CANCEL;
        }
        if (r) { if (r != GZ_E_CANCEL) job_log(j, GZ_LOG_ERROR, r, j->c_out, 0); goto out; }
        if (!w->n) { r = GZ_E_FORMAT; job_log(j, GZ_LOG_ERROR, GZ_N_NO_FILES, j->c_out, 0); goto out; }
        if (is_single_stream(co->format) && (w->n != 1 || w->it[0].is_dir || w->it[0].is_link)) {
            r = GZ_E_METHOD;
            job_log(j, GZ_LOG_ERROR, GZ_N_ONE_FILE, j->c_out, 0);
            goto out;
        }
        gz_os_mutex_lock(j->lock);
        j->total_bytes = w->total;
        gz_os_mutex_unlock(j->lock);
    }

    /* write */
    {
        gzch label[64];
        gz_wopts wo;
        __builtin_memset(&wo, 0, sizeof wo);
        wo.format = co->format;
        wo.method = co->method;
        wo.level = co->level;
        wo.dict_size = co->dict_size;
        wo.solid = co->solid;
        wo.threads = co->threads > 0 ? co->threads : gz_os_cpu_count();
        wo.encryption = j->c_pw ? co->encryption : GZ_WE_NONE;
        wo.password = j->c_pw;
        wo.encrypt_names = j->c_pw ? co->encrypt_names : 0;
        if (j->c_label) wo.label = j->c_label;
        else { gz_archive_stem(j->c_out, label, GZ_COUNTOF(label)); wo.label = label; }
        wo.open_item = c_open_item;
        wo.close_item = c_close_item;
        wo.on_error = c_on_error;
        wo.progress = c_progress;
        wo.user = j;
        wo.cancel = &j->cancel;
        k.k.write = fs_write;
        k.k.write_at = fs_write_at;
        k.j = j;
        k.fd = fd;
        k.cap = 1u << 20;
        k.buf = (u8 *)gz_alloc(k.cap);
        if (!k.buf) { r = GZ_E_NOMEM; goto out; }
        gz_ctx *c = gz_ctx_new();
        if (!c) { r = GZ_E_NOMEM; goto out; }
        c->cancel = &j->cancel;
        r = gz_write_archive(&wo, w->it, w->n, &k.k, c);
        gz_ctx_free(c);
        if (!r) r = fs_flush(&k);
        if (cancelled(j)) r = GZ_E_CANCEL;
        if (r && r != GZ_E_CANCEL) job_log(j, GZ_LOG_ERROR, r, j->c_out, 0);
    }
out:
    if (fd != GZ_FD_NONE) {
        int ce = gz_os_close(fd);
        if (!r && ce) { r = gz_os_err_gz(ce, GZ_E_IO); job_log(j, GZ_LOG_ERROR, r, j->c_out, 0); }
    }
    if (made_tmp) {
        if (!r) {
            int e = gz_os_rename(tmp, j->c_out);
            if (e) { r = gz_os_err_gz(e, GZ_E_CREATE); job_log(j, GZ_LOG_ERROR, r, j->c_out, 0); }
        }
        if (r) gz_os_delete(tmp);
    }
    gz_free(k.buf);
    if (w) { gz_free(w->it); gz_arena_free(&w->ar); }
    gz_free(w);
    gz_free(tmp);
    gz_free(prefix);
    set_current(j, 0);
    int res = final_result(j);
    if (!res && r) res = r;
    job_finish(j, res);
    return 0;
}

/* absolute input path without trailing separators ("/" stays) */
static gzch *norm_input(const gzch *p)
{
    size_t n = wlen(p);
    while (n > 1 && p[n - 1] == SEP) n--;
    return wdupn(p, n);
}

gz_job *gz_compress_start(const gz_compress_opts *o, const gz_callbacks *cb)
{
    gz_job *j = job_alloc(JOB_COMPRESS, cb);
    if (!j) return 0;
    j->co = *o;
    j->c_out = norm_input(o->out ? o->out : u"");
    j->c_in = (gzch **)gz_alloc(((size_t)o->ninputs + 1) * sizeof(gzch *));
    if (!j->c_out || !j->c_in) goto nomem;
    for (u32 i = 0; i < o->ninputs; i++) if (!(j->c_in[i] = norm_input(o->inputs[i]))) goto nomem;
    if (o->password && o->password[0] && !(j->c_pw = wdup(o->password))) goto nomem;
    if (o->label && !(j->c_label = wdup(o->label))) goto nomem;
    j->co.out = j->c_out;
    j->co.password = j->c_pw;
    j->co.label = j->c_label;
    j->co.inputs = (const gzch *const *)j->c_in;
    if (!job_launch(j, compress_main)) goto nomem;
    return j;
nomem:
    gz_job_free(j);
    return 0;
}

/* ---------------- open job ---------------- */

static int open_main(void *arg)
{
    gz_job *j = (gz_job *)arg;
    gz_callbacks cb = j->cb;
    cb.done = 0;
    cb.log = 0;
    int r = gz_handle_open(&j->o_h, j->o_path, &j->oreq, &cb);
    if (r && r != GZ_E_CANCEL) job_log(j, GZ_LOG_ERROR, r, j->o_path, 0);
    job_finish(j, cancelled(j) ? GZ_E_CANCEL : r);
    return 0;
}

gz_job *gz_open_start(const gzch *path, const gz_open_req *req, const gz_callbacks *cb)
{
    gz_job *j = job_alloc(JOB_OPEN, cb);
    if (!j) return 0;
    if (req) j->oreq = *req;
    j->o_path = wdup(path);
    if (!j->o_path) goto nomem;
    if (req && req->password && !(j->o_pw = wdup(req->password))) goto nomem;
    j->oreq.password = j->o_pw;
    j->oreq.cancel = &j->cancel;
    if (!job_launch(j, open_main)) goto nomem;
    return j;
nomem:
    gz_job_free(j);
    return 0;
}

/* ---------------- job control ---------------- */

void gz_job_cancel(gz_job *j)
{
    gz_atomic_store(&j->cancel, 1);
    gz_os_mutex_lock(j->lock);
    gz_os_cond_broadcast(j->cond);
    gz_os_mutex_unlock(j->lock);
}

void gz_job_pause(gz_job *j, int pause)
{
    gz_os_mutex_lock(j->lock);
    gz_atomic_store(&j->paused, pause ? 1 : 0);
    if (!pause) gz_os_cond_broadcast(j->cond);
    gz_os_mutex_unlock(j->lock);
}

int gz_job_wait(gz_job *j)
{
    if (j->thread) {
        gz_os_thread_join(j->thread);
        j->thread = 0;
    }
    return j->result;
}

int gz_job_wait_for(gz_job *j, u32 ms)
{
    gz_os_mutex_lock(j->lock);
    if (!j->finished) gz_os_cond_timedwait(j->cond, j->lock, ms);
    int f = j->finished;
    gz_os_mutex_unlock(j->lock);
    return f;
}

void gz_job_progress(gz_job *j, gz_progress *p)
{
    gz_os_mutex_lock(j->lock);
    snapshot(j, p, gz_os_ms());
    gz_os_mutex_unlock(j->lock);
    p->current = 0;
}

u32 gz_job_log_count(gz_job *j)
{
    gz_os_mutex_lock(j->lock);
    u32 n = j->nlog;
    gz_os_mutex_unlock(j->lock);
    return n;
}

const gz_log *gz_job_log_at(gz_job *j, u32 i)
{
    gz_os_mutex_lock(j->lock);
    const gz_log *l = i < j->nlog ? &j->logs[i] : 0;
    gz_os_mutex_unlock(j->lock);
    return l;
}

const gzch *gz_job_dest(const gz_job *j) { return j->dest; }

gz_handle *gz_job_take_handle(gz_job *j)
{
    gz_job_wait(j);
    gz_handle *h = j->o_h;
    j->o_h = 0;
    return h;
}

void gz_job_free(gz_job *j)
{
    if (!j) return;
    gz_job_wait(j);
    for (u32 i = 0; i < j->nlog; i++) { gz_free(j->logs[i].name); gz_free(j->logs[i].detail); }
    gz_free(j->logs);
    for (u32 i = 0; i < j->nlinks; i++) gz_free(j->links[i].target);
    gz_free(j->links);
    gz_free(j->order);
    gz_free(j->sel);
    gz_free(j->dest);
    gz_free(j->strip);
    if (j->c_in) for (u32 i = 0; i < j->co.ninputs; i++) gz_free(j->c_in[i]);
    gz_free(j->c_in);
    gz_free(j->c_out);
    gz_free(j->c_pw);
    gz_free(j->c_label);
    gz_free(j->o_path);
    gz_free(j->o_pw);
    gz_handle_close(j->o_h);
    gz_os_mutex_free(j->lock);
    gz_os_mutex_free(j->ask_lock);
    gz_os_mutex_free(j->cb_lock);
    gz_os_cond_free(j->cond);
    gz_free(j);
}
