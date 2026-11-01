/*
 * 고깃ZIP - extraction engine
 *
 *   - every worker thread opens its own handle to the archive and owns an
 *     inflater (1.3 MB of buffers), so ZIP entries are decoded in parallel
 *   - entries are handed out in archive order for mostly-sequential reads
 *   - overwrite / password questions are serialised and forwarded to the
 *     progress window with SendMessage (the UI thread never blocks on workers)
 *   - output names are sanitised for Windows (reserved names, invalid
 *     characters, trailing dots) and can never escape the destination folder
 */
#include "app.h"

/* ---------------- archive source ---------------- */

static int src_read_at(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    OVERLAPPED ov;
    DWORD g = 0;
    __builtin_memset(&ov, 0, sizeof ov);
    ov.Offset = (DWORD)off;
    ov.OffsetHigh = (DWORD)(off >> 32);
    *got = 0;
    if (!ReadFile((HANDLE)s->h, buf, n, &g, &ov)) {
        if (GetLastError() == ERROR_HANDLE_EOF) return GZ_OK;
        return GZ_E_IO;
    }
    *got = g;
    return GZ_OK;
}

int src_open(gz_src *s, const wchar_t *path)
{
    wchar_t lp[MAX_PATH * 4];
    path_long(lp, path, GZ_COUNTOF(lp));
    HANDLE h = CreateFileW(lp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return 0; }
    s->h = h;
    s->size = (u64)sz.QuadPart;
    s->read_at = src_read_at;
    return 1;
}

void src_close(gz_src *s)
{
    if (s->h) CloseHandle((HANDLE)s->h);
    s->h = 0;
}

gz_open_arc *arc_open_path(const wchar_t *path, int codepage, volatile long *cancel, int *err)
{
    gz_open_arc *oa = (gz_open_arc *)mem_alloc(sizeof(gz_open_arc));
    *err = GZ_E_NOMEM;
    if (!oa) return 0;
    wchar_t full[MAX_PATH * 2];
    if (!GetFullPathNameW(path, GZ_COUNTOF(full), full, NULL)) wcopy(full, path, GZ_COUNTOF(full));
    oa->path = wdup(full);
    if (!src_open(&oa->src, full)) { *err = GZ_E_IO; arc_close(oa); return 0; }
    gz_inflater *z = gz_inflater_new();
    if (!z) { arc_close(oa); return 0; }
    *err = gz_arc_open(&oa->arc, &oa->src, full, codepage, z, cancel);
    gz_inflater_free(z);
    if (*err) { arc_close(oa); return 0; }
    return oa;
}

void arc_close(gz_open_arc *oa)
{
    if (!oa) return;
    gz_arc_close(oa->arc);
    src_close(&oa->src);
    mem_free(oa->path);
    mem_free(oa);
}

const wchar_t *err_text(int code)
{
    switch (code) {
    case GZ_OK: return S(S_E_OK);
    case GZ_E_IO: return S(S_E_IO);
    case GZ_E_FORMAT: return S(S_E_FORMAT);
    case GZ_E_DATA: return S(S_E_DATA);
    case GZ_E_CRC: return S(S_E_CRC);
    case GZ_E_METHOD: return S(S_E_METHOD);
    case GZ_E_PASSWORD: return S(S_E_PASSWORD);
    case GZ_E_NOMEM: return S(S_E_NOMEM);
    case GZ_E_CANCEL: return S(S_E_CANCEL);
    case GZ_E_TRUNC: return S(S_E_TRUNC);
    case GZ_E_SKIP: return S(S_E_SKIP);
    case GZ_E_CREATE: return S(S_E_CREATE);
    case GZ_E_AUTH: return S(S_E_AUTH);
    case GZ_E_DISK: return S(S_E_DISK);
    }
    return S(S_E_IO);
}

/* ---------------- output names ---------------- */

static int lower3_eq(const wchar_t *c, const char *w)
{
    for (int i = 0; i < 3; i++) if ((c[i] | 32) != w[i]) return 0;
    return 1;
}

/* CON, PRN, AUX, NUL, COM1-9, LPT1-9 (with or without extension) */
static int is_reserved(const wchar_t *c, size_t n)
{
    size_t base = 0;
    while (base < n && c[base] != '.') base++;
    if (base == 3)
        return lower3_eq(c, "con") || lower3_eq(c, "prn") || lower3_eq(c, "aux") || lower3_eq(c, "nul");
    if (base == 4 && c[3] >= '1' && c[3] <= '9')
        return lower3_eq(c, "com") || lower3_eq(c, "lpt");
    return 0;
}

/* Build "<dest>\<sanitised relative path>" for entry e. Returns 0 if the entry
 * is outside the stripped prefix (or is the prefix folder itself). */
static int build_out_path(gz_job *j, const gz_entry *e, wchar_t *out, size_t cap)
{
    const wchar_t *rel = e->name;
    if (j->strip && j->strip[0]) {
        size_t sl = wlen(j->strip);
        for (size_t i = 0; i < sl; i++) if (rel[i] != j->strip[i]) return 0;
        if (rel[sl] != '/') return 0;
        rel += sl + 1;
    }
    if (!rel[0]) return 0;
    wcopy(out, j->dest, cap);
    size_t o = wlen(out);
    if (o && out[o - 1] != '\\') out[o++] = '\\';
    const wchar_t *p = rel;
    int first = 1;
    while (*p) {
        const wchar_t *st = p;
        while (*p && *p != '/') p++;
        size_t n = (size_t)(p - st);
        if (*p) p++;
        if (!n) continue;
        if (o + n + 4 >= cap) return 0;
        if (!first) out[o++] = '\\';
        first = 0;
        if (is_reserved(st, n)) out[o++] = '_';
        for (size_t i = 0; i < n; i++) {
            wchar_t c = st[i];
            if (c < 32 || c == '<' || c == '>' || c == ':' || c == '"' || c == '|' || c == '?' ||
                c == '*' || c == '\\')
                c = '_';
            out[o++] = c;
        }
        /* Windows silently drops trailing dots/spaces: keep the name distinct */
        if (out[o - 1] == '.' || out[o - 1] == ' ') out[o - 1] = '_';
    }
    out[o] = 0;
    return !first;
}

/* "name.txt" -> "name (2).txt" ... until the path is free */
static void unique_name(wchar_t *path, size_t cap)
{
    wchar_t base[MAX_PATH * 4], ext[64];
    wcopy(base, path, GZ_COUNTOF(base));
    const wchar_t *b = path_base(base);
    wchar_t *dot = (wchar_t *)gz_wcsrchr(b, '.');
    ext[0] = 0;
    if (dot && dot != b && wlen(dot) < 60) { wcopy(ext, dot, 64); *dot = 0; }
    for (int i = 2; i < 100000; i++) {
        wchar_t t[24];
        wfmt(t, L" (%d)", i);
        wcopy(path, base, cap);
        wcat(path, t, cap);
        wcat(path, ext, cap);
        wchar_t lp[MAX_PATH * 4];
        path_long(lp, path, GZ_COUNTOF(lp));
        if (!path_exists(lp)) return;
    }
}

/* ---------------- worker ---------------- */

typedef struct {
    gz_out o;
    gz_job *j;
    gz_src src;
    gz_inflater *z;
    HANDLE h;
    wchar_t path[MAX_PATH * 4];
    u32 idx;
    int opened;
    u64 pending;
    u8 pw[1024];
    size_t pwn;
    int pw_gen;
} worker;

static void add_error(gz_job *j, const wchar_t *name, int code)
{
    EnterCriticalSection(&j->lock);
    if (j->nerr == j->caperr) {
        u32 nc = j->caperr ? j->caperr * 2 : 32;
        gz_err *ne = (gz_err *)gz_realloc(j->errs, nc * sizeof(gz_err));
        if (ne) { j->errs = ne; j->caperr = nc; }
    }
    if (j->nerr < j->caperr) {
        j->errs[j->nerr].name = wdup(name);
        j->errs[j->nerr].code = code;
        j->nerr++;
    }
    LeaveCriticalSection(&j->lock);
}

static void flush_progress(worker *w)
{
    if (!w->pending) return;
    EnterCriticalSection(&w->j->lock);
    w->j->done_bytes += w->pending;
    LeaveCriticalSection(&w->j->lock);
    w->pending = 0;
}

static int ask_ui(gz_job *j, gz_ask *a)
{
    u32 t0 = GetTickCount();
    int r = (int)SendMessageW(j->notify, WM_APP_ASK, 0, (LPARAM)a);
    InterlockedExchangeAdd(&j->wait_ms, (LONG)(GetTickCount() - t0));
    return r;
}

static int decide_overwrite(worker *w, const gz_entry *e, wchar_t *lp)
{
    gz_job *j = w->j;
    EnterCriticalSection(&j->ask_lock);
    int mode = j->overwrite;
    if (mode == OW_ASK && !j->cancel) {
        gz_ask a;
        WIN32_FILE_ATTRIBUTE_DATA fa;
        __builtin_memset(&a, 0, sizeof a);
        a.kind = ASK_OVERWRITE;
        a.path = w->path;
        if (GetFileAttributesExW(lp, GetFileExInfoStandard, &fa)) {
            a.old_size = ((u64)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
            a.old_time = ((u64)fa.ftLastWriteTime.dwHighDateTime << 32) | fa.ftLastWriteTime.dwLowDateTime;
        }
        a.new_size = e->usize;
        a.new_time = entry_filetime(e);
        int r = ask_ui(j, &a);
        mode = r == ANS_YES ? OW_ALL : r == ANS_NO ? OW_SKIP : r == ANS_RENAME ? OW_RENAME : -1;
        if (mode < 0) InterlockedExchange(&j->cancel, 1);
        else if (a.apply_all) j->overwrite = mode;
    }
    LeaveCriticalSection(&j->ask_lock);
    return mode;
}

static int w_open(gz_out *o, u32 idx)
{
    worker *w = (worker *)o;
    gz_job *j = w->j;
    const gz_entry *e = &j->oa->arc->e[idx];
    w->idx = idx;
    w->opened = 1;
    w->h = INVALID_HANDLE_VALUE;
    if (j->cancel) return GZ_E_CANCEL;

    EnterCriticalSection(&j->lock);
    wcopy(j->current, e->name, MAX_PATH);
    LeaveCriticalSection(&j->lock);

    if (e->is_link) {
        add_error(j, e->name, GZ_E_SKIP);
        return GZ_E_SKIP;
    }
    if (j->test_only) return GZ_OK;
    if (!build_out_path(j, e, w->path, GZ_COUNTOF(w->path))) return GZ_E_SKIP;

    wchar_t lp[MAX_PATH * 4];
    path_long(lp, w->path, GZ_COUNTOF(lp));
    if (e->is_dir) {
        if (!mkdirs(w->path)) { add_error(j, e->name, GZ_E_CREATE); return GZ_E_CREATE; }
        return GZ_OK;
    }
    {
        wchar_t dir[MAX_PATH * 4];
        path_dir(dir, w->path, GZ_COUNTOF(dir));
        if (!mkdirs(dir)) { add_error(j, e->name, GZ_E_CREATE); return GZ_E_CREATE; }
    }
    DWORD attr = GetFileAttributesW(lp);
    if (attr != INVALID_FILE_ATTRIBUTES) {
        int mode = (attr & FILE_ATTRIBUTE_DIRECTORY) ? OW_RENAME : decide_overwrite(w, e, lp);
        if (mode < 0) return GZ_E_CANCEL;
        if (mode == OW_SKIP) {
            EnterCriticalSection(&j->lock);
            j->skipped++;
            j->done_bytes += e->usize;
            LeaveCriticalSection(&j->lock);
            return GZ_E_SKIP;
        }
        if (mode == OW_RENAME) {
            unique_name(w->path, GZ_COUNTOF(w->path));
            path_long(lp, w->path, GZ_COUNTOF(lp));
        } else if (attr & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
            SetFileAttributesW(lp, FILE_ATTRIBUTE_NORMAL);
        }
    }
    w->h = CreateFileW(lp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (w->h == INVALID_HANDLE_VALUE) {
        add_error(j, e->name, GZ_E_CREATE);
        return GZ_E_CREATE;
    }
    return GZ_OK;
}

static int w_write(gz_out *o, const u8 *p, size_t n)
{
    worker *w = (worker *)o;
    gz_job *j = w->j;
    if (j->paused) WaitForSingleObject(j->run_event, INFINITE);
    if (j->cancel) return GZ_E_CANCEL;
    if (w->h != INVALID_HANDLE_VALUE) {
        while (n) {
            DWORD chunk = n > (1u << 24) ? (1u << 24) : (DWORD)n, wr = 0;
            if (!WriteFile(w->h, p, chunk, &wr, NULL) || wr != chunk) {
                DWORD le = GetLastError();
                return (le == ERROR_DISK_FULL || le == ERROR_HANDLE_DISK_FULL) ? GZ_E_DISK : GZ_E_IO;
            }
            p += wr;
            n -= wr;
            w->pending += wr;
            if (w->pending >= (256u << 10)) flush_progress(w);
        }
    } else {
        w->pending += n;
        if (w->pending >= (256u << 10)) flush_progress(w);
    }
    return GZ_OK;
}

static int w_close(gz_out *o, u32 idx, int st)
{
    worker *w = (worker *)o;
    gz_job *j = w->j;
    const gz_entry *e = &j->oa->arc->e[idx];
    flush_progress(w);
    if (w->h != INVALID_HANDLE_VALUE) {
        if (st == GZ_OK) {
            u64 ft = entry_filetime(e);
            if (ft) {
                FILETIME t;
                t.dwLowDateTime = (DWORD)ft;
                t.dwHighDateTime = (DWORD)(ft >> 32);
                SetFileTime(w->h, NULL, NULL, &t);
            }
        }
        CloseHandle(w->h);
        w->h = INVALID_HANDLE_VALUE;
        wchar_t lp[MAX_PATH * 4];
        path_long(lp, w->path, GZ_COUNTOF(lp));
        if (st != GZ_OK) DeleteFileW(lp);
        else if (e->attr & 7) SetFileAttributesW(lp, e->attr & 7);
    }
    EnterCriticalSection(&j->lock);
    if (!e->is_dir) j->done_files++;
    LeaveCriticalSection(&j->lock);
    if (st != GZ_OK && st != GZ_E_SKIP && st != GZ_E_CANCEL) add_error(j, e->name, st);
    return GZ_OK;
}

/* Make sure the worker holds a password that opens entry idx. */
static int ensure_password(worker *w, u32 idx)
{
    gz_job *j = w->j;
    gz_open_arc *oa = j->oa;
    int tried_gen = -1;
    for (;;) {
        if (j->cancel) return GZ_E_CANCEL;
        EnterCriticalSection(&j->ask_lock);
        int gen = j->pw_gen, have = j->pw_set;
        u8 a[1024], u[1024];
        size_t an = 0, un = 0;
        if (have) {
            an = j->pw_an < sizeof a ? j->pw_an : sizeof a;
            un = j->pw_un < sizeof u ? j->pw_un : sizeof u;
            if (j->pw_a) __builtin_memcpy(a, j->pw_a, an);
            if (j->pw_u) __builtin_memcpy(u, j->pw_u, un);
        }
        LeaveCriticalSection(&j->ask_lock);

        if (have && gen != tried_gen) {
            tried_gen = gen;
            if (w->pw_gen == gen && w->pwn &&
                gz_arc_check_password(oa->arc, &w->src, idx, w->pw, w->pwn) == GZ_OK)
                return GZ_OK;
            if (gz_arc_check_password(oa->arc, &w->src, idx, a, an) == GZ_OK) {
                __builtin_memcpy(w->pw, a, an); w->pwn = an; w->pw_gen = gen;
                return GZ_OK;
            }
            if (un && gz_arc_check_password(oa->arc, &w->src, idx, u, un) == GZ_OK) {
                __builtin_memcpy(w->pw, u, un); w->pwn = un; w->pw_gen = gen;
                return GZ_OK;
            }
        }

        EnterCriticalSection(&j->ask_lock);
        if (j->pw_gen != tried_gen && j->pw_set) { LeaveCriticalSection(&j->ask_lock); continue; }
        if (j->cancel) { LeaveCriticalSection(&j->ask_lock); return GZ_E_CANCEL; }
        gz_ask q;
        __builtin_memset(&q, 0, sizeof q);
        q.kind = ASK_PASSWORD;
        q.path = oa->arc->e[idx].name;
        q.retry = tried_gen >= 0;
        int r = ask_ui(j, &q);
        if (r != ANS_YES) {
            InterlockedExchange(&j->cancel, 1);
            LeaveCriticalSection(&j->ask_lock);
            return GZ_E_CANCEL;
        }
        wcopy(j->pw, q.password, 256);
        mem_free(j->pw_a);
        mem_free(j->pw_u);
        j->pw_a = w_to_mb(gz_plat_acp(), j->pw, &j->pw_an);
        j->pw_u = w_to_mb(CP_UTF8, j->pw, &j->pw_un);
        j->pw_set = 1;
        j->pw_gen++;
        LeaveCriticalSection(&j->ask_lock);
    }
}

static DWORD WINAPI worker_main(void *arg)
{
    worker *w = (worker *)arg;
    gz_job *j = w->j;
    gz_archive *a = j->oa->arc;

    if (a->solid) {
        u8 *sel = j->sel;
        u8 *all = 0;
        if (!sel) {
            all = (u8 *)mem_alloc(a->n + 1);
            if (all) for (u32 i = 0; i < a->n; i++) all[i] = 1;
            sel = all;
        }
        if (sel) {
            int r = gz_arc_extract_solid(a, &w->src, sel, &w->o, w->z, &j->cancel);
            if (r && r != GZ_E_CANCEL) add_error(j, path_base(j->oa->path), r);
        }
        mem_free(all);
        return 0;
    }

    for (;;) {
        LONG k = InterlockedIncrement(&j->next) - 1;
        if ((u32)k >= j->count || j->cancel) break;
        u32 idx = j->order[k];
        gz_entry *e = &a->e[idx];
        const u8 *pw = 0;
        size_t pwn = 0;
        if (e->enc && !e->is_dir) {
            if (ensure_password(w, idx)) break;
            pw = w->pw;
            pwn = w->pwn;
        }
        w->opened = 0;
        int r = gz_arc_extract(a, &w->src, idx, &w->o, pw, pwn, w->z);
        if (r == GZ_E_PASSWORD && !w->opened && e->enc) {
            /* stale password (e.g. per-file passwords): ask again */
            EnterCriticalSection(&j->ask_lock);
            if (j->pw_gen == w->pw_gen) j->pw_set = 0, j->pw_gen++;
            LeaveCriticalSection(&j->ask_lock);
            if (!ensure_password(w, idx))
                r = gz_arc_extract(a, &w->src, idx, &w->o, w->pw, w->pwn, w->z);
        }
        if (r && r != GZ_E_SKIP && r != GZ_E_CANCEL && !w->opened) {
            add_error(j, e->name, r);
            EnterCriticalSection(&j->lock);
            j->done_files++;
            j->done_bytes += e->usize;
            LeaveCriticalSection(&j->lock);
        }
        if (r == GZ_E_CANCEL) break;
    }
    return 0;
}

/* Restore folder timestamps (after the files inside were written). */
static void fix_dir_times(gz_job *j)
{
    gz_archive *a = j->oa->arc;
    for (u32 k = 0; k < j->count && !j->cancel; k++) {
        const gz_entry *e = &a->e[j->order[k]];
        if (!e->is_dir) continue;
        u64 ft = entry_filetime(e);
        wchar_t p[MAX_PATH * 4], lp[MAX_PATH * 4];
        if (!ft || !build_out_path(j, e, p, GZ_COUNTOF(p))) continue;
        path_long(lp, p, GZ_COUNTOF(lp));
        HANDLE h = CreateFileW(lp, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        FILETIME t;
        t.dwLowDateTime = (DWORD)ft;
        t.dwHighDateTime = (DWORD)(ft >> 32);
        SetFileTime(h, NULL, NULL, &t);
        CloseHandle(h);
    }
}

static DWORD WINAPI controller_main(void *arg)
{
    gz_job *j = (gz_job *)arg;
    gz_archive *a = j->oa->arc;
    j->start_tick = GetTickCount();

    if (!j->test_only && !mkdirs(j->dest)) {
        add_error(j, j->dest, GZ_E_CREATE);
        j->result = GZ_E_CREATE;
        j->finished = 1;
        PostMessageW(j->notify, WM_APP_DONE, 0, 0);
        return 0;
    }

    u32 nw = j->threads;
    if (a->solid) nw = 1;
    if (nw > j->count) nw = j->count ? j->count : 1;
    if (nw > 32) nw = 32;
    if (nw < 1) nw = 1;
    j->nworkers = nw;

    worker *ws = (worker *)mem_alloc(sizeof(worker) * nw);
    HANDLE th[32];
    u32 started = 0;
    for (u32 i = 0; ws && i < nw; i++) {
        worker *w = &ws[i];
        w->o.open = w_open;
        w->o.write = w_write;
        w->o.close = w_close;
        w->j = j;
        w->h = INVALID_HANDLE_VALUE;
        w->z = gz_inflater_new();
        if (!w->z || !src_open(&w->src, j->oa->path)) {
            if (i == 0) add_error(j, j->oa->path, w->z ? GZ_E_IO : GZ_E_NOMEM);
            if (w->z) gz_inflater_free(w->z);
            w->z = 0;
            break;
        }
        th[started] = CreateThread(NULL, 256 << 10, worker_main, w, 0, NULL);
        if (!th[started]) { gz_inflater_free(w->z); src_close(&w->src); w->z = 0; break; }
        started++;
    }
    if (started) WaitForMultipleObjects(started, th, TRUE, INFINITE);
    for (u32 i = 0; i < started; i++) CloseHandle(th[i]);
    for (u32 i = 0; ws && i < nw; i++) {
        if (ws[i].z) { gz_inflater_free(ws[i].z); src_close(&ws[i].src); }
    }
    mem_free(ws);
    if (!j->test_only) fix_dir_times(j);

    j->end_tick = GetTickCount();
    j->result = j->cancel ? GZ_E_CANCEL : (j->nerr ? GZ_E_DATA : GZ_OK);
    j->finished = 1;
    PostMessageW(j->notify, WM_APP_DONE, 0, 0);
    return 0;
}

/* ---------------- job setup ---------------- */

gz_job *job_new(gz_open_arc *oa)
{
    gz_job *j = (gz_job *)mem_alloc(sizeof(gz_job));
    if (!j) return 0;
    j->oa = oa;
    j->overwrite = g_set.overwrite;
    j->threads = g_set.threads > 0 ? g_set.threads : cpu_threads();
    InitializeCriticalSection(&j->lock);
    InitializeCriticalSection(&j->ask_lock);
    j->run_event = CreateEventW(NULL, TRUE, TRUE, NULL);
    return j;
}

void job_free(gz_job *j)
{
    if (!j) return;
    for (u32 i = 0; i < j->nerr; i++) mem_free(j->errs[i].name);
    mem_free(j->errs);
    mem_free(j->order);
    mem_free(j->sel_owned);
    mem_free(j->pw_a);
    mem_free(j->pw_u);
    if (j->run_event) CloseHandle(j->run_event);
    if (j->thread) CloseHandle(j->thread);
    DeleteCriticalSection(&j->lock);
    DeleteCriticalSection(&j->ask_lock);
    mem_free(j);
}

static int in_scope(gz_job *j, const gz_entry *e)
{
    if (!e->name[0]) return 0;
    if (!j->strip || !j->strip[0]) return 1;
    size_t sl = wlen(j->strip);
    for (size_t i = 0; i < sl; i++) if (e->name[i] != j->strip[i]) return 0;
    return e->name[sl] == '/';
}

static gz_archive *s_sort_arc;
static int order_less(u32 x, u32 y)
{
    const gz_entry *a = &s_sort_arc->e[x], *b = &s_sort_arc->e[y];
    if (a->is_dir != b->is_dir) return a->is_dir > b->is_dir;   /* folders first */
    return a->off < b->off;
}

static void sort_order(u32 *v, u32 n)
{
    /* bottom-up merge sort (stable, O(n log n), no recursion) */
    u32 *tmp = (u32 *)mem_alloc((size_t)n * sizeof(u32) + 4);
    if (!tmp) return;
    for (u32 width = 1; width < n; width *= 2) {
        for (u32 i = 0; i < n; i += 2 * width) {
            u32 lo = i, mid = i + width < n ? i + width : n, hi = i + 2 * width < n ? i + 2 * width : n;
            u32 a = lo, b = mid, k = lo;
            while (a < mid && b < hi) tmp[k++] = order_less(v[b], v[a]) ? v[b++] : v[a++];
            while (a < mid) tmp[k++] = v[a++];
            while (b < hi) tmp[k++] = v[b++];
        }
        __builtin_memcpy(v, tmp, (size_t)n * sizeof(u32));
    }
    mem_free(tmp);
}

void job_start(gz_job *j)
{
    gz_archive *a = j->oa->arc;
    j->order = (u32 *)mem_alloc((size_t)a->n * sizeof(u32) + 4);
    j->count = 0;
    j->total_bytes = 0;
    j->total_files = 0;
    for (u32 i = 0; j->order && i < a->n; i++) {
        const gz_entry *e = &a->e[i];
        if (j->sel && !j->sel[i]) continue;
        if (!in_scope(j, e)) continue;
        j->order[j->count++] = i;
        if (!e->is_dir) { j->total_bytes += e->usize; j->total_files++; }
    }
    s_sort_arc = a;
    if (!a->solid) sort_order(j->order, j->count);
    if (a->solid && j->strip && j->strip[0] && !j->sel) {
        j->sel = j->sel_owned = (u8 *)mem_alloc(a->n + 1);
        if (j->sel) for (u32 k = 0; k < j->count; k++) j->sel[j->order[k]] = 1;
    }
    j->thread = CreateThread(NULL, 64 << 10, controller_main, j, 0, NULL);
}

/* Smart extraction: create a folder unless everything lives under one top-level item. */
int smart_needs_folder(gz_open_arc *oa, const u8 *sel, const wchar_t *strip)
{
    gz_archive *a = oa->arc;
    const wchar_t *top = 0;
    size_t toplen = 0, sl = strip ? wlen(strip) : 0;
    int top_is_dir = 0;
    for (u32 i = 0; i < a->n; i++) {
        const gz_entry *e = &a->e[i];
        if (sel && !sel[i]) continue;
        const wchar_t *n = e->name;
        if (!n[0]) continue;
        if (sl) {
            size_t k;
            for (k = 0; k < sl && n[k] == strip[k]; k++) {}
            if (k < sl || n[sl] != '/') continue;
            n += sl + 1;
        }
        size_t l = 0;
        while (n[l] && n[l] != '/') l++;
        int dir = n[l] == '/' || e->is_dir;
        if (!top) { top = n; toplen = l; top_is_dir = dir; continue; }
        if (l != toplen) return 1;
        for (size_t k = 0; k < l; k++) if (n[k] != top[k]) return 1;
        if (dir) top_is_dir = 1;
    }
    (void)top_is_dir;
    return 0;
}
