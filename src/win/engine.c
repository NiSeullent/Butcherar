/*
 * 고깃ZIP - glue between the Windows UI and the portable engine
 *
 * Extraction, testing and compression are gz_job's of src/app/engine.c (which
 * runs on os_win.c). The engine calls back from its own threads:
 *   ask       -> SendMessage(WM_APP_ASK) to the progress window, which shows the
 *                question dialog on the UI thread and returns the GZ_ANS_* answer
 *   progress  -> name of the current entry (counters are polled with gz_job_progress)
 *   done      -> PostMessage(WM_APP_DONE)
 * Everything Windows-specific the old engine did (Mark-of-the-Web, reserved
 * names, trailing dots, attributes, long paths) now lives in os_win.c and the
 * engine's GZ_OSC_* paths.
 */
#include "app.h"

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
    case GZ_E_VOLUME: return S(S_E_VOLUME);
    case GZ_E_LIMIT: return S(S_E_LIMIT);
    case GZ_N_RENAMED: return S(S_N_RENAMED);
    case GZ_N_SHORTENED: return S(S_N_SHORTENED);
    case GZ_N_PATH_LONG: return S(S_N_PATH_LONG);
    case GZ_N_LINK_ABSOLUTE: case GZ_N_LINK_ESCAPE: case GZ_N_LINK_THROUGH: return S(S_N_LINK_UNSAFE);
    case GZ_N_LINK_UNSUPPORTED: return S(S_LINK_SKIP);
    case GZ_N_LINK_FAILED: case GZ_N_LINK_TARGET: return S(S_N_LINK_FAILED);
    case GZ_N_SPECIAL: return S(S_N_SPECIAL);
    case GZ_N_LOOP: return S(S_N_LOOP);
    case GZ_N_NOT_FOUND: return S(S_N_NOT_FOUND);
    case GZ_N_UNREADABLE: return S(S_N_UNREADABLE);
    case GZ_N_ONE_FILE: return S(S_C_ONEFILE);
    case GZ_N_EXISTS: return S(S_N_EXISTS);
    case GZ_N_NO_WRITER: return S(S_C_NOWRITER);
    case GZ_N_NO_FILES: return S(S_N_NO_FILES);
    }
    return S(S_E_IO);
}

/* ---------------- jobs ---------------- */

void ui_job_init(ui_job *u, int op)
{
    __builtin_memset(u, 0, sizeof *u);
    u->op = op;
    InitializeCriticalSection(&u->cur_lock);
}

void ui_job_free(ui_job *u)
{
    gz_job_free(u->j);
    u->j = 0;
    DeleteCriticalSection(&u->cur_lock);
}

static int cb_ask(void *user, gz_ask *q)
{
    ui_job *u = (ui_job *)user;
    return (int)SendMessageW(u->notify, WM_APP_ASK, 0, (LPARAM)q);
}

static void cb_progress(void *user, const gz_progress *p)
{
    ui_job *u = (ui_job *)user;
    if (!p->current) return;
    EnterCriticalSection(&u->cur_lock);
    wcopy(u->current, p->current, MAX_PATH);
    LeaveCriticalSection(&u->cur_lock);
}

static void cb_done(void *user, int result)
{
    ui_job *u = (ui_job *)user;
    u->result = result;
    PostMessageW(u->notify, WM_APP_DONE, 0, 0);
}

int ui_job_start(ui_job *u, HWND notify)
{
    gz_callbacks cb;
    __builtin_memset(&cb, 0, sizeof cb);
    cb.user = u;
    cb.ask = cb_ask;
    cb.progress = cb_progress;
    cb.done = cb_done;
    u->notify = notify;
    u->j = u->op == OP_COMPRESS ? gz_compress_start(&u->co, &cb) : gz_extract_start(u->h, &u->xo, &cb);
    return u->j != 0;
}

u32 ui_job_problems(ui_job *u)
{
    u32 n = 0, c = u->j ? gz_job_log_count(u->j) : 0;
    for (u32 i = 0; i < c; i++) {
        const gz_log *l = gz_job_log_at(u->j, i);
        if (l && l->level >= GZ_LOG_WARN) n++;
    }
    return n;
}

/* ---------------- format extensions ---------------- */

static int ext_of(const wchar_t *name, char *out, int cap)
{
    const wchar_t *b = path_base(name), *dot = gz_wcsrchr(b, '.');
    int n = 0;
    if (!dot || dot == b) return 0;
    for (const wchar_t *p = dot + 1; *p; p++) {
        wchar_t c = *p;
        if (c >= 'A' && c <= 'Z') c += 32;
        if (c > 127 || n + 1 >= cap) return 0;
        out[n++] = (char)c;
    }
    out[n] = 0;
    return n;
}

static int exts_has(const char *list, const char *e)
{
    for (const char *p = list; *p;) {
        while (*p == ' ') p++;
        const char *s = p;
        while (*p && *p != ' ') p++;
        size_t k = 0;
        while (s + k < p && e[k] && s[k] == e[k]) k++;
        if (s + k == p && !e[k] && p > s) return 1;
    }
    return 0;
}

int is_archive_name(const wchar_t *name, int strict)
{
    char e[16];
    if (!ext_of(name, e, sizeof e)) return 0;
    if (strict) return assoc_default_on(e);          /* archives, not documents / programs */
    for (int i = 0; gz_formats[i]; i++)
        if (gz_formats[i]->exts && exts_has(gz_formats[i]->exts, e)) return 1;
    return 0;
}

wchar_t *archive_patterns(void)
{
    assoc_ext *l = (assoc_ext *)mem_alloc(512 * sizeof(assoc_ext));
    if (!l) return 0;
    int n = assoc_list(l, 512);
    wchar_t *o = (wchar_t *)mem_alloc(((size_t)n * 20 + 8) * sizeof(wchar_t));
    size_t k = 0;
    for (int i = 0; o && i < n; i++) {
        if (k) o[k++] = ';';
        o[k++] = '*';
        o[k++] = '.';
        for (const char *p = l[i].ext; *p; p++) o[k++] = (wchar_t)(u8)*p;
    }
    if (o) o[k] = 0;
    mem_free(l);
    return o;
}

void open_error_box(HWND owner, const wchar_t *path, int err)
{
    wchar_t t[MAX_PATH * 2 + 256];
    wfmt(t, L"%s\n\n%s\n%s", S(S_OPEN_FAIL), path, err_text(err));
    msg_box(owner, t, MB_ICONWARNING);
}
