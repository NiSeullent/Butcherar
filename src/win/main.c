/*
 * 고깃ZIP - program entry, command line, extraction front-end
 *
 * Command line:
 *   GogitZip.exe [archive]              open the viewer
 *   GogitZip.exe /extract <archive...>  show the extract dialog
 *   GogitZip.exe /here <archive...>     extract next to the archive
 *   GogitZip.exe /smart <archive...>    extract to "<archive name>\" (smart)
 *   GogitZip.exe /to <dir> <archive...> extract into <dir>
 *   GogitZip.exe /test <archive...>     test archives
 *   GogitZip.exe /add <files...>        create-archive dialog
 *   GogitZip.exe /zip <files...>        "<name>.zip" next to the files
 *   GogitZip.exe /7z <files...>         "<name>.7z" next to the files
 *   GogitZip.exe /register [/assoc]     add Explorer menu (and file association)
 *   GogitZip.exe /unregister            remove Explorer integration
 *   GogitZip.exe /bench                 CPU benchmark
 */
#include "app.h"

HINSTANCE g_inst;
const wchar_t *g_exe_path;
static wchar_t s_exe[MAX_PATH * 2];

static void special_dir(int csidl, wchar_t *out)
{
    wchar_t b[MAX_PATH];
    b[0] = 0;
    SHGetSpecialFolderPathW(NULL, b, csidl, FALSE);
    wcopy(out, b, MAX_PATH * 2);
}

int do_extract(HWND owner, gz_handle *h, const wchar_t *src_path, int mode, const wchar_t *to, const u8 *sel,
               const wchar_t *strip, int nsel)
{
    x_opts o;
    __builtin_memset(&o, 0, sizeof o);
    o.h = h;
    o.src_path = src_path;
    o.nselected = nsel;
    o.only_selected = nsel > 0;
    o.overwrite = g_set.overwrite;
    o.open_folder = g_set.open_folder;
    o.make_folder = g_set.smart_folder;
    wchar_t here[MAX_PATH * 2];
    int here_ok = wlen(src_path) < GZ_COUNTOF(here);       /* else "next to the archive" would be cut short */
    path_dir(here, here_ok ? src_path : L"", GZ_COUNTOF(here));
    if (!here_ok && (mode == X_HERE || mode == X_SMART)) {
        msg_box(owner, S(S_N_PATH_LONG), MB_ICONWARNING);
        return GZ_E_CREATE;
    }

    switch (mode) {
    case X_DIALOG:
        wcopy(o.dest, here, GZ_COUNTOF(o.dest));
        if (g_set.dest_mode == 1) special_dir(CSIDL_DESKTOPDIRECTORY, o.dest);
        else if (g_set.dest_mode == 2 && g_set.dest[0] && path_is_dir(g_set.dest)) wcopy(o.dest, g_set.dest, GZ_COUNTOF(o.dest));
        if (!dlg_extract_options(owner, &o)) return GZ_E_CANCEL;
        break;
    case X_HERE:
        wcopy(o.dest, here, GZ_COUNTOF(o.dest));
        o.make_folder = 0;
        break;
    case X_SMART:
        wcopy(o.dest, here, GZ_COUNTOF(o.dest));
        o.make_folder = 1;
        break;
    case X_TO: {
        DWORD n = GetFullPathNameW(to, GZ_COUNTOF(o.dest), o.dest, NULL);
        if (!n || n >= GZ_COUNTOF(o.dest)) {
            msg_box(owner, S(S_E_CREATE), MB_ICONWARNING);
            return GZ_E_CREATE;
        }
        o.make_folder = 0;
        break;
    }
    case X_TEST:
        o.open_folder = 0;
        break;
    }
    const u8 *use_sel = o.only_selected ? sel : 0;
    const wchar_t *use_strip = o.only_selected ? strip : 0;

    ui_job *u = (ui_job *)mem_alloc(sizeof(ui_job));
    if (!u) return GZ_E_NOMEM;
    ui_job_init(u, mode == X_TEST ? OP_TEST : OP_EXTRACT);
    u->h = h;
    wcopy(u->dest, o.dest, GZ_COUNTOF(u->dest));
    /* progress subtitle: the file, or the nested archive's name */
    wcopy(u->out, (h->parent || h->temp) ? h->name : src_path, GZ_COUNTOF(u->out));
    u->title = u->out;
    u->open_folder = o.open_folder;
    gz_extract_opts *xo = &u->xo;
    xo->dest = u->dest;
    xo->path_mode = use_strip && use_strip[0] ? GZ_PATH_STRIP : GZ_PATH_FULL;
    xo->strip = use_strip;
    xo->overwrite = o.overwrite;
    xo->smart = mode != X_TEST && o.make_folder;
    xo->sel = use_sel;
    xo->test = mode == X_TEST;
    xo->threads = g_set.threads;
    int r = run_job_with_progress(owner, u);
    if (mode == X_TEST || ui_job_problems(u) || (r && r != GZ_E_CANCEL)) dlg_errors(owner, u);
    else if (r == GZ_OK && u->open_folder) {
        const wchar_t *d = u->j ? gz_job_dest(u->j) : 0;
        open_in_explorer(d ? d : u->dest, 0);
    }
    ui_job_free(u);
    mem_free(u);
    return r;
}

/* ---------------- command line ---------------- */

static int is_switch(const wchar_t *a) { return a[0] == '/' && a[1] && a[2] != ':'; }

static int cmd_batch(int mode, const wchar_t *to, LPWSTR *argv, int argc, int first)
{
    int rc = 0;
    for (int i = first; i < argc; i++) {
        if (is_switch(argv[i])) continue;
        int err;
        gz_handle *h = open_archive_ui(NULL, argv[i], 0, 0, g_set.codepage, &err);
        if (!h) {
            if (err == GZ_E_CANCEL) return 1;
            open_error_box(NULL, argv[i], err);
            rc = 1;
            continue;
        }
        settings_add_recent(h->path);
        int r = do_extract(NULL, h, h->path, mode, to, 0, 0, 0);
        gz_handle_close(h);
        if (r == GZ_E_CANCEL) return 1;
        if (r) rc = 1;
    }
    settings_save();
    return rc;
}

/* ---- Explorer starts one process per selected item: the first one collects the
 *      others' paths (WM_COPYDATA) until nothing arrived for 0.7 s ---- */

#define COLLECT_CLASS L"GogitZIP.Collect"
#define COLLECT_MAX   100000u

static struct { wchar_t **v; u32 n, cap; DWORD last; ULONG_PTR verb; } s_col;

static void col_add(const wchar_t *p)
{
    /* full path of any length (a shortened one would name another file) */
    size_t pl = wlen(p);
    DWORD need = GetFullPathNameW(p, 0, NULL, NULL);
    size_t cap = (size_t)need + pl + 2;
    wchar_t *full = (wchar_t *)mem_alloc(cap * sizeof(wchar_t));
    if (!full) return;
    DWORD fl = need ? GetFullPathNameW(p, (DWORD)cap, full, NULL) : 0;
    if (!fl || fl >= cap) wcopy(full, p, pl + 1);
    size_t n = wlen(full);
    while (n > 3 && full[n - 1] == '\\') full[--n] = 0;      /* "C:\dir\" -> "C:\dir" */
    int keep = s_col.n < COLLECT_MAX;
    for (u32 i = 0; i < s_col.n && keep; i++) if (!wicmp(s_col.v[i], full)) keep = 0;
    if (keep && s_col.n == s_col.cap) {
        u32 nc = s_col.cap ? s_col.cap * 2 : 16;
        wchar_t **nv = (wchar_t **)gz_realloc(s_col.v, nc * sizeof(wchar_t *));
        if (nv) { s_col.v = nv; s_col.cap = nc; }
        else keep = 0;
    }
    if (keep) s_col.v[s_col.n++] = full;
    else mem_free(full);
}

static LRESULT CALLBACK col_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    if (m == WM_COPYDATA) {
        const COPYDATASTRUCT *cd = (const COPYDATASTRUCT *)lp;
        if (!cd || cd->dwData != s_col.verb || !cd->lpData || (cd->cbData & 1) || cd->cbData > (8u << 20)) return FALSE;
        const wchar_t *p = (const wchar_t *)cd->lpData, *end = p + cd->cbData / 2;
        while (p < end) {                       /* NUL-separated paths; the last may lack its NUL */
            const wchar_t *s = p;
            while (p < end && *p) p++;
            size_t len = (size_t)(p - s);
            wchar_t *t = len && len < GZ_LONGPATH ? (wchar_t *)mem_alloc((len + 1) * sizeof(wchar_t)) : 0;
            if (t) {
                __builtin_memcpy(t, s, len * sizeof(wchar_t));
                t[len] = 0;
                col_add(t);
                mem_free(t);
            }
            p++;
        }
        s_col.last = GetTickCount();
        return TRUE;
    }
    return DefWindowProcW(h, m, wp, lp);
}

/* 1: this process goes on with s_col; 0: the paths went to another process */
static int collect_inputs(int verb, LPWSTR *argv, int argc, int first)
{
    s_col.verb = (ULONG_PTR)(0x475A0000u | (u32)verb);
    for (int i = first; i < argc; i++) if (!is_switch(argv[i])) col_add(argv[i]);
    if (!s_col.n) return 1;
    wchar_t name[64];
    wfmt(name, L"GogitZIP.Collect.%d", verb);
    HANDLE mx = CreateMutexW(NULL, FALSE, name);
    if (mx && GetLastError() == ERROR_ALREADY_EXISTS) {
        /* someone collects already (its window may not exist yet) */
        size_t bytes = 0;
        for (u32 i = 0; i < s_col.n; i++) bytes += (wlen(s_col.v[i]) + 1) * sizeof(wchar_t);
        wchar_t *buf = (wchar_t *)mem_alloc(bytes + 2);
        int sent = 0;
        if (buf) {
            size_t o = 0;
            for (u32 i = 0; i < s_col.n; i++) {
                size_t l = wlen(s_col.v[i]) + 1;
                __builtin_memcpy(buf + o, s_col.v[i], l * sizeof(wchar_t));
                o += l;
            }
            for (int tries = 0; tries < 60 && !sent; tries++) {
                HWND w = FindWindowExW(HWND_MESSAGE, NULL, COLLECT_CLASS, name);
                if (w) {
                    COPYDATASTRUCT cd = { s_col.verb, (DWORD)bytes, buf };
                    DWORD_PTR res = 0;
                    sent = SendMessageTimeoutW(w, WM_COPYDATA, 0, (LPARAM)&cd, SMTO_ABORTIFHUNG, 5000, &res) && res;
                }
                if (!sent) Sleep(50);
            }
            mem_free(buf);
        }
        CloseHandle(mx);
        return !sent;
    }
    WNDCLASSEXW wc;
    __builtin_memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = col_proc;
    wc.hInstance = g_inst;
    wc.lpszClassName = COLLECT_CLASS;
    RegisterClassExW(&wc);
    HWND w = CreateWindowExW(0, COLLECT_CLASS, name, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, g_inst, NULL);
    s_col.last = GetTickCount();
    DWORD start = s_col.last;
    while (w && GetTickCount() - s_col.last < 700 && GetTickCount() - start < 20000) {
        MsgWaitForMultipleObjects(0, NULL, FALSE, 100, QS_ALLINPUT);
        MSG msg;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&msg);
    }
    if (w) DestroyWindow(w);
    if (mx) CloseHandle(mx);                /* a later selection starts its own batch */
    return 1;
}

static int cmd_compress(int verb, LPWSTR *argv, int argc, int first)
{
    if (!collect_inputs(verb, argv, argc, first)) return 0;
    if (!s_col.n) return 1;
    int r;
    if (verb == 0) r = dlg_compress(NULL, (const wchar_t *const *)s_col.v, s_col.n);
    else r = compress_direct(NULL, (const wchar_t *const *)s_col.v, s_col.n, verb == 1 ? GZ_WF_ZIP : GZ_WF_7Z);
    for (u32 i = 0; i < s_col.n; i++) mem_free(s_col.v[i]);
    mem_free(s_col.v);
    return r != GZ_OK;
}

int app_main(void)
{
    g_inst = GetModuleHandleW(NULL);
    GetModuleFileNameW(NULL, s_exe, GZ_COUNTOF(s_exe));
    g_exe_path = s_exe;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);

    HDC dc = GetDC(NULL);
    g_dpi = GetDeviceCaps(dc, LOGPIXELSY);
    ReleaseDC(NULL, dc);
    if (g_dpi < 96) g_dpi = 96;

    os_detect();
    settings_load();
    gz_engine_init(g_set.cpu_tier);

    INITCOMMONCONTROLSEX icc = { sizeof icc, ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES };
    InitCommonControlsEx(&icc);
    OleInitialize(NULL);

    strings_init(gfx_pick_language());
    gfx_fonts_create();
    gfx_init();

    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int rc = 0;
    const wchar_t *a1 = argc > 1 ? argv[1] : L"";

    if (!wicmp(a1, L"/here")) rc = cmd_batch(X_HERE, 0, argv, argc, 2);
    else if (!wicmp(a1, L"/smart")) rc = cmd_batch(X_SMART, 0, argv, argc, 2);
    else if (!wicmp(a1, L"/extract")) rc = cmd_batch(X_DIALOG, 0, argv, argc, 2);
    else if (!wicmp(a1, L"/test")) rc = cmd_batch(X_TEST, 0, argv, argc, 2);
    else if (!wicmp(a1, L"/to") && argc > 3) rc = cmd_batch(X_TO, argv[2], argv, argc, 3);
    else if (!wicmp(a1, L"/add")) rc = cmd_compress(0, argv, argc, 2);
    else if (!wicmp(a1, L"/zip")) rc = cmd_compress(1, argv, argc, 2);
    else if (!wicmp(a1, L"/7z")) rc = cmd_compress(2, argv, argc, 2);
    else if (!wicmp(a1, L"/register")) rc = !shell_register(argc > 2 && !wicmp(argv[2], L"/assoc"));
    else if (!wicmp(a1, L"/unregister")) rc = !shell_unregister();
    else if (!wicmp(a1, L"/bench")) dlg_bench(NULL);
    else {
        const wchar_t *open = 0;
        for (int i = 1; i < argc; i++) if (!is_switch(argv[i])) { open = argv[i]; break; }
        HWND h = mainwnd_create(open, SW_SHOWNORMAL);
        if (h) rc = mainwnd_loop(h);
    }
    if (argv) LocalFree(argv);
    OleUninitialize();
    return rc;
}
