/*
 * 고깃ZIP - program entry, command line, extraction front-end
 *
 * Command line:
 *   GogitZip.exe [archive]              open the viewer
 *   GogitZip.exe /extract <archive>     show the extract dialog
 *   GogitZip.exe /here <archive...>     extract next to the archive
 *   GogitZip.exe /smart <archive...>    extract to "<archive name>\" (smart)
 *   GogitZip.exe /to <dir> <archive...> extract into <dir>
 *   GogitZip.exe /test <archive...>     test archives
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

static void open_in_explorer(const wchar_t *dir)
{
    ShellExecuteW(NULL, L"open", dir, NULL, NULL, SW_SHOWNORMAL);
}

int do_extract(HWND owner, gz_open_arc *oa, int mode, const wchar_t *to, const u8 *sel,
               const wchar_t *strip, int nsel)
{
    gz_extract_opts o;
    __builtin_memset(&o, 0, sizeof o);
    o.oa = oa;
    o.nselected = nsel;
    o.only_selected = nsel > 0;
    o.overwrite = g_set.overwrite;
    o.open_folder = g_set.open_folder;
    o.make_folder = g_set.smart_folder;
    wchar_t here[MAX_PATH * 2];
    path_dir(here, oa->path, GZ_COUNTOF(here));

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
    case X_TO:
        if (!GetFullPathNameW(to, GZ_COUNTOF(o.dest), o.dest, NULL)) wcopy(o.dest, to, GZ_COUNTOF(o.dest));
        o.make_folder = 0;
        break;
    case X_TEST:
        o.open_folder = 0;
        break;
    }
    const u8 *use_sel = o.only_selected ? sel : 0;
    const wchar_t *use_strip = o.only_selected ? strip : 0;
    if (mode != X_TEST && o.make_folder && smart_needs_folder(oa, use_sel, use_strip)) {
        wchar_t name[MAX_PATH];
        wcopy(name, path_base(oa->path), MAX_PATH);
        path_strip_ext(name);
        path_join(o.dest, o.dest, name, GZ_COUNTOF(o.dest));
    }

    gz_job *j = job_new(oa);
    if (!j) return GZ_E_NOMEM;
    j->sel = (u8 *)use_sel;
    j->strip = use_strip;
    j->test_only = mode == X_TEST;
    j->overwrite = o.overwrite;
    j->open_folder = o.open_folder;
    wcopy(j->dest, o.dest, GZ_COUNTOF(j->dest));
    int r = run_job_with_progress(owner, j);
    if (j->test_only || j->nerr) dlg_errors(owner, j);
    else if (r == GZ_OK && j->open_folder) open_in_explorer(j->dest);
    job_free(j);
    return r;
}

/* ---------------- command line ---------------- */

static int cmd_batch(int mode, const wchar_t *to, LPWSTR *argv, int argc, int first)
{
    int rc = 0;
    for (int i = first; i < argc; i++) {
        if (argv[i][0] == '/' && argv[i][1] && argv[i][2] != ':' ) continue;
        int err;
        gz_open_arc *oa = open_archive_ui(NULL, argv[i], g_set.codepage, &err);
        if (!oa) {
            if (err == GZ_E_CANCEL) return 1;
            wchar_t t[MAX_PATH * 2 + 256];
            wfmt(t, L"%s\n\n%s\n%s", S(S_OPEN_FAIL), argv[i], err == GZ_E_METHOD ? S(S_E_SPLIT) : err_text(err));
            msg_box(NULL, t, MB_ICONWARNING);
            rc = 1;
            continue;
        }
        settings_add_recent(oa->path);
        int r = do_extract(NULL, oa, mode, to, 0, 0, 0);
        arc_close(oa);
        if (r == GZ_E_CANCEL) return 1;
        if (r) rc = 1;
    }
    settings_save();
    return rc;
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
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(g_set.cpu_tier);

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
    else if (!wicmp(a1, L"/register")) rc = !shell_register(argc > 2 && !wicmp(argv[2], L"/assoc"));
    else if (!wicmp(a1, L"/unregister")) rc = !shell_unregister();
    else if (!wicmp(a1, L"/bench")) dlg_bench(NULL);
    else {
        const wchar_t *open = 0;
        for (int i = 1; i < argc; i++) if (argv[i][0] != '/') { open = argv[i]; break; }
        HWND h = mainwnd_create(open, SW_SHOWNORMAL);
        if (h) rc = mainwnd_loop(h);
    }
    if (argv) LocalFree(argv);
    OleUninitialize();
    return rc;
}
