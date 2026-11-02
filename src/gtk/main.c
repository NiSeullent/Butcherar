/*
 * 고깃ZIP GTK - start-up and command line modes
 *
 *   gogitzip-gtk [archive]                    main window
 *   gogitzip-gtk --extract-here  ARCHIVE...   into each archive's folder
 *   gogitzip-gtk --extract-smart ARCHIVE...   into a folder named after the archive when needed
 *   gogitzip-gtk --extract-to DIR ARCHIVE...  into DIR
 *   gogitzip-gtk --extract ARCHIVE...         ask with the extract dialog
 *   gogitzip-gtk --test ARCHIVE...            test
 *   gogitzip-gtk --compress FILE...           create dialog (no files: pick them first)
 *        [--output ARCHIVE] [--format zip|7z|tar|tgz|...] [--level 0-9] [--yes]
 *   gogitzip-gtk --set-default-apps           make GogitZIP the default for archives (this user)
 *   options: --yes  answer questions automatically (overwrite, no dialogs; errors on stderr)
 *            --lang ko|en
 * The command line modes show only progress windows (used by file manager
 * integration) and exit with 0 ok, 1 warnings, 2 errors, 7 usage, 255 canceled.
 */
#include "app.h"
#include <stdlib.h>
#include <string.h>
#include <locale.h>

enum { MODE_GUI = 0, MODE_HERE, MODE_SMART, MODE_TO, MODE_DIALOG, MODE_TEST, MODE_COMPRESS, MODE_ASSOC };

static struct {
    int mode, yes, level, format, exit_code, idx;
    char *to, *out;
    GPtrArray *files;               /* absolute fs paths */
    gz_handle *h;
} C;

static void worst(int code)
{
    if (code == EXIT_BREAK || C.exit_code == EXIT_BREAK) C.exit_code = EXIT_BREAK;
    else if (code > C.exit_code) C.exit_code = code;
}

/* ---------------- extract / test archives one after another ---------------- */

static void next_archive(void);

static void on_extracted(gz_run *r, int res, void *user)
{
    worst(run_exit_code(r, res));
    gz_handle_close(C.h);
    C.h = NULL;
    if (res == GZ_E_CANCEL) { gtk_main_quit(); return; }
    next_archive();
}

static void on_cli_opened(gz_run *r, int res, void *user)
{
    const char *path = user;
    C.h = run_take_handle(r);
    if (!C.h) {
        char *d = disp_path(path);
        g_printerr("%s: %s : %s\n", TR(STR_L_ERROR), d, gz_ui_code_text(res ? res : GZ_E_FORMAT));
        if (res != GZ_E_CANCEL && !C.yes) {
            char *s = g_strdup_printf("%s\n%s", d, gz_ui_code_text(res ? res : GZ_E_FORMAT));
            msg_box(NULL, GTK_MESSAGE_WARNING, TR(STR_OPEN_FAIL), s);
            g_free(s);
        }
        g_free(d);
        worst(res == GZ_E_CANCEL ? EXIT_BREAK : EXIT_FATAL);
        if (res == GZ_E_CANCEL) gtk_main_quit();
        else next_archive();
        return;
    }
    gz_extract_opts xo;
    memset(&xo, 0, sizeof xo);
    char *dir = g_path_get_dirname(path);
    char *dest = C.mode == MODE_TO ? g_strdup(C.to) : g_strdup(dir);
    int flags = RUN_QUIET_OK | (C.yes ? RUN_QUIET | RUN_LOG_STDERR : 0);
    xo.overwrite = C.yes ? GZ_OW_ALL : g_set.overwrite;
    xo.smart = C.mode == MODE_SMART;
    xo.path_mode = GZ_PATH_FULL;
    if (C.mode == MODE_TEST) {
        xo.test = 1;
        if (!C.yes) flags &= ~RUN_QUIET_OK;
    } else if (C.mode == MODE_DIALOG) {
        xdlg_out o;
        if (!dlg_extract(NULL, C.h, path, 0, &o)) {
            g_free(dest);
            g_free(dir);
            gz_handle_close(C.h);
            C.h = NULL;
            next_archive();
            return;
        }
        g_free(dest);
        dest = o.dest;
        xo.smart = o.smart;
        xo.overwrite = o.overwrite;
        xo.path_mode = o.path_mode;
        if (o.open_folder) flags |= RUN_OPEN_DEST;
    }
    gzch *wd = fs2w(dest);
    xo.dest = wd;
    xo.threads = g_set.threads;
    gz_run *x = run_extract(NULL, C.h, &xo, flags, on_extracted, NULL);
    gz_free(wd);
    g_free(dest);
    g_free(dir);
    if (!x) {
        worst(EXIT_FATAL);
        gz_handle_close(C.h);
        C.h = NULL;
        next_archive();
    }
}

static void next_archive(void)
{
    if (C.idx >= (int)C.files->len) { gtk_main_quit(); return; }
    const char *p = g_ptr_array_index(C.files, C.idx++);
    if (!run_open(NULL, p, g_set.codepage, on_cli_opened, (void *)p)) {
        worst(EXIT_FATAL);
        next_archive();
    }
}

/* ---------------- compress ---------------- */

static int format_by_name(const char *s)
{
    static const struct { const char *n; int f; } t[] = {
        { "zip", GZ_WF_ZIP }, { "7z", GZ_WF_7Z }, { "tar", GZ_WF_TAR }, { "tgz", GZ_WF_TGZ }, { "tar.gz", GZ_WF_TGZ },
        { "tbz2", GZ_WF_TBZ2 }, { "tar.bz2", GZ_WF_TBZ2 }, { "txz", GZ_WF_TXZ }, { "tar.xz", GZ_WF_TXZ },
        { "tzst", GZ_WF_TZST }, { "tar.zst", GZ_WF_TZST }, { "gz", GZ_WF_GZ }, { "bz2", GZ_WF_BZ2 },
        { "xz", GZ_WF_XZ }, { "zst", GZ_WF_ZST }, { "iso", GZ_WF_ISO },
    };
    for (size_t i = 0; i < G_N_ELEMENTS(t); i++) if (!g_ascii_strcasecmp(s, t[i].n)) return t[i].f;
    return 0;
}

static void on_compressed(gz_run *r, int res, void *user)
{
    worst(run_exit_code(r, res));
    gtk_main_quit();
}

static gboolean start_compress(gpointer u)
{
    int n = (int)C.files->len;
    char **paths = (char **)C.files->pdata;
    cdlg_out o;
    memset(&o, 0, sizeof o);
    if (C.yes && C.out) {
        o.out = abs_path(C.out);
        gzch *w = fs2w(o.out);
        o.format = C.format ? C.format : gz_format_from_name(w);
        gz_free(w);
        if (!o.format) {
            const gz_writer *dw = writer_default(n, n == 1 && !path_is_dir(paths[0]));
            o.format = dw ? dw->format : 0;
        }
        o.level = C.level >= 0 ? C.level : 5;
        o.solid = 1;
        if (!gz_writer_find(o.format)) {
            g_printerr("%s: %s\n", TR(STR_L_ERROR), TR(STR_N_NO_WRITER));
            worst(EXIT_USAGE);
            cdlg_out_free(&o);
            gtk_main_quit();
            return G_SOURCE_REMOVE;
        }
    } else {
        if (C.format) g_set.c_format = C.format;
        if (C.level >= 0) g_set.c_level = C.level;
        if (!dlg_create(NULL, paths, n, &o)) {
            worst(EXIT_BREAK);
            gtk_main_quit();
            return G_SOURCE_REMOVE;
        }
    }
    gz_compress_opts co;
    memset(&co, 0, sizeof co);
    gzch **in = g_new0(gzch *, n + 1);
    for (int i = 0; i < n; i++) in[i] = fs2w(paths[i]);
    gzch *wout = fs2w(o.out), *wpw = o.password ? u2w(o.password) : NULL;
    co.out = wout;
    co.inputs = (const gzch *const *)in;
    co.ninputs = (u32)n;
    co.format = o.format;
    co.method = o.method;
    co.level = o.level;
    co.solid = o.solid;
    co.encryption = wpw ? o.encryption : GZ_WE_NONE;
    co.password = wpw;
    co.encrypt_names = o.encrypt_names;
    co.threads = g_set.threads;
    co.overwrite = C.yes ? GZ_OW_ALL : GZ_OW_ASK;
    int flags = RUN_QUIET_OK | (C.yes ? RUN_QUIET | RUN_LOG_STDERR : 0);
    if (!run_compress(NULL, &co, flags, on_compressed, NULL)) {
        worst(EXIT_FATAL);
        gtk_main_quit();
    }
    for (int i = 0; i < n; i++) gz_free(in[i]);
    g_free(in);
    gz_free(wout);
    if (wpw) { memset(wpw, 0, gz_wcslen(wpw) * sizeof(gzch)); g_free(wpw); }
    cdlg_out_free(&o);
    return G_SOURCE_REMOVE;
}

static int pick_inputs(void)
{
    GtkWidget *fc = gtk_file_chooser_dialog_new(TR(STR_C_PICK_FILES), NULL, GTK_FILE_CHOOSER_ACTION_OPEN,
                                                TR(STR_CANCEL), GTK_RESPONSE_CANCEL, TR(STR_SELECT),
                                                GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(fc), TRUE);
    if (gtk_dialog_run(GTK_DIALOG(fc)) == GTK_RESPONSE_ACCEPT) {
        GSList *l = gtk_file_chooser_get_filenames(GTK_FILE_CHOOSER(fc));
        for (GSList *x = l; x; x = x->next) g_ptr_array_add(C.files, x->data);
        g_slist_free(l);
    }
    gtk_widget_destroy(fc);
    return C.files->len > 0;
}

/* ---------------- start-up ---------------- */

static void pick_language(const char *forced)
{
    int ko = 0;
    if (forced) ko = gz_ui_locale_korean(forced);
    else if (g_set.lang) ko = g_set.lang == 1;
    else {
        const char *vars[] = { "LC_ALL", "LC_MESSAGES", "LANG" };
        for (int i = 0; i < 3; i++) {
            const char *v = g_getenv(vars[i]);
            if (v && *v) { ko = gz_ui_locale_korean(v); break; }
        }
    }
    gz_ui_set_korean(ko);
}

static void set_icons(void)
{
    static const int sz[] = { 16, 24, 32, 48, 64, 128 };
    GList *l = NULL;
    for (size_t i = 0; i < G_N_ELEMENTS(sz); i++) l = g_list_append(l, icon_pixbuf(IC_LOGO, sz[i]));
    gtk_window_set_default_icon_list(l);
    g_list_free_full(l, g_object_unref);
}

static int usage(int code)
{
    fputs(TR(STR_USAGE), code ? stderr : stdout);
    return code;
}

int main(int argc, char **argv)
{
    setlocale(LC_ALL, "");
    settings_load();
    C.files = g_ptr_array_new_with_free_func(g_free);
    C.level = -1;
    const char *lang = NULL;
    int need_val = 0, any_mode = 0;
    /* first pass: language (messages of the usage text) */
    for (int i = 1; i < argc; i++) if (!strcmp(argv[i], "--lang") && i + 1 < argc) lang = argv[i + 1];
    pick_language(lang);
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (need_val) { need_val = 0; continue; }
        if (!strcmp(a, "--")) {
            for (i++; i < argc; i++) g_ptr_array_add(C.files, abs_path(argv[i]));
            break;
        }
#define MODE(m) do { if (any_mode && C.mode != (m)) return usage(EXIT_USAGE); C.mode = (m); any_mode = 1; } while (0)
        if (!strcmp(a, "--extract-here")) MODE(MODE_HERE);
        else if (!strcmp(a, "--extract-smart")) MODE(MODE_SMART);
        else if (!strcmp(a, "--extract")) MODE(MODE_DIALOG);
        else if (!strcmp(a, "--test")) MODE(MODE_TEST);
        else if (!strcmp(a, "--compress")) MODE(MODE_COMPRESS);
        else if (!strcmp(a, "--set-default-apps")) MODE(MODE_ASSOC);
        else if (!strcmp(a, "--extract-to")) {
            MODE(MODE_TO);
            if (i + 1 >= argc) return usage(EXIT_USAGE);
            C.to = abs_path(argv[++i]);
        } else if (!strcmp(a, "--output") || !strcmp(a, "-o")) {
            if (i + 1 >= argc) return usage(EXIT_USAGE);
            g_free(C.out);
            C.out = g_strdup(argv[++i]);
        } else if (!strcmp(a, "--format")) {
            if (i + 1 >= argc || !(C.format = format_by_name(argv[i + 1]))) return usage(EXIT_USAGE);
            i++;
        } else if (!strcmp(a, "--level")) {
            if (i + 1 >= argc) return usage(EXIT_USAGE);
            char *e;
            long v = strtol(argv[++i], &e, 10);
            if (*e || v < 0 || v > 9) return usage(EXIT_USAGE);
            C.level = (int)v;
        } else if (!strcmp(a, "--yes") || !strcmp(a, "-y")) C.yes = 1;
        else if (!strcmp(a, "--lang")) need_val = 1;
        else if (!strcmp(a, "--help") || !strcmp(a, "-h")) return usage(0);
        else if (!strcmp(a, "--version")) { printf("GogitZIP %s\n", GZ_APP_VERSION); return 0; }
        else if (a[0] == '-' && a[1]) return usage(EXIT_USAGE);
        else g_ptr_array_add(C.files, abs_path(a));
#undef MODE
    }
    if ((C.mode == MODE_HERE || C.mode == MODE_SMART || C.mode == MODE_TO || C.mode == MODE_DIALOG ||
         C.mode == MODE_TEST) && !C.files->len)
        return usage(EXIT_USAGE);

    gz_engine_init(-1);
    if (C.mode == MODE_ASSOC) {
        if (!gtk_init_check(&argc, &argv)) { /* GIO alone is enough */ }
        int n = 0, ok = assoc_set_default(&n);
        printf("%d\n", n);
        return ok ? 0 : EXIT_FATAL;
    }
    if (!gtk_init_check(&argc, &argv)) {
        g_printerr("gogitzip-gtk: cannot open display\n");
        return EXIT_FATAL;
    }
    g_set_prgname("gogitzip-gtk");
    g_set_application_name(TR(STR_APP));
    icons_init();
    css_init();
    set_icons();
    temp_sweep_stale();

    switch (C.mode) {
    case MODE_GUI:
        mainwnd_create();
        if (C.files->len) mainwnd_open(g_ptr_array_index(C.files, 0));
        gtk_main();
        break;
    case MODE_COMPRESS:
        if (!C.files->len && !pick_inputs()) { C.exit_code = EXIT_BREAK; break; }
        g_idle_add(start_compress, NULL);
        gtk_main();
        break;
    default:
        if (C.mode == MODE_TO) g_mkdir_with_parents(C.to, 0755);
        next_archive();
        gtk_main();
        break;
    }
    settings_save();
    temp_cleanup();
    if (C.h) gz_handle_close(C.h);
    g_free(C.to);
    g_free(C.out);
    g_ptr_array_free(C.files, TRUE);
    return C.exit_code;
}
