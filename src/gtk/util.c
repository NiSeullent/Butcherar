/*
 * 고깃ZIP GTK - settings, text conversion, temporary folders, small helpers
 */
#include "app.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

gz_settings g_set;

/* ======================================================================
 * settings: ~/.config/gogitzip/settings.ini (GKeyFile)
 * ====================================================================== */

static char *settings_file(void)
{
    return g_build_filename(g_get_user_config_dir(), "gogitzip", "settings.ini", NULL);
}

static int kf_int(GKeyFile *k, const char *grp, const char *key, int def, int lo, int hi)
{
    GError *e = NULL;
    int v = g_key_file_get_integer(k, grp, key, &e);
    if (e) { g_error_free(e); return def; }
    return v < lo || v > hi ? def : v;
}

void settings_load(void)
{
    gz_settings *s = &g_set;
    s->lang = 0;
    s->codepage = 0;
    s->threads = 0;
    s->overwrite = GZ_OW_ASK;
    s->smart = 1;
    s->open_folder = 1;
    s->path_mode = GZ_PATH_FULL;
    s->dest_mode = 0;
    s->show_tree = 1;
    s->win_w = 1192;
    s->win_h = 720;
    s->pane = 240;
    s->c_format = GZ_WF_ZIP;
    s->c_level = 5;
    s->c_enc = GZ_WE_AES256;
    char *fn = settings_file();
    GKeyFile *k = g_key_file_new();
    if (g_key_file_load_from_file(k, fn, G_KEY_FILE_NONE, NULL)) {
        s->lang = kf_int(k, "general", "language", 0, 0, 2);
        s->codepage = kf_int(k, "general", "codepage", 0, 0, 65535);
        if (s->codepage && !gz_plat_cp_valid(s->codepage)) s->codepage = 0;
        s->threads = kf_int(k, "general", "threads", 0, 0, 256);
        s->overwrite = kf_int(k, "extract", "overwrite", GZ_OW_ASK, GZ_OW_ASK, GZ_OW_NEWER);
        s->smart = kf_int(k, "extract", "smart", 1, 0, 1);
        s->open_folder = kf_int(k, "extract", "open_folder", 1, 0, 1);
        s->path_mode = kf_int(k, "extract", "paths", GZ_PATH_FULL, GZ_PATH_FULL, GZ_PATH_NONE);
        s->dest_mode = kf_int(k, "extract", "dest_mode", 0, 0, 1);
        char *d = g_key_file_get_string(k, "extract", "dest", NULL);
        if (d && d[0] == '/') s->dest = d;
        else g_free(d);
        s->show_tree = kf_int(k, "window", "tree", 1, 0, 1);
        s->win_w = kf_int(k, "window", "width", 1192, 400, 16384);
        s->win_h = kf_int(k, "window", "height", 720, 300, 16384);
        s->win_max = kf_int(k, "window", "maximized", 0, 0, 1);
        s->pane = kf_int(k, "window", "pane", 240, 60, 4096);
        s->c_format = kf_int(k, "create", "format", GZ_WF_ZIP, 1, GZ_WF_COUNT - 1);
        s->c_level = kf_int(k, "create", "level", 5, 0, 9);
        s->c_enc = kf_int(k, "create", "encryption", GZ_WE_AES256, GZ_WE_ZIPCRYPTO, GZ_WE_AES256);
        gsize n = 0;
        char **r = g_key_file_get_string_list(k, "recent", "files", &n, NULL);
        for (gsize i = 0, o = 0; r && i < n && o < GZ_RECENT_MAX; i++)
            if (r[i][0] == '/') s->recent[o++] = g_strdup(r[i]);
        g_strfreev(r);
    }
    g_key_file_free(k);
    g_free(fn);
}

void settings_save(void)
{
    gz_settings *s = &g_set;
    GKeyFile *k = g_key_file_new();
    g_key_file_set_integer(k, "general", "language", s->lang);
    g_key_file_set_integer(k, "general", "codepage", s->codepage);
    g_key_file_set_integer(k, "general", "threads", s->threads);
    g_key_file_set_integer(k, "extract", "overwrite", s->overwrite);
    g_key_file_set_integer(k, "extract", "smart", s->smart);
    g_key_file_set_integer(k, "extract", "open_folder", s->open_folder);
    g_key_file_set_integer(k, "extract", "paths", s->path_mode);
    g_key_file_set_integer(k, "extract", "dest_mode", s->dest_mode);
    if (s->dest) g_key_file_set_string(k, "extract", "dest", s->dest);
    g_key_file_set_integer(k, "window", "tree", s->show_tree);
    g_key_file_set_integer(k, "window", "width", s->win_w);
    g_key_file_set_integer(k, "window", "height", s->win_h);
    g_key_file_set_integer(k, "window", "maximized", s->win_max);
    g_key_file_set_integer(k, "window", "pane", s->pane);
    g_key_file_set_integer(k, "create", "format", s->c_format);
    g_key_file_set_integer(k, "create", "level", s->c_level);
    g_key_file_set_integer(k, "create", "encryption", s->c_enc);
    const char *r[GZ_RECENT_MAX];
    int n = 0;
    for (int i = 0; i < GZ_RECENT_MAX; i++) if (s->recent[i]) r[n++] = s->recent[i];
    g_key_file_set_string_list(k, "recent", "files", r, (gsize)n);
    char *dir = g_build_filename(g_get_user_config_dir(), "gogitzip", NULL);
    g_mkdir_with_parents(dir, 0700);
    char *fn = settings_file();
    g_key_file_save_to_file(k, fn, NULL);
    g_free(fn);
    g_free(dir);
    g_key_file_free(k);
}

void settings_add_recent(const char *path)
{
    if (!path || path[0] != '/') return;
    char *p = g_strdup(path);
    int at = GZ_RECENT_MAX - 1;
    for (int i = 0; i < GZ_RECENT_MAX; i++)
        if (g_set.recent[i] && !strcmp(g_set.recent[i], path)) { at = i; break; }
    g_free(g_set.recent[at]);
    for (int i = at; i > 0; i--) g_set.recent[i] = g_set.recent[i - 1];
    g_set.recent[0] = p;
}

int settings_threads(void)
{
    return g_set.threads > 0 ? g_set.threads : gz_os_cpu_count();
}

/* ======================================================================
 * text
 * ====================================================================== */

char *w2u_n(const gzch *w, size_t n)
{
    char *o = g_malloc(n * 3 + 1);
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        u32 c = w[i];
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < n && w[i + 1] >= 0xDC00 && w[i + 1] < 0xE000) {
            c = 0x10000 + ((c - 0xD800) << 10) + (w[i + 1] - 0xDC00u);
            i++;
        } else if (c >= 0xD800 && c < 0xE000) {
            c = 0xFFFD;                      /* lone surrogate (undecodable byte) */
        }
        if (c < 0x80) o[k++] = (char)c;
        else if (c < 0x800) { o[k++] = (char)(0xC0 | c >> 6); o[k++] = (char)(0x80 | (c & 63)); }
        else if (c < 0x10000) {
            o[k++] = (char)(0xE0 | c >> 12);
            o[k++] = (char)(0x80 | ((c >> 6) & 63));
            o[k++] = (char)(0x80 | (c & 63));
        } else {
            o[k++] = (char)(0xF0 | c >> 18);
            o[k++] = (char)(0x80 | ((c >> 12) & 63));
            o[k++] = (char)(0x80 | ((c >> 6) & 63));
            o[k++] = (char)(0x80 | (c & 63));
        }
    }
    o[k] = 0;
    return o;
}

char *w2u(const gzch *w) { return w2u_n(w ? w : u"", w ? gz_wcslen(w) : 0); }

gzch *u2w(const char *s)
{
    glong n = 0;
    gunichar2 *w = g_utf8_to_utf16(s ? s : "", -1, NULL, &n, NULL);
    G_STATIC_ASSERT(sizeof(gunichar2) == sizeof(gzch));
    return (gzch *)w;
}

gzch *fs2w(const char *path) { return gz_os_path_wide(path ? path : ""); }
char *w2fs(const gzch *w) { return gz_os_path_bytes(w ? w : u""); }

void wcopy_cap(gzch *d, const gzch *s, size_t cap)
{
    size_t i = 0;
    if (!cap) return;
    for (; s && s[i] && i + 1 < cap; i++) d[i] = s[i];
    d[i] = 0;
}

char *disp_path(const char *fs_path) { return g_filename_display_name(fs_path ? fs_path : ""); }

char *disp_path_short(const char *fs)
{
    const char *home = g_get_home_dir();
    size_t n = home ? strlen(home) : 0;
    if (n > 1 && !strncmp(fs, home, n) && (fs[n] == '/' || !fs[n])) {
        char *rest = disp_path(fs + n);
        char *r = g_strconcat("~", rest, NULL);
        g_free(rest);
        return r;
    }
    return disp_path(fs);
}

/* Path entries show "~/..." and display names, but keep the real path (which may hold
 * bytes that are not UTF-8) as long as the text is not edited. */
void path_entry_set(GtkEntry *e, const char *fs)
{
    char *u = disp_path_short(fs);
    g_object_set_data_full(G_OBJECT(e), "gz-fs", g_strdup(fs), g_free);
    g_object_set_data_full(G_OBJECT(e), "gz-shown", g_strdup(u), g_free);
    gtk_entry_set_text(e, u);
    gtk_editable_set_position(GTK_EDITABLE(e), -1);
    g_free(u);
}

char *path_entry_get(GtkEntry *e, const char *base)
{
    const char *t = gtk_entry_get_text(e);
    const char *shown = g_object_get_data(G_OBJECT(e), "gz-shown"), *fs = g_object_get_data(G_OBJECT(e), "gz-fs");
    if (shown && fs && !strcmp(shown, t)) return g_strdup(fs);
    while (*t == ' ') t++;
    if (!*t) return NULL;
    char *raw = g_filename_from_utf8(t, -1, NULL, NULL, NULL);
    if (!raw) return NULL;
    if (raw[0] == '~' && (raw[1] == '/' || !raw[1])) {
        char *x = g_strconcat(g_get_home_dir(), raw + 1, NULL);
        g_free(raw);
        raw = x;
    }
    char *ab = g_canonicalize_filename(raw, g_path_is_absolute(raw) ? NULL : base);
    g_free(raw);
    return ab;
}

void fmt_filetime(char *o, size_t cap, u64 ft)
{
    gz_os_tm tm;
    o[0] = 0;
    if (!ft || gz_os_local_time(ft, &tm)) return;
    g_snprintf(o, cap, "%04d-%02d-%02d %02d:%02d", tm.year, tm.month, tm.day, tm.hour, tm.min);
}

/* ======================================================================
 * paths
 * ====================================================================== */

char *abs_path(const char *arg)
{
    if (g_str_has_prefix(arg, "file://")) {
        char *p = g_filename_from_uri(arg, NULL, NULL);
        if (p) return p;
    }
    return g_canonicalize_filename(arg, NULL);
}

int path_is_dir(const char *p) { return p && g_file_test(p, G_FILE_TEST_IS_DIR); }
int path_exists(const char *p) { struct stat st; return p && !lstat(p, &st); }

/* ======================================================================
 * temporary folders
 * ====================================================================== */

static char *s_temp;
static unsigned s_temp_seq;

static char *temp_parent(void)
{
    char name[48];
    g_snprintf(name, sizeof name, "gogitzip-%u", (unsigned)getuid());
    return g_build_filename(g_get_tmp_dir(), name, NULL);
}

/* our own folder: must be a real directory owned by us, not a link planted by someone */
static int own_dir(const char *p)
{
    struct stat st;
    if (mkdir(p, 0700) && errno != EEXIST) return 0;
    if (lstat(p, &st) || !S_ISDIR(st.st_mode) || st.st_uid != getuid()) return 0;
    if ((st.st_mode & 077) && chmod(p, 0700)) return 0;
    return 1;
}

const char *temp_root(void)
{
    if (s_temp) return s_temp;
    char *par = temp_parent();
    if (own_dir(par)) {
        char pid[24];
        g_snprintf(pid, sizeof pid, "%u", (unsigned)getpid());
        char *p = g_build_filename(par, pid, NULL);
        if (own_dir(p)) s_temp = p;
        else g_free(p);
    }
    g_free(par);
    return s_temp;
}

char *temp_new_dir(const char *prefix)
{
    const char *root = temp_root();
    if (!root) return NULL;
    for (int i = 0; i < 1000; i++) {
        char name[48];
        g_snprintf(name, sizeof name, "%s%u", prefix, ++s_temp_seq);
        char *p = g_build_filename(root, name, NULL);
        if (!mkdir(p, 0700)) return p;
        int e = errno;
        g_free(p);
        if (e != EEXIST) return NULL;
    }
    return NULL;
}

/* delete a tree without following links (bounded depth) */
static void rm_tree_at(int dfd, const char *name, int depth)
{
    struct stat st;
    if (fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW)) return;
    if (S_ISDIR(st.st_mode) && depth < 256) {
        int fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0) {
            fchmod(fd, 0700);
            DIR *d = fdopendir(fd);
            if (d) {
                struct dirent *de;
                while ((de = readdir(d))) {
                    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
                    rm_tree_at(dirfd(d), de->d_name, depth + 1);
                }
                closedir(d);
            } else {
                close(fd);
            }
        }
        unlinkat(dfd, name, AT_REMOVEDIR);
    } else {
        unlinkat(dfd, name, 0);
    }
}

static void rm_tree(const char *path) { rm_tree_at(AT_FDCWD, path, 0); }

void temp_sweep_stale(void)
{
    char *par = temp_parent();
    struct stat st;
    if (lstat(par, &st) || !S_ISDIR(st.st_mode) || st.st_uid != getuid()) { g_free(par); return; }
    DIR *d = opendir(par);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d))) {
            const char *c = de->d_name;
            long pid = 0;
            if (*c < '1' || *c > '9') continue;
            for (; *c >= '0' && *c <= '9' && pid < 100000000; c++) pid = pid * 10 + (*c - '0');
            if (*c || pid == (long)getpid()) continue;
            if (kill((pid_t)pid, 0) == 0 || errno == EPERM) continue;      /* still running */
            char *p = g_build_filename(par, de->d_name, NULL);
            rm_tree(p);
            g_free(p);
        }
        closedir(d);
    }
    g_free(par);
}

void temp_cleanup(void)
{
    if (!s_temp) return;
    rm_tree(s_temp);
    char *par = temp_parent();
    rmdir(par);                       /* only when empty */
    g_free(par);
    g_free(s_temp);
    s_temp = NULL;
}

/* ======================================================================
 * desktop integration
 * ====================================================================== */

void open_with_default(GtkWindow *parent, const char *path)
{
    GFile *f = g_file_new_for_path(path);
    char *uri = g_file_get_uri(f);
    GError *err = NULL;
    GdkAppLaunchContext *ctx = gdk_display_get_app_launch_context(gdk_display_get_default());
    gboolean ok = g_app_info_launch_default_for_uri(uri, G_APP_LAUNCH_CONTEXT(ctx), &err);
    if (!ok) {
        g_clear_error(&err);
        ok = gtk_show_uri_on_window(parent, uri, GDK_CURRENT_TIME, &err);
    }
    if (!ok) {
        char *d = disp_path(path);
        msg_box(parent, GTK_MESSAGE_WARNING, TR(STR_OPEN_FILE_FAIL), d);
        g_free(d);
    }
    g_clear_error(&err);
    g_object_unref(ctx);
    g_free(uri);
    g_object_unref(f);
}

void show_folder(GtkWindow *parent, const char *path)
{
    if (path_is_dir(path)) open_with_default(parent, path);
}

void msg_box(GtkWindow *parent, GtkMessageType type, const char *primary, const char *secondary)
{
    GtkWidget *d = gtk_message_dialog_new(parent, GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, type,
                                          GTK_BUTTONS_NONE, "%s", primary);
    if (secondary && *secondary)
        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(d), "%s", secondary);
    gtk_dialog_add_button(GTK_DIALOG(d), TR(STR_OK), GTK_RESPONSE_OK);
    gtk_window_set_title(GTK_WINDOW(d), TR(STR_APP));
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

/* extensions of formats that are usually opened by other programs */
static const char *const k_docs[] = { "docx", "xlsx", "pptx", "odt", "ods", "odp", "odg", "epub", "doc", "xls",
                                      "ppt", "msg", "bin", "raw", "exe", "dll", "apk", "ipa", "whl", "jar",
                                      "war", "ear", "xpi", "appx", "nupkg", "chm", "chi", "chq", "chw", 0 };

int is_archive_name(const char *name)
{
    const char *dot = strrchr(name, '.');
    if (!dot || !dot[1] || strchr(dot, '/')) return 0;
    char ext[24];
    size_t n = 0;
    for (const char *p = dot + 1; *p && n + 1 < sizeof ext; p++) ext[n++] = g_ascii_tolower(*p);
    ext[n] = 0;
    if (dot[1 + n]) return 0;
    for (int i = 0; k_docs[i]; i++) if (!strcmp(ext, k_docs[i])) return 0;
    for (int i = 0; gz_formats[i]; i++) {
        const char *e = gz_formats[i]->exts;
        while (e && *e) {
            const char *s = e;
            while (*e && *e != ' ') e++;
            if ((size_t)(e - s) == n && !memcmp(s, ext, n)) return 1;
            while (*e == ' ') e++;
        }
    }
    /* split volumes: name.7z.001, name.part1.rar ... are opened by their readers */
    if (n == 3 && g_ascii_isdigit(ext[0]) && g_ascii_isdigit(ext[1]) && g_ascii_isdigit(ext[2])) return 1;
    return 0;
}

const char *engine_line(void)
{
    static char s[160];
    if (!s[0])
        g_snprintf(s, sizeof s, "%s  ·  CRC %s  ·  %s", gz_dispatch_inflate_name(), gz_dispatch_crc_name(),
                   gz_dispatch_aes_name());
    return s;
}
