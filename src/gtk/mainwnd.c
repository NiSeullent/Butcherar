/*
 * 고깃ZIP GTK - main window
 *
 *  ┌──────────────────────────────────────────────────────────────┐
 *  │ menu                                                          │
 *  │ [열기] [풀기▾] [새로 압축] │ [테스트] [정보] │ [코드 페이지] [설정] │  toolbar
 *  │ [↑]  archive.zip › 문서 › 사진                                │  path bar
 *  │ folder tree │ file list (virtual model, fixed-height rows)    │
 *  │ 파일 12개, 폴더 3개 · 원본 …                AVX2 엔진 · 8스레드 │  status bar
 *  └──────────────────────────────────────────────────────────────┘
 * Without an archive the browser is replaced by the welcome screen.
 */
#include "app.h"
#include <stdlib.h>
#include <string.h>

enum { X_DIALOG = 0, X_HERE, X_SMART, X_SELECTED };
enum { TC_ICON = 0, TC_NAME, TC_FOLDER, TC_COUNT };
#define MAX_NEST 16

static struct {
    GtkWidget *win, *stack, *recent_box, *recent_title, *crumbs, *up_btn, *paned, *tree_sw, *tree, *list;
    GtkWidget *st_left, *st_right, *menu_recent, *mi_tree, *mi_back, *dropzone;
    GtkAccelGroup *accel;
    GPtrArray *needs_arc;          /* widgets usable only with an open archive */
    gz_handle *h;                  /* archive shown                            */
    gz_handle *outer[MAX_NEST];    /* archives it is nested in (kept open)    */
    int depth;
    char *path;                    /* file of the outermost archive (fs path)  */
    i32 cur;                       /* folder shown                             */
    GzList *model;
    GtkTreeStore *ts;
    GtkTreeViewColumn *cols[LC_COUNT];
    int sort_col, sort_desc, syncing;
    guint status_idle;
} M;

static void navigate(i32 f, i32 focus);
static void update_status(void);
static void rebuild_recent(void);

GtkWindow *mainwnd_window(void) { return M.win ? GTK_WINDOW(M.win) : NULL; }

static int busy(void) { return runs_active() > 0; }

/* ======================================================================
 * title, sensitivity
 * ====================================================================== */

static void update_title(void)
{
    if (!M.h) { gtk_window_set_title(GTK_WINDOW(M.win), TR(STR_APP)); return; }
    char *n = w2u(M.h->name);
    char *t = g_strdup_printf("%s - %s", n, TR(STR_APP));
    gtk_window_set_title(GTK_WINDOW(M.win), t);
    g_free(t);
    g_free(n);
}

static void update_sensitive(void)
{
    for (guint i = 0; i < M.needs_arc->len; i++) gtk_widget_set_sensitive(g_ptr_array_index(M.needs_arc, i), M.h != NULL);
    if (M.mi_back) gtk_widget_set_sensitive(M.mi_back, M.depth > 0);
}

static void need_arc(GtkWidget *w) { g_ptr_array_add(M.needs_arc, w); }

/* ======================================================================
 * folder tree (lazy)
 * ====================================================================== */

static GIcon *folder_icon(void)
{
    static GIcon *ic;
    if (!ic) ic = g_themed_icon_new_with_default_fallbacks("folder");
    return ic;
}

static const gz_archive *s_sort_arc;      /* qsort context (UI thread only) */
static int cmp_sub(const void *x, const void *y)
{
    return name_cmp_natural(s_sort_arc->f[*(const i32 *)x].base, s_sort_arc->f[*(const i32 *)y].base);
}

static void tree_fill(GtkTreeIter *parent, i32 f)
{
    gz_archive *a = M.h->arc;
    u32 n = 0;
    for (i32 s = a->f[f].first_sub; s >= 0 && n < a->nf; s = a->f[s].next_sib) n++;
    if (!n) return;
    i32 *v = g_new(i32, n);
    u32 k = 0;
    for (i32 s = a->f[f].first_sub; s >= 0 && k < n; s = a->f[s].next_sib) v[k++] = s;
    s_sort_arc = a;
    qsort(v, k, sizeof(i32), cmp_sub);
    for (u32 i = 0; i < k; i++) {
        GtkTreeIter it, dummy;
        char *nm = w2u(a->f[v[i]].base);
        gtk_tree_store_insert_with_values(M.ts, &it, parent, -1, TC_ICON, folder_icon(), TC_NAME, nm, TC_FOLDER,
                                          v[i], -1);
        g_free(nm);
        if (a->f[v[i]].first_sub >= 0)          /* placeholder: expandable */
            gtk_tree_store_insert_with_values(M.ts, &dummy, &it, -1, TC_FOLDER, -1, -1);
    }
    g_free(v);
}

/* replace the placeholder child of it by the real subfolders */
static void tree_expand_fill(GtkTreeIter *it)
{
    GtkTreeIter c;
    if (!gtk_tree_model_iter_children(GTK_TREE_MODEL(M.ts), &c, it)) return;
    gint fid = 0;
    gtk_tree_model_get(GTK_TREE_MODEL(M.ts), &c, TC_FOLDER, &fid, -1);
    if (fid != -1) return;
    gtk_tree_store_remove(M.ts, &c);
    gint f = 0;
    gtk_tree_model_get(GTK_TREE_MODEL(M.ts), it, TC_FOLDER, &f, -1);
    tree_fill(it, f);
}

static gboolean on_test_expand(GtkTreeView *tv, GtkTreeIter *it, GtkTreePath *p, gpointer u)
{
    tree_expand_fill(it);
    return FALSE;
}

static void tree_build(void)
{
    gtk_tree_view_set_model(GTK_TREE_VIEW(M.tree), NULL);
    if (M.ts) g_object_unref(M.ts);
    M.ts = gtk_tree_store_new(TC_COUNT, G_TYPE_ICON, G_TYPE_STRING, G_TYPE_INT);
    if (M.h) {
        GtkTreeIter root;
        char *nm = w2u(M.h->name);
        GIcon *ic = g_themed_icon_new_with_default_fallbacks("package-x-generic");
        gtk_tree_store_insert_with_values(M.ts, &root, NULL, -1, TC_ICON, ic, TC_NAME, nm, TC_FOLDER, 0, -1);
        g_object_unref(ic);
        g_free(nm);
        tree_fill(&root, 0);
    }
    gtk_tree_view_set_model(GTK_TREE_VIEW(M.tree), GTK_TREE_MODEL(M.ts));
    GtkTreePath *p = gtk_tree_path_new_first();
    gtk_tree_view_expand_row(GTK_TREE_VIEW(M.tree), p, FALSE);
    gtk_tree_path_free(p);
}

/* select folder f in the tree, expanding its ancestors */
static void tree_sync(i32 f)
{
    if (!M.h || !M.ts) return;
    gz_archive *a = M.h->arc;
    i32 chain[256];
    int n = 0;
    for (i32 x = f; x > 0 && n < 256; x = a->f[x].parent) chain[n++] = x;
    GtkTreeIter it;
    if (!gtk_tree_model_get_iter_first(GTK_TREE_MODEL(M.ts), &it)) return;
    while (n--) {
        tree_expand_fill(&it);
        GtkTreeIter c;
        int found = 0;
        if (gtk_tree_model_iter_children(GTK_TREE_MODEL(M.ts), &c, &it)) {
            do {
                gint id;
                gtk_tree_model_get(GTK_TREE_MODEL(M.ts), &c, TC_FOLDER, &id, -1);
                if (id == chain[n]) { found = 1; break; }
            } while (gtk_tree_model_iter_next(GTK_TREE_MODEL(M.ts), &c));
        }
        GtkTreePath *pp = gtk_tree_model_get_path(GTK_TREE_MODEL(M.ts), &it);
        gtk_tree_view_expand_row(GTK_TREE_VIEW(M.tree), pp, FALSE);
        gtk_tree_path_free(pp);
        if (!found) break;
        it = c;
    }
    M.syncing = 1;
    GtkTreePath *p = gtk_tree_model_get_path(GTK_TREE_MODEL(M.ts), &it);
    tree_expand_fill(&it);
    gtk_tree_view_expand_row(GTK_TREE_VIEW(M.tree), p, FALSE);     /* show the subfolders too */
    gtk_tree_selection_select_path(gtk_tree_view_get_selection(GTK_TREE_VIEW(M.tree)), p);
    gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(M.tree), p, NULL, FALSE, 0, 0);
    gtk_tree_path_free(p);
    M.syncing = 0;
}

static void on_tree_sel(GtkTreeSelection *s, gpointer u)
{
    GtkTreeIter it;
    GtkTreeModel *m;
    if (M.syncing || !M.h || !gtk_tree_selection_get_selected(s, &m, &it)) return;
    gint f = 0;
    gtk_tree_model_get(m, &it, TC_FOLDER, &f, -1);
    if (f >= 0 && f != M.cur && (u32)f < M.h->arc->nf) navigate(f, -1);
}

/* ======================================================================
 * path bar
 * ====================================================================== */

static void on_crumb(GtkButton *b, gpointer u)
{
    i32 f = GPOINTER_TO_INT(u);
    if (M.h && f != M.cur && (u32)f < M.h->arc->nf) navigate(f, -1);
}

static void path_build(void)
{
    GList *ch = gtk_container_get_children(GTK_CONTAINER(M.crumbs));
    for (GList *l = ch; l; l = l->next) gtk_widget_destroy(l->data);
    g_list_free(ch);
    if (!M.h) return;
    gz_archive *a = M.h->arc;
    i32 chain[48];
    int n = 0;
    for (i32 f = M.cur; f >= 0 && n < 48; f = a->f[f].parent) chain[n++] = f;
    GtkWidget *ic = gtk_image_new_from_icon_name("package-x-generic", GTK_ICON_SIZE_MENU);
    gtk_box_pack_start(GTK_BOX(M.crumbs), ic, FALSE, FALSE, 4);
    for (int k = n - 1; k >= 0; k--) {
        i32 f = chain[k];
        char *t = f == 0 ? w2u(M.h->name) : w2u(a->f[f].base);
        GtkWidget *b = gtk_button_new_with_label(t);
        g_free(t);
        gtk_button_set_relief(GTK_BUTTON(b), GTK_RELIEF_NONE);
        gtk_widget_set_focus_on_click(b, FALSE);
        GtkWidget *l = gtk_bin_get_child(GTK_BIN(b));
        if (GTK_IS_LABEL(l)) {
            gtk_label_set_ellipsize(GTK_LABEL(l), PANGO_ELLIPSIZE_MIDDLE);
            gtk_label_set_max_width_chars(GTK_LABEL(l), 40);
        }
        if (k == 0) gtk_style_context_add_class(gtk_widget_get_style_context(b), "gz-crumb-last");
        g_signal_connect(b, "clicked", G_CALLBACK(on_crumb), GINT_TO_POINTER(f));
        gtk_box_pack_start(GTK_BOX(M.crumbs), b, FALSE, FALSE, 0);
        if (k) {
            GtkWidget *s = gtk_label_new("›");
            gtk_style_context_add_class(gtk_widget_get_style_context(s), "gz-sep");
            gtk_box_pack_start(GTK_BOX(M.crumbs), s, FALSE, FALSE, 2);
        }
    }
    gtk_widget_show_all(M.crumbs);
    gtk_widget_set_sensitive(M.up_btn, M.cur != 0 || M.depth > 0);
}

/* ======================================================================
 * file list
 * ====================================================================== */

static void set_rows(gz_lrow *rows, u32 n, i32 focus_kind_folder)
{
    gz_list_sort(M.h->arc, rows, n, M.sort_col, M.sort_desc);
    GzList *m = gz_list_new(M.h->arc, rows, n);
    gtk_tree_view_set_model(GTK_TREE_VIEW(M.list), GTK_TREE_MODEL(m));
    if (M.model) g_object_unref(M.model);
    M.model = m;
    if (!n) return;
    u32 sel = 0;
    if (focus_kind_folder >= 0) {
        const gz_lrow *r = gz_list_rows(m, &n);
        for (u32 i = 0; i < n; i++) if (r[i].kind == 1 && r[i].idx == focus_kind_folder) { sel = i; break; }
    }
    GtkTreePath *p = gtk_tree_path_new_from_indices((gint)sel, -1);
    gtk_tree_view_set_cursor(GTK_TREE_VIEW(M.list), p, NULL, FALSE);
    if (focus_kind_folder < 0) gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(GTK_TREE_VIEW(M.list)));
    gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(M.list), p, NULL, focus_kind_folder >= 0, 0.3f, 0);
    gtk_tree_path_free(p);
}

static void navigate(i32 f, i32 focus)
{
    if (!M.h) return;
    gz_archive *a = M.h->arc;
    if (f < 0 || (u32)f >= a->nf) f = 0;
    M.cur = f;
    u32 cnt = (f != 0) + a->f[f].nsub + a->f[f].nfiles, n = 0;
    gz_lrow *rows = g_new(gz_lrow, cnt + 1);
    if (f != 0) { rows[n].kind = 0; rows[n++].idx = a->f[f].parent; }
    for (i32 s = a->f[f].first_sub; s >= 0 && n < cnt; s = a->f[s].next_sib) { rows[n].kind = 1; rows[n++].idx = s; }
    for (i32 e = a->f[f].first_file; e >= 0 && n < cnt; e = a->e[e].next) { rows[n].kind = 2; rows[n++].idx = e; }
    for (u32 i = 0; i < n; i++) memset(rows[i].pad, 0, sizeof rows[i].pad);
    set_rows(rows, n, focus);
    path_build();
    tree_sync(f);
    update_status();
}

static void on_col_clicked(GtkTreeViewColumn *c, gpointer u)
{
    int col = GPOINTER_TO_INT(u);
    if (!M.h || !M.model) return;
    if (M.sort_col == col) M.sort_desc = !M.sort_desc;
    else { M.sort_col = col; M.sort_desc = 0; }
    for (int i = 0; i < LC_COUNT; i++) {
        if (!M.cols[i]) continue;
        gtk_tree_view_column_set_sort_indicator(M.cols[i], i == M.sort_col);
        gtk_tree_view_column_set_sort_order(M.cols[i], M.sort_desc ? GTK_SORT_DESCENDING : GTK_SORT_ASCENDING);
    }
    u32 n;
    const gz_lrow *r = gz_list_rows(M.model, &n);
    gz_lrow *copy = g_memdup2(r, (gsize)n * sizeof *r + 1);
    set_rows(copy, n, -1);
}

/* selected rows: count and bytes (".." ignored) */
typedef struct { u32 n; u64 bytes; } selsum;
static void sum_fe(GtkTreeModel *m, GtkTreePath *p, GtkTreeIter *it, gpointer u)
{
    selsum *s = u;
    u32 n;
    const gz_lrow *r = gz_list_rows(GZ_LIST(m), &n);
    guint i = GPOINTER_TO_UINT(it->user_data);
    if (i >= n || r[i].kind == 0) return;
    s->n++;
    if (r[i].kind == 2) {
        u64 us = M.h->arc->e[r[i].idx].usize;
        if (us != GZ_SIZE_UNKNOWN) s->bytes += us;
    }
}

static gboolean status_now(gpointer u)
{
    M.status_idle = 0;
    char t[512], x1[32], x2[32], x3[48], x4[48], x5[16];
    if (!M.h) {
        gtk_label_set_text(GTK_LABEL(M.st_left), TR(STR_ST_READY));
        return G_SOURCE_REMOVE;
    }
    gz_archive *a = M.h->arc;
    selsum s = { 0, 0 };
    gtk_tree_selection_selected_foreach(gtk_tree_view_get_selection(GTK_TREE_VIEW(M.list)), sum_fe, &s);
    if (s.n) {
        gz_ui_fmt_thousands(x1, sizeof x1, s.n);
        gz_ui_fmt_size(x3, sizeof x3, s.bytes);
        GZ_UI_FMT(t, sizeof t, STR_ST_SELECTED, x1, x3);
    } else {
        gz_ui_fmt_thousands(x1, sizeof x1, a->nfiles);
        gz_ui_fmt_thousands(x2, sizeof x2, a->ndirs);
        gz_ui_fmt_size(x3, sizeof x3, a->total_usize);
        gz_ui_fmt_size(x4, sizeof x4, a->total_csize);
        gz_ui_fmt_percent(x5, sizeof x5, a->total_csize, a->total_usize);
        GZ_UI_FMT(t, sizeof t, STR_ST_SUMMARY, x1, x2, x3, x4, x5[0] ? x5 : "-");
    }
    gtk_label_set_text(GTK_LABEL(M.st_left), t);
    return G_SOURCE_REMOVE;
}

static void update_status(void)
{
    if (!M.status_idle) M.status_idle = g_idle_add(status_now, NULL);
}

static void on_list_sel(GtkTreeSelection *s, gpointer u) { update_status(); }

/* mark every entry under folder f */
static void mark_folder(gz_archive *a, i32 f, u8 *m)
{
    GArray *st = g_array_new(FALSE, FALSE, sizeof(i32));
    g_array_append_val(st, f);
    u32 guard = 0;
    while (st->len && guard++ <= a->nf) {
        i32 x = g_array_index(st, i32, st->len - 1);
        g_array_set_size(st, st->len - 1);
        if (a->f[x].entry >= 0 && (u32)a->f[x].entry < a->n) m[a->f[x].entry] = 1;
        for (i32 e = a->f[x].first_file; e >= 0 && (u32)e < a->n; e = a->e[e].next) m[e] = 1;
        for (i32 s = a->f[x].first_sub; s >= 0 && (u32)s < a->nf; s = a->f[s].next_sib) g_array_append_val(st, s);
    }
    g_array_free(st, TRUE);
}

typedef struct { u8 *m; u32 rows; GPtrArray *names; } selmask;
static void mask_fe(GtkTreeModel *mo, GtkTreePath *p, GtkTreeIter *it, gpointer u)
{
    selmask *s = u;
    u32 n;
    const gz_lrow *r = gz_list_rows(GZ_LIST(mo), &n);
    guint i = GPOINTER_TO_UINT(it->user_data);
    if (i >= n || r[i].kind == 0) return;
    gz_archive *a = M.h->arc;
    s->rows++;
    if (r[i].kind == 2) s->m[r[i].idx] = 1;
    else mark_folder(a, r[i].idx, s->m);
    if (s->names) g_ptr_array_add(s->names, (gpointer)(r[i].kind == 2 ? a->e[r[i].idx].base : a->f[r[i].idx].base));
}

/* selection -> entry mask (g_free), NULL when nothing is selected */
static u8 *selection_mask(u32 *nrows, GPtrArray *names)
{
    *nrows = 0;
    if (!M.h) return NULL;
    selmask s = { g_malloc0(M.h->arc->n + 1), 0, names };
    gtk_tree_selection_selected_foreach(gtk_tree_view_get_selection(GTK_TREE_VIEW(M.list)), mask_fe, &s);
    *nrows = s.rows;
    if (!s.rows) { g_free(s.m); return NULL; }
    return s.m;
}

/* ======================================================================
 * archives: open, nest, close
 * ====================================================================== */

static void close_all(void)
{
    gtk_tree_view_set_model(GTK_TREE_VIEW(M.list), NULL);
    if (M.model) { g_object_unref(M.model); M.model = NULL; }
    gtk_tree_view_set_model(GTK_TREE_VIEW(M.tree), NULL);
    if (M.ts) { g_object_unref(M.ts); M.ts = NULL; }
    if (M.h) gz_handle_close(M.h);
    while (M.depth) gz_handle_close(M.outer[--M.depth]);
    M.h = NULL;
    g_free(M.path);
    M.path = NULL;
}

static void show_archive(void)
{
    M.cur = 0;
    update_title();
    tree_build();
    gtk_stack_set_visible_child_name(GTK_STACK(M.stack), M.h ? "browse" : "welcome");
    if (M.h) navigate(0, -1);
    else { path_build(); rebuild_recent(); }
    update_sensitive();
    update_status();
    if (M.h) gtk_widget_grab_focus(M.list);
}

static void cmd_close(void)
{
    if (busy()) return;
    close_all();
    show_archive();
}

static void on_opened(gz_run *r, int res, void *user)
{
    char *path = user;
    gz_handle *h = run_take_handle(r);
    if (!h) {
        if (res != GZ_E_CANCEL) {
            char *d = disp_path(path);
            char *s = g_strdup_printf("%s\n%s", d, gz_ui_code_text(res ? res : GZ_E_FORMAT));
            msg_box(GTK_WINDOW(M.win), GTK_MESSAGE_WARNING, TR(STR_OPEN_FAIL), s);
            g_free(s);
            g_free(d);
        }
        g_free(path);
        return;
    }
    close_all();
    M.h = h;
    M.path = path;
    settings_add_recent(path);
    settings_save();
    show_archive();
}

void mainwnd_open(const char *path)
{
    if (busy()) return;
    char *ab = abs_path(path);
    if (!run_open(GTK_WINDOW(M.win), ab, g_set.codepage, on_opened, ab)) g_free(ab);
}

static void on_child_opened(gz_run *r, int res, void *user)
{
    gz_handle *h = run_take_handle(r);
    if (!h) {
        if (res != GZ_E_CANCEL)
            msg_box(GTK_WINDOW(M.win), GTK_MESSAGE_WARNING, TR(STR_OPEN_FAIL), gz_ui_code_text(res ? res : GZ_E_FORMAT));
        return;
    }
    if (M.depth >= MAX_NEST) { gz_handle_close(h); return; }
    gtk_tree_view_set_model(GTK_TREE_VIEW(M.list), NULL);
    M.outer[M.depth++] = M.h;
    M.h = h;
    show_archive();
}

static void cmd_back(void)
{
    if (busy() || !M.depth) return;
    gtk_tree_view_set_model(GTK_TREE_VIEW(M.list), NULL);
    if (M.model) { g_object_unref(M.model); M.model = NULL; }
    gz_handle_close(M.h);
    M.h = M.outer[--M.depth];
    show_archive();
}

static void cmd_up(void)
{
    if (!M.h) return;
    if (M.cur > 0) navigate(M.h->arc->f[M.cur].parent, M.cur);
    else cmd_back();
}

static void add_filters(GtkFileChooser *fc)
{
    GtkFileFilter *ar = gtk_file_filter_new(), *all = gtk_file_filter_new();
    gtk_file_filter_set_name(ar, TR(STR_FILTER_ARC));
    for (int i = 0; gz_formats[i]; i++) {
        const char *e = gz_formats[i]->exts;
        while (e && *e) {
            const char *s = e;
            while (*e && *e != ' ') e++;
            char pat[40], up[40];
            size_t n = (size_t)(e - s);
            if (n && n < 30) {
                g_snprintf(pat, sizeof pat, "*.%.*s", (int)n, s);
                gtk_file_filter_add_pattern(ar, pat);
                for (size_t k = 0; pat[k]; k++) up[k] = g_ascii_toupper(pat[k]);
                up[strlen(pat)] = 0;
                gtk_file_filter_add_pattern(ar, up);
            }
            while (*e == ' ') e++;
        }
    }
    gtk_file_filter_add_pattern(ar, "*.[0-9][0-9][0-9]");
    gtk_file_filter_set_name(all, TR(STR_FILTER_ALL));
    gtk_file_filter_add_pattern(all, "*");
    gtk_file_chooser_add_filter(fc, ar);
    gtk_file_chooser_add_filter(fc, all);
}

static void cmd_open(void)
{
    if (busy()) return;
    GtkWidget *fc = gtk_file_chooser_dialog_new(TR(STR_W_OPEN), GTK_WINDOW(M.win), GTK_FILE_CHOOSER_ACTION_OPEN,
                                                TR(STR_CANCEL), GTK_RESPONSE_CANCEL, TR(STR_TB_OPEN),
                                                GTK_RESPONSE_ACCEPT, NULL);
    add_filters(GTK_FILE_CHOOSER(fc));
    if (M.path) {
        char *d = g_path_get_dirname(M.path);
        gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(fc), d);
        g_free(d);
    }
    char *f = NULL;
    if (gtk_dialog_run(GTK_DIALOG(fc)) == GTK_RESPONSE_ACCEPT) f = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fc));
    gtk_widget_destroy(fc);
    if (f) mainwnd_open(f);
    g_free(f);
}

/* ======================================================================
 * extraction, test, view
 * ====================================================================== */

static char *arc_dir(void)
{
    return M.path ? g_path_get_dirname(M.path) : g_strdup(g_get_home_dir());
}

static void start_extract(const char *dest, int smart, int path_mode, int overwrite, const u8 *sel, int use_strip,
                          int test, int flags)
{
    gz_extract_opts xo;
    memset(&xo, 0, sizeof xo);
    gzch *wd = fs2w(dest), *ws = NULL;
    xo.dest = wd;
    xo.smart = smart;
    xo.path_mode = path_mode;
    if (use_strip && M.cur > 0 && path_mode == GZ_PATH_FULL) {
        ws = M.h->arc->f[M.cur].name;
        xo.path_mode = GZ_PATH_STRIP;
        xo.strip = ws;
    }
    xo.overwrite = overwrite;
    xo.sel = sel;
    xo.test = test;
    xo.threads = g_set.threads;
    run_extract(GTK_WINDOW(M.win), M.h, &xo, flags, NULL, NULL);
    gz_free(wd);
}

static void cmd_extract(int mode)
{
    if (!M.h || busy()) return;
    u32 nsel = 0;
    u8 *mask = selection_mask(&nsel, NULL);
    char *dir = arc_dir();
    if (mode == X_HERE || mode == X_SMART) {
        start_extract(dir, mode == X_SMART, GZ_PATH_FULL, g_set.overwrite, NULL, 0, 0, RUN_QUIET_OK);
    } else {
        xdlg_out o;
        if (dlg_extract(GTK_WINDOW(M.win), M.h, M.path ? M.path : dir, mode == X_SELECTED || nsel ? nsel : 0, &o)) {
            int sel = o.only_selected && mask;
            start_extract(o.dest, o.smart, o.path_mode, o.overwrite, sel ? mask : NULL, sel, 0,
                          RUN_QUIET_OK | (o.open_folder ? RUN_OPEN_DEST : 0));
            g_free(o.dest);
        }
    }
    g_free(dir);
    g_free(mask);
}

static void cmd_test(void)
{
    if (!M.h || busy()) return;
    start_extract("/", 0, GZ_PATH_FULL, GZ_OW_ALL, NULL, 0, 1, 0);
}

static void cmd_info(void)
{
    if (!M.h) return;
    dlg_info(GTK_WINDOW(M.win), M.h, M.path ? M.path : "");
}

typedef struct { char *dir, *name; } viewctx;

static void on_viewed(gz_run *r, int res, void *user)
{
    viewctx *v = user;
    if (res == GZ_OK) {
        char *p = g_build_filename(v->dir, v->name, NULL);
        if (!path_exists(p)) {          /* renamed by the engine (unsafe characters...): take what is there */
            GDir *d = g_dir_open(v->dir, 0, NULL);
            const char *n = d ? g_dir_read_name(d) : NULL;
            if (n) { g_free(p); p = g_build_filename(v->dir, n, NULL); }
            if (d) g_dir_close(d);
        }
        open_with_default(GTK_WINDOW(M.win), p);
        g_free(p);
    }
    g_free(v->dir);
    g_free(v->name);
    g_free(v);
}

static void view_entry(u32 idx)
{
    gz_archive *a = M.h->arc;
    const gz_entry *e = &a->e[idx];
    char *nm = w2fs(e->base);
    if (nm && is_archive_name(nm)) {
        gz_free(nm);
        run_open_child(GTK_WINDOW(M.win), M.h, idx, g_set.codepage, on_child_opened, NULL);
        return;
    }
    char *dir = temp_new_dir("v");
    if (!dir || !nm) { g_free(dir); gz_free(nm); return; }
    viewctx *v = g_new0(viewctx, 1);
    v->dir = dir;
    v->name = g_strdup(nm);
    gz_free(nm);
    u8 *m = g_malloc0(a->n + 1);
    m[idx] = 1;
    gz_extract_opts xo;
    memset(&xo, 0, sizeof xo);
    gzch *wd = fs2w(dir);
    xo.dest = wd;
    xo.path_mode = GZ_PATH_NONE;
    xo.overwrite = GZ_OW_ALL;
    xo.sel = m;
    xo.threads = 1;
    if (!run_extract(GTK_WINDOW(M.win), M.h, &xo, RUN_DELAY | RUN_QUIET_OK, on_viewed, v)) {
        g_free(v->dir);
        g_free(v->name);
        g_free(v);
    }
    gz_free(wd);
    g_free(m);
}

static void activate_row(guint i)
{
    if (!M.model || busy()) return;
    u32 n;
    const gz_lrow *r = gz_list_rows(M.model, &n);
    if (i >= n) return;
    gz_lrow row = r[i];
    if (row.kind == 0) navigate(M.h->arc->f[M.cur].parent, M.cur);
    else if (row.kind == 1) navigate(row.idx, -1);
    else view_entry((u32)row.idx);
}

static void on_row_activated(GtkTreeView *tv, GtkTreePath *p, GtkTreeViewColumn *c, gpointer u)
{
    activate_row((guint)gtk_tree_path_get_indices(p)[0]);
}

static void cmd_view(void)
{
    if (!M.h) return;
    GtkTreePath *p = NULL;
    gtk_tree_view_get_cursor(GTK_TREE_VIEW(M.list), &p, NULL);
    if (!p) return;
    guint i = (guint)gtk_tree_path_get_indices(p)[0];
    gtk_tree_path_free(p);
    activate_row(i);
}

static void set_codepage(int cp)
{
    if (!M.h) { g_set.codepage = cp; return; }
    if (busy()) return;
    gtk_tree_view_set_model(GTK_TREE_VIEW(M.list), NULL);
    gz_handle_set_codepage(M.h, cp);
    types_clear();
    show_archive();
}

/* ======================================================================
 * new archive
 * ====================================================================== */

void mainwnd_compress_paths(char **paths, int n)
{
    if (n <= 0 || busy()) return;
    cdlg_out o;
    if (!dlg_create(GTK_WINDOW(M.win), paths, n, &o)) return;
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
    co.encryption = wpw ? o.encryption : GZ_WE_NONE;
    co.password = wpw;
    co.encrypt_names = o.encrypt_names;
    co.solid = o.solid;
    co.threads = g_set.threads;
    co.overwrite = GZ_OW_ASK;
    run_compress(GTK_WINDOW(M.win), &co, RUN_QUIET_OK, NULL, NULL);
    for (int i = 0; i < n; i++) gz_free(in[i]);
    g_free(in);
    gz_free(wout);
    if (wpw) { memset(wpw, 0, gz_wcslen(wpw) * sizeof(gzch)); g_free(wpw); }
    cdlg_out_free(&o);
}

static void cmd_new(void)
{
    if (busy()) return;
    GtkWidget *fc = gtk_file_chooser_dialog_new(TR(STR_C_PICK_FILES), GTK_WINDOW(M.win), GTK_FILE_CHOOSER_ACTION_OPEN,
                                                TR(STR_CANCEL), GTK_RESPONSE_CANCEL, TR(STR_SELECT),
                                                GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(fc), TRUE);
    GSList *files = NULL;
    if (gtk_dialog_run(GTK_DIALOG(fc)) == GTK_RESPONSE_ACCEPT) files = gtk_file_chooser_get_filenames(GTK_FILE_CHOOSER(fc));
    gtk_widget_destroy(fc);
    int n = (int)g_slist_length(files), i = 0;
    if (n) {
        char **v = g_new0(char *, n + 1);
        for (GSList *l = files; l; l = l->next) v[i++] = l->data;
        mainwnd_compress_paths(v, n);
        g_free(v);
    }
    g_slist_free_full(files, g_free);
}

/* ======================================================================
 * drag and drop
 * ====================================================================== */

static const GtkTargetEntry k_uri_target[] = { { "text/uri-list", 0, 0 } };

static void on_drop(GtkWidget *w, GdkDragContext *ctx, gint x, gint y, GtkSelectionData *sd, guint info, guint t,
                    gpointer u)
{
    if (gtk_drag_get_source_widget(ctx) == M.list) { gtk_drag_finish(ctx, FALSE, FALSE, t); return; }
    char **uris = gtk_selection_data_get_uris(sd);
    GPtrArray *paths = g_ptr_array_new_with_free_func(g_free);
    for (int i = 0; uris && uris[i]; i++) {
        char *p = g_filename_from_uri(uris[i], NULL, NULL);
        if (p) g_ptr_array_add(paths, p);
    }
    g_strfreev(uris);
    gtk_drag_finish(ctx, paths->len > 0, FALSE, t);
    if (paths->len == 1 && !path_is_dir(g_ptr_array_index(paths, 0))) {
        const char *p = g_ptr_array_index(paths, 0);
        char *bn = g_path_get_basename(p);
        int arc = is_archive_name(bn);
        g_free(bn);
        if (arc) { mainwnd_open(p); g_ptr_array_free(paths, TRUE); return; }
    }
    if (paths->len) mainwnd_compress_paths((char **)paths->pdata, (int)paths->len);
    g_ptr_array_free(paths, TRUE);
}

/* drag out: extract the selection into a private temporary folder, hand over its paths */
static void on_drag_get(GtkWidget *w, GdkDragContext *ctx, GtkSelectionData *sd, guint info, guint t, gpointer u)
{
    char **uris = g_object_get_data(G_OBJECT(ctx), "gz-uris");
    if (!uris && M.h && !busy()) {
        u32 nrows = 0;
        GPtrArray *names = g_ptr_array_new();
        u8 *mask = selection_mask(&nrows, names);
        char *dir = mask ? temp_new_dir("d") : NULL;
        if (dir) {
            gz_extract_opts xo;
            memset(&xo, 0, sizeof xo);
            gzch *wd = fs2w(dir);
            xo.dest = wd;
            xo.path_mode = M.cur > 0 ? GZ_PATH_STRIP : GZ_PATH_FULL;
            xo.strip = M.cur > 0 ? M.h->arc->f[M.cur].name : NULL;
            xo.overwrite = GZ_OW_ALL;
            xo.sel = mask;
            xo.threads = g_set.threads;
            gz_run *r = run_extract(GTK_WINDOW(M.win), M.h, &xo, RUN_DELAY | RUN_QUIET_OK, NULL, NULL);
            gz_free(wd);
            int res = r ? run_wait(r) : GZ_E_NOMEM;
            if (res == GZ_OK || res == GZ_E_SKIP) {
                uris = g_new0(char *, names->len + 1);
                guint k = 0;
                for (guint i = 0; i < names->len; i++) {
                    char *fn = w2fs(g_ptr_array_index(names, i));
                    char *p = g_build_filename(dir, fn, NULL);
                    gz_free(fn);
                    if (path_exists(p)) uris[k++] = g_filename_to_uri(p, NULL, NULL);
                    g_free(p);
                }
                g_object_set_data_full(G_OBJECT(ctx), "gz-uris", uris, (GDestroyNotify)g_strfreev);
            }
            g_free(dir);
        }
        g_free(mask);
        g_ptr_array_free(names, TRUE);
    }
    if (uris) gtk_selection_data_set_uris(sd, uris);
}

/* ======================================================================
 * context menu, keys
 * ====================================================================== */

static void cb_view(void) { cmd_view(); }
static void cb_extract_dlg(void) { cmd_extract(X_DIALOG); }
static void cb_extract_sel(void) { cmd_extract(X_SELECTED); }
static void cb_extract_here(void) { cmd_extract(X_HERE); }
static void cb_extract_smart(void) { cmd_extract(X_SMART); }

static GtkWidget *menu_item(GtkWidget *menu, const char *text, GCallback cb, guint key, GdkModifierType mods)
{
    GtkWidget *mi = gtk_menu_item_new_with_mnemonic(text);
    if (cb) g_signal_connect_swapped(mi, "activate", cb, NULL);
    if (key && M.accel) gtk_widget_add_accelerator(mi, "activate", M.accel, key, mods, GTK_ACCEL_VISIBLE);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);
    return mi;
}

static void context_menu(GdkEvent *ev)
{
    GtkWidget *m = gtk_menu_new();
    menu_item(m, TR(STR_M_OPENITEM), G_CALLBACK(cb_view), 0, 0);
    gtk_menu_shell_append(GTK_MENU_SHELL(m), gtk_separator_menu_item_new());
    menu_item(m, TR(STR_M_EXTRACT_SEL), G_CALLBACK(cb_extract_sel), 0, 0);
    menu_item(m, TR(STR_M_EXTRACT), G_CALLBACK(cb_extract_dlg), 0, 0);
    menu_item(m, TR(STR_M_EXTRACT_SMART), G_CALLBACK(cb_extract_smart), 0, 0);
    gtk_menu_shell_append(GTK_MENU_SHELL(m), gtk_separator_menu_item_new());
    menu_item(m, TR(STR_M_TEST), G_CALLBACK(cmd_test), 0, 0);
    menu_item(m, TR(STR_M_INFO), G_CALLBACK(cmd_info), 0, 0);
    gtk_widget_show_all(m);
    g_signal_connect(m, "deactivate", G_CALLBACK(gtk_widget_destroy), NULL);
    gtk_menu_attach_to_widget(GTK_MENU(m), M.list, NULL);
    gtk_menu_popup_at_pointer(GTK_MENU(m), ev);
}

static gboolean on_list_button(GtkWidget *w, GdkEventButton *e, gpointer u)
{
    if (e->type != GDK_BUTTON_PRESS || e->button != 3 || !M.h) return FALSE;
    GtkTreePath *p = NULL;
    if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(M.list), (gint)e->x, (gint)e->y, &p, NULL, NULL, NULL)) {
        GtkTreeSelection *s = gtk_tree_view_get_selection(GTK_TREE_VIEW(M.list));
        if (!gtk_tree_selection_path_is_selected(s, p)) {
            gtk_tree_selection_unselect_all(s);
            gtk_tree_view_set_cursor(GTK_TREE_VIEW(M.list), p, NULL, FALSE);
        }
        gtk_tree_path_free(p);
    }
    context_menu((GdkEvent *)e);
    return TRUE;
}

static gboolean on_list_key(GtkWidget *w, GdkEventKey *e, gpointer u)
{
    if (e->keyval == GDK_KEY_BackSpace || (e->keyval == GDK_KEY_Up && (e->state & GDK_MOD1_MASK))) {
        cmd_up();
        return TRUE;
    }
    if (e->keyval == GDK_KEY_Menu) { context_menu((GdkEvent *)e); return TRUE; }
    return FALSE;
}

/* ======================================================================
 * code page menu
 * ====================================================================== */

static void on_cp_item(GtkCheckMenuItem *mi, gpointer u)
{
    if (gtk_check_menu_item_get_active(mi)) set_codepage(GPOINTER_TO_INT(u));
}

static GtkWidget *cp_menu(void)
{
    GtkWidget *m = gtk_menu_new();
    GSList *grp = NULL;
    int cur = M.h ? M.h->arc->codepage : g_set.codepage;
    for (u32 i = 0; i < gz_ui_ncodepages; i++) {
        int cp = gz_ui_codepages[i].cp;
        if (cp && !gz_plat_cp_valid(cp)) continue;
        char t[96];
        if (M.h && !cp && M.h->arc->any_legacy && gz_ui_cp_name(M.h->arc->used_cp))
            g_snprintf(t, sizeof t, "%s - %s", TR(STR_CP_AUTO), gz_ui_cp_name(M.h->arc->used_cp));
        else
            g_strlcpy(t, TR(gz_ui_codepages[i].sid), sizeof t);
        GtkWidget *mi = gtk_radio_menu_item_new_with_label(grp, t);
        grp = gtk_radio_menu_item_get_group(GTK_RADIO_MENU_ITEM(mi));
        if (cp == cur) gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(mi), TRUE);
        g_signal_connect(mi, "toggled", G_CALLBACK(on_cp_item), GINT_TO_POINTER(cp));
        gtk_menu_shell_append(GTK_MENU_SHELL(m), mi);
        if (!i) gtk_menu_shell_append(GTK_MENU_SHELL(m), gtk_separator_menu_item_new());
    }
    gtk_widget_show_all(m);
    g_signal_connect(m, "deactivate", G_CALLBACK(gtk_widget_destroy), NULL);
    return m;
}

static void cmd_codepage(GtkWidget *anchor)
{
    if (!M.h) return;
    GtkWidget *m = cp_menu();
    gtk_menu_attach_to_widget(GTK_MENU(m), M.win, NULL);
    if (anchor) gtk_menu_popup_at_widget(GTK_MENU(m), anchor, GDK_GRAVITY_SOUTH_WEST, GDK_GRAVITY_NORTH_WEST, NULL);
    else gtk_menu_popup_at_pointer(GTK_MENU(m), NULL);
}

/* ======================================================================
 * welcome screen
 * ====================================================================== */

static void on_recent(GtkButton *b, gpointer u)
{
    const char *p = g_object_get_data(G_OBJECT(b), "gz-path");
    if (p) {
        char *c = g_strdup(p);
        mainwnd_open(c);
        g_free(c);
    }
}

static void rebuild_recent(void)
{
    if (!M.recent_box) return;
    GList *ch = gtk_container_get_children(GTK_CONTAINER(M.recent_box));
    for (GList *l = ch; l; l = l->next) gtk_widget_destroy(l->data);
    g_list_free(ch);
    int any = 0;
    for (int i = 0; i < GZ_RECENT_MAX && any < 6; i++) {
        const char *p = g_set.recent[i];
        if (!p || !path_exists(p)) continue;
        any++;
        GtkWidget *b = gtk_button_new();
        gtk_button_set_relief(GTK_BUTTON(b), GTK_RELIEF_NONE);
        gtk_style_context_add_class(gtk_widget_get_style_context(b), "gz-recent");
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        char *bn = g_path_get_basename(p), *dn = g_path_get_dirname(p);
        char *ubn = disp_path(bn), *udn = disp_path(dn);
        gzch *wb = fs2w(bn);
        GIcon *ic = NULL;
        type_desc(wb ? wb : u"", &ic);
        gz_free(wb);
        gtk_box_pack_start(GTK_BOX(row), gtk_image_new_from_gicon(ic, GTK_ICON_SIZE_MENU), FALSE, FALSE, 0);
        GtkWidget *nl = gtk_label_new(ubn);
        gtk_label_set_ellipsize(GTK_LABEL(nl), PANGO_ELLIPSIZE_MIDDLE);
        gtk_box_pack_start(GTK_BOX(row), nl, FALSE, FALSE, 0);
        GtkWidget *dl = gtk_label_new(udn);
        gtk_label_set_ellipsize(GTK_LABEL(dl), PANGO_ELLIPSIZE_START);
        gtk_label_set_xalign(GTK_LABEL(dl), 0);
        gtk_style_context_add_class(gtk_widget_get_style_context(dl), "gz-faint");
        gtk_box_pack_start(GTK_BOX(row), dl, TRUE, TRUE, 0);
        gtk_container_add(GTK_CONTAINER(b), row);
        g_object_set_data_full(G_OBJECT(b), "gz-path", g_strdup(p), g_free);
        g_signal_connect(b, "clicked", G_CALLBACK(on_recent), NULL);
        gtk_box_pack_start(GTK_BOX(M.recent_box), b, FALSE, FALSE, 0);
        g_free(bn);
        g_free(dn);
        g_free(ubn);
        g_free(udn);
    }
    gtk_widget_set_visible(M.recent_title, any > 0);
    gtk_widget_show_all(M.recent_box);
}

static GtkWidget *centered_label(const char *t, const char *cls)
{
    GtkWidget *l = gtk_label_new(t);
    gtk_label_set_justify(GTK_LABEL(l), GTK_JUSTIFY_CENTER);
    if (cls) gtk_style_context_add_class(gtk_widget_get_style_context(l), cls);
    return l;
}

static GtkWidget *build_welcome(void)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(outer), "gz-welcome");
    GtkWidget *v = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_halign(v, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(v, GTK_ALIGN_CENTER);
    gtk_widget_set_vexpand(v, TRUE);
    gtk_widget_set_size_request(v, 520, -1);
    gtk_box_pack_start(GTK_BOX(v), icon_image(IC_LOGO, 88), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v), centered_label(TR(STR_APP), "gz-title"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v), centered_label(TR(STR_TAGLINE), "gz-dim"), FALSE, FALSE, 0);

    GtkWidget *dz = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    M.dropzone = dz;
    gtk_style_context_add_class(gtk_widget_get_style_context(dz), "gz-dropzone");
    gtk_widget_set_margin_top(dz, 18);
    gtk_box_pack_start(GTK_BOX(dz), centered_label(TR(STR_W_DROP), "gz-dz-title"), FALSE, FALSE, 0);
    /* readable formats: the best known first, then a count of the others */
    static const char *const known[] = { "ZIP", "7z", "RAR", "RAR5", "TAR", "GZIP", "BZIP2", "XZ", "ZSTD", "ISO",
                                         "CAB", "LZ4", "WIM", "DMG", 0 };
    GString *fl = g_string_new(NULL);
    int nf = 0, shown = 0;
    while (gz_formats[nf]) nf++;
    for (int k = 0; known[k] && shown < 9; k++)
        for (int i = 0; i < nf; i++)
            if (!g_ascii_strcasecmp(gz_formats[i]->name, known[k])) {
                if (shown++) g_string_append(fl, " · ");
                g_string_append(fl, gz_formats[i]->name);
                break;
            }
    for (int i = 0; i < nf && shown < 9; i++) {
        int dup = 0;
        for (int k = 0; known[k]; k++) dup |= !g_ascii_strcasecmp(gz_formats[i]->name, known[k]);
        if (dup || (gz_formats[i]->flags & GZ_FMT_WEAK)) continue;
        if (shown++) g_string_append(fl, " · ");
        g_string_append(fl, gz_formats[i]->name);
    }
    if (nf > shown) {
        char c[16], m[64];
        g_snprintf(c, sizeof c, "%d", nf - shown);
        GZ_UI_FMT(m, sizeof m, STR_W_MORE, c);
        g_string_append_printf(fl, "  ·  %s", m);
    }
    GtkWidget *fmts = centered_label(fl->str, "gz-faint");
    gtk_label_set_line_wrap(GTK_LABEL(fmts), TRUE);
    gtk_box_pack_start(GTK_BOX(dz), fmts, FALSE, FALSE, 0);
    g_string_free(fl, TRUE);
    gtk_box_pack_start(GTK_BOX(dz), centered_label(TR(STR_W_DROP2), "gz-faint"), FALSE, FALSE, 0);
    GtkWidget *bb = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign(bb, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top(bb, 12);
    GtkWidget *ob = gtk_button_new_with_label(TR(STR_W_OPEN));
    gtk_style_context_add_class(gtk_widget_get_style_context(ob), "gz-accent");
    gtk_style_context_add_class(gtk_widget_get_style_context(ob), "gz-big");
    g_signal_connect_swapped(ob, "clicked", G_CALLBACK(cmd_open), NULL);
    GtkWidget *nb = gtk_button_new_with_label(TR(STR_W_NEW));
    gtk_style_context_add_class(gtk_widget_get_style_context(nb), "gz-big");
    g_signal_connect_swapped(nb, "clicked", G_CALLBACK(cmd_new), NULL);
    gtk_box_pack_start(GTK_BOX(bb), ob, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bb), nb, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(dz), bb, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v), dz, FALSE, FALSE, 0);

    M.recent_title = gtk_label_new(TR(STR_W_RECENT));
    gtk_label_set_xalign(GTK_LABEL(M.recent_title), 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(M.recent_title), "gz-dim");
    gtk_widget_set_margin_top(M.recent_title, 18);
    gtk_box_pack_start(GTK_BOX(v), M.recent_title, FALSE, FALSE, 0);
    M.recent_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_pack_start(GTK_BOX(v), M.recent_box, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(outer), v, TRUE, TRUE, 0);

    char e[256], th[16], tl[64];
    g_snprintf(th, sizeof th, "%d", gz_os_cpu_count());
    GZ_UI_FMT(tl, sizeof tl, STR_THREADS, th);
    g_snprintf(e, sizeof e, "%s:  %s  ·  %s", TR(STR_W_ENGINE), engine_line(), tl);
    GtkWidget *el = centered_label(e, "gz-faint");
    gtk_widget_set_margin_bottom(el, 10);
    gtk_box_pack_end(GTK_BOX(outer), el, FALSE, FALSE, 0);
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw), outer);
    return sw;
}

/* ======================================================================
 * building the window
 * ====================================================================== */

static GtkWidget *build_list(void)
{
    M.list = gtk_tree_view_new();
    GtkTreeView *tv = GTK_TREE_VIEW(M.list);
    static const int titles[LC_COUNT] = { 0, STR_COL_NAME, STR_COL_SIZE, STR_COL_PACKED, STR_COL_TYPE, STR_COL_MTIME,
                                          STR_COL_RATIO, STR_COL_METHOD, STR_COL_CRC };
    static const int widths[LC_COUNT] = { 0, 270, 88, 88, 130, 128, 60, 100, 82 };
    for (int c = LC_NAME; c < LC_COUNT; c++) {
        GtkTreeViewColumn *col = gtk_tree_view_column_new();
        gtk_tree_view_column_set_title(col, TR(titles[c]));
        if (c == LC_NAME) {
            GtkCellRenderer *ir = gtk_cell_renderer_pixbuf_new();
            gtk_tree_view_column_pack_start(col, ir, FALSE);
            gtk_tree_view_column_add_attribute(col, ir, "gicon", LC_ICON);
        }
        GtkCellRenderer *r = gtk_cell_renderer_text_new();
        if (c == LC_SIZE || c == LC_PACKED || c == LC_RATIO) {
            g_object_set(r, "xalign", 1.0f, NULL);
            gtk_tree_view_column_set_alignment(col, 1.0f);
        }
        if (c == LC_NAME || c == LC_TYPE || c == LC_METHOD) g_object_set(r, "ellipsize", PANGO_ELLIPSIZE_END, NULL);
        if (c == LC_CRC) g_object_set(r, "family", "monospace", NULL);
        gtk_tree_view_column_pack_start(col, r, TRUE);
        gtk_tree_view_column_add_attribute(col, r, "text", c);
        gtk_tree_view_column_set_sizing(col, GTK_TREE_VIEW_COLUMN_FIXED);
        gtk_tree_view_column_set_fixed_width(col, widths[c]);
        gtk_tree_view_column_set_resizable(col, TRUE);
        gtk_tree_view_column_set_clickable(col, TRUE);
        g_signal_connect(col, "clicked", G_CALLBACK(on_col_clicked), GINT_TO_POINTER(c));
        gtk_tree_view_append_column(tv, col);
        M.cols[c] = col;
    }
    M.sort_col = LC_NAME;
    gtk_tree_view_column_set_sort_indicator(M.cols[LC_NAME], TRUE);
    gtk_tree_view_set_fixed_height_mode(tv, TRUE);
    gtk_tree_view_set_enable_search(tv, TRUE);
    gtk_tree_view_set_search_column(tv, LC_NAME);
    gtk_tree_view_set_rubber_banding(tv, TRUE);
    GtkTreeSelection *s = gtk_tree_view_get_selection(tv);
    gtk_tree_selection_set_mode(s, GTK_SELECTION_MULTIPLE);
    g_signal_connect(s, "changed", G_CALLBACK(on_list_sel), NULL);
    g_signal_connect(M.list, "row-activated", G_CALLBACK(on_row_activated), NULL);
    g_signal_connect(M.list, "button-press-event", G_CALLBACK(on_list_button), NULL);
    g_signal_connect(M.list, "key-press-event", G_CALLBACK(on_list_key), NULL);
    gtk_tree_view_enable_model_drag_source(tv, GDK_BUTTON1_MASK, k_uri_target, 1, GDK_ACTION_COPY);
    g_signal_connect(M.list, "drag-data-get", G_CALLBACK(on_drag_get), NULL);
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sw), M.list);
    return sw;
}

static GtkWidget *build_tree(void)
{
    M.tree = gtk_tree_view_new();
    GtkTreeView *tv = GTK_TREE_VIEW(M.tree);
    gtk_tree_view_set_headers_visible(tv, FALSE);
    GtkTreeViewColumn *col = gtk_tree_view_column_new();
    GtkCellRenderer *ir = gtk_cell_renderer_pixbuf_new(), *tr = gtk_cell_renderer_text_new();
    gtk_tree_view_column_pack_start(col, ir, FALSE);
    gtk_tree_view_column_add_attribute(col, ir, "gicon", TC_ICON);
    gtk_tree_view_column_pack_start(col, tr, TRUE);
    gtk_tree_view_column_add_attribute(col, tr, "text", TC_NAME);
    gtk_tree_view_append_column(tv, col);
    gtk_tree_view_set_enable_search(tv, FALSE);
    g_signal_connect(M.tree, "test-expand-row", G_CALLBACK(on_test_expand), NULL);
    g_signal_connect(gtk_tree_view_get_selection(tv), "changed", G_CALLBACK(on_tree_sel), NULL);
    M.tree_sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(M.tree_sw), M.tree);
    return M.tree_sw;
}

static void cb_open(void) { cmd_open(); }
static void cb_new(void) { cmd_new(); }
static void cb_close(void) { cmd_close(); }
static void cb_back(void) { cmd_back(); }
static void cb_quit(void) { gtk_window_close(GTK_WINDOW(M.win)); }
static void cb_test(void) { cmd_test(); }
static void cb_info(void) { cmd_info(); }
static void cb_up(void) { cmd_up(); }
static void cb_selall(void) { if (M.h) gtk_tree_selection_select_all(gtk_tree_view_get_selection(GTK_TREE_VIEW(M.list))); }
static void cb_settings(void) { dlg_settings(GTK_WINDOW(M.win)); }
static void cb_about(void) { dlg_about(GTK_WINDOW(M.win)); }
static void cb_home(void) { gtk_show_uri_on_window(GTK_WINDOW(M.win), GZ_HOMEPAGE, GDK_CURRENT_TIME, NULL); }
static void cb_cp_menu(void) { cmd_codepage(NULL); }

static void on_tree_toggle(GtkCheckMenuItem *mi, gpointer u)
{
    g_set.show_tree = gtk_check_menu_item_get_active(mi);
    gtk_widget_set_visible(M.tree_sw, g_set.show_tree);
}

static void on_recent_mi(GtkMenuItem *mi, gpointer u)
{
    const char *p = g_object_get_data(G_OBJECT(mi), "gz-path");
    if (p) { char *c = g_strdup(p); mainwnd_open(c); g_free(c); }
}

static void fill_recent_menu(GtkWidget *menuitem, gpointer u)
{
    GtkWidget *m = gtk_menu_item_get_submenu(GTK_MENU_ITEM(M.menu_recent));
    GList *ch = gtk_container_get_children(GTK_CONTAINER(m));
    for (GList *l = ch; l; l = l->next) gtk_widget_destroy(l->data);
    g_list_free(ch);
    int any = 0;
    for (int i = 0; i < GZ_RECENT_MAX; i++) {
        if (!g_set.recent[i]) continue;
        char *d = disp_path(g_set.recent[i]);
        char t[64];
        g_snprintf(t, sizeof t, "_%d  ", ++any);
        char *lab = g_strconcat(t, d, NULL);
        GtkWidget *mi = gtk_menu_item_new_with_mnemonic(lab);
        g_object_set_data_full(G_OBJECT(mi), "gz-path", g_strdup(g_set.recent[i]), g_free);
        g_signal_connect(mi, "activate", G_CALLBACK(on_recent_mi), NULL);
        gtk_menu_shell_append(GTK_MENU_SHELL(m), mi);
        g_free(lab);
        g_free(d);
    }
    if (!any) {
        GtkWidget *mi = gtk_menu_item_new_with_label(TR(STR_M_NORECENT));
        gtk_widget_set_sensitive(mi, FALSE);
        gtk_menu_shell_append(GTK_MENU_SHELL(m), mi);
    }
    gtk_widget_show_all(m);
}

static GtkWidget *submenu(GtkWidget *bar, const char *title)
{
    GtkWidget *top = gtk_menu_item_new_with_mnemonic(title);
    GtkWidget *m = gtk_menu_new();
    gtk_menu_set_accel_group(GTK_MENU(m), M.accel);
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(top), m);
    gtk_menu_shell_append(GTK_MENU_SHELL(bar), top);
    return m;
}

static void sep(GtkWidget *m) { gtk_menu_shell_append(GTK_MENU_SHELL(m), gtk_separator_menu_item_new()); }

static GtkWidget *build_menu(void)
{
    GtkWidget *bar = gtk_menu_bar_new();
    GtkWidget *m = submenu(bar, TR(STR_M_FILE));
    menu_item(m, TR(STR_M_OPEN), G_CALLBACK(cb_open), GDK_KEY_o, GDK_CONTROL_MASK);
    menu_item(m, TR(STR_M_NEW), G_CALLBACK(cb_new), GDK_KEY_n, GDK_CONTROL_MASK);
    M.menu_recent = menu_item(m, TR(STR_M_RECENT), NULL, 0, 0);
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(M.menu_recent), gtk_menu_new());
    g_signal_connect(m, "show", G_CALLBACK(fill_recent_menu), NULL);
    sep(m);
    M.mi_back = menu_item(m, TR(STR_M_BACK), G_CALLBACK(cb_back), 0, 0);
    need_arc(menu_item(m, TR(STR_M_CLOSE), G_CALLBACK(cb_close), GDK_KEY_w, GDK_CONTROL_MASK));
    need_arc(menu_item(m, TR(STR_M_INFO), G_CALLBACK(cb_info), GDK_KEY_Return, GDK_MOD1_MASK));
    sep(m);
    menu_item(m, TR(STR_M_QUIT), G_CALLBACK(cb_quit), 0, 0);

    m = submenu(bar, TR(STR_M_ACTION));
    need_arc(menu_item(m, TR(STR_M_EXTRACT), G_CALLBACK(cb_extract_dlg), GDK_KEY_e, GDK_CONTROL_MASK));
    need_arc(menu_item(m, TR(STR_M_EXTRACT_HERE), G_CALLBACK(cb_extract_here), 0, 0));
    need_arc(menu_item(m, TR(STR_M_EXTRACT_SMART), G_CALLBACK(cb_extract_smart), GDK_KEY_q, GDK_CONTROL_MASK));
    need_arc(menu_item(m, TR(STR_M_EXTRACT_SEL), G_CALLBACK(cb_extract_sel), 0, 0));
    sep(m);
    need_arc(menu_item(m, TR(STR_M_TEST), G_CALLBACK(cb_test), GDK_KEY_t, GDK_CONTROL_MASK));

    m = submenu(bar, TR(STR_M_VIEW));
    need_arc(menu_item(m, TR(STR_M_OPENITEM), G_CALLBACK(cmd_view), 0, 0));
    need_arc(menu_item(m, TR(STR_M_UP), G_CALLBACK(cb_up), 0, 0));
    sep(m);
    M.mi_tree = gtk_check_menu_item_new_with_mnemonic(TR(STR_M_TREE));
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(M.mi_tree), g_set.show_tree);
    g_signal_connect(M.mi_tree, "toggled", G_CALLBACK(on_tree_toggle), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(m), M.mi_tree);
    need_arc(menu_item(m, TR(STR_M_SELECTALL), G_CALLBACK(cb_selall), GDK_KEY_a, GDK_CONTROL_MASK));
    need_arc(menu_item(m, TR(STR_M_CODEPAGE), G_CALLBACK(cb_cp_menu), 0, 0));

    m = submenu(bar, TR(STR_M_OPTIONS));
    menu_item(m, TR(STR_M_SETTINGS), G_CALLBACK(cb_settings), 0, 0);

    m = submenu(bar, TR(STR_M_HELP));
    menu_item(m, TR(STR_M_HOMEPAGE), G_CALLBACK(cb_home), 0, 0);
    menu_item(m, TR(STR_M_ABOUT), G_CALLBACK(cb_about), GDK_KEY_F1, 0);
    return bar;
}

static GtkToolItem *tool(GtkWidget *tb, int icon, int sid, int tip, GCallback cb, int needs)
{
    GtkToolItem *t = gtk_tool_button_new(icon_image(icon, 32), TR(sid));
    gtk_tool_item_set_tooltip_text(t, TR(tip));
    gtk_tool_item_set_is_important(t, TRUE);
    if (cb) g_signal_connect_swapped(t, "clicked", cb, NULL);
    gtk_toolbar_insert(GTK_TOOLBAR(tb), t, -1);
    if (needs) need_arc(GTK_WIDGET(t));
    return t;
}

static void on_cp_tool(GtkToolButton *b, gpointer u) { cmd_codepage(GTK_WIDGET(b)); }

static GtkWidget *build_toolbar(void)
{
    GtkWidget *tb = gtk_toolbar_new();
    gtk_toolbar_set_style(GTK_TOOLBAR(tb), GTK_TOOLBAR_BOTH);
    gtk_style_context_add_class(gtk_widget_get_style_context(tb), "gz-toolbar");
    tool(tb, IC_OPEN, STR_TB_OPEN, STR_TT_OPEN, G_CALLBACK(cb_open), 0);
    GtkToolItem *x = gtk_menu_tool_button_new(icon_image(IC_EXTRACT, 32), TR(STR_TB_EXTRACT));
    gtk_tool_item_set_tooltip_text(x, TR(STR_TT_EXTRACT));
    gtk_tool_item_set_is_important(x, TRUE);
    g_signal_connect_swapped(x, "clicked", G_CALLBACK(cb_extract_dlg), NULL);
    GtkWidget *xm = gtk_menu_new();
    GtkWidget *mi = gtk_menu_item_new_with_mnemonic(TR(STR_M_EXTRACT_HERE));
    g_signal_connect_swapped(mi, "activate", G_CALLBACK(cb_extract_here), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(xm), mi);
    mi = gtk_menu_item_new_with_mnemonic(TR(STR_M_EXTRACT_SMART));
    g_signal_connect_swapped(mi, "activate", G_CALLBACK(cb_extract_smart), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(xm), mi);
    mi = gtk_menu_item_new_with_mnemonic(TR(STR_M_EXTRACT_SEL));
    g_signal_connect_swapped(mi, "activate", G_CALLBACK(cb_extract_sel), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(xm), mi);
    gtk_widget_show_all(xm);
    gtk_menu_tool_button_set_menu(GTK_MENU_TOOL_BUTTON(x), xm);
    gtk_toolbar_insert(GTK_TOOLBAR(tb), x, -1);
    need_arc(GTK_WIDGET(x));
    tool(tb, IC_NEW, STR_TB_NEW, STR_TT_NEW, G_CALLBACK(cb_new), 0);
    gtk_toolbar_insert(GTK_TOOLBAR(tb), gtk_separator_tool_item_new(), -1);
    tool(tb, IC_TEST, STR_TB_TEST, STR_TT_TEST, G_CALLBACK(cb_test), 1);
    tool(tb, IC_INFO, STR_TB_INFO, STR_TT_INFO, G_CALLBACK(cb_info), 1);
    gtk_toolbar_insert(GTK_TOOLBAR(tb), gtk_separator_tool_item_new(), -1);
    GtkToolItem *cp = tool(tb, IC_CODEPAGE, STR_TB_CODEPAGE, STR_TT_CODEPAGE, NULL, 1);
    g_signal_connect(cp, "clicked", G_CALLBACK(on_cp_tool), NULL);
    tool(tb, IC_SETTINGS, STR_TB_SETTINGS, STR_TT_SETTINGS, G_CALLBACK(cb_settings), 0);
    return tb;
}

static gboolean on_delete(GtkWidget *w, GdkEvent *e, gpointer u)
{
    if (busy()) return TRUE;                 /* a job is running: cancel it first */
    GdkWindow *gw = gtk_widget_get_window(w);
    g_set.win_max = gw && (gdk_window_get_state(gw) & GDK_WINDOW_STATE_MAXIMIZED);
    if (!g_set.win_max) gtk_window_get_size(GTK_WINDOW(w), &g_set.win_w, &g_set.win_h);
    if (M.tree_sw && gtk_widget_get_visible(M.tree_sw)) g_set.pane = gtk_paned_get_position(GTK_PANED(M.paned));
    settings_save();
    return FALSE;
}

static void on_destroy(GtkWidget *w, gpointer u)
{
    close_all();
    M.win = NULL;
    gtk_main_quit();
}

GtkWidget *mainwnd_create(void)
{
    M.needs_arc = g_ptr_array_new();
    M.win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(M.win), TR(STR_APP));
    gtk_window_set_default_size(GTK_WINDOW(M.win), g_set.win_w, g_set.win_h);
    if (g_set.win_max) gtk_window_maximize(GTK_WINDOW(M.win));
    M.accel = gtk_accel_group_new();
    gtk_window_add_accel_group(GTK_WINDOW(M.win), M.accel);
    g_signal_connect(M.win, "delete-event", G_CALLBACK(on_delete), NULL);
    g_signal_connect(M.win, "destroy", G_CALLBACK(on_destroy), NULL);

    GtkWidget *v = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(M.win), v);
    gtk_box_pack_start(GTK_BOX(v), build_menu(), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v), build_toolbar(), FALSE, FALSE, 0);

    M.stack = gtk_stack_new();
    gtk_stack_add_named(GTK_STACK(M.stack), build_welcome(), "welcome");
    GtkWidget *bv = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *pb = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(pb), "gz-pathbar");
    M.up_btn = gtk_button_new();
    gtk_button_set_image(GTK_BUTTON(M.up_btn), icon_image(IC_UP, 16));
    gtk_button_set_relief(GTK_BUTTON(M.up_btn), GTK_RELIEF_NONE);
    gtk_widget_set_tooltip_text(M.up_btn, TR(STR_TT_UP));
    g_signal_connect_swapped(M.up_btn, "clicked", G_CALLBACK(cb_up), NULL);
    gtk_box_pack_start(GTK_BOX(pb), M.up_btn, FALSE, FALSE, 0);
    M.crumbs = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(M.crumbs), "gz-crumbs");
    gtk_box_pack_start(GTK_BOX(pb), M.crumbs, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(bv), pb, FALSE, FALSE, 0);
    M.paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_pack1(GTK_PANED(M.paned), build_tree(), FALSE, TRUE);
    gtk_paned_pack2(GTK_PANED(M.paned), build_list(), TRUE, TRUE);
    gtk_paned_set_position(GTK_PANED(M.paned), g_set.pane);
    gtk_box_pack_start(GTK_BOX(bv), M.paned, TRUE, TRUE, 0);
    gtk_stack_add_named(GTK_STACK(M.stack), bv, "browse");
    gtk_box_pack_start(GTK_BOX(v), M.stack, TRUE, TRUE, 0);

    GtkWidget *st = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(st), "gz-status");
    M.st_left = gtk_label_new(TR(STR_ST_READY));
    gtk_label_set_xalign(GTK_LABEL(M.st_left), 0);
    gtk_label_set_ellipsize(GTK_LABEL(M.st_left), PANGO_ELLIPSIZE_END);
    gtk_box_pack_start(GTK_BOX(st), M.st_left, TRUE, TRUE, 0);
    char e[128], th[16];
    g_snprintf(th, sizeof th, "%d", settings_threads());
    GZ_UI_FMT(e, sizeof e, STR_ST_ENGINE, gz_dispatch_inflate_name(), th);
    M.st_right = gtk_label_new(e);
    gtk_style_context_add_class(gtk_widget_get_style_context(M.st_right), "gz-dim");
    gtk_box_pack_end(GTK_BOX(st), M.st_right, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(st), icon_image(IC_CPU, 16), FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(v), st, FALSE, FALSE, 0);

    gtk_drag_dest_set(M.win, GTK_DEST_DEFAULT_ALL, k_uri_target, 1, GDK_ACTION_COPY | GDK_ACTION_MOVE | GDK_ACTION_LINK);
    g_signal_connect(M.win, "drag-data-received", G_CALLBACK(on_drop), NULL);

    gtk_widget_show_all(M.win);
    gtk_widget_set_visible(M.tree_sw, g_set.show_tree);
    show_archive();
    return M.win;
}
