/*
 * 고깃ZIP GTK - dialogs
 *
 * Same layout as the Windows dialogs: a header (icon, title, subtitle), the
 * content, and a footer with the main action in the accent color. Option
 * dialogs are modal (gtk_dialog_run); questions asked by a running job are
 * non-blocking and answer through a callback (see run.c).
 */
#include "app.h"
#include "mimetypes.h"
#include <gio/gdesktopappinfo.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---------------- common pieces ---------------- */

static GtkWidget *lbl(const char *t, const char *cls)
{
    GtkWidget *l = gtk_label_new(t);
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    if (cls) gtk_style_context_add_class(gtk_widget_get_style_context(l), cls);
    return l;
}

static GtkWidget *bold(const char *t)
{
    GtkWidget *l = gtk_label_new(NULL);
    char *m = g_markup_printf_escaped("<b>%s</b>", t);
    gtk_label_set_markup(GTK_LABEL(l), m);
    g_free(m);
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    return l;
}

static void accent(GtkWidget *b)
{
    gtk_style_context_add_class(gtk_widget_get_style_context(b), "gz-accent");
}

/* dialog with a header; returns the body box */
static GtkWidget *dlg_new(GtkWindow *parent, const char *title, int icon, const char *head, const char *sub,
                          GtkWidget **body)
{
    GtkWidget *d = g_object_new(GTK_TYPE_DIALOG, "use-header-bar", FALSE, NULL);
    gtk_window_set_title(GTK_WINDOW(d), title);
    gtk_style_context_add_class(gtk_widget_get_style_context(d), "gz-dialog");
    if (parent) {
        gtk_window_set_transient_for(GTK_WINDOW(d), parent);
        gtk_window_set_modal(GTK_WINDOW(d), TRUE);
        gtk_window_set_destroy_with_parent(GTK_WINDOW(d), TRUE);
        gtk_window_set_position(GTK_WINDOW(d), GTK_WIN_POS_CENTER_ON_PARENT);
    } else {
        gtk_window_set_position(GTK_WINDOW(d), GTK_WIN_POS_CENTER);
    }
    gtk_window_set_resizable(GTK_WINDOW(d), FALSE);
    GtkWidget *ca = gtk_dialog_get_content_area(GTK_DIALOG(d));
    gtk_container_set_border_width(GTK_CONTAINER(ca), 0);
    gtk_box_set_spacing(GTK_BOX(ca), 0);
    GtkWidget *h = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_style_context_add_class(gtk_widget_get_style_context(h), "gz-dlg-head");
    gtk_box_pack_start(GTK_BOX(h), icon_image(icon, 32), FALSE, FALSE, 0);
    GtkWidget *hv = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_box_pack_start(GTK_BOX(hv), lbl(head, "gz-dlg-title"), FALSE, FALSE, 0);
    if (sub && *sub) {
        GtkWidget *s = lbl(sub, "gz-dim");
        gtk_label_set_ellipsize(GTK_LABEL(s), PANGO_ELLIPSIZE_MIDDLE);
        gtk_label_set_max_width_chars(GTK_LABEL(s), 64);
        gtk_box_pack_start(GTK_BOX(hv), s, FALSE, FALSE, 0);
    }
    gtk_box_pack_start(GTK_BOX(h), hv, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(ca), h, FALSE, FALSE, 0);
    GtkWidget *b = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_style_context_add_class(gtk_widget_get_style_context(b), "gz-dlg-body");
    gtk_box_pack_start(GTK_BOX(ca), b, TRUE, TRUE, 0);
    *body = b;
    return d;
}

static GtkWidget *add_btn(GtkWidget *d, const char *t, int resp, int primary)
{
    GtkWidget *b = gtk_dialog_add_button(GTK_DIALOG(d), t, resp);
    gtk_widget_set_size_request(b, 96, -1);
    if (primary) {
        accent(b);
        gtk_dialog_set_default_response(GTK_DIALOG(d), resp);
        gtk_widget_set_can_default(b, TRUE);
        gtk_widget_grab_default(b);
    }
    return b;
}

static char *pick_folder(GtkWindow *parent, const char *title, const char *start)
{
    GtkWidget *fc = gtk_file_chooser_dialog_new(title, parent, GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
                                                TR(STR_CANCEL), GTK_RESPONSE_CANCEL, TR(STR_SELECT),
                                                GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_local_only(GTK_FILE_CHOOSER(fc), TRUE);
    gtk_file_chooser_set_create_folders(GTK_FILE_CHOOSER(fc), TRUE);
    if (start && path_is_dir(start)) gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(fc), start);
    char *r = NULL;
    if (gtk_dialog_run(GTK_DIALOG(fc)) == GTK_RESPONSE_ACCEPT) r = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fc));
    gtk_widget_destroy(fc);
    return r;
}

static GtkWidget *combo(const char *const *items, int n, int active)
{
    GtkWidget *c = gtk_combo_box_text_new();
    for (int i = 0; i < n; i++) gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(c), items[i]);
    gtk_combo_box_set_active(GTK_COMBO_BOX(c), active);
    return c;
}

static void size_date(char *o, size_t cap, u64 size, u64 ft)
{
    char s[48], t[48], b[48];
    gz_ui_fmt_size(s, sizeof s, size);
    gz_ui_fmt_thousands(b, sizeof b, size);
    fmt_filetime(t, sizeof t, ft);
    if (t[0]) g_snprintf(o, cap, "%s (%s B)  ·  %s", s, b, t);
    else g_snprintf(o, cap, "%s (%s B)", s, b);
}

/* ======================================================================
 * questions from running jobs (non-blocking)
 * ====================================================================== */

typedef struct {
    gz_ask *q;
    ask_done_fn fn;
    void *user;
    GtkWidget *entry, *all;
    int archive_replace;
} askctx;

static void answer_text(gz_ask *q, const char *utf8)
{
    gzch *w = u2w(utf8);
    wcopy_cap(q->answer, w ? w : u"", GZ_ASK_CAP);
    g_free(w);
}

static void on_show_pw(GtkToggleButton *t, gpointer e)
{
    gtk_entry_set_visibility(GTK_ENTRY(e), gtk_toggle_button_get_active(t));
}

static void ask_response(GtkDialog *d, gint resp, gpointer user)
{
    askctx *x = user;
    gz_ask *q = x->q;
    int ans = GZ_ANS_CANCEL;
    switch (q->kind) {
    case GZ_ASK_PASSWORD:
        if (resp == GTK_RESPONSE_OK) {
            const char *t = gtk_entry_get_text(GTK_ENTRY(x->entry));
            answer_text(q, t);
            ans = t[0] ? GZ_ANS_YES : GZ_ANS_NO;
            gtk_entry_set_text(GTK_ENTRY(x->entry), "");
        } else if (resp == 2) {
            ans = GZ_ANS_NO;
        }
        break;
    case GZ_ASK_OVERWRITE: {
        int all = x->all && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(x->all));
        if (resp == 1) ans = all ? GZ_ANS_YES_ALL : GZ_ANS_YES;
        else if (resp == 2) ans = all ? GZ_ANS_NO_ALL : GZ_ANS_NO;
        else if (resp == 3) ans = all ? GZ_ANS_RENAME_ALL : GZ_ANS_RENAME;
        else if (x->archive_replace && resp == GTK_RESPONSE_NO) ans = GZ_ANS_NO;
        break;
    }
    case GZ_ASK_VOLUME:
        if (resp == GTK_RESPONSE_ACCEPT) {
            char *f = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(d));
            gzch *w = f ? fs2w(f) : NULL;
            wcopy_cap(q->answer, w ? w : u"", GZ_ASK_CAP);
            gz_free(w);
            g_free(f);
            ans = GZ_ANS_YES;
        }
        break;
    }
    gtk_widget_destroy(GTK_WIDGET(d));
    ask_done_fn fn = x->fn;
    void *u = x->user;
    g_free(x);
    fn(u, ans);
}

void ask_dialog(GtkWindow *parent, gz_ask *q, ask_done_fn fn, void *user)
{
    askctx *x = g_new0(askctx, 1);
    x->q = q;
    x->fn = fn;
    x->user = user;
    GtkWidget *d = NULL, *body;
    char *path = w2u(q->path);
    if (q->kind == GZ_ASK_PASSWORD) {
        char *arc = q->archive ? w2u(q->archive) : g_strdup("");
        d = dlg_new(parent, TR(STR_PW_TITLE), IC_LOCK, TR(STR_PW_TITLE), arc, &body);
        g_free(arc);
        GtkWidget *p = lbl(TR(q->retry ? STR_PW_WRONG : STR_PW_PROMPT), q->retry ? "gz-error-text" : NULL);
        gtk_label_set_line_wrap(GTK_LABEL(p), TRUE);
        gtk_box_pack_start(GTK_BOX(body), p, FALSE, FALSE, 0);
        GtkWidget *f = lbl(path, "gz-dim");
        gtk_label_set_ellipsize(GTK_LABEL(f), PANGO_ELLIPSIZE_MIDDLE);
        gtk_box_pack_start(GTK_BOX(body), f, FALSE, FALSE, 0);
        x->entry = gtk_entry_new();
        gtk_entry_set_visibility(GTK_ENTRY(x->entry), FALSE);
        gtk_entry_set_input_purpose(GTK_ENTRY(x->entry), GTK_INPUT_PURPOSE_PASSWORD);
        gtk_entry_set_activates_default(GTK_ENTRY(x->entry), TRUE);
        gtk_widget_set_size_request(x->entry, 380, -1);
        gtk_box_pack_start(GTK_BOX(body), x->entry, FALSE, FALSE, 4);
        GtkWidget *show = gtk_check_button_new_with_label(TR(STR_PW_SHOW));
        g_signal_connect(show, "toggled", G_CALLBACK(on_show_pw), x->entry);
        gtk_box_pack_start(GTK_BOX(body), show, FALSE, FALSE, 0);
        add_btn(d, TR(STR_CANCEL), GTK_RESPONSE_CANCEL, 0);
        add_btn(d, TR(STR_OWQ_SKIP), 2, 0);
        add_btn(d, TR(STR_OK), GTK_RESPONSE_OK, 1);
        gtk_widget_grab_focus(x->entry);
    } else if (q->kind == GZ_ASK_OVERWRITE) {
        x->archive_replace = q->entry == q->path;
        char t[256];
        if (x->archive_replace) {
            d = dlg_new(parent, TR(STR_OWQ_TITLE), IC_WARN, TR(STR_OWQ_TITLE), TR(STR_OWQ_ARC_PROMPT), &body);
            GtkWidget *f = lbl(path, NULL);
            gtk_label_set_ellipsize(GTK_LABEL(f), PANGO_ELLIPSIZE_MIDDLE);
            gtk_box_pack_start(GTK_BOX(body), f, FALSE, FALSE, 0);
            size_date(t, sizeof t, q->old_size, q->old_mtime);
            gtk_box_pack_start(GTK_BOX(body), lbl(t, "gz-dim"), FALSE, FALSE, 0);
            add_btn(d, TR(STR_NO), GTK_RESPONSE_NO, 0);
            add_btn(d, TR(STR_OWQ_OVERWRITE), 1, 1);
        } else {
            d = dlg_new(parent, TR(STR_OWQ_TITLE), IC_WARN, TR(STR_OWQ_TITLE), TR(STR_OWQ_PROMPT), &body);
            char *en = w2u(q->entry);
            GtkWidget *g = gtk_grid_new();
            gtk_grid_set_column_spacing(GTK_GRID(g), 12);
            gtk_grid_set_row_spacing(GTK_GRID(g), 2);
            gtk_grid_attach(GTK_GRID(g), bold(TR(STR_OWQ_EXISTING)), 0, 0, 2, 1);
            GIcon *fic = NULL;
            type_desc(q->entry ? q->entry : u"", &fic);
            GtkWidget *fim = gtk_image_new_from_gicon(fic, GTK_ICON_SIZE_DND);
            gtk_image_set_pixel_size(GTK_IMAGE(fim), 32);
            gtk_grid_attach(GTK_GRID(g), fim, 0, 1, 1, 2);
            GtkWidget *a = lbl(path, NULL);
            gtk_label_set_ellipsize(GTK_LABEL(a), PANGO_ELLIPSIZE_MIDDLE);
            gtk_label_set_max_width_chars(GTK_LABEL(a), 56);
            gtk_widget_set_hexpand(a, TRUE);
            gtk_grid_attach(GTK_GRID(g), a, 1, 1, 1, 1);
            size_date(t, sizeof t, q->old_size, q->old_mtime);
            gtk_grid_attach(GTK_GRID(g), lbl(t, "gz-dim"), 1, 2, 1, 1);
            GtkWidget *sp = gtk_label_new("");
            gtk_widget_set_size_request(sp, -1, 8);
            gtk_grid_attach(GTK_GRID(g), sp, 0, 3, 2, 1);
            gtk_grid_attach(GTK_GRID(g), bold(TR(STR_OWQ_NEW)), 0, 4, 2, 1);
            gtk_grid_attach(GTK_GRID(g), icon_image(IC_EXTRACT, 32), 0, 5, 1, 2);
            GtkWidget *b = lbl(en, NULL);
            gtk_label_set_ellipsize(GTK_LABEL(b), PANGO_ELLIPSIZE_MIDDLE);
            gtk_label_set_max_width_chars(GTK_LABEL(b), 56);
            gtk_grid_attach(GTK_GRID(g), b, 1, 5, 1, 1);
            size_date(t, sizeof t, q->new_size, q->new_mtime);
            gtk_grid_attach(GTK_GRID(g), lbl(t, "gz-dim"), 1, 6, 1, 1);
            gtk_box_pack_start(GTK_BOX(body), g, FALSE, FALSE, 0);
            x->all = gtk_check_button_new_with_label(TR(STR_OWQ_APPLYALL));
            gtk_box_pack_start(GTK_BOX(body), x->all, FALSE, FALSE, 6);
            g_free(en);
            add_btn(d, TR(STR_CANCEL), GTK_RESPONSE_CANCEL, 0);
            add_btn(d, TR(STR_OWQ_RENAME), 3, 0);
            add_btn(d, TR(STR_OWQ_SKIP), 2, 0);
            add_btn(d, TR(STR_OWQ_OVERWRITE), 1, 1);
        }
    } else {
        d = gtk_file_chooser_dialog_new(TR(STR_VOL_TITLE), parent, GTK_FILE_CHOOSER_ACTION_OPEN, TR(STR_CANCEL),
                                        GTK_RESPONSE_CANCEL, TR(STR_OK), GTK_RESPONSE_ACCEPT, NULL);
        gtk_window_set_modal(GTK_WINDOW(d), TRUE);
        char *fs = w2fs(q->path);
        char *dir = g_path_get_dirname(fs);
        if (path_is_dir(dir)) gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(d), dir);
        GtkWidget *note = lbl(TR(STR_VOL_PROMPT), NULL);
        gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
        gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(box), lbl(path, "gz-dim"), FALSE, FALSE, 0);
        gtk_widget_show_all(box);
        gtk_file_chooser_set_extra_widget(GTK_FILE_CHOOSER(d), box);
        g_free(dir);
        gz_free(fs);
    }
    g_free(path);
    g_signal_connect(d, "response", G_CALLBACK(ask_response), x);
    gtk_widget_show_all(d);
    gtk_window_present(GTK_WINDOW(d));
}

/* ======================================================================
 * extract options
 * ====================================================================== */

typedef struct {
    GtkWidget *d, *dest, *smart;
    char *arc_dir;
} xdlg;

static GtkEntry *dest_entry(xdlg *x) { return GTK_ENTRY(gtk_bin_get_child(GTK_BIN(x->dest))); }

static void set_dest(xdlg *x, const char *p) { path_entry_set(dest_entry(x), p); }

static const char *const k_hist_key[5] = { "gz-p0", "gz-p1", "gz-p2", "gz-p3", "gz-p4" };

/* a destination picked from the combo's list: map the shown text back to its path */
static void on_dest_pick(GtkComboBox *cb, gpointer user)
{
    xdlg *x = user;
    int i = gtk_combo_box_get_active(cb);
    const char *p = i >= 0 && i < 5 ? g_object_get_data(G_OBJECT(cb), k_hist_key[i]) : NULL;
    if (p) set_dest(x, p);
}

static void on_browse(GtkButton *b, gpointer user)
{
    xdlg *x = user;
    char *fs = path_entry_get(dest_entry(x), x->arc_dir);
    char *p = pick_folder(GTK_WINDOW(x->d), TR(STR_X_PICK), fs ? fs : x->arc_dir);
    if (p) set_dest(x, p);
    g_free(p);
    g_free(fs);
}

static void on_quick(GtkButton *b, gpointer user)
{
    xdlg *x = user;
    const char *p = g_object_get_data(G_OBJECT(b), "gz-path");
    if (p) set_dest(x, p);
}

int dlg_extract(GtkWindow *parent, gz_handle *h, const char *arc_path, u32 nsel, xdlg_out *o)
{
    memset(o, 0, sizeof *o);
    gz_archive *a = h->arc;
    xdlg x;
    memset(&x, 0, sizeof x);
    x.arc_dir = g_path_get_dirname(arc_path);
    char n1[32], n2[48], sub[512];
    gz_ui_fmt_thousands(n1, sizeof n1, a->nfiles);
    gz_ui_fmt_size(n2, sizeof n2, a->total_usize);
    char *name = w2u(h->name);
    char summary[128];
    GZ_UI_FMT(summary, sizeof summary, STR_X_SUMMARY, n1, n2);
    g_snprintf(sub, sizeof sub, "%s  ·  %s", name, summary);
    g_free(name);
    GtkWidget *body;
    x.d = dlg_new(parent, TR(STR_X_TITLE), IC_EXTRACT, TR(STR_X_TITLE), sub, &body);
    GtkWidget *d = x.d;

    gtk_box_pack_start(GTK_BOX(body), bold(TR(STR_X_DEST)), FALSE, FALSE, 2);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    x.dest = gtk_combo_box_text_new_with_entry();
    gtk_widget_set_size_request(x.dest, 380, -1);
    const char *quick[4] = { x.arc_dir, g_get_user_special_dir(G_USER_DIRECTORY_DESKTOP),
                             g_get_user_special_dir(G_USER_DIRECTORY_DOCUMENTS),
                             g_get_user_special_dir(G_USER_DIRECTORY_DOWNLOAD) };
    const char *hist[5];
    int nh = 0;
    if (g_set.dest && strcmp(g_set.dest, x.arc_dir)) hist[nh++] = g_set.dest;
    for (int i = 0; i < 4; i++)
        if (quick[i] && (!i || path_is_dir(quick[i]))) hist[nh++] = quick[i];
    for (int i = 0; i < nh; i++) {
        char *u = disp_path_short(hist[i]);
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(x.dest), u);
        g_object_set_data_full(G_OBJECT(x.dest), k_hist_key[i], g_strdup(hist[i]), g_free);
        g_free(u);
    }
    g_signal_connect(x.dest, "changed", G_CALLBACK(on_dest_pick), &x);
    gtk_entry_set_activates_default(dest_entry(&x), TRUE);
    set_dest(&x, g_set.dest_mode == 1 && g_set.dest ? g_set.dest : x.arc_dir);
    gtk_box_pack_start(GTK_BOX(row), x.dest, TRUE, TRUE, 0);
    GtkWidget *br = gtk_button_new_with_label(TR(STR_BROWSE));
    g_signal_connect(br, "clicked", G_CALLBACK(on_browse), &x);
    gtk_box_pack_start(GTK_BOX(row), br, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(body), row, FALSE, FALSE, 0);

    GtkWidget *qrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    static const int qs[4] = { STR_X_HERE, STR_X_DESKTOP, STR_X_DOCS, STR_X_DOWNLOADS };
    for (int i = 0; i < 4; i++) {
        if (!quick[i] || (i && !path_is_dir(quick[i]))) continue;
        GtkWidget *b = gtk_button_new_with_label(TR(qs[i]));
        g_object_set_data_full(G_OBJECT(b), "gz-path", g_strdup(quick[i]), g_free);
        g_signal_connect(b, "clicked", G_CALLBACK(on_quick), &x);
        gtk_box_pack_start(GTK_BOX(qrow), b, FALSE, FALSE, 0);
    }
    gtk_box_pack_start(GTK_BOX(body), qrow, FALSE, FALSE, 0);

    x.smart = gtk_check_button_new_with_label(TR(STR_X_MAKEFOLDER));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(x.smart), g_set.smart);
    gtk_box_pack_start(GTK_BOX(body), x.smart, FALSE, FALSE, 4);

    GtkWidget *g = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(g), 6);
    gtk_grid_set_column_spacing(GTK_GRID(g), 12);
    const char *pm[2] = { TR(STR_X_PATH_FULL), TR(STR_X_PATH_NONE) };
    GtkWidget *paths = combo(pm, 2, g_set.path_mode == GZ_PATH_NONE);
    const char *ow[5] = { TR(STR_OW_ASK), TR(STR_OW_ALL), TR(STR_OW_SKIP), TR(STR_OW_RENAME), TR(STR_OW_NEWER) };
    GtkWidget *owc = combo(ow, 5, g_set.overwrite >= 0 && g_set.overwrite <= GZ_OW_NEWER ? g_set.overwrite : 0);
    gtk_widget_set_hexpand(owc, TRUE);
    gtk_grid_attach(GTK_GRID(g), lbl(TR(STR_X_PATHS), NULL), 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(g), paths, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(g), lbl(TR(STR_X_OVERWRITE), NULL), 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(g), owc, 1, 1, 1, 1);
    gtk_box_pack_start(GTK_BOX(body), g, FALSE, FALSE, 0);

    GtkWidget *openf = gtk_check_button_new_with_label(TR(STR_X_OPENFOLDER));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(openf), g_set.open_folder);
    gtk_box_pack_start(GTK_BOX(body), openf, FALSE, FALSE, 0);
    GtkWidget *only = NULL;
    if (nsel) {
        char t[128], n[24];
        gz_ui_fmt_thousands(n, sizeof n, nsel);
        GZ_UI_FMT(t, sizeof t, STR_X_SELECTED, n);
        only = gtk_check_button_new_with_label(t);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(only), TRUE);
        gtk_box_pack_start(GTK_BOX(body), only, FALSE, FALSE, 0);
    }
    add_btn(d, TR(STR_CANCEL), GTK_RESPONSE_CANCEL, 0);
    add_btn(d, TR(STR_X_START), GTK_RESPONSE_OK, 1);
    gtk_widget_show_all(d);
    int ok = 0;
    while (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_OK) {
        char *ab = path_entry_get(dest_entry(&x), x.arc_dir);
        if (!ab) continue;
        o->dest = ab;
        o->smart = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(x.smart));
        o->path_mode = gtk_combo_box_get_active(GTK_COMBO_BOX(paths)) == 1 ? GZ_PATH_NONE : GZ_PATH_FULL;
        o->overwrite = gtk_combo_box_get_active(GTK_COMBO_BOX(owc));
        if (o->overwrite < 0) o->overwrite = GZ_OW_ASK;
        o->open_folder = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(openf));
        o->only_selected = only && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(only));
        g_set.smart = o->smart;
        g_set.path_mode = o->path_mode;
        g_set.overwrite = o->overwrite;
        g_set.open_folder = o->open_folder;
        if (strcmp(ab, x.arc_dir)) { g_free(g_set.dest); g_set.dest = g_strdup(ab); }
        settings_save();
        ok = 1;
        break;
    }
    gtk_widget_destroy(d);
    g_free(x.arc_dir);
    return ok;
}

/* ======================================================================
 * create archive
 * ====================================================================== */

static int single_stream(int f) { return f == GZ_WF_GZ || f == GZ_WF_BZ2 || f == GZ_WF_XZ || f == GZ_WF_ZST; }

static int writer_usable(const gz_writer *w, int ninputs, int single_file)
{
    return !single_stream(w->format) || (ninputs == 1 && single_file);
}

const gz_writer *writer_default(int ninputs, int single_file)
{
    const gz_writer *w = gz_writer_find(g_set.c_format);
    if (w && writer_usable(w, ninputs, single_file)) return w;
    static const int pref[] = { GZ_WF_ZIP, GZ_WF_7Z, GZ_WF_TGZ, GZ_WF_TXZ, GZ_WF_TAR };
    for (u32 i = 0; i < GZ_COUNTOF(pref); i++) if ((w = gz_writer_find(pref[i]))) return w;
    for (int i = 0; gz_writers[i]; i++) if (writer_usable(gz_writers[i], ninputs, single_file)) return gz_writers[i];
    return NULL;
}

char *default_archive_name(char **inputs, int n, const gz_writer *w)
{
    char *dir = g_path_get_dirname(inputs[0]);
    char *base;
    if (n == 1) {
        base = g_path_get_basename(inputs[0]);
        if (!path_is_dir(inputs[0]) && !(w && single_stream(w->format))) {
            char *dot = strrchr(base, '.');
            if (dot && dot != base) *dot = 0;           /* "report.txt" -> "report.zip" */
        }
    } else {
        base = g_path_get_basename(dir);
        if (!strcmp(base, "/") || !strcmp(base, ".")) { g_free(base); base = g_strdup("archive"); }
    }
    char *file = g_strdup_printf("%s.%s", base, w ? w->ext : "zip");
    char *r = g_build_filename(dir, file, NULL);
    g_free(file);
    g_free(base);
    g_free(dir);
    return r;
}

void cdlg_out_free(cdlg_out *o)
{
    g_free(o->out);
    if (o->password) { memset(o->password, 0, strlen(o->password)); g_free(o->password); }
    memset(o, 0, sizeof *o);
}

typedef struct {
    GtkWidget *d, *out, *fmt, *level, *method, *solid, *pw1, *pw2, *encm, *encn, *err, *encbox;
    const gz_writer *wl[GZ_WF_COUNT + 8];
    int nw;
    const gz_writer *cur;
    int ninputs, single_file;
    int methods[GZ_WM_COUNT], nmethods;
    char *base;                     /* folder of the first input: relative names start here */
} cdlg;

static const gz_writer *cd_writer(cdlg *c)
{
    int i = gtk_combo_box_get_active(GTK_COMBO_BOX(c->fmt));
    return i >= 0 && i < c->nw ? c->wl[i] : NULL;
}

/* "a.tar.gz" with old ext "tar.gz" -> "a.zip" */
static void cd_swap_ext(cdlg *c, const gz_writer *old, const gz_writer *nw)
{
    const char *t = gtk_entry_get_text(GTK_ENTRY(c->out));
    size_t n = strlen(t);
    char *base = NULL;
    const gz_writer *cands[GZ_WF_COUNT + 9];
    int k = 0;
    if (old) cands[k++] = old;
    for (int i = 0; gz_writers[i] && k < (int)GZ_COUNTOF(cands); i++) cands[k++] = gz_writers[i];
    for (int i = 0; i < k && !base; i++) {
        size_t e = strlen(cands[i]->ext);
        if (n > e + 1 && t[n - e - 1] == '.' && !g_ascii_strcasecmp(t + n - e, cands[i]->ext))
            base = g_strndup(t, n - e - 1);
    }
    if (!base) base = g_strdup(t);
    char *r = g_strdup_printf("%s.%s", base, nw->ext);
    gtk_entry_set_text(GTK_ENTRY(c->out), r);
    g_free(r);
    g_free(base);
}

static void cd_update(cdlg *c)
{
    const gz_writer *w = cd_writer(c);
    if (!w) return;
    if (c->cur != w) {
        if (c->cur) cd_swap_ext(c, c->cur, w);
        c->cur = w;
        gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(c->method));
        c->nmethods = 0;
        c->methods[c->nmethods++] = GZ_WM_DEFAULT;
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(c->method), gz_ui_method_name(GZ_WM_DEFAULT));
        for (int m = 1; m < GZ_WM_COUNT; m++) {
            if (!(w->methods & (1u << m))) continue;
            c->methods[c->nmethods++] = m;
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(c->method), gz_ui_method_name(m));
        }
        gtk_combo_box_set_active(GTK_COMBO_BOX(c->method), 0);
        gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(c->encm));
        int act = 0, k = 0;
        if (w->encryptions & (1u << GZ_WE_AES256)) {
            gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(c->encm), "2", "AES-256");
            if (g_set.c_enc == GZ_WE_AES256) act = k;
            k++;
        }
        if (w->encryptions & (1u << GZ_WE_ZIPCRYPTO)) {
            gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(c->encm), "1", "ZipCrypto");
            if (g_set.c_enc == GZ_WE_ZIPCRYPTO) act = k;
            k++;
        }
        gtk_combo_box_set_active(GTK_COMBO_BOX(c->encm), k ? act : -1);
    }
    int enc = w->encryptions != 0;
    gtk_widget_set_sensitive(c->encbox, enc);
    gtk_widget_set_tooltip_text(c->encbox, enc ? NULL : TR(STR_C_NO_ENC));
    gtk_widget_set_sensitive(c->solid, w->format == GZ_WF_7Z);
    gtk_widget_set_sensitive(c->encn, w->format == GZ_WF_7Z);
    int lv = gtk_combo_box_get_active(GTK_COMBO_BOX(c->level));
    gtk_widget_set_sensitive(c->method, lv != 0 && c->nmethods > 1);
}

static void on_cd_changed(GtkWidget *w, gpointer user) { cd_update(user); }

static void on_cd_browse(GtkButton *b, gpointer user)
{
    cdlg *c = user;
    GtkWidget *fc = gtk_file_chooser_dialog_new(TR(STR_C_SAVE_AS), GTK_WINDOW(c->d), GTK_FILE_CHOOSER_ACTION_SAVE,
                                                TR(STR_CANCEL), GTK_RESPONSE_CANCEL, TR(STR_SAVE),
                                                GTK_RESPONSE_ACCEPT, NULL);
    char *fs = path_entry_get(GTK_ENTRY(c->out), c->base);
    if (fs && *fs) {
        char *dir = g_path_get_dirname(fs), *bn = g_path_get_basename(fs);
        if (path_is_dir(dir)) gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(fc), dir);
        char *ub = g_filename_display_name(bn);
        gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(fc), ub);
        g_free(ub);
        g_free(dir);
        g_free(bn);
    }
    g_free(fs);
    if (gtk_dialog_run(GTK_DIALOG(fc)) == GTK_RESPONSE_ACCEPT) {
        char *f = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fc));
        if (f) {
            path_entry_set(GTK_ENTRY(c->out), f);
            gzch *w = fs2w(f);
            int fmt = w ? gz_format_from_name(w) : 0;
            gz_free(w);
            for (int i = 0; i < c->nw; i++)
                if (c->wl[i]->format == fmt) { c->cur = c->wl[i]; gtk_combo_box_set_active(GTK_COMBO_BOX(c->fmt), i); }
        }
        g_free(f);
    }
    gtk_widget_destroy(fc);
}

static GtkWidget *grid_row(GtkWidget *g, int row, const char *label, GtkWidget *w)
{
    gtk_grid_attach(GTK_GRID(g), lbl(label, NULL), 0, row, 1, 1);
    gtk_widget_set_hexpand(w, TRUE);
    gtk_grid_attach(GTK_GRID(g), w, 1, row, 1, 1);
    return w;
}

/* index of the usable writer of format f in the list, -1 when there is none (or f is 0) */
static int cd_find(const cdlg *c, int f)
{
    for (int i = 0; f && i < c->nw; i++) if (c->wl[i]->format == f) return i;
    return -1;
}

int dlg_create(GtkWindow *parent, char **inputs, int n, const char *out0, int fmt0, cdlg_out *o)
{
    memset(o, 0, sizeof *o);
    cdlg *c = g_new0(cdlg, 1);
    c->ninputs = n;
    c->base = g_path_get_dirname(inputs[0]);
    c->single_file = n == 1 && !path_is_dir(inputs[0]);
    for (int i = 0; gz_writers[i] && c->nw < (int)GZ_COUNTOF(c->wl); i++)
        if (writer_usable(gz_writers[i], n, c->single_file)) c->wl[c->nw++] = gz_writers[i];
    if (!c->nw) {
        msg_box(parent, GTK_MESSAGE_ERROR, TR(STR_C_NO_WRITERS), NULL);
        g_free(c->base);
        g_free(c);
        return 0;
    }
    char *b0 = g_path_get_basename(inputs[0]);
    char *u0 = disp_path(b0), sub[512];
    g_free(b0);
    if (n > 1) {
        char cnt[24];
        g_snprintf(cnt, sizeof cnt, "%d", n - 1);
        GZ_UI_FMT(sub, sizeof sub, STR_C_SOURCE_MANY, u0, cnt);
    } else {
        g_strlcpy(sub, u0, sizeof sub);
    }
    g_free(u0);
    GtkWidget *body;
    c->d = dlg_new(parent, TR(STR_C_TITLE), IC_NEW, TR(STR_C_TITLE), sub, &body);

    GtkWidget *g = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(g), 8);
    gtk_grid_set_column_spacing(GTK_GRID(g), 12);
    GtkWidget *orow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    c->out = gtk_entry_new();
    gtk_entry_set_activates_default(GTK_ENTRY(c->out), TRUE);
    gtk_widget_set_size_request(c->out, 380, -1);
    gtk_box_pack_start(GTK_BOX(orow), c->out, TRUE, TRUE, 0);
    GtkWidget *br = gtk_button_new_with_label(TR(STR_BROWSE));
    g_signal_connect(br, "clicked", G_CALLBACK(on_cd_browse), c);
    gtk_box_pack_start(GTK_BOX(orow), br, FALSE, FALSE, 0);
    grid_row(g, 0, TR(STR_C_OUT), orow);

    c->fmt = gtk_combo_box_text_new();
    const gz_writer *dw = writer_default(n, c->single_file);
    int act = 0;
    for (int i = 0; i < c->nw; i++) {
        char t[64];
        g_snprintf(t, sizeof t, "%s  (.%s)", c->wl[i]->name, c->wl[i]->ext);
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(c->fmt), t);
        if (c->wl[i] == dw) act = i;
    }
    /* an archive name given by the caller (--output) is kept as it is; its extension picks
     * the format unless one was given too (as the --yes path does) */
    int pick = cd_find(c, fmt0);
    if (pick < 0 && out0 && *out0) {
        gzch *w = fs2w(out0);
        pick = cd_find(c, w ? gz_format_from_name(w) : 0);
        gz_free(w);
    }
    if (pick >= 0) act = pick;
    grid_row(g, 1, TR(STR_C_FORMAT), c->fmt);
    char *defname = out0 && *out0 ? g_strdup(out0) : default_archive_name(inputs, n, c->wl[act]);
    path_entry_set(GTK_ENTRY(c->out), defname);
    g_free(defname);

    c->level = gtk_combo_box_text_new();
    int lact = 3;
    for (int i = 0; i < 6; i++) {
        char t[64];
        g_snprintf(t, sizeof t, "%d - %s", gz_ui_levels[i], gz_ui_level_name(gz_ui_levels[i]));
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(c->level), t);
        if (gz_ui_levels[i] <= g_set.c_level) lact = i;
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(c->level), lact);
    grid_row(g, 2, TR(STR_C_LEVEL), c->level);
    c->method = gtk_combo_box_text_new();
    grid_row(g, 3, TR(STR_C_METHOD), c->method);
    gtk_box_pack_start(GTK_BOX(body), g, FALSE, FALSE, 0);
    c->solid = gtk_check_button_new_with_label(TR(STR_C_SOLID));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(c->solid), TRUE);
    gtk_box_pack_start(GTK_BOX(body), c->solid, FALSE, FALSE, 2);

    GtkWidget *fr = gtk_frame_new(TR(STR_C_ENCRYPTION));
    c->encbox = fr;
    GtkWidget *eg = gtk_grid_new();
    gtk_container_set_border_width(GTK_CONTAINER(eg), 10);
    gtk_grid_set_row_spacing(GTK_GRID(eg), 6);
    gtk_grid_set_column_spacing(GTK_GRID(eg), 12);
    c->pw1 = gtk_entry_new();
    c->pw2 = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(c->pw1), FALSE);
    gtk_entry_set_visibility(GTK_ENTRY(c->pw2), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(c->pw1), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_input_purpose(GTK_ENTRY(c->pw2), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_activates_default(GTK_ENTRY(c->pw2), TRUE);
    grid_row(eg, 0, TR(STR_C_PASSWORD), c->pw1);
    grid_row(eg, 1, TR(STR_C_PASSWORD2), c->pw2);
    c->encm = gtk_combo_box_text_new();
    grid_row(eg, 2, TR(STR_C_ENC_METHOD), c->encm);
    c->encn = gtk_check_button_new_with_label(TR(STR_C_ENC_NAMES));
    gtk_grid_attach(GTK_GRID(eg), c->encn, 1, 3, 1, 1);
    GtkWidget *show = gtk_check_button_new_with_label(TR(STR_PW_SHOW));
    g_signal_connect(show, "toggled", G_CALLBACK(on_show_pw), c->pw1);
    g_signal_connect(show, "toggled", G_CALLBACK(on_show_pw), c->pw2);
    gtk_grid_attach(GTK_GRID(eg), show, 1, 4, 1, 1);
    gtk_container_add(GTK_CONTAINER(fr), eg);
    gtk_box_pack_start(GTK_BOX(body), fr, FALSE, FALSE, 4);
    c->err = lbl("", "gz-error-text");
    gtk_box_pack_start(GTK_BOX(body), c->err, FALSE, FALSE, 0);

    gtk_combo_box_set_active(GTK_COMBO_BOX(c->fmt), act);
    cd_update(c);
    g_signal_connect(c->fmt, "changed", G_CALLBACK(on_cd_changed), c);
    g_signal_connect(c->level, "changed", G_CALLBACK(on_cd_changed), c);
    add_btn(c->d, TR(STR_CANCEL), GTK_RESPONSE_CANCEL, 0);
    add_btn(c->d, TR(STR_C_START), GTK_RESPONSE_OK, 1);
    gtk_widget_show_all(c->d);
    gtk_widget_grab_focus(c->out);
    int ok = 0;
    while (gtk_dialog_run(GTK_DIALOG(c->d)) == GTK_RESPONSE_OK) {
        const gz_writer *w = cd_writer(c);
        char *fs = path_entry_get(GTK_ENTRY(c->out), c->base);
        if (!w || !fs || !*fs) {
            gtk_label_set_text(GTK_LABEL(c->err), TR(STR_C_NEED_NAME));
            g_free(fs);
            continue;
        }
        const char *p1 = gtk_entry_get_text(GTK_ENTRY(c->pw1)), *p2 = gtk_entry_get_text(GTK_ENTRY(c->pw2));
        if (w->encryptions && strcmp(p1, p2)) {
            gtk_label_set_text(GTK_LABEL(c->err), TR(STR_C_PW_MISMATCH));
            g_free(fs);
            continue;
        }
        o->out = fs;
        o->format = w->format;
        int lv = gtk_combo_box_get_active(GTK_COMBO_BOX(c->level));
        o->level = lv >= 0 && lv < 6 ? gz_ui_levels[lv] : 5;
        int mi = gtk_combo_box_get_active(GTK_COMBO_BOX(c->method));
        o->method = o->level == 0 ? (w->methods & (1u << GZ_WM_STORE) ? GZ_WM_STORE : GZ_WM_DEFAULT)
                                  : (mi > 0 && mi < c->nmethods ? c->methods[mi] : GZ_WM_DEFAULT);
        o->solid = w->format == GZ_WF_7Z && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(c->solid));
        if (w->encryptions && p1[0]) {
            o->password = g_strdup(p1);
            const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(c->encm));
            o->encryption = id ? atoi(id) : GZ_WE_AES256;
            o->encrypt_names = w->format == GZ_WF_7Z && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(c->encn));
            g_set.c_enc = o->encryption;
        }
        g_set.c_format = o->format;
        g_set.c_level = o->level;
        settings_save();
        ok = 1;
        break;
    }
    gtk_entry_set_text(GTK_ENTRY(c->pw1), "");
    gtk_entry_set_text(GTK_ENTRY(c->pw2), "");
    gtk_widget_destroy(c->d);
    g_free(c->base);
    g_free(c);
    return ok;
}

/* ======================================================================
 * archive information
 * ====================================================================== */

static void info_row(GtkWidget *g, int *row, const char *k, const char *v)
{
    GtkWidget *kl = lbl(k, "gz-dim");
    gtk_widget_set_valign(kl, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(g), kl, 0, *row, 1, 1);
    GtkWidget *vl = lbl(v, NULL);
    gtk_label_set_selectable(GTK_LABEL(vl), TRUE);
    gtk_label_set_line_wrap(GTK_LABEL(vl), TRUE);
    gtk_label_set_line_wrap_mode(GTK_LABEL(vl), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_max_width_chars(GTK_LABEL(vl), 56);
    gtk_widget_set_hexpand(vl, TRUE);
    gtk_grid_attach(GTK_GRID(g), vl, 1, *row, 1, 1);
    (*row)++;
}

typedef struct { char *m; u32 n; } mcount;
static gint mcount_cmp(gconstpointer a, gconstpointer b)
{
    const mcount *x = a, *y = b;
    return x->n < y->n ? 1 : x->n > y->n ? -1 : 0;
}

void dlg_info(GtkWindow *parent, gz_handle *h, const char *arc_path)
{
    gz_archive *a = h->arc;
    char *name = w2u(h->name);
    GtkWidget *body;
    GtkWidget *d = dlg_new(parent, TR(STR_I_TITLE), IC_INFO, TR(STR_I_TITLE), name, &body);
    GtkWidget *g = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(g), 6);
    gtk_grid_set_column_spacing(GTK_GRID(g), 16);
    int row = 0;
    char t[512], x1[48], x2[48], x3[48];
    char *loc = disp_path(arc_path);
    info_row(g, &row, TR(STR_I_PATH), loc);
    g_free(loc);
    info_row(g, &row, TR(STR_I_FORMAT), gz_arc_type_name(a));
    u64 fsz = a->src_size ? a->src_size : (h->src ? h->src->size : 0);
    gz_ui_fmt_size(x1, sizeof x1, fsz);
    gz_ui_fmt_thousands(x2, sizeof x2, fsz);
    g_snprintf(t, sizeof t, "%s (%s B)", x1, x2);
    info_row(g, &row, TR(STR_I_FILESIZE), t);
    gz_ui_fmt_thousands(x1, sizeof x1, a->nfiles);
    gz_ui_fmt_thousands(x2, sizeof x2, a->ndirs);
    GZ_UI_FMT(t, sizeof t, STR_I_CONTENTS_FMT, x1, x2);
    info_row(g, &row, TR(STR_I_CONTENTS), t);
    gz_ui_fmt_size(x1, sizeof x1, a->total_usize);
    gz_ui_fmt_thousands(x2, sizeof x2, a->total_usize);
    g_snprintf(t, sizeof t, "%s (%s B)", x1, x2);
    info_row(g, &row, TR(STR_I_USIZE), t);
    if (a->total_usize) {
        gz_ui_fmt_percent(x1, sizeof x1, a->total_csize, a->total_usize);
        gz_ui_fmt_size(x3, sizeof x3, a->total_csize);
        g_snprintf(t, sizeof t, "%s  (%s)", x1, x3);
        info_row(g, &row, TR(STR_I_RATIO), t);
    }
    /* methods, most frequent first */
    GHashTable *ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    for (u32 i = 0; i < a->n; i++) {
        if (a->e[i].is_dir) continue;
        gzch w[96];
        gz_arc_method(a, &a->e[i], w, 96);
        if (!w[0]) continue;
        char *m = w2u(w);
        gpointer old = g_hash_table_lookup(ht, m);
        g_hash_table_replace(ht, m, GUINT_TO_POINTER(GPOINTER_TO_UINT(old) + 1));
    }
    if (g_hash_table_size(ht)) {
        GArray *arr = g_array_new(FALSE, FALSE, sizeof(mcount));
        GHashTableIter it;
        gpointer k, v;
        g_hash_table_iter_init(&it, ht);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            mcount mc = { k, GPOINTER_TO_UINT(v) };
            g_array_append_val(arr, mc);
        }
        g_array_sort(arr, mcount_cmp);
        GString *s = g_string_new(NULL);
        for (guint i = 0; i < arr->len && i < 4; i++) {
            if (i) g_string_append(s, ", ");
            g_string_append(s, g_array_index(arr, mcount, i).m);
        }
        if (arr->len > 4) g_string_append(s, ", …");
        info_row(g, &row, TR(STR_I_METHOD), s->str);
        g_string_free(s, TRUE);
        g_array_free(arr, TRUE);
    }
    g_hash_table_destroy(ht);
    info_row(g, &row, TR(STR_I_ENC), TR(a->headers_enc ? STR_I_HDR_ENC : a->has_enc ? STR_I_YES : STR_I_NO));
    if (a->solid) info_row(g, &row, TR(STR_I_SOLID), TR(STR_I_YES));
    if (a->any_legacy || a->any_utf8) {
        const char *cn = a->any_legacy ? gz_ui_cp_name(a->used_cp) : NULL;
        char cpn[64];
        if (a->any_legacy && !cn) { g_snprintf(cpn, sizeof cpn, "CP%d", a->used_cp); cn = cpn; }
        if (a->any_legacy && a->any_utf8) g_snprintf(t, sizeof t, "UTF-8 + %s", cn);
        else g_strlcpy(t, a->any_legacy ? cn : "UTF-8", sizeof t);
        info_row(g, &row, TR(STR_I_CP), t);
    }
    if (a->nvols) {
        g_snprintf(t, sizeof t, "%u", a->nvols + 1);
        info_row(g, &row, TR(STR_I_VOLUMES), t);
    }
    if (a->sfx_shift) {
        gz_ui_fmt_size(x1, sizeof x1, a->sfx_shift);
        GZ_UI_FMT(t, sizeof t, STR_I_SFX, x1);
        info_row(g, &row, TR(STR_I_FORMAT), t);
    }
    gtk_box_pack_start(GTK_BOX(body), g, FALSE, FALSE, 0);
    if (a->comment && a->comment[0]) {
        gtk_box_pack_start(GTK_BOX(body), bold(TR(STR_I_COMMENT)), FALSE, FALSE, 4);
        GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
        gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(sw), GTK_SHADOW_IN);
        gtk_widget_set_size_request(sw, 440, 110);
        GtkWidget *tv = gtk_text_view_new();
        gtk_text_view_set_editable(GTK_TEXT_VIEW(tv), FALSE);
        gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(tv), GTK_WRAP_WORD_CHAR);
        gtk_text_view_set_left_margin(GTK_TEXT_VIEW(tv), 6);
        char *c = w2u(a->comment);
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(tv)), c, -1);
        g_free(c);
        gtk_container_add(GTK_CONTAINER(sw), tv);
        gtk_box_pack_start(GTK_BOX(body), sw, TRUE, TRUE, 0);
    }
    add_btn(d, TR(STR_CLOSE), GTK_RESPONSE_CLOSE, 1);
    gtk_widget_show_all(d);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
    g_free(name);
}

/* ======================================================================
 * settings
 * ====================================================================== */

static const int k_threads[] = { 0, 1, 2, 4, 6, 8, 12, 16, 24, 32, 64 };

/* one Exec argument as the Desktop Entry specification wants it: in double quotes with ", `, $
 * and \ backslash-escaped, % doubled (field codes). Shell quoting ('...'\''...') is not valid
 * there. The string escaping of the value itself (\ -> \\ ...) is GKeyFile's job. */
static char *desktop_exec_arg(const char *arg)
{
    GString *q = g_string_new("\"");
    for (const char *p = arg; *p; p++) {
        if (*p == '"' || *p == '`' || *p == '$' || *p == '\\') g_string_append_c(q, '\\');
        else if (*p == '%') g_string_append_c(q, '%');
        g_string_append_c(q, *p);
    }
    g_string_append_c(q, '"');
    return g_string_free(q, FALSE);
}

/* the program to name in Exec. GIO checks that the program exists by parsing Exec WITHOUT
 * expanding field codes, so a "%%" (the only valid way to write a '%') never names an existing
 * file there, while a single '%' would be eaten at launch: a program path with a '%' is
 * reached through a symbolic link in the user's data folder instead. */
static char *exec_program(const char *self)
{
    if (!strchr(self, '%')) return g_strdup(self);
    char *dir = g_build_filename(g_get_user_data_dir(), "gogitzip", NULL);
    char *link = g_build_filename(dir, "gogitzip-gtk", NULL);
    g_mkdir_with_parents(dir, 0700);
    unlink(link);
    g_free(dir);
    if (symlink(self, link) == 0) return link;
    g_free(link);
    return g_strdup(self);
}

/* the launcher entry: installed one, else a user entry for this executable */
static GDesktopAppInfo *app_info(void)
{
    GDesktopAppInfo *ai = g_desktop_app_info_new("gogitzip.desktop");
    if (ai) return ai;
    char *exe = g_file_read_link("/proc/self/exe", NULL);
    if (!exe) return NULL;
    char *self = exec_program(exe);
    g_free(exe);
    static const char grp[] = G_KEY_FILE_DESKTOP_GROUP;
    GKeyFile *kf = g_key_file_new();
    g_key_file_set_string(kf, grp, G_KEY_FILE_DESKTOP_KEY_TYPE, G_KEY_FILE_DESKTOP_TYPE_APPLICATION);
    g_key_file_set_string(kf, grp, G_KEY_FILE_DESKTOP_KEY_NAME, "GogitZIP");
    g_key_file_set_locale_string(kf, grp, G_KEY_FILE_DESKTOP_KEY_NAME, "ko", "고깃ZIP");
    g_key_file_set_string(kf, grp, G_KEY_FILE_DESKTOP_KEY_ICON, "gogitzip");
    g_key_file_set_boolean(kf, grp, G_KEY_FILE_DESKTOP_KEY_TERMINAL, FALSE);
    g_key_file_set_boolean(kf, grp, G_KEY_FILE_DESKTOP_KEY_NO_DISPLAY, FALSE);
    g_key_file_set_string(kf, grp, G_KEY_FILE_DESKTOP_KEY_CATEGORIES, "GTK;Utility;Archiving;");
    char *q = desktop_exec_arg(self);
    char *exec = g_strconcat(q, " %F", NULL);
    g_key_file_set_string(kf, grp, G_KEY_FILE_DESKTOP_KEY_EXEC, exec);
    g_free(exec);
    g_free(q);
    GString *mt = g_string_new(NULL);
    for (int i = 0; k_ext_mime[i].ext; i++) g_string_append_printf(mt, "%s;", k_ext_mime[i].mime);
    g_key_file_set_string(kf, grp, G_KEY_FILE_DESKTOP_KEY_MIME_TYPE, mt->str);
    g_string_free(mt, TRUE);
    gsize len = 0;
    char *data = g_key_file_to_data(kf, &len, NULL);
    g_key_file_free(kf);
    char *dir = g_build_filename(g_get_user_data_dir(), "applications", NULL);
    g_mkdir_with_parents(dir, 0700);
    char *fn = g_build_filename(dir, "gogitzip.desktop", NULL);
    if (data && g_file_set_contents(fn, data, (gssize)len, NULL)) ai = g_desktop_app_info_new_from_filename(fn);
    g_free(data);
    g_free(fn);
    g_free(dir);
    g_free(self);
    return ai;
}

/* MIME types of the archives the readers in this build open (documents excluded) */
static int readable_ext(const char *ext)
{
    size_t n = strlen(ext);
    for (int i = 0; gz_formats[i]; i++) {
        const char *e = gz_formats[i]->exts;
        while (e && *e) {
            const char *s = e;
            while (*e && *e != ' ') e++;
            if ((size_t)(e - s) == n && !g_ascii_strncasecmp(s, ext, n)) return 1;
            while (*e == ' ') e++;
        }
    }
    return 0;
}

int assoc_set_default(int *count)
{
    *count = 0;
    GDesktopAppInfo *ai = app_info();
    if (!ai) return 0;
    GHashTable *done = g_hash_table_new(g_str_hash, g_str_equal);
    int fail = 0;
    for (int i = 0; k_ext_mime[i].ext; i++) {
        const char *m = k_ext_mime[i].mime;
        if (!readable_ext(k_ext_mime[i].ext) || g_hash_table_contains(done, m)) continue;
        g_hash_table_add(done, (gpointer)m);
        GError *e = NULL;
        if (g_app_info_set_as_default_for_type(G_APP_INFO(ai), m, &e)) (*count)++;
        else fail++;
        g_clear_error(&e);
    }
    g_hash_table_destroy(done);
    g_object_unref(ai);
    return *count > 0 && !fail;
}

static void on_assoc(GtkButton *b, gpointer parent)
{
    int n = 0;
    int ok = assoc_set_default(&n);
    char t[256], c[24];
    g_snprintf(c, sizeof c, "%d", n);
    GZ_UI_FMT(t, sizeof t, STR_S_ASSOC_DONE, c);
    msg_box(GTK_WINDOW(parent), ok ? GTK_MESSAGE_INFO : GTK_MESSAGE_WARNING, ok ? t : TR(STR_S_ASSOC_FAIL),
            ok ? NULL : t);
}

typedef struct { GtkWidget *custom, *chooser; } sdlg;
static void on_dest_mode(GtkToggleButton *t, gpointer user)
{
    sdlg *s = user;
    gtk_widget_set_sensitive(s->chooser, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s->custom)));
}

void dlg_settings(GtkWindow *parent)
{
    GtkWidget *body;
    GtkWidget *d = dlg_new(parent, TR(STR_S_TITLE), IC_SETTINGS, TR(STR_S_TITLE), NULL, &body);
    GtkWidget *g = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(g), 8);
    gtk_grid_set_column_spacing(GTK_GRID(g), 16);
    int row = 0;
    gtk_grid_attach(GTK_GRID(g), bold(TR(STR_S_GENERAL)), 0, row++, 2, 1);
    const char *langs[3] = { TR(STR_S_LANG_AUTO), TR(STR_S_LANG_KO), TR(STR_S_LANG_EN) };
    GtkWidget *lang = combo(langs, 3, g_set.lang);
    gtk_grid_attach(GTK_GRID(g), lbl(TR(STR_S_LANG), NULL), 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(g), lang, 1, row++, 1, 1);
    GtkWidget *cp = gtk_combo_box_text_new();
    int cpa = 0;
    for (u32 i = 0; i < gz_ui_ncodepages; i++) {
        if (gz_ui_codepages[i].cp && !gz_plat_cp_valid(gz_ui_codepages[i].cp)) continue;
        char id[16];
        g_snprintf(id, sizeof id, "%d", gz_ui_codepages[i].cp);
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(cp), id, TR(gz_ui_codepages[i].sid));
        if (gz_ui_codepages[i].cp == g_set.codepage) cpa = (int)i;
    }
    char cpid[16];
    g_snprintf(cpid, sizeof cpid, "%d", g_set.codepage);
    if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(cp), cpid)) gtk_combo_box_set_active(GTK_COMBO_BOX(cp), cpa ? 0 : 0);
    gtk_grid_attach(GTK_GRID(g), lbl(TR(STR_S_CODEPAGE), NULL), 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(g), cp, 1, row++, 1, 1);
    GtkWidget *th = gtk_combo_box_text_new();
    int tha = 0;
    for (u32 i = 0; i < GZ_COUNTOF(k_threads); i++) {
        char t[64], n[16];
        g_snprintf(n, sizeof n, "%d", i ? k_threads[i] : gz_os_cpu_count());
        if (!i) GZ_UI_FMT(t, sizeof t, STR_S_AUTO_N, n);
        else g_strlcpy(t, n, sizeof t);
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(th), t);
        if (k_threads[i] == g_set.threads) tha = (int)i;
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(th), tha);
    gtk_grid_attach(GTK_GRID(g), lbl(TR(STR_S_THREADS), NULL), 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(g), th, 1, row++, 1, 1);

    gtk_grid_attach(GTK_GRID(g), bold(TR(STR_S_EXTRACT)), 0, row++, 2, 1);
    sdlg s;
    GtkWidget *arcd = gtk_radio_button_new_with_label(NULL, TR(STR_S_DEST_ARC));
    s.custom = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(arcd), TR(STR_S_DEST_CUSTOM));
    s.chooser = gtk_file_chooser_button_new(TR(STR_X_PICK), GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER);
    if (g_set.dest && path_is_dir(g_set.dest)) gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(s.chooser), g_set.dest);
    else gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(s.chooser), g_get_home_dir());
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(g_set.dest_mode ? s.custom : arcd), TRUE);
    gtk_widget_set_sensitive(s.chooser, g_set.dest_mode == 1);
    g_signal_connect(s.custom, "toggled", G_CALLBACK(on_dest_mode), &s);
    gtk_grid_attach(GTK_GRID(g), lbl(TR(STR_S_DEST), NULL), 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(g), arcd, 1, row++, 1, 1);
    GtkWidget *crow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(crow), s.custom, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(crow), s.chooser, TRUE, TRUE, 0);
    gtk_grid_attach(GTK_GRID(g), crow, 1, row++, 1, 1);
    GtkWidget *smart = gtk_check_button_new_with_label(TR(STR_S_SMART));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(smart), g_set.smart);
    gtk_grid_attach(GTK_GRID(g), smart, 1, row++, 1, 1);
    const char *ow[5] = { TR(STR_OW_ASK), TR(STR_OW_ALL), TR(STR_OW_SKIP), TR(STR_OW_RENAME), TR(STR_OW_NEWER) };
    GtkWidget *owc = combo(ow, 5, g_set.overwrite);
    gtk_grid_attach(GTK_GRID(g), lbl(TR(STR_S_OVERWRITE), NULL), 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(g), owc, 1, row++, 1, 1);
    GtkWidget *openf = gtk_check_button_new_with_label(TR(STR_X_OPENFOLDER));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(openf), g_set.open_folder);
    gtk_grid_attach(GTK_GRID(g), openf, 1, row++, 1, 1);

    gtk_grid_attach(GTK_GRID(g), bold(TR(STR_S_ASSOC)), 0, row++, 2, 1);
    GtkWidget *ad = lbl(TR(STR_S_ASSOC_DESC), "gz-dim");
    gtk_label_set_line_wrap(GTK_LABEL(ad), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(ad), 50);
    gtk_grid_attach(GTK_GRID(g), ad, 0, row++, 2, 1);
    GtkWidget *ab = gtk_button_new_with_label(TR(STR_S_ASSOC_BTN));
    gtk_widget_set_halign(ab, GTK_ALIGN_START);
    g_signal_connect(ab, "clicked", G_CALLBACK(on_assoc), d);
    gtk_grid_attach(GTK_GRID(g), ab, 0, row++, 2, 1);
    gtk_box_pack_start(GTK_BOX(body), g, FALSE, FALSE, 0);

    add_btn(d, TR(STR_CANCEL), GTK_RESPONSE_CANCEL, 0);
    add_btn(d, TR(STR_OK), GTK_RESPONSE_OK, 1);
    gtk_widget_show_all(d);
    if (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_OK) {
        int nl = gtk_combo_box_get_active(GTK_COMBO_BOX(lang));
        int changed = nl >= 0 && nl != g_set.lang;
        if (nl >= 0) g_set.lang = nl;
        const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(cp));
        g_set.codepage = id ? atoi(id) : 0;
        int ti = gtk_combo_box_get_active(GTK_COMBO_BOX(th));
        g_set.threads = ti > 0 && ti < (int)GZ_COUNTOF(k_threads) ? k_threads[ti] : 0;
        g_set.dest_mode = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s.custom));
        char *f = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(s.chooser));
        if (f) { g_free(g_set.dest); g_set.dest = f; }
        g_set.smart = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(smart));
        int o = gtk_combo_box_get_active(GTK_COMBO_BOX(owc));
        g_set.overwrite = o >= 0 ? o : GZ_OW_ASK;
        g_set.open_folder = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(openf));
        settings_save();
        if (changed) msg_box(GTK_WINDOW(d), GTK_MESSAGE_INFO, TR(STR_S_RESTART), NULL);
    }
    gtk_widget_destroy(d);
}

/* ======================================================================
 * about
 * ====================================================================== */

void dlg_about(GtkWindow *parent)
{
    int nr = 0, nw = 0;
    while (gz_formats[nr]) nr++;
    while (gz_writers[nw]) nw++;
    char a[16], b[16], fm[128];
    g_snprintf(a, sizeof a, "%d", nr);
    g_snprintf(b, sizeof b, "%d", nw);
    GZ_UI_FMT(fm, sizeof fm, STR_A_FORMATS, a, b);
    char *com = g_strdup_printf("%s\n\n%s\n%s: %s\n%s: %s", TR(STR_TAGLINE), fm, TR(STR_A_CPU),
                                g_cpu.brand[0] ? g_cpu.brand : g_cpu.vendor, TR(STR_A_ENGINE), engine_line());
    GdkPixbuf *logo = icon_pixbuf(IC_LOGO, 96);
    gtk_show_about_dialog(parent, "program-name", TR(STR_APP), "version", GZ_APP_VERSION, "comments", com,
                          "website", GZ_HOMEPAGE, "website-label", TR(STR_A_HOME), "copyright",
                          "© 2026 Butcherar", "license-type", GTK_LICENSE_MIT_X11, "logo", logo,
                          "title", TR(STR_A_TITLE), NULL);
    g_object_unref(logo);
    g_free(com);
}

/* ======================================================================
 * job results
 * ====================================================================== */

void dlg_result(GtkWindow *parent, gz_job *j, int kind, int result, int quiet_ok)
{
    gz_progress p;
    gz_job_progress(j, &p);
    u32 nlog = gz_job_log_count(j), shown = 0;
    for (u32 i = 0; i < nlog; i++) if (gz_job_log_at(j, i)->level >= GZ_LOG_WARN) shown++;
    if (result == GZ_E_CANCEL) {
        if (!quiet_ok) msg_box(parent, GTK_MESSAGE_INFO, TR(STR_R_CANCELED), NULL);
        return;
    }
    char t[256], n[32];
    if (!result && !p.errors && !shown) {
        if (kind != RK_TEST || quiet_ok) return;
        char a[32], b[48], c[32], sp[48];
        gz_ui_fmt_thousands(a, sizeof a, p.done_files);
        gz_ui_fmt_size(b, sizeof b, p.done_bytes);
        gz_ui_fmt_duration(c, sizeof c, (p.elapsed_ms + 500) / 1000);
        gz_ui_fmt_speed(sp, sizeof sp, p.elapsed_ms ? p.done_bytes * 1000 / p.elapsed_ms : p.done_bytes);
        GZ_UI_FMT(t, sizeof t, STR_R_STATS, a, b, c, sp);
        GtkWidget *ob;
        GtkWidget *od = dlg_new(parent, TR(STR_R_TITLE), IC_CHECK, TR(STR_R_TEST_OK), t, &ob);
        add_btn(od, TR(STR_OK), GTK_RESPONSE_OK, 1);
        gtk_widget_show_all(od);
        gtk_dialog_run(GTK_DIALOG(od));
        gtk_widget_destroy(od);
        return;
    }
    GtkWidget *body;
    if (p.errors) {
        g_snprintf(n, sizeof n, "%u", p.errors);
        GZ_UI_FMT(t, sizeof t, STR_R_ERRORS, n);
    } else if (result) {
        g_strlcpy(t, TR(STR_R_FAILED), sizeof t);
    } else {
        g_snprintf(n, sizeof n, "%u", p.warnings);
        GZ_UI_FMT(t, sizeof t, STR_R_WARNINGS, n);
    }
    GtkWidget *d = dlg_new(parent, TR(STR_R_TITLE), p.errors || result ? IC_ERROR : IC_WARN, TR(STR_R_TITLE), t,
                           &body);
    gtk_window_set_resizable(GTK_WINDOW(d), TRUE);
    GtkListStore *ls = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    for (u32 i = 0; i < nlog; i++) {
        const gz_log *l = gz_job_log_at(j, i);
        if (!l || l->level < GZ_LOG_WARN) continue;
        char *nm = w2u(l->name), *dt = l->detail ? w2u(l->detail) : NULL;
        char *msg = dt ? g_strdup_printf("%s: %s", gz_ui_code_text(l->code), dt) : g_strdup(gz_ui_code_text(l->code));
        GtkTreeIter it;
        gtk_list_store_append(ls, &it);
        gtk_list_store_set(ls, &it, 0, TR(l->level == GZ_LOG_ERROR ? STR_L_ERROR : STR_L_WARN), 1, nm, 2, msg, -1);
        g_free(nm);
        g_free(dt);
        g_free(msg);
    }
    if (!shown && result) {
        GtkTreeIter it;
        gtk_list_store_append(ls, &it);
        gtk_list_store_set(ls, &it, 0, TR(STR_L_ERROR), 1, "", 2, gz_ui_code_text(result), -1);
    }
    GtkWidget *tv = gtk_tree_view_new_with_model(GTK_TREE_MODEL(ls));
    g_object_unref(ls);
    static const int hd[3] = { STR_L_ERROR, STR_L_ITEM, STR_L_PROBLEM };
    for (int c = 0; c < 3; c++) {
        GtkCellRenderer *r = gtk_cell_renderer_text_new();
        if (c == 1) g_object_set(r, "ellipsize", PANGO_ELLIPSIZE_MIDDLE, NULL);
        GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes(TR(hd[c]), r, "text", c, NULL);
        gtk_tree_view_column_set_resizable(col, TRUE);
        if (c == 1) { gtk_tree_view_column_set_expand(col, TRUE); gtk_tree_view_column_set_min_width(col, 220); }
        gtk_tree_view_append_column(GTK_TREE_VIEW(tv), col);
    }
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(sw), GTK_SHADOW_IN);
    gtk_widget_set_size_request(sw, 560, 200);
    gtk_container_add(GTK_CONTAINER(sw), tv);
    gtk_box_pack_start(GTK_BOX(body), sw, TRUE, TRUE, 0);
    add_btn(d, TR(STR_CLOSE), GTK_RESPONSE_CLOSE, 1);
    gtk_widget_show_all(d);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}
