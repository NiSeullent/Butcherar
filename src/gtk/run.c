/*
 * 고깃ZIP GTK - background jobs and the progress window
 *
 * Engine callbacks arrive on worker threads:
 *   progress  copied into a snapshot under a mutex; a 100 ms UI timer shows it
 *   ask       handed to the UI thread with g_main_context_invoke(); the worker
 *             blocks on a GCond until the (non-blocking) question dialog answers
 *   done      g_idle_add() -> run_finish() on the UI thread
 * The progress window appears at once, or after 400 ms for short internal jobs
 * (opening, viewing a file, drag and drop), so quick work never flickers.
 */
#include "app.h"
#include <string.h>

struct gz_run {
    int kind, flags, refs;
    GtkWindow *parent;
    run_done_fn fn;
    void *user;
    gz_job *job;
    GThread *thread;                 /* RK_CHILD: worker running gz_handle_open_child */
    gz_handle *ph, *h;
    u32 idx;
    int codepage;
    volatile long cancel;
    int child_result;
    char *dest, *subtitle;
    int exit_code;
    /* shared with the worker threads */
    GMutex m;
    GCond c;
    gz_ask *q;
    int ans, answered;
    gz_progress p;
    char cur[1024];
    int have_p;
    /* UI thread */
    int finished, result, paused, canceling, asking;
    GtkWidget *win, *title, *cur_l, *bar, *l1, *r1, *l2, *r2, *eng, *pause_b, *cancel_b, *open_chk;
    guint timer, show_timer;
    GMainLoop *loop;
};

static int s_active;
int runs_active(void) { return s_active; }

static void run_ref(gz_run *r) { r->refs++; }

void run_unref(gz_run *r)
{
    if (--r->refs > 0) return;
    if (r->timer) g_source_remove(r->timer);
    if (r->show_timer) g_source_remove(r->show_timer);
    if (r->win) gtk_widget_destroy(r->win);
    gz_job_free(r->job);
    if (r->h) gz_handle_close(r->h);
    g_free(r->dest);
    g_free(r->subtitle);
    g_mutex_clear(&r->m);
    g_cond_clear(&r->c);
    g_free(r);
}

/* ---------------- worker side ---------------- */

static void cb_progress(void *user, const gz_progress *p)
{
    gz_run *r = user;
    char *cur = p->current ? w2u(p->current) : NULL;
    g_mutex_lock(&r->m);
    r->p = *p;
    r->p.current = NULL;
    if (cur) g_strlcpy(r->cur, cur, sizeof r->cur);
    r->have_p = 1;
    g_mutex_unlock(&r->m);
    g_free(cur);
}

static void show_window(gz_run *r);

static void ask_answered(void *user, int ans)
{
    gz_run *r = user;
    r->asking = 0;
    g_mutex_lock(&r->m);
    r->ans = ans;
    r->answered = 1;
    g_cond_signal(&r->c);
    g_mutex_unlock(&r->m);
}

static gboolean ask_main(gpointer user)
{
    gz_run *r = user;
    if (!(r->flags & RUN_NO_WINDOW)) show_window(r);
    r->asking = 1;
    GtkWindow *par = r->win && gtk_widget_get_visible(r->win) ? GTK_WINDOW(r->win) : r->parent;
    ask_dialog(par, r->q, ask_answered, r);
    return G_SOURCE_REMOVE;
}

static int cb_ask(void *user, gz_ask *q)
{
    gz_run *r = user;
    g_mutex_lock(&r->m);
    r->q = q;
    r->answered = 0;
    g_mutex_unlock(&r->m);
    g_main_context_invoke(NULL, ask_main, r);
    g_mutex_lock(&r->m);
    while (!r->answered) g_cond_wait(&r->c, &r->m);
    int a = r->ans;
    r->q = NULL;
    g_mutex_unlock(&r->m);
    return a;
}

static gboolean finish_idle(gpointer user);

static void cb_done(void *user, int result)
{
    gz_run *r = user;
    g_mutex_lock(&r->m);
    r->result = result;
    g_mutex_unlock(&r->m);
    g_idle_add(finish_idle, r);
}

static gz_callbacks callbacks(gz_run *r)
{
    gz_callbacks cb = { r, cb_ask, cb_progress, NULL, cb_done };
    return cb;
}

static gpointer child_main(gpointer user)
{
    gz_run *r = user;
    gz_callbacks cb = callbacks(r);
    cb.done = NULL;
    gz_open_req req;
    memset(&req, 0, sizeof req);
    req.codepage = r->codepage;
    req.cancel = &r->cancel;
    gz_handle *h = NULL;
    int res = gz_handle_open_child(&h, r->ph, r->idx, &req, &cb);
    if (r->cancel && !res) { gz_handle_close(h); h = NULL; res = GZ_E_CANCEL; }
    g_mutex_lock(&r->m);
    r->h = h;
    r->child_result = res;
    g_mutex_unlock(&r->m);
    cb_done(r, res);
    return NULL;
}

/* ---------------- progress window ---------------- */

static const char *kind_title(int k)
{
    switch (k) {
    case RK_TEST: return TR(STR_P_TESTING);
    case RK_COMPRESS: return TR(STR_P_COMPRESSING);
    case RK_OPEN: case RK_CHILD: return TR(STR_P_OPENING);
    }
    return TR(STR_P_EXTRACTING);
}

static int kind_icon(int k)
{
    switch (k) {
    case RK_TEST: return IC_TEST;
    case RK_COMPRESS: return IC_NEW;
    case RK_OPEN: case RK_CHILD: return IC_OPEN;
    }
    return IC_EXTRACT;
}

static void update(gz_run *r)
{
    if (!r->win) return;
    gz_progress p;
    char cur[1024];
    g_mutex_lock(&r->m);
    p = r->p;
    g_strlcpy(cur, r->cur, sizeof cur);
    int have = r->have_p;
    g_mutex_unlock(&r->m);
    if (r->job) {          /* the job's own counters are authoritative (current name aside) */
        gz_job_progress(r->job, &p);
        have = 1;
    }
    if (!have) return;
    double frac = p.total_bytes ? (double)p.done_bytes / (double)p.total_bytes : 0;
    if (frac > 1) frac = 1;
    if (p.total_bytes) gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(r->bar), frac);
    else gtk_progress_bar_pulse(GTK_PROGRESS_BAR(r->bar));
    gtk_label_set_text(GTK_LABEL(r->cur_l), cur[0] ? cur : (r->canceling ? TR(STR_P_CANCELING) : TR(STR_P_PREPARING)));

    char a[48], b[48], c[48], line[256];
    gz_ui_fmt_size(a, sizeof a, p.done_bytes);
    gz_ui_fmt_size(b, sizeof b, p.total_bytes);
    g_snprintf(line, sizeof line, "%d%%  ·  %s / %s", (int)(frac * 100), a, b);
    gtk_label_set_text(GTK_LABEL(r->l1), line);
    u64 bps = p.elapsed_ms > 200 ? p.done_bytes * 1000 / p.elapsed_ms : 0;
    if (bps) gz_ui_fmt_speed(c, sizeof c, bps);
    else c[0] = 0;
    gtk_label_set_text(GTK_LABEL(r->r1), c);
    gz_ui_fmt_duration(a, sizeof a, p.elapsed_ms / 1000);
    if (bps && p.total_bytes > p.done_bytes) gz_ui_fmt_duration(b, sizeof b, (p.total_bytes - p.done_bytes) / bps);
    else g_strlcpy(b, "--:--", sizeof b);
    g_snprintf(line, sizeof line, "%s %s  ·  %s %s", TR(STR_P_ELAPSED), a, TR(STR_P_REMAIN), b);
    gtk_label_set_text(GTK_LABEL(r->l2), line);
    if (p.total_files) {
        g_snprintf(line, sizeof line, "%s %u / %u", TR(STR_P_FILES), p.done_files, p.total_files);
        gtk_label_set_text(GTK_LABEL(r->r2), line);
    }
    const char *t = r->canceling ? TR(STR_P_CANCELING) : r->paused ? TR(STR_P_PAUSED) : kind_title(r->kind);
    gtk_label_set_text(GTK_LABEL(r->title), t);
}

static gboolean tick(gpointer user)
{
    update(user);
    return G_SOURCE_CONTINUE;
}

static void on_cancel(GtkButton *b, gpointer user)
{
    gz_run *r = user;
    if (r->finished) return;
    r->canceling = 1;
    if (r->job) gz_job_cancel(r->job);
    r->cancel = 1;
    if (r->paused && r->job) gz_job_pause(r->job, 0);
    gtk_widget_set_sensitive(r->cancel_b, FALSE);
    gtk_widget_set_sensitive(r->pause_b, FALSE);
    update(r);
}

static void on_pause(GtkButton *b, gpointer user)
{
    gz_run *r = user;
    if (!r->job || r->finished) return;
    r->paused = !r->paused;
    gz_job_pause(r->job, r->paused);
    gtk_button_set_label(b, TR(r->paused ? STR_P_RESUME : STR_P_PAUSE));
    update(r);
}

static gboolean on_delete(GtkWidget *w, GdkEvent *e, gpointer user)
{
    gz_run *r = user;
    if (!r->asking) on_cancel(NULL, r);
    return TRUE;                       /* the window goes away when the job ends */
}

static gboolean on_key(GtkWidget *w, GdkEventKey *e, gpointer user)
{
    gz_run *r = user;
    if (e->keyval != GDK_KEY_Escape || r->asking) return FALSE;
    on_cancel(NULL, r);
    return TRUE;
}

static GtkWidget *label(const char *t, float xalign, const char *cls)
{
    GtkWidget *l = gtk_label_new(t);
    gtk_label_set_xalign(GTK_LABEL(l), xalign);
    if (cls) gtk_style_context_add_class(gtk_widget_get_style_context(l), cls);
    return l;
}

static void build_window(gz_run *r)
{
    GtkWidget *w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    r->win = w;
    gtk_window_set_title(GTK_WINDOW(w), kind_title(r->kind));
    gtk_window_set_resizable(GTK_WINDOW(w), FALSE);
    gtk_window_set_type_hint(GTK_WINDOW(w), GDK_WINDOW_TYPE_HINT_DIALOG);
    if (r->parent && gtk_widget_get_visible(GTK_WIDGET(r->parent))) {
        gtk_window_set_transient_for(GTK_WINDOW(w), r->parent);
        gtk_window_set_modal(GTK_WINDOW(w), TRUE);
        gtk_window_set_position(GTK_WINDOW(w), GTK_WIN_POS_CENTER_ON_PARENT);
    } else {
        gtk_window_set_position(GTK_WINDOW(w), GTK_WIN_POS_CENTER);
    }
    gtk_window_set_default_size(GTK_WINDOW(w), 540, -1);
    g_signal_connect(w, "delete-event", G_CALLBACK(on_delete), r);
    g_signal_connect(w, "key-press-event", G_CALLBACK(on_key), r);

    GtkWidget *v = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(w), v);

    GtkWidget *head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_style_context_add_class(gtk_widget_get_style_context(head), "gz-dlg-head");
    gtk_box_pack_start(GTK_BOX(head), icon_image(kind_icon(r->kind), 32), FALSE, FALSE, 0);
    GtkWidget *hv = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    r->title = label(kind_title(r->kind), 0, "gz-dlg-title");
    gtk_box_pack_start(GTK_BOX(hv), r->title, FALSE, FALSE, 0);
    GtkWidget *sub = label(r->subtitle ? r->subtitle : "", 0, "gz-dim");
    gtk_label_set_ellipsize(GTK_LABEL(sub), PANGO_ELLIPSIZE_MIDDLE);
    gtk_label_set_max_width_chars(GTK_LABEL(sub), 60);
    gtk_box_pack_start(GTK_BOX(hv), sub, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(head), hv, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(v), head, FALSE, FALSE, 0);

    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(body), "gz-dlg-body");
    r->cur_l = label(TR(STR_P_PREPARING), 0, "gz-dim");
    gtk_label_set_ellipsize(GTK_LABEL(r->cur_l), PANGO_ELLIPSIZE_MIDDLE);
    gtk_label_set_max_width_chars(GTK_LABEL(r->cur_l), 60);
    gtk_box_pack_start(GTK_BOX(body), r->cur_l, FALSE, FALSE, 4);
    r->bar = gtk_progress_bar_new();
    gtk_style_context_add_class(gtk_widget_get_style_context(r->bar), "gz-bar");
    gtk_box_pack_start(GTK_BOX(body), r->bar, FALSE, FALSE, 2);
    GtkWidget *g = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(g), 4);
    gtk_grid_set_column_spacing(GTK_GRID(g), 12);
    r->l1 = label("", 0, NULL);
    r->r1 = label("", 1, NULL);
    r->l2 = label("", 0, NULL);
    r->r2 = label("", 1, NULL);
    gtk_widget_set_hexpand(r->l1, TRUE);
    gtk_grid_attach(GTK_GRID(g), r->l1, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(g), r->r1, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(g), r->l2, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(g), r->r2, 1, 1, 1, 1);
    gtk_box_pack_start(GTK_BOX(body), g, FALSE, FALSE, 4);
    char th[16], eng[200];
    g_snprintf(th, sizeof th, "%d", r->kind == RK_OPEN || r->kind == RK_CHILD ? 1 : settings_threads());
    GZ_UI_FMT(eng, sizeof eng, STR_P_ENGINE, gz_dispatch_inflate_name(), gz_dispatch_crc_name(), th);
    r->eng = label(eng, 0, "gz-faint");
    gtk_box_pack_start(GTK_BOX(body), r->eng, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(v), body, TRUE, TRUE, 0);

    GtkWidget *foot = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_style_context_add_class(gtk_widget_get_style_context(foot), "gz-dlg-foot");
    if (r->kind == RK_EXTRACT) {
        r->open_chk = gtk_check_button_new_with_label(TR(STR_X_OPENFOLDER));
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(r->open_chk), (r->flags & RUN_OPEN_DEST) != 0);
        gtk_box_pack_start(GTK_BOX(foot), r->open_chk, FALSE, FALSE, 0);
    }
    r->cancel_b = gtk_button_new_with_label(TR(STR_CANCEL));
    gtk_style_context_add_class(gtk_widget_get_style_context(r->cancel_b), "gz-accent");
    gtk_widget_set_size_request(r->cancel_b, 110, -1);
    g_signal_connect(r->cancel_b, "clicked", G_CALLBACK(on_cancel), r);
    gtk_box_pack_end(GTK_BOX(foot), r->cancel_b, FALSE, FALSE, 0);
    r->pause_b = gtk_button_new_with_label(TR(STR_P_PAUSE));
    gtk_widget_set_size_request(r->pause_b, 110, -1);
    g_signal_connect(r->pause_b, "clicked", G_CALLBACK(on_pause), r);
    if (r->job && r->kind != RK_OPEN) gtk_box_pack_end(GTK_BOX(foot), r->pause_b, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(v), foot, FALSE, FALSE, 0);
    gtk_widget_show_all(v);
}

static void show_window(gz_run *r)
{
    if (r->show_timer) { g_source_remove(r->show_timer); r->show_timer = 0; }
    if (r->finished || (r->win && gtk_widget_get_visible(r->win))) return;
    if (!r->win) build_window(r);
    update(r);
    gtk_window_present(GTK_WINDOW(r->win));
}

static gboolean show_later(gpointer user)
{
    gz_run *r = user;
    r->show_timer = 0;
    show_window(r);
    return G_SOURCE_REMOVE;
}

/* ---------------- start / finish ---------------- */

static gz_run *run_new(GtkWindow *parent, int kind, int flags, run_done_fn fn, void *user)
{
    gz_run *r = g_new0(gz_run, 1);
    r->refs = 1;
    r->kind = kind;
    r->flags = flags;
    r->parent = parent;
    r->fn = fn;
    r->user = user;
    g_mutex_init(&r->m);
    g_cond_init(&r->c);
    s_active++;
    return r;
}

static void run_started(gz_run *r)
{
    r->timer = g_timeout_add(100, tick, r);
    if (r->flags & RUN_NO_WINDOW) return;
    if (r->flags & RUN_DELAY) r->show_timer = g_timeout_add(400, show_later, r);
    else show_window(r);
}

static gboolean finish_idle(gpointer user)
{
    gz_run *r = user;
    if (r->asking) return G_SOURCE_CONTINUE;          /* never happens: asks block the worker */
    r->finished = 1;
    if (r->timer) { g_source_remove(r->timer); r->timer = 0; }
    if (r->show_timer) { g_source_remove(r->show_timer); r->show_timer = 0; }
    int res;
    if (r->job) {
        res = gz_job_wait(r->job);
        if (r->kind == RK_OPEN) r->h = gz_job_take_handle(r->job);
        else if (r->kind == RK_EXTRACT && gz_job_dest(r->job)) {      /* after smart naming */
            char *d = w2fs(gz_job_dest(r->job));
            g_free(r->dest);
            r->dest = g_strdup(d);
            gz_free(d);
        }
    } else {
        if (r->thread) { g_thread_join(r->thread); r->thread = NULL; }
        res = r->child_result;
    }
    r->result = res;
    r->exit_code = run_exit_code(r, res);
    int open_dest = r->open_chk ? gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(r->open_chk))
                                : (r->flags & RUN_OPEN_DEST) != 0;
    if (r->open_chk) g_set.open_folder = open_dest;
    GtkWindow *par = r->parent && gtk_widget_get_visible(GTK_WIDGET(r->parent)) ? r->parent : NULL;
    if (r->win) { gtk_widget_destroy(r->win); r->win = NULL; }
    if (r->job && (r->flags & RUN_LOG_STDERR)) {
        for (u32 i = 0, n = gz_job_log_count(r->job); i < n; i++) {
            const gz_log *l = gz_job_log_at(r->job, i);
            if (!l || l->level < GZ_LOG_WARN) continue;
            char *nm = w2u(l->name), *dt = l->detail ? w2u(l->detail) : NULL;
            g_printerr("%s: %s : %s%s%s\n", TR(l->level == GZ_LOG_ERROR ? STR_L_ERROR : STR_L_WARN), nm,
                       gz_ui_code_text(l->code), dt ? " : " : "", dt ? dt : "");
            g_free(nm);
            g_free(dt);
        }
        if (res && res != GZ_E_CANCEL && !gz_job_log_count(r->job)) g_printerr("%s: %s\n", TR(STR_L_ERROR), gz_ui_code_text(res));
    }
    if (r->job && !(r->flags & RUN_QUIET) && (r->kind == RK_EXTRACT || r->kind == RK_TEST || r->kind == RK_COMPRESS))
        dlg_result(par, r->job, r->kind, res, (r->flags & RUN_QUIET_OK) != 0);
    if (r->job && r->kind != RK_OPEN) { gz_job_free(r->job); r->job = NULL; }
    if (open_dest && r->kind == RK_EXTRACT && res != GZ_E_CANCEL && r->dest) show_folder(par, r->dest);
    s_active--;
    if (r->fn) r->fn(r, res, r->user);
    if (r->loop) g_main_loop_quit(r->loop);
    run_unref(r);
    return G_SOURCE_REMOVE;
}

static char *subtitle_for(const gzch *w)
{
    return w ? w2u(w) : g_strdup("");
}

gz_run *run_extract(GtkWindow *parent, gz_handle *h, const gz_extract_opts *xo, int flags, run_done_fn fn, void *user)
{
    gz_run *r = run_new(parent, xo->test ? RK_TEST : RK_EXTRACT, flags, fn, user);
    char *p = w2u(h->path);
    r->subtitle = h->parent || h->temp ? w2u(h->name) : p;
    if (r->subtitle != p) g_free(p);
    if (xo->dest) { char *d = w2fs(xo->dest); r->dest = g_strdup(d); gz_free(d); }
    gz_callbacks cb = callbacks(r);
    r->job = gz_extract_start(h, xo, &cb);
    if (!r->job) {
        s_active--;
        run_unref(r);
        msg_box(parent, GTK_MESSAGE_ERROR, TR(STR_E_NOMEM), NULL);
        return NULL;
    }
    run_started(r);
    return r;
}

gz_run *run_compress(GtkWindow *parent, const gz_compress_opts *co, int flags, run_done_fn fn, void *user)
{
    gz_run *r = run_new(parent, RK_COMPRESS, flags, fn, user);
    r->subtitle = subtitle_for(co->out);
    char *d = w2fs(co->out);
    r->dest = g_strdup(d);
    gz_free(d);
    gz_callbacks cb = callbacks(r);
    r->job = gz_compress_start(co, &cb);
    if (!r->job) {
        s_active--;
        run_unref(r);
        msg_box(parent, GTK_MESSAGE_ERROR, TR(STR_E_NOMEM), NULL);
        return NULL;
    }
    run_started(r);
    return r;
}

gz_run *run_open(GtkWindow *parent, const char *path, int codepage, run_done_fn fn, void *user)
{
    gz_run *r = run_new(parent, RK_OPEN, RUN_DELAY | RUN_QUIET, fn, user);
    r->subtitle = disp_path(path);
    gzch *w = fs2w(path);
    gz_open_req req;
    memset(&req, 0, sizeof req);
    req.codepage = codepage;
    gz_callbacks cb = callbacks(r);
    r->job = w ? gz_open_start(w, &req, &cb) : NULL;
    gz_free(w);
    if (!r->job) {
        s_active--;
        run_unref(r);
        return NULL;
    }
    run_started(r);
    return r;
}

gz_run *run_open_child(GtkWindow *parent, gz_handle *ph, u32 idx, int codepage, run_done_fn fn, void *user)
{
    gz_run *r = run_new(parent, RK_CHILD, RUN_DELAY | RUN_QUIET, fn, user);
    r->ph = ph;
    r->idx = idx;
    r->codepage = codepage;
    r->subtitle = idx < ph->arc->n ? w2u(ph->arc->e[idx].name) : g_strdup("");
    r->thread = g_thread_try_new("gz-open", child_main, r, NULL);
    if (!r->thread) {
        s_active--;
        run_unref(r);
        return NULL;
    }
    run_started(r);
    return r;
}

gz_handle *run_take_handle(gz_run *r)
{
    gz_handle *h = r->h;
    r->h = NULL;
    return h;
}

const char *run_dest(gz_run *r) { return r->dest; }

int run_wait(gz_run *r)
{
    run_ref(r);
    if (!r->finished) {
        r->loop = g_main_loop_new(NULL, FALSE);
        g_main_loop_run(r->loop);
        g_main_loop_unref(r->loop);
        r->loop = NULL;
    }
    int res = r->result;
    run_unref(r);
    return res;
}

int run_exit_code(gz_run *r, int result)
{
    if (r->exit_code && r->finished) return r->exit_code;
    if (result == GZ_E_CANCEL || r->canceling) return EXIT_BREAK;
    gz_progress p;
    memset(&p, 0, sizeof p);
    if (r->job) gz_job_progress(r->job, &p);
    if (p.errors || (result && result != GZ_E_SKIP)) return EXIT_FATAL;
    if (p.warnings) return EXIT_WARN;
    return EXIT_OK_;
}
