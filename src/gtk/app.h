/*
 * 고깃ZIP - GTK 3 front end (Linux): shared declarations
 *
 *   main.c      start-up, command line modes (--extract-here/-smart/-to, --compress, --test)
 *   mainwnd.c   main window: toolbar, path bar, folder tree, file list, welcome screen, DnD
 *   listmodel.c virtual GtkTreeModel of one folder (100k+ rows, fixed-height mode)
 *   run.c       background jobs: progress window, questions marshalled to the UI thread
 *   dialogs.c   extract / create / info / settings / about / result / question dialogs
 *   icons.c     icon atlas (res/assets.bin, decoded with our own inflate) + CSS
 *   util.c      settings, temporary folders, text conversion, formatting
 *
 * All archive work runs in src/app/engine on worker threads. Paths handed to the
 * engine are gzch (UTF-16 with surrogate escape, see os.h); GTK widgets get UTF-8.
 */
#ifndef GZ_GTK_APP_H
#define GZ_GTK_APP_H
#include <gtk/gtk.h>
#include "engine.h"
#include "strings.h"
#include "cpu.h"
#include "../win/asset_ids.h"     /* icon ids of res/assets.bin (tools/gen_assets.py) */

#define TR(id) gz_ui_str(id)
#define GZ_HOMEPAGE "https://niseullent.github.io/Butcherar/"
#define GZ_APP_ID "gogitzip"

/* extra icon ids after the atlas (drawn at run time) */
enum { IC_NEW = IC_COUNT, IC_TOTAL };

/* exit codes of the command line modes (as 7-Zip / the CLI tool) */
enum { EXIT_OK_ = 0, EXIT_WARN = 1, EXIT_FATAL = 2, EXIT_USAGE = 7, EXIT_BREAK = 255 };

/* ---------------- util.c ---------------- */

#define GZ_RECENT_MAX 8
typedef struct gz_settings {
    int lang;                 /* 0 automatic, 1 Korean, 2 English           */
    int codepage;             /* default for legacy names, 0 = automatic     */
    int threads;              /* 0 = automatic                               */
    int overwrite;            /* GZ_OW_*                                     */
    int smart;                /* extract dialog: folder named after archive */
    int open_folder;          /* open the destination after extracting      */
    int path_mode;            /* GZ_PATH_FULL / GZ_PATH_NONE                 */
    int dest_mode;            /* 0 archive folder, 1 custom (dest)           */
    char *dest;               /* custom destination (file system encoding)  */
    int show_tree;
    int win_w, win_h, win_max, pane;
    int c_format, c_level, c_enc;   /* create dialog: last choices         */
    char *recent[GZ_RECENT_MAX];
} gz_settings;
extern gz_settings g_set;

void  settings_load(void);
void  settings_save(void);
void  settings_add_recent(const char *path);
int   settings_threads(void);                    /* effective worker count */

/* text: gzch <-> UTF-8 (display, lone surrogates -> U+FFFD) and file system bytes */
char *w2u(const gzch *w);                        /* g_free                 */
char *w2u_n(const gzch *w, size_t n);
gzch *u2w(const char *s);                        /* g_free; NULL if invalid UTF-8 */
gzch *fs2w(const char *path);                    /* gz_free (os.h)         */
char *w2fs(const gzch *w);                       /* gz_free                */
void  wcopy_cap(gzch *d, const gzch *s, size_t cap);
char *disp_path(const char *fs_path);            /* g_free, UTF-8 for display */
char *disp_path_short(const char *fs_path);      /* same, "~/..." under the home folder */
void  path_entry_set(GtkEntry *e, const char *fs);          /* show a path, remember the real one */
char *path_entry_get(GtkEntry *e, const char *base);        /* real / typed path (~, relative), g_free */
void  fmt_filetime(char *o, size_t cap, u64 ft);  /* "2026-10-24 18:30", "" if unknown */

/* absolute, normalised path of a command line argument (g_free) */
char *abs_path(const char *arg);
int   path_is_dir(const char *p);
int   path_exists(const char *p);

/* per-process temporary folder <tmp>/gogitzip-<uid>/<pid>, created on demand;
 * temp_new_dir makes a fresh sub folder inside it. g_free the results. */
const char *temp_root(void);
char *temp_new_dir(const char *prefix);
void  temp_sweep_stale(void);                    /* folders of processes that are gone */
void  temp_cleanup(void);                        /* ours, at exit          */

void  open_with_default(GtkWindow *parent, const char *path);  /* xdg default app */
void  show_folder(GtkWindow *parent, const char *path);
void  msg_box(GtkWindow *parent, GtkMessageType type, const char *primary, const char *secondary);

/* archive file name? (extension known to a reader, documents excluded) */
int   is_archive_name(const char *name);
const char *engine_line(void);                   /* "AVX2 · CRC VPCLMULQDQ · AES-NI" */

/* ---------------- icons.c ---------------- */

void icons_init(void);
cairo_surface_t *icon_surface(int id, int size); /* cached, owned by icons.c, never NULL */
GtkWidget *icon_image(int id, int size);
GdkPixbuf *icon_pixbuf(int id, int size);        /* new reference          */
void css_init(void);

/* ---------------- run.c ---------------- */

typedef struct gz_run gz_run;
enum { RK_EXTRACT = 1, RK_TEST, RK_COMPRESS, RK_OPEN, RK_CHILD };   /* kinds of runs */
/* called on the UI thread when a job has finished (after the result dialog) */
typedef void (*run_done_fn)(gz_run *r, int result, void *user);

enum {                         /* run flags */
    RUN_QUIET_OK   = 1,        /* no "done" message on success                     */
    RUN_QUIET      = 2,        /* no result dialog at all (caller reports)         */
    RUN_OPEN_DEST  = 4,        /* open the destination folder afterwards           */
    RUN_NO_WINDOW  = 8,        /* never show the progress window (short internal jobs) */
    RUN_DELAY      = 16,       /* show the progress window only after 400 ms       */
    RUN_LOG_STDERR = 32        /* also print problems on stderr (command line modes) */
};

gz_run *run_extract(GtkWindow *parent, gz_handle *h, const gz_extract_opts *xo, int flags, run_done_fn fn,
                    void *user);
gz_run *run_compress(GtkWindow *parent, const gz_compress_opts *co, int flags, run_done_fn fn, void *user);
/* open an archive (or entry idx of parent when parent != NULL) in the background;
 * the handle is delivered through fn: run_take_handle() */
gz_run *run_open(GtkWindow *parent, const char *path, int codepage, run_done_fn fn, void *user);
gz_run *run_open_child(GtkWindow *parent, gz_handle *ph, u32 idx, int codepage, run_done_fn fn, void *user);
gz_handle *run_take_handle(gz_run *r);           /* open runs, inside fn           */
const char *run_dest(gz_run *r);                 /* extraction folder / archive (fs path) */
/* block in a nested main loop until the job is done (fn still runs); returns result */
int run_wait(gz_run *r);
/* exit status for the command line modes (EXIT_*) */
int run_exit_code(gz_run *r, int result);
void run_unref(gz_run *r);
int runs_active(void);

/* question dialogs (UI thread); used by run.c, return GZ_ANS_* */
typedef void (*ask_done_fn)(void *user, int answer);
void ask_dialog(GtkWindow *parent, gz_ask *q, ask_done_fn fn, void *user);

/* ---------------- dialogs.c ---------------- */

typedef struct xdlg_out {
    char *dest;                /* UTF-8 fs path, g_free                       */
    int smart, overwrite, path_mode, open_folder, only_selected;
} xdlg_out;
/* extract options; nsel > 0 offers "selected only". Returns 1 on OK. */
int  dlg_extract(GtkWindow *parent, gz_handle *h, const char *arc_path, u32 nsel, xdlg_out *o);

typedef struct cdlg_out {
    char *out;                 /* archive path (fs encoding), g_free          */
    int format, method, level, encryption, encrypt_names, solid;
    char *password;            /* UTF-8, g_free (wiped)                       */
} cdlg_out;
/* inputs: absolute fs paths. out0: archive path proposed (NULL: named after the inputs);
 * fmt0: format proposed (0: from out0's extension, else the default). Returns 1 on OK. */
int  dlg_create(GtkWindow *parent, char **inputs, int n, const char *out0, int fmt0, cdlg_out *o);
void cdlg_out_free(cdlg_out *o);
const gz_writer *writer_default(int ninputs, int single_file);
char *default_archive_name(char **inputs, int n, const gz_writer *w);   /* g_free */

void dlg_info(GtkWindow *parent, gz_handle *h, const char *arc_path);
void dlg_settings(GtkWindow *parent);
void dlg_about(GtkWindow *parent);
/* result of a finished job: errors list or a short message */
void dlg_result(GtkWindow *parent, gz_job *j, int kind, int result, int quiet_ok);
int  assoc_set_default(int *count);              /* file associations (user) */

/* ---------------- mainwnd.c ---------------- */

GtkWidget *mainwnd_create(void);
void mainwnd_open(const char *path);             /* fs path */
void mainwnd_compress_paths(char **paths, int n);
GtkWindow *mainwnd_window(void);

/* ---------------- listmodel.c ---------------- */

enum { LC_ICON = 0, LC_NAME, LC_SIZE, LC_PACKED, LC_TYPE, LC_MTIME, LC_RATIO, LC_METHOD, LC_CRC, LC_COUNT };
typedef struct gz_lrow { u8 kind; u8 pad[3]; i32 idx; } gz_lrow;   /* kind 0 "..", 1 folder, 2 file */

#define GZ_TYPE_LIST (gz_list_get_type())
G_DECLARE_FINAL_TYPE(GzList, gz_list, GZ, LIST, GObject)
/* takes ownership of rows (g_malloc'ed) */
GzList *gz_list_new(gz_archive *a, gz_lrow *rows, u32 n);
const gz_lrow *gz_list_rows(GzList *m, u32 *n);
/* sort column LC_*, descending; folders stay first */
void gz_list_sort(gz_archive *a, gz_lrow *rows, u32 n, int col, int desc);
const char *type_desc(const gzch *name, GIcon **icon);   /* cached per extension */
int name_cmp_natural(const gzch *a, const gzch *b);
void types_clear(void);

#endif
