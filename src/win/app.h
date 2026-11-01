/*
 * 고깃ZIP - Windows front-end shared declarations
 *
 * Target: Windows 2000 (NT 5.0) .. Windows 11. Only APIs present in
 * Windows 2000 are linked statically; newer ones are loaded at run time.
 */
#ifndef GZ_APP_H
#define GZ_APP_H

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#undef WINVER
#undef _WIN32_WINNT
#undef _WIN32_IE
#define WINVER 0x0500
#define _WIN32_WINNT 0x0500
#define _WIN32_IE 0x0501

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>

#include "../core/base.h"
#include "../core/arc.h"
#include "../core/cpu.h"
#include "../core/crc32.h"
#include "../core/inflate.h"
#include "../core/crypto.h"
#include "strings.h"
#include "asset_ids.h"

#define GZ_VERSION_W   L"1.0.0"
#define GZ_VERSION_A   "1.0.0"
#define GZ_HOMEPAGE    L"https://niseullent.github.io/Butcherar/"
#define GZ_REGKEY      L"Software\\GogitZIP"

/* constants missing from the Win2000-level headers */
#ifndef LVS_EX_DOUBLEBUFFER
#define LVS_EX_DOUBLEBUFFER 0x00010000
#endif
#ifndef TVS_EX_DOUBLEBUFFER
#define TVS_EX_DOUBLEBUFFER 0x0004
#endif
#ifndef TVM_SETEXTENDEDSTYLE
#define TVM_SETEXTENDEDSTYLE (TV_FIRST + 44)
#endif
#ifndef HDF_SORTUP
#define HDF_SORTUP   0x0400
#define HDF_SORTDOWN 0x0200
#endif
#ifndef BIF_NEWDIALOGSTYLE
#define BIF_NEWDIALOGSTYLE 0x0040
#endif
#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif
#ifndef LVS_EX_LABELTIP
#define LVS_EX_LABELTIP 0x00004000
#endif
#ifndef CLEARTYPE_QUALITY
#define CLEARTYPE_QUALITY 5
#endif
#ifndef SPI_GETFONTSMOOTHINGTYPE
#define SPI_GETFONTSMOOTHINGTYPE 0x200A
#endif

#define WM_APP_ASK      (WM_APP + 1)   /* worker -> progress dialog: question     */
#define WM_APP_DONE     (WM_APP + 2)   /* worker -> progress dialog: finished      */
#define WM_APP_OPENED   (WM_APP + 3)   /* opener thread -> main window             */

/* ---------------- runtime (rt.c) ---------------- */
void  *mem_alloc(size_t n);
void   mem_free(void *p);
wchar_t *wdup(const wchar_t *s);

/* ---------------- util.c ---------------- */
size_t wlen(const wchar_t *s);
void   wcopy(wchar_t *d, const wchar_t *s, size_t cap);
void   wcat(wchar_t *d, const wchar_t *s, size_t cap);
int    wcmp(const wchar_t *a, const wchar_t *b);
int    wicmp(const wchar_t *a, const wchar_t *b);
/* wsprintfW into a buffer of known capacity (never overflows: wvsprintfW itself
 * stops at 1024 characters, and the result is copied with a bound). */
wchar_t *wfmtn(wchar_t *buf, size_t cap, const wchar_t *fmt, ...);
#define GZ_BUFCAP(b) __builtin_choose_expr(                                         \
        __builtin_types_compatible_p(__typeof__(b), __typeof__(&(b)[0])),          \
        (size_t)1024, sizeof(b) >> 1 /* wchar_t is 2 bytes on Windows */)
#define wfmt(b, ...) wfmtn((b), GZ_BUFCAP(b), __VA_ARGS__)
int    prefix_ieq(const wchar_t *s, const wchar_t *p, size_t n);   /* ASCII case-folded */
void   fmt_u64(wchar_t *o, u64 v);
void   fmt_thousands(wchar_t *o, u64 v);
void   fmt_size(wchar_t *o, u64 v);                            /* 1.5 MB    */
void   fmt_speed(wchar_t *o, u64 bytes_per_sec);
void   fmt_duration(wchar_t *o, u32 seconds);
void   fmt_filetime(wchar_t *o, u64 ft_utc);
u64    entry_filetime(const gz_entry *e);                      /* UTC FILETIME or 0 */
const wchar_t *path_base(const wchar_t *p);
void   path_dir(wchar_t *dir, const wchar_t *path, size_t cap);
void   path_strip_ext(wchar_t *name);                          /* "a.tar.gz" -> "a" */
void   path_join(wchar_t *o, const wchar_t *a, const wchar_t *b, size_t cap);
int    path_is_dir(const wchar_t *p);
int    path_exists(const wchar_t *p);
void   path_long(wchar_t *o, const wchar_t *p, size_t cap);    /* add \\?\ when needed */
int    mkdirs(const wchar_t *path);
u8    *w_to_mb(int cp, const wchar_t *w, size_t *outn);        /* caller mem_free */
int    scale(int px);                                          /* DPI scale from 96 */
extern int g_dpi;

typedef struct {
    int codepage;          /* 0 auto */
    int overwrite;         /* 0 ask, 1 overwrite, 2 skip, 3 rename */
    int open_folder;
    int smart_folder;
    int threads;           /* 0 auto */
    int cpu_tier;          /* -1 auto */
    int lang;              /* 0 auto, 1 ko, 2 en */
    int show_tree;
    int win_x, win_y, win_w, win_h, win_max, split;
    int dest_mode;         /* 0 next to archive, 1 desktop, 2 custom */
    wchar_t dest[MAX_PATH];
    wchar_t recent[6][MAX_PATH];
    int col_w[8];
} gz_settings;
extern gz_settings g_set;
void settings_load(void);
void settings_save(void);
void settings_add_recent(const wchar_t *path);

typedef struct { u32 major, minor, build; int sp; } gz_osver;
extern gz_osver g_os;
void os_detect(void);
const wchar_t *os_name(wchar_t *buf);
int  cpu_threads(void);

/* ---------------- gfx.c ---------------- */
typedef struct {
    HFONT ui, ui_bold, small, title, big, mono;
    int ui_h;
} gz_fonts;
extern gz_fonts g_font;

#define C_ACCENT      RGB(229, 72, 77)
#define C_ACCENT_DK   RGB(200, 50, 58)
#define C_ACCENT_HOT  RGB(240, 92, 96)
#define C_TINT        RGB(253, 237, 237)
#define C_TINT2       RGB(250, 219, 220)
#define C_BG          RGB(255, 255, 255)
#define C_PANEL       RGB(247, 247, 249)
#define C_BORDER      RGB(229, 229, 234)
#define C_TEXT        RGB(32, 33, 38)
#define C_TEXT2       RGB(108, 112, 122)
#define C_SEL         RGB(252, 228, 229)

void gfx_init(void);
void gfx_fonts_create(void);
void gfx_draw_icon(HDC dc, int id, int x, int y, int size, BYTE alpha);
void gfx_round_rect(HDC dc, const RECT *r, int radius, COLORREF fill, COLORREF border, int bw);
void gfx_fill(HDC dc, const RECT *r, COLORREF c);
void gfx_text(HDC dc, const wchar_t *s, const RECT *r, HFONT f, COLORREF c, UINT fmt);
int  gfx_text_w(HDC dc, const wchar_t *s, HFONT f);
HICON gfx_app_icon(int size);
void gfx_button_draw(const DRAWITEMSTRUCT *di, int primary);
void gfx_button_hook(HWND btn);
void gfx_set_theme(HWND hwnd, const wchar_t *app);
int  gfx_pick_language(void);
void gfx_asset_stream(const u8 **p, u32 *n, u32 *raw);
const wchar_t *gfx_face(void);
int  gfx_face_pt(void);

/* ---------------- dialog templates (dlgt.c) ---------------- */
typedef struct { u8 *buf; size_t len, cap; WORD *count; } dlgt;
void dlgt_begin(dlgt *d, const wchar_t *title, int cx, int cy, DWORD style);
void dlgt_item(dlgt *d, int id, WORD cls_atom, const wchar_t *cls, const wchar_t *text,
               int x, int y, int cx, int cy, DWORD style, DWORD exstyle);
INT_PTR dlgt_run(dlgt *d, HWND owner, DLGPROC proc, LPARAM lp);
#define DA_BUTTON 0x80
#define DA_EDIT   0x81
#define DA_STATIC 0x82
#define DA_LIST   0x83
#define DA_COMBO  0x85

/* ---------------- engine.c ---------------- */
enum { OW_ASK = 0, OW_ALL = 1, OW_SKIP = 2, OW_RENAME = 3 };
enum { ASK_OVERWRITE = 1, ASK_PASSWORD = 2 };
enum { ANS_YES = 1, ANS_NO = 2, ANS_RENAME = 3, ANS_CANCEL = 4 };

typedef struct gz_job gz_job;
typedef struct {
    int kind;
    const wchar_t *path;      /* overwrite: target file; password: entry name */
    u64 old_size, old_time, new_size, new_time;
    int retry;                /* password: previous attempt failed */
    int apply_all;            /* out */
    wchar_t password[256];    /* out */
} gz_ask;

typedef struct {
    wchar_t *name;
    int code;
} gz_err;

typedef struct {
    wchar_t *path;
    gz_src src;
    gz_archive *arc;
} gz_open_arc;

struct gz_job {
    /* input */
    gz_open_arc *oa;
    u8 *sel;                  /* NULL = all entries (not owned) */
    u8 *sel_owned;            /* mask allocated by the engine */
    const wchar_t *strip;     /* folder prefix to strip ("a/b") or NULL */
    wchar_t dest[MAX_PATH * 2];
    int overwrite;
    int test_only;
    int threads;
    int open_folder;
    HWND notify;              /* progress window */
    /* password */
    wchar_t pw[256];
    int pw_set, pw_gen;
    u8 *pw_a; size_t pw_an;   /* ANSI encoding */
    u8 *pw_u; size_t pw_un;   /* UTF-8 encoding */
    /* shared progress */
    CRITICAL_SECTION lock, ask_lock;
    volatile LONG cancel;
    volatile LONG paused;
    HANDLE run_event;         /* set = running */
    u64 total_bytes, done_bytes;
    u32 total_files, done_files, skipped, nworkers;
    volatile LONG next;
    u32 *order; u32 count;
    wchar_t current[MAX_PATH];
    gz_err *errs; u32 nerr, caperr;
    u32 start_tick, end_tick;
    volatile LONG wait_ms;    /* time spent waiting for the user */
    int finished, result;
    HANDLE thread;
    u8 *zone;                 /* archive's Zone.Identifier (Mark-of-the-Web), heap */
    DWORD zone_n;
};

gz_open_arc *arc_open_path(const wchar_t *path, int codepage, volatile long *cancel, int *err);
gz_open_arc *open_archive_ui(HWND owner, const wchar_t *path, int codepage, int *err);
void arc_close(gz_open_arc *oa);
int  src_open(gz_src *s, const wchar_t *path);
void src_close(gz_src *s);
gz_job *job_new(gz_open_arc *oa);
void job_free(gz_job *j);
void job_start(gz_job *j);
int  job_out_path(gz_job *j, const gz_entry *e, wchar_t *out, size_t cap);  /* 1 ok, 0 n/a, -1 too long */
const wchar_t *err_text(int code);
int  smart_needs_folder(gz_open_arc *oa, const u8 *sel, const wchar_t *strip);

/* ---------------- dialogs.c ---------------- */
typedef struct {
    gz_open_arc *oa;
    wchar_t dest[MAX_PATH * 2];
    int make_folder, overwrite, open_folder, only_selected, nselected;
} gz_extract_opts;

int  dlg_extract_options(HWND owner, gz_extract_opts *o);
int  run_job_with_progress(HWND owner, gz_job *j);   /* returns 0 ok */
int  dlg_ask(HWND owner, gz_ask *a);
void dlg_settings(HWND owner);
void dlg_about(HWND owner);
void dlg_info(HWND owner, gz_open_arc *oa);
void dlg_errors(HWND owner, gz_job *j);
void dlg_bench(HWND owner);
int  pick_folder(HWND owner, wchar_t *path, const wchar_t *title);
typedef struct { int cp; int sid; } cp_item;
extern const cp_item g_cp_list[];
extern const int g_cp_count;
void msg_box(HWND owner, const wchar_t *text, UINT icon);

/* ---------------- extract helpers (main.c) ---------------- */
enum { X_DIALOG = 0, X_HERE = 1, X_SMART = 2, X_TO = 3, X_TEST = 4 };
int do_extract(HWND owner, gz_open_arc *oa, int mode, const wchar_t *to, const u8 *sel,
               const wchar_t *strip, int nsel);

/* ---------------- mainwnd.c ---------------- */
HWND mainwnd_create(const wchar_t *open_path, int show);
int  mainwnd_loop(HWND hwnd);

/* ---------------- shell.c ---------------- */
int  shell_register(int assoc);
int  shell_unregister(void);
int  shell_is_registered(void);

extern HINSTANCE g_inst;
extern const wchar_t *g_exe_path;

#endif
