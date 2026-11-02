/*
 * 고깃ZIP - Windows front-end shared declarations
 *
 * Target: Windows 2000 (NT 5.0) .. Windows 11. Only APIs present in
 * Windows 2000 are linked statically; newer ones are loaded at run time.
 * Extraction, testing, compression and opening run in the portable engine
 * (src/app/engine.c) on top of the Windows OS layer (os_win.c).
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

#include "base.h"
#include "arc.h"
#include "engine.h"
#include "cpu.h"
#include "crc32.h"
#include "inflate.h"
#include "crypto.h"
#include "strings.h"
#include "asset_ids.h"
#include "selmask.h"

#define GZ_WIDEN_(s)   L##s
#define GZ_WIDEN(s)    GZ_WIDEN_(s)
#define GZ_VERSION_W   GZ_WIDEN(GZ_APP_VERSION)   /* src/core/version.h */
#define GZ_VERSION_A   GZ_APP_VERSION
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

#define WM_APP_ASK      (WM_APP + 1)   /* engine thread -> progress / open window: question */
#define WM_APP_DONE     (WM_APP + 2)   /* engine thread -> progress / open window: finished */
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
void   fmt_u64(wchar_t *o, u64 v);
void   fmt_thousands(wchar_t *o, u64 v);
void   fmt_size(wchar_t *o, u64 v);                            /* 1.5 MB    */
void   fmt_speed(wchar_t *o, u64 bytes_per_sec);
void   fmt_duration(wchar_t *o, u32 seconds);
void   fmt_filetime(wchar_t *o, u64 ft_utc);
u64    entry_filetime(const gz_entry *e);                      /* UTC FILETIME or 0 */
const wchar_t *path_base(const wchar_t *p);
void   path_dir(wchar_t *dir, const wchar_t *path, size_t cap);
void   path_join(wchar_t *o, const wchar_t *a, const wchar_t *b, size_t cap);
int    path_is_dir(const wchar_t *p);                          /* any length (os_win.c long-path form) */
int    path_exists(const wchar_t *p);
DWORD  path_attributes(const wchar_t *p);                      /* os_win.c; INVALID_FILE_ATTRIBUTES */
#define GZ_LONGPATH 32768                                      /* longest Win32 path + NUL */
int    scale(int px);                                          /* DPI scale from 96 */
extern int g_dpi;

typedef struct {
    int codepage;          /* 0 auto */
    int overwrite;         /* GZ_OW_*: 0 ask, 1 overwrite, 2 skip, 3 rename, 4 newer */
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
    /* last compression options */
    int c_format, c_level, c_method, c_enc, c_solid, c_encnames;
    wchar_t assoc[1024];   /* associated extensions "zip 7z ..." (empty = defaults) */
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

/* ---------------- engine glue (engine.c) ----------------
 * A ui_job bundles the engine options with what the progress window needs;
 * questions from the engine's threads reach the UI thread through
 * SendMessage(WM_APP_ASK), the end through PostMessage(WM_APP_DONE). */
enum { OP_EXTRACT = 1, OP_TEST, OP_COMPRESS };

typedef struct ui_job {
    int op;
    gz_handle *h;                 /* extract / test                                   */
    gz_extract_opts xo;           /* engine options (strings point into this struct)  */
    gz_compress_opts co;
    wchar_t dest[MAX_PATH * 2];   /* extraction folder (before smart naming)          */
    wchar_t out[GZ_LONGPATH];     /* compression: archive to create (any length)      */
    wchar_t pw[256];
    const wchar_t *title;         /* progress window subtitle                         */
    int open_folder;
    /* while running / afterwards */
    HWND notify;
    gz_job *j;                    /* engine job, freed by ui_job_free                 */
    int result;
    gz_progress fin;              /* last progress snapshot                           */
    CRITICAL_SECTION cur_lock;
    wchar_t current[MAX_PATH];
} ui_job;

void ui_job_init(ui_job *u, int op);
void ui_job_free(ui_job *u);
int  ui_job_start(ui_job *u, HWND notify);       /* 0 when out of memory */
u32  ui_job_problems(ui_job *u);                 /* logged errors + warnings */
const wchar_t *err_text(int code);              /* GZ_E_* and GZ_N_* */
/* Open an archive (entry idx of parent when parent != NULL) with the "opening"
 * window; password and missing-volume questions are asked there. */
gz_handle *open_archive_ui(HWND owner, const wchar_t *path, gz_handle *parent, u32 idx, int codepage, int *err);
void open_error_box(HWND owner, const wchar_t *path, int err);
/* the name's extension belongs to a registered format (strict: archives only,
 * no documents / executables / generic disk image names) */
int  is_archive_name(const wchar_t *name, int strict);
/* "*.zip;*.7z;..." of every registered format (heap, caller mem_free) */
wchar_t *archive_patterns(void);

/* ---------------- dialogs.c ---------------- */
typedef struct {
    gz_handle *h;
    const wchar_t *src_path;      /* outermost file ("next to the archive")           */
    wchar_t dest[MAX_PATH * 2];
    int make_folder, overwrite, open_folder, only_selected, nselected;
} x_opts;

/* shared dialog look (dialogs.c, compress.c) */
typedef struct {
    int icon, icon_px;
    wchar_t title[128];
    wchar_t sub[512];
    int sub_red;
    int hdr_dlu, foot_dlu;
    int hdr_px, foot_px;
} dlg_base;
void dlg_setup(HWND h, dlg_base *b, int primary_id);
int  dlg_common(HWND h, UINT m, WPARAM wp, LPARAM lp, INT_PTR *ret);
void dlg_gray(HWND h, int id);
void dlg_bold(HWND h, int id);
#define T_STATIC(d, id, t, x, y, w, h, st) dlgt_item(d, id, DA_STATIC, 0, t, x, y, w, h, SS_LEFT | SS_NOPREFIX | (st), 0)
#define T_BUTTON(d, id, t, x, y, w, h)     dlgt_item(d, id, DA_BUTTON, 0, t, x, y, w, h, BS_OWNERDRAW | WS_TABSTOP, 0)
#define T_CHECK(d, id, t, x, y, w, h)      dlgt_item(d, id, DA_BUTTON, 0, t, x, y, w, h, BS_AUTOCHECKBOX | WS_TABSTOP, 0)
#define T_COMBO(d, id, x, y, w, h, st)     dlgt_item(d, id, DA_COMBO, 0, L"", x, y, w, h, WS_VSCROLL | WS_TABSTOP | (st), 0)
#define T_EDIT(d, id, t, x, y, w, h, st)   dlgt_item(d, id, DA_EDIT, 0, t, x, y, w, h, WS_TABSTOP | ES_AUTOHSCROLL | (st), WS_EX_CLIENTEDGE)

int  dlg_extract_options(HWND owner, x_opts *o);
int  run_job_with_progress(HWND owner, ui_job *u);   /* returns the job result */
int  dlg_ask(HWND owner, gz_ask *a);                 /* GZ_ANS_* */
void dlg_settings(HWND owner);
void dlg_about(HWND owner);
void dlg_info(HWND owner, gz_handle *h);
void dlg_errors(HWND owner, ui_job *u);
void dlg_bench(HWND owner);
int  dlg_assoc(HWND owner);                       /* 1 when g_set.assoc changed */
int  pick_folder(HWND owner, wchar_t *path, const wchar_t *title);
typedef struct { int cp; int sid; } cp_item;
extern const cp_item g_cp_list[];
extern const int g_cp_count;
void msg_box(HWND owner, const wchar_t *text, UINT icon);
void open_in_explorer(const wchar_t *dir, const wchar_t *select);

/* ---------------- compress.c ---------------- */
/* inputs: absolute paths. Dialog (Bandizip-like), or direct: "<name>.zip" next to them. */
int  dlg_compress(HWND owner, const wchar_t *const *inputs, u32 n);
int  compress_direct(HWND owner, const wchar_t *const *inputs, u32 n, int format);

/* ---------------- extract helpers (main.c) ---------------- */
enum { X_DIALOG = 0, X_HERE = 1, X_SMART = 2, X_TO = 3, X_TEST = 4 };
int do_extract(HWND owner, gz_handle *h, const wchar_t *src_path, int mode, const wchar_t *to, const u8 *sel,
               const wchar_t *strip, int nsel);

/* ---------------- mainwnd.c ---------------- */
HWND mainwnd_create(const wchar_t *open_path, int show);
int  mainwnd_loop(HWND hwnd);

/* ---------------- shell.c ---------------- */
int  shell_register(int assoc);
int  shell_unregister(void);
int  shell_is_registered(void);
/* extensions of every registered format, grouped for the association dialog */
enum { AG_ZIP = 0, AG_7Z, AG_RAR, AG_ALZ, AG_TAR, AG_ISO, AG_DISK, AG_OTHER, AG_EXE, AG_COUNT };
typedef struct { char ext[16]; int group; int def_on; } assoc_ext;
int  assoc_list(assoc_ext *out, int cap);
int  assoc_default_on(const char *ext);        /* a real archive type (not a document / program) */
int  assoc_wanted(const char *ext);            /* chosen in g_set.assoc (or on by default) */

extern HINSTANCE g_inst;
extern const wchar_t *g_exe_path;

#endif
