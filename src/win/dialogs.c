/*
 * 고깃ZIP - dialogs
 *
 * All dialogs share one look: white content area, a header with an icon,
 * title and subtitle, and a light-gray footer with owner-drawn buttons
 * (accent-red primary button). Templates are built at run time (dlgt.c).
 */
#include "app.h"

static HBRUSH s_br_bg, s_br_panel;

#define FG_GRAY   ((HANDLE)(UINT_PTR)1)
#define FG_RED    ((HANDLE)(UINT_PTR)2)
#define FG_ACCENT ((HANDLE)(UINT_PTR)3)

static void brushes(void)
{
    if (!s_br_bg) {
        s_br_bg = CreateSolidBrush(C_BG);
        s_br_panel = CreateSolidBrush(C_PANEL);
    }
}

static BOOL CALLBACK hook_child(HWND c, LPARAM lp)
{
    wchar_t cls[16];
    GetClassNameW(c, cls, 16);
    if (!wicmp(cls, L"Button") && (GetWindowLongW(c, GWL_STYLE) & BS_TYPEMASK) == BS_OWNERDRAW) {
        gfx_button_hook(c);
        if (GetDlgCtrlID(c) == (int)lp) SetWindowLongPtrW(c, GWLP_USERDATA, 1);
    }
    return TRUE;
}

static void center_window(HWND h)
{
    RECT r, pr;
    HWND owner = GetWindow(h, GW_OWNER);
    GetWindowRect(h, &r);
    if (owner && IsWindowVisible(owner) && !IsIconic(owner)) GetWindowRect(owner, &pr);
    else SystemParametersInfoW(SPI_GETWORKAREA, 0, &pr, 0);
    int w = r.right - r.left, hh = r.bottom - r.top;
    int x = pr.left + (pr.right - pr.left - w) / 2, y = pr.top + (pr.bottom - pr.top - hh) / 2;
    HMONITOR mon = MonitorFromRect(&pr, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi;
    mi.cbSize = sizeof mi;
    if (GetMonitorInfoW(mon, &mi)) {
        if (x + w > mi.rcWork.right) x = mi.rcWork.right - w;
        if (y + hh > mi.rcWork.bottom) y = mi.rcWork.bottom - hh;
        if (x < mi.rcWork.left) x = mi.rcWork.left;
        if (y < mi.rcWork.top) y = mi.rcWork.top;
    }
    SetWindowPos(h, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

void dlg_setup(HWND h, dlg_base *b, int primary_id)
{
    brushes();
    SetWindowLongPtrW(h, DWLP_USER, (LONG_PTR)b);
    RECT r = { 0, b->hdr_dlu, 0, b->foot_dlu };
    MapDialogRect(h, &r);
    b->hdr_px = r.top;
    b->foot_px = b->foot_dlu ? r.bottom : 0;
    if (!b->icon_px) b->icon_px = scale(32);
    EnumChildWindows(h, hook_child, primary_id);
    if (primary_id != IDCANCEL) SendMessageW(h, DM_SETDEFID, (WPARAM)primary_id, 0);
    static HICON s_ic_sm, s_ic_big;      /* loaded once, shared by every dialog */
    if (!s_ic_sm) s_ic_sm = gfx_app_icon(GetSystemMetrics(SM_CXSMICON));
    if (!s_ic_big) s_ic_big = gfx_app_icon(GetSystemMetrics(SM_CXICON));
    SendMessageW(h, WM_SETICON, ICON_SMALL, (LPARAM)s_ic_sm);
    SendMessageW(h, WM_SETICON, ICON_BIG, (LPARAM)s_ic_big);
    center_window(h);
}

static void set_fg(HWND h, int id, HANDLE fg) { SetPropW(GetDlgItem(h, id), L"gzfg", fg); }
static void set_bold(HWND h, int id) { SendDlgItemMessageW(h, id, WM_SETFONT, (WPARAM)g_font.ui_bold, 0); }
void dlg_gray(HWND h, int id) { set_fg(h, id, FG_GRAY); }
void dlg_bold(HWND h, int id) { set_bold(h, id); }

int dlg_common(HWND h, UINT m, WPARAM wp, LPARAM lp, INT_PTR *ret)
{
    dlg_base *b = (dlg_base *)GetWindowLongPtrW(h, DWLP_USER);
    if (!b) return 0;
    switch (m) {
    case WM_CTLCOLORDLG:
        *ret = (INT_PTR)s_br_bg;
        return 1;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
        HWND c = (HWND)lp;
        RECT r;
        GetWindowRect(c, &r);
        MapWindowPoints(NULL, h, (POINT *)&r, 2);
        int foot = b->foot_px && r.top >= b->foot_px;
        HDC dc = (HDC)wp;
        HANDLE fg = GetPropW(c, L"gzfg");
        SetBkColor(dc, foot ? C_PANEL : C_BG);
        SetTextColor(dc, fg == FG_GRAY ? C_TEXT2 : fg == FG_RED ? RGB(210, 40, 50) : fg == FG_ACCENT ? C_ACCENT : C_TEXT);
        *ret = (INT_PTR)(foot ? s_br_panel : s_br_bg);
        return 1;
    }
    case WM_ERASEBKGND: {
        HDC dc = (HDC)wp;
        RECT r;
        GetClientRect(h, &r);
        if (b->foot_px) {
            RECT top = r, bot = r;
            top.bottom = b->foot_px;
            bot.top = b->foot_px;
            gfx_fill(dc, &top, C_BG);
            gfx_fill(dc, &bot, C_PANEL);
            RECT line = bot;
            line.bottom = line.top + 1;
            gfx_fill(dc, &line, C_BORDER);
        } else {
            gfx_fill(dc, &r, C_BG);
        }
        *ret = 1;
        return 1;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        if (b->hdr_px) {
            RECT cr;
            GetClientRect(h, &cr);
            int pad = scale(16), isz = b->icon_px;
            int iy = (b->hdr_px - isz) / 2 + scale(2);
            if (b->icon >= 0) gfx_draw_icon(dc, b->icon, pad, iy, isz, 255);
            int tx = pad + (b->icon >= 0 ? isz + scale(12) : 0);
            RECT tr = { tx, iy - scale(2), cr.right - pad, iy + isz / 2 + scale(4) };
            int big = isz > scale(40);
            HFONT tf = big ? g_font.big : g_font.title;
            if (b->sub[0]) {
                gfx_text(dc, b->title, &tr, tf, C_TEXT, DT_LEFT | DT_BOTTOM | DT_SINGLELINE | DT_END_ELLIPSIS);
                RECT sr = { tx, tr.bottom + scale(1), cr.right - pad, iy + isz + scale(8) };
                gfx_text(dc, b->sub, &sr, g_font.ui, b->sub_red ? RGB(210, 40, 50) : C_TEXT2,
                         DT_LEFT | DT_TOP | DT_SINGLELINE | DT_PATH_ELLIPSIS);
            } else {
                RECT r2 = { tx, 0, cr.right - pad, b->hdr_px };
                gfx_text(dc, b->title, &r2, tf, C_TEXT, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            }
        }
        EndPaint(h, &ps);
        *ret = 0;
        return 1;
    }
    case WM_DRAWITEM: {
        const DRAWITEMSTRUCT *di = (const DRAWITEMSTRUCT *)lp;
        if (di->CtlType == ODT_BUTTON) {
            gfx_button_draw(di, (int)GetWindowLongPtrW(di->hwndItem, GWLP_USERDATA));
            *ret = TRUE;
            return 1;
        }
        return 0;
    }
    }
    return 0;
}

void msg_box(HWND owner, const wchar_t *text, UINT icon)
{
    MessageBoxW(owner, text, S(S_APP), MB_OK | icon);
}

/* open a folder in Explorer, optionally with one item selected ("explorer /select," works on 2000) */
void open_in_explorer(const wchar_t *dir, const wchar_t *select)
{
    if (select && select[0]) {
        wchar_t a[MAX_PATH * 2 + 16];
        wfmt(a, L"/select,\"%s\"", select);
        if ((INT_PTR)ShellExecuteW(NULL, L"open", L"explorer.exe", a, NULL, SW_SHOWNORMAL) > 32) return;
    }
    ShellExecuteW(NULL, L"open", dir, NULL, NULL, SW_SHOWNORMAL);
}

static void add_overwrite_modes(HWND c, int cur)
{
    static const int sid[] = { S_OW_ASK, S_OW_ALL, S_OW_SKIP, S_OW_RENAME, S_OW_NEWER };
    for (u32 i = 0; i < GZ_COUNTOF(sid); i++) SendMessageW(c, CB_ADDSTRING, 0, (LPARAM)S(sid[i]));
    SendMessageW(c, CB_SETCURSEL, (WPARAM)(cur >= 0 && cur < (int)GZ_COUNTOF(sid) ? cur : 0), 0);
}

/* ======================================================================
 * Folder picker: IFileOpenDialog (Vista+) or SHBrowseForFolder (2000/XP)
 * ====================================================================== */

typedef struct ShellItem ShellItem;
typedef struct {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ShellItem *, REFIID, void **);
    ULONG (STDMETHODCALLTYPE *AddRef)(ShellItem *);
    ULONG (STDMETHODCALLTYPE *Release)(ShellItem *);
    void *BindToHandler, *GetParent;
    HRESULT (STDMETHODCALLTYPE *GetDisplayName)(ShellItem *, DWORD, LPWSTR *);
} ShellItemVtbl;
struct ShellItem { const ShellItemVtbl *v; };

typedef struct FileDlg FileDlg;
typedef struct {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(FileDlg *, REFIID, void **);
    ULONG (STDMETHODCALLTYPE *AddRef)(FileDlg *);
    ULONG (STDMETHODCALLTYPE *Release)(FileDlg *);
    HRESULT (STDMETHODCALLTYPE *Show)(FileDlg *, HWND);
    void *SetFileTypes, *SetFileTypeIndex, *GetFileTypeIndex, *Advise, *Unadvise;
    HRESULT (STDMETHODCALLTYPE *SetOptions)(FileDlg *, DWORD);
    HRESULT (STDMETHODCALLTYPE *GetOptions)(FileDlg *, DWORD *);
    void *SetDefaultFolder;
    HRESULT (STDMETHODCALLTYPE *SetFolder)(FileDlg *, ShellItem *);
    void *GetFolder, *GetCurrentSelection, *SetFileName, *GetFileName;
    HRESULT (STDMETHODCALLTYPE *SetTitle)(FileDlg *, LPCWSTR);
    void *SetOkButtonLabel, *SetFileNameLabel;
    HRESULT (STDMETHODCALLTYPE *GetResult)(FileDlg *, ShellItem **);
} FileDlgVtbl;
struct FileDlg { const FileDlgVtbl *v; };

static const GUID k_clsid_fod = { 0xDC1C5A9C, 0xE88A, 0x4dde, { 0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7 } };
static const GUID k_iid_fod = { 0xd57c7288, 0xd4ad, 0x4768, { 0xbe, 0x02, 0x9d, 0x96, 0x95, 0x32, 0xd9, 0x60 } };
static const GUID k_iid_si = { 0x43826d1e, 0xe718, 0x42ee, { 0xbc, 0x55, 0xa1, 0xe2, 0x61, 0xc3, 0x7b, 0xfe } };
typedef HRESULT (WINAPI *SHCreateItem_t)(PCWSTR, void *, REFIID, void **);

static int CALLBACK bff_cb(HWND h, UINT m, LPARAM lp, LPARAM data)
{
    (void)lp;
    if (m == BFFM_INITIALIZED && data) SendMessageW(h, BFFM_SETSELECTIONW, TRUE, data);
    return 0;
}

int pick_folder(HWND owner, wchar_t *path, const wchar_t *title)
{
    if (g_os.major >= 6) {
        FileDlg *fd = 0;
        if (SUCCEEDED(CoCreateInstance(&k_clsid_fod, NULL, CLSCTX_INPROC_SERVER, &k_iid_fod, (void **)&fd)) && fd) {
            int ok = 0;
            DWORD opt = 0;
            fd->v->GetOptions(fd, &opt);
            fd->v->SetOptions(fd, opt | 0x20 /* FOS_PICKFOLDERS */ | 0x40 /* FOS_FORCEFILESYSTEM */);
            fd->v->SetTitle(fd, title);
            SHCreateItem_t mk = (SHCreateItem_t)(void *)GetProcAddress(GetModuleHandleW(L"shell32.dll"),
                                                                      "SHCreateItemFromParsingName");
            ShellItem *init = 0;
            if (mk && path[0] && path_is_dir(path) && SUCCEEDED(mk(path, NULL, &k_iid_si, (void **)&init)) && init) {
                fd->v->SetFolder(fd, init);
                init->v->Release(init);
            }
            if (SUCCEEDED(fd->v->Show(fd, owner))) {
                ShellItem *res = 0;
                if (SUCCEEDED(fd->v->GetResult(fd, &res)) && res) {
                    LPWSTR s = 0;
                    if (SUCCEEDED(res->v->GetDisplayName(res, 0x80058000 /* SIGDN_FILESYSPATH */, &s)) && s) {
                        wcopy(path, s, MAX_PATH * 2);
                        CoTaskMemFree(s);
                        ok = 1;
                    }
                    res->v->Release(res);
                }
            }
            fd->v->Release(fd);
            return ok;
        }
    }
    BROWSEINFOW bi;
    __builtin_memset(&bi, 0, sizeof bi);
    bi.hwndOwner = owner;
    bi.lpszTitle = title;
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    bi.lpfn = bff_cb;
    bi.lParam = (LPARAM)path;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return 0;
    wchar_t buf[MAX_PATH];
    int ok = SHGetPathFromIDListW(pidl, buf);
    CoTaskMemFree(pidl);
    if (ok) wcopy(path, buf, MAX_PATH * 2);
    return ok;
}

/* ======================================================================
 * Extract options
 * ====================================================================== */

enum { ID_X_DEST = 101, ID_X_BROWSE, ID_X_HERE, ID_X_DESKTOP, ID_X_DOCS, ID_X_MKDIR, ID_X_OW, ID_X_OPEN,
       ID_X_SEL, ID_X_OWLABEL, ID_X_DESTLABEL };

typedef struct { dlg_base b; x_opts *o; wchar_t here[MAX_PATH * 2]; } xdlg;

static void special_dir(int csidl, wchar_t *out)
{
    wchar_t b[MAX_PATH];
    b[0] = 0;
    SHGetSpecialFolderPathW(NULL, b, csidl, FALSE);
    wcopy(out, b, MAX_PATH * 2);
}

static INT_PTR CALLBACK xdlg_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    INT_PTR ret;
    if (dlg_common(h, m, wp, lp, &ret)) return ret;
    xdlg *x = (xdlg *)GetWindowLongPtrW(h, DWLP_USER);
    switch (m) {
    case WM_INITDIALOG: {
        x = (xdlg *)lp;
        x_opts *o = x->o;
        dlg_setup(h, &x->b, IDOK);
        set_bold(h, ID_X_DESTLABEL);
        HWND cb = GetDlgItem(h, ID_X_DEST);
        SetWindowTextW(cb, o->dest);
        SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)x->here);
        wchar_t t[MAX_PATH * 2];
        special_dir(CSIDL_DESKTOPDIRECTORY, t);
        if (t[0]) SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)t);
        if (g_set.dest[0] && wicmp(g_set.dest, x->here)) SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)g_set.dest);
        SetWindowTextW(cb, o->dest);
        CheckDlgButton(h, ID_X_MKDIR, o->make_folder ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(h, ID_X_OPEN, o->open_folder ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(h, ID_X_SEL, o->only_selected ? BST_CHECKED : BST_UNCHECKED);
        if (!o->nselected) ShowWindow(GetDlgItem(h, ID_X_SEL), SW_HIDE);
        add_overwrite_modes(GetDlgItem(h, ID_X_OW), o->overwrite);
        SetFocus(GetDlgItem(h, IDOK));
        return FALSE;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_X_BROWSE: {
            wchar_t p[MAX_PATH * 2];
            GetDlgItemTextW(h, ID_X_DEST, p, MAX_PATH * 2);
            if (pick_folder(h, p, S(S_X_PICK))) SetDlgItemTextW(h, ID_X_DEST, p);
            return TRUE;
        }
        case ID_X_HERE: SetDlgItemTextW(h, ID_X_DEST, x->here); return TRUE;
        case ID_X_DESKTOP: case ID_X_DOCS: {
            wchar_t p[MAX_PATH * 2];
            special_dir(LOWORD(wp) == ID_X_DESKTOP ? CSIDL_DESKTOPDIRECTORY : CSIDL_PERSONAL, p);
            SetDlgItemTextW(h, ID_X_DEST, p);
            return TRUE;
        }
        case IDOK: {
            x_opts *o = x->o;
            wchar_t p[MAX_PATH * 2];
            GetDlgItemTextW(h, ID_X_DEST, p, MAX_PATH * 2);
            size_t n = wlen(p);
            while (n && (p[n - 1] == ' ')) p[--n] = 0;
            if (!n) { MessageBeep(MB_ICONWARNING); SetFocus(GetDlgItem(h, ID_X_DEST)); return TRUE; }
            if (!GetFullPathNameW(p, MAX_PATH * 2, o->dest, NULL)) wcopy(o->dest, p, MAX_PATH * 2);
            o->make_folder = IsDlgButtonChecked(h, ID_X_MKDIR) == BST_CHECKED;
            o->open_folder = IsDlgButtonChecked(h, ID_X_OPEN) == BST_CHECKED;
            o->only_selected = o->nselected && IsDlgButtonChecked(h, ID_X_SEL) == BST_CHECKED;
            o->overwrite = (int)SendDlgItemMessageW(h, ID_X_OW, CB_GETCURSEL, 0, 0);
            if (o->overwrite < 0) o->overwrite = GZ_OW_ASK;
            g_set.smart_folder = o->make_folder;
            g_set.open_folder = o->open_folder;
            wchar_t desk[MAX_PATH * 2];
            special_dir(CSIDL_DESKTOPDIRECTORY, desk);
            if (!wicmp(o->dest, x->here)) g_set.dest_mode = 0;
            else if (!wicmp(o->dest, desk)) g_set.dest_mode = 1;
            else { g_set.dest_mode = 2; wcopy(g_set.dest, o->dest, MAX_PATH); }
            settings_save();
            EndDialog(h, 1);
            return TRUE;
        }
        case IDCANCEL:
            EndDialog(h, 0);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

int dlg_extract_options(HWND owner, x_opts *o)
{
    xdlg x;
    __builtin_memset(&x, 0, sizeof x);
    x.o = o;
    path_dir(x.here, o->src_path, GZ_COUNTOF(x.here));
    x.b.icon = IC_EXTRACT;
    wcopy(x.b.title, S(S_X_TITLE), 128);
    {
        wchar_t cnt[32], sz[32], line[128];
        fmt_thousands(cnt, o->h->arc->nfiles);
        fmt_size(sz, o->h->arc->total_usize);
        wfmt(line, S(S_X_SUMMARY), cnt, sz);
        wfmt(x.b.sub, L"%s  ·  %s", path_base(o->h->name), line);
    }
    x.b.hdr_dlu = 40;
    x.b.foot_dlu = 166;
    dlgt d;
    dlgt_begin(&d, S(S_X_TITLE), 310, 194, 0);
    T_STATIC(&d, ID_X_DESTLABEL, S(S_X_DEST), 12, 46, 286, 10, 0);
    T_COMBO(&d, ID_X_DEST, 12, 59, 228, 120, CBS_DROPDOWN | CBS_AUTOHSCROLL);
    T_BUTTON(&d, ID_X_BROWSE, S(S_BROWSE), 244, 58, 54, 15);
    T_BUTTON(&d, ID_X_HERE, S(S_X_HERE), 12, 77, 72, 13);
    T_BUTTON(&d, ID_X_DESKTOP, S(S_X_DESKTOP), 88, 77, 56, 13);
    T_BUTTON(&d, ID_X_DOCS, S(S_X_DOCS), 148, 77, 44, 13);
    T_CHECK(&d, ID_X_MKDIR, S(S_X_MAKEFOLDER), 12, 99, 290, 11);
    T_STATIC(&d, ID_X_OWLABEL, S(S_X_OVERWRITE), 12, 117, 124, 10, 0);
    T_COMBO(&d, ID_X_OW, 140, 115, 130, 90, CBS_DROPDOWNLIST);
    T_CHECK(&d, ID_X_OPEN, S(S_X_OPENFOLDER), 12, 133, 290, 11);
    wchar_t selt[96];
    wfmt(selt, S(S_X_SELECTED), o->nselected);
    T_CHECK(&d, ID_X_SEL, selt, 12, 147, 290, 11);
    T_BUTTON(&d, IDOK, S(S_X_START), 184, 173, 62, 15);
    T_BUTTON(&d, IDCANCEL, S(S_CANCEL), 250, 173, 50, 15);
    return (int)dlgt_run(&d, owner, xdlg_proc, (LPARAM)&x);
}

/* ======================================================================
 * Progress (extraction, test, compression)
 * ====================================================================== */

enum { ID_P_FILE = 201, ID_P_BAR, ID_P_LEFT, ID_P_RIGHT, ID_P_TIME, ID_P_FILES, ID_P_ENGINE, ID_P_OPEN, ID_P_PAUSE };

typedef struct TBL3 TBL3;
typedef struct {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(TBL3 *, REFIID, void **);
    ULONG (STDMETHODCALLTYPE *AddRef)(TBL3 *);
    ULONG (STDMETHODCALLTYPE *Release)(TBL3 *);
    HRESULT (STDMETHODCALLTYPE *HrInit)(TBL3 *);
    void *AddTab, *DeleteTab, *ActivateTab, *SetActiveAlt, *MarkFullscreenWindow;
    HRESULT (STDMETHODCALLTYPE *SetProgressValue)(TBL3 *, HWND, ULONGLONG, ULONGLONG);
    HRESULT (STDMETHODCALLTYPE *SetProgressState)(TBL3 *, HWND, int);
} TBL3Vtbl;
struct TBL3 { const TBL3Vtbl *v; };
static const GUID k_clsid_tbl = { 0x56FDF344, 0xFD6D, 0x11d0, { 0x95, 0x8A, 0x00, 0x60, 0x97, 0xC9, 0xA0, 0x90 } };
static const GUID k_iid_tbl3 = { 0xea1afb91, 0x9e28, 0x4b86, { 0x90, 0xe9, 0x9e, 0x9f, 0x8a, 0x5e, 0xef, 0xaf } };

typedef struct {
    dlg_base b;
    ui_job *u;
    int shown, done, paused, canceling;
    u64 last_ms, last_bytes, speed;
    u32 pct10;   /* 0..1000 */
    TBL3 *tb;
    HWND tbwnd;
    HWND owner;
} pdlg;

static int op_verb(int op) { return op == OP_TEST ? S_P_TESTING : op == OP_COMPRESS ? S_P_COMPRESSING : S_P_EXTRACTING; }

static void p_update(HWND h, pdlg *p)
{
    ui_job *u = p->u;
    gz_progress g;
    __builtin_memset(&g, 0, sizeof g);
    if (u->j) gz_job_progress(u->j, &g);
    u->fin = g;
    wchar_t cur[MAX_PATH];
    EnterCriticalSection(&u->cur_lock);
    wcopy(cur, u->current, MAX_PATH);
    LeaveCriticalSection(&u->cur_lock);
    u64 done = g.done_bytes, total = g.total_bytes, now = g.elapsed_ms;
    if (total && done > total) done = total;
    if (done < p->last_bytes) p->last_bytes = done;
    if (now >= p->last_ms + 400 && !p->paused) {
        u64 inst = (done - p->last_bytes) * 1000 / (now - p->last_ms);
        p->speed = p->speed ? (p->speed * 3 + inst) / 4 : inst;
        p->last_ms = now;
        p->last_bytes = done;
    }
    if (!p->speed && now > 150 && done) p->speed = done * 1000 / now;
    u32 pct10 = total ? (u32)(done * 1000 / total) : (p->done ? 1000 : 0);
    if (pct10 != p->pct10) {
        p->pct10 = pct10;
        InvalidateRect(GetDlgItem(h, ID_P_BAR), NULL, FALSE);
    }
    wchar_t t[512], a[40], b[40], c[40];
    if (cur[0]) SetDlgItemTextW(h, ID_P_FILE, cur);
    fmt_size(a, done);
    fmt_size(b, total);
    wfmt(t, L"%d%%   ·   %s / %s", pct10 / 10, a, b);
    SetDlgItemTextW(h, ID_P_LEFT, t);
    if (p->paused) wcopy(t, S(S_P_PAUSED), 64);
    else if (p->canceling && !p->done) wcopy(t, S(S_P_CANCELING), 64);
    else { fmt_speed(a, p->speed); wcopy(t, a, 64); }
    SetDlgItemTextW(h, ID_P_RIGHT, t);
    fmt_duration(a, (u32)(now / 1000));
    if (p->speed && total > done) fmt_duration(c, (u32)((total - done) / p->speed));
    else wcopy(c, L"--:--", 40);
    wfmt(t, L"%s %s   ·   %s %s", S(S_P_ELAPSED), a, S(S_P_REMAIN), c);
    SetDlgItemTextW(h, ID_P_TIME, t);
    fmt_thousands(a, g.done_files);
    fmt_thousands(b, g.total_files);
    wfmt(t, L"%s %s / %s", S(S_P_FILES), a, b);
    SetDlgItemTextW(h, ID_P_FILES, t);
    wfmt(t, L"%d%% - %s - %s", pct10 / 10, path_base(u->title), S(op_verb(u->op)));
    SetWindowTextW(h, t);
    if (p->tb) {
        p->tb->v->SetProgressState(p->tb, p->tbwnd, p->paused ? 8 : 2);
        p->tb->v->SetProgressValue(p->tb, p->tbwnd, pct10, 1000);
    }
}

static void p_draw_bar(const DRAWITEMSTRUCT *di, pdlg *p)
{
    HDC dc = di->hDC;
    RECT r = di->rcItem;
    gfx_fill(dc, &r, C_BG);
    int rad = (r.bottom - r.top) / 2;
    gfx_round_rect(dc, &r, rad, RGB(238, 238, 242), 0, 0);
    int w = (int)((r.right - r.left) * (i64)p->pct10 / 1000);
    if (w > 0) {
        RECT f = r;
        f.right = f.left + (w < rad * 2 ? rad * 2 : w);
        gfx_round_rect(dc, &f, rad, p->paused ? RGB(245, 170, 60) : C_ACCENT, 0, 0);
    }
}

static void p_show(HWND h, pdlg *p)
{
    if (p->shown) return;
    KillTimer(h, 2);
    ShowWindow(h, SW_SHOW);
    p->shown = 1;
}

static INT_PTR CALLBACK pdlg_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    INT_PTR ret;
    pdlg *p = (pdlg *)GetWindowLongPtrW(h, DWLP_USER);
    if (m == WM_DRAWITEM && p && wp == ID_P_BAR) { p_draw_bar((const DRAWITEMSTRUCT *)lp, p); return TRUE; }
    if (dlg_common(h, m, wp, lp, &ret)) return ret;
    switch (m) {
    case WM_INITDIALOG: {
        p = (pdlg *)lp;
        ui_job *u = p->u;
        dlg_setup(h, &p->b, IDCANCEL);
        set_fg(h, ID_P_ENGINE, FG_GRAY);
        set_fg(h, ID_P_FILE, FG_GRAY);
        set_bold(h, ID_P_LEFT);
        CheckDlgButton(h, ID_P_OPEN, u->open_folder ? BST_CHECKED : BST_UNCHECKED);
        if (u->op == OP_TEST) ShowWindow(GetDlgItem(h, ID_P_OPEN), SW_HIDE);
        wchar_t t[256];
        int nthreads = g_set.threads > 0 ? g_set.threads : cpu_threads();
        if (u->op != OP_COMPRESS) {
            gz_archive *a = u->h->arc;
            if (a->solid) nthreads = 1;
            if (nthreads > (int)a->nfiles && a->nfiles) nthreads = (int)a->nfiles;
        }
        wfmt(t, S(S_P_ENGINE), gz_dispatch_inflate_name(), gz_dispatch_crc_name(), nthreads);
        SetDlgItemTextW(h, ID_P_ENGINE, t);
        SetDlgItemTextW(h, ID_P_FILE, S(S_P_PREPARING));
        p->owner = GetWindow(h, GW_OWNER);
        if (!p->owner || !IsWindowVisible(p->owner))
            SetWindowLongW(h, GWL_EXSTYLE, GetWindowLongW(h, GWL_EXSTYLE) | WS_EX_APPWINDOW);
        p->tbwnd = (p->owner && IsWindowVisible(p->owner)) ? p->owner : h;
        if (g_os.major > 6 || (g_os.major == 6 && g_os.minor >= 1)) {
            if (FAILED(CoCreateInstance(&k_clsid_tbl, NULL, CLSCTX_INPROC_SERVER, &k_iid_tbl3, (void **)&p->tb)))
                p->tb = 0;
            if (p->tb && FAILED(p->tb->v->HrInit(p->tb))) { p->tb->v->Release(p->tb); p->tb = 0; }
        }
        if (!ui_job_start(u, h)) {
            u->result = GZ_E_NOMEM;
            if (p->tb) { p->tb->v->Release(p->tb); p->tb = 0; }
            EndDialog(h, 0);
            return TRUE;
        }
        SetTimer(h, 1, 150, NULL);
        SetTimer(h, 2, 350, NULL);
        return TRUE;
    }
    case WM_TIMER:
        if (wp == 2) {
            KillTimer(h, 2);
            if (!p->done) p_show(h, p);
        } else {
            p_update(h, p);
        }
        return TRUE;
    case WM_APP_ASK: {
        p_show(h, p);
        int r = dlg_ask(h, (gz_ask *)lp);
        SetWindowLongPtrW(h, DWLP_MSGRESULT, r);
        return TRUE;
    }
    case WM_APP_DONE:
        p->done = 1;
        KillTimer(h, 1);
        KillTimer(h, 2);
        p_update(h, p);
        p->u->open_folder = IsDlgButtonChecked(h, ID_P_OPEN) == BST_CHECKED;
        if (p->tb) {
            p->tb->v->SetProgressState(p->tb, p->tbwnd, 0);
            p->tb->v->Release(p->tb);
            p->tb = 0;
        }
        EndDialog(h, 0);
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wp) == ID_P_PAUSE && !p->done && p->u->j) {
            p->paused = !p->paused;
            gz_job_pause(p->u->j, p->paused);
            SetDlgItemTextW(h, ID_P_PAUSE, S(p->paused ? S_P_RESUME : S_P_PAUSE));
            InvalidateRect(GetDlgItem(h, ID_P_BAR), NULL, FALSE);
            p_update(h, p);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) {
            if (!p->done && p->u->j) {
                p->canceling = 1;
                gz_job_cancel(p->u->j);
                if (p->paused) { p->paused = 0; gz_job_pause(p->u->j, 0); }
                EnableWindow(GetDlgItem(h, IDCANCEL), FALSE);
                EnableWindow(GetDlgItem(h, ID_P_PAUSE), FALSE);
                p_update(h, p);
            }
            return TRUE;
        }
        break;
    }
    return FALSE;
}

int run_job_with_progress(HWND owner, ui_job *u)
{
    pdlg p;
    __builtin_memset(&p, 0, sizeof p);
    p.u = u;
    p.b.icon = u->op == OP_TEST ? IC_TEST : u->op == OP_COMPRESS ? IC_COMPRESS : IC_EXTRACT;
    wcopy(p.b.title, S(op_verb(u->op)), 128);
    wcopy(p.b.sub, u->title ? u->title : L"", 512);
    p.b.hdr_dlu = 40;
    p.b.foot_dlu = 114;
    dlgt d;
    dlgt_begin(&d, S(op_verb(u->op)), 300, 140, DS_NOIDLEMSG);
    /* the dialog starts hidden and is shown after 350 ms (fast jobs never flash) */
    {
        DWORD st;
        __builtin_memcpy(&st, d.buf + 12, 4);
        st &= ~WS_VISIBLE;
        st |= WS_MINIMIZEBOX;
        __builtin_memcpy(d.buf + 12, &st, 4);
    }
    T_STATIC(&d, ID_P_FILE, L"", 12, 44, 276, 10, SS_PATHELLIPSIS);
    dlgt_item(&d, ID_P_BAR, DA_STATIC, 0, L"", 12, 57, 276, 7, SS_OWNERDRAW, 0);
    T_STATIC(&d, ID_P_LEFT, L"", 12, 70, 186, 10, 0);
    T_STATIC(&d, ID_P_RIGHT, L"", 200, 70, 88, 10, SS_RIGHT);
    T_STATIC(&d, ID_P_TIME, L"", 12, 82, 186, 10, 0);
    T_STATIC(&d, ID_P_FILES, L"", 200, 82, 88, 10, SS_RIGHT);
    T_STATIC(&d, ID_P_ENGINE, L"", 12, 97, 276, 10, 0);
    T_CHECK(&d, ID_P_OPEN, S(u->op == OP_COMPRESS ? S_C_OPENFOLDER : S_X_OPENFOLDER), 12, 123, 160, 10);
    T_BUTTON(&d, ID_P_PAUSE, S(S_P_PAUSE), 176, 120, 56, 15);
    T_BUTTON(&d, IDCANCEL, S(S_CANCEL), 236, 120, 52, 15);
    dlgt_run(&d, owner, pdlg_proc, (LPARAM)&p);
    if (u->j) {
        u->result = gz_job_wait(u->j);
        gz_job_progress(u->j, &u->fin);
    }
    return u->result;
}

/* ======================================================================
 * Questions from the engine: password / overwrite / missing volume
 * ====================================================================== */

enum { ID_PW_TEXT = 301, ID_PW_EDIT, ID_PW_SHOW };
typedef struct { dlg_base b; gz_ask *a; } adlg;

static INT_PTR CALLBACK pw_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    INT_PTR ret;
    if (dlg_common(h, m, wp, lp, &ret)) return ret;
    adlg *x = (adlg *)GetWindowLongPtrW(h, DWLP_USER);
    switch (m) {
    case WM_INITDIALOG:
        x = (adlg *)lp;
        dlg_setup(h, &x->b, IDOK);
        if (x->a->retry) set_fg(h, ID_PW_TEXT, FG_RED);
        SendDlgItemMessageW(h, ID_PW_EDIT, EM_LIMITTEXT, 255, 0);
        if (g_os.major > 5 || (g_os.major == 5 && g_os.minor >= 1))
            SendDlgItemMessageW(h, ID_PW_EDIT, EM_SETPASSWORDCHAR, 0x25CF, 0);
        SetFocus(GetDlgItem(h, ID_PW_EDIT));
        SetForegroundWindow(h);
        return FALSE;
    case WM_COMMAND:
        if (LOWORD(wp) == ID_PW_SHOW) {
            int show = IsDlgButtonChecked(h, ID_PW_SHOW) == BST_CHECKED;
            wchar_t pc = (g_os.major > 5 || (g_os.major == 5 && g_os.minor >= 1)) ? 0x25CF : '*';
            SendDlgItemMessageW(h, ID_PW_EDIT, EM_SETPASSWORDCHAR, show ? 0 : pc, 0);
            InvalidateRect(GetDlgItem(h, ID_PW_EDIT), NULL, TRUE);
            return TRUE;
        }
        if (LOWORD(wp) == IDOK) {
            GetDlgItemTextW(h, ID_PW_EDIT, x->a->answer, 256);
            EndDialog(h, GZ_ANS_YES);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(h, GZ_ANS_CANCEL); return TRUE; }
        break;
    }
    return FALSE;
}

enum { ID_OW_PATH = 401, ID_OW_L1, ID_OW_I1, ID_OW_L2, ID_OW_I2, ID_OW_ALL, ID_OW_YES, ID_OW_NO, ID_OW_REN };

static void ow_info(wchar_t *o, u64 size, u64 ft)
{
    wchar_t s[40], b[40], t[40];
    fmt_size(s, size);
    fmt_thousands(b, size);
    fmt_filetime(t, ft);
    wfmt(o, L"%s (%s B)   ·   %s", s, b, t[0] ? t : L"-");
}

static INT_PTR CALLBACK ow_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    INT_PTR ret;
    if (dlg_common(h, m, wp, lp, &ret)) return ret;
    adlg *x = (adlg *)GetWindowLongPtrW(h, DWLP_USER);
    switch (m) {
    case WM_INITDIALOG: {
        x = (adlg *)lp;
        dlg_setup(h, &x->b, ID_OW_YES);
        set_bold(h, ID_OW_PATH);
        set_fg(h, ID_OW_L1, FG_GRAY);
        set_fg(h, ID_OW_L2, FG_GRAY);
        wchar_t t[160];
        ow_info(t, x->a->old_size, x->a->old_mtime);
        SetDlgItemTextW(h, ID_OW_I1, t);
        ow_info(t, x->a->new_size, x->a->new_mtime);
        SetDlgItemTextW(h, ID_OW_I2, t);
        SetFocus(GetDlgItem(h, ID_OW_YES));
        SetForegroundWindow(h);
        return FALSE;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp), all = IsDlgButtonChecked(h, ID_OW_ALL) == BST_CHECKED, r = -1;
        if (id == ID_OW_YES) r = all ? GZ_ANS_YES_ALL : GZ_ANS_YES;
        else if (id == ID_OW_NO) r = all ? GZ_ANS_NO_ALL : GZ_ANS_NO;
        else if (id == ID_OW_REN) r = all ? GZ_ANS_RENAME_ALL : GZ_ANS_RENAME;
        else if (id == IDCANCEL) r = GZ_ANS_CANCEL;
        if (r >= 0) { EndDialog(h, r); return TRUE; }
        break;
    }
    }
    return FALSE;
}

enum { ID_V_PATH = 451, ID_V_TEXT, ID_V_BROWSE, ID_V_RETRY };

static INT_PTR CALLBACK vol_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    INT_PTR ret;
    if (dlg_common(h, m, wp, lp, &ret)) return ret;
    adlg *x = (adlg *)GetWindowLongPtrW(h, DWLP_USER);
    switch (m) {
    case WM_INITDIALOG:
        x = (adlg *)lp;
        dlg_setup(h, &x->b, ID_V_BROWSE);
        set_bold(h, ID_V_PATH);
        if (x->a->retry) set_fg(h, ID_V_TEXT, FG_RED);
        SetForegroundWindow(h);
        return TRUE;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_V_BROWSE: {
            wchar_t file[MAX_PATH * 2], dir[MAX_PATH * 2];
            wcopy(file, path_base(x->a->path), GZ_COUNTOF(file));
            path_dir(dir, x->a->path, GZ_COUNTOF(dir));
            OPENFILENAMEW of;
            __builtin_memset(&of, 0, sizeof of);
            of.lStructSize = sizeof of;
            of.hwndOwner = h;
            of.lpstrFilter = L"*.*\0*.*\0";
            of.lpstrFile = file;
            of.nMaxFile = GZ_COUNTOF(file);
            of.lpstrInitialDir = dir;
            of.lpstrTitle = S(S_VOL_TITLE);
            of.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_EXPLORER;
            if (!GetOpenFileNameW(&of)) return TRUE;
            wcopy(x->a->answer, file, GZ_ASK_CAP);
            EndDialog(h, GZ_ANS_YES);
            return TRUE;
        }
        case ID_V_RETRY: x->a->answer[0] = 0; EndDialog(h, GZ_ANS_YES); return TRUE;
        case IDCANCEL: EndDialog(h, GZ_ANS_CANCEL); return TRUE;
        }
        break;
    }
    return FALSE;
}

int dlg_ask(HWND owner, gz_ask *a)
{
    adlg x;
    dlgt d;
    __builtin_memset(&x, 0, sizeof x);
    x.a = a;
    x.b.hdr_dlu = 40;
    if (a->kind == GZ_ASK_PASSWORD) {
        x.b.icon = IC_LOCK;
        wcopy(x.b.title, S(S_PW_TITLE), 128);
        wcopy(x.b.sub, a->path ? a->path : L"", 512);
        x.b.foot_dlu = 100;
        dlgt_begin(&d, S(S_PW_TITLE), 270, 126, 0);
        T_STATIC(&d, ID_PW_TEXT, a->retry ? S(S_PW_WRONG) : a->entry ? S(S_PW_PROMPT) : S(S_PW_ARCHIVE),
                 12, 44, 246, 18, 0);
        T_EDIT(&d, ID_PW_EDIT, L"", 12, 64, 246, 13, ES_PASSWORD);
        T_CHECK(&d, ID_PW_SHOW, S(S_PW_SHOW), 12, 83, 150, 10);
        T_BUTTON(&d, IDOK, S(S_BTN_OK), 152, 106, 52, 15);
        T_BUTTON(&d, IDCANCEL, S(S_CANCEL), 208, 106, 50, 15);
        INT_PTR r = dlgt_run(&d, owner, pw_proc, (LPARAM)&x);
        return r == GZ_ANS_YES ? GZ_ANS_YES : GZ_ANS_CANCEL;
    }
    if (a->kind == GZ_ASK_VOLUME) {
        x.b.icon = IC_OPEN;
        wcopy(x.b.title, S(S_VOL_TITLE), 128);
        wcopy(x.b.sub, a->archive ? a->archive : L"", 512);
        x.b.foot_dlu = 88;
        dlgt_begin(&d, S(S_VOL_TITLE), 300, 114, 0);
        T_STATIC(&d, ID_V_TEXT, a->retry ? S(S_VOL_AGAIN) : S(S_VOL_PROMPT), 12, 44, 276, 18, 0);
        T_STATIC(&d, ID_V_PATH, a->path ? a->path : L"", 12, 66, 276, 10, SS_PATHELLIPSIS);
        T_BUTTON(&d, ID_V_BROWSE, S(S_BROWSE), 128, 94, 56, 15);
        T_BUTTON(&d, ID_V_RETRY, S(S_VOL_RETRY), 188, 94, 50, 15);
        T_BUTTON(&d, IDCANCEL, S(S_CANCEL), 242, 94, 46, 15);
        INT_PTR r = dlgt_run(&d, owner, vol_proc, (LPARAM)&x);
        return r == GZ_ANS_YES ? GZ_ANS_YES : GZ_ANS_CANCEL;
    }
    x.b.icon = IC_WARN;
    wcopy(x.b.title, S(S_OW_TITLE), 128);
    wcopy(x.b.sub, S(S_OW_PROMPT), 512);
    x.b.foot_dlu = 124;
    dlgt_begin(&d, S(S_OW_TITLE), 300, 150, 0);
    T_STATIC(&d, ID_OW_PATH, a->path ? a->path : L"", 12, 44, 276, 10, SS_PATHELLIPSIS);
    T_STATIC(&d, ID_OW_L1, S(S_OW_EXISTING), 12, 60, 276, 9, 0);
    T_STATIC(&d, ID_OW_I1, L"", 12, 70, 276, 10, 0);
    T_STATIC(&d, ID_OW_L2, S(S_OW_NEW), 12, 84, 276, 9, 0);
    T_STATIC(&d, ID_OW_I2, L"", 12, 94, 276, 10, 0);
    T_CHECK(&d, ID_OW_ALL, S(S_OW_APPLYALL), 12, 109, 276, 10);
    T_BUTTON(&d, ID_OW_YES, S(S_OW_B_OVERWRITE), 60, 130, 56, 15);
    T_BUTTON(&d, ID_OW_NO, S(S_OW_B_SKIP), 120, 130, 56, 15);
    T_BUTTON(&d, ID_OW_REN, S(S_OW_B_RENAME), 180, 130, 56, 15);
    T_BUTTON(&d, IDCANCEL, S(S_CANCEL), 240, 130, 48, 15);
    INT_PTR r = dlgt_run(&d, owner, ow_proc, (LPARAM)&x);
    return r < 0 ? GZ_ANS_CANCEL : (int)r;
}

/* ======================================================================
 * Settings
 * ====================================================================== */

const cp_item g_cp_list[] = {
    { 0, S_CP_AUTO }, { 65001, S_CP_UTF8 }, { 949, S_CP_949 }, { 932, S_CP_932 }, { 936, S_CP_936 },
    { 950, S_CP_950 }, { 1252, S_CP_1252 }, { 437, S_CP_437 }, { 866, S_CP_866 }
};
const int g_cp_count = (int)(sizeof g_cp_list / sizeof g_cp_list[0]);

enum { ID_S_CP = 501, ID_S_OW, ID_S_LANG, ID_S_MKDIR, ID_S_OPEN, ID_S_THREADS, ID_S_ENGINE, ID_S_BENCH,
       ID_S_MENU, ID_S_ASSOC, ID_S_H1, ID_S_H2, ID_S_H3, ID_S_L1, ID_S_L2, ID_S_L3, ID_S_L4, ID_S_L5,
       ID_S_TYPES };

static const int k_thread_opts[] = { 0, 1, 2, 4, 6, 8, 12, 16, 24, 32 };

typedef struct { dlg_base b; int tiers[GZ_TIER_COUNT + 1]; int ntiers; int types_changed; wchar_t assoc[1024]; } sdlg;

static INT_PTR CALLBACK sdlg_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    INT_PTR ret;
    if (dlg_common(h, m, wp, lp, &ret)) return ret;
    sdlg *x = (sdlg *)GetWindowLongPtrW(h, DWLP_USER);
    switch (m) {
    case WM_INITDIALOG: {
        x = (sdlg *)lp;
        wcopy(x->assoc, g_set.assoc, GZ_COUNTOF(x->assoc));      /* restored on cancel */
        dlg_setup(h, &x->b, IDOK);
        set_bold(h, ID_S_H1); set_bold(h, ID_S_H2); set_bold(h, ID_S_H3);
        set_fg(h, ID_S_H1, FG_ACCENT); set_fg(h, ID_S_H2, FG_ACCENT); set_fg(h, ID_S_H3, FG_ACCENT);
        HWND c = GetDlgItem(h, ID_S_CP);
        for (int i = 0; i < g_cp_count; i++) {
            SendMessageW(c, CB_ADDSTRING, 0, (LPARAM)S(g_cp_list[i].sid));
            if (g_cp_list[i].cp == g_set.codepage) SendMessageW(c, CB_SETCURSEL, (WPARAM)i, 0);
        }
        add_overwrite_modes(GetDlgItem(h, ID_S_OW), g_set.overwrite);
        c = GetDlgItem(h, ID_S_LANG);
        SendMessageW(c, CB_ADDSTRING, 0, (LPARAM)S(S_S_LANG_AUTO));
        SendMessageW(c, CB_ADDSTRING, 0, (LPARAM)L"한국어");
        SendMessageW(c, CB_ADDSTRING, 0, (LPARAM)L"English");
        SendMessageW(c, CB_SETCURSEL, (WPARAM)g_set.lang, 0);
        CheckDlgButton(h, ID_S_MKDIR, g_set.smart_folder ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(h, ID_S_OPEN, g_set.open_folder ? BST_CHECKED : BST_UNCHECKED);
        c = GetDlgItem(h, ID_S_THREADS);
        wchar_t t[64];
        for (u32 i = 0; i < GZ_COUNTOF(k_thread_opts); i++) {
            if (k_thread_opts[i] == 0) wfmt(t, S(S_S_AUTO_N), cpu_threads());
            else wfmt(t, L"%d", k_thread_opts[i]);
            SendMessageW(c, CB_ADDSTRING, 0, (LPARAM)t);
            if (k_thread_opts[i] == g_set.threads) SendMessageW(c, CB_SETCURSEL, i, 0);
        }
        if (SendMessageW(c, CB_GETCURSEL, 0, 0) < 0) SendMessageW(c, CB_SETCURSEL, 0, 0);
        c = GetDlgItem(h, ID_S_ENGINE);
        x->ntiers = 0;
        wfmt(t, S(S_S_ENGINE_AUTO), gz_tier_name(g_cpu.tier));
        SendMessageW(c, CB_ADDSTRING, 0, (LPARAM)t);
        x->tiers[x->ntiers++] = -1;
        for (int tier = g_cpu.tier; tier >= 0; tier--) {
            if (!gz_cpu_tier_supported(tier)) continue;
            wfmt(t, L"%S", gz_tier_name(tier));
            SendMessageW(c, CB_ADDSTRING, 0, (LPARAM)t);
            if (tier == g_set.cpu_tier) SendMessageW(c, CB_SETCURSEL, (WPARAM)x->ntiers, 0);
            x->tiers[x->ntiers++] = tier;
        }
        if (SendMessageW(c, CB_GETCURSEL, 0, 0) < 0) SendMessageW(c, CB_SETCURSEL, 0, 0);
        int reg = shell_is_registered();
        CheckDlgButton(h, ID_S_MENU, (reg & 1) ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(h, ID_S_ASSOC, (reg & 2) ? BST_CHECKED : BST_UNCHECKED);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == ID_S_BENCH) { dlg_bench(h); return TRUE; }
        if (LOWORD(wp) == ID_S_TYPES) { if (dlg_assoc(h)) x->types_changed = 1; return TRUE; }
        if (LOWORD(wp) == IDOK) {
            int i = (int)SendDlgItemMessageW(h, ID_S_CP, CB_GETCURSEL, 0, 0);
            g_set.codepage = (i >= 0 && i < g_cp_count) ? g_cp_list[i].cp : 0;
            i = (int)SendDlgItemMessageW(h, ID_S_OW, CB_GETCURSEL, 0, 0);
            g_set.overwrite = i < 0 ? 0 : i;
            i = (int)SendDlgItemMessageW(h, ID_S_LANG, CB_GETCURSEL, 0, 0);
            if (i >= 0 && i != g_set.lang) { g_set.lang = i; msg_box(h, S(S_S_RESTART), MB_ICONINFORMATION); }
            g_set.smart_folder = IsDlgButtonChecked(h, ID_S_MKDIR) == BST_CHECKED;
            g_set.open_folder = IsDlgButtonChecked(h, ID_S_OPEN) == BST_CHECKED;
            i = (int)SendDlgItemMessageW(h, ID_S_THREADS, CB_GETCURSEL, 0, 0);
            g_set.threads = (i >= 0 && i < (int)GZ_COUNTOF(k_thread_opts)) ? k_thread_opts[i] : 0;
            i = (int)SendDlgItemMessageW(h, ID_S_ENGINE, CB_GETCURSEL, 0, 0);
            g_set.cpu_tier = (i >= 0 && i < x->ntiers) ? x->tiers[i] : -1;
            gz_dispatch_init(g_set.cpu_tier);
            int menu = IsDlgButtonChecked(h, ID_S_MENU) == BST_CHECKED;
            int assoc = IsDlgButtonChecked(h, ID_S_ASSOC) == BST_CHECKED;
            int reg = shell_is_registered();
            if (menu != ((reg & 1) != 0) || assoc != ((reg & 2) != 0) || (x->types_changed && (menu || assoc))) {
                if (menu || assoc) shell_register(assoc);
                else shell_unregister();
                if (assoc && !(reg & 2) && g_os.major * 100 + g_os.minor >= 602)
                    msg_box(h, S(S_S_ASSOC_WIN8), MB_ICONINFORMATION);
            }
            settings_save();
            EndDialog(h, 1);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) {
            wcopy(g_set.assoc, x->assoc, GZ_COUNTOF(g_set.assoc));
            EndDialog(h, 0);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

void dlg_settings(HWND owner)
{
    sdlg x;
    __builtin_memset(&x, 0, sizeof x);
    x.b.icon = IC_SETTINGS;
    wcopy(x.b.title, S(S_S_TITLE), 128);
    wfmt(x.b.sub, L"%s %s", S(S_APP), GZ_VERSION_W);
    x.b.hdr_dlu = 40;
    x.b.foot_dlu = 236;
    dlgt d;
    dlgt_begin(&d, S(S_S_TITLE), 300, 262, 0);
    T_STATIC(&d, ID_S_H1, S(S_S_GENERAL), 12, 44, 276, 10, 0);
    T_STATIC(&d, ID_S_L1, S(S_S_CODEPAGE), 18, 60, 110, 10, 0);
    T_COMBO(&d, ID_S_CP, 132, 58, 156, 120, CBS_DROPDOWNLIST);
    T_STATIC(&d, ID_S_L2, S(S_S_OVERWRITE), 18, 76, 110, 10, 0);
    T_COMBO(&d, ID_S_OW, 132, 74, 156, 90, CBS_DROPDOWNLIST);
    T_STATIC(&d, ID_S_L3, S(S_S_LANG), 18, 92, 110, 10, 0);
    T_COMBO(&d, ID_S_LANG, 132, 90, 156, 60, CBS_DROPDOWNLIST);
    T_CHECK(&d, ID_S_MKDIR, S(S_X_MAKEFOLDER), 18, 108, 276, 10);
    T_CHECK(&d, ID_S_OPEN, S(S_X_OPENFOLDER), 18, 122, 276, 10);
    T_STATIC(&d, ID_S_H2, S(S_S_PERF), 12, 142, 276, 10, 0);
    T_STATIC(&d, ID_S_L4, S(S_S_THREADS), 18, 158, 110, 10, 0);
    T_COMBO(&d, ID_S_THREADS, 132, 156, 156, 120, CBS_DROPDOWNLIST);
    T_STATIC(&d, ID_S_L5, S(S_S_ENGINE), 18, 174, 110, 10, 0);
    T_COMBO(&d, ID_S_ENGINE, 132, 172, 100, 120, CBS_DROPDOWNLIST);
    T_BUTTON(&d, ID_S_BENCH, S(S_B_RUN), 236, 171, 52, 14);
    T_STATIC(&d, ID_S_H3, S(S_S_SHELL), 12, 194, 276, 10, 0);
    T_CHECK(&d, ID_S_MENU, S(S_S_SHELL_MENU), 18, 208, 270, 10);
    T_CHECK(&d, ID_S_ASSOC, S(S_S_SHELL_ASSOC), 18, 221, 208, 10);
    T_BUTTON(&d, ID_S_TYPES, S(S_AS_BTN), 230, 219, 58, 14);
    T_BUTTON(&d, IDOK, S(S_BTN_OK), 180, 243, 52, 15);
    T_BUTTON(&d, IDCANCEL, S(S_CANCEL), 236, 243, 52, 15);
    dlgt_run(&d, owner, sdlg_proc, (LPARAM)&x);
}

/* ======================================================================
 * About
 * ====================================================================== */

enum { ID_A_TAG = 701, ID_A_L1, ID_A_V1, ID_A_L2, ID_A_V2, ID_A_L3, ID_A_V3, ID_A_L4, ID_A_V4, ID_A_COPY, ID_A_HOME };

static void feature_list(wchar_t *o)
{
    static const struct { u32 f; const wchar_t *n; } fl[] = {
        { CPUF_MMX, L"MMX" }, { CPUF_SSE, L"SSE" }, { CPUF_SSE2, L"SSE2" }, { CPUF_SSE3, L"SSE3" },
        { CPUF_SSSE3, L"SSSE3" }, { CPUF_SSE41, L"SSE4.1" }, { CPUF_SSE42, L"SSE4.2" }, { CPUF_PCLMUL, L"PCLMUL" },
        { CPUF_AESNI, L"AES-NI" }, { CPUF_AVX, L"AVX" }, { CPUF_AVX2, L"AVX2" }, { CPUF_BMI2, L"BMI2" },
        { CPUF_VPCLMUL, L"VPCLMULQDQ" }, { CPUF_VAES, L"VAES" }, { CPUF_SHA, L"SHA" }, { CPUF_AVX512, L"AVX-512" },
    };
    o[0] = 0;
    for (u32 i = 0; i < GZ_COUNTOF(fl); i++) {
        if (!(g_cpu.features & fl[i].f)) continue;
        if (o[0]) wcat(o, L" ", 512);
        wcat(o, fl[i].n, 512);
    }
    if ((g_cpu.features & CPUF_AVX_HW) && !(g_cpu.features & CPUF_AVX))
        wcat(o, strings_korean() ? L"  (AVX: OS 미지원)" : L"  (AVX: no OS support)", 512);
}

static INT_PTR CALLBACK about_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    INT_PTR ret;
    if (dlg_common(h, m, wp, lp, &ret)) return ret;
    switch (m) {
    case WM_INITDIALOG: {
        dlg_base *b = (dlg_base *)lp;
        dlg_setup(h, b, IDOK);
        for (int id = ID_A_L1; id <= ID_A_L4; id += 2) set_fg(h, id, FG_GRAY);
        set_fg(h, ID_A_COPY, FG_GRAY);
        set_fg(h, ID_A_TAG, FG_GRAY);
        wchar_t t[512];
        MultiByteToWideChar(CP_ACP, 0, g_cpu.brand, -1, t, 128);
        wchar_t th[32];
        wfmt(th, L"  ·  %d", cpu_threads());
        wcat(t, th, 512);
        wcat(t, strings_korean() ? L"스레드" : L" threads", 512);
        SetDlgItemTextW(h, ID_A_V1, t);
        wfmt(t, L"%S  ·  CRC %S  ·  %S", gz_dispatch_inflate_name(), gz_dispatch_crc_name(), gz_dispatch_aes_name());
        SetDlgItemTextW(h, ID_A_V2, t);
        SetDlgItemTextW(h, ID_A_V3, os_name(t));
        feature_list(t);
        SetDlgItemTextW(h, ID_A_V4, t);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == ID_A_HOME) { ShellExecuteW(h, L"open", GZ_HOMEPAGE, NULL, NULL, SW_SHOWNORMAL); return TRUE; }
        if (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL) { EndDialog(h, 0); return TRUE; }
        break;
    }
    return FALSE;
}

void dlg_about(HWND owner)
{
    dlg_base b;
    __builtin_memset(&b, 0, sizeof b);
    b.icon = IC_LOGO;
    b.icon_px = scale(56);
    wcopy(b.title, S(S_APP), 128);
#ifdef __x86_64__
    wfmt(b.sub, S(S_A_VERSION), GZ_VERSION_W, L"x64");
#else
    wfmt(b.sub, S(S_A_VERSION), GZ_VERSION_W, L"x86");
#endif
    b.hdr_dlu = 52;
    b.foot_dlu = 158;
    dlgt d;
    dlgt_begin(&d, S(S_A_TITLE), 290, 184, 0);
    T_STATIC(&d, ID_A_TAG, S(S_TAGLINE), 12, 54, 266, 10, 0);
    T_STATIC(&d, ID_A_L1, S(S_A_CPU), 12, 72, 58, 10, 0);
    T_STATIC(&d, ID_A_V1, L"", 72, 72, 206, 10, SS_ENDELLIPSIS);
    T_STATIC(&d, ID_A_L2, S(S_A_ENGINE), 12, 86, 58, 10, 0);
    T_STATIC(&d, ID_A_V2, L"", 72, 86, 206, 10, SS_ENDELLIPSIS);
    T_STATIC(&d, ID_A_L3, S(S_A_OS), 12, 100, 58, 10, 0);
    T_STATIC(&d, ID_A_V3, L"", 72, 100, 206, 10, 0);
    T_STATIC(&d, ID_A_L4, L"CPU", 12, 114, 58, 10, 0);
    T_STATIC(&d, ID_A_V4, L"", 72, 114, 206, 20, 0);
    T_STATIC(&d, ID_A_COPY, S(S_A_COPY), 12, 140, 266, 10, 0);
    T_BUTTON(&d, ID_A_HOME, S(S_A_HOME), 12, 165, 96, 15);
    T_BUTTON(&d, IDOK, S(S_CLOSE), 228, 165, 50, 15);
    dlgt_run(&d, owner, about_proc, (LPARAM)&b);
}

/* ======================================================================
 * Archive information
 * ====================================================================== */

static INT_PTR CALLBACK info_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    INT_PTR ret;
    if (dlg_common(h, m, wp, lp, &ret)) return ret;
    if (m == WM_INITDIALOG) {
        dlg_setup(h, (dlg_base *)lp, IDOK);
        for (int id = 801; id < 830; id += 2) if (GetDlgItem(h, id)) set_fg(h, id, FG_GRAY);
        return TRUE;
    }
    if (m == WM_COMMAND && (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL)) { EndDialog(h, 0); return TRUE; }
    return FALSE;
}

/* distinct entry methods ("Deflate, Store"), most frequent first, at most 4 */
static void method_summary(gz_archive *a, wchar_t *o, size_t cap)
{
    wchar_t m[6][48];
    u32 cnt[6] = { 0 };
    int nm = 0, more = 0;
    o[0] = 0;
    u32 step = a->n > 20000 ? a->n / 20000 : 1;          /* sample huge archives */
    for (u32 i = 0; i < a->n; i += step) {
        if (a->e[i].is_dir) continue;
        wchar_t t[96];
        gz_arc_method(a, &a->e[i], t, 96);
        if (!t[0]) continue;
        t[47] = 0;
        int k = 0;
        while (k < nm && wcmp(m[k], t)) k++;
        if (k == nm) {
            if (nm == 6) { more = 1; continue; }
            wcopy(m[nm++], t, 48);
        }
        cnt[k]++;
    }
    for (int shown = 0; shown < 4; shown++) {
        int best = -1;
        for (int k = 0; k < nm; k++) if (cnt[k] && (best < 0 || cnt[k] > cnt[best])) best = k;
        if (best < 0) break;
        if (shown) wcat(o, L", ", cap);
        wcat(o, m[best], cap);
        cnt[best] = 0;
    }
    if (nm > 4 || more) wcat(o, L", ...", cap);
    if (!o[0]) wcopy(o, L"-", cap);
}

static void enc_summary(gz_archive *a, wchar_t *o, size_t cap)
{
    int zc = 0, aes = 0, other = 0, strength = 0;
    for (u32 i = 0; i < a->n; i++) {
        const gz_entry *e = &a->e[i];
        if (e->enc == GZ_ENC_ZIPCRYPTO) zc = 1;
        else if (e->enc == GZ_ENC_AES) { aes = 1; if (e->aes_strength > strength) strength = e->aes_strength; }
        else if (e->enc) other = 1;
    }
    o[0] = 0;
    if (!a->has_enc && !a->headers_enc) { wcopy(o, S(S_I_NO), cap); return; }
    if (aes) { wchar_t t[24]; wfmt(t, L"AES-%d", strength ? 64 + 64 * strength : 256); wcat(o, t, cap); }
    if (zc) { if (o[0]) wcat(o, L", ", cap); wcat(o, L"ZipCrypto", cap); }
    if (other || !o[0]) { if (o[0]) wcat(o, L", ", cap); wcat(o, S(S_I_YES), cap); }
    if (a->headers_enc) { wcat(o, L"  (", cap); wcat(o, S(S_I_HDRENC), cap); wcat(o, L")", cap); }
}

void dlg_info(HWND owner, gz_handle *hd)
{
    if (!hd) return;
    gz_archive *a = hd->arc;
    dlg_base b;
    __builtin_memset(&b, 0, sizeof b);
    b.icon = IC_INFO;
    wcopy(b.title, S(S_I_TITLE), 128);
    wcopy(b.sub, hd->name, 512);
    b.hdr_dlu = 40;
    wchar_t v[12][300], x1[40], x2[40], x3[40];
    int lab[12], n = 0;
    if (hd->parent || hd->temp) wcopy(v[n], hd->name, 300);      /* nested: "outer.zip/inner.tar" */
    else path_dir(v[n], hd->path, 300);
    lab[n++] = S_I_PATH;
    wfmt(v[n], L"%S", gz_arc_type_name(a));
    if (a->solid) { wcat(v[n], L"  (", 300); wcat(v[n], S(S_I_SOLID), 300); wcat(v[n], L")", 300); }
    lab[n++] = S_I_FORMAT;
    fmt_size(x1, a->src_size); fmt_thousands(x2, a->src_size);
    wfmt(v[n], L"%s (%s B)", x1, x2); lab[n++] = S_I_FILESIZE;
    if (a->nvols) {
        wfmt(v[n], L"%d", (int)a->nvols + 1);
        lab[n++] = S_I_VOLUMES;
    }
    fmt_thousands(x1, a->nfiles); fmt_thousands(x2, a->ndirs);
    wfmt(v[n], strings_korean() ? L"파일 %s개, 폴더 %s개" : L"%s files, %s folders", x1, x2); lab[n++] = S_I_CONTENTS;
    fmt_size(x1, a->total_usize); fmt_thousands(x2, a->total_usize);
    wfmt(v[n], L"%s (%s B)", x1, x2); lab[n++] = S_I_USIZE;
    if (a->total_usize) {
        u64 pct = a->total_csize * 1000 / (a->total_usize ? a->total_usize : 1);
        fmt_size(x3, a->total_csize);
        wfmt(v[n], L"%d.%d%%  (%s)", (int)(pct / 10), (int)(pct % 10), x3);
    } else wcopy(v[n], L"-", 300);
    lab[n++] = S_I_RATIO;
    method_summary(a, v[n], 300); lab[n++] = S_I_METHOD;
    enc_summary(a, v[n], 300); lab[n++] = S_I_ENC;
    {
        const wchar_t *cpn = S(S_CP_AUTO);
        for (int i = 0; i < g_cp_count; i++) if (g_cp_list[i].cp == a->used_cp) cpn = S(g_cp_list[i].sid);
        if (a->used_cp && cpn == S(S_CP_AUTO)) { wfmt(x1, L"CP%d", a->used_cp); cpn = x1; }
        if (a->any_utf8 && !a->any_legacy) cpn = S(S_CP_UTF8);
        wfmt(v[n], L"%s%s", cpn, a->codepage == 0 ? (strings_korean() ? L"  (자동 감지)" : L"  (auto)") : L"");
        lab[n++] = S_I_CP;
    }
    if (a->sfx_shift) {
        fmt_size(x1, a->sfx_shift);
        wfmt(v[n], S(S_I_SFX), x1);
        lab[n++] = -1;
    }
    int has_comment = a->comment && a->comment[0];
    int y = 46;
    dlgt d;
    int h = 46 + n * 13 + (has_comment ? 62 : 0) + 6;
    b.foot_dlu = h;
    dlgt_begin(&d, S(S_I_TITLE), 300, h + 28, 0);
    for (int i = 0; i < n; i++) {
        if (lab[i] >= 0) T_STATIC(&d, 801 + i * 2, S(lab[i]), 12, y, 70, 10, 0);
        T_STATIC(&d, 802 + i * 2, v[i], lab[i] >= 0 ? 86 : 12, y, lab[i] >= 0 ? 202 : 276, 10,
                 i == 0 ? SS_PATHELLIPSIS : SS_ENDELLIPSIS);
        y += 13;
    }
    if (has_comment) {
        T_STATIC(&d, 840, S(S_I_COMMENT), 12, y + 2, 276, 10, 0);
        /* convert lone \n to \r\n for the edit control */
        size_t cl = wlen(a->comment);
        wchar_t *cc = (wchar_t *)mem_alloc((cl * 2 + 2) * sizeof(wchar_t));
        size_t o = 0;
        for (size_t i = 0; i < cl && cc; i++) {
            if (a->comment[i] == '\n' && (i == 0 || a->comment[i - 1] != '\r')) cc[o++] = '\r';
            cc[o++] = a->comment[i];
        }
        if (cc) cc[o] = 0;
        dlgt_item(&d, 841, DA_EDIT, 0, cc ? cc : L"", 12, y + 14, 276, 44,
                  ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE);
        mem_free(cc);
    }
    T_BUTTON(&d, IDOK, S(S_CLOSE), 238, h + 7, 50, 15);
    dlgt_run(&d, owner, info_proc, (LPARAM)&b);
}

/* ======================================================================
 * Result / error report
 * ====================================================================== */

typedef struct { dlg_base b; ui_job *u; } rdlg;

static INT_PTR CALLBACK result_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    INT_PTR ret;
    if (dlg_common(h, m, wp, lp, &ret)) return ret;
    rdlg *x = (rdlg *)GetWindowLongPtrW(h, DWLP_USER);
    switch (m) {
    case WM_INITDIALOG: {
        x = (rdlg *)lp;
        dlg_setup(h, &x->b, IDOK);
        set_fg(h, 901, FG_GRAY);
        HWND lv = GetDlgItem(h, 902);
        if (lv) {
            gfx_set_theme(lv, L"Explorer");
            SendMessageW(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP);
            RECT r;
            GetClientRect(lv, &r);
            LVCOLUMNW c;
            __builtin_memset(&c, 0, sizeof c);
            c.mask = LVCF_TEXT | LVCF_WIDTH;
            c.cx = (r.right - r.left) * 58 / 100;
            c.pszText = (wchar_t *)S(S_COL_NAME);
            SendMessageW(lv, LVM_INSERTCOLUMNW, 0, (LPARAM)&c);
            c.cx = (r.right - r.left) - c.cx - GetSystemMetrics(SM_CXVSCROLL);
            c.pszText = (wchar_t *)S(S_R_PROBLEMS);
            SendMessageW(lv, LVM_INSERTCOLUMNW, 1, (LPARAM)&c);
            u32 nl = gz_job_log_count(x->u->j), row = 0;
            for (u32 i = 0; i < nl && row < 5000; i++) {
                const gz_log *l = gz_job_log_at(x->u->j, i);
                if (!l || l->level < GZ_LOG_WARN) continue;
                LVITEMW it;
                __builtin_memset(&it, 0, sizeof it);
                it.mask = LVIF_TEXT;
                it.iItem = (int)row;
                it.pszText = l->name;
                SendMessageW(lv, LVM_INSERTITEMW, 0, (LPARAM)&it);
                wchar_t t[600];
                wcopy(t, err_text(l->code), 600);
                if (l->detail && l->detail[0]) { wcat(t, L"  (", 600); wcat(t, l->detail, 590); wcat(t, L")", 600); }
                it.iSubItem = 1;
                it.pszText = t;
                SendMessageW(lv, LVM_SETITEMTEXTW, row, (LPARAM)&it);
                row++;
            }
        }
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == 903) {
            ui_job *u = x->u;
            if (u->op == OP_COMPRESS) {
                wchar_t dir[MAX_PATH * 2];
                path_dir(dir, u->out, GZ_COUNTOF(dir));
                open_in_explorer(dir, u->out);
            } else {
                const wchar_t *d = u->j ? gz_job_dest(u->j) : 0;
                open_in_explorer(d ? d : u->dest, 0);
            }
            return TRUE;
        }
        if (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL) { EndDialog(h, 0); return TRUE; }
        break;
    }
    return FALSE;
}

void dlg_errors(HWND owner, ui_job *u)
{
    rdlg x;
    __builtin_memset(&x, 0, sizeof x);
    x.u = u;
    u32 nprob = ui_job_problems(u);
    wcopy(x.b.title, S(S_R_TITLE), 128);
    if (u->result == GZ_E_CANCEL) { x.b.icon = IC_WARN; wcopy(x.b.sub, S(S_R_CANCELED), 512); }
    else if (nprob || u->result) {
        x.b.icon = IC_ERROR;
        wfmt(x.b.sub, S(S_R_ERRORS), nprob ? nprob : 1);
        x.b.sub_red = 1;
    } else {
        x.b.icon = IC_CHECK;
        wcopy(x.b.sub, u->op == OP_TEST ? S(S_R_TEST_OK) : u->op == OP_COMPRESS ? S(S_R_CREATED) : S(S_R_TITLE), 512);
    }
    x.b.hdr_dlu = 40;
    wchar_t st[200], a[32], b[32], c[32], e[32];
    u64 ms = u->fin.elapsed_ms;
    fmt_thousands(a, u->fin.done_files);
    fmt_size(b, u->fin.done_bytes);
    fmt_duration(c, (u32)(ms / 1000));
    if (ms < 10000) wfmt(c, L"%d.%02d s", (int)(ms / 1000), (int)(ms % 1000) / 10);
    fmt_speed(e, ms ? u->fin.done_bytes * 1000 / ms : u->fin.done_bytes);
    wfmt(st, S(S_R_STATS), a, b, c, e);
    int list = nprob > 0;
    int h = list ? 190 : 62;
    x.b.foot_dlu = h;
    dlgt d;
    dlgt_begin(&d, S(S_R_TITLE), 320, h + 28, 0);
    T_STATIC(&d, 901, st, 12, 46, 296, 10, 0);
    if (list)
        dlgt_item(&d, 902, 0, WC_LISTVIEWW, L"", 12, 62, 296, 122,
                  LVS_REPORT | LVS_NOSORTHEADER | LVS_SHOWSELALWAYS | WS_TABSTOP | WS_BORDER, 0);
    if (u->op != OP_TEST && u->result != GZ_E_CANCEL) T_BUTTON(&d, 903, S(S_R_OPENFOLDER), 12, h + 7, 60, 15);
    T_BUTTON(&d, IDOK, S(S_CLOSE), 258, h + 7, 50, 15);
    dlgt_run(&d, owner, result_proc, (LPARAM)&x);
}

/* ======================================================================
 * Benchmark: every supported tier, Deflate + CRC32
 * ====================================================================== */

#define WM_APP_BENCH (WM_APP + 20)

typedef struct {
    dlg_base b;
    HWND h;
    HANDLE th;
    volatile LONG stop;
    u64 inf[GZ_TIER_COUNT], crc[GZ_TIER_COUNT];
    int state[GZ_TIER_COUNT];   /* 0 pending, 1 done, 2 unsupported */
    int running;
} bdlg;

typedef struct { const u8 *p; u32 left; u64 out; } bmem;
static int b_read(void *c, u8 *buf, u32 cap, u32 *got)
{
    bmem *m = (bmem *)c;
    u32 n = m->left < cap ? m->left : cap;
    __builtin_memcpy(buf, m->p, n);
    m->p += n; m->left -= n;
    *got = n;
    return 0;
}
static int b_write(void *c, const u8 *p, size_t n) { (void)p; ((bmem *)c)->out += n; return 0; }

static u64 qpc(void) { LARGE_INTEGER l; QueryPerformanceCounter(&l); return (u64)l.QuadPart; }
static u64 qpf(void) { LARGE_INTEGER l; QueryPerformanceFrequency(&l); return (u64)l.QuadPart; }

static DWORD WINAPI bench_thread(void *arg)
{
    bdlg *x = (bdlg *)arg;
    const u8 *cp;
    u32 cn, raw;
    gfx_asset_stream(&cp, &cn, &raw);
    gz_inflater *z = gz_inflater_new();
    u8 *buf = (u8 *)gz_alloc_big(4u << 20);
    u64 f = qpf();
    for (u32 i = 0; buf && i < (4u << 20); i++) buf[i] = (u8)(i * 2654435761u >> 13);
    for (int t = GZ_TIER_COUNT - 1; t >= 0 && !x->stop; t--) {
        if (!gz_cpu_tier_supported(t) || !z || !cp) { x->state[t] = 2; PostMessageW(x->h, WM_APP_BENCH, 0, 0); continue; }
        gz_dispatch_init(t);
        u64 t0 = qpc(), out = 0;
        int runs = 0;
        do {
            bmem m = { cp, cn, 0 };
            gz_stream_io io = { b_read, b_write, &m };
            gz_inflate_run(z, &io, 0);
            out += m.out;
            runs++;
        } while ((qpc() - t0) < f / 3 && !x->stop);
        u64 dt = qpc() - t0;
        x->inf[t] = dt ? out * f / dt : 0;
        t0 = qpc();
        out = 0;
        u32 c = 0;
        do { c = gz_crc32(c, buf, 4u << 20); out += 4u << 20; } while ((qpc() - t0) < f / 4 && !x->stop);
        dt = qpc() - t0;
        x->crc[t] = dt ? out * f / dt : 0;
        x->state[t] = 1;
        PostMessageW(x->h, WM_APP_BENCH, 0, 0);
        (void)runs;
    }
    gz_dispatch_init(g_set.cpu_tier);
    gz_inflater_free(z);
    gz_free_big(buf, 4u << 20);
    PostMessageW(x->h, WM_APP_BENCH, 1, 0);
    return 0;
}

static void bench_fill(HWND h, bdlg *x)
{
    HWND lv = GetDlgItem(h, 601);
    SendMessageW(lv, LVM_DELETEALLITEMS, 0, 0);
    int row = 0;
    for (int t = GZ_TIER_COUNT - 1; t >= 0; t--) {
#ifdef __x86_64__
        if (t < GZ_TIER_SSE2) continue;
#endif
        wchar_t n[64], a[40], b[40];
        LVITEMW it;
        __builtin_memset(&it, 0, sizeof it);
        it.mask = LVIF_TEXT;
        it.iItem = row;
        wfmt(n, L"%S", gz_tier_name(t));
        it.pszText = n;
        SendMessageW(lv, LVM_INSERTITEMW, 0, (LPARAM)&it);
        if (x->state[t] == 1) { fmt_speed(a, x->inf[t]); fmt_speed(b, x->crc[t]); }
        else if (x->state[t] == 2) { wcopy(a, L"-", 40); wcopy(b, L"-", 40); }
        else { wcopy(a, L"", 40); wcopy(b, L"", 40); }
        it.iSubItem = 1; it.pszText = a;
        SendMessageW(lv, LVM_SETITEMTEXTW, (WPARAM)row, (LPARAM)&it);
        it.iSubItem = 2; it.pszText = b;
        SendMessageW(lv, LVM_SETITEMTEXTW, (WPARAM)row, (LPARAM)&it);
        it.iSubItem = 3;
        it.pszText = (wchar_t *)(x->state[t] == 2 ? S(S_B_UNSUPPORTED) : (t == g_cpu.active ? S(S_B_CURRENT) : L""));
        SendMessageW(lv, LVM_SETITEMTEXTW, (WPARAM)row, (LPARAM)&it);
        row++;
    }
}

static INT_PTR CALLBACK bench_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    INT_PTR ret;
    if (dlg_common(h, m, wp, lp, &ret)) return ret;
    bdlg *x = (bdlg *)GetWindowLongPtrW(h, DWLP_USER);
    switch (m) {
    case WM_INITDIALOG: {
        x = (bdlg *)lp;
        x->h = h;
        dlg_setup(h, &x->b, 602);
        set_fg(h, 603, FG_GRAY);
        HWND lv = GetDlgItem(h, 601);
        gfx_set_theme(lv, L"Explorer");
        SendMessageW(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);
        RECT r;
        GetClientRect(lv, &r);
        int w = r.right - r.left;
        static const int pct[4] = { 22, 25, 25, 28 };
        int sid[4] = { S_B_ENGINE, S_B_INFLATE, S_B_CRC, -1 };
        for (int i = 0; i < 4; i++) {
            LVCOLUMNW c;
            __builtin_memset(&c, 0, sizeof c);
            c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
            c.fmt = (i == 1 || i == 2) ? LVCFMT_RIGHT : LVCFMT_LEFT;
            c.cx = w * pct[i] / 100 - (i == 3 ? 4 : 0);
            c.pszText = sid[i] >= 0 ? (wchar_t *)S(sid[i]) : (wchar_t *)L"";
            SendMessageW(lv, LVM_INSERTCOLUMNW, (WPARAM)i, (LPARAM)&c);
        }
        bench_fill(h, x);
        return TRUE;
    }
    case WM_APP_BENCH:
        bench_fill(h, x);
        if (wp == 1) {
            x->running = 0;
            SetDlgItemTextW(h, 602, S(S_B_RUN));
            EnableWindow(GetDlgItem(h, 602), TRUE);
            if (x->th) { CloseHandle(x->th); x->th = 0; }
        }
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wp) == 602 && !x->running) {
            x->running = 1;
            x->stop = 0;
            for (int t = 0; t < GZ_TIER_COUNT; t++) x->state[t] = 0;
            SetDlgItemTextW(h, 602, S(S_B_RUNNING));
            EnableWindow(GetDlgItem(h, 602), FALSE);
            x->th = CreateThread(NULL, 0, bench_thread, x, 0, NULL);
            return TRUE;
        }
        if (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL) {
            if (x->running) {
                x->stop = 1;
                WaitForSingleObject(x->th, INFINITE);
                CloseHandle(x->th);
                x->th = 0;
                gz_dispatch_init(g_set.cpu_tier);
            }
            EndDialog(h, 0);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

void dlg_bench(HWND owner)
{
    bdlg x;
    __builtin_memset(&x, 0, sizeof x);
    x.b.icon = IC_BENCH;
    wcopy(x.b.title, S(S_B_TITLE), 128);
    MultiByteToWideChar(CP_ACP, 0, g_cpu.brand, -1, x.b.sub, 128);
    x.b.hdr_dlu = 40;
    x.b.foot_dlu = 176;
    dlgt d;
    dlgt_begin(&d, S(S_B_TITLE), 300, 202, 0);
    T_STATIC(&d, 603, S(S_B_DESC), 12, 44, 276, 18, 0);
    dlgt_item(&d, 601, 0, WC_LISTVIEWW, L"", 12, 64, 276, 104,
              LVS_REPORT | LVS_NOSORTHEADER | LVS_SINGLESEL | WS_BORDER, 0);
    T_BUTTON(&d, 602, S(S_B_RUN), 176, 183, 60, 15);
    T_BUTTON(&d, IDOK, S(S_CLOSE), 240, 183, 48, 15);
    dlgt_run(&d, owner, bench_proc, (LPARAM)&x);
}

/* ======================================================================
 * Opening an archive on a background thread (big listings, encrypted
 * headers, missing volumes, nested archives copied to a temporary file)
 * ====================================================================== */

typedef struct {
    dlg_base b;
    const wchar_t *path;
    gz_handle *parent;
    u32 idx;
    int cp;
    volatile long cancel;
    volatile long pct;          /* -1: unknown (marquee), else 0..1000 */
    gz_handle *h;
    int err;
    HWND hwnd;
    int phase;
} odlg;

static int o_ask(void *user, gz_ask *q)
{
    odlg *o = (odlg *)user;
    return (int)SendMessageW(o->hwnd, WM_APP_ASK, 0, (LPARAM)q);
}

static void o_progress(void *user, const gz_progress *p)
{
    odlg *o = (odlg *)user;
    if (!p->total_bytes) return;
    u64 d = p->done_bytes > p->total_bytes ? p->total_bytes : p->done_bytes;
    gz_atomic_store(&o->pct, (long)(d * 1000 / p->total_bytes));
}

static DWORD WINAPI open_thread(void *arg)
{
    odlg *o = (odlg *)arg;
    gz_open_req req;
    gz_callbacks cb;
    __builtin_memset(&req, 0, sizeof req);
    __builtin_memset(&cb, 0, sizeof cb);
    req.codepage = o->cp;
    req.cancel = &o->cancel;
    cb.user = o;
    cb.ask = o_ask;
    cb.progress = o_progress;
    if (o->parent) o->err = gz_handle_open_child(&o->h, o->parent, o->idx, &req, &cb);
    else o->err = gz_handle_open(&o->h, o->path, &req, &cb);
    if (o->cancel && !o->h) o->err = GZ_E_CANCEL;
    PostMessageW(o->hwnd, WM_APP_DONE, 0, 0);
    return 0;
}

static INT_PTR CALLBACK open_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    INT_PTR ret;
    odlg *o = (odlg *)GetWindowLongPtrW(h, DWLP_USER);
    if (m == WM_DRAWITEM && o && wp == 1001) {
        const DRAWITEMSTRUCT *di = (const DRAWITEMSTRUCT *)lp;
        RECT r = di->rcItem;
        gfx_fill(di->hDC, &r, C_BG);
        int rad = (r.bottom - r.top) / 2, w = r.right - r.left, seg = w / 4;
        gfx_round_rect(di->hDC, &r, rad, RGB(238, 238, 242), 0, 0);
        long pct = gz_atomic_load(&o->pct);
        RECT f = r;
        if (pct >= 0) {
            f.right = r.left + (int)(w * (i64)pct / 1000);
        } else {
            int x0 = (o->phase * w / 40) % (w + seg) - seg;
            f.left = r.left + (x0 < 0 ? 0 : x0);
            f.right = r.left + (x0 + seg > w ? w : x0 + seg);
        }
        if (f.right - f.left > rad * 2) gfx_round_rect(di->hDC, &f, rad, C_ACCENT, 0, 0);
        return TRUE;
    }
    if (dlg_common(h, m, wp, lp, &ret)) return ret;
    switch (m) {
    case WM_INITDIALOG: {
        o = (odlg *)lp;
        o->hwnd = h;
        dlg_setup(h, &o->b, IDCANCEL);
        HANDLE th = CreateThread(NULL, 1u << 20, open_thread, o, 0, NULL);
        if (!th) { o->err = GZ_E_NOMEM; EndDialog(h, 0); return TRUE; }
        SetPropW(h, L"gzth", th);
        SetTimer(h, 1, 400, NULL);
        return TRUE;
    }
    case WM_TIMER:
        if (wp == 1) { KillTimer(h, 1); ShowWindow(h, SW_SHOW); SetTimer(h, 2, 30, NULL); }
        else { o->phase++; InvalidateRect(GetDlgItem(h, 1001), NULL, FALSE); }
        return TRUE;
    case WM_APP_ASK: {
        int r = dlg_ask(h, (gz_ask *)lp);
        SetWindowLongPtrW(h, DWLP_MSGRESULT, r);
        return TRUE;
    }
    case WM_APP_DONE: {
        KillTimer(h, 1);
        KillTimer(h, 2);
        HANDLE th = RemovePropW(h, L"gzth");
        if (th) { WaitForSingleObject(th, INFINITE); CloseHandle(th); }
        EndDialog(h, 0);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDCANCEL) {
            gz_atomic_store(&o->cancel, 1);
            EnableWindow(GetDlgItem(h, IDCANCEL), FALSE);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

gz_handle *open_archive_ui(HWND owner, const wchar_t *path, gz_handle *parent, u32 idx, int codepage, int *err)
{
    odlg o;
    wchar_t full[MAX_PATH * 2];
    __builtin_memset(&o, 0, sizeof o);
    o.pct = -1;
    o.cp = codepage;
    if (parent) {
        if (idx >= parent->arc->n) { *err = GZ_E_FORMAT; return 0; }
        o.parent = parent;
        o.idx = idx;
        wcopy(o.b.sub, parent->arc->e[idx].base, 512);
    } else {
        DWORD fl = GetFullPathNameW(path, GZ_COUNTOF(full), full, NULL);
        if (!fl || fl >= GZ_COUNTOF(full)) wcopy(full, path, GZ_COUNTOF(full));
        o.path = full;
        wcopy(o.b.sub, path_base(full), 512);
    }
    o.b.icon = IC_OPEN;
    wcopy(o.b.title, S(S_P_OPENING), 128);
    o.b.hdr_dlu = 40;
    o.b.foot_dlu = 62;
    dlgt d;
    dlgt_begin(&d, S(S_APP), 260, 86, 0);
    {
        DWORD st;
        __builtin_memcpy(&st, d.buf + 12, 4);
        st &= ~WS_VISIBLE;
        __builtin_memcpy(d.buf + 12, &st, 4);
    }
    dlgt_item(&d, 1001, DA_STATIC, 0, L"", 12, 46, 236, 6, SS_OWNERDRAW, 0);
    T_BUTTON(&d, IDCANCEL, S(S_CANCEL), 198, 67, 50, 15);
    dlgt_run(&d, owner, open_proc, (LPARAM)&o);
    *err = o.h ? GZ_OK : (o.err ? o.err : GZ_E_FORMAT);
    return o.h;
}

/* ======================================================================
 * File associations: archive types grouped, checkboxes (tree view:
 * TVS_CHECKBOXES works with the comctl32 of Windows 2000)
 * ====================================================================== */

enum { ID_AS_TREE = 1101, ID_AS_DESC, ID_AS_ALL, ID_AS_NONE, ID_AS_DEF };
#define WM_APP_TVCHECK (WM_APP + 30)

typedef struct {
    dlg_base b;
    assoc_ext *l;
    int n;
    HTREEITEM grp[AG_COUNT];
    HTREEITEM *it;
    int changed;
} asdlg;

static const int k_ag_sid[AG_COUNT] = { S_AG_ZIP, S_AG_7Z, S_AG_RAR, S_AG_ALZ, S_AG_TAR, S_AG_ISO, S_AG_DISK,
                                        S_AG_OTHER, S_AG_EXE };

static void tv_check(HWND tv, HTREEITEM i, int on)
{
    TVITEMW t;
    t.mask = TVIF_STATE;
    t.hItem = i;
    t.stateMask = TVIS_STATEIMAGEMASK;
    t.state = INDEXTOSTATEIMAGEMASK(on ? 2 : 1);
    SendMessageW(tv, TVM_SETITEMW, 0, (LPARAM)&t);
}

static int tv_checked(HWND tv, HTREEITEM i)
{
    return ((UINT)SendMessageW(tv, TVM_GETITEMSTATE, (WPARAM)i, TVIS_STATEIMAGEMASK) >> 12) == 2;
}

/* group boxes follow their members */
static void as_sync_groups(HWND tv, asdlg *x)
{
    for (int g = 0; g < AG_COUNT; g++) {
        if (!x->grp[g]) continue;
        int all = 1;
        for (int i = 0; i < x->n; i++) if (x->l[i].group == g && !tv_checked(tv, x->it[i])) all = 0;
        tv_check(tv, x->grp[g], all);
    }
}

static void as_set(HWND tv, asdlg *x, int mode)       /* 0 none, 1 all, 2 defaults */
{
    for (int i = 0; i < x->n; i++) tv_check(tv, x->it[i], mode == 2 ? x->l[i].def_on : mode);
    as_sync_groups(tv, x);
}

static INT_PTR CALLBACK as_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    INT_PTR ret;
    if (dlg_common(h, m, wp, lp, &ret)) return ret;
    asdlg *x = (asdlg *)GetWindowLongPtrW(h, DWLP_USER);
    HWND tv = GetDlgItem(h, ID_AS_TREE);
    switch (m) {
    case WM_INITDIALOG: {
        x = (asdlg *)lp;
        dlg_setup(h, &x->b, IDOK);
        set_fg(h, ID_AS_DESC, FG_GRAY);
        tv = GetDlgItem(h, ID_AS_TREE);
        SetWindowLongW(tv, GWL_STYLE, GetWindowLongW(tv, GWL_STYLE) | TVS_CHECKBOXES);
        SendMessageW(tv, WM_SETFONT, (WPARAM)g_font.ui, 0);
        for (int g = 0; g < AG_COUNT; g++) {
            int cnt = 0;
            for (int i = 0; i < x->n; i++) cnt += x->l[i].group == g;
            if (!cnt) continue;
            TVINSERTSTRUCTW ins;
            __builtin_memset(&ins, 0, sizeof ins);
            ins.hParent = TVI_ROOT;
            ins.hInsertAfter = TVI_LAST;
            ins.item.mask = TVIF_TEXT | TVIF_PARAM;
            ins.item.pszText = (wchar_t *)S(k_ag_sid[g]);
            ins.item.lParam = -1 - g;
            x->grp[g] = (HTREEITEM)SendMessageW(tv, TVM_INSERTITEMW, 0, (LPARAM)&ins);
            for (int i = 0; i < x->n; i++) {
                if (x->l[i].group != g) continue;
                wchar_t t[20];
                int k = 0;
                t[k++] = '.';
                for (const char *p = x->l[i].ext; *p && k < 18; p++) t[k++] = (wchar_t)(u8)*p;
                t[k] = 0;
                ins.hParent = x->grp[g];
                ins.item.pszText = t;
                ins.item.lParam = i;
                x->it[i] = (HTREEITEM)SendMessageW(tv, TVM_INSERTITEMW, 0, (LPARAM)&ins);
            }
        }
        for (int i = 0; i < x->n; i++) tv_check(tv, x->it[i], assoc_wanted(x->l[i].ext));
        as_sync_groups(tv, x);
        for (int g = 0; g < AG_COUNT; g++)
            if (x->grp[g] && g != AG_EXE) SendMessageW(tv, TVM_EXPAND, TVE_EXPAND, (LPARAM)x->grp[g]);
        if (x->grp[0]) SendMessageW(tv, TVM_SELECTITEM, TVGN_FIRSTVISIBLE, (LPARAM)x->grp[0]);
        return TRUE;
    }
    case WM_NOTIFY: {
        NMHDR *nh = (NMHDR *)lp;
        if (nh->idFrom != ID_AS_TREE) break;
        if (nh->code == NM_CLICK) {
            TVHITTESTINFO hi;
            GetCursorPos(&hi.pt);
            ScreenToClient(tv, &hi.pt);
            HTREEITEM i = (HTREEITEM)SendMessageW(tv, TVM_HITTEST, 0, (LPARAM)&hi);
            if (i && (hi.flags & TVHT_ONITEMSTATEICON)) PostMessageW(h, WM_APP_TVCHECK, 0, (LPARAM)i);
        } else if (nh->code == TVN_KEYDOWN && ((NMTVKEYDOWN *)lp)->wVKey == VK_SPACE) {
            HTREEITEM i = (HTREEITEM)SendMessageW(tv, TVM_GETNEXTITEM, TVGN_CARET, 0);
            if (i) PostMessageW(h, WM_APP_TVCHECK, 0, (LPARAM)i);
        }
        break;
    }
    case WM_APP_TVCHECK: {
        /* the box has toggled by now: a group carries its members along */
        HTREEITEM i = (HTREEITEM)lp;
        int on = tv_checked(tv, i);
        for (int g = 0; g < AG_COUNT; g++) {
            if (x->grp[g] != i) continue;
            for (int k = 0; k < x->n; k++) if (x->l[k].group == g) tv_check(tv, x->it[k], on);
        }
        as_sync_groups(tv, x);
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_AS_ALL: as_set(tv, x, 1); return TRUE;
        case ID_AS_NONE: as_set(tv, x, 0); return TRUE;
        case ID_AS_DEF: as_set(tv, x, 2); return TRUE;
        case IDOK: {
            wchar_t s[1024];
            size_t k = 0;
            int all_default = 1;
            s[0] = 0;
            for (int i = 0; i < x->n; i++) {
                int on = tv_checked(tv, x->it[i]);
                if (on != x->l[i].def_on) all_default = 0;
                if (!on) continue;
                size_t el = 0;
                while (x->l[i].ext[el]) el++;
                if (k + el + 2 >= GZ_COUNTOF(s)) break;
                if (k) s[k++] = ' ';
                for (size_t c = 0; c < el; c++) s[k++] = (wchar_t)(u8)x->l[i].ext[c];
                s[k] = 0;
            }
            if (all_default) s[0] = 0;
            if (!s[0] && !all_default) wcopy(s, L"-", 4);      /* nothing chosen (not "defaults") */
            x->changed = wcmp(s, g_set.assoc) != 0;
            wcopy(g_set.assoc, s, GZ_COUNTOF(g_set.assoc));
            EndDialog(h, 1);
            return TRUE;
        }
        case IDCANCEL: EndDialog(h, 0); return TRUE;
        }
        break;
    }
    return FALSE;
}

int dlg_assoc(HWND owner)
{
    asdlg x;
    __builtin_memset(&x, 0, sizeof x);
    x.l = (assoc_ext *)mem_alloc(512 * sizeof(assoc_ext));
    x.it = (HTREEITEM *)mem_alloc(512 * sizeof(HTREEITEM));
    if (!x.l || !x.it) { mem_free(x.l); mem_free(x.it); return 0; }
    x.n = assoc_list(x.l, 512);
    x.b.icon = IC_SETTINGS;
    wcopy(x.b.title, S(S_AS_TITLE), 128);
    wcopy(x.b.sub, S(S_APP), 512);
    x.b.hdr_dlu = 40;
    x.b.foot_dlu = 218;
    dlgt d;
    dlgt_begin(&d, S(S_AS_TITLE), 280, 244, 0);
    T_STATIC(&d, ID_AS_DESC, S(S_AS_DESC), 12, 44, 256, 18, 0);
    dlgt_item(&d, ID_AS_TREE, 0, WC_TREEVIEWW, L"", 12, 64, 256, 148,
              TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS | WS_TABSTOP | WS_BORDER, 0);
    T_BUTTON(&d, ID_AS_ALL, S(S_AS_ALL), 12, 225, 50, 15);
    T_BUTTON(&d, ID_AS_NONE, S(S_AS_NONE), 66, 225, 50, 15);
    T_BUTTON(&d, ID_AS_DEF, S(S_AS_DEFAULT), 120, 225, 44, 15);
    T_BUTTON(&d, IDOK, S(S_BTN_OK), 172, 225, 46, 15);
    T_BUTTON(&d, IDCANCEL, S(S_CANCEL), 222, 225, 46, 15);
    dlgt_run(&d, owner, as_proc, (LPARAM)&x);
    mem_free(x.l);
    mem_free(x.it);
    return x.changed;
}
