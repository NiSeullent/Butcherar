/*
 * 고깃ZIP - main window
 *
 *  ┌──────────────────────────────────────────────────────────┐
 *  │ menu                                                      │
 *  │ [열기] [압축 풀기] [바로 풀기] │ [테스트] [파일 보기] [정보] │ ... │  toolbar
 *  │ [↑]  archive.zip › 문서 › 사진                            │  path bar
 *  │ folder tree │ file list (virtual list view)               │
 *  │ 파일 12개, 폴더 3개 · 원본 …            AVX2 엔진 · 8스레드 │  status bar
 *  └──────────────────────────────────────────────────────────┘
 */
#include "app.h"

enum {
    CMD_OPEN = 1000, CMD_CLOSE, CMD_INFO, CMD_EXIT, CMD_EXTRACT, CMD_HERE, CMD_SMART, CMD_EXTRACT_SEL,
    CMD_TEST, CMD_VIEW, CMD_UP, CMD_TREE, CMD_SELALL, CMD_SETTINGS, CMD_BENCH, CMD_HOME, CMD_ABOUT,
    CMD_CODEPAGE, CMD_WELCOME_EXTRACT,
    CMD_RECENT0 = 1100, CMD_CP0 = 1200
};

#define ID_TREE 10
#define ID_LIST 11

typedef struct { u8 kind; u8 st; i32 idx; } row;   /* kind 0 = "..", 1 = folder, 2 = file; st = sort scratch */

static struct {
    HWND hwnd, tb, path, tree, list, status, welcome;
    gz_open_arc *oa;
    i32 cur;
    row *rows;
    u32 nrows, caprows;
    int sort_col, sort_desc;
    int split, dragging;
    HIMAGELIST sysimg;
    int ico_folder, ico_folder_open, ico_root;
    HTREEITEM *titem;
    u8 *tpop;
    int syncing;
    HACCEL accel;
    HMENU menu, recent_menu, cp_menu;
    int tb_h, path_h, st_h;
} M;

static wchar_t s_txt[1024];

/* ======================================================================
 * shell icons / type names, cached per extension
 * ====================================================================== */

typedef struct { wchar_t ext[16]; int icon; wchar_t type[64]; } ext_info;
static ext_info s_ext[512];
static int s_next, s_recycle;

static const ext_info *ext_lookup(const wchar_t *base)
{
    const wchar_t *dot = gz_wcsrchr(base, '.');
    wchar_t e[16];
    int n = 0;
    if (dot && dot != base) {
        for (const wchar_t *p = dot; *p && n < 15; p++) {
            wchar_t c = *p;
            if (c >= 'A' && c <= 'Z') c += 32;
            e[n++] = c;
        }
    }
    e[n] = 0;
    for (int i = 0; i < s_next; i++) if (!wcmp(s_ext[i].ext, e)) return &s_ext[i];
    ext_info *x = s_next < 512 ? &s_ext[s_next++] : &s_ext[s_recycle++ & 511];
    wcopy(x->ext, e, 16);
    SHFILEINFOW fi;
    __builtin_memset(&fi, 0, sizeof fi);
    wchar_t probe[24];
    wcopy(probe, L"file", 24);
    wcat(probe, e, 24);
    SHGetFileInfoW(probe, FILE_ATTRIBUTE_NORMAL, &fi, sizeof fi,
                   SHGFI_USEFILEATTRIBUTES | SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_TYPENAME);
    x->icon = fi.iIcon;
    wcopy(x->type, fi.szTypeName[0] ? fi.szTypeName : S(S_FILE), 64);
    return x;
}

static void init_sysicons(void)
{
    SHFILEINFOW fi;
    __builtin_memset(&fi, 0, sizeof fi);
    M.sysimg = (HIMAGELIST)SHGetFileInfoW(L"folder", FILE_ATTRIBUTE_DIRECTORY, &fi, sizeof fi,
                                          SHGFI_USEFILEATTRIBUTES | SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
    M.ico_folder = fi.iIcon;
    SHGetFileInfoW(L"folder", FILE_ATTRIBUTE_DIRECTORY, &fi, sizeof fi,
                   SHGFI_USEFILEATTRIBUTES | SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_OPENICON);
    M.ico_folder_open = fi.iIcon;
}

/* ======================================================================
 * rows / sorting
 * ====================================================================== */

typedef int (WINAPI *StrCmpLogicalW_t)(LPCWSTR, LPCWSTR);
static StrCmpLogicalW_t s_logical;

static const wchar_t *row_name(const row *r)
{
    if (r->kind == 0) return L"..";
    if (r->kind == 1) return M.oa->arc->f[r->idx].base;
    return M.oa->arc->e[r->idx].base;
}

static int name_cmp(const wchar_t *a, const wchar_t *b)
{
    return s_logical ? s_logical(a, b) : lstrcmpiW(a, b);
}

static int u64cmp(u64 a, u64 b) { return a < b ? -1 : a > b; }

static int row_cmp(const row *a, const row *b)
{
    if (a->kind != b->kind) return (int)a->kind - (int)b->kind;
    if (a->kind == 0) return 0;
    gz_archive *ar = M.oa->arc;
    int r = 0;
    if (a->kind == 2) {
        const gz_entry *x = &ar->e[a->idx], *y = &ar->e[b->idx];
        switch (M.sort_col) {
        case 1: r = u64cmp(x->usize, y->usize); break;
        case 2: r = u64cmp(x->csize, y->csize); break;
        case 3: {   /* copy first: the second lookup may recycle the slot */
            wchar_t t[64];
            wcopy(t, ext_lookup(x->base)->type, 64);
            r = lstrcmpiW(t, ext_lookup(y->base)->type);
            break;
        }
        case 4: r = u64cmp(entry_filetime(x), entry_filetime(y)); break;
        case 5: r = u64cmp(x->usize ? x->csize * 1000 / x->usize : 0, y->usize ? y->csize * 1000 / y->usize : 0); break;
        case 6: {
            wchar_t mx[96], my[96];
            gz_arc_method(ar, x, mx, 96);
            gz_arc_method(ar, y, my, 96);
            r = lstrcmpiW(mx, my);
            break;
        }
        case 7: r = u64cmp(x->crc, y->crc); break;
        }
    } else if (M.sort_col == 4) {
        r = u64cmp(ar->f[a->idx].mtime, ar->f[b->idx].mtime);
    }
    if (!r) r = name_cmp(row_name(a), row_name(b));
    return M.sort_desc ? -r : r;
}

static void sort_rows(void)
{
    u32 n = M.nrows;
    row *tmp = (row *)mem_alloc((size_t)n * sizeof(row) + 8);
    if (!tmp) return;
    for (u32 w = 1; w < n; w *= 2) {
        for (u32 i = 0; i < n; i += 2 * w) {
            u32 mid = i + w < n ? i + w : n, hi = i + 2 * w < n ? i + 2 * w : n, a = i, b = mid, k = i;
            while (a < mid && b < hi) tmp[k++] = row_cmp(&M.rows[b], &M.rows[a]) < 0 ? M.rows[b++] : M.rows[a++];
            while (a < mid) tmp[k++] = M.rows[a++];
            while (b < hi) tmp[k++] = M.rows[b++];
        }
        __builtin_memcpy(M.rows, tmp, (size_t)n * sizeof(row));
    }
    mem_free(tmp);
}

static void push_row(u8 kind, i32 idx)
{
    if (M.nrows == M.caprows) {
        u32 nc = M.caprows ? M.caprows * 2 : 256;
        row *nr = (row *)gz_realloc(M.rows, nc * sizeof(row));
        if (!nr) return;
        M.rows = nr;
        M.caprows = nc;
    }
    M.rows[M.nrows].kind = kind;
    M.rows[M.nrows].st = 0;
    M.rows[M.nrows].idx = idx;
    M.nrows++;
}

static void update_status(void);
static void tree_select(i32 f);

static void update_header_arrows(void)
{
    HWND hd = (HWND)SendMessageW(M.list, LVM_GETHEADER, 0, 0);
    int n = (int)SendMessageW(hd, HDM_GETITEMCOUNT, 0, 0);
    for (int i = 0; i < n; i++) {
        HDITEMW h;
        h.mask = HDI_FORMAT;
        SendMessageW(hd, HDM_GETITEMW, (WPARAM)i, (LPARAM)&h);
        h.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (i == M.sort_col) h.fmt |= M.sort_desc ? HDF_SORTDOWN : HDF_SORTUP;
        SendMessageW(hd, HDM_SETITEMW, (WPARAM)i, (LPARAM)&h);
    }
}

static void navigate(i32 f, i32 focus_folder)
{
    if (!M.oa) return;
    gz_archive *a = M.oa->arc;
    if (f < 0 || f >= (i32)a->nf) f = 0;
    M.cur = f;
    M.nrows = 0;
    if (f != 0) push_row(0, a->f[f].parent);
    for (i32 s = a->f[f].first_sub; s >= 0; s = a->f[s].next_sib) push_row(1, s);
    for (i32 e = a->f[f].first_file; e >= 0; e = a->e[e].next) push_row(2, e);
    sort_rows();
    SendMessageW(M.list, LVM_SETITEMCOUNT, M.nrows, 0);
    ListView_SetItemState(M.list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    int sel = 0;
    if (focus_folder >= 0)
        for (u32 i = 0; i < M.nrows; i++)
            if (M.rows[i].kind == 1 && M.rows[i].idx == focus_folder) { sel = (int)i; break; }
    if (M.nrows) {
        ListView_SetItemState(M.list, sel, LVIS_FOCUSED | (focus_folder >= 0 ? LVIS_SELECTED : 0),
                              LVIS_FOCUSED | LVIS_SELECTED);
        ListView_EnsureVisible(M.list, sel, FALSE);
    }
    InvalidateRect(M.list, NULL, TRUE);
    InvalidateRect(M.path, NULL, FALSE);
    tree_select(f);
    update_status();
}

/* ======================================================================
 * tree (lazy population)
 * ====================================================================== */

static HTREEITEM tree_add(HTREEITEM parent, i32 f, const wchar_t *text, int icon, int sel_icon)
{
    gz_archive *a = M.oa->arc;
    TVINSERTSTRUCTW ins;
    __builtin_memset(&ins, 0, sizeof ins);
    ins.hParent = parent;
    ins.hInsertAfter = TVI_SORT;
    ins.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_CHILDREN;
    ins.item.pszText = (wchar_t *)text;
    ins.item.lParam = f;
    ins.item.iImage = icon;
    ins.item.iSelectedImage = sel_icon;
    ins.item.cChildren = a->f[f].nsub ? 1 : 0;
    HTREEITEM h = (HTREEITEM)SendMessageW(M.tree, TVM_INSERTITEMW, 0, (LPARAM)&ins);
    M.titem[f] = h;
    return h;
}

static void tree_populate(i32 f)
{
    gz_archive *a = M.oa->arc;
    if (M.tpop[f]) return;
    M.tpop[f] = 1;
    for (i32 s = a->f[f].first_sub; s >= 0; s = a->f[s].next_sib)
        tree_add(M.titem[f], s, a->f[s].base, M.ico_folder, M.ico_folder_open);
}

static void tree_build(void)
{
    gz_archive *a = M.oa->arc;
    SendMessageW(M.tree, WM_SETREDRAW, FALSE, 0);
    SendMessageW(M.tree, TVM_DELETEITEM, 0, (LPARAM)TVI_ROOT);
    mem_free(M.titem);
    mem_free(M.tpop);
    M.titem = (HTREEITEM *)mem_alloc((size_t)a->nf * sizeof(HTREEITEM) + 8);
    M.tpop = (u8 *)mem_alloc(a->nf + 8);
    if (!M.titem || !M.tpop) return;
    SHFILEINFOW fi;
    __builtin_memset(&fi, 0, sizeof fi);
    SHGetFileInfoW(M.oa->path, 0, &fi, sizeof fi, SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
    M.ico_root = fi.iIcon;
    tree_add(TVI_ROOT, 0, path_base(M.oa->path), M.ico_root, M.ico_root);
    tree_populate(0);
    SendMessageW(M.tree, TVM_EXPAND, TVE_EXPAND, (LPARAM)M.titem[0]);
    SendMessageW(M.tree, WM_SETREDRAW, TRUE, 0);
}

static void tree_select(i32 f)
{
    if (!M.titem || M.syncing) return;
    gz_archive *a = M.oa->arc;
    i32 chain[256];
    int n = 0;
    for (i32 x = f; x > 0 && n < 256; x = a->f[x].parent) chain[n++] = x;
    i32 p = 0;
    while (n--) {
        tree_populate(p);
        p = chain[n];
    }
    if (!M.titem[f]) return;
    M.syncing = 1;
    SendMessageW(M.tree, TVM_SELECTITEM, TVGN_CARET, (LPARAM)M.titem[f]);
    SendMessageW(M.tree, TVM_ENSUREVISIBLE, 0, (LPARAM)M.titem[f]);
    M.syncing = 0;
}

/* ======================================================================
 * status
 * ====================================================================== */

static u32 selected_rows(u64 *bytes)
{
    u32 n = 0;
    *bytes = 0;
    int i = -1;
    while ((i = (int)SendMessageW(M.list, LVM_GETNEXTITEM, (WPARAM)i, LVNI_SELECTED)) >= 0) {
        if ((u32)i >= M.nrows) break;
        if (M.rows[i].kind == 0) continue;
        n++;
        if (M.rows[i].kind == 2) *bytes += M.oa->arc->e[M.rows[i].idx].usize;
    }
    return n;
}

static void update_status(void)
{
    InvalidateRect(M.status, NULL, FALSE);
}

static void status_text(wchar_t *o)
{
    if (!M.oa) { wcopy(o, S(S_ST_READY), 256); return; }
    gz_archive *a = M.oa->arc;
    u64 sb;
    u32 ns = selected_rows(&sb);
    wchar_t x1[32], x2[32], x3[32], x4[32], x5[16];
    if (ns) {
        fmt_thousands(x1, ns);
        fmt_size(x2, sb);
        wfmt(o, S(S_ST_SELECTED), x1, x2);
        return;
    }
    fmt_thousands(x1, a->nfiles);
    fmt_thousands(x2, a->ndirs);
    fmt_size(x3, a->total_usize);
    fmt_size(x4, a->total_csize);
    u32 pct = a->total_usize ? (u32)(a->total_csize * 100 / a->total_usize) : 0;
    wfmt(x5, L"%d%%", pct);
    wfmt(o, S(S_ST_SUMMARY), x1, x2, x3, x4, x5);
}

/* ======================================================================
 * toolbar control
 * ====================================================================== */

typedef struct { int cmd, icon, sid, sep, needs; } tbbtn;
static const tbbtn k_tb[] = {
    { CMD_OPEN, IC_OPEN, S_TB_OPEN, 0, 0 },
    { CMD_EXTRACT, IC_EXTRACT, S_TB_EXTRACT, 0, 1 },
    { CMD_SMART, IC_EXTRACT_HERE, S_TB_HERE, 0, 1 },
    { CMD_TEST, IC_TEST, S_TB_TEST, 1, 1 },
    { CMD_VIEW, IC_VIEW, S_TB_VIEW, 0, 1 },
    { CMD_INFO, IC_INFO, S_TB_INFO, 0, 1 },
    { CMD_CODEPAGE, IC_CODEPAGE, S_TB_CODEPAGE, 1, 1 },
    { CMD_SETTINGS, IC_SETTINGS, S_TB_SETTINGS, 0, 0 },
};
#define NTB ((int)(sizeof k_tb / sizeof k_tb[0]))
static RECT s_tbr[NTB];
static int s_tb_hot = -1, s_tb_down = -1;

static void tb_layout(HDC dc)
{
    int x = scale(8), y = scale(4), h = M.tb_h - scale(9);
    for (int i = 0; i < NTB; i++) {
        if (k_tb[i].sep) x += scale(13);
        int w = gfx_text_w(dc, S(k_tb[i].sid), g_font.ui) + scale(22);
        if (w < scale(66)) w = scale(66);
        SetRect(&s_tbr[i], x, y, x + w, y + h);
        x += w + scale(2);
    }
}

static int tb_hit(int x, int y)
{
    POINT pt = { x, y };
    for (int i = 0; i < NTB; i++) if (PtInRect(&s_tbr[i], pt)) return i;
    return -1;
}

static LRESULT CALLBACK tb_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    switch (m) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC wdc = BeginPaint(h, &ps);
        RECT cr;
        GetClientRect(h, &cr);
        HDC dc = CreateCompatibleDC(wdc);
        HBITMAP bm = CreateCompatibleBitmap(wdc, cr.right, cr.bottom);
        HGDIOBJ ob = SelectObject(dc, bm);
        gfx_fill(dc, &cr, C_BG);
        RECT bl = { 0, cr.bottom - 1, cr.right, cr.bottom };
        gfx_fill(dc, &bl, C_BORDER);
        tb_layout(dc);
        int isz = scale(32);
        for (int i = 0; i < NTB; i++) {
            RECT r = s_tbr[i];
            int enabled = !k_tb[i].needs || M.oa;
            if (k_tb[i].sep) {
                RECT s = { r.left - scale(7), r.top + scale(10), r.left - scale(6), r.bottom - scale(10) };
                gfx_fill(dc, &s, C_BORDER);
            }
            if (enabled && (i == s_tb_hot || i == s_tb_down))
                gfx_round_rect(dc, &r, scale(6), i == s_tb_down ? C_TINT2 : C_TINT, 0, 0);
            int ix = r.left + (r.right - r.left - isz) / 2, iy = r.top + scale(5) + (i == s_tb_down ? 1 : 0);
            gfx_draw_icon(dc, k_tb[i].icon, ix, iy, isz, enabled ? 255 : 80);
            RECT tr = { r.left, iy + isz + scale(2), r.right, r.bottom };
            gfx_text(dc, S(k_tb[i].sid), &tr, g_font.ui, enabled ? C_TEXT : RGB(176, 178, 186),
                     DT_CENTER | DT_TOP | DT_SINGLELINE);
        }
        BitBlt(wdc, 0, 0, cr.right, cr.bottom, dc, 0, 0, SRCCOPY);
        SelectObject(dc, ob);
        DeleteObject(bm);
        DeleteDC(dc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_MOUSEMOVE: {
        int i = tb_hit((short)LOWORD(lp), (short)HIWORD(lp));
        if (i != s_tb_hot) {
            s_tb_hot = i;
            TRACKMOUSEEVENT t = { sizeof t, TME_LEAVE, h, 0 };
            TrackMouseEvent(&t);
            InvalidateRect(h, NULL, FALSE);
        }
        return 0;
    }
    case WM_MOUSELEAVE:
        s_tb_hot = -1;
        InvalidateRect(h, NULL, FALSE);
        return 0;
    case WM_LBUTTONDOWN: {
        int i = tb_hit((short)LOWORD(lp), (short)HIWORD(lp));
        if (i >= 0 && (!k_tb[i].needs || M.oa)) {
            s_tb_down = i;
            SetCapture(h);
            InvalidateRect(h, NULL, FALSE);
        }
        return 0;
    }
    case WM_LBUTTONUP: {
        int i = tb_hit((short)LOWORD(lp), (short)HIWORD(lp));
        int d = s_tb_down;
        s_tb_down = -1;
        ReleaseCapture();
        InvalidateRect(h, NULL, FALSE);
        if (d >= 0 && d == i) {
            if (k_tb[i].cmd == CMD_CODEPAGE) {
                POINT pt = { s_tbr[i].left, s_tbr[i].bottom };
                ClientToScreen(h, &pt);
                PostMessageW(GetParent(h), WM_COMMAND, MAKEWPARAM(CMD_CODEPAGE, 1), MAKELPARAM(pt.x, pt.y));
            } else {
                PostMessageW(GetParent(h), WM_COMMAND, (WPARAM)k_tb[i].cmd, 0);
            }
        }
        return 0;
    }
    }
    return DefWindowProcW(h, m, wp, lp);
}

/* ======================================================================
 * path bar (up button + breadcrumb)
 * ====================================================================== */

#define MAXSEG 48
static RECT s_seg_r[MAXSEG];
static i32 s_seg_f[MAXSEG];
static int s_nseg, s_path_hot = -2;
static RECT s_up_r;

static LRESULT CALLBACK path_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    switch (m) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC wdc = BeginPaint(h, &ps);
        RECT cr;
        GetClientRect(h, &cr);
        HDC dc = CreateCompatibleDC(wdc);
        HBITMAP bm = CreateCompatibleBitmap(wdc, cr.right, cr.bottom);
        HGDIOBJ ob = SelectObject(dc, bm);
        gfx_fill(dc, &cr, C_BG);
        RECT bl = { 0, cr.bottom - 1, cr.right, cr.bottom };
        gfx_fill(dc, &bl, C_BORDER);
        s_nseg = 0;
        if (M.oa) {
            gz_archive *a = M.oa->arc;
            int pad = scale(6), bh = cr.bottom - scale(10);
            SetRect(&s_up_r, pad, scale(5), pad + bh + scale(4), scale(5) + bh);
            int up_ok = M.cur != 0;
            if (up_ok && s_path_hot == -1) gfx_round_rect(dc, &s_up_r, scale(5), C_TINT, 0, 0);
            int is = scale(16);
            gfx_draw_icon(dc, IC_UP, s_up_r.left + (s_up_r.right - s_up_r.left - is) / 2,
                          s_up_r.top + (bh - is) / 2, is, up_ok ? 255 : 70);
            /* box around breadcrumb */
            RECT box = { s_up_r.right + scale(6), scale(5), cr.right - pad, scale(5) + bh };
            gfx_round_rect(dc, &box, scale(5), RGB(250, 250, 251), C_BORDER, 1);
            i32 chain[MAXSEG];
            int n = 0;
            for (i32 f = M.cur; f >= 0 && n < MAXSEG; f = a->f[f].parent) chain[n++] = f;
            int x = box.left + scale(6);
            int iy = box.top + (bh - is) / 2;
            ImageList_Draw(M.sysimg, M.ico_root, dc, x, iy, ILD_TRANSPARENT);
            x += is + scale(6);
            for (int k = n - 1; k >= 0 && s_nseg < MAXSEG; k--) {
                i32 f = chain[k];
                const wchar_t *t = f == 0 ? path_base(M.oa->path) : a->f[f].base;
                int w = gfx_text_w(dc, t, k == 0 ? g_font.ui_bold : g_font.ui) + scale(10);
                if (x + w > box.right - scale(4)) w = box.right - scale(4) - x;
                if (w <= 0) break;
                RECT r = { x, box.top + scale(2), x + w, box.bottom - scale(2) };
                if (s_path_hot == s_nseg && k != 0) gfx_round_rect(dc, &r, scale(4), C_TINT, 0, 0);
                gfx_text(dc, t, &r, k == 0 ? g_font.ui_bold : g_font.ui, k == 0 ? C_TEXT : C_TEXT2,
                         DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                s_seg_r[s_nseg] = r;
                s_seg_f[s_nseg++] = f;
                x += w;
                if (k) {
                    RECT ar = { x, box.top, x + scale(14), box.bottom };
                    gfx_text(dc, L"›", &ar, g_font.ui, RGB(170, 172, 180), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                    x += scale(14);
                }
            }
        }
        BitBlt(wdc, 0, 0, cr.right, cr.bottom, dc, 0, 0, SRCCOPY);
        SelectObject(dc, ob);
        DeleteObject(bm);
        DeleteDC(dc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_MOUSEMOVE: {
        POINT pt = { (short)LOWORD(lp), (short)HIWORD(lp) };
        int hot = -2;
        if (PtInRect(&s_up_r, pt)) hot = -1;
        for (int i = 0; i < s_nseg; i++) if (PtInRect(&s_seg_r[i], pt)) hot = i;
        if (hot != s_path_hot) {
            s_path_hot = hot;
            TRACKMOUSEEVENT t = { sizeof t, TME_LEAVE, h, 0 };
            TrackMouseEvent(&t);
            InvalidateRect(h, NULL, FALSE);
        }
        return 0;
    }
    case WM_MOUSELEAVE:
        s_path_hot = -2;
        InvalidateRect(h, NULL, FALSE);
        return 0;
    case WM_LBUTTONUP: {
        POINT pt = { (short)LOWORD(lp), (short)HIWORD(lp) };
        if (!M.oa) return 0;
        if (PtInRect(&s_up_r, pt)) { PostMessageW(GetParent(h), WM_COMMAND, CMD_UP, 0); return 0; }
        for (int i = 0; i < s_nseg; i++)
            if (PtInRect(&s_seg_r[i], pt) && s_seg_f[i] != M.cur) { navigate(s_seg_f[i], -1); break; }
        return 0;
    }
    }
    return DefWindowProcW(h, m, wp, lp);
}

/* ======================================================================
 * status bar
 * ====================================================================== */

static LRESULT CALLBACK status_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    if (m == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        RECT cr;
        GetClientRect(h, &cr);
        gfx_fill(dc, &cr, C_PANEL);
        RECT tl = { 0, 0, cr.right, 1 };
        gfx_fill(dc, &tl, C_BORDER);
        wchar_t t[256], e[128];
        status_text(t);
        int nth = g_set.threads > 0 ? g_set.threads : cpu_threads();
        wfmt(e, S(S_ST_ENGINE), gz_dispatch_inflate_name(), nth);
        int ew = gfx_text_w(dc, e, g_font.ui);
        int is = scale(16);
        RECT er = { cr.right - ew - scale(12), 0, cr.right - scale(12), cr.bottom };
        gfx_draw_icon(dc, IC_CPU, er.left - is - scale(6), (cr.bottom - is) / 2, is, 255);
        gfx_text(dc, e, &er, g_font.ui, C_TEXT2, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        RECT lr = { scale(12), 0, er.left - is - scale(18), cr.bottom };
        gfx_text(dc, t, &lr, g_font.ui, C_TEXT, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        EndPaint(h, &ps);
        return 0;
    }
    if (m == WM_ERASEBKGND) return 1;
    return DefWindowProcW(h, m, wp, lp);
}

/* ======================================================================
 * welcome screen
 * ====================================================================== */

static RECT s_w_open, s_w_extract, s_w_recent[6];
static int s_w_hot = -1;

static LRESULT CALLBACK welcome_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    switch (m) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC wdc = BeginPaint(h, &ps);
        RECT cr;
        GetClientRect(h, &cr);
        HDC dc = CreateCompatibleDC(wdc);
        HBITMAP bm = CreateCompatibleBitmap(wdc, cr.right, cr.bottom);
        HGDIOBJ ob = SelectObject(dc, bm);
        gfx_fill(dc, &cr, RGB(251, 251, 252));

        int nrec = 0;
        for (int i = 0; i < 6; i++) if (g_set.recent[i][0]) nrec++;
        int cw = scale(520);
        if (cw > cr.right - scale(40)) cw = cr.right - scale(40);
        int logo = scale(88);
        int total = logo + scale(14) + scale(34) + scale(22) + scale(24) + scale(150) + scale(20) +
                    (nrec ? scale(28) + nrec * scale(24) : 0);
        int y = (cr.bottom - total) / 2;
        if (y < scale(16)) y = scale(16);
        int cx = cr.right / 2;
        gfx_draw_icon(dc, IC_LOGO, cx - logo / 2, y, logo, 255);
        y += logo + scale(10);
        RECT t1 = { 0, y, cr.right, y + scale(38) };
        gfx_text(dc, S(S_APP), &t1, g_font.big, C_ACCENT, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        y += scale(38);
        RECT t2 = { 0, y, cr.right, y + scale(22) };
        gfx_text(dc, S(S_TAGLINE), &t2, g_font.ui, C_TEXT2, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        y += scale(22) + scale(20);

        RECT dz = { cx - cw / 2, y, cx + cw / 2, y + scale(150) };
        gfx_round_rect(dc, &dz, scale(14), C_BG, RGB(232, 205, 207), 1);
        RECT d1 = { dz.left, dz.top + scale(18), dz.right, dz.top + scale(42) };
        gfx_text(dc, S(S_W_DROP), &d1, g_font.title, C_TEXT, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        RECT d2 = { dz.left + scale(8), d1.bottom + scale(2), dz.right - scale(8), d1.bottom + scale(22) };
        gfx_text(dc, S(S_W_FORMATS), &d2, g_font.small, C_TEXT2, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        int bw = scale(150), bh = scale(38), gap = scale(12);
        int bx = cx - bw - gap / 2, by = dz.bottom - bh - scale(24);
        SetRect(&s_w_open, bx, by, bx + bw, by + bh);
        SetRect(&s_w_extract, cx + gap / 2, by, cx + gap / 2 + bw, by + bh);
        gfx_round_rect(dc, &s_w_open, scale(8), s_w_hot == 0 ? C_ACCENT_HOT : C_ACCENT, 0, 0);
        gfx_text(dc, S(S_W_OPEN), &s_w_open, g_font.ui_bold, RGB(255, 255, 255), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        gfx_round_rect(dc, &s_w_extract, scale(8), s_w_hot == 1 ? RGB(246, 246, 248) : C_BG,
                       s_w_hot == 1 ? RGB(196, 198, 206) : RGB(214, 216, 222), 1);
        gfx_text(dc, S(S_W_EXTRACT), &s_w_extract, g_font.ui_bold, C_TEXT, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        y = dz.bottom + scale(20);

        for (int i = 0; i < 6; i++) SetRectEmpty(&s_w_recent[i]);
        if (nrec) {
            RECT rh = { cx - cw / 2, y, cx + cw / 2, y + scale(22) };
            gfx_text(dc, S(S_W_RECENT), &rh, g_font.ui_bold, C_TEXT2, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            y += scale(26);
            for (int i = 0, k = 0; i < 6; i++) {
                if (!g_set.recent[i][0]) continue;
                RECT r = { cx - cw / 2, y, cx + cw / 2, y + scale(22) };
                if (s_w_hot == 10 + i) gfx_round_rect(dc, &r, scale(4), C_TINT, 0, 0);
                SHFILEINFOW fi;
                __builtin_memset(&fi, 0, sizeof fi);
                const ext_info *ei = ext_lookup(path_base(g_set.recent[i]));
                ImageList_Draw(M.sysimg, ei->icon, dc, r.left + scale(6), r.top + (scale(22) - scale(16)) / 2, ILD_TRANSPARENT);
                RECT tr = { r.left + scale(30), r.top, r.right - scale(6), r.bottom };
                wchar_t line[MAX_PATH + 8];
                wcopy(line, path_base(g_set.recent[i]), MAX_PATH);
                gfx_text(dc, line, &tr, g_font.ui, C_TEXT, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                int nw = gfx_text_w(dc, line, g_font.ui);
                wchar_t dir[MAX_PATH];
                path_dir(dir, g_set.recent[i], MAX_PATH);
                RECT dr = { tr.left + nw + scale(10), r.top, r.right - scale(6), r.bottom };
                gfx_text(dc, dir, &dr, g_font.small, RGB(160, 162, 170), DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_PATH_ELLIPSIS);
                s_w_recent[i] = r;
                y += scale(24);
                k++;
            }
        }
        /* engine line */
        wchar_t e[256];
        wfmt(e, L"%s:  %S  ·  CRC %S  ·  %S  ·  %d %s", S(S_W_ENGINE), gz_dispatch_inflate_name(),
             gz_dispatch_crc_name(), gz_dispatch_aes_name(), cpu_threads(), strings_korean() ? L"스레드" : L"threads");
        RECT er = { 0, cr.bottom - scale(30), cr.right, cr.bottom - scale(8) };
        gfx_text(dc, e, &er, g_font.small, RGB(160, 162, 170), DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        BitBlt(wdc, 0, 0, cr.right, cr.bottom, dc, 0, 0, SRCCOPY);
        SelectObject(dc, ob);
        DeleteObject(bm);
        DeleteDC(dc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_SIZE:
        InvalidateRect(h, NULL, FALSE);
        return 0;
    case WM_MOUSEMOVE: {
        POINT pt = { (short)LOWORD(lp), (short)HIWORD(lp) };
        int hot = -1;
        if (PtInRect(&s_w_open, pt)) hot = 0;
        else if (PtInRect(&s_w_extract, pt)) hot = 1;
        for (int i = 0; i < 6; i++) if (PtInRect(&s_w_recent[i], pt)) hot = 10 + i;
        if (hot != s_w_hot) {
            s_w_hot = hot;
            TRACKMOUSEEVENT t = { sizeof t, TME_LEAVE, h, 0 };
            TrackMouseEvent(&t);
            InvalidateRect(h, NULL, FALSE);
        }
        SetCursor(LoadCursorW(NULL, hot >= 0 ? IDC_HAND : IDC_ARROW));
        return 0;
    }
    case WM_SETCURSOR:
        if (LOWORD(lp) == HTCLIENT && s_w_hot >= 0) { SetCursor(LoadCursorW(NULL, IDC_HAND)); return TRUE; }
        break;
    case WM_MOUSELEAVE:
        s_w_hot = -1;
        InvalidateRect(h, NULL, FALSE);
        return 0;
    case WM_LBUTTONUP:
        if (s_w_hot == 0) PostMessageW(GetParent(h), WM_COMMAND, CMD_OPEN, 0);
        else if (s_w_hot == 1) PostMessageW(GetParent(h), WM_COMMAND, CMD_WELCOME_EXTRACT, 0);
        else if (s_w_hot >= 10) PostMessageW(GetParent(h), WM_COMMAND, (WPARAM)(CMD_RECENT0 + s_w_hot - 10), 0);
        return 0;
    }
    return DefWindowProcW(h, m, wp, lp);
}

/* ======================================================================
 * layout & menus
 * ====================================================================== */

static void layout(void)
{
    RECT cr;
    GetClientRect(M.hwnd, &cr);
    int w = cr.right, h = cr.bottom;
    int y = 0;
    MoveWindow(M.tb, 0, 0, w, M.tb_h, TRUE);
    y += M.tb_h;
    int bottom = h - M.st_h;
    MoveWindow(M.status, 0, bottom, w, M.st_h, TRUE);
    if (!M.oa) {
        ShowWindow(M.path, SW_HIDE);
        ShowWindow(M.tree, SW_HIDE);
        ShowWindow(M.list, SW_HIDE);
        MoveWindow(M.welcome, 0, y, w, bottom - y, TRUE);
        ShowWindow(M.welcome, SW_SHOW);
        return;
    }
    ShowWindow(M.welcome, SW_HIDE);
    MoveWindow(M.path, 0, y, w, M.path_h, TRUE);
    ShowWindow(M.path, SW_SHOW);
    y += M.path_h;
    int ch = bottom - y;
    if (g_set.show_tree) {
        if (M.split < scale(120)) M.split = scale(120);
        if (M.split > w - scale(200)) M.split = w - scale(200);
        if (M.split < scale(60)) M.split = scale(60);
        MoveWindow(M.tree, 0, y, M.split, ch, TRUE);
        ShowWindow(M.tree, SW_SHOW);
        MoveWindow(M.list, M.split + scale(4), y, w - M.split - scale(4), ch, TRUE);
    } else {
        ShowWindow(M.tree, SW_HIDE);
        MoveWindow(M.list, 0, y, w, ch, TRUE);
    }
    ShowWindow(M.list, SW_SHOW);
}

static void rebuild_recent_menu(void)
{
    while (GetMenuItemCount(M.recent_menu) > 0) DeleteMenu(M.recent_menu, 0, MF_BYPOSITION);
    int any = 0;
    for (int i = 0; i < 6; i++) {
        if (!g_set.recent[i][0]) continue;
        wchar_t t[MAX_PATH + 8];
        wfmt(t, L"&%d  ", i + 1);
        wcat(t, g_set.recent[i], MAX_PATH + 8);
        AppendMenuW(M.recent_menu, MF_STRING, (UINT_PTR)(CMD_RECENT0 + i), t);
        any = 1;
    }
    if (!any) AppendMenuW(M.recent_menu, MF_STRING | MF_GRAYED, 0, S(S_M_NORECENT));
}

static HMENU build_cp_menu(void)
{
    HMENU m = CreatePopupMenu();
    int cur = M.oa ? M.oa->arc->codepage : g_set.codepage;
    for (int i = 0; i < g_cp_count; i++) {
        AppendMenuW(m, MF_STRING | (g_cp_list[i].cp == cur ? MF_CHECKED : 0), (UINT_PTR)(CMD_CP0 + i),
                    S(g_cp_list[i].sid));
        if (i == 0) AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    }
    return m;
}

static void build_menu(void)
{
    HMENU bar = CreateMenu(), f = CreatePopupMenu(), a = CreatePopupMenu(), v = CreatePopupMenu(),
          o = CreatePopupMenu(), hp = CreatePopupMenu();
    M.recent_menu = CreatePopupMenu();
    AppendMenuW(f, MF_STRING, CMD_OPEN, S(S_M_OPEN));
    AppendMenuW(f, MF_POPUP, (UINT_PTR)M.recent_menu, S(S_M_RECENT));
    AppendMenuW(f, MF_STRING, CMD_CLOSE, S(S_M_CLOSE));
    AppendMenuW(f, MF_SEPARATOR, 0, NULL);
    AppendMenuW(f, MF_STRING, CMD_INFO, S(S_M_INFO));
    AppendMenuW(f, MF_SEPARATOR, 0, NULL);
    AppendMenuW(f, MF_STRING, CMD_EXIT, S(S_M_EXIT));
    AppendMenuW(a, MF_STRING, CMD_EXTRACT, S(S_M_EXTRACT));
    AppendMenuW(a, MF_STRING, CMD_SMART, S(S_M_EXTRACT_SMART));
    AppendMenuW(a, MF_STRING, CMD_HERE, S(S_M_EXTRACT_HERE));
    AppendMenuW(a, MF_STRING, CMD_EXTRACT_SEL, S(S_M_EXTRACT_SEL));
    AppendMenuW(a, MF_SEPARATOR, 0, NULL);
    AppendMenuW(a, MF_STRING, CMD_TEST, S(S_M_TEST));
    AppendMenuW(v, MF_STRING, CMD_VIEW, S(S_M_OPENITEM));
    AppendMenuW(v, MF_STRING, CMD_UP, S(S_M_UP));
    AppendMenuW(v, MF_STRING, CMD_SELALL, S(S_M_SELECTALL));
    AppendMenuW(v, MF_SEPARATOR, 0, NULL);
    AppendMenuW(v, MF_STRING | (g_set.show_tree ? MF_CHECKED : 0), CMD_TREE, S(S_M_TREE));
    M.cp_menu = build_cp_menu();
    AppendMenuW(v, MF_POPUP, (UINT_PTR)M.cp_menu, S(S_M_CODEPAGE));
    AppendMenuW(o, MF_STRING, CMD_SETTINGS, S(S_M_SETTINGS));
    AppendMenuW(o, MF_STRING, CMD_BENCH, S(S_M_BENCH));
    AppendMenuW(hp, MF_STRING, CMD_HOME, S(S_M_HOMEPAGE));
    AppendMenuW(hp, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hp, MF_STRING, CMD_ABOUT, S(S_M_ABOUT));
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)f, S(S_M_FILE));
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)a, S(S_M_ACTION));
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)v, S(S_M_VIEW));
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)o, S(S_M_OPTIONS));
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)hp, S(S_M_HELP));
    M.menu = bar;
    rebuild_recent_menu();
}

static void refresh_cp_menu(void)
{
    while (GetMenuItemCount(M.cp_menu) > 0) DeleteMenu(M.cp_menu, 0, MF_BYPOSITION);
    int cur = M.oa ? M.oa->arc->codepage : g_set.codepage;
    for (int i = 0; i < g_cp_count; i++) {
        AppendMenuW(M.cp_menu, MF_STRING | (g_cp_list[i].cp == cur ? MF_CHECKED : 0), (UINT_PTR)(CMD_CP0 + i),
                    S(g_cp_list[i].sid));
        if (i == 0) AppendMenuW(M.cp_menu, MF_SEPARATOR, 0, NULL);
    }
}

static void update_title(void)
{
    wchar_t t[MAX_PATH + 32];
    if (M.oa) wfmt(t, L"%s - %s", path_base(M.oa->path), S(S_APP));
    else wcopy(t, S(S_APP), 64);
    SetWindowTextW(M.hwnd, t);
}

/* ======================================================================
 * archive open / close / actions
 * ====================================================================== */

static void close_archive(void)
{
    if (!M.oa) return;
    SendMessageW(M.list, LVM_SETITEMCOUNT, 0, 0);
    SendMessageW(M.tree, TVM_DELETEITEM, 0, (LPARAM)TVI_ROOT);
    arc_close(M.oa);
    M.oa = 0;
    M.nrows = 0;
    mem_free(M.titem); M.titem = 0;
    mem_free(M.tpop); M.tpop = 0;
    layout();
    update_title();
    InvalidateRect(M.tb, NULL, FALSE);
    update_status();
}

static int open_archive(const wchar_t *path)
{
    int err;
    gz_open_arc *oa = open_archive_ui(M.hwnd, path, g_set.codepage, &err);
    if (!oa) {
        if (err == GZ_E_CANCEL) return 0;
        wchar_t t[MAX_PATH * 2 + 256];
        wfmt(t, L"%s\n\n%s\n%s", S(S_OPEN_FAIL), path, err == GZ_E_METHOD ? S(S_E_SPLIT) : err_text(err));
        msg_box(M.hwnd, t, MB_ICONWARNING);
        return 0;
    }
    close_archive();
    M.oa = oa;
    settings_add_recent(oa->path);
    settings_save();
    rebuild_recent_menu();
    refresh_cp_menu();
    update_title();
    layout();
    tree_build();
    navigate(0, -1);
    InvalidateRect(M.tb, NULL, FALSE);
    SetFocus(M.list);
    return 1;
}

static void cmd_open(void)
{
    wchar_t file[MAX_PATH * 2];
    wchar_t filter[256];
    file[0] = 0;
    int n = 0;
    const wchar_t *parts[] = { S(S_FILTER_ARC), L" (*.zip, *.tar, *.gz, *.tgz)", 0,
                               L"*.zip;*.zipx;*.jar;*.tar;*.gz;*.tgz;*.taz;*.exe", 0, S(S_FILTER_ALL), 0, L"*.*", 0 };
    for (u32 i = 0; i < GZ_COUNTOF(parts); i++) {
        if (!parts[i]) { filter[n++] = 0; continue; }
        for (const wchar_t *p = parts[i]; *p && n < 250; p++) filter[n++] = *p;
    }
    filter[n] = 0;
    OPENFILENAMEW of;
    __builtin_memset(&of, 0, sizeof of);
    of.lStructSize = sizeof of;
    of.hwndOwner = M.hwnd;
    of.lpstrFilter = filter;
    of.lpstrFile = file;
    of.nMaxFile = MAX_PATH * 2;
    of.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_EXPLORER;
    if (GetOpenFileNameW(&of)) open_archive(file);
}

/* selection -> entry mask */
static int collect_selection(u8 **mask, int *count)
{
    gz_archive *a = M.oa->arc;
    *count = 0;
    *mask = 0;
    u8 *m = (u8 *)mem_alloc(a->n + 8);
    if (!m) return 0;
    int i = -1, any = 0;
    while ((i = (int)SendMessageW(M.list, LVM_GETNEXTITEM, (WPARAM)i, LVNI_SELECTED)) >= 0) {
        if ((u32)i >= M.nrows) break;
        row *r = &M.rows[i];
        if (r->kind == 0) continue;
        any = 1;
        (*count)++;
        if (r->kind == 2) { m[r->idx] = 1; continue; }
        const wchar_t *fn = a->f[r->idx].name;
        size_t fl = wlen(fn);
        for (u32 k = 0; k < a->n; k++) {
            const wchar_t *n = a->e[k].name;
            if (prefix_ieq(n, fn, fl) && (n[fl] == '/' || n[fl] == 0)) m[k] = 1;
        }
    }
    if (!any) { mem_free(m); return 0; }
    *mask = m;
    return 1;
}

static void cmd_extract(int mode, int selected_only)
{
    if (!M.oa) return;
    u8 *mask = 0;
    int nsel = 0;
    collect_selection(&mask, &nsel);
    const wchar_t *strip = M.cur ? M.oa->arc->f[M.cur].name : 0;
    if (mode != X_DIALOG && !selected_only) { mem_free(mask); mask = 0; nsel = 0; }
    if (selected_only && !mask) { do_extract(M.hwnd, M.oa, mode, 0, 0, 0, 0); return; }
    do_extract(M.hwnd, M.oa, mode, 0, mask, strip, nsel);
    mem_free(mask);
    SetFocus(M.list);
}

/* %TEMP%\GogitZIP\<pid>: each running copy owns (and later deletes) only its own folder */
static int temp_root(wchar_t *o)
{
    DWORD n = GetTempPathW(MAX_PATH, o);
    if (!n || n >= MAX_PATH - 32) { o[0] = 0; return 0; }
    wchar_t t[32];
    wfmt(t, L"GogitZIP\\%u", (unsigned)GetCurrentProcessId());
    wcat(o, t, MAX_PATH);
    return 1;
}

static void view_entry(u32 idx)
{
    gz_archive *a = M.oa->arc;
    gz_entry *e = &a->e[idx];
    wchar_t dir[MAX_PATH * 2], t[24];
    if (!temp_root(dir)) return;
    wfmt(t, L"\\%08x", GetTickCount() ^ (idx * 2654435761u));
    wcat(dir, t, MAX_PATH * 2);
    gz_job *j = job_new(M.oa);
    if (!j) return;
    u8 *m = (u8 *)mem_alloc(a->n + 8);
    if (!m) { job_free(j); return; }
    m[idx] = 1;
    j->sel = m;
    j->strip = e->folder > 0 ? a->f[e->folder].name : 0;
    wcopy(j->dest, dir, GZ_COUNTOF(j->dest));
    j->overwrite = OW_ALL;
    j->threads = 1;
    int r = run_job_with_progress(M.hwnd, j);
    if (r == GZ_OK && !j->nerr) {
        wchar_t p[MAX_PATH * 4];
        if (job_out_path(j, e, p, GZ_COUNTOF(p)) <= 0) path_join(p, dir, e->base, GZ_COUNTOF(p));
        if ((INT_PTR)ShellExecuteW(M.hwnd, NULL, p, NULL, dir, SW_SHOWNORMAL) <= 32)
            ShellExecuteW(M.hwnd, L"openas", p, NULL, dir, SW_SHOWNORMAL);
    } else if (r != GZ_E_CANCEL) {
        dlg_errors(M.hwnd, j);
    }
    mem_free(m);
    job_free(j);
}

static void delete_tree(const wchar_t *dir)
{
    wchar_t pat[MAX_PATH * 2];
    path_join(pat, dir, L"*", GZ_COUNTOF(pat));
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!wcmp(fd.cFileName, L".") || !wcmp(fd.cFileName, L"..")) continue;
            wchar_t p[MAX_PATH * 2];
            path_join(p, dir, fd.cFileName, GZ_COUNTOF(p));
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                delete_tree(p);
            else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) RemoveDirectoryW(p);   /* junction: unlink only */
            else { SetFileAttributesW(p, FILE_ATTRIBUTE_NORMAL); DeleteFileW(p); }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryW(dir);
}

/* Remove %TEMP%\GogitZIP\<pid> folders left by copies that are no longer running
 * (crash, logoff, or a viewer that kept a file open when GogitZIP closed). */
static void sweep_stale_temp(void)
{
    wchar_t root[MAX_PATH], pat[MAX_PATH + 8];
    if (!temp_root(root)) return;
    wchar_t *b = (wchar_t *)path_base(root);
    if (b <= root) return;
    b[-1] = 0;                                         /* root = %TEMP%\GogitZIP */
    path_join(pat, root, L"*", GZ_COUNTOF(pat));
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD self = GetCurrentProcessId();
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            continue;
        const wchar_t *c = fd.cFileName;
        DWORD pid = 0;
        if (*c < '0' || *c > '9') continue;
        while (*c >= '0' && *c <= '9') pid = pid * 10 + (DWORD)(*c++ - '0');
        if (*c || pid == self) continue;
        int dead;
        HANDLE ph = OpenProcess(SYNCHRONIZE, FALSE, pid);
        if (ph) { dead = WaitForSingleObject(ph, 0) == WAIT_OBJECT_0; CloseHandle(ph); }
        else dead = GetLastError() == ERROR_INVALID_PARAMETER;   /* no such process */
        if (dead) {
            wchar_t p[MAX_PATH * 2];
            path_join(p, root, fd.cFileName, GZ_COUNTOF(p));
            delete_tree(p);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void activate_row(int i)
{
    if (i < 0 || (u32)i >= M.nrows) return;
    row *r = &M.rows[i];
    if (r->kind == 0) navigate(M.oa->arc->f[M.cur].parent, M.cur);
    else if (r->kind == 1) navigate(r->idx, -1);
    else view_entry((u32)r->idx);
}

static void set_codepage(int cp)
{
    if (!M.oa) { g_set.codepage = cp; refresh_cp_menu(); return; }
    gz_arc_set_codepage(M.oa->arc, cp);
    tree_build();
    navigate(0, -1);
    refresh_cp_menu();
}

static void context_menu(int x, int y)
{
    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING, CMD_VIEW, S(S_M_OPENITEM));
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, CMD_EXTRACT_SEL, S(S_M_EXTRACT_SEL));
    AppendMenuW(m, MF_STRING, CMD_EXTRACT, S(S_M_EXTRACT));
    AppendMenuW(m, MF_STRING, CMD_SMART, S(S_M_EXTRACT_SMART));
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, CMD_TEST, S(S_M_TEST));
    AppendMenuW(m, MF_STRING, CMD_INFO, S(S_M_INFO));
    SetMenuDefaultItem(m, CMD_VIEW, FALSE);
    TrackPopupMenu(m, TPM_RIGHTBUTTON, x, y, 0, M.hwnd, NULL);
    DestroyMenu(m);
}

/* ======================================================================
 * list view text
 * ====================================================================== */

static void fmt_kb(wchar_t *o, u64 v)
{
    wchar_t t[32];
    fmt_thousands(t, (v + 1023) / 1024);
    wfmt(o, L"%s KB", t);
}

static void list_dispinfo(NMLVDISPINFOW *di)
{
    LVITEMW *it = &di->item;
    if (!M.oa || it->iItem < 0 || (u32)it->iItem >= M.nrows) return;
    row *r = &M.rows[it->iItem];
    gz_archive *a = M.oa->arc;
    if (it->mask & LVIF_IMAGE) {
        if (r->kind == 2) it->iImage = ext_lookup(a->e[r->idx].base)->icon;
        else it->iImage = M.ico_folder;
    }
    if (!(it->mask & LVIF_TEXT)) return;
    s_txt[0] = 0;
    if (r->kind == 0) {
        if (it->iSubItem == 0) wcopy(s_txt, L"..", 8);
        else if (it->iSubItem == 3) wcopy(s_txt, S(S_PARENT), 64);
    } else if (r->kind == 1) {
        gz_folder *f = &a->f[r->idx];
        switch (it->iSubItem) {
        case 0: wcopy(s_txt, f->base, 1024); break;
        case 3: wcopy(s_txt, S(S_FOLDER), 64); break;
        case 4: if (f->mtime_kind) { gz_entry tmp; tmp.mtime = f->mtime; tmp.mtime_kind = f->mtime_kind; fmt_filetime(s_txt, entry_filetime(&tmp)); } break;
        }
    } else {
        gz_entry *e = &a->e[r->idx];
        switch (it->iSubItem) {
        case 0:
            wcopy(s_txt, e->base, 1020);
            if (e->enc) wcat(s_txt, L" *", 1024);
            break;
        case 1: fmt_kb(s_txt, e->usize); break;
        case 2: fmt_kb(s_txt, e->csize); break;
        case 3: wcopy(s_txt, ext_lookup(e->base)->type, 64); break;
        case 4: fmt_filetime(s_txt, entry_filetime(e)); break;
        case 5:
            if (e->usize) {
                u64 p = e->csize * 100 / e->usize;
                if (p > 999) p = 999;
                wfmt(s_txt, L"%d%%", (int)p);
            }
            break;
        case 6:
            gz_arc_method(a, e, s_txt, 64);
            if (e->enc == GZ_ENC_ZIPCRYPTO) wcat(s_txt, L" · ZipCrypto", 128);
            else if (e->enc == GZ_ENC_AES) {
                wchar_t t[24];
                wfmt(t, L" · AES-%d", 64 + 64 * e->aes_strength);
                wcat(s_txt, t, 128);
            }
            break;
        case 7: if (e->has_crc && !e->is_dir) wfmt(s_txt, L"%08X", e->crc); break;
        }
    }
    it->pszText = s_txt;
}

/* ======================================================================
 * main window procedure
 * ====================================================================== */

static void create_children(HWND h)
{
    M.tb = CreateWindowExW(0, L"GZToolbar", NULL, WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, h, NULL, g_inst, NULL);
    M.path = CreateWindowExW(0, L"GZPath", NULL, WS_CHILD, 0, 0, 0, 0, h, NULL, g_inst, NULL);
    M.status = CreateWindowExW(0, L"GZStatus", NULL, WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, h, NULL, g_inst, NULL);
    M.welcome = CreateWindowExW(0, L"GZWelcome", NULL, WS_CHILD, 0, 0, 0, 0, h, NULL, g_inst, NULL);
    DWORD tvs = TVS_HASBUTTONS | TVS_LINESATROOT | TVS_SHOWSELALWAYS | TVS_DISABLEDRAGDROP;
    if (g_os.major >= 6) tvs |= TVS_FULLROWSELECT | TVS_TRACKSELECT;
    else tvs |= TVS_HASLINES;
    M.tree = CreateWindowExW(0, WC_TREEVIEWW, NULL, WS_CHILD | WS_TABSTOP | tvs, 0, 0, 0, 0, h,
                             (HMENU)(INT_PTR)ID_TREE, g_inst, NULL);
    M.list = CreateWindowExW(0, WC_LISTVIEWW, NULL,
                             WS_CHILD | WS_TABSTOP | LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS | LVS_SHAREIMAGELISTS,
                             0, 0, 0, 0, h, (HMENU)(INT_PTR)ID_LIST, g_inst, NULL);
    SendMessageW(M.tree, WM_SETFONT, (WPARAM)g_font.ui, 0);
    SendMessageW(M.list, WM_SETFONT, (WPARAM)g_font.ui, 0);
    gfx_set_theme(M.tree, L"Explorer");
    gfx_set_theme(M.list, L"Explorer");
    if (g_os.major >= 6) SendMessageW(M.tree, TVM_SETEXTENDEDSTYLE, TVS_EX_DOUBLEBUFFER, TVS_EX_DOUBLEBUFFER);
    SendMessageW(M.tree, TVM_SETIMAGELIST, TVSIL_NORMAL, (LPARAM)M.sysimg);
    SendMessageW(M.tree, TVM_SETBKCOLOR, 0, (LPARAM)C_BG);
    SendMessageW(M.tree, TVM_SETITEMHEIGHT, (WPARAM)(g_font.ui_h + scale(8)), 0);
    SendMessageW(M.list, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)M.sysimg);
    SendMessageW(M.list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
                 LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP | LVS_EX_LABELTIP);
    static const int sid[8] = { S_COL_NAME, S_COL_SIZE, S_COL_PACKED, S_COL_TYPE, S_COL_MTIME, S_COL_RATIO,
                                S_COL_METHOD, S_COL_CRC };
    static const int wd[8] = { 280, 92, 92, 130, 128, 58, 120, 78 };
    for (int i = 0; i < 8; i++) {
        LVCOLUMNW c;
        __builtin_memset(&c, 0, sizeof c);
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        c.fmt = (i == 1 || i == 2 || i == 5) ? LVCFMT_RIGHT : LVCFMT_LEFT;
        c.cx = g_set.col_w[i] > 10 ? g_set.col_w[i] : scale(wd[i]);
        c.pszText = (wchar_t *)S(sid[i]);
        SendMessageW(M.list, LVM_INSERTCOLUMNW, (WPARAM)i, (LPARAM)&c);
    }
    update_header_arrows();
    DragAcceptFiles(h, TRUE);
}

static void save_window(void)
{
    WINDOWPLACEMENT wp;
    wp.length = sizeof wp;
    if (GetWindowPlacement(M.hwnd, &wp)) {
        g_set.win_x = wp.rcNormalPosition.left;
        g_set.win_y = wp.rcNormalPosition.top;
        g_set.win_w = wp.rcNormalPosition.right - wp.rcNormalPosition.left;
        g_set.win_h = wp.rcNormalPosition.bottom - wp.rcNormalPosition.top;
        g_set.win_max = wp.showCmd == SW_SHOWMAXIMIZED;
    }
    g_set.split = MulDiv(M.split, 96, g_dpi);
    for (int i = 0; i < 8; i++) g_set.col_w[i] = (int)SendMessageW(M.list, LVM_GETCOLUMNWIDTH, (WPARAM)i, 0);
    settings_save();
}

static LRESULT on_notify(NMHDR *nh)
{
    if (nh->idFrom == ID_LIST) {
        switch (nh->code) {
        case LVN_GETDISPINFOW:
            list_dispinfo((NMLVDISPINFOW *)nh);
            return 0;
        case LVN_ITEMACTIVATE:
            activate_row(((NMITEMACTIVATE *)nh)->iItem);
            return 0;
        case LVN_KEYDOWN: {
            NMLVKEYDOWN *k = (NMLVKEYDOWN *)nh;
            if (k->wVKey == VK_BACK && M.oa && M.cur) navigate(M.oa->arc->f[M.cur].parent, M.cur);
            return 0;
        }
        case LVN_COLUMNCLICK: {
            int c = ((NMLISTVIEW *)nh)->iSubItem;
            if (c == M.sort_col) M.sort_desc = !M.sort_desc;
            else { M.sort_col = c; M.sort_desc = 0; }
            update_header_arrows();
            if (M.oa) {
                int i = -1;
                for (u32 k = 0; k < M.nrows; k++) M.rows[k].st = 0;
                while ((i = (int)SendMessageW(M.list, LVM_GETNEXTITEM, (WPARAM)i, LVNI_SELECTED)) >= 0 &&
                       (u32)i < M.nrows)
                    M.rows[i].st |= 1;
                i = (int)SendMessageW(M.list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_FOCUSED);
                if (i >= 0 && (u32)i < M.nrows) M.rows[i].st |= 2;
                sort_rows();
                ListView_SetItemState(M.list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
                for (u32 k = 0; k < M.nrows; k++) {
                    if (!M.rows[k].st) continue;
                    UINT stt = ((M.rows[k].st & 1) ? LVIS_SELECTED : 0) | ((M.rows[k].st & 2) ? LVIS_FOCUSED : 0);
                    ListView_SetItemState(M.list, (int)k, stt, stt);
                    if (M.rows[k].st & 2) ListView_EnsureVisible(M.list, (int)k, FALSE);
                }
                InvalidateRect(M.list, NULL, FALSE);
            }
            return 0;
        }
        case LVN_ITEMCHANGED:
        case LVN_ODSTATECHANGED:
            SetTimer(M.hwnd, 7, 40, NULL);
            return 0;
        case LVN_ODFINDITEMW: {
            /* typing in the list jumps to the next name starting with the typed text */
            NMLVFINDITEMW *fi = (NMLVFINDITEMW *)nh;
            const wchar_t *q = fi->lvfi.psz;
            if (!M.oa || !M.nrows || !q || !q[0] || !(fi->lvfi.flags & (LVFI_STRING | LVFI_PARTIAL))) return -1;
            int n = (int)M.nrows, ql = lstrlenW(q);
            int start = (fi->iStart >= 0 && fi->iStart < n) ? fi->iStart : 0;
            for (int k = 0; k < n; k++) {
                int r = (start + k) % n;
                if (!(fi->lvfi.flags & LVFI_WRAP) && start + k >= n) break;
                const wchar_t *nm = row_name(&M.rows[r]);
                int nl = lstrlenW(nm);
                if (nl >= ql && CompareStringW(LOCALE_USER_DEFAULT, NORM_IGNORECASE, nm, ql, q, ql) == CSTR_EQUAL)
                    return r;
            }
            return -1;
        }
        case NM_RCLICK: {
            POINT pt;
            GetCursorPos(&pt);
            if (M.oa) context_menu(pt.x, pt.y);
            return 0;
        }
        }
    } else if (nh->idFrom == ID_TREE) {
        if (nh->code == TVN_ITEMEXPANDINGW) {
            NMTREEVIEWW *t = (NMTREEVIEWW *)nh;
            if (M.oa && (t->action & TVE_EXPAND)) tree_populate((i32)t->itemNew.lParam);
            return 0;
        }
        if (nh->code == TVN_SELCHANGEDW && !M.syncing) {
            NMTREEVIEWW *t = (NMTREEVIEWW *)nh;
            if (M.oa && (i32)t->itemNew.lParam != M.cur) {
                M.syncing = 1;
                navigate((i32)t->itemNew.lParam, -1);
                M.syncing = 0;
            }
            return 0;
        }
    }
    return 0;
}

static int focused_or_selected(void)
{
    int i = (int)SendMessageW(M.list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
    if (i < 0) i = (int)SendMessageW(M.list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_FOCUSED);
    return i;
}

static LRESULT CALLBACK main_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    switch (m) {
    case WM_CREATE:
        M.hwnd = h;
        create_children(h);
        layout();
        return 0;
    case WM_SIZE:
        if (wp != SIZE_MINIMIZED) layout();
        return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO *mm = (MINMAXINFO *)lp;
        mm->ptMinTrackSize.x = scale(560);
        mm->ptMinTrackSize.y = scale(380);
        return 0;
    }
    case WM_SETCURSOR:
        if ((HWND)wp == h && LOWORD(lp) == HTCLIENT && M.oa && g_set.show_tree) {
            POINT pt;
            GetCursorPos(&pt);
            ScreenToClient(h, &pt);
            if (pt.x >= M.split && pt.x < M.split + scale(4)) { SetCursor(LoadCursorW(NULL, IDC_SIZEWE)); return TRUE; }
        }
        break;
    case WM_LBUTTONDOWN:
        if (M.oa && g_set.show_tree) {
            int x = (short)LOWORD(lp);
            if (x >= M.split && x < M.split + scale(4)) { M.dragging = 1; SetCapture(h); }
        }
        return 0;
    case WM_MOUSEMOVE:
        if (M.dragging) {
            M.split = (short)LOWORD(lp);
            layout();
            UpdateWindow(h);
        }
        return 0;
    case WM_LBUTTONUP:
        if (M.dragging) { M.dragging = 0; ReleaseCapture(); }
        return 0;
    case WM_ERASEBKGND: {
        RECT r;
        GetClientRect(h, &r);
        gfx_fill((HDC)wp, &r, C_BORDER);
        return 1;
    }
    case WM_NOTIFY:
        return on_notify((NMHDR *)lp);
    case WM_TIMER:
        if (wp == 7) { KillTimer(h, 7); update_status(); }
        return 0;
    case WM_DROPFILES: {
        wchar_t p[MAX_PATH * 2];
        HDROP d = (HDROP)wp;
        if (DragQueryFileW(d, 0, p, MAX_PATH * 2)) {
            DragFinish(d);
            SetForegroundWindow(h);
            open_archive(p);
        } else {
            DragFinish(d);
        }
        return 0;
    }
    case WM_INITMENUPOPUP: {
        HMENU pm = (HMENU)wp;
        UINT need[] = { CMD_CLOSE, CMD_INFO, CMD_EXTRACT, CMD_HERE, CMD_SMART, CMD_EXTRACT_SEL, CMD_TEST, CMD_VIEW,
                        CMD_UP, CMD_SELALL };
        for (u32 i = 0; i < GZ_COUNTOF(need); i++)
            EnableMenuItem(pm, need[i], MF_BYCOMMAND | (M.oa ? MF_ENABLED : MF_GRAYED));
        CheckMenuItem(pm, CMD_TREE, MF_BYCOMMAND | (g_set.show_tree ? MF_CHECKED : MF_UNCHECKED));
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id >= CMD_RECENT0 && id < CMD_RECENT0 + 6) {
            wchar_t p[MAX_PATH];
            wcopy(p, g_set.recent[id - CMD_RECENT0], MAX_PATH);
            if (p[0]) open_archive(p);
            return 0;
        }
        if (id >= CMD_CP0 && id < CMD_CP0 + g_cp_count) { set_codepage(g_cp_list[id - CMD_CP0].cp); return 0; }
        switch (id) {
        case CMD_OPEN: cmd_open(); break;
        case CMD_WELCOME_EXTRACT:
            cmd_open();
            if (M.oa) cmd_extract(X_DIALOG, 0);
            break;
        case CMD_CLOSE: close_archive(); break;
        case CMD_EXIT: PostMessageW(h, WM_CLOSE, 0, 0); break;
        case CMD_INFO: dlg_info(h, M.oa); break;
        case CMD_EXTRACT: cmd_extract(X_DIALOG, 0); break;
        case CMD_SMART: cmd_extract(X_SMART, 0); break;
        case CMD_HERE: cmd_extract(X_HERE, 0); break;
        case CMD_EXTRACT_SEL: cmd_extract(X_DIALOG, 1); break;
        case CMD_TEST: if (M.oa) do_extract(h, M.oa, X_TEST, 0, 0, 0, 0); break;
        case CMD_VIEW: if (M.oa) activate_row(focused_or_selected()); break;
        case CMD_UP: if (M.oa && M.cur) navigate(M.oa->arc->f[M.cur].parent, M.cur); break;
        case CMD_SELALL:
            if (M.oa) { ListView_SetItemState(M.list, -1, LVIS_SELECTED, LVIS_SELECTED); SetFocus(M.list); }
            break;
        case CMD_TREE: g_set.show_tree = !g_set.show_tree; layout(); break;
        case CMD_SETTINGS: {
            int cp = g_set.codepage;
            dlg_settings(h);
            if (cp != g_set.codepage) set_codepage(g_set.codepage);
            InvalidateRect(M.status, NULL, FALSE);
            InvalidateRect(M.welcome, NULL, FALSE);
            break;
        }
        case CMD_BENCH: dlg_bench(h); break;
        case CMD_HOME: ShellExecuteW(h, L"open", GZ_HOMEPAGE, NULL, NULL, SW_SHOWNORMAL); break;
        case CMD_ABOUT: dlg_about(h); break;
        case CMD_CODEPAGE: {
            refresh_cp_menu();
            int x = (short)LOWORD(lp), y = (short)HIWORD(lp);
            if (HIWORD(wp) != 1) { POINT pt; GetCursorPos(&pt); x = pt.x; y = pt.y; }
            TrackPopupMenu(M.cp_menu, TPM_LEFTALIGN | TPM_TOPALIGN, x, y, 0, h, NULL);
            break;
        }
        }
        return 0;
    }
    case WM_CLOSE:
        save_window();
        DestroyWindow(h);
        return 0;
    case WM_DESTROY: {
        close_archive();
        wchar_t t[MAX_PATH];
        if (temp_root(t)) {
            delete_tree(t);
            sweep_stale_temp();
            wchar_t *b = (wchar_t *)path_base(t);   /* also drop %TEMP%\GogitZIP if now empty */
            if (b > t) { b[-1] = 0; RemoveDirectoryW(t); }
        }
        PostQuitMessage(0);
        return 0;
    }
    }
    return DefWindowProcW(h, m, wp, lp);
}

/* ======================================================================
 * creation
 * ====================================================================== */

static void register_classes(void)
{
    WNDCLASSEXW wc;
    __builtin_memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.hInstance = g_inst;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.lpfnWndProc = main_proc;
    wc.lpszClassName = L"GogitZIPMain";
    wc.hIcon = gfx_app_icon(GetSystemMetrics(SM_CXICON));
    wc.hIconSm = gfx_app_icon(GetSystemMetrics(SM_CXSMICON));
    RegisterClassExW(&wc);
    wc.hIcon = wc.hIconSm = NULL;
    wc.lpfnWndProc = tb_proc;
    wc.lpszClassName = L"GZToolbar";
    RegisterClassExW(&wc);
    wc.lpfnWndProc = path_proc;
    wc.lpszClassName = L"GZPath";
    RegisterClassExW(&wc);
    wc.lpfnWndProc = status_proc;
    wc.lpszClassName = L"GZStatus";
    RegisterClassExW(&wc);
    wc.lpfnWndProc = welcome_proc;
    wc.lpszClassName = L"GZWelcome";
    RegisterClassExW(&wc);
}

static ACCEL k_acc[] = {
    { FCONTROL | FVIRTKEY, 'O', CMD_OPEN }, { FCONTROL | FVIRTKEY, 'W', CMD_CLOSE },
    { FCONTROL | FVIRTKEY, 'E', CMD_EXTRACT }, { FCONTROL | FVIRTKEY, 'Q', CMD_SMART },
    { FCONTROL | FVIRTKEY, 'T', CMD_TEST }, { FCONTROL | FVIRTKEY, 'A', CMD_SELALL },
    { FALT | FVIRTKEY, VK_RETURN, CMD_INFO }, { FVIRTKEY, VK_F1, CMD_ABOUT },
};

HWND mainwnd_create(const wchar_t *open_path, int show)
{
    sweep_stale_temp();
    HMODULE shl = LoadLibraryW(L"shlwapi.dll");
    if (shl) s_logical = (StrCmpLogicalW_t)(void *)GetProcAddress(shl, "StrCmpLogicalW");
    init_sysicons();
    register_classes();
    M.tb_h = scale(68);
    M.path_h = scale(36);
    M.st_h = scale(26);
    M.split = g_set.split > 0 ? scale(g_set.split) : scale(220);
    build_menu();
    M.accel = CreateAcceleratorTableW(k_acc, (int)GZ_COUNTOF(k_acc));

    int w = g_set.win_w > 200 ? g_set.win_w : scale(980), hh = g_set.win_h > 200 ? g_set.win_h : scale(640);
    int x = CW_USEDEFAULT, y = CW_USEDEFAULT;
    if (g_set.win_w > 200) {
        RECT r = { g_set.win_x, g_set.win_y, g_set.win_x + w, g_set.win_y + hh };
        HMONITOR mon = MonitorFromRect(&r, MONITOR_DEFAULTTONULL);
        if (mon) { x = g_set.win_x; y = g_set.win_y; }
    }
    HWND h = CreateWindowExW(WS_EX_ACCEPTFILES, L"GogitZIPMain", S(S_APP), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                             x, y, w, hh, NULL, M.menu, g_inst, NULL);
    if (!h) return 0;
    ShowWindow(h, g_set.win_max ? SW_SHOWMAXIMIZED : show);
    UpdateWindow(h);
    if (open_path && open_path[0]) open_archive(open_path);
    return h;
}

int mainwnd_loop(HWND hwnd)
{
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (M.accel && TranslateAcceleratorW(hwnd, M.accel, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
