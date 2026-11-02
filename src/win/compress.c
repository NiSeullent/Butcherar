/*
 * 고깃ZIP - creating archives
 *
 *   dlg_compress     Bandizip-like dialog: output path, format (every registered
 *                    gz_writer), level, method (filtered by the writer's mask),
 *                    password + confirmation + encryption, 7z options
 *   compress_direct  "<name>.zip" / "<name>.7z" next to the inputs (/zip, /7z,
 *                    Explorer menu), a free name is picked when it exists
 * Both run the engine's compression job in the shared progress window.
 */
#include "app.h"

/* preferred order of the format list */
static const int k_fmt_order[] = { GZ_WF_ZIP, GZ_WF_7Z, GZ_WF_TAR, GZ_WF_TGZ, GZ_WF_TBZ2, GZ_WF_TXZ, GZ_WF_TZST,
                                   GZ_WF_GZ, GZ_WF_BZ2, GZ_WF_XZ, GZ_WF_ZST, GZ_WF_ISO };

static const struct { u8 m; const wchar_t *name; } k_methods[] = {
    { GZ_WM_DEFAULT, 0 }, { GZ_WM_STORE, 0 }, { GZ_WM_DEFLATE, L"Deflate" }, { GZ_WM_DEFLATE64, L"Deflate64" },
    { GZ_WM_BZIP2, L"BZip2" }, { GZ_WM_LZMA, L"LZMA" }, { GZ_WM_LZMA2, L"LZMA2" }, { GZ_WM_PPMD, L"PPMd" },
    { GZ_WM_ZSTD, L"Zstandard" },
};
static const struct { u8 level; int sid; } k_levels[] = {
    { 0, S_L_0 }, { 1, S_L_1 }, { 3, S_L_3 }, { 5, S_L_5 }, { 7, S_L_7 }, { 9, S_L_9 },
};

static int single_stream(int f) { return f == GZ_WF_GZ || f == GZ_WF_BZ2 || f == GZ_WF_XZ || f == GZ_WF_ZST; }

static void a2w(wchar_t *o, const char *s, size_t cap)
{
    size_t i = 0;
    for (; s && s[i] && i + 1 < cap; i++) o[i] = (wchar_t)(u8)s[i];
    o[i] = 0;
}

/* default archive name (without extension) for the inputs; o holds wlen(in[0]) + 8 */
static void default_stem(const wchar_t *const *in, u32 n, wchar_t *o, size_t cap)
{
    if (n == 1) {
        wcopy(o, path_base(in[0]), cap);
        if (!path_is_dir(in[0])) {
            wchar_t *dot = (wchar_t *)gz_wcsrchr(o, '.');
            if (dot && dot != o) *dot = 0;
        }
    } else {
        /* the folder holding them: path_dir in o itself ("C:" grows to "C:\") */
        wcopy(o, in[0], cap);
        path_dir(o, o, cap);
        const wchar_t *b = path_base(o);
        if (b != o) __builtin_memmove(o, b, (wlen(b) + 1) * sizeof(wchar_t));
    }
    size_t k = wlen(o);
    while (k && (o[k - 1] == '.' || o[k - 1] == ' ' || o[k - 1] == '\\' || o[k - 1] == ':')) o[--k] = 0;
    if (!k) wcopy(o, L"archive", cap);
}

/* replace the archive extension of path (if any) by the writer's; 0 (path unchanged)
 * when the result would not fit in cap */
static int set_ext(wchar_t *path, size_t cap, const gz_writer *w)
{
    size_t n = wlen(path);
    const wchar_t *b = path_base(path);
    if (gz_format_from_name(path)) {
        /* known archive extension: drop it (".tar.gz" counts as one) */
        static const char *const dbl[] = { ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst" };
        size_t cut = 0;
        for (u32 i = 0; i < GZ_COUNTOF(dbl) && !cut; i++)
            if (gz_wcs_endswith(path, dbl[i])) { size_t l = 0; while (dbl[i][l]) l++; cut = l; }
        if (!cut) {
            const wchar_t *dot = gz_wcsrchr(b, '.');
            if (dot && dot != b) cut = (size_t)(path + n - dot);
        }
        n -= cut;
    }
    wchar_t e[24];
    e[0] = '.';
    a2w(e + 1, w->ext, 23);
    if (n + wlen(e) >= cap) return 0;
    path[n] = 0;
    wcat(path, e, cap);
    return 1;
}

static void path_too_long(HWND h, int focus_id)
{
    msg_box(h, S(S_N_PATH_LONG), MB_ICONWARNING);
    if (focus_id) SetFocus(GetDlgItem(h, focus_id));
}

static const gz_writer *writer_or_null(int f) { return f ? gz_writer_find(f) : 0; }

/* ---------------- running a compression job ---------------- */

/* overwrite: GZ_OW_ALL only when the user confirmed replacing out; otherwise GZ_OW_ASK,
 * so an archive that exists after all (a race, a check that could not see it) is asked
 * about by the engine instead of being replaced */
static int run_compress(HWND owner, const wchar_t *const *in, u32 n, const wchar_t *out, int format, int method,
                        int level, int enc, const wchar_t *pw, int encnames, int solid, int overwrite)
{
    if (wlen(out) >= GZ_LONGPATH) { msg_box(owner, S(S_N_PATH_LONG), MB_ICONWARNING); return GZ_E_CREATE; }
    ui_job *u = (ui_job *)mem_alloc(sizeof(ui_job));
    if (!u) return GZ_E_NOMEM;
    ui_job_init(u, OP_COMPRESS);
    wcopy(u->out, out, GZ_COUNTOF(u->out));
    if (pw) wcopy(u->pw, pw, GZ_COUNTOF(u->pw));
    u->title = u->out;
    u->open_folder = 0;
    gz_compress_opts *c = &u->co;
    c->out = u->out;
    c->inputs = in;
    c->ninputs = n;
    c->format = format;
    c->method = method;
    c->level = level;
    c->encryption = u->pw[0] ? enc : GZ_WE_NONE;
    c->password = u->pw[0] ? u->pw : 0;
    c->encrypt_names = u->pw[0] ? encnames : 0;
    c->solid = solid;
    c->threads = g_set.threads;
    c->flags = GZ_CF_FOLLOW_LINKS;           /* like Explorer: archive what links point to */
    c->overwrite = overwrite;
    int r = run_job_with_progress(owner, u);
    if (r == GZ_E_CANCEL) {
        /* nothing to report */
    } else if (r || ui_job_problems(u)) {
        dlg_errors(owner, u);
    } else if (u->open_folder) {
        wchar_t *dir = wdup(u->out);
        if (dir) {
            path_dir(dir, u->out, wlen(dir) + 1);
            open_in_explorer(dir, u->out);
            mem_free(dir);
        }
    }
    SecureZeroMemory(u->pw, sizeof u->pw);
    ui_job_free(u);
    mem_free(u);
    return r;
}

int compress_direct(HWND owner, const wchar_t *const *in, u32 n, int format)
{
    const gz_writer *w = writer_or_null(format);
    if (!n) return GZ_E_FORMAT;
    if (!w) { msg_box(owner, S(S_C_NOWRITER), MB_ICONWARNING); return GZ_E_METHOD; }
    if (single_stream(format) && (n != 1 || path_is_dir(in[0]))) {
        msg_box(owner, S(S_C_ONEFILE), MB_ICONWARNING);
        return GZ_E_METHOD;
    }
    /* "<dir>\<stem>.zip", else the first free "<stem> (k).zip". The buffers are sized
     * for the inputs (paths may be longer than MAX_PATH): a name is never cut short,
     * so every candidate is a different file and the one picked is the one checked. */
    wchar_t e[24];
    e[0] = '.';
    a2w(e + 1, w->ext, 23);
    size_t il = wlen(in[0]), cap = 2 * il + wlen(e) + 32;
    wchar_t *dir = (wchar_t *)mem_alloc((il + 8) * sizeof(wchar_t));
    wchar_t *stem = (wchar_t *)mem_alloc((il + 8) * sizeof(wchar_t));
    wchar_t *out = (wchar_t *)mem_alloc(cap * sizeof(wchar_t));
    int r = GZ_E_NOMEM, found = 0;
    if (dir && stem && out) {
        path_dir(dir, in[0], il + 8);
        default_stem(in, n, stem, il + 8);
        for (int k = 1; k < 10000 && !found; k++) {
            wchar_t num[24];
            num[0] = 0;
            if (k > 1) wfmt(num, L" (%d)", k);
            path_join(out, dir, stem, cap);
            wcat(out, num, cap);
            wcat(out, e, cap);
            found = !path_exists(out);
        }
        if (found) {
            r = run_compress(owner, in, n, out, format, GZ_WM_DEFAULT, 5, GZ_WE_AES256, 0, 0, 1, GZ_OW_ASK);
        } else {
            msg_box(owner, S(S_N_EXISTS), MB_ICONWARNING);      /* every name up to "(9999)" is taken */
            r = GZ_E_CREATE;
        }
    }
    mem_free(dir);
    mem_free(stem);
    mem_free(out);
    return r;
}

/* ---------------- dialog ---------------- */

enum { ID_C_OUTL = 1201, ID_C_OUT, ID_C_BROWSE, ID_C_FMTL, ID_C_FMT, ID_C_LVLL, ID_C_LVL, ID_C_METL, ID_C_MET,
       ID_C_SOLID, ID_C_PWL, ID_C_PW, ID_C_PW2L, ID_C_PW2, ID_C_ENCL, ID_C_ENC, ID_C_ENCNAMES, ID_C_SHOW };

typedef struct {
    dlg_base b;
    const wchar_t *const *in;
    u32 n;
    wchar_t out[GZ_LONGPATH];
    int format, method, level, enc, solid, encnames, overwrite;
    wchar_t pw[256];
} cdlg;

/* text of control id in a new buffer of cap units (mem_free); NULL when out of memory or,
 * with *too_long set, when the text does not fit: never a silently shortened path */
static wchar_t *dlg_text(HWND h, int id, size_t cap, int *too_long)
{
    LRESULT n = SendDlgItemMessageW(h, id, WM_GETTEXTLENGTH, 0, 0);
    *too_long = n < 0 || (size_t)n >= cap;
    if (*too_long) return 0;
    wchar_t *p = (wchar_t *)mem_alloc(cap * sizeof(wchar_t));
    if (p) GetDlgItemTextW(h, id, p, (int)cap);
    return p;
}

static int combo_data(HWND h, int id)
{
    int i = (int)SendDlgItemMessageW(h, id, CB_GETCURSEL, 0, 0);
    return i < 0 ? -1 : (int)SendDlgItemMessageW(h, id, CB_GETITEMDATA, (WPARAM)i, 0);
}

static void combo_add(HWND h, int id, const wchar_t *text, int data, int select)
{
    int i = (int)SendDlgItemMessageW(h, id, CB_ADDSTRING, 0, (LPARAM)text);
    if (i < 0) return;
    SendDlgItemMessageW(h, id, CB_SETITEMDATA, (WPARAM)i, (LPARAM)data);
    if (select) SendDlgItemMessageW(h, id, CB_SETCURSEL, (WPARAM)i, 0);
}

/* methods / encryption / options of the selected format */
static void c_format_changed(HWND h, cdlg *x, int fix_ext)
{
    int f = combo_data(h, ID_C_FMT);
    const gz_writer *w = writer_or_null(f);
    if (!w) return;
    x->format = f;
    if (fix_ext) {
        int too_long;
        wchar_t *p = dlg_text(h, ID_C_OUT, GZ_LONGPATH, &too_long);
        if (p && p[0] && set_ext(p, GZ_LONGPATH, w)) SetDlgItemTextW(h, ID_C_OUT, p);
        mem_free(p);
    }
    SendDlgItemMessageW(h, ID_C_MET, CB_RESETCONTENT, 0, 0);
    int any = 0;
    for (u32 i = 0; i < GZ_COUNTOF(k_methods); i++) {
        int m = k_methods[i].m;
        if (m != GZ_WM_DEFAULT && !(w->methods & (1u << m))) continue;
        const wchar_t *nm = m == GZ_WM_DEFAULT ? S(S_C_DEFAULT) : m == GZ_WM_STORE ? S(S_C_STORE) : k_methods[i].name;
        combo_add(h, ID_C_MET, nm, m, m == x->method || (!any && m == GZ_WM_DEFAULT));
        any = 1;
    }
    if (SendDlgItemMessageW(h, ID_C_MET, CB_GETCURSEL, 0, 0) < 0) SendDlgItemMessageW(h, ID_C_MET, CB_SETCURSEL, 0, 0);
    /* a level only matters when something compresses */
    u32 real = w->methods & ~((1u << GZ_WM_DEFAULT) | (1u << GZ_WM_STORE));
    EnableWindow(GetDlgItem(h, ID_C_LVL), real != 0 || single_stream(f));
    EnableWindow(GetDlgItem(h, ID_C_MET), SendDlgItemMessageW(h, ID_C_MET, CB_GETCOUNT, 0, 0) > 1);
    SendDlgItemMessageW(h, ID_C_ENC, CB_RESETCONTENT, 0, 0);
    if (w->encryptions & (1u << GZ_WE_AES256)) combo_add(h, ID_C_ENC, L"AES-256", GZ_WE_AES256, x->enc != GZ_WE_ZIPCRYPTO);
    if (w->encryptions & (1u << GZ_WE_ZIPCRYPTO)) combo_add(h, ID_C_ENC, L"ZipCrypto", GZ_WE_ZIPCRYPTO, x->enc == GZ_WE_ZIPCRYPTO);
    if (SendDlgItemMessageW(h, ID_C_ENC, CB_GETCURSEL, 0, 0) < 0) SendDlgItemMessageW(h, ID_C_ENC, CB_SETCURSEL, 0, 0);
    int can_enc = (w->encryptions & ~1u) != 0;
    static const int pw_ids[] = { ID_C_PW, ID_C_PW2, ID_C_ENC, ID_C_SHOW, ID_C_PWL, ID_C_PW2L, ID_C_ENCL };
    for (u32 i = 0; i < GZ_COUNTOF(pw_ids); i++) EnableWindow(GetDlgItem(h, pw_ids[i]), can_enc);
    EnableWindow(GetDlgItem(h, ID_C_SOLID), f == GZ_WF_7Z);
    EnableWindow(GetDlgItem(h, ID_C_ENCNAMES), f == GZ_WF_7Z && can_enc);
}

static void c_browse(HWND h, cdlg *x)
{
    const gz_writer *w = writer_or_null(x->format);
    wchar_t file[MAX_PATH * 2], filter[160], e[24];
    GetDlgItemTextW(h, ID_C_OUT, file, GZ_COUNTOF(file));
    a2w(e, w ? w->ext : "zip", 24);
    wchar_t nm[48];
    a2w(nm, w ? w->name : "ZIP", 48);
    int k = 0;
    wchar_t part[96];
    wfmt(part, L"%s (*.%s)", nm, e);
    for (const wchar_t *p = part; *p; p++) filter[k++] = *p;
    filter[k++] = 0;
    filter[k++] = '*';
    filter[k++] = '.';
    for (const wchar_t *p = e; *p; p++) filter[k++] = *p;
    filter[k++] = 0;
    for (const wchar_t *p = S(S_FILTER_ALL); *p && k < 140; p++) filter[k++] = *p;
    filter[k++] = 0;
    filter[k++] = '*'; filter[k++] = '.'; filter[k++] = '*';
    filter[k++] = 0;
    filter[k] = 0;
    OPENFILENAMEW of;
    __builtin_memset(&of, 0, sizeof of);
    of.lStructSize = sizeof of;
    of.hwndOwner = h;
    of.lpstrFilter = filter;
    of.lpstrFile = file;
    of.nMaxFile = GZ_COUNTOF(file);
    of.lpstrDefExt = e;
    of.lpstrTitle = S(S_C_SAVE);
    of.Flags = OFN_HIDEREADONLY | OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_NOREADONLYRETURN;
    if (GetSaveFileNameW(&of)) SetDlgItemTextW(h, ID_C_OUT, file);
}

/* the archive path typed in the dialog -> x->out (full path); 0 after telling why not */
static int c_out_path(HWND h, cdlg *x)
{
    const size_t cap = GZ_COUNTOF(x->out);
    int too_long, ok = 0;
    wchar_t *p = dlg_text(h, ID_C_OUT, cap, &too_long);
    wchar_t *t = p ? (wchar_t *)mem_alloc(cap * sizeof(wchar_t)) : 0;
    if (!t) {
        if (too_long) path_too_long(h, ID_C_OUT);
        mem_free(p);
        return 0;
    }
    size_t n = wlen(p);
    while (n && p[n - 1] == ' ') p[--n] = 0;
    if (!n) {
        MessageBeep(MB_ICONWARNING);
        SetFocus(GetDlgItem(h, ID_C_OUT));
    } else {
        ok = 1;
        /* a relative name goes next to the inputs */
        if (!(p[0] == '\\' || (p[0] && p[1] == ':'))) {
            if (wlen(x->in[0]) + n + 2 >= cap) ok = 0;
            else {
                path_dir(t, x->in[0], cap);
                path_join(t, t, p, cap);
                wcopy(p, t, cap);
            }
        }
        /* GetFullPathNameW returns the size it needs (and leaves x->out alone) when the
         * result does not fit: that is an error, not the previous path */
        DWORD fl = ok ? GetFullPathNameW(p, (DWORD)cap, x->out, NULL) : 0;
        if (ok && fl >= cap) ok = 0;
        else if (ok && !fl) wcopy(x->out, p, cap);
        if (!ok) path_too_long(h, ID_C_OUT);
    }
    mem_free(t);
    mem_free(p);
    return ok;
}

static int c_accept(HWND h, cdlg *x)
{
    wchar_t pw2[256];
    if (!c_out_path(h, x)) return 0;
    x->format = combo_data(h, ID_C_FMT);
    /* the typed extension names another format we can write: follow it */
    if (!writer_or_null(x->format)) { msg_box(h, S(S_C_NOWRITER), MB_ICONWARNING); return 0; }
    int typed = gz_format_from_name(x->out);
    if (typed && typed != x->format && gz_writer_find(typed)) x->format = typed;
    else if (typed != x->format && !set_ext(x->out, GZ_COUNTOF(x->out), gz_writer_find(x->format))) {
        path_too_long(h, ID_C_OUT);
        return 0;
    }
    if (single_stream(x->format) && (x->n != 1 || path_is_dir(x->in[0]))) {
        msg_box(h, S(S_C_ONEFILE), MB_ICONWARNING);
        return 0;
    }
    x->method = combo_data(h, ID_C_MET);
    if (x->method < 0) x->method = GZ_WM_DEFAULT;
    int li = (int)SendDlgItemMessageW(h, ID_C_LVL, CB_GETCURSEL, 0, 0);
    x->level = li >= 0 && li < (int)GZ_COUNTOF(k_levels) ? k_levels[li].level : 5;
    x->enc = combo_data(h, ID_C_ENC);
    if (x->enc < 0) x->enc = GZ_WE_AES256;
    x->solid = IsDlgButtonChecked(h, ID_C_SOLID) == BST_CHECKED;
    x->encnames = IsDlgButtonChecked(h, ID_C_ENCNAMES) == BST_CHECKED;
    x->pw[0] = 0;
    if (IsWindowEnabled(GetDlgItem(h, ID_C_PW))) {
        GetDlgItemTextW(h, ID_C_PW, x->pw, 256);
        GetDlgItemTextW(h, ID_C_PW2, pw2, 256);
        int show = IsDlgButtonChecked(h, ID_C_SHOW) == BST_CHECKED;
        if (!show && wcmp(x->pw, pw2)) {
            msg_box(h, S(S_C_PWMISMATCH), MB_ICONWARNING);
            SecureZeroMemory(pw2, sizeof pw2);
            SetFocus(GetDlgItem(h, ID_C_PW2));
            return 0;
        }
        SecureZeroMemory(pw2, sizeof pw2);
    }
    x->overwrite = GZ_OW_ASK;                /* the engine asks if it exists after all */
    if (path_exists(x->out)) {
        wchar_t t[MAX_PATH * 2 + 128];
        wfmt(t, S(S_C_EXISTS), x->out);
        if (path_is_dir(x->out) || MessageBoxW(h, t, S(S_APP), MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES)
            return 0;
        x->overwrite = GZ_OW_ALL;            /* confirmed */
    }
    g_set.c_format = x->format;
    g_set.c_method = x->method;
    g_set.c_level = x->level;
    g_set.c_enc = x->enc;
    g_set.c_solid = x->solid;
    g_set.c_encnames = x->encnames;
    settings_save();
    return 1;
}

static void c_show_pw(HWND h)
{
    int show = IsDlgButtonChecked(h, ID_C_SHOW) == BST_CHECKED;
    wchar_t pc = (g_os.major > 5 || (g_os.major == 5 && g_os.minor >= 1)) ? 0x25CF : '*';
    SendDlgItemMessageW(h, ID_C_PW, EM_SETPASSWORDCHAR, show ? 0 : pc, 0);
    InvalidateRect(GetDlgItem(h, ID_C_PW), NULL, TRUE);
    EnableWindow(GetDlgItem(h, ID_C_PW2), !show && IsWindowEnabled(GetDlgItem(h, ID_C_PW)));
}

static INT_PTR CALLBACK cdlg_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    INT_PTR ret;
    if (dlg_common(h, m, wp, lp, &ret)) return ret;
    cdlg *x = (cdlg *)GetWindowLongPtrW(h, DWLP_USER);
    switch (m) {
    case WM_INITDIALOG: {
        x = (cdlg *)lp;
        dlg_setup(h, &x->b, IDOK);
        dlg_bold(h, ID_C_OUTL);
        int sel = writer_or_null(g_set.c_format) ? g_set.c_format : writer_or_null(GZ_WF_ZIP) ? GZ_WF_ZIP : 0;
        for (u32 i = 0; i < GZ_COUNTOF(k_fmt_order); i++) {
            const gz_writer *w = gz_writer_find(k_fmt_order[i]);
            if (!w) continue;
            wchar_t t[48];
            a2w(t, w->name, 48);
            if (!sel) sel = w->format;
            combo_add(h, ID_C_FMT, t, w->format, w->format == sel);
        }
        for (int i = 0; gz_writers[i]; i++) {            /* formats added later */
            int known = 0;
            for (u32 k = 0; k < GZ_COUNTOF(k_fmt_order); k++) known |= k_fmt_order[k] == gz_writers[i]->format;
            if (known) continue;
            wchar_t t[48];
            a2w(t, gz_writers[i]->name, 48);
            combo_add(h, ID_C_FMT, t, gz_writers[i]->format, 0);
        }
        for (u32 i = 0; i < GZ_COUNTOF(k_levels); i++) combo_add(h, ID_C_LVL, S(k_levels[i].sid), k_levels[i].level,
                                                               k_levels[i].level == x->level);
        if (SendDlgItemMessageW(h, ID_C_LVL, CB_GETCURSEL, 0, 0) < 0) SendDlgItemMessageW(h, ID_C_LVL, CB_SETCURSEL, 3, 0);
        SendDlgItemMessageW(h, ID_C_PW, EM_LIMITTEXT, 255, 0);
        SendDlgItemMessageW(h, ID_C_PW2, EM_LIMITTEXT, 255, 0);
        if (g_os.major > 5 || (g_os.major == 5 && g_os.minor >= 1)) {
            SendDlgItemMessageW(h, ID_C_PW, EM_SETPASSWORDCHAR, 0x25CF, 0);
            SendDlgItemMessageW(h, ID_C_PW2, EM_SETPASSWORDCHAR, 0x25CF, 0);
        }
        CheckDlgButton(h, ID_C_SOLID, x->solid ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(h, ID_C_ENCNAMES, x->encnames ? BST_CHECKED : BST_UNCHECKED);
        SetDlgItemTextW(h, ID_C_OUT, x->out);
        c_format_changed(h, x, 1);
        if (!sel) EnableWindow(GetDlgItem(h, IDOK), FALSE);
        SetFocus(GetDlgItem(h, ID_C_OUT));
        SendDlgItemMessageW(h, ID_C_OUT, EM_SETSEL, 0, -1);
        return FALSE;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_C_FMT:
            if (HIWORD(wp) == CBN_SELCHANGE) c_format_changed(h, x, 1);
            return TRUE;
        case ID_C_BROWSE: c_browse(h, x); return TRUE;
        case ID_C_SHOW: c_show_pw(h); return TRUE;
        case IDOK:
            if (c_accept(h, x)) EndDialog(h, 1);
            return TRUE;
        case IDCANCEL: EndDialog(h, 0); return TRUE;
        }
        break;
    }
    return FALSE;
}

int dlg_compress(HWND owner, const wchar_t *const *in, u32 n)
{
    if (!n) return GZ_E_FORMAT;
    cdlg *x = (cdlg *)mem_alloc(sizeof(cdlg));
    if (!x) return GZ_E_NOMEM;
    x->in = in;
    x->n = n;
    x->level = g_set.c_level >= 0 && g_set.c_level <= 9 ? g_set.c_level : 5;
    x->method = g_set.c_method;
    x->enc = g_set.c_enc ? g_set.c_enc : GZ_WE_AES256;
    x->solid = g_set.c_solid;
    x->encnames = g_set.c_encnames;
    {
        /* "<dir>\<stem>.zip" (the extension follows the format); when that does not fit,
         * just the name: accepting it then says the path is too long */
        size_t il = wlen(in[0]);
        wchar_t *stem = (wchar_t *)mem_alloc((il + 8) * sizeof(wchar_t));
        if (!stem) { mem_free(x); return GZ_E_NOMEM; }
        default_stem(in, n, stem, il + 8);
        if (2 * il + 16 < GZ_COUNTOF(x->out)) {
            path_dir(x->out, in[0], GZ_COUNTOF(x->out));
            path_join(x->out, x->out, stem, GZ_COUNTOF(x->out));
        } else {
            wcopy(x->out, stem, GZ_COUNTOF(x->out));
        }
        wcat(x->out, L".zip", GZ_COUNTOF(x->out));
        mem_free(stem);
    }
    x->b.icon = IC_COMPRESS;
    wcopy(x->b.title, S(S_C_TITLE), 128);
    {
        wchar_t cnt[32], line[128];
        fmt_thousands(cnt, n);
        wfmt(line, S(S_C_SUMMARY), cnt);
        wfmt(x->b.sub, L"%s  ·  %s%s", line, path_base(in[0]), n > 1 ? L", ..." : L"");
    }
    x->b.hdr_dlu = 40;
    x->b.foot_dlu = 170;
    dlgt d;
    dlgt_begin(&d, S(S_C_TITLE), 310, 196, 0);
    T_STATIC(&d, ID_C_OUTL, S(S_C_OUT), 12, 46, 286, 10, 0);
    T_EDIT(&d, ID_C_OUT, L"", 12, 59, 230, 13, 0);
    T_BUTTON(&d, ID_C_BROWSE, S(S_BROWSE), 246, 58, 52, 15);
    T_STATIC(&d, ID_C_FMTL, S(S_C_FORMAT), 12, 84, 62, 10, 0);
    T_COMBO(&d, ID_C_FMT, 76, 82, 80, 140, CBS_DROPDOWNLIST);
    T_STATIC(&d, ID_C_LVLL, S(S_C_LEVEL), 166, 84, 46, 10, 0);
    T_COMBO(&d, ID_C_LVL, 214, 82, 84, 120, CBS_DROPDOWNLIST);
    T_STATIC(&d, ID_C_METL, S(S_C_METHOD), 12, 102, 62, 10, 0);
    T_COMBO(&d, ID_C_MET, 76, 100, 80, 120, CBS_DROPDOWNLIST);
    T_CHECK(&d, ID_C_SOLID, S(S_C_SOLID), 166, 101, 132, 11);
    T_STATIC(&d, ID_C_PWL, S(S_C_PW), 12, 124, 62, 10, 0);
    T_EDIT(&d, ID_C_PW, L"", 76, 122, 80, 13, ES_PASSWORD);
    T_STATIC(&d, ID_C_ENCL, S(S_C_ENC), 166, 124, 46, 10, 0);
    T_COMBO(&d, ID_C_ENC, 214, 122, 84, 60, CBS_DROPDOWNLIST);
    T_STATIC(&d, ID_C_PW2L, S(S_C_PW2), 12, 142, 62, 10, 0);
    T_EDIT(&d, ID_C_PW2, L"", 76, 140, 80, 13, ES_PASSWORD);
    T_CHECK(&d, ID_C_SHOW, S(S_PW_SHOW), 166, 141, 132, 11);
    T_CHECK(&d, ID_C_ENCNAMES, S(S_C_ENCNAMES), 166, 155, 132, 11);
    T_BUTTON(&d, IDOK, S(S_C_START), 186, 177, 60, 15);
    T_BUTTON(&d, IDCANCEL, S(S_CANCEL), 250, 177, 48, 15);
    int r = GZ_E_CANCEL;
    if (dlgt_run(&d, owner, cdlg_proc, (LPARAM)x) == 1)
        r = run_compress(owner, in, n, x->out, x->format, x->method, x->level, x->enc, x->pw, x->encnames, x->solid,
                         x->overwrite);
    SecureZeroMemory(x->pw, sizeof x->pw);
    mem_free(x);
    return r;
}
