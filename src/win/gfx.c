/*
 * 고깃ZIP - drawing: fonts, icon atlas, anti-aliased shapes, buttons
 *
 * Everything is plain GDI + AlphaBlend (msimg32, available since Windows
 * 2000), so the UI looks the same from Windows 2000 to Windows 11.
 * Icons are pre-rendered premultiplied BGRA images stored as one raw-deflate
 * blob in the resources, unpacked with our own inflate engine at start-up.
 */
#include "app.h"

#define ID_ASSETS 100

gz_fonts g_font;
static wchar_t s_face[LF_FACESIZE];
static int s_face_pt = 9;

/* ---------------- fonts ---------------- */

static int CALLBACK font_enum(const LOGFONTW *lf, const TEXTMETRICW *tm, DWORD type, LPARAM lp)
{
    (void)lf; (void)tm; (void)type;
    *(int *)lp = 1;
    return 0;
}

static int font_exists(const wchar_t *face, BYTE charset)
{
    LOGFONTW lf;
    int found = 0;
    __builtin_memset(&lf, 0, sizeof lf);
    lf.lfCharSet = charset;
    wcopy(lf.lfFaceName, face, LF_FACESIZE);
    HDC dc = GetDC(NULL);
    EnumFontFamiliesExW(dc, &lf, font_enum, (LPARAM)&found, 0);
    ReleaseDC(NULL, dc);
    return found;
}

/* Decide UI language + face. Returns 1 for Korean. */
int gfx_pick_language(void)
{
    static const wchar_t *ko_faces[] = { L"맑은 고딕", L"Malgun Gothic", L"나눔고딕", L"NanumGothic",
                                         L"돋움", L"Dotum", L"굴림", L"Gulim" };
    const wchar_t *ko = 0;
    for (u32 i = 0; i < GZ_COUNTOF(ko_faces) && !ko; i++)
        if (font_exists(ko_faces[i], HANGEUL_CHARSET)) ko = ko_faces[i];
    int korean = g_set.lang == 1 ? 1 : g_set.lang == 2 ? 0 : (ko != 0);
    if (korean && ko) {
        wcopy(s_face, ko, LF_FACESIZE);
        s_face_pt = 9;
    } else if (font_exists(L"Segoe UI", DEFAULT_CHARSET)) {
        wcopy(s_face, L"Segoe UI", LF_FACESIZE);
        s_face_pt = 9;
    } else {
        wcopy(s_face, L"Tahoma", LF_FACESIZE);
        s_face_pt = 8;
    }
    return korean;
}

const wchar_t *gfx_face(void) { return s_face; }
int gfx_face_pt(void) { return s_face_pt; }

static HFONT mkfont(int pt10, int weight)
{
    LOGFONTW lf;
    __builtin_memset(&lf, 0, sizeof lf);
    lf.lfHeight = -MulDiv(pt10, g_dpi, 720);
    lf.lfWeight = weight;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfQuality = CLEARTYPE_QUALITY;
    wcopy(lf.lfFaceName, s_face, LF_FACESIZE);
    return CreateFontIndirectW(&lf);
}

void gfx_fonts_create(void)
{
    int pt = s_face_pt * 10;
    g_font.ui = mkfont(pt, FW_NORMAL);
    g_font.ui_bold = mkfont(pt, FW_BOLD);
    g_font.small = mkfont(pt - 5, FW_NORMAL);
    g_font.title = mkfont(pt + 30, FW_BOLD);
    g_font.big = mkfont(pt + 110, FW_BOLD);
    HDC dc = GetDC(NULL);
    HGDIOBJ o = SelectObject(dc, g_font.ui);
    TEXTMETRICW tm;
    GetTextMetricsW(dc, &tm);
    g_font.ui_h = tm.tmHeight;
    SelectObject(dc, o);
    ReleaseDC(NULL, dc);
}

/* ---------------- asset atlas ---------------- */

typedef struct { u16 id, size; u32 off; } asset_rec;
static u8 *s_pix;
static asset_rec *s_rec;
static u32 s_nrec;
static const u8 *s_comp;          /* compressed stream (benchmark input) */
static u32 s_comp_n, s_raw_n;

void gfx_asset_stream(const u8 **p, u32 *n, u32 *raw)
{
    *p = s_comp;
    *n = s_comp_n;
    *raw = s_raw_n;
}

typedef struct { const u8 *p; u32 left; u8 *out; size_t cap, len; } mem_io;
static int m_read(void *c, u8 *buf, u32 cap, u32 *got)
{
    mem_io *m = (mem_io *)c;
    u32 n = m->left < cap ? m->left : cap;
    __builtin_memcpy(buf, m->p, n);
    m->p += n; m->left -= n;
    *got = n;
    return 0;
}
static int m_write(void *c, const u8 *p, size_t n)
{
    mem_io *m = (mem_io *)c;
    if (m->len + n > m->cap) return GZ_E_DATA;
    __builtin_memcpy(m->out + m->len, p, n);
    m->len += n;
    return 0;
}

#define MAX_CACHE 96
typedef struct { int id, size; HBITMAP bmp; } icon_cache;
static icon_cache s_cache[MAX_CACHE];
static int s_ncache;
static HDC s_memdc;

void gfx_init(void)
{
    HRSRC r = FindResourceW(g_inst, MAKEINTRESOURCEW(ID_ASSETS), (LPCWSTR)RT_RCDATA);
    if (!r) return;
    const u8 *d = (const u8 *)LockResource(LoadResource(g_inst, r));
    DWORD sz = SizeofResource(g_inst, r);
    if (!d || sz < 16 || rd32(d) != 0x31415a47u /* "GZA1" */) return;
    u32 count = rd32(d + 4), raw = rd32(d + 8), comp = rd32(d + 12);
    if (16 + count * 8 + comp > sz) return;
    s_rec = (asset_rec *)mem_alloc(count * sizeof(asset_rec));
    s_pix = (u8 *)gz_alloc_big(raw + 16);
    if (!s_rec || !s_pix) return;
    for (u32 i = 0; i < count; i++) {
        const u8 *e = d + 16 + i * 8;
        s_rec[i].id = rd16(e);
        s_rec[i].size = rd16(e + 2);
        s_rec[i].off = rd32(e + 4);
    }
    gz_inflater *z = gz_inflater_new();
    if (!z) return;
    mem_io m = { d + 16 + count * 8, comp, s_pix, raw, 0 };
    gz_stream_io io = { m_read, m_write, &m };
    if (gz_inflate_run(z, &io, 0) == GZ_OK && m.len == raw) {
        s_nrec = count;
        s_comp = d + 16 + count * 8;
        s_comp_n = comp;
        s_raw_n = raw;
    }
    gz_inflater_free(z);
    s_memdc = CreateCompatibleDC(NULL);
}

/* Build a premultiplied DIB of icon `id` at `size`, box-filtering from a larger master. */
static HBITMAP make_icon(int id, int size)
{
    /* smallest stored size >= requested, else the largest one */
    const asset_rec *ge = 0, *largest = 0, *best;
    for (u32 i = 0; i < s_nrec; i++) {
        const asset_rec *r = &s_rec[i];
        if (r->id != id) continue;
        if (r->size >= size && (!ge || r->size < ge->size)) ge = r;
        if (!largest || r->size > largest->size) largest = r;
    }
    best = ge ? ge : largest;
    if (!best) return 0;
    BITMAPINFO bi;
    __builtin_memset(&bi, 0, sizeof bi);
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = size;
    bi.bmiHeader.biHeight = -size;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    void *bits = 0;
    HBITMAP bmp = CreateDIBSection(NULL, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    if (!bmp) return 0;
    u8 *dst = (u8 *)bits;
    const u8 *src = s_pix + best->off;
    int S = best->size;
    if (S == size) {
        __builtin_memcpy(dst, src, (size_t)size * size * 4);
    } else {
        /* area-weighted resample in 1/256 pixel units (works for up/down scaling) */
        for (int y = 0; y < size; y++) {
            int y0 = y * S * 256 / size, y1 = (y + 1) * S * 256 / size;
            for (int x = 0; x < size; x++) {
                int x0 = x * S * 256 / size, x1 = (x + 1) * S * 256 / size;
                u32 acc[4] = { 0, 0, 0, 0 }, wsum = 0;
                for (int sy = y0 >> 8; sy < S && (sy << 8) < y1; sy++) {
                    int wy = ((sy + 1) << 8 < y1 ? (sy + 1) << 8 : y1) - ((sy << 8) > y0 ? sy << 8 : y0);
                    if (wy <= 0) continue;
                    for (int sx = x0 >> 8; sx < S && (sx << 8) < x1; sx++) {
                        int wx = ((sx + 1) << 8 < x1 ? (sx + 1) << 8 : x1) - ((sx << 8) > x0 ? sx << 8 : x0);
                        if (wx <= 0) continue;
                        u32 w = (u32)(wx * wy);
                        const u8 *p = src + ((size_t)sy * S + sx) * 4;
                        acc[0] += p[0] * w; acc[1] += p[1] * w; acc[2] += p[2] * w; acc[3] += p[3] * w;
                        wsum += w;
                    }
                }
                u8 *o = dst + ((size_t)y * size + x) * 4;
                for (int c = 0; c < 4; c++) o[c] = (u8)(wsum ? (acc[c] + wsum / 2) / wsum : 0);
            }
        }
    }
    return bmp;
}

static HBITMAP icon_bitmap(int id, int size)
{
    for (int i = 0; i < s_ncache; i++)
        if (s_cache[i].id == id && s_cache[i].size == size) return s_cache[i].bmp;
    HBITMAP b = make_icon(id, size);
    if (!b) return 0;
    if (s_ncache == MAX_CACHE) { DeleteObject(s_cache[0].bmp); s_ncache--; __builtin_memmove(s_cache, s_cache + 1, sizeof(icon_cache) * s_ncache); }
    s_cache[s_ncache].id = id;
    s_cache[s_ncache].size = size;
    s_cache[s_ncache].bmp = b;
    s_ncache++;
    return b;
}

void gfx_draw_icon(HDC dc, int id, int x, int y, int size, BYTE alpha)
{
    HBITMAP b = icon_bitmap(id, size);
    if (!b || !s_memdc) return;
    HGDIOBJ o = SelectObject(s_memdc, b);
    BLENDFUNCTION bf = { AC_SRC_OVER, 0, alpha, AC_SRC_ALPHA };
    AlphaBlend(dc, x, y, size, size, s_memdc, 0, 0, size, size, bf);
    SelectObject(s_memdc, o);
}

HICON gfx_app_icon(int size)
{
    return (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(1), IMAGE_ICON, size, size, 0);
}

/* ---------------- shapes ---------------- */

void gfx_fill(HDC dc, const RECT *r, COLORREF c)
{
    COLORREF old = SetBkColor(dc, c);
    ExtTextOutW(dc, 0, 0, ETO_OPAQUE, r, NULL, 0, NULL);
    SetBkColor(dc, old);
}

static float clampf(float v) { return v < 0 ? 0 : v > 1 ? 1 : v; }

/* Anti-aliased rounded rectangle with optional border, via signed distance. */
void gfx_round_rect(HDC dc, const RECT *r, int radius, COLORREF fill, COLORREF border, int bw)
{
    int w = r->right - r->left, h = r->bottom - r->top;
    if (w <= 0 || h <= 0) return;
    BITMAPINFO bi;
    __builtin_memset(&bi, 0, sizeof bi);
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    void *bits = 0;
    HBITMAP bmp = CreateDIBSection(NULL, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    if (!bmp) return;
    u32 *px = (u32 *)bits;
    float rad = (float)radius;
    if (rad * 2 > w) rad = w / 2.0f;
    if (rad * 2 > h) rad = h / 2.0f;
    float hx = w / 2.0f, hy = h / 2.0f;
    u32 fr = GetRValue(fill), fg = GetGValue(fill), fb = GetBValue(fill);
    u32 br = GetRValue(border), bg = GetGValue(border), bb = GetBValue(border);
    for (int y = 0; y < h; y++) {
        float qy = (y + 0.5f > hy ? y + 0.5f - hy : hy - y - 0.5f) - (hy - rad);
        for (int x = 0; x < w; x++) {
            float qx = (x + 0.5f > hx ? x + 0.5f - hx : hx - x - 0.5f) - (hx - rad);
            float d;
            if (qx <= 0 && qy <= 0) d = (qx > qy ? qx : qy) - rad;
            else {
                float ax = qx > 0 ? qx : 0, ay = qy > 0 ? qy : 0;
                d = __builtin_sqrtf(ax * ax + ay * ay) - rad;
            }
            float outer = clampf(0.5f - d);
            float inner = bw > 0 ? clampf(0.5f - (d + (float)bw)) : outer;
            float bc = outer - inner;
            u32 a = (u32)(outer * 255.0f + 0.5f);
            u32 R = (u32)(fr * inner + br * bc + 0.5f);
            u32 G = (u32)(fg * inner + bg * bc + 0.5f);
            u32 B = (u32)(fb * inner + bb * bc + 0.5f);
            px[y * w + x] = (a << 24) | (R << 16) | (G << 8) | B;
        }
    }
    HDC m = CreateCompatibleDC(dc);
    HGDIOBJ o = SelectObject(m, bmp);
    BLENDFUNCTION bf = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    AlphaBlend(dc, r->left, r->top, w, h, m, 0, 0, w, h, bf);
    SelectObject(m, o);
    DeleteDC(m);
    DeleteObject(bmp);
}

void gfx_text(HDC dc, const wchar_t *s, const RECT *r, HFONT f, COLORREF c, UINT fmt)
{
    RECT rr = *r;
    HGDIOBJ o = SelectObject(dc, f);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, c);
    DrawTextW(dc, s, -1, &rr, fmt | DT_NOPREFIX);
    SelectObject(dc, o);
}

int gfx_text_w(HDC dc, const wchar_t *s, HFONT f)
{
    SIZE sz = { 0, 0 };
    HGDIOBJ o = SelectObject(dc, f);
    GetTextExtentPoint32W(dc, s, (int)wlen(s), &sz);
    SelectObject(dc, o);
    return sz.cx;
}

/* ---------------- owner-drawn buttons ---------------- */

static LRESULT CALLBACK btn_proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    WNDPROC old = (WNDPROC)GetPropW(h, L"gzold");
    if (m == WM_MOUSEMOVE && !GetPropW(h, L"gzhot")) {
        TRACKMOUSEEVENT t = { sizeof t, TME_LEAVE, h, 0 };
        SetPropW(h, L"gzhot", (HANDLE)1);
        TrackMouseEvent(&t);
        InvalidateRect(h, NULL, FALSE);
    } else if (m == WM_MOUSELEAVE) {
        RemovePropW(h, L"gzhot");
        InvalidateRect(h, NULL, FALSE);
    } else if (m == WM_NCDESTROY) {
        RemovePropW(h, L"gzhot");
        RemovePropW(h, L"gzold");
        SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)old);
    } else if (m == WM_ERASEBKGND) {
        return 1;
    } else if (m == WM_GETDLGCODE) {
        /* Owner-drawn buttons are not "push buttons" to the dialog manager, so
         * Enter would run the dialog's default button instead of the focused
         * one (Tab to "Skip" + Enter must skip, not overwrite). Take Enter here. */
        const MSG *msg = (const MSG *)lp;
        LRESULT r = CallWindowProcW(old, h, m, wp, lp);
        if (msg && msg->message == WM_KEYDOWN && msg->wParam == VK_RETURN) r |= DLGC_WANTMESSAGE;
        return r;
    } else if (m == WM_KEYDOWN && wp == VK_RETURN) {
        if (IsWindowEnabled(h))
            SendMessageW(GetParent(h), WM_COMMAND, MAKEWPARAM(GetDlgCtrlID(h), BN_CLICKED), (LPARAM)h);
        return 0;
    } else if (m == WM_CHAR && wp == '\r') {
        return 0;
    }
    return CallWindowProcW(old, h, m, wp, lp);
}

void gfx_button_hook(HWND btn)
{
    SetPropW(btn, L"gzold", (HANDLE)GetWindowLongPtrW(btn, GWLP_WNDPROC));
    SetWindowLongPtrW(btn, GWLP_WNDPROC, (LONG_PTR)btn_proc);
}

void gfx_button_draw(const DRAWITEMSTRUCT *di, int primary)
{
    HDC dc = di->hDC;
    RECT r = di->rcItem;
    int hot = GetPropW(di->hwndItem, L"gzhot") != 0;
    int down = (di->itemState & ODS_SELECTED) != 0;
    int dis = (di->itemState & ODS_DISABLED) != 0;
    HWND parent = GetParent(di->hwndItem);
    HBRUSH bgb = (HBRUSH)SendMessageW(parent, WM_CTLCOLORBTN, (WPARAM)dc, (LPARAM)di->hwndItem);
    LOGBRUSH lb;
    COLORREF bg = C_BG;
    if (bgb && GetObjectW(bgb, sizeof lb, &lb)) bg = lb.lbColor;
    gfx_fill(dc, &r, bg);

    COLORREF fill, border, text;
    if (primary) {
        fill = dis ? RGB(236, 170, 172) : down ? C_ACCENT_DK : hot ? C_ACCENT_HOT : C_ACCENT;
        border = fill;
        text = RGB(255, 255, 255);
    } else {
        fill = down ? RGB(236, 236, 240) : hot ? RGB(246, 246, 248) : RGB(255, 255, 255);
        border = hot || down ? RGB(196, 198, 206) : RGB(214, 216, 222);
        text = dis ? RGB(170, 172, 178) : C_TEXT;
    }
    RECT rr = r;
    InflateRect(&rr, -1, -1);
    gfx_round_rect(dc, &rr, scale(5), fill, border, primary ? 0 : 1);
    wchar_t t[128];
    GetWindowTextW(di->hwndItem, t, 128);
    gfx_text(dc, t, &r, primary ? g_font.ui_bold : g_font.ui, text, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    if ((di->itemState & ODS_FOCUS) && !(di->itemState & ODS_NOFOCUSRECT) && !primary) {
        RECT f = r;
        InflateRect(&f, -scale(4), -scale(4));
        SetTextColor(dc, C_TEXT);
        SetBkColor(dc, fill);
        DrawFocusRect(dc, &f);
    }
}

/* ---------------- theme helper (Vista+ explorer look) ---------------- */

typedef HRESULT (WINAPI *SetWindowTheme_t)(HWND, LPCWSTR, LPCWSTR);

void gfx_set_theme(HWND hwnd, const wchar_t *app)
{
    static SetWindowTheme_t fn;
    static int tried;
    if (!tried) {
        tried = 1;
        if (g_os.major >= 6) {
            HMODULE ux = LoadLibraryW(L"uxtheme.dll");
            if (ux) fn = (SetWindowTheme_t)(void *)GetProcAddress(ux, "SetWindowTheme");
        }
    }
    if (fn) fn(hwnd, app, NULL);
}
