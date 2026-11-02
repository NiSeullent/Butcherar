/*
 * win_dlgt - run-time dialog templates of the Windows UI (src/win/dlgt.c), under Wine
 *
 *   win_dlgt.exe   builds a DLGTEMPLATEEX with controls whose text starts with U+FFFF
 *                  (an archive comment or a file name can), then
 *                  1. walks it the way the dialog manager does - a title starting with
 *                     0xFFFF is an ordinal, then extraCount and that many bytes of
 *                     creation data - and checks that it finds exactly the controls
 *                     dlgt_item wrote: same count and ids, no ordinal title, every read
 *                     inside the buffer, the walk ending at its end;
 *                  2. creates the dialog (CreateDialogIndirectParamW, needs a display)
 *                     and checks each control by id and its text.
 *                  Prints "ok" or what differs; exit status 0 / 1.
 *
 * Built with MinGW by tests/cases/regress_windows_ui.py together with src/win/dlgt.c
 * (the stubs below stand for gfx.c, util.c and rt.c).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "../../src/win/app.h"

HINSTANCE g_inst;
const wchar_t *gfx_face(void) { return L"Tahoma"; }
int gfx_face_pt(void) { return 9; }
size_t wlen(const wchar_t *s) { size_t n = 0; if (s) while (s[n]) n++; return n; }
void *gz_alloc(size_t n) { return calloc(1, n ? n : 1); }
void *gz_realloc(void *p, size_t n) { return realloc(p, n ? n : 1); }
void gz_free(void *p) { free(p); }

typedef struct { int id; WORD atom; const wchar_t *text; const wchar_t *want; } item;

static const item k_items[] = {
    { 801, DA_STATIC, L"label", L"label" },
    /* ordinal 0x41, extraCount 2 ("A" skipped), then the rest would be parsed as controls */
    { 841, DA_EDIT, L"\xFFFF\x0041\x0002\x0041 INJECTED", L"\xFFFD\x0041\x0002\x0041 INJECTED" },
    /* ordinal 0x41, extraCount 65534: the parser would skip far past the template */
    { 842, DA_EDIT, L"\xFFFF\x0041\xFFFE", L"\xFFFD\x0041\xFFFE" },
    { 843, DA_STATIC, L"\xFFFF", L"\xFFFD" },
    { 844, DA_STATIC, L"", L"" },
    { IDOK, DA_BUTTON, L"Close", L"Close" },
};
#define NITEMS ((int)(sizeof k_items / sizeof k_items[0]))

static int g_fail;
static void fail(const char *what, int a, int b)
{
    printf("FAIL %s (%d, %d)\n", what, a, b);
    g_fail = 1;
}

/* (rd16 / rd32: unaligned little-endian reads of base.h) */

/* sz_Or_Ord: offset after it, or 0 when it runs past end; *ord = it is an ordinal */
static size_t sz_or_ord(const BYTE *b, size_t pos, size_t end, int *ord, size_t *str)
{
    if (pos + 2 > end) return 0;
    if (rd16(b + pos) == 0xFFFF) { *ord = 1; return pos + 4 <= end ? pos + 4 : 0; }
    *ord = 0;
    *str = pos;
    while (pos + 2 <= end && rd16(b + pos)) pos += 2;
    return pos + 2 <= end ? pos + 2 : 0;
}

static int same_text(const BYTE *b, size_t str, const wchar_t *want)
{
    size_t i = 0;
    for (; want[i]; i++) if (rd16(b + str + 2 * i) != (WORD)want[i]) return 0;
    return rd16(b + str + 2 * i) == 0;
}

static void walk(const dlgt *d)
{
    const BYTE *b = d->buf;
    size_t end = d->len, pos;
    int ord;
    size_t str = 0;
    if (end < 26 || rd16(b) != 1 || rd16(b + 2) != 0xFFFF) { fail("header", (int)end, 0); return; }
    DWORD style = rd32(b + 12);
    int count = rd16(b + 16);
    if (count != NITEMS) fail("cDlgItems", count, NITEMS);
    pos = 26;
    for (int k = 0; k < 3 && pos; k++) pos = sz_or_ord(b, pos, end, &ord, &str);   /* menu, class, title */
    if (pos && (style & DS_SETFONT)) {
        pos += 6;
        pos = pos <= end ? sz_or_ord(b, pos, end, &ord, &str) : 0;
    }
    if (!pos) { fail("dialog header runs past the end", 0, 0); return; }
    for (int i = 0; i < count; i++) {
        pos = (pos + 3) & ~(size_t)3;
        if (pos + 24 > end) { fail("item header past the end", i, (int)pos); return; }
        int id = (int)rd32(b + pos + 20);
        pos += 24;
        pos = sz_or_ord(b, pos, end, &ord, &str);               /* class */
        if (!pos) { fail("item class past the end", i, id); return; }
        pos = sz_or_ord(b, pos, end, &ord, &str);               /* title */
        if (!pos) { fail("item title past the end", i, id); return; }
        if (ord) fail("item title is an ordinal", i, id);
        if (pos + 2 > end) { fail("extraCount past the end", i, id); return; }
        size_t extra = rd16(b + pos);
        pos += 2 + extra;
        if (pos > end) { fail("creation data past the end", i, (int)extra); return; }
        if (i < NITEMS && id != k_items[i].id) fail("item id", i, id);
        if (i < NITEMS && !ord && !same_text(b, str, k_items[i].want)) fail("item text", i, id);
    }
    if (((pos + 3) & ~(size_t)3) != ((end + 3) & ~(size_t)3)) fail("walk does not end at the end", (int)pos, (int)end);
}

static INT_PTR CALLBACK proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    (void)h; (void)wp; (void)lp;
    return m == WM_INITDIALOG;
}

static void create(const dlgt *d)
{
    HWND h = CreateDialogIndirectParamW(GetModuleHandleW(NULL), (LPCDLGTEMPLATEW)d->buf, NULL, proc, 0);
    if (!h) { fail("CreateDialogIndirectParamW", (int)GetLastError(), 0); return; }
    for (int i = 0; i < NITEMS; i++) {
        HWND c = GetDlgItem(h, k_items[i].id);
        wchar_t t[64];
        if (!c) { fail("control missing", i, k_items[i].id); continue; }
        t[0] = 0;
        GetWindowTextW(c, t, 64);
        if (wcscmp(t, k_items[i].want)) fail("control text", i, (int)t[0]);
    }
    int n = 0;
    for (HWND c = GetWindow(h, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) n++;
    if (n != NITEMS) fail("number of controls", n, NITEMS);
    DestroyWindow(h);
}

int main(int argc, char **argv)
{
    dlgt d;
    g_inst = GetModuleHandleW(NULL);
    dlgt_begin(&d, L"dlgt", 200, 140, 0);
    for (int i = 0; i < NITEMS; i++)
        dlgt_item(&d, k_items[i].id, k_items[i].atom, 0, k_items[i].text, 8, 8 + 16 * i, 180, 12,
                  k_items[i].atom == DA_EDIT ? ES_AUTOHSCROLL : 0, 0);
    walk(&d);
    if (argc < 2 || strcmp(argv[1], "nogui")) create(&d);
    gz_free(d.buf);
    if (!g_fail) printf("ok\n");
    return g_fail;
}
