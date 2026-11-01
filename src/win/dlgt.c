/*
 * 고깃ZIP - in-memory dialog templates (DLGTEMPLATEEX)
 *
 * Dialogs are described in C at run time so that their text can be Korean or
 * English and their font follows the UI font. Dialog units scale with the
 * font, so every dialog is DPI-correct on all Windows versions.
 */
#include "app.h"

const wchar_t *gfx_face(void);
int gfx_face_pt(void);

static void put(dlgt *d, const void *p, size_t n)
{
    if (d->len + n > d->cap) {
        size_t nc = d->cap ? d->cap * 2 : 2048;
        while (nc < d->len + n) nc *= 2;
        d->buf = (u8 *)gz_realloc(d->buf, nc);
        d->cap = nc;
    }
    __builtin_memcpy(d->buf + d->len, p, n);
    d->len += n;
}
static void put16(dlgt *d, WORD v) { put(d, &v, 2); }
static void put32(dlgt *d, DWORD v) { put(d, &v, 4); }
static void putstr(dlgt *d, const wchar_t *s) { put(d, s ? s : L"", (wlen(s) + 1) * sizeof(wchar_t)); }
static void align4(dlgt *d) { while (d->len & 3) { u8 z = 0; put(d, &z, 1); } }

#define COUNT_OFF 16

void dlgt_begin(dlgt *d, const wchar_t *title, int cx, int cy, DWORD style)
{
    __builtin_memset(d, 0, sizeof *d);
    put16(d, 1);            /* dlgVer    */
    put16(d, 0xFFFF);       /* signature */
    put32(d, 0);            /* helpID    */
    put32(d, 0);            /* exStyle   */
    put32(d, style | DS_SETFONT | WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME);
    put16(d, 0);            /* cDlgItems (patched) */
    put16(d, 0); put16(d, 0);
    put16(d, (WORD)cx); put16(d, (WORD)cy);
    put16(d, 0);            /* menu  */
    put16(d, 0);            /* class */
    putstr(d, title);
    put16(d, (WORD)gfx_face_pt());
    put16(d, FW_NORMAL);
    u8 b[2] = { 0, DEFAULT_CHARSET };
    put(d, b, 2);
    putstr(d, gfx_face());
}

void dlgt_item(dlgt *d, int id, WORD atom, const wchar_t *cls, const wchar_t *text,
               int x, int y, int cx, int cy, DWORD style, DWORD exstyle)
{
    align4(d);
    put32(d, 0);
    put32(d, exstyle);
    put32(d, style | WS_CHILD | WS_VISIBLE);
    put16(d, (WORD)x); put16(d, (WORD)y); put16(d, (WORD)cx); put16(d, (WORD)cy);
    put32(d, (DWORD)id);
    if (atom) { put16(d, 0xFFFF); put16(d, atom); }
    else putstr(d, cls);
    putstr(d, text);
    put16(d, 0);
    WORD n;
    __builtin_memcpy(&n, d->buf + COUNT_OFF, 2);
    n++;
    __builtin_memcpy(d->buf + COUNT_OFF, &n, 2);
}

INT_PTR dlgt_run(dlgt *d, HWND owner, DLGPROC proc, LPARAM lp)
{
    INT_PTR r = DialogBoxIndirectParamW(g_inst, (LPCDLGTEMPLATEW)d->buf, owner, proc, lp);
    gz_free(d->buf);
    d->buf = 0;
    return r;
}
