/*
 * 고깃ZIP - Unix ar archives: static libraries (.a), Windows .lib, Debian .deb
 *
 * "!<arch>\n", then members: 60-byte header (name[16] mtime[12] uid[6] gid[6]
 * mode[8] size[10] "`\n"), data padded to an even offset.
 *   GNU / System V: "name/", "//" long name table, "/123" = name at offset 123
 *                   of that table ("/\n" terminated; Microsoft: NUL terminated),
 *                   "/" and "/SYM64/" symbol tables (hidden).
 *   BSD:            "#1/len": the name is the first len bytes of the data,
 *                   "__.SYMDEF..." symbol tables (hidden).
 * .deb packages are ar archives starting with "debian-binary": the control and
 * data tarballs are shown as files (opened as nested archives).
 */
#include "arc.h"

#define AR_LONGTAB_MAX (64u << 20)    /* GNU long name table */
#define AR_NAME_MAX    65536u         /* BSD inline names    */

static u64 dec_field(const u8 *p, u32 n, int *ok)
{
    u64 v = 0;
    u32 i = 0;
    while (i < n && p[i] == ' ') i++;
    u32 st = i;
    for (; i < n && p[i] >= '0' && p[i] <= '9'; i++) {
        if (v > (~(u64)0 - 9) / 10) { *ok = 0; return 0; }
        v = v * 10 + (u64)(p[i] - '0');
    }
    for (; i < n; i++) if (p[i] != ' ') *ok = 0;     /* only space padding may follow */
    if (i == st && st < n) *ok = 0;                   /* "   x" */
    return v;
}

static u32 oct_field(const u8 *p, u32 n)
{
    u32 v = 0;
    for (u32 i = 0; i < n && p[i] >= '0' && p[i] <= '7'; i++) v = v << 3 | (u32)(p[i] - '0');
    return v;
}

static int is_symdef(const u8 *p, u32 n)
{
    return n >= 9 && !__builtin_memcmp(p, "__.SYMDEF", 9);
}

static int ar_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 8 || __builtin_memcmp(h, "!<arch>\n", 8)) return 0;
    if (n == 8) return 90;                            /* empty archive */
    if (n >= 68 && h[66] == '`' && h[67] == '\n') return 95;
    return 0;
}

static int ar_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u8 *ltab = 0, *nbuf = 0;
    u64 lsize = 0;
    u64 off = 8;
    u32 count = 0;
    int r = GZ_OK, first = 1;
    while (off + 60 <= s->size) {
        if ((++count & 1023) == 0) {
            if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
            if (c->progress) c->progress(c->progress_user, off, s->size);
        }
        u8 h[60];
        if ((r = gz_src_read_exact(s, off, h, 60))) break;
        int ok = 1;
        u64 size = dec_field(h + 48, 10, &ok);
        if (h[58] != '`' || h[59] != '\n' || !ok) { r = GZ_E_FORMAT; break; }
        u64 data = off + 60;
        if (size > s->size - data) { r = GZ_E_TRUNC; break; }
        u64 next = data + size + (size & 1);
        off = next;

        const u8 *nm = h;
        u32 nl = 16;
        while (nl && nm[nl - 1] == ' ') nl--;
        if (nm[0] == '/') {
            if (nl == 1 || (nl == 7 && !__builtin_memcmp(nm, "/SYM64/", 7))) continue;  /* symbol table */
            if (nl == 2 && nm[1] == '/') {                       /* GNU / Microsoft long names */
                if (size > AR_LONGTAB_MAX) { r = GZ_E_LIMIT; break; }
                gz_free(ltab);
                lsize = 0;
                if (!(ltab = (u8 *)gz_alloc((size_t)size + 1))) { r = GZ_E_NOMEM; break; }
                if ((r = gz_src_read_exact(s, data, ltab, (u32)size))) break;
                lsize = size;
                continue;
            }
            if (nm[1] < '0' || nm[1] > '9') continue;            /* "/<ECSYMBOLS>/" and other specials */
            int okn = 1;
            u64 lo = dec_field(nm + 1, 15, &okn);
            if (!okn || lo >= lsize) { r = GZ_E_FORMAT; break; }
            nm = ltab + lo;
            u32 k = 0, room = (u32)(lsize - lo);
            while (k < room && nm[k] != '\n' && nm[k] != 0) k++;
            nl = k;
            if (nl && nm[nl - 1] == '/') nl--;
        } else if (nl > 3 && nm[0] == '#' && nm[1] == '1' && nm[2] == '/') {      /* BSD */
            int okn = 1;
            u64 bl = dec_field(nm + 3, 13, &okn);
            if (!okn || bl > size || bl > AR_NAME_MAX) { r = GZ_E_FORMAT; break; }
            if (!nbuf && !(nbuf = (u8 *)gz_alloc(AR_NAME_MAX + 1))) { r = GZ_E_NOMEM; break; }
            if ((r = gz_src_read_exact(s, data, nbuf, (u32)bl))) break;
            nm = nbuf;
            nl = (u32)bl;
            while (nl && !nm[nl - 1]) nl--;
            data += bl;
            size -= bl;
            if (is_symdef(nm, nl)) continue;
        } else {
            if (nl && nm[nl - 1] == '/') nl--;                   /* GNU "name/" */
            if (is_symdef(nm, nl) || (nl == 11 && !__builtin_memcmp(nm, "ARFILENAMES", 11))) continue;
        }
        if (!nl) continue;
        gz_entry *e;
        if ((r = gz_arc_add_named(a, nm, nl, GZ_NE_LEGACY, &e))) break;
        e->usize = e->csize = size;
        e->off = data;
        int okt = 1;
        u64 mt = dec_field(h + 16, 12, &okt);
        if (okt && mt) {
            e->mtime = gz_unix_to_filetime((i64)mt);
            e->mtime_kind = GZ_MT_FILETIME;
        }
        u32 mode = oct_field(h + 40, 8);
        e->unix_mode = (mode & 07777) | 0100000u;
        e->attr = (mode && !(mode & 0200)) ? 0x21 : 0x20;
        if (first && nl == 13 && !__builtin_memcmp(nm, "debian-binary", 13)) gz_arc_set_type(a, "DEB");
        first = 0;
    }
    gz_free(ltab);
    gz_free(nbuf);
    if (r == GZ_E_CANCEL || r == GZ_E_NOMEM) return r;
    if (r && !a->n) return r;
    return GZ_OK;                 /* tolerate a damaged tail: members found so far */
}

static int ar_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    return gz_extract_stored(a, s, idx, a->e[idx].off, out, c);
}

static void ar_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a; (void)e;
    if (cap >= 6) __builtin_memcpy(buf, "Store", 6);
}

static gz_src *ar_view(gz_archive *a, gz_src *s, u32 idx)
{
    const gz_entry *e = &a->e[idx];
    return gz_src_sub(s, e->off, e->usize);
}

GZ_FORMAT(gz_fmt_ar)
const gz_format gz_fmt_ar = {
    "AR", "a ar deb lib udeb ddeb ipk", 0, ar_probe, ar_open, 0, ar_extract, 0, 0, ar_method, ar_view, 0
};
