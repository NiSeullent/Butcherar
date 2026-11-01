/*
 * 고깃ZIP - PE/COFF executables and DLLs (PE32, PE32+) and TE images (UEFI)
 *
 * Entries, in file order:
 *   .text .data ...     raw section data (SizeOfRawData bytes, clamped to the file, like
 *                       7-Zip); MinGW long names ("/4") come from the COFF string table
 *   .rsrc/...           the resource tree instead of the raw resource section:
 *     ICON              <id>.ico: the image with a one-entry ICONDIR (7-Zip's header);
 *                       PNG images as <id>.png
 *     GROUP_ICON        <name>.ico: the complete icon rebuilt from the group directory
 *                       and its ICON images (as icoutils' wrestool does)
 *     GROUP_CURSOR      <name>.cur: likewise, hot spots taken from the CURSOR images
 *     BITMAP            <id>.bmp: BITMAPFILEHEADER + resource
 *     VERSION           <id> (raw) and <id>.txt (VS_VERSIONINFO as text in 7-Zip's layout)
 *     STRING            STRING.txt: every string table of a language, "id<TAB>text" lines
 *     MANIFEST          <id>.manifest; HTML .html; FONT .fnt; ANICURSOR/ANIICON .ani
 *     others            raw; RCDATA and unknown types get an extension from their content
 *   COFF_SYMBOLS        COFF symbol + string table (unstripped MinGW binaries)
 *   [certificate].p7b   Authenticode signature (the PKCS#7 DER inside WIN_CERTIFICATE)
 *   [overlay]           data after the image (installer payloads, appended archives)
 *
 * Resource names are ".rsrc/<TYPE>/<NAME><ext>"; a name present in several languages
 * becomes a folder ".rsrc/<TYPE>/<NAME>/<LANG><ext>" (".rsrc/STRING/<LANG>.txt").
 * Generated texts are UTF-8 with a BOM and CRLF line ends.
 *
 * Every entry is a short list of pieces (file ranges or bytes kept in memory, e.g. a
 * synthesized ICO header or a text), so extraction and view() are generic: view()
 * gives a random-access source of any entry, so archives inside the overlay or in a
 * resource open in place.
 *
 * Hostile input: all offsets/sizes are checked against the file and the sections; the
 * resource directory is walked exactly three levels deep, a directory reached twice is
 * skipped (cycles, shared subtrees) and the walk, the leaves, the generated text and
 * the memory blob are capped.
 *
 * Registered GZ_FMT_WEAK: an SFX with an appended archive opens as that archive
 * through the archive format's own probe; PE only lists what nothing else claims.
 */
#include "exe.h"

#define PE_MAX_RES    (1u << 18)       /* resource leaves                          */
#define PE_MAX_WALK   (1u << 20)       /* resource directory entries visited       */
#define PE_MAX_TEXT   (64u << 20)      /* generated text in total                  */
#define PE_MAX_BLOB   (128u << 20)     /* bytes kept in memory (headers + texts)   */
#define PE_MAX_SMALL  (4u << 20)       /* resources read at open (groups, version) */
#define PE_MAX_GROUPS (1u << 20)       /* icon/cursor group entries processed      */
#define PE_MAX_LANGS  256              /* string table languages (as 7-Zip)        */
#define PE_NAME_UNITS 512              /* UTF-16 units used from a resource name   */
#define RS_BLK        32768u           /* directory cache block                    */
#define RS_SLOTS      4

enum { RT_CURSOR = 1, RT_BITMAP = 2, RT_ICON = 3, RT_STRING = 6, RT_FONT = 8, RT_RCDATA = 10,
       RT_GROUP_CURSOR = 12, RT_GROUP_ICON = 14, RT_VERSION = 16, RT_ANICURSOR = 21,
       RT_ANIICON = 22, RT_HTML = 23, RT_MANIFEST = 24 };

static const char *const k_rtypes[25] = {
    0, "CURSOR", "BITMAP", "ICON", "MENU", "DIALOG", "STRING", "FONTDIR", "FONT",
    "ACCELERATOR", "RCDATA", "MESSAGETABLE", "GROUP_CURSOR", 0, "GROUP_ICON", 0,
    "VERSION", "DLGINCLUDE", 0, "PLUGPLAY", "VXD", "ANICURSOR", "ANIICON", "HTML", "MANIFEST"
};

/* gz_entry.flags: entry kind; aux = section characteristics or resource language */
enum { K_SECT = 1, K_RES, K_SYM, K_CERT, K_OVL };

/* data piece: a file range or bytes at blob[off] */
typedef struct { u64 off, len; u32 mem, pad_; } pe_piece;

typedef struct {
    pe_piece *pc; u32 npc, cappc;
    u8 *blob; u32 nblob, capblob;
} pe_priv;

typedef struct {
    u8  name[8];
    u32 vsize, va, rawsize, rawptr, chars;
    u64 foff, flen;              /* raw data present in the file */
} pe_sect;

typedef struct {
    u32 type, name;              /* id, or 0x80000000 | offset of the name string */
    u32 lang, size;
    u64 foff;                    /* data in the file (ok)                         */
    u32 grp;                     /* name directory this leaf hangs off            */
    u32 hnext;                   /* ICON/CURSOR id hash chain                     */
    u8  ok, merged;              /* data present; merged into a string text       */
} pe_res;

typedef struct { u8 *p; u32 n, cap; int err; } tbuf;
typedef struct { u32 lang; u8 done; tbuf t; } pe_strs;
typedef struct { u64 off; u32 len; u8 *p; } rs_slot;

typedef struct {
    gz_archive *a; gz_src *s; gz_ctx *c; pe_priv *p;
    u64 fsize;
    pe_sect *sec; u32 nsec;
    u32 *sorted;                 /* section indices by VA                          */
    int te;
    u32 ts;                      /* COFF TimeDateStamp                             */
    u64 hdr_end;                 /* headers: max(SizeOfHeaders, section table end)  */
    u64 hdr_size, tab_end;
    u64 sym_off, sym_end, str_off, str_size;
    u32 dir_rva[16], dir_size[16];
    /* resources */
    int rs_sec;                  /* section holding the resource directory or -1  */
    u64 rs_base, rs_lim;
    rs_slot slot[RS_SLOTS]; u32 slot_next;
    u32 *vis; u32 vcap, vn;      /* visited directory offsets (hash set)            */
    u32 nwalk;
    pe_res *res; u32 nres, capres;
    u32 ngrp; u32 *grpn;         /* usable leaves per name directory                */
    u32 *hash; u32 hcap;         /* ICON / CURSOR lookup                           */
    pe_strs *strs; u32 nstrs;
    u64 ntext;
    u32 ngroup_ents;
    u64 budget;                  /* file bytes the entries may still cover          */
} pe_ctx;

/* ---------------- small helpers ---------------- */

static GZ_NOINLINE int pc_add(pe_priv *p, u64 off, u64 len, u32 mem)
{
    if (p->npc == p->cappc) {
        if (p->cappc >= (1u << 24)) return GZ_E_LIMIT;
        u32 nc = p->cappc ? p->cappc * 2 : 256;
        pe_piece *n = (pe_piece *)gz_realloc(p->pc, (size_t)nc * sizeof(pe_piece));
        if (!n) return GZ_E_NOMEM;
        p->pc = n;
        p->cappc = nc;
    }
    pe_piece *q = &p->pc[p->npc++];
    q->off = off;
    q->len = len;
    q->mem = mem;
    q->pad_ = 0;
    return GZ_OK;
}

static int pc_file(pe_priv *p, u64 off, u64 len) { return len ? pc_add(p, off, len, 0) : GZ_OK; }

static GZ_NOINLINE int pc_mem(pe_priv *p, const void *d, u32 n)
{
    if (!n) return GZ_OK;
    if (n > PE_MAX_BLOB - p->nblob) return GZ_E_LIMIT;
    if (p->nblob + n > p->capblob) {
        u32 nc = p->capblob ? p->capblob : 4096;
        while (nc < p->nblob + n) nc *= 2;
        u8 *b = (u8 *)gz_realloc(p->blob, nc);
        if (!b) return GZ_E_NOMEM;
        p->blob = b;
        p->capblob = nc;
    }
    __builtin_memcpy(p->blob + p->nblob, d, n);
    int r = pc_add(p, p->nblob, n, 1);
    if (!r) p->nblob += n;
    return r;
}

static void pc_rewind(pe_priv *p, u32 first);

/* entry from pieces [first, npc). Overlapping sections or resources could list the same
 * bytes over and over: entries beyond a budget of file bytes are dropped (*pe = NULL). */
static int add_entry(pe_ctx *x, const gz_xname *w, u32 first, u32 kind, u64 aux, gz_entry **pe)
{
    u64 sz = 0, fb = 0;
    for (u32 i = first; i < x->p->npc; i++) {
        sz += x->p->pc[i].len;
        if (!x->p->pc[i].mem) fb += x->p->pc[i].len;
    }
    if (pe) *pe = 0;
    if (fb > x->budget) { pc_rewind(x->p, first); return GZ_OK; }
    x->budget -= fb;
    gz_entry *e;
    int r = gz_exe_add(x->a, w, &e);
    if (r) return r;
    e->off = first;
    e->aux32 = x->p->npc - first;
    e->usize = e->csize = sz;
    e->flags = (u16)kind;
    e->aux = aux;
    if (pe) *pe = e;
    return GZ_OK;
}

/* drop pieces (and blob bytes) added since a failed conversion */
static void pc_rewind(pe_priv *p, u32 first)
{
    for (u32 i = first; i < p->npc; i++)
        if (p->pc[i].mem && p->pc[i].off < p->nblob) p->nblob = (u32)p->pc[i].off;
    p->npc = first;
}

static GZ_NOINLINE void tb_put(tbuf *t, const void *s, u32 n)
{
    if (t->err || !n) return;
    if (n > PE_MAX_TEXT - t->n) { t->err = GZ_E_LIMIT; return; }
    if (t->n + n > t->cap) {
        u32 nc = t->cap ? t->cap : 1024;
        while (nc < t->n + n) nc *= 2;
        u8 *q = (u8 *)gz_realloc(t->p, nc);
        if (!q) { t->err = GZ_E_NOMEM; return; }
        t->p = q;
        t->cap = nc;
    }
    __builtin_memcpy(t->p + t->n, s, n);
    t->n += n;
}

static GZ_NOINLINE void tb_str(tbuf *t, const char *s)
{
    u32 n = 0;
    while (s[n]) n++;
    tb_put(t, s, n);
}

static void tb_ch(tbuf *t, char c) { tb_put(t, &c, 1); }
static void tb_nl(tbuf *t) { tb_put(t, "\r\n", 2); }
static void tb_spaces(tbuf *t, int n) { while (n-- > 0) tb_ch(t, ' '); }

static void tb_dec(tbuf *t, u32 v)
{
    gz_xname w;
    gz_xn_reset(&w);
    gz_xn_num(&w, v);
    tb_put(t, w.b, w.n);
}

static void tb_hex(tbuf *t, u32 v)
{
    char b[12];
    int k = 0;
    do { b[k++] = "0123456789ABCDEF"[v & 15]; v >>= 4; } while (v);
    tb_str(t, "0x");
    while (k) tb_ch(t, b[--k]);
}

/* n UTF-16LE units as UTF-8; esc: '\n' becomes "\n" (string tables) */
static GZ_NOINLINE void tb_u16(tbuf *t, const u8 *le, u32 n, int esc)
{
    u8 o[256 * 3 + 8];
    u32 k = 0;
    for (u32 i = 0; i < n; i++) {
        u32 c = rd16(le + 2 * i);
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < n && rd16(le + 2 * i + 2) >= 0xDC00 && rd16(le + 2 * i + 2) < 0xE000) {
            c = 0x10000 + ((c - 0xD800) << 10) + (rd16(le + 2 * i + 2) - 0xDC00u);
            i++;
        } else if (c >= 0xD800 && c < 0xE000) {
            c = 0xFFFD;
        }
        if (esc && c == '\n') { o[k++] = '\\'; o[k++] = 'n'; }
        else if (c < 0x80) o[k++] = (u8)c;
        else if (c < 0x800) { o[k++] = (u8)(0xC0 | c >> 6); o[k++] = (u8)(0x80 | (c & 63)); }
        else if (c < 0x10000) {
            o[k++] = (u8)(0xE0 | c >> 12); o[k++] = (u8)(0x80 | ((c >> 6) & 63)); o[k++] = (u8)(0x80 | (c & 63));
        } else {
            o[k++] = (u8)(0xF0 | c >> 18); o[k++] = (u8)(0x80 | ((c >> 12) & 63));
            o[k++] = (u8)(0x80 | ((c >> 6) & 63)); o[k++] = (u8)(0x80 | (c & 63));
        }
        if (k >= 256 * 3) { tb_put(t, o, k); k = 0; }
    }
    tb_put(t, o, k);
}

static void tb_free(tbuf *t) { gz_free(t->p); t->p = 0; t->n = t->cap = 0; }

/* " \"<n bytes of UTF-16>\"" as 7-Zip's AddParamString */
static void tb_param(tbuf *t, const u8 *le, u32 nbytes)
{
    tb_str(t, " \"");
    tb_u16(t, le, nbytes / 2, 0);
    tb_ch(t, '"');
}

static const u8 k_bom[3] = { 0xEF, 0xBB, 0xBF };

/* ---------------- RVA mapping ---------------- */

/* file offset of [rva, rva+len) when it lies in one section's raw data (or the headers) */
static int rva_map(const pe_ctx *x, u32 rva, u32 len, u64 *off)
{
    u32 lo = 0, hi = x->nsec;              /* last section (by VA) with va <= rva */
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        if (x->sec[x->sorted[mid]].va <= rva) lo = mid + 1; else hi = mid;
    }
    for (u32 k = lo; k-- > 0 && k + 8 >= lo;) {   /* a few candidates: overlapping sections */
        const pe_sect *t = &x->sec[x->sorted[k]];
        u64 d = (u64)rva - t->va;
        if (d < t->flen && len <= t->flen - d) { *off = t->foff + d; return 1; }
    }
    if (!x->te && (u64)rva + len <= x->hdr_end && (!x->nsec || rva < x->sec[x->sorted[0]].va)) {
        *off = rva;
        return 1;
    }
    return 0;
}

static int rva_sect(const pe_ctx *x, u32 rva)
{
    for (u32 i = 0; i < x->nsec; i++) {
        const pe_sect *t = &x->sec[i];
        if (rva >= t->va && (u64)rva - t->va < t->flen) return (int)i;
    }
    return -1;
}

/* ---------------- headers ---------------- */

static void sort_sections(pe_ctx *x)
{
    u32 n = x->nsec;
    for (u32 i = 0; i < n; i++) x->sorted[i] = i;
    /* shell sort (n <= 65535) by VA */
    for (u32 gap = n / 2; gap; gap /= 2)
        for (u32 i = gap; i < n; i++) {
            u32 v = x->sorted[i], j = i;
            while (j >= gap && x->sec[x->sorted[j - gap]].va > x->sec[v].va) {
                x->sorted[j] = x->sorted[j - gap];
                j -= gap;
            }
            x->sorted[j] = v;
        }
}

static int read_sections(pe_ctx *x, u64 table, u32 n, i64 adj)
{
    if (table > x->fsize) n = 0;
    else if ((u64)n * 40 > x->fsize - table) n = (u32)((x->fsize - table) / 40);
    x->sec = (pe_sect *)gz_alloc((size_t)n * sizeof(pe_sect) + 1);
    x->sorted = (u32 *)gz_alloc((size_t)n * sizeof(u32) + 4);
    if (!x->sec || !x->sorted) return GZ_E_NOMEM;
    u8 *raw = (u8 *)gz_alloc((size_t)n * 40 + 1);
    if (!raw) return GZ_E_NOMEM;
    int r = n ? gz_src_read_exact(x->s, table, raw, n * 40) : GZ_OK;
    if (r) { gz_free(raw); return r; }
    for (u32 i = 0; i < n; i++) {
        const u8 *q = raw + 40 * i;
        pe_sect *t = &x->sec[i];
        __builtin_memcpy(t->name, q, 8);
        t->vsize = rd32(q + 8);
        t->va = rd32(q + 12);
        t->rawsize = rd32(q + 16);
        t->rawptr = rd32(q + 20);
        t->chars = rd32(q + 36);
        i64 fo = (i64)t->rawptr + adj;
        if (t->rawsize && fo >= 0 && (u64)fo < x->fsize) {
            t->foff = (u64)fo;
            t->flen = GZ_MIN((u64)t->rawsize, x->fsize - t->foff);
        }
    }
    gz_free(raw);
    x->nsec = n;
    x->tab_end = table + (u64)n * 40;
    if (x->tab_end > x->hdr_end) x->hdr_end = x->tab_end;
    sort_sections(x);
    return GZ_OK;
}

static int pe_headers(pe_ctx *x, const u8 *h)
{
    u32 lf = rd32(h + 0x3C);
    if (lf > x->fsize - 24 || lf > (16u << 20)) return GZ_E_FORMAT;
    u8 ph[24 + 240];
    u32 want = x->fsize - lf < sizeof ph ? (u32)(x->fsize - lf) : (u32)sizeof ph;
    __builtin_memset(ph, 0, sizeof ph);
    int r = gz_src_read_exact(x->s, lf, ph, want);
    if (r) return r;
    if (rd32(ph) != 0x00004550u) return GZ_E_FORMAT;
    u32 nsec = rd16(ph + 6);
    x->ts = rd32(ph + 8);
    u32 symptr = rd32(ph + 12), nsym = rd32(ph + 16);
    u32 optsz = rd16(ph + 20);
    const u8 *opt = ph + 24;
    u32 avail = GZ_MIN(optsz, want - 24);
    u32 magic = avail >= 2 ? rd16(opt) : 0;
    u32 hdr = avail >= 64 ? rd32(opt + 60) : 0;
    x->hdr_end = x->hdr_size = GZ_MIN((u64)hdr, x->fsize);
    u32 nrva_at = magic == 0x20B ? 108 : 92, dirs = nrva_at + 4;
    if ((magic == 0x10B || magic == 0x20B) && avail >= dirs) {
        u32 nrva = rd32(opt + nrva_at);
        for (u32 i = 0; i < 16 && i < nrva && dirs + 8 * i + 8 <= avail; i++) {
            x->dir_rva[i] = rd32(opt + dirs + 8 * i);
            x->dir_size[i] = rd32(opt + dirs + 8 * i + 4);
        }
    }
    /* COFF symbol table (+ string table right after it) */
    if (symptr && symptr < x->fsize) {
        u64 se = (u64)symptr + (u64)nsym * 18;
        if (se <= x->fsize) {
            x->sym_off = symptr;
            x->sym_end = se;
            u8 b[4];
            if (se + 4 <= x->fsize && !gz_src_read_exact(x->s, se, b, 4)) {
                u32 ss = rd32(b);
                if (ss >= 4 && ss <= x->fsize - se) { x->str_off = se; x->str_size = ss; x->sym_end = se + ss; }
            }
        }
    }
    return read_sections(x, (u64)lf + 24 + optsz, nsec, 0);
}

static const u16 k_te_machines[] = { 0x14C, 0x8664, 0xAA64, 0x1C0, 0x1C2, 0x1C4, 0xEBC, 0x200,
                                     0x5032, 0x5064, 0x5128, 0x6232, 0x6264 };

static int te_ok(const u8 *h, u64 fsize)
{
    if (h[0] != 'V' || h[1] != 'Z' || !h[4]) return 0;
    u32 m = rd16(h + 2), ok = 0;
    for (u32 i = 0; i < GZ_COUNTOF(k_te_machines); i++) ok |= k_te_machines[i] == m;
    if (!ok || h[5] < 10 || h[5] > 13) return 0;           /* EFI subsystems */
    if (rd16(h + 6) < 40 || 40 + (u64)h[4] * 40 > fsize) return 0;
    return 1;
}

static int te_headers(pe_ctx *x, const u8 *h)
{
    if (!te_ok(h, x->fsize)) return GZ_E_FORMAT;
    x->te = 1;
    x->hdr_end = 40;
    gz_arc_set_type(x->a, "TE");
    return read_sections(x, 40, h[4], 40 - (i64)rd16(h + 6));
}

/* ---------------- resource directory ---------------- */

static int rs_read(pe_ctx *x, u64 rel, void *buf, u32 n)
{
    u64 lim = x->rs_lim - x->rs_base;
    if (rel > lim || n > lim - rel) return GZ_E_FORMAT;
    u64 off = x->rs_base + rel;
    if (n > RS_BLK / 2) return gz_src_read_exact(x->s, off, buf, n);
    u8 *d = (u8 *)buf;
    while (n) {
        u64 blk = off & ~(u64)(RS_BLK - 1);
        rs_slot *sl = 0;
        for (u32 i = 0; i < RS_SLOTS; i++)
            if (x->slot[i].p && x->slot[i].off == blk) sl = &x->slot[i];
        if (!sl) {
            sl = &x->slot[x->slot_next++ % RS_SLOTS];
            if (!sl->p && !(sl->p = (u8 *)gz_alloc(RS_BLK))) return GZ_E_NOMEM;
            u32 len = x->fsize - blk < RS_BLK ? (u32)(x->fsize - blk) : RS_BLK;
            sl->off = blk;
            sl->len = 0;
            int r = gz_src_read_exact(x->s, blk, sl->p, len);
            if (r) return r;
            sl->len = len;
        }
        u32 in = (u32)(off - blk);
        if (in >= sl->len) return GZ_E_TRUNC;
        u32 take = GZ_MIN(n, sl->len - in);
        __builtin_memcpy(d, sl->p + in, take);
        d += take; off += take; n -= take;
    }
    return GZ_OK;
}

/* 1 if dir offset v was not seen before (and records it) */
static int visit(pe_ctx *x, u32 v)
{
    if ((x->vn + 1) * 2 > x->vcap) {
        u32 nc = x->vcap ? x->vcap * 2 : 1024;
        u32 *nv = (u32 *)gz_alloc((size_t)nc * sizeof(u32));
        if (!nv) return 0;
        for (u32 i = 0; i < nc; i++) nv[i] = 0xFFFFFFFFu;
        for (u32 i = 0; i < x->vcap; i++) {
            u32 k = x->vis[i];
            if (k == 0xFFFFFFFFu) continue;
            u32 hh = (k * 2654435761u) & (nc - 1);
            while (nv[hh] != 0xFFFFFFFFu) hh = (hh + 1) & (nc - 1);
            nv[hh] = k;
        }
        gz_free(x->vis);
        x->vis = nv;
        x->vcap = nc;
    }
    u32 hh = (v * 2654435761u) & (x->vcap - 1);
    while (x->vis[hh] != 0xFFFFFFFFu) {
        if (x->vis[hh] == v) return 0;
        hh = (hh + 1) & (x->vcap - 1);
    }
    x->vis[hh] = v;
    x->vn++;
    return 1;
}

static int dir_count(pe_ctx *x, u32 rel, u32 *n)
{
    u8 d[16];
    int r = rs_read(x, rel, d, 16);
    if (r) return r;
    *n = (u32)rd16(d + 12) + rd16(d + 14);
    return GZ_OK;
}

static int add_leaf(pe_ctx *x, u32 type, u32 name, u32 lang, const u8 *de)
{
    if (x->nres == x->capres) {
        u32 nc = x->capres ? x->capres * 2 : 256;
        pe_res *n = (pe_res *)gz_realloc(x->res, (size_t)nc * sizeof(pe_res));
        if (!n) return GZ_E_NOMEM;
        x->res = n;
        x->capres = nc;
    }
    pe_res *q = &x->res[x->nres++];
    __builtin_memset(q, 0, sizeof *q);
    q->type = type;
    q->name = name;
    q->lang = lang;
    q->size = rd32(de + 4);
    q->grp = x->ngrp - 1;
    q->ok = (u8)rva_map(x, rd32(de), q->size, &q->foff);
    return GZ_OK;
}

/* type -> name -> language -> data entry */
static int rs_walk(pe_ctx *x)
{
    u32 n0, n1, n2;
    u8 en[8], de[16];
    if (dir_count(x, 0, &n0) || !visit(x, 0)) return GZ_OK;
    for (u32 i0 = 0; i0 < n0; i0++) {
        if (rs_read(x, 16 + 8 * (u64)i0, en, 8)) break;
        u32 type = rd32(en), sub = rd32(en + 4);
        if (!(sub & 0x80000000u)) continue;
        sub &= 0x7FFFFFFFu;
        if (!visit(x, sub) || dir_count(x, sub, &n1)) continue;
        for (u32 i1 = 0; i1 < n1; i1++) {
            if (++x->nwalk > PE_MAX_WALK || x->nres >= PE_MAX_RES) return GZ_OK;
            if (gz_cancelled(x->c)) return GZ_E_CANCEL;
            if (rs_read(x, (u64)sub + 16 + 8 * (u64)i1, en, 8)) break;
            u32 name = rd32(en), sub2 = rd32(en + 4);
            if (!(sub2 & 0x80000000u)) continue;
            sub2 &= 0x7FFFFFFFu;
            if (!visit(x, sub2) || dir_count(x, sub2, &n2)) continue;
            x->ngrp++;
            for (u32 i2 = 0; i2 < n2; i2++) {
                if (++x->nwalk > PE_MAX_WALK || x->nres >= PE_MAX_RES) return GZ_OK;
                if (rs_read(x, (u64)sub2 + 16 + 8 * (u64)i2, en, 8)) break;
                u32 lang = rd32(en), d = rd32(en + 4);
                if (d & 0x80000000u) continue;           /* a fourth level: not a resource */
                if (!visit(x, d) || rs_read(x, d, de, 16)) continue;   /* each data entry once */
                int r = add_leaf(x, type, name, lang & 0x80000000u ? 0 : lang, de);
                if (r) return r;
            }
        }
    }
    return GZ_OK;
}

/* name part for a resource id: decimal, or the UTF-16 name string */
static void xn_resid(pe_ctx *x, gz_xname *w, u32 id)
{
    if (!(id & 0x80000000u)) { gz_xn_num(w, id); return; }
    u8 b[2 + 2 * PE_NAME_UNITS];
    u32 rel = id & 0x7FFFFFFFu, n = 0;
    if (!rs_read(x, rel, b, 2)) {
        n = GZ_MIN((u32)rd16(b), (u32)PE_NAME_UNITS);
        while (n && rs_read(x, (u64)rel + 2, b + 2, 2 * n)) n /= 2;   /* clipped by the section */
    }
    gz_xn_part16(w, b + 2, n);
}

static void xn_type(pe_ctx *x, gz_xname *w, u32 type)
{
    if (type < GZ_COUNTOF(k_rtypes) && k_rtypes[type]) gz_xn_str(w, k_rtypes[type]);
    else xn_resid(x, w, type);
}

/* ".rsrc/<TYPE>/<NAME>" (+ "/<LANG>" when the name exists in several languages) */
static void res_name(pe_ctx *x, gz_xname *w, const pe_res *q)
{
    gz_xn_reset(w);
    gz_xn_str(w, ".rsrc/");
    xn_type(x, w, q->type);
    gz_xn_str(w, "/");
    xn_resid(x, w, q->name);
    if (x->grpn[q->grp] > 1) { gz_xn_str(w, "/"); gz_xn_num(w, q->lang); }
}

static int res_read(pe_ctx *x, const pe_res *q, u32 at, void *buf, u32 n)
{
    if (at > q->size || n > q->size - at) return GZ_E_FORMAT;
    return gz_src_read_exact(x->s, q->foff + at, buf, n);
}

/* whole resource in memory (small ones only) */
static u8 *res_load(pe_ctx *x, const pe_res *q)
{
    if (!q->ok || q->size > PE_MAX_SMALL) return 0;
    u8 *b = (u8 *)gz_alloc((size_t)q->size + 8);
    if (b && q->size && gz_src_read_exact(x->s, q->foff, b, q->size)) { gz_free(b); b = 0; }
    return b;
}

/* ---------------- ICON / CURSOR lookup ---------------- */

static u32 id_hash(u32 type, u32 id) { return (id * 2654435761u) ^ (type * 0x9E3779B9u); }

static int build_hash(pe_ctx *x)
{
    u32 n = 0;
    for (u32 i = 0; i < x->nres; i++)
        if ((x->res[i].type == RT_ICON || x->res[i].type == RT_CURSOR) && !(x->res[i].name & 0x80000000u)) n++;
    if (!n) return GZ_OK;
    u32 cap = 64;
    while (cap < n * 2) cap *= 2;
    x->hash = (u32 *)gz_alloc((size_t)cap * sizeof(u32));
    if (!x->hash) return GZ_E_NOMEM;
    for (u32 i = 0; i < cap; i++) x->hash[i] = 0xFFFFFFFFu;
    x->hcap = cap;
    /* insert backwards: chains list leaves in directory order */
    for (u32 i = x->nres; i-- > 0;) {
        pe_res *q = &x->res[i];
        if ((q->type != RT_ICON && q->type != RT_CURSOR) || (q->name & 0x80000000u)) continue;
        u32 hh = id_hash(q->type, q->name) & (cap - 1);
        q->hnext = x->hash[hh];
        x->hash[hh] = i;
    }
    return GZ_OK;
}

/* leaf of type/id, preferably in language lang */
static const pe_res *find_image(const pe_ctx *x, u32 type, u32 id, u32 lang)
{
    if (!x->hash) return 0;
    const pe_res *first = 0;
    u32 i = x->hash[id_hash(type, id) & (x->hcap - 1)];
    for (u32 steps = 0; i != 0xFFFFFFFFu && steps < 64; i = x->res[i].hnext, steps++) {
        const pe_res *q = &x->res[i];
        if (q->type != type || q->name != id || !q->ok || !q->size) continue;
        if (q->lang == lang) return q;
        if (!first) first = q;
    }
    return first;
}

/* ---------------- conversions ---------------- */

/* ICONDIR for one icon image, exactly as 7-Zip builds it (from the BITMAPINFOHEADER) */
static u32 icon_header(const u8 *b, u32 size, u8 *d)
{
    if (size < 40 || rd32(b) != 40) return 0;
    u32 w = rd32(b + 4), h = rd32(b + 8), planes = rd16(b + 12), bc = rd16(b + 14);
    if ((i32)h < 0) h = 0u - h;
    if (w > (1u << 14) || h > (1u << 14) || planes != 1 || rd32(b + 16) != 0) return 0;
    if (bc != 1 && bc != 4 && bc != 8 && bc != 24 && bc != 32) return 0;
    if (h & 1) return 0;
    h /= 2;
    if (w > 256 || h > 256) return 0;
    u32 img = ((w * bc + 7) / 8 + 3) / 4 * 4 * h + ((w + 7) / 8 + 3) / 4 * 4 * h;
    u32 ncol = bc < 16 ? 1u << bc : 0;
    __builtin_memset(d, 0, 22);
    wr16(d + 2, 1);
    wr16(d + 4, 1);
    d[6] = (u8)w;
    d[7] = (u8)h;
    d[8] = (u8)ncol;
    wr32(d + 14, 40 + ncol * 4 + img);
    wr32(d + 18, 22);
    return 22;
}

/* BITMAPFILEHEADER: pixel offset from the header size and palette */
static u32 bmp_header(const u8 *b, u32 got, u32 size, u8 *d)
{
    if (got < 16) return 0;
    u32 bs = rd32(b), pal;
    if (bs == 12) {
        u32 bc = rd16(b + 10);
        if (bc > 32) return 0;
        pal = bc <= 8 ? 3u << bc : 0;
    } else if (bs >= 40 && bs <= 256 && got >= 40) {
        u32 bc = rd16(b + 14), comp = rd32(b + 16), used = rd32(b + 32);
        if (bc > 32 || used > 65536) return 0;
        pal = (used ? used : bc && bc <= 8 ? 1u << bc : 0) * 4;
        if (bs == 40 && comp == 3) pal += 12;            /* BI_BITFIELDS masks */
        if (bs == 40 && comp == 6) pal += 16;            /* BI_ALPHABITFIELDS  */
    } else {
        return 0;
    }
    if ((u64)bs + pal > size || size > 0xFFFFFFFFu - 14) return 0;
    d[0] = 'B';
    d[1] = 'M';
    wr32(d + 2, 14 + size);
    wr32(d + 6, 0);
    wr32(d + 10, 14 + bs + pal);
    return 14;
}

/* GROUP_ICON / GROUP_CURSOR -> .ico / .cur (pieces only; caller adds the entry) */
static int group_pieces(pe_ctx *x, const pe_res *g, int cursor)
{
    pe_priv *p = x->p;
    u8 *b = res_load(x, g);
    if (!b) return GZ_E_FORMAT;
    int r = GZ_E_FORMAT;
    u8 *hdr = 0;
    if (g->size < 6 || rd16(b + 2) != (cursor ? 2 : 1)) goto out;
    u32 cnt = GZ_MIN((u32)rd16(b + 4), (g->size - 6) / 14);
    if (!cnt || cnt > PE_MAX_GROUPS - x->ngroup_ents) goto out;
    x->ngroup_ents += cnt;
    hdr = (u8 *)gz_alloc(6 + 16 * (size_t)cnt);
    const pe_res **img = (const pe_res **)gz_alloc((size_t)cnt * sizeof(void *));
    if (!hdr || !img) { gz_free(img); r = GZ_E_NOMEM; goto out; }
    u32 k = 0;
    u64 total = 0;
    for (u32 j = 0; j < cnt; j++) {
        const u8 *ge = b + 6 + 14 * j;
        const pe_res *q = find_image(x, cursor ? RT_CURSOR : RT_ICON, rd16(ge + 12), g->lang);
        if (!q || (cursor && q->size <= 4)) continue;
        u8 *fe = hdr + 6 + 16 * k;
        if (cursor) {
            u8 hs[4];
            if (res_read(x, q, 0, hs, 4)) continue;
            fe[0] = ge[0];                               /* width (low byte of the WORD) */
            fe[1] = (u8)(rd16(ge + 2) / 2);              /* height counts XOR + AND masks */
            fe[2] = fe[3] = 0;
            __builtin_memcpy(fe + 4, hs, 4);             /* hot spot */
            wr32(fe + 8, q->size - 4);
        } else {
            __builtin_memcpy(fe, ge, 8);
            wr32(fe + 8, q->size);
        }
        img[k++] = q;
        total += q->size;
    }
    if (!k || total + 6 + 16 * (u64)k > 0xFFFFFFFFu) { gz_free(img); goto out; }   /* offsets are 32-bit */
    u32 off = 6 + 16 * k;
    for (u32 j = 0; j < k; j++) {
        wr32(hdr + 6 + 16 * j + 12, off);
        off += img[j]->size - (cursor ? 4 : 0);
    }
    wr16(hdr, 0);
    wr16(hdr + 2, cursor ? 2 : 1);
    wr16(hdr + 4, (u16)k);
    u32 first = p->npc;
    r = pc_mem(p, hdr, 6 + 16 * k);
    for (u32 j = 0; j < k && !r; j++)
        r = pc_file(p, img[j]->foff + (cursor ? 4 : 0), img[j]->size - (cursor ? 4 : 0));
    if (r) pc_rewind(p, first);
    gz_free(img);
out:
    gz_free(hdr);
    gz_free(b);
    return r;
}

/* ---- VS_VERSIONINFO as text (port of 7-Zip's PeHandler ParseVersion) ---- */

static int wstr_eq(const u8 *p, u32 avail, const char *s)
{
    for (u32 i = 0;; i++) {
        if (2 * i + 2 > avail) return 0;
        if (rd16(p + 2 * i) != (u8)s[i]) return 0;
        if (!s[i]) return 1;
    }
}

/* bytes before the NUL unit in p[0..size), -1 if none */
static i32 wstr_len(const u8 *p, u32 size, int allow_tail)
{
    for (u32 pos = 0;; pos += 2) {
        if (pos + 1 >= size) return allow_tail && pos == size ? (i32)pos : -1;
        if (!rd16(p + pos)) return (i32)pos;
    }
}

typedef struct { u32 total, vlen, text, str; } vblock;

static int vb_parse(vblock *v, const u8 *p, u32 size)
{
    if (size < 6) return 0;
    v->total = rd16(p);
    v->vlen = rd16(p + 2);
    v->text = rd16(p + 4);
    if (v->total < 6 || v->total > size || v->text > 1) return 0;
    i32 t = wstr_len(p + 6, v->total - 6, 0);
    if (t < 0) return 0;
    v->str = (u32)t;
    return 1;
}

static void ver_fixed(tbuf *t, const u8 *f)
{
    static const char *const flags[6] = { "DEBUG", "PRERELEASE", "PATCHED", "PRIVATEBUILD", "INFOINFERRED", "SPECIALBUILD" };
    static const u32 os_val[5] = { 0x10001, 0x10004, 0x20002, 0x30003, 0x40004 };
    static const char *const os_name[5] = { "VOS_DOS_WINDOWS16", "VOS_DOS_WINDOWS32", "VOS_OS216_PM16",
                                            "VOS_OS232_PM32", "VOS_NT_WINDOWS32" };
    static const char *const os_hi[6] = { "VOS_UNKNOWN", "VOS_DOS", "VOS_OS216", "VOS_OS232", "VOS_NT", "VOS_WINCE" };
    static const char *const os_lo[5] = { "VOS__BASE", "VOS__WINDOWS16", "VOS__PM16", "VOS__PM32", "VOS__WINDOWS32" };
    static const char *const ftype[8] = { "VFT_UNKNOWN", "VFT_APP", "VFT_DLL", "VFT_DRV", "VFT_FONT", "VFT_VXD",
                                          "0x6", "VFT_STATIC_LIB" };
    static const char *const drv[13] = { "0", "PRINTER", "KEYBOARD", "LANGUAGE", "DISPLAY", "MOUSE", "NETWORK",
                                         "SYSTEM", "INSTALLABLE", "SOUND", "COMM", "INPUTMETHOD", "VERSIONED_PRINTER" };
    static const char *const font[4] = { "0", "VFT2_FONT_RASTER", "VFT2_FONT_VECTOR", "VFT2_FONT_TRUETYPE" };
    u32 v[11];
    for (u32 i = 0; i < 11; i++) v[i] = rd32(f + 8 + 4 * i);
    for (u32 k = 0; k < 2; k++) {
        tb_str(t, k ? "PRODUCTVERSION " : "FILEVERSION    ");
        u32 ms = v[2 * k], ls = v[2 * k + 1];
        tb_dec(t, ms >> 16); tb_ch(t, ',');
        tb_dec(t, ms & 0xFFFF); tb_ch(t, ',');
        tb_dec(t, ls >> 16); tb_ch(t, ',');
        tb_dec(t, ls & 0xFFFF);
        tb_nl(t);
    }
    tb_str(t, "FILEFLAGSMASK  ");
    tb_hex(t, v[4]);
    tb_nl(t);
    tb_str(t, "FILEFLAGS      ");
    int any = 0;
    for (u32 i = 0; i < 6; i++)
        if (v[5] & (1u << i)) {
            if (any) tb_str(t, " | ");
            tb_str(t, "VS_FF_");
            tb_str(t, flags[i]);
            any = 1;
        }
    if ((v[5] & ~0x3Fu) || !any) {
        if (any) tb_str(t, " | ");
        tb_hex(t, v[5] & ~0x3Fu);
    }
    tb_nl(t);
    tb_str(t, "FILEOS         ");
    u32 os = v[6], i;
    for (i = 0; i < 5 && os != os_val[i]; i++) {}
    if (i < 5) {
        tb_str(t, os_name[i]);
    } else {
        if ((os >> 16) < 6) tb_str(t, os_hi[os >> 16]); else tb_hex(t, os & 0xFFFF0000u);
        if (os & 0xFFFF) {
            tb_str(t, " | ");
            if ((os & 0xFFFF) < 5) tb_str(t, os_lo[os & 0xFFFF]); else tb_hex(t, os & 0xFFFF);
        }
    }
    tb_nl(t);
    tb_str(t, "FILETYPE       ");
    if (v[7] < 8) tb_str(t, ftype[v[7]]); else tb_hex(t, v[7]);
    tb_nl(t);
    tb_str(t, "FILESUBTYPE    ");
    if (v[7] == 3 && v[8] && v[8] < 13) { tb_str(t, "VFT2_DRV_"); tb_str(t, drv[v[8]]); }
    else if (v[7] == 4 && v[8] && v[8] < 4) tb_str(t, font[v[8]]);
    else tb_hex(t, v[8]);
    tb_nl(t);
}

#define PAD4(x) ((x) += (4 - (x)) & 3)

static int ver_text(const u8 *p, u32 size, tbuf *t)
{
    vblock vb;
    if (!vb_parse(&vb, p, size) || vb.vlen != 52 || vb.text || vb.str != 30 || !wstr_eq(p + 6, vb.total - 6, "VS_VERSION_INFO"))
        return 0;
    u32 pos = 6 + 30 + 2;
    PAD4(pos);
    if (pos + vb.vlen > vb.total) return 0;
    if (size > vb.total) size = vb.total;
    const u8 *f = p + pos;
    if (rd32(f) != 0xFEEF04BDu || (rd32(f + 4) != 0x10000 && rd32(f + 4) != 0)) return 0;
    tb_put(t, k_bom, 3);
    ver_fixed(t, f);
    pos += vb.vlen;
    tb_str(t, "{\r\n");
    for (;;) {
        PAD4(pos);
        if (pos >= size) break;
        if (!vb_parse(&vb, p + pos, size - pos) || vb.vlen) return 0;
        u32 end = pos + vb.total;
        pos += 6;
        tb_str(t, "  BLOCK");
        tb_param(t, p + pos, vb.str);
        tb_nl(t);
        tb_str(t, "  {\r\n");
        if (wstr_eq(p + pos, end - pos, "VarFileInfo")) {
            pos += vb.str + 2;
            for (;;) {
                PAD4(pos);
                if (pos >= end) break;
                vblock v2;
                if (!vb_parse(&v2, p + pos, end - pos) || v2.text) return 0;
                u32 end2 = pos + v2.total;
                pos += 6;
                tb_str(t, "    VALUE");
                tb_param(t, p + pos, v2.str);
                if (!wstr_eq(p + pos, end2 - pos, "Translation")) return 0;
                pos += v2.str + 2;
                PAD4(pos);
                if (pos + v2.vlen != end2 || (v2.vlen & 3)) return 0;
                for (u32 n = v2.vlen >> 2; n; n--, pos += 4) {
                    u32 dw = rd32(p + pos);
                    tb_str(t, ", ");
                    tb_hex(t, dw & 0xFFFF);
                    tb_str(t, ", ");
                    tb_dec(t, dw >> 16);
                }
                tb_nl(t);
            }
        } else {
            if (!wstr_eq(p + pos, end - pos, "StringFileInfo")) return 0;
            pos += vb.str + 2;
            for (;;) {
                PAD4(pos);
                if (pos >= end) break;
                vblock v2;
                if (!vb_parse(&v2, p + pos, end - pos) || v2.vlen) return 0;
                u32 end2 = pos + v2.total;
                pos += 6;
                tb_str(t, "    BLOCK");
                tb_param(t, p + pos, v2.str);
                pos += v2.str + 2;
                tb_nl(t);
                tb_str(t, "    {\r\n");
                for (;;) {
                    PAD4(pos);
                    if (pos >= end2) break;
                    vblock v3;
                    if (!vb_parse(&v3, p + pos, end2 - pos)) return 0;
                    u32 end3 = pos + v3.total;
                    pos += 6;
                    if (v3.text) {
                        tb_str(t, "      VALUE");
                        tb_param(t, p + pos, v3.str);
                        pos += v3.str + 2;
                        PAD4(pos);
                        if (v3.vlen > 0 && pos + 2 <= end3) {
                            tb_ch(t, ',');
                            tb_spaces(t, (34 - (int)v3.str) / 2);
                            i32 sl = wstr_len(p + pos, end3 - pos, 1);
                            if (sl < 0) return 0;
                            tb_param(t, p + pos, (u32)sl);
                        }
                    }
                    pos = end3;
                    tb_nl(t);
                }
                tb_str(t, "    }\r\n");
            }
        }
        tb_str(t, "  }\r\n");
    }
    tb_str(t, "}\r\n");
    return !t->err;
}

/* ---- string tables: 16 counted strings per block, merged per language ---- */

static int strings_prepass(pe_ctx *x)
{
    for (u32 i = 0; i < x->nres; i++) {
        pe_res *q = &x->res[i];
        if (q->type != RT_STRING || (q->name & 0x80000000u) || !q->ok || (q->size & 1)) continue;
        if (gz_cancelled(x->c)) return GZ_E_CANCEL;
        u8 *b = res_load(x, q);
        if (!b) continue;
        /* validate first (7-Zip accepts one extra zero unit at the end) */
        u32 pos = 0, okb = 1;
        for (u32 k = 0; k < 16 && okb; k++) {
            if (q->size - pos < 2) { okb = 0; break; }
            u32 len = rd16(b + pos);
            pos += 2;
            if (len * 2 > q->size - pos) okb = 0; else pos += len * 2;
        }
        if (okb && pos != q->size && !(pos + 2 == q->size && !rd16(b + pos))) okb = 0;
        if (okb && pos > PE_MAX_TEXT - x->ntext) okb = 0;
        u32 s;
        for (s = 0; okb && s < x->nstrs && x->strs[s].lang != q->lang; s++) {}
        if (okb && s == x->nstrs) {
            if (x->nstrs >= PE_MAX_LANGS) okb = 0;
            else {
                if (!x->strs && !(x->strs = (pe_strs *)gz_alloc(PE_MAX_LANGS * sizeof(pe_strs)))) {
                    gz_free(b);
                    return GZ_E_NOMEM;
                }
                x->strs[s].lang = q->lang;
                tb_put(&x->strs[s].t, k_bom, 3);
                x->nstrs++;
            }
        }
        if (okb) {
            tbuf *t = &x->strs[s].t;
            u32 base = (q->name - 1) << 4, before = t->n;
            pos = 0;
            for (u32 k = 0; k < 16; k++) {
                u32 len = rd16(b + pos);
                pos += 2;
                if (!len) continue;
                tb_dec(t, base + k);
                tb_ch(t, '\t');
                tb_u16(t, b + pos, len, 1);
                tb_nl(t);
                pos += len * 2;
            }
            if (t->err) { gz_free(b); return t->err == GZ_E_NOMEM ? GZ_E_NOMEM : GZ_OK; }
            x->ntext += t->n - before;
            q->merged = 1;
        }
        gz_free(b);
    }
    return GZ_OK;
}

/* ---------------- entry emission ---------------- */

static int emit_raw(pe_ctx *x, const pe_res *q, gz_xname *w)
{
    u32 first = x->p->npc;
    int r = pc_file(x->p, q->foff, q->size);
    return r ? r : add_entry(x, w, first, K_RES, q->lang, 0);
}

static int emit_text(pe_ctx *x, gz_xname *w, const tbuf *t, u32 lang)
{
    u32 first = x->p->npc;
    int r = pc_mem(x->p, t->p, t->n);
    if (r) { pc_rewind(x->p, first); return r == GZ_E_LIMIT ? GZ_OK : r; }
    return add_entry(x, w, first, K_RES, lang, 0);
}

static int emit_resource(pe_ctx *x, u32 i)
{
    pe_res *q = &x->res[i];
    pe_priv *p = x->p;
    gz_xname w;
    int r;
    if (q->merged) {
        for (u32 s = 0; s < x->nstrs; s++) {
            pe_strs *st = &x->strs[s];
            if (st->lang != q->lang || st->done) continue;
            st->done = 1;
            gz_xn_reset(&w);
            gz_xn_str(&w, ".rsrc/STRING");
            if (x->nstrs > 1) { gz_xn_str(&w, "/"); gz_xn_num(&w, st->lang); }
            gz_xn_str(&w, ".txt");
            r = emit_text(x, &w, &st->t, st->lang);
            tb_free(&st->t);
            return r;
        }
        return GZ_OK;
    }
    res_name(x, &w, q);
    u32 type = q->type, first = p->npc;
    u8 b[64], hd[22];
    u32 got = GZ_MIN(q->size, (u32)sizeof b);
    if (got && res_read(x, q, 0, b, got)) got = 0;
    switch (type) {
    case RT_ICON:
        if (got >= 8 && rd32(b) == 0x474E5089u && rd32(b + 4) == 0x0A1A0A0Du) {
            gz_xn_str(&w, ".png");
        } else if (got >= 40 && icon_header(b, q->size, hd)) {
            r = pc_mem(p, hd, 22);
            if (!r) r = pc_file(p, q->foff, q->size);
            if (!r) { gz_xn_str(&w, ".ico"); return add_entry(x, &w, first, K_RES, q->lang, 0); }
            pc_rewind(p, first);
            if (r != GZ_E_LIMIT) return r;
        }
        break;
    case RT_BITMAP:
        if (bmp_header(b, got, q->size, hd)) {
            r = pc_mem(p, hd, 14);
            if (!r) r = pc_file(p, q->foff, q->size);
            if (!r) { gz_xn_str(&w, ".bmp"); return add_entry(x, &w, first, K_RES, q->lang, 0); }
            pc_rewind(p, first);
            if (r != GZ_E_LIMIT) return r;
        }
        break;
    case RT_GROUP_ICON:
    case RT_GROUP_CURSOR:
        r = group_pieces(x, q, type == RT_GROUP_CURSOR);
        if (!r) {
            gz_xn_str(&w, type == RT_GROUP_CURSOR ? ".cur" : ".ico");
            return add_entry(x, &w, first, K_RES, q->lang, 0);
        }
        if (r == GZ_E_NOMEM) return r;
        break;
    case RT_VERSION: {
        r = emit_raw(x, q, &w);
        if (r) return r;
        u8 *d = res_load(x, q);
        if (!d) return GZ_OK;
        tbuf t = { 0 };
        if (ver_text(d, q->size, &t) && t.n <= PE_MAX_TEXT - x->ntext) {
            x->ntext += t.n;
            gz_xn_str(&w, ".txt");
            r = emit_text(x, &w, &t, q->lang);
        } else if (t.err == GZ_E_NOMEM) {
            r = GZ_E_NOMEM;
        }
        tb_free(&t);
        gz_free(d);
        return r;
    }
    case RT_MANIFEST: gz_xn_ext_if_none(&w, ".manifest"); break;
    case RT_HTML: gz_xn_ext_if_none(&w, ".html"); break;
    case RT_FONT: gz_xn_ext_if_none(&w, ".fnt"); break;
    case RT_ANICURSOR: case RT_ANIICON: gz_xn_ext_if_none(&w, ".ani"); break;
    default:
        if (type == RT_RCDATA || type >= GZ_COUNTOF(k_rtypes) || !k_rtypes[type]) {
            const char *ext = gz_exe_sniff(b, got);
            if (ext) gz_xn_ext_if_none(&w, ext);
        }
        break;
    }
    return emit_raw(x, q, &w);
}

static int emit_resources(pe_ctx *x)
{
    for (u32 i = 0; i < x->nres; i++) {
        if (!x->res[i].ok) continue;
        if (gz_cancelled(x->c)) return GZ_E_CANCEL;
        int r = emit_resource(x, i);
        if (r) return r;
    }
    return GZ_OK;
}

static void section_name(pe_ctx *x, gz_xname *w, u32 i)
{
    const u8 *nm = x->sec[i].name;
    u8 lng[256];
    u32 n = 0;
    while (n < 8 && nm[n]) n++;
    gz_xn_reset(w);
    if (!n) { gz_xn_str(w, "["); gz_xn_num(w, i); gz_xn_str(w, "]"); return; }
    /* "/123": offset into the COFF string table (MinGW long section names) */
    if (nm[0] == '/' && n > 1 && x->str_size) {
        u32 v = 0, k;
        for (k = 1; k < n && nm[k] >= '0' && nm[k] <= '9'; k++) v = v * 10 + (nm[k] - '0');
        if (k == n && v >= 4 && v < x->str_size) {
            u32 m = GZ_MIN((u32)sizeof lng, (u32)(x->str_size - v));
            if (!gz_src_read_exact(x->s, x->str_off + v, lng, m)) {
                u32 l = 0;
                while (l < m && lng[l]) l++;
                if (l && l < m) { gz_xn_part8(w, lng, l); return; }
            }
        }
    }
    gz_xn_part8(w, nm, n);
}

static int emit_section(pe_ctx *x, u32 i, int rename)
{
    gz_xname w;
    section_name(x, &w, i);
    if (rename) { gz_xn_str(&w, "_"); gz_xn_num(&w, i); }
    u32 first = x->p->npc;
    int r = pc_file(x->p, x->sec[i].foff, x->sec[i].flen);
    gz_entry *e = 0;
    if (!r) r = add_entry(x, &w, first, K_SECT, x->sec[i].chars, &e);
    if (!r && e && x->ts) { e->mtime = gz_unix_to_filetime(x->ts); e->mtime_kind = GZ_MT_FILETIME; }
    return r;
}

/* DER length of a PKCS#7 blob (trims WIN_CERTIFICATE padding), or n */
static u32 der_len(const u8 *h, u32 n)
{
    if (n < 4 || h[0] != 0x30) return n;
    u32 l = h[1], hl = 2;
    if (l == 0x82) { l = (u32)h[2] << 8 | h[3]; hl = 4; }
    else if (l == 0x83 && n >= 5) { l = (u32)h[2] << 16 | (u32)h[3] << 8 | h[4]; hl = 5; }
    else if (l == 0x84 && n >= 6) { l = rd32be(h + 2); hl = 6; }
    else if (l & 0x80) return n;
    return l <= n - hl ? l + hl : n;
}

static int emit_certs(pe_ctx *x, u64 *cs, u64 *ce)
{
    u64 off = x->dir_rva[4], size = x->dir_size[4];
    *cs = *ce = 0;
    if (x->te || !off || size < 8 || off > x->fsize || size > x->fsize - off) return GZ_OK;
    *cs = off;
    *ce = off + size;
    u64 pos = off;
    for (u32 k = 0; k < 64 && pos + 8 <= off + size; k++) {
        u8 h[16];
        if (gz_src_read_exact(x->s, pos, h, 16 <= off + size - pos ? 16 : 8)) break;
        u32 len = rd32(h), type = rd16(h + 6);
        if (len < 8 || len > off + size - pos) break;
        if ((type == 2 || type == 1) && len > 8) {
            gz_xname w;
            gz_xn_reset(&w);
            gz_xn_str(&w, "[certificate]");
            if (k) gz_xn_num(&w, k + 1);
            gz_xn_str(&w, type == 2 ? ".p7b" : ".cer");
            u32 dl = len - 8;
            if (type == 2 && len >= 16) dl = der_len(h + 8, dl);
            u32 first = x->p->npc;
            int r = pc_file(x->p, pos + 8, dl);
            if (!r) r = add_entry(x, &w, first, K_CERT, 0, 0);
            if (r) return r;
        }
        pos += ((u64)len + 7) & ~(u64)7;
    }
    return GZ_OK;
}

static int overlay(pe_ctx *x, u64 off, u64 end, const char *name)
{
    if (end <= off) return GZ_OK;
    u32 n0 = x->a->n;
    int r = gz_exe_add_overlay(x->a, x->s, off, end - off, name);
    if (r || x->a->n == n0) return r;
    /* convert the stored range into a piece */
    gz_entry *e = &x->a->e[x->a->n - 1];
    u32 first = x->p->npc;
    r = pc_file(x->p, e->off, e->usize);
    if (r) return r;
    e->off = first;
    e->aux32 = 1;
    e->flags = K_OVL;
    return GZ_OK;
}

static int build(pe_ctx *x)
{
    int r;
    /* resources */
    x->rs_sec = -1;
    if (!x->te && x->dir_rva[2]) {
        int si = rva_sect(x, x->dir_rva[2]);
        if (si >= 0) {
            const pe_sect *t = &x->sec[si];
            x->rs_sec = si;
            x->rs_base = t->foff + (x->dir_rva[2] - t->va);
            x->rs_lim = t->foff + t->flen;
            r = rs_walk(x);
            if (r) return r;
        }
    }
    u32 nok = 0;
    if (x->nres) {
        x->grpn = (u32 *)gz_alloc((size_t)x->ngrp * sizeof(u32) + 4);
        if (!x->grpn) return GZ_E_NOMEM;
        for (u32 i = 0; i < x->nres; i++)
            if (x->res[i].ok) { x->grpn[x->res[i].grp]++; nok++; }
        if ((r = build_hash(x)) || (r = strings_prepass(x))) return r;
    }
    /* sections, the resource tree in place of the resource section */
    for (u32 i = 0; i < x->nsec; i++) {
        if (gz_cancelled(x->c)) return GZ_E_CANCEL;
        int is_rs = nok && (int)i == x->rs_sec;
        int named_rsrc = !__builtin_memcmp(x->sec[i].name, ".rsrc\0\0\0", 8);
        if (!(is_rs && named_rsrc)) {
            r = emit_section(x, i, nok && named_rsrc);
            if (r) return r;
        }
        if (is_rs && (r = emit_resources(x))) return r;
    }
    /* image end: headers (a SizeOfHeaders past the first section data does not count),
     * sections, symbol table */
    u64 end = x->hdr_size, first_data = x->fsize;
    for (u32 i = 0; i < x->nsec; i++)
        if (x->sec[i].flen && x->sec[i].foff < first_data) first_data = x->sec[i].foff;
    if (end > first_data) end = first_data;
    if (end < x->tab_end) end = x->tab_end;
    for (u32 i = 0; i < x->nsec; i++)
        if (x->sec[i].flen && x->sec[i].foff + x->sec[i].flen > end) end = x->sec[i].foff + x->sec[i].flen;
    if (x->sym_end > x->sym_off) {
        gz_xname w;
        gz_xn_reset(&w);
        gz_xn_str(&w, "COFF_SYMBOLS");
        u32 first = x->p->npc;
        gz_entry *e = 0;
        r = pc_file(x->p, x->sym_off, x->sym_end - x->sym_off);
        if (!r) r = add_entry(x, &w, first, K_SYM, 0, &e);
        if (r) return r;
        if (e && x->ts) { e->mtime = gz_unix_to_filetime(x->ts); e->mtime_kind = GZ_MT_FILETIME; }
        if (x->sym_end > end) end = x->sym_end;
    }
    u64 cs, ce;
    if ((r = emit_certs(x, &cs, &ce))) return r;
    if (ce && cs >= end) {
        /* payload between the image and the signature, and anything after it */
        u32 n0 = x->a->n;
        r = overlay(x, end, cs, "[overlay]");
        if (!r) r = overlay(x, ce, x->fsize, x->a->n > n0 ? "[overlay2]" : "[overlay]");
    } else {
        r = overlay(x, ce > end ? ce : end, x->fsize, "[overlay]");
    }
    return r;
}

/* ---------------- format interface ---------------- */

static void pe_close(gz_archive *a)
{
    pe_priv *p = (pe_priv *)a->priv;
    if (!p) return;
    gz_free(p->pc);
    gz_free(p->blob);
    gz_free(p);
    a->priv = 0;
}

static int pe_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    if (s->size < 64) return GZ_E_FORMAT;
    pe_ctx *x = (pe_ctx *)gz_alloc(sizeof(pe_ctx));
    pe_priv *p = (pe_priv *)gz_alloc(sizeof(pe_priv));
    if (!x || !p) { gz_free(x); gz_free(p); return GZ_E_NOMEM; }
    a->priv = p;
    x->a = a;
    x->s = s;
    x->c = c;
    x->p = p;
    x->fsize = s->size;
    x->budget = 4 * s->size + (64u << 20);
    u8 h[64];
    int r = gz_src_read_exact(s, 0, h, 64);
    if (!r) r = h[0] == 'V' && h[1] == 'Z' ? te_headers(x, h) : h[0] == 'M' && h[1] == 'Z' ? pe_headers(x, h) : GZ_E_FORMAT;
    if (!r) r = build(x);
    for (u32 i = 0; i < RS_SLOTS; i++) gz_free(x->slot[i].p);
    for (u32 i = 0; i < x->nstrs; i++) tb_free(&x->strs[i].t);
    gz_free(x->strs);
    gz_free(x->sec);
    gz_free(x->sorted);
    gz_free(x->vis);
    gz_free(x->res);
    gz_free(x->grpn);
    gz_free(x->hash);
    gz_free(x);
    return r;
}

static int pe_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    const gz_entry *e = &a->e[idx];
    const pe_priv *p = (const pe_priv *)a->priv;
    int r = out->open(out, idx);
    if (r) return r;
    int st = GZ_OK;
    for (u32 i = 0; i < e->aux32 && !st; i++) {
        const pe_piece *q = &p->pc[e->off + i];
        if (q->mem) st = out->write(out, p->blob + q->off, (size_t)q->len);
        else st = gz_copy_range(s, q->off, q->len, out, c, 0);
    }
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static gz_src *piece_src(const pe_priv *p, gz_src *s, const pe_piece *q)
{
    if (!q->mem) return gz_src_sub(s, q->off, q->len);
    u8 *m = (u8 *)gz_alloc((size_t)q->len + 1);
    if (!m) return 0;
    __builtin_memcpy(m, p->blob + q->off, (size_t)q->len);
    gz_src *v = gz_src_mem(m, q->len, 1);
    if (!v) gz_free(m);
    return v;
}

static gz_src *pe_view(gz_archive *a, gz_src *s, u32 idx)
{
    const gz_entry *e = &a->e[idx];
    const pe_priv *p = (const pe_priv *)a->priv;
    if (e->aux32 == 0) return gz_src_mem("", 0, 0);
    if (e->aux32 == 1) return piece_src(p, s, &p->pc[e->off]);
    if (e->aux32 > 65536 + 1) return 0;
    gz_src **parts = (gz_src **)gz_alloc((size_t)e->aux32 * sizeof(gz_src *));
    if (!parts) return 0;
    u32 n = 0;
    for (; n < e->aux32; n++)
        if (!(parts[n] = piece_src(p, s, &p->pc[e->off + n]))) break;
    gz_src *v = n == e->aux32 ? gz_src_concat(parts, n) : 0;
    if (!v) for (u32 i = 0; i < n; i++) gz_src_free(parts[i]);
    gz_free(parts);
    return v;
}

static void pe_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    gz_xname w;
    gz_xn_reset(&w);
    if (e->flags == K_SECT) {
        u32 ch = (u32)e->aux;
        gz_xn_str(&w, ch & 0x20 ? "Code " : ch & 0x40 ? "Data " : ch & 0x80 ? "BSS " : "");
        gz_xn_str(&w, ch & 0x40000000u ? "r" : "-");
        gz_xn_str(&w, ch & 0x80000000u ? "w" : "-");
        gz_xn_str(&w, ch & 0x20000000u ? "x" : "-");
    } else if (e->flags == K_RES) {
        gz_xn_str(&w, "Lang ");
        gz_xn_num(&w, e->aux);
    }
    u32 n = GZ_MIN(w.n, cap ? cap - 1 : 0);
    __builtin_memcpy(buf, w.b, n);
    if (cap) buf[n] = 0;
}

static int pe_probe(gz_src *s, const u8 *h, u32 n)
{
    if (n < 64) return 0;
    if (h[0] == 'V' && h[1] == 'Z') return te_ok(h, s->size) ? 50 : 0;
    if (h[0] != 'M' || h[1] != 'Z') return 0;
    u32 lf = rd32(h + 0x3C);
    u8 b[26];
    if (lf > s->size - 26 || lf > (16u << 20)) return 0;
    if ((u64)lf + 26 <= n) __builtin_memcpy(b, h + lf, 26);
    else if (gz_src_read_exact(s, lf, b, 26)) return 0;
    if (rd32(b) != 0x00004550u) return 0;
    u32 magic = rd16(b + 24);
    return magic == 0x10B || magic == 0x20B ? 90 : 60;
}

GZ_FORMAT(gz_fmt_pe)
const gz_format gz_fmt_pe = {
    "PE", "exe dll sys ocx cpl scr efi mui drv ax acm tsp te", GZ_FMT_WEAK,
    pe_probe, pe_open, pe_close, pe_extract, 0, 0, pe_method, pe_view, 0
};
