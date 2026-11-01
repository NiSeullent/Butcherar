/*
 * 고깃ZIP - NSIS installer reader (Nullsoft Scriptable Install System 2.x / 3.x,
 * ANSI and Unicode, 32- and 64-bit, Jim Park's Unicode fork)
 *
 * Layout: [PE stub][firstheader at a 512-byte boundary: flags, EF BE AD DE
 * "NullsoftInst", header size, archive size][data][CRC-32 of the file from
 * offset 512]. The data is either
 *   solid:     ONE compressed stream [u32 header size][header][u32 size][file]...
 *   non-solid: [u32 size | 0x80000000][compressed header], then one block per
 *              file [u32 size (| 0x80000000 when compressed)][data]
 * compressed with zlib (raw Deflate; NSIS 2 writes stored blocks without NLEN),
 * NSIS's bzip2 variant or LZMA (5 property bytes; 7-Zip's modified NSIS puts an
 * x86 BCJ flag byte in front). Headers stored uncompressed mean "SetCompress off".
 *
 * The header is a compiled script: a block table (pages, sections, entries,
 * strings, language tables, ...), 28-byte commands and a string table whose
 * strings embed variables, shell folders and language strings (NSIS 2 codes
 * 252..255, NSIS 3 codes 1..4, Park's fork U+E000..E003). Files come from
 * EW_EXTRACTFILE (name relative to the last SetOutPath = EW_CREATEDIR) and
 * EW_WRITEUNINSTALLER (exe stub patched with the uninstaller icon + uninstaller
 * data). Names, order and version detection follow 7-Zip (NsisIn.cpp):
 * "$INSTDIR\" is dropped, other roots stay ("$PLUGINSDIR/System.dll"), entries
 * are sorted by data position, identical (position, name) pairs are merged.
 *
 * Solid installers: a->solid = 1, one decoding pass per extraction (entries
 * sharing the data of an earlier entry are buffered). Non-solid: random access.
 * NSIS has no per-file checksums; solid entries carry their exact size in the
 * stream, sizes of non-solid compressed entries are unknown until extracted.
 */
#include "arc.h"
#include "lzma.h"
#include "bzip2.h"
#include "bcj.h"

#define FH_SIZE     28u                  /* firstheader                               */
#define SCAN_MAX    (4u << 20)           /* signature search window in PE files       */
#define STUB_MAX    (1u << 20)           /* largest exe stub kept for the uninstaller */
#define HDR_MAX     (128u << 20)         /* largest decompressed header               */
#define PATCH_MAX   (16u << 20)          /* uninstaller patch data                    */
#define DUP_MAX     (64u << 20)          /* solid: buffer shared data up to this size */
#define STR_MAX     32768u               /* longest decoded string (units)            */
#define POOL_MAX    (1u << 26)           /* all names + prefixes (units)              */
#define CMD_SIZE    28u
#define MAX_CMDS    (1u << 25)
#define COMP_FLAG   0x80000000u
#define MAX_PASSES  16                  /* solid: big shared data needs a pass per entry */

static const u8 ns_sig[16] = { 0xEF, 0xBE, 0xAD, 0xDE, 'N', 'u', 'l', 'l', 's', 'o', 'f', 't', 'I', 'n', 's', 't' };

enum { M_COPY = 0, M_DEFLATE, M_BZIP2, M_LZMA };
enum { NT_NSIS2 = 0, NT_NSIS3, NT_PARK1, NT_PARK2, NT_PARK3 };

/* gz_entry.flags */
#define NSF_UNINST 1u          /* patched uninstaller: patch block + uninstaller data block */
#define NSF_FILTER 2u          /* BCJ x86 (method display)                                  */
#define NSF_STORED 4u          /* non-solid block stored uncompressed                       */

/* command ids in the NSIS 3 Unicode layout (7-Zip's main layout) */
enum {
    EW_NOP = 2, EW_SETFILEATTRIBUTES = 10, EW_CREATEDIR = 11, EW_EXTRACTFILE = 20,
    EW_ASSIGNVAR = 25, EW_GETDLGITEM = 35, EW_REGISTERDLL = 44, EW_FSEEK = 58,
    EW_WRITEUNINSTALLER = 62, EW_SECTIONSET = 63, EW_GETOSINFO = 65, EW_RESERVEDOPCODE = 66,
    EW_FPUTWS = 68, EW_LOG = 70, EW_FINDPROC = 71, EW_GETFONTVERSION = 72, EW_GETFONTNAME = 73,
    NUM_CMDS = 74
};

/* parameter count of every command (more non-zero parameters = wrong layout guess) */
static const u8 cmd_params[NUM_CMDS] = {
    0, 0, 1, 1, 0, 2, 6, 1, 0, 2, 2, 3, 3, 3, 4, 2, 4, 3, 2, 2,
    6, 2, 6, 2, 2, 4, 5, 3, 6, 4, 4, 6, 5, 6, 3, 3, 2, 4, 5, 4,
    6, 3, 3, 4, 6, 6, 4, 1, 5, 4, 5, 6, 5, 5, 1, 4, 3, 4, 4, 1,
    2, 3, 4, 5, 4, 6, 2, 1, 4, 4, 2, 2, 2, 2
};

/* variables: $0..$9, $R0..$R9, then these */
#define V_INSTDIR 21
#define V_OUTDIR 22
#define V_EXEDIR 23
#define V_TEMP 25
#define V_PLUGINSDIR 26
#define V_HWNDPARENT_225 27
#define V_SPEC_OUTDIR_225 29
#define V_SPEC_OUTDIR 31
static const char *const var_names[12] = {
    "CMDLINE", "INSTDIR", "OUTDIR", "EXEDIR", "LANGUAGE", "TEMP", "PLUGINSDIR",
    "EXEPATH", "EXEFILE", "HWNDPARENT", "_CLICK", "_OUTDIR"
};

/* CSIDL_* shell folders as NSIS names them */
static const char *const shell_names[] = {
    "DESKTOP", "INTERNET", "SMPROGRAMS", "CONTROLS", "PRINTERS", "DOCUMENTS", "FAVORITES",
    "SMSTARTUP", "RECENT", "SENDTO", "BITBUCKET", "STARTMENU", 0, "MUSIC", "VIDEOS", 0,
    "DESKTOP", "DRIVES", "NETWORK", "NETHOOD", "FONTS", "TEMPLATES", "STARTMENU", "SMPROGRAMS",
    "SMSTARTUP", "DESKTOP", "APPDATA", "PRINTHOOD", "LOCALAPPDATA", "ALTSTARTUP", "ALTSTARTUP",
    "FAVORITES", "INTERNET_CACHE", "COOKIES", "HISTORY", "APPDATA", "WINDIR", "SYSDIR",
    "PROGRAM_FILES", "PICTURES", "PROFILE", "SYSTEMX86", "PROGRAM_FILESX86",
    "PROGRAM_FILES_COMMON", "PROGRAM_FILES_COMMONX8", "TEMPLATES", "DOCUMENTS", "ADMINTOOLS",
    "ADMINTOOLS", "CONNECTIONS", 0, 0, 0, "MUSIC", "PICTURES", "VIDEOS", "RESOURCES",
    "RESOURCES_LOCALIZED", "COMMON_OEM_LINKS", "CDBURN_AREA", 0, "COMPUTERSNEARME"
};

typedef struct {
    u64 base;               /* firstheader offset                                  */
    u64 end;                /* end of the NSIS data (clamped to the file)          */
    u64 pe;                 /* exe stub start (uninstallers), valid if stub_len    */
    u64 blocks;             /* non-solid: offset of the first file block           */
    u32 stub_len;
    u32 hdr_size;
    u32 dict;               /* LZMA dictionary of the header / solid stream        */
    u8 method, solid, lzma_flag, use_filter, nsis_zlib, unicode;
} ns_priv;

/* ---------------- small helpers ---------------- */

typedef int (*ns_sink_fn)(void *user, const u8 *p, size_t n);

static void *lz_new(void) { return gz_lzma_dec_new(); }
static void lz_free(void *p) { gz_lzma_dec_free((gz_lzma_dec *)p); }
static void *bz_new(void) { return gz_bzip2_dec_new(); }
static void bz_free(void *p) { gz_bzip2_dec_free((gz_bzip2_dec *)p); }

static int is_pe(const u8 *p, u32 n)
{
    if (n > 512) n = 512;
    if (n < 0x40 || p[0] != 'M' || p[1] != 'Z') return 0;
    u32 pe = rd32(p + 0x3C);
    if (pe < 0x40 || pe > 0x1000 || (pe & 7) || pe + 24 > n) return 0;
    return rd32(p + pe) == 0x00004550u && rd16(p + pe + 20) >= 96;
}

/* LZMA properties as NSIS writes them (lc 3, lp 0, pb 2, dictionary a multiple of
 * 64 KiB) followed by the first two range coder bytes */
static int lzma_sig(const u8 *p, u32 *dict)
{
    *dict = rd32(p + 1);
    return p[0] == 0x5D && p[1] == 0 && p[2] == 0 && p[5] == 0 && !(p[6] & 0x80);
}

/* p has 8 bytes: LZMA, optionally after a BCJ flag byte (0/1) */
static int lzma_sig_flag(const u8 *p, u32 *dict, u8 *flag)
{
    if (lzma_sig(p, dict)) { *flag = 0; return 1; }
    if (p[0] <= 1 && lzma_sig(p + 1, dict)) { *flag = 1; return 1; }
    return 0;
}

static int bzip2_sig(const u8 *p) { return p[0] == 0x31 && p[1] < 14; }

/* ---------------- locating the firstheader ---------------- */

static int fh_check(const u8 *p)
{
    return !__builtin_memcmp(p + 4, ns_sig, 16) && !(rd32(p) & ~0xFu) && rd32(p + 24) > FH_SIZE;
}

/* Find the firstheader: 512-byte aligned, in the head or (PE files) up to SCAN_MAX.
 * *pe: last PE header seen before it (GZ_SIZE_UNKNOWN = none). */
static int ns_find(gz_src *s, const u8 *head, u32 n, u64 *base, u64 *pe)
{
    *pe = GZ_SIZE_UNKNOWN;
    u32 o = 0;
    for (; o + FH_SIZE <= n; o += 512) {
        if (fh_check(head + o)) { *base = o; return 1; }
        if (is_pe(head + o, n - o)) *pe = o;
    }
    if (n < 2 || head[0] != 'M' || head[1] != 'Z' || !s || s->size <= o) return 0;
    enum { CH = 65536 };
    u8 *buf = (u8 *)gz_alloc(CH + 512);
    if (!buf) return 0;
    u64 lim = s->size < SCAN_MAX ? s->size : SCAN_MAX;
    int found = 0;
    for (u64 off = o; off + FH_SIZE <= lim && !found; off += CH) {
        u32 want = (u32)GZ_MIN((u64)CH + 512, s->size - off), got = 0;
        if (s->read_at(s, off, buf, want, &got) || got < FH_SIZE) break;
        for (u32 k = 0; k < CH && k + FH_SIZE <= got; k += 512) {
            if (fh_check(buf + k)) { *base = off + k; found = 1; break; }
            if (is_pe(buf + k, got - k)) *pe = off + k;
        }
    }
    gz_free(buf);
    return found;
}

static int ns_probe(gz_src *s, const u8 *head, u32 n)
{
    u64 base, pe;
    return ns_find(s, head, n, &base, &pe) ? 85 : 0;
}

/* ---------------- decoding streams ---------------- */

/* Decode one stream at [off, end) of s with method m into sink. lzma_flag: a BCJ x86
 * flag byte precedes the LZMA properties (*filt receives it). nsis_zlib: NSIS 2
 * stored blocks. A sink returning GZ_E_SKIP stops decoding (returned unchanged). */
static int ns_run(gz_src *s, u64 off, u64 end, int m, int lzma_flag, int nsis_zlib,
                  ns_sink_fn sink, void *user, gz_ctx *c, int *filt)
{
    if (off > end) return GZ_E_DATA;
    gz_pipe pp = { { s, off, end, c->cancel }, sink, user };
    gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };
    if (filt) *filt = 0;
    switch (m) {
    case M_COPY: {
        u8 *buf = gz_ctx_buffer(c, 256u << 10);
        if (!buf) return GZ_E_NOMEM;
        while (off < end) {
            if (gz_cancelled(c)) return GZ_E_CANCEL;
            u32 k = (u32)GZ_MIN(end - off, (u64)(256u << 10));
            int r = gz_src_read_exact(s, off, buf, k);
            if (r) return r;
            if ((r = sink(user, buf, k))) return r;
            off += k;
        }
        return GZ_OK;
    }
    case M_DEFLATE: {
        gz_inflater *z = gz_ctx_inflater(c);
        if (!z) return GZ_E_NOMEM;
        return nsis_zlib ? gz_inflate_run_nsis(z, &io) : gz_inflate_run(z, &io, 0);
    }
    case M_BZIP2: {
        gz_bzip2_dec *d = (gz_bzip2_dec *)gz_ctx_slot(c, GZ_SLOT_BZIP2, bz_new, bz_free);
        if (!d) return GZ_E_NOMEM;
        return gz_bzip2_decode_nsis(d, &io, GZ_SIZE_UNKNOWN, 0);
    }
    case M_LZMA: {
        u8 hd[6];
        u32 hn = lzma_flag ? 6 : 5;
        if (end - off < hn) return GZ_E_DATA;
        int r = gz_src_read_exact(s, off, hd, hn);
        if (r) return r;
        u8 flag = lzma_flag ? hd[0] : 0;
        if (flag > 1) return GZ_E_METHOD;
        if (filt) *filt = flag;
        pp.rd.pos = off + hn;
        gz_lzma_dec *d = (gz_lzma_dec *)gz_ctx_slot(c, GZ_SLOT_LZMA, lz_new, lz_free);
        if (!d) return GZ_E_NOMEM;
        gz_lzma_dec_set_flags(d, 0);
        gz_filter_push *fp = 0;
        if (flag) {
            fp = (gz_filter_push *)gz_alloc(sizeof *fp);
            if (!fp) return GZ_E_NOMEM;
            gz_filter_push_init(fp, GZ_BCJ_X86, 0, 0, sink, user);
            pp.sink = gz_filter_push_write;
            pp.user = fp;
        }
        r = gz_lzma_decode(d, hd + (lzma_flag ? 1 : 0), &io, GZ_SIZE_UNKNOWN, 0);
        if (!r && fp) r = gz_filter_push_finish(fp);
        gz_free(fp);
        return r;
    }
    }
    return GZ_E_METHOD;
}

/* method of a compressed block when the header was stored ("Copy" archives) */
static int sniff_method(gz_src *s, u64 off, u64 n, u8 *flag)
{
    u8 b[8] = { 0 };
    u32 dict;
    *flag = 0;
    if (gz_src_read_exact(s, off, b, (u32)GZ_MIN(n, 8))) return M_DEFLATE;
    if (n >= 8 && lzma_sig_flag(b, &dict, flag)) return M_LZMA;
    if (n >= 2 && bzip2_sig(b)) return M_BZIP2;
    return M_DEFLATE;
}

/* One non-solid block at off: [u32 size | COMP_FLAG][data]. *next: offset after it. */
static int ns_block(const ns_priv *p, gz_src *s, u64 off, ns_sink_fn sink, void *user, gz_ctx *c,
                    u64 *next)
{
    u8 w[4];
    int r = gz_src_read_exact(s, off, w, 4);
    if (r) return r;
    u32 v = rd32(w);
    u64 st = off + 4, n = v & ~COMP_FLAG;
    if (n > s->size - st) return GZ_E_TRUNC;
    if (next) *next = st + n;
    if (!(v & COMP_FLAG)) return ns_run(s, st, st + n, M_COPY, 0, 0, sink, user, c, 0);
    int m = p->method;
    u8 fl = p->lzma_flag;
    if (m == M_COPY) m = sniff_method(s, st, n, &fl);
    return ns_run(s, st, st + n, m, fl, p->nsis_zlib, sink, user, c, 0);
}

/* growing buffer sink that stops (GZ_E_SKIP) once want bytes are collected */
typedef struct { u8 *p; u32 n, cap, want; } grab_sink;

static int grab_write(void *u, const u8 *q, size_t n)
{
    grab_sink *g = (grab_sink *)u;
    u32 k = g->want - g->n;
    if (n < k) k = (u32)n;
    if (g->n + k > g->cap) {
        u32 nc = g->cap ? g->cap : 65536;
        while (nc < g->n + k) nc = nc > g->want / 2 ? g->want : nc * 2;
        u8 *np = (u8 *)gz_realloc(g->p, nc);
        if (!np) return GZ_E_NOMEM;
        g->p = np;
        g->cap = nc;
    }
    __builtin_memcpy(g->p + g->n, q, k);
    g->n += k;
    return g->n == g->want ? GZ_E_SKIP : GZ_OK;
}

/* ---------------- header parsing ---------------- */

typedef struct { u16 *p; u32 n, cap; } wbuf;

typedef struct {
    u32 pos, patch, ft_lo, ft_hi, attr;
    i32 prefix;                /* index in the prefix table, -1 = none */
    u32 noff, nlen;            /* name units in the pool               */
    u8 uninst, has_attr;
} ns_item;

typedef struct {
    const u8 *h; u32 hn;       /* decompressed header      */
    const u8 *st; u32 nchars;  /* string table (chars)     */
    int uni, type, n225, n200, log, bad;
    ns_item *it; u32 nit, capit;
    u16 *pool; u32 pn, pcap;   /* names and prefixes       */
    u32 *pfx; u32 npfx, cappfx;/* prefix table: off, len   */
    wbuf cur, spec, tmp;       /* SetOutPath prefix, $_OUTDIR copy, scratch */
    i32 cur_idx;               /* prefix table index of cur (-1 = not stored yet) */
    int err;
} ns_parse;

static void wb_put(wbuf *b, u32 c)
{
    if (b->n == b->cap) {
        if (b->cap >= STR_MAX) return;        /* silently truncated */
        u32 nc = b->cap ? b->cap * 2 : 256;
        u16 *np = (u16 *)gz_realloc(b->p, (size_t)nc * 2);
        if (!np) return;
        b->p = np;
        b->cap = nc;
    }
    b->p[b->n++] = (u16)c;
}

static void wb_ascii(wbuf *b, const char *s) { while (*s) wb_put(b, (u8)*s++); }

static void wb_uint(wbuf *b, u32 v)
{
    char t[12];
    int i = 11;
    t[i] = 0;
    do { t[--i] = (char)('0' + v % 10); v /= 10; } while (v);
    wb_ascii(b, t + i);
}

static void wb_copy(wbuf *b, const u16 *s, u32 n) { for (u32 i = 0; i < n; i++) wb_put(b, s[i]); }

static u32 ch_at(const ns_parse *P, u32 i)
{
    if (i >= P->nchars) return 0;
    return P->uni ? rd16(P->st + 2 * (size_t)i) : P->st[i];
}

static void put_var(const ns_parse *P, u32 idx, wbuf *o)
{
    wb_put(o, '$');
    if (idx < 20) {
        if (idx >= 10) { wb_put(o, 'R'); idx -= 10; }
        wb_uint(o, idx);
        return;
    }
    u32 ni = P->n200 ? 29 : P->n225 ? 30 : 32;
    if (idx < ni) {
        if (P->n225 && idx >= 27) idx += 2;   /* no $EXEPATH / $EXEFILE before 2.26 */
        wb_ascii(o, var_names[idx - 20]);
    } else {
        wb_put(o, '_');
        wb_uint(o, idx - ni);
        wb_put(o, '_');
    }
}

static void put_lang(wbuf *o, u32 id)
{
    wb_ascii(o, "$(LSTR_");
    wb_uint(o, id);
    wb_put(o, ')');
}

static int str_is(const ns_parse *P, u32 off, const char *lit)
{
    for (u32 i = 0;; i++) {
        u32 c = ch_at(P, off + i);
        if (c != (u8)lit[i]) return 0;
        if (!c) return 1;
    }
}

static void put_shell(const ns_parse *P, u32 i1, u32 i2, wbuf *o)
{
    if (i1 & 0x80) {
        /* registry value under HKLM\Software\Microsoft\Windows\CurrentVersion */
        u32 off = i1 & 0x3F;
        if (off >= P->nchars) { wb_ascii(o, "$_ERROR_STR_"); return; }
        int id = str_is(P, off, "ProgramFilesDir") ? 0 : str_is(P, off, "CommonFilesDir") ? 1 : -1;
        wb_ascii(o, id == 0 ? "$PROGRAMFILES" : id == 1 ? "$COMMONFILES" : "$_ERROR_UNSUPPORTED_VALUE_REGISTRY_");
        if (i1 & 0x40) wb_ascii(o, "64");
        if (id < 0) {
            wb_put(o, '(');
            for (u32 i = 0; i < 256; i++) {
                u32 c = ch_at(P, off + i);
                if (!c) break;
                if (c < 0x80 || !P->uni) wb_put(o, c);
            }
            wb_put(o, ')');
        }
        return;
    }
    const char *n = i1 < GZ_COUNTOF(shell_names) ? shell_names[i1] : 0;
    if (!n && i2 < GZ_COUNTOF(shell_names)) n = shell_names[i2];
    wb_put(o, '$');
    if (n) { wb_ascii(o, n); return; }
    wb_ascii(o, "_ERROR_UNSUPPORTED_SHELL_[");
    wb_uint(o, i1);
    wb_put(o, ',');
    wb_uint(o, i2);
    wb_put(o, ']');
}

/* Append the string at char index pos (negative: language string) to o. */
static void ns_string(const ns_parse *P, u32 pos, wbuf *o)
{
    if ((i32)pos < 0) { put_lang(o, ~pos); return; }
    if (pos >= P->nchars) { wb_ascii(o, "$_ERROR_STR_"); return; }
    u32 i = pos, n = P->nchars;
    if (!P->uni) {
        int n3 = P->type == NT_NSIS3;
        while (i < n) {
            u32 c = P->st[i++], code = 0;
            if (!c) break;
            if (n3) { if (c <= 4) code = c; }
            else if (c >= 252) code = c == 252 ? 4 : c == 253 ? 3 : c == 254 ? 2 : 1;
            if (!code) { wb_put(o, c); continue; }
            u32 c0 = ch_at(P, i++);
            if (!c0) break;
            if (code == 4) { wb_put(o, c0); continue; }     /* escaped char */
            u32 c1 = ch_at(P, i++);
            if (!c1) break;
            if (code == 2) put_shell(P, c0, c1, o);
            else {
                u32 v = (c0 & 0x7F) | ((c1 & 0x7F) << 7);
                if (code == 3) put_var(P, v, o); else put_lang(o, v);
            }
        }
        return;
    }
    if (P->type >= NT_PARK1) {
        while (i < n) {
            u32 c = ch_at(P, i++);
            if (!c) break;
            if (c >= 0xE000 && c <= 0xE003) {
                u32 v = ch_at(P, i++);
                if (!v) break;
                if (c != 0xE000) {
                    if (c == 0xE002) put_shell(P, v & 0xFF, v >> 8, o);
                    else if (c == 0xE001) put_var(P, v & 0x7FFF, o);
                    else put_lang(o, v & 0x7FFF);
                    continue;
                }
                c = v;
            }
            wb_put(o, c);
        }
        return;
    }
    while (i < n) {                                      /* NSIS 3 Unicode */
        u32 c = ch_at(P, i++);
        if (c > 4) { wb_put(o, c); continue; }
        if (!c) break;
        u32 v = ch_at(P, i++);
        if (!v) break;
        if (c == 4) { wb_put(o, v); continue; }
        if (c == 2) put_shell(P, v & 0xFF, v >> 8, o);
        else {
            v = (v & 0x7F) | (((v >> 8) & 0x7F) << 7);
            if (c == 3) put_var(P, v, o); else put_lang(o, v);
        }
    }
}

/* variable index if the string at pos starts with a variable code, else -1 */
static i32 var_index(const ns_parse *P, u32 pos)
{
    if (pos >= P->nchars) return -1;
    if (P->uni) {
        if (P->nchars - pos < 6) return -1;
        u32 code = ch_at(P, pos), v = ch_at(P, pos + 1);
        if (!v) return -1;
        if (P->type >= NT_PARK1) return code == 0xE001 ? (i32)(v & 0x7FFF) : -1;
        return code == 3 ? (i32)((v & 0x7F) | (((v >> 8) & 0x7F) << 7)) : -1;
    }
    if (P->nchars - pos < 4) return -1;
    u32 c = P->st[pos], c0 = P->st[pos + 1], c1 = P->st[pos + 2];
    if (c != (P->type == NT_NSIS3 ? 3u : 253u) || !c0 || !c1) return -1;
    return (i32)((c0 & 0x7F) | ((c1 & 0x7F) << 7));
}

/* same, *skip = chars taken by the variable code */
static i32 var_index_skip(const ns_parse *P, u32 pos, u32 *skip)
{
    *skip = 0;
    i32 v = var_index(P, pos);
    if (v >= 0) *skip = P->uni ? 2 : 3;
    return v;
}

/* variable index if the string is exactly a variable followed by end_char */
static i32 var_index_end(const ns_parse *P, u32 pos, u32 end_char, u32 *skip)
{
    *skip = 0;
    i32 v = var_index(P, pos);
    if (v < 0) return v;
    u32 k = P->uni ? 2 : 3;
    if (ch_at(P, pos + k) != end_char) return -1;
    *skip = k + 1;
    return v;
}

static int is_var_str(const ns_parse *P, u32 pos, u32 var)
{
    u32 skip;
    return var <= 0x7FFF && var_index_end(P, pos, 0, &skip) == (i32)var;
}

/* the string starts at the beginning of a string (or after a backslash) */
static int good_string(const ns_parse *P, u32 pos)
{
    if (pos >= P->nchars) return 0;
    if (!pos) return 1;
    u32 c = ch_at(P, pos - 1);
    return c == 0 || c == '\\';
}

static int same_strings(const ns_parse *P, u32 a, u32 b)
{
    if (a == b) return 1;
    if (a >= P->nchars || b >= P->nchars) return 0;
    for (u32 i = 0; a + i < P->nchars && b + i < P->nchars; i++) {
        u32 x = ch_at(P, a + i);
        if (x != ch_at(P, b + i)) return 0;
        if (!x) return 1;
    }
    return 0;
}

/* ---- command layout: NSIS 2 / 3, Park 1..3, with or without EW_LOG ---- */

static u32 get_cmd(const ns_parse *P, u32 a)
{
    if (P->type < NT_PARK1) {
        if (!P->log || a < EW_SECTIONSET) return a;
        return a == EW_SECTIONSET ? (u32)EW_LOG : a - 1;
    }
    if (a < EW_REGISTERDLL) return a;
    if (P->type >= NT_PARK2) {
        if (a == EW_REGISTERDLL) return EW_GETFONTVERSION;
        a--;
    }
    if (P->type >= NT_PARK3) {
        if (a == EW_REGISTERDLL) return EW_GETFONTNAME;
        a--;
    }
    if (a >= EW_FSEEK) {
        if (P->uni) {
            if (a == EW_FSEEK) return EW_FPUTWS;
            if (a == EW_FSEEK + 1) return EW_FPUTWS + 1;
            a -= 2;
        }
        if (a >= EW_SECTIONSET && P->log) return a == EW_SECTIONSET ? (u32)EW_LOG : a - 1;
        if (a == EW_FPUTWS) return EW_FINDPROC;
    }
    return a;
}

/* lowest command id whose parameter count does not fit the guessed layout */
static void find_bad(ns_parse *P, const u8 *p, u32 num)
{
    P->bad = -1;
    for (u32 k = 0; k < num; k++, p += CMD_SIZE) {
        u32 id = get_cmd(P, rd32(p));
        if (id >= NUM_CMDS) continue;
        if (P->bad >= 0 && id >= (u32)P->bad) continue;
        if (id == EW_RESERVEDOPCODE || (P->type != NT_NSIS3 && id == EW_GETOSINFO)) { P->bad = (int)id; continue; }
        u32 i = 6;
        while (i && !rd32(p + i * 4)) i--;
        if ((id == EW_FINDPROC && !i) || cmd_params[id] < i) P->bad = (int)id;
    }
}

/* Version / fork / layout detection (7-Zip's DetectNsisType heuristics). */
static void detect_type(ns_parse *P, const u8 *cmds, u32 num)
{
    int strong_park = 0, strong_nsis = 0;
    P->type = NT_NSIS2;
    if (P->nchars > 2) {
        u32 lim = P->nchars - 2;
        /* NSIS 3 variable codes have bit 7 set in both bytes: "\0" 03 8x 8x */
        for (u32 i = 0; i < lim && !strong_nsis; i++) {
            if (ch_at(P, i) || ch_at(P, i + 1) != 3) continue;
            u32 v = ch_at(P, i + 2);
            if (P->uni ? (v & 0x8080) == 0x8080 : (v & 0x80) != 0) strong_nsis = 1;
        }
        if (strong_nsis) P->type = NT_NSIS3;
        else if (P->uni) { P->type = NT_PARK1; strong_park = 1; }
    }
    const u8 *p;
    u32 k;
    if (P->type == NT_NSIS2 && !P->uni) {
        for (k = 0, p = cmds; k < num; k++, p += CMD_SIZE) {
            u32 id = get_cmd(P, rd32(p));
            if (id == EW_GETDLGITEM) {
                if (is_var_str(P, rd32(p + 8), V_HWNDPARENT_225)) {
                    P->n225 = 1;
                    if (rd32(p + 4) == V_SPEC_OUTDIR_225) { P->n200 = 1; break; }
                }
            } else if (id == EW_ASSIGNVAR) {
                if (rd32(p + 4) == V_SPEC_OUTDIR_225 && !rd32(p + 12) && !rd32(p + 16) &&
                    is_var_str(P, rd32(p + 8), V_OUTDIR))
                    P->n225 = 1;
            }
        }
    }
    int park_found = 0;
    if (!strong_nsis && !P->n225 && !P->n200) {
        /* Park's forks insert commands before EW_WRITEUNINSTALLER: find where its
         * "$INSTDIR\" + name alternative path parameter sits */
        u32 mask = 0, ins_max = P->uni ? 4 : 2;
        for (k = 0, p = cmds; k < num; k++, p += CMD_SIZE) {
            u32 raw = rd32(p);
            if (raw < EW_WRITEUNINSTALLER || raw > EW_WRITEUNINSTALLER + ins_max) continue;
            u32 p0 = rd32(p + 4), p3 = rd32(p + 16), skip;
            if (rd32(p + 20) || rd32(p + 24) || p0 <= 1 || p3 <= 1) continue;
            if (!good_string(P, p0) || !good_string(P, p3)) continue;
            if (var_index_end(P, p3, '\\', &skip) != V_INSTDIR) continue;
            if (same_strings(P, p3 + skip, p0)) mask |= 1u << (raw - EW_WRITEUNINSTALLER);
        }
        if (mask == 1) park_found = 1;
        else if (mask) {
            int nt = P->type;
            if (mask == (P->uni ? 8u : 2u)) nt = NT_PARK2;
            else if (mask == (P->uni ? 16u : 4u)) nt = NT_PARK3;
            if (nt != P->type) { park_found = 1; P->type = nt; }
        }
    }
    find_bad(P, cmds, num);
    if (P->bad < EW_REGISTERDLL) return;
    if (strong_park && !park_found && P->bad < EW_SECTIONSET) {
        P->type = NT_PARK3;
        P->log = 1;                           /* Park 3 comes with EW_LOG */
        find_bad(P, cmds, num);
        if (P->bad > 0 && P->bad < EW_SECTIONSET) {
            P->type = NT_PARK2;
            P->log = 0;
            find_bad(P, cmds, num);
            if (P->bad > 0 && P->bad < EW_SECTIONSET) {
                P->type = NT_PARK1;
                find_bad(P, cmds, num);
            }
        }
    }
    if (P->bad >= EW_SECTIONSET) {
        P->log = !P->log;
        find_bad(P, cmds, num);
        if (P->bad >= EW_SECTIONSET && P->log) {
            P->log = 0;
            find_bad(P, cmds, num);
        }
    }
}

/* ---- items ---- */

static int pool_add(ns_parse *P, const u16 *s, u32 n, u32 *off)
{
    if (n > POOL_MAX - P->pn) return GZ_E_LIMIT;
    if (P->pn + n > P->pcap) {
        u32 nc = P->pcap ? P->pcap : 65536;
        while (nc < P->pn + n) nc *= 2;
        u16 *np = (u16 *)gz_realloc(P->pool, (size_t)nc * 2);
        if (!np) return GZ_E_NOMEM;
        P->pool = np;
        P->pcap = nc;
    }
    if (n) __builtin_memcpy(P->pool + P->pn, s, (size_t)n * 2);
    *off = P->pn;
    P->pn += n;
    return GZ_OK;
}

/* prefix table index of the current output directory (stored on first use) */
static int cur_prefix(ns_parse *P, i32 *idx)
{
    if (P->cur_idx < 0) {
        if (P->npfx == P->cappfx) {
            u32 nc = P->cappfx ? P->cappfx * 2 : 64;
            u32 *np = (u32 *)gz_realloc(P->pfx, (size_t)nc * 8);
            if (!np) return GZ_E_NOMEM;
            P->pfx = np;
            P->cappfx = nc;
        }
        u32 off;
        int r = pool_add(P, P->cur.p, P->cur.n, &off);
        if (r) return r;
        P->pfx[2 * P->npfx] = off;
        P->pfx[2 * P->npfx + 1] = P->cur.n;
        P->cur_idx = (i32)P->npfx++;
    }
    *idx = P->cur_idx;
    return GZ_OK;
}

static ns_item *item_new(ns_parse *P)
{
    if (P->nit == P->capit) {
        if (P->capit >= MAX_CMDS) { P->err = GZ_E_LIMIT; return 0; }
        u32 nc = P->capit ? P->capit * 2 : 64;
        ns_item *np = (ns_item *)gz_realloc(P->it, (size_t)nc * sizeof(ns_item));
        if (!np) { P->err = GZ_E_NOMEM; return 0; }
        P->it = np;
        P->capit = nc;
    }
    ns_item *it = &P->it[P->nit++];
    __builtin_memset(it, 0, sizeof *it);
    it->prefix = -1;
    return it;
}

static int is_abs_var(const ns_parse *P, u32 pos)
{
    i32 v = var_index(P, pos);
    return v == V_INSTDIR || v == V_EXEDIR || v == V_TEMP || v == V_PLUGINSDIR;
}

/* name from string pos; relative names get the current output directory */
static int set_name(ns_parse *P, ns_item *it, u32 pos)
{
    P->tmp.n = 0;
    ns_string(P, pos, &P->tmp);
    const u16 *s = P->tmp.p;
    u32 n = P->tmp.n;
    int abs = is_abs_var(P, pos) ||
              (n >= 2 && s[0] == '\\' && s[1] == '\\') ||
              (n >= 2 && s[1] == ':' && ((s[0] | 0x20) >= 'a' && (s[0] | 0x20) <= 'z'));
    int r = pool_add(P, s, n, &it->noff);
    if (r) return r;
    it->nlen = n;
    return abs ? GZ_OK : cur_prefix(P, &it->prefix);
}

static int read_entries(ns_parse *P, const u8 *cmds, u32 num)
{
    u32 spec_var = P->n225 ? V_SPEC_OUTDIR_225 : V_SPEC_OUTDIR;
    P->cur.n = 0;
    wb_ascii(&P->cur, "$INSTDIR");
    P->cur_idx = -1;
    P->spec.n = 0;
    const u8 *p = cmds;
    for (u32 k = 0; k < num; k++, p += CMD_SIZE) {
        u32 id = get_cmd(P, rd32(p)), pr[6];
        for (int i = 0; i < 6; i++) pr[i] = rd32(p + 4 + 4 * i);
        int r = GZ_OK;
        switch (id) {
        case EW_CREATEDIR: {
            if (!pr[1]) break;                    /* CreateDirectory, not SetOutPath */
            u32 par = pr[0], skip;
            i32 v = var_index_skip(P, par, &skip);
            if (v == (i32)spec_var || v == V_OUTDIR) par += skip;
            P->tmp.n = 0;
            ns_string(P, par, &P->tmp);
            if (v == (i32)spec_var) {
                P->cur.n = 0;
                wb_copy(&P->cur, P->spec.p, P->spec.n);
            } else if (v != V_OUTDIR) {
                P->cur.n = 0;
            }
            wb_copy(&P->cur, P->tmp.p, P->tmp.n);  /* $OUTDIR: relative to the last one */
            P->cur_idx = -1;
            break;
        }
        case EW_ASSIGNVAR:
            if (pr[0] == spec_var) {              /* StrCpy $_OUTDIR $OUTDIR */
                P->spec.n = 0;
                if (is_var_str(P, pr[1], V_OUTDIR) && !pr[2] && !pr[3]) wb_copy(&P->spec, P->cur.p, P->cur.n);
            }
            break;
        case EW_EXTRACTFILE: {
            ns_item *it = item_new(P);
            if (!it) return P->err;
            if ((r = set_name(P, it, pr[1]))) return r;
            it->pos = pr[2];
            it->ft_lo = pr[3];
            it->ft_hi = pr[4];
            if (is_var_str(P, pr[1], 10)) {
                /* "File $R0": InstallLib macro (7-Zip installers); the real name is the
                 * "StrCpy $R4 name" 28 (26 with the old macro) commands earlier */
                u32 back = 28;
                if (k > 1 && rd32(p - CMD_SIZE) == EW_NOP) back -= 2;
                if (k > back) {
                    const u8 *q = p - back * CMD_SIZE;
                    if (rd32(q) == EW_ASSIGNVAR && rd32(q + 4) == 14 && !rd32(q + 12) && !rd32(q + 16)) {
                        it->prefix = -1;
                        if ((r = set_name(P, it, rd32(q + 8)))) return r;
                    }
                }
            }
            break;
        }
        case EW_SETFILEATTRIBUTES:
            if (k && rd32(p - CMD_SIZE) == EW_EXTRACTFILE && pr[0] == rd32(p - CMD_SIZE + 8) && P->nit) {
                P->it[P->nit - 1].attr = pr[1];
                P->it[P->nit - 1].has_attr = 1;
            }
            break;
        case EW_WRITEUNINSTALLER: {
            if (!pr[0] || !good_string(P, pr[0])) break;
            if (P->bad >= 0 && P->bad <= EW_WRITEUNINSTALLER) break;  /* unreliable layout */
            ns_item *it = item_new(P);
            if (!it) return P->err;
            if ((r = set_name(P, it, pr[0]))) return r;
            /* relative name: NSIS 2.29+ uses the "$INSTDIR\" + name alternative */
            if (pr[3] && it->prefix >= 0 && (r = set_name(P, it, pr[3]))) return r;
            it->prefix = -1;
            it->pos = pr[1];
            it->patch = pr[2];
            it->uninst = 1;
            it->ft_hi = 0xFFFFFFFFu;
            break;
        }
        }
    }
    return GZ_OK;
}

static int cmp_units(const u16 *a, u32 an, const u16 *b, u32 bn)
{
    u32 n = an < bn ? an : bn;
    for (u32 i = 0; i < n; i++)
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return an == bn ? 0 : an < bn ? -1 : 1;
}

static int cmp_prefix(const ns_parse *P, i32 x, i32 y)
{
    return cmp_units(P->pool + P->pfx[2 * x], P->pfx[2 * x + 1], P->pool + P->pfx[2 * y], P->pfx[2 * y + 1]);
}

/* 7-Zip's order: data position, then prefix (none first), then name */
static int cmp_item(const ns_parse *P, const ns_item *a, const ns_item *b)
{
    if (a->pos != b->pos) return a->pos < b->pos ? -1 : 1;
    if (a->prefix != b->prefix) {
        if (a->prefix < 0) return -1;
        if (b->prefix < 0) return 1;
        int c = cmp_prefix(P, a->prefix, b->prefix);
        if (c) return c;
    }
    return cmp_units(P->pool + a->noff, a->nlen, P->pool + b->noff, b->nlen);
}

/* stable bottom-up merge sort of item indices */
static int sort_items(const ns_parse *P, u32 *ix, u32 n)
{
    u32 *tmp = (u32 *)gz_alloc((size_t)n * sizeof(u32) + 4);
    if (!tmp) return GZ_E_NOMEM;
    u32 *src = ix, *dst = tmp;
    for (u32 w = 1; w < n; w *= 2) {
        for (u32 lo = 0; lo < n; lo += 2 * w) {
            u32 mid = GZ_MIN(lo + w, n), hi = GZ_MIN(lo + 2 * w, n), i = lo, j = mid, o = lo;
            while (i < mid && j < hi)
                dst[o++] = cmp_item(P, &P->it[src[j]], &P->it[src[i]]) < 0 ? src[j++] : src[i++];
            while (i < mid) dst[o++] = src[i++];
            while (j < hi) dst[o++] = src[j++];
        }
        u32 *t = src; src = dst; dst = t;
    }
    if (src != ix) __builtin_memcpy(ix, src, (size_t)n * sizeof(u32));
    gz_free(tmp);
    return GZ_OK;
}

static int same_item(const ns_parse *P, const ns_item *a, const ns_item *b)
{
    if (a->pos != b->pos) return 0;
    if (cmp_units(P->pool + a->noff, a->nlen, P->pool + b->noff, b->nlen)) return 0;
    if (a->prefix == b->prefix) return 1;
    if (a->prefix < 0 || b->prefix < 0) return 0;
    return !cmp_prefix(P, a->prefix, b->prefix);
}

/* Parse the decompressed header: string table, version, commands -> P->it. */
static int parse_header(ns_parse *P)
{
    const u8 *h = P->h;
    u32 hn = P->hn;
    int is64 = hn >= 4 + 12 * 8;
    for (int k = 0; k < 8 && is64; k++)
        if (rd32(h + 4 + 12 * k + 4)) is64 = 0;           /* high half of 64-bit offsets */
    u32 bho = is64 ? 12 : 8;
    if (hn < 4 + bho * 8) return GZ_E_FORMAT;
    u32 ent_off = rd32(h + 4 + bho * 2), ent_num = rd32(h + 4 + bho * 3 - 4);
    u32 str_off = rd32(h + 4 + bho * 3), lang_off = rd32(h + 4 + bho * 4);
    if (str_off > hn || lang_off > hn || ent_off > hn || lang_off < str_off) return GZ_E_FORMAT;
    u32 sts = lang_off - str_off;
    if (sts < 2) return GZ_E_FORMAT;
    P->st = h + str_off;
    if (P->st[sts - 1]) return GZ_E_FORMAT;
    P->uni = rd16(P->st) == 0;
    P->nchars = sts;
    if (P->uni) {
        if ((sts & 1) || P->st[sts - 2]) return GZ_E_FORMAT;
        P->nchars = sts / 2;
    }
    if (ent_num > MAX_CMDS || (u64)ent_num * CMD_SIZE > hn - ent_off) return GZ_E_FORMAT;
    detect_type(P, h + ent_off, ent_num);
    return read_entries(P, h + ent_off, ent_num);
}

static void parse_free(ns_parse *P)
{
    gz_free(P->it);
    gz_free(P->pool);
    gz_free(P->pfx);
    gz_free(P->cur.p);
    gz_free(P->spec.p);
    gz_free(P->tmp.p);
}

/* ---------------- open ---------------- */

static void ns_close(gz_archive *a)
{
    gz_free(a->priv);
    a->priv = 0;
}

/* "$INSTDIR\" (any case) at the start of s */
static int instdir_prefix(const u16 *s, u32 n)
{
    static const char k[] = "$INSTDIR\\";
    if (n < 9) return 0;
    for (u32 i = 0; i < 9; i++) {
        u32 c = s[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        if (c != (u8)k[i]) return 0;
    }
    return 1;
}

/* Turn the sorted items into entries. ix: sorted item indices, n of them. */
static int add_entries(gz_archive *a, ns_parse *P, const u32 *ix, u32 n, gz_src *s, gz_ctx *c)
{
    ns_priv *p = (ns_priv *)a->priv;
    u8 *nb = (u8 *)gz_alloc(2 * (STR_MAX * 2 + 16));
    if (!nb) return GZ_E_NOMEM;
    int r = GZ_OK;
    u32 nx = 0;                    /* solid size estimate: first item at or after pos + 4 */
    for (u32 k = 0; k < n && !r; k++) {
        const ns_item *it = &P->it[ix[k]];
        if (!(k & 4095) && gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        /* full name: prefix '\' name */
        wbuf *t = &P->tmp;
        t->n = 0;
        if (it->prefix >= 0) {
            u32 po = P->pfx[2 * it->prefix], pl = P->pfx[2 * it->prefix + 1];
            if (pl + it->nlen + 6 > STR_MAX) pl = it->nlen + 6 < STR_MAX ? STR_MAX - it->nlen - 6 : 0;  /* keep the name */
            wb_copy(t, P->pool + po, pl);
            if (pl && P->pool[po + pl - 1] != '\\') wb_put(t, '\\');
        }
        if (it->nlen) wb_copy(t, P->pool + it->noff, it->nlen); else wb_ascii(t, "file");
        u32 st = 0;
        if (instdir_prefix(t->p, t->n)) {
            st = 9;
            if (st < t->n && t->p[st] == '\\') st++;
        }
        int patched = it->uninst && it->patch;
        if (patched && !p->stub_len) wb_ascii(t, ".nsis");
        u32 len = 0;
        for (u32 i = st; i < t->n; i++) {
            if (P->uni) { wr16(nb + len, t->p[i]); len += 2; }
            else nb[len++] = (u8)t->p[i];
        }
        gz_entry *e;
        if ((r = gz_arc_add_named(a, nb, len, P->uni ? GZ_NE_UTF16LE : GZ_NE_LEGACY, &e))) break;
        if (it->ft_hi > 0x01000000u && it->ft_hi < 0xFF000000u) {
            e->mtime = (u64)it->ft_hi << 32 | it->ft_lo;
            e->mtime_kind = GZ_MT_FILETIME;
        }
        if (it->has_attr) e->attr = it->attr & 0xFFFF & ~0x10u;
        e->aux = it->patch;
        e->flags = patched ? NSF_UNINST : 0;
        e->method = p->method;
        e->aux32 = p->dict;
        e->usize = e->csize = GZ_SIZE_UNKNOWN;
        if (p->use_filter) e->flags |= NSF_FILTER;
        if (p->solid) {
            e->off = 4 + (u64)p->hdr_size + it->pos;     /* position in the solid stream */
            /* exact unless something else lies in between (7-Zip's estimate) */
            u64 cur = (u64)it->pos + 4;
            if (nx <= k) nx = k + 1;
            while (nx < n && P->it[ix[nx]].pos < cur) nx++;
            if (!patched && nx < n) e->usize = P->it[ix[nx]].pos - cur;
            continue;
        }
        e->off = p->blocks + it->pos;
        u8 w[10];
        if (e->off >= s->size || gz_src_read_exact(s, e->off, w, (u32)GZ_MIN((u64)10, s->size - e->off)) ||
            s->size - e->off < 4)
            continue;                                      /* extraction reports it */
        u32 v = rd32(w);
        e->csize = v & ~COMP_FLAG;
        if (!(v & COMP_FLAG)) {
            e->method = M_COPY;
            e->flags |= NSF_STORED;
            e->flags &= ~NSF_FILTER;
            if (!patched) e->usize = e->csize;
        } else {
            u8 fl = p->lzma_flag;
            u32 dict;
            if (p->method == M_COPY) e->method = (u16)sniff_method(s, e->off + 4, e->csize, &fl);
            e->flags &= ~NSF_FILTER;
            if (e->method == M_LZMA && s->size - e->off >= 10 && e->csize >= (fl ? 6u : 5u)) {
                if (fl && w[4] == 1) e->flags |= NSF_FILTER;
                dict = rd32(w + 5 + fl);
                e->aux32 = dict;
            }
        }
        if (patched && e->csize <= s->size - e->off - 4) {
            /* the uninstaller data block follows the patch block */
            u64 o2 = e->off + 4 + e->csize;
            u8 w2[4];
            if (o2 + 4 <= s->size && !gz_src_read_exact(s, o2, w2, 4)) {
                u32 v2 = rd32(w2);
                /* both blocks stored: patched stub + uninstaller data */
                if (!(v & COMP_FLAG) && !(v2 & COMP_FLAG)) e->usize = (u64)p->stub_len + v2;
                e->csize += 4 + (v2 & ~COMP_FLAG);
            }
        }
    }
    gz_free(nb);
    return r;
}

/* Decode the header: method / solid detection as 7-Zip, with fallbacks (a
 * non-solid guess that fails is retried as solid Deflate, zlib in both stored
 * block flavours). On success hb holds [u32 size]? + header. */
typedef struct { u8 method, solid, lzma_flag, nsis_zlib; } ns_guess;

static int decode_header(ns_priv *p, gz_src *s, const ns_guess *g, u32 csize, grab_sink *hb, gz_ctx *c,
                         int *filt)
{
    hb->n = 0;
    u64 data = p->base + FH_SIZE;
    if (g->solid) {
        hb->want = p->hdr_size + 4;
        int r = ns_run(s, data, p->end, g->method, g->lzma_flag, g->nsis_zlib, grab_write, hb, c, filt);
        if (r && r != GZ_E_SKIP) return r;
        if (hb->n != hb->want || rd32(hb->p) != p->hdr_size) return GZ_E_FORMAT;
        return GZ_OK;
    }
    hb->want = p->hdr_size;
    if (data + 4 + (u64)csize > p->end) return GZ_E_TRUNC;
    int r = ns_run(s, data + 4, data + 4 + csize, g->method, g->lzma_flag, g->nsis_zlib, grab_write, hb, c, filt);
    if (r && r != GZ_E_SKIP) return r;
    return hb->n == hb->want ? GZ_OK : GZ_E_FORMAT;
}

static int ns_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    int r;
    u64 base, pe;
    {
        /* the probe looked at 64 KiB; search again (head + window) */
        u8 *big = (u8 *)gz_alloc(65536);
        if (!big) return GZ_E_NOMEM;
        u32 bn = (u32)GZ_MIN(s->size, (u64)65536);
        r = gz_src_read_exact(s, 0, big, bn);
        int f = !r && ns_find(s, big, bn, &base, &pe);
        gz_free(big);
        if (r) return r;
        if (!f) return GZ_E_FORMAT;
    }
    u8 fh[FH_SIZE + 12];
    __builtin_memset(fh, 0, sizeof fh);
    u32 fn = (u32)GZ_MIN(s->size - base, (u64)sizeof fh);
    if (fn < FH_SIZE + 4 || gz_src_read_exact(s, base, fh, fn)) return GZ_E_FORMAT;
    ns_priv *p = (ns_priv *)gz_alloc(sizeof(ns_priv));
    if (!p) return GZ_E_NOMEM;
    a->priv = p;
    p->base = base;
    p->hdr_size = rd32(fh + 20);
    u32 arc_size = rd32(fh + 24);
    p->end = GZ_MIN(s->size, base + arc_size);
    if (pe != GZ_SIZE_UNKNOWN && base - pe < STUB_MAX) {
        p->pe = pe;
        p->stub_len = (u32)(base - pe);
    }
    if (!p->hdr_size) return GZ_E_FORMAT;
    if (p->hdr_size > HDR_MAX) return GZ_E_LIMIT;

    /* method guesses: 7-Zip's detection first */
    const u8 *sig = fh + FH_SIZE;
    u32 csz = rd32(sig), dict = 0;
    u8 flag = 0;
    ns_guess gs[4];
    u32 ng = 0;
    u32 hcsize = csz & ~COMP_FLAG;
    if (csz == p->hdr_size) {
        gs[ng++] = (ns_guess){ M_COPY, 0, 0, 0 };
    } else if (lzma_sig_flag(sig, &dict, &flag)) {
        gs[ng++] = (ns_guess){ M_LZMA, 1, flag, 0 };
    } else if (sig[3] == 0x80) {
        u8 f2;
        u32 d2;
        if (lzma_sig_flag(sig + 4, &d2, &f2)) { gs[ng++] = (ns_guess){ M_LZMA, 0, f2, 0 }; dict = d2; }
        else if (bzip2_sig(sig + 4)) gs[ng++] = (ns_guess){ M_BZIP2, 0, 0, 0 };
        else { gs[ng++] = (ns_guess){ M_DEFLATE, 0, 0, 0 }; gs[ng++] = (ns_guess){ M_DEFLATE, 0, 0, 1 }; }
        gs[ng++] = (ns_guess){ M_DEFLATE, 1, 0, 0 };     /* 4th byte of a solid stream was 0x80 */
        gs[ng++] = (ns_guess){ M_DEFLATE, 1, 0, 1 };
    } else if (bzip2_sig(sig)) {
        gs[ng++] = (ns_guess){ M_BZIP2, 1, 0, 0 };
    } else {
        gs[ng++] = (ns_guess){ M_DEFLATE, 1, 0, 0 };
        gs[ng++] = (ns_guess){ M_DEFLATE, 1, 0, 1 };
    }

    grab_sink hb = { 0 };
    ns_parse P;
    __builtin_memset(&P, 0, sizeof P);
    int ok = 0, err = GZ_E_FORMAT;
    const ns_guess *g = gs;
    for (u32 i = 0; i < ng && !ok; i++) {
        g = &gs[i];
        int filt = 0;
        if (g->method == M_COPY) {
            if (base + FH_SIZE + 4 + (u64)p->hdr_size > p->end) { err = GZ_E_TRUNC; continue; }
            u8 *np = (u8 *)gz_realloc(hb.p, p->hdr_size);
            if (!np) { err = GZ_E_NOMEM; break; }
            hb.p = np;
            hb.n = p->hdr_size;
            r = gz_src_read_exact(s, base + FH_SIZE + 4, hb.p, p->hdr_size);
        } else {
            r = decode_header(p, s, g, hcsize, &hb, c, &filt);
        }
        if (r) {
            if (r == GZ_E_CANCEL || r == GZ_E_NOMEM) { err = r; break; }
            if (err == GZ_E_FORMAT) err = r;
            continue;
        }
        parse_free(&P);
        __builtin_memset(&P, 0, sizeof P);
        P.h = hb.p + (g->solid ? 4 : 0);
        P.hn = p->hdr_size;
        r = parse_header(&P);
        if (r) {
            if (r == GZ_E_NOMEM || r == GZ_E_LIMIT) { err = r; break; }
            err = GZ_E_FORMAT;
            continue;
        }
        ok = 1;
        p->method = g->method;
        p->solid = g->solid;
        p->lzma_flag = g->lzma_flag;
        p->use_filter = (u8)filt;
        p->dict = g->method == M_LZMA ? dict : 0;
        /* NSIS 2 zlib: stored blocks without NLEN; NSIS 3 uses standard Deflate */
        p->nsis_zlib = g->nsis_zlib || P.type != NT_NSIS3;
        p->unicode = (u8)P.uni;
        p->blocks = base + FH_SIZE + 4 + (g->method == M_COPY ? p->hdr_size : hcsize);
    }
    if (!ok) {
        parse_free(&P);
        gz_free(hb.p);
        return err == GZ_E_DATA || err == GZ_E_TRUNC ? GZ_E_FORMAT : err;
    }
    u32 *ix = 0;
    r = GZ_OK;
    if (P.nit) {
        ix = (u32 *)gz_alloc((size_t)P.nit * sizeof(u32));
        if (!ix) r = GZ_E_NOMEM;
    }
    u32 n = 0;
    if (!r) {
        for (u32 i = 0; i < P.nit; i++) ix[i] = i;
        r = P.nit ? sort_items(&P, ix, P.nit) : GZ_OK;
    }
    if (!r) {
        /* drop exact duplicates (same data, same full name) */
        for (u32 i = 0; i < P.nit; i++)
            if (!n || !same_item(&P, &P.it[ix[n - 1]], &P.it[ix[i]])) ix[n++] = ix[i];
        r = add_entries(a, &P, ix, n, s, c);
    }
    gz_free(ix);
    parse_free(&P);
    gz_free(hb.p);
    if (r) return r;
    a->solid = p->solid;
    a->win_names = 1;
    (void)o;
    return GZ_OK;
}

/* ---------------- extraction ---------------- */

static int out_sink(void *u, const u8 *p, size_t n)
{
    gz_out *o = (gz_out *)u;
    return o->write(o, p, n);
}

/* Copy of the exe stub with the uninstaller patches applied:
 * patch data = { u32 len, u32 offset, len bytes }... u32 0 */
static int patch_stub(u8 *dst, u32 dn, const u8 *q, size_t n)
{
    for (;;) {
        if (n < 4) return GZ_E_DATA;
        u32 len = rd32(q);
        if (!len) return n == 4 ? GZ_OK : GZ_E_DATA;
        if (n < 8) return GZ_E_DATA;
        u32 off = rd32(q + 4);
        q += 8;
        n -= 8;
        if (n < len || off > dn || len > dn - off) return GZ_E_DATA;
        __builtin_memcpy(dst + off, q, len);
        q += len;
        n -= len;
    }
}

/* write the patched stub (patch data in pd/pn) to out */
static int write_stub(const ns_priv *p, gz_src *s, const u8 *pd, size_t pn, gz_out *out)
{
    if (!p->stub_len) return GZ_OK;
    u8 *stub = (u8 *)gz_alloc(p->stub_len);
    if (!stub) return GZ_E_NOMEM;
    int r = gz_src_read_exact(s, p->pe, stub, p->stub_len);
    if (!r) r = patch_stub(stub, p->stub_len, pd, pn);
    if (!r) r = out->write(out, stub, p->stub_len);
    gz_free(stub);
    return r;
}

/* non-solid: one entry */
static int ns_extract_one(gz_archive *a, gz_src *s, const gz_entry *e, gz_out *out, gz_ctx *c)
{
    const ns_priv *p = (const ns_priv *)a->priv;
    if (!(e->flags & NSF_UNINST)) return ns_block(p, s, e->off, out_sink, out, c, 0);
    gz_mem_sink ms = { 0, 0, 0, PATCH_MAX };
    u64 next = 0;
    int r = ns_block(p, s, e->off, gz_mem_write, &ms, c, &next);
    if (!r && ms.n < e->aux) r = GZ_E_DATA;
    if (!r) r = write_stub(p, s, ms.p, (size_t)e->aux, out);
    gz_mem_sink_free(&ms);
    if (!r) r = ns_block(p, s, next, out_sink, out, c, 0);
    return r;
}

/* ---- solid: one decoding pass feeding the selected entries in stream order ---- */

enum { SX_SEEK, SX_SIZE, SX_DATA };

typedef struct {
    gz_archive *a;
    const ns_priv *p;
    gz_src *s;
    gz_out *out;
    const u32 *list; u32 nl;     /* pending entries of this pass, by stream position */
    u8 *done;                    /* per list index                                  */
    u32 gi, gn;                  /* current group: list[gi .. gi + gn) share the data */
    u64 pos, target;
    int ph;
    u32 blk;                     /* uninstaller: 0 patch block, 1 data block        */
    u8 szb[4]; u32 szn;
    u64 left;
    int opened, st;              /* current entry is open / its status              */
    int keep;                    /* collect the block into mb                       */
    gz_mem_sink mb;
    int *res;                    /* optional: status of the entries (by index)      */
} ns_sx;

static void sx_status(ns_sx *x, u32 idx, int st)
{
    if (x->res) x->res[idx] = st;
}

/* first group at or after list index i whose data has not been passed yet */
static int sx_next_group(ns_sx *x, u32 i)
{
    for (;;) {
        while (i < x->nl && x->done[i]) i++;
        if (i >= x->nl) { x->gi = x->nl; return GZ_E_SKIP; }    /* pass complete */
        u64 t = x->a->e[x->list[i]].off;
        u32 j = i + 1;
        while (j < x->nl && x->a->e[x->list[j]].off == t) j++;
        if (t >= x->pos) {
            x->gi = i;
            x->gn = j - i;
            x->target = t;
            x->ph = SX_SEEK;
            x->blk = 0;
            return GZ_OK;
        }
        i = j;                    /* overlaps data already passed: next pass */
    }
}

static int sx_open(ns_sx *x)
{
    u32 idx = x->list[x->gi];
    int r = x->out->open(x->out, idx);
    x->st = GZ_OK;
    x->opened = !r;
    if (r == GZ_E_SKIP) { sx_status(x, idx, GZ_E_SKIP); return GZ_OK; }
    return r;
}

static int sx_end_block(ns_sx *x)
{
    u32 idx = x->list[x->gi];
    const gz_entry *e = &x->a->e[idx];
    if ((e->flags & NSF_UNINST) && x->blk == 0) {
        int pst = x->keep && x->mb.n == e->aux ? GZ_OK : GZ_E_DATA;   /* patch data complete */
        int r = sx_open(x);
        if (r) return r;
        if (x->opened) {
            x->st = pst ? pst : write_stub(x->p, x->s, x->mb.p, x->mb.n, x->out);
            if (x->st == GZ_E_CANCEL) return GZ_E_CANCEL;
        }
        x->blk = 1;
        x->keep = 0;
        x->ph = SX_SIZE;
        x->szn = 0;
        return GZ_OK;
    }
    x->done[x->gi] = 1;
    if (x->opened) {
        if (x->st == GZ_E_SKIP) x->st = GZ_OK;         /* the sink had enough */
        int r = x->out->close(x->out, idx, x->st);
        sx_status(x, idx, x->st);
        x->opened = 0;
        if (r == GZ_E_CANCEL || x->st == GZ_E_CANCEL) return GZ_E_CANCEL;
    }
    /* entries sharing this data: from the buffer, else in the next pass */
    if (x->keep && !(e->flags & NSF_UNINST)) {
        for (u32 j = 1; j < x->gn; j++) {
            u32 di = x->list[x->gi + j];
            if (x->a->e[di].flags & NSF_UNINST) continue;
            x->done[x->gi + j] = 1;
            int r = x->out->open(x->out, di);
            if (r == GZ_E_SKIP) continue;
            if (r) return r;
            int st = x->mb.n ? x->out->write(x->out, x->mb.p, x->mb.n) : GZ_OK;
            if (st == GZ_E_SKIP) st = GZ_OK;
            r = x->out->close(x->out, di, st);
            sx_status(x, di, st);
            if (r == GZ_E_CANCEL || st == GZ_E_CANCEL) return GZ_E_CANCEL;
        }
    }
    x->keep = 0;
    x->mb.n = 0;
    return sx_next_group(x, x->gi + x->gn);
}

static int sx_begin_block(ns_sx *x, u32 len)
{
    u32 idx = x->list[x->gi];
    const gz_entry *e = &x->a->e[idx];
    x->left = len;
    x->ph = SX_DATA;
    x->mb.n = 0;
    x->keep = 0;
    if ((e->flags & NSF_UNINST) && x->blk == 0) {
        x->keep = len == e->aux && len <= PATCH_MAX;        /* else: data error at the end */
    } else if (x->blk == 0) {
        int r = sx_open(x);
        if (r) return r;
        x->keep = x->gn > 1 && len <= DUP_MAX;
    }
    return len ? GZ_OK : sx_end_block(x);
}

static int sx_write(void *u, const u8 *q, size_t n)
{
    ns_sx *x = (ns_sx *)u;
    while (n) {
        if (x->gi >= x->nl) return GZ_E_SKIP;
        int r;
        switch (x->ph) {
        case SX_SEEK: {
            u64 d = x->target - x->pos;
            if (d >= n) { x->pos += n; return GZ_OK; }
            q += d; n -= (size_t)d; x->pos += d;
            x->ph = SX_SIZE;
            x->szn = 0;
            break;
        }
        case SX_SIZE:
            while (n && x->szn < 4) { x->szb[x->szn++] = *q++; n--; x->pos++; }
            if (x->szn == 4 && (r = sx_begin_block(x, rd32(x->szb)))) return r;
            break;
        default: {
            size_t k = x->left < n ? (size_t)x->left : n;
            if (x->keep && gz_mem_write(&x->mb, q, k))
                x->keep = 0;            /* duplicates go to the next pass, patch data fails */
            if (x->opened && !x->st && !(x->blk == 0 && (x->a->e[x->list[x->gi]].flags & NSF_UNINST))) {
                r = x->out->write(x->out, q, k);
                if (r) {
                    if (r == GZ_E_CANCEL) return r;
                    x->st = r;
                }
            }
            q += k; n -= k; x->pos += k; x->left -= k;
            if (!x->left && (r = sx_end_block(x))) return r;
            break;
        }
        }
    }
    return x->gi >= x->nl ? GZ_E_SKIP : GZ_OK;
}

/* open + close an entry with an error status */
static int fail_entry(gz_out *out, u32 idx, int st, int *res)
{
    int r = out->open(out, idx);
    if (r) return r == GZ_E_SKIP ? GZ_OK : r;
    if (res) res[idx] = st;
    r = out->close(out, idx, st);
    return r == GZ_E_CANCEL ? r : GZ_OK;
}

static int solid_extract(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c, int *res)
{
    const ns_priv *p = (const ns_priv *)a->priv;
    u32 *list = (u32 *)gz_alloc((size_t)a->n * sizeof(u32) + 4);
    u8 *done = (u8 *)gz_alloc((size_t)a->n + 1);
    u8 *fin = (u8 *)gz_alloc((size_t)a->n + 1);      /* per entry: handled */
    int ret = GZ_OK;
    if (!list || !done || !fin) { gz_free(list); gz_free(done); gz_free(fin); return GZ_E_NOMEM; }
    for (int pass = 0; pass < MAX_PASSES && !ret; pass++) {
        u32 nl = 0;
        for (u32 i = 0; i < a->n; i++)
            if (sel[i] && !fin[i]) list[nl++] = i;
        if (!nl) break;
        __builtin_memset(done, 0, nl);
        ns_sx x;
        __builtin_memset(&x, 0, sizeof x);
        x.a = a; x.p = p; x.s = s; x.out = out; x.list = list; x.nl = nl; x.done = done; x.res = res;
        x.mb.limit = DUP_MAX > PATCH_MAX ? DUP_MAX : PATCH_MAX;
        sx_next_group(&x, 0);
        int r = ns_run(s, p->base + FH_SIZE, p->end, p->method, p->lzma_flag, p->nsis_zlib, sx_write, &x, c, 0);
        if (r == GZ_E_SKIP) r = GZ_OK;
        if (!r && x.gi < x.nl) r = GZ_E_DATA;            /* stream ended before the data */
        gz_mem_sink_free(&x.mb);
        if (x.opened) {
            u32 idx = list[x.gi];
            int cr = out->close(out, idx, r ? r : GZ_E_DATA);
            if (res) res[idx] = r ? r : GZ_E_DATA;
            done[x.gi] = 1;
            if (cr == GZ_E_CANCEL) r = GZ_E_CANCEL;
        }
        for (u32 k = 0; k < nl; k++) if (done[k]) fin[list[k]] = 1;
        if (r == GZ_E_CANCEL || r == GZ_E_IO || r == GZ_E_CREATE || r == GZ_E_DISK) {
            ret = r;                                     /* open() failed or cancelled */
            break;
        }
        if (r) {
            /* broken stream: entries beyond the failure point fail; entries deferred
             * to the next pass (data shared with earlier entries) are retried */
            for (u32 k = 0; k < nl && !ret; k++)
                if (!fin[list[k]] && a->e[list[k]].off >= x.pos) {
                    fin[list[k]] = 1;
                    ret = fail_entry(out, list[k], r, res);
                }
        }
    }
    /* left over after MAX_PASSES (overlapping data positions) */
    for (u32 i = 0; i < a->n && !ret; i++)
        if (sel[i] && !fin[i]) ret = fail_entry(out, i, GZ_E_DATA, res);
    gz_free(list);
    gz_free(done);
    gz_free(fin);
    return ret;
}

static int ns_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c);

static int ns_extract_solid(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c)
{
    if (((const ns_priv *)a->priv)->solid) return solid_extract(a, s, sel, out, c, 0);
    for (u32 i = 0; i < a->n; i++) {
        if (gz_cancelled(c)) return GZ_E_CANCEL;
        if (sel[i] && ns_extract(a, s, i, out, c) == GZ_E_CANCEL) return GZ_E_CANCEL;
    }
    return GZ_OK;
}

static int ns_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    const ns_priv *p = (const ns_priv *)a->priv;
    if (p->solid) {
        u8 *sel = (u8 *)gz_alloc(a->n);
        int *res = (int *)gz_alloc((size_t)a->n * sizeof(int));
        if (!sel || !res) { gz_free(sel); gz_free(res); return GZ_E_NOMEM; }
        sel[idx] = 1;
        res[idx] = -1;
        int r = solid_extract(a, s, sel, out, c, res);
        int st = res[idx];
        gz_free(sel);
        gz_free(res);
        if (r) return r;
        return st == GZ_E_SKIP || st < 0 ? GZ_OK : st;
    }
    gz_entry *e = &a->e[idx];
    int r = out->open(out, idx);
    if (r) return r;
    int st = ns_extract_one(a, s, e, out, c);
    if (st == GZ_E_SKIP) st = GZ_OK;
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static gz_src *ns_view(gz_archive *a, gz_src *s, u32 idx)
{
    const gz_entry *e = &a->e[idx];
    if (!(e->flags & NSF_STORED) || (e->flags & NSF_UNINST) || e->usize == GZ_SIZE_UNKNOWN) return 0;
    return gz_src_sub(s, e->off + 4, e->usize);
}

static void ns_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    char t[48];
    u32 n = 0;
    const char *m = e->method == M_DEFLATE ? "zlib" : e->method == M_BZIP2 ? "BZip2" :
                    e->method == M_LZMA ? "LZMA:" : "Store";
    while (*m) t[n++] = *m++;
    if (e->method == M_LZMA) {
        u32 d = e->aux32, lg = 0;
        while (lg < 32 && ((u32)1 << lg) != d) lg++;
        char suf = 0;
        if (lg == 32) {
            lg = d;
            suf = 'b';
            if (!(d & ((1u << 20) - 1))) { lg = d >> 20; suf = 'm'; }
            else if (!(d & ((1u << 10) - 1))) { lg = d >> 10; suf = 'k'; }
        }
        char num[12];
        int k = 11;
        num[k] = 0;
        do { num[--k] = (char)('0' + lg % 10); lg /= 10; } while (lg);
        while (num[k]) t[n++] = num[k++];
        if (suf) t[n++] = suf;
        if (e->flags & NSF_FILTER) { t[n++] = ' '; t[n++] = 'B'; t[n++] = 'C'; t[n++] = 'J'; }
    }
    u32 i = 0;
    for (; i < n && i + 1 < cap; i++) buf[i] = t[i];
    if (cap) buf[i] = 0;
}

GZ_FORMAT(gz_fmt_nsis)
const gz_format gz_fmt_nsis = {
    "NSIS", "exe nsis",
    0, ns_probe, ns_open, ns_close, ns_extract, ns_extract_solid, 0, ns_method, ns_view, 0
};
