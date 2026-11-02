/*
 * 고깃ZIP - 7z writer (readable by 7-Zip 9.20 and later, p7zip, libarchive, py7zr)
 *
 * Layout:
 *   signature header   32 bytes, written first as a placeholder, patched at the end
 *   packed streams     one per folder (a solid block, or one file)
 *   [packed header]    the header compressed with LZMA (+ 7zAES when names are
 *                      encrypted), described by a kEncodedHeader record
 *   header             the plain header, or the kEncodedHeader record
 *
 * A folder is a coder chain, listed packed side first as 7-Zip 23 writes it:
 *   [7zAES] <LZMA2 | LZMA | PPMd | BZip2 | Deflate | Copy> [BCJ | ARM64]
 * with one packed stream; the file sizes and CRCs are in SubStreamsInfo.
 *
 * Executables get their own folders with a branch filter: x86 BCJ for x86/x64
 * PE, ELF and Mach-O code, ARM64 for ARM64 ones. Windows executables are found
 * by extension (.exe .dll .sys .ocx .cpl .scr .drv .efi), every other file of
 * 2 KiB and more by its first bytes (MZ/PE, ELF, Mach-O headers). Nothing is
 * read twice for that: a file's class is guessed from its name and mode, the
 * guess is checked on the first 4 KiB when the file is compressed, and a file
 * that turns out to belong to another group is closed and moved there (only
 * such files are opened a second time).
 *
 * Solid mode (o->solid != 0) groups files by filter, then by type like 7-Zip's
 * -mqs (its extension order, extension, name); a block holds at most
 * clamp(dictionary * 128, 16 MiB, 4 GiB) bytes and 2^20 files. o->solid == 0 and
 * Copy (level 0) write one folder per file.
 *
 * Encryption: 7zAES (AES-256-CBC, key = SHA-256 KDF with 2^19 rounds, no salt,
 * random 16-byte IV per folder). o->encrypt_names also encrypts the header.
 *
 * Header: names (UTF-16LE, '/' separated), empty streams/files (directories and
 * empty files come first, then the files in folder order), MTime/CTime/ATime when
 * known, attributes (Windows bits; 0x8000 + unix mode << 16 when the mode is known,
 * as p7zip / 7-Zip for Linux write them), symbolic links as files holding the
 * UTF-8 target with mode 0120xxx. The header is LZMA-compressed unless that does
 * not make it smaller (always when it is encrypted).
 *
 * Methods: LZMA2 (default), LZMA, PPMd, BZip2, Deflate, Copy (default at level 0).
 * LZMA dictionaries follow 7-Zip's levels (256 KiB at 1 .. 16 MiB at 5 .. 64 MiB at
 * 8-9, o->dict_size overrides), cut down to the folder size; when the encoder cannot
 * get its memory before consuming any input, it is retried with half the dictionary
 * (PPMd: model). Single-threaded: src/fmt has no threads, o->threads is not used.
 *
 * Input is streamed (256 KiB staging buffer); sizes come from what was read, so
 * files that grow or shrink while being archived are stored as they were read.
 * A file that cannot be opened or read goes to o->on_error: GZ_OK skips it (bytes
 * already compressed stay, the file keeps them), anything else aborts.
 */
#include "gz_write.h"
#include "lzma_enc.h"
#include "bcj.h"
#include "bzip2_enc.h"
#include "deflate_enc.h"
#include "ppmd7.h"
#include "crc32.h"

#define STAGE       (256u << 10)      /* input staging buffer                          */
#define ABUF        (64u << 10)       /* AES output buffer (multiple of 16)            */
#define PEEK        4096u             /* bytes checked to classify an executable       */
#define EXE_MIN     2048u             /* smaller files are only classified by name     */
#define SOLID_MIN   ((u64)1 << 24)
#define SOLID_MAX   ((u64)1 << 32)
#define SOLID_FILES (1u << 20)
#define KDF_POWER   19
#define NIL         0xFFFFFFFFu
#if UINTPTR_MAX > 0xFFFFFFFFu
#define HDR_MAX     ((size_t)1 << 31)  /* header bytes in memory                       */
#else
#define HDR_MAX     ((size_t)1 << 28)
#endif

enum {                                  /* property ids */
    kEnd = 0, kHeader = 1, kMainStreamsInfo = 4, kFilesInfo = 5, kPackInfo = 6, kUnPackInfo = 7,
    kSubStreamsInfo = 8, kSize = 9, kCRC = 10, kFolder = 11, kCodersUnPackSize = 12,
    kNumUnPackStream = 13, kEmptyStream = 14, kEmptyFile = 15, kName = 17, kCTime = 18,
    kATime = 19, kMTime = 20, kWinAttributes = 21, kEncodedHeader = 23
};

enum { M_COPY, M_LZMA2, M_LZMA, M_PPMD, M_BZIP2, M_DEFLATE };
static const u8 k_mid[6][3] = { { 0x00 }, { 0x21 }, { 3, 1, 1 }, { 3, 4, 1 }, { 4, 2, 2 }, { 4, 1, 8 } };
static const u8 k_midlen[6] = { 1, 1, 3, 3, 3, 3 };

enum { F_NONE = 0, F_X86, F_ARM64, F_COUNT };     /* branch filter classes (group order) */
static const u8 k_bcj[F_COUNT] = { GZ_BCJ_NONE, GZ_BCJ_X86, GZ_BCJ_ARM64 };
#if defined(__aarch64__) || defined(_M_ARM64)
#define F_HOST F_ARM64
#else
#define F_HOST F_X86
#endif

enum { K_DIR = 1, K_FILE, K_LINK };
enum { S_PLAN = 0, S_STORED, S_SKIPPED, S_EMPTIED, S_DEFER };

typedef struct sz_item {
    const gzch *name;       /* archive name without leading "/" "./" or trailing "/"  */
    u64 size;               /* planned size, then the stored size                     */
    u32 nlen;               /* name length in UTF-16 units                            */
    u32 base, ext;          /* offsets of the base name and the extension (nlen: none) */
    u32 next;               /* solid: next item of the same pending list               */
    u32 folder;             /* folder holding the data (S_STORED)                      */
    u32 crc, attr;
    u16 ext_idx;            /* 7-Zip type order of the extension                       */
    u8  kind, state;
    u8  filter;             /* F_*: guess, then what the data showed                   */
    u8  cand, known, winexe;
} sz_item;

typedef struct sz_folder {
    u64 unpack;             /* bytes in (= every coder's output but AES's)              */
    u64 coder_out;          /* compressor output = AES input                            */
    u64 packed;             /* packed stream size                                       */
    u32 first, count;       /* planned items: w->order[first .. first + count)          */
    u32 nsub;               /* stored files                                             */
    u8  method, filter, aes, nprops;
    u8  props[5];
    u8  iv[16];
} sz_folder;

typedef struct szw {
    const gz_wopts *o;
    const gz_witem *items;
    gz_sink *out;
    gz_ctx *c;
    sz_item *e;
    u32 n;
    u32 *order; u32 norder;
    sz_folder *f; u32 nf, fcap;
    u32 head[F_COUNT], tail[F_COUNT], lhead[F_COUNT], ltail[F_COUNT];
    u8  started[F_COUNT];
    int method, level, filters, enc;
    gz_lzma_enc_opts lo;
    u32 ppmd_mem, ppmd_cap;
    gz_lzma_enc *lz; u32 lz_key;
    gz_ppmd7 *pp;
    gz_bzip2_enc *bz;
    gz_deflate_enc *df;
    gz_aes aes;
    u64 solid_limit;
    u64 base;               /* sink position of the signature header                   */
    u64 total, done;
    u8 *stage, *abuf;
    u8 *lb; u32 lcap;       /* UTF-8 link target                                        */
    u8 rnd[1024]; u32 rnd_pos;  /* random bytes for the IVs                              */
} szw;

/* one coder chain run: input from files (or memory), output to the sink (or memory) */
typedef struct fctx {
    szw *w;
    const u32 *list; u32 n, pos;
    sz_item *cur;           /* file being read                                          */
    gz_wsrc *src;
    const u8 *mp; size_t mn;  /* memory input: link target, or the header (raw)         */
    int raw;
    u32 s_beg, s_fin, s_end;  /* stage: [beg, fin) final, [fin, end) not yet filtered  */
    int eof, auto_filter, filter;
    int pend_err;           /* read error seen while peeking, reported after the bytes before it */
    gz_bcj bcj;
    u64 fed;                /* bytes handed to the compressor                           */
    int aes; u8 iv[16]; u32 an;
    gz_mem_sink *ms;        /* output to memory instead of the sink                     */
    u64 coder_out, packed;
    u32 folder;
} fctx;

static int w_cancelled(const szw *w)
{
    return (w->o->cancel && *w->o->cancel) || gz_cancelled(w->c);
}

/* ---------------- small helpers ---------------- */

/* UTF-16 -> UTF-8 (out NULL: count only); lone U+DC80..U+DCFF are raw bytes of
 * POSIX names that were not UTF-8 and are written back as those bytes */
static u32 w2u(const gzch *s, size_t n, u8 *o)
{
    u32 k = 0;
    for (size_t i = 0; i < n; i++) {
        u32 c = s[i], m;
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < n && s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000) {
            c = 0x10000 + ((c - 0xD800) << 10) + (s[i + 1] - 0xDC00);
            i++;
        } else if (c >= 0xDC80 && c <= 0xDCFF) {
            if (o) o[k] = (u8)(c - 0xDC00);
            k++;
            continue;
        } else if (c >= 0xD800 && c < 0xE000) {
            c = 0xFFFD;
        }
        m = c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
        if (o) {
            u8 *d = o + k;
            if (m == 1) d[0] = (u8)c;
            else if (m == 2) { d[0] = (u8)(0xC0 | (c >> 6)); d[1] = (u8)(0x80 | (c & 63)); }
            else if (m == 3) {
                d[0] = (u8)(0xE0 | (c >> 12)); d[1] = (u8)(0x80 | ((c >> 6) & 63)); d[2] = (u8)(0x80 | (c & 63));
            } else {
                d[0] = (u8)(0xF0 | (c >> 18)); d[1] = (u8)(0x80 | ((c >> 12) & 63));
                d[2] = (u8)(0x80 | ((c >> 6) & 63)); d[3] = (u8)(0x80 | (c & 63));
            }
        }
        k += m;
    }
    return k;
}

static int ci_cmp(const gzch *a, u32 an, const gzch *b, u32 bn)
{
    u32 k = an < bn ? an : bn;
    for (u32 i = 0; i < k; i++) {
        u32 x = a[i], y = b[i];
        if (x - 'A' < 26) x += 32;
        if (y - 'A' < 26) y += 32;
        if (x != y) return x < y ? -1 : 1;
    }
    return an < bn ? -1 : an > bn;
}

/* extension (ASCII, case-insensitive) is one of the words in list */
static int ext_in(const sz_item *e, const char *list)
{
    u32 n = e->nlen - e->ext;
    const gzch *x = e->name + e->ext;
    if (e->ext >= e->nlen) return 0;
    while (*list) {
        u32 k = 0;
        while (list[k] && list[k] != ' ') k++;
        if (k == n) {
            u32 i = 0;
            for (; i < n; i++) {
                u32 c = x[i];
                if (c - 'A' < 26) c += 32;
                if (c != (u8)list[i]) break;
            }
            if (i == n) return 1;
        }
        list += k;
        while (*list == ' ') list++;
    }
    return 0;
}

/* ---------------- file types (solid ordering) ----------------
 * 7-Zip's extension list (7zUpdate.cpp): files are ordered by the position of
 * their extension in it, so that similar data ends up side by side. */
static const char k_exts[] =
    "7z xz lzma ace arc arj bz tbz bz2 tbz2 cab deb gz tgz ha lha lzh lzo lzx pak rar rpm sit zoo zst "
    "zip jar ear war msi apk "
    "3gp avi mov mpeg mpg mpe wmv mkv webm "
    "aac ape fla flac la mp3 m4a mp4 ofr ogg opus pac ra rm rka shn swa tta wv wma wav "
    "swf chm hxi hxs "
    "gif jpeg jpg jp2 png tiff bmp ico psd psp webp heic avif "
    "awg ps eps cgm dxf svg vrml wmf emf ai md "
    "cad dwg pps key sxi max 3ds "
    "iso bin nrg mdf img pdi tar cpio xpi vfd vhd vud vmc vsv "
    "vmdk dsk nvram vmem vmsd vmsn vmss vmtm "
    "inl inc idl acf asa h hpp hxx c cpp cxx cc m mm go swift "
    "rc java kt cs rs pas bas vb cls ctl frm dlg def f77 f f90 f95 asm s "
    "sql manifest dep mak clw csproj vcproj vcxproj sln dsp dsw class "
    "bat cmd bash sh ps1 "
    "xml xsd xsl xslt hxk hxc htm html xhtml xht mht mhtml htw asp aspx css cgi jsp shtml "
    "awk sed hta js json php php3 php4 php5 phptml pl pm py pyo rb tcl ts vbs yaml yml toml "
    "text txt tex ans asc srt reg ini log doc docx mcw dot rtf hlp xls xlsx xlr xlt xlw ppt pptx pdf "
    "sxc sxd sxg sxw stc sti stw stm odt ott odg otg odp otp ods ots odf "
    "abw afp cwk lwp wpd wps wpt wrf wri "
    "abf afm bdf fon mgf otf pcf pfa snf ttf woff woff2 "
    "dbf mdb nsf ntf wdb db fdb gdb sqlite "
    "exe dll ocx vbx sfx sys tlb awx com obj lib out o so a ko dylib "
    "pdb pch idb ncb opt";

#define EXT_TAB 1024u
typedef struct ext_tab {
    u16 slot[EXT_TAB];        /* word number (1-based), 0 = empty */
    u16 off[512];
    u8  len[512];
    u32 nwords;
} ext_tab;

static u32 ext_hash(const u8 *s, u32 n)
{
    u32 h = 2166136261u;
    for (u32 i = 0; i < n; i++) h = (h ^ s[i]) * 16777619u;
    return h ^ (h >> 15);
}

static void ext_build(ext_tab *t)
{
    const char *p = k_exts;
    __builtin_memset(t, 0, sizeof *t);
    while (*p && t->nwords < 512) {
        u32 k = 0, o = (u32)(p - k_exts);
        while (p[k] && p[k] != ' ') k++;
        u32 h = ext_hash((const u8 *)p, k) & (EXT_TAB - 1), dup = 0;
        while (t->slot[h]) {
            u32 w = t->slot[h] - 1u;
            if (t->len[w] == k && !__builtin_memcmp(k_exts + t->off[w], p, k)) { dup = 1; break; }
            h = (h + 1) & (EXT_TAB - 1);
        }
        t->off[t->nwords] = (u16)o;
        t->len[t->nwords] = (u8)k;
        t->nwords++;
        if (!dup) t->slot[h] = (u16)t->nwords;
        p += k;
        while (*p == ' ') p++;
    }
}

/* 0: no extension (or not ASCII), 1..N: position in the list, N + 1: unknown */
static u16 ext_index(const ext_tab *t, const sz_item *e)
{
    u32 n = e->nlen - e->ext;
    u8 s[16];
    if (e->ext >= e->nlen) return 0;
    if (n > sizeof s) return (u16)(t->nwords + 1);
    for (u32 i = 0; i < n; i++) {
        u32 c = e->name[e->ext + i];
        if (c >= 0x80) return 0;
        if (c - 'A' < 26) c += 32;
        s[i] = (u8)c;
    }
    u32 h = ext_hash(s, n) & (EXT_TAB - 1);
    while (t->slot[h]) {
        u32 w = t->slot[h] - 1u;
        if (t->len[w] == n && !__builtin_memcmp(k_exts + t->off[w], s, n)) return (u16)(w + 1);
        h = (h + 1) & (EXT_TAB - 1);
    }
    return (u16)(t->nwords + 1);
}

static int item_less(const szw *w, u32 a, u32 b)
{
    const sz_item *x = &w->e[a], *y = &w->e[b];
    int c;
    if (x->filter != y->filter) return x->filter < y->filter;
    if (x->ext_idx != y->ext_idx) return x->ext_idx < y->ext_idx;
    c = ci_cmp(x->name + x->ext, x->nlen - x->ext, y->name + y->ext, y->nlen - y->ext);
    if (!c) c = ci_cmp(x->name + x->base, x->nlen - x->base, y->name + y->base, y->nlen - y->base);
    if (!c) c = ci_cmp(x->name, x->nlen, y->name, y->nlen);
    if (c) return c < 0;
    return a < b;
}

/* stable merge sort of item indices (insertion-sorted runs of 16, then merges) */
static void sort_items(const szw *w, u32 *a, u32 *tmp, u32 n)
{
    u32 *src = a, *dst = tmp;
    for (u32 i = 0; i < n; i += 16) {
        u32 end = n - i < 16 ? n : i + 16;
        for (u32 j = i + 1; j < end; j++) {
            u32 v = a[j], k = j;
            while (k > i && item_less(w, v, a[k - 1])) { a[k] = a[k - 1]; k--; }
            a[k] = v;
        }
    }
    for (u64 wd = 16; wd < n; wd *= 2) {
        for (u64 lo = 0; lo < n; lo += 2 * wd) {
            u64 mid = lo + wd < n ? lo + wd : n, hi = lo + 2 * wd < n ? lo + 2 * wd : n;
            u64 i = lo, j = mid, k = lo;
            while (i < mid && j < hi) dst[k++] = item_less(w, src[j], src[i]) ? src[j++] : src[i++];
            while (i < mid) dst[k++] = src[i++];
            while (j < hi) dst[k++] = src[j++];
        }
        u32 *t = src; src = dst; dst = t;
    }
    if (src != a) __builtin_memcpy(a, src, (size_t)n * sizeof(u32));
}

/* ---------------- executable detection ---------------- */

static int classify(const u8 *p, u32 n, int winexe)
{
    if (n >= 0x40 && p[0] == 'M' && p[1] == 'Z') {
        u32 pe = rd32(p + 0x3C);
        if (pe <= n - 6 && rd32(p + pe) == 0x00004550u) {
            u32 m = rd16(p + pe + 4);
            if (m == 0x14C || m == 0x8664) return F_X86;
            if (m == 0xAA64) return F_ARM64;
            return F_NONE;
        }
    } else if (n >= 20 && rd32(p) == 0x464C457Fu && p[5] == 1) {      /* ELF, little-endian */
        u32 m = rd16(p + 18);
        if (m == 3 || m == 62) return F_X86;
        if (m == 183) return F_ARM64;
        return F_NONE;
    } else if (n >= 8 && (rd32(p) == 0xFEEDFACEu || rd32(p) == 0xFEEDFACFu)) {    /* Mach-O */
        u32 cpu = rd32(p + 4);
        if (cpu == 7 || cpu == 0x01000007u) return F_X86;
        if (cpu == 0x0100000Cu) return F_ARM64;
        return F_NONE;
    }
    return winexe ? F_X86 : F_NONE;     /* by name, as 7-Zip 9.20 did */
}

/* ---------------- header buffer ---------------- */

typedef struct hbuf { u8 *p; size_t n, cap; int err; } hbuf;

static u8 *hb_need(hbuf *h, size_t k)
{
    if (h->err) return 0;
    if (k > h->cap - h->n) {
        size_t nc = h->cap ? h->cap : 4096;
        while (nc - h->n < k) {
            if (nc >= HDR_MAX) { h->err = GZ_E_LIMIT; return 0; }
            nc *= 2;
        }
        u8 *np = (u8 *)gz_realloc(h->p, nc);
        if (!np) { h->err = GZ_E_NOMEM; return 0; }
        h->p = np;
        h->cap = nc;
    }
    u8 *p = h->p + h->n;
    h->n += k;
    return p;
}

static void hb_byte(hbuf *h, u8 b) { u8 *p = hb_need(h, 1); if (p) *p = b; }
static void hb_bytes(hbuf *h, const void *s, size_t k) { u8 *p = hb_need(h, k); if (p && k) __builtin_memcpy(p, s, k); }
static void hb_u32(hbuf *h, u32 v) { u8 *p = hb_need(h, 4); if (p) wr32(p, v); }
static void hb_u64(hbuf *h, u64 v) { u8 *p = hb_need(h, 8); if (p) wr64(p, v); }

/* 7z number: the first byte's leading 1 bits count the extra little-endian bytes */
static void hb_num(hbuf *h, u64 v)
{
    u8 first = 0, mask = 0x80;
    u32 i;
    for (i = 0; i < 8; i++) {
        if (v < ((u64)1 << (7 * (i + 1)))) { first |= (u8)(v >> (8 * i)); break; }
        first |= mask;
        mask >>= 1;
    }
    u8 *p = hb_need(h, 1 + i);
    if (!p) return;
    p[0] = first;
    for (u32 k = 0; k < i; k++) p[1 + k] = (u8)(v >> (8 * k));
}

static void put_coder(hbuf *h, const u8 *id, u32 idn, const u8 *props, u32 np)
{
    hb_byte(h, (u8)(idn | (np ? 0x20 : 0)));
    hb_bytes(h, id, idn);
    if (np) {
        hb_num(h, np);
        hb_bytes(h, props, np);
    }
}

static void put_folder(hbuf *h, const sz_folder *fo)
{
    static const u8 aes_id[4] = { 0x06, 0xF1, 0x07, 0x01 };
    static const u8 x86_id[4] = { 0x03, 0x03, 0x01, 0x03 };
    static const u8 a64_id[1] = { 0x0A };
    u32 nc = 1u + (fo->aes != 0) + (fo->filter != F_NONE);
    hb_num(h, nc);
    if (fo->aes) {
        u8 ap[18];
        ap[0] = 0x40 | KDF_POWER;           /* IV present, 2^19 rounds */
        ap[1] = 0x0F;                       /* no salt, 16-byte IV     */
        __builtin_memcpy(ap + 2, fo->iv, 16);
        put_coder(h, aes_id, 4, ap, 18);
    }
    put_coder(h, k_mid[fo->method], k_midlen[fo->method], fo->props, fo->nprops);
    if (fo->filter == F_X86) put_coder(h, x86_id, 4, 0, 0);
    else if (fo->filter == F_ARM64) put_coder(h, a64_id, 1, 0, 0);
    for (u32 k = 1; k < nc; k++) {          /* coder k reads coder k-1's output */
        hb_num(h, k);
        hb_num(h, k - 1);
    }
}

static void put_unpack_sizes(hbuf *h, const sz_folder *fo)
{
    if (fo->aes) hb_num(h, fo->coder_out);
    hb_num(h, fo->unpack);
    if (fo->filter != F_NONE) hb_num(h, fo->unpack);
}

/* ---------------- input side of a coder chain ---------------- */

static int link_bytes(szw *w, const gz_witem *it, const u8 **p, size_t *n)
{
    size_t wn = gz_wcslen(it->link_target);
    if (wn > (1u << 20)) return GZ_E_LIMIT;
    u32 need = (u32)wn * 3 + 4;
    if (need > w->lcap) {
        u8 *nb = (u8 *)gz_realloc(w->lb, need);
        if (!nb) return GZ_E_NOMEM;
        w->lb = nb;
        w->lcap = need;
    }
    *n = w2u(it->link_target, wn, w->lb);
    *p = w->lb;
    return GZ_OK;
}

static void account(fctx *f, const u8 *p, u32 n)
{
    szw *w = f->w;
    sz_item *e = f->cur;
    e->size += n;
    e->crc = gz_crc32(e->crc, p, n);
    w->done += n;
    if (w->o->progress) w->o->progress(w->o->user, w->done, w->done > w->total ? w->done : w->total);
}

static int open_file(fctx *f)
{
    szw *w = f->w;
    const gz_wopts *o = w->o;
    u32 i = f->list[f->pos++];
    sz_item *e = &w->e[i];
    const gz_witem *it = &w->items[i];
    int r;
    e->size = 0;
    e->crc = 0;
    e->state = S_PLAN;
    if (e->kind == K_LINK) {
        if ((r = link_bytes(w, it, &f->mp, &f->mn)) != GZ_OK) return r;
        f->cur = e;
        return GZ_OK;
    }
    gz_wsrc *s = 0;
    r = o->open_item(o->user, it, &s);
    if (!r && !s) r = GZ_E_IO;
    if (r) {
        e->state = S_SKIPPED;
        if (r == GZ_E_CANCEL) return r;
        return o->on_error ? o->on_error(o->user, it, r) : r;    /* GZ_OK: skip the file */
    }
    f->src = s;
    f->cur = e;
    return GZ_OK;
}

/* end of the current file; err != 0: it failed while being read */
static int close_file(fctx *f, int err)
{
    szw *w = f->w;
    const gz_wopts *o = w->o;
    sz_item *e = f->cur;
    const gz_witem *it = &w->items[e - w->e];
    if (f->src) o->close_item(o->user, it, f->src);
    f->src = 0;
    f->cur = 0;
    f->mn = 0;
    f->pend_err = 0;
    if (err) {
        if (err == GZ_E_CANCEL) return err;
        int er = o->on_error ? o->on_error(o->user, it, err) : err;
        if (er) return er;
    }
    e->state = e->size ? S_STORED : err ? S_SKIPPED : S_EMPTIED;
    if (e->size) e->folder = f->folder;
    return GZ_OK;
}

/* the file belongs to another filter group: close it unread and queue it there */
static void defer(fctx *f, int cls)
{
    szw *w = f->w;
    sz_item *e = f->cur;
    u32 i = (u32)(e - w->e);
    w->o->close_item(w->o->user, &w->items[i], f->src);
    f->src = 0;
    f->cur = 0;
    f->pend_err = 0;
    e->size = w->items[i].size;             /* planned size again, for the block limits */
    e->filter = (u8)cls;
    e->known = 1;
    e->state = S_DEFER;
    e->next = NIL;
    u32 *hd = w->started[cls] ? &w->lhead[cls] : &w->head[cls];
    u32 *tl = w->started[cls] ? &w->ltail[cls] : &w->tail[cls];
    if (*hd == NIL) *hd = i;
    else w->e[*tl].next = i;
    *tl = i;
}

static int read_src(fctx *f, u8 *buf, u32 cap, u32 *got)
{
    u32 g = 0;
    int r;
    if (f->pend_err) {
        r = f->pend_err;
        f->pend_err = 0;
    } else if (f->src) {
        r = f->src->read(f->src, buf, cap, &g);
        if (g > cap) g = cap;
    } else {
        r = GZ_OK;
        g = f->mn < cap ? (u32)f->mn : cap;
        if (g) __builtin_memcpy(buf, f->mp, g);
        f->mp += g;
        f->mn -= g;
    }
    *got = r ? 0 : g;
    return r;
}

/* first bytes of a file (up to PEEK); a read error after some bytes is kept for later,
 * so that those bytes are stored like with any other read error */
static int peek(fctx *f, u8 *buf, u32 cap, u32 *got)
{
    u32 k = 0, want = cap < PEEK ? cap : PEEK;
    int r = GZ_OK;
    while (k < want) {
        u32 g;
        if ((r = read_src(f, buf + k, want - k, &g)) != GZ_OK || !g) break;
        k += g;
    }
    if (r && k && r != GZ_E_CANCEL) {
        f->pend_err = r;
        r = GZ_OK;
    }
    *got = r ? 0 : k;
    return r;
}

/* raw input: next bytes of the folder's files; *got = 0 at the end */
static int f_fill(fctx *f, u8 *buf, u32 cap, u32 *got)
{
    szw *w = f->w;
    *got = 0;
    if (f->raw) {
        u32 g = f->mn < cap ? (u32)f->mn : cap;
        if (w_cancelled(w)) return GZ_E_CANCEL;
        if (g) __builtin_memcpy(buf, f->mp, g);
        f->mp += g;
        f->mn -= g;
        *got = g;
        return GZ_OK;
    }
    for (;;) {
        u32 g = 0;
        int r;
        if (w_cancelled(w)) return GZ_E_CANCEL;
        if (!f->cur) {
            if (f->pos >= f->n) return GZ_OK;
            if ((r = open_file(f)) != GZ_OK) return r;
            if (!f->cur) continue;
            sz_item *e = f->cur;
            if (e->cand && !e->known) {
                r = peek(f, buf, cap, &g);
                if (!r && g) {
                    int cls = classify(buf, g, e->winexe);
                    e->known = 1;
                    if (f->auto_filter) {
                        e->filter = (u8)cls;
                    } else if (cls != f->filter) {
                        defer(f, cls);
                        continue;
                    }
                }
            } else {
                r = read_src(f, buf, cap, &g);
            }
            if (f->auto_filter) {           /* one file per folder: its class decides */
                f->auto_filter = 0;
                f->filter = e->filter;
                gz_bcj_init(&f->bcj, k_bcj[f->filter], 0, 1);
            }
        } else {
            r = read_src(f, buf, cap, &g);
        }
        if (r == GZ_E_CANCEL) return r;
        if (r || !g) {
            if ((r = close_file(f, r)) != GZ_OK) return r;
            continue;
        }
        account(f, buf, g);
        *got = g;
        return GZ_OK;
    }
}

static int stage_more(fctx *f)
{
    u8 *st = f->w->stage;
    u32 g = 0;
    if (f->s_beg) {
        u32 k = f->s_end - f->s_beg;
        if (k) __builtin_memmove(st, st + f->s_beg, k);
        f->s_fin -= f->s_beg;
        f->s_end = k;
        f->s_beg = 0;
    }
    int r = f_fill(f, st + f->s_end, STAGE - f->s_end, &g);
    if (r) return r;
    if (!g) f->eof = 1;
    f->s_end += g;
    return GZ_OK;
}

/* next filtered bytes, pointing into the stage (valid until the next call); *n = 0 at the end */
static int f_pull(fctx *f, u32 max, const u8 **p, u32 *n)
{
    *n = 0;
    for (;;) {
        if (f->s_beg < f->s_fin) {
            u32 k = f->s_fin - f->s_beg;
            if (k > max) k = max;
            *p = f->w->stage + f->s_beg;
            f->s_beg += k;
            f->fed += k;
            *n = k;
            return GZ_OK;
        }
        if (f->s_fin < f->s_end) {
            if (f->filter == F_NONE || f->eof) {       /* a tail shorter than an instruction stays as is */
                f->s_fin = f->s_end;
                continue;
            }
            size_t d = gz_bcj_code(&f->bcj, f->w->stage + f->s_fin, f->s_end - f->s_fin);
            if (d) {
                f->s_fin += (u32)d;
                continue;
            }
        } else if (f->eof) {
            return GZ_OK;
        }
        int r = stage_more(f);
        if (r) return r;
    }
}

static int f_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    const u8 *p;
    u32 k;
    int r = f_pull((fctx *)ctx, cap, &p, &k);
    if (!r && k) __builtin_memcpy(buf, p, k);
    *got = r ? 0 : k;
    return r;
}

/* ---------------- output side ---------------- */

static int f_out(fctx *f, const u8 *p, size_t n)
{
    int r = f->ms ? gz_mem_write(f->ms, p, n) : gz_sink_write(f->w->out, p, n);
    if (!r) f->packed += n;
    return r;
}

static int f_write(void *ctx, const u8 *p, size_t n)
{
    fctx *f = (fctx *)ctx;
    u8 *ab = f->w->abuf;
    f->coder_out += n;
    if (!f->aes) return f_out(f, p, n);
    while (n) {
        u32 k = ABUF - f->an;
        if (k > n) k = (u32)n;
        __builtin_memcpy(ab + f->an, p, k);
        f->an += k;
        p += k;
        n -= k;
        if (f->an == ABUF) {
            gz_aes_cbc_encrypt(&f->w->aes, f->iv, ab, ABUF);
            f->an = 0;
            int r = f_out(f, ab, ABUF);
            if (r) return r;
        }
    }
    return GZ_OK;
}

static int aes_finish(fctx *f)
{
    u8 *ab = f->w->abuf;
    u32 pad = (16 - (f->an & 15)) & 15;
    if (pad) __builtin_memset(ab + f->an, 0, pad);    /* 7-Zip pads with zeros too */
    f->an += pad;
    if (!f->an) return GZ_OK;
    gz_aes_cbc_encrypt(&f->w->aes, f->iv, ab, f->an);
    u32 k = f->an;
    f->an = 0;
    return f_out(f, ab, k);
}

static int aes_start(fctx *f, sz_folder *fo)
{
    szw *w = f->w;
    if (!w->rnd_pos || w->rnd_pos >= sizeof w->rnd) {
        if (gz_plat_random(w->rnd, sizeof w->rnd) != GZ_OK) return GZ_E_IO;
        w->rnd_pos = 0;
    }
    __builtin_memcpy(f->iv, w->rnd + w->rnd_pos, 16);
    w->rnd_pos += 16;
    f->aes = 1;
    fo->aes = 1;
    __builtin_memcpy(fo->iv, f->iv, 16);
    return GZ_OK;
}

/* ---------------- compressors ---------------- */

/* the dictionary the LZMA encoder will use (lzma_enc.c rounds the same way) */
static u32 dict_eff(u32 d, u64 hint)
{
    if (hint && hint < d) d = (u32)hint;
    if (d <= 4096) return 4096;
    for (u32 i = 11; i < 31; i++) {
        if (d <= (2u << i)) return 2u << i;
        if (d <= (3u << i)) return 3u << i;
    }
    return d;
}

/* a failed allocation before any byte was consumed is retried with half the
 * dictionary / model size (32-bit address space, low memory) */
static int can_retry(const fctx *f, int r, u32 size)
{
    return (r == GZ_E_NOMEM || r == GZ_E_LIMIT) && !f->fed && !f->coder_out && size > (1u << 20);
}

static int run_lzma(fctx *f, sz_folder *fo, const gz_stream_io *io, u64 hint, int lzma2)
{
    szw *w = f->w;
    for (;;) {
        gz_lzma_enc_opts op = w->lo;
        op.size_hint = hint;
        u32 key = dict_eff(op.dict_size, hint);
        int r = gz_lzma_enc_check(&op, lzma2);
        if (!r) {
            if (w->lz && w->lz_key != key) { gz_lzma_enc_free(w->lz); w->lz = 0; }
            if (!w->lz) { w->lz = gz_lzma_enc_new(&op); w->lz_key = key; }
            if (!w->lz) r = GZ_E_NOMEM;
            else if (lzma2) { r = gz_lzma2_encode(w->lz, io, fo->props); fo->nprops = 1; }
            else { r = gz_lzma_encode(w->lz, io, fo->props, 0); fo->nprops = 5; }
        }
        if (can_retry(f, r, w->lo.dict_size)) {
            gz_lzma_enc_free(w->lz);
            w->lz = 0;
            w->lo.dict_size >>= 1;              /* the following folders too */
            continue;
        }
        return r;
    }
}

static int run_ppmd(fctx *f, sz_folder *fo, const gz_stream_io *io, u64 hint)
{
    szw *w = f->w;
    u32 order, mem;
    int r;
    gz_ppmd7z_level(w->level, hint ? hint : GZ_SIZE_UNKNOWN, &order, &mem);
    if (w->ppmd_mem) mem = w->ppmd_mem;
    if (w->ppmd_cap && mem > w->ppmd_cap) mem = w->ppmd_cap;
    for (;;) {
        if (!w->pp && !(w->pp = gz_ppmd7_new())) return GZ_E_NOMEM;
        r = gz_ppmd7z_encode_ex(w->pp, order, mem, io, 0, 0);
        if (can_retry(f, r, mem)) {
            mem >>= 1;
            w->ppmd_cap = mem;
            continue;
        }
        break;
    }
    gz_ppmd7z_write_props(fo->props, order, mem);
    fo->nprops = 5;
    return r;
}

static int run_coder(fctx *f, sz_folder *fo, u64 hint)
{
    szw *w = f->w;
    gz_stream_io io = { f_read, f_write, f };
    int r;
    switch (fo->method) {
    case M_COPY:
        for (;;) {
            const u8 *p;
            u32 k;
            if ((r = f_pull(f, 1u << 20, &p, &k)) != GZ_OK || !k) return r;
            if ((r = f_write(f, p, k)) != GZ_OK) return r;
        }
    case M_LZMA2:
        return run_lzma(f, fo, &io, hint, 1);
    case M_LZMA:
        return run_lzma(f, fo, &io, hint, 0);
    case M_PPMD:
        return run_ppmd(f, fo, &io, hint);
    case M_BZIP2:
        if (!w->bz) {
            int bl = w->level >= 5 ? 9 : w->level <= 1 ? 1 : 2 * w->level - 1;
            if (!(w->bz = gz_bzip2_enc_new(bl))) return GZ_E_NOMEM;
        }
        return gz_bzip2_encode(w->bz, &io);
    case M_DEFLATE:
        if (!w->df) {
            /* 7-Zip's Deflate parses optimally from level 5 on: so do ours from 7 */
            static const u8 dl[10] = { 0, 3, 3, 4, 6, 9, 9, 9, 9, 9 };
            if (!(w->df = gz_deflate_enc_new(dl[w->level]))) return GZ_E_NOMEM;
        }
        return gz_deflate_encode(w->df, &io, 0, 0, 0);
    }
    return GZ_E_METHOD;
}

/* ---------------- folders ---------------- */

static int add_folder(szw *w, const sz_folder *fo)
{
    if (w->nf == w->fcap) {
        u32 nc = w->fcap ? w->fcap * 2 : 64;
        sz_folder *nf = (sz_folder *)gz_realloc(w->f, (size_t)nc * sizeof(sz_folder));
        if (!nf) return GZ_E_NOMEM;
        w->f = nf;
        w->fcap = nc;
    }
    w->f[w->nf++] = *fo;
    return GZ_OK;
}

/* compress w->order[first .. first + count) into one folder (none if no data came) */
static int run_folder(szw *w, u32 first, u32 count, int filter, int auto_filter, u64 hint)
{
    fctx f;
    sz_folder fo;
    int r;
    __builtin_memset(&f, 0, sizeof f);
    __builtin_memset(&fo, 0, sizeof fo);
    f.w = w;
    f.list = w->order + first;
    f.n = count;
    f.filter = filter;
    f.auto_filter = auto_filter;
    f.folder = w->nf;
    gz_bcj_init(&f.bcj, k_bcj[filter], 0, 1);
    fo.first = first;
    fo.count = count;
    fo.method = (u8)w->method;

    while (f.s_end == f.s_beg && !f.eof)        /* data at all? (files may be gone or empty) */
        if ((r = stage_more(&f)) != GZ_OK) goto out;
    r = GZ_OK;
    if (f.s_end == f.s_beg) goto out;
    if (w->enc && (r = aes_start(&f, &fo)) != GZ_OK) goto out;
    r = run_coder(&f, &fo, hint);
    if (!r && !f.eof) r = GZ_E_DATA;           /* a coder stopped before its input ended */
    if (!r && f.aes) r = aes_finish(&f);
    if (!r) {
        fo.filter = (u8)f.filter;
        fo.unpack = f.fed;
        fo.coder_out = f.coder_out;
        fo.packed = f.packed;
        r = add_folder(w, &fo);
    }
out:
    if (f.cur) {                                /* aborted while a file was open */
        if (f.src) w->o->close_item(w->o->user, &w->items[f.cur - w->e], f.src);
        f.cur->state = S_SKIPPED;
    }
    return r;
}

static int run_nonsolid(szw *w)
{
    for (u32 i = 0; i < w->n; i++) {
        sz_item *e = &w->e[i];
        if (e->kind != K_FILE && e->kind != K_LINK) continue;
        if (w_cancelled(w)) return GZ_E_CANCEL;
        u32 first = w->norder;
        w->order[w->norder++] = i;
        int r = run_folder(w, first, 1, F_NONE, w->filters && e->kind == K_FILE, e->size);
        if (r) return r;
    }
    return GZ_OK;
}

/* Filter groups first, plain files last: an executable-looking file that turns
 * out to be a script (the common surprise) still joins the plain group. */
static const u8 k_gorder[F_COUNT] = { F_HOST, F_X86 + F_ARM64 - F_HOST, F_NONE };

static int run_solid(szw *w)
{
    for (int phase = 0; phase < 2; phase++)
        for (int gi = 0; gi < F_COUNT; gi++) {
            int g = k_gorder[gi];
            u32 *hd = phase ? &w->lhead[g] : &w->head[g];
            if (!phase) w->started[g] = 1;
            while (*hd != NIL) {
                u32 first = w->norder, cnt = 0, i = *hd;
                u64 bytes = 0;
                if (w_cancelled(w)) return GZ_E_CANCEL;
                while (i != NIL && cnt < SOLID_FILES) {
                    u64 s = w->e[i].size;
                    if (cnt && (bytes + s > w->solid_limit || bytes + s < bytes)) break;
                    w->order[w->norder++] = i;
                    cnt++;
                    bytes += s;
                    i = w->e[i].next;
                }
                *hd = i;
                int r = run_folder(w, first, cnt, g, 0, bytes);
                if (r) return r;
            }
        }
    return GZ_OK;
}

/* ---------------- planning ---------------- */

static u32 make_attr(const gz_witem *it, int kind)
{
    u32 a = it->attr & 0x7FFFu;             /* 0x8000 and the high half are the unix extension */
    u32 mode = it->unix_mode & 0xFFFFu;
    if (kind == K_DIR) a |= 0x10;
    else a &= ~0x10u;
    if (kind == K_LINK) {
        a &= ~0x400u;                       /* reparse point: here the target is the data */
        mode = 0120000u | ((mode & 07777u) ? (mode & 07777u) : 0777u);
    } else if (mode) {
        mode = (kind == K_DIR ? 0040000u : 0100000u) | (mode & 07777u);
    }
    if (kind != K_DIR && !a) a = 0x20;      /* FILE_ATTRIBUTE_ARCHIVE, as p7zip writes */
    if (mode) a |= 0x8000u | (mode << 16);
    return a;
}

static int prepare(szw *w, ext_tab *xt)
{
    for (u32 i = 0; i < w->n; i++) {
        const gz_witem *it = &w->items[i];
        sz_item *e = &w->e[i];
        const gzch *s = it->name;
        e->next = NIL;
        e->state = S_SKIPPED;
        if (!s) continue;
        while (*s == '/') s++;
        while (s[0] == '.' && s[1] == '/') { s += 2; while (*s == '/') s++; }
        size_t n = gz_wcslen(s);
        while (n && s[n - 1] == '/') n--;
        if (!n || (n == 1 && s[0] == '.')) continue;
        if (n > (1u << 20)) return GZ_E_LIMIT;
        e->state = S_PLAN;
        e->name = s;
        e->nlen = (u32)n;
        u32 b = e->nlen, d;
        while (b && s[b - 1] != '/') b--;
        for (d = e->nlen; d > b && s[d - 1] != '.'; d--) {}
        e->base = b;
        e->ext = d > b ? d : e->nlen;

        int link = it->is_link && it->link_target && it->link_target[0];
        if (link) {
            size_t tn = gz_wcslen(it->link_target);
            if (tn > (1u << 20)) return GZ_E_LIMIT;
            e->kind = K_LINK;
            e->size = w2u(it->link_target, tn, 0);
        } else if (it->is_dir) {
            e->kind = K_DIR;
        } else {                            /* empty files too: they may have grown, or be unreadable */
            e->kind = K_FILE;
            e->size = it->size;
        }
        e->attr = make_attr(it, e->kind);
        if (e->kind == K_FILE || e->kind == K_LINK) {
            w->total += e->size;
            if (xt) e->ext_idx = ext_index(xt, e);
        }
        if (e->kind == K_FILE && w->filters) {
            e->winexe = (u8)ext_in(e, "exe dll sys ocx cpl scr drv efi");
            int unixbin = ext_in(e, "so o ko dylib");
            for (u32 k = e->base; !unixbin && k + 4 <= e->nlen; k++)     /* libfoo.so.1.2 */
                unixbin = s[k] == '.' && s[k + 1] == 's' && s[k + 2] == 'o' && s[k + 3] == '.';
            e->cand = (u8)(e->winexe || e->size >= EXE_MIN);
            if (e->winexe) e->filter = F_X86;
            else if (e->cand && (unixbin || (e->ext == e->nlen && (it->unix_mode & 0111)))) e->filter = F_HOST;
            else e->filter = F_NONE;
        }
    }
    return GZ_OK;
}

static int plan_solid(szw *w, u32 ndata)
{
    u32 *a = (u32 *)gz_alloc((size_t)ndata * 2 * sizeof(u32) + 4);
    if (!a) return GZ_E_NOMEM;
    u32 k = 0;
    for (u32 i = 0; i < w->n; i++)
        if (w->e[i].state == S_PLAN && (w->e[i].kind == K_FILE || w->e[i].kind == K_LINK)) a[k++] = i;
    sort_items(w, a, a + ndata, k);
    for (u32 j = 0; j < k; j++) {
        u32 i = a[j], g = w->e[i].filter;
        if (w->head[g] == NIL) w->head[g] = i;
        else w->e[w->tail[g]].next = i;
        w->tail[g] = i;
    }
    gz_free(a);
    return GZ_OK;
}

/* ---------------- header ---------------- */

static void put_bits_first(hbuf *h, u32 n, u32 ones)       /* n bits, the first `ones` set */
{
    u8 *p = hb_need(h, (n + 7) / 8);
    if (!p) return;
    __builtin_memset(p, 0, (n + 7) / 8);
    for (u32 i = 0; i < ones; i++) p[i >> 3] |= (u8)(0x80 >> (i & 7));
}

static void put_times(hbuf *h, const szw *w, const u32 *ord, u32 m, int which, u8 nid)
{
    u32 nd = 0;
    for (u32 j = 0; j < m; j++) {
        const gz_witem *it = &w->items[ord[j]];
        nd += (which == 0 ? it->ctime : which == 1 ? it->atime : it->mtime) != 0;
    }
    if (!nd) return;
    u32 bv = nd == m ? 0 : (m + 7) / 8;
    hb_byte(h, nid);
    hb_num(h, (u64)nd * 8 + bv + 2);
    hb_byte(h, nd == m);
    if (bv) {
        u8 *p = hb_need(h, bv);
        if (p) {
            __builtin_memset(p, 0, bv);
            for (u32 j = 0; j < m; j++) {
                const gz_witem *it = &w->items[ord[j]];
                if ((which == 0 ? it->ctime : which == 1 ? it->atime : it->mtime) != 0)
                    p[j >> 3] |= (u8)(0x80 >> (j & 7));
            }
        }
    }
    hb_byte(h, 0);                          /* not external */
    for (u32 j = 0; j < m; j++) {
        const gz_witem *it = &w->items[ord[j]];
        u64 t = which == 0 ? it->ctime : which == 1 ? it->atime : it->mtime;
        if (t) hb_u64(h, t);
    }
}

static int build_header(szw *w, hbuf *h, u32 *nfiles)
{
    u32 m = 0, nempty = 0, nefile = 0, multi = 0, notone = 0;
    u32 *ord = (u32 *)gz_alloc((size_t)w->n * sizeof(u32) + 4);
    if (!ord) return GZ_E_NOMEM;
    for (u32 i = 0; i < w->n; i++) {         /* directories and empty files first */
        sz_item *e = &w->e[i];
        if (e->state == S_SKIPPED) continue;
        if (e->kind == K_DIR || e->state == S_EMPTIED) {
            ord[m++] = i;
            nempty++;
            nefile += e->kind != K_DIR;
        }
    }
    for (u32 k = 0; k < w->nf; k++) {        /* then the files in folder order */
        sz_folder *fo = &w->f[k];
        fo->nsub = 0;
        for (u32 j = 0; j < fo->count; j++) {
            u32 i = w->order[fo->first + j];
            if (w->e[i].state == S_STORED && w->e[i].folder == k) { ord[m++] = i; fo->nsub++; }
        }
        multi |= fo->nsub > 1;
        notone |= fo->nsub != 1;
    }
    *nfiles = m;
    if (!m) { gz_free(ord); return GZ_OK; }

    hb_byte(h, kHeader);
    if (w->nf) {
        hb_byte(h, kMainStreamsInfo);
        hb_byte(h, kPackInfo);
        hb_num(h, 0);
        hb_num(h, w->nf);
        hb_byte(h, kSize);
        for (u32 k = 0; k < w->nf; k++) hb_num(h, w->f[k].packed);
        hb_byte(h, kEnd);
        hb_byte(h, kUnPackInfo);
        hb_byte(h, kFolder);
        hb_num(h, w->nf);
        hb_byte(h, 0);
        for (u32 k = 0; k < w->nf; k++) put_folder(h, &w->f[k]);
        hb_byte(h, kCodersUnPackSize);
        for (u32 k = 0; k < w->nf; k++) put_unpack_sizes(h, &w->f[k]);
        hb_byte(h, kEnd);
        hb_byte(h, kSubStreamsInfo);
        if (notone) {
            hb_byte(h, kNumUnPackStream);
            for (u32 k = 0; k < w->nf; k++) hb_num(h, w->f[k].nsub);
        }
        u32 j = nempty;
        if (multi) {
            hb_byte(h, kSize);
            for (u32 k = 0; k < w->nf; k++) {
                for (u32 s = 0; s + 1 < w->f[k].nsub; s++) hb_num(h, w->e[ord[j + s]].size);
                j += w->f[k].nsub;
            }
        }
        hb_byte(h, kCRC);
        hb_byte(h, 1);                      /* all defined */
        for (j = nempty; j < m; j++) hb_u32(h, w->e[ord[j]].crc);
        hb_byte(h, kEnd);
        hb_byte(h, kEnd);
    }

    hb_byte(h, kFilesInfo);
    hb_num(h, m);
    if (nempty) {
        hb_byte(h, kEmptyStream);
        hb_num(h, (m + 7) / 8);
        put_bits_first(h, m, nempty);
        if (nefile) {
            hb_byte(h, kEmptyFile);
            hb_num(h, (nempty + 7) / 8);
            u8 *p = hb_need(h, (nempty + 7) / 8);
            if (p) {
                __builtin_memset(p, 0, (nempty + 7) / 8);
                for (u32 j = 0; j < nempty; j++)
                    if (w->e[ord[j]].kind != K_DIR) p[j >> 3] |= (u8)(0x80 >> (j & 7));
            }
        }
    }
    u64 nb = 1;
    for (u32 j = 0; j < m; j++) nb += ((u64)w->e[ord[j]].nlen + 1) * 2;
    if (nb > HDR_MAX) h->err = GZ_E_LIMIT;
    hb_byte(h, kName);
    hb_num(h, nb);
    hb_byte(h, 0);
    for (u32 j = 0; j < m && !h->err; j++) {
        const sz_item *e = &w->e[ord[j]];
        u8 *p = hb_need(h, ((size_t)e->nlen + 1) * 2);
        if (!p) break;
        for (u32 i = 0; i < e->nlen; i++) wr16(p + 2 * i, e->name[i]);
        wr16(p + 2 * e->nlen, 0);
    }
    put_times(h, w, ord, m, 0, kCTime);
    put_times(h, w, ord, m, 1, kATime);
    put_times(h, w, ord, m, 2, kMTime);
    hb_byte(h, kWinAttributes);
    hb_num(h, (u64)m * 4 + 2);
    hb_byte(h, 1);
    hb_byte(h, 0);
    for (u32 j = 0; j < m; j++) hb_u32(h, w->e[ord[j]].attr);
    hb_byte(h, kEnd);
    hb_byte(h, kEnd);
    gz_free(ord);
    return h->err;
}

/* write the header (LZMA + optional 7zAES, or plain when that is not larger);
 * returns the next-header offset / size / CRC for the signature header */
static int write_header(szw *w, const u8 *hp, size_t hn, u64 *nho, u64 *nhs, u32 *nhcrc)
{
    gz_mem_sink ms;
    fctx f;
    sz_folder fo;
    hbuf d;
    int r;
    __builtin_memset(&ms, 0, sizeof ms);
    __builtin_memset(&f, 0, sizeof f);
    __builtin_memset(&fo, 0, sizeof fo);
    __builtin_memset(&d, 0, sizeof d);
    ms.limit = HDR_MAX;
    f.w = w;
    f.raw = 1;
    f.mp = hp;
    f.mn = hn;
    f.ms = &ms;
    fo.method = M_LZMA;
    u32 hcrc = gz_crc32(0, hp, hn);
    int enc = w->enc && w->o->encrypt_names;
    r = enc ? aes_start(&f, &fo) : GZ_OK;
    if (!r) {
        gz_lzma_enc_opts op;
        gz_lzma_enc_opts_init(&op, 5);
        op.dict_size = 1u << 20;            /* as 7-Zip: LZMA, 1 MiB, long matches */
        op.nice_len = 64;
        op.size_hint = hn;
        gz_lzma_enc *e = gz_lzma_enc_new(&op);
        gz_stream_io io = { f_read, f_write, &f };
        r = e ? gz_lzma_encode(e, &io, fo.props, 0) : GZ_E_NOMEM;
        fo.nprops = 5;
        gz_lzma_enc_free(e);
    }
    if (!r && f.aes) r = aes_finish(&f);
    if (!r && f.fed != hn) r = GZ_E_DATA;
    if (r) goto out;
    fo.unpack = hn;
    fo.coder_out = f.coder_out;
    fo.packed = f.packed;
    u64 pack_pos = w->out->pos - w->base - 32;
    hb_byte(&d, kEncodedHeader);
    hb_byte(&d, kPackInfo);
    hb_num(&d, pack_pos);
    hb_num(&d, 1);
    hb_byte(&d, kSize);
    hb_num(&d, fo.packed);
    hb_byte(&d, kEnd);
    hb_byte(&d, kUnPackInfo);
    hb_byte(&d, kFolder);
    hb_num(&d, 1);
    hb_byte(&d, 0);
    put_folder(&d, &fo);
    hb_byte(&d, kCodersUnPackSize);
    put_unpack_sizes(&d, &fo);
    hb_byte(&d, kCRC);
    hb_byte(&d, 1);
    hb_u32(&d, hcrc);
    hb_byte(&d, kEnd);
    hb_byte(&d, kEnd);
    if ((r = d.err) != GZ_OK) goto out;
    if (!enc && ms.n + d.n >= hn) {          /* tiny header: plain is smaller */
        *nho = w->out->pos - w->base - 32;
        *nhs = hn;
        *nhcrc = hcrc;
        r = gz_sink_write(w->out, hp, hn);
    } else {
        r = gz_sink_write(w->out, ms.p, ms.n);
        *nho = w->out->pos - w->base - 32;
        *nhs = d.n;
        *nhcrc = gz_crc32(0, d.p, d.n);
        if (!r) r = gz_sink_write(w->out, d.p, d.n);
    }
out:
    gz_mem_sink_free(&ms);
    gz_free(d.p);
    return r;
}

static void sig_header(u8 sh[32], u64 nho, u64 nhs, u32 nhcrc)
{
    static const u8 sig[6] = { '7', 'z', 0xBC, 0xAF, 0x27, 0x1C };
    __builtin_memset(sh, 0, 32);
    __builtin_memcpy(sh, sig, 6);
    sh[7] = 4;                              /* format version 0.4 */
    wr64(sh + 12, nho);
    wr64(sh + 20, nhs);
    wr32(sh + 28, nhcrc);
    wr32(sh + 8, gz_crc32(0, sh + 12, 20));
}

/* ---------------- entry point ---------------- */

static int setup(szw *w, const gz_wopts *o)
{
    static const u8 k_dict_log[10] = { 18, 18, 20, 22, 23, 24, 25, 25, 26, 26 };   /* 7-Zip's per level */
    int level = o->level < 0 ? 5 : o->level > 9 ? 9 : o->level;
    int m = o->method;
    w->level = level;
    if (m == GZ_WM_DEFAULT) m = level == 0 ? GZ_WM_STORE : GZ_WM_LZMA2;
    switch (m) {
    case GZ_WM_STORE:   w->method = M_COPY; break;
    case GZ_WM_LZMA2:   w->method = M_LZMA2; break;
    case GZ_WM_LZMA:    w->method = M_LZMA; break;
    case GZ_WM_PPMD:    w->method = M_PPMD; break;
    case GZ_WM_BZIP2:   w->method = M_BZIP2; break;
    case GZ_WM_DEFLATE: w->method = M_DEFLATE; break;
    default: return GZ_E_METHOD;
    }
    w->filters = w->method != M_COPY;
    u64 dict;
    gz_lzma_enc_opts_init(&w->lo, level == 1 ? 2 : level);  /* level 1: long matches pay off */
    w->lo.dict_size = 1u << k_dict_log[level];
    if (o->dict_size) {
        u32 d = o->dict_size < 4096 ? 4096 : o->dict_size > GZ_LZMA_DICT_MAX ? GZ_LZMA_DICT_MAX : o->dict_size;
        w->lo.dict_size = d;
        w->ppmd_mem = o->dict_size < (1u << 16) ? (1u << 16) :
                      o->dict_size > GZ_PPMD_MEM_CAP ? GZ_PPMD_MEM_CAP : o->dict_size;
    }
    switch (w->method) {
    case M_PPMD: {
        u32 order, mem;
        gz_ppmd7z_level(level, GZ_SIZE_UNKNOWN, &order, &mem);
        dict = w->ppmd_mem ? w->ppmd_mem : mem;
        break;
    }
    case M_BZIP2:   dict = 900000; break;
    case M_DEFLATE: dict = 32768; break;
    default:        dict = w->lo.dict_size; break;
    }
    w->solid_limit = dict << 7;
    if (w->solid_limit < SOLID_MIN) w->solid_limit = SOLID_MIN;
    if (w->solid_limit > SOLID_MAX) w->solid_limit = SOLID_MAX;

    if (o->encryption != GZ_WE_NONE) {
        if (o->encryption != GZ_WE_AES256) return GZ_E_METHOD;
        if (!o->password || !o->password[0]) return GZ_E_PASSWORD;
        size_t pn = gz_wcslen(o->password);
        if (pn > 4096) return GZ_E_LIMIT;
        u8 *pw = (u8 *)gz_alloc(pn * 2);
        u8 key[32];
        if (!pw) return GZ_E_NOMEM;
        for (size_t i = 0; i < pn; i++) wr16(pw + 2 * i, o->password[i]);   /* UTF-16LE */
        int r = gz_7z_kdf(0, 0, pw, pn * 2, KDF_POWER, key);
        __builtin_memset(pw, 0, pn * 2);
        gz_free(pw);
        if (!r) r = gz_aes_set_encrypt_key(&w->aes, key, 32);
        __builtin_memset(key, 0, sizeof key);
        if (r) return r;
        w->enc = 1;
        if (!(w->abuf = (u8 *)gz_alloc(ABUF))) return GZ_E_NOMEM;
    }
    return GZ_OK;
}

static int sz_write(const gz_wopts *o, const gz_witem *items, u32 n, gz_sink *out, gz_ctx *c)
{
    if (!out->write_at) return GZ_E_METHOD;   /* the signature header is patched at the end */
    szw *w = (szw *)gz_alloc(sizeof(szw));
    ext_tab *xt = 0;
    hbuf h;
    int r;
    if (!w) return GZ_E_NOMEM;
    __builtin_memset(&h, 0, sizeof h);
    w->o = o;
    w->items = items;
    w->out = out;
    w->c = c;
    w->n = n;
    for (int g = 0; g < F_COUNT; g++) w->head[g] = w->tail[g] = w->lhead[g] = w->ltail[g] = NIL;
    if ((r = setup(w, o)) != GZ_OK) goto done;
    if ((u64)n * 2 * sizeof(u32) > (~(size_t)0 >> 2) || (u64)n * sizeof(sz_item) > (~(size_t)0 >> 2)) {
        r = GZ_E_LIMIT;
        goto done;
    }
    w->e = (sz_item *)gz_alloc((size_t)n * sizeof(sz_item) + 1);
    w->stage = (u8 *)gz_alloc(STAGE);
    int solid = o->solid && w->method != M_COPY;
    if (solid) xt = (ext_tab *)gz_alloc(sizeof(ext_tab));
    if (!w->e || !w->stage || (solid && !xt)) { r = GZ_E_NOMEM; goto done; }
    if (xt) ext_build(xt);
    if ((r = prepare(w, xt)) != GZ_OK) goto done;
    u32 ndata = 0;
    for (u32 i = 0; i < n; i++) ndata += w->e[i].state == S_PLAN && (w->e[i].kind == K_FILE || w->e[i].kind == K_LINK);
    w->order = (u32 *)gz_alloc((size_t)ndata * 2 * sizeof(u32) + 4);   /* deferred files appear twice */
    if (!w->order) { r = GZ_E_NOMEM; goto done; }
    if (solid && (r = plan_solid(w, ndata)) != GZ_OK) goto done;

    u8 sh[32];
    w->base = out->pos;
    sig_header(sh, 0, 0, 0);
    __builtin_memset(sh + 8, 0, 24);        /* placeholder: no start header CRC yet */
    if ((r = gz_sink_write(out, sh, 32)) != GZ_OK) goto done;
    r = solid ? run_solid(w) : run_nonsolid(w);
    if (r) goto done;
    if (w_cancelled(w)) { r = GZ_E_CANCEL; goto done; }

    u32 nfiles = 0;
    u64 nho = 0, nhs = 0;
    u32 nhcrc = 0;
    if ((r = build_header(w, &h, &nfiles)) != GZ_OK) goto done;
    if (nfiles && (r = write_header(w, h.p, h.n, &nho, &nhs, &nhcrc)) != GZ_OK) goto done;
    sig_header(sh, nho, nhs, nhcrc);
    r = gz_sink_patch(out, w->base, sh, 32);
    if (!r && o->progress) o->progress(o->user, w->done, w->done > w->total ? w->done : w->total);
done:
    gz_free(h.p);
    gz_free(xt);
    gz_lzma_enc_free(w->lz);
    if (w->pp) gz_ppmd7_free(w->pp);
    if (w->bz) gz_bzip2_enc_free(w->bz);
    if (w->df) gz_deflate_enc_free(w->df);
    __builtin_memset(&w->aes, 0, sizeof w->aes);
    gz_free(w->e);
    gz_free(w->order);
    gz_free(w->f);
    gz_free(w->stage);
    gz_free(w->abuf);
    gz_free(w->lb);
    gz_free(w);
    return r;
}

GZ_WRITER(gz_wr_7z)
const gz_writer gz_wr_7z = {
    GZ_WF_7Z, "7z", "7z",
    (1u << GZ_WM_DEFAULT) | (1u << GZ_WM_STORE) | (1u << GZ_WM_DEFLATE) | (1u << GZ_WM_BZIP2) |
        (1u << GZ_WM_LZMA) | (1u << GZ_WM_LZMA2) | (1u << GZ_WM_PPMD),
    1u << GZ_WE_AES256,
    sz_write
};
