/*
 * 고깃ZIP - XAR archives (.xar, macOS .pkg installers, .xip) and pbzx streams
 *
 * XAR: 28+ byte big-endian header ("xar!", header size, version, compressed
 * and uncompressed TOC sizes, checksum algorithm), a zlib-compressed XML table
 * of contents, then the heap. The TOC is a tree of <file> elements:
 *   <file id="N"><name [enctype="base64"]>..</name><type [link=..]>file|
 *   directory|symlink|hardlink</type><link>target</link><mode>0644</mode>
 *   <mtime>2020-01-02T03:04:05Z</mtime><data><length/><offset/><size/>
 *   <encoding style="application/x-gzip"/><extracted-checksum style="sha1">hex
 *   </extracted-checksum></data> ...child <file> elements...</file>
 * Data lives at heap + offset (length bytes, size bytes once decoded) and is
 * stored, zlib, bzip2, xz or lzma (the last two through the registered stream
 * formats). SHA-1 / SHA-256 checksums of the TOC and of every file are checked.
 * Inside .pkg files, Payload / Scripts are cpio archives compressed with gzip
 * or pbzx (opened as nested archives through the stream formats + cpio).
 *
 * pbzx: "pbzx", u64 chunk size, then chunks { u64 flags/size, u64 length,
 * data }: an xz stream, or raw bytes. Bit 24 of the flags announces more chunks.
 */
#include "cpio.h"
#include "crypto.h"
#include "bzip2.h"

#define XAR_TOC_MAX   (256u << 20)   /* uncompressed TOC                       */
#define XAR_DEPTH_MAX 512u           /* XML element nesting                    */
#define XAR_PATH_MAX  16384u         /* full path of an entry                  */
#define XAR_NODES_MAX (1u << 21)     /* <file> elements                        */

enum { EN_NONE = 0, EN_ZLIB, EN_BZIP2, EN_XZ, EN_LZMA, EN_OTHER };
enum { CK_NONE = 0, CK_SHA1, CK_SHA256 };
enum { FT_NONE = 0, FT_FILE, FT_DIR, FT_SYMLINK, FT_HARDLINK, FT_OTHER };
enum { NF_DATA = 1, NF_SIZE = 2, NF_MODE = 4, NF_MTIME = 8, NF_BADPATH = 16, NF_LENGTH = 32, NF_OFFSET = 64 };
enum { X_OTHER = 0, X_XAR, X_TOC, X_FILE, X_NAME, X_TYPE, X_DATA, X_LENGTH, X_OFFSET, X_SIZE,
       X_ENCODING, X_EXCK, X_CHECKSUM, X_MODE, X_MTIME, X_LINK };

typedef struct {
    i32 parent;                   /* enclosing <file> node, -1 = top level   */
    u32 id, ref;                  /* hardlink: id of the original (0 = none) */
    u32 name_off, name_len;       /* decoded name in the scratch buffer      */
    u32 link_off, link_len;       /* decoded symlink target                  */
    u32 ck_off;                   /* hex digest text in the TOC              */
    u16 ck_len;
    u8 type, enc, ck, flags;
    u32 mode;
    i64 mtime;
    u64 length, offset, size;
    u32 path_off, path_len;       /* full path in a->raw                     */
} xnode;

typedef struct { u8 tag, b64; i32 node; u32 text; } xlevel;

typedef struct {
    const u8 *x;
    size_t n;
    xlevel *st;
    u32 depth;
    xnode *nd;
    u32 nn, ncap;
    u8 *scr;
    size_t sn, scap;
    u64 ck_off, ck_size;          /* TOC checksum location in the heap */
    u8 ck_style;
} xparse;

typedef struct { u8 ck; u8 digest[32]; } xent;
typedef struct { xent *x; } xar_priv;

/* ---------------- small text helpers ---------------- */

static int is_ws(u8 c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }
static int is_namec(u8 c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '-' || c == '_' || c == ':' || c == '.' || c >= 0x80;
}

static int eq(const u8 *p, size_t n, const char *z)
{
    size_t i = 0;
    for (; i < n && z[i]; i++) if (p[i] != (u8)z[i]) return 0;
    return i == n && !z[i];
}

static void trim(const u8 **p, size_t *n)
{
    while (*n && is_ws(**p)) { (*p)++; (*n)--; }
    while (*n && is_ws((*p)[*n - 1])) (*n)--;
}

/* unsigned number in base 8 or 10; *ok = 0 on junk or overflow */
static u64 num(const u8 *p, size_t n, u32 base, int *ok)
{
    trim(&p, &n);
    u64 v = 0;
    if (!n) *ok = 0;
    for (size_t i = 0; i < n; i++) {
        u32 d = (u32)p[i] - '0';
        if (d >= base || v > (~(u64)0 - d) / base) { *ok = 0; return 0; }
        v = v * base + d;
    }
    return v;
}

static u8 tag_id(const u8 *p, size_t n)
{
    static const struct { const char *s; u8 id; } t[] = {
        { "file", X_FILE }, { "name", X_NAME }, { "type", X_TYPE }, { "data", X_DATA },
        { "length", X_LENGTH }, { "offset", X_OFFSET }, { "size", X_SIZE }, { "encoding", X_ENCODING },
        { "extracted-checksum", X_EXCK }, { "checksum", X_CHECKSUM }, { "mode", X_MODE },
        { "mtime", X_MTIME }, { "link", X_LINK }, { "toc", X_TOC }, { "xar", X_XAR },
    };
    for (u32 i = 0; i < GZ_COUNTOF(t); i++) if (eq(p, n, t[i].s)) return t[i].id;
    return X_OTHER;
}

static u8 enc_of(const u8 *v, size_t n)
{
    if (eq(v, n, "application/octet-stream")) return EN_NONE;
    if (eq(v, n, "application/x-gzip") || eq(v, n, "application/zlib")) return EN_ZLIB;
    if (eq(v, n, "application/x-bzip2")) return EN_BZIP2;
    if (eq(v, n, "application/x-xz")) return EN_XZ;
    if (eq(v, n, "application/x-lzma")) return EN_LZMA;
    return EN_OTHER;
}

static u8 ck_of(const u8 *v, size_t n)
{
    return eq(v, n, "sha1") ? CK_SHA1 : eq(v, n, "sha256") ? CK_SHA256 : CK_NONE;
}

static u32 ck_len(u8 ck) { return ck == CK_SHA1 ? 20 : ck == CK_SHA256 ? 32 : 0; }

static void put_utf8(u8 *o, size_t *k, u32 cp)
{
    if (cp < 0x80) o[(*k)++] = (u8)cp;
    else if (cp < 0x800) { o[(*k)++] = (u8)(0xC0 | cp >> 6); o[(*k)++] = (u8)(0x80 | (cp & 63)); }
    else if (cp < 0x10000) {
        o[(*k)++] = (u8)(0xE0 | cp >> 12); o[(*k)++] = (u8)(0x80 | (cp >> 6 & 63)); o[(*k)++] = (u8)(0x80 | (cp & 63));
    } else {
        o[(*k)++] = (u8)(0xF0 | cp >> 18); o[(*k)++] = (u8)(0x80 | (cp >> 12 & 63));
        o[(*k)++] = (u8)(0x80 | (cp >> 6 & 63)); o[(*k)++] = (u8)(0x80 | (cp & 63));
    }
}

/* XML character data -> UTF-8 (never longer than the input) */
static size_t unescape(const u8 *s, size_t n, u8 *o)
{
    size_t k = 0;
    for (size_t i = 0; i < n;) {
        if (s[i] != '&') { o[k++] = s[i++]; continue; }
        size_t j = i + 1;
        while (j < n && j - i < 12 && s[j] != ';') j++;
        u32 cp = 0;
        int ok = j < n && s[j] == ';';
        const u8 *e = s + i + 1;
        size_t en = j - i - 1;
        if (!ok) {
        } else if (eq(e, en, "lt")) cp = '<';
        else if (eq(e, en, "gt")) cp = '>';
        else if (eq(e, en, "amp")) cp = '&';
        else if (eq(e, en, "quot")) cp = '"';
        else if (eq(e, en, "apos")) cp = '\'';
        else if (en > 1 && e[0] == '#') {
            int hex = e[1] == 'x' || e[1] == 'X';
            size_t d0 = hex ? 2 : 1;
            ok = en > d0;
            for (size_t q = d0; q < en && ok; q++) {
                u32 c = e[q], d;
                if (c - '0' < 10) d = c - '0';
                else if (hex && (c | 0x20) - 'a' < 6) d = (c | 0x20) - 'a' + 10;
                else { ok = 0; break; }
                cp = cp * (hex ? 16 : 10) + d;
                if (cp > 0x10FFFF) ok = 0;
            }
            if (!cp || (cp >= 0xD800 && cp <= 0xDFFF)) ok = 0;
        } else ok = 0;
        if (!ok) { o[k++] = s[i++]; continue; }
        put_utf8(o, &k, cp);
        i = j + 1;
    }
    return k;
}

static size_t base64(const u8 *s, size_t n, u8 *o)
{
    u32 acc = 0, bits = 0;
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        u32 c = s[i], v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+') v = 62;
        else if (c == '/') v = 63;
        else if (c == '=') break;
        else continue;                         /* whitespace */
        acc = acc << 6 | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; o[k++] = (u8)(acc >> bits); }
    }
    return k;
}

static i64 days_from_civil(i64 y, int m, int d)
{
    y -= m <= 2;
    i64 era = (y >= 0 ? y : y - 399) / 400;
    i64 yoe = y - era * 400;
    i64 doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    i64 doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* "YYYY-MM-DDTHH:MM:SS[.frac][Z|+hh:mm]" -> unix time */
static int iso_time(const u8 *p, size_t n, i64 *t)
{
    trim(&p, &n);
    u32 v[6];
    static const u8 len[6] = { 4, 2, 2, 2, 2, 2 };
    static const char sep[6] = { '-', '-', 'T', ':', ':', 0 };
    size_t i = 0;
    for (int f = 0; f < 6; f++) {
        v[f] = 0;
        for (u32 k = 0; k < len[f]; k++, i++) {
            if (i >= n || p[i] < '0' || p[i] > '9') return 0;
            v[f] = v[f] * 10 + (u32)(p[i] - '0');
        }
        if (sep[f]) {
            if (i >= n || (p[i] != (u8)sep[f] && !(f == 2 && p[i] == ' '))) return 0;
            i++;
        }
    }
    if (v[1] < 1 || v[1] > 12 || v[2] < 1 || v[2] > 31 || v[3] > 23 || v[4] > 59 || v[5] > 60) return 0;
    i64 s = days_from_civil(v[0], (int)v[1], (int)v[2]) * 86400 + v[3] * 3600 + v[4] * 60 + v[5];
    if (i < n && p[i] == '.') { i++; while (i < n && p[i] >= '0' && p[i] <= '9') i++; }
    if (i + 6 <= n && (p[i] == '+' || p[i] == '-') && p[i + 3] == ':') {
        i64 off = ((p[i + 1] - '0') * 10 + (p[i + 2] - '0')) * 3600 + ((p[i + 4] - '0') * 10 + (p[i + 5] - '0')) * 60;
        s += p[i] == '+' ? -off : off;
    }
    *t = s;
    return 1;
}

/* ---------------- TOC parser ---------------- */

static int scr_put(xparse *p, const u8 *s, size_t n, int b64, u32 *off, u32 *len)
{
    if (p->sn + n > p->scap) {
        size_t nc = p->scap ? p->scap : 65536;
        while (nc < p->sn + n) nc *= 2;
        if (nc > (size_t)XAR_TOC_MAX * 2) return GZ_E_LIMIT;
        u8 *ns = (u8 *)gz_realloc(p->scr, nc);
        if (!ns) return GZ_E_NOMEM;
        p->scr = ns;
        p->scap = nc;
    }
    size_t k = b64 ? base64(s, n, p->scr + p->sn) : unescape(s, n, p->scr + p->sn);
    *off = (u32)p->sn;
    *len = (u32)k;
    p->sn += k;
    return GZ_OK;
}

/* <file> node of the level `up` levels above the innermost one, NULL if that is no file */
static xnode *file_at(xparse *p, u32 up)
{
    if (p->depth < up + 1) return 0;
    const xlevel *L = &p->st[p->depth - 1 - up];
    return L->tag == X_FILE && L->node >= 0 ? &p->nd[L->node] : 0;
}

static u8 tag_at(xparse *p, u32 up) { return p->depth >= up + 1 ? p->st[p->depth - 1 - up].tag : X_OTHER; }

/* file node owning the innermost <data> child element (…/file/data/x) */
static xnode *data_node(xparse *p) { return tag_at(p, 1) == X_DATA ? file_at(p, 2) : 0; }

static int on_open(xparse *p, u8 tg)
{
    if (p->depth >= XAR_DEPTH_MAX) return GZ_E_LIMIT;
    xlevel *L = &p->st[p->depth];
    L->tag = tg;
    L->b64 = 0;
    L->node = -1;
    L->text = 0;
    u8 pt = tag_at(p, 0);
    if (tg == X_FILE && (pt == X_TOC || (pt == X_FILE && p->st[p->depth - 1].node >= 0))) {
        if (p->nn == p->ncap) {
            if (p->ncap >= XAR_NODES_MAX) return GZ_E_LIMIT;
            u32 nc = p->ncap ? p->ncap * 2 : 256;
            xnode *nn = (xnode *)gz_realloc(p->nd, (size_t)nc * sizeof(xnode));
            if (!nn) return GZ_E_NOMEM;
            p->nd = nn;
            p->ncap = nc;
        }
        xnode *d = &p->nd[p->nn];
        __builtin_memset(d, 0, sizeof *d);
        d->parent = pt == X_TOC ? -1 : p->st[p->depth - 1].node;
        L->node = (i32)p->nn++;
    } else if (tg == X_DATA) {
        xnode *d = file_at(p, 0);
        if (d) d->flags |= NF_DATA;
    }
    p->depth++;
    return GZ_OK;
}

static void on_attr(xparse *p, const u8 *an, size_t al, const u8 *v, size_t vl)
{
    xlevel *L = &p->st[p->depth - 1];
    xnode *d;
    switch (L->tag) {
    case X_FILE:
        if (L->node >= 0 && eq(an, al, "id")) {
            int ok = 1;
            u64 id = num(v, vl, 10, &ok);
            p->nd[L->node].id = ok && id <= 0xffffffffu ? (u32)id : 0;
        }
        break;
    case X_NAME:
        if (eq(an, al, "enctype") && eq(v, vl, "base64")) L->b64 = 1;
        break;
    case X_TYPE:
        if ((d = file_at(p, 1)) && eq(an, al, "link") && !eq(v, vl, "original")) {
            int ok = 1;
            u64 id = num(v, vl, 10, &ok);
            d->ref = ok && id <= 0xffffffffu ? (u32)id : 0;
        }
        break;
    case X_ENCODING:
        if ((d = data_node(p)) && eq(an, al, "style")) d->enc = enc_of(v, vl);
        break;
    case X_EXCK:
        if ((d = data_node(p)) && eq(an, al, "style")) d->ck = ck_of(v, vl);
        break;
    case X_CHECKSUM:
        if (tag_at(p, 1) == X_TOC && eq(an, al, "style")) p->ck_style = ck_of(v, vl);
        break;
    }
}

static int on_close(xparse *p, size_t end)
{
    xlevel *L = &p->st[p->depth - 1];
    const u8 *t = p->x + L->text;
    size_t tn = end > L->text ? end - L->text : 0;
    xnode *d = 0;
    int ok = 1;
    switch (L->tag) {
    case X_NAME:
        if ((d = file_at(p, 1))) return scr_put(p, t, tn, L->b64, &d->name_off, &d->name_len);
        break;
    case X_LINK:
        if ((d = file_at(p, 1))) return scr_put(p, t, tn, 0, &d->link_off, &d->link_len);
        break;
    case X_TYPE:
        if ((d = file_at(p, 1))) {
            trim(&t, &tn);
            d->type = eq(t, tn, "file") ? FT_FILE : eq(t, tn, "directory") ? FT_DIR : eq(t, tn, "symlink") ? FT_SYMLINK
                    : eq(t, tn, "hardlink") ? FT_HARDLINK : FT_OTHER;
        }
        break;
    case X_MODE:
        if ((d = file_at(p, 1))) {
            u64 m = num(t, tn, 8, &ok);
            if (ok) { d->mode = (u32)m & 07777; d->flags |= NF_MODE; }
        }
        break;
    case X_MTIME:
        if ((d = file_at(p, 1)) && iso_time(t, tn, &d->mtime)) d->flags |= NF_MTIME;
        break;
    case X_LENGTH: case X_OFFSET: case X_SIZE:
        if ((d = data_node(p))) {
            u64 v = num(t, tn, 10, &ok);
            if (!ok) v = ~(u64)0;                    /* rejected when extracted */
            if (L->tag == X_LENGTH) { d->length = v; d->flags |= NF_LENGTH; }
            else if (L->tag == X_OFFSET) { d->offset = v; d->flags |= NF_OFFSET; }
            else if (ok) { d->size = v; d->flags |= NF_SIZE; }
        } else if (L->tag != X_LENGTH && tag_at(p, 1) == X_CHECKSUM && tag_at(p, 2) == X_TOC) {
            u64 v = num(t, tn, 10, &ok);
            if (L->tag == X_OFFSET) p->ck_off = ok ? v : ~(u64)0;
            else p->ck_size = ok ? v : 0;
        }
        break;
    case X_EXCK:
        if ((d = data_node(p))) {
            trim(&t, &tn);
            d->ck_off = (u32)(t - p->x);
            d->ck_len = (u16)(tn < 0xffff ? tn : 0xffff);
        }
        break;
    }
    return GZ_OK;
}

static size_t find(const u8 *x, size_t n, size_t i, const char *m)
{
    size_t ml = 0;
    while (m[ml]) ml++;
    for (; i + ml <= n; i++)
        if (x[i] == (u8)m[0] && !__builtin_memcmp(x + i, m, ml)) return i;
    return ~(size_t)0;
}

static int toc_parse(xparse *p)
{
    const u8 *x = p->x;
    size_t n = p->n, i = 0;
    while (i < n) {
        if (x[i] != '<') { i++; while (i < n && x[i] != '<') i++; continue; }
        if (i + 1 >= n) return GZ_E_FORMAT;
        u8 c1 = x[i + 1];
        if (c1 == '!' || c1 == '?') {          /* comment, CDATA, DOCTYPE, processing instruction */
            const char *m = c1 == '?' ? "?>" : (i + 4 <= n && x[i + 2] == '-' && x[i + 3] == '-') ? "-->"
                          : (i + 9 <= n && !__builtin_memcmp(x + i, "<![CDATA[", 9)) ? "]]>" : ">";
            size_t j = find(x, n, i + 2, m);
            if (j == ~(size_t)0) return GZ_E_FORMAT;
            while (*m) { j++; m++; }
            i = j;
            continue;
        }
        if (c1 == '/') {                       /* end tag */
            size_t j = i + 2, ns = j;
            while (j < n && is_namec(x[j])) j++;
            u8 tg = tag_id(x + ns, j - ns);
            while (j < n && x[j] != '>') j++;
            if (j >= n || !p->depth || p->st[p->depth - 1].tag != tg) return GZ_E_FORMAT;
            int r = on_close(p, i);
            if (r) return r;
            p->depth--;
            i = j + 1;
            continue;
        }
        size_t j = i + 1, ns = j;              /* start tag */
        while (j < n && is_namec(x[j])) j++;
        if (j == ns) return GZ_E_FORMAT;
        int r = on_open(p, tag_id(x + ns, j - ns));
        if (r) return r;
        int self = 0;
        for (;;) {
            while (j < n && is_ws(x[j])) j++;
            if (j >= n) return GZ_E_FORMAT;
            if (x[j] == '>') { j++; break; }
            if (x[j] == '/') {
                if (j + 1 < n && x[j + 1] == '>') { self = 1; j += 2; break; }
                return GZ_E_FORMAT;
            }
            size_t an = j;
            while (j < n && is_namec(x[j])) j++;
            size_t al = j - an;
            while (j < n && is_ws(x[j])) j++;
            if (!al || j >= n || x[j] != '=') return GZ_E_FORMAT;
            j++;
            while (j < n && is_ws(x[j])) j++;
            if (j >= n || (x[j] != '"' && x[j] != '\'')) return GZ_E_FORMAT;
            u8 q = x[j++];
            size_t vs = j;
            while (j < n && x[j] != q) j++;
            if (j >= n) return GZ_E_FORMAT;
            on_attr(p, x + an, al, x + vs, j - vs);
            j++;
        }
        p->st[p->depth - 1].text = (u32)j;
        if (self) {
            if ((r = on_close(p, j))) return r;
            p->depth--;
        }
        i = j;
    }
    return p->depth ? GZ_E_FORMAT : GZ_OK;
}

/* ---------------- archive ---------------- */

static int xar_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 28 || __builtin_memcmp(h, "xar!", 4) || rd16be(h + 4) < 28 || rd16be(h + 6) != 1) return 0;
    return 95;
}

static int hexval(u8 c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c |= 0x20;
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

/* the TOC holds a checksum of its compressed bytes in the heap */
static int toc_check(const xparse *p, gz_src *s, const u8 *zt, u32 zn, u64 heap)
{
    u32 cl = ck_len(p->ck_style);
    if (!cl || p->ck_size != cl) return GZ_OK;          /* none / md5: not checked */
    if (p->ck_off > s->size - heap || cl > s->size - heap - p->ck_off) return GZ_E_TRUNC;
    u8 want[32], got[32];
    int r = gz_src_read_exact(s, heap + p->ck_off, want, cl);
    if (r) return r;
    if (p->ck_style == CK_SHA1) gz_sha1_calc(zt, zn, got);
    else gz_sha256_calc(zt, zn, got);
    return __builtin_memcmp(want, got, cl) ? GZ_E_CRC : GZ_OK;
}

/* phase 2: entries from the parsed nodes */
static int build_entries(gz_archive *a, xparse *p, u64 heap, xar_priv *pv)
{
    u8 *tmp = (u8 *)gz_alloc(XAR_PATH_MAX);
    i32 *ent = (i32 *)gz_alloc((size_t)p->nn * sizeof(i32) + 4);
    pv->x = (xent *)gz_alloc((size_t)p->nn * sizeof(xent) + 1);
    if (!tmp || !ent || !pv->x) { gz_free(tmp); gz_free(ent); return GZ_E_NOMEM; }
    int r = GZ_OK;
    for (u32 i = 0; i < p->nn && !r; i++) {
        xnode *d = &p->nd[i];
        ent[i] = -1;
        const xnode *par = d->parent >= 0 ? &p->nd[d->parent] : 0;
        if (par && (par->flags & NF_BADPATH)) { d->flags |= NF_BADPATH; continue; }
        u32 pl = par ? par->path_len : 0;
        u64 total = (u64)pl + (pl ? 1 : 0) + d->name_len;
        if (!d->name_len) { d->path_off = par ? par->path_off : 0; d->path_len = pl; continue; }
        if (total > XAR_PATH_MAX) { d->flags |= NF_BADPATH; continue; }
        if (pl) { __builtin_memcpy(tmp, a->raw + par->path_off, pl); tmp[pl] = '/'; }
        __builtin_memcpy(tmp + pl + (pl ? 1 : 0), p->scr + d->name_off, d->name_len);
        if ((r = gz_arc_raw_append(a, tmp, (u32)total, &d->path_off))) break;
        d->path_len = (u32)total;
        if (d->type == FT_OTHER) continue;                     /* devices, fifos, sockets */
        gz_entry *e;
        if ((r = gz_arc_add_entry(a, &e))) break;
        ent[i] = (i32)(a->n - 1);
        e->raw_off = d->path_off;
        e->raw_len = d->path_len;
        e->name_enc = GZ_NE_UTF8;
        e->is_dir = d->type == FT_DIR;
        e->is_link = d->type == FT_SYMLINK;
        if (d->flags & NF_MTIME) { e->mtime = gz_unix_to_filetime(d->mtime); e->mtime_kind = GZ_MT_FILETIME; }
        e->unix_mode = (d->flags & NF_MODE ? d->mode : e->is_dir ? 0755u : 0644u) |
                       (e->is_dir ? 0040000u : e->is_link ? 0120000u : 0100000u);
        e->attr = e->is_dir ? 0x10 : 0x20;
        if ((d->flags & NF_MODE) && !(d->mode & 0200)) e->attr |= 1;
        if (e->is_link && d->link_len) {
            u32 lo;
            if ((r = gz_arc_raw_append(a, p->scr + d->link_off, d->link_len, &lo))) break;
            e = &a->e[a->n - 1];
            e->link_off = lo;
            e->link_len = d->link_len;
        }
        if (!e->is_dir && !(e->is_link && e->link_len) && (d->flags & NF_DATA)) {
            /* missing or junk numbers become values that fail the range check */
            e->csize = d->flags & NF_LENGTH ? d->length : ~(u64)0;
            u64 off = d->flags & NF_OFFSET ? d->offset : ~(u64)0;
            e->off = off <= ~(u64)0 - heap ? heap + off : ~(u64)0;
            e->usize = d->flags & NF_SIZE ? d->size : d->enc == EN_NONE ? e->csize : GZ_SIZE_UNKNOWN;
            e->method = d->enc;
            xent *x = &pv->x[a->n - 1];
            u32 cl = ck_len(d->ck);
            if (cl && d->ck_len == cl * 2) {
                const u8 *hx = p->x + d->ck_off;
                u32 k = 0;
                for (; k < cl; k++) {
                    int hi = hexval(hx[2 * k]), lo = hexval(hx[2 * k + 1]);
                    if (hi < 0 || lo < 0) break;
                    x->digest[k] = (u8)(hi << 4 | lo);
                }
                if (k == cl) x->ck = d->ck;
            }
        }
    }
    /* hard links: <type link="N">hardlink</type> names the original's id */
    u32 cap = 16;
    while (cap < p->nn * 2) cap <<= 1;
    u32 *ids = r ? 0 : (u32 *)gz_alloc((size_t)cap * sizeof(u32));
    if (!r && !ids) r = GZ_E_NOMEM;
    for (u32 pass = 0; pass < 2 && !r; pass++) {
        for (u32 i = 0; i < p->nn; i++) {
            const xnode *d = &p->nd[i];
            if (ent[i] < 0) continue;
            u32 h;
            if (!pass) {
                if (!d->id) continue;
                h = (d->id * 0x9E3779B1u) & (cap - 1);
                while (ids[h] && p->nd[ids[h] - 1].id != d->id) h = (h + 1) & (cap - 1);
                if (!ids[h]) ids[h] = i + 1;
                continue;
            }
            if (d->type != FT_HARDLINK || !d->ref || (d->flags & NF_DATA)) continue;
            h = (d->ref * 0x9E3779B1u) & (cap - 1);
            while (ids[h] && p->nd[ids[h] - 1].id != d->ref) h = (h + 1) & (cap - 1);
            if (!ids[h] || ids[h] - 1 == i || ent[ids[h] - 1] < 0) continue;
            const xnode *o = &p->nd[ids[h] - 1];
            gz_entry *e = &a->e[ent[i]];
            if (a->e[ent[ids[h] - 1]].is_dir) continue;
            e->is_link = 2;
            e->link_off = o->path_off;
            e->link_len = o->path_len;
        }
    }
    gz_free(ids);
    gz_free(ent);
    gz_free(tmp);
    return r;
}

static int xar_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u8 h[28];
    int r = gz_src_read_exact(s, 0, h, 28);
    if (r) return r;
    if (__builtin_memcmp(h, "xar!", 4) || rd16be(h + 6) != 1) return GZ_E_FORMAT;
    u32 hs = rd16be(h + 4);
    u64 zn = rd64be(h + 8), un = rd64be(h + 16);
    if (hs < 28 || hs > s->size || zn < 2 || zn > s->size - hs) return GZ_E_FORMAT;
    if (un > XAR_TOC_MAX || zn > XAR_TOC_MAX) return GZ_E_LIMIT;
    u64 heap = hs + zn;

    xar_priv *pv = (xar_priv *)gz_alloc(sizeof(xar_priv));
    if (!pv) return GZ_E_NOMEM;
    a->priv = pv;
    u8 *zt = (u8 *)gz_alloc((size_t)zn);
    if (!zt) return GZ_E_NOMEM;
    if ((r = gz_src_read_exact(s, hs, zt, (u32)zn))) { gz_free(zt); return r; }
    if ((zt[0] & 0x0F) != 8 || (zt[0] << 8 | zt[1]) % 31 || (zt[1] & 0x20)) { gz_free(zt); return GZ_E_FORMAT; }

    /* inflate the TOC (zlib) */
    gz_inflater *z = gz_ctx_inflater(c);
    gz_src *zs = gz_src_mem(zt + 2, zn - 2, 0);
    if (!z || !zs) { gz_src_free(zs); gz_free(zt); return GZ_E_NOMEM; }
    gz_mem_sink toc = { 0, 0, 0, un ? (size_t)un : XAR_TOC_MAX };
    gz_pipe pp = { { zs, 0, zs->size, c->cancel }, gz_mem_write, &toc };
    gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };
    r = gz_inflate_run(z, &io, 0);
    gz_src_free(zs);
    if (r) { gz_free(zt); gz_mem_sink_free(&toc); return r == GZ_E_LIMIT || r == GZ_E_CANCEL || r == GZ_E_NOMEM ? r : GZ_E_FORMAT; }

    xparse *p = (xparse *)gz_alloc(sizeof(xparse));
    xlevel *st = (xlevel *)gz_alloc(XAR_DEPTH_MAX * sizeof(xlevel));
    if (!p || !st) r = GZ_E_NOMEM;
    else {
        p->x = toc.p;
        p->n = toc.n;
        p->st = st;
        p->ck_off = ~(u64)0;
        r = toc_parse(p);
        if (!r) r = toc_check(p, s, zt, (u32)zn, heap);
        if (!r) r = build_entries(a, p, heap, pv);
    }
    gz_free(zt);
    if (p) { gz_free(p->nd); gz_free(p->scr); }
    gz_free(p);
    gz_free(st);
    gz_mem_sink_free(&toc);
    return r;
}

static void xar_close(gz_archive *a)
{
    xar_priv *pv = (xar_priv *)a->priv;
    if (pv) gz_free(pv->x);
    gz_free(pv);
    a->priv = 0;
}

/* sink: enforces the declared size and hashes the decoded data */
typedef struct {
    gz_out *out;
    u64 n, limit;
    u8 ck;
    gz_sha1 h1;
    gz_sha256 h2;
} xsink;

static int xs_write(void *u, const u8 *p, size_t n)
{
    xsink *k = (xsink *)u;
    if (n > k->limit - k->n) return GZ_E_DATA;            /* more than the declared size */
    k->n += n;
    if (k->ck == CK_SHA1) gz_sha1_update(&k->h1, p, n);
    else if (k->ck == CK_SHA256) gz_sha256_update(&k->h2, p, n);
    return k->out->write(k->out, p, n);
}

static void *bz_create(void) { return gz_bzip2_dec_new(); }
static void bz_destroy(void *p) { gz_bzip2_dec_free((gz_bzip2_dec *)p); }

static int decode_entry(const gz_entry *e, const xent *x, gz_src *s, gz_out *out, gz_ctx *c)
{
    if (e->off > s->size || e->csize > s->size - e->off) return GZ_E_TRUNC;
    xsink k;
    __builtin_memset(&k, 0, sizeof k);
    k.out = out;
    k.limit = e->usize == GZ_SIZE_UNKNOWN ? ~(u64)0 : e->usize;
    k.ck = x->ck;
    if (k.ck == CK_SHA1) gz_sha1_init(&k.h1);
    else if (k.ck == CK_SHA256) gz_sha256_init(&k.h2);
    gz_src *sub = gz_src_sub(s, e->off, e->csize);
    if (!sub) return GZ_E_NOMEM;
    gz_pipe pp = { { sub, 0, sub->size, c->cancel }, xs_write, &k };
    gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };
    int r;
    u8 zh[2] = { 0, 0 };
    if (e->method == EN_ZLIB && sub->size >= 2 && !(r = gz_src_read_exact(sub, 0, zh, 2)) &&
        !(zh[0] == 0x1F && zh[1] == 0x8B)) {
        gz_inflater *z = gz_ctx_inflater(c);
        if (!z) r = GZ_E_NOMEM;
        else if ((zh[0] & 0x0F) != 8 || (zh[0] << 8 | zh[1]) % 31 || (zh[1] & 0x20)) r = GZ_E_DATA;
        else { pp.rd.pos = 2; r = gz_inflate_run(z, &io, 0); }
    } else if (e->method == EN_NONE) {
        r = gz_stream_copy(sub, xs_write, &k, c);
    } else if (e->method == EN_BZIP2) {
        gz_bzip2_dec *d = (gz_bzip2_dec *)gz_ctx_slot(c, GZ_SLOT_BZIP2, bz_create, bz_destroy);
        r = d ? gz_bzip2_decode(d, &io, e->usize, 1, 0) : GZ_E_NOMEM;
    } else {
        /* xz / lzma / real gzip: whichever stream format recognises the data */
        const gz_stream_codec *sc = gz_stream_codec_find(sub);
        r = sc ? sc->decode(sub, xs_write, &k, c) : GZ_E_METHOD;
    }
    gz_src_free(sub);
    if (!r && e->usize != GZ_SIZE_UNKNOWN && k.n != e->usize) r = GZ_E_DATA;
    if (!r && k.ck) {
        u8 dg[32];
        if (k.ck == CK_SHA1) gz_sha1_final(&k.h1, dg);
        else gz_sha256_final(&k.h2, dg);
        if (__builtin_memcmp(dg, x->digest, ck_len(k.ck))) r = GZ_E_CRC;
    }
    return r;
}

static int xar_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    const gz_entry *e = &a->e[idx];
    const xar_priv *pv = (const xar_priv *)a->priv;
    int r = out->open(out, idx);
    if (r) return r;
    if (e->is_dir || (e->is_link && e->link_len) || (!e->csize && !e->usize)) return out->close(out, idx, GZ_OK);
    int st = decode_entry(e, &pv->x[idx], s, out, c);
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static void xar_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    static const char *const m[] = { "Store", "Deflate", "BZip2", "XZ", "LZMA", "Unknown" };
    const char *s = e->method < GZ_COUNTOF(m) ? m[e->method] : "Unknown";
    u32 i = 0;
    for (; s[i] && i + 1 < cap; i++) buf[i] = s[i];
    if (cap) buf[i] = 0;
}

static gz_src *xar_view(gz_archive *a, gz_src *s, u32 idx)
{
    const gz_entry *e = &a->e[idx];
    if (e->is_dir || e->is_link || e->method != EN_NONE || e->usize != e->csize) return 0;
    if (e->off > s->size || e->csize > s->size - e->off) return 0;
    return gz_src_sub(s, e->off, e->usize);
}

GZ_FORMAT(gz_fmt_xar)
const gz_format gz_fmt_xar = {
    "XAR", "xar pkg xip mpkg", 0, xar_probe, xar_open, xar_close, xar_extract, 0, 0, xar_method, xar_view, 0
};

/* ---------------- pbzx (macOS Payload, .xip Content) ---------------- */

static const gz_stream_codec pbzx_codec;

static int pbzx_decode(gz_src *s, gz_sink_fn sink, void *user, gz_ctx *c)
{
    u8 h[16];
    int r = gz_src_read_exact(s, 0, h, 12);
    if (r) return r;
    if (__builtin_memcmp(h, "pbzx", 4)) return GZ_E_FORMAT;
    u64 flags = rd64be(h + 4), off = 12;
    while ((flags & (1u << 24)) && off < s->size) {
        if (gz_cancelled(c)) return GZ_E_CANCEL;
        if ((r = gz_src_read_exact(s, off, h, 16))) return r;
        flags = rd64be(h);
        u64 len = rd64be(h + 8);
        off += 16;
        if (len > s->size - off) return GZ_E_TRUNC;
        gz_src *sub = gz_src_sub(s, off, len);
        if (!sub) return GZ_E_NOMEM;
        u8 m[6] = { 0 };
        if (len >= 6 && !gz_src_read_exact(sub, 0, m, 6) && !__builtin_memcmp(m, "\xFD" "7zXZ\0", 6)) {
            const gz_stream_codec *sc = gz_stream_codec_find(sub);
            r = sc && sc != &pbzx_codec ? sc->decode(sub, sink, user, c) : GZ_E_METHOD;
        } else {
            r = gz_stream_copy(sub, sink, user, c);       /* stored chunk */
        }
        gz_src_free(sub);
        if (r) return r;                                   /* GZ_E_SKIP included */
        off += len;
    }
    return GZ_OK;
}

static int pbzx_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 28 || __builtin_memcmp(h, "pbzx", 4)) return 0;
    return 90;
}

static const gz_stream_codec pbzx_codec = { "TAR.PBZX", "XZ", 0, pbzx_decode, 0 };

GZ_FORMAT(gz_fmt_pbzx)
const gz_format gz_fmt_pbzx = GZ_STREAM_FORMAT("PBZX", "pbzx", pbzx_probe, &pbzx_codec);
