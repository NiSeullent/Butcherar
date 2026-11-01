/*
 * 고깃ZIP - archive model: format detection, name decoding, folder tree,
 * nested (layered) archives, per-thread contexts
 */
#include "arc.h"
#include "crc32.h"

/* ---------------- arena / entries ---------------- */

struct gz_arena_blk { gz_arena_blk *next; size_t used, cap; };

void *gz_arena_alloc(gz_arena *a, size_t n)
{
    n = (n + 7) & ~(size_t)7;
    gz_arena_blk *b = a->head;
    if (!b || b->used + n > b->cap) {
        size_t cap = n > (256u << 10) ? n : (256u << 10);
        b = (gz_arena_blk *)gz_alloc(sizeof(gz_arena_blk) + cap);
        if (!b) return 0;
        b->cap = cap;
        b->used = 0;
        b->next = a->head;
        a->head = b;
    }
    void *p = (u8 *)(b + 1) + b->used;
    b->used += n;
    return p;
}

void gz_arena_free(gz_arena *a)
{
    gz_arena_blk *b = a->head;
    while (b) { gz_arena_blk *n = b->next; gz_free(b); b = n; }
    a->head = 0;
}

int gz_arc_add_entry(gz_archive *a, gz_entry **pe)
{
    if (a->n == a->cap) {
        if (a->cap >= (1u << 28)) return GZ_E_LIMIT;
        u32 nc = a->cap ? a->cap * 2 : 256;
        gz_entry *ne = (gz_entry *)gz_realloc(a->e, (size_t)nc * sizeof(gz_entry));
        if (!ne) return GZ_E_NOMEM;
        a->e = ne;
        a->cap = nc;
    }
    gz_entry *e = &a->e[a->n++];
    __builtin_memset(e, 0, sizeof(*e));
    e->folder = -1;
    e->next = -1;
    *pe = e;
    return GZ_OK;
}

int gz_arc_raw_append(gz_archive *a, const void *p, size_t n, u32 *off)
{
    if (a->raw_len + n > 0xffffffffu) return GZ_E_LIMIT;
    if (a->raw_len + n > a->raw_cap) {
        size_t nc = a->raw_cap ? a->raw_cap : 65536;
        while (nc < a->raw_len + n) nc *= 2;
        u8 *nr = (u8 *)gz_realloc(a->raw, nc);
        if (!nr) return GZ_E_NOMEM;
        a->raw = nr;
        a->raw_cap = nc;
    }
    *off = (u32)a->raw_len;
    if (n) __builtin_memcpy(a->raw + a->raw_len, p, n);
    a->raw_len += n;
    return GZ_OK;
}

int gz_arc_add_named(gz_archive *a, const void *name, u32 len, int ne, gz_entry **pe)
{
    u32 off;
    int r = gz_arc_raw_append(a, name, len, &off);   /* before the entry: a->e may move */
    if (r) return r;
    r = gz_arc_add_entry(a, pe);
    if (r) return r;
    (*pe)->raw_off = off;
    (*pe)->raw_len = len;
    (*pe)->name_enc = (u8)ne;
    return GZ_OK;
}

void gz_arc_set_type(gz_archive *a, const char *name)
{
    u32 i = 0;
    for (; name[i] && i + 1 < sizeof a->type_name; i++) a->type_name[i] = name[i];
    a->type_name[i] = 0;
}

/* ---------------- per-thread context ---------------- */

gz_ctx *gz_ctx_new(void)
{
    return (gz_ctx *)gz_alloc(sizeof(gz_ctx));
}

static void ctx_drop_views(gz_ctx *c)
{
    while (c->view_n) gz_src_free(c->view_chain[--c->view_n]);
    c->view_arc = 0;
    c->view_raw = 0;
}

void gz_ctx_free(gz_ctx *c)
{
    if (!c) return;
    ctx_drop_views(c);
    for (int i = 0; i < GZ_SLOT_COUNT; i++)
        if (c->slot[i] && c->slot_free[i]) c->slot_free[i](c->slot[i]);
    if (c->z) gz_inflater_free(c->z);
    if (c->buf) gz_free_big(c->buf, c->buf_cap);
    gz_free(c);
}

gz_inflater *gz_ctx_inflater(gz_ctx *c)
{
    if (!c->z) c->z = gz_inflater_new();
    return c->z;
}

u8 *gz_ctx_buffer(gz_ctx *c, u32 size)
{
    if (c->buf_cap < size) {
        u32 cap = size < (256u << 10) ? (256u << 10) : size;
        u8 *b = (u8 *)gz_alloc_big(cap);
        if (!b) return 0;
        if (c->buf) gz_free_big(c->buf, c->buf_cap);
        c->buf = b;
        c->buf_cap = cap;
    }
    return c->buf;
}

void *gz_ctx_slot(gz_ctx *c, int slot, void *(*create)(void), void (*destroy)(void *))
{
    if (slot < 0 || slot >= GZ_SLOT_COUNT) return 0;
    if (c->slot[slot] && c->slot_free[slot] != destroy) {
        if (c->slot_free[slot]) c->slot_free[slot](c->slot[slot]);
        c->slot[slot] = 0;
    }
    if (!c->slot[slot]) {
        c->slot[slot] = create();
        c->slot_free[slot] = destroy;
    }
    return c->slot[slot];
}

/* ---------------- name decoding & tree ---------------- */

static int name_is_ascii(const u8 *s, size_t n)
{
    for (size_t i = 0; i < n; i++) if (s[i] & 0x80) return 0;
    return 1;
}

/* Longest UTF-8 sequence length found in s (1 = ASCII only). */
static int utf8_max_seq(const u8 *s, size_t n)
{
    int m = 1;
    for (size_t i = 0; i < n; i++) {
        if (s[i] >= 0xF0) return 4;
        if (s[i] >= 0xE0) m = 3;
        else if (s[i] >= 0xC0 && m < 2) m = 2;
    }
    return m;
}

/* Vote on one name that is valid UTF-8 built only from 2-byte sequences and also
 * valid in the ANSI code page, e.g. CP949 "캡처" = C4 B8 C3 B3 or GBK "通知" =
 * CD A8 D6 AA. Returns 1 for UTF-8, 0 for the ANSI code page.
 *
 * On 949/936/950 the 2-byte UTF-8 pairs line up with the DBCS pairs. Names typed on
 * Korean/Chinese Windows use the common sets (KS X 1001, GB2312, Big5), whose trail
 * bytes are always >= A1; an accented Latin letter or NFD mark with trail 80-A0
 * ("ś" C5 9B, "à" C3 A0, "ß" C3 9F, CC 81) would be a rare extension character, so
 * it counts for UTF-8. On CP949, pairs with lead >= CA would be Hanja (rare in
 * Korean file names) but are Greek/Cyrillic/Hebrew/Arabic in UTF-8.
 * Pairs that are common in both readings count for the ANSI code page unless they
 * sit inside Latin text: a lone pair next to an ASCII letter ("Résumé", "café"), or
 * a run with ASCII letters on both sides ("Größe", NFD "Việt"). A lone Hangul
 * syllable like "짤.png" (C2 A9, also "©") stays CP949. */
static int vote_ambiguous(const u8 *s, size_t n, int acp)
{
    int euc = acp == 949 || acp == 936 || acp == 950;
    int u = 0, l = 0;
    for (size_t i = 0; i + 1 < n;) {
        if (s[i] < 0xC2 || s[i] > 0xDF) { i++; continue; }
        size_t j = i;
        while (j + 1 < n && s[j] >= 0xC2 && s[j] <= 0xDF) j += 2;
        int pairs = (int)((j - i) / 2);
        for (size_t k = i; k < j; k += 2) {
            u8 ld = s[k], tr = s[k + 1];
            if (euc && tr < 0xA1 && ((ld >= 0xC3 && ld <= 0xC9) || ld == 0xCC))
                u += 3;      /* accented Latin letter / NFD mark in a rare legacy slot */
            else if (acp == 949 && ld >= 0xCA)
                u += 3;      /* Hanja row in CP949, Greek/Cyrillic/Hebrew/Arabic in UTF-8 */
            else
                l += 2;
        }
        int pb = i ? s[i - 1] : ' ', pf = j < n ? s[j] : ' ';
        u8 b = (u8)(pb | 0x20), f = (u8)(pf | 0x20);
        int lb = b >= 'a' && b <= 'z', lf = f >= 'a' && f <= 'z';
        if (pairs == 1 ? (lb || lf) : (lb && lf)) u += 3 * pairs;
        i = j;
    }
    if (!euc) {
        /* Shift-JIS does not line up with UTF-8 pairs: judge by what it decodes to */
        gzch w[512];
        int m = n < 255 ? gz_plat_mb2wc(acp, s, (int)n, w, 512) : 0;
        l = 0;
        for (int k = 0; k < m; k++) {
            u32 c = w[k];
            if ((c >= 0x4E00 && c <= 0x9FFF) || (c >= 0x3040 && c <= 0x30FF)) l += 2;
        }
    }
    return u > l;
}

static int choose_codepage(gz_archive *a)
{
    if (a->codepage != GZ_CP_AUTO) return a->codepage;
    int acp = gz_plat_acp();
    /* DBCS names that happen to be valid UTF-8 come from archives made on CJK Windows.
     * Names from Unix tools (TAR, CPIO, ...) are UTF-8 whenever they are valid. */
    int dbcs = a->win_names && (acp == 932 || acp == 936 || acp == 949 || acp == 950);
    int legacy = 0, all_utf8 = 1, sure = 0, vu = 0, vl = 0;
    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[i];
        if (e->uni_len || e->name_enc != GZ_NE_LEGACY) continue;
        const u8 *r = a->raw + e->raw_off;
        if (name_is_ascii(r, e->raw_len)) continue;
        legacy = 1;
        if (!gz_utf8_valid(r, e->raw_len)) { all_utf8 = 0; break; }
        if (!dbcs || sure) continue;
        /* decisive: 3-byte sequences (real Hangul/CJK UTF-8, "–", "’"), or bytes the
         * ANSI code page rejects (Cyrillic/Greek on CP949) */
        if (utf8_max_seq(r, e->raw_len) >= 3 || !gz_plat_mb_valid(acp, r, (int)e->raw_len)) { sure = 1; continue; }
        if (vote_ambiguous(r, e->raw_len, acp)) vu++; else vl++;
    }
    if (legacy && all_utf8 && (!dbcs || sure || vu > vl)) return GZ_CP_UTF8;
    return acp;
}

/* worst-case UTF-16 units needed for rn raw bytes (+ terminator and slack) */
static size_t name_cap(size_t rn) { return rn * 2 + 4; }

static int decode_raw(const u8 *r, size_t rn, int ne, int cp, gzch *out)
{
    int n = 0;
    if (ne == GZ_NE_UTF16LE || ne == GZ_NE_UTF16BE) {
        for (size_t i = 0; i + 1 < rn; i += 2) {
            gzch c = ne == GZ_NE_UTF16LE ? rd16(r + i) : rd16be(r + i);
            if (!c) break;
            out[n++] = c;
        }
        return n;
    }
    if (ne == GZ_NE_UTF8 || (ne == GZ_NE_LEGACY && cp == GZ_CP_UTF8)) {
        n = gz_utf8_to_utf16(r, rn, out);
    } else if (name_is_ascii(r, rn)) {
        for (n = 0; n < (int)rn; n++) out[n] = r[n];
    } else {
        if (ne == GZ_NE_OEM && cp == GZ_CP_UTF8) cp = gz_plat_oemcp();
        n = gz_plat_mb2wc(cp, r, (int)rn, out, (int)name_cap(rn) - 2);
        if (n <= 0) {
            n = gz_plat_mb2wc(437, r, (int)rn, out, (int)name_cap(rn) - 2);
            if (n <= 0) for (n = 0; n < (int)rn; n++) out[n] = r[n];   /* Latin-1 */
        }
    }
    return n;
}

/* Decode + normalise one name into out (capacity >= name_cap(rn)). Returns length. */
static int decode_name(const u8 *r, size_t rn, int ne, int cp, gzch *out)
{
    int n = decode_raw(r, rn, ne, cp, out);
    n = gz_hangul_compose(out, n);

    /* normalise separators and drop dangerous components */
    int o = 0, i = 0;
    while (i < n) {
        while (i < n && (out[i] == '/' || out[i] == '\\')) i++;
        int st = i;
        while (i < n && out[i] != '/' && out[i] != '\\') i++;
        int len = i - st;
        if (len == 0) continue;
        if (len == 1 && out[st] == '.') continue;
        if (len == 2 && out[st] == '.' && out[st + 1] == '.') continue;
        if (o == 0 && len == 2 && out[st + 1] == ':') continue;     /* "C:" */
        if (o) out[o++] = '/';
        for (int k = 0; k < len; k++) {
            gzch c = out[st + k];
            if (c < 0x20) c = '_';
            out[o++] = c;
        }
    }
    out[o] = 0;
    return o;
}

static u32 path_hash(const gz_archive *a, const gzch *s, u32 n)
{
    u32 h = 2166136261u;
    for (u32 i = 0; i < n; i++) {
        gzch c = s[i];
        if (a->case_fold && c >= 'A' && c <= 'Z') c += 32;
        h = (h ^ c) * 16777619u;
    }
    return h;
}

static int path_eq(const gz_archive *a, const gzch *x, const gzch *y, u32 n)
{
    for (u32 i = 0; i < n; i++) {
        gzch p = x[i], q = y[i];
        if (a->case_fold) {
            if (p >= 'A' && p <= 'Z') p += 32;
            if (q >= 'A' && q <= 'Z') q += 32;
        }
        if (p != q || !y[i]) return 0;
    }
    return y[n] == 0;
}

static int fhash_insert(gz_archive *a, i32 idx);

static int fhash_grow(gz_archive *a)
{
    u32 nc = a->fhash_cap ? a->fhash_cap * 2 : 1024;
    i32 *nh = (i32 *)gz_alloc((size_t)nc * sizeof(i32));
    if (!nh) return GZ_E_NOMEM;
    for (u32 i = 0; i < nc; i++) nh[i] = -1;
    gz_free(a->fhash);
    a->fhash = nh;
    a->fhash_cap = nc;
    for (u32 i = 1; i < a->nf; i++) fhash_insert(a, (i32)i);
    return GZ_OK;
}

static int fhash_insert(gz_archive *a, i32 idx)
{
    const gzch *nm = a->f[idx].name;
    u32 h = path_hash(a, nm, (u32)gz_wcslen(nm)) & (a->fhash_cap - 1);
    while (a->fhash[h] >= 0) h = (h + 1) & (a->fhash_cap - 1);
    a->fhash[h] = idx;
    return GZ_OK;
}

static i32 folder_find(gz_archive *a, const gzch *p, u32 n)
{
    if (!n) return 0;
    u32 h = path_hash(a, p, n) & (a->fhash_cap - 1);
    while (a->fhash[h] >= 0) {
        i32 i = a->fhash[h];
        if (path_eq(a, p, a->f[i].name, n)) return i;
        h = (h + 1) & (a->fhash_cap - 1);
    }
    return -1;
}

static i32 folder_new(gz_archive *a, const gzch *p, u32 n, i32 parent)
{
    if (a->nf == a->capf) {
        u32 nc = a->capf ? a->capf * 2 : 64;
        gz_folder *nf = (gz_folder *)gz_realloc(a->f, (size_t)nc * sizeof(gz_folder));
        if (!nf) return -1;
        a->f = nf;
        a->capf = nc;
    }
    if ((a->nf + 1) * 2 > a->fhash_cap && fhash_grow(a)) return -1;
    i32 idx = (i32)a->nf++;
    gz_folder *f = &a->f[idx];
    __builtin_memset(f, 0, sizeof(*f));
    gzch *nm = (gzch *)gz_arena_alloc(&a->names, (n + 1) * sizeof(gzch));
    if (!nm) return -1;
    if (n) __builtin_memcpy(nm, p, n * sizeof(gzch));
    nm[n] = 0;
    f->name = nm;
    const gzch *sl = gz_wcsrchr(nm, '/');
    f->base = sl ? sl + 1 : nm;
    f->parent = parent;
    f->first_sub = f->first_file = f->entry = -1;
    f->next_sib = -1;
    if (parent >= 0) {
        f->next_sib = a->f[parent].first_sub;
        a->f[parent].first_sub = idx;
        a->f[parent].nsub++;
    }
    if (idx > 0) fhash_insert(a, idx);
    return idx;
}

/* Find or create the folder chain for path p[0..n) */
static i32 folder_get(gz_archive *a, const gzch *p, u32 n)
{
    if (!n) return 0;
    i32 f = folder_find(a, p, n);
    if (f >= 0) return f;
    i32 parent = 0;
    u32 i = 0;
    while (i <= n) {
        if (i == n || p[i] == '/') {
            i32 x = folder_find(a, p, i);
            if (x < 0) {
                x = folder_new(a, p, i, parent);
                if (x < 0) return -1;
            }
            parent = x;
        }
        i++;
    }
    return parent;
}

static void decode_comment(gz_archive *a)
{
    a->comment = 0;
    if (!a->comment_raw || !a->comment_len) return;
    u32 cl = a->comment_len;
    gzch *c = (gzch *)gz_arena_alloc(&a->names, ((size_t)cl * 2 + 4) * sizeof(gzch));
    if (!c) return;
    int n;
    const u8 *r = a->comment_raw;
    if (a->comment_enc != GZ_NE_LEGACY) {
        n = decode_raw(r, cl, a->comment_enc, a->used_cp, c);
    } else if (gz_utf8_valid(r, cl) && !name_is_ascii(r, cl)) {
        n = gz_utf8_to_utf16(r, cl, c);
    } else if (name_is_ascii(r, cl)) {
        for (n = 0; n < (int)cl; n++) c[n] = r[n];
    } else {
        n = gz_plat_mb2wc(a->used_cp == GZ_CP_UTF8 ? gz_plat_acp() : a->used_cp, r, (int)cl, c, (int)cl * 2 + 2);
        if (n < 0) n = 0;
    }
    c[n] = 0;
    a->comment = c;
}

int gz_arc_build_tree(gz_archive *a)
{
    gz_arena_free(&a->names);
    gz_free(a->fhash);
    a->fhash = 0;
    a->fhash_cap = 0;
    a->nf = 0;
    a->nfiles = a->ndirs = 0;
    a->total_usize = a->total_csize = 0;
    a->has_enc = 0;
    a->any_utf8 = a->any_legacy = 0;
    if (fhash_grow(a)) return GZ_E_NOMEM;
    if (folder_new(a, u"", 0, -1) != 0) return GZ_E_NOMEM;

    a->used_cp = choose_codepage(a);
    if (!gz_plat_cp_valid(a->used_cp) && a->used_cp != GZ_CP_UTF8) a->used_cp = gz_plat_oemcp();

    size_t tmpcap = 1024;
    gzch *tmp = (gzch *)gz_alloc(tmpcap * sizeof(gzch));
    if (!tmp) return GZ_E_NOMEM;
    i32 last_folder = 0;
    u32 last_len = 0;
    const gzch *last_name = 0;

    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[i];
        const u8 *r;
        size_t rn;
        int ne;
        if (e->uni_len) { r = a->raw + e->uni_off; rn = e->uni_len; ne = GZ_NE_UTF8; }
        else { r = a->raw + e->raw_off; rn = e->raw_len; ne = e->name_enc; }
        if (ne == GZ_NE_LEGACY && !name_is_ascii(r, rn)) a->any_legacy = 1;
        else if (ne == GZ_NE_UTF8 && !name_is_ascii(r, rn)) a->any_utf8 = 1;
        if (name_cap(rn) > tmpcap) {
            gz_free(tmp);
            tmpcap = name_cap(rn) + 64;
            tmp = (gzch *)gz_alloc(tmpcap * sizeof(gzch));
            if (!tmp) return GZ_E_NOMEM;
        }
        int n = decode_name(r, rn, ne, a->used_cp, tmp);
        gzch *nm = (gzch *)gz_arena_alloc(&a->names, ((size_t)n + 1) * sizeof(gzch));
        if (!nm) { gz_free(tmp); return GZ_E_NOMEM; }
        __builtin_memcpy(nm, tmp, ((size_t)n + 1) * sizeof(gzch));
        e->name = nm;
        e->folder = -1;
        e->next = -1;
        if (e->enc) a->has_enc = 1;
        if (n == 0) { e->base = nm; continue; }      /* unusable name: hidden */

        if (e->is_dir) {
            i32 f = folder_get(a, nm, (u32)n);
            if (f < 0) { gz_free(tmp); return GZ_E_NOMEM; }
            a->f[f].entry = (i32)i;
            a->f[f].mtime = e->mtime;
            a->f[f].mtime_kind = e->mtime_kind;
            e->folder = a->f[f].parent;
            e->base = a->f[f].base;
            continue;
        }
        const gzch *sl = gz_wcsrchr(nm, '/');
        u32 plen = sl ? (u32)(sl - nm) : 0;
        e->base = sl ? sl + 1 : nm;
        i32 f;
        if (last_name && plen == last_len) {
            /* fast path: same directory as previous file */
            u32 k;
            for (k = 0; k < plen && nm[k] == last_name[k]; k++) {}
            f = (k == plen) ? last_folder : folder_get(a, nm, plen);
        } else {
            f = folder_get(a, nm, plen);
        }
        if (f < 0) { gz_free(tmp); return GZ_E_NOMEM; }
        last_folder = f;
        last_len = plen;
        last_name = nm;
        e->folder = f;
        e->next = a->f[f].first_file;
        a->f[f].first_file = (i32)i;
        a->f[f].nfiles++;
        a->nfiles++;
        if (e->usize != GZ_SIZE_UNKNOWN) a->total_usize += e->usize;
        if (e->csize != GZ_SIZE_UNKNOWN) a->total_csize += e->csize;
    }
    a->ndirs = a->nf - 1;
    gz_free(tmp);
    decode_comment(a);
    return GZ_OK;
}

/* ---------------- layered views ---------------- */

/* Source to read archive a's entries from, given the caller's outer file. */
gz_src *gz_arc_layer_src(gz_archive *a, gz_src *outer, gz_ctx *c)
{
    if (!a->parent) return outer;
    if (c->view_arc == a && c->view_raw == outer && c->view_n) return c->view_chain[c->view_n - 1];
    ctx_drop_views(c);
    /* collect the chain from the outermost archive inwards */
    gz_archive *chain[8];
    u32 depth = 0;
    for (gz_archive *x = a; x->parent && depth < 8; x = x->parent) chain[depth++] = x;
    gz_src *s = outer;
    for (u32 i = depth; i-- > 0;) {
        gz_archive *child = chain[i], *par = child->parent;
        gz_src *v = par->fmt->view ? par->fmt->view(par, s, child->parent_idx) : 0;
        if (!v) { ctx_drop_views(c); return 0; }
        c->view_chain[c->view_n++] = v;
        s = v;
    }
    c->view_arc = a;
    c->view_raw = outer;
    return s;
}

/* ---------------- open ---------------- */

#define HEAD_SIZE 65536u
#define MAX_DEPTH 4

static int open_level(gz_archive **out, gz_src *src, const gz_open_opts *o, gz_ctx *c, int depth,
                      gz_archive *parent, u32 parent_idx);

static void probe_all(gz_src *src, const u8 *head, u32 got, int *score, int nf)
{
    for (int i = 0; i < nf; i++) {
        const gz_format *f = gz_formats[i];
        score[i] = (f->probe && f->open) ? f->probe(src, head, got) : 0;
        if (score[i] < 0) score[i] = 0;
        if (score[i] > 100) score[i] = 100;
    }
}

static void arc_free(gz_archive *a)
{
    if (!a) return;
    if (a->fmt && a->fmt->close) a->fmt->close(a);
    gz_free(a->e);
    gz_free(a->f);
    gz_free(a->raw);
    gz_free(a->fhash);
    gz_free(a->comment_raw);
    gz_free(a->password);
    for (u32 i = 0; i < a->nvols; i++) gz_src_free(a->vols[i]);
    gz_free(a->vols);
    gz_arena_free(&a->names);
    gz_free(a);
}

/* Pick the entry of a container that should be opened automatically. */
static int descend_candidate(gz_archive *a)
{
    i32 pick = -1;
    for (u32 i = 0; i < a->n; i++) {
        const gz_entry *e = &a->e[i];
        if (e->is_dir || e->is_aux) continue;
        if (pick >= 0) return -1;          /* more than one: let the user choose */
        pick = (i32)i;
    }
    return pick;
}

static int try_format(gz_archive **out, const gz_format *f, gz_src *src, const gz_open_opts *o,
                      gz_ctx *c, int depth, gz_archive *parent, u32 parent_idx)
{
    gz_archive *a = (gz_archive *)gz_alloc(sizeof(gz_archive));
    if (!a) return GZ_E_NOMEM;
    a->fmt = f;
    a->codepage = o->codepage;
    a->src_size = src->size;
    a->case_fold = gz_plat_case_fold();
    a->parent = parent;
    a->parent_idx = parent_idx;
    gz_arc_set_type(a, f->name);
    int r = f->open(a, src, o, c);
    if (!r) r = gz_arc_build_tree(a);
    if (r) {
        a->parent = 0;
        arc_free(a);
        return r;
    }
    /* disk images / partition maps: open the file system inside */
    if ((f->flags & GZ_FMT_CONTAINER) && !(o->flags & GZ_OPEN_NO_DESCEND) && depth < MAX_DEPTH && f->view) {
        int pick = descend_candidate(a);
        if (pick >= 0) {
            gz_src *v = f->view(a, src, (u32)pick);
            if (v) {
                gz_archive *child = 0;
                int cr = open_level(&child, v, o, c, depth + 1, a, (u32)pick);
                gz_src_free(v);
                if (!cr) {
                    /* child may itself sit on a container opened below (image ->
                     * partition map -> file system): the link to a is the owner */
                    gz_archive *link = child;
                    while (link->parent && link->parent != a) link = link->parent;
                    link->owns_parent = 1;
                    char tn[40];
                    u32 k = 0;
                    for (const char *p = child->type_name; *p && k < 22; p++) tn[k++] = *p;
                    tn[k++] = ' '; tn[k++] = '(';
                    for (const char *p = a->type_name; *p && k < 37; p++) tn[k++] = *p;
                    tn[k++] = ')'; tn[k] = 0;
                    gz_arc_set_type(child, tn);
                    *out = child;
                    return GZ_OK;
                }
                if (cr == GZ_E_CANCEL) { a->parent = 0; arc_free(a); return cr; }
            }
        }
    }
    *out = a;
    return GZ_OK;
}

static int open_level(gz_archive **out, gz_src *src, const gz_open_opts *o, gz_ctx *c, int depth,
                      gz_archive *parent, u32 parent_idx)
{
    *out = 0;
    if (!src->size) return GZ_E_FORMAT;
    u32 want = src->size < HEAD_SIZE ? (u32)src->size : HEAD_SIZE;
    u8 *head = (u8 *)gz_alloc(HEAD_SIZE + 16);
    if (!head) return GZ_E_NOMEM;
    int r = gz_src_read_exact(src, 0, head, want);
    if (r) { gz_free(head); return r; }

    int nf = 0;
    while (gz_formats[nf]) nf++;
    int *score = (int *)gz_alloc((size_t)(nf + 1) * sizeof(int));
    if (!score) { gz_free(head); return GZ_E_NOMEM; }
    probe_all(src, head, want, score, nf);
    gz_free(head);

    /* try formats from the highest score down; weak formats only when nothing else opens */
    r = GZ_E_FORMAT;
    int first_err = 0;
    for (int pass = 0; pass < 2 && r; pass++) {
        for (;;) {
            int best = -1;
            for (int i = 0; i < nf; i++) {
                if (!score[i]) continue;
                int weak = (gz_formats[i]->flags & GZ_FMT_WEAK) != 0;
                if (weak != pass) continue;
                if (best < 0 || score[i] > score[best]) best = i;
            }
            if (best < 0) break;
            score[best] = 0;
            r = try_format(out, gz_formats[best], src, o, c, depth, parent, parent_idx);
            if (!r) break;
            if (r == GZ_E_CANCEL || r == GZ_E_NOMEM) { gz_free(score); return r; }
            /* keep the most specific error from a format that recognised the data */
            if (!first_err || (first_err == GZ_E_FORMAT && r != GZ_E_FORMAT)) first_err = r;
        }
    }
    gz_free(score);
    if (r && first_err) r = first_err;
    return r;
}

int gz_arc_open(gz_archive **out, gz_src *src, const gz_open_opts *o, gz_ctx *c)
{
    gz_open_opts def;
    if (!o) { __builtin_memset(&def, 0, sizeof def); o = &def; }
    gz_ctx *own = 0;
    if (!c) { own = c = gz_ctx_new(); if (!c) return GZ_E_NOMEM; }
    volatile long *old_cancel = c->cancel;
    if (o->cancel) c->cancel = o->cancel;
    void (*old_prog)(void *, u64, u64) = c->progress;
    void *old_pu = c->progress_user;
    if (o->progress) { c->progress = o->progress; c->progress_user = o->user; }
    int r = open_level(out, src, o, c, 0, 0, 0);
    c->cancel = old_cancel;
    c->progress = old_prog;
    c->progress_user = old_pu;
    if (own) gz_ctx_free(own);
    return r;
}

int gz_arc_open_child(gz_archive **out, gz_archive *parent, gz_src *parent_src, u32 idx,
                      const gz_open_opts *o, gz_ctx *c)
{
    *out = 0;
    if (idx >= parent->n || !parent->fmt->view) return GZ_E_METHOD;
    gz_open_opts def;
    if (!o) { __builtin_memset(&def, 0, sizeof def); o = &def; }
    gz_src *s = gz_arc_layer_src(parent, parent_src, c);
    if (!s) return GZ_E_METHOD;
    gz_src *v = parent->fmt->view(parent, s, idx);
    if (!v) return GZ_E_METHOD;
    int r = open_level(out, v, o, c, 1, parent, idx);
    gz_src_free(v);
    ctx_drop_views(c);
    return r;
}

void gz_arc_close(gz_archive *a)
{
    while (a) {
        gz_archive *p = a->owns_parent ? a->parent : 0;
        arc_free(a);
        a = p;
    }
}

int gz_arc_set_codepage(gz_archive *a, int codepage)
{
    a->codepage = codepage;
    return gz_arc_build_tree(a);
}

const char *gz_arc_type_name(const gz_archive *a)
{
    return a->type_name[0] ? a->type_name : (a->fmt ? a->fmt->name : "?");
}

void gz_arc_method(const gz_archive *a, const gz_entry *e, gzch *buf, u32 cap)
{
    char tmp[96];
    tmp[0] = 0;
    if (cap) buf[0] = 0;
    if (!cap || e->is_dir || !a->fmt->method) return;
    a->fmt->method(a, e, tmp, sizeof tmp);
    u32 i = 0;
    for (; tmp[i] && i + 1 < cap && i + 1 < sizeof tmp; i++) buf[i] = (u8)tmp[i];
    buf[i] = 0;
}

/* ---------------- extraction ---------------- */

int gz_arc_extract(gz_archive *a, gz_src *src, u32 idx, gz_out *out, gz_ctx *c)
{
    if (idx >= a->n || !a->fmt->extract) return GZ_E_METHOD;
    gz_src *s = gz_arc_layer_src(a, src, c);
    if (!s) return GZ_E_IO;
    return a->fmt->extract(a, s, idx, out, c);
}

int gz_arc_extract_solid(gz_archive *a, gz_src *src, const u8 *sel, gz_out *out, gz_ctx *c)
{
    gz_src *s = gz_arc_layer_src(a, src, c);
    if (!s) return GZ_E_IO;
    if (a->fmt->extract_solid) return a->fmt->extract_solid(a, s, sel, out, c);
    for (u32 i = 0; i < a->n; i++) {
        if (gz_cancelled(c)) return GZ_E_CANCEL;
        if (!sel[i]) continue;
        int r = a->fmt->extract(a, s, i, out, c);
        if (r == GZ_E_CANCEL) return r;
    }
    return GZ_OK;
}

int gz_arc_check_password(gz_archive *a, gz_src *src, u32 idx, gz_ctx *c)
{
    if (!a->fmt->check_password || idx >= a->n) return GZ_OK;
    gz_src *s = gz_arc_layer_src(a, src, c);
    if (!s) return GZ_E_IO;
    return a->fmt->check_password(a, s, idx, c);
}

gz_src *gz_arc_view(gz_archive *a, gz_src *src, u32 idx, gz_ctx *c)
{
    if (!a->fmt->view || idx >= a->n) return 0;
    gz_src *s = gz_arc_layer_src(a, src, c);
    if (!s) return 0;
    return a->fmt->view(a, s, idx);
}

/* ---------------- helpers for simple formats ---------------- */

int gz_copy_range(gz_src *s, u64 off, u64 len, gz_out *out, gz_ctx *c, u32 *crc)
{
    u8 *buf = gz_ctx_buffer(c, 256u << 10);
    if (!buf) return GZ_E_NOMEM;
    u32 cr = 0;
    while (len) {
        if (gz_cancelled(c)) return GZ_E_CANCEL;
        u32 n = len < (256u << 10) ? (u32)len : (256u << 10);
        int r = gz_src_read_exact(s, off, buf, n);
        if (r) return r;
        if (crc) cr = gz_crc32(cr, buf, n);
        r = out->write(out, buf, n);
        if (r) return r;
        off += n;
        len -= n;
    }
    if (crc) *crc = cr;
    return GZ_OK;
}

int gz_extract_stored(gz_archive *a, gz_src *s, u32 idx, u64 off, gz_out *out, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    int r = out->open(out, idx);
    if (r) return r;
    if (e->is_dir || (e->is_link && e->link_len) || !e->usize || e->usize == GZ_SIZE_UNKNOWN)
        return out->close(out, idx, GZ_OK);
    u32 crc = 0;
    int st = gz_copy_range(s, off, e->usize, out, c, e->has_crc ? &crc : 0);
    if (!st && e->has_crc && crc != e->crc) st = GZ_E_CRC;
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}
