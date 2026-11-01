/*
 * 고깃ZIP - archive model: name decoding, folder tree, format detection
 */
#include "arc.h"
#include "crc32.h"

int gz_zip_probe(gz_src *s, const u8 *head, u32 headn);
int gz_zip_open(gz_archive *a, gz_src *s);
int gz_zip_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, const u8 *pw, size_t pwn, gz_inflater *z);
int gz_zip_check_password(gz_archive *a, gz_src *s, u32 idx, const u8 *pw, size_t pwn);
int gz_tar_probe(const u8 *head, u32 headn);
int gz_tar_open(gz_archive *a, gz_src *s);
int gz_tar_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_inflater *z);
int gz_gzip_open(gz_archive *a, gz_src *s, const wchar_t *file_name, gz_inflater *z, volatile long *cancel);
int gz_gzip_extract(gz_archive *a, gz_src *s, gz_out *out, gz_inflater *z);
int gz_tgz_extract(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_inflater *z, volatile long *cancel);

/* ---------------- small helpers ---------------- */

size_t gz_wcslen(const wchar_t *s) { const wchar_t *p = s; while (*p) p++; return (size_t)(p - s); }
int gz_wcscmp(const wchar_t *a, const wchar_t *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (int)(u16)*a - (int)(u16)*b;
}
static wchar_t lower_ascii(wchar_t c) { return (c >= 'A' && c <= 'Z') ? (wchar_t)(c + 32) : c; }
int gz_wcsicmp_ascii(const wchar_t *a, const wchar_t *b)
{
    while (*a && lower_ascii(*a) == lower_ascii(*b)) { a++; b++; }
    return (int)(u16)lower_ascii(*a) - (int)(u16)lower_ascii(*b);
}
const wchar_t *gz_wcsrchr(const wchar_t *s, wchar_t c)
{
    const wchar_t *r = 0;
    for (; *s; s++) if (*s == c) r = s;
    return r;
}

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
    if (a->raw_len + n > 0xffffffffu) return GZ_E_NOMEM;
    if (a->raw_len + n > a->raw_cap) {
        size_t nc = a->raw_cap ? a->raw_cap : 65536;
        while (nc < a->raw_len + n) nc *= 2;
        u8 *nr = (u8 *)gz_realloc(a->raw, nc);
        if (!nr) return GZ_E_NOMEM;
        a->raw = nr;
        a->raw_cap = nc;
    }
    *off = (u32)a->raw_len;
    __builtin_memcpy(a->raw + a->raw_len, p, n);
    a->raw_len += n;
    return GZ_OK;
}

u64 gz_unix_to_filetime(i64 t)
{
    return (u64)(t * 10000000LL + 116444736000000000LL);
}

/* ---------------- UTF-8 / Hangul ---------------- */

int gz_utf8_valid(const u8 *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        u8 c = s[i];
        if (c < 0x80) { i++; continue; }
        u32 need, cp;
        if (c >= 0xC2 && c <= 0xDF) { need = 1; cp = c & 0x1f; }
        else if (c >= 0xE0 && c <= 0xEF) { need = 2; cp = c & 0x0f; }
        else if (c >= 0xF0 && c <= 0xF4) { need = 3; cp = c & 0x07; }
        else return 0;
        if (n - i <= need) return 0;               /* truncated sequence */
        for (u32 k = 1; k <= need; k++) {
            if ((s[i + k] & 0xC0) != 0x80) return 0;
            cp = (cp << 6) | (s[i + k] & 0x3f);
        }
        if ((need == 2 && cp < 0x800) || (need == 3 && (cp < 0x10000 || cp > 0x10FFFF))) return 0;
        if (cp >= 0xD800 && cp <= 0xDFFF) return 0;
        i += need + 1;
    }
    return 1;
}

int gz_utf8_to_wide(const u8 *s, size_t n, wchar_t *out)
{
    int o = 0;
    size_t i = 0;
    while (i < n) {
        u32 c = s[i], cp, need, k;
        if (c < 0x80) { out[o++] = (wchar_t)c; i++; continue; }
        if (c >= 0xC0 && c <= 0xDF) { cp = c & 0x1f; need = 1; }
        else if (c >= 0xE0 && c <= 0xEF) { cp = c & 0x0f; need = 2; }
        else if (c >= 0xF0 && c <= 0xF7) { cp = c & 0x07; need = 3; }
        else { out[o++] = 0xFFFD; i++; continue; }
        if (n - i <= need) { out[o++] = 0xFFFD; i++; continue; }
        for (k = 1; k <= need; k++) {
            if ((s[i + k] & 0xC0) != 0x80) break;
            cp = (cp << 6) | (s[i + k] & 0x3f);
        }
        if (k <= need) { out[o++] = 0xFFFD; i++; continue; }
        i += need + 1;
        if (cp >= 0x110000) cp = 0xFFFD;
        if (cp >= 0x10000) {
            cp -= 0x10000;
            out[o++] = (wchar_t)(0xD800 + (cp >> 10));
            out[o++] = (wchar_t)(0xDC00 + (cp & 0x3ff));
        } else {
            out[o++] = (wchar_t)cp;
        }
    }
    return o;
}

/* Compose conjoining Hangul jamo (as produced by macOS NFD) into syllables. */
int gz_hangul_compose(wchar_t *s, int n)
{
    int o = 0;
    for (int i = 0; i < n; i++) {
        u32 c = (u16)s[i];
        if (o > 0) {
            u32 prev = (u16)s[o - 1];
            /* L + V -> LV */
            if (prev >= 0x1100 && prev <= 0x1112 && c >= 0x1161 && c <= 0x1175) {
                s[o - 1] = (wchar_t)(0xAC00 + ((prev - 0x1100) * 21 + (c - 0x1161)) * 28);
                continue;
            }
            /* LV + T -> LVT */
            if (prev >= 0xAC00 && prev <= 0xD7A3 && ((prev - 0xAC00) % 28) == 0 &&
                c >= 0x11A8 && c <= 0x11C2) {
                s[o - 1] = (wchar_t)(prev + (c - 0x11A7));
                continue;
            }
        }
        s[o++] = (wchar_t)c;
    }
    return o;
}

/* ---------------- name decoding & tree ---------------- */

static int name_is_ascii(const u8 *s, size_t n)
{
    for (size_t i = 0; i < n; i++) if (s[i] & 0x80) return 0;
    return 1;
}

static int choose_codepage(gz_archive *a)
{
    if (a->codepage != GZ_CP_AUTO) return a->codepage;
    int legacy = 0, all_utf8 = 1;
    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[i];
        if (e->uni_len || e->utf8) continue;
        const u8 *r = a->raw + e->raw_off;
        if (name_is_ascii(r, e->raw_len)) continue;
        legacy = 1;
        if (!gz_utf8_valid(r, e->raw_len)) { all_utf8 = 0; break; }
    }
    if (legacy && all_utf8) return GZ_CP_UTF8;
    return gz_plat_acp();
}

/* Decode + normalise one name into out (capacity >= raw_len*2+4). Returns length. */
static int decode_name(gz_archive *a, const u8 *r, size_t rn, int utf8, int cp, wchar_t *out)
{
    int n;
    if (utf8 || cp == GZ_CP_UTF8) {
        n = gz_utf8_to_wide(r, rn, out);
    } else if (name_is_ascii(r, rn)) {
        for (n = 0; n < (int)rn; n++) out[n] = r[n];
    } else {
        n = gz_plat_mb2wc(cp, r, (int)rn, out, (int)rn * 2 + 2);
        if (n <= 0) {
            n = gz_plat_mb2wc(437, r, (int)rn, out, (int)rn * 2 + 2);
            if (n <= 0) for (n = 0; n < (int)rn; n++) out[n] = r[n];   /* Latin-1 */
        }
    }
    (void)a;
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
            wchar_t c = out[st + k];
            if (c < 0x20) c = '_';
            out[o++] = c;
        }
    }
    out[o] = 0;
    return o;
}

static u32 path_hash(const wchar_t *s, u32 n)
{
    u32 h = 2166136261u;
    for (u32 i = 0; i < n; i++) {
        wchar_t c = s[i];
        if (c >= 'A' && c <= 'Z') c += 32;    /* case-insensitive like Windows */
        h = (h ^ (u16)c) * 16777619u;
    }
    return h;
}

static int path_eq(const wchar_t *a, const wchar_t *b, u32 n)
{
    for (u32 i = 0; i < n; i++) {
        wchar_t x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y || !b[i]) return 0;
    }
    return b[n] == 0;
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
    const wchar_t *nm = a->f[idx].name;
    u32 h = path_hash(nm, (u32)gz_wcslen(nm)) & (a->fhash_cap - 1);
    while (a->fhash[h] >= 0) h = (h + 1) & (a->fhash_cap - 1);
    a->fhash[h] = idx;
    return GZ_OK;
}

static i32 folder_find(gz_archive *a, const wchar_t *p, u32 n)
{
    if (!n) return 0;
    u32 h = path_hash(p, n) & (a->fhash_cap - 1);
    while (a->fhash[h] >= 0) {
        i32 i = a->fhash[h];
        if (path_eq(p, a->f[i].name, n)) return i;
        h = (h + 1) & (a->fhash_cap - 1);
    }
    return -1;
}

static i32 folder_new(gz_archive *a, const wchar_t *p, u32 n, i32 parent)
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
    wchar_t *nm = (wchar_t *)gz_arena_alloc(&a->names, (n + 1) * sizeof(wchar_t));
    if (!nm) return -1;
    __builtin_memcpy(nm, p, n * sizeof(wchar_t));
    nm[n] = 0;
    f->name = nm;
    const wchar_t *sl = gz_wcsrchr(nm, '/');
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
static i32 folder_get(gz_archive *a, const wchar_t *p, u32 n)
{
    if (!n) return 0;
    i32 f = folder_find(a, p, n);
    if (f >= 0) return f;
    /* walk components from the start */
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
    if (folder_new(a, L"", 0, -1) != 0) return GZ_E_NOMEM;

    a->used_cp = choose_codepage(a);
    if (!gz_plat_cp_valid(a->used_cp) && a->used_cp != GZ_CP_UTF8) a->used_cp = gz_plat_oemcp();

    size_t tmpcap = 1024;
    wchar_t *tmp = (wchar_t *)gz_alloc(tmpcap * sizeof(wchar_t));
    if (!tmp) return GZ_E_NOMEM;
    i32 last_folder = 0;
    u32 last_len = 0;
    const wchar_t *last_name = 0;

    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[i];
        const u8 *r;
        size_t rn;
        int utf8;
        if (e->uni_len) { r = a->raw + e->uni_off; rn = e->uni_len; utf8 = 1; }
        else { r = a->raw + e->raw_off; rn = e->raw_len; utf8 = e->utf8; }
        if (utf8 || !name_is_ascii(r, rn)) {
            if (utf8) a->any_utf8 = 1; else a->any_legacy = 1;
        }
        if (rn * 2 + 4 > tmpcap) {
            gz_free(tmp);
            tmpcap = rn * 2 + 64;
            tmp = (wchar_t *)gz_alloc(tmpcap * sizeof(wchar_t));
            if (!tmp) return GZ_E_NOMEM;
        }
        int n = decode_name(a, r, rn, utf8, a->used_cp, tmp);
        wchar_t *nm = (wchar_t *)gz_arena_alloc(&a->names, ((size_t)n + 1) * sizeof(wchar_t));
        if (!nm) { gz_free(tmp); return GZ_E_NOMEM; }
        __builtin_memcpy(nm, tmp, ((size_t)n + 1) * sizeof(wchar_t));
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
        const wchar_t *sl = gz_wcsrchr(nm, '/');
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
        a->total_usize += e->usize;
        a->total_csize += e->csize;
    }
    a->ndirs = a->nf - 1;
    gz_free(tmp);

    if (a->comment_raw && a->comment_len) {
        wchar_t *c = (wchar_t *)gz_arena_alloc(&a->names, ((size_t)a->comment_len * 2 + 4) * sizeof(wchar_t));
        if (c) {
            int n;
            if (gz_utf8_valid(a->comment_raw, a->comment_len) && !name_is_ascii(a->comment_raw, a->comment_len))
                n = gz_utf8_to_wide(a->comment_raw, a->comment_len, c);
            else if (name_is_ascii(a->comment_raw, a->comment_len)) {
                for (n = 0; n < (int)a->comment_len; n++) c[n] = a->comment_raw[n];
            } else {
                n = gz_plat_mb2wc(a->used_cp == GZ_CP_UTF8 ? gz_plat_acp() : a->used_cp,
                                  a->comment_raw, (int)a->comment_len, c, (int)a->comment_len * 2 + 2);
                if (n < 0) n = 0;
            }
            c[n] = 0;
            a->comment = c;
        }
    }
    return GZ_OK;
}

/* ---------------- public API ---------------- */

int gz_arc_open(gz_archive **out, gz_src *src, const wchar_t *file_name, int codepage,
                gz_inflater *z, volatile long *cancel)
{
    u8 head[512];
    u32 got = 0;
    *out = 0;
    __builtin_memset(head, 0, sizeof head);
    int r = src->read_at(src, 0, head, sizeof head, &got);
    if (r) return r;

    gz_archive *a = (gz_archive *)gz_alloc(sizeof(gz_archive));
    if (!a) return GZ_E_NOMEM;
    a->codepage = codepage;
    a->src_size = src->size;

    if (got >= 2 && head[0] == 0x1f && head[1] == 0x8b) {
        r = gz_gzip_open(a, src, file_name, z, cancel);
    } else if (got >= 4 && head[0] == 'P' && head[1] == 'K' &&
               (head[2] == 3 || head[2] == 5 || head[2] == 7)) {
        r = gz_zip_open(a, src);
    } else if (gz_tar_probe(head, got)) {
        r = gz_tar_open(a, src);
    } else {
        r = gz_zip_open(a, src);        /* SFX or zip with prefix data */
        if (r) r = GZ_E_FORMAT;
    }
    if (!r) r = gz_arc_build_tree(a);
    if (r) { gz_arc_close(a); return r; }
    *out = a;
    return GZ_OK;
}

void gz_arc_close(gz_archive *a)
{
    if (!a) return;
    gz_free(a->e);
    gz_free(a->f);
    gz_free(a->raw);
    gz_free(a->fhash);
    gz_free(a->comment_raw);
    gz_arena_free(&a->names);
    gz_free(a);
}

int gz_arc_set_codepage(gz_archive *a, int codepage)
{
    a->codepage = codepage;
    return gz_arc_build_tree(a);
}

const char *gz_arc_type_name(const gz_archive *a)
{
    switch (a->type) {
    case GZ_ARC_ZIP: return "ZIP";
    case GZ_ARC_GZIP: return "GZIP";
    case GZ_ARC_TAR: return "TAR";
    case GZ_ARC_TGZ: return "TAR.GZ";
    }
    return "?";
}

const wchar_t *gz_arc_method_name(const gz_archive *a, const gz_entry *e)
{
    if (e->is_dir) return L"";
    if (a->type == GZ_ARC_TAR) return L"Store";
    if (a->type == GZ_ARC_GZIP || a->type == GZ_ARC_TGZ) return L"Deflate";
    u16 m = e->method == 99 ? e->aes_method : e->method;
    switch (m) {
    case 0: return L"Store";
    case 1: return L"Shrink";
    case 6: return L"Implode";
    case 8: return L"Deflate";
    case 9: return L"Deflate64";
    case 12: return L"BZip2";
    case 14: return L"LZMA";
    case 93: return L"Zstd";
    case 95: return L"XZ";
    case 98: return L"PPMd";
    }
    return L"?";
}

int gz_arc_extract(gz_archive *a, gz_src *src, u32 idx, gz_out *out,
                   const u8 *pw, size_t pwn, gz_inflater *z)
{
    switch (a->type) {
    case GZ_ARC_ZIP: return gz_zip_extract(a, src, idx, out, pw, pwn, z);
    case GZ_ARC_TAR: return gz_tar_extract(a, src, idx, out, z);
    case GZ_ARC_GZIP: return gz_gzip_extract(a, src, out, z);
    }
    return GZ_E_METHOD;
}

int gz_arc_extract_solid(gz_archive *a, gz_src *src, const u8 *sel, gz_out *out,
                         gz_inflater *z, volatile long *cancel)
{
    if (a->type == GZ_ARC_TGZ) return gz_tgz_extract(a, src, sel, out, z, cancel);
    for (u32 i = 0; i < a->n; i++) {
        if (cancel && *cancel) return GZ_E_CANCEL;
        if (!sel[i]) continue;
        gz_arc_extract(a, src, i, out, 0, 0, z);
    }
    return GZ_OK;
}

int gz_arc_check_password(gz_archive *a, gz_src *src, u32 idx, const u8 *pw, size_t pwn)
{
    if (a->type != GZ_ARC_ZIP) return GZ_OK;
    return gz_zip_check_password(a, src, idx, pw, pwn);
}
