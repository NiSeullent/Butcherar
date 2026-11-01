/*
 * 고깃ZIP - TAR (ustar / GNU / pax / v7)
 *
 * The parser is a push-style state machine so the same code lists and
 * extracts plain .tar files (random access, data skipped with seeks) and
 * tarballs inside any compressed stream (see streamfmt.c).
 */
#include "tar.h"
#include "crc32.h"

/* ---------------- header helpers ---------------- */

static u64 tar_num(const u8 *p, u32 n)
{
    if (p[0] & 0x80) {                       /* GNU base-256 */
        u64 v = p[0] & 0x3f;
        for (u32 i = 1; i < n; i++) v = (v << 8) | p[i];
        return v;
    }
    u64 v = 0;
    u32 i = 0;
    while (i < n && (p[i] == ' ' || p[i] == 0)) i++;
    for (; i < n && p[i] >= '0' && p[i] <= '7'; i++) v = (v << 3) | (u64)(p[i] - '0');
    return v;
}

static int tar_cksum_ok(const u8 *h)
{
    u32 s = 0;
    i32 ss = 0;
    for (int i = 0; i < 512; i++) {
        u8 c = (i >= 148 && i < 156) ? ' ' : h[i];
        s += c;
        ss += (i8)c;
    }
    u64 want = tar_num(h + 148, 8);
    return want == s || (i64)want == ss;
}

static int is_zero_block(const u8 *h)
{
    for (int i = 0; i < 512; i++) if (h[i]) return 0;
    return 1;
}

int gz_tar_header_ok(const u8 *h)
{
    return !is_zero_block(h) && tar_cksum_ok(h);
}

static u32 cstr_len(const u8 *p, u32 max)
{
    u32 n = 0;
    while (n < max && p[n]) n++;
    return n;
}

static u8 *dup_bytes(const u8 *p, u32 n)
{
    u8 *d = (u8 *)gz_alloc(n + 1);
    if (d) __builtin_memcpy(d, p, n);
    return d;
}

/* ---------------- parser ---------------- */

struct gz_tar_parser {
    gz_archive *a;
    gz_ctx *c;
    u8 hdr[512];
    u32 hpos;
    int mode;                /* 0 header, 1 entry data, 2 meta data (L/K/x), 3 skip data */
    u64 left, pad;
    u64 pos;                 /* stream offset */
    u8 *meta; u32 meta_len, meta_cap;
    int meta_kind;           /* 'L', 'K' or 'x' */
    u8 *lname; u32 lname_len;           /* GNU long name for the next header  */
    u8 *llink; u32 llink_len;           /* GNU long link name                 */
    u8 *pname; u32 pname_len;           /* pax path                           */
    u8 *plink; u32 plink_len;           /* pax linkpath                       */
    u64 pax_size; int has_pax_size;
    i64 pax_mtime; int has_pax_mtime;
    int done;
    /* extraction */
    int extracting;
    const u8 *sel;
    gz_out *out;
    u32 next_idx;
    i32 cur;                 /* entry being written, -1 none */
    int cur_status;
};

static void set_bytes(u8 **dst, u32 *dn, const u8 *p, u32 n)
{
    gz_free(*dst);
    *dst = dup_bytes(p, n);
    *dn = *dst ? n : 0;
}

static void clear_pending(gz_tar_parser *t)
{
    gz_free(t->lname); t->lname = 0; t->lname_len = 0;
    gz_free(t->llink); t->llink = 0; t->llink_len = 0;
    gz_free(t->pname); t->pname = 0; t->pname_len = 0;
    gz_free(t->plink); t->plink = 0; t->plink_len = 0;
    t->has_pax_size = t->has_pax_mtime = 0;
}

void gz_tar_parser_free(gz_tar_parser *t)
{
    if (!t) return;
    clear_pending(t);
    gz_free(t->meta);
    gz_free(t);
}

gz_tar_parser *gz_tar_parser_new(gz_archive *a, const u8 *sel, gz_out *out, gz_ctx *c)
{
    gz_tar_parser *t = (gz_tar_parser *)gz_alloc(sizeof(gz_tar_parser));
    if (!t) return 0;
    t->a = a;
    t->c = c;
    t->extracting = out != 0;
    t->sel = sel;
    t->out = out;
    t->cur = -1;
    return t;
}

int gz_tar_done(const gz_tar_parser *t) { return t->done; }

static u64 pax_uint(const u8 *v, u32 vn)
{
    u64 s = 0;
    for (u32 k = 0; k < vn && v[k] >= '0' && v[k] <= '9'; k++) s = s * 10 + (u64)(v[k] - '0');
    return s;
}

static void pax_parse(gz_tar_parser *t)
{
    u32 i = 0, n = t->meta_len;
    const u8 *m = t->meta;
    while (i < n) {
        u32 len = 0, j = i;
        while (j < n && m[j] >= '0' && m[j] <= '9') {
            len = len * 10 + (u32)(m[j++] - '0');
            if (len > n) break;                         /* cannot overflow u32 */
        }
        /* the record "<len> <key>=<value>\n" must cover its own length field */
        if (j >= n || m[j] != ' ' || len <= j + 1 - i || len > n - i) break;
        const u8 *kv = m + j + 1;
        u32 kvn = i + len - (j + 1);
        if (kvn && kv[kvn - 1] == '\n') kvn--;
        u32 eq = 0;
        while (eq < kvn && kv[eq] != '=') eq++;
        if (eq < kvn) {
            const u8 *v = kv + eq + 1;
            u32 vn = kvn - eq - 1;
            if (eq == 4 && !__builtin_memcmp(kv, "path", 4)) set_bytes(&t->pname, &t->pname_len, v, vn);
            else if (eq == 8 && !__builtin_memcmp(kv, "linkpath", 8)) set_bytes(&t->plink, &t->plink_len, v, vn);
            else if (eq == 4 && !__builtin_memcmp(kv, "size", 4)) { t->pax_size = pax_uint(v, vn); t->has_pax_size = 1; }
            else if (eq == 5 && !__builtin_memcmp(kv, "mtime", 5)) {
                int neg = vn && v[0] == '-';
                i64 s = (i64)pax_uint(v + neg, vn - (u32)neg);
                t->pax_mtime = neg ? -s : s;
                t->has_pax_mtime = 1;
            }
        }
        i += len;
    }
}

/* Process a complete 512-byte header. */
static int tp_header(gz_tar_parser *t)
{
    const u8 *h = t->hdr;
    if (is_zero_block(h)) { t->done = 1; return GZ_OK; }
    if (!tar_cksum_ok(h)) return GZ_E_FORMAT;

    u8 type = h[156];
    u64 size = tar_num(h + 124, 12);
    if (t->has_pax_size && type != 'x' && type != 'g') size = t->pax_size;
    u64 pad = (512 - (size & 511)) & 511;
    u64 data_pos = t->pos;              /* t->pos already points past the header */

    if (type == 'L' || type == 'K' || type == 'x') {
        if (size > (16u << 20)) return GZ_E_FORMAT;
        t->meta_kind = type;
        t->meta_len = 0;
        if (t->meta_cap < size + 1) {
            gz_free(t->meta);
            t->meta = (u8 *)gz_alloc((size_t)size + 1);
            if (!t->meta) { t->meta_cap = 0; return GZ_E_NOMEM; }
            t->meta_cap = (u32)size + 1;
        }
        t->mode = 2; t->left = size; t->pad = pad;
        return GZ_OK;
    }
    if (type == 'g' || type == 'V' || type == 'M' || type == 'S' || type == 'N') {
        t->mode = 3; t->left = size; t->pad = pad;
        return GZ_OK;
    }

    /* an actual entry */
    const u8 *nm;
    u32 nlen;
    u8 full[256 + 2];
    int ne = GZ_NE_LEGACY;
    if (t->pname) { nm = t->pname; nlen = t->pname_len; ne = GZ_NE_UTF8; }
    else if (t->lname) { nm = t->lname; nlen = cstr_len(t->lname, t->lname_len); }
    else {
        u32 n1 = cstr_len(h, 100);
        if (!__builtin_memcmp(h + 257, "ustar", 5) && h[345]) {
            u32 n0 = cstr_len(h + 345, 155);
            __builtin_memcpy(full, h + 345, n0);
            full[n0] = '/';
            __builtin_memcpy(full + n0 + 1, h, n1);
            nlen = n0 + 1 + n1;
        } else {
            __builtin_memcpy(full, h, n1);
            nlen = n1;
        }
        nm = full;
    }

    int is_file = (type == '0' || type == 0 || type == '7');
    int is_dir = (type == '5');
    int is_link = type == '2' ? 1 : type == '1' ? 2 : 0;
    u32 mode = (u32)tar_num(h + 100, 8);
    i64 mt = t->has_pax_mtime ? t->pax_mtime : (i64)tar_num(h + 136, 12);

    if (is_file || is_dir || is_link) {
        if (!t->extracting) {
            gz_entry *e;
            int r = gz_arc_add_named(t->a, nm, nlen, ne, &e);
            if (r) return r;
            e->is_dir = (u8)(is_dir || (nlen && nm[nlen - 1] == '/'));
            e->is_link = (u8)is_link;
            e->usize = e->csize = is_file ? size : 0;
            e->off = data_pos;
            e->mtime = gz_unix_to_filetime(mt);
            e->mtime_kind = GZ_MT_FILETIME;
            e->unix_mode = (mode & 07777) | (e->is_dir ? 0040000u : is_link == 1 ? 0120000u : 0100000u);
            if (mode && !(mode & 0200)) e->attr |= 1;
            if (e->is_dir) e->attr |= 0x10;
            if (is_link) {
                const u8 *lk = t->plink ? t->plink : t->llink;
                u32 ln = t->plink ? t->plink_len : t->llink ? cstr_len(t->llink, t->llink_len) : 0;
                if (!lk) { lk = h + 157; ln = cstr_len(h + 157, 100); }
                u32 lo;
                if (ln && !gz_arc_raw_append(t->a, lk, ln, &lo)) {
                    e = &t->a->e[t->a->n - 1];
                    e->link_off = lo;
                    e->link_len = ln;
                }
            }
        } else {
            u32 idx = t->next_idx;
            t->cur = -1;
            if (idx < t->a->n && t->sel[idx]) {
                /* links go through open() too, so the engine can report or create them */
                int r = t->out->open(t->out, idx);
                if (r == GZ_OK) {
                    if (!is_file || size == 0) t->out->close(t->out, idx, GZ_OK);
                    else { t->cur = (i32)idx; t->cur_status = GZ_OK; }
                } else if (r == GZ_E_CANCEL) {
                    return GZ_E_CANCEL;
                }   /* other errors were already reported by the engine */
            }
        }
        t->next_idx++;
    }
    clear_pending(t);

    if (is_file && size) { t->mode = 1; t->left = size; t->pad = pad; }
    else if (size && !is_dir) { t->mode = 3; t->left = size; t->pad = pad; }
    else { t->mode = 0; t->left = 0; t->pad = 0; }
    return GZ_OK;
}

static void meta_done(gz_tar_parser *t)
{
    t->meta[t->meta_len] = 0;
    if (t->meta_kind == 'L') set_bytes(&t->lname, &t->lname_len, t->meta, cstr_len(t->meta, t->meta_len));
    else if (t->meta_kind == 'K') set_bytes(&t->llink, &t->llink_len, t->meta, cstr_len(t->meta, t->meta_len));
    else pax_parse(t);
}

int gz_tar_feed(void *parser, const u8 *p, size_t n)
{
    gz_tar_parser *t = (gz_tar_parser *)parser;
    while (n && !t->done) {
        if (t->mode == 0) {
            u32 take = 512 - t->hpos;
            if (take > n) take = (u32)n;
            __builtin_memcpy(t->hdr + t->hpos, p, take);
            t->hpos += take; p += take; n -= take; t->pos += take;
            if (t->hpos == 512) {
                t->hpos = 0;
                int r = tp_header(t);
                if (r) return r;
            }
            continue;
        }
        if (t->left) {
            size_t take = n < t->left ? n : (size_t)t->left;
            if (t->mode == 1 && t->extracting && t->cur >= 0 && t->cur_status == GZ_OK) {
                int r = t->out->write(t->out, p, take);
                if (r) {
                    t->cur_status = r;
                    if (r == GZ_E_CANCEL) return r;
                }
            } else if (t->mode == 2) {
                __builtin_memcpy(t->meta + t->meta_len, p, take);
                t->meta_len += (u32)take;
            }
            t->left -= take; p += take; n -= take; t->pos += take;
            if (!t->left) {
                if (t->mode == 1 && t->extracting && t->cur >= 0) {
                    t->out->close(t->out, (u32)t->cur, t->cur_status);
                    t->cur = -1;
                }
                if (t->mode == 2) meta_done(t);
            }
            continue;
        }
        if (t->pad) {
            size_t take = n < t->pad ? n : (size_t)t->pad;
            t->pad -= take; p += take; n -= take; t->pos += take;
            continue;
        }
        t->mode = 0;
    }
    if (t->c && gz_cancelled(t->c)) return GZ_E_CANCEL;
    return GZ_OK;
}

int gz_tar_finish(gz_tar_parser *t, int status)
{
    if (t->extracting && t->cur >= 0) {
        t->out->close(t->out, (u32)t->cur, status ? status : GZ_E_TRUNC);
        t->cur = -1;
        return status ? status : GZ_E_TRUNC;
    }
    return status;
}

/* ---------------- plain TAR (random access) ---------------- */

static int tar_probe(gz_src *s, const u8 *head, u32 n)
{
    (void)s;
    if (n < 512 || !gz_tar_header_ok(head)) return 0;
    return !__builtin_memcmp(head + 257, "ustar", 5) ? 95 : 70;
}

static int tar_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    gz_tar_parser *t = gz_tar_parser_new(a, 0, 0, c);
    if (!t) return GZ_E_NOMEM;
    u64 off = 0;
    u8 *buf = (u8 *)gz_alloc(65536);
    if (!buf) { gz_tar_parser_free(t); return GZ_E_NOMEM; }
    int r = GZ_OK;
    while (!t->done && off + 512 <= s->size) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        if (t->mode == 0) {
            r = gz_src_read_exact(s, off, t->hdr, 512);
            if (r) break;
            off += 512;
            t->pos = off;
            r = tp_header(t);
            if (r) break;
        } else if (t->mode == 1 || t->mode == 3) {     /* skip data */
            u64 rem = s->size - off;                    /* off <= size here */
            if (t->left > rem || t->pad > rem - t->left) { r = GZ_E_TRUNC; break; }
            off += t->left + t->pad;
            t->pos = off;
            t->left = t->pad = 0;
            t->mode = 0;
        } else {                                       /* read meta data */
            u32 n = t->left > 65536 ? 65536 : (u32)t->left;
            r = gz_src_read_exact(s, off, buf, n);
            if (r) break;
            off += n;
            r = gz_tar_feed(t, buf, n);
            if (r) break;
            if (!t->left) { off += t->pad; t->pad = 0; t->mode = 0; }
        }
    }
    gz_free(buf);
    gz_tar_parser_free(t);
    if (r == GZ_E_CANCEL || r == GZ_E_NOMEM) return r;
    if (r && a->n == 0) return r;
    return GZ_OK;      /* tolerate a damaged tail: entries found so far */
}

static int tar_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    return gz_extract_stored(a, s, idx, a->e[idx].off, out, c);
}

static void tar_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a; (void)e;
    if (cap >= 6) __builtin_memcpy(buf, "Store", 6);
}

static gz_src *tar_view(gz_archive *a, gz_src *s, u32 idx)
{
    gz_entry *e = &a->e[idx];
    if (e->is_dir || e->is_link) return 0;
    return gz_src_sub(s, e->off, e->usize);
}

GZ_FORMAT(gz_fmt_tar)
const gz_format gz_fmt_tar = {
    "TAR", "tar", 0, tar_probe, tar_open, 0, tar_extract, 0, 0, tar_method, tar_view, 0
};
