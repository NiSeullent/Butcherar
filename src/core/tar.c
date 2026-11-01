/*
 * 고깃ZIP - TAR (ustar / GNU / pax), GZIP and TAR.GZ
 */
#include "arc.h"
#include "crc32.h"

/* ---------------- tar header helpers ---------------- */

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

int gz_tar_probe(const u8 *head, u32 n)
{
    if (n < 512) return 0;
    if (is_zero_block(head)) return 0;
    return tar_cksum_ok(head);
}

static u32 cstr_len(const u8 *p, u32 max)
{
    u32 n = 0;
    while (n < max && p[n]) n++;
    return n;
}

/* Streaming tar parser (used for listing and for solid extraction). */
typedef struct {
    gz_archive *a;
    u8 hdr[512];
    u32 hpos;
    int mode;                /* 0 header, 1 data (entry), 2 meta data (L / x), 3 skip data */
    u64 left, pad;
    u64 pos;                 /* stream offset */
    u8 *meta; u32 meta_len, meta_cap;
    int meta_kind;           /* 'L' or 'x' */
    u8 *lname; u32 lname_len;           /* pending long name for next header */
    u8 *pname; u32 pname_len;           /* pending pax path */
    u64 pax_size; int has_pax_size;
    i64 pax_mtime; int has_pax_mtime;
    int done;
    /* extraction */
    int extracting;
    const u8 *sel;
    gz_out *out;
    u32 next_idx;
    i32 cur;                 /* current entry index being written, -1 none */
    int cur_status;
    volatile long *cancel;
    int list_only_seek;      /* random access listing: don't consume data */
} tar_parser;

static void tp_free(tar_parser *t)
{
    gz_free(t->meta);
    gz_free(t->lname);
    gz_free(t->pname);
}

static u8 *dup_bytes(const u8 *p, u32 n)
{
    u8 *d = (u8 *)gz_alloc(n + 1);
    if (d) __builtin_memcpy(d, p, n);
    return d;
}

static void pax_parse(tar_parser *t)
{
    u32 i = 0, n = t->meta_len;
    const u8 *m = t->meta;
    while (i < n) {
        u32 len = 0, j = i;
        while (j < n && m[j] >= '0' && m[j] <= '9') {
            len = len * 10 + (m[j++] - '0');
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
            if (eq == 4 && !__builtin_memcmp(kv, "path", 4)) {
                gz_free(t->pname);
                t->pname = dup_bytes(v, vn);
                t->pname_len = t->pname ? vn : 0;
            } else if (eq == 4 && !__builtin_memcmp(kv, "size", 4)) {
                u64 s = 0;
                for (u32 k = 0; k < vn && v[k] >= '0' && v[k] <= '9'; k++) s = s * 10 + (v[k] - '0');
                t->pax_size = s; t->has_pax_size = 1;
            } else if (eq == 5 && !__builtin_memcmp(kv, "mtime", 5)) {
                i64 s = 0;
                for (u32 k = 0; k < vn && v[k] >= '0' && v[k] <= '9'; k++) s = s * 10 + (v[k] - '0');
                t->pax_mtime = s; t->has_pax_mtime = 1;
            }
        }
        i += len;
    }
}

/* Process a complete 512-byte header. Returns error code. */
static int tp_header(tar_parser *t)
{
    const u8 *h = t->hdr;
    if (is_zero_block(h)) { t->done = 1; return GZ_OK; }
    if (!tar_cksum_ok(h)) return GZ_E_FORMAT;

    u8 type = h[156];
    u64 size = tar_num(h + 124, 12);
    if (t->has_pax_size && type != 'x' && type != 'g') size = t->pax_size;
    u64 pad = (512 - (size & 511)) & 511;
    u64 data_pos = t->pos;              /* t->pos already points past the header */

    if (type == 'L' || type == 'x') {
        if (size > (16u << 20)) return GZ_E_FORMAT;
        t->meta_kind = type;
        t->meta_len = 0;
        if (t->meta_cap < size + 1) {
            gz_free(t->meta);
            t->meta = (u8 *)gz_alloc((size_t)size + 1);
            if (!t->meta) return GZ_E_NOMEM;
            t->meta_cap = (u32)size + 1;
        }
        t->mode = 2; t->left = size; t->pad = pad;
        return GZ_OK;
    }
    if (type == 'g' || type == 'K' || type == 'V' || type == 'M' || type == 'S' || type == 'N') {
        t->mode = 3; t->left = size; t->pad = pad;
        return GZ_OK;
    }

    /* an actual entry */
    const u8 *nm;
    u32 nlen;
    u8 full[256 + 2];
    int utf8 = 0;
    if (t->pname) { nm = t->pname; nlen = t->pname_len; utf8 = 1; }
    else if (t->lname) { nm = t->lname; nlen = t->lname_len; }
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
    int is_link = (type == '1' || type == '2');
    u32 mode = (u32)tar_num(h + 100, 8);
    i64 mt = t->has_pax_mtime ? t->pax_mtime : (i64)tar_num(h + 136, 12);

    if (is_file || is_dir || is_link) {
        if (!t->extracting) {
            gz_entry *e;
            if (gz_arc_add_entry(t->a, &e)) return GZ_E_NOMEM;
            if (gz_arc_raw_append(t->a, nm, nlen, &e->raw_off)) return GZ_E_NOMEM;
            e->raw_len = (u16)(nlen > 65535 ? 65535 : nlen);
            e->utf8 = (u8)utf8;
            e->is_dir = (u8)(is_dir || (nlen && nm[nlen - 1] == '/'));
            e->is_link = (u8)is_link;
            e->usize = e->csize = is_file ? size : 0;
            e->off = data_pos;
            e->mtime = gz_unix_to_filetime(mt);
            e->mtime_kind = GZ_MT_FILETIME;
            if (mode && !(mode & 0200)) e->attr |= 1;
            if (e->is_dir) e->attr |= 0x10;
        } else {
            u32 idx = t->next_idx;
            t->cur = -1;
            if (idx < t->a->n && t->sel[idx]) {
                /* links go through open() too, so the engine can report them as skipped */
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
    gz_free(t->lname); t->lname = 0; t->lname_len = 0;
    gz_free(t->pname); t->pname = 0; t->pname_len = 0;
    t->has_pax_size = t->has_pax_mtime = 0;

    if (is_file && size) { t->mode = 1; t->left = size; t->pad = pad; }
    else if (size && !is_dir && !is_link) { t->mode = 3; t->left = size; t->pad = pad; }
    else if (size && is_link) { t->mode = 3; t->left = size; t->pad = pad; }
    else { t->mode = 0; t->left = 0; t->pad = 0; }
    return GZ_OK;
}

static int tp_feed(tar_parser *t, const u8 *p, size_t n)
{
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
                if (t->mode == 2) {
                    t->meta[t->meta_len] = 0;
                    if (t->meta_kind == 'L') {
                        gz_free(t->lname);
                        u32 ln = cstr_len(t->meta, t->meta_len);
                        t->lname = dup_bytes(t->meta, ln);
                        t->lname_len = t->lname ? ln : 0;
                    } else {
                        pax_parse(t);
                    }
                }
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
    return GZ_OK;
}

/* ---------------- plain TAR (random access) ---------------- */

int gz_tar_open(gz_archive *a, gz_src *s)
{
    tar_parser t;
    __builtin_memset(&t, 0, sizeof t);
    t.a = a;
    a->type = GZ_ARC_TAR;
    u64 off = 0;
    u8 *buf = (u8 *)gz_alloc(65536);
    if (!buf) return GZ_E_NOMEM;
    int r = GZ_OK;
    while (!t.done && off + 512 <= s->size) {
        u32 got;
        if (t.mode == 0) {
            r = s->read_at(s, off, t.hdr, 512, &got);
            if (r) break;
            if (got < 512) break;
            off += 512;
            t.pos = off;
            r = tp_header(&t);
            if (r) break;
        } else if (t.mode == 1 || t.mode == 3) {     /* skip data */
            u64 rem = s->size - off;                  /* off <= size here */
            if (t.left > rem || t.pad > rem - t.left) { r = GZ_E_TRUNC; break; }
            off += t.left + t.pad;
            t.pos = off;
            t.left = t.pad = 0;
            t.mode = 0;
        } else {                                     /* read meta data */
            u32 n = t.left > 65536 ? 65536 : (u32)t.left;
            r = s->read_at(s, off, buf, n, &got);
            if (r || got != n) { r = r ? r : GZ_E_TRUNC; break; }
            off += n;
            r = tp_feed(&t, buf, n);
            if (r) break;
            if (!t.left) { off += t.pad; t.pad = 0; t.mode = 0; }
        }
    }
    gz_free(buf);
    tp_free(&t);
    if (r && a->n == 0) return r;
    return GZ_OK;
}

typedef struct {
    gz_src *src;
    u64 pos, end;
    gz_out *out;
} plain_reader;

static int pr_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    plain_reader *r = (plain_reader *)ctx;
    u64 left = r->end - r->pos;
    *got = 0;
    if (!left) return GZ_OK;
    u32 n = cap;
    if (n > left) n = (u32)left;
    u32 g = 0;
    int e = r->src->read_at(r->src, r->pos, buf, n, &g);
    if (e) return e;
    if (!g) return GZ_E_TRUNC;
    r->pos += g;
    *got = g;
    return GZ_OK;
}

static int pr_write(void *ctx, const u8 *p, size_t n)
{
    plain_reader *r = (plain_reader *)ctx;
    return r->out->write(r->out, p, n);
}

int gz_tar_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_inflater *z)
{
    gz_entry *e = &a->e[idx];
    int r = out->open(out, idx);              /* the engine reports links as skipped */
    if (r) return r;
    if (e->is_dir || e->is_link || !e->usize) return out->close(out, idx, GZ_OK);
    plain_reader pr = { s, e->off, e->off + e->usize, out };
    gz_stream_io io = { pr_read, pr_write, &pr };
    int st = gz_store_run(z, &io);
    if (!st && z->total_out != e->usize) st = GZ_E_TRUNC;
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

/* ---------------- GZIP ---------------- */

/* parse gzip member header at off; returns data offset or 0 on error */
static int gzip_header(gz_src *s, u64 off, u64 *data, u8 *name, u32 *namelen, u32 *mtime)
{
    u8 h[10];
    u32 got;
    if (s->read_at(s, off, h, 10, &got) || got != 10) return GZ_E_TRUNC;
    if (h[0] != 0x1f || h[1] != 0x8b || h[2] != 8) return GZ_E_FORMAT;
    u8 flg = h[3];
    if (mtime) *mtime = rd32(h + 4);
    u64 p = off + 10;
    if (flg & 4) {
        u8 x[2];
        if (s->read_at(s, p, x, 2, &got) || got != 2) return GZ_E_TRUNC;
        p += 2 + rd16(x);
    }
    for (int k = 0; k < 2; k++) {
        u8 bit = k == 0 ? 8 : 16;
        if (!(flg & bit)) continue;
        u8 c[256];
        u32 nl = 0;
        for (;;) {
            if (s->read_at(s, p, c, sizeof c, &got) || !got) return GZ_E_TRUNC;
            u32 i = 0;
            while (i < got && c[i]) i++;
            if (k == 0 && name) {
                for (u32 j = 0; j < i && nl < 255; j++) name[nl++] = c[j];
            }
            p += i;
            if (i < got) { p++; break; }
        }
        if (k == 0 && namelen) *namelen = nl;
    }
    if (flg & 2) p += 2;
    *data = p;
    return GZ_OK;
}

typedef struct {
    gz_src *src;
    u64 pos, end;
    int (*sink)(void *u, const u8 *p, size_t n);
    void *user;
    volatile long *cancel;
} gz_reader;

static int gzr_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    gz_reader *r = (gz_reader *)ctx;
    if (r->cancel && *r->cancel) return GZ_E_CANCEL;
    u64 left = r->end - r->pos;
    *got = 0;
    if (!left) return GZ_OK;
    u32 n = cap;
    if (n > left) n = (u32)left;
    u32 g = 0;
    int e = r->src->read_at(r->src, r->pos, buf, n, &g);
    if (e) return e;
    r->pos += g;
    *got = g;
    return GZ_OK;
}

static int gzr_write(void *ctx, const u8 *p, size_t n)
{
    gz_reader *r = (gz_reader *)ctx;
    return r->sink(r->user, p, n);
}

/* Decode all gzip members starting at a->gz_off into sink. */
static int gzip_stream(gz_archive *a, gz_src *s, gz_inflater *z,
                       int (*sink)(void *, const u8 *, size_t), void *user,
                       volatile long *cancel, u64 *total)
{
    u64 data = a->gz_off;
    *total = 0;
    for (int member = 0;; member++) {
        gz_reader rd = { s, data, s->size, sink, user, cancel };
        gz_stream_io io = { gzr_read, gzr_write, &rd };
        int r = gz_inflate_run(z, &io, 0);
        if (r) return r;
        *total += z->total_out;
        u64 end = rd.pos - z->rest_len;
        u8 tr[8];
        u32 got;
        if (s->read_at(s, end, tr, 8, &got) || got != 8) return GZ_E_TRUNC;
        if (rd32(tr) != z->crc) return GZ_E_CRC;
        if (rd32(tr + 4) != (u32)z->total_out) return GZ_E_DATA;
        u64 next = end + 8;
        u8 h[2];
        if (next + 18 > s->size) break;
        if (s->read_at(s, next, h, 2, &got) || got != 2 || h[0] != 0x1f || h[1] != 0x8b) break;
        if (gzip_header(s, next, &data, 0, 0, 0)) break;
    }
    return GZ_OK;
}

/* tar listing sink */
static int tar_list_sink(void *u, const u8 *p, size_t n)
{
    tar_parser *t = (tar_parser *)u;
    if (t->done) return GZ_OK;
    int r = tp_feed(t, p, n);
    return r;
}

typedef struct { u8 buf[512]; u32 n; } peek_sink;
static int peek_write(void *u, const u8 *p, size_t n)
{
    peek_sink *k = (peek_sink *)u;
    while (n && k->n < 512) { k->buf[k->n++] = *p++; n--; }
    return k->n >= 512 ? GZ_E_SKIP : GZ_OK;
}

int gz_gzip_open(gz_archive *a, gz_src *s, const wchar_t *file_name, gz_inflater *z,
                 volatile long *cancel)
{
    u8 name[256];
    u32 nlen = 0, mt = 0;
    u64 data;
    int r = gzip_header(s, 0, &data, name, &nlen, &mt);
    if (r) return r;
    a->gz_off = data;
    a->type = GZ_ARC_GZIP;
    u8 isz[4] = { 0, 0, 0, 0 };
    u32 got;
    if (s->size >= 18) s->read_at(s, s->size - 4, isz, 4, &got);
    a->gz_isize = rd32(isz);

    /* is it a tarball? peek at the first decompressed block */
    peek_sink pk;
    pk.n = 0;
    {
        gz_reader rd = { s, data, s->size, peek_write, &pk, cancel };
        gz_stream_io io = { gzr_read, gzr_write, &rd };
        r = gz_inflate_run(z, &io, 0);
        if (r && r != GZ_E_SKIP) {
            if (r == GZ_E_CANCEL) return r;
            /* corrupt stream: still list as single file */
        }
    }
    if (pk.n == 512 && tar_cksum_ok(pk.buf) && !is_zero_block(pk.buf)) {
        tar_parser t;
        __builtin_memset(&t, 0, sizeof t);
        t.a = a;
        u64 total;
        r = gzip_stream(a, s, z, tar_list_sink, &t, cancel, &total);
        tp_free(&t);
        if (r == GZ_E_CANCEL) return r;
        if (a->n > 0) {
            a->type = GZ_ARC_TGZ;
            a->solid = 1;
            return GZ_OK;      /* tolerate damaged tail: entries found so far */
        }
        a->n = 0;
        a->raw_len = 0;
    }

    /* single compressed file */
    gz_entry *e;
    if (gz_arc_add_entry(a, &e)) return GZ_E_NOMEM;
    if (nlen) {
        if (gz_arc_raw_append(a, name, nlen, &e->raw_off)) return GZ_E_NOMEM;
        e->raw_len = (u16)nlen;
    } else {
        /* derive from archive name: strip ".gz", ".tgz" -> ".tar" */
        u8 tmp[512];
        u32 tn = 0;
        const wchar_t *fn = file_name ? file_name : L"data.gz";
        const wchar_t *b1 = gz_wcsrchr(fn, '\\'), *b2 = gz_wcsrchr(fn, '/');
        const wchar_t *base = b1 > b2 ? b1 + 1 : (b2 ? b2 + 1 : fn);
        size_t bl = gz_wcslen(base);
        int tgz = 0;
        if (bl > 3 && !gz_wcsicmp_ascii(base + bl - 3, L".gz")) bl -= 3;
        else if (bl > 4 && !gz_wcsicmp_ascii(base + bl - 4, L".tgz")) { bl -= 4; tgz = 1; }
        /* encode as UTF-8 */
        for (size_t i = 0; i < bl && tn < 500; i++) {
            u32 c = (u16)base[i];
            if (c < 0x80) tmp[tn++] = (u8)c;
            else if (c < 0x800) { tmp[tn++] = (u8)(0xC0 | (c >> 6)); tmp[tn++] = (u8)(0x80 | (c & 63)); }
            else { tmp[tn++] = (u8)(0xE0 | (c >> 12)); tmp[tn++] = (u8)(0x80 | ((c >> 6) & 63)); tmp[tn++] = (u8)(0x80 | (c & 63)); }
        }
        if (tgz) { __builtin_memcpy(tmp + tn, ".tar", 4); tn += 4; }
        if (!tn) { __builtin_memcpy(tmp, "data", 4); tn = 4; }
        if (gz_arc_raw_append(a, tmp, tn, &e->raw_off)) return GZ_E_NOMEM;
        e->raw_len = (u16)tn;
        e->utf8 = 1;
    }
    e->usize = a->gz_isize;
    e->csize = s->size;
    e->off = data;
    if (mt) { e->mtime = gz_unix_to_filetime(mt); e->mtime_kind = GZ_MT_FILETIME; }
    e->attr = 0x20;
    return GZ_OK;
}

typedef struct { gz_out *out; } gz_out_sink;
static int gz_single_sink(void *u, const u8 *p, size_t n)
{
    gz_out_sink *k = (gz_out_sink *)u;
    return k->out->write(k->out, p, n);
}

int gz_gzip_extract(gz_archive *a, gz_src *s, gz_out *out, gz_inflater *z)
{
    int r = out->open(out, 0);
    if (r) return r;
    gz_out_sink k = { out };
    u64 total;
    int st = gzip_stream(a, s, z, gz_single_sink, &k, 0, &total);
    if (!st) a->e[0].usize = total;
    int cr = out->close(out, 0, st);
    return st ? st : cr;
}

int gz_tgz_extract(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_inflater *z,
                   volatile long *cancel)
{
    tar_parser t;
    __builtin_memset(&t, 0, sizeof t);
    t.a = a;
    t.extracting = 1;
    t.sel = sel;
    t.out = out;
    t.cur = -1;
    t.cancel = cancel;
    u64 total;
    int r = gzip_stream(a, s, z, tar_list_sink, &t, cancel, &total);
    if (t.cur >= 0) out->close(out, (u32)t.cur, r ? r : GZ_E_TRUNC);
    tp_free(&t);
    return r;
}
