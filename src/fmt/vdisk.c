/*
 * 고깃ZIP - shared plumbing for virtual disk images (see vdisk.h)
 */
#include "vdisk.h"

/* ---------------- view ---------------- */

static void fill_pattern(u8 *p, u32 n, u32 fill, u64 off)
{
    u8 pat[64];
    for (u32 i = 0; i < 64; i++) pat[i] = (u8)(fill >> (8 * ((off + i) & 3)));
    while (n >= 64) { __builtin_memcpy(p, pat, 64); p += 64; n -= 64; }
    if (n) __builtin_memcpy(p, pat, n);
}

static int vd_read(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    gz_vd_view *v = (gz_vd_view *)s;
    *got = 0;
    if (off >= s->size) return GZ_OK;
    if (n > s->size - off) n = (u32)(s->size - off);
    u8 *p = (u8 *)buf;
    u32 left = n;
    /* pending raw run, flushed when the next raw extent is not contiguous */
    gz_src *rs = 0;
    u64 rpos = 0;
    u8 *rdst = 0;
    u32 rlen = 0;
    int r;
    while (left) {
        gz_vd_ext x;
        x.kind = GZ_VD_ZERO; x.fill = 0; x.len = 0; x.src = 0; x.pos = 0; x.mem = 0;
        r = v->map(v, off, &x);
        if (r) return r;
        if (!x.len) return GZ_E_FORMAT;              /* a map must make progress */
        u32 take = x.len < left ? (u32)x.len : left;
        if (x.kind == GZ_VD_RAW) {
            gz_src *src = x.src ? x.src : v->file;
            if (x.pos > src->size || take > src->size - x.pos) return GZ_E_TRUNC;
            if (rlen && src == rs && x.pos == rpos + rlen && p == rdst + rlen) {
                rlen += take;
            } else {
                if (rlen && (r = gz_src_read_exact(rs, rpos, rdst, rlen))) return r;
                rs = src; rpos = x.pos; rdst = p; rlen = take;
            }
        } else if (x.kind == GZ_VD_ZERO || (x.kind == GZ_VD_PARENT && !v->parent)) {
            __builtin_memset(p, 0, take);
        } else if (x.kind == GZ_VD_MEM) {
            __builtin_memcpy(p, x.mem, take);
        } else if (x.kind == GZ_VD_FILL) {
            fill_pattern(p, take, x.fill, off);
        } else if (x.kind == GZ_VD_PARENT) {
            if (off >= v->parent->size) __builtin_memset(p, 0, take);
            else {
                u32 in = v->parent->size - off < take ? (u32)(v->parent->size - off) : take;
                if ((r = gz_src_read_exact(v->parent, off, p, in))) return r;
                if (in < take) __builtin_memset(p + in, 0, take - in);
            }
        } else {
            return GZ_E_FORMAT;
        }
        p += take;
        off += take;
        left -= take;
    }
    if (rlen && (r = gz_src_read_exact(rs, rpos, rdst, rlen))) return r;
    *got = n;
    return GZ_OK;
}

static void vd_free(gz_src *s)
{
    gz_vd_view *v = (gz_vd_view *)s;
    if (v->fini) v->fini(v);
    if (v->z) gz_inflater_free(v->z);
    gz_src_free(v->parent);
    gz_free(v);
}

gz_vd_view *gz_vd_view_new(size_t sz, gz_src *file, const void *img, u64 size, gz_vd_map_fn map)
{
    if (sz < sizeof(gz_vd_view)) sz = sizeof(gz_vd_view);
    gz_vd_view *v = (gz_vd_view *)gz_alloc(sz);
    if (!v) return 0;
    v->s.read_at = vd_read;
    v->s.size = size;
    v->s.free = vd_free;
    v->file = file;
    v->img = img;
    v->map = map;
    return v;
}

/* ---------------- deflate helper ---------------- */

typedef struct { u8 *dst; u32 cap, n; } buf_sink;

static int buf_write(void *user, const u8 *p, size_t n)
{
    buf_sink *k = (buf_sink *)user;
    if (n > (size_t)(k->cap - k->n)) return GZ_E_DATA;
    __builtin_memcpy(k->dst + k->n, p, n);
    k->n += (u32)n;
    return GZ_OK;
}

int gz_vd_inflate(gz_vd_view *v, gz_src *src, u64 pos, u64 len, int zlib, u8 *dst, u32 cap, u32 *outn)
{
    *outn = 0;
    if (pos > src->size || len > src->size - pos) return GZ_E_TRUNC;
    if (zlib) {
        u8 h[2];
        if (len < 2) return GZ_E_DATA;
        int r = gz_src_read_exact(src, pos, h, 2);
        if (r) return r;
        /* CM 8, window <= 32K, check bits, no preset dictionary */
        if ((h[0] & 15) != 8 || (h[0] >> 4) > 7 || ((h[0] << 8) | h[1]) % 31 || (h[1] & 0x20))
            return GZ_E_DATA;
        pos += 2;
        len -= 2;
    }
    if (!v->z && !(v->z = gz_inflater_new())) return GZ_E_NOMEM;
    buf_sink k = { dst, cap, 0 };
    gz_pipe pp = { { src, pos, pos + len, 0 }, buf_write, &k };
    gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };
    int r = gz_inflate_run(v->z, &io, 0);
    *outn = k.n;
    return r;
}

/* ---------------- entries ---------------- */

static int is_sep(gzch c) { return c == '/' || c == '\\'; }

int gz_vd_add_disk(gz_archive *a, const gz_open_opts *o, u64 vsize, u64 csize, gz_entry **pe)
{
    gzch nm[208];
    u32 n = 0;
    const gzch *fn = o ? o->file_name : 0;
    if (fn) {
        const gzch *b = fn;
        for (const gzch *p = fn; *p; p++) if (is_sep(*p)) b = p + 1;
        u32 len = 0, dot = 0;
        while (b[len] && len < 4096) { if (b[len] == '.' && len) dot = len; len++; }
        if (dot) len = dot;
        if (len > 192) len = 192;
        for (; n < len; n++) nm[n] = b[n];
    }
    if (!n) { nm[0] = 'd'; nm[1] = 'i'; nm[2] = 's'; nm[3] = 'k'; n = 4; }
    int has_img = n > 4 && nm[n - 4] == '.' && (nm[n - 3] | 32) == 'i' && (nm[n - 2] | 32) == 'm' &&
                  (nm[n - 1] | 32) == 'g';
    if (!has_img) { nm[n++] = '.'; nm[n++] = 'i'; nm[n++] = 'm'; nm[n++] = 'g'; }
    gz_entry *e;
    int r = gz_arc_add_named(a, nm, n * 2, GZ_NE_UTF16LE, &e);   /* gzch is UTF-16LE in memory */
    if (r) return r;
    e->usize = vsize;
    e->csize = csize;
    e->attr = 0x20;
    if (pe) *pe = e;
    return GZ_OK;
}

int gz_vd_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    gz_src *v = a->fmt->view ? a->fmt->view(a, s, idx) : 0;
    if (!v) return GZ_E_NOMEM;
    int r = out->open(out, idx);
    if (r) { gz_src_free(v); return r; }
    u64 n = e->usize == GZ_SIZE_UNKNOWN ? v->size : e->usize;
    int st = gz_copy_range(v, 0, n, out, c, 0);
    gz_src_free(v);
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

/* ---------------- referenced files ---------------- */

/* dir + name; separators in name follow the style of dir ('\\' only if dir uses it alone) */
static int try_open(const gz_open_opts *o, const gzch *dir, u32 dn, const gzch *name, u32 len, gz_src **out)
{
    gzch *p = (gzch *)gz_alloc(((size_t)dn + len + 1) * sizeof(gzch));
    if (!p) return GZ_E_NOMEM;
    gzch sep = '/';
    const gzch *fn = o->file_name;
    if (fn) {
        int fwd = 0, back = 0;
        for (u32 i = 0; fn[i] && i < 32768; i++) { fwd |= fn[i] == '/'; back |= fn[i] == '\\'; }
        if (back && !fwd) sep = '\\';
    }
    for (u32 i = 0; i < dn; i++) p[i] = dir[i];
    for (u32 i = 0; i < len; i++) p[dn + i] = is_sep(name[i]) ? sep : name[i];
    p[dn + len] = 0;
    *out = 0;
    int r = o->open_volume(o->user, p, out);
    gz_free(p);
    if (!r && !*out) r = GZ_E_VOLUME;
    return r;
}

int gz_vd_open_file16(gz_archive *a, const gz_open_opts *o, const gzch *name, u32 len, gz_src **out)
{
    *out = 0;
    if (!o || !o->open_volume || !len) return GZ_E_VOLUME;
    if (a->nvols >= GZ_VD_MAX_FILES) return GZ_E_LIMIT;
    gz_src **nv = (gz_src **)gz_realloc(a->vols, ((size_t)a->nvols + 1) * sizeof(gz_src *));
    if (!nv) return GZ_E_NOMEM;
    a->vols = nv;
    const gzch *fn = o->file_name;
    u32 dn = 0;
    if (fn) for (u32 i = 0; fn[i] && i < 32768; i++) if (is_sep(fn[i])) dn = i + 1;
    u32 base = 0;
    for (u32 i = 0; i < len; i++) if (is_sep(name[i])) base = i + 1;
    int abs = is_sep(name[0]) || (len > 2 && name[1] == ':' && is_sep(name[2]));
    gz_src *s = 0;
    int r = abs ? try_open(o, 0, 0, name, len, &s) : try_open(o, fn, dn, name, len, &s);
    if (r && r != GZ_E_CANCEL && r != GZ_E_NOMEM && abs && base < len)
        r = try_open(o, fn, dn, name + base, len - base, &s);
    if (r) return (r == GZ_E_CANCEL || r == GZ_E_NOMEM) ? r : GZ_E_VOLUME;
    a->vols[a->nvols++] = s;
    *out = s;
    return GZ_OK;
}

int gz_vd_open_file(gz_archive *a, const gz_open_opts *o, const u8 *name, u32 len, gz_src **out)
{
    *out = 0;
    if (!len || len > 4096) return GZ_E_VOLUME;
    gzch *w = (gzch *)gz_alloc(((size_t)len + 1) * sizeof(gzch));
    if (!w) return GZ_E_NOMEM;
    u32 n;
    if (gz_utf8_valid(name, len)) n = (u32)gz_utf8_to_utf16(name, len, w);
    else for (n = 0; n < len; n++) w[n] = name[n];
    int r = gz_vd_open_file16(a, o, w, n, out);
    gz_free(w);
    return r;
}

void gz_vd_note(gz_archive *a, const char *text, u32 n)
{
    u8 *p = (u8 *)gz_alloc(n + 1);
    if (!p) return;
    __builtin_memcpy(p, text, n);
    gz_free(a->comment_raw);
    a->comment_raw = p;
    a->comment_len = n;
    a->comment_enc = GZ_NE_UTF8;
}

void gz_vd_method_str(char *buf, u32 cap, const char *s)
{
    u32 i = 0;
    if (!cap) return;
    for (; s[i] && i + 1 < cap; i++) buf[i] = s[i];
    buf[i] = 0;
}
