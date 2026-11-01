/*
 * 고깃ZIP - byte sources and stream helpers
 */
#include "stream.h"

int gz_src_read_exact(gz_src *s, u64 off, void *buf, u32 n)
{
    u8 *p = (u8 *)buf;
    while (n) {
        if (off >= s->size) return GZ_E_TRUNC;
        u32 got = 0;
        int r = s->read_at(s, off, p, n, &got);
        if (r) return r;
        if (!got) return GZ_E_TRUNC;
        p += got;
        off += got;
        n -= got;
    }
    return GZ_OK;
}

void gz_src_free(gz_src *s)
{
    if (s && s->free) s->free(s);
}

/* ---- sub-range view ---- */

typedef struct { gz_src s; gz_src *parent; u64 off; } sub_src;

static int sub_read(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    sub_src *v = (sub_src *)s;
    *got = 0;
    if (off >= s->size) return GZ_OK;
    if (n > s->size - off) n = (u32)(s->size - off);
    return v->parent->read_at(v->parent, v->off + off, buf, n, got);
}

static void sub_free(gz_src *s) { gz_free(s); }

gz_src *gz_src_sub(gz_src *parent, u64 off, u64 len)
{
    sub_src *v = (sub_src *)gz_alloc(sizeof(sub_src));
    if (!v) return 0;
    if (off > parent->size) off = parent->size;
    if (len > parent->size - off) len = parent->size - off;
    /* flatten nested views */
    if (parent->read_at == sub_read) {
        sub_src *p = (sub_src *)parent;
        off += p->off;
        parent = p->parent;
    }
    v->s.read_at = sub_read;
    v->s.size = len;
    v->s.free = sub_free;
    v->parent = parent;
    v->off = off;
    return &v->s;
}

/* ---- memory view ---- */

typedef struct { gz_src s; const u8 *p; int own; } mem_src;

static int mem_read(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    mem_src *m = (mem_src *)s;
    *got = 0;
    if (off >= s->size) return GZ_OK;
    if (n > s->size - off) n = (u32)(s->size - off);
    __builtin_memcpy(buf, m->p + off, n);
    *got = n;
    return GZ_OK;
}

static void mem_free(gz_src *s)
{
    mem_src *m = (mem_src *)s;
    if (m->own) gz_free((void *)m->p);
    gz_free(m);
}

gz_src *gz_src_mem(const void *p, u64 n, int own)
{
    mem_src *m = (mem_src *)gz_alloc(sizeof(mem_src));
    if (!m) return 0;
    m->s.read_at = mem_read;
    m->s.size = n;
    m->s.free = mem_free;
    m->p = (const u8 *)p;
    m->own = own;
    return &m->s;
}

/* ---- concatenation ---- */

typedef struct { gz_src s; u32 n; gz_src **part; u64 *start; } cat_src;

static int cat_read(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    cat_src *c = (cat_src *)s;
    u8 *p = (u8 *)buf;
    *got = 0;
    if (off >= s->size) return GZ_OK;
    if (n > s->size - off) n = (u32)(s->size - off);
    /* binary search the part holding off */
    u32 lo = 0, hi = c->n;
    while (hi - lo > 1) {
        u32 mid = (lo + hi) / 2;
        if (c->start[mid] <= off) lo = mid; else hi = mid;
    }
    u32 i = lo;
    while (n && i < c->n) {
        u64 po = off - c->start[i];
        u64 avail = c->part[i]->size - po;
        u32 take = n < avail ? n : (u32)avail;
        if (take) {
            u32 g = 0;
            int r = c->part[i]->read_at(c->part[i], po, p, take, &g);
            if (r) return r;
            *got += g;
            if (g < take) return GZ_OK;
            p += g; off += g; n -= g;
        }
        i++;
    }
    return GZ_OK;
}

static void cat_free(gz_src *s)
{
    cat_src *c = (cat_src *)s;
    for (u32 i = 0; i < c->n; i++) gz_src_free(c->part[i]);
    gz_free(c->part);
    gz_free(c->start);
    gz_free(c);
}

gz_src *gz_src_concat(gz_src **parts, u32 n)
{
    cat_src *c = (cat_src *)gz_alloc(sizeof(cat_src));
    if (!c) return 0;
    c->part = (gz_src **)gz_alloc((size_t)n * sizeof(gz_src *) + 1);
    c->start = (u64 *)gz_alloc((size_t)n * sizeof(u64) + 1);
    if (!c->part || !c->start) {
        gz_free(c->part); gz_free(c->start); gz_free(c);
        return 0;
    }
    u64 total = 0;
    for (u32 i = 0; i < n; i++) {
        c->part[i] = parts[i];
        c->start[i] = total;
        total += parts[i]->size;
    }
    c->n = n;
    c->s.read_at = cat_read;
    c->s.size = total;
    c->s.free = cat_free;
    return &c->s;
}

/* ---- stream helpers ---- */

int gz_range_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    gz_range_reader *r = (gz_range_reader *)ctx;
    *got = 0;
    if (r->cancel && *r->cancel) return GZ_E_CANCEL;
    if (r->pos >= r->end) return GZ_OK;
    u64 left = r->end - r->pos;
    u32 n = cap < left ? cap : (u32)left;
    u32 g = 0;
    int e = r->src->read_at(r->src, r->pos, buf, n, &g);
    if (e) return e;
    if (!g) return GZ_E_TRUNC;
    r->pos += g;
    *got = g;
    return GZ_OK;
}

int gz_pipe_write(void *ctx, const u8 *p, size_t n)
{
    gz_pipe *pp = (gz_pipe *)ctx;
    return pp->sink(pp->user, p, n);
}

int gz_mem_write(void *ctx, const u8 *p, size_t n)
{
    gz_mem_sink *m = (gz_mem_sink *)ctx;
    size_t limit = m->limit ? m->limit : ((size_t)1 << 30);
    if (n > limit - m->n) return GZ_E_LIMIT;
    if (m->n + n > m->cap) {
        size_t nc = m->cap ? m->cap : 4096;
        while (nc < m->n + n) nc *= 2;
        if (nc > limit) nc = limit;
        u8 *np = (u8 *)gz_realloc(m->p, nc);
        if (!np) return GZ_E_NOMEM;
        m->p = np;
        m->cap = nc;
    }
    __builtin_memcpy(m->p + m->n, p, n);
    m->n += n;
    return GZ_OK;
}

void gz_mem_sink_free(gz_mem_sink *m)
{
    gz_free(m->p);
    m->p = 0;
    m->n = m->cap = 0;
}

int gz_peek_write(void *ctx, const u8 *p, size_t n)
{
    gz_peek_sink *k = (gz_peek_sink *)ctx;
    while (n && k->n < k->cap) { k->buf[k->n++] = *p++; n--; }
    return k->n >= k->cap ? GZ_E_SKIP : GZ_OK;
}
