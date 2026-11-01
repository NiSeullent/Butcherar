/*
 * 고깃ZIP - helpers shared by the FAT, exFAT and ext2/3/4 readers (see fs1.h)
 */
#include "fs1.h"

/* ---------------- run sinks ---------------- */

void gz_fs1_sink_init(gz_fs1_sink *k, int (*put)(gz_fs1_sink *, u64, u64), u64 limit)
{
    k->put = put;
    k->limit = limit;
    k->pos = k->flushed = 0;
    k->p_off = k->p_len = 0;
}

static int sink_put(gz_fs1_sink *k)
{
    u64 n = k->p_len;
    if (!n) return GZ_OK;
    k->p_len = 0;
    int r = k->put(k, k->p_off, n);
    if (!r) k->flushed += n;
    return r;
}

int gz_fs1_emit(gz_fs1_sink *k, u64 poff, u64 len)
{
    if (k->pos >= k->limit) return GZ_FS1_FULL;
    u64 room = k->limit - k->pos;
    if (len > room) len = room;
    if (!len) return GZ_OK;
    int join = 0;
    if (k->p_len) {
        if (poff == GZ_FS1_HOLE) join = k->p_off == GZ_FS1_HOLE;
        else join = k->p_off != GZ_FS1_HOLE && k->p_off + k->p_len == poff;
    }
    if (join) {
        k->p_len += len;
    } else {
        int r = sink_put(k);
        if (r) return r;
        k->p_off = poff;
        k->p_len = len;
    }
    k->pos += len;
    return k->pos >= k->limit ? GZ_FS1_FULL : GZ_OK;
}

int gz_fs1_flush(gz_fs1_sink *k, int pad)
{
    if (pad && k->pos < k->limit) {
        int r = gz_fs1_emit(k, GZ_FS1_HOLE, k->limit - k->pos);
        if (r && r != GZ_FS1_FULL) return r;
    }
    return sink_put(k);
}

/* copy to a gz_out */
static int copy_put(gz_fs1_sink *k, u64 poff, u64 len)
{
    gz_fs1_copy *w = (gz_fs1_copy *)k;
    while (len) {
        if (gz_cancelled(w->c)) return GZ_E_CANCEL;
        u32 n = len < w->cap ? (u32)len : w->cap;
        if (poff == GZ_FS1_HOLE) {
            if (!w->zeroed) { __builtin_memset(w->buf, 0, w->cap); w->zeroed = 1; }
        } else {
            w->zeroed = 0;
            int r = gz_src_read_exact(w->s, poff, w->buf, n);
            if (r) return r;
            poff += n;
        }
        int r = w->out->write(w->out, w->buf, n);
        if (r) return r;
        len -= n;
    }
    return GZ_OK;
}

int gz_fs1_copy_init(gz_fs1_copy *w, gz_src *s, gz_out *out, gz_ctx *c, u64 size)
{
    gz_fs1_sink_init(&w->k, copy_put, size);
    w->s = s;
    w->out = out;
    w->c = c;
    w->cap = 256u << 10;
    w->zeroed = 0;
    w->buf = gz_ctx_buffer(c, w->cap);
    return w->buf ? GZ_OK : GZ_E_NOMEM;
}

/* read into memory */
static int mem_put(gz_fs1_sink *k, u64 poff, u64 len)
{
    gz_fs1_mem *m = (gz_fs1_mem *)k;
    u64 end = k->flushed + len;            /* <= limit */
    if (end > (size_t)-1 / 2) return GZ_E_LIMIT;
    if (end > m->cap) {
        size_t nc = m->cap ? m->cap : 4096;
        while (nc < end) nc *= 2;
        if (nc > k->limit) nc = (size_t)k->limit;
        u8 *np = (u8 *)gz_realloc(m->p, nc);
        if (!np) return GZ_E_NOMEM;
        m->p = np;
        m->cap = nc;
    }
    u8 *d = m->p + k->flushed;
    if (poff == GZ_FS1_HOLE) { __builtin_memset(d, 0, (size_t)len); return GZ_OK; }
    while (len) {
        u32 n = len < (1u << 30) ? (u32)len : (1u << 30);
        int r = gz_src_read_exact(m->s, poff, d, n);
        if (r) return r;
        d += n; poff += n; len -= n;
    }
    return GZ_OK;
}

void gz_fs1_mem_init(gz_fs1_mem *m, gz_src *s, u64 limit)
{
    gz_fs1_sink_init(&m->k, mem_put, limit);
    m->s = s;
    m->p = 0;
    m->cap = 0;
}

/* collect a run list */
static int list_put(gz_fs1_sink *k, u64 poff, u64 len)
{
    gz_fs1_list *l = (gz_fs1_list *)k;
    (void)len;
    if (l->n + 1 >= l->max) return GZ_E_LIMIT;      /* keep room for the end marker */
    if (l->n + 1 >= l->cap) {
        u32 nc = l->cap ? l->cap * 2 : 16;
        if (nc > l->max) nc = l->max;
        gz_fs1_run *nr = (gz_fs1_run *)gz_realloc(l->r, (size_t)nc * sizeof(gz_fs1_run));
        if (!nr) return GZ_E_NOMEM;
        l->r = nr;
        l->cap = nc;
    }
    l->r[l->n].loff = k->flushed;
    l->r[l->n].poff = poff;
    l->n++;
    return GZ_OK;
}

void gz_fs1_list_init(gz_fs1_list *l, u64 size, u32 max_runs)
{
    gz_fs1_sink_init(&l->k, list_put, size);
    l->r = 0;
    l->n = l->cap = 0;
    l->max = max_runs < 2 ? 2 : max_runs;
}

void gz_fs1_list_free(gz_fs1_list *l)
{
    gz_free(l->r);
    l->r = 0;
    l->n = l->cap = 0;
}

typedef struct { gz_src s; gz_src *parent; gz_fs1_run *r; u32 n; } run_src;

static int run_read(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    run_src *v = (run_src *)s;
    u8 *p = (u8 *)buf;
    *got = 0;
    if (off >= s->size) return GZ_OK;
    if (n > s->size - off) n = (u32)(s->size - off);
    u32 lo = 0, hi = v->n;                 /* r[n].loff == size */
    while (hi - lo > 1) {
        u32 mid = (lo + hi) / 2;
        if (v->r[mid].loff <= off) lo = mid; else hi = mid;
    }
    for (u32 i = lo; n && i < v->n; i++) {
        u64 in = off - v->r[i].loff, avail = v->r[i + 1].loff - off;
        u32 take = n < avail ? n : (u32)avail;
        if (v->r[i].poff == GZ_FS1_HOLE) {
            __builtin_memset(p, 0, take);
        } else {
            u32 done = 0;
            while (done < take) {
                u32 g = 0;
                int r = v->parent->read_at(v->parent, v->r[i].poff + in + done, p + done, take - done, &g);
                if (r) return r;
                if (!g) { *got += done; return GZ_OK; }
                done += g;
            }
        }
        *got += take;
        p += take; off += take; n -= take;
    }
    return GZ_OK;
}

static void run_free(gz_src *s)
{
    run_src *v = (run_src *)s;
    gz_free(v->r);
    gz_free(v);
}

gz_src *gz_fs1_list_src(gz_src *parent, gz_fs1_list *l)
{
    u64 size = l->k.flushed;
    if (l->n == 0) return gz_src_sub(parent, 0, 0);
    if (l->n == 1 && l->r[0].poff != GZ_FS1_HOLE) {
        u64 po = l->r[0].poff;
        gz_fs1_list_free(l);
        if (po > parent->size || size > parent->size - po) return 0;   /* outside the image */
        return gz_src_sub(parent, po, size);
    }
    run_src *v = (run_src *)gz_alloc(sizeof(run_src));
    if (!v) { gz_fs1_list_free(l); return 0; }
    l->r[l->n].loff = size;                /* end marker (room kept by list_put) */
    l->r[l->n].poff = GZ_FS1_HOLE;
    v->s.read_at = run_read;
    v->s.size = size;
    v->s.free = run_free;
    v->parent = parent;
    v->r = l->r;
    v->n = l->n;
    l->r = 0;
    l->n = l->cap = 0;
    return &v->s;
}

/* ---------------- FAT cluster chains ---------------- */

#define FC_SLOTS 8
#define FC_ENT 512                     /* 2 KiB of table per slot (16 KiB per cache) */

struct gz_fs1_fatcache {
    u32 tag[FC_SLOTS];                 /* block index + 1, 0 = empty */
    u32 e[FC_SLOTS][FC_ENT];
};

gz_fs1_fatcache *gz_fs1_fatcache_new(void)
{
    return (gz_fs1_fatcache *)gz_alloc(sizeof(gz_fs1_fatcache));
}

void gz_fs1_fatcache_free(gz_fs1_fatcache *fc)
{
    gz_free(fc);
}

static int fc_get(const gz_fs1_fat *f, gz_src *s, gz_fs1_fatcache *fc, u32 cl, u32 *v)
{
    u32 blk = cl / FC_ENT, slot = blk & (FC_SLOTS - 1);
    if (fc->tag[slot] != blk + 1) {
        u64 nent = (u64)f->nclus + 2, first = (u64)blk * FC_ENT;
        u32 cnt = nent - first < FC_ENT ? (u32)(nent - first) : FC_ENT;
        fc->tag[slot] = 0;
        int r = gz_src_read_exact(s, f->fat_off + first * 4, fc->e[slot], cnt * 4);
        if (r) return r;
        fc->tag[slot] = blk + 1;
    }
    *v = rd32(&fc->e[slot][cl % FC_ENT]);
    return GZ_OK;
}

int gz_fs1_fat_load32(gz_src *s, u64 off, u32 nent, u32 max_entries, u32 **tab)
{
    *tab = 0;
    if (nent > max_entries) return GZ_OK;
    u32 *t = (u32 *)gz_alloc((size_t)nent * 4 + 4);
    if (!t) return GZ_E_NOMEM;
    int r = gz_src_read_exact(s, off, t, nent * 4);
    if (r) { gz_free(t); return r; }
    *tab = t;
    return GZ_OK;
}

int gz_fs1_fat_walk(const gz_fs1_fat *f, gz_src *s, gz_fs1_fatcache *fc, u32 first, int contiguous,
                    gz_fs1_sink *k)
{
    if (first < 2 || first - 2 >= f->nclus) return GZ_E_DATA;
    if (contiguous) {
        u64 avail = (u64)(f->nclus - (first - 2)) << f->cshift;
        return gz_fs1_emit(k, f->heap + ((u64)(first - 2) << f->cshift), avail);
    }
    gz_fs1_fatcache *own = 0;
    if (!f->tab && !fc) {
        fc = own = gz_fs1_fatcache_new();
        if (!fc) return GZ_E_NOMEM;
    }
    u64 csz = (u64)1 << f->cshift;
    u32 cl = first, saved = first, power = 1, lam = 0;
    int r = GZ_E_DATA;                 /* stays when nclus clusters were visited: a cycle */
    for (u32 i = 0; i < f->nclus; i++) {
        int e = gz_fs1_emit(k, f->heap + ((u64)(cl - 2) << f->cshift), csz);
        if (e) { r = e; break; }
        u32 v;
        if (f->tab) v = f->tab[cl];
        else if ((e = fc_get(f, s, fc, cl, &v))) { r = e; break; }
        v &= f->mask;
        if (v >= f->eoc) { r = GZ_OK; break; }
        if (v < 2 || v - 2 >= f->nclus) { r = GZ_E_DATA; break; }   /* free / bad / out of range */
        /* Brent's cycle detection: catches most loops long before the cluster bound */
        if (v == saved) { r = GZ_E_DATA; break; }
        if (++lam == power) { saved = v; power <<= 1; lam = 0; }
        cl = v;
    }
    gz_fs1_fatcache_free(own);
    return r;
}

/* ---------------- key set ---------------- */

int gz_fs1_set_add(gz_fs1_set *s, u64 key)
{
    key++;                                   /* 0 marks an empty slot */
    if ((s->n + 1) * 2 > s->cap) {
        u32 nc = s->cap ? s->cap * 2 : 256;
        if (nc < s->cap) return -1;
        u64 *nk = (u64 *)gz_alloc((size_t)nc * sizeof(u64));
        if (!nk) return -1;
        for (u32 i = 0; i < s->cap; i++) {
            u64 x = s->k[i];
            if (!x) continue;
            u32 h = (u32)((x * 0x9E3779B97F4A7C15ull) >> 32) & (nc - 1);
            while (nk[h]) h = (h + 1) & (nc - 1);
            nk[h] = x;
        }
        gz_free(s->k);
        s->k = nk;
        s->cap = nc;
    }
    u32 h = (u32)((key * 0x9E3779B97F4A7C15ull) >> 32) & (s->cap - 1);
    while (s->k[h]) {
        if (s->k[h] == key) return 0;
        h = (h + 1) & (s->cap - 1);
    }
    s->k[h] = key;
    s->n++;
    return 1;
}

void gz_fs1_set_free(gz_fs1_set *s)
{
    gz_free(s->k);
    s->k = 0;
    s->n = s->cap = 0;
}

/* ---------------- directory nodes and paths ---------------- */

static u8 comp_na(const u8 *p, u32 n, int ne)
{
    if (ne == GZ_NE_UTF16LE) {
        for (u32 i = 0; i + 1 < n; i += 2) if (p[i + 1] || p[i] >= 0x80) return 2;
        return 0;
    }
    for (u32 i = 0; i < n; i++) if (p[i] >= 0x80) return 1;
    return 0;
}

int gz_fs1_tree_init(gz_fs1_tree *t, int byte_ne, int cp)
{
    __builtin_memset(t, 0, sizeof *t);
    t->byte_ne = byte_ne;
    t->cp = cp;
    t->capn = 64;
    t->n = (gz_fs1_node *)gz_alloc(t->capn * sizeof(gz_fs1_node));
    if (!t->n) return GZ_E_NOMEM;
    t->nn = 1;
    t->n[0].parent = -1;
    t->n[0].ne = (u8)byte_ne;
    return GZ_OK;
}

void gz_fs1_tree_free(gz_fs1_tree *t)
{
    gz_free(t->n);
    gz_free(t->names);
    gz_free(t->buf);
    __builtin_memset(t, 0, sizeof *t);
}

i32 gz_fs1_tree_add(gz_fs1_tree *t, i32 parent, const u8 *name, u32 len, int ne, u64 loc, u64 size, u32 aux)
{
    u32 depth = t->n[parent].depth + 1u;
    if (depth > GZ_FS1_MAXDEPTH) return -2;
    if (t->nn >= (1u << 27)) return -1;
    if (t->nn == t->capn) {
        gz_fs1_node *nn = (gz_fs1_node *)gz_realloc(t->n, (size_t)t->capn * 2 * sizeof(gz_fs1_node));
        if (!nn) return -1;
        t->n = nn;
        t->capn *= 2;
    }
    if ((u64)t->nlen + len > 0x7fffffffu) return -1;
    if (t->nlen + len > t->ncap) {
        u32 nc = t->ncap ? t->ncap : 4096;
        while (nc < t->nlen + len) nc *= 2;
        u8 *np = (u8 *)gz_realloc(t->names, nc);
        if (!np) return -1;
        t->names = np;
        t->ncap = nc;
    }
    if (len) __builtin_memcpy(t->names + t->nlen, name, len);
    gz_fs1_node *x = &t->n[t->nn];
    x->parent = parent;
    x->name_off = t->nlen;
    x->name_len = len;
    x->ne = (u8)ne;
    x->na = (u8)(t->n[parent].na | comp_na(name, len, ne));
    x->depth = (u16)depth;
    x->loc = loc;
    x->size = size;
    x->aux = aux;
    t->nlen += len;
    return (i32)t->nn++;
}

/* Write one component in the output encoding (wide: UTF-16LE, else bytes). NULs become '_'. */
static u32 put_comp(const gz_fs1_tree *t, u8 *d, const u8 *p, u32 n, int ne, int wide)
{
    u32 o = 0;
    if (ne == GZ_NE_UTF16LE) {
        n &= ~1u;
        if (wide) {
            for (u32 i = 0; i < n; i += 2) {
                u8 lo = p[i], hi = p[i + 1];
                if (!lo && !hi) lo = '_';
                d[o++] = lo; d[o++] = hi;
            }
        } else {
            for (u32 i = 0; i < n; i += 2) d[o++] = p[i] ? p[i] : '_';   /* ASCII only here */
        }
        return o;
    }
    if (!wide) {
        for (u32 i = 0; i < n; i++) d[o++] = p[i] ? p[i] : '_';
        return o;
    }
    /* byte name next to non-ASCII UTF-16 names: widen through the code page */
    gzch w[600];
    int m = 0;
    if (comp_na(p, n, ne) && n <= 255) m = gz_plat_mb2wc(t->cp, p, (int)n, w, 600);
    if (m <= 0 || m > (int)n) {
        for (u32 i = 0; i < n; i++) w[i] = p[i];     /* ASCII or Latin-1 fallback */
        m = (int)n;
    }
    for (int i = 0; i < m; i++) {
        gzch c = w[i] ? w[i] : '_';
        d[o++] = (u8)c; d[o++] = (u8)(c >> 8);
    }
    return o;
}

int gz_fs1_add_entry(gz_archive *a, gz_fs1_tree *t, i32 parent, const u8 *name, u32 len, int ne,
                     gz_entry **pe)
{
    u8 na = (u8)(t->n[parent].na | comp_na(name, len, ne));
    int wide = (na & 2) != 0;
    i32 chain[GZ_FS1_MAXDEPTH + 1];
    u32 d = 0;
    u64 need = (u64)len * 2 + 8;
    for (i32 x = parent; x > 0 && d <= GZ_FS1_MAXDEPTH; x = t->n[x].parent) {
        chain[d++] = x;
        need += (u64)t->n[x].name_len * 2 + 2;
    }
    if (need > (1u << 24)) return GZ_E_LIMIT;
    if (need > t->bcap) {
        u32 nc = t->bcap ? t->bcap : 1024;
        while (nc < need) nc *= 2;
        u8 *nb = (u8 *)gz_realloc(t->buf, nc);
        if (!nb) return GZ_E_NOMEM;
        t->buf = nb;
        t->bcap = nc;
    }
    u32 o = 0;
    while (d--) {
        const gz_fs1_node *x = &t->n[chain[d]];
        o += put_comp(t, t->buf + o, t->names + x->name_off, x->name_len, x->ne, wide);
        t->buf[o++] = '/';
        if (wide) t->buf[o++] = 0;
    }
    o += put_comp(t, t->buf + o, name, len, ne, wide);
    return gz_arc_add_named(a, t->buf, o, wide ? GZ_NE_UTF16LE : t->byte_ne, pe);
}
