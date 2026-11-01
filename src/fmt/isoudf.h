/*
 * 고깃ZIP - helpers shared by the ISO 9660 and UDF readers (iso.c, udf.c)
 *
 *   isoudf_civil()   calendar date -> FILETIME
 *   xrun list        file data described as runs of image bytes or zeros,
 *                    exposed as a random-access gz_src (multi-extent, sparse,
 *                    interleaved and remapped files)
 */
#ifndef GZ_ISOUDF_H
#define GZ_ISOUDF_H
#include "arc.h"

/* Seconds since 1970 of a proleptic Gregorian date/time (no validation). */
static inline i64 isoudf_days(i64 y, u32 m, u32 d)
{
    y -= m <= 2;
    i64 era = (y >= 0 ? y : y - 399) / 400;
    i64 yoe = y - era * 400;
    i64 doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    i64 doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* FILETIME of a UTC-adjusted date; tz_min = minutes east of UTC. 0 if the date is invalid. */
static inline u64 isoudf_civil(i64 y, u32 mo, u32 d, u32 h, u32 mi, u32 s, i32 tz_min, u32 ticks)
{
    if (y < 1601 || y > 30000 || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60)
        return 0;
    i64 t = isoudf_days(y, mo, d) * 86400 + (i64)h * 3600 + mi * 60 + s - (i64)tz_min * 60;
    i64 ft = t * 10000000LL + 116444736000000000LL + ticks;
    return ft > 0 ? (u64)ft : 0;
}

/* ---------------- runs of file data ---------------- */

#define XRUN_ZERO (~(u64)0)          /* run reads as zeros (sparse / unrecorded) */

typedef struct { u64 fpos, off, len; } xrun;   /* file position, image offset, length */

typedef struct { xrun *r; u32 n, cap; } xrun_list;

/* Append a run; merges with the previous one when contiguous. */
static inline int xrun_add(xrun_list *l, u64 fpos, u64 off, u64 len)
{
    if (!len) return GZ_OK;
    if (l->n) {
        xrun *p = &l->r[l->n - 1];
        if (p->fpos + p->len == fpos &&
            ((off == XRUN_ZERO && p->off == XRUN_ZERO) || (off != XRUN_ZERO && p->off != XRUN_ZERO && p->off + p->len == off))) {
            p->len += len;
            return GZ_OK;
        }
    }
    if (l->n == l->cap) {
        if (l->cap >= (1u << 26)) return GZ_E_LIMIT;
        u32 nc = l->cap ? l->cap * 2 : 64;
        xrun *nr = (xrun *)gz_realloc(l->r, (size_t)nc * sizeof(xrun));
        if (!nr) return GZ_E_NOMEM;
        l->r = nr;
        l->cap = nc;
    }
    xrun *x = &l->r[l->n++];
    x->fpos = fpos;
    x->off = off;
    x->len = len;
    return GZ_OK;
}

typedef struct { gz_src s; gz_src *parent; u32 n; xrun r[1]; } xrun_src;

static inline int xrun_read(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    xrun_src *v = (xrun_src *)s;
    u8 *p = (u8 *)buf;
    *got = 0;
    if (off >= s->size) return GZ_OK;
    if (n > s->size - off) n = (u32)(s->size - off);
    u32 lo = 0, hi = v->n;                 /* runs are contiguous and sorted by fpos */
    while (hi - lo > 1) {
        u32 mid = (lo + hi) / 2;
        if (v->r[mid].fpos <= off) lo = mid; else hi = mid;
    }
    for (u32 i = lo; n && i < v->n; i++) {
        const xrun *x = &v->r[i];
        if (off < x->fpos || off - x->fpos >= x->len) break;     /* hole: cannot happen */
        u64 in = off - x->fpos;
        u32 take = x->len - in < n ? (u32)(x->len - in) : n;
        if (x->off == XRUN_ZERO) {
            __builtin_memset(p, 0, take);
        } else {
            u32 g = 0;
            int r = v->parent->read_at(v->parent, x->off + in, p, take, &g);
            if (r) return r;
            if (g < take) { *got += g; return GZ_OK; }      /* image ends early */
        }
        p += take; off += take; n -= take; *got += take;
    }
    return GZ_OK;
}

static inline void xrun_free(gz_src *s) { gz_free(s); }

/* View of runs r[0..n) (copied) over parent; size = total length of the runs. */
static inline gz_src *xrun_view(gz_src *parent, const xrun *r, u32 n, u64 size)
{
    if (!n || n > (1u << 24)) return 0;
    xrun_src *v = (xrun_src *)gz_alloc(sizeof(xrun_src) + (size_t)n * sizeof(xrun));
    if (!v) return 0;
    __builtin_memcpy(v->r, r, (size_t)n * sizeof(xrun));
    v->n = n;
    v->parent = parent;
    v->s.read_at = xrun_read;
    v->s.size = size;
    v->s.free = xrun_free;
    return &v->s;
}

#endif
