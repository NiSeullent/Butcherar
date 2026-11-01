/*
 * 고깃ZIP - writer dispatch and sink helpers
 */
#include "gz_write.h"

const gz_writer *gz_writer_find(int format)
{
    for (int i = 0; gz_writers[i]; i++)
        if (gz_writers[i]->format == format) return gz_writers[i];
    return 0;
}

int gz_write_archive(const gz_wopts *o, const gz_witem *items, u32 n, gz_sink *out, gz_ctx *c)
{
    const gz_writer *w = gz_writer_find(o->format);
    if (!w) return GZ_E_METHOD;
    if (o->method && !(w->methods & (1u << o->method))) return GZ_E_METHOD;
    if (o->encryption && !(w->encryptions & (1u << o->encryption))) return GZ_E_METHOD;
    gz_ctx *own = 0;
    if (!c) { own = c = gz_ctx_new(); if (!c) return GZ_E_NOMEM; }
    volatile long *old = c->cancel;
    if (o->cancel) c->cancel = o->cancel;
    int r = w->write(o, items, n, out, c);
    c->cancel = old;
    if (own) gz_ctx_free(own);
    return r;
}

int gz_sink_write(gz_sink *k, const void *p, size_t n)
{
    if (!n) return GZ_OK;
    int r = k->write(k, p, n);
    if (!r) k->pos += n;
    return r;
}

int gz_sink_patch(gz_sink *k, u64 off, const void *p, size_t n)
{
    if (!k->write_at) return GZ_E_METHOD;
    return k->write_at(k, off, p, n);
}
