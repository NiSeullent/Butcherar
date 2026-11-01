/*
 * 고깃ZIP - byte sources, stream callbacks and output targets
 *
 *   gz_src        random-access input (archive file, a view of part of it,
 *                 a memory block, or several volumes back to back)
 *   gz_stream_io  pull input / push output callbacks used by every codec
 *   gz_out        per-entry output target implemented by the engine
 */
#ifndef GZ_STREAM_H
#define GZ_STREAM_H
#include "base.h"

/* ---------------- random-access sources ---------------- */

typedef struct gz_src {
    /* read up to n bytes at off; *got < n only at end of data. Thread-safe for
     * sources handed out by the platform (each worker owns one anyway). */
    int (*read_at)(struct gz_src *s, u64 off, void *buf, u32 n, u32 *got);
    u64 size;
    void *h;
    void (*free)(struct gz_src *s);      /* NULL: owned by someone else */
} gz_src;

int  gz_src_read_exact(gz_src *s, u64 off, void *buf, u32 n);  /* GZ_E_TRUNC on short read */
void gz_src_free(gz_src *s);                                   /* calls s->free if set */

/* View of [off, off+len) of parent (parent must outlive the view). */
gz_src *gz_src_sub(gz_src *parent, u64 off, u64 len);
/* View of a memory block (not copied unless own != 0, then freed with the view). */
gz_src *gz_src_mem(const void *p, u64 n, int own);
/* Parts back to back. Takes ownership of the parts (each freed with gz_src_free). */
gz_src *gz_src_concat(gz_src **parts, u32 n);

/* ---------------- streaming codec callbacks ---------------- */

/* Pull/push stream callbacks.
 * read : fill up to cap bytes, *got = 0 means end of input. Return GZ_OK or error.
 * write: consume n bytes of output. Return GZ_OK or error (e.g. GZ_E_CANCEL,
 *        or GZ_E_SKIP to stop decoding early - callers treat that as "enough"). */
typedef struct {
    int (*read)(void *ctx, u8 *buf, u32 cap, u32 *got);
    int (*write)(void *ctx, const u8 *buf, size_t n);
    void *ctx;
} gz_stream_io;

/* Bounded reader over a source: feeds [pos, end) to a codec. */
typedef struct gz_range_reader {
    gz_src *src;
    u64 pos, end;
    volatile long *cancel;     /* optional */
} gz_range_reader;
int gz_range_read(void *ctx, u8 *buf, u32 cap, u32 *got);   /* use with a gz_range_reader ctx */

/* Reader + sink pair for codecs (gz_stream_io has one ctx for both directions):
 *   gz_pipe pp = { { src, start, end, cancel }, sink, user };
 *   gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };              */
typedef struct gz_pipe {
    gz_range_reader rd;        /* must stay first: gz_range_read casts ctx to it */
    int (*sink)(void *user, const u8 *p, size_t n);
    void *user;
} gz_pipe;
int gz_pipe_write(void *ctx, const u8 *p, size_t n);

/* Growable memory sink: collect a decoded stream in memory (with a hard cap). */
typedef struct gz_mem_sink {
    u8 *p;
    size_t n, cap, limit;      /* limit: GZ_E_LIMIT when exceeded (0 = 1 GiB) */
} gz_mem_sink;
int  gz_mem_write(void *ctx, const u8 *p, size_t n);        /* use with a gz_mem_sink ctx */
void gz_mem_sink_free(gz_mem_sink *m);

/* Fixed buffer sink: fills buf, then returns GZ_E_SKIP (peek at the start of a stream). */
typedef struct gz_peek_sink { u8 *buf; u32 cap, n; } gz_peek_sink;
int gz_peek_write(void *ctx, const u8 *p, size_t n);

/* ---------------- per-entry output ---------------- */

typedef struct gz_out {
    int (*open)(struct gz_out *o, u32 idx);            /* GZ_OK, GZ_E_SKIP or error */
    int (*write)(struct gz_out *o, const u8 *p, size_t n);
    int (*close)(struct gz_out *o, u32 idx, int status);
    void *user;
} gz_out;

#endif
