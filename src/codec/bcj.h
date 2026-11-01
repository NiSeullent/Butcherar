/*
 * 고깃ZIP - branch converters (BCJ filters) and the Delta filter
 *
 * Executable code filters turn relative branch targets into absolute ones
 * (encoding) so that LZMA finds more repeats, and back (decoding). The
 * conversions are byte-exact with xz 5.6+ (liblzma/simple) and 7-Zip 24+.
 *
 *   type            7z method id   xz filter id   parameter
 *   GZ_BCJ_X86      03 03 01 03    0x04           start offset
 *   GZ_BCJ_PPC      03 03 02 05    0x05           start offset (big-endian PowerPC)
 *   GZ_BCJ_IA64     03 03 04 01    0x06           start offset
 *   GZ_BCJ_ARM      03 03 05 01    0x07           start offset (little-endian ARM)
 *   GZ_BCJ_ARMT     03 03 07 01    0x08           start offset
 *   GZ_BCJ_SPARC    03 03 08 05    0x09           start offset
 *   GZ_BCJ_ARM64    0A             0x0A           start offset (7z: optional 4-byte prop)
 *   GZ_BCJ_RISCV    0B             0x0B           start offset (7z: optional 4-byte prop)
 *   GZ_BCJ_DELTA    03             0x03           distance 1..256 (prop byte = distance - 1)
 * (BCJ2, 7z id 03 03 01 1B, is a 4-stream coder: see bcj2.h.)
 *
 * In-place use:
 *   gz_bcj f; gz_bcj_init(&f, GZ_BCJ_X86, 0, 0);
 *   size_t done = gz_bcj_code(&f, buf, n);
 *   - buf[0 .. done) is final; buf[done .. n) (a few bytes) must be presented
 *     again at the start of the next call, followed by more data;
 *   - at the end of the stream the unconverted tail is final as it is.
 * Push use (a filter in front of a sink, e.g. after a decoder):
 *   gz_filter_push fp;      (about 8 KiB: keep it on the heap or in a state struct)
 *   gz_filter_push_init(&fp, GZ_BCJ_ARM64, 0, 0, sink, sink_ctx);
 *   io.write = gz_filter_push_write; io.ctx = &fp;   -> decoder output
 *   ... decode ...;  r = gz_filter_push_finish(&fp);
 * Filters chain: the sink of one push filter can be another's gz_filter_push_write;
 * finish them in data-flow order.
 */
#ifndef GZ_BCJ_H
#define GZ_BCJ_H
#include "base.h"

enum {
    GZ_BCJ_NONE = 0,
    GZ_BCJ_X86,
    GZ_BCJ_PPC,
    GZ_BCJ_IA64,
    GZ_BCJ_ARM,
    GZ_BCJ_ARMT,
    GZ_BCJ_SPARC,
    GZ_BCJ_ARM64,
    GZ_BCJ_RISCV,
    GZ_BCJ_DELTA,
    GZ_BCJ_COUNT
};

typedef struct gz_bcj {
    u8  type, enc;
    u8  dpos;                /* delta: history position                     */
    u8  pad_;
    u32 pos;                 /* stream position of the next byte (mod 2^32) */
    u32 x86_mask, x86_prev;  /* x86 state                                    */
    u32 dist;                /* delta distance                               */
    u8  hist[256];           /* delta history                                */
} gz_bcj;

/* type: GZ_BCJ_*; param: start offset (branch filters) or distance 1..256 (Delta;
 * other values are clamped); encoding: 0 = decode (extract), 1 = encode. */
void   gz_bcj_init(gz_bcj *f, int type, u32 param, int encoding);
/* Convert buf in place; returns the number of leading bytes that are final. */
size_t gz_bcj_code(gz_bcj *f, u8 *buf, size_t n);

/* Required alignment of the start offset (1, 2, 4 or 16; xz and 7-Zip reject
 * other offsets, conversions with them are not reversible). */
u32 gz_bcj_align(int type);

/* Method id lookups (0 = not a filter handled here). */
int gz_bcj_from_xz_id(u64 id);
int gz_bcj_from_7z_id(u64 id);
const char *gz_bcj_name(int type);          /* "BCJ", "ARM64", "Delta", ... */

/* ---- push adapter ---- */
#define GZ_FILTER_PUSH_BUF 8192u

typedef struct gz_filter_push {
    gz_bcj f;
    int (*next)(void *ctx, const u8 *p, size_t n);
    void *next_ctx;
    u32 n;                                  /* bytes held in buf */
    u8  buf[GZ_FILTER_PUSH_BUF];
} gz_filter_push;

void gz_filter_push_init(gz_filter_push *p, int type, u32 param, int encoding,
                         int (*next)(void *ctx, const u8 *p, size_t n), void *next_ctx);
/* ctx = the gz_filter_push. Usable as gz_stream_io.write and as a gz_sink_fn.
 * Returns GZ_OK or the error of the next sink. */
int  gz_filter_push_write(void *ctx, const u8 *p, size_t n);
/* End of data: converts and forwards the held tail. Returns GZ_OK or the sink error. */
int  gz_filter_push_finish(gz_filter_push *p);

#endif
