/*
 * 고깃ZIP - streaming Deflate / Deflate64 decoder
 */
#ifndef GZ_INFLATE_H
#define GZ_INFLATE_H
#include "base.h"
#include "stream.h"

#define GZ_WSIZE       65536u              /* window (Deflate64 needs 64K)  */
#define GZ_OCHUNK      (1u << 20)          /* output flush granularity      */
#define GZ_OMARGIN     (65538u + 256u)     /* max match + wide-copy slack   */
#define GZ_ICAP        (256u << 10)        /* input buffer                  */
#define GZ_ILOOKBEHIND 16u
#define GZ_IPAD        128u

#define GZ_LIT_TBITS   10
#define GZ_DIST_TBITS  8
#define GZ_LIT_TSIZE   2048                /* primary 1024 + subtables      */
#define GZ_DIST_TSIZE  1024                /* primary 256 + subtables       */

typedef struct gz_inflater {
    u32 lit[GZ_LIT_TSIZE];
    u32 dist[GZ_DIST_TSIZE];
    u32 pre[128];
    u8  lens[288 + 32 + 16];

    u8 *ibuf;            /* GZ_ILOOKBEHIND + GZ_ICAP + GZ_IPAD   */
    u8 *obuf;            /* GZ_WSIZE + GZ_OCHUNK + GZ_OMARGIN    */
    void *mem;
    size_t mem_size;

    /* stream state */
    const u8 *in_end, *in_fast_end;
    int in_eof;
    u8 *flushed;
    u32 crc;             /* CRC-32 of produced output        */
    u64 total_out;
    int deflate64;

    /* after a successful run: bytes left unconsumed in ibuf */
    const u8 *rest;
    u32 rest_len;
    int nsis;            /* stored blocks without NLEN (gz_inflate_run_nsis) */
} gz_inflater;

gz_inflater *gz_inflater_new(void);
void gz_inflater_free(gz_inflater *z);

/* Decode one complete deflate stream. Output is CRC'ed and pushed to io->write. */
int gz_inflate_run(gz_inflater *z, const gz_stream_io *io, int deflate64);

/* NSIS 2 variant ("SetCompressor zlib" in NSIS 2.x installers, 7-Zip's NsisMode):
 * a stored block header is LEN (2 bytes) only, no NLEN. Otherwise the same as
 * gz_inflate_run(z, io, 0). */
int gz_inflate_run_nsis(gz_inflater *z, const gz_stream_io *io);

/* Same, with a preset history: matches may reach back into dict[0..dict_len)
 * (dict_len <= GZ_INFLATE_DICT_MAX), e.g. CAB MSZIP blocks continue the previous
 * block's window. Only the new data is pushed, CRC'ed and counted in total_out. */
#define GZ_INFLATE_DICT_MAX 32768u
int gz_inflate_run_dict(gz_inflater *z, const gz_stream_io *io, const u8 *dict, u32 dict_len);

/* Copy a stored stream (no compression) with CRC, using the inflater's buffer. */
int gz_store_run(gz_inflater *z, const gz_stream_io *io);

/* Kernel dispatch */
typedef int (*gz_inflate_fn)(gz_inflater *z, const gz_stream_io *io);
extern gz_inflate_fn gz_inflate_kernel;
int gz_inflate_x86(gz_inflater *z, const gz_stream_io *io);
int gz_inflate_mmx(gz_inflater *z, const gz_stream_io *io);
int gz_inflate_sse(gz_inflater *z, const gz_stream_io *io);
int gz_inflate_sse2(gz_inflater *z, const gz_stream_io *io);
int gz_inflate_avx(gz_inflater *z, const gz_stream_io *io);
int gz_inflate_avx2(gz_inflater *z, const gz_stream_io *io);
int gz_inflate_neon(gz_inflater *z, const gz_stream_io *io);    /* AArch64 only */

/* shared helpers used by the kernels */
int gz_build_table(u32 *table, u32 tbits, u32 tsize, const u8 *lens, u32 nsym,
                   const u32 *templ, int allow_incomplete);
int gz_in_refill(gz_inflater *z, const gz_stream_io *io, const u8 *in, const u8 **new_in);
int gz_out_flush(gz_inflater *z, const gz_stream_io *io, u8 *out, u8 **new_out);
extern u32 gz_lit_templ[288], gz_lit_templ64[288];
extern u32 gz_dist_templ[32], gz_dist_templ64[32], gz_pre_templ[19];
void gz_inflate_init(void);   /* build symbol templates, call once */

/* entry encoding */
#define GZE_LIT  0x2000u
#define GZE_SUB  0x4000u
#define GZE_EXC  0x8000u     /* value 0 = end of block, 1 = invalid */

#endif
