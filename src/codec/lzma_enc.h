/*
 * 고깃ZIP - LZMA / LZMA2 encoder
 *
 * 7-Zip-class encoder: HC4 / BT4 match finders (lz_mf.h), a fast greedy/lazy
 * parser (levels 0-3, like xz -0..-3) and the price-driven optimal parser of
 * 7-Zip's LzmaEnc.c "normal" mode (levels 4-9): rep0-3 matches, short reps,
 * matched literals and the literal+rep0 / match+literal+rep0 look-ahead.
 * Input of any size is streamed with bounded memory (dictionary + look-ahead).
 *
 * Usage:
 *     gz_lzma_enc_opts o;
 *     gz_lzma_enc_opts_init(&o, 6);          // defaults of a level
 *     o.dict_size = 32u << 20;                // optional overrides
 *     o.size_hint = input_size;               // optional: smaller dictionary for small inputs
 *     gz_lzma_enc *e = gz_lzma_enc_new(&o);   // NULL: invalid options or no memory
 *     gz_lzma_encode(e, &io, props, 0);       // raw LZMA, props = 5-byte coder properties
 *     gz_lzma2_encode(e, &io, &dict_prop);    // raw LZMA2 stream (chunks + end byte)
 *     gz_lzma_enc_free(e);
 *
 * io->read pulls the uncompressed input (*got = 0 at its end), io->write
 * receives the compressed stream. Errors from either callback (GZ_E_CANCEL,
 * GZ_E_IO...) are returned unchanged. An encoder can be reused for several
 * streams (tables are kept); it is not shared between threads.
 *
 * Levels (gz_lzma_enc_opts_init); depth 0 = automatic (BT4: 16 + nice/2,
 * HC4: 4 + nice/4):
 *
 *   level  dict      parser  mf   nice  depth     like
 *     0    256 KiB   fast    HC4  128     4       xz -0
 *     1      1 MiB   fast    HC4  128     8       xz -1
 *     2      2 MiB   fast    HC4  273    24       xz -2
 *     3      4 MiB   fast    HC4  273    48       xz -3
 *     4      4 MiB   normal  BT4   16   auto(24)  xz -4
 *     5      8 MiB   normal  BT4   32   auto(32)  xz -5 (7z -mx5: same, 16 MiB)
 *     6      8 MiB   normal  BT4   64   auto(48)  xz -6
 *     7     16 MiB   normal  BT4   64   auto(48)  xz -7
 *     8     32 MiB   normal  BT4   96     64      between xz -8 and -8e
 *     9     64 MiB   normal  BT4  128    128      7z -mx9 (nice 64) .. xz -9e, at xz -9 speed
 *   GZ_LZMA_EXTREME: normal BT4, nice 273, depth 512 (levels 3 and 5: nice 192,
 *   depth auto), like xz -e.
 *   All levels: lc 3, lp 0, pb 2.
 *
 * Limits: dict 4 KiB .. GZ_LZMA_DICT_MAX (1.5 GiB on 64-bit builds, 128 MiB on
 * 32-bit builds, where the whole encoder is also capped at GZ_LZMA_MEM_MAX = 1 GiB);
 * lc 0..8, lp 0..4, pb 0..4 (LZMA2: lc + lp <= 4); nice_len 5..273; depth <= 2^30.
 * Memory (gz_lzma_enc_memusage): window dict + max(dict / 2, 1 MiB) (LZMA2: at least
 * 2 MiB + 1 MiB, an uncompressed chunk is copied from it), links dict * 4 (HC4) or
 * dict * 8 (BT4), hash heads ~dict * 2 (above 32 MiB: ~dict), ~0.3 MiB of coder
 * state, e.g. 16.3 GiB for a 1.5 GiB BT4 dictionary. Levels 0..9:
 * 3.4, 8.6, 16, 31, 47, 93, 93, 185, 369, 673 MiB (xz -0..-9: 3, 9, 17, 32, 48, 94,
 * 94, 186, 370, 674 MiB).
 */
#ifndef GZ_LZMA_ENC_H
#define GZ_LZMA_ENC_H
#include "base.h"
#include "stream.h"
#include "lz_mf.h"

enum { GZ_LZMA_FAST = 0, GZ_LZMA_NORMAL = 1 };

#define GZ_LZMA_EXTREME 0x100          /* flag for gz_lzma_enc_opts_init's level */

#if UINTPTR_MAX > 0xFFFFFFFFu
#define GZ_LZMA_DICT_MAX (1536u << 20)
#define GZ_LZMA_MEM_MAX  (~(u64)0)        /* no cap beyond what the allocator gives  */
#else
#define GZ_LZMA_DICT_MAX (128u << 20)
#define GZ_LZMA_MEM_MAX  ((u64)1 << 30)   /* 32-bit: total encoder memory            */
#endif

typedef struct gz_lzma_enc_opts {
    int level;          /* level the defaults came from (informational)                 */
    u32 dict_size;      /* dictionary bytes; rounded up to 2^n or 3*2^n                 */
    u8  lc, lp, pb;     /* literal context bits, literal position bits, position bits  */
    u8  mode;           /* GZ_LZMA_FAST or GZ_LZMA_NORMAL                               */
    u8  mf;             /* GZ_MF_HC4 or GZ_MF_BT4                                      */
    u8  pad_[3];
    u32 nice_len;       /* stop searching at this match length (5..273)                 */
    u32 depth;          /* match finder cut value, 0 = automatic                       */
    u64 size_hint;      /* expected input size, 0 = unknown. A smaller dictionary is
                           used (and written to the properties) when the input is
                           smaller; a wrong hint only costs ratio, never correctness  */
    u32 test_norm_step; /* testing only: renormalise match-finder positions every N
                           bytes instead of near 2^32 (0 = off)                        */
} gz_lzma_enc_opts;

typedef struct gz_lzma_enc gz_lzma_enc;

/* Defaults of a level 0..9 (larger: 9, negative: 5), optionally | GZ_LZMA_EXTREME. */
void gz_lzma_enc_opts_init(gz_lzma_enc_opts *o, int level);
/* GZ_OK, GZ_E_METHOD (invalid parameter) or GZ_E_LIMIT (dictionary / memory too
 * large for this build). lzma2 != 0 also checks lc + lp <= 4. */
int  gz_lzma_enc_check(const gz_lzma_enc_opts *o, int lzma2);
/* Approximate bytes of memory an encoder with these options allocates. */
u64  gz_lzma_enc_memusage(const gz_lzma_enc_opts *o, int lzma2);

/* o == NULL: level 5. Returns NULL for invalid options or when out of memory
 * (the dictionary tables are allocated by the first encode call). */
gz_lzma_enc *gz_lzma_enc_new(const gz_lzma_enc_opts *o);
void gz_lzma_enc_free(gz_lzma_enc *e);

/* Coder properties, known right after gz_lzma_enc_new (e.g. for a .lzma or ZIP
 * header written before the data):
 *   props[0] = (pb * 5 + lp) * 9 + lc, props[1..4] = dictionary size (LE)  */
void gz_lzma_enc_props(const gz_lzma_enc *e, u8 props[5]);
/* LZMA2 dictionary property byte (0..40). */
u8   gz_lzma2_enc_dict_prop(const gz_lzma_enc *e);

/* Raw LZMA stream (no header). props (may be NULL) is filled before the first
 * write. end_marker: 1 = finish with the end-of-stream marker (needed when the
 * container does not store the size). */
int gz_lzma_encode(gz_lzma_enc *e, const gz_stream_io *io, u8 props[5], int end_marker);
/* Raw LZMA2 stream: chunks of <= 2 MiB unpacked / 64 KiB packed, uncompressed
 * chunks for incompressible data, final 0x00. dict_prop (may be NULL) is
 * filled before the first write. GZ_E_METHOD if lc + lp > 4. */
int gz_lzma2_encode(gz_lzma_enc *e, const gz_stream_io *io, u8 *dict_prop);

/* Byte counts of the last encode call. */
u64 gz_lzma_enc_in_size(const gz_lzma_enc *e);
u64 gz_lzma_enc_out_size(const gz_lzma_enc *e);

#endif
