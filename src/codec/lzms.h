/*
 * 고깃ZIP - LZMS decoder (Microsoft LZMS: WIM/ESD version 3584 resources, solid
 * resources, WOF "LZMS" compressed files)
 *
 * LZMS is chunk based: every chunk is an independent stream whose compressed and
 * uncompressed sizes come from the container (WIM chunk table). A chunk holds two
 * streams in one buffer of 16-bit little-endian words: a range coder (adaptive
 * bits, read forwards from the start) that chooses between literal / LZ match /
 * delta match and their repeat-offset slots, and a bit stream (read backwards
 * from the end, MSB first) of adaptive Huffman symbols (rebuilt every 512 / 1024
 * symbols from the symbol frequencies) and verbatim extra bits. The output is
 * post-processed with an x86 relative-address filter.
 *
 * Usage:
 *     gz_lzms_dec *d = gz_lzms_new();          (or gz_ctx_slot(c, GZ_SLOT_MISC1,
 *                                               gz_lzms_slot_new, gz_lzms_slot_free))
 *     gz_lzms_decode(d, in, in_n, out, out_n);  one call per chunk
 *
 * A WIM chunk whose compressed size equals its uncompressed size is stored and must
 * not be passed to the decoder.
 */
#ifndef GZ_LZMS_H
#define GZ_LZMS_H
#include "base.h"

#define GZ_LZMS_MAX_CHUNK (1u << 30)   /* largest uncompressed chunk accepted */

typedef struct gz_lzms_dec gz_lzms_dec;

gz_lzms_dec *gz_lzms_new(void);      /* ~330 KiB of state; NULL when out of memory */
void gz_lzms_free(gz_lzms_dec *d);

/* Decode one chunk: in[0..in_n) is the whole compressed chunk (an even number of
 * bytes, at least 4), exactly out_n bytes are written to out (nothing past it).
 * The decoder state is reset on every call.
 * GZ_OK, GZ_E_DATA (corrupt stream: bad match offset/length, odd or short input),
 * GZ_E_LIMIT (out_n > GZ_LZMS_MAX_CHUNK). */
int gz_lzms_decode(gz_lzms_dec *d, const u8 *in, size_t in_n, u8 *out, size_t out_n);

/* create/destroy pair for gz_ctx_slot */
void *gz_lzms_slot_new(void);
void  gz_lzms_slot_free(void *d);

#endif
