/*
 * 고깃ZIP - LZMA / LZMA2 decoder
 *
 * Streaming decoder for raw LZMA ("LZMA1") and LZMA2 data, as used by .lzma,
 * .xz, .lz, .7z, ZIP method 14, NSIS, squashfs, ... The stream formats around
 * the raw data are handled by their readers; this module only decodes.
 *
 *   gz_lzma_dec *d = gz_lzma_dec_new();      (or cache one: gz_ctx_slot(c, GZ_SLOT_LZMA, ...))
 *   u64 used;
 *   r = gz_lzma_decode(d, props5, &io, size_or_GZ_SIZE_UNKNOWN, &used);
 *   r = gz_lzma2_decode(d, dict_prop, &io, size_or_GZ_SIZE_UNKNOWN, &used);
 *   gz_lzma_dec_free(d);
 *
 * Input is pulled with io->read in large chunks (the decoder may read up to
 * 64 KiB past the end of the compressed data); *in_used reports the exact number
 * of compressed bytes the stream occupies so containers (lzip members, xz block
 * padding, NSIS) can continue right after it. Output is pushed with io->write in
 * pieces of at most 1 MiB. A sink error (GZ_E_SKIP, GZ_E_CANCEL, ...) is returned
 * unchanged.
 *
 * Memory: the dictionary buffer is min(dictionary size, out_size) (at least
 * 1 MiB when the output is larger), allocated with gz_alloc_big and kept for
 * the next call when large enough. Dictionaries above the limit (default 1.5 GiB
 * on 32-bit targets, 4 GiB on 64-bit) give GZ_E_LIMIT.
 */
#ifndef GZ_LZMA_H
#define GZ_LZMA_H
#include "base.h"
#include "stream.h"

typedef struct gz_lzma_dec gz_lzma_dec;   /* opaque, reusable, one per thread */

gz_lzma_dec *gz_lzma_dec_new(void);
void gz_lzma_dec_free(gz_lzma_dec *d);

/* Largest dictionary buffer the decoder may allocate (bytes, 0 = default).
 * Applies to min(dictionary, out_size); exceeding it gives GZ_E_LIMIT. */
void gz_lzma_dec_set_limit(gz_lzma_dec *d, u64 max_dict);

/* Option flags (persist across calls). GZ_LZMA_LENIENT_END: with a known out_size,
 * just stop there: no check that the range coder is finished or an end marker /
 * end byte follows (7-Zip's behaviour when extracting .7z). *in_used is then the
 * position where decoding stopped. */
enum { GZ_LZMA_LENIENT_END = 1 };
void gz_lzma_dec_set_flags(gz_lzma_dec *d, u32 flags);

/* Raw LZMA ("LZMA1").
 * props: the 5 property bytes (lc/lp/pb byte = (pb * 5 + lp) * 9 + lc, then the
 *        dictionary size, u32 LE). lc <= 8, lp <= 4, pb <= 4 (else GZ_E_DATA).
 * out_size: GZ_SIZE_UNKNOWN - the stream must end with an end marker.
 *           known size     - decoding stops after out_size bytes. The range coder
 *                            must be finished there, or an end marker must follow
 *                            right away (accepted and consumed, as 7-Zip does);
 *                            an end marker before out_size is GZ_E_DATA.
 * in_used (may be NULL): exact compressed size consumed, including the end marker.
 * Errors: GZ_E_DATA corrupt data, GZ_E_TRUNC input ended early, GZ_E_LIMIT
 * dictionary too large, GZ_E_NOMEM, read/sink errors unchanged. */
int gz_lzma_decode(gz_lzma_dec *d, const u8 props[5], const gz_stream_io *io,
                   u64 out_size, u64 *in_used);

/* LZMA2 (xz filter 0x21, 7z method 0x21).
 * dict_prop: the 1-byte dictionary property (0..40; 40 = 4 GiB - 1), else GZ_E_DATA.
 * out_size: GZ_SIZE_UNKNOWN - decode until the end-of-stream control byte (0x00).
 *           known size     - the stream must end exactly there: on a chunk boundary
 *                            followed by the 0x00 end byte (consumed, so *in_used is
 *                            exact); an end byte before out_size is GZ_E_DATA. With
 *                            GZ_LZMA_LENIENT_END decoding just stops after out_size
 *                            bytes, even inside a chunk.
 * Chunks are fully validated: control byte sequence (first chunk resets the
 * dictionary, properties set before the first LZMA chunk, lc + lp <= 4, pb <= 4),
 * every LZMA chunk consumes exactly its packed size and leaves the range coder
 * finished. */
int gz_lzma2_decode(gz_lzma_dec *d, u8 dict_prop, const gz_stream_io *io,
                    u64 out_size, u64 *in_used);

/* Dictionary size encoded by an LZMA2 dictionary property (0 if prop > 40). */
u32 gz_lzma2_dict_size(u8 dict_prop);

/* Same as gz_lzma_decode / gz_lzma2_decode for a whole stream held in memory,
 * output appended to a sink. Convenience for small streams (7z headers,
 * BCJ2 call/jump streams). */
int gz_lzma_decode_mem(gz_lzma_dec *d, const u8 props[5], const u8 *in, size_t in_len,
                       u64 out_size, int (*sink)(void *, const u8 *, size_t), void *user,
                       u64 *in_used);
int gz_lzma2_decode_mem(gz_lzma_dec *d, u8 dict_prop, const u8 *in, size_t in_len,
                        u64 out_size, int (*sink)(void *, const u8 *, size_t), void *user,
                        u64 *in_used);

#endif
