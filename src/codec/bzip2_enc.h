/*
 * 고깃ZIP - BZip2 encoder
 *
 * Writes standard bzip2 streams ("BZh1".."BZh9", one stream, block and stream
 * CRCs) that bzip2 / 7-Zip / any libbz2 decode. Per block: RLE1, BWT by suffix
 * sorting (SA-IS, linear time even on highly repetitive data) of the minimal
 * rotation, MTF + RLE2, 2..6 Huffman tables refined over 4 passes like bzip2
 * (code lengths limited to 17).
 *
 * Memory: about 6 bytes per block byte (5.4 MiB at level 9) + 1.3 MiB of buffers.
 */
#ifndef GZ_BZIP2_ENC_H
#define GZ_BZIP2_ENC_H
#include "base.h"
#include "stream.h"

typedef struct gz_bzip2_enc gz_bzip2_enc;

/* level 1..9 = block size 100k..900k (out-of-range values are clamped). */
gz_bzip2_enc *gz_bzip2_enc_new(int level);
void gz_bzip2_enc_free(gz_bzip2_enc *e);

/* Pull all input with io->read (until *got == 0), push the complete compressed
 * stream with io->write. Reusable: each call writes one new stream.
 * Returns GZ_OK, GZ_E_NOMEM or a reader/writer error unchanged. */
int gz_bzip2_encode(gz_bzip2_enc *e, const gz_stream_io *io);

/* Testing only: emit "randomized" blocks (the bzip2 0.9.0 feature every decoder
 * still has to support). Off by default. */
void gz_bzip2_enc_set_randomized(gz_bzip2_enc *e, int on);

#endif
