/*
 * 고깃ZIP - ZIP Implode (method 6) decoder (PKZIP 1.x)
 *
 * LZ77 with a 4 KiB or 8 KiB window and Shannon-Fano coded lengths, distance
 * high bits and (optionally) literals. ZIP general purpose flags select the
 * variant: bit 1 = 8 KiB window, bit 2 = three trees (coded literals, minimum
 * match 3) instead of two (raw 8-bit literals, minimum match 2).
 */
#ifndef GZ_IMPLODE_H
#define GZ_IMPLODE_H
#include "base.h"
#include "stream.h"

typedef struct gz_implode_dec gz_implode_dec;   /* ~1.2 MiB, reusable */

gz_implode_dec *gz_implode_dec_new(void);
void gz_implode_dec_free(gz_implode_dec *d);

/* Decode one imploded entry. d may be NULL (a decoder is created for the call).
 * out_size: uncompressed size from the ZIP header (Implode has no end marker;
 * GZ_SIZE_UNKNOWN decodes until the input runs out).
 * large_window: (zip flags & 2) != 0, three_trees: (zip flags & 4) != 0.
 * References before the start of the data read zeros (as PKZIP / Info-ZIP).
 * Returns GZ_OK, GZ_E_DATA (bad trees / codes), GZ_E_TRUNC or a callback error. */
int gz_implode_decode(gz_implode_dec *d, const gz_stream_io *io, u64 out_size,
                      int large_window, int three_trees);

#endif
