/*
 * 고깃ZIP - PPMd var.I rev.1 ("Ppmd8"): ZIP compression method 98 (decoder + encoder)
 *
 * Model as in 7-Zip's Ppmd8 (byte-identical with 7-Zip for the RESTART and CUT_OFF
 * restore methods) plus the FREEZE method of Shkarin's var.I rev.1, which 7-Zip leaves
 * out. Range coder: Subbotin's carry-less coder.
 *
 * ZIP method 98 data = 2-byte LE header + range-coded stream + end marker:
 *   header v: order = (v & 0xF) + 1 (2..16), memory = ((v >> 4) & 0xFF) + 1 MiB,
 *             restore method = v >> 12 (0 restart, 1 cut off, 2 freeze)
 */
#ifndef GZ_PPMD8_H
#define GZ_PPMD8_H
#include "ppmd.h"

#define GZ_PPMD8_MIN_ORDER 2
#define GZ_PPMD8_MAX_ORDER 16

enum {
    GZ_PPMD8_RESTART = 0,       /* start over when the memory block is full          */
    GZ_PPMD8_CUT_OFF = 1,       /* prune the context tree                            */
    GZ_PPMD8_FREEZE  = 2        /* stop growing the model (PPMd var.I rev.1 only)    */
};

gz_ppmd8 *gz_ppmd8_new(void);
void gz_ppmd8_free(gz_ppmd8 *p);

/* Decode a ZIP method 98 stream (header included). out_size: the entry's unpacked
 * size (decoding stops there and the end marker must follow) or GZ_SIZE_UNKNOWN (up to
 * the end marker). The model memory is kept and reused when the size is unchanged.
 * Returns GZ_OK, GZ_E_DATA (corrupt / bad header), GZ_E_TRUNC, GZ_E_METHOD (restore
 * method > 2), GZ_E_NOMEM or a callback error (GZ_E_SKIP etc. unchanged).
 * *in_used (optional) receives the number of packed bytes consumed; like 7-Zip, a ZIP
 * reader should also treat *in_used != the entry's packed size as a data error.
 * Restore method 2 (FREEZE) is decoded too, although 7-Zip rejects it as unsupported. */
int gz_ppmd8_zip_decode(gz_ppmd8 *p, const gz_stream_io *io, u64 out_size);
int gz_ppmd8_zip_decode_ex(gz_ppmd8 *p, const gz_stream_io *io, u64 out_size, u64 *in_used);

/* Encode io->read input until got == 0 as a ZIP method 98 stream (header, data, end
 * marker). order 2..16, mem_mb 1..256, restore GZ_PPMD8_*. 7-Zip's level L uses
 * order L + 3, mem 1 << (L - 1) MiB (reduced for small inputs: the smallest power of
 * two m with size <= m MiB / 16), restore L < 7 ? RESTART : CUT_OFF.
 * *in_size / *out_size (optional) receive the byte counts. */
int gz_ppmd8_zip_encode(gz_ppmd8 *p, u32 order, u32 mem_mb, u32 restore, const gz_stream_io *io);
int gz_ppmd8_zip_encode_ex(gz_ppmd8 *p, u32 order, u32 mem_mb, u32 restore, const gz_stream_io *io,
                           u64 *in_size, u64 *out_size);
/* 7-Zip's parameters for a level 1..9 and the input size (GZ_SIZE_UNKNOWN if unknown). */
void gz_ppmd8_zip_level(int level, u64 size, u32 *order, u32 *mem_mb, u32 *restore);

#endif
