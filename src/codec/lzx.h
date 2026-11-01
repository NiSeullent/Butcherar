/*
 * 고깃ZIP - LZX decoder (CAB, CHM, WIM)
 *
 * LZX is decoded in output frames. The decoder keeps the window, the Huffman
 * code lengths (they are delta coded across blocks), the repeated offsets and
 * the current block across calls; one call produces exactly one frame.
 *
 *   CAB  (folder type 3, window bits = (typeCompress >> 8) & 0x1f, 15..21):
 *        gz_lzx_init(d, wbits, 0); gz_lzx_reset(d) at the start of the folder;
 *        then for every CFDATA block (split blocks joined first):
 *            gz_lzx_decode_frame(d, data, cbData, NULL, out, cbUncomp)
 *        LZX blocks span CFDATA boundaries; every CFDATA holds one frame.
 *   CHM  (LZXC control data: window, reset interval in 32 KiB frames, reset table):
 *        gz_lzx_reset(d) at every reset frame, then decode the 32 KiB frames of the
 *        continuous compressed stream with an in_used pointer:
 *            gz_lzx_decode_frame(d, buf, avail, &used, out, 32768) ; buf += used
 *   WIM  (later task) chunks are independent LZX streams with E8 translation size
 *        12000000 and the WIM block-size coding:
 *            d = gz_lzx_new(log2(chunk_size), GZ_LZX_WIM);   chunk_size 2^15..2^21
 *            gz_lzx_decode_chunk(d, in, in_n, out, out_n)   (= reset + one frame)
 *        A chunk whose compressed size equals its uncompressed size is stored
 *        and must not be passed to the decoder.
 *
 * Errors: GZ_E_DATA for corrupt input (the decoder then needs gz_lzx_reset),
 * GZ_E_LIMIT for frame sizes the decoder was not configured for.
 */
#ifndef GZ_LZX_H
#define GZ_LZX_H
#include "base.h"

#define GZ_LZX_FRAME      32768u    /* CAB / CHM frame size                        */
#define GZ_LZX_WIM_E8     12000000u /* WIM E8 translation size                     */

enum {
    GZ_LZX_WIM = 1    /* WIM variant: no E8 header bit (translation always on,
                         GZ_LZX_WIM_E8), 1-bit "default block size" flag,
                         frames up to the window size                              */
};

typedef struct gz_lzx_dec gz_lzx_dec;

/* window_bits 15..21. NULL on bad parameters or out of memory. */
gz_lzx_dec *gz_lzx_new(u32 window_bits, u32 flags);
void gz_lzx_free(gz_lzx_dec *d);
/* Reconfigure (reuses the window allocation when it is large enough) and reset.
 * GZ_OK, GZ_E_METHOD (bad window bits) or GZ_E_NOMEM. */
int  gz_lzx_init(gz_lzx_dec *d, u32 window_bits, u32 flags);

/* Start a new stream: clears the window history, code lengths, repeated offsets,
 * E8 position and frame counter, and re-reads the E8 header (CAB/CHM). */
void gz_lzx_reset(gz_lzx_dec *d);

/* E8 (x86 CALL) translation size. CAB/CHM streams carry it in their header; this
 * call overrides it for the current stream (0 = off). WIM mode defaults to
 * GZ_LZX_WIM_E8 after every reset. */
void gz_lzx_set_e8(gz_lzx_dec *d, u32 translation_size);

/* Decode one frame of out_n bytes (1..32768; WIM mode: 1..2^window_bits).
 *   in_used == NULL: in[0..in_n) is exactly this frame's data (a CAB CFDATA block,
 *                    a WIM chunk); a trailing pad byte of an odd uncompressed block
 *                    ending with the frame is consumed.
 *   in_used != NULL: in is a continuous stream (CHM); *in_used receives the bytes
 *                    consumed up to the frame end (16-bit aligned between frames).
 * out may be NULL to decode without copying (skipping data that is not needed).
 * A short frame (out_n < 32768) ends the stream: a match running past it is cut. */
int  gz_lzx_decode_frame(gz_lzx_dec *d, const u8 *in, u32 in_n, u32 *in_used, u8 *out, u32 out_n);

/* WIM helper: gz_lzx_reset + gz_lzx_decode_frame(d, in, in_n, NULL, out, out_n). */
int  gz_lzx_decode_chunk(gz_lzx_dec *d, const u8 *in, u32 in_n, u8 *out, u32 out_n);

/* Per-thread cache helpers: gz_ctx_slot(c, GZ_SLOT_LZX, gz_lzx_slot_new, gz_lzx_slot_free)
 * then gz_lzx_init(d, window_bits, flags) before use. */
void *gz_lzx_slot_new(void);
void  gz_lzx_slot_free(void *d);

#endif
