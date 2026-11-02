/*
 * 고깃ZIP - RAR 1.5 - 4.x unpacker (archives "Rar!\x1A\x07\x00" and RAR 1.4 "RE~^")
 *
 * Three algorithms share one decoder, as in unrar (window, bit reader, the LZ
 * repeat distances and the last match are common state):
 *   15     RAR 1.5 adaptive Huffman + LZ (also used for RAR 1.3 / 1.4 data)
 *   20, 26 RAR 2.0 LZ + Huffman with multimedia (audio delta) blocks
 *   29, 36 RAR 2.9 / 3.x / 4.x LZ + Huffman, PPMd (var.H) blocks with escape
 *          codes for matches / filters, and RAR VM filters: the six standard
 *          programs (E8, E8E9, ITANIUM, DELTA, RGB, AUDIO) are recognised by
 *          length + CRC32 of their byte code (as 7-Zip and unrar do) and run
 *          natively; any other VM program is GZ_E_METHOD.
 *
 * Solid archives: params.solid continues the previous call's stream (window,
 * tables, PPMd model, filter definitions, adaptive RAR 1.5 state); each file
 * still has its own packed data, whose bit stream starts at a byte boundary.
 * A continuation after a failed call is GZ_E_DATA.
 *
 * End of a file: decoding stops at out_size; a following end-of-file marker
 * (LZ "end of block + new file", PPMd escape 2) or RAR 2.0's table switch is
 * consumed so that the next solid file sees the same state as in unrar. With
 * an unknown size (GZ_SIZE_UNKNOWN) the 2.9 stream must end with its marker;
 * 1.5 / 2.0 streams end with their packed data.
 *
 * Hostile input: Huffman tables (over-subscribed = GZ_E_DATA), distances
 * (beyond the data decoded so far, or 0), the bit position (no reads past the
 * packed data), VM code / filter parameters and the PPMd range coder are all
 * checked; loops consume input or produce bounded output.
 */
#ifndef GZ_RAR3DEC_H
#define GZ_RAR3DEC_H
#include "base.h"
#include "stream.h"

typedef struct gz_rar3_dec gz_rar3_dec;

gz_rar3_dec *gz_rar3_dec_new(void);
void gz_rar3_dec_free(gz_rar3_dec *d);

/* Window size (a power of two, >= 1 MiB) for a stream with dictionary size
 * dict whose total output (all files of a solid run) is total bytes
 * (GZ_SIZE_UNKNOWN when unknown): data is never referenced further back than
 * it was produced, so small streams get a small window. RAR 1.5 - 4.x
 * dictionaries are 64 KiB .. 4 MiB, so the result is at most 4 MiB for them. */
u64 gz_rar3_window_size(u64 dict, u64 total);

typedef struct {
    u32 version;     /* unpack version from the file header: <= 15 (1.3 - 1.5),
                        20, 26, 29, 36; anything else is GZ_E_METHOD             */
    u64 window;      /* from gz_rar3_window_size; a larger cached one may be used */
    int solid;       /* continue the previous file's stream                        */
} gz_rar3_params;

/* Decode one file's packed data (io->read) into io->write. out_size: declared
 * unpacked size or GZ_SIZE_UNKNOWN. Returns GZ_OK, GZ_E_DATA (corrupt),
 * GZ_E_METHOD (unknown VM program / version), GZ_E_LIMIT (window or PPMd memory
 * too large), GZ_E_NOMEM, or a callback error unchanged. */
int gz_rar3_decode(gz_rar3_dec *d, const gz_stream_io *io, u64 out_size, const gz_rar3_params *p);

/* Free the window (and the PPMd model) if larger than keep bytes (0 = always). */
void gz_rar3_dec_trim(gz_rar3_dec *d, u64 keep);

#endif
