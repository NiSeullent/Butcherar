/*
 * 고깃ZIP - RAR 5.0 unpacker (RAR 5.x / 6.x / 7.x "v5" and RAR 7.0 "v7" algorithms)
 *
 * LZ77 with canonical Huffman tables (main 306, distance 64 or 80, low
 * distance 16, repeat length 44 symbols), four repeated distances, blocks
 * with table / last-block flags, and the DELTA, E8, E8E9 and ARM filters,
 * which are applied to copies of the window data in output order.
 *
 * A decoder is reused across files. In solid archives the window, the
 * Huffman tables and the repeated distances continue from the previous
 * file (params.solid); each file still has its own packed stream that
 * starts with a block header.
 *
 * Hostile input: every table, distance, filter and block bound is checked;
 * a distance beyond the data decoded so far, an invalid Huffman code, a
 * block over-read or a filter that cannot fit the window is GZ_E_DATA.
 * Output stops at the declared size (more data is GZ_E_DATA).
 */
#ifndef GZ_RAR5DEC_H
#define GZ_RAR5DEC_H
#include "base.h"
#include "stream.h"

typedef struct gz_rar5_dec gz_rar5_dec;

gz_rar5_dec *gz_rar5_dec_new(void);
void gz_rar5_dec_free(gz_rar5_dec *d);

/* Window size (a power of two, >= 256 KiB) for a stream with dictionary
 * size dict whose total output (all files of a solid run) is total bytes
 * (GZ_SIZE_UNKNOWN when unknown): data can never be referenced further back
 * than it was produced, so small files get a small window. */
u64 gz_rar5_window_size(u64 dict, u64 total);

typedef struct {
    u64 window;      /* from gz_rar5_window_size; the caller enforces its memory cap */
    int v7;          /* RAR 7.0 algorithm (compression version 1): 80 distance codes */
    int solid;       /* continue the previous file's stream (window, tables, distances) */
} gz_rar5_params;

/* Decode one file's packed stream. out_size: declared unpacked size or
 * GZ_SIZE_UNKNOWN (then the stream's last block ends it). A solid
 * continuation after a failed call is GZ_E_DATA. Sink errors are returned
 * unchanged. GZ_E_NOMEM when the window cannot be allocated. */
int gz_rar5_decode(gz_rar5_dec *d, const gz_stream_io *io, u64 out_size, const gz_rar5_params *p);

/* Free the window if it is larger than keep bytes (0 = always); the next
 * non-solid call allocates a new one. */
void gz_rar5_dec_trim(gz_rar5_dec *d, u64 keep);

#endif
