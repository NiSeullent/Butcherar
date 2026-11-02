/*
 * 고깃ZIP - Zstandard encoder (RFC 8878)
 *
 * Writes one standard frame per call: frame header (window descriptor or single
 * segment, optional content size), blocks of at most 128 KiB, optional XXH64
 * content checksum. Each block is emitted as compressed, RLE or raw, whichever
 * is smallest. Compressed blocks carry Huffman literals (1 or 4 streams, new or
 * repeated table; raw / RLE literals when better) and FSE-coded sequences
 * (predefined, RLE, computed or repeated tables, chosen by estimated cost) with
 * repeat offsets.
 *
 * Levels (zstd's own scale; parameters follow the reference encoder's table):
 *     0      store: raw blocks only
 *     1-2    fast       single hash table, accelerating skip over misses
 *     3-4    dfast      long (8-byte) + short hash tables
 *     5      greedy     rows of recent positions with 8-bit tags (zstd's row
 *                       match finder: one tag compare per row instead of a chain walk)
 *     6-7    lazy       rows, one step of lazy evaluation
 *     8-12   lazy2      rows, two steps
 *     13-15  btlazy2    binary trees, two steps
 *     16-19  btopt      binary trees + price-driven optimal parser (16-17 btopt;
 *                       18-19 btultra: fractional prices, no early exits, 3-byte matches)
 *
 * Input is pulled through io->read in large chunks into a window buffer of
 * window + max(window, 1 MiB) + 384 KiB; memory is bounded by the window and the
 * match tables whatever the input size (gz_zstd_enc_memusage): about 3 MiB at
 * level 0, 4 at 1, 7 at 3, 21 at 9, 51 at 12, 43 at 16 and 99 MiB at 19; much less
 * when size_hint announces a small input.
 * No global mutable state: any number of encoders can run on different threads;
 * one encoder is not shared between threads. Output does not depend on the CPU
 * (x86-64 compares row tags with SSE2, other targets with 64-bit SWAR).
 */
#ifndef GZ_ZSTD_ENC_H
#define GZ_ZSTD_ENC_H
#include "base.h"
#include "stream.h"

#define GZ_ZSTD_LEVEL_MAX     19
#define GZ_ZSTD_WINDOWLOG_MIN 10
#define GZ_ZSTD_WINDOWLOG_MAX 27       /* 128 MiB */

typedef struct gz_zstd_enc_opts {
    int level;          /* 0 (store) .. 19; larger values are clamped, negative = 3     */
    u32 window_log;     /* 10..27; 0 = default of the level (19..23)                    */
    int checksum;       /* 1 = append the XXH64 content checksum (default)              */
    u64 size_hint;      /* expected input size, 0 = unknown: inputs smaller than the
                           level's window get a smaller window and smaller tables
                           (a wrong hint only costs ratio, never correctness)          */
} gz_zstd_enc_opts;

typedef struct gz_zstd_enc gz_zstd_enc;

/* Defaults of a level (window_log 0, checksum on, no size hint). */
void gz_zstd_enc_opts_init(gz_zstd_enc_opts *o, int level);
/* Approximate bytes an encoder with these options allocates. */
u64  gz_zstd_enc_memusage(const gz_zstd_enc_opts *o);

/* o == NULL: level 3. NULL when out of memory or window_log is out of range. */
gz_zstd_enc *gz_zstd_enc_new(const gz_zstd_enc_opts *o);
void gz_zstd_enc_free(gz_zstd_enc *e);

/* Compress everything io->read yields (until *got == 0) into one frame pushed
 * through io->write. content_size: the exact input size, stored in the frame
 * header (enables single-segment frames), or GZ_SIZE_UNKNOWN. If the input turns
 * out to have another size the frame is not valid and GZ_E_DATA is returned.
 * Reusable: each call writes an independent frame. Returns GZ_OK, GZ_E_NOMEM,
 * GZ_E_DATA or the first error of io->read / io->write unchanged. */
int gz_zstd_encode(gz_zstd_enc *e, const gz_stream_io *io, u64 content_size);

/* Byte counts of the last encode call. */
u64 gz_zstd_enc_in_size(const gz_zstd_enc *e);
u64 gz_zstd_enc_out_size(const gz_zstd_enc *e);

#endif
