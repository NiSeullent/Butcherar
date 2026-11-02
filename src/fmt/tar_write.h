/*
 * 고깃ZIP - TAR stream writer (POSIX ustar + pax extended headers)
 *
 * The archive is produced by a pull-style generator (gz_tar_reader): every
 * call hands out the next bytes of the tar stream, reading the input files on
 * demand. It plugs straight into an encoder's gz_stream_io read callback, so
 * compressed tarballs (TAR.GZ, TAR.XZ, ...) are written in one pass without an
 * intermediate file. Output is strictly sequential (never uses write_at).
 */
#ifndef GZ_TAR_WRITE_H
#define GZ_TAR_WRITE_H
#include "gz_write.h"

/* Every item of items[0..n) as a tar member; o->open_item/close_item/on_error/progress/
 * cancel are honoured, method/level/encryption are ignored. Ends with the two zero
 * blocks and pads the stream to a 10240-byte record. */
int gz_tar_write(const gz_wopts *o, const gz_witem *items, u32 n, gz_sink *out, gz_ctx *c);

typedef struct gz_tar_reader gz_tar_reader;

/* Generator for the same byte stream gz_tar_write produces. items and o must
 * outlive the reader. NULL when out of memory. */
gz_tar_reader *gz_tar_reader_new(const gz_wopts *o, const gz_witem *items, u32 n, gz_ctx *c);
/* gz_stream_io-compatible read (ctx = the reader): fills buf with up to cap bytes
 * of the tar stream (cap bytes unless the stream ends), *got = 0 at its end.
 * Errors (GZ_E_CANCEL, GZ_E_NOMEM, a read error the on_error callback did not
 * accept...) are sticky: every later call returns the same error. */
int gz_tar_reader_read(void *ctx, u8 *buf, u32 cap, u32 *got);
/* Closes the input file still open (if any) and frees the reader. */
void gz_tar_reader_free(gz_tar_reader *t);
/* Upper estimate of the stream size (headers, data, padding; pax records of
 * names up to 300 bytes), e.g. to size a compressor's window. */
u64 gz_tar_size_estimate(const gz_witem *items, u32 n);

/* UTF-16 name -> UTF-8 bytes (out: at least 3 * n bytes); lone U+DC80..U+DCFF
 * stand for raw bytes of non-UTF-8 POSIX names and are written back as those
 * bytes, other unpaired surrogates become U+FFFD. Returns the byte count. */
u32 gz_tar_name_utf8(const gzch *s, size_t n, u8 *out);

#endif
