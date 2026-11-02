/*
 * 고깃ZIP - .xz / .lzma / .lz stream decoding shared with other readers
 *
 * xz.c registers the XZ, LZMA (LZMA-alone) and LZIP single-stream formats and
 * exports the pieces other readers reuse: the .xz container decoder (ZIP
 * method 95) and the per-thread LZMA decoder (ZIP method 14).
 */
#ifndef GZ_XZ_H
#define GZ_XZ_H
#include "arc.h"
#include "lzma.h"

/* Per-thread LZMA/LZMA2 decoder cached in GZ_SLOT_LZMA (shared by XZ, LZMA, LZIP
 * and ZIP). Flags and limit are reset to the defaults on every call. NULL when out
 * of memory. c must not be NULL. */
gz_lzma_dec *gz_xz_lzma_dec(gz_ctx *c);

/* Decode complete .xz data pulled with in->read (in->write is not used): one or
 * more streams with stream padding; trailing bytes that do not start a stream
 * are ignored. Every header CRC, block check (CRC32 / CRC64 / SHA-256; other
 * check types are skipped like xz does), block size field, index record and
 * stream footer is verified. Output goes to sink(user, p, n); a sink error
 * (GZ_E_SKIP, GZ_E_CANCEL...) is returned unchanged. c may be NULL.
 * Returns GZ_OK, GZ_E_FORMAT (not .xz), GZ_E_DATA (corrupt), GZ_E_CRC,
 * GZ_E_TRUNC, GZ_E_METHOD (unknown filter / reserved flags), GZ_E_LIMIT,
 * GZ_E_NOMEM or a reader error. */
int gz_xz_decode_io(const gz_stream_io *in, int (*sink)(void *user, const u8 *p, size_t n),
                    void *user, gz_ctx *c);

#endif
