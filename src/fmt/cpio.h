/*
 * 고깃ZIP - CPIO parser shared by plain .cpio files, compressed cpio streams
 * (streamfmt.c: .cpio.gz, macOS Payload, initramfs), RPM payloads and XAR/pkg,
 * plus a helper that finds the registered single-stream codec for a source.
 */
#ifndef GZ_CPIO_H
#define GZ_CPIO_H
#include "arc.h"
#include "streamfmt.h"

/* 1 when p[0..n) starts with a cpio header magic: newc "070701", crc "070702",
 * odc "070707" or old binary 070707 (either byte order). */
int gz_cpio_magic(const u8 *p, u32 n);

/* Push parser, same contract as gz_tar_parser:
 *   listing    (out == NULL): adds an entry to a for every file, directory and
 *              symbolic link (devices, fifos, sockets and TRAILER!!! are left out);
 *   extraction (out != NULL): entries are matched by order with the listing,
 *              entries with sel[idx] are opened/written/closed, the others are
 *              skipped. Stops (gz_cpio_done) once every selected entry is done.
 * Symlink targets up to 16 KiB go to a->raw (link_off/link_len), longer ones are
 * the entry data. Data of the crc format (070702) is checked (GZ_E_CRC). */
typedef struct gz_cpio_parser gz_cpio_parser;
gz_cpio_parser *gz_cpio_parser_new(gz_archive *a, const u8 *sel, gz_out *out, gz_ctx *c);
int  gz_cpio_feed(void *parser, const u8 *p, size_t n);   /* gz_sink_fn signature */
/* End of input. Extraction: closes an entry cut short (status, or GZ_E_TRUNC).
 * Listing: resolves hard links (newc stores the data with one link only: the
 * others become is_link = 2 entries naming it). Returns status or an error. */
int  gz_cpio_finish(gz_cpio_parser *t, int status);
int  gz_cpio_done(const gz_cpio_parser *t);
void gz_cpio_parser_free(gz_cpio_parser *t);

/* A whole cpio stream produced by dec(s, ...) (a gz_stream_codec decode, or any
 * function with that signature). list: adds the entries to a (a damaged tail is
 * tolerated once entries were found). extract: one pass, see the parser above. */
typedef int (*gz_decode_fn)(gz_src *s, gz_sink_fn sink, void *user, gz_ctx *c);
int gz_cpio_list_stream(gz_archive *a, gz_src *s, gz_decode_fn dec, gz_ctx *c);
int gz_cpio_extract_stream(gz_archive *a, gz_src *s, gz_decode_fn dec, const u8 *sel,
                           gz_out *out, gz_ctx *c);

/* Registered single-stream format (gzip, bzip2, xz, zstd, lz4, pbzx, ...) whose
 * probe gives the best score for s, NULL when none accepts it. */
const gz_stream_codec *gz_stream_codec_find(gz_src *s);
/* Plain copy of s into sink (a gz_decode_fn for uncompressed data). */
int gz_stream_copy(gz_src *s, gz_sink_fn sink, void *user, gz_ctx *c);

#endif
