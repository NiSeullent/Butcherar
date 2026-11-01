/*
 * 고깃ZIP - single-stream compressed files (.gz .bz2 .xz .lzma .zst .lz4 .lz .Z ...)
 *
 * A stream codec only has to decode its whole stream into a sink. The shared
 * code in streamfmt.c turns that into an archive: a tarball inside is listed
 * and extracted entry by entry (solid), anything else becomes one file named
 * after the stream header or the archive name without its extension.
 *
 * Define a format with:
 *   static const gz_stream_codec xz_codec = { ... };
 *   GZ_FORMAT(gz_fmt_xz)
 *   const gz_format gz_fmt_xz = GZ_STREAM_FORMAT("XZ", "xz txz", xz_probe, &xz_codec);
 */
#ifndef GZ_STREAMFMT_H
#define GZ_STREAMFMT_H
#include "arc.h"

typedef int (*gz_sink_fn)(void *user, const u8 *p, size_t n);

typedef struct gz_stream_info {
    u8  name[256];        /* original file name from the header (raw), name_len 0 = none */
    u32 name_len;
    int name_enc;         /* GZ_NE_* */
    i64 mtime;            /* unix time */
    int has_mtime;
    u64 usize;            /* uncompressed size if stored in the stream, else GZ_SIZE_UNKNOWN */
} gz_stream_info;

typedef struct gz_stream_codec {
    const char *tar_name;      /* type name when it holds a tarball: "TAR.XZ"           */
    const char *method;        /* method column: "LZMA2", "Deflate"                    */
    const char *tar_exts;      /* extensions that mean ".tar" inside: "txz"            */
    /* Decode every member/frame of the stream in s into sink. Must stop without error
     * (return GZ_OK or GZ_E_SKIP) when sink returns GZ_E_SKIP; must propagate other
     * sink errors. Should verify integrity checks (CRC/xxhash) when present. */
    int  (*decode)(gz_src *s, gz_sink_fn sink, void *user, gz_ctx *c);
    /* Optional: fill header information (inf is pre-set to "nothing known"). */
    void (*info)(gz_src *s, gz_stream_info *inf, gz_ctx *c);
} gz_stream_codec;

int  gz_sfmt_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c);
void gz_sfmt_close(gz_archive *a);
int  gz_sfmt_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c);
int  gz_sfmt_extract_solid(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c);
void gz_sfmt_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap);

#define GZ_STREAM_FORMAT(name, exts, probe, codec) \
    { name, exts, 0, probe, gz_sfmt_open, gz_sfmt_close, gz_sfmt_extract, gz_sfmt_extract_solid, \
      0, gz_sfmt_method, 0, codec }

#endif
