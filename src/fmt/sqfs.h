/*
 * 고깃ZIP - helpers shared by the SquashFS and CramFS readers (implemented in squashfs.c)
 */
#ifndef GZ_SQFS_H
#define GZ_SQFS_H
#include "arc.h"

/* One complete zlib stream in[0..n) (2-byte header, Deflate, Adler-32) decoded into
 * out[0..cap). *z is created on first use (caller frees it with gz_inflater_free).
 * GZ_E_DATA: bad header / stream / more than cap bytes; GZ_E_CRC: Adler-32 mismatch. */
int gz_sqfs_zlib(gz_inflater **z, const u8 *in, u32 n, u8 *out, u32 cap, u32 *on);

#endif
