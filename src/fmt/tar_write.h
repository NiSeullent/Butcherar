/*
 * 고깃ZIP - TAR stream writer (POSIX ustar + pax extended headers)
 *
 * Writes strictly sequentially (never uses out->write_at), so compressed
 * tarball writers (TAR.GZ, TAR.XZ, ...) can call it with a sink that
 * compresses on the fly.
 */
#ifndef GZ_TAR_WRITE_H
#define GZ_TAR_WRITE_H
#include "gz_write.h"

/* Every item of items[0..n) as a tar member; o->open_item/close_item/on_error/progress/
 * cancel are honoured, method/level/encryption are ignored. Ends with the two zero
 * blocks and pads the stream to a 10240-byte record. */
int gz_tar_write(const gz_wopts *o, const gz_witem *items, u32 n, gz_sink *out, gz_ctx *c);

#endif
