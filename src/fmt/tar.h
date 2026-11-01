/*
 * 고깃ZIP - streaming TAR parser shared by plain TAR and compressed tarballs
 */
#ifndef GZ_TAR_H
#define GZ_TAR_H
#include "arc.h"

typedef struct gz_tar_parser gz_tar_parser;

/* Listing mode (out == NULL): adds entries to a.
 * Extraction mode: entries are matched by order (the n-th entry listed earlier),
 * entries with sel[idx] are written to out. */
gz_tar_parser *gz_tar_parser_new(gz_archive *a, const u8 *sel, gz_out *out, gz_ctx *c);
int  gz_tar_feed(void *parser, const u8 *p, size_t n);     /* sink signature */
/* end of input: closes an entry cut short (GZ_E_TRUNC). Returns GZ_OK or error. */
int  gz_tar_finish(gz_tar_parser *t, int status);
int  gz_tar_done(const gz_tar_parser *t);                  /* end-of-archive marker seen */
void gz_tar_parser_free(gz_tar_parser *t);

/* 1 if h is a valid (non-zero) tar header block */
int  gz_tar_header_ok(const u8 *h512);

#endif
