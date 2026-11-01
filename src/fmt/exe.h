/*
 * 고깃ZIP - helpers shared by the executable readers (PE/TE, ELF, Mach-O)
 *
 * Entry names are assembled as UTF-8 in a gz_xname (silently truncated at
 * GZ_XNAME_MAX bytes) and added with GZ_NE_UTF8. Name parts taken from the
 * file (section names, resource names) are sanitised: path separators become
 * '_' so a hostile name cannot add folders, "." / ".." components are
 * escaped, and empty parts become "_".
 */
#ifndef GZ_EXE_H
#define GZ_EXE_H
#include "arc.h"

#define GZ_XNAME_MAX 1024

typedef struct { char b[GZ_XNAME_MAX]; u32 n; } gz_xname;

static inline void gz_xn_reset(gz_xname *w) { w->n = 0; }
void gz_xn_str(gz_xname *w, const char *s);              /* literal text (may contain '/')   */
void gz_xn_num(gz_xname *w, u64 v);                      /* decimal                          */
/* One sanitised name part from 8-bit text (Latin-1, stops at NUL). */
void gz_xn_part8(gz_xname *w, const u8 *p, u32 n);
/* One sanitised name part from n UTF-16LE units. */
void gz_xn_part16(gz_xname *w, const u8 *le, u32 n);
/* Append the extension ext (".png") unless the last part already has one. */
void gz_xn_ext_if_none(gz_xname *w, const char *ext);

/* Add an entry named w (UTF-8). */
int gz_exe_add(gz_archive *a, const gz_xname *w, gz_entry **pe);

/* Extension (".zip", ".png", ...) for data starting with p[0..n), or NULL.
 * Used for overlays and untyped resources so extracted files open directly. */
const char *gz_exe_sniff(const u8 *p, u32 n);

/* Reading helpers for formats of either byte order. */
static inline u16 gz_x16(const u8 *p, int be) { return be ? rd16be(p) : rd16(p); }
static inline u32 gz_x32(const u8 *p, int be) { return be ? rd32be(p) : rd32(p); }
static inline u64 gz_x64(const u8 *p, int be) { return be ? rd64be(p) : rd64(p); }

/* Add the data after an image, [off, off+len) of s, as "[overlay]<ext>" (ext sniffed).
 * Ranges of fewer than 8 zero bytes (alignment padding) are not listed.
 * The entry is a stored range: e->off = off, usize = csize = len. */
int gz_exe_add_overlay(gz_archive *a, gz_src *s, u64 off, u64 len, const char *name);

/* extract / view for formats whose entries are plain ranges (e->off, e->usize) */
int gz_exe_extract_range(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c);
gz_src *gz_exe_view_range(gz_archive *a, gz_src *s, u32 idx);

#endif
