/*
 * 고깃ZIP - shared plumbing for virtual disk images
 * (VHD, VHDX, VMDK, VDI, QCOW/QCOW2, Android sparse)
 *
 * An image format parses its tables at open time into a->priv (shared
 * read-only by every thread) and lists one entry: the virtual disk.
 * view() returns a gz_vd_view, a random-access gz_src whose read_at asks the
 * format's map callback what lies at a virtual offset (zeros, a range of an
 * image/extent file, data decoded into a per-view cache, a fill pattern or
 * the parent disk) and copies it out, merging physically contiguous ranges
 * into single large reads. Per-view state (table caches, decoded grains,
 * an inflater) lives in the view, so views on different threads never share
 * mutable data.
 */
#ifndef GZ_VDISK_H
#define GZ_VDISK_H
#include "arc.h"

enum {
    GZ_VD_ZERO = 0,     /* reads as zeros                                        */
    GZ_VD_RAW,          /* bytes at src[pos...]                                  */
    GZ_VD_MEM,          /* bytes at mem (valid until the next map call)          */
    GZ_VD_FILL,         /* 32-bit pattern, phase taken from the virtual offset   */
    GZ_VD_PARENT        /* same virtual range of the parent disk (zeros if none) */
};

typedef struct gz_vd_ext {
    int kind;           /* GZ_VD_*                                               */
    u32 fill;           /* FILL: byte k of the pattern lands at offsets = k mod 4 */
    u64 len;            /* bytes covered from the queried offset (must be >= 1)  */
    gz_src *src;        /* RAW: source to read (NULL = the view's image file)    */
    u64 pos;            /* RAW: offset in src                                    */
    const u8 *mem;      /* MEM                                                   */
} gz_vd_ext;

typedef struct gz_vd_view gz_vd_view;
typedef int (*gz_vd_map_fn)(gz_vd_view *v, u64 off, gz_vd_ext *x);

struct gz_vd_view {
    gz_src s;                       /* must be first; s.size = virtual size      */
    gz_src *file;                   /* image file this view reads through        */
    const void *img;                /* parsed tables (a->priv), read-only        */
    gz_vd_map_fn map;
    void (*fini)(gz_vd_view *v);    /* frees format caches (optional)            */
    gz_src *parent;                 /* GZ_VD_PARENT reads (owned, optional)      */
    gz_inflater *z;                 /* created on first gz_vd_inflate()          */
};

/* Sanity limits shared by the image formats. */
#define GZ_VD_MAX_SIZE   ((u64)1 << 56)        /* virtual disk size                      */
#define GZ_VD_MAX_TABLE  ((u64)256 << 20)      /* bytes of tables loaded at open time    */
#define GZ_VD_MAX_DEPTH  8                     /* differencing / backing chains          */
#define GZ_VD_MAX_FILES  2048                  /* extent / parent files per archive      */

/* New view (struct of sz >= sizeof(gz_vd_view) bytes, zeroed). NULL on failure. */
gz_vd_view *gz_vd_view_new(size_t sz, gz_src *file, const void *img, u64 size, gz_vd_map_fn map);

/* Decode one Deflate stream stored at [pos, pos+len) of src into dst (cap bytes).
 * zlib != 0: an RFC 1950 header precedes the raw stream. *outn = bytes produced;
 * GZ_E_DATA when the output would exceed cap. */
int gz_vd_inflate(gz_vd_view *v, gz_src *src, u64 pos, u64 len, int zlib, u8 *dst, u32 cap, u32 *outn);

/* Add the virtual disk entry, named after the image file ("name.img", else "disk.img"). */
int gz_vd_add_disk(gz_archive *a, const gz_open_opts *o, u64 vsize, u64 csize, gz_entry **pe);

/* extract() for image formats: streams fmt->view(a, s, idx) into out. */
int gz_vd_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c);

/* Open a file referenced by the image (extent, parent) through o->open_volume.
 * name: UTF-8 (or Latin-1) bytes, relative to the image's directory or absolute
 * (then the base name next to the image is tried as well). The source is kept
 * in a->vols and freed with the archive. GZ_E_VOLUME when it cannot be opened. */
int gz_vd_open_file(gz_archive *a, const gz_open_opts *o, const u8 *name, u32 len, gz_src **out);
/* Same with a UTF-16 name. */
int gz_vd_open_file16(gz_archive *a, const gz_open_opts *o, const gzch *name, u32 len, gz_src **out);

/* Store a short ASCII note (n bytes) as the archive comment (e.g. "log not replayed"). */
void gz_vd_note(gz_archive *a, const char *text, u32 n);
#define GZ_VD_NOTE(a, lit) gz_vd_note(a, lit, (u32)sizeof(lit) - 1)

/* Copy an ASCII string into a method buffer. */
void gz_vd_method_str(char *buf, u32 cap, const char *s);

static inline int gz_vd_pow2(u64 x) { return x && !(x & (x - 1)); }
static inline u32 gz_vd_log2(u64 x) { u32 n = 0; while (x > 1) { x >>= 1; n++; } return n; }

#endif
