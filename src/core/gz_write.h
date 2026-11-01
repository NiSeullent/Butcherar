/*
 * 고깃ZIP - archive creation
 *
 * A writer (src/fmt/NAME_write.c, registered with "GZ_WRITER(sym)") turns a list
 * of items into an archive written to a gz_sink. The engine supplies the
 * items (already enumerated, with archive-relative names) and opens each
 * file on demand through o->open_item.
 */
#ifndef GZ_WRITE_H
#define GZ_WRITE_H
#include "arc.h"

enum {                      /* output formats */
    GZ_WF_NONE = 0,
    GZ_WF_ZIP, GZ_WF_7Z, GZ_WF_TAR, GZ_WF_TGZ, GZ_WF_TBZ2, GZ_WF_TXZ, GZ_WF_TZST,
    GZ_WF_GZ, GZ_WF_BZ2, GZ_WF_XZ, GZ_WF_ZST, GZ_WF_ISO,
    GZ_WF_COUNT
};

enum {                      /* methods (gz_wopts.method); 0 = format default */
    GZ_WM_DEFAULT = 0, GZ_WM_STORE, GZ_WM_DEFLATE, GZ_WM_DEFLATE64, GZ_WM_BZIP2,
    GZ_WM_LZMA, GZ_WM_LZMA2, GZ_WM_PPMD, GZ_WM_ZSTD, GZ_WM_COUNT
};

enum { GZ_WE_NONE = 0, GZ_WE_ZIPCRYPTO, GZ_WE_AES256 };

typedef struct gz_witem {
    const gzch *name;       /* archive path, '/' separated, no leading '/'          */
    u64 size;               /* bytes (files)                                        */
    u64 mtime;              /* FILETIME UTC, 0 = unknown                            */
    u64 ctime, atime;       /* FILETIME UTC, 0 = unknown                            */
    u32 attr;               /* FILE_ATTRIBUTE_* bits                                */
    u32 unix_mode;          /* st_mode incl. type bits, 0 = derive from is_dir/attr */
    u8  is_dir;
    u8  is_link;            /* symbolic link: link_target holds the target          */
    u8  pad_[2];
    const gzch *link_target;
    void *user;             /* engine data handed back to open_item                 */
} gz_witem;

/* sequential reader for one input file */
typedef struct gz_wsrc {
    int (*read)(struct gz_wsrc *w, u8 *buf, u32 cap, u32 *got);   /* *got 0 = end */
    void *h;
} gz_wsrc;

/* archive output */
typedef struct gz_sink {
    int (*write)(struct gz_sink *k, const void *p, size_t n);            /* append      */
    int (*write_at)(struct gz_sink *k, u64 off, const void *p, size_t n);  /* patch earlier bytes, NULL for pipes */
    u64 pos;                /* bytes appended so far (maintained by gz_sink_write)  */
    void *h;
} gz_sink;

typedef struct gz_wopts {
    int format;             /* GZ_WF_*                                              */
    int method;             /* GZ_WM_*                                              */
    int level;              /* 0 (store) .. 9 (ultra), default 5                    */
    u32 dict_size;          /* 0 = default for the level                            */
    int solid;              /* 7z: 1 solid (default), 0 one block per file           */
    int threads;            /* 0 = automatic                                        */
    int encryption;         /* GZ_WE_*                                              */
    const gzch *password;
    int encrypt_names;      /* 7z: encrypt the file list too                        */
    int legacy_names;       /* ZIP: write names in the system code page (no UTF-8 flag) */
    const gzch *label;      /* ISO volume label                                     */
    /* open/close an input file; return GZ_OK or an error (the item is then reported
     * through on_error and skipped, or the whole job fails if on_error is NULL)   */
    int  (*open_item)(void *user, const gz_witem *it, gz_wsrc **src);
    void (*close_item)(void *user, const gz_witem *it, gz_wsrc *src);
    /* item could not be read: return GZ_OK to skip it, anything else to abort    */
    int  (*on_error)(void *user, const gz_witem *it, int err);
    /* progress: bytes of input consumed so far / total input bytes              */
    void (*progress)(void *user, u64 in_done, u64 in_total);
    void *user;
    volatile long *cancel;
} gz_wopts;

typedef struct gz_writer {
    int format;             /* GZ_WF_*                                              */
    const char *name;       /* "ZIP", "7z", "TAR.GZ"                                */
    const char *ext;        /* default extension without dot: "zip", "tar.gz"       */
    u32 methods;            /* bit mask of supported GZ_WM_* (1u << method)          */
    u32 encryptions;        /* bit mask of supported GZ_WE_*                         */
    int  (*write)(const gz_wopts *o, const gz_witem *items, u32 n, gz_sink *out, gz_ctx *c);
} gz_writer;

#define GZ_WRITER(sym) extern const gz_writer sym;
extern const gz_writer *const gz_writers[];   /* generated, NULL terminated */

const gz_writer *gz_writer_find(int format);
/* Create an archive: dispatches to the registered writer. */
int gz_write_archive(const gz_wopts *o, const gz_witem *items, u32 n, gz_sink *out, gz_ctx *c);

/* helpers for writers */
int gz_sink_write(gz_sink *k, const void *p, size_t n);       /* write + advance pos */
int gz_sink_patch(gz_sink *k, u64 off, const void *p, size_t n);

#endif
