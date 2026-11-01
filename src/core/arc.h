/*
 * 고깃ZIP - archive model and format plug-in interface
 *
 * Every archive format is a gz_format (src/fmt/<name>.c) registered with a
 * GZ_FORMAT(symbol) line; tools/gen_registry.sh collects those lines into
 * the probe table. gz_arc_open() reads the first 64 KiB, asks every format
 * for a confidence score and opens the archive with the best one.
 *
 * After open the archive is an array of gz_entry (names decoded to UTF-16,
 * '/'-separated, sanitised) plus a folder tree. Extraction pushes entry data
 * into a gz_out supplied by the engine.
 *
 * See docs/ARCHITECTURE.md for the rules every format follows.
 */
#ifndef GZ_ARC_H
#define GZ_ARC_H
#include "base.h"
#include "stream.h"
#include "inflate.h"
#include "crypto.h"

typedef struct gz_archive gz_archive;
typedef struct gz_format gz_format;
typedef struct gz_ctx gz_ctx;

/* codepage selector: 0 = automatic */
#define GZ_CP_AUTO 0
#define GZ_CP_UTF8 65001

enum { GZ_ENC_NONE = 0, GZ_ENC_ZIPCRYPTO = 1, GZ_ENC_AES = 2, GZ_ENC_OTHER = 3 };
enum { GZ_MT_NONE = 0, GZ_MT_FILETIME = 1, GZ_MT_DOS = 2 };

/* how the raw name bytes of an entry are encoded */
enum {
    GZ_NE_LEGACY = 0,     /* system code page; joins automatic code-page detection */
    GZ_NE_UTF8 = 1,       /* UTF-8 by specification or flag                       */
    GZ_NE_UTF16LE = 2,    /* 7z, NTFS, WIM, CFB, Joliet-LE, UDF(after decode) ... */
    GZ_NE_UTF16BE = 3,    /* Joliet, HFS+                                         */
    GZ_NE_OEM = 4         /* DOS OEM code page (FAT short names, old ARJ/LZH)     */
};

typedef struct {
    u64 usize, csize;     /* GZ_SIZE_UNKNOWN when not known                      */
    u64 off;              /* format private: usually the data offset               */
    u64 aux;              /* format private                                        */
    u64 mtime;            /* FILETIME (UTC) or DOS (date<<16|time, local)          */
    u32 crc;              /* CRC-32 when has_crc                                   */
    u32 attr;             /* FILE_ATTRIBUTE_* (RO 1, HIDDEN 2, SYSTEM 4, DIR 0x10, ARCHIVE 0x20) */
    u32 unix_mode;        /* st_mode incl. type bits, 0 = unknown                  */
    u32 raw_off;          /* raw name bytes in a->raw                              */
    u32 raw_len;
    u32 uni_off;          /* UTF-8 name from a unicode extra field (uni_len 0 = none) */
    u32 uni_len;
    u32 link_off;         /* symlink target bytes in a->raw (link_len 0 = target is the data) */
    u32 link_len;
    u32 aux32;            /* format private                                        */
    u16 method;           /* format specific method id                             */
    u16 flags;            /* format specific                                       */
    u16 dos_time;         /* ZIP: for the ZipCrypto check byte                     */
    u16 aes_method;       /* ZIP: real method behind WinZip AES                    */
    u8  mtime_kind;
    u8  is_dir;
    u8  enc;              /* GZ_ENC_*: entry data is encrypted                     */
    u8  aes_strength;     /* ZIP: 1..3                                             */
    u8  aes_ver;          /* ZIP: 1 = AE-1 (CRC valid), 2 = AE-2                   */
    u8  name_enc;         /* GZ_NE_*                                               */
    u8  is_link;          /* symbolic link (1) or hard link (2)                    */
    u8  has_crc;          /* crc field is meaningful                               */
    u8  is_aux;           /* alternate stream / resource fork / metadata entry     */
    u8  pad_[3];
    gzch *name;           /* normalised full path "dir/sub/file.txt"               */
    const gzch *base;     /* last path component                                   */
    i32 folder;           /* containing folder index                               */
    i32 next;             /* next file in same folder                              */
} gz_entry;

typedef struct {
    gzch *name;           /* full path, root = u"" */
    const gzch *base;
    i32 parent;
    i32 first_sub, next_sib, first_file;
    i32 entry;            /* explicit directory entry or -1 */
    u32 nsub, nfiles;
    u64 mtime;
    u8 mtime_kind;
} gz_folder;

typedef struct gz_arena_blk gz_arena_blk;
typedef struct { gz_arena_blk *head; } gz_arena;
void *gz_arena_alloc(gz_arena *a, size_t n);
void  gz_arena_free(gz_arena *a);

/* ---------------- per-thread context ---------------- */

enum { GZ_SLOT_COUNT = 16 };

struct gz_ctx {
    gz_inflater *z;               /* created on demand by gz_ctx_inflater()       */
    const gzch *password;         /* NUL-terminated UTF-16, NULL = none            */
    volatile long *cancel;        /* optional                                      */
    void *slot[GZ_SLOT_COUNT];    /* cached codec states (see gz_ctx_slot)         */
    void (*slot_free[GZ_SLOT_COUNT])(void *);
    gz_archive *view_arc;         /* cached layer views (images/partitions)        */
    gz_src *view_raw;
    gz_src *view_chain[8];
    u32 view_n;
    u8 *buf; u32 buf_cap;         /* scratch buffer, see gz_ctx_buffer             */
    void (*progress)(void *user, u64 done, u64 total);   /* optional, open() only  */
    void *progress_user;
};

gz_ctx *gz_ctx_new(void);
void gz_ctx_free(gz_ctx *c);
gz_inflater *gz_ctx_inflater(gz_ctx *c);
u8 *gz_ctx_buffer(gz_ctx *c, u32 size);      /* per-thread scratch buffer (>= size bytes) */
/* Per-thread cached object for slot id (GZ_SLOT_*): created with create() on first use. */
void *gz_ctx_slot(gz_ctx *c, int slot, void *(*create)(void), void (*destroy)(void *));
enum { GZ_SLOT_LZMA = 0, GZ_SLOT_BZIP2, GZ_SLOT_PPMD, GZ_SLOT_ZSTD, GZ_SLOT_LZX, GZ_SLOT_RAR,
       GZ_SLOT_MISC1, GZ_SLOT_MISC2, GZ_SLOT_MISC3, GZ_SLOT_MISC4 };
static inline int gz_cancelled(const gz_ctx *c) { return c && c->cancel && *c->cancel; }

/* ---------------- open options ---------------- */

enum {
    GZ_OPEN_NO_DESCEND = 1,       /* list partitions of disk images instead of opening the file system */
};

typedef struct gz_open_opts {
    int codepage;                  /* GZ_CP_AUTO or a code page                       */
    const gzch *file_name;         /* archive path ('\\' or '/'), used for naming and volumes */
    volatile long *cancel;
    const gzch *password;          /* known password, may be NULL                     */
    /* Ask for a password (encrypted headers). Write a NUL-terminated string into buf.
     * retry != 0 when the previous password was wrong. Return GZ_OK or GZ_E_CANCEL. */
    int (*ask_password)(void *user, gzch *buf, u32 cap, int retry);
    /* Open another file of a multi-volume set; name is a full path built from file_name.
     * Return GZ_OK and a source with ->free set (closed when the archive closes). */
    int (*open_volume)(void *user, const gzch *name, gz_src **out);
    void *user;
    u32 flags;                     /* GZ_OPEN_*                                        */
    void (*progress)(void *user, u64 done, u64 total);   /* long listings (tar.xz)    */
} gz_open_opts;

/* ---------------- format plug-in ---------------- */

enum {
    GZ_FMT_CONTAINER = 1,   /* entries are disk images / partitions that may hold another format */
    GZ_FMT_WEAK = 2,        /* generic container (PE, ELF, MBR): loses to any specific format */
};

struct gz_format {
    const char *name;        /* display name: "7z", "RAR5", "ISO", "TAR.XZ" ...        */
    const char *exts;        /* space separated lower-case extensions, "iso img"       */
    u32 flags;               /* GZ_FMT_*                                                */
    /* Confidence 0..100 that s is this format. head = first min(64 KiB, size) bytes. */
    int  (*probe)(gz_src *s, const u8 *head, u32 n);
    /* Fill a->e via gz_arc_add_entry. Names stay raw (a->raw); gz_arc_build_tree decodes them. */
    int  (*open)(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c);
    void (*close)(gz_archive *a);                  /* free a->priv (may be NULL)      */
    /* Extract one entry (random access formats). Must call out->open / write / close. */
    int  (*extract)(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c);
    /* Sequential pass over the archive extracting entries with sel[idx] != 0
     * (required when a->solid). NULL = call extract() for each selected entry. */
    int  (*extract_solid)(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c);
    /* GZ_OK when c->password opens entry idx, GZ_E_PASSWORD otherwise. NULL = no check. */
    int  (*check_password)(gz_archive *a, gz_src *s, u32 idx, gz_ctx *c);
    /* Human readable method of an entry ("LZMA2:24 BCJ", "Deflate"). NULL = none. */
    void (*method)(const gz_archive *a, const gz_entry *e, char *buf, u32 cap);
    /* Random-access view of an entry's data (stored files, partitions, disk images).
     * The view reads through s and is freed with gz_src_free. NULL = not available. */
    gz_src *(*view)(gz_archive *a, gz_src *s, u32 idx);
    const void *impl;        /* format specific static data (stream codec, variant) */
};

/* Registry marker: put "GZ_FORMAT(gz_fmt_name)" on its own line in the format's .c file. */
#define GZ_FORMAT(sym) extern const gz_format sym;
extern const gz_format *const gz_formats[];    /* generated, NULL terminated */

/* ---------------- archive ---------------- */

struct gz_archive {
    const gz_format *fmt;
    void *priv;              /* format private state                                   */
    char type_name[40];      /* shown to the user: "TAR.XZ", "NTFS (VHDX)" ...          */
    int solid;               /* entries must be extracted in one sequential pass         */
    int codepage;            /* requested (0 = auto)                                    */
    int used_cp;             /* code page actually used for legacy names                */
    int any_utf8, any_legacy;
    gz_entry *e;  u32 n, cap;
    gz_folder *f; u32 nf, capf;
    u8 *raw; size_t raw_len, raw_cap;
    gz_arena names;          /* entry + folder names (rebuilt on code-page change)       */
    i32 *fhash; u32 fhash_cap;
    gzch *comment;
    u8 *comment_raw; u32 comment_len;
    u8 comment_enc;          /* GZ_NE_* of comment_raw                                  */
    u64 total_usize, total_csize;
    u32 nfiles, ndirs;
    int has_enc;             /* some entry is encrypted                                 */
    int headers_enc;         /* names were encrypted (password asked at open)           */
    u64 sfx_shift;           /* bytes before the archive proper (SFX stub)              */
    u64 src_size;
    gzch *password;          /* password that opened encrypted headers (owned)          */
    gz_src **vols; u32 nvols;  /* extra volumes opened through open_volume (owned)     */
    /* layering: this archive lives inside entry parent_idx of parent */
    gz_archive *parent;
    u32 parent_idx;
    int case_fold;           /* folder tree is case-insensitive                         */
    int owns_parent;         /* close parent with this archive (automatic descent)      */
    int win_names;           /* legacy names come from Windows tools (ZIP, RAR, ...):
                                enables DBCS-vs-UTF-8 voting in code-page detection     */
    /* legacy ZIP/GZ fields kept for the formats that use them */
    u64 gz_off;
    u32 gz_isize;
};

/* Open: o may be NULL (defaults). c supplies the inflater/cancel for listing. */
int  gz_arc_open(gz_archive **out, gz_src *src, const gz_open_opts *o, gz_ctx *c);
/* Open entry idx of an archive as an archive of its own (random access only). */
int  gz_arc_open_child(gz_archive **out, gz_archive *parent, gz_src *parent_src, u32 idx,
                       const gz_open_opts *o, gz_ctx *c);
void gz_arc_close(gz_archive *a);
int  gz_arc_set_codepage(gz_archive *a, int codepage);   /* re-decode names */
const char *gz_arc_type_name(const gz_archive *a);
/* method of an entry as UTF-16 (static per-thread buffer is not used: caller supplies) */
void gz_arc_method(const gz_archive *a, const gz_entry *e, gzch *buf, u32 cap);

/* Extraction. src is the caller's handle to the outer archive file. c->password is used
 * for encrypted entries. Calls out->open/write/close. */
int gz_arc_extract(gz_archive *a, gz_src *src, u32 idx, gz_out *out, gz_ctx *c);
/* Solid formats: one pass, extracts entries with sel[idx] != 0. */
int gz_arc_extract_solid(gz_archive *a, gz_src *src, const u8 *sel, gz_out *out, gz_ctx *c);
/* GZ_OK if c->password opens entry idx (GZ_E_PASSWORD otherwise). */
int gz_arc_check_password(gz_archive *a, gz_src *src, u32 idx, gz_ctx *c);
/* Data source an entry's data can be read from directly (NULL if not random access). */
gz_src *gz_arc_view(gz_archive *a, gz_src *src, u32 idx, gz_ctx *c);

/* ---------------- helpers shared by formats ---------------- */

int  gz_arc_add_entry(gz_archive *a, gz_entry **pe);
int  gz_arc_raw_append(gz_archive *a, const void *p, size_t n, u32 *off);
/* add an entry whose name is given as bytes in encoding ne */
int  gz_arc_add_named(gz_archive *a, const void *name, u32 len, int ne, gz_entry **pe);
int  gz_arc_build_tree(gz_archive *a);    /* decode names + folders */
void gz_arc_set_type(gz_archive *a, const char *name);
/* source to read entry data from: s itself, or the layered view for nested archives */
gz_src *gz_arc_layer_src(gz_archive *a, gz_src *outer, gz_ctx *c);

/* pass every byte of a source range through out (stored entries) */
int  gz_copy_range(gz_src *s, u64 off, u64 len, gz_out *out, gz_ctx *c, u32 *crc);
/* convenience: open + copy stored range + CRC check (if e->has_crc) + close */
int  gz_extract_stored(gz_archive *a, gz_src *s, u32 idx, u64 off, gz_out *out, gz_ctx *c);

/* ---------------- strings ---------------- */

int  gz_utf8_valid(const u8 *s, size_t n);
int  gz_utf8_to_utf16(const u8 *s, size_t n, gzch *out);    /* returns length, out >= n units */
int  gz_utf16_to_utf8(const gzch *s, size_t n, u8 *out);    /* returns bytes, out >= 3n      */
int  gz_hangul_compose(gzch *s, int n);                      /* NFD -> NFC, returns new length */
u64  gz_unix_to_filetime(i64 t);
i64  gz_filetime_to_unix(u64 ft);
u64  gz_dos_to_filetime(u32 dos);           /* DOS date<<16|time (local, as UTC) */
size_t gz_wcslen(const gzch *s);
int    gz_wcscmp(const gzch *a, const gzch *b);
int    gz_wcsicmp_ascii(const gzch *a, const gzch *b);
const gzch *gz_wcsrchr(const gzch *s, gzch c);
gzch  *gz_wcsdup(const gzch *s);
/* "name.ext" ends with ext (ASCII, case-insensitive, ext includes the dot) */
int    gz_wcs_endswith(const gzch *s, const char *ext);

/* ---------------- platform hooks ---------------- */

int gz_plat_mb2wc(int cp, const u8 *s, int n, gzch *out, int cap);
int gz_plat_wc2mb(int cp, const gzch *s, int n, u8 *out, int cap);   /* bytes written, 0 = fail */
int gz_plat_acp(void);
int gz_plat_mb_valid(int cp, const u8 *s, int n);              /* 1 if s is valid in cp */
int gz_plat_oemcp(void);
int gz_plat_cp_valid(int cp);
int gz_plat_case_fold(void);                                   /* file system is case-insensitive */

#endif
