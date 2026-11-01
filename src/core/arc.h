/*
 * 고깃ZIP - archive model (ZIP / GZIP / TAR / TAR.GZ)
 */
#ifndef GZ_ARC_H
#define GZ_ARC_H
#include "base.h"
#include "inflate.h"
#include "crypto.h"

/* random access byte source (one per thread) */
typedef struct gz_src {
    int (*read_at)(struct gz_src *s, u64 off, void *buf, u32 n, u32 *got);
    u64 size;
    void *h;
} gz_src;

/* per-entry output target, implemented by the extraction engine */
typedef struct gz_out {
    int (*open)(struct gz_out *o, u32 idx);            /* GZ_OK, GZ_E_SKIP or error */
    int (*write)(struct gz_out *o, const u8 *p, size_t n);
    int (*close)(struct gz_out *o, u32 idx, int status);
    void *user;
} gz_out;

enum { GZ_ARC_NONE = 0, GZ_ARC_ZIP, GZ_ARC_GZIP, GZ_ARC_TAR, GZ_ARC_TGZ };
enum { GZ_ENC_NONE = 0, GZ_ENC_ZIPCRYPTO = 1, GZ_ENC_AES = 2 };
enum { GZ_MT_NONE = 0, GZ_MT_FILETIME = 1, GZ_MT_DOS = 2 };

/* codepage selector: 0 = automatic */
#define GZ_CP_AUTO 0
#define GZ_CP_UTF8 65001

typedef struct {
    u64 usize, csize;
    u64 off;              /* zip: local header offset; tar: data offset; gz: data offset */
    u64 mtime;            /* FILETIME (UTC) or DOS (date<<16|time, local)        */
    u32 crc;
    u32 attr;             /* FILE_ATTRIBUTE_* (READONLY 1, HIDDEN 2, SYSTEM 4, DIRECTORY 0x10, ARCHIVE 0x20) */
    u32 raw_off;          /* raw name bytes in a->raw                            */
    u32 uni_off;          /* UTF-8 name from unicode extra field (0 = none)      */
    u16 raw_len, uni_len;
    u16 method;
    u16 flags;
    u16 dos_time;
    u16 aes_method;
    u8  mtime_kind;
    u8  is_dir;
    u8  enc;
    u8  aes_strength;     /* 1..3 */
    u8  aes_ver;          /* 1 = AE-1 (CRC valid), 2 = AE-2 */
    u8  utf8;             /* raw name is UTF-8 by flag                           */
    u8  is_link;
    u8  pad_;
    wchar_t *name;        /* normalised full path "dir/sub/file.txt"             */
    const wchar_t *base;  /* last path component                                 */
    i32 folder;           /* containing folder index                             */
    i32 next;             /* next file in same folder                            */
} gz_entry;

typedef struct {
    wchar_t *name;        /* full path, root = L"" */
    const wchar_t *base;
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

typedef struct gz_archive {
    int type;
    int solid;            /* entries must be extracted in one sequential pass */
    int codepage;         /* requested (0 = auto)            */
    int used_cp;          /* codepage actually used for non-UTF-8 names */
    int any_utf8, any_legacy;
    gz_entry *e;  u32 n, cap;
    gz_folder *f; u32 nf, capf;
    u8 *raw; size_t raw_len, raw_cap;
    gz_arena names;       /* entry + folder names (rebuilt on codepage change) */
    i32 *fhash; u32 fhash_cap;
    wchar_t *comment;
    u8 *comment_raw; u32 comment_len;
    u64 total_usize, total_csize;
    u32 nfiles, ndirs;
    int has_enc;
    u64 sfx_shift;        /* bytes prepended before the zip (SFX)  */
    u64 src_size;
    /* gzip */
    u64 gz_off;           /* start of deflate data */
    u32 gz_isize;
    int gz_has_name;
} gz_archive;

/* Open: name is the archive file name (used for .gz entry naming). */
int  gz_arc_open(gz_archive **out, gz_src *src, const wchar_t *file_name, int codepage,
                 gz_inflater *z, volatile long *cancel);
void gz_arc_close(gz_archive *a);
int  gz_arc_set_codepage(gz_archive *a, int codepage);   /* re-decode names */
const char *gz_arc_type_name(const gz_archive *a);
const wchar_t *gz_arc_method_name(const gz_archive *a, const gz_entry *e);

/* Extraction. pw/pwn: password bytes (may be NULL). Calls out->open/write/close. */
int gz_arc_extract(gz_archive *a, gz_src *src, u32 idx, gz_out *out,
                   const u8 *pw, size_t pwn, gz_inflater *z);
/* Solid formats: one pass, extracts entries with sel[idx] != 0. */
int gz_arc_extract_solid(gz_archive *a, gz_src *src, const u8 *sel, gz_out *out,
                         gz_inflater *z, volatile long *cancel);
/* Returns GZ_OK if the password opens entry idx (GZ_E_PASSWORD otherwise). */
int gz_arc_check_password(gz_archive *a, gz_src *src, u32 idx, const u8 *pw, size_t pwn);

/* Helpers shared by formats */
int  gz_arc_add_entry(gz_archive *a, gz_entry **pe);
int  gz_arc_raw_append(gz_archive *a, const void *p, size_t n, u32 *off);
int  gz_arc_build_tree(gz_archive *a);    /* decode names + folders */
int  gz_utf8_valid(const u8 *s, size_t n);
int  gz_utf8_to_wide(const u8 *s, size_t n, wchar_t *out);   /* returns length */
int  gz_hangul_compose(wchar_t *s, int n);                   /* NFD -> NFC, returns new length */
u64  gz_unix_to_filetime(i64 t);

/* Platform hooks */
int gz_plat_mb2wc(int cp, const u8 *s, int n, wchar_t *out, int cap);
int gz_plat_acp(void);
int gz_plat_mb_valid(int cp, const u8 *s, int n);              /* 1 if s is valid in cp */
int gz_plat_oemcp(void);
int gz_plat_cp_valid(int cp);

/* wide string helpers (no libc) */
size_t gz_wcslen(const wchar_t *s);
int    gz_wcscmp(const wchar_t *a, const wchar_t *b);
int    gz_wcsicmp_ascii(const wchar_t *a, const wchar_t *b);
const wchar_t *gz_wcsrchr(const wchar_t *s, wchar_t c);

#endif
