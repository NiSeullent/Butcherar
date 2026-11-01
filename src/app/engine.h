/*
 * 고깃ZIP - portable extraction / compression engine
 *
 * Shared by the command line tool, the Linux GTK and macOS Cocoa front ends
 * and (later) the Windows UI. Everything that touches the system goes through
 * os.h; the engine itself uses no C library.
 *
 *   gz_handle      an archive opened for browsing (entries, folder tree)
 *   gz_job         a background task: open, extract/test or compress
 *   gz_callbacks   how a job talks to its front end:
 *                    ask       questions (overwrite, password, missing volume).
 *                              Runs on a worker thread and blocks until answered;
 *                              GUIs marshal it to their UI thread. Questions are
 *                              serialised: at most one is open at a time.
 *                    progress  ~10 times per second, never concurrently with log
 *                    log       errors, warnings and notes, serialised
 *                    done      last call of the job, from the job thread
 *
 * Typical extraction:
 *     gz_engine_init(-1);
 *     gz_handle *h;  int r = gz_handle_open(&h, path, &req, &cb);
 *     gz_extract_opts xo = { .dest = u"/home/me/out", .overwrite = GZ_OW_ASK };
 *     gz_job *j = gz_extract_start(h, &xo, &cb);
 *     r = gz_job_wait(j);  ... gz_job_free(j); gz_handle_close(h);
 */
#ifndef GZ_ENGINE_H
#define GZ_ENGINE_H
#include "arc.h"
#include "gz_write.h"
#include "os.h"

#define GZ_APP_VERSION "1.0.0"

/* Core tables + CPU kernel dispatch (cpu_tier < 0: automatic). Call once at start-up. */
void gz_engine_init(int cpu_tier);

/* ---------------- callbacks ---------------- */

enum { GZ_ASK_OVERWRITE = 1, GZ_ASK_PASSWORD = 2, GZ_ASK_VOLUME = 3 };
enum {
    GZ_ANS_CANCEL = 0,      /* stop the whole job                                    */
    GZ_ANS_YES,             /* overwrite this file / use answer[] as password or path */
    GZ_ANS_NO,              /* skip this file / no password: skip encrypted entries   */
    GZ_ANS_YES_ALL,         /* overwrite this and every later file                    */
    GZ_ANS_NO_ALL,          /* skip this and every later existing file                */
    GZ_ANS_RENAME,          /* keep both: write this one as "name (2).ext"            */
    GZ_ANS_RENAME_ALL
};

#define GZ_ASK_CAP 1024
typedef struct gz_ask {
    int kind;                /* GZ_ASK_*                                                     */
    const gzch *path;        /* overwrite: existing file; password: entry (or archive) name;
                                volume: expected path of the missing volume                   */
    const gzch *archive;     /* archive name                                                 */
    const gzch *entry;       /* overwrite: archive entry name                                */
    u64 old_size, old_mtime; /* overwrite: existing file (mtime FILETIME UTC, 0 unknown)     */
    u64 new_size, new_mtime; /* overwrite: archive entry                                     */
    int retry;               /* password: the previous one was wrong; volume: not found again */
    gzch answer[GZ_ASK_CAP]; /* out: password / volume path (empty = look again)             */
} gz_ask;

enum { GZ_LOG_NOTE = 0, GZ_LOG_WARN = 1, GZ_LOG_ERROR = 2 };

/* engine notes (gz_log.code) next to the GZ_E_* error codes */
enum {
    GZ_N_FIRST = 64,
    GZ_N_RENAMED = GZ_N_FIRST, /* written under another name (detail: new path)              */
    GZ_N_SHORTENED,           /* name too long for the file system, shortened (detail: path) */
    GZ_N_PATH_LONG,           /* output path too long: not extracted                         */
    GZ_N_LINK_ABSOLUTE,       /* link with an absolute target not created (detail: target)   */
    GZ_N_LINK_ESCAPE,         /* link pointing outside the destination not created           */
    GZ_N_LINK_THROUGH,        /* link inside a linked folder not created                     */
    GZ_N_LINK_UNSUPPORTED,    /* links cannot be created here / skipped by option            */
    GZ_N_LINK_FAILED,         /* creating the link failed (detail: target)                   */
    GZ_N_LINK_TARGET,         /* hard link target missing or not extracted                   */
    GZ_N_SPECIAL,             /* device / pipe / socket not archived                         */
    GZ_N_LOOP,                /* folder link loop not followed                               */
    GZ_N_NOT_FOUND,           /* input file not found                                        */
    GZ_N_UNREADABLE,          /* input file or folder could not be read                      */
    GZ_N_ONE_FILE,            /* single-stream format (gz, xz, ...) needs exactly one file   */
    GZ_N_EXISTS,              /* output archive exists and may not be replaced               */
    GZ_N_NO_WRITER,           /* no writer for the format / method / encryption              */
    GZ_N_NO_FILES,            /* nothing to do                                               */
    GZ_N_LAST
};

typedef struct gz_log {
    int level;               /* GZ_LOG_*                                    */
    int code;                /* GZ_E_* or GZ_N_*                            */
    gzch *name;              /* entry name or file path                     */
    gzch *detail;            /* NULL or extra text (link target, new name)  */
} gz_log;

typedef struct gz_progress {
    u64 done_bytes, total_bytes;   /* uncompressed bytes                          */
    u32 done_files, total_files;
    u32 errors, warnings, skipped;
    u64 elapsed_ms;                /* without the time spent waiting for answers  */
    const gzch *current;           /* entry / file being processed (callback only) */
} gz_progress;

typedef struct gz_callbacks {
    void *user;
    /* NULL ask: overwrite -> skip, password -> none, volume -> missing */
    int  (*ask)(void *user, gz_ask *q);                   /* returns GZ_ANS_* */
    void (*progress)(void *user, const gz_progress *p);
    void (*log)(void *user, const gz_log *l);
    void (*done)(void *user, int result);
} gz_callbacks;

/* ---------------- archives for browsing ---------------- */

typedef struct gz_handle {
    gzch *path;              /* file the entries are read from (outermost file for nested views) */
    gzch *name;              /* display name: "a.zip", "a.zip/disk.iso"                   */
    gz_src *src;             /* open source of path                                       */
    gz_archive *arc;         /* entries + folder tree (see arc.h)                         */
    struct gz_handle *parent;/* nested archive opened through a view: parent (keep it open) */
    int temp;                /* path is a temporary copy, deleted by gz_handle_close       */
    u8 *mark; u32 mark_n;    /* downloaded-file mark of the archive (quarantine)          */
} gz_handle;

typedef struct gz_open_req {
    int codepage;            /* GZ_CP_AUTO or a code page                                 */
    const gzch *password;    /* known password (encrypted headers), may be NULL          */
    u32 flags;               /* GZ_OPEN_* (arc.h)                                         */
    volatile long *cancel;   /* optional                                                  */
} gz_open_req;

/* Synchronous open on the calling thread (asks go to cb->ask on this thread).
 * req and cb may be NULL. Returns GZ_OK or GZ_E_*. */
int  gz_handle_open(gz_handle **out, const gzch *path, const gz_open_req *req, const gz_callbacks *cb);
/* Open entry idx as an archive: directly through a view when the entry is stored
 * contiguously (disk images, stored files), else via a temporary copy. */
int  gz_handle_open_child(gz_handle **out, gz_handle *parent, u32 idx, const gz_open_req *req,
                          const gz_callbacks *cb);
void gz_handle_close(gz_handle *h);
/* re-decode legacy names with a code page (GZ_CP_AUTO = detect) */
int  gz_handle_set_codepage(gz_handle *h, int codepage);

/* ---------------- jobs ---------------- */

typedef struct gz_job gz_job;

enum { GZ_PATH_FULL = 0, GZ_PATH_NONE, GZ_PATH_STRIP };
enum { GZ_OW_ASK = 0, GZ_OW_ALL, GZ_OW_SKIP, GZ_OW_RENAME, GZ_OW_NEWER };
enum {
    GZ_XF_KEEP_BROKEN  = 1,  /* keep partly written files after an error                    */
    GZ_XF_NO_TIMES     = 2,  /* do not restore modification times                           */
    GZ_XF_NO_PERMS     = 4,  /* do not restore permission bits                              */
    GZ_XF_SETUID       = 8,  /* keep setuid / setgid bits (dropped by default)              */
    GZ_XF_UNSAFE_LINKS = 16, /* create links with absolute targets or leaving the destination */
    GZ_XF_NO_LINKS     = 32, /* skip symbolic and hard links                                */
    GZ_XF_NO_MARK      = 64  /* do not copy the archive's quarantine mark to the files      */
};

typedef struct gz_extract_opts {
    const gzch *dest;        /* destination folder (absolute)                                */
    int path_mode;           /* GZ_PATH_*                                                    */
    const gzch *strip;       /* GZ_PATH_STRIP: folder ("a/b") whose contents go to dest      */
    int overwrite;           /* GZ_OW_*                                                      */
    int smart;               /* into dest/<archive name>/ unless everything is in one folder
                                or the archive holds a single file (gz_job_dest tells)        */
    const u8 *sel;           /* NULL = all entries, else arc->n flags (copied)               */
    int test;                /* only test (nothing is written)                               */
    int codepage;            /* 0 = keep the handle's names, -1 = automatic, else code page   */
    int threads;             /* 0 = automatic                                                */
    u32 flags;               /* GZ_XF_*                                                      */
    const gzch *password;    /* tried first, may be NULL                                     */
} gz_extract_opts;

enum { GZ_CF_FOLLOW_LINKS = 1 };   /* archive what links point to instead of the links */

typedef struct gz_compress_opts {
    const gzch *out;                 /* archive to create (absolute)                       */
    const gzch *const *inputs;       /* files / folders (absolute); names are relative to   */
    u32 ninputs;                     /* their common parent folder                         */
    int format;                      /* GZ_WF_*                                            */
    int method;                      /* GZ_WM_* (0 = format default)                       */
    int level;                       /* 0..9                                               */
    u32 dict_size;
    int encryption;                  /* GZ_WE_*                                            */
    const gzch *password;
    int encrypt_names;
    int solid;
    int threads;
    u32 flags;                       /* GZ_CF_*                                            */
    int overwrite;                   /* existing archive: GZ_OW_ASK / GZ_OW_ALL / GZ_OW_SKIP */
    const gzch *label;               /* ISO volume label (NULL = from the archive name)    */
} gz_compress_opts;

/* Start a job on a background thread. NULL only when out of memory. Option strings
 * are copied; the handle must stay open until the job is freed. */
gz_job *gz_extract_start(gz_handle *h, const gz_extract_opts *o, const gz_callbacks *cb);
gz_job *gz_compress_start(const gz_compress_opts *o, const gz_callbacks *cb);
gz_job *gz_open_start(const gzch *path, const gz_open_req *req, const gz_callbacks *cb);

void gz_job_cancel(gz_job *j);
void gz_job_pause(gz_job *j, int pause);
int  gz_job_wait(gz_job *j);                     /* result: GZ_OK, GZ_E_CANCEL or an error */
int  gz_job_wait_for(gz_job *j, u32 ms);         /* 1 when finished                        */
void gz_job_progress(gz_job *j, gz_progress *p); /* snapshot from any thread (current NULL) */
u32  gz_job_log_count(gz_job *j);                /* log entries kept by the job            */
const gz_log *gz_job_log_at(gz_job *j, u32 i);   /* valid until gz_job_free (after the job) */
const gzch *gz_job_dest(const gz_job *j);        /* extraction folder after smart naming   */
gz_handle *gz_job_take_handle(gz_job *j);        /* open jobs: the opened archive (owned)  */
void gz_job_free(gz_job *j);                     /* waits for the job first                */

/* ---------------- helpers for front ends ---------------- */

/* does extracting need a folder of its own? (several top-level items) */
int  gz_smart_needs_folder(const gz_archive *a, const u8 *sel, const gzch *strip);
/* "a.tar.gz" -> "a", "b.part1.rar" -> "b", "c.7z.001" -> "c" (base name, no folders) */
void gz_archive_stem(const gzch *name, gzch *out, u32 cap);
/* GZ_WF_* from an output file name (".tar.gz", ".zip"...), 0 = unknown */
int  gz_format_from_name(const gzch *name);
/* modification time of an entry as FILETIME UTC (DOS times are local), 0 = unknown */
u64  gz_entry_time(const gz_entry *e);
/* link target of entry idx when stored in the header (NULL otherwise), gz_alloc'ed */
gzch *gz_entry_link_target(const gz_archive *a, const gz_entry *e);

#endif
