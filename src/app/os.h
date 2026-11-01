/*
 * 고깃ZIP - operating system abstraction for the portable engine and front ends
 *
 * Paths are NUL-terminated UTF-16 (gzch). The POSIX implementation
 * (src/posix/os_posix.c) converts them to UTF-8 bytes; bytes that are not valid
 * UTF-8 survive the round trip as lone surrogates U+DC80..U+DCFF ("surrogate
 * escape"), so every file name the system returns can be opened again.
 * A Windows implementation of this header maps the calls to Win32.
 *
 * Every function returning int returns GZ_OSE_OK (0) or a GZ_OSE_* code.
 * Memory handed to the caller is allocated with gz_alloc (free with gz_free).
 */
#ifndef GZ_OS_H
#define GZ_OS_H
#include "base.h"
#include "stream.h"

#ifdef _WIN32
#  define GZ_OS_SEP '\\'
#else
#  define GZ_OS_SEP '/'
#endif

/* ---------------- errors ---------------- */

enum {
    GZ_OSE_OK = 0,
    GZ_OSE_NOENT,          /* no such file or directory          */
    GZ_OSE_EXIST,          /* already exists                     */
    GZ_OSE_NAMETOOLONG,    /* name or path too long              */
    GZ_OSE_NOSPC,          /* disk full / quota exceeded         */
    GZ_OSE_ACCES,          /* permission denied / read-only      */
    GZ_OSE_NOTDIR,         /* a path component is not a folder   */
    GZ_OSE_ISDIR,          /* is a folder                        */
    GZ_OSE_LOOP,           /* too many symbolic links            */
    GZ_OSE_NOMEM,
    GZ_OSE_XDEV,           /* cross-device link                  */
    GZ_OSE_NOTSUP,         /* not supported by the file system   */
    GZ_OSE_OTHER
};
/* GZ_E_* for an OS error: NOSPC -> GZ_E_DISK, NOMEM -> GZ_E_NOMEM, otherwise fallback. */
int gz_os_err_gz(int ose, int fallback);

/* ---------------- capabilities ---------------- */

enum {
    GZ_OSC_LINKS      = 1,    /* symbolic and hard links can be created          */
    GZ_OSC_MODES      = 2,    /* POSIX permission bits                           */
    GZ_OSC_WIN_NAMES  = 4,    /* Windows naming rules (CON, <>:"|?*, trailing .) */
    GZ_OSC_NFD_NAMES  = 8,    /* the system may return decomposed names (macOS)  */
    GZ_OSC_CASE_FOLD  = 16,   /* usual file systems ignore case                  */
    GZ_OSC_MARK       = 32,   /* downloaded-file mark (quarantine / Zone.Identifier) */
    GZ_OSC_ATTRS      = 64    /* DOS attributes (read-only, hidden, system) are kept */
};
u32 gz_os_caps(void);
u32 gz_os_umask(void);        /* process umask (0 where meaningless), read once     */

/* ---------------- text ---------------- */

/* UTF-8 bytes of a path as the system wants them (POSIX: surrogate escape). */
char *gz_os_path_bytes(const gzch *w);
gzch *gz_os_path_wide(const char *s);
/* length of w[0..n) in the units the file system limits names by (POSIX: bytes) */
size_t gz_os_native_len(const gzch *w, size_t n);

/* ---------------- files ---------------- */

typedef intptr_t gz_fd;
#define GZ_FD_NONE ((gz_fd)-1)

enum { GZ_FT_NONE = 0, GZ_FT_FILE, GZ_FT_DIR, GZ_FT_LINK, GZ_FT_OTHER };

typedef struct gz_os_info {
    u64 size;
    u64 mtime, atime, ctime;  /* FILETIME UTC (100 ns since 1601)                  */
    u64 dev, ino;             /* identity (cycle detection, "same file" checks)     */
    u32 mode;                 /* st_mode with type bits (synthesised on Windows)    */
    u32 attr;                 /* FILE_ATTRIBUTE_* (synthesised on POSIX)            */
    int type;                 /* GZ_FT_*                                            */
} gz_os_info;

int  gz_os_open_read(const gzch *path, gz_fd *fd);               /* follows links  */
/* Create a new file. Fails with GZ_OSE_EXIST if anything (even a dangling link)
 * is at path: the engine never writes through an existing link. */
int  gz_os_create(const gzch *path, u32 mode, gz_fd *fd);
int  gz_os_read(gz_fd fd, void *buf, u32 n, u32 *got);           /* *got 0 = end   */
int  gz_os_pread(gz_fd fd, u64 off, void *buf, u32 n, u32 *got);
int  gz_os_write(gz_fd fd, const void *p, size_t n);             /* all or error   */
int  gz_os_pwrite(gz_fd fd, u64 off, const void *p, size_t n);
int  gz_os_close(gz_fd fd);
int  gz_os_fstat(gz_fd fd, gz_os_info *st);
int  gz_os_fset_times(gz_fd fd, u64 mtime, u64 atime);           /* 0 = leave as is */
int  gz_os_fset_mode(gz_fd fd, u32 mode);
/* read-only / hidden / system attribute bits of a file just written at path (open as fd);
 * only on GZ_OSC_ATTRS systems (no-op elsewhere) */
#ifdef _WIN32
int  gz_os_fset_attr(gz_fd fd, const gzch *path, u32 attr);
#else
static inline int gz_os_fset_attr(gz_fd fd, const gzch *path, u32 attr) { (void)fd; (void)path; (void)attr; return 0; }
#endif
/* random-access source over a file (reads are thread-safe), freed with gz_src_free */
int  gz_os_open_src(const gzch *path, gz_src **out);

/* ---------------- paths ---------------- */

int  gz_os_stat(const gzch *path, gz_os_info *st, int follow);
int  gz_os_mkdir(const gzch *path, u32 mode);
int  gz_os_mkdirs(const gzch *path);         /* mkdir -p; OK when it is a folder already */
int  gz_os_set_times(const gzch *path, u64 mtime, u64 atime, int follow);
int  gz_os_set_mode(const gzch *path, u32 mode);
int  gz_os_symlink(const gzch *target, const gzch *path);
int  gz_os_readlink(const gzch *path, gzch *buf, u32 cap);       /* NUL-terminated */
int  gz_os_link(const gzch *existing, const gzch *path);         /* hard link, never follows */
int  gz_os_rename(const gzch *from, const gzch *to);             /* replaces "to"  */
int  gz_os_delete(const gzch *path);                             /* file, link or empty folder */
u32  gz_os_name_max(const gzch *dir);        /* longest name component (native units) */
int  gz_os_cwd(gzch *buf, u32 cap);
int  gz_os_temp_dir(gzch *buf, u32 cap);
/* create prefix + random suffix exclusively; full name in path */
int  gz_os_create_temp(const gzch *prefix, gzch *path, u32 cap, gz_fd *fd);

/* Downloaded-file mark of an archive (macOS com.apple.quarantine, Windows
 * Zone.Identifier) and propagation to extracted files. *n = 0 when none. */
int  gz_os_mark_get(const gzch *path, u8 *buf, u32 cap, u32 *n);
void gz_os_mark_set(gz_fd fd, const gzch *path, const u8 *p, u32 n);

/* ---------------- folders ---------------- */

typedef struct gz_os_dir gz_os_dir;
int  gz_os_dir_open(const gzch *path, gz_os_dir **d);
/* next entry ("." and ".." skipped): *name valid until the next call, NULL at the end;
 * *type GZ_FT_* or GZ_FT_NONE when the system does not say */
int  gz_os_dir_next(gz_os_dir *d, const gzch **name, int *type);
void gz_os_dir_close(gz_os_dir *d);

/* ---------------- threads ---------------- */

typedef struct gz_os_thread gz_os_thread;
typedef struct gz_os_mutex gz_os_mutex;
typedef struct gz_os_cond gz_os_cond;

gz_os_thread *gz_os_thread_start(int (*fn)(void *), void *arg, u32 stack_bytes);
int  gz_os_thread_join(gz_os_thread *t);     /* returns fn's result, frees t */

gz_os_mutex *gz_os_mutex_new(void);
void gz_os_mutex_free(gz_os_mutex *m);
void gz_os_mutex_lock(gz_os_mutex *m);
void gz_os_mutex_unlock(gz_os_mutex *m);

gz_os_cond *gz_os_cond_new(void);
void gz_os_cond_free(gz_os_cond *c);
void gz_os_cond_wait(gz_os_cond *c, gz_os_mutex *m);
int  gz_os_cond_timedwait(gz_os_cond *c, gz_os_mutex *m, u32 ms);   /* 1 = timed out */
void gz_os_cond_signal(gz_os_cond *c);
void gz_os_cond_broadcast(gz_os_cond *c);

int  gz_os_cpu_count(void);
u64  gz_os_ms(void);                         /* monotonic milliseconds */

/* atomics on long (GCC / clang builtins exist on every target, i586 included) */
static inline long gz_atomic_load(const volatile long *p) { return __atomic_load_n(p, __ATOMIC_ACQUIRE); }
static inline void gz_atomic_store(volatile long *p, long v) { __atomic_store_n(p, v, __ATOMIC_RELEASE); }
static inline long gz_atomic_add(volatile long *p, long v) { return __atomic_add_fetch(p, v, __ATOMIC_ACQ_REL); }
static inline long gz_atomic_inc(volatile long *p) { return __atomic_add_fetch(p, 1, __ATOMIC_ACQ_REL); }
static inline long gz_atomic_xchg(volatile long *p, long v) { return __atomic_exchange_n(p, v, __ATOMIC_ACQ_REL); }

/* ---------------- time ---------------- */

typedef struct gz_os_tm { int year, month, day, hour, min, sec; } gz_os_tm;
u64  gz_os_now(void);                        /* FILETIME UTC */
u64  gz_os_dos_to_utc(u32 dos);              /* DOS date<<16|time in local time -> FILETIME UTC, 0 if invalid */
int  gz_os_local_time(u64 ft, gz_os_tm *tm); /* FILETIME UTC -> local broken-down time */

#endif
