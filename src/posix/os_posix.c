/*
 * 고깃ZIP - os.h for Linux and macOS
 */
#if defined(__APPLE__)
#  define _DARWIN_C_SOURCE 1
#elif !defined(_GNU_SOURCE)
#  define _GNU_SOURCE 1
#endif
#include "os.h"
#include "arc.h"
#include "plat_posix.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#ifdef __APPLE__
#  include <sys/xattr.h>
#  define ST_ATIM(s) ((s)->st_atimespec)
#  define ST_MTIM(s) ((s)->st_mtimespec)
#  define ST_CTIM(s) ((s)->st_ctimespec)
#else
#  define ST_ATIM(s) ((s)->st_atim)
#  define ST_MTIM(s) ((s)->st_mtim)
#  define ST_CTIM(s) ((s)->st_ctim)
#endif

/* ---------------- errors ---------------- */

static int ose(int e)
{
    switch (e) {
    case 0: return GZ_OSE_OK;
    case ENOENT: return GZ_OSE_NOENT;
    case EEXIST: return GZ_OSE_EXIST;
    case ENAMETOOLONG: return GZ_OSE_NAMETOOLONG;
    case ENOSPC:
#ifdef EDQUOT
    case EDQUOT:
#endif
    case EFBIG: return GZ_OSE_NOSPC;
    case EACCES: case EPERM: case EROFS: return GZ_OSE_ACCES;
    case ENOTDIR: return GZ_OSE_NOTDIR;
    case EISDIR: return GZ_OSE_ISDIR;
    case ELOOP: return GZ_OSE_LOOP;
    case ENOMEM: return GZ_OSE_NOMEM;
    case EXDEV: return GZ_OSE_XDEV;
#if defined(EOPNOTSUPP) && EOPNOTSUPP != ENOTSUP
    case EOPNOTSUPP:
#endif
    case ENOTSUP: return GZ_OSE_NOTSUP;
    }
    return GZ_OSE_OTHER;
}

int gz_os_err_gz(int e, int fallback)
{
    if (e == GZ_OSE_OK) return GZ_OK;
    if (e == GZ_OSE_NOSPC) return GZ_E_DISK;
    if (e == GZ_OSE_NOMEM) return GZ_E_NOMEM;
    return fallback;
}

u32 gz_os_caps(void)
{
#ifdef __APPLE__
    return GZ_OSC_LINKS | GZ_OSC_MODES | GZ_OSC_NFD_NAMES | GZ_OSC_CASE_FOLD | GZ_OSC_MARK;
#else
    return GZ_OSC_LINKS | GZ_OSC_MODES;
#endif
}

u32 gz_os_umask(void)
{
    static volatile long cached = -1;
    long v = gz_atomic_load(&cached);
    if (v < 0) {
        /* reading the umask means setting it: do it once (engine start-up) */
        mode_t m = umask(022);
        umask(m);
        v = (long)(m & 0777);
        gz_atomic_store(&cached, v);
    }
    return (u32)v;
}

/* ---------------- UTF-16 <-> bytes (surrogate escape) ---------------- */

static size_t w2b(const gzch *s, size_t n, char *out)
{
    u8 *o = (u8 *)out;
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        u32 c = s[i];
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < n && s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000) {
            c = 0x10000 + ((c - 0xD800) << 10) + (s[i + 1] - 0xDC00);
            i++;
        } else if (c >= 0xDC80 && c <= 0xDCFF) {
            o[k++] = (u8)(c - 0xDC00);          /* escaped raw byte */
            continue;
        } else if (c >= 0xD800 && c < 0xE000) {
            c = 0xFFFD;
        }
        if (c < 0x80) o[k++] = (u8)c;
        else if (c < 0x800) { o[k++] = (u8)(0xC0 | (c >> 6)); o[k++] = (u8)(0x80 | (c & 63)); }
        else if (c < 0x10000) {
            o[k++] = (u8)(0xE0 | (c >> 12)); o[k++] = (u8)(0x80 | ((c >> 6) & 63)); o[k++] = (u8)(0x80 | (c & 63));
        } else {
            o[k++] = (u8)(0xF0 | (c >> 18)); o[k++] = (u8)(0x80 | ((c >> 12) & 63));
            o[k++] = (u8)(0x80 | ((c >> 6) & 63)); o[k++] = (u8)(0x80 | (c & 63));
        }
    }
    return k;
}

/* bytes -> UTF-16; invalid UTF-8 bytes become U+DC80..U+DCFF. out needs n units. */
static size_t b2w(const char *in, size_t n, gzch *out)
{
    const u8 *s = (const u8 *)in;
    size_t i = 0, o = 0;
    while (i < n) {
        u32 c = s[i];
        if (c < 0x80) { out[o++] = (gzch)c; i++; continue; }
        u32 need = 0, cp = 0;
        if (c >= 0xC2 && c <= 0xDF) { need = 1; cp = c & 0x1f; }
        else if (c >= 0xE0 && c <= 0xEF) { need = 2; cp = c & 0x0f; }
        else if (c >= 0xF0 && c <= 0xF4) { need = 3; cp = c & 0x07; }
        int ok = need && n - i > need;
        for (u32 k = 1; ok && k <= need; k++) {
            if ((s[i + k] & 0xC0) != 0x80) ok = 0;
            else cp = (cp << 6) | (s[i + k] & 0x3f);
        }
        if (ok && ((need == 2 && cp < 0x800) || (need == 3 && (cp < 0x10000 || cp > 0x10FFFF)) ||
                   (cp >= 0xD800 && cp <= 0xDFFF)))
            ok = 0;
        if (!ok) { out[o++] = (gzch)(0xDC00 + c); i++; continue; }
        i += need + 1;
        if (cp >= 0x10000) {
            cp -= 0x10000;
            out[o++] = (gzch)(0xD800 + (cp >> 10));
            out[o++] = (gzch)(0xDC00 + (cp & 0x3ff));
        } else {
            out[o++] = (gzch)cp;
        }
    }
    return o;
}

char *gz_os_path_bytes(const gzch *w)
{
    size_t n = gz_wcslen(w);
    char *s = (char *)gz_alloc(n * 3 + 1);
    if (!s) return 0;
    s[w2b(w, n, s)] = 0;
    return s;
}

gzch *gz_os_path_wide(const char *s)
{
    size_t n = strlen(s);
    gzch *w = (gzch *)gz_alloc((n + 1) * sizeof(gzch));
    if (!w) return 0;
    w[b2w(s, n, w)] = 0;
    return w;
}

size_t gz_os_native_len(const gzch *s, size_t n)
{
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        u32 c = s[i];
        if (c < 0x80) k += 1;
        else if (c < 0x800) k += 2;
        else if (c >= 0xDC80 && c <= 0xDCFF) k += 1;
        else if (c >= 0xD800 && c < 0xDC00 && i + 1 < n && s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000) { k += 4; i++; }
        else k += 3;
    }
    return k;
}

/* native path in a stack buffer when short, on the heap otherwise */
typedef struct { char *p; char sb[1536]; } npath;

static int np_get(npath *np, const gzch *w)
{
    size_t n = gz_wcslen(w);
    np->p = np->sb;
    if (n * 3 + 1 > sizeof np->sb) {
        if (n > (1u << 20)) return GZ_OSE_NAMETOOLONG;
        np->p = (char *)malloc(n * 3 + 1);
        if (!np->p) return GZ_OSE_NOMEM;
    }
    np->p[w2b(w, n, np->p)] = 0;
    return GZ_OSE_OK;
}

static void np_free(npath *np)
{
    if (np->p != np->sb) free(np->p);
}

#define WITH_PATH(np, w) npath np; { int e_ = np_get(&np, (w)); if (e_) return e_; }

/* ---------------- time helpers ---------------- */

static u64 ts_ft(struct timespec t)
{
    i64 s = (i64)t.tv_sec;
    if (s < -11644473600LL) return 0;
    return gz_unix_to_filetime(s) + (u64)(t.tv_nsec / 100);
}

static struct timespec ft_ts(u64 ft)
{
    struct timespec t;
    if (!ft) { t.tv_sec = 0; t.tv_nsec = UTIME_OMIT; return t; }
    i64 s = gz_filetime_to_unix(ft);
    t.tv_sec = (time_t)s;
    t.tv_nsec = (long)((ft % 10000000ULL) * 100);
    return t;
}

static void fill_stat(const struct stat *s, gz_os_info *st)
{
    memset(st, 0, sizeof *st);
    st->size = S_ISREG(s->st_mode) ? (u64)s->st_size : 0;
    st->mtime = ts_ft(ST_MTIM(s));
    st->atime = ts_ft(ST_ATIM(s));
    st->ctime = ts_ft(ST_CTIM(s));
    st->dev = (u64)s->st_dev;
    st->ino = (u64)s->st_ino;
    st->mode = (u32)s->st_mode;
    st->type = S_ISREG(s->st_mode) ? GZ_FT_FILE : S_ISDIR(s->st_mode) ? GZ_FT_DIR
             : S_ISLNK(s->st_mode) ? GZ_FT_LINK : GZ_FT_OTHER;
    st->attr = st->type == GZ_FT_DIR ? 0x10 : 0x20;
    if (!(s->st_mode & 0200)) st->attr |= 1;
}

/* ---------------- files ---------------- */

#define FD(x) ((int)(x))

int gz_os_open_read(const gzch *path, gz_fd *fd)
{
    WITH_PATH(np, path);
    int f = open(np.p, O_RDONLY | O_CLOEXEC);
    int e = f < 0 ? ose(errno) : 0;
    np_free(&np);
    *fd = f < 0 ? GZ_FD_NONE : (gz_fd)f;
    return e;
}

int gz_os_create(const gzch *path, u32 mode, gz_fd *fd)
{
    WITH_PATH(np, path);
    int f;
    do f = open(np.p, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, (mode_t)(mode & 07777));
    while (f < 0 && errno == EINTR);
    int e = f < 0 ? ose(errno) : 0;
    np_free(&np);
    *fd = f < 0 ? GZ_FD_NONE : (gz_fd)f;
    return e;
}

int gz_os_read(gz_fd fd, void *buf, u32 n, u32 *got)
{
    *got = 0;
    for (;;) {
        ssize_t r = read(FD(fd), buf, n);
        if (r >= 0) { *got = (u32)r; return GZ_OSE_OK; }
        if (errno != EINTR) return ose(errno);
    }
}

int gz_os_pread(gz_fd fd, u64 off, void *buf, u32 n, u32 *got)
{
    *got = 0;
    while (n) {
        ssize_t r = pread(FD(fd), buf, n, (off_t)off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return ose(errno);
        }
        if (r == 0) break;
        *got += (u32)r;
        buf = (u8 *)buf + r;
        off += (u64)r;
        n -= (u32)r;
    }
    return GZ_OSE_OK;
}

int gz_os_write(gz_fd fd, const void *p, size_t n)
{
    const u8 *b = (const u8 *)p;
    while (n) {
        size_t c = n > (1u << 30) ? (1u << 30) : n;
        ssize_t r = write(FD(fd), b, c);
        if (r < 0) {
            if (errno == EINTR) continue;
            return ose(errno);
        }
        if (r == 0) return GZ_OSE_NOSPC;
        b += r;
        n -= (size_t)r;
    }
    return GZ_OSE_OK;
}

int gz_os_pwrite(gz_fd fd, u64 off, const void *p, size_t n)
{
    const u8 *b = (const u8 *)p;
    while (n) {
        size_t c = n > (1u << 30) ? (1u << 30) : n;
        ssize_t r = pwrite(FD(fd), b, c, (off_t)off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return ose(errno);
        }
        if (r == 0) return GZ_OSE_NOSPC;
        b += r;
        off += (u64)r;
        n -= (size_t)r;
    }
    return GZ_OSE_OK;
}

int gz_os_close(gz_fd fd)
{
    if (fd == GZ_FD_NONE) return GZ_OSE_OK;
    /* never retry close() on EINTR: the descriptor is gone either way */
    return close(FD(fd)) && errno != EINTR ? ose(errno) : GZ_OSE_OK;
}

int gz_os_fstat(gz_fd fd, gz_os_info *st)
{
    struct stat s;
    if (fstat(FD(fd), &s)) return ose(errno);
    fill_stat(&s, st);
    return GZ_OSE_OK;
}

int gz_os_fset_times(gz_fd fd, u64 mtime, u64 atime)
{
    struct timespec t[2] = { ft_ts(atime), ft_ts(mtime) };
    return futimens(FD(fd), t) ? ose(errno) : GZ_OSE_OK;
}

int gz_os_fset_mode(gz_fd fd, u32 mode)
{
    return fchmod(FD(fd), (mode_t)(mode & 07777)) ? ose(errno) : GZ_OSE_OK;
}

int gz_os_open_src(const gzch *path, gz_src **out)
{
    WITH_PATH(np, path);
    errno = 0;
    *out = gz_posix_open_src(np.p);
    int e = *out ? 0 : (errno ? ose(errno) : GZ_OSE_ISDIR);
    np_free(&np);
    return e;
}

/* ---------------- paths ---------------- */

int gz_os_stat(const gzch *path, gz_os_info *st, int follow)
{
    WITH_PATH(np, path);
    struct stat s;
    int r = follow ? stat(np.p, &s) : lstat(np.p, &s);
    int e = r ? ose(errno) : 0;
    np_free(&np);
    if (!e) fill_stat(&s, st);
    return e;
}

int gz_os_mkdir(const gzch *path, u32 mode)
{
    WITH_PATH(np, path);
    int e = mkdir(np.p, (mode_t)(mode & 07777)) ? ose(errno) : 0;
    np_free(&np);
    return e;
}

/* mkdir -p on a native path (modified in place, restored before returning) */
static int mkdirs_native(char *p)
{
    struct stat s;
    if (!stat(p, &s)) return S_ISDIR(s.st_mode) ? GZ_OSE_OK : GZ_OSE_NOTDIR;
    if (!mkdir(p, 0777)) return GZ_OSE_OK;
    if (errno != ENOENT) {
        int e = errno;
        if (e == EEXIST && !stat(p, &s) && S_ISDIR(s.st_mode)) return GZ_OSE_OK;
        return ose(e);
    }
    /* create the parents from the top */
    size_t n = strlen(p);
    for (size_t i = 1; i < n; i++) {
        if (p[i] != '/') continue;
        p[i] = 0;
        int r = mkdir(p, 0777);
        int e = r ? errno : 0;
        if (r && e == EEXIST && (stat(p, &s) || !S_ISDIR(s.st_mode))) { p[i] = '/'; return GZ_OSE_NOTDIR; }
        p[i] = '/';
        if (r && e != EEXIST) return ose(e);
    }
    if (mkdir(p, 0777) && !(errno == EEXIST && !stat(p, &s) && S_ISDIR(s.st_mode))) return ose(errno);
    return GZ_OSE_OK;
}

int gz_os_mkdirs(const gzch *path)
{
    WITH_PATH(np, path);
    int e = mkdirs_native(np.p);
    np_free(&np);
    return e;
}

int gz_os_set_times(const gzch *path, u64 mtime, u64 atime, int follow)
{
    WITH_PATH(np, path);
    struct timespec t[2] = { ft_ts(atime), ft_ts(mtime) };
    int e = utimensat(AT_FDCWD, np.p, t, follow ? 0 : AT_SYMLINK_NOFOLLOW) ? ose(errno) : 0;
    np_free(&np);
    return e;
}

int gz_os_set_mode(const gzch *path, u32 mode)
{
    WITH_PATH(np, path);
    int e = chmod(np.p, (mode_t)(mode & 07777)) ? ose(errno) : 0;
    np_free(&np);
    return e;
}

int gz_os_symlink(const gzch *target, const gzch *path)
{
    WITH_PATH(nt, target);
    npath np;
    int e = np_get(&np, path);
    if (!e) {
        e = symlink(nt.p, np.p) ? ose(errno) : 0;
        np_free(&np);
    }
    np_free(&nt);
    return e;
}

int gz_os_readlink(const gzch *path, gzch *buf, u32 cap)
{
    if (!cap) return GZ_OSE_NAMETOOLONG;
    buf[0] = 0;
    WITH_PATH(np, path);
    char tmp[4096];
    ssize_t r = readlink(np.p, tmp, sizeof tmp);
    int e = r < 0 ? ose(errno) : 0;
    np_free(&np);
    if (e) return e;
    if ((size_t)r >= sizeof tmp || (size_t)r + 1 > cap) return GZ_OSE_NAMETOOLONG;
    buf[b2w(tmp, (size_t)r, buf)] = 0;
    return GZ_OSE_OK;
}

int gz_os_link(const gzch *existing, const gzch *path)
{
    WITH_PATH(nx, existing);
    npath np;
    int e = np_get(&np, path);
    if (!e) {
        e = linkat(AT_FDCWD, nx.p, AT_FDCWD, np.p, 0) ? ose(errno) : 0;
        np_free(&np);
    }
    np_free(&nx);
    return e;
}

int gz_os_rename(const gzch *from, const gzch *to)
{
    WITH_PATH(nf, from);
    npath nt;
    int e = np_get(&nt, to);
    if (!e) {
        e = rename(nf.p, nt.p) ? ose(errno) : 0;
        np_free(&nt);
    }
    np_free(&nf);
    return e;
}

int gz_os_delete(const gzch *path)
{
    WITH_PATH(np, path);
    int e = 0;
    if (unlink(np.p)) {
        e = errno;
        if (e == EISDIR || e == EPERM) e = rmdir(np.p) ? errno : 0;
    }
    np_free(&np);
    return ose(e);
}

u32 gz_os_name_max(const gzch *dir)
{
    npath np;
    long v = -1;
    if (!np_get(&np, dir)) {
        errno = 0;
        v = pathconf(np.p, _PC_NAME_MAX);
        np_free(&np);
    }
    if (v <= 0 || v > 4096) v = 255;
    return (u32)v;
}

int gz_os_cwd(gzch *buf, u32 cap)
{
    char tmp[4096];
    if (!getcwd(tmp, sizeof tmp)) return ose(errno);
    size_t n = strlen(tmp);
    if (n + 1 > cap) return GZ_OSE_NAMETOOLONG;
    buf[b2w(tmp, n, buf)] = 0;
    return GZ_OSE_OK;
}

int gz_os_temp_dir(gzch *buf, u32 cap)
{
    const char *t = getenv("TMPDIR");
    if (!t || !*t) t = "/tmp";
    size_t n = strlen(t);
    while (n > 1 && t[n - 1] == '/') n--;
    if (n + 1 > cap) return GZ_OSE_NAMETOOLONG;
    buf[b2w(t, n, buf)] = 0;
    return GZ_OSE_OK;
}

int gz_os_create_temp(const gzch *prefix, gzch *path, u32 cap, gz_fd *fd)
{
    static volatile long counter;
    size_t pn = gz_wcslen(prefix);
    if (pn + 9 > cap) return GZ_OSE_NAMETOOLONG;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    u64 x = (u64)ts.tv_nsec * 0x9E3779B97F4A7C15ULL ^ ((u64)getpid() << 32) ^ (u64)(uintptr_t)path;
    int e = GZ_OSE_EXIST;
    for (int tries = 0; tries < 200 && e == GZ_OSE_EXIST; tries++) {
        x ^= (u64)gz_atomic_inc(&counter) * 0xBF58476D1CE4E5B9ULL;
        x ^= x >> 29; x *= 0x94D049BB133111EBULL; x ^= x >> 32;
        __builtin_memcpy(path, prefix, pn * sizeof(gzch));
        static const char al[] = "0123456789abcdefghijklmnopqrstuvwxyz";
        u64 y = x;
        for (int i = 0; i < 6; i++) { path[pn + i] = (gzch)al[y % 36]; y /= 36; }
        path[pn + 6] = 0;
        e = gz_os_create(path, 0600, fd);
    }
    return e;
}

int gz_os_mark_get(const gzch *path, u8 *buf, u32 cap, u32 *n)
{
    *n = 0;
#ifdef __APPLE__
    WITH_PATH(np, path);
    ssize_t r = getxattr(np.p, "com.apple.quarantine", buf, cap, 0, 0);
    np_free(&np);
    if (r > 0 && (size_t)r <= cap) *n = (u32)r;
#else
    (void)path; (void)buf; (void)cap;
#endif
    return GZ_OSE_OK;
}

void gz_os_mark_set(gz_fd fd, const gzch *path, const u8 *p, u32 n)
{
    (void)path;
#ifdef __APPLE__
    if (n && fd != GZ_FD_NONE) fsetxattr(FD(fd), "com.apple.quarantine", p, n, 0, 0);
#else
    (void)fd; (void)p; (void)n;
#endif
}

/* ---------------- folders ---------------- */

struct gz_os_dir { DIR *d; gzch *name; size_t cap; };

int gz_os_dir_open(const gzch *path, gz_os_dir **out)
{
    *out = 0;
    WITH_PATH(np, path);
    DIR *d = opendir(np.p);
    int e = d ? 0 : ose(errno);
    np_free(&np);
    if (e) return e;
    gz_os_dir *x = (gz_os_dir *)calloc(1, sizeof *x);
    if (!x) { closedir(d); return GZ_OSE_NOMEM; }
    x->d = d;
    *out = x;
    return GZ_OSE_OK;
}

int gz_os_dir_next(gz_os_dir *d, const gzch **name, int *type)
{
    *name = 0;
    *type = GZ_FT_NONE;
    for (;;) {
        errno = 0;
        struct dirent *de = readdir(d->d);
        if (!de) return errno ? ose(errno) : GZ_OSE_OK;
        const char *n = de->d_name;
        if (n[0] == '.' && (!n[1] || (n[1] == '.' && !n[2]))) continue;
        size_t len = strlen(n);
        if (len + 1 > d->cap) {
            size_t nc = len + 64;
            gzch *nb = (gzch *)realloc(d->name, nc * sizeof(gzch));
            if (!nb) return GZ_OSE_NOMEM;
            d->name = nb;
            d->cap = nc;
        }
        d->name[b2w(n, len, d->name)] = 0;
        *name = d->name;
#ifdef DT_DIR
        switch (de->d_type) {
        case DT_REG: *type = GZ_FT_FILE; break;
        case DT_DIR: *type = GZ_FT_DIR; break;
        case DT_LNK: *type = GZ_FT_LINK; break;
        case DT_UNKNOWN: break;
        default: *type = GZ_FT_OTHER; break;
        }
#endif
        return GZ_OSE_OK;
    }
}

void gz_os_dir_close(gz_os_dir *d)
{
    if (!d) return;
    closedir(d->d);
    free(d->name);
    free(d);
}

/* ---------------- threads ---------------- */

struct gz_os_thread { pthread_t t; int (*fn)(void *); void *arg; int ret; };
struct gz_os_mutex { pthread_mutex_t m; };
struct gz_os_cond { pthread_cond_t c; };

static void *thread_main(void *p)
{
    gz_os_thread *t = (gz_os_thread *)p;
    t->ret = t->fn(t->arg);
    return 0;
}

gz_os_thread *gz_os_thread_start(int (*fn)(void *), void *arg, u32 stack)
{
    gz_os_thread *t = (gz_os_thread *)calloc(1, sizeof *t);
    if (!t) return 0;
    t->fn = fn;
    t->arg = arg;
    pthread_attr_t a;
    pthread_attr_init(&a);
    size_t ss = stack < (1u << 20) ? (1u << 20) : stack;
#ifdef PTHREAD_STACK_MIN
    if (ss < (size_t)PTHREAD_STACK_MIN) ss = (size_t)PTHREAD_STACK_MIN;
#endif
    pthread_attr_setstacksize(&a, ss);
    int r = pthread_create(&t->t, &a, thread_main, t);
    pthread_attr_destroy(&a);
    if (r) { free(t); return 0; }
    return t;
}

int gz_os_thread_join(gz_os_thread *t)
{
    if (!t) return 0;
    pthread_join(t->t, 0);
    int r = t->ret;
    free(t);
    return r;
}

gz_os_mutex *gz_os_mutex_new(void)
{
    gz_os_mutex *m = (gz_os_mutex *)calloc(1, sizeof *m);
    if (m && pthread_mutex_init(&m->m, 0)) { free(m); m = 0; }
    return m;
}

void gz_os_mutex_free(gz_os_mutex *m)
{
    if (!m) return;
    pthread_mutex_destroy(&m->m);
    free(m);
}

void gz_os_mutex_lock(gz_os_mutex *m) { pthread_mutex_lock(&m->m); }
void gz_os_mutex_unlock(gz_os_mutex *m) { pthread_mutex_unlock(&m->m); }

gz_os_cond *gz_os_cond_new(void)
{
    gz_os_cond *c = (gz_os_cond *)calloc(1, sizeof *c);
    if (!c) return 0;
    pthread_condattr_t a;
    pthread_condattr_init(&a);
#ifndef __APPLE__
    pthread_condattr_setclock(&a, CLOCK_MONOTONIC);
#endif
    int r = pthread_cond_init(&c->c, &a);
    pthread_condattr_destroy(&a);
    if (r) { free(c); return 0; }
    return c;
}

void gz_os_cond_free(gz_os_cond *c)
{
    if (!c) return;
    pthread_cond_destroy(&c->c);
    free(c);
}

void gz_os_cond_wait(gz_os_cond *c, gz_os_mutex *m) { pthread_cond_wait(&c->c, &m->m); }

int gz_os_cond_timedwait(gz_os_cond *c, gz_os_mutex *m, u32 ms)
{
    struct timespec ts;
#ifdef __APPLE__
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    return pthread_cond_timedwait_relative_np(&c->c, &m->m, &ts) == ETIMEDOUT;
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    return pthread_cond_timedwait(&c->c, &m->m, &ts) == ETIMEDOUT;
#endif
}

void gz_os_cond_signal(gz_os_cond *c) { pthread_cond_signal(&c->c); }
void gz_os_cond_broadcast(gz_os_cond *c) { pthread_cond_broadcast(&c->c); }

int gz_os_cpu_count(void)
{
#if defined(__linux__) && defined(CPU_COUNT)
    cpu_set_t set;
    if (!sched_getaffinity(0, sizeof set, &set)) {
        int n = CPU_COUNT(&set);
        if (n > 0) return n;
    }
#endif
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)(n > 1024 ? 1024 : n) : 1;
}

u64 gz_os_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (u64)t.tv_sec * 1000u + (u64)(t.tv_nsec / 1000000L);
}

/* ---------------- time ---------------- */

u64 gz_os_now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return ts_ft(t);
}

u64 gz_os_dos_to_utc(u32 dos)
{
    u32 d = dos >> 16, t = dos & 0xffff;
    if (!d) return 0;
    struct tm tm;
    memset(&tm, 0, sizeof tm);
    tm.tm_year = 80 + (int)(d >> 9);
    tm.tm_mon = (int)((d >> 5) & 15) - 1;
    tm.tm_mday = (int)(d & 31);
    tm.tm_hour = (int)(t >> 11);
    tm.tm_min = (int)((t >> 5) & 63);
    tm.tm_sec = (int)((t & 31) * 2);
    tm.tm_isdst = -1;
    if (tm.tm_mon < 0 || tm.tm_mon > 11 || !tm.tm_mday || tm.tm_hour > 23 || tm.tm_min > 59) return 0;
    time_t s = mktime(&tm);
    if (s == (time_t)-1) return 0;
    return gz_unix_to_filetime((i64)s);
}

int gz_os_local_time(u64 ft, gz_os_tm *o)
{
    memset(o, 0, sizeof *o);
    if (!ft) return GZ_OSE_OTHER;
    time_t s = (time_t)gz_filetime_to_unix(ft);
    struct tm tm;
    if (!localtime_r(&s, &tm)) return GZ_OSE_OTHER;
    o->year = tm.tm_year + 1900;
    o->month = tm.tm_mon + 1;
    o->day = tm.tm_mday;
    o->hour = tm.tm_hour;
    o->min = tm.tm_min;
    o->sec = tm.tm_sec;
    return GZ_OSE_OK;
}
