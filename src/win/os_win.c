/*
 * 고깃ZIP - Windows implementation of src/app/os.h
 *
 * Only Windows 2000 APIs (W functions). Paths longer than MAX_PATH get the
 * \\?\ (or \\?\UNC\) prefix. Condition variables are built from semaphores
 * (CONDITION_VARIABLE and SRWLOCK are Vista+), mutexes are critical sections.
 * Symbolic links are not created (GZ_OSC_LINKS is not reported); directory
 * junctions and symbolic links are reported by gz_os_stat as GZ_FT_LINK so the
 * engine can follow them with loop detection.
 */
#ifndef UNICODE
#define UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#undef WINVER
#undef _WIN32_WINNT
#define WINVER 0x0500
#define _WIN32_WINNT 0x0500
#include <windows.h>
#include "os.h"
#include "arc.h"

#define REPARSE_TAG_SYMLINK     0xA000000Cu
#define REPARSE_TAG_MOUNT_POINT 0xA0000003u
#define STACK_RESERVATION       0x00010000u   /* STACK_SIZE_PARAM_IS_A_RESERVATION (XP+) */

/* ---------------- errors ---------------- */

static int ose_code(DWORD e)
{
    switch (e) {
    case 0: return GZ_OSE_OK;
    case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND: case ERROR_BAD_NETPATH: case ERROR_BAD_NET_NAME:
    case ERROR_INVALID_DRIVE: case ERROR_NOT_READY: case ERROR_BAD_PATHNAME:
        return GZ_OSE_NOENT;
    case ERROR_FILE_EXISTS: case ERROR_ALREADY_EXISTS: return GZ_OSE_EXIST;
    case ERROR_FILENAME_EXCED_RANGE: case ERROR_BUFFER_OVERFLOW: return GZ_OSE_NAMETOOLONG;
    case ERROR_DISK_FULL: case ERROR_HANDLE_DISK_FULL: return GZ_OSE_NOSPC;
    case ERROR_ACCESS_DENIED: case ERROR_WRITE_PROTECT: case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION: case ERROR_PRIVILEGE_NOT_HELD:
        return GZ_OSE_ACCES;
    case ERROR_DIRECTORY: return GZ_OSE_NOTDIR;
    case ERROR_NOT_ENOUGH_MEMORY: case ERROR_OUTOFMEMORY: return GZ_OSE_NOMEM;
    case ERROR_NOT_SAME_DEVICE: return GZ_OSE_XDEV;
    case ERROR_NOT_SUPPORTED: case ERROR_INVALID_FUNCTION: return GZ_OSE_NOTSUP;
    case ERROR_CANT_RESOLVE_FILENAME: return GZ_OSE_LOOP;
    }
    return GZ_OSE_OTHER;
}

static int ose(void) { return ose_code(GetLastError()); }

int gz_os_err_gz(int e, int fallback)
{
    if (e == GZ_OSE_OK) return GZ_OK;
    if (e == GZ_OSE_NOSPC) return GZ_E_DISK;
    if (e == GZ_OSE_NOMEM) return GZ_E_NOMEM;
    return fallback;
}

u32 gz_os_caps(void) { return GZ_OSC_WIN_NAMES | GZ_OSC_CASE_FOLD | GZ_OSC_MARK | GZ_OSC_ATTRS; }
u32 gz_os_umask(void) { return 0; }

/* ---------------- text ---------------- */

char *gz_os_path_bytes(const gzch *w)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return 0;
    char *s = (char *)gz_alloc((size_t)n + 1);
    if (s) WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
    return s;
}

gzch *gz_os_path_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return 0;
    gzch *w = (gzch *)gz_alloc(((size_t)n + 1) * sizeof(gzch));
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

size_t gz_os_native_len(const gzch *w, size_t n) { (void)w; return n; }

/* ---------------- native paths ---------------- */

typedef struct { const wchar_t *p; wchar_t *heap; } npath;

static int is_plain_abs(const gzch *w)
{
    int drive = ((w[0] | 32) >= 'a' && (w[0] | 32) <= 'z' && w[1] == ':' && w[2] == '\\');
    int unc = w[0] == '\\' && w[1] == '\\' && w[2] && w[2] != '?' && w[2] != '.';
    if (!drive && !unc) return 0;
    for (const gzch *p = w; *p; p++) {
        if (*p == '/') return 0;
        /* "\.\" and "\..\" need GetFullPathName's normalisation */
        if (*p == '\\' && p[1] == '.' && (p[2] == '\\' || !p[2] || (p[2] == '.' && (p[3] == '\\' || !p[3]))))
            return 0;
    }
    return 1;
}

/* Path as Win32 wants it: unchanged when short, else \\?\-prefixed full path. */
static int np_get(npath *n, const gzch *w)
{
    n->heap = 0;
    n->p = (const wchar_t *)w;
    size_t len = gz_wcslen(w);
    if (len < MAX_PATH - 12) return GZ_OSE_OK;
    if (w[0] == '\\' && w[1] == '\\' && (w[2] == '?' || w[2] == '.') && w[3] == '\\') return GZ_OSE_OK;
    if (len > 32000) return GZ_OSE_NAMETOOLONG;
    wchar_t *full = (wchar_t *)w;
    wchar_t *tmp = 0;
    if (!is_plain_abs(w)) {
        DWORD need = GetFullPathNameW(w, 0, NULL, NULL);
        if (!need || need > 32000) return need ? GZ_OSE_NAMETOOLONG : ose();
        tmp = (wchar_t *)gz_alloc(((size_t)need + 2) * sizeof(wchar_t));
        if (!tmp) return GZ_OSE_NOMEM;
        DWORD got = GetFullPathNameW(w, need + 1, tmp, NULL);
        if (!got || got > need) { gz_free(tmp); return GZ_OSE_NAMETOOLONG; }
        full = tmp;
    }
    size_t fl = gz_wcslen(full);
    int unc = full[0] == '\\' && full[1] == '\\';
    wchar_t *o = (wchar_t *)gz_alloc((fl + 10) * sizeof(wchar_t));
    if (!o) { gz_free(tmp); return GZ_OSE_NOMEM; }
    static const wchar_t pl[] = L"\\\\?\\", pu[] = L"\\\\?\\UNC\\";
    size_t k = 0;
    if (unc) { for (; pu[k]; k++) o[k] = pu[k]; __builtin_memcpy(o + k, full + 2, (fl - 1) * sizeof(wchar_t)); }
    else { for (; pl[k]; k++) o[k] = pl[k]; __builtin_memcpy(o + k, full, (fl + 1) * sizeof(wchar_t)); }
    gz_free(tmp);
    n->heap = o;
    n->p = o;
    return GZ_OSE_OK;
}

static void np_free(npath *n) { gz_free(n->heap); n->heap = 0; }

/* path + suffix (e.g. ":Zone.Identifier"), as a native path */
static int np_suffix(npath *n, const gzch *w, const wchar_t *suffix)
{
    size_t a = gz_wcslen(w), b = 0;
    while (suffix[b]) b++;
    gzch *t = (gzch *)gz_alloc((a + b + 1) * sizeof(gzch));
    if (!t) return GZ_OSE_NOMEM;
    __builtin_memcpy(t, w, a * sizeof(gzch));
    __builtin_memcpy(t + a, suffix, (b + 1) * sizeof(gzch));
    int e = np_get(n, t);
    if (!e && !n->heap) { n->heap = (wchar_t *)t; n->p = (wchar_t *)t; return GZ_OSE_OK; }
    gz_free(t);
    return e;
}

#define H(fd) ((HANDLE)(fd))

/* ---------------- files ---------------- */

static int open_native(const gzch *path, DWORD access, DWORD share, DWORD disp, DWORD flags, gz_fd *fd)
{
    npath np;
    *fd = GZ_FD_NONE;
    int e = np_get(&np, path);
    if (e) return e;
    HANDLE h = CreateFileW(np.p, access, share, NULL, disp, flags, NULL);
    e = h == INVALID_HANDLE_VALUE ? ose() : GZ_OSE_OK;
    np_free(&np);
    if (!e) *fd = (gz_fd)h;
    return e;
}

int gz_os_open_read(const gzch *path, gz_fd *fd)
{
    return open_native(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, fd);
}

int gz_os_create(const gzch *path, u32 mode, gz_fd *fd)
{
    (void)mode;
    return open_native(path, GENERIC_WRITE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, CREATE_NEW,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, fd);
}

int gz_os_read(gz_fd fd, void *buf, u32 n, u32 *got)
{
    DWORD g = 0;
    *got = 0;
    if (!ReadFile(H(fd), buf, n, &g, NULL)) {
        DWORD le = GetLastError();
        return le == ERROR_HANDLE_EOF || le == ERROR_BROKEN_PIPE ? GZ_OSE_OK : ose_code(le);
    }
    *got = g;
    return GZ_OSE_OK;
}

static int read_at(HANDLE h, u64 off, void *buf, u32 n, u32 *got)
{
    OVERLAPPED ov;
    DWORD g = 0;
    __builtin_memset(&ov, 0, sizeof ov);
    ov.Offset = (DWORD)off;
    ov.OffsetHigh = (DWORD)(off >> 32);
    *got = 0;
    if (!ReadFile(h, buf, n, &g, &ov)) {
        DWORD le = GetLastError();
        return le == ERROR_HANDLE_EOF ? GZ_OSE_OK : ose_code(le);
    }
    *got = g;
    return GZ_OSE_OK;
}

/* A positioned transfer on a synchronous handle moves the file pointer: keep it where
 * it was (POSIX pread/pwrite semantics; one thread per fd). */
int gz_os_pread(gz_fd fd, u64 off, void *buf, u32 n, u32 *got)
{
    LARGE_INTEGER z, cur;
    z.QuadPart = 0;
    int have = SetFilePointerEx(H(fd), z, &cur, FILE_CURRENT) != 0;
    int e = read_at(H(fd), off, buf, n, got);
    if (have) SetFilePointerEx(H(fd), cur, NULL, FILE_BEGIN);
    return e;
}

static int write_all(HANDLE h, const u8 *p, size_t n, OVERLAPPED *ov, u64 off)
{
    while (n) {
        DWORD chunk = n > (16u << 20) ? (16u << 20) : (DWORD)n, wr = 0;
        if (ov) {
            __builtin_memset(ov, 0, sizeof *ov);
            ov->Offset = (DWORD)off;
            ov->OffsetHigh = (DWORD)(off >> 32);
        }
        if (!WriteFile(h, p, chunk, &wr, ov)) return ose();
        if (!wr) return GZ_OSE_NOSPC;
        p += wr;
        n -= wr;
        off += wr;
    }
    return GZ_OSE_OK;
}

int gz_os_write(gz_fd fd, const void *p, size_t n) { return write_all(H(fd), (const u8 *)p, n, 0, 0); }

int gz_os_pwrite(gz_fd fd, u64 off, const void *p, size_t n)
{
    LARGE_INTEGER z, cur;
    OVERLAPPED ov;
    z.QuadPart = 0;
    if (!SetFilePointerEx(H(fd), z, &cur, FILE_CURRENT)) return ose();
    int e = write_all(H(fd), (const u8 *)p, n, &ov, off);
    SetFilePointerEx(H(fd), cur, NULL, FILE_BEGIN);
    return e;
}

int gz_os_close(gz_fd fd) { return CloseHandle(H(fd)) ? GZ_OSE_OK : ose(); }

static u64 ft64(FILETIME t) { return ((u64)t.dwHighDateTime << 32) | t.dwLowDateTime; }
static FILETIME ftset(u64 v) { FILETIME t; t.dwLowDateTime = (DWORD)v; t.dwHighDateTime = (DWORD)(v >> 32); return t; }

static void fill_attr(gz_os_info *st, DWORD attr, int is_link)
{
    st->attr = attr;
    if (is_link) { st->type = GZ_FT_LINK; st->mode = 0120777; }
    else if (attr & FILE_ATTRIBUTE_DIRECTORY) { st->type = GZ_FT_DIR; st->mode = 040755; }
    else { st->type = GZ_FT_FILE; st->mode = (attr & FILE_ATTRIBUTE_READONLY) ? 0100444 : 0100644; }
    if (st->type != GZ_FT_FILE) st->size = 0;
}

static void fill_info(gz_os_info *st, const BY_HANDLE_FILE_INFORMATION *bi, int is_link)
{
    __builtin_memset(st, 0, sizeof *st);
    st->size = ((u64)bi->nFileSizeHigh << 32) | bi->nFileSizeLow;
    st->mtime = ft64(bi->ftLastWriteTime);
    st->atime = ft64(bi->ftLastAccessTime);
    st->ctime = ft64(bi->ftCreationTime);
    st->dev = bi->dwVolumeSerialNumber;
    st->ino = ((u64)bi->nFileIndexHigh << 32) | bi->nFileIndexLow;
    fill_attr(st, bi->dwFileAttributes, is_link);
}

int gz_os_fstat(gz_fd fd, gz_os_info *st)
{
    BY_HANDLE_FILE_INFORMATION bi;
    if (!GetFileInformationByHandle(H(fd), &bi)) return ose();
    fill_info(st, &bi, 0);
    return GZ_OSE_OK;
}

int gz_os_fset_times(gz_fd fd, u64 mtime, u64 atime)
{
    FILETIME m = ftset(mtime), a = ftset(atime);
    return SetFileTime(H(fd), NULL, atime ? &a : NULL, mtime ? &m : NULL) ? GZ_OSE_OK : ose();
}

int gz_os_fset_mode(gz_fd fd, u32 mode) { (void)fd; (void)mode; return GZ_OSE_OK; }

/* read-only / hidden / system: by name (the handle stays usable, SetFileTime still works) */
int gz_os_fset_attr(gz_fd fd, const gzch *path, u32 attr)
{
    (void)fd;
    attr &= FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    if (!attr) return GZ_OSE_OK;
    npath np;
    int e = np_get(&np, path);
    if (e) return e;
    e = SetFileAttributesW(np.p, attr) ? GZ_OSE_OK : ose();
    np_free(&np);
    return e;
}

static int src_read(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    u32 total = 0;
    *got = 0;
    while (total < n) {          /* short reads only at the end */
        u32 g = 0;
        int e = read_at((HANDLE)s->h, off + total, (u8 *)buf + total, n - total, &g);
        if (e) return GZ_E_IO;
        if (!g) break;
        total += g;
    }
    *got = total;
    return GZ_OK;
}

static void src_free(gz_src *s)
{
    if (s->h) CloseHandle((HANDLE)s->h);
    gz_free(s);
}

int gz_os_open_src(const gzch *path, gz_src **out)
{
    gz_fd fd;
    *out = 0;
    int e = open_native(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, &fd);
    if (e) return e;
    LARGE_INTEGER sz;
    BY_HANDLE_FILE_INFORMATION bi;
    if (!GetFileSizeEx(H(fd), &sz) || !GetFileInformationByHandle(H(fd), &bi)) {
        e = ose();
        CloseHandle(H(fd));
        return e ? e : GZ_OSE_OTHER;
    }
    if (bi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { CloseHandle(H(fd)); return GZ_OSE_ISDIR; }
    gz_src *s = (gz_src *)gz_alloc(sizeof(gz_src));
    if (!s) { CloseHandle(H(fd)); return GZ_OSE_NOMEM; }
    s->h = (void *)fd;
    s->size = (u64)sz.QuadPart;
    s->read_at = src_read;
    s->free = src_free;
    *out = s;
    return GZ_OSE_OK;
}

/* ---------------- paths ---------------- */

/* reparse tag of a path that has FILE_ATTRIBUTE_REPARSE_POINT (0 = unknown) */
static DWORD reparse_tag(const wchar_t *np)
{
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(np, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    FindClose(h);
    return (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ? fd.dwReserved0 : 0;
}

static int is_link_tag(DWORD tag) { return tag == REPARSE_TAG_SYMLINK || tag == REPARSE_TAG_MOUNT_POINT; }

int gz_os_stat(const gzch *path, gz_os_info *st, int follow)
{
    npath np;
    __builtin_memset(st, 0, sizeof *st);
    int e = np_get(&np, path);
    if (e) return e;
    HANDLE h = CreateFileW(np.p, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | (follow ? 0 : FILE_FLAG_OPEN_REPARSE_POINT), NULL);
    if (h != INVALID_HANDLE_VALUE) {
        BY_HANDLE_FILE_INFORMATION bi;
        int ok = GetFileInformationByHandle(h, &bi) != 0;
        CloseHandle(h);
        if (ok) {
            int link = !follow && (bi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && is_link_tag(reparse_tag(np.p));
            fill_info(st, &bi, link);
            np_free(&np);
            return GZ_OSE_OK;
        }
    }
    /* in use without sharing, or no access to the object: the directory entry still tells */
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExW(np.p, GetFileExInfoStandard, &fa)) {
        e = ose();
        np_free(&np);
        return e ? e : GZ_OSE_OTHER;
    }
    st->size = ((u64)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
    st->mtime = ft64(fa.ftLastWriteTime);
    st->atime = ft64(fa.ftLastAccessTime);
    st->ctime = ft64(fa.ftCreationTime);
    int link = !follow && (fa.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && is_link_tag(reparse_tag(np.p));
    fill_attr(st, fa.dwFileAttributes, link);
    np_free(&np);
    return GZ_OSE_OK;
}

int gz_os_mkdir(const gzch *path, u32 mode)
{
    (void)mode;
    npath np;
    int e = np_get(&np, path);
    if (e) return e;
    e = CreateDirectoryW(np.p, NULL) ? GZ_OSE_OK : ose();
    np_free(&np);
    return e;
}

static int np_is_dir(const wchar_t *p)
{
    DWORD a = GetFileAttributesW(p);
    return a == INVALID_FILE_ATTRIBUTES ? -1 : (a & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

int gz_os_mkdirs(const gzch *path)
{
    npath np;
    int e = np_get(&np, path);
    if (e) return e;
    size_t n = gz_wcslen(np.p);
    wchar_t *b = (wchar_t *)gz_alloc((n + 2) * sizeof(wchar_t));
    if (!b) { np_free(&np); return GZ_OSE_NOMEM; }
    __builtin_memcpy(b, np.p, (n + 1) * sizeof(wchar_t));
    np_free(&np);
    while (n > 3 && (b[n - 1] == '\\' || b[n - 1] == '/')) b[--n] = 0;
    e = GZ_OSE_OK;
    if (np_is_dir(b) == 1) goto out;
    /* first component that may be created: after "X:\", "\\?\X:\", "\\server\share\", "\\?\UNC\s\sh\" */
    size_t start = 0, i, seps;
    if (b[0] == '\\' && b[1] == '\\' && b[2] == '?' && b[3] == '\\') {
        if ((b[4] | 32) == 'u' && (b[5] | 32) == 'n' && (b[6] | 32) == 'c' && b[7] == '\\') {
            for (i = 8, seps = 0; i < n && seps < 2; i++) if (b[i] == '\\') seps++;
            start = i;
        } else {
            start = 7;
        }
    } else if (b[0] == '\\' && b[1] == '\\') {
        for (i = 2, seps = 0; i < n && seps < 2; i++) if (b[i] == '\\') seps++;
        start = i;
    } else if (n >= 3 && b[1] == ':') {
        start = 3;
    }
    for (i = start; i <= n; i++) {
        if (i < n && b[i] != '\\' && b[i] != '/') continue;
        if (i == start) continue;
        wchar_t c = b[i];
        b[i] = 0;
        int d = np_is_dir(b);
        if (d == 0) { e = GZ_OSE_NOTDIR; break; }
        if (d < 0 && !CreateDirectoryW(b, NULL)) {
            DWORD le = GetLastError();
            if (le != ERROR_ALREADY_EXISTS || np_is_dir(b) != 1) { e = ose_code(le ? le : ERROR_ACCESS_DENIED); break; }
        }
        b[i] = c;
    }
out:
    gz_free(b);
    return e;
}

int gz_os_set_times(const gzch *path, u64 mtime, u64 atime, int follow)
{
    gz_fd fd;
    int e = open_native(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | (follow ? 0 : FILE_FLAG_OPEN_REPARSE_POINT), &fd);
    if (e) return e;
    e = gz_os_fset_times(fd, mtime, atime);
    CloseHandle(H(fd));
    return e;
}

int gz_os_set_mode(const gzch *path, u32 mode) { (void)path; (void)mode; return GZ_OSE_OK; }

int gz_os_symlink(const gzch *target, const gzch *path) { (void)target; (void)path; return GZ_OSE_NOTSUP; }

int gz_os_readlink(const gzch *path, gzch *buf, u32 cap)
{
    (void)path;
    if (cap) buf[0] = 0;
    return GZ_OSE_NOTSUP;
}

int gz_os_link(const gzch *existing, const gzch *path)
{
    npath a, b;
    int e = np_get(&a, existing);
    if (e) return e;
    e = np_get(&b, path);
    if (e) { np_free(&a); return e; }
    e = CreateHardLinkW(b.p, a.p, NULL) ? GZ_OSE_OK : ose();
    np_free(&a);
    np_free(&b);
    return e;
}

int gz_os_rename(const gzch *from, const gzch *to)
{
    npath a, b;
    int e = np_get(&a, from);
    if (e) return e;
    e = np_get(&b, to);
    if (e) { np_free(&a); return e; }
    e = GZ_OSE_OK;
    if (!MoveFileExW(a.p, b.p, MOVEFILE_REPLACE_EXISTING)) {
        e = ose();
        DWORD at = GetFileAttributesW(b.p);
        if (e == GZ_OSE_ACCES && at != INVALID_FILE_ATTRIBUTES && (at & FILE_ATTRIBUTE_READONLY) &&
            !(at & FILE_ATTRIBUTE_DIRECTORY) && SetFileAttributesW(b.p, at & ~FILE_ATTRIBUTE_READONLY))
            e = MoveFileExW(a.p, b.p, MOVEFILE_REPLACE_EXISTING) ? GZ_OSE_OK : ose();
    }
    np_free(&a);
    np_free(&b);
    return e;
}

int gz_os_delete(const gzch *path)
{
    npath np;
    int e = np_get(&np, path);
    if (e) return e;
    DWORD at = GetFileAttributesW(np.p);
    if (at == INVALID_FILE_ATTRIBUTES) {
        e = ose();
    } else if (at & FILE_ATTRIBUTE_DIRECTORY) {          /* folders and junctions */
        e = RemoveDirectoryW(np.p) ? GZ_OSE_OK : ose();
    } else if (!DeleteFileW(np.p)) {
        e = ose();
        if (e == GZ_OSE_ACCES && (at & FILE_ATTRIBUTE_READONLY) &&
            SetFileAttributesW(np.p, at & ~FILE_ATTRIBUTE_READONLY)) {
            e = DeleteFileW(np.p) ? GZ_OSE_OK : ose();
            if (e) SetFileAttributesW(np.p, at);
        }
    }
    np_free(&np);
    return e;
}

/* NTFS, FAT32 (LFN), exFAT and UDF all allow 255 UTF-16 units per name */
u32 gz_os_name_max(const gzch *dir) { (void)dir; return 255; }

static int copy_out(const wchar_t *s, DWORD n, gzch *buf, u32 cap)
{
    while (n > 3 && s[n - 1] == '\\') n--;          /* "C:\" stays */
    if (n + 1 > cap) return GZ_OSE_NAMETOOLONG;
    __builtin_memcpy(buf, s, n * sizeof(gzch));
    buf[n] = 0;
    return GZ_OSE_OK;
}

/* GetCurrentDirectoryW / GetTempPathW: length without NUL, or the size needed */
static int sys_dir(DWORD (WINAPI *get)(DWORD, LPWSTR), gzch *buf, u32 cap)
{
    wchar_t t[MAX_PATH + 2];
    DWORD n = get(MAX_PATH + 1, t);
    if (n && n <= MAX_PATH) return copy_out(t, n, buf, cap);
    if (!n) return ose();
    wchar_t *h = (wchar_t *)gz_alloc(((size_t)n + 2) * sizeof(wchar_t));
    if (!h) return GZ_OSE_NOMEM;
    DWORD m = get(n + 1, h);
    int e = (m && m <= n) ? copy_out(h, m, buf, cap) : GZ_OSE_NAMETOOLONG;
    gz_free(h);
    return e;
}

int gz_os_cwd(gzch *buf, u32 cap) { return sys_dir(GetCurrentDirectoryW, buf, cap); }
int gz_os_temp_dir(gzch *buf, u32 cap) { return sys_dir(GetTempPathW, buf, cap); }

int gz_os_create_temp(const gzch *prefix, gzch *path, u32 cap, gz_fd *fd)
{
    static volatile long counter;
    size_t pn = gz_wcslen(prefix);
    if (pn + 9 > cap) return GZ_OSE_NAMETOOLONG;
    LARGE_INTEGER q;
    QueryPerformanceCounter(&q);
    u64 x = (u64)q.QuadPart * 0x9E3779B97F4A7C15ULL ^ ((u64)GetCurrentProcessId() << 32) ^ GetTickCount() ^
            (u64)(uintptr_t)path;
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

/* Mark-of-the-Web: the "Zone.Identifier" alternate data stream */
int gz_os_mark_get(const gzch *path, u8 *buf, u32 cap, u32 *n)
{
    npath np;
    *n = 0;
    if (cap < 64 || np_suffix(&np, path, L":Zone.Identifier")) return GZ_OSE_OK;
    HANDLE z = CreateFileW(np.p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    np_free(&np);
    if (z == INVALID_HANDLE_VALUE) return GZ_OSE_OK;
    DWORD rd = 0;
    if (ReadFile(z, buf, cap, &rd, NULL) && rd) {
        if (rd == cap) {
            /* enormous stream: keep whole lines (ZoneId comes first) */
            while (rd && buf[rd - 1] != '\n') rd--;
            if (!rd) {
                static const char mz[] = "[ZoneTransfer]\r\nZoneId=3\r\n";
                __builtin_memcpy(buf, mz, sizeof mz - 1);
                rd = sizeof mz - 1;
            }
        }
        *n = rd;
    }
    CloseHandle(z);
    return GZ_OSE_OK;
}

/* Written while the file is still open and before its time is set: writing a named
 * stream updates the file's modification time. */
void gz_os_mark_set(gz_fd fd, const gzch *path, const u8 *p, u32 n)
{
    (void)fd;
    npath np;
    if (!n || np_suffix(&np, path, L":Zone.Identifier")) return;
    HANDLE z = CreateFileW(np.p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    np_free(&np);
    if (z == INVALID_HANDLE_VALUE) return;
    DWORD wr;
    WriteFile(z, p, n, &wr, NULL);
    CloseHandle(z);
}

/* ---------------- folders ---------------- */

struct gz_os_dir { HANDLE h; int pending, done; WIN32_FIND_DATAW fd; };

int gz_os_dir_open(const gzch *path, gz_os_dir **out)
{
    *out = 0;
    size_t n = gz_wcslen(path);
    gzch *pat = (gzch *)gz_alloc((n + 4) * sizeof(gzch));
    if (!pat) return GZ_OSE_NOMEM;
    __builtin_memcpy(pat, path, n * sizeof(gzch));
    if (n && pat[n - 1] != '\\' && pat[n - 1] != '/') pat[n++] = '\\';
    pat[n++] = '*';
    pat[n] = 0;
    npath np;
    int e = np_get(&np, pat);
    if (e) { gz_free(pat); return e; }
    gz_os_dir *d = (gz_os_dir *)gz_alloc(sizeof(gz_os_dir));
    if (!d) { np_free(&np); gz_free(pat); return GZ_OSE_NOMEM; }
    d->h = FindFirstFileW(np.p, &d->fd);
    if (d->h == INVALID_HANDLE_VALUE) {
        DWORD le = GetLastError();
        if (le == ERROR_FILE_NOT_FOUND || le == ERROR_NO_MORE_FILES) {
            d->done = 1;                       /* empty (drive root) */
        } else {
            e = ose_code(le);
            gz_free(d);
            d = 0;
        }
    } else {
        d->pending = 1;
    }
    np_free(&np);
    gz_free(pat);
    *out = d;
    return e;
}

int gz_os_dir_next(gz_os_dir *d, const gzch **name, int *type)
{
    *name = 0;
    *type = GZ_FT_NONE;
    for (;;) {
        if (d->done) return GZ_OSE_OK;
        if (!d->pending) {
            if (!FindNextFileW(d->h, &d->fd)) {
                DWORD le = GetLastError();
                d->done = 1;
                return le == ERROR_NO_MORE_FILES ? GZ_OSE_OK : ose_code(le);
            }
        }
        d->pending = 0;
        const wchar_t *n = d->fd.cFileName;
        if (n[0] == '.' && (!n[1] || (n[1] == '.' && !n[2]))) continue;
        DWORD a = d->fd.dwFileAttributes;
        if (!(a & FILE_ATTRIBUTE_REPARSE_POINT)) *type = (a & FILE_ATTRIBUTE_DIRECTORY) ? GZ_FT_DIR : GZ_FT_FILE;
        *name = (const gzch *)n;
        return GZ_OSE_OK;
    }
}

void gz_os_dir_close(gz_os_dir *d)
{
    if (!d) return;
    if (d->h && d->h != INVALID_HANDLE_VALUE) FindClose(d->h);
    gz_free(d);
}

/* ---------------- threads ---------------- */

struct gz_os_thread { HANDLE h; int (*fn)(void *); void *arg; int ret; };
struct gz_os_mutex { CRITICAL_SECTION cs; };
/* condition variable from two semaphores (SDL's generic algorithm): signal() waits
 * until the woken thread acknowledged, so a later waiter cannot steal the wake-up */
struct gz_os_cond { CRITICAL_SECTION lock; HANDLE wait_sem, done_sem; long waiting, signals; };

static DWORD WINAPI thread_main(void *p)
{
    gz_os_thread *t = (gz_os_thread *)p;
    t->ret = t->fn(t->arg);
    return 0;
}

gz_os_thread *gz_os_thread_start(int (*fn)(void *), void *arg, u32 stack)
{
    gz_os_thread *t = (gz_os_thread *)gz_alloc(sizeof(gz_os_thread));
    if (!t) return 0;
    t->fn = fn;
    t->arg = arg;
    /* XP+: reserve the requested stack, commit on demand. Windows 2000 does not know
     * the flag: there the size is the initial commit, so keep it moderate. */
    DWORD v = GetVersion();
    int xp = (LOBYTE(LOWORD(v)) > 5) || (LOBYTE(LOWORD(v)) == 5 && HIBYTE(LOWORD(v)) >= 1);
    if (!stack) stack = 1u << 20;
    if (!xp && stack > (512u << 10)) stack = 512u << 10;
    t->h = CreateThread(NULL, stack, thread_main, t, xp ? STACK_RESERVATION : 0, NULL);
    if (!t->h) { gz_free(t); return 0; }
    return t;
}

int gz_os_thread_join(gz_os_thread *t)
{
    if (!t) return 0;
    WaitForSingleObject(t->h, INFINITE);
    CloseHandle(t->h);
    int r = t->ret;
    gz_free(t);
    return r;
}

gz_os_mutex *gz_os_mutex_new(void)
{
    gz_os_mutex *m = (gz_os_mutex *)gz_alloc(sizeof(gz_os_mutex));
    if (m) InitializeCriticalSection(&m->cs);
    return m;
}

void gz_os_mutex_free(gz_os_mutex *m)
{
    if (!m) return;
    DeleteCriticalSection(&m->cs);
    gz_free(m);
}

void gz_os_mutex_lock(gz_os_mutex *m) { EnterCriticalSection(&m->cs); }
void gz_os_mutex_unlock(gz_os_mutex *m) { LeaveCriticalSection(&m->cs); }

gz_os_cond *gz_os_cond_new(void)
{
    gz_os_cond *c = (gz_os_cond *)gz_alloc(sizeof(gz_os_cond));
    if (!c) return 0;
    c->wait_sem = CreateSemaphoreW(NULL, 0, 0x7fffffff, NULL);
    c->done_sem = CreateSemaphoreW(NULL, 0, 0x7fffffff, NULL);
    if (!c->wait_sem || !c->done_sem) {
        if (c->wait_sem) CloseHandle(c->wait_sem);
        if (c->done_sem) CloseHandle(c->done_sem);
        gz_free(c);
        return 0;
    }
    InitializeCriticalSection(&c->lock);
    return c;
}

void gz_os_cond_free(gz_os_cond *c)
{
    if (!c) return;
    CloseHandle(c->wait_sem);
    CloseHandle(c->done_sem);
    DeleteCriticalSection(&c->lock);
    gz_free(c);
}

int gz_os_cond_timedwait(gz_os_cond *c, gz_os_mutex *m, u32 ms)
{
    EnterCriticalSection(&c->lock);
    c->waiting++;
    LeaveCriticalSection(&c->lock);
    gz_os_mutex_unlock(m);
    DWORD r = WaitForSingleObject(c->wait_sem, ms == 0xffffffffu ? INFINITE : ms);
    EnterCriticalSection(&c->lock);
    if (c->signals > 0) {
        /* timed out while a signal for us was already posted: take it */
        if (r != WAIT_OBJECT_0) WaitForSingleObject(c->wait_sem, INFINITE);
        ReleaseSemaphore(c->done_sem, 1, NULL);
        c->signals--;
    }
    c->waiting--;
    LeaveCriticalSection(&c->lock);
    gz_os_mutex_lock(m);
    return r == WAIT_OBJECT_0 ? 0 : 1;
}

void gz_os_cond_wait(gz_os_cond *c, gz_os_mutex *m) { gz_os_cond_timedwait(c, m, 0xffffffffu); }

static void cond_wake(gz_os_cond *c, int all)
{
    EnterCriticalSection(&c->lock);
    long n = c->waiting - c->signals;
    if (n > 0) {
        if (!all) n = 1;
        c->signals += n;
        ReleaseSemaphore(c->wait_sem, n, NULL);
        LeaveCriticalSection(&c->lock);
        for (long i = 0; i < n; i++) WaitForSingleObject(c->done_sem, INFINITE);
    } else {
        LeaveCriticalSection(&c->lock);
    }
}

void gz_os_cond_signal(gz_os_cond *c) { cond_wake(c, 0); }
void gz_os_cond_broadcast(gz_os_cond *c) { cond_wake(c, 1); }

int gz_os_cpu_count(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    int n = (int)si.dwNumberOfProcessors;
    return n < 1 ? 1 : n;
}

u64 gz_os_ms(void)
{
    static volatile long have = -1;
    static LARGE_INTEGER freq;
    if (have < 0) gz_atomic_store(&have, QueryPerformanceFrequency(&freq) && freq.QuadPart > 0);
    if (gz_atomic_load(&have)) {
        LARGE_INTEGER c;
        QueryPerformanceCounter(&c);
        u64 v = (u64)c.QuadPart, f = (u64)freq.QuadPart;
        return v / f * 1000 + v % f * 1000 / f;
    }
    return GetTickCount();
}

/* ---------------- time ---------------- */

u64 gz_os_now(void)
{
    FILETIME t;
    GetSystemTimeAsFileTime(&t);
    return ft64(t);
}

u64 gz_os_dos_to_utc(u32 dos)
{
    FILETIME l, u;
    WORD date = (WORD)(dos >> 16), time = (WORD)dos;
    if (!date) return 0;
    if (!DosDateTimeToFileTime(date, time, &l) || !LocalFileTimeToFileTime(&l, &u)) return 0;
    return ft64(u);
}

int gz_os_local_time(u64 ft, gz_os_tm *tm)
{
    FILETIME u = ftset(ft), l;
    SYSTEMTIME s;
    if (!FileTimeToLocalFileTime(&u, &l) || !FileTimeToSystemTime(&l, &s)) return GZ_OSE_OTHER;
    tm->year = s.wYear;
    tm->month = s.wMonth;
    tm->day = s.wDay;
    tm->hour = s.wHour;
    tm->min = s.wMinute;
    tm->sec = s.wSecond;
    return GZ_OSE_OK;
}
