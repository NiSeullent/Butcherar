/*
 * 고깃ZIP - core platform hooks for Linux / macOS (memory, code pages, sources)
 */
#include "arc.h"
#include "plat_posix.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <iconv.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>

void *gz_alloc(size_t n) { return calloc(1, n ? n : 1); }
void *gz_realloc(void *p, size_t n) { return realloc(p, n ? n : 1); }
void gz_free(void *p) { free(p); }

void *gz_alloc_big(size_t n)
{
    if (!n) n = 1;
    void *p = mmap(0, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? 0 : p;
}

void gz_free_big(void *p, size_t n)
{
    if (p) munmap(p, n ? n : 1);
}

/* ---------------- code pages ---------------- */

static int g_acp = -1, g_oemcp = -1;

/* Windows ANSI / OEM code page matching the user's locale: legacy archive names
 * were written by Windows programs in those code pages. */
static void locale_cps(void)
{
    const char *ov = getenv("GZ_TEST_ACP");
    if (!ov) ov = getenv("GOGITZIP_CODEPAGE");
    if (ov && atoi(ov) > 0) { g_acp = g_oemcp = atoi(ov); return; }
    const char *l = getenv("LC_ALL");
    if (!l || !*l) l = getenv("LC_CTYPE");
    if (!l || !*l) l = getenv("LANG");
    if (!l) l = "";
    struct { const char *pre; int acp, oem; } map[] = {
        { "ko", 949, 949 }, { "ja", 932, 932 }, { "zh_TW", 950, 950 }, { "zh_HK", 950, 950 },
        { "zh", 936, 936 }, { "ru", 1251, 866 }, { "uk", 1251, 866 }, { "be", 1251, 866 },
        { "bg", 1251, 866 }, { "sr", 1251, 855 }, { "pl", 1250, 852 }, { "cs", 1250, 852 },
        { "sk", 1250, 852 }, { "hu", 1250, 852 }, { "ro", 1250, 852 }, { "hr", 1250, 852 },
        { "sl", 1250, 852 }, { "el", 1253, 737 }, { "tr", 1254, 857 }, { "he", 1255, 862 },
        { "ar", 1256, 720 }, { "fa", 1256, 720 }, { "lt", 1257, 775 }, { "lv", 1257, 775 },
        { "et", 1257, 775 }, { "vi", 1258, 1258 }, { "th", 874, 874 },
    };
    g_acp = 1252; g_oemcp = 850;
    if (!strncmp(l, "en", 2) || !*l || !strcmp(l, "C") || !strncmp(l, "C.", 2) || !strcmp(l, "POSIX")) {
        g_acp = 1252; g_oemcp = 437;
    }
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++) {
        size_t n = strlen(map[i].pre);
        if (!strncmp(l, map[i].pre, n)) { g_acp = map[i].acp; g_oemcp = map[i].oem; break; }
    }
}

int gz_plat_acp(void) { if (g_acp < 0) locale_cps(); return g_acp; }
int gz_plat_oemcp(void) { if (g_oemcp < 0) locale_cps(); return g_oemcp; }

int gz_plat_case_fold(void)
{
#ifdef __APPLE__
    return 1;
#else
    return 0;
#endif
}

static void cp_name(int cp, char *out, size_t cap)
{
    if (cp == GZ_CP_UTF8) snprintf(out, cap, "UTF-8");
    else snprintf(out, cap, "CP%d", cp);
}

#define CP_CACHE 8
static pthread_mutex_t g_ic_lock = PTHREAD_MUTEX_INITIALIZER;
static struct { int cp; int ok; } g_valid[32];
static int g_nvalid;

int gz_plat_cp_valid(int cp)
{
    if (cp == GZ_CP_UTF8) return 1;
    pthread_mutex_lock(&g_ic_lock);
    for (int i = 0; i < g_nvalid; i++)
        if (g_valid[i].cp == cp) { int ok = g_valid[i].ok; pthread_mutex_unlock(&g_ic_lock); return ok; }
    char name[32];
    cp_name(cp, name, sizeof name);
    iconv_t ic = iconv_open("UTF-16LE", name);
    int ok = ic != (iconv_t)-1;
    if (ok) iconv_close(ic);
    if (g_nvalid < 32) { g_valid[g_nvalid].cp = cp; g_valid[g_nvalid].ok = ok; g_nvalid++; }
    pthread_mutex_unlock(&g_ic_lock);
    return ok;
}

/* convert with iconv; returns output bytes or -1 */
static long conv(const char *to, const char *from, const void *in, size_t inl, void *out, size_t outl)
{
    iconv_t ic = iconv_open(to, from);
    if (ic == (iconv_t)-1) return -1;
    char *ip = (char *)in, *op = (char *)out;
    size_t il = inl, ol = outl;
    size_t r = iconv(ic, &ip, &il, &op, &ol);
    if (r != (size_t)-1) r = iconv(ic, 0, 0, &op, &ol);
    iconv_close(ic);
    if (r == (size_t)-1) return -1;
    return (long)(outl - ol);
}

int gz_plat_mb2wc(int cp, const u8 *s, int n, gzch *out, int cap)
{
    if (n <= 0) return 0;
    char name[32];
    cp_name(cp, name, sizeof name);
    long r = conv("UTF-16LE", name, s, (size_t)n, out, (size_t)cap * 2);
    return r < 0 ? 0 : (int)(r / 2);
}

int gz_plat_wc2mb(int cp, const gzch *s, int n, u8 *out, int cap)
{
    if (n <= 0) return 0;
    char name[32];
    cp_name(cp, name, sizeof name);
    long r = conv(name, "UTF-16LE", s, (size_t)n * 2, out, (size_t)cap);
    return r < 0 ? 0 : (int)r;
}

int gz_plat_mb_valid(int cp, const u8 *s, int n)
{
    if (n <= 0) return 1;
    char name[32];
    cp_name(cp, name, sizeof name);
    size_t cap = (size_t)n * 4 + 8;
    void *tmp = malloc(cap);
    if (!tmp) return 1;
    long r = conv("UTF-16LE", name, s, (size_t)n, tmp, cap);
    free(tmp);
    return r >= 0;
}

/* ---------------- random ---------------- */

int gz_plat_random(void *buf, size_t n)
{
    u8 *p = (u8 *)buf;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return GZ_E_IO;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { close(fd); return GZ_E_IO; }
        p += r;
        n -= (size_t)r;
    }
    close(fd);
    return GZ_OK;
}

/* ---------------- file sources ---------------- */

static int fd_read_at(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    *got = 0;
    while (n) {
        ssize_t r = pread((int)(intptr_t)s->h, buf, n, (off_t)off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return GZ_E_IO;
        }
        if (r == 0) break;
        *got += (u32)r;
        buf = (u8 *)buf + r;
        off += (u64)r;
        n -= (u32)r;
    }
    return GZ_OK;
}

static void fd_free(gz_src *s)
{
    close((int)(intptr_t)s->h);
    free(s);
}

gz_src *gz_posix_open_src(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) || S_ISDIR(st.st_mode)) { close(fd); return 0; }
    gz_src *s = (gz_src *)calloc(1, sizeof(gz_src));
    if (!s) { close(fd); return 0; }
    s->read_at = fd_read_at;
    s->size = (u64)st.st_size;
    s->h = (void *)(intptr_t)fd;
    s->free = fd_free;
    return s;
}

char *gz_posix_utf8(const gzch *w)
{
    size_t n = gz_wcslen(w);
    char *s = (char *)malloc(n * 3 + 1);
    if (!s) return 0;
    int k = gz_utf16_to_utf8(w, n, (u8 *)s);
    s[k] = 0;
    return s;
}

gzch *gz_posix_wide(const char *s)
{
    size_t n = strlen(s);
    gzch *w = (gzch *)malloc((n + 1) * sizeof(gzch));
    if (!w) return 0;
    int k = gz_utf8_to_utf16((const u8 *)s, n, w);
    w[k] = 0;
    return w;
}

int gz_posix_open_volume(void *user, const gzch *name, gz_src **out)
{
    (void)user;
    char *p = gz_posix_utf8(name);
    if (!p) return GZ_E_NOMEM;
    *out = gz_posix_open_src(p);
    free(p);
    return *out ? GZ_OK : GZ_E_VOLUME;
}
