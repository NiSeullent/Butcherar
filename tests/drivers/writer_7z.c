/*
 * 7z writer driver: builds an item list from a manifest and runs gz_write_archive
 * with GZ_WF_7Z, so the tests can use what `gzt c` cannot express: symbolic links,
 * times with 100 ns precision, CTime/ATime, attributes, generated multi-GB inputs,
 * files that fail to open or read, shrink or grow, cancellation, sinks without
 * write_at.     usage: writer_7z <manifest> <out.7z>
 *
 * Manifest lines (tab separated; times are FILETIME values, 0 = unknown):
 *   opt <key> <value>      level method solid password encnames dict
 *                          nowriteat 1 | cancel_at <bytes> | onerror skip|abort
 *   f <name> <path> <mode> <attr> <mtime> <ctime> <atime>     file on disk
 *   d <name> <mode> <attr> <mtime>                            directory
 *   l <name> <target> <mode> <mtime>                          symbolic link
 *   g <name> <size> <seed> <kind> <mode>                      generated data
 *       kind: zero, rand, text, mix
 *   x <name> <declared> <actual> <fail> <seed>                faulty input
 *       fail: none | open | read (error after `actual` bytes)
 *   (mode octal, attr hex)
 *
 * Output: "CRC <crc32> <size> <name>" for every g / x item as produced (an
 * independent bitwise CRC), "ERR <code> <name>" for each on_error call,
 * "PROGRESS <calls> <monotonic> <done> <total>", then "RESULT <code>".
 */
#include "gz_write.h"
#include "cpu.h"
#include "crc32.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static u32 crc_tab[256];
static void crc_init(void)
{
    for (u32 i = 0; i < 256; i++) {
        u32 c = i;
        for (int k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc_tab[i] = c;
    }
}
static u32 crc_upd(u32 crc, const u8 *p, size_t n)
{
    crc = ~crc;
    while (n--) crc = crc_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

enum { T_FILE, T_GEN, T_FAULT };
typedef struct item_info {
    int type;
    char *path;
    u64 actual;          /* bytes delivered (gen: size)     */
    u32 seed;
    int kind;            /* gen kind                         */
    int fail;            /* 0 none, 1 open, 2 read           */
    u32 crc; u64 made;
    int printed;
} item_info;

typedef struct src {
    gz_wsrc w;
    FILE *f;
    item_info *ii;
    u64 pos;
    u64 x;               /* PRNG state */
    const char *wp;      /* text: rest of the current word */
    u32 crc;
} src;

static const char *k_words[] = { "고깃", "archive ", "zip ", "the ", "of ", "7z ", "data ", "\n", "솔리드 ",
                                 "compression ", "block ", "LZMA2 ", "file ", "name ", "0123456789 " };

static void gen(src *s, u8 *buf, u32 n)
{
    int kind0 = s->ii->kind;
    if (kind0 == 0) { memset(buf, 0, n); return; }
    for (u32 i = 0; i < n; i++) {
        int kind = kind0 == 3 ? (int)(((s->pos + i) >> 16) % 3) : kind0;   /* mix: 64 KiB blocks */
        if (kind == 0) { buf[i] = 0; continue; }
        if (kind == 1 || !s->wp || !*s->wp) {
            s->x ^= s->x << 13; s->x ^= s->x >> 7; s->x ^= s->x << 17;
            if (kind == 1) { buf[i] = (u8)(s->x >> 24); continue; }
            s->wp = k_words[(s->x >> 20) % (sizeof k_words / sizeof *k_words)];
        }
        buf[i] = (u8)*s->wp++;
    }
}

static int s_read(gz_wsrc *w, u8 *buf, u32 cap, u32 *got)
{
    src *s = (src *)w;
    item_info *ii = s->ii;
    *got = 0;
    if (ii->type == T_FILE) {
        size_t r = fread(buf, 1, cap, s->f);
        *got = (u32)r;
        return ferror(s->f) ? GZ_E_IO : GZ_OK;
    }
    u64 left = ii->actual - s->pos;
    if (!left) return ii->fail == 2 ? GZ_E_IO : GZ_OK;
    u32 n = left < cap ? (u32)left : cap;
    gen(s, buf, n);
    s->crc = crc_upd(s->crc, buf, n);
    s->pos += n;
    *got = n;
    return GZ_OK;
}

static int g_cancel_set;
static volatile long g_cancel;
static u64 g_cancel_at;
static int g_abort;
static u64 g_calls, g_last, g_last_total;
static int g_mono = 1;

static int open_item(void *user, const gz_witem *it, gz_wsrc **out)
{
    (void)user;
    item_info *ii = (item_info *)it->user;
    if (ii->type == T_FAULT && ii->fail == 1) return GZ_E_IO;
    src *s = (src *)calloc(1, sizeof *s);
    s->w.read = s_read;
    s->ii = ii;
    s->x = 0x9E3779B97F4A7C15ull ^ ii->seed;
    if (ii->type == T_FILE) {
        s->f = fopen(ii->path, "rb");
        if (!s->f) { free(s); return GZ_E_IO; }
    }
    *out = &s->w;
    return GZ_OK;
}

static void close_item(void *user, const gz_witem *it, gz_wsrc *w)
{
    (void)user;
    src *s = (src *)w;
    item_info *ii = (item_info *)it->user;
    if (s->f) fclose(s->f);
    if (ii->type != T_FILE && s->pos == ii->actual) {   /* read to the end: the content stored */
        ii->crc = s->crc;
        ii->made = s->pos;
    }
    free(s);
}

static int on_error(void *user, const gz_witem *it, int err)
{
    (void)user;
    char nm[4096];
    int k = gz_utf16_to_utf8(it->name, gz_wcslen(it->name) < 1300 ? gz_wcslen(it->name) : 1300, (u8 *)nm);
    nm[k] = 0;
    printf("ERR %d %s\n", err, nm);
    return g_abort ? err : GZ_OK;
}

static void progress(void *user, u64 done, u64 total)
{
    (void)user;
    g_calls++;
    if (done < g_last || total < done) g_mono = 0;
    g_last = done;
    g_last_total = total;
    if (g_cancel_set && done >= g_cancel_at) g_cancel = 1;
}

typedef struct { gz_sink k; FILE *f; } fsink;
static int k_write(gz_sink *k, const void *p, size_t n)
{
    return fwrite(p, 1, n, ((fsink *)k)->f) == n ? GZ_OK : GZ_E_IO;
}
static int k_write_at(gz_sink *k, u64 off, const void *p, size_t n)
{
    FILE *f = ((fsink *)k)->f;
    off_t cur = ftello(f);
    if (fseeko(f, (off_t)off, SEEK_SET)) return GZ_E_IO;
    int ok = fwrite(p, 1, n, f) == n;
    fseeko(f, cur, SEEK_SET);
    return ok ? GZ_OK : GZ_E_IO;
}

static char *field(char **p)
{
    char *s = *p, *t = s;
    if (!s) return (char *)"";
    while (*t && *t != '\t' && *t != '\n') t++;
    if (*t == '\t') { *t = 0; *p = t + 1; }
    else { *t = 0; *p = 0; }
    return s;
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    gz_cpu_detect();
    gz_crc32_init();
    gz_aes_init();
    gz_dispatch_init(-1);
    crc_init();
    FILE *mf = fopen(argv[1], "r");
    if (!mf) { perror(argv[1]); return 2; }
    gz_wopts o;
    memset(&o, 0, sizeof o);
    o.format = GZ_WF_7Z;
    o.level = 5;
    o.solid = 1;
    int nowa = 0;
    u32 n = 0, cap = 16;
    gz_witem *it = (gz_witem *)calloc(cap, sizeof *it);
    static char line[1 << 16];
    while (fgets(line, sizeof line, mf)) {
        char *p = line;
        char *t = field(&p);
        if (!*t || *t == '#') continue;
        if (!strcmp(t, "opt")) {
            char *k = field(&p), *v = field(&p);
            if (!strcmp(k, "level")) o.level = atoi(v);
            else if (!strcmp(k, "method")) o.method = atoi(v);
            else if (!strcmp(k, "solid")) o.solid = atoi(v);
            else if (!strcmp(k, "password")) { o.password = gz_posix_wide(v); o.encryption = GZ_WE_AES256; }
            else if (!strcmp(k, "encryption")) o.encryption = atoi(v);
            else if (!strcmp(k, "encnames")) o.encrypt_names = atoi(v);
            else if (!strcmp(k, "dict")) o.dict_size = (u32)strtoul(v, 0, 0);
            else if (!strcmp(k, "nowriteat")) nowa = atoi(v);
            else if (!strcmp(k, "cancel_at")) { g_cancel_set = 1; g_cancel_at = strtoull(v, 0, 0); }
            else if (!strcmp(k, "onerror")) g_abort = !strcmp(v, "abort");
            continue;
        }
        if (n == cap) { cap *= 2; it = (gz_witem *)realloc(it, cap * sizeof *it); }
        gz_witem *w = &it[n++];
        memset(w, 0, sizeof *w);
        item_info *ii = (item_info *)calloc(1, sizeof *ii);
        w->user = ii;
        w->name = gz_posix_wide(field(&p));
        if (!strcmp(t, "f")) {
            ii->type = T_FILE;
            ii->path = strdup(field(&p));
            w->unix_mode = (u32)strtoul(field(&p), 0, 8);
            w->attr = (u32)strtoul(field(&p), 0, 16);
            w->mtime = strtoull(field(&p), 0, 10);
            w->ctime = strtoull(field(&p), 0, 10);
            w->atime = strtoull(field(&p), 0, 10);
            FILE *f = fopen(ii->path, "rb");
            if (f) { fseeko(f, 0, SEEK_END); w->size = (u64)ftello(f); fclose(f); }
        } else if (!strcmp(t, "d")) {
            w->is_dir = 1;
            w->unix_mode = (u32)strtoul(field(&p), 0, 8);
            w->attr = (u32)strtoul(field(&p), 0, 16);
            w->mtime = strtoull(field(&p), 0, 10);
        } else if (!strcmp(t, "l")) {
            w->is_link = 1;
            w->link_target = gz_posix_wide(field(&p));
            w->unix_mode = (u32)strtoul(field(&p), 0, 8);
            w->mtime = strtoull(field(&p), 0, 10);
            w->attr = 0x20;
        } else if (!strcmp(t, "g")) {
            ii->type = T_GEN;
            w->size = ii->actual = strtoull(field(&p), 0, 10);
            ii->seed = (u32)strtoul(field(&p), 0, 10);
            char *k = field(&p);
            ii->kind = !strcmp(k, "zero") ? 0 : !strcmp(k, "rand") ? 1 : !strcmp(k, "text") ? 2 : 3;
            w->unix_mode = (u32)strtoul(field(&p), 0, 8);
            w->attr = 0x20;
        } else if (!strcmp(t, "x")) {
            ii->type = T_FAULT;
            w->size = strtoull(field(&p), 0, 10);
            ii->actual = strtoull(field(&p), 0, 10);
            char *fl = field(&p);
            ii->fail = !strcmp(fl, "open") ? 1 : !strcmp(fl, "read") ? 2 : 0;
            ii->seed = (u32)strtoul(field(&p), 0, 10);
            ii->kind = 2;
            w->attr = 0x20;
        } else {
            fprintf(stderr, "bad line %s\n", t);
            return 2;
        }
    }
    fclose(mf);
    o.open_item = open_item;
    o.close_item = close_item;
    o.on_error = on_error;
    o.progress = progress;
    o.cancel = &g_cancel;
    FILE *f = fopen(argv[2], "w+b");
    if (!f) { perror(argv[2]); return 2; }
    fsink k = { { k_write, nowa ? 0 : k_write_at, 0, 0 }, f };
    int r = gz_write_archive(&o, it, n, &k.k, 0);
    fclose(f);
    for (u32 i = 0; i < n; i++) {
        item_info *ii = (item_info *)it[i].user;
        if (ii->type == T_FILE || it[i].is_dir || it[i].is_link) continue;
        char nm[8192];
        int kk = gz_utf16_to_utf8(it[i].name, gz_wcslen(it[i].name) < 2700 ? gz_wcslen(it[i].name) : 2700, (u8 *)nm);
        nm[kk] = 0;
        printf("CRC %08x %llu %s\n", ii->crc, (unsigned long long)ii->made, nm);
    }
    for (u32 i = 0; i < n; i++) {
        item_info *ii = (item_info *)it[i].user;
        free(ii->path);
        free(ii);
        free((void *)it[i].name);
        free((void *)it[i].link_target);
    }
    free(it);
    free((void *)o.password);
    printf("PROGRESS %llu %d %llu %llu\n", (unsigned long long)g_calls, g_mono, (unsigned long long)g_last,
           (unsigned long long)g_last_total);
    printf("RESULT %d\n", r);
    return 0;
}
