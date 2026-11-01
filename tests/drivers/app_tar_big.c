/*
 * TAR writer limits: an 8 GiB + 513 byte member (pax "size" + base-256), times before
 * 1970 and after 2242 (pax "mtime"), a 300-byte link target (pax "linkpath").
 * The huge member's zero data becomes a hole in the output file (sparse), so the
 * test needs no disk space.   usage: app_tar_big out.tar
 */
#include "gz_write.h"
#include "tar_write.h"
#include "cpu.h"
#include "crc32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct { gz_wsrc w; u64 left; const char *data; size_t n, pos; } fake;

static int fk_read(gz_wsrc *w, u8 *buf, u32 cap, u32 *got)
{
    fake *f = (fake *)w;
    if (f->data) {
        size_t n = f->n - f->pos < cap ? f->n - f->pos : cap;
        memcpy(buf, f->data + f->pos, n);
        f->pos += n;
        *got = (u32)n;
        return GZ_OK;
    }
    u32 n = f->left < cap ? (u32)f->left : cap;
    memset(buf, 0, n < 4096 ? n : 4096);         /* the writer's buffer only ever holds zeros here */
    if (n > 4096) memset(buf + n - 4096, 0, 4096);
    f->left -= n;
    *got = n;
    return GZ_OK;
}

static int open_item(void *user, const gz_witem *it, gz_wsrc **src)
{
    (void)user;
    fake *f = (fake *)calloc(1, sizeof *f);
    f->w.read = fk_read;
    if (it->user) { f->data = (const char *)it->user; f->n = strlen(f->data); }
    else f->left = it->size;
    *src = &f->w;
    return GZ_OK;
}

static void close_item(void *user, const gz_witem *it, gz_wsrc *src) { (void)user; (void)it; free(src); }

typedef struct { gz_sink k; int fd; u64 pos; } sparse_sink;

static int sk_write(gz_sink *k, const void *p, size_t n)
{
    sparse_sink *s = (sparse_sink *)k;
    const u8 *b = (const u8 *)p;
    int zero = n >= 65536;
    for (size_t i = 0; zero && i < 4096; i++) if (b[i] || b[n - 1 - i]) zero = 0;
    if (zero) {
        if (lseek(s->fd, (off_t)n, SEEK_CUR) < 0) return GZ_E_IO;
    } else if (write(s->fd, p, n) != (ssize_t)n) {
        return GZ_E_IO;
    }
    s->pos += n;
    return GZ_OK;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    gz_cpu_detect();
    gz_crc32_init();
    gz_dispatch_init(-1);
    gz_witem it[5];
    memset(it, 0, sizeof it);
    static gzch t300[301];
    for (int i = 0; i < 300; i++) t300[i] = 't';
    it[0].name = u"old.txt";    it[0].size = 3;  it[0].user = (void *)"old";
    it[0].mtime = gz_unix_to_filetime(-31536000);
    it[1].name = u"future.txt"; it[1].size = 3;  it[1].user = (void *)"new";
    it[1].mtime = gz_unix_to_filetime((i64)1 << 34);
    it[2].name = u"huge.bin";   it[2].size = ((u64)8 << 30) + 513;
    it[2].mtime = gz_unix_to_filetime(1600000000);
    it[3].name = u"tail.txt";   it[3].size = 17; it[3].user = (void *)"after the big one";
    it[3].mtime = gz_unix_to_filetime(1600000000);
    it[4].name = u"link";       it[4].is_link = 1; it[4].link_target = t300;
    it[4].mtime = gz_unix_to_filetime(1600000000);
    int fd = open(argv[1], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) { perror(argv[1]); return 1; }
    sparse_sink k;
    memset(&k, 0, sizeof k);
    k.k.write = sk_write;
    k.fd = fd;
    gz_wopts o;
    memset(&o, 0, sizeof o);
    o.format = GZ_WF_TAR;
    o.open_item = open_item;
    o.close_item = close_item;
    int r = gz_write_archive(&o, it, 5, &k.k, 0);
    if (!r && ftruncate(fd, (off_t)k.pos)) r = GZ_E_IO;
    close(fd);
    printf("CREATE %d size=%llu\n", r, (unsigned long long)k.pos);
    return r ? 1 : 0;
}
