/*
 * libFuzzer harness: every registered format, open + list + extract all entries.
 *
 *   make fuzz                      -> build/fuzz/fuzz_arc (clang, ASan + UBSan + libFuzzer)
 *   build/fuzz/fuzz_arc -max_len=1048576 -timeout=20 -rss_limit_mb=3072 CORPUS_DIR SEED_DIRS...
 *
 * Environment:
 *   GZ_FUZZ_FORMAT=name   only try one format (gz_format.name, case-insensitive), e.g. "7z"
 *   GZ_FUZZ_PASSWORD=pw   password used for encrypted headers/entries (default "password")
 *
 * Output is discarded and capped (64 MiB per input) so decompression bombs stay cheap.
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "plat_posix.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define OUT_CAP (64u << 20)

typedef struct { gz_out o; u64 total; } null_out;

static int n_open(gz_out *o, u32 idx) { (void)o; (void)idx; return GZ_OK; }
static int n_write(gz_out *o, const u8 *p, size_t n)
{
    null_out *x = (null_out *)o;
    (void)p;
    x->total += n;
    return x->total > OUT_CAP ? GZ_E_LIMIT : GZ_OK;
}
static int n_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; (void)st; return GZ_OK; }

static gzch g_pw[64];
static int g_ready;

static int ask_pw(void *user, gzch *buf, u32 cap, int retry)
{
    (void)user;
    if (retry) return GZ_E_CANCEL;
    u32 i = 0;
    for (; g_pw[i] && i + 1 < cap; i++) buf[i] = g_pw[i];
    buf[i] = 0;
    return GZ_OK;
}

static int no_volume(void *user, const gzch *name, gz_src **out)
{
    (void)user; (void)name; (void)out;
    return GZ_E_VOLUME;
}

/* restrict probing to one format when GZ_FUZZ_FORMAT is set */
static const gz_format *g_only;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
    const char *pw = getenv("GZ_FUZZ_PASSWORD");
    if (!pw) pw = "password";
    u32 i = 0;
    for (; pw[i] && i + 1 < GZ_COUNTOF(g_pw); i++) g_pw[i] = (u8)pw[i];
    g_pw[i] = 0;
    const char *only = getenv("GZ_FUZZ_FORMAT");
    if (only)
        for (int k = 0; gz_formats[k]; k++)
            if (!strcasecmp(gz_formats[k]->name, only)) g_only = gz_formats[k];
    g_ready = 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!g_ready) LLVMFuzzerInitialize(0, 0);
    gz_src *src = gz_src_mem(data, size, 0);
    if (!src) return 0;
    gz_ctx *c = gz_ctx_new();
    gz_open_opts o;
    memset(&o, 0, sizeof o);
    o.file_name = u"fuzz.bin";
    o.ask_password = ask_pw;
    o.open_volume = no_volume;
    gz_archive *a = 0;
    int r;
    if (g_only) {
        /* open with exactly one format: mimic the core's open path for it */
        r = g_only->probe && g_only->probe(src, data, size < 65536 ? (u32)size : 65536) ? 0 : GZ_E_FORMAT;
        if (!r) r = gz_arc_open(&a, src, &o, c);
        if (!r && a->fmt != g_only) { gz_arc_close(a); a = 0; r = GZ_E_FORMAT; }
    } else {
        r = gz_arc_open(&a, src, &o, c);
    }
    if (!r && a) {
        c->password = g_pw;
        null_out no = { { n_open, n_write, n_close, 0 }, 0 };
        gzch mbuf[96];
        for (u32 i = 0; i < a->n; i++) gz_arc_method(a, &a->e[i], mbuf, 96);
        if (a->solid) {
            u8 *sel = (u8 *)malloc(a->n + 1);
            if (sel) {
                memset(sel, 1, a->n + 1);
                gz_arc_extract_solid(a, src, sel, &no.o, c);
                free(sel);
            }
        } else {
            for (u32 i = 0; i < a->n && no.total <= OUT_CAP; i++) {
                gz_arc_check_password(a, src, i, c);
                gz_arc_extract(a, src, i, &no.o, c);
            }
        }
        /* nested views of the first few entries */
        for (u32 i = 0; i < a->n && i < 4; i++) {
            gz_src *v = gz_arc_view(a, src, i, c);
            if (v) {
                u8 tmp[512];
                u32 got;
                if (v->size) v->read_at(v, v->size > 512 ? v->size / 2 : 0, tmp, sizeof tmp, &got);
                gz_src_free(v);
            }
        }
        gz_arc_set_codepage(a, 949);
        gz_arc_close(a);
    }
    gz_ctx_free(c);
    gz_src_free(src);
    return 0;
}
