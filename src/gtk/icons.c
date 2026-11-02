/*
 * 고깃ZIP GTK - icons and style
 *
 * res/assets.bin (the Windows UI's icon atlas: premultiplied BGRA images,
 * raw Deflate, see tools/gen_assets.py) is linked into the binary and unpacked
 * with our own inflate engine. Premultiplied BGRA is exactly cairo's ARGB32
 * layout on little-endian machines, so the pixels are used as they are.
 */
#include "app.h"

/* the atlas, embedded at build time (path relative to the repository root) */
#if defined(__APPLE__)
#  define GZ_SYM(x) "_" #x
#  define GZ_RODATA ".const_data"
#else
#  define GZ_SYM(x) #x
#  define GZ_RODATA ".section .rodata"
#endif
__asm__(GZ_RODATA "\n"
        ".balign 16\n"
        ".globl " GZ_SYM(gz_assets_bin) "\n"
        GZ_SYM(gz_assets_bin) ":\n"
        ".incbin \"res/assets.bin\"\n"
        ".globl " GZ_SYM(gz_assets_end) "\n"
        GZ_SYM(gz_assets_end) ":\n"
        ".byte 0\n"
        ".text\n");
extern const u8 gz_assets_bin[], gz_assets_end[];

typedef struct { u16 id, size; u32 off; } asset_rec;
static asset_rec *s_rec;
static u32 s_nrec;
static u8 *s_pix;
static u32 s_raw;

typedef struct { const u8 *in; u32 in_n, in_pos; u8 *out; u32 out_cap, out_n; } mem_io;

static int m_read(void *c, u8 *buf, u32 cap, u32 *got)
{
    mem_io *m = (mem_io *)c;
    u32 n = m->in_n - m->in_pos;
    if (n > cap) n = cap;
    __builtin_memcpy(buf, m->in + m->in_pos, n);
    m->in_pos += n;
    *got = n;
    return GZ_OK;
}

static int m_write(void *c, const u8 *p, size_t n)
{
    mem_io *m = (mem_io *)c;
    if (n > m->out_cap - m->out_n) return GZ_E_DATA;
    __builtin_memcpy(m->out + m->out_n, p, n);
    m->out_n += (u32)n;
    return GZ_OK;
}

/* rendered icons, kept for the life of the process (ids x sizes in use: a few dozen) */
typedef struct { int id, size; cairo_surface_t *s; } cache_ent;
static GArray *s_cache;

void icons_init(void)
{
    const u8 *d = gz_assets_bin;
    size_t sz = (size_t)(gz_assets_end - gz_assets_bin);
    if (s_pix || sz < 16 || rd32(d) != 0x31415a47u /* "GZA1" */) return;
    u32 count = rd32(d + 4), raw = rd32(d + 8), comp = rd32(d + 12);
    if (count > 4096 || raw > (64u << 20) || 16 + (u64)count * 8 + comp > sz) return;
    asset_rec *rec = g_new0(asset_rec, count);
    for (u32 i = 0; i < count; i++) {
        const u8 *e = d + 16 + i * 8;
        rec[i].id = rd16(e);
        rec[i].size = rd16(e + 2);
        rec[i].off = rd32(e + 4);
        if (rec[i].size == 0 || rec[i].size > 1024 || (u64)rec[i].off + 4ull * rec[i].size * rec[i].size > raw)
            rec[i].size = 0;                     /* damaged record: never used */
    }
    u8 *pix = g_malloc(raw + 16);
    gz_inflater *z = gz_inflater_new();
    mem_io m = { d + 16 + count * 8, comp, 0, pix, raw, 0 };
    gz_stream_io io = { m_read, m_write, &m };
    if (z && gz_inflate_run(z, &io, 0) == GZ_OK && m.out_n == raw) {
        s_rec = rec;
        s_nrec = count;
        s_pix = pix;
        s_raw = raw;
    } else {
        g_free(rec);
        g_free(pix);
    }
    gz_inflater_free(z);
}

/* stored image of icon id: smallest size >= want, else the largest */
static const asset_rec *find_rec(int id, int want)
{
    const asset_rec *ge = NULL, *big = NULL;
    for (u32 i = 0; i < s_nrec; i++) {
        const asset_rec *r = &s_rec[i];
        if (r->id != id || !r->size) continue;
        if (r->size >= want && (!ge || r->size < ge->size)) ge = r;
        if (!big || r->size > big->size) big = r;
    }
    return ge ? ge : big;
}

static cairo_surface_t *master(const asset_rec *r)
{
    int stride = cairo_format_stride_for_width(CAIRO_FORMAT_ARGB32, r->size);
    cairo_surface_t *s = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, r->size, r->size);
    if (cairo_surface_status(s) != CAIRO_STATUS_SUCCESS) return s;
    cairo_surface_flush(s);
    u8 *dst = cairo_image_surface_get_data(s);
    const u8 *src = s_pix + r->off;
    for (int y = 0; y < r->size; y++)
        __builtin_memcpy(dst + (size_t)y * stride, src + (size_t)y * r->size * 4, (size_t)r->size * 4);
    cairo_surface_mark_dirty(s);
    return s;
}

static void paint_scaled(cairo_t *cr, cairo_surface_t *src, double x, double y, double size)
{
    int w = cairo_image_surface_get_width(src);
    if (w <= 0) return;
    cairo_save(cr);
    cairo_translate(cr, x, y);
    cairo_scale(cr, size / w, size / w);
    cairo_set_source_surface(cr, src, 0, 0);
    cairo_pattern_set_filter(cairo_get_source(cr), CAIRO_FILTER_BEST);
    cairo_paint(cr);
    cairo_restore(cr);
}

/* "New archive": the logo with a green plus badge */
static void draw_new(cairo_t *cr, int size)
{
    const asset_rec *r = find_rec(IC_LOGO, size);
    if (r) {
        cairo_surface_t *m = master(r);
        paint_scaled(cr, m, 0, 0, size * 0.86);
        cairo_surface_destroy(m);
    }
    double rad = size * 0.24, cx = size - rad - size * 0.01, cy = size - rad - size * 0.01;
    cairo_arc(cr, cx, cy, rad + size * 0.04, 0, 2 * G_PI);
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_fill(cr);
    cairo_arc(cr, cx, cy, rad, 0, 2 * G_PI);
    cairo_set_source_rgb(cr, 47 / 255.0, 179 / 255.0, 107 / 255.0);
    cairo_fill(cr);
    double a = rad * 0.55, t = rad * 0.32;
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_rectangle(cr, cx - a, cy - t / 2, 2 * a, t);
    cairo_rectangle(cr, cx - t / 2, cy - a, t, 2 * a);
    cairo_fill(cr);
}

cairo_surface_t *icon_surface(int id, int size)
{
    if (size < 8) size = 8;
    if (size > 512) size = 512;
    if (!s_cache) s_cache = g_array_new(FALSE, FALSE, sizeof(cache_ent));
    for (guint i = 0; i < s_cache->len; i++) {
        cache_ent *c = &g_array_index(s_cache, cache_ent, i);
        if (c->id == id && c->size == size) return c->s;
    }
    cairo_surface_t *s = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, size, size);
    cairo_t *cr = cairo_create(s);
    if (id == IC_NEW) {
        draw_new(cr, size);
    } else {
        const asset_rec *r = s_pix ? find_rec(id, size) : NULL;
        if (r) {
            cairo_surface_t *m = master(r);
            paint_scaled(cr, m, 0, 0, size);
            cairo_surface_destroy(m);
        }
    }
    cairo_destroy(cr);
    cache_ent c = { id, size, s };
    g_array_append_val(s_cache, c);
    return s;
}

GtkWidget *icon_image(int id, int size)
{
    return gtk_image_new_from_surface(icon_surface(id, size));
}

GdkPixbuf *icon_pixbuf(int id, int size)
{
    return gdk_pixbuf_get_from_surface(icon_surface(id, size), 0, 0, size, size);
}

/* ---------------- CSS ---------------- */

static const char k_css[] =
    "@define-color gz_accent #e5484d;\n"
    "@define-color gz_accent_hot #f05c60;\n"
    ".gz-toolbar { padding: 2px 6px; border-bottom: 1px solid alpha(@borders, 0.6); }\n"
    ".gz-toolbar toolbutton > button { padding: 2px 6px; }\n"
    ".gz-toolbar toolbutton label { font-size: 0.92em; }\n"
    ".gz-pathbar { padding: 4px 6px; border-bottom: 1px solid alpha(@borders, 0.6); }\n"
    ".gz-crumbs { border: 1px solid alpha(@borders, 0.8); border-radius: 5px; background: @theme_base_color; padding: 0 4px; }\n"
    ".gz-crumbs button { padding: 1px 6px; min-height: 22px; }\n"
    ".gz-crumbs .gz-sep { color: alpha(@theme_fg_color, 0.45); }\n"
    ".gz-crumb-last { font-weight: bold; }\n"
    ".gz-status { padding: 3px 10px; border-top: 1px solid alpha(@borders, 0.6); }\n"
    ".gz-dim { color: alpha(@theme_fg_color, 0.6); }\n"
    ".gz-faint { color: alpha(@theme_fg_color, 0.45); font-size: 0.9em; }\n"
    ".gz-welcome { background: mix(@theme_bg_color, @theme_base_color, 0.6); }\n"
    ".gz-title { color: @gz_accent; font-size: 22pt; }\n"
    ".gz-dropzone { border: 1px solid #e8cdcf; border-radius: 14px; background: @theme_base_color; padding: 18px 24px 22px 24px; }\n"
    ".gz-dropzone.gz-drag { border: 2px dashed @gz_accent; background: mix(@theme_base_color, @gz_accent, 0.06); }\n"
    ".gz-dz-title { font-size: 1.25em; }\n"
    "button.gz-accent { background-image: none; background-color: @gz_accent; color: #ffffff; border-color: #c8323a; font-weight: bold; }\n"
    "button.gz-accent:hover { background-color: @gz_accent_hot; }\n"
    "button.gz-accent:disabled { background-color: alpha(@gz_accent, 0.45); }\n"
    "button.gz-accent label { color: #ffffff; }\n"
    "button.gz-big { min-height: 34px; min-width: 150px; }\n"
    ".gz-recent { padding: 2px 6px; }\n"
    ".gz-dlg-head { padding: 14px 18px 8px 18px; }\n"
    ".gz-dialog .dialog-action-box { padding: 4px 12px 12px 12px; }\n"
    ".gz-dialog .dialog-action-area button { min-width: 88px; }\n"
    ".gz-dlg-title { font-size: 1.3em; }\n"
    ".gz-dlg-body { padding: 4px 18px 14px 18px; }\n"
    ".gz-dlg-foot { padding: 10px 14px; border-top: 1px solid alpha(@borders, 0.6); background: mix(@theme_bg_color, @theme_base_color, 0.4); }\n"
    ".gz-error-text { color: @error_color; }\n"
    "progressbar.gz-bar trough { min-height: 12px; border-radius: 6px; }\n"
    "progressbar.gz-bar progress { min-height: 12px; border-radius: 6px; background-image: none; background-color: @gz_accent; border-color: @gz_accent; }\n";

void css_init(void)
{
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_data(p, k_css, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), GTK_STYLE_PROVIDER(p),
                                              GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}
