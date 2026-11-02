/*
 * 고깃ZIP macOS - icons
 *
 * Contents/Resources/assets.bin is the Windows UI's icon atlas (res/assets.bin:
 * premultiplied BGRA images in 16..64 px, raw Deflate, see tools/gen_assets.py),
 * unpacked once with our own inflate engine. Every stored size of an icon
 * becomes one representation of an NSImage, so AppKit picks the sharpest one for
 * the point size and the screen's backing scale. Template variants (alpha only)
 * follow the system appearance (dark mode); SF Symbols would need macOS 11.
 */
#import "app.h"

typedef struct { u16 id, size; u32 off; } asset_rec;
static asset_rec *s_rec;
static u32 s_nrec;
static u8 *s_pix;
static NSMutableDictionary<NSString *, NSImage *> *s_cache;

typedef struct { const u8 *in; u32 in_n, in_pos; u8 *out; u32 out_cap, out_n; } mem_io;

static int m_read(void *c, u8 *buf, u32 cap, u32 *got)
{
    mem_io *m = (mem_io *)c;
    u32 n = m->in_n - m->in_pos;
    if (n > cap) n = cap;
    memcpy(buf, m->in + m->in_pos, n);
    m->in_pos += n;
    *got = n;
    return GZ_OK;
}

static int m_write(void *c, const u8 *p, size_t n)
{
    mem_io *m = (mem_io *)c;
    if (n > m->out_cap - m->out_n) return GZ_E_DATA;
    memcpy(m->out + m->out_n, p, n);
    m->out_n += (u32)n;
    return GZ_OK;
}

static NSData *atlasData(void)
{
    NSString *p = [[NSBundle mainBundle] pathForResource:@"assets" ofType:@"bin"];
    if (!p) {      /* development runs outside the bundle: the repository copy */
        NSString *exe = [NSBundle mainBundle].executablePath.stringByDeletingLastPathComponent;
        for (NSString *rel in @[ @"../Resources/assets.bin", @"../../res/assets.bin", @"../res/assets.bin" ]) {
            NSString *q = [exe stringByAppendingPathComponent:rel].stringByStandardizingPath;
            if (pathExists(q)) { p = q; break; }
        }
    }
    return p ? [NSData dataWithContentsOfFile:p] : nil;
}

void iconsInit(void)
{
    if (s_pix) return;
    s_cache = [NSMutableDictionary dictionary];
    NSData *data = atlasData();
    const u8 *d = (const u8 *)data.bytes;
    size_t sz = data.length;
    if (!d || sz < 16 || rd32(d) != 0x31415a47u /* "GZA1" */) return;
    u32 count = rd32(d + 4), raw = rd32(d + 8), comp = rd32(d + 12);
    if (count > 4096 || raw > (64u << 20) || 16 + (u64)count * 8 + comp > sz) return;
    asset_rec *rec = (asset_rec *)calloc(count ? count : 1, sizeof *rec);
    u8 *pix = (u8 *)malloc(raw + 16);
    if (!rec || !pix) { free(rec); free(pix); return; }
    for (u32 i = 0; i < count; i++) {
        const u8 *e = d + 16 + i * 8;
        rec[i].id = rd16(e);
        rec[i].size = rd16(e + 2);
        rec[i].off = rd32(e + 4);
        if (rec[i].size == 0 || rec[i].size > 1024 || (u64)rec[i].off + 4ull * rec[i].size * rec[i].size > raw)
            rec[i].size = 0;                     /* damaged record: never used */
    }
    gz_inflater *z = gz_inflater_new();
    mem_io m = { d + 16 + count * 8, comp, 0, pix, raw, 0 };
    gz_stream_io io = { m_read, m_write, &m };
    if (z && gz_inflate_run(z, &io, 0) == GZ_OK && m.out_n == raw) {
        s_rec = rec;
        s_nrec = count;
        s_pix = pix;
    } else {
        free(rec);
        free(pix);
    }
    gz_inflater_free(z);
}

static NSBitmapImageRep *repFor(const asset_rec *r, CGFloat pt)
{
    size_t n = (size_t)r->size * r->size * 4;
    NSData *px = [NSData dataWithBytes:s_pix + r->off length:n];
    CGDataProviderRef dp = CGDataProviderCreateWithCFData((__bridge CFDataRef)px);
    CGColorSpaceRef cs = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    /* premultiplied BGRA in memory = alpha first, 32-bit little endian */
    CGImageRef img = CGImageCreate(r->size, r->size, 8, 32, (size_t)r->size * 4, cs,
                                   (CGBitmapInfo)kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little, dp,
                                   NULL, false, kCGRenderingIntentDefault);
    CGColorSpaceRelease(cs);
    CGDataProviderRelease(dp);
    if (!img) return nil;
    NSBitmapImageRep *rep = [[NSBitmapImageRep alloc] initWithCGImage:img];
    CGImageRelease(img);
    rep.size = NSMakeSize(pt, pt);
    return rep;
}

static NSImage *atlasImage(int ident, CGFloat pt)
{
    NSImage *img = [[NSImage alloc] initWithSize:NSMakeSize(pt, pt)];
    for (u32 i = 0; i < s_nrec; i++) {
        const asset_rec *r = &s_rec[i];
        if (r->id != ident || !r->size) continue;
        NSBitmapImageRep *rep = repFor(r, pt);
        if (rep) [img addRepresentation:rep];
    }
    return img;
}

/* "New archive": the logo with a green plus badge (drawn at any resolution) */
static NSImage *newArchiveImage(CGFloat pt)
{
    NSImage *logo = atlasImage(IC_LOGO, pt);
    return [NSImage imageWithSize:NSMakeSize(pt, pt) flipped:NO drawingHandler:^BOOL(NSRect r) {
        CGFloat s = r.size.width, lw = s * 0.86;
        [logo drawInRect:NSMakeRect(0, s - lw, lw, lw) fromRect:NSZeroRect operation:NSCompositingOperationSourceOver
                fraction:1.0];
        CGFloat rad = s * 0.24, cx = s - rad - s * 0.01, cy = rad + s * 0.01;
        [[NSColor whiteColor] setFill];
        CGFloat ro = rad + s * 0.04;
        [[NSBezierPath bezierPathWithOvalInRect:NSMakeRect(cx - ro, cy - ro, 2 * ro, 2 * ro)] fill];
        [[NSColor colorWithSRGBRed:47 / 255.0 green:179 / 255.0 blue:107 / 255.0 alpha:1] setFill];
        [[NSBezierPath bezierPathWithOvalInRect:NSMakeRect(cx - rad, cy - rad, 2 * rad, 2 * rad)] fill];
        CGFloat a = rad * 0.55, t = rad * 0.32;
        [[NSColor whiteColor] setFill];
        NSRectFill(NSMakeRect(cx - a, cy - t / 2, 2 * a, t));
        NSRectFill(NSMakeRect(cx - t / 2, cy - a, t, 2 * a));
        return YES;
    }];
}

NSImage *gzIcon(int ident, CGFloat pt)
{
    if (!s_cache) iconsInit();
    NSString *key = [NSString stringWithFormat:@"%d/%g", ident, pt];
    NSImage *img = s_cache[key];
    if (img) return img;
    img = ident == IC_NEW ? newArchiveImage(pt) : atlasImage(ident, pt);
    s_cache[key] = img;
    return img;
}

NSImage *gzTemplateIcon(int ident, CGFloat pt)
{
    if (!s_cache) iconsInit();
    NSString *key = [NSString stringWithFormat:@"t%d/%g", ident, pt];
    NSImage *img = s_cache[key];
    if (img) return img;
    img = [gzIcon(ident, pt) copy];
    img.template = YES;
    s_cache[key] = img;
    return img;
}
