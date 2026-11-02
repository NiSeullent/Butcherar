#!/usr/bin/env python3
"""
고깃ZIP asset generator.

Renders every UI icon and the logo from simple vector shapes (8x supersampled,
Pillow), then writes:

  res/assets.bin        premultiplied BGRA icon atlas, raw-deflate compressed
                        (decoded at runtime by 고깃ZIP's own inflate engine)
  src/win/asset_ids.h   icon ids
  res/app.ico           application icon (16..256)
  res/doc.ico           archive document icon (file association)
  web/assets/*.png      logo images for the official web page

Only needed when the artwork changes; the outputs are committed.
"""
import io, os, struct, zlib, math
from PIL import Image, ImageDraw, ImageFilter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SS = 8  # supersampling factor

RED, RED_D, RED_L = (229, 72, 77), (196, 48, 56), (255, 138, 142)
AMBER, AMBER_D = (247, 186, 61), (226, 150, 28)
GREEN, GREEN_D = (47, 179, 107), (30, 140, 82)
BLUE, BLUE_D = (59, 130, 246), (37, 99, 235)
PURPLE, PURPLE_D = (139, 92, 246), (109, 63, 224)
SLATE, SLATE_D = (100, 116, 139), (71, 85, 105)
ORANGE, ORANGE_D = (251, 146, 60), (234, 108, 20)
WHITE = (255, 255, 255)
INK = (55, 65, 81)


class Canvas:
    """Drawing in a 32x32 design grid, rendered at size*SS."""

    def __init__(self, size, grid=32):
        self.size = size
        self.k = size * SS / grid
        self.img = Image.new("RGBA", (size * SS, size * SS), (0, 0, 0, 0))
        self.d = ImageDraw.Draw(self.img)

    def P(self, *xy):
        return [v * self.k for v in xy]

    def rrect(self, x0, y0, x1, y1, r, fill=None, outline=None, width=0):
        self.d.rounded_rectangle(self.P(x0, y0, x1, y1), radius=r * self.k, fill=rgba(fill),
                                 outline=rgba(outline), width=int(round(width * self.k)))

    def rect(self, x0, y0, x1, y1, fill):
        self.d.rectangle(self.P(x0, y0, x1, y1), fill=rgba(fill))

    def ellipse(self, x0, y0, x1, y1, fill=None, outline=None, width=0):
        self.d.ellipse(self.P(x0, y0, x1, y1), fill=rgba(fill), outline=rgba(outline),
                       width=int(round(width * self.k)))

    def poly(self, pts, fill):
        self.d.polygon([(x * self.k, y * self.k) for x, y in pts], fill=rgba(fill))

    def line(self, pts, fill, width, round_caps=True):
        p = [(x * self.k, y * self.k) for x, y in pts]
        w = width * self.k
        self.d.line(p, fill=rgba(fill), width=int(round(w)), joint="curve")
        if round_caps:
            for x, y in (p[0], p[-1]):
                self.d.ellipse((x - w / 2, y - w / 2, x + w / 2, y + w / 2), fill=rgba(fill))

    def arc(self, x0, y0, x1, y1, a0, a1, fill, width):
        self.d.arc(self.P(x0, y0, x1, y1), a0, a1, fill=rgba(fill), width=int(round(width * self.k)))

    def result(self):
        return self.img.resize((self.size, self.size), Image.LANCZOS)


def rgba(c):
    if c is None:
        return None
    return c if len(c) == 4 else c + (255,)


def gradient_fill(img, mask, top, bottom):
    """Fill mask area of img with a vertical gradient."""
    w, h = img.size
    grad = Image.new("RGBA", (1, h))
    for y in range(h):
        t = y / max(1, h - 1)
        grad.putpixel((0, y), tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3)) + (255,))
    grad = grad.resize((w, h))
    img.paste(grad, (0, 0), mask)


# ------------------------------------------------------------------ icons

def ic_open(c):
    c.rrect(3, 7, 15, 13, 2, AMBER_D)
    c.rrect(3, 9, 29, 26, 2.5, AMBER_D)
    c.poly([(5.5, 13), (30.5, 13), (28, 26), (3, 26)], AMBER)
    c.rrect(3, 12.5, 29, 26, 2.5, None)


def zipper(c, x, y0, y1, w=1.6, col=WHITE):
    y = y0
    i = 0
    while y < y1:
        off = -w if i % 2 == 0 else 0
        c.rrect(x + off, y, x + off + w, y + 1.2, 0.4, col)
        y += 1.8
        i += 1


def box(c, x0, y0, x1, y1, col, dark):
    c.rrect(x0, y0, x1, y1, 2.5, dark)
    c.rrect(x0, y0, x1, y1 - 1.6, 2.5, col)
    c.rrect(x0, y0, x1, y0 + 5, 2.5, dark)
    c.rect(x0, y0 + 3, x1, y0 + 5, dark)


def ic_extract(c):
    box(c, 3, 9, 23, 29, RED, RED_D)
    zipper(c, 13.8, 15, 27)
    # arrow out (up-right)
    c.line([(17, 15), (27.5, 4.5)], GREEN_D, 3.6)
    c.line([(17, 15), (27.5, 4.5)], GREEN, 2.4)
    c.poly([(29.8, 2.2), (29.8, 11), (21, 2.2)], GREEN)


def ic_extract_here(c):
    box(c, 4, 4, 28, 20, RED, RED_D)
    zipper(c, 16.8, 10, 18)
    # tray
    c.rrect(3, 22, 29, 30, 2.5, SLATE_D)
    c.rrect(6, 22, 26, 26, 1.5, (226, 232, 240))
    c.poly([(11, 19), (21, 19), (16, 25)], GREEN)
    c.rect(14, 14, 18, 20, GREEN)


def ic_test(c):
    pts = [(16, 2.5), (28, 7), (27, 17), (16, 29.5), (5, 17), (4, 7)]
    c.poly(pts, GREEN_D)
    c.poly([(16, 4.5), (26, 8.3), (25.2, 16.6), (16, 27), (6.8, 16.6), (6, 8.3)], GREEN)
    c.line([(10.5, 16), (14.5, 20), (22, 11.5)], WHITE, 3.0)


def ic_view(c):
    c.rrect(5, 2.5, 23, 29.5, 2.5, (203, 213, 225))
    c.rrect(6, 3.5, 22, 28.5, 1.8, WHITE)
    for i, y in enumerate((8, 11.5, 15)):
        c.rrect(9, y, 19 - (i == 2) * 4, y + 1.6, 0.8, (148, 163, 184))
    c.ellipse(13, 13, 25, 25, BLUE_D)
    c.ellipse(15, 15, 23, 23, (219, 234, 254))
    c.line([(23.5, 23.5), (28.5, 28.5)], BLUE_D, 3.6)


def ic_info(c):
    c.ellipse(3, 3, 29, 29, BLUE_D)
    c.ellipse(4, 4, 28, 27.4, BLUE)
    c.ellipse(14.2, 8.2, 17.8, 11.8, WHITE)
    c.rrect(14.4, 14, 17.6, 24, 1.2, WHITE)


def ic_codepage(c):
    c.rrect(3, 3, 29, 29, 6, PURPLE_D)
    c.rrect(3, 3, 29, 27.5, 6, PURPLE)
    # "가" glyph drawn with strokes
    c.line([(8, 9), (14.5, 9), (12.5, 21)], WHITE, 2.4)
    c.line([(19.5, 7.5), (19.5, 24)], WHITE, 2.4)
    c.line([(19.5, 15), (24.5, 15)], WHITE, 2.4)


def ic_settings(c):
    cx, cy = 16, 16
    pts = []
    for i in range(16):
        a = math.pi * 2 * i / 16
        r = 13.5 if i % 2 == 0 else 10.5
        a2 = a + (0.13 if i % 2 == 0 else -0.13)
        pts.append((cx + math.cos(a - 0.13) * r, cy + math.sin(a - 0.13) * r))
        pts.append((cx + math.cos(a2) * r, cy + math.sin(a2) * r))
    c.poly(pts, SLATE)
    c.ellipse(6, 6, 26, 26, SLATE)
    c.ellipse(11, 11, 21, 21, WHITE)
    c.ellipse(13.2, 13.2, 18.8, 18.8, SLATE_D)


def ic_up(c):
    c.line([(16, 26), (16, 8)], INK, 3.4)
    c.line([(8, 15), (16, 7), (24, 15)], INK, 3.4)


def ic_cpu(c):
    for i in range(4):
        x = 9.5 + i * 4.3
        c.rect(x, 2, x + 1.8, 30, (148, 163, 184))
        c.rect(2, x, 30, x + 1.8, (148, 163, 184))
    c.rrect(6, 6, 26, 26, 3, SLATE_D)
    c.rrect(10, 10, 22, 22, 1.5, RED)


def ic_lock(c):
    c.arc(9, 3, 23, 19, 180, 360, SLATE_D, 3.2)
    c.line([(10.6, 11), (10.6, 15)], SLATE_D, 3.2, round_caps=False)
    c.line([(21.4, 11), (21.4, 15)], SLATE_D, 3.2, round_caps=False)
    c.rrect(5, 14, 27, 30, 3.5, AMBER_D)
    c.rrect(5, 14, 27, 28.5, 3.5, AMBER)
    c.ellipse(14, 18.5, 18, 22.5, (120, 72, 10))
    c.rect(15.1, 21, 16.9, 25, (120, 72, 10))


def ic_warn(c):
    c.poly([(16, 3), (30.5, 28.5), (1.5, 28.5)], ORANGE_D)
    c.poly([(16, 5.8), (28.2, 27.2), (3.8, 27.2)], AMBER)
    c.rrect(14.6, 11, 17.4, 21, 1.3, (60, 40, 10))
    c.ellipse(14.4, 22.5, 17.6, 25.7, (60, 40, 10))


def ic_bench(c):
    c.ellipse(2, 4, 30, 32, ORANGE_D)
    c.ellipse(3, 5, 29, 31, ORANGE)
    c.ellipse(6, 8, 26, 28, WHITE)
    c.rect(2, 22, 30, 32, (0, 0, 0, 0))
    for i in range(7):
        a = math.radians(200 + i * 23.3)
        c.line([(16 + math.cos(a) * 8.5, 18 + math.sin(a) * 8.5),
                (16 + math.cos(a) * 6.8, 18 + math.sin(a) * 6.8)], SLATE, 1.2)
    a = math.radians(305)
    c.line([(16, 18), (16 + math.cos(a) * 8, 18 + math.sin(a) * 8)], RED_D, 2.4)
    c.ellipse(13.8, 15.8, 18.2, 20.2, INK)


def ic_folder(c):
    c.rrect(3, 7, 14, 12, 2, AMBER_D)
    c.rrect(3, 9, 29, 26, 2.5, AMBER)


def ic_check(c):
    c.ellipse(3, 3, 29, 29, GREEN)
    c.line([(10, 16.5), (14.5, 21), (22.5, 12)], WHITE, 3.2)


def ic_error(c):
    c.ellipse(3, 3, 29, 29, RED)
    c.line([(11, 11), (21, 21)], WHITE, 3.2)
    c.line([(21, 11), (11, 21)], WHITE, 3.2)


def ic_compress(c):
    # archive box with an arrow going in (mirror of ic_extract)
    box(c, 9, 9, 29, 29, RED, RED_D)
    zipper(c, 19.8, 15, 27)
    c.line([(3.5, 3.5), (12.5, 12.5)], BLUE_D, 3.6)
    c.line([(3.5, 3.5), (12.5, 12.5)], BLUE, 2.4)
    c.poly([(16, 16), (16, 7), (7, 16)], BLUE)


ICONS = [
    ("IC_OPEN", ic_open), ("IC_EXTRACT", ic_extract), ("IC_EXTRACT_HERE", ic_extract_here),
    ("IC_TEST", ic_test), ("IC_VIEW", ic_view), ("IC_INFO", ic_info),
    ("IC_CODEPAGE", ic_codepage), ("IC_SETTINGS", ic_settings), ("IC_UP", ic_up),
    ("IC_CPU", ic_cpu), ("IC_LOCK", ic_lock), ("IC_WARN", ic_warn), ("IC_BENCH", ic_bench),
    ("IC_FOLDER", ic_folder), ("IC_CHECK", ic_check), ("IC_ERROR", ic_error),
    ("IC_COMPRESS", ic_compress),
]
ICON_SIZES = [16, 24, 32, 48, 64]   # other sizes are box-filtered at runtime


# ------------------------------------------------------------------ logo

def logo(size, tile=True):
    """App logo: meat-red squircle with fat marbling and an opening zipper
    whose pull is a little bone."""
    S = size * SS
    k = S / 32.0
    clear = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    img = clear.copy()
    mask = Image.new("L", (S, S), 0)
    md = ImageDraw.Draw(mask)
    pad = 1.0 if tile else 0
    md.rounded_rectangle((pad * k, pad * k, (32 - pad) * k, (32 - pad) * k), radius=7.5 * k, fill=255)
    gradient_fill(img, mask, (255, 122, 112), (218, 44, 64))

    def clipped(layer):
        img.alpha_composite(Image.composite(layer, clear, mask))

    # fat marbling: smooth sine streaks
    marb = clear.copy()
    m = ImageDraw.Draw(marb)
    for (x0, x1, y, amp, ph, w, a) in [(0, 11, 8.5, 1.1, 0.0, 1.5, 80), (21, 33, 22.5, 1.0, 1.4, 1.5, 80),
                                       (-1, 9, 25.5, 0.9, 2.2, 1.1, 60), (22, 33, 6.5, 0.8, 0.6, 1.1, 60)]:
        pts = []
        n = 40
        for i in range(n + 1):
            x = x0 + (x1 - x0) * i / n
            pts.append((x * k, (y + amp * math.sin(ph + i / n * math.pi * 1.6)) * k))
        m.line(pts, fill=(255, 255, 255, a), width=int(w * k), joint="curve")
    clipped(marb)

    z = clear.copy()
    d = ImageDraw.Draw(z)
    TAPE = (150, 20, 40, 255)
    TOOTH = (255, 255, 255, 255)
    # closed part (below the slider)
    d.rounded_rectangle((13.3 * k, 12 * k, 18.7 * k, 33 * k), radius=1.2 * k, fill=TAPE)
    y, i = 15.6, 0
    while y < 31.5:
        x = 13.9 if i % 2 == 0 else 15.8
        d.rounded_rectangle((x * k, y * k, (x + 2.3) * k, (y + 1.25) * k), radius=0.5 * k, fill=TOOTH)
        y += 1.9
        i += 1
    # open part (above the slider): two diverging rows
    for side in (-1, 1):
        x_top, x_bot = 16 + side * 8.5, 16 + side * 1.6
        d.line([(x_bot * k, 12 * k), (x_top * k, -1 * k)], fill=TAPE, width=int(3.0 * k))
        for j in range(6):
            t = (j + 0.6) / 6.0
            cx = x_bot + (x_top - x_bot) * t + side * 0.9
            cy = 12 - 13 * t
            d.rounded_rectangle(((cx - 1.0) * k, (cy - 0.55) * k, (cx + 1.0) * k, (cy + 0.55) * k),
                                radius=0.45 * k, fill=TOOTH)
    # slider
    d.rounded_rectangle((12.4 * k, 9.6 * k, 19.6 * k, 15.0 * k), radius=1.8 * k, fill=(255, 255, 255, 255))
    d.rounded_rectangle((13.6 * k, 13.2 * k, 18.4 * k, 14.2 * k), radius=0.5 * k, fill=(240, 200, 200, 255))
    # bone pull
    BONE = (255, 246, 232, 255)
    BONE_S = (214, 170, 140, 255)
    for col, dx, dy in ((BONE_S, 0.25, 0.35), (BONE, 0, 0)):
        d.rounded_rectangle(((15.0 + dx) * k, (13.6 + dy) * k, (17.0 + dx) * k, (23.4 + dy) * k),
                            radius=0.9 * k, fill=col)
        for bx in (14.9, 17.1):
            d.ellipse(((bx - 1.75 + dx) * k, (22.0 + dy) * k, (bx + 1.75 + dx) * k, (25.5 + dy) * k), fill=col)
    clipped(z)

    # soft top highlight
    hl = clear.copy()
    ImageDraw.Draw(hl).ellipse((-8 * k, -16 * k, 24 * k, 11 * k), fill=(255, 255, 255, 34))
    clipped(hl)
    return img.resize((size, size), Image.LANCZOS)


def doc_icon(size):
    S = size * SS
    k = S / 32.0
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.polygon([(6 * k, 1.5 * k), (20 * k, 1.5 * k), (26.5 * k, 8 * k), (26.5 * k, 30.5 * k), (6 * k, 30.5 * k)],
              fill=(203, 213, 225, 255))
    d.polygon([(6.8 * k, 2.3 * k), (19.6 * k, 2.3 * k), (25.7 * k, 8.4 * k), (25.7 * k, 29.7 * k),
               (6.8 * k, 29.7 * k)], fill=(255, 255, 255, 255))
    d.polygon([(19.6 * k, 2.3 * k), (19.6 * k, 8.4 * k), (25.7 * k, 8.4 * k)], fill=(226, 232, 240, 255))
    lg = logo(size * 3 // 4 if size >= 24 else size, tile=True).resize((int(17 * k), int(17 * k)), Image.LANCZOS)
    img.alpha_composite(lg, (int(8 * k), int(11.5 * k)))
    return img.resize((size, size), Image.LANCZOS)


LOGO_SIZES = [48, 96, 192]


# ------------------------------------------------------------------ writers

def premul_bgra(im):
    out = bytearray()
    px = im.load()
    w, h = im.size
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            out += bytes(((b * a + 127) // 255, (g * a + 127) // 255, (r * a + 127) // 255, a))
    return bytes(out)


def write_ico(path, images):
    """images: list of PIL RGBA. <=64 stored as 32bpp BMP (works on Windows 2000), 256 as PNG."""
    entries, blobs = [], []
    for im in images:
        w, h = im.size
        if w >= 256:
            b = io.BytesIO()
            im.save(b, "PNG")
            data = b.getvalue()
        else:
            hdr = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, 0, 0, 0, 0, 0)
            px = im.load()
            xor = bytearray()
            for y in range(h - 1, -1, -1):
                for x in range(w):
                    r, g, b_, a = px[x, y]
                    xor += bytes((b_, g, r, a))
            stride = ((w + 31) // 32) * 4
            andm = bytearray()
            for y in range(h - 1, -1, -1):
                row = bytearray(stride)
                for x in range(w):
                    if px[x, y][3] < 128:
                        row[x // 8] |= 0x80 >> (x % 8)
                andm += row
            data = hdr + bytes(xor) + bytes(andm)
        entries.append((w, h, data))
    off = 6 + 16 * len(entries)
    out = struct.pack("<HHH", 0, 1, len(entries))
    for w, h, data in entries:
        out += struct.pack("<BBBBHHII", w & 255, h & 255, 0, 0, 1, 32, len(data), off)
        off += len(data)
    for _, _, data in entries:
        out += data
    open(path, "wb").write(out)


def main():
    os.makedirs(os.path.join(ROOT, "res"), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "web", "assets"), exist_ok=True)
    records = []      # (id, size, pixels)
    for idx, (name, fn) in enumerate(ICONS):
        for s in ICON_SIZES:
            c = Canvas(s)
            fn(c)
            records.append((idx, s, premul_bgra(c.result())))
    logo_id = len(ICONS)
    for s in LOGO_SIZES:
        records.append((logo_id, s, premul_bgra(logo(s))))

    blob = bytearray()
    table = bytearray()
    for i, s, px in records:
        table += struct.pack("<HHI", i, s, len(blob))
        blob += px
    comp = zlib.compressobj(9, zlib.DEFLATED, -15, 9)
    data = comp.compress(bytes(blob)) + comp.flush()
    with open(os.path.join(ROOT, "res", "assets.bin"), "wb") as f:
        f.write(b"GZA1" + struct.pack("<III", len(records), len(blob), len(data)) + table + data)
    print("assets.bin: %d images, %d KB raw -> %d KB" % (len(records), len(blob) // 1024, len(data) // 1024))

    with open(os.path.join(ROOT, "src", "win", "asset_ids.h"), "w") as f:
        f.write("/* generated by tools/gen_assets.py - do not edit */\n#ifndef GZ_ASSET_IDS_H\n#define GZ_ASSET_IDS_H\n")
        for idx, (name, _) in enumerate(ICONS):
            f.write("#define %-16s %d\n" % (name, idx))
        f.write("#define %-16s %d\n" % ("IC_LOGO", logo_id))
        f.write("#define IC_COUNT         %d\n#endif\n" % (logo_id + 1))

    write_ico(os.path.join(ROOT, "res", "app.ico"), [logo(s) for s in (16, 20, 24, 32, 40, 48, 64, 256)])
    write_ico(os.path.join(ROOT, "res", "doc.ico"), [doc_icon(s) for s in (16, 24, 32, 48, 256)])
    logo(512).save(os.path.join(ROOT, "web", "assets", "logo-512.png"))
    logo(192).save(os.path.join(ROOT, "web", "assets", "logo-192.png"))
    logo(32).save(os.path.join(ROOT, "web", "assets", "favicon-32.png"))
    # preview sheet for humans
    sheet = Image.new("RGBA", (40 * len(ICONS) + 20, 300), (255, 255, 255, 255))
    for idx, (name, fn) in enumerate(ICONS):
        for j, s in enumerate((16, 24, 32, 48)):
            c = Canvas(s)
            fn(c)
            sheet.alpha_composite(c.result(), (10 + idx * 40, 10 + [0, 22, 50, 90][j]))
    for j, s in enumerate((32, 64, 128)):
        sheet.alpha_composite(logo(s), (10 + j * 150, 150))
    sheet.save(os.path.join(ROOT, "tools", "preview.png"))


if __name__ == "__main__":
    main()
