#!/usr/bin/env python3
"""
고깃ZIP macOS icons: AppIcon.icns (the app) and ArchiveIcon.icns (archive documents),
rendered on Linux with the same vector code as res/app.ico / res/doc.ico
(tools/gen_assets.py, needs Pillow). The outputs are committed in data/mac/; the macOS build
only copies them (no iconutil, no Python imaging needed there).

ICNS container (big endian): "icns", u32 total length, then elements: 4-char type, u32 length
(including the 8-byte element header), data. Every element here is a PNG file (macOS 10.7+):

    ic07  128 x 128        ic11   32 x 32   (16 pt @2x)
    ic08  256 x 256        ic12   64 x 64   (32 pt @2x)
    ic09  512 x 512
    ic10 1024 x 1024 (512 pt @2x)

  python3 tools/make_icns.py               render and write data/mac/AppIcon.icns, ArchiveIcon.icns
  python3 tools/make_icns.py --check       validate the committed files (structure, PNG sizes)
  python3 tools/make_icns.py --dump FILE   list the elements of an .icns file
"""
import io, os, struct, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "data", "mac")

# element type -> pixel size (PNG elements only)
PNG_TYPES = {"icp4": 16, "icp5": 32, "icp6": 64, "ic07": 128, "ic08": 256, "ic09": 512, "ic10": 1024,
             "ic11": 32, "ic12": 64, "ic13": 256, "ic14": 512}
APP_TYPES = ["ic11", "ic12", "ic07", "ic08", "ic09", "ic10"]
DOC_TYPES = ["ic11", "ic12", "ic07", "ic08", "ic09", "ic10"]
REQUIRED = ["ic07", "ic08", "ic09", "ic10"]
PNG_SIG = b"\x89PNG\r\n\x1a\n"


def pack(elements):
    """elements: [(type, png bytes)] -> icns bytes"""
    body = b""
    for t, data in elements:
        tb = t.encode("ascii")
        if len(tb) != 4:
            raise ValueError("bad element type %r" % t)
        body += tb + struct.pack(">I", 8 + len(data)) + data
    return b"icns" + struct.pack(">I", 8 + len(body)) + body


def parse(data):
    """icns bytes -> [(type, payload)]; raises ValueError on a malformed container"""
    if len(data) < 8 or data[:4] != b"icns":
        raise ValueError("not an icns file")
    total = struct.unpack(">I", data[4:8])[0]
    if total != len(data):
        raise ValueError("length field %d != file size %d" % (total, len(data)))
    out, pos = [], 8
    while pos < total:
        if pos + 8 > total:
            raise ValueError("truncated element header at %d" % pos)
        t = data[pos:pos + 4].decode("latin-1")
        n = struct.unpack(">I", data[pos + 4:pos + 8])[0]
        if n < 8 or pos + n > total:
            raise ValueError("bad element length %d at %d" % (n, pos))
        out.append((t, data[pos + 8:pos + n]))
        pos += n
    return out


def png_size(png):
    """(width, height) from the IHDR chunk"""
    if png[:8] != PNG_SIG or png[12:16] != b"IHDR":
        raise ValueError("not a PNG")
    return struct.unpack(">II", png[16:24])


def validate(data, required=REQUIRED):
    """list of problems (empty when fine)"""
    try:
        els = parse(data)
    except ValueError as e:
        return [str(e)]
    problems, seen = [], set()
    for t, payload in els:
        if t in seen:
            problems.append("duplicate element " + t)
        seen.add(t)
        if t in PNG_TYPES:
            try:
                w, h = png_size(payload)
            except ValueError as e:
                problems.append("%s: %s" % (t, e))
                continue
            if (w, h) != (PNG_TYPES[t], PNG_TYPES[t]):
                problems.append("%s: %dx%d, want %d" % (t, w, h, PNG_TYPES[t]))
    for t in required:
        if t not in seen:
            problems.append("missing " + t)
    return problems


def render(kind, size):
    """PNG bytes of the logo (kind "app") or archive document icon (kind "doc")"""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import gen_assets
    old = gen_assets.SS
    # 8x supersampling up to 256 px; fewer samples for the big ones keep memory sane
    gen_assets.SS = 8 if size <= 256 else 4 if size <= 512 else 2
    try:
        img = gen_assets.logo(size) if kind == "app" else gen_assets.doc_icon(size)
    finally:
        gen_assets.SS = old
    b = io.BytesIO()
    img.save(b, "PNG", optimize=True)
    return b.getvalue()


def build(kind, types):
    cache = {}
    els = []
    for t in types:
        s = PNG_TYPES[t]
        if s not in cache:
            cache[s] = render(kind, s)
        els.append((t, cache[s]))
    return pack(els)


def main():
    a = sys.argv[1:]
    if a[:1] == ["--dump"] and len(a) == 2:
        for t, payload in parse(open(a[1], "rb").read()):
            info = "%dx%d PNG" % png_size(payload) if payload[:8] == PNG_SIG else "raw"
            print("%s %8d  %s" % (t, len(payload), info))
        return
    files = {"AppIcon.icns": ("app", APP_TYPES), "ArchiveIcon.icns": ("doc", DOC_TYPES)}
    if a[:1] == ["--check"]:
        bad = 0
        for name in files:
            p = os.path.join(OUT, name)
            probs = validate(open(p, "rb").read()) if os.path.exists(p) else ["missing file"]
            for x in probs:
                print("%s: %s" % (name, x))
            bad += len(probs)
        sys.exit(1 if bad else 0)
    os.makedirs(OUT, exist_ok=True)
    for name, (kind, types) in files.items():
        data = build(kind, types)
        probs = validate(data)
        if probs:
            raise SystemExit("%s: %s" % (name, "; ".join(probs)))
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(data)
        print("wrote data/mac/%s (%d bytes)" % (name, len(data)))


if __name__ == "__main__":
    main()
