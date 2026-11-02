"""XZ / LZMA-alone / lzip single-stream formats (src/fmt/xz.c).

Fixtures come from the reference tools at test time: xz (every preset, -e, all
check types, --block-size, -T0 multi-block files with size fields, BCJ / Delta
filter chains, LZMA2 options, concatenated streams with stream padding,
--format=lzma), lzip (presets, multimember, dictionary codings), Python's lzma
module, tar. Results are compared byte for byte with the input (and with 7-Zip
for some). The xz decoder is also driven through gz_xz_decode_io (ZIP method 95
path) with readers returning odd-sized pieces, and without a gz_ctx.

Hostile inputs: crafted index / footer / block header / check / trailer damage
with the exact error expected, truncations and bit flips through gzt, and
in-process mutation fuzzing (tests/drivers/zipxz.c; GZ_FUZZ_ITERS sets the
iterations per target)."""
import io, os, random, shutil, struct, subprocess, tarfile, time, zlib, lzma

E_FORMAT, E_DATA, E_CRC, E_METHOD, E_TRUNC = 2, 3, 4, 5, 9

WORDS = ["고기", "삼겹살", "목살", "갈비", "xz", "lzma", "lzip", "archive", "hello", "world", "\n", "the",
         "quick", "brown", "fox", "2024", "0123456789"]

def text(n, seed=1):
    rnd = random.Random(seed)
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(WORDS).encode() + b" "
    return bytes(out[:n])

def rand(n, seed=2):
    return random.Random(seed).randbytes(n)

def write(t, name, data):
    p = t.path(name)
    with open(p, "wb") as f:
        f.write(data)
    return p

def tool(t, args, data):
    return t.sh(args, input=data).stdout

# ---------------------------------------------------------------- .xz structure helpers

def vli(n):
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)

def read_vli(b, i):
    v = s = 0
    while True:
        c = b[i]; i += 1
        v |= (c & 0x7F) << s; s += 7
        if not c & 0x80:
            return v, i

def xz_split(b):
    """single-stream file -> (header, blocks, index records, footer flags)"""
    bsize = (struct.unpack("<I", b[-8:-4])[0] + 1) * 4
    istart = len(b) - 12 - bsize
    ix = b[istart:len(b) - 12]
    n, i = read_vli(ix, 1)
    recs = []
    for _ in range(n):
        u, i = read_vli(ix, i)
        s, i = read_vli(ix, i)
        recs.append([u, s])
    return b[:12], b[12:istart], recs, b[-4:-2]

def xz_index(recs, count=None):
    body = b"\0" + vli(len(recs) if count is None else count) + b"".join(vli(u) + vli(s) for u, s in recs)
    body += b"\0" * (-len(body) % 4)
    return body + struct.pack("<I", zlib.crc32(body))

def xz_footer(isize, flags):
    x = struct.pack("<I", isize // 4 - 1) + flags
    return struct.pack("<I", zlib.crc32(x)) + x + b"YZ"

def xz_join(hdr, blocks, recs, flags, count=None, bsize=None, fflags=None):
    ix = xz_index(recs, count)
    return hdr + blocks + ix + xz_footer(bsize or len(ix), fflags or flags)

def with_block_header(b, fn):
    """rewrite the first block header with fn(bytearray without CRC), fixing its CRC"""
    hs = (b[12] + 1) * 4
    h = bytearray(b[12:12 + hs - 4])
    fn(h)
    return b[:12] + bytes(h) + struct.pack("<I", zlib.crc32(h)) + b[12 + hs:]

# ---------------------------------------------------------------- checks

def status(t, p):
    r, rows, out = t.extract(p)
    so = r.stdout.decode(errors="replace")
    if so.startswith("OPEN_ERROR"):
        return "open%s" % so.split()[1]
    return rows[0][0] if rows else None

def expect_status(t, label, p, want):
    """want: code(s) found at extraction or already at open ("open<code>" demands open)"""
    st = status(t, p)
    ws = want if isinstance(want, (tuple, list, set)) else (want,)
    ok = st in ws or (isinstance(st, str) and st[4:].isdigit() and int(st[4:]) in ws)
    return t.record(ok, label, "status %r want %r" % (st, want))

def size_listed(t, p, want, label):
    r, typ, rows = t.listing(p)
    got = rows[0]["usize"] if rows else None
    return t.record(got == want, label, "listed %r want %r (%s)" % (got, want, typ))

def run(t):
    t.need("xz")
    TXT = text(1 << 20)
    BIG = text(4 << 20, 7)
    RND = rand(300000)
    gzt_bin = open(t.gzt, "rb").read()
    EXE = gzt_bin[:1500000]
    a64 = "/usr/aarch64-linux-gnu/lib/libc.so.6"
    ARM = open(a64, "rb").read()[:800000] if os.path.exists(a64) else rand(400000, 9)
    MIX = TXT[:200000] + RND[:50000] + EXE[:200000] + b"\0" * 70000 + TXT[:100000]
    cases = []                                           # (label, path, data) for the driver

    def xzc(label, data, *opts, name=None, expect=None, listed=True):
        x = tool(t, ["xz", "-c", "-T1"] + list(opts), data) if not any(o.startswith("-T") for o in opts) else \
            tool(t, ["xz", "-c"] + list(opts), data)
        p = write(t, "xz/%s.xz" % (name or label.replace(" ", "_").replace("=", "").replace(",", "_")), x)
        nm = os.path.basename(p)[:-3]
        t.check_extract(p, {nm: data}, label="xz " + label, expect_type="XZ")
        if listed:
            size_listed(t, p, len(data), "xz %s size from index" % label)
        cases.append((label, p, data))
        return p, x

    # presets, extreme, checks
    for pre in ("-0", "-1", "-3", "-6", "-9", "-0e", "-6e"):
        xzc("preset %s" % pre, TXT, pre)
    xzc("preset -9e", MIX, "-9e")
    for ck in ("none", "crc32", "crc64", "sha256"):
        xzc("check %s" % ck, MIX, "--check=" + ck, "-3")
    xzc("big text", BIG, "-2")
    xzc("random", RND, "-6")
    # blocks: single-threaded --block-size (no sizes in headers), -T0 / -T2 (sizes stored)
    p_blk, x_blk = xzc("block-size 64k", MIX, "--block-size=65536", "-1")
    p_mt, x_mt = xzc("T0 block-size 300k", BIG, "-T0", "--block-size=300000", "-1")
    xzc("T2 sha256", BIG, "-T2", "--block-size=1000000", "--check=sha256", "-0")
    xzc("tiny blocks", TXT[:200000], "--block-size=1000", "-0")
    # filters
    for f, data in (("--x86", EXE), ("--arm64", ARM), ("--arm", ARM), ("--armthumb", ARM), ("--powerpc", EXE),
                    ("--ia64", EXE), ("--sparc", EXE), ("--x86=start=4096", EXE), ("--arm64=start=1048576", ARM)):
        xzc("filter " + f.lstrip("-"), data, f, "--lzma2=preset=1")
    for d in (1, 2, 4, 7, 256):
        xzc("delta %d" % d, MIX, "--delta=dist=%d" % d, "--lzma2=preset=0")
    xzc("x86 delta chain", EXE, "--x86", "--delta=dist=4", "--lzma2=preset=1")
    xzc("3 filters", EXE, "--delta=dist=2", "--x86", "--arm", "--lzma2=preset=1,dict=64KiB")
    xzc("lzma2 lc0 lp4 pb0", MIX, "--lzma2=lc=0,lp=4,pb=0,dict=4KiB")
    xzc("lzma2 lc4 fast", MIX, "--lzma2=lc=4,lp=0,pb=4,mode=fast,nice=8")
    p_empty, x_empty = xzc("empty", b"", name="empty")

    # concatenated streams, stream padding, trailing data
    x1 = tool(t, ["xz", "-c", "-1"], TXT[:300000])
    x2 = tool(t, ["xz", "-c", "-1", "--check=sha256"], RND[:100000])
    want = TXT[:300000] + RND[:100000]
    for label, blob in (("2 streams", x1 + x2), ("padding 4/400", x1 + b"\0" * 4 + x2 + b"\0" * 400),
                        ("empty stream between", x1 + x_empty + b"\0" * 8 + x2), ("multi-block + stream", x_blk + x1)):
        p = write(t, "xz/cat_%s.xz" % label.replace(" ", "_").replace("/", "_"), blob)
        exp = want if label != "multi-block + stream" else MIX + TXT[:300000]
        t.check_extract(p, {os.path.basename(p)[:-3]: exp}, label="xz " + label)
        cases.append((label, p, exp))
    size_listed(t, t.path("xz/cat_padding_4_400.xz"), len(want), "xz size of padded streams")
    p = write(t, "xz/trailing.xz", x1 + b"garbage!")
    t.check_extract(p, {"trailing": TXT[:300000]}, label="xz trailing data ignored")
    expect_status(t, "xz padding not a multiple of 4", write(t, "xz/pad2.xz", x1 + b"\0\0"), E_DATA)

    # 7-Zip agrees
    if t.tool("7z"):
        for p in (p_mt, p_blk, t.path("xz/cat_padding_4_400.xz"), t.path("xz/filter_x86.xz")):
            t.check_vs_7z(p, label="xz vs 7z " + os.path.basename(p), allow_extra=False)

    # ---------------- .lzma
    for label, data, opts in (("lzma -0", TXT, ["-0"]), ("lzma -6", MIX, ["-6"]), ("lzma -9e", MIX, ["-9e"]),
                              ("lzma lc0 lp2 pb0", MIX, ["--lzma1=lc=0,lp=2,pb=0"]), ("lzma empty", b"", ["-1"])):
        x = tool(t, ["xz", "--format=lzma", "-c"] + opts, data)
        p = write(t, "lzma/%s.lzma" % label.replace(" ", "_"), x)
        t.check_extract(p, {os.path.basename(p)[:-5]: data}, label=label, expect_type="LZMA")
        cases.append((label, p, data))
    x = lzma.compress(MIX, format=lzma.FORMAT_ALONE)
    p = write(t, "lzma/python.lzma", x)
    t.check_extract(p, {"python": MIX}, label="lzma python FORMAT_ALONE")
    size_listed(t, p, -1, "lzma unknown size")
    # header with the size filled in (the LZMA SDK writes it); the end marker may still follow
    p = write(t, "lzma/known.lzma", x[:5] + struct.pack("<Q", len(MIX)) + x[13:])
    t.check_extract(p, {"known": MIX}, label="lzma known size + end marker")
    size_listed(t, p, len(MIX), "lzma size from header")
    expect_status(t, "lzma size too small", write(t, "lzma/small.lzma", x[:5] + struct.pack("<Q", len(MIX) - 5) + x[13:]), E_DATA)
    expect_status(t, "lzma size too large", write(t, "lzma/large.lzma", x[:5] + struct.pack("<Q", len(MIX) + 5) + x[13:]), (E_DATA, E_TRUNC))

    # ---------------- .lz
    if t.tool("lzip"):
        for label, data, opts in (("lzip -0", TXT, ["-0"]), ("lzip -6", MIX, ["-6"]), ("lzip -9", MIX, ["-9"]),
                                  ("lzip dict 12KiB", MIX, ["-s", "12KiB"]), ("lzip dict 4KiB", TXT, ["-s", "4KiB"]),
                                  ("lzip multimember", BIG, ["-1", "-b", "700KiB"]),
                                  ("lzip small members", TXT, ["-0", "-b", "100KiB"]), ("lzip empty", b"", ["-1"])):
            x = tool(t, ["lzip", "-c"] + opts, data)
            p = write(t, "lz/%s.lz" % label.replace(" ", "_"), x)
            t.check_extract(p, {os.path.basename(p)[:-3]: data}, label=label, expect_type="LZIP")
            size_listed(t, p, len(data), label + " size from trailers")
            cases.append((label, p, data))
        lz1 = tool(t, ["lzip", "-c", "-1"], TXT[:200000])
        lz2 = tool(t, ["lzip", "-c", "-3"], RND[:50000])
        p = write(t, "lz/cat.lz", lz1 + lz2)
        t.check_extract(p, {"cat": TXT[:200000] + RND[:50000]}, label="lzip cat members")
        p = write(t, "lz/trailing.lz", lz1 + b"some trailing data")
        t.check_extract(p, {"trailing": TXT[:200000]}, label="lzip trailing data ignored")
        # damaged trailers
        n = len(lz1)
        def lzpatch(off, val, size=4):
            b = bytearray(lz1)
            b[n - 20 + off:n - 20 + off + size] = val.to_bytes(size, "little")
            return bytes(b)
        crc, dsize, msize = struct.unpack("<IQQ", lz1[-20:])
        expect_status(t, "lzip bad CRC", write(t, "lz/badcrc.lz", lzpatch(0, crc ^ 1)), E_CRC)
        expect_status(t, "lzip bad data size", write(t, "lz/baddsize.lz", lzpatch(4, dsize + 1, 8)), E_DATA)
        expect_status(t, "lzip bad member size", write(t, "lz/badmsize.lz", lzpatch(12, msize - 4, 8)), E_DATA)
        expect_status(t, "lzip bad version", write(t, "lz/badver.lz", lz1[:4] + b"\x02" + lz1[5:]), "open%d" % E_METHOD)
        expect_status(t, "lzip bad dictionary", write(t, "lz/baddict.lz", lz1[:5] + b"\x0b" + lz1[6:]), "open%d" % E_DATA)
        expect_status(t, "lzip truncated", write(t, "lz/trunc.lz", lz1[:-7]), E_TRUNC)
        expect_status(t, "lzip second member cut", write(t, "lz/cut2.lz", lz1 + lz2[:40]), (E_TRUNC, E_DATA))

    # ---------------- tarballs
    files = {"tar/a.txt": TXT[:100000], "tar/sub/b.bin": RND[:70000], "tar/empty": b"", "tar/한글.txt": "고기".encode() * 500}
    tb = io.BytesIO()
    with tarfile.open(fileobj=tb, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for k, v in files.items():
            ti = tarfile.TarInfo(k); ti.size = len(v); ti.mtime = 1600000000
            tf.addfile(ti, io.BytesIO(v))
    tar = tb.getvalue()
    tars = [("tar.xz", ["xz", "-c", "-3"], "TAR.XZ"), ("txz", ["xz", "-c", "-T0", "--block-size=50000"], "TAR.XZ"),
            ("tar.lzma", ["xz", "--format=lzma", "-c"], "TAR.LZMA"), ("tlz", ["xz", "--format=lzma", "-c"], "TAR.LZMA")]
    if t.tool("lzip"):
        tars += [("tar.lz", ["lzip", "-c"], "TAR.LZ"), ("tlz", ["lzip", "-c", "-b", "100KiB"], "TAR.LZ")]
    for ext, cmd, typ in tars:
        p = write(t, "tar/%s_%s.%s" % (cmd[0], typ.split(".")[1], ext), tool(t, cmd, tar))
        t.check_extract(p, files, label="%s (%s)" % (ext, typ), expect_type=typ)
    if t.tool("tar"):
        src = t.write_tree(t.path("tarsrc"), {"d/x.txt": TXT[:5000], "d/y.bin": RND[:3000]})
        for flag, ext, typ in (("-J", "tar.xz", "TAR.XZ"), ("--lzma", "tar.lzma", "TAR.LZMA"), ("--lzip", "tar.lz", "TAR.LZ")):
            if flag == "--lzip" and not t.tool("lzip"):
                continue
            p = t.path("tar/gnu.%s" % ext)
            t.sh(["tar", "-c", flag, "-f", p, "-C", src, "d"])
            head = open(p, "rb").read(6)       # GNU tar may run xz for --lzma: the content decides
            typ = "TAR.XZ" if head.startswith(b"\xfd7zXZ") else "TAR.LZ" if head.startswith(b"LZIP") else "TAR.LZMA"
            t.check_extract(p, {"d/x.txt": TXT[:5000], "d/y.bin": RND[:3000]}, label="GNU tar %s" % flag,
                            expect_type=typ, allow_extra=True)

    # ---------------- crafted damage with the exact error
    hdr, blocks, recs, flags = xz_split(x1)
    ok_again = xz_join(hdr, blocks, recs, flags)
    t.record(ok_again == x1, "xz rebuild helpers", "")
    bad = [("index usize +1", xz_join(hdr, blocks, [[recs[0][0], recs[0][1] + 1]] + recs[1:], flags), E_DATA),
           ("index unpadded +4", xz_join(hdr, blocks, [[recs[0][0] + 4, recs[0][1]]] + recs[1:], flags), E_DATA),
           ("index count +1", xz_join(hdr, blocks, recs, flags, count=len(recs) + 1), (E_DATA, E_TRUNC, E_CRC)),
           ("index extra record", xz_join(hdr, blocks, recs + [[16, 100]], flags), E_DATA),
           ("backward size", xz_join(hdr, blocks, recs, flags, bsize=len(xz_index(recs)) + 4), E_DATA),
           ("footer flags", xz_join(hdr, blocks, recs, flags, fflags=b"\0\x0a"), E_DATA),
           ("index CRC", x1[:-16] + bytes([x1[-16] ^ 0x40]) + x1[-15:], E_CRC),
           ("footer CRC", x1[:-12] + bytes([x1[-12] ^ 1]) + x1[-11:], E_CRC),
           ("footer magic", x1[:-1] + b"X", E_DATA),
           ("block check", x1[:12 + len(blocks) - 1] + bytes([x1[12 + len(blocks) - 1] ^ 0x80]) + x1[12 + len(blocks):], E_CRC),
           ("block header CRC", x1[:14] + bytes([x1[14] ^ 4]) + x1[15:], E_CRC),
           ("block reserved flag", with_block_header(x1, lambda h: h.__setitem__(1, h[1] | 0x10)), E_METHOD),
           ("unknown filter", with_block_header(x1, lambda h: h.__setitem__(2, 0x30)), E_METHOD),
           ("dict prop 41", with_block_header(x1, lambda h: h.__setitem__(4, 41)), E_DATA),
           ("header padding", with_block_header(x1, lambda h: h.__setitem__(len(h) - 1, 1)), E_METHOD),
           ("stream flags", x1[:7] + b"\x10" + x1[8:], "open%d" % E_CRC),
           ("data bit flip", x1[:200] + bytes([x1[200] ^ 0x10]) + x1[201:], (E_DATA, E_CRC)),
           ("truncated in block", x1[:len(x1) // 2], (E_TRUNC, E_DATA)),
           ("truncated in index", x1[:-14], E_TRUNC),
           ("no footer", x1[:-12], E_TRUNC)]
    # multi-threaded file: sizes in the block header must match the data
    h2, b2, r2, f2 = xz_split(x_mt)
    def bump_csize(h):
        assert h[1] & 0x40
        c, i = read_vli(h, 2)
        nb = vli(c + 1)
        if len(nb) == i - 2:
            h[2:i] = nb
    bad.append(("block csize field", with_block_header(x_mt, bump_csize), (E_DATA, E_TRUNC)))
    def bump_usize(h):
        c, i = read_vli(h, 2)
        u, j = read_vli(h, i)
        nb = vli(u - 1)
        if len(nb) == j - i:
            h[i:j] = nb
    bad.append(("block usize field", with_block_header(x_mt, bump_usize), E_DATA))
    for label, blob, want in bad:
        expect_status(t, "xz " + label, write(t, "bad/%s.xz" % label.replace(" ", "_"), blob), want)
    # a corrupt second stream is reported, not silently cut
    expect_status(t, "xz corrupt 2nd stream", write(t, "bad/second.xz", x1 + x2[:12] + bytes([x2[12] ^ 1]) + x2[13:]), E_CRC)

    # truncations / flips through gzt (no crash, no hang)
    rnd = random.Random(11)
    for src_label, blob in (("xz", x_mt), ("xzblk", x_blk), ("lzma", open(t.path("lzma/lzma_-6.lzma"), "rb").read())) + \
            ((("lz", open(t.path("lz/lzip_multimember.lz"), "rb").read()),) if t.tool("lzip") else ()):
        blob = blob[:400000]
        for k in range(8):
            b = bytearray(blob)
            if k < 3:
                b = b[:rnd.randrange(1, len(b))]
            else:
                for _ in range(1 + k % 3):
                    i = rnd.randrange(min(len(b), 64)) if k % 2 else rnd.randrange(len(b))
                    b[i] ^= 1 << rnd.randrange(8)
            t.check_hostile(write(t, "hostile/%s_%d.bin" % (src_label, k), bytes(b)), "hostile %s #%d" % (src_label, k), timeout=60)

    # ---------------- driver: piecewise reads (ZIP method 95 path), no gz_ctx, fuzzing
    drv = t.build_driver("tests/drivers/zipxz.c")
    for label, p, data in cases:
        want = "status=0 size=%d crc=%08x" % (len(data), zlib.crc32(data))
        if p.endswith(".xz"):
            for mode in ((0, 1, 2) if len(data) < 2000000 else (1, 2)):
                r = t.sh([drv, "xzio", p, str(mode), str(len(label))], check=False)
                out = r.stdout.decode().strip()
                t.record(out == want, "xzio mode %d %s" % (mode, label), out + " want " + want)
        r = t.sh([drv, "stream", p], check=False)
        out = r.stdout.decode().strip()
        t.record(out == want, "no-ctx decode %s" % label, out + " want " + want)
    iters = int(os.environ.get("GZ_FUZZ_ITERS", "250"))
    small = tool(t, ["xz", "-c", "-T0", "--block-size=4000", "--x86", "--lzma2=preset=1"], MIX[:40000])
    seeds = [("xz_mt", write(t, "fuzz/mt.xz", small), "seed.xz"),
             ("xz_cat", write(t, "fuzz/cat.xz", tool(t, ["xz", "-c", "--check=sha256", "-0"], TXT[:20000]) + b"\0" * 8 +
                                                tool(t, ["xz", "-c", "--delta=dist=3", "--lzma2=preset=0"], RND[:5000])), "seed.xz"),
             ("tar_xz", write(t, "fuzz/t.txz", tool(t, ["xz", "-c", "-0", "--block-size=3000"], tar[:30000])), "seed.txz"),
             ("lzma", write(t, "fuzz/s.lzma", tool(t, ["xz", "--format=lzma", "-c", "-0"], TXT[:30000])), "seed.lzma")]
    if t.tool("lzip"):
        seeds.append(("lzip", write(t, "fuzz/s.lz", tool(t, ["lzip", "-c", "-0", "-b", "100KiB"], TXT[:250000])), "seed.lz"))
    for label, p, name in seeds:
        r = t.sh([drv, "fuzz", p, str(iters), "7", name], check=False, timeout=900)
        out = r.stdout.decode().strip()
        err = r.stderr.decode(errors="replace")
        t.record(r.returncode == 0 and out.startswith("fuzz iters=") and "Sanitizer" not in err and "runtime error" not in err,
                 "fuzz %s" % label, out + " " + err[-300:])

    # ---------------- speed (recorded, not asserted: sanitizer builds are slow)
    p = write(t, "speed.bin", BIG + MIX * 4)
    x = tool(t, ["xz", "-c", "-6", "-T1"], open(p, "rb").read())
    px = write(t, "speed.xz", x)
    t0 = time.time(); t.sh(["xz", "-dc", "-T1", px]); tr = time.time() - t0
    t0 = time.time(); r, rows, out = t.extract(px); tg = time.time() - t0
    t.record(rows and rows[0][0] == 0, "xz speed", "gzt %.2fs vs xz -d %.2fs (%.1f MB)" % (tg, tr, os.path.getsize(p) / 1e6))
