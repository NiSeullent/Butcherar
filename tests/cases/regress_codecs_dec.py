"""Regressions for the decompression codecs (slice "codecs-dec").

codecs-dec-1  LZMA2: input that ends inside a chunk's compressed data is a
              truncation (GZ_E_TRUNC = 9), as for LZMA1, BZip2, Zstd, Deflate...
              It used to be reported as GZ_E_DATA. Reads past the end of a
              *complete* chunk (packed size field too small) stay GZ_E_DATA.
              Checked on raw LZMA2 through tests/drivers/lzma_test.c (known and
              unknown size, byte-wise reads) and on .xz files through gzt.
codecs-dec-2  Zstd: a 4-stream Huffman literals section (compressed or treeless)
              needs Regenerated_Size >= 6 (reference decoder:
              MIN_LITERALS_FOR_4_STREAMS); rs 0, 3 and 4 used to be decoded.
              Frames are crafted here; the zstd CLI, when present, confirms the
              reference verdict for every frame.

Everything is generated at test time with Python's lzma module and struct.
"""
import os, random, shutil, struct, subprocess, lzma

GZ_OK, GZ_E_DATA, GZ_E_TRUNC = 0, 3, 9


def write(t, name, data):
    p = t.path(name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def status(t, p):
    """gzt x: 'open<code>' when the archive did not open, else the first entry's status"""
    r, rows, out = t.extract(p)
    err = r.stderr.decode(errors="replace")
    if r.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err:
        return "crash rc=%d %s" % (r.returncode, err[-300:])
    so = r.stdout.decode(errors="replace")
    if so.startswith("OPEN_ERROR"):
        return "open%s" % so.split()[1]
    return rows[0][0] if rows else None


def expect_status(t, label, p, want):
    st = status(t, p)
    ok = st == want or st == "open%d" % want
    return t.record(ok, label, "status %r want %r" % (st, want))


def extracted(t, p):
    r, rows, out = t.extract(p)
    if r.returncode or 0 not in rows or rows[0][0] != 0:
        return None
    fp = os.path.join(out, "0.bin")
    return open(fp, "rb").read() if os.path.exists(fp) else None


class LzmaDrv:
    def __init__(self, t):
        self.t = t
        self.exe = t.build_driver("tests/drivers/lzma_test.c", name="lzma_test")
        self.n = 0

    def dec(self, data, spec, *opts):
        self.n += 1
        inp = self.t.path("lz", "in_%d.bin" % (self.n % 4))
        out = self.t.path("lz", "out_%d.bin" % (self.n % 4))
        with open(inp, "wb") as f:
            f.write(data)
        r = subprocess.run([self.exe, "dec"] + [str(o) for o in opts] + [inp, out, spec],
                           capture_output=True, timeout=120)
        err = r.stderr.decode(errors="replace")
        info = dict(tok.split("=", 1) for tok in r.stdout.decode(errors="replace").split() if "=" in tok)
        bad = r.returncode != 0 or "Sanitizer" in err or "runtime error" in err or "rc" not in info
        return int(info.get("rc", -1)), (err[-400:] if bad else "")


def lzma2_chunks(b):
    """[(offset, header length, data length, compressed?)] of a raw LZMA2 stream"""
    out, pos = [], 0
    while pos < len(b):
        ctl = b[pos]
        if ctl == 0:
            break
        if ctl < 0x80:
            n = (b[pos + 1] << 8 | b[pos + 2]) + 1
            out.append((pos, 3, n, False))
            pos += 3 + n
        else:
            hl = 6 if (ctl >> 5) & 3 >= 2 else 5
            n = (b[pos + 3] << 8 | b[pos + 4]) + 1
            out.append((pos, hl, n, True))
            pos += hl + n
    return out


def dict_prop(size):
    for p in range(41):
        if ((2 | (p & 1)) << (p // 2 + 11)) >= size:
            return p
    return 40


def semi_text(n, seed):
    """about 2:1 compressible: random letters from a small alphabet, some words"""
    rnd = random.Random(seed)
    words = [b"lzma2 ", b"chunk ", b"\xea\xb3\xa0\xea\xb8\xb0 ", b"truncated ", b"\n"]
    out = bytearray()
    while len(out) < n:
        if rnd.random() < 0.2:
            out += rnd.choice(words)
        else:
            out += bytes(rnd.choice(b"abcdefghijklmnop") for _ in range(rnd.randrange(1, 12)))
    return bytes(out[:n])


# ---------------------------------------------------------------- codecs-dec-1

def lzma2_truncation(t):
    drv = LzmaDrv(t)
    data = semi_text(400000, 5)
    raw2 = lzma.compress(data, format=lzma.FORMAT_RAW,
                         filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}])
    spec = "lzma2:%d" % dict_prop(1 << 20)
    rc, err = drv.dec(raw2, spec)
    t.record(rc == GZ_OK and not err, "lzma2 control: complete stream", "rc=%d %s" % (rc, err))
    chunks = [c for c in lzma2_chunks(raw2) if c[3]]
    t.record(len(chunks) >= 3, "lzma2 fixture has several LZMA chunks", "%d" % len(chunks))
    picks = [chunks[0], chunks[len(chunks) // 2], chunks[-1]]
    for ci, (off, hl, pack, _) in enumerate(picks):
        ds = off + hl
        # cut inside the range coder init, just after it, in the middle and one
        # byte before the chunk's end: always a truncation
        for where, cut in (("in rc init", ds + 3), ("after rc init", ds + 6),
                           ("middle", ds + pack // 2), ("last byte missing", ds + pack - 1)):
            piece = raw2[:cut]
            for mode, opts in (("unknown size", ()), ("known size", ("-o", len(data))),
                               ("1-byte reads", ("-r", 1))):
                rc, err = drv.dec(piece, spec, *opts)
                t.record(rc == GZ_E_TRUNC and not err,
                         "lzma2 chunk %d cut %s (%s)" % (ci, where, mode), "rc=%d %s" % (rc, err))

    # a complete chunk whose packed size field is too small: the decoder needs
    # bytes beyond the chunk -> corrupt data, whether more input follows or not
    off, hl, pack, _ = chunks[0]
    for dec_by in (1, 2, 4):
        b = bytearray(raw2)
        np = pack - 1 - dec_by
        b[off + 3], b[off + 4] = np >> 8, np & 0xFF
        rc, err = drv.dec(bytes(b), spec)
        t.record(rc == GZ_E_DATA and not err, "lzma2 packed size -%d, stream follows" % dec_by,
                 "rc=%d %s" % (rc, err))
        rc, err = drv.dec(bytes(b[:off + hl + pack - dec_by]), spec)
        t.record(rc == GZ_E_DATA and not err, "lzma2 packed size -%d, input ends with the chunk" % dec_by,
                 "rc=%d %s" % (rc, err))

    # LZMA1 keeps reporting truncation
    alone = lzma.compress(data, format=lzma.FORMAT_ALONE, preset=6)
    props, raw1 = alone[:5].hex(), alone[13:]
    for frac in (0.3, 0.5, 0.9):
        rc, err = drv.dec(raw1[:int(len(raw1) * frac)], "lzma1:" + props, "-o", len(data))
        t.record(rc == GZ_E_TRUNC and not err, "lzma1 cut at %d%%" % int(frac * 100), "rc=%d %s" % (rc, err))

    # archive level: .xz cut inside its LZMA2 block (the index and footer are tiny)
    x = lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64)
    p = write(t, "xz/full.xz", x)
    t.record(extracted(t, p) == data, "xz control: complete file", "")
    for frac in (0.1, 0.3, 0.5, 0.9, 0.99):
        p = write(t, "xz/cut%d.xz" % int(frac * 100), x[:int(len(x) * frac)])
        expect_status(t, "xz cut in block at %d%%" % int(frac * 100), p, GZ_E_TRUNC)
    # the same through a filter chain (BCJ in front of LZMA2)
    x = lzma.compress(data * 2, format=lzma.FORMAT_XZ,
                      filters=[{"id": lzma.FILTER_X86}, {"id": lzma.FILTER_LZMA2, "preset": 1}])
    p = write(t, "xz/cut_bcj.xz", x[:len(x) * 2 // 3])
    expect_status(t, "xz BCJ+LZMA2 cut in block", p, GZ_E_TRUNC)


# ---------------------------------------------------------------- codecs-dec-2

def z_lit(rs, ltype, streams):
    """Huffman literals with two 1-bit symbols (tree '80 10'), every code bit 1"""
    tree = b"\x80\x10" if ltype == 2 else b""
    if streams == 4:
        seg = (rs + 3) // 4
        counts = [seg, seg, seg, rs - 3 * seg]
        body = struct.pack("<HHH", 1, 1, 1) + bytes((1 << k) | ((1 << k) - 1) for k in counts)
        sf = 1
    else:
        body = bytes([(1 << rs) | ((1 << rs) - 1)])
        sf = 0
    cs = len(tree) + len(body)
    h = ltype | sf << 2 | rs << 4 | cs << 14
    return h.to_bytes(3, "little") + tree + body


def z_block(lit, last):
    content = lit + b"\x00"                     # no sequences
    return (int(last) | 2 << 1 | len(content) << 3).to_bytes(3, "little") + content


def z_frame(*blocks):
    return b"\x28\xb5\x2f\xfd\x00\x00" + b"".join(blocks)   # 1 KiB window, no size, no checksum


def zstd_small_literals(t):
    have_ref = bool(t.tool("zstd"))
    cases = []
    # (label, frame, expected output or None for GZ_E_DATA)
    for rs in (0, 3, 4):
        cases.append(("4-stream compressed rs=%d" % rs, z_frame(z_block(z_lit(rs, 2, 4), 1)), None))
    for rs in (6, 8, 12):
        cases.append(("4-stream compressed rs=%d" % rs, z_frame(z_block(z_lit(rs, 2, 4), 1)), b"\x01" * rs))
    for rs in (1, 3, 5):
        cases.append(("1-stream compressed rs=%d" % rs, z_frame(z_block(z_lit(rs, 2, 1), 1)), b"\x01" * rs))
    first = z_block(z_lit(8, 2, 4), 0)
    for rs in (0, 3, 4):
        cases.append(("4-stream treeless rs=%d" % rs, z_frame(first, z_block(z_lit(rs, 3, 4), 1)), None))
    for rs in (6, 9):
        cases.append(("4-stream treeless rs=%d" % rs, z_frame(first, z_block(z_lit(rs, 3, 4), 1)),
                      b"\x01" * (8 + rs)))
    cases.append(("1-stream treeless rs=3", z_frame(first, z_block(z_lit(3, 3, 1), 1)), b"\x01" * 11))
    for i, (label, frame, want) in enumerate(cases):
        p = write(t, "zst/c%02d.zst" % i, frame)
        if have_ref:
            r = subprocess.run(["zstd", "-q", "-d", "-c", p], capture_output=True, timeout=60)
            ref = r.stdout if r.returncode == 0 else None
            t.record(ref == want, "zstd reference agrees: " + label, "ref %r want %r" % (ref, want))
        if want is None:
            expect_status(t, "zstd " + label, p, GZ_E_DATA)
        else:
            got = extracted(t, p)
            t.record(got == want, "zstd " + label, "got %r want %r" % (got, want))


def run(t):
    lzma2_truncation(t)
    zstd_small_literals(t)
