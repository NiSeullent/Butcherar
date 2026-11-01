"""PPMd codecs: var.H (Ppmd7: 7z coder, RAR 3.x coder, 7z encoder) and var.I rev.1 (Ppmd8: ZIP
method 98) against pyppmd (7-Zip's C code), 7-Zip itself (7z/ZIP archives, RAR 3.x via the Rar
codec) and unar (independent var.I / RAR implementation); memory-exhaustion restarts, FREEZE,
a Python reference port of the RAR range decoder, hostile streams (fuzzed in-process), 32-bit and
AArch64 (qemu) builds of the driver, speed."""
import os, random, shutil, struct, subprocess, sys, time, zlib

SAN = "sanitize" in os.environ.get("HOST_CFLAGS", "")
SCALE = 0.25 if SAN else 1.0

# ---------------------------------------------------------------- data

def blob(kind, n, seed=1):
    rnd = random.Random(seed * 7919 + n)
    if kind == "rand":
        return rnd.randbytes(n)
    if kind == "text":
        words = [b"gogi", b"samgyeopsal", b"moksal", b"galbi", b"archive", b"ppmd", b"\n", b"the", b"of",
                 "고기".encode(), "압축".encode(), b"and", b"zip", b"Shkarin", b"model", b"context"]
        out = bytearray()
        while len(out) < n:
            out += rnd.choice(words) + rnd.choice([b" ", b" ", b", ", b".\n"])
        return bytes(out[:n])
    if kind == "mixed":       # text, binary records and noise: grows the model fast (exhaustion)
        out = bytearray()
        while len(out) < n:
            k = rnd.randrange(5)
            if k == 0: out += blob("text", rnd.randrange(100, 4000), rnd.randrange(1 << 30))
            elif k == 1: out += rnd.randbytes(rnd.randrange(10, 600))
            elif k == 2: out += b"".join(struct.pack("<IH", rnd.randrange(1 << 20), rnd.randrange(64)) for _ in range(rnd.randrange(1, 80)))
            elif k == 3: out += bytes([rnd.randrange(256)]) * rnd.randrange(1, 300)
            else: out += bytes(rnd.randrange(65, 91) for _ in range(rnd.randrange(5, 200)))
        return bytes(out[:n])
    if kind == "runs":
        out = bytearray()
        while len(out) < n:
            out += bytes([rnd.randrange(3)]) * rnd.choice([1, 2, 5, 100, 1000, 70000])
        return bytes(out[:n])
    if kind == "allbytes":    # every symbol, so escapes reach the order -1 context
        return bytes(range(256)) * (n // 256) + bytes(range(n % 256))
    raise ValueError(kind)

def sz(n):
    return max(1, int(n * SCALE))

# ---------------------------------------------------------------- pyppmd helpers

def load_pyppmd(t):
    try:
        import pyppmd
        return pyppmd
    except ImportError:
        pass
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "pyppmd"], capture_output=True, timeout=300)
    try:
        import pyppmd
        return pyppmd
    except ImportError:
        return None

def chunked(enc, data, endmark):
    # pyppmd's Ppmd8Encoder drops a byte at 32 KiB output-buffer boundaries when one call
    # produces more than that: feed it in small pieces.
    out = b"".join(enc.encode(data[i:i + 4096]) for i in range(0, len(data), 4096))
    return out + enc.flush(endmark=endmark)

def py7_enc(pp, data, order, mem, endmark=False):
    return chunked(pp.Ppmd7Encoder(order, mem), data, endmark)

def py8_enc(pp, data, order, mb, restore):
    hdr = ((order - 1) | ((mb - 1) << 4) | (restore << 12)).to_bytes(2, "little")
    return hdr + chunked(pp.Ppmd8Encoder(order, mb << 20, restore), data, True)

# ---------------------------------------------------------------- containers

def num7z(v):
    for n in range(9):
        if n == 8:
            return b"\xff" + v.to_bytes(8, "little")
        if v < (1 << (8 * n + 7 - n)):
            return bytes([((0xFF00 >> n) & 0xFF) | (v >> (8 * n))]) + (v & ((1 << (8 * n)) - 1)).to_bytes(n, "little")

def make_7z(name, data, packed, order, mem):
    props = bytes([order]) + struct.pack("<I", mem)
    nm = name.encode("utf-16-le") + b"\0\0"
    h = (b"\x01\x04\x06" + num7z(0) + num7z(1) + b"\x09" + num7z(len(packed)) + b"\x00"
         + b"\x07\x0b" + num7z(1) + b"\x00" + num7z(1) + b"\x23\x03\x04\x01" + num7z(5) + props
         + b"\x0c" + num7z(len(data)) + b"\x0a\x01" + struct.pack("<I", zlib.crc32(data)) + b"\x00"
         + b"\x00" + b"\x05" + num7z(1) + b"\x11" + num7z(len(nm) + 1) + b"\x00" + nm + b"\x00\x00")
    start = struct.pack("<QQI", len(packed), len(h), zlib.crc32(h))
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(start)) + start + packed + h

def make_zip98(name, data, packed):
    nm = name.encode()
    crc = zlib.crc32(data)
    dt = struct.pack("<HH", 0, (40 << 9) | (1 << 5) | 1)
    lh = struct.pack("<IHHH", 0x04034b50, 63, 0, 98) + dt + struct.pack("<IIIHH", crc, len(packed), len(data), len(nm), 0) + nm
    cd = (struct.pack("<IHHHH", 0x02014b50, 63, 63, 0, 98) + dt
          + struct.pack("<IIIHHHHHII", crc, len(packed), len(data), len(nm), 0, 0, 0, 0, 0, 0) + nm)
    eocd = struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, 1, 1, len(cd), len(lh) + len(packed), 0)
    return lh + packed + cd + eocd

def make_rar3(name, data, packed):
    """RAR 2.9 archive with one file packed by method 0x35 (unpack version 29)."""
    mh = struct.pack("<BHHHI", 0x73, 0, 13, 0, 0)
    fn = name.encode()
    ftime = ((2020 - 1980) << 9 | 1 << 5 | 1) << 16
    fh = struct.pack("<BHHIIBIIBBHI", 0x74, 0x8000 | 0x80, 32 + len(fn), len(packed), len(data), 2,
                     zlib.crc32(data), ftime, 29, 0x35, len(fn), 0x20) + fn
    return (b"Rar!\x1a\x07\x00" + struct.pack("<H", zlib.crc32(mh) & 0xFFFF) + mh
            + struct.pack("<H", zlib.crc32(fh) & 0xFFFF) + fh + packed + bytes.fromhex("c43d7b00400700"))

def props_7z(arc):
    """(order, mem) of the PPMd coder in a 7z archive with a plain (-mhc=off) header."""
    hoff, hsize = struct.unpack("<QQ", arc[12:28])
    h = arc[32 + hoff:32 + hoff + hsize]
    i = h.find(b"\x23\x03\x04\x01\x05")
    if i < 0:
        return None
    return h[i + 5], struct.unpack("<I", h[i + 6:i + 10])[0]

# ---------------------------------------------------------------- RAR range decoder reference

M32 = 0xFFFFFFFF

def rar_rc_replay(stream, recs):
    """unrar's RangeCoder (coder.cpp: absolute code/low, GetCurrentCount, GetCurrentShiftCount,
    ARI_DEC_NORMALIZE), replaying the operations reported by gz_ppmd7_rar_rc_test."""
    pos = 0
    def byte():
        nonlocal pos
        b = stream[pos] if pos < len(stream) else 0
        pos += 1
        return b
    code = low = 0
    rng = M32
    for _ in range(4):
        code = ((code << 8) | byte()) & M32
    for i, (op, a, b, c, R, C, L, extra) in enumerate(recs):
        if op in (0, 2):
            rng //= a                                   # range /= SubRange.scale
            count = ((code - low) & M32) // rng
            if count != c:
                return "op %d: count %d != %d" % (i, c, count)
            if op == 2:
                return None if count >= a else "op %d: count %d < total" % (i, count)
            lo, size = b >> 16, b & 0xFFFF
            low = (low + rng * lo) & M32
            rng = (rng * size) & M32
        else:
            rng >>= 14
            bit = 0 if ((code - low) & M32) // rng < a else 1
            if bit != c:
                return "op %d: bit %d != %d" % (i, c, bit)
            lo, hi = (0, a) if bit == 0 else (a, 1 << 14)
            low = (low + rng * lo) & M32
            rng = (rng * (hi - lo)) & M32
        while True:                                     # ARI_DEC_NORMALIZE
            if ((low ^ ((low + rng) & M32)) & M32) >= (1 << 24):
                if rng >= (1 << 15):
                    break
                rng = (-low) & ((1 << 15) - 1)
            code = ((code << 8) | byte()) & M32
            rng = (rng << 8) & M32
            low = (low << 8) & M32
        if (rng, (code - low) & M32, low) != (R, C, L):
            return "op %d: state %08x/%08x/%08x != %08x/%08x/%08x" % (i, R, C, L, rng, (code - low) & M32, low)
    return None

# ---------------------------------------------------------------- run

def run(t):
    drv = t.build_driver("tests/drivers/ppmd_test.c")
    pp = load_pyppmd(t)
    W = t.work
    has7z = bool(shutil.which("7z"))
    info7z = subprocess.run(["7z", "i"], capture_output=True).stdout.decode(errors="replace") if has7z else ""
    has_rar3 = "Rar3" in info7z
    has_unar = bool(shutil.which("unar"))

    def D(*args, env=None, timeout=600):
        e = dict(os.environ)
        if env:
            e.update(env)
        r = subprocess.run([drv] + [str(a) for a in args], capture_output=True, env=e, timeout=timeout)
        out = r.stdout.decode(errors="replace").strip()
        rc = None
        for tok in out.split():
            if tok.startswith("rc="):
                rc = int(tok[3:])
        return r.returncode, rc, out + r.stderr.decode(errors="replace")[-300:]

    def wr(name, data):
        fn = t.path(name)
        with open(fn, "wb") as f:
            f.write(data)
        return fn

    def rd(name):
        with open(t.path(name), "rb") as f:
            return f.read()

    # ------------------------------------------------ Ppmd7 (7z) vs pyppmd
    cases7 = [
        (2, 1 << 16, "text", 60000), (3, 1 << 20, "text", 150000), (4, 2048, "mixed", 30000),
        (5, 1 << 14, "mixed", 200000), (6, 16 << 20, "text", 300000), (6, 1 << 18, "mixed", 400000),
        (8, 1 << 20, "mixed", 600000), (10, 3000, "allbytes", 20000), (12, 1 << 22, "rand", 100000),
        (16, 1 << 17, "mixed", 300000), (20, 1 << 20, "text", 200000), (24, 5555, "text", 50000),
        (32, 1 << 24, "mixed", 300000), (40, 1 << 16, "runs", 300000), (48, 1 << 19, "mixed", 300000),
        (63, 1 << 20, "text", 100000), (64, 2048, "text", 20000), (64, 1 << 21, "mixed", 400000),
        (7, 1 << 20, "runs", 500000), (2, 2048, "allbytes", 3000), (6, 1 << 20, "text", 1), (6, 1 << 20, "text", 0),
    ]
    if pp:
        for i, (order, mem, kind, n) in enumerate(cases7):
            data = blob(kind, sz(n) if n > 1 else n, i)
            ref = py7_enc(pp, data, order, mem)
            lab = "ppmd7 o%d mem%d %s %d" % (order, mem, kind, len(data))
            # our decoder on pyppmd output (known size, varying read chunks)
            env = {"PPMD_CHUNK": str([0, 1, 7, 4093][i % 4])}
            _, rc, out = D("d7", order, mem, len(data), wr("p7.ppmd", ref), t.path("p7.out"), env=env)
            t.record(rc == 0 and rd("p7.out") == data, lab + " decode", out)
            # our encoder: byte-identical with 7-Zip's C code
            _, rc, out = D("e7", order, mem, wr("p7.raw", data), t.path("p7.enc"))
            t.record(rc == 0 and rd("p7.enc") == ref, lab + " encode identical", out)
            # end marker: unknown size, and known size followed by a marker
            if i % 3 == 0:
                refm = py7_enc(pp, data, order, mem, endmark=True)
                _, rc, out = D("d7", order, mem, "u", wr("p7m.ppmd", refm), t.path("p7m.out"))
                t.record(rc == 0 and rd("p7m.out") == data, lab + " endmark, size unknown", out)
                _, rc, out = D("d7", order, mem, len(data), t.path("p7m.ppmd"), t.path("p7m.out"))
                t.record(rc == 0 and rd("p7m.out") == data, lab + " endmark, size known", out)
            if i % 4 == 1:     # pyppmd decodes ours (independent of the byte comparison above)
                dec = pp.Ppmd7Decoder(order, mem)
                t.record(dec.decode(rd("p7.enc"), len(data)) == data, lab + " pyppmd decodes ours")
        # stream reuse: same object, alternating memory sizes (model block reallocated / reused)
        data = blob("mixed", sz(200000), 77)
        ok = True
        for mem in (1 << 16, 1 << 16, 1 << 20, 4096, 1 << 20):
            ref = py7_enc(pp, data, 6, mem)
            _, rc, out = D("d7", 6, mem, len(data), wr("reuse.ppmd", ref), t.path("reuse.out"),
                           env={"PPMD_REPEAT": "3"})
            ok &= rc == 0 and rd("reuse.out") == data
        t.record(ok, "ppmd7 object reuse across sizes")
    else:
        t.record(True, "pyppmd unavailable: pyppmd cross-checks skipped")

    # ------------------------------------------------ Ppmd8 (ZIP 98) vs pyppmd
    cases8 = [
        (2, 1, 0, "text", 100000), (3, 1, 1, "mixed", 1500000), (4, 2, 0, "mixed", 2500000),
        (6, 16, 0, "text", 300000), (6, 1, 1, "mixed", 2000000), (8, 1, 0, "mixed", 1200000),
        (8, 1, 1, "mixed", 3000000), (10, 4, 1, "rand", 200000), (12, 1, 1, "text", 1500000),
        (16, 1, 0, "mixed", 1000000), (16, 2, 1, "mixed", 2500000), (5, 1, 0, "allbytes", 50000),
        (7, 3, 1, "runs", 600000), (6, 1, 0, "text", 0), (6, 1, 0, "text", 1),
    ]
    if pp:
        for i, (order, mb, restore, kind, n) in enumerate(cases8):
            data = blob(kind, sz(n) if n > 1 else n, 100 + i)
            ref = py8_enc(pp, data, order, mb, restore)
            lab = "ppmd8 o%d %dM r%d %s %d" % (order, mb, restore, kind, len(data))
            env = {"PPMD_CHUNK": str([0, 3, 4096, 1][i % 4])}
            _, rc, out = D("d8", len(data), wr("p8.ppmd", ref), t.path("p8.out"), env=env)
            t.record(rc == 0 and rd("p8.out") == data, lab + " decode", out)
            _, rc, out = D("d8", "u", t.path("p8.ppmd"), t.path("p8.out"))
            t.record(rc == 0 and rd("p8.out") == data, lab + " decode, size unknown", out)
            _, rc, out = D("e8", order, mb, restore, wr("p8.raw", data), t.path("p8.enc"))
            t.record(rc == 0 and rd("p8.enc") == ref, lab + " encode identical", out)

    # ------------------------------------------------ real 7-Zip archives
    if has7z:
        src = blob("mixed", sz(1500000), 5) + blob("text", sz(800000), 6)
        wr("src.bin", src)
        zcases = [["-mm=PPMd", "-mx=9"], ["-mm=PPMd", "-mx=1"], ["-mm=PPMd", "-mx=5"],
                  ["-mm=PPMd:o=16:mem=1m:a=1"], ["-mm=PPMd:o=2:mem=1m:a=0"], ["-mm=PPMd:o=10:mem=2m:a=1"]]
        for zc in zcases:
            arc = t.path("z%s.zip" % "".join(c for c in "".join(zc) if c.isalnum()))
            if os.path.exists(arc):
                os.remove(arc)
            t.sh(["7z", "a", "-tzip"] + zc + [arc, t.path("src.bin")])
            _, rc, out = D("zip", arc, t.path("zip.out"))
            t.record(rc == 0 and rd("zip.out") == src, "7-Zip zip %s decode" % " ".join(zc), out)
            # our encoder with the parameters from the header: same bytes as 7-Zip
            z = open(arc, "rb").read()
            nlen, xlen = struct.unpack("<HH", z[26:30])
            csize = struct.unpack("<I", z[18:22])[0]
            pk = z[30 + nlen + xlen:30 + nlen + xlen + csize]
            v = struct.unpack("<H", pk[:2])[0]
            _, rc, out = D("e8", (v & 15) + 1, ((v >> 4) & 255) + 1, v >> 12, t.path("src.bin"), t.path("zip.enc"))
            t.record(rc == 0 and rd("zip.enc") == pk, "7-Zip zip %s encode identical" % " ".join(zc), out)
        for o, m in ((32, 24), (6, 20), (2, 16), (24, 22), (16, 16)):   # 7-Zip: o <= 32, mem >= 64K
            arc = t.path("s%d_%d.7z" % (o, m))
            if os.path.exists(arc):
                os.remove(arc)
            t.sh(["7z", "a", "-t7z", "-m0=PPMd:o=%d:mem=%d" % (o, m), "-mhc=off", arc, t.path("src.bin")])
            _, rc, out = D("7z", arc, t.path("7z.out"))
            t.record(rc == 0 and rd("7z.out") == src, "7-Zip 7z o=%d mem=2^%d decode" % (o, m), out)
            s7 = open(arc, "rb").read()
            hoff = struct.unpack("<Q", s7[12:20])[0]
            _, rc, out = D("e7", o, 1 << m, t.path("src.bin"), t.path("7z.enc"))
            t.record(rc == 0 and rd("7z.enc") == s7[32:32 + hoff], "7-Zip 7z o=%d mem=2^%d encode identical" % (o, m), out)

        # default parameters per level: ours (gz_ppmd7z_level / gz_ppmd8_zip_level) vs 7-Zip's choice
        # (the big size crosses the memory reduction threshold of every level: 256 MiB / 16)
        big_runs = blob("runs", 17 << 20, 9)
        for data in (src[:1000], src[:100000], src[:2300000], big_runs):
            size = len(data)
            wr("lv.bin", data)
            for level in ((1, 3, 5, 7, 9) if size < (1 << 24) else (5, 7, 8, 9)):
                r = subprocess.run([drv, "level", str(level), str(size)], capture_output=True)
                f = r.stdout.decode().split()
                want7, wantz = (int(f[1]), int(f[2])), (int(f[4]), int(f[5]), int(f[6]))
                arc = t.path("lv.7z")
                if os.path.exists(arc):
                    os.remove(arc)
                t.sh(["7z", "a", "-t7z", "-m0=PPMd", "-mx=%d" % level, "-mhc=off", arc, t.path("lv.bin")])
                got7 = props_7z(open(arc, "rb").read())
                arc = t.path("lv.zip")
                if os.path.exists(arc):
                    os.remove(arc)
                t.sh(["7z", "a", "-tzip", "-mm=PPMd", "-mx=%d" % level, arc, t.path("lv.bin")])
                z = open(arc, "rb").read()
                nlen, xlen = struct.unpack("<HH", z[26:30])
                v = struct.unpack("<H", z[30 + nlen + xlen:32 + nlen + xlen])[0]
                gotz = ((v & 15) + 1, ((v >> 4) & 255) + 1, v >> 12)
                t.record(got7 == want7 and gotz == wantz and struct.unpack("<H", z[8:10])[0] == 98,
                         "level %d size %d defaults match 7-Zip" % (level, size),
                         "7z %s/%s zip %s/%s" % (got7, want7, gotz, wantz))
        del big_runs

        # our encoders inside hand-made containers, checked by 7-Zip itself
        for (order, mem, kind, n) in ((6, 1 << 24, "text", 400000), (32, 1 << 16, "mixed", 500000), (2, 2048, "allbytes", 9000)):
            data = blob(kind, sz(n), order)
            _, rc, out = D("e7", order, mem, wr("o7.raw", data), t.path("o7.enc"))
            arc = wr("ours_o%d.7z" % order, make_7z("f.bin", data, rd("o7.enc"), order, mem))
            r, outdir = t.sevenzip_extract(arc)
            ok = r.returncode == 0 and open(os.path.join(outdir, "f.bin"), "rb").read() == data
            t.record(ok, "7z extracts our 7z PPMd o%d mem%d" % (order, mem), r.stdout.decode(errors="replace")[-200:] if not ok else out)
            _, rc, out = D("7z", arc, t.path("o7.out"))
            t.record(rc == 0 and rd("o7.out") == data, "driver parses our 7z o%d" % order, out)
        for (order, mb, restore, kind, n) in ((6, 1, 1, "mixed", 2000000), (16, 8, 0, "text", 300000)):
            data = blob(kind, sz(n), order)
            _, rc, out = D("e8", order, mb, restore, wr("o8.raw", data), t.path("o8.enc"))
            arc = wr("ours_o%d.zip" % order, make_zip98("f.bin", data, rd("o8.enc")))
            r, outdir = t.sevenzip_extract(arc)
            ok = r.returncode == 0 and open(os.path.join(outdir, "f.bin"), "rb").read() == data
            t.record(ok, "7z extracts our zip PPMd o%d r%d" % (order, restore), r.stdout.decode(errors="replace")[-200:] if not ok else out)

    # ------------------------------------------------ FREEZE (var.I rev.1), checked by unar
    for (order, mb, kind, n) in ((6, 1, "mixed", 2500000), (16, 1, "mixed", 1500000), (4, 1, "text", 3000000), (10, 2, "mixed", 3000000)):
        data = blob(kind, sz(n), 300 + order)
        _, rc, out = D("e8", order, mb, 2, wr("fz.raw", data), t.path("fz.enc"))
        _, rc2, out2 = D("d8", len(data), t.path("fz.enc"), t.path("fz.out"))
        lab = "ppmd8 FREEZE o%d %dM %d" % (order, mb, len(data))
        t.record(rc == 0 and rc2 == 0 and rd("fz.out") == data, lab + " round trip", out + " | " + out2)
        # the models only differ once the memory is exhausted: make sure FREEZE really ran
        D("e8", order, mb, 0, t.path("fz.raw"), t.path("fz0.enc"))
        t.record(rd("fz0.enc") != rd("fz.enc"), lab + " memory exhausted (differs from RESTART)")
        if has_unar:
            arc = wr("freeze_o%d.zip" % order, make_zip98("f.bin", data, rd("fz.enc")))
            od = t.path("unar_fz")
            shutil.rmtree(od, ignore_errors=True)
            r = subprocess.run(["unar", "-q", "-f", "-o", od, arc], capture_output=True, timeout=300)
            fp = os.path.join(od, "f.bin")
            ok = r.returncode == 0 and os.path.exists(fp) and open(fp, "rb").read() == data
            t.record(ok, lab + " unar extracts it", (r.stdout + r.stderr).decode(errors="replace")[-200:])

    # ------------------------------------------------ RAR 3.x variant
    rar_cases = [("8:1:0", 101, "text", 300000), ("6:16:0", 2, "mixed", 400000),
                 ("4:1:50000,0:0:60000,0:0:0", 32, "mixed", 300000),
                 ("64:2:100000,25:1:0", 0, "mixed", 400000), ("2:1:0", 255, "allbytes", 40000),
                 ("16:1:0", 7, "mixed", 3000000), ("40:1:1000000,0:0:0", 1, "mixed", 2500000),
                 ("10:1:700000,3:2:700000,0:0:0", 2, "mixed", 2000000), ("5:1:0", 2, "text", 0)]
    if not has_rar3:
        t.record(True, "7-Zip has no Rar3 codec (Debian: apt-get install 7zip-rar): RAR checked by unar only")
    rar_streams, rar_sizes = [], []
    for i, (spec, esc, kind, n) in enumerate(rar_cases):
        data = blob(kind, sz(n) if n else 0, 500 + i)
        lab = "rar ppm %s esc%d %d" % (spec, esc, len(data))
        _, rc, out = D("erar", spec, esc, wr("r.raw", data), t.path("r.pk"))
        if rc != 0:
            t.record(False, lab + " encode", out)
            continue
        pk = rd("r.pk")
        rar_streams.append(pk)
        rar_sizes.append(len(data))
        _, rc, out = D("drar", len(data), t.path("r.pk"), t.path("r.out"))
        t.record(rc == 0 and rd("r.out") == data, lab + " decode", out)
        arc = wr("r%d.rar" % i, make_rar3("f.txt", data, pk))
        if has_rar3:
            r, outdir = t.sevenzip_extract(arc)
            fp = os.path.join(outdir, "f.txt")
            ok = r.returncode == 0 and os.path.exists(fp) and open(fp, "rb").read() == data
            t.record(ok, lab + " 7-Zip Rar3 agrees", "" if ok else r.stdout.decode(errors="replace")[-300:])
        if has_unar:
            od = t.path("unar_r")
            shutil.rmtree(od, ignore_errors=True)
            r = subprocess.run(["unar", "-q", "-f", "-o", od, arc], capture_output=True, timeout=300)
            fp = os.path.join(od, "f.txt")
            ok = r.returncode == 0 and os.path.exists(fp) and open(fp, "rb").read() == data
            t.record(ok, lab + " unar agrees", (r.stdout + r.stderr).decode(errors="replace")[-200:])
        # corrupt / truncated RAR PPM data must fail cleanly
        if len(pk) > 20:
            bad = bytearray(pk)
            bad[len(bad) // 2] ^= 0x10
            code, rc, out = D("drar", len(data), wr("rbad.pk", bytes(bad)), t.path("rbad.out"), timeout=60)
            t.record(code in (0, 1), lab + " bit flip handled", out)
            code, rc, out = D("drar", len(data), wr("rcut.pk", pk[:len(pk) // 3]), t.path("rcut.out"), timeout=60)
            t.record(code == 1, lab + " truncation detected", out)

    # PPM block headers the RAR decoder rejects (rc_init / model errors)
    for lab, payload, want in (("continue without a model", b"\x85" + bytes(8), 3),
                               ("reset with order 1", b"\xa0\x00" + bytes(8), 3),
                               ("start code 0xFFFFFFFF", b"\xa5\x00\xff\xff\xff\xff" + bytes(8), 3),
                               ("truncated start code", b"\xa5\x00\x00\x00", 9)):
        code, rc, out = D("drar", 100, wr("rhdr.pk", payload), t.path("rhdr.out"), timeout=60)
        t.record(code == 1 and rc == want, "rar ppm header: " + lab, out)

    # range decoder against the Python port of unrar's RangeCoder
    streams = [random.Random(9).randbytes(40000), bytes(20000), b"\xff" * 100, b"\x7f\xff\xff\xff" + bytes(1000)]
    streams += [s[3:] for s in rar_streams[:3]]            # range-coded bytes of real RAR PPM blocks
    for si, st in enumerate(streams):
        nops = 0
        err = None
        for seed in range(1, 41):
            r = subprocess.run([drv, "rctest", str(seed * 2654435761 % (1 << 32)), "4000", wr("rc.bin", st)],
                               capture_output=True, timeout=60)
            recs = [tuple(int(x) for x in line.split()) for line in r.stdout.decode().splitlines() if line.strip()]
            nops += len(recs)
            err = rar_rc_replay(st, recs) if recs else "no records"
            if err:
                err = "seed %d: %s" % (seed, err)
                break
        t.record(err is None, "rar range decoder vs unrar-style reference, stream %d (%d ops)" % (si, nops), err or "")

    # ------------------------------------------------ hostile input
    base = blob("mixed", sz(300000), 42)
    if pp:
        s7 = py7_enc(pp, base, 8, 1 << 16)
        s8 = py8_enc(pp, base, 8, 1, 1)
    else:
        D("e7", 8, 1 << 16, wr("h.raw", base), t.path("h7.enc"))
        D("e8", 8, 1, 1, t.path("h.raw"), t.path("h8.enc"))
        s7, s8 = rd("h7.enc"), rd("h8.enc")
    wr("h7.ppmd", s7)
    wr("h8.ppmd", s8)
    iters = 60 if SAN else 300
    code, rc, out = D("fuzz7", 8, 1 << 16, len(base), iters, 1, t.path("h7.ppmd"), timeout=900)
    t.record(code == 0 and "fuzz ok" in out, "ppmd7 fuzz (truncation, bit flips)", out)
    code, rc, out = D("fuzz8", len(base), iters, 2, t.path("h8.ppmd"), timeout=900)
    t.record(code == 0 and "fuzz ok" in out, "ppmd8 fuzz (truncation, bit flips)", out)
    small = blob("text", 3000, 3)
    if pp:
        tiny7 = py7_enc(pp, small, 4, 2048)
        tiny8 = py8_enc(pp, small, 4, 1, 0)
        code, rc, out = D("fuzz7", 4, 2048, len(small), iters * 4, 3, wr("t7.ppmd", tiny7), timeout=900)
        t.record(code == 0, "ppmd7 fuzz small model", out)
        code, rc, out = D("fuzz8", len(small), iters * 4, 4, wr("t8.ppmd", tiny8), timeout=900)
        t.record(code == 0, "ppmd8 fuzz small stream", out)
    # RAR PPM blocks: one model, a model kept across blocks, new models, small and 2 MiB memory
    for k in (0, 2, 3):
        if k < len(rar_streams) and rar_sizes[k]:
            pk = rar_streams[k][:60000] if not SAN else rar_streams[k][:20000]
            code, rc, out = D("fuzzrar", rar_sizes[k], iters, 5 + k, wr("rf.pk", pk), timeout=900)
            t.record(code == 0 and "fuzz ok" in out, "rar ppm fuzz stream %d" % k, out)

    E = {"DATA": 3, "METHOD": 5, "TRUNC": 9, "SKIP": 10, "LIMIT": 15}
    hostile = [
        ("7z first byte not 0", ["d7", 6, 1 << 20, 100], b"\x01" + s7[1:], E["DATA"]),
        ("7z code 0xFFFFFFFF", ["d7", 6, 1 << 20, 100], b"\x00\xff\xff\xff\xff" + s7[5:], E["DATA"]),
        ("7z empty input", ["d7", 6, 1 << 20, 100], b"", E["TRUNC"]),
        ("7z order 1", ["d7", 1, 1 << 20, 100], s7, E["METHOD"]),
        ("7z order 65", ["d7", 65, 1 << 20, 100], s7, E["METHOD"]),
        ("7z mem 2047", ["d7", 6, 2047, 100], s7, E["METHOD"]),
        ("7z mem above format max", ["d7", 6, 0xFFFFFFFF, 100], s7, E["METHOD"]),
        ("7z mem 3 GiB (cap)", ["d7", 6, 3 << 30, 100], s7, E["LIMIT"]),
        ("7z mem 2 GiB + 4 (cap)", ["d7", 6, (2 << 30) + 4, 100], s7, E["LIMIT"]),
        ("7z huge size, short input", ["d7", 8, 1 << 16, 1 << 40], s7, E["TRUNC"]),
        ("7z unknown size, no end marker", ["d7", 8, 1 << 16, "u"], s7, E["TRUNC"]),
        ("7z zero stream, unknown size", ["d7", 6, 1 << 20, "u"], bytes(5000), None),
        ("7z garbage, unknown size", ["d7", 6, 1 << 20, "u"], b"\x00" + random.Random(1).randbytes(20000), None),
        # no end marker in 7z: with the coder exactly finished one more symbol may decode
        # without input (7-Zip accepts it too; the container CRC catches it)
        ("7z size beyond data", ["d7", 8, 1 << 16, len(base) + 1], s7, "any"),
        ("zip header order 1", ["d8", 100], b"\xf0\x00" + s8[2:], E["DATA"]),
        ("zip restore method 3", ["d8", 100], bytes([s8[0], s8[1] | 0x30]) + s8[2:], E["METHOD"]),
        ("zip header only", ["d8", 100], s8[:2], E["TRUNC"]),
        ("zip one byte", ["d8", 100], s8[:1], E["TRUNC"]),
        ("zip code 0xFFFFFFFF", ["d8", 100], s8[:2] + b"\xff\xff\xff\xff" + s8[6:], E["DATA"]),
        ("zip missing end marker", ["d8", len(base)], s8[:-6], None),
        ("zip size shorter than data", ["d8", len(base) - 1], s8, E["DATA"]),
        ("zip garbage, unknown size", ["d8", "u"], b"\x37\x10" + random.Random(2).randbytes(30000), None),
        ("zip max memory header, garbage", ["d8", "u"], b"\xff\x2f" + random.Random(3).randbytes(3000), None),
    ]
    for lab, args, payload, want in hostile:
        fn = wr("host.bin", payload)
        try:
            code, rc, out = D(*(list(args) + [fn, t.path("host.out")]), timeout=120)
        except subprocess.TimeoutExpired:
            t.record(False, "hostile " + lab, "timeout")
            continue
        ok = code in (0, 1) and rc is not None and (want == "any" or (rc == want if want is not None else rc != 0))
        t.record(ok, "hostile " + lab, out)
    # sink errors come back unchanged and stop decoding
    _, rc, out = D("d7", 8, 1 << 16, len(base), t.path("h7.ppmd"), t.path("skip.out"), env={"PPMD_FAIL_AFTER": "0"})
    t.record(rc == E["SKIP"], "ppmd7 sink GZ_E_SKIP propagated", out)
    _, rc, out = D("d8", len(base), t.path("h8.ppmd"), t.path("skip.out"), env={"PPMD_FAIL_AFTER": "0"})
    t.record(rc == E["SKIP"], "ppmd8 sink GZ_E_SKIP propagated", out)
    _, rc, out = D("e7", 6, 1 << 20, t.path("h.raw") if os.path.exists(t.path("h.raw")) else wr("h.raw", base),
                   t.path("skip.out"), env={"PPMD_FAIL_AFTER": "0"})
    t.record(rc == E["SKIP"], "ppmd7 encoder sink error propagated", out)

    # ------------------------------------------------ other builds: 32-bit and AArch64 (qemu)
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    targets = []
    if not SAN and shutil.which("gcc"):
        targets.append(("m32", ["gcc", "-m32"], []))
    if not SAN and shutil.which("aarch64-linux-gnu-gcc") and shutil.which("qemu-aarch64"):
        targets.append(("aarch64", ["aarch64-linux-gnu-gcc"],
                        ["qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"]))
    xdata = blob("mixed", 800000, 61)
    wr("x.raw", xdata)
    # (command, input) pairs whose output the cross builds must reproduce byte for byte
    xjobs = [("e7 o4 2K", ["e7", 4, 2048], "x.raw"), ("e7 o32 1M", ["e7", 32, 1 << 20], "x.raw"),
             ("e8 o8 1M cut-off", ["e8", 8, 1, 1], "x.raw"), ("e8 o6 1M freeze", ["e8", 6, 1, 2], "x.raw"),
             ("e8 o4 1M restart", ["e8", 4, 1, 0], "x.raw"),
             ("erar", ["erar", "12:1:300000,0:0:100000,5:1:0", 7], "x.raw")]
    host_out = {}
    for i, (lab, args, src_name) in enumerate(xjobs):
        D(*(args + [t.path(src_name), t.path("xh_%d" % i)]))
        host_out[lab] = rd("xh_%d" % i)
    for tag, cc, runner in targets:
        exe = t.path("ppmd_test_" + tag)
        r = subprocess.run(cc + ["-std=gnu11", "-O2", "-DPPMD_TEST_STANDALONE",
                                 "-I" + os.path.join(root, "src/core"), "-I" + os.path.join(root, "src/codec"),
                                 "-o", exe, os.path.join(root, "tests/drivers/ppmd_test.c"),
                                 os.path.join(root, "src/codec/ppmd7.c"), os.path.join(root, "src/codec/ppmd8.c")],
                           capture_output=True)
        if r.returncode:
            if tag == "m32":
                t.record(True, "m32: no multilib, 32-bit run skipped")
                continue
            t.record(False, tag + " build", r.stderr.decode(errors="replace")[-300:])
            continue

        def X(*args, timeout=900):
            rr = subprocess.run(runner + [exe] + [str(a) for a in args], capture_output=True, timeout=timeout)
            o = rr.stdout.decode(errors="replace").strip()
            rcx = None
            for tok in o.split():
                if tok.startswith("rc="):
                    rcx = int(tok[3:])
            return rcx, o + rr.stderr.decode(errors="replace")[-300:]

        for lab, args, src_name in xjobs:
            rcx, out = X(*(args + [t.path(src_name), t.path("xc.out")]))
            t.record(rcx == 0 and rd("xc.out") == host_out[lab], "%s %s identical to host" % (tag, lab), out)
        # decoders on the same streams
        for lab, args in (("d7 o4 2K", ["d7", 4, 2048, len(xdata)]), ("d7 o32 1M", ["d7", 32, 1 << 20, len(xdata)]),
                          ("d8 cut-off", ["d8", len(xdata)]), ("d8 freeze", ["d8", "u"]),
                          ("drar", ["drar", len(xdata)])):
            stream = host_out[{"d7 o4 2K": "e7 o4 2K", "d7 o32 1M": "e7 o32 1M", "d8 cut-off": "e8 o8 1M cut-off",
                               "d8 freeze": "e8 o6 1M freeze", "drar": "erar"}[lab]]
            rcx, out = X(*(args + [wr("xc.pk", stream), t.path("xc.out")]))
            t.record(rcx == 0 and rd("xc.out") == xdata, "%s %s" % (tag, lab), out)
        if has7z and os.path.exists(t.path("s32_24.7z")):
            rcx, out = X("7z", t.path("s32_24.7z"), t.path("xc.out"))
            t.record(rcx == 0 and rd("xc.out") == rd("src.bin"), tag + " 7-Zip 7z o=32 mem=2^24", out)
            for zn in ("zmmPPMdo16mem1ma1.zip", "zmmPPMdmx9.zip"):      # cut-off with exhaustion, -mx=9
                if os.path.exists(t.path(zn)):
                    rcx, out = X("zip", t.path(zn), t.path("xc.out"))
                    t.record(rcx == 0 and rd("xc.out") == rd("src.bin"), tag + " 7-Zip " + zn, out)
        if tag == "m32":     # 32-bit memory cap: 1 GiB
            rcx, out = X("d7", 6, (1 << 30) + 4, 100, wr("xc.pk", host_out["e7 o4 2K"]), t.path("xc.out"))
            t.record(rcx == 15, "m32 7z mem 1 GiB + 4 -> GZ_E_LIMIT", out)
            rcx, out = X("d8", 100, wr("xc.pk", b"\xff\x0f" + bytes(100)), t.path("xc.out"))
            t.record(rcx in (3, 9), "m32 zip 256 MiB model allocates", out)

    # ------------------------------------------------ speed (informational)
    if not SAN and has7z:
        big = blob("mixed", 6 << 20, 11) + blob("text", 6 << 20, 12)
        wr("bench.bin", big)
        lines = []
        for o, m in ((6, 24), (32, 24)):
            arc = t.path("bench_o%d.7z" % o)
            if os.path.exists(arc):
                os.remove(arc)
            t0 = time.time()
            t.sh(["7z", "a", "-t7z", "-m0=PPMd:o=%d:mem=%d" % (o, m), "-mmt=1", "-mhc=off", arc, t.path("bench.bin")])
            t7e = time.time() - t0
            t0 = time.time()
            t.sh(["7z", "t", arc])
            t7d = time.time() - t0
            _, rc, oute = D("e7", o, 1 << m, t.path("bench.bin"), t.path("bench.enc"))
            _, rc2, outd = D("7z", arc, t.path("bench.out"))
            ms_e = float(oute.split("ms=")[1].split()[0])
            ms_d = float(outd.split("ms=")[1].split()[0])
            mb = len(big) / 1e6
            lines.append("7z o%d: ours dec %.1f MB/s enc %.1f MB/s | 7-Zip dec %.1f enc %.1f MB/s"
                         % (o, mb / (ms_d / 1e3), mb / (ms_e / 1e3), mb / t7d, mb / t7e))
            if pp and o == 6:
                packed = rd("bench.enc")
                t0 = time.time()
                pp.Ppmd7Decoder(o, 1 << m).decode(packed, len(big))
                tpd = time.time() - t0
                t0 = time.time()
                py7_enc(pp, big, o, 1 << m)
                tpe = time.time() - t0
                lines.append("pyppmd o%d: dec %.1f enc %.1f MB/s" % (o, mb / tpd, mb / tpe))
        arc = t.path("bench.zip")
        if os.path.exists(arc):
            os.remove(arc)
        t0 = time.time()
        t.sh(["7z", "a", "-tzip", "-mm=PPMd", "-mx=9", "-mmt=1", arc, t.path("bench.bin")])
        tze = time.time() - t0
        t0 = time.time()
        t.sh(["7z", "t", arc])
        tzd = time.time() - t0
        _, rc, outd = D("zip", arc, t.path("bench.out"))
        ms_d = float(outd.split("ms=")[1].split()[0])
        lines.append("zip mx9: ours dec %.1f MB/s | 7-Zip dec %.1f enc %.1f MB/s"
                     % (len(big) / 1e6 / (ms_d / 1e3), len(big) / 1e6 / tzd, len(big) / 1e6 / tze))
        t.record(True, "speed", "; ".join(lines))
