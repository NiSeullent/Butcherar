"""BZip2 codec: decoder vs bzip2 / lbzip2 / pbzip2 / 7-Zip, our encoder vs bzip2 -d,
concatenated streams, tarballs, the NSIS variant, crafted hostile streams, fuzzing, speed."""
import os, io, random, shutil, subprocess, tarfile, time

def blob(kind, n, seed=1):
    rnd = random.Random(seed * 7919 + n)
    if kind == "rand":
        return rnd.randbytes(n)
    if kind == "text":
        words = [b"gogi", b"samgyeopsal", b"moksal", b"galbi", b"archive", b"bzip2", b"\n", b"the", b"of",
                 "고기".encode(), "압축".encode(), b"and", b"zip"]
        out = bytearray()
        while len(out) < n:
            out += rnd.choice(words) + b" "
        return bytes(out[:n])
    if kind == "runs":          # runs around the RLE1 limits (4, 255, 256 ...)
        out = bytearray()
        while len(out) < n:
            out += bytes([rnd.randrange(4)]) * rnd.choice([1, 2, 3, 4, 5, 6, 250, 251, 254, 255, 256, 257, 259, 1000, 4000])
        return bytes(out[:n])
    if kind == "binary":        # mixed structure: words, small ints, zero padding
        out = bytearray()
        while len(out) < n:
            k = rnd.randrange(4)
            if k == 0: out += rnd.randrange(1 << 32).to_bytes(4, "little") * rnd.randrange(1, 9)
            elif k == 1: out += bytes(rnd.randrange(64))
            elif k == 2: out += bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 40)))
            else: out += b"\x8b\x45\xfc\x89\x45\xf8" * rnd.randrange(1, 5)
        return bytes(out[:n])
    if kind == "period":        # periodic data: worst case for comparison-based BWT sorts
        unit = rnd.randbytes(rnd.randrange(2, 9))
        return (unit * (n // len(unit) + 1))[:n]
    raise ValueError(kind)

def fib_word(n):
    a, b = b"a", b"ab"
    while len(b) < n:
        a, b = b, b + a
    return b[:n]

# ---------------- tiny bzip2 writer for crafting hostile streams ----------------

def crc_be(data, crc=0xFFFFFFFF):
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 else (crc << 1) & 0xFFFFFFFF
    return crc

class Bits:
    def __init__(self):
        self.v, self.n, self.out = 0, 0, bytearray()
    def put(self, n, v):
        for i in range(n - 1, -1, -1):
            self.v = (self.v << 1) | ((v >> i) & 1)
            self.n += 1
            if self.n == 8:
                self.out.append(self.v); self.v = self.n = 0
    def done(self):
        if self.n:
            self.put(8 - self.n, 0)
        return bytes(self.out)

def craft(data, **m):
    """Single-block bzip2 stream of data (< 1000 bytes, no RLE1 runs needed). Keyword
    arguments corrupt one field: orig, ngroups, nsel, sel_bad, len_start, len_walk,
    oversub, inuse_empty, runb, crc, no_eob, combined."""
    blk = bytes(data)
    n = len(blk)
    rots = sorted(range(n), key=lambda i: blk[i:] + blk[:i])
    L = bytes(blk[(i - 1) % n] for i in rots)
    orig = rots.index(0)
    used = sorted(set(blk))
    seq = {b: i for i, b in enumerate(used)}
    alpha = len(used) + 2
    mtf, syms, z = list(range(len(used))), [], 0
    def flush(z):
        if z:
            z -= 1
            while True:
                syms.append(z & 1)
                if z < 2: break
                z = (z - 2) // 2
    for b in L:
        c = seq[b]
        if mtf[0] == c:
            z += 1; continue
        flush(z); z = 0
        j = mtf.index(c); mtf.pop(j); mtf.insert(0, c)
        syms.append(j + 1)
    flush(z)
    if "runb" in m:
        syms = [1] * 40 + syms
    if not m.get("no_eob"):
        syms.append(alpha - 1)
    # complete code with lengths k and k+1
    k = max(1, (alpha - 1).bit_length() - 1)
    nlong = 2 * (alpha - (1 << k)) if alpha > (1 << k) else 0
    lens = [k] * (alpha - nlong) + [k + 1] * nlong
    if m.get("oversub"):
        lens = [1] * alpha
    codes, code = {}, 0
    for ln in range(1, 21):
        for s in range(alpha):
            if lens[s] == ln:
                codes[s] = (code, ln); code += 1
        code <<= 1
    w = Bits()
    w.put(32, 0x425A6839)
    w.put(24, 0x314159); w.put(24, 0x265359)
    bcrc = crc_be(blk) ^ 0xFFFFFFFF
    w.put(32, m.get("crc", bcrc))
    w.put(1, 0)
    w.put(24, m.get("orig", orig))
    if m.get("inuse_empty"):
        w.put(16, 0)
    else:
        u16 = 0
        for b in used: u16 |= 0x8000 >> (b >> 4)
        w.put(16, u16)
        for i in range(16):
            if u16 & (0x8000 >> i):
                v = 0
                for b in used:
                    if b >> 4 == i: v |= 0x8000 >> (b & 15)
                w.put(16, v)
    ng = m.get("ngroups", 2)
    nsel = m.get("nsel", (len(syms) + 49) // 50)
    w.put(3, ng); w.put(15, nsel)
    for i in range(nsel):
        j = 6 if (m.get("sel_bad") and i == nsel - 1) else 0
        w.put(j + 1, ((1 << j) - 1) << 1)
    for t in range(max(ng, 2) if ng <= 6 else 2):
        cur = m.get("len_start", lens[0])
        w.put(5, cur)
        for s in range(alpha):
            if m.get("len_walk") and t == 0 and s == 1:
                for _ in range(25): w.put(2, 2)        # walks past 20
            while cur < lens[s]: w.put(2, 2); cur += 1
            while cur > lens[s]: w.put(2, 3); cur -= 1
            w.put(1, 0)
    for s in syms:
        c, ln = codes[s]
        w.put(ln, c)
    w.put(24, 0x177245); w.put(24, 0x385090)
    w.put(32, m.get("combined", bcrc))
    return w.done()

def run(t):
    t.need("bzip2")
    D = t.build_driver("tests/drivers/bzip2_test.c")
    W = t.work
    def drv(*args, timeout=600):
        r = t.sh([D] + [str(a) for a in args], check=False, timeout=timeout)
        return r.returncode, r.stdout.decode(errors="replace").strip()
    def rc_of(out):
        p = out.split()
        return int(p[1]) if len(p) > 1 and p[0] == "RC" else None
    def put(name, data):
        p = t.path(name)
        with open(p, "wb") as f: f.write(data)
        return p
    def bz(data, *opts, tool="bzip2"):
        return t.sh([tool, "-c"] + list(opts), input=data).stdout
    def cleanup():
        # extraction results and decoded copies are big; fixtures stay for debugging
        for f in os.listdir(W):
            fp = os.path.join(W, f)
            if f.startswith("out_") and os.path.isdir(fp):
                shutil.rmtree(fp, ignore_errors=True)
            elif f.endswith((".out", ".bin")) and os.path.isfile(fp) and os.path.getsize(fp) > 200000:
                os.remove(fp)
    def hostile(p, label=None):
        # like t.check_hostile, but gzt's own context leak on a failed open (tests/gzt.c) must not
        # count: leak checking is off for these runs only (memory errors and UB still fail);
        # codec leaks are covered by the in-process fuzz driver, which runs with leak checks
        env = {"ASAN_OPTIONS": (os.environ.get("ASAN_OPTIONS", "") + ":detect_leaks=0").lstrip(":")}
        label = label or "hostile " + os.path.basename(p)
        try:
            r, rows, out = t.extract(p, timeout=120, env=env)
        except subprocess.TimeoutExpired:
            return t.record(False, label, "timeout")
        err = r.stderr.decode(errors="replace")
        bad = r.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err
        return t.record(not bad, label, "rc=%d %s" % (r.returncode, err[-300:] if bad else ""))

    samples = {
        "empty": b"", "one": b"x", "two": b"ab", "aaaa": b"aaaa", "aaaa5": b"aaaaa",
        "text": blob("text", 1500000), "rand": blob("rand", 300000), "runs": blob("runs", 1200000),
        "binary": blob("binary", 1000000), "period": blob("period", 950000),
        "zeros": bytes(2000000), "run255": b"q" * 255, "run256": b"q" * 256, "run259": b"q" * 259,
        "alphabet": bytes(range(256)) * 50,
        # highly repetitive blocks: slow paths of comparison sorts, deep SA-IS recursion
        "period3": (b"abc" * 400000)[:1100000], "zzz1": b"\0\0\0\1" * 250000,
        "fib": fib_word(1000000), "abab": b"ab" * 500000 + b"a",
    }

    # 1) reference streams at every level through the stream format (gzt x)
    for name, data in samples.items():
        levels = range(1, 10) if name in ("text", "runs", "binary") else (1, 9)
        for lv in levels:
            p = put("ref_%s_%d.bz2" % (name, lv), bz(data, "-%d" % lv))
            t.check_extract(p, {"ref_%s_%d" % (name, lv): data}, expect_type="BZIP2",
                            label="bzip2 -%d %s" % (lv, name))

    # 2) lbzip2 / pbzip2 / 7-Zip outputs (pbzip2 and lbzip2 write several streams)
    big = blob("text", 3000000, 5) + blob("binary", 1500000, 6)
    for tool, opts in (("lbzip2", ["-9", "-n", "4"]), ("lbzip2", ["-1"]), ("pbzip2", ["-9", "-p4"]),
                       ("pbzip2", ["-1", "-b3"])):
        if not t.tool(tool):
            t.record(True, "%s missing (skipped)" % tool); continue
        p = put("%s_%s.bz2" % (tool, opts[0][1:]), bz(big, *opts, tool=tool))
        t.check_extract(p, {"%s_%s" % (tool, opts[0][1:]): big}, label="%s %s" % (tool, " ".join(opts)))
    if t.tool("7z"):
        for mx, mt in ((9, 1), (5, 4), (1, 2)):
            src = put("sz_in_%d.bin" % mx, big)
            arc = t.path("sz_%d.bz2" % mx)
            if os.path.exists(arc): os.remove(arc)
            t.sh(["7z", "a", "-tbzip2", "-mx=%d" % mx, "-mmt=%d" % mt, arc, src])
            t.check_extract(arc, {"sz_%d" % mx: big}, label="7z -tbzip2 -mx%d -mmt%d" % (mx, mt))

    # 3) concatenated streams (+ trailing garbage, which bzip2 ignores)
    a, b, c = samples["text"][:400000], samples["rand"], samples["runs"][:300000]
    cat = bz(a, "-9") + bz(b, "-1") + bz(b"", "-5") + bz(c, "-3")
    t.check_extract(put("cat.bz2", cat), {"cat": a + b + c}, label="concatenated streams")
    t.check_extract(put("catz.bz2", cat + bytes(100)), {"catz": a + b + c}, label="concatenated + zero padding")
    t.check_extract(put("catg.bz2", cat + b"BZh0garbage"), {"catg": a + b + c}, label="concatenated + garbage")
    # codec API: multi_stream = 0 stops after the first stream, in_used is exact
    first = bz(a, "-9")
    rc, out = drv("dec", put("cat_api.bz2", cat + b"trailer"), t.path("cat_api.out"), 0)
    t.record(rc == 0 and out.split()[:4] == ["RC", "0", "USED", str(len(first))] and
             open(t.path("cat_api.out"), "rb").read() == a, "single stream + in_used", out)
    rc, out = drv("dec", t.path("cat_api.bz2"), t.path("cat_api2.out"), 1)
    t.record(rc == 0 and out.split()[:4] == ["RC", "0", "USED", str(len(cat))] and
             open(t.path("cat_api2.out"), "rb").read() == a + b + c, "multi stream in_used", out)
    # out_size: exact, smaller (stops), larger (stream too short = GZ_E_DATA)
    p = put("osz.bz2", bz(samples["text"], "-2"))
    n = len(samples["text"])
    for want, exp_rc, exp_n in ((n, 0, n), (n - 1, 0, n - 1), (123457, 0, 123457), (0, 0, 0), (n + 1, 3, None)):
        rc, out = drv("dec", p, t.path("osz.out"), 1, want)
        got = open(t.path("osz.out"), "rb").read()
        ok = rc_of(out) == exp_rc and (exp_n is None or got == samples["text"][:exp_n])
        if want == n and ok:
            ok = out.split()[3] == str(os.path.getsize(p))
        t.record(ok, "out_size %d" % want, out)
    # tiny reads (1..7 bytes per read) give the same result
    for name in ("text", "runs", "zeros"):
        p = put("chunk_%s.bz2" % name, bz(samples[name], "-9"))
        rc, out = drv("chunks", p, t.path("chunk_%s.out" % name))
        t.record(rc_of(out) == 0 and open(t.path("chunk_%s.out" % name), "rb").read() == samples[name],
                 "tiny reads %s" % name, out)

    cleanup()

    # 4) tarballs: .tar.bz2 / .tbz2 / .tbz (bzip2 CLI and Python's libbz2)
    files = {"docs/readme.txt": samples["text"][:20000], "docs/고기.txt": "삼겹살".encode() * 3000,
             "bin/data.bin": samples["binary"][:300000], "empty.txt": b"", "docs": None, "bin": None}
    tb = io.BytesIO()
    with tarfile.open(fileobj=tb, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for k in sorted(files):
            ti = tarfile.TarInfo(k)
            if files[k] is None:
                ti.type = tarfile.DIRTYPE; tf.addfile(ti)
            else:
                ti.size = len(files[k]); tf.addfile(ti, io.BytesIO(files[k]))
    tar = tb.getvalue()
    for ext in ("tar.bz2", "tbz2", "tbz"):
        t.check_extract(put("tarball." + ext, bz(tar, "-9")), files, expect_type="TAR.BZ2", label="tarball ." + ext)
    p = t.path("pytar.tar.bz2")
    with tarfile.open(p, "w:bz2", compresslevel=3) as tf:
        for k in sorted(files):
            if files[k] is not None:
                ti = tarfile.TarInfo(k); ti.size = len(files[k]); tf.addfile(ti, io.BytesIO(files[k]))
    t.check_extract(p, {k: v for k, v in files.items() if v is not None}, expect_type="TAR.BZ2", label="python tarfile w:bz2")
    r, typ, rows = t.listing(t.path("tarball.tbz2"))
    t.record(typ == "TAR.BZ2" and any(x["method"] == "BZip2" for x in rows), "listing type/method", "%s %s" % (typ, rows[:1]))

    # 5) our encoder: every level, decoded by bzip2 -d and by our decoder, ratio vs bzip2
    worst = 0.0
    for name, data in samples.items():
        src = put("enc_%s.bin" % name, data)
        levels = range(1, 10) if name in ("text", "binary", "runs") else (1, 9)
        for lv in levels:
            outp = t.path("enc_%s_%d.bz2" % (name, lv))
            rc, out = drv("enc", lv, src, outp)
            if rc_of(out) != 0:
                t.record(False, "encode L%d %s" % (lv, name), out); continue
            ours = open(outp, "rb").read()
            ref = t.sh(["bzip2", "-dc"], input=ours, check=False)
            mine_rc, mine = drv("dec", outp, outp + ".out")
            ok = ref.returncode == 0 and ref.stdout == data and rc_of(mine) == 0 and \
                open(outp + ".out", "rb").read() == data
            rsz = len(bz(data, "-%d" % lv))
            d = 100.0 * (len(ours) - rsz) / max(rsz, 1)
            if len(data) > 100000: worst = max(worst, d)
            t.record(ok and (d < 1.0 or len(data) < 1000), "encode L%d %s" % (lv, name),
                     "%d vs bzip2 %d (%+.3f%%)%s" % (len(ours), rsz, d, "" if ok else " DECODE MISMATCH " + ref.stderr.decode()[-200:]))
    t.record(worst < 1.0, "encoder ratio within 1% of bzip2", "worst %+.3f%%" % worst)
    src = t.path("enc_text.bin")
    rc, out = drv("enc", 9, src, t.path("enc_reuse.bz2"), "-", "again")
    t.record(rc == 0 and rc_of(out) == 0, "encoder object reuse", out)
    rc, out = drv("enc", 5, src, t.path("enc_tiny.bz2"), "tiny")
    t.record(rc_of(out) == 0 and t.sh(["bzip2", "-dc", t.path("enc_tiny.bz2")]).stdout == samples["text"],
             "encoder with tiny reads", out)
    if t.tool("7z"):
        r = t.sh(["7z", "t", t.path("enc_binary_9.bz2")], check=False)
        t.record(r.returncode == 0, "7z t accepts our stream", r.stdout.decode(errors="replace")[-200:])
    # stream format front end on our own output (bz2 + tarball)
    t.check_extract(t.path("enc_text_9.bz2"), {"enc_text_9": samples["text"]}, label="gzt x on our .bz2")
    tsrc = put("enc_tar.bin", tar)
    rc, out = drv("enc", 9, tsrc, t.path("enc_tar.tar.bz2"))
    t.check_extract(t.path("enc_tar.tar.bz2"), files, expect_type="TAR.BZ2", label="gzt x on our .tar.bz2")

    # 5b) in-process self test: thousands of generated strings (alphabets of 1..256 symbols,
    #     periodic, Fibonacci, runs, x^k y patterns) through encoder + decoder
    for iters, maxlen, seed in ((6000, 5000, 11), (40, 1000000, 12)):
        rc, out = drv("selftest", iters, maxlen, seed, timeout=1800)
        t.record(rc == 0 and out.endswith("0 failures"), "self test %d x <= %d bytes" % (iters, maxlen), out[-300:])

    # 6) randomized blocks (bzip2 0.9.0): written by the encoder's test switch
    for name in ("text", "runs", "period", "one", "run259"):
        src = t.path("enc_%s.bin" % name)
        outp = t.path("rand_%s.bz2" % name)
        rc, out = drv("enc", 9, src, outp, "rand")
        ref = t.sh(["bzip2", "-dc", outp], check=False)
        mine_rc, mine = drv("dec", outp, outp + ".out")
        t.record(ref.returncode == 0 and ref.stdout == samples[name] and rc_of(mine) == 0 and
                 open(outp + ".out", "rb").read() == samples[name], "randomized block %s" % name, mine)

    cleanup()

    # 7) NSIS variant (makensis "SetCompressor bzip2"): non-solid blocks and one solid stream
    if t.tool("makensis"):
        import struct
        payload = samples["text"][:700000] + samples["binary"][:200000]
        nd = t.path("nsis")
        put("nsis/payload.bin", payload)
        for solid in (0, 1):
            with open(os.path.join(nd, "s%d.nsi" % solid), "w") as f:
                f.write('SetCompressor %sbzip2\nOutFile "s%d.exe"\nSection\nSetOutPath $INSTDIR\nFile payload.bin\nSectionEnd\n'
                        % ("/SOLID " if solid else "", solid))
            t.sh(["makensis", "-V1", "s%d.nsi" % solid], cwd=nd)
            exe = open(os.path.join(nd, "s%d.exe" % solid), "rb").read()
            fh = exe.find(b"\xef\xbe\xad\xdeNullsoftInst") - 4
            hlen, total = struct.unpack_from("<II", exe, fh + 20)
            pos, ok, info = fh + 28, False, ""
            if solid:
                p = put("nsis/solid.bin", exe[pos:])
                rc, out = drv("nsis", p, 0, p + ".out")
                dec = open(p + ".out", "rb").read()
                if rc_of(out) == 0 and len(dec) >= 4 + hlen + 4:
                    fl, = struct.unpack_from("<I", dec, 4 + hlen)
                    ok = dec[8 + hlen: 8 + hlen + fl] == payload
                info = out
            else:
                blocks = []
                for k in range(2):
                    ln, = struct.unpack_from("<I", exe, pos)
                    blocks.append(exe[pos + 4: pos + 4 + (ln & 0x7fffffff)])
                    pos += 4 + (ln & 0x7fffffff)
                p = put("nsis/file.bin", blocks[1] + b"tail")
                rc, out = drv("nsis", p, 0, p + ".out")
                ok = rc_of(out) == 0 and open(p + ".out", "rb").read() == payload and out.split()[3] == str(len(blocks[1]))
                p0 = put("nsis/hdr.bin", blocks[0])
                rc0, out0 = drv("nsis", p0, 0, p0 + ".out", hlen)
                ok = ok and rc_of(out0) == 0 and os.path.getsize(p0 + ".out") == hlen
                info = out + " / " + out0
            t.record(ok, "NSIS bzip2 %s" % ("solid" if solid else "non-solid"), info)
    else:
        t.record(True, "makensis missing (NSIS variant skipped)")

    # 8) crafted hostile streams: exact error codes from the codec, no crash through gzt
    msg = b"hostile bzip2 streams must fail cleanly: " + bytes(range(32, 127))
    good = craft(msg)
    r = t.sh(["bzip2", "-dc"], input=good, check=False)
    t.record(r.returncode == 0 and r.stdout == msg, "crafter sanity (bzip2 -d)")
    E_DATA, E_CRC, E_TRUNC, E_FORMAT = 3, 4, 9, 2
    cases = [
        ("good", {}, 0),
        ("huge origPtr", {"orig": 0xFFFFFF}, E_DATA),
        ("origPtr == n", {"orig": len(msg)}, E_DATA),
        ("ngroups 1", {"ngroups": 1}, E_DATA),
        ("ngroups 7", {"ngroups": 7}, E_DATA),
        ("nselectors 0", {"nsel": 0}, E_DATA),
        ("too few selectors", {"nsel": 1}, E_DATA),
        ("selector >= ngroups", {"sel_bad": 1}, E_DATA),
        ("length start 0", {"len_start": 0}, E_DATA),
        ("length start 21", {"len_start": 21}, E_DATA),
        ("length walks past 20", {"len_walk": 1}, E_DATA),
        ("over-subscribed code", {"oversub": 1}, E_DATA),
        ("empty symbol map", {"inuse_empty": 1}, E_DATA),
        ("RUNB overflow", {"runb": 1}, E_DATA),
        ("missing EOB", {"no_eob": 1}, None),
        ("bad block CRC", {"crc": 0x12345678}, E_CRC),
        ("bad stream CRC", {"combined": 0x12345678}, E_CRC),
    ]
    for label, mods, want in cases:
        p = put("craft_%s.bz2" % label.replace(" ", "_").replace(">=", "ge").replace("==", "eq"), craft(msg, **mods))
        rc, out = drv("dec", p, p + ".out")
        got = rc_of(out)
        t.record(rc == 0 and (got == want if want is not None else got not in (None, 0)), "crafted: " + label, out)
        hostile(p, label="gzt crafted: " + label)
    good_p = t.path("craft_good.bz2")
    for cut in (3, 4, 9, 10, 14, len(good) - 5, len(good) - 1):
        p = put("trunc_%d.bz2" % cut, good[:cut])
        rc, out = drv("dec", p, p + ".out")
        t.record(rc_of(out) in (E_FORMAT, E_TRUNC, E_DATA), "truncated at %d" % cut, out)
    p = put("notbz.bz2", b"BZh9" + b"\x31\x41\x59\x26\x53\x59" + bytes(64))
    rc, out = drv("dec", p, p + ".out")
    t.record(rc_of(out) in (E_DATA, E_TRUNC), "zeroed block", out)
    rc, out = drv("dec", put("nohdr.bz2", b"BZh0" + bytes(20)), t.path("nohdr.out"))
    t.record(rc_of(out) == E_FORMAT, "bad header", out)
    # a real stream with its first block CRC flipped
    rs = bytearray(bz(samples["text"][:200000], "-9"))
    rs[10] ^= 0x40
    p = put("badcrc_real.bz2", bytes(rs))
    rc, out = drv("dec", p, p + ".out")
    t.record(rc_of(out) == E_CRC, "bzip2 stream with flipped block CRC", out)
    hostile(p)

    # 9) fuzzing (in process): truncations, bit flips, byte noise, NSIS mode, tiny reads
    fz = [put("fz_text.bz2", bz(samples["text"][:60000], "-1")), put("fz_runs.bz2", bz(samples["runs"][:80000], "-2")),
          put("fz_rand.bz2", bz(samples["rand"][:20000], "-9")), put("fz_multi.bz2", bz(b"abc" * 999, "-1") + bz(b"xyz", "-1")),
          good_p, t.path("rand_period.bz2")]
    iters = int(os.environ.get("GZ_FUZZ_ITERS", "1500"))
    for i, p in enumerate(fz):
        try:
            rc, out = drv("fuzz", p, iters, 1000 + i, timeout=900)
        except subprocess.TimeoutExpired:
            rc, out = -1, "timeout"
        t.record(rc == 0 and out.startswith("FUZZ"), "fuzz %s" % os.path.basename(p), out)
    for p in fz[:3]:
        data = bytearray(open(p, "rb").read())
        rnd = random.Random(len(data))
        for k in range(6):
            m = bytearray(data)
            for _ in range(3): m[rnd.randrange(len(m))] ^= 1 << rnd.randrange(8)
            hostile(put("gzfz_%d_%s" % (k, os.path.basename(p)), bytes(m)))

    # 10) speed vs bzip2 (informational; the record fails only if we are much slower)
    sp = put("speed.bin", blob("text", 6000000, 9) + blob("binary", 3000000, 9))
    spz = put("speed.bin.bz2", bz(open(sp, "rb").read(), "-9"))
    rc, dec = drv("bench-dec", spz, 3)
    rc2, enc = drv("bench-enc", 9, sp, 1)
    t0 = time.time(); t.sh(["bzip2", "-dc", spz]); td = time.time() - t0
    t0 = time.time(); t.sh(["bzip2", "-9", "-c", sp]); te = time.time() - t0
    size = os.path.getsize(sp)
    def mbs(s):
        try: return float(s.split()[-2])
        except Exception: return 0.0
    sanitized = "sanitize" in os.environ.get("HOST_CFLAGS", "")
    ok = sanitized or (mbs(dec) > 0.7 * size / td / 1e6 and mbs(enc) > 0.7 * size / te / 1e6)
    t.record(ok, "speed", "decode %.1f MB/s (bzip2 %.1f), encode -9 %.1f MB/s (bzip2 %.1f)" %
             (mbs(dec), size / td / 1e6, mbs(enc), size / te / 1e6))
    cleanup()
