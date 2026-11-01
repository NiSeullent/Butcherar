"""Zstandard / LZ4 / xxHash: decoders vs the zstd and lz4 CLIs, .zst/.lz4 stream formats,
tarballs inside, hostile input (in-process fuzzing), speed report."""
import io, os, random, shutil, struct, subprocess, sys, tarfile, time

# XXH32 / XXH64 (seed 0) of bytes((i * 7 + 3) & 255 for i in range(n)), from the reference implementation
XXH_VECTORS = [
    (0, 0x02cc5d05, 0xef46db3751d8e999),
    (1, 0x21ae663a, 0x1f25c8d0bc1f4bb6),
    (3, 0xcd3d2242, 0x31d2363f52e564c9),
    (4, 0x725479f2, 0x9bb64b7d66ee9fda),
    (15, 0x82d3c84d, 0x1b47cb8243cc8e32),
    (16, 0x8845547d, 0x434850232b787be2),
    (17, 0x450e5f84, 0x1efa7025f1b97a7a),
    (31, 0x1f73d3c7, 0xa2aa5f33cc4a6119),
    (32, 0xe988ccb7, 0x23c3c17ef790fd97),
    (33, 0x94f536d5, 0x50a7cfc7ba588784),
    (100, 0x73091a4d, 0xa61f8d4c170fe531),
    (1000, 0xc85a5152, 0x5f235fa033f1a3fb),
    (65537, 0x5dee75d3, 0x8c846e275f1376ae),
]

GZ_E_DATA, GZ_E_METHOD = 3, 5


def text(n, seed=1):
    rnd = random.Random(seed)
    words = [b"zstd", b"lz4", b"\xea\xb3\xa0\xea\xb8\xb0", b"archive", b"frame", b"block", b"window",
             b"\n", b"  ", b"0123456789", b"literal", b"sequence", b"offset", b"Huffman", b"FSE"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words) + (b" " if rnd.random() < 0.7 else b",")
    return bytes(out[:n])


def noise(n, seed=2):
    return random.Random(seed).randbytes(n)


def mixed(n, seed=3):
    """text, random runs, zero runs, short periods (overlap copies) and far repeats"""
    rnd = random.Random(seed)
    out = bytearray()
    while len(out) < n:
        k = rnd.randrange(6)
        if k == 0:
            out += text(rnd.randrange(100, 20000), rnd.randrange(1000))
        elif k == 1:
            out += noise(rnd.randrange(10, 5000), rnd.randrange(1000))
        elif k == 2:
            out += bytes(rnd.randrange(1, 70000))
        elif k == 3:
            pat = noise(rnd.randrange(1, 16), rnd.randrange(1000))
            out += pat * rnd.randrange(2, 3000)
        elif k == 4 and len(out) > 1000:
            a = rnd.randrange(len(out) - 500)
            out += out[a:a + rnd.randrange(3, 500)]
        else:
            out += bytes([rnd.randrange(256)]) * rnd.randrange(1, 300)
    return bytes(out[:n])


def run(t):
    t.need("zstd", "lz4")
    # GNU ld: route gz_alloc_big through calloc so ASan also guards the window buffers
    wrap = ["-DZT_WRAP_BIG", "-Wl,--wrap=gz_alloc_big", "-Wl,--wrap=gz_free_big"] if sys.platform.startswith("linux") else []
    drv = t.build_driver("tests/drivers/zstd_test.c", extra=wrap)
    sanitized = "sanitize" in os.environ.get("HOST_CFLAGS", "")
    W = t.work

    def wfile(name, data):
        p = t.path(name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def drv_run(*args, timeout=600):
        r = subprocess.run([drv] + [str(a) for a in args], capture_output=True, timeout=timeout)
        out = (r.stdout + r.stderr).decode(errors="replace")
        return r.returncode, out

    def check_dec(arc, raw_path, label):
        """driver: chunked reads, in_used, out_size limits, sink errors, memory API"""
        try:
            rc, out = drv_run("dec", arc, raw_path)
        except subprocess.TimeoutExpired:
            return t.record(False, label, "timeout")
        return t.record(rc == 0 and out.startswith("OK"), label, out.strip()[-300:])

    def check_err(arc, want, label):
        rc, out = drv_run("err", arc)
        got = out.split()[1] if out.startswith("RESULT") else out
        ok = (got == str(want)) if not callable(want) else want(int(got) if got.isdigit() else -1)
        return t.record(ok, label, out.strip()[-200:])

    def hostile(p, timeout=120):
        """gzt x must not crash or hang. Leak detection is off for gzt only: it does not free
        its gz_ctx when opening fails (tests/gzt.c); the codecs themselves are leak-checked
        by the in-process fuzzer below."""
        label = "hostile " + os.path.basename(p)
        try:
            r, rows, out = t.extract(p, timeout=timeout, env={"ASAN_OPTIONS": "detect_leaks=0"})
        except subprocess.TimeoutExpired:
            return t.record(False, label, "timeout")
        err = r.stderr.decode(errors="replace")
        bad = r.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err
        return t.record(not bad, label, "rc=%d %s" % (r.returncode, err[-300:] if bad else ""))

    def zstd(args, src, dst, stdin=False):
        if stdin:
            with open(src, "rb") as f:
                data = f.read()
            r = t.sh(["zstd", "-q", "-c"] + args, input=data)
            with open(dst, "wb") as f:
                f.write(r.stdout)
        else:
            t.sh(["zstd", "-q", "-f"] + args + [src, "-o", dst])
        return dst

    def lz4(args, src, dst):
        t.sh(["lz4", "-q", "-f"] + args + [src, dst])
        return dst

    samples = {
        "empty": b"",
        "one": b"x",
        "small": text(100),
        "text": text(3 << 20),
        "noise": noise(1 << 20),
        "mixed": mixed(4 << 20),
        "zeros": bytes(2 << 20),
    }
    raw = {k: wfile("raw_%s.bin" % k, v) for k, v in samples.items()}

    # ---------------- xxHash ----------------
    bad = []
    for n, h32, h64 in XXH_VECTORS:
        p = wfile("xxh_%d.bin" % n, bytes((i * 7 + 3) & 255 for i in range(n)))
        rc, out = drv_run("xxh", p)
        f = out.split()
        want = ["%08x" % h32, "%016x" % h64] * 2
        if f != want:
            bad.append("%d: %s" % (n, out.strip()))
    try:
        import xxhash
        for k in ("text", "mixed"):
            rc, out = drv_run("xxh", raw[k])
            d = samples[k]
            want = ["%08x" % xxhash.xxh32(d).intdigest(), "%016x" % xxhash.xxh64(d).intdigest()] * 2
            if out.split() != want:
                bad.append("%s: %s" % (k, out.strip()))
    except ImportError:
        pass
    t.record(not bad, "xxhash32/64 vectors (one-shot + streamed)", "; ".join(bad))

    # ---------------- Zstandard vs zstd CLI ----------------
    fuzz_zst = []
    for name in samples:
        for lvl in (1, 3, 19):
            arc = zstd(["-%d" % lvl], raw[name], t.path("%s.L%d.zst" % (name, lvl)))
            check_dec(arc, raw[name], "zstd -%d %s" % (lvl, name))
            if lvl == 3:
                fuzz_zst.append(arc)
        t.check_extract(t.path("%s.L3.zst" % name), {"%s.L3" % name: samples[name]}, expect_type="ZSTD",
                        label="gzt x %s.L3.zst" % name)
    # --ultra -22 (big window, long matches, many FSE tables)
    for name in ("text", "mixed"):
        arc = zstd(["--ultra", "-22"], raw[name], t.path("%s.L22.zst" % name))
        check_dec(arc, raw[name], "zstd --ultra -22 %s" % name)
    fuzz_zst.append(t.path("mixed.L22.zst"))
    # no content size (stdin and --no-content-size), no checksum
    for name in ("text", "mixed", "zeros", "empty"):
        arc = zstd(["-3"], raw[name], t.path("%s.stdin.zst" % name), stdin=True)
        check_dec(arc, raw[name], "zstd stdin (no content size) %s" % name)
        arc = zstd(["-5", "--no-content-size", "--no-check"], raw[name], t.path("%s.nocs.zst" % name))
        check_dec(arc, raw[name], "zstd --no-content-size --no-check %s" % name)
    t.check_extract(t.path("mixed.stdin.zst"), {"mixed.stdin": samples["mixed"]}, label="gzt x mixed.stdin.zst")
    fuzz_zst.append(t.path("mixed.nocs.zst"))
    # small windows: the circular window buffer wraps; matches straddle the segments
    rep = noise(600 << 10, 7) * 6 + text(500 << 10)
    rp = wfile("raw_rep.bin", rep)
    for wl in (10, 17, 20):
        arc = zstd(["-3", "--zstd=wlog=%d" % wl], rp, t.path("rep.w%d.stdin.zst" % wl), stdin=True)
        check_dec(arc, rp, "zstd wlog=%d stdin (wrapping window)" % wl)
        arc = zstd(["-3", "--zstd=wlog=%d" % wl], rp, t.path("rep.w%d.zst" % wl))
        check_dec(arc, rp, "zstd wlog=%d content size > window" % wl)
    fuzz_zst.append(t.path("rep.w17.stdin.zst"))
    # --long=27: matches 12+ MiB back; via stdin the 128 MiB window buffer grows while decoding
    big = noise(8 << 20, 11)
    lp = wfile("raw_long.bin", big + text(4 << 20, 12) + big + mixed(1 << 20, 13))
    arc = zstd(["-3", "--long=27"], lp, t.path("long27.zst"))
    check_dec(arc, lp, "zstd --long=27")
    arc = zstd(["-3", "--long=27"], lp, t.path("long27.stdin.zst"), stdin=True)
    check_dec(arc, lp, "zstd --long=27 stdin (128 MiB window)")
    t.check_extract(arc, {"long27.stdin": open(lp, "rb").read()}, label="gzt x long27.stdin.zst")
    for f in (lp, t.path("long27.zst"), arc):            # big; the disk is shared
        os.remove(f)
    shutil.rmtree(t.path("out_long27.stdin.zst"), ignore_errors=True)
    # multiple frames and skippable frames
    parts = [zstd(["-%d" % l], raw[n], t.path("part_%s_%d.zst" % (n, l))) for n, l in
             (("text", 1), ("empty", 3), ("mixed", 19), ("one", 3))]
    blobs = [open(p, "rb").read() for p in parts]
    want = samples["text"] + samples["mixed"] + samples["one"]
    wp = wfile("raw_multi.bin", want)
    multi = wfile("multi.zst", b"".join(blobs))
    check_dec(multi, wp, "zstd multiple frames (cat)")
    t.check_extract(multi, {"multi": want}, label="gzt x multi.zst")

    def skip_frame(k, payload):
        return struct.pack("<II", 0x184D2A50 + k, len(payload)) + payload
    sk = wfile("skippable.zst", skip_frame(0, b"meta" * 100) + blobs[0] + skip_frame(15, b"") +
               skip_frame(7, noise(70000, 5)) + blobs[2] + blobs[3] + skip_frame(3, b"tail"))
    check_dec(sk, wp, "zstd skippable frames around/between frames")
    t.check_extract(sk, {"skippable": want}, label="gzt x skippable-first .zst")
    only = wfile("only_skip.zst", skip_frame(1, b"abc") + skip_frame(2, b""))
    check_err(only, 0, "zstd only skippable frames -> empty output")
    # dictionaries are not supported: GZ_E_METHOD (and garbage without the dict ID must fail cleanly)
    dsrc = os.path.join(W, "dict_samples")
    shutil.rmtree(dsrc, ignore_errors=True)
    os.makedirs(dsrc)
    rnd = random.Random(9)
    for i in range(400):
        with open(os.path.join(dsrc, "s%03d.json" % i), "w") as f:
            f.write('{"id": %d, "name": "user%d", "tags": ["%s", "%s"], "score": %d, "active": %s}\n' % (
                i, rnd.randrange(10000), rnd.choice("abcdef") * 3, rnd.choice(["red", "green", "blue"]),
                rnd.randrange(1000), rnd.choice(["true", "false"])) * 3)
    dict_p = t.path("dict.bin")
    r = t.sh(["zstd", "-q", "-f", "--train"] + sorted(os.path.join(dsrc, x) for x in os.listdir(dsrc)) +
             ["--maxdict=4096", "-o", dict_p], check=False)
    if r.returncode == 0:
        one = os.path.join(dsrc, "s007.json")
        arc = zstd(["-3", "-D", dict_p], one, t.path("dict.zst"))
        check_err(arc, GZ_E_METHOD, "zstd dictionary frame -> GZ_E_METHOD")
        r2, rows2, out2 = t.extract(arc)
        t.record(r2.returncode in (0, 1) and (not rows2 or all(v[0] for v in rows2.values())),
                 "gzt x dictionary frame fails cleanly", r2.stdout.decode(errors="replace")[:200])
        arc = zstd(["-3", "-D", dict_p, "--no-dictID"], one, t.path("nodictid.zst"))
        check_err(arc, lambda c: c != 0, "zstd dictionary without ID -> error, no crash")
    else:
        t.record(False, "zstd --train", r.stderr.decode(errors="replace")[-300:])
    # legacy v0.x frames: unsupported
    leg = wfile("legacy07.zst", struct.pack("<I", 0xFD2FB527) + noise(100))
    check_err(leg, GZ_E_METHOD, "zstd legacy v0.7 magic -> GZ_E_METHOD")

    # ---------------- LZ4 vs lz4 CLI ----------------
    fuzz_lz4 = []
    lz4_opts = {
        "L1": ["-1"], "L9": ["-9"], "csize": ["--content-size"], "BD": ["-BD"], "B4": ["-B4"],
        "B5": ["-B5"], "B6": ["-B6"], "B7": ["-B7"], "nocrc": ["--no-frame-crc"], "BX": ["-BX"],
        "BD_B4_BX_cs": ["-BD", "-B4", "-BX", "--content-size", "-9"], "legacy": ["-l"],
    }
    for name in samples:
        for tag, opts in lz4_opts.items():
            if name in ("one", "small", "zeros") and tag not in ("L1", "legacy", "BD_B4_BX_cs"):
                continue
            arc = lz4(opts, raw[name], t.path("%s.%s.lz4" % (name, tag)))
            check_dec(arc, raw[name], "lz4 %s %s" % (" ".join(opts), name))
            if tag in ("B4", "B5") and name != "empty":
                rc, out = drv_run("blk", arc, raw[name])
                t.record(rc == 0, "lz4 raw block API %s %s" % (tag, name), out.strip()[-200:])
            if name == "mixed" and tag in ("L1", "BD_B4_BX_cs", "legacy", "B4"):
                fuzz_lz4.append(arc)
        if name != "empty":
            t.check_extract(t.path("%s.L1.lz4" % name), {"%s.L1" % name: samples[name]}, expect_type="LZ4",
                            label="gzt x %s.L1.lz4" % name)
    t.check_extract(t.path("mixed.legacy.lz4"), {"mixed.legacy": samples["mixed"]}, label="gzt x legacy .lz4")
    lparts = [open(t.path(p), "rb").read() for p in ("text.L1.lz4", "mixed.legacy.lz4", "noise.BD.lz4")]
    lwant = samples["text"] + samples["mixed"] + samples["noise"]
    lwp = wfile("raw_lmulti.bin", lwant)
    check_dec(wfile("multi.lz4", b"".join(lparts)), lwp, "lz4 multiple frames incl. legacy (cat)")
    lsk = wfile("skippable.lz4", skip_frame(4, b"x" * 999) + lparts[0] + skip_frame(0, b"") + lparts[1] +
                lparts[2] + skip_frame(9, b"end"))
    check_dec(lsk, lwp, "lz4 skippable frames")
    t.check_extract(lsk, {"skippable": lwant}, label="gzt x skippable-first .lz4")
    # sizes in the listing come from the frame headers
    r, typ, rows = t.listing(t.path("text.csize.lz4"))
    t.record(typ == "LZ4" and rows and rows[0]["usize"] == len(samples["text"]) and rows[0]["method"] == "LZ4",
             "lz4 listing: type, content size, method", "%s %s" % (typ, rows[:1]))
    r, typ, rows = t.listing(t.path("text.L3.zst"))
    t.record(typ == "ZSTD" and rows and rows[0]["usize"] == len(samples["text"]) and rows[0]["method"] == "Zstd",
             "zstd listing: type, content size, method", "%s %s" % (typ, rows[:1]))
    r, typ, rows = t.listing(multi)
    t.record(rows and rows[0]["usize"] == len(want), "zstd listing: content size summed over frames", str(rows[:1]))

    # ---------------- tarballs ----------------
    files = {
        "readme.txt": text(5000, 21),
        "문서/보고서.txt": text(120000, 22),
        "문서/사진/고기.jpg": noise(70000, 23),
        "empty.txt": b"",
        "deep/a/b/c/d/e.bin": mixed(300000, 24),
        "big.bin": mixed(3 << 20, 25),
    }
    tp = t.path("tree.tar")
    with tarfile.open(tp, "w", format=tarfile.PAX_FORMAT) as tf:
        for k, v in files.items():
            ti = tarfile.TarInfo(k)
            ti.size = len(v)
            ti.mtime = 1600000000
            tf.addfile(ti, io.BytesIO(v))
    for arcname, maker, typ in (
            ("tree.tar.zst", lambda d: zstd(["-19"], tp, d), "TAR.ZST"),
            ("tree.tzst", lambda d: zstd(["-3", "--long=27"], tp, d, stdin=True), "TAR.ZST"),
            ("tree.tar.lz4", lambda d: lz4(["-9", "-BD"], tp, d), "TAR.LZ4"),
            ("tree.tlz4", lambda d: lz4(["-l"], tp, d), "TAR.LZ4")):
        arc = maker(t.path(arcname))
        t.check_extract(arc, files, expect_type=typ, label="gzt x " + arcname)
        for tier in (0, 3):
            t.check_extract(arc, files, tier=tier, label="gzt x %s tier %d" % (arcname, tier))

    # ---------------- plain kernels (no BMI2) ----------------
    env = dict(os.environ, ZT_TIER="3")
    for arc, rp_ in ((t.path("mixed.L19.zst"), raw["mixed"]), (t.path("text.L22.zst"), raw["text"]),
                     (t.path("rep.w17.stdin.zst"), rp)):
        r = subprocess.run([drv, "dec", arc, rp_], capture_output=True, env=env, timeout=600)
        t.record(r.returncode == 0, "plain kernels " + os.path.basename(arc), r.stdout.decode()[-200:])

    # ---------------- hostile input ----------------
    count = 150 if sanitized else 400
    for i, arc in enumerate(fuzz_zst + fuzz_lz4 + [sk, lsk]):
        try:
            rc, out = drv_run("fuzz", arc, count, 1000 + i, timeout=900)
        except subprocess.TimeoutExpired:
            t.record(False, "fuzz " + os.path.basename(arc), "timeout (hang?)")
            continue
        bad = rc != 0 or "Sanitizer" in out or "runtime error" in out or not out.startswith("OK")
        t.record(not bad, "fuzz %d mutations %s" % (count, os.path.basename(arc)), out.strip()[-300:])
    rnd = random.Random(77)
    for arc in (t.path("mixed.L3.zst"), t.path("mixed.BD_B4_BX_cs.lz4"), t.path("tree.tar.zst"),
                t.path("tree.tlz4")):
        data = bytearray(open(arc, "rb").read())
        for k in range(8):
            m = bytearray(data)
            if k % 3 == 0:
                m = m[:rnd.randrange(len(m))]
            else:
                for _ in range(rnd.randrange(1, 6)):
                    m[rnd.randrange(len(m))] ^= 1 << rnd.randrange(8)
            hp = wfile("hostile_%d_%s" % (k, os.path.basename(arc)), bytes(m))
            hostile(hp)
    # crafted: huge declared window, reserved bits, bogus block types, absurd sizes
    hdr = struct.pack("<I", 0xFD2FB528)
    crafted = {
        "win_2tib.zst": hdr + bytes([0x00, 0xF8]) + bytes([1, 0, 0]),          # window 2^41
        "reserved.zst": hdr + bytes([0x08, 0x50]) + bytes([1, 0, 0]),
        "blocktype3.zst": hdr + bytes([0x20, 0x10]) + bytes([0x07, 0x00, 0x00]),
        "rawbig.zst": hdr + bytes([0x00, 0x50]) + struct.pack("<I", 0xFFFFF8)[:3],
        "huge_fcs.zst": hdr + bytes([0xE0]) + struct.pack("<Q", 1 << 62) + bytes([1, 0, 0]),
        "lz4_bigblock.lz4": bytes.fromhex("04224d18") + bytes([0x40, 0x40, 0xc0]) + struct.pack("<I", 0x7FFFFFFF),
        "lz4_legacy_huge.lz4": bytes.fromhex("02214c18") + struct.pack("<I", 0x7FFFFFF0) + b"\0" * 64,
    }
    for name, data in crafted.items():
        p = wfile("crafted_" + name, data)
        check_err(p, lambda c: c != 0, "crafted %s rejected" % name)
        hostile(p)
    check_err(t.path("crafted_win_2tib.zst"), 15, "zstd window 2 TiB -> GZ_E_LIMIT")

    # extraction outputs are not needed any more
    for f in os.listdir(W):
        if f.startswith("out_"):
            shutil.rmtree(os.path.join(W, f), ignore_errors=True)

    # ---------------- speed (informational) ----------------
    if sanitized:
        return
    corp = bytearray()
    for root in ("/usr/share/doc", "/usr/include", "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/usr/bin"):
        for dp, dns, fns in os.walk(root):
            for fn in sorted(fns):
                fp = os.path.join(dp, fn)
                if os.path.isfile(fp) and not os.path.islink(fp) and len(corp) < (48 << 20):
                    try:
                        corp += open(fp, "rb").read(4 << 20)
                    except OSError:
                        pass
            if len(corp) >= 48 << 20:
                break
    if len(corp) < (8 << 20):
        corp += mixed(32 << 20, 99)
    cp = wfile("speed_corpus.bin", bytes(corp))

    def cli_speed(cmd, n):
        best = 1e9
        for _ in range(3):
            t0 = time.perf_counter()
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            best = min(best, time.perf_counter() - t0)
        return n / best / 1e6

    for tag, maker, cli in (("zstd -3", lambda d: zstd(["-3", "-T0"], cp, d), "zstd"),
                            ("zstd -19", lambda d: zstd(["-19", "-T0"], cp, d), "zstd"),
                            ("lz4 -1", lambda d: lz4(["-1"], cp, d), "lz4")):
        arc = maker(t.path("speed.%s.%s" % (tag.replace(" ", ""), "zst" if cli == "zstd" else "lz4")))
        rc, out = drv_run("bench", arc, 2)
        ref = cli_speed([cli, "-d", "-c", "-q", arc], len(corp))
        t.record(rc == 0, "speed %s (%d MB corpus)" % (tag, len(corp) >> 20),
                 "ours %s | %s -d %.0f MB/s" % (out.strip()[3:].split(" (")[0], cli, ref))
        os.remove(arc)
    os.remove(cp)
