"""Compressed tarball writers (TAR.GZ / TAR.BZ2 / TAR.XZ / TAR.ZST), single-file writers
(.gz .bz2 .xz .zst) and the Zstandard encoder.

Round trips through GNU tar (-z -j -J --zstd), the gzip / bzip2 / xz / zstd CLIs, 7-Zip and our own
reader at several levels; header details (gzip name + mtime, xz block sizes + CRC-64, zstd content
size + checksum); empty inputs; error paths (pipe sinks, shrinking / growing / unreadable inputs,
cancel, one-file rule) through a C driver; the zstd encoder at every level on many input shapes,
verified by the zstd CLI; a size / speed table against gzip, bzip2, xz and zstd.
GZ_SLOW=1 adds a 1 GiB generated input per format family (memory must stay bounded)."""
import io, os, random, re, shutil, struct, subprocess, sys, tarfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAN = "sanitize" in os.environ.get("HOST_CFLAGS", "")
SLOW = os.environ.get("GZ_SLOW") == "1"
TAR_FLAG = {"tgz": "-z", "tbz2": "-j", "txz": "-J", "tzst": "--zstd"}
EXT = {"tgz": "tar.gz", "tbz2": "tar.bz2", "txz": "tar.xz", "tzst": "tar.zst", "gz": "gz", "bz2": "bz2", "xz": "xz",
       "zst": "zst"}
TOOL = {"gz": "gzip", "bz2": "bzip2", "xz": "xz", "zst": "zstd", "tgz": "gzip", "tbz2": "bzip2", "txz": "xz",
        "tzst": "zstd"}
OUR_TYPE = {"tgz": "TAR.GZ", "tbz2": "TAR.BZ2", "txz": "TAR.XZ", "tzst": "TAR.ZST", "gz": "GZIP", "bz2": "BZIP2",
            "xz": "XZ", "zst": "ZSTD"}


# ---------------- inputs ----------------

def text(n, seed=1):
    rnd = random.Random(seed)
    words = [b"tar", b"gzip", b"bzip2", b"xz", b"zstd", "고깃집".encode(), b"archive", b"\n", b"block",
             b"0123456789", b"window", b"literal", b"sequence", b"offset", b"Huffman", b"frame"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words) + (b" " if rnd.random() < 0.7 else b",")
    return bytes(out[:n])


def noise(n, seed=2):
    return random.Random(seed).randbytes(n)


def sources(limit):
    out = bytearray()
    for top in ("src", "tests", "docs"):
        for dp, dns, fns in os.walk(os.path.join(ROOT, top)):
            dns.sort()
            for f in sorted(fns):
                if f.endswith((".c", ".h", ".py", ".md")) and len(out) < limit:
                    out += open(os.path.join(dp, f), "rb").read()
    return bytes(out[:limit])


def binaries(limit):
    out = bytearray()
    for d in ("/usr/bin", "/usr/lib/x86_64-linux-gnu", "/usr/lib"):
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if len(out) >= limit:
                break
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            try:
                out += open(p, "rb").read(min(limit - len(out), 1 << 20))
            except OSError:
                pass
    return bytes(out[:limit])


def corpus(limit):
    """sources, binaries, text, noise and long repeats, interleaved in large pieces"""
    parts = [sources(limit), binaries(limit), text(limit // 2, 5)]
    parts = [p for p in parts if p]
    rnd = random.Random(42)
    out = bytearray()
    while len(out) < limit:
        k = rnd.randrange(10)
        if k == 0:
            out += noise(rnd.randrange(1000, 60000), rnd.randrange(1 << 30))
        elif k == 1 and len(out) > 300000:
            a = rnd.randrange(len(out) - 200000)
            out += out[a:a + rnd.randrange(1000, 200000)]
        else:
            p = rnd.choice(parts)
            n = rnd.randrange(20000, 400000)
            o = rnd.randrange(0, max(1, len(p) - n))
            out += p[o:o + n]
    return bytes(out[:limit])


def tree():
    return {
        "top": None,
        "top/empty_dir": None,
        "top/a.txt": text(50000, 3),
        "top/empty.bin": b"",
        "top/noise.bin": noise(70000, 4),
        "top/sub/zeros.bin": bytes(300000),
        "top/sub/src.txt": sources(400000),
        "top/한글 폴더/파일 이름.txt": "압축 테스트 고깃ZIP\n".encode() * 500,
        "top/" + "long_directory_name_" * 4 + "/" + "x" * 90 + ".dat": text(3000, 9),
        "top/odd size.bin": noise(513, 6) + bytes(511),
    }


# ---------------- helpers ----------------

NOLEAK = {"ASAN_OPTIONS": "detect_leaks=0"}     # gzt c keeps its item list until exit


def create(t, fmt, level, base, rels, out, env=None):
    if os.path.exists(out):
        os.remove(out)
    r = t.run_gzt(["c", fmt, out, str(level), "-", base] + rels, dict(NOLEAK, **(env or {})))
    return r.returncode == 0 and os.path.exists(out), r


def files_of(tree_):
    return {k: v for k, v in tree_.items() if v is not None}


def tar_extract_check(t, fmt, arc, tree_):
    out = t.path("gnutar_" + os.path.basename(arc))
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    r = subprocess.run(["tar", TAR_FLAG[fmt], "-xf", arc, "-C", out], capture_output=True)
    if r.returncode:
        return "GNU tar: " + r.stderr.decode(errors="replace")[-300:]
    got = t.read_tree(out)
    want = files_of(tree_)
    if got != want:
        miss = sorted(set(want) - set(got))[:3]
        bad = sorted(k for k in want if k in got and got[k] != want[k])[:3]
        return "GNU tar content: missing %s differ %s extra %s" % (miss, bad, sorted(set(got) - set(want))[:3])
    for k, v in tree_.items():
        if v is None and not os.path.isdir(os.path.join(out, k)):
            return "GNU tar: directory %s missing" % k
    return None


_XZ_READER = {}


def own_reader(t, fmt):
    """our XZ reader may live in another branch: only check what gzt can open"""
    if fmt not in ("xz", "txz"):
        return True
    if "ok" not in _XZ_READER:
        p = t.path("probe.xz")
        open(p, "wb").write(subprocess.run(["xz", "-c"], input=b"probe", capture_output=True).stdout)
        r, typ, rows = t.listing(p)
        _XZ_READER["ok"] = typ is not None and "XZ" in typ
    return _XZ_READER["ok"]


def tool_test(fmt, path):
    tool = TOOL[fmt]
    r = subprocess.run([tool, "-t", "-q" if tool != "gzip" else "-t", path], capture_output=True)
    return r.returncode == 0, r.stderr.decode(errors="replace")[-200:]


def tool_decompress(fmt, path):
    r = subprocess.run([TOOL[fmt], "-d", "-c", path], capture_output=True)
    return r.stdout if r.returncode == 0 else None


# ---------------- tests ----------------

def test_tarballs(t):
    tr = tree()
    base = t.write_tree(t.path("tree"), tr)
    rels = sorted(tr.keys())
    levels = {"tgz": (0, 1, 5, 9), "tbz2": (1, 9), "txz": (0, 1, 6), "tzst": (0, 1, 3, 5, 7, 9)}
    if SAN:
        levels = {"tgz": (1, 9), "tbz2": (1,), "txz": (0, 3), "tzst": (0, 1, 5, 9)}
    for fmt, lvs in levels.items():
        for lv in lvs:
            label = "%s L%d" % (fmt, lv)
            arc = t.path("tree_L%d.%s" % (lv, EXT[fmt]))
            ok, r = create(t, fmt, lv, base, rels, arc)
            if not ok:
                t.record(False, label + " create", r.stdout.decode(errors="replace")[-200:])
                continue
            ok, err = tool_test(fmt, arc)
            t.record(ok, label + " %s -t" % TOOL[fmt], err)
            prob = tar_extract_check(t, fmt, arc, tr)
            t.record(prob is None, label + " GNU tar -x", prob or "%d bytes" % os.path.getsize(arc))
            if own_reader(t, fmt):
                t.check_extract(arc, files_of(tr), label=label + " own reader", expect_type=OUR_TYPE[fmt])
    # 7-Zip reads the gzip / bzip2 / xz tarballs too
    if shutil.which("7z"):
        for fmt in ("tgz", "tbz2", "txz"):
            arc = t.path("tree_L1.%s" % EXT[fmt])
            if os.path.exists(arc):
                r = subprocess.run(["7z", "x", "-so", arc], capture_output=True)
                ok = r.returncode == 0 and r.stdout[:512] and len(r.stdout) % 10240 == 0
                t.record(ok, "%s readable by 7z" % fmt, "%d tar bytes" % len(r.stdout))


def test_single(t):
    data = sources(700000) + noise(30000, 8) + text(200000, 9)
    base = t.write_tree(t.path("single"), {"dir/조각 file.txt": data})
    rel = "dir/조각 file.txt"
    mt = 1600000000
    os.utime(os.path.join(base, rel), (mt, mt))
    levels = {"gz": (0, 1, 6, 9), "bz2": (1, 5, 9), "xz": (0, 1, 6), "zst": (0, 1, 3, 5, 7, 9)}
    if SAN:
        levels = {"gz": (1, 9), "bz2": (1,), "xz": (0, 3), "zst": (0, 1, 5, 9)}
    for fmt, lvs in levels.items():
        for lv in lvs:
            label = "%s L%d" % (fmt, lv)
            arc = t.path("single_L%d.%s" % (lv, fmt))
            ok, r = create(t, fmt, lv, base, [rel], arc)
            if not ok:
                t.record(False, label + " create", r.stdout.decode(errors="replace")[-200:])
                continue
            ok, err = tool_test(fmt, arc)
            t.record(ok, label + " %s -t" % TOOL[fmt], err)
            t.record(tool_decompress(fmt, arc) == data, label + " %s -d" % TOOL[fmt], "%d bytes" % os.path.getsize(arc))
            if own_reader(t, fmt):
                r2, rows, out = t.extract(arc)
                p0 = os.path.join(out, "0.bin")
                got = open(p0, "rb").read() if os.path.exists(p0) else None
                t.record(r2.returncode == 0 and got == data, label + " own reader", "rows=%d" % len(rows))
            if fmt == "gz":
                raw = open(arc, "rb").read()
                flg, mtime = raw[3], struct.unpack("<I", raw[4:8])[0]
                name = raw[10:raw.index(b"\0", 10)] if flg & 8 else b""
                t.record(name == "조각 file.txt".encode() and mtime == mt and raw[8] in (0, 2, 4),
                         label + " header name + mtime", "%r %d xfl=%d" % (name, mtime, raw[8]))
                r = subprocess.run(["gzip", "-lN", arc], capture_output=True, text=True)
                t.record("조각 file.txt" in r.stdout, label + " gzip -lN shows the name", r.stdout[-120:])
            if fmt == "xz":
                r = subprocess.run(["xz", "-lvv", "--robot", arc], capture_output=True, text=True)
                ok = r.returncode == 0 and "\tCRC64\t" in r.stdout and re.search(r"^summary\t.*\tyes\t", r.stdout, re.M)
                t.record(bool(ok), label + " xz -lvv: CRC64 check, sizes in block headers", r.stdout[-200:])
            if fmt == "zst":
                r = subprocess.run(["zstd", "-lv", arc], capture_output=True, text=True)
                out = r.stdout + r.stderr
                ok = "(%d B)" % len(data) in out and "XXH64" in out
                t.record(ok, label + " zstd -lv: content size + checksum", out.strip().splitlines()[-1] if out else "")


def test_empty(t):
    base = t.write_tree(t.path("empty"), {"e/empty.txt": b"", "e/d": None})
    for fmt in ("gz", "bz2", "xz", "zst"):
        arc = t.path("empty.%s" % fmt)
        ok, r = create(t, fmt, 5, base, ["e/empty.txt"], arc)
        if not ok:
            t.record(False, "%s empty file" % fmt, r.stdout.decode(errors="replace"))
            continue
        ok, err = tool_test(fmt, arc)
        dec = tool_decompress(fmt, arc)
        own = True
        if own_reader(t, fmt):
            r2, rows, out = t.extract(arc)
            own = os.path.exists(os.path.join(out, "0.bin")) and open(os.path.join(out, "0.bin"), "rb").read() == b""
        t.record(ok and dec == b"" and own, "%s empty file" % fmt, "%d bytes: %s" % (os.path.getsize(arc), err))
        ok2, r = create(t, fmt, 5, base, ["e/d"], t.path("dir.%s" % fmt))
        t.record(not ok2 and b"CREATE 5" in r.stdout, "%s rejects a directory" % fmt, r.stdout.decode(errors="replace"))
        ok2, r = create(t, fmt, 5, base, ["e/empty.txt", "e/d"], t.path("two.%s" % fmt))
        t.record(not ok2 and b"CREATE 5" in r.stdout, "%s rejects two items" % fmt, r.stdout.decode(errors="replace"))
    for fmt in ("tgz", "tbz2", "txz", "tzst"):
        arc = t.path("empty.%s" % EXT[fmt])
        tr = {"e": None, "e/d": None, "e/empty.txt": b""}
        ok, r = create(t, fmt, 5, base, ["e", "e/d", "e/empty.txt"], arc)
        prob = tar_extract_check(t, fmt, arc, tr) if ok else "create failed"
        t.record(prob is None, "%s empty file + directory" % fmt, prob or "")


def test_xz_blocks(t):
    """big inputs become several xz blocks with sizes in their headers: xz -T decodes them in parallel"""
    data = corpus(2 << 20 if SAN else 7 << 20)
    base = t.write_tree(t.path("xzb"), {"big.bin": data})
    for lv, want in ((0, 1 << 20), (1, 3 << 20)):
        arc = t.path("blocks_L%d.xz" % lv)
        ok, r = create(t, "xz", lv, base, ["big.bin"], arc)
        if not ok:
            t.record(False, "xz L%d blocks" % lv, "create failed")
            continue
        r = subprocess.run(["xz", "-lvv", "--robot", arc], capture_output=True, text=True)
        blocks = [l.split("\t") for l in r.stdout.splitlines() if l.startswith("block\t")]
        nb = len(blocks)
        expect = (len(data) + want - 1) // want
        sizes = all(b[-1].startswith("--lzma2") for b in blocks) if blocks else False
        t.record(nb == expect and sizes, "xz L%d: %d blocks of <= %d KiB" % (lv, expect, want >> 10),
                 "got %d blocks" % nb)
        d = subprocess.run(["xz", "-T4", "-d", "-c", arc], capture_output=True)
        t.record(d.returncode == 0 and d.stdout == data, "xz L%d: parallel xz -T4 -d" % lv, "")
        if own_reader(t, "xz"):
            r2, rows, out = t.extract(arc)
            got = open(os.path.join(out, "0.bin"), "rb").read() if os.path.exists(os.path.join(out, "0.bin")) else None
            t.record(got == data, "xz L%d: own reader" % lv, "")
            shutil.rmtree(out, ignore_errors=True)
        os.remove(arc)
    shutil.rmtree(base, ignore_errors=True)


def test_driver(t):
    drv = t.build_driver("tests/drivers/stream_write_drv.c")
    wd = t.path("drv")
    shutil.rmtree(wd, ignore_errors=True)
    os.makedirs(wd)
    r = subprocess.run([drv, "cases"], cwd=wd, capture_output=True, text=True, timeout=600)
    err = r.stderr[-500:]
    if "Sanitizer" in err or "runtime error" in err:
        t.record(False, "driver cases: sanitizer", err)
    for line in r.stdout.splitlines():
        if line.startswith("ok "):
            t.record(True, line[3:], "")
        elif line.startswith("FAIL "):
            t.record(False, line[5:], "")
    t.record(r.returncode == 0 and "ALL OK" in r.stdout, "driver cases complete", "rc=%d %s" % (r.returncode, err))
    # what the driver wrote must be valid for the reference tools
    want_zero_pad = b"\0" * 4000
    for fn in sorted(os.listdir(wd)):
        path = os.path.join(wd, fn)
        stem, ext = fn.split(".", 1)
        fmt = {"tgz": "tgz", "tbz2": "tbz2", "txz": "txz", "tzst": "tzst"}.get(ext, ext)
        if fmt in TAR_FLAG:
            r = subprocess.run(["tar", TAR_FLAG[fmt], "-xOf", path], capture_output=True)
            ok = r.returncode == 0
            if stem == "shrink":
                ok = ok and len(r.stdout) == 5000 and r.stdout[1000:] == want_zero_pad
            elif stem == "grow":
                ok = ok and len(r.stdout) == 4000
            elif stem == "readerr":
                ok = ok and len(r.stdout) == 200010 and r.stdout[70000:200000] == bytes(130000)
            elif stem == "empty":
                ok = ok and r.stdout == b""
            t.record(ok, "tar %s -x %s" % (TAR_FLAG[fmt], fn), "%d bytes out" % len(r.stdout))
        elif fmt in TOOL:
            dec = tool_decompress(fmt, path)
            ok = dec is not None
            if stem == "shrink":
                ok = ok and len(dec) == (5000 if fmt == "zst" else 1000)
            elif stem == "grow":
                ok = ok and len(dec) == (4000 if fmt == "zst" else 9000)
            t.record(ok, "%s -d %s" % (TOOL[fmt], fn), "%s bytes out" % (len(dec) if dec is not None else None))


def zstd_cli_size(data_path, lv):
    r = subprocess.run(["zstd", "-%d" % lv, "-T1", "-c", data_path], capture_output=True)
    return len(r.stdout)


def test_zstd_encoder(t):
    drv = t.build_driver("tests/drivers/zstd_enc_test.c")
    # random inputs of every shape through every level, window size and read chunking
    fz = t.path("zfuzz")
    shutil.rmtree(fz, ignore_errors=True)
    os.makedirs(fz)
    n = 120 if SAN else 400
    r = subprocess.run([drv, "fuzz", "17", str(n), fz], capture_output=True, text=True, timeout=1800)
    t.record(r.returncode == 0, "zstd encoder: %d random inputs, our decoder" % n, r.stdout[-300:] + r.stderr[-300:])
    bad = []
    for f in sorted(os.listdir(fz)):
        if f.endswith(".zst"):
            d = subprocess.run(["zstd", "-d", "-q", "-c", os.path.join(fz, f)], capture_output=True)
            raw = open(os.path.join(fz, f[:-4] + ".raw"), "rb").read()
            if d.returncode or d.stdout != raw:
                bad.append(f)
    t.record(not bad, "zstd encoder: zstd CLI decodes every frame", ", ".join(bad[:5]))
    shutil.rmtree(fz, ignore_errors=True)
    r = subprocess.run([drv, "err", "3"], capture_output=True, text=True)
    t.record(r.returncode == 0, "zstd encoder: read/write errors, wrong content size, reuse", r.stdout[-300:])
    r = subprocess.run([drv, "err", "19"], capture_output=True, text=True, timeout=600)
    t.record(r.returncode == 0, "zstd encoder: errors at level 19", r.stdout[-300:])

    # every level on a mixed corpus (with and without content size, reads of random sizes)
    data = corpus(1 << 20 if SAN else 4 << 20)
    src = t.path("zcorpus.bin")
    open(src, "wb").write(data)
    for lv in range(0, 20):
        if SAN and lv not in (0, 1, 3, 5, 8, 13, 16, 19):
            continue
        out = t.path("zl%d.zst" % lv)
        args = [drv, "enc", str(lv), src, out] + (["size"] if lv % 2 else ["-"]) + (["0", "65537"] if lv % 3 == 0 else [])
        r = subprocess.run(args, capture_output=True, text=True, timeout=900)
        d = subprocess.run(["zstd", "-d", "-q", "-c", out], capture_output=True)
        ok = r.returncode == 0 and d.returncode == 0 and d.stdout == data
        t.record(ok, "zstd encoder level %d: zstd -d" % lv, r.stdout.strip())
        os.remove(out)
    # small windows (block size limited by the window), multi-frame output of one encoder
    for wl in (10, 12, 17):
        out = t.path("zw%d.zst" % wl)
        r = subprocess.run([drv, "enc", "6", src, out, "-", str(wl)], capture_output=True, text=True)
        info = subprocess.run(["zstd", "-lv", out], capture_output=True, text=True)
        d = subprocess.run(["zstd", "-d", "-q", "-c", out], capture_output=True)
        t.record(d.returncode == 0 and d.stdout == data and ("(%d B)" % (1 << wl)) in info.stdout + info.stderr,
                 "zstd encoder window 2^%d" % wl, "")
        os.remove(out)
    out = t.path("zmulti.zst")
    r = subprocess.run([drv, "multi", "9", src, out], capture_output=True, text=True)
    d = subprocess.run(["zstd", "-d", "-q", "-c", out], capture_output=True)
    t.record(r.returncode == 0 and d.stdout == data + data[:len(data) // 3] + data, "zstd encoder: 3 frames, reused", "")
    os.remove(out)
    os.remove(src)
    # special inputs: all zero, one repeated short pattern, incompressible, tiny
    for name, blob in (("zeros", bytes(3 << 20)), ("pattern", b"abcdefg" * 300000), ("noise", noise(1 << 20, 3)),
                       ("one byte", b"x"), ("five bytes", b"aaaaa"), ("empty", b"")):
        p = t.path("zs.bin")
        open(p, "wb").write(blob)
        for lv in (1, 3, 6, 12, 19):
            out = t.path("zs.zst")
            r = subprocess.run([drv, "enc", str(lv), p, out, "size"], capture_output=True, text=True, timeout=600)
            d = subprocess.run(["zstd", "-d", "-q", "-c", out], capture_output=True)
            ok = r.returncode == 0 and d.returncode == 0 and d.stdout == blob
            if ok and name in ("zeros", "pattern"):
                ok = os.path.getsize(out) < 400
            if ok and name == "noise":
                ok = os.path.getsize(out) <= len(blob) + len(blob) // 1000 + 64
            t.record(ok, "zstd encoder %s L%d" % (name, lv), "%d -> %d" % (len(blob), os.path.getsize(out)))


def test_cross(t):
    """the encoder writes the same bytes on i586 (-m32), x86-64 (SSE2 row tags) and AArch64 (QEMU)"""
    drv = t.build_driver("tests/drivers/zstd_enc_test.c")
    srcs = [os.path.join(ROOT, p) for p in ("tests/drivers/zstd_enc_test.c", "src/codec/zstd_enc.c",
                                             "src/codec/xxhash.c")]
    cflags = ["-std=gnu11", "-O2", "-DZSTDENC_STANDALONE", "-Wall", "-Wextra", "-Wno-unused-parameter",
              "-Wno-missing-field-initializers"] + ["-I" + os.path.join(ROOT, d) for d in ("src/core", "src/codec")]
    n = 30 if SAN else 80
    native = t.path("x_native")
    shutil.rmtree(native, ignore_errors=True)
    os.makedirs(native)
    subprocess.run([drv, "fuzz", "23", str(n), native], capture_output=True, timeout=1800)
    for name, cc, extra, runner, env in (
            ("i586", "cc", ["-m32", "-march=i586"], [], None),
            ("aarch64", "aarch64-linux-gnu-gcc", [], ["qemu-aarch64", "-cpu", "max"],
             dict(os.environ, QEMU_LD_PREFIX="/usr/aarch64-linux-gnu"))):
        if not shutil.which(cc) or (runner and not shutil.which(runner[0])):
            continue
        exe = t.path("zstdenc_" + name)
        r = subprocess.run([cc] + extra + cflags + ["-o", exe] + srcs, capture_output=True)
        if r.returncode or b"warning" in r.stderr:
            if name == "i586" and b"warning" not in r.stderr:
                continue                   # no 32-bit multilib here
            t.record(False, "%s build" % name, r.stderr.decode(errors="replace")[-400:])
            continue
        out = t.path("x_" + name)
        shutil.rmtree(out, ignore_errors=True)
        os.makedirs(out)
        r = subprocess.run(runner + [exe, "fuzz", "23", str(n), out], capture_output=True, timeout=3600, env=env)
        diff = [f for f in sorted(os.listdir(native)) if f.endswith(".zst") and
                (not os.path.exists(os.path.join(out, f)) or
                 open(os.path.join(native, f), "rb").read() != open(os.path.join(out, f), "rb").read())]
        t.record(r.returncode == 0 and not diff, "zstd encoder: %s writes the same %d frames" % (name, n),
                 "rc=%d differ: %s" % (r.returncode, ", ".join(diff[:5])))
        shutil.rmtree(out, ignore_errors=True)
    shutil.rmtree(native, ignore_errors=True)


def test_compare(t):
    """sizes and speeds against the reference CLIs at matching levels (one thread)"""
    if SAN:
        return
    drv = t.build_driver("tests/drivers/zstd_enc_test.c")
    data = corpus(16 << 20)
    base = t.write_tree(t.path("cmp"), {"corpus.bin": data})
    src = os.path.join(base, "corpus.bin")
    rows = []

    def timed(args):
        t0 = time.perf_counter()
        r = subprocess.run(args, capture_output=True)
        return r, time.perf_counter() - t0

    mb = len(data) / 1e6
    worst = 0.0
    for lv in (1, 3, 9, 19):
        out = t.path("cmp%d.zst" % lv)
        r, _ = timed([drv, "enc", str(lv), src, out, "size"])
        ours, sec = int(r.stdout.split()[1]), float(r.stdout.split()[2])
        z, zsec = timed(["zstd", "-%d" % lv, "-T1", "-q", "-c", src])
        ratio = 100.0 * ours / len(z.stdout)
        worst = max(worst, ratio)
        rows.append("zstd -%-2d ours %9d %7.1f MB/s | zstd %9d %7.1f MB/s | size %6.2f%%" %
                    (lv, ours, mb / sec, len(z.stdout), mb / zsec, ratio))
        t.record(ratio < 103.0, "ratio vs zstd -%d within 3%%" % lv, rows[-1])
    for fmt, tool, lvs in (("gz", "gzip", (1, 6, 9)), ("bz2", "bzip2", (1, 9)), ("xz", "xz", (1, 6))):
        for lv in lvs:
            arc = t.path("cmp_L%d.%s" % (lv, fmt))
            (ok, r), sec = (lambda t0: (create(t, fmt, lv, base, ["corpus.bin"], arc), time.perf_counter() - t0))(
                time.perf_counter())
            ref, rsec = timed([tool, "-%d" % lv, "-c", src] + (["-T1"] if tool == "xz" else []))
            ours = os.path.getsize(arc) if ok else 0
            ratio = 100.0 * ours / max(1, len(ref.stdout))
            rows.append("%-5s -%d ours %9d %7.1f MB/s | %-5s %9d %7.1f MB/s | size %6.2f%%" %
                        (tool, lv, ours, mb / sec, tool, len(ref.stdout), mb / rsec, ratio))
            t.record(ok and ratio < 104.0, "%s L%d size vs %s -%d" % (fmt, lv, tool, lv), rows[-1])
    print("\n".join(["writer_streams: %.1f MB corpus" % mb] + rows))
    for f in os.listdir(t.work):
        if f.startswith("cmp"):
            p = os.path.join(t.work, f)
            shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.remove(p)


def test_big(t):
    """GZ_SLOW=1: 1 GiB generated member, streamed through a pipe into the reference tool"""
    if not SLOW or SAN:
        return
    drv = t.build_driver("tests/drivers/stream_write_drv.c")
    # (format, level, checker, RSS limit in MiB: encoder memory + 1 MiB buffers, never the input size)
    for fmt, lv, check, limit in (("tzst", 5, ["zstd", "-t", "-"], 64), ("tgz", 1, ["gzip", "-t"], 48),
                                  ("txz", 1, ["xz", "-t", "-"], 96), ("zst", 6, ["zstd", "-t", "-"], 64),
                                  ("bz2", 1, ["bzip2", "-t"], 48)):
        p = subprocess.Popen([drv, "big", fmt, str(lv), "1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        c = subprocess.run(check, stdin=p.stdout, capture_output=True)
        p.stdout.close()
        err = p.stderr.read().decode()
        rc = p.wait()
        m = re.search(r"rss_kb=(\d+)", err)
        rss = int(m.group(1)) >> 10 if m else 1 << 20
        t.record(rc == 0 and c.returncode == 0 and rss <= limit, "1 GiB %s L%d through a pipe" % (fmt, lv),
                 "%s (limit %d MiB)" % (err.strip(), limit))


def run(t):
    t.need("tar", "gzip", "bzip2", "xz", "zstd")
    test_tarballs(t)
    test_single(t)
    test_empty(t)
    test_xz_blocks(t)
    test_driver(t)
    test_zstd_encoder(t)
    test_cross(t)
    test_compare(t)
    test_big(t)
