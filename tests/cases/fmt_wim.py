"""WIM / ESD / SWM reader and LZMS decoder.

Fixtures come from wimlib-imagex (capture / append / split, every compression type,
chunk sizes, solid resources, unix data, NTFS alternate streams through an NTFS image
written with mkntfs + ntfscp) and are checked against the source trees, 7-Zip and
wimlib's own extraction. The LZMS decoder is checked chunk by chunk against wimlib's
LZMS compressor (libwim through ctypes). Hostile inputs: truncation, bit flips, and
crafted metadata (dentry cycles, huge counts and lengths), chunk tables, solid headers,
encrypted ESD and SHA-1 mismatches, patched into uncompressed WIMs with a small parser.
"""
import os, sys, time, struct, random, shutil, hashlib, ctypes, ctypes.util, subprocess


def text_blob(n, seed):
    rnd = random.Random(seed)
    words = ["고기", "삼겹살", "목살", "갈비", "WIM", "image", "Windows", "setup", "system32", "\r\n", "drivers"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words).encode() + b" "
    return bytes(out[:n])


def rand_blob(n, seed):
    return random.Random(seed).randbytes(n)


def code_blob(n):
    """x86 machine code: exercises the LZX E8 and LZMS x86 translations"""
    data = b""
    for p in ("/usr/bin/ls", "/usr/bin/cp", "/usr/bin/bash", sys.executable):
        if os.path.exists(p):
            data += open(p, "rb").read()
        if len(data) >= n:
            break
    if len(data) < n:
        rnd = random.Random(5)
        while len(data) < n:
            data += bytes([0xE8]) + struct.pack("<i", rnd.randrange(-5000, 5000)) + rnd.randbytes(11)
    return data[:n]


def source_tree():
    """files {rel: bytes}, empty dirs, symlinks {rel: target}, hard links {rel: rel}"""
    files = {
        "readme.txt": text_blob(5000, 1),
        "문서/보고서.txt": text_blob(150000, 2),
        "bin/code.exe": code_blob(400000),
        "data/random.bin": rand_blob(200000, 3),
        "data/zeros.bin": bytes(2 << 20),
        "data/big.txt": text_blob(1300000, 4),
        "deep/a/b/c/d/e/f.txt": b"deep file\n",
        "empty.txt": b"",
        "dup1.txt": text_blob(70000, 5),
        "dup2.txt": text_blob(70000, 5),
        "한글 폴더/빈 파일": b"",
        "공백 이름 (1).txt": b"spaces and parens\n",
        "odd/size_32769.bin": text_blob(32769, 6),
        "odd/size_65536.bin": text_blob(65536, 7),
    }
    dirs = ["빈폴더", "deep/empty"]
    links = {"link_rel": "readme.txt", "bin/link_up": "../문서/보고서.txt", "link_abs": "/etc/hostname"}
    hard = {"hard_readme.txt": "readme.txt"}
    return files, dirs, links, hard


def write_source(t, root, files, dirs, links, hard):
    t.write_tree(root, files)
    for d in dirs:
        os.makedirs(os.path.join(root, d), exist_ok=True)
    for k, v in links.items():
        os.symlink(v, os.path.join(root, k))
    for k, v in hard.items():
        os.link(os.path.join(root, v), os.path.join(root, k))
    return root


def capture(t, src, out, *opts, label=None):
    if os.path.exists(out):
        os.remove(out)
    r = t.sh(["wimlib-imagex", "capture", src, out] + list(opts), check=False)
    if r.returncode:
        t.record(False, label or "capture " + os.path.basename(out), r.stderr.decode(errors="replace")[-300:])
        return None
    return out


def compare(t, arc, files, links=None, label=None, env=None, dirs=(), check_dirs=True):
    """Our extraction + listing against {name: data} and {link: target}."""
    label = label or os.path.basename(arc)
    links = links or {}
    try:
        r, rows, out = t.extract(arc, env=env)
    except subprocess.TimeoutExpired:
        return t.record(False, label, "timeout")
    if r.returncode:
        return t.record(False, label, "driver failed: " + r.stdout.decode(errors="replace")[:200])
    lr, typ, lst = t.listing(arc, env=env)
    targets = {}
    for row in lst:
        nm, _, tg = row["name"].partition(" -> ")
        targets[nm] = tg
    problems, seen, seen_dirs = [], set(), set()
    for i, (st, isdir, size, name) in rows.items():
        if isdir:
            seen_dirs.add(name)
            continue
        seen.add(name)
        data = open(os.path.join(out, "%d.bin" % i), "rb").read() if os.path.exists(os.path.join(out, "%d.bin" % i)) else None
        if name in links:
            got = targets.get(name) or (data.decode("utf-8", "replace") if data is not None else None)
            if st or got != links[name]:
                problems.append("link %s: st=%d %r" % (name, st, got))
        elif name in files:
            if st or data != files[name]:
                problems.append("%s: st=%d %s" % (name, st, "data" if not st else ""))
        else:
            problems.append("unexpected " + name)
    for k in list(files) + list(links):
        if k not in seen:
            problems.append("missing " + k)
    if check_dirs:
        for d in dirs:
            if d not in seen_dirs:
                problems.append("missing dir " + d)
    shutil.rmtree(out, ignore_errors=True)
    return t.record(not problems, label, "; ".join(problems[:6]) or "%d entries, %s" % (len(rows), typ))


def vs_7z(t, arc, label, links=()):
    """7-Zip's extraction as the reference (it shows wimlib's symlinks as files with an
    alternate stream "name:_" - those are left out)."""
    r, out = t.sevenzip_extract(arc)
    if r.returncode:
        return t.record(False, label, "7z failed: " + r.stdout.decode(errors="replace")[-200:])
    exp = {k: v for k, v in t.read_tree(out).items() if not (k.endswith(":_") and not v)}
    shutil.rmtree(out, ignore_errors=True)
    return compare(t, arc, exp, dict(links), label=label, check_dirs=False)


def hostile(t, path, label, keep=False):
    """check_hostile, then drop the input and its output (keeps the work directory small)"""
    ok = t.check_hostile(path, label=label)
    shutil.rmtree(os.path.join(t.work, "out_" + os.path.basename(path)), ignore_errors=True)
    if ok and not keep:
        os.remove(path)
    return ok


def lib_wim():
    name = ctypes.util.find_library("wim") or "libwim.so.15"
    try:
        lib = ctypes.CDLL(name)
    except OSError:
        return None
    lib.wimlib_create_compressor.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p)]
    lib.wimlib_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    lib.wimlib_compress.restype = ctypes.c_size_t
    lib.wimlib_free_compressor.argtypes = [ctypes.c_void_p]
    return lib


def lzms_compress(lib, data, level, block=None):
    c = ctypes.c_void_p()
    if lib.wimlib_create_compressor(3, block or max(len(data), 1), level, ctypes.byref(c)):
        return None
    out = ctypes.create_string_buffer(len(data) + 64)
    n = lib.wimlib_compress(data, len(data), out, max(len(data) - 1, 0), c)
    lib.wimlib_free_compressor(c)
    return out.raw[:n] if n else None


# ---------------- a small WIM parser for patching uncompressed images ----------------

class Wim:
    def __init__(self, path):
        self.b = bytearray(open(path, "rb").read())

    def reshdr(self, o):
        b = self.b
        return int.from_bytes(b[o:o + 7], "little"), b[o + 7], struct.unpack_from("<Q", b, o + 8)[0], \
            struct.unpack_from("<Q", b, o + 16)[0]

    def table(self):
        """[(file position of the entry, size, flags, off, usize, part, hash)]"""
        size, fl, off, us = self.reshdr(0x30)
        out = []
        for p in range(off, off + size - 49, 50):
            s, f, o, u = self.reshdr(p)
            out.append((p, s, f, o, u, struct.unpack_from("<H", self.b, p + 24)[0], bytes(self.b[p + 30:p + 50])))
        return out

    def metadata(self, i=0):
        m = [e for e in self.table() if e[2] & 2]
        e = m[i]
        assert not (e[2] & 4), "metadata must be uncompressed"
        return e, bytearray(self.b[e[3]:e[3] + e[4]])

    def set_metadata(self, i, data):
        e, old = self.metadata(i)
        assert len(data) == len(old)
        self.b[e[3]:e[3] + len(data)] = data
        self.b[e[0] + 30:e[0] + 50] = hashlib.sha1(bytes(data)).digest()

    def blob_of(self, data):
        h = hashlib.sha1(data).digest()
        for e in self.table():
            if e[6] == h:
                return e
        return None

    def dentries(self, m):
        """{name: offset} of every dentry, walking the tree from the root"""
        root = (struct.unpack_from("<I", m, 0)[0] + 7) & ~7
        out = {}

        def walk(off, prefix, depth):
            while depth < 64:
                ln = struct.unpack_from("<Q", m, off)[0]
                if ln <= 8:
                    return
                nb = struct.unpack_from("<H", m, off + 0x64)[0]
                nstr = struct.unpack_from("<H", m, off + 0x60)[0]
                name = prefix + m[off + 0x66:off + 0x66 + nb].decode("utf-16le")
                out[name] = off
                sub = struct.unpack_from("<Q", m, off + 16)[0]
                attr = struct.unpack_from("<I", m, off + 8)[0]
                nxt = off + ((ln + 7) & ~7)
                for _ in range(nstr):
                    nxt += (struct.unpack_from("<Q", m, nxt)[0] + 7) & ~7
                if sub and attr & 0x10:
                    walk(sub, name + "/", depth + 1)
                off = nxt
        out[""] = root
        walk(struct.unpack_from("<Q", m, root + 16)[0], "", 0)
        return out

    def save(self, path):
        open(path, "wb").write(self.b)
        return path


def run(t):
    t.need("wimlib-imagex")
    have7z = bool(t.tool("7z"))
    W = t.work
    files, dirs, links, hard = source_tree()
    allfiles = dict(files)
    for k, v in hard.items():
        allfiles[k] = files[v]
    src = write_source(t, os.path.join(W, "src"), files, dirs, links, hard)
    small = {k: v for k, v in files.items() if not k.startswith("data/")}
    ssrc = write_source(t, os.path.join(W, "src_small"), small, dirs, {"link_rel": "readme.txt"}, {})

    # ---- every compression type and chunk size, against the source tree and 7-Zip
    cases = [("none", []), ("XPRESS", []), ("LZX", []), ("LZMS", []),
             ("XPRESS", ["--chunk-size=4096"]), ("XPRESS", ["--chunk-size=65536"]),
             ("LZX", ["--chunk-size=65536"]), ("LZX", ["--chunk-size=2097152"]),
             ("LZMS", ["--chunk-size=32768"]), ("LZMS", ["--chunk-size=1048576"]),
             ("LZMS", ["--chunk-size=67108864"]), ("LZX", ["--compress=maximum"])]
    made = {}
    for ct, extra in cases:
        tag = ct + "".join(x.replace("--chunk-size=", "_c").replace("--compress=", "_") for x in extra)
        arc = capture(t, src, t.path("c_%s.wim" % tag), "--compress=" + ct, *extra)
        if not arc:
            continue
        made[tag] = arc
        compare(t, arc, allfiles, links, label="%s: source tree" % tag, dirs=dirs)
        if have7z:
            vs_7z(t, arc, "%s: vs 7-Zip" % tag, links)

    # solid resources (version 3584): LZMS, and LZX / XPRESS / none inside solid blocks
    solid = [("solid LZMS", ["--solid"]), ("solid LZMS 1M chunks", ["--solid", "--solid-chunk-size=1048576"]),
             ("solid LZMS 32K chunks", ["--solid", "--solid-chunk-size=32768"]),
             ("solid LZX", ["--solid", "--solid-compress=LZX"]),
             ("solid XPRESS", ["--solid", "--solid-compress=XPRESS"])]
    for label, opts in solid:
        arc = capture(t, src, t.path(label.replace(" ", "_") + ".wim"), *opts)
        if not arc:
            continue
        made[label] = arc
        compare(t, arc, allfiles, links, label=label, dirs=dirs)
        if have7z:
            vs_7z(t, arc, label + ": vs 7-Zip", links)
    if "solid LZMS" in made:
        _, typ, lst = t.listing(made["solid LZMS"])
        meth = {r["name"]: r["method"] for r in lst}
        t.record(meth.get("data/big.txt", "").startswith("LZMS:26") and "Solid" in meth.get("data/big.txt", ""),
                 "solid method name", str(meth.get("data/big.txt")))
        # random access into solid resources (each entry on its own, shuffled)
        drv = t.build_driver("tests/drivers/arc_random.c")
        for mode in ("rev", "shuffle"):
            out = t.path("rand_" + mode)
            shutil.rmtree(out, ignore_errors=True)
            r = t.sh([drv, made["solid LZMS"], out, mode, "3"], check=False)
            ok = r.returncode == 0
            bad = []
            for line in r.stdout.decode("utf-8", "replace").splitlines():
                p = line.split("\t")
                if len(p) == 5 and p[2] == "0" and p[4] in allfiles:
                    if p[1] != "0" or open(os.path.join(out, p[0] + ".bin"), "rb").read() != allfiles[p[4]]:
                        bad.append(p[4])
            shutil.rmtree(out, ignore_errors=True)
            t.record(ok and not bad, "solid random access " + mode, ", ".join(bad[:4]))
    if "LZX" in made:
        _, typ, lst = t.listing(made["LZX"])
        meth = {r["name"]: r["method"] for r in lst}
        t.record(meth.get("data/big.txt") == "LZX:15" and meth.get("data/random.bin") == "Copy",
                 "method names", "%s / %s" % (meth.get("data/big.txt"), meth.get("data/random.bin")))
        t.record(typ == "WIM", "type name", str(typ))

    # ---- wimlib apply as a second reference (also checks symlink targets on disk)
    if "LZMS" in made:
        ap = t.path("apply_lzms")
        shutil.rmtree(ap, ignore_errors=True)
        r = t.sh(["wimlib-imagex", "apply", made["LZMS"], "1", ap], check=False)
        if not r.returncode:
            exp = t.read_tree(ap)
            lk = {}
            for dp, dns, fns in os.walk(ap):
                for f in fns + dns:
                    fp = os.path.join(dp, f)
                    if os.path.islink(fp):
                        lk[os.path.relpath(fp, ap)] = os.readlink(fp)
            compare(t, made["LZMS"], exp, lk, label="LZMS vs wimlib apply")
        shutil.rmtree(ap, ignore_errors=True)

    # ---- a WIM written by 7-Zip (its own writer: uncompressed, links followed)
    if have7z:
        z7 = t.path("by7z.wim")
        if os.path.exists(z7):
            os.remove(z7)
        r = t.sh(["7z", "a", "-twim", z7, "src_small"], cwd=W, check=False)
        if r.returncode:
            t.record(False, "7z a -twim", r.stdout.decode(errors="replace")[-200:])
        else:
            exp = {"src_small/" + k: v for k, v in small.items()}
            exp["src_small/link_rel"] = small["readme.txt"]
            compare(t, z7, exp, label="WIM written by 7-Zip", dirs=["src_small/빈폴더", "src_small/deep/empty"])

    # ---- unix data (--unix-data): permissions from wimlib's tagged items
    os.chmod(os.path.join(ssrc, "readme.txt"), 0o640)
    os.chmod(os.path.join(ssrc, "deep"), 0o750)
    arc = capture(t, ssrc, t.path("unix.wim"), "--unix-data", "--compress=LZX")
    if arc:
        _, typ, lst = t.listing(arc)
        m = {r["name"].partition(" -> ")[0]: r["mode"] for r in lst}
        t.record(m.get("readme.txt") == 0o100640 and m.get("deep") == 0o40750 and m.get("link_rel") == 0o120777,
                 "unix modes", "%o %o %o" % (m.get("readme.txt", 0), m.get("deep", 0), m.get("link_rel", 0)))

    # ---- several images: folders "1", "2" and [1].xml (like 7-Zip)
    multi = t.path("multi.wim")
    if "LZX" in made:
        shutil.copy(made["LZX"], multi)
        s2 = t.write_tree(os.path.join(W, "src2"), {"x/two.txt": b"second image\n", "공유.txt": files["readme.txt"]})
        r1 = t.sh(["wimlib-imagex", "append", s2, multi, "두 번째"], check=False)
        s3 = t.write_tree(os.path.join(W, "src3"), {"three.txt": b"3"})
        r2 = t.sh(["wimlib-imagex", "append", s3, multi, "third", "--compress=LZX"], check=False)
        if r1.returncode or r2.returncode:
            t.record(False, "wimlib append", (r1.stderr + r2.stderr).decode(errors="replace")[-200:])
        else:
            exp = {"1/" + k: v for k, v in allfiles.items()}
            exp.update({"2/x/two.txt": b"second image\n", "2/공유.txt": files["readme.txt"], "3/three.txt": b"3"})
            raw = Wim(multi)
            sz, fl, off, us = raw.reshdr(0x48)
            exp["[1].xml"] = bytes(raw.b[off:off + sz])
            compare(t, multi, exp, {"1/" + k: v for k, v in links.items()}, label="3 images",
                    dirs=["1", "2", "3", "1/빈폴더", "2/x"])
            if have7z:
                vs_7z(t, multi, "3 images: vs 7-Zip", {"1/" + k: v for k, v in links.items()})

    # ---- split WIM (.swm parts through open_volume), opened from any part
    if os.path.exists(multi):
        sp = t.path("split", "set.swm")
        for f in os.listdir(os.path.dirname(sp)):
            os.remove(os.path.join(os.path.dirname(sp), f))
        r = t.sh(["wimlib-imagex", "split", multi, sp, "%.3f" % (os.path.getsize(multi) / 3.5 / 1048576)], check=False)
        parts = sorted(os.listdir(os.path.dirname(sp)))
        if r.returncode or len(parts) < 3:
            t.record(False, "wimlib split", "%s %s" % (parts, r.stderr.decode(errors="replace")[-200:]))
        else:
            exp = {"1/" + k: v for k, v in allfiles.items()}
            exp.update({"2/x/two.txt": b"second image\n", "2/공유.txt": files["readme.txt"], "3/three.txt": b"3"})
            raw = Wim(sp)
            sz, fl, off, us = raw.reshdr(0x48)
            exp["[1].xml"] = bytes(raw.b[off:off + sz])
            lk = {"1/" + k: v for k, v in links.items()}
            compare(t, sp, exp, lk, label="split: %d parts from part 1" % len(parts))
            compare(t, t.path("split", "set2.swm"), exp, lk, label="split: opened from part 2")
            # a missing part: its files fail with GZ_E_VOLUME (14), the rest extracts
            os.rename(t.path("split", "set2.swm"), t.path("split", "gone.bin"))
            r, rows, out = t.extract(sp)
            st = {name: s for i, (s, isdir, size, name) in rows.items() if not isdir}
            vol = sum(1 for v in st.values() if v == 14)
            okf = sum(1 for k, v in st.items() if v == 0 and k in exp and
                      open(os.path.join(out, "%d.bin" % [i for i, rr in rows.items() if rr[3] == k][0]), "rb").read() == exp[k])
            t.record(r.returncode == 0 and vol > 0 and okf > 0 and vol + okf + 3 >= len(st),
                     "split: missing part 2", "volume errors %d, good %d of %d" % (vol, okf, len(st)))
            shutil.rmtree(out, ignore_errors=True)
            os.rename(t.path("split", "gone.bin"), t.path("split", "set2.swm"))
            # part 1 missing: nothing can be listed
            os.rename(sp, t.path("split", "gone1.bin"))
            r = t.run_gzt(["l", t.path("split", "set2.swm")])
            t.record(b"OPEN_ERROR 14" in r.stdout, "split: part 1 missing -> GZ_E_VOLUME", r.stdout.decode()[:80])
            os.rename(t.path("split", "gone1.bin"), sp)
        # split of a solid LZMS WIM
        if "solid LZMS" in made:
            sp = t.path("split_solid", "s.swm")
            for f in os.listdir(os.path.dirname(sp)):
                os.remove(os.path.join(os.path.dirname(sp), f))
            r = t.sh(["wimlib-imagex", "split", made["solid LZMS"], sp, "0.1"], check=False)
            if not r.returncode:
                compare(t, sp, allfiles, links, label="split solid LZMS")

    # ---- NTFS alternate data streams, security data, attributes (NTFS image capture)
    if t.tool("mkntfs") and t.tool("ntfscp"):
        img = t.path("ntfs.img")
        with open(img, "wb") as f:
            f.truncate(16 << 20)
        t.sh(["mkntfs", "-F", "-q", "-Q", img], check=False)
        main, alt, alt2 = b"main data stream\n", text_blob(50000, 9), b"zone id\n"
        pm, pa, pb = (t.path("ads_" + n) for n in ("m", "a", "b"))
        open(pm, "wb").write(main)
        open(pa, "wb").write(alt)
        open(pb, "wb").write(alt2)
        ok = not t.sh(["ntfscp", img, pm, "file.txt"], check=False).returncode
        ok = ok and not t.sh(["ntfscp", "-N", "big stream", img, pa, "file.txt"], check=False).returncode
        ok = ok and not t.sh(["ntfscp", "-N", "Zone.Identifier", img, pb, "file.txt"], check=False).returncode
        if ok:
            for ct in ("LZX", "LZMS"):
                arc = capture(t, img, t.path("ads_%s.wim" % ct), "--compress=" + ct)
                if arc:
                    exp = {"file.txt": main, "file.txt:big stream": alt, "file.txt:Zone.Identifier": alt2}
                    compare(t, arc, exp, label="NTFS ADS %s" % ct, check_dirs=False)
                    if have7z:
                        vs_7z(t, arc, "NTFS ADS %s: vs 7-Zip" % ct)
        else:
            t.record(False, "ntfscp alternate streams")

    # ---- LZMS decoder against wimlib's compressor, chunk by chunk
    lib = lib_wim()
    drv = t.build_driver("tests/drivers/lzms_test.c")
    rec = t.path("lzms.rec")
    if lib:
        inputs = [("text", text_blob(600000, 11)), ("code", code_blob(500000)),
                  ("prog32", b"".join(struct.pack("<I", 1000 + i * 37) for i in range(60000))),
                  ("prog16", b"".join(struct.pack("<HH", i * 3 & 0xffff, (5000 - i * 2) & 0xffff) for i in range(40000))),
                  ("rgb", bytes(v for i in range(50000) for v in ((i * 2) & 255, (i * 3 + 7) & 255, (100 + i // 50) & 255))),
                  ("runs", b"a" * 50000 + b"ab" * 20000 + b"abc" * 10000),
                  ("mixed", text_blob(60000, 12) + rand_blob(8000, 13) + code_blob(80000))]
        tiny = [b"x" * n for n in (1, 2, 3, 4, 16, 17, 18, 19, 64)] + [text_blob(n, n) for n in (5, 31, 100, 257, 4097)]
        n = 0
        with open(rec, "wb") as f:
            def put(chunk, lvl, block=None):
                z = lzms_compress(lib, chunk, lvl, block)
                if z:
                    f.write(struct.pack("<II", len(chunk), len(z)) + z + chunk)
                    return 1
                return 0
            for name, data in inputs:
                for lvl in (1, 50, 100):
                    for cs in (32768, 131072, 1 << 20):
                        for k in range(0, min(len(data), 3 * cs), cs):
                            n += put(data[k:k + cs], lvl, cs)
                n += put(data, 50)                      # whole input as one chunk
            for d in tiny:
                n += put(d, 50)
        r = t.sh([drv, "dec", rec], check=False)
        t.record(r.returncode == 0, "LZMS chunks vs wimlib (%d)" % n, r.stdout.decode(errors="replace")[-300:])
        r = t.sh([drv, "fuzz", rec, "4000", "11"], check=False, timeout=300)
        bad = r.returncode != 0 or b"Sanitizer" in r.stderr or b"runtime error" in r.stderr
        t.record(not bad, "LZMS fuzz (bit flips, truncation, garbage, sizes)",
                 (r.stdout + r.stderr).decode(errors="replace")[-300:])
        r = t.sh([drv, "bench", rec, "3"], check=False)
        t.record(r.returncode == 0, "LZMS speed", r.stdout.decode().strip())
    else:
        t.record(True, "LZMS codec vs libwim skipped (no libwim)")

    # ---- crafted and hostile inputs (uncompressed WIM, so the metadata can be patched)
    base = capture(t, ssrc, t.path("plain.wim"), "--compress=none")
    if base:
        w = Wim(base)
        e, m = w.metadata()
        ds = w.dentries(m)

        def patched(name, fn):
            ww = Wim(base)
            mm = bytearray(m)
            fn(ww, mm)
            ww.set_metadata(0, mm)
            return ww.save(t.path("h_" + name + ".wim"))

        root_sub = struct.unpack_from("<Q", m, ds[""] + 16)[0]
        deep = ds["deep"]
        # directory cycles: a subdirectory listing its ancestor's children, or itself
        p = patched("cycle", lambda ww, mm: struct.pack_into("<Q", mm, ds["deep/a/b"] + 16, root_sub))
        hostile(t, p, "hostile: dentry cycle to root", keep=True)
        r, rows, out = t.extract(p)
        shutil.rmtree(out, ignore_errors=True)
        t.record(r.returncode == 0 and len(rows) < 100, "dentry cycle is cut", "%d entries" % len(rows))
        p = patched("selfloop", lambda ww, mm: struct.pack_into("<Q", mm, deep + 16, deep))
        hostile(t, p, "hostile: directory listing itself")
        for name, fn in [
            ("dlen_huge", lambda ww, mm: struct.pack_into("<Q", mm, ds["readme.txt"], 0xFFFFFFFFFFFFFFF0)),
            ("dlen_small", lambda ww, mm: struct.pack_into("<Q", mm, ds["readme.txt"], 40)),
            ("nstreams", lambda ww, mm: struct.pack_into("<H", mm, ds["readme.txt"] + 0x60, 0xFFFF)),
            ("namelen", lambda ww, mm: struct.pack_into("<H", mm, ds["readme.txt"] + 0x64, 0xFFFF)),
            ("namelen_odd", lambda ww, mm: struct.pack_into("<H", mm, ds["readme.txt"] + 0x64, 7)),
            ("sec_huge", lambda ww, mm: struct.pack_into("<I", mm, 0, 0xFFFFFFF0)),
            ("sub_unaligned", lambda ww, mm: struct.pack_into("<Q", mm, deep + 16, root_sub + 3)),
            ("sub_far", lambda ww, mm: struct.pack_into("<Q", mm, deep + 16, 1 << 62)),
            ("dotdot", lambda ww, mm: mm.__setitem__(slice(ds["readme.txt"] + 0x66, ds["readme.txt"] + 0x6A), "..".encode("utf-16le"))),
        ]:
            hostile(t, patched(name, fn), "hostile: metadata " + name, keep=name == "dotdot")
        # ".." as a name must not escape: it is dropped
        r, rows, out = t.extract(t.path("h_dotdot.wim"))
        t.record(all(".." not in rr[3].split("/") for rr in rows.values()), "dentry named '..' dropped")
        shutil.rmtree(out, ignore_errors=True)

        # SHA-1 mismatch -> GZ_E_CRC (4) for that file only
        ww = Wim(base)
        be = ww.blob_of(files["문서/보고서.txt"])
        ww.b[be[3] + 1000] ^= 0x20
        p = ww.save(t.path("h_sha1.wim"))
        r, rows, out = t.extract(p)
        st = {rr[3]: rr[0] for rr in rows.values()}
        t.record(st.get("문서/보고서.txt") == 4 and st.get("readme.txt") == 0, "SHA-1 mismatch -> GZ_E_CRC",
                 str(st.get("문서/보고서.txt")))
        shutil.rmtree(out, ignore_errors=True)
        # metadata SHA-1 mismatch: the image cannot be trusted
        ww = Wim(base)
        ww.b[e[3] + e[4] - 20] ^= 1
        p = ww.save(t.path("h_metasha.wim"))
        r = t.run_gzt(["l", p])
        t.record(b"OPEN_ERROR 4" in r.stdout, "metadata SHA-1 mismatch -> open fails", r.stdout.decode()[:60])

        # encrypted ESD: <ENCRYPTED> in the XML data -> GZ_E_METHOD (5)
        ww = Wim(base)
        xml = ("﻿<WIM><ESD><ENCRYPTED><KEY>AAAA</KEY></ENCRYPTED></ESD><IMAGE INDEX=\"1\"></IMAGE></WIM>").encode("utf-16le")
        off = len(ww.b)
        ww.b += xml
        struct.pack_into("<Q", ww.b, 0x48, len(xml) | (2 << 56))
        struct.pack_into("<QQ", ww.b, 0x50, off, len(xml))
        p = ww.save(t.path("h_encrypted.esd"))
        r = t.run_gzt(["l", p])
        t.record(b"OPEN_ERROR 5" in r.stdout, "encrypted ESD -> GZ_E_METHOD", r.stdout.decode()[:60])

        # header / blob table fields
        for name, fn in [
            ("images_huge", lambda b: struct.pack_into("<I", b, 0x2C, 0xFFFFFFFF)),
            ("images_more", lambda b: struct.pack_into("<I", b, 0x2C, 7)),
            ("parts_huge", lambda b: struct.pack_into("<HH", b, 0x28, 1, 0xFFFF)),
            ("parts_weird", lambda b: struct.pack_into("<HH", b, 0x28, 3, 2)),
            ("table_huge", lambda b: struct.pack_into("<QQQ", b, 0x30, 0x00FFFFFFFFFFFFFF, 0, 0xFFFFFFFFFFFF)),
            ("table_past_end", lambda b: struct.pack_into("<Q", b, 0x38, len(b) - 10)),
            ("xml_huge", lambda b: struct.pack_into("<QQQ", b, 0x48, 0x40000000, 0x100, 0x40000000)),
            ("chunk_zero_compressed", lambda b: struct.pack_into("<II", b, 0x10, 0x40082, 0)),
            ("header_short", lambda b: struct.pack_into("<I", b, 8, 12)),
        ]:
            ww = Wim(base)
            fn(ww.b)
            hostile(t, ww.save(t.path("h_%s.wim" % name)), "hostile: header " + name)
        # blob table entries: wrong offsets, sizes, flags and part numbers
        tab = w.table()
        for name, fn in [
            ("blob_off", lambda b, p: struct.pack_into("<Q", b, p + 8, 0xFFFFFFFFFFFF0000)),
            ("blob_usize", lambda b, p: struct.pack_into("<Q", b, p + 16, 0xFFFFFFFFFFFFFFFF)),
            ("blob_compressed", lambda b, p: b.__setitem__(p + 7, 4)),
            ("blob_solid", lambda b, p: b.__setitem__(p + 7, 0x10)),
            ("blob_solid_magic", lambda b, p: (b.__setitem__(p + 7, 0x10), struct.pack_into("<Q", b, p + 16, 1 << 32))),
            ("blob_spanned", lambda b, p: b.__setitem__(p + 7, 8)),
            ("blob_part", lambda b, p: struct.pack_into("<H", b, p + 24, 9)),
            ("blob_meta", lambda b, p: b.__setitem__(p + 7, 2)),
        ]:
            for k, ent in enumerate(tab[:3]):
                ww = Wim(base)
                fn(ww.b, ent[0])
                hostile(t, ww.save(t.path("h_%s_%d.wim" % (name, k))), "hostile: table %s #%d" % (name, k))
        # huge blob tables built to be slow: 200000 hashes sharing their first bytes, and a
        # run of 60000 solid resources with 60000 blobs (must stay fast: sorted lookups)
        rnd = random.Random(3)
        old = b"".join(bytes(w.b[e[0]:e[0] + 50]) for e in tab)
        bulk = [struct.pack("<QQQHI", 10, 208, 10, 1, 1) + bytes(8) + rnd.randbytes(12) for _ in range(200000)]
        solid_res = struct.pack("<Q", 16 | (0x10 << 56)) + struct.pack("<QQHI", 208, 1 << 32, 1, 1) + bytes(20)
        solid_blob = [struct.pack("<Q", 5 | (0x10 << 56)) + struct.pack("<QQHI", k * 7, 5, 1, 1) + rnd.randbytes(20)
                      for k in range(60000)]
        for name, ents in (("collide", bulk), ("solid_run", [solid_res] * 60000 + solid_blob)):
            ww = Wim(base)
            tb = old + b"".join(ents)
            off = len(ww.b)
            ww.b += tb
            struct.pack_into("<QQQ", ww.b, 0x30, len(tb) | (2 << 56), off, len(tb))
            p = ww.save(t.path("h_table_%s.wim" % name))
            t0 = time.time()
            hostile(t, p, "hostile: table %s (%d entries)" % (name, len(ents)))
            t.record(time.time() - t0 < 20, "table %s is fast" % name, "%.1fs" % (time.time() - t0))

    # chunk tables and compressed streams of every method
    for tag in ("LZX", "XPRESS", "LZMS", "solid LZMS", "solid LZX"):
        if tag not in made:
            continue
        w = Wim(made[tag])
        tab = sorted(w.table(), key=lambda e: -e[1])
        big = tab[0]
        rnd = random.Random(len(tag))
        variants = []
        for k in range(6):
            b = bytearray(w.b)
            pos = big[3] + (k * 4 if k < 3 else rnd.randrange(big[1]))
            if k < 3:
                struct.pack_into("<I", b, pos, [0xFFFFFFFF, 0, 0x7FFFFFFF][k])
            else:
                for q in range(64):
                    if pos + q < len(b):
                        b[pos + q] = rnd.getrandbits(8)
            variants.append(b)
        if big[2] & 0x10:
            for vals in [(1 << 62, 1 << 26, 3), (1000, 0, 3), (1000, 4096, 9), (1 << 40, 1 << 30, 3), (5, 1, 2)]:
                b = bytearray(w.b)
                struct.pack_into("<QII", b, big[3], *vals)
                variants.append(b)
        for k, b in enumerate(variants):
            p = t.path("h_chunks_%s_%d.wim" % (tag.replace(" ", "_"), k))
            open(p, "wb").write(b)
            hostile(t, p, "hostile: %s chunk table/data %d" % (tag, k))

    # truncation and random bit flips of every kind of fixture
    rnd = random.Random(7)
    for tag in ("none", "LZX", "XPRESS", "LZMS", "solid LZMS", "solid XPRESS"):
        if tag not in made:
            continue
        data = open(made[tag], "rb").read()
        for k, cut in enumerate([100, 208, 300, len(data) // 3, len(data) - 2000, len(data) - 100, len(data) - 1]):
            p = t.path("h_trunc_%s_%d.wim" % (tag.replace(" ", "_"), k))
            open(p, "wb").write(data[:max(cut, 0)])
            hostile(t, p, "hostile: %s truncated at %d" % (tag, cut))
        for k in range(12):
            b = bytearray(data)
            for _ in range(rnd.randrange(1, 16)):
                b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
            p = t.path("h_flip_%s_%d.wim" % (tag.replace(" ", "_"), k))
            open(p, "wb").write(b)
            hostile(t, p, "hostile: %s bit flips %d" % (tag, k))

    # in-process fuzzing (many more variants; small fixtures keep it fast under ASan)
    fz = t.build_driver("tests/drivers/wim_fuzz.c")
    fsrc = t.write_tree(os.path.join(W, "src_fuzz"), {"a.txt": text_blob(40000, 31), "b/c.bin": code_blob(60000),
                                                     "b/d.txt": b"tiny", "e.bin": rand_blob(3000, 32)})
    os.symlink("a.txt", os.path.join(fsrc, "link"))
    for k, opts in enumerate([["--compress=none"], ["--compress=LZX"], ["--compress=XPRESS"], ["--compress=LZMS"],
                              ["--solid"], ["--solid", "--solid-compress=LZX"]]):
        arc = capture(t, fsrc, t.path("fz_%d.wim" % k), *opts)
        if not arc:
            continue
        r = t.sh([fz, arc, "400", str(k + 1)], check=False, timeout=600)
        out = (r.stdout + r.stderr).decode(errors="replace")
        t.record(r.returncode == 0 and "Sanitizer" not in out and "runtime error" not in out,
                 "in-process fuzz %s" % " ".join(opts), out.strip()[-300:])

    # ---- engine: multithreaded extraction through the command line tool (links on disk)
    cli = os.path.join(os.path.dirname(t.gzt), "gogitzip")
    if os.path.exists(cli) and "LZX" in made:
        for tag in ("LZX", "solid LZMS"):
            if tag not in made:
                continue
            out = t.path("cli_" + tag.replace(" ", "_"))
            shutil.rmtree(out, ignore_errors=True)
            r = subprocess.run([cli, "x", made[tag], "-o", out, "-t", "4"], capture_output=True, timeout=300)
            got = t.read_tree(out)
            lk = {}
            for dp, dns, fns in os.walk(out):
                for f in fns + dns:
                    fp = os.path.join(dp, f)
                    if os.path.islink(fp):
                        lk[os.path.relpath(fp, out)] = os.readlink(fp)
            bad = [k for k, v in allfiles.items() if got.get(k) != v]
            lbad = [k for k in ("link_rel", "bin/link_up") if lk.get(k) != links[k]]
            err = r.stderr.decode(errors="replace")
            rc_ok = r.returncode == 0 or (r.returncode == 1 and err.count("WARNING") == 1 and "link_abs" in err)
            t.record(rc_ok and not bad and not lbad, "gogitzip x -t 4 (%s)" % tag,
                     "rc=%d %s %s %s" % (r.returncode, bad[:3], lbad, r.stderr.decode(errors="replace")[-200:]))
            shutil.rmtree(out, ignore_errors=True)

    # ---- speed: LZMS solid extraction against 7-Zip and wimlib
    big = t.path("perf_src")
    if not os.path.exists(big):
        t.write_tree(big, {"code.bin": code_blob(4 << 20), "text.txt": text_blob(12 << 20, 21),
                           "rand.bin": rand_blob(2 << 20, 22)})
    for label, opts in (("LZMS solid", ["--solid"]), ("LZX", ["--compress=LZX"])):
        arc = capture(t, big, t.path("perf_%s.wim" % label.replace(" ", "_")), *opts)
        if not arc:
            continue
        t0 = time.time()
        r, rows, out = t.extract(arc)
        ours = time.time() - t0
        ok = r.returncode == 0 and all(v[0] == 0 for v in rows.values())
        shutil.rmtree(out, ignore_errors=True)
        detail = "ours %.2fs" % ours
        if have7z:
            t0 = time.time()
            rr, ref = t.sevenzip_extract(arc)
            detail += ", 7-Zip %.2fs" % (time.time() - t0)
            shutil.rmtree(ref, ignore_errors=True)
        ap = t.path("perf_apply")
        shutil.rmtree(ap, ignore_errors=True)
        t0 = time.time()
        t.sh(["wimlib-imagex", "apply", arc, "1", ap], check=False)
        detail += ", wimlib apply %.2fs" % (time.time() - t0)
        shutil.rmtree(ap, ignore_errors=True)
        os.remove(arc)
        t.record(ok, "speed %s 18 MB" % label, detail)
