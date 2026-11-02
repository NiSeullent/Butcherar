"""SquashFS 4.0 / 3.x and CramFS images.

SquashFS (mksquashfs): every compressor (gzip, lzo, lz4, xz with BCJ filters, zstd, lzma),
block sizes 4K..1M, fragments / tail ends on and off, uncompressed tables (-noI -noD -noF
-noX), sparse files, duplicates, hard links, symlinks, Korean (NFC/NFD) names, big
directories, files > 4 GiB, modes / times / owners; checked against the source tree,
7-Zip and unsquashfs. SquashFS 3.1 (crafted writer, checked with 7-Zip first): little /
big endian, extended inodes, check-data markers, raw-LZMA and "shsq" vendor variants. CramFS (mkfs.cramfs + a crafted writer for the extended block
pointers of newer kernels): little/big endian, block sizes, boot pad, holes, CRC.
Random-access views, nested archives, threads, per-thread caches across archives,
hostile images (targeted patches + in-process fuzzing)."""
import os, io, random, shutil, socket, struct, subprocess, time, unicodedata, zipfile, zlib, calendar

ENV = dict(os.environ, LANG="C.UTF-8", LC_ALL="C.UTF-8", TZ="UTC")
WHEN = calendar.timegm((2021, 3, 4, 5, 6, 7))
FT_EPOCH = 11644473600

def ft_of(unix):
    return (unix + FT_EPOCH) * 10000000

def blob(n, seed, kind="rand"):
    rnd = random.Random(seed * 7919 + n)
    if kind == "rand":
        return rnd.randbytes(n)
    words = ["고기".encode(), b"meat", b"grill", b"squash", b"block", b"\n", b"fragment", b"inode", b"zip"]
    out = bytearray()
    while len(out) < n:
        if kind == "mixed" and rnd.random() < 0.02:
            out += rnd.randbytes(rnd.randrange(64, 4096))
        else:
            out += rnd.choice(words) + b" "
    return bytes(out[:n])

def with_dirs(files):
    out = dict(files)
    for k in files:
        parts = k.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            out.setdefault("/".join(parts[:i]), None)
    return out

# ---------------------------------------------------------------- driver helpers (fs1_dump)

def dump(drv, img):
    r = subprocess.run([drv, "l", img], capture_output=True, timeout=300)
    rows, typ = {}, None
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if p[0] == "TYPE":
            typ = p[1]
        elif len(p) >= 13 and p[0].isdigit():
            name, link = p[12], None
            if " -> " in name:
                name, link = name.split(" -> ", 1)
            rows[name] = dict(idx=int(p[0]), is_dir=int(p[1]), is_link=int(p[2]), usize=int(p[3]),
                              csize=int(p[4]), mk=int(p[5]), mtime=int(p[6]), attr=int(p[7]),
                              mode=int(p[8], 8), aux=int(p[9]), aux32=int(p[10]), flags=int(p[11]), link=link)
    return r, typ, rows

def check_views(t, drv, img, label):
    """extraction CRC == CRC of the random-access view read in shuffled chunks"""
    r = subprocess.run([drv, "v", img], capture_output=True, timeout=600)
    bad, n = [], 0
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if len(p) < 9 or not p[0].isdigit():
            continue
        n += 1
        st, size, crcx, kind, vs, crcv, err, name = int(p[1]), int(p[2]), p[3], p[4], int(p[5]), p[6], int(p[7]), p[8]
        if st:
            bad.append("%s: extract %d" % (name, st))
        elif kind != "view":
            bad.append("%s: no view" % name)
        elif vs != size or crcv != crcx or err:
            bad.append("%s: view size %d/%d crc %s/%s err %d" % (name, vs, size, crcv, crcx, err))
    return t.record(r.returncode == 0 and n and not bad, label, "; ".join(bad[:5]) or "%d files" % n)

def drop_out(t, img):
    """remove the extraction directory gztest's check_extract leaves behind"""
    shutil.rmtree(os.path.join(t.work, "out_" + os.path.basename(img)), ignore_errors=True)

def extract_check(t, img, exp, label, typ=None, with7z=False):
    """one extraction with gzt, compared with the expected tree and (optionally) with 7-Zip's"""
    tag = os.path.basename(img)
    r, rows, out = t.extract(img)
    info = r.stderr.decode("utf-8", "replace").strip().splitlines()
    info = info[0] if info else ""
    got = {}
    for i, (st, isdir, size, name) in rows.items():
        if not isdir:
            got[name] = (st, os.path.join(out, "%d.bin" % i))
    def compare(want, lab, allow_extra):
        bad = []
        for k, v in want.items():
            if v is None:
                continue
            g = got.get(gztest_norm(k))
            if not g:
                bad.append("missing " + k)
            elif g[0]:
                bad.append("%s: error %d" % (k, g[0]))
            elif open(g[1], "rb").read() != v:
                bad.append("%s: data" % k)
        if not allow_extra:
            names = {gztest_norm(k) for k, v in want.items() if v is not None}
            bad += ["unexpected " + n for n in got if n not in names]
        if r.returncode or (typ and ("type=%s " % typ) not in info):
            bad.append("driver rc=%d %s" % (r.returncode, info))
        return t.record(not bad, lab, "; ".join(bad[:6]) or "%d files" % len(got))
    compare(exp, label, False)
    if with7z:
        r7, out7 = t.sevenzip_extract(img, extra=["-snld"])
        if r7.returncode:
            t.record(False, label + " vs 7z", "7z failed: " + r7.stdout.decode(errors="replace")[-300:])
        else:
            compare(t.read_tree(out7), label + " vs 7z", True)
            shutil.rmtree(out7, ignore_errors=True)
    shutil.rmtree(out, ignore_errors=True)

def gztest_norm(name):
    import gztest
    return gztest.normalize(name)

def survive(drv, img, timeout=60):
    try:
        for cmd in ("l", "v"):
            r = subprocess.run([drv, cmd, img], capture_output=True, timeout=timeout)
            err = r.stderr.decode(errors="replace")
            if r.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err:
                return "%s rc=%d %s" % (cmd, r.returncode, err[-300:])
    except subprocess.TimeoutExpired:
        return "timeout"
    return None

def hostile(t, drv, img, label):
    why = survive(drv, img)
    if why is None:
        return t.check_hostile(img, label=label)
    return t.record(False, label, why)

# ---------------------------------------------------------------- source trees

def make_src(t, root, files, links=(), hard=(), sparse=(), modes=None, owners=None, xattrs=(), special=False):
    """files {rel: bytes|None}, links [(rel, target)], hard [(rel, existing)], sparse [(rel, size, [(off, bytes)])]"""
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    for k, v in sorted(files.items()):
        p = os.path.join(root, k)
        if v is None:
            os.makedirs(p, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(v)
    for rel, size, chunks in sparse:
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.truncate(size)
            for off, data in chunks:
                f.seek(off)
                f.write(data)
    for rel, tgt in hard:
        os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
        os.link(os.path.join(root, tgt), os.path.join(root, rel))
    for rel, tgt in links:
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        os.symlink(tgt, p)
    if special:
        os.mkfifo(os.path.join(root, "special/fifo"))
        os.mknod(os.path.join(root, "special/chardev"), 0o20644, os.makedev(1, 3))
        os.mknod(os.path.join(root, "special/blockdev"), 0o60644, os.makedev(7, 0))
        tmp = "/tmp/gzsq%d" % os.getpid()           # AF_UNIX paths are short: bind, then move
        if os.path.exists(tmp):
            os.remove(tmp)
        s = socket.socket(socket.AF_UNIX)
        s.bind(tmp)
        s.close()
        shutil.move(tmp, os.path.join(root, "special/sock"))
    for rel, mode in (modes or {}).items():
        os.chmod(os.path.join(root, rel), mode)
    for rel, (uid, gid) in (owners or {}).items():
        os.chown(os.path.join(root, rel), uid, gid, follow_symlinks=False)
    for rel, name, val in xattrs:
        try:
            os.setxattr(os.path.join(root, rel), name, val)
        except OSError:
            pass
    for dp, dns, fns in os.walk(root, topdown=False):
        for n in fns + dns:
            os.utime(os.path.join(dp, n), (WHEN, WHEN), follow_symlinks=False)
    os.utime(root, (WHEN, WHEN))
    return root

NFD_NAME = unicodedata.normalize("NFD", "한우.txt")

def main_tree(t):
    f = {
        "readme.txt": blob(5000, 1, "text"),
        "empty.txt": b"",
        "ro.txt": b"read only\n",
        "suid.bin": b"\x7fELF fake\n",
        "owned.txt": b"owned by 1234:5678\n",
        "xattr.txt": b"has an extended attribute\n",
        "고기/삼겹살.txt": "삼겹살은 맛있다\n".encode() * 300,
        "고기/소고기/등심.bin": blob(70000, 3),
        "고기/" + NFD_NAME: b"nfd name\n",
        "deep/" + "/".join("d%d" % i for i in range(30)) + "/leaf.txt": b"deep\n",
        "big/mixed.bin": blob(2500000, 9, "mixed"),
        "big/text.txt": blob(1200000, 10, "text"),
        "dup/a.bin": blob(200000, 11),
        "dup/b.bin": blob(200000, 11),
        "exe/prog.bin": open(t.gzt, "rb").read()[:1000000],
        "emptydir": None,
        "private": None,
    }
    for n in (4095, 4096, 4097, 65535, 65536, 65537, 131071, 131072, 131073, 1048575, 1048577):
        f["sizes/s%d.bin" % n] = blob(n, n, "mixed")
    for i in range(150):
        f["many/f%03d.txt" % i] = ("small file %d\n" % i).encode() * (1 + i % 13)
    for i in range(700):
        f["bigdir/entry_with_a_longer_name_%04d" % i] = bytes([i & 0xFF]) * (i % 5)
    links = [("link_rel", "readme.txt"), ("고기/link_up", "../readme.txt"),
             ("long_link", "x" * 300 + "/target"), ("dangling", "nowhere/at/all"), ("dirlink", "고기")]
    hard = [("hard/readme_hl.txt", "readme.txt"), ("hard/big_hl.bin", "big/mixed.bin")]
    sp_chunks = [(1 << 20, blob(100000, 21)), ((3 << 20) - 10, b"0123456789")]
    sparse = [("sparse/holes.bin", 3 << 20, sp_chunks), ("sparse/zeros.bin", 1 << 20, [])]
    modes = {"ro.txt": 0o444, "suid.bin": 0o4755, "exe/prog.bin": 0o755, "private": 0o700}
    owners = {"owned.txt": (1234, 5678)}
    xattrs = [("xattr.txt", "user.gogi", b"meat")]
    exp = dict(f)
    exp.update({h: f[tgt] for h, tgt in hard})
    sp = bytearray(3 << 20)
    for off, data in sp_chunks:
        sp[off:off + len(data)] = data
    exp["sparse/holes.bin"] = bytes(sp)
    exp["sparse/zeros.bin"] = bytes(1 << 20)
    src = make_src(t, t.path("src_main"), f, links, hard, sparse, modes, owners, xattrs)
    exp = with_dirs(exp)
    for l, _ in links:
        exp[l] = b""                       # links extract as empty entries (target in the header)
    return src, exp, dict(links)

def mksq(t, src, name, opts):
    img = t.path(name)
    if os.path.exists(img):
        os.remove(img)
    t.sh(["mksquashfs", src, img, "-noappend", "-quiet", "-no-progress"] + list(opts), env=ENV)
    return img

# ---------------------------------------------------------------- SquashFS: reference images

# (tag, mksquashfs options, compare with 7-Zip); views are checked on VIEWS (shuffled reads are slow on big blocks);
# KEEP images are used again later, the others are deleted after their checks
VIEWS = {"gzip", "gzip_4k", "gzip_nofrag", "nocomp", "lzo_1x1_16k", "lz4hc_64k", "xz_bcj", "zstd_4k_l19", "lzma"}
KEEP = {"gzip", "gzip_4k", "xz", "xz_1m", "lzo_1x1_16k", "zstd"}
VARIANTS = [
    ("gzip", ["-comp", "gzip"], True),
    ("gzip_4k", ["-comp", "gzip", "-b", "4K"], True),
    ("gzip_1m_tail", ["-comp", "gzip", "-b", "1M", "-tailends"], True),
    ("gzip_nofrag", ["-comp", "gzip", "-no-fragments"], False),
    ("gzip_w8_l1", ["-comp", "gzip", "-Xwindow-size", "8", "-Xcompression-level", "1"], False),
    ("gzip_noIDFX", ["-comp", "gzip", "-noI", "-noD", "-noF", "-noX"], False),
    ("nocomp", ["-no-compression"], True),
    ("lzo", ["-comp", "lzo"], True),
    ("lzo_1x1_16k", ["-comp", "lzo", "-Xalgorithm", "lzo1x_1", "-b", "16K", "-tailends"], False),
    ("lz4", ["-comp", "lz4"], False),
    ("lz4hc_64k", ["-comp", "lz4", "-Xhc", "-b", "64K"], False),
    ("xz", ["-comp", "xz"], False),
    ("xz_bcj", ["-comp", "xz", "-Xbcj", "x86,arm,armthumb,powerpc,sparc,ia64"], True),
    ("xz_1m", ["-comp", "xz", "-b", "1M", "-Xdict-size", "50%", "-tailends"], True),
    ("zstd", ["-comp", "zstd"], False),
    ("zstd_4k_l19", ["-comp", "zstd", "-b", "4K", "-Xcompression-level", "19", "-tailends"], False),
    ("lzma", ["-comp", "lzma"], True),
    ("nodup_nosparse", ["-comp", "zstd", "-no-duplicates", "-no-sparse", "-no-hardlinks", "-no-xattrs"], False),
]

def squash_main(t, drv):
    src, exp, links = main_tree(t)
    meth = {"gzip": "Deflate", "lzo": "LZO", "lz4": "LZ4", "xz": "XZ", "zstd": "Zstd", "lzma": "LZMA"}
    imgs = {}
    for tag, opts, vs7z in VARIANTS:
        img = mksq(t, src, "sq_%s.sqfs" % tag, opts)
        imgs[tag] = img
        extract_check(t, img, exp, "squashfs %s" % tag, "SquashFS", vs7z)
        if tag in VIEWS:
            check_views(t, drv, img, "squashfs %s views" % tag)
        r, typ, rows = dump(drv, img)
        comp = opts[1] if opts[0] == "-comp" else None
        bad = []
        if comp and "-noD" not in opts and rows.get("big/text.txt", {}).get("idx") is not None:
            m = subprocess.run([t.gzt, "l", img], capture_output=True).stdout.decode()
            if ("\t%s\t" % meth[comp]) not in m:
                bad.append("method %s missing" % meth[comp])
        if tag in ("nocomp", "gzip_noIDFX"):
            m = subprocess.run([t.gzt, "l", img], capture_output=True).stdout.decode()
            if "\tStore\t" not in m or "\tDeflate\t" in m:
                bad.append("stored image shows a compressed method")
        t.record(not bad, "squashfs %s method" % tag, "; ".join(bad))
        if tag not in KEEP:
            os.remove(img)
    # portable kernels (scalar Adler-32, plain inflate) give the same result
    t.check_extract(imgs["gzip_4k"], exp, tier=0, label="squashfs gzip_4k tier 0")
    drop_out(t, imgs["gzip_4k"])
    # metadata (default gzip image)
    r, typ, rows = dump(drv, imgs["gzip"])
    bad = []
    def want(name, **kv):
        row = rows.get(unicodedata.normalize("NFC", name))
        if not row:
            bad.append("missing %s" % name)
            return
        for k, v in kv.items():
            if row[k] != v:
                bad.append("%s %s=%r want %r" % (name, k, row[k], v))
    want("readme.txt", mode=0o100644, mtime=ft_of(WHEN), mk=1, usize=5000, is_dir=0)
    want("ro.txt", mode=0o100444, attr=1)
    want("suid.bin", mode=0o104755)
    want("exe/prog.bin", mode=0o100755)
    want("private", mode=0o40700, is_dir=1, attr=0x10)
    want("owned.txt", aux=1234 | 5678 << 32)
    want("고기", is_dir=1, mtime=ft_of(WHEN))
    want("sparse/holes.bin", usize=3 << 20)
    want("hard/big_hl.bin", usize=2500000)
    for l, tgt in links.items():
        want(l, is_link=1, link=tgt, mode=0o120777, usize=0)
    for n in rows:
        if n.startswith("special"):
            bad.append("special file listed: " + n)
    if typ != "SquashFS":
        bad.append("type %s" % typ)
    t.record(not bad, "squashfs metadata", "; ".join(bad[:6]))
    # unsquashfs agrees on the names (files, dirs, links)
    out = subprocess.run(["unsquashfs", "-l", "-d", "", imgs["xz"]], capture_output=True, env=ENV).stdout.decode()
    names = {unicodedata.normalize("NFC", l.lstrip("/")) for l in out.splitlines() if l.strip("/")}
    ours = {unicodedata.normalize("NFC", n) for n in rows}
    t.record(names == ours, "squashfs names vs unsquashfs -l", str(sorted(names ^ ours)[:5]))
    # unsquashfs extraction vs ours for a compressor 7-Zip cannot read
    ref = t.path("unsq_zstd")
    shutil.rmtree(ref, ignore_errors=True)
    t.sh(["unsquashfs", "-q", "-n", "-d", ref, imgs["zstd"]], env=ENV)
    t.check_extract(imgs["zstd"], t.read_tree(ref), label="squashfs zstd vs unsquashfs", allow_extra=True)
    drop_out(t, imgs["zstd"])
    shutil.rmtree(ref, ignore_errors=True)
    # explicit view ranges across block / fragment / sparse boundaries
    data = exp["sparse/holes.bin"]
    rng = [(0, 10), ((1 << 20) - 5, 100), ((1 << 20) + 99990, 20), ((3 << 20) - 12, 12), (131072 - 3, 7)]
    for tag in ("gzip_4k", "xz_1m", "lzo_1x1_16k"):
        args = [drv, "r", imgs[tag], "sparse/holes.bin"]
        for o, n in rng:
            args += [str(o), str(n)]
        out = subprocess.run(args, capture_output=True, timeout=60).stdout.decode().split("\n")
        got = [l.split("\t") for l in out[1:] if l]
        want_r = [["0", "%08x" % zlib.crc32(data[o:o + n])] for o, n in rng]
        t.record(got == want_r, "squashfs %s view ranges" % tag, str(got[:3]))
    # nested zip read through the view (no temp file)
    inner = {"a.txt": blob(30000, 31, "text"), "b/c.bin": blob(9000, 32)}
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in inner.items():
            z.writestr(k, v)
    nsrc = make_src(t, t.path("src_nested"), {"inner/stuff.zip": bio.getvalue(), "pad.bin": blob(300000, 33)})
    for tag, opts in (("gzip", ["-comp", "gzip", "-b", "4K"]), ("stored", ["-noD", "-noF", "-no-fragments"])):
        img = mksq(t, nsrc, "sq_nested_%s.sqfs" % tag, opts)
        r = subprocess.run([drv, "n", img, "inner/stuff.zip"], capture_output=True, timeout=120)
        out = r.stdout.decode("utf-8", "replace").splitlines()
        got = {}
        for line in out[1:]:
            p = line.split("\t")
            if len(p) == 5:
                got[p[4]] = (int(p[1]), int(p[2]), p[3])
        wantn = {k: (0, len(v), "%08x" % zlib.crc32(v)) for k, v in inner.items()}
        ok = r.returncode == 0 and out and out[0].startswith("TYPE\tZIP") and got == wantn
        t.record(ok, "squashfs nested zip (%s)" % tag, "" if ok else str(out[:3]))
    return src, exp, imgs

def squash_special(t, drv):
    files = {"special/keep.txt": b"keep\n", "a.txt": b"a\n"}
    src = make_src(t, t.path("src_special"), files, special=True)
    img = mksq(t, src, "sq_special.sqfs", ["-comp", "gzip"])
    t.check_extract(img, with_dirs(files), label="squashfs special files skipped")
    img2 = mksq(t, src, "sq_special_pseudo.sqfs",
                ["-comp", "xz", "-p", "pdev c 600 0 0 4 64", "-p", "pfifo i 644 0 0 f",
                 "-p", "psock I 0 644 0 0 s", "-p", "plink s 777 0 0 a.txt", "-p", "abs s 777 0 0 /etc/passwd"])
    r, typ, rows = dump(drv, img2)
    ok = set(rows) == {"special", "special/keep.txt", "a.txt", "plink", "abs"} and rows["plink"]["link"] == "a.txt" \
        and rows["abs"]["link"] == "/etc/passwd"
    t.record(ok, "squashfs pseudo devices skipped", str(sorted(rows)))

def empty_images(t, have_sq, have_cr):
    src = make_src(t, t.path("src_empty"), {})
    imgs = []
    if have_sq:
        imgs.append(("SquashFS", mksq(t, src, "sq_empty.sqfs", [])))
    if have_cr:
        imgs.append(("CramFS", mkcram(t, src, "cr_empty.cramfs", [])))
    for typ, img in imgs:
        r = subprocess.run([t.gzt, "l", img], capture_output=True)
        t.record(r.stdout.decode().startswith("TYPE\t%s\t0\t" % typ), "%s empty image" % typ, r.stdout.decode()[:80])

def squash_huge(t, drv):
    """ext file inode > 4 GiB, mostly sparse (the image is cached in the work directory)"""
    size = (5 << 30) + 1234
    chunks = [(0, b"head" * 1000), ((4 << 30) - 100, b"X" * 300), (5 << 30, b"T" * 1234)]
    img = t.path("sq_huge.sqfs")
    if not os.path.exists(img):
        src = make_src(t, t.path("src_huge"), {}, sparse=[("huge.bin", size, chunks)])
        mksq(t, src, "sq_huge.sqfs.tmp", ["-comp", "zstd"])
        os.replace(img + ".tmp", img)
        shutil.rmtree(src, ignore_errors=True)
    r = subprocess.run([drv, "x", img, "huge.bin"], capture_output=True, timeout=600)
    p = r.stdout.decode().strip().split("\t")
    t.record(len(p) == 3 and p[0] == "0" and int(p[1]) == size, "squashfs > 4 GiB file extract", str(p))
    def piece(o, n):
        out = bytearray(n)
        for co, cd in chunks:
            a, b = max(o, co), min(o + n, co + len(cd))
            if a < b:
                out[a - o:b - o] = cd[a - co:b - co]
        return bytes(out)
    rng = [(0, 5000), ((4 << 30) - 200, 1000), ((5 << 30) - 10, 1244), ((1 << 32) + 7, 33)]
    args = [drv, "r", img, "huge.bin"]
    for o, n in rng:
        args += [str(o), str(n)]
    out = subprocess.run(args, capture_output=True, timeout=120).stdout.decode().split("\n")
    got = [l.split("\t") for l in out[1:] if l]
    t.record(out[0] == "SIZE\t%d" % size and got == [["0", "%08x" % zlib.crc32(piece(o, n))] for o, n in rng],
             "squashfs > 4 GiB view ranges", str(out[:3]))

def squash_threads(t, sdrv, imgs):
    for tag in ("gzip_4k", "xz"):
        r = subprocess.run([sdrv, "mt", imgs[tag], "6", "1"], capture_output=True, timeout=600)
        out = r.stdout.decode()
        t.record(r.returncode == 0 and out.startswith("OK"), "squashfs %s 6 threads" % tag, out[-300:])
    # per-thread caches across archives: same layout, different fragment contents
    imgs2 = []
    for k in range(3):
        files = {"f%02d.txt" % i: bytes([65 + (i + k) % 26]) * (100 + i) for i in range(40)}
        files["blk.bin"] = blob(70000, 40 + k)
        src = make_src(t, t.path("src_seq%d" % k), files)
        img = mksq(t, src, "sq_seq%d.sqfs" % k, ["-no-compression", "-b", "64K"])
        imgs2.append((img, files))
    r = subprocess.run([sdrv, "seq"] + [i for i, _ in imgs2], capture_output=True, timeout=120)
    bad, n = [], 0
    for line in r.stdout.decode().splitlines():
        p = line.split("\t")
        if len(p) != 6:
            continue
        n += 1
        k, st, crc, name = int(p[1]), int(p[3]), p[4], p[5]
        if st or crc != "%08x" % zlib.crc32(imgs2[k][1][name]):
            bad.append("pass %s img %d %s" % (p[0], k, name))
    t.record(not bad and n == 2 * sum(len(f) for _, f in imgs2), "squashfs caches across archives",
             "; ".join(bad[:4]) or "%d checks" % n)

def squash_sqfstar(t):
    """images written by sqfstar (tar input)"""
    if not t.tool("sqfstar"):
        return
    files = {"t/a.txt": blob(20000, 51, "text"), "t/b.bin": blob(150000, 52), "t/한글.txt": "한글\n".encode()}
    src = make_src(t, t.path("src_tar"), files)
    tarp = t.path("in.tar")
    t.sh(["tar", "-C", src, "-cf", tarp, "t"], env=ENV)
    img = t.path("sq_sqfstar.sqfs")
    if os.path.exists(img):
        os.remove(img)
    with open(tarp, "rb") as f:
        r = subprocess.run(["sqfstar", "-quiet", "-comp", "xz", img], stdin=f, capture_output=True, env=ENV)
    if r.returncode:
        return t.record(False, "sqfstar image", r.stderr.decode()[-300:])
    t.check_extract(img, with_dirs(files), label="squashfs from sqfstar")

def squash_perf(t, sdrv):
    files = {"perf/text.bin": blob(48 << 20, 61, "mixed")}
    src = make_src(t, t.path("src_perf"), files)
    res = []
    for comp, opts in (("gzip", []), ("xz", []), ("zstd", []), ("lz4", []), ("lzo", []), ("lzma", [])):
        img = mksq(t, src, "sq_perf_%s.sqfs" % comp, ["-comp", comp] + opts)
        r = subprocess.run([sdrv, "bench", img, "perf/text.bin", "2"], capture_output=True, timeout=600)
        p = r.stdout.decode().split("\t")
        ok = r.returncode == 0 and len(p) == 5 and p[3] == "%08x" % zlib.crc32(files["perf/text.bin"])
        t0 = time.time()
        subprocess.run(["unsquashfs", "-q", "-n", "-p", "1", "-d", t.path("perf_ref"), "-f", img],
                       capture_output=True, env=ENV)
        ref = time.time() - t0
        res.append("%s %s MB/s (unsquashfs -p1 %.0f MB/s)" % (comp, p[2] if len(p) > 2 else "?", (48 << 20) / ref / 1e6))
        t.record(ok, "squashfs bench %s" % comp, res[-1])
        os.remove(img)
    shutil.rmtree(t.path("perf_ref"), ignore_errors=True)
    shutil.rmtree(src, ignore_errors=True)

# ---------------------------------------------------------------- SquashFS: hostile images

class Sq:
    """minimal SquashFS 4.0 parser for uncompressed (-no-compression) images: locate structures"""
    def __init__(self, path):
        self.path = path
        self.d = bytearray(open(path, "rb").read())
        f = struct.unpack_from("<IIIIIHHHHHHQQQQQQQQ", self.d)
        (self.magic, self.inodes, _, self.bs, self.nfrag, self.comp, self.blog, self.flags, self.nids,
         _, _, self.root, self.used, self.idt, self.xat, self.itab, self.dtab, self.ftab, self.ltab) = f
        self.it = self.table(self.itab, self.dtab)
        self.dt = self.table(self.dtab, self.ftab if self.nfrag else self.ltab)
    def table(self, start, end):
        blocks, off, dec = [], start, 0
        while off < end and off + 2 <= len(self.d):
            h = struct.unpack_from("<H", self.d, off)[0]
            n = h & 0x7FFF
            if not (h & 0x8000) or not n:
                break
            blocks.append((off - start, dec, off + 2, n))
            dec += n
            off += 2 + n
        return blocks
    def foff(self, tab, blk, off):
        for rel, dec, data, n in tab:
            if rel == blk:
                return data + off
        raise KeyError(blk)
    def entries(self, ino_blk, ino_off):
        """[(name, dirent file offset, header file offset, inode file offset)] of a directory inode"""
        io_ = self.foff(self.it, ino_blk, ino_off)
        typ = struct.unpack_from("<H", self.d, io_)[0]
        if typ == 1:
            sb, _, fsz, off = struct.unpack_from("<IIHH", self.d, io_ + 16)
        else:
            _, fsz, sb, _, _, off = struct.unpack_from("<IIIIHH", self.d, io_ + 16)
        p, end, out = self.foff(self.dt, sb, off), None, []
        end = p + fsz - 3
        while p + 12 <= end:
            cnt, sblk, _ = struct.unpack_from("<III", self.d, p)
            hdr = p
            p += 12
            for _ in range(cnt + 1):
                eo, _, et, sz = struct.unpack_from("<HhHH", self.d, p)
                name = bytes(self.d[p + 8:p + 9 + sz]).decode()
                out.append((name, p, hdr, self.foff(self.it, sblk, eo), sblk, eo))
                p += 9 + sz
        return out
    def find(self, path):
        blk, off = self.root >> 16, self.root & 0xFFFF
        ent = None
        for comp in path.split("/"):
            ent = [e for e in self.entries(blk, off) if e[0] == comp][0]
            blk, off = ent[4], ent[5]
        return dict(dirent=ent[1], hdr=ent[2], inode=ent[3], blk=ent[4], off=ent[5])
    def save(self, path):
        with open(path, "wb") as f:
            f.write(self.d)
        return path

def squash_hostile(t, drv, sdrv):
    files = {"a.txt": b"alpha\n" * 10, "dir/b.bin": blob(300000, 71), "dir/sub/c.txt": b"c\n",
             "frag1.txt": b"fragment one\n", "frag2.txt": b"fragment two\n"}
    src = make_src(t, t.path("src_host"), files, links=[("dir/lnk", "../a.txt")])
    base = mksq(t, src, "h_base.sqfs", ["-no-compression", "-b", "64K"])
    exp_base = with_dirs(files)
    t.check_extract(base, dict(exp_base, **{"dir/lnk": b""}), label="squashfs hostile base image")
    cases = []
    def case(name, fn, check=None):
        s = Sq(base)
        try:
            fn(s)
        except Exception as e:
            return t.record(False, "squashfs hostile %s (setup)" % name, repr(e))
        img = s.save(t.path("h_%s.sqfs" % name))
        hostile(t, drv, img, "squashfs hostile %s" % name)
        if check:
            check(img)
    def put(fmt, off, *v):
        return lambda s: struct.pack_into(fmt, s.d, off(s) if callable(off) else off, *v)
    def listing(img):
        return dump(drv, img)[2]
    # directory loops: dir/sub -> dir, dir -> root
    def loop1(s):
        d, sub = s.find("dir"), s.find("dir/sub")
        hb = struct.unpack_from("<I", s.d, sub["hdr"] + 4)[0]
        if hb != d["blk"]:
            raise RuntimeError("blocks differ")
        struct.pack_into("<H", s.d, sub["dirent"], d["off"])
    case("loop_parent", loop1,
         lambda img: t.record(set(listing(img)) >= {"dir", "dir/sub", "a.txt"} and len(listing(img)) < 20,
                              "squashfs loop listing finite", str(sorted(listing(img)))))
    def loop2(s):
        d = s.find("dir")
        struct.pack_into("<H", s.d, d["dirent"], s.root & 0xFFFF)
        struct.pack_into("<I", s.d, d["hdr"] + 4, s.root >> 16)
    case("loop_root", loop2)
    case("dir_count_huge", lambda s: struct.pack_into("<I", s.d, s.find("dir")["hdr"], 0xFFFFFFFF))
    case("name_len_huge", lambda s: struct.pack_into("<H", s.d, s.find("dir/b.bin")["dirent"] + 6, 0xFFFF))
    case("dirent_off_huge", lambda s: struct.pack_into("<H", s.d, s.find("a.txt")["dirent"], 0xFFF0))
    case("inode_type_bad", lambda s: struct.pack_into("<H", s.d, s.find("a.txt")["inode"], 99))
    case("inode_type_dir", lambda s: struct.pack_into("<H", s.d, s.find("dir/b.bin")["inode"], 1))
    case("file_size_huge", lambda s: struct.pack_into("<I", s.d, s.find("dir/b.bin")["inode"] + 28, 0xFFFFFFFF))
    case("block_word_huge", lambda s: struct.pack_into("<I", s.d, s.find("dir/b.bin")["inode"] + 32, 0x00FFFFFF))
    case("block_word_short", lambda s: struct.pack_into("<I", s.d, s.find("dir/b.bin")["inode"] + 32, 0x01000010))
    case("block_word_comp", lambda s: struct.pack_into("<I", s.d, s.find("dir/b.bin")["inode"] + 32, 0x00001000))
    case("data_start_eof", lambda s: struct.pack_into("<I", s.d, s.find("dir/b.bin")["inode"] + 16, 0xFFFFFF00))
    case("frag_index_huge", lambda s: struct.pack_into("<I", s.d, s.find("frag1.txt")["inode"] + 20, 0x7FFFFFFF))
    case("frag_offset_huge", lambda s: struct.pack_into("<I", s.d, s.find("frag2.txt")["inode"] + 24, 0xFFFFFFF0))
    case("frag_entry_size", lambda s: struct.pack_into("<I", s.d, struct.unpack_from("<Q", s.d, s.ftab)[0] + 2 + 8,
                                                       0x00FFFFFF))
    case("frag_index_ptr", lambda s: struct.pack_into("<Q", s.d, s.ftab, 0xFFFFFFFFFF))
    case("link_size_huge", lambda s: struct.pack_into("<I", s.d, s.find("dir/lnk")["inode"] + 20, 0xFFFFFFFF))
    case("dir_size_huge", lambda s: struct.pack_into("<H", s.d, s.find("dir")["inode"] + 24, 0xFFFF))
    case("dir_start_bad", lambda s: struct.pack_into("<I", s.d, s.find("dir")["inode"] + 16, 0x123))
    case("root_ref_bad", lambda s: struct.pack_into("<Q", s.d, 32, 0x7FFFFFFF0000))
    case("root_is_file", lambda s: struct.pack_into("<Q", s.d, 32, s.find("a.txt")["blk"] << 16 | s.find("a.txt")["off"]))
    case("nfrag_huge", lambda s: struct.pack_into("<I", s.d, 16, 0xFFFFFFFF))
    case("nids_huge", lambda s: struct.pack_into("<H", s.d, 26, 0xFFFF))
    case("id_tab_eof", lambda s: struct.pack_into("<Q", s.d, 48, 0xFFFFFFFFFFF0))
    case("tables_swapped", lambda s: struct.pack_into("<QQ", s.d, 64, s.dtab, s.itab))
    case("bytes_used_small", lambda s: struct.pack_into("<Q", s.d, 40, s.dtab + 1))
    case("block_log_bad", lambda s: struct.pack_into("<H", s.d, 22, 30))
    case("comp_unknown", lambda s: struct.pack_into("<H", s.d, 20, 9))
    case("meta_len0", lambda s: struct.pack_into("<H", s.d, s.itab, 0x8000))
    case("meta_len_huge", lambda s: struct.pack_into("<H", s.d, s.dtab, 0xFFFF))
    case("meta_compressed_garbage", lambda s: struct.pack_into("<H", s.d, s.dtab, 0x0100))
    case("version1", lambda s: struct.pack_into("<H", s.d, 28, 1),
         lambda img: t.record(b"OPEN_ERROR 5" in subprocess.run([t.gzt, "l", img], capture_output=True).stdout,
                              "squashfs 1.x reported unsupported"))
    case("version3_on_v4", lambda s: struct.pack_into("<H", s.d, 28, 3))
    # truncations
    data = open(base, "rb").read()
    for cut in (96, 200, len(data) // 2, len(data) - 300, len(data) - 1):
        p = t.path("h_trunc_%d.sqfs" % cut)
        with open(p, "wb") as f:
            f.write(data[:cut])
        hostile(t, drv, p, "squashfs truncated at %d" % cut)
    # in-process fuzzing of every compressor (small images: many iterations)
    fz = {"a.txt": blob(3000, 81, "text"), "d/b.bin": blob(70000, 82, "mixed"), "d/e/c.txt": b"c\n" * 50,
          "x.bin": open(t.gzt, "rb").read()[200000:260000]}
    for i in range(30):
        fz["m/f%02d" % i] = ("f%d" % i).encode() * (i + 1)
    fsrc = make_src(t, t.path("src_fuzz"), fz, links=[("d/l", "../a.txt")], hard=[("hl.txt", "a.txt")])
    n = int(os.environ.get("GZ_SQFS_FUZZ", "400"))
    for tag, opts in (("gzip", ["-comp", "gzip", "-b", "16K"]), ("xz", ["-comp", "xz", "-Xbcj", "x86", "-b", "16K"]),
                      ("lzma", ["-comp", "lzma", "-b", "16K"]), ("lzo", ["-comp", "lzo", "-b", "16K"]),
                      ("lz4", ["-comp", "lz4", "-b", "16K"]), ("zstd", ["-comp", "zstd", "-b", "16K"]),
                      ("raw", ["-no-compression", "-b", "4K"])):
        img = mksq(t, fsrc, "fz_%s.sqfs" % tag, opts)
        r = subprocess.run([sdrv, "fuzz", img, str(n), str(len(tag) * 977)], capture_output=True, timeout=1200)
        err = r.stderr.decode(errors="replace")
        ok = r.returncode == 0 and "Sanitizer" not in err and "runtime error" not in err
        t.record(ok, "squashfs fuzz %s" % tag, (r.stdout.decode().strip() + " " + err[-300:]).strip())

# ---------------------------------------------------------------- SquashFS 3.x (crafted writer)

def sq3_bits(fields, nbytes, be):
    """bit fields [(position, width, value)] numbered like squashfs-tools' SQUASHFS_SWAP:
    from the least significant bit in little-endian images, from the most significant in big"""
    v = 0
    for pos, w, val in fields:
        val &= (1 << w) - 1
        v |= val << (nbytes * 8 - pos - w) if be else val << pos
    return v.to_bytes(nbytes, "big" if be else "little")

def sq3_codec(kind, bs):
    """block compressor: zlib, raw LZMA without properties (vendor), or 'mixed' (.lzma header
    with the real size / zlib, alternating; "shsq" magic)"""
    import lzma
    n = [0]
    def raw(d):
        return lzma.compress(d, format=lzma.FORMAT_RAW,
                             filters=[{"id": lzma.FILTER_LZMA1, "dict_size": bs, "lc": 3, "lp": 0, "pb": 2}])
    def alone(d):
        c = bytearray(lzma.compress(d, format=lzma.FORMAT_ALONE, filters=[{"id": lzma.FILTER_LZMA1, "dict_size": bs}]))
        c[5:13] = struct.pack("<Q", len(d))
        return bytes(c)
    def mixed(d):
        n[0] += 1
        return alone(d) if n[0] % 2 else zlib.compress(d, 9)
    return {"zlib": lambda d: zlib.compress(d, 9), "lzma_raw": raw, "mixed": mixed, "none": lambda d: d}[kind]

class Sq3Meta:
    def __init__(self, be, cf, check):
        self.be, self.cf, self.check = be, cf, check
        self.buf, self.out, self.starts = bytearray(), bytearray(), []
    def pos(self):
        return len(self.starts) * 8192 + len(self.buf)
    def flush(self, final):
        while len(self.buf) >= 8192 or (final and self.buf):
            blk, self.buf = bytes(self.buf[:8192]), self.buf[8192:]
            self.starts.append(len(self.out))
            c = self.cf(blk)
            c, h = (blk, len(blk) | 0x8000) if len(c) >= len(blk) else (c, len(c))
            self.out += struct.pack(">H" if self.be else "<H", h) + (b"\xff" if self.check else b"") + c
    def add(self, data):
        p = self.pos()
        self.buf += data
        self.flush(False)
        return p
    def ref(self, p):
        k = p // 8192
        return (self.starts[k] if k < len(self.starts) else len(self.out)), p % 8192

def sq3_write(tree, be=False, bs=4096, comp="zlib", check=False, ext=False, uid=0, gid=0, mtime=1600000000):
    """SquashFS 3.1 image. tree: {name: bytes (file) | "->target" (symlink) | dict (directory)}"""
    E = ">" if be else "<"
    cf = sq3_codec(comp, bs)
    img = bytearray(119)
    frags, fragbuf = [], bytearray()
    it, dt = Sq3Meta(be, cf, check), Sq3Meta(be, cf, check)
    counter = [1]
    def store(data):
        c = cf(data)
        if len(c) >= len(data):
            img.extend(data)
            return len(data) | (1 << 24)
        img.extend(c)
        return len(c)
    def flush_frag():
        if fragbuf:
            st = len(img)
            frags.append((st, store(bytes(fragbuf))))
            fragbuf.clear()
    def base(t, ino, mode):
        return [(0, 4, t), (4, 12, mode), (16, 8, 1 if uid else 0), (24, 8, 1 if gid else 255),
                (32, 32, mtime), (64, 32, ino)]
    def write_file(data, ino, large):
        start, blocks = len(img), []
        nfull = len(data) // bs
        tail = data[nfull * bs:]
        use_frag = 0 < len(tail) < bs and len(data) % 5 != 1      # some tails as short blocks
        nblk = nfull if use_frag else (len(data) + bs - 1) // bs
        for i in range(nblk):
            blocks.append(store(data[i * bs:(i + 1) * bs]))
        frag, foff = 0xFFFFFFFF, 0
        if use_frag:
            if len(fragbuf) + len(tail) > bs:
                flush_frag()
            frag, foff = len(frags), len(fragbuf)
            fragbuf.extend(tail)
        bl = b"".join(struct.pack(E + "I", b) for b in blocks)
        if large:
            hdr = sq3_bits(base(9, ino, 0o640) + [(96, 32, 1), (128, 64, start), (192, 32, frag), (224, 32, foff),
                                                    (256, 64, len(data))], 40, be)
        else:
            hdr = sq3_bits(base(2, ino, 0o644) + [(96, 64, start), (160, 32, frag), (192, 32, foff),
                                                    (224, 32, len(data))], 32, be)
        return it.add(hdr + bl), 2
    def write_dir(d, myino, parent):
        kids = []
        for name in sorted(d):
            v = d[name]
            ino = counter[0]
            counter[0] += 1
            if isinstance(v, dict):
                p, t = write_dir(v, ino, myino)
            elif isinstance(v, str):
                tgt = v[2:].encode()
                p, t = it.add(sq3_bits(base(3, ino, 0o777) + [(96, 32, 1), (128, 16, len(tgt))], 18, be) + tgt), 3
            else:
                p, t = write_file(v, ino, ext and len(v) % 3 == 0)
            kids.append((name.encode(), p, t, ino))
        listing, i = bytearray(), 0
        while i < len(kids):
            blk, grp = it.ref(kids[i][1])[0], []
            while i < len(kids) and len(grp) < 256 and it.ref(kids[i][1])[0] == blk:
                grp.append(kids[i])
                i += 1
            listing += sq3_bits([(0, 8, len(grp) - 1), (8, 32, blk), (40, 32, grp[0][3])], 9, be)
            for nm, p, t, ino in grp:
                listing += sq3_bits([(0, 13, it.ref(p)[1]), (13, 3, t), (16, 8, len(nm) - 1),
                                     (24, 16, ino - grp[0][3])], 5, be) + nm
        dblk, doff = dt.ref(dt.add(bytes(listing)))
        if ext:
            hdr = sq3_bits(base(8, myino, 0o755) + [(96, 32, 2), (128, 27, len(listing) + 3), (155, 13, doff),
                                                      (168, 32, dblk), (200, 16, 0), (216, 32, parent)], 31, be)
        else:
            hdr = sq3_bits(base(1, myino, 0o755) + [(96, 32, 2), (128, 19, len(listing) + 3), (147, 13, doff),
                                                      (160, 32, dblk), (192, 32, parent)], 28, be)
        return it.add(hdr), 1
    root_ino = counter[0]
    counter[0] += 1
    rootp, _ = write_dir(tree, root_ino, 0)
    flush_frag()
    it.flush(True)
    dt.flush(True)
    rblk, roff = it.ref(rootp)
    itab = len(img)
    img += it.out
    dtab = len(img)
    img += dt.out
    fm = Sq3Meta(be, cf, check)
    for st, sz in frags:
        fm.add(struct.pack(E + "QII", st, sz, 0))
    fm.flush(True)
    fstart = len(img)
    img += fm.out
    ftab = len(img)
    for s0 in fm.starts:
        img += struct.pack(E + "Q", fstart + s0)
    uids, gids = [0] + ([uid] if uid else []), [0] + ([gid] if gid else [])
    ustart = len(img)
    img += b"".join(struct.pack(E + "I", u) for u in uids)
    gstart = len(img)
    img += b"".join(struct.pack(E + "I", g) for g in gids)
    used = len(img)
    magic = 0x71736873 if comp == "mixed" else 0x73717368
    flags = (0 if comp != "none" else 3) | (4 if check else 0)
    sb = struct.pack(E + "IIIIIIIHHHH", magic, counter[0] - 1, used, ustart, gstart, itab, dtab, 3, 1,
                     bs if bs < 65536 else 0, bs.bit_length() - 1)
    sb += struct.pack(E + "BBBIQIII", flags, len(uids), len(gids), mtime, rblk << 16 | roff, bs, len(frags), ftab)
    sb += struct.pack(E + "QQQQQQQ", used, ustart, gstart, itab, dtab, ftab, 0xFFFFFFFFFFFFFFFF)
    img[:119] = sb
    img += bytes((-len(img)) % 4096)
    return bytes(img)

def sq3_tree():
    rnd = random.Random(33)
    tree = {"a.txt": blob(5000, 401, "text"), "big.bin": rnd.randbytes(20000) + blob(30000, 402, "text"),
            "empty": b"", "small": b"x", "lnk": "->a.txt", "고기.txt": "고기\n".encode() * 100,
            "sub": {"c.txt": blob(9000, 403, "text"), "d.bin": blob(12288, 404, "mixed"), "deep": {"e": b"eee\n"},
                    "up": "->../a.txt"},
            "many": {"f%03d" % i: blob(i * 7 + 1, 405 + i, "text") for i in range(300)}}
    def flat(tr, pre=""):
        out = {}
        for k, v in tr.items():
            if isinstance(v, dict):
                out[pre + k] = None
                out.update(flat(v, pre + k + "/"))
            else:
                out[pre + k] = v if isinstance(v, bytes) else b""
        return out
    return tree, flat(tree)

def squash_v3(t, drv, sdrv):
    tree, exp = sq3_tree()
    files = {k: v for k, v in exp.items() if v is not None and k not in ("lnk", "sub/up")}
    variants = [("le", {}), ("be", {"be": True}), ("le_ext_check", {"ext": True, "check": True}),
                ("be_raw_16k", {"be": True, "comp": "none", "bs": 16384}),
                ("be_ext_owner", {"be": True, "ext": True, "uid": 1000, "gid": 50}),
                ("le_lzma_raw", {"comp": "lzma_raw"}), ("be_lzma_raw_ext", {"be": True, "comp": "lzma_raw", "ext": True}),
                ("le_mixed", {"comp": "mixed", "bs": 8192}), ("be_mixed_check", {"be": True, "comp": "mixed", "check": True})]
    imgs = {}
    for tag, kw in variants:
        p = t.path("sq3_%s.sqfs" % tag)
        open(p, "wb").write(sq3_write(tree, **kw))
        imgs[tag] = p
        # the writer is validated by 7-Zip, then we must agree with the source
        r7, out7 = t.sevenzip_extract(p, extra=["-snld"])
        got7 = t.read_tree(out7) if not r7.returncode else None
        shutil.rmtree(out7, ignore_errors=True)
        t.record(got7 == files, "squashfs 3.x %s: 7-Zip reads the crafted image" % tag,
                 "" if got7 == files else "rc=%d %d/%d files" % (r7.returncode, len(got7 or {}), len(files)))
        extract_check(t, p, exp, "squashfs 3.x %s" % tag, "SquashFS")
        check_views(t, drv, p, "squashfs 3.x %s views" % tag)
    r, typ, rows = dump(drv, imgs["be_ext_owner"])
    bad = []
    a = rows.get("a.txt", {})
    if a.get("mode") != 0o100644 or a.get("mtime") != ft_of(1600000000) or a.get("aux") != 1000 | 50 << 32:
        bad.append("a.txt %r" % a)
    d = rows.get("sub/d.bin", {})
    if d.get("mode") != 0o100640 or d.get("flags") != 9:          # extended file inode
        bad.append("sub/d.bin %r" % d)
    if rows.get("sub", {}).get("flags") != 8:                      # extended directory inode
        bad.append("sub flags %r" % rows.get("sub"))
    if rows.get("lnk", {}).get("link") != "a.txt" or rows.get("sub/up", {}).get("link") != "../a.txt":
        bad.append("links")
    if rows.get("sub", {}).get("mode") != 0o40755:
        bad.append("sub %r" % rows.get("sub"))
    t.record(not bad, "squashfs 3.x metadata (big endian, extended inodes)", "; ".join(bad))
    r, typ, rows = dump(drv, imgs["le"])
    t.record(rows.get("a.txt", {}).get("aux") == 0, "squashfs 3.x gid 255 = uid")
    r = subprocess.run([sdrv, "mt", imgs["be_lzma_raw_ext"], "4", "1"], capture_output=True, timeout=300)
    t.record(r.returncode == 0 and r.stdout.startswith(b"OK"), "squashfs 3.x 4 threads", r.stdout.decode()[-200:])
    n = int(os.environ.get("GZ_SQFS_FUZZ", "400"))
    small = {"a.txt": blob(3000, 411, "text"), "d": {"b.bin": blob(30000, 412, "mixed"), "c": b"c\n" * 40},
             "l": "->a.txt", "m": {"f%02d" % i: b"f" * (i + 1) for i in range(20)}}
    for tag, kw in (("le", {}), ("be_ext", {"be": True, "ext": True, "check": True}),
                    ("lzma_raw", {"comp": "lzma_raw"}), ("mixed_be", {"comp": "mixed", "be": True})):
        p = t.path("fz3_%s.sqfs" % tag)
        open(p, "wb").write(sq3_write(small, **kw))
        r = subprocess.run([sdrv, "fuzz", p, str(n), str(len(tag) * 7)], capture_output=True, timeout=1200)
        err = r.stderr.decode(errors="replace")
        ok = r.returncode == 0 and "Sanitizer" not in err and "runtime error" not in err
        t.record(ok, "squashfs 3.x fuzz %s" % tag, (r.stdout.decode().strip() + " " + err[-300:]).strip())
    # 1.x / 2.x: recognised, reported as unsupported
    d = bytearray(open(imgs["le"], "rb").read())
    struct.pack_into("<H", d, 28, 2)
    p = t.path("sq2.sqfs")
    open(p, "wb").write(d)
    r = subprocess.run([t.gzt, "l", p], capture_output=True)
    t.record(b"OPEN_ERROR 5" in r.stdout, "squashfs 2.x reported unsupported", r.stdout.decode()[:60])

# ---------------------------------------------------------------- CramFS

def cram_tree(t):
    f = {
        "readme.txt": blob(5000, 101, "text"),
        "empty.txt": b"",
        "고기/삼겹살.txt": "삼겹살\n".encode() * 500,
        "고기/" + NFD_NAME: b"nfd\n",
        "bin/data.bin": blob(70000, 103),
        "bin/mixed.bin": blob(2000000, 104, "mixed"),
        "dup1.bin": blob(9000, 105),
        "dup2.bin": blob(9000, 105),
        "deep/" + "/".join("d%d" % i for i in range(20)) + "/leaf.txt": b"deep\n",
        "emptydir": None,
    }
    for n in (1023, 1024, 1025, 4095, 4096, 4097, 65535, 65536, 65537):
        f["sizes/s%d.bin" % n] = blob(n, n, "mixed")
    for i in range(150):
        f["many/f%03d.txt" % i] = ("cram %d\n" % i).encode() * (1 + i % 9)
    sp_chunks = [(40000, blob(9000, 106)), ((1 << 20) - 3, b"end")]
    links = [("lnk", "readme.txt"), ("고기/up", "../readme.txt"), ("longlnk", "y" * 250)]
    modes = {"bin/data.bin": 0o755, "readme.txt": 0o444}
    owners = {"bin/data.bin": (321, 77)}
    src = make_src(t, t.path("src_cram"), f, links, sparse=[("sparse.bin", 1 << 20, sp_chunks)], modes=modes,
                   owners=owners)
    sp = bytearray(1 << 20)
    for off, data in sp_chunks:
        sp[off:off + len(data)] = data
    exp = with_dirs(dict(f, **{"sparse.bin": bytes(sp)}))
    for l, _ in links:
        exp[l] = b""
    return src, exp, dict(links)

def mkcram(t, src, name, opts):
    img = t.path(name)
    if os.path.exists(img):
        os.remove(img)
    t.sh(["mkfs.cramfs"] + list(opts) + [src, img], env=ENV)
    return img

def cram_main(t, drv, sdrv):
    src, exp, links = cram_tree(t)
    imgs = {}
    for tag, opts, vs7z in (("le", [], True), ("be", ["-N", "big"], True), ("holes", ["-z"], False),
                            ("pad", ["-p"], False), ("b8k", ["-b", "8192"], False), ("b16k", ["-b", "16384"], False),
                            ("b64k_be", ["-b", "65536", "-N", "big"], False), ("b1k", ["-b", "1024"], False),
                            ("named", ["-n", "GOGI", "-e", "7"], True)):
        img = mkcram(t, src, "cr_%s.cramfs" % tag, opts)
        imgs[tag] = img
        extract_check(t, img, exp, "cramfs %s" % tag, "CramFS", vs7z)
        check_views(t, drv, img, "cramfs %s views" % tag)
    t.check_extract(imgs["be"], exp, tier=0, label="cramfs be tier 0")
    drop_out(t, imgs["be"])
    r, typ, rows = dump(drv, imgs["be"])
    bad = []
    for l, tgt in links.items():
        row = rows.get(l)
        if not row or row["link"] != tgt or not row["is_link"]:
            bad.append("link %s" % l)
    if rows.get("bin/data.bin", {}).get("mode") != 0o100755 or rows["bin/data.bin"]["aux"] != 321 | 77 << 32:
        bad.append("data.bin mode/owner %r" % rows.get("bin/data.bin"))
    if rows.get("readme.txt", {}).get("attr") != 1 or rows["readme.txt"]["mk"] != 0:
        bad.append("readme.txt attr/time %r" % rows.get("readme.txt"))
    t.record(not bad and typ == "CramFS", "cramfs metadata", "; ".join(bad))
    # special files
    sfiles = {"special/keep.txt": b"keep\n"}
    ssrc = make_src(t, t.path("src_cram_special"), sfiles, special=True)
    img = mkcram(t, ssrc, "cr_special.cramfs", [])
    t.check_extract(img, with_dirs(sfiles), label="cramfs special files skipped")
    # image CRC: a damaged byte outside any file is reported per file
    d = bytearray(open(imgs["le"], "rb").read())
    d[48] ^= 0x55                                         # volume name
    p = t.path("cr_badcrc.cramfs")
    open(p, "wb").write(d)
    r, rows2, out = t.extract(p)
    sts = {v[0] for k, v in rows2.items() if not v[1] and v[2]}
    t.record(sts == {4}, "cramfs image CRC mismatch reported", str(sts))
    r = subprocess.run([sdrv, "mt", imgs["b8k"], "6", "2"], capture_output=True, timeout=300)
    t.record(r.returncode == 0 and r.stdout.startswith(b"OK"), "cramfs 6 threads", r.stdout.decode()[-200:])
    return imgs

# crafted images: extended block pointers (direct / uncompressed), big endian, v1

def cram_write(entries, be=False, bs=4096, ext=True, v2=True, pad=False):
    """entries: [(name, mode, data_or_target, kinds)] in the root directory; kinds per block:
    'z' compressed, 'h' hole, 'u' uncompressed, 'dz' direct compressed, 'du' direct uncompressed"""
    E = ">" if be else "<"
    base = 512 if pad else 0
    def inode(mode, uid, size, gid, namelen4, off4):
        if be:
            return struct.pack(">III", mode << 16 | uid, size << 8 | gid, namelen4 << 26 | off4)
        return struct.pack("<III", mode | uid << 16, size | gid << 24, namelen4 | off4 << 6)
    names = [n.encode() for n, *_ in entries]
    dirsize = sum(12 + (len(n) + 3) // 4 * 4 for n in names)
    pos = base + 76 + dirsize
    img = bytearray(pos)
    offs = []
    for (name, mode, data, kinds), nb in zip(entries, names):
        if not data:
            offs.append(0)
            continue
        pos = (pos + 3) & ~3
        start = pos
        nblk = (len(data) + bs - 1) // bs
        img += bytes(pos + 4 * nblk - len(img))
        pos += 4 * nblk
        ptrs = []
        for i in range(nblk):
            chunk = data[i * bs:(i + 1) * bs]
            k = kinds[i % len(kinds)] if kinds else "z"
            if k == "h" and any(chunk):
                k = "z"
            if k in ("dz", "du"):
                pos = (pos + 3) & ~3
                img += bytes(pos - len(img))
                if k == "dz":
                    c = zlib.compress(chunk, 9)
                    img += struct.pack(E + "H", len(c)) + c
                    ptrs.append(0x40000000 | (pos >> 2))
                    pos += 2 + len(c)
                else:
                    img += chunk if i + 1 < nblk else chunk
                    ptrs.append(0xC0000000 | (pos >> 2))
                    pos += len(chunk) if i + 1 == nblk else bs
                    img += bytes(pos - len(img))
            elif k == "h":
                ptrs.append(pos)
            elif k == "u":
                img += chunk
                pos += len(chunk)
                ptrs.append(0x80000000 | pos)
            else:
                c = zlib.compress(chunk, 9)
                img += c
                pos += len(c)
                ptrs.append(pos)
        struct.pack_into(E + "%dI" % nblk, img, start, *ptrs)
        offs.append(start)
    pos = (pos + 3) & ~3
    img += bytes(pos - len(img))
    d = base + 76
    for (name, mode, data, kinds), nb, off in zip(entries, names, offs):
        nl = (len(nb) + 3) // 4
        img[d:d + 12] = inode(mode, 0, len(data), 0, nl, off >> 2)
        img[d + 12:d + 12 + nl * 4] = nb + bytes(nl * 4 - len(nb))
        d += 12 + nl * 4
    flags = (1 if v2 else 0) | 2 | (0x800 if ext else 0)
    total = len(img)
    sb = struct.pack(E + "IIII", 0x28CD3D45, total, flags, 0) + b"Compressed ROMFS" + \
        struct.pack(E + "IIII", 0, 0, 0, len(entries) + 1) + b"crafted".ljust(16, b"\0") + \
        inode(0o40755, 0, dirsize, 0, 0, (base + 76) >> 2)
    img[base:base + 76] = sb
    if v2:
        struct.pack_into(E + "I", img, base + 32, zlib.crc32(bytes(img[base:])))
    return bytes(img)

def cram_crafted(t, drv):
    data = [blob(4096 * 6 + 1000, 201, "mixed"), blob(4096 * 3, 202, "text"), blob(50000, 203)]
    zeros = bytes(4096 * 2) + b"tail" + bytes(5000)
    kindsets = [["z", "dz", "du", "u", "z", "dz", "z"], ["du", "z", "dz"], ["dz", "dz", "u"]]
    for be in (False, True):
        for pad in (False, True):
            ents = [("f%d.bin" % i, 0o100644, d, k) for i, (d, k) in enumerate(zip(data, kindsets))]
            ents.append(("holes.bin", 0o100600, zeros, ["h"]))
            ents.append(("lnk", 0o120777, b"f0.bin", []))
            ents.append(("empty", 0o100644, b"", []))
            tag = "%s%s" % ("be" if be else "le", "_pad" if pad else "")
            p = t.path("cr_ext_%s.cramfs" % tag)
            open(p, "wb").write(cram_write(ents, be=be, pad=pad))
            exp = {"f%d.bin" % i: d for i, d in enumerate(data)}
            exp.update({"holes.bin": zeros, "lnk": b"", "empty": b""})
            t.check_extract(p, exp, label="cramfs ext pointers %s" % tag)
            check_views(t, drv, p, "cramfs ext pointers %s views" % tag)
            r, typ, rows = dump(drv, p)
            t.record(rows.get("lnk", {}).get("link") == "f0.bin", "cramfs crafted link %s" % tag)
    # version 1 (no fsid / CRC), plain pointers, 16K blocks
    ents = [("a.bin", 0o100644, blob(70000, 211, "mixed"), ["z"]), ("b.txt", 0o100644, b"bee\n", ["z"])]
    p = t.path("cr_v1.cramfs")
    open(p, "wb").write(cram_write(ents, ext=False, v2=False, bs=16384))
    t.check_extract(p, {"a.bin": ents[0][2], "b.txt": b"bee\n"}, label="cramfs v1 16K blocks")
    return p

def cram_hostile(t, drv, sdrv, imgs):
    le = open(imgs["le"], "rb").read()
    def variant(name, fn):
        d = bytearray(le)
        fn(d)
        p = t.path("hc_%s.cramfs" % name)
        open(p, "wb").write(d)
        hostile(t, drv, p, "cramfs hostile %s" % name)
    root_off = (struct.unpack_from("<I", le, 72)[0] >> 6) << 2
    def first_dirent(d):
        return root_off
    variant("root_size_huge", lambda d: struct.pack_into("<I", d, 68, (struct.unpack_from("<I", d, 68)[0] & 0xFF000000) | 0xFFFFFF))
    variant("root_off_eof", lambda d: struct.pack_into("<I", d, 72, (struct.unpack_from("<I", d, 72)[0] & 63) | 0x3FFFFFF << 6))
    variant("namelen0", lambda d: struct.pack_into("<I", d, root_off + 8, struct.unpack_from("<I", d, root_off + 8)[0] & ~63))
    def loop(d):                                          # every directory entry points at the root listing
        w = struct.unpack_from("<I", d, root_off + 8)[0]
        struct.pack_into("<I", d, root_off, (struct.unpack_from("<I", d, root_off)[0] & 0xFFFF0000) | 0o40755)
        struct.pack_into("<I", d, root_off + 4, (struct.unpack_from("<I", d, 68)[0] & 0xFFFFFF))
        struct.pack_into("<I", d, root_off + 8, (w & 63) | (root_off >> 2) << 6)
    variant("dir_loop", loop)
    variant("flags_unknown", lambda d: struct.pack_into("<I", d, 8, 0x10000))
    variant("size_small", lambda d: struct.pack_into("<I", d, 4, 80))
    for cut in (76, 200, len(le) // 3, len(le) - 100):
        p = t.path("hc_trunc_%d.cramfs" % cut)
        open(p, "wb").write(le[:cut])
        hostile(t, drv, p, "cramfs truncated at %d" % cut)
    n = int(os.environ.get("GZ_SQFS_FUZZ", "400"))
    fz = {"a.txt": blob(3000, 301, "text"), "d/b.bin": blob(30000, 302, "mixed"), "d/e/c.txt": b"c\n" * 50}
    for i in range(20):
        fz["m/f%02d" % i] = ("f%d" % i).encode() * (i + 1)
    fsrc = make_src(t, t.path("src_cfuzz"), fz, links=[("d/l", "../a.txt")])
    for tag, opts in (("le", []), ("be", ["-N", "big"]), ("z", ["-z"])):
        img = mkcram(t, fsrc, "cfz_%s.cramfs" % tag, opts)
        r = subprocess.run([sdrv, "fuzz", img, str(n), str(len(tag) * 131)], capture_output=True, timeout=1200)
        err = r.stderr.decode(errors="replace")
        ok = r.returncode == 0 and "Sanitizer" not in err and "runtime error" not in err
        t.record(ok, "cramfs fuzz %s" % tag, (r.stdout.decode().strip() + " " + err[-300:]).strip())
    for be in (False, True):
        ents = [("f.bin", 0o100644, blob(30000, 311, "mixed"), ["dz", "du", "u", "z", "h"]), ("l", 0o120777, b"f.bin", [])]
        p = t.path("cfz_ext_%d.cramfs" % be)
        open(p, "wb").write(cram_write(ents, be=be))
        r = subprocess.run([sdrv, "fuzz", p, str(n), str(17 + be)], capture_output=True, timeout=1200)
        err = r.stderr.decode(errors="replace")
        t.record(r.returncode == 0 and "Sanitizer" not in err and "runtime error" not in err,
                 "cramfs fuzz ext pointers %s" % ("be" if be else "le"), r.stdout.decode().strip())

# ----------------------------------------------------------------

def run(t):
    have_sq = t.tool("mksquashfs") and t.tool("unsquashfs") and t.tool("7z")
    have_cr = t.tool("mkfs.cramfs") and t.tool("7z")
    if not t.tool("7z"):
        t.skip("needs 7z (reference) and squashfs-tools / mkfs.cramfs")
    drv = t.build_driver("tests/drivers/fs1_dump.c")
    sdrv = t.build_driver("tests/drivers/sqfs_drv.c")
    if have_sq:
        src, exp, imgs = squash_main(t, drv)
        squash_special(t, drv)
        squash_threads(t, sdrv, imgs)
        squash_sqfstar(t)
        squash_hostile(t, drv, sdrv)
        if os.environ.get("GZ_SQFS_BIG", "1") != "0":
            squash_huge(t, drv)
        if os.environ.get("GZ_SQFS_PERF"):
            squash_perf(t, sdrv)
        for img in imgs.values():                    # keep the work directory small
            if os.path.exists(img):
                os.remove(img)
        shutil.rmtree(src, ignore_errors=True)
    else:
        t.record(True, "squashfs skipped (no squashfs-tools)")
    if t.tool("7z"):
        squash_v3(t, drv, sdrv)
    cram_crafted(t, drv)
    empty_images(t, have_sq, have_cr)
    if have_cr:
        imgs = cram_main(t, drv, sdrv)
        cram_hostile(t, drv, sdrv, imgs)
    else:
        t.record(True, "cramfs mkfs tests skipped (no mkfs.cramfs)")
