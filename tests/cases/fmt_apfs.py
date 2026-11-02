"""APFS containers: images from mkapfs (apfsprogs) and from the builder in _apfs_build.py
(checkpoints, object maps, several volumes, deep fs trees, hashed / plain names, sparse and
fragmented files, decmpfs zlib / LZVN / LZFSE / stored inline and in resource forks, symlinks,
hard links, sealed and encrypted volumes, block sizes 4-64 KiB). References: 7-Zip and
libfsapfs (pyfsapfs) where they support the feature, else the builder's input. Views, nested
archives, GPT descent, hostile images and checksum-aware in-process fuzzing."""
import os, sys, io, random, shutil, struct, subprocess, zipfile, zlib, unicodedata

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _apfs_build as B

FT_EPOCH = 11644473600
T0 = 1700000000 * 10**9 + 123456789


def ft_of_ns(ns):
    return ns // 100 + FT_EPOCH * 10**7


def blob(n, seed=1, text=False):
    rnd = random.Random(seed * 7919 + n)
    if not text:
        return rnd.randbytes(n)
    words = [b"\xea\xb3\xa0\xea\xb8\xb0", b"meat", b"grill", b"zip", b"apfs", b"\n", b"extent", b"inode"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words) + b" "
    return bytes(out[:n])


def with_dirs(files):
    out = dict(files)
    for k in files:
        parts = k.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            out.setdefault("/".join(parts[:i]), None)
    return out


def dump(drv, img, env=None):
    r = subprocess.run([drv, "l", img], capture_output=True, env=env, timeout=300)
    rows, typ, comment = {}, None, None
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if p[0] == "TYPE":
            typ = p[1]
        elif p[0] == "COMMENT":
            comment = p[1]
        elif len(p) >= 14 and p[0].isdigit():
            name, link = p[13], None
            if " -> " in name:
                name, link = name.split(" -> ", 1)
            rows[name] = dict(idx=int(p[0]), is_dir=int(p[1]), is_link=int(p[2]), usize=int(p[3]),
                              csize=int(p[4]), mk=int(p[5]), mtime=int(p[6]), attr=int(p[7]),
                              mode=int(p[8], 8), aux=int(p[9]), aux32=int(p[10]), flags=int(p[11]),
                              method=p[12], link=link)
    return r, typ, comment, rows


def xcrc(drv, img):
    r = subprocess.run([drv, "x", img], capture_output=True, timeout=300)
    out = {}
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if len(p) == 5 and p[0].isdigit():
            out[p[4]] = (int(p[1]), int(p[2]), p[3])
    return r, out


def check_crcs(t, drv, img, files, label, errors=None):
    """files: {name: bytes}; errors: {name: status} expected failures"""
    r, got = xcrc(drv, img)
    bad = []
    for k, v in files.items():
        n = unicodedata.normalize("NFC", k)
        if n not in got:
            bad.append("missing " + n)
            continue
        st, size, crc = got[n]
        if errors and k in errors:
            if st != errors[k]:
                bad.append("%s: status %d want %d" % (n, st, errors[k]))
            continue
        if st or size != len(v) or crc != "%08x" % zlib.crc32(v):
            bad.append("%s: st %d size %d/%d" % (n, st, size, len(v)))
    return t.record(r.returncode == 0 and not bad, label, "; ".join(bad[:6]) or "%d entries" % len(got))


def survive(drv, img, timeout=60):
    try:
        for cmd in ("l", "x", "v"):
            r = subprocess.run([drv, cmd, img], capture_output=True, timeout=timeout)
            err = r.stderr.decode(errors="replace")
            if r.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err:
                return "%s rc=%d %s" % (cmd, r.returncode, err[-400:])
    except subprocess.TimeoutExpired:
        return "timeout"
    return None


def hostile(t, drv, img, label):
    why = survive(drv, img)
    return t.record(why is None, "hostile " + label, why or "")


def write(t, name, data):
    p = t.path(name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def zip_bytes(files):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in files.items():
            z.writestr(k, v)
    return bio.getvalue()


# ---------------------------------------------------------------- image blocks

def blocks_of(img, bs, typ=None, sub=None):
    out = []
    for i in range(len(img) // bs):
        b = img[i * bs:(i + 1) * bs]
        ck = struct.unpack_from("<Q", b)[0]
        if not ck or ck != B.fletcher64(b):
            continue
        ty, st = struct.unpack_from("<II", b, 24)
        if (typ is None or ty & 0xFFFF == typ) and (sub is None or st == sub):
            out.append(i)
    return out


def patch(img, bs, blk, fn, reseal=True):
    """fn(bytearray block) modifies in place; checksum fixed afterwards"""
    d = bytearray(img)
    b = bytearray(d[blk * bs:(blk + 1) * bs])
    fn(b)
    if reseal:
        b = bytearray(B.seal(b))
    d[blk * bs:(blk + 1) * bs] = b
    return bytes(d)


def node_toc(b, bs):
    flags, level, nkeys = struct.unpack_from("<HHI", b, 0x20)
    toff, tlen = struct.unpack_from("<HH", b, 0x28)
    vend = bs - 40 if flags & 1 else bs
    kb = 0x38 + toff + tlen
    ents = []
    for i in range(nkeys):
        if flags & 4:
            ko, vo = struct.unpack_from("<HH", b, 0x38 + toff + 4 * i)
            ents.append((kb + ko, None, vend - vo, None))
        else:
            ko, kl, vo, vl = struct.unpack_from("<HHHH", b, 0x38 + toff + 8 * i)
            ents.append((kb + ko, kl, vend - vo, vl))
    return flags, level, ents


# ---------------------------------------------------------------- volumes used below

def feature_volume(seven_zip_only=False, name="Macintosh HD"):
    """files + expected data; seven_zip_only: only what 7-Zip and libfsapfs can read too"""
    v = B.Volume(name)
    exp = {}

    def f(path, data, **kw):
        v.file(path, data, **kw)
        exp[path] = data

    v.dir("docs", mtime_ns=T0 + 5)
    v.dir("docs/empty")
    v.dir("깊은")
    f("docs/hello.txt", b"hello apfs\n", uid=0, gid=80, mode=0o100600, mtime_ns=T0 + 777)
    f("docs/한글 파일.txt", "고깃집 아카이브".encode())
    f("깊은/NFD " + unicodedata.normalize("NFD", "한글") + ".txt", b"nfd name")
    f("empty.bin", b"")
    f("frag.bin", blob(300000, 3), frag=5)
    f("text.txt", blob(70000, 4, True))
    f("z_inline.txt", blob(20000, 5, True), compress=("zlib", "inline"))
    f("z_inline_stored.bin", blob(1500, 6), compress=("zlib", "inline"))
    f("z_rsrc.txt", blob(300000, 7, True), compress=("zlib", "rsrc"))
    f("z_rsrc_mixed.bin", blob(65536, 8, True) + blob(65536, 9) + blob(1000, 10, True), compress=("zlib", "rsrc"))
    f("vn_inline.txt", blob(9000, 11, True), compress=("lzvn", "inline"))
    f("vn_inline_stored.bin", blob(700, 12), compress=("lzvn", "inline"))
    f("vn_rsrc.txt", blob(200000, 13, True), compress=("lzvn", "rsrc"))
    f("vn_rsrc_mixed.bin", blob(65536, 14) + blob(30000, 15, True), compress=("lzvn", "rsrc"))
    f("copy9.bin", blob(2000, 16), compress=("raw9", "inline"))
    f("z_dec_stream.txt", blob(400000, 17, True), compress=("zlib", "inline"), dec_stream=True)
    f("hidden.txt", b"hidden", bsd=B.UF_HIDDEN)
    f("readonly.txt", b"ro", mode=0o100444)
    v.symlink("docs/link", "hello.txt")
    v.symlink("abs_link", "/usr/bin/env")
    v.hardlink("docs/hardlink.txt", "docs/hello.txt")
    exp["docs/hardlink.txt"] = exp["docs/hello.txt"]
    if not seven_zip_only:
        v.fifo("fifo")                                  # skipped (7-Zip shows it as a file)
    deep = "d"
    v.dir(deep)
    for i in range(30):
        deep += "/n%d" % i
        v.dir(deep)
    f(deep + "/bottom.txt", b"bottom")
    if not seven_zip_only:
        f("sparse.bin", blob(4096, 20) + bytes(3 * 4096) + blob(5000, 21), sparse=[(4096, 3 * 4096)])
        f("sparse_gap.bin", blob(4096, 22) + bytes(8192) + blob(100, 23), sparse=[(4096, 8192)],
          hole_records=False)
        f("sparse_tail.bin", blob(5000, 24) + bytes(1 << 20), size=5000 + (1 << 20))
        v.by_path["sparse_tail.bin"].data = blob(5000, 24)
        f("fs_inline.txt", blob(30000, 25, True), compress=("lzfse", "inline"))
        f("fs_rsrc.txt", blob(250000, 26, True), compress=("lzfse", "rsrc"))
        f("fs_rsrc_stored.bin", blob(70000, 27), compress=("lzfse", "rsrc"))
        f("raw1.bin", blob(3000, 28), compress=("raw", "inline"))
        f("raw10.bin", blob(140000, 29), compress=("raw", "rsrc"))
        f("rsrc_embedded.txt", blob(3000, 30, True), compress=("zlib", "rsrc"), rsrc_embedded=True)
        f("xattrs.txt", b"has xattrs", xattrs={"user.test": b"value", "com.apple.FinderInfo": bytes(32),
                                               "big.attr": blob(6000, 31)})
        v.file("lzbitmap.bin", b"x" * 100, compress=("lzbitmap", "inline"))
    return v, exp


def run(t):
    t.need("lzfse")
    drv = t.build_driver("tests/drivers/apfs_drv.c")
    have7z = shutil.which("7z") is not None
    py12 = shutil.which("python3.12")
    pyf = None
    if py12 and subprocess.run([py12, "-I", "-c", "import pyfsapfs"], capture_output=True).returncode == 0:
        pyf = py12

    # ------------------------------------------------ mkapfs (independent writer)
    if shutil.which("mkapfs"):
        for name, args in (("mk_ci", ["-L", "Gogit 고깃"]), ("mk_cs", ["-s", "-L", "Sensitive"])):
            img = t.path(name + ".img")
            with open(img, "wb") as fh:
                fh.truncate(128 << 20)
            t.sh(["mkapfs"] + args + [img])
            r, typ, com, rows = dump(drv, img)
            want = args[-1]
            t.record(r.returncode == 0 and typ == "APFS" and com == want and not rows,
                     "mkapfs %s: empty volume, label" % name, "%s %r %d" % (typ, com, len(rows)))
            r = t.run_gzt(["l", img])
            t.record(r.returncode == 0 and b"TYPE\tAPFS\t0" in r.stdout, "gzt lists mkapfs %s" % name,
                     r.stdout[:80])
    else:
        t.record(True, "mkapfs not installed (apfsprogs): skipped")

    # ------------------------------------------------ feature image vs expectations
    v, exp = feature_volume()
    img_b = B.build([v])
    img = write(t, "features.img", img_b)
    t.check_extract(img, with_dirs(exp), label="features: names + data", expect_type="APFS", allow_extra=True)
    check_crcs(t, drv, img, exp, "features: streamed CRCs")
    r, typ, com, rows = dump(drv, img)
    t.record(typ == "APFS" and com == "Macintosh HD", "features: type + volume name comment", "%s %r" % (typ, com))
    meta = []
    h = rows.get("docs/hello.txt", {})
    if h.get("mode") != 0o100600 or h.get("aux") != 0 | (80 << 32) or h.get("mtime") != ft_of_ns(T0 + 777) \
            or h.get("mk") != 1 or h.get("attr") != 0:
        meta.append("hello %r" % h)
    d = rows.get("docs", {})
    if not d.get("is_dir") or d.get("mtime") != ft_of_ns(T0 + 5) or d.get("attr") != 0x10:
        meta.append("docs %r" % d)
    if rows.get("docs/link", {}).get("link") != "hello.txt" or rows.get("abs_link", {}).get("link") != "/usr/bin/env":
        meta.append("symlinks")
    if rows.get("docs/link", {}).get("mode") != 0o120755:
        meta.append("link mode")
    if rows.get("hidden.txt", {}).get("attr") != 2 or rows.get("readonly.txt", {}).get("attr") != 1:
        meta.append("attrs")
    if "fifo" in rows:
        meta.append("fifo listed")
    if rows.get("text.txt", {}).get("aux") != 501 | (20 << 32):
        meta.append("uid/gid")
    for k, m in (("z_inline.txt", "zlib"), ("z_rsrc.txt", "zlib"), ("vn_rsrc.txt", "LZVN"), ("fs_rsrc.txt", "LZFSE"),
                 ("copy9.bin", "Store"), ("raw10.bin", "Store"), ("lzbitmap.bin", "LZBITMAP"), ("text.txt", "")):
        if rows.get(k, {}).get("method") != m:
            meta.append("method %s=%r" % (k, rows.get(k, {}).get("method")))
    if rows.get("z_rsrc.txt", {}).get("usize") != 300000:
        meta.append("decmpfs size")
    if rows.get("sparse_tail.bin", {}).get("usize") != 5000 + (1 << 20):
        meta.append("sparse tail size")
    t.record(not meta, "features: metadata (mode, uid/gid, ns times, attrs, links, methods)", "; ".join(meta))
    r, got = xcrc(drv, img)
    t.record(got.get("lzbitmap.bin", (0,))[0] == 5, "features: LZBITMAP -> GZ_E_METHOD", repr(got.get("lzbitmap.bin")))
    t.record(got.get("fifo") is None and all(st == 0 for k, (st, _, _) in got.items() if k != "lzbitmap.bin"),
             "features: every other entry extracts", repr([k for k, (st, _, _) in got.items() if st][:5]))

    # views: plain files are random-access views, compressed ones are not
    rv = subprocess.run([drv, "v", img], capture_output=True, timeout=300)
    bad, nv = [], 0
    for line in rv.stdout.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if len(p) < 9 or not p[0].isdigit():
            continue
        st, size, crcx, kind, vs, crcv, err, name = int(p[1]), int(p[2]), p[3], p[4], int(p[5]), p[6], int(p[7]), p[8]
        comp = rows.get(name, {}).get("method", "") != ""
        if name == "lzbitmap.bin":
            continue
        if st:
            bad.append("%s: st %d" % (name, st))
        elif comp != (kind == "noview"):
            bad.append("%s: %s" % (name, kind))
        elif kind == "view":
            nv += 1
            if vs != size or crcv != crcx or err:
                bad.append("%s: view %d/%d %s/%s err %d" % (name, vs, size, crcv, crcx, err))
    t.record(rv.returncode == 0 and nv >= 8 and not bad, "features: views == extraction", "; ".join(bad[:5]) or "%d views" % nv)

    # ------------------------------------------------ references: 7-Zip and libfsapfs
    v7, exp7 = feature_volume(seven_zip_only=True)
    img7 = write(t, "ref7z.img", B.build([v7]))
    if have7z:
        t.check_vs_7z(img7, label="7-Zip reference (zlib/LZVN/stored, links, deep dirs)", allow_extra=True)
    for bs in (8192, 16384, 65536):
        vb = B.Volume("bs%d" % bs)
        eb = {}
        for i in range(12):
            d = blob(1000 * i * i + 1, 40 + i, i % 2 == 0)
            vb.file("f%02d.bin" % i, d, frag=1 + i % 3, compress=(("zlib", "rsrc") if i % 4 == 1 else ("lzvn", "inline") if i % 4 == 3 else None))
            eb["f%02d.bin" % i] = d
        p = write(t, "bs%d.img" % bs, B.build([vb], bs=bs))
        t.check_extract(p, eb, label="block size %d" % bs)   # 7-Zip checks superblocks as 4 KiB
    if pyf:
        script = (
            "import sys, pyfsapfs, zlib\n"
            "c = pyfsapfs.container(); c.open(sys.argv[1])\n"
            "for vi in range(c.number_of_volumes):\n"
            "    v = c.get_volume(vi)\n"
            "    def walk(e, p):\n"
            "        for k in range(e.number_of_sub_file_entries):\n"
            "            s = e.get_sub_file_entry(k); q = (p + '/' if p else '') + s.name\n"
            "            link = s.symbolic_link_target\n"
            "            if s.number_of_sub_file_entries or (s.file_mode & 0o170000) == 0o40000:\n"
            "                print('D\\t' + q); walk(s, q)\n"
            "            elif link is not None: print('L\\t%s\\t%s' % (q, link))\n"
            "            else:\n"
            "                try: d = s.read() or b''; print('F\\t%s\\t%d\\t%08x' % (q, len(d), zlib.crc32(d)))\n"
            "                except Exception as ex: print('E\\t%s' % q)\n"
            "    walk(v.get_root_directory(), '')\n")
        for label, path, ex in (("features", img, exp), ("7z set", img7, exp7)):
            r = subprocess.run([pyf, "-I", "-c", script, path], capture_output=True, timeout=300)
            ref = {}
            for line in r.stdout.decode("utf-8", "replace").splitlines():
                p = line.split("\t")
                if p[0] == "F":
                    ref[unicodedata.normalize("NFC", p[1])] = (int(p[2]), p[3])
            _, got = xcrc(drv, path)
            bad = [k for k, (n, c) in ref.items() if k != "fifo" and (got.get(k, (1, 0, ""))[1:] != (n, c) or got[k][0])]
            # libfsapfs 20201107 lacks LZFSE, type 9/10, extent gaps / sparse tails: those are
            # checked against the builder's input above
            core = [k for k in ("frag.bin", "z_inline.txt", "z_rsrc_mixed.bin", "vn_inline_stored.bin", "vn_rsrc_mixed.bin",
                                "sparse.bin", "docs/hardlink.txt", "깊은/NFD 한글.txt") if k in ex or k == "깊은/NFD 한글.txt"]
            missing = [k for k in core if k not in ref and (label == "features" or k != "sparse.bin")]
            t.record(r.returncode == 0 and len(ref) > 10 and not bad and not missing,
                     "libfsapfs reference (%s): %d files agree" % (label, len(ref)), "bad %s missing %s" % (bad[:4], missing[:4]))
    else:
        t.record(True, "pyfsapfs (python3-fsapfs) not available: libfsapfs comparison skipped")

    # ------------------------------------------------ names: case-sensitive / plain keys, deep trees
    for label, kw in (("case-sensitive hashed", dict(case_insensitive=False)),
                      ("plain (non-hashed) keys", dict(case_insensitive=False, hashed=False)),
                      ("deep fs tree (3 records per node)", dict(leaf_max=3)),
                      ("hashed index nodes", dict(leaf_max=4, hashed_index=True))):
        vn = B.Volume("names", **kw)
        en = {}
        vn.dir("Dir")
        vn.dir("dir")
        for i in range(120 if "deep" in label else 40):
            nm = ("Dir/" if i % 3 == 0 else "dir/" if i % 3 == 1 else "") + "파일%03d_%s.txt" % (i, "Ab"[i % 2])
            d = blob(i * 37 + 1, 50 + i)
            vn.file(nm, d)
            en[nm] = d
        p = write(t, "names_%d.img" % len(label), B.build([vn]))
        t.check_extract(p, with_dirs(en), label=label)
        if have7z and "hashed index" not in label:
            t.check_vs_7z(p, label="7-Zip reference: " + label)

    # ------------------------------------------------ several volumes, encrypted volume
    va, ea = feature_volume(seven_zip_only=True, name="Data")
    vb2 = B.Volume("Data", case_insensitive=False)
    vb2.file("second.txt", b"second volume")
    vc = B.Volume("")
    vc.dir("x")
    vc.file("x/third.bin", blob(10000, 60))
    venc = B.Volume("Secret", encrypted=True)
    venc.file("secret.txt", b"not readable")
    pm = write(t, "multi.img", B.build([va, vb2, vc, venc]))
    em = {"Data/" + k: d for k, d in ea.items()}
    em.update({"Data (2)/second.txt": b"second volume", "Volume 3/x/third.bin": blob(10000, 60)})
    t.check_extract(pm, with_dirs(em), label="four volumes: one folder each (name, unique, Volume N)", allow_extra=True)
    r, got = xcrc(drv, pm)
    t.record(got.get("Secret", (0,))[0] == 5 and not any(k.startswith("Secret/") for k in got),
             "encrypted volume folder -> GZ_E_METHOD", repr(got.get("Secret")))
    if have7z:
        # 7-Zip names volume folders Volume1..N and cannot open a container with an encrypted
        # volume: compare the three readable volumes
        pm7 = write(t, "multi7.img", B.build([va, vb2, vc]))
        r7, out7 = t.sevenzip_extract(pm7)
        ref = t.read_tree(out7)
        mp = {"Volume1/": "Data/", "Volume2/": "Data (2)/", "Volume3/": "Volume 3/"}
        refm = {}
        for k, d in ref.items():
            for a, b in mp.items():
                if k.startswith(a):
                    refm[b + k[len(a):]] = d
        _, got = xcrc(drv, pm7)
        bad = [k for k, d in refm.items() if got.get(unicodedata.normalize("NFC", k), (1, 0, ""))[1:] !=
               (len(d), "%08x" % zlib.crc32(d))]
        t.record(len(refm) > 20 and not bad, "7-Zip reference: multi-volume contents", repr(bad[:4]))
    penc = write(t, "encrypted.img", B.build([venc]))
    r = subprocess.run([drv, "l", penc], capture_output=True)
    t.record(b"OPEN_ERROR 5" in r.stdout, "single encrypted volume: open -> GZ_E_METHOD", r.stdout[:60])

    # ------------------------------------------------ sealed volumes (file-extent tree)
    for mode in (True, "physical"):
        vs = B.Volume("System", sealed=mode, leaf_max=4)
        es = {}
        vs.dir("System")
        for i in range(25):
            d = blob(i * 3001 + 7, 70 + i, i % 2 == 0)
            vs.file("System/lib%02d.dylib" % i, d, frag=1 + i % 4)
            es["System/lib%02d.dylib" % i] = d
        vs.file("System/c.txt", blob(90000, 99, True), compress=("lzvn", "rsrc"))
        es["System/c.txt"] = blob(90000, 99, True)
        p = write(t, "sealed_%s.img" % mode, B.build([vs]))
        t.check_extract(p, with_dirs(es), label="sealed volume (%s fs tree)" % ("virtual, hashed" if mode is True else "physical"))
        if have7z and mode is True:
            t.check_vs_7z(p, label="7-Zip reference: sealed volume (SHA-256 hashed nodes)")

    # ------------------------------------------------ checkpoints
    old = B.Volume("CP")
    old.file("state.txt", b"old state")
    old.file("only_old.txt", b"gone later")
    new = B.Volume("CP")
    new.file("state.txt", b"new state")
    new.file("only_new.txt", b"added")
    cases = (("block 0 newest", dict(block0="newest"), "new"),
             ("block 0 stale, newest in descriptor area", dict(block0="oldest"), "new"),
             ("block 0 checksum bad", dict(block0="none"), "new"),
             ("newest copy corrupt, block 0 stale", dict(block0="oldest", corrupt=(1,)), "old"),
             ("newest copy corrupt, block 0 newest", dict(block0="newest", corrupt=(1,)), "new"),
             ("descriptor ring wraps", dict(block0="oldest", desc_blocks=2), "new"))
    for label, kw, want in cases:
        p = write(t, "cp_%d.img" % len(label), B.build([[old], [new]], **kw))
        e = {"state.txt": b"new state", "only_new.txt": b"added"} if want == "new" else \
            {"state.txt": b"old state", "only_old.txt": b"gone later"}
        t.check_extract(p, e, label="checkpoint: " + label)
    # newest checkpoint's container object map destroyed: the older checkpoint is used
    cpb = B.build([[old], [new]])
    om = blocks_of(cpb, 4096, B.T_OMAP)
    newest_om = max(om, key=lambda b: struct.unpack_from("<Q", cpb, b * 4096 + 16)[0])
    broken = patch(cpb, 4096, newest_om, lambda b: b.__setitem__(slice(0x30, 0x38), b"\xff" * 8))
    p = write(t, "cp_omap.img", broken)
    t.check_extract(p, {"state.txt": b"old state", "only_old.txt": b"gone later"},
                    label="checkpoint: newest object map broken -> older checkpoint")

    # ------------------------------------------------ nested archive, GPT partition
    inner = {"in/a.txt": b"inside zip", "b.bin": blob(5000, 80)}
    vz = B.Volume("Nest")
    vz.dir("pkg")
    vz.file("pkg/data.zip", zip_bytes(inner), frag=3)
    pn = write(t, "nested.img", B.build([vz]))
    r = subprocess.run([drv, "n", pn, "pkg/data.zip"], capture_output=True, timeout=60)
    out = r.stdout.decode("utf-8", "replace").splitlines()
    gotn = {}
    for line in out[1:]:
        p = line.split("\t")
        if len(p) == 5:
            gotn[p[4]] = (int(p[1]), int(p[2]), p[3])
    wantn = {k: (0, len(d), "%08x" % zlib.crc32(d)) for k, d in inner.items()}
    t.record(out and out[0].startswith("TYPE\tZIP") and gotn == wantn, "zip inside APFS opened through its view",
             repr(out[:2]))
    if shutil.which("sgdisk"):
        apfs_img = B.build([v7])
        disk = t.path("gpt.img")
        with open(disk, "wb") as fh:
            fh.truncate(len(apfs_img) + (2 << 20))
        t.sh(["sgdisk", "-n", "1:2048:+%dK" % (len(apfs_img) // 1024), "-t", "1:7C3457EF-0000-11AA-AA11-00306543ECAC",
              disk])
        with open(disk, "r+b") as fh:
            fh.seek(2048 * 512)
            fh.write(apfs_img)
        r, rows, outd = t.extract(disk)
        info = r.stderr.decode(errors="replace")
        t.check_extract(disk, with_dirs(exp7), label="APFS partition in a GPT disk (descent)", allow_extra=True)
        t.record("type=APFS" in info, "GPT descent type name", info.splitlines()[0] if info else "")

    # ------------------------------------------------ hostile images
    base = B.build([v7])
    hostile(t, drv, write(t, "hostile_base.img", base), "unmodified base")
    bs = 4096
    fs_nodes = blocks_of(base, bs, None, B.T_FSTREE)
    om_nodes = blocks_of(base, bs, None, B.T_OMAP)
    # a deep fs tree for structural attacks
    vd = B.Volume("deep", leaf_max=3)
    for i in range(60):
        vd.file("f%02d" % i, blob(100 + i, i))
    vd.dir("loopdir")
    deep_img = B.build([vd])
    dfs = blocks_of(deep_img, bs, None, B.T_FSTREE)
    droot = [b for b in dfs if struct.unpack_from("<H", deep_img, b * bs + 0x20)[0] & 1][0]
    dindex = [b for b in dfs if struct.unpack_from("<H", deep_img, b * bs + 0x22)[0] > 0]
    hcases = []

    def child_to(img, blk, target_oid):
        def fn(b):
            _, _, ents = node_toc(b, bs)
            for ko, kl, vo, vl in ents:
                struct.pack_into("<Q", b, vo, target_oid)
        return patch(img, bs, blk, fn)

    root_oid = struct.unpack_from("<Q", deep_img, droot * bs + 8)[0]
    hcases.append(("fs index nodes point at the root (loop)", child_to(deep_img, droot, root_oid)))
    for blk in dindex[:2]:
        oid = struct.unpack_from("<Q", deep_img, blk * bs + 8)[0]
        hcases.append(("fs index node points at itself", child_to(deep_img, blk, oid)))
    # every child of the root -> the same subtree (DAG, visited once)
    def same_child(b):
        _, _, ents = node_toc(b, bs)
        first = struct.unpack_from("<Q", b, ents[0][2])[0]
        for ko, kl, vo, vl in ents:
            struct.pack_into("<Q", b, vo, first)
    hcases.append(("fs root children all the same subtree", patch(deep_img, bs, droot, same_child)))
    hcases.append(("fs root level 15", patch(deep_img, bs, droot, lambda b: struct.pack_into("<H", b, 0x22, 15))))
    hcases.append(("fs root nkeys huge", patch(deep_img, bs, droot, lambda b: struct.pack_into("<I", b, 0x24, 0xFFFFFFF))))
    hcases.append(("fs root toc beyond node", patch(deep_img, bs, droot, lambda b: struct.pack_into("<HH", b, 0x28, 0xFF00, 0x0FFF))))
    for blk in fs_nodes[:1]:
        def bad_offsets(b):
            _, _, ents = node_toc(b, bs)
            for i, (ko, kl, vo, vl) in enumerate(ents):
                toff = struct.unpack_from("<H", b, 0x28)[0]
                struct.pack_into("<HHHH", b, 0x38 + toff + 8 * i, 0xFFF0 if i % 2 else 0, 0xFFFF, 0xFFFE if i % 3 else 2, 0xFFFF)
        hcases.append(("fs leaf toc offsets out of range", patch(base, bs, blk, bad_offsets)))
    for blk in om_nodes[:3]:
        def om_loop(b):
            flags, level, ents = node_toc(b, bs)
            if flags & 2:
                for ko, kl, vo, vl in ents:
                    struct.pack_into("<Q", b, vo + 8, blk)          # every object -> this omap node
            else:
                for ko, kl, vo, vl in ents:
                    struct.pack_into("<Q", b, vo, blk)
        hcases.append(("omap entries point at the omap node", patch(base, bs, blk, om_loop)))
    hcases.append(("all checksums bad", bytes(b ^ (0xFF if i % bs < 8 else 0) for i, b in enumerate(base))))
    hcases.append(("superblock block count huge",
                   patch(base, bs, 0, lambda b: struct.pack_into("<Q", b, 0x28, (1 << 50)))))
    hcases.append(("superblock desc area huge", patch(base, bs, 0, lambda b: struct.pack_into("<IIQ", b, 0x68, 0x7FFFFFFF, 0, 1))))
    hcases.append(("superblock max volumes huge", patch(base, bs, 0, lambda b: struct.pack_into("<I", b, 0xB4, 0xFFFFFFFF))))
    hcases.append(("truncated to 3 blocks", base[:3 * bs]))
    hcases.append(("truncated mid-way", base[:len(base) // 2 + 1234]))
    # records: extents out of range / overlapping / huge, directory loops, decmpfs bombs
    vr = B.Volume("records")
    vr.dir("a")
    vr.dir("a/b")
    vr.file("a/b/ok.txt", b"ok")
    vr.file("victim.bin", blob(9000, 90))
    vr.file("bomb_z.bin", b"z" * 1000, compress=("zlib", "inline"))
    vr.file("bomb_r.bin", b"r" * 70000, compress=("zlib", "rsrc"))
    vr.file("bomb_v.bin", b"v" * 1000, compress=("lzvn", "inline"))
    rec_img = B.build([vr])
    hcases.append(("records base", rec_img))
    fw_ids = {}
    q = [vr.root]
    nid = 16
    while q:
        dnode = q.pop(0)
        for c in dnode.children:
            fw_ids[c.name] = nid
            nid += 1
            if c.kind == "dir":
                q.append(c)

    def extra_img(recs):
        vx = B.Volume("records")
        vx.dir("a")
        vx.dir("a/b")
        vx.file("a/b/ok.txt", b"ok")
        vx.file("victim.bin", blob(9000, 90))
        vx.file("bomb_z.bin", b"z" * 1000, compress=("zlib", "inline"))
        vx.file("bomb_r.bin", b"r" * 70000, compress=("zlib", "rsrc"))
        vx.file("bomb_v.bin", b"v" * 1000, compress=("lzvn", "inline"))
        vx.extra = recs
        return B.build([vx])
    vid = fw_ids["victim.bin"]
    ext_key = lambda oid, la: B.jkey(oid, B.J_EXTENT) + struct.pack("<Q", la)
    hcases.append(("extent beyond the container", extra_img([(ext_key(vid, 1 << 20), struct.pack("<QQQ", 8192, 1 << 40, 0))])))
    hcases.append(("extent length huge", extra_img([(ext_key(vid, 4096 * 3), struct.pack("<QQQ", (1 << 56) - 4096, 5, 0))])))
    hcases.append(("extent overlapping", extra_img([(ext_key(vid, 100), struct.pack("<QQQ", 4096, 3, 0))])))
    a_id, b_id = fw_ids["a"], fw_ids["b"]
    drec = lambda par, name, child, dt: (B.FsWriter(None, B.Volume("x"), 0).drec_key(par, name),
                                         struct.pack("<QQH", child, 0, dt))
    hcases.append(("directory contains its parent (loop)", extra_img([drec(b_id, "up", a_id, 4), drec(a_id, "self", a_id, 4),
                                                                     drec(b_id, "root", 2, 4)])))
    hcases.append(("dangling directory records", extra_img([drec(2, "ghost%d" % i, 9000 + i, 8) for i in range(50)])))
    for name, img_x in hcases:
        hostile(t, drv, write(t, "h_%02d.img" % (hcases.index((name, img_x))), img_x), name)

    # decmpfs size bombs: patch the uncompressed size inside the leaf node in place
    def bomb(img_in, size):
        out = bytearray(img_in)
        for blk in blocks_of(img_in, bs, None, B.T_FSTREE):
            b = bytearray(out[blk * bs:(blk + 1) * bs])
            pos = b.find(b"fpmc")
            while pos >= 0:
                struct.pack_into("<Q", b, pos + 8, size)
                pos = b.find(b"fpmc", pos + 4)
            out[blk * bs:(blk + 1) * bs] = B.seal(b)
        return bytes(out)
    for sz in (1 << 50, 1 << 31, 65537, 0):
        p = write(t, "bomb_%d.img" % sz, bomb(rec_img, sz))
        why = survive(drv, p)
        r, got = xcrc(drv, p)
        okb = why is None and all(got.get(k, (1,))[0] != 0 for k in ("bomb_z.bin", "bomb_r.bin", "bomb_v.bin")) \
            if sz else why is None
        t.record(okb, "decmpfs size %d: errors, no hang or huge allocation" % sz, why or repr({k: got.get(k) for k in ("bomb_z.bin", "bomb_r.bin", "bomb_v.bin")}))

    # damaged records do not hide the rest: the victim's neighbours still extract
    p = write(t, "h_overlap.img", extra_img([(ext_key(vid, 100), struct.pack("<QQQ", 4096, 3, 0))]))
    r, got = xcrc(drv, p)
    t.record(got.get("a/b/ok.txt", (1,))[0] == 0, "damaged extents: other files still extract", repr(got.get("a/b/ok.txt")))

    # checksum-aware in-process fuzzing (list + extract + views of every variant)
    asan = "sanitize" in os.environ.get("HOST_CFLAGS", "")
    for label, data, n in (("features", img_b, 1500 if asan else 6000), ("deep tree", deep_img, 1500 if asan else 5000),
                           ("multi-volume", open(pm, "rb").read(), 800 if asan else 3000),
                           ("sealed", open(t.path("sealed_True.img"), "rb").read(), 800 if asan else 3000)):
        p = write(t, "fuzz_src_%d.img" % len(label), data)
        try:
            r = subprocess.run([drv, "fuzz", p, str(n), str(len(label) * 7919)], capture_output=True, timeout=900)
            err = r.stderr.decode(errors="replace")
            ok = r.returncode == 0 and b"FUZZ" in r.stdout and "Sanitizer" not in err and "runtime error" not in err
            t.record(ok, "fuzz %s: %d mutated images" % (label, n), r.stdout.decode()[:80] if ok else err[-500:])
        except subprocess.TimeoutExpired:
            t.record(False, "fuzz %s" % label, "timeout")

    # ------------------------------------------------ performance
    vp = B.Volume("perf")
    big = blob(24 << 20, 5)
    vp.file("big.bin", big, frag=8)
    vp.file("big.txt", blob(8 << 20, 6, True), compress=("zlib", "rsrc"))
    vp.file("big_vn.txt", blob(1 << 20, 7, True), compress=("lzvn", "rsrc"))   # Python LZVN encoder: keep it small
    for i in range(2000):
        vp.file("f%04d.txt" % i, b"small %d" % i)
    pp = write(t, "perf.img", B.build([vp]))
    r = subprocess.run([drv, "bench", pp, "3"], capture_output=True, timeout=600)
    t.record(r.returncode == 0 and b"BENCH" in r.stdout, "bench: " + r.stdout.decode().strip(), "")
