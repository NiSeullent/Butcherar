"""CPIO / AR (.a, .lib, .deb) / RPM / XAR (.pkg, pbzx) / split volume tests.

Fixtures are made at test time: GNU cpio (newc, crc, odc, bin) and Python
writers (big-endian binary, bad checksums, concatenated archives), ar / llvm-ar /
llvm-lib, dpkg-deb, rpmbuild (gzip / bzip2 / xz / lzma / zstd / no payload
compression), bsdtar --format xar and a Python XAR writer (zlib / bzip2 / none /
xz encodings, SHA-1 / SHA-256 checksums, base64 names, hard links, .pkg layout
with cpio.gz and pbzx payloads), 7z -v / split for volume sets.
References: the source trees, 7-Zip and bsdtar extraction. Two small real
packages (Fedora 43 "hello" RPM with a zstd payload and signature headers,
Debian "hello" .deb) are downloaded once into the work directory when the
network is available (GZ_OFFLINE=1 skips them); they are only parsed.
The unixfmt driver (tests/drivers/unixfmt.c) dumps metadata (kind, mode,
mtime, link targets), runs the mutation fuzzer and a 4-thread extraction check.
"""
import os, io, struct, zlib, bz2, lzma, hashlib, random, shutil, subprocess, base64, gzip, glob, time
from gztest import normalize

E_CRC, E_METHOD, E_TRUNC, E_LIMIT, E_DATA, E_FORMAT = 4, 5, 9, 15, 3, 2

def blob(n, seed=1, text=False):
    rnd = random.Random(seed * 1000003 + n)
    if not text:
        return bytes(rnd.getrandbits(8) for _ in range(n)) if n < 200000 else rnd.randbytes(n)
    words = [b"gogi", b"samgyeopsal", b"zip", b"cpio", b"\xea\xb3\xa0\xea\xb8\xb0", b"\n", b"archive"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words) + b" "
    return bytes(out[:n])

def make_src(t, name, big=True, links=True):
    """A tree with text/binary/empty files, Korean names, nested dirs, a symlink, a hard link group."""
    root = os.path.join(t.work, name)
    shutil.rmtree(root, ignore_errors=True)
    files = {
        "readme.txt": blob(5000, 1, True),
        "문서/보고서.txt": blob(70001, 2, True),
        "문서/사진/고기.jpg": blob(40003, 3),
        "empty.txt": b"",
        "deep/a/b/c/d/e.bin": blob(1234, 4),
        "odd name & <x>.txt": b"amp & lt <\n",
    }
    if big:
        files["big.bin"] = blob(3 << 20, 5, True)
    for i in range(40):
        files["many/f%03d.txt" % i] = ("file %d\n" % i).encode() * (i + 1)
    t.write_tree(root, files)
    os.makedirs(os.path.join(root, "emptydir"))
    if links:
        os.symlink("../readme.txt", os.path.join(root, "deep/link"))
        os.link(os.path.join(root, "readme.txt"), os.path.join(root, "deep/hard1"))
        os.link(os.path.join(root, "readme.txt"), os.path.join(root, "many/hard2"))
    os.chmod(os.path.join(root, "문서/사진/고기.jpg"), 0o600)
    os.chmod(os.path.join(root, "deep/a/b/c/d/e.bin"), 0o755)
    for i, f in enumerate(sorted(files)):
        os.utime(os.path.join(root, f), (1600000000 + i * 3600, 1600000000 + i * 3600))
    if links:
        try:
            os.mkfifo(os.path.join(root, "fifo"))
        except OSError:
            pass
    return root

def ref_tree(root):
    """{rel: ("f", data, mode, mtime) | ("l", target, mode, mtime) | ("d", None, mode, mtime)}"""
    out = {}
    for dp, dns, fns in os.walk(root):
        for n in dns + fns:
            p = os.path.join(dp, n)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            st = os.lstat(p)
            if os.path.islink(p):
                out[rel] = ("l", os.readlink(p), 0o777, int(st.st_mtime))
            elif os.path.isdir(p):
                out[rel] = ("d", None, st.st_mode & 0o7777, int(st.st_mtime))
            elif os.path.isfile(p):
                out[rel] = ("f", open(p, "rb").read(), st.st_mode & 0o7777, int(st.st_mtime))
    return out

def dump(t, drv, arc, env=None):
    r = t.sh([drv, "dump", arc], check=False, env=env)
    typ, rows = None, []
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if p[0] == "TYPE":
            typ = p[1]
        elif p[0] == "OPEN_ERROR":
            typ = "ERROR %s" % p[1]
        elif len(p) >= 6 and p[0].isdigit():
            rows.append(dict(idx=int(p[0]), kind=p[1], mode=int(p[2], 8), mtime=None if p[3] == "-" else int(p[3]),
                             usize=int(p[4]), name=p[5], link=p[6] if len(p) > 6 else None))
    return typ, rows, r.stderr.decode("utf-8", "replace")

def verify(t, drv, arc, ref, label=None, expect_type=None, meta=True, exact=True, skip=()):
    """Extract arc with gzt and compare with a reference tree: regular files byte-exact
    (hard link entries through their target), symlink targets, modes and mtimes."""
    label = label or os.path.basename(arc)
    typ, rows, _ = dump(t, drv, arc)
    if expect_type and typ != expect_type:
        return t.record(False, label, "type %s (want %s)" % (typ, expect_type))
    r, xr, out = t.extract(arc)
    if r.returncode:
        return t.record(False, label, "driver failed %s" % r.stdout[-300:])
    ours = {}
    data = {}
    for row in rows:
        ours[row["name"]] = row
        st = xr.get(row["idx"], (-1,))[0]
        fp = os.path.join(out, "%d.bin" % row["idx"])
        if row["kind"] == "f":
            data[row["name"]] = open(fp, "rb").read() if st == 0 and os.path.exists(fp) else ("error %d" % st)
    probs = []
    for rel, (kind, val, mode, mtime) in sorted(ref.items()):
        n = normalize(rel)
        if any(n == s or n.startswith(s + "/") for s in skip):
            continue
        o = ours.get(n)
        if o is None:
            if kind != "d":
                probs.append("missing " + n)
            continue
        if kind == "f":
            if o["kind"] == "h":
                tgt = normalize(o["link"] or "")
                if data.get(tgt) != val:
                    probs.append("hard link %s -> %s: target data differs" % (n, tgt))
            elif o["kind"] != "f":
                probs.append("%s: kind %s" % (n, o["kind"]))
            elif data.get(n) != val:
                probs.append("data " + n + (" (%s)" % data[n] if isinstance(data.get(n), str) else ""))
        elif kind == "l" and meta:
            if o["kind"] != "l" or o["link"] != val:
                probs.append("symlink %s: %s %r" % (n, o["kind"], o["link"]))
        if meta and kind != "l" and (o["mode"] & 0o7777) != mode:
            probs.append("mode %s %o != %o" % (n, o["mode"] & 0o7777, mode))
        if meta and kind == "f" and o["mtime"] != mtime:
            probs.append("mtime %s %s != %s" % (n, o["mtime"], mtime))
    if exact:
        want = {normalize(k) for k, v in ref.items() if v[0] != "d"}
        for o in rows:
            if o["kind"] != "d" and o["name"] and o["name"] not in want:
                probs.append("unexpected " + o["name"])
    return t.record(not probs, label, "; ".join(probs[:6]) or "%d entries %s" % (len(rows), typ))

def vs_7z(t, drv, arc, label=None, skip_re=None, **kw):
    out = os.path.join(t.work, "ref7z_" + os.path.basename(arc))
    shutil.rmtree(out, ignore_errors=True)
    r = subprocess.run(["7z", "x", "-y", "-o" + out, arc], capture_output=True, timeout=600)
    # rc 2 with "Sub items Errors": 7-Zip cannot create the fifo / device entries
    if r.returncode and not (r.returncode == 2 and b"Sub items Errors" in r.stdout and os.path.isdir(out)):
        return t.record(False, label or "7z " + os.path.basename(arc), "7z failed: " + r.stdout.decode(errors="replace")[-300:])
    ref = ref_tree(out)
    if skip_re:
        import re
        ref = {k: v for k, v in ref.items() if not re.match(skip_re, k)}
    return verify(t, drv, arc, ref, label=label or "vs 7z " + os.path.basename(arc), meta=False, **kw)

def vs_bsdtar(t, drv, arc, label=None, **kw):
    out = os.path.join(t.work, "refbt_" + os.path.basename(arc))
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    r = subprocess.run(["bsdtar", "-xpf", arc, "-C", out], capture_output=True, timeout=600)
    if r.returncode:
        return t.record(False, label or "bsdtar " + os.path.basename(arc), "bsdtar failed: " + r.stderr.decode(errors="replace")[-300:])
    return verify(t, drv, arc, ref_tree(out), label=label or "vs bsdtar " + os.path.basename(arc), **kw)

def status_of(t, arc):
    r, rows, out = t.extract(arc)
    return r, rows

# ---------------------------------------------------------------- CPIO

def cpio_create(t, root, fmt, out, extra=()):
    names = subprocess.run(["find", "."], cwd=root, capture_output=True).stdout
    r = subprocess.run(["cpio", "-o", "-H", fmt] + list(extra), cwd=root, input=names, capture_output=True)
    if r.returncode:
        raise RuntimeError("cpio failed: %s" % r.stderr[-300:])
    open(out, "wb").write(r.stdout)
    return out

def newc_hdr(name, data, mode=0o100644, ino=1, nlink=1, mtime=1700000000, magic=b"070701", check=None,
             namesize=None, filesize=None):
    nm = name.encode() + b"\0" if isinstance(name, str) else name
    if check is None:
        check = sum(data) & 0xFFFFFFFF if magic == b"070702" else 0
    fields = [ino, mode, 0, 0, nlink, mtime, len(data) if filesize is None else filesize, 8, 1, 0, 0,
              len(nm) if namesize is None else namesize, check]
    h = magic + b"".join(b"%08X" % f for f in fields) + nm
    h += b"\0" * (-len(h) % 4)
    return h + data + b"\0" * (-len(data) % 4)

def newc(entries, magic=b"070701", trailer=True):
    """entries: [(name, data, mode, extra kw)]"""
    out = b"".join(newc_hdr(n, d, m, ino=i + 1, magic=magic, **kw) for i, (n, d, m, kw) in enumerate(entries))
    if trailer:
        out += newc_hdr("TRAILER!!!", b"", 0, ino=0, nlink=1, mtime=0, magic=magic)
    return out + b"\0" * (-len(out) % 512)

def bin_cpio(entries, be=False):
    e = ">" if be else "<"
    out = b""
    for i, (name, data, mode) in enumerate(entries + [("TRAILER!!!", b"", 0)]):
        nm = name.encode() + b"\0"
        mt = 1650000000 + i
        h = struct.pack(e + "13H", 0o070707, 1, i + 1, mode, 0, 0, 1, 0, mt >> 16, mt & 0xFFFF, len(nm),
                        len(data) >> 16, len(data) & 0xFFFF)
        h += nm + b"\0" * (len(nm) & 1)
        out += h + data + b"\0" * (len(data) & 1)
    return out

def test_cpio(t, drv):
    root = make_src(t, "cpio_src")
    ref = ref_tree(root)
    ref.pop("fifo", None)
    for fmt in ("newc", "crc", "odc", "bin"):
        p = cpio_create(t, root, fmt, t.path("t_%s.cpio" % fmt))
        # GNU cpio's bin format keeps only the low 16 bits of inode numbers: fine here
        verify(t, drv, p, ref, label="cpio %s" % fmt, expect_type="CPIO")
        if t.tool("7z"):
            # 7-Zip refuses "../" symlinks and turns the fifo into a file
            vs_7z(t, drv, p, label="cpio %s vs 7z" % fmt, skip_re=r"^fifo$", exact=False)
        if t.tool("bsdtar"):
            vs_bsdtar(t, drv, p, label="cpio %s vs bsdtar" % fmt)
    # hard links: newc keeps the data with the last link only
    typ, rows, _ = dump(t, drv, t.path("t_newc.cpio"))
    links = {r["name"]: r["link"] for r in rows if r["kind"] == "h"}
    holders = {normalize(v) for v in links.values()}
    t.record(len(links) == 2 and len(holders) == 1, "cpio newc hard link group", repr(links))
    sl = [r for r in rows if r["kind"] == "l"]
    t.record(len(sl) == 1 and sl[0]["name"] == "deep/link" and sl[0]["link"] == "../readme.txt", "cpio symlink target", repr(sl))
    # compressed cpio streams through the stream formats
    raw = open(t.path("t_newc.cpio"), "rb").read()
    variants = [("gz", gzip.compress(raw, 6), "CPIO.GZ"), ("bz2", bz2.compress(raw), "CPIO.BZ2")]
    if t.tool("zstd"):
        t.sh(["zstd", "-q", "-f", "-3", t.path("t_newc.cpio"), "-o", t.path("t_newc.cpio.zst")])
        variants.append(("zst", open(t.path("t_newc.cpio.zst"), "rb").read(), "CPIO.ZST"))
    for ext, blobz, typ in variants:
        p = t.path("t_newc.cpio." + ext)
        open(p, "wb").write(blobz)
        verify(t, drv, p, ref, label="cpio.%s" % ext, expect_type=typ)
    odc = open(t.path("t_odc.cpio"), "rb").read()
    p = t.path("t_odc.cpio.gz")
    open(p, "wb").write(gzip.compress(odc))
    verify(t, drv, p, ref, label="odc cpio.gz", expect_type="CPIO.GZ")
    # one entry from a compressed stream (decodes up to it, stops early)
    big = t.path("t_newc.cpio.gz")
    r = t.sh([drv, "threads", big], check=False)
    t.record(r.returncode == 0 and b"ok" in r.stdout, "cpio.gz 4 threads", r.stdout.decode()[-200:])

    # Python-made: big-endian binary, little-endian binary with odd sizes
    ents = [("a.txt", b"x" * 7, 0o100644), ("dir", b"", 0o040755), ("dir/b.bin", blob(70001, 9), 0o100600),
            ("dir/sl", b"a.txt", 0o120777), ("dev", b"", 0o020644), ("한글.txt", "한글".encode(), 0o100644)]
    for be in (False, True):
        p = t.path("py_bin_%s.cpio" % ("be" if be else "le"))
        open(p, "wb").write(bin_cpio(ents, be))
        exp = {"a.txt": b"x" * 7, "dir/b.bin": blob(70001, 9), "한글.txt": "한글".encode(), "dir": None}
        t.check_extract(p, exp, allow_extra=True, expect_type="CPIO", label="py bin %s" % ("BE" if be else "LE"))
        typ, rows, _ = dump(t, drv, p)
        names = [r["name"] for r in rows]
        okm = "dev" not in names and any(r["name"] == "dir/sl" and r["link"] == "a.txt" for r in rows) and \
              any(r["name"] == "a.txt" and r["mtime"] == 1650000000 for r in rows)
        t.record(okm, "py bin %s meta" % ("BE" if be else "LE"), repr(rows[:3]))

    # crc format: a wrong checksum is reported for that entry only
    good, bad = b"good data\n" * 100, b"bad data\n" * 100
    p = t.path("crc_bad.cpio")
    open(p, "wb").write(newc([("good.txt", good, 0o100644, {}), ("bad.txt", bad, 0o100644, {"check": 12345})], magic=b"070702"))
    r, rows = status_of(t, p)
    st = {v[3]: v[0] for v in rows.values()}
    t.record(st.get("good.txt") == 0 and st.get("bad.txt") == E_CRC, "cpio crc mismatch", repr(st))
    pg = t.path("crc_bad.cpio.gz")
    open(pg, "wb").write(gzip.compress(open(p, "rb").read()))
    r, rows = status_of(t, pg)
    st = {v[3]: v[0] for v in rows.values()}
    t.record(st.get("good.txt") == 0 and st.get("bad.txt") == E_CRC, "cpio.gz crc mismatch", repr(st))

    # initramfs style: an archive, zero padding, a second archive
    a1 = newc([("early/ucode.bin", blob(3000, 11), 0o100644, {})])
    a2 = newc([("init", b"#!/bin/sh\n", 0o100755, {}), ("etc", b"", 0o040755, {}), ("etc/x", b"y" * 5, 0o100644, {})])
    p = t.path("initramfs.cpio")
    open(p, "wb").write(a1 + b"\0" * 1536 + a2)
    exp = {"early/ucode.bin": blob(3000, 11), "init": b"#!/bin/sh\n", "etc/x": b"y" * 5}
    t.check_extract(p, exp, label="concatenated cpio")
    pg = t.path("initramfs.cpio.gz")
    open(pg, "wb").write(gzip.compress(a1 + b"\0" * 1536 + a2))
    t.check_extract(pg, exp, label="concatenated cpio.gz", expect_type="CPIO.GZ")
    # junk after the trailer is ignored
    p = t.path("junk_tail.cpio")
    open(p, "wb").write(a1 + b"\0" * 100 + b"this is not cpio" * 10)
    t.check_extract(p, {"early/ucode.bin": blob(3000, 11)}, label="cpio junk tail")
    # empty archive (only TRAILER!!!)
    p = t.path("empty.cpio")
    open(p, "wb").write(newc([]))
    r, rows = status_of(t, p)
    t.record(r.returncode == 0 and not rows, "empty cpio", r.stdout.decode()[-100:])
    # zip slip names stay inside
    p = t.path("slip.cpio")
    open(p, "wb").write(newc([("../../evil.txt", b"e", 0o100644, {}), ("/abs/x.txt", b"a", 0o100644, {})]))
    t.check_extract(p, {"evil.txt": b"e", "abs/x.txt": b"a"}, label="cpio slip names")

    # hostile headers
    hs = []
    def hostile(name, b):
        p = t.path("hostile", name)
        open(p, "wb").write(b)
        hs.append(p)
        return t.check_hostile(p, label="hostile cpio " + name)
    hostile("namesize_huge.cpio", newc_hdr("a", b"abc", namesize=0xFFFFFFFF) + newc([]))
    hostile("filesize_huge.cpio", newc_hdr("a", b"abc", filesize=0xFFFFFFFF))
    hostile("namesize_zero.cpio", newc_hdr("a", b"abc", namesize=0))
    hostile("bad_hex.cpio", b"070701" + b"Z" * 104 + b"\0" * 400)
    hostile("trunc_name.cpio", newc_hdr("abcdefghijklmnop", b"x" * 100)[:115])
    hostile("odc_junk.cpio", b"070707" + b"9" * 70 + b"\0" * 400)
    hostile("bin_trunc.cpio", bin_cpio(ents)[:40])
    hostile("link_huge.cpio", newc_hdr("l", b"T" * 200000, mode=0o120777) + newc([]))
    hostile("many_links.cpio", newc([("h%d" % i, b"" if i % 7 else b"data", 0o100644, {"nlink": 3}) for i in range(500)]))
    for i, f in enumerate(("namesize_huge", "filesize_huge")):
        pg = t.path("hostile", f + ".cpio.gz")
        open(pg, "wb").write(gzip.compress(open(t.path("hostile", f + ".cpio"), "rb").read()))
        hs.append(pg)
        t.check_hostile(pg, label="hostile cpio.gz " + f)
    return [t.path("t_newc.cpio"), t.path("t_odc.cpio"), t.path("t_crc.cpio"), t.path("py_bin_be.cpio"),
            t.path("initramfs.cpio.gz"), t.path("crc_bad.cpio")], hs

# ---------------------------------------------------------------- AR

def test_ar(t, drv):
    src = os.path.join(t.work, "ar_src")
    shutil.rmtree(src, ignore_errors=True)
    os.makedirs(src)
    names = ["a", "very_long_object_file_name_number_one", "b", "another_quite_long_name", "odd"]
    for i, n in enumerate(names):
        open(os.path.join(src, n + ".c"), "w").write("int f%d(void){return %d;}\nint g%d;\n" % (i, i, i))
        t.sh(["cc", "-c", n + ".c"], cwd=src)
    open(os.path.join(src, "odd.o"), "ab").write(b"!")                  # odd member size
    objs = [n + ".o" for n in names]
    exp = {o: open(os.path.join(src, o), "rb").read() for o in objs}
    seeds = []
    p = t.path("gnu.a")
    if os.path.exists(p):
        os.remove(p)
    t.sh(["ar", "rcs", p] + objs, cwd=src)
    t.check_extract(p, exp, expect_type="AR", label="GNU ar long names + symtab")
    seeds.append(p)
    if t.tool("7z"):
        vs_7z(t, drv, p, label="GNU ar vs 7z", skip_re=r"^\d+\.txt$")
    if t.tool("llvm-ar"):
        for fmt in ("bsd", "gnu", "darwin"):
            p = t.path("llvm_%s.a" % fmt)
            if os.path.exists(p):
                os.remove(p)
            t.sh(["llvm-ar", "--format=" + fmt, "rcs", p] + objs, cwd=src)
            # reference: llvm-ar's own extraction (darwin pads members to 8 bytes inside the size)
            xd = os.path.join(t.work, "llvm_x_" + fmt)
            shutil.rmtree(xd, ignore_errors=True)
            os.makedirs(xd)
            t.sh(["llvm-ar", "x", p], cwd=xd)
            t.check_extract(p, t.read_tree(xd), expect_type="AR", label="llvm-ar %s" % fmt)
            if fmt == "bsd":
                seeds.append(p)
                if t.tool("7z"):
                    vs_7z(t, drv, p, label="BSD ar vs 7z", skip_re=r"^(\d+\.txt|__\.SYMDEF.*)$")
    if t.tool("llvm-lib") and t.tool("clang"):
        for n in names:
            t.sh(["clang", "--target=x86_64-pc-windows-msvc", "-c", n + ".c", "-o", n + ".obj"], cwd=src)
        p = t.path("ms.lib")
        if os.path.exists(p):
            os.remove(p)
        t.sh(["llvm-lib", "/out:" + p] + [n + ".obj" for n in names], cwd=src)
        expl = {n + ".obj": open(os.path.join(src, n + ".obj"), "rb").read() for n in names}
        r, rows, out = t.extract(p)
        got = {os.path.basename(v[3]): open(os.path.join(out, "%d.bin" % k), "rb").read() for k, v in rows.items() if v[0] == 0}
        t.record(got == expl, "MS .lib (linker members hidden, NUL long names)", repr(sorted(got)))
        seeds.append(p)
    # GNU thin-free archive with duplicate member names (ar q)
    p = t.path("dup.a")
    if os.path.exists(p):
        os.remove(p)
    t.sh(["ar", "q", p, "a.o", "b.o", "a.o"], cwd=src)
    r, rows, out = t.extract(p)
    t.record(sorted(v[3] for v in rows.values()) == ["a.o", "a.o", "b.o"], "ar duplicate names", repr(rows))

    # Debian packages
    if t.tool("dpkg-deb"):
        d = os.path.join(t.work, "deb_root")
        shutil.rmtree(d, ignore_errors=True)
        t.write_tree(d, {"DEBIAN/control": b"Package: gogit-test\nVersion: 1.0\nArchitecture: all\nMaintainer: t <t@t>\nDescription: t\n",
                         "usr/share/doc/gogit-test/README": blob(20000, 7, True),
                         "usr/bin/tool": blob(5000, 8)})
        for z in ("gzip", "xz", "zstd", "none"):
            p = t.path("pkg_%s.deb" % z)
            r = t.sh(["dpkg-deb", "--root-owner-group", "-Z" + z, "--build", d, p], check=False)
            if r.returncode:
                t.record(True, "dpkg-deb -Z%s unsupported" % z)
                continue
            ref = os.path.join(t.work, "deb_ar_" + z)
            shutil.rmtree(ref, ignore_errors=True)
            os.makedirs(ref)
            t.sh(["ar", "x", p], cwd=ref)
            exp = t.read_tree(ref)
            t.check_extract(p, exp, expect_type="DEB", label="deb -Z%s" % z)
            r, rows, out = t.extract(p)
            first = rows.get(0, (0, 0, 0, ""))[3]
            t.record(first == "debian-binary" and set(exp) == {v[3] for v in rows.values()}, "deb -Z%s members" % z, repr(rows))
            if z == "gzip":
                seeds.append(p)
                # the data tarball opens as an archive of its own
                inner = [k for k in exp if k.startswith("data.tar")][0]
                ip = t.path("deb_inner_" + inner)
                open(ip, "wb").write(exp[inner])
                t.check_extract(ip, {"usr/share/doc/gogit-test/README": blob(20000, 7, True), "usr/bin/tool": blob(5000, 8)},
                                allow_extra=True, label="deb data.tar.gz nested")

    # hostile
    hs = []
    def hostile(name, b):
        p = t.path("hostile", name)
        open(p, "wb").write(b)
        hs.append(p)
        return t.check_hostile(p, label="hostile ar " + name)
    def mh(name, size, mode=b"644", fmag=b"`\n"):
        return name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + mode.ljust(8) + size.ljust(10) + fmag
    hostile("size_huge.a", b"!<arch>\n" + mh(b"a.o/", b"9999999999") + b"x" * 100)
    hostile("size_junk.a", b"!<arch>\n" + mh(b"a.o/", b"12x") + b"x" * 100)
    hostile("longname_oob.a", b"!<arch>\n" + mh(b"//", b"4") + b"ab/\n" + mh(b"/99999", b"2") + b"xy")
    hostile("longname_noterm.a", b"!<arch>\n" + mh(b"//", b"4") + b"abcd" + mh(b"/2", b"2") + b"xy")
    hostile("bsd_name_huge.a", b"!<arch>\n" + mh(b"#1/99999", b"10") + b"x" * 10)
    hostile("bad_fmag.a", b"!<arch>\n" + mh(b"a.o/", b"2", fmag=b"XX") + b"xy")
    hostile("trunc.a", open(t.path("gnu.a"), "rb").read()[:200])
    p = t.path("hostile", "bsd_name_huge.a")
    r, rows = status_of(t, p)
    t.record(r.stdout.startswith(b"OPEN_ERROR"), "ar BSD name longer than member", r.stdout[-80:])
    return seeds, hs

# ---------------------------------------------------------------- RPM

SPEC = r"""
Name: gogit-test
Version: 1.2
Release: 3
Summary: test package for gogitzip
License: MIT
BuildArch: noarch
%description
test package
%install
mkdir -p %{buildroot}/usr/share/gogit/sub %{buildroot}/usr/bin %{buildroot}/usr/share/gogit/empty
cp -a SRCDIR/. %{buildroot}/usr/share/gogit/sub/
ln -s ../share/gogit/a.txt %{buildroot}/usr/bin/link
printf 'hello rpm\n' > %{buildroot}/usr/share/gogit/a.txt
ln %{buildroot}/usr/share/gogit/a.txt %{buildroot}/usr/share/gogit/hard.txt
chmod 0750 %{buildroot}/usr/share/gogit/sub/big.bin
touch -d @1500000000 %{buildroot}/usr/share/gogit/a.txt
%files
/usr/share/gogit
/usr/bin/link
"""

def rpm_build(t, payload, src):
    top = os.path.join(t.work, "rpmtop_" + payload.replace(".", "_"))
    shutil.rmtree(top, ignore_errors=True)
    for d in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS", "BUILDROOT"):
        os.makedirs(os.path.join(top, d))
    spec = os.path.join(top, "SPECS/t.spec")
    open(spec, "w").write(SPEC.replace("SRCDIR", src))
    r = t.sh(["rpmbuild", "--define", "_topdir " + top, "--define", "_binary_payload " + payload,
              "--define", "__os_install_post %{nil}", "--define", "_build_id_links none",
              "--define", "_source_date_epoch_from_changelog 0", "-bb", spec], check=False, timeout=300)
    f = glob.glob(os.path.join(top, "RPMS/noarch/*.rpm"))
    if r.returncode or not f:
        return None
    dst = t.path("pkg_%s.rpm" % payload.split(".")[1])
    shutil.move(f[0], dst)
    shutil.rmtree(top, ignore_errors=True)
    return dst

def stream_ok(t, data, ext):
    """True when the stream format for ext is registered in this build (gzt opens it)."""
    p = t.path("probe." + ext)
    open(p, "wb").write(data)
    r = t.run_gzt(["l", p])
    return r.returncode == 0 and not r.stdout.startswith(b"OPEN_ERROR")

def test_rpm(t, drv):
    if not t.tool("rpmbuild"):
        return [], []
    src = os.path.join(t.work, "rpm_src")
    t.write_tree(src, {"big.bin": blob(1 << 20, 21, True), "rand.bin": blob(100000, 22), "한글 이름.txt": "고기".encode() * 99,
                       "d/e/f.txt": b"deep\n", "zero.txt": b""})
    have_xz = stream_ok(t, lzma.compress(b"x" * 100), "xz")
    have_lzma = stream_ok(t, lzma.compress(b"x" * 100, format=lzma.FORMAT_ALONE), "lzma")
    seeds = []
    for payload, method in (("w9.gzdio", "Deflate"), ("w9.bzdio", "BZip2"), ("w19.zstdio", "Zstd"),
                            ("w0.ufdio", "Store"), ("w6.xzdio", None), ("w6.lzdio", None)):
        p = rpm_build(t, payload, src)
        if not p:
            t.record(True, "rpmbuild %s unsupported here" % payload)
            continue
        kind = payload.split(".")[1]
        avail = {"xzdio": have_xz, "lzdio": have_lzma}.get(kind, True)
        if not avail:
            r = t.run_gzt(["l", p])
            t.record(r.stdout.startswith(b"OPEN_ERROR %d" % E_METHOD), "rpm %s without codec: GZ_E_METHOD" % kind, r.stdout[-80:])
            continue
        if t.tool("bsdtar"):
            vs_bsdtar(t, drv, p, label="rpm %s vs bsdtar" % kind, expect_type="RPM")
        typ, rows, comment = dump(t, drv, p)
        okc = "gogit-test-1.2-3.noarch" in comment and "test package for gogitzip" in comment
        t.record(okc, "rpm %s comment" % kind, comment.strip()[:120])
        hl = [r for r in rows if r["kind"] == "h"]
        sl = [r for r in rows if r["kind"] == "l"]
        mt = [r for r in rows if r["name"].endswith("gogit/a.txt") or r["name"].endswith("gogit/hard.txt")]
        t.record(len(hl) == 1 and len(sl) == 1 and sl[0]["link"] == "../share/gogit/a.txt" and
                 all(m["mtime"] == 1500000000 for m in mt), "rpm %s links/mtime" % kind, repr(hl + sl))
        if method:
            r = t.run_gzt(["l", p])
            t.record(("\t%s\t" % method).encode() in r.stdout, "rpm %s method column" % kind, r.stdout[:200])
        if kind in ("gzdio", "zstdio", "ufdio"):
            seeds.append(p)
        if kind == "gzdio":
            r = t.sh([drv, "threads", p], check=False)
            t.record(r.returncode == 0 and b"ok" in r.stdout, "rpm 4 threads", r.stdout.decode()[-200:])
    # hostile RPMs (made from the gzip one)
    hs = []
    base = t.path("pkg_gzdio.rpm")
    if os.path.exists(base):
        b = bytearray(open(base, "rb").read())
        def hostile(name, data):
            p = t.path("hostile", name)
            open(p, "wb").write(bytes(data))
            hs.append(p)
            return t.check_hostile(p, label="hostile rpm " + name)
        x = bytearray(b); x[96 + 8:96 + 12] = b"\xff\xff\xff\xff"; hostile("sig_il.rpm", x)
        x = bytearray(b); x[96 + 12:96 + 16] = b"\x7f\xff\xff\xff"; hostile("sig_dl.rpm", x)
        il, dl = struct.unpack(">II", b[96 + 8:96 + 16])
        h2 = (96 + 16 + il * 16 + dl + 7) & ~7
        x = bytearray(b); x[h2 + 8:h2 + 12] = b"\x00\x00\xff\xff"; hostile("hdr_il.rpm", x)
        x = bytearray(b); x[h2 + 12:h2 + 16] = b"\x0f\xff\xff\xff"; hostile("hdr_dl.rpm", x)
        # index entries pointing outside the data store
        x = bytearray(b)
        hil = struct.unpack(">I", b[h2 + 8:h2 + 12])[0]
        for k in range(hil):
            o = h2 + 16 + k * 16
            x[o + 8:o + 12] = struct.pack(">I", 0x7FFFFFF0 + k)
        hostile("hdr_offsets.rpm", x)
        hostile("trunc_payload.rpm", b[:len(b) - 50000])
        hostile("trunc_header.rpm", b[:h2 + 40])
        r = t.run_gzt(["l", t.path("hostile", "sig_il.rpm")])
        t.record(r.stdout.startswith(b"OPEN_ERROR %d" % E_LIMIT), "rpm huge tag count: GZ_E_LIMIT", r.stdout[-60:])
    return seeds, hs

# ---------------------------------------------------------------- XAR

def xar_build(files, toc_ck="sha1", heap_prefix=b"", corrupt_toc_ck=False, extra=b"", header_alg=None, raw_toc=None):
    """files: nested list of dicts: name, type (file/directory/symlink/hardlink/fifo), data, enc
    (gzip/bzip2/none/xz/lzma), ck (sha1/sha256/md5/none), mode, mtime, link (symlink target or
    hardlink ref id / "original"), b64 (base64 name), children. Returns the archive bytes."""
    heap = bytearray()
    cklen = {"sha1": 20, "sha256": 32, "md5": 16}.get(toc_ck, 0)
    heap += b"\0" * cklen + heap_prefix
    ids = [0]
    def esc(s):
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    def dig(kind, d):
        return {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "md5": hashlib.md5}[kind](d).hexdigest()
    def node(f):
        ids[0] += 1
        fid = f.get("id", ids[0])
        x = '<file id="%d">' % fid
        if f.get("b64"):
            x += '<name enctype="base64">%s</name>' % base64.b64encode(f["name"].encode()).decode()
        else:
            x += "<name>%s</name>" % esc(f["name"])
        ty = f.get("type", "file")
        if ty == "hardlink":
            x += '<type link="%s">hardlink</type>' % f["link"]
        else:
            x += "<type>%s</type>" % ty
        if ty == "symlink":
            x += '<link type="file">%s</link>' % esc(f["link"])
        x += "<mode>%04o</mode>" % f.get("mode", 0o755 if ty == "directory" else 0o644)
        if "mtime" in f:
            x += "<mtime>%s</mtime>" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(f["mtime"]))
        if "data" in f:
            d = f["data"]
            enc = f.get("enc", "gzip")
            z = {"gzip": lambda b: zlib.compress(b, 9), "bzip2": bz2.compress, "none": lambda b: b,
                 "xz": lambda b: lzma.compress(b), "lzma": lambda b: lzma.compress(b, format=lzma.FORMAT_ALONE)}[enc](d)
            if f.get("garble"):
                z = bytearray(z); z[len(z) // 2] ^= 0x55; z = bytes(z)
            style = {"gzip": "application/x-gzip", "bzip2": "application/x-bzip2", "none": "application/octet-stream",
                     "xz": "application/x-xz", "lzma": "application/x-lzma"}[enc]
            ck = f.get("ck", "sha1")
            off = len(heap)
            heap.extend(z)
            x += "<data><length>%d</length><offset>%d</offset><size>%d</size>" % (
                f.get("length", len(z)), f.get("offset", off), f.get("size", len(d)))
            x += '<encoding style="%s"/>' % style
            if ck != "none":
                x += '<archived-checksum style="%s">%s</archived-checksum>' % (ck, dig(ck, z))
                x += '<extracted-checksum style="%s">%s</extracted-checksum>' % (ck, f.get("digest", dig(ck, d)))
            x += "</data>"
        for c in f.get("children", []):
            x += node(c)
        return x + "</file>\n"
    body = "".join(node(f) for f in files)
    cks = '<checksum style="%s"><offset>0</offset><size>%d</size></checksum>' % (toc_ck, cklen) if cklen else ""
    toc = ('<?xml version="1.0" encoding="UTF-8"?>\n<xar>\n <toc>\n  <creation-time>2024-01-01T00:00:00</creation-time>\n'
           '  %s\n%s </toc>\n</xar>\n' % (cks, body)).encode() if raw_toc is None else raw_toc
    ztoc = zlib.compress(toc, 9)
    if cklen:
        d = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "md5": hashlib.md5}[toc_ck](ztoc).digest()
        if corrupt_toc_ck:
            d = bytes([d[0] ^ 1]) + d[1:]
        heap[0:cklen] = d
    alg = header_alg if header_alg is not None else {"sha1": 1, "md5": 2}.get(toc_ck, 3 if cklen else 0)
    return struct.pack(">4sHHQQI", b"xar!", 28, 1, len(ztoc), len(toc), alg) + ztoc + bytes(heap) + extra

def pbzx(data, chunk=65536, xz=True):
    out = bytearray(b"pbzx" + struct.pack(">Q", 1 << 24))
    pos = 0
    while True:
        c = data[pos:pos + chunk]
        pos += len(c)
        more = pos < len(data)
        z = lzma.compress(c, check=lzma.CHECK_NONE) if xz else c
        out += struct.pack(">QQ", len(c) | ((1 << 24) if more else 0), len(z)) + z
        if not more:
            return bytes(out)

def test_xar(t, drv):
    seeds, hs = [], []
    root = make_src(t, "xar_src", big=False)
    ref = ref_tree(root)
    ref.pop("fifo", None)
    if t.tool("bsdtar"):
        for comp in ("gzip", "bzip2", "none", "xz", "lzma"):
            for ck in ("sha1", "md5", "none"):
                if comp in ("xz", "lzma") and ck != "sha1":
                    continue
                p = t.path("bt_%s_%s.xar" % (comp, ck))
                if os.path.exists(p):
                    os.remove(p)
                r = t.sh(["bsdtar", "--format", "xar", "--options", "xar:compression=%s,xar:checksum=%s" % (comp, ck),
                          "-cf", p] + sorted(os.listdir(root)), cwd=root, check=False)
                if r.returncode:
                    t.record(True, "bsdtar xar %s unsupported" % comp)
                    continue
                if comp in ("xz", "lzma") and not stream_ok(t, lzma.compress(b"x" * 100) if comp == "xz" else
                                                           lzma.compress(b"x" * 100, format=lzma.FORMAT_ALONE), comp):
                    r, rows = status_of(t, p)
                    st = {v[3]: v[0] for v in rows.values() if not v[1]}
                    t.record(st.get("문서/보고서.txt") == E_METHOD and st.get("empty.txt") == 0,
                             "xar %s without codec: GZ_E_METHOD" % comp, repr(st)[:200])
                    continue
                verify(t, drv, p, ref, label="bsdtar xar %s/%s" % (comp, ck), expect_type="XAR")
                if comp == "gzip" and ck == "sha1":
                    seeds.append(p)
                    r = t.sh([drv, "threads", p], check=False)
                    t.record(r.returncode == 0 and b"ok" in r.stdout, "xar 4 threads", r.stdout.decode()[-200:])

    # Python-made XAR: every encoding and checksum, base64 / escaped names, hard links
    big = blob(600000, 31, True)
    files = [
        {"name": "z.txt", "data": b"zlib " * 999, "enc": "gzip", "mtime": 1234567890},
        {"name": "b.bin", "data": blob(70000, 32), "enc": "bzip2", "ck": "sha256", "mode": 0o600},
        {"name": "n.bin", "data": blob(5000, 33), "enc": "none", "ck": "md5"},
        {"name": "big.txt", "data": big, "enc": "gzip"},
        {"name": "empty", "data": b"", "enc": "none"},
        {"name": "nodata.txt"},
        {"name": "a & b <c>.txt", "data": b"esc", "enc": "none"},
        {"name": "base64 이름.txt", "b64": True, "data": "한글".encode(), "enc": "gzip"},
        {"name": "dir", "type": "directory", "mtime": 1500000000, "children": [
            {"name": "sub", "type": "directory", "children": [
                {"name": "deep.txt", "data": b"deep", "enc": "bzip2", "id": 77, "type": "hardlink", "link": "original"}]},
            {"name": "sl", "type": "symlink", "link": "../z.txt"},
            {"name": "hl", "type": "hardlink", "link": "77"},
            {"name": "hl_missing", "type": "hardlink", "link": "999"},
            {"name": "pipe", "type": "fifo"},
        ]},
    ]
    exp = {"z.txt": b"zlib " * 999, "b.bin": blob(70000, 32), "n.bin": blob(5000, 33), "big.txt": big, "empty": b"",
           "nodata.txt": b"", "a & b <c>.txt": b"esc", "base64 이름.txt": "한글".encode(), "dir/sub/deep.txt": b"deep",
           "dir/hl_missing": b""}
    for ck in ("sha1", "sha256", "md5", "none"):
        p = t.path("py_%s.xar" % ck)
        open(p, "wb").write(xar_build(files, toc_ck=ck))
        t.check_extract(p, exp, allow_extra=True, expect_type="XAR", label="py xar toc %s" % ck)
    p = t.path("py_sha1.xar")
    seeds.append(p)
    typ, rows, _ = dump(t, drv, p)
    by = {r["name"]: r for r in rows}
    okm = (by.get("dir/hl", {}).get("kind") == "h" and by["dir/hl"]["link"] == "dir/sub/deep.txt" and
           by.get("dir/sl", {}).get("link") == "../z.txt" and by.get("z.txt", {}).get("mtime") == 1234567890 and
           by.get("dir", {}).get("mtime") == 1500000000 and (by.get("b.bin", {}).get("mode", 0) & 0o777) == 0o600 and
           "dir/pipe" not in by)
    t.record(okm, "py xar metadata (hard link, symlink, mtime, mode, fifo hidden)", repr(sorted(by))[:300])
    r = t.run_gzt(["l", p])
    t.record(b"\tBZip2\t" in r.stdout and b"\tDeflate\t" in r.stdout and b"\tStore\t" in r.stdout, "xar method column", r.stdout[:300])
    # 7-Zip's XAR reader rejects links and fifos: compare it on plain trees
    if t.tool("7z"):
        plain = [f for f in files if f.get("type", "file") == "file" and "data" in f and f["name"].isascii() and
                 not f.get("b64") and "&" not in f["name"]] + \
                [{"name": "dir", "type": "directory", "children": [{"name": "x.bin", "data": blob(9000, 34), "enc": "bzip2"}]}]
        p7 = t.path("py_plain.xar")
        open(p7, "wb").write(xar_build(plain))
        vs_7z(t, drv, p7, label="py xar vs 7z", skip_re=r"^\[TOC\]\.xml$")
        if t.tool("bsdtar"):
            # ASCII names: 7-Zip neither decodes base64 names (bsdtar's choice for UTF-8) nor entities
            proot7 = t.write_tree(os.path.join(t.work, "xar_plain_src"), {"a.txt": blob(5000, 61, True),
                                  "d/b.bin": blob(70000, 62), "d/e/c.txt": b"c" * 999, "empty": b""})
            for comp in ("gzip", "bzip2", "none"):
                p7 = t.path("bt_plain_%s.xar" % comp)
                if os.path.exists(p7):
                    os.remove(p7)
                t.sh(["bsdtar", "--format", "xar", "--options", "xar:compression=" + comp, "-cf", p7] +
                     sorted(os.listdir(proot7)), cwd=proot7)
                vs_7z(t, drv, p7, label="bsdtar xar %s vs 7z" % comp, skip_re=r"^\[TOC\]\.xml$")

    # bad file checksum, bad data, size mismatch, TOC checksum mismatch
    bad = [{"name": "ok.txt", "data": b"fine", "enc": "gzip"},
           {"name": "badsum.txt", "data": b"x" * 1000, "enc": "gzip", "digest": "00" * 20},
           {"name": "garbled.txt", "data": b"y" * 5000, "enc": "gzip", "garble": True},
           {"name": "garbled.bz2", "data": b"y" * 5000, "enc": "bzip2", "garble": True},
           {"name": "toolong.txt", "data": b"z" * 3000, "enc": "gzip", "size": 100, "ck": "none"},
           {"name": "tooshort.txt", "data": b"z" * 3000, "enc": "none", "size": 5000, "length": 3000, "ck": "none"},
           {"name": "past_eof.txt", "data": b"q" * 10, "enc": "none", "offset": 1 << 40, "ck": "none"}]
    p = t.path("bad.xar")
    open(p, "wb").write(xar_build(bad))
    r, rows = status_of(t, p)
    st = {v[3]: v[0] for v in rows.values()}
    want = {"ok.txt": 0, "badsum.txt": E_CRC, "toolong.txt": E_DATA, "tooshort.txt": E_DATA, "past_eof.txt": E_TRUNC}
    okb = all(st.get(k) == v for k, v in want.items()) and st.get("garbled.txt", 0) != 0 and st.get("garbled.bz2", 0) != 0
    t.record(okb, "xar per-file errors", repr(st))
    hs.append(p)
    p = t.path("bad_tocck.xar")
    open(p, "wb").write(xar_build(files, corrupt_toc_ck=True))
    r = t.run_gzt(["l", p])
    t.record(r.stdout.startswith(b"OPEN_ERROR %d" % E_CRC), "xar TOC checksum mismatch", r.stdout[-60:])

    # macOS .pkg layout: Payload (cpio odc, gzip or pbzx), Scripts, Bom, PackageInfo, Distribution
    proot = make_src(t, "pkg_payload", big=False)
    pref = ref_tree(proot)
    pref.pop("fifo", None)
    odc = cpio_create(t, proot, "odc", t.path("payload.cpio"))
    odc_b = open(odc, "rb").read()
    scripts = newc([("postinstall", b"#!/bin/sh\nexit 0\n", 0o100755, {})])
    payload_gz, scripts_gz = gzip.compress(odc_b, mtime=0), gzip.compress(scripts, mtime=0)
    pkg = [{"name": "Distribution", "data": b"<?xml version='1.0'?><installer-gui-script/>", "enc": "gzip"},
           {"name": "Resources", "type": "directory", "children": [{"name": "en.lproj", "type": "directory"}]},
           {"name": "gogit.pkg", "type": "directory", "children": [
               {"name": "PackageInfo", "data": b"<pkg-info/>", "enc": "gzip"},
               {"name": "Bom", "data": blob(3000, 41), "enc": "gzip"},
               {"name": "Payload", "data": payload_gz, "enc": "none"},
               {"name": "Scripts", "data": scripts_gz, "enc": "none"}]}]
    p = t.path("gogit.pkg")
    open(p, "wb").write(xar_build(pkg))
    t.check_extract(p, {"gogit.pkg/Payload": payload_gz, "gogit.pkg/Scripts": scripts_gz,
                        "Distribution": b"<?xml version='1.0'?><installer-gui-script/>"}, allow_extra=True,
                    expect_type="XAR", label=".pkg members")
    seeds.append(p)
    pl = t.path("pkg_Payload")
    open(pl, "wb").write(payload_gz)
    verify(t, drv, pl, pref, label=".pkg Payload (cpio.gz) nested", expect_type="CPIO.GZ")
    ps = t.path("pkg_Scripts")
    open(ps, "wb").write(scripts_gz)
    t.check_extract(ps, {"postinstall": b"#!/bin/sh\nexit 0\n"}, label=".pkg Scripts nested", expect_type="CPIO.GZ")
    # pbzx payloads (stored chunks always work; xz chunks need the xz stream format)
    p = t.path("Payload_pbzx_raw")
    open(p, "wb").write(pbzx(odc_b, chunk=50000, xz=False))
    verify(t, drv, p, pref, label="pbzx stored chunks", expect_type="CPIO.PBZX")
    seeds.append(p)
    p = t.path("Payload_pbzx_xz")
    open(p, "wb").write(pbzx(odc_b, chunk=50000, xz=True))
    if stream_ok(t, lzma.compress(b"x" * 100), "xz"):
        verify(t, drv, p, pref, label="pbzx xz chunks", expect_type="CPIO.PBZX")
    else:
        r = t.run_gzt(["l", p])
        t.record(r.stdout.startswith(b"OPEN_ERROR"), "pbzx xz chunks without xz: error", r.stdout[-60:])
    p = t.path("raw.pbzx")
    rawd = blob(200000, 42, True)
    open(p, "wb").write(pbzx(rawd, chunk=30000, xz=False))
    t.check_extract(p, [("raw", rawd)], label="pbzx single file", expect_type="PBZX")

    # hostile TOCs
    def hostile(name, data, label=None):
        p = t.path("hostile", name)
        open(p, "wb").write(data)
        hs.append(p)
        return t.check_hostile(p, label=label or "hostile xar " + name)
    deep = b"<xar><toc>" + b'<file id="1"><name>d</name><type>directory</type>' * 20000 + b"</file>" * 20000 + b"</toc></xar>"
    hostile("deep.xar", xar_build([], toc_ck="none", raw_toc=deep))
    r = t.run_gzt(["l", t.path("hostile", "deep.xar")])
    t.record(r.stdout.startswith(b"OPEN_ERROR %d" % E_LIMIT), "xar XML depth limit", r.stdout[-60:])
    hostile("unbalanced.xar", xar_build([], toc_ck="none", raw_toc=b"<xar><toc><file><name>a</name></toc></xar>"))
    hostile("unterminated.xar", xar_build([], toc_ck="none", raw_toc=b"<xar><toc><file id=\"1\"><name>a"))
    hostile("attr_junk.xar", xar_build([], toc_ck="none", raw_toc=b"<xar><toc><file id=1><name>a</name></file></toc></xar>"))
    hostile("entities.xar", xar_build([], toc_ck="none", raw_toc=b"<xar><toc><file id='1'><name>&#0;&#xD800;&#99999999;&bogus;&amp</name>"
                                      b"<type>file</type><data><offset>0</offset><length>5</length><size>5</size></data></file></toc></xar>"))
    hostile("numbers.xar", xar_build([], toc_ck="none", raw_toc=b"<xar><toc><file id='99999999999999999999'><name>n</name>"
                                     b"<type link='x'>hardlink</type><mode>9999</mode><mtime>9999-99-99T99:99:99Z</mtime>"
                                     b"<data><offset>18446744073709551615</offset><length>18446744073709551615</length>"
                                     b"<size>99999999999999999999999</size><encoding style='application/x-bzip2'/>"
                                     b"<extracted-checksum style='sha1'>zz</extracted-checksum></data></file></toc></xar>"))
    hostile("selflink.xar", xar_build([{"name": "a", "type": "hardlink", "link": "1", "id": 1}], toc_ck="none"))
    many = b"<xar><toc>" + b"".join(b'<file id="%d"><name>f%d</name><type>file</type></file>' % (i, i) for i in range(1, 30001)) + b"</toc></xar>"
    p = t.path("hostile", "many.xar")
    open(p, "wb").write(xar_build([], toc_ck="none", raw_toc=many))
    t0 = time.time()
    r = t.run_gzt(["l", p])
    t.record(r.stdout.count(b"\n") == 30001 and time.time() - t0 < 20, "xar 30000 files listing", "%.2fs" % (time.time() - t0))
    hb = bytearray(xar_build(files))
    hb[8:16] = struct.pack(">Q", 1 << 50)
    hostile("toc_huge.xar", bytes(hb))
    hb = bytearray(xar_build(files))
    hb[16:24] = struct.pack(">Q", 1 << 40)
    hostile("toc_usize_huge.xar", bytes(hb))
    hb = bytearray(xar_build(files))
    hb[16:24] = struct.pack(">Q", 10)
    hostile("toc_usize_small.xar", bytes(hb))
    # decompression bomb: the TOC inflates far beyond its declared size
    bz = zlib.compress(b"<xar><toc>" + b" " * (16 << 20) + b"</toc></xar>", 9)
    hostile("toc_bomb.xar", struct.pack(">4sHHQQI", b"xar!", 28, 1, len(bz), 1 << 20, 0) + bz)
    r = t.run_gzt(["l", t.path("hostile", "toc_bomb.xar")])
    t.record(r.stdout.startswith(b"OPEN_ERROR %d" % E_LIMIT), "xar TOC bomb: GZ_E_LIMIT", r.stdout[-60:])
    hostile("trunc.xar", xar_build(files)[:300])

    # XML-level fuzzing: mutate the plain TOC (the in-process fuzzer mostly hits its zlib stream)
    small = [f for f in files if f["name"] != "big.txt"]
    base = xar_build(small, toc_ck="none")
    hs0, = struct.unpack(">H", base[4:6])
    zl, = struct.unpack(">Q", base[8:16])
    toc = zlib.decompress(base[hs0:hs0 + zl])
    heap = base[hs0 + zl:]
    rnd = random.Random(7)
    fz = os.path.join(t.work, "xmlfuzz")
    shutil.rmtree(fz, ignore_errors=True)
    os.makedirs(fz)
    for i in range(int(os.environ.get("GZ_FUZZ_ITERS", "120")) * 2):
        x = bytearray(toc)
        for _ in range(rnd.randint(1, 4)):
            k, pos = rnd.randrange(6), rnd.randrange(len(x))
            if k == 0:
                x[pos] = rnd.choice(b'<>/="&;#x0123456789 ')
            elif k == 1:
                del x[pos:pos + rnd.randint(1, 64)]
            elif k == 2:
                q = rnd.randrange(len(x))
                x[pos:pos] = x[q:q + rnd.randint(1, 200)]
            elif k == 3:
                x[pos:pos] = rnd.choice([b"<file>", b"</file>", b"<data>", b"<!--", b"<![CDATA[", b"&#x110000;",
                                         b'<name enctype="base64">', b"18446744073709551616"])
            elif k == 4:
                m = x.find(b"<offset>", pos)
                if m > 0:
                    x[m + 8:m + 8] = str(rnd.choice([0, 1, 2 ** 31, 2 ** 32, 2 ** 63, 2 ** 64 - 1])).encode()
            else:
                x[pos] ^= 1 << rnd.randrange(8)
        z = zlib.compress(bytes(x))
        b = struct.pack(">4sHHQQI", b"xar!", 28, 1, len(z), len(x), 0) + z + heap
        open(os.path.join(fz, "m%04d.xar" % i), "wb").write(b)
    r = t.sh([drv, "many"] + sorted(glob.glob(os.path.join(fz, "*.xar"))), check=False, timeout=600)
    err = r.stderr.decode(errors="replace")
    t.record(r.returncode == 0 and "Sanitizer" not in err and "runtime error" not in err,
             "xar TOC XML mutations", (r.stdout.decode()[-80:] + err[-400:]).strip())
    shutil.rmtree(fz, ignore_errors=True)
    return seeds, hs

# ---------------------------------------------------------------- split volumes

def test_split(t, drv):
    seeds, hs = [], []
    W = os.path.join(t.work, "split")
    shutil.rmtree(W, ignore_errors=True)
    os.makedirs(W)
    files = {"a.txt": b"hello split\n" * 5000, "d/rand.bin": blob(250000, 51), "d/e.txt": b"e" * 33}
    src = t.write_tree(os.path.join(W, "src"), files)
    if t.tool("7z"):
        t.sh(["7z", "a", "-tzip", "-v70k", os.path.join(W, "s.zip"), "a.txt", "d"], cwd=src)
        p = os.path.join(W, "s.zip.001")
        t.check_extract(p, files, expect_type="ZIP (Split)", label="7z -v zip.001")
        seeds.append(p)
        t.sh(["7z", "a", "-v100k", os.path.join(W, "s.7z"), "a.txt", "d"], cwd=src)
        p = os.path.join(W, "s.7z.001")
        parts = sorted(glob.glob(os.path.join(W, "s.7z.[0-9][0-9][0-9]")))
        whole = b"".join(open(x, "rb").read() for x in parts)
        typ, rows, _ = dump(t, drv, p)
        if typ == "7z (Split)":
            t.check_extract(p, files, label="7z -v 7z.001")
        else:
            t.check_extract(p, [("s.7z", whole)], expect_type="Split", label="7z -v 7z.001 joined (no 7z reader)")
        r = t.run_gzt(["l", p], {"GZ_NO_DESCEND": "1"})
        t.record(b"TYPE\tSplit\t1" in r.stdout and b"Split:%d" % len(parts) in r.stdout, "split no descend", r.stdout[:200])
        # a lone .001 (single-volume 7z -v output) opens as what it is
        t.sh(["7z", "a", "-tzip", "-v10m", os.path.join(W, "one.zip"), "a.txt"], cwd=src)
        t.check_extract(os.path.join(W, "one.zip.001"), {"a.txt": files["a.txt"]}, expect_type="ZIP", label="lone .001")
    tar = os.path.join(W, "s.tar")
    t.sh(["tar", "cf", tar, "a.txt", "d"], cwd=src)
    tb = open(tar, "rb").read()
    # split -d: 4 parts, the last one shorter
    t.sh(["split", "-b", "60000", "-d", "-a", "3", "--numeric-suffixes=1", tar, tar + "."])
    p = tar + ".001"
    t.check_extract(p, files, expect_type="TAR (Split)", label="split tar.001")
    seeds.append(p)
    r = t.sh([drv, "threads", p], check=False)
    t.record(r.returncode == 0 and b"ok" in r.stdout, "split 4 threads", r.stdout.decode()[-200:])
    # a cut cpio (no TRAILER!!!) must not open alone
    cp = cpio_create(t, src, "newc", os.path.join(W, "s.cpio"))
    t.sh(["split", "-b", "70000", "-d", "-a", "3", "--numeric-suffixes=1", cp, cp + "."])
    t.check_extract(cp + ".001", files, expect_type="CPIO (Split)", label="split cpio.001")
    # parts of exactly equal size (the set ends when the next part is missing)
    eq = os.path.join(W, "eq.bin")
    data = blob(4 * 32768, 52)
    for i in range(4):
        open(eq + ".%03d" % (i + 1), "wb").write(data[i * 32768:(i + 1) * 32768])
    t.check_extract(eq + ".001", [("eq.bin", data)], expect_type="Split", label="split equal parts")
    # 4-digit suffixes
    q = os.path.join(W, "four.dat")
    for i in range(3):
        open(q + ".%04d" % (i + 1), "wb").write(data[i * 50000:(i + 1) * 50000])
    t.check_extract(q + ".0001", [("four.dat", data[:150000])], expect_type="Split", label="split .0001")
    # ISO split for FAT32: the first part alone must not open as a short ISO
    if t.tool("genisoimage"):
        iso = os.path.join(W, "cd.iso")
        t.sh(["genisoimage", "-quiet", "-R", "-J", "-o", iso, src])
        t.sh(["split", "-b", "100000", "-d", "-a", "3", "--numeric-suffixes=1", iso, iso + "."])
        t.check_extract(iso + ".001", files, expect_type="ISO (Split)", label="split iso.001")
    # missing middle part: only the parts before it
    mm = os.path.join(W, "mm.bin")
    for i in (1, 2, 4):
        open(mm + ".%03d" % i, "wb").write(data[(i - 1) * 32768:i * 32768])
    t.check_extract(mm + ".001", [("mm.bin", data[:65536])], expect_type="Split", label="split missing part")
    # .002 alone or .000 are not a set start
    r = t.run_gzt(["l", tar + ".002"])
    t.record(b"Split" not in r.stdout, "split .002 is no set start", r.stdout[:80])
    return seeds, hs

# ---------------------------------------------------------------- real packages (optional download)

REAL = [
    # (file, url, reference tool): read-only test data, cached in the work directory
    ("hello.fc43.rpm", "https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Everything/x86_64/os/Packages/h/"
                       "hello-2.12.2-2.fc43.x86_64.rpm", "bsdtar"),
    ("hello_debian.deb", "http://deb.debian.org/debian/pool/main/h/hello/hello_2.12.3-1_amd64.deb", "ar"),
]

def fetch(t, name, url):
    p = t.path("dl", name)
    if os.path.exists(p) and os.path.getsize(p) > 0:
        return p
    if os.environ.get("GZ_OFFLINE"):
        return None
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            data = r.read(4 << 20)
    except Exception:
        return None
    open(p, "wb").write(data)
    return p

def test_real(t, drv):
    seeds = []
    for name, url, ref in REAL:
        p = fetch(t, name, url)
        if not p:
            t.record(True, "download %s skipped (offline)" % name)
            continue
        if ref == "bsdtar" and t.tool("bsdtar"):
            # payload codec may be missing in this build (xz): then GZ_E_METHOD
            r = t.run_gzt(["l", p])
            if r.stdout.startswith(b"OPEN_ERROR %d" % E_METHOD):
                t.record(True, "real %s: payload codec not built in" % name)
            else:
                vs_bsdtar(t, drv, p, label="real %s vs bsdtar" % name, expect_type="RPM")
                seeds.append(p)
        elif ref == "ar":
            xd = os.path.join(t.work, "dl_ar_" + name)
            shutil.rmtree(xd, ignore_errors=True)
            os.makedirs(xd)
            t.sh(["ar", "x", p], cwd=xd)
            t.check_extract(p, t.read_tree(xd), expect_type="DEB", label="real %s" % name)
            seeds.append(p)
    return seeds, []

# ---------------------------------------------------------------- fuzz

def test_fuzz(t, drv, seeds, hostile):
    iters = int(os.environ.get("GZ_FUZZ_ITERS", "120"))
    for i, s in enumerate(seeds):
        if not s or not os.path.exists(s):
            continue
        if os.path.getsize(s) > (4 << 20):
            continue
        try:
            r = t.sh([drv, "fuzz", s, str(iters), str(i + 1)], check=False, timeout=600)
        except subprocess.TimeoutExpired:
            t.record(False, "fuzz " + os.path.basename(s), "timeout")
            continue
        err = r.stderr.decode(errors="replace")
        ok = r.returncode == 0 and b"ok" in r.stdout and "Sanitizer" not in err and "runtime error" not in err
        t.record(ok, "fuzz %s x%d" % (os.path.basename(s), iters), (r.stdout.decode()[-80:] + err[-400:]).strip())
    hostile = [h for h in hostile if os.path.exists(h)]
    if hostile:
        r = t.sh([drv, "many"] + hostile, check=False, timeout=600)
        err = r.stderr.decode(errors="replace")
        t.record(r.returncode == 0 and "Sanitizer" not in err and "runtime error" not in err,
                 "hostile set in memory (%d files)" % len(hostile), (r.stdout.decode()[-80:] + err[-400:]).strip())

def gnu_cpio():
    """GNU cpio writes crc/newc/odc/bin; BSD cpio (macOS) lacks the crc format and differs in links"""
    import subprocess as sp
    try:
        r = sp.run(["cpio", "--version"], capture_output=True, timeout=10)
    except Exception:
        return False
    return b"GNU" in r.stdout + r.stderr

def run(t):
    t.need("cpio")
    if not gnu_cpio():
        t.skip("needs GNU cpio (BSD cpio lacks -H crc)")
    drv = t.build_driver("tests/drivers/unixfmt.c")
    seeds, hs = [], []
    for fn in (test_cpio, test_ar, test_rpm, test_xar, test_split, test_real):
        s, h = fn(t, drv)
        seeds += s
        hs += h
    test_fuzz(t, drv, seeds, hs)
