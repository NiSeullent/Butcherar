"""Legacy formats and codecs: Unix compress (.Z / .taz), ARJ (methods 0-4, garble,
volumes, SFX, DOS hosts, symlinks), LZH (-lh0/1/4/5/6/7-, -lzs-, -lz5-, header
levels 0-3, extended headers, Shift-JIS names), MS SZDD / QBasic SZ / KWAJ, and
the ZIP Shrink / Implode codecs (raw streams through a C driver).

Fixtures come from the reference tools (ncompress, arj, mscompress, jlha when
installed) and from the Python encoders in _legacy_enc.py, which are checked
against independent decoders (uncompress, lhasa, 7-Zip, Info-ZIP unzip,
libmspack) before our decoders are compared with them."""
import io, os, random, shutil, struct, subprocess, sys, tarfile, zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _legacy_enc as E

WORDS = ["고기", "삼겹살", "목살", "갈비", "zip", "archive", "hello", "world", "LHA", "ARJ",
         "compress", "the", "quick", "brown", "fox", "\n", "1990", "BBS"]

def text(n, seed=1):
    rnd = random.Random(seed)
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(WORDS).encode() + b" "
    return bytes(out[:n])

def rand(n, seed=2):
    rnd = random.Random(seed)
    return bytes(rnd.getrandbits(8) for _ in range(n))

TXT = text(150000)
RND = rand(40000)
MIX = TXT[:50000] + RND[:20000] + TXT[50000:100000] + b"\0" * 3000 + TXT[:20000]

def write(t, name, data):
    p = t.path(name)
    with open(p, "wb") as f:
        f.write(data)
    return p

def corruptions(data, n=8, seed=5, header=64):
    """truncated and bit-flipped variants (flips concentrated in the header)"""
    rnd = random.Random(seed)
    out = []
    for frac in (0.02, 0.3, 0.7, 0.98):
        out.append(data[:max(1, int(len(data) * frac))])
    for k in range(n):
        b = bytearray(data)
        lim = min(len(b), header) if k % 2 == 0 else len(b)
        for _ in range(1 + k % 3):
            i = rnd.randrange(lim)
            b[i] ^= 1 << rnd.randrange(8)
        out.append(bytes(b))
    return out

def hostile_check(t, path, label):
    """t.check_hostile, but tolerating the gz_ctx that tests/gzt.c leaks when an
    archive fails to open (LeakSanitizer suppression for that one allocation)"""
    supp = os.path.join(t.work, "lsan.supp")
    if not os.path.exists(supp):
        with open(supp, "w") as f:
            f.write("leak:gz_ctx_new\n")
    env = {"LSAN_OPTIONS": "suppressions=%s:print_suppressions=0" % supp}
    try:
        r, rows, out = t.extract(path, env=env, timeout=60)
    except subprocess.TimeoutExpired:
        return t.record(False, label, "timeout")
    err = r.stderr.decode(errors="replace")
    bad = r.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err
    return t.record(not bad, label, "rc=%d %s" % (r.returncode, err[-600:] if bad else ""))

def hostile_set(t, label, data, n=8, header=64):
    for k, d in enumerate(corruptions(data, n, header=header)):
        hostile_check(t, write(t, "hostile/%s_%d.bin" % (label, k), d), "hostile %s #%d" % (label, k))

# ------------------------------------------------------------------ .Z

def section_z(t):
    files = {"txt": TXT, "rnd": RND, "mix": MIX}
    if t.tool("compress"):
        for nm, d in files.items():
            for bits in (10, 12, 13, 16):
                z = t.sh(["compress", "-f", "-b%d" % bits, "-c"], input=d, check=False).stdout   # rc 2: grew
                t.check_extract(write(t, "z/%s%d.dat.Z" % (nm, bits), z), {"%s%d.dat" % (nm, bits): d},
                                expect_type="Z", label="compress -b%d %s" % (bits, nm))
    # our encoder: -b9 (codes widen to 10 bits like compress 4.x), non-block mode, CLEAR codes
    for bits, block, ce in ((9, True, 0), (9, False, 0), (11, True, 1500), (16, False, 0), (14, True, 700)):
        z = E.compress_Z(MIX, bits, block, ce)
        ok_ref = True
        if t.tool("uncompress"):
            ok_ref = t.sh(["uncompress", "-c"], input=z, check=False).stdout == MIX
            t.record(ok_ref, "uncompress accepts encoder b%d block=%d clear=%d" % (bits, block, ce))
        name = "enc_b%d_%d_%d" % (bits, block, ce)
        t.check_extract(write(t, "z/%s.Z" % name, z), {name: MIX}, label="encoder .Z b%d block=%d clear=%d" % (bits, block, ce))
    # tarball inside: .tar.Z and .taz
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for nm, d in (("docs/한글.txt", TXT[:30000]), ("bin/r.bin", RND[:5000]), ("empty", b"")):
            ti = tarfile.TarInfo(nm); ti.size = len(d); ti.mtime = 1600000000
            tf.addfile(ti, io.BytesIO(d))
    tz = E.compress_Z(buf.getvalue(), 16)
    exp = {"docs/한글.txt": TXT[:30000], "bin/r.bin": RND[:5000], "empty": b""}
    t.check_extract(write(t, "z/a.tar.Z", tz), exp, expect_type="TAR.Z")
    t.check_extract(write(t, "z/b.taz", tz), exp, expect_type="TAR.Z")
    # edge cases: empty stream, header only, max bits out of range
    t.check_extract(write(t, "z/empty.Z", b"\x1f\x9d\x90"), {"empty": b""}, label=".Z header only")
    p = write(t, "z/badbits.Z", b"\x1f\x9d\x91" + E.compress_Z(TXT[:1000])[3:])
    r, rows, out = t.extract(p)
    t.record(r.returncode in (0, 1) and (not rows or rows[0][0] != 0), ".Z with 17 bits rejected", str(rows))
    hostile_set(t, "Z", E.compress_Z(MIX[:30000], 12, True, 400), 10)

# ------------------------------------------------------------------ ARJ

ARJ_FILES = {
    "a.txt": TXT[:100000],
    "sub/b.bin": RND[:30000],
    "sub/deep/c.txt": MIX,
    "empty.txt": b"",
    "z.txt": b"hello hello hello hello",
    "한글 이름.txt": TXT[:3000],
}

def arj_headers(data):
    """split an ARJ file into (offset, basic header bytes, ext blocks, payload) records"""
    recs = []
    p = 0
    while p + 4 <= len(data):
        assert data[p:p + 2] == b"\x60\xea"
        sz = struct.unpack_from("<H", data, p + 2)[0]
        if sz == 0:
            recs.append(("end", data[p:]))
            break
        h = data[p + 4:p + 4 + sz]
        q = p + 4 + sz + 4
        exts = []
        while True:
            es = struct.unpack_from("<H", data, q)[0]; q += 2
            if es == 0:
                break
            exts.append(data[q:q + es]); q += es + 4
        csize = struct.unpack_from("<I", h, 12)[0] if h[6] != 2 else 0
        recs.append(("hdr", h, exts, data[q:q + csize]))
        p = q + csize
    return recs

def arj_build(recs):
    out = bytearray()
    for r in recs:
        if r[0] == "end":
            out += r[1]; continue
        _, h, exts, payload = r
        out += b"\x60\xea" + struct.pack("<H", len(h)) + h + struct.pack("<I", zlib_crc(h))
        for e in exts:
            out += struct.pack("<H", len(e)) + e + struct.pack("<I", zlib_crc(e))
        out += b"\0\0" + payload
    return bytes(out)

def zlib_crc(b):
    return zlib.crc32(b) & 0xFFFFFFFF

def arj_to_dos(data, codepage):
    """rewrite a Unix-host ARJ as a DOS-host one: OS 0, DOS times, DOS attributes,
    names re-encoded in the OEM code page"""
    recs = arj_headers(data)
    out = []
    for r in recs:
        if r[0] == "end":
            out.append(r); continue
        _, h, exts, payload = r
        h = bytearray(h)
        h[3] = 0
        fhs = h[0]
        rest = bytes(h[fhs:])
        name = rest.split(b"\0")[0]
        comment = rest[len(name) + 1:].split(b"\0")[0]
        name = name.decode("utf-8").encode(codepage)
        if h[6] != 2:
            struct.pack_into("<I", h, 8, E.dos_time(2019, 12, 31, 23, 59, 58))
            struct.pack_into("<H", h, 26, 0x10 if h[6] == 3 else 0x20)
        h = bytes(h[:fhs]) + name + b"\0" + comment + b"\0"
        out.append(("hdr", h, [], payload))
    return arj_build(out)

def section_arj(t):
    if not t.tool("arj"):
        t.record(True, "arj not installed (ARJ fixtures skipped)")
        return
    src = t.write_tree(os.path.join(t.work, "arj_src"), ARJ_FILES)
    names = sorted(ARJ_FILES)
    def make(name, *opts):
        p = t.path("arj", name)
        for f in os.listdir(os.path.dirname(p)):
            if f.startswith(os.path.splitext(name)[0] + "."):
                os.remove(os.path.join(os.path.dirname(p), f))
        t.sh(["arj", "a", "-r", "-y"] + list(opts) + [p] + names, cwd=src)
        return p
    for m in range(5):
        p = make("m%d.arj" % m, "-m%d" % m)
        t.check_extract(p, ARJ_FILES, expect_type="ARJ", label="arj -m%d" % m)
        if t.tool("7z") and m:
            t.check_vs_7z(p, label="arj -m%d vs 7z" % m)
    # garbled (password) files: every method, wrong password, UTF-8 Korean password
    for m in (0, 1, 4):
        p = make("g%d.arj" % m, "-m%d" % m, "-ggogi1234")
        t.check_extract(p, ARJ_FILES, pw="gogi1234", label="arj garble -m%d" % m)
        r, rows, out = t.extract(p, pw="nope")
        bad = [st for st, isdir, size, nm in rows.values() if size and st not in (6,)]
        t.record(rows and not bad, "arj garble -m%d wrong password -> GZ_E_PASSWORD" % m, str(list(rows.values())[:4]))
        r, rows, out = t.extract(p)
        t.record(rows and all(st == 6 for st, isdir, size, nm in rows.values() if size),
                 "arj garble -m%d no password" % m, str(list(rows.values())[:3]))
    p = make("gk.arj", "-m1", "-g고기맛")
    t.check_extract(p, ARJ_FILES, pw="고기맛", label="arj garble UTF-8 Korean password")
    t.check_extract(p, ARJ_FILES, pw="고기맛", acp=949, label="arj garble Korean password, CP949 system")
    # multi-volume set with files split across volumes
    p = make("vol.arj", "-m1", "-v40k")
    vols = sorted(f for f in os.listdir(os.path.dirname(p)) if f.startswith("vol."))
    t.record(len(vols) >= 3, "arj -v40k made %d volumes" % len(vols), str(vols))
    t.check_extract(p, ARJ_FILES, label="arj multi-volume")
    os.remove(t.path("arj", "vol.a02"))
    r, rows, out = t.extract(p)
    t.record(r.returncode in (0, 1) and any(st != 0 for st, isdir, size, nm in rows.values()),
             "arj missing volume reported", str(list(rows.values())[:6]))
    # SFX stub in front
    sfx = write(t, "arj/sfx.exe", b"MZ" + rand(20000, 9).replace(b"\x60\xea", b"\x61\xea") + open(t.path("arj", "m1.arj"), "rb").read())
    t.check_extract(sfx, ARJ_FILES, label="arj SFX")
    # DOS host: OEM names (CP949 on Korean DOS, CP437 elsewhere), DOS times
    base = open(t.path("arj", "m1.arj"), "rb").read()
    t.check_extract(write(t, "arj/dos949.arj", arj_to_dos(base, "cp949")), ARJ_FILES, acp=949, label="arj DOS host CP949 names")
    lat = {"café/naïve.txt": TXT[:2000], "Größe.txt": RND[:100]}
    src2 = t.write_tree(os.path.join(t.work, "arj_src2"), lat)
    p2 = t.path("arj", "lat.arj")
    if os.path.exists(p2):
        os.remove(p2)
    t.sh(["arj", "a", "-r", "-y", p2] + sorted(lat), cwd=src2)
    t.check_extract(write(t, "arj/dos437.arj", arj_to_dos(open(p2, "rb").read(), "cp437")), lat, acp=437,
                    label="arj DOS host CP437 names")
    # directories, symlink (UXSPECIAL), Unix modes
    tree = os.path.join(t.work, "arj_src3")
    shutil.rmtree(tree, ignore_errors=True)
    os.makedirs(os.path.join(tree, "d1/d2"))
    with open(os.path.join(tree, "d1/f"), "wb") as f:
        f.write(b"x\n")
    os.chmod(os.path.join(tree, "d1/f"), 0o755)
    os.symlink("../some/long/target_name_here.txt", os.path.join(tree, "d1/lnk"))
    p3 = t.path("arj", "tree.arj")
    if os.path.exists(p3):
        os.remove(p3)
    t.sh(["arj", "a", "-r", "-y", "-a1", p3, "d1"], cwd=tree)
    r, typ, rows = t.listing(p3)
    lk = [x for x in rows if x["name"].startswith("d1/lnk")]
    t.record(lk and lk[0]["name"] == "d1/lnk -> ../some/long/target_name_here.txt" and (lk[0]["mode"] & 0o170000) == 0o120000,
             "arj symlink target", str(lk))
    fx = [x for x in rows if x["name"] == "d1/f"]
    t.record(fx and fx[0]["mode"] == 0o100755, "arj unix mode", str(fx))
    t.record(any(x["name"] == "d1/d2" and x["is_dir"] for x in rows), "arj directory entry", str(rows))
    for m in (1, 4):
        hostile_set(t, "arj_m%d" % m, open(t.path("arj", "m%d.arj" % m), "rb").read()[:60000], 10, header=200)
    hostile_set(t, "arj_garble", open(t.path("arj", "g1.arj"), "rb").read()[:40000], 4, header=200)

# ------------------------------------------------------------------ LZH

LZH_FILES = [
    (b"readme.txt", TXT[:60000]),
    (b"bin/random.bin", RND[:8000]),
    (b"bin/mixed.dat", (b"=" * 40 + b"    hello    ") * 40 + MIX[:30000]),
    (b"one.txt", b"x"),
    (b"two.txt", b"xy"),
    (b"zero.txt", b""),
]

def lha_archive(level, method, files, **kw):
    out = b""
    for path, raw in files:
        comp = E.lha_compress(raw, method)
        d, _, n = path.rpartition(b"/")
        if level >= 2:
            out += E.lha_member(level, method, n, comp, raw, dirname=(d + b"/") if d else None, **kw)
        else:
            out += E.lha_member(level, method, path.replace(b"/", b"\\"), comp, raw, **kw)
    return out + b"\0"

def lhasa_extract(t, p):
    od = os.path.join(t.work, "lhasa_" + os.path.basename(p))
    shutil.rmtree(od, ignore_errors=True)
    os.makedirs(od)
    t.sh(["lha", "xqw=" + od, p], check=False)
    return t.read_tree(od)

def section_lzh(t):
    have_lhasa = bool(t.tool("lha"))
    exp = {k.decode(): v for k, v in LZH_FILES}
    for method in ("-lh0-", "-lh1-", "-lh4-", "-lh5-", "-lh6-", "-lh7-", "-lzs-", "-lz5-"):
        for level in (0, 1, 2, 3):
            mode = 0o100644 if level != 0 or method == "-lh5-" else None
            p = write(t, "lzh/%s_l%d.lzh" % (method.strip("-"), level), lha_archive(level, method, LZH_FILES, unix_mode=mode))
            if have_lhasa:
                got = lhasa_extract(t, p)
                t.record(got == exp, "lhasa accepts encoder %s level %d" % (method, level),
                         "" if got == exp else str(sorted(got)))
            t.check_extract(p, exp, expect_type="LZH", label="lzh %s level %d" % (method, level))
    # long -lh1- stream: the adaptive tree is rebuilt every 32K symbols
    big = [(b"lh1big.bin", RND + TXT)]
    p = write(t, "lzh/lh1big.lzh", lha_archive(2, "-lh1-", big))
    if have_lhasa:
        t.record(lhasa_extract(t, p) == {"lh1big.bin": RND + TXT}, "lhasa accepts long -lh1-")
    t.check_extract(p, {"lh1big.bin": RND + TXT}, label="lzh -lh1- tree rebuilds")
    # many small static-Huffman blocks
    raw = MIX + TXT
    comp = E.lh_encode(raw, 5, block=1500)
    p = write(t, "lzh/blocks.lzh", E.lha_member(2, "-lh5-", b"blocks.bin", comp, raw) + b"\0")
    t.check_extract(p, {"blocks.bin": raw}, label="lzh -lh5- many blocks")
    # extended headers: directory (0xFF), Unix mode, Windows times, directory and symlink entries
    wt = 132514080000000000
    ents = E.lha_member(2, "-lh5-", b"f.txt", E.lha_compress(TXT[:5000], "-lh5-"), TXT[:5000],
                        dirname=b"a/b/", unix_mode=0o100600, wintime=wt)
    ents += E.lha_member(2, "-lhd-", b"", b"", b"", dirname=b"a/empty/", unix_mode=0o040755)
    # LHa for UNIX splits "a/lnk|../f.txt" at the last '/': directory "a/lnk|../", name "f.txt"
    ents += E.lha_member(2, "-lhd-", b"f.txt", b"", b"", dirname=b"a/lnk|../", unix_mode=0o120777)
    ents += E.lha_member(1, "-lh5-", b"l1.txt", E.lha_compress(TXT[:999], "-lh5-"), TXT[:999], dirname=b"x/y/", unix_mode=0o100755)
    p = write(t, "lzh/ext.lzh", ents + b"\0")
    t.check_extract(p, {"a/b/f.txt": TXT[:5000], "x/y/l1.txt": TXT[:999], "a/empty": None}, allow_extra=True, label="lzh ext headers")
    r, typ, rows = t.listing(p)
    lk = [x for x in rows if x["name"].startswith("a/lnk")]
    t.record(lk and lk[0]["name"] == "a/lnk -> ../f.txt" and (lk[0]["mode"] & 0o170000) == 0o120000, "lzh symlink", str(lk))
    t.record(any(x["name"] == "a/b/f.txt" and x["mode"] == 0o100600 and x["method"] == "LH5" for x in rows), "lzh unix mode + method", str(rows))
    t.record(any(x["name"] == "a/empty" and x["is_dir"] for x in rows), "lzh directory entry", str(rows))
    # bad header CRC (extended header 0x00) is rejected
    bad = bytearray(E.lha_member(2, "-lh0-", b"crc.txt", b"abc", b"abc"))
    bad[28] ^= 0x55
    r, rows, out = t.extract(write(t, "lzh/badcrc.lzh", bytes(bad) + b"\0"))
    t.record(r.returncode == 1 or not rows, "lzh header CRC mismatch rejected", r.stdout.decode()[:80])
    # data CRC-16 mismatch
    m = bytearray(E.lha_member(2, "-lh0-", b"d.txt", b"abcd", b"abcd"))
    m[-1] ^= 1
    r, rows, out = t.extract(write(t, "lzh/datacrc.lzh", bytes(m) + b"\0"))
    t.record(rows and rows[0][0] == 4, "lzh data CRC-16 mismatch -> GZ_E_CRC", str(rows))
    # Shift-JIS names (0x5C trail bytes must not split the path), CP949 names
    sj = ["ソフト\\表示.txt", "データ/能力.txt"]
    files = [(n.encode("cp932").replace(b"/", b"\\"), TXT[:100 + i]) for i, n in enumerate(sj)]
    p = write(t, "lzh/sjis.lzh", lha_archive(0, "-lh5-", files, os_id=b"M"))
    t.check_extract(p, {"ソフト/表示.txt": TXT[:100], "データ/能力.txt": TXT[:101]}, acp=932, label="lzh Shift-JIS names")
    files = [("자료/보고서.txt".encode("cp949").replace(b"/", b"\\"), TXT[:500])]
    p = write(t, "lzh/cp949.lzh", lha_archive(1, "-lh5-", files, os_id=b"M"))
    t.check_extract(p, {"자료/보고서.txt": TXT[:500]}, acp=949, label="lzh CP949 names")
    # SFX
    p = write(t, "lzh/sfx.exe", b"MZ" + rand(30000, 3).replace(b"-l", b"-L") + lha_archive(2, "-lh5-", LZH_FILES[:3]))
    t.check_extract(p, {k.decode(): v for k, v in LZH_FILES[:3]}, label="lzh SFX")
    # unsupported method listed, extraction fails cleanly
    p = write(t, "lzh/lh3.lzh", E.lha_member(2, "-lh3-", b"x.bin", b"\x12\x34", b"zz") + b"\0")
    r, rows, out = t.extract(p)
    t.record(rows and rows[0][0] == 5, "lzh -lh3- -> GZ_E_METHOD", str(rows))
    # jlha (Java LHA) archives, when installed
    if t.tool("jlha"):
        src = t.write_tree(os.path.join(t.work, "jlha_src"), {"a.txt": TXT[:80000], "s/b.bin": RND[:9000]})
        for m in (5, 6, 7):
            for lv in (0, 1, 2):
                p = t.path("lzh", "jlha_%d_%d.lzh" % (m, lv))
                if os.path.exists(p):
                    os.remove(p)
                t.sh(["jlha", "a%do%d" % (lv, m), p, "a.txt", "s/b.bin"], cwd=src, check=False, timeout=300)
                if os.path.exists(p):
                    with open(p, "rb") as f:
                        hd = f.read(32)
                    t.record(hd[2:7] == b"-lh%d-" % m and hd[20] == lv, "jlha made -lh%d- level %d" % (m, lv), repr(hd[2:7]))
                    t.check_extract(p, {"a.txt": TXT[:80000], "s/b.bin": RND[:9000]}, label="jlha -lh%d- level %d" % (m, lv))
    for meth in ("-lh1-", "-lh5-", "-lh7-", "-lzs-", "-lz5-"):
        hostile_set(t, "lzh_" + meth.strip("-"), lha_archive(2 if meth != "-lz5-" else 0, meth, LZH_FILES[:3]), 8, header=120)

# ------------------------------------------------------------------ MS SZDD / KWAJ

def section_mslz(t, ref):
    def refcheck(kind, p, want_prefix, label, exact_len=None):
        if not ref:
            return
        o = p + ".ref"
        r = t.sh([ref, kind, p, o], check=False)
        got = open(o, "rb").read() if os.path.exists(o) else None
        ok = got is not None and (got == want_prefix if exact_len is None else got[:exact_len] == want_prefix)
        t.record(ok, "libmspack accepts " + label, r.stdout.decode().strip())
    raw = MIX[:120000]
    if t.tool("mscompress"):
        d = os.path.join(t.work, "msc")
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
        with open(os.path.join(d, "setup.exe"), "wb") as f:
            f.write(raw)
        t.sh(["mscompress", "setup.exe"], cwd=d)
        t.check_extract(os.path.join(d, "setup.exe_"), {"setup.exe": raw}, expect_type="SZDD", label="mscompress SZDD")
        if t.tool("7z"):
            r, out = t.sevenzip_extract(os.path.join(d, "setup.exe_"))
            t.record(r.returncode == 0 and list(t.read_tree(out).values()) == [raw], "7z agrees on SZDD")
    p = write(t, "ms/SETUP.EX_", E.szdd_file(raw, ord("E")))
    refcheck("szdd", p, raw, "encoder SZDD")
    t.check_extract(p, {"SETUP.EXE": raw}, label="SZDD missing last char")
    t.check_extract(write(t, "ms/readme.tx_", E.szdd_file(TXT[:5000], ord("T"))), {"readme.txt": TXT[:5000]}, label="SZDD lower-case name")
    t.check_extract(write(t, "ms/driver.sy_", E.szdd_file(RND[:3000], 0)), {"driver.sys": RND[:3000]}, label="SZDD guessed extension")
    t.check_extract(write(t, "ms/empty.dl_", E.szdd_file(b"", ord("L"))), {"empty.dll": b""}, label="SZDD empty")
    p = write(t, "ms/qb.ex_", E.szqb_file(raw))
    refcheck("szdd", p, raw, "encoder QBasic SZ")
    t.check_extract(p, {"qb.exe": raw}, label="QBasic SZ")
    for method in range(5):
        for with_len in (True, False):
            k = E.kwaj_file(method, raw, b"ORIGINAL", b"DAT", with_len)
            p = write(t, "ms/kw%d%d.dat_" % (method, with_len), k)
            want = raw
            if ref:
                o = p + ".ref"
                rr = t.sh([ref, "kwaj", p, o], check=False)
                got = open(o, "rb").read() if os.path.exists(o) else b""
                t.record(got[:len(raw)] == raw, "libmspack accepts encoder KWAJ %d len=%d" % (method, with_len), rr.stdout.decode().strip())
                if not with_len:
                    want = got        # no length: both decoders run to the end of the input
            elif method == 3 and not with_len:
                continue              # trailing pad bits may decode: needs the reference
            t.check_extract(p, {"ORIGINAL.DAT": want}, expect_type="KWAJ", label="KWAJ method %d len=%d" % (method, with_len))
    t.check_extract(write(t, "ms/noname.da_", E.kwaj_file(3, TXT[:7000])), {"noname.da": TXT[:7000]}, label="KWAJ without stored name")
    hostile_set(t, "szdd", E.szdd_file(raw[:30000], ord("E")), 8, header=20)
    for method in (2, 3, 4):
        hostile_set(t, "kwaj%d" % method, E.kwaj_file(method, raw[:40000], b"X", b"Y"), 8, header=40)

# ------------------------------------------------------------------ Shrink / Implode / raw codecs

def section_codecs(t, drv):
    def run_drv(args, timeout=60):
        try:
            r = subprocess.run([drv] + args, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return None, "timeout"
        return r, r.stdout.decode().strip()
    def check(label, codec, comp, raw, params, size=None):
        i = write(t, "codec/%s.in" % label.replace(" ", "_"), comp)
        o = i + ".out"
        r, s = run_drv([codec, i, o, str(len(raw) if size is None else size)] + [str(x) for x in params])
        got = open(o, "rb").read() if r and os.path.exists(o) else None
        return t.record(r is not None and s.startswith("status=0 ") and got == raw, label, s)
    data = MIX + TXT
    # Shrink, cross-checked through ZIP containers with 7-Zip and Info-ZIP
    zents = []
    for nm, d in (("txt", TXT), ("mix", data), ("rnd", RND)):
        comp, clears = E.shrink_encode(d)
        check("shrink %s (%d partial clears)" % (nm, clears), "shrink", comp, d, [])
        zents.append((b"shrink_%s" % nm.encode(), 1, 0, comp, d))
    for large in (0, 1):
        for three in (0, 1):
            comp = E.implode_encode(data, large, three)
            check("implode %dK %d trees" % (8 if large else 4, 3 if three else 2), "implode", comp, data, [large, three])
            zents.append((b"implode_%d%d" % (large, three), 6, (2 if large else 0) | (4 if three else 0), comp, data))
            hostile_codec(t, drv, "implode%d%d" % (large, three), comp, len(data), ["implode"], [large, three])
    zp = write(t, "codec/legacy.zip", E.zip_raw(zents))
    for tool, args in (("7z", ["7z", "x", "-y"]), ("unzip", ["unzip", "-o", "-qq"])):
        if not t.tool(tool):
            continue
        od = os.path.join(t.work, "zipref_" + tool)
        shutil.rmtree(od, ignore_errors=True)
        os.makedirs(od)
        if tool == "7z":
            t.sh(args + ["-o" + od, zp], check=False)
        else:
            t.sh(args + ["-d", od, zp], check=False)
        got = t.read_tree(od)
        t.record(all(got.get(nm.decode()) == d for nm, m, f, c, d in zents), "%s accepts encoder Shrink/Implode" % tool,
                 str(sorted(got)))
    # Shrink: truncated stream with a known size, unknown size runs to the end of input
    comp, _ = E.shrink_encode(TXT[:20000])
    r, s = run_drv(["shrink", write(t, "codec/sh_trunc.in", comp[:len(comp) // 2]), t.path("codec/x.out"), "20000"])
    t.record(s.startswith("status=9 "), "shrink truncated -> GZ_E_TRUNC", s)
    check("shrink unknown size", "shrink", comp, TXT[:20000], [], size=-1)
    hostile_codec(t, drv, "shrink", E.shrink_encode(MIX[:30000])[0], 30000, ["shrink"], [])
    # every LZH-family method as a raw stream, with the size unknown where it ends itself
    raw = MIX[:60000]
    for meth, num in (("-lh1-", 1), ("-lh4-", 2), ("-lh5-", 3), ("-lh6-", 4), ("-lh7-", 5), ("-lzs-", 6), ("-lz5-", 7)):
        comp = E.lha_compress(raw, meth)
        check("raw %s" % meth, "lzh", comp, raw, [num])
        hostile_codec(t, drv, "lzh" + meth.strip("-"), comp, len(raw), ["lzh"], [num])
    for name, num, comp in (("SZDD", 10, E.szdd_file(raw)[14:]), ("SZ", 11, E.szqb_file(raw)[12:]),
                            ("KWAJ", 12, E.kwaj_lzh_encode(raw))):
        check("raw %s" % name, "lzh", comp, raw, [num])
        hostile_codec(t, drv, "lzh" + name, comp, len(raw), ["lzh"], [num])
    z = E.compress_Z(raw, 13)
    check("raw LZW", "lzw", z[3:], raw, [z[2]], size=-1)
    hostile_codec(t, drv, "lzw", z[3:], -1, ["lzw"], [z[2]])
    # throughput (informational)
    for label, codec, comp, params, n in (("lh5", "lzh", E.lha_compress(TXT, "-lh5-"), [3], len(TXT)),
                                          ("LZW", "lzw", E.compress_Z(TXT, 16)[3:], [0x90], len(TXT)),
                                          ("implode", "implode", E.implode_encode(TXT, 1, 1), [1, 1], len(TXT))):
        i = write(t, "codec/bench_%s.in" % label, comp)
        r, s = run_drv(["bench", codec, i, "-", str(n)] + [str(x) for x in params] + ["20"], timeout=300)
        t.record(r is not None and s.startswith("status=0 "), "throughput %s" % label, s)

def hostile_codec(t, drv, label, comp, size, head, params):
    for k, d in enumerate(corruptions(comp, 10, seed=11, header=40)):
        i = write(t, "codec/hostile_%s_%d.in" % (label, k), d)
        try:
            r = subprocess.run([drv] + head + [i, i + ".out", str(size)] + [str(x) for x in params],
                               capture_output=True, timeout=30)
            err = r.stderr.decode(errors="replace")
            ok = r.returncode == 0 and "Sanitizer" not in err and "runtime error" not in err
            t.record(ok, "hostile codec %s #%d" % (label, k), "" if ok else "rc=%d %s" % (r.returncode, err[-300:]))
        except subprocess.TimeoutExpired:
            t.record(False, "hostile codec %s #%d" % (label, k), "timeout")

# ------------------------------------------------------------------ real-world samples (network)

# Small DOS / Windows 3.x era archives from the BBS CD-ROM mirror at cd.textfiles.com
# (CICA Windows archive, July 1992; Garbo PC archive). Downloaded at test time into
# the work directory (not committed); the section is skipped when offline.
BBS = "http://cd.textfiles.com/"
BBS_ZIPS = ["cica9207/WIN3/ICONS/TGICONS1.ZIP", "cica9207/WIN3/ICONS/TAMR101.ZIP",
            "cica9207/WIN3/FONTS/FONTLIST.ZIP", "cica9207/WIN3/FONTS/DMPFM151.ZIP",
            "cica9207/WIN3/FONTS/ARC13P.ZIP"]
BBS_ARCS = ["garbo/PC/ARCERS/HYPER25.LZH", "garbo/PC/ARCERS/SQPC131.LZH", "garbo/PC/ARCERS/LHA213.EXE",
            "garbo/PC/ARCERS/ARJ230NG.EXE"]

def fetch(t, rel):
    import urllib.request
    p = os.path.join(t.work, "bbs", os.path.basename(rel))
    if os.path.exists(p) and os.path.getsize(p):
        return p
    os.makedirs(os.path.dirname(p), exist_ok=True)
    try:
        d = urllib.request.urlopen(BBS + rel, timeout=20).read()
    except Exception:
        return None
    with open(p, "wb") as f:
        f.write(d)
    return p

def section_bbs(t, drv):
    import zipfile
    got_any = False
    for rel in BBS_ZIPS:
        p = fetch(t, rel)
        if not p:
            continue
        got_any = True
        raw = open(p, "rb").read()
        bad = []
        n = 0
        for i in zipfile.ZipFile(p).infolist():
            if i.compress_type not in (1, 6):
                continue
            nl, xl = struct.unpack_from("<HH", raw, i.header_offset + 26)
            off = i.header_offset + 30 + nl + xl
            fi = write(t, "bbs/%s_%d.in" % (os.path.basename(p), n), raw[off:off + i.compress_size])
            n += 1
            args = ["shrink", fi, fi + ".out", str(i.file_size)] if i.compress_type == 1 else \
                ["implode", fi, fi + ".out", str(i.file_size), str(1 if i.flag_bits & 2 else 0), str(1 if i.flag_bits & 4 else 0)]
            r = subprocess.run([drv] + args, capture_output=True, timeout=60)
            out = open(fi + ".out", "rb").read() if os.path.exists(fi + ".out") else b""
            if not r.stdout.startswith(b"status=0 ") or zlib.crc32(out) & 0xFFFFFFFF != i.CRC or len(out) != i.file_size:
                bad.append(i.filename)
        t.record(not bad and n, "PKZIP 1.x %s: %d Shrink/Implode members" % (os.path.basename(p), n), str(bad))
    for rel in BBS_ARCS:
        p = fetch(t, rel)
        if not p:
            continue
        got_any = True
        r, rows, out = t.extract(p)
        files = [v for v in rows.values() if not v[1]]
        t.record(r.returncode == 0 and files and all(v[0] == 0 for v in files),
                 "real archive %s: %d files, checksums OK" % (os.path.basename(p), len(files)), str(list(rows.values())[:4]))
        if p.endswith(".LZH") and t.tool("lha"):
            ref = {k.lower(): v for k, v in lhasa_extract(t, p).items()}
            mine = {}
            for i, (st, isdir, size, nm) in rows.items():
                fp = os.path.join(out, "%d.bin" % i)
                if not isdir and os.path.exists(fp):
                    mine[nm.lower()] = open(fp, "rb").read()
            t.record(ref and ref == mine, "real archive %s same as lhasa" % os.path.basename(p), str(sorted(ref)))
    if not got_any:
        t.record(True, "real-world samples skipped (offline)")

# ------------------------------------------------------------------ main

def run(t):
    drv = t.build_driver("tests/drivers/legacy_codec.c")
    ref = None
    try:
        ref = t.build_driver("tests/drivers/mspack_ref.c", extra=["-lmspack"])
    except Exception:
        ref = None
    section_z(t)
    section_arj(t)
    section_lzh(t)
    section_mslz(t, ref)
    section_codecs(t, drv)
    section_bbs(t, drv)
