"""Apple disk images and file systems: UDIF .dmg (koly + XML plist / binary resource
fork, mish chunk tables: zero, ignore, raw, ADC, zlib, bzip2, LZFSE, XZ; 7-Zip style
partition names, automatic descent into the HFS+ partition, CRC-32 check), HFS+ /
HFSX (catalog / extents overflow / attributes B-trees, fragmented forks, symlinks,
file and directory hard links, decmpfs zlib / LZVN / LZFSE, resource forks, NFD
names, HFS wrapper) and classic HFS (hfsutils). Volumes are written by the Python
builder in _hfsbuild.py (checked with fsck.hfsplus), compared with 7-Zip where it
can read them, and attacked with corrupted structures and mutation fuzzing."""
import os, random, struct, subprocess, sys, unicodedata, zlib, base64, io, zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _hfsbuild as H

ENV = dict(os.environ, LANG="C.UTF-8", LC_ALL="C.UTF-8", TZ="UTC")
FT_EPOCH = 11644473600

def blob(n, seed=1):
    return random.Random(seed * 7919 + n).randbytes(n)

def text(n, seed=1):
    rnd = random.Random(seed)
    words = ["고기", "삼겹살", "apple", "disk", "image", "HFS+", "catalog", "B-tree", "\n", "fork", "zip"]
    out = []
    size = 0
    while size < n:
        w = rnd.choice(words) + " "
        out.append(w)
        size += len(w.encode())
    return " ".join(out).encode()[:n]

def nfd(s):
    return unicodedata.normalize("NFD", s)

def ft(unix):
    return (unix + FT_EPOCH) * 10000000

def with_dirs(vol, files):
    """{path: data} under the volume folder, plus every directory (None)"""
    out = {vol: None}
    for k, v in files.items():
        out[vol + "/" + k] = v
        parts = k.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            out.setdefault(vol + "/" + "/".join(parts[:i]), None)
    return out

def write(t, name, data):
    p = t.path(name)
    with open(p, "wb") as f:
        f.write(data)
    return p

def fsck_ok(t, img, label):
    if not t.tool("fsck.hfsplus"):
        return
    r = t.sh(["fsck.hfsplus", "-n", "-f", img], check=False)
    out = r.stdout.decode(errors="replace")
    t.record("appears to be OK" in out, "fsck " + label, out.strip().splitlines()[-1] if out.strip() else "")

def listing(t, img, env=None):
    r, typ, rows = t.listing(img, env=env)
    return typ, {x["name"]: x for x in rows}

def drv_rows(t, drv, img, env=None):
    r = subprocess.run([drv, "l", img], capture_output=True, env=env, timeout=120)
    rows, typ, comment = {}, None, None
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if p[0] == "TYPE":
            typ = p[1]
        elif p[0] == "COMMENT":
            comment = p[1]
        elif len(p) >= 13 and p[0].isdigit():
            name, link = p[12], None
            if " -> " in name:
                name, link = name.split(" -> ", 1)
            rows[name] = dict(idx=int(p[0]), is_dir=int(p[1]), is_link=int(p[2]), usize=int(p[3]),
                              csize=int(p[4]), mk=int(p[5]), mtime=int(p[6]), attr=int(p[7]),
                              mode=int(p[8], 8), link=link)
    return typ, comment, rows

def check_views(t, drv, img, label, env=None):
    """extraction CRC == CRC of the entry view read in shuffled chunks (fs1_dump v)"""
    r = subprocess.run([drv, "v", img], capture_output=True, timeout=600, env=env)
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

def open_error(t, img, code, label):
    r, rows, out = t.extract(img)
    got = r.stdout.decode(errors="replace").strip()
    return t.record(got.startswith("OPEN_ERROR %d" % code), label, got[:120])

def entry_status(t, img, name, code, label, env=None):
    r, rows, out = t.extract(img, env=env)
    st = [s for (s, d, z, n) in rows.values() if n == name]
    return t.record(st == [code], label, "status %s" % st)

# ---------------------------------------------------------------- HFS+

def basic_volume(slash=True):
    v = H.HfsPlus("Test Vol")
    files = {
        "hello.txt": b"hello world\n" * 100,
        "dir/sub/big.bin": blob(300000, 2),
        nfd("dir/한글 파일.txt"): "안녕하세요 HFS+\n".encode() * 50,
        nfd("Café.txt"): b"accent stays NFD",
        "dir/frag.bin": blob(150000, 3),
        "rsrc.txt": b"data fork",
        "empty": b"",
        "deep/a/b/c/d/e/f/g/h/leaf.txt": b"deep\n",
        "spaces and (parens) [x].txt": b"punct",
    }
    for k, d in files.items():
        v.add(k, d, fragment=12 if k == "dir/frag.bin" else 0, rsrc=b"resource fork bytes" * 10 if k == "rsrc.txt" else b"",
              mtime=1600000000 + len(k), locked=k == "hello.txt", invisible=k == "empty", mode=0o600 if k == "empty" else 0o644)
    v.mkdir("emptydir", mode=0o700)
    v.symlink("link", "dir/sub/big.bin")
    v.symlink("dir/sublink", "sub/big.bin")
    if slash:
        sl = v.add("slash", b"slash in name")
        sl.name = "a/b"                                       # '/' in an HFS+ name -> ':' (7-Zip: '_')
        files["a:b"] = b"slash in name"
    return v, files

def hfs_basic(t, fs1):
    v, files = basic_volume()
    img = write(t, "basic.hfs", v.build())
    fsck_ok(t, img, "basic volume (builder self-check)")
    exp = with_dirs("Test Vol", files)
    exp["Test Vol/emptydir"] = None
    exp["Test Vol/rsrc.txt:rsrc"] = b"resource fork bytes" * 10
    t.check_extract(img, exp, label="hfs+ basic", expect_type="HFS+", allow_extra=True)
    typ, rows = listing(t, img)
    got_links = {n: r for n, r in rows.items() if r["mode"] & 0o170000 == 0o120000}
    t.record(typ == "HFS+" and set(got_links) == {"Test Vol/link -> dir/sub/big.bin", "Test Vol/dir/sublink -> sub/big.bin"},
             "hfs+ symlink targets", str(sorted(got_links)))
    want_mode = {"Test Vol/empty": 0o100600, "Test Vol/emptydir": 0o40700, "Test Vol/hello.txt": 0o100644}
    bad = [n for n, m in want_mode.items() if n not in rows or rows[n]["mode"] != m]
    t.record(not bad, "hfs+ modes", str([(n, oct(rows[n]["mode"]) if n in rows else None) for n in bad]))
    if fs1:
        typ, comment, dr = drv_rows(t, fs1, img)
        e = dr.get("Test Vol/hello.txt", {})
        ok = e.get("mk") == 1 and e.get("mtime") == ft(1600000000 + len("hello.txt")) and e.get("attr", 0) & 1
        ok = ok and dr.get("Test Vol/empty", {}).get("attr", 0) & 2
        ok = ok and dr.get("Test Vol/rsrc.txt:rsrc", {}).get("usize") == 190
        t.record(ok, "hfs+ times / locked / invisible / rsrc size", str([e, dr.get("Test Vol/empty")]))
        check_views(t, fs1, img, "hfs+ views (fragmented, rsrc)")
    if t.tool("7z"):
        v, files = basic_volume(slash=False)
        img7 = write(t, "basic7.hfs", v.build())
        t.check_vs_7z(img7, label="hfs+ basic vs 7z", allow_extra=True)
    return img

def hfs_compressed(t, fs1):
    v = H.HfsPlus("Packed")
    exp = {}
    have_lzfse = H._lzfse is not None
    kinds = ["zlib-inline", "zlib-rsrc", "lzvn-inline", "lzvn-rsrc", "store-inline"]
    if have_lzfse:
        kinds += ["lzfse-inline", "lzfse-rsrc"]
    for k in kinds:
        if k.endswith("inline"):
            d = text(600, len(k)) if k.startswith("store") else b"".join(b"line %d of a small file\n" % (i % 50) for i in range(2500))
        else:
            d = text(200000 + len(k) * 1000, len(k)) + blob(70000, 9)    # last blocks incompressible
        it = v.add("cmp/" + k + ".txt", d)
        v.compress(it, k)
        exp["cmp/" + k + ".txt"] = d
        if k.endswith("rsrc"):
            r = blob(150000, len(k))
            it = v.add("raw/" + k + ".bin", r)
            v.compress(it, k, raw_blocks=True)                    # every block stored raw
            exp["raw/" + k + ".bin"] = r
    it = v.add("cmp/empty-zlib", b"")
    v.compress(it, "zlib-inline")
    exp["cmp/empty-zlib"] = b""
    exp["plain.txt"] = b"not compressed\n"
    v.add("plain.txt", exp["plain.txt"])
    img = write(t, "compressed.hfs", v.build())
    fsck_ok(t, img, "decmpfs volume (builder self-check)")
    t.check_extract(img, with_dirs("Packed", exp), label="hfs+ decmpfs %s" % " ".join(kinds), allow_extra=True)
    typ, rows = listing(t, img)
    meth = {n.split("/")[-1]: r["method"] for n, r in rows.items() if "/cmp/" in n}
    want = {"zlib-inline.txt": "ZLIB", "lzvn-rsrc.txt": "LZVN", "store-inline.txt": "decmpfs Store"}
    t.record(all(meth.get(k) == m for k, m in want.items()), "hfs+ decmpfs method column", str(meth))
    if fs1:
        check_views(t, fs1, img, "hfs+ decmpfs views (block cache)")
    # 7-Zip 23 reads zlib and LZVN decmpfs (not LZFSE or type 1)
    if t.tool("7z"):
        v2 = H.HfsPlus("Packed7")
        for k in ("zlib-inline", "zlib-rsrc", "lzvn-inline", "lzvn-rsrc"):
            d = b"".join(b"%s %d\n" % (k.encode(), i % 77) for i in range(3000)) if "inline" in k else text(150000, len(k) + 3)
            it = v2.add(k + ".txt", d)
            v2.compress(it, k)
        img2 = write(t, "compressed7.hfs", v2.build())
        t.check_vs_7z(img2, label="hfs+ decmpfs zlib/LZVN vs 7z")
    # unknown compression type: listed, extraction says unsupported method
    v3 = H.HfsPlus("Odd")
    it = v3.add("lzbitmap.bin", b"x" * 1000)
    v3.compress(it, "zlib-inline")
    it.decmpfs = it.decmpfs[:4] + struct.pack("<I", 13) + it.decmpfs[8:]
    img3 = write(t, "odd.hfs", v3.build())
    entry_status(t, img3, "Odd/lzbitmap.bin", 5, "hfs+ decmpfs type 13 -> GZ_E_METHOD")

def hfs_links(t, fs1):
    v = H.HfsPlus("Links")
    d1 = text(5000, 4)
    v.hardlink(["one.txt", "dir/two.txt", "dir/sub/three.txt"], d1)
    d2 = text(150000, 5)
    v.hardlink(["packed-a.txt", "packed-b.txt"], d2, compress="zlib-rsrc")
    v.add("tm/target/inner.txt", b"inside a directory hard link\n")
    v.add("tm/target/deeper/x.bin", blob(5000, 6))
    v.dirlink(["dirlink", "tm/second"], "tm/target")
    v.add("normal.txt", b"normal")
    img = write(t, "links.hfs", v.build())
    exp = {"one.txt": d1, "dir/two.txt": d1, "dir/sub/three.txt": d1, "packed-a.txt": d2, "packed-b.txt": d2,
           "normal.txt": b"normal", "dirlink/inner.txt": b"inside a directory hard link\n",
           "dirlink/deeper/x.bin": blob(5000, 6)}
    e = with_dirs("Links", exp)
    e["Links/tm"] = e["Links/tm/second"] = None
    t.check_extract(img, e, label="hfs+ file + directory hard links (private stores hidden)")
    typ, rows = listing(t, img)
    hidden = [n for n in rows if "Private" in n or "iNode" in n or "dir_" in n]
    t.record(not hidden and rows.get("Links/tm/second", {}).get("is_dir") == 1, "hfs+ hard link stores hidden", str(hidden))

def hfs_variants(t, fs1):
    # HFSX, case-sensitive, 512-byte blocks and nodes: a deep B-tree with index nodes
    v = H.HfsPlus("CaseVol", hfsx=True, case_sensitive=True, bs=512, node_size=512)
    exp = {"A.txt": b"upper", "a.txt": b"lower", "Dir/x": b"x" * 3000}
    for i in range(300):
        exp["many/file%03d.dat" % i] = blob(random.Random(i).randrange(0, 3000), i)
    for k, d in exp.items():
        v.add(k, d)
    img = write(t, "hfsx.img", v.build())
    fsck_ok(t, img, "hfsx (builder self-check)")
    t.check_extract(img, with_dirs("CaseVol", exp), label="hfsx case-sensitive, 512-byte nodes", expect_type="HFSX")
    if t.tool("7z"):
        t.check_vs_7z(img, label="hfsx vs 7z")
    # HFS wrapper (classic MDB embedding the HFS+ volume)
    v = H.HfsPlus("Wrapped")
    exp = {"in/wrapped.txt": b"inside a wrapper\n" * 100}
    v.add("in/wrapped.txt", exp["in/wrapped.txt"])
    img = write(t, "wrapper.img", H.hfs_wrapper(v.build()))
    t.check_extract(img, with_dirs("Wrapped", exp), label="hfs wrapper -> embedded HFS+", expect_type="HFS+")
    if fs1:
        check_views(t, fs1, img, "hfs wrapper views")
    # catalog file in 11 fragments (its own extents overflow records)
    v = H.HfsPlus("FragCat", bs=512, node_size=512, cat_fragments=11)
    exp = {}
    for i in range(250):
        exp["d%02d/f%03d.txt" % (i % 7, i)] = b"file %d\n" % i * (i % 13)
    for k, d in exp.items():
        v.add(k, d, fragment=10 if k.endswith("7.txt") else 0)
    img = write(t, "fragcat.img", v.build())
    fsck_ok(t, img, "fragmented catalog (builder self-check)")
    t.check_extract(img, with_dirs("FragCat", exp), label="hfs+ fragmented catalog + forks")
    # journal files hidden, dirty journal noted
    v = H.HfsPlus("Journal", journal_files=True, dirty_journal=True)
    v.add("file.txt", b"journaled")
    v.add(".fseventsd/fseventsd-uuid", b"0123456789ABCDEF")
    img = write(t, "journal.img", v.build())
    r, rows, out = t.extract(img)
    names = sorted(n for (s, d, z, n) in rows.values())
    err = r.stderr.decode(errors="replace")
    t.record(names == ["Journal", "Journal/file.txt"] and "journal not replayed" in err,
             "hfs+ journal files and .fseventsd hidden, dirty journal noted", "%s %s" % (names, err[-80:]))
    # real empty volumes from mkfs.hfsplus (plain and journaled)
    if t.tool("mkfs.hfsplus"):
        for opts, lab in (([], "plain"), (["-J"], "journaled"), (["-s"], "case-sensitive")):
            p = t.path("mkfs_%s.img" % lab)
            with open(p, "wb") as f:
                f.truncate(16 << 20)
            r = t.sh(["mkfs.hfsplus"] + opts + ["-v", "Empty " + lab, p], check=False)
            if r.returncode:
                continue
            r, typ, rows = t.listing(p)
            t.record(typ in ("HFS+", "HFSX") and [x["name"] for x in rows] == ["Empty " + lab],
                     "mkfs.hfsplus %s: only the root folder" % lab, "%s %s" % (typ, [x["name"] for x in rows]))

def macbinary(name, data, rsrc, ftype=b"APPL", creator=b"GZIP"):
    """MacBinary II file (128-byte header with CRC-16/XMODEM, forks padded to 128)"""
    import binascii
    h = bytearray(128)
    h[1] = len(name)
    h[2:2 + len(name)] = name
    h[65:69], h[69:73] = ftype, creator
    struct.pack_into(">II", h, 83, len(data), len(rsrc))
    struct.pack_into(">II", h, 91, H.hfs_time(1600000000), H.hfs_time(1600000000))
    h[122] = h[123] = 129
    struct.pack_into(">H", h, 124, binascii.crc_hqx(bytes(h[:124]), 0))
    pad = lambda b: b + bytes(-len(b) % 128)
    return bytes(h) + pad(data) + pad(rsrc)

def hfs_classic(t):
    if not (t.tool("hformat") and t.tool("hcopy")):
        return
    home = t.path("hfshome")
    os.makedirs(home, exist_ok=True)
    env = dict(ENV, HOME=home)
    img = t.path("classic.hfs")
    if os.path.exists(img):
        os.remove(img)
    with open(img, "wb") as f:
        f.truncate(4 << 20)
    exp = {"Folder/Sub/random.bin": blob(100000, 11), "Folder/note.txt": b"classic text\n" * 40,
           "big.bin": blob(700000, 12), "Folder/empty": b""}
    src = t.path("classic_src")
    os.makedirs(src, exist_ok=True)
    t.sh(["hformat", "-l", "Classic Vol", img], env=env)
    t.sh(["hmkdir", ":Folder"], env=env)
    t.sh(["hmkdir", ":Folder:Sub"], env=env)
    t.sh(["hmkdir", ":Empty Folder"], env=env)
    for k, d in exp.items():
        p = os.path.join(src, k.replace("/", "_"))
        with open(p, "wb") as f:
            f.write(d)
        t.sh(["hcopy", "-r", p, ":" + k.replace("/", ":")], env=env)
    # Mac Roman name (0x8E = e acute) and a MacBinary II file with a resource fork
    p = os.path.join(src, "roman")
    with open(p, "wb") as f:
        f.write(b"roman name")
    t.sh(["hcopy", "-r", p, b":Folder:Caf\x8e Cr\x8fme"], env=env)
    exp["Folder/Café Crème"] = b"roman name"
    data, rsrc = text(3000, 13), b"RSRC" * 700
    p = os.path.join(src, "app.bin")
    with open(p, "wb") as f:
        f.write(macbinary(b"Tool", data, rsrc))
    t.sh(["hcopy", "-m", p, ":Folder:Tool"], env=env)
    exp["Folder/Tool"] = data
    exp["Folder/Tool:rsrc"] = rsrc
    t.sh(["humount"], env=env, check=False)
    e = with_dirs("Classic Vol", exp)
    e["Classic Vol/Empty Folder"] = None
    t.check_extract(img, e, label="classic HFS (hfsutils)", expect_type="HFS")
    typ, rows = listing(t, img)
    t.record(rows.get("Classic Vol/big.bin", {}).get("usize") == 700000, "classic HFS sizes", "")

# ---------------------------------------------------------------- DMG

def dmg_volume():
    v = H.HfsPlus("DmgVol")
    files = {"readme.txt": text(20000, 21), "bin/data.bin": blob(200000, 22) + bytes(300000) + text(9000, 23),
             nfd("한글/파일.txt"): "디스크 이미지".encode() * 300}
    for k, d in files.items():
        v.add(k, d)
    return v.build(), files

def dmg_tests(t, fs1):
    hfs, files = dmg_volume()
    exp = with_dirs("DmgVol", files)
    nd = dict(ENV, GZ_NO_DESCEND="1")
    parts = H.apm_disk(hfs)
    want_names = ["0.ddm", "1.Apple_partition_map", "2.hfs", "3.free"]
    variants = [("zlib", [H.T_ZLIB]), ("bzip2", [H.T_BZ2]), ("adc", [H.T_ADC]), ("raw", [H.T_RAW]),
                ("xz", [H.T_XZ]), ("mixed", [H.T_ZLIB, H.T_RAW, H.T_ADC, H.T_BZ2, H.T_XZ])]
    if H._lzfse is not None:
        variants += [("lzfse", [H.T_LZFSE]), ("mixed2", [H.T_LZFSE, H.T_ZLIB, H.T_ADC])]
    for name, meth in variants:
        dmg = write(t, "t_%s.dmg" % name, H.udif(parts, methods=meth, chunk_sec=64))
        t.check_extract(dmg, exp, label="dmg %s -> HFS+" % name, expect_type="HFS+ (DMG)")
        want = {n: d for n, (_, d) in zip(want_names, parts)}
        want["2.hfs"] = hfs + bytes(len(want["2.hfs"]) - len(hfs))
        t.check_extract(dmg, want, label="dmg %s partitions (names, CRC)" % name, env=nd, expect_type="DMG")
        if name in ("zlib", "bzip2", "adc", "raw") and t.tool("7z"):
            r = t.sh(["7z", "t", "-tdmg", dmg], check=False)
            t.record(r.returncode == 0, "dmg %s: builder accepted by 7-Zip (CRCs)" % name, r.stdout.decode().strip()[-60:])
        if name in ("zlib", "bzip2", "adc", "raw") and t.tool("dmg2img"):
            out = t.path("d2i_%s.img" % name)
            r = t.sh(["dmg2img", "-i", dmg, "-o", out], check=False)
            if r.returncode == 0:
                whole = b"".join(d for _, d in parts)
                got = open(out, "rb").read()
                t.record(got[:len(whole)] == whole, "dmg %s: dmg2img agrees with the builder" % name, "")
    dmg = t.path("t_zlib.dmg")
    if t.tool("7z"):
        t.check_vs_7z(dmg, label="dmg zlib vs 7z (auto-open HFS+)")
    typ, rows = listing(t, dmg, env=nd)
    aux = sorted(n for n, r in rows.items())
    t.record(typ == "DMG" and aux == want_names and rows["2.hfs"]["method"].startswith("ZLIB"),
             "dmg listing like 7-Zip", "%s %s %s" % (typ, aux, rows.get("2.hfs", {}).get("method")))
    if fs1:
        check_views(t, fs1, dmg, "dmg partition views", env=nd)
        check_views(t, fs1, t.path("t_mixed.dmg"), "dmg mixed: HFS+ file views through chunk cache")
        # zip inside HFS+ inside the DMG: nested open through two views
        inner = {"z/one.txt": b"one" * 1000, "z/two.bin": blob(70000, 30)}
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
            for k, d in inner.items():
                z.writestr(k, d)
        v = H.HfsPlus("Nest")
        v.add("pkg/inner.zip", bio.getvalue())
        nest = write(t, "nested.dmg", H.udif(H.apm_disk(v.build()), methods=[H.T_ZLIB], chunk_sec=16))
        r = subprocess.run([fs1, "n", nest, "Nest/pkg/inner.zip"], capture_output=True, timeout=120)
        out = r.stdout.decode(errors="replace").splitlines()
        got = {}
        for line in out[1:]:
            p = line.split("\t")
            if len(p) == 5:
                got[p[4]] = (int(p[1]), int(p[2]), p[3])
        want = {k: (0, len(d), "%08x" % zlib.crc32(d)) for k, d in inner.items()}
        t.record(out and out[0].startswith("TYPE\tZIP") and got == want, "zip inside HFS+ inside DMG (views)", str(out[:2]))
    # binary resource fork instead of the XML plist (old images)
    dmg = write(t, "t_rsrc.dmg", H.udif(parts, methods=[H.T_ZLIB], chunk_sec=64, use_rsrc=True))
    t.check_extract(dmg, exp, label="dmg resource-fork partition list", expect_type="HFS+ (DMG)")
    if t.tool("7z"):
        r = t.sh(["7z", "t", "-tdmg", dmg], check=False)
        t.record(r.returncode == 0, "dmg resource fork: builder accepted by 7-Zip", r.stdout.decode().strip()[-60:])
    # one partition without a map, image appended to other data, GPT-style names
    dmg = write(t, "t_single.dmg", H.udif([("whole disk (Apple_HFS : 0)", hfs)], methods=[H.T_ZLIB]))
    t.check_extract(dmg, exp, label="dmg single partition", expect_type="HFS+ (DMG)")
    dmg = write(t, "t_prefix.dmg", H.udif([("whole disk (Apple_HFS : 0)", hfs)], methods=[H.T_ZLIB], prefix=b"MZ" + bytes(4094)))
    t.check_extract(dmg, exp, label="dmg appended to other data", expect_type="HFS+ (DMG)")
    # koly at the start (a few old images): offsets relative to the image or to the header end
    body = H.udif([("whole disk (Apple_HFS : 0)", hfs)], methods=[H.T_ZLIB])
    k = bytearray(body[-512:])
    dmg = write(t, "t_front_rel.dmg", bytes(k) + body[:-512])
    t.check_extract(dmg, exp, label="dmg koly at the start (relative offsets)", expect_type="HFS+ (DMG)")
    struct.pack_into(">Q", k, 24, 512)
    struct.pack_into(">Q", k, 216, struct.unpack(">Q", k[216:224])[0] + 512)
    dmg = write(t, "t_front_abs.dmg", bytes(k) + body[:-512])
    t.check_extract(dmg, exp, label="dmg koly at the start (absolute offsets)", expect_type="HFS+ (DMG)")
    gpt = [("Protective Master Boot Record (MBR : 0)", b"\x55" * 512), ("GPT Header (Primary GPT Header : 1)", b"E" * 512),
           ("GPT Partition Data (Primary GPT Table : 2)", b"T" * 16384), ("(Apple_Free : 3)", bytes(4096)),
           ("disk image (Apple_HFS : 4)", hfs), ("(Apple_Free : 5)", bytes(4096)),
           ("GPT Partition Data (Backup GPT Table : 6)", b"T" * 16384), ("GPT Header (Backup GPT Header : 7)", b"E" * 512)]
    dmg = write(t, "t_gpt.dmg", H.udif(gpt, methods=[H.T_ZLIB]))
    t.check_extract(dmg, exp, label="dmg GPT layout -> HFS+", expect_type="HFS+ (DMG)")
    typ, rows = listing(t, dmg, env=nd)
    want = ["0.MBR", "1.Primary GPT Header", "2.Primary GPT Table", "3.free", "4.hfs", "5.free",
            "6.Backup GPT Table", "7.Backup GPT Header"]
    t.record(sorted(rows) == sorted(want), "dmg GPT partition names like 7-Zip", str(sorted(rows)))
    if t.tool("7z"):
        r = t.sh(["7z", "l", "-tdmg", dmg], check=False)
        out = r.stdout.decode(errors="replace")
        t.record(all(w in out for w in want), "dmg GPT names match 7-Zip's listing", "")
    # two file systems: no automatic descent, both listed; 12 partitions: two-digit names
    many = [("part %d (Apple_HFS : %d)" % (i, i), hfs if i in (3, 9) else bytes(1024)) for i in range(12)]
    dmg = write(t, "t_many.dmg", H.udif(many, methods=[H.T_ZLIB]))
    typ, rows = listing(t, dmg)
    t.record(typ == "DMG" and "03.hfs" in rows and "11.hfs" in rows, "dmg 12 partitions: zero-padded names, no descent",
             "%s %s" % (typ, sorted(rows)[:4]))
    # names without "(Type : n)": 7-Zip's "<n>_<name>"
    dmg = write(t, "t_plain.dmg", H.udif([("Plain Name", bytes(2048)), ("whole disk (Apple_HFS : 1)", hfs)]))
    typ, rows = listing(t, dmg, env=nd)
    t.record(sorted(rows) == ["0_Plain Name", "1.hfs"], "dmg plain partition names", str(sorted(rows)))
    # plumbing is recognised by the partition type, not by the volume name
    dmg = write(t, "t_driver.dmg", H.udif([("Driver Descriptor Map (DDM : 0)", bytes(512)),
                                           ("My Driver Disk (Apple_HFS : 1)", hfs), ("(Apple_Free : 2)", bytes(1024))]))
    t.check_extract(dmg, exp, label="dmg volume named 'Driver': still opened", expect_type="HFS+ (DMG)")
    # encrypted images
    enc = write(t, "enc2.dmg", b"encrcdsa" + struct.pack(">I", 2) + blob(8000, 40))
    open_error(t, enc, 5, "dmg encrcdsa (v2 encrypted) -> GZ_E_METHOD")
    enc = write(t, "enc1.dmg", blob(8000, 41) + b"cdsaencr")
    open_error(t, enc, 5, "dmg cdsaencr (v1 encrypted) -> GZ_E_METHOD")
    # bad partition checksum, unknown chunk type
    good = H.udif([("whole disk (Apple_HFS : 0)", hfs)], methods=[H.T_ZLIB])
    bad = bytearray(good)
    m = mish_patch(bad, lambda mb: mb[:72] + struct.pack(">I", struct.unpack(">I", mb[72:76])[0] ^ 1) + mb[76:])
    dmg = write(t, "badcrc.dmg", bytes(m))
    entry_status(t, dmg, "0.hfs", 4, "dmg partition CRC mismatch -> GZ_E_CRC", env=nd)
    m = mish_patch(bytearray(good), lambda mb: set_chunk(mb, 1, typ=0x80000009))
    dmg = write(t, "unkchunk.dmg", bytes(m))
    entry_status(t, dmg, "0.hfs", 5, "dmg unknown chunk type -> GZ_E_METHOD", env=nd)

# ---------------------------------------------------------------- real images (downloaded, see tests/data/dmg/README.md)

SAMPLES = [
    ("https://www.libsdl.org/release/SDL-1.2.9.dmg", "cb0a6f390e39f33b22914cf282967ab8a370eaa8d11b9e64db9dea2ebff974e2"),
    ("https://www.libsdl.org/release/SDL2-2.0.0.dmg", "9dca7ee5273947ca3276515e61f51b99687f763a8616fcb1ebbeef1de485dde7"),
    ("https://www.libsdl.org/release/SDL2-2.30.10.dmg", "b946bdc9bd1288483052531285af445c15585201f084c7fa74a22d05b449d6ca"),
]
_offline = []

def fetch(t, url, sha):
    """download into the work directory (cached, checked); None when offline"""
    import hashlib, urllib.request
    p = os.path.join(t.work, "dl", os.path.basename(url))
    if os.path.exists(p) and hashlib.sha256(open(p, "rb").read()).hexdigest() == sha:
        return p
    if _offline:
        return None
    os.makedirs(os.path.dirname(p), exist_ok=True)
    try:
        d = urllib.request.urlopen(url, timeout=30).read(8 << 20)
    except Exception:
        _offline.append(url)
        return None
    if hashlib.sha256(d).hexdigest() != sha:
        return None
    with open(p + ".part", "wb") as f:
        f.write(d)
    os.replace(p + ".part", p)
    return p

def real_dmgs(t):
    for url, sha in SAMPLES:
        p = fetch(t, url, sha)
        if not p:
            continue
        name = os.path.basename(p)
        if t.tool("7z"):
            t.check_vs_7z(p, label="real %s vs 7z" % name, allow_extra=True, expect_type="HFS+ (DMG)")
        r, rows, out = t.extract(p, env=dict(ENV, GZ_NO_DESCEND="1"))
        bad = [n for (st, d, z, n) in rows.values() if st]
        t.record(r.returncode == 0 and rows and not bad, "real %s: every partition CRC OK" % name, str(bad))

# ---------------------------------------------------------------- mish surgery for hostile images

def find_plist(d):
    k = d[-512:]
    xo, xl = struct.unpack(">QQ", k[216:232])
    return xo, xl

def mish_patch(d, fn, which=0):
    """decode the base64 mish of partition `which`, apply fn, re-encode in place (XML rebuilt)"""
    xo, xl = find_plist(d)
    x = bytes(d[xo:xo + xl]).decode()
    pos = 0
    for _ in range(which + 1):
        a = x.index("<data>", pos) + 6
        b = x.index("</data>", a)
        pos = b
    mb = bytearray(base64.b64decode("".join(x[a:b].split())))
    mb = fn(mb)
    x2 = (x[:a] + "\n" + base64.b64encode(bytes(mb)).decode() + "\n" + x[b:]).encode()
    k = bytearray(d[-512:])
    struct.pack_into(">Q", k, 224, len(x2))
    return bytes(d[:xo]) + x2 + bytes(k)

def set_chunk(mb, i, typ=None, sec=None, nsec=None, off=None, length=None):
    cnt = struct.unpack(">I", mb[200:204])[0]
    i = max(0, min(i, cnt - 2))                    # small partitions have few chunks
    o = 204 + 40 * i
    t, c, s, n, of, ln = struct.unpack(">IIQQQQ", mb[o:o + 40])
    mb[o:o + 40] = struct.pack(">IIQQQQ", t if typ is None else typ, c, s if sec is None else sec,
                               n if nsec is None else nsec, of if off is None else off, ln if length is None else length)
    return mb

def hostile(t):
    hfs, files = dmg_volume()
    good = H.udif(H.apm_disk(hfs), methods=[H.T_ZLIB, H.T_ADC, H.T_BZ2], chunk_sec=32)
    cases = {
        "chunk count huge": lambda mb: mb[:200] + struct.pack(">I", 0xFFFFFFF0) + mb[204:],
        "chunk offset past end": lambda mb: set_chunk(mb, 2, off=1 << 40),
        "chunk length huge": lambda mb: set_chunk(mb, 2, length=1 << 50),
        "sector count huge": lambda mb: mb[:16] + struct.pack(">Q", 1 << 62) + mb[24:],
        "chunk sectors huge": lambda mb: set_chunk(mb, 2, nsec=1 << 60),
        "chunks overlap": lambda mb: set_chunk(mb, 3, sec=0),
        "compressed chunk 1 GiB": lambda mb: set_chunk(mb, 2, nsec=2 << 21),
        "data offset huge": lambda mb: mb[:24] + struct.pack(">Q", (1 << 64) - 512) + mb[32:],
        "truncated mish": lambda mb: mb[:230],
        "not mish": lambda mb: b"hsim" + mb[4:],
        "chunk data garbage": lambda mb: set_chunk(mb, 3, off=0, length=4000),
    }
    for i, (lab, fn) in enumerate(cases.items()):
        for which in (0, 2):
            p = write(t, "h_dmg_%d_%d.dmg" % (i, which), mish_patch(bytearray(good), fn, which))
            t.check_hostile(p, label="dmg hostile: %s (partition %d)" % (lab, which))
    xo, xl = find_plist(good)
    k = bytearray(good[-512:])
    struct.pack_into(">QQ", k, 216, xo, 1 << 40)
    t.check_hostile(write(t, "h_dmg_xmlhuge.dmg", good[:-512] + bytes(k)), label="dmg hostile: XML length huge")
    struct.pack_into(">QQ", k, 216, len(good) - 100, 50)
    t.check_hostile(write(t, "h_dmg_xmlbad.dmg", good[:-512] + bytes(k)), label="dmg hostile: XML points at koly")
    t.check_hostile(write(t, "h_dmg_trunc.dmg", good[:len(good) // 2] + good[-512:]), label="dmg hostile: data fork truncated")
    x = good[xo:xo + xl].replace(b"</dict>", b"")
    k = bytearray(good[-512:])
    struct.pack_into(">Q", k, 224, len(x))
    t.check_hostile(write(t, "h_dmg_xmlcut.dmg", good[:xo] + x + bytes(k)), label="dmg hostile: XML without </dict>")
    r = H.rsrc_fork([("disk (Apple_HFS : 0)", b"mish" + bytes(300))])
    r = r[:16] + b"\xff" * 8 + r[24:]
    t.check_hostile(write(t, "h_dmg_rsrc.dmg", r + H.koly(0, 0, 0, 1, [0], 0, 0, len(r))), label="dmg hostile: resource fork garbage")

    # HFS+ structures
    v, _ = basic_volume()
    img = bytearray(v.build())
    bs = 4096
    vh = img[1024:1536]
    cat_start = struct.unpack(">I", vh[272 + 16:272 + 20])[0] * bs
    ns = struct.unpack(">H", img[cat_start + 14 + 18:cat_start + 14 + 20])[0]
    first_leaf = struct.unpack(">I", img[cat_start + 14 + 10:cat_start + 14 + 14])[0]

    def variant(name, fn):
        b = bytearray(img)
        fn(b)
        t.check_hostile(write(t, "h_hfs_%s.img" % name, bytes(b)), label="hfs+ hostile: %s" % name.replace("_", " "))
    leaf = cat_start + first_leaf * ns
    variant("leaf_loop", lambda b: struct.pack_into(">I", b, leaf, first_leaf))
    variant("leaf_far", lambda b: struct.pack_into(">I", b, leaf, 0xFFFFFFF0))
    variant("record_offsets", lambda b: struct.pack_into(">HH", b, leaf + ns - 4, 0xFFF0, 3))
    variant("numrecords_huge", lambda b: struct.pack_into(">H", b, leaf + 10, 0xFFFF))
    variant("node_size", lambda b: struct.pack_into(">H", b, cat_start + 14 + 18, 7))
    variant("total_nodes", lambda b: struct.pack_into(">I", b, cat_start + 14 + 22, 0xFFFFFFFF))
    variant("block_size", lambda b: struct.pack_into(">I", b, 1024 + 40, 0x10000000))
    variant("total_blocks", lambda b: struct.pack_into(">I", b, 1024 + 44, 1))
    variant("catalog_extent", lambda b: struct.pack_into(">II", b, 1024 + 272 + 16, 0xFFFFFF00, 0x1000))
    variant("catalog_size", lambda b: struct.pack_into(">Q", b, 1024 + 272, 1 << 62))
    variant("key_lengths", lambda b: [struct.pack_into(">H", b, leaf + o, 0xFFFF) for o in range(14, 2000, 98)])

    def parent_cycle(b):
        # make folders their own ancestors: rewrite parent IDs of the leaf's records
        n = struct.unpack(">H", b[leaf + 10:leaf + 12])[0]
        for i in range(n):
            o = struct.unpack(">H", b[leaf + ns - 2 * (i + 1):leaf + ns - 2 * i])[0]
            struct.pack_into(">I", b, leaf + o + 2, 16 + (i % 3))
    variant("parent_cycle", parent_cycle)
    # extents overflow chain that does not advance / leaves the volume
    v = H.HfsPlus("Frag")
    v.add("frag.bin", blob(200000, 50), fragment=20)
    img2 = bytearray(v.build())
    ext_start = struct.unpack(">I", img2[1024 + 192 + 16:1024 + 192 + 20])[0] * bs
    leaf2 = ext_start + struct.unpack(">I", img2[ext_start + 14 + 10:ext_start + 14 + 14])[0] * 4096

    def ext_bad(b):
        struct.pack_into(">II", b, leaf2 + 14 + 12, 0xFFFFFFF0, 0x20)        # first overflow extent
    def ext_zero(b):
        struct.pack_into(">I", b, leaf2 + 14 + 8, 0)                          # start block 0: never matches
    img = img2
    variant("overflow_extent_outside", ext_bad)
    variant("overflow_start_mismatch", ext_zero)
    # decmpfs: huge sizes, bad tables
    v = H.HfsPlus("Cmp")
    it = v.add("a.txt", text(200000, 51))
    v.compress(it, "zlib-rsrc")
    it = v.add("b.txt", text(200000, 52))
    v.compress(it, "lzvn-rsrc")
    it = v.add("c.txt", b"tiny" * 1000)
    v.compress(it, "zlib-inline")
    it.decmpfs = it.decmpfs[:8] + struct.pack("<Q", 1 << 50) + it.decmpfs[16:]
    img = bytearray(v.build())
    variant("decmpfs_rsrc_tables", lambda b: [b.__setitem__(slice(i, i + 4), b"\xff\xff\xff\x7f")
                                              for i in range(0, len(b) - 4, 4) if b[i:i + 4] == struct.pack("<I", 4 * 5)])
    t.check_hostile(write(t, "h_hfs_decmpfs_huge.img", bytes(img)), label="hfs+ hostile: decmpfs size 1 PiB inline")

def mish_fuzz(t):
    """structure-aware: random chunk types / sectors / offsets / lengths in decoded mish tables"""
    rnd = random.Random(1234)
    hfs, files = dmg_volume()
    goods = [H.udif(H.apm_disk(hfs), methods=[H.T_ZLIB, H.T_ADC, H.T_BZ2, H.T_XZ, H.T_RAW], chunk_sec=16),
             H.udif([("whole disk (Apple_HFS : 0)", hfs)], methods=[H.T_RAW, H.T_ZLIB], chunk_sec=8)]
    special = [0, 1, 2, 511, 512, 0x7FFFFFFF, 0xFFFFFFFF, 1 << 32, 1 << 40, 1 << 63, (1 << 64) - 1]
    types = [0, 1, 2, 0x7FFFFFFE, 0xFFFFFFFF, 0x80000004, 0x80000005, 0x80000006, 0x80000007, 0x80000008]

    def mutate(mb):
        cnt = struct.unpack(">I", mb[200:204])[0]
        for _ in range(rnd.randrange(1, 5)):
            if rnd.random() < 0.15:
                off = rnd.choice([16, 24, 64, 68, 72, 200])
                w = 4 if off in (64, 68, 72, 200) else 8
            else:
                f = rnd.randrange(6)
                off = 204 + 40 * rnd.randrange(max(cnt, 1)) + [0, 4, 8, 16, 24, 32][f]
                w = 4 if f < 2 else 8
            if off + w > len(mb):
                continue
            old = int.from_bytes(mb[off:off + w], "big")
            v = rnd.choice([rnd.choice(special), rnd.getrandbits(8 * w), old + rnd.randrange(-3, 4)])
            if w == 4 and off >= 204 and (off - 204) % 40 == 0:
                v = rnd.choice(types)
            mb[off:off + w] = (v % (1 << (8 * w))).to_bytes(w, "big")
        return mb
    iters = max(20, int(os.environ.get("GZ_FUZZ_ITERS", "150")) // 2)
    bad = []
    p = t.path("mishfuzz.dmg")
    for it in range(iters):
        with open(p, "wb") as f:
            f.write(mish_patch(bytearray(goods[it % 2]), mutate, rnd.randrange(4) if it % 2 == 0 else 0))
        for env in (ENV, dict(ENV, GZ_NO_DESCEND="1")):
            try:
                r, rows, out = t.extract(p, env=env, timeout=60)
            except subprocess.TimeoutExpired:
                bad.append("%d timeout" % it)
                continue
            err = r.stderr.decode(errors="replace")
            if r.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err:
                bad.append("%d rc=%d %s" % (it, r.returncode, err[-200:]))
    t.record(not bad, "dmg mish structure fuzz (%d tables)" % iters, "; ".join(bad[:3]))

def fuzz(t, seeds):
    drv = t.build_driver("tests/drivers/imgfuzz.c")
    iters = int(os.environ.get("GZ_FUZZ_ITERS", "150"))
    for i, p in enumerate(seeds):
        if not os.path.exists(p):
            continue
        r = t.sh([drv, p, str(iters), str(4000 + i)], check=False, timeout=900)
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        ok = r.returncode == 0 and "ok %d" % iters in out and "Sanitizer" not in out and "runtime error" not in out
        t.record(ok, "fuzz " + os.path.basename(p), out.strip()[-300:])
    for p in seeds[:3]:
        r = t.sh([drv, "-t", p], check=False, timeout=600)
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        t.record(r.returncode == 0 and out.startswith("ok"), "threads " + os.path.basename(p), out.strip()[-200:])

def run(t):
    fs1 = None
    try:
        fs1 = t.build_driver("tests/drivers/fs1_dump.c", name="fs1_dump_dmg")
    except Exception as e:
        t.record(False, "build fs1_dump driver", str(e)[-300:])
    hfs_basic(t, fs1)
    hfs_compressed(t, fs1)
    hfs_links(t, fs1)
    hfs_variants(t, fs1)
    hfs_classic(t)
    dmg_tests(t, fs1)
    real_dmgs(t)
    hostile(t)
    mish_fuzz(t)
    seeds = [t.path(n) for n in ("t_mixed.dmg", "t_lzfse.dmg", "compressed.hfs", "basic.hfs", "links.hfs",
                                 "hfsx.img", "t_rsrc.dmg", "t_xz.dmg", "classic.hfs", "fragcat.img")]
    fuzz(t, seeds)
