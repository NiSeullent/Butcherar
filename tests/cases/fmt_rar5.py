"""RAR 5.0 reader + unpacker tests.

Fixtures
  * libarchive's RAR5 test archives (uuencoded in its source tarball, fetched once
    from the Ubuntu archive pool into the test-data cache) and the samples of the
    PyPI package rarfile (sdist) - methods, solid, filters, BLAKE2, volumes, -p/-hp
    encryption, links, versions, comments, SFX and libarchive's malformed files.
    Expected contents come from 7-Zip (t.check_vs_7z); passwords are the ones
    documented by those test suites ("password", "password2").
  * tests/data/rar5: a few of those archives committed for offline runs.
  * tests/drivers/rar5_tool.c: a RAR5 writer with its own LZ/Huffman encoder for the
    features real samples rarely have (all four filters at many offsets, table reuse,
    tiny blocks, long distances, big dictionaries, solid + encryption + HMAC sums,
    volumes in both naming styles, RAR7 algorithm). Its archives are checked with
    7-Zip where 7-Zip supports the feature.
Hostile input: libarchive's malformed archives, truncated / bit-flipped variants
through gzt, and the in-process mutation fuzzer of rar5_tool (under ASan/UBSan when
HOST_CFLAGS asks for it).
"""
import os, re, glob, json, shutil, random, binascii, tarfile, subprocess, urllib.request, time

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data", "rar5")
CACHE = os.environ.get("GZ_TESTDATA") or os.path.join(os.path.expanduser("~"), ".cache", "gogitzip-testdata")
POOL = "http://archive.ubuntu.com/ubuntu/pool/main/liba/libarchive/"
SANITIZED = "sanitize" in os.environ.get("HOST_CFLAGS", "")

# ---------------------------------------------------------------- fixtures

def fetch(url, name):
    os.makedirs(CACHE, exist_ok=True)
    p = os.path.join(CACHE, name)
    if os.path.exists(p) and os.path.getsize(p):
        return p
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            data = r.read()
    except Exception:
        return None
    with open(p + ".tmp", "wb") as f:
        f.write(data)
    os.replace(p + ".tmp", p)
    return p

def libarchive_tarball():
    os.makedirs(CACHE, exist_ok=True)
    have = sorted(glob.glob(os.path.join(CACHE, "libarchive_*.orig.tar.*")))
    have = [h for h in have if not h.endswith(".asc") and not h.endswith(".tmp")]
    if have:
        return have[-1]
    try:
        with urllib.request.urlopen(POOL, timeout=30) as r:
            idx = r.read().decode("latin-1")
    except Exception:
        return None
    names = set(re.findall(r'libarchive_([0-9.]+)\.orig\.tar\.(xz|gz)"', idx))
    if not names:
        return None
    ver, ext = max(names, key=lambda v: [int(x) for x in v[0].split(".") if x.isdigit()])
    fn = "libarchive_%s.orig.tar.%s" % (ver, ext)
    return fetch(POOL + fn, fn)

def uudecode(text):
    out = bytearray()
    started = False
    for line in text.splitlines():
        if line.startswith(b"begin "):
            started = True
            continue
        if not started or not line:
            continue
        if line.strip() == b"end":
            break
        try:
            out += binascii.a2b_uu(line)
        except binascii.Error:
            n = (((line[0] - 32) & 63) * 4 + 5) // 3
            out += binascii.a2b_uu(line[:n])
    return bytes(out)

def libarchive_samples(t):
    tb = libarchive_tarball()
    if not tb:
        return None
    d = t.path("la")
    os.makedirs(d, exist_ok=True)
    if not glob.glob(os.path.join(d, "*.rar")):
        with tarfile.open(tb) as tf:
            for m in tf.getmembers():
                b = os.path.basename(m.name)
                if b.startswith("test_read_format_rar5") and b.endswith(".uu") and m.isfile():
                    data = uudecode(tf.extractfile(m).read())
                    open(os.path.join(d, b[:-3]), "wb").write(data)
    return d

def rarfile_samples(t):
    p = None
    have = sorted(glob.glob(os.path.join(CACHE, "rarfile-*.tar.gz")))
    if have:
        p = have[-1]
    else:
        try:
            with urllib.request.urlopen("https://pypi.org/pypi/rarfile/json", timeout=30) as r:
                info = json.loads(r.read().decode())
            sd = [u for u in info["urls"] if u["packagetype"] == "sdist"]
            if sd:
                p = fetch(sd[0]["url"], sd[0]["filename"])
        except Exception:
            p = None
    if not p:
        return None
    d = t.path("rf")
    os.makedirs(d, exist_ok=True)
    if not glob.glob(os.path.join(d, "rar5-*")):
        with tarfile.open(p) as tf:
            for m in tf.getmembers():
                b = os.path.basename(m.name)
                if "/test/files/" in m.name and m.isfile() and b.startswith("rar5-") and not b.endswith(".exp"):
                    open(os.path.join(d, b), "wb").write(tf.extractfile(m).read())
    return d

# ---------------------------------------------------------------- helpers

def manifest(t, arc, pw=None):
    """gzt x rows: {name: (status, is_dir, data or None)} and stderr"""
    r, rows, out = t.extract(arc, pw=pw)
    res = {}
    for i, (st, isdir, size, name) in rows.items():
        fp = os.path.join(out, "%d.bin" % i)
        res[name] = (st, isdir, open(fp, "rb").read() if os.path.exists(fp) and not isdir else None)
    return r, res

def check_rows(t, label, arc, expect, pw=None, exact=True):
    """expect: {name: bytes | int status | None (dir)}"""
    r, res = manifest(t, arc, pw)
    if r.returncode:
        return t.record(False, label, "driver failed: " + r.stdout.decode(errors="replace")[:200])
    probs = []
    for k, v in expect.items():
        if k not in res:
            probs.append("missing " + k); continue
        st, isdir, data = res[k]
        if v is None:
            if not isdir: probs.append("not a dir " + k)
        elif isinstance(v, int):
            if st != v: probs.append("%s: status %d want %d" % (k, st, v))
        elif st != 0 or data != v:
            probs.append("%s: status %d data %s" % (k, st, "ok" if data == v else "bad"))
    if exact:
        for k in res:
            if k not in expect: probs.append("unexpected " + k)
    return t.record(not probs, label, "; ".join(probs[:6]))

def listing_map(t, arc, env=None):
    """gzt l rows by name (the name column carries " -> target" for links)"""
    r, typ, rows = t.listing(arc, env=env)
    return r, typ, {row["name"].split(" -> ")[0]: row for row in rows}

def text_data(n, seed):
    r = random.Random(seed)
    words = [bytes(r.choice(b"abcdefghijklmnopqrstuvwxyz") for _ in range(r.randint(2, 9))) for _ in range(500)]
    out = bytearray()
    while len(out) < n:
        out += r.choice(words) + (b"\n" if r.random() < 0.1 else b" ")
    return bytes(out[:n])

def exe_data(n, seed):
    r = random.Random(seed)
    out = bytearray()
    while len(out) < n:
        k = r.random()
        if k < 0.25:
            out += b"\xe8" + r.randint(0, 0x40000).to_bytes(4, "little")
        elif k < 0.35:
            out += b"\xe9" + (0x100000000 - r.randint(1, 0x40000)).to_bytes(4, "little")
        elif k < 0.55:
            out += r.randint(0, 0xffffff).to_bytes(3, "little") + b"\xeb"
        elif k < 0.6:
            out += b"\xe8" + r.randint(0xfff000, 0x1000000).to_bytes(4, "little")
        else:
            out += bytes(r.getrandbits(8) for _ in range(r.randint(1, 12)))
    return bytes(out[:n])

def wav_data(n, seed):
    r = random.Random(seed)
    out = bytearray()
    a = b = 0
    while len(out) < n:
        a = (a + r.randint(-3, 3)) & 0xffff
        b = (b + r.randint(-5, 5)) & 0xffff
        out += a.to_bytes(2, "little") + b.to_bytes(2, "little") + bytes([r.getrandbits(2)])
    return bytes(out[:n])

class Maker:
    """rar5_tool make wrapper: inputs written once, archive checked by 7-Zip."""
    def __init__(self, t, tool):
        self.t, self.tool = t, tool
        self.src = t.path("gen_src")
        os.makedirs(self.src, exist_ok=True)
        self.files = {
            "doc/text.txt": text_data(400000, 1),
            "bin/prog.exe": exe_data(300000, 2),
            "media/sound.wav": wav_data(200000, 3),
            "random.bin": random.Random(4).randbytes(6000),
            "zeros.bin": b"\0" * 90000,
            "tiny.txt": b"abc",
            "empty.txt": b"",
            "한글 이름.txt": "안녕하세요 RAR5\n".encode() * 50,
        }
        for k, v in self.files.items():
            p = os.path.join(self.src, k.replace("/", "_"))
            open(p, "wb").write(v)

    def entries(self, names=None):
        names = names or list(self.files)
        return ["%s=%s" % (k, os.path.join(self.src, k.replace("/", "_"))) for k in names]

    def make(self, name, args, entries=None):
        arc = self.t.path("gen", name)
        base = arc.replace("%d", "")
        for f in glob.glob(os.path.join(os.path.dirname(arc), os.path.basename(base).split(".")[0] + ".*")):
            os.remove(f)
        r = subprocess.run([self.tool, "make", arc] + args + (entries if entries is not None else self.entries()),
                           capture_output=True, timeout=600)
        if r.returncode:
            self.t.record(False, "make " + name, r.stderr.decode(errors="replace")[-300:])
            return None
        return arc.replace("%d", "1") if "%d" in arc else arc

# ---------------------------------------------------------------- test groups

def test_real_samples(t, la, rf):
    """every sample 7-Zip extracts: identical results"""
    if la:
        for n in ["compressed", "blake2", "arm", "extra_field_version", "fileattr", "hardlink",
                  "multiarchive.part01", "multiarchive_solid.part01", "multiple_files", "multiple_files_solid",
                  "owner", "solid", "stored", "stored_manyfiles", "unicode", "win32", "zip_in_rar"]:
            p = os.path.join(la, "test_read_format_rar5_%s.rar" % n)
            if os.path.exists(p):
                t.check_vs_7z(p, label="libarchive " + n, allow_extra=n in ("unicode",))
        p = os.path.join(la, "test_read_format_rar5_sfx.exe")
        if os.path.exists(p):
            t.check_vs_7z(p, label="libarchive sfx.exe", expect_type="RAR5")
        z = os.path.join(la, "test_read_format_rar5_extra_data_size_toolong.rar.Z")
        if os.path.exists(z):
            raw = t.sh(["gzip", "-dc", z], check=False).stdout
            if raw:
                p = t.path("extra_data_size_toolong.rar")
                open(p, "wb").write(raw)
                t.check_hostile(p)
        for n in ["encrypted_filenames", "solid_encrypted", "solid_encrypted_filenames"]:
            t.check_vs_7z(os.path.join(la, "test_read_format_rar5_%s.rar" % n), pw="password", label="libarchive " + n)
        # a.txt / c.txt plain, b.txt "password", d.txt "password2"
        enc = os.path.join(la, "test_read_format_rar5_encrypted.rar")
        check_rows(t, "libarchive encrypted (password)", enc, {
            "a.txt": b"This is from a.txt", "b.txt": b"This is from b.txt",
            "c.txt": b"This is from c.txt", "d.txt": 6}, pw="password")
        check_rows(t, "libarchive encrypted (password2)", enc, {
            "a.txt": b"This is from a.txt", "b.txt": 6, "c.txt": b"This is from c.txt",
            "d.txt": b"This is from d.txt"}, pw="password2")
        check_rows(t, "libarchive solid_encrypted without password", os.path.join(la, "test_read_format_rar5_solid_encrypted.rar"),
                   {"a.txt": 6, "b.txt": 6, "c.txt": 6, "d.txt": 6})
        r, typ, rows = t.listing(os.path.join(la, "test_read_format_rar5_encrypted_filenames.rar"))
        t.record(b"OPEN_ERROR 6" in r.stdout, "libarchive -hp without password: GZ_E_PASSWORD", r.stdout[:80])
        sym = os.path.join(la, "test_read_format_rar5_symlink.rar")
        r, typ, m = listing_map(t, sym)
        ok = m.get("symlink.txt", {}).get("method") == "Symlink" and m.get("dirlink", {}).get("is_dir") == 0
        t.record(ok and b"symlink.txt -> file.txt" in r.stdout and b"dirlink -> dir" in r.stdout,
                 "libarchive symlink listing", r.stdout.decode(errors="replace")[-200:])
        check_rows(t, "libarchive symlink data", sym, {"file.txt": b"1234\n", "symlink.txt": 0, "dirlink": 0, "dir": None})
        # parsers must skip padding at the end of headers and unknown skippable headers
        for n in ["main_block_extra_bytes", "skip_block_extra_bytes"]:
            check_rows(t, "libarchive " + n, os.path.join(la, "test_read_format_rar5_%s.rar" % n),
                       {"helloworld.txt": b"hello libarchive test suite!\n"})
        r, typ, m = listing_map(t, os.path.join(la, "test_read_format_rar5_solid.rar"))
        t.record(typ == "RAR5" and all(v["method"] == "m5:1M" for v in m.values()) and len(m) == 7,
                 "listing methods (m5:1M)", str([v["method"] for v in m.values()]))
    if rf:
        for p in sorted(glob.glob(os.path.join(rf, "rar5-*.rar"))):
            b = os.path.basename(p)
            if b in ("rar5-readonly-win.rar",) or ".part2" in b or ".part3" in b:
                continue                       # RAR4 despite its name / later volumes
            links = "symlink" in b or "evil" in b
            if links:
                continue
            t.check_vs_7z(p, pw="password", label="rarfile " + b)
        for n in ("rar5-vols.part2.rar", "rar5-vols.part3.rar"):
            # opening a later volume starts from the first one
            r, out = t.sevenzip_extract(os.path.join(rf, "rar5-vols.part1.rar"))
            t.check_extract(os.path.join(rf, n), t.read_tree(out), label="rarfile %s (from part1)" % n)
        r, typ, m = listing_map(t, os.path.join(rf, "rar5-symlink-unix.rar"))
        t.record(m.get("data_link", {}).get("mode") == 0o120777 and b"random_link -> ../random123" in r.stdout,
                 "rarfile unix symlinks", r.stdout.decode(errors="replace")[-200:])
        r, typ, m = listing_map(t, os.path.join(rf, "rar5-symlink-win.rar"))
        t.record(m.get("links/dir_link", {}).get("is_dir") == 0 and b"links/file_link -> ../content/file.txt" in r.stdout,
                 "rarfile windows symlinks / junctions", r.stdout.decode(errors="replace")[-300:])
        r, typ, m = listing_map(t, os.path.join(rf, "rar5-hlink.rar"))
        t.record(m.get("stest2.txt", {}).get("method") == "Hardlink" and b"stest3.txt -> stest1.txt" in r.stdout,
                 "rarfile hard links", r.stdout.decode(errors="replace")[-200:])
        r, typ, m = listing_map(t, os.path.join(rf, "rar5-versions.rar"))
        t.record(set(m) == {"[VER]/1/versioned.txt", "[VER]/2/versioned.txt", "versioned.txt"},
                 "rarfile file versions as [VER]/n/", str(sorted(m)))
        hp = os.path.join(rf, "rar5-hpsw.rar")
        r, rows, out = t.extract(hp, pw="password")
        t.record(b"comment: RAR5 archive - hdr-password" in r.stderr, "rarfile -hp comment", r.stderr[-200:])
        r, rows, out = t.extract(hp, pw="wrong")
        t.record(b"OPEN_ERROR 6" in r.stdout, "rarfile -hp wrong password", r.stdout[:80])
        check_rows(t, "rarfile -p wrong password", os.path.join(rf, "rar5-psw.rar"),
                   {"stest1.txt": 6, "stest2.txt": 6}, pw="wrong")
        r, rows, out = t.extract(os.path.join(rf, "rar5-blake.rar"))
        t.record(b"comment: RAR5 archive - blake" in r.stderr, "rarfile comment", r.stderr[-200:])
        r, typ, m = listing_map(t, os.path.join(rf, "rar5-psw.rar"))
        t.record(m.get("stest1.txt", {}).get("method") == "m3:128K AES" and m.get("stest2.txt", {}).get("method") == "Store AES",
                 "listing methods with AES", str({k: v["method"] for k, v in m.items()}))
        t.check_hostile(os.path.join(rf, "rar5-evil-symlink-traversal.rar"))

def test_committed(t):
    """offline fixtures (copies of upstream samples, see tests/data/rar5/README.md)"""
    exp = {
        "compressed.rar": None, "solid.rar": None, "blake2.rar": None, "win32.rar": None,
        "multiarchive_solid.part01.rar": None, "rar5-dups.rar": "password", "rar5-psw-blake.rar": "password",
        "rar5-hpsw.rar": "password",
    }
    for n, pw in exp.items():
        p = os.path.join(DATA, n)
        if os.path.exists(p):
            if shutil.which("7z"):
                t.check_vs_7z(p, pw=pw, label="committed " + n)
            else:
                r, res = manifest(t, p, pw)
                t.record(r.returncode == 0 and all(v[0] == 0 for v in res.values()), "committed " + n)

def test_generated(t, mk):
    F = mk.files
    plain = {k: v for k, v in F.items()}
    cases = [
        ("store.rar", ["-m", "0"], None),
        ("m1.rar", ["-m", "1", "-d", "17"], None),
        ("m3.rar", ["-m", "3", "-d", "20", "-host", "0"], None),
        ("e8.rar", ["-m", "5", "-f", "e8"], None),
        ("e8e9.rar", ["-m", "5", "-f", "e8e9", "-flen", "200000"], None),
        ("arm.rar", ["-m", "5", "-f", "arm"], None),
        ("delta.rar", ["-m", "5", "-f", "delta"], None),
        ("mixblocks.rar", ["-m", "5", "-f", "mix", "-flen", "3000", "-blk", "7000", "-reuse"], None),
        ("tinyblocks.rar", ["-m", "2", "-blk", "300", "-reuse", "-depth", "64"], None),
        ("solid.rar", ["-s", "-m", "4", "-f", "mix", "-reuse", "-blk", "60000"], None),
        ("solid_b2.rar", ["-s", "-m", "3", "-b2"], None),
        ("both.rar", ["-m", "3", "-both"], None),
        ("aes.rar", ["-m", "3", "-p", "Pässwörd ✓", "-lg2", "5"], "Pässwörd ✓"),
        ("aes_mac.rar", ["-m", "3", "-p", "secret", "-lg2", "5", "-mac", "-both"], "secret"),
        ("aes_solid.rar", ["-s", "-m", "3", "-p", "secret", "-lg2", "15", "-mac", "-b2", "-f", "mix"], "secret"),
        ("hp.rar", ["-m", "3", "-p", "secret", "-hp", "-lg2", "5", "-mac", "-cmt", "comment über alles"], "secret"),
        ("vols.part%d.rar", ["-m", "3", "-vol", "90000", "-s", "-f", "mix"], None),
        ("vols_hp.part%d.rar", ["-m", "3", "-vol", "70000", "-p", "secret", "-hp", "-lg2", "5"], "secret"),
        ("vols_store.part%d.rar", ["-m", "0", "-vol", "65536", "-p", "x", "-lg2", "4", "-b2"], "x"),
    ]
    for name, args, pw in cases:
        arc = mk.make(name, args)
        if arc:
            t.check_vs_7z(arc, pw=pw, label="generated " + name)
    # old volume naming (7-Zip only follows partN names for RAR5): content check
    arc = mk.make("oldvol.rar", ["-m", "3", "-vol", "80000", "-vold", "-s"])
    if arc:
        t.check_extract(arc, plain, label="generated old-style volumes .rar/.r00/...")
        r00 = arc[:-4] + ".r01"
        t.check_extract(r00, plain, label="generated old-style volumes opened at .r01")
    # SFX with a fake executable stub that contains decoy "Rar!" bytes
    arc = mk.make("sfx.exe", ["-m", "3", "-sfx", "150000"])
    if arc:
        t.check_extract(arc, plain, label="generated SFX stub", expect_type="RAR5")
    # RAR 7.0 algorithm (version 1): 80 distance codes, not readable by 7-Zip 23.01
    arc = mk.make("v7.rar", ["-v7", "-m", "3", "-d", "24", "-f", "mix", "-s"])
    if arc:
        t.check_extract(arc, plain, label="generated RAR7 algorithm (v1 tables)")
        r, typ, m = listing_map(t, arc)
        t.record(m.get("tiny.txt", {}).get("method") == "v7:m3:16M", "RAR7 method string", str(m.get("tiny.txt")))
    # unknown unpacked size: decoded until the last block
    arc = mk.make("nosize.rar", ["-m", "3", "-nosize"])
    if arc:
        t.check_extract(arc, plain, label="generated unknown sizes")
    # dictionary beyond the memory cap with unknown sizes -> GZ_E_LIMIT, not an allocation
    arc = mk.make("huge_dict.rar", ["-v7", "-m", "3", "-d", "34", "-nosize"], entries=mk.entries(["tiny.txt"]))
    if arc:
        check_rows(t, "64 GiB dictionary refused (GZ_E_LIMIT)", arc, {"tiny.txt": 15})
    # ... but a small file with a huge declared dictionary gets a small window
    arc = mk.make("small_bigdict.rar", ["-v7", "-m", "3", "-d", "34"], entries=mk.entries(["tiny.txt", "random.bin"]))
    if arc:
        check_rows(t, "small file with 16 GiB dictionary", arc, {"tiny.txt": F["tiny.txt"], "random.bin": F["random.bin"]})
    # links, directories, file copies, comment
    ents = mk.entries(["doc/text.txt", "tiny.txt"]) + ["dir/", "dir/sub/", "L:link=doc/text.txt", "H:hard=doc/text.txt",
                                                       "C:copy=tiny.txt", "L:dir/up=../tiny.txt"]
    arc = mk.make("links.rar", ["-m", "3", "-cmt", "kommentar"], entries=ents)
    if arc:
        check_rows(t, "generated links: hard link and copy carry data", arc, {
            "doc/text.txt": F["doc/text.txt"], "tiny.txt": F["tiny.txt"], "dir": None, "dir/sub": None,
            "link": 0, "hard": F["doc/text.txt"], "copy": F["tiny.txt"], "dir/up": 0})
        r, typ, m = listing_map(t, arc)
        t.record(b"link -> doc/text.txt" in r.stdout and m.get("hard", {}).get("method") == "Hardlink" and
                 m.get("copy", {}).get("method") == "Copy" and m.get("link", {}).get("mode") == 0o120777,
                 "generated links listing", r.stdout.decode(errors="replace")[-300:])
        r, rows, out = t.extract(arc)
        t.record(b"comment: kommentar" in r.stderr, "generated comment", r.stderr[-100:])
    # wrong passwords
    arc = mk.make("aes_w.rar", ["-m", "3", "-p", "right", "-lg2", "4"], entries=mk.entries(["tiny.txt", "doc/text.txt"]))
    if arc:
        check_rows(t, "wrong password -> GZ_E_PASSWORD", arc, {"tiny.txt": 6, "doc/text.txt": 6}, pw="wrong")
        check_rows(t, "no password -> GZ_E_PASSWORD", arc, {"tiny.txt": 6, "doc/text.txt": 6})
    arc = mk.make("aes_ws.rar", ["-s", "-m", "3", "-p", "right", "-lg2", "4"], entries=mk.entries(["tiny.txt", "doc/text.txt", "bin/prog.exe"]))
    if arc:
        check_rows(t, "solid: wrong password reported per entry", arc, {"tiny.txt": 6, "doc/text.txt": 6, "bin/prog.exe": 6}, pw="wrong")
    arc = mk.make("hp_w.rar", ["-m", "3", "-p", "right", "-hp", "-lg2", "4"], entries=mk.entries(["tiny.txt"]))
    if arc:
        r, typ, rows = t.listing(arc)
        t.record(b"OPEN_ERROR 6" in r.stdout, "-hp without password -> GZ_E_PASSWORD at open", r.stdout[:60])

def test_long_distance(t, mk):
    """64 MiB dictionary, matches 24 MiB back, large window allocation"""
    big = random.Random(9).randbytes(1 << 20)
    filler = random.Random(10).randbytes(24 << 20)
    data = big + filler + big + text_data(2 << 20, 11) + big[: 1 << 19]
    p = os.path.join(mk.src, "far.bin")
    open(p, "wb").write(data)
    arc = mk.make("far.rar", ["-m", "5", "-d", "26", "-depth", "4"], entries=["far.bin=" + p])
    if arc:
        t.check_vs_7z(arc, label="generated 64M dictionary, 25M distances")
    arc = mk.make("far_solid.rar", ["-s", "-m", "5", "-d", "26", "-depth", "4", "-f", "e8"],
                  entries=["a.bin=" + p, "b.bin=" + p])
    if arc:
        t.check_vs_7z(arc, label="generated solid run over 2 x 28 MiB")
    # window smaller than the stream: the ring wraps many times
    arc = mk.make("wrap.rar", ["-m", "3", "-d", "18", "-f", "mix", "-flen", "60000"], entries=["far.bin=" + p])
    if arc:
        t.check_vs_7z(arc, label="generated 256K window over 28 MiB (wrapping)")

def test_volumes_damage(t, mk):
    arc = mk.make("dmg.part%d.rar", ["-m", "3", "-vol", "100000"])
    if not arc:
        return
    vols = sorted(glob.glob(arc.replace("part1", "part*")))
    d = t.path("dmg_missing")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    for v in vols[:-2] + vols[-1:]:
        shutil.copy(v, d)
    r, res = manifest(t, os.path.join(d, os.path.basename(vols[0])))
    bad = [k for k, v in res.items() if v[0] == 14]
    t.record(r.returncode == 0 and bad and all(v[0] in (0, 14) for v in res.values()),
             "missing volume -> GZ_E_VOLUME for the split file", str({k: v[0] for k, v in res.items()}))
    d = t.path("dmg_trunc")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    for v in vols:
        shutil.copy(v, d)
    mid = os.path.join(d, os.path.basename(vols[1]))
    b = open(mid, "rb").read()
    open(mid, "wb").write(b[: len(b) // 2])
    r, res = manifest(t, os.path.join(d, os.path.basename(vols[0])))
    t.record(r.returncode == 0 and any(v[0] not in (0, -1) for v in res.values()),
             "truncated middle volume: errors, no crash", str({k: v[0] for k, v in res.items()}))
    t.check_hostile(os.path.join(d, os.path.basename(vols[0])))

def test_hostile(t, la, rf, mk, tool):
    if la:
        for p in sorted(glob.glob(os.path.join(la, "*.rar"))):
            t.check_hostile(p)
    # truncations and bit flips of small archives through gzt
    srcs = []
    for n in ["solid.rar", "aes_mac.rar", "mixblocks.rar", "hp.rar", "links.rar"]:
        p = t.path("gen", n)
        if os.path.exists(p):
            srcs.append(p)
    rnd = random.Random(5)
    k = 0
    for p in srcs[:3]:
        b = open(p, "rb").read()
        for cut in (8, 20, 40, len(b) // 3, len(b) - 17):
            q = t.path("hostile", "cut%d_%s" % (cut, os.path.basename(p)))
            open(q, "wb").write(b[:cut])
            t.check_hostile(q, pw="secret")
        for i in range(6):
            bb = bytearray(b)
            for _ in range(rnd.randint(1, 6)):
                pos = rnd.randrange(len(bb)) if rnd.random() < 0.5 else rnd.randrange(min(len(bb), 600))
                bb[pos] ^= 1 << rnd.randrange(8)
            q = t.path("hostile", "flip%d_%s" % (k, os.path.basename(p)))
            k += 1
            open(q, "wb").write(bytes(bb))
            t.check_hostile(q, pw="secret")
    # in-process mutation fuzzing
    seeds = []
    small = mk.files["doc/text.txt"][:20000]
    sp = os.path.join(mk.src, "small.txt")
    open(sp, "wb").write(small)
    ep = os.path.join(mk.src, "small.exe")
    open(ep, "wb").write(mk.files["bin/prog.exe"][:15000])
    for name, args in [("fz_solid.rar", ["-s", "-m", "5", "-f", "mix", "-flen", "2000", "-blk", "3000", "-reuse"]),
                       ("fz_aes.rar", ["-m", "3", "-p", "secret", "-lg2", "1", "-mac", "-both", "-f", "e8"]),
                       ("fz_hp.rar", ["-m", "4", "-p", "secret", "-hp", "-lg2", "1", "-cmt", "c"]),
                       ("fz_v7.rar", ["-v7", "-m", "3", "-blk", "2000", "-f", "delta"])]:
        a = mk.make(name, args, entries=["s.txt=" + sp, "e.exe=" + ep, "d/", "L:l=s.txt", "C:c=s.txt"])
        if a:
            seeds.append(a)
    if la:
        for n in ["arm", "multiple_files_solid", "blake2", "win32"]:
            p = os.path.join(la, "test_read_format_rar5_%s.rar" % n)
            if os.path.exists(p):
                seeds.append(p)
    iters = 400 if SANITIZED else 1500
    for i, s in enumerate(seeds):
        try:
            r = subprocess.run([tool, "fuzz", s, str(iters), str(100 + i), "secret"], capture_output=True, timeout=900)
        except subprocess.TimeoutExpired:
            t.record(False, "fuzz " + os.path.basename(s), "timeout")
            continue
        err = r.stderr.decode(errors="replace")
        ok = r.returncode == 0 and "Sanitizer" not in err and "runtime error" not in err
        t.record(ok, "fuzz %s x%d" % (os.path.basename(s), iters), (r.stdout.decode().strip() + " " + err[-400:]) if not ok else r.stdout.decode().strip())

def test_speed(t, mk, tool):
    """throughput of a ~40 MB solid archive (informational, compared with 7-Zip)"""
    if SANITIZED:
        return
    data = text_data(24 << 20, 21) + exe_data(8 << 20, 22) + wav_data(8 << 20, 23)
    p = os.path.join(mk.src, "speed.bin")
    open(p, "wb").write(data)
    arc = mk.make("speed.rar", ["-m", "5", "-d", "25", "-f", "e8", "-flen", "65536", "-depth", "24"], entries=["speed.bin=" + p])
    if not arc:
        return
    r = subprocess.run([tool, "bench", arc, "3"], capture_output=True, timeout=600)
    m = re.search(rb"([0-9.]+) MB/s", r.stdout)
    ours = float(m.group(1)) if m else 0
    t0 = time.time()
    s = subprocess.run(["7z", "t", arc], capture_output=True)
    dt7 = time.time() - t0
    ref = len(data) / dt7 / 1e6 if s.returncode == 0 else 0
    ok = ours > 0 and (ref == 0 or ours > ref * 0.5)
    t.record(ok, "speed", "ours %.0f MB/s, 7z t %.0f MB/s (%d MB, compressed %d MB)" %
             (ours, ref, len(data) >> 20, os.path.getsize(arc) >> 20))

def run(t):
    t.need("7z")
    tool = t.build_driver("tests/drivers/rar5_tool.c")
    mk = Maker(t, tool)
    la = libarchive_samples(t)
    rf = rarfile_samples(t)
    if not la or not rf:
        t.record(True, "upstream samples unavailable (offline?): libarchive=%s rarfile=%s" % (bool(la), bool(rf)))
    test_committed(t)
    test_real_samples(t, la, rf)
    test_generated(t, mk)
    test_long_distance(t, mk)
    test_volumes_damage(t, mk)
    test_hostile(t, la, rf, mk, tool)
    test_speed(t, mk, tool)
