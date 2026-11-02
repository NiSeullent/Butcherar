"""RAR 1.5 - 4.x (and RAR 1.4) reader + unpacker tests: src/fmt/rar.c, src/codec/rar3dec.c.

Fixtures
  * libarchive's RAR test archives (test_read_format_rar*.rar.uu, test_rar_multivolume*,
    the SFX and the split sets, uuencoded in its source tarball, fetched once from the
    Ubuntu archive pool into the test-data cache) and the samples of the PyPI package
    rarfile (sdist): RAR 1.5 / 2.0 / 2.9 data, PPMd, E8E9 + DELTA filters, solid,
    volumes in both naming styles, -p / -hp encryption, RAR 2.0 encryption, comments,
    Unicode names, Unix symlinks, SFX and libarchive's malformed files. Passwords are
    the documented ones ("password", "password2", "12345678").
  * tests/data/rar: a few of them committed for offline runs.
  * tests/drivers/rar3_tool.c: a RAR 1.5 - 4.x / RAR 1.4 writer with encoders for all
    three algorithms (every symbol kind, PPMd blocks, the six standard VM filters with
    forged byte code, RAR 2.0 audio blocks, RAR 1.5 StMode ...), volumes, AES / RAR 2.0
    / 1.5 / 1.3 ciphers, -hp, comments, NTFS streams. Its archives are checked against
    the input data and against the reference extractors that support the feature:
      unrar (RARLAB's, if installed): everything but the fake SFX stub
      7-Zip 23.01: no VM filters (its RAR plugin crashes on every filter archive here),
        no RAR 1.4, no RAR 1.5 encryption, and RAR 2.0 audio with changing channel
        counts differs (7-Zip keeps whole stale delta tables, unrar does not)
      unar: no AES, no forged filter programs, no audio, no stored member mid-run
Hostile input: libarchive's malformed archives, truncated / bit-flipped variants through
gzt, and rar3_tool's in-process mutation fuzzer (header CRCs recomputed after mutation
so damaged fields get parsed), under ASan/UBSan when HOST_CFLAGS asks for it.
"""
import os, re, glob, json, shutil, random, binascii, tarfile, subprocess, urllib.request, time

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data", "rar")
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
    if not glob.glob(os.path.join(d, "test_read_format_rar.rar")):
        with tarfile.open(tb) as tf:
            for m in tf.getmembers():
                b = os.path.basename(m.name)
                if m.isfile() and b.endswith(".uu") and "rar" in b and "rar5" not in b:
                    open(os.path.join(d, b[:-3]), "wb").write(uudecode(tf.extractfile(m).read()))
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
    if not glob.glob(os.path.join(d, "rar3-*")):
        with tarfile.open(p) as tf:
            for m in tf.getmembers():
                b = os.path.basename(m.name)
                if "/test/files/" in m.name and m.isfile() and not b.startswith("rar5-") and not b.endswith(".exp"):
                    open(os.path.join(d, b), "wb").write(tf.extractfile(m).read())
    return d

# ---------------------------------------------------------------- helpers

def manifest(t, arc, pw=None):
    """gzt x rows: {name: (status, is_dir, data or None)}"""
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

def all_ok(t, label, arc, pw=None):
    """every entry extracts with status 0 (the archive's own CRCs check the data)"""
    r, res = manifest(t, arc, pw)
    bad = [k for k, v in res.items() if v[0] != 0]
    return t.record(r.returncode == 0 and res and not bad, label,
                    (r.stdout.decode(errors="replace")[:120] if r.returncode else "bad: %s" % bad[:5]))

def listing_map(t, arc, env=None):
    r, typ, rows = t.listing(arc, env=env)
    return r, typ, {row["name"].split(" -> ")[0]: row for row in rows}

def ref_tree(t, tool, arc, pw):
    """extract with a reference tool: (ok, {name: data})"""
    out = t.path("ref_%s_%s" % (tool, os.path.basename(arc)))
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    if tool == "7z":
        cmd = ["7z", "x", "-y", "-o" + out, arc, "-p" + (pw if pw is not None else "-")]
    elif tool == "unrar":
        cmd = ["unrar", "x", "-o+", "-idq", "-p" + (pw if pw is not None else "-"), arc, out + "/"]
    else:
        cmd = ["unar", "-q", "-f", "-D", "-o", out, arc] + (["-p", pw] if pw else [])
    env = dict(os.environ)
    env["LC_ALL"] = "C.UTF-8"                  # unrar maps names through the locale
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=600, env=env)
    except subprocess.TimeoutExpired:
        return False, {}, "timeout"
    if r.returncode < 0:
        return False, {}, "killed by signal %d" % -r.returncode
    # unrar exits non-zero for warnings (old comments, unsafe links): the data decides
    ok = r.returncode == 0 or (tool == "unrar" and r.returncode in (1, 3))
    return ok, t.read_tree(out), r.stdout.decode(errors="replace")[-200:]

def check_ref(t, tool, arc, pw=None, label=None, allow_extra=False):
    """our extraction equals the reference tool's (skipped when the tool is missing)"""
    if not shutil.which(tool):
        return True
    label = (label or os.path.basename(arc)) + " = " + tool
    ok, tree, msg = ref_tree(t, tool, arc, pw)
    if not ok or not tree:
        return t.record(False, label, "%s failed: %s" % (tool, msg))
    # links are extracted as links (or skipped) and older file versions need -ver: extras allowed
    return t.check_extract(arc, tree, pw=pw, label=label, allow_extra=allow_extra or tool == "unrar")

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
        elif k < 0.45:
            out += b"\xe8" + r.randint(0xfff000, 0x1000000).to_bytes(4, "little")
        elif k < 0.55:
            # IA-64 bundle with a branch slot (template 0x10, opcode 5 in bits 37..40 of slot 0)
            v = (0x10 | r.getrandbits(1)) | (r.getrandbits(20) << 18) | (5 << 42)
            out += v.to_bytes(16, "little")
        else:
            out += bytes(r.getrandbits(8) for _ in range(r.randint(1, 12)))
    return bytes(out[:n])

def wav_data(n, seed, ch=2):
    r = random.Random(seed)
    out = bytearray()
    v = [0] * ch
    while len(out) < n:
        for c in range(ch):
            v[c] = (v[c] + r.randint(-3, 3)) & 0xff
            out.append(v[c])
    return bytes(out[:n])

def rgb_data(n, seed, w=64):
    r = random.Random(seed)
    out = bytearray()
    i = 0
    while len(out) < n:
        x, y = i % w, i // w
        out += bytes([(x * 3 + y) & 255, (x + y * 2) & 255, (x ^ y) & 255])
        if r.random() < 0.05:
            out[-1] ^= r.getrandbits(8)
        i += 1
    return bytes(out[:n])

class Maker:
    """rar3_tool make wrapper; inputs written once"""
    def __init__(self, t, tool):
        self.t, self.tool = t, tool
        self.src = t.path("gen_src")
        os.makedirs(self.src, exist_ok=True)
        self.files = {
            "doc/text.txt": text_data(250000, 1),
            "bin/prog.exe": exe_data(160000, 2),
            "media/sound.wav": wav_data(120000, 3),
            "media/image.raw": rgb_data(90000, 4),
            "random.bin": random.Random(5).randbytes(12000),
            "zeros.bin": b"\0" * 70000,
            "tiny.txt": b"abc",
            "small.txt": text_data(5000, 6),
            "empty.txt": b"",
        }
        for k, v in self.files.items():
            open(self.path(k), "wb").write(v)

    def path(self, k):
        return os.path.join(self.src, k.replace("/", "_"))

    def entries(self, names=None):
        names = names or [k for k in self.files if k != "empty.txt"]
        return ["%s=%s" % (k, self.path(k)) for k in names]

    def make(self, name, args, entries=None):
        arc = self.t.path("gen", name)
        base = os.path.basename(arc).split(".")[0]
        for f in glob.glob(os.path.join(os.path.dirname(arc), base + ".*")):
            os.remove(f)
        r = subprocess.run([self.tool, "make", arc] + args + (entries if entries is not None else self.entries()),
                           capture_output=True, timeout=900)
        if r.returncode:
            self.t.record(False, "make " + name, r.stderr.decode(errors="replace")[-300:])
            return None
        return arc

def first_volume(arc):
    for c in (arc[:-4] + ".part1.rar", arc[:-4] + ".part01.rar"):
        if os.path.exists(c):
            return c
    return arc

# ---------------------------------------------------------------- real archives

# 7-Zip 23.01's RAR plugin crashes on these here (VM filters / some LZ streams): unar instead
SEVENZ_CRASH = {"rar3-solid.rar", "seektest.rar", "test_read_format_rar_filter.rar",
                "test_read_format_rar_filter_incomplete_block.rar"}

def test_committed(t):
    """offline fixtures (copies of upstream samples, see tests/data/rar/README.md)"""
    pws = {"rar202-comment-psw.rar": "password", "rar3-comment-hpsw.rar": "password",
           "test_read_format_rar4_solid_encrypted.rar": "password"}
    for p in sorted(glob.glob(os.path.join(DATA, "*.rar"))):
        n = os.path.basename(p)
        if ".part2" in n or ".part3" in n:
            continue
        all_ok(t, "committed " + n, p, pws.get(n))
        if n in SEVENZ_CRASH or not shutil.which("7z"):
            check_ref(t, "unar", p, pws.get(n), label="committed " + n)
        else:
            t.check_vs_7z(p, pw=pws.get(n), label="committed " + n)
        check_ref(t, "unrar", p, pws.get(n), label="committed " + n)
    r, rows, out = t.extract(os.path.join(DATA, "rar15-comment.rar"))
    t.record(b"comment: RARcomment -----" in r.stderr, "RAR 1.5 packed comment", r.stderr[-120:])
    r, rows, out = t.extract(os.path.join(DATA, "rar202-comment-psw.rar"), pw="password")
    t.record(b"comment: RARcomment" in r.stderr, "RAR 2.0 packed comment", r.stderr[-120:])
    r, rows, out = t.extract(os.path.join(DATA, "rar3-comment-hpsw.rar"), pw="password")
    t.record(b"comment: RARcomment" in r.stderr, "-hp CMT comment", r.stderr[-120:])
    r, typ, m = listing_map(t, os.path.join(DATA, "test_read_format_rar_compress_best.rar"))
    t.record(m.get("LibarchiveAddingTest.html", {}).get("method") == "m5:128K PPMd" and
             m.get("testlink", {}).get("mode") == 0o120777, "listing: PPMd method, Unix symlink",
             str({k: (v["method"], oct(v["mode"])) for k, v in m.items()}))
    r, typ, m = listing_map(t, os.path.join(DATA, "rar15-comment.rar"))
    t.record(m.get("FILE1.TXT", {}).get("method") == "v15:m3:64K" and m.get("FILE2.TXT", {}).get("method") == "Store",
             "listing: RAR 1.5 methods", str({k: v["method"] for k, v in m.items()}))
    r, typ, m = listing_map(t, os.path.join(DATA, "rar202-comment-psw.rar"))
    t.record(all(v["method"] == "v20:m3:64K Crypt20" for v in m.values()) and typ == "RAR",
             "listing: RAR 2.0 encryption", str({k: v["method"] for k, v in m.items()}))
    # opening the second volume starts from the first one
    vols = [os.path.join(DATA, "test_rar_multivolume_single_file.part%d.rar" % i) for i in (1, 2, 3)]
    r, res = manifest(t, vols[0])
    whole = {k: v[2] for k, v in res.items() if not v[1]}
    t.check_extract(vols[1], whole, label="committed volume set opened at part2")

def test_real_samples(t, la, rf):
    if la:
        names = ["test_read_format_rar.rar", "test_read_format_rar3_lowdist_reset.rar",
                 "test_read_format_rar_binary_data.rar", "test_read_format_rar_compress_best.rar",
                 "test_read_format_rar_compress_normal.rar", "test_read_format_rar_multi_lzss_blocks.rar",
                 "test_read_format_rar_noeof.rar", "test_read_format_rar_subblock.rar",
                 "test_read_format_rar_unicode.rar", "test_read_format_rar_windows.rar",
                 "test_read_format_rar_filter.rar", "test_read_format_rar_filter_incomplete_block.rar",
                 "test_rar_multivolume_multiple_files.part1.rar", "test_rar_multivolume_single_file.part1.rar",
                 "test_rar_multivolume_uncompressed_files.part01.rar", "test_read_format_rar_multivolume.part0001.rar",
                 "test_read_format_rar_ppmd_lzss_conversion.rar"]
        for n in names:
            p = os.path.join(la, n)
            if not os.path.exists(p):
                continue
            if n in SEVENZ_CRASH:
                check_ref(t, "unar", p, label="libarchive " + n)
            elif "ppmd_lzss_conversion" not in n:
                t.check_vs_7z(p, label="libarchive " + n)
            if "ppmd_lzss_conversion" in n:
                all_ok(t, "libarchive " + n + " (240 MB of PPMd <-> LZ switches)", p)
            else:
                check_ref(t, "unrar", p, label="libarchive " + n)
        sfx = os.path.join(la, "test_read_format_rar_sfx.exe")
        if os.path.exists(sfx):
            t.check_vs_7z(sfx, label="libarchive sfx.exe", expect_type="RAR")
        # passwords: b.txt "password", d.txt "password2"; -hp / data encryption "12345678"
        enc = os.path.join(la, "test_read_format_rar4_encrypted.rar")
        exp_a, exp_b = b"This is from a.txt", b"This is from b.txt"
        if os.path.exists(enc):
            check_rows(t, "libarchive rar4 encrypted (password)", enc, {
                "a.txt": exp_a, "b.txt": exp_b, "c.txt": b"This is from c.txt", "d.txt": 6}, pw="password")
            check_rows(t, "libarchive rar4 encrypted (password2)", enc, {
                "a.txt": exp_a, "b.txt": 6, "c.txt": b"This is from c.txt", "d.txt": b"This is from d.txt"}, pw="password2")
            check_rows(t, "libarchive rar4 encrypted (no password)", enc, {
                "a.txt": exp_a, "b.txt": 6, "c.txt": b"This is from c.txt", "d.txt": 6})
        for n in ["test_read_format_rar4_solid_encrypted.rar", "test_read_format_rar4_encrypted_filenames.rar",
                  "test_read_format_rar4_solid_encrypted_filenames.rar"]:
            p = os.path.join(la, n)
            if os.path.exists(p):
                t.check_vs_7z(p, pw="password", label="libarchive " + n)
        p = os.path.join(la, "test_read_format_rar4_solid_encrypted.rar")
        if os.path.exists(p):
            check_rows(t, "libarchive solid encrypted without password", p, {"a.txt": 6, "b.txt": 6, "c.txt": 6, "d.txt": 6})
        for n in ["test_read_format_rar_encryption_data.rar", "test_read_format_rar_encryption_partially.rar",
                  "test_read_format_rar_encryption_header.rar"]:
            p = os.path.join(la, n)
            if os.path.exists(p):
                t.check_vs_7z(p, pw="12345678", label="libarchive " + n)
        p = os.path.join(la, "test_read_format_rar4_encrypted_filenames.rar")
        if os.path.exists(p):
            r, typ, rows = t.listing(p)
            t.record(b"OPEN_ERROR 6" in r.stdout, "-hp without password: GZ_E_PASSWORD", r.stdout[:60])
            r, rows, out = t.extract(p, pw="wrong")
            t.record(b"OPEN_ERROR 6" in r.stdout, "-hp wrong password: GZ_E_PASSWORD", r.stdout[:60])
        # opening a later volume starts from the first one
        for first, later in [("test_rar_multivolume_multiple_files.part1.rar", "test_rar_multivolume_multiple_files.part4.rar"),
                             ("test_read_format_rar_multivolume.part0001.rar", "test_read_format_rar_multivolume.part0003.rar")]:
            if os.path.exists(os.path.join(la, later)):
                r, res = manifest(t, os.path.join(la, first))
                whole = {k: v[2] for k, v in res.items() if not v[1]}
                t.check_extract(os.path.join(la, later), whole, label="libarchive %s (from part 1)" % later)
        for p in sorted(glob.glob(os.path.join(la, "*.rar"))) + sorted(glob.glob(os.path.join(la, "*_a?"))):
            t.check_hostile(p, pw="password")
    if rf:
        for p in sorted(glob.glob(os.path.join(rf, "*.rar"))):
            n = os.path.basename(p)
            if n.startswith("ctime5") or ".part2" in n or ".part3" in n:
                continue                         # RAR5 / later volumes
            if n in SEVENZ_CRASH:
                check_ref(t, "unar", p, pw="password", label="rarfile " + n)
            else:
                t.check_vs_7z(p, pw="password", label="rarfile " + n)
            if n != "unicode2.rar":              # unrar cannot create that name in this locale
                check_ref(t, "unrar", p, pw="password", label="rarfile " + n)
        for n in ("rar3-vols.part2.rar", "rar3-vols.part3.rar", "rar3-old.r00", "rar3-old.r01"):
            whole_from = "rar3-vols.part1.rar" if "vols" in n else "rar3-old.rar"
            r, res = manifest(t, os.path.join(rf, whole_from))
            whole = {k: v[2] for k, v in res.items() if not v[1]}
            t.check_extract(os.path.join(rf, n), whole, label="rarfile %s (from the first volume)" % n)
        r, rows, out = t.extract(os.path.join(rf, "rar15-comment.rar"))
        t.record(b"comment: RARcomment -----" in r.stderr, "rarfile RAR 1.5 comment", r.stderr[-120:])
        r, rows, out = t.extract(os.path.join(rf, "rar3-comment-plain.rar"))
        t.record(b"comment: RARcomment" in r.stderr, "rarfile CMT comment", r.stderr[-120:])
        check_rows(t, "rarfile RAR 2.0 encryption, wrong password", os.path.join(rf, "rar202-comment-psw.rar"),
                   {"FILE1.TXT": 6, "FILE2.TXT": 6}, pw="wrong")
        r, typ, m = listing_map(t, os.path.join(rf, "rar3-symlink-unix.rar"))
        t.record(m.get("data_link", {}).get("mode") == 0o120777 and m.get("data.txt", {}).get("mode") == 0o100664,
                 "rarfile Unix symlink / modes", str({k: oct(v["mode"]) for k, v in m.items()}))
        r, typ, m = listing_map(t, os.path.join(rf, "rar3-versions.rar"))
        t.record(set(m) == {"versioned.txt;1", "versioned.txt;2", "versioned.txt"}, "rarfile file versions", str(sorted(m)))
        r, rows, out = t.extract(os.path.join(rf, "rar3-comment-hpsw.rar"), pw="wrong")
        t.record(b"OPEN_ERROR 6" in r.stdout, "rarfile -hp wrong password", r.stdout[:60])
        t.record(t.listing(os.path.join(rf, "unicode.rar"))[1] == "RAR", "rarfile UTF-8 names (no Unicode flag)")

# ---------------------------------------------------------------- generated archives

def refs_for(t, arc, pw, refs, label, allow_extra=False):
    if "u" in refs:
        check_ref(t, "unrar", arc, pw, label, allow_extra)
    if "7" in refs and shutil.which("7z"):
        t.check_vs_7z(arc, pw=pw, label=label + " = 7z", allow_extra=allow_extra)
    if "a" in refs:
        check_ref(t, "unar", arc, pw, label, allow_extra)

GEN = [
    # name, options, references (u: unrar, 7: 7-Zip, a: unar)
    ("m3", ["-m", "3"], "u7a"),
    ("m5var", ["-m", "5", "-var", "-lazy"], "u7a"),
    ("store", ["-m", "0", "-exttime"], "u7a"),
    ("solid", ["-m", "3", "-s"], "u7"),
    ("solidvar", ["-m", "3", "-s", "-var", "-blk", "3000"], "u7"),
    ("blk", ["-m", "3", "-blk", "400", "-var"], "u7a"),
    ("d16", ["-m", "2", "-d", "16"], "u7a"),
    ("d22", ["-m", "4", "-d", "22", "-lazy"], "u7a"),
    ("ppm", ["-m", "5", "-ppm"], "u7a"),
    ("ppmvar", ["-m", "5", "-ppm", "-var", "-blk", "4000"], "u7a"),
    ("ppm_o2", ["-m", "5", "-ppm", "-order", "2", "-mb", "0"], "u7a"),
    ("ppm_o64", ["-m", "5", "-ppm", "-order", "64", "-mb", "40"], "u7a"),
    ("mix", ["-m", "5", "-mix", "-var", "-blk", "2000", "-s"], "u7"),
    ("e8", ["-m", "3", "-f", "e8"], "u"),
    ("e8e9", ["-m", "3", "-f", "e8e9", "-var"], "u"),
    ("itanium", ["-m", "3", "-f", "itanium", "-flen", "40000"], "u"),
    ("delta", ["-m", "3", "-f", "delta"], "u"),
    ("rgb", ["-m", "3", "-f", "rgb"], "u"),
    ("audio", ["-m", "3", "-f", "audio"], "u"),
    ("fmix", ["-m", "3", "-f", "mix", "-var", "-flen", "20000"], "u"),
    ("fstack", ["-m", "3", "-f", "delta+e8", "-flen", "30000"], "u"),
    ("fbig", ["-m", "3", "-f", "e8e9", "-flen", "0x3C000"], "u"),
    ("fppm", ["-m", "5", "-mix", "-f", "mix", "-var", "-flen", "30000", "-blk", "3000"], "u"),
    ("fsolid", ["-m", "3", "-s", "-f", "mix", "-var", "-flen", "25000"], "u"),
    ("aes", ["-m", "3", "-p", "Pässwörd ✓"], "u7"),
    ("aes_solid", ["-m", "3", "-s", "-p", "secret", "-var", "-mix"], "u7"),
    ("hp", ["-m", "3", "-p", "secret", "-hp", "-cmt", "comment über alles"], "u7"),
    ("vol", ["-m", "3", "-vol", "150000"], "u7a"),
    ("vol_many", ["-m", "3", "-vol", "40000", "-s"], "u7"),
    ("vold", ["-m", "3", "-vol", "150000", "-vold", "-s"], "u7"),
    ("volhp", ["-m", "3", "-vol", "200000", "-p", "pw", "-hp"], "u7"),
    ("uni", ["-m", "3", "-uni", "-exttime", "-host", "3"], "u7a"),
    ("large", ["-m", "3", "-large", "-exttime"], "u7a"),
    ("unknown", ["-m", "3", "-unknown", "-s", "-var"], "u"),      # 7-Zip: no unknown sizes
    ("cmt", ["-m", "3", "-cmt", "archive comment"], "u7a"),
    ("v20", ["-fmt", "20", "-m", "3"], "u7a"),
    ("v20var", ["-fmt", "20", "-m", "3", "-var", "-blk", "2000"], "u7"),     # unar fails 2 files
    ("v20solid", ["-fmt", "20", "-m", "3", "-s", "-var"], "u7"),
    ("v20audio", ["-fmt", "20", "-m", "3", "-audio", "2"], "u7"),
    ("v20audiovar", ["-fmt", "20", "-m", "3", "-audio", "4", "-var", "-s", "-blk", "3000"], "u"),
    ("v20crypt", ["-fmt", "20", "-m", "3", "-p", "secret"], "u7a"),
    ("v20cmt", ["-fmt", "20", "-m", "3", "-d", "16", "-cmt", "old comment here"], "u7a"),
    ("v20vol", ["-fmt", "20", "-m", "3", "-vol", "120000", "-noend"], "u7a"),
    ("v15", ["-fmt", "15", "-m", "3", "-d", "16"], "u7a"),
    ("v15var", ["-fmt", "15", "-m", "3", "-d", "16", "-var"], "u7a"),
    ("v15solid", ["-fmt", "15", "-m", "3", "-d", "16", "-s", "-var"], "u7"),
    ("v15crypt", ["-fmt", "15", "-m", "3", "-d", "16", "-p", "secret"], "ua"),
    ("v15cmt", ["-fmt", "15", "-m", "3", "-d", "16", "-cmt", "rar 1.5 comment", "-vol", "100000"], "u7a"),
    ("v14", ["-fmt", "14", "-m", "3"], "u"),
    ("v14solid", ["-fmt", "14", "-m", "3", "-s", "-var", "-cmt", "1.4 comment"], "u"),
    ("v14crypt", ["-fmt", "14", "-m", "3", "-p", "secret", "-vol", "100000"], "u"),
]

def pw_of(args):
    return args[args.index("-p") + 1] if "-p" in args else None

def test_generated(t, mk):
    F = mk.files
    plain = {k: v for k, v in F.items() if k != "empty.txt"}
    for name, args, refs in GEN:
        arc = mk.make(name + ".rar", args)
        if not arc:
            continue
        first = first_volume(arc)
        pw = pw_of(args)
        t.check_extract(first, plain, pw=pw, label="generated " + name, expect_type="RAR 1.4" if "14" in name else "RAR")
        refs_for(t, first, pw, refs, "generated " + name)
    # solid archive with a directory and an empty (stored) file inside the run
    ents = mk.entries(["doc/text.txt"]) + ["dir/"] + ["empty.txt=" + mk.path("empty.txt")] + mk.entries(["bin/prog.exe", "tiny.txt"])
    arc = mk.make("solid_dirs.rar", ["-m", "3", "-s", "-var"], entries=ents)
    if arc:
        exp = {"doc/text.txt": F["doc/text.txt"], "dir": None, "empty.txt": b"", "bin/prog.exe": F["bin/prog.exe"],
               "tiny.txt": F["tiny.txt"]}
        check_rows(t, "solid run across a directory and a stored file", arc, exp)
        refs_for(t, arc, None, "u7", "solid run across a directory and a stored file")
        # random access into the middle of the run
        r, typ, m = listing_map(t, arc)
        t.record(m.get("bin/prog.exe", {}).get("method") == "m3:1M", "solid listing", str(m.get("bin/prog.exe")))
    # SFX: a fake executable stub with decoy markers
    arc = mk.make("sfx.exe", ["-m", "3", "-sfx", "70000"])
    if arc:
        t.check_extract(arc, plain, label="generated SFX stub", expect_type="RAR")
    # NTFS streams (RAR 3 STM service headers, RAR 2 sub-blocks) as aux entries
    for fmt in ("29", "20"):
        ents = mk.entries(["small.txt"]) + ["S:zone=" + mk.path("tiny.txt"), "S:big=" + mk.path("doc/text.txt")] + \
            mk.entries(["random.bin"])
        arc = mk.make("streams%s.rar" % fmt, ["-fmt", fmt, "-m", "3"] + (["-p", "pw"] if fmt == "29" else []), entries=ents)
        if arc:
            check_rows(t, "NTFS streams (%s)" % ("STM" if fmt == "29" else "sub-blocks"), arc, {
                "small.txt": F["small.txt"], "small.txt:zone": F["tiny.txt"], "small.txt:big": F["doc/text.txt"],
                "random.bin": F["random.bin"]}, pw="pw" if fmt == "29" else None)
            refs_for(t, arc, "pw" if fmt == "29" else None, "u", "NTFS streams " + fmt, allow_extra=False)
    # symlinks, directories, Unix modes, Unicode names
    ents = ["dir/", "dir/sub/", "L:dir/link=../small.txt", "한글 이름.txt=" + mk.path("small.txt"),
            "Ελληνικά/κείμενο.txt=" + mk.path("tiny.txt")]
    arc = mk.make("links.rar", ["-m", "3", "-host", "3", "-uni"], entries=ents)
    if arc:
        check_rows(t, "Unix symlink + Unicode names", arc, {"dir": None, "dir/sub": None, "dir/link": b"../small.txt",
                   "한글 이름.txt": F["small.txt"], "Ελληνικά/κείμενο.txt": F["tiny.txt"]})
        r, typ, m = listing_map(t, arc)
        t.record(m.get("dir/link", {}).get("mode") == 0o120777 and m.get("dir", {}).get("mode") == 0o40755,
                 "Unix modes", str({k: oct(v["mode"]) for k, v in m.items()}))
        refs_for(t, arc, None, "u7a", "Unix symlink + Unicode names", allow_extra=True)   # links: not files
    # comments of every kind
    for name, args, text in [("c29", ["-cmt", "CMT text"], "CMT text"),
                             ("c29u", ["-cmt", "유니코드 주석", "-cmtu"], "유니코드 주석"),
                             ("c29s", ["-cmt", "stored comment", "-cmtstore"], "stored comment"),
                             ("c20", ["-fmt", "20", "-cmt", "packed 2.0"], "packed 2.0"),
                             ("c20s", ["-fmt", "20", "-cmt", "stored 2.0", "-cmtstore"], "stored 2.0"),
                             ("c15", ["-fmt", "15", "-cmt", "packed 1.5"], "packed 1.5"),
                             ("c14", ["-fmt", "14", "-cmt", "packed 1.4"], "packed 1.4"),
                             ("c14s", ["-fmt", "14", "-cmt", "stored 1.4", "-cmtstore"], "stored 1.4")]:
        arc = mk.make(name + ".rar", ["-m", "3"] + args, entries=mk.entries(["tiny.txt"]))
        if arc:
            r, rows, out = t.extract(arc)
            t.record(("comment: " + text).encode() in r.stderr, "comment " + name, r.stderr[-100:])
    # method strings
    for name, args, want in [("ms_store", ["-m", "0"], "Store"), ("ms_29", ["-m", "3", "-d", "22"], "m3:4M"),
                             ("ms_ppm", ["-m", "5", "-ppm", "-d", "17"], "m5:128K PPMd"),
                             ("ms_aes", ["-m", "1", "-p", "x"], "m1:1M AES"),
                             ("ms_20", ["-fmt", "20", "-m", "2", "-d", "18", "-p", "x"], "v20:m2:256K Crypt20"),
                             ("ms_15", ["-fmt", "15", "-m", "4", "-d", "16", "-p", "x"], "v15:m4:64K Crypt15"),
                             ("ms_14", ["-fmt", "14", "-m", "5", "-p", "x"], "v15:m5:64K Crypt13")]:
        arc = mk.make(name + ".rar", args, entries=mk.entries(["small.txt"]))
        if arc:
            r, typ, m = listing_map(t, arc)
            t.record(m.get("small.txt", {}).get("method") == want, "method string " + want, str(m.get("small.txt")))
    # passwords
    for fmt, label in (("29", "AES"), ("20", "RAR 2.0"), ("15", "RAR 1.5"), ("14", "RAR 1.3")):
        arc = mk.make("pw%s.rar" % fmt, ["-fmt", fmt, "-m", "3", "-p", "right"] + (["-s"] if fmt != "14" else []),
                      entries=mk.entries(["small.txt", "doc/text.txt"]))
        if arc:
            check_rows(t, label + ": wrong password -> GZ_E_PASSWORD", arc, {"small.txt": 6, "doc/text.txt": 6}, pw="wrong")
            check_rows(t, label + ": no password -> GZ_E_PASSWORD", arc, {"small.txt": 6, "doc/text.txt": 6})
            check_rows(t, label + ": right password", arc, {"small.txt": F["small.txt"], "doc/text.txt": F["doc/text.txt"]}, pw="right")
    arc = mk.make("hp_w.rar", ["-m", "3", "-p", "right", "-hp"], entries=mk.entries(["tiny.txt"]))
    if arc:
        r, typ, rows = t.listing(arc)
        t.record(b"OPEN_ERROR 6" in r.stdout, "-hp without password -> GZ_E_PASSWORD at open", r.stdout[:60])
        r, rows, out = t.extract(arc, pw="wrong")
        t.record(b"OPEN_ERROR 6" in r.stdout, "-hp wrong password -> GZ_E_PASSWORD at open", r.stdout[:60])
    # VM programs that are no standard filter: GZ_E_METHOD for that file; bad XOR: GZ_E_DATA
    arc = mk.make("bogus.rar", ["-m", "3", "-f", "bogus"], entries=mk.entries(["small.txt", "doc/text.txt"]))
    if arc:
        check_rows(t, "unknown VM program -> GZ_E_METHOD", arc, {"small.txt": 5, "doc/text.txt": 5})
    arc = mk.make("badxor.rar", ["-m", "3", "-f", "badxor"], entries=mk.entries(["small.txt"]))
    if arc:
        check_rows(t, "VM code with a bad XOR -> GZ_E_DATA", arc, {"small.txt": 3})
    # old-style volumes opened at a later volume, new style opened at part 2
    arc = mk.make("ov.rar", ["-m", "3", "-vol", "60000", "-vold", "-s"])
    if arc:
        t.check_extract(arc[:-4] + ".r01", plain, label="old-style volumes opened at .r01")
    arc = mk.make("nv.rar", ["-m", "3", "-vol", "60000"])
    if arc:
        t.check_extract(arc[:-4] + ".part2.rar" if os.path.exists(arc[:-4] + ".part2.rar") else arc[:-4] + ".part02.rar",
                        plain, label="new-style volumes opened at part 2")

def cleanup(t, *arcs):
    for a in arcs:
        if not a:
            continue
        b = os.path.basename(a)
        shutil.rmtree(os.path.join(t.work, "out_" + b), ignore_errors=True)
        shutil.rmtree(os.path.join(t.work, "ref7z_" + b), ignore_errors=True)
        for f in glob.glob(a[:-4] + "*"):
            os.remove(f)

def test_long_distance(t, mk):
    """4 MiB dictionary with 3+ MiB distances (RAR 2.9) and 1 MiB (RAR 2.0) in solid runs"""
    big = random.Random(9).randbytes(1 << 19)
    filler = random.Random(10).randbytes(3 << 20)
    data = big + filler + big + text_data(1 << 20, 11)
    p = os.path.join(mk.src, "far.bin")
    open(p, "wb").write(data)
    for name, args in [("far29.rar", ["-m", "3", "-d", "22", "-s", "-var"]), ("far20.rar", ["-fmt", "20", "-m", "3", "-d", "20", "-s"])]:
        arc = mk.make(name, args, entries=["a.bin=" + p, "b.bin=" + mk.path("small.txt"), "c.bin=" + p])
        if arc:
            t.check_extract(arc, {"a.bin": data, "b.bin": mk.files["small.txt"], "c.bin": data}, label="long distances " + name)
            refs_for(t, arc, None, "u7", "long distances " + name)
        cleanup(t, arc)
    os.remove(p)

def test_volumes_damage(t, mk):
    arc = mk.make("dmg.rar", ["-m", "3", "-vol", "100000"])
    if not arc:
        return
    vols = sorted(glob.glob(arc[:-4] + ".part*.rar"))
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

def test_hostile(t, mk, tool, la):
    # truncations and bit flips through gzt
    rnd = random.Random(5)
    k = 0
    for name in ["mix.rar", "fmix.rar", "v20audiovar.rar", "v15var.rar", "hp.rar", "v14solid.rar"]:
        p = t.path("gen", name)
        if not os.path.exists(p):
            continue
        b = open(p, "rb").read()
        for cut in (8, 20, 40, len(b) // 3, len(b) - 17):
            q = t.path("hostile", "cut%d_%s" % (cut, name))
            open(q, "wb").write(b[:cut])
            t.check_hostile(q, pw="secret")
        for i in range(5):
            bb = bytearray(b)
            for _ in range(rnd.randint(1, 6)):
                pos = rnd.randrange(len(bb)) if rnd.random() < 0.5 else rnd.randrange(min(len(bb), 600))
                bb[pos] ^= 1 << rnd.randrange(8)
            q = t.path("hostile", "flip%d_%s" % (k, name))
            k += 1
            open(q, "wb").write(bytes(bb))
            t.check_hostile(q, pw="secret")
    # in-process mutation fuzzing (header CRCs recomputed for half of the mutations)
    seeds = []
    sp = os.path.join(mk.src, "fz.txt")
    open(sp, "wb").write(mk.files["doc/text.txt"][:12000])
    ep = os.path.join(mk.src, "fz.exe")
    open(ep, "wb").write(mk.files["bin/prog.exe"][:12000])
    wp = os.path.join(mk.src, "fz.wav")
    open(wp, "wb").write(mk.files["media/sound.wav"][:8000])
    ents = ["s.txt=" + sp, "e.exe=" + ep, "d/", "w.wav=" + wp, "S:st=" + sp]
    for name, args in [("fz_lz.rar", ["-m", "3", "-var", "-blk", "800", "-s", "-f", "mix", "-flen", "3000"]),
                       ("fz_ppm.rar", ["-m", "5", "-mix", "-var", "-blk", "1500", "-s", "-mb", "1", "-f", "mix", "-flen", "4000"]),
                       ("fz_aes.rar", ["-m", "3", "-p", "secret", "-hp", "-cmt", "c", "-uni", "-exttime"]),
                       ("fz_v20.rar", ["-fmt", "20", "-m", "3", "-audio", "3", "-var", "-blk", "700", "-s", "-cmt", "x"]),
                       ("fz_v15.rar", ["-fmt", "15", "-m", "3", "-var", "-s", "-d", "16"]),
                       ("fz_v14.rar", ["-fmt", "14", "-m", "3", "-var", "-s", "-cmt", "y"])]:
        a = mk.make(name, args, entries=ents if "v14" not in name else ents[:4])
        if a:
            seeds.append(a)
    if la:
        for n in ["test_read_format_rar_filter.rar", "test_read_format_rar_compress_best.rar", "test_read_format_rar.rar"]:
            p = os.path.join(la, n)
            if os.path.exists(p):
                seeds.append(p)
    iters = 300 if SANITIZED else 1500
    for i, s in enumerate(seeds):
        try:
            r = subprocess.run([tool, "fuzz", s, str(iters), str(100 + i), "secret"], capture_output=True, timeout=1200)
        except subprocess.TimeoutExpired:
            t.record(False, "fuzz " + os.path.basename(s), "timeout")
            continue
        err = r.stderr.decode(errors="replace")
        ok = r.returncode == 0 and "Sanitizer" not in err and "runtime error" not in err
        t.record(ok, "fuzz %s x%d" % (os.path.basename(s), iters),
                 (r.stdout.decode().strip() + " " + err[-400:]) if not ok else r.stdout.decode().strip())

def cross_build(t, cc, flags, name):
    """rar3_tool + the whole core from source for another target"""
    root = os.path.dirname(os.path.dirname(HERE))
    srcs = []
    for d in ("src/core", "src/codec", "src/fmt"):
        srcs += sorted(glob.glob(os.path.join(root, d, "*.c")))
    srcs.append(os.path.join(root, "src/posix/plat_posix.c"))
    srcs.append(os.path.join(os.path.dirname(t.gzt), "gen", "registry.c"))
    exe = t.path(name)
    r = t.sh(cc + flags + ["-std=gnu11", "-O1", "-w", "-pthread"] +
             ["-I" + os.path.join(root, d) for d in ("src/core", "src/codec", "src/fmt", "src/posix")] +
             ["-o", exe, os.path.join(root, "tests/drivers/rar3_tool.c")] + srcs + ["-pthread"], check=False, timeout=900)
    if r.returncode:
        t.record(False, "build " + name, r.stderr.decode(errors="replace")[-400:])
        return None
    return exe

def test_targets(t, tool, la):
    """the same per-entry results (status, size, CRC) from i386 and AArch64 builds"""
    if SANITIZED:
        return
    arcs = []
    for n in ["m5var.rar", "solidvar.rar", "ppmvar.rar", "mix.rar", "fmix.rar", "fstack.rar", "fppm.rar", "aes_solid.rar",
              "hp.rar", "vol.part1.rar", "v20audiovar.rar", "v20crypt.rar", "v15var.rar", "v15crypt.rar", "v14solid.rar",
              "unknown.rar", "streams29.rar"]:
        p = t.path("gen", n)
        if os.path.exists(p):
            arcs.append(p)
    if la:
        for n in ["test_read_format_rar_filter.rar", "test_read_format_rar_compress_best.rar", "test_read_format_rar_binary_data.rar"]:
            p = os.path.join(la, n)
            if os.path.exists(p):
                arcs.append(p)
    pws = {}
    for a in arcs:
        b = os.path.basename(a)
        pws[a] = "secret" if b in ("aes_solid.rar", "hp.rar", "v20crypt.rar", "v15crypt.rar") else \
                 "pw" if b == "streams29.rar" else "x"
    ref = {a: subprocess.run([tool, "check", a, pws[a]], capture_output=True).stdout for a in arcs}
    targets = []
    if shutil.which("gcc") and subprocess.run(["gcc", "-m32", "-x", "c", "-", "-o", os.devnull],
                                              input=b"int main(void){return 0;}", capture_output=True).returncode == 0:
        targets.append(("i386", ["gcc", "-m32", "-march=i586"], [], []))
    if shutil.which("aarch64-linux-gnu-gcc") and shutil.which("qemu-aarch64") and os.path.isdir("/usr/aarch64-linux-gnu"):
        targets.append(("arm64", ["aarch64-linux-gnu-gcc"], [], ["qemu-aarch64", "-cpu", "max"]))
    env = dict(os.environ)
    env.setdefault("QEMU_LD_PREFIX", "/usr/aarch64-linux-gnu")
    for name, cc, flags, run in targets:
        exe = cross_build(t, cc, flags, "rar3_tool_" + name)
        if not exe:
            continue
        bad = []
        for a in arcs:
            got = subprocess.run(run + [exe, "check", a, pws[a]], capture_output=True, env=env, timeout=900).stdout
            if got != ref[a]:
                bad.append(os.path.basename(a))
        t.record(not bad, "%s build: %d archives match the host" % (name, len(arcs)), "; ".join(bad[:6]))

def test_speed(t, mk, tool):
    """decoding throughput (informational) against unrar / 7-Zip"""
    if SANITIZED:
        return
    data = text_data(12 << 20, 21) + exe_data(3 << 20, 22) + wav_data(3 << 20, 23)
    p = os.path.join(mk.src, "speed.bin")
    open(p, "wb").write(data)
    for name, args in [("speed_lz.rar", ["-m", "3", "-d", "22", "-f", "e8e9", "-flen", "65536"]),
                       ("speed_20.rar", ["-fmt", "20", "-m", "3", "-d", "20"]),
                       ("speed_15.rar", ["-fmt", "15", "-m", "3", "-d", "16"])]:
        arc = mk.make(name, args, entries=["speed.bin=" + p])
        if not arc:
            continue
        r = subprocess.run([tool, "bench", arc, "3"], capture_output=True, timeout=600)
        m = re.search(rb"([0-9.]+) MB/s", r.stdout)
        ours = float(m.group(1)) if m else 0
        detail = "ours %.0f MB/s" % ours
        refspeed = 0
        for refname, cmd in (("unrar", ["unrar", "t", "-idq", arc]), ("7z", ["7z", "t", arc])):
            if not shutil.which(cmd[0]):
                continue
            t0 = time.time()
            s = subprocess.run(cmd, capture_output=True)
            dt = time.time() - t0
            if s.returncode == 0:
                sp = len(data) / dt / 1e6
                refspeed = max(refspeed, sp)
                detail += ", %s %.0f MB/s" % (refname, sp)
        t.record(ours > 0 and (refspeed == 0 or ours > refspeed * 0.5), "speed " + name, detail)
        cleanup(t, arc)
    os.remove(p)

def run(t):
    tool = t.build_driver("tests/drivers/rar3_tool.c")
    mk = Maker(t, tool)
    la = libarchive_samples(t)
    rf = rarfile_samples(t)
    if not la or not rf:
        t.record(True, "upstream samples unavailable (offline?): libarchive=%s rarfile=%s" % (bool(la), bool(rf)))
    if not shutil.which("unrar"):
        t.record(True, "unrar not installed: generated archives are checked against 7-Zip / unar and their inputs")
    test_committed(t)
    test_real_samples(t, la, rf)
    test_generated(t, mk)
    test_long_distance(t, mk)
    test_volumes_damage(t, mk)
    test_hostile(t, mk, tool, la)
    test_targets(t, tool, la)
    test_speed(t, mk, tool)
