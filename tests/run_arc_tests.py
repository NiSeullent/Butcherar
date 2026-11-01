#!/usr/bin/env python3
"""
고깃ZIP archive-layer regression test.

Builds a set of archives (zipfile / pyzipper / 7z / tarfile / gzip) covering
Korean CP949 + UTF-8 names, macOS NFD names, Deflate64, ZipCrypto, WinZip AES,
ZIP64, SFX prefixes, zip-slip paths, tar (gnu/pax), tar.gz and .gz, then runs
the native test driver (test_arc) on each and compares every extracted entry
byte-for-byte with Python's own extraction.

usage: run_arc_tests.py <test_arc binary> <work dir>
"""
import os, sys, io, gzip, random, shutil, struct, subprocess, tarfile, unicodedata, zipfile

BIN, WORK = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
os.makedirs(WORK, exist_ok=True)
random.seed(42)

def blob(n, kind=0):
    if kind == 0:
        return os.urandom(n)
    words = ["고기", "삼겹살", "목살", "갈비", "zip", "archive", "hello", "world", "\n"]
    out = bytearray()
    while len(out) < n:
        out += random.choice(words).encode()
        out += b" "
    return bytes(out[:n])

FILES = {
    "readme.txt": blob(5000, 1),
    "문서/보고서.txt": blob(120000, 1),
    "문서/사진/고기.jpg": blob(70000, 0),
    "empty.txt": b"",
    "deep/a/b/c/d/e.bin": blob(300000, 1),
    "big.bin": blob(3 << 20, 1),
}

def normalize(name):
    """What 고깃ZIP is expected to show for a raw entry name."""
    name = name.replace("\\", "/")
    parts = [p for p in name.split("/") if p not in ("", ".", "..")]
    if parts and len(parts[0]) == 2 and parts[0][1] == ":":
        parts = parts[1:]
    s = "/".join(parts)
    return unicodedata.normalize("NFC", s) if any(0x1100 <= ord(c) <= 0x11FF for c in s) else s

class RawInfo(zipfile.ZipInfo):
    """ZipInfo whose name bytes are written verbatim, without the UTF-8 flag."""
    def __init__(self, raw, **kw):
        super().__init__(raw.decode("latin-1"), **kw)
        self.raw_name = raw
    def _encodeFilenameFlags(self):
        return self.raw_name, self.flag_bits & ~0x800

cases = []   # (archive path, password, expected {index: (name, bytes or None for dir)})

def add_zip_case(path, password=None, names=None, from_files=False):
    exp = {}
    with zipfile.ZipFile(path) as z:
        if password:
            z.setpassword(password.encode())
        for i, info in enumerate(z.infolist()):
            if names:
                nm = names[i]
            else:
                nm = info.filename
            if info.is_dir():
                exp[i] = (normalize(nm), None)
            elif from_files:
                exp[i] = (normalize(nm), FILES[normalize(nm)])
            else:
                exp[i] = (normalize(nm), z.read(info))
    cases.append((path, password, exp))

# 1) plain deflate, UTF-8 names (flag set by zipfile)
p = os.path.join(WORK, "utf8.zip")
with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("문서/", b"")
    for k, v in FILES.items():
        z.writestr(k, v)
add_zip_case(p)

# 2) CP949 names without UTF-8 flag (like zips made on Korean Windows)
p = os.path.join(WORK, "cp949.zip")
cp_names = []
with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
    for k, v in FILES.items():
        zi = RawInfo(k.encode("cp949"), date_time=(2020, 5, 17, 13, 45, 10))
        zi.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi, v)
        cp_names.append(k)
add_zip_case(p, names=cp_names)

# 3) macOS style: decomposed Hangul (NFD) UTF-8 without flag, plus backslashes
p = os.path.join(WORK, "macnfd.zip")
nfd_names = []
with zipfile.ZipFile(p, "w", zipfile.ZIP_STORED) as z:
    for k in ["한글파일.txt", "폴더\\하위\\깍두기.txt", "__MACOSX/._x"]:
        nfd = unicodedata.normalize("NFD", k)
        zi = RawInfo(nfd.encode("utf-8"))
        z.writestr(zi, k.encode())
        nfd_names.append(nfd)
add_zip_case(p, names=nfd_names)

# 4) zip-slip & absolute paths
p = os.path.join(WORK, "slip.zip")
slip = ["../../evil.txt", "/abs/path.txt", "C:\\Windows\\x.txt", "./ok/./fine.txt", "a/../b.txt"]
with zipfile.ZipFile(p, "w") as z:
    for k in slip:
        z.writestr(zipfile.ZipInfo(k), k.encode())
add_zip_case(p, names=slip)

# 5) ZIP64 forced + SFX prefix
p = os.path.join(WORK, "zip64.zip")
with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
    for i in range(70000 // 100):
        z.writestr("many/f%05d.txt" % i, ("file %d " % i).encode() * 3)
    with z.open("forced64.bin", "w", force_zip64=True) as f:
        f.write(FILES["big.bin"])
add_zip_case(p)
sfx = os.path.join(WORK, "sfx.exe")
with open(sfx, "wb") as f:
    f.write(b"MZ" + os.urandom(40000))
    f.write(open(os.path.join(WORK, "utf8.zip"), "rb").read())
cases.append((sfx, None, cases[0][2]))

# 6) 7z: Deflate64, ZipCrypto, AES-256
src = os.path.join(WORK, "src")
shutil.rmtree(src, ignore_errors=True)
for k, v in FILES.items():
    fp = os.path.join(src, k)
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    open(fp, "wb").write(v)
def sevenzip(name, *opts):
    out = os.path.join(WORK, name)
    if os.path.exists(out):
        os.remove(out)
    subprocess.run(["7z", "a", "-tzip", out, "."] + list(opts), cwd=src, check=True,
                   stdout=subprocess.DEVNULL)
    return out
HAVE_7Z = shutil.which("7z") is not None
if HAVE_7Z:
    add_zip_case(sevenzip("d64.zip", "-mm=Deflate64", "-mx=9"), from_files=True)
    add_zip_case(sevenzip("zipcrypto.zip", "-pgogi1234", "-mem=ZipCrypto"), "gogi1234", from_files=True)
    add_zip_case(sevenzip("aes256.zip", "-pgogi1234", "-mem=AES256"), "gogi1234", from_files=True)
    add_zip_case(sevenzip("aes128store.zip", "-pgogi1234", "-mem=AES128", "-mm=Copy"), "gogi1234", from_files=True)
else:
    print("7z not found: Deflate64 / 7-Zip AES cases skipped")

# 7) pyzipper AES (AE-2) all strengths
try:
    import pyzipper
    for bits in (128, 192, 256):
        p = os.path.join(WORK, "pyaes%d.zip" % bits)
        with pyzipper.AESZipFile(p, "w", compression=pyzipper.ZIP_DEFLATED,
                                 encryption=pyzipper.WZ_AES) as z:
            z.setpassword(b"meat")
            z.setencryption(pyzipper.WZ_AES, nbits=bits)
            for k, v in FILES.items():
                z.writestr(k, v)
        exp = {}
        with pyzipper.AESZipFile(p) as z:
            z.setpassword(b"meat")
            for i, info in enumerate(z.infolist()):
                exp[i] = (normalize(info.filename), z.read(info))
        cases.append((p, "meat", exp))
except ImportError:
    print("pyzipper missing: AES-pyzipper cases skipped")

# 8) Info-ZIP style traditional encryption via `zip -P` (data descriptor)
if shutil.which("zip"):
    p = os.path.join(WORK, "infozip.zip")
    if os.path.exists(p):
        os.remove(p)
    subprocess.run(["zip", "-q", "-r", "-P", "secret", p, "."], cwd=src, check=True)
    with zipfile.ZipFile(p) as z:
        names = [i.filename if i.flag_bits & 0x800 else i.filename.encode("cp437").decode("utf-8")
                 for i in z.infolist()]
    add_zip_case(p, "secret", names=names, from_files=True)

# 9) tar formats
def add_tar_case(path, mode, fmt):
    with tarfile.open(path, mode, format=fmt) as t:
        for k, v in FILES.items():
            ti = tarfile.TarInfo(k)
            ti.size = len(v)
            ti.mtime = 1600000000
            t.addfile(ti, io.BytesIO(v))
        long = "long/" + "아주긴이름" * 30 + ".txt"
        ti = tarfile.TarInfo(long); ti.size = 3; t.addfile(ti, io.BytesIO(b"abc"))
        ti = tarfile.TarInfo("dir1"); ti.type = tarfile.DIRTYPE; t.addfile(ti)
    exp = {}
    with tarfile.open(path) as t:
        for i, m in enumerate(t.getmembers()):
            exp[i] = (normalize(m.name), None if m.isdir() else t.extractfile(m).read())
    cases.append((path, None, exp))

add_tar_case(os.path.join(WORK, "pax.tar"), "w", tarfile.PAX_FORMAT)
add_tar_case(os.path.join(WORK, "gnu.tar"), "w", tarfile.GNU_FORMAT)
add_tar_case(os.path.join(WORK, "pax.tar.gz"), "w:gz", tarfile.PAX_FORMAT)
add_tar_case(os.path.join(WORK, "gnu.tgz"), "w:gz", tarfile.GNU_FORMAT)

# 10) single .gz (with and without FNAME) + multi-member
p = os.path.join(WORK, "single.txt.gz")
with open(p, "wb") as raw, gzip.GzipFile("single.txt", "wb", fileobj=raw) as g:
    g.write(FILES["big.bin"])
cases.append((p, None, {0: ("single.txt", FILES["big.bin"])}))
p = os.path.join(WORK, "multi.dat.gz")
with open(p, "wb") as f:
    f.write(gzip.compress(b"first member\n", mtime=0))
    f.write(gzip.compress(FILES["readme.txt"], mtime=0))
cases.append((p, None, {0: ("multi.dat", b"first member\n" + FILES["readme.txt"])}))

# ---------------- run ----------------
fails = 0
for path, pw, exp in cases:
    out = os.path.join(WORK, "out_" + os.path.basename(path))
    shutil.rmtree(out, ignore_errors=True)
    args = [BIN, path, out] + ([pw] if pw else [])
    r = subprocess.run(args, capture_output=True)
    if r.returncode:
        print("FAIL run", path, r.stdout.decode()[:300], r.stderr.decode()[:300])
        fails += 1
        continue
    rows = [l.split("\t") for l in r.stdout.decode().splitlines() if "\t" in l]
    got = {int(a): (int(b), int(c), e) for a, b, c, d, e in rows}
    bad = 0
    for i, (name, data) in exp.items():
        if i not in got:
            print("  missing entry", i, name); bad += 1; continue
        st, isdir, gname = got[i]
        if gname != name:
            print("  name mismatch #%d: got %r want %r" % (i, gname, name)); bad += 1
        if data is None:
            continue
        if st != 0:
            print("  extract error #%d %s: %d" % (i, name, st)); bad += 1; continue
        fp = os.path.join(out, "%d.bin" % i)
        if not os.path.exists(fp) or open(fp, "rb").read() != data:
            print("  data mismatch #%d %s" % (i, name)); bad += 1
    info = r.stderr.decode().strip().splitlines()[0] if r.stderr else ""
    print("%-4s %-22s %4d entries  %s" % ("ok" if not bad else "FAIL", os.path.basename(path), len(exp), info))
    fails += bad != 0

# wrong password must be rejected cleanly
wrong_src = os.path.join(WORK, "aes256.zip" if HAVE_7Z else "pyaes256.zip")
r = subprocess.run([BIN, wrong_src, os.path.join(WORK, "out_wrong"), "nope"],
                   capture_output=True)
rows = [l.split("\t") for l in r.stdout.decode().splitlines() if "\t" in l]
wrong_ok = all(int(row[1]) in (6, 0) and (int(row[1]) == 6 or int(row[2]) == 1) for row in rows)
print("%-4s wrong password rejected" % ("ok" if wrong_ok else "FAIL"))
fails += not wrong_ok
print("RESULT:", "OK" if not fails else "%d FAILED" % fails)
sys.exit(1 if fails else 0)
