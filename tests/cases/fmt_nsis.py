"""NSIS installer tests (src/fmt/nsis.c, NSIS mode of src/codec/inflate.c).

Fixtures are built at test time with makensis (NSIS 3: zlib / bzip2 / LZMA, solid
and non-solid, ANSI and Unicode, x86 and amd64 targets, "SetCompress off"): files
with Korean names in nested folders, File /r trees, /oname, duplicates, plug-ins,
uninstallers, shell folders, $OUTDIR chains, user variables, language strings and a
big file. 7-Zip is the reference for names, contents, sizes, times and methods.

NSIS 2 installers are synthesised from makensis output: the string table is
recoded to NSIS 2 codes (252..255) and the data recompressed with this module's
own Deflate writer in NSIS 2 form (stored blocks without NLEN) or with LZMA behind
7-Zip's BCJ flag byte; 7-Zip checks them too. Real NSIS 2 installers are downloaded
when the network allows (tests/data/nsis/README.md). Hostile inputs: truncations,
smashed header fields, bad string offsets, absurd sizes, overlapping solid data,
broken uninstaller patches, long SetOutPath chains and an in-process fuzzer.
"""
import os, struct, random, zlib, lzma, bisect, hashlib, shutil, subprocess, time, urllib.request, datetime

SIG = b"\xef\xbe\xad\xdeNullsoftInst"
PLUGDIR = "/usr/share/nsis/Plugins"

# ---------------------------------------------------------------- fixture data

def blob(n, seed, kind=1):
    rnd = random.Random(seed)
    if kind == 0:
        return rnd.randbytes(n)
    words = [b"samgyeopsal", b"moksal", b"galbi ", b"\xea\xb3\xa0\xea\xb8\xb0", b"installer\r\n", b"$INSTDIR", b"\x00\x01\x02"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words)
        if rnd.random() < 0.05:
            out += b"\xe8" + struct.pack("<i", rnd.randint(-5000, 5000))      # x86 CALL-like
    return bytes(out[:n])

BASE_FILES = {
    "a.txt": b"hello nsis\n" * 100,
    "rand.bin": blob(150000, 1, 0),
    "empty.txt": b"",
    "고기.txt": "삼겹살 목살\n".encode() * 30,
    "sub/b.txt": b"sub file\n" * 1000,
    "sub/deep/c.dat": bytes(range(256)) * 50,
    "tree/t1.txt": b"t1",
    "tree/x/t2.txt": blob(30000, 2),
    "tree/x/y/한글 폴더/깊은 파일.txt": "깊은 곳\n".encode() * 7,
    "code.bin": blob(60000, 3),
    "ro.txt": b"read only\n",
}

SCRIPT = r'''
Name "Gogi Test"
OutFile "{out}"
InstallDir "$PROGRAMFILES\GogiTest"
RequestExecutionLevel user
Var MyDir
LangString LS_NAME 1033 "langfile"
Page directory
Page instfiles
Section "Main"
  SetOutPath "$INSTDIR"
  File "src/a.txt"
  File "src/rand.bin"
  File "src/empty.txt"
  File "src/고기.txt"
  File "src/code.bin"
  File "src/ro.txt"
  SetFileAttributes "ro.txt" READONLY|HIDDEN
  File /r "src/tree"
  SetOutPath "$INSTDIR\sub"
  File "src/sub/b.txt"
  SetOutPath "$OUTDIR\deep"
  File "src/sub/deep/c.dat"
  SetOutPath "$INSTDIR"
  File /oname=renamed.txt "src/a.txt"
  File /oname=$(LS_NAME).txt "src/a.txt"
  StrCpy $MyDir "$INSTDIR\mine"
  SetOutPath $MyDir
  File "src/sub/b.txt"
  SetOutPath "$PROGRAMFILES\Common"
  File "src/a.txt"
  SetOutPath "$COMMONFILES\Gogi"
  File "src/sub/b.txt"
  SetOutPath "$APPDATA\Gogi"
  File "src/a.txt"
  SetOutPath "$LOCALAPPDATA\Gogi"
  File "src/code.bin"
  SetOutPath "$DESKTOP"
  File "src/sub/b.txt"
  SetOutPath "$TEMP\t"
  File "src/sub/b.txt"
  SetOutPath "$SYSDIR"
  File "src/a.txt"
  SetOutPath "$SMPROGRAMS\Gogi"
  File "src/sub/b.txt"
  SetOutPath "$EXEDIR"
  File "src/tree/t1.txt"
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "src/sub/b.txt"
  System::Call 'kernel32::GetTickCount()i .r0'
  nsExec::Exec "cmd"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteUninstaller "uninst2.exe"
SectionEnd
Section "Uninstall"
  Delete "$INSTDIR\a.txt"
  RMDir "$INSTDIR"
SectionEnd
'''

# names (as 7-Zip shows them) -> source file
EXPECT_NAMES = {
    "a.txt": "a.txt", "rand.bin": "rand.bin", "empty.txt": "empty.txt", "고기.txt": "고기.txt",
    "code.bin": "code.bin", "ro.txt": "ro.txt", "tree/t1.txt": "tree/t1.txt",
    "tree/x/t2.txt": "tree/x/t2.txt", "tree/x/y/한글 폴더/깊은 파일.txt": "tree/x/y/한글 폴더/깊은 파일.txt",
    "sub/b.txt": "sub/b.txt", "sub/deep/c.dat": "sub/deep/c.dat", "renamed.txt": "a.txt",
    "$(LSTR_37).txt": "a.txt", "$_0_/b.txt": "sub/b.txt", "$PROGRAMFILES/Common/a.txt": "a.txt",
    "$COMMONFILES/Gogi/b.txt": "sub/b.txt", "$APPDATA/Gogi/a.txt": "a.txt",
    "$LOCALAPPDATA/Gogi/code.bin": "code.bin", "$DESKTOP/b.txt": "sub/b.txt", "$TEMP/t/b.txt": "sub/b.txt",
    "$SYSDIR/a.txt": "a.txt", "$SMPROGRAMS/Gogi/b.txt": "sub/b.txt", "$EXEDIR/t1.txt": "tree/t1.txt",
    "$PLUGINSDIR/b.txt": "sub/b.txt",
}


def write(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


def makensis(t, wdir, name, body, head):
    nsi = os.path.join(wdir, name + ".nsi")
    with open(nsi, "w", encoding="utf-8") as f:
        f.write(head + "\n" + body.replace("{out}", name + ".exe"))
    out = os.path.join(wdir, name + ".exe")
    if os.path.exists(out):
        os.remove(out)
    t.sh(["makensis", "-V1", "-INPUTCHARSET", "UTF8", nsi], cwd=wdir)
    return out


def head_for(comp, solid, charset):
    h = "Target %s\n" % charset
    if comp == "off":
        return h + "SetCompress off\n"
    return h + "SetCompressor %s%s\n" % ("/SOLID " if solid else "", comp)

# ---------------------------------------------------------------- NSIS structure helpers

def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def find_fh(b):
    for o in range(0, len(b) - 28, 512):
        if b[o + 4:o + 20] == SIG:
            return o
    return -1


def split_copy(b):
    """'SetCompress off' installer -> (stub, flags, header, data area)"""
    o = find_fh(b)
    flags, hsize, asize = u32(b, o), u32(b, o + 20), u32(b, o + 24)
    assert u32(b, o + 28) == hsize, "header is compressed"
    crc = 4 if (flags & 8) or not (flags & 4) else 0
    return b[:o], flags, b[o + 32:o + 32 + hsize], b[o + 32 + hsize:o + asize - crc]


def blocks_of(h):
    """block table (32-bit layout): [(offset, num)] x 8"""
    return [struct.unpack_from("<II", h, 4 + 8 * k) for k in range(8)]


def commands(h):
    off, num = blocks_of(h)[2]
    return [(off + 28 * i, list(struct.unpack_from("<7I", h, off + 28 * i))) for i in range(num)]


def to_nsis2(h):
    """NSIS 3 ANSI string codes (1..4) -> NSIS 2 (255, 254, 253, 252), same lengths"""
    bl = blocks_of(h)
    so, lo = bl[3][0], bl[4][0]
    st = bytearray(h[so:lo])
    assert st[:2] != b"\0\0", "Unicode header"
    i = 0
    while i < len(st):
        c = st[i]
        assert c != 4 and c < 252, "string needs an escape"
        if 1 <= c <= 3:
            st[i] = {1: 255, 2: 254, 3: 253}[c]
            i += 3
        else:
            i += 1
    return h[:so] + bytes(st) + h[lo:]


class BitW:
    def __init__(self):
        self.out, self.acc, self.n = bytearray(), 0, 0

    def bits(self, v, n):
        self.acc |= v << self.n
        self.n += n
        while self.n >= 8:
            self.out.append(self.acc & 255)
            self.acc >>= 8
            self.n -= 8

    def huff(self, code, n):
        self.bits(int(format(code, "0%db" % n)[::-1], 2), n)

    def align(self):
        if self.n:
            self.out.append(self.acc & 255)
        self.acc = self.n = 0


LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
LEN_EXTRA = [0] * 8 + [1] * 4 + [2] * 4 + [3] * 4 + [4] * 4 + [5] * 4 + [0]
DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073,
             4097, 6145, 8193, 12289, 16385, 24577]
DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]


def fixed_sym(w, s):
    if s < 144:
        w.huff(0x30 + s, 8)
    elif s < 256:
        w.huff(0x190 + s - 144, 9)
    elif s < 280:
        w.huff(s - 256, 7)
    else:
        w.huff(0xC0 + s - 280, 8)


def deflate(data, seed, nsis=True, stored_ratio=0.35, stored_from=0):
    """Deflate writer: random mix of stored blocks (NSIS 2 form: LEN without NLEN when
    nsis) at any bit position and fixed-Huffman blocks with LZ77 matches that reach
    back into earlier blocks."""
    rnd = random.Random(seed)
    w, pos, n, hist = BitW(), 0, len(data), {}
    while True:
        blen = min(n - pos, rnd.choice([0, 1, 7, 300, 5000, 40000, 65535]))
        final = pos + blen >= n
        if pos >= stored_from and rnd.random() < stored_ratio:
            w.bits(int(final), 1)
            w.bits(0, 2)
            w.align()
            w.out += struct.pack("<H", blen)
            if not nsis:
                w.out += struct.pack("<H", blen ^ 0xFFFF)
            w.out += data[pos:pos + blen]
            for k in range(pos, pos + blen - 2, 3):
                hist[data[k:k + 3]] = k
        else:
            w.bits(int(final), 1)
            w.bits(1, 2)
            i, end = pos, pos + blen
            while i < end:
                j = hist.get(data[i:i + 3]) if i + 3 <= end else None
                if j is not None and i - j <= 32768:
                    L = 3
                    while L < 258 and i + L < end and data[j + L] == data[i + L]:
                        L += 1
                    c = 28 if L == 258 else bisect.bisect_right(LEN_BASE, L) - 1
                    fixed_sym(w, 257 + c)
                    w.bits(L - LEN_BASE[c], LEN_EXTRA[c])
                    d = i - j
                    dc = bisect.bisect_right(DIST_BASE, d) - 1
                    w.huff(dc, 5)
                    w.bits(d - DIST_BASE[dc], DIST_EXTRA[dc])
                    for k in range(i, i + L):
                        hist[data[k:k + 3]] = k
                    i += L
                    continue
                fixed_sym(w, data[i])
                hist[data[i:i + 3]] = i
                i += 1
            fixed_sym(w, 256)
        pos += blen
        if final:
            break
    w.align()
    return bytes(w.out)


def lzma_nsis(data, bcj):
    """[BCJ flag]? 5D dict(23) + raw LZMA (with end marker), like 7-Zip's modified NSIS"""
    filt = ([{"id": lzma.FILTER_X86}] if bcj else []) + \
           [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 23, "lc": 3, "lp": 0, "pb": 2}]
    raw = lzma.compress(data, format=lzma.FORMAT_RAW, filters=filt)
    return (b"\x01" if bcj else b"") + b"\x5d" + struct.pack("<I", 1 << 23) + raw


def repack(stub, flags, h, data, comp, solid, seed=1):
    """Rebuild an installer from a stored header + data area with another compression."""
    def cz(x):
        return deflate(x, seed) if comp == "zlib" else lzma_nsis(x, comp == "lzma_bcj")
    if solid:
        body = cz(struct.pack("<I", len(h)) + h + data)
    else:
        pmap, nd, pos = {}, bytearray(), 0
        while pos < len(data):
            sz = u32(data, pos)
            blk = data[pos + 4:pos + 4 + sz]
            pmap[pos] = len(nd)
            c = cz(blk)
            nd += (struct.pack("<I", len(c) | 0x80000000) + c) if len(c) < len(blk) else (struct.pack("<I", sz) + blk)
            pos += 4 + sz
        hb = bytearray(h)
        for off, c in commands(h):
            if c[0] == 20:
                struct.pack_into("<I", hb, off + 12, pmap[c[3]])
            elif c[0] == 62:
                struct.pack_into("<I", hb, off + 8, pmap[c[2]])
        hc = cz(bytes(hb))
        body = struct.pack("<I", len(hc) | 0x80000000) + hc + bytes(nd)
    fh = struct.pack("<I", flags & ~4) + SIG + struct.pack("<II", len(h), 28 + len(body) + 4)
    exe = stub + fh + body
    return exe + struct.pack("<I", zlib.crc32(exe[512:]))

# ---------------------------------------------------------------- comparisons

def sevenzip_slt(t, arc):
    r = t.sh(["7z", "l", "-slt", arc], env=dict(os.environ, TZ="UTC"))
    items, cur, started = [], None, False
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("----------"):
            started = True
            continue
        if not started:
            continue
        if line.startswith("Path = "):
            cur = {"Path": line[7:]}
            items.append(cur)
        elif cur is not None and " = " in line:
            k, v = line.split(" = ", 1)
            cur[k] = v
        elif cur is not None and line.endswith(" ="):
            cur[line[:-2]] = ""
    return items


def drv_list(t, drv, arc):
    r = t.sh([drv, "list", arc], check=False)
    rows = []
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if len(p) == 7 and p[0].isdigit():
            rows.append(dict(name=p[1], usize=int(p[2]), csize=int(p[3]), method=p[4], ft=int(p[5]), attr=int(p[6])))
    return rows


def ft_text(ft):
    s, frac = divmod(ft - 116444736000000000, 10000000)
    return (datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=s)).strftime("%Y-%m-%d %H:%M:%S") + ".%07d" % frac


def check_props(t, drv, arc, label):
    """names, order, sizes, times, attributes and methods vs 7z l -slt"""
    ref = sevenzip_slt(t, arc)
    got = drv_list(t, drv, arc)
    probs = []
    if [x["Path"] for x in ref] != [g["name"] for g in got]:
        probs.append("names/order: %r vs %r" % ([x["Path"] for x in ref][:6], [g["name"] for g in got][:6]))
    meth = {"Copy": "Store", "Deflate": "zlib"}
    for x, g in zip(ref, got):
        # 7-Zip shows the patch block size for stored uninstallers; ours is the output size
        if x.get("Size", "") != ("" if g["usize"] < 0 else str(g["usize"])) and "unins" not in g["name"]:
            probs.append("%s size %r/%d" % (g["name"], x.get("Size"), g["usize"]))
        if x.get("Solid") == "-" and x.get("Packed Size", "") != ("" if g["csize"] < 0 else str(g["csize"])) \
                and not g["name"].endswith(".exe"):
            probs.append("%s csize %r/%d" % (g["name"], x.get("Packed Size"), g["csize"]))
        if x.get("Modified", "") != (ft_text(g["ft"]) if g["ft"] else ""):
            probs.append("%s time %r/%r" % (g["name"], x.get("Modified"), ft_text(g["ft"]) if g["ft"] else ""))
        m = x.get("Method", "")
        if m.startswith("BCJ "):
            m = m[4:] + " BCJ" if m[4:].startswith("LZMA") else meth.get(m[4:], m[4:])
        else:
            m = meth.get(m, m)
        if m != g["method"]:
            probs.append("%s method %r/%r" % (g["name"], x.get("Method"), g["method"]))
        want_attr = {"": 0, "RH": 3}.get(x.get("Attributes", ""), -1)
        if want_attr != g["attr"]:
            probs.append("%s attr %r/%d" % (g["name"], x.get("Attributes"), g["attr"]))
    return t.record(not probs, label, "; ".join(probs[:6]) or "%d entries" % len(got))


def check_expected(t, arc, src, label, prefix_map=None):
    """our extraction against the source files (names as 7-Zip shows them)"""
    exp = {}
    for name, srcname in EXPECT_NAMES.items():
        exp[name] = src[srcname]
    return t.check_extract(arc, exp, label=label, allow_extra=True, expect_type="NSIS")


def download(t, name, url, sha):
    """cached download of a public test fixture; None when offline"""
    cache = os.path.join(os.path.dirname(t.work), "nsis_dl")
    os.makedirs(cache, exist_ok=True)
    p = os.path.join(cache, name)
    if not os.path.exists(p):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                data = r.read()
        except Exception:
            return None
        if hashlib.sha256(data).hexdigest() != sha:
            return None
        write(p, data)
    return p

# ---------------------------------------------------------------- tests

def run(t):
    t.need("makensis", "7z")
    wd = t.path("nsis")
    os.makedirs(wd, exist_ok=True)
    src = dict(BASE_FILES)
    t.write_tree(os.path.join(wd, "src"), src)
    drv = t.build_driver("tests/drivers/nsis_drv.c")
    have_amd64 = os.path.isdir(os.path.join(PLUGDIR, "amd64-unicode"))
    plug = {cs: open(os.path.join(PLUGDIR, cs, "System.dll"), "rb").read()
            for cs in ("x86-unicode", "x86-ansi", "amd64-unicode") if os.path.exists(os.path.join(PLUGDIR, cs, "System.dll"))}

    # ---- makensis matrix ----
    built = {}
    for comp in ("zlib", "bzip2", "lzma", "off"):
        for solid in ((False, True) if comp != "off" else (False,)):
            for cs in ("x86-unicode", "x86-ansi", "amd64-unicode"):
                if cs == "amd64-unicode" and (not have_amd64 or comp == "bzip2"):
                    continue
                name = "%s%s_%s" % (comp, "_solid" if solid else "", cs)
                arc = makensis(t, wd, name, SCRIPT, head_for(comp, solid, cs))
                built[name] = arc
                t.check_vs_7z(arc, label="7z " + name, expect_type="NSIS")
                check_props(t, drv, arc, "props " + name)
                if "unicode" in cs:
                    check_expected(t, arc, src, "content " + name)
                r, typ, rows = t.listing(arc)
                names = [x["name"] for x in rows]
                okp = "$PLUGINSDIR/System.dll" in names and "uninstall.exe" in names and "uninst2.exe" in names
                if cs in plug and okp:
                    rr, rws, out = t.extract(arc)
                    idx = [i for i, v in rws.items() if v[3] == "$PLUGINSDIR/System.dll"]
                    okp = bool(idx) and open(os.path.join(out, "%d.bin" % idx[0]), "rb").read() == plug[cs]
                t.record(okp, "plugin + uninstallers " + name)
                rr = t.sh([drv, "subsets", arc], check=False)
                t.record(rr.returncode == 0, "subsets " + name, rr.stdout.decode(errors="replace")[-300:])

    # the uninstaller is an NSIS archive of its own (uninstall flag set)
    r, out = t.sevenzip_extract(built["lzma_solid_x86-unicode"])
    un = os.path.join(out, "uninstall.exe")
    if os.path.exists(un):
        r2 = t.run_gzt(["l", un])
        t.record(r2.returncode == 0 and b"TYPE\tNSIS" in r2.stdout, "uninstaller opens as NSIS",
                 r2.stdout.decode(errors="replace")[:200])

    # ---- methods shown ----
    for name, want in (("lzma_solid_x86-unicode", "LZMA:23"), ("zlib_x86-ansi", "zlib"),
                       ("bzip2_solid_x86-ansi", "BZip2"), ("off_x86-unicode", "Store")):
        r, typ, rows = t.listing(built[name])
        ms = {x["method"] for x in rows}
        t.record(want in ms and (want != "zlib" or "Store" in ms), "method " + name, repr(sorted(ms)))

    # ---- CP949 names in an ANSI installer ----
    ko = makensis(t, wd, "ansi_ko", r'''
Name "ko"
OutFile "{out}"
RequestExecutionLevel user
Section
  SetOutPath "$INSTDIR\KOD1"
  File /oname=KOF1.txt "src/a.txt"
  File /oname=KOF2KOF3.dat "src/sub/b.txt"
SectionEnd
''', "Target x86-ansi\nSetCompress off\n")
    b = bytearray(open(ko, "rb").read())
    for ph, kw in ((b"KOD1", "폴더"), (b"KOF1", "고기"), (b"KOF2", "삼겹"), (b"KOF3", "살맛")):
        cp = kw.encode("cp949")
        assert len(cp) == len(ph)
        k = b.find(ph)
        while k >= 0:
            b[k:k + len(ph)] = cp
            k = b.find(ph)
    write(ko, bytes(b))
    t.check_extract(ko, {"폴더/고기.txt": src["a.txt"], "폴더/삼겹살맛.dat": src["sub/b.txt"]}, acp=949,
                    label="ANSI installer, CP949 names")

    # ---- big file, many files ----
    big = {"big/big.bin": blob(24 << 20, 7), "big/rand.bin": blob(3 << 20, 8, 0)}
    for i in range(1500):
        big["many/d%02d/f%04d.txt" % (i % 37, i)] = b"file %d\n" % i * (i % 7)
    t.write_tree(os.path.join(wd, "srcbig"), big)
    for comp, solid in (("lzma", True), ("zlib", False), ("bzip2", True)):
        name = "big_%s%s" % (comp, "_solid" if solid else "")
        arc = makensis(t, wd, name, r'''
Name "big"
OutFile "{out}"
RequestExecutionLevel user
Section
  SetOutPath "$INSTDIR"
  File /r "srcbig\*.*"
SectionEnd
''', head_for(comp, solid, "x86-unicode"))
        t.check_extract(arc, big, label="big " + name)
        t0 = time.time()
        t.extract(arc)
        dt = time.time() - t0
        t1 = time.time()
        t.sevenzip_extract(arc)
        d7 = time.time() - t1
        t.record(True, "speed " + name, "gzt x %.2fs, 7z x %.2fs (%d MiB)" % (dt, d7, sum(map(len, big.values())) >> 20))

    # ---- NSIS 2 (synthesised) ----
    for cs in ("x86-ansi",):
        stub, flags, h, data = split_copy(open(built["off_" + cs], "rb").read())
        h2 = to_nsis2(h)
        for comp in ("zlib", "lzma", "lzma_bcj"):
            for solid in (False, True):
                name = "nsis2_%s%s" % (comp, "_solid" if solid else "")
                arc = write(os.path.join(wd, name + ".exe"), repack(stub, flags, h2, data, comp, solid, seed=len(name)))
                t.check_vs_7z(arc, label="7z " + name, expect_type="NSIS")
                check_props(t, drv, arc, "props " + name)
                rr = t.sh([drv, "subsets", arc], check=False)
                t.record(rr.returncode == 0, "subsets " + name, rr.stdout.decode(errors="replace")[-300:])
    # NSIS 3 solid zlib is standard Deflate: stored blocks with NLEN in the data (7-Zip
    # agrees) and in the header too (7-Zip reads headers as NSIS-2 Deflate; we retry)
    r, ref = t.sevenzip_extract(built["off_x86-unicode"])
    ref = t.read_tree(ref)
    stub, flags, h, data = split_copy(open(built["off_x86-unicode"], "rb").read())
    for name, sfrom in (("nsis3_zlib_std_solid", 4 + len(h)), ("nsis3_zlib_std_solid_hdr", 0)):
        body = deflate(struct.pack("<I", len(h)) + h + data, 5, nsis=False, stored_ratio=0.5, stored_from=sfrom)
        fh = struct.pack("<I", flags & ~4) + SIG + struct.pack("<II", len(h), 28 + len(body) + 4)
        exe = stub + fh + body
        arc = write(os.path.join(wd, name + ".exe"), exe + struct.pack("<I", zlib.crc32(exe[512:])))
        if sfrom:
            t.check_vs_7z(arc, label="7z " + name, expect_type="NSIS")
        t.check_extract(arc, ref, label="content " + name, expect_type="NSIS")

    # ---- NSIS-2 Deflate codec ----
    for seed, n, kind in ((1, 0, 1), (2, 1, 1), (3, 70000, 0), (4, 400000, 1), (5, 1 << 20, 1), (6, 300000, 0)):
        data = blob(n, seed + 100, kind)
        std = deflate(data, seed, nsis=False, stored_ratio=0.5)
        okz = zlib.decompressobj(-15).decompress(std) == data          # the writer itself
        ns = write(t.path("nsdef_%d.bin" % seed), deflate(data, seed, nsis=True, stored_ratio=0.5))
        o = t.path("nsdef_%d.out" % seed)
        r = t.sh([drv, "inflate", ns, o, "1"], check=False)
        ok = okz and r.returncode == 0 and open(o, "rb").read() == data
        write(t.path("stdef_%d.bin" % seed), std)
        r2 = t.sh([drv, "inflate", t.path("stdef_%d.bin" % seed), o, "0"], check=False)
        ok = ok and r2.returncode == 0 and open(o, "rb").read() == data
        t.record(ok, "NSIS Deflate stream %d (%d bytes)" % (seed, n),
                 "writer ok=%s %s %s" % (okz, r.stdout.decode().strip(), r2.stdout.decode().strip()))

    # ---- real NSIS 2 installers (downloaded) ----
    dl = [("7z920.exe", "https://www.7-zip.org/a/7z920.exe",
           "1e2f2a8fb52d3972b9b65b8ad1bebb66965c47a2994f89b3d652c31e6f6e4c3c"),
          ("nsis-2.46-setup.exe", "https://downloads.sourceforge.net/project/nsis/NSIS%202/2.46/nsis-2.46-setup.exe",
           "69c2ae5c9f2ee45b0626905faffaa86d4e2fc0d3e8c118c8bc6899df68467b32"),
          ("nsis20.exe", "https://downloads.sourceforge.net/project/nsis/NSIS%202/2.0/nsis20.exe",
           "d9e5e3094641b350b2ed9f8bb7097404b094c4e92ed77b47775e410ee1487ce3")]
    for name, url, sha in dl:
        p = download(t, name, url, sha)
        if not p:
            t.record(True, "download " + name, "skipped (offline)")
            continue
        t.check_vs_7z(p, label="7z " + name, expect_type="NSIS")
        check_props(t, drv, p, "props " + name)

    # ---- hostile ----
    hostile(t, drv, wd, built)


def hostile(t, drv, wd, built):
    hd = t.path("hostile")
    os.makedirs(hd, exist_ok=True)
    rnd = random.Random(77)
    # truncations
    for name in ("lzma_solid_x86-unicode", "zlib_x86-ansi", "bzip2_solid_x86-ansi", "off_x86-unicode", "lzma_x86-unicode"):
        b = open(built[name], "rb").read()
        o = find_fh(b)
        cuts = sorted({o + 3, o + 27, o + 28, o + 31, o + 40, o + 200, o + 2000, len(b) - 5, len(b) - 1000,
                       (o + len(b)) // 2, len(b) * 3 // 4})
        for k, cut in enumerate(cuts):
            p = write(os.path.join(hd, "trunc_%s_%d.exe" % (name, k)), b[:cut])
            t.check_hostile(p)
    # firstheader fields
    b = open(built["lzma_solid_x86-unicode"], "rb").read()
    o = find_fh(b)
    for k, (off, val) in enumerate(((0, 0xFFFFFFFF), (0, 0x10), (20, 0xFFFFFFFF), (20, 0), (20, 0x7FFFFFF0), (20, 1),
                                    (24, 29), (24, 0xFFFFFFFF), (24, 28), (28, 0x80000000), (28, 0x7FFFFFFF))):
        x = bytearray(b)
        struct.pack_into("<I", x, o + off, val)
        t.check_hostile(write(os.path.join(hd, "fh_%d.exe" % k), bytes(x)))
    # header structures of stored-header installers (ANSI and Unicode)
    for cs in ("x86-ansi", "x86-unicode"):
        b = open(built["off_" + cs], "rb").read()
        o = find_fh(b)
        hs = o + 32
        stub, flags, h, data = split_copy(b)
        bl = blocks_of(h)
        cmds = commands(h)
        nch = bl[4][0] - bl[3][0]
        muts = []
        for k in range(8):                                         # block table
            muts += [(4 + 8 * k, 0xFFFFFFFF), (8 + 8 * k, 0x7FFFFFFF), (4 + 8 * k, len(h))]
        muts += [(4 + 8 * 4, bl[3][0]), (4 + 8 * 4, bl[3][0] + 1), (4 + 8 * 3, bl[4][0] - 1)]
        for off, c in cmds:
            if c[0] == 20:                                         # EW_EXTRACTFILE
                muts += [(off + 8, 0x7FFFFFFF), (off + 8, nch - 1), (off + 8, 0xFFFFFFF0), (off + 12, 0xFFFFFFFF),
                         (off + 12, len(data) - 2), (off + 12, len(data) + 100)]
            elif c[0] == 11 and c[2]:                              # SetOutPath
                muts += [(off + 4, 0x80000000), (off + 4, nch + 5)]
            elif c[0] == 62:                                       # WriteUninstaller
                muts += [(off + 8, len(data) - 4), (off + 12, 0xFFFFFFFF), (off + 12, 3), (off + 16, 0x7FFFFFFF)]
        muts = rnd.sample(muts, min(len(muts), 60))
        for k, (off, val) in enumerate(muts):
            x = bytearray(b)
            struct.pack_into("<I", x, hs + off, val)
            t.check_hostile(write(os.path.join(hd, "hdr_%s_%d.exe" % (cs, k)), bytes(x)))
        # string table: codes at the very end, bad shell / variable numbers
        so, lo = bl[3][0], bl[4][0]
        for k in range(40):
            x = bytearray(b)
            pos = hs + so + rnd.randrange(lo - so)
            x[pos] = rnd.choice([1, 2, 3, 4, 0xFF, 0x80, 0])
            if pos + 1 < hs + lo:
                x[pos + 1] = rnd.choice([0x80, 0xFF, 0x7F, 1])
            t.check_hostile(write(os.path.join(hd, "str_%s_%d.exe" % (cs, k)), bytes(x)))
        # data block size words
        for k in range(12):
            x = bytearray(b)
            off = 0
            for _ in range(rnd.randrange(4)):
                off += 4 + u32(data, off)
                if off >= len(data):
                    off = 0
            struct.pack_into("<I", x, hs + len(h) + off, rnd.choice([0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0x80000010,
                                                                     len(data), 0x80000000 | len(data)]))
            t.check_hostile(write(os.path.join(hd, "blk_%s_%d.exe" % (cs, k)), bytes(x)))
    # solid streams with broken size words / overlapping positions / bad patches (recompressed)
    stub, flags, h, data = split_copy(open(built["off_x86-unicode"], "rb").read())
    for k in range(10):
        hb, db = bytearray(h), bytearray(data)
        cmds = commands(h)
        if k < 4:
            pos = rnd.choice([c[3] for off, c in cmds if c[0] == 20])
            struct.pack_into("<I", db, pos, rnd.choice([0xFFFFFFF0, 0x7FFFFFFF, len(data), 3]))
        elif k < 7:
            for off, c in cmds:
                if c[0] == 20 and rnd.random() < 0.5:
                    struct.pack_into("<I", hb, off + 12, rnd.randrange(len(data)))   # inside other data
        else:
            for off, c in cmds:
                if c[0] == 62:
                    p = c[2]
                    if k == 7:
                        struct.pack_into("<I", hb, off + 12, c[3] + 1)               # patch size mismatch
                    else:
                        struct.pack_into("<II", db, p + 4, 0x10000, 0x7FFFFF00)      # patch out of range
        body = zlib.compress(struct.pack("<I", len(h)) + bytes(hb) + bytes(db), 1)[2:-4]
        fh = struct.pack("<I", 4) + SIG + struct.pack("<II", len(h), 28 + len(body))
        t.check_hostile(write(os.path.join(hd, "solid_%d.exe" % k), stub + fh + body))
    # long SetOutPath $OUTDIR chain (prefix capped), thousands of files in one folder
    body = "\n".join("  SetOutPath \"$OUTDIR\\abcdefghij\"" for _ in range(4000))
    arc = makensis(t, hd, "chain", r'''
Name "chain"
OutFile "{out}"
RequestExecutionLevel user
Section
  SetOutPath "$INSTDIR"
%s
  File /oname=deep.txt "../nsis/src/a.txt"
SectionEnd
''' % body, "Target x86-unicode\nSetCompress off\n")
    rows = drv_list(t, drv, arc)
    t.record(len(rows) == 1 and rows[0]["name"].endswith("/deep.txt"), "SetOutPath chain (name kept)",
             rows[0]["name"][-40:] if rows else "no entry")
    t.check_hostile(arc)
    # in-process fuzzer (ASan/UBSan when HOST_CFLAGS asks for it)
    iters = 400 if "sanitize" in os.environ.get("HOST_CFLAGS", "") else 1500
    for name in ("off_x86-unicode", "off_x86-ansi", "zlib_x86-ansi", "lzma_x86-unicode", "lzma_solid_x86-ansi",
                 "bzip2_x86-unicode"):
        try:
            r = t.sh([drv, "fuzz", built[name], str(iters), str(len(name))], check=False, timeout=900)
            t.record(r.returncode == 0 and r.stdout.startswith(b"ok"), "fuzz " + name,
                     (r.stdout + r.stderr).decode(errors="replace")[-300:])
        except subprocess.TimeoutExpired:
            t.record(False, "fuzz " + name, "timeout")
