"""Compound File Binary (OLE2 / MSI) reader: v3/v4, DIFAT, MiniFAT, storages, MSI names, views,
nested archives, hostile inputs. Fixtures come from a small CFB writer below, wixl and msibuild."""
import os, io, random, shutil, struct, subprocess, zipfile

NOSTREAM = FREE = 0xFFFFFFFF
END, FATSEC, DIFSEC = 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC
SIG = bytes.fromhex("D0CF11E0A1B11AE1")
MSI_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
FT = 132000000000000000          # a FILETIME (2019)

def msi_encode(name, table=False):
    """MSI stream name compression (as msitools / Windows Installer write it)."""
    out = [chr(0x4840)] if table else []
    i = 0
    while i < len(name):
        c = name[i]
        if c in MSI_CHARS:
            m1 = MSI_CHARS.index(c)
            if i + 1 < len(name) and name[i + 1] in MSI_CHARS:
                out.append(chr(0x3800 + m1 + (MSI_CHARS.index(name[i + 1]) << 6)))
                i += 2
                continue
            out.append(chr(0x4800 + m1))
        else:
            out.append(c)
        i += 1
    return "".join(out)

def shown(name):
    """Name 고깃ZIP / 7-Zip show for a raw CFB name."""
    return "".join("[%d]" % ord(c) if ord(c) < 0x20 else c for c in name)

class Node:
    def __init__(self, name, data=None, kids=None, ctime=0, mtime=0):
        self.name, self.data, self.kids, self.ctime, self.mtime = name, data, kids, ctime, mtime

def S(name, data, **kw):
    return Node(name, data=data, **kw)

def D(name, *kids, **kw):
    return Node(name, kids=list(kids), **kw)

def expected(nodes, prefix=""):
    """{path: bytes | None} as listed by the reader (names already shown)."""
    out = {}
    for n in nodes:
        p = prefix + shown(n.name)
        if n.kids is not None:
            out[p] = None
            out.update(expected(n.kids, p + "/"))
        else:
            out[p] = n.data
    return out

def build_cfb(nodes, v=3, shift=None, mshift=6, cutoff=4096, seed=None, pad_last=True, msect_seed=None):
    """Write a compound file. seed: shuffle the physical sector order (fragmented chains);
    msect_seed: shuffle mini sectors. Returns (bytes, info) with offsets for tampering."""
    shift = shift or (9 if v == 3 else 12)
    ss, ms = 1 << shift, 1 << mshift
    epsec = ss // 4
    ents = [dict(name="Root Entry", type=5, left=NOSTREAM, right=NOSTREAM, child=NOSTREAM, start=END,
                 size=0, ctime=0, mtime=0)]
    streams = []

    def add(parent, kids):
        idxs = []
        for k in kids:
            i = len(ents)
            ents.append(dict(name=k.name, type=1 if k.kids is not None else 2, left=NOSTREAM, right=NOSTREAM,
                             child=NOSTREAM, start=END, size=0, ctime=k.ctime, mtime=k.mtime, data=k.data))
            idxs.append(i)
            if k.kids is not None:
                add(i, k.kids)
            else:
                streams.append(i)
        order = sorted(idxs, key=lambda i: (len(ents[i]["name"]), ents[i]["name"].upper()))

        def bal(lo, hi):
            if lo >= hi:
                return NOSTREAM
            mid = (lo + hi) // 2
            e = ents[order[mid]]
            e["left"], e["right"] = bal(lo, mid), bal(mid + 1, hi)
            return order[mid]
        ents[parent]["child"] = bal(0, len(order))
    add(0, nodes)

    # mini stream
    mini = [i for i in streams if 0 < len(ents[i]["data"]) < cutoff]
    nmini = sum((len(ents[i]["data"]) + ms - 1) // ms for i in mini)
    mpos = list(range(nmini))
    if msect_seed is not None:
        random.Random(msect_seed).shuffle(mpos)
    mstream = bytearray(nmini * ms)
    mfat = [FREE] * nmini
    k = 0
    for i in mini:
        d = ents[i]["data"]
        cnt = (len(d) + ms - 1) // ms
        chain = mpos[k:k + cnt]
        k += cnt
        for j, m in enumerate(chain):
            mstream[m * ms:m * ms + ms] = d[j * ms:(j + 1) * ms].ljust(ms, b"\0")
            mfat[m] = chain[j + 1] if j + 1 < cnt else END
        ents[i]["start"], ents[i]["size"] = chain[0], len(d)
    ents[0]["size"] = len(mstream)

    def sectors(b, fill=b"\0"):
        return [b[o:o + ss].ljust(ss, fill) for o in range(0, len(b), ss)]

    def dir_entry(e):
        nm = e["name"].encode("utf-16-le")[:62]
        return ((nm + b"\0\0").ljust(64, b"\0") +
                struct.pack("<HBBIII", len(nm) + 2, e["type"], 1, e["left"], e["right"], e["child"]) +
                b"\0" * 20 + struct.pack("<QQIQ", e["ctime"], e["mtime"], e["start"], e["size"]))
    empty = dict(name="", type=0, left=NOSTREAM, right=NOSTREAM, child=NOSTREAM, ctime=0, mtime=0, start=0, size=0)
    ndir = -(-len(ents) * 128 // ss)

    # logical chains: (key, [sector bytes]); the directory is filled in once starts are known
    chains = [("dir", [b""] * ndir)]
    if mfat:
        chains.append(("mfat", sectors(b"".join(struct.pack("<I", x) for x in mfat), b"\xff")))
    if mstream:
        chains.append(("mstream", sectors(bytes(mstream))))
    for i in streams:
        if len(ents[i]["data"]) >= cutoff:
            chains.append((i, sectors(ents[i]["data"])))
    reserved = max(0, 512 // ss - 1)          # 128/256-byte sectors overlapping the header
    nl = reserved + sum(len(c[1]) for c in chains)
    nf = 1
    while True:
        nd = max(0, -(-(nf - 109) // (epsec - 1)))
        if nf * epsec >= nl + nf + nd:
            break
        nf += 1
    total = nl + nf + nd
    phys = list(range(reserved, total))
    if seed is not None:
        random.Random(seed).shuffle(phys)
    fat_ids, dif_ids = phys[:nf], phys[nf:nf + nd]
    fat = [FREE] * (nf * epsec)
    for s in fat_ids:
        fat[s] = FATSEC
    for s in dif_ids:
        fat[s] = DIFSEC
    content, starts = {}, {}
    k = nf + nd
    for key, secs in chains:
        ids = phys[k:k + len(secs)]
        k += len(secs)
        for j, s in enumerate(ids):
            fat[s] = ids[j + 1] if j + 1 < len(ids) else END
            content[s] = secs[j]
        starts[key] = ids
    for j, s in enumerate(fat_ids):
        content[s] = b"".join(struct.pack("<I", x) for x in fat[j * epsec:(j + 1) * epsec])
    rest = fat_ids[109:]
    for j, s in enumerate(dif_ids):
        part = rest[j * (epsec - 1):(j + 1) * (epsec - 1)]
        part += [FREE] * (epsec - 1 - len(part))
        content[s] = b"".join(struct.pack("<I", x) for x in part + [dif_ids[j + 1] if j + 1 < nd else END])
    if mstream:
        ents[0]["start"] = starts["mstream"][0]
    for i in streams:
        if len(ents[i]["data"]) >= cutoff:
            ents[i]["start"], ents[i]["size"] = starts[i][0], len(ents[i]["data"])
    dirb = b"".join(dir_entry(e) for e in ents)
    dirb += dir_entry(empty) * ((ndir * ss - len(dirb)) // 128)
    for j, s in enumerate(starts["dir"]):
        content[s] = dirb[j * ss:(j + 1) * ss]
    hdr = bytearray(512)
    hdr[0:8] = SIG
    struct.pack_into("<HHHHH", hdr, 0x18, 0x3E, v, 0xFFFE, shift, mshift)
    struct.pack_into("<IIIIIIIIII", hdr, 0x28, ndir if v == 4 else 0, nf, starts["dir"][0], 0, cutoff,
                     starts["mfat"][0] if mfat else END, len(starts.get("mfat", [])), dif_ids[0] if nd else END, nd, 0)
    for j in range(109):
        struct.pack_into("<I", hdr, 0x4C + 4 * j, fat_ids[j] if j < nf else FREE)
    out = bytearray((total + 1) * ss)
    out[0:512] = hdr
    for s, c in content.items():
        out[(s + 1) * ss:(s + 2) * ss] = c
    if not pad_last:
        for key, ids in starts.items():
            if ids and ids[-1] == total - 1 and isinstance(key, int):
                del out[len(out) - (ss - (len(ents[key]["data"]) % ss or ss)):]
    info = dict(ss=ss, shift=shift, ents=ents, starts=starts, fat_ids=fat_ids, dif_ids=dif_ids, nf=nf,
                dir_off=[(starts["dir"][(i * 128) // ss] + 1) * ss + (i * 128) % ss for i in range(len(ents))],
                fat_off=lambda sid: (fat_ids[sid // epsec] + 1) * ss + (sid % epsec) * 4)
    return bytes(out), info

def blob(n, seed):
    r = random.Random(seed)
    if n > 100000:
        return r.randbytes(n)
    words = [b"gogi ", b"samgyeopsal ", b"\xea\xb3\xa0\xea\xb8\xb0 ", b"OLE2 ", b"compound ", b"\n"]
    out = bytearray()
    while len(out) < n:
        out += r.choice(words)
    return bytes(out[:n])

def write(t, name, data):
    p = t.path(name)
    with open(p, "wb") as f:
        f.write(data)
    return p

def vs7z(t, arc, label=None, rename=None, **kw):
    """Compare with 7-Zip's extraction of the compound file itself (-tCompound: no MSI cab descent)."""
    out = os.path.join(t.work, "ref7z_" + os.path.basename(arc))
    shutil.rmtree(out, ignore_errors=True)
    env = dict(os.environ, LC_ALL="C.UTF-8")
    r = subprocess.run(["7z", "x", "-y", "-tCompound", "-o" + out, arc], capture_output=True, env=env, timeout=300)
    if r.returncode:
        return t.record(False, label or os.path.basename(arc), "7z failed: " + r.stdout.decode(errors="replace")[-300:])
    exp = t.read_tree(out)
    for a, b in (rename or {}).items():
        exp[b] = exp.pop(a)
    return t.check_extract(arc, exp, label=(label or os.path.basename(arc)) + " vs 7z", **kw)

def patch32(b, off, val):
    b = bytearray(b)
    struct.pack_into("<I", b, off, val)
    return bytes(b)

def patch64(b, off, val):
    b = bytearray(b)
    struct.pack_into("<Q", b, off, val)
    return bytes(b)

# gzt leaks its context when an open fails; leaks of the reader itself are caught by the
# in-process fuzz driver, which frees everything
NOLEAK = {"ASAN_OPTIONS": (os.environ.get("ASAN_OPTIONS", "") + ":detect_leaks=0").lstrip(":")}

def check_hostile(t, path, timeout=60):
    label = "hostile " + os.path.basename(path)
    try:
        r, rows, out = t.extract(path, env=NOLEAK, timeout=timeout)
    except subprocess.TimeoutExpired:
        return t.record(False, label, "timeout")
    err = r.stderr.decode(errors="replace")
    bad = r.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err
    return t.record(not bad, label, "rc=%d %s" % (r.returncode, err[-300:] if bad else ""))

def run(t):
    have7z = bool(t.tool("7z"))
    drv = t.build_driver("tests/drivers/cfb_check.c")

    def drive(*args, timeout=600):
        r = subprocess.run([drv] + [str(a) for a in args], capture_output=True, timeout=timeout)
        return r.returncode, r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace")

    def check_view(arc, label=None):
        rc, out = drive("view", arc)
        t.record(rc == 0 and "VIEW OK" in out, label or "view " + os.path.basename(arc), out.strip()[-300:])

    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("inner/한글.txt", "안녕 고깃ZIP\n" * 200)
        z.writestr("inner/raw.bin", blob(30000, 9), compress_type=zipfile.ZIP_STORED)
    zip_big = zbuf.getvalue()
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("tiny.txt", b"mini stream zip\n" * 20)
    zip_small = zbuf.getvalue()
    assert len(zip_small) < 4096

    # 1) v3: mini + regular streams, storages, Korean names, control characters, times
    tree = [
        S("\x05SummaryInformation", blob(300, 1)),
        S("\x01CompObj", blob(90, 2)),
        S("WordDocument", blob(25000, 3)),
        S("1Table", blob(4096, 4)),                    # exactly the cutoff: regular stream
        S("Data", blob(4095, 5)),                      # just below: mini stream
        S("empty", b""),
        S("고깃집 메뉴.txt", "삼겹살 목살 갈비\n".encode() * 50),
        D("ObjectPool", D("_1234", S("\x01Ole", blob(20, 6)), S("\x03ObjInfo", blob(6, 7)),
                          S("Contents", blob(9000, 8)), ctime=FT, mtime=FT + 10000000), ctime=FT, mtime=FT),
        D("빈 저장소"),
        D("문서", S("보고서.hwp", blob(5000, 10)), S("zip_big.zip", zip_big), S("zip_small.zip", zip_small)),
    ]
    data, info = build_cfb(tree)
    p = write(t, "v3.doc", data)
    exp = expected(tree)
    t.check_extract(p, exp, expect_type="Compound")
    if have7z:
        vs7z(t, p)
    check_view(p)

    # same tree, fragmented: shuffled sectors and mini sectors, unpadded last sector
    data, info = build_cfb(tree, seed=7, msect_seed=8)
    pf = write(t, "v3_frag.doc", data)
    t.check_extract(pf, exp, label="v3 fragmented")
    if have7z:
        vs7z(t, pf)
    check_view(pf, "view v3 fragmented")
    big = [S("last.bin", blob(10000, 11))]
    data, info = build_cfb(big, pad_last=False)
    t.check_extract(write(t, "unpadded.cfb", data), expected(big), label="unpadded last sector")

    # nested archives through the sector-chain view (regular and mini stream, fragmented)
    for arc in (p, pf):
        for name, src in (("문서/zip_big.zip", zip_big), ("문서/zip_small.zip", zip_small)):
            od = os.path.join(t.work, "child_%s_%s" % (os.path.basename(arc), os.path.basename(name)))
            rc, out = drive("child", arc, name, od)
            ok = rc == 0 and "TYPE\tZIP" in out
            with zipfile.ZipFile(io.BytesIO(src)) as z:
                want = {i.filename: z.read(i) for i in z.infolist()}
            rows = [l.split("\t") for l in out.splitlines() if l[:1].isdigit()]
            for row in rows:
                if row[2] == "0":
                    got = open(os.path.join(od, row[0] + ".bin"), "rb").read()
                    ok = ok and row[1] == "0" and want.get(row[4]) == got
            ok = ok and len([r for r in rows if r[2] == "0"]) == len(want)
            t.record(ok, "child %s in %s" % (name, os.path.basename(arc)), out[-300:])

    # 1b) independent writer: Windows structured storage (ole32 StgCreateStorageEx) under Wine
    if t.tool("wine") and t.tool("x86_64-w64-mingw32-gcc"):
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        exe = os.path.join(t.work, "cfb_wine_writer.exe")
        t.sh(["x86_64-w64-mingw32-gcc", "-O2", "-municode", "-o", exe,
              os.path.join(root, "tests/drivers/cfb_wine_writer.c"), "-lole32", "-luuid"])

        def wfill(n, seed):
            x, out = (seed * 2654435761 + 1) & 0xFFFFFFFF, bytearray(n)
            for i in range(n):
                x = (x * 1103515245 + 12345) & 0xFFFFFFFF
                out[i] = (x >> 16) & 0xFF
            return bytes(out)
        wexp = {"[5]SummaryInformation": wfill(400, 1), "WordDocument": wfill(150000, 2), "1Table": wfill(4096, 3),
                "Data": wfill(4095, 4), "empty": b"", "한글 이름.txt": wfill(3000, 6), "ObjectPool": None,
                "ObjectPool/_1234567/[1]Ole": wfill(20, 7), "ObjectPool/_1234567/[3]ObjInfo": wfill(6, 8),
                "ObjectPool/_1234567/Contents": wfill(70000, 9)}
        for i in range(40):
            wexp["ObjectPool/_1234567/s%03d" % i] = wfill(100 + i * 397, 100 + i)
        env = dict(os.environ, WINEDEBUG="-all")
        for ssz in (512, 4096):
            pw = os.path.join(t.work, "wine%d.doc" % ssz)
            if os.path.exists(pw):
                os.remove(pw)
            try:
                r = subprocess.run(["wine", exe, pw, str(ssz)], capture_output=True, env=env, timeout=180)
            except subprocess.TimeoutExpired:
                break
            if b"WRITE_OK" not in r.stdout or not os.path.exists(pw):
                break                                   # Wine not usable here: nothing to compare
            t.check_extract(pw, wexp, label="Wine ole32 docfile, %d-byte sectors" % ssz, expect_type="Compound")
            if have7z:
                vs7z(t, pw)
            check_view(pw, "view Wine docfile %d" % ssz)

    # 2) v4 (4096-byte sectors, 64-bit sizes), fragmented
    tree4 = [S("big.bin", blob(300000, 20)), S("small", blob(100, 21)), S("mid", blob(5000, 22)),
             D("st", S("한국어 이름", blob(7000, 23)), S("\x05Props", blob(64, 24)))]
    for seed in (None, 3):
        data, info = build_cfb(tree4, v=4, seed=seed, msect_seed=seed)
        p4 = write(t, "v4_%s.cfb" % seed, data)
        t.check_extract(p4, expected(tree4), label="v4 seed %s" % seed)
        if have7z:
            vs7z(t, p4)
        check_view(p4, "view v4 seed %s" % seed)

    # 3) DIFAT beyond the 109 header entries (v3: > 7 MB of sectors), shuffled FAT and data
    treed = [S("huge.bin", blob(7500000, 30)), S("tail.txt", blob(3000, 31)), D("x", S("y", blob(9000, 32)))]
    data, info = build_cfb(treed, seed=11)
    assert info["nf"] > 109 and info["dif_ids"]
    pd = write(t, "difat.cfb", data)
    t.check_extract(pd, expected(treed), label="DIFAT %d FAT sectors" % info["nf"])
    if have7z:
        vs7z(t, pd)
    check_view(pd, "view DIFAT")
    # 128-byte sectors (7-Zip accepts them): several DIFAT sectors in a small file
    treet = [S("a.bin", blob(600000, 33)), S("b", blob(50, 34))]
    data, info = build_cfb(treet, shift=7, seed=12)
    assert len(info["dif_ids"]) >= 2
    pt = write(t, "sect128.cfb", data)
    t.check_extract(pt, expected(treet), label="128-byte sectors, %d DIFAT sectors" % len(info["dif_ids"]))
    if have7z:
        vs7z(t, pt)

    # 4) deep storage tree and many entries
    node = S("leaf.txt", b"deep leaf\n")
    for d in range(40, 0, -1):
        node = D("d%02d" % d, node, S("f%02d" % d, blob(100 + d, d)))
    many = [D("box%02d" % b, *[S("s%04d" % i, blob(50 + (i * 37) % 6000, i)) for i in range(b * 100, b * 100 + 100)])
            for b in range(30)]
    treem = [node] + many
    data, info = build_cfb(treem, seed=5, msect_seed=6)
    pm = write(t, "many.cfb", data)
    t.check_extract(pm, expected(treem), label="deep tree + 3000 streams")
    if have7z:
        vs7z(t, pm)

    # 5) MSI names: tables ('!'), packed pairs, odd length, cabinet streams
    cab = None
    if t.tool("gcab"):
        cd = t.write_tree(os.path.join(t.work, "cabsrc"), {"cabfile1.txt": b"cab one\n" * 100,
                                                           "cabfile2.bin": blob(20000, 40)})
        cab = os.path.join(t.work, "inner.cab")
        if os.path.exists(cab):
            os.remove(cab)
        t.sh(["gcab", "-c", "-z", cab, "cabfile1.txt", "cabfile2.bin"], cwd=cd)
        cab = open(cab, "rb").read()
    cabdata = cab or (b"MSCF" + blob(6000, 41))
    msi_tree = [
        S(msi_encode("_Tables", True), blob(40, 42)),
        S(msi_encode("_StringPool", True), blob(500, 43)),
        S(msi_encode("Property", True), blob(30, 44)),
        S(msi_encode("Binary.Icon1"), blob(5000, 45)),
        S(msi_encode("cab1.cab"), cabdata),
        S(msi_encode("PatchCab"), cabdata),                    # MSCF stream without extension
        S(msi_encode("abc"), b"odd length name"),
        S("\x05SummaryInformation", blob(400, 46)),
    ]
    data, info = build_cfb(msi_tree)
    pmsi = write(t, "generated.msi", data)
    want = {"!_Tables": msi_tree[0].data, "!_StringPool": msi_tree[1].data, "!Property": msi_tree[2].data,
            "Binary.Icon1": msi_tree[3].data, "cab1.cab": cabdata, "PatchCab.cab": cabdata,
            "abc": b"odd length name", "[5]SummaryInformation": msi_tree[7].data}
    t.check_extract(pmsi, want, expect_type="MSI", label="MSI names")
    if have7z:
        vs7z(t, pmsi, rename={"PatchCab": "PatchCab.cab"})
    # partly encoded name inside an MSI package (7-Zip leaves it encoded)
    mixed = msi_tree + [S(msi_encode("Binary.my-icon"), b"mixed")]
    data, info = build_cfb(mixed)
    want2 = dict(want, **{"Binary.my-icon": b"mixed"})
    t.check_extract(write(t, "mixed.msi", data), want2, label="MSI mixed name")
    # the same encoded names in a file that is not an MSI package by its names: type stays Compound
    data, info = build_cfb([S("WordDocument", b"x" * 10)])
    t.check_extract(write(t, "plain.cfb", data), {"WordDocument": b"x" * 10}, expect_type="Compound")

    # 6) wixl: real MSI with an embedded MSZIP cabinet
    gzt_has_cab = False
    if cab:
        rc = t.run_gzt(["l", write(t, "probe.cab", cab)])
        gzt_has_cab = rc.returncode == 0 and (b"TYPE\tCab" in rc.stdout or b"TYPE\tCAB" in rc.stdout)
    if t.tool("wixl"):
        wd = t.write_tree(os.path.join(t.work, "wixl"), {"readme.txt": b"GogitZIP MSI test\n" * 30,
                                                          "data.bin": blob(150000, 50), "small.ini": b"[a]\nb=1\n"})
        with open(os.path.join(wd, "t.wxs"), "w") as f:
            f.write('''<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="GogitTest" Language="1033" Version="1.0.0" Manufacturer="Gogit"
           UpgradeCode="12345678-1234-1234-1234-123456789012">
    <Package InstallerVersion="200" Compressed="yes" Comments="test"/>
    <Media Id="1" Cabinet="cab1.cab" EmbedCab="yes"/>
    <Directory Id="TARGETDIR" Name="SourceDir"><Directory Id="ProgramFilesFolder">
      <Directory Id="INSTALLDIR" Name="Gogit">
        <Component Id="C1" Guid="11111111-2222-3333-4444-555555555555">
          <File Id="readme.txt" Source="readme.txt"/><File Id="data.bin" Source="data.bin"/>
          <File Id="small.ini" Source="small.ini"/>
        </Component>
      </Directory></Directory></Directory>
    <Feature Id="Main" Level="1"><ComponentRef Id="C1"/></Feature>
  </Product>
</Wix>
''')
        pw = os.path.join(t.work, "wixl.msi")
        t.sh(["wixl", "-o", pw, "t.wxs"], cwd=wd)
        r, typ, rows = t.listing(pw)
        names = {x["name"] for x in rows}
        t.record(typ == "MSI" and "cab1.cab" in names and "[5]SummaryInformation" in names, "wixl listing",
                 "%s %s" % (typ, sorted(names)[:6]))
        if have7z:
            vs7z(t, pw, label="wixl.msi")
        check_view(pw, "view wixl.msi")
        if gzt_has_cab:
            od = os.path.join(t.work, "child_wixl")
            rc, out = drive("child", pw, "cab1.cab", od)
            rows = [l.split("\t") for l in out.splitlines() if l[:1].isdigit()]
            got = {r[4]: open(os.path.join(od, r[0] + ".bin"), "rb").read() for r in rows if r[1] == "0"}
            src = t.read_tree(wd)
            ok = rc == 0 and len(got) == 3 and all(got.get(k) == src[k] for k in ("readme.txt", "data.bin", "small.ini"))
            t.record(ok, "wixl cab1.cab as nested archive", out[-300:])
    if t.tool("msibuild"):
        pb = os.path.join(t.work, "msibuild.msi")
        if os.path.exists(pb):
            os.remove(pb)
        cabf = write(t, "stream.cab", cabdata)
        t.sh(["msibuild", pb, "-a", "mycab", cabf])             # one option per call
        t.sh(["msibuild", pb, "-a", "Binary.data", write(t, "b.bin", blob(9000, 51))])
        t.sh(["msibuild", pb, "-s", "GogitTest", "test", "Intel;1033", "{12345678-1234-1234-1234-123456789012}"])
        r, typ, rows = t.listing(pb)
        names = {x["name"] for x in rows}
        t.record(typ == "MSI" and "mycab.cab" in names and "Binary.data" in names, "msibuild streams",
                 "%s %s" % (typ, sorted(names)))
        if have7z:
            vs7z(t, pb, rename={"mycab": "mycab.cab"})
        if gzt_has_cab:
            rc, out = drive("child", pb, "mycab.cab", os.path.join(t.work, "child_msibuild"))
            t.record(rc == 0 and out.count("\t0\t0\t") >= 2, "msibuild mycab.cab as nested archive", out[-300:])

    # 7) hostile inputs
    small = [S("a", blob(5000, 60)), S("b", blob(10000, 61)), S("m1", blob(100, 62)), S("m2", blob(300, 63)),
             D("st", S("c", blob(700, 64)), D("st2", S("d", blob(4500, 65))))]
    base, info = build_cfb(small)
    ents, starts = info["ents"], info["starts"]
    exp_small = expected(small)
    idx = {e["name"]: i for i, e in enumerate(ents)}
    hostile = {}
    # FAT cycle inside stream b, self loop in stream a
    bs = starts[idx["b"]]
    hostile["fat_cycle"] = patch32(base, info["fat_off"](bs[10]), bs[2])
    hostile["fat_self"] = patch32(base, info["fat_off"](starts[idx["a"]][0]), starts[idx["a"]][0])
    # cross link: a's chain runs into b's sectors
    hostile["cross_link"] = patch32(base, info["fat_off"](starts[idx["a"]][2]), bs[0])
    for sh in (0, 6, 17, 30, 255, 0xFFFF):
        b = bytearray(base)
        struct.pack_into("<H", b, 0x1E, sh)
        hostile["shift_%d" % sh] = bytes(b)
    b = bytearray(base)
    struct.pack_into("<H", b, 0x20, 12)
    hostile["mshift_gt_shift"] = bytes(b)
    # directory: cycles through left/right/child links, self references, root as a child
    o = info["dir_off"]
    hostile["dir_self_child"] = patch32(base, o[idx["st"]] + 0x4C, idx["st"])
    hostile["dir_root_child"] = patch32(base, o[idx["st2"]] + 0x4C, 0)
    hostile["dir_left_loop"] = patch32(patch32(base, o[idx["a"]] + 0x44, idx["b"]), o[idx["b"]] + 0x44, idx["a"])
    hostile["dir_huge_link"] = patch32(base, o[0] + 0x4C, 0x7FFFFFFF)
    hostile["dir_start_end"] = patch32(base, 0x30, END)
    hostile["dir_start_huge"] = patch32(base, 0x30, 0xFFFFFFF0)
    # mini stream out of range
    hostile["mini_start_huge"] = patch32(base, o[idx["m1"]] + 0x74, 0x00FFFFFF)
    hostile["root_size_huge"] = patch32(base, o[0] + 0x78, 0xFFFFFFF0)
    hostile["root_start_bad"] = patch32(base, o[0] + 0x74, 0xFFFFFF00)
    hostile["minifat_count_huge"] = patch32(base, 0x40, 0xFFFFFFFF)
    hostile["cutoff_zero"] = patch32(base, 0x38, 0)
    hostile["cutoff_huge"] = patch32(base, 0x38, 0xFFFFFFFF)
    # huge sizes / counts
    hostile["size_4g"] = patch32(base, o[idx["b"]] + 0x78, 0xFFFFFFFF)
    hostile["num_fat_huge"] = patch32(base, 0x2C, 0xFFFFFFFF)
    hostile["num_difat_loop"] = patch32(patch32(base, 0x48, 0x10000000), 0x44, 0)
    hostile["difat_garbage"] = patch32(patch32(base, 0x4C, 0xFFFFFFF0), 0x2C, 3)
    b4, i4 = build_cfb(tree4, v=4)
    o4 = i4["dir_off"]
    hostile["v4_size_2e62"] = patch64(b4, o4[1] + 0x78, 1 << 62)
    hostile["v4_size_max"] = patch64(b4, o4[2] + 0x78, 0xFFFFFFFFFFFFFFFF)
    # a 200-deep storage chain (depth cap), and a chain linked into a loop
    node = S("leaf", b"x")
    for d in range(200):
        node = D("s%d" % d, node)
    bd, idd = build_cfb([node])
    hostile["deep200"] = bd
    hostile["deep_loop"] = patch32(bd, idd["dir_off"][30] + 0x4C, 3)
    for k in (100, 511, 512, 513, 1000, 1536, len(base) - 1000, len(base) - 1):
        hostile["trunc_%d" % k] = base[:k]
    for name, d in sorted(hostile.items()):
        check_hostile(t, write(t, "hostile_%s.cfb" % name, d))

    # behaviour of the damaged files: the damaged stream fails, the others still extract
    def check_partial(name, bad, label):
        r, rows, out = t.extract(t.path("hostile_%s.cfb" % name), env=NOLEAK)
        okk = r.returncode == 0
        seen = set()
        for i, (st, isdir, size, nm) in rows.items():
            seen.add(nm)
            if isdir:
                continue
            if nm in bad:
                okk = okk and st != 0
            else:
                okk = okk and st == 0 and open(os.path.join(out, "%d.bin" % i), "rb").read() == exp_small.get(nm)
        okk = okk and seen >= set(exp_small)
        t.record(okk, label, "" if okk else str(sorted(rows.values()))[:300])
    check_partial("fat_cycle", {"b"}, "FAT cycle: only the looping stream fails")
    check_partial("fat_self", {"a"}, "FAT self link: only that stream fails")
    check_partial("cross_link", {"a"}, "cross-linked chain: the second owner fails")
    check_partial("size_4g", {"b"}, "4 GiB claimed size: stream fails, others fine")
    r, rows, out = t.extract(t.path("hostile_deep200.cfb"), env=NOLEAK)
    t.record(r.returncode == 0 and len(rows) == 64, "storage depth capped at 64", "%d rows" % len(rows))
    for name in ("shift_0", "shift_6", "shift_17", "shift_30", "mshift_gt_shift", "dir_start_end"):
        r = t.run_gzt(["l", t.path("hostile_%s.cfb" % name)], NOLEAK)
        t.record(b"OPEN_ERROR" in r.stdout, "rejected: " + name, r.stdout.decode(errors="replace")[:100])

    # in-process fuzzing (bit flips, special values, truncation) under the sanitizers when enabled
    seeds = [("v3", build_cfb(small)[0]), ("v3frag", build_cfb(small, seed=2, msect_seed=3)[0]),
             ("v4", build_cfb([S("x", blob(5000, 70)), S("y", blob(200, 71)), D("z", S("w", blob(90, 72)))], v=4)[0]),
             ("msi", build_cfb(msi_tree[:4] + msi_tree[6:])[0]),
             ("difat7", build_cfb([S("a", blob(450000, 73)), S("b", blob(64, 74))], shift=7)[0])]
    iters = 600 if "fsanitize" in os.environ.get("HOST_CFLAGS", "") else 3000
    for name, d in seeds:
        rc, out = drive("fuzz", write(t, "seed_%s.cfb" % name, d), iters if name != "difat7" else iters // 10, 1234)
        t.record(rc == 0 and "FUZZ" in out and "FAIL" not in out, "fuzz %s" % name, out.strip()[-300:])
