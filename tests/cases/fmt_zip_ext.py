"""ZIP compression methods beyond Deflate and split / spanned ZIP sets (src/fmt/zip.c).

Methods: BZip2 (12), LZMA (14, with and without the end marker), PPMd var.I
(98), Deflate64 (9) from 7-Zip (plain, AES-256, ZipCrypto), BZip2 from Info-ZIP
zip -Z bzip2 and Python's zipfile (BZip2 / LZMA, also through pyzipper AES),
Zstd (93) and XZ (95) entries crafted from zstd / xz output, Shrink (1) and
Implode (6) from the encoders in _legacy_enc.py, Reduce (2-5, compression
factors 1-4) from the APPNOTE-based encoder below, each also ZipCrypto-encrypted
by a small Python ZipCrypto writer. Unsupported methods (JPEG, WavPack, ...)
must give GZ_E_METHOD; wrong CRCs and sizes must be reported.

Real-world Reduce data: no tool available here writes or reads Reduce (Info-ZIP
unzip is built COPYRIGHT_CLEAN, 7-Zip and The Unarchiver lack it), so a PKZIP
0.9x archive from the PC-SIG library CD-ROM (8th edition) mirrored at
cd.textfiles.com are downloaded at test time (not committed; skipped offline):
pcsig08/1001_100/DISK1016/PCCU.ZIP, 1801_900/DISK1811/HOMEINV.ZIP and
1801_900/DISK1855/SPCINV.ZIP (Reduce factor 4, Shrink and Store entries with
the CRC-32s PKZIP 0.9x wrote around 1989). Our encoder's output is checked by
the decoder validated on those files.

Split sets: Info-ZIP zip -s (name.z01 .. name.zip, entries and data running
across parts, ZIP64, bzip2, ZipCrypto), opened at the .zip or at the .z01,
upper-case part names, a missing part (GZ_E_VOLUME for the entries that need
it, the rest extract), 7-Zip -v volumes (.zip.001, joined by split.c).

Hostile: corrupted entries of every method, mutation fuzzing in process
(tests/drivers/zipxz.c, GZ_FUZZ_ITERS iterations per target)."""
import io, os, random, shutil, struct, subprocess, sys, zipfile, zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _legacy_enc as E

E_DATA, E_CRC, E_METHOD, E_PASSWORD, E_TRUNC, E_VOLUME = 3, 4, 5, 6, 9, 14

WORDS = ["고기", "삼겹살", "목살", "갈비", "zip", "bzip2", "lzma", "ppmd", "zstd", "xz", "hello", "world", "\n"]

def text(n, seed=1):
    rnd = random.Random(seed)
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(WORDS).encode() + b" "
    return bytes(out[:n])

def rand(n, seed=2):
    return random.Random(seed).randbytes(n)

FILES = {
    "readme.txt": text(5000, 3),
    "문서/보고서.txt": text(300000, 4),
    "문서/사진/고기.jpg": rand(90000, 5),
    "empty.txt": b"",
    "deep/a/b/c.bin": rand(1000, 6) * 200,
    "big.txt": text(3 << 19, 8),
}

# ---------------------------------------------------------------- crafted archives

def _crc_byte(c, b):
    c ^= b
    for _ in range(8):
        c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
    return c

_TAB = [_crc_byte(0, i) for i in range(256)]

def zipcrypto(data, pw, check, seed=1):
    k = [0x12345678, 0x23456789, 0x34567890]
    def upd(b):
        k[0] = (k[0] >> 8) ^ _TAB[(k[0] ^ b) & 0xFF]
        k[1] = ((k[1] + (k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k[2] = (k[2] >> 8) ^ _TAB[(k[2] ^ (k[1] >> 24)) & 0xFF]
    for b in pw:
        upd(b)
    out = bytearray()
    for b in random.Random(seed).randbytes(11) + bytes([check]) + data:
        t = (k[2] | 2) & 0xFFFF
        out.append(b ^ (((t * (t ^ 1)) >> 8) & 0xFF))
        upd(b)
    return bytes(out)

def zip_build(entries):
    """entries: dicts with name, method, raw, comp; optional flags, pw (ZipCrypto), crc, usize."""
    out = bytearray(); cd = bytearray()
    for e in entries:
        name = e["name"].encode()
        flags = e.get("flags", 0) | 0x800
        crc = e.get("crc", zlib.crc32(e["raw"]))
        usize = e.get("usize", len(e["raw"]))
        comp = e["comp"]
        if e.get("pw"):
            comp = zipcrypto(comp, e["pw"], crc >> 24)
            flags |= 1
        off = len(out)
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 63, flags, e["method"], 0x6000, 0x5021, crc, len(comp), usize,
                           len(name), 0) + name + comp
        cd += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 63, 63, flags, e["method"], 0x6000, 0x5021, crc, len(comp),
                          usize, len(name), 0, 0, 0, 0, 0x20, off) + name
    cdo = len(out)
    out += cd + struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(cd), cdo, 0)
    return bytes(out)

# ---------------------------------------------------------------- Reduce encoder (APPNOTE 5.2)

DLE = 0x90

def reduce_lz(data, factor, nolz=False):
    """first stage: literals, DLE 0 = literal 0x90, DLE V [X] Y = copy (see zip.c)"""
    mask = 0x7F >> (factor - 1)
    maxd, maxlen = 256 << factor, mask + 255 + 3
    out, head, i, n = bytearray(), {}, 0, len(data)
    while i < n:
        best, bd = 0, 0
        if not nolz and i + 3 <= n:
            for j in reversed(head.get(data[i:i + 3], [])[-8:]):
                d = i - j
                if d > maxd:
                    break
                l = 3
                while l < maxlen and i + l < n and data[j + l] == data[i + l]:
                    l += 1
                if l > best:
                    best, bd = l, d
        hi, lo, L = (bd - 1) >> 8, (bd - 1) & 0xFF, best - 3
        if best >= 3 and not (hi == 0 and L == 0):          # V = 0 would read as a literal DLE
            if L >= mask:
                out += bytes([DLE, (hi << (8 - factor)) | mask, L - mask, lo])
            else:
                out += bytes([DLE, (hi << (8 - factor)) | L, lo])
            step = best
        else:
            out += bytes([DLE, 0]) if data[i] == DLE else data[i:i + 1]
            step = 1
        for k in range(step):
            if i + k + 3 <= n:
                head.setdefault(data[i + k:i + k + 3], []).append(i + k)
        i += step
    return bytes(out)

def reduce_encode(data, factor, nolz=False, maxset=32):
    """second stage: follower sets (S(255) first, 6-bit sizes), LSB-first bits"""
    import collections
    s = reduce_lz(data, factor, nolz)
    cnt = collections.defaultdict(collections.Counter)
    last = 0
    for c in s:
        cnt[last][c] += 1
        last = c
    sets = {j: [c for c, k in cnt[j].most_common(maxset) if k > 1] for j in range(256)}
    out, acc, nb = bytearray(), 0, 0
    def put(bits, v):
        nonlocal acc, nb
        acc |= v << nb
        nb += bits
        while nb >= 8:
            out.append(acc & 0xFF); acc >>= 8; nb -= 8
    for j in range(255, -1, -1):
        put(6, len(sets[j]))
        for c in sets[j]:
            put(8, c)
    last = 0
    for c in s:
        fs = sets[last]
        if not fs:
            put(8, c)
        elif c in fs:
            put(1, 0)
            put(max(1, (len(fs) - 1).bit_length()), fs.index(c))
        else:
            put(1, 1)
            put(8, c)
        last = c
    return bytes(out) + (bytes([acc]) if nb else b"")

def write(t, name, data):
    p = t.path(name)
    with open(p, "wb") as f:
        f.write(data)
    return p

PCSIG = "http://cd.textfiles.com/pcsig08/"
REAL_ZIPS = ["1001_100/DISK1016/PCCU.ZIP", "1801_900/DISK1811/HOMEINV.ZIP", "1801_900/DISK1855/SPCINV.ZIP"]

def fetch(t, url):
    """download a test file into the work directory (cached); None when offline"""
    import urllib.request
    p = os.path.join(t.work, "dl", os.path.basename(url))
    if os.path.exists(p) and os.path.getsize(p):
        return p
    os.makedirs(os.path.dirname(p), exist_ok=True)
    try:
        d = urllib.request.urlopen(url, timeout=20).read()
    except Exception:
        return None
    with open(p + ".part", "wb") as f:
        f.write(d)
    os.replace(p + ".part", p)
    return p

def status_map(t, p, pw=None):
    r, rows, out = t.extract(p, pw=pw)
    return {name: st for st, isdir, size, name in rows.values() if not isdir}, r

def run(t):
    W = t.work
    src = t.write_tree(os.path.join(W, "src"), FILES)
    have7z = bool(t.tool("7z"))

    # ---------------- 7-Zip: every method it writes, plain / AES-256 / ZipCrypto
    def sz(name, *opts):
        out = t.path("7z", name)
        if os.path.exists(out):
            os.remove(out)
        t.sh(["7z", "a", "-tzip", out, "."] + list(opts), cwd=src)
        return out
    if have7z:
        for m in ("BZip2", "LZMA", "LZMA:eos", "PPMd", "Deflate64"):
            tag = m.replace(":", "_")
            p = sz("%s.zip" % tag, "-mm=" + m)
            t.check_extract(p, FILES, label="7z %s" % m, expect_type="ZIP")
            p = sz("%s_aes.zip" % tag, "-mm=" + m, "-pgogi1234", "-mem=AES256")
            t.check_extract(p, FILES, pw="gogi1234", label="7z %s AES-256" % m)
        for m in ("BZip2", "LZMA", "PPMd"):
            p = sz("%s_zc.zip" % m, "-mm=" + m, "-pgogi1234", "-mem=ZipCrypto")
            t.check_extract(p, FILES, pw="gogi1234", label="7z %s ZipCrypto" % m)
        for lv in ("1", "9"):
            for m in ("BZip2", "LZMA", "PPMd"):
                t.check_extract(sz("%s_x%s.zip" % (m, lv), "-mm=" + m, "-mx=" + lv), FILES, label="7z %s -mx=%s" % (m, lv))
        t.check_extract(sz("ppmd_o16.zip", "-mm=PPMd", "-mo=16", "-mmem=64m"), FILES, label="7z PPMd order 16 mem 64m")
        t.check_extract(sz("ppmd_o2.zip", "-mm=PPMd", "-mo=2", "-mmem=1m"), FILES, label="7z PPMd order 2 mem 1m")
        t.check_extract(sz("lzma_d16.zip", "-mm=LZMA", "-md=64k", "-mlc=0", "-mlp=2", "-mpb=0"), FILES, label="7z LZMA lc0 lp2 pb0")
        p = t.path("7z", "PPMd_aes.zip")
        r, rows, out = t.extract(p, pw="wrong")
        t.record(rows and all(st == E_PASSWORD or isdir for st, isdir, size, name in rows.values()),
                 "PPMd AES wrong password", str(list(rows.values())[:3]))
        r, typ, rows = t.listing(t.path("7z", "PPMd_aes.zip"))
        t.record(any(x["method"] == "PPMd AES-256" for x in rows), "method column PPMd AES-256", str([x["method"] for x in rows][:3]))

    # ---------------- Info-ZIP and Python's zipfile / pyzipper
    if t.tool("zip"):
        for label, opts in (("zip -Z bzip2", ["-Z", "bzip2"]), ("zip -Z bzip2 -P", ["-Z", "bzip2", "-P", "secret"])):
            p = t.path("iz_%d.zip" % len(opts))
            if os.path.exists(p):
                os.remove(p)
            t.sh(["zip", "-q", "-r"] + opts + [p, "."], cwd=src)
            t.check_extract(p, FILES, pw="secret" if "-P" in opts else None, label=label, allow_extra=True)
    for ct, label in ((zipfile.ZIP_BZIP2, "bzip2"), (zipfile.ZIP_LZMA, "lzma")):
        p = t.path("py_%s.zip" % label)
        with zipfile.ZipFile(p, "w", ct) as z:
            for k, v in FILES.items():
                z.writestr(k, v)
        t.check_extract(p, FILES, label="python zipfile %s" % label)
    try:
        import pyzipper
        for ct, label in ((pyzipper.ZIP_BZIP2, "bzip2"), (pyzipper.ZIP_LZMA, "lzma")):
            p = t.path("pyaes_%s.zip" % label)
            with pyzipper.AESZipFile(p, "w", compression=ct, encryption=pyzipper.WZ_AES) as z:
                z.setpassword(b"meat")
                for k, v in FILES.items():
                    z.writestr(k, v)
            t.check_extract(p, FILES, pw="meat", label="pyzipper AES %s" % label)
    except ImportError:
        pass

    # ---------------- crafted: Zstd, XZ, Shrink, Implode (+ ZipCrypto), unsupported methods
    T1, T2, R1 = FILES["문서/보고서.txt"], FILES["big.txt"][:1500000], FILES["문서/사진/고기.jpg"]
    def comp(cmd, data):
        return t.sh(cmd, input=data).stdout
    ents = []
    if t.tool("zstd"):
        ents += [dict(name="zstd/l3.txt", method=93, raw=T1, comp=comp(["zstd", "-c", "-3"], T1)),
                 dict(name="zstd/l19.txt", method=93, raw=T2, comp=comp(["zstd", "-c", "-19"], T2)),
                 dict(name="zstd/nocheck.bin", method=93, raw=R1, comp=comp(["zstd", "-c", "--no-check"], R1)),
                 dict(name="zstd/2frames.txt", method=93, raw=T1 + R1,
                      comp=comp(["zstd", "-c", "-1"], T1) + comp(["zstd", "-c", "-1"], R1)),
                 dict(name="zstd/empty", method=93, raw=b"", comp=comp(["zstd", "-c"], b""))]
    if t.tool("xz"):
        ents += [dict(name="xz/6.txt", method=95, raw=T1, comp=comp(["xz", "-c", "-6"], T1)),
                 dict(name="xz/mt.txt", method=95, raw=T2, comp=comp(["xz", "-c", "-T0", "--block-size=200000", "-1"], T2)),
                 dict(name="xz/x86.bin", method=95, raw=R1, comp=comp(["xz", "-c", "--x86", "--lzma2=preset=1", "--check=sha256"], R1)),
                 dict(name="xz/2streams.txt", method=95, raw=T1 + R1,
                      comp=comp(["xz", "-c", "-0"], T1) + b"\0" * 4 + comp(["xz", "-c", "-0", "--check=none"], R1)),
                 dict(name="xz/empty", method=95, raw=b"", comp=comp(["xz", "-c"], b""))]
    leg = T1[:120000]
    ents += [dict(name="legacy/shrink.txt", method=1, raw=leg, comp=E.shrink_encode(leg)[0]),
             dict(name="legacy/shrink_rnd.bin", method=1, raw=R1[:30000], comp=E.shrink_encode(R1[:30000])[0])]
    for large in (0, 1):
        for three in (0, 1):
            ents.append(dict(name="legacy/implode_%d%d.txt" % (large, three), method=6, flags=(2 if large else 0) | (4 if three else 0),
                             raw=leg[:60000], comp=E.implode_encode(leg[:60000], large, three)))
    red = leg[:40000] + bytes([DLE]) * 300 + R1[:3000] + bytes(range(256)) * 8 + leg[:20000]
    for f in (1, 2, 3, 4):
        ents.append(dict(name="legacy/reduce%d.txt" % f, method=1 + f, raw=red, comp=reduce_encode(red, f)))
    ents.append(dict(name="legacy/reduce_63.txt", method=3, raw=red[:30000], comp=reduce_encode(red[:30000], 2, maxset=63)))
    ents.append(dict(name="legacy/reduce_lit.bin", method=5, raw=R1[:5000], comp=reduce_encode(R1[:5000], 4, nolz=True, maxset=0)))
    ents.append(dict(name="legacy/reduce_empty", method=2, raw=b"", comp=reduce_encode(b"", 1)))
    p = write(t, "crafted.zip", zip_build(ents))
    exp = {e["name"]: e["raw"] for e in ents}
    t.check_extract(p, exp, label="crafted Zstd/XZ/Shrink/Implode")
    r, typ, rows = t.listing(p)
    want_m = {93: "Zstd", 95: "XZ", 1: "Shrink", 6: "Implode", 2: "Reduce", 3: "Reduce", 4: "Reduce", 5: "Reduce"}
    t.record(all(x["method"] == want_m[e["method"]] for x, e in zip(rows, ents)), "crafted method column",
             str([x["method"] for x in rows][:6]))
    encs = [dict(e, pw=b"zc-pass") for e in ents]
    p = write(t, "crafted_zc.zip", zip_build(encs))
    t.check_extract(p, exp, pw="zc-pass", label="crafted methods + ZipCrypto")
    sm, r = status_map(t, p, pw="zc-wrong")
    t.record(sm and all(st in (E_PASSWORD, E_DATA, E_CRC) for n, st in sm.items() if exp.get(n)),
             "crafted ZipCrypto wrong password", str(sorted(set(sm.values()))))

    # unsupported methods and damage: exact statuses
    good = ents[0] if ents and ents[0]["method"] == 93 else ents[-1]
    bad = [dict(name="m/m7", method=7, raw=b"abc", comp=b"\0" * 10, want=E_METHOD),
           dict(name="m/m19", method=19, raw=b"abc", comp=b"\0" * 10, want=E_METHOD),
           dict(name="m/jpeg", method=96, raw=b"abc", comp=b"\0" * 10, want=E_METHOD),
           dict(name="m/wavpack", method=97, raw=b"abc", comp=b"\0" * 10, want=E_METHOD),
           dict(name="m/m10", method=10, raw=b"abc", comp=b"\0" * 10, want=E_METHOD)]
    for e in ents:
        if not e["raw"]:
            continue
        stem = "d/%d_%s" % (e["method"], e["name"].replace("/", "_"))
        bad.append(dict(e, name=stem + "_crc", crc=zlib.crc32(e["raw"]) ^ 1, want=E_CRC))
        bad.append(dict(e, name=stem + "_short", usize=len(e["raw"]) - 1, want=(E_DATA, E_CRC)))
        bad.append(dict(e, name=stem + "_long", usize=len(e["raw"]) + 1, want=(E_DATA, E_TRUNC, E_CRC)))
        bad.append(dict(e, name=stem + "_cut", comp=e["comp"][:len(e["comp"]) // 2], want=(E_DATA, E_TRUNC, E_CRC)))
    p = write(t, "bad_methods.zip", zip_build(bad))
    sm, r = status_map(t, p)
    wrong = []
    for e in bad:
        w = e["want"] if isinstance(e["want"], tuple) else (e["want"],)
        if sm.get(e["name"]) not in w:
            wrong.append("%s=%s" % (e["name"], sm.get(e["name"])))
    t.record(not wrong and len(sm) == len(bad), "unsupported methods / CRC / size errors", "; ".join(wrong[:8]))
    # 7-Zip LZMA / PPMd / BZip2 entries with damage
    if have7z:
        for m in ("LZMA", "PPMd", "BZip2"):
            raw = open(t.path("7z", "%s.zip" % m), "rb").read()
            zf = zipfile.ZipFile(io.BytesIO(raw))
            info = zf.getinfo("big.txt")
            data_off = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
            b = bytearray(raw)
            b[data_off + info.compress_size // 2] ^= 0x20
            sm, r = status_map(t, write(t, "flip_%s.zip" % m, bytes(b)))
            t.record(sm.get("big.txt") in (E_DATA, E_CRC) and sm.get("readme.txt") == 0,
                     "%s damaged entry reported, others fine" % m, str(sm))

    # ---------------- split / spanned sets
    if t.tool("zip"):
        def zsplit(name, size, *opts, files=None):
            d = t.path("split", name)
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d)
            p = os.path.join(d, name + ".zip")
            t.sh(["zip", "-q", "-r", "-s", size] + list(opts) + [p, "."], cwd=files or src)
            return d, p
        d, p = zsplit("s1", "64k")
        parts = sorted(os.listdir(d))
        t.record(len(parts) >= 6 and parts[0] == "s1.z01", "zip -s made a set", " ".join(parts))
        r, typ, rows0 = t.listing(p)
        nent = len(rows0)
        t.check_extract(p, FILES, label="split .zip", expect_type="ZIP", allow_extra=True)
        t.check_extract(os.path.join(d, "s1.z01"), FILES, label="split opened at .z01", allow_extra=True)
        if have7z:
            t.check_vs_7z(p, label="split vs 7z", allow_extra=True)
        r, typ, rows = t.listing(os.path.join(d, "s1.z01"))
        t.record(typ == "ZIP" and len(rows) == nent and nent > len(FILES), "split .z01 listing", "%s %d" % (typ, len(rows)))
        d2, p2 = zsplit("s2", "64k", "-Z", "bzip2", "-P", "pw")
        t.check_extract(p2, FILES, pw="pw", label="split bzip2 + ZipCrypto", allow_extra=True)
        d3, p3 = zsplit("s3", "200k", "-fz")
        t.check_extract(p3, FILES, label="split ZIP64", allow_extra=True)
        # upper-case names
        d4 = t.path("split", "UP")
        shutil.rmtree(d4, ignore_errors=True)
        os.makedirs(d4)
        for f in os.listdir(d):
            shutil.copy(os.path.join(d, f), os.path.join(d4, f.upper()))
        t.check_extract(os.path.join(d4, "S1.ZIP"), FILES, label="split upper-case names", allow_extra=True)
        # a missing part: listing works, entries that need it give GZ_E_VOLUME
        d5 = t.path("split", "miss")
        shutil.rmtree(d5, ignore_errors=True)
        shutil.copytree(d, d5)
        os.remove(os.path.join(d5, "s1.z04"))
        sm, r = status_map(t, os.path.join(d5, "s1.zip"))
        nvol = sum(1 for v in sm.values() if v == E_VOLUME)
        okn = sum(1 for k, v in sm.items() if v == 0 and t.read_tree(t.path("src")).get(k) is not None)
        t.record(nvol >= 1 and okn >= 1 and nvol + okn == len(sm) and len(sm) == len(FILES),
                 "split missing .z04: GZ_E_VOLUME", str(sm))
        # only the last part
        d6 = t.path("split", "last")
        shutil.rmtree(d6, ignore_errors=True)
        os.makedirs(d6)
        shutil.copy(p, os.path.join(d6, "s1.zip"))
        r, typ, rows = t.listing(os.path.join(d6, "s1.zip"))
        t.record(len(rows) == nent, "split: listing from the last part alone", "%s %d" % (typ, len(rows)))
        sm, r = status_map(t, os.path.join(d6, "s1.zip"))
        t.record(sm and all(v in (0, E_VOLUME) for v in sm.values()) and E_VOLUME in sm.values(),
                 "split: last part alone extracts what it holds", str(sm))
        # a .z01 without its .zip
        d7 = t.path("split", "noz")
        shutil.rmtree(d7, ignore_errors=True)
        os.makedirs(d7)
        shutil.copy(os.path.join(d, "s1.z01"), os.path.join(d7, "s1.z01"))
        r, rows, out = t.extract(os.path.join(d7, "s1.z01"))
        t.record(r.stdout.startswith(b"OPEN_ERROR %d" % E_VOLUME), ".z01 without .zip: GZ_E_VOLUME", r.stdout[:40])
        # hostile split sets: damaged middle part, truncated part, truncated .zip
        d8 = t.path("split", "dmg")
        shutil.rmtree(d8, ignore_errors=True)
        shutil.copytree(d, d8)
        with open(os.path.join(d8, "s1.z03"), "r+b") as f:
            f.truncate(5000)
        t.check_hostile(os.path.join(d8, "s1.zip"), "split truncated middle part")
        b = bytearray(open(os.path.join(d8, "s1.z05"), "rb").read())
        for i in range(0, len(b), 997):
            b[i] ^= 0x55
        open(os.path.join(d8, "s1.z05"), "wb").write(bytes(b))
        t.check_hostile(os.path.join(d8, "s1.zip"), "split damaged part")
        # damaged directory / end records in the last part (disk numbers, offsets, counts)
        last = open(p, "rb").read()
        eocd = last.rfind(b"PK\x05\x06")
        cdo = last.find(b"PK\x01\x02")
        rnd = random.Random(5)
        for k in range(10):
            b = bytearray(last)
            if k < 4:                                    # EOCD fields: disk, cd disk, counts, size, offset
                fld = [4, 6, 8, 10, 12, 16][rnd.randrange(6)]
                b[eocd + fld:eocd + fld + 2] = bytes([rnd.randrange(256), rnd.choice([0, 0xFF, 1])])
            else:                                        # central directory: disk start, offsets, sizes
                for _ in range(3):
                    i = cdo + rnd.randrange(max(1, eocd - cdo))
                    b[i] = rnd.choice([0, 0xFF, b[i] ^ 0x08])
            dk = t.path("split", "cd%d" % k)
            shutil.rmtree(dk, ignore_errors=True)
            shutil.copytree(d, dk)
            open(os.path.join(dk, "s1.zip"), "wb").write(bytes(b))
            t.check_hostile(os.path.join(dk, "s1.zip"), "split damaged directory #%d" % k)
            t.check_hostile(os.path.join(dk, "s1.z01"), "split damaged directory via .z01 #%d" % k)
    if have7z:
        d = t.path("split", "v7")
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
        t.sh(["7z", "a", "-tzip", "-v150k", os.path.join(d, "v.zip"), "."], cwd=src)
        t.check_extract(os.path.join(d, "v.zip.001"), FILES, label="7-Zip -v150k .zip.001")

    # ---------------- real PKZIP 0.9x Reduce / Shrink / Store archives (network)
    for rel in REAL_ZIPS:
        real = fetch(t, PCSIG + rel)
        nm = os.path.basename(rel)
        if not real:
            t.record(True, "PKZIP 0.9x %s skipped (offline)" % nm)
            break
        infos = zipfile.ZipFile(real).infolist()
        sm, r = status_map(t, real)
        meth = sorted({i.compress_type for i in infos})
        t.record(len(sm) == len(infos) and all(v == 0 for v in sm.values()) and 5 in meth,
                 "PKZIP 0.9x %s: Reduce CRCs match" % nm, "%s methods %s" % (sm, meth))
        rr, rows, out = t.extract(real)
        sizes = {name: size for st, isdir, size, name in rows.values()}
        t.record(all(sizes.get(i.filename) == i.file_size and
                     os.path.getsize(os.path.join(out, "%d.bin" % k)) == i.file_size for k, i in enumerate(infos)),
                 "PKZIP 0.9x %s sizes" % nm, str(sizes))

    # ---------------- hostile: mutations through gzt and in-process fuzzing
    rnd = random.Random(3)
    pool = [t.path("crafted.zip")] + ([t.path("7z", "LZMA.zip"), t.path("7z", "PPMd_aes.zip")] if have7z else [])
    for k in range(12):
        b = bytearray(open(pool[k % len(pool)], "rb").read())
        if k % 3 == 0:
            b = b[:rnd.randrange(len(b))]
        else:
            for _ in range(3):
                i = rnd.randrange(len(b))
                b[i] ^= 1 << rnd.randrange(8)
        t.check_hostile(write(t, "hostile/z%d.zip" % k, bytes(b)), "hostile zip #%d" % k, pw="gogi1234", timeout=60)
    drv = t.build_driver("tests/drivers/zipxz.c")
    iters = int(os.environ.get("GZ_FUZZ_ITERS", "250"))
    small = [dict(e, raw=e["raw"], comp=e["comp"]) for e in ents if len(e["comp"]) < 12000]
    seeds = [("crafted", write(t, "fuzz/crafted.zip", zip_build(small))),
             ("crafted_zc", write(t, "fuzz/crafted_zc.zip", zip_build([dict(e, pw=b"pw1234") for e in small])))]
    if have7z:
        fs = t.write_tree(t.path("fuzzsrc"), {"a.txt": text(20000, 9), "b.bin": rand(3000, 9), "c/d.txt": text(5000, 10)})
        for m in ("LZMA", "PPMd", "BZip2"):
            p = t.path("fuzz", "%s.zip" % m)
            if os.path.exists(p):
                os.remove(p)
            t.sh(["7z", "a", "-tzip", "-mm=" + m, "-ppw1234", "-mem=AES256" if m == "PPMd" else "-mem=ZipCrypto", p, "."], cwd=fs)
            seeds.append((m, p))
    for label, p in seeds:
        r = t.sh([drv, "fuzz", p, str(iters), "11", "seed.zip"], check=False, timeout=900)
        out = r.stdout.decode().strip()
        err = r.stderr.decode(errors="replace")
        t.record(r.returncode == 0 and out.startswith("fuzz iters=") and "Sanitizer" not in err and "runtime error" not in err,
                 "fuzz zip %s" % label, out + " " + err[-300:])
