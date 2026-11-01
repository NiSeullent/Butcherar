"""CAB (+ LZX and Quantum codec) tests.

Fixtures: gcab (None / MSZIP), a Python CAB builder (MSZIP via zlib with preset
dictionaries, reserve fields, multi-cabinet sets with split blocks, SFX stubs),
LZX and Quantum folders from tests/drivers/lzx_tool.c and qtm_tool.c (encoders
whose output is cross-checked with 7-Zip and cabextract before it is used) and
libmspack's test cabinets (Microsoft-made set, MSZIP/LZX/Quantum sample). LZX WIM
mode is checked against wimlib-made WIMs (SHA-1 of every resource).
"""
import os, struct, random, zlib, shutil, subprocess, hashlib, math, time, importlib.util, tarfile, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------- CAB builder

def csum(data, seed=0):
    n = len(data) & ~3
    s = seed
    for (w,) in struct.iter_unpack("<I", data[:n]):
        s ^= w
    r = data[n:]
    if len(r) == 3:
        s ^= r[0] << 16 | r[1] << 8 | r[2]
    elif len(r) == 2:
        s ^= r[0] << 8 | r[1]
    elif len(r) == 1:
        s ^= r[0]
    return s

def cfdata(d, u, res=b"", checksum=True, res_in_sum=True):
    """CFDATA block. The spec (and 7-Zip) checksums the reserve area, libmspack does not."""
    h = struct.pack("<HH", len(d), u)
    cs = csum(h + res if res_in_sum else h, csum(d)) if checksum else 0
    return struct.pack("<I", cs) + h + res + d

def none_blocks(data, size=32768):
    return [(data[i:i + size], len(data[i:i + size])) for i in range(0, len(data), size)] or []

def mszip_blocks(data, level=6):
    out, hist = [], b""
    for i in range(0, len(data), 32768):
        blk = data[i:i + 32768]
        c = zlib.compressobj(level, zlib.DEFLATED, -15, zdict=hist) if hist else zlib.compressobj(level, zlib.DEFLATED, -15)
        out.append((b"CK" + c.compress(blk) + c.flush(), len(blk)))
        hist = (hist + blk)[-32768:]
    return out

def read_lzxf(path):
    b = open(path, "rb").read()
    n = struct.unpack_from("<I", b, 4)[0]
    o, fr = 8, []
    for i in range(n):
        c, u = struct.unpack_from("<II", b, o)
        fr.append((b[o + 8:o + 8 + c], u))
        o += 8 + c
    return fr

def build_cab(folders, files, res=None, prev=None, nxt=None, setid=0x4242, icab=0, checksum=True, res_in_sum=True):
    """folders: [(typeCompress, [(cdata, usize)])]
    files: [(name bytes, size, offset, iFolder, attr, date, time)]
    res: (header reserve bytes, folder reserve size, data reserve size)"""
    flags = (1 if prev else 0) | (2 if nxt else 0) | (4 if res else 0)
    hdr_extra = b""
    if res:
        hdr_extra = struct.pack("<HBB", len(res[0]), res[1], res[2]) + res[0]
    if prev:
        hdr_extra += prev[0] + b"\0" + prev[1] + b"\0"
    if nxt:
        hdr_extra += nxt[0] + b"\0" + nxt[1] + b"\0"
    rf = res[1] if res else 0
    rd = res[2] if res else 0
    fold_off = 36 + len(hdr_extra)
    files_off = fold_off + len(folders) * (8 + rf)
    cffiles = b"".join(struct.pack("<IIHHHH", size, off, ifold, date, tm, attr) + name + b"\0"
                       for name, size, off, ifold, attr, date, tm in files)
    data_off = files_off + len(cffiles)
    fold_tab, blob = b"", b""
    for ctype, blocks in folders:
        fold_tab += struct.pack("<IHH", data_off + len(blob), len(blocks), ctype) + bytes(range(rf))
        for d, u in blocks:
            blob += cfdata(d, u, bytes((7 * k + 1) & 255 for k in range(rd)), checksum, res_in_sum)
    total = data_off + len(blob)
    hdr = b"MSCF" + struct.pack("<IIIIIBBHHHHH", 0, total, 0, files_off, 0, 3, 1, len(folders), len(files), flags, setid, icab)
    return hdr + hdr_extra + fold_tab + cffiles + blob

def file_list(names_sizes, ifold=0, attr=0x20, start=0):
    out, off = [], start
    for name, size in names_sizes:
        out.append((name, size, off, ifold, attr, 0x5A21, 0x6000))
        off += size
    return out

def build_set(blocks, ctype, files, cuts, split=True, base="set"):
    """One folder spread over len(cuts)+1 cabinets. cuts: block indices where the next
    cabinet starts; with split, the block before each cut is split between cabinets.
    Like Microsoft's tools, a file is listed in every cabinet holding a piece of a
    block it overlaps (CONTINUED_* markers when that is more than one)."""
    parts = []           # per cabinet: list of (cdata, u, block index)
    pending = None
    bounds = [0] + list(cuts) + [len(blocks)]
    for k in range(len(bounds) - 1):
        cur = []
        if pending:
            cur.append(pending)
            pending = None
        for bi in range(bounds[k], bounds[k + 1]):
            d, u = blocks[bi]
            if bi == bounds[k + 1] - 1 and k < len(bounds) - 2 and split and len(d) > 2:
                h = len(d) // 2
                cur.append((d[:h], 0, bi))
                pending = (d[h:], u, bi)
            else:
                cur.append((d, u, bi))
        parts.append(cur)
    ustart, pos = [], 0
    for d, u in blocks:
        ustart.append((pos, pos + u))
        pos += u
    def in_cab(k, off, size):
        for d, u, bi in parts[k]:
            a, b = ustart[bi]
            if (size and off < b and off + size > a) or (not size and a <= off < b):
                return True
        return not size and k == len(parts) - 1 and off >= pos
    names = ["%s%d.cab" % (base, k + 1) for k in range(len(parts))]
    cabs = []
    for k, cur in enumerate(parts):
        fl = []
        for name, size, off, ifold, attr, date, tm in files:
            where = [j for j in range(len(parts)) if in_cab(j, off, size)]
            if k not in where:
                continue
            first, last = where[0], where[-1]
            f = 0 if first == last else 0xFFFE if k == first else 0xFFFD if k == last else 0xFFFF
            fl.append((name, size, off, f, attr, date, tm))
        prev = (names[k - 1].encode(), b"Disk%d" % k) if k else None
        nxt = (names[k + 1].encode(), b"Disk%d" % (k + 2)) if k + 1 < len(parts) else None
        cabs.append(build_cab([(ctype, [(d, u) for d, u, bi in cur])], fl, prev=prev, nxt=nxt, icab=k))
    return names, cabs

# ---------------------------------------------------------------- data

def blob(n, kind, seed):
    rnd = random.Random(seed * 1000 + n)
    if kind == 0:
        return bytes(rnd.getrandbits(8) for _ in range(n))
    words = [b"meat", b"grill", b"samgyeopsal", b"cabinet", b"folder", b"\xea\xb3\xa0\xea\xb8\xb0", b"lzx", b"\n", b"window"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words) + b" "
        if rnd.random() < 0.02:
            out += b"\xe8" + bytes(rnd.getrandbits(8) for _ in range(4))   # x86 CALL-like bytes
    return bytes(out[:n])

def x86_like(n, seed):
    """machine-code-like data: many E8 xx xx xx xx with near targets"""
    rnd = random.Random(seed)
    out = bytearray()
    while len(out) < n:
        r = rnd.random()
        if r < 0.15:
            out += b"\xe8" + struct.pack("<i", rnd.randint(-40000, 40000))
        elif r < 0.5:
            out += bytes([0x48, 0x89, rnd.choice([0x45, 0x5d, 0xe5]), rnd.getrandbits(8)])
        else:
            out += bytes(rnd.getrandbits(8) & 0x3f for _ in range(3))
    return bytes(out[:n])

def split_files(data, rnd, maxn=6, prefix=b"dir\\f"):
    sizes, left = [], len(data)
    while left:
        s = min(left, rnd.randint(0, len(data) // 3 + 1))
        sizes.append(s)
        left -= s
    sizes.insert(rnd.randint(0, len(sizes)), 0)        # an empty file somewhere
    names = [(prefix + b"%02d.bin" % i, s) for i, s in enumerate(sizes)]
    exp, off = {}, 0
    for name, s in names:
        exp[name.decode().replace("\\", "/")] = data[off:off + s]
        off += s
    return names, exp

# ---------------------------------------------------------------- tests

def write(path, data):
    with open(path, "wb") as f:
        f.write(data)
    return path

def ref_ok(t, path, exp, label, refs=("7z", "cabextract")):
    """verify a generated fixture with 7-Zip (and cabextract) before trusting it"""
    ok = True
    if "7z" in refs and t.tool("7z"):
        r, out = t.sevenzip_extract(path)
        got = t.read_tree(out)
        ok = r.returncode == 0 and all(got.get(k) == v for k, v in exp.items() if v)
        if not ok:
            t.record(False, label + " 7z reference", r.stdout.decode(errors="replace")[-300:])
    if ok and "cabextract" in refs and t.tool("cabextract"):
        out = t.path("refcx_" + os.path.basename(path))
        shutil.rmtree(out, ignore_errors=True)
        os.makedirs(out)
        r = subprocess.run(["cabextract", "-q", "-d", out, path], capture_output=True)
        got = t.read_tree(out)
        ok = r.returncode == 0 and all(got.get(k) == v for k, v in exp.items() if v)
        if not ok:
            t.record(False, label + " cabextract reference", (r.stdout + r.stderr).decode(errors="replace")[-300:])
    return ok

def fetch(t, url, name):
    """download once into build/testdata (shared by test runs); None when offline"""
    cache = os.path.join(os.path.dirname(os.path.dirname(t.work)), "testdata")
    os.makedirs(cache, exist_ok=True)
    p = os.path.join(cache, name)
    if os.path.exists(p) and os.path.getsize(p):
        return p
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            data = r.read()
    except Exception:
        return None
    with open(p + ".tmp", "wb") as f:
        f.write(data)
    os.replace(p + ".tmp", p)
    return p

def cabextract_tree(t, path, d):
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    r = subprocess.run(["cabextract", "-q", "-d", d, path], capture_output=True)
    return r.returncode, t.read_tree(d)

def check_hostile2(t, drv, path):
    """gzt must not crash or hang (its own context leaks when an open fails, so leak
    checks are off there); the per-entry driver frees everything, leak checks on"""
    label = "hostile " + os.path.basename(path)
    try:
        r, rows, out = t.extract(path, env={"ASAN_OPTIONS": "detect_leaks=0"}, timeout=30)
    except subprocess.TimeoutExpired:
        return t.record(False, label, "timeout")
    err = r.stderr.decode(errors="replace")
    bad = r.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err
    if not bad:
        out2 = t.path("rndh_" + os.path.basename(path))
        shutil.rmtree(out2, ignore_errors=True)
        try:
            r2 = subprocess.run([drv, path, out2, "shuffle", "3"], capture_output=True, timeout=30)
        except subprocess.TimeoutExpired:
            return t.record(False, label + " per-entry", "timeout")
        err = r2.stderr.decode(errors="replace")
        bad = r2.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err
        shutil.rmtree(out2, ignore_errors=True)
    shutil.rmtree(out, ignore_errors=True)
    return t.record(not bad, label, err[-400:] if bad else "")

def check_random(t, drv, arc, exp, order, label):
    """per-entry extraction (random access path) against expected {name: bytes}"""
    out = t.path("rnd_" + os.path.basename(arc) + "_" + order)
    shutil.rmtree(out, ignore_errors=True)
    r = t.sh([drv, arc, out, order, "7"], check=False)
    bad, seen = [], set()
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if len(p) != 5 or not p[0].isdigit():
            continue
        i, st, isdir, name = int(p[0]), int(p[1]), int(p[2]), p[4]
        if isdir or name not in exp:
            continue
        seen.add(name)
        if st != 0 or open(os.path.join(out, "%d.bin" % i), "rb").read() != exp[name]:
            bad.append("%s:%d" % (name, st))
    bad += ["missing " + k for k in exp if k not in seen]
    shutil.rmtree(out, ignore_errors=True)
    return t.record(r.returncode == 0 and not bad, label, ",".join(bad[:5]))

def listing_map(t, path, **kw):
    r, typ, rows = t.listing(path, **kw)
    return typ, {x["name"]: x for x in rows}

def run(t):
    W = t.work
    has7z = bool(t.tool("7z"))

    # ---- gcab fixtures: None and MSZIP
    if t.tool("gcab"):
        files = {"a.bin": blob(100000, 0, 1), "sub/b.txt": blob(290000, 1, 2), "c.txt": b"hi\n",
                 "empty": b"", "deep/x/y/z.txt": blob(70000, 1, 3)}
        src = t.write_tree(os.path.join(W, "gsrc"), files)
        for opt, meth in (([], "None"), (["-z"], "MSZIP")):
            p = t.path("gcab%s.cab" % "".join(opt))
            if os.path.exists(p):
                os.remove(p)
            t.sh(["gcab", "-c"] + opt + [p] + sorted(files), cwd=src)
            t.check_extract(p, files, expect_type="CAB")
            if has7z:
                t.check_vs_7z(p, label="vs 7z " + os.path.basename(p))
            typ, m = listing_map(t, p)
            t.record(all(m[k]["method"] == meth and m[k]["usize"] == len(v) for k, v in files.items()),
                     "gcab %s listing" % meth, str([(x["name"], x["method"]) for x in m.values()][:3]))

    # ---- MSZIP / None folders from the builder: several folders, reserves, attributes
    rnd = random.Random(5)
    d1, d2, d3 = blob(200000, 1, 4), blob(50000, 0, 5), blob(123457, 1, 6)
    n1, e1 = split_files(d1, rnd, prefix=b"mszip\\f")
    n2, e2 = split_files(d2, rnd, prefix=b"store\\f")
    n3, e3 = split_files(d3, rnd, prefix=b"mszip9\\f")
    files = file_list(n1, 0) + file_list(n2, 1) + file_list(n3, 2)
    folders = [(1, mszip_blocks(d1)), (0, none_blocks(d2)), (1, mszip_blocks(d3, 9))]
    exp = dict(e1, **e2, **e3)
    p = write(t.path("multi_folder.cab"), build_cab(folders, files))
    if ref_ok(t, p, exp, "multi_folder.cab"):
        t.check_extract(p, exp)
    # stored blocks of any size (7-Zip expects 32 KiB ones, cabextract does not)
    odd = [(1, mszip_blocks(d1)), (0, none_blocks(d2, 20000)), (1, mszip_blocks(d3, 9))]
    p = write(t.path("odd_blocks.cab"), build_cab(odd, files))
    if ref_ok(t, p, exp, "odd_blocks.cab", refs=("cabextract",)):
        t.check_extract(p, exp, label="stored blocks of 20000 bytes")
    p = write(t.path("reserve.cab"), build_cab(folders, files, res=(b"RESERVED-HEADER" * 3, 7, 5)))
    if ref_ok(t, p, exp, "reserve.cab", refs=("7z",)):
        t.check_extract(p, exp, label="reserve fields")
    p = write(t.path("reserve2.cab"), build_cab(folders, files, res=(b"R" * 6144, 0, 3), res_in_sum=False))
    if ref_ok(t, p, exp, "reserve2.cab", refs=("cabextract",)):
        t.check_extract(p, exp, label="reserve fields, libmspack-style checksums")
    p = write(t.path("nocsum.cab"), build_cab(folders, files, checksum=False))
    t.check_extract(p, exp, label="no checksums")

    # names, attributes
    names = [("한글/파일.txt".encode(), 0xa0), ("readonly.txt".encode(), 0x21), ("tool.sh".encode(), 0x60),
             ("hidden_sys.dat".encode(), 0x26)]
    data = b"name test\n" * 100
    fl = [(nm, len(data), 0, 0, at, 0x5A21, 0x6000) for nm, at in names]
    p = write(t.path("names.cab"), build_cab([(0, none_blocks(data))], fl))
    t.check_extract(p, {"한글/파일.txt": data, "readonly.txt": data, "tool.sh": data, "hidden_sys.dat": data},
                    label="utf8 names + shared data")
    typ, m = listing_map(t, p)
    t.record(m.get("tool.sh", {}).get("mode") == 0o100755, "exec attribute -> mode 755", str(m.get("tool.sh")))
    cp = [("문서\\보고서.txt", b"report"), ("사진\\고기.jpg", b"meat")]
    fl, blobd, off = [], b"", 0
    for k, v in cp:
        fl.append((k.encode("cp949"), len(v), off, 0, 0x20, 0x5A21, 0x6000))
        blobd += v
        off += len(v)
    p = write(t.path("cp949.cab"), build_cab([(1, mszip_blocks(blobd))], fl))
    t.check_extract(p, {k: v for k, v in cp}, acp=949, label="cp949 names")

    # ---- LZX: the test encoder, cross-checked with 7-Zip / cabextract
    tool = t.build_driver("tests/drivers/lzx_tool.c")
    drv = t.build_driver("tests/drivers/arc_random.c")
    qtool = t.build_driver("tests/drivers/qtm_tool.c")
    inputs = {
        "text": blob(400000, 1, 7),
        "x86": x86_like(300000, 8),
        "mixed": x86_like(150000, 9) + blob(150000, 0, 10) + blob(150000, 1, 11),
        "small": b"tiny lzx data",
        "frame": blob(32768, 1, 12),
    }
    cases = [("text", 15, 0, "v", 32768), ("text", 16, 0, "a", 0), ("x86", 17, 12000000, "a", 32768),
             ("x86", 21, 3000000, "r", 0), ("mixed", 18, 0, "r", 1000), ("mixed", 19, 12000000, "u", 0),
             ("mixed", 20, 0, "v", 65536), ("small", 15, 0, "v", 0), ("frame", 16, 12000000, "u", 32768),
             ("mixed", 21, 0, "r", 3000)]
    for i, (name, wb, e8, mode, bs) in enumerate(cases):
        data = inputs[name]
        src = write(t.path("lzx_in_%d.bin" % i), data)
        lz = t.path("lzx_%d.lzxf" % i)
        t.sh([tool, "enc", src, lz, str(wb), str(e8), mode, str(bs), str(i + 1)])
        names, ex = split_files(data, random.Random(i), prefix=b"lzx\\part")
        p = write(t.path("lzx_%s_%d_%s_%d.cab" % (name, wb, mode, i)),
                  build_cab([(3 | wb << 8, read_lzxf(lz))], file_list(names)))
        label = "LZX:%d %s e8=%d mode=%s bs=%d" % (wb, name, e8, mode, bs)
        if ref_ok(t, p, ex, label):
            t.check_extract(p, ex, label=label)
        # codec level: per frame and as a continuous stream
        for how in ("frame", "cont"):
            outp = t.path("lzx_dec_%d_%s.bin" % (i, how))
            r = t.sh([tool, "dec", lz, outp, str(wb), how], check=False)
            t.record(r.returncode == 0 and open(outp, "rb").read() == data, "codec %s %s" % (how, label),
                     r.stdout.decode(errors="replace")[-200:])
    typ, m = listing_map(t, p)
    t.record(any(x["method"] == "LZX:21" for x in m.values()), "LZX method name", str(list(m.values())[:1]))

    # resets every N frames (CHM style), continuous decoding with reset points
    data = inputs["mixed"]
    src = write(t.path("reset_in.bin"), data)
    for rf, mode in ((1, "v"), (2, "u"), (3, "r")):
        lz = t.path("reset_%d.lzxf" % rf)
        t.sh([tool, "enc", src, lz, "16", "12000000", mode, "0", str(rf), str(rf)])
        for how in ("frame", "cont"):
            outp = t.path("reset_dec.bin")
            r = t.sh([tool, "dec", lz, outp, "16", how, str(rf)], check=False)
            t.record(r.returncode == 0 and open(outp, "rb").read() == data, "codec reset/%d %s %s" % (rf, mode, how))

    # ---- WIM mode against wimlib's LZX compressor
    if t.tool("wimlib-imagex"):
        spec = importlib.util.spec_from_file_location("_wimchunks", os.path.join(HERE, "_wimchunks.py"))
        wc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wc)
        wsrc = t.write_tree(os.path.join(W, "wimsrc"), {"x86.bin": inputs["x86"], "text.txt": inputs["text"],
                                                        "mixed.bin": inputs["mixed"], "rnd.bin": blob(70000, 0, 3)})
        for cs in (32768, 65536, 1 << 21):
            wim = t.path("lzx_%d.wim" % cs)
            if os.path.exists(wim):
                os.remove(wim)
            r = t.sh(["wimlib-imagex", "capture", wsrc, wim, "--compress=LZX", "--chunk-size=%d" % cs], check=False)
            if r.returncode:
                t.record(False, "wimlib capture %d" % cs, r.stderr.decode(errors="replace")[-200:])
                continue
            good = total = 0
            for chunk, chunks, sha in wc.resources(wim):
                lz = t.path("wim.lzxf")
                wc.write_lzxf(lz, chunks)
                outp = t.path("wim.out")
                r = t.sh([tool, "dec", lz, outp, str(int(math.log2(chunk))), "wim"], check=False)
                total += 1
                good += r.returncode == 0 and hashlib.sha1(open(outp, "rb").read()).digest() == sha
            t.record(total and good == total, "WIM LZX chunk %d (%d resources)" % (cs, total), "%d/%d" % (good, total))

    # ---- codec fuzzing (corrupt frames must fail cleanly)
    fz = t.path("lzx_3.lzxf")
    r = t.sh([tool, "fuzz", fz, "21", "300", "1"], check=False, timeout=300)
    t.record(r.returncode == 0, "LZX fuzz (frames)", r.stdout.decode(errors="replace").strip())
    if t.tool("wimlib-imagex") and os.path.exists(t.path("lzx_32768.wim")):
        res = wc.resources(t.path("lzx_32768.wim"))
        if res:
            lz = t.path("wimfz.lzxf")
            wc.write_lzxf(lz, res[0][1])
            r = t.sh([tool, "fuzz", lz, "15", "300", "2", "wim"], check=False, timeout=300)
            t.record(r.returncode == 0, "LZX fuzz (WIM chunks)", r.stdout.decode(errors="replace").strip())

    # ---- multi-cabinet sets (split blocks, files continued across cabinets)
    data = blob(300000, 1, 20) + x86_like(100000, 21)
    names, ex = split_files(data, random.Random(3), prefix=b"set\\f")
    fl = file_list(names)
    src = write(t.path("set_in.bin"), data)
    lz = t.path("set.lzxf")
    t.sh([tool, "enc", src, lz, "17", "0", "a", "32768", "4"])
    qf = t.path("set.frames")
    t.sh([qtool, "enc", src, qf, "17", "4"])
    variants = [("mszip", 1, mszip_blocks(data)), ("lzx", 3 | 17 << 8, read_lzxf(lz)), ("none", 0, none_blocks(data)),
                ("quantum", 2 | 4 << 4 | 17 << 8, read_lzxf(qf))]
    for vname, ctype, blocks in variants:
        d = os.path.join(W, "set_" + vname)
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
        cabnames, cabs = build_set(blocks, ctype, fl, [4, 9], split=vname != "none", base="disk")
        for nm, cb in zip(cabnames, cabs):
            write(os.path.join(d, nm), cb)
        first = os.path.join(d, cabnames[0])
        # libmspack cannot merge one folder over three cabinets with different files
        # at each boundary: 7-Zip is the reference here, both for two cabinets
        if not ref_ok(t, first, ex, "set " + vname, refs=("7z",)):
            continue
        d2 = os.path.join(W, "set2_" + vname)
        shutil.rmtree(d2, ignore_errors=True)
        os.makedirs(d2)
        n2, c2 = build_set(blocks, ctype, fl, [6], split=vname != "none", base="two")
        for nm, cb in zip(n2, c2):
            write(os.path.join(d2, nm), cb)
        if ref_ok(t, os.path.join(d2, n2[0]), ex, "set2 " + vname, refs=("7z",)):
            t.check_extract(os.path.join(d2, n2[1]), ex, label="two cabinets %s (from second)" % vname)
        t.check_extract(first, ex, label="cabinet set %s (from first)" % vname)
        t.check_extract(os.path.join(d, cabnames[1]), ex, label="cabinet set %s (from middle)" % vname)
        check_random(t, drv, os.path.join(d, cabnames[2]), ex, "shuffle", "cabinet set %s per-entry (from last)" % vname)
        if has7z and vname == "lzx":
            t.check_vs_7z(first, label="vs 7z cabinet set")
        # last cabinet missing: files that need it fail with GZ_E_VOLUME, the others extract
        os.rename(os.path.join(d, cabnames[2]), os.path.join(d, "gone.cab"))
        r, rows, out = t.extract(first)
        okc = bad = 0
        for i, (st, isdir, size, name) in rows.items():
            if st == 0 and open(os.path.join(out, "%d.bin" % i), "rb").read() == ex[name]:
                okc += 1
            elif st == 14:
                bad += 1
        t.record(r.returncode == 0 and okc > 0 and bad > 0 and okc + bad == len(rows),
                 "cabinet set %s, missing last volume" % vname, "ok=%d volume_err=%d of %d" % (okc, bad, len(rows)))

    # ---- SFX / IExpress-like executables
    lzcab = open(t.path("lzx_x86_17_a_2.cab"), "rb").read()
    names, ex = split_files(inputs["x86"], random.Random(2), prefix=b"lzx\\part")
    stub = b"MZ" + bytes(58) + blob(70000, 0, 30) + b"MSCF\0\0\0\0garbage-not-a-cab" + blob(9000, 0, 31)
    p = write(t.path("setup.exe"), stub + lzcab + blob(3000, 0, 32))
    t.check_extract(p, ex, label="CAB inside an executable", expect_type="CAB")
    p = write(t.path("not_sfx.bin"), b"XX" + bytes(1000) + lzcab)
    r, rows, out = t.extract(p)
    t.record(b"OPEN_ERROR" in r.stdout or "type=CAB" not in r.stderr.decode(), "no deep scan without MZ")

    # ---- Quantum: the test encoder, cross-checked with 7-Zip / cabextract
    qcases = [("text", 10, 0), ("x86", 15, 0), ("mixed", 16, 0), ("text", 18, 0), ("mixed", 21, 0),
              ("small", 12, 0), ("mixed", 17, -1)]
    for i, (name, wb, pad) in enumerate(qcases):
        data = inputs[name]
        src = write(t.path("qtm_in_%d.bin" % i), data)
        qf = t.path("qtm_%d.frames" % i)
        t.sh([qtool, "enc", src, qf, str(wb), str(i + 1), str(pad)])
        names, ex = split_files(data, random.Random(50 + i), prefix=b"qtm\\part")
        p = write(t.path("qtm_%s_%d_%d.cab" % (name, wb, i)),
                  build_cab([(2 | 4 << 4 | wb << 8, read_lzxf(qf))], file_list(names)))
        label = "Quantum:%d %s pad=%d" % (wb, name, pad)
        # 7-Zip wants a block to end right after the coder's flush; Microsoft's tools
        # (and cabextract) also allow up to 4 padding bytes
        if ref_ok(t, p, ex, label, refs=("7z", "cabextract") if pad == 0 else ("cabextract",)):
            t.check_extract(p, ex, label=label)
        outp = t.path("qtm_dec.bin")
        r = t.sh([qtool, "dec", qf, outp, str(wb)], check=False)
        t.record(r.returncode == 0 and open(outp, "rb").read() == data, "codec " + label)
    typ, m = listing_map(t, p)
    t.record(any(x["method"] == "Quantum:17" for x in m.values()), "Quantum method name", str(list(m.values())[:1]))
    r = t.sh([qtool, "fuzz", t.path("qtm_4.frames"), "21", "300", "3"], check=False, timeout=300)
    t.record(r.returncode == 0, "Quantum fuzz (frames)", r.stdout.decode(errors="replace").strip())
    p = write(t.path("quantum_bad_window.cab"), build_cab([(2 | 7 << 4 | 9 << 8, [(b"\x00" * 100, 200)])],
                                                          file_list([(b"q.bin", 200)])))
    r, rows, out = t.extract(p)
    t.record(rows.get(0, (0,))[0] == 5, "Quantum window 2^9 -> GZ_E_METHOD", str(rows))

    # ---- all four methods in one cabinet
    qf = t.path("qtm_2.frames")
    ds, dm, dl = blob(50000, 0, 5), blob(200000, 1, 4), inputs["mixed"]
    mixed4 = [(0, none_blocks(ds)), (1, mszip_blocks(dm)), (3 | 18 << 8, read_lzxf(t.path("lzx_4.lzxf"))),
              (2 | 4 << 4 | 16 << 8, read_lzxf(qf))]
    n4 = [(b"m4\\store.bin", len(ds)), (b"m4\\mszip.bin", len(dm)), (b"m4\\lzx.bin", len(dl)), (b"m4\\qtm.bin", len(dl))]
    fl4 = [(nm, sz, 0, k, 0x20, 0x5A21, 0x6000) for k, (nm, sz) in enumerate(n4)]
    exp4 = {"m4/store.bin": ds, "m4/mszip.bin": dm, "m4/lzx.bin": dl, "m4/qtm.bin": dl}
    p = write(t.path("four_methods.cab"), build_cab(mixed4, fl4))
    if ref_ok(t, p, exp4, "four_methods.cab"):
        t.check_extract(p, exp4, label="None + MSZIP + LZX + Quantum folders")
        check_random(t, drv, p, exp4, "rev", "four methods, per-entry extraction")
    check_random(t, drv, t.path("multi_folder.cab"), exp, "shuffle", "multi_folder.cab per-entry extraction")

    # ---- checksum / data errors are reported per folder
    good = build_cab(folders, files)
    bad = bytearray(good)
    o = good.index(b"CK", good.index(b"CK") + 10)       # a later MSZIP block of folder 0
    bad[o + 40] ^= 0x55
    p = write(t.path("badsum.cab"), bytes(bad))
    r, rows, out = t.extract(p)
    sts = {name.split("/")[0]: [] for st, isdir, size, name in rows.values()}
    for st, isdir, size, name in rows.values():
        sts[name.split("/")[0]].append(st)
    t.record(4 in sts.get("mszip", []) and all(s == 0 for s in sts.get("store", [1])),
             "bad CFDATA checksum -> GZ_E_CRC in that folder only", str(sts))

    # ---- libmspack's CAB test files (Microsoft-made sets, Quantum, reserve, broken files)
    hostile = []
    tgz = fetch(t, "https://www.cabextract.org.uk/libmspack/libmspack-0.11alpha.tar.gz", "libmspack-0.11alpha.tar.gz")
    if tgz:
        md = os.path.join(W, "mspack")
        shutil.rmtree(md, ignore_errors=True)
        os.makedirs(md)
        with tarfile.open(tgz) as tf:
            for m in tf.getmembers():
                if "/test_files/cabd/" in m.name and m.isfile() and m.name.endswith(".cab"):
                    nm = os.path.basename(m.name)
                    if nm.startswith("multi_basic"):
                        nm = "cabd_" + nm                # the names stored in the set
                    write(os.path.join(md, nm), tf.extractfile(m).read())
        exp3 = None
        if t.tool("cabextract"):
            rc, exp3 = cabextract_tree(t, os.path.join(md, "cabd_multi_basic_pt1.cab"), t.path("mb_ref"))
        if exp3:
            t.check_extract(os.path.join(md, "cabd_multi_basic_pt1.cab"), exp3, label="libmspack multi_basic set (5 cabinets)")
            t.check_extract(os.path.join(md, "cabd_multi_basic_pt3.cab"), exp3, label="libmspack multi_basic set from part 3")
        for nm in sorted(os.listdir(md)):
            p = os.path.join(md, nm)
            if nm.startswith(("normal_", "reserve_", "mszip_lzx")) and t.tool("cabextract"):
                rc, exp = cabextract_tree(t, p, t.path("ms_ref"))
                if nm.startswith("mszip_lzx"):
                    r, rows, out = t.extract(p)
                    res = {name: (st, open(os.path.join(out, "%d.bin" % i), "rb").read() if st == 0 else None)
                           for i, (st, isdir, size, name) in rows.items()}
                    ok = res.get("mszip.txt", (1,))[1] == exp.get("mszip.txt") and res.get("lzx.txt", (1,))[1] == exp.get("lzx.txt")
                    ok = ok and res.get("qtm.txt", (1,))[1] == exp.get("qtm.txt")
                    t.record(ok, "libmspack " + nm, str({k: v[0] for k, v in res.items()}))
                elif rc == 0 and exp:
                    t.check_extract(p, exp, label="libmspack " + nm)
            else:
                hostile.append(("mspack_" + nm[:-4], open(p, "rb").read()))

    # ---- hostile inputs
    base = build_cab(folders, files)
    for cut in (10, 36, 50, 60, 100, 200, 400, len(base) // 2, len(base) - 7):
        hostile.append(("trunc%d" % cut, base[:cut]))
    rng = random.Random(77)
    for k in range(40):
        b = bytearray(base)
        for _ in range(rng.randint(1, 6)):
            o = rng.randrange(0, 400) if k % 2 else rng.randrange(len(b))
            b[o] ^= 1 << rng.randrange(8)
        hostile.append(("flip%d" % k, bytes(b)))
    def patch(off, fmt, val):
        b = bytearray(base)
        struct.pack_into(fmt, b, off, val)
        return bytes(b)
    hostile += [
        ("nfold_huge", patch(26, "<H", 0xffff)), ("nfiles_huge", patch(28, "<H", 0xffff)),
        ("coff_files_huge", patch(16, "<I", 0xfffffff0)), ("fold_start_huge", patch(36, "<I", 0xfffffff0)),
        ("fold_blocks_huge", patch(40, "<H", 0xffff)), ("bad_lzx_window", patch(42, "<H", 3 | 31 << 8)),
        ("ifolder_bad", patch(36 + 24 + 8, "<H", 77)), ("uoff_huge", patch(36 + 24 + 4, "<I", 0xffffff00)),
        ("size_huge", patch(36 + 24, "<I", 0xffffffff)),
    ]
    lb = bytearray(open(t.path("lzx_mixed_21_r_9.cab"), "rb").read())
    dpos = struct.unpack_from("<I", lb, 36)[0]
    for k in range(30):
        b = bytearray(lb)
        for _ in range(3):
            b[dpos + 8 + rng.randrange(min(4000, len(b) - dpos - 8))] ^= 1 << rng.randrange(8)
        hostile.append(("lzx_flip%d" % k, bytes(b)))
    b = bytearray(lb)
    struct.pack_into("<H", b, dpos + 4, 0xffff)          # CFDATA size past the end
    hostile.append(("cfdata_size", bytes(b)))
    # a cabinet that names itself as the next one
    hostile.append(("self_next", build_cab(folders, files, nxt=(b"hostile_self_next.cab", b"x"))))
    for name, data in hostile:
        check_hostile2(t, drv, write(t.path("hostile_%s.cab" % name), data))

    # ---- speed: a bigger LZX:21 cabinet vs 7-Zip
    big = (x86_like(3000000, 40) + blob(3000000, 1, 41)) * 2
    src = write(t.path("big_in.bin"), big)
    lz = t.path("big.lzxf")
    t.sh([tool, "enc", src, lz, "21", "12000000", "a", "32768", "5", "0", "8"], timeout=600)
    p = write(t.path("big.cab"), build_cab([(3 | 21 << 8, read_lzxf(lz))], file_list([(b"big.bin", len(big))])))
    t0 = time.time()
    r, rows, out = t.extract(p)
    t1 = time.time()
    ok = rows.get(0, (1,))[0] == 0 and open(os.path.join(out, "0.bin"), "rb").read() == big
    detail = "gzt %.2fs" % (t1 - t0)
    if has7z:
        t0 = time.time()
        subprocess.run(["7z", "t", p], capture_output=True)
        detail += ", 7z t %.2fs" % (time.time() - t0)
    t.record(ok, "LZX:21 12 MB", detail)

    # ---- keep the work directory small (fixtures stay for debugging)
    for nm in os.listdir(W):
        p = os.path.join(W, nm)
        if os.path.isdir(p) and nm.startswith(("out_", "ref7z_", "refcx_", "rndh_", "mb_ref", "ms_ref")):
            shutil.rmtree(p, ignore_errors=True)
        elif nm.startswith(("big", "lzx_in_", "lzx_dec_", "reset_dec", "wim.out")):
            os.remove(p)
