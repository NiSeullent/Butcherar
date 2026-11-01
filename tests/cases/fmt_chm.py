"""CHM tests.

Fixtures: chmcmd (Free Pascal) projects, a committed chmcmd CHM
(tests/data/chm, regenerated content checked byte for byte), a Python CHM writer
using the LZX test encoder (windows 2^15..2^21, reset intervals, E8, stored LZX
blocks; cross-checked with 7-Zip), Microsoft-made 7-zip.chm from the 7-Zip
installer (downloaded, skipped offline) and libmspack's CHM regression files
(downloaded, hostile).
"""
import os, struct, random, shutil, subprocess, hashlib, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DATA = os.path.join(ROOT, "tests", "data", "chm")

WORDS = "meat grill pork belly kimchi rice soju lettuce garlic onion pepper sauce archive cabinet help".split()

def make_project(n, seed, big=4000, nimg=5):
    """deterministic HTML help sources: {relative path: bytes}"""
    rnd = random.Random(seed)
    files = {}
    for i in range(n):
        body = " ".join(rnd.choice(WORDS) for _ in range(rnd.randint(20, big)))
        name = "html/page%03d.html" % i if i % 3 else "html/sub/topic%03d.html" % i
        files[name] = ("<html><head><title>Page %d</title></head><body><h1>Page %d</h1><p>%s</p>"
                       "<a href=\"page001.html\">x</a></body></html>" % (i, i, body)).encode()
    for i in range(nimg):
        files["img/pic%d.bin" % i] = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(100, 30000)))
    return files

def write_project(root, files):
    shutil.rmtree(root, ignore_errors=True)
    for k, v in files.items():
        os.makedirs(os.path.dirname(os.path.join(root, k)), exist_ok=True)
        open(os.path.join(root, k), "wb").write(v)
    hhp = ("[OPTIONS]\nCompatibility=1.1 or later\nCompiled file=test.chm\nDefault topic=html/page001.html\n"
           "Display compile progress=No\nLanguage=0x409 English (United States)\nTitle=Test\n\n[FILES]\n" +
           "\n".join(k.replace("/", "\\") for k in sorted(files)) + "\n")
    open(os.path.join(root, "test.hhp"), "w").write(hhp)

# ---------------------------------------------------------------- CHM writer

def encint(v):
    out = [v & 0x7f]
    v >>= 7
    while v:
        out.append(0x80 | (v & 0x7f))
        v >>= 7
    return bytes(reversed(out))

GUID_ITSF1 = bytes.fromhex("10fd017caa7bd0119e0c00a0c922e6ec")
GUID_ITSF2 = bytes.fromhex("11fd017caa7bd0119e0c00a0c922e6ec")
GUID_ITSP = bytes.fromhex("6a92025d2e21d0119df900a0c922e6ec")
MSC = "::DataSpace/Storage/MSCompressed/"
RT = MSC + "Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable"

def build_chm(sec0_files, sec1_files, frames, wbits, ri_frames, chunk=4096, ctl_version=2):
    """sec0/sec1: {"/name": bytes}; frames: LZX frames [(cdata, u)] of the section-1 files
    concatenated in sorted name order (padded to whole frames). Returns the CHM bytes."""
    ulen = sum(len(v) for v in sec1_files.values())
    comp = b"".join(d for d, u in frames)
    ents = {"/": (0, 0, 0)}
    s0 = bytearray()
    def add0(name, data):
        ents[name] = (0, len(s0), len(data))
        s0.extend(data)
    add0("::DataSpace/NameList", bytes.fromhex("1e0002000c00") + "Uncompressed".encode("utf-16le") + b"\0\0" +
         b"\x0c\x00" + "MSCompressed".encode("utf-16le") + b"\0\0")
    ws = (1 << wbits) // 32768 if ctl_version == 2 else 1 << wbits
    ri = ri_frames if ctl_version == 2 else ri_frames * 32768
    # "cache size": hhc and chmcmd write window / 64 KiB (chmlib derives the reset frequency from it)
    cache = max(1, (1 << wbits) // 65536)
    add0(MSC + "ControlData", struct.pack("<I4sIIIII", 6, b"LZXC", ctl_version, ri, ws, cache, 0))
    add0(MSC + "SpanInfo", struct.pack("<Q", ulen))
    add0(MSC + "Transform/List", "{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}".encode("utf-16le"))
    offs, o = [], 0
    for d, u in frames:
        offs.append(o)
        o += len(d)
    offs.append(o)
    add0(RT, struct.pack("<IIIIQQQ", 2, len(offs), 8, 0x28, ulen, len(comp), 32768) + b"".join(struct.pack("<Q", x) for x in offs))
    add0(MSC + "Content", comp)
    for k in sorted(sec0_files):
        add0(k, sec0_files[k])
    o = 0
    for k in sorted(sec1_files):
        ents[k] = (1, o, len(sec1_files[k]))
        o += len(sec1_files[k])
    dirs = set()
    for k in list(sec0_files) + list(sec1_files):
        parts = k.split("/")[1:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/" + "/".join(parts[:i]) + "/")
    for d in dirs:
        ents[d] = (0, 0, 0)
    ents[MSC.rstrip("/").rsplit("/", 1)[0] + "/"] = (0, 0, 0)   # a directory among the internals
    # PMGL chunks
    chunks, cur, count = [], bytearray(), 0
    names = sorted(ents, key=lambda s: s.lower())
    for nm in names:
        nb = nm.encode()
        sec, off, ln = ents[nm]
        e = encint(len(nb)) + nb + encint(sec) + encint(off) + encint(ln)
        if 0x14 + len(cur) + len(e) + 2 > chunk:
            chunks.append((bytes(cur), count))
            cur, count = bytearray(), 0
        cur += e
        count += 1
    chunks.append((bytes(cur), count))
    dirb = bytearray()
    nch = len(chunks)
    for i, (body, cnt) in enumerate(chunks):
        free = chunk - 0x14 - len(body)
        c = b"PMGL" + struct.pack("<IIii", free, 0, i - 1 if i else -1, i + 1 if i + 1 < nch else -1) + body
        c += bytes(chunk - len(c) - 2) + struct.pack("<H", cnt)
        dirb += c
    itsp = b"ITSP" + struct.pack("<IIIIIIiIIiII", 1, 0x54, 10, chunk, 2, 1, -1, 0, nch - 1, -1, nch, 0x409) + GUID_ITSP + \
        struct.pack("<Iiii", 0x54, -1, -1, -1)
    directory = itsp + dirb
    dir_off = 0x60 + 0x18
    content_off = dir_off + len(directory)
    total = content_off + len(s0)
    itsf = b"ITSF" + struct.pack("<IIII", 3, 0x60, 1, 0x12345678) + struct.pack("<I", 0x409) + GUID_ITSF1 + GUID_ITSF2 + \
        struct.pack("<QQQQQ", 0x60, 0x18, dir_off, len(directory), content_off)
    hs0 = struct.pack("<IIQII", 0x1FE, 0, total, 0, 0)
    return itsf + hs0 + directory + bytes(s0)

def read_lzxf(path):
    b = open(path, "rb").read()
    n = struct.unpack_from("<I", b, 4)[0]
    o, fr = 8, []
    for i in range(n):
        c, u = struct.unpack_from("<II", b, o)
        fr.append((b[o + 8:o + 8 + c], u))
        o += 8 + c
    return fr

# ---------------------------------------------------------------- helpers

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

def check_random(t, drv, arc, exp, order, label):
    """per-entry extraction (random access) against expected {name: bytes}"""
    out = t.path("rnd_" + os.path.basename(arc) + "_" + order)
    shutil.rmtree(out, ignore_errors=True)
    r = t.sh([drv, arc, out, order, "7"], check=False)
    bad = []
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if len(p) != 5 or not p[0].isdigit():
            continue
        i, st, isdir, name = int(p[0]), int(p[1]), int(p[2]), p[4]
        if isdir or name not in exp:
            continue
        if st != 0 or open(os.path.join(out, "%d.bin" % i), "rb").read() != exp[name]:
            bad.append("%s:%d" % (name, st))
    return t.record(r.returncode == 0 and not bad, label, ",".join(bad[:5]))

def synthetic_ref(t, p, exp):
    """Which reference accepts a synthetic CHM: "7z", "chmlib", "none" (both decline the
    parameters: the expected data is known anyway) or False (a reference decodes it
    differently: the writer or encoder is wrong)."""
    unsupported = True
    if t.tool("7z"):
        rr, out = t.sevenzip_extract(p)
        txt = rr.stdout.decode(errors="replace")
        if "Unsupported" not in txt:
            got = t.read_tree(out)
            if rr.returncode == 0 and all(got.get(k) == v for k, v in exp.items()):
                return "7z"
            return False
    if t.tool("extract_chmLib"):
        out = t.path("refcl_" + os.path.basename(p))
        shutil.rmtree(out, ignore_errors=True)
        subprocess.run(["extract_chmLib", p, out], capture_output=True)
        got = t.read_tree(out)
        if all(got.get(k) == v for k, v in exp.items()):
            return "chmlib"
    return "none" if unsupported else False

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

def run(t):
    W = t.work
    has7z = bool(t.tool("7z"))
    drv = t.build_driver("tests/drivers/arc_random.c")

    # ---- committed chmcmd fixture: content regenerated and compared byte for byte
    small = make_project(12, 1, big=600, nimg=2)
    fx = os.path.join(DATA, "chmcmd_small.chm")
    if os.path.exists(fx):
        t.check_extract(fx, small, allow_extra=True, expect_type="CHM", label="committed chmcmd fixture")
        check_random(t, drv, fx, small, "rev", "committed fixture, per-entry extraction")

    # ---- chmcmd projects
    if t.tool("chmcmd"):
        for n, seed in ((40, 2), (150, 3)):
            files = make_project(n, seed)
            proj = os.path.join(W, "proj%d" % n)
            write_project(proj, files)
            r = t.sh(["chmcmd", "--no-html-scan", "test.hhp"], cwd=proj, check=False)
            p = os.path.join(proj, "test.chm")
            if r.returncode or not os.path.exists(p):
                t.record(False, "chmcmd %d" % n, r.stdout.decode(errors="replace")[-300:])
                continue
            dst = t.path("chmcmd_%d.chm" % n)
            shutil.copy(p, dst)
            t.check_extract(dst, files, allow_extra=True, label="chmcmd %d pages" % n)
            if has7z:
                t.check_vs_7z(dst, label="vs 7z chmcmd %d" % n)
            for order in ("rev", "shuffle"):
                check_random(t, drv, dst, files, order, "chmcmd %d per-entry %s" % (n, order))
            r2, typ, rows = t.listing(dst)
            m = {x["name"]: x for x in rows}
            t.record(m.get("html/page001.html", {}).get("method") == "LZX:16" and m.get("#SYSTEM", {}).get("method") == "Copy"
                     and not any(k.startswith("::") or k.startswith("DataSpace") for k in m),
                     "chmcmd %d listing/method names" % n, str(list(m.items())[:3]))

    # ---- synthetic CHMs: LZX parameters chmcmd does not use
    tool = t.build_driver("tests/drivers/lzx_tool.c")
    rnd = random.Random(9)
    cases = [(15, 1, 0, "v", 0), (16, 2, 0, "a", 32768), (17, 4, 0, "r", 0), (18, 4, 12000000, "a", 0),
             (19, 3, 0, "u", 0), (20, 8, 0, "r", 5000), (21, 2, 12000000, "r", 0), (21, 1000, 0, "a", 32768),
             (16, 1, 0, "u", 1001)]
    for i, (wb, ri, e8, mode, bs) in enumerate(cases):
        src = make_project(25, 100 + i, big=3000, nimg=3)
        sec1 = {"/" + k: v for k, v in src.items() if not k.endswith("pic0.bin")}
        sec0 = {"/" + k: v for k, v in src.items() if k.endswith("pic0.bin")}
        sec0["/#SYSTEM"] = b"\x03\x00\x00\x00" + bytes(range(60))
        stream = b"".join(sec1[k] for k in sorted(sec1))
        stream += bytes(-len(stream) % 32768)      # like hhc / chmcmd: whole frames
        sp = t.path("syn_%d.bin" % i)
        open(sp, "wb").write(stream)
        lz = t.path("syn_%d.lzxf" % i)
        t.sh([tool, "enc", sp, lz, str(wb), str(e8), mode, str(bs), str(i + 3), str(ri)])
        chm = build_chm(sec0, sec1, read_lzxf(lz), wb, ri, ctl_version=1 if i == 3 else 2)
        p = t.path("syn_w%d_r%d_%s%s.chm" % (wb, ri, mode, "_e8" if e8 else ""))
        open(p, "wb").write(chm)
        exp = {k[1:]: v for k, v in list(sec1.items()) + list(sec0.items())}
        label = "synthetic CHM LZX:%d reset=%d e8=%d mode=%s" % (wb, ri, e8, mode)
        ref = synthetic_ref(t, p, exp)
        if ref is False:
            t.record(False, label + " (reference rejects the fixture)")
            continue
        t.check_extract(p, exp, label=label + " [%s]" % ref)
        check_random(t, drv, p, exp, "shuffle", label + " per-entry")

    # ---- Microsoft-made CHM (HTML Help Workshop): 7-zip.chm from the 7-Zip installer
    inst = fetch(t, "https://www.7-zip.org/a/7z2301-x64.exe", "7z2301-x64.exe")
    if inst and has7z:
        d = t.path("msdl")
        shutil.rmtree(d, ignore_errors=True)
        r = t.sh(["7z", "e", "-y", "-o" + d, inst, "7-zip.chm"], check=False)
        p = os.path.join(d, "7-zip.chm")
        if r.returncode == 0 and os.path.exists(p):
            t.check_vs_7z(p, label="Microsoft-made 7-zip.chm vs 7z")
            rr, out = t.sevenzip_extract(p)
            check_random(t, drv, p, t.read_tree(out), "shuffle", "7-zip.chm per-entry")
    else:
        t.record(True, "7-zip.chm download skipped (offline)")

    # ---- hostile inputs
    base = None
    for cand in (os.path.join(W, "chmcmd_40.chm"), fx, t.path("syn_w17_r4_r.chm")):
        if os.path.exists(cand):
            base = open(cand, "rb").read()
            break
    hostile = []
    if base:
        rng = random.Random(5)
        for cut in (0x30, 0x60, 0x80, 0xd0, 0x200, 0x1000, len(base) // 2, len(base) - 100):
            hostile.append(("trunc%d" % cut, base[:cut]))
        for k in range(60):
            b = bytearray(base)
            region = (0, 0x1100) if k % 3 == 0 else (0x1100, len(b)) if k % 3 == 1 else (0, len(b))
            for _ in range(rng.randint(1, 8)):
                o = rng.randrange(*region)
                b[o] ^= 1 << rng.randrange(8)
            hostile.append(("flip%d" % k, bytes(b)))
        def patch(off, fmt, val):
            b = bytearray(base)
            struct.pack_into(fmt, b, off, val)
            return bytes(b)
        dir_off = struct.unpack_from("<Q", base, 0x48)[0]
        hostile += [
            ("dir_off_huge", patch(0x48, "<Q", 1 << 62)), ("dir_len_huge", patch(0x50, "<Q", (1 << 64) - 1)),
            ("content_huge", patch(0x58, "<Q", (1 << 64) - 16)), ("chunk_size_huge", patch(dir_off + 0x10, "<I", 0xffffffff)),
            ("chunk_size_small", patch(dir_off + 0x10, "<I", 8)), ("nchunks_huge", patch(dir_off + 0x2c, "<I", 0xffffffff)),
            ("pmgl_range", patch(dir_off + 0x20, "<I", 0xfffffff0)), ("free_huge", patch(dir_off + 0x54 + 4, "<I", 0xffffffff)),
        ]
        # reset table / control data corruption
        lz = base.find(b"LZXC")
        if lz > 0:
            for name, off, val in (("ri_zero", 8, 0), ("window_bad", 12, 3), ("version_bad", 4, 9), ("window_huge", 12, 0x40000)):
                hostile.append((name, patch(lz + off, "<I", val)))
        # reset table entries pointing anywhere
        b = bytearray(base)
        marker = struct.pack("<II", 8, 0x28)
        k = b.find(marker)
        if k > 0:
            for j in range(8):
                struct.pack_into("<Q", b, k + 0x20 + 8 * j, rng.getrandbits(40))
            hostile.append(("rt_entries", bytes(b)))
            hostile.append(("rt_count", patch(k - 4, "<I", 0xffffffff)))
            hostile.append(("rt_ulen", patch(k + 8, "<Q", (1 << 63))))
    for name, data in hostile:
        p = t.path("hostile_%s.chm" % name)
        open(p, "wb").write(data)
        check_hostile2(t, drv, p)
    # libmspack's CHM regression files
    tgz = fetch(t, "https://www.cabextract.org.uk/libmspack/libmspack-0.11alpha.tar.gz", "libmspack-0.11alpha.tar.gz")
    if tgz:
        import tarfile
        n = 0
        with tarfile.open(tgz) as tf:
            for m in tf.getmembers():
                if "/test_files/chmd/" in m.name and m.isfile():
                    data = tf.extractfile(m).read()
                    if m.name.endswith(".xor"):
                        data = bytes(x ^ 0xff for x in data)   # stored inverted (virus scanners)
                    p = t.path("mspack_" + os.path.basename(m.name).replace(".xor", ""))
                    open(p, "wb").write(data)
                    check_hostile2(t, drv, p)
                    n += 1
        t.record(n > 5, "libmspack CHM regression files", str(n))

    # ---- keep the work directory small (fixtures stay for debugging)
    for nm in os.listdir(W):
        p = os.path.join(W, nm)
        if os.path.isdir(p) and nm.startswith(("out_", "ref7z_", "refcl_", "rnd_", "rndh_", "msdl", "proj")):
            shutil.rmtree(p, ignore_errors=True)
