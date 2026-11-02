"""
ZIP writer (src/fmt/zip_write.c).

Archives written by `gzt c` and by tests/drivers/zip_write_drv.c are checked with
7-Zip (7z t + 7z x, tree compare), Info-ZIP (unzip -t), Python zipfile / pyzipper and
our own reader, plus a structural lint of every archive (local vs central headers,
data descriptors, ZIP64 records, contiguous entries, extras):

  * every method (Store, Deflate, BZip2, LZMA+EOS, PPMd) at every level 1-9, level 0 =
    store, dictionary / model / block size overrides
  * ZipCrypto and WinZip AES-256 with ASCII and Korean passwords, wrong passwords
  * streaming output (sink without write_at): data descriptors, 8-byte descriptors
    for files larger than announced
  * incompressible files re-stored over their compressed data, also when the file
    changes between the two reads
  * legacy CP949 names (+ Info-ZIP Unicode Path extra) and their UTF-8 fallback
  * 70000 entries (ZIP64 end records); > 4 GiB files and offsets with GZ_TEST_SLOW=1
  * symlinks, empty files and folders, times (DOS/NTFS/UT), unix modes
  * read errors, abort, cancel, bad options, progress; in-process fuzzer (random
    items/options/failures, checked with our reader); our reader on damaged output
"""
import os, mmap, struct, shutil, subprocess, zipfile, zlib, random

ENV = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8", TZ="UTC")
# `gzt c` (tests/gzt.c) does not free its item list; our own driver is leak-free
NOLEAK = {"ASAN_OPTIONS": (os.environ.get("ASAN_OPTIONS", "") + ":detect_leaks=0").lstrip(":")}
SIG_L, SIG_C, SIG_D, SIG_E, SIG_E64, SIG_L64 = 0x04034b50, 0x02014b50, 0x08074b50, 0x06054b50, 0x06064b50, 0x07064b50
METHOD_NAMES = {0: "Store", 8: "Deflate", 12: "BZip2", 14: "LZMA", 98: "PPMd"}

try:
    import pyzipper
except Exception:                     # optional
    pyzipper = None


# ---------------------------------------------------------------- structure lint

def extras(b):
    out, p = [], 0
    while p + 4 <= len(b):
        i, n = struct.unpack_from("<HH", b, p)
        out.append((i, b[p + 4:p + 4 + n]))
        p += 4 + n
    return out, p == len(b)


def lint(path):
    """Parse the archive the way a strict reader would. Returns (problems, info)."""
    with open(path, "rb") as f:
        data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            return lint_data(data)
        finally:
            data.close()


def lint_data(data):
    P = []
    info = {"desc": 0, "desc64": 0, "zip64_eocd": False, "filler": 0, "entries": [], "local_z64": 0}
    e = data.rfind(struct.pack("<I", SIG_E))
    if e < 0 or e + 22 != len(data):
        return ["no end record at the very end"], info
    _, d0, d1, n1, n2, cds, cdo, cml = struct.unpack_from("<IHHHHIIH", data, e)
    if cml or d0 or d1 or n1 != n2:
        P.append("EOCD fields %r" % ((d0, d1, n1, n2, cml),))
    count = n1
    if e >= 20 and struct.unpack_from("<I", data, e - 20)[0] == SIG_L64:
        _, dk, z64off, ndisk = struct.unpack_from("<IIQI", data, e - 20)
        info["zip64_eocd"] = True
        if z64off + 56 != e - 20:
            P.append("ZIP64 end record not right before the locator")
        sig, sz, mb, vn, a, b, c1, c2, cds64, cdo64 = struct.unpack_from("<IQHHIIQQQQ", data, z64off)
        if sig != SIG_E64 or sz != 44 or a or b or c1 != c2 or ndisk != 1 or dk:
            P.append("bad ZIP64 end record")
        if n1 != 0xFFFF and n1 != c1:
            P.append("count mismatch %d/%d" % (n1, c1))
        if cds != 0xFFFFFFFF and cds != cds64 or cdo != 0xFFFFFFFF and cdo != cdo64:
            P.append("EOCD/ZIP64 directory mismatch")
        count, cds, cdo = c1, cds64, cdo64
        cd_end = z64off
    else:
        cd_end = e
        if n1 == 0xFFFF or cds == 0xFFFFFFFF or cdo == 0xFFFFFFFF:
            P.append("EOCD needs ZIP64 records")
    if cdo + cds != cd_end:
        P.append("directory not where the end record says (%d+%d != %d)" % (cdo, cds, cd_end))
    p, ents = cdo, []
    while p < cdo + cds:
        (sig, made, ver, fl, meth, tm, dt, crc, cs, us, nl, xl, cl, disk, ia, ea, off) = \
            struct.unpack_from("<IHHHHHHIIIHHHHHII", data, p)
        if sig != SIG_C:
            P.append("bad central signature at %d" % p)
            break
        name = data[p + 46:p + 46 + nl]
        xs, ok = extras(data[p + 46 + nl:p + 46 + nl + xl])
        if not ok or cl or disk or ia:
            P.append("central fields of %r" % name)
        ids = [i for i, _ in xs]
        if len(ids) != len(set(ids)):
            P.append("duplicate extras in %r" % name)
        xd = dict(xs)
        if 1 in xd:
            z, q = xd[1], 0
            want = (us == 0xFFFFFFFF) + (cs == 0xFFFFFFFF) + (off == 0xFFFFFFFF)
            if len(z) != 8 * want or not want:
                P.append("central ZIP64 extra size of %r" % name)
            if us == 0xFFFFFFFF: us = struct.unpack_from("<Q", z, q)[0]; q += 8
            if cs == 0xFFFFFFFF: cs = struct.unpack_from("<Q", z, q)[0]; q += 8
            if off == 0xFFFFFFFF: off = struct.unpack_from("<Q", z, q)[0]; q += 8
        elif 0xFFFFFFFF in (us, cs, off):
            P.append("0xFFFFFFFF without ZIP64 extra in %r" % name)
        if made >> 8 not in (0, 3) or (made & 0xFF) != 63:
            P.append("version made by %x" % made)
        ent = dict(name=name, flags=fl, method=meth, crc=crc, csize=cs, usize=us, off=off, ver=ver,
                   made=made, attr=ea, extra=xd, time=tm, date=dt)
        if meth == 99:
            a = xd.get(0x9901)
            if not a or len(a) != 7 or a[2:4] != b"AE" or a[4] != 3:
                P.append("AES extra of %r" % name)
            else:
                ent["aes_ver"], ent["real"] = struct.unpack_from("<H", a)[0], struct.unpack_from("<H", a, 5)[0]
                if ent["aes_ver"] == 2 and crc:
                    P.append("AE-2 with CRC in %r" % name)
                if not fl & 1:
                    P.append("AES without encryption flag")
        else:
            ent["real"] = meth
        if ent["real"] not in METHOD_NAMES:
            P.append("method %d" % ent["real"])
        if ent["real"] == 14 and not fl & 2:
            P.append("LZMA without EOS flag")
        if name.endswith(b"/") and (us or cs):
            P.append("directory with data %r" % name)
        ents.append(ent)
        p += 46 + nl + xl + cl
    if p != cdo + cds:
        P.append("directory size")
    if len(ents) != count:
        P.append("entry count %d != %d" % (len(ents), count))
    info["entries"] = ents
    # local headers, data, descriptors: contiguous from offset 0
    pos = 0
    for ent in sorted(ents, key=lambda x: x["off"]):
        if ent["off"] != pos:
            P.append("gap/overlap before %r (%d != %d)" % (ent["name"], ent["off"], pos))
        o = ent["off"]
        (sig, ver, fl, meth, tm, dt, crc, cs, us, nl, xl) = struct.unpack_from("<IHHHHHIIIHH", data, o)
        name = data[o + 30:o + 30 + nl]
        lx, ok = extras(data[o + 30 + nl:o + 30 + nl + xl])
        lxd = dict(lx)
        if sig != SIG_L or name != ent["name"] or not ok:
            P.append("local header of %r" % ent["name"]); pos = o; break
        if (ver, fl, meth, tm, dt) != (ent["ver"], ent["flags"], ent["method"], ent["time"], ent["date"]):
            P.append("local/central fields differ for %r" % name)
        desc = bool(fl & 8)
        z64 = 1 in lxd
        info["local_z64"] += z64
        if z64:
            if len(lxd[1]) != 16:
                P.append("local ZIP64 extra size")
            lus, lcs = struct.unpack_from("<QQ", lxd[1])
        if not desc:
            if z64:
                if (cs, us) != (0xFFFFFFFF, 0xFFFFFFFF): P.append("local ZIP64 without 0xFFFFFFFF")
                cs, us = lcs, lus
            if (crc, cs, us) != (ent["crc"], ent["csize"], ent["usize"]):
                P.append("local sizes/CRC of %r: %r vs %r" % (name, (crc, cs, us), (ent["crc"], ent["csize"], ent["usize"])))
        else:
            if crc or cs or us or (z64 and (lus or lcs)):
                P.append("descriptor entry with local values %r" % name)
        for k in (0x000A, 0x5455, 0x7075, 0x9901):
            if (k in lxd) != (k in ent["extra"]) or (k in (0x000A, 0x7075, 0x9901) and lxd.get(k) != ent["extra"].get(k)):
                P.append("extra %04x differs local/central in %r" % (k, name))
        end = o + 30 + nl + xl + ent["csize"]
        if desc:
            if z64:
                sig, dcrc, dcs, dus = struct.unpack_from("<IIQQ", data, end); end += 24; info["desc64"] += 1
            else:
                sig, dcrc, dcs, dus = struct.unpack_from("<IIII", data, end); end += 16
            info["desc"] += 1
            if sig != SIG_D or (dcrc, dcs, dus) != (ent["crc"], ent["csize"], ent["usize"]):
                P.append("data descriptor of %r" % name)
        ent["data"] = o + 30 + nl + xl
        ent["local_z64"] = z64
        pos = end
    if cdo < pos:
        P.append("directory overlaps data")
    elif cdo > pos:
        info["filler"] = cdo - pos
        if data[pos:cdo].strip(b"\0"):
            P.append("non-zero filler before the directory")
    return P, info


def rename_extra(data, old, new):
    """Give every extra field `old` of the local and central headers the id `new`."""
    b = bytearray(data)
    e = data.rfind(struct.pack("<I", SIG_E))
    cds, cdo = struct.unpack_from("<II", data, e + 12)
    heads = []
    p = cdo
    while p < cdo + cds:
        nl, xl, cl = struct.unpack_from("<HHH", data, p + 28)
        heads.append(p + 46 + nl)
        heads.append(None)
        off = struct.unpack_from("<I", data, p + 42)[0]
        lnl, lxl = struct.unpack_from("<HH", data, off + 26)
        heads[-1] = off + 30 + lnl
        for start, n in ((p + 46 + nl, xl), (off + 30 + lnl, lxl)):
            q = start
            while q + 4 <= start + n:
                i, sz = struct.unpack_from("<HH", b, q)
                if i == old:
                    struct.pack_into("<H", b, q, new)
                q += 4 + sz
        p += 46 + nl + xl + cl
    return bytes(b)


def lint_check(t, path, label, want_desc=None, want_filler=None):
    probs, info = lint(path)
    if want_desc is not None and info["desc"] != want_desc:
        probs.append("descriptors %d (want %d)" % (info["desc"], want_desc))
    if want_filler is not None and bool(info["filler"]) != want_filler:
        probs.append("filler %d" % info["filler"])
    t.record(not probs, "lint " + label, "; ".join(probs[:5]) or "%d entries, %d descriptors, filler %d" %
             (len(info["entries"]), info["desc"], info["filler"]))
    return info


# ---------------------------------------------------------------- reference tools

def tree_of(root):
    out = {}
    for dp, dns, fns in os.walk(root):
        rel = os.path.relpath(dp, root).replace(os.sep, "/")
        for d in dns:
            fp = os.path.join(dp, d)
            k = (rel + "/" + d if rel != "." else d)
            out[k] = ("link", os.readlink(fp)) if os.path.islink(fp) else None
        for f in fns:
            fp = os.path.join(dp, f)
            k = (rel + "/" + f if rel != "." else f)
            out[k] = ("link", os.readlink(fp)) if os.path.islink(fp) else open(fp, "rb").read()
    return out


def diff(got, want):
    bad = []
    for k, v in want.items():
        if k not in got:
            bad.append("missing " + k)
        elif got[k] != v:
            bad.append("differs " + k)
    for k in got:
        if k not in want:
            bad.append("extra " + k)
    return bad


def check_7z(t, arc, want, label, pw=None, extra=(), keep=False):
    r = subprocess.run(["7z", "t", arc, "-p" + (pw if pw is not None else "")] + list(extra),
                       capture_output=True, env=ENV, timeout=600)
    ok = r.returncode == 0 and b"Everything is Ok" in r.stdout
    if not ok:
        return t.record(False, "7z t " + label, (r.stdout + r.stderr).decode(errors="replace")[-400:])
    if want is None:
        return t.record(True, "7z t " + label)
    out = t.path("x7_" + os.path.basename(arc))
    shutil.rmtree(out, ignore_errors=True)
    r = subprocess.run(["7z", "x", "-y", "-o" + out, arc, "-p" + (pw if pw is not None else "")] + list(extra),
                       capture_output=True, env=ENV, timeout=600)
    bad = diff(tree_of(out), want)
    if not keep:
        shutil.rmtree(out, ignore_errors=True)        # the disk is shared with other test runs
    return t.record(r.returncode == 0 and not bad, "7z x " + label,
                    "; ".join(bad[:5]) + (r.stdout + r.stderr).decode(errors="replace")[-300:] * (r.returncode != 0))


def check_py(t, arc, want, label, pw=None):
    """zipfile (or pyzipper for AES); PPMd entries are only listed (no decoder). Python's
    ZipCrypto runs at ~2 MB/s: of big ZipCrypto entries only the head is compared (that
    still checks the password check byte and the start of the data)."""
    try:
        with zipfile.ZipFile(arc) as z:
            aes = any(i.compress_type == 99 for i in z.infolist())
        if aes and not pyzipper:
            return None
        Z = pyzipper.AESZipFile if aes else zipfile.ZipFile
        bad, got = [], {}
        with Z(arc) as z:
            if pw is not None:
                z.setpassword(pw.encode())
            for i in z.infolist():
                n = i.filename.rstrip("/")
                if i.is_dir():
                    got[n] = None
                    continue
                real = i.compress_type
                if real == 99:
                    a = dict(extras(i.extra)[0]).get(0x9901)
                    real = struct.unpack_from("<H", a, 5)[0]
                if real == 98:
                    d = want.get(n)
                elif i.flag_bits & 1 and i.compress_type != 99 and i.file_size > (1 << 20):
                    with z.open(i) as f:
                        head = f.read(65536)
                    w = want.get(n)
                    d = w if isinstance(w, bytes) and w[:65536] == head else head
                else:
                    d = z.read(i)
                if (i.external_attr >> 16) & 0o170000 == 0o120000:
                    d = ("link", d.decode())
                got[n] = d
        bad = diff(got, want)
        return t.record(not bad, ("pyzipper " if aes else "zipfile ") + label, "; ".join(bad[:5]))
    except Exception as ex:
        return t.record(False, "python " + label, "%s: %s" % (type(ex).__name__, ex))


def check_unzip(t, arc, label, pw=None):
    if not shutil.which("unzip"):
        return None
    with zipfile.ZipFile(arc) as z:
        if any(i.compress_type not in (0, 8, 12) for i in z.infolist()):
            return None               # Info-ZIP unzip 6: no LZMA, PPMd or AES
    r = subprocess.run(["unzip", "-t", "-P", pw or "", arc], capture_output=True, env=ENV, timeout=600)
    return t.record(r.returncode == 0, "unzip -t " + label, r.stdout.decode(errors="replace")[-300:] * (r.returncode != 0))


def check_own(t, arc, want, label, pw=None, acp=None):
    """Our reader (gzt x): entries whose method it lacks (GZ_E_METHOD = 5) are not counted."""
    r, rows, out = t.extract(arc, pw=pw, acp=acp)
    if r.returncode:
        return t.record(False, "own " + label, "gzt failed " + r.stdout.decode(errors="replace")[-200:])
    bad, checked, unsup = [], 0, 0
    names = set()
    for i, (st, isdir, size, name) in rows.items():
        names.add(name)
        w = want.get(name, "?")
        if w == "?":
            bad.append("extra " + name); continue
        if isdir or w is None:
            if not (isdir and w is None): bad.append("kind " + name)
            continue
        if st == 5:
            unsup += 1; continue
        d = open(os.path.join(out, "%d.bin" % i), "rb").read() if st == 0 else None
        if isinstance(w, tuple):
            w = w[1].encode()
        if st or d != w:
            bad.append("%s: st=%d" % (name, st))
        checked += 1
    for k in want:
        if k not in names:
            bad.append("missing " + k)
    shutil.rmtree(out, ignore_errors=True)
    if not checked and not bad:
        return None                    # nothing our reader can decode yet
    return t.record(not bad, "own " + label, "; ".join(bad[:5]) or "%d files (%d unsupported)" % (checked, unsup))


def check_all(t, arc, want, label, pw=None, sevenz=True, own=True, desc=None, filler=None):
    lint_check(t, arc, label, desc, filler)
    if sevenz:
        check_7z(t, arc, want, label, pw)
    check_py(t, arc, want, label, pw)
    check_unzip(t, arc, label, pw)
    if own:
        check_own(t, arc, want, label, pw)


# ---------------------------------------------------------------- data

def text(n, seed=1):
    rnd = random.Random(seed)
    words = ["고기", "삼겹살", "목살", "갈비", "zip", "archive", "hello", "world", "압축", "테스트", "\n"]
    out, size = [], 0
    while size < n:
        w = rnd.choice(words) + " "
        out.append(w)
        size += len(w.encode())
    return "".join(out).encode()[:n]


def noise(n, seed=2):
    return random.Random(seed).randbytes(n)


def drv(t, exe, args, env=None, timeout=900):
    e = dict(ENV)
    if env:
        e.update(env)
    r = subprocess.run([exe] + args, capture_output=True, env=e, timeout=timeout)
    return r, r.stdout.decode("utf-8", "replace")


def created(out):
    for line in out.splitlines():
        if line.startswith("CREATE "):
            return int(line.split()[1])
    return -1


def progress_ok(out):
    for line in out.splitlines():
        if line.startswith("PROGRESS "):
            _, done, total, calls, mono = line.split()
            return done == total and mono == "1" and int(calls) > 0
    return False


# ---------------------------------------------------------------- tests

def run(t):
    t.need("7z")
    exe = t.build_driver("tests/drivers/zip_write_drv.c")

    # ---- method x level matrix through gzt c (the engine's path) ----
    files = {
        "docs": None, "docs/readme.txt": text(150000), "docs/한글 이름.txt": ("한글 내용 " * 4000).encode(),
        "bin": None, "bin/random.bin": noise(120000), "bin/zeros.bin": b"\0" * 100000,
        "empty.txt": b"", "tiny.txt": b"hi!\n", "emptydir": None,
    }
    src = t.write_tree(t.path("src_matrix"), files)
    rels = sorted(files)
    want = dict(files)
    combos = [(1, 5, "store"), (0, 0, "level0")] + [(2, l, "deflate%d" % l) for l in range(1, 10)] + \
             [(m, l, "%s%d" % (n, l)) for m, n in ((4, "bzip2"), (5, "lzma"), (7, "ppmd")) for l in range(1, 10)]
    for m, lv, label in combos:
        arc = t.path("m_%s.zip" % label)
        if os.path.exists(arc):
            os.remove(arc)
        r = t.run_gzt(["c", "zip", arc, str(lv), "-", src] + rels, dict(NOLEAK, GZ_METHOD=str(m)))
        if not t.record(r.returncode == 0, "create " + label, r.stdout.decode(errors="replace")[-200:]):
            continue
        check_all(t, arc, want, label, desc=0)
        with zipfile.ZipFile(arc) as z:
            meth = {i.filename: i.compress_type for i in z.infolist()}
        expect = 0 if m == 1 or lv == 0 else {2: 8, 4: 12, 5: 14, 7: 98}[m]
        ok = meth["docs/readme.txt"] == expect and meth["bin/random.bin"] == 0 and meth["empty.txt"] == 0 \
            and meth["tiny.txt"] == 0
        t.record(ok, "methods chosen " + label, str(meth))
    # levels: higher Deflate levels are not larger on text
    sz = {l: os.path.getsize(t.path("m_deflate%d.zip" % l)) for l in (1, 6, 9)}
    t.record(sz[9] <= sz[6] and sz[9] < sz[1], "deflate level sizes", str(sz))

    # o->dict_size: LZMA dictionary, PPMd model size, BZip2 block size
    for meth, dsz, label in (("lzma", 65536, "LZMA dictionary 64 KiB"), ("ppmd", 2 << 20, "PPMd model 2 MiB"),
                             ("bzip2", 200000, "BZip2 blocks 200k")):
        arc = t.path("dict_%s.zip" % meth)
        r, out = drv(t, exe, ["c", "-m", meth, "-l", "9", "-d", str(dsz), arc, src, "docs/readme.txt"])
        if not t.record(created(out) == 0, "create " + label, out[-200:]):
            continue
        e = lint(arc)[1]["entries"][0]
        with open(arc, "rb") as f:
            f.seek(e["data"])
            head = f.read(16)
        if meth == "lzma":
            ok = head[:4] == b"\x09\x14\x05\x00" and struct.unpack_from("<I", head, 5)[0] == dsz
        elif meth == "ppmd":
            ok = ((struct.unpack_from("<H", head)[0] >> 4) & 0xFF) + 1 == dsz >> 20
        else:
            ok = head[:4] == b"BZh2"
        t.record(ok, label, head.hex())
        check_7z(t, arc, {"docs": None, "docs/readme.txt": files["docs/readme.txt"]}, label)

    # ---- encryption: ZipCrypto / AES, ASCII and Korean passwords ----
    for enc, encname in ((1, "zipcrypto"), (2, "aes")):
        for pw in ("secret", "고깃집 비번!"):
            for m, lv in ((2, 5), (0, 0), (5, 3)):
                if enc == 1 and m == 5:
                    continue
                label = "%s %s m%d L%d" % (encname, "kr" if pw != "secret" else "ascii", m, lv)
                arc = t.path("e_%s_%d_%d_%d.zip" % (encname, pw == "secret", m, lv))
                if os.path.exists(arc):
                    os.remove(arc)
                r = t.run_gzt(["c", "zip", arc, str(lv), pw, src] + rels, dict(NOLEAK, GZ_METHOD=str(m), GZ_ENC=str(enc)))
                if not t.record(r.returncode == 0, "create " + label, r.stdout.decode(errors="replace")[-200:]):
                    continue
                check_all(t, arc, want, label, pw=pw, desc=0)
                info = lint(arc)[1]
                encd = [e for e in info["entries"] if not e["name"].endswith(b"/")]
                ok = all(e["flags"] & 1 for e in encd) and not any(e["flags"] & 1 for e in info["entries"]
                                                                   if e["name"].endswith(b"/"))
                if enc == 2:
                    ok = ok and all(e["method"] == 99 for e in encd)
                    ok = ok and all(e["aes_ver"] == (2 if e["usize"] < 20 else 1) for e in encd)
                t.record(ok, "encryption flags " + label)
                r = subprocess.run(["7z", "t", "-pwrong", arc], capture_output=True, env=ENV)
                t.record(r.returncode != 0, "7z rejects wrong password " + label)
                r2, rows, out = t.extract(arc, pw="wrong")
                t.record(r2.returncode == 0 and all(st != 0 for (st, isdir, size, n) in rows.values()
                                                    if not isdir and size), "own reader rejects wrong password " + label)

    # ---- tree with symlinks, modes, times through the driver ----
    base = t.path("src_drv")
    shutil.rmtree(base, ignore_errors=True)
    tree = {"top": None, "top/a.txt": text(30000, 3), "top/run.sh": b"#!/bin/sh\necho hi\n", "top/secret": b"s3cr3t",
            "top/ro.txt": b"read only", "top/empty": b"", "top/sub": None, "top/sub/empty_dir": None,
            "top/sub/old.txt": b"old", "top/sub/future.txt": b"future", "top/큰파일.bin": noise(4400000, 7),
            "top/text_big.txt": text(4600000, 8)}
    t.write_tree(base, tree)
    os.symlink("a.txt", os.path.join(base, "top/link_a"))
    os.symlink("sub", os.path.join(base, "top/link_dir"))
    os.chmod(os.path.join(base, "top/run.sh"), 0o755)
    os.chmod(os.path.join(base, "top/secret"), 0o600)
    os.chmod(os.path.join(base, "top/ro.txt"), 0o444)
    T0 = 981173106                                           # 2001-02-03 04:05:06 UTC
    os.utime(os.path.join(base, "top/a.txt"), ns=(T0 * 10**9 + 789123400, T0 * 10**9 + 789123400))
    os.utime(os.path.join(base, "top/sub/old.txt"), ns=(157766400 * 10**9, 157766400 * 10**9))      # 1975
    os.utime(os.path.join(base, "top/sub/future.txt"), ns=(2240611200 * 10**9, 2240611200 * 10**9))  # 2041
    want_drv = {k: v for k, v in tree.items()}
    want_drv["top/link_a"] = ("link", "a.txt")
    want_drv["top/link_dir"] = ("link", "sub")
    rels = sorted(want_drv)
    for mode in ("", "-s"):
        for enc in ("none", "zc", "aes"):
            for meth in ("deflate", "lzma"):
                if enc == "zc" and meth == "lzma":
                    continue
                label = "drv %s %s%s" % (meth, enc, " stream" if mode else "")
                arc = t.path("d_%s_%s%s.zip" % (meth, enc, mode))
                pw = "pw 한글" if enc != "none" else None
                args = ["c", "-m", meth, "-l", "1", "-t"] + ([mode] if mode else []) + \
                       (["-e", enc, "-p", pw] if pw else []) + [arc, base] + rels
                r, out = drv(t, exe, args)
                if not t.record(r.returncode == 0 and created(out) == 0, "create " + label, out[-300:] + r.stderr.decode()[-300:]):
                    continue
                t.record(progress_ok(out), "progress " + label, out[-200:])
                # descriptors: streamed files (> 4 MiB) on pipes, and every streamed ZipCrypto file
                ndesc = 2 if mode or enc == "zc" else 0
                info = lint_check(t, arc, label, ndesc)
                check_7z(t, arc, want_drv, label, pw, keep=(mode == "" and enc == "none" and meth == "deflate"))
                check_py(t, arc, want_drv, label, pw)
                check_unzip(t, arc, label, pw)
                own_want = {k: (v[1].encode() if isinstance(v, tuple) else v) for k, v in want_drv.items()}
                check_own(t, arc, own_want, label, pw)
                if mode == "" and enc == "none":
                    big = [e for e in info["entries"] if e["name"] == "top/큰파일.bin".encode()][0]
                    t.record(big["real"] == 0 and big["csize"] == 4400000, "incompressible big file re-stored " + label,
                             "%d %d" % (big["real"], big["csize"]))
                if mode == "-s":
                    big = [e for e in info["entries"] if e["name"] == "top/큰파일.bin".encode()][0]
                    t.record(big["flags"] & 8 and big["real"] == {"deflate": 8, "lzma": 14}[meth],
                             "streamed big file keeps its method " + label)
                if arc != t.path("d_deflate_none.zip"):
                    os.remove(arc)
    # attributes, links, times (from the plain deflate archive)
    arc = t.path("d_deflate_none.zip")
    info = lint(arc)[1]
    ents = {e["name"].decode(): e for e in info["entries"]}
    modes = {k: e["attr"] >> 16 for k, e in ents.items()}
    ok = modes["top/run.sh"] == 0o100755 and modes["top/secret"] == 0o100600 and modes["top/ro.txt"] == 0o100444 \
        and modes["top/link_a"] == 0o120777 and modes["top/sub/"] == 0o040000 | (os.stat(os.path.join(base, "top/sub")).st_mode & 0o7777) \
        and all(e["made"] >> 8 == 3 for e in ents.values())
    ok = ok and ents["top/ro.txt"]["attr"] & 1 and ents["top/sub/"]["attr"] & 0x10 and not ents["top/a.txt"]["attr"] & 0x11
    t.record(ok, "unix modes + DOS attributes", str({k: oct(v) for k, v in modes.items()}))
    t.record(ents["top/link_a"]["real"] == 0 and ents["top/link_a"]["usize"] == 5, "symlink stored with target as data")

    def times(e):
        x = e["extra"]
        nt = x.get(0x000A)
        ut = x.get(0x5455)
        mt = struct.unpack_from("<Q", nt, 8)[0] if nt else None
        u = struct.unpack_from("<i", ut, 1)[0] if ut and len(ut) >= 5 else None
        d, tm = e["date"], e["time"]
        dos = (1980 + (d >> 9), (d >> 5) & 15, d & 31, tm >> 11, (tm >> 5) & 63, (tm & 31) * 2)
        return mt, u, dos
    mt, u, dos = times(ents["top/a.txt"])
    ft = (T0 + 11644473600) * 10**7 + 7891234
    t.record(mt == ft and u == T0 and dos == (2001, 2, 3, 4, 5, 8), "times: NTFS exact, UT, DOS (UTC, rounded up)",
             "%r %r %r" % (mt, u, dos))
    mt, u, dos = times(ents["top/sub/old.txt"])
    t.record(dos == (1980, 1, 1, 0, 0, 0) and u == 157766400 and mt == (157766400 + 11644473600) * 10**7,
             "times: before 1980 (DOS clamped)", "%r %r %r" % (mt, u, dos))
    mt, u, dos = times(ents["top/sub/future.txt"])
    t.record(u is None and mt == (2240611200 + 11644473600) * 10**7 and dos[0] == 2041,
             "times: after 2038 (no UT, NTFS kept)", "%r %r %r" % (mt, u, dos))
    ut_local = None
    with open(arc, "rb") as f:
        d = f.read()
        e = ents["top/a.txt"]
        nl, xl = struct.unpack_from("<HH", d, e["off"] + 26)
        lx = dict(extras(d[e["off"] + 30 + nl:e["off"] + 30 + nl + xl])[0])
        ut_local = lx.get(0x5455)
    t.record(ut_local is not None and ut_local[0] == 3 and len(ut_local) == 9, "UT local: mtime + atime")
    # 7-Zip restores the exact time from the NTFS extra
    out = t.path("x7_d_deflate_none.zip")
    st = os.stat(os.path.join(out, "top/a.txt"))
    t.record(st.st_mtime_ns // 100 == ft - (11644473600 * 10**7), "7z restores 100 ns mtime", str(st.st_mtime_ns))
    t.record(os.path.islink(os.path.join(out, "top/link_a")), "7z restores the symlink")

    # ---- files larger than announced (hints 0): local ZIP64 extra + 8-byte descriptors ----
    for mode in ("-s", ""):
        label = "hint 0%s" % (" stream" if mode else "")
        arc = t.path("h0%s.zip" % mode)
        r, out = drv(t, exe, ["c", "-H", "-m", "deflate", "-l", "1"] + ([mode] if mode else []) + [arc, base] + rels)
        if t.record(created(out) == 0, "create " + label, out[-300:]):
            info = lint_check(t, arc, label, 2 if mode else 0)
            t.record(info["local_z64"] == 2 and info["desc64"] == (2 if mode else 0), "local ZIP64 for unannounced sizes " + label,
                     "%d %d" % (info["local_z64"], info["desc64"]))
            check_7z(t, arc, want_drv, label)
            check_py(t, arc, want_drv, label)
            check_unzip(t, arc, label)
            os.remove(arc)

    # ---- re-store: gap reused by later entries / filler before the directory ----
    rs = t.write_tree(t.path("src_restore"), {"a_rand.bin": noise(4300000, 11), "b.txt": text(50000, 12),
                                              "c_rand.bin": noise(4250000, 13)})
    for meth, enc in (("deflate", "none"), ("deflate", "zc"), ("deflate", "aes"), ("bzip2", "none"),
                      ("lzma", "aes"), ("ppmd", "zc")):
        if True:
            label = "re-store %s %s" % (meth, enc)
            arc = t.path("rs_%s_%s.zip" % (meth, enc))
            pw = ["-e", enc, "-p", "x"] if enc != "none" else []
            r, out = drv(t, exe, ["c", "-m", meth, "-l", "1"] + pw + [arc, rs, "a_rand.bin", "b.txt", "c_rand.bin"])
            if not t.record(created(out) == 0, "create " + label, out[-300:]):
                continue
            info = lint_check(t, arc, label, 2 if enc == "zc" else 0)
            stored = [e["name"] for e in info["entries"] if e["real"] == 0]
            t.record(stored == [b"a_rand.bin", b"c_rand.bin"], "incompressible files stored " + label, str(stored))
            want_rs = {"a_rand.bin": noise(4300000, 11), "b.txt": text(50000, 12), "c_rand.bin": noise(4250000, 13)}
            if meth == "deflate" or enc == "zc":
                check_7z(t, arc, want_rs, label, "x" if pw else None)
                check_py(t, arc, want_rs, label, "x" if pw else None)
            else:
                check_7z(t, arc, None, label, "x" if pw else None)
            os.remove(arc)
    # the file changes between the two reads: the entry holds the second read
    arc = t.path("rs_changed.zip")
    r, out = drv(t, exe, ["c", "-m", "lzma", "-l", "1", "-G", "a_rand.bin", arc, rs, "a_rand.bin", "b.txt"])
    chg = bytearray(noise(4300000, 11))
    chg[0] ^= 0x5A
    if t.record(created(out) == 0, "create re-store of a changing file", out[-300:]):
        lint_check(t, arc, "re-store of a changing file")
        check_7z(t, arc, {"a_rand.bin": bytes(chg), "b.txt": text(50000, 12)}, "re-store of a changing file")
        os.remove(arc)

    # ---- legacy CP949 names ----
    names = {"plain.txt": b"a", "한글.txt": b"b", "폴더": None, "폴더/문서 파일.txt": b"c", "日本語.txt": b"d",
             "Āmoji 😀.txt": b"e"}
    lsrc = t.write_tree(t.path("src_legacy"), names)
    for legacy in (True, False):
        label = "names %s" % ("legacy cp949" if legacy else "utf-8")
        arc = t.path("names_%d.zip" % legacy)
        r, out = drv(t, exe, ["c"] + (["-L"] if legacy else []) + [arc, lsrc] + sorted(names), {"GZ_TEST_ACP": "949"})
        if not t.record(created(out) == 0, "create " + label, out[-300:]):
            continue
        lint_check(t, arc, label)
        bad = []
        for i in lint(arc)[1]["entries"]:            # raw names (zipfile applies 0x7075 itself)
            utf = bool(i["flags"] & 0x800)
            raw, xd = i["name"], i["extra"]
            if utf:
                n = raw.decode().rstrip("/")
                if legacy and n != "Āmoji 😀.txt":
                    bad.append("utf-8 " + n)
                if 0x7075 in xd:
                    bad.append("unicode extra with flag " + n)
                if n not in names:
                    bad.append("name " + n)
                continue
            if True:
                try:
                    dec = raw.decode("cp949").rstrip("/")
                except UnicodeDecodeError:
                    bad.append("not cp949 %r" % raw); continue
                if dec not in names:
                    bad.append("name %r" % dec)
                if dec != "plain.txt" and not legacy:
                    bad.append("legacy without -L " + dec)
                if not raw.isascii():
                    u = xd.get(0x7075)
                    if not u or u[0] != 1 or struct.unpack_from("<I", u, 1)[0] != zlib.crc32(raw) or \
                            u[5:].decode().rstrip("/") != dec:
                        bad.append("unicode path extra " + dec)
        t.record(not bad, "raw names " + label, "; ".join(bad[:5]))
        check_7z(t, arc, names, label + " (7z, Unicode Path extra)")
        t.check_extract(arc, names, acp=949, label="own reader " + label + " (acp 949)")
    # the names alone (no Unicode Path extra): 7z with -mcp=949 must see CP949 bytes
    arc2 = t.path("names_nounicode.zip")
    open(arc2, "wb").write(rename_extra(open(t.path("names_1.zip"), "rb").read(), 0x7075, 0x9999))
    # (7-Zip for Linux ignores -mcp: it relies on the Unicode Path extra, checked above)
    want_names = sorted(k + "/" if v is None else k for k, v in names.items())
    with zipfile.ZipFile(arc2, metadata_encoding="cp949") as z:
        t.record(sorted(z.namelist()) == want_names, "zipfile cp949: legacy names without Unicode Path",
                 str(z.namelist()))
    if shutil.which("lsar"):
        r = subprocess.run(["lsar", "-e", "cp949", arc2], capture_output=True, env=ENV)
        got = sorted(r.stdout.decode(errors="replace").splitlines()[1:])
        t.record(got == want_names, "lsar -e cp949: legacy names without Unicode Path", str(got))
    t.check_extract(arc2, names, acp=949, label="own reader: legacy names without Unicode Path (acp 949)")

    # ---- 70000 entries: ZIP64 end records ----
    arc = t.path("many.zip")
    r, out = drv(t, exe, ["many", arc, "70000"])
    if t.record(created(out) == 0, "create 70000 entries", out[-300:]):
        info = lint_check(t, arc, "70000 entries")
        t.record(info["zip64_eocd"] and len(info["entries"]) == 70070, "ZIP64 end record for 70070 entries")
        check_7z(t, arc, None, "70000 entries")
        with zipfile.ZipFile(arc) as z:
            il = z.infolist()
            ok = len(il) == 70070 and z.read("d069/f069999.txt") == z.read(il[-1]) and len(z.read(il[-1])) == 69999 % 7
            t.record(ok and z.testzip() is None, "zipfile reads 70070 entries")
        check_unzip(t, arc, "70000 entries")
        r2, typ, rows = t.listing(arc)
        t.record(typ == "ZIP" and len(rows) == 70070, "own reader lists 70070 entries", str(len(rows)))
        os.remove(arc)

    # ---- errors, cancel, options ----
    esrc = t.write_tree(t.path("src_err"), {"small.txt": text(5000, 21), "big.txt": text(6 << 20, 22), "ok.txt": b"fine"})
    erels = ["small.txt", "big.txt", "ok.txt"]
    arc = t.path("err_small.zip")
    r, out = drv(t, exe, ["c", "-E", "small.txt:100", arc, esrc] + erels)
    t.record(created(out) == 0 and "ONERR small.txt 1" in out, "read error in a small file: reported, skipped", out[-200:])
    check_7z(t, arc, {"big.txt": text(6 << 20, 22), "ok.txt": b"fine"}, "read error in a small file")
    arc = t.path("err_big.zip")
    r, out = drv(t, exe, ["c", "-E", "big.txt:1000000", arc, esrc] + erels)
    t.record(created(out) == 0 and "ONERR big.txt 1" in out, "read error in a streamed file: reported", out[-200:])
    lint_check(t, arc, "read error in a streamed file")
    check_7z(t, arc, {"small.txt": text(5000, 21), "big.txt": text(6 << 20, 22)[:1000000], "ok.txt": b"fine"},
             "read error in a streamed file (partial entry)")
    r, out = drv(t, exe, ["c", "-a", "-E", "small.txt:0", t.path("err_abort.zip"), esrc] + erels)
    t.record(created(out) == 1, "on_error abort stops the job", out[-200:])
    r, out = drv(t, exe, ["c", "-c", "2000000", t.path("cancel.zip"), esrc] + erels)
    t.record(created(out) == 8, "cancel", out[-200:])
    r, out = drv(t, exe, ["c", "-e", "zc", t.path("nopw.zip"), esrc] + erels)
    t.record(created(out) == 6, "encryption without password", out[-200:])
    r, out = drv(t, exe, ["c", "-m", "deflate64", t.path("d64.zip"), esrc] + erels)
    t.record(created(out) == 5, "unsupported method", out[-200:])
    arc = t.path("empty_archive.zip")
    r, out = drv(t, exe, ["c", arc, esrc])
    if t.record(created(out) == 0 and os.path.getsize(arc) == 22, "empty archive = end record only"):
        check_7z(t, arc, None, "empty archive")
        with zipfile.ZipFile(arc) as z:
            t.record(z.namelist() == [], "zipfile opens the empty archive")

    # ---- in-process fuzzer: random items, options, read errors, changing files, failing sinks ----
    iters = int(os.environ.get("GZ_FUZZ_ITERS", "60"))
    for seed in (1, 2):
        r, out = drv(t, exe, ["fuzz", str(seed), str(iters)], timeout=1800)
        err = r.stderr.decode(errors="replace")
        t.record(r.returncode == 0 and "bad=0" in out and "Sanitizer" not in err and "runtime error" not in err,
                 "fuzz seed %d x%d" % (seed, iters), (out[-400:] + err[-400:]).strip())

    # ---- our reader on damaged writer output ----
    rnd = random.Random(5)
    for name in ("m_deflate5.zip", "e_aes_1_2_5.zip", "e_zipcrypto_0_2_5.zip", "names_1.zip", "dict_lzma.zip"):
        p = t.path(name)
        if not os.path.exists(p):
            continue
        d = open(p, "rb").read()
        for k in range(6):
            b = bytearray(d)
            if k == 0:
                b = b[:rnd.randrange(len(b))]
            else:
                for _ in range(rnd.randrange(1, 8)):
                    b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
            hp = t.path("hostile_%s_%d.zip" % (name[:-4], k))
            open(hp, "wb").write(bytes(b))
            t.check_hostile(hp, pw="secret")

    for name in ("err_small.zip", "err_big.zip", "d_deflate_none.zip"):
        if os.path.exists(t.path(name)):
            os.remove(t.path(name))
    shutil.rmtree(t.path("x7_d_deflate_none.zip"), ignore_errors=True)
    shutil.rmtree(t.path("src_drv"), ignore_errors=True)
    shutil.rmtree(t.path("src_restore"), ignore_errors=True)
    shutil.rmtree(t.path("src_err"), ignore_errors=True)

    # ---- > 4 GiB (GZ_TEST_SLOW=1): ZIP64 sizes, offsets and descriptors ----
    if not os.environ.get("GZ_TEST_SLOW"):
        return
    size = (4 << 30) + 123457
    for label, args in (("deflate", ["-l", "1"]), ("store", ["-l", "0"]), ("store stream", ["-l", "0", "-s"])):
        arc = t.path("big_%s.zip" % label.replace(" ", "_"))
        r, out = drv(t, exe, ["big"] + args + [arc, str(size), "3"], timeout=3600)
        if not t.record(created(out) == 0, "create > 4 GiB " + label, out[-300:]):
            continue
        info = lint_check(t, arc, "> 4 GiB " + label, 1 if "stream" in label else 0)
        ents = {e["name"]: e for e in info["entries"]}
        big = ents[b"huge.bin"]
        ok = big["usize"] == size and big["local_z64"] and 1 in big["extra"]
        if "store" in label:
            ok = ok and ents[b"after3.txt"]["off"] > (4 << 30) and info["zip64_eocd"]
        t.record(ok, "ZIP64 fields > 4 GiB " + label)
        check_7z(t, arc, None, "> 4 GiB " + label)
        crc0 = [l.split()[2] for l in out.splitlines() if l.startswith("ITEM0 ")]
        r, vout = drv(t, exe, ["verify", arc], timeout=3600)
        rows = [l.split("\t") for l in vout.splitlines() if l[:1].isdigit()]
        ok = len(rows) == 4 and all(x[1] == "0" for x in rows) and int(rows[0][2]) == size and [rows[0][3]] == crc0
        t.record(ok, "own reader > 4 GiB " + label, vout[-300:])
        with zipfile.ZipFile(arc) as z:
            ok = z.getinfo("huge.bin").file_size == size and z.getinfo("huge.bin").CRC == int(crc0[0], 16)
            ok = ok and [len(z.read("after%d.txt" % k)) for k in (1, 2, 3)] == [1000, 2000, 3000]
            t.record(ok, "zipfile > 4 GiB " + label)
        os.remove(arc)
