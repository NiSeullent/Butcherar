"""ALZ and EGG (ESTsoft ALZip) readers, the AZO decoder and LEA.

Archives are written at test time by tests/cases/_alzegg.py (no tool creates
them on Linux; ALZip itself is not run). Independent checks:
  * The Unarchiver (unar/lsar) reads ALZ store/deflate/obfuscated deflate and split
    sets; unalz (apt) reads ALZ store/deflate and ZipCrypto (Debian links it against
    the system libbz2, which breaks its ALZ bzip2 variant, so bzip2 is not compared)
  * a real ALZip archive (t.alz from the patool test data, downloaded from PyPI at
    test time; skipped offline) and the EGG specification's own example archives
  * LEA test vectors from KS X 3246, AZO streams decoded by the C driver
"""
import os, random, shutil, struct, subprocess, sys, zlib, unicodedata

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _alzegg as A

ST_OK, ST_CRC, ST_PASSWORD, ST_AUTH, ST_VOLUME = 0, 4, 6, 12, 14


def wr(t, name, data):
    p = t.path(name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def text(n, seed=0):
    rng = random.Random(seed)
    words = ["다람쥐", "헌", "쳇바퀴에", "타고파", "the", "quick", "brown", "fox", "jumps", "가나다", "0123"]
    out, have = [], 0
    while have < n:
        w = (rng.choice(words) + (" " if rng.random() < 0.9 else "\n")).encode("utf-8")
        out.append(w)
        have += len(w)
    return b"".join(out)[:n]


def blob(n, seed=1):
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(n))


def x86ish(n, seed=2):
    """code-like bytes with E8/E9 calls whose targets look like rel32"""
    rng = random.Random(seed)
    b = bytearray()
    while len(b) < n:
        r = rng.random()
        if r < 0.15:
            b += bytes([0xE8]) + struct.pack("<i", rng.randrange(-5000, 5000))
        elif r < 0.2:
            b += bytes([0xE9]) + struct.pack("<i", rng.randrange(-300, 300))
        else:
            b += bytes(rng.choice([[0x55], [0x8B, 0xEC], [0x83, 0xC4, 0x08], [0x90], [0xC3], [0x6A, 0x00]]))
    return bytes(b[:n])


def drv_run(t, drv, args, timeout=300):
    return subprocess.run([drv] + args, capture_output=True, timeout=timeout)


def drv_rows(out):
    rows = {}
    for line in out.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if len(p) == 5 and p[0].isdigit():
            rows[int(p[0])] = (int(p[1]), p[4])
    return rows


def statuses(t, arc, pw=None, acp=None):
    r, rows, out = t.extract(arc, pw=pw, acp=acp)
    return {v[3]: v[0] for v in rows.values()}, rows, out


# ------------------------------------------------------------------ ALZ

def alz_corpus():
    t1 = text(7000, 1)
    b1 = blob(3000, 2) * 20 + text(5000, 3)
    files = [("폴더\\", None),
             ("폴더\\한글 이름.txt", t1),
             ("store.bin", b1[:4000]),
             ("bzip2.bin", b1),
             ("obfuscated.txt", t1 * 2),
             ("deflate.bin", b1),
             ("empty.txt", b""),
             ("하위\\깊은\\파일.dat", blob(70000, 9))]
    return files


def alz_records(files, methods=None, pw=None, widths=None):
    meth = {"store.bin": 0, "bzip2.bin": 1, "obfuscated.txt": 3, "empty.txt": 0}
    recs = []
    rng = random.Random(4)
    for i, (n, d) in enumerate(files):
        m = (methods or {}).get(n, meth.get(n, 2))
        recs.append(A.alz_entry(n.encode("cp949"), d, method=m, pw=pw if d is not None else None,
                                width=(widths or {}).get(n), rng=rng))
    return recs


def expected(files):
    return {n.replace("\\", "/"): d for n, d in files}


def section_alz_basic(t):
    files = alz_corpus()
    arc = wr(t, "alz/basic.alz", A.alz_archive(alz_records(files)))
    t.check_extract(arc, expected(files), acp=949, label="ALZ store/deflate/bzip2 (DLZ)/obfuscated, CP949 names",
                    expect_type="ALZ")
    # every size field width
    for w in (1, 2, 4, 8):
        d = text(200 if w == 1 else 3000, w)
        a = wr(t, "alz/width%d.alz" % w, A.alz_archive([A.alz_entry(b"w.txt", d, method=2 if w > 1 else 0, width=w)]))
        t.check_extract(a, {"w.txt": d}, label="ALZ %d-byte size fields" % w)
    # standard bzip2 framing under method 1 and a multi-block DLZ stream
    big = text(1500000, 5)
    a = wr(t, "alz/bz.alz", A.alz_archive([
        A.alz_entry(b"std.txt", big[:100000], method=1, comp=__import__("bz2").compress(big[:100000])),
        A.alz_entry(b"multi.txt", big, method=1, comp=A.alz_bzip2(big, chunk=400000))]))
    t.check_extract(a, {"std.txt": big[:100000], "multi.txt": big}, label="ALZ bzip2: BZh stream and 4 DLZ blocks")
    # method listing
    r, typ, rows = t.listing(arc, cp=949)
    m = {x["name"]: x["method"] for x in rows}
    t.record(m.get("bzip2.bin") == "BZip2" and m.get("obfuscated.txt") == "Obfuscated Deflate" and
             m.get("store.bin") == "Store" and typ == "ALZ", "ALZ method names", str(m))
    # The Unarchiver: everything but the DLZ bzip2 entry
    if t.tool("unar"):
        ref = os.path.join(t.work, "alz/unar_basic")
        shutil.rmtree(ref, ignore_errors=True)
        sub = [f for f in files if f[0] != "bzip2.bin"]
        a2 = wr(t, "alz/unar.alz", A.alz_archive(alz_records(sub)))
        rr = t.sh(["unar", "-q", "-f", "-D", "-e", "cp949", "-o", ref, a2], check=False)
        got = t.read_tree(ref)
        want = {k: v for k, v in expected(sub).items() if v is not None}
        t.record(rr.returncode == 0 and got == want, "ALZ: The Unarchiver extracts the same (incl. obfuscated deflate)",
                 "rc=%d %s" % (rr.returncode, sorted(set(got) ^ set(want))))
        t.check_extract(a2, got, acp=949, label="ALZ vs The Unarchiver", allow_extra=True)
    if t.tool("unalz"):
        sub = [f for f in files if f[0] not in ("bzip2.bin", "obfuscated.txt")]
        a3 = wr(t, "alz/unalz.alz", A.alz_archive(alz_records(sub)))
        ref = os.path.join(t.work, "alz/unalz_basic")
        shutil.rmtree(ref, ignore_errors=True)
        os.makedirs(ref)
        rr = t.sh(["unalz", "-utf8", "-d", ref, a3], check=False)
        got = {k: v for k, v in t.read_tree(ref).items() if v or k == "empty.txt"}
        want = {k: v for k, v in expected(sub).items() if v is not None}
        t.record(got == want, "ALZ: unalz extracts the same", "rc=%d %s" % (rr.returncode, sorted(set(got) ^ set(want))))


def section_alz_crypto(t):
    files = [("a.txt", text(9000, 7)), ("b.bin", blob(5000, 8)), ("c.txt", text(30000, 9)), ("d", None)]
    for label, pw, enc in [("ASCII", "secret", b"secret"), ("Korean CP949", "비밀번호", "비밀번호".encode("cp949")),
                           ("Korean UTF-8", "암호123", "암호123".encode("utf-8"))]:
        recs = [A.alz_entry(n.encode(), d, method=(0 if n == "b.bin" else 1 if n == "c.txt" else 2),
                            pw=enc if d is not None else None, rng=random.Random(len(n))) for n, d in files]
        arc = wr(t, "alz/enc_%d.alz" % len(enc), A.alz_archive(recs))
        t.check_extract(arc, expected(files), pw=pw, label="ALZ ZipCrypto, %s password" % label)
        st, rows, out = statuses(t, arc, pw="wrong" + pw)
        t.record(st.get("a.txt") == ST_PASSWORD and st.get("b.bin") == ST_PASSWORD and st.get("d") == 0,
                 "ALZ ZipCrypto %s: wrong password reported" % label, str(st))
        if label == "ASCII" and t.tool("unalz"):
            sub = [f for f in files if f[0] != "c.txt"]
            recs = [A.alz_entry(n.encode(), d, method=0 if n == "b.bin" else 2, pw=enc if d is not None else None)
                    for n, d in sub]
            a2 = wr(t, "alz/enc_unalz.alz", A.alz_archive(recs))
            ref = os.path.join(t.work, "alz/unalz_enc")
            shutil.rmtree(ref, ignore_errors=True)
            os.makedirs(ref)
            t.sh(["unalz", "-pwd", pw, "-d", ref, a2], check=False)
            got = {k: v for k, v in t.read_tree(ref).items() if v}
            t.record(got == {k: v for k, v in expected(sub).items() if v}, "ALZ ZipCrypto: unalz agrees", str(sorted(got)))
    # check byte from the DOS time (descriptor bit 3, as unalz accepts)
    d = text(4000, 11)
    zc, hdr = A.zc_header(b"pw", A.DOS_TIME >> 8, random.Random(3))
    comp = zc.encrypt(A.deflate_raw(d))
    rec = (b"BLZ\x01" + struct.pack("<HBIBB", 5, 0x20, A.DOS_TIME, 0x29, 0) + struct.pack("<BBI", 2, 0, zlib.crc32(d)) +
           struct.pack("<HH", len(comp), len(d)) + b"x.txt" + hdr + comp)
    arc = wr(t, "alz/enc_time.alz", A.alz_archive([rec]))
    t.check_extract(arc, {"x.txt": d}, pw="pw", label="ALZ ZipCrypto with the time check byte (descriptor bit 3)")


def section_alz_volumes(t):
    files = alz_corpus()
    stream = A.alz_archive(alz_records(files))
    vols = A.alz_split(stream, 9000)
    names = A.alz_vol_names(t.path("alz/vol/set"), len(vols))
    for nm, v in zip(names, vols):
        wr(t, os.path.relpath(nm, t.work), v)
    exp = expected(files)
    t.check_extract(names[0], exp, acp=949, label="ALZ split set (%d volumes) from .alz" % len(vols))
    t.check_extract(names[2], exp, acp=949, label="ALZ split set opened at .a01")
    # The Unarchiver joins the volumes the same way
    if t.tool("unar"):
        ref = os.path.join(t.work, "alz/unar_vol")
        shutil.rmtree(ref, ignore_errors=True)
        rr = t.sh(["unar", "-q", "-f", "-D", "-e", "cp949", "-o", ref, names[0]], check=False)
        got = t.read_tree(ref)
        want = {k: v for k, v in exp.items() if v is not None and k != "bzip2.bin"}
        t.record(all(got.get(k) == v for k, v in want.items()), "ALZ split set: The Unarchiver agrees",
                 "rc=%d missing %s" % (rr.returncode, sorted(k for k in want if got.get(k) != want[k])))
    # upper-case names
    up = [os.path.join(os.path.dirname(n), os.path.basename(n).upper()) for n in names]
    for nm, v in zip(up, vols):
        wr(t, os.path.relpath(nm.replace("vol" + os.sep, "volup" + os.sep), t.work), v)
    t.check_extract(up[0].replace("vol" + os.sep, "volup" + os.sep), exp, acp=949, label="ALZ split set, .ALZ/.A00 names")
    # a missing middle volume: what lies before it is listed and extracts
    miss = t.path("alz/miss/set.alz")
    for k, (nm, v) in enumerate(zip(A.alz_vol_names(miss[:-4], len(vols)), vols)):
        if k != 3:
            wr(t, os.path.relpath(nm, t.work), v)
    st, rows, out = statuses(t, miss, acp=949)
    first = files[1][0].replace("\\", "/")
    t.record(st.get(first) == 0 and (any(v == ST_VOLUME for v in st.values()) or len(st) < len(files)),
             "ALZ split set with a missing volume", str(st))


def section_alz_misc(t):
    d = text(5000, 12)
    arc = wr(t, "alz/comment.alz", A.alz_archive([A.alz_entry(b"a.txt", d)], comment="압축 주석입니다".encode("cp949"),
                                                  file_comments={0: "파일 주석".encode("cp949")}))
    r, rows, out = t.extract(arc, acp=949)
    err = r.stderr.decode("utf-8", "replace")
    t.record(rows.get(0, (1,))[0] == 0 and "comment: 압축 주석입니다" in err, "ALZ archive comment (ELZ section)", err[-200:])
    # a cut archive keeps the complete entries
    files = alz_corpus()
    s = A.alz_archive(alz_records(files))
    cut = wr(t, "alz/cut.alz", s[:len(s) * 2 // 3])
    st, rows, out = statuses(t, cut, acp=949)
    t.record(st.get("폴더/한글 이름.txt") == 0 and any(v not in (0, -1) for v in st.values()),
             "ALZ cut short: complete entries extract", str(st))
    # an .a00 volume opened on its own (first volume missing)
    vols = A.alz_split(s, 9000)
    p = wr(t, "alz/lone/x.a00", vols[1])
    r, rows, out = t.extract(p)
    t.record(r.returncode in (0, 1) and not rows, "ALZ: a lone continuation volume is refused", r.stdout.decode()[:100])


def fetch(t, url, name):
    import urllib.request
    p = os.path.join(t.work, "dl", name)
    if os.path.exists(p) and os.path.getsize(p):
        return p
    os.makedirs(os.path.dirname(p), exist_ok=True)
    try:
        d = urllib.request.urlopen(url, timeout=30).read()
    except Exception:
        return None
    with open(p + ".part", "wb") as f:
        f.write(d)
    os.replace(p + ".part", p)
    return p


PATOOL = "https://files.pythonhosted.org/packages/1a/3c/328a6a4e3da061efbd8d69e6b8d7cd5ee37877f9782c68e5b370f4a10dbf/patool-4.1.0.tar.gz"


def section_alz_real(t):
    """t.alz / t.alz.foo from the patool 4.1.0 sdist (GPL-3; downloaded, not committed)"""
    import tarfile
    sd = fetch(t, PATOOL, "patool-4.1.0.tar.gz")
    if not sd:
        return
    got = 0
    with tarfile.open(sd) as tf:
        for m in ("patool-4.1.0/tests/data/t.alz", "patool-4.1.0/tests/data/t.alz.foo"):
            try:
                data = tf.extractfile(m).read()
            except Exception:
                continue
            p = wr(t, "real/" + os.path.basename(m).replace(".foo", "2.alz"), data)
            st, rows, out = statuses(t, p)
            ok = rows and all(v[0] == 0 for v in rows.values())
            if ok and t.tool("lsar"):
                ref = os.path.join(t.work, "real/unar_" + os.path.basename(p))
                shutil.rmtree(ref, ignore_errors=True)
                t.sh(["unar", "-q", "-f", "-D", "-o", ref, p], check=False)
                exp = t.read_tree(ref)
                t.check_extract(p, exp, label="real ALZip archive %s vs The Unarchiver" % os.path.basename(m))
            t.record(ok, "real ALZip archive %s (patool test data)" % os.path.basename(m), str(rows))
            got += 1


# ------------------------------------------------------------------ EGG

def section_egg_spec(t):
    t.check_extract(wr(t, "egg/spec_simple.egg", A.spec_simple()), {"0": b"hello"},
                    label="EGG spec example: simple archive (no file name)", expect_type="EGG")
    t.check_extract(wr(t, "egg/spec_general.egg", A.spec_general()), {"hello.txt": b"hello"},
                    label="EGG spec example: general archive")
    t.check_extract(wr(t, "egg/spec_solid.egg", A.spec_solid()), {"a.txt": b"a", "b.txt": b"bc"},
                    label="EGG spec example: solid archive")
    r, typ, rows = t.listing(t.path("egg/spec_general.egg"))
    t.record(typ == "EGG" and rows and rows[0]["usize"] == 5, "EGG listing", str(rows))


def egg_corpus():
    t1, t2 = text(40000, 21), text(9000, 22)
    b1 = blob(6000, 23) + t2
    return t1, t2, b1


def section_egg_methods(t):
    t1, t2, b1 = egg_corpus()
    e = A.Egg()
    e.add("dir", None)
    e.add("dir/store.txt", t2, method="store")
    e.add("dir/deflate.txt", t1, method="deflate")
    e.add("bzip2.txt", t1, method="bzip2")
    e.add("lzma.txt", t1, method="lzma")
    e.add("azo.txt", t1, method="azo")
    e.add("azo-x86.bin", x86ish(30000), method="azo-x86")
    e.add("multi.bin", b1 * 3, method="deflate", blocks=[1000, 5000, len(b1) * 3 - 6000])
    e.add("multi-azo.txt", t2 * 2, method="azo", blocks=[7000, len(t2) * 2 - 7000])
    e.add("empty.txt", b"", method="store")
    e.add("한글 파일.txt", t2, method="deflate")
    e.add("cp949 이름.txt", b"cp949\n", method="store", locale=949)
    e.add("日本語.txt", b"sjis\n", method="store", locale=932)
    e.add("sys.txt", b"system locale\n", method="store", locale=0, raw_name=b"sys.txt")
    p = e.add("parent", None)
    c = e.add("child", None, parent=p.fid)
    e.add("leaf.txt", b"leaf\n", method="store", parent=c.fid)
    e.add("unix.sh", b"#!/bin/sh\n", method="store", win=False, posix=(0o100755, 1714570000))
    e.add("udir", None, win=False, posix=(0o040755, 1714570000))
    e.add("dummy.txt", b"after a dummy field\n", method="store", extra=A.field("DUMMY", b"\0" * 8) + A.field("SKIP", b"zz"))
    e.add("nfd.txt", unicodedata.normalize("NFD", "한글").encode() + b"\n", method="store")
    e.comment = "아카이브 주석".encode()
    arc = wr(t, "egg/methods.egg", e.build())
    exp = {f.name if f.parent is None else None: f.data for f in e.files if f.parent is None}
    exp.update({"parent/child": None, "parent/child/leaf.txt": b"leaf\n"})
    exp.pop(None, None)
    t.check_extract(arc, exp, label="EGG store/deflate/bzip2/LZMA/AZO(+x86), multi-block, names, relative paths",
                    expect_type="EGG")
    r, rows, out = t.extract(arc)
    t.record("comment: 아카이브 주석" in r.stderr.decode("utf-8", "replace"), "EGG archive comment")
    r, typ, rows = t.listing(arc)
    by = {x["name"]: x for x in rows}
    t.record(by.get("unix.sh", {}).get("mode") == 0o100755 and by.get("udir", {}).get("is_dir") == 1 and
             by.get("azo.txt", {}).get("method") == "AZO" and by.get("lzma.txt", {}).get("method") == "LZMA",
             "EGG listing: POSIX mode, POSIX directory, method names",
             str({k: (v["mode"], v["method"]) for k, v in by.items()})[:300])
    # a bigger AZO file (several AZO blocks per EGG block, stored and coded blocks)
    big = text(200000, 31) + blob(20000, 32) + bytes(30000)
    e = A.Egg()
    e.add("big.bin", big, method="azo")
    arc = wr(t, "egg/azo_big.egg", e.build())
    t.check_extract(arc, {"big.bin": big}, label="EGG AZO 250 KB (text, random, zeros)")


def section_egg_crypto(t):
    t1, t2, b1 = egg_corpus()
    kinds = ["zip", "aes128", "aes256", "lea128", "lea256"] if A.have_aes() else ["zip", "lea128", "lea256"]
    for kind in kinds:
        for label, pw, enc in [("ASCII", "secret", b"secret"), ("Korean", "비밀번호", "비밀번호".encode())]:
            e = A.Egg(seed=len(kind) + len(enc))
            e.add("a.txt", t1, method="deflate", enc=kind, pw=enc)
            e.add("b.bin", b1, method="store", enc=kind, pw=enc)
            e.add("c.txt", t2, method="lzma", enc=kind, pw=enc)
            e.add("d.txt", t2, method="lzma", enc=kind, pw=enc, lzma_enc_header=True)
            e.add("e.txt", t1, method="bzip2", enc=kind, pw=enc, blocks=[10000, len(t1) - 10000])
            e.add("f.txt", t2, method="azo", enc=kind, pw=enc)
            e.add("plain.txt", t2, method="deflate")
            arc = wr(t, "egg/enc_%s_%d.egg" % (kind, len(enc)), e.build())
            exp = {f.name: f.data for f in e.files}
            t.check_extract(arc, exp, pw=pw, label="EGG %s, %s password (deflate/store/LZMA x2/bzip2 x2 blocks/AZO)" %
                            (kind, label))
        st, rows, out = statuses(t, arc, pw="nope")
        t.record(all(st.get(n) == ST_PASSWORD for n in "a.txt b.bin c.txt e.txt".split()) and st.get("plain.txt") == 0,
                 "EGG %s: wrong password" % kind, str(st))
        if kind != "zip":
            # authentication code: flip one encrypted byte
            data = bytearray(open(arc, "rb").read())
            off = data.find(t2[:0] + b"#") if False else None
            e2 = A.Egg(seed=5)
            e2.add("x.bin", b1, method="store", enc=kind, pw=b"k")
            raw = bytearray(e2.build())
            raw[-20] ^= 0x40
            p = wr(t, "egg/tamper_%s.egg" % kind, bytes(raw))
            st, rows, out = statuses(t, p, pw="k")
            t.record(st.get("x.bin") in (ST_AUTH, ST_CRC), "EGG %s: tampered data -> HMAC/CRC error" % kind, str(st))
            e3 = A.Egg(seed=6)
            e3.add("y.txt", t2, method="deflate", enc=kind, pw=b"k", footer=False)
            t.check_extract(wr(t, "egg/nofooter_%s.egg" % kind, e3.build()), {"y.txt": t2}, pw="k",
                            label="EGG %s without the HMAC footer" % kind)


def section_egg_solid(t, drv):
    t1, t2, b1 = egg_corpus()
    files = [("d", None)] + [("d/f%02d.txt" % i, text(300 + i * 517, 40 + i)) for i in range(20)] + \
            [("z/empty.txt", b""), ("big.bin", b1 * 4)]
    methods = ["deflate", "bzip2", "lzma", "azo", "store"]
    for m in methods:
        e = A.Egg(solid=True)
        e.solid_method = m
        e.solid_block = 5000 if m != "store" else 3000
        for n, d in files:
            e.add(n, d)
        arc = wr(t, "egg/solid_%s.egg" % m, e.build())
        t.check_extract(arc, dict(files), label="EGG solid %s (%d blocks across file boundaries)" %
                        (m, (sum(len(d or b"") for _, d in files) + e.solid_block - 1) // e.solid_block))
        if m in ("deflate", "azo"):
            for order in ("each", "rev"):
                out = os.path.join(t.work, "egg/solid_%s_%s" % (m, order))
                r = drv_run(t, drv, ["x", arc, out, "", order])
                rows = drv_rows(r.stdout)
                good = all(rows.get(i, (1,))[0] == 0 for i in range(len(files))) and b"VIOLATIONS 0" in r.stdout
                data_ok = all(open(os.path.join(out, "%d.bin" % i), "rb").read() == d
                              for i, (n, d) in enumerate(files) if d is not None)
                t.record(good and data_ok, "EGG solid %s: entries one by one (%s)" % (m, order),
                         r.stdout.decode()[-300:])
    # encrypted solid streams: key in the last file's field or in the global header
    for kind, where in [("zip", "file"), ("aes256" if A.have_aes() else "lea256", "file"), ("lea128", "global")]:
        e = A.Egg(solid=True, seed=3)
        e.solid_method = "deflate"
        e.solid_block = 4000
        e.solid_enc = (kind, "솔리드".encode(), where)
        for n, d in files:
            e.add(n, d)
        arc = wr(t, "egg/solid_enc_%s_%s.egg" % (kind, where), e.build())
        t.check_extract(arc, dict(files), pw="솔리드", label="EGG solid, %s key in the %s header" % (kind, where))
        st, rows, out = statuses(t, arc, pw="x")
        t.record(st.get("d/f03.txt") == ST_PASSWORD, "EGG solid %s: wrong password" % kind, str(st)[:200])
        out = os.path.join(t.work, "egg/solid_enc_rev_%s" % kind)
        r = drv_run(t, drv, ["x", arc, out, "솔리드", "rev"])
        rows = drv_rows(r.stdout)
        t.record(all(v[0] == 0 for v in rows.values()) and b"VIOLATIONS 0" in r.stdout,
                 "EGG solid %s: entries one by one, backwards" % kind, r.stdout.decode()[-200:])
    # a damaged block: the files touching it fail, the others extract
    e = A.Egg(solid=True)
    e.solid_method = "store"
    e.solid_block = 3000
    for n, d in files:
        e.add(n, d)
    raw = bytearray(e.build())
    first = files[1][1]
    pos = raw.find(first[:64])
    raw[pos + 3500] ^= 0xFF                      # inside the second block
    arc = wr(t, "egg/solid_bad.egg", bytes(raw))
    st, rows, out = statuses(t, arc)
    bad = [n for n, v in st.items() if v != 0]
    t.record(bad and st.get("d/f00.txt") == 0 and st.get("big.bin") == 0 and all(v in (0, ST_CRC) for v in st.values()),
             "EGG solid: a corrupt block fails only its files", str(bad))


def section_egg_split(t):
    t1, t2, b1 = egg_corpus()
    e = A.Egg()
    e.add("dir", None)
    for i in range(8):
        e.add("dir/s%d.txt" % i, text(3000 + i * 1111, 60 + i), method="deflate" if i % 2 else "store")
    e.add("azo.txt", t2, method="azo")
    vols = e.build_split(4096)
    names = []
    for k, v in enumerate(vols):
        names.append(wr(t, "egg/split/set.vol%d.egg" % (k + 1), v))
    exp = {f.name: f.data for f in e.files}
    t.check_extract(names[0], exp, label="EGG split set (%d volumes) from vol1" % len(vols))
    t.check_extract(names[3], exp, label="EGG split set opened at vol4")
    for k, v in enumerate(vols):
        wr(t, "egg/splitup/SET.VOL%d.EGG" % (k + 1), v)
    t.check_extract(t.path("egg/splitup/SET.VOL1.EGG"), exp, label="EGG split set, upper-case names")
    for k, v in enumerate(vols):
        if k != 2:
            wr(t, "egg/splitmiss/set.vol%d.egg" % (k + 1), v)
    st, rows, out = statuses(t, t.path("egg/splitmiss/set.vol1.egg"))
    t.record(st.get("dir/s0.txt") == 0 and (any(v == ST_VOLUME for v in st.values()) or len(st) < len(exp)),
             "EGG split set with a missing volume", str(st))
    # solid + split + encrypted
    e = A.Egg(solid=True, seed=8)
    e.solid_method = "lzma"
    e.solid_block = 6000
    e.solid_enc = ("zip", b"pw", "file")
    for i in range(10):
        e.add("f%d.txt" % i, text(2500 + 300 * i, 80 + i))
    vols = e.build_split(3000)
    for k, v in enumerate(vols):
        wr(t, "egg/ssplit/s.vol%d.egg" % (k + 1), v)
    t.check_extract(t.path("egg/ssplit/s.vol1.egg"), {f.name: f.data for f in e.files}, pw="pw",
                    label="EGG solid + split (%d volumes) + ZipCrypto" % len(vols))


def section_azo(t, drv):
    cases = [("text", text(50000, 90), 16384, False), ("random", blob(20000, 91), 8192, False),
             ("zeros", bytes(60000), 65536, False), ("x86", x86ish(40000), 16384, True),
             ("tiny", b"ab", 4096, False), ("one", b"z", 4096, False), ("mixed", text(9000, 92) + blob(3000) + text(9000, 92), 4000, True)]
    for name, data, bs, x86 in cases:
        s = A.azo_compress(data, bs, x86=x86, seed=len(name))
        i = wr(t, "azo/%s.azo" % name, s)
        r = drv_run(t, drv, ["azo", i, i + ".out"])
        out = open(i + ".out", "rb").read() if os.path.exists(i + ".out") else b""
        t.record(r.stdout.startswith(b"AZO 0 used %d" % len(s)) and out == data,
                 "AZO %s: %d -> %d bytes%s" % (name, len(data), len(s), " (x86 filter)" if x86 else ""),
                 r.stdout.decode()[:80])
    # corrupt streams fail cleanly
    good = A.azo_compress(text(20000, 93), 8192, seed=4)
    for label, bad in [("version", b"2" + good[1:]), ("check", good[:2] + good[2:10] + bytes([good[10] ^ 1]) + good[11:]),
                       ("cut", good[:len(good) // 2]), ("garbage", good[:14] + blob(len(good) - 14, 5))]:
        i = wr(t, "azo/bad_%s.azo" % label, bad)
        r = drv_run(t, drv, ["azo", i, i + ".out"])
        t.record(r.returncode == 0 and not r.stdout.startswith(b"AZO 0 ") and b"runtime error" not in r.stderr,
                 "AZO corrupt (%s) is rejected" % label, r.stdout.decode()[:60])


def section_hostile(t, drv):
    t1, t2, b1 = egg_corpus()
    seeds = []
    e = A.Egg()
    e.add("a.txt", t2, method="deflate")
    e.add("b.txt", t2, method="azo")
    e.add("c.txt", t2[:3000], method="lzma", enc="lea128", pw=b"p")
    seeds.append(("egg", wr(t, "fz/seed.egg", e.build()), "p"))
    e = A.Egg(solid=True)
    e.solid_method = "azo"
    e.solid_block = 3000
    for i in range(6):
        e.add("f%d" % i, text(1500, 100 + i))
    seeds.append(("egg-solid", wr(t, "fz/seed_solid.egg", e.build()), ""))
    recs = [A.alz_entry(b"a.txt", t2, method=3), A.alz_entry(b"b.txt", t2, method=1),
            A.alz_entry(b"c.txt", t2[:2000], method=2, pw=b"p")]
    seeds.append(("alz", wr(t, "fz/seed.alz", A.alz_archive(recs, comment=b"c")), "p"))
    iters = int(os.environ.get("GZ_FUZZ_ITERS", "600"))
    for name, p, pw in seeds:
        r = drv_run(t, drv, ["fuzz", p, str(iters), str(len(name)), pw], timeout=900)
        err = r.stderr.decode(errors="replace")
        t.record(r.returncode == 0 and b"FUZZ OK" in r.stdout and "Sanitizer" not in err and "runtime error" not in err,
                 "fuzz %s: %d mutations (bit flips, cuts, big numbers)" % (name, iters),
                 (r.stdout.decode()[-200:] + err[-400:]))
    # a few whole-file cases through gzt
    raw = open(seeds[0][1], "rb").read()
    hostile = {
        "huge-length": raw.replace(struct.pack("<Q", len(t2)), struct.pack("<Q", 1 << 62), 1),
        "huge-block": raw[:raw.find(struct.pack("<I", A.SIG["BLOCK"])) + 6] + b"\xff" * 8 + raw[raw.find(struct.pack("<I", A.SIG["BLOCK"])) + 14:],
        "field-size": raw[:14] + struct.pack("<IBI", A.SIG["DUMMY"], 1, 0xFFFFFFF0) + raw[14:],
        "loop-parent": A.Egg().build(),
    }
    e = A.Egg()
    a1 = e.add("a", None, fid=5, parent=6)
    e.add("b", None, fid=6, parent=5)
    e.add("c.txt", b"x", method="store", parent=6)
    hostile["loop-parent"] = e.build()
    for k, v in hostile.items():
        t.check_hostile(wr(t, "fz/h_%s.egg" % k, v), label="hostile EGG %s" % k)
    alz = open(seeds[2][1], "rb").read()
    for k, v in {"width-3": alz[:19] + bytes([0x30]) + alz[20:], "huge-size": alz[:23] + b"\xff\xff\xff\xff" + alz[27:],
                 "volume-id": alz[:6] + b"\x05\x00" + alz[8:]}.items():
        t.check_hostile(wr(t, "fz/h_%s.alz" % k, v), label="hostile ALZ %s" % k)


def run(t):
    if not A.have_aes():
        t.record(True, "pycryptodomex missing: AES cases use LEA only")
    drv = t.build_driver("tests/drivers/alzegg.c")
    r = drv_run(t, drv, ["lea"])
    t.record(r.stdout.strip() == b"LEA OK", "LEA-128/192/256 KS X 3246 vectors + CTR", r.stdout.decode())
    section_azo(t, drv)
    section_alz_basic(t)
    section_alz_crypto(t)
    section_alz_volumes(t)
    section_alz_misc(t)
    section_alz_real(t)
    section_egg_spec(t)
    section_egg_methods(t)
    section_egg_crypto(t)
    section_egg_solid(t, drv)
    section_egg_split(t)
    section_hostile(t, drv)
