"""Deflate encoder (src/codec/deflate_enc.c).

Byte-exact roundtrips at levels 0-9 over text (English, Korean), source code, binaries,
random, zeros and mixed data from 0 B to 64 MiB, decoded both by Python's zlib (raw,
wbits=-15) and by our own inflater (driver), plus 7-Zip on .gz wrappers. Compressed sizes
are compared with zlib at the same level (must not be larger on any corpus >= 64 KiB) and
a ratio / speed table is recorded (-v). Driver self-tests: read/write error propagation,
encoder reuse, identical output on every SIMD tier, fuzzed data shapes and read chunking,
a generated 64 MiB stream that never sits in memory.
"""
import io, os, random, re, shutil, struct, subprocess, sys, tarfile, time, zlib

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SANITIZED = "sanitize" in os.environ.get("HOST_CFLAGS", "")


def english(limit):
    out = bytearray()
    paths = []
    for base in ("/usr/share/common-licenses", "/usr/share/doc"):
        for dp, dns, fns in os.walk(base):
            dns.sort()
            for f in sorted(fns):
                paths.append(os.path.join(dp, f))
    for p in paths:
        if len(out) >= limit:
            break
        try:
            if os.path.islink(p):
                continue
            raw = open(p, "rb").read(1 << 20)
            if p.endswith(".gz"):
                raw = zlib.decompress(raw, 47)
            raw.decode("ascii")
            out += raw
        except Exception:
            continue
    if len(out) < limit:                              # fallback: Python's own sources' docstrings
        for dp, dns, fns in os.walk(os.path.dirname(os.__file__)):
            for f in sorted(fns):
                if f.endswith(".py") and len(out) < limit:
                    try:
                        out += open(os.path.join(dp, f), "rb").read()
                    except OSError:
                        pass
    return bytes(out[:limit])


def korean(limit):
    """Word-bigram text seeded from the repository's Korean files (UTF-8 Hangul statistics)."""
    src = ""
    for rel in ("README.md", "src/win/strings.h", "web/index.html"):
        try:
            src += open(os.path.join(ROOT, rel), encoding="utf-8").read() + "\n"
        except OSError:
            pass
    src = re.sub(r"<[^>]*>", " ", src)
    words = [w for w in re.findall(r"[가-힣]+[.,!?]?|[A-Za-z0-9]+|\n", src)]
    if len(words) < 100:
        words = "고기 삼겹살 목살 갈비 압축 파일 폴더 암호 해제 지원 . \n".split(" ") * 20
    nxt = {}
    for a, b in zip(words, words[1:]):
        nxt.setdefault(a, []).append(b)
    rnd = random.Random(949)
    out = bytearray(src.encode("utf-8"))
    w = words[0]
    while len(out) < limit:
        w = rnd.choice(nxt.get(w) or words)
        out += (w if w == "\n" else w + " ").encode("utf-8")
    return bytes(out[:limit])


def source_tar(limit):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for top in ("src", "tests", "docs", "tools"):
            for dp, dns, fns in os.walk(os.path.join(ROOT, top)):
                dns.sort()
                for f in sorted(fns):
                    p = os.path.join(dp, f)
                    if f.endswith((".c", ".h", ".py", ".md", ".sh")):
                        ti = tf.gettarinfo(p, os.path.relpath(p, ROOT))
                        ti.mtime = 1700000000
                        ti.uid = ti.gid = 0
                        ti.uname = ti.gname = ""
                        with open(p, "rb") as fh:
                            tf.addfile(ti, fh)
    return buf.getvalue()[:limit]


def binaries(limit):
    out = bytearray()
    for d in ("/usr/bin", "/bin", "/usr/sbin"):
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if len(out) >= limit:
                break
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            try:
                out += open(p, "rb").read(limit - len(out))
            except OSError:
                pass
    return bytes(out[:limit])


def mixed(parts, limit, seed=7):
    rnd = random.Random(seed)
    out = bytearray()
    while len(out) < limit:
        p = rnd.choice(parts)
        n = rnd.randrange(2000, 200000)
        o = rnd.randrange(0, max(1, len(p) - n))
        out += p[o:o + n]
    return bytes(out[:limit])


def gz_wrap(raw, data):
    return (b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" + raw +
            struct.pack("<II", zlib.crc32(data) & 0xffffffff, len(data) & 0xffffffff))


def zlib_raw(data, lv):
    c = zlib.compressobj(lv, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def run(t):
    drv = t.build_driver("tests/drivers/deflate_test.c")
    big = 1 << 20 if SANITIZED else 3 << 20
    eng = english(big)
    kor = korean(big // 2 if SANITIZED else 1 << 20)
    src = source_tar(big)
    bins = binaries(big)
    rnd = random.Random(1).randbytes(1 << 20)
    corpora = [
        ("english", eng), ("korean", kor), ("source", src), ("binaries", bins),
        ("random", rnd), ("zeros", bytes(1 << 20)),
        ("mixed", mixed([eng, kor, src, bins, rnd, bytes(65536)], 2 * big)),
    ]
    # edge sizes around block / window / stored-block limits
    for n in (0, 1, 2, 3, 4, 5, 100, 4095, 32768, 65535, 65536, 65537, 300000):
        corpora.append(("text%d" % n, eng[:n]))
    corpora.append(("rnd70000", rnd[:70000]))
    corpora.append(("period3", b"abc" * 100000))

    sevenzip = shutil.which("7z")
    sizes = {}
    for name, data in corpora:
        path = t.path("in_" + name)
        with open(path, "wb") as f:
            f.write(data)
        for lv in range(10):
            out = t.path("out_%s_L%d.raw" % (name, lv))
            r = t.sh([drv, "enc", str(lv), path, out], check=False)
            label = "%s L%d" % (name, lv)
            if r.returncode:
                t.record(False, label, "driver: " + (r.stdout + r.stderr).decode(errors="replace")[-300:])
                continue
            crc, n, cn, ms, kern = r.stdout.decode().split()
            comp = open(out, "rb").read()
            d = zlib.decompressobj(-15)
            try:
                got = d.decompress(comp) + d.flush()
            except zlib.error as ex:
                t.record(False, label, "zlib: %s" % ex)
                continue
            ok = (got == data and d.eof and not d.unused_data and int(crc, 16) == zlib.crc32(data)
                  and int(cn) == len(comp) and int(n) == len(data))
            sizes[(name, lv)] = len(comp)
            detail = "%d -> %d" % (len(data), len(comp))
            if ok and len(data) >= 65536 and lv > 0:
                zs = len(zlib_raw(data, lv))
                detail += " (zlib %d, %+.2f%%)" % (zs, 100.0 * (len(comp) - zs) / zs)
                # never larger, except a few header bytes per 300 KB block on data that
                # shrinks >1000x (zlib fits 1 MiB of zeros into one block)
                ok = len(comp) <= zs or (len(comp) * 500 < len(data) and
                                         len(comp) - zs <= 16 * (len(data) // 300000 + 1))
            t.record(ok, label, detail)
            if sevenzip and lv in (1, 6, 9) and name in ("english", "binaries", "text65537", "text0"):
                gz = t.path("gz_%s_L%d.gz" % (name, lv))
                with open(gz, "wb") as f:
                    f.write(gz_wrap(comp, data))
                rr = subprocess.run(["7z", "t", gz], capture_output=True)
                t.record(rr.returncode == 0, "7z t %s L%d" % (name, lv), "" if not rr.returncode else
                         rr.stdout.decode(errors="replace")[-200:])

    # higher levels must not lose against lower ones by much (monotonic-ish ratio)
    for name in ("english", "korean", "source", "binaries", "mixed"):
        s = [sizes.get((name, lv)) for lv in range(1, 10)]
        if None not in s:
            t.record(s[8] <= min(s) * 1.001, "%s L9 best" % name, " ".join(map(str, s)))

    # read chunking (1..N byte reads) must not change the output
    p = t.path("in_text300000")
    for lv in (1, 4, 7, 9):
        a, b = t.path("chunk_a.raw"), t.path("chunk_b.raw")
        r1 = t.sh([drv, "enc", str(lv), p, a], check=False)
        r2 = t.sh([drv, "enc", str(lv), p, b, "777"], check=False)
        t.record(r1.returncode == 0 and r2.returncode == 0 and open(a, "rb").read() == open(b, "rb").read(),
                 "chunked reads L%d" % lv)

    # every SIMD tier gives the same bytes (x86: 0 = x86/SSE2 baseline, 3 = SSE2, 6 = AVX2)
    p = t.path("in_mixed")
    for lv in (2, 6, 8):
        outs = []
        for tier in ("0", "3", "6"):
            o = t.path("tier%s_L%d.raw" % (tier, lv))
            r = t.sh([drv, "enc", str(lv), p, o], check=False, env=dict(os.environ, GZ_TIER=tier))
            outs.append(open(o, "rb").read() if r.returncode == 0 else None)
        t.record(outs[0] is not None and outs.count(outs[0]) == 3, "tiers identical L%d" % lv)

    # driver self-tests
    for args, label in ((["errors"], "error propagation"), (["reuse"], "encoder reuse"),
                        (["fuzz", "11", "150" if SANITIZED else "400", "700000"], "fuzz shapes/chunking")):
        r = t.sh([drv] + args, check=False, timeout=1800)
        t.record(r.returncode == 0, label, r.stdout.decode(errors="replace").strip()[-200:])
    for lv, mb in ((0, 64), (1, 64), (6, 64), (9, 16 if not SANITIZED else 4)):
        if SANITIZED:
            mb = min(mb, 8)
        r = t.sh([drv, "stream", str(lv), str(mb)], check=False, timeout=1800)
        t.record(r.returncode == 0, "stream %d MiB L%d" % (mb, lv), r.stdout.decode(errors="replace").strip())

    # ratio / speed table against zlib (informational; timing is skipped under sanitizers)
    if SANITIZED:
        return
    table = []
    for name in ("english", "korean", "source", "binaries", "mixed", "random"):
        path = t.path("in_" + name)
        data = open(path, "rb").read()
        r = t.sh([drv, "bench", "123456789", path, "0.25"], check=False, timeout=1800)
        for line in r.stdout.decode().splitlines():
            lv, n, cn, mbs, okk = line.split()
            lv = int(lv)
            best, tot, reps = 1e9, 0.0, 0
            while tot < 0.25 or reps < 2:
                t0 = time.process_time()
                zs = len(zlib_raw(data, lv))
                dt = time.process_time() - t0
                best, tot, reps = min(best, dt), tot + dt, reps + 1
                if dt > 2:
                    break
            zm = len(data) / 1e6 / max(best, 1e-9)
            table.append("%-9s L%d  ours %9d  zlib %9d  %+6.2f%%  %7.1f MB/s  zlib %7.1f MB/s  x%.2f" % (
                name, lv, int(cn), zs, 100.0 * (int(cn) - zs) / zs, float(mbs), zm, float(mbs) / zm))
    with open(t.path("ratio_speed.txt"), "w") as f:
        f.write("\n".join(table) + "\n")
    for row in table:
        t.record(True, "table", row)
