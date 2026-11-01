"""LZMA / LZMA2 encoder (src/codec/lzma_enc.c): xz and 7-Zip must decode what we encode.

Corpora (English and Korean text, source tar, binaries, random, zeros, mixed), every level,
raw LZMA / raw LZMA2 / .lzma / .xz (wrapped here), LZMA2 chunk structure at the 64 KiB and
2 MiB boundaries, options (lc/lp/pb, dictionary, nice, depth, finders, parsers, size hints),
streaming (tiny reads, stdin, 100 MB with bounded memory), renormalisation, determinism,
error propagation, random option fuzzing, ratio against xz.

GZ_LZMAENC_BENCH=1 prints a ratio/speed table against xz -0..-9e and 7z -mx1..9;
GZ_LZMAENC_SLOW=1 adds a 100 MB level 6 run."""
import os, sys, random, subprocess, hashlib, struct, zlib, tarfile, io, time, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MiB = 1 << 20
CH_U, CH_P = 2 * MiB, 1 << 16


# ---------------- containers / parsers ----------------

def dict_from_prop(p):
    return 0xFFFFFFFF if p == 40 else (2 | (p & 1)) << (p // 2 + 11)


def varint(n):
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def xz_wrap(raw2, dprop, data):
    """Single-block .xz file (CRC32 check) around a raw LZMA2 stream."""
    le32 = lambda v: struct.pack("<I", v & 0xFFFFFFFF)
    flags = b"\x00\x01"
    out = bytearray(b"\xfd7zXZ\x00" + flags + le32(zlib.crc32(flags)))
    bh = bytearray(b"\x00\x00" + b"\x21\x01" + bytes([dprop]))      # 1 filter: LZMA2
    while (len(bh) + 4) % 4:
        bh.append(0)
    bh[0] = (len(bh) + 4) // 4 - 1
    bh += le32(zlib.crc32(bh))
    out += bh + raw2
    while len(out) % 4:                      # block padding
        out.append(0)
    out += le32(zlib.crc32(data))
    unpadded = len(bh) + len(raw2) + 4
    idx = bytearray(b"\x00" + varint(1) + varint(unpadded) + varint(len(data)))
    while len(idx) % 4:
        idx.append(0)
    idx += le32(zlib.crc32(idx))
    out += idx
    back = le32(len(idx) // 4 - 1) + flags
    out += le32(zlib.crc32(back)) + back + b"YZ"
    return bytes(out)


def parse_lzma2(buf):
    """Validate an LZMA2 stream's chunk structure; returns [(kind, control, unpacked, packed)]."""
    pos, chunks, need = 0, [], 0xE1          # first chunk: dictionary reset (1 or >= 0xE0)
    while True:
        if pos >= len(buf):
            raise ValueError("no end byte")
        c = buf[pos]
        if c == 0:
            if pos + 1 != len(buf):
                raise ValueError("data after end byte")
            return chunks
        if c in (1, 2):
            if need == 0xE1 and c != 1:
                raise ValueError("first chunk without dictionary reset")
            u = (buf[pos + 1] << 8 | buf[pos + 2]) + 1
            chunks.append(("copy", c, u, u))
            pos += 3 + u
            if c == 1:
                need = 0xC0
        elif c >= 0x80:
            if need == 0xE1 and c < 0xE0:
                raise ValueError("first LZMA chunk without dictionary reset")
            if need and c < min(need, 0xE0):
                raise ValueError("LZMA chunk %02x needs >= %02x" % (c, need))
            u = ((c & 0x1F) << 16 | buf[pos + 1] << 8 | buf[pos + 2]) + 1
            p = (buf[pos + 3] << 8 | buf[pos + 4]) + 1
            hl = 6 if c >= 0xC0 else 5
            if hl == 6 and buf[pos + 5] >= 9 * 5 * 5:
                raise ValueError("bad properties")
            chunks.append(("lzma", c, u, p))
            pos += hl + p
            need = 0
        else:
            raise ValueError("bad control %02x" % c)


# ---------------- corpora ----------------

KO_WORDS = ("고기 삼겹살 목살 갈비 압축 파일 폴더 바이트 사전 문자열 한글 대한민국 서울 부산 학교 학생 선생님 "
            "회사 사람 시간 오늘 내일 어제 우리 나라 정부 경제 문화 역사 사회 기술 컴퓨터 프로그램 데이터 "
            "프로그래머 개발 운영체제 사용자 화면 설정 저장 불러오기 결과 오류 성공 실패 확인 취소 "
            "그리고 그러나 하지만 또한 때문에 위하여 대하여 통하여 있다 없다 하다 되다 보다 같다").split()
KO_TAIL = ["은", "는", "이", "가", "을", "를", "에", "에서", "으로", "와", "과", "의", "도", "만", ""]
KO_END = ["다.", "습니다.", "요.", "까?", "다,", "고", "며"]


def korean_text(n, seed=3):
    rnd = random.Random(seed)
    out, size = [], 0
    while size < n:
        words = [rnd.choice(KO_WORDS) + rnd.choice(KO_TAIL) for _ in range(rnd.randint(3, 12))]
        s = " ".join(words) + rnd.choice(KO_END) + ("\n" if rnd.random() < 0.2 else " ")
        out.append(s)
        size += len(s.encode())
    return "".join(out).encode()[:n]


def english_text(n):
    """System documentation text (vim help, licenses); a generated fallback elsewhere."""
    out = bytearray()
    for d in ("/usr/share/vim", "/usr/share/common-licenses", "/usr/share/doc"):
        if not os.path.isdir(d):
            continue
        for dp, dns, fns in sorted(os.walk(d)):
            dns.sort()
            for fn in sorted(fns):
                if fn.endswith(".txt") or d.endswith("licenses") or fn == "copyright":
                    fp = os.path.join(dp, fn)
                    if os.path.isfile(fp) and not os.path.islink(fp):
                        out += open(fp, "rb").read()
                        if len(out) >= n:
                            return bytes(out[:n])
    rnd = random.Random(4)
    words = ("the of and to in is that for it as with was on be by this are or from at an which "
             "have not but they his her one all their there been has more when will would who "
             "archive compression dictionary encoder decoder window match literal stream").split()
    while len(out) < n:
        out += (" ".join(rnd.choice(words) for _ in range(rnd.randint(4, 15))) + ".\n").encode()
    return bytes(out[:n])


def source_tar(n):
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for sub in ("src", "tests", "docs", "tools"):
            for dp, dns, fns in sorted(os.walk(os.path.join(ROOT, sub))):
                dns.sort()
                for fn in sorted(fns):
                    fp = os.path.join(dp, fn)
                    if os.path.isfile(fp) and not os.path.islink(fp) and os.path.getsize(fp) < (4 << 20):
                        tf.add(fp, os.path.relpath(fp, ROOT), recursive=False)
                if bio.tell() >= n:
                    break
    return bio.getvalue()[:n]


def binaries(n):
    out = bytearray()
    for d in ("/usr/bin", "/bin", "/usr/lib"):
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            fp = os.path.join(d, fn)
            if os.path.isfile(fp) and not os.path.islink(fp) and 20000 < os.path.getsize(fp) < (3 << 20):
                with open(fp, "rb") as f:
                    head = f.read(4)
                    if head in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
                        out += head + f.read()
            if len(out) >= n:
                return bytes(out[:n])
    rnd = random.Random(6)
    while len(out) < n:                       # fallback: structured pseudo machine code
        out += bytes([0x48, 0x89, rnd.randrange(256), 0xe8]) + struct.pack("<i", rnd.randrange(-4096, 4096))
    return bytes(out[:n])


# ---------------- run(t) ----------------

def run(t):
    t.need("xz")
    have7z = shutil.which("7z") is not None
    asan = "-fsanitize" in os.environ.get("HOST_CFLAGS", "")
    scale = 0.35 if asan else 1.0
    drv = t.build_driver("tests/drivers/lzmaenc_test.c")
    W = t.work
    times = [time.time()]

    def lap(section):           # GZ_LZMAENC_TIMES=1: seconds per section on stderr
        times.append(time.time())
        if os.environ.get("GZ_LZMAENC_TIMES") and section > 1:
            print("codec_lzmaenc section %d: %.1f s" % (section - 1, times[-1] - times[-2]), file=sys.stderr)

    def sz(n):
        return max(1, int(n * scale))

    def gen(kind, n, seed=1):
        return subprocess.run([drv, "gen", kind, str(n), str(seed)], capture_output=True, check=True).stdout

    def write(name, data):
        p = os.path.join(W, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def enc(fmt, level, src, dst, opts=(), stdin=None, timeout=900):
        r = subprocess.run([drv, "enc", fmt, str(level), src, dst] + list(opts), capture_output=True,
                           stdin=stdin, timeout=timeout)
        st = {}
        for kv in r.stderr.decode(errors="replace").split():
            if "=" in kv:
                k, v = kv.split("=", 1)
                st[k] = v
        st["rc"] = r.returncode
        st["stdout"] = r.stdout.decode(errors="replace").strip()
        err = r.stderr.decode(errors="replace")
        if "runtime error" in err or "Sanitizer" in err:      # UBSan reports but carries on
            st["rc"] = 99
            st["stdout"] = err[-400:]
        return st

    def xz_args(fmt, st):
        pb_ = int(st["props"], 16)
        lc, lp, pb = pb_ % 9, pb_ // 9 % 5, pb_ // 45
        if fmt == "raw2":
            return ["--format=raw", "--lzma2=dict=%d" % dict_from_prop(int(st["dprop"]))]
        if fmt.startswith("raw1"):
            return ["--format=raw", "--lzma1=lc=%d,lp=%d,pb=%d,dict=%s" % (lc, lp, pb, st["dict"])]
        return ["--format=lzma"]

    def xz_dec(fmt, path, st):
        r = subprocess.run(["xz"] + xz_args(fmt, st) + ["-dc", path], capture_output=True, timeout=600)
        return r.stdout if r.returncode == 0 else ("xz: " + r.stderr.decode(errors="replace")[-200:])

    def sevenzip_dec(path):
        r = subprocess.run(["7z", "x", "-so", "-y", path], capture_output=True, timeout=600)
        return r.stdout if r.returncode == 0 else ("7z: " + r.stdout.decode(errors="replace")[-200:])

    def roundtrip(label, data, fmt, level, opts=(), src=None, decoders=("xz",)):
        """Encode data (or the file src), decode with the given tools, compare. Returns stats."""
        src = src or write("in.bin", data)
        out = os.path.join(W, "out.%s" % fmt)
        st = enc(fmt, level, src, out, opts)
        if st["rc"]:
            t.record(False, label, "encode failed rc=%d %s" % (st["rc"], st["stdout"]))
            return None
        problems = []
        if fmt == "raw2":
            try:
                parse_lzma2(open(out, "rb").read())
            except (ValueError, IndexError) as ex:
                problems.append("chunks: %s" % ex)
        for d in decoders:
            if d == "xz":
                got = xz_dec(fmt, out, st)
            elif fmt == "raw2":
                xzp = out + ".xz"
                with open(xzp, "wb") as f:
                    f.write(xz_wrap(open(out, "rb").read(), int(st["dprop"]), data))
                got = sevenzip_dec(xzp)
            else:
                lz = out + ".lzma"
                shutil.copyfile(out, lz)
                got = sevenzip_dec(lz)
            if got != data:
                problems.append("%s mismatch%s" % (d, ": " + got if isinstance(got, str) else ""))
        st["size"] = os.path.getsize(out)
        t.record(not problems, label, "; ".join(problems) or "%d -> %d" % (len(data), st["size"]))
        return st

    lap(1)
    # 1) API self test (option checks, properties, reuse, error propagation)
    r = subprocess.run([drv, "selftest"], capture_output=True, timeout=600)
    err = r.stderr.decode(errors="replace")
    t.record(r.returncode == 0 and "runtime error" not in err, "selftest", err[-600:])

    lap(2)
    # 2) corpora
    corp = {
        "en": english_text(sz(2 * MiB)),
        "ko": korean_text(sz(MiB)) + open(os.path.join(ROOT, "README.md"), "rb").read(),
        "src": source_tar(sz(2 * MiB)),
        "bin": binaries(sz(3 * MiB)),
        "random": random.Random(5).randbytes(sz(MiB)),
        "zeros": bytes(sz(3 * MiB)),
        "mixed": gen("mixed", sz(4 * MiB), 7),
    }
    files = {k: write("c_%s.bin" % k, v) for k, v in corp.items()}
    sizes = {}
    both = ("xz", "7z") if have7z else ("xz",)
    for name in ("en", "mixed"):
        for lv in range(10):
            for fmt in ("raw2", "alone") if lv in (0, 4, 9) else ("raw2",):
                st = roundtrip("%s L%d %s" % (name, lv, fmt), corp[name], fmt, lv, src=files[name],
                               decoders=both if lv in (1, 6, 9) or fmt == "alone" else ("xz",))
                if st and fmt == "raw2":
                    sizes[(name, lv)] = st["size"]
    for name in ("ko", "src", "bin", "random", "zeros"):
        for lv in (0, 1, 3, 4, 6, 9) if name in ("ko", "bin") else (0, 3, 6, 9):
            roundtrip("%s L%d raw2" % (name, lv), corp[name], "raw2", lv, src=files[name],
                      decoders=both if lv in (1, 6, 9) else ("xz",))
        roundtrip("%s L5 raw1" % name, corp[name], "raw1", 5, src=files[name])
        roundtrip("%s L2 alone" % name, corp[name], "alone", 2, src=files[name], decoders=both)

    lap(3)
    # 3) tiny inputs, every format
    rnd = random.Random(11)
    tiny = [b"", b"a", b"ab", b"aaa", b"abab", b"\x00" * 5, b"abcabcabcabc"] + \
           [bytes(rnd.choice(b"ab\x00\xff") for _ in range(n)) for n in (13, 64, 199, 273, 274, 300, 777)]
    for i, d in enumerate(tiny):
        for lv in (0, 6, 9):
            for fmt in ("raw1", "raw2", "alone", "alone-eos"):
                roundtrip("tiny #%d (%d B) L%d %s" % (i, len(d), lv, fmt), d, fmt, lv)

    lap(4)
    # 4) LZMA2 chunk boundaries (2 MiB unpacked, 64 KiB packed / uncompressed chunks)
    txt = (corp["en"] + corp["ko"] + corp["src"]) * 2
    rbytes = random.Random(12).randbytes(2 * MiB + 1 + 65537)
    cases = []
    for n in (CH_U - 1, CH_U, CH_U + 1, 2 * CH_U + 17):
        cases.append(("text", n, (txt * (n // len(txt) + 1))[:n]))
    for n in (CH_P - 1, CH_P, CH_P + 1, CH_U - 1, CH_U, CH_U + 1):
        cases.append(("random", n, rbytes[:n]))
    # alternating compressible / incompressible pieces: LZMA chunk after an uncompressed one
    alt = b"".join((txt[i * 70000:(i + 1) * 70000] if i % 2 else rbytes[i * 9000:i * 9000 + 300000])
                   for i in range(8))
    cases.append(("alternating", len(alt), alt))
    for kind, n, data in cases:
        for lv in (1, 6):
            st = roundtrip("lzma2 %s %d L%d" % (kind, n, lv), data, "raw2", lv,
                           decoders=("xz", "7z") if have7z and lv == 6 else ("xz",))
            if not st:
                continue
            ch = parse_lzma2(open(os.path.join(W, "out.raw2"), "rb").read())
            bad = [c for c in ch if (c[0] == "lzma" and (c[2] > CH_U or c[3] > CH_P)) or
                   (c[0] == "copy" and c[2] > CH_P)]
            short = [c for c in ch[:-1] if c[0] == "lzma" and c[2] < CH_U - 6000 and c[3] < 57000 and
                     kind == "text"]
            total = sum(c[2] for c in ch)
            ok = not bad and not short and total == n
            if kind == "random":     # stored: n + 3 bytes per chunk (<= 64 KiB each) + end byte
                ok = ok and all(c[0] == "copy" for c in ch) and st["size"] == n + 3 * len(ch) + 1 and \
                    len(ch) <= n // 50000 + 2
            if kind == "alternating":
                ok = ok and any(c[0] == "copy" for c in ch) and any(c[0] == "lzma" and c[1] < 0xA0 for c in ch)
            t.record(ok, "lzma2 %s %d L%d structure" % (kind, n, lv),
                     "%d chunks %s" % (len(ch), "; ".join("%s:%02x:%d/%d" % c for c in (bad + short)[:4])))

    lap(5)
    # 5) options
    samp = (corp["mixed"][:sz(600000)] + corp["en"][:sz(400000)] + corp["bin"][:sz(300000)])
    sp = write("samp.bin", samp)
    variants = [
        ("raw1", 6, ["lc=0", "lp=0", "pb=0"]), ("raw1", 6, ["lc=4", "lp=0", "pb=4"]),
        ("raw1", 4, ["lc=0", "lp=4", "pb=0"]), ("raw2", 6, ["lc=1", "lp=3", "pb=1"]),
        ("raw2", 1, ["lc=2", "lp=2", "pb=3"]), ("raw1", 6, ["dict=4096"]), ("raw1", 1, ["dict=4096"]),
        ("raw2", 6, ["dict=65536"]), ("raw2", 3, ["dict=5000"]), ("raw2", 6, ["dict=%d" % (3 << 20)]),
        ("raw2", 6, ["nice=5"]), ("raw2", 6, ["nice=273"]), ("raw2", 1, ["nice=5"]), ("raw2", 3, ["nice=273"]),
        ("raw2", 6, ["depth=1"]), ("raw2", 2, ["depth=1"]), ("raw2", 6, ["depth=100000"]),
        ("raw2", 6, ["mf=hc4"]), ("raw2", 1, ["mf=bt4"]), ("raw1", 6, ["mode=fast"]),
        ("raw1", 1, ["mode=normal"]), ("raw2", 9, ["hint=1000"]), ("raw2", 9, ["hint=%d" % len(samp)]),
        ("raw2", 0, ["hint=%d" % (len(samp) * 3)]), ("raw2", 5, ["extreme=1"]), ("raw2", 7, ["extreme=1"]),
        ("raw2", 6, ["dict=4096", "hint=100"]),
    ]
    for fmt, lv, opts in variants:
        roundtrip("opts L%d %s %s" % (lv, fmt, " ".join(opts)), samp, fmt, lv, opts, src=sp)
    if have7z:   # lc + lp > 4 is LZMA-only and beyond xz's limits; 7-Zip decodes it
        for opts in (["lc=8", "lp=4", "pb=4"], ["lc=5", "lp=0"], ["lc=0", "lp=4", "pb=0", "dict=4096"]):
            roundtrip("opts .lzma %s via 7z" % " ".join(opts), samp, "alone", 6, opts, src=sp, decoders=("7z",))

    lap(6)
    # 6) equivalences: output does not depend on read sizes, renormalisation or reuse
    def same(label, a_opts, b_opts, fmt="raw2", lv=6, src=sp, b_stdin=False):
        a = enc(fmt, lv, src, os.path.join(W, "eq_a"), a_opts)
        if b_stdin:
            with open(src, "rb") as f:
                b = enc(fmt, lv, "-", os.path.join(W, "eq_b"), b_opts, stdin=f)
        else:
            b = enc(fmt, lv, src, os.path.join(W, "eq_b"), b_opts)
        ok = a["rc"] == 0 and b["rc"] == 0 and \
            open(os.path.join(W, "eq_a"), "rb").read() == open(os.path.join(W, "eq_b"), "rb").read()
        t.record(ok, label, "rc %d/%d" % (a["rc"], b["rc"]))
    for lv in (2, 6):
        same("renormalise L%d" % lv, [], ["norm=70000"], lv=lv)
        same("renormalise L%d dict 4K" % lv, ["dict=4096"], ["dict=4096", "norm=5000"], fmt="raw1", lv=lv)
        same("4093-byte reads L%d" % lv, [], ["rchunk=4093"], lv=lv)
        same("stdin L%d" % lv, [], [], lv=lv, b_stdin=True)
        same("reuse L%d" % lv, ["reuse=1"], [], lv=lv)
    sp2 = write("samp2.bin", samp[:200000])
    same("1-byte reads L6", [], ["rchunk=1"], src=sp2)
    same("1-byte reads L0 raw1", [], ["rchunk=1"], fmt="raw1", lv=0, src=sp2)

    lap(7)
    # 7) error propagation through the driver
    for fmt in ("raw1", "raw2"):
        st = enc(fmt, 6, sp, os.path.join(W, "err.bin"), ["failread=300000"])
        t.record(st["rc"] == 3 and st["stdout"] == "err=1", "read error %s" % fmt, str(st.get("stdout")))
        st = enc(fmt, 6, sp, os.path.join(W, "err.bin"), ["failwrite=5000"])
        t.record(st["rc"] == 3 and st["stdout"] == "err=8", "write error %s" % fmt, str(st.get("stdout")))
    st = enc("raw2", 6, sp, os.path.join(W, "err.bin"), ["lc=4", "lp=1"])
    t.record(st["rc"] == 3 and st["stdout"] == "err=5", "lzma2 lc+lp>4 rejected", str(st.get("stdout")))

    lap(8)
    # 8) random option fuzzing on small inputs
    rnd = random.Random(2024)
    for i in range(30 if not asan else 12):
        n = rnd.choice([rnd.randrange(1, 5000), rnd.randrange(5000, 300000)])
        off = rnd.randrange(0, len(samp) - n) if n < len(samp) else 0
        data = samp[off:off + n]
        if rnd.random() < 0.3:
            data = bytes(rnd.choice(b"abc") for _ in range(min(n, 3000))) + data
        fmt = rnd.choice(["raw1", "raw2", "alone"])
        lc = rnd.randrange(0, 5)
        lp = rnd.randrange(0, 5 - lc)
        opts = ["lc=%d" % lc, "lp=%d" % lp, "pb=%d" % rnd.randrange(0, 5),
                "dict=%d" % rnd.choice([4096, 6000, 65536, 1 << 20]), "nice=%d" % rnd.choice([5, 8, 33, 128, 273]),
                "depth=%d" % rnd.choice([0, 1, 3, 40]), "mf=%s" % rnd.choice(["hc4", "bt4"]),
                "mode=%s" % rnd.choice(["fast", "normal"])]
        if rnd.random() < 0.3:
            opts.append("rchunk=%d" % rnd.randrange(1, 9000))
        if rnd.random() < 0.3:
            opts.append("norm=%d" % rnd.randrange(1000, 100000))
        roundtrip("fuzz #%d %s %d B %s" % (i, fmt, len(data), " ".join(opts)), data, fmt, rnd.randrange(10), opts)

    lap(9)
    # 9) 100 MB stream through a pipe: bounded memory
    big = 100 * MiB if not asan else 24 * MiB
    for lv, limit_mb in ((1, 48), (6, 160)) if os.environ.get("GZ_LZMAENC_SLOW") else ((1, 48),):
        gp = subprocess.Popen([drv, "gen", "mixed", str(big), "9"], stdout=subprocess.PIPE)
        out = os.path.join(W, "big.lz2")
        st = enc("raw2", lv, "-", out, stdin=gp.stdout, timeout=3600)
        gp.wait()
        h = hashlib.sha256()
        gp = subprocess.Popen([drv, "gen", "mixed", str(big), "9"], stdout=subprocess.PIPE)
        for blk in iter(lambda: gp.stdout.read(1 << 20), b""):
            h.update(blk)
        gp.wait()
        dec = subprocess.Popen(["xz", "--format=raw", "--lzma2=dict=%d" % dict_from_prop(int(st.get("dprop", 0))),
                                "-dc", out], stdout=subprocess.PIPE)
        h2, n2 = hashlib.sha256(), 0
        for blk in iter(lambda: dec.stdout.read(1 << 20), b""):
            h2.update(blk)
            n2 += len(blk)
        dec.wait()
        rss = int(st.get("rss_kb", 0)) // 1024
        ok = st["rc"] == 0 and dec.returncode == 0 and n2 == big and h.digest() == h2.digest() and \
            (asan or rss <= limit_mb)
        t.record(ok, "%d MB stream L%d" % (big >> 20, lv), "%s -> %d bytes, %.1f s, RSS %d MB" % (
            st.get("in"), os.path.getsize(out), float(st.get("sec", 0)), rss))
        os.remove(out)

    lap(10)
    # 10) ratio against xz (same parameters: level 6 / 9 must be close)
    if not asan:
        for name in ("en", "mixed"):
            for lv, tol in ((1, 1.02), (6, 1.02), (9, 1.01)):
                r = subprocess.run(["xz", "-T1", "-%d" % lv, "--format=raw", "-c", files[name]],
                                   capture_output=True)
                ours = sizes.get((name, lv))
                ok = ours is not None and ours <= len(r.stdout) * tol
                t.record(ok, "ratio %s L%d vs xz -%d" % (name, lv, lv), "ours %s xz %d (%+.2f%%)" % (
                    ours, len(r.stdout), (ours - len(r.stdout)) * 100.0 / len(r.stdout) if ours else 0))

    lap(11)
    if os.environ.get("GZ_LZMAENC_BENCH"):
        bench(t, drv, files, have7z)


def bench(t, drv, files, have7z):
    """Ratio / single-thread speed table: ours (raw LZMA2) vs xz -0..-9e (raw) vs 7z .xz LZMA2."""
    W = t.work
    out = os.path.join(W, "bench.out")
    lines = ["%-7s %-5s %12s %8s | %12s %8s %7s | %12s %8s" % (
        "corpus", "level", "ours", "MB/s", "xz", "MB/s", "diff", "7z", "MB/s")]
    for name in ("en", "ko", "src", "bin", "mixed"):
        f = files[name]
        n = os.path.getsize(f)
        for lv in [str(i) for i in range(10)] + ["9e"]:
            ext = lv.endswith("e")
            l = lv.rstrip("e")
            r = subprocess.run([drv, "enc", "raw2", l, f, out] + (["extreme=1"] if ext else []),
                               capture_output=True)
            st = dict(kv.split("=", 1) for kv in r.stderr.decode().split() if "=" in kv)
            ours, osec = os.path.getsize(out), float(st["sec"])
            t0 = time.time()
            x = subprocess.run(["xz", "-T1", "-" + l + ("e" if ext else ""), "--format=raw", "-c", f],
                               capture_output=True).stdout
            xsec = time.time() - t0
            s7 = s7sec = 0
            if have7z and l != "0" and not ext:
                p7 = os.path.join(W, "bench.xz")
                if os.path.exists(p7):
                    os.remove(p7)
                t0 = time.time()
                subprocess.run(["7z", "a", "-txz", "-m0=LZMA2", "-mx=" + l, "-mmt=1", p7, f], capture_output=True)
                s7sec = time.time() - t0
                s7 = os.path.getsize(p7)
            lines.append("%-7s %-5s %12d %8.2f | %12d %8.2f %+6.2f%% | %12s %8s" % (
                name, lv, ours, n / osec / 1e6, len(x), n / xsec / 1e6, (ours - len(x)) * 100.0 / len(x),
                s7 or "-", "%.2f" % (n / s7sec / 1e6) if s7 else "-"))
    print("\n".join(lines))
    t.record(True, "benchmark", "\n" + "\n".join(lines))
