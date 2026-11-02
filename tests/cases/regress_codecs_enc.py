"""Regressions of the compression encoders (src/codec/deflate_enc.c, lzma_enc.c, lz_mf.c,
bzip2_enc.c, zstd_enc.c) under clang's -fsanitize=undefined.

codecs-enc-1: the LZMA optimal parser (opt_normal, levels 4-9 incl. the default 5) formed
`e->len_prices[pos_state] - LEN_MIN`, a pointer 2 elements before a u32[272] row (before the
whole array for pos_state 0). The reads stayed in bounds, but clang UBSan reports
"index -2 out of bounds for type 'u32[272]'" on nearly every normal-mode encode, and with
-fno-sanitize-recover the process aborts, so no clang UBSan build (macOS cc, HOSTCC=clang,
libFuzzer targets) could run LZMA levels 4-9. gcc's UBSan does not check this, so the module
builds with clang and is skipped without it.

  1) tests/drivers/lzmaenc_test.c standalone (lzma_enc.c + lz_mf.c) built with clang
     -fsanitize=undefined -fno-sanitize-recover=all: every level, raw LZMA / LZMA2 / .lzma,
     both match finders, both parsers, extreme, lc/lp/pb and nice/depth variants on compressible
     text with repeats (a match path is needed: a 2-byte input never reaches it). Each run must
     exit 0 without a UBSan report and give the same bytes as the host (gcc) build of the driver.
  2) tests/drivers/enc_fuzz.c (Deflate, LZMA, LZMA2, BZip2, Zstandard: encode, decode with our
     decoders, compare) under the same clang UBSan: the inputs of 1) through the round trip and
     generated inputs over every codec, level and option byte.
  3) end to end: gzt (all of src/core, src/codec, src/fmt) built with the same clang UBSan
     writes .xz at levels 4-9 (the case the defect report reproduced) and 7z / ZIP / gz / bz2 /
     zst / tar.xz with every encoder method, then lists and extracts them; every run must be
     free of UBSan reports and give back the input files.

Found by the fuzz session of this slice (outside the slice, minimal fix in src/fmt/sevenz.c):
a 7z whose coders carry no properties at all (BZip2 or Copy only, e.g. what our writer makes
with BZip2) left the property buffer NULL, and the reader formed `st->props + cd->prop`
(NULL + 0, undefined; clang UBSan aborts) when listing methods and extracting. Covered by 3).
"""
import os, random, shutil, subprocess, sys, hashlib, concurrent.futures as cf

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UBSAN = ["-O1", "-g", "-fsanitize=undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]
WARN = ["-Wall", "-Wextra", "-Wno-unused-parameter", "-Wno-missing-field-initializers"]
INC = ["-I" + os.path.join(ROOT, "src/core"), "-I" + os.path.join(ROOT, "src/codec")]
FUZZ_SRCS = ["src/core/cpu.c", "src/core/crc32.c", "src/core/crc64.c", "src/core/sha1.c", "src/core/sha256.c",
             "src/core/aes.c", "src/core/blake2.c", "src/codec/inflate.c", "src/codec/deflate_enc.c",
             "src/codec/lzma.c", "src/codec/lzma_enc.c", "src/codec/lz_mf.c", "src/codec/bzip2.c",
             "src/codec/bzip2_enc.c", "src/codec/zstd.c", "src/codec/zstd_enc.c", "src/codec/xxhash.c"]


def find_clang(work):
    """(compiler, "") for a clang whose -fsanitize=undefined links and runs here,
    else (None, why)."""
    cands = [os.environ.get("CLANG"), "clang"]
    for cc in (os.environ.get("HOSTCC"), "cc"):
        if cc:
            try:
                if b"clang" in subprocess.run([cc, "--version"], capture_output=True, timeout=30).stdout:
                    cands.append(cc)
            except (OSError, subprocess.TimeoutExpired):
                pass
    src = os.path.join(work, "probe.c")
    exe = os.path.join(work, "probe")
    with open(src, "w") as f:
        f.write("int main(int c, char **v) { int a[4] = {0}; return a[c & 3] + (v == 0); }\n")
    why = "no clang"
    for cc in cands:
        if not cc or not shutil.which(cc):
            continue
        try:
            r = subprocess.run([cc] + UBSAN + ["-o", exe, src], capture_output=True, timeout=120)
            if r.returncode:
                why = "%s -fsanitize=undefined: %s" % (cc, r.stderr.decode(errors="replace").strip()[-200:])
                continue
            if subprocess.run([exe], capture_output=True, timeout=30).returncode == 0:
                return cc, ""
            why = "%s: UBSan probe program failed" % cc
        except (OSError, subprocess.TimeoutExpired) as ex:
            why = "%s: %s" % (cc, ex)
    return None, why


def text_with_repeats(n, seed):
    """Source-code-like text: words, numbers, and earlier lines copied again (matches of every
    length and distance, rep matches, literal + rep0 sequences)."""
    rnd = random.Random(seed)
    words = ("static const u32 len_prices pos_state price match literal state rep0 dist "
             "if for while return opt cur back len_end nice depth 압축 사전 고기 0x1F 2048").split()
    lines = []
    size = 0
    while size < n:
        if lines and rnd.random() < 0.35:
            s = rnd.choice(lines[-200:])
            if rnd.random() < 0.5:                      # copy with a small change
                k = rnd.randrange(len(s))
                s = s[:k] + rnd.choice(words) + s[k:]
        else:
            s = "    " * rnd.randrange(4) + " ".join(rnd.choice(words) for _ in range(rnd.randint(2, 12)))
            s += rnd.choice([";", " {", " }", " = %d;" % rnd.randrange(100000), ""])
        lines.append(s)
        size += len(s.encode()) + 1
    return ("\n".join(lines) + "\n").encode()[:n]


def run(t):
    W = t.work
    cc, why = find_clang(W)
    if not cc:
        t.skip("needs clang with a working -fsanitize=undefined runtime (%s)" % why)
    env = dict(os.environ, UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1")

    def clean(r):
        err = r.stderr.decode(errors="replace")
        return r.returncode == 0 and "runtime error" not in err, err[-1500:]

    # ---- 1) the LZMA encoder alone under clang UBSan ----
    lz_ub = os.path.join(W, "lzmaenc_ubsan")
    t.sh([cc, "-std=gnu11"] + UBSAN + WARN + INC + ["-DLZMAENC_STANDALONE", "-o", lz_ub,
          os.path.join(ROOT, "tests/drivers/lzmaenc_test.c"), os.path.join(ROOT, "src/codec/lzma_enc.c"),
          os.path.join(ROOT, "src/codec/lz_mf.c")])
    lz_native = t.build_driver("tests/drivers/lzmaenc_test.c", name="lzmaenc_native")

    inputs = {}
    for name, data in (("text48k", text_with_repeats(48 << 10, 1)),
                       ("text300k", text_with_repeats(300 << 10, 2)),
                       ("short", b"ab" * 40 + b"abc" * 30)):
        p = os.path.join(W, name + ".bin")
        with open(p, "wb") as f:
            f.write(data)
        inputs[name] = p

    cases = []
    for lv in range(10):
        cases.append(("raw2", lv, [], "text48k"))
    for lv in (4, 5, 9):
        cases.append(("raw1", lv, [], "text48k"))
        cases.append(("alone", lv, [], "short"))
    cases += [("raw2", 5, [], "text300k"),
              ("raw2", 6, ["extreme=1"], "text48k"),
              ("alone-eos", 3, ["extreme=1"], "text48k"),        # level 3 extreme: normal parser
              ("raw2", 2, ["mode=normal", "mf=hc4"], "text48k"),
              ("raw1", 7, ["mf=hc4"], "text48k"),
              ("raw1-noeos", 4, ["pb=0", "lc=0", "lp=0"], "text48k"),   # pos_state 0 only
              ("raw1", 8, ["pb=4", "lp=4", "lc=8"], "text48k"),         # 16 pos_state rows
              ("raw2", 9, ["nice=273", "depth=4"], "text48k"),
              ("raw2", 5, ["nice=5", "rchunk=777"], "text48k"),
              ("raw2", 6, ["dict=4096", "norm=5000"], "text300k")]
    for fmt, lv, opts, src in cases:
        label = "lzma ubsan %s level %d %s %s" % (fmt, lv, " ".join(opts), src)
        o_ub, o_nat = os.path.join(W, "ub.out"), os.path.join(W, "nat.out")
        r = subprocess.run([lz_ub, "enc", fmt, str(lv), inputs[src], o_ub] + opts,
                           capture_output=True, env=env, timeout=600)
        ok, err = clean(r)
        if not t.record(ok, label, "rc=%d %s" % (r.returncode, err)):
            continue
        r2 = subprocess.run([lz_native, "enc", fmt, str(lv), inputs[src], o_nat] + opts,
                            capture_output=True, timeout=600)
        same = r2.returncode == 0 and open(o_ub, "rb").read() == open(o_nat, "rb").read()
        t.record(same, label + ": same bytes as the host build", "rc=%d" % r2.returncode)
    r = subprocess.run([lz_ub, "stress", "40", "11"], capture_output=True, env=env, timeout=900)
    ok, err = clean(r)
    t.record(ok, "lzma ubsan stress (random options and data)", "rc=%d %s" % (r.returncode, err))

    # ---- 2) round trip of every encoder under clang UBSan ----
    objdir = os.path.join(W, "obj")
    os.makedirs(objdir, exist_ok=True)
    objs = []
    for s in FUZZ_SRCS:
        o = os.path.join(objdir, os.path.basename(s)[:-2] + ".o")
        t.sh([cc, "-std=gnu11"] + UBSAN + WARN + INC + ["-c", os.path.join(ROOT, s), "-o", o])
        objs.append(o)
    ef = os.path.join(W, "enc_fuzz_ubsan")
    t.sh([cc, "-std=gnu11"] + UBSAN + WARN + INC + ["-DENC_FUZZ_MAIN", "-o", ef,
          os.path.join(ROOT, "tests/drivers/enc_fuzz.c")] + objs)

    # codec numbers of enc_fuzz: 1 LZMA + end marker, 2 LZMA (size known), 3 LZMA2
    for codec in (1, 2, 3):
        for lv in range(4, 10):
            for src in ("text48k", "short"):
                r = subprocess.run([ef, "one", str(codec), str(lv), inputs[src]], capture_output=True,
                                   env=env, timeout=600)
                ok, err = clean(r)
                t.record(ok, "round trip ubsan: codec %d level %d %s" % (codec, lv, src),
                         "rc=%d %s" % (r.returncode, err))
    # LZMA2 normal parser, every pb (1..16 len_prices rows) with lc + lp <= 4 corner cases
    # (enc_fuzz header h[2] = 2: normal parser, h[3] = lc + 9 lp + 45 pb)
    for pb in range(5):
        for lc, lp in ((0, 0), (3, 0), (0, 4), (4, 0), (1, 3)):
            r = subprocess.run([ef, "one", "3", "6", inputs["text48k"], "2", str(lc + 9 * lp + 45 * pb)],
                               capture_output=True, env=env, timeout=600)
            ok, err = clean(r)
            t.record(ok, "round trip ubsan: lzma2 lc=%d lp=%d pb=%d" % (lc, lp, pb),
                     "rc=%d %s" % (r.returncode, err))
    # every encoder: Deflate 0-9, LZMA 0-9 (+ extreme), BZip2 1-9, Zstandard 0-19, options
    for seed, count in ((1, 240), (2, 240)):
        r = subprocess.run([ef, "rand", str(seed), str(count), "40000"], capture_output=True, env=env,
                           timeout=1800)
        ok, err = clean(r)
        t.record(ok, "round trip ubsan: %d generated inputs (seed %d)" % (count, seed),
                 "rc=%d %s" % (r.returncode, err))

    # ---- 3) end to end through the writers and readers with a clang UBSan gzt ----
    gobj = os.path.join(W, "gzt_obj")
    os.makedirs(gobj, exist_ok=True)
    core = sorted(os.path.join(d, f) for d in ("src/core", "src/codec", "src/fmt")
                  for f in os.listdir(os.path.join(ROOT, d)) if f.endswith(".c"))
    posix = sorted(os.path.join("src/posix", f) for f in os.listdir(os.path.join(ROOT, "src/posix"))
                   if f.endswith(".c"))
    reg = os.path.join(W, "registry.c")
    t.sh(["sh", os.path.join(ROOT, "tools/gen_registry.sh"), reg] + [os.path.join(ROOT, f) for f in core])
    ginc = ["-I" + os.path.join(ROOT, d) for d in ("src/core", "src/codec", "src/fmt", "src/app", "src/posix")]
    gflags = ["-std=gnu11"] + UBSAN + WARN + ["-Wno-cast-function-type", "-finput-charset=UTF-8", "-pthread"] + ginc

    def cc_one(src):
        o = os.path.join(gobj, src.replace("/", "_")[:-2] + ".o")
        r = subprocess.run([cc] + gflags + ["-c", src if os.path.isabs(src) else os.path.join(ROOT, src),
                            "-o", o], capture_output=True, timeout=900)
        return o, r

    objs = []
    with cf.ThreadPoolExecutor(2) as ex:
        for o, r in ex.map(cc_one, core + posix + [reg]):
            if r.returncode:
                t.record(False, "clang UBSan build of gzt", r.stderr.decode(errors="replace")[-1500:])
                return
            objs.append(o)
    gzt_ub = os.path.join(W, "gzt_ubsan")
    t.sh([cc] + gflags + ["-o", gzt_ub, os.path.join(ROOT, "tests/gzt.c")] + objs + ["-pthread"] +
         (["-liconv"] if sys.platform == "darwin" else []))

    tree = os.path.join(W, "tree")
    files = {"text.txt": open(inputs["text48k"], "rb").read(),
             "big.txt": open(inputs["text300k"], "rb").read()[:120000],
             "short.txt": open(inputs["short"], "rb").read(),
             "zeros.bin": bytes(70000),
             "noise.bin": bytes(random.Random(5).randrange(256) for _ in range(20000))}
    t.write_tree(tree, files)

    def roundtrip(fmt, level, names, method=None):
        label = "gzt ubsan %s level %d%s" % (fmt, level, " method %d" % method if method is not None else "")
        arc = os.path.join(W, "e2e." + fmt)
        e = dict(env)
        if method is not None:
            e["GZ_METHOD"] = str(method)
        r = subprocess.run([gzt_ub, "c", fmt, arc, str(level), "-", tree] + names, capture_output=True, env=e,
                           timeout=900)
        ok, err = clean(r)
        if not t.record(ok, label + ": create", "rc=%d %s" % (r.returncode, err)):
            return
        r = subprocess.run([gzt_ub, "l", arc], capture_output=True, env=env, timeout=600)
        ok, err = clean(r)
        t.record(ok, label + ": list", "rc=%d %s" % (r.returncode, err))
        out = os.path.join(W, "e2e_out")
        shutil.rmtree(out, ignore_errors=True)
        r = subprocess.run([gzt_ub, "x", arc, out], capture_output=True, env=env, timeout=600)
        ok, err = clean(r)
        got = []
        for line in r.stdout.decode("utf-8", "replace").splitlines():
            p = line.split("\t")
            if len(p) == 5 and p[0].isdigit() and p[2] == "0":
                ok = ok and p[1] == "0"
                fp = os.path.join(out, p[0] + ".bin")
                got.append(hashlib.sha256(open(fp, "rb").read()).hexdigest() if os.path.exists(fp) else "")
        want = sorted(hashlib.sha256(files[n]).hexdigest() for n in names)
        t.record(ok and sorted(got) == want, label + ": extract", "rc=%d %s" % (r.returncode, err))

    for lv in range(4, 10):                                   # codecs-enc-1 at the format level
        roundtrip("xz", lv, ["text.txt"])
    allf = sorted(files)
    # GZ_WM_*: 2 Deflate, 4 BZip2, 5 LZMA, 6 LZMA2; 7z with BZip2 only: property-less coders
    for m in (4, 5, 6):
        roundtrip("7z", 5, allf, m)
    roundtrip("7z", 9, allf)
    for m in (2, 4, 5):
        roundtrip("zip", 6, allf, m)
    for fmt, lv in (("gz", 9), ("bz2", 9), ("zst", 19), ("zst", 3), ("txz", 6), ("tzst", 7)):
        roundtrip(fmt, lv, ["big.txt"] if fmt in ("gz", "bz2", "zst") else allf)
