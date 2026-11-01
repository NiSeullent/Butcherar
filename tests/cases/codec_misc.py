"""Small block codecs: ADC, LZNT1, LZO1X (+ lzop .lzo files), LZFSE/LZVN, XPRESS plain / Huffman.

References: lzop and lzfse command line tools, wimlib-imagex (XPRESS WIM chunks), and when
installed: liblzo2 / liblzfse / libwim (differential fuzzing through tests/drivers/misc_ref.c),
Samba's MS-XCA module (python3.12) and dissect.util. Encoders for ADC, LZNT1 and both XPRESS
variants are written here from the specifications ([MS-XCA], libdmg's ADC).
"""
import heapq, importlib.util, os, random, shutil, struct, subprocess, sys, tarfile, io


# ---------------------------------------------------------------- data

def sample(n, seed=1):
    """Mixed data: words, runs with short periods, random bytes, copies from far back."""
    rnd = random.Random(seed)
    words = [b"gogi", b"zip", b"samgyeopsal", b"archive", b"\n", b"lzo", b"0123456789", b"  "]
    out = bytearray()
    while len(out) < n:
        k = rnd.randrange(6)
        if k == 0:
            out += b" ".join(rnd.choice(words) for _ in range(rnd.randrange(5, 80)))
        elif k == 1:
            out += bytes([rnd.randrange(256)]) * rnd.randrange(1, 3000)
        elif k == 2:
            p = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 8)))
            out += p * rnd.randrange(2, 400)
        elif k == 3:
            out += bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 2000)))
        elif k == 4 and len(out) > 100:
            a = rnd.randrange(len(out))
            out += out[a:a + rnd.randrange(3, 5000)]
        else:
            out += bytes(range(256))[rnd.randrange(200):]
    return bytes(out[:n])


def skewed(n, seed=2):
    """Symbol frequencies ~ Fibonacci: Huffman codes up to the 15-bit limit."""
    rnd = random.Random(seed)
    fib, a, b = [], 1, 1
    for _ in range(40):
        fib.append(a)
        a, b = b, a + b
    syms = list(range(40))
    rnd.shuffle(syms)
    return bytes(rnd.choices([s * 6 for s in syms], weights=fib[::-1], k=n))


# ---------------------------------------------------------------- encoders

class Matcher:
    """Greedy LZ77 match finder (3-byte hash chains, newest candidates first)."""
    def __init__(self, data, depth=16):
        self.d, self.depth, self.tab = data, depth, {}

    def insert(self, i):
        if i + 3 <= len(self.d):
            self.tab.setdefault(self.d[i:i + 3], []).append(i)

    def find(self, i, end, max_dist, max_len):
        d = self.d
        lim = min(max_len, end - i)
        if lim < 3:
            return 0, 0
        cands = self.tab.get(d[i:i + 3])
        best_l = best_d = 0
        for p in reversed((cands or [])[-self.depth:]):
            dist = i - p
            if dist > max_dist:
                break
            l = 3
            while l + 32 <= lim and d[p + l:p + l + 32] == d[i + l:i + l + 32]:
                l += 32
            while l < lim and d[p + l] == d[i + l]:
                l += 1
            if l > best_l:
                best_l, best_d = l, dist
                if l == lim:
                    break
        return best_l, best_d


def adc_compress(data):
    m = Matcher(data)
    out, lit, i, n = bytearray(), bytearray(), 0, len(data)

    def flush():
        while lit:
            c = lit[:128]
            out.append(0x80 | (len(c) - 1))
            out.extend(c)
            del lit[:128]
    while i < n:
        l, dist = m.find(i, n, 65536, 67)
        if l == 3 and dist > 1024:
            l = 0
        if l >= 3:
            flush()
            if dist <= 1024 and l <= 18:
                out += bytes([((l - 3) << 2) | ((dist - 1) >> 8), (dist - 1) & 0xff])
            else:
                out += bytes([0x40 | (l - 4)]) + (dist - 1).to_bytes(2, "big")
            for k in range(i, i + l):
                m.insert(k)
            i += l
        else:
            m.insert(i)
            lit.append(data[i])
            i += 1
    flush()
    return bytes(out)


def lznt1_chunk(c):
    m = Matcher(c)
    out, i, n = bytearray(), 0, len(c)
    while i < n:
        fp = len(out)
        out.append(0)
        flags = 0
        for bit in range(8):
            if i >= n:
                break
            l = 0
            if i > 0:
                lg, x = 0, i - 1
                while x >= 16:
                    x >>= 1
                    lg += 1
                l, dist = m.find(i, n, 1 << (4 + lg), (0xfff >> lg) + 3)
            if l >= 3:
                out += (((dist - 1) << (12 - lg)) | (l - 3)).to_bytes(2, "little")
                flags |= 1 << bit
                for k in range(i, i + l):
                    m.insert(k)
                i += l
            else:
                m.insert(i)
                out.append(c[i])
                i += 1
        out[fp] = flags
    return bytes(out)


def lznt1_compress(data, store=False):
    out = bytearray()
    for s in range(0, len(data), 4096):
        c = data[s:s + 4096]
        z = lznt1_chunk(c)
        if store or len(z) >= len(c):
            out += (0x3000 | (len(c) - 1)).to_bytes(2, "little") + c
        else:
            out += (0xb000 | (len(z) - 1)).to_bytes(2, "little") + z
    return bytes(out)


def xpress_compress(data):
    """[MS-XCA] 2.3 Plain LZ77 compression."""
    m = Matcher(data)
    out = bytearray(4)
    flags = nflags = fpos = 0
    half = None
    i, n = 0, len(data)
    while i < n:
        l, dist = m.find(i, n, 8192, 1 << 20)
        if l >= 3:
            for k in range(i, i + l):
                m.insert(k)
            i += l
            ml = l - 3
            out += (((dist - 1) << 3) | min(ml, 7)).to_bytes(2, "little")
            if ml >= 7:
                ml -= 7
                if half is None:
                    half = len(out)
                    out.append(min(ml, 15))
                else:
                    out[half] |= min(ml, 15) << 4
                    half = None
                if ml >= 15:
                    ml -= 15
                    if ml < 255:
                        out.append(ml)
                    else:
                        out.append(255)
                        ml += 7 + 15
                        out += ml.to_bytes(2, "little") if ml < 1 << 16 else b"\0\0" + ml.to_bytes(4, "little")
            flags = (flags << 1) | 1
        else:
            m.insert(i)
            out.append(data[i])
            i += 1
            flags <<= 1
        nflags += 1
        if nflags == 32:
            out[fpos:fpos + 4] = (flags & 0xffffffff).to_bytes(4, "little")
            flags = nflags = 0
            fpos = len(out)
            out += b"\0\0\0\0"
    flags = ((flags << (32 - nflags)) | ((1 << (32 - nflags)) - 1)) & 0xffffffff
    out[fpos:fpos + 4] = flags.to_bytes(4, "little")
    return bytes(out)


def huff_lengths(counts, maxlen=15):
    counts = list(counts)
    used = [s for s, c in enumerate(counts) if c]
    if not used:
        counts[0] = counts[1] = 1
    elif len(used) == 1:
        counts[used[0] ^ 1] = 1
    while True:
        heap = [(c, s, (s,)) for s, c in enumerate(counts) if c]
        heapq.heapify(heap)
        lens, uid = [0] * len(counts), len(counts)
        while len(heap) > 1:
            c1, _, a = heapq.heappop(heap)
            c2, _, b = heapq.heappop(heap)
            for s in a + b:
                lens[s] += 1
            heapq.heappush(heap, (c1 + c2, uid, a + b))
            uid += 1
        if max(lens) <= maxlen:
            return lens
        counts = [(c + 1) // 2 if c else 0 for c in counts]


def canonical(lens):
    codes, code = [0] * len(lens), 0
    for l in range(1, 16):
        for s in range(len(lens)):
            if lens[s] == l:
                codes[s] = code
                code += 1
        code <<= 1
    return codes


class XWriter:
    """Bit writer of Samba's MS-XCA encoder: 16-bit units fill two reserved slots ahead,
    extra length bytes go to the head of the byte stream."""
    def __init__(self, out, start):
        self.out, self.bits, self.nb = out, 0, 0
        self.next, self.pend, self.head = start, start + 2, start + 4
        self._grow()

    def _grow(self):
        if len(self.out) < self.head + 64:
            self.out.extend(bytes(self.head + 4096 - len(self.out)))

    def put(self, v, n):
        self.bits = ((self.bits << n) | v) & 0xffffffff
        self.nb += n
        if self.nb > 16:
            w = (self.bits >> (self.nb - 16)) & 0xffff
            self.nb -= 16
            self._grow()
            self.out[self.next:self.next + 2] = w.to_bytes(2, "little")
            self.next, self.pend, self.head = self.pend, self.head, self.head + 2

    def byte(self, b):
        self._grow()
        self.out[self.head] = b
        self.head += 1

    def finish(self):
        end = self.head - (2 if self.nb == 0 else 0)
        self.put(0, 16 - self.nb)
        self.put(0, 16)
        self.put(0, 16)
        return end


def xhuff_compress(data, eof=True, cross=False, block=65536):
    """[MS-XCA] LZ77+Huffman. cross=True lets matches run past the 64 KiB block end
    (the next block then starts where that match ended, as decoders expect)."""
    m = Matcher(data)
    out = bytearray()
    pos, n = 0, len(data)
    while True:
        bend = min(n, pos + block)
        toks, counts, i = [], [0] * 512, pos
        while i < bend:
            l, dist = m.find(i, n if cross else bend, 65535, 1 << 20)
            if l >= 3:
                ml = l - 3
                toks.append((256 | ((dist.bit_length() - 1) << 4) | min(ml, 15), ml, dist))
                for k in range(i, i + l):
                    m.insert(k)
                i += l
            else:
                m.insert(i)
                toks.append((data[i], 0, 0))
                i += 1
            counts[toks[-1][0]] += 1
        last = i >= n
        if last and eof:
            toks.append((256, 0, 1))
            counts[256] += 1
        lens = huff_lengths(counts)
        codes = canonical(lens)
        start = len(out)
        out += bytes(lens[2 * k] | (lens[2 * k + 1] << 4) for k in range(256))
        w = XWriter(out, start + 256)
        for sym, ml, dist in toks:
            w.put(codes[sym], lens[sym])
            if sym < 256:
                continue
            if (sym & 15) == 15:
                if ml >= 270:
                    w.byte(255)
                    for b in (ml.to_bytes(2, "little") if ml < 65535 else b"\0\0" + ml.to_bytes(4, "little")):
                        w.byte(b)
                else:
                    w.byte(ml - 15)
            ob = dist.bit_length() - 1
            if ob:
                w.put(dist - (1 << ob), ob)
        del out[w.finish():]
        pos = i
        if last:
            break
    return bytes(out)


# ---------------------------------------------------------------- container helpers

def lzfse_blocks(c):
    """[(magic, offset, size)] of the blocks of an LZFSE stream."""
    out, p = [], 0
    while p + 4 <= len(c):
        m = c[p:p + 4]
        if m == b"bvx$":
            out.append((m, p, 4))
            break
        if m == b"bvx-":
            sz = 8 + struct.unpack_from("<I", c, p + 4)[0]
        elif m == b"bvxn":
            sz = 12 + struct.unpack_from("<I", c, p + 8)[0]
        elif m == b"bvx2":
            v0, v1, v2 = struct.unpack_from("<QQQ", c, p + 8)
            sz = (v2 & 0xffffffff) + ((v0 >> 20) & 0xfffff) + ((v1 >> 40) & 0xfffff)
        else:
            break
        out.append((m, p, sz))
        p += sz
    return out


def lzfse_v2_to_v1(c):
    """Rewrite every bvx2 block with the plain bvx1 header (772 bytes)."""
    out = bytearray()
    for m, p, sz in lzfse_blocks(c):
        if m != b"bvx2":
            out += c[p:p + sz]
            continue
        n_raw = struct.unpack_from("<I", c, p + 4)[0]
        v0, v1, v2 = struct.unpack_from("<QQQ", c, p + 8)
        hs = v2 & 0xffffffff
        f = lambda v, o, n: (v >> o) & ((1 << n) - 1)
        freq, acc, an, q, end = [], 0, 0, p + 32, p + hs
        nbt = [2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14] * 2
        vt = [0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1, 0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1]
        for _ in range(360):
            while q < end and an + 8 <= 32:
                acc |= c[q] << an
                an += 8
                q += 1
            b = acc & 31
            nb = nbt[b]
            freq.append(8 + ((acc >> 4) & 15) if nb == 8 else 24 + ((acc >> 4) & 0x3ff) if nb == 14 else vt[b])
            acc >>= nb
            an -= nb
        nlp, nmp = f(v0, 20, 20), f(v1, 40, 20)
        h = struct.pack("<IIIIIIIi4HiHHH", 0x31787662, n_raw, nlp + nmp, f(v0, 0, 20), f(v0, 40, 20), nlp, nmp,
                        f(v0, 60, 3) - 7, f(v1, 0, 10), f(v1, 10, 10), f(v1, 20, 10), f(v1, 30, 10),
                        f(v1, 60, 3) - 7, f(v2, 32, 10), f(v2, 42, 10), f(v2, 52, 10))
        h += struct.pack("<360H", *freq) + b"\0\0"
        assert len(h) == 772
        out += h + c[p + hs:p + sz]
    return bytes(out)


def lzop_blocks(b):
    """[(compressed bytes, uncompressed size)] of the first file of an lzop archive."""
    p = 9
    ver = struct.unpack_from(">H", b, p)[0]
    p += 4 + (2 if ver >= 0x940 else 0) + 1 + (1 if ver >= 0x940 else 0)
    flags = struct.unpack_from(">I", b, p)[0]
    p += 4 + (4 if flags & 0x800 else 0) + 8 + (4 if ver >= 0x940 else 0)
    p += 1 + b[p] + 4
    out = []
    while True:
        dl = struct.unpack_from(">I", b, p)[0]
        p += 4
        if not dl:
            return out
        sl = struct.unpack_from(">I", b, p)[0]
        p += 4 + 4 * ((flags & 1) + bool(flags & 0x100))
        if sl < dl:
            p += 4 * (bool(flags & 2) + bool(flags & 0x200))
        out.append((b[p:p + sl], dl))
        p += sl


def wim_chunks(path):
    """Compressed chunks (offset, size, out size) of the file resources of a WIM."""
    b = open(path, "rb").read()
    chunk = struct.unpack_from("<I", b, 0x14)[0]

    def reshdr(o):
        return int.from_bytes(b[o:o + 7], "little"), b[o + 7], *struct.unpack_from("<QQ", b, o + 8)
    lsz, _, loff, _ = reshdr(0x30)
    res = []
    for e in range(loff, loff + lsz, 50):
        sz, fl, off, osz = reshdr(e)
        if not (fl & 4) or (fl & 2):
            continue
        n = (osz + chunk - 1) // chunk
        esz = 8 if osz > 0xffffffff else 4
        tab = [0] + [int.from_bytes(b[off + k * esz:off + (k + 1) * esz], "little") for k in range(n - 1)]
        base, csz = off + (n - 1) * esz, sz - (n - 1) * esz
        chunks = []
        for k in range(n):
            ce = tab[k + 1] if k + 1 < n else csz
            chunks.append((base + tab[k], ce - tab[k], min(chunk, osz - k * chunk)))
        res.append((chunks, b[e + 30:e + 50]))
    return b, res


SAMBA_SO = "/usr/lib/python3/dist-packages/samba/compression.cpython-312-x86_64-linux-gnu.so"
SAMBA_PY = r'''
import importlib.util, sys
spec = importlib.util.spec_from_file_location("samba.compression", sys.argv[5])
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
mode, fin, fout, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
d = open(fin, "rb").read()
r = {"hc": lambda: c.huffman_compress(d), "pc": lambda: c.plain_compress(d),
     "hd": lambda: c.huffman_decompress(d, n), "pd": lambda: c.plain_decompress(d, n)}[mode]()
open(fout, "wb").write(r)
'''


# ---------------------------------------------------------------- tests

def run(t):
    drv = t.build_driver("tests/drivers/misc_test.c")
    W = t.work
    cnt = [0]
    # tests/gzt.c does not free its context when an archive fails to open: not our leak
    lsan = t.path("lsan.supp")
    open(lsan, "w").write("leak:gz_ctx_new\n")

    def hostile(path):
        label = "hostile " + os.path.basename(path)
        try:
            r, rows, out = t.extract(path, env={"LSAN_OPTIONS": "suppressions=" + lsan}, timeout=30)
        except subprocess.TimeoutExpired:
            return t.record(False, label, "timeout")
        err = r.stderr.decode(errors="replace")
        bad = r.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err
        return t.record(not bad, label, "rc=%d %s" % (r.returncode, err[-300:] if bad else ""))

    def dec(codec, comp, cap):
        cnt[0] += 1
        p, o = t.path("in_%d.bin" % cnt[0]), t.path("out_%d.bin" % cnt[0])
        open(p, "wb").write(comp)
        r = t.sh([drv, "d", codec, p, o, str(cap)], timeout=120)
        f = dict(kv.split("=") for kv in r.stdout.decode().split())
        out = open(o, "rb").read()
        os.remove(p)
        os.remove(o)
        return int(f["rc"]), out, int(f["used"])

    def check(codec, comp, data, label, cap=None, rc=0, used=None):
        r, out, u = dec(codec, comp, len(data) if cap is None else cap)
        ok = r == rc and out == data and (used is None or u == used)
        return t.record(ok, label, "" if ok else "rc=%d out=%d/%d used=%d" % (r, len(out), len(data), u))

    def expect_rc(codec, comp, cap, rcs, label, prefix=None):
        r, out, u = dec(codec, comp, cap)
        ok = r in rcs and (prefix is None or out == prefix[:len(out)])
        return t.record(ok, label, "rc=%d out=%d" % (r, len(out)))

    corpus = [("mixed", sample(150000, 3)), ("random", os.urandom(30000)), ("tiny", b"ab"),
              ("one", b"x"), ("zeros", bytes(100000)), ("period3", b"abc" * 30000),
              ("text", b"".join(b"line %d of the misc codec test\n" % i for i in range(5000)))]
    fuzz_inputs = {}

    # ---------------- ADC ----------------
    for name, d in corpus:
        z = adc_compress(d)
        check("adc", z, d, "adc %s" % name, used=len(z))
        if name == "mixed":
            fuzz_inputs["adc"] = (z[:6000], 20000)
            check("adc", z, d[:77777], "adc output cut at cap", cap=77777)
    check("adc", b"", b"", "adc empty")
    expect_rc("adc", b"\x01\x00", 64, (3,), "adc distance before start")
    expect_rc("adc", b"\x80a\x40\x00", 64, (9,), "adc truncated 3-byte op")
    expect_rc("adc", b"\x85abc", 64, (9,), "adc truncated literal")
    check("adc", b"\x80a\x3c\x00", b"a" * 19, "adc 2-byte max match")
    check("adc", b"\x80a\x7f\x00\x00", b"a" * 68, "adc 3-byte max match")

    # ---------------- LZNT1 ----------------
    for name, d in corpus:
        z = lznt1_compress(d)
        check("lznt1", z, d, "lznt1 %s" % name)
        if name == "mixed":
            fuzz_inputs["lznt1"] = (z[:9000], 20000)
            check("lznt1", lznt1_compress(d, store=True), d, "lznt1 stored chunks")
            check("lznt1", z + b"\0\0garbage", d, "lznt1 zero header ends")
            check("lznt1", z, d[:65536], "lznt1 unit cut at 64 KiB", cap=65536)
    rnd = os.urandom(4096 * 3)
    mixed = lznt1_compress(rnd[:4096], store=True) + lznt1_compress(b"A" * 4096) + lznt1_compress(rnd[4096:])
    check("lznt1", mixed, rnd[:4096] + b"A" * 4096 + rnd[4096:], "lznt1 stored/compressed mix")
    # a short compressed chunk is zero-padded to 4 KiB when another chunk follows
    short = lznt1_compress(b"hello world" * 10)
    check("lznt1", short + lznt1_compress(b"next"), (b"hello world" * 10).ljust(4096, b"\0") + b"next",
          "lznt1 short chunk padding")
    check("lznt1", short, b"hello world" * 10, "lznt1 last chunk not padded")
    expect_rc("lznt1", b"\x02\xb0\x01\x00\x00", 4096, (3,), "lznt1 match at chunk start")
    expect_rc("lznt1", b"\xff\xbf\x00", 8192, (9,), "lznt1 chunk past input")
    over = b"\x02a" + (0x0fff).to_bytes(2, "little")         # literal, then a 4098-byte match
    expect_rc("lznt1", b"\x03\xb0" + over, 8192, (3,), "lznt1 match past chunk end")

    # ---------------- XPRESS plain ----------------
    for name, d in corpus:
        z = xpress_compress(d)
        check("xpress", z, d, "xpress %s" % name)
        if name == "mixed":
            fuzz_inputs["xpress"] = (z[:7000], 20000)
    long = b"q" + bytes(70000) + b"r" + b"\1" * 300
    check("xpress", xpress_compress(long), long, "xpress 32-bit match length")
    check("xpress", xpress_compress(b"abc" * 100)[:-1], b"abc", "xpress cut input", cap=300, rc=9)
    expect_rc("xpress", b"\0\0\0\x80\x08\x00", 64, (3,), "xpress distance before start")

    # ---------------- XPRESS Huffman ----------------
    big = sample(300001, 11)
    xh_cases = corpus + [("multi", big), ("skewed", skewed(70000)), ("exact64k", big[:65536])]
    for name, d in xh_cases:
        if not d:
            continue
        z = xhuff_compress(d)
        check("xhuff", z, d, "xhuff %s" % name)
    check("xhuff", xhuff_compress(big, eof=False), big, "xhuff without end symbol")
    cross = b"z" + bytes(200000) + sample(70000, 5)
    check("xhuff", xhuff_compress(cross, cross=True), cross, "xhuff matches across blocks")
    zx = xhuff_compress(sample(20000, 7))
    fuzz_inputs["xhuff"] = (zx, 20000)
    expect_rc("xhuff", zx[:200], 20000, (9,), "xhuff short table")
    expect_rc("xhuff", zx[:len(zx) // 2], 20000, (3, 9), "xhuff truncated stream")
    expect_rc("xhuff", bytes(256) + b"\0" * 8, 100, (3,), "xhuff empty code")
    expect_rc("xhuff", b"\x11" * 256 + b"\0" * 8, 100, (3,), "xhuff over-subscribed code")
    check("xhuff", b"", b"", "xhuff zero output")

    # independent decoders of our encoders' output
    try:
        import dissect.util.compression.lznt1 as dl
        import dissect.util.compression.lzxpress as dx
        import dissect.util.compression.lzxpress_huffman as dh
        d = sample(100000, 21)
        t.record(dl.decompress(lznt1_compress(d)) == d, "dissect lznt1 decodes our LZNT1")
        t.record(dx.decompress(xpress_compress(d)) == d, "dissect lzxpress decodes our XPRESS")
        t.record(dh.decompress(xhuff_compress(d))[:len(d)] == d, "dissect lzxpress_huffman decodes ours")
    except ImportError:
        pass
    if os.path.exists(SAMBA_SO) and shutil.which("python3.12"):
        sp = t.path("samba.py")
        open(sp, "w").write(SAMBA_PY)

        def samba(mode, d, n=0):
            fi, fo = t.path("samba.in"), t.path("samba.out")
            open(fi, "wb").write(d)
            r = subprocess.run(["python3.12", "-I", sp, mode, fi, fo, str(n), SAMBA_SO], capture_output=True)
            return open(fo, "rb").read() if r.returncode == 0 else None
        for sz in (100, 65536, 65537, 300001):
            d = big[:sz]
            hz, pz = samba("hc", d), samba("pc", d)
            if hz is None or pz is None:
                break
            check("xhuff", hz, d, "samba huffman -> ours %d" % sz)
            check("xpress", pz, d, "samba plain -> ours %d" % sz)
            t.record(samba("hd", xhuff_compress(d), sz) == d, "ours huffman -> samba %d" % sz)
            t.record(samba("pd", xpress_compress(d), sz) == d, "ours plain -> samba %d" % sz)

    # WIM resources compressed by wimlib (XPRESS = LZ77+Huffman, 4 KiB .. 64 KiB chunks)
    if t.tool("wimlib-imagex"):
        src = t.write_tree(os.path.join(W, "wimsrc"), {"f%d.bin" % i: sample(20000 + 37000 * i, 30 + i)
                                                        for i in range(5)})
        import hashlib
        for cs in (4096, 32768, 65536):
            wim = t.path("x%d.wim" % cs)
            if os.path.exists(wim):
                os.remove(wim)
            t.sh(["wimlib-imagex", "capture", src, wim, "--compress=XPRESS", "--chunk-size=%d" % cs])
            b, res = wim_chunks(wim)
            jobs, stored = [], []
            for chunks, sha in res:
                jobs += ["%d %d %d" % c for c in chunks if c[1] != c[2]]
            open(t.path("jobs"), "w").write("\n".join(jobs) + "\n")
            r = t.sh([drv, "batch", "xhuff", wim, t.path("jobs"), t.path("wimout")])
            dec_out = open(t.path("wimout"), "rb").read()
            pos, good = 0, 0
            for chunks, sha in res:
                buf = bytearray()
                for o, l, u in chunks:
                    if l == u:
                        buf += b[o:o + l]
                    else:
                        buf += dec_out[pos:pos + u]
                        pos += u
                good += hashlib.sha1(buf).digest() == sha
            t.record(b"bad=0" in r.stdout and good == len(res) and res, "wim xpress chunks %d" % cs,
                     "%s sha ok %d/%d" % (r.stdout.decode().strip(), good, len(res)))

    # ---------------- LZFSE / LZVN ----------------
    if t.tool("lzfse"):
        def lzfse_enc(d):
            fi, fo = t.path("lz.in"), t.path("lz.lzfse")
            open(fi, "wb").write(d)
            t.sh(["lzfse", "-encode", "-i", fi, "-o", fo])
            return open(fo, "rb").read()
        lz_cases = [(n, d) for n, d in corpus if d] + [("s4095", sample(4095, 1)), ("s4096", sample(4096, 2)),
                                                         ("multi", big + sample(800000, 12)), ("rand200k", os.urandom(200000))]
        for name, d in lz_cases:
            z = lzfse_enc(d)
            kinds = sorted(set(m.decode() for m, _, _ in lzfse_blocks(z)))
            check("lzfse", z, d, "lzfse %s (%s)" % (name, ",".join(kinds)), used=len(z))
            if b"bvx2" in [m for m, _, _ in lzfse_blocks(z)]:
                check("lzfse", lzfse_v2_to_v1(z), d, "lzfse %s as bvx1" % name)
            if kinds == ["bvx$", "bvxn"]:
                p, sz = lzfse_blocks(z)[0][1:]
                check("lzvn", z[p + 12:p + sz], d, "lzvn raw %s" % name, used=sz - 12)
            fs = t.path("size.lzfse")
            open(fs, "wb").write(z + b"trailing")
            r = t.sh([drv, "size", fs]).stdout.decode()
            t.record(r.strip() == "rc=0 size=%d used=%d" % (len(d), len(z)), "lzfse size %s" % name, r.strip())
            if name == "mixed":
                fuzz_inputs["lzfse"] = (z, len(d))
                expect_rc("lzfse", z, len(d) - 1, (3,), "lzfse output larger than cap")
                expect_rc("lzfse", z[:-4], len(d), (9,), "lzfse missing end block")
            if name == "s4095":
                fuzz_inputs["lzfse_vn"] = (z, len(d))
                vn = [(p, sz) for m, p, sz in lzfse_blocks(z) if m == b"bvxn"][0]
                fuzz_inputs["lzvn"] = (z[vn[0] + 12:vn[0] + vn[1]], len(d))
        # stored blocks + a stream of several kinds of blocks back to back (matches cross blocks)
        a, b2 = sample(5000, 40), sample(100000, 41)
        raw = b"bvx-" + struct.pack("<I", len(a)) + a
        z2 = lzfse_enc(b2)
        stitched = raw + z2[:-4] + b"bvx-" + struct.pack("<I", 3) + b"end" + b"bvx$"
        check("lzfse", stitched, a + b2 + b"end", "lzfse stored + compressed blocks")
        check("lzfse", b"bvx$", b"", "lzfse empty stream")
        expect_rc("lzfse", b"bvxz\0\0\0\0", 16, (3,), "lzfse bad magic")
        expect_rc("lzfse", b"bvxn" + struct.pack("<II", 0, 8) + b"\x06" + bytes(7) + b"bvx$", 16, (3,),
                  "lzfse empty lzvn block")
        # LZVN opcodes
        check("lzvn", b"\xe3abc\x00\x03\xf0\x00" + b"\x06" + bytes(7), (b"abc" * 8)[:22], "lzvn sml_d + lrg_m")
        expect_rc("lzvn", b"\xf3\x06" + bytes(7), 64, (3,), "lzvn match without distance")
        expect_rc("lzvn", b"\x70\x00\x06" + bytes(7), 64, (3,), "lzvn undefined opcode")
        expect_rc("lzvn", b"\xe3abc", 64, (9,), "lzvn missing end opcode")
        check("lzvn", b"\x0e\x16\xe1z\x06" + bytes(7), b"z", "lzvn nops")

    # ---------------- LZO1X raw blocks + lzop files ----------------
    if t.tool("lzop"):
        def lzop(args, data, name="data.bin", stdin=False):
            fi, fo = t.path("lzsrc", name), t.path("lzop.lzo")
            open(fi, "wb").write(data)
            if os.path.exists(fo):
                os.remove(fo)
            if stdin:
                fo2 = open(fo, "wb")
                subprocess.run(["lzop", "-c"] + args, stdin=open(fi, "rb"), stdout=fo2, check=True)
                fo2.close()
            else:
                t.sh(["lzop", "-f", "-o", fo] + args + [fi])
            return open(fo, "rb").read()
        blobs = []
        for name, d in corpus + [("multi", big * 2)]:
            for lvl in ("-1", "-9"):
                for blk, dl in lzop_blocks(lzop([lvl], d)):
                    if len(blk) < dl:
                        blobs.append((blk, dl))
        allb = b"".join(b for b, _ in blobs)
        open(t.path("lzo.blob"), "wb").write(allb)
        jobs, off = [], 0
        for b_, dl in blobs:
            jobs.append("%d %d %d" % (off, len(b_), dl))
            off += len(b_)
        open(t.path("lzo.jobs"), "w").write("\n".join(jobs) + "\n")
        r = t.sh([drv, "batch", "lzo", t.path("lzo.blob"), t.path("lzo.jobs"), t.path("lzo.out")])
        t.record(b"bad=0" in r.stdout and len(blobs) > 10, "lzo1x raw blocks", r.stdout.decode().strip())
        fuzz_inputs["lzo"] = blobs[0]
        z = blobs[0][0]
        expect_rc("lzo", z[:-3], blobs[0][1], (9,), "lzo1x missing end marker")
        expect_rc("lzo", z, blobs[0][1] - 1, (3,), "lzo1x output larger than cap")
        check("lzo", b"\x11\0\0", b"", "lzo1x empty block")

        # lzop files through the archive layer, against lzop -dc
        def lzop_case(label, args, data, name="data.bin", stdin=False, want=None, ext="lzo"):
            z = lzop(args, data, name, stdin)
            arc = t.path("%s.%s" % (label.replace(" ", "_"), ext))
            open(arc, "wb").write(z)
            ref = subprocess.run(["lzop", "-dc", arc], capture_output=True).stdout
            if ref != data:
                return t.record(False, label, "lzop -dc disagrees")
            return t.check_extract(arc, {want or name: data}, label="lzop " + label, expect_type="LZO")
        text = b"".join(b"%d: lzop test line, gogi zip\n" % i for i in range(60000))
        for lvl in ("-1", "-3", "-7", "-8", "-9"):
            lzop_case("level %s" % lvl, [lvl], text)
        lzop_case("adler32 both", ["-CC"], text)
        lzop_case("crc32 both", ["--crc32", "-CC"], text)
        lzop_case("no checksum", ["-F"], text)
        lzop_case("random data", [], os.urandom(600000))
        lzop_case("empty file", [], b"")
        lzop_case("multi block", ["-9"], big * 4)
        for f in (1, 2, 4, 16):
            lzop_case("filter %d" % f, ["--filter=%d" % f], sample(300000, 50 + f))
        lzop_case("stdin", [], text[:5000], name="piped.bin", stdin=True, want="stdin")
        # a tarball inside: entries are listed and extracted one by one
        tb = io.BytesIO()
        files = {"dir/a.txt": text[:100000], "dir/b.bin": os.urandom(5000), "c.txt": b"cee"}
        with tarfile.open(fileobj=tb, mode="w", format=tarfile.GNU_FORMAT) as tf:
            for k, v in files.items():
                ti = tarfile.TarInfo(k)
                ti.size = len(v)
                tf.addfile(ti, io.BytesIO(v))
        z = lzop([], tb.getvalue(), "x.tar")
        for ext in ("tar.lzo", "tzo"):
            arc = t.path("tarball." + ext)
            open(arc, "wb").write(z)
            t.check_extract(arc, files, label="lzop tarball ." + ext, expect_type="TAR.LZO")
        # concatenated files decode back to back like lzop -dc
        z1, z2 = lzop([], b"first part\n", "one.txt"), lzop(["-9"], text[:20000], "two.txt")
        arc = t.path("concat.lzo")
        open(arc, "wb").write(z1 + z2)
        t.check_extract(arc, {"one.txt": b"first part\n" + text[:20000]}, label="lzop concatenated files")
        r, typ, rows = t.listing(t.path("level_-9.lzo"))
        t.record(rows and rows[0]["usize"] == len(text) and rows[0]["method"] == "LZO1X",
                 "lzop listing size + method", str(rows[:1]))
        # corrupt data: checksum / structure errors are reported, nothing crashes
        z = bytearray(lzop(["-CC"], text))
        z[len(z) // 2] ^= 0x20
        arc = t.path("corrupt.lzo")
        open(arc, "wb").write(z)
        rr, rows, _ = t.extract(arc)
        t.record(rr.returncode == 0 and rows and rows[0][0] != 0, "lzop corrupt block reported", str(rows))
        zt = lzop(["-9"], text)
        rng = random.Random(5)
        for i in range(12):
            h = bytearray(zt[:rng.randrange(40, len(zt))])
            for _ in range(rng.randrange(0, 4)):
                h[rng.randrange(len(h))] ^= 1 << rng.randrange(8)
            p = t.path("hostile_%d.lzo" % i)
            open(p, "wb").write(h)
            hostile(p)
        bad = bytearray(zt[:80])
        hdr = 9 + 2 + 2 + 2 + 1 + 1 + 4 + 4 + 4 + 4 + 1 + len("data.bin") + 4
        bad[hdr:hdr + 8] = struct.pack(">II", 0x7fffffff, 0x10)       # absurd block size
        p = t.path("hostile_bigblock.lzo")
        open(p, "wb").write(bytes(bad))
        hostile(p)

    # ---------------- differential fuzzing against reference libraries ----------------
    variants = [("-DHAVE_LZO", "-l:liblzo2.so.2"), ("-DHAVE_LZFSE", "-llzfse"), ("-DHAVE_WIM", "-l:libwim.so.15")]
    have = []
    for v in variants:
        try:
            t.build_driver("tests/drivers/misc_ref.c", "misc_ref_probe", extra=list(v))
            have.append(v)
        except RuntimeError:
            pass
    refd = None
    if have:
        refd = t.build_driver("tests/drivers/misc_ref.c", "misc_ref",
                              extra=[v[0] for v in have] + [v[1] for v in have])
        have = [v[0] for v in have]
    if refd:
        iters = "4000" if "sanitize" in os.environ.get("HOST_CFLAGS", "") else "20000"
        if "-DHAVE_LZO" in have:
            r = t.sh([refd, "lzogen", "300", "1"], check=False)
            t.record(r.returncode == 0, "liblzo2 compressors -> ours", r.stdout.decode().strip())
            if "lzo" in fuzz_inputs:
                p = t.path("ref.lzo1x")
                open(p, "wb").write(fuzz_inputs["lzo"][0])
                r = t.sh([refd, "lzo", p, iters, "2"], check=False)
                t.record(r.returncode == 0, "lzo1x mutations agree with liblzo2", r.stdout.decode().strip())
        if "-DHAVE_LZFSE" in have:
            for k in ("lzfse", "lzfse_vn"):
                if k in fuzz_inputs:
                    p = t.path("ref_%s.lzfse" % k)
                    open(p, "wb").write(fuzz_inputs[k][0])
                    r = t.sh([refd, "lzfse", p, iters, "3"], check=False)
                    t.record(r.returncode == 0, "%s mutations agree with liblzfse" % k, r.stdout.decode().strip())
        if "-DHAVE_WIM" in have:
            r = t.sh([refd, "xhuffgen", "1500", "4"], check=False)
            t.record(r.returncode == 0, "wimlib xpress compressor -> ours", r.stdout.decode().strip())
            p = t.path("ref_xh.bin")
            open(p, "wb").write(big[:200000])
            r = t.sh([refd, "xhuff", p, str(int(iters) // 4), "5"], check=False)
            t.record(r.returncode == 0, "xpress mutations agree with wimlib", r.stdout.decode().strip())

    # ---------------- mutation fuzzing (no crash / hang / overrun; ASan in sanitizer runs) ----------------
    iters = "1500" if "sanitize" in os.environ.get("HOST_CFLAGS", "") else "4000"
    for k, (z, n) in sorted(fuzz_inputs.items()):
        codec = {"lzfse_vn": "lzfse"}.get(k, k)
        p = t.path("fuzz_%s.bin" % k)
        open(p, "wb").write(z)
        try:
            r = t.sh([drv, "fuzz", codec, p, str(n), iters, "7"], check=False, timeout=300)
            err = r.stderr.decode(errors="replace")
            ok = r.returncode == 0 and "Sanitizer" not in err and "runtime error" not in err
            t.record(ok, "fuzz %s" % k, r.stdout.decode().strip() + err[-400:])
        except subprocess.TimeoutExpired:
            t.record(False, "fuzz %s" % k, "timeout")

    # ---------------- other CPUs: AArch64 (QEMU) and 32-bit i586 give identical results ----------------
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    srcs = [os.path.join(root, f) for f in ["tests/drivers/misc_test.c", "src/posix/plat_posix.c", "src/core/str.c"] +
            ["src/codec/%s.c" % c for c in ("adc", "lznt1", "lzo", "lzfse", "xpress")]]
    inc = ["-I" + os.path.join(root, d) for d in ("src/core", "src/codec", "src/fmt", "src/posix")]
    qenv = dict(os.environ, QEMU_LD_PREFIX="/usr/aarch64-linux-gnu")
    for arch, cc, flags, runner in (("aarch64", "aarch64-linux-gnu-gcc", [], ["qemu-aarch64", "-cpu", "max"]),
                                    ("i586", os.environ.get("HOSTCC", "cc"), ["-m32", "-march=i586"], [])):
        if not shutil.which(cc) or (runner and not shutil.which(runner[0])) or sys.platform != "linux":
            continue
        exe = t.path("misc_test_" + arch)
        r = subprocess.run([cc, "-std=gnu11", "-O2"] + flags + inc + ["-o", exe] + srcs + ["-pthread"], capture_output=True)
        if r.returncode:
            continue                                  # no cross / multilib toolchain
        same = []
        for k, (z, n) in sorted(fuzz_inputs.items()):
            codec = {"lzfse_vn": "lzfse"}.get(k, k)
            p = t.path("fuzz_%s.bin" % k)
            a1 = subprocess.run([drv, "fuzz", codec, p, str(n), "300", "9"], capture_output=True, timeout=300).stdout
            a2 = subprocess.run(runner + [exe, "fuzz", codec, p, str(n), "300", "9"], capture_output=True,
                                env=qenv, timeout=300).stdout
            o1, o2 = t.path("x86.out"), t.path("arch.out")
            b1 = subprocess.run([drv, "d", codec, p, o1, str(n)], capture_output=True).stdout
            b2 = subprocess.run(runner + [exe, "d", codec, p, o2, str(n)], capture_output=True, env=qenv).stdout
            if a1 != a2 or b1 != b2 or open(o1, "rb").read() != open(o2, "rb").read():
                same.append(k)
        t.record(not same, "%s build agrees with host" % arch, ("differs: " + " ".join(same)) if same else
                 "%d codecs, 300 mutations each" % len(fuzz_inputs))

    # ---------------- speed (informational) ----------------
    if "sanitize" not in os.environ.get("HOST_CFLAGS", "") and t.verbose:
        d = sample(1 << 20, 99)
        for codec, fn in (("adc", adc_compress), ("lznt1", lznt1_compress), ("xpress", xpress_compress),
                          ("xhuff", xhuff_compress)):
            p = t.path("bench.%s" % codec)
            open(p, "wb").write(fn(d))
            r = t.sh([drv, "bench", codec, p, str(len(d)), "300"], check=False)
            t.record(r.returncode == 0, "speed %s" % codec, r.stdout.decode().strip())
