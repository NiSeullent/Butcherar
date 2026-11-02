"""LZMA / LZMA2 decoders, BCJ + Delta filters and BCJ2 (src/codec/lzma.c, bcj.c, bcj2.c).

Everything goes through tests/drivers/lzma_test.c. References: xz (raw LZMA1 / LZMA2 /
filter chains), Python's lzma module, 7-Zip (.7z with LZMA lc8/lp4, multi-block LZMA2,
BCJ2), the XZ Utils conformance files in tests/data/codec_lzma, and a Python port of
the xz 5.6 RISC-V filter (the installed xz may predate it).
"""
import os, random, struct, subprocess, zlib, hashlib, lzma, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA = os.path.join(ROOT, "tests", "data", "codec_lzma")

GZ_OK, GZ_E_DATA, GZ_E_TRUNC, GZ_E_LIMIT = 0, 3, 9, 15

# ---------------------------------------------------------------- data sets

def gen_text(n, seed=1):
    rnd = random.Random(seed)
    words = ["고기", "삼겹살", "lzma", "range", "coder", "dictionary", "the", "of", "and",
             "0x%04x" % 4660, "\n", "    ", "return", "static", "u32", "Bandizip"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words).encode() + b" "
        if rnd.random() < 0.02:
            out += bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 40)))
    return bytes(out[:n])

def gen_random(n, seed=2):
    return random.Random(seed).randbytes(n)

def gen_bins(n, dirs=("/usr/bin",), seed=0):
    out = bytearray()
    files = []
    for d in dirs:
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                p = os.path.join(d, f)
                if os.path.isfile(p) and not os.path.islink(p) and os.path.getsize(p) > 4096:
                    files.append(p)
    random.Random(seed).shuffle(files)
    for p in files:
        try:
            out += open(p, "rb").read()
        except OSError:
            continue
        if len(out) >= n:
            break
    return bytes(out[:n])

def gen_mixed(n, seed=3):
    rnd = random.Random(seed)
    parts = []
    while sum(map(len, parts)) < n:
        k = rnd.random()
        m = rnd.randint(1000, 120000)
        if k < 0.4:
            parts.append(gen_text(m, rnd.getrandbits(16)))
        elif k < 0.55:
            parts.append(gen_random(m, rnd.getrandbits(16)))
        elif k < 0.7:
            parts.append(bytes([rnd.getrandbits(8)]) * m)
        elif k < 0.85:
            pat = rnd.randbytes(rnd.randint(2, 9))
            parts.append((pat * (m // len(pat) + 1))[:m])
        elif parts:
            src = rnd.choice(parts)            # long-distance repeat
            parts.append(src[: min(m, len(src))])
    return b"".join(parts)[:n]

# ---------------------------------------------------------------- synthetic machine code

def synth_code(arch, n, seed=7):
    rnd = random.Random(seed)
    o = bytearray()
    while len(o) < n:
        r = rnd.random()
        if arch == "x86":
            if r < 0.12:
                o += b"\xe8" + struct.pack("<i", rnd.randint(-70000, 70000))
            elif r < 0.2:
                o += b"\xe9" + struct.pack("<I", rnd.getrandbits(32))
            elif r < 0.25:
                o += bytes([0xE8, rnd.choice([0, 0xFF, 0xE8, 0xE9]), 0xFF, 0x00, 0xE9, 0xFF])
            elif r < 0.3:
                o += b"\x0f" + bytes([0x80 | rnd.getrandbits(4)]) + struct.pack("<i", rnd.randint(-999, 999))
            else:
                o += rnd.randbytes(rnd.randint(1, 6))
        elif arch == "arm":
            o += struct.pack("<I", (0xEB000000 | rnd.getrandbits(24)) if r < 0.3 else rnd.getrandbits(32))
        elif arch == "armt":
            if r < 0.3:
                o += struct.pack("<HH", 0xF000 | rnd.getrandbits(11), 0xF800 | rnd.getrandbits(11))
            elif r < 0.33:
                o += rnd.randbytes(1)                    # misalign the halfword stream
            else:
                o += struct.pack("<H", rnd.getrandbits(16))
        elif arch == "ppc":
            o += struct.pack(">I", (0x48000001 | rnd.getrandbits(24) << 2) if r < 0.3 else rnd.getrandbits(32))
        elif arch == "sparc":
            if r < 0.15:
                o += struct.pack(">I", 0x40000000 | rnd.getrandbits(22))
            elif r < 0.3:
                o += struct.pack(">I", 0x7FC00000 | rnd.getrandbits(22))
            else:
                o += struct.pack(">I", rnd.getrandbits(32))
        elif arch == "ia64":
            b = rnd.getrandbits(128)
            b = (b & ~0x1F) | rnd.choice([0x10, 0x11, 0x12, 0x13, 0x16, 0x17, 0x18, 0x19, 0x1C, 0x1D, 0x05])
            for slot in range(3):
                if rnd.random() < 0.6:
                    pos = 5 + 41 * slot
                    ins = (b >> pos) & ((1 << 41) - 1)
                    ins = (ins & ~(0xF << 37)) | (5 << 37)
                    ins &= ~(7 << 9)
                    b = (b & ~(((1 << 41) - 1) << pos)) | (ins << pos)
            o += b.to_bytes(16, "little")
        elif arch == "arm64":
            if r < 0.2:
                o += struct.pack("<I", 0x94000000 | rnd.getrandbits(26))
            elif r < 0.4:
                immhi = rnd.getrandbits(19) if rnd.random() < 0.3 else (rnd.getrandbits(16) | (0x7F000 if rnd.random() < 0.5 else 0))
                o += struct.pack("<I", 0x90000000 | rnd.getrandbits(2) << 29 | (immhi & 0x7FFFF) << 5 | rnd.getrandbits(5))
            else:
                o += struct.pack("<I", rnd.getrandbits(32))
        elif arch == "riscv":
            if r < 0.15:                                  # JAL ra/t0
                o += struct.pack("<I", 0x6F | rnd.choice([1, 5]) << 7 | rnd.getrandbits(20) << 12)
            elif r < 0.35:                                # AUIPC + matching inst2
                rd = rnd.choice([1, 3, 5, 6, 7, 10, 11, 31])
                o += struct.pack("<I", 0x17 | rd << 7 | rnd.getrandbits(20) << 12)
                rs1 = rd if rnd.random() < 0.8 else rnd.getrandbits(5)
                low = rnd.choice([0x67, 0x13, 0x03 | 3 << 12, 0x23 | 3 << 12, rnd.getrandbits(7) | 3])
                o += struct.pack("<I", (low & 0x7FFF) | rs1 << 15 | rnd.getrandbits(12) << 20 | (rnd.getrandbits(5) << 7 if low in (0x67, 0x13) else 0))
            elif r < 0.45:                                # AUIPC x0 / x2 (special format, fake pairs)
                o += struct.pack("<I", 0x17 | rnd.choice([0, 2]) << 7 | rnd.getrandbits(20) << 12)
                o += struct.pack("<I", rnd.getrandbits(32))
            elif r < 0.55:
                o += struct.pack("<H", rnd.getrandbits(16) & ~3 | rnd.getrandbits(2))   # compressed
            else:
                o += rnd.randbytes(rnd.choice([2, 4]))
    return bytes(o[:n])

# ---------------------------------------------------------------- RISC-V reference (xz 5.6 riscv.c)

M32 = 0xFFFFFFFF

def _rd32(b, i): return struct.unpack_from("<I", b, i)[0]
def _wr32(b, i, v): struct.pack_into("<I", b, i, v & M32)
def _wr32be(b, i, v): struct.pack_into(">I", b, i, v & M32)

def _not_auipc_pair(auipc, inst2):
    return (((auipc << 8) & M32) ^ ((inst2 - 3) & M32)) & 0xF8003

def _not_special_auipc(auipc, rs1):
    return ((((auipc - 0x3117) & M32) << 18) & M32) >= (rs1 & 0x1D)

def riscv_encode_ref(data, now_pos=0):
    """Whole-stream RISC-V encoding as xz does it (the tail < 8 bytes stays unfiltered)."""
    buf = bytearray(data)
    size = len(buf)
    if size < 8:
        return bytes(buf)
    size -= 8
    i = 0
    while i <= size:
        inst = buf[i]
        if inst == 0xEF:
            b1 = buf[i + 1]
            if b1 & 0x0D:
                i += 2
                continue
            b2, b3 = buf[i + 2], buf[i + 3]
            pc = (now_pos + i) & M32
            addr = ((b1 & 0xF0) << 8) | ((b2 & 0x0F) << 16) | ((b2 & 0x10) << 7) | \
                   ((b2 & 0xE0) >> 4) | ((b3 & 0x7F) << 4) | ((b3 & 0x80) << 13)
            addr = (addr + pc) & M32
            buf[i + 1] = (b1 & 0x0F) | ((addr >> 13) & 0xF0)
            buf[i + 2] = (addr >> 9) & 0xFF
            buf[i + 3] = (addr >> 1) & 0xFF
            i += 4
        elif (inst & 0x7F) == 0x17:
            inst = _rd32(buf, i)
            if inst & 0xE80:
                inst2 = _rd32(buf, i + 4)
                if _not_auipc_pair(inst, inst2):
                    i += 6
                    continue
                addr = inst & 0xFFFFF000
                addr = (addr + (inst2 >> 20) - ((inst2 >> 19) & 0x1000)) & M32
                addr = (addr + now_pos + i) & M32
                _wr32(buf, i, 0x17 | (2 << 7) | ((inst2 << 12) & M32))
                _wr32be(buf, i + 4, addr)
            else:
                fake_rs1 = inst >> 27
                if _not_special_auipc(inst, fake_rs1):
                    i += 4
                    continue
                fake_addr = _rd32(buf, i + 4)
                fake_inst2 = (inst >> 12) | ((fake_addr << 20) & M32)
                _wr32(buf, i, 0x17 | (fake_rs1 << 7) | (fake_addr & 0xFFFFF000))
                _wr32(buf, i + 4, fake_inst2)
            i += 8
        else:
            i += 2
    return bytes(buf)

# ---------------------------------------------------------------- container parsers (test only)

def read_vli(d, p):
    v, s = 0, 0
    while True:
        b = d[p]
        p += 1
        v |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            return v, p

XZ_FILTERS = {0x03: "delta", 0x04: "x86", 0x05: "ppc", 0x06: "ia64", 0x07: "arm", 0x08: "armt",
              0x09: "sparc", 0x0A: "arm64", 0x0B: "riscv"}

def parse_xz_block(d):
    """First block of an .xz file: (data offset, decode spec, check type, comp size, uncomp size)."""
    assert d[:6] == b"\xfd7zXZ\x00"
    check = d[7] & 0x0F
    p = 12
    hsize = (d[p] + 1) * 4
    flags = d[p + 1]
    q = p + 2
    csize = usize = None
    if flags & 0x40:
        csize, q = read_vli(d, q)
    if flags & 0x80:
        usize, q = read_vli(d, q)
    filters = []
    for _ in range((flags & 3) + 1):
        fid, q = read_vli(d, q)
        psz, q = read_vli(d, q)
        filters.append((fid, d[q:q + psz]))
        q += psz
    spec = None
    chain = []
    for fid, props in filters:
        if fid == 0x21:
            spec = "lzma2:%d" % props[0]
        elif fid == 0x03:
            chain.append("delta:%d" % (props[0] + 1))
        else:
            start = struct.unpack("<I", props)[0] if len(props) == 4 else 0
            chain.append("%s:%d" % (XZ_FILTERS[fid], start))
    spec += "".join("+" + c for c in reversed(chain))       # decoding order
    return p + hsize, spec, check, csize, usize

def xz_check(kind, data):
    if kind == 0:
        return b""
    if kind == 1:
        return struct.pack("<I", zlib.crc32(data))
    if kind == 4:
        poly, crc = 0xC96C5795D7870F42, 0xFFFFFFFFFFFFFFFF
        table = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ poly if c & 1 else c >> 1
            table.append(c)
        for b in data:
            crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
        return struct.pack("<Q", crc ^ 0xFFFFFFFFFFFFFFFF)
    if kind == 10:
        return hashlib.sha256(data).digest()
    raise ValueError(kind)

def parse_7z(path):
    """Folders of a 7z archive with an unencoded header (-mhc=off)."""
    d = open(path, "rb").read()
    assert d[:6] == b"7z\xbc\xaf\x27\x1c"
    nh_off = struct.unpack_from("<Q", d, 12)[0]
    p = [32 + nh_off]

    def byte():
        v = d[p[0]]
        p[0] += 1
        return v

    def num():
        first = byte()
        mask, val = 0x80, 0
        for i in range(8):
            if not first & mask:
                return val | ((first & (mask - 1)) << (8 * i))
            val |= byte() << (8 * i)
            mask >>= 1
        return val

    def skip_digests(n):
        alldef = byte()
        if alldef:
            defined = n
        else:
            bits = 0
            for i in range((n + 7) // 8):
                bits += bin(byte()).count("1")
            defined = bits
        p[0] += 4 * defined

    assert byte() == 0x01, "header must not be encoded"
    assert byte() == 0x04
    assert byte() == 0x06
    pack_pos, npack = num(), num()
    sizes = []
    t = byte()
    while t:
        if t == 0x09:
            sizes = [num() for _ in range(npack)]
        elif t == 0x0A:
            skip_digests(npack)
        t = byte()
    assert byte() == 0x07 and byte() == 0x0B
    nfold = num()
    assert byte() == 0
    folders = []
    for _ in range(nfold):
        coders = []
        for _ in range(num()):
            fl = byte()
            cid = d[p[0]:p[0] + (fl & 0xF)]
            p[0] += fl & 0xF
            nin, nout = (num(), num()) if fl & 0x10 else (1, 1)
            props = b""
            if fl & 0x20:
                k = num()
                props = d[p[0]:p[0] + k]
                p[0] += k
            coders.append(dict(id=cid, nin=nin, nout=nout, props=props))
        tin = sum(c["nin"] for c in coders)
        tout = sum(c["nout"] for c in coders)
        binds = [(num(), num()) for _ in range(tout - 1)]
        npk = tin - len(binds)
        if npk == 1:
            packed = [i for i in range(tin) if i not in [b[0] for b in binds]]
        else:
            packed = [num() for _ in range(npk)]
        folders.append(dict(coders=coders, binds=binds, packed=packed))
    assert byte() == 0x0C
    for f in folders:
        f["usizes"] = [num() for _ in range(sum(c["nout"] for c in f["coders"]))]
    off, k = 32 + pack_pos, 0
    for f in folders:
        f["pack"] = []
        for _ in f["packed"]:
            f["pack"].append((off, sizes[k]))
            off += sizes[k]
            k += 1
    return folders

def coder_codec(c):
    if c["id"] == b"\x03\x01\x01":
        return "lzma1:" + c["props"].hex()
    if c["id"] == b"\x21":
        return "lzma2:%d" % c["props"][0]
    if c["id"] == b"\x00":
        return "copy"
    raise ValueError("coder %s" % c["id"].hex())

def bcj2_args(f):
    """Driver arguments for a folder BCJ2(main <- coder, call <- coder, jump <- coder, rc packed)."""
    coders = f["coders"]
    in_base, out_base, b = [], [], None
    ni = no = 0
    for i, c in enumerate(coders):
        in_base.append(ni)
        out_base.append(no)
        ni += c["nin"]
        no += c["nout"]
        if c["id"] == b"\x03\x03\x01\x1b":
            b = i
    assert b is not None
    bound = dict(f["binds"])                        # in index -> out index
    specs = []
    for k in range(4):
        sin = in_base[b] + k
        if sin in bound:
            out = bound[sin]
            ci = max(i for i in range(len(coders)) if out_base[i] <= out)
            cin = in_base[ci]
            off, size = f["pack"][f["packed"].index(cin)]
            specs.append("%d:%d:%s:%d" % (off, size, coder_codec(coders[ci]), f["usizes"][out]))
        else:
            off, size = f["pack"][f["packed"].index(sin)]
            specs.append("%d:%d:copy:%d" % (off, size, size))
    return [str(f["usizes"][out_base[b]])] + specs

# ---------------------------------------------------------------- driver helpers

def dict_prop(dict_size):
    for p in range(41):
        if p == 40 or (2 | (p & 1)) << (p // 2 + 11) >= dict_size:
            return p

def lzma1_props(lc, lp, pb, dict_size):
    return bytes([(pb * 5 + lp) * 9 + lc]) + struct.pack("<I", dict_size)

class Drv:
    def __init__(self, t, exe, prefix=()):
        self.t, self.exe, self.prefix = t, exe, list(prefix)
        self.n = 0

    def run(self, args, timeout=300):
        r = subprocess.run(self.prefix + [self.exe] + [str(a) for a in args], capture_output=True, timeout=timeout)
        err = r.stderr.decode(errors="replace")
        info = {}
        for tok in r.stdout.decode(errors="replace").split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                info[k] = v
        bad = r.returncode != 0 or "Sanitizer" in err or "runtime error" in err or "rc" not in info
        return info, bad, err[-600:]

    def dec(self, data_or_path, spec, *opts):
        self.n += 1
        if isinstance(data_or_path, bytes):
            inp = self.t.path("in_%d.bin" % (self.n % 4))
            open(inp, "wb").write(data_or_path)
        else:
            inp = data_or_path
        out = self.t.path("out_%d.bin" % (self.n % 4))
        info, bad, err = self.run(["dec"] + list(opts) + [inp, out, spec])
        data = open(out, "rb").read() if os.path.exists(out) else None
        rc = int(info.get("rc", -1))
        return rc, int(info.get("used", -1)), data, (err if bad else "")

    def filt(self, data, name, param, enc, *opts):
        self.n += 1
        inp = self.t.path("fin_%d.bin" % (self.n % 4))
        out = self.t.path("fout_%d.bin" % (self.n % 4))
        open(inp, "wb").write(data)
        info, bad, err = self.run(["filt"] + list(opts) + [inp, out, name, param, enc])
        return open(out, "rb").read(), (err if bad else "")

def run(t):
    t.need("xz")
    exe = t.build_driver("tests/drivers/lzma_test.c")
    drv = Drv(t, exe)
    asan = "sanitize" in os.environ.get("HOST_CFLAGS", "")

    def check_dec(label, comp, spec, expect, opts=(), want_used=None, want_rc=GZ_OK):
        rc, used, out, err = drv.dec(comp, spec, *opts)
        if err:
            return t.record(False, label, err)
        if want_rc != GZ_OK:
            return t.record(rc == want_rc, label, "rc=%d want %d" % (rc, want_rc))
        clen = len(comp) if isinstance(comp, bytes) else os.path.getsize(comp)
        want_used = clen if want_used is None else want_used
        ok = rc == GZ_OK and out == expect and used == want_used
        return t.record(ok, label, "" if ok else "rc=%d used=%d/%d out=%s/%d" % (
            rc, used, want_used, None if out is None else len(out), len(expect)))

    def xz_raw(data, *filt):
        r = subprocess.run(["xz", "--format=raw", "-c"] + list(filt), input=data, capture_output=True)
        if r.returncode:
            raise RuntimeError(r.stderr.decode())
        return r.stdout

    text = gen_text(400000)
    rnd = gen_random(150000)
    mixed = gen_mixed(3 << 20)
    bins = gen_bins(2 << 20)
    zeros = bytes(1 << 20)
    small = [b"", b"a", b"ab", b"\x00" * 5, gen_text(100, 9), gen_random(37, 4)]

    # ---- 1. raw LZMA1 (xz writes an end marker): lc/lp/pb/dict combinations
    sample = mixed[:200000] + bins[:100000]
    combos = [(lc, lp, pb) for lc in range(5) for lp in range(5) if lc + lp <= 4 for pb in (0, 2, 4)]
    for i, (lc, lp, pb) in enumerate(combos):
        dsz = [4096, 65536, 1 << 20][i % 3]
        comp = xz_raw(sample, "--lzma1=lc=%d,lp=%d,pb=%d,dict=%d" % (lc, lp, pb, dsz))
        spec = "lzma1:" + lzma1_props(lc, lp, pb, dsz).hex()
        check_dec("raw1 lc%d lp%d pb%d d%d" % (lc, lp, pb, dsz), comp, spec, sample)
    for name, data in [("text", text), ("random", rnd), ("zeros", zeros), ("bins", bins)] + \
                      [("small%d" % i, s) for i, s in enumerate(small)]:
        for preset in ("0", "6e"):
            comp = xz_raw(data, "--lzma1=preset=%s,dict=1MiB" % preset)
            spec = "lzma1:" + lzma1_props(3, 0, 2, 1 << 20).hex()
            check_dec("raw1 %s p%s" % (name, preset), comp, spec, data)
    # long data through a small window (wraps the circular buffer many times)
    for dsz, mode in [(4096, "fast"), (65536, "normal"), (1572864, "normal")]:
        comp = xz_raw(mixed, "--lzma1=dict=%d,mode=%s,nice=273" % (dsz, mode))
        spec = "lzma1:" + lzma1_props(3, 0, 2, dsz).hex()
        check_dec("raw1 mixed d%d %s" % (dsz, mode), comp, spec, mixed)
        check_dec("raw1 mixed d%d known size" % dsz, comp, spec, mixed, ("-o", len(mixed)))
    # repeats exactly at the window edge
    blk = gen_random((1 << 20) - 3, 77)
    edge = blk + blk + blk[:5000] + blk
    comp = xz_raw(edge, "--lzma1=dict=1MiB,nice=273")
    check_dec("raw1 window edge", comp, "lzma1:" + lzma1_props(3, 0, 2, 1 << 20).hex(), edge)

    # ---- 2. known size / end marker / trailing data / read chunking
    comp = xz_raw(text, "--lzma1=dict=1MiB")
    spec1 = "lzma1:" + lzma1_props(3, 0, 2, 1 << 20).hex()
    check_dec("raw1 known size + marker", comp, spec1, text, ("-o", len(text)))
    check_dec("raw1 size too big", comp, spec1, text, ("-o", len(text) + 1), want_rc=GZ_E_DATA)
    check_dec("raw1 size too small", comp, spec1, text, ("-o", len(text) - 1), want_rc=GZ_E_DATA)
    rc, used, out, err = drv.dec(comp, spec1, "-o", len(text) - 1, "-L")
    t.record(not err and rc == 0 and out == text[:-1], "raw1 lenient short size", "rc=%d" % rc)
    check_dec("raw1 trailing data", comp + b"\x00\xff" * 300, spec1, text, want_used=len(comp))
    for rchunk in ("1", "-7", "-3000", "65535"):
        check_dec("raw1 read chunk %s" % rchunk, comp + b"tail", spec1, text, ("-r", rchunk),
                  want_used=len(comp))
    check_dec("raw1 truncated", comp[:-1], spec1, text, want_rc=GZ_E_TRUNC)
    check_dec("raw1 truncated half", comp[: len(comp) // 2], spec1, text, want_rc=GZ_E_TRUNC)

    # .lzma files: xz / Python (unknown size + end marker)
    for name, data in [("text", text), ("bins", bins), ("empty", b"")]:
        p = t.path("x_%s.lzma" % name)
        open(p, "wb").write(lzma.compress(data, format=lzma.FORMAT_ALONE))
        check_dec("alone python %s" % name, p, "alone", data)
        check_dec("alone python %s rchunk" % name, p, "alone", data, ("-r", "-50"))

    # ---- 3. raw LZMA2
    for name, data in [("text", text), ("random", rnd), ("mixed", mixed), ("zeros", zeros), ("bins", bins)] + \
                      [("small%d" % i, s) for i, s in enumerate(small)]:
        for opt, dsz in [("preset=1", 1 << 20), ("preset=6", 8 << 20),
                         ("dict=64KiB,lc=0,lp=4,pb=4", 65536), ("dict=4KiB,lc=4,lp=0,pb=0,mode=fast", 4096)]:
            if len(data) < 1000 and opt != "preset=6":
                continue
            comp = xz_raw(data, "--lzma2=" + opt)
            check_dec("raw2 %s %s" % (name, opt), comp, "lzma2:%d" % dict_prop(dsz), data)
    comp = xz_raw(mixed, "--lzma2=preset=6")
    spec2 = "lzma2:%d" % dict_prop(8 << 20)
    check_dec("raw2 known size", comp, spec2, mixed, ("-o", len(mixed)))
    check_dec("raw2 small dict prop window", comp, "lzma2:%d" % dict_prop(1 << 20), mixed,
              want_rc=GZ_E_DATA)        # distances beyond the declared dictionary
    check_dec("raw2 size too big", comp, spec2, mixed, ("-o", len(mixed) + 1), want_rc=GZ_E_DATA)
    check_dec("raw2 size too small", comp, spec2, mixed, ("-o", len(mixed) - 1), want_rc=GZ_E_DATA)
    rc, used, out, err = drv.dec(comp, spec2, "-o", 1000000, "-L")
    t.record(not err and rc == 0 and out == mixed[:1000000], "raw2 lenient cut", "rc=%d" % rc)
    check_dec("raw2 trailing", comp + b"\x01\x02\x03" * 99, spec2, mixed, want_used=len(comp))
    check_dec("raw2 known + trailing", comp + b"\x01" * 9, spec2, mixed, ("-o", len(mixed)), want_used=len(comp))
    for rchunk in ("1", "-5", "-70000"):
        check_dec("raw2 read chunk %s" % rchunk, comp, spec2, mixed, ("-r", rchunk))
    check_dec("raw2 truncated", comp[:-1], spec2, mixed, want_rc=GZ_E_TRUNC)
    rc, used, out, err = drv.dec(comp[: len(comp) // 3], spec2)
    t.record(not err and rc == GZ_E_TRUNC, "raw2 truncated third", "rc=%d" % rc)   # cut inside a chunk

    # ---- 4. XZ Utils conformance files
    for fn in sorted(os.listdir(DATA)):
        p = os.path.join(DATA, fn)
        d = open(p, "rb").read()
        if fn.endswith(".lzma"):
            want = {"good-unknown_size-with_eopm.lzma": GZ_OK, "good-known_size-without_eopm.lzma": GZ_OK,
                    "good-known_size-with_eopm.lzma": GZ_OK}.get(fn)
            rc, used, out, err = drv.dec(p, "alone")
            if want == GZ_OK:
                ok = not err and rc == 0 and used == len(d) and out == lzma.decompress(d, format=lzma.FORMAT_ALONE)
            else:
                ok = not err and rc in (GZ_E_DATA, GZ_E_TRUNC)
            t.record(ok, "xz-files " + fn, "rc=%d used=%d/%d %s" % (rc, used, len(d), err))
        elif fn.endswith(".lz"):
            # lzip members: LZMA (lc3 lp0 pb2) + end marker, then a 12 (v0) / 20 (v1) byte trailer
            pos, out_all, ok, why = 0, b"", True, ""
            while ok and pos + 6 <= len(d) and d[pos:pos + 4] == b"LZIP":
                ver, ds = d[pos + 4], d[pos + 5]
                dsz = (1 << (ds & 0x1F)) - ((1 << (ds & 0x1F)) // 16) * (ds >> 5)
                rc, used, out, err = drv.dec(p, "lzma1:" + lzma1_props(3, 0, 2, dsz).hex(), "-s", pos + 6)
                tr = pos + 6 + used
                crc, size = struct.unpack_from("<IQ", d, tr)
                ok = not err and rc == 0 and crc == zlib.crc32(out) and size == len(out)
                if ok and ver == 1:
                    ok = struct.unpack_from("<Q", d, tr + 12)[0] == used + 26
                why = "rc=%d used=%d %s" % (rc, used, err)
                out_all += out or b""
                pos = tr + (20 if ver == 1 else 12)
            t.record(ok and out_all, "xz-files " + fn, why)
        elif fn.endswith(".xz"):
            off, spec, ck, csize, usize = parse_xz_block(d)
            good = fn.startswith("good")
            opts = ["-s", off] + (["-n", csize] if csize else [])
            rc, used, out, err = drv.dec(p, spec, *opts)
            if good:
                ref = lzma.decompress(d)
                ok = not err and rc == 0 and (csize is None or used == csize)
                # the check field follows the block padding: proves *in_used is exact
                end = off + used
                end += -end % 4
                ck_val = xz_check(ck, out or b"")
                ok = ok and d[end:end + len(ck_val)] == ck_val
                # good-2-lzma2.xz has two blocks: only the first one is decoded here
                ok = ok and (ref.startswith(out) if fn == "good-2-lzma2.xz" else out == ref)
            else:
                ok = not err and rc != 0
            t.record(ok, "xz-files " + fn, "spec=%s rc=%d used=%d %s" % (spec, rc, used, err))

    # ---- 5. 7-Zip made streams: LZMA lc8/lp4 (known size, no marker), eos, multi-block LZMA2
    if t.tool("7z"):
        src = t.path("7zsrc", "data.bin")
        open(src, "wb").write(mixed[:1500000])
        for name, m in [("lzma_lc8lp4", ["-m0=LZMA:lc=8:lp=4:pb=4:d=64k"]), ("lzma_lc0", ["-m0=LZMA:lc=0:lp=0:pb=0:d=1m"]),
                        ("lzma_eos", ["-m0=LZMA:eos:d=256k"]), ("lzma_lc8", ["-m0=LZMA:lc=8:lp=0:d=4m"]),
                        ("lzma2_mt", ["-m0=LZMA2:d=256k:c=300k", "-mmt=4"]), ("lzma2_x9", ["-m0=LZMA2", "-mx=9"])]:
            arc = t.path("7z_%s.7z" % name)
            if os.path.exists(arc):
                os.remove(arc)
            t.sh(["7z", "a", "-t7z", "-mhc=off", arc, src] + m)
            f = parse_7z(arc)[0]
            off, size = f["pack"][0]
            spec = coder_codec(f["coders"][0])
            exp = mixed[:1500000]
            rc, used, out, err = drv.dec(arc, spec, "-s", off, "-n", size, "-o", f["usizes"][0])
            ok = not err and rc == 0 and out == exp and used == size
            t.record(ok, "7z " + name, "%s rc=%d used=%d/%d %s" % (spec, rc, used, size, err))
            rc, used, out, err = drv.dec(arc, spec, "-s", off, "-n", size, "-o", f["usizes"][0], "-L", "-r", "-999")
            t.record(not err and rc == 0 and out == exp, "7z %s lenient" % name, "rc=%d" % rc)

    # ---- 6. branch filters and Delta vs xz (both directions, chunking)
    xz_name = {"x86": "x86", "ppc": "powerpc", "ia64": "ia64", "arm": "arm", "armt": "armthumb",
               "sparc": "sparc", "arm64": "arm64", "riscv": "riscv"}
    helps = subprocess.run(["xz", "--long-help"], capture_output=True).stdout.decode()
    arm64_libs = gen_bins(1 << 20, ("/usr/aarch64-linux-gnu/lib",), 3)
    for f, xn in xz_name.items():
        datas = [("synth", synth_code(f, 300001 if f != "ia64" else 300000, 11))]
        if f == "x86":
            datas.append(("bins", bins[:1500000]))
        if f == "arm64" and arm64_libs:
            datas.append(("libs", arm64_libs))
        datas.append(("text", text[:50000]))
        has_xz = ("--" + xn) in helps
        for start in (0, 0x10000 if f != "x86" else 12345):
            for dname, data in datas:
                label = "%s %s start=%d" % (f, dname, start)
                if has_xz:
                    fopt = "--%s" % xn + ("=start=%d" % start if start else "")
                    comp = xz_raw(data, fopt, "--lzma2=dict=1MiB")
                    spec = "lzma2:%d+%s:%d" % (dict_prop(1 << 20), f, start)
                    check_dec(label + " dec", comp, spec, data)
                    check_dec(label + " dec split", comp, spec, data, ("-k", "777"))
                    ref = lzma.decompress(comp, format=lzma.FORMAT_RAW,
                                          filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}])
                elif f == "riscv":
                    ref = riscv_encode_ref(data, start)
                else:
                    t.record(False, label, "xz lacks --%s" % xn)
                    continue
                enc, err = drv.filt(data, f, start, 1)
                t.record(not err and enc == ref, label + " enc", err)
                enc2, err = drv.filt(data, f, start, 1, "-k", "33")
                t.record(not err and enc2 == ref, label + " enc push", err)
                back, err = drv.filt(ref, f, start, 0)
                t.record(not err and back == data, label + " dec in-place", err)
                back2, err = drv.filt(ref, f, start, 0, "-k", "9000")
                t.record(not err and back2 == data, label + " dec push", err)
        # arbitrary data: decoding after encoding restores it
        for seed in range(3):
            data = gen_random(20000 + seed, 100 + seed)
            enc, err1 = drv.filt(data, f, seed * 16, 1)
            back, err2 = drv.filt(enc, f, seed * 16, 0, "-k", "17")
            t.record(not err1 and not err2 and back == data, "%s random roundtrip %d" % (f, seed), err1 + err2)
    for dist in (1, 2, 3, 4, 7, 16, 100, 255, 256):
        data = mixed[:200000] if dist % 2 else bins[:200000]
        comp = xz_raw(data, "--delta=dist=%d" % dist, "--lzma2=dict=1MiB")
        spec = "lzma2:%d+delta:%d" % (dict_prop(1 << 20), dist)
        check_dec("delta %d dec" % dist, comp, spec, data, ("-k", "300") if dist > 100 else ())
        ref = lzma.decompress(comp, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}])
        enc, err = drv.filt(data, "delta", dist, 1, "-k", "200")
        t.record(not err and enc == ref, "delta %d enc" % dist, err)
    # chains: x86 then delta
    comp = xz_raw(bins[:400000], "--x86", "--delta=dist=4", "--lzma2=dict=1MiB")
    check_dec("chain x86+delta", comp, "lzma2:%d+delta:4+x86:0" % dict_prop(1 << 20), bins[:400000], ("-k", "1000"))

    # ---- 7. BCJ2 (7z archives on x86 code)
    if t.tool("7z"):
        cases = [("bins1", bins[:120000]), ("bins2", gen_bins(3 << 20, ("/usr/bin", "/usr/lib/x86_64-linux-gnu"), 5)),
                 ("synth", synth_code("x86", 400000, 3)), ("tail_e8", bins[:5000] + b"\x90\xe8"),
                 ("tail_jcc", bins[:3000] + b"\x0f\x85\x01\x02"), ("tiny", b"\xe8\x00\x00\x00\x00\xe9")]
        for name, data in cases:
            src = t.path("bcj2src", name + ".bin")
            open(src, "wb").write(data)
            arc = t.path("bcj2_%s.7z" % name)
            if os.path.exists(arc):
                os.remove(arc)
            t.sh(["7z", "a", "-t7z", "-m0=BCJ2", "-m1=LZMA:d24", "-m2=LZMA:d19", "-m3=LZMA:d19",
                  "-mb0:1", "-mb0s1:2", "-mb0s2:3", "-mhc=off", arc, src])
            f = parse_7z(arc)[0]
            args = bcj2_args(f)
            out = t.path("bcj2_%s.out" % name)
            for extra in ([], ["-r", "-77"]):
                info, bad, err = drv.run(["bcj2"] + extra + [arc, out] + args)
                got = open(out, "rb").read() if os.path.exists(out) else None
                ok = not bad and info.get("rc") == "0" and got == data
                t.record(ok, "bcj2 %s %s" % (name, " ".join(extra)), "%s %s" % (info, err))
        # hostile: damaged streams must fail cleanly
        d0 = open(t.path("bcj2_bins2.7z"), "rb").read()
        f = parse_7z(t.path("bcj2_bins2.7z"))[0]
        args = bcj2_args(f)
        r = random.Random(5)
        bad_runs = []
        for i in range(25 if not asan else 12):
            d = bytearray(d0)
            for _ in range(r.randint(1, 6)):
                at = r.randrange(32, len(d) - 200)
                d[at] ^= 1 << r.randrange(8)
            p = t.path("bcj2_bad.7z")
            open(p, "wb").write(d)
            info, bad, err = drv.run(["bcj2", p, t.path("bcj2_bad.out")] + args, timeout=120)
            if bad:
                bad_runs.append(err)
        t.record(not bad_runs, "bcj2 bit flips", "; ".join(bad_runs)[:500])

    # ---- 8. limits and invalid parameters
    hdr = lzma1_props(3, 0, 2, 0xFFFFFFFF) + b"\xff" * 8
    p = t.path("huge_dict.lzma")
    open(p, "wb").write(hdr + lzma.compress(b"x" * 1000, format=lzma.FORMAT_ALONE)[13:])
    rc, used, out, err = drv.dec(p, "alone", "-m", 1 << 28)
    t.record(not err and rc == GZ_E_LIMIT, "dict 4 GiB over limit", "rc=%d %s" % (rc, err))
    rc, used, out, err = drv.dec(p, "alone", "-m", 1 << 28, "-o", 1000)
    t.record(not err and rc == 0 and out == b"x" * 1000, "dict 4 GiB, small known size", "rc=%d %s" % (rc, err))
    comp = xz_raw(b"hello" * 99, "--lzma2=dict=4KiB")
    rc, used, out, err = drv.dec(comp, "lzma2:40", "-m", 1 << 30)
    t.record(not err and rc == GZ_E_LIMIT, "lzma2 prop 40 over limit", "rc=%d" % rc)
    rc, used, out, err = drv.dec(comp, "lzma2:41")
    t.record(not err and rc == GZ_E_DATA, "lzma2 prop 41", "rc=%d" % rc)
    rc, used, out, err = drv.dec(comp, "lzma1:e100100000")
    t.record(not err and rc == GZ_E_DATA, "lzma1 props byte 225", "rc=%d" % rc)

    # ---- 9. hostile input: in-process fuzzing (truncation, bit flips, wrong sizes)
    iters = "1500" if asan else "4000"
    fz = []
    fz.append(("raw2 text", xz_raw(text[:60000], "--lzma2=dict=64KiB"), "lzma2:%d" % dict_prop(65536)))
    fz.append(("raw2 mixed", xz_raw(mixed[:150000], "--lzma2=preset=2"), "lzma2:%d" % dict_prop(1 << 20)))
    fz.append(("raw1 lc4lp4?", xz_raw(sample[:80000], "--lzma1=lc=0,lp=4,pb=4,dict=64KiB"),
               "lzma1:" + lzma1_props(0, 4, 4, 65536).hex()))
    fz.append(("alone", lzma.compress(text[:40000], format=lzma.FORMAT_ALONE), "alone"))
    fz.append(("raw2 x86+delta", xz_raw(bins[:100000], "--x86", "--delta=dist=2", "--lzma2=dict=1MiB"),
               "lzma2:%d+delta:2+x86:0" % dict_prop(1 << 20)))
    fz.append(("raw2 arm64", xz_raw(synth_code("arm64", 50000), "--arm64", "--lzma2=dict=64KiB"),
               "lzma2:%d+arm64:0" % dict_prop(65536)))
    fz.append(("riscv copy", synth_code("riscv", 30000), "copy+riscv:0+ia64:0+sparc:0"))
    for i, (name, comp, spec) in enumerate(fz):
        p = t.path("fuzz_%d.bin" % i)
        open(p, "wb").write(comp)
        info, bad, err = drv.run(["fuzz", "-c", 1 << 26, p, spec, iters, 1000 + i], timeout=600)
        t.record(not bad and info.get("rc") == "0", "fuzz " + name, " ".join("%s=%s" % kv for kv in info.items()) + err)

    # ---- 10. other builds: 32-bit (dictionary limit) and AArch64 under qemu
    srcs = [os.path.join(ROOT, s) for s in ("tests/drivers/lzma_test.c", "src/codec/lzma.c",
                                            "src/codec/bcj.c", "src/codec/bcj2.c")]
    inc = ["-I" + os.path.join(ROOT, d) for d in ("src/core", "src/codec")]
    targets = []
    if t.tool("gcc") and not asan:
        targets.append(("m32", ["gcc", "-m32"], []))
    if t.tool("aarch64-linux-gnu-gcc") and t.tool("qemu-aarch64") and not asan:
        targets.append(("aarch64", ["aarch64-linux-gnu-gcc"],
                        ["qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"]))
    for tag, cc, runner in targets:
        exe2 = t.path("lzma_test_" + tag)
        r = subprocess.run(cc + ["-std=gnu11", "-O2", "-DLZMA_TEST_STANDALONE"] + inc + ["-o", exe2] + srcs,
                           capture_output=True)
        if r.returncode:
            if tag == "m32":
                continue              # no multilib: nothing to test
            t.record(False, tag + " build", r.stderr.decode()[-300:])
            continue
        d2 = Drv(t, exe2, runner)
        comp = xz_raw(mixed, "--x86", "--lzma2=preset=6")
        rc, used, out, err = d2.dec(comp, "lzma2:%d+x86:0" % dict_prop(8 << 20), "-k", "5000")
        t.record(not err and rc == 0 and out == mixed and used == len(comp), tag + " lzma2+x86", "rc=%d %s" % (rc, err))
        comp = xz_raw(sample, "--lzma1=lc=1,lp=3,pb=1,dict=64KiB")
        rc, used, out, err = d2.dec(comp, "lzma1:" + lzma1_props(1, 3, 1, 65536).hex(), "-r", "-100")
        t.record(not err and rc == 0 and out == sample, tag + " lzma1", "rc=%d %s" % (rc, err))
        if arm64_libs:
            comp = xz_raw(arm64_libs, "--arm64", "--lzma2=dict=1MiB")
            rc, used, out, err = d2.dec(comp, "lzma2:%d+arm64:0" % dict_prop(1 << 20))
            t.record(not err and rc == 0 and out == arm64_libs, tag + " arm64", "rc=%d %s" % (rc, err))
        if tag == "m32":
            p_huge = t.path("huge_dict.lzma")
            rc, used, out, err = d2.dec(p_huge, "alone")
            t.record(not err and rc == GZ_E_LIMIT, "m32 dict 4 GiB default limit", "rc=%d %s" % (rc, err))
            rc, used, out, err = d2.dec(p_huge, "alone", "-o", 1000)
            t.record(not err and rc == 0 and out == b"x" * 1000, "m32 dict 4 GiB small size", "rc=%d %s" % (rc, err))
