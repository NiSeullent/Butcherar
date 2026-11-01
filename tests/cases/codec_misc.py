"""Small block codecs: ADC, LZNT1, LZO1X (+ lzop .lzo files), LZFSE/LZVN, XPRESS plain / Huffman.

Encoders written here from the specifications ([MS-XCA], libdmg's ADC, Apple's LZVN opcode
table, liblzo's LZO1X instruction set, lzop's file layout) make the module work without any
reference tool. Each reference, when installed, adds checks: lzop and lzfse tools (or the pip
modules lzfse / pyliblzfse, or liblzfse.so), wimlib-imagex (XPRESS WIM chunks), liblzo2 /
liblzfse / libwim (differential fuzzing through tests/drivers/misc_ref.c), Samba's MS-XCA
module (python3.12), dissect.util, and Wine + MinGW (ntdll's RtlDecompressBuffer for LZNT1,
tests/drivers/misc_rtl.c).
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


def lznt1_hdr(body, compressed=True):
    """Chunk header for a chunk body of len(body) bytes."""
    return ((0xb000 if compressed else 0x3000) | (len(body) - 1)).to_bytes(2, "little")


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


def lzvn_compress(data, kinds=None, nops=False, prefix=b""):
    """LZVN with every instruction kind (Apple's lzvn_decode_base.c opcode layout).
    prefix: bytes already decoded before this stream (earlier blocks), matches may use them.
    kinds: set that collects the names of the opcodes emitted."""
    kinds = set() if kinds is None else kinds
    buf = prefix + data
    m = Matcher(buf)
    for k in range(len(prefix)):
        m.insert(k)
    out, lit = bytearray(), bytearray()
    mlim = (10, 8, 6, 4)                    # longest sml_d/lrg_d/pre_d match for 0..3 literals
    i, n, prev, ops = len(prefix), len(buf), 0, 0

    def literals(keep):
        while len(lit) > keep:
            c = min(len(lit) - keep, 271)
            kinds.add("lrg_l" if c >= 16 else "sml_l")
            out.extend(bytes([0xe0, c - 16]) if c >= 16 else bytes([0xe0 | c]))
            out.extend(lit[:c])
            del lit[:c]

    while i < n:
        l, d = m.find(i, n, 65535, 600)
        if l < 3:
            m.insert(i)
            lit.append(buf[i])
            i += 1
            continue
        literals(3)
        L = len(lit)
        if d == prev and L == 0:            # previous distance, no literal: match opcodes only
            mm = 0
        elif d == prev:
            mm = min(l, mlim[L])
            kinds.add("pre_d")
            out.append(L << 6 | (mm - 3) << 3 | 6)
        elif d < 0x600:
            mm = min(l, mlim[L])
            kinds.add("sml_d")
            out.extend(bytes([L << 6 | (mm - 3) << 3 | d >> 8, d & 0xff]))
        elif d < 0x4000:
            mm = min(l, 34)
            kinds.add("med_d")
            out.append(0xa0 | L << 3 | (mm - 3) >> 2)
            out.extend((d << 2 | ((mm - 3) & 3)).to_bytes(2, "little"))
        else:
            mm = min(l, mlim[L])
            kinds.add("lrg_d")
            out.append(L << 6 | (mm - 3) << 3 | 7)
            out.extend(d.to_bytes(2, "little"))
        out.extend(lit)
        lit.clear()
        rest = l - mm
        while rest:                         # the rest of the match: previous distance
            c = min(rest, 271)
            kinds.add("lrg_m" if c >= 16 else "sml_m")
            out.extend(bytes([0xf0, c - 16]) if c >= 16 else bytes([0xf0 | c]))
            rest -= c
        prev = d
        for k in range(i, i + l):
            m.insert(k)
        i += l
        ops += 1
        if nops and ops % 41 == 0:
            kinds.add("nop")
            out.append(0x0e if ops % 2 else 0x16)
    literals(0)
    return bytes(out + b"\x06" + bytes(7))


def lzo1x_compress(data):
    """LZO1X (lzo1x_9x.c instruction layout): first literal run, literal runs, M2, M3, M4 with
    extended lengths, 1..3 literals carried in the low bits of the previous match."""
    m = Matcher(data)
    out, lit = bytearray(), bytearray()
    i, n, last = 0, len(data), -1           # last: offset of the low-bits byte of the last match

    def ext(v, mask):                       # length v in the instruction byte or extension bytes
        if v <= mask:
            return bytes([v]), b""
        v -= mask
        e = bytearray()
        while v > 255:
            e.append(0)
            v -= 255
        return b"\0", bytes(e + bytes([v]))

    def literals():
        t = len(lit)
        if not t:
            return
        if last < 0 and not out and t <= 238:
            out.append(17 + t)
        elif t <= 3:
            out[last] |= t
        elif t <= 18:
            out.append(t - 3)
        else:
            b0, e = ext(t - 3, 15)
            out.extend(b0 + e)
        out.extend(lit)
        lit.clear()

    while i < n:
        l, d = m.find(i, n, 49151, 2000)
        if l < 3 or (d > 0x4000 and l < 4):
            m.insert(i)
            lit.append(data[i])
            i += 1
            continue
        literals()
        if l <= 8 and d <= 0x800:
            out.extend(bytes([(l - 1) << 5 | ((d - 1) & 7) << 2, (d - 1) >> 3]))
            last = len(out) - 2
        elif d <= 0x4000:
            b0, e = ext(l - 2, 31)
            out.extend(bytes([0x20 | b0[0]]) + e + ((d - 1) << 2).to_bytes(2, "little"))
            last = len(out) - 2
        else:
            dd = d - 0x4000
            b0, e = ext(l - 2, 7)
            out.extend(bytes([0x10 | (dd >> 14 & 1) << 3 | b0[0]]) + e + ((dd & 0x3fff) << 2).to_bytes(2, "little"))
            last = len(out) - 2
        for k in range(i, i + l):
            m.insert(k)
        i += l
    literals()
    return bytes(out + b"\x11\0\0")


def lzop_file(data, name=b"data.bin", flags=0x03000001, block=256 << 10, filt=0, mtime=0x5ee76200, level=5):
    """An lzop file (format of lzop 1.04) whose blocks come from lzo1x_compress."""
    import zlib
    crc_h = flags & 0x1000
    ck = (lambda b: zlib.crc32(b)) if crc_h else (lambda b: zlib.adler32(b))
    h = struct.pack(">HHHBBI", 0x1040, 0x20a0, 0x0940, 1, level, flags | (0x800 if filt else 0))
    if filt:
        h += struct.pack(">I", filt)
    h += struct.pack(">IIIB", 0o100644, mtime, 0, len(name)) + name
    out = bytearray(b"\x89LZO\0\r\n\x1a\n" + h + struct.pack(">I", ck(h)))
    for s in range(0, len(data), block):
        raw = data[s:s + block]
        f = bytearray(raw)
        for k in range(len(f) - 1, filt - 1, -1) if filt else ():
            f[k] = (f[k] - f[k - filt]) & 0xff     # lzop's delta filter, undone after decoding
        z = lzo1x_compress(bytes(f))
        stored = len(z) >= len(raw)
        out += struct.pack(">II", len(raw), len(raw) if stored else len(z))
        for bit, fn in ((1, zlib.adler32), (0x100, zlib.crc32)):
            if flags & bit:
                out += struct.pack(">I", fn(raw))
        if not stored:
            for bit, fn in ((2, zlib.adler32), (0x200, zlib.crc32)):
                if flags & bit:
                    out += struct.pack(">I", fn(z))
        out += bytes(f) if stored else z
    return bytes(out + b"\0\0\0\0")


def lzfse_reference(t):
    """(encode, decode) with Apple's reference LZFSE: the lzfse tool, the pip modules lzfse
    or liblzfse (pyliblzfse), or liblzfse.so through ctypes. (None, None) when absent."""
    if t.tool("lzfse"):
        def enc(d):
            fi, fo = t.path("lz.in"), t.path("lz.lzfse")
            open(fi, "wb").write(d)
            t.sh(["lzfse", "-encode", "-i", fi, "-o", fo])
            return open(fo, "rb").read()

        def dec(z, n):
            fi, fo = t.path("lzd.lzfse"), t.path("lzd.out")
            open(fi, "wb").write(z)
            r = subprocess.run(["lzfse", "-decode", "-i", fi, "-o", fo], capture_output=True)
            return open(fo, "rb").read() if r.returncode == 0 else None
        return enc, dec
    for mod in ("lzfse", "liblzfse"):
        try:
            lib = importlib.import_module(mod)
            return lib.compress, lambda z, n: lib.decompress(z)
        except Exception:
            pass
    try:
        import ctypes
        lib = ctypes.CDLL("liblzfse.so.1")
        lib.lzfse_encode_buffer.restype = lib.lzfse_decode_buffer.restype = ctypes.c_size_t

        def enc(d):
            cap = len(d) + len(d) // 8 + 4096
            out = ctypes.create_string_buffer(cap)
            k = lib.lzfse_encode_buffer(out, ctypes.c_size_t(cap), d, ctypes.c_size_t(len(d)), None)
            return out.raw[:k]

        def dec(z, n):
            out = ctypes.create_string_buffer(n + 1)
            k = lib.lzfse_decode_buffer(out, ctypes.c_size_t(n + 1), z, ctypes.c_size_t(len(z)), None)
            return out.raw[:k]
        return enc, dec
    except OSError:
        return None, None


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
    expect_rc("lznt1", b"\x03\xb0" + over, 4099, (3,), "lznt1 match past chunk end, output full")
    # literal + 4095-byte match fill the chunk; the group's next literal tokens overflow it
    full = b"\x02a" + (4092).to_bytes(2, "little") + b"xyz"
    expect_rc("lznt1", lznt1_hdr(full) + full, 4097, (3,), "lznt1 literals past chunk end, output full")
    edge = [("flag byte ends chunk", lznt1_hdr(b"\0abcdefgh\x01") + b"\0abcdefgh\x01" + lznt1_hdr(b"\0XYZ") + b"\0XYZ",
             b"abcdefgh".ljust(4096, b"\0") + b"XYZ"),
            ("stored short chunk padding", lznt1_compress(b"abc" * 100, store=True) + lznt1_compress(b"next"),
             (b"abc" * 100).ljust(4096, b"\0") + b"next")]
    for label, z, d in edge:
        check("lznt1", z, d, "lznt1 " + label, cap=65536)
    # NTFS: a run of clusters may end one byte after the last chunk (Wine reports an error)
    check("lznt1", lznt1_compress(b"tail" * 50) + b"\x01", b"tail" * 50, "lznt1 trailing odd byte", cap=65536)

    # Windows semantics: ntdll's RtlDecompressBuffer under Wine (checked against Windows by
    # Wine's own tests) must give the same bytes as ours, padding of short chunks included
    wine_cc = shutil.which("i686-w64-mingw32-gcc") or shutil.which("x86_64-w64-mingw32-gcc")
    if t.tool("wine") and wine_cc:
        wd = t.path("wine")
        os.makedirs(wd, exist_ok=True)
        exe = os.path.join(wd, "misc_rtl.exe")
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        r = subprocess.run([wine_cc, "-O2", "-o", exe, os.path.join(root, "tests/drivers/misc_rtl.c")],
                           capture_output=True)
        d, txt = sample(60000, 13), dict(corpus)["text"][:70000]
        big_cap = 1 << 17
        # (label, stream, expected bytes or None = only compare with Wine, output capacity)
        wcases = [("mixed", lznt1_compress(d), d, big_cap), ("text", lznt1_compress(txt), txt, big_cap),
                  ("zeros", lznt1_compress(bytes(50000)), bytes(50000), big_cap),
                  ("random", lznt1_compress(os.urandom(9000)), None, big_cap),
                  ("short chunks", short + lznt1_compress(b"next") + short, None, big_cap),
                  ("cut output", lznt1_compress(d), d[:5000], 5000)] + [e + (big_cap,) for e in edge]
        jobs = []
        for i, (label, z, dd, cap) in enumerate(wcases):
            open(os.path.join(wd, "w%d.in" % i), "wb").write(z)
            jobs.append("w%d.in w%d.out %d" % (i, i, cap))
        open(os.path.join(wd, "jobs.txt"), "w").write("\n".join(jobs) + "\n")
        try:
            w = subprocess.run(["wine", "misc_rtl.exe", "jobs.txt"], cwd=wd, capture_output=True, timeout=180,
                               env=dict(os.environ, WINEDEBUG="-all")) if r.returncode == 0 else None
        except subprocess.TimeoutExpired:
            w = None
        st = w.stdout.decode(errors="replace").split() if w is not None and w.returncode == 0 else []
        if len(st) == 2 * len(wcases):                  # else Wine is not usable here: skip
            for i, (label, z, dd, cap) in enumerate(wcases):
                ref = open(os.path.join(wd, "w%d.out" % i), "rb").read()
                rc, ours, _ = dec("lznt1", z, cap)
                ok = st[2 * i] == "status=00000000" and rc == 0 and ours == ref and (dd is None or ref == dd)
                t.record(ok, "lznt1 %s = RtlDecompressBuffer (Wine)" % label,
                         "%s ours rc=%d %d bytes, wine %d bytes" % (st[2 * i], rc, len(ours), len(ref)))

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
    enc, refdec = lzfse_reference(t)
    # hand-made streams: no reference tool needed
    check("lzfse", b"bvx$", b"", "lzfse empty stream")
    expect_rc("lzfse", b"bvxz\0\0\0\0", 16, (3,), "lzfse bad magic")
    expect_rc("lzfse", b"bvxn" + struct.pack("<II", 0, 8) + b"\x06" + bytes(7) + b"bvx$", 16, (3,),
              "lzfse empty lzvn block")
    check("lzvn", b"\xe3abc\x00\x03\xf0\x00" + b"\x06" + bytes(7), (b"abc" * 8)[:22], "lzvn sml_d + lrg_m")
    expect_rc("lzvn", b"\xf3\x06" + bytes(7), 64, (3,), "lzvn match without distance")
    expect_rc("lzvn", b"\x40\x00a\x06" + bytes(7), 64, (3,), "lzvn sml_d distance 0")
    expect_rc("lzvn", b"\x70\x00\x06" + bytes(7), 64, (3,), "lzvn undefined opcode")
    expect_rc("lzvn", b"\xe3abc", 64, (9,), "lzvn missing end opcode")
    expect_rc("lzvn", b"\xe3abc\x06" + bytes(6), 64, (9,), "lzvn cut end opcode")
    check("lzvn", b"\x0e\x16\xe1z\x06" + bytes(7), b"z", "lzvn nops")
    # LZVN from the encoder above: every opcode kind; the reference decoder must agree
    vn_kinds = set()
    for name, d in [("mixed", sample(120000, 31)), ("text", dict(corpus)["text"]), ("zeros", bytes(70000)),
                    ("random", os.urandom(3000)), ("one", b"x")]:
        vn = lzvn_compress(d, vn_kinds, nops=True)
        check("lzvn", vn, d, "lzvn ours %s" % name, used=len(vn))
        blk = b"bvxn" + struct.pack("<II", len(d), len(vn)) + vn + b"bvx$"
        check("lzfse", blk, d, "lzfse bvxn ours %s" % name, used=len(blk))
        if refdec:
            t.record(refdec(blk, len(d)) == d, "reference lzfse decodes our lzvn %s" % name)
        if name == "mixed":
            fuzz_inputs["lzvn"] = (vn[:20000], len(d))
    t.record(len(vn_kinds) == 9, "lzvn encoder used every opcode kind", " ".join(sorted(vn_kinds)))
    # stored and LZVN blocks back to back: matches reach into earlier blocks
    a, b2 = sample(5000, 40), sample(9000, 41)[:3000] + sample(5000, 40)[1000:4000]
    vn = lzvn_compress(b2, prefix=a)
    stitched = (b"bvx-" + struct.pack("<I", len(a)) + a + b"bvxn" + struct.pack("<II", len(b2), len(vn)) + vn +
                b"bvx-" + struct.pack("<I", 3) + b"end" + b"bvx$")
    check("lzfse", stitched, a + b2 + b"end", "lzfse stored + lzvn blocks")
    if refdec:
        t.record(refdec(stitched, len(a + b2) + 3) == a + b2 + b"end", "reference lzfse decodes stored + lzvn blocks")
    expect_rc("lzfse", stitched[len(a) + 8:], len(b2) + 3, (3,), "lzfse lzvn distance before the stream start")

    if enc:
        a, b2 = sample(5000, 40), sample(100000, 41)
        stitched = b"bvx-" + struct.pack("<I", len(a)) + a + enc(b2)[:-4] + b"bvx-" + struct.pack("<I", 3) + b"end" + b"bvx$"
        check("lzfse", stitched, a + b2 + b"end", "lzfse stored + compressed blocks")
        lz_cases = [(n, d) for n, d in corpus if d] + [("s4095", sample(4095, 1)), ("s4096", sample(4096, 2)),
                                                         ("multi", big + sample(800000, 12)), ("rand200k", os.urandom(200000))]
        for name, d in lz_cases:
            z = enc(d)
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
    else:
        fuzz_inputs["lzfse_vn"] = (stitched, len(a + b2) + 3)
    # ---------------- LZO1X raw blocks + lzop files ----------------
    # the encoder above (no reference tool needed); lzop -dc checks its files when present
    for name, d in corpus + [("multi", big)]:
        z = lzo1x_compress(d)
        check("lzo", z, d, "lzo1x ours %s" % name, used=len(z))
        if name == "mixed":
            fuzz_inputs["lzo"] = (z[:12000], len(d))
    check("lzo", b"\x11\0\0", b"", "lzo1x empty block")
    check("lzo", b"\x12a\x11\0\0", b"a", "lzo1x first literal run of 1")
    expect_rc("lzo", b"\x15abcd\x40\x01\x11\0\0", 64, (3,), "lzo1x M2 distance before start")
    expect_rc("lzo", b"\x15abcd\x11\0", 64, (9,), "lzo1x cut end marker")
    expect_rc("lzo", b"\x00" * 40, 1 << 16, (9,), "lzo1x run of zero length bytes")
    z = lzo1x_compress(dict(corpus)["text"])
    expect_rc("lzo", z + b"junk", len(dict(corpus)["text"]), (0,), "lzo1x input after the end marker")
    r, out, used = dec("lzo", z + b"junk", len(dict(corpus)["text"]))
    t.record(used == len(z), "lzo1x consumed bytes stop at the end marker", "used=%d of %d" % (used, len(z)))

    text = b"".join(b"%d: lzop test line, gogi zip\n" % i for i in range(60000))
    own = [("adler32 data", dict(), text), ("adler32 + crc32 both", dict(flags=0x03000303), text),
           ("no checksum", dict(flags=0x03000000), text), ("crc32 header", dict(flags=0x03001101), text),
           ("stored blocks", dict(block=64 << 10), os.urandom(200000)), ("empty", dict(), b""),
           ("small blocks", dict(block=4096, flags=0x03000003), sample(100000, 60)),
           ("filter 3", dict(filt=3), sample(150000, 61)), ("filter 1 stored", dict(filt=1), os.urandom(70000))]
    for label, kw, d in own:
        arc = t.path("own_%s.lzo" % label.replace(" ", "_"))
        open(arc, "wb").write(lzop_file(d, **kw))
        if t.tool("lzop"):
            ref = subprocess.run(["lzop", "-dc", arc], capture_output=True).stdout
            t.record(ref == d, "lzop -dc decodes our lzop file: %s" % label)
        t.check_extract(arc, {"data.bin": d}, label="lzop ours " + label, expect_type="LZO")
    r, typ, rows = t.listing(t.path("own_adler32_data.lzo"))
    t.record(rows and rows[0]["usize"] == len(text) and rows[0]["method"] == "LZO1X",
             "lzop listing size + method (ours)", str(rows[:1]))
    zo = lzop_file(text, flags=0x03000303, block=32768)
    for label, pos in (("data checksum", -40), ("header checksum", 20)):
        z = bytearray(zo)
        z[pos] ^= 0x10
        arc = t.path("own_corrupt_%s.lzo" % label.replace(" ", "_"))
        open(arc, "wb").write(z)
        rr, rows, _ = t.extract(arc, env={"LSAN_OPTIONS": "suppressions=" + lsan})
        t.record(rr.returncode in (0, 1) and (not rows or rows[0][0] != 0), "lzop corrupt %s reported" % label,
                 str(rows))
    rng = random.Random(6)
    for i in range(16):
        h = bytearray(zo[:rng.randrange(30, len(zo))])
        for _ in range(rng.randrange(0, 4)):
            h[rng.randrange(len(h))] ^= 1 << rng.randrange(8)
        p = t.path("hostile_own_%d.lzo" % i)
        open(p, "wb").write(h)
        hostile(p)
    hdr = len(lzop_file(b""))  - 4                                      # first block header
    bad = bytearray(lzop_file(b"x" * 100))
    bad[hdr:hdr + 8] = struct.pack(">II", 0x7fffffff, 0x10)           # absurd block size
    p = t.path("hostile_bigblock.lzo")
    open(p, "wb").write(bytes(bad))
    hostile(p)
    bad[hdr:hdr + 8] = struct.pack(">II", 0x3ffffff, 0x10)            # 64 MiB block, 16 bytes of data
    p = t.path("hostile_bigblock2.lzo")
    open(p, "wb").write(bytes(bad))
    hostile(p)
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
                          ("xhuff", xhuff_compress), ("lzo", lzo1x_compress), ("lzvn", lzvn_compress)):
            p = t.path("bench.%s" % codec)
            open(p, "wb").write(fn(d))
            r = t.sh([drv, "bench", codec, p, str(len(d)), "300"], check=False)
            t.record(r.returncode == 0, "speed %s" % codec, r.stdout.decode().strip())
