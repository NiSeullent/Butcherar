"""Reference writers for fmt_alz_egg.py (test tooling only).

고깃ZIP reads ALZ and EGG archives but does not create them. These writers build
test archives from the format descriptions: the EGG specification 1.0 (ESTsoft),
the ALZ layout read by unalz 0.65 / The Unarchiver / ESTsoft's unegg, plus:

  * alz_bzip2():   bzip2 in ALZip's headerless "DLZ\\1" block framing, made by
                   re-framing single-block streams from Python's bz2
  * obfuscate():   ALZ method 3, a raw deflate stream whose dynamic headers list
                   the code length code lengths in the size-keyed order
  * azo_compress(): AZO streams; the encoder mirrors the decoder model of
                   src/codec/azo.c (greedy LZ with seeded random choices so every
                   code path of the decoder is used; ratio is irrelevant)
  * ZipCrypto, LEA (KS X 3246) and WinZip-style AES-CTR for the encryption tests
"""
import bz2, hashlib, hmac, lzma, random, struct, zlib

# ------------------------------------------------------------------ crypto

_T = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    _T.append(_c)


class ZipCrypto:
    def __init__(self, pw):
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for b in pw:
            self.upd(b)

    def upd(self, b):
        self.k0 = _T[(self.k0 ^ b) & 0xFF] ^ (self.k0 >> 8)
        self.k1 = ((self.k1 + (self.k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = _T[(self.k2 ^ (self.k1 >> 24)) & 0xFF] ^ (self.k2 >> 8)

    def encrypt(self, data):
        out = bytearray(len(data))
        for i, p in enumerate(data):
            t = (self.k2 | 2) & 0xFFFF
            out[i] = p ^ (((t * (t ^ 1)) >> 8) & 0xFF)
            self.upd(p)
        return bytes(out)


def zc_header(pw, check, rng):
    """(cipher state after the header, encrypted 12-byte header) with check as last byte"""
    zc = ZipCrypto(pw)
    h = bytes(rng.randrange(256) for _ in range(11)) + bytes([check & 0xFF])
    return zc, zc.encrypt(h)


_DELTA = [0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957]
M32 = 0xFFFFFFFF


def _rol(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & M32 if n else x


def lea_round_keys(key):
    t = list(struct.unpack("<%dI" % (len(key) // 4), key))
    rk = []
    sh = [1, 3, 6, 11, 13, 17]
    if len(key) == 16:
        for i in range(24):
            d = _DELTA[i % 4]
            for j in range(4):
                t[j] = _rol((t[j] + _rol(d, i + j)) & M32, sh[j])
            rk.append([t[0], t[1], t[2], t[1], t[3], t[1]])
    elif len(key) == 24:
        for i in range(28):
            d = _DELTA[i % 6]
            for j in range(6):
                t[j] = _rol((t[j] + _rol(d, i + j)) & M32, sh[j])
            rk.append(list(t))
    else:
        for i in range(32):
            d = _DELTA[i % 8]
            r = []
            for j in range(6):
                x = (6 * i + j) % 8
                t[x] = _rol((t[x] + _rol(d, i + j)) & M32, sh[j])
                r.append(t[x])
            rk.append(r)
    return rk


def lea_encrypt_block(rk, blk):
    x0, x1, x2, x3 = struct.unpack("<4I", blk)
    for r in rk:
        n0 = _rol(((x0 ^ r[0]) + (x1 ^ r[1])) & M32, 9)
        n1 = _rol(((x1 ^ r[2]) + (x2 ^ r[3])) & M32, 27)
        n2 = _rol(((x2 ^ r[4]) + (x3 ^ r[5])) & M32, 29)
        x0, x1, x2, x3 = n0, n1, n2, x0
    return struct.pack("<4I", x0, x1, x2, x3)


class LeaCtr:
    """EGG LEA-CTR: big-endian counter from 0"""
    def __init__(self, key):
        self.rk = lea_round_keys(key)
        self.ctr = 0
        self.ks = b""

    def crypt(self, data):
        out = bytearray(len(data))
        for i, b in enumerate(data):
            if not self.ks:
                self.ks = lea_encrypt_block(self.rk, self.ctr.to_bytes(16, "big"))
                self.ctr = (self.ctr + 1) & ((1 << 128) - 1)
            out[i] = b ^ self.ks[0]
            self.ks = self.ks[1:]
        return bytes(out)


class AesCtr:
    """WinZip AES-CTR: little-endian counter from 1"""
    def __init__(self, key):
        from Cryptodome.Cipher import AES
        self.e = AES.new(key, AES.MODE_ECB)
        self.ctr = 1
        self.ks = b""

    def crypt(self, data):
        need = len(data) - len(self.ks)
        if need > 0:
            nb = (need + 15) // 16
            self.ks += self.e.encrypt(b"".join((self.ctr + i).to_bytes(16, "little") for i in range(nb)))
            self.ctr += nb
        ks, self.ks = self.ks[:len(data)], self.ks[len(data):]
        return bytes(a ^ b for a, b in zip(data, ks))


def have_aes():
    try:
        from Cryptodome.Cipher import AES  # noqa: F401
        return True
    except ImportError:
        return False


# ------------------------------------------------------------------ bits

class BitsMSB:
    def __init__(self):
        self.v = 0
        self.n = 0

    def put(self, n, v):
        self.v = (self.v << n) | (v & ((1 << n) - 1))
        self.n += n

    def bytes(self):
        pad = (-self.n) % 8
        return (self.v << pad).to_bytes((self.n + pad) // 8, "big") if self.n else b""


def _getbits_msb(v, nbits, pos, n):
    return (v >> (nbits - pos - n)) & ((1 << n) - 1)


# ------------------------------------------------------------------ ALZ

def alz_bzip2(data, chunk=600000):
    """bzip2 in ALZ framing: "DLZ\\1" + block body ... "DLZ\\2", no header or CRCs"""
    w = BitsMSB()
    for i in range(0, len(data), chunk):
        s = bz2.compress(data[i:i + chunk], 9)
        v = int.from_bytes(s, "big")
        nb = len(s) * 8
        crc = int.from_bytes(s[10:14], "big")
        assert s[:4] == b"BZh9" and s[4:10] == bytes.fromhex("314159265359")
        for pad in range(8):
            p = nb - pad - 80
            if (_getbits_msb(v, nb, p, 48) == 0x177245385090 and _getbits_msb(v, nb, p + 48, 32) == crc):
                break
        else:
            raise AssertionError("not a single-block bzip2 stream")
        body = p - 113                    # after the block magic, CRC and randomised bit
        w.put(32, 0x444C5A01)
        w.put(body, _getbits_msb(v, nb, 113, body))
    w.put(32, 0x444C5A02)
    return w.bytes()


def silly_order(param):
    o = list(range(19))
    for i in range(19):
        j = (i % 6) * 3 + param
        if j > 18:
            j %= 18
        if j != i:
            o[i], o[j] = o[j], o[i]
    return o


_STD_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]


def obfuscate(raw, order):
    """re-write the dynamic block headers of a raw deflate stream for another code
    length code order (ALZ method 3)"""
    bits = [(raw[i >> 3] >> (i & 7)) & 1 for i in range(len(raw) * 8)]
    pos = [0]

    def rd(n):
        v = 0
        for i in range(n):
            v |= bits[pos[0]] << i
            pos[0] += 1
        return v

    def table(lens):
        codes, code, bl = {}, 0, [0] * 16
        for l in lens:
            if l:
                bl[l] += 1
        nxt, code = [0] * 16, 0
        for b in range(1, 16):
            code = (code + bl[b - 1]) << 1
            nxt[b] = code
        for s, l in enumerate(lens):
            if l:
                codes[(l, nxt[l])] = s
                nxt[l] += 1
        return codes

    def sym(t):
        c = l = 0
        while True:
            c = (c << 1) | rd(1)
            l += 1
            if (l, c) in t:
                return t[(l, c)]
            if l > 15:
                raise ValueError("bad code")

    LB = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
    LE = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
    DE = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]
    edits = []                       # (start of HCLEN, end of the lengths, new bits)
    while True:
        final = rd(1)
        typ = rd(2)
        if typ == 0:
            pos[0] = (pos[0] + 7) & ~7
            n = rd(16)
            rd(16)
            pos[0] += 8 * n
        elif typ in (1, 2):
            if typ == 1:
                lt = table([8] * 144 + [9] * 112 + [7] * 24 + [8] * 8)
                dt = table([5] * 30)
            else:
                hlit, hdist = rd(5) + 257, rd(5) + 1
                hstart = pos[0]
                hclen = rd(4) + 4
                pl = [0] * 19
                for i in range(hclen):
                    pl[_STD_ORDER[i]] = rd(3)
                hend = pos[0]
                cnt = max([i + 1 for i in range(19) if pl[order[i]]] + [4])
                nb = [(cnt - 4 >> k) & 1 for k in range(4)]
                for i in range(cnt):
                    nb += [(pl[order[i]] >> k) & 1 for k in range(3)]
                edits.append((hstart, hend, nb))
                pt = table(pl)
                lens = []
                while len(lens) < hlit + hdist:
                    s = sym(pt)
                    if s < 16:
                        lens.append(s)
                    elif s == 16:
                        lens += [lens[-1]] * (3 + rd(2))
                    elif s == 17:
                        lens += [0] * (3 + rd(3))
                    else:
                        lens += [0] * (11 + rd(7))
                lt, dt = table(lens[:hlit]), table(lens[hlit:])
            while True:
                s = sym(lt)
                if s == 256:
                    break
                if s > 256:
                    rd(LE[s - 257])
                    d = sym(dt)
                    rd(DE[d])
        else:
            raise ValueError("bad block")
        if final:
            break
    out, last = [], 0
    for a, b, nb in edits:
        out += bits[last:a] + nb
        last = b
    out += bits[last:pos[0]]
    out += [0] * ((-len(out)) % 8)
    return bytes(sum(out[i + k] << k for k in range(8)) for i in range(0, len(out), 8))


def deflate_raw(data, level=6):
    c = zlib.compressobj(level, zlib.DEFLATED, -15, 9)
    return c.compress(data) + c.flush()


DOS_TIME = 0x58A1_6B2C   # 2024-05-01 13:25:24


def alz_entry(name, data, method=2, width=None, pw=None, attr=None, dostime=DOS_TIME, desc_extra=0,
              rng=None, comp=None, level=6):
    """one "BLZ\\1" record; data None = directory (no size block)"""
    rng = rng or random.Random(1)
    if data is None:
        return (b"BLZ\x01" + struct.pack("<HBIBB", len(name), 0x10 if attr is None else attr, dostime, desc_extra, 0) + name)
    if comp is None:
        comp = {0: lambda d: d, 1: alz_bzip2, 2: lambda d: deflate_raw(d, level),
                3: lambda d: obfuscate(deflate_raw(d, level), silly_order(len(d) % 16))}[method](data)
    crc = zlib.crc32(data)
    hdr12 = b""
    if pw is not None:
        zc, hdr12 = zc_header(pw, crc >> 24, rng)
        comp = zc.encrypt(comp)
    if width is None:
        m = max(len(comp), len(data))
        width = 1 if m < 0x100 else 2 if m < 0x10000 else 4 if m < 0x100000000 else 8
    fmt = {1: "B", 2: "H", 4: "I", 8: "Q"}[width]
    desc = (width << 4) | (1 if pw is not None else 0) | desc_extra
    return (b"BLZ\x01" + struct.pack("<HBIBB", len(name), 0x20 if attr is None else attr, dostime, desc, 0) +
            struct.pack("<BBI", method, 0, crc) + struct.pack("<" + fmt + fmt, len(comp), len(data)) +
            name + hdr12 + comp)


def alz_archive(records, comment=None, file_comments=None, volume=0):
    s = b"ALZ\x01" + struct.pack("<HH", 10, volume) + b"".join(records)
    sec = b""
    if comment is not None or file_comments:
        sec = b"ELZ\x01"
        for idx, text in sorted((file_comments or {}).items()):
            sec += struct.pack("<IH", idx, len(text)) + text
        if comment is not None:
            sec += struct.pack("<IH", 0xFFFFFFFF, len(comment)) + comment
    return s + sec + b"CLZ\x01" + struct.pack("<II", len(sec), 0) + b"CLZ\x02"


def alz_split(stream, part):
    """split an archive into .alz/.a00/... volumes (8-byte headers, 16-byte tails)"""
    chunks = [stream[:part]]
    rest = stream[part:]
    while rest:
        chunks.append(rest[:part])
        rest = rest[part:]
    vols = []
    for k, ch in enumerate(chunks):
        v = (b"ALZ\x01" + struct.pack("<HH", 10, k) if k else b"") + ch
        if k + 1 < len(chunks):
            v += b"CLZ\x01" + bytes(8) + b"CLZ\x03"
        vols.append(v)
    return vols


def alz_vol_names(base, n):
    return [base + ".alz"] + ["%s.%s%02d" % (base, chr(ord("a") + k // 100), k % 100) for k in range(n - 1)]


# ------------------------------------------------------------------ AZO encoder

class _RC:
    def __init__(self):
        self.low, self.up, self.pend = 0, M32, 0
        self.bits = BitsMSB()

    def unit(self, tb):
        if self.low == 0 and self.up == M32:
            return 1 << (32 - tb)
        return (self.up - self.low + 1) >> tb

    def _emit(self, b):
        self.bits.put(1, b)
        while self.pend:
            self.bits.put(1, b ^ 1)
            self.pend -= 1

    def _rescale(self):
        while not ((self.low ^ self.up) & 0x80000000):
            self._emit(self.low >> 31)
            self.low = (self.low << 1) & M32
            self.up = ((self.up << 1) | 1) & M32
        while (self.low & 0x40000000) and not (self.up & 0x40000000):
            self.pend += 1
            self.low = (self.low << 1) & 0x7FFFFFFF
            self.up = ((self.up << 1) | 0x80000001) & M32

    def bit(self, b, cum, tb):
        t = self.unit(tb)
        if b:
            self.low += t * cum
        else:
            self.up = self.low + t * cum - 1
        self._rescale()

    def uniform(self, v, tb):
        t = self.unit(tb)
        self.up = self.low + t * (v + 1) - 1
        self.low += t * v
        self._rescale()

    def finish(self):
        self.pend += 1
        self._emit(0 if self.low < 0x40000000 else 1)
        return self.bits.bytes()


class _Bool:
    def __init__(self):
        self.p = [2048] * 256
        self.st = 0

    def enc(self, rc, b):
        p = self.p[self.st]
        rc.bit(b, p, 12)
        self.p[self.st] = p - (p >> 6) if b else p + ((4096 - p) >> 6)
        self.st = ((self.st << 1) & 255) | b


def _tree_learn(p, pre, b):
    p[pre] = p[pre] - (p[pre] >> 4) if b else p[pre] + ((1024 - p[pre]) >> 4)


def _tree_enc(p, nb, rc, val):
    pre = 1
    for i in range(nb - 1, -1, -1):
        b = (val >> i) & 1
        rc.bit(b, p[pre], 10)
        _tree_learn(p, pre, b)
        pre = (pre << 1) | b


def _tree_upd(p, nb, val):
    pre = 1
    for i in range(nb - 1, -1, -1):
        b = (val >> i) & 1
        _tree_learn(p, pre, b)
        pre = (pre << 1) | b


def _tree_cmp(a, b, nb, val):
    x = y = pre = 1
    for i in range(nb - 1, -1, -1):
        v = (val >> i) & 1
        pa, pb = a[pre], b[pre]
        if (x | y) & 0xFFC00000:
            x >>= 10
            y >>= 10
        x = (x * (1024 - pa if v else pa)) & M32
        y = (y * (1024 - pb if v else pb)) & M32
        pre = (pre << 1) | v
    return 1 if x > y else -1 if x < y else 0


class _Pred:
    def __init__(self, keys, nb, sh):
        self.nb, self.sh = nb, sh
        self.fine = [[512] * (1 << nb) for _ in range(keys)]
        self.coarse = [[512] * (1 << nb) for _ in range((keys >> sh) or 1)]
        self.lucky = [0] * keys

    def enc(self, rc, ctx, val):
        f, c = self.fine[ctx], self.coarse[ctx >> self.sh]
        if self.lucky[ctx] >= 0:
            _tree_enc(f, self.nb, rc, val)
            _tree_upd(c, self.nb, val)
        else:
            _tree_enc(c, self.nb, rc, val)
            _tree_upd(f, self.nb, val)
        self.lucky[ctx] += _tree_cmp(f, c, self.nb, val)


class _Recent:
    def __init__(self, first):
        self.flag = _Bool()
        self.sel = [512, 512]
        self.v = [first, first + 1]

    def enc(self, rc, idx):
        """idx: position in the list, None = not a recent value (flag 0 only)"""
        if idx is None:
            self.flag.enc(rc, 0)
            return
        self.flag.enc(rc, 1)
        _tree_enc(self.sel, 1, rc, idx)
        v = self.v[idx]
        if idx:
            self.v[1] = self.v[0]
        self.v[0] = v

    def push(self, v):
        self.v = [v, self.v[0]]


def _codes(minv, sgap, gap):
    base, extra = [minv], [0]
    for i in range(1, 128):
        extra.append(0 if i < sgap else (i - sgap) // gap)
        base.append(base[-1] + (1 << extra[i - 1]))
    return base, extra


LEN_BASE, LEN_EXTRA = _codes(2, 32, 8)
DIST_BASE, DIST_EXTRA = _codes(1, 16, 4)
MAX_LEN = LEN_BASE[127] + (1 << LEN_EXTRA[127]) - 1


def _code_of(base, v):
    lo, hi = 0, 127
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if base[mid] <= v:
            lo = mid
        else:
            hi = mid - 1
    return lo


def dist_code(d):
    v = d - 1
    if v < 16:
        return v
    v -= 16
    e = (v // 4 + 1).bit_length() - 1
    return min(16 + e * 4 + (v - ((1 << e) - 1) * 4) // (1 << e), 127)


def azo_block(buf, rng):
    """code one AZO block (models fresh per block)"""
    rc = _RC()
    lit = _Pred(256, 8, 5)
    length = _Pred(128, 7, 4)
    match, reuse = _Bool(), _Bool()
    reuse_recent, dist_recent = _Recent(0), _Recent(1)
    reuse_tree, dist_tree = [512] * 128, [512] * 128
    dpos, dlen = [0] * 128, [2 + i for i in range(128)]
    n = len(buf)
    heads = {}
    lit.enc(rc, 0, buf[0])
    pos = 1

    def remember(p):
        if p + 3 <= n:
            heads.setdefault(buf[p:p + 3], []).append(p)

    remember(0)
    while pos < n:
        left = n - pos
        # longest new match from the hash chain (last 24 positions)
        best_l, best_d = 0, 0
        for q in reversed(heads.get(buf[pos:pos + 3], [])[-24:]):
            l = 0
            lim = min(left, MAX_LEN)
            while l < lim and buf[q + l] == buf[pos + l]:
                l += 1
            if l > best_l:
                best_l, best_d = l, pos - q
        if best_l < 3 and left >= 2:
            for d in dist_recent.v:                  # short repeat at a recent distance
                if 1 <= d <= pos and buf[pos:pos + 2] == buf[pos - d:pos - d + 2]:
                    best_l, best_d = 2, d
                    break
        # a reusable earlier match (position, length)
        reuse_j = None
        for j in range(16):
            p0, l0 = dpos[j], dlen[j]
            if p0 < pos and l0 <= left and l0 >= max(best_l, 2) and buf[pos:pos + l0] == buf[p0:p0 + l0]:
                reuse_j = j
                break
        r = rng.random()
        if reuse_j is not None and r < 0.9:
            match.enc(rc, 1)
            reuse.enc(rc, 1)
            if reuse_j in reuse_recent.v:
                reuse_recent.enc(rc, reuse_recent.v.index(reuse_j))
            else:
                reuse_recent.enc(rc, None)
                _tree_enc(reuse_tree, 7, rc, reuse_j)
                reuse_recent.push(reuse_j)
            p0, l0 = dpos[reuse_j], dlen[reuse_j]
            del dpos[reuse_j], dlen[reuse_j]
            dpos.insert(0, p0)
            dlen.insert(0, l0)
            step = l0
        elif best_l >= 2 and r < 0.97:
            l = best_l
            if l > 4 and rng.random() < 0.15:
                l = rng.randrange(2, l)              # vary the lengths
            d = best_d
            match.enc(rc, 1)
            reuse.enc(rc, 0)
            if d in dist_recent.v:
                dist_recent.enc(rc, dist_recent.v.index(d))
            else:
                dist_recent.enc(rc, None)
                c = _code_of(DIST_BASE, d)
                _tree_enc(dist_tree, 7, rc, c)
                if DIST_EXTRA[c]:
                    rc.uniform(d - DIST_BASE[c], DIST_EXTRA[c])
                dist_recent.push(d)
            c = _code_of(LEN_BASE, l)
            length.enc(rc, dist_code(d), c)
            if LEN_EXTRA[c]:
                rc.uniform(l - LEN_BASE[c], LEN_EXTRA[c])
            dpos.insert(0, pos)
            dlen.insert(0, l)
            dpos.pop()
            dlen.pop()
            step = l
        else:
            match.enc(rc, 0)
            lit.enc(rc, buf[pos - 1], buf[pos])
            step = 1
        for k in range(step):
            remember(pos + k)
        pos += step
    return rc.finish()


def x86_filter(buf, encode=True):
    b = bytearray(buf)
    i = 0
    while len(b) >= 5 and i < len(b) - 4:
        if b[i] in (0xE8, 0xE9):
            if b[i + 4] in (0x00, 0xFF):
                a = struct.unpack_from("<I", b, i + 1)[0]
                a = (a + i if encode else a - i) & M32
                a = a | 0xFF000000 if (a >> 24) & 1 else a & 0x00FFFFFF
                struct.pack_into("<I", b, i + 1, a)
            i += 5
        else:
            i += 1
    return bytes(b)


def azo_compress(data, block=32768, x86=False, seed=1, store=False):
    rng = random.Random(seed)
    out = b"1" + bytes([1 if x86 else 0])
    for i in range(0, len(data), block):
        buf = data[i:i + block]
        if x86:
            buf = x86_filter(buf)
        comp = None if store else azo_block(buf, rng)
        if comp is None or len(comp) + 8 > len(buf):
            comp = buf
        out += struct.pack(">III", len(buf), len(comp), len(buf) ^ len(comp)) + comp
    return out + struct.pack(">III", 0, 0, 0)


# ------------------------------------------------------------------ EGG

SIG = dict(EGG=0x41474745, FILE=0x0A8590E3, BLOCK=0x02B50C13, ENCRYPT=0x08D1470F, WINFO=0x2C86950B,
           PINFO=0x1EE922E5, NAME=0x0A8591AC, COMMENT=0x04C63672, SPLIT=0x24F5A262, SOLID=0x24E5A060,
           DUMMY=0x07463307, END=0x08E28222, SKIP=0xFFFF0000, GENC=0x08D144A8)
END = struct.pack("<I", SIG["END"])
FILETIME = 133590000000000000           # 2024-05-01 (UTC)
METHODS = {"store": 0, "deflate": 1, "bzip2": 2, "azo": 3, "lzma": 4}
ENCS = {"zip": 0, "aes128": 1, "aes256": 2, "lea128": 5, "lea256": 6}


def field(sig, data, flags=0):
    if flags & 1:
        return struct.pack("<IBI", SIG[sig], flags, len(data)) + data
    return struct.pack("<IBH", SIG[sig], flags, len(data)) + data


def egg_compress(method, data, azo_block_size=16384, seed=1):
    if method == "store":
        return data
    if method == "deflate":
        return deflate_raw(data)
    if method == "bzip2":
        return bz2.compress(data, 9)
    if method == "lzma":
        s = lzma.compress(data, format=lzma.FORMAT_ALONE, preset=6)
        return b"\x09\x14\x05\x00" + s[:5] + s[13:]
    if method == "azo":
        return azo_compress(data, azo_block_size, x86=False, seed=seed)
    if method == "azo-x86":
        return azo_compress(data, azo_block_size, x86=True, seed=seed)
    raise ValueError(method)


class Crypt:
    """per-file (or solid stream) cipher + the encryption field payload"""
    def __init__(self, kind, pw, rng, check_crc=0):
        self.kind = kind
        self.macs = None
        if kind == "zip":
            self.zc, hdr = zc_header(pw, check_crc >> 24, rng)
            self.payload = bytes([0]) + hdr + struct.pack("<I", check_crc)
            return
        kl = 16 if kind in ("aes128", "lea128") else 32
        salt = bytes(rng.randrange(256) for _ in range(kl // 2))
        dk = hashlib.pbkdf2_hmac("sha1", pw, salt, 1000, 2 * kl + 2)
        self.c = AesCtr(dk[:kl]) if kind.startswith("aes") else LeaCtr(dk[:kl])
        self.mac = hmac.new(dk[kl:2 * kl], digestmod=hashlib.sha1)
        self.head = bytes([ENCS[kind]]) + salt + dk[2 * kl:]

    def crypt(self, data):
        if self.kind == "zip":
            return self.zc.encrypt(data)
        ct = self.c.crypt(data)
        self.mac.update(ct)
        return ct

    def field_payload(self, footer=True):
        if self.kind == "zip":
            return self.payload
        return self.head + (self.mac.digest()[:10] if footer else b"")


class EggFile:
    def __init__(self, name, data=None, method="deflate", blocks=None, enc=None, pw=None, locale=None,
                 parent=None, win=True, posix=None, mtime=FILETIME, attr=None, fid=None, comment=None,
                 lzma_enc_header=False, name_flags=0, extra=b"", footer=True, raw_name=None):
        self.__dict__.update(locals())
        del self.__dict__["self"]


class Egg:
    def __init__(self, solid=False, seed=7, version=0x0100, header_id=0x1234ABCD):
        self.files = []
        self.solid = solid
        self.rng = random.Random(seed)
        self.version = version
        self.header_id = header_id
        self.solid_block = 4096
        self.solid_method = "deflate"
        self.solid_enc = None            # (kind, pw, "file" | "global")
        self.comment = None
        self.prefix_extra = b""

    def add(self, *a, **kw):
        f = EggFile(*a, **kw)
        if f.fid is None:
            f.fid = len(self.files)
        self.files.append(f)
        return f

    def _name_field(self, f):
        flags = f.name_flags
        body = b""
        if f.locale is not None:
            flags |= 8
            body += struct.pack("<H", f.locale)
        if f.parent is not None:
            flags |= 16
            body += struct.pack("<I", f.parent)
        if f.raw_name is not None:
            nm = f.raw_name
        elif f.locale in (949, 932):
            nm = f.name.encode("cp949" if f.locale == 949 else "cp932")
        else:
            nm = f.name.encode("utf-8")
        return field("NAME", body + nm, flags)

    def _file_fields(self, f, enc_payload=None):
        out = struct.pack("<IIQ", SIG["FILE"], f.fid, len(f.data or b""))
        out += self._name_field(f)
        if f.comment is not None:
            out += field("COMMENT", f.comment)
        if f.win:
            attr = f.attr if f.attr is not None else (0x80 if f.data is None else 0)
            out += field("WINFO", struct.pack("<QB", f.mtime, attr))
        if f.posix is not None:
            mode, mt = f.posix
            out += field("PINFO", struct.pack("<IIIQ", mode, 1000, 1000, mt))
        out += f.extra
        if enc_payload is not None:
            out += field("ENCRYPT", enc_payload)
        return out + END

    def _blocks(self, method, data, crypt=None, lzma_enc_header=False, sizes=None):
        """[(header bytes, data bytes)]"""
        parts, out = [], []
        if sizes:
            p = 0
            for s in sizes:
                parts.append(data[p:p + s])
                p += s
            assert p == len(data)
        else:
            parts = [data]
        for k, part in enumerate(parts):
            comp = egg_compress(method, part, seed=k + 1)
            if crypt is not None:
                if method == "lzma" and not lzma_enc_header:
                    comp = comp[:9] + crypt.crypt(comp[9:])
                else:
                    comp = crypt.crypt(comp)
            m = METHODS[method.split("-")[0]]
            hdr = struct.pack("<IBBIII", SIG["BLOCK"], m, 0, len(part), len(comp), zlib.crc32(part)) + END
            out.append((hdr, comp))
        return out

    def chunks(self):
        """the archive as [(bytes, cuttable)]"""
        pre = struct.pack("<IHII", SIG["EGG"], self.version, self.header_id, 0)
        if self.solid:
            pre += field("SOLID", b"")
        pre += self.prefix_extra
        ch = []
        solid_crypt = None
        if self.solid and self.solid_enc:
            kind, pw, where = self.solid_enc
            solid_crypt = Crypt(kind, pw, self.rng)
        recs = []
        for i, f in enumerate(self.files):
            if self.solid:
                last = i == len(self.files) - 1
                recs.append([f, None, last and solid_crypt is not None and self.solid_enc[2] == "file"])
                continue
            crypt = None
            if f.enc:
                crc0 = zlib.crc32(f.data or b"")
                crypt = Crypt(f.enc, f.pw, self.rng, crc0)
            blocks = [] if f.data is None or (not f.data and f.blocks is None) else \
                self._blocks(f.method, f.data, crypt, f.lzma_enc_header, f.blocks)
            recs.append([f, (crypt, blocks), False])
        solid_blocks = []
        if self.solid:
            stream = b"".join(f.data for f in self.files if f.data)
            sizes = [min(self.solid_block, len(stream) - p) for p in range(0, len(stream), self.solid_block)]
            if stream:
                solid_blocks = self._blocks(self.solid_method, stream, solid_crypt, False, sizes)
            if solid_crypt is not None and self.solid_enc[2] == "global":
                pre += field("GENC", solid_crypt.field_payload())
        ch.append((pre + END, False))
        for f, blk, carries_enc in recs:
            if blk is None:
                payload = solid_crypt.field_payload() if carries_enc else None
                ch.append((self._file_fields(f, payload), False))
                continue
            crypt, blocks = blk
            payload = crypt.field_payload(f.footer) if crypt else None
            ch.append((self._file_fields(f, payload), False))
            for h, d in blocks:
                ch.append((h, False))
                ch.append((d, True))
        for h, d in solid_blocks:
            ch.append((h, False))
            ch.append((d, True))
        if self.comment is not None:
            ch.append((field("COMMENT", self.comment), False))
        ch.append((END, False))
        return ch

    def build(self):
        return b"".join(c for c, _ in self.chunks())

    def build_split(self, size, ids=None):
        """volumes of at most about size bytes; headers and fields are never cut"""
        ch = self.chunks()
        vols, cur = [], bytearray()
        ids = ids or [self.header_id + k for k in range(1000)]
        first = ch[0][0]
        # the first volume's prefix gets the split field; later volumes start fresh
        assert first.startswith(struct.pack("<I", SIG["EGG"]))
        bodies = []
        body = bytearray()
        for data, cut in ch[1:]:
            data = bytes(data)
            while data:
                room = size - len(body)
                if len(data) <= room:
                    body += data
                    data = b""
                elif cut and room > 0:
                    body += data[:room]
                    data = data[room:]
                else:
                    if body:
                        bodies.append(bytes(body))
                    body = bytearray()
                    if not cut and len(data) > size:
                        body += data
                        data = b""
        bodies.append(bytes(body))
        n = len(bodies)
        for k, b in enumerate(bodies):
            hid = ids[k]
            split = field("SPLIT", struct.pack("<II", ids[k - 1] if k else 0, ids[k + 1] if k + 1 < n else 0))
            if k == 0:
                pre = first[:6] + struct.pack("<I", hid) + first[10:-4] + split + END
            else:
                pre = struct.pack("<IHII", SIG["EGG"], self.version, hid, 0) + split + END
            vols.append(pre + b)
        return vols


# ------------------------------------------------------------------ spec examples (EGG spec 1.0, section 3)

def spec_simple():
    return bytes.fromhex("45474741" "0001" "01000000" "00000000" "2282E208"
                         "E390850A" "00000000" "0500000000000000" "2282E208"
                         "130CB502" "00" "00" "05000000" "05000000" "86A61036" "2282E208") + b"hello" + bytes.fromhex("2282E208")


def spec_general():
    return bytes.fromhex("45474741" "0001" "01000000" "00000000" "2282E208"
                         "E390850A" "00000000" "0500000000000000"
                         "AC91850A" "00" "0900") + b"hello.txt" + bytes.fromhex(
                         "0B95862C" "00" "0900" "23C9A34F63FBC701" "00" "2282E208"
                         "130CB502" "00" "00" "05000000" "05000000" "86A61036" "2282E208") + b"hello" + bytes.fromhex("2282E208")


def spec_solid():
    return bytes.fromhex("45474741" "0001" "01000000" "00000000" "60A0E524" "00" "0000" "2282E208"
                         "E390850A" "00000000" "0100000000000000" "AC91850A" "00" "0500") + b"a.txt" + bytes.fromhex(
                         "0B95862C" "00" "0900" "23C9A34F63FBC701" "00" "2282E208"
                         "E390850A" "01000000" "0200000000000000" "AC91850A" "00" "0500") + b"b.txt" + bytes.fromhex(
                         "0B95862C" "00" "0900" "67FAA34F63FBC701" "00" "2282E208"
                         "130CB502" "00" "00" "03000000" "03000000" "C2412435" "2282E208") + b"abc" + bytes.fromhex("2282E208")
