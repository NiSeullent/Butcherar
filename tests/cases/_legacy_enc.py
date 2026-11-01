"""Small reference encoders for the legacy formats tested by fmt_legacy.py.

No writer exists for these formats in 고깃ZIP; the encoders produce valid
streams so the decoders can be checked against independent tools (lhasa,
7-Zip, Info-ZIP unzip, libmspack). They favour clarity over ratio: greedy
LZ77 with short hash chains.
"""
import heapq, struct, zlib

# ---------------------------------------------------------------- bit writers

class BitsMSB:
    def __init__(self):
        self.out = bytearray(); self.acc = 0; self.n = 0
    def put(self, nbits, val):
        if nbits == 0:
            return
        self.acc = (self.acc << nbits) | (val & ((1 << nbits) - 1)); self.n += nbits
        while self.n >= 8:
            self.n -= 8
            self.out.append((self.acc >> self.n) & 0xFF)
        self.acc &= (1 << self.n) - 1
    def code(self, c, l):
        self.put(l, c)
    def bytes(self, pad=0):
        if self.n:
            self.out.append(((self.acc << (8 - self.n)) | (((1 << (8 - self.n)) - 1) if pad else 0)) & 0xFF)
            self.n = 0; self.acc = 0
        return bytes(self.out)

class BitsLSB:
    def __init__(self):
        self.out = bytearray(); self.acc = 0; self.n = 0
    def put(self, nbits, val):
        self.acc |= (val & ((1 << nbits) - 1)) << self.n; self.n += nbits
        while self.n >= 8:
            self.out.append(self.acc & 0xFF); self.acc >>= 8; self.n -= 8
    def bytes(self):
        if self.n:
            self.out.append(self.acc & 0xFF); self.acc = 0; self.n = 0
        return bytes(self.out)

# ---------------------------------------------------------------- LZ77

def lz_tokens(data, window, minm, maxm, depth=8, hist=b""):
    """Greedy LZ77: list of int literals and (length, distance) matches.
    hist: dictionary preceding data that matches may reach into."""
    buf = bytes(hist) + bytes(data)
    n = len(buf)
    table = {}
    def insert(i):
        if i + 3 <= n:
            k = buf[i:i + 3]
            l = table.get(k)
            if l is None:
                table[k] = [i]
            else:
                l.append(i)
                if len(l) > 4 * depth:
                    del l[:-depth]
    for i in range(len(hist)):
        insert(i)
    toks = []
    i = len(hist)
    while i < n:
        bl = bd = 0
        if i + max(minm, 3) <= n:
            maxl = min(maxm, n - i)
            for j in reversed(table.get(buf[i:i + 3], ())[-depth:]):
                d = i - j
                if d > window:
                    break
                l = 3
                while l + 16 <= maxl and buf[j + l:j + l + 16] == buf[i + l:i + l + 16]:
                    l += 16
                while l < maxl and buf[j + l] == buf[i + l]:
                    l += 1
                if l > bl:
                    bl, bd = l, d
                    if l == maxl:
                        break
        if bl >= minm:
            toks.append((bl, bd))
            for k in range(i, i + bl):
                insert(k)
            i += bl
        else:
            toks.append(buf[i]); insert(i); i += 1
    return toks

# ---------------------------------------------------------------- Huffman

def huff_lens(freq, maxlen):
    """Code lengths (0 = unused) with max length maxlen."""
    n = len(freq)
    syms = [i for i in range(n) if freq[i]]
    lens = [0] * n
    if not syms:
        return lens
    if len(syms) == 1:
        lens[syms[0]] = 1
        return lens
    f = list(freq)
    while True:
        heap = [(f[i], i, i) for i in syms]
        heapq.heapify(heap)
        cnt = n
        kids = {}
        while len(heap) > 1:
            a = heapq.heappop(heap); b = heapq.heappop(heap)
            kids[cnt] = (a[2], b[2])
            heapq.heappush(heap, (a[0] + b[0], cnt, cnt)); cnt += 1
        stack = [(heap[0][2], 0)]
        while stack:
            node, d = stack.pop()
            if node < n:
                lens[node] = d
            else:
                stack.append((kids[node][0], d + 1)); stack.append((kids[node][1], d + 1))
        if max(lens) <= maxlen:
            return lens
        f = [(x + 1) // 2 if x else 0 for x in f]

def canon(lens):
    """Canonical codes, shorter first, then by symbol (MSB-first values)."""
    maxl = max(lens) if lens else 0
    count = [0] * (maxl + 2)
    for l in lens:
        if l:
            count[l] += 1
    nxt = [0] * (maxl + 2)
    code = 0
    for b in range(1, maxl + 1):
        code = (code + count[b - 1]) << 1 if b > 1 else 0
        nxt[b] = code
    codes = [0] * len(lens)
    for i, l in enumerate(lens):
        if l:
            codes[i] = nxt[l]; nxt[l] += 1
    return codes

def used(freq):
    return [i for i, f in enumerate(freq) if f]

# ---------------------------------------------------------------- CRCs

def crc16(data, crc=0):
    tab = _crc16_tab()
    for b in data:
        crc = (crc >> 8) ^ tab[(crc ^ b) & 0xFF]
    return crc

_T16 = None
def _crc16_tab():
    global _T16
    if _T16 is None:
        t = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
            t.append(c)
        _T16 = t
    return _T16

# ---------------------------------------------------------------- LHA -lh4..7-

LH_PARAMS = {4: (12, 14, 4), 5: (13, 14, 4), 6: (15, 16, 5), 7: (16, 17, 5)}

def _write_pt_len(w, lens, nn, nbit, special):
    n = nn
    while n > 0 and lens[n - 1] == 0:
        n -= 1
    w.put(nbit, n)
    i = 0
    while i < n:
        k = lens[i]; i += 1
        if k <= 6:
            w.put(3, k)
        else:
            w.put(k - 3, (1 << (k - 3)) - 2)
        if i == special:
            while i < 6 and lens[i] == 0:
                i += 1
            w.put(2, (i - 3) & 3)

def _c_len_tokens(c_len):
    n = len(c_len)
    while n > 0 and c_len[n - 1] == 0:
        n -= 1
    toks = []
    i = 0
    while i < n:
        k = c_len[i]; i += 1
        if k == 0:
            cnt = 1
            while i < n and c_len[i] == 0:
                i += 1; cnt += 1
            if cnt <= 2:
                toks += [(0, 0, 0)] * cnt
            elif cnt <= 18:
                toks.append((1, 4, cnt - 3))
            elif cnt == 19:
                toks.append((0, 0, 0)); toks.append((1, 4, 15))
            else:
                toks.append((2, 9, cnt - 20))
        else:
            toks.append((k + 2, 0, 0))
    return n, toks

def lh_encode(data, method, block=16384, toks=None):
    """-lh4- .. -lh7- (ar002 / LHA static Huffman), several blocks."""
    dicbit, np_, pbit = LH_PARAMS[method]
    if toks is None:
        toks = lz_tokens(data, 1 << dicbit, 3, 256)
    w = BitsMSB()
    for b0 in range(0, max(len(toks), 1), block):
        blk = toks[b0:b0 + block]
        if not blk:
            break
        cf = [0] * 510; pf = [0] * np_
        for t in blk:
            if isinstance(t, int):
                cf[t] += 1
            else:
                cf[256 + t[0] - 3] += 1; pf[(t[1] - 1).bit_length()] += 1
        w.put(16, len(blk))
        cu = used(cf)
        if len(cu) >= 2:
            c_len = huff_lens(cf, 16)
            n, ctoks = _c_len_tokens(c_len)
            tf = [0] * 19
            for s, _, _ in ctoks:
                tf[s] += 1
            tu = used(tf)
            if len(tu) >= 2:
                t_len = huff_lens(tf, 16)
                _write_pt_len(w, t_len, 19, 5, 3)
            else:
                t_len = [0] * 19
                w.put(5, 0); w.put(5, tu[0])
            t_code = canon(t_len)
            w.put(9, n)
            for s, eb, ev in ctoks:
                w.code(t_code[s], t_len[s]); w.put(eb, ev)
        else:
            c_len = [0] * 510
            w.put(5, 0); w.put(5, 0); w.put(9, 0); w.put(9, cu[0])
        c_code = canon(c_len)
        pu = used(pf)
        if len(pu) >= 2:
            p_len = huff_lens(pf, 16)
            _write_pt_len(w, p_len, np_, pbit, -1)
        else:
            p_len = [0] * np_
            w.put(pbit, 0); w.put(pbit, pu[0] if pu else 0)
        p_code = canon(p_len)
        for t in blk:
            if isinstance(t, int):
                w.code(c_code[t], c_len[t])
            else:
                s = 256 + t[0] - 3
                w.code(c_code[s], c_len[s])
                p = t[1] - 1; pc = p.bit_length()
                w.code(p_code[pc], p_len[pc])
                if pc > 1:
                    w.put(pc - 1, p & ((1 << (pc - 1)) - 1))
    return w.bytes()

# ---------------------------------------------------------------- LHarc -lh1- (LZHUF)

class _AdaptiveHuff:
    NCHAR = 314
    T = 627
    R = 626
    def __init__(self):
        N, T = self.NCHAR, self.T
        self.freq = [0] * (T + 1); self.son = [0] * T; self.prnt = [0] * (T + N)
        for i in range(N):
            self.freq[i] = 1; self.son[i] = i + T; self.prnt[i + T] = i
        i, j = 0, N
        while j <= self.R:
            self.freq[j] = self.freq[i] + self.freq[i + 1]
            self.son[j] = i; self.prnt[i] = self.prnt[i + 1] = j
            i += 2; j += 1
        self.freq[T] = 0xFFFF; self.prnt[self.R] = 0
    def reconst(self):
        T, N = self.T, self.NCHAR
        freq, son, prnt = self.freq, self.son, self.prnt
        j = 0
        for i in range(T):
            if son[i] >= T:
                freq[j] = (freq[i] + 1) // 2; son[j] = son[i]; j += 1
        i, j = 0, N
        while j < T:
            f = freq[i] + freq[i + 1]
            freq[j] = f
            k = j - 1
            while f < freq[k]:
                k -= 1
            k += 1
            freq[k + 1:j + 1] = freq[k:j]; freq[k] = f
            son[k + 1:j + 1] = son[k:j]; son[k] = i
            i += 2; j += 1
        for i in range(T):
            k = son[i]
            if k >= T:
                prnt[k] = i
            else:
                prnt[k] = prnt[k + 1] = i
    def update(self, c):
        freq, son, prnt, T = self.freq, self.son, self.prnt, self.T
        if freq[self.R] == 0x8000:
            self.reconst()
        c = prnt[c + T]
        while True:
            freq[c] += 1; k = freq[c]
            l = c + 1
            if k > freq[l]:
                l += 1
                while k > freq[l]:
                    l += 1
                l -= 1
                freq[c] = freq[l]; freq[l] = k
                i = son[c]; prnt[i] = l
                if i < T:
                    prnt[i + 1] = l
                j = son[l]; son[l] = i
                prnt[j] = c
                if j < T:
                    prnt[j + 1] = c
                son[c] = j
                c = l
            c = prnt[c]
            if c == 0:
                break
    def encode(self, w, c):
        bits = []
        k = self.prnt[c + self.T]
        while True:
            bits.append(k & 1)
            k = self.prnt[k]
            if k == self.R:
                break
        for b in reversed(bits):
            w.put(1, b)
        self.update(c)

_P_LEN_COUNTS = (1, 3, 8, 12, 24, 16)

def _lh1_pos_table():
    lens, codes = [], []
    code = 0
    for l, cnt in zip(range(3, 9), _P_LEN_COUNTS):
        for _ in range(cnt):
            lens.append(l); codes.append(code); code += 1
        code <<= 1
    return lens, codes

def lh1_encode(data):
    toks = lz_tokens(data, 4096, 3, 60, hist=b" " * 4096)
    plen, pcode = _lh1_pos_table()
    h = _AdaptiveHuff()
    w = BitsMSB()
    for t in toks:
        if isinstance(t, int):
            h.encode(w, t)
        else:
            h.encode(w, 256 + t[0] - 3)
            p = t[1] - 1
            w.put(plen[p >> 6], pcode[p >> 6]); w.put(6, p & 63)
    return w.bytes()

# ---------------------------------------------------------------- ring LZSS (lzs, lz5, SZDD)

def lz5_ring():
    r = bytearray()
    for i in range(256):
        r += bytes([i]) * 13
    r += bytes(range(256)) + bytes(range(255, -1, -1)) + bytes(128) + b" " * 110 + bytes(18)
    return bytes(r)

def _ring_hist(ring, start):
    return bytes(ring[(start + i) % len(ring)] for i in range(len(ring)))

def lzss_flag_encode(data, ring, start, minm=3, maxm=18):
    """flag-byte LZSS (LArc -lz5-, SZDD): 1 = literal, 0 = 12-bit ring position + 4-bit length."""
    toks = lz_tokens(data, len(ring), minm, maxm, hist=_ring_hist(ring, start))
    out = bytearray()
    r = start
    for g in range(0, len(toks), 8):
        grp = toks[g:g + 8]
        flags = 0; body = bytearray()
        for k, t in enumerate(grp):
            if isinstance(t, int):
                flags |= 1 << k; body.append(t); r += 1
            else:
                p = (r - t[1]) & 4095
                body += bytes([p & 0xFF, ((p >> 4) & 0xF0) | (t[0] - 3)]); r += t[0]
        out.append(flags); out += body
    return bytes(out)

def lzs_encode(data):
    """LArc -lzs-: 2 KiB ring of spaces, start 2048-17, lengths 2..17."""
    start = 2048 - 17
    toks = lz_tokens(data, 2048, 3, 17, hist=b" " * 2048)
    w = BitsMSB()
    r = start
    for t in toks:
        if isinstance(t, int):
            w.put(1, 1); w.put(8, t); r += 1
        else:
            w.put(1, 0); w.put(11, (r - t[1]) & 2047); w.put(4, t[0] - 2); r += t[0]
    return w.bytes()

# ---------------------------------------------------------------- LHA archive headers

def dos_time(y, mo, d, h, mi, s):
    return ((y - 1980) << 25) | (mo << 21) | (d << 16) | (h << 11) | (mi << 5) | (s // 2)

def lha_member(level, method, name, comp, raw, mtime=1600000000, dtime=None, os_id=b"U",
               dirname=None, unix_mode=None, wintime=None, attr=0x20, common_crc=True, ext_name=False):
    """One LHA member (header + data). name/dirname are bytes; dirname uses '/'
    for level 2/3 (converted to 0xFF), level 0/1 put the full path in the name."""
    method = method.encode() if isinstance(method, str) else method
    crc = crc16(raw)
    dtime = dtime if dtime is not None else dos_time(2020, 5, 17, 13, 45, 10)
    def ext(t, d):
        return bytes([t]) + d
    if level == 0:
        full = (dirname or b"") + name
        h = method + struct.pack("<IIIBBB", len(comp), len(raw), dtime, attr, 0, len(full)) + full + struct.pack("<H", crc)
        if unix_mode is not None:
            h += b"U\0" + struct.pack("<IHHH", mtime, unix_mode, 1000, 1000)
        return bytes([len(h), sum(h) & 0xFF]) + h + comp
    if level == 1:
        exts = []
        if dirname:
            exts.append(ext(2, dirname.replace(b"/", b"\xff")))
        if unix_mode is not None:
            exts.append(ext(0x50, struct.pack("<H", unix_mode)))
        exts.append(ext(0x54, struct.pack("<I", mtime)))
        blobs = b""
        sizes = [len(e) + 2 for e in exts]
        for k, e in enumerate(exts):
            blobs += e + struct.pack("<H", sizes[k + 1] if k + 1 < len(sizes) else 0)
        nm = b"" if ext_name else name
        if ext_name:
            pass
        base = method + struct.pack("<IIIBBB", len(comp) + len(blobs), len(raw), dtime, 0x20, 1, len(nm)) + nm + \
            struct.pack("<H", crc) + os_id + struct.pack("<H", sizes[0] if sizes else 0)
        return bytes([len(base), sum(base) & 0xFF]) + base + blobs + comp
    # level 2 / 3
    fs = 2 if level == 2 else 4
    exts = []
    if common_crc:
        exts.append(ext(0, b"\0\0"))
    exts.append(ext(1, name))
    if dirname:
        exts.append(ext(2, dirname.replace(b"/", b"\xff")))
    if unix_mode is not None:
        exts.append(ext(0x50, struct.pack("<H", unix_mode)))
    if wintime is not None:
        exts.append(ext(0x41, struct.pack("<QQQ", wintime, wintime, wintime)))
    sizes = [len(e) + fs for e in exts]
    pk = "<H" if fs == 2 else "<I"
    blobs = b""
    for k, e in enumerate(exts):
        blobs += e + struct.pack(pk, sizes[k + 1] if k + 1 < len(sizes) else 0)
    if level == 2:
        head = method + struct.pack("<IIIBBH", len(comp), len(raw), mtime, 0x20, 2, crc) + os_id + struct.pack("<H", sizes[0])
        total = 2 + len(head) + len(blobs)
        hdr = bytearray(struct.pack("<H", total) + head + blobs)
    else:
        head = method + struct.pack("<IIIBBH", len(comp), len(raw), mtime, 0x20, 3, crc) + os_id
        total = 2 + len(head) + 4 + 4 + len(blobs)
        hdr = bytearray(struct.pack("<H", 4) + head + struct.pack("<II", total, sizes[0]) + blobs)
    if common_crc:
        off = (24 if level == 2 else 28) + fs + 1
        hc = crc16(bytes(hdr))
        hdr[off:off + 2] = struct.pack("<H", hc)
    return bytes(hdr) + comp

def lha_compress(raw, method):
    if method == "-lh0-":
        return raw
    if method == "-lh1-":
        return lh1_encode(raw)
    if method == "-lzs-":
        return lzs_encode(raw)
    if method == "-lz5-":
        return lzss_flag_encode(raw, lz5_ring(), 4096 - 18)
    return lh_encode(raw, int(method[3]))

# ---------------------------------------------------------------- Unix compress

def compress_Z(data, maxbits=16, block=True, clear_every=0):
    """Unix compress as compress 4.x / ncompress decode it: codes in groups of 8
    (n_bits bytes), width changes and CLEARs pad to the group end, the width
    grows when the decoder's next free entry exceeds the current maximum code.
    clear_every: emit a CLEAR after that many codes (block mode, for testing)."""
    out = bytearray(b"\x1f\x9d" + bytes([maxbits | (0x80 if block else 0)]))
    maxmax = 1 << maxbits
    w = BitsLSB()
    st = {"n_bits": 9, "maxcode": 511, "free": 257 if block else 256, "ncodes": 0, "started": False}
    table = {}
    def pad():
        k = (8 - st["ncodes"] % 8) % 8
        for _ in range(k):
            w.put(st["n_bits"], 0)
        st["ncodes"] = 0
    def write(code):
        if st["free"] > st["maxcode"]:
            pad()
            st["n_bits"] += 1
            st["maxcode"] = maxmax if st["n_bits"] == maxbits else (1 << st["n_bits"]) - 1
        w.put(st["n_bits"], code); st["ncodes"] += 1
    def emit(code):
        write(code)
        if st["started"]:
            st["free"] = min(st["free"] + 1, maxmax)
        st["started"] = True
    if not data:
        return bytes(out)
    ent = data[0]
    since = 0
    for c in data[1:]:
        e = table.get((ent, c))
        if e is not None:
            ent = e; continue
        emit(ent); since += 1
        if st["free"] < maxmax:
            table[(ent, c)] = st["free"]        # the number the decoder will give it
        ent = c
        if clear_every and block and since >= clear_every:
            write(256); pad()
            st["n_bits"] = 9; st["maxcode"] = 511; st["free"] = 256
            table.clear(); since = 0
    emit(ent)
    return bytes(out) + w.bytes()

# ---------------------------------------------------------------- ZIP Shrink

def shrink_encode(data):
    """ZIP method 1 with partial clears, mirroring 7-Zip's decoder model."""
    MAXC = 8192
    EMPTY = -1
    parent = [EMPTY] * MAXC
    suffix = [0] * MAXC
    child = {}
    w = BitsLSB()
    nbits = 9
    head = 257
    last = -1
    last_str = b""
    i = 0
    n = len(data)
    clears = 0
    while i < n:
        h = head
        while h < MAXC and parent[h] != EMPTY:
            h += 1
        pending = last >= 0 and h < MAXC
        free_after = sum(1 for k in range(h + 1, MAXC) if parent[k] == EMPTY) if pending and h > MAXC - 600 else 999
        code = data[i]; L = 1
        if not (pending and free_after == 0):
            while i + L < n:
                nx = child.get((code, data[i + L]))
                if nx is None:
                    break
                code = nx; L += 1
            if pending:
                cand = last_str + last_str[:1]
                if len(cand) > L and data[i:i + len(cand)] == cand:
                    code = h; L = len(cand)
        while code >= (1 << nbits):
            w.put(nbits, 256); w.put(nbits, 1); nbits += 1
        w.put(nbits, code)
        cur = data[i:i + L]
        if pending:
            parent[h] = last; suffix[h] = cur[0]; child[(last, cur[0])] = h; head = h + 1
        last = code; last_str = cur; i += L
        if pending and free_after == 0 and i < n:
            # table now full and the last code is a literal: partial clear
            w.put(nbits, 256); w.put(nbits, 2)
            is_par = [False] * MAXC
            for k in range(257, MAXC):
                if parent[k] != EMPTY and parent[k] >= 0:
                    is_par[parent[k]] = True
            for k in range(257, MAXC):
                if not is_par[k]:
                    parent[k] = EMPTY
            child = {(parent[k], suffix[k]): k for k in range(257, MAXC) if parent[k] != EMPTY}
            head = 257
            clears += 1
    return w.bytes(), clears

# ---------------------------------------------------------------- ZIP Implode

def implode_encode(data, large, three):
    dl = 7 if large else 6
    window = 8192 if large else 4096
    minm = 3 if three else 2
    toks = lz_tokens(data, window, 3, minm + 63 + 255)
    lf = [1] * 256; nf = [1] * 64; df = [1] * 64
    for t in toks:
        if isinstance(t, int):
            lf[t] += 1
        else:
            nf[min(t[0] - minm, 63)] += 1; df[(t[1] - 1) >> dl] += 1
    trees = []
    if three:
        trees.append(huff_lens(lf, 16))
    trees.append(huff_lens(nf, 16)); trees.append(huff_lens(df, 16))
    w = BitsLSB()
    for lens in trees:
        groups = []
        for l in lens:
            if groups and groups[-1][0] == l and groups[-1][1] < 16:
                groups[-1][1] += 1
            else:
                groups.append([l, 1])
        w.put(8, len(groups) - 1)
        for l, c in groups:
            w.put(8, ((c - 1) << 4) | (l - 1))
    codes = [canon(t) for t in trees]
    def emit(ti, sym):
        l = trees[ti][sym]; c = codes[ti][sym]
        for b in range(l - 1, -1, -1):
            w.put(1, 1 - ((c >> b) & 1))       # inverted bits
    li, ni, di = (0, 1, 2) if three else (None, 0, 1)
    for t in toks:
        if isinstance(t, int):
            w.put(1, 1)
            if three:
                emit(li, t)
            else:
                w.put(8, t)
        else:
            w.put(1, 0)
            d = t[1] - 1
            w.put(dl, d & ((1 << dl) - 1))
            emit(di, d >> dl)
            L = t[0] - minm
            if L >= 63:
                emit(ni, 63); w.put(8, L - 63)
            else:
                emit(ni, L)
    return w.bytes()

def zip_raw(entries):
    """Minimal ZIP writer: entries = [(name, method, flags, comp, raw)]."""
    out = bytearray(); cd = bytearray()
    for name, method, flags, comp, raw in entries:
        crc = zlib.crc32(raw) & 0xFFFFFFFF
        off = len(out)
        lh = struct.pack("<IHHHHHIIIHH", 0x04034B50, 10, flags, method, 0x6000, 0x5021, crc, len(comp), len(raw), len(name), 0)
        out += lh + name + comp
        cd += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 10, 10, flags, method, 0x6000, 0x5021, crc, len(comp),
                          len(raw), len(name), 0, 0, 0, 0, 0x20, off) + name
    cdo = len(out)
    out += cd + struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(cd), cdo, 0)
    return bytes(out)

# ---------------------------------------------------------------- MS KWAJ

def kwaj_lzh_encode(data):
    """KWAJ method 3: all five tables sent as raw 4-bit lengths (type 3)."""
    toks = lz_tokens(data, 4096, 3, 17, hist=b" " * 4096)
    ML1, ML2, LL, OFF, LIT = range(5)
    seq = []
    lit_run = False
    i = 0
    while i < len(toks):
        if isinstance(toks[i], int):
            run = []
            while i < len(toks) and isinstance(toks[i], int) and len(run) < 32:
                run.append(toks[i]); i += 1
            seq.append((ML2 if lit_run else ML1, 0)); seq.append((LL, len(run) - 1))
            seq += [(LIT, b) for b in run]
            lit_run = len(run) != 32
        else:
            l, d = toks[i]; i += 1
            off = d & 4095
            seq.append((ML2 if lit_run else ML1, l - 2)); seq.append((OFF, off >> 6)); seq.append((-1, off & 63))
            lit_run = False
    nsym = (16, 16, 32, 64, 256)
    freqs = [[0] * n for n in nsym]
    for t, s in seq:
        if t >= 0:
            freqs[t][s] += 1
    lens = []
    for t in range(5):
        u = used(freqs[t])
        if len(u) == 1:
            freqs[t][(u[0] + 1) % nsym[t]] = 1      # two codes: a complete table
        lens.append(huff_lens(freqs[t], 15))
    codes = [canon(l) for l in lens]
    w = BitsMSB()
    for _ in range(6):
        w.put(4, 3)
    for t in range(5):
        for l in lens[t]:
            w.put(4, l)
    for t, s in seq:
        if t < 0:
            w.put(6, s)
        else:
            w.code(codes[t][s], lens[t][s])
    return w.bytes()

def kwaj_mszip_encode(data):
    out = bytearray(); hist = b""
    for k in range(0, len(data), 32768):
        chunk = data[k:k + 32768]
        co = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=hist) if hist else zlib.compressobj(9, zlib.DEFLATED, -15)
        comp = co.compress(chunk) + co.flush()
        out += struct.pack("<H", len(comp) + 2) + b"CK" + comp
        hist = (hist + chunk)[-32768:]
    return bytes(out) + b"\0\0"

def kwaj_file(method, raw, name=None, ext=None, with_len=True):
    if method == 0:
        comp = raw
    elif method == 1:
        comp = bytes(b ^ 0xFF for b in raw)
    elif method == 2:
        comp = lzss_flag_encode(raw, b" " * 4096, 4096 - 18)    # libmspack: QBasic window start
    elif method == 3:
        comp = kwaj_lzh_encode(raw)
    else:
        comp = kwaj_mszip_encode(raw)
    flags = 0; opt = b""
    if with_len:
        flags |= 1; opt += struct.pack("<I", len(raw))
    if name is not None:
        flags |= 8; opt += name + b"\0"
    if ext is not None:
        flags |= 0x10; opt += ext + b"\0"
    hdr = b"KWAJ\x88\xf0\x27\xd1" + struct.pack("<HHH", method, 14 + len(opt), flags) + opt
    return hdr + comp

def szdd_file(raw, missing=0):
    return b"SZDD\x88\xf0\x27\x33A" + bytes([missing]) + struct.pack("<I", len(raw)) + \
        lzss_flag_encode(raw, b" " * 4096, 4096 - 16)

def szqb_file(raw):
    return b"SZ \x88\xf0\x27\x33\xd1" + struct.pack("<I", len(raw)) + lzss_flag_encode(raw, b" " * 4096, 4096 - 18)
