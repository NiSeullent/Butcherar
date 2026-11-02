"""
Builders for the DMG / HFS+ tests (tests/cases/fmt_dmg_hfs.py).

HfsPlus: writes an HFS+ / HFSX volume from scratch (no mounting needed):
  allocation bitmap, catalog / extents overflow / attributes B-trees with index
  nodes, thread records, folders, files with data and resource forks,
  fragmented forks (extents overflow records, also for the catalog file
  itself), symlinks, file hard links (iNode files in the private data folder),
  directory hard links, decmpfs compressed files (zlib / LZVN / LZFSE, inline or
  in the resource fork), Finder flags, BSD owner/mode, HFS wrapper.

udif(): wraps a raw disk image into a UDIF .dmg (koly trailer, XML plist or
classic resource fork with blkx entries, mish tables; chunks stored, zero,
ignored, ADC, zlib, bzip2, LZFSE, XZ).

Everything is big-endian and follows Apple TN1150 / the UDIF layout used by
hdiutil.
"""
import base64, bz2, lzma, struct, zlib

try:
    import lzfse as _lzfse
except ImportError:                     # pip install pyliblzfse
    _lzfse = None

HFS_EPOCH = 2082844800

def hfs_time(unix):
    return (unix + HFS_EPOCH) & 0xFFFFFFFF

# ---------------------------------------------------------------- codecs

def adc_compress(data):
    """Greedy ADC (Apple Data Compression): literal runs and 2/3-byte matches."""
    out, lit, i, n = bytearray(), bytearray(), 0, len(data)
    table = {}

    def flush():
        while lit:
            c = lit[:128]
            out.append(0x80 | (len(c) - 1))
            out.extend(c)
            del lit[:128]
    while i < n:
        best_l, best_d = 0, 0
        if i + 3 <= n:
            key = data[i:i + 3]
            j = table.get(key)
            table[key] = i
            if j is not None and i - j <= 65536:
                l = 0
                while l < 67 and i + l < n and data[j + l] == data[i + l]:
                    l += 1
                best_l, best_d = l, i - j
        if best_l >= 3 and not (best_l == 3 and best_d > 1024):
            flush()
            if best_d <= 1024 and best_l <= 18:
                out += bytes([((best_l - 3) << 2) | ((best_d - 1) >> 8), (best_d - 1) & 0xFF])
            else:
                out += bytes([0x40 | (best_l - 4)]) + (best_d - 1).to_bytes(2, "big")
            for k in range(i + 1, min(i + best_l, n - 2)):
                table[data[k:k + 3]] = k
            i += best_l
        else:
            lit.append(data[i])
            i += 1
    flush()
    return bytes(out)

def lzvn_literals(data):
    """LZVN stream made of literal opcodes only (+ end of stream)."""
    out = bytearray()
    i = 0
    while i < len(data):
        c = min(len(data) - i, 271)
        out += bytes([0xE0, c - 16]) if c >= 16 else bytes([0xE0 | c])
        out += data[i:i + c]
        i += c
    return bytes(out + b"\x06" + bytes(7))

_lzvn_enc = None

def lzvn_compress(data):
    """Real LZVN matches when tests/cases/codec_misc.py's encoder is importable."""
    global _lzvn_enc
    if _lzvn_enc is None:
        try:
            import codec_misc
            _lzvn_enc = codec_misc.lzvn_compress
        except Exception:
            _lzvn_enc = lzvn_literals
    return _lzvn_enc(data)

def lzfse_compress(data):
    if _lzfse is None:
        raise RuntimeError("pyliblzfse missing")
    return _lzfse.compress(data)

# ---------------------------------------------------------------- B-trees

def _node(kind, height, recs, ns, flink=0, blink=0):
    b = bytearray(ns)
    struct.pack_into(">IIbBHH", b, 0, flink, blink, kind, height, len(recs), 0)
    off = 14
    offs = []
    for r in recs:
        assert len(r) % 2 == 0
        offs.append(off)
        b[off:off + len(r)] = r
        off += len(r)
    offs.append(off)
    assert off + 2 * len(offs) <= ns, "node overflow"
    for i, o in enumerate(offs):
        struct.pack_into(">H", b, ns - 2 * (i + 1), o)
    return bytes(b)

def _pack(recs, ns):
    """split records into nodes (each node: 14 + sum + 2 * (n + 1) <= ns)"""
    groups, cur, used = [], [], 14 + 2
    for r in recs:
        need = len(r) + 2
        if cur and used + need > ns:
            groups.append(cur)
            cur, used = [], 14 + 2
        cur.append(r)
        used += need
    if cur:
        groups.append(cur)
    return groups

def btree(records, ns, max_key, key_cmp=0, var_index=True, total_nodes=None, index_key=None, btype=0):
    """records: sorted list of (key bytes incl. length field, data bytes).
    Returns the B-tree file bytes (total_nodes * ns)."""
    leafrecs = []
    for k, d in records:
        r = k + d
        if len(r) % 2:
            r += b"\0"
        leafrecs.append(r)
    groups = _pack(leafrecs, ns)
    nodes = {}                  # node number -> (kind, height, records, fLink, bLink)
    nxt = 1
    # leaves
    leaf_nums = list(range(nxt, nxt + len(groups)))
    nxt += len(groups)
    first_keys = []
    gi = 0
    for g in groups:
        first_keys.append(records[gi][0])
        gi += len(g)
    level_nodes = [(n, fk) for n, fk in zip(leaf_nums, first_keys)]
    for i, (n, g) in enumerate(zip(leaf_nums, groups)):
        nodes[n] = (-1, 1, g, leaf_nums[i + 1] if i + 1 < len(leaf_nums) else 0, leaf_nums[i - 1] if i else 0)
    height = 1
    while len(level_nodes) > 1:
        height += 1
        irecs = []
        for n, fk in level_nodes:
            k = index_key(fk) if index_key else fk
            if not var_index:
                k = k + bytes(max_key + 2 - len(k))
            irecs.append((k + struct.pack(">I", n), fk))
        igroups, cur, used = [], [], 16
        for r, fk in irecs:
            if cur and used + len(r) + 2 > ns:
                igroups.append(cur)
                cur, used = [], 16
            cur.append((r, fk))
            used += len(r) + 2
        if cur:
            igroups.append(cur)
        nums = list(range(nxt, nxt + len(igroups)))
        nxt += len(igroups)
        for i, (n, g) in enumerate(zip(nums, igroups)):
            nodes[n] = (0, height, [r for r, _ in g], nums[i + 1] if i + 1 < len(nums) else 0, nums[i - 1] if i else 0)
        level_nodes = [(n, g[0][1]) for n, g in zip(nums, igroups)]
    root = level_nodes[0][0] if level_nodes else 0
    used = nxt
    total = total_nodes or used
    total = max(total, used)
    map_bits = (ns - 14 - 106 - 128 - 8) * 8
    assert total <= map_bits, "B-tree needs map nodes"
    hdr = struct.pack(">HIIIIHHII", height if records else 0, root, len(records),
                      leaf_nums[0] if leaf_nums else 0, leaf_nums[-1] if leaf_nums else 0,
                      ns, max_key, total, total - used)
    hdr += struct.pack(">HIBBI", 0, ns, btype, key_cmp, 6 if var_index else 2) + bytes(64)
    assert len(hdr) == 106
    bm = bytearray(ns - 14 - 106 - 128 - 8)
    for i in range(used):
        bm[i >> 3] |= 0x80 >> (i & 7)
    out = bytearray(total * ns)
    out[0:ns] = _node(1, 0, [hdr, bytes(128), bytes(bm)], ns)
    for n, (kind, h, recs, fl, bl) in nodes.items():
        out[n * ns:(n + 1) * ns] = _node(kind, h, recs, ns, fl, bl)
    return bytes(out)

# ---------------------------------------------------------------- HFS+

def _fold(c):
    if c == 0:
        return 0xFFFF
    if 0x41 <= c <= 0x5A:
        return c + 32
    return c

def u16name(s):
    return s.encode("utf-16-be")

class Item:
    def __init__(self, cnid, parent, name, folder):
        self.cnid, self.parent, self.name, self.folder = cnid, parent, name, folder
        self.mode = 0o40755 if folder else 0o100644
        self.mtime = 1700000000
        self.uid = self.gid = 0
        self.data = b""
        self.rsrc = b""
        self.children = []
        self.ftype = self.creator = b"\0\0\0\0"
        self.fdflags = 0
        self.flags = 0
        self.special = 0
        self.owner_flags = 0
        self.decmpfs = None         # attribute value (bytes)
        self.fragment = 0           # split forks into this many extents
        self.dext = self.rext = []

class HfsPlus:
    def __init__(self, volname="Test", bs=4096, hfsx=False, case_sensitive=False, node_size=4096,
                 cat_fragments=0, journal_files=False, dirty_journal=False):
        self.bs, self.hfsx, self.cs, self.ns = bs, hfsx, case_sensitive, node_size
        self.cat_fragments = cat_fragments
        self.journal_files = journal_files
        self.dirty_journal = dirty_journal
        self.items = {2: Item(2, 1, volname, True)}
        self.next = 16
        self.paths = {"": 2}
        self.priv_file = self.priv_dir = None
        self.inodes = 0

    # ---- tree
    def _new(self, parent, name, folder):
        cnid = self.next
        self.next += 1
        it = Item(cnid, parent, name, folder)
        self.items[cnid] = it
        self.items[parent].children.append(cnid)
        return it

    def _dir_of(self, path):
        parts = path.split("/")
        cur = ""
        cnid = 2
        for p in parts[:-1]:
            cur = cur + "/" + p if cur else p
            if cur not in self.paths:
                self.paths[cur] = self._new(cnid, p, True).cnid
            cnid = self.paths[cur]
        return cnid, parts[-1]

    def mkdir(self, path, mode=0o755, mtime=None):
        parent, name = self._dir_of(path)
        it = self._new(parent, name, True)
        it.mode = 0o40000 | mode
        if mtime is not None:
            it.mtime = mtime
        self.paths[path] = it.cnid
        return it

    def add(self, path, data, rsrc=b"", mode=0o644, mtime=None, fragment=0, locked=False, invisible=False,
            ftype=b"\0\0\0\0", creator=b"\0\0\0\0", uid=501, gid=20):
        parent, name = self._dir_of(path)
        it = self._new(parent, name, False)
        it.data, it.rsrc, it.mode, it.fragment = data, rsrc, 0o100000 | mode, fragment
        it.uid, it.gid = uid, gid
        if mtime is not None:
            it.mtime = mtime
        if locked:
            it.flags |= 1
        if invisible:
            it.fdflags |= 0x4000
        it.ftype, it.creator = ftype, creator
        return it

    def symlink(self, path, target):
        it = self.add(path, target.encode())
        it.mode = 0o120755
        it.ftype, it.creator = b"slnk", b"rhap"
        return it

    def _private(self, kind):
        if kind == 1:
            if self.priv_file is None:
                it = self._new(2, "\0\0\0\0HFS+ Private Data", True)
                it.mode = 0o40000
                it.fdflags = 0x4000
                self.priv_file = it.cnid
            return self.priv_file
        if self.priv_dir is None:
            it = self._new(2, ".HFS+ Private Directory Data\r", True)
            it.mode = 0o41333
            it.fdflags = 0x4000
            self.priv_dir = it.cnid
        return self.priv_dir

    def hardlink(self, paths, data, mode=0o644, compress=None):
        """one iNode file shown at every path"""
        priv = self._private(1)
        num = self.next + 1000
        inode = self._new(priv, "iNode%d" % num, False)
        inode.data, inode.mode = data, 0o100000 | mode
        inode.special = len(paths)
        if compress:
            self.compress(inode, compress)
        for p in paths:
            parent, name = self._dir_of(p)
            it = self._new(parent, name, False)
            it.ftype, it.creator = b"hlnk", b"hfs+"
            it.special = num
            it.flags |= 0x20
            it.mode = 0o100000 | mode
        return inode

    def dirlink(self, paths, target_dir):
        """directory hard links: target_dir moves to the private store as dir_<n>"""
        priv = self._private(2)
        tcnid = self.paths[target_dir]
        t = self.items[tcnid]
        self.items[t.parent].children.remove(tcnid)
        t.parent = priv
        t.name = "dir_%d" % tcnid
        self.items[priv].children.append(tcnid)
        del self.paths[target_dir]
        for p in paths:
            parent, name = self._dir_of(p)
            it = self._new(parent, name, False)
            it.ftype, it.creator = b"fdrp", b"MACS"
            it.special = tcnid
            it.flags |= 0x20
            it.mode = 0o100000 | 0o755

    def compress(self, it, kind, raw_blocks=False):
        """decmpfs: kind = zlib|lzvn|lzfse|store + '-inline' / '-rsrc'"""
        data = it.data
        fam, where = kind.split("-")
        types = {("zlib", "inline"): 3, ("zlib", "rsrc"): 4, ("lzvn", "inline"): 7, ("lzvn", "rsrc"): 8,
                 ("lzfse", "inline"): 11, ("lzfse", "rsrc"): 12, ("store", "inline"): 1}
        t = types[(fam, where)]

        def enc(b):
            if fam == "zlib":
                z = zlib.compress(b, 9)
                return z if len(z) < len(b) and not raw_blocks else b"\xff" + b
            if fam == "lzvn":
                z = lzvn_compress(b)
                return z if len(z) < len(b) and not raw_blocks else b"\x06" + b
            if fam == "lzfse":
                z = lzfse_compress(b)
                return z if len(z) < len(b) and not raw_blocks else b"\xff" + b
            return b
        hdr = b"fpmc" + struct.pack("<IQ", t, len(data))
        if where == "inline":
            it.decmpfs = hdr + enc(data)
            assert len(it.decmpfs) <= 3802, "inline decmpfs value too big for an attribute record"
        else:
            blocks = [enc(data[i:i + 65536]) for i in range(0, len(data), 65536)]
            if t == 4:
                n = len(blocks)
                body = bytearray(struct.pack("<I", n))
                off = 4 + 8 * n
                for b in blocks:
                    body += struct.pack("<II", off, len(b))
                    off += len(b)
                for b in blocks:
                    body += b
                res = struct.pack(">I", len(body)) + bytes(body)
                dlen = len(res)
                rmap = bytes(16) + bytes(4) + bytes(2) + struct.pack(">HHH", 0, 28, 50)
                rmap += struct.pack(">H4sHH", 0, b"cmpf", 0, 10) + struct.pack(">HHBBHI", 1, 0xFFFF, 0, 0, 0, 0)
                assert len(rmap) == 50
                rf = struct.pack(">IIII", 256, 256 + dlen, dlen, 50) + bytes(240) + res + rmap
            else:
                n = len(blocks)
                offs = [4 * (n + 1)]
                for b in blocks:
                    offs.append(offs[-1] + len(b))
                rf = b"".join(struct.pack("<I", o) for o in offs) + b"".join(blocks)
            it.rsrc = rf
            it.decmpfs = hdr
        it.owner_flags |= 0x20
        it.flags |= 0x04
        it.data = b""
        return it

    # ---- layout
    def _sortkey(self, parent, name):
        units = struct.unpack(">%dH" % (len(name.encode("utf-16-be")) // 2), name.encode("utf-16-be"))
        if not self.cs:
            units = tuple(_fold(u) for u in units)
        return (parent, units)

    def build(self, extra_blocks=16):
        bs, ns = self.bs, self.ns
        if self.journal_files:
            j = self.add(".journal", bytes(bs * 2))
            j.fdflags |= 0x4000
            ji = self.add(".journal_info_block", bytes(bs))
            ji.fdflags |= 0x4000
        files = [i for i in self.items.values() if not i.folder]
        folders = [i for i in self.items.values() if i.folder]
        # catalog records with placeholder extents (sizes do not depend on them)
        recs = self._catalog_records(dummy=True)
        attrs = self._attr_records()
        nb = lambda n: (n + bs - 1) // bs
        cat_nodes = len(btree(recs, ns, 516, var_index=True, index_key=None)) // ns + 4
        attr_nodes = (len(btree(attrs, ns, 266, var_index=True)) // ns + 2) if attrs else 0
        data_blocks = sum(nb(len(i.data)) * (2 if i.fragment else 1) + nb(len(i.rsrc)) * (2 if i.fragment else 1)
                          for i in files)
        ext_nodes = 4 + sum(1 for i in files if i.fragment) // 8
        sys_blocks = nb(cat_nodes * ns) * (2 if self.cat_fragments else 1) + nb(attr_nodes * ns) + nb(ext_nodes * ns)
        total = 4 + sys_blocks + data_blocks + extra_blocks
        total += nb((total + 7) // 8) + 2
        self.total = total
        self.used = bytearray(total)
        hdr_blocks = nb(1536)
        for b in range(hdr_blocks):
            self.used[b] = 1
        self.used[total - 1] = 1                         # alternate volume header
        if bs == 512:
            self.used[total - 2] = 1
        self.cursor = hdr_blocks
        bm_size = (total + 7) // 8
        self.alloc_ext = self._alloc(nb(bm_size))
        self.ext_ext = self._alloc(nb(ext_nodes * ns))
        if self.cat_fragments:
            self.cat_ext = self._alloc_frag(nb(cat_nodes * ns), self.cat_fragments)
        else:
            self.cat_ext = self._alloc(nb(cat_nodes * ns))
        self.attr_ext = self._alloc(nb(attr_nodes * ns)) if attr_nodes else []
        for i in sorted(files, key=lambda x: x.cnid):
            i.dext = self._alloc_frag(nb(len(i.data)), i.fragment) if i.fragment else self._alloc(nb(len(i.data)))
            i.rext = self._alloc_frag(nb(len(i.rsrc)), i.fragment) if i.fragment else self._alloc(nb(len(i.rsrc)))
        # extents overflow records
        xrecs = []
        def overflow(fileid, fork, exts):
            done = sum(c for _, c in exts[:8])
            rest = exts[8:]
            while rest:
                chunk, rest = rest[:8], rest[8:]
                d = b"".join(struct.pack(">II", s, c) for s, c in chunk) + bytes(8 * (8 - len(chunk)))
                xrecs.append((struct.pack(">HBBII", 10, fork, 0, fileid, done), d))
                done += sum(c for _, c in chunk)
        overflow(4, 0, self.cat_ext)
        for i in files:
            overflow(i.cnid, 0, i.dext)
            overflow(i.cnid, 0xFF, i.rext)
        xrecs.sort(key=lambda r: (struct.unpack(">I", r[0][4:8])[0], r[0][2], struct.unpack(">I", r[0][8:12])[0]))
        recs = self._catalog_records(dummy=False)
        cat = btree(recs, ns, 516, key_cmp=(0xBC if self.cs else 0xCF) if self.hfsx else 0, var_index=True,
                    total_nodes=sum(c for _, c in self.cat_ext) * bs // ns)
        ext = btree(xrecs, ns, 10, var_index=False, total_nodes=sum(c for _, c in self.ext_ext) * bs // ns)
        att = btree(attrs, ns, 266, var_index=True, total_nodes=sum(c for _, c in self.attr_ext) * bs // ns) if attrs else b""
        img = bytearray(total * bs)

        def put(exts, data):
            off = 0
            for s, c in exts:
                chunk = data[off:off + c * bs]
                img[s * bs:s * bs + len(chunk)] = chunk
                off += c * bs
        put(self.ext_ext, ext)
        put(self.cat_ext, cat)
        put(self.attr_ext, att)
        for i in files:
            put(i.dext, i.data)
            put(i.rext, i.rsrc)
        bm = bytearray(nb(bm_size) * bs)
        for b in range(total):
            if self.used[b]:
                bm[b >> 3] |= 0x80 >> (b & 7)
        put(self.alloc_ext, bm)
        free = total - sum(self.used)
        vh = bytearray(512)
        attrs_bits = 0x100 if not self.dirty_journal else 0x2000
        struct.pack_into(">2sHII", vh, 0, b"HX" if self.hfsx else b"H+", 5 if self.hfsx else 4, attrs_bits, 0x31302E30)
        t = hfs_time(1700000000)
        struct.pack_into(">IIIII", vh, 12, 0, t, t, 0, t)
        struct.pack_into(">II", vh, 32, len(files), len(folders) - 1)
        struct.pack_into(">IIIIIII", vh, 40, bs, total, free, self.cursor, bs, bs, self.next)
        struct.pack_into(">IQ", vh, 68, 1, 1)

        def fork(off, size, exts):
            struct.pack_into(">QII", vh, off, size, bs if size else 0, sum(c for _, c in exts))
            for k, (s, c) in enumerate(exts[:8]):
                struct.pack_into(">II", vh, off + 16 + 8 * k, s, c)
        fork(112, len(bm), self.alloc_ext)
        fork(192, len(ext), self.ext_ext)
        fork(272, len(cat), self.cat_ext)
        fork(352, len(att), self.attr_ext)
        img[1024:1536] = vh
        img[total * bs - 1024:total * bs - 512] = vh
        return bytes(img)

    def _alloc(self, n):
        if not n:
            return []
        s = self.cursor
        for b in range(s, s + n):
            assert not self.used[b], "allocation overlap"
            self.used[b] = 1
        self.cursor += n
        return [(s, n)]

    def _alloc_frag(self, n, parts):
        """n blocks in up to `parts` extents separated by one-block gaps"""
        out = []
        left = n
        k = max(1, min(parts, n))
        for i in range(k):
            c = left // (k - i)
            out += self._alloc(c)
            left -= c
            self.cursor += 1                          # gap (stays free)
        return out

    def _fork(self, size, exts):
        b = struct.pack(">QII", size, 0, sum(c for _, c in exts))
        e8 = exts[:8]
        b += b"".join(struct.pack(">II", s, c) for s, c in e8) + bytes(8 * (8 - len(e8)))
        return b

    def _perms(self, it):
        return struct.pack(">IIBBHI", it.uid, it.gid, 0, it.owner_flags, it.mode, it.special)

    def _catalog_records(self, dummy):
        recs = []
        t = lambda it: hfs_time(it.mtime)
        for it in self.items.values():
            nm = u16name(it.name)
            key = struct.pack(">HIH", 6 + len(nm), it.parent, len(nm) // 2) + nm
            if it.folder:
                d = struct.pack(">hHII", 1, 0, len(it.children), it.cnid)
                d += struct.pack(">IIIII", t(it), t(it), t(it), t(it), 0)
                d += self._perms(it)
                d += bytes(8) + struct.pack(">H", it.fdflags) + bytes(6)      # FolderInfo
                d += bytes(16) + struct.pack(">II", 0, 0)
                assert len(d) == 88
                thr_type = 3
            else:
                d = struct.pack(">hHII", 2, it.flags | 0x02, 0, it.cnid)
                d += struct.pack(">IIIII", t(it), t(it), t(it), t(it), 0)
                d += self._perms(it)
                d += it.ftype + it.creator + struct.pack(">H", it.fdflags) + bytes(6)
                d += bytes(16) + struct.pack(">II", 0, 0)
                d += self._fork(len(it.data), [] if dummy else it.dext)
                d += self._fork(len(it.rsrc), [] if dummy else it.rext)
                assert len(d) == 248
                thr_type = 4
            recs.append((self._sortkey(it.parent, it.name), key, d))
            # thread record: key (own CNID, empty name) -> parent + name
            tk = struct.pack(">HIH", 6, it.cnid, 0)
            td = struct.pack(">hHIH", thr_type, 0, it.parent, len(nm) // 2) + nm
            recs.append((self._sortkey(it.cnid, ""), tk, td))
        recs.sort(key=lambda r: r[0])
        return [(k, d) for _, k, d in recs]

    def _attr_records(self):
        out = []
        name = u16name("com.apple.decmpfs")
        for it in sorted(self.items.values(), key=lambda x: x.cnid):
            if it.decmpfs is None:
                continue
            key = struct.pack(">HHIIH", 12 + len(name), 0, it.cnid, 0, len(name) // 2) + name
            v = it.decmpfs
            d = struct.pack(">III", 0x10, 0, 0) + struct.pack(">I", len(v)) + v
            out.append((key, d))
        return out

def hfs_wrapper(hfsplus, volname=b"Wrapper"):
    """Classic HFS volume (MDB) embedding the HFS+ volume (as old Mac OS 8/9 disks)."""
    abs_ = 4096
    start = 16                     # drAlBlSt in 512-byte sectors (8 KiB)
    nblk = (len(hfsplus) + abs_ - 1) // abs_
    img = bytearray(start * 512 + nblk * abs_ + 1024 + 512)
    img[start * 512:start * 512 + len(hfsplus)] = hfsplus
    m = bytearray(512)
    struct.pack_into(">2sIIHHHHHIIHIH", m, 0, b"BD", 0, 0, 0x100, 0, 3, 0, nblk, abs_, abs_, start, 100, 0)
    m[36] = len(volname)
    m[37:37 + len(volname)] = volname
    struct.pack_into(">2sHH", m, 124, b"H+", 0, nblk)
    img[1024:1536] = m
    img[len(img) - 1024:len(img) - 512] = m
    return bytes(img)

# ---------------------------------------------------------------- UDIF

T_ZERO, T_RAW, T_IGN, T_ADC, T_ZLIB, T_BZ2, T_LZFSE, T_XZ = 0, 1, 2, 0x80000004, 0x80000005, 0x80000006, 0x80000007, 0x80000008
T_COMMENT, T_END = 0x7FFFFFFE, 0xFFFFFFFF

def chunk_compress(t, d):
    if t == T_ZLIB:
        return zlib.compress(d, 6)
    if t == T_BZ2:
        return bz2.compress(d, 9)
    if t == T_XZ:
        return lzma.compress(d, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64)
    if t == T_LZFSE:
        return lzfse_compress(d)
    if t == T_ADC:
        return adc_compress(d)
    return d

def mish(first_sec, data, methods, chunk_sec, data_pos, comment=True, zero_kind=None):
    nsec = (len(data) + 511) // 512
    data = data + bytes(nsec * 512 - len(data))
    chunks, blobs = [], []
    pos = data_pos
    s = k = 0
    if comment:
        chunks.append((T_COMMENT, 0, 0, 0, 0))
    while s < nsec:
        n = min(chunk_sec, nsec - s)
        d = data[s * 512:(s + n) * 512]
        if not any(d):
            zk = zero_kind if zero_kind is not None else (T_ZERO if k % 2 == 0 else T_IGN)
            chunks.append((zk, s, n, pos, 0))
        else:
            t = methods[k % len(methods)]
            z = chunk_compress(t, d)
            if t != T_RAW and len(z) >= len(d):
                t, z = T_RAW, d
            chunks.append((t, s, n, pos, len(z)))
            blobs.append(z)
            pos += len(z)
        s += n
        k += 1
    chunks.append((T_END, nsec, 0, pos, 0))
    crc = 0                                   # UDIF checksum: "ignore" runs are left out
    for (t, ss, n, o, l) in chunks:
        if n and t != T_IGN:
            crc = zlib.crc32(data[ss * 512:(ss + n) * 512], crc)
    hdr = b"mish" + struct.pack(">IQQQII", 1, first_sec, nsec, 0, 0x208, 0) + bytes(24)
    hdr += struct.pack(">II", 2, 32) + struct.pack(">I", crc) + bytes(124)
    hdr += struct.pack(">I", len(chunks))
    for (t, ss, n, o, l) in chunks:
        hdr += struct.pack(">IIQQQQ", t, 0, ss, n, o, l)
    return hdr, b"".join(blobs), nsec, crc

def plist(parts):
    out = ['<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
           '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n'
           '\t<key>resource-fork</key>\n\t<dict>\n\t\t<key>blkx</key>\n\t\t<array>\n']
    for i, (name, m) in enumerate(parts):
        b = base64.b64encode(m).decode()
        b = "\n".join("\t\t\t\t" + b[j:j + 52] for j in range(0, len(b), 52))
        name = name.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        out.append('\t\t\t<dict>\n\t\t\t\t<key>Attributes</key>\n\t\t\t\t<string>0x0050</string>\n'
                   '\t\t\t\t<key>CFName</key>\n\t\t\t\t<string>%s</string>\n\t\t\t\t<key>Data</key>\n'
                   '\t\t\t\t<data>\n%s\n\t\t\t\t</data>\n\t\t\t\t<key>ID</key>\n\t\t\t\t<string>%d</string>\n'
                   '\t\t\t\t<key>Name</key>\n\t\t\t\t<string>%s</string>\n\t\t\t</dict>\n' % (name, b, i - 1, name))
    out.append('\t\t</array>\n\t\t<key>plst</key>\n\t\t<array>\n\t\t\t<dict>\n\t\t\t\t<key>Attributes</key>\n'
               '\t\t\t\t<string>0x0050</string>\n\t\t\t\t<key>Data</key>\n\t\t\t\t<data>\n\t\t\t\tAAAA\n'
               '\t\t\t\t</data>\n\t\t\t\t<key>ID</key>\n\t\t\t\t<string>0</string>\n\t\t\t\t<key>Name</key>\n'
               '\t\t\t\t<string></string>\n\t\t\t</dict>\n\t\t</array>\n\t</dict>\n</dict>\n</plist>\n')
    return "".join(out).encode()

def rsrc_fork(parts):
    """classic resource fork with one 'blkx' resource per partition (Mac Roman names)"""
    data = bytearray()
    refs = []
    names = bytearray()
    for i, (name, m) in enumerate(parts):
        nb = name.encode("mac_roman")[:255]
        refs.append((i, len(names), len(data)))
        names += bytes([len(nb)]) + nb
        data += struct.pack(">I", len(m)) + m
    n = len(parts)
    tl = struct.pack(">H", 0) + struct.pack(">4sHH", b"blkx", n - 1, 2 + 8)
    reflist = b"".join(struct.pack(">HHI", 1000 + i, no, do & 0xFFFFFF) + bytes(4) for i, no, do in refs)
    typelist = tl + reflist
    map_hdr_len = 28
    doff = 256
    mlen = map_hdr_len + len(typelist) + len(names)
    hdr = struct.pack(">IIII", doff, doff + len(data), len(data), mlen)
    rmap = hdr + bytes(4) + bytes(2) + struct.pack(">HHH", 0, map_hdr_len, map_hdr_len + len(typelist))
    rmap += typelist + names
    return hdr + bytes(240) + bytes(data) + rmap

def koly(data_len, xml_off, xml_len, nsec, crcs, data_crc, rsrc_off=0, rsrc_len=0, df_off=0):
    master = zlib.crc32(b"".join(struct.pack(">I", c) for c in crcs))
    k = b"koly" + struct.pack(">III", 4, 512, 1) + struct.pack(">QQQQQ", 0, df_off, data_len, rsrc_off, rsrc_len)
    k += struct.pack(">II", 1, 1) + bytes(16) + struct.pack(">II", 2, 32) + struct.pack(">I", data_crc) + bytes(124)
    k += struct.pack(">QQ", xml_off, xml_len) + bytes(120) + struct.pack(">II", 2, 32) + struct.pack(">I", master) + bytes(124)
    k += struct.pack(">IQ", 1, nsec) + bytes(12)
    assert len(k) == 512
    return k

def udif(parts, methods=(T_ZLIB,), chunk_sec=2048, use_rsrc=False, prefix=b"", zero_kind=None):
    """parts: list of (blkx name, raw bytes). Returns the .dmg bytes."""
    blob = bytearray()
    ms, crcs = [], []
    first = 0
    for name, data in parts:
        m, b, nsec, crc = mish(first, data, list(methods), chunk_sec, len(blob), zero_kind=zero_kind)
        blob += b
        ms.append((name, m))
        crcs.append(crc)
        first += nsec
    dcrc = zlib.crc32(bytes(blob))
    if use_rsrc:
        r = rsrc_fork(ms)
        return prefix + bytes(blob) + r + koly(len(blob), 0, 0, first, crcs, dcrc, len(blob), len(r))
    x = plist(ms)
    return prefix + bytes(blob) + x + koly(len(blob), len(blob), len(x), first, crcs, dcrc)

def apm_disk(hfs, name="disk image", free_tail=16):
    """hdiutil-like APM layout: DDM, partition map, the HFS+ partition, free space"""
    ddm = bytearray(512)
    struct.pack_into(">2sHI", ddm, 0, b"ER", 512, 64 + (len(hfs) // 512) + free_tail)
    pm = bytearray(63 * 512)
    ents = [("Apple", "Apple_partition_map", 1, 63), (name, "Apple_HFS", 64, len(hfs) // 512),
            ("", "Apple_Free", 64 + len(hfs) // 512, free_tail)]
    for i, (n, t, s, c) in enumerate(ents):
        e = bytearray(512)
        struct.pack_into(">2sHIII", e, 0, b"PM", 0, len(ents), s, c)
        e[16:16 + len(n)] = n.encode()
        e[48:48 + len(t)] = t.encode()
        pm[i * 512:(i + 1) * 512] = e
    return [("Driver Descriptor Map (DDM : 0)", bytes(ddm)),
            ("Apple (Apple_partition_map : 1)", bytes(pm)),
            ("%s (Apple_HFS : 2)" % name, hfs),
            ("(Apple_Free : 3)", bytes(free_tail * 512))]
