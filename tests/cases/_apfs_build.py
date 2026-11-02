"""APFS container builder for fmt_apfs.py (helper, not a test module).

Writes containers following Apple's "Apple File System Reference": container
superblock + checkpoint descriptor area (checkpoint map, superblock copies of
several checkpoints), container object map, volume superblocks, volume object
maps and file-system B-trees (any depth, fixed / variable records, plain or
hashed index nodes), inodes with xfields, hashed / plain directory records,
xattrs (embedded and data streams), file extents (fragmented, sparse),
decmpfs compression (zlib / LZVN / LZFSE / stored, inline or resource fork),
symlinks, hard links (sibling records), sealed volumes (physical fs tree +
file-extent tree) and encrypted volumes (unreadable on purpose).

    vol = Volume("Data", case_insensitive=True)
    vol.dir("docs"); vol.file("docs/a.txt", b"hello", mtime_ns=...)
    img = build([vol], bs=4096)                       # bytes

The space manager and reaper are not written (readers do not need them).
"""
import os, struct, zlib, unicodedata, subprocess

NX_MAGIC, APSB_MAGIC = b"NXSB", b"APSB"
OBJ_PHYS, OBJ_EPH = 0x40000000, 0x80000000
T_NX, T_BTREE, T_BTNODE, T_OMAP, T_CPMAP, T_FS, T_FSTREE, T_EXTREF, T_SNAPMETA, T_FEXT = \
    0x1, 0x2, 0x3, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10, 0x1F
J_INODE, J_XATTR, J_SIBLING, J_DSTREAM_ID, J_EXTENT, J_DREC, J_SIBMAP = 3, 4, 5, 6, 8, 9, 12
UF_COMPRESSED, UF_HIDDEN = 0x20, 0x8000
DT_DIR, DT_REG, DT_LNK, DT_FIFO = 4, 8, 10, 1


def fletcher64(b):
    s1 = s2 = 0
    # sum in big slices: the modulo is applied at the end (same residue)
    for w in struct.unpack_from("<%dI" % ((len(b) - 8) // 4), b, 8):
        s1 += w
        s2 += s1
    s1 %= 0xFFFFFFFF
    s2 %= 0xFFFFFFFF
    c1 = 0xFFFFFFFF - ((s1 + s2) % 0xFFFFFFFF)
    c2 = 0xFFFFFFFF - ((s1 + c1) % 0xFFFFFFFF)
    return (c2 << 32) | c1


def seal(blk):
    blk = bytearray(blk)
    struct.pack_into("<Q", blk, 0, fletcher64(blk))
    return bytes(blk)


def obj(bs, oid, xid, typ, sub, body):
    b = bytearray(bs)
    struct.pack_into("<QQQII", b, 0, 0, oid, xid, typ, sub)
    b[32:32 + len(body)] = body
    return seal(b)


_CRC = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x82F63B78 if _c & 1 else _c >> 1
    _CRC.append(_c)


def name_hash(name, case_fold):
    """22-bit directory-record hash: CRC-32C register (no final xor) over UTF-32LE NFD."""
    s = unicodedata.normalize("NFD", name.casefold() if case_fold else name)
    crc = 0xFFFFFFFF
    for ch in s:
        for byte in struct.pack("<I", ord(ch)):
            crc = _CRC[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc & 0x3FFFFF


def jkey(oid, typ):
    return struct.pack("<Q", (typ << 60) | oid)


# ---------------------------------------------------------------- compression helpers

def lzvn_compress(data):
    """Small greedy LZVN encoder (literal runs, lrg_d / sml_d matches, sml_m / lrg_m)."""
    out, lit = bytearray(), bytearray()
    table = {}
    i, n = 0, len(data)
    def flush_lits(keep):
        while len(lit) > keep:
            c = min(len(lit) - keep, 271)
            out.extend(bytes([0xE0, c - 16]) if c >= 16 else bytes([0xE0 | c]))
            out.extend(lit[:c])
            del lit[:c]
    while i < n:
        cand = table.get(data[i:i + 4]) if i + 4 <= n else None
        if i + 4 <= n:
            table[data[i:i + 4]] = i
        if cand is None or i - cand > 0xFFFF:
            lit.append(data[i]); i += 1
            continue
        d = i - cand
        l = 4
        while i + l < n and l < 2000 and data[cand + l] == data[i + l]:
            l += 1
        flush_lits(3)
        L = len(lit)
        mm = min(l, (10, 8, 6, 4)[L])
        if d < 0x600:
            out.extend(bytes([L << 6 | (mm - 3) << 3 | d >> 8, d & 0xFF]))
        else:
            out.append(L << 6 | (mm - 3) << 3 | 7)
            out.extend(struct.pack("<H", d))
        out.extend(lit)
        lit.clear()
        rest = l - mm
        while rest:
            c = min(rest, 271)
            out.extend(bytes([0xF0, c - 16]) if c >= 16 else bytes([0xF0 | c]))
            rest -= c
        for k in range(i + 1, min(i + l, n - 3)):
            table[data[k:k + 4]] = k
        i += l
    flush_lits(0)
    return bytes(out + b"\x06" + bytes(7))


def lzfse_compress(data):
    r = subprocess.run(["lzfse", "-encode"], input=data, capture_output=True, check=True)
    return r.stdout


def comp_block(kind, data):
    """one decmpfs block: kind 'zlib' | 'lzvn' | 'lzfse' | 'raw'; stored when it does not shrink"""
    if kind == "raw":
        return data
    if kind == "zlib":
        z = zlib.compress(data, 9)
        return z if len(z) < len(data) else b"\xff" + data
    if kind == "lzvn":
        z = lzvn_compress(data)
        return z if len(z) < len(data) else b"\x06" + data
    z = lzfse_compress(data)
    return z if len(z) < len(data) + 1 else b"\xff" + data


DEC_TYPES = {("raw", "inline"): 1, ("zlib", "inline"): 3, ("zlib", "rsrc"): 4, ("lzvn", "inline"): 7,
             ("lzvn", "rsrc"): 8, ("raw9", "inline"): 9, ("raw", "rsrc"): 10, ("lzfse", "inline"): 11,
             ("lzfse", "rsrc"): 12, ("lzbitmap", "inline"): 13}


def decmpfs(data, kind, where, chunk=65536):
    """-> (decmpfs xattr value, resource fork bytes or None)"""
    t = DEC_TYPES[(kind, where)]
    hdr = b"fpmc" + struct.pack("<IQ", t, len(data))
    if where == "inline":
        if kind == "raw":
            return hdr + data, None
        if kind == "raw9":
            return hdr + b"\xcc" + data, None             # 0xCC marker (as 7-Zip expects)
        if kind == "lzbitmap":
            return hdr + b"\x00" * 8, None
        return hdr + comp_block(kind, data), None
    blocks = [comp_block(kind, data[o:o + chunk]) for o in range(0, len(data), chunk)]
    if kind == "zlib":
        tab = struct.pack("<I", len(blocks))
        off = 4 + 8 * len(blocks)
        for b in blocks:
            tab += struct.pack("<II", off, len(b))
            off += len(b)
        cmpf = tab + b"".join(blocks)
        rdata = struct.pack(">I", len(cmpf)) + cmpf
        dlen = len(rdata)
        head = struct.pack(">IIII", 0x100, 0x100 + dlen, dlen, 0x32)
        rmap = head + bytes(4 + 2 + 2) + struct.pack(">HH", 0x1C, 0x32) + struct.pack(">H", 0) + b"cmpf" + \
            struct.pack(">HH", 0, 0x0A) + struct.pack(">HHII", 1, 0xFFFF, 0, 0)
        return hdr, head + bytes(0x100 - 16) + rdata + rmap
    offs = [4 * (len(blocks) + 1)]
    for b in blocks:
        offs.append(offs[-1] + len(b))
    return hdr, struct.pack("<%dI" % len(offs), *offs) + b"".join(blocks)


# ---------------------------------------------------------------- volume description

class Node:
    def __init__(self, kind, name, parent, **kw):
        self.kind, self.name, self.parent = kind, name, parent
        self.children = []
        self.data = kw.get("data", b"")
        self.target = kw.get("target")
        self.mode = kw.get("mode")
        self.uid, self.gid = kw.get("uid", 501), kw.get("gid", 20)
        self.mtime = kw.get("mtime_ns", 1700000000 * 10**9 + 123456789)
        self.compress = kw.get("compress")        # (kind, where)
        self.sparse = kw.get("sparse")            # list of (offset, length) holes (block aligned)
        self.hole_records = kw.get("hole_records", True)   # holes as pblk-0 extents, else left out
        self.frag = kw.get("frag", 1)             # number of extents for the data
        self.xattrs = dict(kw.get("xattrs", {}))
        self.bsd = kw.get("bsd", 0)
        self.size = kw.get("size")                # logical size override (sparse tail)
        self.dec_stream = kw.get("dec_stream", False)   # decmpfs xattr as data stream
        self.rsrc_embedded = kw.get("rsrc_embedded", False)
        self.ino = None
        self.links = []                           # extra (parent, name) for hard links


class Volume:
    def __init__(self, name, case_insensitive=True, hashed=True, encrypted=False, sealed=False,
                 leaf_max=None, role=0, hashed_index=False):
        """sealed: False, True (virtual hashed fs tree + integrity meta, file extents in the
        file-extent tree) or 'physical' (physical hashed fs tree)."""
        self.name = name
        self.case_insensitive = case_insensitive
        self.hashed = hashed or case_insensitive
        self.encrypted = encrypted
        self.sealed = sealed
        self.leaf_max = leaf_max                  # records per fs-tree leaf (forces deep trees)
        self.role = role
        self.hashed_index = hashed_index or sealed
        self.root = Node("dir", "root", None, mode=0o40755)
        self.by_path = {"": self.root}
        self.extra = []                           # extra raw fs records (hostile tests)

    def _add(self, path, kind, **kw):
        parent_path, _, name = path.rpartition("/")
        par = self.by_path[parent_path]
        n = Node(kind, name, par, **kw)
        par.children.append(n)
        self.by_path[path] = n
        return n

    def dir(self, path, **kw):
        kw.setdefault("mode", 0o40755)
        return self._add(path, "dir", **kw)

    def file(self, path, data, **kw):
        kw.setdefault("mode", 0o100644)
        return self._add(path, "file", data=data, **kw)

    def symlink(self, path, target, **kw):
        kw.setdefault("mode", 0o120755)
        return self._add(path, "link", target=target, **kw)

    def fifo(self, path, **kw):
        kw.setdefault("mode", 0o10644)
        return self._add(path, "fifo", **kw)

    def hardlink(self, path, existing):
        n = self.by_path[existing]
        parent_path, _, name = path.rpartition("/")
        n.links.append((self.by_path[parent_path], name))
        return n


# ---------------------------------------------------------------- image writer

class Image:
    def __init__(self, bs, nblocks):
        self.bs, self.nblocks = bs, nblocks
        self.blocks = {}
        self.next = 0
        self.next_oid = 1026

    def alloc(self, n=1):
        b = self.next
        self.next += n
        assert self.next <= self.nblocks, "image too small"
        return b

    def oid(self):
        self.next_oid += 1
        return self.next_oid - 1

    def put(self, blk, data):
        assert len(data) % self.bs == 0
        for i in range(0, len(data), self.bs):
            self.blocks[blk + i // self.bs] = data[i:i + self.bs]

    def write_data(self, data):
        nb = (len(data) + self.bs - 1) // self.bs
        if nb == 0:
            return 0
        b = self.alloc(nb)
        self.put(b, data + bytes(nb * self.bs - len(data)))
        return b

    def bytes(self):
        out = bytearray(self.nblocks * self.bs)
        for k, v in self.blocks.items():
            out[k * self.bs:(k + 1) * self.bs] = v
        return bytes(out)


def build_btree(img, recs, xid, sub, physical, fixed=None, leaf_max=None, omap=None, hashed_index=False,
                bt_flags=0, info=None):
    """recs: sorted [(key, value)]. Returns the root oid (physical: its block).
    omap: list collecting (oid, paddr) for virtual nodes.
    hashed_index: sealed-volume nodes (BTNODE_HASHED): index values are child oid + SHA-256 of the
    child block; in virtual trees the child oid is stored relative to the root oid (as 7-Zip
    reads real sealed volumes). info: dict receiving the root block ('root_block')."""
    bs = img.bs
    storage = OBJ_PHYS if physical else 0

    def node_bytes(entries, level, root, nkeys_total=0, nnodes=0, longest=(0, 0)):
        fx = fixed is not None
        es = 4 if fx else 8
        tlen = max(len(entries), 1) * es
        tlen = (tlen + 63) // 64 * 64 if not fx else (tlen + 31) // 32 * 32
        vend = bs - 40 if root else bs
        kb = 0x38 + tlen
        toc, keys, vals = bytearray(), bytearray(), bytearray()
        for k, v in entries:
            ko = len(keys)
            keys += k
            if not fx:
                keys += bytes(-len(keys) % 8)          # keys and values start 8-aligned
            vals = bytearray(v) + bytearray(0 if fx else -len(v) % 8) + vals
            vo = len(vals)                             # value starts vo bytes before the end
            if fx:
                toc += struct.pack("<HH", ko, vo)
            else:
                toc += struct.pack("<HHHH", ko, len(k), vo, len(v))
        assert kb + len(keys) <= vend - len(vals), "node overflow"
        b = bytearray(bs)
        flags = (1 if root else 0) | (2 if level == 0 else 0) | (4 if fx else 0) | (8 if hashed_index else 0)
        free_off = len(keys)
        free_len = vend - len(vals) - (kb + len(keys))
        struct.pack_into("<HHIHHHHHHHH", b, 0x20, flags, level, len(entries), 0, tlen, free_off, free_len,
                         0xFFFF, 0, 0xFFFF, 0)
        b[0x38:0x38 + len(toc)] = toc
        b[kb:kb + len(keys)] = keys
        b[vend - len(vals):vend] = vals
        if root:
            ks, vs = (fixed if fx else (0, 0))
            struct.pack_into("<IIIIIIQQ", b, bs - 40, bt_flags | (0x80 if hashed_index else 0), bs, ks, vs,
                             longest[0], longest[1], nkeys_total, nnodes)
        return b

    def fits(entries, root):
        if sum(len(k) + len(v) + 16 for k, v in entries) > bs:
            return False
        try:
            node_bytes(entries, 0, root)
            return True
        except (AssertionError, struct.error):
            return False

    def split(entries, limit, root_ok):
        groups, cur = [], []
        for e in entries:
            cur.append(e)
            if (limit and len(cur) > limit) or not fits(cur, False):
                cur.pop()
                groups.append(cur)
                cur = [e]
        if cur:
            groups.append(cur)
        return groups

    import hashlib
    longest = (max([len(k) for k, _ in recs] or [0]), max([len(v) for _, v in recs] or [0]))
    level, entries, nnodes = 0, list(recs), 0
    root_oid = None if physical else img.oid()
    while True:
        lim = leaf_max if level == 0 else (leaf_max and max(2, leaf_max))
        if (not lim or len(entries) <= lim) and fits(entries, True):
            break
        groups = split(entries, lim, False)
        nxt = []
        for g in groups:
            nb = node_bytes(g, level, False)
            if physical:
                pa = img.alloc()
                oid = pa
            else:
                pa, oid = img.alloc(), img.oid()
                omap.append((oid, pa))
            struct.pack_into("<QQII", nb, 8, oid, xid, storage | T_BTNODE, sub)
            blk = seal(nb)
            img.put(pa, blk)
            nnodes += 1
            if hashed_index:
                child = struct.pack("<Q", oid if physical else oid - root_oid) + hashlib.sha256(blk).digest()
            else:
                child = struct.pack("<Q", oid)
            nxt.append((g[0][0], child))
        entries = nxt
        level += 1
    nb = node_bytes(entries, level, True, len(recs), nnodes + 1, longest)
    if physical:
        pa = img.alloc()
        oid = pa
    else:
        pa, oid = img.alloc(), root_oid
        omap.append((oid, pa))
    struct.pack_into("<QQII", nb, 8, oid, xid, storage | T_BTREE, sub)
    blk = seal(nb)
    img.put(pa, blk)
    if info is not None:
        info["root_block"] = blk
    return oid


def build_omap(img, maps, xid, flags=0, val_flags=0):
    """maps: [(oid, paddr)] (or (oid, paddr, xid, flags)). Returns the omap object block."""
    recs = []
    for m in sorted(maps):
        oid, pa = m[0], m[1]
        x = m[2] if len(m) > 2 else xid
        f = m[3] if len(m) > 3 else val_flags
        recs.append((struct.pack("<QQ", oid, x), struct.pack("<IIQ", f, img.bs, pa)))
    root = build_btree(img, recs, xid, T_OMAP, True, fixed=(16, 16), bt_flags=0x10 | 0x02)
    pa = img.alloc()
    body = struct.pack("<IIIIQQQQQ", flags, 0, OBJ_PHYS | T_BTREE, OBJ_PHYS | T_BTREE, root, 0, 0, 0, 0)
    img.put(pa, obj(img.bs, pa, xid, OBJ_PHYS | T_OMAP, 0, body))
    return pa


def inode_val(parent, private, n, nlink, size, alloced, name, extra_flags=0, has_dstream=True, usize=0):
    mode = n.mode
    t = n.mtime
    iflags = extra_flags
    xf = []
    xf.append((4, 0x02, name.encode() + b"\0"))                       # INO_EXT_TYPE_NAME
    if has_dstream:
        xf.append((8, 0x20, struct.pack("<QQQQQ", size, alloced, 0, size, 0)))
    hdrs = b"".join(struct.pack("<BBH", ty, fl, len(d)) for ty, fl, d in xf)
    data = b"".join(d + bytes(-len(d) % 8) for _, _, d in xf)
    xblob = struct.pack("<HH", len(xf), len(data)) + hdrs + data
    v = struct.pack("<QQQQQQQiIIIIIHHQ", parent, private, t - 10**9, t, t, t, iflags, nlink, 0, 1,
                    n.bsd, n.uid, n.gid, mode, 0, usize)
    return v + xblob


class FsWriter:
    """Turns a Volume into sorted fs-tree records and data blocks."""

    def __init__(self, img, vol, xid):
        self.img, self.vol, self.xid = img, vol, xid
        self.recs = []
        self.fext = []
        self.next_id = 16
        self.counts = dict(files=0, dirs=0, links=0, other=0)

    def new_id(self):
        self.next_id += 1
        return self.next_id - 1

    def drec_key(self, parent, name):
        nb = name.encode() + b"\0"
        if self.vol.hashed:
            h = name_hash(name, self.vol.case_insensitive)
            return jkey(parent, J_DREC) + struct.pack("<I", (h << 10) | len(nb)) + nb
        return jkey(parent, J_DREC) + struct.pack("<H", len(nb)) + nb

    def extents(self, sid, data, holes, frag, size, hole_records=True, dstream_rec=True):
        """write data, return allocated bytes; extents keyed by stream id sid. Blocks past
        len(data) get no extent (a sparse tail when the logical size is larger)."""
        bs = self.img.bs
        hole_blocks = set()
        for off, ln in holes or ():
            for b in range(off // bs, (off + ln) // bs):
                hole_blocks.add(b)
        runs = []                                   # (first logical block, count, is_hole)
        for b in range((len(data) + bs - 1) // bs):
            h = b in hole_blocks
            if runs and runs[-1][2] == h and runs[-1][0] + runs[-1][1] == b:
                runs[-1][1] += 1
            else:
                runs.append([b, 1, h])
        # split data runs into frag pieces (non-contiguous on disk: a gap block between)
        out = []
        for lb, cnt, h in runs:
            if h:
                if hole_records:
                    out.append((lb, cnt, 0))
                continue
            pieces = max(1, min(frag, cnt))
            step = (cnt + pieces - 1) // pieces
            k = 0
            while k < cnt:
                c = min(step, cnt - k)
                chunk = data[(lb + k) * bs:(lb + k + c) * bs]
                pa = self.img.write_data(chunk + bytes(c * bs - len(chunk)))
                out.append((lb + k, c, pa))
                if pieces > 1:
                    self.img.alloc()                # gap
                k += c
        alloced = 0
        for lb, cnt, pa in out:
            rec = (jkey(sid, J_EXTENT) + struct.pack("<Q", lb * bs),
                   struct.pack("<QQQ", cnt * bs, pa, 0))
            if self.vol.sealed:
                self.fext.append((struct.pack("<QQ", sid, lb * bs), struct.pack("<QQ", cnt * bs, pa)))
            else:
                self.recs.append(rec)
            if pa:
                alloced += cnt * bs
        if out and dstream_rec:                     # files only: xattr streams have none
            self.recs.append((jkey(sid, J_DSTREAM_ID), struct.pack("<I", 1)))
        return alloced

    def xattr(self, ino, name, value, flags=0, stream=False):
        k = jkey(ino, J_XATTR) + struct.pack("<H", len(name) + 1) + name.encode() + b"\0"
        if stream or len(value) > 3804:
            sid = self.new_id()
            al = self.extents(sid, value, None, 1, None, dstream_rec=False)
            v = struct.pack("<HH", 1 | flags, 48) + struct.pack("<Q", sid) + \
                struct.pack("<QQQQQ", len(value), al, 0, len(value), 0)
        else:
            v = struct.pack("<HH", 2 | flags, len(value)) + value
        self.recs.append((k, v))

    def walk(self):
        vol = self.vol
        t = vol.root.mtime
        # root / private-dir records (as mkapfs and macOS write them)
        root = vol.root
        root.ino = 2
        self.recs.append((jkey(2, J_INODE), inode_val(1, 2, root, len(root.children), 0, 0, "root",
                                                       has_dstream=False)))
        priv = Node("dir", "private-dir", None, mode=0o40755)
        self.recs.append((jkey(3, J_INODE), inode_val(1, 3, priv, 0, 0, 0, "private-dir", has_dstream=False)))
        self.recs.append((self.drec_key(1, "root"), struct.pack("<QQH", 2, t, DT_DIR)))
        self.recs.append((self.drec_key(1, "private-dir"), struct.pack("<QQH", 3, t, DT_DIR)))
        q = [root]
        allnodes = []
        while q:
            d = q.pop(0)
            for c in d.children:
                c.ino = self.new_id()
                allnodes.append(c)
                if c.kind == "dir":
                    q.append(c)
        for c in allnodes:
            self.emit(c)
        for k, v in vol.extra:
            self.recs.append((k, v))

    def emit(self, n):
        ino = n.ino
        typ = {"dir": DT_DIR, "file": DT_REG, "link": DT_LNK, "fifo": DT_FIFO}[n.kind]
        names = [(n.parent, n.name)] + n.links
        nlink = len(names)
        sib_ids = []
        for par, name in names:
            v = struct.pack("<QQH", ino, n.mtime, typ)
            if nlink > 1:
                sid = self.new_id()
                sib_ids.append((sid, par, name))
                v += struct.pack("<HH", 1, 8) + struct.pack("<BBH", 1, 0, 8) + struct.pack("<Q", sid)
            self.recs.append((self.drec_key(par.ino, name), v))
        if n.kind == "dir":
            self.counts["dirs"] += 1
            self.recs.append((jkey(ino, J_INODE), inode_val(n.parent.ino, ino, n, len(n.children), 0, 0, n.name,
                                                           has_dstream=False)))
            return
        if n.kind == "link":
            self.counts["links"] += 1
            self.recs.append((jkey(ino, J_INODE), inode_val(n.parent.ino, ino, n, 1, 0, 0, n.name,
                                                           has_dstream=False)))
            self.xattr(ino, "com.apple.fs.symlink", n.target.encode() + b"\0", flags=4)
            return
        if n.kind == "fifo":
            self.counts["other"] += 1
            self.recs.append((jkey(ino, J_INODE), inode_val(n.parent.ino, ino, n, 1, 0, 0, n.name,
                                                           has_dstream=False)))
            return
        self.counts["files"] += 1
        if n.compress:
            kind, where = n.compress
            dec, rsrc = decmpfs(n.data, kind, where)
            n.bsd |= UF_COMPRESSED
            self.recs.append((jkey(ino, J_INODE), inode_val(n.parent.ino, ino, n, nlink, 0, 0, n.name,
                                                           extra_flags=0x40000, has_dstream=False,
                                                           usize=len(n.data))))
            xs = [("com.apple.decmpfs", dec, n.dec_stream)]
            if rsrc is not None:
                xs.append(("com.apple.ResourceFork", rsrc, not n.rsrc_embedded))
            for name, val, st in sorted(xs):
                self.xattr(ino, name, val, stream=st)
        else:
            al = self.extents(ino, n.data, n.sparse, n.frag, n.size, n.hole_records)
            size = len(n.data) if n.size is None else n.size
            fl = 0x200 if n.sparse else 0
            self.recs.append((jkey(ino, J_INODE), inode_val(n.parent.ino, ino, n, nlink, size, al, n.name,
                                                           extra_flags=fl)))
            for name, val in sorted(n.xattrs.items()):
                self.xattr(ino, name, val)
        for sid, par, name in sib_ids:
            nb = name.encode() + b"\0"
            self.recs.append((jkey(ino, J_SIBLING) + struct.pack("<Q", sid),
                              struct.pack("<QH", par.ino, len(nb)) + nb))
            self.recs.append((jkey(sid, J_SIBMAP), struct.pack("<Q", ino)))

    def sorted_recs(self):
        def key(r):
            k = r[0]
            hdr = struct.unpack_from("<Q", k)[0]
            oid, typ = hdr & ((1 << 60) - 1), hdr >> 60
            rest = k[8:]
            if typ == J_DREC and self.vol.hashed:
                lh = struct.unpack_from("<I", rest)[0]
                return (oid, typ, lh >> 10, rest[4:])
            if typ == J_DREC or typ == J_XATTR:
                return (oid, typ, 0, rest[2:])
            if typ in (J_EXTENT, J_SIBLING):
                return (oid, typ, struct.unpack_from("<Q", rest)[0], b"")
            return (oid, typ, 0, rest)
        return sorted(self.recs, key=key)


def build_volume(img, vol, xid, index):
    fw = FsWriter(img, vol, xid)
    fw.walk()
    recs = fw.sorted_recs()
    if vol.encrypted:
        # nodes are cipher text: random blocks behind encrypted omap values
        maps = []
        root = img.oid()
        pa = img.alloc()
        img.put(pa, os.urandom(img.bs))
        maps.append((root, pa, xid, 4))
        omap = build_omap(img, maps, xid)
        fext = 0
    else:
        maps = []
        integ = 0
        if vol.sealed:
            info = {}
            phys = vol.sealed == "physical"
            root = build_btree(img, recs, xid, T_FSTREE, phys, leaf_max=vol.leaf_max, omap=maps,
                               hashed_index=True, bt_flags=0x10 if phys else 0, info=info)
            fext = build_btree(img, sorted(fw.fext), xid, T_FEXT, True, fixed=(16, 16),
                               leaf_max=vol.leaf_max, bt_flags=0x10)
            import hashlib
            integ = img.oid()
            ipa = img.alloc()
            body = struct.pack("<IIIIQ", 1, 0, 1, 0x80, 0) + bytes(0x80 - 0x38) + \
                hashlib.sha256(info["root_block"]).digest()
            img.put(ipa, obj(img.bs, integ, xid, 0x1E, 0, body))
            maps.append((integ, ipa))
        else:
            root = build_btree(img, recs, xid, T_FSTREE, False, leaf_max=vol.leaf_max, omap=maps,
                               hashed_index=vol.hashed_index)
            fext = 0
        omap = build_omap(img, maps, xid)
    if vol.encrypted:
        integ = 0
    extref = build_btree(img, [], xid, T_EXTREF, True, bt_flags=0x10)
    snap = build_btree(img, [], xid, T_SNAPMETA, True, bt_flags=0x10)
    vo = img.oid()
    pa = img.alloc()
    b = bytearray(img.bs - 32)
    o = lambda off: off - 32
    inc = (1 if vol.case_insensitive else 0) | (8 if vol.hashed and not vol.case_insensitive else 0) | \
        (0x20 if vol.sealed else 0)
    struct.pack_into("<4sIQQQQQQQ", b, o(0x20), APSB_MAGIC, index, 2, 0, inc, 1700000000 * 10**9, 0, 0,
                     img.next)
    struct.pack_into("<HHIIIHH", b, o(0x60), 5, 0, 0, 0, 0, 1, 0)                 # meta crypto
    struct.pack_into("<III", b, o(0x74), OBJ_PHYS | T_BTREE if vol.sealed == "physical" else T_BTREE,
                     OBJ_PHYS | T_BTREE, OBJ_PHYS | T_BTREE)
    struct.pack_into("<QQQQ", b, o(0x80), omap, root, extref, snap)
    struct.pack_into("<QQQQQQQ", b, o(0xB0), fw.next_id, fw.counts["files"], fw.counts["dirs"],
                     fw.counts["links"], fw.counts["other"], 0, 0)
    b[o(0xF0):o(0x100)] = bytes(range(16 * index, 16 * index + 16))
    struct.pack_into("<QQ", b, o(0x100), 1700000001 * 10**9, 0 if vol.encrypted else 1)   # fs_flags
    fb = b"gogitzip-apfs-test (1.0)"
    b[o(0x110):o(0x110) + len(fb)] = fb
    struct.pack_into("<QQ", b, o(0x130), 1700000000 * 10**9, xid)
    nm = vol.name.encode()[:255]
    b[o(0x2C0):o(0x2C0) + len(nm)] = nm
    struct.pack_into("<IH", b, o(0x3C0), 3, vol.role)
    if vol.sealed:
        struct.pack_into("<QQI", b, o(0x400), integ, fext, OBJ_PHYS | T_BTREE)
    img.put(pa, obj(img.bs, vo, xid, T_FS, 0, b))
    return vo, pa


def build(states, bs=4096, nblocks=None, desc_blocks=8, block0="newest", corrupt=(), max_fs=None):
    """states: one list of Volumes per checkpoint (oldest first), or just [Volume, ...].
    block0: which checkpoint superblock block 0 holds ('newest' / 'oldest' / 'none').
    corrupt: checkpoint indexes whose superblock copy in the descriptor area gets a bad checksum."""
    if states and isinstance(states[0], Volume):
        states = [states]
    img = Image(bs, 1 << 40)
    img.alloc(1 + desc_blocks + 8)                  # block 0, checkpoint descriptor + data areas
    built = []
    for ci, vols in enumerate(states):
        xid = 5 + 2 * ci
        vrefs = []
        for vi, v in enumerate(vols):
            vrefs.append(build_volume(img, v, xid, vi))
        comap = build_omap(img, [(vo, pa) for vo, pa in vrefs], xid, flags=1)
        built.append((xid, vrefs, comap))
    if nblocks is None:
        nblocks = img.next + 16
    img.nblocks = nblocks
    if max_fs is None:                              # one volume per 512 MiB (apfsck checks it)
        max_fs = max(max(len(v) for v in states), min(100, -(-nblocks * bs // (512 << 20))))
    sbs = []
    for ci, (xid, vrefs, comap) in enumerate(built):
        sb = bytearray(bs - 32)
        o = lambda off: off - 32
        struct.pack_into("<4sIQQQQ", sb, o(0x20), NX_MAGIC, bs, nblocks, 0, 0, 2)
        sb[o(0x48):o(0x58)] = bytes(range(0xA0, 0xB0))
        struct.pack_into("<QQIIQQIIIIII", sb, o(0x58), img.next_oid, xid + 1, desc_blocks, 8, 1, 1 + desc_blocks,
                         (2 * ci + 2) % desc_blocks, 0, (2 * ci) % desc_blocks, 2, 0, 0)
        struct.pack_into("<QQQII", sb, o(0x98), 0x400, comap, 0x401, 0, max_fs)
        for i, (vo, pa) in enumerate(vrefs):
            struct.pack_into("<Q", sb, o(0xB8) + 8 * i, vo)
        sbs.append((xid, bytes(sb)))
    for ci, (xid, sb) in enumerate(sbs):
        cpm = struct.pack("<II", 1, 0)
        d0 = 1 + (2 * ci) % desc_blocks
        img.put(d0, obj(bs, d0, xid, OBJ_PHYS | T_CPMAP, 0, cpm))
        blk = obj(bs, 1, xid, OBJ_EPH | T_NX, 0, sb)
        if ci in corrupt:
            blk = bytearray(blk)
            blk[0] ^= 0xFF
            blk = bytes(blk)
        img.put(1 + (2 * ci + 1) % desc_blocks, blk)
    if block0 != "none":
        xid, sb = sbs[-1] if block0 == "newest" else sbs[0]
        img.put(0, obj(bs, 1, xid, OBJ_EPH | T_NX, 0, sb))
    else:                                           # block 0 with a bad checksum
        b0 = bytearray(obj(bs, 1, sbs[0][0], OBJ_EPH | T_NX, 0, sbs[0][1]))
        b0[3] ^= 0x5A
        img.put(0, bytes(b0))
    return img.bytes()
