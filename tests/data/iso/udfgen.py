"""
Minimal UDF image writer (ECMA-167 / OSTA UDF 1.02 - 2.60) for reader tests
(used by tests/cases/fmt_iso.py). mkudffs only formats empty volumes and loop
mounts are not available in CI containers, so the test images are built here.

    u = Udf(layout="type1"|"sparable"|"vat"|"meta", rev=0x201, bs=2048, efe=None)
    d = u.dir(u.root, "sub")
    u.file(d, "a.txt", b"data", ad="short"|"long"|"ext"|"inicb", hidden=True)
    u.file(u.root, "sparse.bin", segs=[("data", b".."), ("zero", 1 << 20, 1)])
    u.symlink(u.root, "ln", ["/", "usr", "bin"])
    raw = u.build()

Options per file: ad, segs (data / zero extents), split (bytes per extent, placed in
reverse order), aed (descriptors kept in the entry before an allocation extent chain),
strategy4096 (an older entry superseded through an indirect entry), deleted, hidden,
aed_loop / ie_loop (hostile: the chain points back to its start),
name16 (16-bit CS0), iu (implementation use bytes in the FID).
Volume options: layout, rev, bs, efe, vat15 (UDF 1.50 VAT), remap (sparable: packets of
the first file moved to the spare area), break_main_meta (corrupt the metadata file so the
mirror is needed), break_main_vds, anchors ("256", "256+end", "end").
"""
import struct

def crc16(data):
    c = 0
    for b in data:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) if c & 0x8000 else (c << 1)
            c &= 0xffff
    return c


def tagged(ident, body, loc, ver=2, crclen=None):
    """body = descriptor bytes after the 16-byte tag"""
    if crclen is None:
        crclen = len(body)
    t = bytearray(struct.pack("<HHBBHHHI", ident, ver, 0, 0, 1, crc16(body[:crclen]), crclen, loc))
    t[4] = (sum(t[0:4]) + sum(t[5:16])) & 0xff
    return bytes(t) + body


def regid(ident, suffix=b"", flags=0):
    return bytes([flags]) + ident.ljust(23, b"\0")[:23] + suffix.ljust(8, b"\0")[:8]


def cs0(s, wide=None):
    if wide is None:
        wide = any(ord(ch) > 255 for ch in s)
    return b"\x10" + s.encode("utf-16-be") if wide else b"\x08" + s.encode("latin-1")


def dstring(s, n):
    b = cs0(s) if s else b""
    return b.ljust(n - 1, b"\0")[:n - 1] + bytes([len(b)])


def charspec():
    return b"\0" + b"OSTA Compressed Unicode".ljust(63, b"\0")


def timestamp(t=(2026, 11, 1, 12, 30, 15), tz=540, cs=12, hu=34, us=56):
    y, mo, d, h, mi, s = t
    return struct.pack("<HhBBBBBBBB", (1 << 12) | (tz & 0xfff), y, mo, d, h, mi, s, cs, hu, us)


def short_ad(length, pos, typ=0):
    return struct.pack("<II", (typ << 30) | length, pos)


def long_ad(length, pos, part, typ=0):
    return struct.pack("<IIH", (typ << 30) | length, pos, part) + b"\0" * 6


def ext_ad(length, pos, part, typ=0):
    return struct.pack("<IIIIH", (typ << 30) | length, length, length, pos, part) + b"\0" * 2


class Node:
    def __init__(self, name, kind, parent):
        self.name, self.kind, self.parent = name, kind, parent
        self.children = []
        self.data = b""
        self.opt = {}


class Udf:
    def __init__(self, layout="type1", rev=0x201, bs=2048, efe=None, vat15=False, remap=False,
                 break_main_meta=False, break_main_vds=False, anchors="256+end", strategy=4, meta_split=False):
        self.layout, self.rev, self.bs = layout, rev, bs
        self.efe = rev >= 0x200 if efe is None else efe
        self.vat15, self.remap, self.meta_split = vat15, remap, meta_split
        self.break_main_meta, self.break_main_vds, self.anchors = break_main_meta, break_main_vds, anchors
        self.tagver = 3 if rev >= 0x200 else 2
        self.root = Node("", "dir", None)
        self.uid = 16

    def dir(self, parent, name, **opt):
        n = Node(name, "dir", parent)
        n.opt = opt
        parent.children.append(n)
        return n

    def file(self, parent, name, data=b"", **opt):
        n = Node(name, "file", parent)
        n.data = data
        n.opt = opt
        parent.children.append(n)
        return n

    def ref(self, parent, name, target=None, loc=None, part=0, is_dir=True, **opt):
        """FID naming another node's ICB (hard link / loop) or a raw location (part, loc)"""
        n = Node(name, "ref", parent)
        n.target, n.loc, n.part, n.is_dir = target, loc, part, is_dir
        n.opt = opt
        parent.children.append(n)
        return n

    def symlink(self, parent, name, comps, **opt):
        n = Node(name, "link", parent)
        n.comps = comps
        n.opt = opt
        parent.children.append(n)
        return n

    # ------------------------------------------------------------------
    def _icb_space(self):
        """(map index used for ICBs and directory data, map index for file data)"""
        return {"type1": (0, 0), "sparable": (0, 0), "vat": (1, 0), "meta": (1, 0)}[self.layout]

    def build(self):
        bs = self.bs
        icb_map, data_map = self._icb_space()
        # block spaces: "icb" holds FSD / entries / directories, "data" holds file contents
        self.icb_blocks = {}          # icb block -> bytes
        self.data_blocks = {}         # data block -> bytes
        self.n_icb = 2                # 0: FSD, 1: terminating descriptor
        self.n_data = 0
        same = icb_map == data_map
        if self.layout == "meta":
            self.n_data = 2           # physical blocks 0, 1: metadata file / mirror entries

        def alloc_icb(n=1):
            if same:
                return alloc_data(n)
            b = self.n_icb
            self.n_icb += n
            return b

        def alloc_data(n):
            if same:
                b = max(self.n_icb, self.n_data)
                self.n_icb = self.n_data = b + n
                return b
            b = self.n_data
            self.n_data += n
            return b

        def put_icb(b, data):
            (self.data_blocks if same else self.icb_blocks)[b] = data

        def put_data(b, data):
            self.data_blocks[b] = data

        self.nfiles = self.ndirs = 0

        # assign ICB locations first (parents need children's locations)
        def assign(n):
            if n.kind == "ref":
                return
            n.icb = alloc_icb(2 if n.opt.get("strategy4096") else 1)
            if n.opt.get("strategy4096"):
                n.icb_new = alloc_icb(1)
            for c in n.children:
                assign(c)
        assign(self.root)

        def fid(name, chars, icb_loc, iu=b"", wide=None, part=None):
            ident = cs0(name, wide) if name is not None else b""
            body = struct.pack("<HBB", 1, chars, len(ident)) + long_ad(bs, icb_loc, icb_map if part is None else part) + \
                struct.pack("<H", len(iu)) + iu + ident
            total = (16 + len(body) + 3) & ~3
            body = body.ljust(total - 16, b"\0")
            return body                # tag added when the location is known

        def entry(n, ftype, info, ads, adtype, embedded=None, loc=0, strategy=4, links=1, perm=None):
            efe = self.efe
            ad_bytes = embedded if adtype == 3 else b"".join(ads)
            if perm is None:
                perm = n.opt.get("perm") if n and "perm" in n.opt else (0x1CA5 if ftype == 4 else 0x1884)   # 0755 / 0644
            flags = adtype | (n.opt.get("icbflags", 0) if n else 0)
            icbtag = struct.pack("<IHHHBB", 0, strategy, 0, 1 if strategy == 4 else 2, 0, ftype) + b"\0" * 6 + \
                struct.pack("<H", flags)
            recorded = sum(((struct.unpack_from("<I", a)[0] & 0x3fffffff) + bs - 1) // bs for a in ads) if adtype != 3 else 0
            t = timestamp()
            if efe:
                body = icbtag + struct.pack("<IIIHBBIQQQ", 0xffffffff, 0xffffffff, perm, links, 0, 0, 0, info, info, recorded) + \
                    t + t + t + t + struct.pack("<II", 1, 0) + b"\0" * 16 + b"\0" * 16 + regid(b"*GogitZIP test") + \
                    struct.pack("<QII", self.uid, 0, len(ad_bytes)) + ad_bytes
                ident = 266
            else:
                body = icbtag + struct.pack("<IIIHBBIQQ", 0xffffffff, 0xffffffff, perm, links, 0, 0, 0, info, recorded) + \
                    t + t + t + struct.pack("<I", 1) + b"\0" * 16 + regid(b"*GogitZIP test") + \
                    struct.pack("<QII", self.uid, 0, len(ad_bytes)) + ad_bytes
                ident = 261
            self.uid += 1
            assert 16 + len(body) <= bs, "entry too large"
            return tagged(ident, body, loc, self.tagver)

        def make_ads(extents, adtype, part):
            """extents: list of (length, pos, typ)"""
            out = []
            for (ln, pos, typ) in extents:
                if adtype == 0:
                    out.append(short_ad(ln, pos, typ))
                elif adtype == 1:
                    out.append(long_ad(ln, pos, part, typ))
                else:
                    out.append(ext_ad(ln, pos, part, typ))
            return out

        def place_data(data, nblocks_hint=None):
            nb = max(1, (len(data) + bs - 1) // bs)
            b = alloc_data(nb)
            for k in range(nb):
                put_data(b + k, data[k * bs:(k + 1) * bs].ljust(bs, b"\0"))
            return b

        def write_entry(n, ftype, data, info=None):
            opt = n.opt if n else {}
            ad = opt.get("ad", "short" if self.layout != "meta" or ftype == 4 else "long")
            if ad == "short" and ftype != 4 and data_map != icb_map:
                ad = "long"           # file data lives in another partition
            adtype = {"short": 0, "long": 1, "ext": 2, "inicb": 3}[ad]
            info = len(data) if info is None else info
            embedded = None
            extents = []
            if adtype == 3:
                embedded = data
            elif "segs" in opt:
                for s in opt["segs"]:
                    if s[0] == "data":
                        extents.append((len(s[1]), place_data(s[1]), 0))
                    else:
                        extents.append((s[1], 0, s[2]))
            elif data:
                split = opt.get("split")
                if split:
                    chunks = [data[i:i + split] for i in range(0, len(data), split)]
                    locs = [place_data(ch) for ch in reversed(chunks)][::-1]
                    extents = [(len(ch), loc, 0) for ch, loc in zip(chunks, locs)]
                else:
                    # one extent per 2^30 - bs bytes
                    mx = (1 << 30) - bs
                    for i in range(0, len(data), mx):
                        ch = data[i:i + mx]
                        extents.append((len(ch), place_data(ch), 0))
            part = data_map if ftype != 4 else icb_map
            ads = make_ads(extents, adtype, part)
            if "aed" in opt and adtype != 3:
                keep = opt["aed"]
                rest = ads[keep:]
                ads = ads[:keep]
                # chain of allocation extent descriptors, two descriptors per block
                chain = [rest[i:i + 2] for i in range(0, len(rest), 2)]
                locs = [alloc_icb() for _ in chain]
                for k, grp in enumerate(chain):
                    body_ads = b"".join(grp)
                    if k + 1 < len(chain) or opt.get("aed_loop"):
                        nxt = locs[(k + 1) % len(chain)]
                        body_ads += short_ad(bs, nxt, 3) if adtype == 0 else long_ad(bs, nxt, icb_map, 3) \
                            if adtype == 1 else ext_ad(bs, nxt, icb_map, 3)
                    body = struct.pack("<II", 0, len(body_ads)) + body_ads
                    put_icb(locs[k], tagged(258, body, locs[k], self.tagver).ljust(bs, b"\0"))
                if chain:
                    ads.append(short_ad(bs, locs[0], 3) if adtype == 0 else long_ad(bs, locs[0], icb_map, 3)
                               if adtype == 1 else ext_ad(bs, locs[0], icb_map, 3))
            fe = entry(n, ftype, info, ads, adtype, embedded, loc=n.icb if n else 0,
                       strategy=4096 if opt.get("strategy4096") else 4)
            if opt.get("strategy4096"):
                # the entry at n.icb is outdated; n.icb + 1 is an indirect entry to the new one
                old = entry(n, ftype, 5, [], 3, b"STALE", loc=n.icb, strategy=4096)
                put_icb(n.icb, old.ljust(bs, b"\0"))
                tgt = n.icb if opt.get("ie_loop") else n.icb_new
                ie = tagged(259, struct.pack("<IHHHBB", 0, 4096, 0, 2, 0, 3) + b"\0" * 6 + struct.pack("<H", 0) +
                            long_ad(bs, tgt, icb_map), n.icb + 1, self.tagver)
                put_icb(n.icb + 1, ie.ljust(bs, b"\0"))
                fe2 = entry(n, ftype, info, ads, adtype, embedded, loc=n.icb_new, strategy=4096)
                put_icb(n.icb_new, fe2.ljust(bs, b"\0"))
            else:
                put_icb(n.icb, fe.ljust(bs, b"\0"))

        def symlink_data(comps):
            out = b""
            for c in comps:
                if c == "/":
                    out += struct.pack("<BBH", 2, 0, 0)
                elif c == "..":
                    out += struct.pack("<BBH", 3, 0, 0)
                elif c == ".":
                    out += struct.pack("<BBH", 4, 0, 0)
                else:
                    ident = cs0(c)
                    out += struct.pack("<BBH", 5, len(ident), 0) + ident
            return out

        def walk(n):
            if n.kind == "dir":
                self.ndirs += 1
                parent = n.parent or n
                fids = [fid(None, 0x0A, parent.icb)]
                for c in n.children:
                    is_dir = c.kind == "dir" or (c.kind == "ref" and c.is_dir)
                    chars = (0x02 if is_dir else 0) | (0x01 if c.opt.get("hidden") else 0)
                    if c.opt.get("deleted"):
                        chars |= 0x04
                    if c.kind == "ref":
                        loc = c.target.icb if c.target else c.loc
                        fids.append(fid(c.name, chars, loc, part=None if c.target else c.part))
                        continue
                    fids.append(fid(c.name, chars, c.icb, c.opt.get("iu", b""), c.opt.get("name16")))
                # FID tags carry the block they start in; compute with a running offset
                n.dirdata = fids
                for c in n.children:
                    if c.kind != "ref":
                        walk(c)
            elif n.kind == "file":
                self.nfiles += 1

        walk(self.root)

        def emit(n):
            if n.kind == "dir":
                # directory data: decide placement first (inicb if it fits)
                raw_len = sum(16 + len(f) for f in n.dirdata)
                ad = n.opt.get("ad", "short")
                if ad == "inicb" and raw_len > bs - 300:
                    ad = "short"
                n.opt["ad"] = ad
                if ad == "inicb":
                    data = b"".join(tagged(257, f, n.icb, self.tagver) for f in n.dirdata)
                    write_entry(n, 4, data)
                else:
                    nb = max(1, (raw_len + bs - 1) // bs)
                    start = alloc_icb(nb)
                    data = b""
                    for f in n.dirdata:
                        data += tagged(257, f, start + len(data) // bs, self.tagver)
                    for k in range(nb):
                        put_icb(start + k, data[k * bs:(k + 1) * bs].ljust(bs, b"\0"))
                    ads = [(len(data), start, 0)]
                    adtype = {"short": 0, "long": 1, "ext": 2}[ad]
                    fe = entry(n, 4, len(data), make_ads(ads, adtype, icb_map), adtype, loc=n.icb)
                    put_icb(n.icb, fe.ljust(bs, b"\0"))
                for c in n.children:
                    if c.kind != "ref":
                        emit(c)
            elif n.kind == "file" and n.opt.get("deleted"):
                write_entry(n, 5, b"")        # deleted: the entry stays, its data is gone
            elif n.kind == "file":
                info = n.opt.get("info")
                if "segs" in n.opt and info is None:
                    info = sum(len(s[1]) if s[0] == "data" else s[1] for s in n.opt["segs"])
                write_entry(n, n.opt.get("ftype", 5), n.data, info)
            else:
                d = symlink_data(n.comps)
                n.opt.setdefault("ad", "inicb")
                write_entry(n, 12, d)

        emit(self.root)

        # file set descriptor + terminator in the ICB space
        fsd = timestamp() + struct.pack("<HHIIII", 3, 3, 1, 1, 0, 0) + charspec() + dstring("GZTEST", 128) + \
            charspec() + dstring("GZTEST", 32) + dstring("", 32) + dstring("", 32) + \
            long_ad(bs, self.root.icb, icb_map) + regid(b"*OSTA UDF Compliant", struct.pack("<HB", self.rev, 0)) + \
            b"\0" * 16 + b"\0" * 16 + b"\0" * 32
        put_icb(0, tagged(256, fsd, 0, self.tagver).ljust(bs, b"\0"))
        put_icb(1, tagged(8, b"\0" * 496, 1, self.tagver).ljust(bs, b"\0"))
        return self._volume()

    # ------------------------------------------------------------------
    def _volume(self):
        bs = self.bs
        vstep = max(2048, bs)
        vrs_end = 32768 + 3 * vstep
        mvds = (vrs_end + bs - 1) // bs
        rvds = mvds + 16
        lvid = rvds + 16
        stab = lvid + 2                      # sparing tables (2 x 2 sectors)
        assert stab + 4 < 256
        pstart = 257
        layout = self.layout
        data_blocks = dict(self.data_blocks)
        meta_info = None
        if layout == "meta":
            # metadata partition content after the file data in the physical partition; the
            # mirror copy comes first (7-Zip flags unread data after the last area it reads)
            n_meta = self.n_icb
            mirror = max(self.n_data, 2)
            mstart = mirror + n_meta
            for b, d in self.icb_blocks.items():
                data_blocks[mstart + b] = d
                data_blocks[mirror + b] = d
            plen = mstart + n_meta
            # metadata file entries (meta_split: two extents, the second half stored after a
            # gap, so the metadata partition is not contiguous; 7-Zip reads only one extent)
            if self.meta_split and n_meta > 1:
                half = n_meta // 2
                tail = mstart + n_meta + 3
                for b, d in self.icb_blocks.items():
                    if b >= half:
                        data_blocks[tail + b - half] = d
                        data_blocks[mstart + b] = b"\xDD" * bs
                plen = tail + n_meta - half
                exts = [(half * bs, mstart), ((n_meta - half) * bs, tail)]
            else:
                exts = [(n_meta * bs, mstart)]
            mexts = [(n_meta * bs, mirror)]
            meta_info = (n_meta, exts, mexts)
        elif layout == "vat":
            # virtual blocks are mapped in a shuffled order onto physical blocks after the data
            n_v = self.n_icb
            vbase = max(self.n_data, 0)
            order = list(range(n_v))
            order = order[::2] + order[1::2]          # not identity: neighbours split apart
            vat = [0xffffffff] * n_v
            for k, v in enumerate(order):
                vat[v] = vbase + k
                data_blocks[vbase + k] = self.icb_blocks.get(v, b"\0" * bs)
            plen = vbase + n_v + 1                    # + VAT entry
            vat_loc = vbase + n_v
        else:
            plen = max(self.n_data, 2)
        spare = []
        if layout == "sparable":
            pkt = 32
            plen = (plen + pkt - 1) // pkt * pkt + pkt
            spare_start = pstart + plen
            nspare = 2 * pkt
            # remap the packets holding the first file's data
            remaps = []
            if self.remap:
                for b in sorted(data_blocks):
                    pk = b - b % pkt
                    if pk not in [r[0] for r in remaps] and b >= 2:
                        remaps.append((pk, spare_start + len(remaps) * pkt))
                    if len(remaps) == 2:
                        break
            spare = remaps
        total = pstart + plen
        if layout == "sparable":
            total += 2 * 32
        if self.anchors != "256":
            total += 1                                 # end anchor
        img = bytearray(total * bs)

        def wsec(sec, data):
            img[sec * bs:sec * bs + len(data)] = data

        # VRS
        for k, ident in enumerate([b"BEA01", b"NSR03" if self.rev >= 0x200 else b"NSR02", b"TEA01"]):
            img[32768 + k * vstep:32768 + k * vstep + 7] = b"\0" + ident + b"\1"
        # partition contents
        for b, d in data_blocks.items():
            sec = pstart + b
            if layout == "sparable":
                pk = b - b % 32
                for (o, mloc) in spare:
                    if o == pk:
                        wsec(mloc + (b - pk), d)
                        d = b"\xDE" * bs                # stale copy at the original place
            wsec(sec, d)
        # metadata file entries
        domain = regid(b"*OSTA UDF Compliant", struct.pack("<HB", self.rev, 0))
        if meta_info:
            n_meta, exts, mexts = meta_info
            for k, (ft, ex) in enumerate([(250, exts), (251, mexts)]):
                ads = b"".join(short_ad(l, p) for (l, p) in ex)
                info = n_meta * bs
                icbtag = struct.pack("<IHHHBB", 0, 4, 0, 1, 0, ft) + b"\0" * 6 + struct.pack("<H", 0)
                t = timestamp()
                body = icbtag + struct.pack("<IIIHBBIQQQ", 0, 0, 0, 1, 0, 0, 0, info, info, n_meta) + t + t + t + t + \
                    struct.pack("<II", 1, 0) + b"\0" * 32 + regid(b"*GogitZIP test") + \
                    struct.pack("<QII", 0, 0, len(ads)) + ads
                fe = tagged(266, body, k, 3)
                if k == 0 and self.break_main_meta:
                    fe = b"\xBB" * 64 + fe[64:]
                wsec(pstart + k, fe.ljust(bs, b"\0"))
        if layout == "vat":
            entries = b"".join(struct.pack("<I", v) for v in vat)
            if self.vat15:
                vdata = entries + regid(b"*UDF Virtual Alloc Tbl", struct.pack("<H", 0x150)) + struct.pack("<I", 0xffffffff)
                ftype = 0
            else:
                hdr = struct.pack("<HH", 152, 0) + dstring("GZTEST", 128) + struct.pack("<IIIHHHH", 0xffffffff, self.nfiles,
                                                                                      self.ndirs, 0x150, 0x150, self.rev, 0)
                vdata = hdr + entries
                ftype = 248
            icbtag = struct.pack("<IHHHBB", 0, 4, 0, 1, 0, ftype) + b"\0" * 6 + struct.pack("<H", 3)
            t = timestamp()
            if self.efe:
                body = icbtag + struct.pack("<IIIHBBIQQQ", 0, 0, 0, 1, 0, 0, 0, len(vdata), len(vdata), 0) + t + t + t + t + \
                    struct.pack("<II", 1, 0) + b"\0" * 32 + regid(b"*GogitZIP test") + struct.pack("<QII", 0, 0, len(vdata)) + vdata
                fe = tagged(266, body, vat_loc, self.tagver)
            else:
                body = icbtag + struct.pack("<IIIHBBIQQ", 0, 0, 0, 1, 0, 0, 0, len(vdata), 0) + t + t + t + \
                    struct.pack("<I", 1) + b"\0" * 16 + regid(b"*GogitZIP test") + struct.pack("<QII", 0, 0, len(vdata)) + vdata
                fe = tagged(261, body, vat_loc, self.tagver)
            assert len(fe) <= bs
            wsec(pstart + vat_loc, fe.ljust(bs, b"\0"))
        # sparing tables
        if layout == "sparable":
            ents = b"".join(struct.pack("<II", o, m) for (o, m) in spare)
            ents += b"".join(struct.pack("<II", 0xfffffff0, 0) for _ in range(4 - len(spare)))
            body = regid(b"*UDF Sparing Table", struct.pack("<H", self.rev)) + struct.pack("<HHI", 4, 0, 1) + ents
            st = tagged(0, body, stab, self.tagver)
            wsec(stab, st)
            wsec(stab + 2, st)
        # partition maps
        if layout in ("type1",):
            maps = struct.pack("<BBHH", 1, 6, 1, 0)
        elif layout == "sparable":
            maps = struct.pack("<BBH", 2, 64, 0) + regid(b"*UDF Sparable Partition", struct.pack("<H", self.rev)) + \
                struct.pack("<HHHBBI", 1, 0, 32, 2, 0, 2 * bs) + struct.pack("<II", stab, stab + 2) + b"\0" * 8
        elif layout == "vat":
            maps = struct.pack("<BBHH", 1, 6, 1, 0) + struct.pack("<BBH", 2, 64, 0) + \
                regid(b"*UDF Virtual Partition", struct.pack("<H", self.rev)) + struct.pack("<HH", 1, 0) + b"\0" * 24
        else:
            maps = struct.pack("<BBHH", 1, 6, 1, 0) + struct.pack("<BBH", 2, 64, 0) + \
                regid(b"*UDF Metadata Partition", struct.pack("<H", self.rev)) + struct.pack("<HH", 1, 0) + \
                struct.pack("<IIIIHB", 0, 1, 0xffffffff, 32, 1, 0) + b"\0" * 5
        nmaps = {"type1": 1, "sparable": 1, "vat": 2, "meta": 2}[layout]
        icb_map = self._icb_space()[0]
        t = timestamp()
        ver = self.tagver

        def vds(base, seq0):
            pvd = struct.pack("<II", seq0, 0) + dstring("GZTEST", 32) + struct.pack("<HHHHII", 1, 1, 2, 2, 1, 1) + \
                dstring("GZTEST", 128) + charspec() + charspec() + b"\0" * 16 + regid(b"*GogitZIP") + t + \
                regid(b"*GogitZIP") + b"\0" * 64 + struct.pack("<IH", 0, 1) + b"\0" * 22
            pd = struct.pack("<IHH", seq0 + 1, 1, 0) + regid(b"+NSR03" if self.rev >= 0x200 else b"+NSR02") + b"\0" * 128 + \
                struct.pack("<III", 1, pstart, plen) + regid(b"*GogitZIP") + b"\0" * 128 + b"\0" * 156
            lvd = struct.pack("<I", seq0 + 2) + charspec() + dstring("GZTEST", 128) + struct.pack("<I", bs) + domain + \
                long_ad(bs, 0, icb_map) + struct.pack("<II", len(maps), nmaps) + regid(b"*GogitZIP") + b"\0" * 128 + \
                struct.pack("<II", 2 * bs, lvid) + maps
            descs = [tagged(1, pvd, base, ver), tagged(5, pd, base + 1, ver), tagged(6, lvd, base + 2, ver),
                     tagged(8, b"\0" * 496, base + 3, ver)]
            for k, dsc in enumerate(descs):
                wsec(base + k, dsc)

        vds(mvds, 1)
        vds(rvds, 1)
        if self.break_main_vds:
            for k in range(4):
                wsec(mvds + k, b"\xCC" * 32)
        iu = regid(b"*GogitZIP") + struct.pack("<IIHHH", self.nfiles, self.ndirs, 0x102, self.rev, self.rev)
        lvidd = t + struct.pack("<I", 1) + b"\0" * 8 + struct.pack("<Q", self.uid) + b"\0" * 24 + \
            struct.pack("<II", nmaps, len(iu)) + struct.pack("<I", 0) * nmaps + struct.pack("<I", plen) * nmaps + iu
        wsec(lvid, tagged(9, lvidd, lvid, ver))
        avdp = struct.pack("<IIII", 16 * bs, mvds, 16 * bs, rvds) + b"\0" * 480
        if self.anchors in ("256", "256+end"):
            wsec(256, tagged(2, avdp, 256, ver))
        if self.anchors in ("end", "256+end"):
            wsec(total - 1, tagged(2, avdp, total - 1, ver))
        return bytes(img)
