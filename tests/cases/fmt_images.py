"""Disk images and partition maps: MBR/EBR, GPT (512/4K, backup header), APM, VHD (fixed,
dynamic, differencing), VHDX, VMDK (sparse, streamOptimized, flat, split, custom descriptors),
VDI, QCOW/QCOW2 (v1/v2/v3, compressed, subclusters), Android sparse; hostile inputs + fuzzing.

Raw disks are built with sfdisk / sgdisk / Python, converted with qemu-img / img2simg, and every
extracted virtual disk / partition is compared with the raw source and with qemu-img's own output."""
import os, io, glob, random, shutil, struct, tarfile, zlib, uuid

ND = {"GZ_NO_DESCEND": "1"}
MiB = 1 << 20


def blob(n, seed):
    return random.Random(seed).randbytes(n)


def text(n, seed):
    rnd = random.Random(seed)
    words = [b"disk", b"image", b"partition", b"\xea\xb3\xa0\xea\xb8\xb0", b"sector", b"\n", b"zip"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words) + b" "
    return bytes(out[:n])


def make_tar(files):
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for k, v in sorted(files.items()):
            ti = tarfile.TarInfo(k)
            ti.size = len(v)
            ti.mtime = 1600000000
            tf.addfile(ti, io.BytesIO(v))
    return bio.getvalue()


def put(path, off, data):
    with open(path, "r+b") as f:
        f.seek(off)
        f.write(data)


def write_sparse(path, data):
    """Write data leaving all-zero 64 KiB blocks as holes."""
    with open(path, "wb") as f:
        f.truncate(len(data))
        z = bytes(65536)
        for o in range(0, len(data), 65536):
            if data[o:o + 65536] != z[:len(data[o:o + 65536])]:
                f.seek(o)
                f.write(data[o:o + 65536])


def new_file(path, size):
    with open(path, "wb") as f:
        f.truncate(size)


def read(path, off=0, n=None):
    with open(path, "rb") as f:
        f.seek(off)
        return f.read() if n is None else f.read(n)


# ---------------------------------------------------------------- hand-made structures

def gpt_build(path, size, ss, parts):
    """parts: (first_lba, last_lba, type_guid_str, name, content)"""
    img = bytearray(size)
    nlba = size // ss
    img[446 + 4] = 0xEE
    struct.pack_into("<II", img, 446 + 8, 1, min(nlba - 1, 0xFFFFFFFF))
    img[510:512] = b"\x55\xaa"
    ents = bytearray(128 * 128)
    for i, (f, l, tg, name, content) in enumerate(parts):
        e = uuid.UUID(tg).bytes_le + uuid.uuid4().bytes_le + struct.pack("<QQQ", f, l, 0) + \
            name.encode("utf-16-le").ljust(72, b"\0")
        ents[i * 128:(i + 1) * 128] = e
        img[f * ss:f * ss + len(content)] = content
    ecrc = zlib.crc32(ents)
    esec = len(ents) // ss

    def hdr(my, alt, elba):
        h = bytearray(92)
        h[0:8] = b"EFI PART"
        struct.pack_into("<IIIIQQQQ", h, 8, 0x00010000, 92, 0, 0, my, alt, 2 + esec, nlba - 2 - esec)
        h[56:72] = uuid.uuid4().bytes_le
        struct.pack_into("<QIII", h, 72, elba, 128, 128, ecrc)
        struct.pack_into("<I", h, 16, zlib.crc32(h))
        return bytes(h)
    img[ss:ss + 92] = hdr(1, nlba - 1, 2)
    img[2 * ss:2 * ss + len(ents)] = ents
    img[(nlba - 1 - esec) * ss:(nlba - 1) * ss] = ents
    img[(nlba - 1) * ss:(nlba - 1) * ss + 92] = hdr(nlba - 1, 1, nlba - 1 - esec)
    write_sparse(path, img)


def apm_build(path, size, parts, bs=512):
    """parts: (name, type, start_block, nblocks, content); the map itself is entry 1."""
    img = bytearray(size)
    img[0:2] = b"ER"
    struct.pack_into(">HI", img, 2, bs, size // bs)
    allp = [("Apple", "Apple_partition_map", 1, 63, b"")] + list(parts)
    for i, (name, typ, start, cnt, content) in enumerate(allp):
        o = (i + 1) * bs
        img[o:o + 2] = b"PM"
        struct.pack_into(">III", img, o + 4, len(allp), start, cnt)
        img[o + 16:o + 48] = name.encode().ljust(32, b"\0")
        img[o + 48:o + 80] = typ.encode().ljust(32, b"\0")
        img[start * bs:start * bs + len(content)] = content
    write_sparse(path, img)


def vhd_footer(vsize, dtype, data_off, uid):
    f = bytearray(512)
    f[0:8] = b"conectix"
    struct.pack_into(">IIQI", f, 8, 2, 0x10000, data_off, 0x2a2a2a2a)
    f[28:32] = b"gzt "
    struct.pack_into(">I", f, 32, 0x10000)
    f[36:40] = b"Wi2k"
    struct.pack_into(">QQII", f, 40, vsize, vsize, 0, dtype)
    f[68:84] = uid
    struct.pack_into(">I", f, 64, (~sum(f)) & 0xFFFFFFFF)
    return bytes(f)


def vhd_dynamic(path, vsize, bs, blocks, dtype=3, uid=None, parent=None, locators=()):
    """blocks: {index: (bitmap_bytes, data_bytes)}; parent: (uid, unicode name);
    locators: [(code, utf16le path bytes)]. Returns the image uid."""
    uid = uid or uuid.uuid4().bytes
    nbat = (vsize + bs - 1) // bs
    bmp = (((bs // 512) + 7) // 8 + 511) // 512 * 512
    bat_off = 1536
    pos = bat_off + (nbat * 4 + 511) // 512 * 512
    loc_area = []
    for code, data in locators:
        loc_area.append((code, pos, data))
        pos += (len(data) + 511) // 512 * 512
    bat = [0xFFFFFFFF] * nbat
    body = bytearray()
    for i in sorted(blocks):
        bat[i] = (pos + len(body)) // 512
        bm, data = blocks[i]
        body += bm.ljust(bmp, b"\0") + data.ljust(bs, b"\0")
    h = bytearray(1024)
    h[0:8] = b"cxsparse"
    struct.pack_into(">QQIII", h, 8, 0xFFFFFFFFFFFFFFFF, bat_off, 0x10000, nbat, bs)
    if parent:
        h[40:56] = parent[0]
        name = parent[1].encode("utf-16-be")
        h[64:64 + len(name)] = name
    for k, (code, off, data) in enumerate(loc_area):
        struct.pack_into(">4sIIIQ", h, 576 + 24 * k, code, (len(data) + 511) // 512 * 512, len(data), 0, off)
    struct.pack_into(">I", h, 36, (~sum(h)) & 0xFFFFFFFF)
    foot = vhd_footer(vsize, dtype, 512, uid)
    with open(path, "wb") as f:
        f.write(foot)
        f.write(h)
        f.write(struct.pack(">%dI" % nbat, *bat).ljust(pos - bat_off - sum((len(d) + 511) // 512 * 512 for _, _, d in loc_area), b"\xff"))
        for code, off, data in loc_area:
            f.write(data.ljust((len(data) + 511) // 512 * 512, b"\0"))
        f.write(body)
        f.write(foot)
    return uid


def crc32c(data):
    c = 0xFFFFFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ (0x82F63B78 if c & 1 else 0)
    return c ^ 0xFFFFFFFF


def bitmap_from(sectors_present, nsec):
    b = bytearray((nsec + 7) // 8)
    for s in sectors_present:
        b[s >> 3] |= 0x80 >> (s & 7)
    return bytes(b)


def simg_build(path, bs, chunks, total=None):
    """chunks: ('raw', bytes) | ('fill', u32, nblocks) | ('skip', nblocks) | ('crc', value|None)"""
    body = bytearray()
    expanded = bytearray()
    blocks = 0
    n = 0
    for c in chunks:
        if c[0] == "raw":
            nb = len(c[1]) // bs
            body += struct.pack("<HHII", 0xCAC1, 0, nb, 12 + len(c[1])) + c[1]
            expanded += c[1]
        elif c[0] == "fill":
            body += struct.pack("<HHIII", 0xCAC2, 0, c[2], 16, c[1])
            nb = c[2]
            expanded += struct.pack("<I", c[1]) * (nb * bs // 4)
        elif c[0] == "skip":
            nb = c[1]
            body += struct.pack("<HHII", 0xCAC3, 0, nb, 12)
            expanded += bytes(nb * bs)
        else:
            nb = 0
            v = zlib.crc32(expanded) if c[1] is None else c[1]
            body += struct.pack("<HHIII", 0xCAC4, 0, 0, 16, v)
        blocks += nb
        n += 1
    total = blocks if total is None else total
    hdr = struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, bs, total, n, 0)
    open(path, "wb").write(hdr + body)
    return bytes(expanded) + bytes(max(0, total - blocks) * bs)


# ---------------------------------------------------------------- checks

def check_disk(t, img, qfmt, expect, label=None):
    """GZ_NO_DESCEND: the single virtual disk entry equals expect (zero padded to the virtual
    size) and qemu-img's own conversion (qfmt)."""
    label = label or "disk " + os.path.basename(img)
    r, rows, out = t.extract(img, env=ND)
    if r.returncode or len(rows) != 1 or rows[0][0] != 0:
        return t.record(False, label, "extract failed: %s %s" % (r.stdout.decode(errors="replace")[:200],
                                                                 r.stderr.decode(errors="replace")[:200]))
    data = read(os.path.join(out, "0.bin"))
    shutil.rmtree(out, ignore_errors=True)
    want_name = os.path.splitext(os.path.basename(img))[0]
    if not want_name.endswith(".img"):
        want_name += ".img"
    if rows[0][3] != want_name:
        return t.record(False, label, "name %r, want %r" % (rows[0][3], want_name))
    if qfmt:
        ref = t.path("qref_" + os.path.basename(img) + ".raw")
        t.sh(["qemu-img", "convert", "-f", qfmt, "-O", "raw", img, ref])
        refd = read(ref)
        os.remove(ref)
        if data != refd:
            pos = next((i for i in range(min(len(data), len(refd))) if data[i] != refd[i]), min(len(data), len(refd)))
            return t.record(False, label, "differs from qemu-img: %d vs %d bytes, first diff at %d" % (len(data), len(refd), pos))
    if expect is not None:
        if len(data) < len(expect) or data[:len(expect)] != expect or data[len(expect):].strip(b"\0"):
            return t.record(False, label, "differs from the source (%d vs %d bytes)" % (len(data), len(expect)))
    return t.record(True, label, "%d bytes" % len(data))


def cleanup(t, img):
    """Remove an image, its extent files and extraction output (keeps the work dir small)."""
    stem = os.path.splitext(img)[0]
    for p in [img] + glob.glob(stem + "-*.vmdk"):
        os.remove(p)
    shutil.rmtree(os.path.join(t.work, "out_" + os.path.basename(img)), ignore_errors=True)


def check_listing(t, arc, typ, names, env=None, label=None):
    label = label or "list " + os.path.basename(arc)
    r, gtyp, rows = t.listing(arc, env=env)
    got = [x["name"] for x in rows]
    ok = r.returncode == 0 and gtyp == typ and got == names
    return t.record(ok, label, "" if ok else "type %r names %r (want %r %r) %s" % (
        gtyp, got, typ, names, r.stdout.decode(errors="replace")[:200]))


def check_open_error(t, arc, code, label=None):
    label = label or "error %s" % os.path.basename(arc)
    # gzt keeps its context when opening fails: no leak report for that under ASan
    r = t.run_gzt(["l", arc], {"ASAN_OPTIONS": "detect_leaks=0"})
    out = r.stdout.decode(errors="replace")
    ok = ("OPEN_ERROR %d" % code) in out
    return t.record(ok, label, "" if ok else "want OPEN_ERROR %d, got %r" % (code, out[:200]))


def check_entry_error(t, arc, code, label=None, env=None):
    label = label or "entry error %s" % os.path.basename(arc)
    r, rows, out = t.extract(arc, env=env)
    err = r.stderr.decode(errors="replace")
    ok = r.returncode == 0 and rows and all(v[0] == code for v in rows.values()) and "Sanitizer" not in err
    return t.record(ok, label, "" if ok else "rc=%d rows=%r %s" % (r.returncode, rows, err[-200:]))


def qemu(t, fmt, src, dst, opts=(), sfmt="raw"):
    if os.path.exists(dst):
        os.remove(dst)
    t.sh(["qemu-img", "convert", "-f", sfmt, "-O", fmt] + list(opts) + [src, dst])
    return dst


IMAGES = [
    # qemu format, file suffix, options, our type name
    ("vpc", "dyn.vhd", [], "VHD"),
    ("vpc", "fixed.vhd", ["-o", "subformat=fixed"], "VHD"),
    ("vpc", "force.vhd", ["-o", "force_size=on"], "VHD"),
    ("vhdx", "dyn.vhdx", [], "VHDX"),
    ("vhdx", "fixed.vhdx", ["-o", "subformat=fixed"], "VHDX"),
    ("vhdx", "b1m.vhdx", ["-o", "block_size=1M"], "VHDX"),
    ("vmdk", "sparse.vmdk", ["-o", "subformat=monolithicSparse"], "VMDK"),
    ("vmdk", "stream.vmdk", ["-o", "subformat=streamOptimized"], "VMDK"),
    ("vmdk", "flat.vmdk", ["-o", "subformat=monolithicFlat"], "VMDK"),
    ("vmdk", "split.vmdk", ["-o", "subformat=twoGbMaxExtentSparse"], "VMDK"),
    ("vmdk", "splitflat.vmdk", ["-o", "subformat=twoGbMaxExtentFlat"], "VMDK"),
    ("vdi", "dyn.vdi", [], "VDI"),
    ("vdi", "static.vdi", ["-o", "static=on"], "VDI"),
    ("qcow2", "v3.qcow2", [], "QCOW2"),
    ("qcow2", "v2.qcow2", ["-o", "compat=0.10"], "QCOW2"),
    ("qcow2", "c.qcow2", ["-c"], "QCOW2"),
    ("qcow2", "c512.qcow2", ["-c", "-o", "cluster_size=512"], "QCOW2"),
    ("qcow2", "c2m.qcow2", ["-c", "-o", "cluster_size=2M"], "QCOW2"),
    ("qcow2", "sub.qcow2", ["-o", "extended_l2=on"], "QCOW2"),
    ("qcow2", "subc.qcow2", ["-c", "-o", "extended_l2=on,cluster_size=128K"], "QCOW2"),
    ("qcow", "v1.qcow", [], "QCOW"),
]


def qemu_io_image(t, qfmt, path, copts):
    """8 MiB image written out of order with patterns, sub-cluster writes and zero writes."""
    if os.path.exists(path):
        os.remove(path)
    t.sh(["qemu-img", "create", "-q", "-f", qfmt] + copts + [path, "8M"])
    cmds = []
    for i in reversed(range(0, 128, 3)):                     # 64 KiB blocks, descending order
        cmds += ["-c", "write -P %d %d 65536" % (i + 1, i * 65536)]
    for i in range(0, 128, 7):                               # small writes inside blocks
        cmds += ["-c", "write -P %d %d 4096" % (120 + i, i * 65536 + 12288)]
    if qfmt in ("qcow2", "vmdk", "vhdx"):
        cmds += ["-c", "write -z 1048576 1048576", "-c", "write -z -u 4194304 524288",
                 "-c", "write -z 6291456 65536"]
    cmds += ["-c", "write -P 99 %d 1000" % (8 * MiB - 1536)]  # unaligned, near the end
    t.sh(["qemu-io"] + cmds + [path])
    return path


def qcow1_compressed(t, raw, path):
    """QCOW v1 image of raw with some clusters rewritten compressed (text and patterns)."""
    qemu(t, "qcow", raw, path)
    cmds = []
    for i in range(24):
        src = t.path("q1src%d.bin" % i)
        open(src, "wb").write(text(4096, 100 + i))
        cmds += ["-c", "write -c -s %s %d 4096" % (src, (40 + 7 * i) * 4096)]
    cmds += ["-c", "write -c -P 0x5a %d 4096" % (220 * 4096)]
    t.sh(["qemu-io"] + cmds + [path])
    return path


def run(t):
    t.need("qemu-img", "sfdisk", "sgdisk")
    W = t.work
    files = {
        "readme.txt": text(5000, 1),
        "docs/report.txt": text(700000, 2),
        "docs/photo.jpg": blob(900000, 3),
        "empty.txt": b"",
        "deep/a/b/c.bin": blob(123457, 4),
    }
    tarb = make_tar(files)

    # ---- disk A: MBR, one Linux partition holding a tarball (auto-descend), unaligned tail
    rawA = t.path("diskA.raw")
    new_file(rawA, 12 * MiB + 7 * 512)
    t.sh(["sfdisk", "-q", rawA], input=b"label: dos\nstart=2048, size=16384, type=83\n")
    put(rawA, MiB, tarb)
    put(rawA, 10 * MiB, blob(300000, 5))                  # data outside the partition
    A = read(rawA)
    t.check_extract(rawA, files, expect_type="TAR (MBR)", label="mbr auto-descend")
    check_listing(t, rawA, "MBR", ["1.linux"], env=ND)

    # ---- disk B: GPT with three partitions (FAT, Korean label + holes, tarball)
    rawB = t.path("diskB.raw")
    new_file(rawB, 16 * MiB)
    t.sh(["sgdisk", "-n", "1:2048:+3M", "-t", "1:ef00", "-c", "1:EFI System",
          "-n", "2:0:+6M", "-t", "2:8300", "-c", "2:데이터/백업",
          "-n", "3:0:+4M", "-t", "3:0700", "-c", "3:tarball", rawB])
    fat = t.path("fat.img")
    if os.path.exists(fat):
        os.remove(fat)
    if t.tool("mkfs.vfat"):
        t.sh(["mkfs.vfat", "-C", fat, "3072"])
    else:
        open(fat, "wb").write(blob(3 * MiB, 6))
    p2 = blob(MiB, 7) + bytes(MiB) + b"\xab\xcd\xef\x01" * (MiB // 4) + blob(MiB // 2, 8) + bytes(2 * MiB + MiB // 2)
    put(rawB, MiB, read(fat))
    put(rawB, 4 * MiB, p2)
    put(rawB, 10 * MiB, tarb)
    B = read(rawB)
    b_names = ["1.EFI System.fat", "2.데이터_백업.linux", "3.tarball.img"]
    b_parts = {b_names[0]: B[MiB:4 * MiB], b_names[1]: B[4 * MiB:10 * MiB], b_names[2]: B[10 * MiB:14 * MiB]}
    t.check_extract(rawB, b_parts, expect_type="GPT", label="gpt 3 partitions")

    # GPT damaged: primary header, primary array, both arrays
    for kind in ("hdr", "array", "both"):
        p = t.path("gpt_bad_%s.raw" % kind)
        d = bytearray(B)
        if kind == "hdr":
            d[512 + 40] ^= 1
        if kind in ("array", "both"):
            d[1024 + 60] ^= 1
        if kind == "both":
            d[len(d) - 33 * 512 + 60] ^= 1
        write_sparse(p, d)
        if kind == "both":
            check_open_error(t, p, 4, label="gpt both arrays bad -> CRC")
        else:
            t.check_extract(p, b_parts, label="gpt backup (%s)" % kind)

    # GPT with 4096-byte sectors, no tool needed
    raw4k = t.path("gpt4k.raw")
    c1, c2 = blob(3 * MiB, 9), text(2 * MiB, 10)
    gpt_build(raw4k, 8 * MiB, 4096, [(256, 256 + 768 - 1, "0FC63DAF-8483-4772-8E79-3D69D8477DE4", "root", c1),
                                     (1280, 1280 + 512 - 1, "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "", c2)])
    t.check_extract(raw4k, {"1.root.linux": c1, "2.img": c2}, expect_type="GPT", label="gpt 4K sectors")

    # ---- disk C: MBR with extended partition and logical partitions
    rawC = t.path("diskC.raw")
    new_file(rawC, 13 * MiB)
    t.sh(["sfdisk", "-q", rawC], input=b"label: dos\nstart=2048, size=4096, type=83\n"
                                       b"start=8192, size=16384, type=5\n"
                                       b"start=10240, size=4096, type=83\n"
                                       b"start=16384, size=8192, type=c\n")
    c_p1, c_l5, c_l6 = blob(2 * MiB, 11), blob(2 * MiB, 12), blob(4 * MiB, 13)
    put(rawC, 2048 * 512, c_p1)
    put(rawC, 10240 * 512, c_l5)
    put(rawC, 16384 * 512, c_l6)
    t.check_extract(rawC, {"1.linux": c_p1, "5.linux": c_l5, "6.fat": c_l6}, expect_type="MBR", label="mbr logical")

    # EBR chain loop: the second EBR points back to the first
    loopC = t.path("ebr_loop.raw")
    d = bytearray(read(rawC))
    e1 = 8192 * 512
    nxt = struct.unpack_from("<I", d, e1 + 462 + 8)[0]
    ebr2 = (8192 + nxt) * 512
    struct.pack_into("<I", d, ebr2 + 462 + 8, 0)           # next = start of the extended partition
    d[ebr2 + 462 + 4] = 5
    write_sparse(loopC, d)
    t.check_extract(loopC, {"1.linux": c_p1, "5.linux": c_l5, "6.fat": c_l6}, label="ebr loop")
    # partitions beyond the end of the image are not listed, a truncated one fails on extraction
    trC = t.path("mbr_trunc.raw")
    write_sparse(trC, read(rawC, 0, 10 * MiB))
    r, rows, out = t.extract(trC)
    st = {v[3]: v[0] for v in rows.values()}
    t.record(st.get("1.linux") == 0 and st.get("5.linux") == 0 and st.get("6.fat") == 9, "mbr truncated", repr(st))

    # ---- APM
    rawE = t.path("apm.raw")
    e1d, e2d = blob(MiB, 14), tarb
    apm_build(rawE, 8 * MiB, [("MacOS", "Apple_HFS", 64, 2048, e1d), ("Tar", "Apple_UNIX_SVR2", 4096, 8192, e2d),
                              ("", "Apple_Free", 12288, 4096, b"")])
    t.check_extract(rawE, {"2.MacOS.hfs": e1d, "3.Tar.img": e2d + bytes(8192 * 512 - len(e2d))},
                    expect_type="APM", label="apm")

    # ---- images of disk A (auto-descend to the tarball) and disk B (GPT, three partitions)
    for qfmt, suffix, opts, tname in IMAGES:
        for dn, raw, data in (("a", rawA, A), ("b", rawB, B)):
            img = t.path("%s_%s" % (dn, suffix))
            try:
                qemu(t, qfmt, raw, img, opts)
            except RuntimeError as e:
                t.record(False, "create " + os.path.basename(img), str(e)[:200])
                continue
            # qemu rounds VHD sizes up to a CHS geometry; reference = qemu's own reading
            check_disk(t, img, qfmt, data)
            if dn == "a":
                t.check_extract(img, files, expect_type="TAR (MBR) (%s)" % tname, label="descend " + os.path.basename(img))
            else:
                t.check_extract(img, b_parts, expect_type="GPT (%s)" % tname, label="parts " + os.path.basename(img))
            cleanup(t, img)

    # QCOW v1 with compressed clusters (qemu-img convert cannot write them: use qemu-io)
    if t.tool("qemu-io"):
        q1 = qcow1_compressed(t, rawA, t.path("a_v1c.qcow"))
        check_disk(t, q1, "qcow", None, label="qcow v1 compressed clusters")
        t.check_extract(q1, files, label="descend a_v1c.qcow")

    # images written by qemu-io: allocation order differs from the virtual order, zero writes
    # (qcow2 zero flag, VMDK zeroed grains, VHDX zero blocks), partial clusters
    if t.tool("qemu-io"):
        for qfmt, name, copts in (("qcow2", "io.qcow2", []), ("qcow2", "io_pre.qcow2", ["-o", "preallocation=metadata"]),
                                  ("qcow2", "io_sub.qcow2", ["-o", "extended_l2=on"]),
                                  ("qcow2", "io_v2.qcow2", ["-o", "compat=0.10"]),
                                  ("vmdk", "io_zg.vmdk", ["-o", "zeroed_grain=on"]), ("vmdk", "io.vmdk", []),
                                  ("vpc", "io.vhd", []), ("vhdx", "io.vhdx", []), ("vdi", "io.vdi", []),
                                  ("qcow", "io.qcow", [])):
            img = qemu_io_image(t, qfmt, t.path(name), copts)
            check_disk(t, img, qfmt, None, label="qemu-io " + name)

    # a disk image holding a bare tarball (no partition table)
    rawT = t.path("bare.raw")
    open(rawT, "wb").write(tarb + bytes(-len(tarb) % 4096 + 8192))
    for qfmt, suffix in (("qcow2", "bare.qcow2"), ("vmdk", "bare.vmdk"), ("vhdx", "bare.vhdx")):
        img = qemu(t, qfmt, rawT, t.path(suffix))
        t.check_extract(img, files, label="bare tar in " + suffix)

    # ---- VMDK: custom descriptor with FLAT (+offset), ZERO and SPARSE extents
    x1, x3 = blob(2 * MiB, 20), blob(2 * MiB, 21)
    open(t.path("ext1.raw"), "wb").write(x1)
    open(t.path("ext3.raw"), "wb").write(x3)
    x2raw = t.path("ext2.raw")
    x2 = blob(MiB, 22) + bytes(MiB) + text(MiB, 23)
    open(x2raw, "wb").write(x2)
    qemu(t, "vmdk", x2raw, t.path("ext2.vmdk"), ["-o", "subformat=monolithicSparse"])
    desc = t.path("custom.vmdk")
    open(desc, "w").write('# Disk DescriptorFile\nversion=1\nCID=12345678\nparentCID=ffffffff\n'
                          'createType="twoGbMaxExtentSparse"\n\n# Extent description\n'
                          'RW 4096 FLAT "ext1.raw" 0\nRW 2048 ZERO\nRW 6144 SPARSE "ext2.vmdk"\n'
                          'RW 2048 FLAT "ext3.raw" 1024\n\nddb.virtualHWVersion = "4"\n')
    # qemu ignores ZERO extents (VMware reads them as zeros): compare with qemu without one
    check_disk(t, desc, None, x1 + bytes(MiB) + x2 + x3[512 * 1024:512 * 1024 + MiB], label="vmdk custom descriptor")
    desc2 = t.path("custom2.vmdk")
    open(desc2, "w").write('# Disk DescriptorFile\nversion=1\nCID=12345678\nparentCID=ffffffff\n'
                           'createType="twoGbMaxExtentFlat"\n\n# Extent description\n'
                           'RW 2048 FLAT "ext3.raw" 1024\nRW 6144 SPARSE "ext2.vmdk"\nRW 4096 FLAT "ext1.raw" 0\n')
    check_disk(t, desc2, "vmdk", x3[512 * 1024:512 * 1024 + MiB] + x2 + x1, label="vmdk mixed extents vs qemu")
    missing = t.path("missing.vmdk")
    open(missing, "w").write('# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\ncreateType="monolithicFlat"\n'
                             'RW 2048 FLAT "no-such-file.raw" 0\n')
    check_open_error(t, missing, 14, label="vmdk missing extent")
    base = qemu(t, "vmdk", x2raw, t.path("base.vmdk"))
    delta = t.path("delta.vmdk")
    if os.path.exists(delta):
        os.remove(delta)
    t.sh(["qemu-img", "create", "-q", "-f", "vmdk", "-b", "base.vmdk", "-F", "vmdk", delta], cwd=W)
    check_open_error(t, delta, 5, label="vmdk delta -> METHOD")

    # ---- QCOW2 extras: backing file, zstd clusters
    child = t.path("child.qcow2")
    qemu(t, "qcow2", x2raw, t.path("parent.qcow2"))
    if os.path.exists(child):
        os.remove(child)
    t.sh(["qemu-img", "create", "-q", "-f", "qcow2", "-b", "parent.qcow2", "-F", "qcow2", child], cwd=W)
    check_open_error(t, child, 5, label="qcow2 backing -> METHOD")
    zs = t.path("zstd.qcow2")
    try:
        qemu(t, "qcow2", x2raw, zs, ["-c", "-o", "compression_type=zstd"])
        check_entry_error(t, zs, 5, env=ND, label="qcow2 zstd clusters -> METHOD")
    except RuntimeError:
        pass

    # ---- VHD: hand-made dynamic disk with partial bitmaps, differencing chain
    bs = 4096
    vsize = 64 * bs
    rnd = random.Random(30)
    base_data = rnd.randbytes(vsize)
    base_uid = uuid.uuid4().bytes
    open(t.path("base.vhd"), "wb").write(base_data + vhd_footer(vsize, 2, 0xFFFFFFFFFFFFFFFF, base_uid))
    mid_blocks, top_blocks = {}, {}
    expect = bytearray(base_data)
    for b in range(0, 64, 3):                              # mid: every third block, odd sectors only
        dat = rnd.randbytes(bs)
        mid_blocks[b] = (bitmap_from([s for s in range(8) if s & 1], 8), dat)
        for s in range(1, 8, 2):
            expect[b * bs + s * 512:b * bs + (s + 1) * 512] = dat[s * 512:(s + 1) * 512]
    expect_mid = bytes(expect)
    for b in range(0, 64, 5):                              # top: every fifth block, sectors 0..3
        dat = rnd.randbytes(bs)
        top_blocks[b] = (bitmap_from(range(4), 8), dat)
        for s in range(4):
            expect[b * bs + s * 512:b * bs + (s + 1) * 512] = dat[s * 512:(s + 1) * 512]
    mid_uid = vhd_dynamic(t.path("mid.vhd"), vsize, bs, mid_blocks, dtype=4, parent=(base_uid, "base.vhd"))
    vhd_dynamic(t.path("top.vhd"), vsize, bs, top_blocks, dtype=4, parent=(mid_uid, "nonexistent.vhd"),
                locators=[(b"W2ru", ".\\mid.vhd".encode("utf-16-le")), (b"W2ku", "C:\\x\\mid.vhd".encode("utf-16-le"))])
    check_disk(t, t.path("top.vhd"), None, bytes(expect), label="vhd differencing chain")
    check_disk(t, t.path("mid.vhd"), None, expect_mid, label="vhd differencing parent by name")
    orphan = t.path("orphan.vhd")
    vhd_dynamic(orphan, vsize, bs, top_blocks, dtype=4, parent=(uuid.uuid4().bytes, "base.vhd"))
    check_open_error(t, orphan, 5, label="vhd parent uid mismatch -> METHOD")
    # dynamic (not differencing): clear bitmap bits read as zeros
    dexp = bytearray(vsize)
    dyn_blocks = {}
    for b in (0, 7, 63):
        dat = rnd.randbytes(bs)
        dyn_blocks[b] = (bitmap_from([0, 2, 7], 8), dat)
        for s in (0, 2, 7):
            dexp[b * bs + s * 512:b * bs + (s + 1) * 512] = dat[s * 512:(s + 1) * 512]
    vhd_dynamic(t.path("bitmap.vhd"), vsize, bs, dyn_blocks)
    check_disk(t, t.path("bitmap.vhd"), None, bytes(dexp), label="vhd sector bitmaps")

    # ---- Android sparse images
    if t.tool("img2simg"):
        rawS = t.path("android.raw")
        sdata = blob(MiB, 40) + bytes(2 * MiB) + b"\xef\xbe\xad\xde" * (MiB // 4) + text(MiB + 4096, 41)
        open(rawS, "wb").write(sdata)
        simg = t.path("android.simg")
        t.sh(["img2simg", rawS, simg])
        check_disk(t, simg, None, sdata, label="img2simg")
        tsimg = t.path("tar.simg")
        t.sh(["img2simg", rawT, tsimg])
        t.check_extract(tsimg, files, expect_type="TAR (Sparse)", label="sparse holding a tarball")
    ch = [("raw", blob(8192, 42)), ("fill", 0x01020304, 3), ("crc", None), ("skip", 5), ("raw", text(4096, 43)), ("crc", None)]
    sx = simg_build(t.path("crc.simg"), 4096, ch, total=14)
    check_disk(t, t.path("crc.simg"), None, sx, label="sparse crc chunks")
    ch[2] = ("crc", 0x12345678)
    simg_build(t.path("badcrc.simg"), 4096, ch)
    check_entry_error(t, t.path("badcrc.simg"), 4, env=ND, label="sparse crc mismatch")
    simg_build(t.path("over.simg"), 4096, [("skip", 10)], total=5)
    check_open_error(t, t.path("over.simg"), 2, label="sparse chunks beyond total")

    # ---- hostile structures
    hostile(t, rawA, A)
    fuzz(t)
    for d in glob.glob(os.path.join(W, "out_*")):
        shutil.rmtree(d, ignore_errors=True)


def hostile(t, rawA, A):
    W = t.work
    small = t.path("small.raw")
    open(small, "wb").write(A[:2 * MiB])
    # VHD: BAT entry beyond the file, huge virtual size, broken checksum
    vhd = qemu(t, "vpc", small, t.path("h.vhd"))
    d = bytearray(read(vhd))
    bat_off = struct.unpack_from(">Q", d, 512 + 16)[0]
    struct.pack_into(">I", d, bat_off, 0x7FFFFFF0)
    write_sparse(t.path("h_bat.vhd"), d)
    check_entry_error(t, t.path("h_bat.vhd"), 9, env=ND, label="vhd BAT beyond file")
    d = bytearray(read(vhd))
    for base in (0, len(d) - 512):
        struct.pack_into(">Q", d, base + 48, 1 << 60)
        struct.pack_into(">I", d, base + 64, 0)
        struct.pack_into(">I", d, base + 64, (~sum(d[base:base + 512])) & 0xFFFFFFFF)
    write_sparse(t.path("h_huge.vhd"), d)
    check_open_error(t, t.path("h_huge.vhd"), 15, label="vhd huge virtual size")
    d = bytearray(read(vhd))
    d[30] ^= 1
    d[-512 + 30] ^= 1
    write_sparse(t.path("h_sum.vhd"), d)
    check_open_error(t, t.path("h_sum.vhd"), 4, label="vhd footer checksum")

    # QCOW2: L1 beyond the file, size not covered by L1, L2 entry pointing into the header
    q = qemu(t, "qcow2", small, t.path("h.qcow2"))
    d = bytearray(read(q))
    l1 = struct.unpack_from(">Q", d, 40)[0]
    struct.pack_into(">Q", d, l1, 0x7FFFFFFFFE00 | (1 << 63))
    write_sparse(t.path("h_l1.qcow2"), d)
    check_entry_error(t, t.path("h_l1.qcow2"), 9, env=ND, label="qcow2 L1 beyond file")
    d = bytearray(read(q))
    struct.pack_into(">Q", d, 24, 1 << 50)
    write_sparse(t.path("h_size.qcow2"), d)
    check_open_error(t, t.path("h_size.qcow2"), 2, label="qcow2 size beyond L1")
    d = bytearray(read(q))
    l2 = struct.unpack_from(">Q", d, l1)[0] & 0x00fffffffffffe00
    for i in range(32):
        struct.pack_into(">Q", d, l2 + 8 * i, (1 << 63) | l1)     # every cluster = the L1 table
    write_sparse(t.path("h_overlap.qcow2"), d)
    t.check_hostile(t.path("h_overlap.qcow2"), label="qcow2 overlapping tables")
    d = bytearray(read(q))
    struct.pack_into(">Q", d, 72, struct.unpack_from(">Q", d, 72)[0] | (1 << 40))
    write_sparse(t.path("h_feat.qcow2"), d)
    check_open_error(t, t.path("h_feat.qcow2"), 5, label="qcow2 unknown incompatible feature")

    # compressed clusters with garbage data
    qc = qemu(t, "qcow2", small, t.path("hc.qcow2"), ["-c"])
    d = bytearray(read(qc))
    for i in range(len(d) // 2, len(d), 97):
        d[i] ^= 0x5A
    write_sparse(t.path("h_cdata.qcow2"), d)
    t.check_hostile(t.path("h_cdata.qcow2"), label="qcow2 corrupt compressed clusters")

    # VMDK: grain directory beyond the file, absurd descriptor extent
    v = qemu(t, "vmdk", small, t.path("h.vmdk"))
    d = bytearray(read(v))
    gd = struct.unpack_from("<Q", d, 56)[0] * 512
    struct.pack_into("<I", d, gd, 0x7FFFFFF0)
    rgd = struct.unpack_from("<Q", d, 48)[0] * 512
    struct.pack_into("<I", d, rgd, 0x7FFFFFF0)
    write_sparse(t.path("h_gd.vmdk"), d)
    check_entry_error(t, t.path("h_gd.vmdk"), 9, env=ND, label="vmdk grain table beyond file")
    d = bytearray(read(v))
    gd = struct.unpack_from("<Q", d, 56)[0] * 512
    struct.pack_into("<I", d, gd, 0x7FFFFFF0)
    write_sparse(t.path("h_gd1.vmdk"), d)
    t.check_extract(t.path("h_gd1.vmdk"), {"h_gd1.img": A[:2 * MiB]}, env=ND, label="vmdk redundant grain directory")
    open(t.path("h_desc.vmdk"), "w").write('# Disk DescriptorFile\ncreateType="monolithicFlat"\n'
                                          'RW 99999999999999999999 FLAT "small.raw" 0\n')
    check_open_error(t, t.path("h_desc.vmdk"), 2, label="vmdk absurd extent size")
    s = qemu(t, "vmdk", small, t.path("hs.vmdk"), ["-o", "subformat=streamOptimized"])
    d = bytearray(read(s))
    for i in range(70000, len(d) - 2048, 333):
        d[i] ^= 0xA5
    write_sparse(t.path("h_stream.vmdk"), d)
    t.check_hostile(t.path("h_stream.vmdk"), label="vmdk corrupt compressed grains")

    # VDI: block beyond the file, disk larger than the block map
    vd = qemu(t, "vdi", small, t.path("h.vdi"))
    d = bytearray(read(vd))
    moff = struct.unpack_from("<I", d, 340)[0]
    struct.pack_into("<I", d, moff, 0x00FFFFFF)
    write_sparse(t.path("h_map.vdi"), d)
    check_entry_error(t, t.path("h_map.vdi"), 9, env=ND, label="vdi block beyond file")
    d = bytearray(read(vd))
    struct.pack_into("<Q", d, 368, 1 << 45)
    write_sparse(t.path("h_size.vdi"), d)
    check_open_error(t, t.path("h_size.vdi"), 2, label="vdi size beyond block map")

    # VHDX: both headers broken; BAT entry beyond file
    x = qemu(t, "vhdx", small, t.path("h.vhdx"))
    d = bytearray(read(x))
    d[65536 + 100] ^= 1
    d[131072 + 100] ^= 1
    write_sparse(t.path("h_hdr.vhdx"), d)
    check_open_error(t, t.path("h_hdr.vhdx"), 4, label="vhdx headers checksum")
    d = bytearray(read(x))
    d[196608 + 300] ^= 1
    write_sparse(t.path("h_rt.vhdx"), d)
    t.check_extract(t.path("h_rt.vhdx"), {"h_rt.img": A[:2 * MiB]}, env=ND, label="vhdx region table copy")

    # VHDX: the newest valid header wins; a log that was not replayed is noted in the comment
    d = bytearray(read(x))
    s1, s2 = struct.unpack_from("<Q", d, 65536 + 8)[0], struct.unpack_from("<Q", d, 131072 + 8)[0]
    newest = 65536 if s1 > s2 else 131072
    d[newest + 100] ^= 1
    write_sparse(t.path("h_hdr1.vhdx"), d)
    t.check_extract(t.path("h_hdr1.vhdx"), {"h_hdr1.img": A[:2 * MiB]}, env=ND, label="vhdx older header")
    d = bytearray(read(x))
    d[newest + 48:newest + 64] = uuid.uuid4().bytes
    d[newest + 4:newest + 8] = b"\0\0\0\0"
    struct.pack_into("<I", d, newest + 4, crc32c(bytes(d[newest:newest + 4096])))
    write_sparse(t.path("h_log.vhdx"), d)
    r, rows, out = t.extract(t.path("h_log.vhdx"), env=ND)
    ok = r.returncode == 0 and rows.get(0, (1,))[0] == 0 and b"log not replayed" in r.stderr
    t.record(ok and read(os.path.join(out, "0.bin")) == A[:2 * MiB], "vhdx dirty log noted", r.stderr.decode(errors="replace")[-200:])

    # MBR: overlapping / out of range partitions, all-garbage table
    d = bytearray(read(small))
    struct.pack_into("<II", d, 446 + 16 + 8, 2048, 0xFFFFFFFF)
    d[446 + 16 + 4] = 0x83
    write_sparse(t.path("h_mbr.raw"), d)
    t.check_hostile(t.path("h_mbr.raw"), label="mbr partition beyond end")


def fuzz(t):
    """Mutation fuzzing of small images through the C driver (no crash, no hang)."""
    drv = t.build_driver("tests/drivers/imgfuzz.c")
    small = t.path("small.raw")
    seeds = [small]
    for qfmt, suffix, opts in (("vpc", "f.vhd", []), ("vpc", "ff.vhd", ["-o", "subformat=fixed"]),
                               ("vhdx", "f.vhdx", []), ("vmdk", "f.vmdk", []),
                               ("vmdk", "fs.vmdk", ["-o", "subformat=streamOptimized"]), ("vdi", "f.vdi", []),
                               ("qcow2", "f.qcow2", []), ("qcow2", "fc.qcow2", ["-c", "-o", "cluster_size=4K"]),
                               ("qcow2", "fx.qcow2", ["-o", "extended_l2=on"])):
        seeds.append(qemu(t, qfmt, small, t.path("fz_" + suffix), opts))
    if t.tool("qemu-io"):
        seeds.append(qcow1_compressed(t, small, t.path("fz_f.qcow")))
    for p in ("gpt4k.raw", "apm.raw", "diskC.raw", "crc.simg", "top.vhd", "bitmap.vhd", "custom.vmdk", "custom2.vmdk"):
        seeds.append(t.path(p))
    # concurrent extraction through one archive (descends to the partitions / tar files)
    rawB = t.path("diskB.raw")
    th = [qemu(t, "qcow2", rawB, t.path("th.qcow2"), ["-c", "-o", "cluster_size=16K"]),
          qemu(t, "vmdk", rawB, t.path("th.vmdk"), ["-o", "subformat=streamOptimized"]),
          qemu(t, "vpc", rawB, t.path("th.vhd")), t.path("top.vhd"), t.path("diskC.raw")]
    for p in th:
        r = t.sh([drv, "-t", p], check=False, timeout=600)
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        t.record(r.returncode == 0 and out.startswith("ok"), "threads " + os.path.basename(p), out.strip()[-300:])
    for p in th[:3]:
        cleanup(t, p)
    iters = int(os.environ.get("GZ_FUZZ_ITERS", "150"))
    for i, p in enumerate(seeds):
        if not os.path.exists(p):
            continue
        r = t.sh([drv, p, str(iters), str(1000 + i)], check=False, timeout=600)
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        ok = r.returncode == 0 and "ok %d" % iters in out and "Sanitizer" not in out and "runtime error" not in out
        t.record(ok, "fuzz " + os.path.basename(p), out.strip()[-300:])
