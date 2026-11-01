"""Split the LZX resources of a (non-solid) WIM into .lzxf chunk files for the LZX
WIM-mode test (helper for fmt_cab.py, not a test module).

    resources(wim_path) -> [(chunk_size, [(compressed_chunk, usize)], sha1)]
"""
import struct

def _reshdr(b, o):
    size = int.from_bytes(b[o:o + 7], "little")
    flags = b[o + 7]
    off, orig = struct.unpack_from("<QQ", b, o + 8)
    return size, flags, off, orig

def resources(path, limit=64):
    b = open(path, "rb").read()
    if b[:8] != b"MSWIM\0\0\0":
        raise ValueError("not a WIM")
    hflags, chunk = struct.unpack_from("<II", b, 0x10)
    if not (hflags & 0x40000):          # LZX
        raise ValueError("not LZX compressed")
    tsize, tflags, toff, torig = _reshdr(b, 0x30)
    table = b[toff:toff + tsize]
    out = []
    for i in range(0, len(table) - 49, 50):
        size, flags, off, orig = _reshdr(table, i)
        sha = table[i + 30:i + 50]
        if not (flags & 4) or (flags & 0x10) or orig == 0:   # compressed, not solid
            continue
        n = (orig + chunk - 1) // chunk
        esz = 8 if orig > 0xffffffff else 4
        ct = b[off:off + esz * (n - 1)]
        starts = [0] + [int.from_bytes(ct[k * esz:(k + 1) * esz], "little") for k in range(n - 1)]
        base = off + esz * (n - 1)
        end = size - esz * (n - 1)
        chunks = []
        for k in range(n):
            cs = (starts[k + 1] if k + 1 < n else end) - starts[k]
            us = chunk if k + 1 < n else orig - chunk * (n - 1)
            chunks.append((b[base + starts[k]:base + starts[k] + cs], us))
        out.append((chunk, chunks, sha))
        if len(out) >= limit:
            break
    return out

def write_lzxf(path, chunks):
    with open(path, "wb") as f:
        f.write(b"LZXF" + struct.pack("<I", len(chunks)))
        for d, u in chunks:
            f.write(struct.pack("<II", len(d), u) + d)
