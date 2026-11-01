"""
Core crypto / checksum primitives (src/core: sha1, sha256, aes, crypto KDFs, crc32, crc64, blake2).

Driver: tests/drivers/crypto_test.c. Every check runs at every x86 dispatch tier the
machine supports plus the portable-only setting (-2); the AArch64 build runs under
qemu-aarch64 -cpu max (SHA1/SHA2/AES/PMULL/CRC32 emulated) when the cross tools exist.

References: hashlib (sha1, sha256, blake2s; BLAKE2sp built from hashlib.blake2s tree
parameters), hmac, hashlib.pbkdf2_hmac, zlib.crc32, xz block check values (CRC-64),
the `cryptography` package or the openssl CLI (AES), and Python ports of the 7z,
RAR 3.x (unrar SetKey30 incl. the SHA-1 block rewrite) and RAR 5.0 key derivations.
"""
import hashlib, hmac, os, random, shutil, struct, subprocess, zlib

# ---------------------------------------------------------------- references

def blake2sp(data):
    leaves = [hashlib.blake2s(digest_size=32, fanout=8, depth=2, leaf_size=0, node_offset=i,
                              node_depth=0, inner_size=32, last_node=(i == 7)) for i in range(8)]
    for j in range(0, len(data), 64):
        leaves[(j // 64) % 8].update(data[j:j + 64])
    root = hashlib.blake2s(digest_size=32, fanout=8, depth=2, leaf_size=0, node_offset=0,
                           node_depth=1, inner_size=32, last_node=True)
    for l in leaves:
        root.update(l.digest())
    return root.digest()

_CRC64_T = []
def crc64(data):
    if not _CRC64_T:
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ (0xC96C5795D7870F42 if c & 1 else 0)
            _CRC64_T.append(c)
    c = 0xFFFFFFFFFFFFFFFF
    t = _CRC64_T
    for b in data:
        c = t[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFFFFFFFFFF

def ref_digest(alg, data):
    if alg == "sha1": return hashlib.sha1(data).hexdigest()
    if alg == "sha256": return hashlib.sha256(data).hexdigest()
    if alg == "blake2s": return hashlib.blake2s(data).hexdigest()
    if alg == "blake2sp": return blake2sp(data).hex()
    if alg == "crc32": return "%08x" % (zlib.crc32(data) & 0xFFFFFFFF)
    if alg == "crc64": return "%016x" % crc64(data)
    raise ValueError(alg)

def kdf7z(salt, pw, power):
    if power == 0x3F:
        return (salt + pw + bytes(32))[:32]
    n = 1 << power
    unit_tail = salt + pw
    return hashlib.sha256(b"".join(unit_tail + struct.pack("<Q", i) for i in range(n))).digest()

def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def _sha1_w_tail(block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 80):
        w.append(_rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
    return struct.pack("<16I", *w[64:80])

def kdf_rar3(pw, salt):
    """unrar CryptData::SetKey30 with sha1_process_rar29: blocks hashed straight from
    the password buffer are overwritten with W[64..79] (little-endian words)."""
    raw = bytearray(pw[:254] + (salt or b""))
    L = len(raw)
    sha = hashlib.sha1()
    count = 0
    iv = bytearray(16)
    for i in range(0x40000):
        sha.update(bytes(raw))
        j = count & 63
        if j + L > 63:
            k = 64 - j
            while k + 63 < L:
                raw[k:k + 64] = _sha1_w_tail(bytes(raw[k:k + 64]))
                k += 64
        count += L
        sha.update(bytes((i & 0xFF, (i >> 8) & 0xFF, (i >> 16) & 0xFF)))
        count += 3
        if i % 0x4000 == 0:
            iv[i // 0x4000] = sha.copy().digest()[19]
    d = sha.digest()
    key = bytes(d[i * 4 + 3 - j] for i in range(4) for j in range(4))
    return key, bytes(iv)

def kdf_rar5(pw, salt, lg2):
    n = 1 << lg2
    key = hashlib.pbkdf2_hmac("sha256", pw, salt, n)
    hk = hashlib.pbkdf2_hmac("sha256", pw, salt, n + 16)
    pv = hashlib.pbkdf2_hmac("sha256", pw, salt, n + 32)
    pc = bytearray(8)
    for i, b in enumerate(pv):
        pc[i % 8] ^= b
    return key, hk, bytes(pc)

class AesRef:
    """ECB block function from `cryptography`, else the openssl CLI."""
    def __init__(self, t):
        self.t = t
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            self.mod = (Cipher, algorithms, modes)
        except Exception:
            self.mod = None
            if not shutil.which("openssl"):
                t.skip("no AES reference (cryptography / openssl)")

    def run(self, mode, key, iv, data, enc):
        if self.mod:
            Cipher, algorithms, modes = self.mod
            m = modes.ECB() if mode == "ecb" else modes.CBC(iv)
            c = Cipher(algorithms.AES(key), m)
            o = c.encryptor() if enc else c.decryptor()
            return o.update(data) + o.finalize()
        args = ["openssl", "enc", "-aes-%d-%s" % (len(key) * 8, mode), "-nopad", "-K", key.hex()]
        if mode == "cbc":
            args += ["-iv", iv.hex()]
        if not enc:
            args.append("-d")
        return subprocess.run(args, input=data, capture_output=True, check=True).stdout

    def winzip_ctr(self, key, data):
        nb = (len(data) + 15) // 16
        ctr = b"".join(struct.pack("<QQ", i + 1, 0) for i in range(nb))
        ks = self.run("ecb", key, None, ctr, True)
        return bytes(a ^ b for a, b in zip(data, ks))

# ---------------------------------------------------------------- checks

SIZES = [0, 1, 3, 15, 16, 17, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 257,
         447, 448, 449, 511, 512, 513, 575, 576, 959, 960, 961, 1023, 1024, 1025, 1471, 1472,
         1536, 2047, 4096, 4099, 65536, 65543, 1 << 20, (1 << 20) + 513]

def make_files(t, rnd):
    files = []
    for n in SIZES:
        p = t.path("data", "f%d.bin" % n)
        if not os.path.exists(p):
            with open(p, "wb") as f:
                f.write(rnd.randbytes(n))
        files.append(p)
    return files

def run_drv(t, drv, args, timeout=600):
    r = subprocess.run(drv + args, capture_output=True, timeout=timeout)
    if r.returncode:
        raise RuntimeError("driver failed (%d): %s %s" % (r.returncode, " ".join(args[:4]),
                                                          (r.stdout + r.stderr).decode(errors="replace")[-400:]))
    return r.stdout.decode().split()

def check_all(t, drv, tiers, label, files, data, aes, rnd, light=False):
    """digests, HMAC, PBKDF2, AES and KDFs at each tier vs the references"""
    refs = {}
    for alg in ("sha1", "sha256", "blake2s", "blake2sp", "crc32", "crc64"):
        refs[alg] = [ref_digest(alg, d) for d in data]
    for tier in tiers:
        tl = "%s tier %s" % (label, tier)
        for alg, want in refs.items():
            got = run_drv(t, drv, ["hash", alg, str(tier)] + files)
            bad = [os.path.basename(f) for f, g, w in zip(files, got, want) if g != w]
            t.record(not bad and len(got) == len(want), "%s %s (%d sizes)" % (tl, alg, len(want)),
                     "mismatch: " + " ".join(bad[:6]) if bad else "")
        # HMAC with short / block-size / long keys
        small = [f for f, d in zip(files, data) if len(d) <= 70000]
        sdata = [d for d in data if len(d) <= 70000]
        for alg in ("sha1", "sha256"):
            for kl in ((0, 65) if light else (0, 1, 20, 64, 65, 200)):
                key = bytes(rnd.randrange(256) for _ in range(kl))
                got = run_drv(t, drv, ["hmac", alg, str(tier), key.hex() or "-"] + small)
                want = [hmac.new(key, d, alg).hexdigest() for d in sdata]
                t.record(got == want, "%s hmac-%s key %d" % (tl, alg, kl))
        # PBKDF2
        for alg, it, pl, sl, ol in (("sha1", 1, 8, 4, 20), ("sha1", 1000, 10, 16, 66), ("sha1", 3, 70, 8, 41),
                                    ("sha256", 1, 0, 0, 32), ("sha256", 2, 64, 16, 33), ("sha256", 1000, 100, 64, 100)):
            pw = bytes(rnd.randrange(256) for _ in range(pl))
            salt = bytes(rnd.randrange(256) for _ in range(sl))
            got = run_drv(t, drv, ["pbkdf2", alg, str(tier), str(it), pw.hex() or "-", salt.hex() or "-", str(ol)])
            want = hashlib.pbkdf2_hmac(alg, pw, salt, it, ol).hex()
            t.record(got == [want], "%s pbkdf2-%s it=%d out=%d" % (tl, alg, it, ol))
        # AES: every key size and mode, sizes around the 8/16-block kernel widths
        if aes:
            for kl in (16, 24, 32):
                key = bytes(rnd.randrange(256) for _ in range(kl))
                iv = bytes(rnd.randrange(256) for _ in range(16))
                sizes = (0, 16, 48, 112, 128, 144, 256, 272, 496, 4096, 65536 + 48, 100003)
                for n in ((48, 144, 272, 4099) if light else sizes):
                    pt = rnd.randbytes(n)
                    src = t.path("aes", "%s_in_%d" % (label, n))      # per target: they run concurrently
                    out = t.path("aes", "%s_out_%d" % (label, n))
                    with open(src, "wb") as f:
                        f.write(pt)
                    full = pt[:len(pt) & ~15]
                    cases = [("ecb-enc", aes.run("ecb", key, iv, full, True)),
                             ("ecb-dec", aes.run("ecb", key, iv, full, False)),
                             ("cbc-enc", aes.run("cbc", key, iv, full, True)),
                             ("cbc-dec", aes.run("cbc", key, iv, full, False)),
                             ("ctr", aes.winzip_ctr(key, pt))]
                    bad = []
                    for mode, want in cases:
                        run_drv(t, drv, ["aes", mode, str(tier), key.hex(), iv.hex(), src, out])
                        if open(out, "rb").read() != want:
                            bad.append("%s/%d" % (mode, n))
                    t.record(not bad, "%s aes-%d n=%d" % (tl, kl * 8, n), " ".join(bad))
        # KDFs
        for salt, pw, power in ((b"", b"", 0), (b"", "a".encode("utf-16-le"), 1),
                                (os.urandom(8), "비밀번호".encode("utf-16-le"), 6),
                                (os.urandom(16), "password12".encode("utf-16-le"), 7),
                                (os.urandom(16), ("x" * 100).encode("utf-16-le"), 12),
                                (os.urandom(16), "p@ss".encode("utf-16-le"), 19 if not light else 13),
                                (os.urandom(16), "short".encode("utf-16-le"), 0x3F),
                                (b"ab", ("y" * 20).encode("utf-16-le"), 0x3F)):
            got = run_drv(t, drv, ["kdf7z", str(tier), str(power), salt.hex() or "-", pw.hex() or "-"])
            t.record(got == [kdf7z(salt, pw, power).hex()], "%s 7z kdf power=%d pw=%d" % (tl, power, len(pw)))
        for pw, salt, lg2 in ((b"", os.urandom(16), 0), (b"password", os.urandom(16), 1),
                              ("암호 test".encode(), os.urandom(16), 5), (b"x" * 90, os.urandom(16), 15),
                              (b"k", os.urandom(64), 3)):
            got = run_drv(t, drv, ["kdfrar5", str(tier), str(lg2), salt.hex(), pw.hex() or "-"])
            want = [x.hex() for x in kdf_rar5(pw, salt, lg2)]
            t.record(got == want, "%s rar5 kdf lg2=%d pw=%d" % (tl, lg2, len(pw)))

def rar3_refs():
    """RAR 3.x cases: short passwords (batched path) and long ones (unrar's in-place rewrite)."""
    cases = [("", True), ("a", True), ("test", True), ("비밀번호", True), ("x" * 28, True),
             ("y" * 29, True), ("z" * 10, False), ("long password with the rewrite!", True), ("Q" * 47, False)]
    refs = []
    for pw, with_salt in cases:
        salt = os.urandom(8) if with_salt else None
        b = pw.encode("utf-16-le")
        refs.append((b, salt, kdf_rar3(b, salt)))
    return refs

def check_rar3(t, drv, tiers, label, refs):
    for tier in tiers:
        for b, salt, (key, iv) in refs:
            got = run_drv(t, drv, ["kdfrar3", str(tier), salt.hex() if salt else "-", b.hex() or "-"])
            t.record(got == [key.hex(), iv.hex()], "%s tier %s rar3 kdf pw=%d salt=%d" % (label, tier, len(b) // 2, bool(salt)))

def check_rar3_vs_rarfile(t):
    """The Python port above against rarfile's independent rar3_s2k (pip install rarfile)."""
    try:
        import rarfile
    except Exception:
        return
    for pw in ("", "secret", "비밀", "a" * 29, "long password with the rewrite!"):
        salt = os.urandom(8)
        want = rarfile.rar3_s2k(pw, salt)
        got = kdf_rar3(pw.encode("utf-16-le"), salt)
        t.record(tuple(want) == got, "rar3 reference vs rarfile pw=%d" % len(pw))

def check_zipcrypto(t, drv, rnd):
    """ZipCrypto encryption (for the ZIP writer) decrypted by Python's zipfile."""
    import zipfile
    dec = getattr(zipfile, "_ZipDecrypter", None)
    if dec is None:
        return
    for pw in (b"", b"secret", "비밀".encode()):
        pt = rnd.randbytes(5000)
        src, out = t.path("zc", "in"), t.path("zc", "out")
        with open(src, "wb") as f:
            f.write(pt)
        run_drv(t, drv, ["zcenc", pw.hex() or "-", src, out])
        t.record(dec(pw)(open(out, "rb").read()) == pt, "zipcrypto encrypt vs zipfile pw=%d" % len(pw))

def check_xz_crc64(t, drv, files):
    if not shutil.which("xz"):
        return
    for f in files:
        if os.path.getsize(f) > (1 << 20):
            continue
        xzf = t.path("xz", os.path.basename(f) + ".xz")
        with open(xzf, "wb") as o:
            subprocess.run(["xz", "--check=crc64", "-0", "-c", f], stdout=o, check=True)
        r = subprocess.run(["xz", "--robot", "-lvv", xzf], capture_output=True, check=True)
        blocks = [l.split("\t") for l in r.stdout.decode().splitlines() if l.startswith("block")]
        want = blocks[0][10] if blocks else "%016x" % crc64(b"")   # empty input: no block
        got = run_drv(t, drv, ["hash", "crc64", "-1", f])
        t.record(got == [want], "crc64 vs xz %s" % os.path.basename(f), "got %s want %s" % (got, want))

def selftest_rec(t, cmd, label, timeout=900, env=None):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return t.record(False, label, "timeout")
    out = r.stdout.decode(errors="replace")
    return t.record(r.returncode == 0 and " 0 failed" in out, label,
                    out.strip().splitlines()[-1] if out.strip() else r.stderr.decode(errors="replace")[-300:])

def standalone(t, cc, flags, name):
    """Build the driver from the sources directly (cross / 32-bit targets)."""
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    srcs = [os.path.join(root, "src", s) for s in ("core/cpu.c", "core/crc32.c", "core/crc64.c", "core/crypto.c",
                                                     "core/sha1.c", "core/sha256.c", "core/aes.c", "core/blake2.c")]
    exe = t.path(name)
    t.sh(cc + flags + ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Wno-unused-parameter",
                       "-Wno-missing-field-initializers", "-Werror", "-DCT_STANDALONE"] +
         ["-I" + os.path.join(root, d) for d in ("src/core", "src/codec", "src/fmt")] +
         ["-o", exe, os.path.join(root, "tests/drivers/crypto_test.c")] + srcs)
    return exe

def run_i586(t, files, data):
    """i586 build (the 32-bit Windows binary's code: 4-wide AES-NI, 8 xmm registers, the
    x86/MMX/SSE tiers x86-64 cannot select)."""
    probe = t.path("m32probe.c")
    with open(probe, "w") as f:
        f.write("#include <stdio.h>\nint main(void) { return 0; }\n")
    if subprocess.run(["gcc", "-m32", "-o", probe + ".out", probe], capture_output=True).returncode == 0:
        m32 = standalone(t, ["gcc", "-m32"], ["-march=i586", "-mtune=generic"], "crypto_test_i586")
    else:
        m32 = None          # no 32-bit multilib
    if m32:
        selftest_rec(t, [m32, "selftest", "quick"], "i586 selftest (all tiers)")
        info = run_drv(t, [m32], ["info"])
        tiers32 = " ".join(info).split("tiers=")[1].split("crc32=")[0].split()
        small = [f for f, d in zip(files, data) if len(d) <= 70000]
        for tier in ["0", tiers32[-1]]:
            for alg in ("sha1", "sha256", "blake2sp", "crc32", "crc64"):
                got = run_drv(t, [m32], ["hash", alg, tier] + small)
                want = [ref_digest(alg, d) for d in data if len(d) <= 70000]
                t.record(got == want, "i586 tier %s %s" % (tier, alg))
            got = run_drv(t, [m32], ["kdf7z", tier, "10", "00" * 16, "6100"])
            t.record(got == [kdf7z(bytes(16), b"a\0", 10).hex()], "i586 tier %s 7z kdf" % tier)

def run_windows(t):
    """MinGW builds with the Windows exe's code generation flags, run under wine."""
    if not shutil.which("wine"):
        return
    for cc, flags, name in (("i686-w64-mingw32-gcc", ["-march=i586", "-mtune=generic", "-mincoming-stack-boundary=2"],
                             "crypto_test_w32.exe"),
                            ("x86_64-w64-mingw32-gcc", ["-march=x86-64", "-mtune=generic"], "crypto_test_w64.exe")):
        if shutil.which(cc):
            exe = standalone(t, [cc], flags, name)
            selftest_rec(t, ["wine", exe, "selftest", "quick"], "%s selftest under wine" % name,
                         timeout=300, env=dict(os.environ, WINEDEBUG="-all"))

def run_arm64(t, files, data, aes, r3):
    """AArch64 build under qemu (SHA1/SHA2/AES/PMULL/CRC32 emulated by -cpu max)."""
    cc, qemu = shutil.which("aarch64-linux-gnu-gcc"), shutil.which("qemu-aarch64")
    if not (cc and qemu and os.path.isdir("/usr/aarch64-linux-gnu")):
        return
    exe = standalone(t, [cc], [], "crypto_test_arm64")
    env = dict(os.environ)
    env.setdefault("QEMU_LD_PREFIX", "/usr/aarch64-linux-gnu")
    os.environ.setdefault("QEMU_LD_PREFIX", "/usr/aarch64-linux-gnu")
    arm = [qemu, "-cpu", "max", exe]
    selftest_rec(t, arm + ["selftest", "quick"], "arm64 selftest (qemu -cpu max)", env=env)
    info = run_drv(t, arm, ["info"])
    t.record("crc32=PMULL+CRC32" in info and "crc64=PMULL" in info and "sha=ARMv8" in info,
             "arm64 kernels: " + " ".join(info[-6:]))
    check_all(t, arm, ["-1"], "arm64", files, data, aes, random.Random(64), light=True)
    check_rar3(t, arm, ["-1"], "arm64", r3)

def run(t):
    import threading
    drv = [t.build_driver("tests/drivers/crypto_test.c")]
    rnd = random.Random(20261101)
    files = make_files(t, rnd)
    data = [open(f, "rb").read() for f in files]
    aes = AesRef(t)
    r3 = rar3_refs()

    # the other targets run next to the native checks (mostly waiting on subprocesses)
    def guarded(fn, *a):
        try:
            fn(*a)
        except Exception as e:
            t.record(False, "%s exception" % fn.__name__, repr(e)[-500:])
    threads = [threading.Thread(target=guarded, args=(run_i586, t, files, data)),
               threading.Thread(target=guarded, args=(run_windows, t)),
               threading.Thread(target=guarded, args=(run_arm64, t, files, data, aes, r3))]
    for th in threads:
        th.start()

    selftest_rec(t, drv + ["selftest"], "selftest (kernels vs portable, forced tiers)")
    info = run_drv(t, drv, ["info"])
    tiers = ["-2"] + " ".join(info).split("tiers=")[1].split("crc32=")[0].split()
    t.record(True, "kernels: " + " ".join(info[-5:]))
    check_all(t, drv, tiers, "x86", files, data, aes, rnd)
    check_rar3(t, drv, ["-2", tiers[-1]], "x86", r3)
    check_rar3_vs_rarfile(t)
    check_xz_crc64(t, drv, files)
    check_zipcrypto(t, drv, rnd)
    for args in (["kdf7z", "-1", "25", "-", "-"], ["kdfrar5", "-1", "25", "00" * 16, "-"]):
        r = subprocess.run(drv + args, capture_output=True, timeout=60)
        t.record(r.returncode == 1 and r.stdout.split() == [b"error", b"15"], "%s rejects 2^25" % args[0])
    for th in threads:
        th.join()
