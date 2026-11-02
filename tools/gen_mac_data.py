#!/usr/bin/env python3
"""
고깃ZIP macOS bundle data generator.

Writes (outputs are committed; run again after adding formats):

  data/mac/Info.plist                    bundle Info.plist template (@VERSION@ is filled by the
                                         Makefile): document types for the readable archive
                                         extensions, imported UTI declarations for the types macOS
                                         does not know, Finder services (NSServices)
  data/mac/en.lproj/InfoPlist.strings    English names (also makes "en" a bundle localization)
  data/mac/ko.lproj/InfoPlist.strings    Korean display name, document type and UTI names
  data/mac/ko.lproj/ServicesMenu.strings Korean titles of the Finder services

The .strings files are XML property lists (CFBundle reads every plist format), so they are
UTF-8 and checkable with plistlib. The document types come from the curated TYPES table
below; the readable extensions collected from the format modules (src/fmt/*.c, as
tools/gen_linux_data.py does) are only compared with it and differences reported (the app
still opens any file through "Open").

  python3 tools/gen_mac_data.py            regenerate
  python3 tools/gen_mac_data.py --check    exit 1 when a generated file is stale
"""
import os, sys, plistlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import gen_linux_data  # readable_exts(), DOCS

BUNDLE_ID = "io.github.niseullent.gogitzip"
OWN = BUNDLE_ID + "."           # prefix of the UTIs we declare for types macOS lacks

# UTIs declared by macOS itself (CoreTypes): used as they are, never redeclared
SYSTEM_UTIS = {
    "public.zip-archive", "public.tar-archive", "org.gnu.gnu-zip-archive", "org.gnu.gnu-zip-tar-archive",
    "public.bzip2-archive", "public.cpio-archive", "public.iso-image", "com.apple.disk-image-udif",
    "com.apple.xar-archive", "com.apple.installer-package-archive",
}

# document types: (English name, Korean name, LSHandlerRank, kind, [(extension, UTI)])
# UTI "@x" = our own identifier OWN + x. Third-party identifiers in common use (7-Zip, RAR,
# XZ) are imported under their usual names so other apps' declarations merge with ours.
# Rank: Default for archives; Alternate for disk images and installers (GogitZIP shows
# in "Open With" but never takes them from DiskImageMounter / Installer).
TYPES = [
    ("ZIP archive", "ZIP 압축 파일", "Default", "archive",
     [("zip", "public.zip-archive"), ("zipx", "@zipx-archive")]),
    ("7-Zip archive", "7-Zip 압축 파일", "Default", "archive", [("7z", "org.7-zip.7-zip-archive")]),
    ("RAR archive", "RAR 압축 파일", "Default", "archive",
     [("rar", "com.rarlab.rar-archive"), ("r00", "@rar-volume")]),
    ("ALZip archive", "알집 압축 파일", "Default", "archive", [("alz", "@alz-archive")]),
    ("EGG archive", "EGG 압축 파일", "Default", "archive", [("egg", "@egg-archive")]),
    ("TAR archive", "TAR 압축 파일", "Default", "archive", [("tar", "public.tar-archive")]),
    ("Gzip archive", "Gzip 압축 파일", "Default", "archive",
     [("gz", "org.gnu.gnu-zip-archive"), ("gzip", "@gzip-archive")]),
    ("Gzip-compressed TAR archive", "Gzip으로 압축한 TAR 압축 파일", "Default", "archive",
     [("tgz", "org.gnu.gnu-zip-tar-archive"), ("tpz", "@tar-gzip-archive")]),
    ("Bzip2 archive", "Bzip2 압축 파일", "Default", "archive",
     [("bz2", "public.bzip2-archive"), ("bzip2", "@bzip2-archive")]),
    ("Bzip2-compressed TAR archive", "Bzip2로 압축한 TAR 압축 파일", "Default", "archive",
     [("tbz2", "@tar-bzip2-archive"), ("tbz", "@tar-bzip2-archive")]),
    ("XZ archive", "XZ 압축 파일", "Default", "archive",
     [("xz", "org.tukaani.xz-archive"), ("txz", "@tar-xz-archive")]),
    ("LZMA archive", "LZMA 압축 파일", "Default", "archive",
     [("lzma", "org.tukaani.lzma-archive"), ("tlz", "@tar-lzma-archive"), ("lz", "@lzip-archive")]),
    ("Zstandard archive", "Zstandard 압축 파일", "Default", "archive",
     [("zst", "@zstd-archive"), ("zstd", "@zstd-archive"), ("tzst", "@tar-zstd-archive")]),
    ("LZ4 archive", "LZ4 압축 파일", "Default", "archive", [("lz4", "@lz4-archive"), ("tlz4", "@tar-lz4-archive")]),
    ("LZO archive", "LZO 압축 파일", "Default", "archive", [("lzo", "@lzo-archive"), ("tzo", "@tar-lzo-archive")]),
    ("Unix compress archive", "Unix compress 압축 파일", "Default", "archive",
     [("z", "@z-archive"), ("taz", "@tar-z-archive")]),
    ("Cabinet archive", "CAB 압축 파일", "Default", "archive", [("cab", "@cab-archive")]),
    ("ARJ archive", "ARJ 압축 파일", "Default", "archive", [("arj", "@arj-archive")]),
    ("LHA archive", "LHA 압축 파일", "Default", "archive", [("lzh", "@lha-archive"), ("lha", "@lha-archive")]),
    ("CPIO archive", "CPIO 압축 파일", "Default", "archive", [("cpio", "public.cpio-archive")]),
    ("XAR archive", "XAR 압축 파일", "Default", "archive", [("xar", "com.apple.xar-archive")]),
    ("Windows image", "Windows 이미지", "Default", "archive",
     [("wim", "@wim-image"), ("swm", "@wim-image"), ("esd", "@wim-image")]),
    ("Split archive", "분할 압축 파일", "Default", "archive", [("001", "@split-archive")]),
    ("Unix ar archive", "Unix ar 압축 파일", "Alternate", "archive", [("ar", "@ar-archive")]),
    ("RPM package", "RPM 패키지", "Alternate", "archive", [("rpm", "@rpm-package")]),
    ("Debian package", "Debian 패키지", "Alternate", "archive",
     [("deb", "@deb-package"), ("udeb", "@deb-package"), ("ddeb", "@deb-package"), ("ipk", "@ipk-package")]),
    ("Installer package", "설치 패키지", "Alternate", "archive", [("pkg", "com.apple.installer-package-archive")]),
    ("Windows Installer package", "Windows Installer 패키지", "Alternate", "archive",
     [("msi", "@msi-package"), ("msp", "@msi-package"), ("msm", "@msi-package"), ("mst", "@msi-package")]),
    ("NSIS installer", "NSIS 설치 파일", "Alternate", "archive", [("nsis", "@nsis-archive")]),
    ("Disc image", "디스크 이미지", "Alternate", "image", [("iso", "public.iso-image"), ("udf", "@udf-image")]),
    ("Apple disk image", "Apple 디스크 이미지", "Alternate", "image", [("dmg", "com.apple.disk-image-udif")]),
    ("Virtual disk image", "가상 디스크 이미지", "Alternate", "image",
     [("vhd", "@vhd-image"), ("vhdx", "@vhdx-image"), ("avhdx", "@vhdx-image"), ("vmdk", "@vmdk-image"),
      ("vdi", "@vdi-image"), ("qcow", "@qcow-image"), ("qcow2", "@qcow-image"), ("qcow2c", "@qcow-image")]),
    ("File system image", "파일 시스템 이미지", "Alternate", "image",
     [("squashfs", "@squashfs-image"), ("sqfs", "@squashfs-image"), ("sfs", "@squashfs-image"),
      ("squash", "@squashfs-image"), ("snap", "@snap-image"), ("cramfs", "@cramfs-image"), ("cram", "@cramfs-image"),
      ("ext2", "@ext-image"), ("ext3", "@ext-image"), ("ext4", "@ext-image"), ("exfat", "@exfat-image"),
      ("ntfs", "@ntfs-image"), ("hfs", "@hfs-image"), ("hfsx", "@hfs-image"), ("hfsplus", "@hfs-image"),
      ("apfs", "@apfs-image"), ("simg", "@android-sparse-image")]),
    ("Floppy disk image", "플로피 디스크 이미지", "Alternate", "image",
     [("vfd", "@floppy-image"), ("flp", "@floppy-image"), ("ima", "@floppy-image")]),
]

# readable, but documents / programs / generic names: never claimed (as tools/gen_linux_data.py)
EXCLUDED = set(gen_linux_data.DOCS) | {
    "dylib", "so", "o", "ko", "bundle", "macho", "elf", "efi", "sys", "drv", "ocx", "cpl", "scr", "mui", "ax", "acm",
    "tsp", "prx", "lib", "te", "axf", "mod", "xip", "pbzx", "mpkg", "smi", "z01", "ddeb", "ipa", "lzs",
    "38_", "bm_", "ch_", "cp_", "dl_", "dr_", "ex_", "fo_", "hl_", "in_", "ov_", "sy_", "tx_",
}

# Finder services: (default title, Korean title, message, file types: "all" or "archives")
SERVICES = [
    ("Compress with GogitZIP", "고깃ZIP으로 압축", "compressFiles", "all"),
    ("Extract Here", "여기에 풀기", "extractHere", "archives"),
    ("Extract to Folder", "폴더를 만들어 풀기", "extractSmart", "archives"),
]

KO_DISPLAY = "고깃ZIP"
COPYRIGHT_EN = "© 2026 Butcherar project. Free software under the MIT license."
COPYRIGHT_KO = "© 2026 Butcherar 프로젝트. MIT 라이선스로 배포되는 자유 소프트웨어."


def uti_of(u):
    return OWN + u[1:] if u.startswith("@") else u


def selected_types():
    """TYPES with the UTIs spelled out. The table is used as it is (not filtered by the readers
    present) so the generated files do not change when a format module lands in another branch."""
    return [(en, ko, rank, kind, [(e, uti_of(u)) for e, u in pairs]) for en, ko, rank, kind, pairs in TYPES]


def imported_types(types):
    """one declaration per UTI we do not get from macOS: its extensions, name, conformance"""
    decl = {}
    for en, ko, rank, kind, pairs in types:
        for ext, uti in pairs:
            if uti in SYSTEM_UTIS:
                continue
            d = decl.setdefault(uti, {"en": en, "ko": ko, "kind": kind, "exts": []})
            if ext not in d["exts"]:
                d["exts"].append(ext)
    out = []
    for uti, d in decl.items():
        conforms = ["public.data", "public.archive"] if d["kind"] == "archive" else ["public.data", "public.disk-image"]
        out.append({
            "UTTypeIdentifier": uti,
            "UTTypeDescription": d["en"],
            "UTTypeConformsTo": conforms,
            "UTTypeIconFile": "ArchiveIcon",
            "UTTypeTagSpecification": {"public.filename-extension": d["exts"]},
        })
    return out


def archive_utis(types):
    seen, r = set(), []
    for en, ko, rank, kind, pairs in types:
        for ext, uti in pairs:
            if uti not in seen:
                seen.add(uti)
                r.append(uti)
    return r


def info_plist(types):
    doc_types = []
    for en, ko, rank, kind, pairs in types:
        utis = []
        for ext, uti in pairs:
            if uti not in utis:
                utis.append(uti)
        doc_types.append({
            "CFBundleTypeName": en,
            "CFBundleTypeRole": "Viewer",
            "LSHandlerRank": rank,
            "CFBundleTypeIconFile": "ArchiveIcon",
            "LSItemContentTypes": utis,
        })
    arcs = ["public.archive", "public.disk-image"] + archive_utis(types)
    services = []
    for title, ko, msg, files in SERVICES:
        services.append({
            "NSMenuItem": {"default": title},
            "NSMessage": msg,
            "NSPortName": "GogitZIP",
            "NSRequiredContext": {},
            "NSSendFileTypes": ["public.item"] if files == "all" else arcs,
            "NSSendTypes": ["NSFilenamesPboardType", "public.file-url"],
        })
    return {
        "CFBundleDevelopmentRegion": "en",
        "CFBundleDisplayName": "GogitZIP",
        "CFBundleExecutable": "GogitZIP",
        "CFBundleIconFile": "AppIcon",
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleLocalizations": ["en", "ko"],
        "CFBundleName": "GogitZIP",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "@VERSION@",
        "CFBundleSignature": "????",
        "CFBundleVersion": "@VERSION@",
        "LSApplicationCategoryType": "public.app-category.utilities",
        "LSHasLocalizedDisplayName": True,
        "LSMinimumSystemVersion": "10.13",
        "LSMinimumSystemVersionByArchitecture": {"x86_64": "10.13", "arm64": "11.0"},
        "NSHighResolutionCapable": True,
        "NSHumanReadableCopyright": COPYRIGHT_EN,
        "NSPrincipalClass": "NSApplication",
        "NSSupportsAutomaticGraphicsSwitching": True,
        "CFBundleDocumentTypes": doc_types,
        "UTImportedTypeDeclarations": imported_types(types),
        "NSServices": services,
    }


def strings_en(types):
    return {"CFBundleDisplayName": "GogitZIP", "CFBundleName": "GogitZIP", "NSHumanReadableCopyright": COPYRIGHT_EN}


def strings_ko(types):
    d = {"CFBundleDisplayName": KO_DISPLAY, "CFBundleName": KO_DISPLAY, "NSHumanReadableCopyright": COPYRIGHT_KO}
    for en, ko, rank, kind, pairs in types:
        d[en] = ko                     # CFBundleTypeName and UTTypeDescription values are the keys
    return d


def services_ko():
    return {title: ko for title, ko, msg, files in SERVICES}


def dump(obj):
    return plistlib.dumps(obj, fmt=plistlib.FMT_XML, sort_keys=False)


def outputs():
    readable = gen_linux_data.readable_exts()
    types = selected_types()
    return {
        os.path.join("data", "mac", "Info.plist"): dump(info_plist(types)),
        os.path.join("data", "mac", "en.lproj", "InfoPlist.strings"): dump(strings_en(types)),
        os.path.join("data", "mac", "ko.lproj", "InfoPlist.strings"): dump(strings_ko(types)),
        os.path.join("data", "mac", "ko.lproj", "ServicesMenu.strings"): dump(services_ko()),
    }, readable


def unmapped(readable):
    """readable extensions Finder will not offer GogitZIP for, and claimed ones no reader opens"""
    claimed = {e for t in TYPES for e, u in t[4]}
    numeric = lambda e: e.strip("0123456789") == ""
    missing = sorted(e for e in readable - claimed - EXCLUDED if not numeric(e))
    unread = sorted(e for e in claimed - readable if not numeric(e))
    return missing, unread


def main():
    check = "--check" in sys.argv
    files, readable = outputs()
    stale = []
    for rel, data in files.items():
        p = os.path.join(ROOT, rel)
        old = open(p, "rb").read() if os.path.exists(p) else None
        if old != data:
            stale.append(rel)
            if not check:
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "wb") as f:
                    f.write(data)
    missing, unread = unmapped(readable)
    if missing:        # a new reader: still works, Finder just does not offer GogitZIP for it
        print("note: readable extensions without a document type (add them to TYPES or EXCLUDED):",
              " ".join(missing))
    if unread:         # a reader still to come (or removed): Finder offers GogitZIP for nothing
        print("note: document type extensions no reader opens yet:", " ".join(unread))
    if check:
        if stale:
            print("stale:", " ".join(stale))
        sys.exit(1 if stale else 0)
    print("wrote", ", ".join(files))


if __name__ == "__main__":
    main()
