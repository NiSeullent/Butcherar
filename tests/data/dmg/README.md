# DMG / HFS test data

No binary fixtures are committed: every volume and disk image used by
`tests/cases/fmt_dmg_hfs.py` is generated at test time by the Python builder
in `tests/cases/_hfsbuild.py` (HFS+ / HFSX volumes, HFS wrapper, UDIF images
with every chunk type, XML and resource-fork partition lists), by
`mkfs.hfsplus` (hfsprogs, empty volumes) and by hfsutils (`hformat`, `hmkdir`,
`hcopy`: classic HFS volumes).

Real images made by Apple's `hdiutil` are downloaded at test time into the
work directory (`build/testwork/fmt_dmg_hfs/dl`, cached, SHA-256 checked) and
skipped when offline. They are only parsed, never executed:

| File | Origin | SHA-256 | Notes |
|------|--------|---------|-------|
| SDL-1.2.9.dmg (312 KB) | https://www.libsdl.org/release/SDL-1.2.9.dmg | cb0a6f390e39f33b22914cf282967ab8a370eaa8d11b9e64db9dea2ebff974e2 | APM layout (DDM, partition map, Apple_HFS, Apple_Free), zlib + ignore chunks, symlinks in a framework |
| SDL2-2.0.0.dmg (1.0 MB) | https://www.libsdl.org/release/SDL2-2.0.0.dmg | 9dca7ee5273947ca3276515e61f51b99687f763a8616fcb1ebbeef1de485dde7 | APM layout, zlib |
| SDL2-2.30.10.dmg (2.0 MB) | https://www.libsdl.org/release/SDL2-2.30.10.dmg | b946bdc9bd1288483052531285af445c15585201f084c7fa74a22d05b449d6ca | GPT layout (MBR, GPT header/table, Apple_HFS), zlib, zero and ignore chunks |
