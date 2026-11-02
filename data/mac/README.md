# 고깃ZIP for macOS: bundle data

Everything here is generated and committed, so a Mac needs only the Xcode command line
tools to build (`make mac`, see [docs/BUILD-mac.md](../../docs/BUILD-mac.md)).

| file | made by | what |
| --- | --- | --- |
| `Info.plist` | `tools/gen_mac_data.py` | bundle Info.plist; `@VERSION@` is replaced by `GZ_APP_VERSION` at build time. Document types for the archive extensions the readers open, imported UTI declarations for the types macOS does not know, Finder services |
| `en.lproj/InfoPlist.strings` | `tools/gen_mac_data.py` | English names (makes "en" a localization of the bundle) |
| `ko.lproj/InfoPlist.strings` | `tools/gen_mac_data.py` | 고깃ZIP, Korean document type names |
| `ko.lproj/ServicesMenu.strings` | `tools/gen_mac_data.py` | 고깃ZIP으로 압축 · 여기에 풀기 · 폴더를 만들어 풀기 |
| `AppIcon.icns` | `tools/make_icns.py` | app icon, PNG elements 32 .. 1024 px |
| `ArchiveIcon.icns` | `tools/make_icns.py` | icon of archive documents |

```sh
python3 tools/gen_mac_data.py      # after adding a reader: also lists unclaimed extensions
python3 tools/make_icns.py         # after changing the artwork (Pillow)
```

The `.strings` files are XML property lists rather than the `"key" = "value";` text form:
CFBundle reads both, and the XML form is plain UTF-8 that `plistlib` can check.
