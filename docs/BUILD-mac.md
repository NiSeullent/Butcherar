# Building 고깃ZIP for macOS

The macOS front end (`src/mac`, Objective-C with ARC) is a Cocoa app on top of the
portable engine (`src/app/engine.c`), the POSIX platform layer (`src/posix`) and the
core (`src/core`, `src/codec`, `src/fmt`). One universal binary runs on

| CPU            | minimum macOS                      |
|----------------|------------------------------------|
| Intel (x86_64) | 10.13 High Sierra                  |
| Apple silicon  | 11 Big Sur (set by the toolchain)  |

## Requirements

* macOS with the Xcode command line tools (`xcode-select --install`) or Xcode.
  A macOS 11 SDK or newer is needed (Xcode 12.2+): the arm64 slice and the macOS 11
  look (`NSWindowToolbarStyleExpanded`, `NSTableViewStyleFullWidth`, used behind
  `@available`) need it. CI builds with the default Xcode of the `macos-14` runner.
* GNU make (the one shipped with the command line tools is fine).
* Nothing else: the icons (`data/mac/*.icns`) and the bundle data (`data/mac/Info.plist`,
  `*.lproj`) are committed, the icon atlas `res/assets.bin` is decoded at run time.

## Build

```sh
make mac            # build/mac/GogitZIP.app (universal, signed ad hoc) + build/gogitzip
make dmg            # build/GogitZIP-mac.dmg (the app + an /Applications link, HFS+, zlib)
make test           # core tests (+ checks of the built bundle, tests/cases/app_mac.py)
open build/mac/GogitZIP.app
```

Useful variables:

| variable   | default                              | meaning                                         |
|------------|--------------------------------------|-------------------------------------------------|
| `MACARCHS` | `-arch x86_64 -arch arm64`           | e.g. `-arch arm64` for a quick native build      |
| `MACMIN`   | `-mmacosx-version-min=10.13`         | deployment target of the x86_64 slice           |
| `MACSIGN`  | `-` (ad hoc)                         | signing identity, e.g. `"Developer ID Application: …"` |
| `MACOPT`   | `-O2`                                | optimisation of the core (the UI uses `-Os`)    |

Objects go to `build/mac/obj` (never `build/host`, which test drivers link wholesale).
The Objective-C files are compiled **without** `-Isrc/app`: `src/app/strings.h` has the
C library's header name and only chains to the system `<strings.h>` when it is found on
the include path (as in the C builds); the mac sources include it by relative path.

## Bundle layout

```
GogitZIP.app/Contents/
  Info.plist                 data/mac/Info.plist with @VERSION@ = GZ_APP_VERSION (src/app/engine.h)
  PkgInfo
  MacOS/GogitZIP             the app (universal)
  Helpers/gogitzip           the command line tool (src/app/cli.c, universal)
  Resources/AppIcon.icns     app icon        (tools/make_icns.py)
  Resources/ArchiveIcon.icns document icon   (tools/make_icns.py)
  Resources/assets.bin       toolbar / dialog icon atlas (res/assets.bin, tools/gen_assets.py)
  Resources/en.lproj, ko.lproj   InfoPlist.strings (display name, document type names),
                                 ServicesMenu.strings (Finder service titles)
```

The command line tool lives in `Helpers/` because the default macOS file systems ignore
case: `MacOS/gogitzip` would be the same file as `MacOS/GogitZIP`.

## Regenerating the data (on Linux or macOS)

```sh
python3 tools/gen_mac_data.py          # data/mac/Info.plist + *.lproj/*.strings
python3 tools/gen_mac_data.py --check  # are they up to date? (run by tests/cases/app_mac.py)
python3 tools/make_icns.py             # data/mac/AppIcon.icns, ArchiveIcon.icns (needs Pillow)
python3 tools/make_icns.py --check     # structure / PNG sizes of the committed .icns files
```

`gen_mac_data.py` holds the table of document types (extension → UTI, English and Korean
names, handler rank). Archives get `LSHandlerRank` Default, disk images and installers
Alternate (GogitZIP is offered in "Open With" but never takes them over from
DiskImageMounter or Installer). UTIs macOS already declares are referenced; the others are
declared as imported types. When a new reader lands, the check prints a note listing the
extensions that have no document type yet: add them to `TYPES` (or `EXCLUDED`) and
regenerate. The `.strings` files are XML property lists (CFBundle reads every plist
format), which keeps them UTF-8 and checkable with `plistlib`.

The icons are rendered from the same vector code as the Windows / Linux icons
(`tools/gen_assets.py`): PNG elements `ic11` (32), `ic12` (64), `ic07` (128), `ic08` (256),
`ic09` (512) and `ic10` (1024).

## Signing, notarisation

`make mac` signs ad hoc, inside out (the helper first, then the bundle) and verifies the
signature. Ad hoc signed apps run on the machine that built them; downloaded copies are
stopped by Gatekeeper (Control-click → Open once, or
`xattr -dr com.apple.quarantine /Applications/GogitZIP.app`).

For distribution sign with a Developer ID, the hardened runtime and a timestamp, then
notarise the disk image:

```sh
make mac MACSIGN="Developer ID Application: NAME (TEAMID)"
codesign --force --options runtime --timestamp --sign "Developer ID Application: NAME (TEAMID)" \
    build/mac/GogitZIP.app/Contents/Helpers/gogitzip build/mac/GogitZIP.app
make dmg
xcrun notarytool submit build/GogitZIP-mac.dmg --keychain-profile NOTARY --wait
xcrun stapler staple build/GogitZIP-mac.dmg
```

The app needs no entitlements (no sandbox: it reads and writes wherever the user points
it, like Archive Utility).

## Using it

* **Finder**: double-click archives (after "Open With → GogitZIP", or *Settings → Make
  GogitZIP the default*), drop archives on the Dock icon to open them, other files to
  compress them.
* **Services** (Finder context menu → Quick Actions / Services): *Compress with GogitZIP*
  (고깃ZIP으로 압축), *Extract Here* (여기에 풀기), *Extract to Folder* (폴더를 만들어 풀기).
  They are enabled by default (`NSRequiredContext`); macOS picks them up after the app's
  first launch (`NSUpdateDynamicServices`), or after `/System/Library/CoreServices/pbs -update`.
* **Main window**: toolbar (Open, Extract, New Archive, Test, Info, Code Page, Settings),
  folder tree, file list (sortable columns, type-to-select, Return / Cmd-Down opens,
  Delete / Cmd-Up goes up), path control including the levels of nested archives,
  drag entries out to Finder (file promises), drop files in.
* **Command line** (also for automation; the bundle's binary takes the options, or
  `open -a GogitZIP --args …`):

  ```sh
  A=/Applications/GogitZIP.app/Contents/MacOS/GogitZIP
  $A --extract-to ~/out a.zip b.7z      # into ~/out
  $A --extract-here a.zip               # next to the archive
  $A --extract-smart a.zip              # into a folder named after it when needed
  $A --extract a.zip                    # ask with the extract window
  $A --test a.zip
  $A --compress dir file --output x.7z --level 7 --yes
  ```
  `--yes` answers every question (overwrite) and reports problems on stderr; exit codes
  are 0 ok, 1 warnings, 2 errors, 7 usage, 255 canceled. The plain command line tool is
  `GogitZIP.app/Contents/Helpers/gogitzip` (see `src/app/cli.c`).
* **Language**: Korean when the system prefers Korean, English otherwise; *Settings*
  overrides it (applies at the next start), so does `--lang ko|en`.
* **Settings** live in `~/Library/Preferences/io.github.niseullent.gogitzip.plist`;
  temporary files (viewed entries, drag and drop) in `$TMPDIR/GogitZIP-<pid>`, removed at
  exit and swept at the next start if the app crashed.
* Extracted files inherit the archive's quarantine mark (`com.apple.quarantine`), as with
  Archive Utility.

## Source map

| file                | contents                                                              |
|---------------------|-----------------------------------------------------------------------|
| `src/mac/app.h`     | shared declarations                                                   |
| `src/mac/main.m`    | `main`, menus, application delegate (open documents, Services), command line modes, batch extraction |
| `src/mac/mainwnd.m` | main window controller: toolbar, path control, tree, list, status bar, welcome view, drag and drop |
| `src/mac/run.m`     | jobs on worker threads, progress window, question marshalling         |
| `src/mac/dialogs.m` | extract / create / info / result / question dialogs, about panel      |
| `src/mac/prefs.m`   | settings (NSUserDefaults), recent archives, preferences window, default app |
| `src/mac/icons.m`   | icon atlas → NSImage (all sizes as representations, template variants) |
| `src/mac/util.m`    | UTF-16 ↔ NSString / file system paths, formatting, temp folders, file types |
| `src/mac/mstrings.h`| strings only the Mac UI needs (the rest: `src/app/strings.h`)         |

Threading: engine callbacks arrive on worker threads. Progress is copied under a mutex
and shown by a 100 ms timer in the common run loop modes; questions (`gz_ask`) are
dispatched to the main queue where a sheet answers through a completion block while the
worker waits on a semaphore; the job's end is dispatched to the main queue.

## Without a Mac

Nothing in `src/mac` can be compiled on Linux, but `tests/cases/app_mac.py` checks what
can be checked there: the generated data is current and valid (`plistlib`), the `.icns`
structure, the strings tables (both languages, same placeholders), selectors named in
Info.plist exist in the sources, and — when GNUstep's headers are installed
(`apt install libgnustep-gui-dev`) — an Objective-C syntax and ARC check of every
`src/mac/*.m` against GNUstep plus a small shim declaring the newer AppKit API
(`tests/data/app_mac/gnustep/`). GNUstep is not AppKit: that check catches typos and
type errors, not wrong AppKit usage; the macOS CI job (`.github/workflows/build.yml`,
job `macos`) is the real build.
