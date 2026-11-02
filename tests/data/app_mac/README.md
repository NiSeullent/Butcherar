# tests/data/app_mac

Written for this project (no third-party files).

`gnustep/` holds the include shims for the optional Objective-C syntax check of
`src/mac/*.m` on Linux (tests/cases/app_mac.py), run when GNUstep's AppKit headers
(`apt install libgnustep-gui-dev`), its GCC Objective-C runtime headers and clang are
present:

* `appkit_compat.h` — declarations (only) of the macOS 10.12 .. 11 AppKit API that
  GNUstep 0.30 lacks, with the signatures of Apple's SDK; force-included before each file
* `dispatch/dispatch.h`, `CoreServices/CoreServices.h`, `objc/blocks_runtime.h` — stubs
  of the system headers the sources include

The GCC runtime headers (`objc/*.h`) are copied into the test's work folder at run time
and patched for clang's ARC there (they are not committed here).
