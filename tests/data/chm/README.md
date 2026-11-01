# CHM fixtures

`chmcmd_small.chm` (30 KB) - built with `chmcmd` (Free Pascal 3.2.2 fp-utils,
`chmcmd --no-html-scan test.hhp`) from the project that
`tests/cases/fmt_chm.py: make_project(12, 1, big=600, nimg=2)` writes with
`write_project()`. LZXC version 2, 64 KiB window, reset every 2 frames.
The test regenerates the sources and compares the extracted pages byte for
byte, so it needs neither chmcmd nor 7-Zip.

Downloaded at test time (cached in `build/testdata`, skipped when offline):

* `https://www.7-zip.org/a/7z2301-x64.exe` - `7-zip.chm` inside it was made by
  Microsoft HTML Help Workshop (128 KiB window, reset every 4 frames).
* `https://www.cabextract.org.uk/libmspack/libmspack-0.11alpha.tar.gz` -
  libmspack's regression files (`test/test_files/chmd/*.chm`, the `.xor` one is
  stored inverted) are run as hostile inputs; `test/test_files/cabd/*.cab`
  are used by `fmt_cab.py` (Microsoft-made multi-cabinet set, MSZIP/LZX/Quantum
  folders, reserve fields, broken files).
