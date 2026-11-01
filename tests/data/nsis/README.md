NSIS test fixtures
==================

Nothing is committed here: tests/cases/fmt_nsis.py builds its installers with
makensis (apt package `nsis`, NSIS 3.x) at test time and synthesises NSIS 2
installers from them.

When the network is available the module also downloads these real NSIS 2
installers (they are only parsed and unpacked, never executed). They are cached
in `<work>/../nsis_dl/`, verified by SHA-256 and skipped cleanly when offline:

| file                | origin                                                                                   | SHA-256 |
|---------------------|------------------------------------------------------------------------------------------|---------|
| 7z920.exe           | https://www.7-zip.org/a/7z920.exe (7-Zip 9.20 setup, NSIS 2, solid LZMA)                  | 1e2f2a8fb52d3972b9b65b8ad1bebb66965c47a2994f89b3d652c31e6f6e4c3c |
| nsis-2.46-setup.exe | https://downloads.sourceforge.net/project/nsis/NSIS%202/2.46/nsis-2.46-setup.exe          | 69c2ae5c9f2ee45b0626905faffaa86d4e2fc0d3e8c118c8bc6899df68467b32 |
| nsis20.exe          | https://downloads.sourceforge.net/project/nsis/NSIS%202/2.0/nsis20.exe (NSIS 2.00 layout) | d9e5e3094641b350b2ed9f8bb7097404b094c4e92ed77b47775e410ee1487ce3 |
