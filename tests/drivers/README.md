C drivers for codec-level tests. A case module builds one with
`t.build_driver("tests/drivers/<name>.c")`: it is linked against the host core
objects in build/host (run `make build/gzt` first, same HOST_CFLAGS).

win_dlgt.c and win_postclose.c are Windows programs instead: tests/cases/regress_windows_ui.py
builds them with MinGW (win_dlgt.c together with src/win/dlgt.c) and runs them under Wine.
