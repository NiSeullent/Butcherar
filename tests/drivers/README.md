C drivers for codec-level tests. A case module builds one with
`t.build_driver("tests/drivers/<name>.c")`: it is linked against the host core
objects in build/host (run `make build/gzt` first, same HOST_CFLAGS).

`gtk_dragsrc.c` (a GTK 3 drag source standing in for a file manager) and
`gtk_thread_shim.c` (an LD_PRELOAD shim that delays `gtk_main()` and reports GTK
calls made off the UI thread) are standalone helpers that
tests/cases/regress_gtk_mac.py compiles itself (gtk+-3.0, no core objects).
