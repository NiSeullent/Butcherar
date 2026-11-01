C drivers for codec-level tests. A case module builds one with
`t.build_driver("tests/drivers/<name>.c")`: it is linked against the host core
objects in build/host (run `make build/gzt` first, same HOST_CFLAGS).
