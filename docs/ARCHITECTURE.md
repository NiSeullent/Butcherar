# 고깃ZIP architecture and contributor rules

This document is the contract every part of the code base follows. Read it
before adding a codec, an archive format, a writer or a front end.

## Layout

```
src/core/    model + helpers shared by everything (no OS calls)
  base.h       integer types, gzch (UTF-16 unit), rd16/rd32/rd64 (+ *be), error codes, alloc hooks
  stream.h/c   gz_src (random access input), views (sub/mem/concat), gz_stream_io,
               gz_range_reader, gz_pipe, memory/peek sinks, gz_out
  arc.h/c      gz_archive / gz_entry / gz_folder, format registry, probing, name
               decoding (code pages, UTF-8/16, Hangul NFC), folder tree, nested archives,
               gz_ctx (per-thread state), helpers for stored data
  str.c        UTF-8/UTF-16 conversion, Hangul composition, time conversion, gz_wcs*
  gz_write.h   archive creation API (gz_wopts, gz_witem, gz_sink, writer registry)
  write.c      writer dispatch
  version.h    GZ_APP_VERSION and GZ_VER_MAJOR/MINOR/PATCH: the one place of the program
               version (front ends, res/app.rc, Makefile packages, docs checked by tests)
  cpu.c/h      CPUID / XGETBV / AArch64 HWCAP detection and kernel dispatch
  crc32.c/h    CRC-32 (slice-by-8, PCLMULQDQ, AVX, VPCLMULQDQ)
  crypto.c/h   ZipCrypto, SHA-1, HMAC, PBKDF2-SHA1, AES-CTR (T-table, AES-NI)
src/codec/   compression codecs (decoders and encoders), one module per family
src/fmt/     archive formats (readers) and writers, one file per format
src/posix/   Linux/macOS platform hooks (memory, iconv code pages, file sources)
src/win/     Windows front end (no C runtime, Windows 2000+)
src/app/     portable engine (extraction/compression jobs) + command line tool
src/gtk/     Linux GTK 3 front end
src/mac/     macOS Cocoa front end
tests/       gzt.c test driver, run_tests.py, cases/*.py, lib/gztest.py
tools/       gen_registry.sh, gen_assets.py, gen_linux_data.py, gen_mac_data.py, make_icns.py,
             gen_docs.py (format tables of README / web site / release notes), linux/ (packages),
             web_screens.py (Windows screenshots of the web site under Wine)
data/        Linux launcher, MIME, icons, metainfo; macOS Info.plist, icons, localizations
web/         official web site (GitHub Pages)
.github/     CI and release workflow (build.yml), site deployment (pages.yml), release notes
```

Include directories: `-Isrc/core -Isrc/codec -Isrc/fmt` (and `src/app`,
`src/posix` for front ends). Include headers by bare name: `#include "arc.h"`.

## Portability rules (core, codec, fmt)

* C11 (`-std=gnu11`), GCC and clang. Must compile warning-free with
  `-Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers` for:
  i686 MinGW (`-march=i586`), x86-64 MinGW, x86-64/AArch64 Linux, x86-64/arm64 macOS.
* **No libc** in core/codec/fmt: only `<stddef.h>`, `<stdint.h>`, compiler
  intrinsics headers. Use `__builtin_memcpy/memset/memcmp/memmove`, `gz_alloc`
  (zeroed), `gz_realloc`, `gz_free`, `gz_alloc_big/gz_free_big` (page-granular, for
  dictionaries and windows > 1 MiB). No `malloc`, `printf`, `qsort`, `strlen`...
  (write tiny local helpers instead).
* No OS calls, no threads, no globals that change after init (formats and codecs
  run concurrently on several threads; per-thread state lives in `gz_ctx` or is
  allocated per call). Read-only tables built once in an `*_init()` called from
  start-up are fine (see `gz_crc32_init`), or use `static const` tables.
* Little-endian only. Use `rd16/rd32/rd64` and `rd16be/...` for unaligned access,
  never pointer casts.
* Stack: at most ~16 KiB per function. Worker threads have 512 KiB stacks on
  Windows. Put big state on the heap.
* 32-bit safety: sizes from files are `u64`; check before casting to `size_t`/`u32`.
  Never allocate a size taken from a header without a sane cap (return `GZ_E_LIMIT`).
* SIMD: the binary must run on a Pentium (i586) and on any x86-64 / ARMv8-A.
  Faster kernels are compiled with `__attribute__((target("...")))` (works in GCC
  and clang; do not use `#pragma GCC target`) and chosen in `gz_dispatch_init`
  from `g_cpu.features` / `g_cpu.active` tier. AVX/AVX2 only when `CPUF_AVX` is set
  (it already includes the OS YMM check). Guard x86 code with
  `#if defined(__i386__) || defined(__x86_64__)` and AArch64 code with
  `#if defined(__aarch64__)`; provide a portable C path for every kernel.
* Hostile input: every length, offset, count, index and table entry read from
  a file is checked. No infinite loops on corrupt data (each loop must make
  progress or be bounded). Decompression bombs: decoders stop at the declared
  output size when one exists. Recursion depth is bounded. Run your code under
  `-fsanitize=address,undefined` with corrupted/truncated inputs.

## Errors

Return `GZ_OK` or a `GZ_E_*` code (base.h). Typical mapping: bad structure
`GZ_E_FORMAT`, bad compressed data `GZ_E_DATA`, checksum `GZ_E_CRC`,
unsupported feature/method `GZ_E_METHOD`, wrong password `GZ_E_PASSWORD`,
HMAC mismatch `GZ_E_AUTH`, short input `GZ_E_TRUNC`, absurd sizes `GZ_E_LIMIT`,
missing volume `GZ_E_VOLUME`. Propagate `GZ_E_CANCEL` and `GZ_E_SKIP` coming from
callbacks unchanged.

## Codecs (src/codec)

A codec module `foo.c` + `foo.h` exposes a streaming decoder:

```c
typedef struct gz_foo_dec gz_foo_dec;            /* opaque, reusable */
gz_foo_dec *gz_foo_dec_new(void);
void gz_foo_dec_free(gz_foo_dec *d);
/* Pull compressed bytes with io->read, push output with io->write.
 * out_size: exact size when known, else GZ_SIZE_UNKNOWN (stream must end itself).
 * Stops after out_size bytes even if input remains. Returns GZ_OK / GZ_E_*.
 * If the sink returns an error (GZ_E_SKIP, GZ_E_CANCEL...) return it unchanged. */
int gz_foo_decode(gz_foo_dec *d, const gz_stream_io *io, u64 out_size /*, codec params */);
```

* Input: `io->read(io->ctx, buf, cap, &got)`; `got == 0` is end of input. Read in
  large chunks (64-256 KiB) into an internal buffer. A decoder may read past the
  end of its stream only within what the container bounds (containers give a
  bounded reader); if the container needs to know how much was consumed, report
  it (e.g. an `*in_used` out parameter).
* Output: push in chunks of up to ~1 MiB from your window buffer.
* `gz_stream_io` has ONE `ctx` for both callbacks; use `gz_pipe`
  (`{ gz_range_reader, sink, user }`) to combine a bounded source reader with a sink.
* Decoders are reused across entries: `*_decode` resets state each call. Cache a
  decoder per thread with `gz_ctx_slot(c, GZ_SLOT_FOO, create, destroy)`.
* Filters (BCJ, Delta, ...) are push-style transforms: `write` processes bytes and
  forwards to the next `write`, keeping a small carry buffer.
* Encoders mirror decoders: `gz_foo_encode(enc, const gz_stream_io *io, params)`
  pulls raw input and pushes compressed output.
* Unit-test against reference tools (zlib, xz, bzip2, zstd, 7z...) from
  `tests/cases/codec_foo.py` through the gzt driver (add a gzt sub-command only if
  you must; prefer testing through a format).

## Formats (src/fmt)

One file per format, registered by a marker line (picked up by
`tools/gen_registry.sh`, no shared table to edit):

```c
GZ_FORMAT(gz_fmt_foo)
const gz_format gz_fmt_foo = {
    "FOO", "foo bar",          /* display name, extensions                */
    0,                         /* GZ_FMT_CONTAINER / GZ_FMT_WEAK          */
    foo_probe, foo_open, foo_close, foo_extract, foo_extract_solid,
    foo_check_password, foo_method, foo_view, 0 /* impl */
};
```

* `probe(s, head, n)`: confidence 0..100 from the first <= 64 KiB (`head`) plus
  optional extra reads through `s`. Exact magic at offset 0: 90-95. Magic deeper in
  the file: 60-85. Heuristic only: 20-50. The highest score is opened first; if
  `open` fails the next one is tried. `GZ_FMT_WEAK` formats (PE resources, ELF,
  MBR) are tried only when every specific format failed.
* `open(a, s, o, c)`: parse the directory, call `gz_arc_add_named(a, raw, len,
  GZ_NE_*, &e)` for each entry and fill `usize`, `csize`, `mtime` (+`mtime_kind`,
  prefer FILETIME via `gz_unix_to_filetime`), `attr`, `unix_mode`, `is_dir`,
  `is_link` (+ `link_off/link_len` when the target is in the header),
  `crc` + `has_crc`, `enc`, and your private `off`/`aux`/`aux32`/`method`/`flags`.
  Names stay raw: `gz_arc_build_tree` decodes them later (code page detection,
  separators `/` and `\`, `..` removal, Hangul NFC). Store format-wide state in
  `a->priv` (freed in `close`). Set `a->win_names = 1` if legacy names come from
  Windows tools. Set `a->solid = 1` when entries can only be extracted in one
  sequential pass. Use `gz_arc_set_type(a, "7z")` for a more specific type name.
  Do not keep the `gz_src *s` pointer: extraction gets its own source per thread.
  Header encryption: ask with `o->ask_password` (retry flag on a wrong one), keep
  the working password in `a->password` (gz_wcsdup).
  Volumes: build sibling names from `o->file_name`, open with `o->open_volume`,
  keep them in `a->vols/a->nvols` (freed by the core).
  Long listings: call `c->progress(c->progress_user, done, total)` now and then,
  and stop with `GZ_E_CANCEL` when `gz_cancelled(c)`.
* `extract(a, s, idx, out, c)`: `out->open(out, idx)` (may return `GZ_E_SKIP` or an
  error: return it without writing), then `out->write` chunks, then
  `out->close(out, idx, status)` exactly once, and return the status. Verify
  CRCs/sizes. Directories and links also go through open/close. Password:
  `c->password` (UTF-16, may be NULL) - convert to the bytes the format needs
  (UTF-16LE for 7z/RAR3, UTF-8 for RAR5, try ANSI then UTF-8 for ZIP-like
  formats). Wrong password: `GZ_E_PASSWORD` before `out->open` when the format can
  tell (check value), otherwise as the close status.
* `extract_solid(a, s, sel, out, c)`: one pass extracting entries with `sel[i]`;
  skipped entries are decoded but not opened.
* `check_password`: `GZ_OK` if `c->password` opens entry idx (cheap check), else
  `GZ_E_PASSWORD`. NULL if the format has no encryption.
* `method(a, e, buf, cap)`: ASCII method text, e.g. `"LZMA2:24 BCJ"`, `"Store"`.
* `view(a, s, idx)`: random-access `gz_src` of an entry's data when it is stored
  contiguously or can be mapped (partitions, disk images, stored files), else NULL.
  Disk images and partition maps set `GZ_FMT_CONTAINER`: if they hold exactly one
  non-directory entry, the core opens the file system inside automatically
  (`gz_arc_open` returns the inner archive, type shown as "NTFS (VHD)").
* Compressed single streams (.gz .bz2 .xz .zst ...): implement a
  `gz_stream_codec` and use `GZ_STREAM_FORMAT(...)` (streamfmt.h); tarballs inside
  are handled for you.
* Helpers: `gz_src_read_exact`, `gz_src_sub`, `gz_range_reader`/`gz_pipe`,
  `gz_copy_range`, `gz_extract_stored`, `gz_ctx_buffer` (per-thread 256 KiB+ buffer),
  `gz_ctx_inflater` (Deflate), `gz_ctx_slot`.

## Writers (src/fmt/*_write.c)

```c
GZ_WRITER(gz_wr_foo)
const gz_writer gz_wr_foo = { GZ_WF_FOO, "FOO", "foo", methods_mask, enc_mask, foo_write };
```

`write(o, items, n, out, c)`: items are already enumerated (directories before
their contents, archive-relative `/` names). Open each file with
`o->open_item`, read until `got == 0`, close with `o->close_item`. A failing
item goes to `o->on_error` (skip on `GZ_OK`, abort otherwise). Report progress
with `o->progress`. Append output with `gz_sink_write(out, p, n)`; patch headers
with `gz_sink_patch` (may be unavailable: `out->write_at == NULL`, then write
streaming variants, e.g. ZIP data descriptors). Honour `o->cancel`.

## Tests

* `make test` builds `build/gzt` (native driver: `gzt x|l|c ...`, see tests/gzt.c)
  and runs every `tests/cases/*.py` module (`def run(t)`, helpers in
  tests/lib/gztest.py: `check_extract`, `check_vs_7z`, `check_hostile`,
  `check_roundtrip`, `listing`, `need`, `skip`).
* Fixtures are generated at test time with the reference tools (7z, xz, zstd,
  xorriso, mksquashfs, makensis, ...). Small binary fixtures that cannot be
  generated go to `tests/data/<format>/` (keep them small, document their origin).
* Every format adds hostile-input checks (truncated, bit-flipped, huge counts).
* Run `make test HOST_CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"`
  before finishing.
* A new reader or writer changes the format tables of README.md, web/index.html and
  .github/release-notes.md: run `python3 tools/gen_docs.py` (and describe the format in
  its META table). `tests/cases/release_meta.py` fails while they are stale, while the
  version differs between src/core/version.h and the documents, or when the workflow
  calls a make target that does not exist.

## Releases

* The version lives in `src/core/version.h` only; `python3 tools/gen_docs.py` copies it
  into the documents. The Linux metainfo gets a new `<release>` entry by hand.
* `.github/workflows/build.yml` builds Windows (x86, x64), Linux packages (`make dist-linux`,
  `make deb` on x86_64 and aarch64, glibc 2.35 baseline), the macOS disk image, and runs the
  tests on Linux x86_64 / ARM64 and macOS. A pushed `v*` tag or a release published in
  the UI gets every package, `SHA256SUMS.txt` and `.github/release-notes.md`;
  *Run workflow* with a tag rebuilds that tag and replaces its assets.
