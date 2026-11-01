# codec_lzma fixtures

All files in this directory are copied unchanged from the XZ Utils 5.8.1 source
tarball (`tests/files/`, downloaded from
https://deb.debian.org/debian/pool/main/x/xz-utils/xz-utils_5.8.1.orig.tar.xz).
They are distributed under the BSD Zero Clause License (0BSD); most were made by
hand with a hex editor to hit specific decoder corner cases. See the XZ Utils
`tests/files/README` for the full descriptions; the short version:

| file | what it exercises |
|------|-------------------|
| good-1-lzma2-1.xz | two LZMA2 chunks, the second sets new properties |
| good-1-lzma2-2.xz | two chunks, the second resets the state without new properties |
| good-1-lzma2-3.xz | uncompressed chunk (dictionary reset) then LZMA with new properties |
| good-1-lzma2-4.xz | LZMA, uncompressed with dictionary reset, LZMA with new properties |
| good-1-lzma2-5.xz | empty LZMA2 stream (only the end byte) |
| good-2-lzma2.xz | two blocks |
| bad-1-lzma2-1..11.xz | first chunk without dictionary reset, references across a dictionary reset, invalid lc/lp, missing properties, reserved control byte 3, end marker inside LZMA2, truncations, missing end byte |
| good-*.lzma / bad-*.lzma | .lzma end conditions: known / unknown size with or without end marker, size too big / too small (literal, short rep, match crossing the end) |
| good-1-arm64-lzma2-1/2.xz | ARM64 filter, wrap-around and sign extension, non-zero start offset |
| good-1-3delta-lzma2.xz | three chained Delta filters |
| good-1-delta-lzma2.tiff.xz | Delta on a real image |
| good-1-empty-bcj-lzma2.xz | empty block with the PowerPC filter |
| good-1-check-crc64.xz, good-1-check-sha256.xz | plain LZMA2 blocks with CRC64 / SHA-256 checks |
| good-1-v0.lz, good-1-v1.lz, good-2-v1-v1.lz, good-1-v1-trailing-1.lz | lzip members: LZMA with end marker followed by a trailer (exact end of stream) |

tests/cases/codec_lzma.py parses the .xz / .lz containers itself (minimal test-only
parsers) and feeds the raw LZMA / LZMA2 data and the filter chain to the codecs.
