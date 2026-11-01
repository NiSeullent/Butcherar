# ISO 9660 / UDF test data

No binary fixtures are committed: every image is built at test time by
`tests/cases/fmt_iso.py`.

* Real tools: genisoimage (Rock Ridge, Joliet, levels 1-4, El Torito, `-hide`,
  `-hidden`, `-udf` bridge), xorriso (`-as mkisofs`, multiple boot entries),
  mkudffs (empty UDF volumes of every media type it supports: type 1, sparable,
  VAT 1.50 / 2.01 / 2.50, 512 / 4096-byte blocks), pycdlib (UDF 2.60 bridge, optional).
* `isogen.py` - a minimal ISO 9660 writer for structures the tools do not produce:
  multi-extent files with small, out-of-order extents, interleaved files,
  extended attribute records, associated files, Rock Ridge continuation areas
  (also looping ones), hand-written El Torito catalogs and directory loops.
* `udfgen.py` - a minimal UDF writer (mkudffs only formats empty volumes and loop
  mounts are unavailable in CI): type 1, sparable (with remapped packets),
  virtual (VAT 1.50 and 2.00) and metadata (2.50+, split metadata file, broken
  main copy -> mirror) partitions; FE / EFE; short, long, extended and embedded
  allocation descriptors; allocation extent chains; ICB strategy 4096; sparse and
  > 4 GiB files; 8 / 16-bit CS0 names; hidden / deleted FIDs; symlinks; reserve
  VDS and end-anchor-only volumes; hostile loops (directory, allocation extent and
  indirect entry chains, references outside every partition).

7-Zip 23.01 reads the generated type 1 and metadata-partition volumes (compared in
the tests, which keep the metadata mirror before the main copy because 7-Zip flags
unread data after the last area it reads as a header error). It refuses volumes with
symlinks, allocation extent chains, indirect entries, split metadata files, VAT or
sparable partitions; those are checked against the generator's own contents.
