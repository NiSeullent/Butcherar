# ALZ / EGG test data

No binary fixtures are committed for the ALZ and EGG readers; `tests/cases/fmt_alz_egg.py`
builds or fetches everything at test time:

* **Generated archives** – `tests/cases/_alzegg.py` writes ALZ and EGG archives from the
  format descriptions (test tooling only; 고깃ZIP does not create these formats):
  * ALZ: layout as read by unalz 0.65, The Unarchiver (XADALZipParser) and the ALZ reader
    in ESTsoft's unegg 0.5 (store, deflate, method 3 "obfuscated deflate", bzip2 in the
    headerless `DLZ\1` framing, ZipCrypto, `.alz/.a00/...` volumes, `ELZ\1` comments).
  * EGG: *EGG Format Specification 1.0* (ESTsoft, 2009-2016,
    `https://aldn.altools.co.kr/setup/EGG_Specification.zip`), cross-read with unegg 0.5
    (`https://aldn.altools.co.kr/setup/unegg.tar.bz`): store, deflate, bzip2, LZMA, AZO,
    multi-block files, solid archives, split volumes, ZipCrypto, AES-128/256, LEA-128/256.
  * AZO streams come from a Python encoder that mirrors `src/codec/azo.c`.
* **Specification examples** – the "Simple", "General" and "Solid" example archives of the
  EGG specification (section 3) are rebuilt byte for byte (the solid example's CRC-32 is
  corrected: the document prints a wrong value for "abc").
* **Real ALZip archives** – `tests/data/t.alz` and `t.alz.foo` from the patool 4.1.0 source
  distribution on PyPI (GPL-3, 58/59 bytes, made by ALZip in 2012) are downloaded into the
  test work directory and compared with The Unarchiver; the check is skipped offline.
