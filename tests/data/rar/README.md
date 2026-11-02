# RAR 1.5 - 4.x offline fixtures

Small archives made by the RAR program, copied from two public test suites so
that tests/cases/fmt_rar.py can check real RAR output without network access.
The test module downloads the full sets when it can (see its docstring).

| file | origin |
|------|--------|
| test_read_format_rar_filter.rar (E8E9 + DELTA VM filters), test_read_format_rar_compress_best.rar (PPMd), test_read_format_rar3_lowdist_reset.rar, test_read_format_rar4_solid_encrypted.rar (AES, solid; password `password`), test_read_format_rar_unicode.rar, test_rar_multivolume_single_file.part1-3.rar | libarchive 3.8.10 source tarball (`libarchive_3.8.10.orig.tar.xz` from http://archive.ubuntu.com/ubuntu/pool/main/liba/libarchive/), `libarchive/test/<name>.uu`, uudecoded; BSD-2-Clause |
| rar15-comment.rar (RAR 1.5 data + packed comment), rar202-comment-psw.rar (RAR 2.0 encryption; password `password`), rar2-unix-owner.rar, rar3-comment-hpsw.rar (-hp; password `password`), rar3-solid.rar, unicode.rar | sdist of the PyPI package rarfile 4.5 (`rarfile-4.5.tar.gz`), `test/files/`; ISC license |

SHA-256:

```
f81c66b8a2d424e74a8ba76cf265206173404c3504b8dae7da6a27cf58141057  rar15-comment.rar
899724d4ac341fee19567a23a4d3b08b35d69cca0d14a4d01a6e08a5869d2281  rar2-unix-owner.rar
ec28322015b8102cc569c5564cdfecf1eb634350e2a67258c4230858182b8663  rar202-comment-psw.rar
29c61403d1e7cec0b15eb7e33cfa217cebd56bf1a4a78a2642715eca474350b2  rar3-comment-hpsw.rar
0944932546b994f282cdb3ac724112c312d406b4c1aecfe1eaf9e734e8f96aa2  rar3-solid.rar
54769cdaa6aeac494b9ba580804598369ba240f61550620434e08350e4428ec2  test_rar_multivolume_single_file.part1.rar
9dd6b28d2fdf0d012390259548cc86be9535ee6eb5ec630c99fbb5dc8d037ed1  test_rar_multivolume_single_file.part2.rar
7d72ef6e876e98e6a317b7e534c0285615a2953543e68135a8a0dcc94b41cf21  test_rar_multivolume_single_file.part3.rar
45ca17d52b91a6f24c48fe5d79b04cb26052f7e1d732d8bf8e459c433540f916  test_read_format_rar3_lowdist_reset.rar
428d44a21042069bbc1891c30a66c48f55540aa37dd8b7ff92c39c5914e3a4a6  test_read_format_rar4_solid_encrypted.rar
7005b3c6e169ae559f0183c5f0640fdd201b329cf61838c1ca45725949fe0e06  test_read_format_rar_compress_best.rar
b058412adcd3329a868cb66561a224eb0acf22ad2d380ef5d9e17e432a47d6a8  test_read_format_rar_filter.rar
3dc3d2a8f3f6cbfeeb6f45b3bb09fa7b2bf4b52e10e80df29217fdeaa9dbda45  test_read_format_rar_unicode.rar
1d1d25ff7e1a4190055bda32a771a4a5e282ddd8078ce730ca44c45befcec176  unicode.rar
```

Expected contents: the archives' own CRC-32s (every entry must extract with
status 0) and, when the tools are installed, 7-Zip / unrar / unar.
