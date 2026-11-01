# RAR5 offline fixtures

Small archives made by the RAR program, copied from two public test suites so
that tests/cases/fmt_rar5.py can check real RAR output without network access.
The test module downloads the full sets when it can (see its docstring).

| file | origin |
|------|--------|
| compressed.rar, solid.rar, blake2.rar, win32.rar, multiarchive_solid.part01-04.rar | libarchive 3.8.10 source tarball (`libarchive_3.8.10.orig.tar.xz` from http://archive.ubuntu.com/ubuntu/pool/main/liba/libarchive/), `libarchive/test/test_read_format_rar5_<name>.rar.uu`, uudecoded; BSD-2-Clause |
| rar5-dups.rar, rar5-psw-blake.rar, rar5-hpsw.rar | sdist of the PyPI package rarfile 4.5 (`rarfile-4.5.tar.gz`), `test/files/`; ISC license; password `password` |

SHA-256:

```
e2889c7498cb8065b9fd2338b142a135b906576a30d24acaf44850cca6fb845a  blake2.rar
68f9d7e2662cd5bc5607ba9c6bf1edbf121cf3b08011a7d8643091791750a7c8  compressed.rar
6607f575dad0b28aaeb02298b4c04a0e5a606e77f952127d2d9e346f60616a26  multiarchive_solid.part01.rar
eb119ed53511905ca6f1844c164b6246d8fcdca0d1f38a8e3fb13da9c0932fbd  multiarchive_solid.part02.rar
e814c3dbdaf3f613fd25c840065d25543f31e6b6c95505e7e25f47867a4812bd  multiarchive_solid.part03.rar
9ff5a4e633b0e82a2ce6e022f3d389654dbb77a0906a34f107676d6673989c9f  multiarchive_solid.part04.rar
60a752ef7f0373d881171dcb068810fe12a698b53f2bbce93ae4fb1b4e68cf8e  rar5-dups.rar
9aff93dfd85b1e44daeef233105831999a2076299997b7790e1cf1fd557a4457  rar5-hpsw.rar
6f6914979dfdc56b323f362f8fbead9ab70105b5f8590b7d3a6fa3a7cdd9540c  rar5-psw-blake.rar
1149dda288494ab6c954d0e3f2a8831318aaf9c69e7da741729bb0c681f924b5  solid.rar
f33f17c7b3f1a623bba4f81b41565860ae9f1589dfaf7386e62a520543390c49  win32.rar
```
