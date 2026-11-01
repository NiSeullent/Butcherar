# 고깃ZIP (GogitZIP) build
#
#   make            -> build/GogitZip.exe (x86, Windows 2000+) and build/GogitZip64.exe (x64)
#   make test       -> native core tests (Linux/macOS/MSYS2 with zlib)
#
# Works with MinGW-w64 cross compilers on Linux or natively in MSYS2.

CC32  ?= i686-w64-mingw32-gcc
CC64  ?= x86_64-w64-mingw32-gcc
WR32  ?= i686-w64-mingw32-windres
WR64  ?= x86_64-w64-mingw32-windres
HOSTCC ?= cc
B     := build

CORE := src/core/cpu.c src/core/crc32.c src/core/inflate.c src/core/crypto.c \
        src/core/arc.c src/core/zip.c src/core/tar.c
WIN  := src/win/rt.c src/win/util.c src/win/strings.c src/win/gfx.c src/win/dlgt.c \
        src/win/engine.c src/win/dialogs.c src/win/mainwnd.c src/win/main.c src/win/shell.c
HDRS := $(wildcard src/core/*.h src/win/*.h)

# No C runtime: we provide memcpy & co. ourselves (src/win/rt.c).
CFLAGS := -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers \
          -Wno-cast-function-type -fno-stack-protector -fno-asynchronous-unwind-tables \
          -fno-unwind-tables -fno-ident -fno-math-errno -fno-exceptions \
          -ffunction-sections -finput-charset=UTF-8 -DUNICODE -D_UNICODE
OPT_CORE := -O2
OPT_UI   := -Os
RTFLAGS  := -fno-builtin -fno-tree-loop-distribute-patterns

# x86: baseline i586 (Pentium) - everything faster is chosen at run time.
ARCH32 := -march=i586 -mtune=generic -mincoming-stack-boundary=2
ARCH64 := -march=x86-64 -mtune=generic

LIBS := -lkernel32 -luser32 -lgdi32 -lmsimg32 -lcomctl32 -lcomdlg32 -lshell32 \
        -lshlwapi -ladvapi32 -lole32 -lgcc
LD32 := -nostdlib -s -Wl,--gc-sections -Wl,-e,_gz_start -Wl,--subsystem,windows:5.00 \
        -Wl,--major-os-version,5 -Wl,--minor-os-version,0 -Wl,--large-address-aware \
        -Wl,--dynamicbase -Wl,--nxcompat -Wl,--no-insert-timestamp
LD64 := -nostdlib -s -Wl,--gc-sections -Wl,-e,gz_start -Wl,--subsystem,windows:5.02 \
        -Wl,--major-os-version,5 -Wl,--minor-os-version,2 \
        -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va -Wl,--no-insert-timestamp

OBJ32 := $(patsubst src/%.c,$(B)/x86/%.o,$(CORE) $(WIN)) $(B)/x86/res.o
OBJ64 := $(patsubst src/%.c,$(B)/x64/%.o,$(CORE) $(WIN)) $(B)/x64/res.o

all: $(B)/GogitZip.exe $(B)/GogitZip64.exe

$(B)/GogitZip.exe: $(OBJ32)
	$(CC32) $(LD32) -o $@ $^ $(LIBS)

$(B)/GogitZip64.exe: $(OBJ64)
	$(CC64) $(LD64) -o $@ $^ $(LIBS)

$(B)/x86/core/%.o: src/core/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC32) $(CFLAGS) $(OPT_CORE) $(ARCH32) -c $< -o $@
$(B)/x64/core/%.o: src/core/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC64) $(CFLAGS) $(OPT_CORE) $(ARCH64) -c $< -o $@
$(B)/x86/win/rt.o: src/win/rt.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC32) $(CFLAGS) $(OPT_CORE) $(RTFLAGS) $(ARCH32) -c $< -o $@
$(B)/x64/win/rt.o: src/win/rt.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC64) $(CFLAGS) $(OPT_CORE) $(RTFLAGS) $(ARCH64) -c $< -o $@
$(B)/x86/win/%.o: src/win/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC32) $(CFLAGS) $(OPT_UI) $(ARCH32) -c $< -o $@
$(B)/x64/win/%.o: src/win/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC64) $(CFLAGS) $(OPT_UI) $(ARCH64) -c $< -o $@

$(B)/x86/res.o: res/app.rc res/app.ico res/doc.ico res/assets.bin res/app.manifest
	@mkdir -p $(dir $@)
	$(WR32) -c 65001 -I res -O coff $< $@
$(B)/x64/res.o: res/app.rc res/app.ico res/doc.ico res/assets.bin res/app.manifest
	@mkdir -p $(dir $@)
	$(WR64) -c 65001 -I res -O coff $< $@

# ---- native tests of the portable core ----
ICORE := src/core/cpu.c src/core/crc32.c src/core/inflate.c src/core/crypto.c
test: $(B)/test_inflate $(B)/test_arc
	$(B)/test_inflate
	python3 tests/run_arc_tests.py $(B)/test_arc $(B)/arcwork

$(B)/test_inflate: tests/test_inflate.c $(ICORE) $(HDRS)
	@mkdir -p $(B)
	$(HOSTCC) -O2 -g -Isrc/core -o $@ tests/test_inflate.c $(ICORE) -lz

$(B)/test_arc: tests/test_arc.c $(CORE) $(HDRS)
	@mkdir -p $(B)
	$(HOSTCC) -O2 -g -fshort-wchar -Wno-pointer-sign -Isrc/core -o $@ tests/test_arc.c $(CORE)

assets:
	python3 tools/gen_assets.py

clean:
	rm -rf $(B)

.PHONY: all test assets clean
