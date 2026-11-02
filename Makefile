# 고깃ZIP (GogitZIP) build
#
#   make            -> Windows: build/GogitZip.exe (x86, Windows 2000+) and build/GogitZip64.exe (x64)
#   make test       -> native core tests (Linux / macOS / MSYS2)
#   make cli        -> build/gogitzip (portable command line tool, this machine)
#   make linux      -> build/linux/gogitzip-gtk (GTK 3 GUI) + build/gogitzip
#   make install    -> Linux: programs, launcher, MIME package, icons (PREFIX=/usr/local, DESTDIR=)
#   make mac        -> build/mac/GogitZIP.app (on macOS, universal x86_64 + arm64)
#
# Sources: src/core (model, crypto, CPU dispatch), src/codec (compression codecs),
# src/fmt (archive formats and writers), src/win (Windows UI), src/posix (Linux/macOS
# platform layer), src/app (portable engine + CLI), src/gtk, src/mac.

CC32  ?= i686-w64-mingw32-gcc
CC64  ?= x86_64-w64-mingw32-gcc
WR32  ?= i686-w64-mingw32-windres
WR64  ?= x86_64-w64-mingw32-windres
HOSTCC ?= cc
B     := build

CORE := $(sort $(wildcard src/core/*.c src/codec/*.c src/fmt/*.c))
WIN  := $(sort $(wildcard src/win/*.c))
APP  := $(sort $(wildcard src/app/*.c))
POSIX := $(sort $(wildcard src/posix/*.c))
HDRS := $(wildcard src/core/*.h src/codec/*.h src/fmt/*.h src/win/*.h src/app/*.h src/posix/*.h)
INC  := -Isrc/core -Isrc/codec -Isrc/fmt -Isrc/app -Isrc/posix
REG  := $(B)/gen/registry.c

# No C runtime on Windows: we provide memcpy & co. ourselves (src/win/rt.c).
WARN := -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wno-cast-function-type
CFLAGS := -std=gnu11 $(WARN) -fno-stack-protector -fno-asynchronous-unwind-tables \
          -fno-unwind-tables -fno-ident -fno-math-errno -fno-exceptions \
          -ffunction-sections -finput-charset=UTF-8 -DUNICODE -D_UNICODE $(INC)
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

# the Windows UI runs the portable engine (src/app/engine.c) on top of src/win/os_win.c
WINAPP := src/app/engine.c
OBJ32 := $(patsubst src/%.c,$(B)/x86/%.o,$(CORE) $(WINAPP) $(WIN)) $(B)/x86/gen/registry.o $(B)/x86/res.o
OBJ64 := $(patsubst src/%.c,$(B)/x64/%.o,$(CORE) $(WINAPP) $(WIN)) $(B)/x64/gen/registry.o $(B)/x64/res.o

all: win
win: $(B)/GogitZip.exe $(B)/GogitZip64.exe

# format / writer tables from the GZ_FORMAT(...) / GZ_WRITER(...) marker lines
$(REG): $(CORE) tools/gen_registry.sh
	@mkdir -p $(dir $@)
	sh tools/gen_registry.sh $@ $(CORE)

$(B)/GogitZip.exe: $(OBJ32)
	$(CC32) $(LD32) -o $@ $^ $(LIBS)

$(B)/GogitZip64.exe: $(OBJ64)
	$(CC64) $(LD64) -o $@ $^ $(LIBS)

$(B)/x86/gen/registry.o: $(REG) $(HDRS)
	@mkdir -p $(dir $@)
	$(CC32) $(CFLAGS) $(OPT_CORE) $(ARCH32) -c $< -o $@
$(B)/x64/gen/registry.o: $(REG) $(HDRS)
	@mkdir -p $(dir $@)
	$(CC64) $(CFLAGS) $(OPT_CORE) $(ARCH64) -c $< -o $@

define core_rules
$(B)/x86/$(1)/%.o: src/$(1)/%.c $$(HDRS)
	@mkdir -p $$(dir $$@)
	$$(CC32) $$(CFLAGS) $$(OPT_CORE) $$(ARCH32) -c $$< -o $$@
$(B)/x64/$(1)/%.o: src/$(1)/%.c $$(HDRS)
	@mkdir -p $$(dir $$@)
	$$(CC64) $$(CFLAGS) $$(OPT_CORE) $$(ARCH64) -c $$< -o $$@
endef
$(foreach d,core codec fmt,$(eval $(call core_rules,$(d))))

# the engine only orchestrates I/O (the hot loops are in the codecs): optimise for size
$(B)/x86/app/%.o: src/app/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC32) $(CFLAGS) $(OPT_UI) $(ARCH32) -c $< -o $@
$(B)/x64/app/%.o: src/app/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC64) $(CFLAGS) $(OPT_UI) $(ARCH64) -c $< -o $@

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

# ---- native build of the portable core (tests, CLI, Linux/macOS front ends) ----
HOST_CFLAGS ?= -O2 -g
HOSTFLAGS := -std=gnu11 $(WARN) -finput-charset=UTF-8 -pthread $(INC) $(HOST_CFLAGS)
HOST_LIBS := -pthread
ifeq ($(shell uname -s),Darwin)
HOST_LIBS += -liconv
endif
HOSTOBJ := $(patsubst src/%.c,$(B)/host/%.o,$(CORE) $(POSIX)) $(B)/host/gen/registry.o

$(B)/host/gen/registry.o: $(REG) $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HOSTFLAGS) -c $< -o $@
$(B)/host/%.o: src/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HOSTFLAGS) -c $< -o $@

$(B)/gzt: tests/gzt.c $(HOSTOBJ)
	$(HOSTCC) $(HOSTFLAGS) -o $@ tests/gzt.c $(HOSTOBJ) $(HOST_LIBS)

# command line tool: core + POSIX layer + portable engine (cli.c holds main, so it is
# linked directly and never lands in build/host where test drivers pick up objects)
APPOBJ := $(patsubst src/%.c,$(B)/host/%.o,$(filter-out src/app/cli.c,$(APP)))
$(B)/gogitzip: src/app/cli.c $(HOSTOBJ) $(APPOBJ)
	$(HOSTCC) $(HOSTFLAGS) -o $@ src/app/cli.c $(HOSTOBJ) $(APPOBJ) $(HOST_LIBS)
cli: $(B)/gogitzip

# ---- Linux GTK 3 front end: core + POSIX layer + engine + src/gtk ----
# Objects live in build/linux/obj, not build/host (test drivers link every build/host object).
# res/assets.bin (the icon atlas) is embedded by src/gtk/icons.c (.incbin, path from the repo root).
GTKPKG     ?= gtk+-3.0
GTK_CFLAGS  = $(shell pkg-config --cflags $(GTKPKG))
GTK_LIBS    = $(shell pkg-config --libs $(GTKPKG))
GTKSRC     := $(sort $(wildcard src/gtk/*.c))
GTKOBJ     := $(patsubst src/gtk/%.c,$(B)/linux/obj/%.o,$(GTKSRC))
GTKHDRS    := $(wildcard src/gtk/*.h) src/win/asset_ids.h
$(B)/linux/obj/%.o: src/gtk/%.c $(HDRS) $(GTKHDRS) res/assets.bin
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HOSTFLAGS) $(GTK_CFLAGS) -c $< -o $@
$(B)/linux/gogitzip-gtk: $(GTKOBJ) $(HOSTOBJ) $(APPOBJ)
	$(HOSTCC) $(HOSTFLAGS) -o $@ $(GTKOBJ) $(HOSTOBJ) $(APPOBJ) $(GTK_LIBS) $(HOST_LIBS)
linux: $(B)/linux/gogitzip-gtk $(B)/gogitzip

# make install [PREFIX=/usr/local] [DESTDIR=staging]: binaries, launcher, MIME package, icons
PREFIX  ?= /usr/local
DESTDIR ?=
SHARE   := $(DESTDIR)$(PREFIX)/share
ICON_SIZES := 16 22 24 32 48 64 128 256 512
install: linux
	install -Dm755 $(B)/linux/gogitzip-gtk $(DESTDIR)$(PREFIX)/bin/gogitzip-gtk
	install -Dm755 $(B)/gogitzip $(DESTDIR)$(PREFIX)/bin/gogitzip
	install -Dm644 data/linux/gogitzip.desktop $(SHARE)/applications/gogitzip.desktop
	install -Dm644 data/linux/gogitzip-mime.xml $(SHARE)/mime/packages/gogitzip.xml
	install -Dm644 data/linux/gogitzip.metainfo.xml $(SHARE)/metainfo/gogitzip.metainfo.xml
	for s in $(ICON_SIZES); do \
	  install -Dm644 data/linux/icons/hicolor/$${s}x$${s}/apps/gogitzip.png \
	    $(SHARE)/icons/hicolor/$${s}x$${s}/apps/gogitzip.png || exit 1; done
	@if [ -z "$(DESTDIR)" ]; then \
	  update-mime-database $(SHARE)/mime >/dev/null 2>&1 || true; \
	  update-desktop-database -q $(SHARE)/applications >/dev/null 2>&1 || true; \
	  gtk-update-icon-cache -q -t $(SHARE)/icons/hicolor >/dev/null 2>&1 || true; fi
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/gogitzip-gtk $(DESTDIR)$(PREFIX)/bin/gogitzip \
	  $(SHARE)/applications/gogitzip.desktop $(SHARE)/mime/packages/gogitzip.xml \
	  $(SHARE)/metainfo/gogitzip.metainfo.xml
	for s in $(ICON_SIZES); do rm -f $(SHARE)/icons/hicolor/$${s}x$${s}/apps/gogitzip.png; done

ICORE := src/core/cpu.c src/core/crc32.c src/codec/inflate.c src/core/crypto.c src/core/stream.c \
         src/core/crc64.c src/core/sha1.c src/core/sha256.c src/core/aes.c src/core/blake2.c
$(B)/test_inflate: tests/test_inflate.c $(ICORE) $(HDRS)
	@mkdir -p $(B)
	$(HOSTCC) -O2 -g $(INC) -o $@ tests/test_inflate.c $(ICORE) -lz

test: $(B)/test_inflate $(B)/gzt $(B)/gogitzip
	$(B)/test_inflate
	HOST_CFLAGS="$(HOST_CFLAGS)" HOSTCC="$(HOSTCC)" python3 tests/run_tests.py --gzt $(B)/gzt --work $(B)/testwork $(TESTARGS)

# rebuild host objects (e.g. after switching HOST_CFLAGS to sanitizers)
clean-host:
	rm -rf $(B)/host $(B)/gzt $(B)/gogitzip $(B)/test_inflate $(B)/linux

assets:
	python3 tools/gen_assets.py

clean:
	rm -rf $(B)

.PHONY: all win cli linux install uninstall test assets clean clean-host
