# WDUV v2 — Makefile
# Linux:   make test        (build + run the unit/e2e suite with gcc)
# MinGW:   make exe         (cross-build vista-defender-update-{386,amd64}.exe)
CC      ?= gcc
MINGW32 ?= i686-w64-mingw32-gcc
MINGW64 ?= x86_64-w64-mingw32-gcc
WINDRES ?= x86_64-w64-mingw32-windres
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Isrc
LDFLAGS ?=

SRCS_CORE = src/util.c src/sha256.c src/pe.c src/lzx.c src/cab.c src/apply.c
SRCS_WIN  = src/main.c src/gui.c src/ops.c src/status.c src/platform_win.c
SRCS_LNX  = src/platform_stub.c

all: test exe

# ---- linux test build (platform stubs) ----
test: build/vdu-test
	./build/vdu-test

build/vdu-test: $(SRCS_CORE) $(SRCS_LNX) tests/testmain.c tests/fixtures.c tests/tests_impl.c tests/test_integration.c
	@mkdir -p build
	$(CC) $(CFLAGS) -Itests -o $@ $(SRCS_CORE) $(SRCS_LNX) tests/testmain.c tests/fixtures.c tests/tests_impl.c tests/test_integration.c $(LDFLAGS)

# ---- windows exes (mingw cross) ----
exe: dist/vista-defender-update-386.exe dist/vista-defender-update-amd64.exe

build/rsrc_386.o: tools/versioninfo.rc assets/logo.ico
	@mkdir -p build
	i686-w64-mingw32-windres -O coff -F pe-i386 tools/versioninfo.rc -o $@

build/rsrc_amd64.o: tools/versioninfo.rc assets/logo.ico
	@mkdir -p build
	$(WINDRES) -O coff -F pe-x86-64 tools/versioninfo.rc -o $@

dist/vista-defender-update-386.exe: $(SRCS_CORE) $(SRCS_WIN) build/rsrc_386.o
	@mkdir -p dist
	$(MINGW32) $(CFLAGS) -D_WIN32_WINNT=0x0600 -Wl,--major-os-version,6,--minor-os-version,0,--major-subsystem-version,6,--minor-subsystem-version,0 -o $@ $(SRCS_CORE) $(SRCS_WIN) build/rsrc_386.o -lwinhttp -ladvapi32 -lrpcrt4 -lshell32 -lcomdlg32 -lgdi32 -static -s

dist/vista-defender-update-amd64.exe: $(SRCS_CORE) $(SRCS_WIN) build/rsrc_amd64.o
	@mkdir -p dist
	$(MINGW64) $(CFLAGS) -D_WIN32_WINNT=0x0600 -Wl,--major-os-version,6,--minor-os-version,0,--major-subsystem-version,6,--minor-subsystem-version,0 -o $@ $(SRCS_CORE) $(SRCS_WIN) build/rsrc_amd64.o -lwinhttp -ladvapi32 -lrpcrt4 -lshell32 -lcomdlg32 -lgdi32 -static -s

clean:
	rm -rf build dist

.PHONY: all test exe clean
