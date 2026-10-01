# WDUV — vista-defender-update v2

![CI](https://github.com/stelgen/WDUV/actions/workflows/ci.yml/badge.svg)
[![Release](https://img.shields.io/github/v/release/stelgen/WDUV)](https://github.com/stelgen/WDUV/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![WDUV logo](assets/logo.png)

**Fresh file signatures for the built-in Windows Defender of Windows Vista —
without touching its engine.**

The built-in Windows Defender of Windows Vista (app `1.1.1600.0`) kept
receiving engine and definition updates through Windows Update until the OS
went out of support. A fully updated installation carries engine
`1.1.17020.2` — and, notably, it happily runs definition generations far
newer than its engine build (a stock system shows `Definition Version
1.315.1121.0`, a mid-2020 generation). WDUV v2 exploits exactly that:

1. it downloads the **freshest definition package that has a chance to load**
   on the local engine (ranked ladder, see `sources`),
2. unpacks it **in pure C** (PE → `.rsrc` → CAB → stored/LZX folders — no
   external tools),
3. applies **only the antispyware signature files** (`mpasbase.vdm`,
   `mpasdlta.vdm`) the way Vista itself does — a fresh
   `Definition Updates\{GUID}` folder plus a registry pointer flip,
4. starts the service and **watches it**: if the engine rejects the new
   definitions, everything is rolled back automatically and the next-older
   source is tried.

The engine binary is **never replaced** in default mode. There is no Go, no
.NET, no runtime dependencies — a single ~170 KB static executable whose PE
header is natively stamped `minOS 6.00` by the linker.

> [!WARNING]
> The tool swaps antivirus signature databases on a 2006-era product. Every
> apply is preceded by a full backup and is reversible with one command, but
> you are experimenting with an unsupported configuration — which is exactly
> what the health-checked ladder is for.

## The definition-generation matrix (measured, 01.10.2026)

| source | package engine | mpas generation | notes |
|---|---|---|---|
| `current` (fwlink 121721) | 1.1.26080.3 | **1.459.497.0** | today's Win11-era package; 10 engine-years newer than Vista's |
| `vista-x86-2019` (archive.org) | 1.2.1009.0 | 1.305.416.0 | frozen package tagged *for Windows Vista x86* |
| `win7-x86-2018` (archive.org) | 1.2.1009.0 | 1.283.1902.0 | Windows 7 era |
| `xp-2016` (archive.org) | 1.2.1003.0 | 1.225.2438.0 | April 2016 |

Your engine already runs generation **1.315** — proof that the vdm format of
its era tolerated (much) newer generations than the engine build. Whether
generation 459 still parses on `1.1.17020.2` is the experiment `update`
performs safely: try → health-check → auto-rollback → fall through the ladder.

**Why not convert the 2026 definitions into the 2015 format?** Both formats
are undocumented MMPC containers (each vdm is a PE shell whose `.rsrc` holds
the engine's signature database). A converter would mean reverse-engineering
two proprietary database formats *and* their integrity model, and the 2016
engine has no code for the record types ten years of scan technology added.
That is a research project, not a tool — the honest substitute is the
era-aware ladder above.

## Usage

```
vdu status                       local engine/definition versions + registry state
vdu sources                      the pinned source ladder
vdu fetch <name> [-out dir]      download + unpack a package (run on a modern PC;
                                 TLS 1.2 required — Vista's schannel usually
                                 cannot reach modern CDNs directly)
vdu update [-source name]        download → apply → health-check → auto-rollback
                                 → next source on failure
vdu apply -package <pkg|dir>     apply extracted signatures (signatures-only)
vdu backup                       back up the current definition set
vdu rollback                     restore the last backup
vdu verify <name|file>           SHA-256 + structure + version report
```

Flags: `-dry-run`, `-force` (skip the engine-family gate), `-no-health`.
Carry a `fetch`ed folder to the Vista box on a USB stick and `apply -package`
it there — that is the recommended offline flow.

## What "apply" actually does (Vista's own model)

1. reads the current pointers `HKLM\SOFTWARE\Microsoft\Windows Defender\Signatures`
   → `Antivirus` / `AntiSpyware` (they name the active `Definition Updates\{GUID}`
   folder),
2. stops `WinDefend` (it locks the files),
3. copies the current `{GUID}` set into `...\vdu-backup\<timestamp>\` +
   writes `manifest.json`,
4. creates `Definition Updates\{new GUID}\` with the new `mpasbase.vdm` /
   `mpasdlta.vdm`,
5. flips both registry values to the new GUID,
6. starts the service and watches it for 5 seconds; on failure → automatic
   rollback (pointers + files restored, failed folder removed).

## Build & test

```bash
make test      # 13-test suite: bit reader, canonical Huffman, pre-tree runs,
               # literal/E8/uncompressed LZX streams, CAB stored round-trips,
               # PE wrapper, versioninfo parser, apply/rollback e2e
make exe       # mingw cross-build, i386 + amd64, minOS 6.00 baked in
```

Optional integration check against the real packages (kept out of CI — the
fixtures are hundreds of MB):

```bash
VDU_TEST_MPAM=mpam-fe.exe \
VDU_TEST_VISTA=mpam-fe_vista_x86.exe \
VDU_TEST_WIN7=mpam-fe-w7x86.exe \
make test        # verifies every extracted file byte-for-byte vs cabextract
```

## Project layout

```
src/main.c            CLI
src/apply.c           backup / GUID-flip apply / rollback / health check
src/cab.c, src/lzx.c  CAB + LZX extractors (lzx.c = port of libmspack, LGPL-2.1)
src/pe.c              PE parsing, CAB locator, VS_VERSIONINFO reader
src/platform_win.c    registry / service / WinHTTP / GUID (real Windows layer)
src/platform_stub.c   portable stubs — the full pipeline is tested on Linux
tools/                patchpe.py (minOS verify), icon.py, versioninfo.rc
docs/ANALYSIS.md      measured package matrix + format notes (RU)
```

## License

MIT — except `src/lzx.c`, a port of
[libmspack](https://github.com/kyz/libmspack)'s `lzxd.c` (LGPL-2.1).

---

*WDUV = Windows Defender Update (Vista). v1 (Go prototype) lives in the
`v1.0.0` tag; v2 is the C rewrite with the engine-preserving model.*
