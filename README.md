# WDUV — vista-defender-update

![CI](https://github.com/stelgen/WDUV/actions/workflows/ci.yml/badge.svg)
[![Release](https://img.shields.io/github/v/release/stelgen/WDUV)](https://github.com/stelgen/WDUV/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**An offline signature-update tool for Windows Defender on Windows Vista.**

Windows Vista reached end of support in 2017, and its built-in Windows Defender
stopped receiving definition updates the moment Microsoft's infrastructure
moved on. The classic update endpoint, however, is still alive:
[`https://go.microsoft.com/fwlink/?LinkID=121721`](https://go.microsoft.com/fwlink/?LinkID=121721)
redirects to the current *Microsoft Antimalware* signature package
(`mpam-fe.exe`). WDUV downloads that package, unpacks it, applies the engine
and antispyware definition files to Defender's directories, patches the
registry and restarts the service — with a full backup, rollback and dry-run
support.

> [!WARNING]
> This tool replaces antivirus engine files with content downloaded from
> Microsoft over TLS. Run it only if you understand what it does, keep the
> backup it creates, and prefer `apply -local` when you have already vetted
> the files yourself.

## What it does

```
update     download → extract → stop service → backup → apply → registry → start
apply      same, from a pre-extracted local directory
download   just fetch the package (read-only)
status     show installed files, registry version, service state, last backup
backup     write a timestamped copy of the current signature files
rollback   restore the last backup (restores files, removes created ones,
           restores the registry values)
```

Flags: `-dry-run` (preview without touching the system), `-local <dir>`,
`-out <file>`.

The registry values written are `HKLM\SOFTWARE\Microsoft\Windows Defender\Signatures`
→ `Antivirus` / `AntiSpyware` (default `1.269.1752.0`, override with the
`VDU_SIG_VERSION` environment variable). The WinDefend service is stopped
before files are copied (it locks them) and started afterwards; on any failure
the service is always started again.

## How the package is unpacked

Microsoft's signature packages are small PE executables whose `.rsrc` section
carries one huge CAB archive. The CAB holds three folders:

| folder | compression | contents |
|---|---|---|
| 0 | **LZX**, 2 MiB window | `mpengine.dll`, `MpSigStub.exe` |
| 1 | stored | `mpasbase.vdm` |
| 2 | stored | `mpasdlta.vdm`, `mpavbase.vdm`, `mpavdlta.vdm` |

WDUV parses the PE, locates the CAB and unpacks it **in pure Go**: a faithful
port of libmspack's LZX decompressor (see `lzx.go`, `docs/ANALYSIS.md`), an
MSZIP decoder and the stored-codec plumbing — no external binaries required.
Extracted output is validated against `cabextract` on a real 221 MB package
(see *Testing*).

Only the antispyware set is applied (`mpengine.dll`, `MpSigStub.exe`,
`mpasbase.vdm`, `mpasdlta.vdm`); the `mpav*` files belong to Security
Essentials-style antivirus products and are extracted but skipped.

## Compatibility notes (read this before using on Vista)

- **Use the `vista` binaries from Releases for Vista/7/8.** They are built
  with Go 1.20.14 — the last toolchain line that still targets legacy Windows —
  and their PE minimum-OS field is patched to 6.00 (`tools/patchpe.py`).
  Mainline Go (1.21+) officially requires Windows 10 and stamps
  `MajorOperatingSystemVersion = 10.0`; such executables are rejected by the
  Vista loader outright.
- The `vista` build expects an SSE2-capable CPU (any Pentium 4/Athlon 64 or
  later) and enough free memory for a ~220 MB in-package scan; apply copies
  write ~150 MB to `ProgramData`.
- Whether the *current* package's engine (1.1.26xx) runs on Vista is beyond
  what this tool can promise — Microsoft stopped publishing Vista-compatible
  engines years ago. For a controlled, known-good update use
  `apply -local <dir>` with a package or files you have verified yourself.
- Nothing here defeats Defender's own integrity model: the same files could be
  copied by hand. The tool automates the boring, error-prone part.

## Building

```bash
# standard build (Windows 10+, current Go)
GOOS=windows GOARCH=386   go build -trimpath -ldflags "-s -w" -o vdu-386.exe .
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o vdu-amd64.exe .

# legacy build for Vista (Go 1.20.14 + PE header patch)
curl -fsSL https://go.dev/dl/go1.20.14.linux-amd64.tar.gz | tar xz
GOOS=windows GOARCH=386   ./go/bin/go build -trimpath -ldflags "-s -w" -o vdu-386.exe .
GOOS=windows GOARCH=amd64 ./go/bin/go build -trimpath -ldflags "-s -w" -o vdu-amd64.exe .
python3 tools/patchpe.py --set 6.0 vdu-386.exe vdu-amd64.exe
python3 tools/patchpe.py --verify 6.0 vdu-386.exe vdu-amd64.exe
```

The committed `.syso` resources embed the icon and version info into every
Windows build automatically (`tools/versioninfo.rc`, regenerate with
`windres` if you change them; `tools/icon.py` regenerates `assets/`).

## Testing

```bash
go test ./...                                   # unit tests (any OS)
VDU_TEST_MPAM=/path/to/mpam-fe.exe go test -run TestRealPackageExtraction -v
```

The unit suite covers the bit reader, canonical Huffman table building, LZX
pre-tree length decoding (including 17/18/19 runs), handcrafted literal-only
and uncompressed-block streams, E8/E9 translation, CAB layout, PE resource
location, backup/apply/rollback orchestration and download handling — all
platform-independent thanks to a hook-based split of the Windows-only
facilities (`vista_windows.go`).

`TestRealPackageExtraction` (opt-in) runs the full pipeline on a real
Microsoft package and pins SHA-256 hashes of all six embedded files against a
`cabextract`-derived reference.

## Project layout

```
main.go            commands, orchestration, backup/apply/rollback, download
pe.go              PE parsing + CAB (MSCF) locator
cab.go             CAB header/folder/file tables, folder stream, split writer
mszip.go           MSZIP (per-block deflate) decoder
lzx.go             LZX decoder (Go port of libmspack lzxd.c, LGPL-2.1)
vista_windows.go   registry + WinDefend service hooks (real implementation)
*_test.go          unit + integration tests
tools/             patchpe.py (PE min-version), icon.py, versioninfo.rc
assets/            logo.ico / logo.png (Vista-style quadrant shield)
docs/ANALYSIS.md   anatomy of the real package + design notes
```

## License

MIT — except `lzx.go`, which is a port of
[libmspack](https://github.com/kyz/libmspack)'s `lzxd.c` and therefore
LGPL-2.1 (its header states the provenance).

---

*Проект также документирован на русском в `docs/ANALYSIS.md`. WDUV = Windows
Defender Update (Vista).*
