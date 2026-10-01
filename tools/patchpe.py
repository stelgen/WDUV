#!/usr/bin/env python3
"""patchpe.py — patch/verify the PE minimum OS version of Windows executables.

The Go linker stamps OptionalHeader.MajorOperatingSystemVersion/Minor with
its own baseline. For binaries that must load on Windows Vista (NT 6.00) we
rewrite those fields to 6.00 (and the subsystem version to match), then
verify. Usage:

    patchpe.py --set 6.0 FILE...   patch to Major.Minor (default 6.0)
    patchpe.py --verify 6.0 FILE   exit 0 iff every FILE has minOS == 6.0
"""
import argparse
import struct
import sys


def pe_optional_header(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[:2] != b"MZ" or data[e:e + 4] != b"PE\x00\x00":
        raise ValueError("not a PE file")
    opt = e + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError(f"unsupported optional header magic {magic:#x}")
    return opt, magic


def get_min_os(data):
    opt, _ = pe_optional_header(data)
    maj, mino = struct.unpack_from("<BB", data, opt + 40)
    return maj, mino


def set_min_os(data, major, minor):
    opt, _ = pe_optional_header(data)
    # MajorOperatingSystemVersion/Minor (offset 40/41), MajorSubsystemVersion/
    # Minor (48/49). The subsystem version is not enforced by the desktop
    # loader but keeping it consistent avoids confusion.
    struct.pack_into("<BB", data, opt + 40, major, minor)
    struct.pack_into("<BB", data, opt + 48, major, minor)
    return data


def main(argv=None):
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--set", metavar="VER")
    g.add_argument("--verify", metavar="VER")
    ap.add_argument("files", nargs="+")
    args = ap.parse_args(argv)

    if args.set:
        major, minor = (int(x) for x in args.set.split("."))
        for path in args.files:
            with open(path, "rb") as fh:
                data = bytearray(fh.read())
            set_min_os(data, major, minor)
            with open(path, "wb") as fh:
                fh.write(data)
            print(f"{path}: minOS set to {major}.{minor}")
        return 0

    want_major, want_minor = (int(x) for x in args.verify.split("."))
    rc = 0
    for path in args.files:
        with open(path, "rb") as fh:
            data = fh.read()
        try:
            maj, mino = get_min_os(data)
        except ValueError as exc:
            print(f"{path}: FAIL ({exc})")
            rc = 1
            continue
        if (maj, mino) != (want_major, want_minor):
            print(f"{path}: FAIL (minOS {maj}.{mino} != {want_major}.{want_minor})")
            rc = 1
        else:
            print(f"{path}: OK (minOS {maj}.{mino})")
    return rc


if __name__ == "__main__":
    sys.exit(main())
