#!/usr/bin/env python3
"""Extract the DPMX overlay archive embedded in d2.exe.

This implements the resource decode loop recovered from d2.exe:

    tmp = ((encrypted_byte - key2) & 0xff) ^ key1
    state = (state + tmp) & 0xff
    output_byte = state

The sample has its DPMX archive at the PE overlay start, 0x1c400.
"""

from __future__ import annotations

import argparse
import os
import struct
from dataclasses import dataclass
from pathlib import Path


DPMX_MAGIC = b"DPMX"
DEFAULT_ARCHIVE_OFFSET = 0x1C400

# These two pairs are equivalent for the byte transform because adding 0x80 to
# key2 and xor-ing 0x80 into key1 cancel each other out. 0xaf/0x83 is the pair
# recovered by known-plaintext validation against every BMP/WAV entry.
DEFAULT_GLOBAL_KEY1 = 0xAF
DEFAULT_GLOBAL_KEY2 = 0x83


@dataclass(frozen=True)
class DpmxEntry:
    index: int
    name: str
    flags: int
    seed: int
    offset: int
    size: int


def find_dpmx(data: bytes) -> int:
    hit = data.find(DPMX_MAGIC, DEFAULT_ARCHIVE_OFFSET)
    if hit != -1:
        return hit
    hit = data.find(DPMX_MAGIC)
    if hit == -1:
        raise ValueError("DPMX magic not found")
    return hit


def read_entries(data: bytes, base: int) -> tuple[int, list[DpmxEntry]]:
    magic = data[base : base + 4]
    if magic != DPMX_MAGIC:
        raise ValueError(f"expected DPMX at 0x{base:x}, got {magic!r}")

    data_offset, count, _reserved = struct.unpack_from("<III", data, base + 4)
    entries: list[DpmxEntry] = []
    table = base + 0x10
    for index in range(count):
        pos = table + index * 0x20
        raw_name = data[pos : pos + 0x10].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="replace")
        flags, seed, offset, size = struct.unpack_from("<IIII", data, pos + 0x10)
        entries.append(DpmxEntry(index, name, flags, seed, offset, size))

    return base + data_offset, entries


def derive_entry_keys(seed: int, global_key1: int, global_key2: int) -> tuple[int, int]:
    if seed == 0:
        return 0, 0

    b0 = seed & 0xFF
    b1 = (seed >> 8) & 0xFF
    b2 = (seed >> 16) & 0xFF
    b3 = (seed >> 24) & 0xFF

    entry_key1 = ((b0 + 0x55) ^ b2) & 0xFF
    entry_key2 = ((b1 + 0xAA) ^ b3) & 0xFF
    return (entry_key1 + global_key1) & 0xFF, (entry_key2 + global_key2) & 0xFF


def decode_payload(payload: bytes, seed: int, global_key1: int, global_key2: int) -> bytes:
    if seed == 0:
        return payload

    key1, key2 = derive_entry_keys(seed, global_key1, global_key2)
    state = 0
    out = bytearray(len(payload))
    for i, value in enumerate(payload):
        delta = ((value - key2) & 0xFF) ^ key1
        state = (state + delta) & 0xFF
        out[i] = state
    return bytes(out)


def safe_output_path(root: Path, name: str) -> Path:
    clean = name.replace("\\", "/").split("/")[-1]
    if not clean:
        clean = "unnamed"
    return root / clean


def validate_known_magic(name: str, data: bytes) -> bool | None:
    lower = name.lower()
    if lower.endswith(".bmp"):
        return data.startswith(b"BM")
    if lower.endswith(".wav"):
        return data.startswith(b"RIFF") and data[8:12] == b"WAVE"
    return None


def extract(exe: Path, out_dir: Path, global_key1: int, global_key2: int) -> tuple[int, int, int]:
    data = exe.read_bytes()
    base = find_dpmx(data)
    data_base, entries = read_entries(data, base)

    out_dir.mkdir(parents=True, exist_ok=True)
    checked = 0
    passed = 0
    for entry in entries:
        start = data_base + entry.offset
        end = start + entry.size
        if start < data_base or end > len(data):
            raise ValueError(f"{entry.name}: payload out of range")

        decoded = decode_payload(data[start:end], entry.seed, global_key1, global_key2)
        verdict = validate_known_magic(entry.name, decoded)
        if verdict is not None:
            checked += 1
            passed += int(verdict)

        path = safe_output_path(out_dir, entry.name)
        path.write_bytes(decoded)

    return len(entries), checked, passed


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract DPMX resources from d2.exe")
    parser.add_argument("exe", nargs="?", default="d2.exe", type=Path)
    parser.add_argument("-o", "--out", default=Path("extracted_dpmx"), type=Path)
    parser.add_argument("--key1", default=DEFAULT_GLOBAL_KEY1, type=lambda x: int(x, 0))
    parser.add_argument("--key2", default=DEFAULT_GLOBAL_KEY2, type=lambda x: int(x, 0))
    args = parser.parse_args()

    count, checked, passed = extract(args.exe, args.out, args.key1, args.key2)
    print(f"extracted={count} output={args.out}")
    print(f"validated_known_magic={passed}/{checked}")
    if checked and checked != passed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
