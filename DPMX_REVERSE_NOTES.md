# DPMX Reverse Notes

Target: `d2.exe`

Tool: `E:\radare2-6.1.4-w64\bin\radare2.exe`

## Container Layout

The DPMX archive is embedded in the PE overlay at raw offset `0x1c400`.

```text
0x1c400 +0x00  "DPMX"
0x1c400 +0x04  u32 data_offset = 0x1270
0x1c400 +0x08  u32 entry_count = 0x93
0x1c400 +0x0c  u32 reserved = 0
0x1c400 +0x10  0x20-byte entries
```

Entry layout:

```text
+0x00 char name[16]
+0x10 u32 flags/reserved
+0x14 u32 seed
+0x18 u32 payload_offset_from_data_base
+0x1c u32 payload_size
```

The payload data base is:

```text
0x1c400 + 0x1270 = 0x1d670
```

## Key Functions

- `0x4038d0`: DPMX initialization and index table loading.
- `0x403640`: resource name lookup and per-entry key setup.
- `0x4037f0`: resource read path and byte decode loop.
- `0x403bc0`: `DPM:` / `MEM:` path handling.
- `0x403ce0`: higher-level resource read API.

Useful radare2 commands:

```text
aaa
izz~DPMX
axt 0x0041a338
pdf @ 0x4038d0
pdf @ 0x403640
pdf @ 0x4037f0
pdf @ 0x403bc0
pdf @ 0x403ce0
```

## Per-Entry Key

For nonzero entry seed:

```c
b0 = seed & 0xff;
b1 = (seed >> 8) & 0xff;
b2 = (seed >> 16) & 0xff;
b3 = (seed >> 24) & 0xff;

entry_key1 = ((b0 + 0x55) ^ b2) & 0xff;
entry_key2 = ((b1 + 0xaa) ^ b3) & 0xff;
```

The static evidence is in `0x403781..0x4037a8`.

For this sample, known-plaintext validation across all BMP/WAV entries gives
equivalent global key pairs `0xaf,0x83` and `0x2f,0x03`. The extractor uses
`0xaf,0x83`.

## Decode Loop

The actual byte transform is at `0x4038a7..0x4038af`:

```c
key1 = (global_key1 + entry_key1) & 0xff;
key2 = (global_key2 + entry_key2) & 0xff;
state = 0;

for each encrypted byte b:
    delta = ((b - key2) & 0xff) ^ key1;
    state = (state + delta) & 0xff;
    out[i] = state;
```

Entries with seed `0` are copied as plain data in this sample.

`back.bmp` validates the loop: encrypted bytes at `0x1d670` decode to:

```text
42 4d e0 17 04 00 00 00 00 00 36 00 ...
```

That is a valid BMP header.
