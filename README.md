```
  ____________  ______
 / ___/ ___/ / / / __ \
/ /__/ /  / /_/ / /_/ /
\___/_/   \__, /\____/
         /____/
```

[![CI](https://github.com/dhmztr/cryo/actions/workflows/ci.yml/badge.svg)](https://github.com/dhmztr/cryo/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/cryoarc.svg)](https://crates.io/crates/cryoarc)

Block-based archive tool with a choice of zstd, xz or DEFLATE compression and optional AES-256-GCM or ChaCha20-Poly1305 encryption. Compression is parallelized across a worker pool: one thread reads and chunks the input, a pool of workers compresses/encrypts blocks concurrently, and a single writer thread persists them in order.

## Install

```sh
cargo install cryoarc
```

Unix only — Linux and macOS. cryo stores POSIX permission bits and recreates symlinks, so it does not build on Windows.

## Build from source

```sh
cargo build --release
```

Binary lands at `target/release/cryo`.

## Usage

### Compress

```sh
cryo compress <name> [options]
```

| Flag                    | Default    | Description                                       |
| ----------------------- | ---------- | ------------------------------------------------- |
| `-P, --path <PATH>`     | `./`       | Source path                                       |
| `-r, --recursive`       | false      | Recurse into subdirectories                       |
| `-c, --compression <A>` | `zstd`     | Algorithm: `zstd`, `xz`, `deflate`, `none`        |
| `--cl <N>`              | `3`        | Compression level, range depends on the algorithm |
| `-e, --et <TYPE>`       | `none`     | Encryption: `aes`, `cha-cha`, `none`              |
| `--ep <PROFILE>`        | `balanced` | Argon2 profile: `fast`, `balanced`, `paranoid`    |
| `--bs <SIZE>`           | `512KiB`   | Block size (e.g. `1MiB`, `256KiB`)                |
| `--confirm`             | on         | Prompt for the password twice (see note below)    |
| `-v, --debug`           | false      | Debug tracing on stderr                           |

`-r` is required when `--path` points at a directory; without it cryo refuses rather than writing an empty archive. A single file can be compressed without `-r`.

```sh
cryo compress backup -P ./docs -r --cl 9 -e aes
```

### Decompress

```sh
cryo decompress <archive.cryo> [options] [FILTER]...
```

| Flag                 | Default | Description                                            |
| -------------------- | ------- | ------------------------------------------------------ |
| `-o, --output <DIR>` | `./`    | Output directory (must be empty or new)                |
| `[FILTER]...`        | none    | Glob patterns; only matching entries are extracted     |
| `--confirm`          | on      | Prompt for the password twice (see note below)         |
| `-v, --debug`        | false   | Debug tracing on stderr                                |

Also accepts the five `--max-*` guards documented under [Size limits](#size-limits).

```sh
cryo decompress backup.cryo -o ./restored
cryo decompress backup.cryo -o ./restored '*.md' 'src/**'
```

### Append

```sh
cryo append -f <archive.cryo> -a <FILE|DIR>
```

| Flag                   | Default  | Description                                       |
| ---------------------- | -------- | ------------------------------------------------- |
| `-f, --archive <PATH>` | required | Existing `.cryo` archive to append to             |
| `-a, --append <PATH>`  | required | File or directory to add (directories go in whole) |
| `--confirm`            | on       | Prompt for the password twice (see note below)    |

```sh
cryo append -f backup.cryo -a ./notes.md
```

Entries already present in the archive are skipped rather than duplicated. New blocks inherit the archive's existing compression, encryption and block size — those cannot be changed on append.

Append never writes to the archive in place: it copies it to a sibling `.tmp` file, appends there, and atomically renames over the original on success. If anything fails the `.tmp` is removed and the original is left untouched.

### List

```sh
cryo list <archive.cryo> [--format auto|human|plain|json] [--confirm]
```

Prints file entries with permissions, type, size, compression ratio, timestamp, and path. Defaults to colored output when stdout is a terminal and plain tab-separated output when piped.

### Verify

```sh
cryo verify <archive.cryo>
```

Reads every block and checks its BLAKE3 checksum without writing anything to disk. Takes no options; on an encrypted archive it asks for the password once.

## Password prompts

Encrypted archives prompt for a password on stdin; it is never taken from an argument or environment variable. `compress`, `decompress`, `append` and `list` expose `--confirm`, which asks for the password a second time and aborts on mismatch — worth having on `compress`, where a typo would otherwise produce a permanently unreadable archive.

Note that `--confirm` is currently a plain on/off flag that already defaults to on, so passing it changes nothing and there is no `--no-confirm` to switch it off. Every command listed above asks twice today; `verify` asks once.

## Debugging

Pass `-v` before the subcommand to enable debug tracing output on stderr. `compress` and `decompress` also accept `-v` after the subcommand:

```sh
cryo -v decompress archive.cryo -o ./out
cryo decompress archive.cryo -o ./out -v
```

## Archive format

Current format version is `3`. Both the 8-byte magic and the version are checked when an archive is opened, so older or foreign files are rejected rather than misread.

```
[ 4 bytes      ] header length (little-endian u32)
[ N bytes      ] msgpack-encoded Header
[ blocks...    ] compressed, encrypted data blocks
[ index        ] msgpack-encoded Index (optionally compressed, optionally encrypted)
[ 29 bytes     ] Footer
```

Footer layout (all little-endian):

```
bytes  0-7  : u64      index offset in file
bytes  8-11 : u32      stored index size (after encryption)
bytes 12-15 : u32      plain index size (before compression)
byte  16    : u8       1 if the index is compressed, 0 otherwise
bytes 17-28 : [u8; 12] nonce the index was encrypted with
```

The index nonce lives in the footer because it is needed to decrypt the index itself, so it cannot be stored inside it.

Each block is compressed with the archive's algorithm if that shrinks it — otherwise it is stored raw, and the index records which — then encrypted. The BLAKE3 checksum in the index covers the raw plaintext block before compression or encryption. Each index entry also carries that block's offset, stored and plain sizes, and its nonce.

Files spanning multiple blocks are reassembled by slicing the relevant byte ranges out of each decoded block.

## Size limits

All limits have conservative defaults and can be raised per-decompression:

| Flag                | Default               |
| ------------------- | --------------------- |
| `--max-file-size`   | 10 GiB                |
| `--max-block-size`  | 256 MiB               |
| `--max-m-cost`      | 1 GiB (Argon2 memory) |
| `--max-index-size`  | 100 MiB               |
| `--max-header-size` | 64 KiB                |

These exist to protect against malformed or malicious archives that claim enormous sizes before any data is read.

## Benchmarks

`scripts/bench.sh` generates a ~970 MiB compressible corpus, then benchmarks **every compression algorithm cryo supports against its counterpart under `tar`** — `zstd`, `deflate` (versus `gzip`, which is DEFLATE in a container), `xz` and `none`, each at a matched compression level. For every pair it reports compress time, decompress time, archive size, ratio and throughput, plus an `ok`/`BAD` column verifying the extracted tree is byte-complete, so a corrupt result can never be mistaken for a fast one.

Run it with `./scripts/bench.sh` (needs `tar`, plus whichever of `gzip`, `zstd`, `xz` you want compared — a missing tool just marks that `tar` row `skip`). Tunable via env: `ALGOS`, `CORPUS_MB`, `FILES`, `BS`, `CRYO_BIN`, `ZSTD_LEVEL`, `GZIP_LEVEL`, `XZ_LEVEL`. `xz` over the full corpus takes minutes, so `ALGOS="zstd none" CORPUS_MB=100 ./scripts/bench.sh` is the quick loop.

The script's `gzip` row currently only measures the `tar` side: it passes `-c gzip` to cryo, which since the multi-algorithm rework spells that codec `deflate` and rejects the old name.

Reading the numbers: cryo compresses fixed-size blocks across many threads, while `tar | gzip` pushes one stream through one core — much of the wall-clock gap is that, not the codec. The same block chunking is why cryo's ratio trails single-stream `tar` on highly repetitive data, most visibly with `xz`.

Measured on a 16-core machine, average of 3 runs:

|                                 | Time      | Output size |
| ------------------------------- | --------- | ----------- |
| cryo (sequential, pre-parallel) | 0.76s     | 23 MiB      |
| **cryo (parallel worker pool)** | **0.28s** | 23 MiB      |
| `tar` + `gzip -6`               | 2.26s     | 49 MiB      |
| `tar` + `zstd` (default)        | 0.45s     | 21 MiB      |

Parallelizing compression gives ~2.7x speedup over the sequential implementation with identical output size (block layout and compression level are unchanged, only how blocks get produced). `gzip` is both slower and produces a larger archive than either. `tar`+`zstd` streams the whole archive through one zstd context so it can find long-range matches across block/file boundaries that cryo's fixed-size block chunking can't see, which is why its ratio edges out cryo's on highly repetitive data; cryo's parallel path is still faster in wall-clock time on multi-core machines.

## Encryption

The password is hashed with Argon2id using a per-archive random salt, at the cost parameters chosen by `--ep`.

Every block gets its own 12-byte nonce drawn from the OS CSPRNG, stored alongside that block's entry in the index. Nonces are not derived from the block index, so re-writing a block — as `append` does — cannot collide with a nonce already used under the same key.

Each block is sealed with 24 bytes of associated data: the block number as a little-endian `u64` followed by the 16-byte random archive id. That binds every ciphertext to its position and to the archive it came from, so blocks cannot be reordered between archives or swapped within one without the AEAD tag failing. The index itself is sealed the same way, using `u64::MAX` as its block number.
