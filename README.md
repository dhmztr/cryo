```
  ____________  ______
 / ___/ ___/ / / / __ \
/ /__/ /  / /_/ / /_/ /
\___/_/   \__, /\____/
         /____/
```

[![CI](https://github.com/dhmztr/cryo/actions/workflows/ci.yml/badge.svg)](https://github.com/dhmztr/cryo/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/cryoarc.svg)](https://crates.io/crates/cryoarc)

Block-based archive tool with zstd compression and optional AES-256-GCM or ChaCha20-Poly1305 encryption. Compression is parallelized across a worker pool: one thread reads and chunks the input, a pool of workers compresses/encrypts blocks concurrently, and a single writer thread persists them in order.

## Install

```sh
cargo install cryoarc
```

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

| Flag                           | Default    | Description                                    |
| ------------------------------ | ---------- | ---------------------------------------------- |
| `-P, --path <PATH>`            | `./`       | Source path                                    |
| `-r, --recursive`              | false      | Recurse into subdirectories                    |
| `-c, --compression-level <N>`  | `3`        | zstd level (-7 to 22)                          |
| `-e, --encryption-type <TYPE>` | `none`     | `aes`, `chacha`, or `none`                     |
| `--ep <PROFILE>`               | `balanced` | Argon2 profile: `fast`, `balanced`, `paranoid` |
| `--bs <SIZE>`                  | `512KiB`   | Block size (e.g. `1MiB`, `256KiB`)             |

```sh
cryo compress backup -P ./docs -r -c 9 -e aes
```

### Decompress

```sh
cryo decompress <archive.cryo> [options]
```

| Flag                 | Default | Description                             |
| -------------------- | ------- | --------------------------------------- |
| `-o, --output <DIR>` | `./`    | Output directory (must be empty or new) |

```sh
cryo decompress backup.cryo -o ./restored
```

### Append

```sh
cryo append --archive <DIR> --append <DIR>
```

| Flag        | Default | Description                                               |
| ----------- | ------- | --------------------------------------------------------- |
| `--archive` | `None`  | Select archive to append to (must be existing directory ) |
| `--append`  | `None`  | Select which file/dir to append from (must exist)         |

### List

```sh
cryo list <archive.cryo> [--format auto|human|plain|json]
```

Prints file entries with permissions, type, size, compression ratio, timestamp, and path. Defaults to colored output when stdout is a terminal and plain tab-separated output when piped.

### Verify

```sh
cryo verify <archive.cryo>
```

Reads every block and checks its BLAKE3 checksum without writing anything to disk.

## Debugging

Pass `-v` before the subcommand to enable debug tracing output on stderr:

```sh
cryo -v decompress archive.cryo -o ./out
```

## Archive format

```
[ 4 bytes      ] header length (little-endian u32)
[ N bytes      ] msgpack-encoded Header
[ blocks...    ] zstd-compressed, encrypted data blocks
[ index        ] msgpack-encoded Index (optionally compressed, optionally encrypted)
[ 17 bytes     ] Footer
```

Footer layout (all little-endian):

```
bytes  0-7  : u64  index offset in file
bytes  8-11 : u32  stored index size (after encryption)
bytes 12-15 : u32  plain index size (before compression)
byte  16    : u8   1 if index is zstd-compressed, 0 otherwise
```

Each block is compressed with zstd if that shrinks it, then encrypted. The BLAKE3 checksum in the index covers the raw plaintext block before compression or encryption.

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

`scripts/bench.sh` generates a ~970 MiB compressible corpus, then benchmarks **every compression algorithm cryo supports against the same algorithm under `tar`** — `zstd`, `gzip`, `xz` and `none`, each at a matched compression level. For every pair it reports compress time, decompress time, archive size, ratio and throughput, plus an `ok`/`BAD` column verifying the extracted tree is byte-complete, so a corrupt result can never be mistaken for a fast one.

Run it with `./scripts/bench.sh` (needs `tar`, plus whichever of `gzip`, `zstd`, `xz` you want compared — a missing tool just marks that `tar` row `skip`). Tunable via env: `ALGOS`, `CORPUS_MB`, `FILES`, `BS`, `CRYO_BIN`, `ZSTD_LEVEL`, `GZIP_LEVEL`, `XZ_LEVEL`. `xz` over the full corpus takes minutes, so `ALGOS="zstd gzip" CORPUS_MB=100 ./scripts/bench.sh` is the quick loop.

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

The password is hashed with Argon2id using a per-archive random salt. Block nonces are derived by XOR-ing a random base nonce with the block index, so each block gets a unique nonce without storing one per block. The archive index uses a fixed sentinel value (`u64::MAX`) as its block number.
