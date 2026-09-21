#!/usr/bin/env bash
# Compare each cryo algorithm against the same algorithm via `tar | <compressor>`,
# on the same corpus and level: compress time, decompress time, and size.
# Note: cryo packs blocks across threads while `tar | gzip` is one stream on one
# core, so much of the time difference is that, not the codec itself.
#
# ENV: CRYO_BIN, CORPUS_MB, FILES, ALGOS, BS, ZSTD_LEVEL, GZIP_LEVEL, XZ_LEVEL
set -euo pipefail

CRYO_BIN="${CRYO_BIN:-./target/release/cryo}"
CORPUS_MB="${CORPUS_MB:-970}"
FILES="${FILES:-20}"
BS="${BS:-512KiB}"
ALGOS="${ALGOS:-zstd gzip xz none}"
ZSTD_LEVEL="${ZSTD_LEVEL:-3}"
GZIP_LEVEL="${GZIP_LEVEL:-6}"
XZ_LEVEL="${XZ_LEVEL:-6}"

WORK="$(mktemp -d)"
DATA="$WORK/data"
trap 'rm -rf "$WORK"' EXIT

if [ ! -x "$CRYO_BIN" ]; then
    echo "building release binary..."
    cargo build --release
fi

# corpus: repetitive logs that compress well
mkdir -p "$DATA"
base="$WORK/base.txt"
for i in $(seq 1 20000); do
    echo "2026-08-20T21:$((i % 60)):00Z INFO worker-$((i % 8)) processed request id=$i status=ok latency_ms=$((i % 200)) path=/api/v1/resource/$((i % 50))"
done >"$base"

repeats=$(((CORPUS_MB * 1024 * 1024) / FILES / $(stat -c%s "$base")))
for i in $(seq 1 "$FILES"); do
    for _ in $(seq 1 "$repeats"); do cat "$base"; done >"$DATA/log$i.txt"
done

CORPUS_BYTES=$(du -sb "$DATA" | cut -f1)

now() { date +%s%N; }

secs() { awk "BEGIN { printf \"%.2f\", ($2 - $1) / 1000000000 }"; }

human() { numfmt --to=iec --suffix=B "$1" 2>/dev/null || echo "${1}B"; }

throughput() { awk "BEGIN { printf \"%.0f\", ($CORPUS_BYTES / 1048576) / ($1 > 0 ? $1 : 0.001) }"; }

ratio() { awk "BEGIN { printf \"%.1fx\", $CORPUS_BYTES / ($1 > 0 ? $1 : 1) }"; }

row() { printf "%-6s %-12s %9s %9s %11s %7s %9s %6s\n" "$@"; }

# sets global COMP/DECOMP/EXT/LEVEL for the given algorithm
setup_algo() {
    case "$1" in
    zstd)
        LEVEL="$ZSTD_LEVEL" COMP="zstd -q -$ZSTD_LEVEL" DECOMP="zstd -dcq" EXT="tar.zst"
        ;;
    gzip)
        LEVEL="$GZIP_LEVEL" COMP="gzip -$GZIP_LEVEL" DECOMP="gzip -dc" EXT="tar.gz"
        ;;
    xz)
        LEVEL="$XZ_LEVEL" COMP="xz -$XZ_LEVEL" DECOMP="xz -dc" EXT="tar.xz"
        ;;
    none)
        LEVEL="0" COMP="cat" DECOMP="cat" EXT="tar"
        ;;
    *)
        echo "unknown algorithm: $1" >&2
        return 1
        ;;
    esac
}

# "ok" if the extracted tree has the same byte count as the corpus, guarding
# against benchmarking silent corruption
check_bytes() {
    if [ "$(du -sb "$1" | cut -f1)" = "$CORPUS_BYTES" ]; then echo ok; else echo BAD; fi
}

bench_cryo() {
    local algo="$1" archive="$WORK/cryo_$1.cryo" out="$WORK/out_cryo_$1"
    local s e ct dt size

    s=$(now)
    "$CRYO_BIN" compress "$archive" -P "$DATA" -r -c "$algo" --cl "$LEVEL" --bs "$BS" >/dev/null 2>&1
    e=$(now)
    ct=$(secs "$s" "$e")

    mkdir -p "$out"
    s=$(now)
    "$CRYO_BIN" decompress "$archive" -o "$out" >/dev/null 2>&1
    e=$(now)
    dt=$(secs "$s" "$e")

    size=$(stat -c%s "$archive")
    row "$algo" "cryo" "${ct}s" "${dt}s" "$(human "$size")" "$(ratio "$size")" \
        "$(throughput "$ct")" "$(check_bytes "$out")"
    rm -rf "$out" "$archive"
}

bench_tar() {
    local algo="$1" archive="$WORK/tar_$1.$EXT" out="$WORK/out_tar_$1"
    local s e ct dt size

    s=$(now)
    tar -C "$WORK" -cf - data | $COMP >"$archive"
    e=$(now)
    ct=$(secs "$s" "$e")

    mkdir -p "$out"
    s=$(now)
    $DECOMP <"$archive" | tar -C "$out" -xf -
    e=$(now)
    dt=$(secs "$s" "$e")

    size=$(stat -c%s "$archive")
    row "$algo" "tar|$algo" "${ct}s" "${dt}s" "$(human "$size")" "$(ratio "$size")" \
        "$(throughput "$ct")" "$(check_bytes "$out/data")"
    rm -rf "$out" "$archive"
}

echo "corpus:  $(human "$CORPUS_BYTES") in $FILES files"
echo "cryo:    $CRYO_BIN (block $BS, multithreaded)"
echo "tar:     single stream, single core"
echo "levels:  zstd=$ZSTD_LEVEL gzip=$GZIP_LEVEL xz=$XZ_LEVEL"
echo
row "algo" "tool" "compress" "decomp" "size" "ratio" "MB/s" "ok"
row "----" "----" "--------" "------" "----" "-----" "----" "--"

for algo in $ALGOS; do
    setup_algo "$algo"

    bench_cryo "$algo"

    # tar needs an external tool; cryo has the codecs built in
    tool="${COMP%% *}"
    if command -v "$tool" >/dev/null 2>&1; then
        bench_tar "$algo"
    else
        row "$algo" "tar|$algo" "-" "-" "-" "-" "-" "skip"
    fi
    echo
done
