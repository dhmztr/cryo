#!/usr/bin/env bash
set -euo pipefail

CRYO_BIN="${CRYO_BIN:-./target/release/cryo}"
WORK="$(mktemp -d)"
DATA="$WORK/data"
CORPUS_MB="${CORPUS_MB:-970}"
FILES="${FILES:-20}"

trap 'rm -rf "$WORK"' EXIT

if [ ! -x "$CRYO_BIN" ]; then
    echo "building release binary..."
    cargo build --release
fi

mkdir -p "$DATA"
base="$WORK/base.txt"
for i in $(seq 1 20000); do
    echo "2026-08-20T21:$((i % 60)):00Z INFO worker-$((i % 8)) processed request id=$i status=ok latency_ms=$((i % 200)) path=/api/v1/resource/$((i % 50))"
done >"$base"

repeats=$(((CORPUS_MB * 1024 * 1024) / FILES / $(stat -c%s "$base")))
for i in $(seq 1 "$FILES"); do
    for _ in $(seq 1 "$repeats"); do cat "$base"; done >"$DATA/log$i.txt"
done

echo "corpus: $(du -sh "$DATA" | cut -f1)"
echo

run() {
    local label="$1"
    shift
    local start end
    start=$(date +%s%N)
    "$@" >/dev/null 2>&1
    end=$(date +%s%N)
    printf "%-24s %6.2fs\n" "$label" "$(awk "BEGIN { print ($end - $start) / 1000000000 }")"
}

size_of() {
    du -h "$1" | cut -f1
}

echo "== cryo (multithreaded) =="
run "compress" "$CRYO_BIN" compress "$WORK/cryo.cryo" -P "$DATA" -r --bs 512KiB
echo "size: $(size_of "$WORK/cryo.cryo")"
echo

echo "== tar + gzip (default -6) =="
start=$(date +%s%N)
tar -C "$WORK" -cf - data | gzip >"$WORK/data.tar.gz"
end=$(date +%s%N)
printf "%-24s %6.2fs\n" "compress" "$(awk "BEGIN { print ($end - $start) / 1000000000 }")"
echo "size: $(size_of "$WORK/data.tar.gz")"
echo

echo "== tar + zstd (default level) =="
start=$(date +%s%N)
tar -C "$WORK" -cf - data | zstd -q -o "$WORK/data.tar.zst"
end=$(date +%s%N)
printf "%-24s %6.2fs\n" "compress" "$(awk "BEGIN { print ($end - $start) / 1000000000 }")"
echo "size: $(size_of "$WORK/data.tar.zst")"
