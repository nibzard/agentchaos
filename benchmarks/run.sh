#!/bin/sh
# Run every beta-target benchmark and build the report (T043, spec 21).
# Raw output lands in benchmarks/raw/; collate.py turns it into
# report.json and report.md. Go benchmarks use bounded iteration
# counts so runs stay quick and recorder memory stays bounded.
set -e

root="$(cd "$(dirname "$0")/.." && pwd)"
raw="$root/benchmarks/raw"
mkdir -p "$raw"

echo "== broker: deterministic gate, throughput, grant expiry =="
(cd "$root/broker" &&
    go test -bench=. -benchtime=2000x -run='^$' ./...) \
    > "$raw/broker.txt" 2>&1
cat "$raw/broker.txt"

echo "== evidence-plane: metadata event ingest =="
(cd "$root/evidence-plane" &&
    go test -bench=. -benchtime=100x -run='^$' ./...) \
    > "$raw/evidence.txt" 2>&1
cat "$raw/evidence.txt"

echo "== supervisor: reviewer decisions and deadline enforcement =="
(cd "$root/supervisor" &&
    go test -bench=. -benchtime=50x -run='^$' ./...) \
    > "$raw/supervisor.txt" 2>&1
cat "$raw/supervisor.txt"

echo "== governor: fencing acknowledgment =="
(cd "$root/governor" &&
    go test -bench=. -benchtime=20x -run='^$' ./...) \
    > "$raw/governor.txt" 2>&1
cat "$raw/governor.txt"

echo "== execution plane: runner overhead and setup =="
python3 "$root/execution-plane/benchmarks/runner_overhead.py" \
    --out "$raw/runner_overhead.json"

echo "== collating =="
python3 "$root/benchmarks/collate.py"
