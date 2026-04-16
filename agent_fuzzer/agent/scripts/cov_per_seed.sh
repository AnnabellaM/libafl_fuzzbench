#!/bin/bash
# Per-seed coverage entrypoint. Mounted into the agent-cov-<target> container.
#   Usage: cov_per_seed.sh <seeds_dir> <out_dir>
# Produces:
#   <out_dir>/json/<seed_name>.json   — llvm-cov export JSON for each seed
# Uses $FUZZ_BIN from image env (baked by Dockerfile.<target>.cov).
set -u
SEEDS="${1:?seeds dir}"
OUT="${2:?out dir}"
: "${FUZZ_BIN:?FUZZ_BIN not set in image}"

mkdir -p "$OUT/profraw" "$OUT/profdata" "$OUT/json"

count=0
ok=0
for f in "$SEEDS"/*; do
    [ -f "$f" ] || continue
    name=$(basename "$f")
    count=$((count + 1))
    profraw="$OUT/profraw/$name.profraw"
    profdata="$OUT/profdata/$name.profdata"
    jsonf="$OUT/json/$name.json"

    LLVM_PROFILE_FILE="$profraw" timeout 10 "$FUZZ_BIN" "$f" >/dev/null 2>&1 || true
    [ -f "$profraw" ] || continue
    llvm-profdata-18 merge -sparse "$profraw" -o "$profdata" 2>/dev/null || continue
    llvm-cov-18 export "$FUZZ_BIN" -instr-profile="$profdata" --skip-expansions \
        > "$jsonf" 2>/dev/null || { rm -f "$jsonf"; continue; }
    ok=$((ok + 1))
done

echo "cov_per_seed: $ok/$count seeds produced coverage json"
