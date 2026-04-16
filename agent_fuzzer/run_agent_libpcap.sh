#!/bin/bash
# Standalone agent analysis on libpcap — produces detailed per-seed stats.
#
# This runs the blocker-analyst agent once against the libpcap target,
# using existing seeds (or generating them from a short fuzzer run),
# and outputs detailed structured reports to out/.
#
# Prerequisites:
#   - Docker images: agent-cov-libpcap (coverage), libafl-libpcap-generic (fuzzer)
#   - ANTHROPIC_API_KEY set
#
# Usage:
#   ./run_agent_libpcap.sh [--skip-prefuzz] [--prefuzz-duration 120] [--max-turns 50]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/out"
IPC_DIR="${OUT_DIR}/ipc"
SEEDS_DIR="${IPC_DIR}/seeds"
RESULTS_DIR="${IPC_DIR}/results"
COV_OUT="${OUT_DIR}/cov_out"
REPORT_DIR="${OUT_DIR}/reports"

SKIP_PREFUZZ=0
PREFUZZ_DURATION=300    # 5 min of fuzzing to build seed corpus
AGENT_MAX_TURNS="${AGENT_MAX_TURNS:-50}"
DOCKER_COV_IMAGE="agent-cov-libpcap"
DOCKER_FUZZ_IMAGE="libafl-libpcap-generic"

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-prefuzz)       SKIP_PREFUZZ=1;          shift ;;
        --prefuzz-duration)   PREFUZZ_DURATION="$2";   shift 2 ;;
        --max-turns)          AGENT_MAX_TURNS="$2";    shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

echo "============================================"
echo "Agent Fuzzer — Libpcap Blocker Analysis"
echo "============================================"
echo "Output directory: $OUT_DIR"
echo "Pre-fuzz duration: ${PREFUZZ_DURATION}s"
echo "Agent max turns: $AGENT_MAX_TURNS"
echo ""

# Clean and prepare directories
rm -rf "$OUT_DIR"
mkdir -p "$SEEDS_DIR" "$RESULTS_DIR" "$COV_OUT" "$REPORT_DIR"

# ── Step 1: Build seed corpus ──────────────────────────────────────────────
if [ "$SKIP_PREFUZZ" = "0" ]; then
    echo "==> Step 1: Running generic fuzzer for ${PREFUZZ_DURATION}s to build seed corpus..."
    CORPUS_TMP="${OUT_DIR}/prefuzz_corpus"
    mkdir -p "$CORPUS_TMP"

    docker rm -f agent-prefuzz-libpcap 2>/dev/null || true
    docker run --rm \
        --name agent-prefuzz-libpcap \
        -v "${CORPUS_TMP}:/corpus" \
        -e DURATION="$PREFUZZ_DURATION" \
        "$DOCKER_FUZZ_IMAGE" \
        > "${OUT_DIR}/prefuzz.log" 2>&1 || true

    # Copy seeds from corpus queue
    if [ -d "${CORPUS_TMP}/queue" ]; then
        cp "${CORPUS_TMP}/queue"/* "$SEEDS_DIR/" 2>/dev/null || true
    fi
    NUM_SEEDS=$(find "$SEEDS_DIR" -type f 2>/dev/null | wc -l)
    echo "    Pre-fuzz produced $NUM_SEEDS seeds"
else
    echo "==> Step 1: Skipping pre-fuzz. Using initial seed only."
    # Minimal pcap seed
    printf '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' \
        > "$SEEDS_DIR/seed_initial.pcap"
    NUM_SEEDS=1
fi

echo "    Seeds directory: $SEEDS_DIR ($NUM_SEEDS seeds)"

# Write manifest
cat > "${IPC_DIR}/request.json" <<MANIFEST
{
    "num_seeds": $NUM_SEEDS,
    "seeds_dir": "$SEEDS_DIR",
    "timestamp": $(date +%s),
    "target": "libpcap"
}
MANIFEST

# ── Step 2: Run baseline coverage ──────────────────────────────────────────
echo ""
echo "==> Step 2: Running baseline coverage analysis..."
docker run --rm \
    -v "$SEEDS_DIR:/corpus:ro" \
    -v "$COV_OUT:/cov_out" \
    "$DOCKER_COV_IMAGE" \
    > "${OUT_DIR}/baseline_cov.log" 2>&1 || true

echo "    Baseline coverage reports at: $COV_OUT/"
if [ -f "$COV_OUT/branch_coverage_summary.txt" ]; then
    echo "    Summary:"
    head -20 "$COV_OUT/branch_coverage_summary.txt" | sed 's/^/      /'
fi

# ── Step 3: Invoke agent with enhanced reporting prompt ────────────────────
echo ""
echo "==> Step 3: Invoking blocker-analyst agent with detailed reporting..."

PROMPT="## Fuzzer Plateau — Blocker Resolution Request (with Detailed Reporting)

The fuzzer has detected a coverage plateau on **libpcap** and needs your help to break through.

### IPC Paths
- Seeds (current queue): $SEEDS_DIR ($NUM_SEEDS seeds)
- Manifest: ${IPC_DIR}/request.json
- Write resolved seeds to: $RESULTS_DIR
- Signal completion by creating: ${IPC_DIR}/done

### Coverage Verification via Docker
A Docker image \`$DOCKER_COV_IMAGE\` is available with the coverage-instrumented target.

**Run coverage on seeds:**
\`\`\`bash
docker run --rm -v $SEEDS_DIR:/corpus:ro -v $COV_OUT:/cov_out $DOCKER_COV_IMAGE
# Read $COV_OUT/branch_coverage_show.txt for detailed per-line/branch coverage
# Read $COV_OUT/branch_coverage_summary.txt for summary
\`\`\`

To verify a single candidate seed:
\`\`\`bash
mkdir -p /tmp/verify_seed && cp <candidate> /tmp/verify_seed/
docker run --rm -v /tmp/verify_seed:/corpus:ro -v /tmp/verify_cov:/cov_out $DOCKER_COV_IMAGE
# Compare /tmp/verify_cov/branch_coverage_show.txt with baseline
\`\`\`

### Target Source
The libpcap target is built from: https://github.com/the-tcpdump-group/libpcap (commit 17ff63e)
The fuzz harness is \`testprogs/fuzz/fuzz_both.c\`.
The source is inside the Docker image at \`/src/libpcap/\`. You can extract it:
\`\`\`bash
docker run --rm --entrypoint cat $DOCKER_COV_IMAGE /src/libpcap/testprogs/fuzz/fuzz_both.c
\`\`\`

### CRITICAL: Detailed Report Output

In addition to writing seeds to $RESULTS_DIR, you MUST write a detailed JSON report to:
**$REPORT_DIR/blocker_report.json**

The report MUST have this exact structure:
\`\`\`json
{
  \"target\": \"libpcap\",
  \"timestamp\": \"<ISO 8601>\",
  \"baseline_seeds\": $NUM_SEEDS,
  \"baseline_branches_covered\": <number from baseline coverage>,
  \"total_branches_analyzed\": <N>,
  \"discarded\": [
    {
      \"branch_id\": \"<file:line or description>\",
      \"rule\": \"NEG-1|NEG-2|NEG-3|NEG-4\",
      \"evidence\": \"<brief reason>\"
    }
  ],
  \"resolved\": [
    {
      \"branch_id\": \"<file:line or description>\",
      \"seed_file\": \"seed_001\",
      \"attempt_number\": 1,
      \"strategy\": \"nearest_seed|targeted_mutation|semantic_guess|boundary_values|structural_craft\",
      \"strategy_detail\": \"<what specifically was done>\",
      \"hypothesis\": \"<what you thought would trigger the branch>\",
      \"verified\": true,
      \"new_branches_hit\": <number of new branches this seed covers>
    }
  ],
  \"backlogged\": [
    {
      \"branch_id\": \"<file:line or description>\",
      \"attempts\": [
        {
          \"attempt_number\": 1,
          \"strategy\": \"<strategy name>\",
          \"detail\": \"<what was tried>\",
          \"result\": \"<why it failed>\"
        }
      ],
      \"insight\": \"<best guess for future attempts>\"
    }
  ],
  \"summary\": {
    \"total_analyzed\": <N>,
    \"discarded_count\": <N>,
    \"resolved_count\": <N>,
    \"backlogged_count\": <N>,
    \"seeds_generated\": <N>,
    \"final_branches_covered\": <number after adding resolved seeds>
  }
}
\`\`\`

Also write a human-readable summary to: **$REPORT_DIR/summary.txt**

### Your Task
1. Run baseline coverage via Docker to identify uncovered branches
2. Read the coverage report + extract and read target source to understand what's blocking
3. Apply negative rule filtering (NEG-1 through NEG-4) to skip unproductive branches
4. For productive branches, use semantic seed guessing (up to 5 attempts each)
5. Verify each candidate seed via Docker before accepting it
6. Write all verified seeds as files in $RESULTS_DIR (name them seed_001, seed_002, etc.)
7. Write the detailed blocker_report.json and summary.txt to $REPORT_DIR
8. When done, create the file ${IPC_DIR}/done to signal completion

Start by running baseline coverage, then reading the report and target source."

claude -p "$PROMPT" \
    --agent fuzzing-blocker-analyst \
    --max-turns "$AGENT_MAX_TURNS" \
    --dangerously-skip-permissions \
    2>&1 | tee "${OUT_DIR}/agent_session.log" \
    || echo "[run] Agent exited with non-zero status: $?"

# Ensure done signal
if [ ! -f "${IPC_DIR}/done" ]; then
    touch "${IPC_DIR}/done"
fi

# ── Step 4: Summary ───────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "Agent Analysis Complete"
echo "============================================"

NUM_RESULTS=$(find "$RESULTS_DIR" -type f 2>/dev/null | wc -l)
echo "Seeds generated: $NUM_RESULTS"
echo ""
echo "Output structure:"
echo "  out/"
echo "  ├── ipc/seeds/          — input seed corpus ($NUM_SEEDS)"
echo "  ├── ipc/results/        — agent-generated seeds ($NUM_RESULTS)"
echo "  ├── cov_out/            — baseline coverage reports"
echo "  ├── reports/"
echo "  │   ├── blocker_report.json  — detailed per-seed stats"
echo "  │   └── summary.txt          — human-readable summary"
echo "  ├── agent_session.log   — full agent conversation"
echo "  └── prefuzz.log         — pre-fuzz output"

if [ -f "$REPORT_DIR/blocker_report.json" ]; then
    echo ""
    echo "=== Blocker Report Summary ==="
    python3 -c "
import json
with open('$REPORT_DIR/blocker_report.json') as f:
    r = json.load(f)
s = r.get('summary', {})
print(f\"  Branches analyzed: {s.get('total_analyzed', '?')}\")
print(f\"  Discarded (neg rules): {s.get('discarded_count', '?')}\")
print(f\"  Resolved: {s.get('resolved_count', '?')}\")
print(f\"  Backlogged: {s.get('backlogged_count', '?')}\")
print(f\"  Seeds generated: {s.get('seeds_generated', '?')}\")
print(f\"  Baseline branches: {r.get('baseline_branches_covered', '?')}\")
print(f\"  Final branches: {s.get('final_branches_covered', '?')}\")
print()
for res in r.get('resolved', []):
    print(f\"  ✓ {res['branch_id']} → {res['seed_file']} (attempt {res['attempt_number']}, {res['strategy']})\")
    print(f\"    {res['strategy_detail']}\")
" 2>/dev/null || echo "  (Could not parse report)"
fi

if [ -f "$REPORT_DIR/summary.txt" ]; then
    echo ""
    echo "=== Human-Readable Summary ==="
    cat "$REPORT_DIR/summary.txt"
fi
