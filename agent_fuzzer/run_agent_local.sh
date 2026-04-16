#!/bin/bash
# Local (no-Docker) agent bridge for quick test_harness testing.
# Invokes the fuzzing-blocker-analyst Claude Code agent, pointing it at a
# locally compiled coverage-instrumented binary.
#
# Required env vars:
#   TARGET_SOURCE  — path to target source (.c file)
#   VERIFY_BIN     — path to coverage-instrumented verify binary
#
# Optional:
#   AGENT_MAX_TURNS — default 30

set -euo pipefail

AGENT_DIR="${1:?Usage: run_agent_local.sh <agent_dir>}"
AGENT_DIR="$(cd "$AGENT_DIR" && pwd)"

# Debug logging — capture everything to a file since fuzzer may swallow stdio
DEBUG_LOG="$AGENT_DIR/agent_debug.log"
exec > >(tee -a "$DEBUG_LOG") 2>&1
echo "===== run_agent_local.sh START $(date +%s) ====="
echo "PID=$$ PPID=$PPID CWD=$(pwd)"
echo "ARGS: $*"
echo "ENV (filtered):"
env | grep -iE "^(HOME|USER|PATH|ANTHROPIC|TARGET|VERIFY|AGENT|CLAUDE)" | sort
echo "claude path: $(command -v claude || echo NOT_FOUND)"
echo "==========================================="

SEEDS_DIR="$AGENT_DIR/seeds"
RESULTS_DIR="$AGENT_DIR/results"
DONE_FILE="$AGENT_DIR/done"
MANIFEST="$AGENT_DIR/request.json"

TARGET_SOURCE="${TARGET_SOURCE:?TARGET_SOURCE env var required}"
VERIFY_BIN="${VERIFY_BIN:?VERIFY_BIN env var required}"
AGENT_MAX_TURNS="${AGENT_MAX_TURNS:-30}"

rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

NUM_SEEDS=$(find "$SEEDS_DIR" -type f 2>/dev/null | wc -l)

PROMPT="## Fuzzer Plateau — Blocker Resolution Request

The fuzzer has detected a coverage plateau and needs your help to break through.

### IPC Paths
- Seeds (current queue): $SEEDS_DIR ($NUM_SEEDS seeds)
- Manifest: $MANIFEST
- Write resolved seeds to: $RESULTS_DIR
- Signal completion by creating: $DONE_FILE

### Target Source
The target source code is at: $TARGET_SOURCE
Read it to understand branch conditions and guide your seed generation.

### Coverage Verification (LOCAL, no Docker)
A coverage-instrumented binary is available at: $VERIFY_BIN

To measure coverage for a candidate seed file:
\`\`\`bash
LLVM_PROFILE_FILE=/tmp/cov_\$\$.profraw $VERIFY_BIN <seed_file>
llvm-profdata merge -sparse /tmp/cov_\$\$.profraw -o /tmp/cov_\$\$.profdata
llvm-cov show $VERIFY_BIN -instr-profile=/tmp/cov_\$\$.profdata $TARGET_SOURCE
\`\`\`

Use \`llvm-cov report\` for a summary or \`llvm-cov show\` for per-line coverage.
You can merge multiple .profraw files to see cumulative coverage of a seed set.

### Your Task
1. Run coverage on the current queue to identify which branches are uncovered
2. Read the target source to understand what inputs trigger the uncovered branches
3. Apply negative rule filtering (NEG-1..NEG-4) to skip unproductive branches
4. For productive branches, use semantic seed guessing (up to 5 attempts)
5. Verify each candidate by running it through $VERIFY_BIN and checking llvm-cov
6. Write verified seeds to $RESULTS_DIR (name them seed_001, seed_002, ...)
7. Create $DONE_FILE when finished

Start now."

echo "[run_agent_local.sh] Invoking fuzzing-blocker-analyst agent..."
echo "[run_agent_local.sh] Seeds: $NUM_SEEDS  Target: $TARGET_SOURCE  Verify: $VERIFY_BIN"

claude -p "$PROMPT" \
    --agent fuzzing-blocker-analyst \
    --max-turns "$AGENT_MAX_TURNS" \
    --dangerously-skip-permissions \
    || echo "[run_agent_local.sh] Agent exited with non-zero status: $?"

if [ ! -f "$DONE_FILE" ]; then
    echo "[run_agent_local.sh] Agent did not create done signal, creating it now."
    touch "$DONE_FILE"
fi

NUM_RESULTS=$(find "$RESULTS_DIR" -type f 2>/dev/null | wc -l)
echo "[run_agent_local.sh] Agent phase complete. Generated $NUM_RESULTS seed(s)."
