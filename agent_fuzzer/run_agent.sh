#!/bin/bash
# Bridge script: connects the LibAFL fuzzer's IPC protocol to the
# fuzzing-blocker-analyst Claude Code agent.
#
# Usage: run_agent.sh <agent_dir>
#   - Reads seeds from <agent_dir>/seeds/
#   - Reads manifest from <agent_dir>/request.json
#   - Builds (or reuses) a Docker image with the coverage-instrumented target
#   - Invokes the Claude Code agent to analyze blockers and generate seeds
#   - Agent verifies seeds via Docker container running llvm-cov
#   - Agent writes results to <agent_dir>/results/
#   - Touches <agent_dir>/done when finished
#
# Environment variables:
#   TARGET_SOURCE   — path to target source file (for semantic analysis)
#   TARGET_NAME     — target name for Docker build (default: test_harness)
#   (Docker build context is agent_fuzzer/ itself — self-contained)
#   AGENT_MAX_TURNS — max Claude agent turns (default: 30)
#   SKIP_DOCKER_BUILD — set to 1 to skip Docker image build (reuse existing)

set -euo pipefail

AGENT_DIR="${1:?Usage: run_agent.sh <agent_dir>}"
AGENT_DIR="$(cd "$AGENT_DIR" && pwd)"

SEEDS_DIR="$AGENT_DIR/seeds"
RESULTS_DIR="$AGENT_DIR/results"
DONE_FILE="$AGENT_DIR/done"
MANIFEST="$AGENT_DIR/request.json"

TARGET_SOURCE="${TARGET_SOURCE:-}"
TARGET_NAME="${TARGET_NAME:-test_harness}"
AGENT_MAX_TURNS="${AGENT_MAX_TURNS:-30}"
SKIP_DOCKER_BUILD="${SKIP_DOCKER_BUILD:-0}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

DOCKER_IMAGE="agent-cov-${TARGET_NAME}"

# Ensure results directory exists and is clean
rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

# ── Step 1: Build coverage Docker image ──────────────────────────────────
if [ "$SKIP_DOCKER_BUILD" != "1" ]; then
    echo "[run_agent.sh] Building coverage image: $DOCKER_IMAGE (target=$TARGET_NAME)..."

    # Self-contained: Dockerfile.agent-cov includes the base stage,
    # build context is agent_fuzzer/ itself
    docker build -f "$SCRIPT_DIR/Dockerfile.agent-cov" \
        --build-arg TARGET="$TARGET_NAME" \
        -t "$DOCKER_IMAGE" \
        "$SCRIPT_DIR"

    echo "[run_agent.sh] Docker image ready: $DOCKER_IMAGE"
else
    echo "[run_agent.sh] Skipping Docker build (SKIP_DOCKER_BUILD=1), reusing $DOCKER_IMAGE"
fi

# ── Step 2: Build prompt for Claude Code agent ───────────────────────────
NUM_SEEDS=$(find "$SEEDS_DIR" -type f 2>/dev/null | wc -l)

PROMPT="## Fuzzer Plateau — Blocker Resolution Request

The fuzzer has detected a coverage plateau and needs your help to break through.

### IPC Paths
- Seeds (current queue): $SEEDS_DIR ($NUM_SEEDS seeds)
- Manifest: $MANIFEST
- Write resolved seeds to: $RESULTS_DIR
- Signal completion by creating: $DONE_FILE"

if [ -n "$TARGET_SOURCE" ] && [ -f "$TARGET_SOURCE" ]; then
    PROMPT="$PROMPT

### Target Source
The target source code is at: $TARGET_SOURCE
Read it to understand branch conditions and guide your seed generation."
fi

COV_OUT="$AGENT_DIR/cov_out"

PROMPT="$PROMPT

### Coverage Verification via Docker
A Docker image \`$DOCKER_IMAGE\` is available with the coverage-instrumented target.

**Run coverage on seeds:**
\`\`\`bash
docker run --rm -v $SEEDS_DIR:/seeds -v $COV_OUT:/cov_out $DOCKER_IMAGE /seeds /cov_out
# Read $COV_OUT/branch_coverage_show.txt for detailed per-line/branch coverage
# Read $COV_OUT/branch_coverage_summary.txt for summary
\`\`\`

You can use the same command to verify candidate seeds — put them in a temp directory and run coverage on that directory. Compare the reports to see if new branches were hit.

### Your Task
1. Run baseline coverage via Docker to identify uncovered branches
2. Read the coverage report + target source to understand what's blocking
3. Apply negative rule filtering (NEG-1 through NEG-4) to skip unproductive branches
4. For productive branches, use semantic seed guessing (up to 5 attempts each)
5. Verify each candidate seed via Docker before accepting it
6. Write all verified seeds as files in $RESULTS_DIR (name them seed_001, seed_002, etc.)
7. When done, create the file $DONE_FILE to signal the fuzzer to resume

Start by running baseline coverage, then reading the report and target source."

# ── Step 3: Invoke Claude Code agent ─────────────────────────────────────
echo "[run_agent.sh] Invoking fuzzing-blocker-analyst agent..."
echo "[run_agent.sh] Seeds: $NUM_SEEDS, Target: $TARGET_NAME, Image: $DOCKER_IMAGE"

claude -p "$PROMPT" \
    --agent fuzzing-blocker-analyst \
    --max-turns "$AGENT_MAX_TURNS" \
    --dangerously-skip-permissions \
    || echo "[run_agent.sh] Agent exited with non-zero status: $?"

# ── Step 4: Ensure done signal ───────────────────────────────────────────
if [ ! -f "$DONE_FILE" ]; then
    echo "[run_agent.sh] Agent did not create done signal, creating it now."
    touch "$DONE_FILE"
fi

NUM_RESULTS=$(find "$RESULTS_DIR" -type f 2>/dev/null | wc -l)
echo "[run_agent.sh] Agent phase complete. Generated $NUM_RESULTS seed(s)."
