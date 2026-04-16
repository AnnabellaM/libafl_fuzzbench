#!/bin/bash
# Quick test for the agent_fuzzer.
# Usage: ./test.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
WORK_DIR="/tmp/agent_fuzzer_test"

echo "=== Building agent_fuzzer ==="
cd "$REPO_DIR"
cargo build --release -p agent_fuzzer

# Compiler wrapper is at target/release/agent_fuzzer_cc
CC="$REPO_DIR/target/release/agent_fuzzer_cc"

echo "=== Compiling test harness ==="
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/seeds" "$WORK_DIR/corpus" "$WORK_DIR/agent_ipc"

# Compile the test harness with LibAFL instrumentation
"$CC" --libafl "$SCRIPT_DIR/test_harness.c" -o "$WORK_DIR/fuzzer" -lm -lstdc++

# Create a minimal seed
echo -n "AAAA" > "$WORK_DIR/seeds/seed0"

echo "=== Running fuzzer (short plateau timeout for testing) ==="
echo "Fuzzer binary: $WORK_DIR/fuzzer"
echo "Seeds: $WORK_DIR/seeds/"
echo "Corpus output: $WORK_DIR/corpus/"
echo "Agent IPC dir: $WORK_DIR/agent_ipc/"
echo ""
echo "The fuzzer will run with a 30s plateau timeout."
echo "When it pauses, it will export seeds to $WORK_DIR/agent_ipc/seeds/"
echo "and wait for you (or your agent) to:"
echo "  1. Write new seeds to $WORK_DIR/agent_ipc/results/"
echo "  2. Touch $WORK_DIR/agent_ipc/done"
echo ""
echo "To simulate the agent manually:"
echo "  mkdir -p $WORK_DIR/agent_ipc/results"
echo "  echo -n 'FUZZKILL' > $WORK_DIR/agent_ipc/results/seed_agent_0"
echo "  touch $WORK_DIR/agent_ipc/done"
echo ""
echo "Press Ctrl+C to stop."
echo ""

# Use the Claude Code agent if `claude` CLI is available, otherwise manual mode
AGENT_CMD=""
if command -v claude &>/dev/null; then
    echo "Claude CLI found — using fuzzing-blocker-analyst agent automatically."
    AGENT_CMD="--agent-cmd $SCRIPT_DIR/run_agent.sh"
    export TARGET_SOURCE="$SCRIPT_DIR/test_harness.c"
    export TARGET_NAME="test_harness"
else
    echo "No Claude CLI — running in manual agent mode."
    echo "To simulate the agent manually:"
    echo "  mkdir -p $WORK_DIR/agent_ipc/results"
    echo "  echo -n 'DEEPSEED' > $WORK_DIR/agent_ipc/results/seed_agent_0"
    echo "  touch $WORK_DIR/agent_ipc/done"
fi
echo ""

"$WORK_DIR/fuzzer" \
    -o "$WORK_DIR/corpus" \
    -i "$WORK_DIR/seeds" \
    -t 1000 \
    --plateau-secs 30 \
    --agent-budget-secs 120 \
    --agent-dir "$WORK_DIR/agent_ipc" \
    $AGENT_CMD
