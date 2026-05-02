#!/bin/bash
# Host-side watcher: monitors the IPC directory for plateau signals from the
# fuzzer (running inside Docker) and invokes the Claude Code agent.
#
# Usage:
#   ./watch_agent.sh <agent_ipc_dir> [options]
#
# The fuzzer container mounts this directory and writes request.json when it
# hits a plateau. This script detects the request, runs run_agent.sh, and
# the fuzzer picks up results when it sees the done file.
#
# Environment variables (passed through to run_agent.sh):
#   TARGET_SOURCE   — path to target source file
#   TARGET_NAME     — target name for Docker coverage image (default: libpcap)
#   AGENT_MAX_TURNS — max Claude agent turns (default: 30)
#   SKIP_DOCKER_BUILD — set to 1 after first run to reuse coverage image

set -euo pipefail

AGENT_DIR="${1:?Usage: watch_agent.sh <agent_ipc_dir>}"
AGENT_DIR="$(cd "$AGENT_DIR" 2>/dev/null && pwd)" || { echo "Directory $1 does not exist"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POLL_INTERVAL="${POLL_INTERVAL:-5}"

# Bridge script: either the old fuzzing-blocker-analyst prompt (run_agent.sh)
# or the new Python loop (run_agent_loop.sh). Default: run_agent.sh for
# back-compat; set AGENT_BRIDGE=run_agent_loop.sh for the loop path.
AGENT_BRIDGE="${AGENT_BRIDGE:-run_agent.sh}"

REQUEST="$AGENT_DIR/request.json"
DONE="$AGENT_DIR/done"

echo "[watcher] Watching $AGENT_DIR for plateau signals (poll every ${POLL_INTERVAL}s)"
echo "[watcher] Press Ctrl+C to stop"

while true; do
    # Wait for request.json (fuzzer cleans it up after each cycle)
    if [ -f "$REQUEST" ]; then
        echo ""
        echo "[watcher] ============================================"
        echo "[watcher] Plateau signal detected at $(date)"
        echo "[watcher] ============================================"

        # Invoke the agent bridge
        "$SCRIPT_DIR/$AGENT_BRIDGE" "$AGENT_DIR"

        echo "[watcher] Agent phase complete. Fuzzer will resume."
        echo "[watcher] Resuming watch..."
        echo ""

        # Brief pause to let the fuzzer pick up the done file and clean up
        sleep 2
    fi

    sleep "$POLL_INTERVAL"
done
