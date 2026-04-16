#!/usr/bin/env bash
# run_experiment.sh — Run agent_fuzzer vs generic on a target, collect coverage timeseries
#
# Usage:
#   ./agent_fuzzer/run_experiment.sh [--target libpcap] [--trials 3] [--duration 7200]
#
# Output:
#   ./agent_fuzzer/exp_out/<target>/<fuzzer>/trial<N>/         — corpus
#   ./agent_fuzzer/exp_out/coverage_ts/<target>/<fuzzer>/trial<N>/coverage_timeseries.csv

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

TARGET="libpcap"
TRIALS=3
DURATION=7200          # 2 hours
PLATEAU_SECS=300       # 5 minutes
AGENT_BUDGET_SECS=300  # 5 minutes
AGENT_MAX_TURNS=30
INTERVAL_MIN=5         # coverage checkpoint every 5 min
SKIP_BUILD=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --target)       TARGET="$2";           shift 2 ;;
        --trials)       TRIALS="$2";           shift 2 ;;
        --duration)     DURATION="$2";         shift 2 ;;
        --plateau-secs) PLATEAU_SECS="$2";     shift 2 ;;
        --interval)     INTERVAL_MIN="$2";     shift 2 ;;
        --skip-build)   SKIP_BUILD=1;          shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

EXP_DIR="${SCRIPT_DIR}/exp_out"
COV_DIR="${EXP_DIR}/coverage_ts"
mkdir -p "$EXP_DIR"

echo "============================================"
echo "Experiment: agent_fuzzer vs generic"
echo "Target: $TARGET, Trials: $TRIALS, Duration: ${DURATION}s"
echo "Plateau: ${PLATEAU_SECS}s, Agent budget: ${AGENT_BUDGET_SECS}s"
echo "Output: $EXP_DIR"
echo "============================================"

# ── Step 1: Build Docker images (all via shared docker/ folder) ──────────────
if [ "$SKIP_BUILD" = "1" ]; then
    echo ""
    echo "==> Skipping Docker builds (--skip-build)"
else
    echo ""
    echo "==> Building Docker images..."

    echo "  [1/4] libafl-base..."
    docker build -f "$REPO_ROOT/docker/Dockerfile.base" -t libafl-base "$REPO_ROOT" > /dev/null 2>&1

    echo "  [2/4] libafl-${TARGET}-generic..."
    docker build --build-arg FUZZER=generic \
        -f "$REPO_ROOT/docker/targets/Dockerfile.${TARGET}" \
        -t "libafl-${TARGET}-generic" "$REPO_ROOT" > /dev/null 2>&1

    echo "  [3/4] libafl-${TARGET}-agent_fuzzer..."
    docker build --build-arg FUZZER=agent_fuzzer \
        -f "$REPO_ROOT/docker/targets/Dockerfile.${TARGET}" \
        -t "libafl-${TARGET}-agent_fuzzer" "$REPO_ROOT" > /dev/null 2>&1

    echo "  [4/4] libafl-coverage-base + libafl-${TARGET}-cov..."
    docker build -f "$REPO_ROOT/docker/Dockerfile.coverage-base" \
        -t libafl-coverage-base "$REPO_ROOT" > /dev/null 2>&1
    docker build -f "$REPO_ROOT/docker/targets/Dockerfile.${TARGET}.cov" \
        -t "libafl-${TARGET}-cov" "$REPO_ROOT" > /dev/null 2>&1

    echo "==> All images built."
fi

# ── Step 2: Run generic trials ───────────────────────────────────────────────
echo ""
echo "==> Launching generic trials..."
cpu=0

for trial in $(seq 1 "$TRIALS"); do
    name="generic-${TARGET}-trial${trial}"
    corpus="${EXP_DIR}/${TARGET}/generic/trial${trial}"
    mkdir -p "$corpus"

    echo "  Starting ${name} on CPU ${cpu}..."
    docker rm -f "$name" 2>/dev/null || true
    docker run -d \
        --name "$name" \
        --cpuset-cpus "$cpu" \
        --memory "4g" \
        \
        -v "${corpus}:/corpus" \
        -e DURATION="$DURATION" \
        "libafl-${TARGET}-generic" > /dev/null
    (( cpu++ )) || true
done

# ── Step 3: Run agent_fuzzer trials ──────────────────────────────────────────
echo ""
echo "==> Launching agent_fuzzer trials..."

for trial in $(seq 1 "$TRIALS"); do
    name="agent-${TARGET}-trial${trial}"
    corpus="${EXP_DIR}/${TARGET}/agent_fuzzer/trial${trial}"
    ipc_dir="${EXP_DIR}/${TARGET}/agent_fuzzer/trial${trial}_ipc"
    mkdir -p "$corpus" "$ipc_dir"

    echo "  Starting ${name} on CPU ${cpu}..."
    docker rm -f "$name" 2>/dev/null || true
    # Override the shared image's CMD to inject agent-specific flags.
    docker run -d \
        --name "$name" \
        --cpuset-cpus "$cpu" \
        --memory "4g" \
        -v "${corpus}:/corpus" \
        -v "${ipc_dir}:/agent_ipc" \
        -e DURATION="$DURATION" \
        -e PLATEAU_SECS="$PLATEAU_SECS" \
        -e AGENT_BUDGET_SECS="$AGENT_BUDGET_SECS" \
        --entrypoint bash \
        "libafl-${TARGET}-agent_fuzzer" \
        -c 'timeout --kill-after=10 ${DURATION} /fuzz/fuzz_both -o /corpus -i /seeds --plateau-secs ${PLATEAU_SECS} --agent-budget-secs ${AGENT_BUDGET_SECS} --agent-dir /agent_ipc; exit 0' \
        > /dev/null

    # Launch watcher for this trial in background
    echo "  Starting watcher for ${name}..."
    TARGET_NAME="$TARGET" \
    SKIP_DOCKER_BUILD=1 \
    AGENT_MAX_TURNS="$AGENT_MAX_TURNS" \
    POLL_INTERVAL=5 \
        "$SCRIPT_DIR/watch_agent.sh" "$ipc_dir" \
        > "${EXP_DIR}/${name}-watcher.log" 2>&1 &

    (( cpu++ )) || true
done

echo ""
echo "==> All trials launched. ${TRIALS} generic + ${TRIALS} agent_fuzzer = $((TRIALS*2)) containers."
echo ""
docker ps --filter "name=generic-${TARGET}\|agent-${TARGET}" \
    --format "table {{.Names}}\t{{.Status}}"

echo ""
echo "==> Waiting for experiments to complete (${DURATION}s = $((DURATION/3600))h $((DURATION%3600/60))m)..."
echo "    Monitor: docker logs -f <container-name>"
echo "    Stop:    docker stop \$(docker ps -q --filter name=${TARGET})"

# Wait for all containers to finish
for trial in $(seq 1 "$TRIALS"); do
    docker wait "generic-${TARGET}-trial${trial}" > /dev/null 2>&1 || true
    docker wait "agent-${TARGET}-trial${trial}" > /dev/null 2>&1 || true
done

# Kill watchers
pkill -f "watch_agent.sh.*${TARGET}" 2>/dev/null || true

echo ""
echo "==> All trials finished. Collecting coverage timeseries..."

# ── Step 4: Collect coverage timeseries ──────────────────────────────────────
# Use the shared libafl-${TARGET}-cov image with its timeseries entrypoint.

for fuzzer in generic agent_fuzzer; do
    for trial in $(seq 1 "$TRIALS"); do
        corpus="${EXP_DIR}/${TARGET}/${fuzzer}/trial${trial}/queue"
        ts_out="${COV_DIR}/${TARGET}/${fuzzer}/trial${trial}"
        mkdir -p "$ts_out"

        if [ ! -d "$corpus" ] || [ -z "$(ls -A "$corpus" 2>/dev/null)" ]; then
            echo "  [SKIP] ${fuzzer}/trial${trial}: empty corpus"
            continue
        fi

        echo "  Measuring coverage: ${fuzzer}/trial${trial}..."
        docker run --rm \
            -v "${corpus}:/corpus:ro" \
            -v "${ts_out}:/cov_out" \
            --entrypoint python3 \
            "libafl-${TARGET}-cov" \
            /run_coverage_timeseries.py /corpus /cov_out "$INTERVAL_MIN" \
            > "${EXP_DIR}/${fuzzer}-${TARGET}-trial${trial}-cov.log" 2>&1 || \
            echo "  [WARN] Coverage collection failed for ${fuzzer}/trial${trial}"
    done
done

echo ""
echo "==> Coverage timeseries collected at: ${COV_DIR}/"
echo ""
echo "==> Experiment complete!"
echo "    Results: ${EXP_DIR}/${TARGET}/"
echo "    Coverage: ${COV_DIR}/${TARGET}/"
echo ""
echo "To plot: python3 agent_fuzzer/plot_coverage.py"
