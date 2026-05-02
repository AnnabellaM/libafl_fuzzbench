#!/usr/bin/env bash
# run_sqlite3_experiment.sh — 1-hour comparison: agent_fuzzer vs generic on sqlite3
#
# Output:
#   ./agent_fuzzer/out/sqlite3/<fuzzer>/trial1/          — corpus
#   ./agent_fuzzer/out/sqlite3/coverage_ts/<fuzzer>/...   — coverage timeseries
#   ./agent_fuzzer/out/sqlite3/agent_reports/trial<N>/    — per-trial agent reports

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

TARGET="sqlite3"
TRIALS="${TRIALS:-1}"
DURATION="${DURATION:-3600}"               # default 1 hour, override via env
PLATEAU_SECS="${PLATEAU_SECS:-90}"
AGENT_BUDGET_SECS="${AGENT_BUDGET_SECS:-300}"
AGENT_MAX_TURNS="${AGENT_MAX_TURNS:-50}"
AGENT_BRIDGE="${AGENT_BRIDGE:-run_agent.sh}"  # run_agent_loop.sh for AGENT_USE_LOOP path
INTERVAL_MIN="${INTERVAL_MIN:-5}"
FUZZ_BIN="ossfuzz"

EXP_DIR="${SCRIPT_DIR}/out/${TARGET}"
COV_DIR="${EXP_DIR}/coverage_ts"
REPORT_DIR="${EXP_DIR}/agent_reports"
mkdir -p "$EXP_DIR" "$COV_DIR" "$REPORT_DIR"

echo "============================================"
echo "Experiment: agent_fuzzer vs generic on sqlite3"
echo "Duration: ${DURATION}s (1h), Trials: $TRIALS"
echo "Plateau: ${PLATEAU_SECS}s, Agent budget: ${AGENT_BUDGET_SECS}s"
echo "Output: $EXP_DIR"
echo "============================================"

# ── Step 1: Build Docker images ────────────────────────────────────────────
echo ""
echo "==> Building Docker images..."

echo "  [1/4] libafl-base (checking cache)..."
docker build -f "$REPO_ROOT/docker/Dockerfile.base" -t libafl-base "$REPO_ROOT" > /dev/null 2>&1

echo "  [2/4] libafl-sqlite3-generic..."
docker build --build-arg FUZZER=generic \
    -f "$REPO_ROOT/docker/targets/Dockerfile.sqlite3" \
    -t "libafl-sqlite3-generic" "$REPO_ROOT" > "${EXP_DIR}/build-generic.log" 2>&1

echo "  [3/4] libafl-sqlite3-agent_fuzzer..."
docker build --build-arg FUZZER=agent_fuzzer \
    -f "$REPO_ROOT/docker/targets/Dockerfile.sqlite3" \
    -t "libafl-sqlite3-agent_fuzzer" "$REPO_ROOT" > "${EXP_DIR}/build-agent.log" 2>&1

echo "  [4/4] libafl-coverage-base + agent-cov-sqlite3..."
docker build -f "$REPO_ROOT/docker/Dockerfile.coverage-base" \
    -t libafl-coverage-base "$REPO_ROOT" > /dev/null 2>&1
docker build -f "$REPO_ROOT/docker/targets/Dockerfile.sqlite3.cov" \
    -t "agent-cov-sqlite3" "$REPO_ROOT" > "${EXP_DIR}/build-cov.log" 2>&1
# Also tag for the experiment coverage collection step
docker tag "agent-cov-sqlite3" "libafl-sqlite3-cov"

echo "==> All images built."

# ── Step 2: Run generic trials ─────────────────────────────────────────────
echo ""
echo "==> Launching generic trial..."
cpu=0

for trial in $(seq 1 "$TRIALS"); do
    name="generic-${TARGET}-trial${trial}"
    corpus="${EXP_DIR}/generic/trial${trial}"
    mkdir -p "$corpus"

    echo "  Starting ${name} on CPU ${cpu}..."
    docker rm -f "$name" 2>/dev/null || true
    docker run -d \
        --name "$name" \
        --cpuset-cpus "$cpu" \
        --memory "4g" \
        -v "${corpus}:/corpus" \
        -e DURATION="$DURATION" \
        "libafl-sqlite3-generic" > /dev/null
    (( cpu++ )) || true
done

# ── Step 3: Run agent_fuzzer trials ────────────────────────────────────────
echo ""
echo "==> Launching agent_fuzzer trial..."

for trial in $(seq 1 "$TRIALS"); do
    name="agent-${TARGET}-trial${trial}"
    corpus="${EXP_DIR}/agent_fuzzer/trial${trial}"
    ipc_dir="${EXP_DIR}/agent_fuzzer/trial${trial}_ipc"
    report_trial_dir="${REPORT_DIR}/trial${trial}"
    mkdir -p "$corpus" "$ipc_dir" "$report_trial_dir"

    echo "  Starting ${name} on CPU ${cpu}..."
    docker rm -f "$name" 2>/dev/null || true
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
        "libafl-sqlite3-agent_fuzzer" \
        -c "timeout --kill-after=10 \${DURATION} /fuzz/${FUZZ_BIN} -o /corpus -i /seeds --plateau-secs \${PLATEAU_SECS} --agent-budget-secs \${AGENT_BUDGET_SECS} --agent-dir /agent_ipc; exit 0" \
        > /dev/null

    # Launch watcher for this trial in background
    echo "  Starting watcher for ${name}..."
    TARGET_NAME="$TARGET" \
    SKIP_DOCKER_BUILD=1 \
    AGENT_MAX_TURNS="$AGENT_MAX_TURNS" \
    AGENT_BRIDGE="$AGENT_BRIDGE" \
    POLL_INTERVAL=5 \
        "$SCRIPT_DIR/watch_agent.sh" "$ipc_dir" \
        > "${EXP_DIR}/agent-watcher-trial${trial}.log" 2>&1 &

    (( cpu++ )) || true
done

echo ""
echo "==> All trials launched."
docker ps --filter "name=generic-${TARGET}\|agent-${TARGET}" \
    --format "table {{.Names}}\t{{.Status}}"

echo ""
echo "==> Waiting for experiments to complete (${DURATION}s = 1h)..."
echo "    Monitor: docker logs -f <container-name>"
echo "    Agent watcher log: tail -f ${EXP_DIR}/agent-watcher-trial1.log"
echo ""

# Wait for all containers to finish
for trial in $(seq 1 "$TRIALS"); do
    docker wait "generic-${TARGET}-trial${trial}" > /dev/null 2>&1 || true
    docker wait "agent-${TARGET}-trial${trial}" > /dev/null 2>&1 || true
done

# Kill watchers
pkill -f "watch_agent.sh.*${TARGET}" 2>/dev/null || true

echo ""
echo "==> All trials finished. Collecting coverage timeseries..."

# ── Step 4: Collect coverage timeseries ────────────────────────────────────
for fuzzer in generic agent_fuzzer; do
    for trial in $(seq 1 "$TRIALS"); do
        corpus="${EXP_DIR}/${fuzzer}/trial${trial}/queue"
        ts_out="${COV_DIR}/${fuzzer}/trial${trial}"
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
            "libafl-sqlite3-cov" \
            /run_coverage_timeseries.py /corpus /cov_out "$INTERVAL_MIN" \
            > "${EXP_DIR}/${fuzzer}-cov-trial${trial}.log" 2>&1 || \
            echo "  [WARN] Coverage collection failed for ${fuzzer}/trial${trial}"
    done
done

# ── Step 5: Collect agent reports ──────────────────────────────────────────
echo ""
echo "==> Collecting agent reports..."
for trial in $(seq 1 "$TRIALS"); do
    ipc_dir="${EXP_DIR}/agent_fuzzer/trial${trial}_ipc"
    report_trial_dir="${REPORT_DIR}/trial${trial}"

    # The agent may have been invoked multiple times (multiple plateau cycles).
    # Each cycle's results are cleaned up by the fuzzer, but the watcher log has the history.
    # Copy whatever reports exist in the ipc_dir.
    cp "$ipc_dir"/results/* "$report_trial_dir/" 2>/dev/null || true
    cp "${EXP_DIR}/agent-watcher-trial${trial}.log" "$report_trial_dir/" 2>/dev/null || true

    echo "  Trial $trial: $(find "$report_trial_dir" -type f | wc -l) files collected"
done

# ── Step 6: Final summary ─────────────────────────────────────────────────
echo ""
echo "============================================"
echo "Experiment Complete: sqlite3 (1 hour)"
echo "============================================"
echo ""
echo "Output structure:"
echo "  out/sqlite3/"
echo "  ├── generic/trial1/          — generic fuzzer corpus"
echo "  ├── agent_fuzzer/trial1/     — agent fuzzer corpus"
echo "  ├── agent_fuzzer/trial1_ipc/ — IPC directory"
echo "  ├── coverage_ts/             — coverage timeseries CSVs"
echo "  ├── agent_reports/trial1/    — agent seeds + watcher log"
echo "  └── *.log                    — build + watcher logs"
echo ""

# Quick coverage comparison
echo "=== Final Coverage ==="
for fuzzer in generic agent_fuzzer; do
    for trial in $(seq 1 "$TRIALS"); do
        ts_file="${COV_DIR}/${fuzzer}/trial${trial}/coverage_timeseries.csv"
        if [ -f "$ts_file" ]; then
            last_line=$(tail -1 "$ts_file")
            echo "  ${fuzzer}/trial${trial}: $last_line"
        else
            echo "  ${fuzzer}/trial${trial}: (no timeseries data)"
        fi
    done
done
