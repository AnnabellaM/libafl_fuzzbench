#!/usr/bin/env bash
# run_experiments.sh — build images and run all (fuzzer × target × trial) experiments
#
# Usage:
#   ./docker/run_experiments.sh [--trials N] [--duration SECONDS] [--fuzzers "a b c"] [--targets "x y"]
#
# Examples:
#   ./docker/run_experiments.sh
#   ./docker/run_experiments.sh --trials 5 --duration 86400 --fuzzers "generic fast cmplog"
#
# Section 5.1 experiment (roadblock bypass):
#   ./docker/run_experiments.sh --trials 5 --duration 86400 \
#       --fuzzers "naive cmplog value_profile value_profile_cmplog" \
#       --targets "bloaty lcms libpcap sqlite3 mbedtls"

set -euo pipefail

# ── defaults ────────────────────────────────────────────────────────────────
TRIALS=3
TRIAL_START=1         # first trial index (e.g. set to 4 to add trials 4..N+3)
DURATION=86400        # 24 hours in seconds
FUZZERS="generic fast naive cmplog mopt"
TARGETS="harfbuzz bloaty"
MAX_PARALLEL=64       # max simultaneous trial containers; trials beyond this batch
RESULTS_DIR="$(pwd)/out"
SEEDS_DIR="$(pwd)/docker/seeds"
# ── arg parsing ─────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --trials)       TRIALS="$2";       shift 2 ;;
        --trial-start)  TRIAL_START="$2";  shift 2 ;;
        --duration)     DURATION="$2";     shift 2 ;;
        --fuzzers)      FUZZERS="$2";      shift 2 ;;
        --targets)      TARGETS="$2";      shift 2 ;;
        --max-parallel) MAX_PARALLEL="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

mkdir -p "$RESULTS_DIR"

# ── step 1: build base image ─────────────────────────────────────────────────
echo "==> Building base image (libafl-base)..."
docker build \
    -f docker/Dockerfile.base \
    -t libafl-base \
    .

# ── step 2: build per-(fuzzer, target) images ────────────────────────────────
failed_builds=()
for target in $TARGETS; do
    for fuzzer in $FUZZERS; do
        image="libafl-${target}-${fuzzer}"
        echo "==> Building ${image}..."
        if ! docker build \
            --build-arg FUZZER="${fuzzer}" \
            -f "docker/targets/Dockerfile.${target}" \
            -t "${image}" \
            .; then
            echo "!!! Build failed for ${image}, skipping."
            failed_builds+=("${image}")
        fi
    done
done

if [[ ${#failed_builds[@]} -gt 0 ]]; then
    echo ""
    echo "==> The following images failed to build and will be skipped:"
    for img in "${failed_builds[@]}"; do echo "    ${img}"; done
fi

# ── step 3: launch experiments in batches of MAX_PARALLEL ───────────────────
# Build the flat list of (target, fuzzer, trial) tuples, skipping failed builds.
combos=()
for target in $TARGETS; do
    for fuzzer in $FUZZERS; do
        image="libafl-${target}-${fuzzer}"
        if [[ " ${failed_builds[*]} " == *" ${image} "* ]]; then
            continue
        fi
        for trial in $(seq "$TRIAL_START" $((TRIAL_START + TRIALS - 1))); do
            combos+=("$target $fuzzer $trial")
        done
    done
done

total=${#combos[@]}
echo "==> ${total} trial(s) queued; running ${MAX_PARALLEL} in parallel."

i=0
batch_idx=0
while (( i < total )); do
    batch_idx=$((batch_idx + 1))
    cids=()
    log_pids=()
    cpu=${CPU_START:-0}
    batch_size=0
    while (( batch_size < MAX_PARALLEL && i < total )); do
        read -r target fuzzer trial <<< "${combos[$i]}"
        image="libafl-${target}-${fuzzer}"
        name="${target}-${fuzzer}-trial${trial}"
        corpus="${RESULTS_DIR}/${target}/${fuzzer}/trial${trial}"
        seeds="${SEEDS_DIR}/${target}"
        mkdir -p "$corpus"

        seed_vol=()
        if [ -d "${seeds}" ] && [ -n "$(ls -A "${seeds}" 2>/dev/null)" ]; then
            seed_vol=(-v "${seeds}:/seeds:ro")
        fi

        # Remove any stale container with the same name (from a prior aborted run).
        docker rm -f "${name}" >/dev/null 2>&1 || true

        echo "==> [batch ${batch_idx}] Starting ${name} on CPU ${cpu}..."
        cid=$(docker run -d \
            --name "${name}" \
            --cpuset-cpus "${cpu}" \
            --memory "4g" \
            -v "${corpus}:/corpus" \
            "${seed_vol[@]}" \
            -e DURATION="${DURATION}" \
            "${image}")
        docker logs -f "${cid}" > "${RESULTS_DIR}/${name}.log" 2>&1 &
        log_pids+=($!)
        cids+=("$cid")
        (( cpu++ )) || true
        i=$((i + 1))
        batch_size=$((batch_size + 1))
    done

    echo "==> [batch ${batch_idx}] ${#cids[@]} containers launched; waiting for completion..."
    for cid in "${cids[@]}"; do
        docker wait "$cid" >/dev/null
    done
    # Reap log followers and clean up containers.
    for pid in "${log_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    for cid in "${cids[@]}"; do
        docker rm "$cid" >/dev/null 2>&1 || true
    done
    echo "==> [batch ${batch_idx}] complete."
done

echo ""
echo "==> All ${total} trial(s) finished."
echo "Results at:        ${RESULTS_DIR}/"
