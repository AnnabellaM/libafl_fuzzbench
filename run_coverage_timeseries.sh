#!/usr/bin/env bash
# run_coverage_timeseries.sh — generate time-series branch coverage CSVs
#
# For each (target, fuzzer, trial), replays the corpus in chronological order
# using the per-input elapsed_ms from LibAFL metadata files, and records branch
# coverage at regular intervals.
#
# Prerequisites: coverage Docker images must already be built
#   (run docker/run_coverage.sh first, or at least build the *-cov images)
#
# Usage:
#   ./run_coverage_timeseries.sh [--targets "a b"] [--fuzzers "x y"] \
#                                [--trials N] [--interval MIN]
#
# Output:
#   ./out/coverage/<target>/<fuzzer>/trial<N>/coverage_timeseries.csv

set -euo pipefail

TARGETS="bloaty lcms libpcap mbedtls sqlite3"
FUZZERS="naive cmplog value_profile value_profile_cmplog"
TRIALS=3
INTERVAL_MIN=30
RESULTS_DIR="$(pwd)/out"
COV_DIR="${RESULTS_DIR}/coverage"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

while [[ $# -gt 0 ]]; do
    case $1 in
        --targets)  TARGETS="$2";       shift 2 ;;
        --fuzzers)  FUZZERS="$2";       shift 2 ;;
        --trials)   TRIALS="$2";        shift 2 ;;
        --interval) INTERVAL_MIN="$2";  shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

ENTRYPOINT_SCRIPT="${SCRIPT_DIR}/docker/run_coverage_timeseries_entrypoint.py"
if [[ ! -f "${ENTRYPOINT_SCRIPT}" ]]; then
    echo "Error: entrypoint not found at ${ENTRYPOINT_SCRIPT}"
    exit 1
fi

for target in $TARGETS; do
    image="libafl-${target}-cov"
    if ! docker image inspect "${image}" &>/dev/null; then
        echo "  Skipping ${target}: image ${image} not found"
        continue
    fi

    for fuzzer in $FUZZERS; do
        for trial in $(seq 1 "$TRIALS"); do
            corpus="${RESULTS_DIR}/${target}/${fuzzer}/trial${trial}/queue"
            out_dir="${COV_DIR}/${target}/${fuzzer}/trial${trial}"
            csv_out="${out_dir}/coverage_timeseries.csv"

            if [[ ! -d "${corpus}" ]]; then
                echo "  Skipping ${target}/${fuzzer}/trial${trial}: no queue dir"
                continue
            fi

            if [[ -f "${csv_out}" ]]; then
                echo "  Already done: ${target}/${fuzzer}/trial${trial} — skipping"
                continue
            fi

            mkdir -p "${out_dir}"
            echo "==> Time-series coverage: ${target}/${fuzzer}/trial${trial} ..."

            docker run --rm \
                -v "${corpus}:/corpus:ro" \
                -v "${out_dir}:/cov_out" \
                -v "${ENTRYPOINT_SCRIPT}:/run_coverage_timeseries.py:ro" \
                --entrypoint python3 \
                "${image}" \
                /run_coverage_timeseries.py /corpus /cov_out "${INTERVAL_MIN}"

            if [[ -f "${csv_out}" ]]; then
                echo "    -> ${csv_out}"
            else
                echo "    !! No CSV produced for ${target}/${fuzzer}/trial${trial}"
            fi
        done
    done
done

echo ""
echo "==> Done. CSVs under ${COV_DIR}/"
find "${COV_DIR}" -name "coverage_timeseries.csv" | sort | while read -r f; do
    lines=$(wc -l < "$f")
    echo "  ${f}  (${lines} rows)"
done
