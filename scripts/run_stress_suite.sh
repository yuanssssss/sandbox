#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="configs/minimal.toml"
SCENARIO="echo_burst"
ITERATIONS=12
CONCURRENCY=4
ARTIFACT_ROOT=".sandbox-runs/stress"
REPORT_PATH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)
            CONFIG="$2"
            shift 2
            ;;
        --scenario)
            SCENARIO="$2"
            shift 2
            ;;
        --iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        --concurrency)
            CONCURRENCY="$2"
            shift 2
            ;;
        --artifact-root)
            ARTIFACT_ROOT="$2"
            shift 2
            ;;
        --report)
            REPORT_PATH="$2"
            shift 2
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

case "$SCENARIO" in
    echo_burst)
        COMMAND=(/bin/echo stress-ok)
        ;;
    workdir_round_trip)
        COMMAND=(/bin/sh -c "printf 'stress' > /work/stress.txt && cat /work/stress.txt")
        ;;
    cpu_bound_success)
        COMMAND=(
            /usr/bin/python3
            -c
            $'total = 0\nfor i in range(500000):\n total += i\nprint(total > 0)'
        )
        ;;
    *)
        echo "unknown stress scenario: $SCENARIO" >&2
        exit 2
        ;;
esac

cd "$ROOT_DIR"
cargo build -p sandbox-cli >/dev/null

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ROOT="$ARTIFACT_ROOT/$TIMESTAMP"
mkdir -p "$RUN_ROOT"

run_one() {
    local iteration="$1"
    local run_dir="$RUN_ROOT/run-$iteration"
    mkdir -p "$run_dir"

    local status=0
    if ! target/debug/sandbox-cli --log-level warn run --config "$CONFIG" --artifact-dir "$run_dir" --result-format json --command "${COMMAND[@]}" >"$run_dir/cli.stdout" 2>"$run_dir/cli.stderr"; then
        status=$?
    fi

    printf '%s\n' "$status" >"$run_dir/exit_code"
}

START_EPOCH="$(date +%s)"
running=0
for iteration in $(seq 1 "$ITERATIONS"); do
    run_one "$iteration" &
    running=$((running + 1))
    if (( running >= CONCURRENCY )); then
        if ! wait -n; then
            :
        fi
        running=$((running - 1))
    fi
done

while (( running > 0 )); do
    if ! wait -n; then
        :
    fi
    running=$((running - 1))
done

END_EPOCH="$(date +%s)"
DURATION_SECONDS=$((END_EPOCH - START_EPOCH))
PASSED_RUNS=0
FAILED_RUNS=0
FAILURE_ARTIFACTS=()

for exit_file in "$RUN_ROOT"/run-*/exit_code; do
    status="$(tr -d '\n' <"$exit_file")"
    if [[ "$status" == "0" ]]; then
        PASSED_RUNS=$((PASSED_RUNS + 1))
    else
        FAILED_RUNS=$((FAILED_RUNS + 1))
        FAILURE_ARTIFACTS+=("$(dirname "$exit_file")")
    fi
done

SUMMARY_JSON="$RUN_ROOT/summary.json"
{
    printf '{\n'
    printf '  "generated_at_utc": "%s",\n' "$TIMESTAMP"
    printf '  "config": "%s",\n' "$CONFIG"
    printf '  "scenario": "%s",\n' "$SCENARIO"
    printf '  "iterations": %s,\n' "$ITERATIONS"
    printf '  "concurrency": %s,\n' "$CONCURRENCY"
    printf '  "duration_seconds": %s,\n' "$DURATION_SECONDS"
    printf '  "passed_runs": %s,\n' "$PASSED_RUNS"
    printf '  "failed_runs": %s,\n' "$FAILED_RUNS"
    printf '  "artifact_root": "%s",\n' "$RUN_ROOT"
    printf '  "failure_artifacts": ['
    for i in "${!FAILURE_ARTIFACTS[@]}"; do
        if (( i > 0 )); then
            printf ', '
        fi
        printf '"%s"' "${FAILURE_ARTIFACTS[$i]}"
    done
    printf ']\n'
    printf '}\n'
} >"$SUMMARY_JSON"

DEFAULT_REPORT_PATH="$RUN_ROOT/report.md"
if [[ -n "$REPORT_PATH" ]]; then
    mkdir -p "$(dirname "$REPORT_PATH")"
else
    REPORT_PATH="$DEFAULT_REPORT_PATH"
fi

{
    printf '# Sandbox Stress Report\n\n'
    printf -- '- generated_at_utc: `%s`\n' "$TIMESTAMP"
    printf -- '- config: `%s`\n' "$CONFIG"
    printf -- '- scenario: `%s`\n' "$SCENARIO"
    printf -- '- iterations: `%s`\n' "$ITERATIONS"
    printf -- '- concurrency: `%s`\n' "$CONCURRENCY"
    printf -- '- duration_seconds: `%s`\n' "$DURATION_SECONDS"
    printf -- '- passed_runs: `%s`\n' "$PASSED_RUNS"
    printf -- '- failed_runs: `%s`\n' "$FAILED_RUNS"
    printf -- '- artifact_root: `%s`\n' "$RUN_ROOT"
    printf -- '- summary_json: `%s`\n' "$SUMMARY_JSON"
    printf '\n## Failure Artifacts\n\n'
    if (( ${#FAILURE_ARTIFACTS[@]} == 0 )); then
        printf -- '- none\n'
    else
        for artifact in "${FAILURE_ARTIFACTS[@]}"; do
            printf -- '- `%s`\n' "$artifact"
        done
    fi
} >"$REPORT_PATH"

echo "[stress] report: $REPORT_PATH"
echo "[stress] summary json: $SUMMARY_JSON"
echo "[stress] passed=$PASSED_RUNS failed=$FAILED_RUNS duration_seconds=$DURATION_SECONDS"
