#!/usr/bin/env bash
set -euo pipefail

PROXY_PORT="${PROXY_PORT:-5050}"
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
TAG_BASE="${TAG:-e2e-kv-batch-test}"
WORKSPACE="${WORKSPACE:-${BORINGCACHE_DEFAULT_WORKSPACE:-boringcache/testing2}}"
BINARY="${BINARY:-./target/release/boringcache}"
PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"
TMP_ROOT="${TMPDIR:-/tmp}/boringcache-kv-bench"
BINARY_DIR="${TMP_ROOT}/bin"
TMP_BINARY="${BINARY_DIR}/boringcache"
TARGET_ROOT="${TMP_ROOT}/targets"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${LOG_DIR:-${TMP_ROOT}/logs-${RUN_ID}}"
PARALLEL_JOBS="${PARALLEL_JOBS:-2}"
CARGO_CMD="${CARGO_CMD:-cargo build --release --locked}"
RUST_LOG_LEVEL="${RUST_LOG_LEVEL:-info}"
SETTLE_SECS="${SETTLE_SECS:-10}"
RUN_STRESS="${RUN_STRESS:-1}"
RUN_SCOPED_TAGS="${RUN_SCOPED_TAGS:-0}"
SCCACHE_BACKEND="${SCCACHE_BACKEND:-proxy}"

if [[ "$SCCACHE_BACKEND" != "proxy" && "$SCCACHE_BACKEND" != "local" ]]; then
  echo "ERROR: SCCACHE_BACKEND must be 'proxy' or 'local'"
  exit 1
fi

USE_PROXY="0"
if [[ "$SCCACHE_BACKEND" == "proxy" ]]; then
  USE_PROXY="1"
fi

TAG_SUFFIX=""
if [[ "$RUN_SCOPED_TAGS" == "1" ]]; then
  TAG_SUFFIX="-${RUN_ID}"
fi

EFFICACY_TAG="${EFFICACY_TAG:-${TAG_BASE}-stable${TAG_SUFFIX}}"
STRESS_TAG="${STRESS_TAG:-${TAG_BASE}-stress${TAG_SUFFIX}}"

PROXY_PID=""

if [[ "$USE_PROXY" == "1" && -z "${BORINGCACHE_API_TOKEN:-}" ]]; then
  echo "ERROR: BORINGCACHE_API_TOKEN not set"
  exit 1
fi

deps=(sccache)
if [[ "$USE_PROXY" == "1" ]]; then
  deps+=(curl lsof)
fi
for dep in "${deps[@]}"; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: ${dep} not found in PATH"
    exit 1
  fi
done

stop_proxy() {
  if [[ -n "${PROXY_PID:-}" ]]; then
    kill "$PROXY_PID" >/dev/null 2>&1 || true
    wait "$PROXY_PID" >/dev/null 2>&1 || true
    PROXY_PID=""
  fi
}

cleanup() {
  stop_proxy
  sccache --stop-server >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ ! -x "$BINARY" ]]; then
  echo "Building boringcache..."
  cargo build --release --locked 2>&1 | tail -n 5
fi

mkdir -p "$BINARY_DIR" "$TARGET_ROOT" "$LOG_DIR"
cp "$BINARY" "$TMP_BINARY"
chmod +x "$TMP_BINARY"

echo "Binary: $TMP_BINARY"
echo "Workspace: $WORKSPACE"
echo "Efficacy tag: $EFFICACY_TAG"
echo "Stress tag: $STRESS_TAG"
echo "Proxy: ${PROXY_HOST}:${PROXY_PORT}"
echo "Parallel jobs: $PARALLEL_JOBS"
echo "Run-scoped tags: $RUN_SCOPED_TAGS"
echo "sccache backend: $SCCACHE_BACKEND"
echo "Cargo command: $CARGO_CMD"
echo "Logs: $LOG_DIR"

start_proxy() {
  local tag="$1"
  local log_file="$2"
  stop_proxy
  {
    echo ""
    echo "=== Proxy start $(date -u +"%Y-%m-%dT%H:%M:%SZ") tag=${tag} ==="
  } >>"$log_file"
  BORINGCACHE_API_TOKEN="$BORINGCACHE_API_TOKEN" \
    RUST_LOG="$RUST_LOG_LEVEL" \
    "$TMP_BINARY" cache-registry "$WORKSPACE" "$tag" \
    --host "$PROXY_HOST" \
    --port "$PROXY_PORT" \
    --no-platform \
    --no-git >>"$log_file" 2>&1 &
  PROXY_PID=$!
  sleep 2
}

ensure_proxy_ready() {
  local log_file="$1"
  for _ in $(seq 1 20); do
    if curl -fsS "${PROXY_URL}/v2/" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: proxy failed to start"
  tail -n 120 "$log_file" || true
  exit 1
}

reset_sccache() {
  sccache --stop-server >/dev/null 2>&1 || true
  sleep 1
  if [[ "$USE_PROXY" == "1" ]]; then
    SCCACHE_WEBDAV_ENDPOINT="${PROXY_URL}/" sccache --start-server >/dev/null 2>&1
  else
    sccache --start-server >/dev/null 2>&1
  fi
  sccache --zero-stats >/dev/null 2>&1
}

run_build() {
  local label="$1"
  local target_dir="$2"
  local log_file="$3"
  local start_ts end_ts elapsed
  rm -rf "$target_dir"
  mkdir -p "$target_dir"
  start_ts="$(date +%s)"
  if [[ "$USE_PROXY" == "1" ]]; then
    SCCACHE_WEBDAV_ENDPOINT="${PROXY_URL}/" \
      RUSTC_WRAPPER=sccache \
      CARGO_INCREMENTAL=0 \
      CARGO_TARGET_DIR="$target_dir" \
      bash -lc "$CARGO_CMD" >"$log_file" 2>&1
  else
    RUSTC_WRAPPER=sccache \
      CARGO_INCREMENTAL=0 \
      CARGO_TARGET_DIR="$target_dir" \
      bash -lc "$CARGO_CMD" >"$log_file" 2>&1
  fi
  end_ts="$(date +%s)"
  elapsed="$((end_ts - start_ts))"
  echo "$elapsed" >"${log_file}.seconds"
  echo "${label} completed in ${elapsed}s"
}

stat_value() {
  local key="$1"
  local file="$2"
  case "$key" in
    "Compile requests")
      awk '$1 == "Compile" && $2 == "requests" { print $3; exit }' "$file"
      ;;
    "Cache hits")
      awk '$1 == "Cache" && $2 == "hits" && $3 ~ /^[0-9]+$/ { print $3; exit }' "$file"
      ;;
    "Cache misses")
      awk '$1 == "Cache" && $2 == "misses" && $3 ~ /^[0-9]+$/ { print $3; exit }' "$file"
      ;;
    "Cache hits rate")
      awk '$1 == "Cache" && $2 == "hits" && $3 == "rate" { print $(NF-1); exit }' "$file"
      ;;
    "Cache hits rate (Rust)")
      awk '$1 == "Cache" && $2 == "hits" && $3 == "rate" && $4 == "(Rust)" { print $(NF-1); exit }' "$file"
      ;;
    "Average cache read hit")
      awk '$1 == "Average" && $2 == "cache" && $3 == "read" && $4 == "hit" { print $5; exit }' "$file"
      ;;
    *)
      sed -n "s/^[[:space:]]*${key}[[:space:]]\\+\\([0-9.][0-9.]*\\)\\( %\\)*$/\\1/p" "$file" | head -n 1
      ;;
  esac
}

print_stats_summary() {
  local label="$1"
  local file="$2"
  local req hits misses rate rust_rate
  req="$(stat_value 'Compile requests' "$file")"
  hits="$(stat_value 'Cache hits' "$file")"
  misses="$(stat_value 'Cache misses' "$file")"
  rate="$(stat_value 'Cache hits rate' "$file")"
  rust_rate="$(stat_value 'Cache hits rate (Rust)' "$file")"
  req="${req:-0}"
  hits="${hits:-0}"
  misses="${misses:-0}"
  rate="${rate:-0}"
  rust_rate="${rust_rate:-0}"
  echo "${label}: requests=${req}, hits=${hits}, misses=${misses}, hit_rate=${rate}%, rust_hit_rate=${rust_rate}%"
}

count_pattern() {
  local file="$1"
  local pattern="$2"
  if command -v rg >/dev/null 2>&1; then
    rg -c "$pattern" "$file" || true
  else
    grep -c "$pattern" "$file" || true
  fi
}

format_delta() {
  local base="$1"
  local current="$2"
  local delta pct
  delta="$((base - current))"
  pct="$(awk -v saved="$delta" -v baseline="$base" 'BEGIN { if (baseline == 0) { printf "0.00" } else { printf "%.2f", (saved * 100) / baseline } }')"
  echo "${delta}s (${pct}%)"
}

phase_efficacy() {
  local phase_dir proxy_log
  phase_dir="${LOG_DIR}/efficacy"
  proxy_log="${phase_dir}/proxy.log"
  mkdir -p "$phase_dir"

  echo ""
  echo "=== Phase 1: Key-stable efficacy ==="
  echo "Tag: ${EFFICACY_TAG}"
  echo "Target dir reused across runs: ${TARGET_ROOT}/efficacy-stable"

  if [[ "$USE_PROXY" == "1" ]]; then
    start_proxy "$EFFICACY_TAG" "$proxy_log"
    ensure_proxy_ready "$proxy_log"
    echo "Proxy running (pid=${PROXY_PID})"
  else
    echo "Using local sccache backend (no proxy process)"
  fi

  echo ""
  echo "Running efficacy cold pass..."
  reset_sccache
  run_build "efficacy-cold" "${TARGET_ROOT}/efficacy-stable" "${phase_dir}/cold.log"
  sccache --show-stats >"${phase_dir}/cold-sccache-stats.txt" 2>&1
  print_stats_summary "Efficacy cold stats" "${phase_dir}/cold-sccache-stats.txt"

  echo ""
  echo "Waiting for writes to settle (${SETTLE_SECS}s)..."
  sleep "$SETTLE_SECS"

  echo ""
  echo "Restarting cache backend for efficacy warm pass..."
  if [[ "$USE_PROXY" == "1" ]]; then
    start_proxy "$EFFICACY_TAG" "$proxy_log"
    ensure_proxy_ready "$proxy_log"
  fi

  reset_sccache
  run_build "efficacy-warm" "${TARGET_ROOT}/efficacy-stable" "${phase_dir}/warm.log"
  sccache --show-stats >"${phase_dir}/warm-sccache-stats.txt" 2>&1
  print_stats_summary "Efficacy warm stats" "${phase_dir}/warm-sccache-stats.txt"
  if [[ "$USE_PROXY" == "1" ]]; then
    stop_proxy
  fi

  EFFICACY_COLD_SECONDS="$(cat "${phase_dir}/cold.log.seconds")"
  EFFICACY_WARM_SECONDS="$(cat "${phase_dir}/warm.log.seconds")"
  EFFICACY_DELTA="$(format_delta "$EFFICACY_COLD_SECONDS" "$EFFICACY_WARM_SECONDS")"
  EFFICACY_RUST_HIT_RATE="$(stat_value 'Cache hits rate (Rust)' "${phase_dir}/warm-sccache-stats.txt")"
  EFFICACY_RUST_HIT_RATE="${EFFICACY_RUST_HIT_RATE:-0}"
  EFFICACY_AVG_READ_HIT="$(stat_value 'Average cache read hit' "${phase_dir}/warm-sccache-stats.txt")"
  EFFICACY_AVG_READ_HIT="${EFFICACY_AVG_READ_HIT:-0}"
  if [[ "$USE_PROXY" == "1" ]]; then
    EFFICACY_PROXY_429="$(count_pattern "$proxy_log" '429 Too Many Requests')"
    EFFICACY_PROXY_CONFLICTS="$(count_pattern "$proxy_log" 'tag conflict')"
  else
    EFFICACY_PROXY_429="0"
    EFFICACY_PROXY_CONFLICTS="0"
  fi
}

phase_stress() {
  local phase_dir proxy_log lock_waits warm_sum avg
  phase_dir="${LOG_DIR}/stress"
  proxy_log="${phase_dir}/proxy.log"
  mkdir -p "$phase_dir"

  echo ""
  echo "=== Phase 2: Parallel contention stress ==="
  echo "Tag: ${STRESS_TAG}"
  echo "Parallel jobs: ${PARALLEL_JOBS}"

  if [[ "$USE_PROXY" == "1" ]]; then
    start_proxy "$STRESS_TAG" "$proxy_log"
    ensure_proxy_ready "$proxy_log"
    echo "Proxy running (pid=${PROXY_PID})"
  else
    echo "Using local sccache backend (no proxy process)"
  fi

  echo ""
  echo "Running stress prewarm pass..."
  reset_sccache
  run_build "stress-prewarm" "${TARGET_ROOT}/stress-prewarm" "${phase_dir}/prewarm.log"
  sccache --show-stats >"${phase_dir}/prewarm-sccache-stats.txt" 2>&1
  print_stats_summary "Stress prewarm stats" "${phase_dir}/prewarm-sccache-stats.txt"

  echo ""
  echo "Waiting for writes to settle (${SETTLE_SECS}s)..."
  sleep "$SETTLE_SECS"

  echo ""
  echo "Restarting cache backend for stress parallel pass..."
  if [[ "$USE_PROXY" == "1" ]]; then
    start_proxy "$STRESS_TAG" "$proxy_log"
    ensure_proxy_ready "$proxy_log"
  fi

  reset_sccache
  declare -a build_pids=()
  for i in $(seq 1 "$PARALLEL_JOBS"); do
    run_build "stress-parallel-${i}" "${TARGET_ROOT}/stress-job-${i}" "${phase_dir}/parallel-${i}.log" &
    build_pids+=($!)
  done
  for pid in "${build_pids[@]}"; do
    wait "$pid"
  done
  sccache --show-stats >"${phase_dir}/parallel-sccache-stats.txt" 2>&1
  print_stats_summary "Stress parallel stats" "${phase_dir}/parallel-sccache-stats.txt"
  if [[ "$USE_PROXY" == "1" ]]; then
    stop_proxy
  fi

  STRESS_PREWARM_SECONDS="$(cat "${phase_dir}/prewarm.log.seconds")"
  warm_sum=0
  lock_waits=0
  for i in $(seq 1 "$PARALLEL_JOBS"); do
    warm_sum="$((warm_sum + $(cat "${phase_dir}/parallel-${i}.log.seconds")))"
    lock_waits="$((lock_waits + $(count_pattern "${phase_dir}/parallel-${i}.log" 'Blocking waiting for file lock')))"
  done
  avg="$((warm_sum / PARALLEL_JOBS))"
  STRESS_AVG_SECONDS="$avg"
  STRESS_DELTA="$(format_delta "$STRESS_PREWARM_SECONDS" "$STRESS_AVG_SECONDS")"
  STRESS_RUST_HIT_RATE="$(stat_value 'Cache hits rate (Rust)' "${phase_dir}/parallel-sccache-stats.txt")"
  STRESS_RUST_HIT_RATE="${STRESS_RUST_HIT_RATE:-0}"
  STRESS_LOCK_WAITS="$lock_waits"
  if [[ "$USE_PROXY" == "1" ]]; then
    STRESS_PROXY_429="$(count_pattern "$proxy_log" '429 Too Many Requests')"
    STRESS_PROXY_CONFLICTS="$(count_pattern "$proxy_log" 'tag conflict')"
  else
    STRESS_PROXY_429="0"
    STRESS_PROXY_CONFLICTS="0"
  fi
}

phase_efficacy
if [[ "$RUN_STRESS" == "1" ]]; then
  phase_stress
fi

echo ""
echo "========================================="
echo "Phase 1 (key-stable efficacy)"
echo "  Cold:                 ${EFFICACY_COLD_SECONDS}s"
echo "  Warm:                 ${EFFICACY_WARM_SECONDS}s"
echo "  Delta (cold-warm):    ${EFFICACY_DELTA}"
echo "  Warm Rust hit rate:   ${EFFICACY_RUST_HIT_RATE}%"
echo "  Warm avg read hit:    ${EFFICACY_AVG_READ_HIT}s"
echo "  Proxy 429:            ${EFFICACY_PROXY_429:-0}"
echo "  Proxy tag conflicts:  ${EFFICACY_PROXY_CONFLICTS:-0}"
echo "  Logs:                 ${LOG_DIR}/efficacy"

if [[ "$RUN_STRESS" == "1" ]]; then
  echo ""
  echo "Phase 2 (parallel contention stress)"
  echo "  Prewarm:              ${STRESS_PREWARM_SECONDS}s"
  for i in $(seq 1 "$PARALLEL_JOBS"); do
    echo "  Parallel job ${i}:      $(cat "${LOG_DIR}/stress/parallel-${i}.log.seconds")s"
  done
  echo "  Parallel avg:         ${STRESS_AVG_SECONDS}s"
  echo "  Delta (prewarm-avg):  ${STRESS_DELTA}"
  echo "  Parallel Rust hit:    ${STRESS_RUST_HIT_RATE}%"
  echo "  Local lock waits:     ${STRESS_LOCK_WAITS}"
  echo "  Proxy 429:            ${STRESS_PROXY_429:-0}"
  echo "  Proxy tag conflicts:  ${STRESS_PROXY_CONFLICTS:-0}"
  echo "  Logs:                 ${LOG_DIR}/stress"
fi

echo ""
echo "Root logs: ${LOG_DIR}"
echo "========================================="
