#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
source "${SCRIPT_DIR}/../e2e-helpers.sh"

PROXY_PORT="${PROXY_PORT:-5050}"
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
TAG_BASE="${TAG:-bc-e2e-cli-sccache}"
WORKSPACE="${WORKSPACE:-${BORINGCACHE_DEFAULT_WORKSPACE:-boringcache/testing2}}"
BINARY="${BINARY:-${CLI_REPO_ROOT}/target/release/boringcache}"
PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"
TMP_ROOT="${TMPDIR:-/tmp}/boringcache-kv-bench"
BINARY_DIR="${TMP_ROOT}/bin"
TARGET_ROOT="${TMP_ROOT}/targets"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${LOG_DIR:-${TMP_ROOT}/logs-${RUN_ID}}"
TMP_BINARY="${BINARY_DIR}/boringcache-${RUN_ID}"
PARALLEL_JOBS="${PARALLEL_JOBS:-2}"
CARGO_CMD="${CARGO_CMD:-cargo build --release --locked}"
RUST_LOG_LEVEL="${RUST_LOG_LEVEL:-${RUST_LOG:-info}}"
SCCACHE_LOG_LEVEL="${SCCACHE_LOG_LEVEL:-${SCCACHE_LOG:-}}"
STRESS_PREWARM_FIXED_TARGET_DIR="${STRESS_PREWARM_FIXED_TARGET_DIR:-0}"
SETTLE_SECS="${SETTLE_SECS:-10}"
RUN_STRESS="${RUN_STRESS:-1}"
RUN_EFFICACY="${RUN_EFFICACY:-1}"
RUN_SCOPED_TAGS="${RUN_SCOPED_TAGS:-0}"
EFFICACY_FRESH_WARM_SCCACHE_DIR="${EFFICACY_FRESH_WARM_SCCACHE_DIR:-0}"
SCCACHE_BACKEND="${SCCACHE_BACKEND:-proxy}"
PROXY_READY_TIMEOUT_SECS="${PROXY_READY_TIMEOUT_SECS:-90}"
PROXY_READY_POLL_SECS="${PROXY_READY_POLL_SECS:-1}"
PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_SECS:-210}"
PROXY_SHUTDOWN_WAIT_MIN_SECS=210
BUILD_TIMEOUT_SECS="${BUILD_TIMEOUT_SECS:-0}"
BUILD_HEARTBEAT_SECS="${BUILD_HEARTBEAT_SECS:-30}"
BUILD_CLEANUP_WAIT_SECS="${BUILD_CLEANUP_WAIT_SECS:-20}"
BUILD_FAILURE_TAIL_LINES="${BUILD_FAILURE_TAIL_LINES:-60}"
BUILD_WARN_SECS="${BUILD_WARN_SECS:-120}"
BUILD_STALL_WARN_SECS="${BUILD_STALL_WARN_SECS:-90}"
PROXY_READY_WARN_SECS="${PROXY_READY_WARN_SECS:-15}"
SCCACHE_PORT_SEED="${SCCACHE_PORT_SEED:-$((4200 + (RANDOM % 2000)))}"
SCCACHE_SERVER_PORT="${SCCACHE_SERVER_PORT:-}"
SCCACHE_DIR="${SCCACHE_DIR:-${TMP_ROOT}/sccache-${RUN_ID}}"
EFFICACY_WARM_SCCACHE_DIR="${EFFICACY_WARM_SCCACHE_DIR:-${SCCACHE_DIR}-warm}"
STRESS_SCCACHE_PORT_BASE="${STRESS_SCCACHE_PORT_BASE:-}"
STRESS_SCCACHE_ISOLATION="${STRESS_SCCACHE_ISOLATION:-0}"
STRESS_PREWARM_TARGET_DIR="${STRESS_PREWARM_TARGET_DIR:-${TARGET_ROOT}/stress-prewarm-stable}"
PORT_RECLAIM_WAIT_SECS="${PORT_RECLAIM_WAIT_SECS:-15}"
BUDGET_EFFICACY_RUST_HIT_RATE_MIN="${BUDGET_EFFICACY_RUST_HIT_RATE_MIN:-}"
BUDGET_EFFICACY_WARM_REQUESTS_MIN="${BUDGET_EFFICACY_WARM_REQUESTS_MIN:-}"
BUDGET_EFFICACY_REMOTE_TAG_HITS_MIN="${BUDGET_EFFICACY_REMOTE_TAG_HITS_MIN:-}"
BUDGET_EFFICACY_TWO_PASS_HIT_RATE_MIN="${BUDGET_EFFICACY_TWO_PASS_HIT_RATE_MIN:-}"
BUDGET_EFFICACY_TWO_PASS_HIT_RATE_MAX="${BUDGET_EFFICACY_TWO_PASS_HIT_RATE_MAX:-}"
BUDGET_EFFICACY_CACHE_OPS_RECORDS_MIN="${BUDGET_EFFICACY_CACHE_OPS_RECORDS_MIN:-}"
BUDGET_EFFICACY_CACHE_OPS_HIT_RATE_MIN="${BUDGET_EFFICACY_CACHE_OPS_HIT_RATE_MIN:-}"
BUDGET_EFFICACY_CACHE_OPS_HIT_RATE_MAX="${BUDGET_EFFICACY_CACHE_OPS_HIT_RATE_MAX:-}"
BUDGET_EFFICACY_CACHE_OPS_SCCACHE_HIT_RATE_DELTA_MAX="${BUDGET_EFFICACY_CACHE_OPS_SCCACHE_HIT_RATE_DELTA_MAX:-}"
BUDGET_EFFICACY_CACHE_READ_ERRORS_MAX="${BUDGET_EFFICACY_CACHE_READ_ERRORS_MAX:-}"
BUDGET_EFFICACY_CACHE_TIMEOUTS_MAX="${BUDGET_EFFICACY_CACHE_TIMEOUTS_MAX:-}"
BUDGET_EFFICACY_PROXY_429_MAX="${BUDGET_EFFICACY_PROXY_429_MAX:-}"
BUDGET_EFFICACY_PROXY_CONFLICTS_MAX="${BUDGET_EFFICACY_PROXY_CONFLICTS_MAX:-}"
BUDGET_STRESS_RUST_HIT_RATE_MIN="${BUDGET_STRESS_RUST_HIT_RATE_MIN:-}"
BUDGET_STRESS_SCCACHE_STARTUP_TIMEOUTS_MAX="${BUDGET_STRESS_SCCACHE_STARTUP_TIMEOUTS_MAX:-}"
BUDGET_STRESS_SCCACHE_UNEXPECTED_SHUTDOWNS_MAX="${BUDGET_STRESS_SCCACHE_UNEXPECTED_SHUTDOWNS_MAX:-}"
BUDGET_STRESS_LOCK_WAITS_MAX="${BUDGET_STRESS_LOCK_WAITS_MAX:-}"
BUDGET_STRESS_PROXY_429_MAX="${BUDGET_STRESS_PROXY_429_MAX:-}"
BUDGET_STRESS_PROXY_CONFLICTS_MAX="${BUDGET_STRESS_PROXY_CONFLICTS_MAX:-}"
BUDGET_STRESS_PROXY_HEALTH_CHECK_FAILS_MAX="${BUDGET_STRESS_PROXY_HEALTH_CHECK_FAILS_MAX:-}"
BUDGET_STRESS_PARALLEL_AVG_SECONDS_MAX="${BUDGET_STRESS_PARALLEL_AVG_SECONDS_MAX:-}"
BUDGET_STRESS_CACHE_READ_ERRORS_MAX="${BUDGET_STRESS_CACHE_READ_ERRORS_MAX:-}"
BUDGET_STRESS_CACHE_TIMEOUTS_MAX="${BUDGET_STRESS_CACHE_TIMEOUTS_MAX:-}"

if [[ "$SCCACHE_BACKEND" != "proxy" && "$SCCACHE_BACKEND" != "local" ]]; then
  echo "ERROR: SCCACHE_BACKEND must be 'proxy' or 'local'"
  exit 1
fi

if ! [[ "$PARALLEL_JOBS" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: PARALLEL_JOBS must be a positive integer"
  exit 1
fi

if [[ "$RUN_EFFICACY" != "0" && "$RUN_EFFICACY" != "1" ]]; then
  echo "ERROR: RUN_EFFICACY must be 0 or 1"
  exit 1
fi

if [[ "$EFFICACY_FRESH_WARM_SCCACHE_DIR" != "0" && "$EFFICACY_FRESH_WARM_SCCACHE_DIR" != "1" ]]; then
  echo "ERROR: EFFICACY_FRESH_WARM_SCCACHE_DIR must be 0 or 1"
  exit 1
fi

if [[ "$RUN_STRESS" != "0" && "$RUN_STRESS" != "1" ]]; then
  echo "ERROR: RUN_STRESS must be 0 or 1"
  exit 1
fi

if [[ "$RUN_EFFICACY" == "0" && "$RUN_STRESS" == "0" ]]; then
  echo "ERROR: at least one phase must be enabled (RUN_EFFICACY=1 and/or RUN_STRESS=1)"
  exit 1
fi

if ! [[ "$BUILD_TIMEOUT_SECS" =~ ^[0-9]+$ ]]; then
  echo "ERROR: BUILD_TIMEOUT_SECS must be a non-negative integer"
  exit 1
fi

if ! [[ "$BUILD_HEARTBEAT_SECS" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: BUILD_HEARTBEAT_SECS must be a positive integer"
  exit 1
fi

if ! [[ "$BUILD_CLEANUP_WAIT_SECS" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: BUILD_CLEANUP_WAIT_SECS must be a positive integer"
  exit 1
fi

if ! [[ "$BUILD_FAILURE_TAIL_LINES" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: BUILD_FAILURE_TAIL_LINES must be a positive integer"
  exit 1
fi

if ! [[ "$BUILD_WARN_SECS" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: BUILD_WARN_SECS must be a positive integer"
  exit 1
fi

if ! [[ "$BUILD_STALL_WARN_SECS" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: BUILD_STALL_WARN_SECS must be a positive integer"
  exit 1
fi

if [[ "${PROXY_SHUTDOWN_WAIT_SECS}" =~ ^[0-9]+$ ]] \
  && (( PROXY_SHUTDOWN_WAIT_SECS < PROXY_SHUTDOWN_WAIT_MIN_SECS )); then
  PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_MIN_SECS}"
fi

if ! [[ "$PROXY_READY_WARN_SECS" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: PROXY_READY_WARN_SECS must be a positive integer"
  exit 1
fi

if [[ -n "$SCCACHE_SERVER_PORT" ]] && ! [[ "$SCCACHE_SERVER_PORT" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: SCCACHE_SERVER_PORT must be a positive integer"
  exit 1
fi

if [[ -n "$STRESS_SCCACHE_PORT_BASE" ]] && ! [[ "$STRESS_SCCACHE_PORT_BASE" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: STRESS_SCCACHE_PORT_BASE must be a positive integer"
  exit 1
fi

if [[ -n "$STRESS_SCCACHE_PORT_BASE" ]] && (( STRESS_SCCACHE_PORT_BASE > 65535 )); then
  echo "ERROR: STRESS_SCCACHE_PORT_BASE must be <= 65535"
  exit 1
fi

if [[ "$STRESS_SCCACHE_ISOLATION" != "0" && "$STRESS_SCCACHE_ISOLATION" != "1" ]]; then
  echo "ERROR: STRESS_SCCACHE_ISOLATION must be 0 or 1"
  exit 1
fi

if [[ "$STRESS_PREWARM_FIXED_TARGET_DIR" != "0" && "$STRESS_PREWARM_FIXED_TARGET_DIR" != "1" ]]; then
  echo "ERROR: STRESS_PREWARM_FIXED_TARGET_DIR must be 0 or 1"
  exit 1
fi

if ! [[ "$PORT_RECLAIM_WAIT_SECS" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: PORT_RECLAIM_WAIT_SECS must be a positive integer"
  exit 1
fi

is_number() {
  [[ "$1" =~ ^-?[0-9]+([.][0-9]+)?$ ]]
}

require_numeric_if_set() {
  local name="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    return 0
  fi
  if ! is_number "$value"; then
    echo "ERROR: ${name} must be numeric when set"
    exit 1
  fi
}

require_numeric_if_set "BUDGET_EFFICACY_RUST_HIT_RATE_MIN" "$BUDGET_EFFICACY_RUST_HIT_RATE_MIN"
require_numeric_if_set "BUDGET_EFFICACY_WARM_REQUESTS_MIN" "$BUDGET_EFFICACY_WARM_REQUESTS_MIN"
require_numeric_if_set "BUDGET_EFFICACY_REMOTE_TAG_HITS_MIN" "$BUDGET_EFFICACY_REMOTE_TAG_HITS_MIN"
require_numeric_if_set "BUDGET_EFFICACY_TWO_PASS_HIT_RATE_MIN" "$BUDGET_EFFICACY_TWO_PASS_HIT_RATE_MIN"
require_numeric_if_set "BUDGET_EFFICACY_TWO_PASS_HIT_RATE_MAX" "$BUDGET_EFFICACY_TWO_PASS_HIT_RATE_MAX"
require_numeric_if_set "BUDGET_EFFICACY_CACHE_OPS_RECORDS_MIN" "$BUDGET_EFFICACY_CACHE_OPS_RECORDS_MIN"
require_numeric_if_set "BUDGET_EFFICACY_CACHE_OPS_HIT_RATE_MIN" "$BUDGET_EFFICACY_CACHE_OPS_HIT_RATE_MIN"
require_numeric_if_set "BUDGET_EFFICACY_CACHE_OPS_HIT_RATE_MAX" "$BUDGET_EFFICACY_CACHE_OPS_HIT_RATE_MAX"
require_numeric_if_set "BUDGET_EFFICACY_CACHE_OPS_SCCACHE_HIT_RATE_DELTA_MAX" "$BUDGET_EFFICACY_CACHE_OPS_SCCACHE_HIT_RATE_DELTA_MAX"
require_numeric_if_set "BUDGET_EFFICACY_CACHE_READ_ERRORS_MAX" "$BUDGET_EFFICACY_CACHE_READ_ERRORS_MAX"
require_numeric_if_set "BUDGET_EFFICACY_CACHE_TIMEOUTS_MAX" "$BUDGET_EFFICACY_CACHE_TIMEOUTS_MAX"
require_numeric_if_set "BUDGET_EFFICACY_PROXY_429_MAX" "$BUDGET_EFFICACY_PROXY_429_MAX"
require_numeric_if_set "BUDGET_EFFICACY_PROXY_CONFLICTS_MAX" "$BUDGET_EFFICACY_PROXY_CONFLICTS_MAX"
require_numeric_if_set "BUDGET_STRESS_RUST_HIT_RATE_MIN" "$BUDGET_STRESS_RUST_HIT_RATE_MIN"
require_numeric_if_set "BUDGET_STRESS_SCCACHE_STARTUP_TIMEOUTS_MAX" "$BUDGET_STRESS_SCCACHE_STARTUP_TIMEOUTS_MAX"
require_numeric_if_set "BUDGET_STRESS_SCCACHE_UNEXPECTED_SHUTDOWNS_MAX" "$BUDGET_STRESS_SCCACHE_UNEXPECTED_SHUTDOWNS_MAX"
require_numeric_if_set "BUDGET_STRESS_LOCK_WAITS_MAX" "$BUDGET_STRESS_LOCK_WAITS_MAX"
require_numeric_if_set "BUDGET_STRESS_PROXY_429_MAX" "$BUDGET_STRESS_PROXY_429_MAX"
require_numeric_if_set "BUDGET_STRESS_PROXY_CONFLICTS_MAX" "$BUDGET_STRESS_PROXY_CONFLICTS_MAX"
require_numeric_if_set "BUDGET_STRESS_PROXY_HEALTH_CHECK_FAILS_MAX" "$BUDGET_STRESS_PROXY_HEALTH_CHECK_FAILS_MAX"
require_numeric_if_set "BUDGET_STRESS_PARALLEL_AVG_SECONDS_MAX" "$BUDGET_STRESS_PARALLEL_AVG_SECONDS_MAX"
require_numeric_if_set "BUDGET_STRESS_CACHE_READ_ERRORS_MAX" "$BUDGET_STRESS_CACHE_READ_ERRORS_MAX"
require_numeric_if_set "BUDGET_STRESS_CACHE_TIMEOUTS_MAX" "$BUDGET_STRESS_CACHE_TIMEOUTS_MAX"

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
PROXY_READY_FILE=""
INTERRUPTED="0"
declare -a ACTIVE_BUILD_PIDS=()
declare -a SCCACHE_INSTANCES=()

if [[ "$USE_PROXY" == "1" ]]; then
  require_save_capable_token
  export_resolved_cli_tokens admin
fi

deps=(sccache pgrep ps)
if [[ "$USE_PROXY" == "1" ]]; then
  deps+=(curl)
fi
for dep in "${deps[@]}"; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: ${dep} not found in PATH"
    exit 1
  fi
done

PORT_TOOL=""
if command -v lsof >/dev/null 2>&1; then
  PORT_TOOL="lsof"
elif command -v ss >/dev/null 2>&1; then
  PORT_TOOL="ss"
elif [[ "$USE_PROXY" == "1" ]]; then
  echo "ERROR: either lsof or ss must be available to inspect listening ports"
  exit 1
fi

register_sccache_instance() {
  local port="$1"
  local dir="$2"
  local entry="${port}|${dir}"
  local existing
  for existing in "${SCCACHE_INSTANCES[@]-}"; do
    if [[ "$existing" == "$entry" ]]; then
      return 0
    fi
  done
  SCCACHE_INSTANCES+=("$entry")
}

stop_registered_sccache_servers() {
  local entry port dir
  for entry in "${SCCACHE_INSTANCES[@]-}"; do
    port="${entry%%|*}"
    dir="${entry#*|}"
    run_with_clean_sccache_env \
      "SCCACHE_SERVER_PORT=$port" \
      "SCCACHE_DIR=$dir" \
      sccache --stop-server >/dev/null 2>&1 || true
  done
}

remove_active_build_pid() {
  local target_pid="$1"
  local -a remaining=()
  local pid
  for pid in "${ACTIVE_BUILD_PIDS[@]-}"; do
    if [[ "$pid" != "$target_pid" ]]; then
      remaining+=("$pid")
    fi
  done
  ACTIVE_BUILD_PIDS=("${remaining[@]-}")
}

children_of_pid() {
  pgrep -P "$1" 2>/dev/null || true
}

signal_pid_tree() {
  local pid="$1"
  local signal_name="$2"
  local child
  for child in $(children_of_pid "$pid"); do
    signal_pid_tree "$child" "$signal_name"
  done
  kill -s "$signal_name" "$pid" >/dev/null 2>&1 || true
}

stop_pid_tree() {
  local pid="$1"
  local label="$2"
  local wait_secs="$3"
  local deadline
  if [[ -z "${pid:-}" ]]; then
    return 0
  fi
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    return 0
  fi
  signal_pid_tree "$pid" TERM
  deadline=$((SECONDS + wait_secs))
  while kill -0 "$pid" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "WARNING: ${label} ${pid} did not exit after ${wait_secs}s, sending SIGKILL"
      signal_pid_tree "$pid" KILL
      break
    fi
    sleep 1
  done
  wait "$pid" >/dev/null 2>&1 || true
}

stop_background_jobs() {
  local job_pids
  local pid
  job_pids="$(jobs -pr || true)"
  if [[ -z "$job_pids" ]]; then
    return 0
  fi
  for pid in $job_pids; do
    stop_pid_tree "$pid" "background job" "$BUILD_CLEANUP_WAIT_SECS"
  done
}

stop_proxy() {
  if [[ -n "${PROXY_PID:-}" ]]; then
    stop_pid_tree "$PROXY_PID" "proxy" "$PROXY_SHUTDOWN_WAIT_SECS"
    PROXY_PID=""
  fi
  rm -f "${PROXY_READY_FILE:-}" >/dev/null 2>&1 || true
  PROXY_READY_FILE=""
}

handle_interrupt() {
  if [[ "$INTERRUPTED" == "1" ]]; then
    return
  fi
  INTERRUPTED="1"
  trap '' INT TERM
  echo ""
  echo "Interrupt received, shutting down..."
  exit 130
}

cleanup() {
  stop_background_jobs
  local pid
  for pid in "${ACTIVE_BUILD_PIDS[@]-}"; do
    stop_pid_tree "$pid" "build" "$BUILD_CLEANUP_WAIT_SECS"
  done
  ACTIVE_BUILD_PIDS=()
  stop_proxy
  stop_registered_sccache_servers
  rm -f "$TMP_BINARY" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap handle_interrupt INT TERM

if [[ ! -x "$BINARY" ]]; then
  echo "Building boringcache..."
  cargo build --release --locked 2>&1 | tail -n 5
fi

mkdir -p "$BINARY_DIR" "$TARGET_ROOT" "$LOG_DIR" "$SCCACHE_DIR"
register_sccache_instance "$SCCACHE_SERVER_PORT" "$SCCACHE_DIR"
cp "$BINARY" "$TMP_BINARY"
chmod +x "$TMP_BINARY"

echo "Binary: $TMP_BINARY"
echo "Workspace: $WORKSPACE"
echo "Efficacy tag: $EFFICACY_TAG"
echo "Stress tag: $STRESS_TAG"
echo "Proxy: ${PROXY_HOST}:${PROXY_PORT}"
echo "Parallel jobs: $PARALLEL_JOBS"
echo "Run efficacy phase: ${RUN_EFFICACY}"
echo "Run stress phase: ${RUN_STRESS}"
echo "Run-scoped tags: $RUN_SCOPED_TAGS"
if [[ "$EFFICACY_FRESH_WARM_SCCACHE_DIR" == "1" ]]; then
  echo "Efficacy warm sccache mode: fresh (${EFFICACY_WARM_SCCACHE_DIR})"
else
  echo "Efficacy warm sccache mode: reuse (${SCCACHE_DIR})"
fi
echo "sccache backend: $SCCACHE_BACKEND"
echo "sccache server port: $SCCACHE_SERVER_PORT"
echo "sccache dir: $SCCACHE_DIR"
if [[ -n "$SCCACHE_LOG_LEVEL" ]]; then
  echo "sccache log level: $SCCACHE_LOG_LEVEL"
else
  echo "sccache log level: default"
fi
echo "Stress sccache isolation: ${STRESS_SCCACHE_ISOLATION}"
echo "Stress sccache base port: ${STRESS_SCCACHE_PORT_BASE}"
if [[ "$STRESS_PREWARM_FIXED_TARGET_DIR" == "1" ]]; then
  echo "Stress prewarm target mode: fixed (${STRESS_PREWARM_TARGET_DIR})"
else
  echo "Stress prewarm target mode: per-job (${TARGET_ROOT}/stress-job-<n>)"
fi
echo "Build heartbeat: ${BUILD_HEARTBEAT_SECS}s"
echo "Build warn threshold: ${BUILD_WARN_SECS}s"
echo "Build stall threshold: ${BUILD_STALL_WARN_SECS}s"
echo "Proxy ready warn threshold: ${PROXY_READY_WARN_SECS}s"
echo "Cargo command: $CARGO_CMD"
echo "Logs: $LOG_DIR"
echo "sccache control log: ${LOG_DIR}/sccache-control.log"
echo "sccache daemon logs: ${LOG_DIR}/sccache-<port>.log"

reclaim_stale_proxy_port() {
  local log_file="$1"
  local listener_pids
  local pid
  local cmd
  listener_pids="$(port_listener_pids "$PROXY_PORT")"
  if [[ -z "$listener_pids" ]]; then
    return 0
  fi
  for pid in $listener_pids; do
    cmd="$(ps -p "$pid" -o command= 2>/dev/null || true)"
    if [[ "$cmd" == *"boringcache"* && "$cmd" == *"cache-registry"* ]]; then
      echo "WARNING: reclaiming stale proxy on port ${PROXY_PORT} (pid=${pid})" | tee -a "$log_file"
      stop_pid_tree "$pid" "stale proxy" "$PORT_RECLAIM_WAIT_SECS"
    fi
  done
  listener_pids="$(port_listener_pids "$PROXY_PORT")"
  if [[ -n "$listener_pids" ]]; then
    echo "ERROR: proxy port ${PROXY_PORT} is already in use" | tee -a "$log_file"
    port_listener_details "$PROXY_PORT" | tee -a "$log_file"
    exit 1
  fi
}

port_listener_pids() {
  local port="$1"
  if [[ "$PORT_TOOL" == "lsof" ]]; then
    lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
  elif [[ "$PORT_TOOL" == "ss" ]]; then
    ss -lntp "sport = :$port" 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | sort -u
  else
    true
  fi
}

port_listener_details() {
  local port="$1"
  if [[ "$PORT_TOOL" == "lsof" ]]; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
  elif [[ "$PORT_TOOL" == "ss" ]]; then
    ss -lntp "sport = :$port" 2>/dev/null || true
  else
    true
  fi
}

next_available_sccache_port() {
  local candidate="$1"
  local reserved_port="${2:-}"
  local limit=256
  local listeners
  while (( limit > 0 )); do
    if (( candidate > 65535 )); then
      candidate=10240
    fi
    if [[ -n "$reserved_port" && "$candidate" == "$reserved_port" ]]; then
      candidate=$((candidate + 1))
      limit=$((limit - 1))
      continue
    fi
    listeners="$(port_listener_pids "$candidate")"
    if [[ -z "$listeners" ]]; then
      echo "$candidate"
      return 0
    fi
    candidate=$((candidate + 1))
    limit=$((limit - 1))
  done
  echo "ERROR: unable to find a free sccache server port" >&2
  exit 1
}

sccache_error_log_path() {
  local sccache_port="$1"
  echo "${LOG_DIR}/sccache-${sccache_port}.log"
}

if [[ -z "$SCCACHE_SERVER_PORT" ]]; then
  SCCACHE_SERVER_PORT="$(next_available_sccache_port "$SCCACHE_PORT_SEED" "$PROXY_PORT")"
elif [[ "$SCCACHE_SERVER_PORT" == "$PROXY_PORT" ]]; then
  echo "ERROR: SCCACHE_SERVER_PORT (${SCCACHE_SERVER_PORT}) must differ from PROXY_PORT (${PROXY_PORT})"
  exit 1
fi

if (( SCCACHE_SERVER_PORT > 65535 )); then
  echo "ERROR: SCCACHE_SERVER_PORT must be <= 65535"
  exit 1
fi

if [[ -z "$STRESS_SCCACHE_PORT_BASE" ]]; then
  STRESS_SCCACHE_PORT_BASE="$((SCCACHE_SERVER_PORT + 100))"
fi

if (( STRESS_SCCACHE_PORT_BASE > 65535 )); then
  echo "ERROR: STRESS_SCCACHE_PORT_BASE must be <= 65535"
  exit 1
fi

proxy_request_metrics_path() {
  local log_file="$1"
  local phase_dir
  phase_dir="$(dirname "$log_file")"
  echo "${phase_dir}/request-metrics.jsonl"
}

phase_metadata_hints() {
  local phase="$1"
  printf 'project=cli-cache-registry,phase=%s,tool=sccache' "$phase"
}

start_proxy() {
  local tag="$1"
  local log_file="$2"
  local metadata_hints="${3:-}"
  local metrics_file
  stop_proxy
  reclaim_stale_proxy_port "$log_file"
  metrics_file="$(proxy_request_metrics_path "$log_file")"
  PROXY_READY_FILE="$(mktemp "${LOG_DIR}/cache-registry-ready.XXXXXX")"
  rm -f "${PROXY_READY_FILE}"
  {
    echo ""
    echo "=== Proxy start $(date -u +"%Y-%m-%dT%H:%M:%SZ") tag=${tag} metrics=${metrics_file} hints=${metadata_hints:-none} ==="
  } >>"$log_file"
  BORINGCACHE_METRICS_FORMAT="${BORINGCACHE_METRICS_FORMAT:-json}" \
    BORINGCACHE_PROXY_METADATA_HINTS="$metadata_hints" \
    BORINGCACHE_REQUEST_METRICS_PATH="$metrics_file" \
    BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS="${BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS:-1}" \
    RUST_LOG="$RUST_LOG_LEVEL" \
    "$TMP_BINARY" cache-registry "$WORKSPACE" "$tag" \
    --host "$PROXY_HOST" \
    --port "$PROXY_PORT" \
    --ready-file "${PROXY_READY_FILE}" \
    --no-platform \
    --no-git >>"$log_file" 2>&1 &
  PROXY_PID=$!
}

ensure_proxy_ready() {
  local log_file="$1"
  wait_for_ready_file "${PROXY_READY_FILE}" "${PROXY_PID:-}" "$log_file"
}

reset_sccache() {
  local sccache_port="${1:-$SCCACHE_SERVER_PORT}"
  local sccache_dir="${2:-$SCCACHE_DIR}"
  local sccache_error_log sccache_ctl_log
  local -a sccache_env
  sccache_error_log="$(sccache_error_log_path "$sccache_port")"
  sccache_ctl_log="${LOG_DIR}/sccache-control.log"
  touch "$sccache_error_log" "$sccache_ctl_log"
  sccache_env=(
    "SCCACHE_SERVER_PORT=$sccache_port"
    "SCCACHE_DIR=$sccache_dir"
    "SCCACHE_ERROR_LOG=$sccache_error_log"
  )
  if [[ -n "$SCCACHE_LOG_LEVEL" ]]; then
    sccache_env+=("SCCACHE_LOG=$SCCACHE_LOG_LEVEL")
  fi
  register_sccache_instance "$sccache_port" "$sccache_dir"
  run_with_clean_sccache_env "${sccache_env[@]}" sccache --stop-server >/dev/null 2>&1 || true
  sleep 1
  if [[ "$USE_PROXY" == "1" ]]; then
    run_with_clean_sccache_env "${sccache_env[@]}" \
      "SCCACHE_WEBDAV_ENDPOINT=${PROXY_URL}" \
      sccache --start-server >>"$sccache_ctl_log" 2>&1
  else
    run_with_clean_sccache_env "${sccache_env[@]}" \
      sccache --start-server >>"$sccache_ctl_log" 2>&1
  fi
  run_with_clean_sccache_env "${sccache_env[@]}" sccache --zero-stats >>"$sccache_ctl_log" 2>&1
}

run_build() {
  local label="$1"
  local target_dir="$2"
  local log_file="$3"
  local sccache_port="${4:-$SCCACHE_SERVER_PORT}"
  local sccache_dir="${5:-$SCCACHE_DIR}"
  local sccache_error_log sccache_ctl_log
  local start_ts end_ts elapsed
  local build_pid now next_heartbeat status latest_line
  local build_warned last_log_size current_log_size next_stall_warn_at next_lock_warn_at
  sccache_error_log="$(sccache_error_log_path "$sccache_port")"
  sccache_ctl_log="${LOG_DIR}/sccache-control.log"
  touch "$sccache_error_log" "$sccache_ctl_log"
  register_sccache_instance "$sccache_port" "$sccache_dir"
  echo "${label} starting..."
  rm -rf "$target_dir"
  mkdir -p "$target_dir"
  start_ts="$(date +%s)"
  if [[ "$USE_PROXY" == "1" ]]; then
    if [[ -n "$SCCACHE_LOG_LEVEL" ]]; then
      run_with_clean_sccache_env \
        "SCCACHE_SERVER_PORT=$sccache_port" \
        "SCCACHE_DIR=$sccache_dir" \
        "SCCACHE_ERROR_LOG=$sccache_error_log" \
        "SCCACHE_LOG=$SCCACHE_LOG_LEVEL" \
        "SCCACHE_WEBDAV_ENDPOINT=${PROXY_URL}" \
        RUSTC_WRAPPER=sccache \
        CARGO_INCREMENTAL=0 \
        "CARGO_TARGET_DIR=$target_dir" \
        bash -lc "$CARGO_CMD" >"$log_file" 2>&1 &
    else
      run_with_clean_sccache_env \
        "SCCACHE_SERVER_PORT=$sccache_port" \
        "SCCACHE_DIR=$sccache_dir" \
        "SCCACHE_ERROR_LOG=$sccache_error_log" \
        "SCCACHE_WEBDAV_ENDPOINT=${PROXY_URL}" \
        RUSTC_WRAPPER=sccache \
        CARGO_INCREMENTAL=0 \
        "CARGO_TARGET_DIR=$target_dir" \
        bash -lc "$CARGO_CMD" >"$log_file" 2>&1 &
    fi
  else
    if [[ -n "$SCCACHE_LOG_LEVEL" ]]; then
      SCCACHE_SERVER_PORT="$sccache_port" \
        SCCACHE_DIR="$sccache_dir" \
        SCCACHE_ERROR_LOG="$sccache_error_log" \
        SCCACHE_LOG="$SCCACHE_LOG_LEVEL" \
        RUSTC_WRAPPER=sccache \
        CARGO_INCREMENTAL=0 \
        CARGO_TARGET_DIR="$target_dir" \
        bash -lc "$CARGO_CMD" >"$log_file" 2>&1 &
    else
      SCCACHE_SERVER_PORT="$sccache_port" \
        SCCACHE_DIR="$sccache_dir" \
        SCCACHE_ERROR_LOG="$sccache_error_log" \
        RUSTC_WRAPPER=sccache \
        CARGO_INCREMENTAL=0 \
        CARGO_TARGET_DIR="$target_dir" \
        bash -lc "$CARGO_CMD" >"$log_file" 2>&1 &
    fi
  fi
  build_pid=$!
  ACTIVE_BUILD_PIDS+=("$build_pid")
  next_heartbeat=$((start_ts + BUILD_HEARTBEAT_SECS))
  next_stall_warn_at=$((start_ts + BUILD_STALL_WARN_SECS))
  next_lock_warn_at="$start_ts"
  build_warned="0"
  if [[ -f "$log_file" ]]; then
    last_log_size="$(wc -c < "$log_file" 2>/dev/null || echo 0)"
  else
    last_log_size=0
  fi
  while kill -0 "$build_pid" >/dev/null 2>&1; do
    now="$(date +%s)"
    current_log_size="$(wc -c < "$log_file" 2>/dev/null || echo 0)"
    if [[ "$current_log_size" != "$last_log_size" ]]; then
      last_log_size="$current_log_size"
      next_stall_warn_at=$((now + BUILD_STALL_WARN_SECS))
    fi
    if [[ "$BUILD_TIMEOUT_SECS" -gt 0 ]] && (( now - start_ts >= BUILD_TIMEOUT_SECS )); then
      echo "ERROR: ${label} exceeded BUILD_TIMEOUT_SECS=${BUILD_TIMEOUT_SECS}s"
      stop_pid_tree "$build_pid" "$label build" "$BUILD_CLEANUP_WAIT_SECS"
      remove_active_build_pid "$build_pid"
      tail -n "$BUILD_FAILURE_TAIL_LINES" "$log_file" || true
      return 124
    fi
    if [[ "$build_warned" == "0" ]] && (( now - start_ts >= BUILD_WARN_SECS )); then
      latest_line="$(awk 'NF { line=$0 } END { print line }' "$log_file" 2>/dev/null || true)"
      if [[ -n "$latest_line" ]]; then
        echo "WARNING: ${label} has been running for $((now - start_ts))s | ${latest_line}" | tee -a "$log_file"
      else
        echo "WARNING: ${label} has been running for $((now - start_ts))s" | tee -a "$log_file"
      fi
      build_warned="1"
    fi
    if (( now >= next_stall_warn_at )); then
      latest_line="$(awk 'NF { line=$0 } END { print line }' "$log_file" 2>/dev/null || true)"
      if [[ -n "$latest_line" ]]; then
        echo "WARNING: ${label} has no new log output for ${BUILD_STALL_WARN_SECS}s | ${latest_line}" | tee -a "$log_file"
      else
        echo "WARNING: ${label} has no new log output for ${BUILD_STALL_WARN_SECS}s" | tee -a "$log_file"
      fi
      if [[ "$USE_PROXY" == "1" ]] && ! proxy_status_ok "${PROXY_PORT}"; then
        echo "WARNING: ${label} proxy health check failed (${PROXY_URL}${PROXY_STATUS_PATH})" | tee -a "$log_file"
      fi
      next_stall_warn_at=$((now + BUILD_STALL_WARN_SECS))
    fi
    if (( now >= next_heartbeat )); then
      elapsed="$((now - start_ts))"
      latest_line="$(awk 'NF { line=$0 } END { print line }' "$log_file" 2>/dev/null || true)"
      if [[ -n "$latest_line" ]]; then
        echo "  [heartbeat] ${label} running ${elapsed}s | ${latest_line}"
        if [[ "$latest_line" == *"Blocking waiting for file lock"* ]] && (( now >= next_lock_warn_at )); then
          echo "WARNING: ${label} is waiting on Cargo artifact lock; another build may still own the target dir lock" | tee -a "$log_file"
          next_lock_warn_at=$((now + BUILD_STALL_WARN_SECS))
        fi
      else
        echo "  [heartbeat] ${label} running ${elapsed}s"
      fi
      next_heartbeat=$((now + BUILD_HEARTBEAT_SECS))
    fi
    sleep 1
  done
  if wait "$build_pid"; then
    status=0
  else
    status=$?
  fi
  remove_active_build_pid "$build_pid"
  end_ts="$(date +%s)"
  elapsed="$((end_ts - start_ts))"
  echo "$elapsed" >"${log_file}.seconds"
  if [[ "$status" -ne 0 ]]; then
    echo "ERROR: ${label} failed with exit code ${status}. Recent log output:"
    tail -n "$BUILD_FAILURE_TAIL_LINES" "$log_file" || true
    if [[ -f "$sccache_error_log" ]]; then
      echo ""
      echo "Recent sccache daemon log (${sccache_error_log}):"
      tail -n "$BUILD_FAILURE_TAIL_LINES" "$sccache_error_log" || true
    fi
    if [[ -f "$sccache_ctl_log" ]]; then
      echo ""
      echo "Recent sccache control log (${sccache_ctl_log}):"
      tail -n "$BUILD_FAILURE_TAIL_LINES" "$sccache_ctl_log" || true
    fi
    return "$status"
  fi
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
      awk '
        $1 == "Cache" && $2 == "hits" && $3 == "rate" && $4 != "(Rust)" {
          if ($4 == "-") { print 0; exit }
          if ($NF == "%") { print $(NF-1); exit }
          print $4; exit
        }
      ' "$file"
      ;;
    "Cache hits rate (Rust)")
      awk '
        $1 == "Cache" && $2 == "hits" && $3 == "rate" && $4 == "(Rust)" {
          if ($5 == "-") { print 0; exit }
          if ($NF == "%") { print $(NF-1); exit }
          print $5; exit
        }
      ' "$file"
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
  local count
  if command -v rg >/dev/null 2>&1; then
    count="$(rg -c "$pattern" "$file" 2>/dev/null || true)"
  else
    count="$(grep -c "$pattern" "$file" 2>/dev/null || true)"
  fi
  echo "${count:-0}"
}

print_request_metrics_summary() {
  local phase_dir="$1"
  local label="$2"
  local metrics_file total failures retries
  metrics_file="${phase_dir}/request-metrics.jsonl"
  if [[ ! -f "$metrics_file" ]]; then
    echo "${label} request metrics: not captured"
    return
  fi

  total="$(wc -l < "$metrics_file" 2>/dev/null || echo 0)"
  failures="$(count_pattern "$metrics_file" '"error":')"
  retries="$(count_pattern "$metrics_file" '"retry_count":[1-9]')"
  echo "${label} request metrics: events=${total}, failures=${failures}, retry_events=${retries}, file=${metrics_file}"
}

load_request_metrics_summary() {
  local phase_dir="$1"
  local metrics_file summary_file
  metrics_file="${phase_dir}/request-metrics.jsonl"
  summary_file="${phase_dir}/request-metrics-summary.env"
  if [[ ! -f "$metrics_file" ]]; then
    return 1
  fi
  if ! python3 "${SCRIPT_DIR}/request-metrics-summary.py" "$metrics_file" >"$summary_file"; then
    return 1
  fi
  # shellcheck disable=SC1090
  source "$summary_file"
  return 0
}

format_delta() {
  local base="$1"
  local current="$2"
  local delta pct
  delta="$((base - current))"
  pct="$(awk -v saved="$delta" -v baseline="$base" 'BEGIN { if (baseline == 0) { printf "0.00" } else { printf "%.2f", (saved * 100) / baseline } }')"
  echo "${delta}s (${pct}%)"
}

BUDGET_FAILURES=0

budget_check_min() {
  local label="$1"
  local actual="$2"
  local minimum="$3"
  if [[ -z "$minimum" ]]; then
    return 0
  fi
  if awk -v a="$actual" -v b="$minimum" 'BEGIN { exit (a + 0 >= b + 0) ? 0 : 1 }'; then
    echo "  BUDGET OK: ${label} ${actual} >= ${minimum}"
  else
    echo "  BUDGET FAIL: ${label} ${actual} < ${minimum}"
    BUDGET_FAILURES=$((BUDGET_FAILURES + 1))
  fi
}

budget_check_max() {
  local label="$1"
  local actual="$2"
  local maximum="$3"
  if [[ -z "$maximum" ]]; then
    return 0
  fi
  if awk -v a="$actual" -v b="$maximum" 'BEGIN { exit (a + 0 <= b + 0) ? 0 : 1 }'; then
    echo "  BUDGET OK: ${label} ${actual} <= ${maximum}"
  else
    echo "  BUDGET FAIL: ${label} ${actual} > ${maximum}"
    BUDGET_FAILURES=$((BUDGET_FAILURES + 1))
  fi
}

evaluate_budgets() {
  local checks=0

  echo ""
  echo "Budget checks:"

  if [[ "$RUN_EFFICACY" == "1" ]]; then
    if [[ -n "$BUDGET_EFFICACY_RUST_HIT_RATE_MIN" ]]; then
      checks=$((checks + 1))
      budget_check_min "efficacy warm rust hit rate (%)" "${EFFICACY_RUST_HIT_RATE:-0}" "$BUDGET_EFFICACY_RUST_HIT_RATE_MIN"
    fi
    if [[ -n "$BUDGET_EFFICACY_WARM_REQUESTS_MIN" ]]; then
      checks=$((checks + 1))
      budget_check_min "efficacy warm compile requests" "${EFFICACY_WARM_REQUESTS:-0}" "$BUDGET_EFFICACY_WARM_REQUESTS_MIN"
    fi
    if [[ -n "$BUDGET_EFFICACY_REMOTE_TAG_HITS_MIN" ]]; then
      checks=$((checks + 1))
      budget_check_min "efficacy remote tag hits" "${EFFICACY_REMOTE_TAG_HITS:-0}" "$BUDGET_EFFICACY_REMOTE_TAG_HITS_MIN"
    fi
    if [[ -n "$BUDGET_EFFICACY_TWO_PASS_HIT_RATE_MIN" ]]; then
      checks=$((checks + 1))
      budget_check_min "efficacy two-pass rust hit rate (%)" "${EFFICACY_TWO_PASS_HIT_RATE:-0}" "$BUDGET_EFFICACY_TWO_PASS_HIT_RATE_MIN"
    fi
    if [[ -n "$BUDGET_EFFICACY_TWO_PASS_HIT_RATE_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "efficacy two-pass rust hit rate (%)" "${EFFICACY_TWO_PASS_HIT_RATE:-0}" "$BUDGET_EFFICACY_TWO_PASS_HIT_RATE_MAX"
    fi
    if [[ -n "$BUDGET_EFFICACY_CACHE_OPS_RECORDS_MIN" ]]; then
      checks=$((checks + 1))
      budget_check_min "efficacy cache-ops record count" "${EFFICACY_CACHE_OPS_RECORDS:-0}" "$BUDGET_EFFICACY_CACHE_OPS_RECORDS_MIN"
    fi
    if [[ -n "$BUDGET_EFFICACY_CACHE_OPS_HIT_RATE_MIN" ]]; then
      checks=$((checks + 1))
      budget_check_min "efficacy cache-ops sccache GET hit rate (%)" "${EFFICACY_CACHE_OPS_HIT_RATE:-0}" "$BUDGET_EFFICACY_CACHE_OPS_HIT_RATE_MIN"
    fi
    if [[ -n "$BUDGET_EFFICACY_CACHE_OPS_HIT_RATE_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "efficacy cache-ops sccache GET hit rate (%)" "${EFFICACY_CACHE_OPS_HIT_RATE:-0}" "$BUDGET_EFFICACY_CACHE_OPS_HIT_RATE_MAX"
    fi
    if [[ -n "$BUDGET_EFFICACY_CACHE_OPS_SCCACHE_HIT_RATE_DELTA_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "efficacy cache-ops vs sccache hit-rate delta (pp)" "${EFFICACY_CACHE_OPS_SCCACHE_HIT_RATE_DELTA:-0}" "$BUDGET_EFFICACY_CACHE_OPS_SCCACHE_HIT_RATE_DELTA_MAX"
    fi
    if [[ -n "$BUDGET_EFFICACY_CACHE_READ_ERRORS_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "efficacy sccache cache read errors" "${EFFICACY_CACHE_READ_ERRORS:-0}" "$BUDGET_EFFICACY_CACHE_READ_ERRORS_MAX"
    fi
    if [[ -n "$BUDGET_EFFICACY_CACHE_TIMEOUTS_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "efficacy sccache cache timeouts" "${EFFICACY_CACHE_TIMEOUTS:-0}" "$BUDGET_EFFICACY_CACHE_TIMEOUTS_MAX"
    fi
    if [[ -n "$BUDGET_EFFICACY_PROXY_429_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "efficacy proxy 429 count" "${EFFICACY_PROXY_429:-0}" "$BUDGET_EFFICACY_PROXY_429_MAX"
    fi
    if [[ -n "$BUDGET_EFFICACY_PROXY_CONFLICTS_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "efficacy proxy tag conflicts" "${EFFICACY_PROXY_CONFLICTS:-0}" "$BUDGET_EFFICACY_PROXY_CONFLICTS_MAX"
    fi
  fi

  if [[ "$RUN_STRESS" == "1" ]]; then
    if [[ -n "$BUDGET_STRESS_RUST_HIT_RATE_MIN" ]]; then
      checks=$((checks + 1))
      budget_check_min "stress parallel rust hit rate (%)" "${STRESS_RUST_HIT_RATE:-0}" "$BUDGET_STRESS_RUST_HIT_RATE_MIN"
    fi
    if [[ -n "$BUDGET_STRESS_SCCACHE_STARTUP_TIMEOUTS_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "stress sccache startup timeouts" "${STRESS_SCCACHE_STARTUP_TIMEOUTS:-0}" "$BUDGET_STRESS_SCCACHE_STARTUP_TIMEOUTS_MAX"
    fi
    if [[ -n "$BUDGET_STRESS_SCCACHE_UNEXPECTED_SHUTDOWNS_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "stress sccache unexpected shutdowns" "${STRESS_SCCACHE_UNEXPECTED_SHUTDOWNS:-0}" "$BUDGET_STRESS_SCCACHE_UNEXPECTED_SHUTDOWNS_MAX"
    fi
    if [[ -n "$BUDGET_STRESS_LOCK_WAITS_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "stress local lock waits" "${STRESS_LOCK_WAITS:-0}" "$BUDGET_STRESS_LOCK_WAITS_MAX"
    fi
    if [[ -n "$BUDGET_STRESS_PROXY_429_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "stress proxy 429 count" "${STRESS_PROXY_429:-0}" "$BUDGET_STRESS_PROXY_429_MAX"
    fi
    if [[ -n "$BUDGET_STRESS_PROXY_CONFLICTS_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "stress proxy tag conflicts" "${STRESS_PROXY_CONFLICTS:-0}" "$BUDGET_STRESS_PROXY_CONFLICTS_MAX"
    fi
    if [[ -n "$BUDGET_STRESS_PROXY_HEALTH_CHECK_FAILS_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "stress proxy health check failures" "${STRESS_PROXY_HEALTH_CHECK_FAILS:-0}" "$BUDGET_STRESS_PROXY_HEALTH_CHECK_FAILS_MAX"
    fi
    if [[ -n "$BUDGET_STRESS_PARALLEL_AVG_SECONDS_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "stress parallel average seconds" "${STRESS_AVG_SECONDS:-0}" "$BUDGET_STRESS_PARALLEL_AVG_SECONDS_MAX"
    fi
    if [[ -n "$BUDGET_STRESS_CACHE_READ_ERRORS_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "stress sccache cache read errors" "${STRESS_CACHE_READ_ERRORS:-0}" "$BUDGET_STRESS_CACHE_READ_ERRORS_MAX"
    fi
    if [[ -n "$BUDGET_STRESS_CACHE_TIMEOUTS_MAX" ]]; then
      checks=$((checks + 1))
      budget_check_max "stress sccache cache timeouts" "${STRESS_CACHE_TIMEOUTS:-0}" "$BUDGET_STRESS_CACHE_TIMEOUTS_MAX"
    fi
  fi

  if (( checks == 0 )); then
    echo "  no budgets configured"
    return 0
  fi

  if (( BUDGET_FAILURES > 0 )); then
    echo "  budget failures: ${BUDGET_FAILURES}"
    return 1
  fi

  echo "  all checks passed (${checks})"
  return 0
}

phase_efficacy() {
  local phase_dir proxy_log warm_sccache_dir
  phase_dir="${LOG_DIR}/efficacy"
  proxy_log="${phase_dir}/proxy.log"
  warm_sccache_dir="$SCCACHE_DIR"
  if [[ "$EFFICACY_FRESH_WARM_SCCACHE_DIR" == "1" ]]; then
    warm_sccache_dir="$EFFICACY_WARM_SCCACHE_DIR"
  fi
  mkdir -p "$phase_dir"
  rm -f "$(proxy_request_metrics_path "$proxy_log")"

  echo ""
  echo "=== Phase 1: Key-stable efficacy ==="
  echo "Tag: ${EFFICACY_TAG}"
  echo "Target dir reused across runs: ${TARGET_ROOT}/efficacy-stable"

  if [[ "$USE_PROXY" == "1" ]]; then
    start_proxy "$EFFICACY_TAG" "$proxy_log" "$(phase_metadata_hints "sccache-efficacy-cold")"
    ensure_proxy_ready "$proxy_log"
    echo "Proxy running (pid=${PROXY_PID})"
  else
    echo "Using local sccache backend (no proxy process)"
  fi

  echo ""
  echo "Running efficacy cold pass..."
  reset_sccache
  run_build "efficacy-cold" "${TARGET_ROOT}/efficacy-stable" "${phase_dir}/cold.log"
  run_with_clean_sccache_env \
    "SCCACHE_SERVER_PORT=$SCCACHE_SERVER_PORT" \
    "SCCACHE_DIR=$SCCACHE_DIR" \
    sccache --show-stats >"${phase_dir}/cold-sccache-stats.txt" 2>&1
  print_stats_summary "Efficacy cold stats" "${phase_dir}/cold-sccache-stats.txt"
  EFFICACY_COLD_REQUESTS="$(stat_value 'Compile requests' "${phase_dir}/cold-sccache-stats.txt")"
  EFFICACY_COLD_HITS="$(stat_value 'Cache hits' "${phase_dir}/cold-sccache-stats.txt")"
  EFFICACY_COLD_MISSES="$(stat_value 'Cache misses' "${phase_dir}/cold-sccache-stats.txt")"
  EFFICACY_COLD_REQUESTS="${EFFICACY_COLD_REQUESTS:-0}"
  EFFICACY_COLD_HITS="${EFFICACY_COLD_HITS:-0}"
  EFFICACY_COLD_MISSES="${EFFICACY_COLD_MISSES:-0}"

  echo ""
  echo "Waiting for writes to settle (${SETTLE_SECS}s)..."
  sleep "$SETTLE_SECS"

  echo ""
  echo "Restarting cache backend for efficacy warm pass..."
  if [[ "$USE_PROXY" == "1" ]]; then
    start_proxy "$EFFICACY_TAG" "$proxy_log" "$(phase_metadata_hints "sccache-efficacy-warm")"
    ensure_proxy_ready "$proxy_log"
    echo ""
    echo "=== Phase 1b: Verify published remote tag before efficacy warm pass ==="
    if ! verify_remote_tag_visible "$TMP_BINARY" "$WORKSPACE" "$EFFICACY_TAG" "$phase_dir" "${BUDGET_EFFICACY_REMOTE_TAG_HITS_MIN:-1}" "${REMOTE_TAG_VERIFY_ATTEMPTS}" "${REMOTE_TAG_VERIFY_SLEEP_SECS}" "$proxy_log"; then
      exit 1
    fi
    EFFICACY_REMOTE_TAG_HITS="${REMOTE_TAG_CHECK_HITS:-0}"
    EFFICACY_REMOTE_TAG_MISSES="${REMOTE_TAG_CHECK_MISSES:-0}"
  else
    EFFICACY_REMOTE_TAG_HITS="0"
    EFFICACY_REMOTE_TAG_MISSES="0"
  fi

  if [[ "$EFFICACY_FRESH_WARM_SCCACHE_DIR" == "1" ]]; then
    rm -rf "$warm_sccache_dir"
    mkdir -p "$warm_sccache_dir"
    echo "Using fresh warm sccache dir: ${warm_sccache_dir}"
  fi
  reset_sccache "$SCCACHE_SERVER_PORT" "$warm_sccache_dir"
  run_build "efficacy-warm" "${TARGET_ROOT}/efficacy-stable" "${phase_dir}/warm.log" "$SCCACHE_SERVER_PORT" "$warm_sccache_dir"
  run_with_clean_sccache_env \
    "SCCACHE_SERVER_PORT=$SCCACHE_SERVER_PORT" \
    "SCCACHE_DIR=$warm_sccache_dir" \
    sccache --show-stats >"${phase_dir}/warm-sccache-stats.txt" 2>&1
  print_stats_summary "Efficacy warm stats" "${phase_dir}/warm-sccache-stats.txt"
  if [[ "$USE_PROXY" == "1" ]]; then
    stop_proxy
    print_request_metrics_summary "$phase_dir" "Efficacy"
    if load_request_metrics_summary "$phase_dir"; then
      EFFICACY_CACHE_OPS_RECORDS="${request_metrics_cache_ops_sccache_get_records_total:-0}"
      EFFICACY_CACHE_OPS_HITS="${request_metrics_cache_ops_sccache_get_hits:-0}"
      EFFICACY_CACHE_OPS_MISSES="${request_metrics_cache_ops_sccache_get_misses:-0}"
      EFFICACY_CACHE_OPS_ERRORS="${request_metrics_cache_ops_sccache_get_errors:-0}"
      EFFICACY_CACHE_OPS_HIT_RATE="${request_metrics_cache_ops_sccache_get_hit_rate:-0}"
      echo "Efficacy cache ops (sccache get): records=${EFFICACY_CACHE_OPS_RECORDS}, hits=${EFFICACY_CACHE_OPS_HITS}, misses=${EFFICACY_CACHE_OPS_MISSES}, errors=${EFFICACY_CACHE_OPS_ERRORS}, hit_rate=${EFFICACY_CACHE_OPS_HIT_RATE}%"
    else
      EFFICACY_CACHE_OPS_RECORDS="0"
      EFFICACY_CACHE_OPS_HITS="0"
      EFFICACY_CACHE_OPS_MISSES="0"
      EFFICACY_CACHE_OPS_ERRORS="0"
      EFFICACY_CACHE_OPS_HIT_RATE="0"
      echo "Efficacy cache ops (sccache): metrics unavailable"
    fi
  else
    EFFICACY_CACHE_OPS_RECORDS="0"
    EFFICACY_CACHE_OPS_HITS="0"
    EFFICACY_CACHE_OPS_MISSES="0"
    EFFICACY_CACHE_OPS_ERRORS="0"
    EFFICACY_CACHE_OPS_HIT_RATE="0"
  fi

  EFFICACY_COLD_SECONDS="$(cat "${phase_dir}/cold.log.seconds")"
  EFFICACY_WARM_SECONDS="$(cat "${phase_dir}/warm.log.seconds")"
  EFFICACY_DELTA="$(format_delta "$EFFICACY_COLD_SECONDS" "$EFFICACY_WARM_SECONDS")"
  EFFICACY_RUST_HIT_RATE="$(stat_value 'Cache hits rate (Rust)' "${phase_dir}/warm-sccache-stats.txt")"
  EFFICACY_RUST_HIT_RATE="${EFFICACY_RUST_HIT_RATE:-0}"
  EFFICACY_AVG_READ_HIT="$(stat_value 'Average cache read hit' "${phase_dir}/warm-sccache-stats.txt")"
  EFFICACY_AVG_READ_HIT="${EFFICACY_AVG_READ_HIT:-0}"
  EFFICACY_WARM_REQUESTS="$(stat_value 'Compile requests' "${phase_dir}/warm-sccache-stats.txt")"
  EFFICACY_WARM_HITS="$(stat_value 'Cache hits' "${phase_dir}/warm-sccache-stats.txt")"
  EFFICACY_WARM_MISSES="$(stat_value 'Cache misses' "${phase_dir}/warm-sccache-stats.txt")"
  EFFICACY_WARM_REQUESTS="${EFFICACY_WARM_REQUESTS:-0}"
  EFFICACY_WARM_HITS="${EFFICACY_WARM_HITS:-0}"
  EFFICACY_WARM_MISSES="${EFFICACY_WARM_MISSES:-0}"
  EFFICACY_CACHE_READ_ERRORS="$(stat_value 'Cache read errors' "${phase_dir}/warm-sccache-stats.txt")"
  EFFICACY_CACHE_TIMEOUTS="$(stat_value 'Cache timeouts' "${phase_dir}/warm-sccache-stats.txt")"
  EFFICACY_CACHE_READ_ERRORS="${EFFICACY_CACHE_READ_ERRORS:-0}"
  EFFICACY_CACHE_TIMEOUTS="${EFFICACY_CACHE_TIMEOUTS:-0}"
  EFFICACY_TWO_PASS_HIT_RATE="$(awk \
    -v cold_hits="${EFFICACY_COLD_HITS}" \
    -v cold_misses="${EFFICACY_COLD_MISSES}" \
    -v warm_hits="${EFFICACY_WARM_HITS}" \
    -v warm_misses="${EFFICACY_WARM_MISSES}" \
    'BEGIN {
      total_hits = cold_hits + warm_hits;
      total_misses = cold_misses + warm_misses;
      denom = total_hits + total_misses;
      if (denom == 0) { printf "0.00" } else { printf "%.2f", (total_hits * 100) / denom }
    }'
  )"
  EFFICACY_CACHE_OPS_SCCACHE_HIT_RATE_DELTA="$(awk \
    -v cache_ops="${EFFICACY_CACHE_OPS_HIT_RATE:-0}" \
    -v sccache="${EFFICACY_TWO_PASS_HIT_RATE:-0}" \
    'BEGIN {
      delta = cache_ops - sccache;
      if (delta < 0) { delta = -delta }
      printf "%.2f", delta
    }'
  )"
  if [[ "$USE_PROXY" == "1" ]]; then
    EFFICACY_PROXY_429="$(count_pattern "$proxy_log" '429 Too Many Requests')"
    EFFICACY_PROXY_CONFLICTS="$(count_pattern "$proxy_log" 'tag conflict')"
  else
    EFFICACY_PROXY_429="0"
    EFFICACY_PROXY_CONFLICTS="0"
  fi
}

phase_stress() {
  local phase_dir proxy_log lock_waits warm_sum avg prewarm_sum prewarm_avg health_check_fails
  local parallel_req_sum parallel_hit_sum parallel_miss_sum parallel_hit_rate
  local parallel_failed all_done daemon_timeouts daemon_shutdowns
  local parallel_port_seed sccache_port_i sccache_dir_i req_i hits_i misses_i
  local prewarm_target_dir prewarm_stats_file
  local -a build_pids=()
  local -a stress_sccache_ports=()
  local -a stress_sccache_dirs=()
  phase_dir="${LOG_DIR}/stress"
  proxy_log="${phase_dir}/proxy.log"
  mkdir -p "$phase_dir"
  rm -f "$(proxy_request_metrics_path "$proxy_log")"

  echo ""
  echo "=== Phase 2: Parallel contention stress ==="
  echo "Tag: ${STRESS_TAG}"
  echo "Parallel jobs: ${PARALLEL_JOBS}"
  if [[ "$STRESS_SCCACHE_ISOLATION" == "1" ]]; then
    echo "Stress parallel sccache mode: isolated daemon per job"
  else
    echo "Stress parallel sccache mode: shared daemon"
  fi

  if [[ "$USE_PROXY" == "1" ]]; then
    start_proxy "$STRESS_TAG" "$proxy_log" "$(phase_metadata_hints "sccache-stress-prewarm")"
    ensure_proxy_ready "$proxy_log"
    echo "Proxy running (pid=${PROXY_PID})"
  else
    echo "Using local sccache backend (no proxy process)"
  fi

  echo ""
  echo "Running stress prewarm pass..."
  reset_sccache
  prewarm_sum=0
  health_check_fails=0
  for i in $(seq 1 "$PARALLEL_JOBS"); do
    if [[ "$STRESS_PREWARM_FIXED_TARGET_DIR" == "1" ]]; then
      prewarm_target_dir="${STRESS_PREWARM_TARGET_DIR}"
    else
      prewarm_target_dir="${TARGET_ROOT}/stress-job-${i}"
    fi
    run_build "stress-prewarm-${i}" "${prewarm_target_dir}" "${phase_dir}/prewarm-${i}.log"
    health_check_fails="$((health_check_fails + $(count_pattern "${phase_dir}/prewarm-${i}.log" 'proxy health check failed')))"
    prewarm_sum="$((prewarm_sum + $(cat "${phase_dir}/prewarm-${i}.log.seconds")))"
    prewarm_stats_file="${phase_dir}/prewarm-${i}-sccache-stats.txt"
    run_with_clean_sccache_env \
      "SCCACHE_SERVER_PORT=$SCCACHE_SERVER_PORT" \
      "SCCACHE_DIR=$SCCACHE_DIR" \
      sccache --show-stats >"${prewarm_stats_file}" 2>&1
    print_stats_summary "Stress prewarm stats pass ${i}" "${prewarm_stats_file}"
    if [[ "$USE_PROXY" == "1" && "$i" -lt "$PARALLEL_JOBS" ]]; then
      echo "Waiting for writes to settle (${SETTLE_SECS}s) before next stress prewarm build..."
      sleep "$SETTLE_SECS"
      echo "Restarting cache backend before stress-prewarm-$((i + 1))..."
      start_proxy "$STRESS_TAG" "$proxy_log" "$(phase_metadata_hints "sccache-stress-prewarm")"
      ensure_proxy_ready "$proxy_log"
    fi
  done
  run_with_clean_sccache_env \
    "SCCACHE_SERVER_PORT=$SCCACHE_SERVER_PORT" \
    "SCCACHE_DIR=$SCCACHE_DIR" \
    sccache --show-stats >"${phase_dir}/prewarm-sccache-stats.txt" 2>&1
  print_stats_summary "Stress prewarm stats" "${phase_dir}/prewarm-sccache-stats.txt"

  echo ""
  echo "Waiting for writes to settle (${SETTLE_SECS}s)..."
  sleep "$SETTLE_SECS"

  echo ""
  echo "Restarting cache backend for stress parallel pass..."
  if [[ "$USE_PROXY" == "1" ]]; then
    start_proxy "$STRESS_TAG" "$proxy_log" "$(phase_metadata_hints "sccache-stress-parallel")"
    ensure_proxy_ready "$proxy_log"
  fi

  if [[ "$STRESS_SCCACHE_ISOLATION" == "1" ]]; then
    parallel_port_seed="$STRESS_SCCACHE_PORT_BASE"
    for i in $(seq 1 "$PARALLEL_JOBS"); do
      sccache_port_i="$(next_available_sccache_port "$parallel_port_seed")"
      parallel_port_seed=$((sccache_port_i + 1))
      sccache_dir_i="${TMP_ROOT}/sccache-${RUN_ID}-stress-${i}"
      mkdir -p "$sccache_dir_i"
      register_sccache_instance "$sccache_port_i" "$sccache_dir_i"
      reset_sccache "$sccache_port_i" "$sccache_dir_i"
      stress_sccache_ports+=("$sccache_port_i")
      stress_sccache_dirs+=("$sccache_dir_i")
      echo "stress-parallel-${i} sccache: port=${sccache_port_i}, dir=${sccache_dir_i}"
      run_build "stress-parallel-${i}" "${TARGET_ROOT}/stress-job-${i}" "${phase_dir}/parallel-${i}.log" "$sccache_port_i" "$sccache_dir_i" &
      build_pids+=($!)
    done
  else
    reset_sccache
    for i in $(seq 1 "$PARALLEL_JOBS"); do
      stress_sccache_ports+=("$SCCACHE_SERVER_PORT")
      stress_sccache_dirs+=("$SCCACHE_DIR")
      run_build "stress-parallel-${i}" "${TARGET_ROOT}/stress-job-${i}" "${phase_dir}/parallel-${i}.log" &
      build_pids+=($!)
    done
  fi

  parallel_failed=0
  while true; do
    all_done="true"
    for pid in "${build_pids[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        all_done="false"
        break
      fi
    done
    if [[ "$all_done" == "true" ]]; then
      break
    fi
    echo "  [heartbeat] parallel builds running... ($(date -u +%H:%M:%S))"
    sleep 30
  done
  for pid in "${build_pids[@]}"; do
    if wait "$pid"; then
      :
    else
      parallel_failed=1
    fi
  done

  daemon_timeouts=0
  daemon_shutdowns=0
  for i in $(seq 1 "$PARALLEL_JOBS"); do
    daemon_timeouts="$((daemon_timeouts + $(count_pattern "${phase_dir}/parallel-${i}.log" 'Timed out waiting for server startup')))"
    daemon_shutdowns="$((daemon_shutdowns + $(count_pattern "${phase_dir}/parallel-${i}.log" 'server looks like it shut down unexpectedly')))"
  done
  STRESS_SCCACHE_STARTUP_TIMEOUTS="$daemon_timeouts"
  STRESS_SCCACHE_UNEXPECTED_SHUTDOWNS="$daemon_shutdowns"
  if [[ "$daemon_timeouts" -gt 0 || "$daemon_shutdowns" -gt 0 ]]; then
    echo "WARNING: stress parallel detected sccache instability (startup_timeouts=${daemon_timeouts}, unexpected_shutdowns=${daemon_shutdowns})"
  fi

  if [[ "$parallel_failed" -ne 0 ]]; then
    echo "ERROR: one or more stress parallel jobs failed"
    return 1
  fi

  if [[ "$STRESS_SCCACHE_ISOLATION" == "1" ]]; then
    parallel_req_sum=0
    parallel_hit_sum=0
    parallel_miss_sum=0
    for i in $(seq 1 "$PARALLEL_JOBS"); do
      SCCACHE_SERVER_PORT="${stress_sccache_ports[$((i - 1))]}" \
        SCCACHE_DIR="${stress_sccache_dirs[$((i - 1))]}" \
        run_with_clean_sccache_env sccache --show-stats >"${phase_dir}/parallel-${i}-sccache-stats.txt" 2>&1
      print_stats_summary "Stress parallel stats job ${i}" "${phase_dir}/parallel-${i}-sccache-stats.txt"
      req_i="$(stat_value 'Compile requests' "${phase_dir}/parallel-${i}-sccache-stats.txt")"
      hits_i="$(stat_value 'Cache hits' "${phase_dir}/parallel-${i}-sccache-stats.txt")"
      misses_i="$(stat_value 'Cache misses' "${phase_dir}/parallel-${i}-sccache-stats.txt")"
      req_i="${req_i:-0}"
      hits_i="${hits_i:-0}"
      misses_i="${misses_i:-0}"
      parallel_req_sum=$((parallel_req_sum + req_i))
      parallel_hit_sum=$((parallel_hit_sum + hits_i))
      parallel_miss_sum=$((parallel_miss_sum + misses_i))
    done
    parallel_hit_rate="$(awk -v hits="$parallel_hit_sum" -v req="$parallel_req_sum" 'BEGIN { if (req == 0) { printf "0.00" } else { printf "%.2f", (hits * 100) / req } }')"
    cat >"${phase_dir}/parallel-sccache-stats.txt" <<EOF
Compile requests $parallel_req_sum
Cache hits $parallel_hit_sum
Cache misses $parallel_miss_sum
Cache hits rate $parallel_hit_rate %
Cache hits rate (Rust) $parallel_hit_rate %
EOF
  else
    run_with_clean_sccache_env \
      "SCCACHE_SERVER_PORT=$SCCACHE_SERVER_PORT" \
      "SCCACHE_DIR=$SCCACHE_DIR" \
      sccache --show-stats >"${phase_dir}/parallel-sccache-stats.txt" 2>&1
  fi
  print_stats_summary "Stress parallel stats" "${phase_dir}/parallel-sccache-stats.txt"
  if [[ "$USE_PROXY" == "1" ]]; then
    stop_proxy
    print_request_metrics_summary "$phase_dir" "Stress"
  fi

  prewarm_avg="$((prewarm_sum / PARALLEL_JOBS))"
  STRESS_PREWARM_SECONDS="$prewarm_avg"
  warm_sum=0
  lock_waits=0
  for i in $(seq 1 "$PARALLEL_JOBS"); do
    warm_sum="$((warm_sum + $(cat "${phase_dir}/parallel-${i}.log.seconds")))"
    lock_waits="$((lock_waits + $(count_pattern "${phase_dir}/parallel-${i}.log" 'Blocking waiting for file lock')))"
    health_check_fails="$((health_check_fails + $(count_pattern "${phase_dir}/parallel-${i}.log" 'proxy health check failed')))"
  done
  avg="$((warm_sum / PARALLEL_JOBS))"
  STRESS_AVG_SECONDS="$avg"
  STRESS_DELTA="$(format_delta "$STRESS_PREWARM_SECONDS" "$STRESS_AVG_SECONDS")"
  STRESS_RUST_HIT_RATE="$(stat_value 'Cache hits rate (Rust)' "${phase_dir}/parallel-sccache-stats.txt")"
  STRESS_RUST_HIT_RATE="${STRESS_RUST_HIT_RATE:-0}"
  STRESS_PREWARM_REQUESTS="$(stat_value 'Compile requests' "${phase_dir}/prewarm-sccache-stats.txt")"
  STRESS_PREWARM_HITS="$(stat_value 'Cache hits' "${phase_dir}/prewarm-sccache-stats.txt")"
  STRESS_PREWARM_MISSES="$(stat_value 'Cache misses' "${phase_dir}/prewarm-sccache-stats.txt")"
  STRESS_PARALLEL_REQUESTS="$(stat_value 'Compile requests' "${phase_dir}/parallel-sccache-stats.txt")"
  STRESS_PARALLEL_HITS="$(stat_value 'Cache hits' "${phase_dir}/parallel-sccache-stats.txt")"
  STRESS_PARALLEL_MISSES="$(stat_value 'Cache misses' "${phase_dir}/parallel-sccache-stats.txt")"
  STRESS_PREWARM_REQUESTS="${STRESS_PREWARM_REQUESTS:-0}"
  STRESS_PREWARM_HITS="${STRESS_PREWARM_HITS:-0}"
  STRESS_PREWARM_MISSES="${STRESS_PREWARM_MISSES:-0}"
  STRESS_PARALLEL_REQUESTS="${STRESS_PARALLEL_REQUESTS:-0}"
  STRESS_PARALLEL_HITS="${STRESS_PARALLEL_HITS:-0}"
  STRESS_PARALLEL_MISSES="${STRESS_PARALLEL_MISSES:-0}"
  STRESS_CACHE_READ_ERRORS="$(stat_value 'Cache read errors' "${phase_dir}/parallel-sccache-stats.txt")"
  STRESS_CACHE_TIMEOUTS="$(stat_value 'Cache timeouts' "${phase_dir}/parallel-sccache-stats.txt")"
  STRESS_CACHE_READ_ERRORS="${STRESS_CACHE_READ_ERRORS:-0}"
  STRESS_CACHE_TIMEOUTS="${STRESS_CACHE_TIMEOUTS:-0}"
  STRESS_LOCK_WAITS="$lock_waits"
  STRESS_PROXY_HEALTH_CHECK_FAILS="$health_check_fails"
  if [[ "$USE_PROXY" == "1" ]]; then
    STRESS_PROXY_429="$(count_pattern "$proxy_log" '429 Too Many Requests')"
    STRESS_PROXY_CONFLICTS="$(count_pattern "$proxy_log" 'tag conflict')"
  else
    STRESS_PROXY_429="0"
    STRESS_PROXY_CONFLICTS="0"
    STRESS_PROXY_HEALTH_CHECK_FAILS="0"
  fi
}

if [[ "$RUN_EFFICACY" == "1" ]]; then
  phase_efficacy
fi
if [[ "$RUN_STRESS" == "1" ]]; then
  phase_stress
fi

echo ""
echo "========================================="
if [[ "$RUN_EFFICACY" == "1" ]]; then
  echo "Phase 1 (key-stable efficacy)"
  echo "  Scope:                same-runner, reused target dir"
  echo "  Cold:                 ${EFFICACY_COLD_SECONDS}s"
  echo "  Warm:                 ${EFFICACY_WARM_SECONDS}s"
  echo "  Delta (cold-warm):    ${EFFICACY_DELTA}"
  echo "  Warm Rust hit rate:   ${EFFICACY_RUST_HIT_RATE}%"
  echo "  Two-pass Rust hit:    ${EFFICACY_TWO_PASS_HIT_RATE}%"
  echo "  Remote tag hits/miss: ${EFFICACY_REMOTE_TAG_HITS:-0}/${EFFICACY_REMOTE_TAG_MISSES:-0}"
  echo "  Warm req/hit/miss:    ${EFFICACY_WARM_REQUESTS}/${EFFICACY_WARM_HITS}/${EFFICACY_WARM_MISSES}"
  echo "  Cold req/hit/miss:    ${EFFICACY_COLD_REQUESTS}/${EFFICACY_COLD_HITS}/${EFFICACY_COLD_MISSES}"
  echo "  Cache ops GET hit:    ${EFFICACY_CACHE_OPS_HIT_RATE}% (records=${EFFICACY_CACHE_OPS_RECORDS}, hits=${EFFICACY_CACHE_OPS_HITS}, misses=${EFFICACY_CACHE_OPS_MISSES}, errors=${EFFICACY_CACHE_OPS_ERRORS})"
  echo "  Hit-rate delta:       ${EFFICACY_CACHE_OPS_SCCACHE_HIT_RATE_DELTA:-0}pp (cache-ops GET vs two-pass sccache)"
  echo "  Cache read errors:    ${EFFICACY_CACHE_READ_ERRORS}"
  echo "  Cache timeouts:       ${EFFICACY_CACHE_TIMEOUTS}"
  echo "  Warm avg read hit:    ${EFFICACY_AVG_READ_HIT}s"
  echo "  Proxy 429:            ${EFFICACY_PROXY_429:-0}"
  echo "  Proxy tag conflicts:  ${EFFICACY_PROXY_CONFLICTS:-0}"
  echo "  Note:                 compare against internal cache-registry health only, not fresh-runner benchmark repos"
  echo "  Logs:                 ${LOG_DIR}/efficacy"
fi

if [[ "$RUN_STRESS" == "1" ]]; then
  echo ""
  echo "Phase 2 (parallel contention stress)"
  echo "  Prewarm:              ${STRESS_PREWARM_SECONDS}s"
  for i in $(seq 1 "$PARALLEL_JOBS"); do
    echo "  Parallel job ${i}:      $(cat "${LOG_DIR}/stress/parallel-${i}.log.seconds")s"
  done
  echo "  Parallel avg:         ${STRESS_AVG_SECONDS}s"
  echo "  Delta (prewarm-avg):  ${STRESS_DELTA}"
  echo "  Prewarm req/hit/miss: ${STRESS_PREWARM_REQUESTS}/${STRESS_PREWARM_HITS}/${STRESS_PREWARM_MISSES}"
  echo "  Parallel req/hit/miss:${STRESS_PARALLEL_REQUESTS}/${STRESS_PARALLEL_HITS}/${STRESS_PARALLEL_MISSES}"
  echo "  Parallel Rust hit:    ${STRESS_RUST_HIT_RATE}%"
  echo "  Cache read errors:    ${STRESS_CACHE_READ_ERRORS}"
  echo "  Cache timeouts:       ${STRESS_CACHE_TIMEOUTS}"
  echo "  sccache start timeouts: ${STRESS_SCCACHE_STARTUP_TIMEOUTS:-0}"
  echo "  sccache unexpected shutdowns: ${STRESS_SCCACHE_UNEXPECTED_SHUTDOWNS:-0}"
  echo "  Local lock waits:     ${STRESS_LOCK_WAITS}"
  echo "  Proxy 429:            ${STRESS_PROXY_429:-0}"
  echo "  Proxy tag conflicts:  ${STRESS_PROXY_CONFLICTS:-0}"
  echo "  Proxy health failures:${STRESS_PROXY_HEALTH_CHECK_FAILS:-0}"
  echo "  Logs:                 ${LOG_DIR}/stress"
fi

budget_status=0
if ! evaluate_budgets; then
  budget_status=1
fi

echo ""
echo "Root logs: ${LOG_DIR}"
echo "========================================="

if [[ "$budget_status" -ne 0 ]]; then
  exit 1
fi
