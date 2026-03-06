#!/usr/bin/env bash
set -euo pipefail

PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT_A="${PROXY_PORT_A:-5050}"
PROXY_PORT_B="${PROXY_PORT_B:-5052}"
PROXY_PORT_VERIFY="${PROXY_PORT_VERIFY:-5054}"
SCCACHE_PORT_A="${SCCACHE_PORT_A:-$((4200 + (RANDOM % 1000)))}"
SCCACHE_PORT_B="${SCCACHE_PORT_B:-$((SCCACHE_PORT_A + 1))}"
TAG="${TAG:-bc-e2e-cli-dual-proxy-contention}"
WORKSPACE="${WORKSPACE:-${BORINGCACHE_DEFAULT_WORKSPACE:-boringcache/testing2}}"
BINARY="${BINARY:-./target/release/boringcache}"
TMP_ROOT="${TMPDIR:-/tmp}/boringcache-dual-proxy"
BINARY_DIR="${TMP_ROOT}/bin"
TMP_BINARY="${BINARY_DIR}/boringcache"
TARGET_ROOT="${TMP_ROOT}/targets"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${LOG_DIR:-${TMP_ROOT}/logs-${RUN_ID}}"
CARGO_CMD="${CARGO_CMD:-cargo build --release --locked}"
RUST_LOG_LEVEL="${RUST_LOG_LEVEL:-info}"
SETTLE_SECS="${SETTLE_SECS:-10}"
SHUTDOWN_WAIT="${SHUTDOWN_WAIT:-30}"
BUILD_TIMEOUT_SECS="${BUILD_TIMEOUT_SECS:-0}"
BUILD_HEARTBEAT_SECS="${BUILD_HEARTBEAT_SECS:-30}"
BUILD_CLEANUP_WAIT_SECS="${BUILD_CLEANUP_WAIT_SECS:-20}"
BUILD_FAILURE_TAIL_LINES="${BUILD_FAILURE_TAIL_LINES:-60}"
PROXY_READY_TIMEOUT_SECS="${PROXY_READY_TIMEOUT_SECS:-90}"
PROXY_READY_POLL_SECS="${PROXY_READY_POLL_SECS:-1}"
PORT_RECLAIM_WAIT_SECS="${PORT_RECLAIM_WAIT_SECS:-15}"
PREWARM_SCCACHE_DIR="${TMP_ROOT}/sccache-prewarm-${RUN_ID}"
SCCACHE_DIR_A="${TMP_ROOT}/sccache-a-${RUN_ID}"
SCCACHE_DIR_B="${TMP_ROOT}/sccache-b-${RUN_ID}"

PROXY_PID_A=""
PROXY_PID_B=""
PROXY_PID_VERIFY=""
INTERRUPTED="0"
declare -a ACTIVE_BUILD_PIDS=()

require_numeric() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "ERROR: ${name} must be a non-negative integer"
    exit 1
  fi
}

require_positive() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: ${name} must be a positive integer"
    exit 1
  fi
}

require_port() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[1-9][0-9]*$ ]] || (( value > 65535 )); then
    echo "ERROR: ${name} must be an integer between 1 and 65535"
    exit 1
  fi
}

if [[ -z "${BORINGCACHE_API_TOKEN:-}" ]]; then
  echo "ERROR: BORINGCACHE_API_TOKEN not set"
  exit 1
fi

require_port "PROXY_PORT_A" "$PROXY_PORT_A"
require_port "PROXY_PORT_B" "$PROXY_PORT_B"
require_port "PROXY_PORT_VERIFY" "$PROXY_PORT_VERIFY"
require_port "SCCACHE_PORT_A" "$SCCACHE_PORT_A"
require_port "SCCACHE_PORT_B" "$SCCACHE_PORT_B"
require_positive "SETTLE_SECS" "$SETTLE_SECS"
require_positive "SHUTDOWN_WAIT" "$SHUTDOWN_WAIT"
require_numeric "BUILD_TIMEOUT_SECS" "$BUILD_TIMEOUT_SECS"
require_positive "BUILD_HEARTBEAT_SECS" "$BUILD_HEARTBEAT_SECS"
require_positive "BUILD_CLEANUP_WAIT_SECS" "$BUILD_CLEANUP_WAIT_SECS"
require_positive "BUILD_FAILURE_TAIL_LINES" "$BUILD_FAILURE_TAIL_LINES"
require_positive "PROXY_READY_TIMEOUT_SECS" "$PROXY_READY_TIMEOUT_SECS"
require_positive "PROXY_READY_POLL_SECS" "$PROXY_READY_POLL_SECS"
require_positive "PORT_RECLAIM_WAIT_SECS" "$PORT_RECLAIM_WAIT_SECS"

if [[ "$SCCACHE_PORT_A" == "$SCCACHE_PORT_B" ]]; then
  echo "ERROR: SCCACHE_PORT_A and SCCACHE_PORT_B must be different"
  exit 1
fi

for dep in sccache curl pgrep ps; do
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
else
  echo "ERROR: either lsof or ss must be available to inspect listening ports"
  exit 1
fi

remove_active_build_pid() {
  local target_pid="$1"
  local -a remaining=()
  local pid
  for pid in "${ACTIVE_BUILD_PIDS[@]}"; do
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

port_listener_pids() {
  local port="$1"
  if [[ "$PORT_TOOL" == "lsof" ]]; then
    lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
  else
    ss -lntp "sport = :$port" 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | sort -u
  fi
}

port_listener_details() {
  local port="$1"
  if [[ "$PORT_TOOL" == "lsof" ]]; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
  else
    ss -lntp "sport = :$port" 2>/dev/null || true
  fi
}

reclaim_stale_proxy_port() {
  local port="$1"
  local log_file="$2"
  local listener_pids
  local pid
  local cmd
  listener_pids="$(port_listener_pids "$port")"
  if [[ -z "$listener_pids" ]]; then
    return 0
  fi
  for pid in $listener_pids; do
    cmd="$(ps -p "$pid" -o command= 2>/dev/null || true)"
    if [[ "$cmd" == *"boringcache"* && "$cmd" == *"cache-registry"* ]]; then
      echo "WARNING: reclaiming stale proxy on port ${port} (pid=${pid})" | tee -a "$log_file"
      stop_pid_tree "$pid" "stale proxy" "$PORT_RECLAIM_WAIT_SECS"
    fi
  done
  listener_pids="$(port_listener_pids "$port")"
  if [[ -n "$listener_pids" ]]; then
    echo "ERROR: proxy port ${port} is already in use" | tee -a "$log_file"
    port_listener_details "$port" | tee -a "$log_file"
    exit 1
  fi
}

stop_proxy_by_var() {
  local pid_var="$1"
  local label="$2"
  local pid="${!pid_var:-}"
  if [[ -n "$pid" ]]; then
    stop_pid_tree "$pid" "proxy ${label}" "$SHUTDOWN_WAIT"
    eval "${pid_var}=''"
  fi
}

stop_all() {
  stop_proxy_by_var "PROXY_PID_A" "A"
  stop_proxy_by_var "PROXY_PID_B" "B"
  stop_proxy_by_var "PROXY_PID_VERIFY" "verify"
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
  for pid in "${ACTIVE_BUILD_PIDS[@]}"; do
    stop_pid_tree "$pid" "build" "$BUILD_CLEANUP_WAIT_SECS"
  done
  ACTIVE_BUILD_PIDS=()
  stop_all
  SCCACHE_SERVER_PORT="$SCCACHE_PORT_A" SCCACHE_DIR="$PREWARM_SCCACHE_DIR" sccache --stop-server >/dev/null 2>&1 || true
  SCCACHE_SERVER_PORT="$SCCACHE_PORT_A" SCCACHE_DIR="$SCCACHE_DIR_A" sccache --stop-server >/dev/null 2>&1 || true
  SCCACHE_SERVER_PORT="$SCCACHE_PORT_B" SCCACHE_DIR="$SCCACHE_DIR_B" sccache --stop-server >/dev/null 2>&1 || true
  rm -f "$TMP_BINARY" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap handle_interrupt INT TERM

if [[ ! -x "$BINARY" ]]; then
  echo "Building boringcache..."
  cargo build --release --locked 2>&1 | tail -n 5
fi

mkdir -p "$BINARY_DIR" "$TARGET_ROOT" "$LOG_DIR" "$PREWARM_SCCACHE_DIR" "$SCCACHE_DIR_A" "$SCCACHE_DIR_B"
cp "$BINARY" "$TMP_BINARY"
chmod +x "$TMP_BINARY"

echo "=== Dual-Proxy Contention Test ==="
echo "Binary:       $TMP_BINARY"
echo "Workspace:    $WORKSPACE"
echo "Tag:          $TAG"
echo "Proxy A:      ${PROXY_HOST}:${PROXY_PORT_A}"
echo "Proxy B:      ${PROXY_HOST}:${PROXY_PORT_B}"
echo "Verify proxy: ${PROXY_HOST}:${PROXY_PORT_VERIFY}"
echo "sccache A:    port ${SCCACHE_PORT_A}"
echo "sccache B:    port ${SCCACHE_PORT_B}"
echo "sccache prewarm dir: ${PREWARM_SCCACHE_DIR}"
echo "sccache A dir: ${SCCACHE_DIR_A}"
echo "sccache B dir: ${SCCACHE_DIR_B}"
echo "Build timeout: ${BUILD_TIMEOUT_SECS}s (0 disables)"
echo "Build heartbeat: ${BUILD_HEARTBEAT_SECS}s"
echo "Cargo cmd:    $CARGO_CMD"
echo "Logs:         $LOG_DIR"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
  echo "${label}: requests=${req:-0}, hits=${hits:-0}, misses=${misses:-0}, hit_rate=${rate:-0}%, rust_hit_rate=${rust_rate:-0}%"
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

format_delta() {
  local base="$1"
  local current="$2"
  local delta pct
  delta="$((base - current))"
  pct="$(awk -v saved="$delta" -v baseline="$base" 'BEGIN { if (baseline == 0) { printf "0.00" } else { printf "%.2f", (saved * 100) / baseline } }')"
  echo "${delta}s (${pct}%)"
}

start_proxy() {
  local label="$1"
  local port="$2"
  local log_file="$3"
  local pid_var="$4"
  stop_proxy_by_var "$pid_var" "$label"
  reclaim_stale_proxy_port "$port" "$log_file"
  {
    echo ""
    echo "=== Proxy ${label} start $(date -u +"%Y-%m-%dT%H:%M:%SZ") tag=${TAG} port=${port} ==="
  } >>"$log_file"
  BORINGCACHE_API_TOKEN="$BORINGCACHE_API_TOKEN" \
    RUST_LOG="$RUST_LOG_LEVEL" \
    "$TMP_BINARY" cache-registry "$WORKSPACE" "$TAG" \
    --host "$PROXY_HOST" \
    --port "$port" \
    --no-platform \
    --no-git >>"$log_file" 2>&1 &
  eval "${pid_var}=$!"
  sleep 2
}

ensure_proxy_ready() {
  local port="$1"
  local log_file="$2"
  local pid_var="$3"
  local url="http://${PROXY_HOST}:${port}/v2/"
  local attempts
  attempts="$((PROXY_READY_TIMEOUT_SECS / PROXY_READY_POLL_SECS))"
  if (( attempts < 1 )); then
    attempts=1
  fi
  for _ in $(seq 1 "$attempts"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    if [[ -n "${!pid_var:-}" ]] && ! kill -0 "${!pid_var}" >/dev/null 2>&1; then
      echo "ERROR: proxy ${port} exited before readiness check completed"
      tail -n 120 "$log_file" || true
      exit 1
    fi
    sleep "$PROXY_READY_POLL_SECS"
  done
  echo "ERROR: proxy on port ${port} failed to start within ${PROXY_READY_TIMEOUT_SECS}s"
  tail -n 120 "$log_file" || true
  exit 1
}

stop_proxy_graceful() {
  local pid_var="$1"
  local label="$2"
  if [[ -z "${!pid_var:-}" ]]; then
    return 0
  fi
  echo "Stopping proxy ${label} (pid=${!pid_var})..."
  stop_proxy_by_var "$pid_var" "$label"
  echo "Proxy ${label} stopped"
}

reset_sccache_for() {
  local port="$1"
  local sccache_dir="$2"
  local proxy_port="$3"
  local proxy_url="http://${PROXY_HOST}:${proxy_port}"
  SCCACHE_SERVER_PORT="$port" \
    SCCACHE_DIR="$sccache_dir" \
    sccache --stop-server >/dev/null 2>&1 || true
  sleep 1
  SCCACHE_SERVER_PORT="$port" \
    SCCACHE_DIR="$sccache_dir" \
    SCCACHE_WEBDAV_ENDPOINT="$proxy_url" \
    sccache --start-server >/dev/null 2>&1
  SCCACHE_SERVER_PORT="$port" \
    SCCACHE_DIR="$sccache_dir" \
    sccache --zero-stats >/dev/null 2>&1
}

run_build_for() {
  local label="$1"
  local target_dir="$2"
  local log_file="$3"
  local sccache_port="$4"
  local proxy_port="$5"
  local sccache_dir="$6"
  local proxy_url="http://${PROXY_HOST}:${proxy_port}"
  local start_ts end_ts elapsed
  local build_pid now next_heartbeat status latest_line
  rm -rf "$target_dir"
  mkdir -p "$target_dir"
  echo "${label} starting..."
  start_ts="$(date +%s)"
  SCCACHE_SERVER_PORT="$sccache_port" \
    SCCACHE_DIR="$sccache_dir" \
    SCCACHE_WEBDAV_ENDPOINT="$proxy_url" \
    RUSTC_WRAPPER=sccache \
    CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR="$target_dir" \
    bash -lc "$CARGO_CMD" >"$log_file" 2>&1 &
  build_pid=$!
  ACTIVE_BUILD_PIDS+=("$build_pid")
  next_heartbeat=$((start_ts + BUILD_HEARTBEAT_SECS))
  while kill -0 "$build_pid" >/dev/null 2>&1; do
    now="$(date +%s)"
    if [[ "$BUILD_TIMEOUT_SECS" -gt 0 ]] && (( now - start_ts >= BUILD_TIMEOUT_SECS )); then
      echo "ERROR: ${label} exceeded BUILD_TIMEOUT_SECS=${BUILD_TIMEOUT_SECS}s"
      stop_pid_tree "$build_pid" "$label build" "$BUILD_CLEANUP_WAIT_SECS"
      remove_active_build_pid "$build_pid"
      tail -n "$BUILD_FAILURE_TAIL_LINES" "$log_file" || true
      return 124
    fi
    if (( now >= next_heartbeat )); then
      elapsed="$((now - start_ts))"
      latest_line="$(awk 'NF { line=$0 } END { print line }' "$log_file" 2>/dev/null || true)"
      if [[ -n "$latest_line" ]]; then
        echo "  [heartbeat] ${label} running ${elapsed}s | ${latest_line}"
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
    return "$status"
  fi
  echo "${label} completed in ${elapsed}s"
}

# ---------------------------------------------------------------------------
# Phase 1: Prewarm — single proxy cold build to populate baseline
# ---------------------------------------------------------------------------

echo ""
echo "=== Phase 1: Prewarm (populate baseline tag) ==="
PREWARM_DIR="${LOG_DIR}/prewarm"
PREWARM_PROXY_LOG="${PREWARM_DIR}/proxy.log"
mkdir -p "$PREWARM_DIR" "$PREWARM_SCCACHE_DIR"

start_proxy "prewarm" "$PROXY_PORT_A" "$PREWARM_PROXY_LOG" "PROXY_PID_A"
ensure_proxy_ready "$PROXY_PORT_A" "$PREWARM_PROXY_LOG" "PROXY_PID_A"
echo "Prewarm proxy running (pid=${PROXY_PID_A})"

reset_sccache_for "$SCCACHE_PORT_A" "$PREWARM_SCCACHE_DIR" "$PROXY_PORT_A"
run_build_for "prewarm-cold" "${TARGET_ROOT}/prewarm" "${PREWARM_DIR}/cold.log" "$SCCACHE_PORT_A" "$PROXY_PORT_A" "$PREWARM_SCCACHE_DIR"
SCCACHE_SERVER_PORT="$SCCACHE_PORT_A" SCCACHE_DIR="$PREWARM_SCCACHE_DIR" sccache --show-stats >"${PREWARM_DIR}/cold-sccache-stats.txt" 2>&1
print_stats_summary "Prewarm cold stats" "${PREWARM_DIR}/cold-sccache-stats.txt"

SCCACHE_SERVER_PORT="$SCCACHE_PORT_A" SCCACHE_DIR="$PREWARM_SCCACHE_DIR" sccache --stop-server >/dev/null 2>&1 || true
echo "Waiting for writes to settle (${SETTLE_SECS}s)..."
sleep "$SETTLE_SECS"

stop_proxy_graceful "PROXY_PID_A" "prewarm"

PREWARM_COLD_SECONDS="$(cat "${PREWARM_DIR}/cold.log.seconds")"
PREWARM_ENTRIES="$(count_pattern "$PREWARM_PROXY_LOG" 'KV flush summary:')"
PREWARM_FLUSH_UPLOADED="$(sed -n 's/.*KV flush summary:.*uploaded=\([0-9]*\).*/\1/p' "$PREWARM_PROXY_LOG" | tail -1)"
PREWARM_FLUSH_UPLOADED="${PREWARM_FLUSH_UPLOADED:-0}"
echo "Prewarm: ${PREWARM_COLD_SECONDS}s, flush_uploaded=${PREWARM_FLUSH_UPLOADED}"

# ---------------------------------------------------------------------------
# Phase 2: Dual-proxy contention — two proxies racing on the same tag
# ---------------------------------------------------------------------------

echo ""
echo "=== Phase 2: Dual-Proxy Contention ==="
CONTENTION_DIR="${LOG_DIR}/contention"
PROXY_LOG_A="${CONTENTION_DIR}/proxy-a.log"
PROXY_LOG_B="${CONTENTION_DIR}/proxy-b.log"
mkdir -p "$CONTENTION_DIR" "$SCCACHE_DIR_A" "$SCCACHE_DIR_B"

start_proxy "A" "$PROXY_PORT_A" "$PROXY_LOG_A" "PROXY_PID_A"
start_proxy "B" "$PROXY_PORT_B" "$PROXY_LOG_B" "PROXY_PID_B"
ensure_proxy_ready "$PROXY_PORT_A" "$PROXY_LOG_A" "PROXY_PID_A"
ensure_proxy_ready "$PROXY_PORT_B" "$PROXY_LOG_B" "PROXY_PID_B"
echo "Proxy A running (pid=${PROXY_PID_A}) on port ${PROXY_PORT_A}"
echo "Proxy B running (pid=${PROXY_PID_B}) on port ${PROXY_PORT_B}"

reset_sccache_for "$SCCACHE_PORT_A" "$SCCACHE_DIR_A" "$PROXY_PORT_A"
reset_sccache_for "$SCCACHE_PORT_B" "$SCCACHE_DIR_B" "$PROXY_PORT_B"

echo "Starting parallel builds..."
CONTENTION_START="$(date +%s)"

run_build_for "contention-A" "${TARGET_ROOT}/contention-a" "${CONTENTION_DIR}/build-a.log" "$SCCACHE_PORT_A" "$PROXY_PORT_A" "$SCCACHE_DIR_A" &
BUILD_PID_A=$!

run_build_for "contention-B" "${TARGET_ROOT}/contention-b" "${CONTENTION_DIR}/build-b.log" "$SCCACHE_PORT_B" "$PROXY_PORT_B" "$SCCACHE_DIR_B" &
BUILD_PID_B=$!

BUILD_FAILED=0
while true; do
  all_done=true
  if kill -0 "$BUILD_PID_A" >/dev/null 2>&1; then
    all_done=false
  fi
  if kill -0 "$BUILD_PID_B" >/dev/null 2>&1; then
    all_done=false
  fi
  if [[ "$all_done" == "true" ]]; then
    break
  fi
  echo "  [heartbeat] contention builds running... ($(date -u +%H:%M:%S))"
  sleep 30
done
if wait "$BUILD_PID_A"; then :; else BUILD_FAILED=1; fi
if wait "$BUILD_PID_B"; then :; else BUILD_FAILED=1; fi

CONTENTION_END="$(date +%s)"
CONTENTION_WALL="$((CONTENTION_END - CONTENTION_START))"

if [[ "$BUILD_FAILED" -ne 0 ]]; then
  echo "WARNING: one or more contention builds failed (continuing to collect metrics)"
fi

SCCACHE_SERVER_PORT="$SCCACHE_PORT_A" SCCACHE_DIR="$SCCACHE_DIR_A" sccache --show-stats >"${CONTENTION_DIR}/sccache-a-stats.txt" 2>&1
SCCACHE_SERVER_PORT="$SCCACHE_PORT_B" SCCACHE_DIR="$SCCACHE_DIR_B" sccache --show-stats >"${CONTENTION_DIR}/sccache-b-stats.txt" 2>&1
print_stats_summary "sccache A stats" "${CONTENTION_DIR}/sccache-a-stats.txt"
print_stats_summary "sccache B stats" "${CONTENTION_DIR}/sccache-b-stats.txt"

SCCACHE_SERVER_PORT="$SCCACHE_PORT_A" SCCACHE_DIR="$SCCACHE_DIR_A" sccache --stop-server >/dev/null 2>&1 || true
SCCACHE_SERVER_PORT="$SCCACHE_PORT_B" SCCACHE_DIR="$SCCACHE_DIR_B" sccache --stop-server >/dev/null 2>&1 || true

echo ""
echo "Stopping both proxies (triggering shutdown flush)..."
stop_proxy_graceful "PROXY_PID_A" "A"
stop_proxy_graceful "PROXY_PID_B" "B"

BUILD_A_SECONDS="$(cat "${CONTENTION_DIR}/build-a.log.seconds" 2>/dev/null || echo "0")"
BUILD_B_SECONDS="$(cat "${CONTENTION_DIR}/build-b.log.seconds" 2>/dev/null || echo "0")"

CONFLICTS_A="$(count_pattern "$PROXY_LOG_A" 'tag conflict')"
CONFLICTS_B="$(count_pattern "$PROXY_LOG_B" 'tag conflict')"

FLUSHED_A="$(count_pattern "$PROXY_LOG_A" 'KV batch: flushed')"
FLUSHED_B="$(count_pattern "$PROXY_LOG_B" 'KV batch: flushed')"

TIMEOUT_A="$(count_pattern "$PROXY_LOG_A" 'Shutdown: flush timeout')"
TIMEOUT_B="$(count_pattern "$PROXY_LOG_B" 'Shutdown: flush timeout')"

DROPS_A="$(count_pattern "$PROXY_LOG_A" 'flush dropped permanently')"
DROPS_B="$(count_pattern "$PROXY_LOG_B" 'flush dropped permanently')"

FLUSH_SUMMARY_A="$(sed -n 's/.*KV flush summary:.*uploaded=\([0-9]*\).*already_present=\([0-9]*\).*duration_ms=\([0-9]*\).*/uploaded=\1 already_present=\2 duration_ms=\3/p' "$PROXY_LOG_A" | tail -1)"
FLUSH_SUMMARY_B="$(sed -n 's/.*KV flush summary:.*uploaded=\([0-9]*\).*already_present=\([0-9]*\).*duration_ms=\([0-9]*\).*/uploaded=\1 already_present=\2 duration_ms=\3/p' "$PROXY_LOG_B" | tail -1)"
FLUSH_SUMMARY_A="${FLUSH_SUMMARY_A:-none}"
FLUSH_SUMMARY_B="${FLUSH_SUMMARY_B:-none}"

echo ""
echo "--- Contention metrics ---"
echo "Build A: ${BUILD_A_SECONDS}s"
echo "Build B: ${BUILD_B_SECONDS}s"
echo "Wall clock: ${CONTENTION_WALL}s"
echo "Proxy A: conflicts=${CONFLICTS_A}, batches_flushed=${FLUSHED_A}, flush_timeouts=${TIMEOUT_A}, permanent_drops=${DROPS_A}"
echo "Proxy B: conflicts=${CONFLICTS_B}, batches_flushed=${FLUSHED_B}, flush_timeouts=${TIMEOUT_B}, permanent_drops=${DROPS_B}"
echo "Flush A: ${FLUSH_SUMMARY_A}"
echo "Flush B: ${FLUSH_SUMMARY_B}"

# ---------------------------------------------------------------------------
# Phase 3: Verification — third proxy loads merged index
# ---------------------------------------------------------------------------

echo ""
echo "=== Phase 3: Verification (merged index check) ==="
VERIFY_DIR="${LOG_DIR}/verify"
VERIFY_PROXY_LOG="${VERIFY_DIR}/proxy.log"
mkdir -p "$VERIFY_DIR"

start_proxy "verify" "$PROXY_PORT_VERIFY" "$VERIFY_PROXY_LOG" "PROXY_PID_VERIFY"
ensure_proxy_ready "$PROXY_PORT_VERIFY" "$VERIFY_PROXY_LOG" "PROXY_PID_VERIFY"
echo "Verification proxy running (pid=${PROXY_PID_VERIFY}) on port ${PROXY_PORT_VERIFY}"

sleep 3

VERIFY_PRELOADED="$(sed -n 's/.*KV index preloaded: \([0-9]*\) entries.*/\1/p' "$VERIFY_PROXY_LOG" | tail -1)"
VERIFY_PRELOADED="${VERIFY_PRELOADED:-0}"

stop_proxy_graceful "PROXY_PID_VERIFY" "verify"

echo "Merged index entries: ${VERIFY_PRELOADED}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

TOTAL_CONFLICTS="$((CONFLICTS_A + CONFLICTS_B))"
TOTAL_TIMEOUTS="$((TIMEOUT_A + TIMEOUT_B))"
TOTAL_DROPS="$((DROPS_A + DROPS_B))"

echo ""
echo "========================================="
echo "Dual-Proxy Contention Test Results"
echo "========================================="
echo ""
echo "Prewarm"
echo "  Cold build:           ${PREWARM_COLD_SECONDS}s"
echo "  Flush uploaded:       ${PREWARM_FLUSH_UPLOADED}"
echo ""
echo "Contention"
echo "  Build A:              ${BUILD_A_SECONDS}s"
echo "  Build B:              ${BUILD_B_SECONDS}s"
echo "  Wall clock:           ${CONTENTION_WALL}s"
echo "  Proxy A conflicts:    ${CONFLICTS_A}"
echo "  Proxy B conflicts:    ${CONFLICTS_B}"
echo "  Total conflicts:      ${TOTAL_CONFLICTS}"
echo "  Proxy A flush:        ${FLUSH_SUMMARY_A}"
echo "  Proxy B flush:        ${FLUSH_SUMMARY_B}"
echo "  Flush timeouts:       ${TOTAL_TIMEOUTS}"
echo "  Permanent drops:      ${TOTAL_DROPS}"
echo ""
echo "Verification"
echo "  Merged index entries: ${VERIFY_PRELOADED}"
echo ""
echo "Logs: ${LOG_DIR}"
echo "========================================="

PASS=1

if [[ "$TOTAL_TIMEOUTS" -gt 0 ]]; then
  echo ""
  echo "FAIL: ${TOTAL_TIMEOUTS} flush timeout(s) detected"
  PASS=0
fi

if [[ "$TOTAL_DROPS" -gt 0 ]]; then
  echo ""
  echo "FAIL: ${TOTAL_DROPS} permanent drop(s) detected"
  PASS=0
fi

if [[ "$VERIFY_PRELOADED" -eq 0 ]]; then
  echo ""
  echo "FAIL: verification proxy loaded 0 entries (expected merged index)"
  PASS=0
fi

if [[ "$PASS" -eq 1 ]]; then
  echo ""
  echo "PASS: both proxies flushed without timeouts/drops, merged index has ${VERIFY_PRELOADED} entries"
fi

exit $((1 - PASS))
