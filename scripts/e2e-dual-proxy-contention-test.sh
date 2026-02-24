#!/usr/bin/env bash
set -euo pipefail

PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT_A="${PROXY_PORT_A:-5050}"
PROXY_PORT_B="${PROXY_PORT_B:-5052}"
PROXY_PORT_VERIFY="${PROXY_PORT_VERIFY:-5054}"
SCCACHE_PORT_A="${SCCACHE_PORT_A:-4226}"
SCCACHE_PORT_B="${SCCACHE_PORT_B:-4227}"
TAG="${TAG:-e2e-dual-proxy-contention}"
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

if [[ -z "${BORINGCACHE_API_TOKEN:-}" ]]; then
  echo "ERROR: BORINGCACHE_API_TOKEN not set"
  exit 1
fi

for dep in sccache curl lsof; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: ${dep} not found in PATH"
    exit 1
  fi
done

PROXY_PID_A=""
PROXY_PID_B=""
PROXY_PID_VERIFY=""

stop_all() {
  for pid_var in PROXY_PID_A PROXY_PID_B PROXY_PID_VERIFY; do
    local pid="${!pid_var:-}"
    if [[ -n "$pid" ]]; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
      eval "${pid_var}=''"
    fi
  done
}

cleanup() {
  stop_all
  SCCACHE_SERVER_PORT="$SCCACHE_PORT_A" sccache --stop-server >/dev/null 2>&1 || true
  SCCACHE_SERVER_PORT="$SCCACHE_PORT_B" sccache --stop-server >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ ! -x "$BINARY" ]]; then
  echo "Building boringcache..."
  cargo build --release --locked 2>&1 | tail -n 5
fi

mkdir -p "$BINARY_DIR" "$TARGET_ROOT" "$LOG_DIR"
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
      awk '$1 == "Cache" && $2 == "hits" && $3 == "rate" { print $(NF-1); exit }' "$file"
      ;;
    "Cache hits rate (Rust)")
      awk '$1 == "Cache" && $2 == "hits" && $3 == "rate" && $4 == "(Rust)" { print $(NF-1); exit }' "$file"
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
  if command -v rg >/dev/null 2>&1; then
    rg -c "$pattern" "$file" 2>/dev/null || echo "0"
  else
    grep -c "$pattern" "$file" 2>/dev/null || echo "0"
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

start_proxy() {
  local label="$1"
  local port="$2"
  local log_file="$3"
  local pid_var="$4"
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
  local url="http://${PROXY_HOST}:${port}/v2/"
  for _ in $(seq 1 20); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: proxy on port ${port} failed to start"
  tail -n 120 "$log_file" || true
  exit 1
}

stop_proxy_graceful() {
  local pid_var="$1"
  local label="$2"
  local pid="${!pid_var:-}"
  if [[ -z "$pid" ]]; then
    return 0
  fi
  echo "Stopping proxy ${label} (pid=${pid}) with SIGTERM..."
  kill -TERM "$pid" 2>/dev/null || true
  local waited=0
  while kill -0 "$pid" 2>/dev/null && [[ "$waited" -lt "$SHUTDOWN_WAIT" ]]; do
    sleep 1
    waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    echo "WARNING: proxy ${label} did not exit within ${SHUTDOWN_WAIT}s, sending SIGKILL"
    kill -9 "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
  eval "${pid_var}=''"
  echo "Proxy ${label} stopped (waited ${waited}s)"
}

reset_sccache_for() {
  local port="$1"
  local sccache_dir="$2"
  local proxy_port="$3"
  local proxy_url="http://${PROXY_HOST}:${proxy_port}/"
  SCCACHE_SERVER_PORT="$port" sccache --stop-server >/dev/null 2>&1 || true
  sleep 1
  SCCACHE_SERVER_PORT="$port" \
    SCCACHE_DIR="$sccache_dir" \
    SCCACHE_WEBDAV_ENDPOINT="$proxy_url" \
    sccache --start-server >/dev/null 2>&1
  SCCACHE_SERVER_PORT="$port" sccache --zero-stats >/dev/null 2>&1
}

run_build_for() {
  local label="$1"
  local target_dir="$2"
  local log_file="$3"
  local sccache_port="$4"
  local proxy_port="$5"
  local proxy_url="http://${PROXY_HOST}:${proxy_port}/"
  rm -rf "$target_dir"
  mkdir -p "$target_dir"
  local start_ts end_ts elapsed
  start_ts="$(date +%s)"
  SCCACHE_SERVER_PORT="$sccache_port" \
    SCCACHE_WEBDAV_ENDPOINT="$proxy_url" \
    RUSTC_WRAPPER=sccache \
    CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR="$target_dir" \
    bash -lc "$CARGO_CMD" >"$log_file" 2>&1
  end_ts="$(date +%s)"
  elapsed="$((end_ts - start_ts))"
  echo "$elapsed" >"${log_file}.seconds"
  echo "${label} completed in ${elapsed}s"
}

# ---------------------------------------------------------------------------
# Phase 1: Prewarm — single proxy cold build to populate baseline
# ---------------------------------------------------------------------------

echo ""
echo "=== Phase 1: Prewarm (populate baseline tag) ==="
PREWARM_DIR="${LOG_DIR}/prewarm"
PREWARM_PROXY_LOG="${PREWARM_DIR}/proxy.log"
PREWARM_SCCACHE_DIR="${TMP_ROOT}/sccache-prewarm"
mkdir -p "$PREWARM_DIR" "$PREWARM_SCCACHE_DIR"

start_proxy "prewarm" "$PROXY_PORT_A" "$PREWARM_PROXY_LOG" "PROXY_PID_A"
ensure_proxy_ready "$PROXY_PORT_A" "$PREWARM_PROXY_LOG"
echo "Prewarm proxy running (pid=${PROXY_PID_A})"

reset_sccache_for "$SCCACHE_PORT_A" "$PREWARM_SCCACHE_DIR" "$PROXY_PORT_A"
run_build_for "prewarm-cold" "${TARGET_ROOT}/prewarm" "${PREWARM_DIR}/cold.log" "$SCCACHE_PORT_A" "$PROXY_PORT_A"
SCCACHE_SERVER_PORT="$SCCACHE_PORT_A" sccache --show-stats >"${PREWARM_DIR}/cold-sccache-stats.txt" 2>&1
print_stats_summary "Prewarm cold stats" "${PREWARM_DIR}/cold-sccache-stats.txt"

SCCACHE_SERVER_PORT="$SCCACHE_PORT_A" sccache --stop-server >/dev/null 2>&1 || true
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
SCCACHE_DIR_A="${TMP_ROOT}/sccache-a"
SCCACHE_DIR_B="${TMP_ROOT}/sccache-b"
mkdir -p "$CONTENTION_DIR" "$SCCACHE_DIR_A" "$SCCACHE_DIR_B"

start_proxy "A" "$PROXY_PORT_A" "$PROXY_LOG_A" "PROXY_PID_A"
start_proxy "B" "$PROXY_PORT_B" "$PROXY_LOG_B" "PROXY_PID_B"
ensure_proxy_ready "$PROXY_PORT_A" "$PROXY_LOG_A"
ensure_proxy_ready "$PROXY_PORT_B" "$PROXY_LOG_B"
echo "Proxy A running (pid=${PROXY_PID_A}) on port ${PROXY_PORT_A}"
echo "Proxy B running (pid=${PROXY_PID_B}) on port ${PROXY_PORT_B}"

reset_sccache_for "$SCCACHE_PORT_A" "$SCCACHE_DIR_A" "$PROXY_PORT_A"
reset_sccache_for "$SCCACHE_PORT_B" "$SCCACHE_DIR_B" "$PROXY_PORT_B"

echo "Starting parallel builds..."
CONTENTION_START="$(date +%s)"

run_build_for "contention-A" "${TARGET_ROOT}/contention-a" "${CONTENTION_DIR}/build-a.log" "$SCCACHE_PORT_A" "$PROXY_PORT_A" &
BUILD_PID_A=$!

run_build_for "contention-B" "${TARGET_ROOT}/contention-b" "${CONTENTION_DIR}/build-b.log" "$SCCACHE_PORT_B" "$PROXY_PORT_B" &
BUILD_PID_B=$!

BUILD_FAILED=0
wait "$BUILD_PID_A" || BUILD_FAILED=1
wait "$BUILD_PID_B" || BUILD_FAILED=1

CONTENTION_END="$(date +%s)"
CONTENTION_WALL="$((CONTENTION_END - CONTENTION_START))"

if [[ "$BUILD_FAILED" -ne 0 ]]; then
  echo "WARNING: one or more contention builds failed (continuing to collect metrics)"
fi

SCCACHE_SERVER_PORT="$SCCACHE_PORT_A" sccache --show-stats >"${CONTENTION_DIR}/sccache-a-stats.txt" 2>&1
SCCACHE_SERVER_PORT="$SCCACHE_PORT_B" sccache --show-stats >"${CONTENTION_DIR}/sccache-b-stats.txt" 2>&1
print_stats_summary "sccache A stats" "${CONTENTION_DIR}/sccache-a-stats.txt"
print_stats_summary "sccache B stats" "${CONTENTION_DIR}/sccache-b-stats.txt"

SCCACHE_SERVER_PORT="$SCCACHE_PORT_A" sccache --stop-server >/dev/null 2>&1 || true
SCCACHE_SERVER_PORT="$SCCACHE_PORT_B" sccache --stop-server >/dev/null 2>&1 || true

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
ensure_proxy_ready "$PROXY_PORT_VERIFY" "$VERIFY_PROXY_LOG"
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
