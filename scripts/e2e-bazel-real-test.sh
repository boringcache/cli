#!/usr/bin/env bash
set -euo pipefail

PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-5058}"
WORKSPACE="${WORKSPACE:-${BORINGCACHE_DEFAULT_WORKSPACE:-boringcache/testing2}}"
TAG_BASE="${TAG:-bc-e2e-cli-bazel-real}"
BINARY="${BINARY:-./target/release/boringcache}"
BAZEL_BIN="${BAZEL_BIN:-bazel}"
TMP_ROOT="${TMPDIR:-/tmp}/boringcache-bazel-real-e2e"
BINARY_DIR="${TMP_ROOT}/bin"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${LOG_DIR:-${TMP_ROOT}/logs-${RUN_ID}}"
TMP_BINARY="${BINARY_DIR}/boringcache-${RUN_ID}"
PROXY_LOG="${LOG_DIR}/proxy.log"
PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"
SETTLE_SECS="${SETTLE_SECS:-5}"
PROXY_READY_TIMEOUT_SECS="${PROXY_READY_TIMEOUT_SECS:-90}"
PROXY_READY_POLL_SECS="${PROXY_READY_POLL_SECS:-1}"
HTTP_CONNECT_TIMEOUT_SECS="${HTTP_CONNECT_TIMEOUT_SECS:-5}"
HTTP_REQUEST_TIMEOUT_SECS="${HTTP_REQUEST_TIMEOUT_SECS:-30}"
PHASE3_MAX_ATTEMPTS="${PHASE3_MAX_ATTEMPTS:-4}"
PHASE3_RETRY_SLEEP_SECS="${PHASE3_RETRY_SLEEP_SECS:-3}"
PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_SECS:-30}"
BUILD_TIMEOUT_SECS="${BUILD_TIMEOUT_SECS:-0}"
BUILD_HEARTBEAT_SECS="${BUILD_HEARTBEAT_SECS:-30}"
BUILD_CLEANUP_WAIT_SECS="${BUILD_CLEANUP_WAIT_SECS:-20}"
BUILD_FAILURE_TAIL_LINES="${BUILD_FAILURE_TAIL_LINES:-120}"
BAZEL_BUILD_JOBS="${BAZEL_BUILD_JOBS:-128}"
BAZEL_REMOTE_MAX_CONNECTIONS="${BAZEL_REMOTE_MAX_CONNECTIONS:-64}"
STRESS_ACTION_COUNT="${STRESS_ACTION_COUNT:-96}"
BUDGET_REMOTE_TIMEOUTS_MAX="${BUDGET_REMOTE_TIMEOUTS_MAX:-0}"
PROXY_PID=""
INTERRUPTED="0"
declare -a ACTIVE_BUILD_PIDS=()
REMOTE_TIMEOUTS_TOTAL=0

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

if [[ -z "${BORINGCACHE_API_TOKEN:-}" ]]; then
  echo "ERROR: BORINGCACHE_API_TOKEN not set"
  exit 1
fi

for dep in curl cmp pgrep stat "$BAZEL_BIN"; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: ${dep} not found in PATH"
    exit 1
  fi
done

if [[ ! -x "${BINARY}" ]]; then
  echo "ERROR: BINARY not executable at ${BINARY}"
  exit 1
fi

require_positive "PROXY_PORT" "$PROXY_PORT"
require_positive "SETTLE_SECS" "$SETTLE_SECS"
require_positive "PROXY_READY_TIMEOUT_SECS" "$PROXY_READY_TIMEOUT_SECS"
require_positive "PROXY_READY_POLL_SECS" "$PROXY_READY_POLL_SECS"
require_positive "HTTP_CONNECT_TIMEOUT_SECS" "$HTTP_CONNECT_TIMEOUT_SECS"
require_positive "HTTP_REQUEST_TIMEOUT_SECS" "$HTTP_REQUEST_TIMEOUT_SECS"
require_positive "PHASE3_MAX_ATTEMPTS" "$PHASE3_MAX_ATTEMPTS"
require_positive "PHASE3_RETRY_SLEEP_SECS" "$PHASE3_RETRY_SLEEP_SECS"
require_positive "PROXY_SHUTDOWN_WAIT_SECS" "$PROXY_SHUTDOWN_WAIT_SECS"
require_numeric "BUILD_TIMEOUT_SECS" "$BUILD_TIMEOUT_SECS"
require_positive "BUILD_HEARTBEAT_SECS" "$BUILD_HEARTBEAT_SECS"
require_positive "BUILD_CLEANUP_WAIT_SECS" "$BUILD_CLEANUP_WAIT_SECS"
require_positive "BUILD_FAILURE_TAIL_LINES" "$BUILD_FAILURE_TAIL_LINES"
require_positive "BAZEL_BUILD_JOBS" "$BAZEL_BUILD_JOBS"
require_positive "BAZEL_REMOTE_MAX_CONNECTIONS" "$BAZEL_REMOTE_MAX_CONNECTIONS"
require_numeric "STRESS_ACTION_COUNT" "$STRESS_ACTION_COUNT"
require_numeric "BUDGET_REMOTE_TIMEOUTS_MAX" "$BUDGET_REMOTE_TIMEOUTS_MAX"

if (( STRESS_ACTION_COUNT < 0 )); then
  echo "ERROR: STRESS_ACTION_COUNT must be >= 0"
  exit 1
fi

if (( BUDGET_REMOTE_TIMEOUTS_MAX < 0 )); then
  echo "ERROR: BUDGET_REMOTE_TIMEOUTS_MAX must be >= 0"
  exit 1
fi

mkdir -p "$LOG_DIR" "$BINARY_DIR"
cp "$BINARY" "$TMP_BINARY"
chmod +x "$TMP_BINARY"
: >"$PROXY_LOG"

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

stop_proxy() {
  if [[ -n "${PROXY_PID:-}" ]]; then
    stop_pid_tree "$PROXY_PID" "proxy" "$PROXY_SHUTDOWN_WAIT_SECS"
    PROXY_PID=""
  fi
}

cleanup() {
  set +e
  stop_background_jobs
  local pid
  for pid in "${ACTIVE_BUILD_PIDS[@]}"; do
    stop_pid_tree "$pid" "build" "$BUILD_CLEANUP_WAIT_SECS"
  done
  ACTIVE_BUILD_PIDS=()
  stop_proxy
  rm -f "$TMP_BINARY" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap handle_interrupt INT TERM

http_status() {
  local path="$1"
  local status
  status="$(
    curl -sS -o /dev/null -w "%{http_code}" \
      --connect-timeout "$HTTP_CONNECT_TIMEOUT_SECS" \
      --max-time "$HTTP_REQUEST_TIMEOUT_SECS" \
      "${PROXY_URL}${path}" 2>/dev/null || true
  )"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf '%s' "$status"
}

file_mtime_epoch() {
  local file_path="$1"
  if stat -c %Y "$file_path" >/dev/null 2>&1; then
    stat -c %Y "$file_path"
    return 0
  fi
  stat -f %m "$file_path"
}

wait_for_proxy_ready() {
  local waited=0
  while (( waited < PROXY_READY_TIMEOUT_SECS )); do
    if [[ "$(http_status "/v2/")" == "200" ]]; then
      return 0
    fi
    if [[ -n "${PROXY_PID:-}" ]] && ! kill -0 "$PROXY_PID" >/dev/null 2>&1; then
      echo "ERROR: proxy exited before readiness"
      tail -n 200 "$PROXY_LOG" || true
      exit 1
    fi
    sleep "$PROXY_READY_POLL_SECS"
    waited=$((waited + PROXY_READY_POLL_SECS))
  done

  echo "ERROR: timed out waiting for proxy readiness (${PROXY_READY_TIMEOUT_SECS}s)"
  tail -n 200 "$PROXY_LOG" || true
  exit 1
}

start_proxy() {
  local tag="$1"
  stop_proxy
  {
    echo
    echo "=== Proxy start $(date -u +"%Y-%m-%dT%H:%M:%SZ") tag=${tag} ==="
  } >>"$PROXY_LOG"
  BORINGCACHE_API_TOKEN="${BORINGCACHE_API_TOKEN}" \
    "$TMP_BINARY" cache-registry "$WORKSPACE" "$tag" \
      --host "$PROXY_HOST" \
      --port "$PROXY_PORT" \
      --no-platform \
      --no-git \
      --fail-on-cache-error >>"$PROXY_LOG" 2>&1 &
  PROXY_PID=$!
  wait_for_proxy_ready
}

run_bazel_build() {
  local phase="$1"
  local output_root="$2"
  local marker_file="$3"
  local stress_marker_dir="$4"
  local workspace_dir="$5"
  local target="$6"
  local log_path="${LOG_DIR}/${phase}.log"
  local start_ts end_ts elapsed
  local build_pid now next_heartbeat status latest_line

  rm -rf "$output_root"
  mkdir -p "$output_root"
  echo "${phase} starting..."
  start_ts="$(date +%s)"
  (
    cd "$workspace_dir"
    "$BAZEL_BIN" --batch --output_user_root="$output_root" build "$target" \
      --color=no \
      --curses=no \
      --noshow_progress \
      --show_result=0 \
      --spawn_strategy=local \
      --genrule_strategy=local \
      --jobs="${BAZEL_BUILD_JOBS}" \
      --remote_max_connections="${BAZEL_REMOTE_MAX_CONNECTIONS}" \
      --remote_cache="${PROXY_URL}" \
      --remote_timeout=60 \
      --remote_upload_local_results=true \
      --remote_accept_cached=true \
      --action_env="BAZEL_MARKER_FILE=${marker_file}" \
      --action_env="BAZEL_STRESS_MARKER_DIR=${stress_marker_dir}" >"$log_path" 2>&1
  ) &
  build_pid=$!
  ACTIVE_BUILD_PIDS+=("$build_pid")
  next_heartbeat=$((start_ts + BUILD_HEARTBEAT_SECS))
  while kill -0 "$build_pid" >/dev/null 2>&1; do
    now="$(date +%s)"
    if [[ "$BUILD_TIMEOUT_SECS" -gt 0 ]] && (( now - start_ts >= BUILD_TIMEOUT_SECS )); then
      echo "ERROR: ${phase} exceeded BUILD_TIMEOUT_SECS=${BUILD_TIMEOUT_SECS}s"
      stop_pid_tree "$build_pid" "${phase} build" "$BUILD_CLEANUP_WAIT_SECS"
      remove_active_build_pid "$build_pid"
      tail -n "$BUILD_FAILURE_TAIL_LINES" "$log_path" || true
      return 124
    fi
    if (( now >= next_heartbeat )); then
      elapsed="$((now - start_ts))"
      latest_line="$(awk 'NF { line=$0 } END { print line }' "$log_path" 2>/dev/null || true)"
      if [[ -n "$latest_line" ]]; then
        echo "  [heartbeat] ${phase} running ${elapsed}s | ${latest_line}"
      else
        echo "  [heartbeat] ${phase} running ${elapsed}s"
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
  echo "$elapsed" >"${log_path}.seconds"
  local timeout_count
  timeout_count="$(grep -c "connection timed out: /127.0.0.1:${PROXY_PORT}" "$log_path" 2>/dev/null || true)"
  timeout_count="${timeout_count:-0}"
  if [[ -n "$timeout_count" && "$timeout_count" =~ ^[0-9]+$ ]] && (( timeout_count > 0 )); then
    echo "WARNING: ${phase} observed ${timeout_count} remote cache connect timeout(s)"
    REMOTE_TIMEOUTS_TOTAL=$((REMOTE_TIMEOUTS_TOTAL + timeout_count))
  fi
  if [[ "$status" -ne 0 ]]; then
    echo "ERROR: ${phase} failed with exit code ${status}. Recent log output:"
    tail -n "$BUILD_FAILURE_TAIL_LINES" "$log_path" || true
    return "$status"
  fi
  echo "${phase} completed in ${elapsed}s"
}

echo "Binary: ${TMP_BINARY}"
echo "Workspace: ${WORKSPACE}"
echo "Tag: ${TAG_BASE}-${RUN_ID}"
echo "Proxy: ${PROXY_HOST}:${PROXY_PORT}"
echo "Bazel binary: $(command -v "$BAZEL_BIN")"
echo "Build timeout: ${BUILD_TIMEOUT_SECS}s (0 disables)"
echo "Build heartbeat: ${BUILD_HEARTBEAT_SECS}s"
echo "Proxy shutdown wait: ${PROXY_SHUTDOWN_WAIT_SECS}s"
echo "Bazel jobs: ${BAZEL_BUILD_JOBS}"
echo "Bazel remote_max_connections: ${BAZEL_REMOTE_MAX_CONNECTIONS}"
echo "Stress actions: ${STRESS_ACTION_COUNT}"
echo "Budget remote timeouts max: ${BUDGET_REMOTE_TIMEOUTS_MAX}"
echo "Logs: ${LOG_DIR}"

TAG="${TAG_BASE}-${RUN_ID}"
start_proxy "$TAG"

BAZEL_WS="${LOG_DIR}/bazel-workspace"
MARKER_FILE="${LOG_DIR}/bazel-action-executed.marker"
OUTPUT_ROOT_A="${LOG_DIR}/bazel-out-a"
OUTPUT_ROOT_B="${LOG_DIR}/bazel-out-b"
OUTPUT_ROOT_C="${LOG_DIR}/bazel-out-c"
OUTPUT_ROOT_D="${LOG_DIR}/bazel-out-d"
OUTPUT_ROOT_E="${LOG_DIR}/bazel-out-e"
STRESS_MARKER_DIR="${LOG_DIR}/bazel-stress-markers"

mkdir -p "$BAZEL_WS"
cat > "${BAZEL_WS}/MODULE.bazel" <<'EOF_MODULE'
module(name = "boringcache_bazel_remote_cache_e2e")
EOF_MODULE
cat > "${BAZEL_WS}/BUILD.bazel" <<'EOF_BUILD'
genrule(
    name = "emit",
    srcs = ["input.txt"],
    outs = ["out.txt"],
    cmd = """
set -euo pipefail
if [[ -f "$$BAZEL_MARKER_FILE" ]]; then
  echo "expected remote cache hit; action re-executed" >&2
  exit 42
fi
cp $(location input.txt) $@
touch "$$BAZEL_MARKER_FILE"
""",
)
EOF_BUILD

if (( STRESS_ACTION_COUNT > 0 )); then
  mkdir -p "${BAZEL_WS}/stress"
  for i in $(seq 1 "$STRESS_ACTION_COUNT"); do
    idx="$(printf "%03d" "$i")"
    printf 'stress-input-%s-%s\n' "$RUN_ID" "$idx" > "${BAZEL_WS}/stress/${idx}.txt"
    cat >> "${BAZEL_WS}/BUILD.bazel" <<EOF_STRESS_RULE

genrule(
    name = "emit_stress_${idx}",
    srcs = ["stress/${idx}.txt"],
    outs = ["stress_${idx}.out"],
    cmd = """
set -euo pipefail
marker="\$\$BAZEL_STRESS_MARKER_DIR/emit_stress_${idx}.marker"
if [[ -f "\$\$marker" ]]; then
  echo "expected stress remote cache hit; action re-executed" >&2
  exit 43
fi
mkdir -p "\$\$BAZEL_STRESS_MARKER_DIR"
cp \$(location stress/${idx}.txt) \$@
touch "\$\$marker"
""",
)
EOF_STRESS_RULE
  done

  {
    echo
    echo "genrule("
    echo "    name = \"stress_bundle\","
    echo "    srcs = ["
    for i in $(seq 1 "$STRESS_ACTION_COUNT"); do
      idx="$(printf "%03d" "$i")"
      echo "        \":emit_stress_${idx}\","
    done
    echo "    ],"
    echo "    outs = [\"stress_bundle.out\"],"
    echo "    cmd = \"cat \$(SRCS) > \$@\","
    echo ")"
  } >> "${BAZEL_WS}/BUILD.bazel"
fi

printf 'bazel-real-e2e-%s\n' "$RUN_ID" > "${BAZEL_WS}/input.txt"
rm -f "$MARKER_FILE"
rm -rf "$STRESS_MARKER_DIR"

echo
echo "=== Phase 1: Cold build (expect local execution + upload) ==="
run_bazel_build "bazel-build-1" "$OUTPUT_ROOT_A" "$MARKER_FILE" "$STRESS_MARKER_DIR" "$BAZEL_WS" "//:emit"
if [[ ! -f "$MARKER_FILE" ]]; then
  echo "ERROR: marker file missing after first build; action did not execute"
  tail -n 200 "${LOG_DIR}/bazel-build-1.log" || true
  exit 1
fi
MARKER_MTIME_AFTER_PHASE1="$(file_mtime_epoch "$MARKER_FILE")"
cmp "${BAZEL_WS}/input.txt" "${BAZEL_WS}/bazel-bin/out.txt"

echo
echo "=== Phase 2: Warm build with isolated output root (expect remote hit) ==="
run_bazel_build "bazel-build-2" "$OUTPUT_ROOT_B" "$MARKER_FILE" "$STRESS_MARKER_DIR" "$BAZEL_WS" "//:emit"
MARKER_MTIME_AFTER_PHASE2="$(file_mtime_epoch "$MARKER_FILE")"
if [[ "$MARKER_MTIME_AFTER_PHASE2" != "$MARKER_MTIME_AFTER_PHASE1" ]]; then
  echo "ERROR: marker file changed on second build; action re-executed instead of remote hit"
  tail -n 200 "${LOG_DIR}/bazel-build-2.log" || true
  exit 1
fi
cmp "${BAZEL_WS}/input.txt" "${BAZEL_WS}/bazel-bin/out.txt"

echo
echo "Waiting for writes to settle (${SETTLE_SECS}s)..."
sleep "$SETTLE_SECS"

echo
echo "=== Phase 3: Restart proxy and verify persisted remote hit ==="
stop_proxy
start_proxy "$TAG"
PHASE3_OK=0
PHASE3_LAST_LOG=""
for ((attempt=1; attempt<=PHASE3_MAX_ATTEMPTS; attempt++)); do
  phase_name="bazel-build-3-attempt-${attempt}"
  phase_output_root="${OUTPUT_ROOT_C}-${attempt}"
  phase_log="${LOG_DIR}/${phase_name}.log"
  PHASE3_LAST_LOG="$phase_log"

  if run_bazel_build "$phase_name" "$phase_output_root" "$MARKER_FILE" "$STRESS_MARKER_DIR" "$BAZEL_WS" "//:emit"; then
    MARKER_MTIME_AFTER_PHASE3="$(file_mtime_epoch "$MARKER_FILE")"
    if [[ "$MARKER_MTIME_AFTER_PHASE3" != "$MARKER_MTIME_AFTER_PHASE1" ]]; then
      echo "ERROR: marker file changed after proxy restart; persisted cache miss caused re-execution"
      tail -n 200 "$phase_log" || true
      exit 1
    fi
    cmp "${BAZEL_WS}/input.txt" "${BAZEL_WS}/bazel-bin/out.txt"
    PHASE3_OK=1
    break
  fi

  if grep -Fq "expected remote cache hit; action re-executed" "$phase_log"; then
    if (( attempt < PHASE3_MAX_ATTEMPTS )); then
      echo "Phase 3 attempt ${attempt}/${PHASE3_MAX_ATTEMPTS} missed after restart; retrying in ${PHASE3_RETRY_SLEEP_SECS}s..."
      sleep "$PHASE3_RETRY_SLEEP_SECS"
      continue
    fi
    echo "ERROR: persisted cache was still unavailable after ${PHASE3_MAX_ATTEMPTS} attempts"
    tail -n 200 "$phase_log" || true
    exit 1
  fi

  echo "ERROR: bazel phase 3 failed for an unexpected reason"
  tail -n 200 "$phase_log" || true
  exit 1
done

if [[ "$PHASE3_OK" != "1" ]]; then
  echo "ERROR: phase 3 did not succeed"
  if [[ -n "$PHASE3_LAST_LOG" ]]; then
    tail -n 200 "$PHASE3_LAST_LOG" || true
  fi
  exit 1
fi

if (( STRESS_ACTION_COUNT > 0 )); then
  echo
  echo "=== Phase 4: High-concurrency stress warm (expect remote hits, no connect timeouts) ==="
  rm -rf "$STRESS_MARKER_DIR"
  mkdir -p "$STRESS_MARKER_DIR"

  run_bazel_build "bazel-stress-cold" "$OUTPUT_ROOT_D" "$MARKER_FILE" "$STRESS_MARKER_DIR" "$BAZEL_WS" "//:stress_bundle"
  stress_marker_count="$(find "$STRESS_MARKER_DIR" -type f | wc -l | tr -d ' ')"
  if [[ "$stress_marker_count" != "$STRESS_ACTION_COUNT" ]]; then
    echo "ERROR: expected ${STRESS_ACTION_COUNT} stress markers after cold run, found ${stress_marker_count}"
    tail -n 200 "${LOG_DIR}/bazel-stress-cold.log" || true
    exit 1
  fi
  cat "${BAZEL_WS}"/stress/*.txt > "${LOG_DIR}/stress-expected.txt"
  cmp "${LOG_DIR}/stress-expected.txt" "${BAZEL_WS}/bazel-bin/stress_bundle.out"

  echo "Waiting for writes to settle (${SETTLE_SECS}s)..."
  sleep "$SETTLE_SECS"
  stop_proxy
  start_proxy "$TAG"

  run_bazel_build "bazel-stress-warm" "$OUTPUT_ROOT_E" "$MARKER_FILE" "$STRESS_MARKER_DIR" "$BAZEL_WS" "//:stress_bundle"
  cmp "${LOG_DIR}/stress-expected.txt" "${BAZEL_WS}/bazel-bin/stress_bundle.out"
fi

if (( REMOTE_TIMEOUTS_TOTAL > BUDGET_REMOTE_TIMEOUTS_MAX )); then
  echo "ERROR: observed ${REMOTE_TIMEOUTS_TOTAL} remote cache connect timeout(s), budget max is ${BUDGET_REMOTE_TIMEOUTS_MAX}"
  exit 1
fi

echo
echo "Bazel real-client e2e passed"
echo "Remote cache connect timeouts observed: ${REMOTE_TIMEOUTS_TOTAL}"
echo "Logs: ${LOG_DIR}"
