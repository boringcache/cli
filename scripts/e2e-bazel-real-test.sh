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
PROXY_PID=""

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

for dep in curl cmp stat "$BAZEL_BIN"; do
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

mkdir -p "$LOG_DIR" "$BINARY_DIR"
cp "$BINARY" "$TMP_BINARY"
chmod +x "$TMP_BINARY"

cleanup() {
  set +e
  if [[ -n "${PROXY_PID:-}" ]]; then
    kill "$PROXY_PID" >/dev/null 2>&1 || true
    wait "$PROXY_PID" >/dev/null 2>&1 || true
    PROXY_PID=""
  fi
}
trap cleanup EXIT INT TERM

http_status() {
  local path="$1"
  curl -sS -o /dev/null -w "%{http_code}" \
    --connect-timeout "$HTTP_CONNECT_TIMEOUT_SECS" \
    --max-time "$HTTP_REQUEST_TIMEOUT_SECS" \
    "${PROXY_URL}${path}"
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
  : >"$PROXY_LOG"
  BORINGCACHE_API_TOKEN="${BORINGCACHE_API_TOKEN}" \
    "$TMP_BINARY" cache-registry "$WORKSPACE" "$tag" \
      --host "$PROXY_HOST" \
      --port "$PROXY_PORT" \
      --no-platform \
      --no-git \
      --fail-on-cache-error >"$PROXY_LOG" 2>&1 &
  PROXY_PID=$!
  wait_for_proxy_ready
}

stop_proxy() {
  if [[ -n "${PROXY_PID:-}" ]]; then
    kill "$PROXY_PID" >/dev/null 2>&1 || true
    wait "$PROXY_PID" >/dev/null 2>&1 || true
    PROXY_PID=""
  fi
}

run_bazel_build() {
  local phase="$1"
  local output_root="$2"
  local marker_file="$3"
  local workspace_dir="$4"
  local log_path="${LOG_DIR}/${phase}.log"

  rm -rf "$output_root"
  mkdir -p "$output_root"
  (
    cd "$workspace_dir"
    "$BAZEL_BIN" --batch --output_user_root="$output_root" build //:emit \
      --color=no \
      --curses=no \
      --noshow_progress \
      --show_result=0 \
      --spawn_strategy=local \
      --genrule_strategy=local \
      --remote_cache="${PROXY_URL}" \
      --remote_timeout=60 \
      --remote_upload_local_results=true \
      --remote_accept_cached=true \
      --action_env="BAZEL_MARKER_FILE=${marker_file}" >"$log_path" 2>&1
  )
}

echo "Binary: ${TMP_BINARY}"
echo "Workspace: ${WORKSPACE}"
echo "Tag: ${TAG_BASE}-${RUN_ID}"
echo "Proxy: ${PROXY_HOST}:${PROXY_PORT}"
echo "Bazel binary: $(command -v "$BAZEL_BIN")"
echo "Logs: ${LOG_DIR}"

TAG="${TAG_BASE}-${RUN_ID}"
start_proxy "$TAG"

BAZEL_WS="${LOG_DIR}/bazel-workspace"
MARKER_FILE="${LOG_DIR}/bazel-action-executed.marker"
OUTPUT_ROOT_A="${LOG_DIR}/bazel-out-a"
OUTPUT_ROOT_B="${LOG_DIR}/bazel-out-b"
OUTPUT_ROOT_C="${LOG_DIR}/bazel-out-c"

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
printf 'bazel-real-e2e-%s\n' "$RUN_ID" > "${BAZEL_WS}/input.txt"
rm -f "$MARKER_FILE"

echo
echo "=== Phase 1: Cold build (expect local execution + upload) ==="
run_bazel_build "bazel-build-1" "$OUTPUT_ROOT_A" "$MARKER_FILE" "$BAZEL_WS"
if [[ ! -f "$MARKER_FILE" ]]; then
  echo "ERROR: marker file missing after first build; action did not execute"
  tail -n 200 "${LOG_DIR}/bazel-build-1.log" || true
  exit 1
fi
MARKER_MTIME_AFTER_PHASE1="$(stat -c %Y "$MARKER_FILE")"
cmp "${BAZEL_WS}/input.txt" "${BAZEL_WS}/bazel-bin/out.txt"

echo
echo "=== Phase 2: Warm build with isolated output root (expect remote hit) ==="
run_bazel_build "bazel-build-2" "$OUTPUT_ROOT_B" "$MARKER_FILE" "$BAZEL_WS"
MARKER_MTIME_AFTER_PHASE2="$(stat -c %Y "$MARKER_FILE")"
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
run_bazel_build "bazel-build-3" "$OUTPUT_ROOT_C" "$MARKER_FILE" "$BAZEL_WS"
MARKER_MTIME_AFTER_PHASE3="$(stat -c %Y "$MARKER_FILE")"
if [[ "$MARKER_MTIME_AFTER_PHASE3" != "$MARKER_MTIME_AFTER_PHASE1" ]]; then
  echo "ERROR: marker file changed after proxy restart; persisted cache miss caused re-execution"
  tail -n 200 "${LOG_DIR}/bazel-build-3.log" || true
  exit 1
fi
cmp "${BAZEL_WS}/input.txt" "${BAZEL_WS}/bazel-bin/out.txt"

echo
echo "Bazel real-client e2e passed"
echo "Logs: ${LOG_DIR}"
