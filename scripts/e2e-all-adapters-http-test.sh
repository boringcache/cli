#!/usr/bin/env bash
set -euo pipefail

PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-5050}"
WORKSPACE="${WORKSPACE:-${BORINGCACHE_DEFAULT_WORKSPACE:-boringcache/testing2}}"
TAG_BASE="${TAG:-bc-e2e-cli-all-adapters}"
BINARY="${BINARY:-./target/release/boringcache}"
TMP_ROOT="${TMPDIR:-/tmp}/boringcache-all-adapters-e2e"
BINARY_DIR="${TMP_ROOT}/bin"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${LOG_DIR:-${TMP_ROOT}/logs-${RUN_ID}}"
TMP_BINARY="${BINARY_DIR}/boringcache-${RUN_ID}"
PROXY_LOG="${LOG_DIR}/proxy.log"
PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"
SETTLE_SECS="${SETTLE_SECS:-5}"
PROXY_READY_TIMEOUT_SECS="${PROXY_READY_TIMEOUT_SECS:-90}"
PROXY_READY_POLL_SECS="${PROXY_READY_POLL_SECS:-1}"
PROXY_READY_WARN_SECS="${PROXY_READY_WARN_SECS:-15}"
PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_SECS:-20}"
PORT_RECLAIM_WAIT_SECS="${PORT_RECLAIM_WAIT_SECS:-15}"
HTTP_CONNECT_TIMEOUT_SECS="${HTTP_CONNECT_TIMEOUT_SECS:-5}"
HTTP_REQUEST_TIMEOUT_SECS="${HTTP_REQUEST_TIMEOUT_SECS:-30}"
AUTH_BEARER="${ADAPTER_AUTH_BEARER:-adapter-e2e-token}"

PROXY_PID=""
INTERRUPTED="0"
PORT_TOOL=""

BAZEL_AC_DIGEST="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
BAZEL_CAS_DIGEST="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
GRADLE_KEY="gradle-key-e2e"
MAVEN_PATH="/v1.1/com.example/app/abcdef1234567890/buildinfo.xml"
NX_HASH="nxhash123"
NX_MISS="nxmissing456"
TURBO_HASH="deadbeefcafe1234"
TURBO_MISS="facefeedc0ffee12"
SCCACHE_KEY="abc123deadbeef"
GO_ACTION="1111111111111111111111111111111111111111111111111111111111111111"

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

require_positive "PROXY_PORT" "$PROXY_PORT"
require_positive "SETTLE_SECS" "$SETTLE_SECS"
require_positive "PROXY_READY_TIMEOUT_SECS" "$PROXY_READY_TIMEOUT_SECS"
require_positive "PROXY_READY_POLL_SECS" "$PROXY_READY_POLL_SECS"
require_positive "PROXY_READY_WARN_SECS" "$PROXY_READY_WARN_SECS"
require_positive "PROXY_SHUTDOWN_WAIT_SECS" "$PROXY_SHUTDOWN_WAIT_SECS"
require_positive "PORT_RECLAIM_WAIT_SECS" "$PORT_RECLAIM_WAIT_SECS"
require_positive "HTTP_CONNECT_TIMEOUT_SECS" "$HTTP_CONNECT_TIMEOUT_SECS"
require_positive "HTTP_REQUEST_TIMEOUT_SECS" "$HTTP_REQUEST_TIMEOUT_SECS"

for dep in curl pgrep ps cmp; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: ${dep} not found in PATH"
    exit 1
  fi
done

if command -v lsof >/dev/null 2>&1; then
  PORT_TOOL="lsof"
elif command -v ss >/dev/null 2>&1; then
  PORT_TOOL="ss"
else
  echo "ERROR: either lsof or ss must be available to inspect listening ports"
  exit 1
fi

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
      echo "WARNING: reclaiming stale proxy on port ${PROXY_PORT} (pid=${pid})" | tee -a "$PROXY_LOG"
      stop_pid_tree "$pid" "stale proxy" "$PORT_RECLAIM_WAIT_SECS"
    fi
  done
  listener_pids="$(port_listener_pids "$PROXY_PORT")"
  if [[ -n "$listener_pids" ]]; then
    echo "ERROR: proxy port ${PROXY_PORT} is already in use" | tee -a "$PROXY_LOG"
    port_listener_details "$PROXY_PORT" | tee -a "$PROXY_LOG"
    exit 1
  fi
}

stop_proxy() {
  if [[ -n "${PROXY_PID:-}" ]]; then
    stop_pid_tree "$PROXY_PID" "proxy" "$PROXY_SHUTDOWN_WAIT_SECS"
    PROXY_PID=""
  fi
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
  stop_proxy
  rm -f "$TMP_BINARY" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap handle_interrupt INT TERM

if [[ ! -x "$BINARY" ]]; then
  echo "Building boringcache..."
  cargo build --release --locked 2>&1 | tail -n 5
fi

mkdir -p "$BINARY_DIR" "$LOG_DIR"
cp "$BINARY" "$TMP_BINARY"
chmod +x "$TMP_BINARY"

echo "Binary: $TMP_BINARY"
echo "Workspace: $WORKSPACE"
echo "Tag: ${TAG_BASE}-${RUN_ID}"
echo "Proxy: ${PROXY_HOST}:${PROXY_PORT}"
echo "HTTP connect timeout: ${HTTP_CONNECT_TIMEOUT_SECS}s"
echo "HTTP request timeout: ${HTTP_REQUEST_TIMEOUT_SECS}s"
echo "Logs: $LOG_DIR"

start_proxy() {
  local tag="$1"
  stop_proxy
  reclaim_stale_proxy_port
  {
    echo ""
    echo "=== Proxy start $(date -u +"%Y-%m-%dT%H:%M:%SZ") tag=${tag} ==="
  } >>"$PROXY_LOG"
  BORINGCACHE_API_TOKEN="$BORINGCACHE_API_TOKEN" \
    RUST_LOG="${RUST_LOG:-warn}" \
    "$TMP_BINARY" cache-registry "$WORKSPACE" "$tag" \
    --host "$PROXY_HOST" \
    --port "$PROXY_PORT" \
    --no-platform \
    --no-git >>"$PROXY_LOG" 2>&1 &
  PROXY_PID=$!
  sleep 2
}

ensure_proxy_ready() {
  local attempts start_ts next_warn now waited latest_line
  attempts="$((PROXY_READY_TIMEOUT_SECS / PROXY_READY_POLL_SECS))"
  if (( attempts < 1 )); then
    attempts=1
  fi
  start_ts="$(date +%s)"
  next_warn=$((start_ts + PROXY_READY_WARN_SECS))
  for _ in $(seq 1 "$attempts"); do
    if curl -fsS --max-time 2 "${PROXY_URL}/v2/" >/dev/null; then
      return 0
    fi
    now="$(date +%s)"
    if (( now >= next_warn )); then
      waited="$((now - start_ts))"
      latest_line="$(awk 'NF { line=$0 } END { print line }' "$PROXY_LOG" 2>/dev/null || true)"
      if [[ -n "$latest_line" ]]; then
        echo "WARNING: proxy readiness still waiting after ${waited}s | ${latest_line}" | tee -a "$PROXY_LOG"
      else
        echo "WARNING: proxy readiness still waiting after ${waited}s" | tee -a "$PROXY_LOG"
      fi
      next_warn=$((now + PROXY_READY_WARN_SECS))
    fi
    if [[ -n "${PROXY_PID:-}" ]] && ! kill -0 "$PROXY_PID" >/dev/null 2>&1; then
      echo "ERROR: proxy exited before readiness check completed"
      tail -n 120 "$PROXY_LOG" || true
      exit 1
    fi
    sleep "$PROXY_READY_POLL_SECS"
  done
  echo "ERROR: proxy failed to become ready within ${PROXY_READY_TIMEOUT_SECS}s"
  tail -n 120 "$PROXY_LOG" || true
  exit 1
}

http_request() {
  local method="$1"
  local path="$2"
  local expected_status="$3"
  local body_file="$4"
  local output_file="$5"
  shift 5
  local status
  local args=(
    -sS
    --connect-timeout "$HTTP_CONNECT_TIMEOUT_SECS"
    --max-time "$HTTP_REQUEST_TIMEOUT_SECS"
    -w "%{http_code}"
    "${PROXY_URL}${path}"
  )
  if [[ "$method" == "HEAD" ]]; then
    args+=(--head -o /dev/null -D "$output_file")
  else
    args+=(-X "$method" -o "$output_file")
  fi
  if [[ -n "$body_file" ]]; then
    args+=(--data-binary "@$body_file")
  fi
  local header
  for header in "$@"; do
    args+=(-H "$header")
  done
  status="$(curl "${args[@]}")" || {
    echo "ERROR: curl request failed for ${method} ${path}"
    tail -n 80 "$PROXY_LOG" || true
    exit 1
  }
  if [[ "$status" != "$expected_status" ]]; then
    echo "ERROR: ${method} ${path} returned ${status}, expected ${expected_status}"
    echo "Response body:"
    cat "$output_file" || true
    echo "Proxy log tail:"
    tail -n 120 "$PROXY_LOG" || true
    exit 1
  fi
}

assert_file_equals() {
  local expected="$1"
  local actual="$2"
  local label="$3"
  if ! cmp -s "$expected" "$actual"; then
    echo "ERROR: payload mismatch for ${label}"
    echo "Expected bytes: $(wc -c < "$expected" 2>/dev/null || echo 0)"
    echo "Actual bytes:   $(wc -c < "$actual" 2>/dev/null || echo 0)"
    exit 1
  fi
}

assert_contains() {
  local pattern="$1"
  local file="$2"
  local label="$3"
  if ! grep -q "$pattern" "$file"; then
    echo "ERROR: expected pattern '${pattern}' missing in ${label}"
    cat "$file" || true
    exit 1
  fi
}

assert_not_contains() {
  local pattern="$1"
  local file="$2"
  local label="$3"
  if grep -q "$pattern" "$file"; then
    echo "ERROR: unexpected pattern '${pattern}' present in ${label}"
    cat "$file" || true
    exit 1
  fi
}

run_round_trip_phase() {
  local phase="$1"
  local phase_dir="${LOG_DIR}/${phase}"
  mkdir -p "$phase_dir"

  local bazel_ac_payload="${phase_dir}/bazel-ac.payload"
  local bazel_cas_payload="${phase_dir}/bazel-cas.payload"
  local gradle_payload="${phase_dir}/gradle.payload"
  local maven_payload="${phase_dir}/maven.payload"
  local nx_payload="${phase_dir}/nx.payload"
  local nx_terminal_payload="${phase_dir}/nx-terminal.payload"
  local turbo_payload="${phase_dir}/turbo.payload"
  local sccache_payload="${phase_dir}/sccache.payload"
  local go_payload="${phase_dir}/go.payload"

  printf "bazel-ac-%s\n" "$phase" >"$bazel_ac_payload"
  printf "bazel-cas-%s\n" "$phase" >"$bazel_cas_payload"
  printf "gradle-%s\n" "$phase" >"$gradle_payload"
  printf "maven-%s\n" "$phase" >"$maven_payload"
  printf "nx-%s\n" "$phase" >"$nx_payload"
  printf "nx-terminal-%s\n" "$phase" >"$nx_terminal_payload"
  printf "turbo-%s\n" "$phase" >"$turbo_payload"
  printf "sccache-%s\n" "$phase" >"$sccache_payload"
  printf "go-%s\n" "$phase" >"$go_payload"

  local auth_header="Authorization: Bearer ${AUTH_BEARER}"
  local json_header="Content-Type: application/json"
  echo "== ${phase}: write =="
  http_request "PUT" "/ac/${BAZEL_AC_DIGEST}" "200" "$bazel_ac_payload" "${phase_dir}/bazel-ac-put.out"
  http_request "PUT" "/cas/${BAZEL_CAS_DIGEST}" "200" "$bazel_cas_payload" "${phase_dir}/bazel-cas-put.out"
  http_request "PUT" "/cache/${GRADLE_KEY}" "200" "$gradle_payload" "${phase_dir}/gradle-put.out"
  http_request "PUT" "${MAVEN_PATH}" "200" "$maven_payload" "${phase_dir}/maven-put.out"
  http_request "PUT" "/v1/cache/${NX_HASH}" "200" "$nx_payload" "${phase_dir}/nx-put.out" "$auth_header"
  http_request "PUT" "/v1/cache/${NX_HASH}/terminalOutputs" "200" "$nx_terminal_payload" "${phase_dir}/nx-terminal-put.out" "$auth_header"
  http_request "GET" "/v8/artifacts/status" "200" "" "${phase_dir}/turbo-status.out" "$auth_header"
  assert_contains '"status":"enabled"' "${phase_dir}/turbo-status.out" "turborepo status"
  http_request "PUT" "/v8/artifacts/${TURBO_HASH}" "202" "$turbo_payload" "${phase_dir}/turbo-put.out" "$auth_header"
  assert_contains '"urls":\[\]' "${phase_dir}/turbo-put.out" "turborepo put response"
  printf '{"hashes":["%s","%s"]}\n' "$TURBO_HASH" "$TURBO_MISS" >"${phase_dir}/turbo-query.json"
  http_request "POST" "/v8/artifacts" "200" "${phase_dir}/turbo-query.json" "${phase_dir}/turbo-query.out" "$auth_header" "$json_header"
  assert_contains "\"${TURBO_HASH}\"" "${phase_dir}/turbo-query.out" "turborepo query response"
  assert_contains "\"${TURBO_MISS}\":null" "${phase_dir}/turbo-query.out" "turborepo query miss response"
  http_request "POST" "/v8/artifacts/events" "200" "" "${phase_dir}/turbo-events.out" "$auth_header"
  http_request "MKCOL" "/a/b/c" "201" "" "${phase_dir}/sccache-mkcol.out"
  http_request "PUT" "/a/b/c/${SCCACHE_KEY}" "201" "$sccache_payload" "${phase_dir}/sccache-put.out"
  http_request "PUT" "/gocache/${GO_ACTION}" "201" "$go_payload" "${phase_dir}/go-put.out"
  printf '{"hashes":["%s","%s"]}\n' "$NX_HASH" "$NX_MISS" >"${phase_dir}/nx-query.json"
  http_request "POST" "/v1/cache" "200" "${phase_dir}/nx-query.json" "${phase_dir}/nx-query.out" "$auth_header" "$json_header"
  assert_contains "\"${NX_MISS}\"" "${phase_dir}/nx-query.out" "nx query response"
  assert_not_contains "\"${NX_HASH}\"" "${phase_dir}/nx-query.out" "nx query response"

  echo "== ${phase}: read =="
  http_request "HEAD" "/ac/${BAZEL_AC_DIGEST}" "200" "" "${phase_dir}/bazel-ac-head.out"
  http_request "HEAD" "/cas/${BAZEL_CAS_DIGEST}" "200" "" "${phase_dir}/bazel-cas-head.out"
  http_request "HEAD" "/cache/${GRADLE_KEY}" "200" "" "${phase_dir}/gradle-head.out"
  http_request "HEAD" "${MAVEN_PATH}" "200" "" "${phase_dir}/maven-head.out"
  http_request "HEAD" "/v1/cache/${NX_HASH}" "200" "" "${phase_dir}/nx-head.out" "$auth_header"
  http_request "HEAD" "/v1/cache/${NX_HASH}/terminalOutputs" "200" "" "${phase_dir}/nx-terminal-head.out" "$auth_header"
  http_request "HEAD" "/v8/artifacts/${TURBO_HASH}" "200" "" "${phase_dir}/turbo-head.out" "$auth_header"
  http_request "HEAD" "/a/b/c/${SCCACHE_KEY}" "200" "" "${phase_dir}/sccache-head.out"
  http_request "HEAD" "/gocache/${GO_ACTION}" "200" "" "${phase_dir}/go-head.out"

  http_request "GET" "/ac/${BAZEL_AC_DIGEST}" "200" "" "${phase_dir}/bazel-ac-get.bin"
  assert_file_equals "$bazel_ac_payload" "${phase_dir}/bazel-ac-get.bin" "bazel-ac"
  http_request "GET" "/cas/${BAZEL_CAS_DIGEST}" "200" "" "${phase_dir}/bazel-cas-get.bin"
  assert_file_equals "$bazel_cas_payload" "${phase_dir}/bazel-cas-get.bin" "bazel-cas"
  http_request "GET" "/cache/${GRADLE_KEY}" "200" "" "${phase_dir}/gradle-get.bin"
  assert_file_equals "$gradle_payload" "${phase_dir}/gradle-get.bin" "gradle"
  http_request "GET" "${MAVEN_PATH}" "200" "" "${phase_dir}/maven-get.bin"
  assert_file_equals "$maven_payload" "${phase_dir}/maven-get.bin" "maven"
  http_request "GET" "/v1/cache/${NX_HASH}" "200" "" "${phase_dir}/nx-get.bin" "$auth_header"
  assert_file_equals "$nx_payload" "${phase_dir}/nx-get.bin" "nx artifact"
  http_request "GET" "/v1/cache/${NX_HASH}/terminalOutputs" "200" "" "${phase_dir}/nx-terminal-get.bin" "$auth_header"
  assert_file_equals "$nx_terminal_payload" "${phase_dir}/nx-terminal-get.bin" "nx terminal output"
  http_request "GET" "/v8/artifacts/${TURBO_HASH}" "200" "" "${phase_dir}/turbo-get.bin" "$auth_header"
  assert_file_equals "$turbo_payload" "${phase_dir}/turbo-get.bin" "turborepo artifact"
  http_request "GET" "/a/b/c/${SCCACHE_KEY}" "200" "" "${phase_dir}/sccache-get.bin"
  assert_file_equals "$sccache_payload" "${phase_dir}/sccache-get.bin" "sccache object"
  http_request "GET" "/gocache/${GO_ACTION}" "200" "" "${phase_dir}/go-get.bin"
  assert_file_equals "$go_payload" "${phase_dir}/go-get.bin" "go action"
}

verify_restart_read_phase() {
  local phase_dir="${LOG_DIR}/phase2"
  local source_dir="${LOG_DIR}/phase1"
  mkdir -p "$phase_dir"
  local auth_header="Authorization: Bearer ${AUTH_BEARER}"
  local json_header="Content-Type: application/json"

  echo "== phase2: read after restart =="
  http_request "GET" "/v8/artifacts/status" "200" "" "${phase_dir}/turbo-status.out" "$auth_header"
  assert_contains '"status":"enabled"' "${phase_dir}/turbo-status.out" "turborepo status"

  http_request "HEAD" "/ac/${BAZEL_AC_DIGEST}" "200" "" "${phase_dir}/bazel-ac-head.out"
  http_request "HEAD" "/cas/${BAZEL_CAS_DIGEST}" "200" "" "${phase_dir}/bazel-cas-head.out"
  http_request "HEAD" "/cache/${GRADLE_KEY}" "200" "" "${phase_dir}/gradle-head.out"
  http_request "HEAD" "${MAVEN_PATH}" "200" "" "${phase_dir}/maven-head.out"
  http_request "HEAD" "/v1/cache/${NX_HASH}" "200" "" "${phase_dir}/nx-head.out" "$auth_header"
  http_request "HEAD" "/v1/cache/${NX_HASH}/terminalOutputs" "200" "" "${phase_dir}/nx-terminal-head.out" "$auth_header"
  http_request "HEAD" "/v8/artifacts/${TURBO_HASH}" "200" "" "${phase_dir}/turbo-head.out" "$auth_header"
  http_request "HEAD" "/a/b/c/${SCCACHE_KEY}" "200" "" "${phase_dir}/sccache-head.out"
  http_request "HEAD" "/gocache/${GO_ACTION}" "200" "" "${phase_dir}/go-head.out"

  http_request "GET" "/ac/${BAZEL_AC_DIGEST}" "200" "" "${phase_dir}/bazel-ac-get.bin"
  assert_file_equals "${source_dir}/bazel-ac.payload" "${phase_dir}/bazel-ac-get.bin" "bazel-ac after restart"
  http_request "GET" "/cas/${BAZEL_CAS_DIGEST}" "200" "" "${phase_dir}/bazel-cas-get.bin"
  assert_file_equals "${source_dir}/bazel-cas.payload" "${phase_dir}/bazel-cas-get.bin" "bazel-cas after restart"
  http_request "GET" "/cache/${GRADLE_KEY}" "200" "" "${phase_dir}/gradle-get.bin"
  assert_file_equals "${source_dir}/gradle.payload" "${phase_dir}/gradle-get.bin" "gradle after restart"
  http_request "GET" "${MAVEN_PATH}" "200" "" "${phase_dir}/maven-get.bin"
  assert_file_equals "${source_dir}/maven.payload" "${phase_dir}/maven-get.bin" "maven after restart"
  http_request "GET" "/v1/cache/${NX_HASH}" "200" "" "${phase_dir}/nx-get.bin" "$auth_header"
  assert_file_equals "${source_dir}/nx.payload" "${phase_dir}/nx-get.bin" "nx artifact after restart"
  http_request "GET" "/v1/cache/${NX_HASH}/terminalOutputs" "200" "" "${phase_dir}/nx-terminal-get.bin" "$auth_header"
  assert_file_equals "${source_dir}/nx-terminal.payload" "${phase_dir}/nx-terminal-get.bin" "nx terminal after restart"
  http_request "GET" "/v8/artifacts/${TURBO_HASH}" "200" "" "${phase_dir}/turbo-get.bin" "$auth_header"
  assert_file_equals "${source_dir}/turbo.payload" "${phase_dir}/turbo-get.bin" "turborepo after restart"
  http_request "GET" "/a/b/c/${SCCACHE_KEY}" "200" "" "${phase_dir}/sccache-get.bin"
  assert_file_equals "${source_dir}/sccache.payload" "${phase_dir}/sccache-get.bin" "sccache after restart"
  http_request "GET" "/gocache/${GO_ACTION}" "200" "" "${phase_dir}/go-get.bin"
  assert_file_equals "${source_dir}/go.payload" "${phase_dir}/go-get.bin" "go action after restart"

  printf '{"hashes":["%s","%s"]}\n' "$NX_HASH" "$NX_MISS" >"${phase_dir}/nx-query.json"
  http_request "POST" "/v1/cache" "200" "${phase_dir}/nx-query.json" "${phase_dir}/nx-query.out" "$auth_header" "$json_header"
  assert_contains "\"${NX_MISS}\"" "${phase_dir}/nx-query.out" "nx query after restart"
  assert_not_contains "\"${NX_HASH}\"" "${phase_dir}/nx-query.out" "nx query after restart"

  printf '{"hashes":["%s","%s"]}\n' "$TURBO_HASH" "$TURBO_MISS" >"${phase_dir}/turbo-query.json"
  http_request "POST" "/v8/artifacts" "200" "${phase_dir}/turbo-query.json" "${phase_dir}/turbo-query.out" "$auth_header" "$json_header"
  assert_contains "\"${TURBO_HASH}\"" "${phase_dir}/turbo-query.out" "turborepo query after restart"
  assert_contains "\"${TURBO_MISS}\":null" "${phase_dir}/turbo-query.out" "turborepo query miss after restart"
}

TAG="${TAG_BASE}-${RUN_ID}"

start_proxy "$TAG"
ensure_proxy_ready

echo ""
echo "=== Phase 1: Write and read with running proxy ==="
run_round_trip_phase "phase1"

echo ""
echo "Waiting for writes to settle (${SETTLE_SECS}s)..."
sleep "$SETTLE_SECS"

echo ""
echo "Restarting proxy to verify persisted index..."
stop_proxy
start_proxy "$TAG"
ensure_proxy_ready

echo ""
echo "=== Phase 2: Read-only verification after proxy restart ==="
verify_restart_read_phase

stop_proxy

echo ""
echo "========================================="
echo "All adapter HTTP e2e checks passed"
echo "  Bazel AC/CAS"
echo "  Gradle"
echo "  Maven (v1.1 path)"
echo "  Nx artifact/terminal/query"
echo "  Turborepo status/artifact/query/events"
echo "  sccache WebDAV key path + MKCOL"
echo "  Go cache object API"
echo "Logs: ${LOG_DIR}"
echo "========================================="
