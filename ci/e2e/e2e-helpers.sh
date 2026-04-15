#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/e2e-auth.sh"
source "${SCRIPT_DIR}/e2e-remote-tag.sh"

PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-}"
PROXY_STATUS_PATH="${PROXY_STATUS_PATH:-/_boringcache/status}"
PROXY_READY_TIMEOUT_SECS="${PROXY_READY_TIMEOUT_SECS:-90}"
PROXY_READY_POLL_SECS="${PROXY_READY_POLL_SECS:-1}"
PROXY_READY_WARN_SECS="${PROXY_READY_WARN_SECS:-15}"
PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_SECS:-210}"
PROXY_SHUTDOWN_WAIT_MIN_SECS=210
PORT_RECLAIM_WAIT_SECS="${PORT_RECLAIM_WAIT_SECS:-15}"
SCCACHE_CONFLICT_ENV_VARS=(
  SCCACHE_ENDPOINT
  SCCACHE_BUCKET
  SCCACHE_REGION
  SCCACHE_S3_KEY_PREFIX
  SCCACHE_S3_USE_SSL
  SCCACHE_S3_NO_CREDENTIALS
  SCCACHE_S3_SERVER_SIDE_ENCRYPTION
  SCCACHE_S3_ENABLE_VIRTUAL_HOST_STYLE
  SCCACHE_GCS_BUCKET
  SCCACHE_GCS_KEY_PATH
  SCCACHE_GCS_CREDENTIALS_URL
  SCCACHE_AZURE_CONNECTION_STRING
  SCCACHE_AZURE_BLOB_CONTAINER
  SCCACHE_REDIS
  SCCACHE_MEMCACHED
  SCCACHE_WEBDAV_ENDPOINT
  SCCACHE_WEBDAV_USERNAME
  SCCACHE_WEBDAV_PASSWORD
)
declare -ag E2E_TAG_SCOPE_FLAGS=(--no-platform --no-git)

_HELPER_PROXY_PID=""
_HELPER_PROXY_LOG=""
_HELPER_PROXY_METRICS=""
_HELPER_PROXY_READY_FILE=""
_HELPER_INTERRUPTED="0"
_HELPER_PORT_TOOL=""
declare -a _HELPER_TAGS_TO_DELETE=()
declare -a _HELPER_CLEANUP_CALLBACKS=()

if command -v lsof >/dev/null 2>&1; then
  _HELPER_PORT_TOOL="lsof"
elif command -v ss >/dev/null 2>&1; then
  _HELPER_PORT_TOOL="ss"
fi

if [[ "${PROXY_SHUTDOWN_WAIT_SECS}" =~ ^[0-9]+$ ]] \
  && (( PROXY_SHUTDOWN_WAIT_SECS < PROXY_SHUTDOWN_WAIT_MIN_SECS )); then
  PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_MIN_SECS}"
fi

require_positive() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: ${name} must be a positive integer"
    exit 1
  fi
}

require_numeric() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "ERROR: ${name} must be a non-negative integer"
    exit 1
  fi
}

run_with_clean_sccache_env() {
  local -a env_cmd=(env)
  local name
  for name in "${SCCACHE_CONFLICT_ENV_VARS[@]}"; do
    env_cmd+=("-u" "$name")
  done
  "${env_cmd[@]}" "$@"
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

sha256_file_hex() {
  local file_path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file_path" | awk '{print $1}'
  else
    shasum -a 256 "$file_path" | awk '{print $1}'
  fi
}

port_listener_pids() {
  local port="$1"
  if [[ "$_HELPER_PORT_TOOL" == "lsof" ]]; then
    lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
  elif [[ "$_HELPER_PORT_TOOL" == "ss" ]]; then
    ss -lntp "sport = :$port" 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | sort -u
  fi
}

port_listener_details() {
  local port="$1"
  if [[ "$_HELPER_PORT_TOOL" == "lsof" ]]; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
  elif [[ "$_HELPER_PORT_TOOL" == "ss" ]]; then
    ss -lntp "sport = :$port" 2>/dev/null || true
  fi
}

next_available_sccache_port() {
  local candidate="$1"
  local reserved_port="${2:-}"
  local limit="${3:-256}"
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

reclaim_stale_proxy_port() {
  local port="${1:-${PROXY_PORT:-5050}}"
  local listener_pids pid cmd
  listener_pids="$(port_listener_pids "$port")"
  if [[ -z "$listener_pids" ]]; then
    return 0
  fi
  for pid in $listener_pids; do
    cmd="$(ps -p "$pid" -o command= 2>/dev/null || true)"
    if [[ "$cmd" == *"boringcache"* && "$cmd" == *"cache-registry"* ]]; then
      echo "WARNING: reclaiming stale proxy on port ${port} (pid=${pid})"
      stop_pid_tree "$pid" "stale proxy" "$PORT_RECLAIM_WAIT_SECS"
    fi
  done
  listener_pids="$(port_listener_pids "$port")"
  if [[ -n "$listener_pids" ]]; then
    echo "ERROR: port ${port} is already in use"
    port_listener_details "$port"
    exit 1
  fi
}

start_proxy() {
  local binary="$1"
  local workspace="$2"
  local tag="$3"
  local port="${4:-${PROXY_PORT:-5050}}"
  local log_file="${5:-${LOG_DIR}/proxy.log}"
  local extra_args="${6:-}"

  stop_proxy
  reclaim_stale_proxy_port "$port"

  _HELPER_PROXY_LOG="$log_file"
  local metrics_dir
  metrics_dir="$(dirname "$log_file")"
  _HELPER_PROXY_METRICS="${metrics_dir}/cache-registry-request-metrics.jsonl"
  _HELPER_PROXY_READY_FILE="$(mktemp "${metrics_dir}/cache-registry-ready.XXXXXX")"
  rm -f "${_HELPER_PROXY_READY_FILE}"
  {
    echo ""
    echo "=== Proxy start $(date -u +"%Y-%m-%dT%H:%M:%SZ") tag=${tag} ==="
  } >>"$log_file"

  local metadata_hints="${BORINGCACHE_PROXY_METADATA_HINTS:-}"

  if [[ -n "$extra_args" ]]; then
    RUST_LOG="${RUST_LOG:-warn}" \
    BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
    BORINGCACHE_OBSERVABILITY_JSONL_PATH="${_HELPER_PROXY_METRICS}" \
    BORINGCACHE_PROXY_METADATA_HINTS="${metadata_hints}" \
      "$binary" cache-registry "$workspace" "$tag" \
      --host "$PROXY_HOST" \
      --port "$port" \
      --ready-file "${_HELPER_PROXY_READY_FILE}" \
      "${E2E_TAG_SCOPE_FLAGS[@]}" \
      $extra_args >>"$log_file" 2>&1 &
  else
    RUST_LOG="${RUST_LOG:-warn}" \
    BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
    BORINGCACHE_OBSERVABILITY_JSONL_PATH="${_HELPER_PROXY_METRICS}" \
    BORINGCACHE_PROXY_METADATA_HINTS="${metadata_hints}" \
      "$binary" cache-registry "$workspace" "$tag" \
      --host "$PROXY_HOST" \
      --port "$port" \
      --ready-file "${_HELPER_PROXY_READY_FILE}" \
      "${E2E_TAG_SCOPE_FLAGS[@]}" >>"$log_file" 2>&1 &
  fi
  _HELPER_PROXY_PID=$!
}

proxy_status_probe() {
  local port="${1:-${PROXY_PORT:-5050}}"
  local response status phase publish_state
  response="$(
    curl -sS -D - -o /dev/null \
      --max-time 2 \
      "http://${PROXY_HOST}:${port}${PROXY_STATUS_PATH}" 2>/dev/null || true
  )"
  status="$(printf '%s\n' "$response" | awk 'tolower($1) ~ /^http\// { status = $2 } END { print status }')"
  phase="$(printf '%s\n' "$response" | awk -F': ' 'tolower($1) == "x-boringcache-proxy-phase" { gsub("\\r", "", $2); phase = tolower($2) } END { print phase }')"
  publish_state="$(printf '%s\n' "$response" | awk -F': ' 'tolower($1) == "x-boringcache-publish-state" { gsub("\\r", "", $2); publish = tolower($2) } END { print publish }')"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf '%s %s %s' "$status" "${phase:-unknown}" "${publish_state:-unknown}"
}

proxy_status_ok() {
  local port="${1:-${PROXY_PORT:-5050}}"
  local probe status phase publish_state
  probe="$(proxy_status_probe "$port")"
  read -r status phase publish_state <<<"$probe"
  [[ "$status" == "200" ]]
}

wait_for_proxy_phase() {
  local expected_phase="$1"
  local port="${2:-${PROXY_PORT:-5050}}"
  local pid="${3:-${_HELPER_PROXY_PID:-}}"
  local log_file="${4:-${_HELPER_PROXY_LOG:-/dev/null}}"
  local attempts start_ts next_warn now waited
  local probe status phase publish_state
  attempts="$((PROXY_READY_TIMEOUT_SECS / PROXY_READY_POLL_SECS))"
  if (( attempts < 1 )); then
    attempts=1
  fi
  start_ts="$(date +%s)"
  next_warn=$((start_ts + PROXY_READY_WARN_SECS))
  for _ in $(seq 1 "$attempts"); do
    probe="$(proxy_status_probe "$port")"
    read -r status phase publish_state <<<"$probe"
    if [[ "$status" == "200" && "$phase" == "$expected_phase" ]]; then
      return 0
    fi
    now="$(date +%s)"
    if (( now >= next_warn )); then
      waited="$((now - start_ts))"
      echo "WARNING: proxy phase still waiting after ${waited}s (want=${expected_phase} phase=${phase:-unknown} publish=${publish_state:-unknown})"
      next_warn=$((now + PROXY_READY_WARN_SECS))
    fi
    if [[ -n "${pid:-}" ]] && ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "ERROR: proxy exited before readiness"
      tail -n 80 "${log_file}" || true
      exit 1
    fi
    sleep "$PROXY_READY_POLL_SECS"
  done
  echo "ERROR: proxy failed to reach phase ${expected_phase} within ${PROXY_READY_TIMEOUT_SECS}s"
  tail -n 80 "${log_file}" || true
  exit 1
}

wait_for_ready_file() {
  local ready_file="$1"
  local pid="${2:-}"
  local log_file="${3:-/dev/null}"
  local attempts start_ts next_warn now waited
  attempts="$((PROXY_READY_TIMEOUT_SECS / PROXY_READY_POLL_SECS))"
  if (( attempts < 1 )); then
    attempts=1
  fi
  start_ts="$(date +%s)"
  next_warn=$((start_ts + PROXY_READY_WARN_SECS))
  for _ in $(seq 1 "$attempts"); do
    if [[ -f "$ready_file" ]]; then
      return 0
    fi
    now="$(date +%s)"
    if (( now >= next_warn )); then
      waited="$((now - start_ts))"
      echo "WARNING: proxy readiness marker still waiting after ${waited}s (${ready_file})"
      next_warn=$((now + PROXY_READY_WARN_SECS))
    fi
    if [[ -n "${pid:-}" ]] && ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "ERROR: proxy exited before readiness"
      tail -n 80 "${log_file}" || true
      exit 1
    fi
    sleep "$PROXY_READY_POLL_SECS"
  done
  echo "ERROR: proxy failed to create readiness marker within ${PROXY_READY_TIMEOUT_SECS}s (${ready_file})"
  tail -n 80 "${log_file}" || true
  exit 1
}

wait_for_proxy() {
  local port="${1:-${PROXY_PORT:-5050}}"
  local pid="${2:-${_HELPER_PROXY_PID:-}}"
  local log_file="${3:-${_HELPER_PROXY_LOG:-/dev/null}}"
  local ready_file="${4:-${_HELPER_PROXY_READY_FILE:-}}"
  if [[ -n "${ready_file:-}" ]]; then
    wait_for_ready_file "$ready_file" "$pid" "$log_file"
    return 0
  fi
  wait_for_proxy_phase "ready" "$port" "$pid" "$log_file"
}

wait_for_proxy_publish_settled() {
  local port="${1:-${PROXY_PORT:-5050}}"
  local pid="${2:-${_HELPER_PROXY_PID:-}}"
  local log_file="${3:-${_HELPER_PROXY_LOG:-/dev/null}}"
  local attempts start_ts next_warn now waited
  local probe status phase publish_state
  attempts="$((PROXY_READY_TIMEOUT_SECS / PROXY_READY_POLL_SECS))"
  if (( attempts < 1 )); then
    attempts=1
  fi
  start_ts="$(date +%s)"
  next_warn=$((start_ts + PROXY_READY_WARN_SECS))
  for _ in $(seq 1 "$attempts"); do
    probe="$(proxy_status_probe "$port")"
    read -r status phase publish_state <<<"$probe"
    if [[ "$status" == "200" && "$publish_state" == "settled" ]]; then
      return 0
    fi
    now="$(date +%s)"
    if (( now >= next_warn )); then
      waited="$((now - start_ts))"
      echo "WARNING: proxy publish still waiting after ${waited}s (phase=${phase:-unknown} publish=${publish_state:-unknown})"
      next_warn=$((now + PROXY_READY_WARN_SECS))
    fi
    if [[ -n "${pid:-}" ]] && ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "ERROR: proxy exited before publish settled"
      tail -n 80 "${log_file}" || true
      exit 1
    fi
    sleep "$PROXY_READY_POLL_SECS"
  done
  echo "ERROR: proxy publish did not settle within ${PROXY_READY_TIMEOUT_SECS}s"
  tail -n 80 "${log_file}" || true
  exit 1
}

stop_proxy() {
  if [[ -n "${_HELPER_PROXY_PID:-}" ]]; then
    stop_pid_tree "$_HELPER_PROXY_PID" "proxy" "$PROXY_SHUTDOWN_WAIT_SECS"
    _HELPER_PROXY_PID=""
  fi
  rm -f "${_HELPER_PROXY_READY_FILE:-}" >/dev/null 2>&1 || true
  _HELPER_PROXY_READY_FILE=""
}

proxy_pid() {
  printf '%s' "${_HELPER_PROXY_PID:-}"
}

proxy_log() {
  printf '%s' "${_HELPER_PROXY_LOG:-}"
}

proxy_metrics_file() {
  printf '%s' "${_HELPER_PROXY_METRICS:-}"
}

dump_cache_ops_summary() {
  local metrics_file="${1:-$(proxy_metrics_file)}"
  local summary_file="${2:-}"
  if [[ ! -f "${metrics_file}" ]]; then
    echo "  cache ops: no metrics file found"
    return 0
  fi
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -z "${summary_file}" ]]; then
    summary_file="$(dirname "${metrics_file}")/cache-ops-summary.env"
  fi
  if python3 "${script_dir}/request-metrics-summary.py" "${metrics_file}" > "${summary_file}" 2>/dev/null; then
    source "${summary_file}"
    echo "  cache ops: records=${request_metrics_cache_ops_records_total:-0} hits=${request_metrics_cache_ops_sccache_get_hits:-0} misses=${request_metrics_cache_ops_sccache_get_misses:-0}"
  else
    echo "  cache ops: summary unavailable"
  fi
}

register_tag_for_cleanup() {
  _HELPER_TAGS_TO_DELETE+=("$1")
}

register_cleanup_callback() {
  _HELPER_CLEANUP_CALLBACKS+=("$1")
}

wait_for_visibility() {
  local binary="$1"
  local workspace="$2"
  local tag="$3"
  local attempts="${4:-15}"
  local log_file="${LOG_DIR:-.}/visibility-${tag}.log"
  for _ in $(seq 1 "$attempts"); do
    if "$binary" check "${E2E_TAG_SCOPE_FLAGS[@]}" --fail-on-miss "$workspace" "$tag" \
      > "$log_file" 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: tag did not become visible in time: ${tag}"
  cat "$log_file"
  exit 1
}

assert_file_contains() {
  local file="$1"
  local pattern="$2"
  if ! grep -q "$pattern" "$file"; then
    echo "ASSERT FAILED: ${file} does not contain '${pattern}'"
    exit 1
  fi
}

assert_file_not_contains() {
  local file="$1"
  local pattern="$2"
  if grep -q "$pattern" "$file"; then
    echo "ASSERT FAILED: ${file} contains '${pattern}' (expected absent)"
    exit 1
  fi
}

assert_exit_nonzero() {
  local description="$1"
  shift
  set +e
  "$@" >/dev/null 2>&1
  local status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    echo "ASSERT FAILED: expected non-zero exit from: ${description}"
    exit 1
  fi
  return 0
}

timed_run() {
  local label="$1"
  shift
  local start_ts end_ts elapsed
  start_ts="$(date +%s)"
  "$@"
  end_ts="$(date +%s)"
  elapsed="$((end_ts - start_ts))"
  echo "${label} completed in ${elapsed}s"
}

_helper_cleanup() {
  set +e
  local -a cleanup_callbacks=()
  local -a tags_to_delete=()
  local cb
  if [[ "${_HELPER_CLEANUP_CALLBACKS+set}" == "set" ]]; then
    cleanup_callbacks=("${_HELPER_CLEANUP_CALLBACKS[@]}")
  fi
  if [[ "${#cleanup_callbacks[@]}" -gt 0 ]]; then
    for cb in "${cleanup_callbacks[@]}"; do
      "$cb"
    done
  fi
  stop_proxy
  if [[ "${_HELPER_TAGS_TO_DELETE+set}" == "set" ]]; then
    tags_to_delete=("${_HELPER_TAGS_TO_DELETE[@]}")
  fi
  if [[ "${#tags_to_delete[@]}" -gt 0 && -n "${_HELPER_BINARY:-}" && -n "${_HELPER_WORKSPACE:-}" ]]; then
    for tag in "${tags_to_delete[@]}"; do
      "$_HELPER_BINARY" delete "${E2E_TAG_SCOPE_FLAGS[@]}" "$_HELPER_WORKSPACE" "$tag" >/dev/null 2>&1 || true
    done
  fi
}

_helper_dump_logs() {
  set +e
  echo "=== E2E debug logs ==="
  if [[ -d "${LOG_DIR:-.}" ]]; then
    while IFS= read -r log_file; do
      echo "--- ${log_file} ---"
      tail -n 120 "${log_file}" || true
    done < <(find "${LOG_DIR:-.}" -name '*.log' -type f 2>/dev/null | sort)
  fi
  echo "=== End E2E debug logs ==="
}

setup_e2e_traps() {
  local binary="$1"
  local workspace="$2"
  _HELPER_BINARY="$binary"
  _HELPER_WORKSPACE="$workspace"
  trap _helper_dump_logs ERR
  trap _helper_cleanup EXIT
}

handle_interrupt() {
  if [[ "$_HELPER_INTERRUPTED" == "1" ]]; then
    return
  fi
  _HELPER_INTERRUPTED="1"
  trap '' INT TERM
  echo ""
  echo "Interrupt received, shutting down..."
  exit 130
}
trap handle_interrupt INT TERM
