#!/usr/bin/env bash
set -euo pipefail

DOCKER_E2E_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${DOCKER_E2E_SCRIPT_DIR}/../e2e-auth.sh"
source "${DOCKER_E2E_SCRIPT_DIR}/../e2e-remote-tag.sh"

CLI_REPO_ROOT="$(cd "${DOCKER_E2E_SCRIPT_DIR}/../../.." && pwd)"
BINARY="${BINARY:-${CLI_REPO_ROOT}/target/debug/boringcache}"
WORKSPACE="${WORKSPACE:?WORKSPACE is required}"
E2E_TAG_PREFIX="${E2E_TAG_PREFIX:-gha-cache-registry}"
PORT="${PORT:-5000}"
PROXY_PORT="${PROXY_PORT:-${PORT}}"
REGISTRY_PORT="${REGISTRY_PORT:-${PORT}}"
LOG_DIR="${LOG_DIR:-.}"
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_STATUS_HOST="${PROXY_STATUS_HOST:-127.0.0.1}"
PROXY_STATUS_PATH="${PROXY_STATUS_PATH:-/_boringcache/status}"
OCI_HYDRATION="${OCI_HYDRATION:-metadata-only}"
BUILD_TIMEOUT_SECS="${BUILD_TIMEOUT_SECS:-0}"
BUILD_HEARTBEAT_SECS="${BUILD_HEARTBEAT_SECS:-30}"
BUILD_CLEANUP_WAIT_SECS="${BUILD_CLEANUP_WAIT_SECS:-20}"
BUILD_FAILURE_TAIL_LINES="${BUILD_FAILURE_TAIL_LINES:-120}"
PROXY_READY_TIMEOUT_SECS="${PROXY_READY_TIMEOUT_SECS:-90}"
PROXY_READY_POLL_SECS="${PROXY_READY_POLL_SECS:-1}"
PROXY_READY_WARN_SECS="${PROXY_READY_WARN_SECS:-10}"
PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_SECS:-210}"
PROXY_SHUTDOWN_WAIT_MIN_SECS=210
BUDGET_REMOTE_TAG_HITS_MIN="${BUDGET_REMOTE_TAG_HITS_MIN:-1}"

mkdir -p "${LOG_DIR}"

RUN_ID="${GITHUB_RUN_ID:-local}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}"
BUILDER="bc-e2e-${RUN_ID}-${RUN_ATTEMPT}"
CACHE_TAG="${E2E_TAG_PREFIX}-docker-buildkit-${RUN_ID}-${RUN_ATTEMPT}"
CACHE_REF="localhost:${REGISTRY_PORT}/boringcache-e2e/cache:${CACHE_TAG}"
CACHE_REF_IMPLICIT="localhost:${REGISTRY_PORT}/boringcache-e2e/cache"
CACHE_TAG_ALIAS="${CACHE_TAG}-alias"
CACHE_REF_ALIAS="localhost:${REGISTRY_PORT}/boringcache-e2e/cache:${CACHE_TAG_ALIAS}"
REGISTRY_ROOT_TAG="${E2E_TAG_PREFIX}-docker-buildkit-registry-${RUN_ID}-${RUN_ATTEMPT}"
SERVE_PID=""
PROXY_READY_FILE=""
INTERRUPTED="0"
declare -a LOG_FILES=()
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

require_numeric "BUILD_TIMEOUT_SECS" "$BUILD_TIMEOUT_SECS"
require_positive "BUILD_HEARTBEAT_SECS" "$BUILD_HEARTBEAT_SECS"
require_positive "BUILD_CLEANUP_WAIT_SECS" "$BUILD_CLEANUP_WAIT_SECS"
require_positive "BUILD_FAILURE_TAIL_LINES" "$BUILD_FAILURE_TAIL_LINES"
require_positive "PROXY_READY_TIMEOUT_SECS" "$PROXY_READY_TIMEOUT_SECS"
require_positive "PROXY_READY_POLL_SECS" "$PROXY_READY_POLL_SECS"
require_positive "PROXY_READY_WARN_SECS" "$PROXY_READY_WARN_SECS"
if [[ "${PROXY_SHUTDOWN_WAIT_SECS}" =~ ^[0-9]+$ ]] \
  && (( PROXY_SHUTDOWN_WAIT_SECS < PROXY_SHUTDOWN_WAIT_MIN_SECS )); then
  PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_MIN_SECS}"
fi
require_positive "PROXY_SHUTDOWN_WAIT_SECS" "$PROXY_SHUTDOWN_WAIT_SECS"
require_numeric "BUDGET_REMOTE_TAG_HITS_MIN" "$BUDGET_REMOTE_TAG_HITS_MIN"
require_save_capable_token

for dep in docker curl pgrep; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: required dependency not found: ${dep}"
    exit 1
  fi
done

export_resolved_cli_tokens admin

remove_active_build_pid() {
  local target_pid="$1"
  local -a remaining=()
  local pid
  if (( ${#ACTIVE_BUILD_PIDS[@]} > 0 )); then
    for pid in "${ACTIVE_BUILD_PIDS[@]}"; do
      if [[ "$pid" != "$target_pid" ]]; then
        remaining+=("$pid")
      fi
    done
  fi
  ACTIVE_BUILD_PIDS=()
  if (( ${#remaining[@]} > 0 )); then
    ACTIVE_BUILD_PIDS=("${remaining[@]}")
  fi
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
  if [[ -n "${SERVE_PID:-}" ]]; then
    stop_pid_tree "${SERVE_PID}" "cache-registry proxy" "$PROXY_SHUTDOWN_WAIT_SECS"
  fi
  SERVE_PID=""
  rm -f "${PROXY_READY_FILE:-}" >/dev/null 2>&1 || true
  PROXY_READY_FILE=""
}

cleanup() {
  set +e
  stop_background_jobs
  local pid
  if (( ${#ACTIVE_BUILD_PIDS[@]} > 0 )); then
    for pid in "${ACTIVE_BUILD_PIDS[@]}"; do
      stop_pid_tree "$pid" "build" "$BUILD_CLEANUP_WAIT_SECS"
    done
  fi
  ACTIVE_BUILD_PIDS=()
  stop_proxy
  docker buildx rm --force "${BUILDER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap handle_interrupt INT TERM

proxy_status_probe() {
  local response status phase publish_state
  response="$(
    curl -sS -D - -o /dev/null \
      --max-time 2 \
      "http://${PROXY_STATUS_HOST}:${PROXY_PORT}${PROXY_STATUS_PATH}" 2>/dev/null || true
  )"
  status="$(printf '%s\n' "$response" | awk 'tolower($1) ~ /^http\// { status = $2 } END { print status }')"
  phase="$(printf '%s\n' "$response" | awk -F': ' 'tolower($1) == "x-boringcache-proxy-phase" { gsub("\\r", "", $2); phase = tolower($2) } END { print phase }')"
  publish_state="$(printf '%s\n' "$response" | awk -F': ' 'tolower($1) == "x-boringcache-publish-state" { gsub("\\r", "", $2); publish = tolower($2) } END { print publish }')"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf '%s %s %s' "$status" "${phase:-unknown}" "${publish_state:-unknown}"
}

start_proxy() {
  local log_file="$1"
  local metadata_hints="${2:-}"
  local readiness_reference="${3:-}"
  local -a proxy_cmd
  local attempts start_ts next_warn now waited
  stop_proxy
  LOG_FILES+=("${log_file}")
  PROXY_READY_FILE="$(mktemp "${LOG_DIR}/cache-registry-ready.XXXXXX")"
  rm -f "${PROXY_READY_FILE}"
  proxy_cmd=(
    "${BINARY}" cache-registry "${WORKSPACE}" "${REGISTRY_ROOT_TAG}"
    --host "${PROXY_HOST}"
    --port "${PROXY_PORT}"
    --ready-file "${PROXY_READY_FILE}"
    --no-platform
    --no-git
    --fail-on-cache-error
    --oci-hydration "${OCI_HYDRATION}"
  )
  if [[ -n "$readiness_reference" ]]; then
    proxy_cmd+=(--oci-prefetch-ref "boringcache-e2e/cache@${readiness_reference}")
  fi
  BORINGCACHE_PROXY_METADATA_HINTS="${metadata_hints}" \
    "${proxy_cmd[@]}" > "${log_file}" 2>&1 &
  SERVE_PID=$!

  local ready=0
  attempts="$((PROXY_READY_TIMEOUT_SECS / PROXY_READY_POLL_SECS))"
  if (( attempts < 1 )); then
    attempts=1
  fi
  start_ts="$(date +%s)"
  next_warn=$((start_ts + PROXY_READY_WARN_SECS))
  for _ in $(seq 1 "$attempts"); do
    if [[ -f "${PROXY_READY_FILE}" ]]; then
      if [[ -n "$readiness_reference" ]]; then
        if manifest_reference_is_readable "$readiness_reference"; then
          ready=1
          break
        fi
      else
        ready=1
        break
      fi
    fi
    now="$(date +%s)"
    if (( now >= next_warn )); then
      waited="$((now - start_ts))"
      if [[ -n "$readiness_reference" ]]; then
        echo "WARNING: cache-registry readiness still waiting after ${waited}s (marker=${PROXY_READY_FILE} ref=${readiness_reference})"
      else
        echo "WARNING: cache-registry readiness still waiting after ${waited}s (marker=${PROXY_READY_FILE})"
      fi
      next_warn=$((now + PROXY_READY_WARN_SECS))
    fi
    if ! kill -0 "${SERVE_PID}" >/dev/null 2>&1; then
      echo "cache-registry exited before readiness"
      cat "${log_file}"
      exit 1
    fi
    sleep "${PROXY_READY_POLL_SECS}"
  done

  if [[ "${ready}" != "1" ]]; then
    echo "timed out waiting for cache-registry readiness"
    cat "${log_file}"
    exit 1
  fi
}

capture_proxy_status() {
  local label="$1"
  local status_file="${LOG_DIR}/proxy-status-${label}.json"
  LOG_FILES+=("${status_file}")
  curl -fsS --max-time 5 \
    "http://${PROXY_STATUS_HOST}:${PROXY_PORT}${PROXY_STATUS_PATH}" \
    -o "${status_file}" 2>/dev/null || true
}

run_build() {
  local log_file="$1"
  local start_ts end_ts elapsed
  local build_pid now next_heartbeat status latest_line
  shift
  LOG_FILES+=("${log_file}")
  echo "build step starting: ${log_file}"
  start_ts="$(date +%s)"
  (
    set -o pipefail
    docker buildx build \
      --builder "${BUILDER}" \
      --progress plain \
      --load \
      --file e2e-context/Dockerfile \
      "$@" \
      e2e-context 2>&1 | tee "${log_file}"
  ) &
  build_pid=$!
  ACTIVE_BUILD_PIDS+=("$build_pid")
  next_heartbeat=$((start_ts + BUILD_HEARTBEAT_SECS))
  while kill -0 "$build_pid" >/dev/null 2>&1; do
    now="$(date +%s)"
    if [[ "$BUILD_TIMEOUT_SECS" -gt 0 ]] && (( now - start_ts >= BUILD_TIMEOUT_SECS )); then
      echo "ERROR: docker build step exceeded BUILD_TIMEOUT_SECS=${BUILD_TIMEOUT_SECS}s (${log_file})"
      stop_pid_tree "$build_pid" "docker build" "$BUILD_CLEANUP_WAIT_SECS"
      remove_active_build_pid "$build_pid"
      tail -n "$BUILD_FAILURE_TAIL_LINES" "$log_file" || true
      return 124
    fi
    if (( now >= next_heartbeat )); then
      elapsed="$((now - start_ts))"
      latest_line="$(awk 'NF { line=$0 } END { print line }' "$log_file" 2>/dev/null || true)"
      if [[ -n "$latest_line" ]]; then
        echo "  [heartbeat] docker build running ${elapsed}s | ${latest_line}"
      else
        echo "  [heartbeat] docker build running ${elapsed}s"
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
    echo "ERROR: docker build failed with exit code ${status} (${log_file}). Recent log output:"
    tail -n "$BUILD_FAILURE_TAIL_LINES" "$log_file" || true
    return "$status"
  fi
  echo "build step completed in ${elapsed}s (${log_file})"
}

is_transient_registry_export_error() {
  local log_file="$1"
  grep -Eq \
    'expected sha256:.*got sha256:e3b0|error writing layer blob|error writing manifest blob|unexpected status from PUT request.*(400 Bad Request|500 Internal Server Error)|Alias write failed .*confirm failed: Server error \(500\)' \
    "${log_file}"
}

run_build_with_retry() {
  local log_file="$1"
  shift
  local attempts=4
  local attempt
  for attempt in $(seq 1 "${attempts}"); do
    if run_build "${log_file}" "$@"; then
      return 0
    fi
    if [[ "${attempt}" -lt "${attempts}" ]] && is_transient_registry_export_error "${log_file}"; then
      echo "transient registry export error on attempt ${attempt}/${attempts}; retrying..."
      sleep $((attempt * 3))
      continue
    fi
    return 1
  done
}

create_builder() {
  docker buildx create \
    --name "${BUILDER}" \
    --driver docker-container \
    --driver-opt network=host \
    --use
  docker buildx inspect "${BUILDER}" --bootstrap
}

reset_builder() {
  docker buildx rm --force "${BUILDER}" >/dev/null 2>&1 || true
  create_builder
}

assert_cached() {
  local log_file="$1"
  if ! grep -q "CACHED" "${log_file}"; then
    echo "expected cached steps in ${log_file}"
    exit 1
  fi
}

assert_registry_import_succeeded() {
  local log_file="$1"
  if ! grep -q "importing cache manifest from" "${log_file}"; then
    echo "expected registry cache import attempt in ${log_file}"
    exit 1
  fi
  if grep -E -n "failed to configure registry cache importer|httpReadSeeker: failed open: .*(not found|500 Internal Server Error)|Blob storage returned error|OCI blob body download failed" "${log_file}" >/tmp/e2e-import-failure.log 2>/dev/null; then
    echo "registry cache import failed in ${log_file}"
    cat /tmp/e2e-import-failure.log
    exit 1
  fi
}

assert_import_reference_seen() {
  local log_file="$1"
  local reference="$2"
  if ! grep -Fq "importing cache manifest from ${reference}" "${log_file}"; then
    echo "expected cache import reference '${reference}' in ${log_file}"
    exit 1
  fi
}

manifest_reference_is_readable() {
  local reference="$1"
  local url="http://${PROXY_STATUS_HOST}:${PROXY_PORT}/v2/boringcache-e2e/cache/manifests/${reference}"
  local accept_header="Accept: application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"
  local digest
  digest=$(
    curl -fsS -I --max-time 2 -H "${accept_header}" "${url}" 2>/dev/null \
      | awk 'tolower($1)=="docker-content-digest:" {print $2}' \
      | tr -d '\r' \
      | tail -n1
  ) || true
  [[ -n "${digest}" ]]
}

fetch_manifest_with_retry() {
  local reference="$1"
  local manifest_file="$2"
  local attempts="${3:-20}"
  local url="http://${PROXY_STATUS_HOST}:${PROXY_PORT}/v2/boringcache-e2e/cache/manifests/${reference}"
  local accept_header="Accept: application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"

  for _ in $(seq 1 "${attempts}"); do
    if curl -fsS -H "${accept_header}" "${url}" -o "${manifest_file}"; then
      return 0
    fi
    sleep 1
  done

  echo "manifest did not become readable for reference ${reference} after ${attempts}s"
  return 1
}

resolve_manifest_digest_with_retry() {
  local reference="$1"
  local attempts="${2:-20}"
  local url="http://${PROXY_STATUS_HOST}:${PROXY_PORT}/v2/boringcache-e2e/cache/manifests/${reference}"
  local accept_header="Accept: application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"

  for _ in $(seq 1 "${attempts}"); do
    local digest
    digest=$(
      curl -fsS -I -H "${accept_header}" "${url}" 2>/dev/null \
        | awk 'tolower($1)=="docker-content-digest:" {print $2}' \
        | tr -d '\r' \
        | tail -n1
    ) || true
    if [[ -n "${digest}" ]]; then
      echo "${digest}"
      return 0
    fi
    sleep 1
  done

  echo "manifest digest header did not become readable for reference ${reference} after ${attempts}s" >&2
  return 1
}

cd "${LOG_DIR}"
reset_builder

echo "=== Docker Buildkit Registry Adapter E2E ==="
echo "Build timeout: ${BUILD_TIMEOUT_SECS}s (0 disables)"
echo "Build heartbeat: ${BUILD_HEARTBEAT_SECS}s"
echo "Proxy shutdown wait: ${PROXY_SHUTDOWN_WAIT_SECS}s"
echo "OCI hydration: ${OCI_HYDRATION}"
echo "Logs: ${LOG_DIR}"

mkdir -p e2e-context
cat > e2e-context/Dockerfile <<'EOF'
FROM scratch
COPY payload.bin /payload.bin
COPY f01.txt /f01.txt
COPY f02.txt /f02.txt
COPY f03.txt /f03.txt
COPY f04.txt /f04.txt
COPY f05.txt /f05.txt
COPY f06.txt /f06.txt
COPY f07.txt /f07.txt
COPY f08.txt /f08.txt
COPY f09.txt /f09.txt
COPY f10.txt /f10.txt
COPY f11.txt /f11.txt
COPY f12.txt /f12.txt
EOF
for i in $(seq -w 1 12); do
  printf 'layer-%s\n' "${i}" > "e2e-context/f${i}.txt"
done
dd if=/dev/zero of=e2e-context/payload.bin bs=1M count=6 status=none

phase_metadata_hints() {
  local phase="$1"
  printf 'project=cli-cache-registry,phase=%s,scenario=docker-buildkit,tool=oci' "$phase"
}

echo
echo "=== Phase 1: Cold build and warm import ==="
start_proxy "serve-initial.log" "$(phase_metadata_hints "docker-buildkit-cold-warm")"
run_build_with_retry "first-build.log" \
  --cache-from "type=registry,ref=${CACHE_REF}" \
  --cache-to "type=registry,ref=${CACHE_REF},mode=max"
reset_builder
run_build_with_retry "second-build.log" \
  --cache-from "type=registry,ref=${CACHE_REF}" \
  --cache-to "type=registry,ref=${CACHE_REF},mode=max"
assert_cached "second-build.log"
assert_registry_import_succeeded "second-build.log"
capture_proxy_status "phase1-warm"
run_build_with_retry "third-build-reexport.log" \
  --no-cache \
  --cache-to "type=registry,ref=${CACHE_REF},mode=max"
stop_proxy

echo
echo "=== Phase 1b: Verify published remote tag resolves ==="
if ! verify_remote_tag_visible "$BINARY" "$WORKSPACE" "$REGISTRY_ROOT_TAG" "${LOG_DIR}/phase1b-publish" "$BUDGET_REMOTE_TAG_HITS_MIN" "${REMOTE_TAG_VERIFY_ATTEMPTS}" "${REMOTE_TAG_VERIFY_SLEEP_SECS}" "serve-initial.log"; then
  exit 1
fi

echo
echo "=== Phase 2: Restart proxy and verify persisted warm import ==="
start_proxy "serve-restart.log" "$(phase_metadata_hints "docker-buildkit-restart")" "${CACHE_TAG}"
reset_builder
run_build_with_retry "fourth-build-after-restart.log" \
  --cache-from "type=registry,ref=${CACHE_REF}" \
  --cache-to "type=registry,ref=${CACHE_REF},mode=max"
assert_cached "fourth-build-after-restart.log"
assert_registry_import_succeeded "fourth-build-after-restart.log"
capture_proxy_status "phase2-restart-warm"

echo
echo "=== Phase 3: Implicit latest cache import compatibility ==="
run_build_with_retry "fifth-build-implicit-export.log" \
  --no-cache \
  --cache-to "type=registry,ref=${CACHE_REF_IMPLICIT},mode=max"
reset_builder
run_build_with_retry "sixth-build-implicit-warm.log" \
  --cache-from "type=registry,ref=${CACHE_REF_IMPLICIT}" \
  --cache-to "type=registry,ref=${CACHE_REF_IMPLICIT},mode=max"
assert_cached "sixth-build-implicit-warm.log"
assert_registry_import_succeeded "sixth-build-implicit-warm.log"
assert_import_reference_seen "sixth-build-implicit-warm.log" "${CACHE_REF_IMPLICIT}"
capture_proxy_status "phase3-implicit-warm"

echo
echo "=== Phase 4: Alias publish and alias warm import ==="
run_build_with_retry "seventh-build-alias-export.log" \
  --cache-from "type=registry,ref=${CACHE_REF}" \
  --cache-to "type=registry,ref=${CACHE_REF_ALIAS},mode=max"
assert_registry_import_succeeded "seventh-build-alias-export.log"
run_build_with_retry "eighth-build-alias-warm.log" \
  --cache-from "type=registry,ref=${CACHE_REF_ALIAS}" \
  --cache-to "type=registry,ref=${CACHE_REF_ALIAS},mode=max"
assert_cached "eighth-build-alias-warm.log"
assert_registry_import_succeeded "eighth-build-alias-warm.log"
capture_proxy_status "phase4-alias-warm"

for tag in "${CACHE_TAG}" "latest" "${CACHE_TAG_ALIAS}"; do
  manifest_file="manifest-${tag}.json"
  LOG_FILES+=("${manifest_file}")
  fetch_manifest_with_retry "${tag}" "${manifest_file}"
  manifest_digest="$(resolve_manifest_digest_with_retry "${tag}")"
  digest_manifest_file="manifest-${tag}-digest.json"
  LOG_FILES+=("${digest_manifest_file}")
  fetch_manifest_with_retry "${manifest_digest}" "${digest_manifest_file}"
done

declare -a BAD_PATTERNS=(
  'expected sha256:.*got sha256:e3b0'
  'error writing layer blob'
  'broken pipe'
  'Validation failed on cache confirm'
  '422 Unprocessable Entity'
  'unexpected status from PUT request.*400 Bad Request'
)
for pattern in "${BAD_PATTERNS[@]}"; do
  if grep -E -n "${pattern}" "${LOG_FILES[@]}" >/tmp/e2e-pattern-hit.log 2>/dev/null; then
    echo "found bad signature pattern: ${pattern}"
    cat /tmp/e2e-pattern-hit.log
    exit 1
  fi
done

echo
echo "Docker buildkit registry e2e passed"
