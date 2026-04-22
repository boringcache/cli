#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../e2e-auth.sh"

BINARY="${BINARY:?BINARY is required}"
WORKSPACE="${WORKSPACE:-${GITHUB_REPOSITORY:-}}"
TAG="${TAG:-}"
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-5000}"
PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"
PROXY_STATUS_PATH="${PROXY_STATUS_PATH:-/_boringcache/status}"
PROXY_READY_TIMEOUT_SECS="${PROXY_READY_TIMEOUT_SECS:-90}"
PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_SECS:-210}"
LOG_DIR="${LOG_DIR:-.}"
ALIAS_REF="${ALIAS_REF:-branch-main}"
RUN_ID="${GITHUB_RUN_ID:-${BORINGCACHE_E2E_RUN_ID:-local}}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-${BORINGCACHE_E2E_RUN_ATTEMPT:-1}}"
RUN_A_REF="${RUN_A_REF:-run-a-${RUN_ID}-${RUN_ATTEMPT}}"
RUN_B_REF="${RUN_B_REF:-run-b-${RUN_ID}-${RUN_ATTEMPT}}"
RUN_A_STARTED_AT="${RUN_A_STARTED_AT:-2026-04-21T10:00:00Z}"
RUN_B_STARTED_AT="${RUN_B_STARTED_AT:-2026-04-21T10:05:00Z}"

WORK_DIR="$(mktemp -d)"
PROXY_PID=""
PROXY_READY_FILE=""
PROXY_LOG=""
PROXY_METRICS=""

mkdir -p "${LOG_DIR}"

if [[ -z "${WORKSPACE}" ]]; then
  echo "ERROR: WORKSPACE or GITHUB_REPOSITORY is required"
  exit 1
fi

if [[ -z "${TAG}" ]]; then
  TAG="gha-oci-same-alias-${RUN_ID}-${RUN_ATTEMPT}"
fi

sha256_file_hex() {
  local file_path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file_path}" | awk '{print $1}'
  else
    shasum -a 256 "${file_path}" | awk '{print $1}'
  fi
}

dump_logs() {
  set +e
  echo "=== OCI same-alias E2E debug logs ==="
  find "${LOG_DIR}" -maxdepth 1 -type f \( -name '*.log' -o -name '*.env' -o -name '*.headers' \) -print \
    | sort \
    | while IFS= read -r file; do
        echo "--- ${file} ---"
        tail -n 120 "${file}" || true
      done
  echo "=== End OCI same-alias E2E debug logs ==="
}

stop_proxy() {
  if [[ -z "${PROXY_PID:-}" ]]; then
    return 0
  fi

  if kill -0 "${PROXY_PID}" >/dev/null 2>&1; then
    kill "${PROXY_PID}" >/dev/null 2>&1 || true
    local deadline=$((SECONDS + PROXY_SHUTDOWN_WAIT_SECS))
    while kill -0 "${PROXY_PID}" >/dev/null 2>&1; do
      if (( SECONDS >= deadline )); then
        echo "WARNING: proxy ${PROXY_PID} did not exit after ${PROXY_SHUTDOWN_WAIT_SECS}s, sending SIGKILL"
        kill -9 "${PROXY_PID}" >/dev/null 2>&1 || true
        break
      fi
      sleep 1
    done
  fi

  wait "${PROXY_PID}" >/dev/null 2>&1 || true
  PROXY_PID=""
  rm -f "${PROXY_READY_FILE:-}" >/dev/null 2>&1 || true
  PROXY_READY_FILE=""
}

cleanup() {
  set +e
  stop_proxy
  rm -rf "${WORK_DIR}"
}
trap dump_logs ERR
trap cleanup EXIT

wait_for_proxy_ready() {
  local attempts="${PROXY_READY_TIMEOUT_SECS}"
  for _ in $(seq 1 "${attempts}"); do
    if [[ -f "${PROXY_READY_FILE}" ]]; then
      return 0
    fi
    if ! kill -0 "${PROXY_PID}" >/dev/null 2>&1; then
      echo "ERROR: proxy exited during startup"
      tail -n 120 "${PROXY_LOG}" || true
      exit 1
    fi
    sleep 1
  done

  echo "ERROR: proxy did not become ready"
  tail -n 120 "${PROXY_LOG}" || true
  exit 1
}

start_proxy() {
  local label="$1"
  local run_uid="$2"
  local run_started_at="$3"
  local read_only="${4:-false}"

  stop_proxy
  PROXY_LOG="${LOG_DIR}/proxy-${label}.log"
  PROXY_METRICS="${LOG_DIR}/metrics-${label}.jsonl"
  PROXY_READY_FILE="$(mktemp "${LOG_DIR}/proxy-ready-${label}.XXXXXX")"
  rm -f "${PROXY_READY_FILE}"

  local -a proxy_cmd=(
    "${BINARY}" cache-registry "${WORKSPACE}" "${TAG}"
    --host "${PROXY_HOST}"
    --port "${PROXY_PORT}"
    --ready-file "${PROXY_READY_FILE}"
    --no-platform
    --no-git
    --on-demand
    --oci-alias-promotion-ref "${ALIAS_REF}"
    --metadata-hint "phase=${label}"
    --metadata-hint "ci_provider=boringcache-e2e"
    --metadata-hint "ci_run_uid=${run_uid}"
    --metadata-hint "ci_run_attempt=1"
    --metadata-hint "ci_ref_type=branch"
    --metadata-hint "ci_ref_name=main"
    --metadata-hint "ci_default_branch=main"
    --metadata-hint "ci_run_started_at=${run_started_at}"
  )
  if [[ "${read_only}" == "true" ]]; then
    proxy_cmd+=(--read-only)
  else
    proxy_cmd+=(--fail-on-cache-error)
  fi

  RUST_LOG="${RUST_LOG:-info}" \
  BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
  BORINGCACHE_OBSERVABILITY_JSONL_PATH="${PROXY_METRICS}" \
    "${proxy_cmd[@]}" >"${PROXY_LOG}" 2>&1 &
  PROXY_PID=$!
  wait_for_proxy_ready
}

write_manifest() {
  local run_ref="$1"
  local payload_file="$2"
  local manifest_file="$3"

  python3 - "${run_ref}" "${payload_file}" "${manifest_file}" <<'PY'
import hashlib
import json
import pathlib
import sys

run_ref, payload_path, manifest_path = sys.argv[1:]
payload = pathlib.Path(payload_path).read_bytes()
digest = "sha256:" + hashlib.sha256(payload).hexdigest()
manifest = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {
        "mediaType": "application/vnd.oci.empty.v1+json",
        "digest": digest,
        "size": len(payload),
    },
    "layers": [],
    "annotations": {
        "org.opencontainers.image.ref.name": run_ref,
        "org.boringcache.e2e": "same-alias-writer",
    },
}
pathlib.Path(manifest_path).write_bytes(
    json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
)
print(digest)
PY
}

http_request() {
  local method="$1"
  local url="$2"
  local body_file="$3"
  local output_file="$4"
  local headers_file="$5"
  shift 5

  local -a curl_args=(-sS -D "${headers_file}" -o "${output_file}" -w "%{http_code}" -X "${method}")
  if [[ -n "${body_file}" ]]; then
    curl_args+=(--data-binary "@${body_file}")
  fi
  curl_args+=("$@" "${url}")
  curl "${curl_args[@]}"
}

assert_status() {
  local status="$1"
  local expected="$2"
  local label="$3"
  local headers_file="$4"
  local body_file="$5"

  if [[ "${status}" != "${expected}" ]]; then
    echo "ERROR: ${label} returned ${status}; expected ${expected}"
    cat "${headers_file}" || true
    cat "${body_file}" || true
    tail -n 120 "${PROXY_LOG}" || true
    exit 1
  fi
}

publish_run_ref() {
  local label="$1"
  local run_ref="$2"
  local run_started_at="$3"
  local payload_file="${WORK_DIR}/${label}-payload.bin"
  local manifest_file="${WORK_DIR}/${label}-manifest.json"
  local headers_file="${LOG_DIR}/${label}.headers"
  local body_file="${WORK_DIR}/${label}.body"
  local blob_digest manifest_digest status

  printf 'same-alias %s %s\n' "${label}" "${run_ref}" >"${payload_file}"
  blob_digest="$(write_manifest "${run_ref}" "${payload_file}" "${manifest_file}")"
  manifest_digest="sha256:$(sha256_file_hex "${manifest_file}")"
  printf '%s\n' "${manifest_digest}" >"${WORK_DIR}/${label}-manifest.digest"

  start_proxy "${label}" "${label}" "${run_started_at}" false

  status="$(
    http_request \
      POST \
      "${PROXY_URL}/v2/cache/blobs/uploads/?digest=${blob_digest}" \
      "${payload_file}" \
      "${body_file}" \
      "${headers_file}"
  )"
  assert_status "${status}" "201" "${label} blob upload" "${headers_file}" "${body_file}"

  status="$(
    http_request \
      PUT \
      "${PROXY_URL}/v2/cache/manifests/${run_ref}" \
      "${manifest_file}" \
      "${body_file}" \
      "${headers_file}" \
      -H "Content-Type: application/vnd.oci.image.manifest.v1+json"
  )"
  assert_status "${status}" "201" "${label} manifest publish" "${headers_file}" "${body_file}"

  local response_digest
  response_digest="$(
    awk 'tolower($1) == "docker-content-digest:" { gsub("\r", "", $2); print $2 }' "${headers_file}" | tail -n1
  )"
  if [[ "${response_digest}" != "${manifest_digest}" ]]; then
    echo "ERROR: ${label} manifest digest mismatch (expected=${manifest_digest} actual=${response_digest:-none})"
    cat "${headers_file}"
    exit 1
  fi

  stop_proxy
}

write_metrics_summary() {
  local label="$1"
  local metrics_file="${LOG_DIR}/metrics-${label}.jsonl"
  local summary_file="${LOG_DIR}/summary-${label}.env"

  if [[ ! -f "${metrics_file}" ]]; then
    echo "ERROR: missing metrics file ${metrics_file}"
    exit 1
  fi

  python3 "${SCRIPT_DIR}/../request-metrics-summary.py" "${metrics_file}" >"${summary_file}"
}

summary_value() {
  local summary_file="$1"
  local key="$2"
  awk -F= -v key="${key}" '$1 == key { print $2 }' "${summary_file}" | tail -n1
}

assert_summary_positive() {
  local summary_file="$1"
  local key="$2"
  local value
  value="$(summary_value "${summary_file}" "${key}")"
  if ! [[ "${value:-0}" =~ ^[0-9]+$ ]] || (( value <= 0 )); then
    echo "ERROR: expected ${key} > 0 in ${summary_file}; got ${value:-0}"
    cat "${summary_file}"
    exit 1
  fi
}

fetch_manifest_once() {
  local reference="$1"
  local output_file="$2"
  local headers_file="$3"
  local status

  status="$(
    http_request \
      GET \
      "${PROXY_URL}/v2/cache/manifests/${reference}" \
      "" \
      "${output_file}" \
      "${headers_file}" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"
  )"
  assert_status "${status}" "200" "manifest ${reference} fresh read" "${headers_file}" "${output_file}"
}

assert_same_file() {
  local expected="$1"
  local actual="$2"
  local label="$3"

  if ! cmp -s "${expected}" "${actual}"; then
    echo "ERROR: ${label} did not match expected manifest"
    echo "--- expected ${expected} ---"
    cat "${expected}" || true
    echo "--- actual ${actual} ---"
    cat "${actual}" || true
    exit 1
  fi
}

for dep in awk cmp curl python3; do
  if ! command -v "${dep}" >/dev/null 2>&1; then
    echo "ERROR: required dependency not found: ${dep}"
    exit 1
  fi
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  echo "ERROR: required dependency not found: sha256sum or shasum"
  exit 1
fi

require_save_capable_token
export_resolved_cli_tokens admin
unset BORINGCACHE_API_TOKEN

echo "=== OCI same-alias writer E2E ==="
echo "Workspace: ${WORKSPACE}"
echo "Tag family: ${TAG}"
echo "Run refs: older=${RUN_A_REF} newer=${RUN_B_REF}"
echo "Alias ref: ${ALIAS_REF}"

echo
echo "=== Phase 1: newer writer publishes first and promotes alias ==="
publish_run_ref "run-b" "${RUN_B_REF}" "${RUN_B_STARTED_AT}"
write_metrics_summary "run-b"
assert_summary_positive \
  "${LOG_DIR}/summary-run-b.env" \
  "request_metrics_cache_session_oci_oci_engine_alias_promotion_promoted"

echo
echo "=== Phase 2: older writer finishes second and must not replace alias ==="
publish_run_ref "run-a" "${RUN_A_REF}" "${RUN_A_STARTED_AT}"
write_metrics_summary "run-a"
assert_summary_positive \
  "${LOG_DIR}/summary-run-a.env" \
  "request_metrics_cache_session_oci_oci_engine_alias_promotion_ignored_stale"

echo
echo "=== Phase 3: fresh proxy reads both immutable refs and winning alias ==="
start_proxy "verify" "verify" "${RUN_B_STARTED_AT}" true
fetch_manifest_once "${RUN_A_REF}" "${WORK_DIR}/verify-run-a.json" "${LOG_DIR}/verify-run-a.headers"
fetch_manifest_once "${RUN_B_REF}" "${WORK_DIR}/verify-run-b.json" "${LOG_DIR}/verify-run-b.headers"
fetch_manifest_once "${ALIAS_REF}" "${WORK_DIR}/verify-alias.json" "${LOG_DIR}/verify-alias.headers"

assert_same_file "${WORK_DIR}/run-a-manifest.json" "${WORK_DIR}/verify-run-a.json" "older immutable run ref"
assert_same_file "${WORK_DIR}/run-b-manifest.json" "${WORK_DIR}/verify-run-b.json" "newer immutable run ref"
assert_same_file "${WORK_DIR}/run-b-manifest.json" "${WORK_DIR}/verify-alias.json" "same-alias winner"
stop_proxy

BAD_PATTERN_LOG="${WORK_DIR}/e2e-oci-same-alias-bad-pattern.log"
if grep -E -n 'blob unknown|MANIFEST_BLOB_UNKNOWN|unexpected status from PUT request.*400 Bad Request' "${LOG_DIR}"/*.log >"${BAD_PATTERN_LOG}" 2>/dev/null; then
  echo "ERROR: found OCI publish failure signature"
  cat "${BAD_PATTERN_LOG}"
  exit 1
fi

echo
echo "OCI same-alias writer e2e passed"
