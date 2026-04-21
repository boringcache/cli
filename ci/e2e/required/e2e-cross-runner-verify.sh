#!/usr/bin/env bash
set -euo pipefail

BINARY="${BINARY:?BINARY is required}"
WORKSPACE="${WORKSPACE:-${GITHUB_REPOSITORY:-}}"
TAG="${TAG:?TAG is required}"
CAS_DIGEST="${CAS_DIGEST:?CAS_DIGEST is required}"
AC_DIGEST="${AC_DIGEST:?AC_DIGEST is required}"
PROXY_PORT="${PROXY_PORT:-5050}"
WORK_DIR="$(mktemp -d)"
PROXY_URL="http://127.0.0.1:${PROXY_PORT}"
PROXY_STATUS_PATH="${PROXY_STATUS_PATH:-/_boringcache/status}"
PROXY_LOG="${WORK_DIR}/proxy.log"
PROXY_PID=""
PROXY_READY_FILE="${WORK_DIR}/proxy.ready"

cleanup() {
  set +e
  if [[ -n "${PROXY_PID}" ]]; then
    kill "${PROXY_PID}" >/dev/null 2>&1 || true
    wait "${PROXY_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

proxy_status_probe() {
  local response status phase publish_state
  response="$(
    curl -sS -D - -o /dev/null \
      --max-time 2 \
      "${PROXY_URL}${PROXY_STATUS_PATH}" 2>/dev/null || true
  )"
  status="$(printf '%s\n' "$response" | awk 'tolower($1) ~ /^http\// { status = $2 } END { print status }')"
  phase="$(printf '%s\n' "$response" | awk -F': ' 'tolower($1) == "x-boringcache-proxy-phase" { gsub("\\r", "", $2); phase = tolower($2) } END { print phase }')"
  publish_state="$(printf '%s\n' "$response" | awk -F': ' 'tolower($1) == "x-boringcache-publish-state" { gsub("\\r", "", $2); publish = tolower($2) } END { print publish }')"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf '%s %s %s' "$status" "${phase:-unknown}" "${publish_state:-unknown}"
}

wait_for_proxy_ready() {
  for _ in $(seq 1 30); do
    if [[ -f "${PROXY_READY_FILE}" ]]; then
      return 0
    fi
    if ! kill -0 "${PROXY_PID}" 2>/dev/null; then
      echo "ERROR: proxy exited during startup"
      cat "${PROXY_LOG}"
      exit 1
    fi
    sleep 1
  done
  echo "ERROR: proxy did not become ready"
  cat "${PROXY_LOG}"
  exit 1
}

fetch_and_verify_blob() {
  local label="$1"
  local path="$2"
  local expected_digest="$3"
  local output_path="$4"
  local status actual

  rm -f "${output_path}"
  status="$(
    curl -sS --max-time 30 -o "${output_path}" -w "%{http_code}" "${PROXY_URL}${path}" \
      || printf '000'
  )"
  if [[ "${status}" != "200" ]]; then
    echo "ERROR: ${label} GET returned ${status} on first fresh-reader attempt (expected 200)"
    tail -n 80 "${PROXY_LOG}"
    exit 1
  fi

  actual="$(sha256sum "${output_path}" | awk '{print $1}')"
  if [[ "${actual}" != "${expected_digest}" ]]; then
    echo "ERROR: ${label} content mismatch (expected=${expected_digest} actual=${actual})"
    exit 1
  fi
  echo "${label} blob verified: digest matches"
}

for dep in cmp curl sha256sum; do
  if ! command -v "${dep}" >/dev/null 2>&1; then
    echo "ERROR: required dependency not found: ${dep}"
    exit 1
  fi
done

if [[ -z "${WORKSPACE}" ]]; then
  echo "ERROR: WORKSPACE or GITHUB_REPOSITORY is required"
  exit 1
fi

unset BORINGCACHE_API_TOKEN

RUST_LOG=info "${BINARY}" cache-registry "${WORKSPACE}" "${TAG}" \
  --read-only \
  --host 127.0.0.1 \
  --port "${PROXY_PORT}" \
  --ready-file "${PROXY_READY_FILE}" \
  --no-platform \
  --no-git \
  >>"${PROXY_LOG}" 2>&1 &
PROXY_PID=$!
wait_for_proxy_ready

echo "Proxy ready on fresh runner, verifying CAS blobs..."
fetch_and_verify_blob "CAS" "/cas/${CAS_DIGEST}" "${CAS_DIGEST}" "${WORK_DIR}/cas-restored.bin"
fetch_and_verify_blob "AC" "/ac/${AC_DIGEST}" "${AC_DIGEST}" "${WORK_DIR}/ac-restored.bin"

echo "Cross-runner CAS persistence verified"
