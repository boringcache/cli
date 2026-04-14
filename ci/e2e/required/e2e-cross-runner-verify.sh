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
PROXY_LOG="${WORK_DIR}/proxy.log"
PROXY_PID=""
PROXY_READY=0

cleanup() {
  set +e
  if [[ -n "${PROXY_PID}" ]]; then
    kill "${PROXY_PID}" >/dev/null 2>&1 || true
    wait "${PROXY_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

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
  --no-platform \
  --no-git \
  >>"${PROXY_LOG}" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 30); do
  if curl -fsS --max-time 2 "${PROXY_URL}/v2/" >/dev/null 2>&1; then
    PROXY_READY=1
    break
  fi
  if ! kill -0 "${PROXY_PID}" 2>/dev/null; then
    echo "ERROR: proxy exited during startup"
    cat "${PROXY_LOG}"
    exit 1
  fi
  sleep 1
done

if [[ "${PROXY_READY}" != "1" ]]; then
  echo "ERROR: proxy did not become ready"
  cat "${PROXY_LOG}"
  exit 1
fi

echo "Proxy ready on fresh runner, verifying CAS blobs..."
CAS_STATUS="$(curl -sS --max-time 30 -o "${WORK_DIR}/cas-restored.bin" -w "%{http_code}" "${PROXY_URL}/cas/${CAS_DIGEST}")"
if [[ "${CAS_STATUS}" != "200" ]]; then
  echo "ERROR: CAS GET returned ${CAS_STATUS} (expected 200)"
  tail -n 60 "${PROXY_LOG}"
  exit 1
fi
CAS_ACTUAL="$(sha256sum "${WORK_DIR}/cas-restored.bin" | awk '{print $1}')"
if [[ "${CAS_ACTUAL}" != "${CAS_DIGEST}" ]]; then
  echo "ERROR: CAS content mismatch (expected=${CAS_DIGEST} actual=${CAS_ACTUAL})"
  exit 1
fi
echo "CAS blob verified: digest matches"

AC_STATUS="$(curl -sS --max-time 30 -o "${WORK_DIR}/ac-restored.bin" -w "%{http_code}" "${PROXY_URL}/ac/${AC_DIGEST}")"
if [[ "${AC_STATUS}" != "200" ]]; then
  echo "ERROR: AC GET returned ${AC_STATUS} (expected 200)"
  tail -n 60 "${PROXY_LOG}"
  exit 1
fi
AC_ACTUAL="$(sha256sum "${WORK_DIR}/ac-restored.bin" | awk '{print $1}')"
if [[ "${AC_ACTUAL}" != "${AC_DIGEST}" ]]; then
  echo "ERROR: AC content mismatch (expected=${AC_DIGEST} actual=${AC_ACTUAL})"
  exit 1
fi
echo "AC blob verified: digest matches"

echo "Cross-runner CAS persistence verified"
