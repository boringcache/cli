#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../e2e-remote-tag.sh"

BINARY="${BINARY:?BINARY is required}"
WORKSPACE="${WORKSPACE:-${GITHUB_REPOSITORY:-}}"
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

for dep in base64 cmp curl dd sha256sum; do
  if ! command -v "${dep}" >/dev/null 2>&1; then
    echo "ERROR: required dependency not found: ${dep}"
    exit 1
  fi
done

if [[ -z "${WORKSPACE}" ]]; then
  echo "ERROR: WORKSPACE or GITHUB_REPOSITORY is required"
  exit 1
fi

export_resolved_cli_tokens admin
unset BORINGCACHE_API_TOKEN

TAG="${TAG:-gha-cross-runner-cas-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}}"
CAS_PAYLOAD="${WORK_DIR}/cas-payload.bin"
AC_PAYLOAD="${WORK_DIR}/ac-payload.bin"

dd if=/dev/urandom bs=1024 count=64 2>/dev/null | base64 > "${CAS_PAYLOAD}"
CAS_DIGEST="$(sha256sum "${CAS_PAYLOAD}" | awk '{print $1}')"

printf 'cross-runner-ac-%s-%s\n' "${GITHUB_RUN_ID:-local}" "${GITHUB_RUN_ATTEMPT:-1}" > "${AC_PAYLOAD}"
AC_DIGEST="$(sha256sum "${AC_PAYLOAD}" | awk '{print $1}')"

RUST_LOG=info "${BINARY}" cache-registry "${WORKSPACE}" "${TAG}" \
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

echo "Proxy ready, writing CAS + AC blobs..."
curl -fsS --max-time 30 -X PUT --data-binary "@${CAS_PAYLOAD}" -o /dev/null -w "CAS PUT: %{http_code}\n" "${PROXY_URL}/cas/${CAS_DIGEST}"
curl -fsS --max-time 30 -X PUT --data-binary "@${AC_PAYLOAD}" -o /dev/null -w "AC PUT: %{http_code}\n" "${PROXY_URL}/ac/${AC_DIGEST}"

echo "Verifying blobs readable on same proxy..."
curl -fsS --max-time 30 -o "${WORK_DIR}/cas-verify.bin" "${PROXY_URL}/cas/${CAS_DIGEST}"
if ! cmp -s "${CAS_PAYLOAD}" "${WORK_DIR}/cas-verify.bin"; then
  echo "ERROR: CAS blob readback mismatch on seed runner"
  exit 1
fi
curl -fsS --max-time 30 -o "${WORK_DIR}/ac-verify.bin" "${PROXY_URL}/ac/${AC_DIGEST}"
if ! cmp -s "${AC_PAYLOAD}" "${WORK_DIR}/ac-verify.bin"; then
  echo "ERROR: AC blob readback mismatch on seed runner"
  exit 1
fi

echo "Flushing proxy (graceful shutdown)..."
kill "${PROXY_PID}"
wait "${PROXY_PID}" 2>/dev/null || true
PROXY_PID=""

echo "Waiting for published remote tag before handing off to fresh runner..."
verify_remote_tag_visible \
  "${BINARY}" \
  "${WORKSPACE}" \
  "${TAG}" \
  "${WORK_DIR}/publish-check" \
  1 \
  "${REMOTE_TAG_VERIFY_ATTEMPTS}" \
  "${REMOTE_TAG_VERIFY_SLEEP_SECS}" \
  "${PROXY_LOG}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "tag=${TAG}"
    echo "cas_digest=${CAS_DIGEST}"
    echo "ac_digest=${AC_DIGEST}"
  } >> "${GITHUB_OUTPUT}"
fi

echo "Seed complete: tag=${TAG} cas=${CAS_DIGEST} ac=${AC_DIGEST}"
