#!/usr/bin/env bash
set -euo pipefail

REQUIRED_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${REQUIRED_SCRIPT_DIR}/../e2e-auth.sh"
source "${REQUIRED_SCRIPT_DIR}/../e2e-helpers.sh"
source "${REQUIRED_SCRIPT_DIR}/../e2e-remote-tag.sh"

BINARY="${BINARY:?BINARY is required}"
WORKSPACE="${WORKSPACE:-${GITHUB_REPOSITORY:-}}"
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-5330}"
PROXY_READY_TIMEOUT_SECS="${PROXY_READY_TIMEOUT_SECS:-90}"
PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_SECS:-210}"
LOG_DIR="${LOG_DIR:-.}"
OCI_NAME="${OCI_NAME:-cache}"
RUN_ID="${GITHUB_RUN_ID:-${BORINGCACHE_E2E_RUN_ID:-local}}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-${BORINGCACHE_E2E_RUN_ATTEMPT:-1}}"
TAG_A="${TAG_A:-gha-oci-human-tag-a-${RUN_ID}-${RUN_ATTEMPT}}"
TAG_B="${TAG_B:-gha-oci-human-tag-b-${RUN_ID}-${RUN_ATTEMPT}}"

WORK_DIR="$(mktemp -d)"
mkdir -p "${LOG_DIR}"

cleanup() {
  set +e
  stop_proxy
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

if [[ -z "${WORKSPACE}" ]]; then
  echo "ERROR: WORKSPACE or GITHUB_REPOSITORY is required"
  exit 1
fi

if [[ "${TAG_A}" == "${TAG_B}" ]]; then
  echo "ERROR: TAG_A and TAG_B must be distinct"
  exit 1
fi

require_save_capable_token
export_resolved_cli_tokens admin

sha256_file_hex() {
  local file_path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file_path}" | awk '{print $1}'
  else
    shasum -a 256 "${file_path}" | awk '{print $1}'
  fi
}

assert_status() {
  local headers="$1"
  local expected="$2"
  if ! grep -Eq "^HTTP/.* ${expected} " "${headers}"; then
    echo "ASSERT FAILED: expected HTTP ${expected}"
    cat "${headers}" || true
    exit 1
  fi
}

make_payload_and_manifest() {
  local label="$1"
  local payload_file="${WORK_DIR}/${label}.txt"
  local manifest_file="${WORK_DIR}/${label}-manifest.json"
  local digest size

  printf 'human-tag-oci %s\n' "${label}" >"${payload_file}"
  digest="sha256:$(sha256_file_hex "${payload_file}")"
  size="$(wc -c <"${payload_file}" | tr -d ' ')"

  cat >"${manifest_file}" <<JSON
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.boringcache.e2e.config.v1+json","digest":"${digest}","size":${size}},"layers":[],"annotations":{"org.boringcache.e2e":"human-tag-restore-isolation","org.boringcache.e2e.label":"${label}"}}
JSON
}

publish_manifest() {
  local label="$1"
  local reference="$2"
  local payload_file="${WORK_DIR}/${label}.txt"
  local manifest_file="${WORK_DIR}/${label}-manifest.json"
  local blob_headers="${LOG_DIR}/${label}-blob.headers"
  local manifest_headers="${LOG_DIR}/${label}-manifest.headers"

  make_payload_and_manifest "${label}"

  curl -sS -D "${blob_headers}" -o /dev/null \
    -X POST \
    --data-binary "@${payload_file}" \
    "http://${PROXY_HOST}:${PROXY_PORT}/v2/${OCI_NAME}/blobs/uploads/?digest=sha256:$(sha256_file_hex "${payload_file}")"
  assert_status "${blob_headers}" 201

  curl -sS -D "${manifest_headers}" -o /dev/null \
    -X PUT \
    -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
    --data-binary "@${manifest_file}" \
    "http://${PROXY_HOST}:${PROXY_PORT}/v2/${OCI_NAME}/manifests/${reference}"
  assert_status "${manifest_headers}" 201
}

fetch_manifest() {
  local reference="$1"
  local expected_status="$2"
  local output_file="$3"
  local headers_file="$4"

  curl -sS -D "${headers_file}" -o "${output_file}" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json" \
    "http://${PROXY_HOST}:${PROXY_PORT}/v2/${OCI_NAME}/manifests/${reference}"
  assert_status "${headers_file}" "${expected_status}"
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

echo "=== OCI human-tag restore isolation E2E ==="
echo "Workspace: ${WORKSPACE}"
echo "Tag A: ${TAG_A}"
echo "Tag B: ${TAG_B}"
echo "OCI name: ${OCI_NAME}"

echo
echo "=== Phase 1: publish manifest under human tag B ==="
start_proxy "${BINARY}" "${WORKSPACE}" "${TAG_B}" "${PROXY_PORT}" "${LOG_DIR}/proxy-tag-b.log" "--fail-on-cache-error"
wait_for_proxy "${PROXY_PORT}"
publish_manifest "tag-b" "${TAG_B}"
stop_proxy

verify_remote_tag_visible \
  "${BINARY}" \
  "${WORKSPACE}" \
  "${TAG_B}" \
  "${LOG_DIR}/tag-b-publish-check" \
  1 \
  "${REMOTE_TAG_VERIFY_ATTEMPTS}" \
  "${REMOTE_TAG_VERIFY_SLEEP_SECS}" \
  "${LOG_DIR}/proxy-tag-b.log"

echo
echo "=== Phase 2: fresh proxy misses distinct human tag A ==="
start_proxy "${BINARY}" "${WORKSPACE}" "${TAG_A}" "${PROXY_PORT}" "${LOG_DIR}/proxy-tag-a-miss.log" "--read-only --fail-on-cache-error"
wait_for_proxy "${PROXY_PORT}"
fetch_manifest "${TAG_A}" 404 "${WORK_DIR}/tag-a-miss.json" "${LOG_DIR}/tag-a-miss.headers"
stop_proxy

echo
echo "=== Phase 3: publish manifest under human tag A ==="
start_proxy "${BINARY}" "${WORKSPACE}" "${TAG_A}" "${PROXY_PORT}" "${LOG_DIR}/proxy-tag-a.log" "--fail-on-cache-error"
wait_for_proxy "${PROXY_PORT}"
publish_manifest "tag-a" "${TAG_A}"
stop_proxy

verify_remote_tag_visible \
  "${BINARY}" \
  "${WORKSPACE}" \
  "${TAG_A}" \
  "${LOG_DIR}/tag-a-publish-check" \
  1 \
  "${REMOTE_TAG_VERIFY_ATTEMPTS}" \
  "${REMOTE_TAG_VERIFY_SLEEP_SECS}" \
  "${LOG_DIR}/proxy-tag-a.log"

echo
echo "=== Phase 4: fresh proxy restores both human tags by requested ref ==="
start_proxy "${BINARY}" "${WORKSPACE}" "${TAG_A}" "${PROXY_PORT}" "${LOG_DIR}/proxy-readback.log" "--read-only --fail-on-cache-error"
wait_for_proxy "${PROXY_PORT}"
fetch_manifest "${TAG_A}" 200 "${WORK_DIR}/tag-a-readback.json" "${LOG_DIR}/tag-a-readback.headers"
fetch_manifest "${TAG_B}" 200 "${WORK_DIR}/tag-b-readback.json" "${LOG_DIR}/tag-b-readback.headers"
assert_same_file "${WORK_DIR}/tag-a-manifest.json" "${WORK_DIR}/tag-a-readback.json" "tag A restore"
assert_same_file "${WORK_DIR}/tag-b-manifest.json" "${WORK_DIR}/tag-b-readback.json" "tag B restore"
stop_proxy

echo
echo "OCI human-tag restore isolation e2e passed"
