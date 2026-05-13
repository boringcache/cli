#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../e2e-auth.sh"
source "${SCRIPT_DIR}/../e2e-helpers.sh"

CLI_REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BINARY="${BINARY:-${CLI_REPO_ROOT}/target/debug/boringcache}"
WORKSPACE="${WORKSPACE:?WORKSPACE is required}"
LOG_DIR="${LOG_DIR:-.}"
PROXY_PORT="${PROXY_PORT:-5050}"
API_URL="${BORINGCACHE_API_URL:-https://api.boringcache.com}"
RUN_ID="${GITHUB_RUN_ID:-local}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}"
CACHE_TAG="${E2E_TAG_PREFIX:-gha-cache-registry}-oci-contract-${RUN_ID}-${RUN_ATTEMPT}"
MANIFEST_REF="${MANIFEST_REF:-${CACHE_TAG}}"
OCI_NAME="boringcache-e2e/oci-contract-${RUN_ID}-${RUN_ATTEMPT}"
ARTIFACT_TYPE="application/vnd.example.cache-marker.v1"
VISIBILITY_ATTEMPTS="${OCI_CONTRACT_VISIBILITY_ATTEMPTS:-6}"
VISIBILITY_SLEEP_SECS="${OCI_CONTRACT_VISIBILITY_SLEEP_SECS:-2}"
PROXY_LOG="${LOG_DIR}/proxy.log"
PROXY_RESTART_LOG="${LOG_DIR}/proxy-restart.log"
MANIFEST_FILE="${LOG_DIR}/manifest.json"
PUT_HEADERS="${LOG_DIR}/put.headers"
PUT_BODY="${LOG_DIR}/put.body"
GET_HEADERS="${LOG_DIR}/manifest-get.headers"
GET_BODY="${LOG_DIR}/manifest-get.body"
RESTART_GET_HEADERS="${LOG_DIR}/manifest-restart.headers"
RESTART_GET_BODY="${LOG_DIR}/manifest-restart.body"

mkdir -p "${LOG_DIR}"
setup_e2e_traps "${BINARY}" "${WORKSPACE}"
require_save_capable_token
bootstrap_cli_session "${BINARY}" "${WORKSPACE}" "${API_URL}" "${LOG_DIR}/auth.log" admin

cat >"${MANIFEST_FILE}" <<EOF
{"schemaVersion":2,"mediaType":"application/vnd.oci.artifact.manifest.v1+json","artifactType":"${ARTIFACT_TYPE}","blobs":[],"annotations":{"org.example.kind":"cache-marker","org.example.run":"${RUN_ID}-${RUN_ATTEMPT}"}}
EOF

MANIFEST_DIGEST="sha256:$(sha256_file_hex "${MANIFEST_FILE}")"

assert_status() {
  local headers="$1"
  local expected="$2"
  if ! grep -Eq "^HTTP/.* ${expected} " "${headers}"; then
    echo "ASSERT FAILED: expected HTTP ${expected}"
    cat "${headers}"
    exit 1
  fi
}

curl_get_with_status_retry() {
  local headers="$1"
  local body="$2"
  local expected="$3"
  local url="$4"
  local attempts="${5:-${VISIBILITY_ATTEMPTS}}"
  local sleep_secs="${6:-${VISIBILITY_SLEEP_SECS}}"
  local attempt

  for attempt in $(seq 1 "$attempts"); do
    if curl -sS -D "${headers}" -o "${body}" "${url}" \
      && grep -Eq "^HTTP/.* ${expected} " "${headers}"; then
      return 0
    fi

    if (( attempt < attempts )); then
      echo "WARNING: expected HTTP ${expected} from ${url} (attempt ${attempt}/${attempts}); retrying in ${sleep_secs}s"
      cat "${headers}" || true
      sleep "${sleep_secs}"
    fi
  done

  assert_status "${headers}" "${expected}"
}

assert_header() {
  local headers="$1"
  local name="$2"
  local expected="$3"
  if ! grep -Fqi -- "${name}: ${expected}" "${headers}"; then
    echo "ASSERT FAILED: expected header ${name}: ${expected}"
    cat "${headers}"
    exit 1
  fi
}

echo "=== Phase 1: Push human-tagged manifest and verify by tag ==="
start_proxy "${BINARY}" "${WORKSPACE}" "${CACHE_TAG}" "${PROXY_PORT}" "${PROXY_LOG}" "--fail-on-cache-error"
wait_for_proxy "${PROXY_PORT}"

curl -sS -D "${PUT_HEADERS}" -o "${PUT_BODY}" \
  -X PUT \
  -H "Content-Type: application/vnd.oci.artifact.manifest.v1+json" \
  --data-binary "@${MANIFEST_FILE}" \
  "http://${PROXY_HOST}:${PROXY_PORT}/v2/${OCI_NAME}/manifests/${MANIFEST_REF}"
assert_status "${PUT_HEADERS}" 201
assert_header "${PUT_HEADERS}" "Docker-Distribution-API-Version" "registry/2.0"
assert_header "${PUT_HEADERS}" "Docker-Content-Digest" "${MANIFEST_DIGEST}"
if [[ -s "${PUT_BODY}" ]]; then
  echo "ASSERT FAILED: manifest PUT response body should be empty"
  cat "${PUT_BODY}"
  exit 1
fi

curl -sS -D "${GET_HEADERS}" -o "${GET_BODY}" \
  "http://${PROXY_HOST}:${PROXY_PORT}/v2/${OCI_NAME}/manifests/${MANIFEST_REF}"
assert_status "${GET_HEADERS}" 200
assert_header "${GET_HEADERS}" "Content-Type" "application/vnd.oci.artifact.manifest.v1+json"
assert_header "${GET_HEADERS}" "Docker-Content-Digest" "${MANIFEST_DIGEST}"
cmp -s "${MANIFEST_FILE}" "${GET_BODY}"

echo "=== Phase 2: Restart proxy and verify human tag restore ==="
stop_proxy
echo "Waiting for human cache tag ${CACHE_TAG} before restart"
if ! verify_remote_tag_visible \
  "${BINARY}" \
  "${WORKSPACE}" \
  "${CACHE_TAG}" \
  "${LOG_DIR}/publish-check-human-tag" \
  1 \
  "${VISIBILITY_ATTEMPTS}" \
  "${VISIBILITY_SLEEP_SECS}" \
  "${PROXY_LOG}"; then
  exit 1
fi
start_proxy "${BINARY}" "${WORKSPACE}" "${CACHE_TAG}" "${PROXY_PORT}" "${PROXY_RESTART_LOG}" "--fail-on-cache-error"
wait_for_proxy "${PROXY_PORT}"

curl_get_with_status_retry \
  "${RESTART_GET_HEADERS}" \
  "${RESTART_GET_BODY}" \
  200 \
  "http://${PROXY_HOST}:${PROXY_PORT}/v2/${OCI_NAME}/manifests/${MANIFEST_REF}"
assert_header "${RESTART_GET_HEADERS}" "Content-Type" "application/vnd.oci.artifact.manifest.v1+json"
assert_header "${RESTART_GET_HEADERS}" "Docker-Content-Digest" "${MANIFEST_DIGEST}"
cmp -s "${MANIFEST_FILE}" "${RESTART_GET_BODY}"

echo "OCI manifest contract e2e passed"
