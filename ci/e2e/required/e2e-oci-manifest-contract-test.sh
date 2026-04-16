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
REGISTRY_ROOT_TAG="${E2E_TAG_PREFIX:-gha-cache-registry}-oci-contract-${RUN_ID}-${RUN_ATTEMPT}"
OCI_NAME="boringcache-e2e/oci-contract-${RUN_ID}-${RUN_ATTEMPT}"
SUBJECT_DIGEST="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ARTIFACT_TYPE="application/vnd.example.sbom.v1"
PROXY_LOG="${LOG_DIR}/proxy.log"
PROXY_RESTART_LOG="${LOG_DIR}/proxy-restart.log"
MANIFEST_FILE="${LOG_DIR}/subject-manifest.json"
PUT_HEADERS="${LOG_DIR}/put.headers"
PUT_BODY="${LOG_DIR}/put.body"
GET_HEADERS="${LOG_DIR}/manifest-get.headers"
GET_BODY="${LOG_DIR}/manifest-get.body"
REFERRERS_HEADERS="${LOG_DIR}/referrers.headers"
REFERRERS_BODY="${LOG_DIR}/referrers.json"
FILTER_HEADERS="${LOG_DIR}/referrers-filter.headers"
FILTER_BODY="${LOG_DIR}/referrers-filter.json"
RESTART_GET_HEADERS="${LOG_DIR}/manifest-get-restart.headers"
RESTART_GET_BODY="${LOG_DIR}/manifest-get-restart.body"
RESTART_REFERRERS_HEADERS="${LOG_DIR}/referrers-restart.headers"
RESTART_REFERRERS_BODY="${LOG_DIR}/referrers-restart.json"

mkdir -p "${LOG_DIR}"
setup_e2e_traps "${BINARY}" "${WORKSPACE}"
require_save_capable_token
bootstrap_cli_session "${BINARY}" "${WORKSPACE}" "${API_URL}" "${LOG_DIR}/auth.log" admin

cat >"${MANIFEST_FILE}" <<EOF
{"schemaVersion":2,"mediaType":"application/vnd.oci.artifact.manifest.v1+json","artifactType":"${ARTIFACT_TYPE}","blobs":[],"subject":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"${SUBJECT_DIGEST}","size":123},"annotations":{"org.example.kind":"sbom"}}
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

assert_header() {
  local headers="$1"
  local name="$2"
  local expected="$3"
  if ! grep -Eiq "^${name}: ${expected}" "${headers}"; then
    echo "ASSERT FAILED: expected header ${name}: ${expected}"
    cat "${headers}"
    exit 1
  fi
}

check_referrers_body() {
  local body_file="$1"
  local expected_digest="$2"
  local expected_artifact_type="$3"
  python3 - "$body_file" "$expected_digest" "$expected_artifact_type" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)

assert payload["schemaVersion"] == 2, payload
assert payload["mediaType"] == "application/vnd.oci.image.index.v1+json", payload
manifests = payload["manifests"]
assert len(manifests) == 1, manifests
descriptor = manifests[0]
assert descriptor["digest"] == sys.argv[2], descriptor
assert descriptor["artifactType"] == sys.argv[3], descriptor
assert descriptor["annotations"]["org.example.kind"] == "sbom", descriptor
PY
}

echo "=== Phase 1: Push subject manifest and verify referrers ==="
start_proxy "${BINARY}" "${WORKSPACE}" "${REGISTRY_ROOT_TAG}" "${PROXY_PORT}" "${PROXY_LOG}" "--fail-on-cache-error"
wait_for_proxy "${PROXY_PORT}"

curl -sS -D "${PUT_HEADERS}" -o "${PUT_BODY}" \
  -X PUT \
  -H "Content-Type: application/vnd.oci.artifact.manifest.v1+json" \
  --data-binary "@${MANIFEST_FILE}" \
  "http://${PROXY_HOST}:${PROXY_PORT}/v2/${OCI_NAME}/manifests/main"
assert_status "${PUT_HEADERS}" 201
assert_header "${PUT_HEADERS}" "Docker-Distribution-API-Version" "registry/2.0"
assert_header "${PUT_HEADERS}" "OCI-Subject" "${SUBJECT_DIGEST}"
assert_header "${PUT_HEADERS}" "Docker-Content-Digest" "${MANIFEST_DIGEST}"
if [[ -s "${PUT_BODY}" ]]; then
  echo "ASSERT FAILED: manifest PUT response body should be empty"
  cat "${PUT_BODY}"
  exit 1
fi

curl -sS -D "${GET_HEADERS}" -o "${GET_BODY}" \
  "http://${PROXY_HOST}:${PROXY_PORT}/v2/${OCI_NAME}/manifests/${MANIFEST_DIGEST}"
assert_status "${GET_HEADERS}" 200
assert_header "${GET_HEADERS}" "Content-Type" "application/vnd.oci.artifact.manifest.v1+json"
cmp -s "${MANIFEST_FILE}" "${GET_BODY}"

curl -sS -D "${REFERRERS_HEADERS}" -o "${REFERRERS_BODY}" \
  "http://${PROXY_HOST}:${PROXY_PORT}/v2/${OCI_NAME}/referrers/${SUBJECT_DIGEST}"
assert_status "${REFERRERS_HEADERS}" 200
assert_header "${REFERRERS_HEADERS}" "Content-Type" "application/vnd.oci.image.index.v1+json"
check_referrers_body "${REFERRERS_BODY}" "${MANIFEST_DIGEST}" "${ARTIFACT_TYPE}"

curl -sS -D "${FILTER_HEADERS}" -o "${FILTER_BODY}" \
  "http://${PROXY_HOST}:${PROXY_PORT}/v2/${OCI_NAME}/referrers/${SUBJECT_DIGEST}?artifactType=${ARTIFACT_TYPE}"
assert_status "${FILTER_HEADERS}" 200
assert_header "${FILTER_HEADERS}" "OCI-Filters-Applied" "artifactType"
check_referrers_body "${FILTER_BODY}" "${MANIFEST_DIGEST}" "${ARTIFACT_TYPE}"

wait_for_proxy_publish_settled "${PROXY_PORT}"

echo "=== Phase 2: Restart proxy and verify persisted referrers ==="
stop_proxy
start_proxy "${BINARY}" "${WORKSPACE}" "${REGISTRY_ROOT_TAG}" "${PROXY_PORT}" "${PROXY_RESTART_LOG}" "--fail-on-cache-error"
wait_for_proxy "${PROXY_PORT}"

curl -sS -D "${RESTART_GET_HEADERS}" -o "${RESTART_GET_BODY}" \
  "http://${PROXY_HOST}:${PROXY_PORT}/v2/${OCI_NAME}/manifests/${MANIFEST_DIGEST}"
assert_status "${RESTART_GET_HEADERS}" 200
assert_header "${RESTART_GET_HEADERS}" "Content-Type" "application/vnd.oci.artifact.manifest.v1+json"
cmp -s "${MANIFEST_FILE}" "${RESTART_GET_BODY}"

curl -sS -D "${RESTART_REFERRERS_HEADERS}" -o "${RESTART_REFERRERS_BODY}" \
  "http://${PROXY_HOST}:${PROXY_PORT}/v2/${OCI_NAME}/referrers/${SUBJECT_DIGEST}"
assert_status "${RESTART_REFERRERS_HEADERS}" 200
assert_header "${RESTART_REFERRERS_HEADERS}" "Content-Type" "application/vnd.oci.image.index.v1+json"
check_referrers_body "${RESTART_REFERRERS_BODY}" "${MANIFEST_DIGEST}" "${ARTIFACT_TYPE}"

echo "OCI manifest contract e2e passed"
