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
REFERRERS_TAG="${SUBJECT_DIGEST/:/-}"
ARTIFACT_TYPE="application/vnd.example.sbom.v1"
VISIBILITY_ATTEMPTS="${OCI_CONTRACT_VISIBILITY_ATTEMPTS:-6}"
VISIBILITY_SLEEP_SECS="${OCI_CONTRACT_VISIBILITY_SLEEP_SECS:-2}"
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
RESTART_REFERRERS_HEADERS="${LOG_DIR}/referrers-restart.headers"
RESTART_REFERRERS_BODY="${LOG_DIR}/referrers-restart.json"

mkdir -p "${LOG_DIR}"
setup_e2e_traps "${BINARY}" "${WORKSPACE}"
require_save_capable_token
bootstrap_cli_session "${BINARY}" "${WORKSPACE}" "${API_URL}" "${LOG_DIR}/auth.log" admin

cat >"${MANIFEST_FILE}" <<EOF
{"schemaVersion":2,"mediaType":"application/vnd.oci.artifact.manifest.v1+json","artifactType":"${ARTIFACT_TYPE}","blobs":[],"subject":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"${SUBJECT_DIGEST}","size":123},"annotations":{"org.example.kind":"sbom","org.example.run":"${RUN_ID}-${RUN_ATTEMPT}"}}
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
matches = [descriptor for descriptor in manifests if descriptor.get("digest") == sys.argv[2]]
assert len(matches) == 1, manifests
descriptor = matches[0]
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

echo "=== Phase 2: Restart proxy and verify persisted referrers ==="
stop_proxy
if ! verify_remote_tag_visible \
  "${BINARY}" \
  "${WORKSPACE}" \
  "${REFERRERS_TAG}" \
  "${LOG_DIR}/publish-check-referrers" \
  1 \
  "${VISIBILITY_ATTEMPTS}" \
  "${VISIBILITY_SLEEP_SECS}" \
  "${PROXY_LOG}"; then
  exit 1
fi
start_proxy "${BINARY}" "${WORKSPACE}" "${REGISTRY_ROOT_TAG}" "${PROXY_PORT}" "${PROXY_RESTART_LOG}" "--fail-on-cache-error"
wait_for_proxy "${PROXY_PORT}"

curl_get_with_status_retry \
  "${RESTART_REFERRERS_HEADERS}" \
  "${RESTART_REFERRERS_BODY}" \
  200 \
  "http://${PROXY_HOST}:${PROXY_PORT}/v2/${OCI_NAME}/referrers/${SUBJECT_DIGEST}"
assert_header "${RESTART_REFERRERS_HEADERS}" "Content-Type" "application/vnd.oci.image.index.v1+json"
check_referrers_body "${RESTART_REFERRERS_BODY}" "${MANIFEST_DIGEST}" "${ARTIFACT_TYPE}"

echo "OCI manifest contract e2e passed"
