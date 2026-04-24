#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../e2e-auth.sh"

BINARY="${BINARY:?BINARY is required}"
WORKSPACE="${WORKSPACE:-${GITHUB_REPOSITORY:-}}"
API_URL="${BORINGCACHE_API_URL:?BORINGCACHE_API_URL is required}"
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT_B="${PROXY_PORT_B:-5330}"
PROXY_PORT_A="${PROXY_PORT_A:-5331}"
PROXY_READY_TIMEOUT_SECS="${PROXY_READY_TIMEOUT_SECS:-90}"
PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_SECS:-210}"
LOG_DIR="${LOG_DIR:-.}"
OCI_NAME="${OCI_NAME:-cache}"
OCI_REFERENCE="${OCI_REFERENCE:-buildcache}"
RUN_ID="${GITHUB_RUN_ID:-${BORINGCACHE_E2E_RUN_ID:-local}}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-${BORINGCACHE_E2E_RUN_ATTEMPT:-1}}"
TAG_A="${TAG_A:-gha-oci-rooted-restore-a-${RUN_ID}-${RUN_ATTEMPT}}"
TAG_B="${TAG_B:-gha-oci-rooted-restore-b-${RUN_ID}-${RUN_ATTEMPT}}"

WORK_DIR="$(mktemp -d)"
declare -a PROXY_PIDS=()
declare -a PROXY_READY_FILES=()
declare -a PROXY_LOGS=()

mkdir -p "${LOG_DIR}"

if [[ -z "${WORKSPACE}" ]]; then
  echo "ERROR: WORKSPACE or GITHUB_REPOSITORY is required"
  exit 1
fi

if [[ "${TAG_A}" == "${TAG_B}" ]]; then
  echo "ERROR: TAG_A and TAG_B must be distinct"
  exit 1
fi

sha256_file_hex() {
  local file_path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file_path}" | awk '{print $1}'
  else
    shasum -a 256 "${file_path}" | awk '{print $1}'
  fi
}

sha256_string_hex() {
  local input="$1"
  python3 - "${input}" <<'PY'
import hashlib
import sys

print(hashlib.sha256(sys.argv[1].encode("utf-8")).hexdigest())
PY
}

ref_tag_for_input() {
  local input="$1"
  python3 - "${input}" <<'PY'
import hashlib
import sys

REF_TAG_PREFIX = "oci_ref_"
REF_TAG_HASH_BYTES = 16
REF_TAG_MAX_BODY_BYTES = 240

input_value = sys.argv[1]
fragment = []
fragment_len = 0
previous_was_separator = False

for ch in input_value:
    if ch.isascii() and (ch.isalnum() or ch in "-_."):
        replacement = ch
        previous_was_separator = False
    elif ch in ":/@":
        if previous_was_separator:
            continue
        replacement = "__"
        previous_was_separator = True
    else:
        if previous_was_separator:
            continue
        replacement = "_"
        previous_was_separator = True

    if fragment_len + len(replacement) > REF_TAG_MAX_BODY_BYTES:
        break
    fragment.append(replacement)
    fragment_len += len(replacement)

readable = "".join(fragment).strip("._-")
if not readable:
    readable = "ref"

digest = hashlib.sha256(input_value.encode("utf-8")).hexdigest()
print(f"{REF_TAG_PREFIX}{readable}__{digest[:REF_TAG_HASH_BYTES]}")
PY
}

legacy_ref_tag_for_input() {
  local input="$1"
  printf 'oci_ref_%s\n' "$(sha256_string_hex "${input}")"
}

registry_root_tag_for_human_tag() {
  local tag="$1"
  printf 'bc_registry_root_v2_%s\n' "$(sha256_string_hex "${tag}")"
}

urlencode() {
  local value="$1"
  python3 - "${value}" <<'PY'
import sys
import urllib.parse

print(urllib.parse.quote(sys.argv[1], safe=""))
PY
}

proxy_url() {
  local port="$1"
  printf 'http://%s:%s' "${PROXY_HOST}" "${port}"
}

api_workspace_base() {
  local namespace_slug workspace_slug
  IFS=/ read -r namespace_slug workspace_slug <<<"${WORKSPACE}"
  if [[ -z "${namespace_slug}" || -z "${workspace_slug}" ]]; then
    echo "ERROR: WORKSPACE must be namespace/workspace"
    exit 1
  fi
  printf '%s/v2/workspaces/%s/%s' \
    "${API_URL%/}" \
    "$(urlencode "${namespace_slug}")" \
    "$(urlencode "${workspace_slug}")"
}

dump_logs() {
  set +e
  echo "=== OCI rooted-restore isolation E2E debug logs ==="
  find "${LOG_DIR}" -maxdepth 1 -type f \( -name '*.log' -o -name '*.env' -o -name '*.headers' -o -name '*.json' \) -print \
    | sort \
    | while IFS= read -r file; do
        echo "--- ${file} ---"
        tail -n 120 "${file}" || true
      done
  echo "=== End OCI rooted-restore isolation E2E debug logs ==="
}

tail_proxy_logs() {
  local log_file
  for log_file in "${PROXY_LOGS[@]}"; do
    [[ -f "${log_file}" ]] || continue
    echo "--- ${log_file} ---"
    tail -n 120 "${log_file}" || true
  done
}

stop_proxy_pid() {
  local proxy_pid="$1"
  local ready_file="$2"

  if [[ -z "${proxy_pid:-}" ]]; then
    return 0
  fi

  if kill -0 "${proxy_pid}" >/dev/null 2>&1; then
    kill "${proxy_pid}" >/dev/null 2>&1 || true
    local deadline=$((SECONDS + PROXY_SHUTDOWN_WAIT_SECS))
    while kill -0 "${proxy_pid}" >/dev/null 2>&1; do
      if (( SECONDS >= deadline )); then
        echo "WARNING: proxy ${proxy_pid} did not exit after ${PROXY_SHUTDOWN_WAIT_SECS}s, sending SIGKILL"
        kill -9 "${proxy_pid}" >/dev/null 2>&1 || true
        break
      fi
      sleep 1
    done
  fi

  wait "${proxy_pid}" >/dev/null 2>&1 || true
  rm -f "${ready_file:-}" >/dev/null 2>&1 || true
}

stop_all_proxies() {
  local i
  for ((i = ${#PROXY_PIDS[@]} - 1; i >= 0; i--)); do
    stop_proxy_pid "${PROXY_PIDS[$i]}" "${PROXY_READY_FILES[$i]}"
  done
  PROXY_PIDS=()
  PROXY_READY_FILES=()
}

cleanup() {
  set +e
  stop_all_proxies
  rm -rf "${WORK_DIR}"
}
trap dump_logs ERR
trap cleanup EXIT

wait_for_proxy_ready() {
  local proxy_pid="$1"
  local ready_file="$2"
  local proxy_log="$3"
  local attempts="${PROXY_READY_TIMEOUT_SECS}"
  for _ in $(seq 1 "${attempts}"); do
    if [[ -f "${ready_file}" ]]; then
      return 0
    fi
    if ! kill -0 "${proxy_pid}" >/dev/null 2>&1; then
      echo "ERROR: proxy exited during startup"
      tail -n 120 "${proxy_log}" || true
      exit 1
    fi
    sleep 1
  done

  echo "ERROR: proxy did not become ready"
  tail -n 120 "${proxy_log}" || true
  exit 1
}

start_proxy_instance() {
  local label="$1"
  local port="$2"
  local human_tag="$3"
  local read_only="${4:-false}"
  local proxy_log="${LOG_DIR}/proxy-${label}.log"
  local proxy_metrics="${LOG_DIR}/metrics-${label}.jsonl"
  local ready_file
  ready_file="$(mktemp "${LOG_DIR}/proxy-ready-${label}.XXXXXX")"

  rm -f "${ready_file}"

  local -a proxy_cmd=(
    "${BINARY}" cache-registry "${WORKSPACE}" "${human_tag}"
    --host "${PROXY_HOST}"
    --port "${port}"
    --ready-file "${ready_file}"
    --no-platform
    --no-git
    --on-demand
    --metadata-hint "scenario=oci-rooted-restore-isolation"
    --metadata-hint "phase=${label}"
  )
  if [[ "${read_only}" == "true" ]]; then
    proxy_cmd+=(--read-only)
  else
    proxy_cmd+=(--fail-on-cache-error)
  fi

  BORINGCACHE_API_URL="${API_URL}" \
  BORINGCACHE_API_TOKEN="${ADMIN_TOKEN}" \
  BORINGCACHE_ADMIN_TOKEN="${ADMIN_TOKEN}" \
  BORINGCACHE_SAVE_TOKEN="${ADMIN_TOKEN}" \
  BORINGCACHE_RESTORE_TOKEN="${ADMIN_TOKEN}" \
  RUST_LOG="${RUST_LOG:-info}" \
  BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
  BORINGCACHE_OBSERVABILITY_JSONL_PATH="${proxy_metrics}" \
    "${proxy_cmd[@]}" >"${proxy_log}" 2>&1 &
  local proxy_pid=$!
  PROXY_PIDS+=("${proxy_pid}")
  PROXY_READY_FILES+=("${ready_file}")
  PROXY_LOGS+=("${proxy_log}")
  wait_for_proxy_ready "${proxy_pid}" "${ready_file}" "${proxy_log}"
}

write_manifest() {
  local reference="$1"
  local payload_file="$2"
  local manifest_file="$3"

  python3 - "${reference}" "${payload_file}" "${manifest_file}" <<'PY'
import hashlib
import json
import pathlib
import sys

reference, payload_path, manifest_path = sys.argv[1:]
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
        "org.opencontainers.image.ref.name": reference,
        "org.boringcache.e2e": "rooted-restore-isolation",
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

api_request() {
  local method="$1"
  local url="$2"
  local body_file="$3"
  local output_file="$4"
  local headers_file="$5"
  shift 5
  local auth_header="Authorization: Bearer ${ADMIN_TOKEN}"

  local -a curl_args=(-sS -D "${headers_file}" -o "${output_file}" -w "%{http_code}" -X "${method}" -H "${auth_header}")
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
    tail_proxy_logs
    exit 1
  fi
}

prepare_ref_manifest() {
  local label="$1"
  local reference="$2"
  local payload_file="${WORK_DIR}/${label}-payload.bin"
  local manifest_file="${WORK_DIR}/${label}-manifest.json"
  local blob_digest manifest_digest

  printf 'rooted-restore %s %s\n' "${label}" "${reference}" >"${payload_file}"
  blob_digest="$(write_manifest "${reference}" "${payload_file}" "${manifest_file}")"
  printf '%s\n' "${blob_digest}" >"${WORK_DIR}/${label}-blob.digest"
  manifest_digest="sha256:$(sha256_file_hex "${manifest_file}")"
  printf '%s\n' "${manifest_digest}" >"${WORK_DIR}/${label}-manifest.digest"
}

upload_blob_for_ref() {
  local label="$1"
  local proxy_url="$2"
  local payload_file="${WORK_DIR}/${label}-payload.bin"
  local headers_file="${LOG_DIR}/${label}-blob.headers"
  local body_file="${WORK_DIR}/${label}-blob.body"
  local blob_digest status

  blob_digest="$(cat "${WORK_DIR}/${label}-blob.digest")"

  status="$(
    http_request \
      POST \
      "${proxy_url}/v2/${OCI_NAME}/blobs/uploads/?digest=${blob_digest}" \
      "${payload_file}" \
      "${body_file}" \
      "${headers_file}"
  )"
  assert_status "${status}" "201" "${label} blob upload" "${headers_file}" "${body_file}"
}

publish_manifest_for_ref() {
  local label="$1"
  local proxy_url="$2"
  local reference="$3"
  local manifest_file="${WORK_DIR}/${label}-manifest.json"
  local headers_file="${LOG_DIR}/${label}-manifest.headers"
  local body_file="${WORK_DIR}/${label}-manifest.body"
  local manifest_digest status

  manifest_digest="$(cat "${WORK_DIR}/${label}-manifest.digest")"

  status="$(
    http_request \
      PUT \
      "${proxy_url}/v2/${OCI_NAME}/manifests/${reference}" \
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
}

cache_entry_id_for_tag() {
  local tag="$1"
  local safe_tag
  safe_tag="$(echo "${tag}" | tr -c '[:alnum:]' '-')"
  local url
  local output_file="${WORK_DIR}/restore-${safe_tag}.json"
  local headers_file="${LOG_DIR}/restore-${safe_tag}.headers"
  local encoded_entries
  encoded_entries="$(urlencode "${tag}")"
  url="$(api_workspace_base)/caches?entries=${encoded_entries}"

  local status
  status="$(
    api_request \
      GET \
      "${url}" \
      "" \
      "${output_file}" \
      "${headers_file}"
  )"
  if [[ "${status}" != "200" && "${status}" != "207" ]]; then
    echo "ERROR: restore lookup for ${tag} returned ${status}"
    cat "${headers_file}" || true
    cat "${output_file}" || true
    exit 1
  fi

  python3 - "${output_file}" "${tag}" <<'PY'
import json
import sys

path, requested_tag = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)

for item in payload:
    if item.get("tag") == requested_tag and item.get("status") == "hit":
        cache_entry_id = item.get("cache_entry_id")
        if cache_entry_id:
            print(cache_entry_id)
            sys.exit(0)

raise SystemExit(f"missing hit for {requested_tag}")
PY
}

tag_pointer_version() {
  local tag="$1"
  local safe_tag
  safe_tag="$(echo "${tag}" | tr -c '[:alnum:]' '-')"
  local output_file="${WORK_DIR}/pointer-${safe_tag}.json"
  local headers_file="${LOG_DIR}/pointer-${safe_tag}.headers"
  local url
  url="$(api_workspace_base)/caches/tags/$(urlencode "${tag}")"

  local status
  status="$(
    api_request \
      GET \
      "${url}" \
      "" \
      "${output_file}" \
      "${headers_file}"
  )"

  if [[ "${status}" == "404" ]]; then
    printf '0\n'
    return 0
  fi

  assert_status "${status}" "200" "tag pointer ${tag}" "${headers_file}" "${output_file}"
  python3 - "${output_file}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)

version = payload.get("version")
if not version:
    raise SystemExit("missing tag pointer version")
print(version)
PY
}

publish_ready_tag() {
  local tag="$1"
  local cache_entry_id="$2"
  local write_scope_tag="$3"
  local version
  version="$(tag_pointer_version "${tag}")"

  local safe_tag
  safe_tag="$(echo "${tag}" | tr -c '[:alnum:]' '-')"
  local body_file="${WORK_DIR}/publish-${safe_tag}.json"
  local output_file="${WORK_DIR}/publish-${safe_tag}.body"
  local headers_file="${LOG_DIR}/publish-${safe_tag}.headers"
  python3 - "${cache_entry_id}" "${write_scope_tag}" "${body_file}" <<'PY'
import json
import pathlib
import sys

cache_entry_id, write_scope_tag, body_path = sys.argv[1:]
payload = {
    "cache_entry_id": cache_entry_id,
    "publish_mode": "cas",
    "write_scope_tag": write_scope_tag,
}
pathlib.Path(body_path).write_text(json.dumps(payload), encoding="utf-8")
PY

  local url
  url="$(api_workspace_base)/caches/tags/$(urlencode "${tag}")/publish"
  local status
  status="$(
    api_request \
      PUT \
      "${url}" \
      "${body_file}" \
      "${output_file}" \
      "${headers_file}" \
      -H "Content-Type: application/json" \
      -H "If-Match: ${version}"
  )"
  assert_status "${status}" "200" "publish ready tag ${tag}" "${headers_file}" "${output_file}"
}

fetch_manifest_with_status() {
  local reference="$1"
  local proxy_url="$2"
  local output_file="$3"
  local headers_file="$4"
  local expected_status="$5"
  local status

  status="$(
    http_request \
      GET \
      "${proxy_url}/v2/${OCI_NAME}/manifests/${reference}" \
      "" \
      "${output_file}" \
      "${headers_file}" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"
  )"
  assert_status "${status}" "${expected_status}" "manifest ${reference} fresh read" "${headers_file}" "${output_file}"
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

require_admin_capable_token
export_resolved_cli_tokens admin
ADMIN_TOKEN="$(resolve_admin_capable_token)"
unset BORINGCACHE_API_TOKEN

ROOT_TAG_A="$(registry_root_tag_for_human_tag "${TAG_A}")"
ROOT_TAG_B="$(registry_root_tag_for_human_tag "${TAG_B}")"
PRIMARY_TAG_A="$(ref_tag_for_input "${TAG_A}:${OCI_NAME}:${OCI_REFERENCE}")"
PRIMARY_TAG_B="$(ref_tag_for_input "${TAG_B}:${OCI_NAME}:${OCI_REFERENCE}")"
LEGACY_COMPAT_TAG_A="$(legacy_ref_tag_for_input "${ROOT_TAG_A}:${OCI_NAME}:${OCI_REFERENCE}")"
LEGACY_COMPAT_TAG_B="$(legacy_ref_tag_for_input "${ROOT_TAG_B}:${OCI_NAME}:${OCI_REFERENCE}")"
SHARED_READABLE_FALLBACK_TAG="$(ref_tag_for_input "${OCI_NAME}:${OCI_REFERENCE}")"
SHARED_LEGACY_FALLBACK_TAG="$(legacy_ref_tag_for_input "${OCI_NAME}:${OCI_REFERENCE}")"
WRITE_SCOPE_TAG="${OCI_NAME}:${OCI_REFERENCE}"

echo "=== OCI rooted restore isolation E2E ==="
echo "Workspace: ${WORKSPACE}"
echo "Tag A: ${TAG_A}"
echo "Tag B: ${TAG_B}"
echo "OCI ref: ${OCI_NAME}:${OCI_REFERENCE}"
echo "Primary tag A: ${PRIMARY_TAG_A}"
echo "Primary tag B: ${PRIMARY_TAG_B}"
echo "Legacy compat tag A: ${LEGACY_COMPAT_TAG_A}"
echo "Legacy compat tag B: ${LEGACY_COMPAT_TAG_B}"
echo "Shared readable fallback tag: ${SHARED_READABLE_FALLBACK_TAG}"
echo "Shared legacy fallback tag: ${SHARED_LEGACY_FALLBACK_TAG}"

echo
echo "=== Phase 1: publish root-scoped manifest for root B ==="
prepare_ref_manifest "root-b" "${OCI_REFERENCE}"
start_proxy_instance "root-b" "${PROXY_PORT_B}" "${TAG_B}" false
upload_blob_for_ref "root-b" "$(proxy_url "${PROXY_PORT_B}")"
publish_manifest_for_ref "root-b" "$(proxy_url "${PROXY_PORT_B}")" "${OCI_REFERENCE}"
stop_all_proxies

B_CACHE_ENTRY_ID="$(cache_entry_id_for_tag "${PRIMARY_TAG_B}")"
if [[ -z "${B_CACHE_ENTRY_ID}" ]]; then
  echo "ERROR: failed to resolve cache entry for ${PRIMARY_TAG_B}"
  exit 1
fi
LEGACY_B_CACHE_ENTRY_ID="$(cache_entry_id_for_tag "${LEGACY_COMPAT_TAG_B}")"
if [[ "${LEGACY_B_CACHE_ENTRY_ID}" != "${B_CACHE_ENTRY_ID}" ]]; then
  echo "ERROR: expected readable and legacy rooted aliases for root B to point at the same entry"
  exit 1
fi

echo
echo "=== Phase 2: backfill shared readable and legacy unrooted aliases to root B entry ==="
publish_ready_tag "${SHARED_READABLE_FALLBACK_TAG}" "${B_CACHE_ENTRY_ID}" "${WRITE_SCOPE_TAG}"
publish_ready_tag "${SHARED_LEGACY_FALLBACK_TAG}" "${B_CACHE_ENTRY_ID}" "${WRITE_SCOPE_TAG}"
SHARED_READABLE_CACHE_ENTRY_ID="$(cache_entry_id_for_tag "${SHARED_READABLE_FALLBACK_TAG}")"
SHARED_LEGACY_CACHE_ENTRY_ID="$(cache_entry_id_for_tag "${SHARED_LEGACY_FALLBACK_TAG}")"
if [[ "${SHARED_READABLE_CACHE_ENTRY_ID}" != "${B_CACHE_ENTRY_ID}" ]]; then
  echo "ERROR: expected shared readable fallback tag to point at root B entry"
  exit 1
fi
if [[ "${SHARED_LEGACY_CACHE_ENTRY_ID}" != "${B_CACHE_ENTRY_ID}" ]]; then
  echo "ERROR: expected shared legacy fallback tag to point at root B entry"
  exit 1
fi

echo
echo "=== Phase 3: distinct root A ignores shared unrooted fallbacks while its rooted aliases are absent ==="
start_proxy_instance "verify-a-isolated" "${PROXY_PORT_A}" "${TAG_A}" true
fetch_manifest_with_status "${OCI_REFERENCE}" "$(proxy_url "${PROXY_PORT_A}")" "${WORK_DIR}/verify-a-isolated.json" "${LOG_DIR}/verify-a-isolated.headers" "404"
stop_all_proxies

echo
echo "=== Phase 4: once root A publishes its own rooted aliases, restore prefers them over shared fallbacks ==="
prepare_ref_manifest "root-a" "${OCI_REFERENCE}"
start_proxy_instance "root-a" "${PROXY_PORT_A}" "${TAG_A}" false
upload_blob_for_ref "root-a" "$(proxy_url "${PROXY_PORT_A}")"
publish_manifest_for_ref "root-a" "$(proxy_url "${PROXY_PORT_A}")" "${OCI_REFERENCE}"
stop_all_proxies

A_CACHE_ENTRY_ID="$(cache_entry_id_for_tag "${PRIMARY_TAG_A}")"
if [[ -z "${A_CACHE_ENTRY_ID}" ]]; then
  echo "ERROR: failed to resolve cache entry for ${PRIMARY_TAG_A}"
  exit 1
fi
LEGACY_A_CACHE_ENTRY_ID="$(cache_entry_id_for_tag "${LEGACY_COMPAT_TAG_A}")"
if [[ "${LEGACY_A_CACHE_ENTRY_ID}" != "${A_CACHE_ENTRY_ID}" ]]; then
  echo "ERROR: expected readable and legacy rooted aliases for root A to point at the same entry"
  exit 1
fi
if [[ "${A_CACHE_ENTRY_ID}" == "${B_CACHE_ENTRY_ID}" ]]; then
  echo "ERROR: expected root A and root B to publish distinct cache entries"
  exit 1
fi

start_proxy_instance "verify-a-primary" "${PROXY_PORT_A}" "${TAG_A}" true
fetch_manifest_with_status "${OCI_REFERENCE}" "$(proxy_url "${PROXY_PORT_A}")" "${WORK_DIR}/verify-a-primary.json" "${LOG_DIR}/verify-a-primary.headers" "200"
assert_same_file "${WORK_DIR}/root-a-manifest.json" "${WORK_DIR}/verify-a-primary.json" "root A primary restore"
stop_all_proxies

echo
echo "OCI rooted restore isolation e2e passed"
