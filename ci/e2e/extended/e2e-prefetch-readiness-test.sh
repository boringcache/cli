#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
source "${SCRIPT_DIR}/../e2e-remote-tag.sh"

PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-5059}"
WORKSPACE="${WORKSPACE:-${BORINGCACHE_DEFAULT_WORKSPACE:-boringcache/testing2}}"
TAG_BASE="${TAG:-bc-e2e-prefetch-readiness}"
BINARY="${BINARY:-${CLI_REPO_ROOT}/target/release/boringcache}"
TMP_ROOT="${TMPDIR:-/tmp}/boringcache-prefetch-e2e"
LOG_DIR="${LOG_DIR:-${TMP_ROOT}/logs}"
PROXY_LOG="${LOG_DIR}/proxy.log"
PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"
PROXY_STATUS_PATH="${PROXY_STATUS_PATH:-/_boringcache/status}"
PROXY_READY_TIMEOUT_SECS="${PROXY_READY_TIMEOUT_SECS:-300}"
PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_SECS:-210}"
PROXY_SHUTDOWN_WAIT_MIN_SECS=210
HTTP_CONNECT_TIMEOUT_SECS="${HTTP_CONNECT_TIMEOUT_SECS:-5}"
HTTP_REQUEST_TIMEOUT_SECS="${HTTP_REQUEST_TIMEOUT_SECS:-30}"
SEED_FLUSH_TIMEOUT_SECS="${SEED_FLUSH_TIMEOUT_SECS:-180}"

BLOB_COUNT="${BLOB_COUNT:-20000}"
BLOB_SIZE_BYTES="${BLOB_SIZE_BYTES:-4096}"
SEED_CONCURRENCY="${SEED_CONCURRENCY:-64}"
VERIFY_CONCURRENCY="${VERIFY_CONCURRENCY:-64}"
BUDGET_PREFETCH_FAILURES_MAX="${BUDGET_PREFETCH_FAILURES_MAX:-0}"
BUDGET_VERIFY_FAILURES_MAX="${BUDGET_VERIFY_FAILURES_MAX:-0}"
BUDGET_REMOTE_TAG_HITS_MIN="${BUDGET_REMOTE_TAG_HITS_MIN:-1}"
REMOTE_BLOB_URL_VERIFY_ATTEMPTS="${REMOTE_BLOB_URL_VERIFY_ATTEMPTS:-30}"
REMOTE_BLOB_URL_VERIFY_SLEEP_SECS="${REMOTE_BLOB_URL_VERIFY_SLEEP_SECS:-2}"

PROXY_PID=""
TAG=""
SEED_BLOB_CACHE_DIR=""
FRESH_CACHE_DIR=""
PREFETCH_WARMING_POLLS=0
PREFETCH_READY_POLLS=0

require_save_capable_token

if [[ "${PROXY_SHUTDOWN_WAIT_SECS}" =~ ^[0-9]+$ ]] \
  && (( PROXY_SHUTDOWN_WAIT_SECS < PROXY_SHUTDOWN_WAIT_MIN_SECS )); then
  PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_MIN_SECS}"
fi

if [[ ! -x "${BINARY}" ]]; then
  echo "ERROR: BINARY not executable at ${BINARY}"
  exit 1
fi

export_resolved_cli_tokens admin

mkdir -p "$LOG_DIR"
: >"$PROXY_LOG"

http_proxy_status_probe() {
  local response
  response="$(
    curl -sS -D - -o /dev/null \
      --connect-timeout "$HTTP_CONNECT_TIMEOUT_SECS" \
      --max-time "$HTTP_REQUEST_TIMEOUT_SECS" \
      "${PROXY_URL}${PROXY_STATUS_PATH}" 2>/dev/null || true
  )"

  local status phase publish_state
  status="$(printf '%s\n' "$response" | awk 'tolower($1) ~ /^http\// { status = $2 } END { print status }')"
  phase="$(printf '%s\n' "$response" | awk -F': ' 'tolower($1) == "x-boringcache-proxy-phase" { gsub("\\r", "", $2); phase = tolower($2) } END { print phase }')"
  publish_state="$(printf '%s\n' "$response" | awk -F': ' 'tolower($1) == "x-boringcache-publish-state" { gsub("\\r", "", $2); publish = tolower($2) } END { print publish }')"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf '%s %s %s' "$status" "$phase" "$publish_state"
}

wait_for_proxy_ready() {
  local waited=0
  while (( waited < PROXY_READY_TIMEOUT_SECS )); do
    local probe status phase publish_state
    probe="$(http_proxy_status_probe)"
    read -r status phase publish_state <<<"$probe"
    if [[ "$status" == "200" && "$phase" == "ready" ]]; then
      PREFETCH_READY_POLLS=$((PREFETCH_READY_POLLS + 1))
      return 0
    fi
    if [[ "$status" == "200" && "$phase" == "warming" ]]; then
      PREFETCH_WARMING_POLLS=$((PREFETCH_WARMING_POLLS + 1))
    fi
    if [[ -n "${PROXY_PID:-}" ]] && ! kill -0 "$PROXY_PID" >/dev/null 2>&1; then
      echo "ERROR: proxy exited before readiness"
      tail -n 200 "$PROXY_LOG" || true
      exit 1
    fi
    sleep 1
    waited=$((waited + 1))
    if (( waited % 10 == 0 )); then
      echo "  waiting for proxy readiness... (phase=${phase:-unknown}, publish=${publish_state:-unknown}, ${waited}s)"
    fi
  done

  echo "ERROR: timed out waiting for proxy readiness (${PROXY_READY_TIMEOUT_SECS}s)"
  tail -n 200 "$PROXY_LOG" || true
  exit 1
}

wait_for_publish_settled() {
  local waited=0

  while (( waited < SEED_FLUSH_TIMEOUT_SECS )); do
    local probe status phase publish_state
    probe="$(http_proxy_status_probe)"
    read -r status phase publish_state <<<"$probe"
    if [[ "$status" == "200" && "$publish_state" == "settled" ]]; then
      echo "  proxy reports publish settled"
      return 0
    fi

    if [[ -n "${PROXY_PID:-}" ]] && ! kill -0 "$PROXY_PID" >/dev/null 2>&1; then
      echo "ERROR: proxy exited before publish settled"
      tail -n 200 "$PROXY_LOG" || true
      exit 1
    fi

    sleep 2
    waited=$((waited + 2))
    if (( waited % 10 == 0 )); then
      echo "  waiting for publish settled... (phase=${phase:-unknown}, publish=${publish_state:-unknown}, ${waited}s)"
    fi
  done

  echo "ERROR: timed out waiting for publish settled (${SEED_FLUSH_TIMEOUT_SECS}s)"
  tail -n 200 "$PROXY_LOG" || true
  exit 1
}

write_blob_download_url_request() {
  local digests_file="$1"
  local blob_size_bytes="$2"
  local cache_entry_id="$3"
  local request_file="$4"

  python3 - "$digests_file" "$blob_size_bytes" "$cache_entry_id" >"$request_file" <<'PY'
import json
import sys

digests_file, blob_size_bytes, cache_entry_id = sys.argv[1:]
with open(digests_file, encoding="utf-8") as handle:
    digests = [line.strip() for line in handle if line.strip()]

json.dump({
    "cache_entry_id": cache_entry_id,
    "verify_storage": True,
    "blobs": [
        {"digest": digest, "size_bytes": int(blob_size_bytes)}
        for digest in digests
    ],
}, sys.stdout)
PY
}

blob_download_url_count() {
  local response_file="$1"

  python3 - "$response_file" <<'PY'
import json
import sys

try:
    body = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print("0 0")
    raise SystemExit(0)

download_urls = body.get("download_urls") or []
missing = body.get("missing") or []
print(f"{len(download_urls)} {len(missing)}")
PY
}

wait_for_remote_blob_download_urls() {
  local cache_entry_id="$1"
  local digests_file="$2"
  local blob_size_bytes="$3"
  local output_dir="$4"
  local attempts="${5:-$REMOTE_BLOB_URL_VERIFY_ATTEMPTS}"
  local sleep_secs="${6:-$REMOTE_BLOB_URL_VERIFY_SLEEP_SECS}"
  local auth_token namespace_slug workspace_slug endpoint request_file response_file stderr_file expected_count
  local attempt status resolved missing

  auth_token="$(resolve_restore_capable_token || true)"
  if [[ -z "$auth_token" ]]; then
    echo "ERROR: restore-capable token unavailable for blob URL visibility check"
    return 1
  fi
  if [[ "$WORKSPACE" != */* ]]; then
    echo "ERROR: workspace must be namespace/name for blob URL visibility check"
    return 1
  fi

  mkdir -p "$output_dir"
  namespace_slug="$(workspace_namespace_slug "$WORKSPACE")"
  workspace_slug="$(workspace_name_slug "$WORKSPACE")"
  endpoint="${BORINGCACHE_API_URL}/v2/workspaces/${namespace_slug}/${workspace_slug}/caches/blobs/download-urls"
  request_file="${output_dir}/blob-download-urls-request.json"
  response_file="${output_dir}/blob-download-urls-response.json"
  stderr_file="${output_dir}/blob-download-urls.stderr.txt"
  expected_count="$(wc -l < "$digests_file" | tr -d ' ')"

  write_blob_download_url_request "$digests_file" "$blob_size_bytes" "$cache_entry_id" "$request_file"

  for attempt in $(seq 1 "$attempts"); do
    status="$(
      curl -sS \
        -X POST \
        -H "Authorization: Bearer ${auth_token}" \
        -H "Accept: application/json" \
        -H "Content-Type: application/json" \
        --data-binary "@${request_file}" \
        -o "$response_file" \
        -w "%{http_code}" \
        "$endpoint" 2>"$stderr_file" || printf '000'
    )"
    if [[ "$status" == "200" ]]; then
      read -r resolved missing <<<"$(blob_download_url_count "$response_file")"
      echo "Remote blob URL check: resolved=${resolved}/${expected_count} missing=${missing} file=${response_file}"
      if (( resolved >= expected_count )); then
        return 0
      fi
    else
      echo "WARNING: blob URL check returned ${status} (attempt ${attempt}/${attempts})"
      cat "$stderr_file" || true
    fi

    if (( attempt < attempts )); then
      echo "  waiting for remote blob URLs to verify... (${attempt}/${attempts})"
      sleep "$sleep_secs"
    fi
  done

  echo "ERROR: remote blob download URLs did not converge for ${cache_entry_id}"
  if [[ -f "$response_file" ]]; then
    cat "$response_file" || true
  fi
  return 1
}

stop_proxy() {
  if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID"
    local waited=0
    while kill -0 "$PROXY_PID" 2>/dev/null && (( waited < PROXY_SHUTDOWN_WAIT_SECS )); do
      sleep 1
      waited=$((waited + 1))
    done
    wait "$PROXY_PID" 2>/dev/null || true
    PROXY_PID=""
  fi
}

cleanup() {
  set +e
  stop_proxy
  if [[ -n "${TAG:-}" ]]; then
    "$BINARY" delete --no-platform --no-git "$WORKSPACE" "$TAG" 2>/dev/null || true
  fi
}
trap cleanup EXIT

start_proxy() {
  local proxy_tag="$1"
  local metadata_hints="${2:-}"
  local blob_cache_dir="${3:-}"
  stop_proxy
  {
    echo
    echo "=== Proxy start $(date -u +"%Y-%m-%dT%H:%M:%SZ") tag=${proxy_tag} hints=${metadata_hints:-none} ==="
  } >>"$PROXY_LOG"
  BORINGCACHE_BLOB_DOWNLOAD_CONCURRENCY="${SEED_CONCURRENCY}" \
    BORINGCACHE_BLOB_READ_CACHE_DIR="${blob_cache_dir}" \
    BORINGCACHE_PROXY_METADATA_HINTS="$metadata_hints" \
    RUST_LOG="${RUST_LOG_LEVEL:-info}" \
    "$BINARY" cache-registry "$WORKSPACE" "$proxy_tag" \
      --host "$PROXY_HOST" \
      --port "$PROXY_PORT" \
      --no-platform \
      --no-git \
      --fail-on-cache-error >>"$PROXY_LOG" 2>&1 &
  PROXY_PID=$!
  wait_for_proxy_ready
}

echo "=== Prefetch readiness e2e test ==="
echo "  blob_count=${BLOB_COUNT} blob_size=${BLOB_SIZE_BYTES}"
echo "  seed_concurrency=${SEED_CONCURRENCY} verify_concurrency=${VERIFY_CONCURRENCY}"
echo ""

RUN_ID="$(date +%s)-$$"
TAG="${TAG_BASE}-${RUN_ID}"
SEED_BLOB_CACHE_DIR="${TMP_ROOT}/seed-blob-cache-${RUN_ID}"
FRESH_CACHE_DIR="${TMP_ROOT}/fresh-cache-${RUN_ID}"
mkdir -p "$SEED_BLOB_CACHE_DIR" "$FRESH_CACHE_DIR"

phase_metadata_hints() {
  local phase="$1"
  printf 'project=cli-cache-registry,phase=%s,scenario=prefetch-readiness' "$phase"
}

echo "=== Phase 1: Seed ${BLOB_COUNT} blobs via proxy ==="
start_proxy "$TAG" "$(phase_metadata_hints "prefetch-seed")" "$SEED_BLOB_CACHE_DIR"

DATA_DIR="${TMP_ROOT}/data-${RUN_ID}"
mkdir -p "$DATA_DIR"

generate_blob() {
  local idx="$1"
  local path="${DATA_DIR}/blob-${idx}.bin"
  dd if=/dev/urandom bs="$BLOB_SIZE_BYTES" count=1 2>/dev/null > "$path"
  local digest
  digest="$(sha256sum "$path" | awk '{print $1}')"
  echo "${digest} ${path}"
}

echo "  generating ${BLOB_COUNT} random blobs..."
DIGESTS_FILE="${DATA_DIR}/digests.txt"
: > "$DIGESTS_FILE"

seq 0 $((BLOB_COUNT - 1)) | xargs -P "$SEED_CONCURRENCY" -n 1 bash -c '
  data_dir="$1"
  blob_size="$2"
  digests_file="$3"
  proxy_url="$4"
  idx="$5"
  path="${data_dir}/blob-${idx}.bin"
  dd if=/dev/urandom bs="${blob_size}" count=1 2>/dev/null > "$path"
  digest="$(sha256sum "$path" | awk "{print \$1}")"
  echo "${digest}" >> "${digests_file}"
  curl -sS --max-time 30 -X PUT --data-binary "@${path}" -o /dev/null \
    -w "" "${proxy_url}/cas/${digest}"
' _ "$DATA_DIR" "$BLOB_SIZE_BYTES" "$DIGESTS_FILE" "$PROXY_URL"

SEED_COUNT="$(wc -l < "$DIGESTS_FILE" | tr -d ' ')"
echo "  seeded ${SEED_COUNT} blobs"

if (( SEED_COUNT < BLOB_COUNT )); then
  echo "ERROR: only seeded ${SEED_COUNT}/${BLOB_COUNT} blobs"
  exit 1
fi

echo "  waiting for proxy publish-settled state..."
wait_for_publish_settled

echo "  flushing proxy..."
stop_proxy
echo "  seed proxy stopped"

echo ""
echo "=== Phase 1b: Verify published remote tag resolves ==="
if ! verify_remote_tag_visible "$BINARY" "$WORKSPACE" "$TAG" "$LOG_DIR" "$BUDGET_REMOTE_TAG_HITS_MIN" "${REMOTE_TAG_VERIFY_ATTEMPTS}" "${REMOTE_TAG_VERIFY_SLEEP_SECS}" "$PROXY_LOG"; then
  exit 1
fi
REMOTE_TAG_HITS="${REMOTE_TAG_CHECK_HITS:-0}"
REMOTE_TAG_MISSES="${REMOTE_TAG_CHECK_MISSES:-0}"
REMOTE_CACHE_ENTRY_ID="${REMOTE_TAG_POINTER_CACHE_ENTRY_ID:-}"
if [[ -z "$REMOTE_CACHE_ENTRY_ID" ]]; then
  echo "ERROR: remote tag pointer did not expose a cache entry id for ${TAG}"
  exit 1
fi

echo ""
echo "=== Phase 1c: Wait for remote blob download URLs ==="
if ! wait_for_remote_blob_download_urls "$REMOTE_CACHE_ENTRY_ID" "$DIGESTS_FILE" "$BLOB_SIZE_BYTES" "$LOG_DIR/blob-url-check"; then
  exit 1
fi

echo ""
echo "=== Phase 2: Restart proxy on fresh disk cache, verify readiness gates on prefetch ==="

PREFETCH_WARMING_POLLS=0
PREFETCH_READY_POLLS=0
PREFETCH_START="$(date +%s)"
start_proxy "$TAG" "$(phase_metadata_hints "prefetch-restart")" "$FRESH_CACHE_DIR"
PREFETCH_END="$(date +%s)"
PREFETCH_SECS=$((PREFETCH_END - PREFETCH_START))
echo "  proxy became ready in ${PREFETCH_SECS}s (prefetched manifest blobs)"

PREFETCH_LOG_LINES="$(grep -c "Prefetch:" "$PROXY_LOG" || true)"
echo "  prefetch log lines: ${PREFETCH_LOG_LINES}"

PREFETCH_DONE_LINE="$(grep "Prefetch: complete\|Prefetch: done" "$PROXY_LOG" | tail -1 || true)"
if [[ -n "$PREFETCH_DONE_LINE" ]]; then
  echo "  ${PREFETCH_DONE_LINE}"
fi

PREFETCH_FAILURES="$(grep -o "failures=[0-9]*" "$PROXY_LOG" | tail -1 | cut -d= -f2 || echo "0")"
if (( PREFETCH_FAILURES > BUDGET_PREFETCH_FAILURES_MAX )); then
  echo "ERROR: prefetch had ${PREFETCH_FAILURES} failures (budget: ${BUDGET_PREFETCH_FAILURES_MAX})"
  tail -n 100 "$PROXY_LOG"
  exit 1
fi

echo ""
echo "=== Phase 3: Verify all ${SEED_COUNT} blobs served from local cache ==="

VERIFY_FAILURES=0
VERIFY_START="$(date +%s)"

xargs -P "$VERIFY_CONCURRENCY" -n 1 bash -c '
  proxy_url="$1"
  digest="$2"
  status="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 "${proxy_url}/cas/${digest}")"
  if [[ "$status" != "200" ]]; then
    echo "MISS: ${digest} status=${status}" >&2
    exit 1
  fi
' _ "$PROXY_URL" < "$DIGESTS_FILE" 2>"${DATA_DIR}/verify-errors.txt" || true

VERIFY_END="$(date +%s)"
VERIFY_SECS=$((VERIFY_END - VERIFY_START))

if [[ -f "${DATA_DIR}/verify-errors.txt" ]]; then
  VERIFY_FAILURES="$(wc -l < "${DATA_DIR}/verify-errors.txt" | tr -d ' ')"
fi

echo "  verified ${SEED_COUNT} blobs in ${VERIFY_SECS}s (${VERIFY_FAILURES} failures)"

if (( VERIFY_FAILURES > BUDGET_VERIFY_FAILURES_MAX )); then
  echo "ERROR: ${VERIFY_FAILURES} blobs failed verification (budget: ${BUDGET_VERIFY_FAILURES_MAX})"
  head -20 "${DATA_DIR}/verify-errors.txt"
  echo "--- proxy log tail ---"
  tail -n 100 "$PROXY_LOG"
  exit 1
fi

echo ""
echo "=== Phase 4: Verify proxy status reported warming before ready ==="
echo "  warming polls observed: ${PREFETCH_WARMING_POLLS}"
echo "  ready polls observed:   ${PREFETCH_READY_POLLS}"

echo ""
echo "=== Results ==="
echo "  blobs seeded:    ${SEED_COUNT}"
echo "  prefetch time:   ${PREFETCH_SECS}s"
echo "  prefetch fails:  ${PREFETCH_FAILURES}"
echo "  remote tag hits: ${REMOTE_TAG_HITS:-0}"
echo "  remote tag miss: ${REMOTE_TAG_MISSES:-0}"
echo "  warming polls:   ${PREFETCH_WARMING_POLLS}"
echo "  verify time:     ${VERIFY_SECS}s"
echo "  verify failures: ${VERIFY_FAILURES}"
echo ""
echo "Prefetch readiness e2e passed"
