#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/e2e-remote-tag.sh"

PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-5059}"
WORKSPACE="${WORKSPACE:-${BORINGCACHE_DEFAULT_WORKSPACE:-boringcache/testing2}}"
TAG_BASE="${TAG:-bc-e2e-prefetch-readiness}"
BINARY="${BINARY:-./target/release/boringcache}"
TMP_ROOT="${TMPDIR:-/tmp}/boringcache-prefetch-e2e"
LOG_DIR="${LOG_DIR:-${TMP_ROOT}/logs}"
PROXY_LOG="${LOG_DIR}/proxy.log"
PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"
PROXY_READY_TIMEOUT_SECS="${PROXY_READY_TIMEOUT_SECS:-300}"
PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_SECS:-30}"
HTTP_CONNECT_TIMEOUT_SECS="${HTTP_CONNECT_TIMEOUT_SECS:-5}"
HTTP_REQUEST_TIMEOUT_SECS="${HTTP_REQUEST_TIMEOUT_SECS:-30}"
SETTLE_SECS="${SETTLE_SECS:-5}"
SEED_FLUSH_TIMEOUT_SECS="${SEED_FLUSH_TIMEOUT_SECS:-180}"
SEED_FLUSH_STALL_TIMEOUT_SECS="${SEED_FLUSH_STALL_TIMEOUT_SECS:-60}"

BLOB_COUNT="${BLOB_COUNT:-20000}"
BLOB_SIZE_BYTES="${BLOB_SIZE_BYTES:-4096}"
SEED_CONCURRENCY="${SEED_CONCURRENCY:-64}"
VERIFY_CONCURRENCY="${VERIFY_CONCURRENCY:-64}"
BUDGET_PREFETCH_FAILURES_MAX="${BUDGET_PREFETCH_FAILURES_MAX:-0}"
BUDGET_VERIFY_FAILURES_MAX="${BUDGET_VERIFY_FAILURES_MAX:-0}"
BUDGET_REMOTE_TAG_HITS_MIN="${BUDGET_REMOTE_TAG_HITS_MIN:-1}"

PROXY_PID=""
TAG=""

if [[ -z "${BORINGCACHE_API_TOKEN:-}" ]]; then
  echo "ERROR: BORINGCACHE_API_TOKEN not set"
  exit 1
fi

if [[ ! -x "${BINARY}" ]]; then
  echo "ERROR: BINARY not executable at ${BINARY}"
  exit 1
fi

mkdir -p "$LOG_DIR"
: >"$PROXY_LOG"

http_status() {
  local path="$1"
  local status
  status="$(
    curl -sS -o /dev/null -w "%{http_code}" \
      --connect-timeout "$HTTP_CONNECT_TIMEOUT_SECS" \
      --max-time "$HTTP_REQUEST_TIMEOUT_SECS" \
      "${PROXY_URL}${path}" 2>/dev/null || true
  )"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf '%s' "$status"
}

wait_for_proxy_ready() {
  local waited=0
  while (( waited < PROXY_READY_TIMEOUT_SECS )); do
    if [[ "$(http_status "/v2/")" == "200" ]]; then
      return 0
    fi
    if [[ -n "${PROXY_PID:-}" ]] && ! kill -0 "$PROXY_PID" >/dev/null 2>&1; then
      echo "ERROR: proxy exited before readiness"
      tail -n 200 "$PROXY_LOG" || true
      exit 1
    fi
    sleep 1
    waited=$((waited + 1))
    if (( waited % 10 == 0 )); then
      echo "  waiting for proxy readiness... (${waited}s)"
    fi
  done

  echo "ERROR: timed out waiting for proxy readiness (${PROXY_READY_TIMEOUT_SECS}s)"
  tail -n 200 "$PROXY_LOG" || true
  exit 1
}

flushed_entry_count() {
  awk '
    /KV batch: flushed [0-9]+ new entries/ {
      sum += $4
    }
    END {
      print sum + 0
    }
  ' "$PROXY_LOG"
}

latest_blob_upload_progress() {
  awk '
    /KV blob upload progress:/ {
      uploaded = ""
      total = ""
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^uploaded=/) {
          value = $i
          sub(/^uploaded=/, "", value)
          split(value, parts, "/")
          uploaded = parts[1]
          total = parts[2]
        }
      }
    }
    END {
      if (uploaded != "" && total != "") {
        printf "%s/%s", uploaded, total
      }
    }
  ' "$PROXY_LOG"
}

wait_for_seed_flush() {
  local target="$1"
  local waited=0
  local last_flushed=0
  local stalled_for=0

  while (( waited < SEED_FLUSH_TIMEOUT_SECS )); do
    local flushed
    flushed="$(flushed_entry_count)"
    if [[ "$flushed" =~ ^[0-9]+$ ]] && (( flushed >= target )); then
      echo "  published flush progress reached ${flushed}/${target} entries"
      return 0
    fi

    if [[ -n "${PROXY_PID:-}" ]] && ! kill -0 "$PROXY_PID" >/dev/null 2>&1; then
      echo "ERROR: proxy exited before seed flush completed"
      tail -n 200 "$PROXY_LOG" || true
      exit 1
    fi

    if [[ "$flushed" =~ ^[0-9]+$ ]] && (( flushed > last_flushed )); then
      last_flushed="$flushed"
      stalled_for=0
    else
      stalled_for=$((stalled_for + 2))
      if (( stalled_for >= SEED_FLUSH_STALL_TIMEOUT_SECS )) && \
        grep -Eq 'KV batch flush failed:|tag conflict|Cache upload in progress' "$PROXY_LOG"; then
        echo "ERROR: seed flush stalled at ${flushed:-0}/${target} entries for ${stalled_for}s after backend flush errors/conflicts"
        tail -n 200 "$PROXY_LOG" || true
        exit 1
      fi
    fi

    sleep 2
    waited=$((waited + 2))
    if (( waited % 10 == 0 )); then
      local upload_progress=""
      upload_progress="$(latest_blob_upload_progress)"
      if [[ -n "$upload_progress" ]]; then
        echo "  waiting for seed flush progress... (${flushed:-0}/${target} entries published, uploads ${upload_progress}, ${waited}s)"
      else
        echo "  waiting for seed flush progress... (${flushed:-0}/${target} entries, ${waited}s)"
      fi
    fi
  done

  echo "ERROR: timed out waiting for seed flush progress (${SEED_FLUSH_TIMEOUT_SECS}s)"
  tail -n 200 "$PROXY_LOG" || true
  exit 1
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
  stop_proxy
  {
    echo
    echo "=== Proxy start $(date -u +"%Y-%m-%dT%H:%M:%SZ") tag=${proxy_tag} hints=${metadata_hints:-none} ==="
  } >>"$PROXY_LOG"
  BORINGCACHE_API_TOKEN="${BORINGCACHE_API_TOKEN}" \
    BORINGCACHE_BLOB_DOWNLOAD_CONCURRENCY="${SEED_CONCURRENCY}" \
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

phase_metadata_hints() {
  local phase="$1"
  printf 'project=cli-cache-registry,phase=%s,scenario=prefetch-readiness' "$phase"
}

echo "=== Phase 1: Seed ${BLOB_COUNT} blobs via proxy ==="
start_proxy "$TAG" "$(phase_metadata_hints "prefetch-seed")"

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

seq 0 $((BLOB_COUNT - 1)) | xargs -P "$SEED_CONCURRENCY" -I{} bash -c '
  path="'"$DATA_DIR"'/blob-{}.bin"
  dd if=/dev/urandom bs='"$BLOB_SIZE_BYTES"' count=1 2>/dev/null > "$path"
  digest="$(sha256sum "$path" | awk "{print \$1}")"
  echo "${digest}" >> "'"$DIGESTS_FILE"'"
  curl -sS --max-time 30 -X PUT --data-binary "@${path}" -o /dev/null \
    -w "" "'"$PROXY_URL"'/cas/${digest}"
'

SEED_COUNT="$(wc -l < "$DIGESTS_FILE" | tr -d ' ')"
echo "  seeded ${SEED_COUNT} blobs"

if (( SEED_COUNT < BLOB_COUNT )); then
  echo "ERROR: only seeded ${SEED_COUNT}/${BLOB_COUNT} blobs"
  exit 1
fi

echo "  waiting for writes to settle (${SETTLE_SECS}s)..."
sleep "$SETTLE_SECS"
echo "  waiting for published index flush..."
wait_for_seed_flush "$BLOB_COUNT"

echo "  flushing proxy..."
stop_proxy
echo "  seed proxy stopped"

echo ""
echo "=== Phase 1b: Verify published remote tag resolves ==="
if ! verify_remote_tag_visible "$BINARY" "$WORKSPACE" "$TAG" "$LOG_DIR" "$BUDGET_REMOTE_TAG_HITS_MIN" "${REMOTE_TAG_VERIFY_ATTEMPTS:-30}" "${REMOTE_TAG_VERIFY_SLEEP_SECS:-2}" "$PROXY_LOG"; then
  exit 1
fi
REMOTE_TAG_HITS="${REMOTE_TAG_CHECK_HITS:-0}"
REMOTE_TAG_MISSES="${REMOTE_TAG_CHECK_MISSES:-0}"

echo ""
echo "=== Phase 2: Restart proxy on fresh disk cache, verify readiness gates on prefetch ==="

FRESH_CACHE_DIR="${TMP_ROOT}/fresh-cache-${RUN_ID}"
mkdir -p "$FRESH_CACHE_DIR"

PREFETCH_START="$(date +%s)"
start_proxy "$TAG" "$(phase_metadata_hints "prefetch-restart")"
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

xargs -P "$VERIFY_CONCURRENCY" -I{} bash -c '
  status="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 "'"$PROXY_URL"'/cas/{}")"
  if [[ "$status" != "200" ]]; then
    echo "MISS: {} status=${status}" >&2
    exit 1
  fi
' < "$DIGESTS_FILE" 2>"${DATA_DIR}/verify-errors.txt" || true

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
echo "=== Phase 4: Verify /v2/ was 503 during prefetch ==="

V2_503_COUNT="$(grep -c "503" "$PROXY_LOG" || true)"
echo "  503 responses logged: ${V2_503_COUNT}"

echo ""
echo "=== Results ==="
echo "  blobs seeded:    ${SEED_COUNT}"
echo "  prefetch time:   ${PREFETCH_SECS}s"
echo "  prefetch fails:  ${PREFETCH_FAILURES}"
echo "  remote tag hits: ${REMOTE_TAG_HITS:-0}"
echo "  remote tag miss: ${REMOTE_TAG_MISSES:-0}"
echo "  verify time:     ${VERIFY_SECS}s"
echo "  verify failures: ${VERIFY_FAILURES}"
echo ""
echo "Prefetch readiness e2e passed"
