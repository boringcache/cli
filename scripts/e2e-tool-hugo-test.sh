#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/e2e-helpers.sh"

BINARY="${BINARY:-./target/debug/boringcache}"
WORKSPACE="${WORKSPACE:?WORKSPACE is required}"
LOG_DIR="${LOG_DIR:-.}"
PORT="${PORT:-5000}"
RUN_ID="${GITHUB_RUN_ID:-local}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}"
BUILD_TIMEOUT_SECS="${BUILD_TIMEOUT_SECS:-300}"
BUILD_HEARTBEAT_SECS="${BUILD_HEARTBEAT_SECS:-30}"
BUILD_CLEANUP_WAIT_SECS="${BUILD_CLEANUP_WAIT_SECS:-20}"
PROXY_SHUTDOWN_WAIT_SECS="${PROXY_SHUTDOWN_WAIT_SECS:-30}"
BUDGET_REMOTE_TAG_HITS_MIN="${BUDGET_REMOTE_TAG_HITS_MIN:-1}"

require_save_capable_token

for dep in docker curl; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: required dependency not found: ${dep}"
    exit 1
  fi
done

if [[ ! -x "${BINARY}" ]]; then
  echo "ERROR: BINARY is not executable: ${BINARY}"
  exit 1
fi

export_resolved_cli_tokens admin

mkdir -p "${LOG_DIR}"
HUGO_LOG_DIR="${LOG_DIR}/tool-hugo-e2e"
rm -rf "${HUGO_LOG_DIR}"
mkdir -p "${HUGO_LOG_DIR}"

TAG="$(e2e_tag "tool-hugo")"
REGISTRY_TAG="${TAG}-registry"
CACHE_REF="localhost:${PORT}/boringcache-e2e/hugo:${TAG}"
BUILDER="bc-hugo-e2e-${RUN_ID}-${RUN_ATTEMPT}"
SERVE_PID=""

setup_e2e_traps "${BINARY}" "${WORKSPACE}"
register_tag_for_cleanup "${REGISTRY_TAG}"

hugo_cleanup() {
  docker buildx rm --force "${BUILDER}" >/dev/null 2>&1 || true
}
register_cleanup_callback hugo_cleanup

CONTEXT_DIR="${HUGO_LOG_DIR}/context"
mkdir -p "${CONTEXT_DIR}"

cat > "${CONTEXT_DIR}/Dockerfile" <<'DOCKERFILE'
FROM alpine:3.21 AS builder
RUN apk add --no-cache hugo git
WORKDIR /site
RUN hugo new site mysite
WORKDIR /site/mysite
RUN printf 'baseURL = "https://example.com/"\nlanguageCode = "en-us"\ntitle = "E2E Test Site"\n' > hugo.toml
RUN mkdir -p content/posts && \
    printf -- '---\ntitle: "Test Post"\ndate: 2026-01-01\n---\n\nHello from BoringCache e2e.\n' > content/posts/test.md
RUN hugo --minify

FROM alpine:3.21
COPY --from=builder /site/mysite/public /site/public
DOCKERFILE

docker buildx create \
  --name "${BUILDER}" \
  --driver docker-container \
  --driver-opt network=host \
  --use
docker buildx inspect "${BUILDER}" --bootstrap

export BORINGCACHE_PROXY_METADATA_HINTS="project=e2e-tool-hugo,tool=oci"
start_proxy "${BINARY}" "${WORKSPACE}" "${REGISTRY_TAG}" "${PORT}" "${HUGO_LOG_DIR}/proxy.log"
wait_for_proxy "${PORT}"

echo "=== Phase 1: Cold Docker build (seed cache) ==="
COLD_LOG="${HUGO_LOG_DIR}/cold-build.log"
COLD_START="$(date +%s)"
(
  set -o pipefail
  docker buildx build \
    --builder "${BUILDER}" \
    --progress plain \
    --load \
    --file "${CONTEXT_DIR}/Dockerfile" \
    --cache-to "type=registry,ref=${CACHE_REF},mode=max" \
    --tag "hugo-e2e-cold:latest" \
    "${CONTEXT_DIR}" 2>&1 | tee "${COLD_LOG}"
)
COLD_END="$(date +%s)"
COLD_SECS="$((COLD_END - COLD_START))"
echo "Cold build completed in ${COLD_SECS}s"

docker buildx prune --builder "${BUILDER}" --all --force >/dev/null 2>&1

echo "=== Phase 2: Warm Docker build (cache hit) ==="
WARM_LOG="${HUGO_LOG_DIR}/warm-build.log"
WARM_START="$(date +%s)"
(
  set -o pipefail
  docker buildx build \
    --builder "${BUILDER}" \
    --progress plain \
    --load \
    --file "${CONTEXT_DIR}/Dockerfile" \
    --cache-from "type=registry,ref=${CACHE_REF}" \
    --tag "hugo-e2e-warm:latest" \
    "${CONTEXT_DIR}" 2>&1 | tee "${WARM_LOG}"
)
WARM_END="$(date +%s)"
WARM_SECS="$((WARM_END - WARM_START))"
echo "Warm build completed in ${WARM_SECS}s"

if grep -q "importing cache manifest from" "${WARM_LOG}"; then
  echo "  registry cache import confirmed"
else
  echo "ERROR: warm build did not import cache from registry"
  exit 1
fi

if grep -q "CACHED" "${WARM_LOG}"; then
  echo "  cached layers detected in warm build"
else
  echo "ERROR: no CACHED steps found in warm build output — cache import did not produce layer reuse"
  exit 1
fi

stop_proxy
dump_cache_ops_summary

if [[ "${BUDGET_REMOTE_TAG_HITS_MIN}" -gt 0 ]]; then
  verify_remote_tag_visible "${BINARY}" "${WORKSPACE}" "${REGISTRY_TAG}" "${HUGO_LOG_DIR}" \
    "${BUDGET_REMOTE_TAG_HITS_MIN}" 30 2 "$(proxy_log)"
  echo "  remote tag verified (hits=${REMOTE_TAG_CHECK_HITS:-0})"
fi

echo ""
echo "Hugo tool e2e passed. Cold=${COLD_SECS}s Warm=${WARM_SECS}s Logs: ${HUGO_LOG_DIR}"
