#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/e2e-helpers.sh"

CLI_REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BINARY="${BINARY:-${CLI_REPO_ROOT}/target/debug/boringcache}"
WORKSPACE="${WORKSPACE:?WORKSPACE is required}"
LOG_DIR="${LOG_DIR:-.}"
PROXY_PORT="${PROXY_PORT:-4227}"
RUN_ID="${GITHUB_RUN_ID:-local}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}"
BUDGET_REMOTE_TAG_HITS_MIN="${BUDGET_REMOTE_TAG_HITS_MIN:-1}"

require_save_capable_token

for dep in node npm; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: required dependency not found: ${dep}"
    exit 1
  fi
done

if ! command -v turbo >/dev/null 2>&1; then
  echo "Installing turbo..."
  npm install -g turbo 2>&1 | tail -n 3
fi

if [[ ! -x "${BINARY}" ]]; then
  echo "ERROR: BINARY is not executable: ${BINARY}"
  exit 1
fi

export_resolved_cli_tokens admin

mkdir -p "${LOG_DIR}"
TURBO_LOG_DIR="${LOG_DIR}/tool-turbo-e2e"
rm -rf "${TURBO_LOG_DIR}"
mkdir -p "${TURBO_LOG_DIR}"

TAG="$(e2e_tag "tool-turbo")"
PROXY_URL="http://127.0.0.1:${PROXY_PORT}"

setup_e2e_traps "${BINARY}" "${WORKSPACE}"
register_tag_for_cleanup "${TAG}"

PROJECT_DIR="${TURBO_LOG_DIR}/turbo-project"
mkdir -p "${PROJECT_DIR}/packages/pkg-a" "${PROJECT_DIR}/packages/pkg-b"

cat > "${PROJECT_DIR}/package.json" <<'EOF'
{
  "name": "turbo-e2e-monorepo",
  "private": true,
  "packageManager": "npm@10.9.0",
  "workspaces": ["packages/*"]
}
EOF

cat > "${PROJECT_DIR}/turbo.json" <<'EOF'
{
  "$schema": "https://turbo.build/schema.json",
  "tasks": {
    "build": {
      "outputs": ["dist/**"],
      "dependsOn": ["^build"]
    }
  }
}
EOF

cat > "${PROJECT_DIR}/packages/pkg-a/package.json" <<'EOF'
{
  "name": "pkg-a",
  "version": "1.0.0",
  "scripts": {
    "build": "mkdir -p dist && echo \"pkg-a-built-$(date +%s%N)\" > dist/output.txt && echo 'pkg-a built'"
  }
}
EOF

cat > "${PROJECT_DIR}/packages/pkg-b/package.json" <<'EOF'
{
  "name": "pkg-b",
  "version": "1.0.0",
  "scripts": {
    "build": "mkdir -p dist && echo \"pkg-b-built-$(date +%s%N)\" > dist/output.txt && echo 'pkg-b built'"
  },
  "dependencies": {
    "pkg-a": "workspace:*"
  }
}
EOF

export BORINGCACHE_PROXY_METADATA_HINTS="project=e2e-tool-turbo,tool=turborepo"
start_proxy "${BINARY}" "${WORKSPACE}" "${TAG}" "${PROXY_PORT}" "${TURBO_LOG_DIR}/proxy.log"
wait_for_proxy "${PROXY_PORT}"

echo "=== Phase 1: Cold Turbo build (seed remote cache) ==="
COLD_CACHE_DIR="${TURBO_LOG_DIR}/turbo-cache-cold"
COLD_LOG="${TURBO_LOG_DIR}/cold-build.log"
COLD_START="$(date +%s)"
(
  cd "${PROJECT_DIR}"
  TURBO_API="${PROXY_URL}" \
  TURBO_TEAM="boringcache-e2e" \
  TURBO_TOKEN="e2e-token" \
    turbo run build --cache-dir="${COLD_CACHE_DIR}" --verbosity=2 2>&1 | tee "${COLD_LOG}"
)
COLD_END="$(date +%s)"
COLD_SECS="$((COLD_END - COLD_START))"
echo "Cold build completed in ${COLD_SECS}s"

assert_file_contains "${COLD_LOG}" "pkg-a built"
assert_file_contains "${COLD_LOG}" "pkg-b built"

COLD_PKG_A_OUTPUT="$(cat "${PROJECT_DIR}/packages/pkg-a/dist/output.txt")"
COLD_PKG_B_OUTPUT="$(cat "${PROJECT_DIR}/packages/pkg-b/dist/output.txt")"

rm -rf "${COLD_CACHE_DIR}"
rm -rf "${PROJECT_DIR}/packages/pkg-a/dist" "${PROJECT_DIR}/packages/pkg-b/dist"

echo "=== Phase 2: Warm Turbo build (remote cache hit) ==="
WARM_CACHE_DIR="${TURBO_LOG_DIR}/turbo-cache-warm"
WARM_LOG="${TURBO_LOG_DIR}/warm-build.log"
WARM_START="$(date +%s)"
(
  cd "${PROJECT_DIR}"
  TURBO_API="${PROXY_URL}" \
  TURBO_TEAM="boringcache-e2e" \
  TURBO_TOKEN="e2e-token" \
    turbo run build --cache-dir="${WARM_CACHE_DIR}" --verbosity=2 2>&1 | tee "${WARM_LOG}"
)
WARM_END="$(date +%s)"
WARM_SECS="$((WARM_END - WARM_START))"
echo "Warm build completed in ${WARM_SECS}s"

if grep -qi "cache hit\|FULL TURBO\|remote cache" "${WARM_LOG}"; then
  echo "  turbo remote cache hit confirmed"
else
  echo "  turbo build log does not show explicit cache hit markers (will verify via output comparison)"
fi

WARM_PKG_A_OUTPUT="$(cat "${PROJECT_DIR}/packages/pkg-a/dist/output.txt")"
WARM_PKG_B_OUTPUT="$(cat "${PROJECT_DIR}/packages/pkg-b/dist/output.txt")"

if [[ "${COLD_PKG_A_OUTPUT}" == "${WARM_PKG_A_OUTPUT}" ]]; then
  echo "  pkg-a output matches cold build (cache replay, not re-execution)"
else
  echo "ERROR: pkg-a output differs — task was re-executed instead of cache replay"
  echo "  cold: ${COLD_PKG_A_OUTPUT}"
  echo "  warm: ${WARM_PKG_A_OUTPUT}"
  exit 1
fi

if [[ "${COLD_PKG_B_OUTPUT}" == "${WARM_PKG_B_OUTPUT}" ]]; then
  echo "  pkg-b output matches cold build (cache replay, not re-execution)"
else
  echo "ERROR: pkg-b output differs — task was re-executed instead of cache replay"
  echo "  cold: ${COLD_PKG_B_OUTPUT}"
  echo "  warm: ${WARM_PKG_B_OUTPUT}"
  exit 1
fi

stop_proxy
dump_cache_ops_summary

if [[ "${BUDGET_REMOTE_TAG_HITS_MIN}" -gt 0 ]]; then
  if ! verify_remote_tag_visible "${BINARY}" "${WORKSPACE}" "${TAG}" "${TURBO_LOG_DIR}" \
    "${BUDGET_REMOTE_TAG_HITS_MIN}" 30 2 "$(proxy_log)"; then
    exit 1
  fi
  echo "  remote tag verified (hits=${REMOTE_TAG_CHECK_HITS:-0})"
fi

echo ""
echo "Turbo tool e2e passed. Cold=${COLD_SECS}s Warm=${WARM_SECS}s Logs: ${TURBO_LOG_DIR}"
