#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../e2e-helpers.sh"

CLI_REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BINARY="${BINARY:-${CLI_REPO_ROOT}/target/debug/boringcache}"
WORKSPACE="${WORKSPACE:?WORKSPACE is required}"
LOG_DIR="${LOG_DIR:-.}"
PROXY_PORT="${PROXY_PORT:-4228}"
BUDGET_REMOTE_TAG_HITS_MIN="${BUDGET_REMOTE_TAG_HITS_MIN:-1}"

require_save_capable_token

for dep in node npm python3; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: required dependency not found: ${dep}"
    exit 1
  fi
done

if ! command -v nx >/dev/null 2>&1; then
  echo "Installing nx..."
  npm install -g nx 2>&1 | tail -n 3
fi

if [[ ! -x "${BINARY}" ]]; then
  echo "ERROR: BINARY is not executable: ${BINARY}"
  exit 1
fi

realpath_py() {
  python3 - "$1" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
}

export_resolved_cli_tokens admin

mkdir -p "${LOG_DIR}"
NX_LOG_DIR="${LOG_DIR}/tool-nx-e2e"
rm -rf "${NX_LOG_DIR}"
mkdir -p "${NX_LOG_DIR}"

TAG="$(e2e_tag "tool-nx")"
PROXY_URL="http://127.0.0.1:${PROXY_PORT}"

setup_e2e_traps "${BINARY}" "${WORKSPACE}"
register_tag_for_cleanup "${TAG}"

NX_BIN_REAL="$(realpath_py "$(command -v nx)")"
NX_PACKAGE_DIR="$(cd "$(dirname "${NX_BIN_REAL}")/.." && pwd)"
PROJECT_DIR="${NX_LOG_DIR}/nx-project"
mkdir -p "${PROJECT_DIR}/node_modules"
ln -s "${NX_PACKAGE_DIR}" "${PROJECT_DIR}/node_modules/nx"

cat > "${PROJECT_DIR}/package.json" <<'EOF'
{
  "name": "nx-remote-e2e",
  "private": true,
  "version": "1.0.0"
}
EOF

cat > "${PROJECT_DIR}/nx.json" <<'EOF'
{
  "$schema": "./node_modules/nx/schemas/nx-schema.json",
  "namedInputs": {
    "default": [
      "{workspaceRoot}/nx.json",
      "{projectRoot}/package.json",
      "{projectRoot}/project.json",
      "{projectRoot}/build.sh"
    ]
  },
  "targetDefaults": {
    "build": {
      "cache": true,
      "inputs": ["default"]
    }
  }
}
EOF

cat > "${PROJECT_DIR}/build.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

count=0
if [[ -f "${MARKER_FILE}" ]]; then
  count="$(cat "${MARKER_FILE}")"
fi
count="$((count + 1))"

echo "${count}" > "${MARKER_FILE}"
mkdir -p dist
echo "nx-${count}" > dist/out.txt
EOF
chmod +x "${PROJECT_DIR}/build.sh"

cat > "${PROJECT_DIR}/project.json" <<'EOF'
{
  "name": "demo",
  "root": ".",
  "targets": {
    "build": {
      "executor": "nx:run-commands",
      "outputs": ["{projectRoot}/dist"],
      "options": {
        "command": "bash ./build.sh"
      }
    }
  }
}
EOF

export BORINGCACHE_PROXY_METADATA_HINTS="project=e2e-tool-nx,tool=nx"
start_proxy "${BINARY}" "${WORKSPACE}" "${TAG}" "${PROXY_PORT}" "${NX_LOG_DIR}/proxy.log"
wait_for_proxy "${PROXY_PORT}"

NX_MARKER="${NX_LOG_DIR}/nx-marker.txt"
NX_AUTH_TOKEN="nx-e2e-token"

echo "=== Phase 1: Cold Nx build (seed remote cache) ==="
COLD_CACHE_DIR="${NX_LOG_DIR}/nx-cache-cold"
COLD_LOG="${NX_LOG_DIR}/cold-build.log"
COLD_START="$(date +%s)"
(
  cd "${PROJECT_DIR}"
  MARKER_FILE="${NX_MARKER}" \
  NX_DAEMON=false \
  NX_CACHE_DIRECTORY="${COLD_CACHE_DIR}" \
  NX_SELF_HOSTED_REMOTE_CACHE_SERVER="${PROXY_URL}" \
  NX_SELF_HOSTED_REMOTE_CACHE_ACCESS_TOKEN="${NX_AUTH_TOKEN}" \
    nx run demo:build --verbose 2>&1 | tee "${COLD_LOG}"
)
COLD_END="$(date +%s)"
COLD_SECS="$((COLD_END - COLD_START))"
echo "Cold build completed in ${COLD_SECS}s"

if [[ "$(cat "${NX_MARKER}")" != "1" ]]; then
  echo "ERROR: nx cold run did not execute exactly once"
  cat "${COLD_LOG}"
  exit 1
fi

if [[ ! -s "${PROJECT_DIR}/dist/out.txt" ]]; then
  echo "ERROR: nx cold run did not write dist/out.txt"
  cat "${COLD_LOG}"
  exit 1
fi
COLD_OUTPUT="$(cat "${PROJECT_DIR}/dist/out.txt")"

# Nx keeps local cache metadata outside the explicit cache directory. Clear it so
# the warm phase has to materialize from the remote proxy path.
(
  cd "${PROJECT_DIR}"
  NX_DAEMON=false nx reset --onlyCache > "${NX_LOG_DIR}/nx-reset.log" 2>&1
)
rm -rf "${COLD_CACHE_DIR}" "${PROJECT_DIR}/dist"

echo "=== Phase 2: Warm Nx build (remote cache hit) ==="
WARM_CACHE_DIR="${NX_LOG_DIR}/nx-cache-warm"
WARM_LOG="${NX_LOG_DIR}/warm-build.log"
WARM_START="$(date +%s)"
(
  cd "${PROJECT_DIR}"
  MARKER_FILE="${NX_MARKER}" \
  NX_DAEMON=false \
  NX_CACHE_DIRECTORY="${WARM_CACHE_DIR}" \
  NX_SELF_HOSTED_REMOTE_CACHE_SERVER="${PROXY_URL}" \
  NX_SELF_HOSTED_REMOTE_CACHE_ACCESS_TOKEN="${NX_AUTH_TOKEN}" \
    nx run demo:build --verbose 2>&1 | tee "${WARM_LOG}"
)
WARM_END="$(date +%s)"
WARM_SECS="$((WARM_END - WARM_START))"
echo "Warm build completed in ${WARM_SECS}s"

if [[ "$(cat "${NX_MARKER}")" != "1" ]]; then
  echo "ERROR: nx warm run re-executed instead of using remote cache"
  cat "${WARM_LOG}"
  exit 1
fi

if [[ ! -s "${PROJECT_DIR}/dist/out.txt" ]]; then
  echo "ERROR: nx warm cache hit did not restore dist/out.txt"
  cat "${WARM_LOG}"
  exit 1
fi
WARM_OUTPUT="$(cat "${PROJECT_DIR}/dist/out.txt")"
if [[ "${COLD_OUTPUT}" != "${WARM_OUTPUT}" ]]; then
  echo "ERROR: nx warm output differs from cold output"
  echo "  cold: ${COLD_OUTPUT}"
  echo "  warm: ${WARM_OUTPUT}"
  exit 1
fi

stop_proxy
dump_cache_ops_summary

if [[ "${BUDGET_REMOTE_TAG_HITS_MIN}" -gt 0 ]]; then
  if ! verify_remote_tag_visible "${BINARY}" "${WORKSPACE}" "${TAG}" "${NX_LOG_DIR}" \
    "${BUDGET_REMOTE_TAG_HITS_MIN}" "${REMOTE_TAG_VERIFY_ATTEMPTS}" "${REMOTE_TAG_VERIFY_SLEEP_SECS}" "$(proxy_log)"; then
    exit 1
  fi
  echo "  remote tag verified (hits=${REMOTE_TAG_CHECK_HITS:-0})"
fi

echo ""
echo "Nx tool e2e passed. Cold=${COLD_SECS}s Warm=${WARM_SECS}s Logs: ${NX_LOG_DIR}"
