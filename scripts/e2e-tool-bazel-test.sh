#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/e2e-helpers.sh"

BINARY="${BINARY:-./target/debug/boringcache}"
WORKSPACE="${WORKSPACE:?WORKSPACE is required}"
LOG_DIR="${LOG_DIR:-.}"
PROXY_PORT="${PROXY_PORT:-5059}"
RUN_ID="${GITHUB_RUN_ID:-local}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}"
BUDGET_REMOTE_TAG_HITS_MIN="${BUDGET_REMOTE_TAG_HITS_MIN:-1}"

require_save_capable_token

for dep in bazel curl; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    if [[ "$dep" == "bazel" ]] && command -v bazelisk >/dev/null 2>&1; then
      continue
    fi
    echo "ERROR: required dependency not found: ${dep}"
    exit 1
  fi
done

BAZEL_CMD="bazel"
if ! command -v bazel >/dev/null 2>&1 && command -v bazelisk >/dev/null 2>&1; then
  BAZEL_CMD="bazelisk"
fi

if [[ ! -x "${BINARY}" ]]; then
  echo "ERROR: BINARY is not executable: ${BINARY}"
  exit 1
fi

export_resolved_cli_tokens

mkdir -p "${LOG_DIR}"
BAZEL_LOG_DIR="${LOG_DIR}/tool-bazel-e2e"
rm -rf "${BAZEL_LOG_DIR}"
mkdir -p "${BAZEL_LOG_DIR}"

TAG="$(e2e_tag "tool-bazel")"
PROXY_URL="http://127.0.0.1:${PROXY_PORT}"

setup_e2e_traps "${BINARY}" "${WORKSPACE}"
register_tag_for_cleanup "${TAG}"

PROJECT_DIR="${BAZEL_LOG_DIR}/bazel-project"
mkdir -p "${PROJECT_DIR}"

cat > "${PROJECT_DIR}/MODULE.bazel" <<'EOF'
module(name = "e2e_test", version = "0.1.0")
EOF

cat > "${PROJECT_DIR}/.bazelversion" <<'EOF'
7.6.1
EOF

cat > "${PROJECT_DIR}/BUILD.bazel" <<'BUILDFILE'
genrule(
    name = "emit",
    srcs = ["input.txt"],
    outs = ["output.txt"],
    cmd = "cp $< $@ && echo 'generated' >> $@",
)

genrule(
    name = "transform",
    srcs = ["input.txt"],
    outs = ["transformed.txt"],
    cmd = "cat $< | tr 'a-z' 'A-Z' > $@",
)

genrule(
    name = "hash",
    srcs = ["input.txt"],
    outs = ["hashed.txt"],
    cmd = "sha256sum $< > $@",
)
BUILDFILE

printf 'hello from boringcache bazel e2e test %s\n' "${RUN_ID}" > "${PROJECT_DIR}/input.txt"

bazel_cleanup() {
  (cd "${PROJECT_DIR}" && ${BAZEL_CMD} shutdown 2>/dev/null || true)
}
register_cleanup_callback bazel_cleanup

export BORINGCACHE_PROXY_METADATA_HINTS="project=e2e-tool-bazel,tool=bazel"
start_proxy "${BINARY}" "${WORKSPACE}" "${TAG}" "${PROXY_PORT}" "${BAZEL_LOG_DIR}/proxy.log"
wait_for_proxy "${PROXY_PORT}"

COLD_OUTPUT_BASE="${BAZEL_LOG_DIR}/output-base-cold"
WARM_OUTPUT_BASE="${BAZEL_LOG_DIR}/output-base-warm"

echo "=== Phase 1: Cold Bazel build (seed remote cache) ==="
COLD_LOG="${BAZEL_LOG_DIR}/cold-build.log"
COLD_START="$(date +%s)"
(
  cd "${PROJECT_DIR}"
  ${BAZEL_CMD} \
    --output_base="${COLD_OUTPUT_BASE}" \
    build \
    --remote_cache="${PROXY_URL}" \
    --remote_upload_local_results \
    //:emit //:transform //:hash 2>&1 | tee "${COLD_LOG}"
)
COLD_END="$(date +%s)"
COLD_SECS="$((COLD_END - COLD_START))"
echo "Cold build completed in ${COLD_SECS}s"

if [[ -f "${COLD_OUTPUT_BASE}/execroot/_main/bazel-out/k8-fastbuild/bin/output.txt" ]]; then
  echo "  cold build output verified"
fi

echo "=== Phase 2: Warm Bazel build (remote cache hit) ==="
WARM_LOG="${BAZEL_LOG_DIR}/warm-build.log"
WARM_START="$(date +%s)"
(
  cd "${PROJECT_DIR}"
  ${BAZEL_CMD} \
    --output_base="${WARM_OUTPUT_BASE}" \
    build \
    --remote_cache="${PROXY_URL}" \
    //:emit //:transform //:hash 2>&1 | tee "${WARM_LOG}"
)
WARM_END="$(date +%s)"
WARM_SECS="$((WARM_END - WARM_START))"
echo "Warm build completed in ${WARM_SECS}s"

remote_hits=0
if grep -q "remote cache hit" "${WARM_LOG}" 2>/dev/null; then
  remote_hits="$(grep -c "remote cache hit" "${WARM_LOG}" || echo 0)"
  echo "  remote cache hits: ${remote_hits}"
fi

if grep -q "0 processes" "${WARM_LOG}" 2>/dev/null || [[ "${remote_hits}" -gt 0 ]]; then
  echo "  warm build used remote cache (no local re-execution)"
else
  echo "ERROR: warm build re-executed actions locally instead of using remote cache"
  cat "${WARM_LOG}"
  exit 1
fi

(cd "${PROJECT_DIR}" && ${BAZEL_CMD} --output_base="${COLD_OUTPUT_BASE}" shutdown 2>/dev/null || true)
(cd "${PROJECT_DIR}" && ${BAZEL_CMD} --output_base="${WARM_OUTPUT_BASE}" shutdown 2>/dev/null || true)

stop_proxy
dump_cache_ops_summary

if [[ "${BUDGET_REMOTE_TAG_HITS_MIN}" -gt 0 ]]; then
  verify_remote_tag_visible "${BINARY}" "${WORKSPACE}" "${TAG}" "${BAZEL_LOG_DIR}" \
    "${BUDGET_REMOTE_TAG_HITS_MIN}" 30 2 "$(proxy_log)"
  echo "  remote tag verified (hits=${REMOTE_TAG_CHECK_HITS:-0})"
fi

echo ""
echo "Bazel tool e2e passed. Cold=${COLD_SECS}s Warm=${WARM_SECS}s Logs: ${BAZEL_LOG_DIR}"
