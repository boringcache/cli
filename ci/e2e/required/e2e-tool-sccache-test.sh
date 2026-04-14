#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../e2e-helpers.sh"

CLI_REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BINARY="${BINARY:-${CLI_REPO_ROOT}/target/debug/boringcache}"
WORKSPACE="${WORKSPACE:?WORKSPACE is required}"
LOG_DIR="${LOG_DIR:-.}"
PROXY_PORT="${PROXY_PORT:-5058}"
RUN_ID="${GITHUB_RUN_ID:-local}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}"
SCCACHE_PORT_SEED="${SCCACHE_PORT_SEED:-$((4200 + (RANDOM % 2000)))}"
SCCACHE_SERVER_PORT="${SCCACHE_SERVER_PORT:-}"
BUDGET_REMOTE_TAG_HITS_MIN="${BUDGET_REMOTE_TAG_HITS_MIN:-1}"

require_save_capable_token

for dep in cargo sccache; do
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
SCCACHE_LOG_DIR="${LOG_DIR}/tool-sccache-e2e"
rm -rf "${SCCACHE_LOG_DIR}"
mkdir -p "${SCCACHE_LOG_DIR}"

TAG="$(e2e_tag "tool-sccache")"
PROXY_URL="http://127.0.0.1:${PROXY_PORT}"
if [[ -z "${SCCACHE_SERVER_PORT}" ]]; then
  SCCACHE_SERVER_PORT="$(next_available_sccache_port "${SCCACHE_PORT_SEED}" "${PROXY_PORT}")"
elif ! [[ "${SCCACHE_SERVER_PORT}" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: SCCACHE_SERVER_PORT must be a positive integer"
  exit 1
elif [[ "${SCCACHE_SERVER_PORT}" == "${PROXY_PORT}" ]]; then
  echo "ERROR: SCCACHE_SERVER_PORT (${SCCACHE_SERVER_PORT}) must differ from PROXY_PORT (${PROXY_PORT})"
  exit 1
fi

if (( SCCACHE_SERVER_PORT > 65535 )); then
  echo "ERROR: SCCACHE_SERVER_PORT must be <= 65535"
  exit 1
fi

setup_e2e_traps "${BINARY}" "${WORKSPACE}"
register_tag_for_cleanup "${TAG}"

PROJECT_DIR="${SCCACHE_LOG_DIR}/rust-project"
mkdir -p "${PROJECT_DIR}/src"

cat > "${PROJECT_DIR}/Cargo.toml" <<EOF
[package]
name = "sccache-e2e-project"
version = "0.1.0"
edition = "2024"
EOF

cat > "${PROJECT_DIR}/src/main.rs" <<'EOF'
fn main() {
    println!("result = {}", sccache_e2e_project::compute(42));
}
EOF

cat > "${PROJECT_DIR}/src/lib.rs" <<'EOF'
pub fn compute(n: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..n {
        result = result.wrapping_add(i.wrapping_mul(i));
    }
    result
}

pub fn factorial(n: u64) -> u64 {
    (1..=n).product()
}

pub fn fibonacci(n: u64) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n {
        let tmp = b;
        b = a.wrapping_add(b);
        a = tmp;
    }
    a
}
EOF

stop_sccache_server() {
  run_with_clean_sccache_env "SCCACHE_SERVER_PORT=${SCCACHE_SERVER_PORT}" sccache --stop-server >/dev/null 2>&1 || true
}
register_cleanup_callback stop_sccache_server

start_sccache_server() {
  local sccache_dir="$1"
  local sccache_control_log="${SCCACHE_LOG_DIR}/sccache-control.log"
  local sccache_error_log="${SCCACHE_LOG_DIR}/sccache-${SCCACHE_SERVER_PORT}.log"
  touch "${sccache_control_log}" "${sccache_error_log}"
  run_with_clean_sccache_env \
    "SCCACHE_DIR=${sccache_dir}" \
    "SCCACHE_WEBDAV_ENDPOINT=${PROXY_URL}/" \
    "SCCACHE_SERVER_PORT=${SCCACHE_SERVER_PORT}" \
    "SCCACHE_ERROR_LOG=${sccache_error_log}" \
    SCCACHE_LOG=info \
    sccache --start-server >> "${sccache_control_log}" 2>&1
  run_with_clean_sccache_env \
    "SCCACHE_DIR=${sccache_dir}" \
    "SCCACHE_SERVER_PORT=${SCCACHE_SERVER_PORT}" \
    "SCCACHE_ERROR_LOG=${sccache_error_log}" \
    sccache --zero-stats >> "${sccache_control_log}" 2>&1
}

export BORINGCACHE_PROXY_METADATA_HINTS="project=e2e-tool-sccache,tool=sccache"
start_proxy "${BINARY}" "${WORKSPACE}" "${TAG}" "${PROXY_PORT}" "${SCCACHE_LOG_DIR}/proxy.log"
wait_for_proxy "${PROXY_PORT}"
echo "Proxy port: ${PROXY_PORT}"
echo "sccache server port: ${SCCACHE_SERVER_PORT}"

echo "=== Phase 1: Cold Rust build (seed sccache via proxy) ==="
TARGET_DIR="${SCCACHE_LOG_DIR}/target-shared"
COLD_SCCACHE_DIR="${SCCACHE_LOG_DIR}/sccache-cold"
COLD_LOG="${SCCACHE_LOG_DIR}/cold-build.log"

stop_sccache_server
rm -rf "${TARGET_DIR}"
mkdir -p "${COLD_SCCACHE_DIR}"
start_sccache_server "${COLD_SCCACHE_DIR}"

COLD_START="$(date +%s)"
(
  cd "${PROJECT_DIR}"
  run_with_clean_sccache_env \
    "SCCACHE_DIR=${COLD_SCCACHE_DIR}" \
    "SCCACHE_WEBDAV_ENDPOINT=${PROXY_URL}/" \
    "SCCACHE_SERVER_PORT=${SCCACHE_SERVER_PORT}" \
    "SCCACHE_ERROR_LOG=${SCCACHE_LOG_DIR}/sccache-${SCCACHE_SERVER_PORT}.log" \
    SCCACHE_LOG=info \
    RUSTC_WRAPPER=sccache \
    CARGO_INCREMENTAL=0 \
    "CARGO_TARGET_DIR=${TARGET_DIR}" \
    cargo build --release 2>&1 | tee "${COLD_LOG}"
)
COLD_END="$(date +%s)"
COLD_SECS="$((COLD_END - COLD_START))"

run_with_clean_sccache_env "SCCACHE_SERVER_PORT=${SCCACHE_SERVER_PORT}" sccache --show-stats > "${SCCACHE_LOG_DIR}/cold-stats.txt" 2>&1
echo "Cold build completed in ${COLD_SECS}s"
cat "${SCCACHE_LOG_DIR}/cold-stats.txt"

cold_requests="$(grep -o 'Compile requests[[:space:]]*[0-9]*' "${SCCACHE_LOG_DIR}/cold-stats.txt" | grep -o '[0-9]*$' || echo 0)"
cold_hits="$(grep -o 'Cache hits[[:space:]]*[0-9]*' "${SCCACHE_LOG_DIR}/cold-stats.txt" | grep -o '[0-9]*$' || echo 0)"
cold_misses="$(grep -o 'Cache misses[[:space:]]*[0-9]*' "${SCCACHE_LOG_DIR}/cold-stats.txt" | grep -o '[0-9]*$' || echo 0)"
echo "  cold: requests=${cold_requests} hits=${cold_hits} misses=${cold_misses}"

echo "=== Phase 2: Warm Rust build (sccache cache hit via proxy) ==="
WARM_SCCACHE_DIR="${SCCACHE_LOG_DIR}/sccache-warm"
WARM_LOG="${SCCACHE_LOG_DIR}/warm-build.log"

stop_sccache_server
rm -rf "${TARGET_DIR}"
mkdir -p "${WARM_SCCACHE_DIR}"
start_sccache_server "${WARM_SCCACHE_DIR}"

WARM_START="$(date +%s)"
(
  cd "${PROJECT_DIR}"
  run_with_clean_sccache_env \
    "SCCACHE_DIR=${WARM_SCCACHE_DIR}" \
    "SCCACHE_WEBDAV_ENDPOINT=${PROXY_URL}/" \
    "SCCACHE_SERVER_PORT=${SCCACHE_SERVER_PORT}" \
    "SCCACHE_ERROR_LOG=${SCCACHE_LOG_DIR}/sccache-${SCCACHE_SERVER_PORT}.log" \
    SCCACHE_LOG=info \
    RUSTC_WRAPPER=sccache \
    CARGO_INCREMENTAL=0 \
    "CARGO_TARGET_DIR=${TARGET_DIR}" \
    cargo build --release 2>&1 | tee "${WARM_LOG}"
)
WARM_END="$(date +%s)"
WARM_SECS="$((WARM_END - WARM_START))"

run_with_clean_sccache_env "SCCACHE_SERVER_PORT=${SCCACHE_SERVER_PORT}" sccache --show-stats > "${SCCACHE_LOG_DIR}/warm-stats.txt" 2>&1
echo "Warm build completed in ${WARM_SECS}s"
cat "${SCCACHE_LOG_DIR}/warm-stats.txt"

warm_hits="$(grep -o 'Cache hits[[:space:]]*[0-9]*' "${SCCACHE_LOG_DIR}/warm-stats.txt" | grep -o '[0-9]*$' || echo 0)"
echo "  warm: hits=${warm_hits}"

if [[ "${warm_hits}" -gt 0 ]]; then
  echo "  sccache cache hit confirmed (hits=${warm_hits})"
else
  echo "ERROR: no sccache cache hits on warm build"
  exit 1
fi

stop_sccache_server
stop_proxy
dump_cache_ops_summary

if [[ "${BUDGET_REMOTE_TAG_HITS_MIN}" -gt 0 ]]; then
  if ! verify_remote_tag_visible "${BINARY}" "${WORKSPACE}" "${TAG}" "${SCCACHE_LOG_DIR}" \
    "${BUDGET_REMOTE_TAG_HITS_MIN}" "${REMOTE_TAG_VERIFY_ATTEMPTS}" "${REMOTE_TAG_VERIFY_SLEEP_SECS}" "$(proxy_log)"; then
    exit 1
  fi
  echo "  remote tag verified (hits=${REMOTE_TAG_CHECK_HITS:-0})"
fi

echo ""
echo "sccache tool e2e passed. Cold=${COLD_SECS}s Warm=${WARM_SECS}s hits=${warm_hits} Logs: ${SCCACHE_LOG_DIR}"
