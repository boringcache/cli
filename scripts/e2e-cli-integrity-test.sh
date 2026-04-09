#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/e2e-helpers.sh"

CLI_REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BINARY="${BINARY:-${CLI_REPO_ROOT}/target/debug/boringcache}"
WORKSPACE="${WORKSPACE:?WORKSPACE is required}"
BORINGCACHE_API_URL="${BORINGCACHE_API_URL:-https://api.boringcache.com}"
LOG_DIR="${LOG_DIR:-.}"
RUN_ID="${GITHUB_RUN_ID:-local}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}"

if ! resolve_save_capable_token >/dev/null; then
  echo "ERROR: configure BORINGCACHE_SAVE_TOKEN"
  exit 1
fi

for dep in cmp grep mktemp readlink; do
  if ! command -v "${dep}" >/dev/null 2>&1; then
    echo "ERROR: required dependency not found: ${dep}"
    exit 1
  fi
done

if [[ ! -x "${BINARY}" ]]; then
  echo "ERROR: BINARY is not executable: ${BINARY}"
  exit 1
fi

mkdir -p "${LOG_DIR}"
E2E_LOG_DIR="${LOG_DIR}/cli-integrity-e2e"
rm -rf "${E2E_LOG_DIR}"
mkdir -p "${E2E_LOG_DIR}"
CLI_HOME="$(mktemp -d)"
CLI="${BINARY}"
TAGS_TO_DELETE=()

dump_logs() {
  set +e
  echo "=== CLI integrity e2e logs ==="
  if [[ -d "${E2E_LOG_DIR}" ]]; then
    shopt -s nullglob
    for log_file in "${E2E_LOG_DIR}"/*.log "${E2E_LOG_DIR}"/*.json; do
      echo "--- ${log_file} ---"
      tail -n 200 "${log_file}" || true
    done
    shopt -u nullglob
  fi
  echo "=== End CLI integrity e2e logs ==="
}

cleanup() {
  set +e
  export HOME="${CLI_HOME}"
  if [[ -x "${CLI}" && "${#TAGS_TO_DELETE[@]}" -gt 0 ]]; then
    for tag in "${TAGS_TO_DELETE[@]}"; do
      "${CLI}" delete --no-platform --no-git "${WORKSPACE}" "${tag}" \
        > "${E2E_LOG_DIR}/cleanup-${tag}.log" 2>&1 || true
    done
  fi
  rm -rf "${CLI_HOME}"
}

trap dump_logs ERR
trap cleanup EXIT

compute_sha256() {
  local path="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    local digest _
    read -r digest _ < <(sha256sum "${path}")
    printf '%s\n' "${digest}"
    return 0
  fi

  if command -v shasum >/dev/null 2>&1; then
    local digest _
    read -r digest _ < <(shasum -a 256 "${path}")
    printf '%s\n' "${digest}"
    return 0
  fi

  echo "ERROR: neither sha256sum nor shasum is available"
  exit 1
}

wait_for_visibility() {
  local tag="$1"
  local log_file="$2"
  for _ in $(seq 1 15); do
    if "${CLI}" check --no-platform --no-git --fail-on-miss "${WORKSPACE}" "${tag}" \
      > "${log_file}" 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "tag did not become visible in time: ${tag}"
  cat "${log_file}"
  exit 1
}

expect_restore_failure() {
  local tag="$1"
  local target="$2"
  local expected_pattern="$3"
  local log_file="$4"

  set +e
  "${CLI}" restore --no-platform --no-git --fail-on-cache-error "${WORKSPACE}" "${tag}:${target}" \
    > "${log_file}" 2>&1
  local status=$?
  set -e

  if [[ "${status}" -eq 0 ]]; then
    echo "expected restore to fail for tag ${tag}"
    cat "${log_file}"
    exit 1
  fi
  if ! grep -q "${expected_pattern}" "${log_file}"; then
    echo "restore failure log did not contain expected pattern: ${expected_pattern}"
    cat "${log_file}"
    exit 1
  fi
  if [[ -L "${target}/bin/swift" || -e "${target}/bin/swift" ]]; then
    echo "blocked symlink was restored unexpectedly for tag ${tag}"
    ls -la "${target}/bin" || true
    exit 1
  fi
}

export HOME="${CLI_HOME}"
bootstrap_cli_session "${CLI}" "${WORKSPACE}" "${BORINGCACHE_API_URL}" "${E2E_LOG_DIR}/auth.log" admin

TAG_ROOT="$(e2e_tag "cli-integrity")"

echo "=== Phase 0: verify downloaded CLI artifact checksum ==="
CHECKSUM_FILE="$(dirname "${CLI}")/boringcache.sha256"
if [[ ! -f "${CHECKSUM_FILE}" ]]; then
  echo "expected checksum file next to downloaded CLI artifact: ${CHECKSUM_FILE}"
  exit 1
fi
read -r EXPECTED_CHECKSUM _ < "${CHECKSUM_FILE}"
ACTUAL_CHECKSUM="$(compute_sha256 "${CLI}")"
if [[ -z "${EXPECTED_CHECKSUM}" || "${EXPECTED_CHECKSUM}" != "${ACTUAL_CHECKSUM}" ]]; then
  echo "downloaded CLI artifact checksum mismatch"
  echo "expected: ${EXPECTED_CHECKSUM:-<empty>}"
  echo "actual:   ${ACTUAL_CHECKSUM}"
  exit 1
fi
"${CLI}" --version > "${E2E_LOG_DIR}/artifact-version.log"

SAFE_TAG="${TAG_ROOT}-safe-relative"
SAFE_SRC="${E2E_LOG_DIR}/safe-src"
SAFE_RESTORE="${E2E_LOG_DIR}/safe-restore"
TAGS_TO_DELETE+=("${SAFE_TAG}")

mkdir -p "${SAFE_SRC}/bin" "${SAFE_SRC}/toolchains/6.1/usr/bin"
printf 'swift-stub-%s\n' "${RUN_ID}" > "${SAFE_SRC}/toolchains/6.1/usr/bin/swift"
chmod +x "${SAFE_SRC}/toolchains/6.1/usr/bin/swift"
ln -s ../toolchains/6.1/usr/bin/swift "${SAFE_SRC}/bin/swift"
ln -s swift "${SAFE_SRC}/bin/swiftc"

echo "=== Phase 1: allow in-root relative symlinks ==="
"${CLI}" save --no-platform --no-git "${WORKSPACE}" "${SAFE_TAG}:${SAFE_SRC}" \
  > "${E2E_LOG_DIR}/safe-save.log"
wait_for_visibility "${SAFE_TAG}" "${E2E_LOG_DIR}/safe-check.log"
"${CLI}" restore --no-platform --no-git "${WORKSPACE}" "${SAFE_TAG}:${SAFE_RESTORE}" \
  > "${E2E_LOG_DIR}/safe-restore.log"

if [[ ! -L "${SAFE_RESTORE}/bin/swift" ]]; then
  echo "expected restored swift path to be a symlink"
  exit 1
fi
if [[ "$(readlink "${SAFE_RESTORE}/bin/swift")" != "../toolchains/6.1/usr/bin/swift" ]]; then
  echo "restored swift symlink target did not match expected relative path"
  readlink "${SAFE_RESTORE}/bin/swift"
  exit 1
fi
if [[ "$(readlink "${SAFE_RESTORE}/bin/swiftc")" != "swift" ]]; then
  echo "restored swiftc symlink target did not match expected relative path"
  readlink "${SAFE_RESTORE}/bin/swiftc"
  exit 1
fi
cmp -s "${SAFE_SRC}/toolchains/6.1/usr/bin/swift" "${SAFE_RESTORE}/bin/swift"

ABS_TAG="${TAG_ROOT}-blocked-absolute"
ABS_SRC="${E2E_LOG_DIR}/blocked-absolute-src"
ABS_RESTORE="${E2E_LOG_DIR}/blocked-absolute-restore"
TAGS_TO_DELETE+=("${ABS_TAG}")

mkdir -p "${ABS_SRC}/bin"
printf 'blocked-absolute-%s\n' "${RUN_ID}" > "${ABS_SRC}/payload.txt"
ln -s /bin/sh "${ABS_SRC}/bin/swift"

echo "=== Phase 2: reject absolute symlinks ==="
"${CLI}" save --no-platform --no-git "${WORKSPACE}" "${ABS_TAG}:${ABS_SRC}" \
  > "${E2E_LOG_DIR}/blocked-absolute-save.log"
wait_for_visibility "${ABS_TAG}" "${E2E_LOG_DIR}/blocked-absolute-check.log"
expect_restore_failure \
  "${ABS_TAG}" \
  "${ABS_RESTORE}" \
  "Absolute symlink target is not allowed" \
  "${E2E_LOG_DIR}/blocked-absolute-restore.log"

ESCAPE_TAG="${TAG_ROOT}-blocked-escape"
ESCAPE_SRC="${E2E_LOG_DIR}/blocked-escape-src"
ESCAPE_RESTORE="${E2E_LOG_DIR}/blocked-escape-restore"
ESCAPE_EXTERNAL_DIR="${E2E_LOG_DIR}/outside/toolchain"
TAGS_TO_DELETE+=("${ESCAPE_TAG}")

mkdir -p "${ESCAPE_SRC}/bin"
mkdir -p "${ESCAPE_EXTERNAL_DIR}"
printf 'blocked-escape-%s\n' "${RUN_ID}" > "${ESCAPE_SRC}/payload.txt"
printf 'external-swift-%s\n' "${RUN_ID}" > "${ESCAPE_EXTERNAL_DIR}/swift"
ln -s ../../outside/toolchain/swift "${ESCAPE_SRC}/bin/swift"

echo "=== Phase 3: reject escaping relative symlinks ==="
"${CLI}" save --no-platform --no-git "${WORKSPACE}" "${ESCAPE_TAG}:${ESCAPE_SRC}" \
  > "${E2E_LOG_DIR}/blocked-escape-save.log"
wait_for_visibility "${ESCAPE_TAG}" "${E2E_LOG_DIR}/blocked-escape-check.log"
expect_restore_failure \
  "${ESCAPE_TAG}" \
  "${ESCAPE_RESTORE}" \
  "Symlink target escapes restore root" \
  "${E2E_LOG_DIR}/blocked-escape-restore.log"

echo "CLI integrity e2e passed. Logs: ${E2E_LOG_DIR}"
