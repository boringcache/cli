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
RUN_SHA="${GITHUB_SHA:-localsha}"
MOUNT_SHUTDOWN_WAIT_SECS="${MOUNT_SHUTDOWN_WAIT_SECS:-20}"
CLI_CONTROL_PLANE_RETRY_ATTEMPTS="${CLI_CONTROL_PLANE_RETRY_ATTEMPTS:-2}"
CLI_CONTROL_PLANE_RETRY_DELAY_SECS="${CLI_CONTROL_PLANE_RETRY_DELAY_SECS:-2}"

require_positive() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: ${name} must be a positive integer"
    exit 1
  fi
}

require_positive "MOUNT_SHUTDOWN_WAIT_SECS" "$MOUNT_SHUTDOWN_WAIT_SECS"
require_positive "CLI_CONTROL_PLANE_RETRY_ATTEMPTS" "$CLI_CONTROL_PLANE_RETRY_ATTEMPTS"
require_positive "CLI_CONTROL_PLANE_RETRY_DELAY_SECS" "$CLI_CONTROL_PLANE_RETRY_DELAY_SECS"

if ! resolve_save_capable_token >/dev/null; then
  echo "ERROR: configure BORINGCACHE_SAVE_TOKEN"
  exit 1
fi

file_mode_octal() {
  local path="$1"
  if stat -c '%a' "$path" >/dev/null 2>&1; then
    stat -c '%a' "$path"
  else
    stat -f '%Lp' "$path"
  fi
}

for dep in jq stat mktemp grep cmp curl pgrep script sh; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: required dependency not found: ${dep}"
    exit 1
  fi
done

children_of_pid() {
  pgrep -P "$1" 2>/dev/null || true
}

signal_pid_tree() {
  local pid="$1"
  local signal_name="$2"
  local child
  for child in $(children_of_pid "$pid"); do
    signal_pid_tree "$child" "$signal_name"
  done
  kill -s "$signal_name" "$pid" >/dev/null 2>&1 || true
}

stop_pid_tree() {
  local pid="$1"
  local label="$2"
  local wait_secs="$3"
  local deadline
  if [[ -z "${pid:-}" ]]; then
    return 0
  fi
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    return 0
  fi
  signal_pid_tree "$pid" TERM
  deadline=$((SECONDS + wait_secs))
  while kill -0 "$pid" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "WARNING: ${label} ${pid} did not exit after ${wait_secs}s, sending SIGKILL"
      signal_pid_tree "$pid" KILL
      break
    fi
    sleep 1
  done
  wait "$pid" >/dev/null 2>&1 || true
}

if [[ ! -x "${BINARY}" ]]; then
  echo "ERROR: BINARY is not executable: ${BINARY}"
  exit 1
fi

mkdir -p "${LOG_DIR}"
CLI_LOG_DIR="${LOG_DIR}/cli-command-e2e"
mkdir -p "${CLI_LOG_DIR}"
CLI_HOME="$(mktemp -d)"
export HOME="${CLI_HOME}"
CLI="${BINARY}"

dump_cli_debug_logs() {
  set +e
  echo "=== CLI core debug logs ==="
  if [[ -d "${CLI_LOG_DIR}" ]]; then
    shopt -s nullglob
    for log_file in "${CLI_LOG_DIR}"/*.log "${CLI_LOG_DIR}"/*.json; do
      echo "--- ${log_file} ---"
      tail -n 200 "${log_file}" || true
    done
    shopt -u nullglob
  fi
  if [[ -f "${MOUNT_LOG:-}" ]]; then
    echo "--- ${MOUNT_LOG} ---"
    tail -n 200 "${MOUNT_LOG}" || true
  fi
  echo "=== End CLI core debug logs ==="
}

dump_cli_debug_logs_on_failure() {
  local status="$1"
  if [[ "$status" -ne 0 ]]; then
    dump_cli_debug_logs
  fi
}

trap 'dump_cli_debug_logs_on_failure "$?"' EXIT

run_cli_control_plane_capture() {
  local label="$1"
  local output_path="$2"
  shift 2

  local stderr_log="${output_path}.stderr.log"
  local stdout_tmp
  local attempt
  local status=1

  rm -f "${stderr_log}"

  for ((attempt = 1; attempt <= CLI_CONTROL_PLANE_RETRY_ATTEMPTS; attempt++)); do
    stdout_tmp="$(mktemp)"
    if "$@" > "${stdout_tmp}" 2> "${stderr_log}"; then
      mv "${stdout_tmp}" "${output_path}"
      rm -f "${stderr_log}"
      return 0
    fi
    status=$?
    rm -f "${stdout_tmp}"
    if (( attempt == CLI_CONTROL_PLANE_RETRY_ATTEMPTS )); then
      echo "ERROR: ${label} failed after ${CLI_CONTROL_PLANE_RETRY_ATTEMPTS} attempt(s)"
      if [[ -s "${stderr_log}" ]]; then
        tail -n 80 "${stderr_log}" || true
      fi
      return "${status}"
    fi
    echo "WARNING: ${label} failed on attempt ${attempt}/${CLI_CONTROL_PLANE_RETRY_ATTEMPTS}; retrying in ${CLI_CONTROL_PLANE_RETRY_DELAY_SECS}s"
    if [[ -s "${stderr_log}" ]]; then
      tail -n 20 "${stderr_log}" || true
    fi
    sleep "${CLI_CONTROL_PLANE_RETRY_DELAY_SECS}"
  done

  return "${status}"
}

bootstrap_cli_session "${CLI}" "${WORKSPACE}" "${BORINGCACHE_API_URL}" "${CLI_LOG_DIR}/auth.log" admin
"${CLI}" config get default_workspace > "${CLI_LOG_DIR}/config-get-default-workspace.log"
grep -q "${WORKSPACE}" "${CLI_LOG_DIR}/config-get-default-workspace.log"
"${CLI}" config list --json > "${CLI_LOG_DIR}/config-list.json"
run_cli_control_plane_capture "workspaces smoke" "${CLI_LOG_DIR}/workspaces.json" \
  "${CLI}" workspaces --json
run_cli_control_plane_capture "ls smoke" "${CLI_LOG_DIR}/ls.json" \
  "${CLI}" ls --limit 1 --json

run_dashboard_smoke() {
  local log_file="$1"
  local dashboard_cmd
  printf -v dashboard_cmd '%q ' env -u CI "${CLI}" dashboard "${WORKSPACE}" --interval 5
  dashboard_cmd="${dashboard_cmd% }"

  if script -qec "printf ready >/dev/null" /dev/null >/dev/null 2>&1; then
    ({ sleep 2; printf 'q' || true; } 2>/dev/null) |
      TERM=xterm-256color COLUMNS=80 LINES=24 \
      script -qec "${dashboard_cmd}" "${log_file}" >/dev/null 2>&1

    if [[ ! -s "${log_file}" ]]; then
      echo "dashboard smoke did not capture any terminal output"
      exit 1
    fi
    assert_file_not_contains "${log_file}" "interactive terminal"
    assert_file_not_contains "${log_file}" "needs a larger terminal"
  else
    ({ sleep 2; printf 'q' || true; } 2>/dev/null) |
      TERM=xterm-256color COLUMNS=80 LINES=24 \
      script -q "${log_file}" "${CLI}" dashboard "${WORKSPACE}" --interval 5 >/dev/null 2>&1

    if [[ ! -s "${log_file}" ]]; then
      echo "dashboard smoke did not capture any terminal output"
      exit 1
    fi
  fi
}

TAG_ROOT="$(e2e_tag "cli-core")"
TAG_DIR="${TAG_ROOT}-dir"
TAG_FILE="${TAG_ROOT}-file"
TAG_MOUNT="${TAG_ROOT}-mount"
SRC_DIR="${CLI_LOG_DIR}/src"
RESTORE_DIR="${CLI_LOG_DIR}/restore-dir"
SINGLE_FILE="${CLI_LOG_DIR}/single.txt"
RESTORE_FILE_DIR="${CLI_LOG_DIR}/restore-file"
MOUNT_SRC_DIR="${CLI_LOG_DIR}/mount-src"
MOUNT_WATCH_DIR="${CLI_LOG_DIR}/mount-watch"
MOUNT_RESTORE_DIR="${CLI_LOG_DIR}/mount-restore"
MOUNT_LOG="${CLI_LOG_DIR}/mount.log"
IDENTITY_FILE="${CLI_LOG_DIR}/age-identity.txt"
MISSING_TAG="${TAG_ROOT}-missing"

mkdir -p "${SRC_DIR}"
printf 'cli-e2e-dir-%s\n' "${RUN_SHA}" > "${SRC_DIR}/a.txt"
printf 'cli-e2e-nested-%s\n' "${RUN_ID}" > "${SRC_DIR}/nested.txt"
printf 'cli-e2e-file-%s\n' "${RUN_ATTEMPT}" > "${SINGLE_FILE}"

echo "=== Phase 1: Save/restore/delete (archive cache path) ==="
"${CLI}" save "${E2E_TAG_SCOPE_FLAGS[@]}" "${WORKSPACE}" "${TAG_DIR}:${SRC_DIR},${TAG_FILE}:${SINGLE_FILE}" > "${CLI_LOG_DIR}/save.log"
save_visible=0
for _ in $(seq 1 10); do
  if "${CLI}" check "${E2E_TAG_SCOPE_FLAGS[@]}" --fail-on-miss "${WORKSPACE}" "${TAG_DIR},${TAG_FILE}" > "${CLI_LOG_DIR}/check-hit.log" 2>&1; then
    save_visible=1
    break
  fi
  sleep 1
done
if [[ "${save_visible}" != "1" ]]; then
  echo "saved tags did not become visible in time"
  cat "${CLI_LOG_DIR}/check-hit.log"
  exit 1
fi

echo "=== Phase 1b: dashboard compact TUI smoke ==="
run_dashboard_smoke "${CLI_LOG_DIR}/dashboard.log"

"${CLI}" restore "${E2E_TAG_SCOPE_FLAGS[@]}" "${WORKSPACE}" "${TAG_DIR}:${RESTORE_DIR},${TAG_FILE}:${RESTORE_FILE_DIR}" > "${CLI_LOG_DIR}/restore.log"

cmp -s "${SRC_DIR}/a.txt" "${RESTORE_DIR}/a.txt"
cmp -s "${SRC_DIR}/nested.txt" "${RESTORE_DIR}/nested.txt"
cmp -s "${SINGLE_FILE}" "${RESTORE_FILE_DIR}/single.txt"

set +e
"${CLI}" restore "${E2E_TAG_SCOPE_FLAGS[@]}" --lookup-only --fail-on-cache-miss "${WORKSPACE}" "${MISSING_TAG}:${CLI_LOG_DIR}/missing-target" > "${CLI_LOG_DIR}/restore-miss.log" 2>&1
restore_miss_status=$?
set -e
if [[ "${restore_miss_status}" -eq 0 ]]; then
  echo "expected restore miss to fail with non-zero exit code"
  cat "${CLI_LOG_DIR}/restore-miss.log"
  exit 1
fi
if ! grep -q "Cache miss for tags" "${CLI_LOG_DIR}/restore-miss.log"; then
  echo "restore miss log did not include cache miss summary"
  cat "${CLI_LOG_DIR}/restore-miss.log"
  exit 1
fi

"${CLI}" delete "${E2E_TAG_SCOPE_FLAGS[@]}" "${WORKSPACE}" "${TAG_DIR},${TAG_FILE}" > "${CLI_LOG_DIR}/delete.log"
deleted_confirmed=0
for _ in $(seq 1 10); do
  if "${CLI}" check "${E2E_TAG_SCOPE_FLAGS[@]}" --fail-on-miss "${WORKSPACE}" "${TAG_DIR},${TAG_FILE}" > "${CLI_LOG_DIR}/check-after-delete.log" 2>&1; then
    sleep 1
    continue
  fi
  deleted_confirmed=1
  break
done
if [[ "${deleted_confirmed}" != "1" ]]; then
  echo "deleted tags were still visible after retries"
  cat "${CLI_LOG_DIR}/check-after-delete.log"
  exit 1
fi

RUN_TAG="${TAG_ROOT}-run"
RUN_PROXY_TAG="${TAG_ROOT}-run-proxy"
RUN_SEED_DIR="${CLI_LOG_DIR}/run-seed"
RUN_TARGET_DIR="${CLI_LOG_DIR}/run-target"
RUN_VERIFY_DIR="${CLI_LOG_DIR}/run-verify"
RUN_MISS_SENTINEL="${CLI_LOG_DIR}/run-miss-sentinel.txt"
REPO_CONFIG_DIR="${CLI_LOG_DIR}/repo-config-run"
REPO_CONFIG_BIN_DIR="${REPO_CONFIG_DIR}/bin"
REPO_CONFIG_TAG="${TAG_ROOT}-repo-config-bundler"
REPO_CONFIG_PROFILE="bundle-install"

echo "=== Phase 2: run command cache integration ==="
mkdir -p "${RUN_SEED_DIR}"
printf 'run-warm-cache-%s\n' "${RUN_SHA}" > "${RUN_SEED_DIR}/restored.txt"
"${CLI}" save "${E2E_TAG_SCOPE_FLAGS[@]}" "${WORKSPACE}" "${RUN_TAG}:${RUN_SEED_DIR}" > "${CLI_LOG_DIR}/run-seed-save.log"

run_seed_visible=0
for _ in $(seq 1 10); do
  if "${CLI}" check "${E2E_TAG_SCOPE_FLAGS[@]}" --fail-on-miss "${WORKSPACE}" "${RUN_TAG}" > "${CLI_LOG_DIR}/run-seed-check.log" 2>&1; then
    run_seed_visible=1
    break
  fi
  sleep 1
done
if [[ "${run_seed_visible}" != "1" ]]; then
  echo "run seed tag did not become visible in time"
  cat "${CLI_LOG_DIR}/run-seed-check.log"
  exit 1
fi

RUN_ARCHIVE_SCRIPT="${CLI_LOG_DIR}/run-archive-child.sh"
cat > "${RUN_ARCHIVE_SCRIPT}" <<EOF
#!/usr/bin/env sh
set -eu
[ "\$(cat "\$1/restored.txt")" = "run-warm-cache-${RUN_SHA}" ] || exit 27
printf "run-generated-%s\n" "${RUN_ID}" > "\$1/generated.txt"
EOF
chmod +x "${RUN_ARCHIVE_SCRIPT}"
"${CLI}" run "${E2E_TAG_SCOPE_FLAGS[@]}" --force --fail-on-cache-error "${WORKSPACE}" "${RUN_TAG}:${RUN_TARGET_DIR}" -- sh "${RUN_ARCHIVE_SCRIPT}" "${RUN_TARGET_DIR}" > "${CLI_LOG_DIR}/run-archive.log"

"${CLI}" restore "${E2E_TAG_SCOPE_FLAGS[@]}" "${WORKSPACE}" "${RUN_TAG}:${RUN_VERIFY_DIR}" > "${CLI_LOG_DIR}/run-verify-restore.log"
if [[ ! -f "${RUN_VERIFY_DIR}/generated.txt" ]]; then
  echo "run verify restore is missing generated.txt"
  cat "${CLI_LOG_DIR}/run-verify-restore.log"
  exit 1
fi
if ! grep -q "run-generated-${RUN_ID}" "${RUN_VERIFY_DIR}/generated.txt"; then
  echo "run verify restore missing expected marker in generated.txt"
  cat "${RUN_VERIFY_DIR}/generated.txt"
  exit 1
fi

set +e
"${CLI}" run "${E2E_TAG_SCOPE_FLAGS[@]}" --fail-on-cache-miss "${WORKSPACE}" "${MISSING_TAG}:${CLI_LOG_DIR}/run-missing-target" -- sh -ec 'printf "unexpected-run\n" > "$1"' _ "${RUN_MISS_SENTINEL}" > "${CLI_LOG_DIR}/run-miss.log" 2>&1
run_miss_status=$?
set -e
if [[ "${run_miss_status}" -ne 78 ]]; then
  echo "expected run miss exit code 78, got ${run_miss_status}"
  cat "${CLI_LOG_DIR}/run-miss.log"
  exit 1
fi
if [[ -f "${RUN_MISS_SENTINEL}" ]]; then
  echo "run child command executed despite fail-on-cache-miss"
  cat "${CLI_LOG_DIR}/run-miss.log"
  exit 1
fi

RUN_PROXY_SCRIPT="${CLI_LOG_DIR}/run-proxy-child.sh"
cat > "${RUN_PROXY_SCRIPT}" <<'EOF'
#!/usr/bin/env sh
set -eu
endpoint="${NX_SELF_HOSTED_REMOTE_CACHE_SERVER:-}"
[ -n "${endpoint}" ] || exit 31
[ "${TURBO_API:-}" = "${endpoint}" ] || exit 32
expected_ref="127.0.0.1:$1/cache:$2"
[ "$3" = "${expected_ref}" ] || exit 33
curl -fsS --max-time 2 "${endpoint}/v2/" >/dev/null || exit 34
EOF
chmod +x "${RUN_PROXY_SCRIPT}"
"${CLI}" run "${WORKSPACE}" --proxy "${RUN_PROXY_TAG}" "${E2E_TAG_SCOPE_FLAGS[@]}" --host 127.0.0.1 --port 0 -- sh "${RUN_PROXY_SCRIPT}" "{PORT}" "${RUN_PROXY_TAG}" "{CACHE_REF}" > "${CLI_LOG_DIR}/run-proxy.log"

"${CLI}" delete "${E2E_TAG_SCOPE_FLAGS[@]}" "${WORKSPACE}" "${RUN_TAG}" > "${CLI_LOG_DIR}/run-delete.log"

echo "=== Phase 2b: repo config profiles ==="
mkdir -p "${REPO_CONFIG_BIN_DIR}"
cat > "${REPO_CONFIG_DIR}/.boringcache.toml" <<EOF
workspace = "${WORKSPACE}"

[entries.bundler]
tag = "${REPO_CONFIG_TAG}"

[profiles.${REPO_CONFIG_PROFILE}]
entries = ["bundler"]
EOF

cat > "${REPO_CONFIG_BIN_DIR}/bundle" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "install" ]]; then
  echo "expected bundle install" >&2
  exit 41
fi

if [[ -z "${BUNDLE_PATH:-}" ]]; then
  echo "BUNDLE_PATH missing" >&2
  exit 42
fi

mkdir -p "${BUNDLE_PATH}"

case "${REPO_CONFIG_MODE:?}" in
  seed)
    printf 'repo-config-seed-%s\n' "${RUN_ID_FOR_E2E:?}" > "${BUNDLE_PATH}/marker.txt"
    ;;
  verify)
    grep -q "repo-config-seed-${RUN_ID_FOR_E2E:?}" "${BUNDLE_PATH}/marker.txt" || exit 43
    printf 'repo-config-restored-%s\n' "${RUN_ID_FOR_E2E:?}" > "${BUNDLE_PATH}/restored.txt"
    ;;
  *)
    echo "unknown REPO_CONFIG_MODE=${REPO_CONFIG_MODE}" >&2
    exit 44
    ;;
esac
EOF
chmod +x "${REPO_CONFIG_BIN_DIR}/bundle"

(
  cd "${REPO_CONFIG_DIR}"
  PATH="${REPO_CONFIG_BIN_DIR}:$PATH" \
    REPO_CONFIG_MODE=seed \
    RUN_ID_FOR_E2E="${RUN_ID}" \
    "${CLI}" run "${E2E_TAG_SCOPE_FLAGS[@]}" --skip-restore --profile "${REPO_CONFIG_PROFILE}" -- bundle install \
      > "${CLI_LOG_DIR}/repo-config-seed.log"
)

rm -rf "${REPO_CONFIG_DIR}/vendor"

(
  cd "${REPO_CONFIG_DIR}"
  PATH="${REPO_CONFIG_BIN_DIR}:$PATH" \
    REPO_CONFIG_MODE=verify \
    RUN_ID_FOR_E2E="${RUN_ID}" \
    "${CLI}" run "${E2E_TAG_SCOPE_FLAGS[@]}" --skip-save --profile "${REPO_CONFIG_PROFILE}" -- bundle install \
      > "${CLI_LOG_DIR}/repo-config-restore.log"
)

grep -q "repo-config-restored-${RUN_ID}" "${REPO_CONFIG_DIR}/vendor/bundle/restored.txt"

echo "=== Phase 3: encryption + mount sync ==="
"${CLI}" setup-encryption "${WORKSPACE}" --identity-output "${IDENTITY_FILE}" > "${CLI_LOG_DIR}/setup-encryption.log"
if [[ ! -f "${IDENTITY_FILE}" ]]; then
  echo "setup-encryption did not create identity file"
  exit 1
fi
identity_mode="$(file_mode_octal "${IDENTITY_FILE}")"
if [[ "${identity_mode}" != "600" ]]; then
  echo "identity file permissions are not 0600"
  echo "${identity_mode} ${IDENTITY_FILE}"
  exit 1
fi

mkdir -p "${MOUNT_SRC_DIR}"
printf 'mount-initial-%s\n' "${RUN_SHA}" > "${MOUNT_SRC_DIR}/file.txt"
"${CLI}" save "${E2E_TAG_SCOPE_FLAGS[@]}" "${WORKSPACE}" "${TAG_MOUNT}:${MOUNT_SRC_DIR}" > "${CLI_LOG_DIR}/mount-save.log"

encrypted_visible=0
for _ in $(seq 1 10); do
  "${CLI}" ls "${WORKSPACE}" --limit 500 --json > "${CLI_LOG_DIR}/ls-after-encryption.json"
  if jq -e --arg tag "${TAG_MOUNT}" '.entries[]? | select(.tag == $tag and .encrypted == true)' "${CLI_LOG_DIR}/ls-after-encryption.json" >/dev/null; then
    encrypted_visible=1
    break
  fi
  sleep 1
done
if [[ "${encrypted_visible}" != "1" ]]; then
  echo "encrypted entry for ${TAG_MOUNT} was not visible in ls output"
  cat "${CLI_LOG_DIR}/ls-after-encryption.json"
  exit 1
fi

MOUNT_PID=""
cleanup_mount() {
  set +e
  if [[ -n "${MOUNT_PID:-}" ]] && kill -0 "${MOUNT_PID}" >/dev/null 2>&1; then
    stop_pid_tree "${MOUNT_PID}" "mount process" "$MOUNT_SHUTDOWN_WAIT_SECS"
  fi
}
trap cleanup_mount EXIT

"${CLI}" mount "${E2E_TAG_SCOPE_FLAGS[@]}" "${WORKSPACE}" "${TAG_MOUNT}:${MOUNT_WATCH_DIR}" --identity "${IDENTITY_FILE}" --verbose > "${MOUNT_LOG}" 2>&1 &
MOUNT_PID=$!

mount_ready=0
for _ in $(seq 1 30); do
  if ! kill -0 "${MOUNT_PID}" >/dev/null 2>&1; then
    echo "mount exited before readiness"
    cat "${MOUNT_LOG}"
    exit 1
  fi
  if grep -q "Watching" "${MOUNT_LOG}"; then
    mount_ready=1
    break
  fi
  sleep 1
done
if [[ "${mount_ready}" != "1" ]]; then
  echo "mount did not reach watch state in time"
  cat "${MOUNT_LOG}"
  exit 1
fi

printf 'mount-updated-%s\n' "${RUN_ID}" >> "${MOUNT_WATCH_DIR}/file.txt"
sleep 2
kill -INT "${MOUNT_PID}" >/dev/null 2>&1 || true
if ! wait "${MOUNT_PID}"; then
  echo "mount exited with non-zero status"
  cat "${MOUNT_LOG}"
  exit 1
fi
if grep -q "Final sync failed" "${MOUNT_LOG}"; then
  echo "mount reported final sync failure"
  cat "${MOUNT_LOG}"
  exit 1
fi
MOUNT_PID=""
trap - EXIT

"${CLI}" restore "${E2E_TAG_SCOPE_FLAGS[@]}" --identity "${IDENTITY_FILE}" "${WORKSPACE}" "${TAG_MOUNT}:${MOUNT_RESTORE_DIR}" > "${CLI_LOG_DIR}/mount-restore.log"
grep -q "mount-updated-${RUN_ID}" "${MOUNT_RESTORE_DIR}/file.txt"

"${CLI}" delete "${E2E_TAG_SCOPE_FLAGS[@]}" "${WORKSPACE}" "${TAG_MOUNT}" > "${CLI_LOG_DIR}/mount-delete.log"

echo "CLI core e2e passed. Logs: ${CLI_LOG_DIR}"
