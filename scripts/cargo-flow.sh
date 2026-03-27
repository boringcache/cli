#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${BORINGCACHE_ENV_FILE:-${REPO_ROOT}/.boringcache.env}"
SCCACHE_CONFLICT_ENV_VARS=(
  SCCACHE_ENDPOINT
  SCCACHE_BUCKET
  SCCACHE_REGION
  SCCACHE_S3_KEY_PREFIX
  SCCACHE_S3_USE_SSL
  SCCACHE_S3_NO_CREDENTIALS
  SCCACHE_S3_SERVER_SIDE_ENCRYPTION
  SCCACHE_S3_ENABLE_VIRTUAL_HOST_STYLE
  SCCACHE_GCS_BUCKET
  SCCACHE_GCS_KEY_PATH
  SCCACHE_GCS_CREDENTIALS_URL
  SCCACHE_AZURE_CONNECTION_STRING
  SCCACHE_AZURE_BLOB_CONTAINER
  SCCACHE_REDIS
  SCCACHE_MEMCACHED
  SCCACHE_WEBDAV_ENDPOINT
  SCCACHE_WEBDAV_USERNAME
  SCCACHE_WEBDAV_PASSWORD
)
RUN_FLOW_CHILD_PID=""
RUN_FLOW_SIGNAL_STATUS=0

if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
fi

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

require_cmd() {
  local name="$1"
  if ! has_cmd "${name}"; then
    echo "ERROR: required command not found: ${name}" >&2
    exit 1
  fi
}

clear_conflicting_sccache_env() {
  local name
  for name in "${SCCACHE_CONFLICT_ENV_VARS[@]}"; do
    unset "${name}"
  done
}

resolve_boringcache_binary() {
  if [[ -n "${BORINGCACHE_CARGO_FLOW_BINARY:-}" ]]; then
    printf '%s\n' "${BORINGCACHE_CARGO_FLOW_BINARY}"
    return 0
  fi
  if [[ -x "${REPO_ROOT}/target/debug/boringcache" ]]; then
    printf '%s\n' "${REPO_ROOT}/target/debug/boringcache"
    return 0
  fi
  if [[ -x "${REPO_ROOT}/target/release/boringcache" ]]; then
    printf '%s\n' "${REPO_ROOT}/target/release/boringcache"
    return 0
  fi
  if has_cmd boringcache; then
    command -v boringcache
    return 0
  fi
  return 1
}

rust_field() {
  local key="$1"
  local line
  while IFS= read -r line; do
    case "${line}" in
      "${key}: "*)
        printf '%s\n' "${line#${key}: }"
        return 0
        ;;
    esac
  done <<<"$(rustc -vV)"
  echo "ERROR: failed to read rustc ${key}" >&2
  exit 1
}

rust_release() {
  rust_field release
}

rust_host() {
  rust_field host
}

proxy_port() {
  local port="${BORINGCACHE_CARGO_PROXY_PORT:-0}"
  if ! [[ "${port}" =~ ^[0-9]+$ ]] || (( port > 65535 )); then
    echo "ERROR: BORINGCACHE_CARGO_PROXY_PORT must be an integer between 0 and 65535" >&2
    exit 1
  fi
  printf '%s\n' "${port}"
}

detect_profile() {
  local profile="debug"
  local expect_profile="0"
  local arg
  for arg in "$@"; do
    if [[ "${expect_profile}" == "1" ]]; then
      profile="${arg}"
      expect_profile="0"
      continue
    fi
    case "${arg}" in
      --release)
        profile="release"
        ;;
      --profile)
        expect_profile="1"
        ;;
      --profile=*)
        profile="${arg#--profile=}"
        ;;
    esac
  done
  printf '%s\n' "${profile}"
}

target_dir_empty() {
  local dir="$1"
  if [[ ! -d "${dir}" ]]; then
    return 0
  fi
  [[ -z "$(find "${dir}" -mindepth 1 -print -quit 2>/dev/null)" ]]
}

existing_proxy_env() {
  [[ -n "${SCCACHE_WEBDAV_ENDPOINT:-}" || -n "${SCCACHE_ENDPOINT:-}" || -n "${NX_SELF_HOSTED_REMOTE_CACHE_SERVER:-}" || -n "${TURBO_API:-}" ]]
}

requested_mode() {
  printf '%s\n' "${BORINGCACHE_CARGO_FLOW_MODE:-auto}"
}

effective_mode() {
  local requested
  requested="$(requested_mode)"
  case "${requested}" in
    plain|boringcache)
      printf '%s\n' "${requested}"
      ;;
    auto)
      if existing_proxy_env || [[ -n "${GITHUB_ACTIONS:-}" || -n "${CI:-}" ]]; then
        printf 'plain\n'
      elif has_cmd sccache && resolve_boringcache_binary >/dev/null; then
        printf 'boringcache\n'
      else
        printf 'plain\n'
      fi
      ;;
    *)
      echo "ERROR: unsupported BORINGCACHE_CARGO_FLOW_MODE=${requested}" >&2
      exit 1
      ;;
  esac
}

target_archive_mode() {
  printf '%s\n' "${BORINGCACHE_CARGO_TARGET_ARCHIVE_MODE:-restore-when-empty}"
}

workspace_name() {
  printf '%s\n' "${BORINGCACHE_CARGO_WORKSPACE:-${BORINGCACHE_DEFAULT_WORKSPACE:-boringcache/cli}}"
}

build_proxy_tag() {
  local profile="$1"
  if [[ -n "${BORINGCACHE_CARGO_PROXY_TAG:-}" ]]; then
    printf '%s\n' "${BORINGCACHE_CARGO_PROXY_TAG}"
    return 0
  fi
  printf 'rust-%s-sccache-%s-%s\n' "${RUST_RELEASE}" "${profile}" "${RUST_HOST}"
}

build_target_tag() {
  local profile="$1"
  if [[ -n "${BORINGCACHE_CARGO_TARGET_TAG:-}" ]]; then
    printf '%s\n' "${BORINGCACHE_CARGO_TARGET_TAG}"
    return 0
  fi
  printf 'cargo-target-%s-rust-%s-%s\n' "${profile}" "${RUST_RELEASE}" "${RUST_HOST}"
}

prepare_environment() {
  require_cmd cargo
  require_cmd rustc
  RUST_RELEASE="$(rust_release)"
  RUST_HOST="$(rust_host)"
  WORKSPACE="$(workspace_name)"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
  MODE="$(effective_mode)"
  if [[ "${MODE}" == "boringcache" ]]; then
    require_cmd sccache
    clear_conflicting_sccache_env
    BORINGCACHE_BINARY="$(resolve_boringcache_binary)" || {
      echo "ERROR: boringcache binary not found. Build ./target/debug/boringcache once or set BORINGCACHE_CARGO_FLOW_BINARY." >&2
      exit 1
    }
    export BORINGCACHE_DEFAULT_WORKSPACE="${WORKSPACE}"
    export SCCACHE_DIR="${SCCACHE_DIR:-${REPO_ROOT}/.boringcache/sccache}"
    export SCCACHE_SERVER_PORT="${SCCACHE_SERVER_PORT:-4228}"
    export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
    mkdir -p "${SCCACHE_DIR}"
  fi
}

target_archive_action() {
  local profile="$1"
  local archive_mode
  archive_mode="$(target_archive_mode)"
  if [[ "${MODE}" != "boringcache" ]]; then
    printf 'disabled\n'
    return 0
  fi
  if [[ "${profile}" != "debug" ]]; then
    printf 'disabled\n'
    return 0
  fi
  case "${archive_mode}" in
    off)
      printf 'disabled\n'
      ;;
    restore-when-empty)
      if target_dir_empty "${CARGO_TARGET_DIR}"; then
        printf 'restore-when-empty\n'
      else
        printf 'skip-restore-target-present\n'
      fi
      ;;
    seed)
      if target_dir_empty "${CARGO_TARGET_DIR}"; then
        printf 'restore-and-save\n'
      else
        printf 'save-only-target-present\n'
      fi
      ;;
    *)
      echo "ERROR: unsupported BORINGCACHE_CARGO_TARGET_ARCHIVE_MODE=${archive_mode}" >&2
      exit 1
      ;;
  esac
}

show_environment() {
  local profile="${1:-debug}"
  local proxy_tag
  local target_tag
  prepare_environment
  proxy_tag="$(build_proxy_tag "${profile}")"
  target_tag="$(build_target_tag "${profile}")"

  cat <<EOF
mode=${MODE}
requested_mode=$(requested_mode)
binary=${BORINGCACHE_BINARY:-none}
env_file=${ENV_FILE}
workspace=${WORKSPACE}
rust_release=${RUST_RELEASE}
rust_host=${RUST_HOST}
cargo_target_dir=${CARGO_TARGET_DIR}
sccache_dir=${SCCACHE_DIR:-none}
sccache_server_port=${SCCACHE_SERVER_PORT:-none}
proxy_port=$(proxy_port)
cargo_incremental=${CARGO_INCREMENTAL:-unset}
target_archive_mode=$(target_archive_mode)
target_archive_action=$(target_archive_action "${profile}")
proxy_tag=${proxy_tag}
target_tag=${target_tag}
EOF
}

restore_target_archive_if_needed() {
  local profile="$1"
  if [[ "$(target_archive_action "${profile}")" != "restore-when-empty" ]]; then
    return 0
  fi
  local target_tag
  target_tag="$(build_target_tag "${profile}")"
  if ! "${BORINGCACHE_BINARY}" restore "${WORKSPACE}" "${target_tag}:${CARGO_TARGET_DIR}" --no-platform --no-git; then
    echo "[cargo-flow] target restore skipped for ${target_tag}" >&2
  fi
}

print_sccache_stats() {
  if ! has_cmd sccache; then
    return 0
  fi
  if [[ "${MODE}" != "boringcache" && "${RUSTC_WRAPPER:-}" != "sccache" ]]; then
    return 0
  fi
  SCCACHE_SERVER_PORT="${SCCACHE_SERVER_PORT:-4228}" sccache --show-stats || true
}

stop_sccache_server_if_needed() {
  if [[ "${MODE}" != "boringcache" ]] || ! has_cmd sccache; then
    return 0
  fi
  SCCACHE_SERVER_PORT="${SCCACHE_SERVER_PORT}" sccache --stop-server >/dev/null 2>&1 || true
}

run_command_with_forwarded_signals() {
  local status=0
  RUN_FLOW_CHILD_PID=""
  RUN_FLOW_SIGNAL_STATUS=0

  "$@" &
  RUN_FLOW_CHILD_PID=$!
  trap 'forward_run_flow_signal INT 130' INT
  trap 'forward_run_flow_signal TERM 143' TERM
  wait "${RUN_FLOW_CHILD_PID}" || status=$?
  trap - INT TERM
  RUN_FLOW_CHILD_PID=""
  if [[ "${RUN_FLOW_SIGNAL_STATUS}" -ne 0 ]]; then
    return "${RUN_FLOW_SIGNAL_STATUS}"
  fi
  return "${status}"
}

forward_run_flow_signal() {
  local signal_name="$1"
  local exit_status="$2"
  RUN_FLOW_SIGNAL_STATUS="${exit_status}"
  if [[ -z "${RUN_FLOW_CHILD_PID}" ]]; then
    return 0
  fi
  kill -s "${signal_name}" "-${RUN_FLOW_CHILD_PID}" >/dev/null 2>&1 || \
    kill -s "${signal_name}" "${RUN_FLOW_CHILD_PID}" >/dev/null 2>&1 || true
  wait "${RUN_FLOW_CHILD_PID}" >/dev/null 2>&1 || true
}

run_flow() {
  local cargo_args=("$@")
  local profile
  local proxy_tag
  local status
  local run_args

  if [[ "${#cargo_args[@]}" -eq 0 ]]; then
    echo "ERROR: cargo arguments required" >&2
    exit 1
  fi

  prepare_environment
  profile="$(detect_profile "${cargo_args[@]}")"
  if [[ "${MODE}" == "plain" ]]; then
    cargo "${cargo_args[@]}"
    print_sccache_stats
    return 0
  fi

  proxy_tag="$(build_proxy_tag "${profile}")"
  restore_target_archive_if_needed "${profile}"

  run_args=(run "${WORKSPACE}" --proxy "${proxy_tag}" --no-platform --no-git --host 127.0.0.1 --port "$(proxy_port)")
  case "$(target_archive_action "${profile}")" in
    restore-and-save)
      run_args+=("$(build_target_tag "${profile}"):${CARGO_TARGET_DIR}")
      ;;
    save-only-target-present)
      run_args+=("$(build_target_tag "${profile}"):${CARGO_TARGET_DIR}" --skip-restore)
      ;;
  esac

  stop_sccache_server_if_needed
  status=0
  run_command_with_forwarded_signals "${BORINGCACHE_BINARY}" "${run_args[@]}" -- cargo "${cargo_args[@]}" || status=$?
  print_sccache_stats
  stop_sccache_server_if_needed
  return "${status}"
}

run_rust_2024_compat() {
  local saved_rustflags="${RUSTFLAGS-}"
  local compat_flag="-Wrust-2024-compatibility"
  local status=0

  if [[ -n "${saved_rustflags}" ]]; then
    export RUSTFLAGS="${saved_rustflags} ${compat_flag}"
  else
    export RUSTFLAGS="${compat_flag}"
  fi

  run_flow check --locked --all-targets "$@" || status=$?

  if [[ -n "${saved_rustflags}" ]]; then
    export RUSTFLAGS="${saved_rustflags}"
  else
    unset RUSTFLAGS
  fi

  return "${status}"
}

usage() {
  cat <<'EOF'
Usage:
  scripts/cargo-flow.sh env
  scripts/cargo-flow.sh build [cargo build args...]
  scripts/cargo-flow.sh test [cargo test args...]
  scripts/cargo-flow.sh clippy
  scripts/cargo-flow.sh compat [cargo check args...]
  scripts/cargo-flow.sh check
  scripts/cargo-flow.sh cargo <cargo args...>
EOF
}

main() {
  local command="${1:-}"
  if [[ -z "${command}" ]]; then
    usage
    exit 1
  fi
  shift

  case "${command}" in
    env)
      show_environment "${1:-debug}"
      ;;
    build)
      run_flow build --locked "$@"
      ;;
    test)
      run_flow test --locked "$@"
      ;;
    clippy)
      run_flow clippy --locked --all-targets --all-features "$@" -- -D warnings
      ;;
    compat)
      run_rust_2024_compat "$@"
      ;;
    check)
      ./scripts/verify-rust-version-sync.sh
      cargo fmt -- --check
      run_flow clippy --locked --all-targets --all-features -- -D warnings
      run_rust_2024_compat
      run_flow test --locked
      ;;
    cargo)
      if [[ "${#@}" -eq 0 ]]; then
        echo "ERROR: cargo subcommand required after 'cargo'" >&2
        exit 1
      fi
      run_flow "$@"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
