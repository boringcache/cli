#!/usr/bin/env bash

e2e_tag() {
  local name="$1"
  if [[ -z "${BORINGCACHE_E2E_LOCAL_RUN_ID:-}" ]]; then
    export BORINGCACHE_E2E_LOCAL_RUN_ID="local-$(date +%s)"
  fi
  local run_id="${GITHUB_RUN_ID:-${BORINGCACHE_E2E_RUN_ID:-${BORINGCACHE_E2E_LOCAL_RUN_ID}}}"
  local run_attempt="${GITHUB_RUN_ATTEMPT:-${BORINGCACHE_E2E_RUN_ATTEMPT:-1}}"
  printf 'gha-%s-%s-%s' "$name" "$run_id" "$run_attempt"
}

resolve_restore_capable_token() {
  local mode="${1:-default}"
  local token
  local -a candidates=()

  if [[ "$mode" == "admin" ]]; then
    candidates=(
      "${BORINGCACHE_E2E_ADMIN_TOKEN:-}"
      "${BORINGCACHE_ADMIN_TOKEN:-}"
      "${BORINGCACHE_E2E_RESTORE_TOKEN:-}"
      "${BORINGCACHE_RESTORE_TOKEN:-}"
      "${BORINGCACHE_E2E_SAVE_TOKEN:-}"
      "${BORINGCACHE_SAVE_TOKEN:-}"
    )
  else
    candidates=(
      "${BORINGCACHE_E2E_RESTORE_TOKEN:-}"
      "${BORINGCACHE_RESTORE_TOKEN:-}"
      "${BORINGCACHE_E2E_SAVE_TOKEN:-}"
      "${BORINGCACHE_SAVE_TOKEN:-}"
      "${BORINGCACHE_E2E_ADMIN_TOKEN:-}"
      "${BORINGCACHE_ADMIN_TOKEN:-}"
    )
  fi

  for token in "${candidates[@]}"; do
    if [[ -n "${token}" ]]; then
      printf '%s\n' "${token}"
      return 0
    fi
  done
  return 1
}

resolve_save_capable_token() {
  local mode="${1:-default}"
  local token
  local -a candidates=()

  if [[ "$mode" == "admin" ]]; then
    candidates=(
      "${BORINGCACHE_E2E_ADMIN_TOKEN:-}"
      "${BORINGCACHE_ADMIN_TOKEN:-}"
      "${BORINGCACHE_E2E_SAVE_TOKEN:-}"
      "${BORINGCACHE_SAVE_TOKEN:-}"
    )
  else
    candidates=(
      "${BORINGCACHE_E2E_SAVE_TOKEN:-}"
      "${BORINGCACHE_SAVE_TOKEN:-}"
      "${BORINGCACHE_E2E_ADMIN_TOKEN:-}"
      "${BORINGCACHE_ADMIN_TOKEN:-}"
    )
  fi

  for token in "${candidates[@]}"; do
    if [[ -n "${token}" ]]; then
      printf '%s\n' "${token}"
      return 0
    fi
  done
  return 1
}

resolve_admin_capable_token() {
  local token
  for token in \
    "${BORINGCACHE_E2E_ADMIN_TOKEN:-}" \
    "${BORINGCACHE_ADMIN_TOKEN:-}"; do
    if [[ -n "${token}" ]]; then
      printf '%s\n' "${token}"
      return 0
    fi
  done
  return 1
}

require_restore_capable_token() {
  if ! resolve_restore_capable_token >/dev/null; then
    echo "ERROR: configure BORINGCACHE_RESTORE_TOKEN, BORINGCACHE_SAVE_TOKEN, or BORINGCACHE_ADMIN_TOKEN"
    exit 1
  fi
}

require_save_capable_token() {
  if ! resolve_save_capable_token >/dev/null; then
    echo "ERROR: configure BORINGCACHE_SAVE_TOKEN or BORINGCACHE_ADMIN_TOKEN"
    exit 1
  fi
}

require_admin_capable_token() {
  if ! resolve_admin_capable_token >/dev/null; then
    echo "ERROR: configure BORINGCACHE_ADMIN_TOKEN"
    exit 1
  fi
}

export_resolved_cli_tokens() {
  local mode="${1:-default}"
  local restore_token save_token admin_token
  restore_token="$(resolve_restore_capable_token "$mode" || true)"
  save_token="$(resolve_save_capable_token "$mode" || true)"
  admin_token="$(resolve_admin_capable_token || true)"

  if [[ -n "${restore_token}" ]]; then
    export BORINGCACHE_RESTORE_TOKEN="${restore_token}"
  else
    unset BORINGCACHE_RESTORE_TOKEN
  fi

  if [[ -n "${save_token}" ]]; then
    export BORINGCACHE_SAVE_TOKEN="${save_token}"
  else
    unset BORINGCACHE_SAVE_TOKEN
  fi

  if [[ -n "${admin_token}" ]]; then
    export BORINGCACHE_ADMIN_TOKEN="${admin_token}"
  else
    unset BORINGCACHE_ADMIN_TOKEN
  fi
}

bootstrap_cli_session() {
  local binary="$1"
  local workspace="$2"
  local api_url="$3"
  local auth_log="$4"
  local token_mode="${5:-default}"

  export BORINGCACHE_DEFAULT_WORKSPACE="${workspace}"
  export BORINGCACHE_API_URL="${api_url}"
  export_resolved_cli_tokens "$token_mode"
  unset BORINGCACHE_API_TOKEN

  {
    printf 'token_mode=%s\n' "${token_mode}"
    printf 'mode=env\n'
    printf 'binary=%s\n' "${binary}"
    printf 'workspace=%s\n' "${workspace}"
    printf 'api_url=%s\n' "${api_url}"
    printf 'restore_token=%s\n' "${BORINGCACHE_RESTORE_TOKEN:+configured}"
    printf 'save_token=%s\n' "${BORINGCACHE_SAVE_TOKEN:+configured}"
    printf 'admin_token=%s\n' "${BORINGCACHE_ADMIN_TOKEN:+configured}"
  } > "${auth_log}"
}
