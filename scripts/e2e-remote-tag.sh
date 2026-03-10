#!/usr/bin/env bash

REMOTE_TAG_VERIFY_ATTEMPTS="${REMOTE_TAG_VERIFY_ATTEMPTS:-30}"
REMOTE_TAG_VERIFY_SLEEP_SECS="${REMOTE_TAG_VERIFY_SLEEP_SECS:-2}"

json_summary_value() {
  local key="$1"
  local file="$2"

  if command -v jq >/dev/null 2>&1; then
    jq -r ".${key} // 0" "$file"
    return 0
  fi

  tr -d '\n' <"$file" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" | head -n 1
}

remote_tag_check_once() {
  local binary="$1"
  local workspace="$2"
  local tag="$3"
  local output_dir="$4"
  local check_file stderr_file hits misses

  mkdir -p "$output_dir"
  check_file="${output_dir}/remote-tag-check.json"
  stderr_file="${output_dir}/remote-tag-check.stderr.txt"

  if ! "$binary" check "$workspace" "$tag" --no-platform --no-git --json >"$check_file" 2>"$stderr_file"; then
    REMOTE_TAG_CHECK_ERROR_FILE="$stderr_file"
    export REMOTE_TAG_CHECK_ERROR_FILE
    return 1
  fi

  hits="$(json_summary_value "hits" "$check_file")"
  misses="$(json_summary_value "misses" "$check_file")"
  REMOTE_TAG_CHECK_HITS="${hits:-0}"
  REMOTE_TAG_CHECK_MISSES="${misses:-0}"
  REMOTE_TAG_CHECK_FILE="$check_file"
  REMOTE_TAG_CHECK_STDERR_FILE="$stderr_file"
  export \
    REMOTE_TAG_CHECK_FILE \
    REMOTE_TAG_CHECK_HITS \
    REMOTE_TAG_CHECK_MISSES \
    REMOTE_TAG_CHECK_STDERR_FILE
  return 0
}

verify_remote_tag_visible() {
  local binary="$1"
  local workspace="$2"
  local tag="$3"
  local output_dir="$4"
  local minimum_hits="${5:-1}"
  local attempts="${6:-$REMOTE_TAG_VERIFY_ATTEMPTS}"
  local sleep_secs="${7:-$REMOTE_TAG_VERIFY_SLEEP_SECS}"
  local proxy_log="${8:-}"
  local attempt

  for attempt in $(seq 1 "$attempts"); do
    if remote_tag_check_once "$binary" "$workspace" "$tag" "$output_dir"; then
      echo "Remote tag check (${tag}): hits=${REMOTE_TAG_CHECK_HITS:-0}, misses=${REMOTE_TAG_CHECK_MISSES:-0}, file=${REMOTE_TAG_CHECK_FILE}"
      if awk -v a="${REMOTE_TAG_CHECK_HITS:-0}" -v b="$minimum_hits" 'BEGIN { exit (a + 0 >= b + 0) ? 0 : 1 }'; then
        return 0
      fi
    else
      echo "WARNING: remote tag check command failed for ${tag} (attempt ${attempt}/${attempts})"
      if [[ -n "${REMOTE_TAG_CHECK_ERROR_FILE:-}" && -f "${REMOTE_TAG_CHECK_ERROR_FILE}" ]]; then
        cat "${REMOTE_TAG_CHECK_ERROR_FILE}" || true
      fi
    fi

    if (( attempt < attempts )); then
      echo "  waiting for remote tag ${tag} to publish... (${attempt}/${attempts})"
      sleep "$sleep_secs"
    fi
  done

  echo "ERROR: remote tag ${tag} is not published (hits=${REMOTE_TAG_CHECK_HITS:-0}, misses=${REMOTE_TAG_CHECK_MISSES:-0})"
  if [[ -n "$proxy_log" && -f "$proxy_log" ]]; then
    echo "--- proxy log tail ---"
    tail -n 120 "$proxy_log" || true
  fi
  return 1
}
